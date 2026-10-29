"""
Principal-session liveness, re-authentication, and the poison-fuse that stops
IOLITE from ever learning authorization intent from untrustworthy traffic.

THE FAILURE THIS KILLS
----------------------
A long autonomous crawl of a giant app *will* lose its session partway through
(idle timeout, rotated CSRF token, revoked JWT, a silent redirect to the login
page that still returns 200). If Diamond Sword keeps "capturing as A" after
that, it is really capturing as an anonymous user — and every one of those
exchanges is a lie. Feed those to IOLITE and it learns the *wrong* access-control
policy for the target: the single most expensive way to poison the pipeline,
because the error is invisible and compounds.

TWO IDEAS DO THE WORK
---------------------
1. Liveness by *substance*, not by status. A 200 proves nothing — the login
   page is a 200. A session is alive only if the response to a cheap, idempotent
   read of an *owned anchor* still carries this principal's own discriminating
   identity (id / handle / email), the same "substantive, discriminating value"
   test ONYX uses to judge a leak. This is the one place the system refuses the
   status-code oracle.

2. A bracketed poison-fuse. Every login bumps an ``epoch``. An exchange is
   trustworthy only if liveness was green at epoch E *before* it was sent and
   still green at the same epoch E *after* — i.e. the session did not silently
   die underneath the capture window. Anything whose bracket is not closed-green
   is quarantined and never reaches IOLITE. We would rather capture less than
   capture a lie.

Step-up / MFA is not a failure; it is a human checkpoint. We transition to
STEPUP and signal PAUSE_FOR_HUMAN (the explorer already understands that stop)
instead of burning retries against a challenge no bot should answer.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol


class SessionState:
    FRESH, STALE, DEAD, STEPUP = "FRESH", "STALE", "DEAD", "STEPUP"


class StepUpRequired(RuntimeError):
    def __init__(self, pid: str):
        super().__init__(f"principal {pid}: step-up/MFA challenge — human needed")
        self.pid = pid


class ReauthFailed(RuntimeError):
    def __init__(self, pid: str, attempts: int):
        super().__init__(f"principal {pid}: re-auth failed after {attempts} attempts")
        self.pid, self.attempts = pid, attempts


@dataclass
class AuthMaterial:
    headers: dict[str, str] = field(default_factory=dict)   # Authorization, Cookie, X-CSRF-Token...
    secrets: dict[str, str] = field(default_factory=dict)   # refresh_token etc. — never logged


@dataclass
class ProbeResponse:
    status: int
    headers: Mapping[str, str]
    body: str


# send(method, url, headers, body) -> ProbeResponse  (adapted from the live sender)
SendFn = Callable[[str, str, Mapping[str, str], "str | None"], ProbeResponse]


# --- login recipes (pluggable) -------------------------------------------------------

class AuthRecipe(Protocol):
    def login(self, send: SendFn) -> AuthMaterial: ...


@dataclass
class StaticHeaders:
    """Baseline: the operator supplied headers (the CLI's ``A=hdrs.json``). No
    automatic re-login is possible, so a dead session escalates to the human —
    but liveness is still enforced, so we never trust it blindly."""
    headers: dict[str, str]

    def login(self, send: SendFn) -> AuthMaterial:
        return AuthMaterial(headers=dict(self.headers))


@dataclass
class TokenRefresh:
    """Refresh a bearer token at a refresh endpoint, reading the new token from a
    JSON key in the response. Fully automatic re-auth."""
    refresh_url: str
    refresh_token: str
    token_json_key: str = "access_token"
    header_name: str = "Authorization"
    scheme: str = "Bearer"

    def login(self, send: SendFn) -> AuthMaterial:
        import json
        body = json.dumps({"refresh_token": self.refresh_token})
        r = send("POST", self.refresh_url, {"Content-Type": "application/json"}, body)
        try:
            tok = str(json.loads(r.body).get(self.token_json_key, ""))
        except (ValueError, AttributeError, TypeError):
            tok = ""
        if not tok:
            raise ReauthFailed("token-refresh", 1)
        return AuthMaterial(headers={self.header_name: f"{self.scheme} {tok}".strip()})


# --- liveness probe ------------------------------------------------------------------

@dataclass
class LivenessProbe:
    """A cheap, idempotent, owned-resource read plus the invariant that proves the
    response still belongs to this principal.

    ``identity_markers`` are this principal's own discriminating values (user id,
    username, email). ``url`` is a GET that, authenticated as this principal,
    echoes at least one marker (e.g. GitLab's /api/v4/user). Alive iff a marker
    appears as a discriminating token AND the body is not a login/challenge page.
    """
    method: str
    url: str
    identity_markers: tuple[str, ...]
    login_markers: tuple[str, ...] = (
        "sign in", "log in", "password", "authenticity_token",
        "two-factor", "verification code",
    )
    min_marker_len: int = 3

    def holds(self, r: ProbeResponse) -> tuple[bool, str]:
        if r.status in (401, 403):
            return False, "unauthorized"
        if r.status == 0:
            return False, "transport_error"
        text = r.body or ""
        low = text.lower()
        if any(m in low for m in self.login_markers) and not _looks_like_json(text):
            return False, "challenge_or_login_page"   # a 200 login page is still dead
        for m in self.identity_markers:
            if m and len(m) >= self.min_marker_len and m in text:
                return True, f"marker:{_mask(m)}"
        return False, "identity_marker_absent"

    def is_stepup(self, r: ProbeResponse) -> bool:
        low = (r.body or "").lower()
        return any(k in low for k in ("two-factor", "verification code", "one-time", "otp", "mfa"))


def _looks_like_json(text: str) -> bool:
    return text.lstrip()[:1] in ("{", "[")


def _mask(v: str) -> str:
    return (v[:2] + "\u2026") if len(v) > 3 else "\u2026"


# --- a principal's session -----------------------------------------------------------

@dataclass
class _Session:
    pid: str
    recipe: AuthRecipe
    probe: LivenessProbe
    material: AuthMaterial = field(default_factory=AuthMaterial)
    state: str = SessionState.STALE
    epoch: int = 0
    last_verified: float = -1e18
    logged_in: bool = False


class SessionHub:
    """Owns every principal's session, enforces periodic liveness, re-auths, and
    exposes the confidence signal the transport brackets each capture with."""

    def __init__(
        self,
        *,
        verify_every_s: float = 45.0,          # re-verify at least this often (time)...
        verify_every_n: int = 25,              # ...and at least this often (request count)
        max_reauth: int = 2,
        clock: Callable[[], float] = time.monotonic,
        audit: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self._verify_s = verify_every_s
        self._verify_n = verify_every_n
        self._max_reauth = max_reauth
        self._clock = clock
        self._audit = audit or (lambda k, p: None)
        self._lock = threading.RLock()
        self._sess: dict[str, _Session] = {}
        self._since_verify: dict[str, int] = {}

    def register(self, pid: str, recipe: AuthRecipe, probe: LivenessProbe) -> None:
        with self._lock:
            self._sess[pid] = _Session(pid=pid, recipe=recipe, probe=probe)
            self._since_verify[pid] = 0

    def auth_headers(self, pid: str) -> dict[str, str]:
        with self._lock:
            return dict(self._sess[pid].material.headers)

    def epoch(self, pid: str) -> int:
        with self._lock:
            return self._sess[pid].epoch

    def ensure_fresh(self, pid: str, send: SendFn) -> None:
        """Guarantee the session is FRESH before a capture window, re-authing if
        needed. Raises StepUpRequired (human) or ReauthFailed (dead)."""
        s = self._get(pid)
        if not s.logged_in:
            self._login(s, send)
        self._verify(s, send)
        if s.state == SessionState.FRESH:
            return
        if s.state == SessionState.STEPUP:
            raise StepUpRequired(pid)
        for attempt in range(1, self._max_reauth + 1):     # STALE/DEAD -> recover within budget
            try:
                self._login(s, send)
                self._verify(s, send)
            except StepUpRequired:
                raise
            except Exception as e:                          # recipe failure -> keep trying
                self._audit("sess.reauth_error",
                            {"pid": pid, "attempt": attempt, "err": type(e).__name__})
            if s.state == SessionState.FRESH:
                self._audit("sess.reauth_ok", {"pid": pid, "attempt": attempt, "epoch": s.epoch})
                return
            if s.state == SessionState.STEPUP:
                raise StepUpRequired(pid)
        raise ReauthFailed(pid, self._max_reauth)

    def maybe_verify(self, pid: str, send: SendFn) -> None:
        """Periodic re-verification, rate-limited by both time and request count."""
        with self._lock:
            s = self._sess[pid]
            n = self._since_verify.get(pid, 0) + 1
            self._since_verify[pid] = n
            due = (self._clock() - s.last_verified) >= self._verify_s or n >= self._verify_n
        if due:
            self._verify(s, send)
            with self._lock:
                self._since_verify[pid] = 0

    def confidence(self, pid: str) -> tuple[int, bool, float]:
        """(epoch, fresh_now, seconds_since_verified). The transport brackets a
        capture with two reads of this and trusts an exchange only if the epoch
        did not change and the state stayed FRESH across the window."""
        with self._lock:
            s = self._sess[pid]
            return s.epoch, s.state == SessionState.FRESH, self._clock() - s.last_verified

    # -- internals -------------------------------------------------------------------

    def _get(self, pid: str) -> _Session:
        with self._lock:
            return self._sess[pid]

    def _login(self, s: _Session, send: SendFn) -> None:
        mat = s.recipe.login(send)
        with self._lock:
            s.material = mat
            s.epoch += 1                       # new identity epoch invalidates older captures
            s.logged_in = True
            s.state = SessionState.STALE       # not trusted until verified
        self._audit("sess.login", {"pid": s.pid, "epoch": s.epoch})

    def _verify(self, s: _Session, send: SendFn) -> None:
        r = send(s.probe.method, s.probe.url, dict(s.material.headers), None)
        if s.probe.is_stepup(r):
            with self._lock:
                s.state = SessionState.STEPUP
            self._audit("sess.stepup", {"pid": s.pid})
            return
        ok, why = s.probe.holds(r)
        with self._lock:
            s.state = SessionState.FRESH if ok else SessionState.DEAD
            s.last_verified = self._clock()
        self._audit("sess.verify", {"pid": s.pid, "state": s.state, "why": why})
