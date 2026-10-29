"""
LiveTransport — the single chokepoint every authenticated request passes
through, and the seam where pacing (#5) and session-liveness (#4) become two
sides of one boundary.

Everything that leaves Diamond Sword as a principal goes through one method, so
all guards are enforced in one place and can never be forgotten by a caller:

    scope  ->  ROE  ->  governor.acquire  ->  send (with session auth)
           ->  governor.observe  ->  liveness bracket  ->  capture ledger  ->  audit

THE SEAM, STATED
----------------
A request cannot be *paced* correctly without knowing it is a real authenticated
request, and a capture cannot be *trusted* without knowing the session was alive
across the exact window the governor timed. One object owns both facts, so the
clean/quarantine verdict and the rate decision are made from the same truth —
that is why #4 and #5 are built together rather than bolted on side by side.

Fail-closed throughout: scope deny, ROE deny, a CONSENT-gated mutation, a
step-up challenge, a dead session, or an open circuit all stop the request and
say why, without ever sending blind.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from .governor import AutomationDenied, CircuitOpen, Governor
from .session import ProbeResponse, ReauthFailed, SessionHub, StepUpRequired
from ..capture.ledger import CaptureLedger


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: str
    final_url: str


# send(method, url, headers, body) -> HttpResponse  (urllib / playwright / mitmproxy adapter)
Sender = Callable[[str, str, Mapping[str, str], "str | None"], HttpResponse]


@dataclass
class LiveResult:
    sent: bool
    clean: bool
    status: int
    response: HttpResponse | None
    reason: str              # why not sent / why quarantined, when relevant
    dry_run: bool = False


def _ekey(method: str, url: str) -> str:
    return f"{method.upper()} {urlsplit(url).path or '/'}"


class LiveTransport:
    def __init__(
        self,
        *,
        sender: Sender,
        scope_guard: Any,                  # diamond_sword.legal.scope_guard.ScopeGuard
        roe_policy: Any,                   # diamond_sword.legal.roe.RoePolicy
        governor: Governor,
        sessions: SessionHub,
        ledger: CaptureLedger,
        audit: Callable[[str, dict[str, Any]], None] | None = None,
        now_hour: Callable[[], int] | None = None,
    ) -> None:
        self._send = sender
        self._scope = scope_guard
        self._roe = roe_policy
        self._gov = governor
        self._sx = sessions
        self._ledger = ledger
        self._audit = audit or (lambda k, p: None)
        self._now_hour = now_hour

    # -- the one public entrypoint ---------------------------------------------------

    def request(self, pid: str, method: str, url: str, *,
                body: str | None = None, extra_headers: Mapping[str, str] | None = None,
                mutating: bool | None = None, label: str | None = None,
                grant: Any = None) -> LiveResult:
        """One authenticated request. Reads pass ``grant=None`` and are refused if
        they turn out to mutate. A mutation (object creation/cleanup by the object
        factory) passes a ``Grant`` from the consent gate: scope, session, governor
        and the ledger still apply, but ROE was already adjudicated by the gate, so
        the CONSENT refusal is skipped only for a grant that truly authorizes a real
        (non-dry) write. Scope is never waivable, grant or no grant."""
        from ..legal.roe import Action, Mode, evaluate   # local import: bind to the real ROE API

        host = (urlsplit(url).hostname or "").lower()

        # 1) scope — fail-closed, and NOT waivable by a grant
        dec = self._scope.check(url)
        if not dec:
            self._audit("tx.scope_deny", {"url": url, "reason": dec.reason})
            return LiveResult(False, False, 0, None, f"scope:{dec.reason}")

        # 2) ROE / consent. A real grant (proceed & not dry_run) authorizes the write;
        #    otherwise the ROE verdict decides and CONSENT/dry-run is refused here
        #    (the consent gate owns approval — fail-closed).
        granted = bool(getattr(grant, "proceed", False) and not getattr(grant, "dry_run", False))
        if granted:
            self._audit("tx.granted", {"url": url, "method": method,
                                       "reason": getattr(grant, "reason", "grant")})
        else:
            action = Action(kind="request", method=method, url=url, label=label, mutating=mutating)
            verdict = evaluate(self._roe, action, self._now_hour() if self._now_hour else None)
            if verdict.mode == Mode.DENY:
                self._audit("tx.roe_deny", {"url": url, "reason": verdict.reason})
                return LiveResult(False, False, 0, None, f"roe:{verdict.reason}")
            if verdict.mode == Mode.CONSENT or verdict.dry_run:
                self._audit("tx.dry_run", {"url": url, "method": method, "reason": verdict.reason})
                return LiveResult(False, False, 0, None, f"dry_run:{verdict.reason}", dry_run=True)

        # 3) session must be FRESH before the capture window opens
        try:
            self._sx.ensure_fresh(pid, self._probe_sender())
        except StepUpRequired:
            self._audit("tx.pause_stepup", {"pid": pid})
            return LiveResult(False, False, 0, None, "PAUSE_FOR_HUMAN:stepup")
        except ReauthFailed:
            self._audit("tx.session_dead", {"pid": pid})
            return LiveResult(False, False, 0, None, "session_dead")

        # 4) bracket-open: snapshot confidence, pace, send, observe
        epoch0, fresh0, _ = self._sx.confidence(pid)
        try:
            self._gov.acquire(host, endpoint_key=_ekey(method, url))
        except (AutomationDenied, CircuitOpen) as e:
            return LiveResult(False, False, 0, None, f"governor:{type(e).__name__}")

        headers = {**self._sx.auth_headers(pid), **(extra_headers or {})}
        resp = self._send(method, url, headers, body)
        self._gov.observe(host, resp.status, resp.headers, resp.body, endpoint_key=_ekey(method, url))

        # 5) bracket-close: periodic re-verify, then trust only if epoch held AND still FRESH
        self._sx.maybe_verify(pid, self._probe_sender())
        epoch1, fresh1, _ = self._sx.confidence(pid)
        clean = fresh0 and fresh1 and (epoch0 == epoch1) and resp.status not in (401, 403)

        self._ledger.record(pid=pid, epoch=epoch0, clean=clean,
                            method=method, url=resp.final_url or url, status=resp.status,
                            req_headers=headers, req_body=body,
                            resp_headers=resp.headers, resp_body=resp.body)
        if not clean:
            self._audit("tx.quarantine", {"pid": pid, "url": url, "epoch0": epoch0, "epoch1": epoch1,
                                          "fresh0": fresh0, "fresh1": fresh1, "status": resp.status})
        return LiveResult(True, clean, resp.status, resp, "" if clean else "session_bracket")

    # -- helpers ---------------------------------------------------------------------

    def _probe_sender(self) -> Callable[[str, str, Mapping[str, str], str | None], ProbeResponse]:
        """Adapt the HttpResponse sender to the session module's ProbeResponse.
        Probe/login traffic is still scope-gated and paced, but is NOT bracketed
        (it is how we establish the bracket in the first place)."""
        def probe_send(method: str, url: str, headers: Mapping[str, str],
                       body: str | None) -> ProbeResponse:
            if not self._scope.allowed(url):
                return ProbeResponse(0, {}, "")
            host = (urlsplit(url).hostname or "").lower()
            try:
                self._gov.acquire(host, endpoint_key=_ekey(method, url))
            except (AutomationDenied, CircuitOpen):
                return ProbeResponse(0, {}, "")
            r = self._send(method, url, headers, body)
            self._gov.observe(host, r.status, r.headers, r.body, endpoint_key=_ekey(method, url))
            return ProbeResponse(r.status, r.headers, r.body)
        return probe_send
