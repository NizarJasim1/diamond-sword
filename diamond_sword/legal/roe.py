"""Rules of Engagement: what Diamond Sword may DO to an in-scope target.

This is the "define" side of the action-permission boundary; ``consent_gate`` is the
"enforce" side. Scope answers *where* (which URL); ROE answers *what* (which action).
They are different boundaries, so they are different units — but within this unit,
policy (here) and the human gate (consent_gate) are the two sides of one boundary.

Every action gets exactly one verdict:
- ALLOW   : safe / read-only -> run automatically.
- CONSENT : mutating but not forbidden -> a human must approve (consent_gate), dry-run first.
- DENY    : forbidden (destructive red line, method not permitted, automation not allowed,
            outside the agreed window) -> never run.

Grounding (the standing red lines for this project):
- read-only by default (passive capture); mutations need explicit consent + dry-run.
- destructive actions are off-limits (we must never damage the target or a victim account).
- respect ``automation_permitted``; respect an agreed time window.

Design choices that keep this safe without over-blocking:
- GET / HEAD / OPTIONS are read-only and allowed even if the URL text contains scary words
  (reading ``/account/delete`` just views a page; the crawl is capture-first anyway).
- The destructive check applies only to *mutating* actions, and ``DELETE`` is always
  destructive.
- Destructive keywords are matched on path/label *tokens* (not raw substrings), so ``/pay``
  is caught but ``/paypal`` and ``/display`` are not.

Pure, deterministic, standard library only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

__all__ = [
    "RoeError",
    "Action",
    "RoePolicy",
    "RoeDecision",
    "Mode",
    "Reason",
    "SAFE_METHODS",
    "MUTATING_METHODS",
    "evaluate",
    "from_engagement",
]

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Destructive signals, matched against path/label tokens (exact token) unless noted.
_DESTRUCTIVE_TOKENS = frozenset({
    "delete", "remove", "destroy", "deactivate", "disable", "drop",
    "logout", "signout", "revoke", "purge", "wipe", "reset", "unsubscribe",
    "withdraw", "transfer", "payout", "refund", "chargeback",
    "pay", "payment", "charge", "checkout", "billing",
    "password", "passwd", "credentials", "credential",
    "2fa", "mfa", "otp", "totp",
})
# A few compound phrases that only read as destructive together.
_DESTRUCTIVE_SUBSTRINGS = (
    "change-email", "change_email", "close-account", "close_account",
    "delete-account", "delete_account", "api-key", "apikey", "access-token",
)
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


class RoeError(ValueError):
    """Raised when the engagement's ROE payload is malformed."""


class Mode:
    ALLOW = "ALLOW"
    CONSENT = "CONSENT"
    DENY = "DENY"


class Reason:
    ALLOW_READ_ONLY = "ALLOW_READ_ONLY"
    ALLOW_WHITELISTED = "ALLOW_WHITELISTED"
    CONSENT_MUTATION = "CONSENT_MUTATION"
    DENY_DESTRUCTIVE = "DENY_DESTRUCTIVE"
    DENY_READ_ONLY_MODE = "DENY_READ_ONLY_MODE"
    DENY_METHOD_NOT_ALLOWED = "DENY_METHOD_NOT_ALLOWED"
    DENY_AUTOMATION_FORBIDDEN = "DENY_AUTOMATION_FORBIDDEN"
    DENY_OUTSIDE_WINDOW = "DENY_OUTSIDE_WINDOW"


@dataclass(frozen=True)
class Action:
    """A thing Diamond Sword might do: an HTTP request or a UI interaction.

    ``kind``: "request" | "ui" | "nav". For requests, ``method`` is set. ``label`` is the
    human/semantic intent for UI actions ("click: Delete account"). ``mutating`` is an
    optional explicit hint that overrides method-based inference.
    """

    kind: str = "request"
    method: str | None = None
    url: str | None = None
    label: str | None = None
    mutating: bool | None = None

    def norm_method(self) -> str | None:
        return self.method.upper() if isinstance(self.method, str) else None


@dataclass(frozen=True)
class RoePolicy:
    """The rules-of-engagement policy, compiled from the engagement document."""

    read_only: bool = True
    automation_permitted: bool = True
    allow_methods: frozenset[str] | None = None
    extra_destructive: tuple[str, ...] = ()
    allow_mutations: tuple[str, ...] = ()        # substrings of url/label that may be mutated
    auto_allow_whitelisted: bool = False          # whitelisted mutations run without asking
    dry_run_default: bool = True
    time_window: tuple[int, int] | None = None    # (start_hour, end_hour), 24h, end exclusive
    max_rps: float | None = None                  # stored for the pacer, not enforced here


@dataclass(frozen=True)
class RoeDecision:
    """One action's verdict: the mode, why, the rule, and whether it must be a dry run."""

    mode: str
    reason: str
    dry_run: bool = False
    rule: str | None = None


# --------------------------------------------------------------------------------------
# Classification helpers.
# --------------------------------------------------------------------------------------

def _haystack(action: Action) -> str:
    return " ".join(p for p in (action.url or "", action.label or "") if p).lower()


def _is_mutating(action: Action) -> bool:
    if action.mutating is not None:
        return action.mutating
    if action.kind == "request":
        return action.norm_method() in MUTATING_METHODS
    return False  # a plain navigation/click is read-only unless explicitly flagged


def _is_destructive(action: Action, extra: tuple[str, ...]) -> bool:
    if action.norm_method() == "DELETE":
        return True
    hay = _haystack(action)
    if not hay:
        return False
    tokens = {t for t in _TOKEN_SPLIT.split(hay) if t}
    if tokens & _DESTRUCTIVE_TOKENS:
        return True
    needles = _DESTRUCTIVE_SUBSTRINGS + tuple(e.lower() for e in extra)
    return any(sub in hay for sub in needles)


def _whitelisted(action: Action, policy: RoePolicy) -> bool:
    if not policy.allow_mutations:
        return False
    hay = _haystack(action)
    return any(w.lower() in hay for w in policy.allow_mutations)


def _in_window(window: tuple[int, int], now_hour: int) -> bool:
    start, end = window
    if start <= end:
        return start <= now_hour < end
    return now_hour >= start or now_hour < end  # overnight window, e.g. (22, 6)


# --------------------------------------------------------------------------------------
# The verdict.
# --------------------------------------------------------------------------------------

def evaluate(policy: RoePolicy, action: Action, now_hour: int | None = None) -> RoeDecision:
    """Return the :class:`RoeDecision` for ``action`` under ``policy``.

    ``now_hour`` (0-23) is injected by the caller so the time-window check stays
    deterministic and testable; if the policy sets no window it is ignored.
    """
    if not policy.automation_permitted:
        return RoeDecision(Mode.DENY, Reason.DENY_AUTOMATION_FORBIDDEN)

    if policy.time_window is not None and now_hour is not None:
        if not _in_window(policy.time_window, now_hour):
            return RoeDecision(Mode.DENY, Reason.DENY_OUTSIDE_WINDOW, rule=str(policy.time_window))

    if policy.allow_methods is not None and action.kind == "request":
        if action.norm_method() not in policy.allow_methods:
            return RoeDecision(Mode.DENY, Reason.DENY_METHOD_NOT_ALLOWED, rule=action.norm_method())

    if not _is_mutating(action):
        return RoeDecision(Mode.ALLOW, Reason.ALLOW_READ_ONLY)

    # From here the action mutates state.
    if _is_destructive(action, policy.extra_destructive):
        return RoeDecision(Mode.DENY, Reason.DENY_DESTRUCTIVE)

    if _whitelisted(action, policy):
        if policy.auto_allow_whitelisted:
            return RoeDecision(Mode.ALLOW, Reason.ALLOW_WHITELISTED, dry_run=policy.dry_run_default)
        return RoeDecision(Mode.CONSENT, Reason.CONSENT_MUTATION, dry_run=policy.dry_run_default)

    if policy.read_only:
        return RoeDecision(Mode.DENY, Reason.DENY_READ_ONLY_MODE)

    return RoeDecision(Mode.CONSENT, Reason.CONSENT_MUTATION, dry_run=policy.dry_run_default)


# --------------------------------------------------------------------------------------
# Parsing the engagement's roe payload.
# --------------------------------------------------------------------------------------

def _as_bool(value: Any, default: bool, key: str) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise RoeError(f"roe.{key} must be a boolean")
    return value


def from_engagement(roe: dict[str, Any] | None) -> RoePolicy:
    """Compile an engagement ``roe`` object into a :class:`RoePolicy` (safe defaults).

    Unknown keys are ignored; wrong types raise :class:`RoeError`. Defaults are the strict,
    safe ones: read-only, automation permitted, dry-run on, nothing whitelisted.
    """
    if roe is None:
        return RoePolicy()
    if not isinstance(roe, dict):
        raise RoeError("roe must be an object")

    allow_methods_raw = roe.get("allow_methods")
    allow_methods: frozenset[str] | None = None
    if allow_methods_raw is not None:
        if not isinstance(allow_methods_raw, list) or any(not isinstance(m, str) for m in allow_methods_raw):
            raise RoeError("roe.allow_methods must be a list of strings")
        allow_methods = frozenset(m.upper() for m in allow_methods_raw)

    def _str_tuple(key: str) -> tuple[str, ...]:
        raw = roe.get(key, [])
        if raw is None:
            return ()
        if not isinstance(raw, list) or any(not isinstance(x, str) for x in raw):
            raise RoeError(f"roe.{key} must be a list of strings")
        return tuple(raw)

    window_raw = roe.get("time_window")
    time_window: tuple[int, int] | None = None
    if window_raw is not None:
        if (not isinstance(window_raw, (list, tuple)) or len(window_raw) != 2
                or not all(isinstance(h, int) and 0 <= h <= 24 for h in window_raw)):
            raise RoeError("roe.time_window must be [start_hour, end_hour] in 0..24")
        time_window = (int(window_raw[0]), int(window_raw[1]))

    max_rps_raw = roe.get("max_rps")
    if max_rps_raw is not None and not isinstance(max_rps_raw, (int, float)):
        raise RoeError("roe.max_rps must be a number")

    return RoePolicy(
        read_only=_as_bool(roe.get("read_only"), True, "read_only"),
        automation_permitted=_as_bool(roe.get("automation_permitted"), True, "automation_permitted"),
        allow_methods=allow_methods,
        extra_destructive=_str_tuple("extra_destructive"),
        allow_mutations=_str_tuple("allow_mutations"),
        auto_allow_whitelisted=_as_bool(roe.get("auto_allow_whitelisted"), False, "auto_allow_whitelisted"),
        dry_run_default=_as_bool(roe.get("dry_run_default"), True, "dry_run_default"),
        time_window=time_window,
        max_rps=float(max_rps_raw) if max_rps_raw is not None else None,
    )
