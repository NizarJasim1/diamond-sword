"""Explicit, deterministic recovery: map a symptom to a recovery action; escalate on repeats.

Symptoms: session expired, modal, rate-limited/WAF, unexpected page, destructive-blocked. No AI.
The browser/network facts arrive as Signals (status, waf, destructive-blocked) plus the snapshot.
Stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .intent import Postcondition
from .invariant import check_postcondition
from .locator_cascade import DomSnapshot

__all__ = ["Symptom", "Action", "Signals", "classify", "recover", "RecoveryFSM"]


class Symptom(str, Enum):
    OK = "OK"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    MODAL = "MODAL"
    RATE_LIMITED = "RATE_LIMITED"
    UNEXPECTED_PAGE = "UNEXPECTED_PAGE"
    DESTRUCTIVE_BLOCKED = "DESTRUCTIVE_BLOCKED"


class Action(str, Enum):
    PROCEED = "PROCEED"
    PAUSE_FOR_HUMAN = "PAUSE_FOR_HUMAN"
    DISMISS_MODAL = "DISMISS_MODAL"
    BACKOFF_RETRY = "BACKOFF_RETRY"
    GOTO_NEAREST_KNOWN = "GOTO_NEAREST_KNOWN"
    ABORT_STEP = "ABORT_STEP"


@dataclass(frozen=True)
class Signals:
    http_status: int = 200
    waf: bool = False
    destructive_blocked: bool = False


_LOGIN_MARKERS = ("login", "signin", "sign-in", "sessions/new", "/auth")
_MODAL_ROLES = ("dialog", "alertdialog")
_MAP = {
    Symptom.OK: Action.PROCEED,
    Symptom.SESSION_EXPIRED: Action.PAUSE_FOR_HUMAN,
    Symptom.MODAL: Action.DISMISS_MODAL,
    Symptom.RATE_LIMITED: Action.BACKOFF_RETRY,
    Symptom.UNEXPECTED_PAGE: Action.GOTO_NEAREST_KNOWN,
    Symptom.DESTRUCTIVE_BLOCKED: Action.ABORT_STEP,
}


def classify(snap: DomSnapshot, post: Postcondition | None, sig: Signals) -> Symptom:
    if sig.destructive_blocked:
        return Symptom.DESTRUCTIVE_BLOCKED
    if sig.http_status == 429 or sig.waf:
        return Symptom.RATE_LIMITED
    if sig.http_status in (401, 403) or any(m in snap.url.lower() for m in _LOGIN_MARKERS):
        return Symptom.SESSION_EXPIRED
    if any(e.role in _MODAL_ROLES for e in snap.elements):
        return Symptom.MODAL
    if post is not None and not check_postcondition(snap, post):
        return Symptom.UNEXPECTED_PAGE
    return Symptom.OK


def recover(symptom: Symptom) -> Action:
    return _MAP[symptom]


class RecoveryFSM:
    """Tracks consecutive non-OK symptoms; a symptom that will not clear escalates to ABORT_STEP."""

    def __init__(self, max_retries: int = 3) -> None:
        self.max_retries = max_retries
        self._last: Symptom | None = None
        self._streak = 0

    def step(self, snap: DomSnapshot, post: Postcondition | None,
             sig: Signals) -> tuple[Symptom, Action, int]:
        sym = classify(snap, post, sig)
        if sym == Symptom.OK:
            self._streak = 0
        elif sym == self._last:
            self._streak += 1
        else:
            self._streak = 1
        self._last = sym
        act = recover(sym)
        if sym in (Symptom.UNEXPECTED_PAGE, Symptom.MODAL) and self._streak > self.max_retries:
            act = Action.ABORT_STEP
        return sym, act, self._streak
