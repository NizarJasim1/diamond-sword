"""Per-principal authenticated context + session-expiry detection (stop -> human -> resume).

The human logs in once; Diamond Sword reuses the saved storage state. If a response looks like an
auth wall (401/403 or a redirect to a login page) the principal is marked unauthenticated and
needs a human. Deterministic; the real storage/login is handled by the capture backend.
"""
from __future__ import annotations
from dataclasses import dataclass
from ..heal.recovery_fsm import _LOGIN_MARKERS
__all__ = ["SessionState", "is_session_expired", "SessionManager"]


@dataclass(frozen=True)
class SessionState:
    principal: str
    authenticated: bool
    storage_ref: str | None = None


def is_session_expired(status: int, final_url: str) -> bool:
    if status in (401, 403):
        return True
    u = (final_url or "").lower()
    return any(m in u for m in _LOGIN_MARKERS)


class SessionManager:
    def __init__(self) -> None:
        self._states: dict[str, SessionState] = {}

    def register(self, principal: str, storage_ref: str | None) -> SessionState:
        st = SessionState(principal, True, storage_ref)   # human has logged in
        self._states[principal] = st
        return st

    def check(self, principal: str, status: int, final_url: str) -> SessionState:
        prev = self._states.get(principal)
        storage = prev.storage_ref if prev else None
        ok = not is_session_expired(status, final_url)
        st = SessionState(principal, ok, storage)
        self._states[principal] = st
        return st

    def need_human(self, principal: str) -> bool:
        st = self._states.get(principal)
        return st is None or not st.authenticated
