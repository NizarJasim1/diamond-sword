"""Enforcement of the ROE verdict at the moment of an action.

This is the "enforce" side of the action-permission boundary (``roe`` is the "define"
side). It turns a :class:`~diamond_sword.legal.roe.RoeDecision` into a concrete
:class:`Grant`: proceed or not, and whether it must be a dry run.

The human-in-the-loop is fail-closed: a CONSENT verdict needs an approver to say yes, and
the default approver says no. So if no human is wired in, mutations never happen — exactly
what we want for an unattended run. ALLOW runs automatically; DENY never asks anyone.

Every grant is handed to a :class:`GrantSink`, so the audit ledger (built later) can record
the full action-permission trail with no change here.

Pure, deterministic, standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol, runtime_checkable

from .roe import Action, Mode, RoeDecision, RoePolicy, evaluate

__all__ = [
    "Grant",
    "GrantReason",
    "Approver",
    "DenyingApprover",
    "AutoApprover",
    "CallbackApprover",
    "GrantSink",
    "ListSink",
    "ConsentGate",
]


class GrantReason:
    CONSENT_APPROVED = "CONSENT_APPROVED"
    CONSENT_DENIED = "CONSENT_DENIED"


@dataclass(frozen=True)
class Grant:
    """The final word on one action: whether it proceeds, and whether only as a dry run."""

    proceed: bool
    dry_run: bool
    reason: str
    mode: str
    decision: RoeDecision

    def __bool__(self) -> bool:
        return self.proceed


@runtime_checkable
class Approver(Protocol):
    """Decides a CONSENT action. The real one prompts the human; defaults deny."""

    def approve(self, action: Action, decision: RoeDecision) -> bool: ...


class DenyingApprover:
    """Fail-closed default: never approve a mutation without an explicit human yes."""

    def approve(self, action: Action, decision: RoeDecision) -> bool:
        return False


class AutoApprover:
    """A fixed answer, for tests and for an explicit --yes/--no run mode."""

    def __init__(self, answer: bool) -> None:
        self._answer = answer

    def approve(self, action: Action, decision: RoeDecision) -> bool:
        return self._answer


class CallbackApprover:
    """Wraps a callable (e.g. an interactive CLI prompt) as an Approver."""

    def __init__(self, fn: Callable[[Action, RoeDecision], bool]) -> None:
        self._fn = fn

    def approve(self, action: Action, decision: RoeDecision) -> bool:
        return bool(self._fn(action, decision))


class GrantSink(Protocol):
    def record(self, grant: Grant, action: Action) -> None: ...


class ListSink:
    """In-memory sink for tests and as the audit-ledger seam."""

    def __init__(self) -> None:
        self.grants: list[Grant] = []

    def record(self, grant: Grant, action: Action) -> None:
        self.grants.append(grant)


class _NullSink:
    def record(self, grant: Grant, action: Action) -> None:  # pragma: no cover - trivial
        return None


class ConsentGate:
    """Authorizes actions by combining the ROE policy with a fail-closed consent step."""

    def __init__(
        self,
        policy: RoePolicy,
        approver: Approver | None = None,
        sink: GrantSink | None = None,
    ) -> None:
        self._policy = policy
        self._approver: Approver = approver if approver is not None else DenyingApprover()
        self._sink: GrantSink = sink if sink is not None else _NullSink()

    def authorize(self, action: Action, now_hour: int | None = None) -> Grant:
        """Return the :class:`Grant` for ``action`` and record it to the sink."""
        decision = evaluate(self._policy, action, now_hour)
        grant = self._resolve(action, decision)
        self._sink.record(grant, action)
        return grant

    def _resolve(self, action: Action, decision: RoeDecision) -> Grant:
        if decision.mode == Mode.ALLOW:
            return Grant(True, decision.dry_run, decision.reason, decision.mode, decision)

        if decision.mode == Mode.DENY:
            # Never ask anyone about a forbidden action.
            return Grant(False, False, decision.reason, decision.mode, decision)

        # CONSENT: a human must say yes; the default approver says no (fail-closed).
        approved = self._approver.approve(action, decision)
        if approved:
            return Grant(True, decision.dry_run, GrantReason.CONSENT_APPROVED, decision.mode, decision)
        return Grant(False, decision.dry_run, GrantReason.CONSENT_DENIED, decision.mode, decision)
