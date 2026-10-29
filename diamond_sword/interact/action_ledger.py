"""Durable interaction progress \u2014 so an interrupted exploration resumes with nothing lost and
never re-does an action it already tried.

Event-sourced, exactly like :mod:`diamond_sword.heal.coverage_ledger`: every step appends one
small JSONL event; the current state is rebuilt by replaying the log; a crash-truncated final
line is dropped on replay. The coverage of an exploration = the set of ``(state_fingerprint,
action_signature)`` pairs attempted.

Events:
- ``state``   : a state fingerprint was observed (data: fp, url?)
- ``action``  : an action was attempted (data: state, sig, kind, performed, grant)
- ``trap``    : a state was capped/trapped (data: fp, reason)
- ``question``: a control the cascade could not resolve (data: qid)

Standard library only; deterministic.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..util.jsonl import append_jsonl, read_jsonl

__all__ = ["ActionLedger", "ActionState", "rebuild_actions"]


class ActionLedger:
    """Append-only interaction-progress log for one exploration."""

    def __init__(self, path: str) -> None:
        self._path = path

    def record(self, event: str, **data: Any) -> None:
        append_jsonl(self._path, {"event": event, "data": data})

    def mark_state(self, fp: str, url: str | None = None) -> None:
        self.record("state", fp=fp, url=url)

    def mark_action(self, state: str, sig: str, kind: str, performed: bool, grant: str) -> None:
        self.record("action", state=state, sig=sig, kind=kind, performed=performed, grant=grant)

    def mark_trap(self, fp: str, reason: str) -> None:
        self.record("trap", fp=fp, reason=reason)

    def ask(self, qid: str) -> None:
        self.record("question", qid=qid)

    def state(self) -> "ActionState":
        return rebuild_actions(self._path)


@dataclass
class ActionState:
    """The reconstructed position of an exploration."""

    states: set[str] = field(default_factory=set)
    attempted: set[tuple[str, str]] = field(default_factory=set)   # (state_fp, sig)
    performed: set[tuple[str, str]] = field(default_factory=set)
    traps: set[str] = field(default_factory=set)
    questions: set[str] = field(default_factory=set)
    events: int = 0
    trailing_incomplete: bool = False

    def is_done(self, state_fp: str, sig: str) -> bool:
        return (state_fp, sig) in self.attempted


def rebuild_actions(path: str) -> ActionState:
    """Replay the log at ``path`` and return the current :class:`ActionState`."""
    result = read_jsonl(path)
    st = ActionState(events=len(result.records), trailing_incomplete=result.trailing_incomplete)
    for entry in result.records:
        event = entry.get("event")
        data = entry.get("data") or {}
        if event == "state":
            fp = data.get("fp")
            if fp is not None:
                st.states.add(fp)
        elif event == "action":
            state = data.get("state")
            sig = data.get("sig")
            if state is not None and sig is not None:
                st.attempted.add((state, sig))
                if data.get("performed"):
                    st.performed.add((state, sig))
        elif event == "trap":
            fp = data.get("fp")
            if fp is not None:
                st.traps.add(fp)
        elif event == "question":
            qid = data.get("qid")
            if qid is not None:
                st.questions.add(qid)
    return st
