"""Durable crawl progress — so an interrupted run resumes with nothing lost.

This is event-sourced: every step appends one small event to an append-only JSONL file, and
the current state is rebuilt by replaying the log. A crash leaves at most a half-written
final line, which the replay drops; everything completed before it is recovered exactly.

Events (generic ``record(event, **data)``, plus named helpers):
- ``frontier``  : a URL/template added to the to-visit queue (data: ref)
- ``visited``   : a template fingerprint finished (data: fp, ref?)
- ``captured``  : a principal's capture completed (data: principal)
- ``question``  : a puzzle deferred to the batch oracle (data: qid)
- ``answer``    : an oracle answer applied (data: qid)
- ``checkpoint``: a named checkpoint (data: label, ...)

The frontier that still needs work = everything added minus everything visited.

Standard library only; deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..util.jsonl import append_jsonl, read_jsonl

__all__ = ["CoverageLedger", "CoverageState", "rebuild"]


class CoverageLedger:
    """Append-only progress log for one run."""

    def __init__(self, path: str) -> None:
        self._path = path

    def record(self, event: str, **data: Any) -> None:
        append_jsonl(self._path, {"event": event, "data": data})

    # Named helpers (thin wrappers for the common events) ------------------------------
    def add_frontier(self, ref: str) -> None:
        self.record("frontier", ref=ref)

    def mark_visited(self, fingerprint: str, ref: str | None = None) -> None:
        self.record("visited", fp=fingerprint, ref=ref)

    def mark_captured(self, principal: str) -> None:
        self.record("captured", principal=principal)

    def ask(self, qid: str) -> None:
        self.record("question", qid=qid)

    def answer(self, qid: str) -> None:
        self.record("answer", qid=qid)

    def checkpoint(self, label: str, **data: Any) -> None:
        self.record("checkpoint", label=label, **data)

    def state(self) -> "CoverageState":
        return rebuild(self._path)


@dataclass
class CoverageState:
    """The reconstructed position of a crawl."""

    frontier_added: set[str] = field(default_factory=set)
    visited: set[str] = field(default_factory=set)
    principals: set[str] = field(default_factory=set)
    questions: set[str] = field(default_factory=set)
    answers: set[str] = field(default_factory=set)
    checkpoints: list[dict[str, Any]] = field(default_factory=list)
    events: int = 0
    trailing_incomplete: bool = False

    @property
    def pending_frontier(self) -> set[str]:
        """Refs added to the frontier that have not been visited yet."""
        return self.frontier_added - self.visited

    @property
    def open_questions(self) -> set[str]:
        """Questions asked that have no applied answer yet."""
        return self.questions - self.answers


def rebuild(path: str) -> CoverageState:
    """Replay the log at ``path`` and return the current :class:`CoverageState`.

    Tolerant of a crash-truncated final line (it is dropped; ``trailing_incomplete`` is set).
    """
    result = read_jsonl(path)
    state = CoverageState(events=len(result.records), trailing_incomplete=result.trailing_incomplete)
    for entry in result.records:
        event = entry.get("event")
        data = entry.get("data") or {}
        if event == "frontier":
            ref = data.get("ref")
            if ref is not None:
                state.frontier_added.add(ref)
        elif event == "visited":
            fp = data.get("fp")
            if fp is not None:
                state.visited.add(fp)
            ref = data.get("ref")
            if ref is not None:
                state.visited.add(ref)
        elif event == "captured":
            p = data.get("principal")
            if p is not None:
                state.principals.add(p)
        elif event == "question":
            qid = data.get("qid")
            if qid is not None:
                state.questions.add(qid)
        elif event == "answer":
            qid = data.get("qid")
            if qid is not None:
                state.answers.add(qid)
        elif event == "checkpoint":
            state.checkpoints.append(data)
    return state
