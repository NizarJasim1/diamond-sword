"""Collect puzzles the deterministic cascade could not solve — WITHOUT stopping the crawl."""
from __future__ import annotations
from typing import Any
from ..util.jsonl import append_jsonl, read_jsonl
__all__ = ["QuestionBus"]


class QuestionBus:
    def __init__(self, path: str) -> None:
        self._path = path

    def ask(self, qid: str, kind: str, **context: Any) -> bool:
        """Record a puzzle (deduped by id). Returns True if newly added. Never blocks."""
        if qid in self.ids():
            return False
        append_jsonl(self._path, {"id": qid, "kind": kind, "context": context})
        return True

    def ids(self) -> set[str]:
        return {str(r["id"]) for r in read_jsonl(self._path).records if r.get("id")}

    def pending(self) -> list[dict[str, Any]]:
        return list(read_jsonl(self._path).records)
