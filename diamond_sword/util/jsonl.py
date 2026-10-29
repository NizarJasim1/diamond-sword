"""Crash-safe append-only JSONL: one JSON object per line.

Both ledgers are append-only logs on disk. Two properties matter:
- an append is flushed to disk immediately, so an interrupted run loses at most the line
  being written, never earlier ones;
- a reader tolerates a truncated or garbage FINAL line (the one a crash cut off): it returns
  every complete line and reports that the tail was incomplete, instead of raising.

Standard library only.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from collections.abc import Iterator
from typing import Any

__all__ = ["append_jsonl", "read_jsonl", "ReadResult"]


def append_jsonl(path: str, obj: Any) -> None:
    """Append one object as a JSON line to ``path`` (creating parent dirs), flushed to disk."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    line = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
        fh.flush()
        os.fsync(fh.fileno())


@dataclass(frozen=True)
class ReadResult:
    """Parsed records plus whether the file ended on an incomplete/garbage line."""

    records: list[dict[str, Any]]
    trailing_incomplete: bool

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)


def read_jsonl(path: str) -> ReadResult:
    """Read every complete JSON line from ``path``.

    A blank line is skipped. A malformed line that is NOT the last line is also skipped
    (the file is still usable). A malformed LAST line is treated as a crash-truncated write:
    it is dropped and ``trailing_incomplete`` is set. A missing file reads as empty.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            raw_lines = fh.readlines()
    except FileNotFoundError:
        return ReadResult([], False)

    records: list[dict[str, Any]] = []
    trailing_incomplete = False
    last_index = len(raw_lines) - 1
    for i, raw in enumerate(raw_lines):
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, json.JSONDecodeError):
            if i == last_index:
                trailing_incomplete = True
            # a non-final corrupt line is skipped but does not abort the read
            continue
        if isinstance(obj, dict):
            records.append(obj)
    return ReadResult(records, trailing_incomplete)
