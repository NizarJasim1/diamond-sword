"""Tamper-evident audit log — the legal proof that Diamond Sword stayed in bounds.

Every scope decision (from ``scope_guard``) and every action grant (from ``consent_gate``)
is appended to one hash-chained JSONL file. Each entry carries the previous entry's hash, so
altering, deleting, or reordering any entry breaks the chain and :func:`verify` detects it.

This unit does not change the cores it records: it plugs into their existing seams. It
exposes ``decision_sink`` (a ``DecisionSink``) and ``grant_sink`` (a ``GrantSink``), so you
construct the ledger once and hand those to the guard and the consent gate.

Entries are written append-only and flushed to disk, so an interrupted run keeps every
completed entry; a half-written final line is reported by :func:`verify`, not mistaken for
tampering.

Standard library only; deterministic given an injected clock.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

from ..util.hashing import GENESIS, canonical_json, chain_hash
from ..util.jsonl import append_jsonl, read_jsonl

__all__ = ["AuditLedger", "VerifyResult", "verify"]


def _decision_payload(decision: Any) -> dict[str, Any]:
    # Duck-typed so the ledger needn't import the guard's types.
    return {
        "allowed": bool(decision.allowed),
        "reason": getattr(decision, "reason", None),
        "url": getattr(decision, "url", None),
        "host": getattr(decision, "host", None),
        "matched": getattr(decision, "matched", None),
    }


def _grant_payload(grant: Any, action: Any) -> dict[str, Any]:
    return {
        "proceed": bool(grant.proceed),
        "dry_run": bool(getattr(grant, "dry_run", False)),
        "reason": getattr(grant, "reason", None),
        "mode": getattr(grant, "mode", None),
        "action": {
            "kind": getattr(action, "kind", None),
            "method": getattr(action, "method", None),
            "url": getattr(action, "url", None),
            "label": getattr(action, "label", None),
        },
    }


class _DecisionAdapter:
    def __init__(self, ledger: "AuditLedger") -> None:
        self._ledger = ledger

    def record(self, decision: Any) -> None:
        self._ledger.log_scope(decision)


class _GrantAdapter:
    def __init__(self, ledger: "AuditLedger") -> None:
        self._ledger = ledger

    def record(self, grant: Any, action: Any) -> None:
        self._ledger.log_action(grant, action)


class AuditLedger:
    """Append-only, hash-chained audit log for one engagement/run.

    On construction, an existing file is read so the chain CONTINUES from its last hash
    (resume after a restart). ``clock`` is injectable for deterministic tests.
    """

    def __init__(self, path: str, clock: Callable[[], float] | None = None) -> None:
        self._path = path
        self._clock = clock if clock is not None else time.time
        result = read_jsonl(path)
        if result.records:
            last = result.records[-1]
            self._prev = str(last.get("hash", GENESIS))
            self._seq = int(last.get("seq", len(result.records) - 1)) + 1
        else:
            self._prev = GENESIS
            self._seq = 0

    @property
    def decision_sink(self) -> _DecisionAdapter:
        return _DecisionAdapter(self)

    @property
    def grant_sink(self) -> _GrantAdapter:
        return _GrantAdapter(self)

    def log_scope(self, decision: Any) -> str:
        return self._append("scope", _decision_payload(decision))

    def log_action(self, grant: Any, action: Any) -> str:
        return self._append("action", _grant_payload(grant, action))

    def _append(self, kind: str, payload: dict[str, Any]) -> str:
        seq = self._seq
        ts = self._clock()
        body = canonical_json({"seq": seq, "ts": ts, "kind": kind, "payload": payload})
        entry_hash = chain_hash(self._prev, body)
        entry = {"seq": seq, "ts": ts, "kind": kind, "payload": payload,
                 "prev": self._prev, "hash": entry_hash}
        append_jsonl(self._path, entry)
        self._prev = entry_hash
        self._seq = seq + 1
        return entry_hash


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of re-deriving the chain from disk."""

    ok: bool
    count: int
    trailing_incomplete: bool
    broken_at: int | None = None
    reason: str | None = None

    def __bool__(self) -> bool:
        return self.ok


def verify(path: str) -> VerifyResult:
    """Re-derive every hash and link from ``path`` and report whether the chain is intact.

    ``ok`` is True iff every complete entry hashes to its stored hash and links to the one
    before it. A half-written final line sets ``trailing_incomplete`` but does not, by
    itself, make the chain invalid. Any mismatch sets ``ok`` False and ``broken_at`` to the
    first bad entry's sequence index.
    """
    result = read_jsonl(path)
    prev = GENESIS
    for idx, entry in enumerate(result.records):
        try:
            seq = entry["seq"]
            ts = entry["ts"]
            kind = entry["kind"]
            payload = entry["payload"]
            stored_prev = entry["prev"]
            stored_hash = entry["hash"]
        except (KeyError, TypeError):
            return VerifyResult(False, len(result.records), result.trailing_incomplete,
                                broken_at=idx, reason="MALFORMED_ENTRY")

        if stored_prev != prev:
            return VerifyResult(False, len(result.records), result.trailing_incomplete,
                                broken_at=seq, reason="BROKEN_LINK")

        body = canonical_json({"seq": seq, "ts": ts, "kind": kind, "payload": payload})
        recomputed = chain_hash(stored_prev, body)
        if recomputed != stored_hash:
            return VerifyResult(False, len(result.records), result.trailing_incomplete,
                                broken_at=seq, reason="HASH_MISMATCH")
        prev = stored_hash

    return VerifyResult(True, len(result.records), result.trailing_incomplete)
