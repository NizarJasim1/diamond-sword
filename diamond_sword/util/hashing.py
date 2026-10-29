"""Deterministic hashing primitives for the tamper-evident ledgers.

Determinism is the whole point: the same record must always canonicalize and hash to the
same value, on any machine, so that a stored hash proves the stored bytes were not altered.

Standard library only.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

__all__ = ["sha256_hex", "canonical_json", "chain_hash", "GENESIS"]

# The chain's starting link (hash of the entry before the first one).
GENESIS = "0" * 64


def sha256_hex(data: str | bytes) -> str:
    """SHA-256 of ``data`` as lowercase hex. Strings are encoded UTF-8."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> str:
    """A canonical JSON string: keys sorted, no insignificant whitespace, UTF-8 kept.

    Sorting keys and fixing separators make the encoding independent of dict insertion
    order, so hashing is stable across runs and machines.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def chain_hash(prev: str, body: str) -> str:
    """Link hash = SHA-256(prev_hash + canonical_body).

    Because ``prev`` is folded into every hash, changing any earlier entry (or reordering
    entries) changes every hash after it — that is what makes the chain tamper-evident.
    """
    return sha256_hex(prev + body)
