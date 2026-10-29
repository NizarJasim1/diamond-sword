"""Postcondition checks + structural DOM stability (three identical tree hashes = settled).

A failed postcondition means recover, not crash. Pure, stdlib only.
"""
from __future__ import annotations

from collections.abc import Sequence

from .intent import Postcondition
from .locator_cascade import DomSnapshot, exists

__all__ = ["check_postcondition", "is_stable", "StabilityTracker"]


def check_postcondition(snap: DomSnapshot, post: Postcondition) -> bool:
    if post.url_contains is not None and post.url_contains not in snap.url:
        return False
    if post.element_appears is not None and not exists(snap, post.element_appears):
        return False
    if post.element_gone is not None and exists(snap, post.element_gone):
        return False
    return True


def is_stable(hashes: Sequence[str], required: int = 3) -> bool:
    """True once the last ``required`` tree hashes are all equal (DOM settled)."""
    if len(hashes) < required:
        return False
    return len(set(hashes[-required:])) == 1


class StabilityTracker:
    def __init__(self, required: int = 3) -> None:
        self.required = required
        self._hashes: list[str] = []

    def push(self, tree_hash: str) -> bool:
        self._hashes.append(tree_hash)
        return is_stable(self._hashes, self.required)
