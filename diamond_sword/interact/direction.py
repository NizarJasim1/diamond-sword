"""How a human operator (optionally with an LLM assistant) DIRECTS the exploration \u2014 offline, frozen, diffable.

This preserves the project red line (zero AI at runtime, ONYX alone judges): the operator authors a
playbook *before* the run; the explorer only consumes the frozen :class:`Direction` at runtime.
The playbook's optional ``interaction`` block carries:

- ``flows``   : ordered intents to run first (log in, "create a project", "open settings") \u2014 they
  seed the explorer into deep states a blind walk would never reach, and still pass ROE/consent.
- ``priority``: label/href substrings to hunt first (``admin``, ``billing``, ``settings``).
- ``avoid``   : label/href substrings never to click (beyond ROE's destructive list) \u2014 program
  landmines ("Invite", "Leave organization") that are not literally destructive tokens.
- ``seeds``   : URLs to start fresh exploration from.

Pure, deterministic, standard library only.
"""
from __future__ import annotations
from typing import Any

from dataclasses import dataclass

from ..heal.intent import Intent, Postcondition
from ..heal.locator_cascade import Target
from ..oracle.schemas import validate_playbook

__all__ = ["Flow", "Direction"]


@dataclass(frozen=True)
class Flow:
    id: str
    steps: tuple[Intent, ...]


@dataclass(frozen=True)
class Direction:
    flows: tuple[Flow, ...] = ()
    priority: tuple[str, ...] = ()      # lowercase substrings, earlier = higher priority
    avoid: tuple[str, ...] = ()         # lowercase substrings
    seeds: tuple[str, ...] = ()

    def is_avoided(self, label: str, href: str | None) -> bool:
        hay = (label or "").lower() + " " + (href or "").lower()
        return any(a and a in hay for a in self.avoid)

    def priority_rank(self, label: str, href: str | None) -> int:
        """Higher = hunt sooner. 0 means not prioritised."""
        hay = (label or "").lower() + " " + (href or "").lower()
        for i, p in enumerate(self.priority):
            if p and p in hay:
                return len(self.priority) - i
        return 0

    @staticmethod
    def from_doc(doc: dict[str, Any]) -> "Direction":
        """Compile a validated playbook document's ``interaction`` block into a Direction."""
        d = validate_playbook(doc)
        inter = d.get("interaction") or {}
        flows = tuple(
            Flow(f["id"], tuple(_intent(s) for s in (f.get("steps") or [])))
            for f in (inter.get("flows") or [])
        )
        priority = tuple(str(p).lower() for p in (inter.get("priority") or []))
        avoid = tuple(str(a).lower() for a in (inter.get("avoid") or []))
        seeds = tuple(str(s) for s in (inter.get("seeds") or []))
        return Direction(flows=flows, priority=priority, avoid=avoid, seeds=seeds)


def _intent(step: dict[str, Any]) -> Intent:
    target = Target(
        role=step.get("role"), test_id=step.get("test_id"), label=step.get("label"),
        text=step.get("text"), tag=step.get("tag"), css=step.get("css"), xpath=step.get("xpath"),
        near=step.get("near"),
    )
    post: Postcondition | None = None
    if step.get("expect_url") or step.get("expect_text") or step.get("expect_gone"):
        post = Postcondition(
            url_contains=step.get("expect_url"),
            element_appears=Target(text=step["expect_text"]) if step.get("expect_text") else None,
            element_gone=Target(text=step["expect_gone"]) if step.get("expect_gone") else None,
        )
    return Intent(action=str(step.get("action", "click")), target=target,
                  value=step.get("value"), postcondition=post)
