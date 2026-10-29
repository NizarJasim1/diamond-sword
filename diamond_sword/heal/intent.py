"""An action is a semantic INTENT (what to do + how to find it + how to know it worked),
never coordinates. Pure data. Stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass

from .locator_cascade import Target

__all__ = ["Postcondition", "Intent"]


@dataclass(frozen=True)
class Postcondition:
    url_contains: str | None = None
    element_appears: Target | None = None
    element_gone: Target | None = None


@dataclass(frozen=True)
class Intent:
    action: str                      # "click" | "fill" | "read" | "navigate"
    target: Target
    value: str | None = None         # for "fill"
    postcondition: Postcondition | None = None
