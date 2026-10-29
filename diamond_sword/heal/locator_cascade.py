"""Deterministic locator cascade: role -> test-id -> aria/label -> text -> stable-ancestor -> selector.

First strategy that yields EXACTLY ONE match wins; an ambiguous (>1) or empty (0) layer falls
through. Zero AI. Runs over an abstract DomSnapshot (faked in tests, built from Playwright on the
user's machine). Pure, stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["Target", "Element", "DomSnapshot", "LocateResult", "STRATEGY_ORDER",
           "locate", "exists"]

STRATEGY_ORDER = ("role", "test_id", "label", "text", "ancestor", "selector")


@dataclass(frozen=True)
class Target:
    role: str | None = None
    test_id: str | None = None
    label: str | None = None           # aria-label / placeholder / associated label text
    text: str | None = None            # exact visible text
    near: str | None = None            # stable ancestor id/test-id to scope under
    tag: str | None = None
    css: str | None = None
    xpath: str | None = None


@dataclass(frozen=True)
class Element:
    node_id: str
    tag: str
    role: str | None = None
    test_id: str | None = None
    label: str | None = None
    text: str | None = None
    ancestors: tuple[str, ...] = ()
    selectors: frozenset[str] = field(default_factory=frozenset)
    href: str | None = None            # for links; used by the interaction layer (scope + dedup)
    input_type: str | None = None      # for <input>; distinguishes text / submit / checkbox


@dataclass(frozen=True)
class DomSnapshot:
    url: str
    elements: tuple[Element, ...]


@dataclass(frozen=True)
class LocateResult:
    node_id: str | None
    strategy: str
    candidates: int
    reason: str


def _match_fields(e: Element, t: Target) -> bool:
    if t.role is not None and e.role != t.role:
        return False
    if t.test_id is not None and e.test_id != t.test_id:
        return False
    if t.label is not None and e.label != t.label:
        return False
    if t.text is not None and e.text != t.text:
        return False
    if t.tag is not None and e.tag != t.tag:
        return False
    return True


def _unique(matches: list[Element]) -> str | None:
    return matches[0].node_id if len(matches) == 1 else None


def _sel_match(e: Element, t: Target) -> bool:
    return bool((t.css and t.css in e.selectors) or (t.xpath and t.xpath in e.selectors))


def locate(snap: DomSnapshot, t: Target) -> LocateResult:
    els = snap.elements
    if t.role is not None:
        m = [e for e in els if e.role == t.role]
        nid = _unique(m)
        if nid is not None:
            return LocateResult(nid, "role", len(m), "ok")
    if t.test_id is not None:
        m = [e for e in els if e.test_id == t.test_id]
        nid = _unique(m)
        if nid is not None:
            return LocateResult(nid, "test_id", len(m), "ok")
    if t.label is not None:
        m = [e for e in els if e.label == t.label]
        nid = _unique(m)
        if nid is not None:
            return LocateResult(nid, "label", len(m), "ok")
    if t.text is not None:
        m = [e for e in els if e.text == t.text]
        nid = _unique(m)
        if nid is not None:
            return LocateResult(nid, "text", len(m), "ok")
    if t.near is not None:
        scope = [e for e in els if t.near in e.ancestors]
        m = [e for e in scope if _match_fields(e, t)]
        nid = _unique(m)
        if nid is not None:
            return LocateResult(nid, "ancestor", len(m), "ok")
    if t.css is not None or t.xpath is not None:
        m = [e for e in els if _sel_match(e, t)]
        nid = _unique(m)
        if nid is not None:
            return LocateResult(nid, "selector", len(m), "ok")
    return LocateResult(None, "none", 0, "not_found_or_ambiguous")


def exists(snap: DomSnapshot, t: Target) -> bool:
    """True if ANY set strategy finds at least one element (used by postconditions)."""
    els = snap.elements
    checks: list[bool] = []
    if t.role is not None:
        checks.append(any(e.role == t.role for e in els))
    if t.test_id is not None:
        checks.append(any(e.test_id == t.test_id for e in els))
    if t.label is not None:
        checks.append(any(e.label == t.label for e in els))
    if t.text is not None:
        checks.append(any(e.text == t.text for e in els))
    if t.near is not None:
        scope = [e for e in els if t.near in e.ancestors]
        checks.append(any(_match_fields(e, t) for e in scope))
    if t.css is not None or t.xpath is not None:
        checks.append(any(_sel_match(e, t) for e in els))
    return any(checks) if checks else False
