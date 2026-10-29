"""Turn a DOM snapshot into the set of interactive controls worth exercising, each a semantic
:class:`ActionCandidate` (an intent the locator cascade can resolve + a stable signature + a
mutation hint for ROE).

Classification is intrinsic (by the element's own tag/role/type), never learned, because the
explorer must decide WHILE it walks. A control that merely *reads* (a link, a plain button) is
marked non-mutating; a control that *changes state* (submit, a verb-labelled button) is flagged
so ROE gates it and destructive ones are denied. Probe values for form fields are harmless and
deterministic \u2014 they exist only to exercise the form so its traffic is captured.

Pure, deterministic, standard library only.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urldefrag, urljoin

from ..heal.locator_cascade import DomSnapshot, Element, Target
from . import action as A

__all__ = ["ActionCandidate", "interactive_elements", "INTERACTIVE_ROLES", "MUTATING_VERBS"]

INTERACTIVE_ROLES = frozenset({
    "button", "link", "menuitem", "menuitemcheckbox", "menuitemradio", "tab",
    "checkbox", "switch", "radio", "option", "combobox", "searchbox", "textbox",
})
_CLICK_TAGS = frozenset({"a", "button"})
_FILL_TAGS = frozenset({"input", "textarea"})
_SELECT_TAGS = frozenset({"select"})
# input types that are not free-text fields
_NON_TEXT_INPUT = frozenset({"submit", "button", "reset", "file", "image", "hidden",
                             "checkbox", "radio"})
_TOGGLE_ROLES = frozenset({"checkbox", "switch", "radio"})

# Verbs that signal a state change (ROE then splits these into consent vs. destructive-deny).
MUTATING_VERBS = frozenset({
    "save", "create", "update", "add", "submit", "apply", "send", "post", "upload",
    "confirm", "buy", "pay", "checkout", "delete", "remove", "edit", "new", "invite",
    "transfer", "withdraw", "deactivate", "disable", "enable", "reset", "change", "publish",
})

_TOKEN = re.compile(r"[^a-z0-9]+")
_SLUG = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class ActionCandidate:
    signature: str
    ui: A.UiAction
    label: str
    href: str | None
    mutating: bool
    role: str | None
    tag: str


def _tokens(*vals: str | None) -> set[str]:
    out: set[str] = set()
    for v in vals:
        if v:
            out |= {t for t in _TOKEN.split(v.lower()) if t}
    return out


def _is_interactive(e: Element) -> bool:
    return (e.tag in _CLICK_TAGS or e.tag in _FILL_TAGS or e.tag in _SELECT_TAGS
            or e.role in INTERACTIVE_ROLES)


def _abs_href(base: str, href: str | None) -> str | None:
    if not href:
        return None
    return urldefrag(urljoin(base, href))[0]


def _label_of(e: Element) -> str:
    for v in (e.text, e.label, e.test_id):
        if v and v.strip():
            return v.strip()
    return f"<{e.tag}{(' role=' + e.role) if e.role else ''}>"


def _probe_value(e: Element) -> str:
    """A harmless, deterministic value to exercise a field (never real or sensitive data)."""
    hint = f"{e.test_id or ''} {e.label or ''} {e.input_type or ''}".lower()
    if "email" in hint:
        return "ds-probe@example.test"
    if "pass" in hint:
        return "Ds-Probe-123!"
    if any(k in hint for k in ("phone", "tel", "mobile")):
        return "5550100"
    if any(k in hint for k in ("number", "amount", "qty", "age", "count")):
        return "1"
    if "date" in hint:
        return "2025-01-01"
    if "url" in hint:
        return "https://example.test/ds"
    if any(k in hint for k in ("search", "query")):
        return "ds"
    return "ds-probe"


def _target(e: Element) -> Target:
    return Target(
        role=e.role, test_id=e.test_id, label=e.label, text=e.text, tag=e.tag,
        near=(e.ancestors[-1] if e.ancestors else None),
        css=(next(iter(sorted(e.selectors))) if e.selectors else None),
    )


def _candidate(snap: DomSnapshot, e: Element) -> ActionCandidate | None:
    if not _is_interactive(e):
        return None
    it = (e.input_type or "").lower()
    href = _abs_href(snap.url, e.href)

    if e.tag in _FILL_TAGS:
        if e.tag == "input" and it in _NON_TEXT_INPUT:
            if it in ("checkbox", "radio"):
                kind, value, mutating = A.CLICK, None, False
            elif it in ("submit", "button", "image"):
                kind, value, mutating = A.CLICK, None, True
            else:  # reset / file / hidden: never exercise
                return None
        else:
            kind, value, mutating = A.FILL, _probe_value(e), False
    elif e.tag in _SELECT_TAGS or e.role == "combobox":
        kind, value, mutating = A.SELECT, None, False
    elif e.role in _TOGGLE_ROLES or it in ("checkbox", "radio"):
        kind, value, mutating = A.CLICK, None, False
    else:
        kind, value = A.CLICK, None
        mutating = it == "submit" or bool(_tokens(e.text, e.label, e.test_id) & MUTATING_VERBS)

    t = _target(e)
    sig = A.action_signature(kind, t, href)
    ui = A.UiAction(kind=kind, target=t, value=value, url=href if kind == A.CLICK else None)
    return ActionCandidate(sig, ui, _label_of(e), href, mutating, e.role, e.tag)


def interactive_elements(snap: DomSnapshot) -> list[ActionCandidate]:
    """All distinct interactive controls on a screen, de-duplicated by signature (so three
    identical rows yield one candidate), in document order."""
    out: list[ActionCandidate] = []
    seen: set[str] = set()
    for e in snap.elements:
        cand = _candidate(snap, e)
        if cand is None or cand.signature in seen:
            continue
        seen.add(cand.signature)
        out.append(cand)
    return out
