"""Interaction primitives and the deterministic identities that make exploring a giant/cyclic
SPA *finite*.

Two boundaries live here, and they are two sides of one seam ("is this control / this screen
something we have already handled?"):

- ``action_signature`` collapses the same logical control across renders. A list of 10 000
  orders has one "Delete" control, not 10 000: ids in the control's identifier are folded to
  ``#`` so ``delete-order-5`` and ``delete-order-6`` share a signature.
- ``state_fingerprint`` collapses the same screen across renders. ``/orders/1`` and
  ``/orders/2`` are one state (URL path TEMPLATE + the value-free structural shape of the
  page), so the explorer visits the *template*, never every instance.

Pure, deterministic, standard library only. No coordinates, no clock, no randomness, no AI.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..coverage.template_engine import path_template
from ..heal.locator_cascade import DomSnapshot, Element, Target
from ..heal.recovery_fsm import Signals
from ..legal.roe import Action as RoeAction
from ..util.hashing import canonical_json, sha256_hex

__all__ = [
    "CLICK", "FILL", "SELECT", "SUBMIT", "NAVIGATE", "UI_KINDS",
    "UiAction", "StateView", "action_signature", "state_fingerprint", "to_roe_action",
]

CLICK = "click"
FILL = "fill"
SELECT = "select"
SUBMIT = "submit"
NAVIGATE = "navigate"
UI_KINDS = frozenset({CLICK, FILL, SELECT, SUBMIT, NAVIGATE})

_DIGITS = re.compile(r"\d+")


@dataclass(frozen=True)
class UiAction:
    """What the driver should DO: a semantic intent (kind + how to find it), never coordinates."""

    kind: str
    target: Target
    value: str | None = None       # for FILL
    url: str | None = None         # resolved href for a link click / NAVIGATE target


@dataclass(frozen=True)
class StateView:
    """A *settled* screen the driver returns: the DOM (for the locator cascade), a structural
    tree hash (DOM-stability + state identity), and the environment signals the recovery FSM
    reads (HTTP status, WAF, destructive-blocked)."""

    snapshot: DomSnapshot
    tree_hash: str
    signals: Signals = Signals()


def _norm(s: str) -> str:
    """Fold digit runs to ``#`` so an id embedded in an identifier does not fragment dedup."""
    return _DIGITS.sub("#", s)


def _ident(target: Target, href: str | None) -> str:
    """The stable identifier of a control, in locator-cascade priority order. For a link the
    href is reduced to a path TEMPLATE so instances of one route collapse to one control."""
    if target.test_id:
        return "tid:" + _norm(target.test_id)
    if target.role and target.text:
        return "role:" + target.role + "|txt:" + _norm(target.text)
    if target.label:
        return "lbl:" + _norm(target.label)
    if target.text:
        return "txt:" + _norm(target.text)
    if href:
        return "href:" + path_template(urlsplit(href).path or "/")[0]
    if target.css:
        return "css:" + target.css
    if target.xpath:
        return "xp:" + target.xpath
    if target.role:
        return "role:" + target.role
    return "tag:" + (target.tag or "?")


def action_signature(kind: str, target: Target, href: str | None = None) -> str:
    """Deterministic 16-hex signature of a control: (kind, tag, role, stable-identifier, scope)."""
    body = canonical_json([kind, target.tag or "", target.role or "",
                           _ident(target, href), target.near or ""])
    return sha256_hex(body)[:16]


def _el_key(e: Element) -> str:
    """Value-free structural key of an element for state fingerprinting (ids folded to ``#``)."""
    tid = _norm(e.test_id) if e.test_id else ""
    return f"{e.tag}|{e.role or ''}|{tid}"


def state_fingerprint(view: "StateView | DomSnapshot") -> str:
    """Fingerprint a screen by URL path TEMPLATE + the multiset of its structural element keys.
    Two renders of the same screen (different ids/values/text) collapse to one state."""
    snap = view.snapshot if isinstance(view, StateView) else view
    tmpl = path_template(urlsplit(snap.url).path or "/")[0]
    keys = sorted(_el_key(e) for e in snap.elements)
    return sha256_hex(canonical_json([tmpl, keys]))[:16]


def to_roe_action(kind: str, label: str, href: str | None, mutating: bool) -> RoeAction:
    """Map a UI candidate to a ROE :class:`Action` so the consent gate can judge it. Both the
    label and the href are passed, so ROE's destructive-token match sees the whole surface (a
    "Delete" button and a ``/pay`` link are both caught)."""
    return RoeAction(kind="ui", method=None, url=href, label=label, mutating=mutating)
