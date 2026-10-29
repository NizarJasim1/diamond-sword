"""Structural fingerprint of a page — so two renders of the same template collapse to one.

This is the "content" side of the instance/template boundary; ``template_engine`` is the
"address" side. Some sites give distinct templates the same-shaped URL, or the same template
many URL shapes; the structural fingerprint catches "same page, different data" that path
templating alone would miss. The crawler dedups on both.

What makes a fingerprint STABLE across instances and DISCRIMINATING across templates
-----------------------------------------------------------------------------------
Two renders of one template (two order pages, two user profiles) differ only in *content* —
text, ids, amounts, csrf tokens — never in *structure*. So the fingerprint is built from the
structural skeleton only and deliberately throws away everything content-derived:

  KEPT  (structural): the tag tree in document order, each tag with its nesting depth, plus
                      the two attributes that denote an element's *type/role* rather than its
                      data — an ``<input>``'s ``type`` (text vs password vs hidden) and any
                      ``role``. These distinguish a login form from a search form.
  DROPPED (volatile): all text, ids, names, values, ``href``/``src``/``action`` URLs (they
                      carry ids), ``class``/``style`` (CSS-module hashes are unstable),
                      ``data-*`` values, and the whole ``<head>`` (page-specific canonical
                      URLs, og tags) and ``<script>``/``<style>``/``<svg>`` subtrees.

"Stripping the session/nonce/csrf variables" falls out of this for free: those live in
attribute *values*, which are all dropped — while the *presence* of a hidden csrf input still
counts as structure.

Robustness (Tier T3): the input is untrusted HTML. ``html.parser`` is lenient (good for the
messy real web); the token stream is bounded so a hostile or enormous page cannot exhaust
memory; and fingerprinting never raises on bad markup. For a security tool, over-collapsing
(merging two real surfaces) is the worse error, so the skeleton keeps depth and element type
to stay on the discriminating side when in doubt.

Pure, deterministic, standard library only. No network, no randomness, no clock.
"""

from __future__ import annotations

from html.parser import HTMLParser

from ..util.hashing import canonical_json, sha256_hex

__all__ = ["skeleton", "fingerprint", "MAX_TOKENS"]

# Void elements never have an end tag, so they are never pushed on the nesting stack.
_VOID = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
     "meta", "param", "source", "track", "wbr"}
)

# Noise subtrees contribute no stable structure and are skipped whole (head holds
# page-specific meta/canonical URLs; script/style/svg hold volatile or non-DOM content).
_NOISE = frozenset({"head", "script", "style", "noscript", "svg"})

# Attributes kept as a type/role signal. Everything else is volatile and dropped.
_TYPE_TAGS = frozenset({"input", "button", "select", "textarea"})

MAX_TOKENS = 4000  # upper bound on skeleton length; keeps hostile/huge pages bounded


class _SkeletonParser(HTMLParser):
    """Collects a depth-annotated structural token per kept start tag, in document order."""

    def __init__(self, max_tokens: int = MAX_TOKENS) -> None:
        super().__init__(convert_charrefs=True)
        self.tokens: list[str] = []
        self.max_tokens = max_tokens
        self._depth = 0
        self._stack: list[str] = []
        self._skip_depth = 0  # >0 means we are inside a noise subtree

    # Normal start tag (``<div>``) and self-closing start tag (``<img/>``) share the logic;
    # the difference is only whether the tag opens a subtree we must later close.
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag, attrs, void=tag.lower() in _VOID)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag, attrs, void=True)

    def _start(self, tag: str, attrs: list[tuple[str, str | None]], void: bool) -> None:
        tag = tag.lower()
        if self._skip_depth:
            if not void:
                self._skip_depth += 1
            return
        if tag in _NOISE:
            if not void:
                self._skip_depth += 1
            return
        self._emit(tag, attrs)
        if not void:
            self._stack.append(tag)
            self._depth += 1

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self._skip_depth:
            self._skip_depth -= 1
            return
        if self._stack and self._stack[-1] == tag:
            self._stack.pop()
            self._depth -= 1
        elif tag in self._stack:
            # Tolerate misnesting: unwind to the matching open tag.
            while self._stack:
                popped = self._stack.pop()
                self._depth -= 1
                if popped == tag:
                    break

    def _emit(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if len(self.tokens) >= self.max_tokens:
            return
        d = {k.lower(): (v or "") for k, v in attrs}
        extra = ""
        if tag in _TYPE_TAGS and "type" in d:
            extra += "[type=" + d["type"].strip().lower() + "]"
        if "role" in d:
            extra += "[role=" + d["role"].strip().lower() + "]"
        self.tokens.append(f"{self._depth}:{tag}{extra}")


def skeleton(html: str, max_tokens: int = MAX_TOKENS) -> tuple[str, ...]:
    """Return the structural token sequence (depth:tag[type/role]) for ``html``.

    Deterministic and bounded by ``max_tokens``. Exposed alongside :func:`fingerprint` so the
    skeleton is inspectable — you can see exactly why two pages do or do not collapse.
    """
    parser = _SkeletonParser(max_tokens=max_tokens)
    parser.feed(html or "")
    parser.close()
    return tuple(parser.tokens)


def fingerprint(html: str, max_tokens: int = MAX_TOKENS) -> str:
    """SHA-256 hex of the canonicalized structural skeleton of ``html``.

    Same template, different data -> same fingerprint. Different structure -> different
    fingerprint. Reuses the ledger's canonical-JSON + SHA-256 so hashing is identical and
    stable across the whole project.
    """
    return sha256_hex(canonical_json(list(skeleton(html, max_tokens=max_tokens))))
