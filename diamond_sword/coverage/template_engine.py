"""Fold concrete URLs into a bounded set of path TEMPLATES, and detect traps.

This is the "address" side of the instance/template boundary. ``fingerprint`` is the
"content" side (page structure). Both answer one question — *is this a new template or
just another instance of one we've seen?* — and the crawler dedups on both. They live in
the same unit (the coverage seam) because they are two sides of the same boundary.

Why this is the load-bearing core of the whole tool
---------------------------------------------------
A giant site has effectively unbounded *instances* (``/orders/1``, ``/orders/2``, ...) but
a bounded set of *templates* (``/orders/{id}``). Coverage of every template is finite and
achievable; coverage of every instance is neither. So the giant collapses here, from
millions of URLs to hundreds of templates, or it never collapses at all.

Grounding (bug-bounty reality, verified 2026-10-03)
---------------------------------------------------
- Authorization bugs hide behind identifiers in the path and in the JSON body: sequential
  numeric ids, UUIDs, Mongo ObjectIds / git SHAs (hex), opaque base64/nanoid tokens, and
  GitLab's sequential ``gid`` numbers. The id *scheme* matters downstream: a sequential
  ``{num}`` is enumerable (juicy IDOR), a ``{uuid}`` is not. So placeholders are TYPED, not
  a single ``{id}`` — the type feeds triage and the object factory (they track
  sequential/uuid/gid id patterns).
- Infinite surface ("traps") is the classic crawler failure on giants: calendars, infinite
  scroll, and pagination all manifest the same way — *one template, endless instances*. The
  universal guard is therefore "cap distinct instances per template", with a tighter,
  clearer cap for the obvious pagination/offset query keys.

Design decisions
----------------
- Segment classification is *intrinsic* (by the segment's own shape), not learned from a
  corpus, because the crawler must dedup WHILE it walks — it cannot wait for a post-pass.
  The rules are deliberately conservative and high-precision: a route name that merely looks
  wordy (``/documentation``, ``/api/v1``, ``/users/me``) stays literal; only segments that
  carry real identifier signal collapse. Golden + differential tests pin the exact rules so
  a self-consistent weakening (widen a rule, drop a guard) is caught.
- For a security tool, *under*-coverage (merging two genuinely distinct surfaces) is worse
  than a little *over*-coverage (visiting a near-duplicate), so the template key is kept at
  the honest surface granularity ``(method, path_template, sorted query keys)`` — method and
  the set of query keys change the surface; query *values* do not.

Pure, deterministic, standard library only. No network, no randomness, no clock.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from ..legal.scope_parser import remove_dot_segments  # reuse the reviewed dot-segment logic

__all__ = [
    "PH_NUM",
    "PH_UUID",
    "PH_HEX",
    "PH_DATE",
    "PH_TOKEN",
    "PAGINATION_KEYS",
    "classify_segment",
    "path_template",
    "TemplateConfig",
    "Observation",
    "TemplateMap",
]

# Typed placeholders. The braces make them unmistakable in a template and impossible to
# collide with a real (brace-free) path segment.
PH_NUM = "{num}"
PH_UUID = "{uuid}"
PH_HEX = "{hex}"
PH_DATE = "{date}"
PH_TOKEN = "{token}"

# Query keys that drive paging/offset. Treating a key as pagination only means its distinct
# values are capped sooner with a clearer reason; 20 distinct values of any one param is
# already ample authz coverage, so a slightly generous set is low-risk and stops traps early.
PAGINATION_KEYS = frozenset(
    {"page", "offset", "start", "cursor", "after", "before", "skip", "p",
     "pagenum", "page_num", "pageno"}
)

# Classification thresholds (named so they are visible, tunable, and mutation-testable).
_HEX_MIN_LEN = 12   # git short-SHA / ObjectId territory; below this, hex-looking words stay literal
_TOKEN_MIN_LEN = 16  # opaque base64/nanoid territory; below this, mixed strings stay literal

_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_NUM_RE = re.compile(r"[0-9]+")
_HEX_RE = re.compile(r"[0-9a-f]+")

_ASCII_LETTERS = frozenset(string.ascii_letters)
_ASCII_DIGITS = frozenset("0123456789")


def _has_ascii_alpha(s: str) -> bool:
    return any(c in _ASCII_LETTERS for c in s)


def _has_ascii_digit(s: str) -> bool:
    return any(c in _ASCII_DIGITS for c in s)


def classify_segment(seg: str) -> str | None:
    """Return the placeholder for a variable-looking path segment, or ``None`` if literal.

    Order matters: most specific shape first. The rules (and why each guard exists):

    - ``{uuid}``  : canonical 8-4-4-4-12 hex. Highest precision, checked first.
    - ``{date}``  : ``YYYY-MM-DD``. Checked before ``{num}`` (a date is not all-digits anyway,
      but keeping it explicit documents intent).
    - ``{num}``   : all ASCII digits (``1021``, a year, a single id). Matched with a regex,
      not ``str.isdigit()``, because ``str.isdigit()`` also accepts Unicode digits.
    - ``{hex}``   : length >= 12 hex that CONTAINS a digit. The length and digit guards keep
      all-letter hex words (``deadbeefcafe``) and short hex-ish words (``cafe``) literal.
    - ``{token}`` : length >= 16 containing BOTH a letter and a digit — opaque base64/nanoid.
      The "both" guard keeps long all-letter route words (``documentationpage``) literal; the
      length guard keeps short mixed strings (``v2``, ``a1``) literal.

    Examples that must stay literal: ``v1``, ``v2``, ``me``, ``settings``, ``documentation``.
    Examples that must collapse: ``1021``, a UUID, a 40-char SHA, ``my-cool-post-12345``.
    """
    if not seg:
        return None
    if _UUID_RE.fullmatch(seg):
        return PH_UUID
    if _DATE_RE.fullmatch(seg):
        return PH_DATE
    if _NUM_RE.fullmatch(seg):
        return PH_NUM
    low = seg.lower()
    if len(low) >= _HEX_MIN_LEN and _HEX_RE.fullmatch(low) and _has_ascii_digit(low):
        return PH_HEX
    if len(seg) >= _TOKEN_MIN_LEN and _has_ascii_alpha(seg) and _has_ascii_digit(seg):
        return PH_TOKEN
    return None


def path_template(path: str) -> tuple[str, int]:
    """Return ``(template, depth)`` for a URL path.

    ``.``/``..`` are removed first (reusing the scope parser's RFC-3986 logic, so an attacker
    cannot dodge dedup with ``/orders/./1`` or ``/a/../orders/1``), then each segment is
    classified. ``depth`` is the number of path segments — the crawler caps on it so a
    trap that keeps nesting is cut. The template drops a trailing slash (``/orders/`` and
    ``/orders`` are the same surface); the root stays ``/``.
    """
    norm = remove_dot_segments(path or "/")
    segs = [s for s in norm.split("/") if s]
    depth = len(segs)
    if not segs:
        return "/", 0
    out = [classify_segment(s) or s for s in segs]
    return "/" + "/".join(out), depth


@dataclass(frozen=True)
class TemplateConfig:
    """Caps that keep a giant site finite. Defaults are safety ceilings, not visit targets:
    the crawler may visit far fewer instances per template; these only stop runaway."""

    max_depth: int = 12
    max_instances_per_template: int = 50
    max_values_per_pagination_key: int = 20


@dataclass(frozen=True)
class Observation:
    """The verdict for one observed URL."""

    url: str
    method: str
    template_key: str
    path_template: str
    query_keys: tuple[str, ...]
    is_new_template: bool
    enqueue: bool
    is_trap: bool
    reason: str  # see TemplateMap.observe for the full set of reason codes


class TemplateMap:
    """Collapses observed URLs into templates and decides enqueue/skip for the crawler.

    Stateful across a crawl (and the state is exactly what a crawler would checkpoint): for
    each template key, the set of concrete instances already seen; for each
    (template, pagination-key), the distinct values seen; and the set of templates found to
    be traps. All inputs are untrusted URLs and are treated as data.
    """

    def __init__(self, config: TemplateConfig | None = None) -> None:
        self.config = config or TemplateConfig()
        self._templates: dict[str, set[str]] = {}
        self._pag_values: dict[tuple[str, str], set[str]] = {}
        self.traps: set[str] = set()

    @property
    def templates(self) -> tuple[str, ...]:
        """All distinct template keys seen so far, sorted (stable for reporting)."""
        return tuple(sorted(self._templates))

    def instance_count(self, template_key: str) -> int:
        return len(self._templates.get(template_key, ()))

    def observe(self, url: str, method: str = "GET") -> Observation:
        """Classify one URL. Reason codes:

        - ``ENQUEUE_NEW_TEMPLATE`` — first time this template is seen; visit it.
        - ``ENQUEUE_NEW_INSTANCE`` — known template, a new concrete instance under the caps.
        - ``DUPLICATE_INSTANCE``   — this exact instance was already seen; do not re-crawl.
        - ``DEPTH_EXCEEDED``       — path deeper than ``max_depth``; skip (nesting trap guard).
        - ``INSTANCE_CAP``         — template hit its instance ceiling; trap, stop enqueuing.
        - ``PAGINATION_CAP``       — a paging/offset key hit its value ceiling; trap.
        - ``BAD_URL``              — a non-http(s) scheme; never enqueued.
        """
        method = (method or "GET").upper()
        parts = urlsplit(url)
        if parts.scheme and parts.scheme not in ("http", "https"):
            return Observation(url, method, "", "", (), False, False, False, "BAD_URL")

        raw_path = parts.path or "/"
        tmpl, depth = path_template(raw_path)
        q_items = parse_qsl(parts.query, keep_blank_values=True)
        query_keys = tuple(sorted({k for k, _ in q_items}))
        template_key = f"{method} {tmpl}" + (("?" + ",".join(query_keys)) if query_keys else "")
        is_new_template = template_key not in self._templates

        def obs(enqueue: bool, is_trap: bool, reason: str) -> Observation:
            return Observation(url, method, template_key, tmpl, query_keys,
                               is_new_template, enqueue, is_trap, reason)

        if depth > self.config.max_depth:
            self._templates.setdefault(template_key, set())
            return obs(False, False, "DEPTH_EXCEEDED")

        seen = self._templates.setdefault(template_key, set())
        norm_path = remove_dot_segments(raw_path)
        instance_id = norm_path + "?" + "&".join(f"{k}={v}" for k, v in sorted(q_items))

        if instance_id in seen:
            return obs(False, template_key in self.traps, "DUPLICATE_INSTANCE")

        # Pagination/offset keys: a tighter, clearer cap than the generic instance cap.
        for k, v in q_items:
            if k.lower() in PAGINATION_KEYS:
                vals = self._pag_values.setdefault((template_key, k.lower()), set())
                if v not in vals and len(vals) >= self.config.max_values_per_pagination_key:
                    self.traps.add(template_key)
                    return obs(False, True, "PAGINATION_CAP")
                vals.add(v)

        if len(seen) >= self.config.max_instances_per_template:
            self.traps.add(template_key)
            return obs(False, True, "INSTANCE_CAP")

        seen.add(instance_id)
        return obs(True, False, "ENQUEUE_NEW_TEMPLATE" if is_new_template else "ENQUEUE_NEW_INSTANCE")
