"""Scope parsing and the matching primitives that DEFINE what a program's scope means.

This is the "define" side of the scope boundary. ``scope_guard`` is the "enforce" side
and uses the primitives here. Both are kept in one unit because parsing produces the rules
and guarding applies them: two sides of the same boundary.

Grounding (bug-bounty reality, verified 2026-10-03):
- HackerOne/Bugcrowd scopes mix wildcard hosts (``*.acmepay.example``), exact hosts
  (``api.acmepay.example``), optional URL/path scoping, an out-of-scope host list, and
  out-of-scope vulnerability classes.
- Out-of-scope precedence over in-scope is the real-world rule (``dev.acmepay.example`` is
  excluded even though ``*.acmepay.example`` is in scope).

Security note (the load-bearing part): host matching must reject suffix/substring spoofs
such as ``api.acmepay.example.evil.com`` and ``notacmepay.example``. The classic vulnerability is
a naive ``host.endswith("acmepay.example")``; we never do that — a wildcard match requires a
real label boundary (a leading dot) and the apex is matched only by an exact rule.

Pure, deterministic, standard library only. No network, no randomness.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ScopeError",
    "Asset",
    "Engagement",
    "normalize_host",
    "host_matches",
    "remove_dot_segments",
    "path_matches",
    "load_engagement",
]

# Kinds that denote a reachable network target we are allowed to check URLs against.
# Mobile app-store links and source repos are in a program's scope list but are not
# network hosts we crawl, so they never gate a URL.
NETWORK_KINDS = frozenset({"web", "api", "url"})
_NON_NETWORK_HOST_HINTS = (
    "apps.apple.com",
    "play.google.com",
    "itunes.apple.com",
    "github.com",
)


class ScopeError(ValueError):
    """Raised when an engagement document is structurally malformed."""


@dataclass(frozen=True)
class Asset:
    """One in-scope or out-of-scope entry, compiled from the engagement document.

    ``host`` is a normalized pattern: either an exact host (``api.acmepay.example``) or a
    wildcard (``*.acmepay.example``). ``path`` is an optional normalized path prefix and
    ``port`` an optional required port. ``raw`` keeps the original string for the audit log.
    """

    kind: str
    host: str
    path: str | None = None
    port: int | None = None
    raw: str = ""

    @property
    def is_network(self) -> bool:
        return self.kind in NETWORK_KINDS and bool(self.host)

    @property
    def is_wildcard(self) -> bool:
        return self.host.startswith("*.")


@dataclass(frozen=True)
class Engagement:
    """A parsed, validated program engagement (scope + rules-of-engagement payload)."""

    program: str
    platform: str
    in_scope: tuple[Asset, ...]
    out_scope: tuple[Asset, ...]
    out_classes: tuple[str, ...] = ()
    roe: dict[str, Any] = field(default_factory=dict)

    @property
    def network_in_scope(self) -> tuple[Asset, ...]:
        return tuple(a for a in self.in_scope if a.is_network)

    @property
    def network_out_scope(self) -> tuple[Asset, ...]:
        return tuple(a for a in self.out_scope if a.is_network)


# --------------------------------------------------------------------------------------
# Host normalization and matching — the security-critical primitives.
# --------------------------------------------------------------------------------------

def normalize_host(host: str | None) -> str | None:
    """Return a canonical host (lowercase, no trailing dot, IDNA/ASCII) or ``None``.

    ``None`` means the host is unusable and the caller must fail closed. We reject empty
    labels, consecutive dots, whitespace, and anything that will not survive IDNA encoding.
    A leading ``*.`` is preserved for wildcard patterns; everything after it is normalized.
    """
    if host is None:
        return None
    h = host.strip().lower()
    if not h:
        return None

    wildcard = False
    if h.startswith("*."):
        wildcard = True
        h = h[2:]

    if h.endswith("."):  # strip a single trailing dot (FQDN form)
        h = h[:-1]
    if not h or " " in h or "\t" in h:
        return None
    labels = h.split(".")
    if any(label == "" for label in labels):  # catches "", "a..b", leading/trailing dot
        return None

    # IDNA-encode non-ASCII hosts; plain-ASCII hosts pass through unchanged.
    if not h.isascii():
        try:
            h = h.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            return None

    return ("*." + h) if wildcard else h


def host_matches(pattern: str, host: str) -> bool:
    """True iff ``host`` is covered by the normalized ``pattern``.

    Rules:
    - exact pattern ``a.b.com`` matches only the identical host.
    - wildcard ``*.b.com`` matches any strict subdomain of ``b.com`` at any depth
      (``a.b.com``, ``x.a.b.com``) but NOT the apex ``b.com`` itself.

    Trace of the dangerous cases (why this is not ``endswith("b.com")``):
      pattern ``*.acmepay.example``, host ``api.acmepay.example.evil.com``
        -> base = "acmepay.example"; host.endswith(".acmepay.example")? host ends with
           ".evil.com", so False. Rejected.  ✓
      pattern ``acmepay.example``, host ``notacmepay.example``
        -> exact compare, "notacmepay.example" != "acmepay.example". Rejected.  ✓
      pattern ``*.acmepay.example``, host ``acmepay.example``
        -> host == base, so the strict-subdomain check fails. Rejected (apex needs its
           own exact rule).  ✓
    """
    if not pattern or not host:
        return False
    if pattern.startswith("*."):
        base = pattern[2:]
        if not base:
            return False
        # strict subdomain: a real label boundary (leading dot) and not the apex itself.
        return host != base and host.endswith("." + base)
    return host == pattern


def remove_dot_segments(path: str) -> str:
    """RFC-3986-style dot-segment removal so ``/api/../admin`` normalizes to ``/admin``.

    Prevents a path-scoped rule from being bypassed (or falsely matched) via ``.`` / ``..``.
    """
    if not path:
        return "/"
    out: list[str] = []
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg)
    normalized = "/" + "/".join(out)
    if path.endswith("/") and normalized != "/":
        normalized += "/"
    return normalized


def path_matches(asset_path: str | None, url_path: str) -> bool:
    """True if ``url_path`` falls under the asset's optional path prefix.

    No asset path means no path constraint. A prefix matches on segment boundaries, so
    ``/admin`` does not match ``/administrator`` but does match ``/admin`` and ``/admin/x``.
    """
    if not asset_path:
        return True
    a = remove_dot_segments(asset_path)
    u = remove_dot_segments(url_path or "/")
    if a == "/":
        return True
    a_core = a.rstrip("/")
    return u == a_core or u.startswith(a_core + "/")


# --------------------------------------------------------------------------------------
# Engagement parsing.
# --------------------------------------------------------------------------------------

def _classify_kind(host: str, declared: str | None) -> str:
    if declared:
        return declared
    if any(hint in host for hint in _NON_NETWORK_HOST_HINTS):
        return "other"
    return "web"


def _asset_from_string(raw: str, declared_kind: str | None) -> Asset:
    """Compile a shorthand string entry into an Asset.

    Accepts: ``*.x.com`` | ``api.x.com`` | ``x.com/api`` | ``x.com/api/*`` |
    ``https://app.x.com/path`` | store/repo URLs (classified non-network).
    """
    s = raw.strip()
    if not s:
        raise ScopeError("empty scope entry")

    scheme = ""
    rest = s
    if "://" in s:
        scheme, rest = s.split("://", 1)
        scheme = scheme.lower()

    # split host[:port] from path
    host_port, _, path_part = rest.partition("/")
    path = "/" + path_part if path_part else None
    if path:
        # a trailing wildcard in the scope path ("/api/*") just means the prefix "/api"
        path = path.rstrip("*")
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/") or "/"
        path = remove_dot_segments(path)
        if path == "/":
            path = None

    port: int | None = None
    host_raw = host_port
    if ":" in host_port and not host_port.startswith("["):
        host_raw, _, port_s = host_port.partition(":")
        if port_s:
            try:
                port = int(port_s)
            except ValueError as exc:
                raise ScopeError(f"bad port in scope entry {raw!r}") from exc

    host = normalize_host(host_raw)
    if host is None:
        raise ScopeError(f"unparseable host in scope entry {raw!r}")

    kind = _classify_kind(host.removeprefix("*."), declared_kind)
    return Asset(kind=kind, host=host, path=path, port=port, raw=raw)


def _asset_from_obj(obj: dict[str, Any]) -> Asset:
    declared_kind = obj.get("type") or obj.get("kind")
    host_field = obj.get("host") or obj.get("asset") or obj.get("url") or obj.get("domain")
    if not isinstance(host_field, str) or not host_field.strip():
        raise ScopeError(f"scope object missing a host: {obj!r}")
    # Reuse the string path for host/port/path extraction, then overlay explicit fields.
    base = _asset_from_string(host_field, declared_kind if isinstance(declared_kind, str) else None)
    path = base.path
    if isinstance(obj.get("path"), str) and obj["path"].strip():
        p = remove_dot_segments(obj["path"])
        path = None if p == "/" else p
    port = base.port
    if "port" in obj and obj["port"] is not None:
        try:
            port = int(obj["port"])
        except (ValueError, TypeError) as exc:
            raise ScopeError(f"bad port in scope object {obj!r}") from exc
    return Asset(kind=base.kind, host=base.host, path=path, port=port, raw=base.raw)


def _compile_assets(items: Any, where: str) -> tuple[Asset, ...]:
    if items is None:
        return ()
    if not isinstance(items, list):
        raise ScopeError(f"'{where}' must be a list, got {type(items).__name__}")
    out: list[Asset] = []
    for item in items:
        if isinstance(item, str):
            out.append(_asset_from_string(item, None))
        elif isinstance(item, dict):
            out.append(_asset_from_obj(item))
        else:
            raise ScopeError(f"'{where}' entry must be a string or object, got {type(item).__name__}")
    return tuple(out)


def load_engagement(source: dict[str, Any]) -> Engagement:
    """Validate and compile an engagement document into an :class:`Engagement`.

    Expected shape (fields tolerant, structure strict)::

        {
          "program": "acmepay", "platform": "hackerone",
          "scope": {
            "in":  ["*.acmepay.example", {"type":"api","host":"api.acmepay.example"}],
            "out": ["dev.acmepay.example"],
            "out_classes": ["username enumeration without impact"]
          },
          "roe": { ... }                      # stored for roe.py, not interpreted here
        }

    Raises :class:`ScopeError` on malformed structure. An empty in-scope list is allowed
    and is safe: with nothing in scope the guard denies everything (fail-closed).
    """
    if not isinstance(source, dict):
        raise ScopeError("engagement must be a JSON object")

    scope = source.get("scope", source)  # allow a bare {"in":...,"out":...} too
    if not isinstance(scope, dict):
        raise ScopeError("'scope' must be an object")

    in_items = scope.get("in", scope.get("in_scope"))
    out_items = scope.get("out", scope.get("out_of_scope"))
    out_classes_raw = scope.get("out_classes", scope.get("out_of_scope_classes", []))

    if out_classes_raw is None:
        out_classes_raw = []
    if not isinstance(out_classes_raw, list) or any(not isinstance(c, str) for c in out_classes_raw):
        raise ScopeError("'out_classes' must be a list of strings")

    roe = source.get("roe", {})
    if roe is None:
        roe = {}
    if not isinstance(roe, dict):
        raise ScopeError("'roe' must be an object")

    return Engagement(
        program=str(source.get("program", "")),
        platform=str(source.get("platform", "")),
        in_scope=_compile_assets(in_items, "scope.in"),
        out_scope=_compile_assets(out_items, "scope.out"),
        out_classes=tuple(out_classes_raw),
        roe=roe,
    )
