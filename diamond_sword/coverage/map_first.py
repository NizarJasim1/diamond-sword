"""Acquire the KNOWN surface before walking it: robots, sitemap, OpenAPI, GraphQL, JS mining.

Every function PARSES provided text/bytes; nothing fetches (fetching is an injected adapter in
the crawler). Untrusted input is data: JSON via json.loads, XML sitemaps via a <loc> regex
(deliberately NOT an XML parser, to avoid entity-expansion / XXE on hostile input). Stdlib only.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

__all__ = ["SeedEntry", "parse_robots", "parse_sitemap", "parse_openapi",
           "parse_graphql_introspection", "mine_js", "MapFirst"]

_HTTP_METHODS = frozenset({"get", "put", "post", "delete", "patch", "head", "options", "trace"})
_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE | re.DOTALL)
_JS_PATH_RE = re.compile(r"""['"](/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,300})['"]""")
_JS_URL_RE = re.compile(r"""https?://[^\s'"<>()]{1,300}""")


@dataclass(frozen=True)
class SeedEntry:
    ref: str          # a path or absolute URL
    method: str       # GET by default
    source: str       # robots | sitemap | openapi | graphql | js


def parse_robots(text: str) -> tuple[frozenset[str], frozenset[str]]:
    """Return (paths, sitemaps). Disallow/Allow paths are seeds; Sitemap lines are follow-ups."""
    paths: set[str] = set()
    sitemaps: set[str] = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if not val:
            continue
        if key in ("disallow", "allow") and val.startswith("/"):
            paths.add(val.rstrip("*") or "/")
        elif key == "sitemap":
            sitemaps.add(val)
    return frozenset(paths), frozenset(sitemaps)


def parse_sitemap(xml_text: str) -> tuple[frozenset[str], frozenset[str]]:
    """Return (page_urls, child_sitemaps). A <sitemapindex> yields child sitemaps; a urlset pages."""
    locs = [m.group(1) for m in _LOC_RE.finditer(xml_text or "")]
    if re.search(r"<\s*sitemapindex", xml_text or "", re.IGNORECASE):
        return frozenset(), frozenset(locs)
    return frozenset(locs), frozenset()


def _as_obj(data: Any) -> dict[str, Any]:
    if isinstance(data, str):
        data = json.loads(data)
    return data if isinstance(data, dict) else {}


def parse_openapi(data: Any) -> frozenset[tuple[str, str]]:
    """Return {(METHOD, path)} from an OpenAPI/Swagger document (dict or JSON string)."""
    obj = _as_obj(data)
    paths = obj.get("paths")
    out: set[tuple[str, str]] = set()
    if isinstance(paths, dict):
        for path, item in paths.items():
            if not isinstance(path, str) or not path.startswith("/"):
                continue
            if isinstance(item, dict):
                for method in item:
                    if isinstance(method, str) and method.lower() in _HTTP_METHODS:
                        out.add((method.upper(), path))
    return frozenset(out)


def parse_graphql_introspection(data: Any) -> tuple[frozenset[str], frozenset[str]]:
    """Return (query_fields, mutation_fields) from a GraphQL introspection result."""
    obj = _as_obj(data)
    schema = obj.get("data", obj).get("__schema") if isinstance(obj.get("data", obj), dict) else None
    if not isinstance(schema, dict):
        return frozenset(), frozenset()
    q_name = (schema.get("queryType") or {}).get("name")
    m_name = (schema.get("mutationType") or {}).get("name")
    q: set[str] = set()
    m: set[str] = set()
    for typ in schema.get("types", []) or []:
        if not isinstance(typ, dict):
            continue
        fields = typ.get("fields") or []
        names = {str(f["name"]) for f in fields if isinstance(f, dict) and f.get("name")}
        if typ.get("name") == q_name:
            q |= names
        elif typ.get("name") == m_name:
            m |= names
    return frozenset(q), frozenset(m)


def mine_js(text: str) -> frozenset[str]:
    """Extract candidate endpoints (quoted /paths and absolute http(s) URLs) from JS source."""
    out: set[str] = set()
    for m in _JS_PATH_RE.finditer(text or ""):
        out.add(m.group(1))
    for m in _JS_URL_RE.finditer(text or ""):
        out.add(m.group(0))
    return frozenset(out)


class MapFirst:
    """Aggregate parsed surface into a deduplicated, deterministic set of seeds."""

    def __init__(self) -> None:
        self._seeds: dict[tuple[str, str, str], SeedEntry] = {}

    def _add(self, ref: str, source: str, method: str = "GET") -> None:
        key = (ref, method.upper(), source)
        self._seeds.setdefault(key, SeedEntry(ref, method.upper(), source))

    def add_robots(self, text: str) -> frozenset[str]:
        paths, sitemaps = parse_robots(text)
        for p in paths:
            self._add(p, "robots")
        return sitemaps

    def add_sitemap(self, xml_text: str) -> frozenset[str]:
        pages, children = parse_sitemap(xml_text)
        for u in pages:
            self._add(u, "sitemap")
        return children

    def add_openapi(self, data: Any) -> None:
        for method, path in parse_openapi(data):
            self._add(path, "openapi", method)

    def add_js(self, text: str) -> None:
        for ref in mine_js(text):
            self._add(ref, "js")

    def add_graphql(self, data: Any, endpoint: str = "/api/graphql") -> tuple[frozenset[str], frozenset[str]]:
        """Fold a GraphQL introspection result into seeds (the endpoint + each query/mutation field).

        GitLab and other giants expose the deep authz surface through GraphQL, not REST — the nested
        resolvers are exactly where BOLA hides. Recording every field as a seed (POST to the graphql
        endpoint) makes that surface visible to triage, the object factory, and IOLITE's spec.
        """
        q, m = parse_graphql_introspection(data)
        if q or m:
            self._add(endpoint, "graphql", "POST")
        for name in sorted(q):
            self._add(f"{endpoint}#query.{name}", "graphql", "POST")
        for name in sorted(m):
            self._add(f"{endpoint}#mutation.{name}", "graphql", "POST")
        return q, m

    def seeds(self) -> tuple[SeedEntry, ...]:
        return tuple(self._seeds[k] for k in sorted(self._seeds))
