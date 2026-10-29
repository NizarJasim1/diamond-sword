"""Deterministic, read-only frontier crawler. Pure logic; the browser/network is an injected adapter.

Per URL: scope check (fail-closed) -> template dedup/trap gate -> fetch (GET only) -> structural
fingerprint -> record + ledger -> expand links (unless structurally seen). The frontier is a
priority queue ordered by authorization-triage score (hunt the juicy templates first), with a
deterministic insertion tie-break. No AI, no randomness, no mutation. Playwright arrives in the
capture layer; here the fetch adapter is faked in tests and real on the user's machine.
"""
from __future__ import annotations

import heapq
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Callable, Iterable
from urllib.parse import urldefrag, urljoin, urlsplit

from .fingerprint import fingerprint
from .template_engine import TemplateMap
from .triage import score_url

__all__ = ["FetchResult", "Page", "CrawlResult", "extract_links", "Crawler"]


@dataclass(frozen=True)
class FetchResult:
    status: int
    html: str
    final_url: str = ""


@dataclass(frozen=True)
class Page:
    url: str
    template_key: str
    fingerprint: str
    status: int


@dataclass(frozen=True)
class CrawlResult:
    pages: tuple[Page, ...]
    templates: tuple[str, ...]
    traps: tuple[str, ...]
    distinct_structures: int


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        d = {k.lower(): (v or "") for k, v in attrs}
        for key in ("href", "src", "action"):
            if d.get(key):
                self.links.append(d[key])


def extract_links(html: str, base: str) -> list[str]:
    """Absolute http(s) links from href/src/action, fragment-stripped, deduped, in document order."""
    p = _LinkExtractor()
    p.feed(html or "")
    p.close()
    out: list[str] = []
    seen: set[str] = set()
    for href in p.links:
        u = urldefrag(urljoin(base, href))[0]
        if urlsplit(u).scheme in ("http", "https") and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _deny_all(_: str) -> bool:
    return False


class Crawler:
    def __init__(
        self,
        fetch: Callable[[str], FetchResult | None],
        in_scope: Callable[[str], bool] | None = None,
        template_map: TemplateMap | None = None,
        ledger: object | None = None,
        max_pages: int = 5000,
    ) -> None:
        self.fetch = fetch
        self.in_scope = in_scope or _deny_all   # fail-closed: no scope => crawl nothing
        self.template_map = template_map
        self.ledger = ledger
        self.max_pages = max_pages

    def crawl(self, seeds: Iterable[str] = (), start: str | None = None) -> CrawlResult:
        tmap = self.template_map or TemplateMap()
        base = start or ""
        heap: list[tuple[int, int, str]] = []
        counter = 0
        queued: set[str] = set()
        pages: list[Page] = []
        visited_fps: set[str] = set()

        def push(raw: str) -> None:
            nonlocal counter
            u = raw
            if u.startswith("/") and base:
                u = urljoin(base, u)
            u = urldefrag(u)[0]
            if u in queued or not self.in_scope(u):   # fail-closed pre-filter
                return
            queued.add(u)
            heapq.heappush(heap, (-score_url(u, "GET").score, counter, u))
            counter += 1
            if self.ledger is not None:
                self.ledger.add_frontier(u)  # type: ignore[attr-defined]

        if start:
            push(start)
        for s in seeds:
            push(s)

        while heap and len(pages) < self.max_pages:
            _, _, url = heapq.heappop(heap)
            if not self.in_scope(url):   # re-check at pop (fail-closed)
                continue
            obs = tmap.observe(url, "GET")
            if not obs.enqueue:          # duplicate / trap / depth / bad-url -> skip fetch
                continue
            fr = self.fetch(url)
            if fr is None:
                continue
            fp = fingerprint(fr.html)
            pages.append(Page(url, obs.template_key, fp, fr.status))
            if self.ledger is not None:
                self.ledger.mark_visited(fp, url)  # type: ignore[attr-defined]
            if fp in visited_fps:        # same structure seen -> don't re-expand its links
                continue
            visited_fps.add(fp)
            for link in extract_links(fr.html, fr.final_url or url):
                push(link)

        return CrawlResult(tuple(pages), tmap.templates, tuple(sorted(tmap.traps)), len(visited_fps))
