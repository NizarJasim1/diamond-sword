"""Run the same crawl for each principal (A, then B, then anon) and tag results by principal.

This is what ONYX needs for Δstate: the identical surface fetched under different identities. Each
principal gets its own crawler (its authenticated fetch adapter is injected); sequencing is fixed
and deterministic. No AI. The actual HAR writing is the capture layer; here we drive
the walk per principal and collect per-principal results.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from .crawler import Crawler, Page

__all__ = ["PrincipalResult", "PrincipalManager"]


@dataclass(frozen=True)
class PrincipalResult:
    principal: str
    pages: tuple[Page, ...]
    templates: tuple[str, ...]
    traps: tuple[str, ...]


class PrincipalManager:
    def __init__(self, principals: list[str], make_crawler: Callable[[str], Crawler],
                 ledger: object | None = None) -> None:
        if not principals:
            raise ValueError("at least one principal is required")
        self.principals = list(principals)
        self.make_crawler = make_crawler
        self.ledger = ledger

    def run(self, seeds: Iterable[str] = (), start: str | None = None) -> dict[str, PrincipalResult]:
        seeds = tuple(seeds)
        out: dict[str, PrincipalResult] = {}
        for principal in self.principals:   # fixed order: as given (A, B, anon)
            crawler = self.make_crawler(principal)
            res = crawler.crawl(seeds, start)
            if self.ledger is not None:
                self.ledger.mark_captured(principal)  # type: ignore[attr-defined]
            out[principal] = PrincipalResult(principal, res.pages, res.templates, res.traps)
        return out

    @staticmethod
    def common_templates(results: dict[str, "PrincipalResult"]) -> set[str]:
        """Templates discovered under EVERY principal — the shared surface ONYX compares."""
        sets = [set(r.templates) for r in results.values()]
        if not sets:
            return set()
        common = sets[0]
        for s in sets[1:]:
            common &= s
        return common
