"""Playwright backend (deterministic browser hand). Pure transform here; live driving on your machine.

``entry_from_playwright`` converts a request/response pair into a HarEntry and is fully testable.
``playwright_fetch_adapter`` drives a real Playwright page as the crawler's fetch (live, on the operator's machine).
"""
from __future__ import annotations
from typing import Any, Callable
from ..coverage.crawler import FetchResult
from .har_model import HarEntry, HarLog
__all__ = ["entry_from_playwright", "playwright_fetch_adapter"]


def entry_from_playwright(principal: str, request: Any, response: Any) -> HarEntry:
    return HarEntry(
        principal=principal,
        method=getattr(request, "method", "GET"),
        url=getattr(request, "url", ""),
        status=int(getattr(response, "status", 0)),
        req_headers=dict(getattr(request, "headers", {}) or {}),
        req_body=getattr(request, "post_data", None),
        resp_headers=dict(getattr(response, "headers", {}) or {}),
        resp_body=getattr(response, "text", None),
    )


def playwright_fetch_adapter(page: Any, principal: str, har_log: HarLog) -> Callable[[str], FetchResult]:
    def fetch(url: str) -> FetchResult:  # pragma: no cover - requires a live browser (L2)
        resp = page.goto(url)
        html = page.content()
        status = int(getattr(resp, "status", 0)) if resp is not None else 0
        har_log.add(HarEntry(principal, "GET", url, status, resp_body=html))
        return FetchResult(status, html, getattr(page, "url", url))
    return fetch
