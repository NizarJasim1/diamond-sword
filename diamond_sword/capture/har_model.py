"""Multi-principal HAR model — the artifact IOLITE consumes. Deterministic, stdlib only.

Each entry is tagged with its principal (the ``_principal`` field) so ONYX can compare the same
surface across identities for Δstate. URLs are normalized for stable output. The HAR is faithful
where it matters to the next stage: the request/response ``mimeType`` comes from the real
Content-Type header (never hard-coded), and ``queryString`` is populated from the URL — so IOLITE
sees a form body as a form body and a JSON body as JSON, not everything mislabeled as JSON.
"""
from __future__ import annotations
from typing import Any
import json
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urldefrag, urlencode, urlsplit, urlunsplit
from ..legal.scope_parser import remove_dot_segments
__all__ = ["HarEntry", "HarLog", "normalize_url"]


def normalize_url(url: str) -> str:
    u = urldefrag(url)[0]
    p = urlsplit(u)
    path = remove_dot_segments(p.path or "/")
    query = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
    return urlunsplit((p.scheme, p.netloc, path, query, ""))


def _headers(d: dict[str, str]) -> list[dict[str, str]]:
    return [{"name": k, "value": v} for k, v in d.items()]


def _content_type(headers: dict[str, str], default: str) -> str:
    """Return the media type from a Content-Type header (case-insensitive), else ``default``."""
    for k, v in (headers or {}).items():
        if k.lower() == "content-type" and v:
            return v.split(";")[0].strip()
    return default


def _query_string(url: str) -> list[dict[str, str]]:
    q = urlsplit(urldefrag(url)[0]).query
    return [{"name": k, "value": v} for k, v in parse_qsl(q, keep_blank_values=True)]


def _req_mime(headers: dict[str, str], body: str) -> str:
    """Request body media type: the real header if present, else inferred from the body shape."""
    ct = _content_type(headers, "")
    if ct:
        return ct
    s = (body or "").lstrip()
    if s[:1] in ("{", "["):
        return "application/json"
    if "=" in s and "\n" not in s and " " not in s:
        return "application/x-www-form-urlencoded"
    return "text/plain"


@dataclass(frozen=True)
class HarEntry:
    principal: str
    method: str
    url: str
    status: int
    req_headers: dict[str, str] = field(default_factory=dict)
    req_body: str | None = None
    resp_headers: dict[str, str] = field(default_factory=dict)
    resp_body: str | None = None

    def to_har(self) -> dict[str, Any]:
        request: dict[str, Any] = {"method": self.method.upper(), "url": normalize_url(self.url),
                         "httpVersion": "HTTP/1.1", "headers": _headers(self.req_headers),
                         "queryString": _query_string(self.url), "headersSize": -1, "bodySize": -1}
        if self.req_body is not None:
            request["postData"] = {"mimeType": _req_mime(self.req_headers, self.req_body),
                                   "text": self.req_body}
        return {"startedDateTime": "1970-01-01T00:00:00Z", "time": 0, "request": request,
                "response": {"status": self.status, "statusText": "", "httpVersion": "HTTP/1.1",
                             "headers": _headers(self.resp_headers),
                             "content": {"size": len(self.resp_body or ""),
                                         "mimeType": _content_type(self.resp_headers, "text/html"),
                                         "text": self.resp_body or ""},
                             "redirectURL": "", "headersSize": -1, "bodySize": -1},
                "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0},
                "_principal": self.principal}


@dataclass
class HarLog:
    entries: list[HarEntry] = field(default_factory=list)

    def add(self, entry: HarEntry) -> None:
        self.entries.append(entry)

    def principals(self) -> set[str]:
        return {e.principal for e in self.entries}

    def to_har(self) -> dict[str, Any]:
        return {"log": {"version": "1.2", "creator": {"name": "Diamond Sword", "version": "1.2"},
                        "entries": [e.to_har() for e in self.entries]}}

    def write(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_har(), fh, ensure_ascii=False, indent=2)
