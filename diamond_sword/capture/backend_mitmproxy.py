"""mitmproxy backend (recommended: captures all traffic incl. non-browser, full bodies+headers).

``entry_from_flow`` converts a mitmproxy flow into a HarEntry (pure, testable). ``DiamondSwordAddon``
is the live ``mitmdump -s`` addon for your machine (L2); it only reads flows and appends HAR.
"""
from __future__ import annotations
from typing import Any
from .har_model import HarEntry, HarLog
__all__ = ["entry_from_flow", "DiamondSwordAddon"]


def _text(obj: Any) -> str | None:
    if obj is None:
        return None
    getter = getattr(obj, "get_text", None)
    if callable(getter):
        try:
            value = getter()
            return None if value is None else str(value)
        except Exception:
            return None
    return getattr(obj, "text", None)


def entry_from_flow(principal: str, flow: Any) -> HarEntry:
    req = flow.request
    resp = getattr(flow, "response", None)
    return HarEntry(
        principal=principal,
        method=getattr(req, "method", "GET"),
        url=getattr(req, "url", ""),
        status=int(getattr(resp, "status_code", 0)) if resp is not None else 0,
        req_headers=dict(getattr(req, "headers", {}) or {}),
        req_body=_text(req),
        resp_headers=dict(getattr(resp, "headers", {}) or {}) if resp is not None else {},
        resp_body=_text(resp),
    )


class DiamondSwordAddon:  # pragma: no cover - runs inside mitmdump on your machine (L2)
    """Usage: mitmdump -s this_addon.py (set DS_PRINCIPAL + DS_HAR env). Read-only; appends HAR."""

    def __init__(self, principal: str = "A", har_path: str = "capture.har") -> None:
        self.principal = principal
        self.har_path = har_path
        self.log = HarLog()

    def response(self, flow: Any) -> None:
        self.log.add(entry_from_flow(self.principal, flow))
        self.log.write(self.har_path)
