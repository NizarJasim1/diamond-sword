"""Schema-verify any model output BEFORE use (offline, semantic only). Never raises; never judges."""
from __future__ import annotations
import json
from typing import Any
__all__ = ["verify_json"]


def verify_json(text: str, required_keys: tuple[str, ...] = ()) -> dict[str, Any] | None:
    """Parse ``text`` as a JSON object and require ``required_keys``; return it, or None if invalid."""
    if not isinstance(text, str):
        return None
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        t = t[4:] if t[:4].lower() == "json" else t
        t = t.strip()
    try:
        obj = json.loads(t)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    if any(k not in obj for k in required_keys):
        return None
    return obj
