"""The ONYX finding contract — the single, fail-LOUD boundary between ONYX and the report.

Why this exists
---------------
ONYX alone judges (Δstate, zero false positives). Everything downstream of ONYX is only as
trustworthy as the agreement on *what a finding looks like*. The old report read raw dicts with
``.get()`` everywhere, so a single renamed key from the real ONYX produced a report full of
``None`` with no error — the worst possible failure for a zero-FP tool (a real bug, silently
dropped). This module makes that boundary explicit and loud:

- One typed :class:`Finding` is the only shape the report consumes.
- :func:`normalize_finding` is the ONE place the real ONYX schema is read. It is tolerant of
  cosmetic differences (``url``/``endpoint``, ``delta``/``evidence``, ``principals=[a,b]`` vs
  ``principal_a``/``principal_b``) but STRICT on substance: a BOLA finding must carry its
  cross-principal Δstate evidence, or we raise :class:`FindingSchemaError` naming the exact
  missing field. When you point this at the real ONYX, a mismatch fails immediately with the
  field name, and you fix the mapping in this one function — never a silent null again.

Pure, deterministic, standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

__all__ = ["FindingSchemaError", "Finding", "DEFAULT_REQUIRED", "normalize_finding", "normalize_findings"]


class FindingSchemaError(ValueError):
    """Raised when an ONYX finding does not carry the substance a report needs."""


# The honest minimum for a cross-principal authorization finding: what kind of bug, where it is,
# the two identities compared, and the Δstate evidence that proves the divergence. Severity/id are
# optional (defaulted) because they are presentation, not proof.
DEFAULT_REQUIRED = ("type", "endpoint", "principal_a", "principal_b", "delta")

# Cosmetic aliases: different ONYX builds may name the same substance differently. Resolving these
# here keeps a trivial rename from ever reaching (and silently breaking) the report.
_ALIASES: dict[str, tuple[str, ...]] = {
    "endpoint": ("endpoint", "url", "target", "path"),
    "delta": ("delta", "delta_evidence", "evidence", "diff"),
    "type": ("type", "kind", "class", "category"),
    "id": ("id", "finding_id", "uid"),
    "severity": ("severity", "sev", "risk"),
    "method": ("method", "verb", "http_method"),
    "principal_a": ("principal_a", "principalA", "a", "victim", "owner"),
    "principal_b": ("principal_b", "principalB", "b", "attacker", "other"),
}


@dataclass(frozen=True)
class Finding:
    """One confirmed cross-principal authorization finding, as the report consumes it."""

    type: str
    endpoint: str
    principal_a: str
    principal_b: str
    delta: Any
    method: str = "GET"
    severity: str = "unknown"
    id: str | None = None
    repro: tuple[str, ...] = ()
    scope_proof: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def _pick(raw: dict[str, Any], canonical: str) -> Any:
    """Return the first present alias value for ``canonical`` (``None`` if none present)."""
    for key in _ALIASES.get(canonical, (canonical,)):
        if key in raw and raw[key] not in (None, ""):
            return raw[key]
    return None


def _principals(raw: dict[str, Any]) -> tuple[Any, Any]:
    """Resolve the two principals from either ``principal_a/b`` or a ``principals`` pair."""
    a = _pick(raw, "principal_a")
    b = _pick(raw, "principal_b")
    if (a is None or b is None) and isinstance(raw.get("principals"), (list, tuple)):
        pair = list(raw["principals"])
        if len(pair) >= 2:
            a = a if a is not None else pair[0]
            b = b if b is not None else pair[1]
    return a, b


def _default_repro(ftype: str, endpoint: str, method: str, a: Any, b: Any) -> tuple[str, ...]:
    return (
        f"As {a}: note the object at {endpoint}.",
        f"As {b}: {method} {endpoint} and observe the same object (cross-principal access).",
        f"Compare responses: ONYX confirmed a Δstate divergence ({ftype}); see evidence.",
    )


def normalize_finding(
    raw: Any,
    scope_prove: Callable[[str], str | None] | None = None,
    required: tuple[str, ...] = DEFAULT_REQUIRED,
) -> Finding:
    """Validate one raw ONYX finding into a typed :class:`Finding`, failing LOUD on missing substance.

    ``scope_prove`` (optional) stamps a scope proof for the endpoint, so the report can show the
    finding was in bounds. ``required`` is the substance contract; adjust it only if you have a
    deliberate reason, never to paper over a genuinely absent field.
    """
    if not isinstance(raw, dict):
        raise FindingSchemaError(f"ONYX finding must be an object, got {type(raw).__name__}")

    endpoint = _pick(raw, "endpoint")
    a, b = _principals(raw)
    resolved: dict[str, Any] = {
        "type": _pick(raw, "type"),
        "endpoint": endpoint,
        "principal_a": a,
        "principal_b": b,
        "delta": _pick(raw, "delta"),
    }

    for name in required:
        if name not in resolved:
            # A required name outside the known fields means the contract was mis-set.
            raise FindingSchemaError(f"unknown required field {name!r}; fix DEFAULT_REQUIRED")
        if resolved[name] is None:
            tried = ", ".join(_ALIASES.get(name, (name,)))
            raise FindingSchemaError(
                f"ONYX finding missing required field {name!r} "
                f"(looked for any of: {tried}; got keys: {sorted(raw)})"
            )

    ftype = str(resolved["type"])
    endpoint_s = str(resolved["endpoint"])
    method = str(_pick(raw, "method") or "GET").upper()
    known = {k for alias in _ALIASES.values() for k in alias} | {"principals", "repro"}
    repro_raw = raw.get("repro")
    repro = tuple(str(s) for s in repro_raw) if isinstance(repro_raw, (list, tuple)) and repro_raw \
        else _default_repro(ftype, endpoint_s, method, resolved["principal_a"], resolved["principal_b"])

    return Finding(
        type=ftype,
        endpoint=endpoint_s,
        principal_a=str(resolved["principal_a"]),
        principal_b=str(resolved["principal_b"]),
        delta=resolved["delta"],
        method=method,
        severity=str(_pick(raw, "severity") or "unknown"),
        id=(str(_pick(raw, "id")) if _pick(raw, "id") is not None else None),
        repro=repro,
        scope_proof=(scope_prove(endpoint_s) if (scope_prove and endpoint_s) else None),
        extra={k: v for k, v in raw.items() if k not in known},
    )


def normalize_findings(
    raw: Any,
    scope_prove: Callable[[str], str | None] | None = None,
    required: tuple[str, ...] = DEFAULT_REQUIRED,
) -> tuple[Finding, ...]:
    """Validate a list of raw ONYX findings; raise :class:`FindingSchemaError` on a bad shape."""
    if isinstance(raw, dict) and "findings" in raw:
        raw = raw["findings"]
    if not isinstance(raw, (list, tuple)):
        raise FindingSchemaError(f"ONYX findings must be a list, got {type(raw).__name__}")
    items: Iterable[Any] = raw
    return tuple(normalize_finding(f, scope_prove, required) for f in items)
