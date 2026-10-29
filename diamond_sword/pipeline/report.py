"""Assemble the final report: per finding a PoC, Δstate evidence, scope proof, and repro steps.

Accepts either typed :class:`~diamond_sword.pipeline.finding.Finding` objects (the real ONYX
path, already validated by the fail-loud contract) or raw dicts (the offline ``report`` command,
kept forgiving). Both funnel through one typed conversion so output keys are consistent — no more
scattered guessing over an unknown shape.
"""
from __future__ import annotations
from typing import Any, Callable
from .finding import Finding
__all__ = ["build_report", "to_markdown"]


def _repro(f: dict[str, Any]) -> list[str]:
    url = f.get("endpoint") or f.get("url") or ""
    a, b = f.get("principal_a"), f.get("principal_b")
    return [f"As {a}: note the object at {url}.",
            f"As {b}: {f.get('method', 'GET')} {url} and observe the same object (cross-principal access).",
            "Compare responses: ONYX confirmed a Δstate divergence (see evidence)."]


def _to_dict(item: Any) -> dict[str, Any]:
    """Normalize one finding (typed Finding or raw dict) into the dict the assembler reads."""
    if isinstance(item, Finding):
        return {"id": item.id, "type": item.type, "severity": item.severity,
                "endpoint": item.endpoint, "method": item.method,
                "principal_a": item.principal_a, "principal_b": item.principal_b,
                "delta": item.delta, "repro": list(item.repro), "scope_proof": item.scope_proof}
    return item if isinstance(item, dict) else {}


def build_report(findings: Any, program: str,
                 scope_prove: Callable[[str], str | None] | None = None) -> dict[str, Any]:
    out: list[dict[str, Any]] = []
    for item in findings:
        f = _to_dict(item)
        url = f.get("endpoint") or f.get("url") or ""
        pre_proof = f.get("scope_proof")   # typed findings already carry their proof
        out.append({
            "id": f.get("id"),
            "type": f.get("type"),
            "severity": f.get("severity", "unknown"),
            "endpoint": url,
            "method": f.get("method", "GET"),
            "principals": [f.get("principal_a"), f.get("principal_b")],
            "delta_evidence": f.get("delta"),
            "scope_proof": pre_proof if pre_proof is not None else (scope_prove(url) if (scope_prove and url) else None),
            "repro": f.get("repro") or _repro(f),
        })
    return {"program": program, "count": len(out), "findings": out}


def to_markdown(report: dict[str, Any]) -> str:
    lines = [f"# Diamond Sword report: {report.get('program', '')}",
             f"Findings: {report.get('count', 0)}", ""]
    for f in report.get("findings", []):
        lines += [f"## [{f.get('severity')}] {f.get('type')} — {f.get('id')}",
                  f"- Endpoint: `{f.get('method')} {f.get('endpoint')}`",
                  f"- Principals: {f.get('principals')}",
                  f"- Scope proof: {f.get('scope_proof')}",
                  f"- Δstate: {f.get('delta_evidence')}",
                  "- Repro:"]
        lines += [f"  {i}. {s}" for i, s in enumerate(f.get("repro", []), 1)]
        lines.append("")
    return "\n".join(lines)
