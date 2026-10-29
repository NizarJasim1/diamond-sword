"""Thin bridge to ONYX: spec -> confirmed findings via Δstate. Runner is injected. ONYX alone judges."""
from __future__ import annotations
from typing import Any, Callable
from .finding import Finding, normalize_findings
__all__ = ["OnyxBridge"]


class OnyxBridge:
    def __init__(self, runner: Callable[[dict[str, Any]], list[dict[str, Any]]]) -> None:
        self.runner = runner   # real: onyx_link.verify_spec/scan; test: a fake

    def scan(self, spec: dict[str, Any]) -> list[dict[str, Any]]:
        findings = self.runner(spec)
        if not isinstance(findings, list):
            raise ValueError("ONYX runner must return a list of findings")
        return findings

    def scan_typed(
        self,
        spec: dict[str, Any],
        scope_prove: Callable[[str], str | None] | None = None,
    ) -> tuple[Finding, ...]:
        """Validated findings (the fail-LOUD ONYX contract) — use on the real ONYX path.

        Any renamed/missing substance in ONYX's output raises FindingSchemaError here, naming the
        field, instead of surfacing as silent nulls in the report.
        """
        return normalize_findings(self.scan(spec), scope_prove)
