"""The end-to-end run: crawl per principal -> write HAR -> IOLITE -> ONYX -> report.

This is the entry point the pipeline lacked. It wires the REAL legal gates (ScopeGuard +
AuditLedger), the per-principal recording crawl (into a HAR), the coverage ledger (so a run
resumes), and the two sibling tools through their bridges — then validates ONYX's output with the
fail-LOUD contract (:meth:`OnyxBridge.scan_typed`) before building the report.

Everything external is injected, so the suite drives it with fakes and the CLI supplies the real
ones: ``make_fetch(principal, guard, har)`` returns the fetch adapter (urllib today, Playwright/
mitmproxy on your machine) and records each request into ``har``; ``iolite_run``/``onyx_run`` are
the runners from :mod:`diamond_sword.pipeline.runners`. Pure orchestration, stdlib only.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from ..capture.har_model import HarLog
from ..coverage.crawler import Crawler
from ..coverage.principal_manager import PrincipalManager, PrincipalResult
from ..coverage.template_engine import TemplateMap
from ..heal.coverage_ledger import CoverageLedger
from ..legal.audit_ledger import AuditLedger
from ..legal.scope_guard import ScopeGuard
from .finding import Finding
from .iolite_bridge import IoliteBridge
from .onyx_bridge import OnyxBridge
from .report import build_report

__all__ = ["PipeResult", "run_pipe"]


@dataclass(frozen=True)
class PipeResult:
    report: dict[str, Any] | None
    findings: tuple[Finding, ...]
    principals: dict[str, PrincipalResult]
    har_paths: tuple[str, ...]
    judged: bool


def _safe(name: str) -> str:
    return "".join(c if (c.isalnum() or c in "-_") else "_" for c in name) or "anon"


def _prover(engagement: Any) -> Callable[[str], str | None]:
    """A sink-less scope prover for stamping findings (does not pollute the audit ledger)."""
    guard = ScopeGuard(engagement)

    def prove(url: str) -> str | None:
        decision = guard.check(url)
        return decision.matched if decision.allowed else None

    return prove


def run_pipe(
    engagement: Any,
    principals: list[str],
    make_fetch: Callable[[str, ScopeGuard, HarLog], Callable[[str], Any]],
    *,
    start: str | None = None,
    seeds: Iterable[str] = (),
    iolite_run: Callable[[tuple[str, ...]], dict[str, Any]] | None = None,
    onyx_run: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None,
    audit_path: str | None = None,
    coverage_path: str | None = None,
    har_dir: str = ".",
    scope_prove: Callable[[str], str | None] | None = None,
    max_pages: int = 500,
) -> PipeResult:
    """Run the whole pipeline. Writes one HAR per principal; judges only if both runners are given.

    With no IOLITE/ONYX runner (e.g. you only want the multi-principal HAR, or those tools are not
    wired yet) the crawl still runs and the HARs are written — the judging step is simply skipped.
    """
    if not principals:
        raise ValueError("at least one principal is required")

    audit = AuditLedger(audit_path) if audit_path else None
    guard = ScopeGuard(engagement, audit.decision_sink if audit else None)
    cov = CoverageLedger(coverage_path) if coverage_path else None
    prove = scope_prove if scope_prove is not None else _prover(engagement)
    har_logs: dict[str, HarLog] = {}

    def make_crawler(principal: str) -> Crawler:
        har = HarLog()
        har_logs[principal] = har
        return Crawler(make_fetch(principal, guard, har), guard.allowed,
                       TemplateMap(), ledger=cov, max_pages=max_pages)

    pm = PrincipalManager(list(principals), make_crawler, ledger=cov)
    results = pm.run(tuple(seeds), start)

    os.makedirs(har_dir, exist_ok=True)
    har_paths: list[str] = []
    for principal in principals:
        path = os.path.join(har_dir, f"capture.{_safe(principal)}.har")
        har_logs[principal].write(path)
        har_paths.append(path)

    report: dict[str, Any] | None = None
    findings: tuple[Finding, ...] = ()
    if iolite_run is not None and onyx_run is not None:
        spec = IoliteBridge(iolite_run).build_spec(tuple(har_paths))
        findings = OnyxBridge(onyx_run).scan_typed(spec, prove)   # fail-LOUD ONYX contract
        report = build_report(findings, str(getattr(engagement, "program", "")), prove)

    return PipeResult(report, findings, results, tuple(har_paths), report is not None)
