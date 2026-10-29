"""End-to-end *interactive* run: explore (drive the browser + capture) \u2192 HAR \u2192 IOLITE \u2192 ONYX \u2192
report.

The sibling of :func:`diamond_sword.pipeline.run.run_pipe`, but it exercises a logged-in app
control-by-control with the interaction :class:`Explorer` instead of the GET link-crawler \u2014 so an
SPA giant yields the multi-principal HAR ONYX needs. The legal gates are the real ones:
``ScopeGuard`` (where) and ``ConsentGate`` over the engagement's ``RoePolicy`` (what), wired to the
tamper-evident audit ledger. Everything external is injected: ``make_driver(principal)`` returns a
``DriverPort`` exposing ``.har`` (a :class:`HarLog`). Standard library only.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable

from ..interact.action_ledger import ActionLedger
from ..interact.direction import Direction
from ..interact.explorer import DriverPort, ExploreConfig, Explorer, ExploreResult
from ..legal.audit_ledger import AuditLedger
from ..legal.consent_gate import Approver, ConsentGate
from ..legal.roe import RoePolicy, from_engagement
from ..legal.scope_guard import ScopeGuard
from .finding import Finding
from .iolite_bridge import IoliteBridge
from .onyx_bridge import OnyxBridge
from .report import build_report
from .run import _prover, _safe

__all__ = ["ExploreRunResult", "run_explore", "playwright_make_driver"]


@dataclass(frozen=True)
class ExploreRunResult:
    report: dict[str, Any] | None
    findings: tuple[Finding, ...]
    explorations: dict[str, ExploreResult]
    har_paths: tuple[str, ...]
    judged: bool


def run_explore(
    engagement: Any,
    principals: list[str],
    make_driver: Callable[[str], DriverPort],
    *,
    roe: RoePolicy | None = None,
    approver: Approver | None = None,
    direction: Direction | None = None,
    start: str | None = None,
    iolite_run: Callable[[tuple[str, ...]], dict[str, Any]] | None = None,
    onyx_run: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None,
    audit_path: str | None = None,
    action_ledger_dir: str | None = None,
    har_dir: str = ".",
    now_hour: int | None = None,
    config: ExploreConfig | None = None,
) -> ExploreRunResult:
    """Explore each principal, write one HAR per principal, and judge only if both runners are set.

    With no IOLITE/ONYX runner the exploration still runs and the HARs are written; judging is
    simply skipped (handy when you only want the multi-principal capture).
    """
    if not principals:
        raise ValueError("at least one principal is required")

    policy = roe if roe is not None else from_engagement(getattr(engagement, "roe", None))
    audit = AuditLedger(audit_path) if audit_path else None
    guard = ScopeGuard(engagement, audit.decision_sink if audit else None)
    prove = _prover(engagement)

    os.makedirs(har_dir, exist_ok=True)
    explorations: dict[str, ExploreResult] = {}
    har_paths: list[str] = []

    for principal in principals:
        driver = make_driver(principal)
        gate = ConsentGate(policy, approver, audit.grant_sink if audit else None)
        ledger = None
        if action_ledger_dir:
            os.makedirs(action_ledger_dir, exist_ok=True)
            ledger = ActionLedger(os.path.join(action_ledger_dir, f"explore.{_safe(principal)}.jsonl"))
        explorer = Explorer(driver, guard, gate, principal, direction=direction,
                            ledger=ledger, now_hour=now_hour, config=config)
        explorations[principal] = explorer.run(start=start)
        har = getattr(driver, "har", None)
        path = os.path.join(har_dir, f"capture.{_safe(principal)}.har")
        if har is not None:
            har.write(path)
        har_paths.append(path)

    report: dict[str, Any] | None = None
    findings: tuple[Finding, ...] = ()
    if iolite_run is not None and onyx_run is not None:
        spec = IoliteBridge(iolite_run).build_spec(tuple(har_paths))
        findings = OnyxBridge(onyx_run).scan_typed(spec, prove)
        report = build_report(findings, str(getattr(engagement, "program", "")), prove)

    return ExploreRunResult(report, findings, explorations, tuple(har_paths), report is not None)


def playwright_make_driver(  # pragma: no cover - requires a live browser (L2)
    browser: Any,
    storage_by_principal: dict[str, str] | None = None,
    *,
    config_kw: dict[str, Any] | None = None,
) -> Callable[[str], DriverPort]:
    """Build a ``make_driver`` that opens a fresh Playwright context per principal (reusing that
    principal's saved ``storage_state`` from a one-time human login) and returns a
    :class:`~diamond_sword.capture.driver_playwright.PlaywrightDriver`."""
    from ..capture.driver_playwright import PlaywrightDriver

    storage = storage_by_principal or {}

    def make(principal: str) -> DriverPort:
        kwargs: dict[str, Any] = {}
        if principal in storage:
            kwargs["storage_state"] = storage[principal]
        ctx = browser.new_context(**kwargs)
        page = ctx.new_page()
        return PlaywrightDriver(page, principal=principal, **(config_kw or {}))

    return make
