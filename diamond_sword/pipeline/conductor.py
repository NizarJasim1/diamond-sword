"""Deterministic journey FSM: map -> crawl (per principal) -> [factory] -> IOLITE -> ONYX -> report.

Checkpoints each stage to the coverage ledger so an interrupted run resumes. Pure orchestration;
every external capability (crawl fetch, scope, IOLITE, ONYX, object creation) is injected.
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Iterable

from ..coverage.principal_manager import PrincipalManager, PrincipalResult
from .report import build_report
__all__ = ["Stage", "ConductorResult", "Conductor"]


class Stage(str, Enum):
    MAP = "MAP"
    CRAWL = "CRAWL"
    FACTORY = "FACTORY"
    IOLITE = "IOLITE"
    ONYX = "ONYX"
    REPORT = "REPORT"
    DONE = "DONE"


@dataclass(frozen=True)
class ConductorResult:
    report: dict[str, Any]
    findings: tuple[dict[str, Any], ...]
    templates: tuple[str, ...]
    stages: tuple[str, ...]
    principals: dict[str, PrincipalResult]


class Conductor:
    def __init__(self, program: str, principal_manager: PrincipalManager,
                 iolite_bridge: Any, onyx_bridge: Any,
                 scope_prove: Callable[[str], str | None] | None = None,
                 ledger: Any | None = None,
                 object_factory: Any | None = None,
                 object_specs: Iterable[Any] = ()) -> None:
        self.program = program
        self.principal_manager = principal_manager
        self.iolite_bridge = iolite_bridge
        self.onyx_bridge = onyx_bridge
        self.scope_prove = scope_prove
        self.ledger = ledger
        self.object_factory = object_factory
        self.object_specs = tuple(object_specs)

    def _ck(self, stages: list[str], stage: Stage) -> None:
        stages.append(stage.value)
        if self.ledger is not None:
            self.ledger.checkpoint(stage.value)

    def run(self, seeds: Iterable[str] = (), start: str | None = None,
            har_paths: tuple[str, ...] = ()) -> ConductorResult:
        stages: list[str] = []
        self._ck(stages, Stage.MAP)
        self._ck(stages, Stage.CRAWL)
        principals = self.principal_manager.run(seeds, start)
        templates = tuple(sorted(PrincipalManager.common_templates(principals)))
        if self.object_factory is not None and self.object_specs:
            self._ck(stages, Stage.FACTORY)
            for spec in self.object_specs:
                self.object_factory.create(spec)
        self._ck(stages, Stage.IOLITE)
        spec = self.iolite_bridge.build_spec(har_paths)
        self._ck(stages, Stage.ONYX)
        findings = self.onyx_bridge.scan(spec)
        self._ck(stages, Stage.REPORT)
        report = build_report(findings, self.program, self.scope_prove)
        self._ck(stages, Stage.DONE)
        return ConductorResult(report, tuple(findings), templates, tuple(stages), principals)
