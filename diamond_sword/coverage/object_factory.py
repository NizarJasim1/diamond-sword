"""Create a FEW objects per principal for Δstate comparison — every creation guarded + logged.

Guards: scope_check (fail-closed) then the ConsentGate authorize (mutations need human consent,
dry-run by default). Records the id pattern (sequential/uuid/gid/opaque) for triage/ONYX. The
actual HTTP creation is an injected create_fn (faked in tests; real on the user's machine).
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable
from ..legal.roe import Action
from .template_engine import classify_segment, PH_NUM, PH_UUID
__all__ = ["CreateSpec", "Created", "detect_id_pattern", "ObjectFactory"]


@dataclass(frozen=True)
class CreateSpec:
    principal: str
    url: str
    template: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class Created:
    principal: str
    template: str
    object_id: str | None
    id_pattern: str
    dry_run: bool
    proceeded: bool
    reason: str


def detect_id_pattern(object_id: str | None) -> str:
    if not object_id:
        return "unknown"
    if object_id.startswith("gid://"):
        return "gid"
    cls = classify_segment(object_id)
    if cls == PH_NUM:
        return "sequential"
    if cls == PH_UUID:
        return "uuid"
    return "opaque"


class ObjectFactory:
    def __init__(self, scope_check: Callable[[str], bool],
                 authorize: Callable[[Action], Any],
                 create_fn: Callable[[CreateSpec], str | None]) -> None:
        self.scope_check = scope_check
        self.authorize = authorize          # ConsentGate.authorize -> Grant
        self.create_fn = create_fn

    def create(self, spec: CreateSpec) -> Created:
        if not self.scope_check(spec.url):                       # fail-closed scope
            return Created(spec.principal, spec.template, None, "unknown", False, False, "OUT_OF_SCOPE")
        grant = self.authorize(Action(kind="request", method="POST", url=spec.url, mutating=True))
        if not grant.proceed:                                   # consent denied / destructive / etc.
            return Created(spec.principal, spec.template, None, "unknown", bool(getattr(grant, "dry_run", False)),
                           False, getattr(grant, "reason", "DENIED"))
        if grant.dry_run:                                       # consented but dry-run: plan only
            return Created(spec.principal, spec.template, None, "unknown", True, True, "DRY_RUN")
        oid = self.create_fn(spec)
        return Created(spec.principal, spec.template, oid, detect_id_pattern(oid), False, True, "CREATED")
