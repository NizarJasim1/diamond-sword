"""Thin bridge to IOLITE: multi-principal HAR -> ONYX-ready spec.json. Runner is injected."""
from __future__ import annotations
from typing import Any, Callable
__all__ = ["IoliteBridge"]


class IoliteBridge:
    def __init__(self, runner: Callable[[tuple[str, ...]], dict[str, Any]]) -> None:
        self.runner = runner   # real: shell to `iolite hook|full`; test: a fake

    def build_spec(self, har_paths: tuple[str, ...]) -> dict[str, Any]:
        spec = self.runner(tuple(har_paths))
        if not isinstance(spec, dict):
            raise ValueError("IOLITE runner must return a spec dict")
        return spec
