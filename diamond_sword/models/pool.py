"""Round-robin free-model pool with failover + a verify gate. Optional, offline-authoring only.

NEVER used in the judgment path (ONYX alone judges via Δstate) and never required at runtime. The
actual HTTP call is an injected ``caller``; output is accepted only if ``verify_fn`` passes.
"""
from __future__ import annotations
from typing import Callable, Sequence
from .providers import Provider
__all__ = ["ModelPool"]


class ModelPool:
    def __init__(self, providers: Sequence[Provider],
                 caller: Callable[[Provider, str], str | None]) -> None:
        if not providers:
            raise ValueError("at least one provider is required")
        self.providers = tuple(providers)
        self.caller = caller
        self._next = 0

    def ask(self, prompt: str,
            verify_fn: Callable[[str], bool] | None = None) -> str | None:
        """Try providers in rotation until one returns output that passes verify_fn. Else None."""
        n = len(self.providers)
        for i in range(n):
            provider = self.providers[(self._next + i) % n]
            try:
                out = self.caller(provider, prompt)
            except Exception:
                continue
            if out is None:
                continue
            if verify_fn is not None and not verify_fn(out):
                continue
            self._next = (self._next + i + 1) % n   # advance past the one that worked
            return out
        return None
