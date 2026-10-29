"""Human-ish pacing with AIMD backoff and Retry-After, never faster than roe's max_rps.

Delay floor = 1/max_rps (so the rate cap is always respected). Success -> additive decrease of
delay (rate creeps up); rate-limit -> multiplicative increase (capped), and a server Retry-After
is honored in full. Deterministic (no random jitter). Stdlib only.
"""
from __future__ import annotations

__all__ = ["Pacer"]


class Pacer:
    def __init__(self, max_rps: float, additive: float | None = None,
                 mult: float = 2.0, max_delay: float = 30.0) -> None:
        if max_rps <= 0:
            raise ValueError("max_rps must be positive")
        self.floor = 1.0 / max_rps
        self.max_delay = max(max_delay, self.floor)
        self.mult = mult
        self.additive = additive if additive is not None else self.floor
        self._delay = self.floor

    def next_delay(self) -> float:
        return self._delay

    def on_success(self) -> float:
        self._delay = max(self.floor, self._delay - self.additive)  # AIMD decrease, never below floor
        return self._delay

    def on_rate_limited(self, retry_after: float | None = None) -> float:
        self._delay = min(self.max_delay, self._delay * self.mult)  # multiplicative increase, capped
        if retry_after is not None:
            self._delay = max(self._delay, retry_after)             # honor the server fully
        return self._delay
