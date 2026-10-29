"""
Live-transport governor — adaptive pacing, throttle-aware backoff, and a
per-host circuit breaker, in front of every request Diamond Sword makes.

WHY THIS EXISTS (and why the old Pacer is not enough)
-----------------------------------------------------
``capture.Pacer`` is a fixed max-RPS sleeper. Against a giant, well-defended
target (GitLab-class and larger) a constant rate is both too slow when the
target is calm and too fast the moment it starts shedding load: it cannot
react, so you either waste hours or walk straight into a WAF ban that burns the
account and the whole program.

This governor treats pacing as a *control problem*. Per host it runs an AIMD
controller — the additive-increase / multiplicative-decrease discipline that
keeps TCP from collapsing the internet: creep faster while the target is
healthy, collapse instantly the moment it pushes back. On top sit the three
things a polite, hard-to-detect, legally-safe automated client needs:

  * exact Retry-After obedience (a server that *tells* you to wait is obeyed to
    the second, overriding the controller);
  * decorrelated / full jitter on every wait, so our requests never line up
    into a machine-perfect cadence (politeness *and* a smaller automation
    signature);
  * a circuit breaker that, on sustained blocking, pauses the host and leaves
    an audit record — failing closed instead of hammering a target that has
    clearly said no.

DESIGN INVARIANTS
-----------------
  * Fail-closed: automation not permitted, outside the ROE time window, or a
    tripped circuit  ->  ``acquire`` denies. Nothing leaks past.
  * Deterministic: the clock, the sleep and the RNG are injected, so a given
    (seed, inputs) sequence produces identical waits — unit-testable to the
    millisecond. Jitter is randomness with a seat belt.
  * Thread-safe: an explorer may drive several principals at once; all host
    state is guarded and per-host concurrency is capped by a condition.
  * Honest cost: every observed response updates a per-endpoint cost ledger
    (requests, bytes, throttle events) that the econ layer reads to price a
    target in real $/hour terms.

It enforces ``RoePolicy.max_rps`` as the *ceiling* the controller may never
cross (the ROE comment says max_rps is "stored for the pacer, not enforced
here" — this is that pacer).
"""
from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Mapping

# --- throttle-signal classification --------------------------------------------------

# (operational-header substring, label). Body text is deliberately NOT used as a
# primary signal: a 403 page that merely mentions a vendor in its footer is not a
# block. The status and the operational headers carry the real signal.
_WAF_HEADER_FINGERPRINTS = (
    ("cf-mitigated", "cloudflare"),
    ("cf-ray", "cloudflare"),
    ("x-amzn-waf", "aws-waf"),
    ("x-amzn-errortype", "aws-apigw"),
    ("x-akamai", "akamai"),
    ("akamai-grn", "akamai"),
    ("x-iinfo", "incapsula"),
    ("x-cdn:incapsula", "incapsula"),
    ("x-sucuri", "sucuri"),
    ("x-datadome", "datadome"),
)
_BLOCK_STATUSES = frozenset({403, 406, 409, 429, 503})
_HARD_THROTTLE = frozenset({429, 503})


@dataclass(frozen=True)
class ThrottleVerdict:
    throttled: bool
    hard: bool                   # 429/503 or explicit Retry-After -> back off aggressively
    retry_after: float | None    # seconds to wait, if the server told us
    fingerprint: str             # "" when no WAF signature matched


def _retry_after_seconds(value: str, now_epoch: float) -> float | None:
    value = value.strip()
    if not value:
        return None
    if value.isdigit():
        return max(0.0, float(value))
    try:  # HTTP-date form
        dt = parsedate_to_datetime(value)
        if dt is None:
            return None
        return max(0.0, dt.timestamp() - now_epoch)
    except (TypeError, ValueError, OverflowError):
        return None


def classify_response(status: int, headers: Mapping[str, str], body: str,
                      now_epoch: float) -> ThrottleVerdict:
    """Decide, from one response, whether the target is pushing back and how hard."""
    low = {str(k).lower(): str(v or "") for k, v in headers.items()}
    retry = _retry_after_seconds(low["retry-after"], now_epoch) if "retry-after" in low else None

    fp = ""
    joined = " ".join(f"{k}:{v}" for k, v in low.items())
    for sub, label in _WAF_HEADER_FINGERPRINTS:
        if sub in joined:
            fp = label
            break

    if status in _HARD_THROTTLE or (retry is not None and retry > 0):
        return ThrottleVerdict(True, True, retry, fp)
    if status in _BLOCK_STATUSES and fp:
        # a 403/406 *with* a WAF signature is a soft block worth easing off for
        return ThrottleVerdict(True, False, retry, fp)
    if status == 0:  # transport error / reset -> treat as a soft throttle
        return ThrottleVerdict(True, False, None, "reset")
    return ThrottleVerdict(False, False, None, fp)


# --- per-host AIMD controller + circuit breaker --------------------------------------

class _Circuit:
    CLOSED, OPEN, HALF_OPEN = "CLOSED", "OPEN", "HALF_OPEN"


@dataclass
class _HostState:
    rate: float                   # current permitted req/s
    min_rate: float
    max_rate: float
    alpha: float                  # additive increase (req/s per clean response)
    beta: float                   # multiplicative decrease factor on throttle
    next_release: float = 0.0     # monotonic time the next request may leave
    inflight: int = 0
    max_inflight: int = 1
    circuit: str = _Circuit.CLOSED
    consecutive_throttles: int = 0
    open_until: float = 0.0
    open_streak: int = 0          # how many times we've opened — grows the cool-off
    requests: int = 0
    bytes_seen: int = 0
    throttles: int = 0
    per_endpoint: dict[str, Any] = field(default_factory=dict[str, Any])


class CircuitOpen(RuntimeError):
    """Raised by acquire() when the host circuit is open/tripped and must pause."""
    def __init__(self, host: str, reason: str):
        super().__init__(f"circuit open for {host}: {reason}")
        self.host, self.reason = host, reason


class AutomationDenied(RuntimeError):
    """Raised by acquire() when ROE forbids automation or we are outside the window."""


class Governor:
    """Adaptive, thread-safe, deterministic request governor, one controller per host."""

    def __init__(
        self,
        *,
        max_rps: float | None,                  # from RoePolicy.max_rps; None -> safe default ceiling
        automation_permitted: bool = True,
        time_window: tuple[int, int] | None = None,
        start_fraction: float = 0.25,           # begin at 25% of the ceiling, earn the rest
        alpha: float = 0.08,                    # +0.08 req/s per clean response
        beta: float = 0.5,                      # halve the rate on a throttle
        trip_after: int = 4,                    # consecutive throttles that open the circuit
        base_cooloff: float = 20.0,             # first open lasts ~this many seconds
        max_cooloff: float = 600.0,
        give_up_after_opens: int = 4,           # this many opens on one host -> permanent trip
        max_inflight: int = 2,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
        wall_clock: Callable[[], float] = time.time,    # for Retry-After HTTP-date math
        rng: random.Random | None = None,
        audit: Callable[[str, dict[str, Any]], None] | None = None,
        now_hour: Callable[[], int] | None = None,      # injected hour for the ROE window
    ) -> None:
        self._ceiling = float(max_rps) if max_rps and max_rps > 0 else 2.0
        self._automation = bool(automation_permitted)
        self._window = time_window
        self._now_hour = now_hour
        self._start_fraction = start_fraction
        self._alpha, self._beta = alpha, beta
        self._trip_after = trip_after
        self._base_cooloff, self._max_cooloff = base_cooloff, max_cooloff
        self._give_up = give_up_after_opens
        self._max_inflight = max_inflight
        self._clock, self._sleep, self._wall = clock, sleeper, wall_clock
        self._rng = rng or random.Random(0xD1A)
        self._audit = audit or (lambda k, p: None)
        self._lock = threading.RLock()
        self._cv = threading.Condition(self._lock)
        self._hosts: dict[str, _HostState] = {}
        self._permanently_tripped: set[str] = set()

    # -- public API ------------------------------------------------------------------

    def acquire(self, host: str, endpoint_key: str | None = None) -> None:
        """Block until a request to ``host`` may be sent. Fail-closed on ROE/circuit."""
        if not self._automation:
            self._audit("gov.deny", {"host": host, "reason": "automation_forbidden"})
            raise AutomationDenied("ROE: automation_permitted is false")
        if self._window is not None and self._now_hour is not None:
            h = self._now_hour()
            lo, hi = self._window
            inside = (lo <= h < hi) if lo <= hi else (h >= lo or h < hi)
            if not inside:
                self._audit("gov.deny", {"host": host, "reason": "outside_window", "hour": h})
                raise AutomationDenied(f"outside ROE window {self._window} (hour {h})")

        total = 0.0
        with self._cv:
            if host in self._permanently_tripped:
                raise CircuitOpen(host, "host permanently tripped after repeated blocks")
            st = self._host(host)
            # wait out an open circuit (bounded); when it expires allow exactly one probe
            while st.circuit == _Circuit.OPEN:
                remaining = st.open_until - self._clock()
                if remaining <= 0:
                    st.circuit = _Circuit.HALF_OPEN
                    break
                self._audit("gov.circuit_wait", {"host": host, "remaining": round(remaining, 2)})
                self._cv.wait(timeout=min(remaining, 5.0))
                if host in self._permanently_tripped:
                    raise CircuitOpen(host, "tripped while waiting")
            # concurrency gate
            while st.inflight >= st.max_inflight:
                self._cv.wait(timeout=5.0)
            # rate gate: honor next_release, then add full jitter across the interval
            now = self._clock()
            wait = max(0.0, st.next_release - now)
            interval = 1.0 / max(st.rate, 1e-6)
            jitter = self._rng.uniform(0.0, interval)   # full jitter spreads the cadence
            total = wait + jitter
            st.next_release = now + total + interval
            st.inflight += 1
        if total > 0:
            self._sleep(total)

    def observe(self, host: str, status: int, headers: Mapping[str, str],
                body: str = "", *, endpoint_key: str | None = None) -> None:
        """Feed one response back: adapt the rate, drive the circuit, record cost."""
        verdict = classify_response(status, headers, body, self._wall())
        with self._cv:
            st = self._host(host)
            st.inflight = max(0, st.inflight - 1)
            st.requests += 1
            st.bytes_seen += len(body or "")
            if endpoint_key:
                ec = st.per_endpoint.setdefault(endpoint_key, {"n": 0, "throttled": 0, "bytes": 0})
                ec["n"] += 1
                ec["bytes"] += len(body or "")

            if verdict.throttled:
                st.throttles += 1
                if endpoint_key:
                    st.per_endpoint[endpoint_key]["throttled"] += 1
                st.consecutive_throttles += 1
                factor = self._beta * (self._beta if verdict.hard else 1.0)  # hard throttle hits twice
                st.rate = max(st.min_rate, st.rate * factor)
                if verdict.retry_after and verdict.retry_after > 0:          # obeyed to the second
                    st.next_release = self._clock() + verdict.retry_after
                if st.circuit == _Circuit.HALF_OPEN or st.consecutive_throttles >= self._trip_after:
                    self._open_circuit(host, st, verdict.fingerprint or f"status {status}")
                self._audit("gov.throttled", {"host": host, "status": status,
                                              "fp": verdict.fingerprint, "rate": round(st.rate, 3)})
            else:
                st.consecutive_throttles = 0
                if st.circuit == _Circuit.HALF_OPEN:
                    st.circuit = _Circuit.CLOSED                              # probe succeeded -> recover
                    st.open_streak = 0
                    self._audit("gov.circuit_close", {"host": host})
                st.rate = min(st.max_rate, st.rate + st.alpha)               # additive increase, capped
            self._cv.notify_all()

    def tripped(self, host: str) -> bool:
        with self._lock:
            if host in self._permanently_tripped:
                return True
            st = self._hosts.get(host)
            return bool(st and st.circuit == _Circuit.OPEN and self._clock() < st.open_until)

    def report(self) -> dict[str, Any]:
        """Per-host and per-endpoint cost — consumed by the econ layer."""
        with self._lock:
            return {
                h: {"rate": round(s.rate, 3), "requests": s.requests, "bytes": s.bytes_seen,
                    "throttles": s.throttles, "circuit": s.circuit,
                    "endpoints": {k: dict(v) for k, v in s.per_endpoint.items()}}
                for h, s in self._hosts.items()
            }

    # -- internals -------------------------------------------------------------------

    def _host(self, host: str) -> _HostState:
        st = self._hosts.get(host)
        if st is None:
            start = max(0.2, self._ceiling * self._start_fraction)
            st = _HostState(rate=start, min_rate=0.1, max_rate=self._ceiling,
                            alpha=self._alpha, beta=self._beta, max_inflight=self._max_inflight)
            self._hosts[host] = st
        return st

    def _open_circuit(self, host: str, st: _HostState, reason: str) -> None:
        st.open_streak += 1
        if st.open_streak > self._give_up:
            self._permanently_tripped.add(host)                    # acquire() raises on this
            st.circuit = _Circuit.OPEN
            st.open_until = float("inf")
            self._audit("gov.trip_permanent", {"host": host, "reason": reason})
            self._cv.notify_all()
            return
        cool = min(self._max_cooloff, self._base_cooloff * (2 ** (st.open_streak - 1)))
        cool = self._rng.uniform(self._base_cooloff, max(self._base_cooloff, cool))  # decorrelated
        st.circuit = _Circuit.OPEN
        st.open_until = self._clock() + cool
        st.consecutive_throttles = 0
        st.rate = st.min_rate
        self._audit("gov.circuit_open", {"host": host, "cool": round(cool, 1), "reason": reason})
