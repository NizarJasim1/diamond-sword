"""Fail-closed enforcement of a program's scope on every URL Diamond Sword would touch.

This is the "enforce" side of the scope boundary (``scope_parser`` is the "define" side).
Every outbound request in Diamond Sword must pass :meth:`ScopeGuard.check` first. The guard never
guesses: anything not provably in scope is denied.

Order of judgment (and why):
1. Parse the URL safely. A URL we cannot parse is denied (``DENY_BAD_URL``).
2. Scheme must be http/https. Other schemes are not network targets (``DENY_BAD_SCHEME``).
3. Extract the host via ``urlsplit().hostname`` — this strips any ``user:pass@`` and port,
   which defeats ``https://api.acmepay.example@evil.com/`` (hostname becomes ``evil.com``).
4. Out-of-scope is checked BEFORE in-scope, because exclusion wins in real programs
   (``dev.acmepay.example`` is excluded even under ``*.acmepay.example``).
5. In-scope match -> allow. No match -> deny (``DENY_NOT_IN_SCOPE``), the fail-closed default.

Every decision is a structured :class:`Decision` and is handed to a :class:`DecisionSink`,
so the audit ledger (built next) can record a tamper-evident trail with zero changes here.

Pure, deterministic, standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit

from .scope_parser import Asset, Engagement, host_matches, normalize_host, path_matches

__all__ = ["Reason", "Decision", "DecisionSink", "ListSink", "ScopeGuard"]


class Reason:
    """Stable decision reason codes (stable strings are easy to log, test, and audit)."""

    ALLOW_IN_SCOPE = "ALLOW_IN_SCOPE"
    DENY_OUT_OF_SCOPE = "DENY_OUT_OF_SCOPE"
    DENY_NOT_IN_SCOPE = "DENY_NOT_IN_SCOPE"
    DENY_BAD_SCHEME = "DENY_BAD_SCHEME"
    DENY_BAD_HOST = "DENY_BAD_HOST"
    DENY_BAD_URL = "DENY_BAD_URL"


@dataclass(frozen=True)
class Decision:
    """The verdict for one URL: whether it is allowed, why, and which rule matched."""

    allowed: bool
    reason: str
    url: str
    host: str | None = None
    matched: str | None = None  # the raw scope entry that decided it, when any

    def __bool__(self) -> bool:  # lets callers write `if guard.check(url):`
        return self.allowed


@runtime_checkable
class DecisionSink(Protocol):
    """Anything that records decisions (the audit ledger will implement this)."""

    def record(self, decision: Decision) -> None: ...


class ListSink:
    """A simple in-memory sink, useful for tests and as the audit-ledger seam."""

    def __init__(self) -> None:
        self.decisions: list[Decision] = []

    def record(self, decision: Decision) -> None:
        self.decisions.append(decision)


class _NullSink:
    def record(self, decision: Decision) -> None:  # pragma: no cover - trivial
        return None


class ScopeGuard:
    """Decides, fail-closed, whether a URL is inside the engagement scope.

    Construct once per engagement and call :meth:`check` for every candidate URL.
    """

    _ALLOWED_SCHEMES = frozenset({"http", "https"})
    _DEFAULT_PORTS = {"http": 80, "https": 443}

    def __init__(self, engagement: Engagement, sink: DecisionSink | None = None) -> None:
        self._eng = engagement
        self._sink: DecisionSink = sink if sink is not None else _NullSink()
        # Only network assets can ever match a URL; precompute to keep check() tight.
        self._in = engagement.network_in_scope
        self._out = engagement.network_out_scope

    # -- public API ---------------------------------------------------------------------

    def check(self, url: str, method: str | None = None) -> Decision:
        """Return the :class:`Decision` for ``url`` and record it to the sink.

        ``method`` is accepted for a complete audit record; method policy (read-only vs
        mutating) is enforced separately by the ROE unit, not here.
        """
        decision = self._judge(url)
        self._sink.record(decision)
        return decision

    def allowed(self, url: str) -> bool:
        """Convenience boolean wrapper around :meth:`check`."""
        return self.check(url).allowed

    # -- internals ----------------------------------------------------------------------

    def _judge(self, url: str) -> Decision:
        if not isinstance(url, str) or not url.strip():
            return Decision(False, Reason.DENY_BAD_URL, str(url))

        try:
            parts = urlsplit(url.strip())
        except ValueError:
            return Decision(False, Reason.DENY_BAD_URL, url)

        scheme = (parts.scheme or "").lower()
        if scheme not in self._ALLOWED_SCHEMES:
            return Decision(False, Reason.DENY_BAD_SCHEME, url, matched=scheme or None)

        # .hostname strips userinfo and port and lowercases; this is the anti-spoofing step.
        raw_host = parts.hostname
        try:
            port = parts.port  # may raise ValueError on a malformed port
        except ValueError:
            return Decision(False, Reason.DENY_BAD_URL, url)

        host = normalize_host(raw_host)
        if host is None:
            return Decision(False, Reason.DENY_BAD_HOST, url)

        effective_port = port if port is not None else self._DEFAULT_PORTS[scheme]
        path = parts.path or "/"

        # 1) Out-of-scope wins. Check exclusions first.
        hit = self._first_match(self._out, host, effective_port, path)
        if hit is not None:
            return Decision(False, Reason.DENY_OUT_OF_SCOPE, url, host=host, matched=hit.raw)

        # 2) In-scope match -> allow.
        hit = self._first_match(self._in, host, effective_port, path)
        if hit is not None:
            return Decision(True, Reason.ALLOW_IN_SCOPE, url, host=host, matched=hit.raw)

        # 3) Fail-closed default.
        return Decision(False, Reason.DENY_NOT_IN_SCOPE, url, host=host)

    @staticmethod
    def _first_match(assets: tuple[Asset, ...], host: str, port: int, path: str) -> Asset | None:
        for a in assets:
            if not host_matches(a.host, host):
                continue
            if a.port is not None and a.port != port:
                continue
            if not path_matches(a.path, path):
                continue
            return a
        return None
