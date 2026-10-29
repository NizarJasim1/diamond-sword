"""
CaptureLedger — the poison-fuse made concrete.

Every exchange ``LiveTransport`` produces is recorded here with the session
epoch it was sent under and a clean/quarantined verdict. Only clean exchanges
are assembled into the ``HarLog`` that reaches IOLITE; quarantined ones are kept
apart for the audit trail and never shape the authorization model. Capturing
less is always cheaper than capturing a lie.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .har_model import HarEntry, HarLog


@dataclass
class _Quarantined:
    pid: str
    epoch: int
    entry: HarEntry
    why: str = "session_bracket"


@dataclass
class CaptureLedger:
    clean: HarLog = field(default_factory=HarLog)
    quarantine: list[Any] = field(default_factory=list)
    _counts: dict[str, Any] = field(default_factory=lambda: {"clean": 0, "quarantined": 0})

    def record(self, *, pid: str, epoch: int, clean: bool, method: str, url: str, status: int,
               req_headers: Mapping[str, str] | None, req_body: str | None,
               resp_headers: Mapping[str, str] | None, resp_body: str | None,
               why: str = "session_bracket") -> None:
        entry = HarEntry(
            principal=pid, method=method, url=url, status=status,
            req_headers=dict(req_headers or {}), req_body=req_body,
            resp_headers=dict(resp_headers or {}), resp_body=resp_body,
        )
        if clean:
            self.clean.add(entry)
            self._counts["clean"] += 1
        else:
            self.quarantine.append(_Quarantined(pid, epoch, entry, why))
            self._counts["quarantined"] += 1

    def clean_har(self, pid: str | None = None) -> HarLog:
        """The only HAR that may be handed to IOLITE. Optionally per-principal."""
        if pid is None:
            return self.clean
        sub = HarLog()
        for e in self.clean.entries:
            if e.principal == pid:
                sub.add(e)
        return sub

    def stats(self) -> dict[str, Any]:
        return dict(self._counts)
