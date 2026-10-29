"""Ingest reviewed answers (offline), validate (schema + scope, fail-closed), promote to playbook."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable
from .playbook import Playbook, Rule
from .schemas import validate_answers
__all__ = ["ApplyReport", "apply_answers"]


@dataclass(frozen=True)
class ApplyReport:
    playbook: Playbook
    applied: tuple[str, ...]
    rejected: tuple[tuple[str, str], ...]   # (answer_id, reason)


def apply_answers(answers: dict[str, Any], playbook: Playbook,
                  scope_check: Callable[[str], bool] | None = None) -> ApplyReport:
    validate_answers(answers)
    pb = playbook
    applied: list[str] = []
    rejected: list[tuple[str, str]] = []
    for ans in answers.get("answers", []):
        url = ans.get("url") or (ans.get("rule", {}) or {}).get("url")
        if url and scope_check is not None and not scope_check(url):
            rejected.append((ans["id"], "OUT_OF_SCOPE"))   # fail-closed
            continue
        if "rule" in ans:
            r = ans["rule"]
            pb = pb.add_rule(Rule(ans["id"], r.get("when", {}), r.get("action", {})))
            applied.append(ans["id"])
        elif "id_pattern" in ans:
            ip = ans["id_pattern"]
            pb = pb.set_id_pattern(ip["template"], ip["pattern"])
            applied.append(ans["id"])
        else:
            rejected.append((ans["id"], "NO_ACTIONABLE_FIELD"))
    return ApplyReport(pb, tuple(applied), tuple(rejected))
