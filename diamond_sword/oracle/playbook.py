"""The frozen, diffable program for a target: rules + learned id patterns. Immutable/functional."""
from __future__ import annotations
from dataclasses import dataclass, field, replace
from typing import Any
from .schemas import validate_playbook
__all__ = ["Rule", "Playbook"]


@dataclass(frozen=True)
class Rule:
    id: str
    when: dict[str, Any] = field(default_factory=dict)
    action: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Playbook:
    target: str
    version: int = 1
    rules: tuple[Rule, ...] = ()
    id_patterns: dict[str, str] = field(default_factory=dict)

    def add_rule(self, rule: Rule) -> "Playbook":
        if any(r.id == rule.id for r in self.rules):   # idempotent: same id never duplicated
            return self
        return replace(self, rules=self.rules + (rule,))

    def set_id_pattern(self, template: str, pattern: str) -> "Playbook":
        d = dict(self.id_patterns)
        d[template] = pattern
        return replace(self, id_patterns=d)

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "target": self.target,
                "rules": [{"id": r.id, "when": r.when, "action": r.action} for r in self.rules],
                "id_patterns": dict(self.id_patterns)}

    @staticmethod
    def from_dict(doc: dict[str, Any]) -> "Playbook":
        d = validate_playbook(doc)
        rules = tuple(Rule(r["id"], r.get("when", {}), r.get("action", {})) for r in d.get("rules", []))
        return Playbook(d["target"], int(d.get("version", 1)), rules, dict(d.get("id_patterns", {})))

    def diff(self, other: "Playbook") -> dict[str, list[str]]:
        mine = {r.id for r in self.rules}
        theirs = {r.id for r in other.rules}
        return {"added": sorted(theirs - mine), "removed": sorted(mine - theirs)}
