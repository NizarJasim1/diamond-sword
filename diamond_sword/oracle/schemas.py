"""Minimal strict validators for questions/answers/playbook docs (stdlib; no jsonschema)."""
from __future__ import annotations
from typing import Any
__all__ = ["SchemaError", "validate_questions", "validate_answers", "validate_playbook"]


class SchemaError(ValueError):
    """Raised when an oracle document is structurally malformed."""


def _obj(d: Any, where: str) -> dict[str, Any]:
    if not isinstance(d, dict):
        raise SchemaError(f"{where} must be an object")
    return d


def _list(d: Any, where: str) -> list[Any]:
    if not isinstance(d, list):
        raise SchemaError(f"{where} must be a list")
    return d


def validate_questions(doc: Any) -> dict[str, Any]:
    d = _obj(doc, "questions doc")
    for q in _list(d.get("questions", []), "questions"):
        q = _obj(q, "question")
        if not isinstance(q.get("id"), str) or not q["id"]:
            raise SchemaError("question.id must be a non-empty string")
        if not isinstance(q.get("kind"), str) or not q["kind"]:
            raise SchemaError("question.kind must be a non-empty string")
    return d


def validate_answers(doc: Any) -> dict[str, Any]:
    d = _obj(doc, "answers doc")
    for a in _list(d.get("answers", []), "answers"):
        a = _obj(a, "answer")
        if not isinstance(a.get("id"), str) or not a["id"]:
            raise SchemaError("answer.id must be a non-empty string")
        if "rule" in a:
            _obj(a["rule"], "answer.rule")
        elif "id_pattern" in a:
            ip = _obj(a["id_pattern"], "answer.id_pattern")
            if not isinstance(ip.get("template"), str) or not isinstance(ip.get("pattern"), str):
                raise SchemaError("id_pattern needs string template+pattern")
    return d


def validate_playbook(doc: Any) -> dict[str, Any]:
    d = _obj(doc, "playbook")
    if not isinstance(d.get("target"), str) or not d["target"]:
        raise SchemaError("playbook.target must be a non-empty string")
    for r in _list(d.get("rules", []), "rules"):
        r = _obj(r, "rule")
        if not isinstance(r.get("id"), str) or not r["id"]:
            raise SchemaError("rule.id must be a non-empty string")
    _obj(d.get("id_patterns", {}), "id_patterns")
    inter = d.get("interaction")
    if inter is not None:
        inter = _obj(inter, "playbook.interaction")
        for f in _list(inter.get("flows", []), "interaction.flows"):
            f = _obj(f, "flow")
            if not isinstance(f.get("id"), str) or not f["id"]:
                raise SchemaError("flow.id must be a non-empty string")
            for s in _list(f.get("steps", []), "flow.steps"):
                s = _obj(s, "step")
                if not isinstance(s.get("action"), str) or not s["action"]:
                    raise SchemaError("step.action must be a non-empty string")
        for key in ("priority", "avoid", "seeds"):
            v = inter.get(key, [])
            if v is not None and (not isinstance(v, list) or any(not isinstance(x, str) for x in v)):
                raise SchemaError(f"interaction.{key} must be a list of strings")
    return d
