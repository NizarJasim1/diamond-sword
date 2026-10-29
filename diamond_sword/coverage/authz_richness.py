"""
Authorization-richness scoring — decide WHERE a finite crawl should spend its
budget so it lands on the places BOLA / BFLA / IDOR actually live, instead of
burning a giant state-space on blind breadth-first walking.

WHAT THIS IS, AND IS NOT
------------------------
It is NOT a vulnerability oracle — ONYX owns every verdict by Δstate. It is a
*prioritizer*: from structural signals only, deterministically, it ranks how
likely a state is to HIDE an authorization bug, so the state-graph frontier
explores the object-bearing, mutating, privilege-adjacent surface first and the
inert marketing pages last. On a target larger than GitLab you will never
exercise everything; this is what makes "the part you do exercise" the right
part.

THE SIGNALS (each mapped to the bug class it predicts)
------------------------------------------------------
  * OBJECT_IN_PATH  — the route carries a swappable id ({id}/{uuid})     -> BOLA/IDOR
  * OWNER_FIELD     — a form carries an owner / user / tenant field       -> cross-principal / cross-tenant (the crown)
  * MUTATING        — a destructive/creative control or a write method    -> BFLA / mass-assignment reach
  * PRIVILEGE       — admin / members / roles / billing / token surface   -> privilege escalation, BFLA
  * API             — /api or /graphql or a captured XHR endpoint         -> the real object surface, not the chrome
  * EXPORT          — export / download / report                          -> query-authz inheritance leaks

Weights are defaults, overridable per engagement. The score is a small integer so
it is cheap to sort and stable to reason about; `reasons` is returned alongside
so a dossier can explain *why* a state ranked where it did.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True)
class RichnessWeights:
    object_in_path: int = 5
    owner_field: int = 6        # cross-principal / cross-tenant is the highest-value authz bug
    mutating: int = 4
    privilege: int = 5
    api: int = 3
    export: int = 4
    count_bonus_cap: int = 3    # a little extra for many such controls, but bounded


_PRIVILEGE_TOKENS = (
    "admin", "settings", "member", "members", "role", "roles", "permission",
    "permissions", "acl", "billing", "invoice", "token", "api_key", "apikey",
    "access_token", "keys", "team", "org", "organization", "owner", "transfer",
    "impersonat", "sudo", "grant", "revoke", "approval",
)
_EXPORT_TOKENS = ("export", "download", "report", "backup", "dump", "csv", "pdf", "archive")
_API_TOKENS = ("/api", "/graphql", "/rest", "/v1/", "/v2/", "/v3/", "/gql")
_OWNER_FIELDS = frozenset({
    "owner", "owner_id", "ownerid", "user_id", "userid", "author", "author_id",
    "account", "account_id", "assignee", "assignee_id", "created_by", "customer",
    "customer_id", "org_id", "organization_id", "group_id", "tenant", "tenant_id",
    "namespace_id", "project_id",
})
_MUTATING_LABELS = (
    "delete", "remove", "save", "update", "edit", "create", "add ", "new ",
    "transfer", "invite", "revoke", "grant", "disable", "enable", "archive",
    "merge", "approve", "deactivate", "reset", "rotate", "pay", "refund",
)


def _has_object_segment(url_template: str) -> bool:
    return "{" in url_template  # templater collapses a swappable id to {id}/{uuid}


def _is_api(url_template: str) -> bool:
    low = url_template.lower()
    return any(t in low for t in _API_TOKENS)


def _priv_hit(text: str) -> bool:
    low = (text or "").lower()
    return any(t in low for t in _PRIVILEGE_TOKENS)


def _export_hit(text: str) -> bool:
    low = (text or "").lower()
    return any(t in low for t in _EXPORT_TOKENS)


def control_is_owner_field(field_names: Any) -> bool:
    for f in field_names or ():
        if str(f).strip().lower() in _OWNER_FIELDS:
            return True
    return False


def label_is_mutating(label: str) -> bool:
    low = f" {(label or '').lower()} "
    return any(tok in low for tok in _MUTATING_LABELS)


def score_state(url_template: str, controls: Any, weights: RichnessWeights | None = None
                ) -> tuple[int, tuple[str, ...]]:
    """Return (score, reasons). `controls` are duck-typed: each exposes
    .kind, .method, .label, .template, .bears_object, .owner_field, .mutating."""
    w = weights or RichnessWeights()
    score = 0
    reasons: list[str] = []

    # --- state-level signals (from the URL template) ---
    if _has_object_segment(url_template):
        score += w.object_in_path
        reasons.append("object_in_path")
    if _is_api(url_template):
        score += w.api
        reasons.append("api_surface")
    if _priv_hit(url_template):
        score += w.privilege
        reasons.append("privilege_path")

    # --- control-level signals (bounded count bonus so one page can't explode) ---
    n_owner = n_mut = n_priv = n_obj = n_export = n_api = 0
    for c in controls or ():
        tmpl = getattr(c, "template", "") or ""
        label = getattr(c, "label", "") or ""
        if getattr(c, "owner_field", False):
            n_owner += 1
        if getattr(c, "mutating", False) or label_is_mutating(label):
            n_mut += 1
        if getattr(c, "bears_object", False) or _has_object_segment(tmpl):
            n_obj += 1
        if _priv_hit(tmpl) or _priv_hit(label):
            n_priv += 1
        if _export_hit(tmpl) or _export_hit(label):
            n_export += 1
        if getattr(c, "kind", "") == "api" or _is_api(tmpl):
            n_api += 1

    def _add(count: int, weight: int, reason: str) -> None:
        nonlocal score
        if count:
            score += weight + min(count, w.count_bonus_cap)
            reasons.append(f"{reason}x{count}")

    _add(n_owner, w.owner_field, "owner_field")
    _add(n_mut, w.mutating, "mutating")
    _add(n_obj, w.object_in_path, "object_control")
    _add(n_priv, w.privilege, "privilege_control")
    _add(n_export, w.export, "export")
    _add(n_api, w.api, "api_control")

    return score, tuple(reasons)


def area_of(url_template: str) -> str:
    """The coarse area a template belongs to — the first meaningful path segment.
    Used by the state-graph to budget areas fairly (so /issues cannot starve
    /admin on a giant app)."""
    path = urlsplit(url_template).path if "://" in url_template else url_template
    for seg in (path or "/").split("/"):
        if seg and seg != "{id}" and not seg.startswith("{"):
            return seg.lower()
    return "root"
