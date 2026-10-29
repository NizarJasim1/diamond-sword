"""Rank templates by authorization-attack value, deterministically (OWASP API Top 10; BOLA=API1).

Higher score = hunt first: object ids, money, admin/role, state-change verbs, export/download,
GraphQL. Pure, stdlib only, no network/clock/randomness.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from .template_engine import path_template

__all__ = ["TriageResult", "score_template", "score_url", "rank"]

_PLACEHOLDERS = frozenset({"{num}", "{uuid}", "{hex}", "{token}", "{date}"})
_MONEY = frozenset({"pay", "payment", "payments", "billing", "invoice", "invoices", "wallet",
                    "withdraw", "transfer", "payout", "charge", "refund", "balance", "card",
                    "cards", "checkout", "order", "orders", "subscription", "price", "coupon"})
_ADMIN = frozenset({"admin", "administrator", "manage", "management", "role", "roles",
                    "permission", "permissions", "internal", "superuser", "sudo", "config",
                    "settings", "owner", "member", "members", "staff", "impersonate"})
_EXPORT = frozenset({"export", "download", "report", "reports", "backup", "dump", "csv", "pdf"})
_AUTH = frozenset({"login", "logout", "token", "session", "oauth", "sso", "2fa", "mfa",
                   "password", "reset", "verify", "auth", "credential", "credentials"})
_GQL = frozenset({"graphql", "graphiql", "graphql-explorer"})
_STATE_METHOD = {"POST": 3, "PUT": 4, "PATCH": 4, "DELETE": 6}
_STATIC_SUFFIX = (".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                  ".woff", ".woff2", ".ttf", ".map", ".webp", ".avif")
_ID_QKEYS = frozenset({"id", "uid", "account", "user", "owner", "member", "pid", "gid", "ref"})


@dataclass(frozen=True)
class TriageResult:
    score: int
    categories: tuple[str, ...]
    reasons: tuple[str, ...]


def _toks(seg: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", seg.lower()) if t]


def _qkey_is_id(k: str) -> bool:
    k = k.lower()
    return k in _ID_QKEYS or k.endswith("_id") or k == "id"


def score_template(method: str, template: str, query_keys: tuple[str, ...] = ()) -> TriageResult:
    """Score a (method, path_template, query_keys). Deterministic integer + categories."""
    method = (method or "GET").upper()
    segs = [s for s in template.split("/") if s]
    last = segs[-1] if segs else ""
    cats: set[str] = set()
    reasons: list[str] = []

    # Pure static assets carry no authz value regardless of other tokens.
    if any(last.lower().endswith(suf) for suf in _STATIC_SUFFIX):
        return TriageResult(0, ("static",), ("static asset",))

    score = 0
    for seg in segs:
        if seg in _PLACEHOLDERS:
            score += 2
            cats.add("object_id")
            reasons.append(f"id segment {seg}")
        for t in _toks(seg):
            if t in _MONEY:
                score += 5; cats.add("money"); reasons.append(f"money:{t}")
            if t in _ADMIN:
                score += 5; cats.add("admin"); reasons.append(f"admin:{t}")
            if t in _EXPORT:
                score += 3; cats.add("export"); reasons.append(f"export:{t}")
            if t in _AUTH:
                score += 3; cats.add("auth"); reasons.append(f"auth:{t}")
            if t in _GQL:
                score += 4; cats.add("graphql"); reasons.append(f"graphql:{t}")

    if method in _STATE_METHOD:
        score += _STATE_METHOD[method]
        cats.add("state_change")
        reasons.append(f"method:{method}")

    for k in query_keys:
        if _qkey_is_id(k):
            score += 2; cats.add("object_id"); reasons.append(f"id query key:{k}")

    return TriageResult(score, tuple(sorted(cats)), tuple(reasons))


def score_url(url: str, method: str = "GET") -> TriageResult:
    parts = urlsplit(url)
    tmpl, _ = path_template(parts.path or "/")
    qkeys = tuple(sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)}))
    return score_template(method, tmpl, qkeys)


def rank(items: list[tuple[str, str, str, tuple[str, ...]]]) -> list[tuple[str, TriageResult]]:
    """items: (template_key, method, path_template, query_keys). Returns sorted desc by score,
    tie-broken by template_key, each paired with its TriageResult. Stable + deterministic."""
    scored = [(key, score_template(m, t, q)) for key, m, t, q in items]
    scored.sort(key=lambda kr: (-kr[1].score, kr[0]))
    return scored
