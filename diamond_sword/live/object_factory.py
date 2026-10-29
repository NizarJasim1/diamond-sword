"""
Dual-principal object factory — mint the owner/attacker material that a BOLA
proof is impossible without, autonomously and inside the legal gate.

WHY NOTHING DOWNSTREAM WORKS WITHOUT THIS
-----------------------------------------
IDOR/BOLA is "an owner creates a resource; an attacker then tries to reach it."
You cannot prove it by browsing: you need, as *two* principals you control, two
comparable objects whose real ids you captured at the moment of creation — so
ONYX can make B read the object A owns and watch the state leak. Everything the
rest of the pipeline does with cross-principal access rests on this material
existing and being correctly owned. Until now it leaned on the operator creating
objects by hand; this closes that, on a target larger than GitLab, without ever
guessing who owns what — ownership here is *ground truth*, because this code
created the object as that principal one moment earlier.

HOW IT STAYS SAFE AND SMALL
---------------------------
  * Every create and every cleanup is a mutation, so it goes through the real
    consent gate (``ConsentGate.authorize`` -> ``Grant``). No grant, or a dry-run
    grant, and nothing is sent — fail-closed, by the same rule as any other write.
  * Minimal footprint: only *required* fields are filled, with the smallest valid
    value, and unique-looking fields get a deterministic probe token so repeated
    creates do not collide. Reversible when the surface offers a delete —
    ``cleanup()`` removes what it made, through the gate again.
  * It only *produces and labels* material; it never decides a breach. ONYX owns
    every verdict by Δstate. The factory's one claim — "principal P owns object
    O" — is a fact it witnessed, not an inference.

It drives everything through the one LiveTransport chokepoint, so scope, session
liveness, pacing and the capture ledger apply to factory traffic exactly as they
do to a read.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Sequence
from urllib.parse import urlencode, urljoin, urlsplit

# --- field specs + minimal valid payload synthesis -----------------------------------

@dataclass(frozen=True)
class FieldSpec:
    name: str
    kind: str = "string"          # string|text|email|int|bool|enum|id|ref
    required: bool = True
    options: tuple[str, ...] = ()  # for enum
    ref_otype: str = ""           # for ref/id: the object type this field points at


def minimal_payload(fields: Sequence[FieldSpec], *, seq: int,
                    owner_refs: dict[str, str] | None = None) -> dict[str, str]:
    """Smallest valid body: only required fields, smallest valid value each.
    ``owner_refs`` maps an otype -> an id this principal already owns, so a
    required parent/owner reference points at the principal's OWN object (keeping
    the new object genuinely theirs)."""
    refs = owner_refs or {}
    body: dict[str, str] = {}
    for f in fields:
        if not f.required:
            continue                                  # footprint: skip optionals
        k = f.kind
        if k in ("ref", "id"):
            body[f.name] = refs.get(f.ref_otype, "1")
        elif k == "enum":
            body[f.name] = (f.options[0] if f.options else "default")
        elif k == "email":
            body[f.name] = f"ds+probe{seq}@example.test"
        elif k == "int":
            body[f.name] = "1"
        elif k == "bool":
            body[f.name] = "false"
        elif k == "text":
            body[f.name] = "ds probe"
        else:  # string — unique so apps that require a unique name don't 409
            body[f.name] = f"ds-probe-{seq}"
    return body


def _encode(fields: dict[str, str], content_type: str) -> str:
    if "json" in content_type:
        return json.dumps(fields)
    return urlencode(fields)


# --- recipe + results ----------------------------------------------------------------

@dataclass(frozen=True)
class CreateRecipe:
    otype: str
    collection_url: str                 # POST target that mints the object
    fields: dict[str, str]              # already-synthesized minimal payload
    method: str = "POST"
    content_type: str = "application/json"
    id_json_keys: tuple[str, ...] = ("id", "iid", "key", "slug", "uuid", "gid")
    instance_url_template: str = ""     # e.g. "/api/v4/projects/{id}" (read-back; Location preferred)
    delete_url_template: str = ""       # e.g. "/api/v4/projects/{id}"
    delete_method: str = "DELETE"


def recipe_from_form(otype: str, collection_url: str, field_specs: Sequence[FieldSpec], *,
                     seq: int, method: str = "POST", content_type: str = "application/json",
                     owner_refs: dict[str, str] | None = None,
                     instance_url_template: str = "", delete_url_template: str = "") -> CreateRecipe:
    """Build a recipe from a create-form the explorer discovered (its action URL
    and field specs), synthesizing the minimal payload. This is the seam to #3:
    the state graph flags the create affordance; the factory turns it into material."""
    return CreateRecipe(
        otype=otype, collection_url=collection_url,
        fields=minimal_payload(field_specs, seq=seq, owner_refs=owner_refs),
        method=method, content_type=content_type,
        instance_url_template=instance_url_template, delete_url_template=delete_url_template,
    )


@dataclass
class OwnedObject:
    pid: str
    otype: str
    oid: str
    instance_url: str                   # ground-truth read-back URL (the owner can read this)
    collection_url: str
    seq: int
    delete_url: str = ""
    delete_method: str = "DELETE"


@dataclass(frozen=True)
class AttackPair:
    """The BOLA substrate ONYX consumes: attacker_pid attempts owner's read-back URL."""
    otype: str
    owner_pid: str
    owner_object: OwnedObject
    attacker_pid: str
    readback_url: str


# --- the factory ---------------------------------------------------------------------

class ObjectFactory:
    def __init__(
        self,
        *,
        transport: Any,                 # live.transport.LiveTransport
        consent_gate: Any,              # legal.consent_gate.ConsentGate (authorize -> Grant)
        principals: Sequence[str],
        base_url: str = "",
        audit: Callable[[str, dict[str, Any]], None] | None = None,
        now_hour: Callable[[], int] | None = None,
    ) -> None:
        self._tx = transport
        self._gate = consent_gate
        self._principals = list(principals)
        self._base = base_url
        self._audit = audit or (lambda k, p: None)
        self._now_hour = now_hour
        self._objs: list[OwnedObject] = []
        self._seq = 0

    # -- creation --------------------------------------------------------------------

    def seed(self, recipe: CreateRecipe, pid: str) -> OwnedObject | None:
        """Create one object as ``pid`` (gated). Returns the owned object or None
        when the gate refuses, the create fails, or no id can be recovered."""
        from ..legal.roe import Action

        self._seq += 1
        action = Action(kind="request", method=recipe.method, url=recipe.collection_url,
                        label=f"create {recipe.otype}", mutating=True)
        grant = self._gate.authorize(action, self._now_hour() if self._now_hour else None)
        if not getattr(grant, "proceed", False):
            self._audit("factory.denied", {"otype": recipe.otype, "pid": pid,
                                           "reason": getattr(grant, "reason", "denied")})
            return None
        if getattr(grant, "dry_run", False):
            self._audit("factory.dry_run", {"otype": recipe.otype, "pid": pid,
                                            "fields": list(recipe.fields.keys())})
            return None

        body = _encode(recipe.fields, recipe.content_type)
        res = self._tx.request(pid, recipe.method, recipe.collection_url, body=body,
                               extra_headers={"Content-Type": recipe.content_type},
                               mutating=True, label=f"create {recipe.otype}", grant=grant)
        if not res.sent or res.response is None or res.status not in (200, 201, 202):
            self._audit("factory.create_failed", {"otype": recipe.otype, "pid": pid,
                                                   "status": res.status, "reason": res.reason})
            return None

        oid = self._extract_id(res.response, recipe)
        if not oid:
            self._audit("factory.no_id", {"otype": recipe.otype, "pid": pid, "status": res.status})
            return None

        instance_url = self._instance_url(res.response, recipe, oid)
        delete_url = (self._abs(recipe.delete_url_template.replace("{id}", oid))
                      if recipe.delete_url_template else instance_url)
        obj = OwnedObject(pid=pid, otype=recipe.otype, oid=oid, instance_url=instance_url,
                          collection_url=recipe.collection_url, seq=self._seq,
                          delete_url=delete_url, delete_method=recipe.delete_method)
        self._objs.append(obj)
        self._audit("factory.created", {"otype": recipe.otype, "pid": pid, "oid": oid,
                                        "instance_url": instance_url})
        return obj

    def seed_pair(self, recipe_for: Callable[[str], CreateRecipe],
                  principals: Sequence[str] | None = None) -> list[OwnedObject]:
        """Create one comparable object per principal (default: the first two) so
        each can serve as owner while the others serve as attackers. ``recipe_for``
        is a per-principal recipe builder (payloads must differ enough not to
        collide — the ``seq`` in minimal_payload already handles uniqueness)."""
        pids = list(principals or self._principals[:2])
        made: list[OwnedObject] = []
        for pid in pids:
            obj = self.seed(recipe_for(pid), pid)
            if obj is not None:
                made.append(obj)
        return made

    # -- consumption -----------------------------------------------------------------

    def pairs(self, otype: str | None = None) -> list[AttackPair]:
        """Every owned object × every OTHER principal — the owner/attacker matrix
        handed to IOLITE/ONYX as cross-principal probes."""
        out: list[AttackPair] = []
        for o in self._objs:
            if otype and o.otype != otype:
                continue
            for p in self._principals:
                if p == o.pid:
                    continue
                out.append(AttackPair(otype=o.otype, owner_pid=o.pid, owner_object=o,
                                      attacker_pid=p, readback_url=o.instance_url))
        return out

    def owned(self) -> list[OwnedObject]:
        return list(self._objs)

    # -- reversal (minimal footprint) ------------------------------------------------

    def cleanup(self) -> dict[str, Any]:
        """Best-effort deletion of everything created, through the gate again.
        Leaves the target as close to untouched as the surface allows."""
        from ..legal.roe import Action

        removed, kept = 0, 0
        for o in self._objs:
            if not o.delete_url:
                kept += 1
                continue
            action = Action(kind="request", method=o.delete_method, url=o.delete_url,
                            label=f"delete {o.otype}", mutating=True)
            grant = self._gate.authorize(action, self._now_hour() if self._now_hour else None)
            if not getattr(grant, "proceed", False) or getattr(grant, "dry_run", False):
                kept += 1
                continue
            res = self._tx.request(o.pid, o.delete_method, o.delete_url,
                                   mutating=True, label=f"delete {o.otype}", grant=grant)
            if res.sent and res.status in (200, 202, 204):
                removed += 1
            else:
                kept += 1
        self._audit("factory.cleanup", {"removed": removed, "kept": kept})
        return {"removed": removed, "kept": kept}

    # -- id / url recovery -----------------------------------------------------------

    def _extract_id(self, resp: Any, recipe: CreateRecipe) -> str | None:
        # 1) Location header is the most reliable — the server tells us the instance
        loc = _header(resp.headers, "location")
        if loc:
            seg = urlsplit(loc).path.rstrip("/").rsplit("/", 1)[-1]
            if seg:
                return seg
        # 2) a JSON body with a known id key (shallow, plus one "data" nesting)
        try:
            data = json.loads(resp.body)
        except (ValueError, TypeError):
            data = None
        for src in (data, (data or {}).get("data") if isinstance(data, dict) else None):
            if isinstance(src, dict):
                for k in recipe.id_json_keys:
                    if src.get(k) not in (None, ""):
                        return str(src[k])
        # 3) the final URL redirected to an instance under the collection
        fin = getattr(resp, "final_url", "") or ""
        if fin and fin.rstrip("/") != recipe.collection_url.rstrip("/"):
            seg = urlsplit(fin).path.rstrip("/").rsplit("/", 1)[-1]
            if seg and seg not in recipe.collection_url:
                return seg
        return None

    def _instance_url(self, resp: Any, recipe: CreateRecipe, oid: str) -> str:
        loc = _header(resp.headers, "location")
        if loc:
            return self._abs(loc)
        fin = getattr(resp, "final_url", "") or ""
        if fin and fin.rstrip("/") != recipe.collection_url.rstrip("/"):
            return fin
        if recipe.instance_url_template:
            return self._abs(recipe.instance_url_template.replace("{id}", oid))
        return recipe.collection_url.rstrip("/") + "/" + oid

    def _abs(self, url: str) -> str:
        if url.startswith("http"):
            return url
        if self._base:
            return urljoin(self._base.rstrip("/") + "/", url.lstrip("/"))
        return url


def _header(headers: Any, name: str) -> str:
    if not headers:
        return ""
    for k, v in headers.items():
        if str(k).lower() == name:
            return str(v or "")
    return ""
