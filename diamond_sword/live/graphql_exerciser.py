"""
GraphQL operation exerciser — reach the object surface the UI never touches.

WHY THE UI IS NOT ENOUGH
------------------------
On a GraphQL-heavy target (GitLab-class and larger) the browser issues a thin
slice of the schema; the rest of the operations — often the juicy,
object-by-id, owner-returning ones — are never fired, so a capture-only crawl
can't see them and a single GraphQL query has earned five-figure bounties. This
module pulls the schema by introspection, picks the operations that actually
bear on authorization, fills their id arguments with the dual-principal material
the object factory produced, and runs each one as *owner* and as *attacker* — the
exact owner/attacker read-back pair ONYX's cross-operation engine confirms by
Δstate (its U1 blind spot: the same object reachable through a different op).

DESIGN NOTES THAT MATTER
------------------------
  * Introspection via the *principal's session* (cookie), not a bare token —
    which is why it still works where token-auth introspection is broken on some
    deployments; on failure it falls back to an operator-supplied schema.
  * Operation documents are SYNTHESIZED and depth-bounded: a minimal, valid
    query that selects scalar leaves plus one level into owner-like nested
    objects (enough to witness a leak) and no deeper — so complexity limits are
    respected and we never DoS the target.
  * Read-only by default. Mutations are catalogued but exercised only when the
    operator opts in, and then only through the consent gate (a real Grant) —
    fail-closed, exactly like the object factory.
  * It only *produces probes and material*. ONYX decides every breach by Δstate.

All traffic goes through the one LiveTransport chokepoint, so scope, session
liveness, pacing and the capture ledger apply here too.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

# --- introspection query (compact, standard shape) -----------------------------------

INTROSPECTION_QUERY = (
    "query IntrospectionQuery { __schema { queryType { name } mutationType { name } "
    "types { kind name fields(includeDeprecated:true) { name args { name type { ...Tr } } "
    "type { ...Tr } } enumValues { name } } } } "
    "fragment Tr on __Type { kind name ofType { kind name ofType { kind name "
    "ofType { kind name ofType { kind name } } } } }"
)

# --- sensitivity heuristic -----------------------------------------------------------

_SENSITIVE_TOKENS = (
    "email", "token", "secret", "password", "passwd", "apikey", "api_key", "key",
    "ssn", "phone", "address", "private", "balance", "salary", "owner", "author",
    "user", "credential", "session", "oauth", "access", "billing", "invoice", "card",
)


def _name_sensitive(name: str) -> bool:
    low = (name or "").lower()
    return any(t in low for t in _SENSITIVE_TOKENS)


# --- schema model --------------------------------------------------------------------

@dataclass(frozen=True)
class TypeRef:
    name: str
    kind: str
    required: bool = False
    is_list: bool = False

    def gql(self) -> str:
        base = self.name + ("!" if self.required else "")
        return f"[{base}]" if self.is_list else base


@dataclass(frozen=True)
class Arg:
    name: str
    type: TypeRef


@dataclass(frozen=True)
class Field:
    name: str
    args: tuple[Arg, ...]
    type: TypeRef


@dataclass
class GType:
    name: str
    kind: str
    fields: dict[str, Field] = field(default_factory=dict)
    enum_values: tuple[str, ...] = ()


def _unwrap(tr: dict[str, Any] | None) -> TypeRef:
    required = bool(tr and tr.get("kind") == "NON_NULL")
    is_list = False
    cur = tr
    while cur:
        k = cur.get("kind")
        if k == "LIST":
            is_list = True
        if cur.get("name") and k not in ("NON_NULL", "LIST"):
            return TypeRef(str(cur["name"]), str(k), required, is_list)
        cur = cur.get("ofType")
    return TypeRef("Unknown", "SCALAR", required, is_list)


class Schema:
    def __init__(self, types: dict[str, GType], query_type: str, mutation_type: str | None):
        self.types = types
        self.query_type = query_type
        self.mutation_type = mutation_type

    def field(self, kind: str, name: str) -> Field | None:
        root = self.query_type if kind == "query" else (self.mutation_type or "")
        gt = self.types.get(root)
        return gt.fields.get(name) if gt else None

    # -- sensitivity / selection -----------------------------------------------------

    def type_sensitive(self, type_name: str) -> bool:
        gt = self.types.get(type_name)
        if not gt or gt.kind not in ("OBJECT", "INTERFACE"):
            return _name_sensitive(type_name)
        return any(_name_sensitive(fn) for fn in gt.fields)

    def selection(self, type_name: str, depth: int = 1, max_fields: int = 8,
                  _seen: frozenset[str] = frozenset()) -> str:
        """A minimal, depth-bounded selection: scalar leaves + one level into
        owner-like nested objects. Deterministic (introspection field order)."""
        gt = self.types.get(type_name)
        if not gt or gt.kind not in ("OBJECT", "INTERFACE"):
            return ""   # scalar/enum: it is itself a leaf, no sub-selection
        leaves: list[str] = []
        nested: list[str] = []
        for fn, fld in gt.fields.items():
            if fn.startswith("__"):
                continue
            if any(a.type.required for a in fld.args):
                continue                              # skip fields that need args
            inner = self.types.get(fld.type.name)
            if inner and inner.kind in ("OBJECT", "INTERFACE"):
                if depth > 0 and _name_sensitive(fn) and fld.type.name not in _seen:
                    sub = self.selection(fld.type.name, depth - 1, 4, _seen | {type_name})
                    if sub:
                        nested.append(f"{fn} {{ {sub} }}")
            else:
                leaves.append(fn)
        parts = leaves[:max_fields] + nested
        return " ".join(parts) if parts else "__typename"


def schema_from_introspection(data: dict[str, Any]) -> Schema | None:
    sch = (data or {}).get("__schema") if "data" not in (data or {}) else data["data"].get("__schema")
    if not sch:
        return None
    types: dict[str, GType] = {}
    for t in sch.get("types", []):
        name = t.get("name")
        if not name:
            continue
        fields: dict[str, Field] = {}
        for f in (t.get("fields") or []):
            args = tuple(Arg(a["name"], _unwrap(a.get("type"))) for a in (f.get("args") or []))
            fields[f["name"]] = Field(f["name"], args, _unwrap(f.get("type")))
        enums = tuple(e["name"] for e in (t.get("enumValues") or []))
        types[name] = GType(name, t.get("kind", ""), fields, enums)
    q = (sch.get("queryType") or {}).get("name") or "Query"
    m = (sch.get("mutationType") or {}).get("name")
    return Schema(types, q, m)


# --- op selection + document synthesis -----------------------------------------------

def _is_id_arg(a: Arg) -> bool:
    n = a.name.lower()
    return a.type.name == "ID" or n in ("id", "iid", "gid") or n.endswith("id")


def _effect(kind: str, has_id: bool) -> str:
    if kind == "mutation":
        return "MODIFY_OBJECT" if has_id else "CREATE_OBJECT"
    return "ACCESS_OBJECT" if has_id else "LIST"


def _literal(tr: TypeRef, schema: Schema | None) -> str:
    n = tr.name
    if n in ("Int", "Float"):
        return "1"
    if n == "Boolean":
        return "false"
    gt = schema.types.get(n) if schema else None
    if gt and gt.kind == "ENUM" and gt.enum_values:
        return gt.enum_values[0]
    return '"ds-probe"'   # ID / String / unknown scalar


@dataclass(frozen=True)
class GraphQLOp:
    name: str
    kind: str                      # "query" | "mutation"
    id_args: tuple[str, ...]
    return_type: str
    sensitive: bool
    effect_class: str


@dataclass(frozen=True)
class GraphQLProbe:
    op_name: str
    kind: str
    principal: str                 # who sent it (attacker or owner-baseline)
    owner_pid: str
    target_object_id: str
    variables: dict[str, Any]
    document: str
    effect_class: str


# --- the exerciser -------------------------------------------------------------------

class GraphQLExerciser:
    def __init__(
        self,
        *,
        transport: Any,             # live.transport.LiveTransport
        graphql_url: str,
        schema: Schema | None = None,
        consent_gate: Any = None,   # required only to exercise mutations
        audit: Callable[[str, dict[str, Any]], None] | None = None,
        now_hour: Callable[[], int] | None = None,
    ) -> None:
        self._tx = transport
        self._url = graphql_url
        self._schema = schema
        self._gate = consent_gate
        self._audit = audit or (lambda k, p: None)
        self._now_hour = now_hour

    # -- introspection ---------------------------------------------------------------

    def fetch_schema(self, pid: str) -> Schema | None:
        """Pull the schema as ``pid`` (session cookie). Returns None on failure so
        the caller can fall back to an operator-supplied schema."""
        body = json.dumps({"query": INTROSPECTION_QUERY})
        res = self._tx.request(pid, "POST", self._url, body=body,
                               extra_headers={"Content-Type": "application/json"}, mutating=False)
        if not res.sent or res.response is None:
            self._audit("gql.introspection_unsent", {"pid": pid, "reason": res.reason})
            return None
        try:
            data = json.loads(res.response.body)
        except (ValueError, TypeError):
            data = None
        schema = schema_from_introspection(data) if isinstance(data, dict) else None
        if schema is None:
            self._audit("gql.introspection_empty", {"pid": pid, "status": res.status})
            return None
        self._schema = schema
        self._audit("gql.schema", {"types": len(schema.types), "query": schema.query_type,
                                   "mutation": schema.mutation_type})
        return schema

    # -- catalogue -------------------------------------------------------------------

    def authz_ops(self, want_mutations: bool = False) -> list[GraphQLOp]:
        """Operations that bear on authorization: object-by-id reads/writes, or
        operations returning a sensitive object type."""
        if self._schema is None:
            return []
        ops: list[GraphQLOp] = []
        roots = [("query", self._schema.query_type)]
        if want_mutations and self._schema.mutation_type:
            roots.append(("mutation", self._schema.mutation_type))
        for kind, root in roots:
            gt = self._schema.types.get(root or "")
            if not gt:
                continue
            for fn, fld in gt.fields.items():
                if fn.startswith("__"):
                    continue
                id_args = tuple(a.name for a in fld.args if _is_id_arg(a) and a.type.required)
                sensitive = self._schema.type_sensitive(fld.type.name) or _name_sensitive(fn)
                ret = self._schema.types.get(fld.type.name)
                if id_args or (ret and ret.kind == "OBJECT" and sensitive):
                    ops.append(GraphQLOp(fn, kind, id_args, fld.type.name, bool(sensitive),
                                         _effect(kind, bool(id_args))))
        return ops

    # -- document synthesis ----------------------------------------------------------

    def build_op(self, fld: Field, kind: str, object_id: str) -> tuple[str, dict[str, Any]]:
        """A minimal valid document: the id arg becomes a variable, other required
        scalar args take safe literals, the selection is depth-bounded."""
        args: list[str] = []
        var_decls: list[str] = []
        variables: dict[str, Any] = {}
        id_done = False
        for a in fld.args:
            if _is_id_arg(a) and a.type.required and not id_done:
                args.append(f"{a.name}: $oid")
                var_decls.append(f"$oid: {a.type.gql() or 'ID!'}")
                variables["oid"] = object_id
                id_done = True
            elif a.type.required:
                args.append(f"{a.name}: {_literal(a.type, self._schema)}")
        argstr = f"({', '.join(args)})" if args else ""
        sel = self._schema.selection(fld.type.name) if self._schema else ""
        selblock = f" {{ {sel} }}" if sel else ""
        head = f"{kind} Probe({', '.join(var_decls)})" if var_decls else f"{kind} Probe"
        return f"{head} {{ {fld.name}{argstr}{selblock} }}", variables

    # -- exercise --------------------------------------------------------------------

    def exercise(self, pairs: Sequence[Any], *, want_mutations: bool = False) -> list[GraphQLProbe]:
        """For every fillable authz op and every owner/attacker pair, run the op as
        the attacker (the probe) and as the owner (the Δstate baseline). Returns the
        probe records; the responses are in the capture ledger."""
        if self._schema is None:
            return []
        probes: list[GraphQLProbe] = []
        ops = [o for o in self.authz_ops(want_mutations) if o.id_args]
        for op in ops:
            fld = self._schema.field(op.kind, op.name)
            if fld is None:
                continue
            mutating = op.kind == "mutation"
            for pair in pairs:
                doc, variables = self.build_op(fld, op.kind, pair.owner_object.oid)
                for sender_pid in (pair.attacker_pid, pair.owner_pid):   # attacker probe, then owner baseline
                    ok = self._run(sender_pid, doc, variables, mutating)
                    if ok:
                        probes.append(GraphQLProbe(op.name, op.kind, sender_pid, pair.owner_pid,
                                                   pair.owner_object.oid, dict(variables), doc,
                                                   op.effect_class))
        self._audit("gql.exercised", {"ops": len(ops), "probes": len(probes)})
        return probes

    def _run(self, pid: str, document: str, variables: dict[str, Any], mutating: bool) -> bool:
        from ..legal.roe import Action

        grant = None
        if mutating:
            if self._gate is None:
                return False                               # no gate -> never mutate
            action = Action(kind="request", method="POST", url=self._url,
                            label="graphql mutation", mutating=True)
            grant = self._gate.authorize(action, self._now_hour() if self._now_hour else None)
            if not getattr(grant, "proceed", False) or getattr(grant, "dry_run", False):
                return False
        body = json.dumps({"query": document, "variables": variables})
        res = self._tx.request(pid, "POST", self._url, body=body,
                               extra_headers={"Content-Type": "application/json"},
                               mutating=mutating, label="graphql", grant=grant)
        return bool(res.sent)
