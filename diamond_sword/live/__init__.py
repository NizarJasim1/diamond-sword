"""
diamond_sword.live — the live-engine substrate that makes Diamond Sword able to
recon giant, well-defended targets autonomously and legally.

Five capabilities, built as pure, deterministic, dependency-injected logic so the
core stays testable and the browser/urllib/mitmproxy backends are just adapters:

  governor         (#5) adaptive pacing + WAF/throttle backoff + per-host circuit breaker
  session          (#4) substantive liveness + re-auth + the epoch poison-fuse
  transport        (seam) the single chokepoint: scope -> ROE/grant -> pace -> send -> bracket -> ledger
  object_factory   (#1) dual-principal owned-object seeding -> owner/attacker pairs for ONYX
  graphql_exerciser(#2) introspection + authz-op selection + bounded query synthesis + owner/attacker exercise

The state-flow graph + coverage estimation (#3) and the authz-richness scorer live
under diamond_sword.coverage (state_graph, authz_richness) since they extend the
existing coverage layer.
"""
from .governor import AutomationDenied, CircuitOpen, Governor, classify_response
from .session import (
    AuthMaterial, AuthRecipe, LivenessProbe, ProbeResponse, ReauthFailed,
    SessionHub, SessionState, StaticHeaders, StepUpRequired, TokenRefresh,
)
from .transport import HttpResponse, LiveResult, LiveTransport, Sender
from .object_factory import (
    AttackPair, CreateRecipe, FieldSpec, ObjectFactory, OwnedObject,
    minimal_payload, recipe_from_form,
)
from .graphql_exerciser import (
    GraphQLExerciser, GraphQLOp, GraphQLProbe, Schema, schema_from_introspection,
)

__all__ = [
    "Governor", "AutomationDenied", "CircuitOpen", "classify_response",
    "SessionHub", "SessionState", "LivenessProbe", "AuthRecipe", "AuthMaterial",
    "ProbeResponse", "StaticHeaders", "TokenRefresh", "StepUpRequired", "ReauthFailed",
    "LiveTransport", "LiveResult", "HttpResponse", "Sender",
    "ObjectFactory", "CreateRecipe", "OwnedObject", "AttackPair", "FieldSpec",
    "minimal_payload", "recipe_from_form",
    "GraphQLExerciser", "Schema", "GraphQLOp", "GraphQLProbe", "schema_from_introspection",
]
