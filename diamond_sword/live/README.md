# diamond_sword.live — live-engine substrate

Makes Diamond Sword able to recon giant, well-defended targets (GitLab-class and
larger) autonomously and legally. All of it is pure, deterministic,
dependency-injected logic (stdlib only); the browser / urllib / mitmproxy
backends are adapters behind a single `Sender` callable.

## The five additions

| # | module | job |
|---|--------|-----|
| #4 | `session.py` | session liveness by *substance* (not status), pluggable re-auth, step-up → human, and the **epoch poison-fuse** so IOLITE never learns from traffic captured after a session silently died |
| #5 | `governor.py` | per-host **AIMD** pacing, Retry-After obedience, WAF/throttle detection, decorrelated jitter, and a **circuit breaker** that fails closed on sustained blocking |
| seam | `transport.py` | `LiveTransport` — the one chokepoint every request crosses: scope → ROE/grant → `governor.acquire` → send → `governor.observe` → session bracket → capture ledger → audit |
| #1 | `object_factory.py` | **dual-principal** owned-object seeding through the app's own affordances (minimal payloads, reversible), producing owner↔attacker **pairs** — the BOLA substrate ONYX confirms |
| #2 | `graphql_exerciser.py` | introspection via the principal's **session**, authz-op selection, **depth-bounded** query synthesis, filled from factory ids, exercised as owner and attacker → feeds ONYX cross-operation |

State-flow graph + coverage estimation (**#3**) and the authz-richness scorer are
under `diamond_sword/coverage/` (`state_graph.py`, `authz_richness.py`), extending
the existing coverage layer (reuse `template_engine`, `fingerprint`).

## How they compose

```
build a Sender over your Playwright/urllib backend (returns HttpResponse incl. headers)

SessionHub.register(pid, recipe, LivenessProbe(owned-anchor, identity_markers))  # per principal
Governor(max_rps=roe.max_rps, automation_permitted=roe.automation_permitted, time_window=roe.time_window)
LiveTransport(sender, scope_guard, roe_policy, governor, sessions, CaptureLedger)

StateGraph(...)              # drives the explorer frontier; one line per settled state:
   g.observe(StateObservation(url, status, structure_hash, controls))
   target = g.next_target(); path = g.path_from(current_sid, target.sid)

ObjectFactory(transport, consent_gate, principals).seed_pair(recipe_for)  -> pairs()
GraphQLExerciser(transport, graphql_url).fetch_schema(pid); .exercise(factory.pairs())

hand ledger.clean_har(pid) -> IOLITE build; factory.pairs()/gql probes -> ONYX
```

## Guarantees preserved (every module keeps these)

1. **Deterministic** — clock, sleep and RNG are injected; jitter is seeded. Unit-testable to the millisecond.
2. **Fail-closed** — scope deny, ROE deny, a dry-run/denied grant, step-up, dead session, or an open circuit all stop the request and say why. Scope is never waivable.
3. **No authz logic in capture** — Diamond Sword produces and labels material only; ownership is ground truth (it created the object). ONYX decides every breach by Δstate.
4. **Poison-fuse** — only session-bracketed exchanges reach IOLITE (`CaptureLedger.clean_har`); the rest are quarantined.
5. **Audit** — every decision is emitted to the hash-chained audit ledger via the injected `audit` sink.

Each module ships with a deterministic smoke test demonstrating its behavior.
