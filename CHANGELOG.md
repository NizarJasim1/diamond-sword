# Changelog

## [1.3.0] - 2026-10

Live engine for large, well-defended targets.

### Added
- `live/transport.py`: a single chokepoint for every request (scope → rules of
  engagement → pacing → send → session check → capture ledger → audit).
- `live/governor.py`: per-host AIMD pacing, `Retry-After` handling, block detection,
  jitter, and a circuit breaker that stops the run on sustained blocking.
- `live/session.py`: session liveness judged by content, not status code; pluggable
  re-auth; step-up auth handed to a human; captures after a silent logout are
  discarded so they can't poison analysis.
- `live/object_factory.py`: creates owner/other-account object pairs through the
  app's own features, with minimal, reversible payloads.
- `live/graphql_exerciser.py`: introspection through the user's session,
  depth-bounded queries on authorization-relevant operations, run as both accounts.
- `coverage/state_graph.py` and `coverage/authz_richness.py`: state-flow coverage
  estimation and ranking of pages by how much authorization logic they carry.

## [1.2.0] - 2026-10

Interaction layer.

### Added
- `interact/`: element discovery, actions, action ledger, playbook direction and an
  explorer that exercises every interactive element, each action gated by rules of
  engagement and consent.
- Playwright driver that records every XHR/fetch as HAR.
- `explore` command. Destructive actions are refused even with `--yes`.

## [1.1.0] - 2026-10

End to end.

### Added
- `pipe` and `resume` commands: crawl per principal → HAR → IOLITE → ONYX → report,
  resumable after a crash.
- Real IOLITE and ONYX runners that fail loudly on a broken contract.
- Typed findings with strict validation of ONYX output.
- GraphQL fields from introspection become crawl seeds.

### Fixed
- HAR entries now carry the real `mimeType` and a populated `queryString`.

## [1.0.0] - 2026-10

First complete version.

### Added
- Legal core: scope parser and guard (fail-closed, out-of-scope precedence,
  hostname-spoof resistant), rules of engagement, consent gate, hash-chained audit log.
- Coverage engine: map-first seeding from OpenAPI/GraphQL/sitemaps/JS, URL
  fingerprinting and templates, crawler, triage, principal manager.
- Self-healing: locator cascade, invariants, recovery state machine, resumable
  coverage ledger.
- Question bus and playbooks for anything a run can't resolve alone.
- Capture layer with Playwright and mitmproxy backends.
- Mutation testing on every core module.
