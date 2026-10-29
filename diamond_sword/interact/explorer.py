"""The exploration engine: a deterministic journey over a live app that exercises every control
a human would, generating (and letting the driver capture) all the traffic ONYX needs \u2014 with
zero AI at runtime and every action gated by ROE + consent.

Shape of one run:

1. Run the operator's **flows** (log in, "create a project", "open settings") to seed deep states.
2. For each **seed URL** (plus flows' landing states), explore the state machine:
   snapshot \u2192 fingerprint the state \u2192 enumerate interactive controls \u2192 rank (operator priority,
   then authorization-triage) \u2192 for each control not already handled, in scope, not avoided:
   locate (cascade) \u2192 gate (ROE + consent) \u2192 perform (unless denied / dry-run) \u2192 recover from
   symptoms (modal / session / WAF / unexpected) \u2192 record \u2192 if it reached a new state, enqueue it.

Finiteness on a giant/cyclic SPA comes from :mod:`action` (control signatures + state
fingerprints) plus the caps in :class:`ExploreConfig`. Safety comes entirely from the injected
``scope_guard`` (where) and ``consent_gate`` (what): destructive actions are DENIED and never
performed; other mutations need consent (fail-closed) and run dry first.

Everything external is an injected port, so the suite drives it with a fake and the operator's
machine supplies a real Playwright/mitmproxy driver. Standard library only.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Protocol, runtime_checkable

from ..heal.intent import Intent, Postcondition
from ..heal.pacer import Pacer
from ..heal.recovery_fsm import Action as FsmAction
from ..heal.recovery_fsm import RecoveryFSM
from ..heal.locator_cascade import locate
from ..coverage.triage import score_template, score_url
from .action import StateView, UiAction, state_fingerprint, to_roe_action
from .action_ledger import ActionLedger
from .direction import Direction, Flow
from .elements import MUTATING_VERBS, ActionCandidate, interactive_elements

__all__ = ["DriverPort", "ExploreConfig", "ExploreResult", "Explorer"]

_STOP = object()


@runtime_checkable
class DriverPort(Protocol):
    """What the engine needs from the outside world (a live browser). Faked in tests; a real
    Playwright/mitmproxy driver implements it on the operator's machine. Every method returns a
    SETTLED :class:`StateView` (the driver waits for DOM stability before returning)."""

    def snapshot(self) -> StateView: ...
    def perform(self, ui: UiAction) -> StateView: ...
    def goto(self, url: str) -> StateView: ...
    def dismiss_modal(self) -> StateView: ...


@dataclass(frozen=True)
class ExploreConfig:
    """Caps that keep a giant site finite. Ceilings, not targets."""

    max_total_actions: int = 2000
    max_actions_per_state: int = 60
    max_states: int = 400
    max_state_revisits: int = 3
    max_symptom_retries: int = 6


@dataclass(frozen=True)
class ExploreResult:
    states_seen: int
    actions_attempted: int
    actions_performed: int
    traps: tuple[str, ...]
    open_questions: tuple[str, ...]
    stopped: str = ""      # "" | "PAUSE_FOR_HUMAN" | "BUDGET"


class Explorer:
    def __init__(
        self,
        driver: DriverPort,
        scope_guard: Any,
        consent_gate: Any,
        principal: str = "A",
        *,
        direction: Direction | None = None,
        ledger: ActionLedger | None = None,
        session: Any = None,
        question_bus: Any = None,
        pacer: Pacer | None = None,
        config: ExploreConfig | None = None,
        now_hour: int | None = None,
        home: str | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self.driver = driver
        self.scope = scope_guard
        self.gate = consent_gate
        self.principal = principal
        self.direction = direction or Direction()
        self.ledger = ledger
        self.session = session
        self.qbus = question_bus
        self.pacer = pacer
        self.cfg = config or ExploreConfig()
        self.now_hour = now_hour
        self.home = home
        self._sleep = sleep or (lambda _secs: None)

        resumed = ledger.state() if ledger else None
        self.seen_states: set[str] = set(resumed.states) if resumed else set()
        self.done: set[tuple[str, str]] = set(resumed.attempted) if resumed else set()
        self.traps: set[str] = set(resumed.traps) if resumed else set()
        self.questions: set[str] = set(resumed.questions) if resumed else set()
        self.revisits: dict[str, int] = {}
        self.attempted = 0
        self.performed = 0
        self.stopped = ""
        self.worklist: deque[str] = deque()

    # -- public ------------------------------------------------------------------------

    def run(self, start: str | None = None) -> ExploreResult:
        if self.home is None:
            self.home = (self.direction.seeds[0] if self.direction.seeds else start)

        for flow in self.direction.flows:
            if self._run_flow(flow) is _STOP:
                return self._result()

        seeds: list[str] = []
        for u in (*self.direction.seeds, *( (start,) if start else () )):
            if u and u not in seeds:
                seeds.append(u)
        self.worklist.extend(seeds)

        while self.worklist and not self.stopped:
            url = self.worklist.popleft()
            if not self.scope.allowed(url):
                continue
            if self._explore_url(url) is _STOP:
                break
        return self._result()

    # -- exploration -------------------------------------------------------------------

    def _explore_url(self, url: str) -> object:
        view = self.driver.goto(url)
        return self._explore_state(view, url)

    def _explore_state(self, view: StateView, origin_url: str) -> object:
        if self._budget_hit():
            return _STOP
        fp = state_fingerprint(view)
        self._see(fp, view.snapshot.url)
        self.revisits[fp] = self.revisits.get(fp, 0) + 1
        if fp in self.traps:
            return None
        if self.revisits[fp] > self.cfg.max_state_revisits:
            self._trap(fp, "REVISIT_CAP")
            return None

        settled = self._settle(view, None)
        if settled is _STOP:
            return _STOP
        if settled is None:                     # arrival symptom could not clear
            return None
        view = settled
        fp = state_fingerprint(view)
        url0 = view.snapshot.url

        candidates = self._rank(interactive_elements(view.snapshot))
        per_state = 0
        for cand in candidates:
            if self._budget_hit():
                return _STOP
            if per_state >= self.cfg.max_actions_per_state:
                self._trap(fp, "PER_STATE_CAP")
                break
            key = (fp, cand.signature)
            if key in self.done:
                continue

            if self.direction.is_avoided(cand.label, cand.href):
                self._mark(fp, cand, False, "AVOIDED")
                continue
            if cand.href and not self.scope.allowed(cand.href):
                self._mark(fp, cand, False, "OUT_OF_SCOPE")
                continue

            loc = locate(view.snapshot, cand.ui.target)
            if loc.node_id is None:
                self._ask(fp, cand)
                self._mark(fp, cand, False, "LOCATE_FAILED")
                continue

            grant = self.gate.authorize(
                to_roe_action(cand.ui.kind, cand.label, cand.href, cand.mutating), self.now_hour)
            per_state += 1
            self.attempted += 1
            if (not grant.proceed) or grant.dry_run:
                self._mark(fp, cand, False, grant.reason)
                continue

            if self.pacer is not None:
                self._sleep(self.pacer.next_delay())
            view2 = self.driver.perform(cand.ui)
            self.performed += 1
            self._mark(fp, cand, True, grant.reason)
            if self.pacer is not None:
                self.pacer.on_success()

            settled2 = self._settle(view2, _expected(cand))
            if settled2 is _STOP:
                return _STOP
            if settled2 is None:
                # could not clear; try to get back and continue
                view = self.driver.goto(url0)
                if state_fingerprint(view) != fp:
                    break
                continue
            view2 = settled2

            newfp = state_fingerprint(view2)
            if newfp != fp:
                nav = view2.snapshot.url
                if self.scope.allowed(nav) and newfp not in self.seen_states:
                    self.worklist.append(nav)
                view = self.driver.goto(url0)                 # return to finish this state
                if state_fingerprint(view) != fp:
                    break
            else:
                view = view2
        return None

    # -- flows (operator-directed seeding) ---------------------------------------------

    def _run_flow(self, flow: Flow) -> object:
        for step in flow.steps:
            if self._budget_hit():
                return _STOP
            view = self.driver.snapshot()
            loc = locate(view.snapshot, step.target)
            if loc.node_id is None:
                qid = f"flow:{flow.id}:{step.action}"
                if qid not in self.questions:
                    self.questions.add(qid)
                    if self.qbus is not None:
                        self.qbus.ask(qid, "flow_locate_failed", flow=flow.id, action=step.action)
                    if self.ledger is not None:
                        self.ledger.ask(qid)
                continue
            action = to_roe_action(step.action, _step_label(step), None, _flow_mutating(step))
            grant = self.gate.authorize(action, self.now_hour)
            self.attempted += 1
            if (not grant.proceed) or grant.dry_run:
                continue
            if self.pacer is not None:
                self._sleep(self.pacer.next_delay())
            ui = UiAction(kind=step.action, target=step.target, value=step.value)
            view2 = self.driver.perform(ui)
            self.performed += 1
            if self.pacer is not None:
                self.pacer.on_success()
            # A flow is the operator's deliberate path (often THROUGH login pages), so a
            # login-page/401 "session expired" symptom here is expected, not a reason to pause.
            settled = self._settle(view2, step.postcondition, suppress_session=True)
            if settled is _STOP:
                return _STOP
        return None

    # -- recovery ----------------------------------------------------------------------

    def _settle(self, view: StateView, post: Postcondition | None,
                suppress_session: bool = False) -> Any:
        """Drive the recovery FSM until the screen is OK, or abort/stop. Returns a settled
        :class:`StateView`, ``None`` (skip this step) or ``_STOP`` (pause for a human).

        ``suppress_session`` is set by login/seed flows, where being on an auth page is expected;
        it turns the SESSION_EXPIRED verdict into PROCEED instead of pausing."""
        fsm = RecoveryFSM(max_retries=self.cfg.max_symptom_retries)
        for _ in range(self.cfg.max_symptom_retries + 1):
            sym, act, _streak = fsm.step(view.snapshot, post, view.signals)
            if act == FsmAction.PROCEED:
                return view
            if act == FsmAction.PAUSE_FOR_HUMAN:
                if suppress_session:
                    return view
                if self.session is not None:
                    self.session.check(self.principal, view.signals.http_status, view.snapshot.url)
                self.stopped = "PAUSE_FOR_HUMAN"
                return _STOP
            if act == FsmAction.ABORT_STEP:
                return None
            if act == FsmAction.DISMISS_MODAL:
                view = self.driver.dismiss_modal()
            elif act == FsmAction.GOTO_NEAREST_KNOWN:
                view = self.driver.goto(self.home or view.snapshot.url)
            elif act == FsmAction.BACKOFF_RETRY:
                if self.pacer is not None:
                    self._sleep(self.pacer.on_rate_limited())
                view = self.driver.snapshot()
        return None

    # -- ranking -----------------------------------------------------------------------

    def _rank(self, cands: list[ActionCandidate]) -> list[ActionCandidate]:
        def key(c: ActionCandidate) -> tuple[int, int, str]:
            pr = self.direction.priority_rank(c.label, c.href)
            return (-pr, -_triage(c), c.signature)
        return sorted(cands, key=key)

    # -- bookkeeping -------------------------------------------------------------------

    def _see(self, fp: str, url: str | None) -> None:
        if fp not in self.seen_states:
            self.seen_states.add(fp)
            if self.ledger is not None:
                self.ledger.mark_state(fp, url)

    def _trap(self, fp: str, reason: str) -> None:
        if fp not in self.traps:
            self.traps.add(fp)
            if self.ledger is not None:
                self.ledger.mark_trap(fp, reason)

    def _ask(self, fp: str, cand: ActionCandidate) -> None:
        qid = f"{fp}:{cand.signature}"
        if qid in self.questions:
            return
        self.questions.add(qid)
        if self.qbus is not None:
            self.qbus.ask(qid, "locate_failed", label=cand.label, kind=cand.ui.kind)
        if self.ledger is not None:
            self.ledger.ask(qid)

    def _mark(self, fp: str, cand: ActionCandidate, performed: bool, grant: str) -> None:
        self.done.add((fp, cand.signature))
        if self.ledger is not None:
            self.ledger.mark_action(fp, cand.signature, cand.ui.kind, performed, grant)

    def _budget_hit(self) -> bool:
        if self.attempted >= self.cfg.max_total_actions or len(self.seen_states) > self.cfg.max_states:
            self.stopped = self.stopped or "BUDGET"
            return True
        return False

    def _result(self) -> ExploreResult:
        return ExploreResult(
            states_seen=len(self.seen_states),
            actions_attempted=self.attempted,
            actions_performed=self.performed,
            traps=tuple(sorted(self.traps)),
            open_questions=tuple(sorted(self.questions)),
            stopped=self.stopped,
        )


# -- module helpers --------------------------------------------------------------------

def _triage(c: ActionCandidate) -> int:
    if c.href:
        return score_url(c.href, "GET").score
    seg = "".join(ch if ch.isalnum() else "-" for ch in (c.label or "").lower()).strip("-") or "x"
    return score_template("POST" if c.mutating else "GET", "/" + seg).score


def _expected(cand: ActionCandidate) -> Postcondition | None:
    return None


def _step_label(step: Intent) -> str:
    t = step.target
    for v in (t.text, t.label, t.test_id, t.role):
        if v:
            return v
    return step.action


def _flow_mutating(step: Intent) -> bool:
    if step.action in ("fill", "select", "read", "navigate"):
        return False
    t = step.target
    toks: set[str] = set()
    for v in (t.text, t.label, t.test_id):
        if v:
            toks |= {w for w in v.lower().replace("-", " ").replace("_", " ").split() if w}
    return bool(toks & MUTATING_VERBS)
