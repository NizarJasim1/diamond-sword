"""
State-flow graph + coverage estimation — the engine that lets a finite crawl
cover a target larger than GitLab without drowning in its state-space.

THE PROBLEM, PRECISELY
----------------------
"Exercise every control" is linear in the number of states, and a giant app has
an unbounded number of *near-identical* states (ten thousand issue pages, each a
new URL, each structurally the same). Blind breadth-first either explodes or
caps out before it reaches /admin. Three ideas fix it, all built on the existing
`template_engine` (URL -> template) and `fingerprint` (DOM -> structure):

1. SEMANTIC DEDUP. A state's identity is (url_template, structure_hash), not its
   URL. All ten thousand issue pages collapse to ONE node. Volatile content
   never inflates the graph — the same discipline ONYX uses when it strips
   volatile fields during calibration.

2. AUTHZ-PRIORITIZED FRONTIER. The next place to explore is chosen by
   authorization-richness (object-bearing, mutating, privilege, owner-field,
   api) — not FIFO. The budget is spent where BOLA/BFLA live first.

3. PRINCIPLED STOPPING, NOT A BLIND CAP. We estimate how much of the reachable
   space is still unseen with a Good-Turing signal (the share of states seen
   exactly once ~ the probability the next visit is new) combined with a
   sliding-window discovery rate. When both decay, the area is saturated and we
   move the budget elsewhere — instead of a fixed max_states that is always
   wrong in one direction.

Plus per-area budgeting (one giant area cannot starve the rest) and
cheapest-first restoration (re-reach any state by the shortest known action
path, via BFS over the graph, instead of re-crawling).

Deterministic and pure: no wall clock, no network, an internal observation
counter is the only "time". The browser/urllib layers feed it normalized
observations; it never fetches anything itself.
"""
from __future__ import annotations
from collections.abc import Callable
from typing import Any

import re
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .authz_richness import RichnessWeights, area_of, score_state

# --- defensive templater (prefer the real one; never hard-fail on it) ----------------

_SEG_ID = re.compile(r"^(\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{16,}|[0-9a-fA-F]{8}-[0-9a-fA-F-]+)$")


def _fallback_template(url: str) -> str:
    path = urlsplit(url).path or "/"
    return "/".join("{id}" if (s and _SEG_ID.match(s)) else s for s in path.split("/")) or "/"


def default_template(url: str) -> str:
    """Normalize any url/path to its template, via the real `template_engine`
    (which returns ``(template, depth)`` and expects a *path*), with a regex
    fallback so the graph never hard-fails on the templater."""
    path = urlsplit(url).path if "://" in url else url
    path = path or "/"
    try:
        from .template_engine import path_template
        r = path_template(path)
        t = r[0] if isinstance(r, (tuple, list)) else r
        return t if isinstance(t, str) else _fallback_template(url)
    except Exception:
        return _fallback_template(url)


# --- normalized inputs the graph speaks (adapters build these) -----------------------

@dataclass(frozen=True)
class Control:
    """One action available from a state, normalized away from StateView / Page."""
    kind: str = "link"               # "link" | "form" | "button" | "api" | "nav"
    method: str = "GET"
    template: str = ""               # path_template of the control's target
    label: str = ""                  # human text (button/link)
    bears_object: bool = False       # target carries a swappable id
    owner_field: bool = False        # a form field names an owner/user/tenant
    mutating: bool = False

    def key(self) -> str:
        return f"{self.kind}:{self.method}:{self.template or self.label}".lower()


@dataclass(frozen=True)
class StateObservation:
    url: str
    method: str = "GET"
    status: int = 200
    structure_hash: str = ""         # fingerprint() of the DOM/body skeleton
    controls: tuple[Control, ...] = ()


@dataclass
class SurfaceState:
    sid: str
    url_template: str
    area: str
    structure_hash: str
    controls: tuple[Control, ...]
    authz_score: int
    authz_reasons: tuple[str, ...]
    discovered_seq: int
    status: int = 200
    visits: int = 1
    tried: set[str] = field(default_factory=set)      # control.key()s already exercised

    @property
    def unexplored(self) -> int:
        live = {c.key() for c in self.controls}
        return len(live - self.tried)


# --- control adapters (so crawler/explorer wiring is one line each) ------------------

def link_control(href: str, templater: Callable[[str], str] | None = None) -> Control:
    tmpl = (templater or default_template)(href)
    return Control(kind="link", method="GET", template=tmpl, bears_object="{" in tmpl)


def form_control(method: str, action: str, field_names: Any = (), label: str = "",
                 templater: Callable[[str], str] | None = None) -> Control:
    from .authz_richness import control_is_owner_field, label_is_mutating
    tmpl = (templater or default_template)(action)
    m = (method or "GET").upper()
    return Control(kind="form", method=m, template=tmpl, label=label,
                   bears_object="{" in tmpl, owner_field=control_is_owner_field(field_names),
                   mutating=(m in ("POST", "PUT", "PATCH", "DELETE")) or label_is_mutating(label))


def button_control(label: str) -> Control:
    from .authz_richness import label_is_mutating
    return Control(kind="button", method="POST", label=label, mutating=label_is_mutating(label))


# --- the graph -----------------------------------------------------------------------

class StateGraph:
    def __init__(
        self,
        *,
        weights: RichnessWeights | None = None,
        max_instances_per_template: int = 8,     # the Nth near-duplicate becomes a trap
        area_action_budget: int = 400,
        area_state_budget: int = 120,
        authz_weight: float = 10.0,
        novelty_weight: float = 4.0,
        revisit_penalty: float = 6.0,
        unexplored_weight: float = 0.5,
        saturate_min_obs: int = 40,
        gt_epsilon: float = 0.04,                # Good-Turing P(new) below this -> likely saturated
        rate_window: int = 60,
        rate_epsilon: float = 0.05,              # new-states-per-visit below this -> saturated
        templater: Callable[[str], str] | None = None,
    ) -> None:
        self._w = weights or RichnessWeights()
        self._max_inst = max_instances_per_template
        self._area_action_budget = area_action_budget
        self._area_state_budget = area_state_budget
        self._authz_w, self._nov_w = authz_weight, novelty_weight
        self._revisit_pen, self._unexp_w = revisit_penalty, unexplored_weight
        self._sat_min, self._gt_eps = saturate_min_obs, gt_epsilon
        self._rate_eps = rate_epsilon
        self._user_tpl = templater
        self._tpl_cache: dict[str, str] = {}

        self._states: dict[str, SurfaceState] = {}
        self._adj: dict[str, list[tuple[str, str]]] = {}     # src_sid -> [(dst_sid, action_key)]
        self._root: str | None = None
        self._seq = 0

        self._tpl_instances: dict[str, int] = {}
        self._trap_templates: set[str] = set()
        self._sid_obs: dict[str, int] = {}                   # visits per sid, for Good-Turing
        self._rate_window = rate_window
        self._recent_new: deque[int] = deque(maxlen=rate_window)   # global
        self._area_recent: dict[str, deque[float]] = {}                   # per-area discovery rate
        # per-area accounting
        self._area_obs: dict[str, int] = {}
        self._area_states: dict[str, int] = {}
        self._area_singletons: dict[str, int] = {}
        self._area_spent: dict[str, int] = {}

    # -- templating (prefer the real engine) -----------------------------------------

    def _template(self, url: str) -> str:
        t = self._tpl_cache.get(url)
        if t is not None:
            return t
        t = None
        if self._user_tpl:
            try:
                r = self._user_tpl(url)
                t = r[0] if isinstance(r, (tuple, list)) else r
            except Exception:
                t = None
        if not isinstance(t, str):
            t = default_template(url)
        self._tpl_cache[url] = t
        return t

    # -- ingestion -------------------------------------------------------------------

    def observe(self, obs: StateObservation, from_sid: str | None = None,
                via: Control | None = None) -> SurfaceState:
        """Record a visited state, collapse it to its semantic node, update coverage,
        and link the edge that reached it. Returns the (new or merged) node."""
        self._seq += 1
        tmpl = self._template(obs.url)
        area = area_of(tmpl)
        sid = f"{obs.method.upper()} {tmpl}#{(obs.structure_hash or '')[:12]}"

        # template instance cap / trap gate (built on the existing templater's intent)
        self._tpl_instances[tmpl] = self._tpl_instances.get(tmpl, 0) + 1
        if self._tpl_instances[tmpl] > self._max_inst:
            self._trap_templates.add(tmpl)

        was_new = sid not in self._states
        self._sid_obs[sid] = self._sid_obs.get(sid, 0) + 1
        self._area_obs[area] = self._area_obs.get(area, 0) + 1
        self._recent_new.append(1 if was_new else 0)
        self._area_recent.setdefault(area, deque(maxlen=self._rate_window)).append(1 if was_new else 0)

        if was_new:
            score, reasons = score_state(tmpl, obs.controls, self._w)
            st = SurfaceState(sid=sid, url_template=tmpl, area=area,
                              structure_hash=obs.structure_hash, controls=tuple(obs.controls),
                              authz_score=score, authz_reasons=reasons,
                              discovered_seq=self._seq, status=obs.status)
            self._states[sid] = st
            self._area_states[area] = self._area_states.get(area, 0) + 1
            self._area_singletons[area] = self._area_singletons.get(area, 0) + 1
            if self._root is None:
                self._root = sid
        else:
            st = self._states[sid]
            st.visits += 1
            if self._sid_obs[sid] == 2:                       # left the singleton set
                self._area_singletons[area] = max(0, self._area_singletons.get(area, 0) - 1)
            merged = self._merge_controls(st.controls, obs.controls)
            if len(merged) != len(st.controls):               # new controls -> rescore
                st.controls = merged
                st.authz_score, st.authz_reasons = score_state(tmpl, merged, self._w)

        if from_sid and via is not None and from_sid in self._states:
            self._link(from_sid, sid, via.key())
        return st

    @staticmethod
    def _merge_controls(a: tuple[Control, ...], b: Any) -> tuple[Control, ...]:
        seen = {c.key(): c for c in a}
        for c in b or ():
            seen.setdefault(c.key(), c)
        return tuple(seen.values())

    def _link(self, src: str, dst: str, action_key: str) -> None:
        edges = self._adj.setdefault(src, [])
        if not any(d == dst and k == action_key for d, k in edges):
            edges.append((dst, action_key))

    def mark_exercised(self, sid: str, control_key: str) -> None:
        st = self._states.get(sid)
        if st is None:
            return
        st.tried.add(control_key)
        self._area_spent[st.area] = self._area_spent.get(st.area, 0) + 1

    # -- scheduling ------------------------------------------------------------------

    def _priority(self, st: SurfaceState) -> float:
        inst = self._tpl_instances.get(st.url_template, 1)
        novelty = 1.0 / inst                      # prefer under-sampled templates
        return (self._authz_w * st.authz_score
                + self._nov_w * novelty
                + self._unexp_w * st.unexplored
                - self._revisit_pen * (st.visits - 1))

    def _eligible(self, st: SurfaceState) -> bool:
        if st.unexplored <= 0:
            return False
        if st.url_template in self._trap_templates:
            return False
        if self._area_spent.get(st.area, 0) >= self._area_action_budget:
            return False
        if self._area_states.get(st.area, 0) >= self._area_state_budget and st.visits > 1:
            return False
        return True

    def frontier(self) -> list[SurfaceState]:
        """States still worth exploring, best-first (authz-rich, novel, un-exhausted)."""
        cands = [s for s in self._states.values() if self._eligible(s)]
        cands.sort(key=lambda s: (self._priority(s), -s.discovered_seq), reverse=True)
        return cands

    def next_target(self) -> SurfaceState | None:
        """The single best next state, skipping saturated areas; None when the whole
        reachable, in-budget, unsaturated space is exhausted (a real stop signal)."""
        for st in self.frontier():
            if not self.saturated(st.area):
                return st
        return None

    # -- cheapest-first restoration --------------------------------------------------

    def path_from(self, start_sid: str | None, goal_sid: str) -> list[str] | None:
        """Shortest known action sequence (list of control keys) from `start_sid`
        (or the root) to `goal_sid`. [] if already there, None if unreachable."""
        start = start_sid or self._root
        if start is None or goal_sid not in self._states:
            return None
        if start == goal_sid:
            return []
        q: deque[str] = deque([start])
        back: dict[str, tuple[str, str]] = {}            # sid -> (prev_sid, action_key)
        seen = {start}
        while q:
            cur = q.popleft()
            for dst, akey in self._adj.get(cur, ()):  # BFS -> fewest actions
                if dst in seen:
                    continue
                back[dst] = (cur, akey)
                if dst == goal_sid:
                    path, node = [], dst
                    while node != start:
                        prev, a = back[node]
                        path.append(a)
                        node = prev
                    return list(reversed(path))
                seen.add(dst)
                q.append(dst)
        return None

    # -- coverage & saturation -------------------------------------------------------

    def saturated(self, area: str | None = None) -> bool:
        if area is None:
            obs = sum(self._area_obs.values())
            singletons = sum(self._area_singletons.values())
        else:
            obs = self._area_obs.get(area, 0)
            singletons = self._area_singletons.get(area, 0)
        if obs < self._sat_min:
            return False
        gt_p_new = singletons / obs                      # Good-Turing: P(next visit is new)
        win = self._area_recent.get(area) if area is not None else self._recent_new
        rate = (sum(win) / len(win)) if win else 1.0     # discovery rate for THIS area
        budget_done = (area is not None
                       and self._area_spent.get(area, 0) >= self._area_action_budget)
        return budget_done or (gt_p_new < self._gt_eps and rate < self._rate_eps)

    def coverage(self) -> dict[str, Any]:
        areas = {}
        for a in sorted(set(self._area_obs) | set(self._area_states)):
            obs = self._area_obs.get(a, 0)
            singc = self._area_singletons.get(a, 0)
            areas[a] = {
                "states": self._area_states.get(a, 0),
                "observations": obs,
                "spent_actions": self._area_spent.get(a, 0),
                "p_new": round(singc / obs, 3) if obs else 1.0,
                "saturated": self.saturated(a),
            }
        exercised = sum(1 for s in self._states.values() if s.tried)
        return {
            "states_total": len(self._states),
            "states_exercised": exercised,
            "templates_total": len(self._tpl_instances),
            "trap_templates": len(self._trap_templates),
            "frontier_size": len(self.frontier()),
            "global_saturated": self.saturated(None),
            "areas": areas,
        }

    # -- diagnostics -----------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self._root,
            "states": [
                {"sid": s.sid, "template": s.url_template, "area": s.area,
                 "authz": s.authz_score, "reasons": list(s.authz_reasons),
                 "visits": s.visits, "unexplored": s.unexplored,
                 "trap": s.url_template in self._trap_templates}
                for s in sorted(self._states.values(), key=lambda x: -x.authz_score)
            ],
            "edges": {src: list(dsts) for src, dsts in self._adj.items()},
            "coverage": self.coverage(),
        }
