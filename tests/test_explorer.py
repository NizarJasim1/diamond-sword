import os
import tempfile
import unittest

from diamond_sword.heal.pacer import Pacer
from diamond_sword.interact.action_ledger import ActionLedger
from diamond_sword.interact.explorer import Explorer, ExploreConfig
from diamond_sword.legal.consent_gate import AutoApprover, ConsentGate
from diamond_sword.legal.roe import RoePolicy
from diamond_sword.legal.scope_guard import ScopeGuard
from tests._fakeapp import FakeApp, engagement

DASH = "https://app.test/dashboard"


class RecSink:
    """Captures every gated action's verdict for assertions."""

    def __init__(self):
        self.rows = []

    def record(self, grant, action):
        self.rows.append((action.label, grant.proceed, grant.reason))

    def labels(self):
        return {(r[0], r[1]) for r in self.rows}


def _explore(app, policy, approver=None, sink=None, **kw):
    gate = ConsentGate(policy, approver, sink)
    ex = Explorer(app, ScopeGuard(engagement()), gate, "A", **kw)
    return ex.run(start=DASH)


class TestCoverageAndCapture(unittest.TestCase):
    def test_reaches_states_and_captures_har(self):
        app = FakeApp(authenticated=True)
        res = _explore(app, RoePolicy())
        self.assertEqual(res.states_seen, 6)
        paths = app.urls()
        for p in ("/orders", "/settings", "/admin", "/orders/1", "/admin/users"):
            self.assertTrue(any(u.endswith(p) for u in paths), f"never reached {p}")
        self.assertTrue(app.har.entries, "no traffic captured")

    def test_route_instances_collapse(self):
        app = FakeApp(authenticated=True)
        _explore(app, RoePolicy())
        paths = app.urls()
        self.assertTrue(any(u.endswith("/orders/1") for u in paths))
        self.assertFalse(any(u.endswith("/orders/2") for u in paths))
        self.assertFalse(any(u.endswith("/orders/3") for u in paths))

    def test_modal_dismissed(self):
        app = FakeApp(authenticated=True)
        _explore(app, RoePolicy())
        self.assertGreaterEqual(app.dismiss_calls, 1)


class TestSafety(unittest.TestCase):
    def test_read_only_denies_mutations(self):
        app = FakeApp(authenticated=True)
        sink = RecSink()
        _explore(app, RoePolicy(), sink=sink)
        labels = sink.labels()
        self.assertIn(("Delete", False), labels)
        self.assertIn(("Edit", False), labels)
        self.assertIn(("Update", False), labels)
        self.assertIn(("Create", False), labels)
        # no state-changing HTTP verbs were ever performed
        self.assertNotIn("DELETE", app.methods())
        self.assertNotIn("PUT", app.methods())

    def test_destructive_never_performed_even_with_auto_approve(self):
        app = FakeApp(authenticated=True)
        sink = RecSink()
        # the most permissive safe-ish config: approve everything, no dry-run
        _explore(app, RoePolicy(read_only=False, dry_run_default=False),
                 approver=AutoApprover(True), sink=sink)
        labels = sink.labels()
        # Edit is a consented mutation -> actually performed
        self.assertIn(("Edit", True), labels)
        self.assertIn("PUT", app.methods())
        # Delete is destructive -> denied no matter what, never performed
        self.assertIn(("Delete", False), labels)
        delete_reasons = [r[2] for r in sink.rows if r[0] == "Delete"]
        self.assertTrue(all("DESTRUCTIVE" in x for x in delete_reasons))
        self.assertNotIn("DELETE", app.methods())

    def test_out_of_scope_link_not_followed(self):
        app = FakeApp(authenticated=True, with_evil_link=True)
        res = _explore(app, RoePolicy())
        self.assertFalse(any("evil.test" in u for u in app.urls()),
                         "out-of-scope link must never be visited")
        self.assertEqual(res.states_seen, 6)  # in-scope coverage unaffected


class TestRecoveryAndResume(unittest.TestCase):
    def test_rate_limit_backoff(self):
        app = FakeApp(authenticated=True, rate_limit_at=2)
        sleeps = []
        res = _explore(app, RoePolicy(), pacer=Pacer(max_rps=1000),
                       sleep=lambda s: sleeps.append(s))
        self.assertNotEqual(res.stopped, "PAUSE_FOR_HUMAN")
        self.assertTrue(sleeps, "pacer/backoff should have been exercised")
        self.assertGreater(res.states_seen, 1, "should recover and keep exploring")

    def test_session_expiry_pauses(self):
        app = FakeApp(authenticated=False)
        gate = ConsentGate(RoePolicy())
        ex = Explorer(app, ScopeGuard(engagement()), gate, "A")
        res = ex.run(start="https://app.test/admin")
        self.assertEqual(res.stopped, "PAUSE_FOR_HUMAN")

    def test_resume_skips_done_actions(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "explore.jsonl")

        app1 = FakeApp(authenticated=True)
        res1 = _explore(app1, RoePolicy(), ledger=ActionLedger(path))
        self.assertGreater(res1.actions_attempted, 0)

        app2 = FakeApp(authenticated=True)
        res2 = _explore(app2, RoePolicy(), ledger=ActionLedger(path))
        self.assertEqual(res2.actions_attempted, 0)
        self.assertEqual(res2.actions_performed, 0)


class TestBudget(unittest.TestCase):
    def test_total_action_cap_stops(self):
        app = FakeApp(authenticated=True)
        res = _explore(app, RoePolicy(), config=ExploreConfig(max_total_actions=3))
        self.assertLessEqual(res.actions_attempted, 4)
        self.assertEqual(res.stopped, "BUDGET")


if __name__ == "__main__":
    unittest.main()
