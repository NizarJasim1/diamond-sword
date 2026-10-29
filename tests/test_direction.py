import unittest

from diamond_sword.interact.direction import Direction
from diamond_sword.interact.explorer import Explorer
from diamond_sword.legal.consent_gate import ConsentGate
from diamond_sword.legal.roe import RoePolicy
from diamond_sword.legal.scope_guard import ScopeGuard
from diamond_sword.oracle.schemas import SchemaError
from tests._fakeapp import FakeApp, engagement


class TestDirectionParsing(unittest.TestCase):
    def test_from_doc(self):
        doc = {"target": "t", "interaction": {
            "flows": [{"id": "login", "steps": [
                {"action": "fill", "test_id": "email", "value": "a@b.c"},
                {"action": "click", "text": "Sign in", "expect_url": "/dashboard"}]}],
            "priority": ["Admin", "Billing"], "avoid": ["Logout"],
            "seeds": ["https://app.test/dashboard"]}}
        d = Direction.from_doc(doc)
        self.assertEqual(len(d.flows), 1)
        self.assertEqual(d.flows[0].id, "login")
        self.assertEqual(len(d.flows[0].steps), 2)
        self.assertEqual(d.seeds, ("https://app.test/dashboard",))
        self.assertEqual(d.priority, ("admin", "billing"))

    def test_avoid_and_priority(self):
        d = Direction(priority=("admin", "billing"), avoid=("logout",))
        self.assertTrue(d.is_avoided("Logout", None))
        self.assertTrue(d.is_avoided("x", "https://app.test/logout"))
        self.assertFalse(d.is_avoided("Save", None))
        self.assertGreater(d.priority_rank("Admin panel", None), d.priority_rank("Billing", None))
        self.assertEqual(d.priority_rank("Nothing", None), 0)

    def test_bad_interaction_rejected(self):
        with self.assertRaises(SchemaError):
            Direction.from_doc({"target": "t", "interaction": {"flows": "nope"}})
        with self.assertRaises(SchemaError):
            Direction.from_doc({"target": "t", "interaction": {"priority": [1, 2]}})


class TestFlowAndAvoidEndToEnd(unittest.TestCase):
    def _gate(self):
        return ConsentGate(RoePolicy())  # read-only, fail-closed

    def test_login_flow_reaches_dashboard(self):
        app = FakeApp(authenticated=False)
        doc = {"target": "fake", "interaction": {
            "flows": [{"id": "login", "steps": [
                {"action": "fill", "test_id": "email", "value": "a@b.c"},
                {"action": "fill", "test_id": "password", "value": "pw"},
                {"action": "click", "text": "Sign in", "expect_url": "/dashboard"}]}],
            "seeds": ["https://app.test/dashboard"]}}
        ex = Explorer(app, ScopeGuard(engagement()), self._gate(), "A",
                      direction=Direction.from_doc(doc))
        res = ex.run()
        self.assertTrue(app.auth, "flow should have logged in")
        self.assertGreater(res.states_seen, 1)
        self.assertTrue(any("/dashboard" in u for u in app.urls()))

    def test_avoid_blocks_navigation(self):
        app = FakeApp(authenticated=True)
        d = Direction(avoid=("admin",), seeds=("https://app.test/dashboard",))
        ex = Explorer(app, ScopeGuard(engagement()), self._gate(), "A", direction=d)
        ex.run()
        self.assertFalse(any(u.endswith("/admin") for u in app.urls()),
                         "Admin link was avoided and must never be navigated")


if __name__ == "__main__":
    unittest.main()
