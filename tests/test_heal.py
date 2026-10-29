"""Spec-first T3 tests for the self-healing core (locator_cascade, invariant, recovery_fsm, pacer)."""
import unittest

from diamond_sword.heal.intent import Postcondition
from diamond_sword.heal.invariant import StabilityTracker, check_postcondition, is_stable
from diamond_sword.heal.locator_cascade import DomSnapshot, Element, Target, exists, locate
from diamond_sword.heal.pacer import Pacer
from diamond_sword.heal.recovery_fsm import Action, RecoveryFSM, Signals, Symptom, classify, recover


def snap(elements, url="https://t.com/app"):
    return DomSnapshot(url, tuple(elements))


class TestCascade(unittest.TestCase):
    def test_role_unique_wins(self):
        s = snap([Element("n1", "button", role="button"), Element("n2", "a", role="link")])
        r = locate(s, Target(role="button"))
        self.assertEqual((r.node_id, r.strategy), ("n1", "role"))

    def test_ambiguous_role_falls_through_to_test_id(self):
        s = snap([Element("n1", "button", role="button", test_id="save"),
                  Element("n2", "button", role="button", test_id="cancel")])
        r = locate(s, Target(role="button", test_id="save"))
        self.assertEqual((r.node_id, r.strategy), ("n1", "test_id"))

    def test_text_ambiguous_resolved_by_ancestor(self):
        s = snap([Element("d1", "button", text="Delete", ancestors=("card-1",)),
                  Element("d2", "button", text="Delete", ancestors=("card-2",))])
        r = locate(s, Target(text="Delete", near="card-1"))
        self.assertEqual((r.node_id, r.strategy), ("d1", "ancestor"))

    def test_text_unique_wins(self):
        s = snap([Element("t1", "span", text="Logout"), Element("t2", "span", text="Home")])
        r = locate(s, Target(text="Logout"))
        self.assertEqual((r.node_id, r.strategy), ("t1", "text"))

    def test_selector_layer(self):
        s = snap([Element("n1", "div", selectors=frozenset({"#main>button"}))])
        self.assertEqual(locate(s, Target(css="#main>button")).node_id, "n1")

    def test_not_found(self):
        r = locate(snap([Element("n1", "div")]), Target(role="button"))
        self.assertIsNone(r.node_id)

    def test_exists(self):
        s = snap([Element("n1", "div", role="dialog")])
        self.assertTrue(exists(s, Target(role="dialog")))
        self.assertFalse(exists(s, Target(role="button")))


class TestInvariant(unittest.TestCase):
    def test_postcondition_all_conditions(self):
        s = snap([Element("n1", "h1", text="Dashboard")], url="https://t.com/dashboard")
        self.assertTrue(check_postcondition(s, Postcondition(url_contains="dashboard",
                                                             element_appears=Target(text="Dashboard"))))
        self.assertFalse(check_postcondition(s, Postcondition(url_contains="settings")))
        self.assertFalse(check_postcondition(s, Postcondition(element_gone=Target(text="Dashboard"))))

    def test_is_stable(self):
        self.assertFalse(is_stable(["a", "a"], 3))        # not enough samples
        self.assertTrue(is_stable(["x", "a", "a", "a"], 3))
        self.assertFalse(is_stable(["a", "a", "b"], 3))   # last 3 differ

    def test_stability_tracker(self):
        t = StabilityTracker(3)
        self.assertFalse(t.push("a"))
        self.assertFalse(t.push("a"))
        self.assertTrue(t.push("a"))


class TestRecovery(unittest.TestCase):
    def test_classify_each(self):
        base = snap([], url="https://t.com/app")
        self.assertEqual(classify(base, None, Signals(destructive_blocked=True)), Symptom.DESTRUCTIVE_BLOCKED)
        self.assertEqual(classify(base, None, Signals(http_status=429)), Symptom.RATE_LIMITED)
        self.assertEqual(classify(base, None, Signals(waf=True)), Symptom.RATE_LIMITED)
        self.assertEqual(classify(base, None, Signals(http_status=401)), Symptom.SESSION_EXPIRED)
        self.assertEqual(classify(snap([], url="https://t.com/users/sign-in"), None, Signals()), Symptom.SESSION_EXPIRED)
        self.assertEqual(classify(snap([Element("m", "div", role="dialog")]), None, Signals()), Symptom.MODAL)
        self.assertEqual(classify(base, Postcondition(url_contains="dashboard"), Signals()), Symptom.UNEXPECTED_PAGE)
        self.assertEqual(classify(base, None, Signals()), Symptom.OK)

    def test_recover_mapping(self):
        self.assertEqual(recover(Symptom.SESSION_EXPIRED), Action.PAUSE_FOR_HUMAN)
        self.assertEqual(recover(Symptom.RATE_LIMITED), Action.BACKOFF_RETRY)
        self.assertEqual(recover(Symptom.OK), Action.PROCEED)

    def test_escalation_and_reset(self):
        fsm = RecoveryFSM(max_retries=2)
        s = snap([], url="https://t.com/x")
        post = Postcondition(url_contains="dashboard")  # -> UNEXPECTED_PAGE
        self.assertEqual(fsm.step(s, post, Signals())[1], Action.GOTO_NEAREST_KNOWN)  # streak 1
        self.assertEqual(fsm.step(s, post, Signals())[1], Action.GOTO_NEAREST_KNOWN)  # streak 2
        self.assertEqual(fsm.step(s, post, Signals())[1], Action.ABORT_STEP)          # streak 3 > 2
        # an OK resets the streak
        self.assertEqual(fsm.step(s, None, Signals())[0], Symptom.OK)
        self.assertEqual(fsm.step(s, post, Signals())[2], 1)


class TestPacer(unittest.TestCase):
    def test_floor_is_rate_cap(self):
        p = Pacer(max_rps=2.0)
        self.assertAlmostEqual(p.next_delay(), 0.5)

    def test_success_never_below_floor(self):
        p = Pacer(max_rps=2.0)
        for _ in range(5):
            p.on_success()
        self.assertGreaterEqual(p.next_delay(), 0.5)

    def test_rate_limit_increases_capped(self):
        p = Pacer(max_rps=2.0, mult=2.0, max_delay=4.0)
        d1 = p.on_rate_limited()
        self.assertAlmostEqual(d1, 1.0)            # 0.5 * 2
        for _ in range(10):
            p.on_rate_limited()
        self.assertLessEqual(p.next_delay(), 4.0)  # capped

    def test_retry_after_honored(self):
        p = Pacer(max_rps=10.0)
        self.assertGreaterEqual(p.on_rate_limited(retry_after=5.0), 5.0)

    def test_invalid_rps(self):
        with self.assertRaises(ValueError):
            Pacer(0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
