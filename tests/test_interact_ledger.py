import os
import tempfile
import unittest

from diamond_sword.interact.action_ledger import ActionLedger, rebuild_actions


class TestActionLedger(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "explore.jsonl")

    def test_record_and_rebuild(self):
        led = ActionLedger(self.path)
        led.mark_state("s1", "https://x/a")
        led.mark_action("s1", "sigA", "click", True, "ALLOW_READ_ONLY")
        led.mark_action("s1", "sigB", "click", False, "DENY_DESTRUCTIVE")
        led.mark_trap("s2", "PER_STATE_CAP")
        led.ask("q1")
        st = rebuild_actions(self.path)
        self.assertIn("s1", st.states)
        self.assertTrue(st.is_done("s1", "sigA"))
        self.assertTrue(st.is_done("s1", "sigB"))
        self.assertIn(("s1", "sigA"), st.performed)
        self.assertNotIn(("s1", "sigB"), st.performed)
        self.assertIn("s2", st.traps)
        self.assertIn("q1", st.questions)

    def test_is_done_false_for_unknown(self):
        led = ActionLedger(self.path)
        led.mark_action("s1", "sigA", "click", True, "ALLOW_READ_ONLY")
        st = led.state()
        self.assertFalse(st.is_done("s1", "other"))
        self.assertFalse(st.is_done("sX", "sigA"))

    def test_crash_truncated_line_tolerated(self):
        led = ActionLedger(self.path)
        led.mark_action("s1", "sigA", "click", True, "ALLOW")
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write('{"event": "action", "data": {"state": "s1", "sig": "par')  # no newline
        st = rebuild_actions(self.path)
        self.assertTrue(st.trailing_incomplete)
        self.assertTrue(st.is_done("s1", "sigA"))        # the complete record survived


if __name__ == "__main__":
    unittest.main()
