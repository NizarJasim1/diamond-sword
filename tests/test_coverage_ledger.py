"""Tests for diamond_sword.heal.coverage_ledger (Tier T3): resume with nothing lost."""

import os
import tempfile
import unittest

from diamond_sword.heal.coverage_ledger import CoverageLedger, rebuild


class TestCoverageLedger(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "coverage.jsonl")

    def tearDown(self):
        self._tmp.cleanup()

    def test_replay_reconstructs_state(self):  # REQ-CL-01
        led = CoverageLedger(self.path)
        led.add_frontier("/orders/{id}")
        led.add_frontier("/users/{id}")
        led.mark_visited("/orders/{id}")
        led.mark_captured("A")
        led.mark_captured("B")
        led.ask("q1")
        led.answer("q1")
        led.ask("q2")
        led.checkpoint("after-A", note="done")

        st = led.state()
        self.assertEqual(st.frontier_added, {"/orders/{id}", "/users/{id}"})
        self.assertEqual(st.visited, {"/orders/{id}"})
        self.assertEqual(st.principals, {"A", "B"})
        self.assertEqual(st.pending_frontier, {"/users/{id}"})   # added minus visited
        self.assertEqual(st.open_questions, {"q2"})              # asked minus answered
        self.assertEqual(len(st.checkpoints), 1)

    def test_crash_truncated_tail_tolerated(self):  # REQ-CL-02
        led = CoverageLedger(self.path)
        led.add_frontier("/a")
        led.mark_visited("/a")
        led.add_frontier("/b")
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write('{"event":"visited","da')  # crash mid-write
        st = rebuild(self.path)
        self.assertTrue(st.trailing_incomplete)
        self.assertEqual(st.frontier_added, {"/a", "/b"})
        self.assertEqual(st.visited, {"/a"})
        self.assertEqual(st.pending_frontier, {"/b"})           # recovered exactly

    def test_resume_appends_and_reconstructs(self):  # REQ-CL-03
        led = CoverageLedger(self.path)
        led.add_frontier("/a")
        led.mark_visited("/a")
        led2 = CoverageLedger(self.path)  # reopen after "restart"
        led2.add_frontier("/b")
        led2.mark_visited("/b")
        st = rebuild(self.path)
        self.assertEqual(st.visited, {"/a", "/b"})
        self.assertEqual(st.pending_frontier, set())

    def test_empty_is_clean(self):
        st = rebuild(self.path)
        self.assertEqual(st.events, 0)
        self.assertEqual(st.pending_frontier, set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
