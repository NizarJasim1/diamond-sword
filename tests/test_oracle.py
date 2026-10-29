"""Spec-first T3 tests: oracle schemas, question_bus, answer_apply (scope fail-closed), playbook."""
import os
import tempfile
import unittest

from diamond_sword.oracle.answer_apply import apply_answers
from diamond_sword.oracle.playbook import Playbook, Rule
from diamond_sword.oracle.question_bus import QuestionBus
from diamond_sword.oracle.schemas import SchemaError, validate_answers, validate_questions


class TestSchemas(unittest.TestCase):
    def test_valid_and_invalid(self):
        validate_questions({"questions": [{"id": "q1", "kind": "locator"}]})
        validate_answers({"answers": [{"id": "q1", "rule": {"when": {}, "action": {}}}]})
        for bad in ({"questions": [{"kind": "x"}]}, {"questions": "x"}):
            with self.assertRaises(SchemaError):
                validate_questions(bad)


class TestQuestionBus(unittest.TestCase):
    def test_ask_dedup_and_pending(self):
        with tempfile.TemporaryDirectory() as d:
            qb = QuestionBus(os.path.join(d, "q.jsonl"))
            self.assertTrue(qb.ask("q1", "locator", url="/x"))
            self.assertFalse(qb.ask("q1", "locator"))          # deduped, does not block
            self.assertEqual({p["id"] for p in qb.pending()}, {"q1"})


class TestPlaybook(unittest.TestCase):
    def test_add_rule_idempotent_and_roundtrip(self):
        pb = Playbook("gitlab").add_rule(Rule("r1", {"a": 1}, {"b": 2}))
        pb2 = pb.add_rule(Rule("r1", {}, {}))                   # same id -> no duplicate
        self.assertEqual(len(pb2.rules), 1)
        self.assertEqual(Playbook.from_dict(pb.to_dict()).rules, pb.rules)

    def test_set_id_pattern_and_diff(self):
        pb = Playbook("x").set_id_pattern("/orders/{num}", "sequential")
        self.assertEqual(pb.id_patterns["/orders/{num}"], "sequential")
        self.assertEqual(Playbook("x").add_rule(Rule("r1")).diff(Playbook("x")),
                         {"added": [], "removed": ["r1"]})


class TestAnswerApply(unittest.TestCase):
    def test_applies_rule_and_id_pattern(self):
        ans = {"answers": [{"id": "a1", "rule": {"when": {}, "action": {"click": "x"}}},
                           {"id": "a2", "id_pattern": {"template": "/o/{num}", "pattern": "sequential"}}]}
        rep = apply_answers(ans, Playbook("x"))
        self.assertEqual(set(rep.applied), {"a1", "a2"})
        self.assertEqual(len(rep.playbook.rules), 1)
        self.assertEqual(rep.playbook.id_patterns["/o/{num}"], "sequential")

    def test_out_of_scope_answer_rejected(self):  # fail-closed
        ans = {"answers": [{"id": "bad", "url": "https://evil.com/x",
                            "rule": {"when": {}, "action": {}}}]}
        rep = apply_answers(ans, Playbook("x"), scope_check=lambda u: "t.com" in u)
        self.assertEqual(rep.applied, ())
        self.assertEqual(rep.rejected, (("bad", "OUT_OF_SCOPE"),))


if __name__ == "__main__":
    unittest.main(verbosity=2)
