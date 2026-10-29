"""Spec-first T3 tests: offline model pool (failover + verify gate) and output verification."""
import unittest

from diamond_sword.models.pool import ModelPool
from diamond_sword.models.providers import FREE_PROVIDERS, Provider
from diamond_sword.models.verify import verify_json


class TestVerifyJson(unittest.TestCase):
    def test_valid_and_fenced(self):
        self.assertEqual(verify_json('{"a":1}', ("a",)), {"a": 1})
        self.assertEqual(verify_json('```json\n{"a":1}\n```', ("a",)), {"a": 1})

    def test_rejections(self):
        self.assertIsNone(verify_json('{"a":1}', ("b",)))   # missing key
        self.assertIsNone(verify_json('{"a":1}', ("a", "b")))   # multi-key: one missing
        self.assertIsNone(verify_json("not json"))
        self.assertIsNone(verify_json("[1,2]"))             # not an object
        self.assertIsNone(verify_json(None))                # not a string


class TestPool(unittest.TestCase):
    def test_failover_on_none(self):
        calls = []

        def caller(p, prompt):
            calls.append(p.name)
            return None if p.name == "groq" else "ok"

        pool = ModelPool(FREE_PROVIDERS, caller)
        self.assertEqual(pool.ask("hi"), "ok")
        self.assertEqual(calls[:2], ["groq", "gemini"])     # rotated past the failing one

    def test_verify_gate_rejects_bad_output(self):
        def caller(p, prompt):
            return "bad" if p.name == "groq" else '{"ok":1}'
        pool = ModelPool(FREE_PROVIDERS, caller)
        out = pool.ask("hi", verify_fn=lambda t: verify_json(t, ("ok",)) is not None)
        self.assertEqual(out, '{"ok":1}')

    def test_all_fail_returns_none(self):
        self.assertIsNone(ModelPool((Provider("x", "m", 1),), lambda p, s: None).ask("hi"))

    def test_caller_exception_fails_over(self):
        def caller(p, s):
            if p.name == "groq":
                raise RuntimeError("boom")
            return "ok"
        self.assertEqual(ModelPool(FREE_PROVIDERS, caller).ask("hi"), "ok")

    def test_empty_providers(self):
        with self.assertRaises(ValueError):
            ModelPool((), lambda p, s: "x")


if __name__ == "__main__":
    unittest.main(verbosity=2)
