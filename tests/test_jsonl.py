"""Tests for diamond_sword.util.jsonl (Tier T3): crash-safe append and tolerant read."""

import os
import tempfile
import unittest

from diamond_sword.util.jsonl import append_jsonl, read_jsonl


class TestJsonl(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "sub", "log.jsonl")  # sub tests dir creation

    def tearDown(self):
        self._tmp.cleanup()

    def test_round_trip(self):
        append_jsonl(self.path, {"a": 1})
        append_jsonl(self.path, {"b": 2})
        res = read_jsonl(self.path)
        self.assertEqual([r for r in res], [{"a": 1}, {"b": 2}])
        self.assertFalse(res.trailing_incomplete)

    def test_missing_file_is_empty(self):
        res = read_jsonl(os.path.join(self._tmp.name, "nope.jsonl"))
        self.assertEqual(len(res), 0)
        self.assertFalse(res.trailing_incomplete)

    def test_blank_lines_skipped(self):
        append_jsonl(self.path, {"a": 1})
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write("\n   \n")
        append_jsonl(self.path, {"b": 2})
        self.assertEqual([r for r in read_jsonl(self.path)], [{"a": 1}, {"b": 2}])

    def test_corrupt_final_line_is_trailing_incomplete(self):  # crash-truncated write
        append_jsonl(self.path, {"a": 1})
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write('{"b": 2, "oops')  # truncated, no newline
        res = read_jsonl(self.path)
        self.assertEqual([r for r in res], [{"a": 1}])
        self.assertTrue(res.trailing_incomplete)

    def test_corrupt_middle_line_skipped_not_fatal(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write('{"a":1}\n')
            fh.write('{bad}\n')
            fh.write('{"c":3}\n')
        res = read_jsonl(self.path)
        self.assertEqual([r for r in res], [{"a": 1}, {"c": 3}])
        self.assertFalse(res.trailing_incomplete)


if __name__ == "__main__":
    unittest.main(verbosity=2)
