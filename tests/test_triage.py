"""Spec-first T3 tests for coverage.triage: golden scores, ordering, query-key ids."""
import unittest
from diamond_sword.coverage.triage import TriageResult, rank, score_template, score_url


class TestTriage(unittest.TestCase):
    def test_golden_scores(self):
        self.assertEqual(score_template("GET", "/payment", ()).score, 5)
        self.assertEqual(score_template("GET", "/admin", ()).score, 5)
        self.assertEqual(score_template("GET", "/graphql", ()).score, 4)
        self.assertEqual(score_template("DELETE", "/orders/{num}", ()).score, 13)
        self.assertEqual(score_template("GET", "/static/app.js", ()), TriageResult(0, ("static",), ("static asset",)))

    def test_export_data_file_not_static(self):
        # .csv/.pdf are data exports (high value), not zeroed assets
        self.assertGreater(score_template("GET", "/reports/export.csv", ()).score, 0)

    def test_url_templatized_then_scored(self):
        self.assertEqual(score_url("https://t.com/orders/1021").score, 7)  # orders(+5)+{num}(+2)

    def test_query_key_id(self):
        self.assertIn("object_id", score_template("GET", "/items", ("user_id",)).categories)
        self.assertNotIn("object_id", score_template("GET", "/items", ("sort",)).categories)

    def test_token_match_not_substring(self):
        # "display" must not match "pay"
        self.assertEqual(score_template("GET", "/display", ()).score, 0)

    def test_rank_orders_desc(self):
        items = [("a", "GET", "/static/x.js", ()), ("b", "DELETE", "/orders/{num}", ()),
                 ("c", "GET", "/graphql", ())]
        order = [k for k, _ in rank(items)]
        self.assertEqual(order, ["b", "c", "a"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
