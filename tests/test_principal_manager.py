"""Spec-first T3 tests for coverage.principal_manager: per-principal tagging, order, common set."""
import os
import tempfile
import unittest
from urllib.parse import urlsplit

from diamond_sword.coverage.crawler import Crawler, FetchResult
from diamond_sword.coverage.principal_manager import PrincipalManager, PrincipalResult
from diamond_sword.heal.coverage_ledger import CoverageLedger

BASE = "https://t.com"


def _pages_for(principal):
    # A sees an extra admin-only link that B/anon do not.
    extra = '<a href="/admin/secret">s</a>' if principal == "A" else ""
    pages = {BASE + "/": f'<body><nav><a href="/orders/1">o</a>{extra}</nav></body>',
             BASE + "/orders/1": "<body><main><p>o</p></main></body>"}
    if principal == "A":
        pages[BASE + "/admin/secret"] = "<body><main><p>secret</p></main></body>"
    return pages


def _fetch_for(principal):
    pages = _pages_for(principal)

    def f(url):
        html = pages.get(url)
        return FetchResult(200, html, url) if html is not None else FetchResult(404, "", url)
    return f


def _in_scope(url):
    return urlsplit(url).netloc == "t.com"


class TestPrincipalManager(unittest.TestCase):
    def test_tagging_order_and_common(self):
        order_seen = []

        def make(principal):
            order_seen.append(principal)
            return Crawler(_fetch_for(principal), _in_scope)

        pm = PrincipalManager(["A", "B", "anon"], make)
        results = pm.run(start=BASE + "/")
        self.assertEqual(order_seen, ["A", "B", "anon"])              # fixed order
        self.assertEqual(set(results), {"A", "B", "anon"})
        for p, r in results.items():
            self.assertEqual(r.principal, p)                          # correct tag
        # only A discovered the admin-only template
        self.assertIn("GET /admin/secret", results["A"].templates)
        self.assertNotIn("GET /admin/secret", results["B"].templates)
        common = PrincipalManager.common_templates(results)
        self.assertIn("GET /orders/{num}", common)
        self.assertNotIn("GET /admin/secret", common)                # intersection excludes A-only

    def test_ledger_captures_each_principal(self):
        with tempfile.TemporaryDirectory() as d:
            led = CoverageLedger(os.path.join(d, "cov.jsonl"))
            pm = PrincipalManager(["A", "B", "anon"],
                                  lambda p: Crawler(_fetch_for(p), _in_scope), ledger=led)
            pm.run(start=BASE + "/")
            self.assertEqual(led.state().principals, {"A", "B", "anon"})

    def test_requires_principal(self):
        with self.assertRaises(ValueError):
            PrincipalManager([], lambda p: None)

    def test_common_templates_requires_all_principals(self):
        # B is the ONLY principal missing t2; a correct intersection must drop t2.
        results = {
            "A": PrincipalResult("A", (), ("t1", "t2", "t3"), ()),
            "B": PrincipalResult("B", (), ("t1", "t3"), ()),
            "anon": PrincipalResult("anon", (), ("t1", "t2", "t3"), ()),
        }
        self.assertEqual(PrincipalManager.common_templates(results), {"t1", "t3"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
