"""Spec-first T3 tests for coverage.crawler: collapse, scope fail-closed, traps, dedup, ledger."""
import os
import tempfile
import unittest
from urllib.parse import urlsplit

from diamond_sword.coverage.crawler import Crawler, FetchResult, extract_links
from diamond_sword.heal.coverage_ledger import CoverageLedger

BASE = "https://t.com"
ORDER_TPL = '<body><main><h1>Order</h1><a href="/orders/{i}/receipt">r</a></main></body>'
RECEIPT = '<body><main><h2>Receipt</h2></main></body>'
LEAF = '<body><main><p>leaf</p></main></body>'


def _site():
    pages = {}
    index_links = ['<a href="/orders/1">o1</a><a href="/orders/2">o2</a><a href="/orders/3">o3</a>',
                   '<a href="/admin">adm</a><a href="/reports/export.csv">exp</a>',
                   '<a href="https://evil.com/x">oos</a><a href="/static/app.js">js</a>']
    index_links += [f'<a href="/cal?page={n}">p{n}</a>' for n in range(1, 60)]
    pages[BASE + "/"] = "<body><nav>" + "".join(index_links) + "</nav></body>"
    for i in (1, 2, 3):
        pages[f"{BASE}/orders/{i}"] = ORDER_TPL.format(i=i)
        pages[f"{BASE}/orders/{i}/receipt"] = RECEIPT
    pages[BASE + "/admin"] = LEAF
    pages[BASE + "/reports/export.csv"] = LEAF
    pages[BASE + "/static/app.js"] = LEAF
    for n in range(1, 60):
        pages[f"{BASE}/cal?page={n}"] = LEAF
    return pages


def _fetch(pages):
    def f(url):
        html = pages.get(url)
        return FetchResult(200, html, url) if html is not None else FetchResult(404, "", url)
    return f


def _in_scope(url):
    return urlsplit(url).netloc == "t.com"


class TestCrawler(unittest.TestCase):
    def setUp(self):
        self.pages = _site()

    def test_out_of_scope_never_visited(self):  # fail-closed
        c = Crawler(_fetch(self.pages), _in_scope)
        res = c.crawl(start=BASE + "/")
        self.assertTrue(all(urlsplit(p.url).netloc == "t.com" for p in res.pages))
        self.assertFalse(any("evil.com" in p.url for p in res.pages))

    def test_templates_collapse(self):
        c = Crawler(_fetch(self.pages), _in_scope)
        res = c.crawl(start=BASE + "/")
        self.assertIn("GET /orders/{num}", res.templates)
        self.assertIn("GET /orders/{num}/receipt", res.templates)
        self.assertIn("GET /admin", res.templates)

    def test_pagination_trap_detected(self):
        c = Crawler(_fetch(self.pages), _in_scope)
        res = c.crawl(start=BASE + "/")
        self.assertTrue(any(t.startswith("GET /cal") for t in res.traps))

    def test_no_rewalk_structural_dedup(self):
        c = Crawler(_fetch(self.pages), _in_scope)
        res = c.crawl(start=BASE + "/")
        # 3 receipts share one structure -> counted once among distinct structures
        self.assertLess(res.distinct_structures, len(res.pages))

    def test_ledger_resume_state(self):
        with tempfile.TemporaryDirectory() as d:
            led = CoverageLedger(os.path.join(d, "cov.jsonl"))
            Crawler(_fetch(self.pages), _in_scope, ledger=led).crawl(start=BASE + "/")
            st = led.state()
            self.assertGreater(len(st.visited), 0)
            self.assertGreater(len(st.frontier_added), 0)

    def test_deny_all_by_default(self):  # no scope predicate => crawl nothing (fail-closed)
        res = Crawler(_fetch(self.pages)).crawl(start=BASE + "/")
        self.assertEqual(res.pages, ())

    def test_extract_links_filters_schemes(self):
        html = '<a href="/a">x</a><a href="javascript:void(0)">y</a><a href="https://z.com/b">z</a>'
        links = extract_links(html, BASE + "/")
        self.assertIn(BASE + "/a", links)
        self.assertIn("https://z.com/b", links)
        self.assertFalse(any("javascript" in u for u in links))


if __name__ == "__main__":
    unittest.main(verbosity=2)
