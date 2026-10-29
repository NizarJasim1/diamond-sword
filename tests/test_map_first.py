"""Spec-first T3 tests for coverage.map_first: robots/sitemap/openapi/graphql/js parsers."""
import unittest
from diamond_sword.coverage.map_first import (
    MapFirst, mine_js, parse_graphql_introspection, parse_openapi, parse_robots, parse_sitemap,
)


class TestMapFirst(unittest.TestCase):
    def test_robots(self):
        paths, sm = parse_robots("User-agent: *\nDisallow: /admin\nAllow: /public\n"
                                 "Sitemap: https://t.com/sitemap.xml\n# c")
        self.assertEqual(paths, frozenset({"/admin", "/public"}))
        self.assertEqual(sm, frozenset({"https://t.com/sitemap.xml"}))

    def test_sitemap_urlset(self):
        pages, children = parse_sitemap(
            "<urlset><url><loc>https://t.com/a</loc></url><url><loc>https://t.com/b</loc></url></urlset>")
        self.assertEqual(pages, frozenset({"https://t.com/a", "https://t.com/b"}))
        self.assertEqual(children, frozenset())

    def test_sitemap_index(self):
        pages, children = parse_sitemap(
            "<sitemapindex><sitemap><loc>https://t.com/s1.xml</loc></sitemap></sitemapindex>")
        self.assertEqual(pages, frozenset())
        self.assertEqual(children, frozenset({"https://t.com/s1.xml"}))

    def test_sitemap_no_entity_expansion(self):  # hostile XML must not expand entities / crash
        bad = ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "AAA">]>'
               "<urlset><url><loc>https://t.com/&a;</loc></url></urlset>")
        pages, _ = parse_sitemap(bad)  # regex-based: entity left inert, no expansion, no crash
        self.assertTrue(all("AAA" not in u for u in pages))

    def test_openapi(self):
        out = parse_openapi({"paths": {"/users/{id}": {"get": {}, "post": {}}, "/health": {"get": {}}}})
        self.assertEqual(out, frozenset({("GET", "/users/{id}"), ("POST", "/users/{id}"),
                                         ("GET", "/health")}))

    def test_graphql(self):
        q, m = parse_graphql_introspection({"data": {"__schema": {
            "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
            "types": [{"name": "Query", "fields": [{"name": "me"}, {"name": "orders"}]},
                      {"name": "Mutation", "fields": [{"name": "deleteOrder"}]}]}}})
        self.assertEqual(q, frozenset({"me", "orders"}))
        self.assertEqual(m, frozenset({"deleteOrder"}))

    def test_mine_js(self):
        js = 'fetch("/api/v2/orders"); const u="https://t.com/x"; img.src="/p.png";'
        self.assertEqual(mine_js(js),
                         frozenset({"/api/v2/orders", "https://t.com/x", "/p.png"}))

    def test_aggregate_seeds_deterministic(self):
        mf = MapFirst()
        mf.add_robots("Disallow: /admin")
        mf.add_openapi({"paths": {"/a": {"get": {}}}})
        refs = [s.ref for s in mf.seeds()]
        self.assertEqual(refs, sorted(refs))
        self.assertIn("/admin", refs)
        self.assertIn("/a", refs)


if __name__ == "__main__":
    unittest.main(verbosity=2)
