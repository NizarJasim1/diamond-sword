"""Spec-first tests for diamond_sword.legal.scope_guard (Tier T3).

Covers: allow/deny on realistic bug-bounty scope shapes (fictional programs), out-of-scope precedence,
the fail-closed default, a hostile URL corpus (userinfo spoof, suffix spoof, bad scheme),
port and path constraints, and the DecisionSink seam for the audit ledger.
"""

import json
import os
import unittest

from diamond_sword.legal.scope_guard import Decision, ListSink, Reason, ScopeGuard
from diamond_sword.legal.scope_parser import load_engagement

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures", "engagements")


def _guard(name, sink=None):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return ScopeGuard(load_engagement(json.load(fh)), sink=sink)


class TestAcmePayScope(unittest.TestCase):
    def setUp(self):
        self.g = _guard("acmepay.json")

    def test_exact_host_allowed(self):  # REQ-SC-04
        d = self.g.check("https://api.acmepay.example/v3/currencies")
        self.assertTrue(d.allowed)
        self.assertEqual(d.reason, Reason.ALLOW_IN_SCOPE)

    def test_wildcard_subdomain_allowed(self):
        self.assertTrue(self.g.allowed("https://random123.acmepay.example/"))
        self.assertTrue(self.g.allowed("https://a.b.acmemint.example/x"))

    def test_apex_listed_allowed(self):
        self.assertTrue(self.g.allowed("https://acmepay.example/"))

    def test_wildcard_only_apex_denied(self):  # acmemint has only *.acmemint.example
        d = self.g.check("https://acmemint.example/")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, Reason.DENY_NOT_IN_SCOPE)

    def test_out_of_scope_precedence(self):  # REQ-SC-03 — exclusion beats *.acmepay.example
        d = self.g.check("https://dev.acmepay.example/anything")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, Reason.DENY_OUT_OF_SCOPE)

    def test_unrelated_host_denied(self):
        d = self.g.check("https://example.org/")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, Reason.DENY_NOT_IN_SCOPE)


class TestHostileCorpus(unittest.TestCase):
    """The security core: no spoof may be allowed."""

    def setUp(self):
        self.g = _guard("acmepay.json")

    def test_userinfo_spoof_denied(self):  # NFR-SC-01
        d = self.g.check("https://api.acmepay.example@evil.com/")
        self.assertFalse(d.allowed)
        self.assertEqual(d.host, "evil.com")  # hostname stripped userinfo correctly

    def test_suffix_spoof_denied(self):  # NFR-SC-01
        self.assertFalse(self.g.allowed("https://api.acmepay.example.evil.com/"))

    def test_substring_spoof_denied(self):
        self.assertFalse(self.g.allowed("https://notacmepay.example/"))

    def test_nonhttp_schemes_denied(self):  # REQ-SC-04
        for url in ("javascript:alert(1)", "ftp://api.acmepay.example/", "file:///etc/passwd",
                    "data:text/html,x"):
            d = self.g.check(url)
            self.assertFalse(d.allowed, url)

    def test_empty_and_garbage_denied(self):
        self.assertFalse(self.g.allowed(""))
        self.assertFalse(self.g.allowed("   "))
        self.assertFalse(self.g.allowed("not a url"))

    def test_case_insensitive_host(self):
        self.assertTrue(self.g.allowed("https://API.AcmePay.EXAMPLE/v3"))

    def test_fqdn_trailing_dot(self):
        self.assertTrue(self.g.allowed("https://api.acmepay.example./v3"))


class TestPortAndPath(unittest.TestCase):
    def test_port_constraint(self):  # REQ-SC-05
        eng = load_engagement({"scope": {"in": [{"host": "x.com", "port": 8443}]}})
        g = ScopeGuard(eng)
        self.assertFalse(g.allowed("https://x.com/"))           # default 443 != 8443
        self.assertTrue(g.allowed("https://x.com:8443/"))

    def test_no_port_constraint_allows_any(self):
        g = _guard("crapi.local.json")
        self.assertTrue(g.allowed("http://127.0.0.1:8888/identity/api"))
        self.assertTrue(g.allowed("http://localhost/x"))

    def test_path_prefix(self):  # REQ-SC-05
        eng = load_engagement({"scope": {"in": [{"host": "x.com", "path": "/api"}]}})
        g = ScopeGuard(eng)
        self.assertTrue(g.allowed("https://x.com/api"))
        self.assertTrue(g.allowed("https://x.com/api/v1/users"))
        self.assertFalse(g.allowed("https://x.com/apix"))        # boundary
        self.assertFalse(g.allowed("https://x.com/other"))
        self.assertFalse(g.allowed("https://x.com/api/../admin"))  # traversal normalized


class TestDevHubScope(unittest.TestCase):
    def setUp(self):
        self.g = _guard("devhub.json")

    def test_graphql_and_rest_paths_allowed(self):  # REST-vs-GraphQL both on devhub.example
        self.assertTrue(self.g.allowed("https://devhub.example/api/graphql"))
        self.assertTrue(self.g.allowed("https://devhub.example/api/v4/projects/1"))

    def test_subdomain_allowed_but_oos_excluded(self):
        self.assertTrue(self.g.allowed("https://registry.devhub.example/x"))
        self.assertFalse(self.g.allowed("https://forum.devhub.example/t/1"))


class TestDecisionSink(unittest.TestCase):
    def test_every_check_is_recorded(self):  # REQ-SC-06 — audit-ledger seam
        sink = ListSink()
        g = _guard("acmepay.json", sink=sink)
        g.check("https://api.acmepay.example/a")
        g.check("https://dev.acmepay.example/b")
        g.check("https://evil.com/c")
        self.assertEqual(len(sink.decisions), 3)
        self.assertTrue(sink.decisions[0].allowed)
        self.assertEqual(sink.decisions[1].reason, Reason.DENY_OUT_OF_SCOPE)
        self.assertEqual(sink.decisions[2].reason, Reason.DENY_NOT_IN_SCOPE)
        for d in sink.decisions:
            self.assertIsInstance(d, Decision)
            self.assertTrue(d.url)

    def test_decision_is_truthy_by_allowed(self):
        g = _guard("acmepay.json")
        self.assertTrue(bool(g.check("https://api.acmepay.example/a")))
        self.assertFalse(bool(g.check("https://evil.com/a")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
