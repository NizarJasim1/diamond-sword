"""Spec-first tests for diamond_sword.legal.scope_parser (Tier T3).

Covers: host normalization, the host-match primitive (incl. the dangerous spoof cases),
path-prefix matching, engagement parsing (valid + malformed), and a differential property
test of host_matches against an independent label-list reference over random hosts.
"""

import json
import os
import random
import unittest

from diamond_sword.legal.scope_parser import (
    Engagement,
    ScopeError,
    host_matches,
    load_engagement,
    normalize_host,
    path_matches,
    remove_dot_segments,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures", "engagements")


def _load(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


class TestNormalizeHost(unittest.TestCase):
    def test_lowercase_and_trailing_dot(self):  # REQ-SC-02
        self.assertEqual(normalize_host("API.AcmePay.EXAMPLE."), "api.acmepay.example")

    def test_wildcard_prefix_preserved(self):
        self.assertEqual(normalize_host("*.AcmePay.example"), "*.acmepay.example")

    def test_rejects_empty_and_whitespace(self):
        for bad in ("", "   ", None, "has space.com", "a\tb.com"):
            self.assertIsNone(normalize_host(bad))

    def test_rejects_empty_labels(self):
        for bad in ("a..b.com", ".acmepay.example", "acmepay.example..", "*."):
            self.assertIsNone(normalize_host(bad))

    def test_idn_encoded_to_ascii(self):  # NFR-SC-01 (normalization survives IDNA)
        out = normalize_host("MÜNCHEN.de")
        self.assertIsNotNone(out)
        self.assertTrue(out.isascii())
        self.assertTrue(out.endswith(".de"))


class TestHostMatches(unittest.TestCase):
    def test_exact(self):  # REQ-SC-02
        self.assertTrue(host_matches("api.acmepay.example", "api.acmepay.example"))
        self.assertFalse(host_matches("api.acmepay.example", "app.acmepay.example"))

    def test_wildcard_any_depth(self):
        self.assertTrue(host_matches("*.acmepay.example", "api.acmepay.example"))
        self.assertTrue(host_matches("*.acmepay.example", "a.b.acmepay.example"))

    def test_wildcard_does_not_match_apex(self):
        self.assertFalse(host_matches("*.acmepay.example", "acmepay.example"))

    def test_suffix_spoof_rejected(self):  # NFR-SC-01 — the classic endswith bug
        self.assertFalse(host_matches("*.acmepay.example", "api.acmepay.example.evil.com"))
        self.assertFalse(host_matches("acmepay.example", "api.acmepay.example.evil.com"))

    def test_substring_spoof_rejected(self):
        self.assertFalse(host_matches("acmepay.example", "notacmepay.example"))
        self.assertFalse(host_matches("*.acmepay.example", "xacmepay.example"))

    def test_empty_inputs(self):
        self.assertFalse(host_matches("", "a.com"))
        self.assertFalse(host_matches("*.", "a.com"))
        self.assertFalse(host_matches("a.com", ""))


class TestPathMatching(unittest.TestCase):
    def test_remove_dot_segments(self):
        self.assertEqual(remove_dot_segments("/api/../admin"), "/admin")
        self.assertEqual(remove_dot_segments("/a/./b/"), "/a/b/")
        self.assertEqual(remove_dot_segments("/../../x"), "/x")
        self.assertEqual(remove_dot_segments(""), "/")

    def test_prefix_boundary(self):  # REQ-SC-05
        self.assertTrue(path_matches("/api", "/api"))
        self.assertTrue(path_matches("/api", "/api/v1/users"))
        self.assertFalse(path_matches("/api", "/apix"))
        self.assertFalse(path_matches("/admin", "/administrator"))

    def test_no_constraint(self):
        self.assertTrue(path_matches(None, "/anything"))
        self.assertTrue(path_matches("/", "/anything"))

    def test_traversal_cannot_bypass(self):
        self.assertFalse(path_matches("/api", "/api/../admin"))  # normalizes to /admin


class TestLoadEngagement(unittest.TestCase):
    def test_minimal_valid(self):  # REQ-SC-01
        eng = load_engagement({"program": "p", "scope": {"in": ["api.x.com"]}})
        self.assertIsInstance(eng, Engagement)
        self.assertEqual(len(eng.in_scope), 1)
        self.assertEqual(eng.in_scope[0].host, "api.x.com")

    def test_bare_scope_shape(self):
        eng = load_engagement({"in": ["a.com"], "out": ["b.a.com"]})
        self.assertEqual(len(eng.in_scope), 1)
        self.assertEqual(len(eng.out_scope), 1)

    def test_string_shorthands(self):
        eng = load_engagement({"scope": {"in": ["*.x.com", "x.com/api/*", "https://app.x.com/p"]}})
        hosts = [a.host for a in eng.in_scope]
        self.assertIn("*.x.com", hosts)
        api = next(a for a in eng.in_scope if a.host == "x.com")
        self.assertEqual(api.path, "/api")

    def test_object_with_port_and_path(self):
        eng = load_engagement({"scope": {"in": [{"type": "api", "host": "x.com", "port": 8443, "path": "/v1"}]}})
        a = eng.in_scope[0]
        self.assertEqual((a.host, a.port, a.path), ("x.com", 8443, "/v1"))

    def test_non_network_kinds_flagged(self):
        eng = load_engagement({"scope": {"in": ["https://github.com/acmepay", "api.x.com"]}})
        kinds = {a.host: a.is_network for a in eng.in_scope}
        self.assertFalse(kinds["github.com"])
        self.assertTrue(kinds["api.x.com"])

    def test_malformed_raises(self):  # REQ-SC-01 — strict structure
        for bad in (
            [],                                              # not a dict
            {"scope": {"in": "api.x.com"}},                  # in must be a list
            {"scope": {"in": [123]}},                        # entry not str/obj
            {"scope": {"in": [{"type": "web"}]}},            # object missing host
            {"scope": {"in": ["bad host.com"]}},             # unparseable host
            {"scope": {"in": [], "out_classes": "nope"}},    # out_classes not list
            {"scope": {"in": [{"host": "x.com", "port": "abc"}]}},  # bad port
        ):
            with self.assertRaises(ScopeError):
                load_engagement(bad)

    def test_empty_in_scope_is_allowed(self):  # safe: guard denies everything
        eng = load_engagement({"scope": {"in": []}})
        self.assertEqual(eng.in_scope, ())

    def test_real_fixtures_load(self):  # REQ-SC-01 on grounded shapes
        for name in ("crapi.local.json", "acmepay.json", "devhub.json"):
            eng = load_engagement(_load(name))
            self.assertGreater(len(eng.network_in_scope), 0, name)


class TestHostMatchDifferential(unittest.TestCase):
    """host_matches must agree with an INDEPENDENT label-list reference on random hosts."""

    @staticmethod
    def _ref(pattern, host):
        # Independent implementation: compare label lists, not string suffixes.
        if pattern.startswith("*."):
            base = pattern[2:].split(".")
            hl = host.split(".")
            return len(hl) > len(base) and hl[-len(base):] == base
        return host == pattern

    def test_random_agreement(self):  # NFR-SC-02 determinism + correctness
        rng = random.Random(1337)
        labels = ["a", "b", "api", "app", "acmepay", "com", "evil", "x", "co", "net"]
        bases = ["acmepay.example", "x.com", "a.b.com", "co", "evil.com"]
        checked = 0
        for _ in range(4000):
            host = ".".join(rng.choice(labels) for _ in range(rng.randint(1, 5)))
            base = rng.choice(bases)
            pattern = ("*." + base) if rng.random() < 0.5 else base
            self.assertEqual(
                host_matches(pattern, host),
                self._ref(pattern, host),
                msg=f"pattern={pattern!r} host={host!r}",
            )
            checked += 1
        self.assertEqual(checked, 4000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
