"""Spec-first tests for diamond_sword.legal.roe (Tier T3).

Covers: the read/consent/deny verdict for every method and mode, destructive-action
detection (incl. the token-vs-substring trap), method allowlist, whitelist override,
time window, engagement parsing, and an exhaustive differential over the decision matrix.
"""

import itertools
import unittest

from diamond_sword.legal.roe import (
    Action,
    Mode,
    Reason,
    RoeError,
    RoePolicy,
    evaluate,
    from_engagement,
)


def req(method, url=None, **kw):
    return Action(kind="request", method=method, url=url, **kw)


class TestReadOnlyAndMutations(unittest.TestCase):
    def test_safe_methods_allowed(self):  # REQ-RO-02
        for m in ("GET", "HEAD", "OPTIONS", "get"):
            d = evaluate(RoePolicy(), req(m, "https://x.com/users/1"))
            self.assertEqual((d.mode, d.reason), (Mode.ALLOW, Reason.ALLOW_READ_ONLY))

    def test_read_only_mode_blocks_mutations(self):  # REQ-RO-03
        d = evaluate(RoePolicy(read_only=True), req("POST", "https://x.com/orders"))
        self.assertEqual((d.mode, d.reason), (Mode.DENY, Reason.DENY_READ_ONLY_MODE))

    def test_mutation_needs_consent_when_not_read_only(self):  # REQ-RO-04
        d = evaluate(RoePolicy(read_only=False), req("POST", "https://x.com/orders"))
        self.assertEqual((d.mode, d.reason), (Mode.CONSENT, Reason.CONSENT_MUTATION))
        self.assertTrue(d.dry_run)  # dry-run default on

    def test_dry_run_default_off(self):
        d = evaluate(RoePolicy(read_only=False, dry_run_default=False), req("PUT", "https://x.com/a/1"))
        self.assertEqual(d.mode, Mode.CONSENT)
        self.assertFalse(d.dry_run)


class TestDestructive(unittest.TestCase):
    def test_delete_method_is_destructive(self):  # REQ-RO-05 (hard red line)
        for ro in (True, False):
            d = evaluate(RoePolicy(read_only=ro), req("DELETE", "https://x.com/orders/1"))
            self.assertEqual((d.mode, d.reason), (Mode.DENY, Reason.DENY_DESTRUCTIVE))

    def test_destructive_tokens_in_url_or_label(self):
        bad = [
            req("POST", "https://x.com/account/logout"),
            req("POST", "https://x.com/users/1/password"),
            req("POST", "https://x.com/wallet/withdraw"),
            req("POST", "https://x.com/payments/transfer"),
            req("POST", "https://x.com/settings/disable-2fa"),
            Action(kind="ui", label="click: Delete account", mutating=True),
        ]
        for a in bad:
            d = evaluate(RoePolicy(read_only=False), a)
            self.assertEqual(d.reason, Reason.DENY_DESTRUCTIVE, a)

    def test_token_match_not_substring(self):  # /pay caught, /paypal and /display safe
        d_pay = evaluate(RoePolicy(read_only=False), req("POST", "https://x.com/pay"))
        self.assertEqual(d_pay.reason, Reason.DENY_DESTRUCTIVE)
        for safe_url in ("https://x.com/paypal/link", "https://x.com/display/order"):
            d = evaluate(RoePolicy(read_only=False), req("POST", safe_url))
            self.assertEqual(d.reason, Reason.CONSENT_MUTATION, safe_url)

    def test_get_to_scary_url_is_read_only(self):  # reading a delete page is not destructive
        d = evaluate(RoePolicy(), req("GET", "https://x.com/account/delete"))
        self.assertEqual(d.reason, Reason.ALLOW_READ_ONLY)

    def test_extra_destructive_patterns(self):
        pol = RoePolicy(read_only=False, extra_destructive=("promote-admin",))
        d = evaluate(pol, req("POST", "https://x.com/users/1/promote-admin"))
        self.assertEqual(d.reason, Reason.DENY_DESTRUCTIVE)


class TestGatesAndWhitelist(unittest.TestCase):
    def test_automation_forbidden_blocks_everything(self):  # REQ-RO-01
        d = evaluate(RoePolicy(automation_permitted=False), req("GET", "https://x.com/"))
        self.assertEqual((d.mode, d.reason), (Mode.DENY, Reason.DENY_AUTOMATION_FORBIDDEN))

    def test_method_allowlist(self):  # REQ-RO-06
        pol = RoePolicy(read_only=False, allow_methods=frozenset({"GET", "POST"}))
        self.assertEqual(evaluate(pol, req("PUT", "https://x.com/a")).reason, Reason.DENY_METHOD_NOT_ALLOWED)
        self.assertEqual(evaluate(pol, req("GET", "https://x.com/a")).reason, Reason.ALLOW_READ_ONLY)

    def test_whitelist_consent_then_auto(self):  # REQ-RO-07 (override read-only narrowly)
        base = dict(read_only=True, allow_mutations=("/orders",))
        d1 = evaluate(RoePolicy(**base), req("POST", "https://x.com/orders"))
        self.assertEqual(d1.reason, Reason.CONSENT_MUTATION)  # whitelisted but still asks
        d2 = evaluate(RoePolicy(**base, auto_allow_whitelisted=True), req("POST", "https://x.com/orders"))
        self.assertEqual((d2.mode, d2.reason), (Mode.ALLOW, Reason.ALLOW_WHITELISTED))

    def test_time_window(self):
        pol = RoePolicy(time_window=(9, 17))
        self.assertEqual(evaluate(pol, req("GET", "https://x.com/"), now_hour=3).reason,
                         Reason.DENY_OUTSIDE_WINDOW)
        self.assertEqual(evaluate(pol, req("GET", "https://x.com/"), now_hour=10).reason,
                         Reason.ALLOW_READ_ONLY)

    def test_overnight_window(self):
        pol = RoePolicy(time_window=(22, 6))
        self.assertEqual(evaluate(pol, req("GET", "https://x.com/"), now_hour=23).reason,
                         Reason.ALLOW_READ_ONLY)
        self.assertEqual(evaluate(pol, req("GET", "https://x.com/"), now_hour=12).reason,
                         Reason.DENY_OUTSIDE_WINDOW)


class TestFromEngagement(unittest.TestCase):
    def test_defaults_are_strict(self):  # REQ-RO-08
        pol = from_engagement(None)
        self.assertTrue(pol.read_only)
        self.assertTrue(pol.automation_permitted)
        self.assertTrue(pol.dry_run_default)

    def test_parse_full(self):
        pol = from_engagement({
            "read_only": False, "automation_permitted": True,
            "allow_methods": ["get", "post"], "allow_mutations": ["/orders"],
            "auto_allow_whitelisted": True, "dry_run_default": False,
            "time_window": [9, 17], "max_rps": 2, "extra_destructive": ["promote-admin"],
        })
        self.assertEqual(pol.allow_methods, frozenset({"GET", "POST"}))
        self.assertEqual(pol.time_window, (9, 17))
        self.assertEqual(pol.max_rps, 2.0)
        self.assertIn("promote-admin", pol.extra_destructive)

    def test_malformed_raises(self):  # REQ-RO-08 strict types
        for bad in (
            {"read_only": "yes"},
            {"allow_methods": "GET"},
            {"allow_mutations": [1]},
            {"time_window": [9]},
            {"time_window": [9, 30]},
            {"max_rps": "fast"},
            [],
        ):
            with self.assertRaises(RoeError):
                from_engagement(bad)


class TestDecisionMatrixDifferential(unittest.TestCase):
    """evaluate() must agree with an independent decision table over the full matrix."""

    @staticmethod
    def _ref(method, read_only, automation, destructive_url):
        # Independent re-derivation of the policy, written from the spec not the code.
        if not automation:
            return Mode.DENY, Reason.DENY_AUTOMATION_FORBIDDEN
        is_mut = method in ("POST", "PUT", "PATCH", "DELETE")
        if not is_mut:
            return Mode.ALLOW, Reason.ALLOW_READ_ONLY
        if method == "DELETE" or destructive_url:
            return Mode.DENY, Reason.DENY_DESTRUCTIVE
        if read_only:
            return Mode.DENY, Reason.DENY_READ_ONLY_MODE
        return Mode.CONSENT, Reason.CONSENT_MUTATION

    def test_full_matrix(self):  # NFR-RO-02 determinism + correctness
        methods = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
        checked = 0
        for method, read_only, automation, destructive in itertools.product(
            methods, [True, False], [True, False], [True, False]
        ):
            url = "https://x.com/account/logout" if destructive else "https://x.com/orders"
            pol = RoePolicy(read_only=read_only, automation_permitted=automation)
            d = evaluate(pol, req(method, url))
            self.assertEqual((d.mode, d.reason), self._ref(method, read_only, automation, destructive),
                             msg=f"m={method} ro={read_only} auto={automation} destr={destructive}")
            checked += 1
        self.assertEqual(checked, 7 * 2 * 2 * 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
