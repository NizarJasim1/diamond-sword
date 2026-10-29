"""Spec-first tests for diamond_sword.legal.consent_gate (Tier T3).

Covers: ALLOW auto-proceeds, DENY never asks, CONSENT is fail-closed by default, the
approver is consulted only for CONSENT, dry-run propagation, whitelist auto-allow without
asking, and the GrantSink audit seam.
"""

import unittest

from diamond_sword.legal.consent_gate import (
    AutoApprover,
    ConsentGate,
    Grant,
    GrantReason,
    ListSink,
)
from diamond_sword.legal.roe import Action, Mode, Reason, RoePolicy


def req(method, url=None, **kw):
    return Action(kind="request", method=method, url=url, **kw)


class _CountingApprover:
    """Records how often it was asked, and answers a fixed value."""

    def __init__(self, answer):
        self.answer = answer
        self.calls = 0

    def approve(self, action, decision):
        self.calls += 1
        return self.answer


class TestAllowAndDeny(unittest.TestCase):
    def test_allow_proceeds_without_asking(self):  # REQ-CG-01
        appr = _CountingApprover(True)
        gate = ConsentGate(RoePolicy(), approver=appr)
        g = gate.authorize(req("GET", "https://x.com/users/1"))
        self.assertTrue(g.proceed)
        self.assertEqual(g.reason, Reason.ALLOW_READ_ONLY)
        self.assertEqual(appr.calls, 0)  # ALLOW never consults the approver

    def test_deny_never_asks(self):  # REQ-CG-02 — forbidden actions don't reach a human
        appr = _CountingApprover(True)
        gate = ConsentGate(RoePolicy(read_only=False), approver=appr)
        g = gate.authorize(req("DELETE", "https://x.com/orders/1"))
        self.assertFalse(g.proceed)
        self.assertEqual(g.reason, Reason.DENY_DESTRUCTIVE)
        self.assertEqual(appr.calls, 0)


class TestConsent(unittest.TestCase):
    def test_default_is_fail_closed(self):  # REQ-CG-03 — no human wired -> no mutation
        gate = ConsentGate(RoePolicy(read_only=False))  # default DenyingApprover
        g = gate.authorize(req("POST", "https://x.com/orders"))
        self.assertFalse(g.proceed)
        self.assertEqual(g.reason, GrantReason.CONSENT_DENIED)

    def test_consent_approved(self):  # REQ-CG-04
        gate = ConsentGate(RoePolicy(read_only=False), approver=AutoApprover(True))
        g = gate.authorize(req("POST", "https://x.com/orders"))
        self.assertTrue(g.proceed)
        self.assertEqual(g.reason, GrantReason.CONSENT_APPROVED)
        self.assertTrue(g.dry_run)  # dry-run default carried through

    def test_consent_declined(self):
        gate = ConsentGate(RoePolicy(read_only=False), approver=AutoApprover(False))
        g = gate.authorize(req("POST", "https://x.com/orders"))
        self.assertFalse(g.proceed)
        self.assertEqual(g.reason, GrantReason.CONSENT_DENIED)

    def test_dry_run_off_propagates(self):
        gate = ConsentGate(RoePolicy(read_only=False, dry_run_default=False), approver=AutoApprover(True))
        g = gate.authorize(req("PATCH", "https://x.com/a/1"))
        self.assertTrue(g.proceed)
        self.assertFalse(g.dry_run)

    def test_whitelist_auto_allows_without_asking(self):  # REQ-CG-05
        appr = _CountingApprover(True)
        pol = RoePolicy(read_only=True, allow_mutations=("/orders",), auto_allow_whitelisted=True)
        gate = ConsentGate(pol, approver=appr)
        g = gate.authorize(req("POST", "https://x.com/orders"))
        self.assertTrue(g.proceed)
        self.assertEqual(g.mode, Mode.ALLOW)
        self.assertEqual(appr.calls, 0)


class TestSinkAndTruthiness(unittest.TestCase):
    def test_sink_records_every_grant(self):  # REQ-CG-06 — audit seam
        sink = ListSink()
        gate = ConsentGate(RoePolicy(read_only=False), approver=AutoApprover(True), sink=sink)
        gate.authorize(req("GET", "https://x.com/a"))        # ALLOW
        gate.authorize(req("DELETE", "https://x.com/a/1"))   # DENY
        gate.authorize(req("POST", "https://x.com/orders"))  # CONSENT approved
        self.assertEqual(len(sink.grants), 3)
        self.assertEqual([g.proceed for g in sink.grants], [True, False, True])
        for g in sink.grants:
            self.assertIsInstance(g, Grant)

    def test_grant_is_truthy_by_proceed(self):
        gate = ConsentGate(RoePolicy())
        self.assertTrue(bool(gate.authorize(req("GET", "https://x.com/a"))))
        gate2 = ConsentGate(RoePolicy(read_only=False))
        self.assertFalse(bool(gate2.authorize(req("DELETE", "https://x.com/a/1"))))


if __name__ == "__main__":
    unittest.main(verbosity=2)
