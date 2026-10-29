"""Tests for diamond_sword.legal.audit_ledger (Tier T3).

Covers: a good chain verifies; payload tampering, link tampering and reordering are detected;
a crash-truncated tail is tolerated; the chain resumes across restarts; and the ledger plugs
into the ALREADY-BUILT scope_guard and consent_gate via their sinks.
"""

import json
import os
import tempfile
import unittest

from diamond_sword.legal.audit_ledger import AuditLedger, verify
from diamond_sword.legal.consent_gate import AutoApprover, ConsentGate
from diamond_sword.legal.roe import Action, RoePolicy
from diamond_sword.legal.scope_guard import ScopeGuard
from diamond_sword.legal.scope_parser import load_engagement

ZERO = lambda: 0.0  # noqa: E731 - deterministic clock for tests


def _lines(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(x) for x in fh if x.strip()]


def _rewrite(path, records):
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")


class _D:  # a minimal duck-typed decision
    def __init__(self, allowed, reason, url, host=None, matched=None):
        self.allowed, self.reason, self.url, self.host, self.matched = allowed, reason, url, host, matched


class TestChainIntegrity(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "audit.jsonl")

    def tearDown(self):
        self._tmp.cleanup()

    def test_good_chain_verifies(self):  # REQ-AL-01
        led = AuditLedger(self.path, clock=ZERO)
        led.log_scope(_D(True, "ALLOW_IN_SCOPE", "https://api.x.com/a"))
        led.log_scope(_D(False, "DENY_NOT_IN_SCOPE", "https://evil.com/b", host="evil.com"))
        res = verify(self.path)
        self.assertTrue(res.ok)
        self.assertEqual(res.count, 2)
        self.assertFalse(res.trailing_incomplete)

    def test_payload_tamper_detected(self):  # REQ-AL-02 — the core guarantee
        led = AuditLedger(self.path, clock=ZERO)
        led.log_scope(_D(False, "DENY_NOT_IN_SCOPE", "https://evil.com/b", host="evil.com"))
        led.log_scope(_D(True, "ALLOW_IN_SCOPE", "https://api.x.com/a"))
        recs = _lines(self.path)
        recs[0]["payload"]["allowed"] = True   # flip a deny into an allow after the fact
        _rewrite(self.path, recs)
        res = verify(self.path)
        self.assertFalse(res.ok)
        self.assertEqual(res.reason, "HASH_MISMATCH")
        self.assertEqual(res.broken_at, 0)

    def test_link_tamper_detected(self):  # REQ-AL-02
        led = AuditLedger(self.path, clock=ZERO)
        led.log_scope(_D(True, "ALLOW_IN_SCOPE", "https://api.x.com/a"))
        led.log_scope(_D(True, "ALLOW_IN_SCOPE", "https://api.x.com/c"))
        recs = _lines(self.path)
        recs[1]["prev"] = "f" * 64  # break the link to the previous entry
        _rewrite(self.path, recs)
        res = verify(self.path)
        self.assertFalse(res.ok)
        self.assertEqual(res.reason, "BROKEN_LINK")

    def test_reorder_detected(self):
        led = AuditLedger(self.path, clock=ZERO)
        led.log_scope(_D(True, "ALLOW_IN_SCOPE", "https://api.x.com/a"))
        led.log_scope(_D(True, "ALLOW_IN_SCOPE", "https://api.x.com/c"))
        recs = _lines(self.path)
        _rewrite(self.path, [recs[1], recs[0]])  # swap order
        self.assertFalse(verify(self.path).ok)

    def test_truncated_tail_tolerated(self):  # REQ-AL-03
        led = AuditLedger(self.path, clock=ZERO)
        led.log_scope(_D(True, "ALLOW_IN_SCOPE", "https://api.x.com/a"))
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write('{"seq":1,"ts":0,"kind":"scope","pay')  # crash mid-write
        res = verify(self.path)
        self.assertTrue(res.ok)                 # the intact prefix is still valid
        self.assertTrue(res.trailing_incomplete)
        self.assertEqual(res.count, 1)

    def test_resume_continues_chain(self):  # REQ-AL-04
        led = AuditLedger(self.path, clock=ZERO)
        led.log_scope(_D(True, "ALLOW_IN_SCOPE", "https://api.x.com/a"))
        led2 = AuditLedger(self.path, clock=ZERO)  # reopen
        led2.log_scope(_D(True, "ALLOW_IN_SCOPE", "https://api.x.com/c"))
        res = verify(self.path)
        self.assertTrue(res.ok)
        self.assertEqual(res.count, 2)
        recs = _lines(self.path)
        self.assertEqual(recs[1]["prev"], recs[0]["hash"])  # chained across restart


class TestIntegrationWithCores(unittest.TestCase):
    """The ledger records the ALREADY-BUILT scope guard and consent gate via their sinks."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "audit.jsonl")

    def tearDown(self):
        self._tmp.cleanup()

    def test_scope_and_consent_feed_one_chain(self):  # REQ-AL-05
        led = AuditLedger(self.path, clock=ZERO)
        guard = ScopeGuard(load_engagement({"scope": {"in": ["api.x.com"]}}), sink=led.decision_sink)
        gate = ConsentGate(RoePolicy(read_only=False), approver=AutoApprover(True), sink=led.grant_sink)

        guard.check("https://api.x.com/users/1")     # allow (scope entry)
        guard.check("https://evil.com/x")            # deny (scope entry)
        gate.authorize(Action("request", "POST", "https://api.x.com/orders"))  # consent (action entry)

        res = verify(self.path)
        self.assertTrue(res.ok)
        self.assertEqual(res.count, 3)
        kinds = [r["kind"] for r in _lines(self.path)]
        self.assertEqual(kinds, ["scope", "scope", "action"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
