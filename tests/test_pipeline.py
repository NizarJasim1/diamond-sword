"""Spec-first T3 tests: object_factory (guarded), bridges, report, conductor e2e, cli smoke."""
import contextlib
import io
import os
import tempfile
import unittest
from types import SimpleNamespace
from urllib.parse import urlsplit

from diamond_sword.cli import main
from diamond_sword.coverage.crawler import Crawler, FetchResult
from diamond_sword.coverage.object_factory import CreateSpec, ObjectFactory, detect_id_pattern
from diamond_sword.coverage.principal_manager import PrincipalManager
from diamond_sword.heal.pacer import Pacer  # noqa: F401 (import-stability check)
from diamond_sword.legal.audit_ledger import AuditLedger
from diamond_sword.legal.consent_gate import AutoApprover, ConsentGate
from diamond_sword.legal.roe import RoePolicy
from diamond_sword.legal.scope_guard import ScopeGuard
from diamond_sword.legal.scope_parser import load_engagement
from diamond_sword.heal.coverage_ledger import CoverageLedger
from diamond_sword.pipeline.conductor import Conductor
from diamond_sword.pipeline.iolite_bridge import IoliteBridge
from diamond_sword.pipeline.onyx_bridge import OnyxBridge
from diamond_sword.pipeline.report import build_report, to_markdown

BASE = "https://t.com"
IN_SCOPE = lambda u: urlsplit(u).netloc == "t.com"


def _grant(proceed, dry_run, reason="x"):
    return SimpleNamespace(proceed=proceed, dry_run=dry_run, reason=reason)


class TestObjectFactory(unittest.TestCase):
    def test_id_patterns(self):
        self.assertEqual(detect_id_pattern("1042"), "sequential")
        self.assertEqual(detect_id_pattern("550e8400-e29b-41d4-a716-446655440000"), "uuid")
        self.assertEqual(detect_id_pattern("gid://gitlab/Issue/7"), "gid")
        self.assertEqual(detect_id_pattern("Xy9Zq2Lm8Kp4Rt6Vw"), "opaque")
        self.assertEqual(detect_id_pattern(None), "unknown")

    def test_out_of_scope_blocked(self):
        f = ObjectFactory(IN_SCOPE, lambda a: _grant(True, False), lambda s: "1")
        c = f.create(CreateSpec("A", "https://evil.com/o", "/o", {}))
        self.assertEqual((c.proceeded, c.reason), (False, "OUT_OF_SCOPE"))

    def test_consent_deny_blocks(self):  # real ROE+consent: read-only policy denies mutation
        gate = ConsentGate(RoePolicy(read_only=True), AutoApprover(True))
        f = ObjectFactory(IN_SCOPE, gate.authorize, lambda s: "1")
        c = f.create(CreateSpec("A", BASE + "/orders", "/orders", {}))
        self.assertFalse(c.proceeded)

    def test_dry_run_plans_only(self):  # real consent approves but dry-run -> no creation
        gate = ConsentGate(RoePolicy(read_only=False, dry_run_default=True), AutoApprover(True))
        f = ObjectFactory(IN_SCOPE, gate.authorize, lambda s: self.fail("must not create in dry-run"))
        c = f.create(CreateSpec("A", BASE + "/orders", "/orders", {}))
        self.assertEqual((c.proceeded, c.dry_run, c.object_id), (True, True, None))

    def test_created_records_id_pattern(self):  # stub grant to exercise real creation path
        f = ObjectFactory(IN_SCOPE, lambda a: _grant(True, False), lambda s: "1042")
        c = f.create(CreateSpec("A", BASE + "/orders", "/orders", {}))
        self.assertEqual((c.proceeded, c.reason, c.id_pattern), (True, "CREATED", "sequential"))


class TestBridgesAndReport(unittest.TestCase):
    def test_bridges_validate(self):
        self.assertEqual(IoliteBridge(lambda h: {"endpoints": []}).build_spec(()), {"endpoints": []})
        with self.assertRaises(ValueError):
            IoliteBridge(lambda h: None).build_spec(())
        self.assertEqual(OnyxBridge(lambda s: []).scan({}), [])
        with self.assertRaises(ValueError):
            OnyxBridge(lambda s: None).scan({})

    def test_report_scope_proof_and_repro(self):
        eng = load_engagement({"program": "t", "scope": {"in": ["t.com"]}})
        prove = lambda u: ScopeGuard(eng).check(u).matched
        rep = build_report([{"id": "f1", "type": "BOLA", "endpoint": BASE + "/orders/1",
                             "principal_a": "A", "principal_b": "B", "delta": {"x": 1}}],
                           "t", prove)
        self.assertEqual(rep["count"], 1)
        self.assertIsNotNone(rep["findings"][0]["scope_proof"])
        self.assertTrue(rep["findings"][0]["repro"])      # auto repro when none supplied
        self.assertIn("BOLA", to_markdown(rep))


def _site(principal):
    return {BASE + "/": '<body><a href="/orders/1">o</a></body>',
            BASE + "/orders/1": "<body><main><p>o</p></main></body>"}


def _fetch(principal):
    pages = _site(principal)
    return lambda u: FetchResult(200, pages.get(u, ""), u) if pages.get(u) is not None else FetchResult(404, "", u)


class TestConductorE2E(unittest.TestCase):
    def test_full_dry_run_pipeline(self):
        with tempfile.TemporaryDirectory() as d:
            led = CoverageLedger(os.path.join(d, "cov.jsonl"))
            pm = PrincipalManager(["A", "anon"], lambda p: Crawler(_fetch(p), IN_SCOPE), ledger=led)
            eng = load_engagement({"program": "t", "scope": {"in": ["t.com"]}})
            prove = lambda u: ScopeGuard(eng).check(u).matched
            iolite = IoliteBridge(lambda har: {"endpoints": [{"url": BASE + "/orders/1"}]})
            onyx = OnyxBridge(lambda spec: [{"id": "f1", "type": "BOLA", "endpoint": BASE + "/orders/1",
                                             "principal_a": "A", "principal_b": "anon", "delta": {"d": 1}}])
            cond = Conductor("t", pm, iolite, onyx, scope_prove=prove, ledger=led)
            res = cond.run(start=BASE + "/", har_paths=("a.har", "anon.har"))
            self.assertEqual(res.stages, ("MAP", "CRAWL", "IOLITE", "ONYX", "REPORT", "DONE"))
            self.assertEqual(res.report["count"], 1)
            self.assertIn("GET /orders/{num}", res.templates)
            self.assertIsNotNone(res.report["findings"][0]["scope_proof"])
            # checkpoints were written to the ledger (resumable)
            labels = {c.get("label") for c in led.state().checkpoints}
            self.assertEqual(labels, {"MAP", "CRAWL", "IOLITE", "ONYX", "REPORT", "DONE"})


class TestCLI(unittest.TestCase):
    def test_init_verify_report(self):
        with tempfile.TemporaryDirectory() as d:
            eng_path = os.path.join(d, "e.json")
            with open(eng_path, "w", encoding="utf-8") as fh:
                fh.write('{"program":"t","scope":{"in":["t.com"]}}')
            self.assertEqual(main(["init", eng_path]), 0)

            audit_path = os.path.join(d, "a.jsonl")
            led = AuditLedger(audit_path, clock=lambda: 0.0)
            led.log_scope(SimpleNamespace(allowed=True, reason="ALLOW_IN_SCOPE",
                                          url="https://t.com/x", host="t.com", matched="t.com"))
            self.assertEqual(main(["verify", audit_path]), 0)

            findings_path = os.path.join(d, "f.json")
            with open(findings_path, "w", encoding="utf-8") as fh:
                fh.write('[{"id":"f1","type":"BOLA","endpoint":"https://t.com/o/1"}]')
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main(["report", findings_path, "--program", "t"]), 0)
            self.assertIn("BOLA", out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
