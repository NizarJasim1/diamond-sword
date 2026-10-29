"""Spec-first T3 tests for the v1.1 external-boundary fixes.

Seam: Diamond Sword <-> the outside world (IOLITE, ONYX, live browser) and the data contracts
between them. Covers the fail-loud ONYX finding contract, the real runners, the faithful HAR,
GraphQL seed acquisition, and the full run_pipe entry point (with injected fakes).
"""
import json
import os
import tempfile
import unittest
from types import SimpleNamespace

from diamond_sword.capture.har_model import HarEntry
from diamond_sword.coverage.crawler import FetchResult
from diamond_sword.coverage.map_first import MapFirst
from diamond_sword.heal.coverage_ledger import CoverageLedger, rebuild
from diamond_sword.legal.scope_parser import load_engagement
from diamond_sword.pipeline.finding import (
    Finding, FindingSchemaError, normalize_finding, normalize_findings,
)
from diamond_sword.pipeline.onyx_bridge import OnyxBridge
from diamond_sword.pipeline.report import build_report
from diamond_sword.pipeline.run import run_pipe
from diamond_sword.pipeline.runners import RunnerError, iolite_runner, onyx_runner
from diamond_sword.cli import _import_onyx_link, _parse_principals, main

FULL = {"id": "f1", "type": "BOLA", "endpoint": "https://t.com/orders/1",
        "principal_a": "A", "principal_b": "B", "delta": {"x": 1}}


# -- the ONYX finding contract (fail-loud) ----------------------------------------------

class TestFindingContract(unittest.TestCase):
    def test_valid_full_finding(self):
        f = normalize_finding(FULL)
        self.assertIsInstance(f, Finding)
        self.assertEqual((f.type, f.endpoint, f.principal_a, f.principal_b), ("BOLA", "https://t.com/orders/1", "A", "B"))
        self.assertEqual(f.delta, {"x": 1})

    def test_aliases_resolve(self):
        raw = {"kind": "IDOR", "url": "https://t.com/u/9", "principals": ["a", "b"], "evidence": {"d": 2}}
        f = normalize_finding(raw)
        self.assertEqual((f.type, f.endpoint, f.principal_a, f.principal_b, f.delta),
                         ("IDOR", "https://t.com/u/9", "a", "b", {"d": 2}))

    def test_missing_substance_fails_loud_naming_field(self):
        no_delta = {k: v for k, v in FULL.items() if k != "delta"}
        with self.assertRaises(FindingSchemaError) as cm:
            normalize_finding(no_delta)
        self.assertIn("delta", str(cm.exception))
        with self.assertRaises(FindingSchemaError):
            normalize_finding({k: v for k, v in FULL.items() if k != "principal_b"})
        with self.assertRaises(FindingSchemaError):
            normalize_finding({k: v for k, v in FULL.items() if k != "endpoint"})

    def test_non_dict_fails(self):
        with self.assertRaises(FindingSchemaError):
            normalize_finding(["not", "a", "dict"])

    def test_scope_prove_stamps_proof(self):
        f = normalize_finding(FULL, scope_prove=lambda u: "t.com" if u else None)
        self.assertEqual(f.scope_proof, "t.com")

    def test_default_repro_generated_else_kept(self):
        self.assertTrue(normalize_finding(FULL).repro)
        f = normalize_finding({**FULL, "repro": ["step one"]})
        self.assertEqual(f.repro, ("step one",))

    def test_normalize_findings_shapes(self):
        self.assertEqual(len(normalize_findings([FULL, FULL])), 2)
        self.assertEqual(len(normalize_findings({"findings": [FULL]})), 1)
        with self.assertRaises(FindingSchemaError):
            normalize_findings("nope")


# -- the real runners (injected process / module) ---------------------------------------

def _run_writes_spec(spec_path, content, rc=0, stderr=""):
    def run(cmd, **kw):
        if rc == 0:
            with open(spec_path, "w", encoding="utf-8") as fh:
                json.dump(content, fh)
        return SimpleNamespace(returncode=rc, stdout="", stderr=stderr)
    return run


class TestRunners(unittest.TestCase):
    def test_iolite_runner_ok(self):
        with tempfile.TemporaryDirectory() as d:
            sp = os.path.join(d, "spec.json")
            run = _run_writes_spec(sp, {"endpoints": [1, 2]})
            spec = iolite_runner(spec_path=sp, run=run)(("a.har", "b.har"))
            self.assertEqual(spec, {"endpoints": [1, 2]})

    def test_iolite_runner_nonzero_exit_fails_loud(self):
        with tempfile.TemporaryDirectory() as d:
            sp = os.path.join(d, "spec.json")
            run = _run_writes_spec(sp, {}, rc=2, stderr="boom")
            with self.assertRaises(RunnerError) as cm:
                iolite_runner(spec_path=sp, run=run)(("a.har",))
            self.assertIn("boom", str(cm.exception))

    def test_iolite_runner_missing_spec_fails(self):
        with tempfile.TemporaryDirectory() as d:
            sp = os.path.join(d, "nope.json")
            run = lambda cmd, **kw: SimpleNamespace(returncode=0, stdout="", stderr="")
            with self.assertRaises(RunnerError):
                iolite_runner(spec_path=sp, run=run)(("a.har",))

    def test_iolite_runner_empty_har_fails(self):
        with self.assertRaises(RunnerError):
            iolite_runner(run=lambda *a, **k: None)(())

    def test_onyx_runner_ok_and_verify_called(self):
        seen = []
        mod = SimpleNamespace(verify_spec=lambda s: seen.append(s), scan=lambda s: [FULL])
        out = onyx_runner(mod)({"endpoints": []})
        self.assertEqual(out, [FULL])
        self.assertEqual(len(seen), 1)

    def test_onyx_runner_requires_scan(self):
        with self.assertRaises(RunnerError):
            onyx_runner(SimpleNamespace(verify_spec=lambda s: None))

    def test_onyx_runner_rejects_nonlist(self):
        with self.assertRaises(RunnerError):
            onyx_runner(SimpleNamespace(scan=lambda s: {"not": "list"}))({})


# -- bridge typed scan + report over typed findings -------------------------------------

class TestBridgeAndReport(unittest.TestCase):
    def test_scan_typed_validates(self):
        typed = OnyxBridge(lambda s: [FULL]).scan_typed({})
        self.assertEqual(typed[0].type, "BOLA")
        with self.assertRaises(FindingSchemaError):
            OnyxBridge(lambda s: [{"type": "BOLA", "endpoint": "https://t.com/x"}]).scan_typed({})

    def test_build_report_from_typed(self):
        f = normalize_finding(FULL, scope_prove=lambda u: "t.com")
        rep = build_report([f], "t")
        self.assertEqual(rep["count"], 1)
        self.assertEqual(rep["findings"][0]["scope_proof"], "t.com")
        self.assertEqual(rep["findings"][0]["principals"], ["A", "B"])
        self.assertTrue(rep["findings"][0]["repro"])


# -- faithful HAR -----------------------------------------------------------------------

class TestFaithfulHar(unittest.TestCase):
    def test_form_body_not_mislabeled_json(self):
        # json-looking body but a form header: the real header must win over body inference.
        e = HarEntry("A", "POST", "https://t.com/x", 200,
                     req_headers={"Content-Type": "application/x-www-form-urlencoded"}, req_body='{"a":1}')
        self.assertEqual(e.to_har()["request"]["postData"]["mimeType"], "application/x-www-form-urlencoded")

    def test_json_body_inferred_when_no_header(self):
        e = HarEntry("A", "POST", "https://t.com/x", 200, req_body='{"a":1}')
        self.assertEqual(e.to_har()["request"]["postData"]["mimeType"], "application/json")

    def test_query_string_populated(self):
        qs = HarEntry("A", "GET", "https://t.com/x?a=1&b=2", 200).to_har()["request"]["queryString"]
        self.assertEqual({(q["name"], q["value"]) for q in qs}, {("a", "1"), ("b", "2")})

    def test_response_mime_from_header(self):
        e = HarEntry("A", "GET", "https://t.com/x", 200,
                     resp_headers={"Content-Type": "application/json; charset=utf-8"}, resp_body="{}")
        self.assertEqual(e.to_har()["response"]["content"]["mimeType"], "application/json")


# -- GraphQL seed acquisition (giants) --------------------------------------------------

class TestGraphqlSeeds(unittest.TestCase):
    def test_add_graphql_builds_field_seeds(self):
        introspection = {"data": {"__schema": {
            "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
            "types": [
                {"name": "Query", "fields": [{"name": "project"}, {"name": "user"}]},
                {"name": "Mutation", "fields": [{"name": "deleteProject"}]},
            ]}}}
        mf = MapFirst()
        q, m = mf.add_graphql(introspection, endpoint="/api/graphql")
        self.assertEqual(q, frozenset({"project", "user"}))
        self.assertEqual(m, frozenset({"deleteProject"}))
        refs = {s.ref for s in mf.seeds()}
        self.assertIn("/api/graphql", refs)
        self.assertIn("/api/graphql#query.project", refs)
        self.assertIn("/api/graphql#mutation.deleteProject", refs)


# -- the full pipeline entry point ------------------------------------------------------

SITE = {
    "https://t.com/": '<a href="/orders/1">1</a><a href="/orders/2">2</a>',
    "https://t.com/orders/1": "<div>order 1</div>",
    "https://t.com/orders/2": "<div>order 2</div>",
}


def _fake_make_fetch(principal, guard, har):
    def fetch(url):
        html = SITE.get(url)
        if html is None:
            return None
        har.add(HarEntry(principal, "GET", url, 200, resp_body=html))
        return FetchResult(200, html, url)
    return fetch


def _eng():
    return load_engagement({"program": "t", "platform": "h", "scope": {"in": ["t.com"]}})


class TestRunPipe(unittest.TestCase):
    def test_full_run_judges_and_writes_har(self):
        with tempfile.TemporaryDirectory() as d:
            cov = os.path.join(d, "cov.jsonl")
            iolite = lambda hars: {"endpoints": [{"url": "https://t.com/orders/1"}], "hars": list(hars)}
            onyx = lambda spec: [{"id": "f1", "type": "BOLA", "endpoint": "https://t.com/orders/1",
                                  "principal_a": "A", "principal_b": "anon", "delta": {"d": 1}}]
            res = run_pipe(_eng(), ["A", "anon"], _fake_make_fetch, start="https://t.com/",
                           iolite_run=iolite, onyx_run=onyx, coverage_path=cov, har_dir=d)
            self.assertTrue(res.judged)
            self.assertEqual(len(res.findings), 1)
            self.assertEqual(res.findings[0].type, "BOLA")
            self.assertEqual(res.report["count"], 1)
            self.assertIsNotNone(res.report["findings"][0]["scope_proof"])
            self.assertTrue(os.path.exists(os.path.join(d, "capture.A.har")))
            self.assertTrue(os.path.exists(os.path.join(d, "capture.anon.har")))
            state = rebuild(cov)
            self.assertEqual(state.principals, {"A", "anon"})
            self.assertTrue(state.visited)

    def test_without_runners_still_writes_har(self):
        with tempfile.TemporaryDirectory() as d:
            res = run_pipe(_eng(), ["A"], _fake_make_fetch, start="https://t.com/", har_dir=d)
            self.assertFalse(res.judged)
            self.assertEqual(res.findings, ())
            self.assertTrue(os.path.exists(os.path.join(d, "capture.A.har")))

    def test_one_runner_only_does_not_judge(self):
        # Guards the "judge only with BOTH runners" invariant (an inverted guard would crash here).
        with tempfile.TemporaryDirectory() as d:
            res = run_pipe(_eng(), ["A"], _fake_make_fetch, start="https://t.com/",
                           iolite_run=lambda hars: {"x": 1}, onyx_run=None, har_dir=d)
            self.assertFalse(res.judged)

    def test_bad_onyx_output_fails_loud_through_pipe(self):
        # scan_typed must validate inside the pipe (a raw .scan would let this through silently).
        with tempfile.TemporaryDirectory() as d:
            iolite = lambda hars: {"endpoints": []}
            onyx = lambda spec: [{"type": "BOLA", "endpoint": "https://t.com/x"}]  # missing principals/delta
            with self.assertRaises(FindingSchemaError):
                run_pipe(_eng(), ["A"], _fake_make_fetch, start="https://t.com/",
                         iolite_run=iolite, onyx_run=onyx, har_dir=d)

    def test_resume_seeds_pending(self):
        with tempfile.TemporaryDirectory() as d:
            res = run_pipe(_eng(), ["A"], _fake_make_fetch, seeds=["https://t.com/orders/1"], har_dir=d)
            self.assertTrue(os.path.exists(os.path.join(d, "capture.A.har")))
            self.assertTrue(res.principals["A"].pages)


# -- cli wiring (offline) ---------------------------------------------------------------

class TestCliWiring(unittest.TestCase):
    def test_parse_principals_default_and_file(self):
        self.assertEqual(_parse_principals(None), (["anon"], {}))
        with tempfile.TemporaryDirectory() as d:
            hp = os.path.join(d, "h.json")
            with open(hp, "w", encoding="utf-8") as fh:
                json.dump({"Cookie": "x=1"}, fh)
            names, headers = _parse_principals([f"A={hp}", "anon"])
            self.assertEqual(names, ["A", "anon"])
            self.assertEqual(headers["A"], {"Cookie": "x=1"})

    def test_import_onyx_link_then_runner(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "onyx_link.py")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("def verify_spec(s):\n    return True\n\ndef scan(s):\n    return []\n")
            run = onyx_runner(_import_onyx_link(p))
            self.assertEqual(run({"endpoints": []}), [])

    def test_resume_command_reports_state(self):
        with tempfile.TemporaryDirectory() as d:
            cov = os.path.join(d, "cov.jsonl")
            led = CoverageLedger(cov)
            led.add_frontier("https://t.com/a")
            led.add_frontier("https://t.com/b")
            led.mark_visited("fp1", "https://t.com/a")
            self.assertEqual(main(["resume", "--coverage", cov, "--show", "5"]), 0)


if __name__ == "__main__":
    unittest.main()
