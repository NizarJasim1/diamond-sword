"""Spec-first T3 tests: har_model, session, mitmproxy/playwright backend transforms."""
import json
import os
import tempfile
import unittest
from types import SimpleNamespace

from diamond_sword.capture.backend_mitmproxy import entry_from_flow
from diamond_sword.capture.backend_playwright import entry_from_playwright
from diamond_sword.capture.har_model import HarEntry, HarLog, normalize_url
from diamond_sword.capture.session import SessionManager, is_session_expired


class TestHarModel(unittest.TestCase):
    def test_normalize_url(self):
        self.assertEqual(normalize_url("https://t.com/a/../b?z=2&a=1#frag"), "https://t.com/b?a=1&z=2")

    def test_entry_to_har(self):
        e = HarEntry("A", "post", "https://t.com/o?b=2&a=1", 201,
                     req_headers={"X": "1"}, req_body="{}", resp_body="<html>")
        h = e.to_har()
        self.assertEqual(h["request"]["method"], "POST")
        self.assertEqual(h["request"]["url"], "https://t.com/o?a=1&b=2")
        self.assertEqual(h["_principal"], "A")
        self.assertIn("postData", h["request"])
        self.assertEqual(h["response"]["status"], 201)

    def test_entry_without_body_has_no_postdata(self):
        self.assertNotIn("postData", HarEntry("A", "GET", "https://t.com/x", 200).to_har()["request"])

    def test_log_multiprincipal_and_roundtrip(self):
        log = HarLog()
        log.add(HarEntry("A", "GET", "https://t.com/x", 200))
        log.add(HarEntry("B", "GET", "https://t.com/x", 200))
        self.assertEqual(log.principals(), {"A", "B"})
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.har")
            log.write(p)
            with open(p, encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(doc["log"]["version"], "1.2")
            self.assertEqual(len(doc["log"]["entries"]), 2)
            self.assertEqual({e["_principal"] for e in doc["log"]["entries"]}, {"A", "B"})


class TestSession(unittest.TestCase):
    def test_is_session_expired(self):
        self.assertTrue(is_session_expired(401, "https://t.com/x"))
        self.assertTrue(is_session_expired(200, "https://t.com/users/sign-in"))
        self.assertFalse(is_session_expired(200, "https://t.com/dashboard"))

    def test_manager_flow(self):
        sm = SessionManager()
        self.assertTrue(sm.register("A", "state.json").authenticated)
        self.assertFalse(sm.need_human("A"))
        st = sm.check("A", 401, "https://t.com/login")
        self.assertFalse(st.authenticated)
        self.assertTrue(sm.need_human("A"))
        self.assertTrue(sm.check("A", 200, "https://t.com/app").authenticated)


class TestBackendTransforms(unittest.TestCase):
    def test_playwright(self):
        req = SimpleNamespace(method="GET", url="https://t.com/x", headers={"A": "1"}, post_data=None)
        resp = SimpleNamespace(status=200, headers={"B": "2"}, text="<html>")
        e = entry_from_playwright("A", req, resp)
        self.assertEqual((e.principal, e.method, e.status, e.resp_body), ("A", "GET", 200, "<html>"))

    def test_mitmproxy(self):
        flow = SimpleNamespace(
            request=SimpleNamespace(method="POST", url="https://t.com/o", headers={"A": "1"},
                                    get_text=lambda: "reqbody"),
            response=SimpleNamespace(status_code=201, headers={"B": "2"}, get_text=lambda: "respbody"))
        e = entry_from_flow("B", flow)
        self.assertEqual((e.principal, e.method, e.status), ("B", "POST", 201))
        self.assertEqual((e.req_body, e.resp_body), ("reqbody", "respbody"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
