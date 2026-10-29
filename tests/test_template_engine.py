"""Spec-first tests for diamond_sword.coverage.template_engine (Tier T3).

Covers segment classification (golden cases + a differential against an independent
set-based reference over an enumerated and randomized corpus), path templating, the
enqueue/skip decision, template identity, the depth/instance/pagination caps and trap
detection, the giant-collapse property, and the untrusted-scheme boundary.
"""

import random
import string
import dataclasses
import unittest

from diamond_sword.coverage.template_engine import (
    PAGINATION_KEYS,
    Observation,
    TemplateConfig,
    TemplateMap,
    classify_segment,
    path_template,
)


# --------------------------------------------------------------------------------------
# classify_segment — golden cases (these pin the exact rules; a widened/narrowed rule fails)
# --------------------------------------------------------------------------------------

class TestClassifyGolden(unittest.TestCase):
    VARIABLE = {
        "1021": "{num}", "0": "{num}", "2024": "{num}",            # REQ-TE-01 numeric ids/years
        "550e8400-e29b-41d4-a716-446655440000": "{uuid}",          # canonical uuid
        "2024-01-15": "{date}",                                    # date
        "9fceb02d8e3f97a5e3b3f3a1c0d2e4f6": "{hex}",               # 32-hex token
        "507f1f77bcf86cd799439011": "{hex}",                       # 24-hex mongo ObjectId
        "a1b2c3d4e5f6a7b8": "{hex}",                               # 16-hex with digits
        "my-cool-post-12345": "{token}",                           # opaque slug (alpha+digit, >=16)
        "aGVsbG8xd29ybGQyMw": "{token}",                           # base64-ish token
    }
    LITERAL = [
        "v1", "v2", "me", "settings", "users", "documentation",    # REQ-TE-02 route words stay literal
        "documentationpage",                                       # long but no digit -> not a token
        "deadbeefcafe",                                            # 12 hex but NO digit -> not hex
        "cafe", "deface", "decade",                                # short hex-ish words -> literal
        "abc123",                                                  # mixed but len 6 (<12 hex, <16 token)
        "ab12", "x1",                                              # short mixed -> literal
        "api", "graphql", "v1.0", "index.html",
    ]

    def test_variables(self):  # REQ-TE-01
        for seg, want in self.VARIABLE.items():
            self.assertEqual(classify_segment(seg), want, msg=seg)

    def test_literals(self):  # REQ-TE-02
        for seg in self.LITERAL:
            self.assertIsNone(classify_segment(seg), msg=seg)

    def test_empty(self):
        self.assertIsNone(classify_segment(""))

    def test_uuid_case_insensitive(self):
        self.assertEqual(classify_segment("550E8400-E29B-41D4-A716-446655440000"), "{uuid}")

    def test_num_rejects_unicode_digits(self):
        # str.isdigit() would accept these; the regex must not (text/encoding pitfall).
        self.assertIsNone(classify_segment("\u00b2\u00b3"))  # superscript 2,3
        self.assertIsNone(classify_segment("\u0660\u0661"))  # arabic-indic 0,1


def _ref_classify(seg: str) -> str | None:
    """Independent reference: set-membership + explicit lengths, no shared regexes."""
    if seg == "":
        return None
    hexset = set("0123456789abcdef")
    digits = set("0123456789")
    parts = seg.split("-")
    if (len(parts) == 5 and [len(p) for p in parts] == [8, 4, 4, 4, 12]
            and all(p and set(p.lower()) <= hexset for p in parts)):
        return "{uuid}"
    if (len(parts) == 3 and [len(p) for p in parts] == [4, 2, 2]
            and all(set(p) <= digits for p in parts)):
        return "{date}"
    if seg and set(seg) <= digits:
        return "{num}"
    low = seg.lower()
    if len(low) >= 12 and set(low) <= hexset and (set(low) & digits):
        return "{hex}"
    if (len(seg) >= 16 and any(c in string.ascii_letters for c in seg)
            and (set(seg) & digits)):
        return "{token}"
    return None


class TestClassifyDifferential(unittest.TestCase):
    """classify_segment must agree with the independent reference everywhere."""

    def test_enumerated_and_random(self):  # NFR-TE-02
        samples: list[str] = list(TestClassifyGolden.VARIABLE) + TestClassifyGolden.LITERAL
        rng = random.Random(20261004)
        alphabet = string.ascii_letters + string.digits + "----__."
        for _ in range(6000):
            n = rng.randint(1, 20)
            samples.append("".join(rng.choice(alphabet) for _ in range(n)))
        # also stress the uuid/date/hex shapes directly
        hx = "0123456789abcdef"
        for _ in range(1000):
            samples.append("-".join("".join(rng.choice(hx) for _ in range(w))
                                    for w in (8, 4, 4, 4, 12)))
            samples.append(f"{rng.randint(1000,9999)}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}")
            samples.append("".join(rng.choice(hx) for _ in range(rng.randint(8, 40))))
        checked = 0
        for s in samples:
            self.assertEqual(classify_segment(s), _ref_classify(s), msg=repr(s))
            checked += 1
        self.assertGreaterEqual(checked, 7000)


# --------------------------------------------------------------------------------------
# path_template
# --------------------------------------------------------------------------------------

class TestPathTemplate(unittest.TestCase):
    def test_collapse_and_depth(self):  # REQ-TE-03
        self.assertEqual(path_template("/orders/1021"), ("/orders/{num}", 2))
        self.assertEqual(path_template("/orders/1022"), ("/orders/{num}", 2))

    def test_trailing_slash_and_root(self):
        self.assertEqual(path_template("/orders/1022/"), ("/orders/{num}", 2))
        self.assertEqual(path_template("/"), ("/", 0))
        self.assertEqual(path_template(""), ("/", 0))

    def test_dot_segments_normalized(self):  # cannot dodge dedup with ./ or ../
        self.assertEqual(path_template("/a/../orders/./5"), ("/orders/{num}", 2))

    def test_mixed_literals_and_vars(self):
        self.assertEqual(
            path_template("/api/v1/projects/42/issues/550e8400-e29b-41d4-a716-446655440000"),
            ("/api/v1/projects/{num}/issues/{uuid}", 6),
        )


# --------------------------------------------------------------------------------------
# observe — decisions, identity, caps, traps
# --------------------------------------------------------------------------------------

class TestObserveDecisions(unittest.TestCase):
    def test_new_template_then_instance_then_duplicate(self):  # REQ-TE-04
        tm = TemplateMap()
        a = tm.observe("https://x.com/orders/1")
        self.assertEqual((a.enqueue, a.is_new_template, a.reason),
                         (True, True, "ENQUEUE_NEW_TEMPLATE"))
        b = tm.observe("https://x.com/orders/2")
        self.assertEqual((b.enqueue, b.is_new_template, b.reason),
                         (True, False, "ENQUEUE_NEW_INSTANCE"))
        self.assertEqual(a.template_key, b.template_key)
        c = tm.observe("https://x.com/orders/2")  # exact repeat
        self.assertEqual((c.enqueue, c.reason), (False, "DUPLICATE_INSTANCE"))

    def test_identity_ignores_query_values_but_not_keys(self):  # REQ-TE-05
        tm = TemplateMap()
        k1 = tm.observe("https://x.com/search?q=foo&sort=asc").template_key
        k2 = tm.observe("https://x.com/search?q=bar&sort=desc").template_key
        self.assertEqual(k1, k2)  # same keys, different values -> same template
        k3 = tm.observe("https://x.com/search?q=foo").template_key
        self.assertNotEqual(k1, k3)  # different key-set -> different template

    def test_identity_includes_method(self):  # REQ-TE-05
        tm = TemplateMap()
        g = tm.observe("https://x.com/orders/1", "GET").template_key
        p = tm.observe("https://x.com/orders/1", "POST").template_key
        self.assertNotEqual(g, p)

    def test_depth_cap(self):  # REQ-TE-06
        tm = TemplateMap(TemplateConfig(max_depth=3))
        shallow = tm.observe("https://x.com/a/b/c")
        self.assertTrue(shallow.enqueue)
        deep = tm.observe("https://x.com/a/b/c/d")
        self.assertEqual((deep.enqueue, deep.reason), (False, "DEPTH_EXCEEDED"))

    def test_instance_cap_is_trap(self):  # REQ-TE-07 (calendar/scroll via generic cap)
        tm = TemplateMap(TemplateConfig(max_instances_per_template=3))
        reasons = [tm.observe(f"https://x.com/day/{i}").reason for i in range(5)]
        # first 3 distinct instances enqueue, the 4th hits the ceiling exactly
        self.assertEqual(reasons[:3], ["ENQUEUE_NEW_TEMPLATE", "ENQUEUE_NEW_INSTANCE",
                                       "ENQUEUE_NEW_INSTANCE"])
        self.assertEqual(reasons[3], "INSTANCE_CAP")
        self.assertIn("GET /day/{num}", tm.traps)

    def test_pagination_cap_is_trap(self):  # REQ-TE-08
        tm = TemplateMap(TemplateConfig(max_values_per_pagination_key=3,
                                        max_instances_per_template=10_000))
        self.assertIn("page", PAGINATION_KEYS)
        reasons = [tm.observe(f"https://x.com/list?page={i}").reason for i in range(5)]
        self.assertEqual(reasons[3], "PAGINATION_CAP")
        self.assertTrue(any(k.startswith("GET /list") for k in tm.traps))

    def test_bad_scheme_never_enqueued(self):  # REQ-TE-09 trust boundary
        for url in ("javascript:alert(1)", "data:text/html,x", "mailto:a@b.com",
                    "ftp://x.com/f"):
            o = TemplateMap().observe(url)
            self.assertEqual((o.enqueue, o.reason), (False, "BAD_URL"), msg=url)

    def test_relative_url_is_allowed(self):
        # hrefs are often relative; no scheme is fine and must still templatize.
        o = TemplateMap().observe("/orders/7")
        self.assertEqual((o.enqueue, o.path_template), (True, "/orders/{num}"))


class TestGiantCollapse(unittest.TestCase):
    def test_thousands_of_instances_collapse(self):  # NFR-TE-01
        tm = TemplateMap(TemplateConfig(max_instances_per_template=10_000))
        for i in range(5000):
            tm.observe(f"https://x.com/orders/{i}")
            tm.observe(f"https://x.com/users/{i}/profile")
        self.assertEqual(set(tm.templates),
                         {"GET /orders/{num}", "GET /users/{num}/profile"})
        # a seen instance is never re-crawled
        again = tm.observe("https://x.com/orders/4999")
        self.assertEqual((again.enqueue, again.reason), (False, "DUPLICATE_INSTANCE"))

    def test_collapse_with_default_caps_marks_traps(self):
        tm = TemplateMap()  # default cap 50
        enq = sum(tm.observe(f"https://x.com/p/{i}").enqueue for i in range(1000))
        self.assertEqual(enq, 50)                       # enqueues exactly up to the ceiling
        self.assertEqual(tm.templates, ("GET /p/{num}",))
        self.assertIn("GET /p/{num}", tm.traps)

    def test_observation_is_frozen(self):
        o = TemplateMap().observe("https://x.com/a")
        self.assertIsInstance(o, Observation)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            o.enqueue = False  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main(verbosity=2)
