"""Spec-first tests for diamond_sword.coverage.fingerprint (Tier T3).

Covers a frozen golden skeleton + hash, instance collapse (same template, different data ->
same fingerprint), discrimination (different structure -> different fingerprint), volatile
stripping (csrf/nonce/id/href/class/text/data-* ignored; input-type and role kept), noise
subtree handling (head/script/style/svg), bounded + crash-proof parsing of hostile input,
determinism, and a differential of the tag sequence against generated DOM trees.
"""

import random
import unittest

from diamond_sword.coverage.fingerprint import fingerprint, skeleton

# Golden vectors — computed once from the real module and frozen (see session log 2026-10-04).
GOLDEN_HTML = (
    '<!doctype html><html><head><title>x</title>'
    '<meta charset="utf-8"><link rel="canonical" href="/u/1"></head>'
    '<body><nav><a href="/home">Home</a></nav>'
    '<main><form action="/login?csrf=abc123">'
    '<input type="text" name="user" value="v"><input type="password" name="pw">'
    '<input type="hidden" name="csrf" value="DEADBEEF"><button type="submit">Go</button>'
    '</form><svg><path d="M0 0"/></svg>'
    '<ul role="list"><li>a</li><li>b</li></ul></main></body></html>'
)
GOLDEN_SKELETON = (
    "0:html", "1:body", "2:nav", "3:a", "2:main", "3:form",
    "4:input[type=text]", "4:input[type=password]", "4:input[type=hidden]",
    "4:button[type=submit]", "3:ul[role=list]", "4:li", "4:li",
)
GOLDEN_FP = "04c25118e7d322f809f78ffd720d485f1df6c02fa0fc852de2464d2beedafae9"


class TestGolden(unittest.TestCase):
    def test_skeleton_frozen(self):  # REQ-FP-05 inspectable + pinned
        self.assertEqual(skeleton(GOLDEN_HTML), GOLDEN_SKELETON)

    def test_fingerprint_frozen(self):
        self.assertEqual(fingerprint(GOLDEN_HTML), GOLDEN_FP)

    def test_head_and_noise_subtrees_dropped(self):  # REQ-FP-04
        sk = skeleton(GOLDEN_HTML)
        self.assertNotIn("title", " ".join(sk))   # head dropped
        self.assertNotIn("svg", " ".join(sk))     # svg subtree dropped
        self.assertNotIn("path", " ".join(sk))

    def test_input_types_kept(self):  # REQ-FP-03 (type is structural)
        self.assertIn("4:input[type=password]", skeleton(GOLDEN_HTML))


class TestInstanceCollapse(unittest.TestCase):
    """Same template rendered with different data must give the same fingerprint."""

    PAGE_A = (
        '<body><main><h1>Order 1021</h1>'
        '<table><tr><td>Total</td><td>$9.99</td></tr></table>'
        '<a href="/orders/1021/receipt">Receipt</a></main></body>'
    )
    PAGE_B = (
        '<body><main><h1>Order 7788</h1>'
        '<table><tr><td>Total</td><td>$42.00</td></tr></table>'
        '<a href="/orders/7788/receipt">Receipt</a></main></body>'
    )

    def test_same_structure_different_data(self):  # REQ-FP-01
        self.assertEqual(fingerprint(self.PAGE_A), fingerprint(self.PAGE_B))

    def test_structurally_different_pages_differ(self):  # REQ-FP-02
        other = '<body><main><h1>Dashboard</h1><nav><a>x</a><a>y</a></nav></main></body>'
        self.assertNotEqual(fingerprint(self.PAGE_A), fingerprint(other))


class TestVolatileStripping(unittest.TestCase):
    def test_csrf_nonce_id_href_class_text_ignored(self):  # REQ-FP-03
        a = ('<body><form action="/x?csrf=AAA"><input type="hidden" name="t" value="AAA">'
             '<div id="a1" class="css-9xk2" data-k="v1">hello</div></form></body>')
        b = ('<body><form action="/y?csrf=ZZZ"><input type="hidden" name="t" value="ZZZ">'
             '<div id="b2" class="css-7qp0" data-k="v2">world</div></form></body>')
        self.assertEqual(fingerprint(a), fingerprint(b))

    def test_input_type_changes_structure(self):  # REQ-FP-03 (type must matter)
        login = '<body><form><input type="text"><input type="password"></form></body>'
        search = '<body><form><input type="text"><input type="search"></form></body>'
        self.assertNotEqual(fingerprint(login), fingerprint(search))

    def test_role_changes_structure(self):
        a = '<body><div role="dialog"><span>x</span></div></body>'
        b = '<body><div role="navigation"><span>x</span></div></body>'
        self.assertNotEqual(fingerprint(a), fingerprint(b))


class TestRobustness(unittest.TestCase):
    def test_malformed_does_not_raise(self):  # REQ-FP-06 (Gate 3)
        for bad in ("<div><span></div></p><<<", "<body><table><tr><td>",
                    "", "   ", "<!-- comment only -->", "no tags at all",
                    "<body>" + "<div>" * 50):  # unbalanced nesting
            fingerprint(bad)  # must not raise
            self.assertIsInstance(skeleton(bad), tuple)

    def test_injection_in_values_is_inert(self):  # untrusted content is data
        a = '<body><a href="javascript:alert(1)">x</a></body>'
        b = '<body><a href="/safe">x</a></body>'
        self.assertEqual(fingerprint(a), fingerprint(b))  # href value dropped -> same

    def test_token_bound(self):  # REQ-FP-06 memory bound on huge/hostile input
        huge = "<body>" + ("<div></div>" * 10_000) + "</body>"
        self.assertLessEqual(len(skeleton(huge, max_tokens=100)), 100)

    def test_fragment_without_body(self):  # AJAX fragments have no <body>
        frag = '<ul><li>a</li><li>b</li></ul>'
        sk = skeleton(frag)
        self.assertEqual(sk, ("0:ul", "1:li", "1:li"))

    def test_determinism(self):  # NFR-FP-01
        self.assertEqual(fingerprint(GOLDEN_HTML), fingerprint(GOLDEN_HTML))


# --------------------------------------------------------------------------------------
# Differential: generate random DOM trees; the generator records the true tag sequence,
# and the skeleton's tag sequence must equal it. Independent of the parser internals.
# --------------------------------------------------------------------------------------

_STRUCT_TAGS = ["div", "section", "article", "nav", "main", "ul", "li", "span", "p",
                "table", "tr", "td", "header", "footer", "form", "label"]


def _gen_tree(rng: random.Random, depth: int, seq: list[str]) -> str:
    """Render a random tree of structural tags; append each opened tag to ``seq`` in order."""
    tag = rng.choice(_STRUCT_TAGS)
    seq.append(tag)
    # random volatile noise that must not affect the tag sequence
    attrs = f' id="x{rng.randint(0, 9999)}" class="c{rng.randint(0, 9)}"'
    text = rng.choice(["", "hello", str(rng.randint(0, 1000))])
    children = ""
    if depth > 0:
        for _ in range(rng.randint(0, 3)):
            children += _gen_tree(rng, depth - 1, seq)
    return f"<{tag}{attrs}>{text}{children}</{tag}>"


def _tags_of(sk: tuple[str, ...]) -> list[str]:
    """Extract just the tag name from each 'depth:tag[extra]' token."""
    out = []
    for tok in sk:
        name = tok.split(":", 1)[1]
        name = name.split("[", 1)[0]
        out.append(name)
    return out


class TestTagSequenceDifferential(unittest.TestCase):
    def test_generated_trees_match(self):  # NFR-FP-02
        rng = random.Random(4242)
        checked = 0
        for _ in range(500):
            seq: list[str] = []
            html = "<body>" + _gen_tree(rng, rng.randint(0, 4), seq) + "</body>"
            got = _tags_of(skeleton(html, max_tokens=100_000))
            self.assertEqual(got, ["body"] + seq)
            checked += 1
        self.assertEqual(checked, 500)

    def test_same_tree_different_data_same_fp(self):  # REQ-FP-01 at scale
        rng = random.Random(99)
        for _ in range(100):
            seq: list[str] = []
            # build structure once, then render twice with different ids/text
            spec = _gen_tree(rng, rng.randint(1, 3), seq)
            # second render: mutate only the volatile bits by regenerating with a shifted rng
            html1 = "<body>" + spec + "</body>"
            html2 = html1.replace('id="x', 'id="y').replace("hello", "world")
            self.assertEqual(fingerprint(html1), fingerprint(html2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
