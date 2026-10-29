import unittest

from diamond_sword.heal.locator_cascade import DomSnapshot, Element
from diamond_sword.interact import action as A
from diamond_sword.interact.elements import interactive_elements


def _snap(*els):
    return DomSnapshot("https://app.test/page", tuple(els))


class TestInteractiveElements(unittest.TestCase):
    def _by_label(self, cands):
        return {c.label: c for c in cands}

    def test_picks_and_classifies(self):
        cands = interactive_elements(_snap(
            Element("a1", "a", role="link", text="Go", href="/x"),
            Element("b1", "button", role="button", text="Save"),
            Element("b2", "button", role="button", text="Open"),
            Element("i1", "input", test_id="email", input_type="email"),
            Element("i2", "input", text="Submit", input_type="submit"),
            Element("i3", "input", test_id="h", input_type="hidden"),
            Element("i4", "input", test_id="f", input_type="file"),
            Element("i5", "input", test_id="agree", input_type="checkbox"),
            Element("s1", "select", test_id="country"),
            Element("d1", "div", role="button", text="Menu"),
            Element("sp", "span", text="plain"),
        ))
        by = self._by_label(cands)
        # hidden/file skipped; plain span skipped
        self.assertNotIn("h", by)
        self.assertNotIn("f", by)
        self.assertNotIn("plain", by)
        # link resolved + non-mutating
        self.assertEqual(by["Go"].href, "https://app.test/x")
        self.assertEqual(by["Go"].ui.kind, A.CLICK)
        self.assertFalse(by["Go"].mutating)
        # verb button is mutating; neutral button is not
        self.assertTrue(by["Save"].mutating)
        self.assertFalse(by["Open"].mutating)
        # text input -> FILL with a harmless probe value
        self.assertEqual(by["email"].ui.kind, A.FILL)
        self.assertEqual(by["email"].ui.value, "ds-probe@example.test")
        # submit input -> click + mutating
        self.assertEqual(by["Submit"].ui.kind, A.CLICK)
        self.assertTrue(by["Submit"].mutating)
        # checkbox -> click, not mutating
        self.assertEqual(by["agree"].ui.kind, A.CLICK)
        self.assertFalse(by["agree"].mutating)
        # select
        self.assertEqual(by["country"].ui.kind, A.SELECT)
        # custom role=button
        self.assertEqual(by["Menu"].ui.kind, A.CLICK)

    def test_dedup_by_signature(self):
        cands = interactive_elements(_snap(
            Element("b1", "button", role="button", text="Save"),
            Element("b2", "button", role="button", text="Save"),
        ))
        self.assertEqual(len(cands), 1)

    def test_order_links_collapse(self):
        cands = interactive_elements(_snap(
            Element("o1", "a", role="link", text="Order 1", href="/orders/1"),
            Element("o2", "a", role="link", text="Order 2", href="/orders/2"),
            Element("o3", "a", role="link", text="Order 3", href="/orders/3"),
        ))
        self.assertEqual(len(cands), 1)


if __name__ == "__main__":
    unittest.main()
