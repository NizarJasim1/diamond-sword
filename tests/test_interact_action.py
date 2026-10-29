import unittest

from diamond_sword.heal.locator_cascade import DomSnapshot, Element, Target
from diamond_sword.interact.action import (
    action_signature, state_fingerprint, to_roe_action,
)


class TestActionSignature(unittest.TestCase):
    def test_deterministic(self):
        t = Target(role="button", text="Save")
        self.assertEqual(action_signature("click", t), action_signature("click", t))

    def test_id_digits_folded(self):
        a = action_signature("click", Target(test_id="delete-order-5"))
        b = action_signature("click", Target(test_id="delete-order-6"))
        self.assertEqual(a, b)

    def test_text_digits_folded(self):
        a = action_signature("click", Target(role="link", text="Order 5"))
        b = action_signature("click", Target(role="link", text="Order 6"))
        self.assertEqual(a, b)

    def test_href_templated(self):
        a = action_signature("click", Target(tag="a"), href="https://x/orders/1")
        b = action_signature("click", Target(tag="a"), href="https://x/orders/2")
        self.assertEqual(a, b)

    def test_kind_distinguishes(self):
        t = Target(test_id="field")
        self.assertNotEqual(action_signature("click", t), action_signature("fill", t))

    def test_different_controls_differ(self):
        self.assertNotEqual(
            action_signature("click", Target(role="button", text="Save")),
            action_signature("click", Target(role="button", text="Delete")),
        )


class TestStateFingerprint(unittest.TestCase):
    def _detail(self, oid):
        return DomSnapshot(f"https://x/orders/{oid}", (
            Element("n0", "button", role="button", text="Delete"),
            Element("n1", "a", role="link", text="Back", href="/orders"),
        ))

    def test_route_instances_collapse(self):
        self.assertEqual(state_fingerprint(self._detail(1)), state_fingerprint(self._detail(2)))

    def test_structure_change_differs(self):
        base = self._detail(1)
        more = DomSnapshot("https://x/orders/1", base.elements + (
            Element("n2", "button", role="button", text="Edit"),))
        self.assertNotEqual(state_fingerprint(base), state_fingerprint(more))

    def test_different_route_differs(self):
        a = DomSnapshot("https://x/orders/1", ())
        b = DomSnapshot("https://x/settings", ())
        self.assertNotEqual(state_fingerprint(a), state_fingerprint(b))


class TestToRoeAction(unittest.TestCase):
    def test_fields(self):
        a = to_roe_action("click", "Delete", "https://x/orders/1", True)
        self.assertEqual(a.kind, "ui")
        self.assertEqual(a.label, "Delete")
        self.assertEqual(a.url, "https://x/orders/1")
        self.assertTrue(a.mutating)
        self.assertIsNone(a.method)


if __name__ == "__main__":
    unittest.main()
