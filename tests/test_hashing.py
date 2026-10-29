"""Golden-vector tests for diamond_sword.util.hashing (Tier T3).

These pin the exact hashing behaviour so any change to canonicalization or the chain hash is
caught — including self-consistent weakenings that a round-trip test would miss.
"""

import unittest

from diamond_sword.util.hashing import GENESIS, canonical_json, chain_hash, sha256_hex

# Real values, computed once and frozen (see session log).
SHA_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
BODY0 = '{"kind":"scope","payload":{"allowed":true,"reason":"ALLOW_IN_SCOPE"},"seq":0,"ts":0}'
CHAIN0 = "76b7af46b46f31e9e1e06cf0be0daa9461957bf136aae8773329e5be0f904c08"


class TestHashing(unittest.TestCase):
    def test_sha256_known_vector(self):
        self.assertEqual(sha256_hex("abc"), SHA_ABC)
        self.assertEqual(sha256_hex(b"abc"), SHA_ABC)  # str and bytes agree

    def test_canonical_json_sorts_keys(self):  # order independence is the point
        self.assertEqual(canonical_json({"b": 1, "a": 2}), '{"a":2,"b":1}')
        self.assertEqual(canonical_json({"a": 2, "b": 1}), canonical_json({"b": 1, "a": 2}))

    def test_canonical_json_compact_and_unicode(self):
        self.assertEqual(canonical_json({"x": "café"}), '{"x":"café"}')

    def test_chain_hash_golden(self):
        body = canonical_json({"seq": 0, "ts": 0, "kind": "scope",
                               "payload": {"allowed": True, "reason": "ALLOW_IN_SCOPE"}})
        self.assertEqual(body, BODY0)
        self.assertEqual(chain_hash(GENESIS, body), CHAIN0)

    def test_chain_hash_depends_on_prev(self):
        body = '{"a":1}'
        self.assertNotEqual(chain_hash(GENESIS, body), chain_hash("1" * 64, body))


if __name__ == "__main__":
    unittest.main(verbosity=2)
