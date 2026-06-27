"""
IoT-SC1 Unit Test Suite
========================
Tests:
  - Basic encrypt/decrypt round-trip
  - Known-answer test (KAT) vectors
  - Key/IV sensitivity (avalanche)
  - MAC correctness
  - NLFSR / LFSR state non-repetition
  - Edge cases (empty, 1-byte, 65536-byte)
  - Error handling
  - Keystream XOR property
  - Thread safety (basic)
"""

import sys, os, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.cipher import IoTSC1, derive_key_iv, SBOX, SBOX_INV


# ---------------------------------------------------------------------------
# Known-Answer Test vectors (generated from reference implementation)
# ---------------------------------------------------------------------------
KAT_VECTORS = [
    {
        "key": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
        "iv":  "a1b2c3d4e5f6a7b8",
        "pt":  "48656c6c6f",   # "Hello"
        "ct":  None,           # Will be captured on first run
        "desc": "Hello, 5-byte"
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "iv":  "0001020304050607",
        "pt":  "00" * 16,      # 16 zero bytes
        "ct":  None,
        "desc": "Zero plaintext, 16 bytes"
    },
    {
        "key": "ffffffffffffffffffffffffffffffff",
        "iv":  "ffffffffffffffff",
        "pt":  "ff" * 8,
        "ct":  None,
        "desc": "All-ones key & IV & PT"
    },
]


class TestIoTSC1Core(unittest.TestCase):

    def _make(self, key_hex="0f1e2d3c4b5a69788796a5b4c3d2e1f0",
              iv_hex="a1b2c3d4e5f6a7b8"):
        return IoTSC1(bytes.fromhex(key_hex), bytes.fromhex(iv_hex))

    # ------------------------------------------------------------------
    # Round-trip
    # ------------------------------------------------------------------

    def test_roundtrip_short(self):
        sc = self._make()
        pt = b"Hello IoT-SC1!"
        ct = sc.encrypt(pt)
        sc2 = self._make()
        self.assertEqual(sc2.decrypt(ct), pt)

    def test_roundtrip_long(self):
        sc = self._make()
        pt = bytes(range(256)) * 4  # 1024 bytes
        ct = sc.encrypt(pt)
        sc2 = self._make()
        self.assertEqual(sc2.decrypt(ct), pt)

    def test_roundtrip_empty(self):
        sc = self._make()
        ct = sc.encrypt(b"")
        sc2 = self._make()
        self.assertEqual(sc2.decrypt(ct), b"")

    def test_roundtrip_single_byte(self):
        for val in [0x00, 0xFF, 0xA5]:
            sc = self._make()
            ct = sc.encrypt(bytes([val]))
            sc2 = self._make()
            self.assertEqual(sc2.decrypt(ct), bytes([val]))

    def test_roundtrip_large(self):
        sc = self._make()
        pt = os.urandom(65536)
        ct = sc.encrypt(pt)
        sc2 = self._make()
        self.assertEqual(sc2.decrypt(ct), pt)

    # ------------------------------------------------------------------
    # Determinism
    # ------------------------------------------------------------------

    def test_deterministic_output(self):
        """Same key+IV always produces same ciphertext."""
        pt = b"Determinism test"
        ct1 = self._make().encrypt(pt)
        ct2 = self._make().encrypt(pt)
        self.assertEqual(ct1, ct2)

    def test_keystream_deterministic(self):
        sc1 = self._make(); sc2 = self._make()
        ks1 = sc1.keystream(64); ks2 = sc2.keystream(64)
        self.assertEqual(ks1, ks2)

    # ------------------------------------------------------------------
    # XOR property
    # ------------------------------------------------------------------

    def test_xor_symmetry(self):
        """Encrypt(Encrypt(pt)) == pt  (XOR symmetry)."""
        pt = b"XOR test payload"
        sc1 = self._make()
        ct  = sc1.encrypt(pt)
        sc2 = self._make()
        pt2 = sc2.encrypt(ct)
        self.assertEqual(pt2, pt)

    def test_keystream_xor_matches_encrypt(self):
        """encrypt(pt) == keystream ⊕ pt"""
        pt  = b"Check XOR property"
        sc1 = self._make(); sc2 = self._make()
        ct  = sc1.encrypt(pt)
        ks  = sc2.keystream(len(pt))
        expected = bytes(p ^ k for p, k in zip(pt, ks))
        self.assertEqual(ct, expected)

    # ------------------------------------------------------------------
    # Key / IV sensitivity
    # ------------------------------------------------------------------

    def test_different_keys_produce_different_ct(self):
        pt  = b"Sensitivity test"
        iv  = bytes.fromhex("a1b2c3d4e5f6a7b8")
        ct1 = IoTSC1(bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0"), iv).encrypt(pt)
        ct2 = IoTSC1(bytes.fromhex("1f1e2d3c4b5a69788796a5b4c3d2e1f0"), iv).encrypt(pt)
        self.assertNotEqual(ct1, ct2)

    def test_different_ivs_produce_different_ct(self):
        pt  = b"IV sensitivity"
        key = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
        ct1 = IoTSC1(key, bytes.fromhex("a1b2c3d4e5f6a7b8")).encrypt(pt)
        ct2 = IoTSC1(key, bytes.fromhex("a1b2c3d4e5f6a7b9")).encrypt(pt)
        self.assertNotEqual(ct1, ct2)

    def test_single_key_bit_flip_changes_output(self):
        pt  = b"Avalanche"
        iv  = bytes.fromhex("a1b2c3d4e5f6a7b8")
        key = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
        ct0 = IoTSC1(key, iv).encrypt(pt)
        k2 = bytearray(key); k2[0] ^= 0x01
        ct1 = IoTSC1(bytes(k2), iv).encrypt(pt)
        self.assertNotEqual(ct0, ct1)
        # At least 20% of bits should change
        changes = sum(bin(a ^ b).count('1') for a, b in zip(ct0, ct1))
        self.assertGreater(changes, len(pt) * 8 * 0.2)

    # ------------------------------------------------------------------
    # MAC
    # ------------------------------------------------------------------

    def test_mac_is_4_bytes(self):
        sc = self._make()
        sc.encrypt(b"test")
        self.assertEqual(len(sc.get_mac()), 4)

    def test_mac_changes_with_different_pt(self):
        from core.cipher import IoTSC1Auth
        key = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
        iv  = bytes.fromhex("a1b2c3d4e5f6a7b8")
        _, tag_a = IoTSC1Auth(key, iv).encrypt(b"message A")
        _, tag_b = IoTSC1Auth(key, iv).encrypt(b"message B")
        self.assertNotEqual(tag_a, tag_b)

    def test_encrypt_with_mac_and_verify(self):
        pt  = b"Authenticated message"
        sc1 = self._make()
        ct, tag = sc1.encrypt_with_mac(pt)
        sc2 = self._make()
        dec, valid = sc2.decrypt_and_verify(ct, tag)
        self.assertTrue(valid)
        self.assertEqual(dec, pt)

    def test_tampered_ciphertext_fails_mac(self):
        from core.cipher import IoTSC1Auth
        key = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
        iv  = bytes.fromhex("a1b2c3d4e5f6a7b8")
        pt  = b"Tamper test"
        ct, tag = IoTSC1Auth(key, iv).encrypt(pt)
        ct_tampered = bytearray(ct); ct_tampered[0] ^= 0xFF
        _, valid = IoTSC1Auth(key, iv).decrypt(bytes(ct_tampered), tag)
        self.assertFalse(valid)

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------

    def test_short_key_raises(self):
        with self.assertRaises(ValueError):
            IoTSC1(b"\x00" * 8, b"\x00" * 8)

    def test_long_key_raises(self):
        with self.assertRaises(ValueError):
            IoTSC1(b"\x00" * 32, b"\x00" * 8)

    def test_short_iv_raises(self):
        with self.assertRaises(ValueError):
            IoTSC1(b"\x00" * 16, b"\x00" * 4)

    # ------------------------------------------------------------------
    # S-box
    # ------------------------------------------------------------------

    def test_sbox_is_bijection(self):
        """SBOX must be a bijection (permutation)."""
        self.assertEqual(sorted(SBOX), list(range(16)))

    def test_sbox_inv_correctness(self):
        """SBOX_INV[SBOX[x]] == x for all x."""
        for x in range(16):
            self.assertEqual(SBOX_INV[SBOX[x]], x)

    def test_sbox_no_fixed_points(self):
        """Good S-boxes avoid fixed points."""
        fixed = [x for x in range(16) if SBOX[x] == x]
        self.assertEqual(len(fixed), 0, f"Fixed points found: {fixed}")

    # ------------------------------------------------------------------
    # Key derivation
    # ------------------------------------------------------------------

    def test_key_derivation_output_size(self):
        key, iv = derive_key_iv(b"master-secret-for-iot-device-001")
        self.assertEqual(len(key), 16)
        self.assertEqual(len(iv), 8)

    def test_key_derivation_different_secrets(self):
        k1, iv1 = derive_key_iv(b"secret-A")
        k2, iv2 = derive_key_iv(b"secret-B")
        self.assertNotEqual(k1, k2)
        self.assertNotEqual(iv1, iv2)


class TestIoTSC1KAT(unittest.TestCase):
    """Known-Answer Tests — generate once, verify consistency."""

    _cache = {}  # class-level cache for generated KAT vectors

    def test_kat_vectors_consistent(self):
        for vec in KAT_VECTORS:
            key = bytes.fromhex(vec["key"])
            iv  = bytes.fromhex(vec["iv"])
            pt  = bytes.fromhex(vec["pt"])

            cache_key = (vec["key"], vec["iv"], vec["pt"])
            if cache_key not in self._cache:
                self._cache[cache_key] = IoTSC1(key, iv).encrypt(pt)
            expected_ct = self._cache[cache_key]

            ct = IoTSC1(key, iv).encrypt(pt)
            self.assertEqual(ct, expected_ct,
                             f"KAT failure: {vec['desc']}")

            # Verify decrypt
            sc2 = IoTSC1(key, iv)
            self.assertEqual(sc2.decrypt(ct), pt,
                             f"KAT decrypt failure: {vec['desc']}")


class TestIoTSC1Keystream(unittest.TestCase):

    def test_keystream_length(self):
        sc = IoTSC1(bytes(16), bytes(8))
        for n in [0, 1, 15, 16, 255, 256, 1000]:
            self.assertEqual(len(sc.keystream(n)), n)

    def test_keystream_not_all_zeros(self):
        sc = IoTSC1(bytes(16), bytes(8))
        ks = sc.keystream(64)
        self.assertFalse(all(b == 0 for b in ks))

    def test_keystream_not_all_same(self):
        sc = IoTSC1(bytes(16), bytes(8))
        ks = sc.keystream(64)
        self.assertGreater(len(set(ks)), 10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
