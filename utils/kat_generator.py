"""
IoT-SC1 Known-Answer Test (KAT) Vector Generator
===================================================
Generates and saves official KAT vectors to kat_vectors.json.
These vectors serve as the ground truth for cross-platform verification
and thesis documentation.

Run:
    python utils/kat_generator.py
"""

import json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.cipher import IoTSC1

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "kat_vectors.json")

RAW_VECTORS = [
    # (description, key_hex, iv_hex, plaintext_hex)
    ("All-zero key, all-zero IV, all-zero PT (16B)",
     "00000000000000000000000000000000",
     "0000000000000000",
     "00000000000000000000000000000000"),

    ("All-ones key, all-ones IV, all-ones PT (16B)",
     "ffffffffffffffffffffffffffffffff",
     "ffffffffffffffff",
     "ffffffffffffffff"),

    ("Standard test vector — 'Hello IoT-SC1!'",
     "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
     "a1b2c3d4e5f6a7b8",
     bytes("Hello IoT-SC1!".encode()).hex()),

    ("Incremental key & IV, zero PT (32B)",
     "000102030405060708090a0b0c0d0e0f",
     "0001020304050607",
     "00" * 32),

    ("Random-looking key, sensor data PT",
     "deadbeefcafebabe0123456789abcdef",
     "0102030405060708",
     bytes(b'{"temp":38.7,"hum":61.2}').hex()),

    ("Single byte PT",
     "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
     "a1b2c3d4e5f6a7b8",
     "ff"),

    ("Empty PT",
     "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
     "a1b2c3d4e5f6a7b8",
     ""),

    ("256-byte PT (keystream uniformity)",
     "aabbccddeeff00112233445566778899",
     "aabbccddeeff0011",
     "".join(f"{i:02x}" for i in range(256))),

    ("IV = all-zeros, key = alternating nibbles",
     "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
     "0000000000000000",
     bytes(b"5G NB-IoT payload test").hex()),

    ("Max-length typical IoT frame (64B)",
     "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
     "fedcba9876543210",
     "ab" * 64),
]


def generate():
    vectors = []
    print(f"\n  Generating {len(RAW_VECTORS)} KAT vectors...\n")

    for desc, key_hex, iv_hex, pt_hex in RAW_VECTORS:
        key = bytes.fromhex(key_hex)
        iv  = bytes.fromhex(iv_hex)
        pt  = bytes.fromhex(pt_hex)

        sc = IoTSC1(key, iv)
        ct, tag = sc.encrypt_with_mac(pt) if pt else (b"", b"\x00\x00\x00\x00")

        # Verify decrypt
        sc2 = IoTSC1(key, iv)
        dec, valid = sc2.decrypt_and_verify(ct, tag)
        assert dec == pt, f"KAT self-check failed: {desc}"
        assert valid or not pt, f"MAC check failed: {desc}"

        vec = {
            "description": desc,
            "key":         key_hex,
            "iv":          iv_hex,
            "plaintext":   pt_hex,
            "ciphertext":  ct.hex(),
            "mac_tag":     tag.hex(),
            "pt_len":      len(pt),
            "ct_len":      len(ct),
        }
        vectors.append(vec)
        print(f"  ✅  {desc[:55]}")
        if pt:
            print(f"       PT : {pt_hex[:32]}{'...' if len(pt_hex)>32 else ''}")
            print(f"       CT : {ct.hex()[:32]}{'...' if len(ct.hex())>32 else ''}")
            print(f"       MAC: {tag.hex()}")
        else:
            print(f"       (empty)")

    meta = {
        "cipher":    "IoT-SC1",
        "version":   "1.0.0",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "key_size":  128,
        "iv_size":   64,
        "vectors":   vectors,
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\n  Saved {len(vectors)} KAT vectors → {OUTPUT_FILE}")
    return vectors


def verify_from_file(path: str = OUTPUT_FILE):
    """Re-verify all KAT vectors from saved JSON."""
    with open(path) as f:
        data = json.load(f)

    print(f"\n  Verifying {len(data['vectors'])} KAT vectors from {path}...\n")
    all_pass = True
    for vec in data["vectors"]:
        key = bytes.fromhex(vec["key"])
        iv  = bytes.fromhex(vec["iv"])
        pt  = bytes.fromhex(vec["plaintext"])
        expected_ct = bytes.fromhex(vec["ciphertext"])
        expected_tag = bytes.fromhex(vec["mac_tag"])

        sc = IoTSC1(key, iv)
        ct, tag = sc.encrypt_with_mac(pt)

        ct_ok  = (ct == expected_ct)
        tag_ok = (tag == expected_tag)
        ok = ct_ok and tag_ok

        if not ok:
            all_pass = False
        status = "✅" if ok else "❌"
        print(f"  {status}  {vec['description'][:60]}")
        if not ok:
            print(f"       CT  match: {ct_ok}")
            print(f"       TAG match: {tag_ok}")

    print(f"\n  {'All KAT vectors verified ✅' if all_pass else 'FAILURES DETECTED ❌'}\n")
    return all_pass


if __name__ == "__main__":
    generate()
    verify_from_file()
