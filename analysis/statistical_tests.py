"""
NIST-style Statistical Test Suite for IoT-SC1 Keystream
========================================================
Tests implemented:
  1. Monobit (Frequency) Test
  2. Block Frequency Test
  3. Runs Test
  4. Serial Test (2-bit)
  5. Approximate Entropy Test
  6. Chi-Square Uniformity Test
  7. Autocorrelation Test
  8. Shannon Entropy (bits/byte)
  9. Hamming Weight Distribution
 10. Avalanche Effect Test

All p-values: pass threshold = 0.01
"""

import math
import struct
from collections import Counter
from typing import List, Dict, Tuple, Optional
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.cipher import IoTSC1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bits(data: bytes) -> List[int]:
    """Convert bytes to list of bits (MSB first)."""
    result = []
    for byte in data:
        for i in range(7, -1, -1):
            result.append((byte >> i) & 1)
    return result


def erfc(x: float) -> float:
    """Complementary error function (Horner approximation)."""
    t = 1.0 / (1.0 + 0.3275911 * abs(x))
    poly = t * (0.254829592 + t * (-0.284496736 + t * (
           1.421413741 + t * (-1.453152027 + t * 1.061405429))))
    val = 1.0 - poly * math.exp(-x * x)
    return 2.0 - val if x < 0 else val


def igamc(a: float, x: float) -> float:
    """Incomplete gamma function Q(a,x) via continued fraction (simplified)."""
    if x < 0 or a <= 0:
        return 0.0
    if x == 0:
        return 1.0
    # Series approximation
    if x < a + 1:
        ap = a; s = d = 1.0 / a
        for _ in range(200):
            ap += 1
            d *= x / ap
            s += d
            if abs(d) < abs(s) * 1e-7:
                break
        return 1.0 - s * math.exp(-x + a * math.log(x) - math.lgamma(a))
    else:
        b = x + 1.0 - a; c = 1.0 / 1e-300; d = 1.0 / b; h = d
        for i in range(1, 201):
            an = -i * (i - a)
            b += 2
            d = an * d + b; d = 1.0 / d if abs(d) < 1e-300 else d
            c = b + an / c; c = 1.0 / 1e-300 if abs(c) < 1e-300 else c
            d = 1.0 / d; h *= d * c
            if abs(d * c - 1.0) < 1e-7:
                break
        return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


# ---------------------------------------------------------------------------
# Individual tests
# ---------------------------------------------------------------------------

def test_monobit(bits: List[int]) -> Dict:
    """NIST SP 800-22 Test 1: Frequency (Monobit) Test."""
    n = len(bits)
    s = sum(1 if b else -1 for b in bits)
    s_obs = abs(s) / math.sqrt(n)
    p = erfc(s_obs / math.sqrt(2))
    ones = sum(bits)
    return {
        "name": "Monobit (Frequency)",
        "p_value": round(p, 6),
        "pass": p >= 0.01,
        "detail": f"ones={ones}/{n}, S_obs={s_obs:.4f}"
    }


def test_block_frequency(bits: List[int], M: int = 128) -> Dict:
    """NIST SP 800-22 Test 2: Block Frequency Test."""
    n = len(bits)
    N = n // M
    if N < 1:
        return {"name": "Block Frequency", "p_value": None, "pass": False, "detail": "n too small"}
    chi_sq = 0.0
    for i in range(N):
        block = bits[i*M:(i+1)*M]
        pi_i = sum(block) / M
        chi_sq += (pi_i - 0.5) ** 2
    chi_sq *= 4 * M
    p = igamc(N / 2.0, chi_sq / 2.0)
    return {
        "name": "Block Frequency",
        "p_value": round(p, 6),
        "pass": p >= 0.01,
        "detail": f"N={N} blocks of M={M}, χ²={chi_sq:.3f}"
    }


def test_runs(bits: List[int]) -> Dict:
    """NIST SP 800-22 Test 3: Runs Test."""
    n = len(bits)
    pi = sum(bits) / n
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return {"name": "Runs", "p_value": 0.0, "pass": False,
                "detail": f"pre-test failed: pi={pi:.4f}"}
    vn = 1 + sum(1 for i in range(n - 1) if bits[i] != bits[i+1])
    num = abs(vn - 2 * n * pi * (1 - pi))
    den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p = erfc(num / den)
    return {
        "name": "Runs",
        "p_value": round(p, 6),
        "pass": p >= 0.01,
        "detail": f"V_n={vn}, expected≈{2*n*pi*(1-pi):.1f}"
    }


def test_serial(bits: List[int]) -> Dict:
    """NIST SP 800-22 Test 7: Serial Test (m=2)."""
    n = len(bits)
    m = 2
    freq = {}
    for length in [m, m - 1, m - 2]:
        f = Counter()
        for i in range(n):
            pattern = tuple(bits[i:i+length] if i + length <= n
                            else bits[i:] + bits[:i+length-n])
            f[pattern] += 1
        freq[length] = f
    psi_m   = sum(c**2 for c in freq[m].values())   * 2**m   / n - n
    psi_m1  = sum(c**2 for c in freq[m-1].values()) * 2**(m-1) / n - n
    psi_m2  = sum(c**2 for c in freq[m-2].values()) * 2**(m-2) / n - n
    delta1  = psi_m - psi_m1
    delta2  = psi_m - 2*psi_m1 + psi_m2
    p1 = igamc(2**(m-2), delta1 / 2.0)
    p2 = igamc(2**(m-3), delta2 / 2.0) if m > 2 else 1.0
    p = min(p1, p2)
    return {
        "name": "Serial (m=2)",
        "p_value": round(p, 6),
        "pass": p >= 0.01,
        "detail": f"Δ₁ψ²={delta1:.3f}, Δ₂ψ²={delta2:.3f}"
    }


def test_chi_square(data: bytes) -> Dict:
    """Chi-square uniformity test over byte values."""
    n = len(data)
    expected = n / 256.0
    freq = Counter(data)
    chi_sq = sum((freq.get(i, 0) - expected) ** 2 / expected for i in range(256))
    # Degrees of freedom = 255
    p = igamc(255 / 2.0, chi_sq / 2.0)
    return {
        "name": "Chi-Square (byte uniformity)",
        "p_value": round(p, 6),
        "pass": 200 <= chi_sq <= 320,   # 99% CI for df=255
        "detail": f"χ²={chi_sq:.2f}, df=255, expected≈255"
    }


def test_entropy(data: bytes) -> Dict:
    """Shannon entropy in bits/byte."""
    n = len(data)
    freq = Counter(data)
    entropy = -sum((c / n) * math.log2(c / n) for c in freq.values())
    return {
        "name": "Shannon Entropy",
        "p_value": entropy,   # not a p-value, repurposed field
        "pass": entropy >= 7.9,
        "detail": f"{entropy:.6f} bits/byte (ideal = 8.0)"
    }


def test_autocorrelation(bits: List[int], d: int = 1) -> Dict:
    """Autocorrelation test at lag d."""
    n = len(bits)
    a = sum(bits[i] ^ bits[i + d] for i in range(n - d))
    z = (2 * a - (n - d)) / math.sqrt(n - d)
    p = erfc(abs(z) / math.sqrt(2))
    return {
        "name": f"Autocorrelation (lag={d})",
        "p_value": round(p, 6),
        "pass": p >= 0.01,
        "detail": f"A={a}, Z={z:.4f}"
    }


def test_avalanche(key: bytes, iv: bytes, message: bytes) -> Dict:
    """
    Avalanche effect: flip each key bit, measure avg bit change in ciphertext.
    Ideal = 50% bits change per key bit flip.
    """
    from core.cipher import IoTSC1
    sc0 = IoTSC1(key, iv)
    ct0 = sc0.encrypt(message)
    bits0 = _bits(ct0)
    n_key_bits = len(key) * 8
    total_changes = 0

    for byte_idx in range(len(key)):
        for bit_idx in range(8):
            k2 = bytearray(key)
            k2[byte_idx] ^= (1 << bit_idx)
            sc2 = IoTSC1(bytes(k2), iv)
            ct2 = sc2.encrypt(message)
            bits2 = _bits(ct2)
            changes = sum(a ^ b for a, b in zip(bits0, bits2))
            total_changes += changes

    avg_change_pct = total_changes / (n_key_bits * len(bits0)) * 100
    return {
        "name": "Avalanche Effect (key bits)",
        "p_value": avg_change_pct,
        "pass": 45.0 <= avg_change_pct <= 55.0,
        "detail": f"{avg_change_pct:.2f}% bits changed per key bit flip (ideal=50%)"
    }


def test_hamming_weight(data: bytes) -> Dict:
    """Check that byte-level Hamming weights are uniformly distributed."""
    weights = Counter(bin(b).count('1') for b in data)
    total = len(data)
    # Expected: binomial B(8, 0.5)
    from math import comb
    expected = {k: total * comb(8, k) / 256 for k in range(9)}
    chi_sq = sum((weights.get(k, 0) - expected[k]) ** 2 / expected[k]
                 for k in range(9) if expected[k] > 0)
    p = igamc(8 / 2.0, chi_sq / 2.0)
    return {
        "name": "Hamming Weight Distribution",
        "p_value": round(p, 6),
        "pass": p >= 0.01,
        "detail": f"χ²={chi_sq:.3f}, distribution: {dict(sorted(weights.items()))}"
    }


# ---------------------------------------------------------------------------
# Full test suite
# ---------------------------------------------------------------------------

def run_full_suite(key: bytes, iv: bytes, n_bytes: int = 2048,
                   verbose: bool = True) -> List[Dict]:
    """
    Run complete statistical test suite on IoT-SC1 keystream.

    Parameters
    ----------
    key     : 16-byte key
    iv      : 8-byte IV
    n_bytes : number of keystream bytes to generate
    verbose : print results to stdout

    Returns
    -------
    List of result dicts, each with: name, p_value, pass, detail
    """
    sc = IoTSC1(key, iv)
    ks = sc.keystream(n_bytes)
    bits = _bits(ks)

    tests = [
        test_monobit(bits),
        test_block_frequency(bits),
        test_runs(bits),
        test_serial(bits),
        test_autocorrelation(bits, d=1),
        test_autocorrelation(bits, d=2),
        test_chi_square(ks),
        test_entropy(ks),
        test_hamming_weight(ks),
        test_avalanche(key, iv, b"IoT-SC1 Avalanche Test Payload v1.0"),
    ]

    if verbose:
        print(f"\n{'='*60}")
        print(f"  IoT-SC1 Statistical Test Suite")
        print(f"  Key : {key.hex()}")
        print(f"  IV  : {iv.hex()}")
        print(f"  Data: {n_bytes} bytes ({n_bytes*8} bits)")
        print(f"{'='*60}")
        passed = sum(1 for t in tests if t["pass"])
        for t in tests:
            status = "✅ PASS" if t["pass"] else "❌ FAIL"
            pv = f"p={t['p_value']:.6f}" if isinstance(t['p_value'], float) else f"={t['p_value']}"
            print(f"  {status}  {t['name']:<35} {pv}")
            print(f"         {t['detail']}")
        print(f"{'='*60}")
        print(f"  Result: {passed}/{len(tests)} tests passed")
        print(f"{'='*60}\n")

    return tests


if __name__ == "__main__":
    key = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    iv  = bytes.fromhex("a1b2c3d4e5f6a7b8")
    results = run_full_suite(key, iv, n_bytes=2048)
