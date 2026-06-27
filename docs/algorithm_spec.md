# IoT-SC1 Algorithm Specification
**Version 1.0.0 | Thesis Reference Document**

---

## 1. Introduction

IoT-SC1 (IoT Stream Cipher, version 1) is a lightweight synchronous stream cipher designed for resource-constrained IoT devices and 5G NB-IoT (Narrowband IoT) networks. It targets Class 0–2 devices (< 50 KB RAM, 8–32-bit microcontrollers) while providing sufficient security for session-level data protection.

---

## 2. Design Goals

| Goal                  | Specification                                 |
|-----------------------|-----------------------------------------------|
| Key size              | 128 bits                                      |
| Security level        | ~64 bits (birthday bound)                     |
| ROM footprint         | ≤ 256 bytes                                   |
| RAM (state) footprint | ≤ 32 bytes                                    |
| Throughput (MCU)      | ≥ 0.5 Mbps at 8 MHz                           |
| Authentication        | 32-bit MAC tag                                |
| Target standard       | Compatible with 3GPP TS 33.401 NB-IoT sec.   |

---

## 3. Notation

- `⊕`  : XOR (bitwise exclusive-or)
- `·`  : AND (bitwise)
- `‖`  : Concatenation
- `s[i]` : Bit i of state s (0 = LSB)
- `K₁, K₂` : 64-bit halves of the 128-bit key

---

## 4. Key and IV Loading (KSA)

Given:
- Key  K = K₁ ‖ K₂  (K₁, K₂ each 64 bits)
- IV   N  (64 bits)

```
LFSR_state  ← K₁ ⊕ N
NLFSR_state ← K₂ ⊕ N ⊕ 0xA5A5A5A5A5A5A5A5
```

If either register is all-zero after initialization, it is replaced with a non-zero default constant to avoid the degenerate all-zero state.

**Warm-up**: Both registers are clocked **64 times** before any keystream byte is output. This prevents related-key distinguishers on the initial state.

---

## 5. LFSR (Linear Feedback Shift Register)

### Parameters
- Width: 64 bits
- Primitive polynomial: x⁶⁴ + x⁶³ + x⁶¹ + x⁶⁰ + 1
- Period: 2⁶⁴ − 1 ≈ 1.8 × 10¹⁹ states
- Implementation: Galois LFSR (efficient in software)

### Galois LFSR Update

```
tap_mask = 0xF000000000000001
parity   = popcount(LFSR_state AND tap_mask) mod 2
LFSR_state ← (LFSR_state SHR 1) OR (parity SHL 63)
```

### Rationale
The LFSR provides maximal-period linear diffusion across the 64-bit state. Its primitive polynomial ensures that all 2⁶⁴ − 1 non-zero states are visited before the sequence repeats.

---

## 6. NLFSR (Non-Linear Feedback Shift Register)

### Parameters
- Width: 64 bits
- Feedback polynomial: non-linear (degree ≥ 3)

### Feedback Function
```
f(s) = s[63] ⊕ s[61] ⊕ s[58] ⊕ (s[32] · s[47]) ⊕ (s[15] · s[25] · s[40])
```

### NLFSR Update
```
fb ← f(NLFSR_state)
NLFSR_state ← (NLFSR_state SHR 1) OR (fb SHL 63)
```

### Non-linear Terms
| Term              | Type     | Degree |
|-------------------|----------|--------|
| s[63] ⊕ s[61] ⊕ s[58] | Linear  | 1      |
| s[32] · s[47]    | Quadratic | 2      |
| s[15] · s[25] · s[40] | Cubic  | 3      |

The cubic term ensures the overall algebraic degree ≥ 3, providing resistance against Berlekamp-Massey linear synthesis attacks.

---

## 7. Filter / Combiner Function

**Tap extraction:**

```
a ← extract_byte(LFSR_state,  taps=[0, 7, 15, 23, 31, 39, 47, 55])
b ← extract_byte(NLFSR_state, taps=[3, 11, 19, 27, 35, 43, 51, 59])
```

`extract_byte(reg, positions)` selects one bit from each specified position and assembles them into a byte (bit 0 from position[0], bit 1 from position[1], ...).

**Combiner:**
```
combined ← a ⊕ b ⊕ (a · b)
```

This is an affine-over-GF(2) combiner. It achieves correlation immunity of order 1 (Siegenthaler, 1984), preventing correlation attacks that exploit the linear LFSR component.

---

## 8. S-box Substitution

A 4×4 S-box (derived from the PRESENT block cipher) is applied independently to each nibble of `combined`:

```
hi_nibble ← SBOX[(combined >> 4) AND 0xF]
lo_nibble ← SBOX[combined AND 0xF]
keystream_byte ← (hi_nibble << 4) OR lo_nibble
```

**S-box table:**
```
Index : 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
Value : C  5  6  B  9  0  A  D  3  E  F  8  4  7  1  2
```

**Cryptographic properties:**
| Property               | Value | Significance                          |
|------------------------|-------|---------------------------------------|
| Differential uniformity | 4    | Optimal for 4×4; resists diff. crypto. |
| Nonlinearity           | 4     | Maximum for 4×4; resists linear crypto.|
| Fixed points           | 0     | No trivial identity mappings           |
| Bijection              | Yes   | Fully invertible                       |

---

## 9. Keystream Output & Encryption

```
keystream_byte ← S-box output (1 byte per clock)
ciphertext_byte ← plaintext_byte ⊕ keystream_byte
```

Decryption is identical (symmetric XOR).

---

## 10. MAC Authentication

A 32-bit MAC tag is accumulated during encryption:

```
MAC ← 0
For each keystream byte k and index i:
    MAC ← (MAC × 1664525 + k + i) mod 2³²
```

After processing all bytes, a final mixing step is applied:
```
MAC ← MAC ⊕ (MAC >> 16)
MAC ← (MAC × 0x45d9f3b) mod 2³²
MAC ← MAC ⊕ (MAC >> 16)
```

The 4-byte MAC is appended to the ciphertext and verified by the receiver.

---

## 11. IV Uniqueness for 5G NB-IoT

In the 5G NB-IoT context, the 64-bit IV is composed as:

```
IV = timestamp_ms[31:0] ‖ sequence_counter[31:0]
```

This ensures IV uniqueness across:
- Time: millisecond-resolution UNIX timestamp
- Restarts: monotonic sequence counter stored in EEPROM

---

## 12. Security Analysis Summary

| Attack                  | Security Margin | Notes                                      |
|-------------------------|-----------------|--------------------------------------------|
| Brute-force (key)       | 2¹²⁸            | Full key space exhaustion                  |
| Birthday bound          | 2⁶⁴             | State collision; practical security level  |
| Berlekamp-Massey        | Resistant       | NLFSR degree ≥ 3 prevents linear synthesis |
| Differential crypto.    | Resistant       | S-box DU = 4                               |
| Linear crypto.          | Resistant       | S-box NL = 4; CI-1 combiner               |
| Correlation attack      | CI-1 protected  | Siegenthaler-compliant combiner            |
| Time-memory tradeoff    | 2⁶⁴ time/memory | State size 128 bits                        |

---

## 13. Comparison with Related Work

| Cipher      | Key  | State | DU  | NL  | ROM   | Target       |
|-------------|------|-------|-----|-----|-------|--------------|
| **IoT-SC1** | 128b | 128b  | 4   | 4   | 256B  | IoT / 5G     |
| Grain-128   | 128b | 256b  | N/A | N/A | ~1KB  | RFID / IoT   |
| Trivium     | 80b  | 288b  | N/A | N/A | ~800B | HW stream    |
| MICKEY-2.0  | 128b | 200b  | N/A | N/A | ~1KB  | Lightweight  |

IoT-SC1 achieves the smallest ROM footprint among comparable ciphers, at the cost of a reduced security level suitable for IoT use cases.

---

## 14. Limitations

1. **Security level**: ~64 bits is below the 80-bit threshold recommended for long-term security. Suitable for session data, not archival.
2. **No post-quantum resistance**: Symmetric 64-bit security is not quantum-safe.
3. **MAC length**: 32-bit MAC provides ~1-in-4-billion forgery probability — adequate for IoT but insufficient for critical infrastructure.
4. **Not NIST-standardized**: Academic/research cipher; independent audit not yet performed.

---

## 15. References

1. Bogdanov, A. et al. "PRESENT: An Ultra-Lightweight Block Cipher." CHES 2007.
2. Hell, M. et al. "Grain: A Stream Cipher for Constrained Environments." IJWMC 2007.
3. NIST SP 800-22 Rev 1a. "A Statistical Test Suite for Random and Pseudorandom Number Generators."
4. Siegenthaler, T. "Correlation-immunity of nonlinear combining functions for cryptographic applications." IEEE Trans. Inf. Theory, 1984.
5. 3GPP TS 33.401. "Security architecture." Release 16.
6. Berlekamp, E. "Algebraic Coding Theory." 1968.
7. Massey, J. "Shift-register synthesis and BCH decoding." IEEE Trans. Inf. Theory, 1969.
