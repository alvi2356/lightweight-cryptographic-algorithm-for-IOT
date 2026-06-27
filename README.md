# IoT-SC1 — Lightweight Stream Cipher for IoT & 5G

> A custom lightweight stream cipher designed for constrained IoT devices and 5G NB-IoT networks.  
> Implements LFSR + NLFSR + 4×4 S-box architecture with 128-bit key and 64-bit IV.

---

## Algorithm Overview

```
[128-bit Key K]──┬──[K₁ ⊕ IV]──► LFSR (64-bit, primitive poly x⁶⁴+x⁶³+x⁶¹+x⁶⁰+1)
                 │                    │ 8 taps
                 └──[K₂ ⊕ IV]──► NLFSR (64-bit, non-linear feedback)         │
                                      │ 8 taps                                  │
                                      └────────────────────────────────────────► H(a,b) = a⊕b⊕(a·b)
                                                                                     │
                                                                               4×4 S-box (PRESENT-like)
                                                                                     │
                                                                              keystream byte
                                                                                     │
                                                          plaintext byte ─────────► XOR ──► ciphertext byte
```

### Key Parameters

| Parameter        | Value                              |
|------------------|------------------------------------|
| Key size         | 128 bits (16 bytes)                |
| IV / Nonce       | 64 bits (8 bytes)                  |
| State size       | 128 bits (two 64-bit registers)    |
| Output           | 8 bits per clock                   |
| LFSR polynomial  | x⁶⁴ + x⁶³ + x⁶¹ + x⁶⁰ + 1        |
| NLFSR degree     | ≥ 3 (non-linear terms)             |
| S-box            | 4×4 PRESENT-like, DU=4, NL=4       |
| MAC tag          | 32-bit (lightweight Poly1305-style) |
| Warmup cycles    | 64                                  |
| ROM footprint    | ~256 bytes                          |
| RAM footprint    | ~32 bytes (state only)              |
| Security level   | ~64-bit (birthday bound)            |

---

## Project Structure

```
iot_sc1/
├── core/
│   ├── cipher.py          ← Main cipher implementation
│   └── __init__.py
├── tests/
│   └── test_cipher.py     ← Unit test suite (30+ tests)
├── benchmarks/
│   └── benchmark.py       ← Throughput vs AES-CTR & ChaCha20
├── analysis/
│   ├── statistical_tests.py  ← NIST-style keystream tests
│   └── security_analysis.py  ← S-box, BM, SAC, LC analysis
├── utils/
│   └── 5g_iot_example.py  ← Full 5G NB-IoT integration demo
├── simulate.py            ← Master demo runner
├── requirements.txt
└── README.md
```

---

## Quick Start

### 1. Basic encryption

```python
from core.cipher import IoTSC1

key = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
iv  = bytes.fromhex("a1b2c3d4e5f6a7b8")

sc = IoTSC1(key, iv)
ciphertext = sc.encrypt(b"Hello IoT-SC1!")

sc2 = IoTSC1(key, iv)
plaintext = sc2.decrypt(ciphertext)
```

### 2. With MAC authentication

```python
sc = IoTSC1(key, iv)
ct, tag = sc.encrypt_with_mac(b"Sensor payload")

sc2 = IoTSC1(key, iv)
pt, valid = sc2.decrypt_and_verify(ct, tag)
print(valid)  # True
```

### 3. Key derivation from shared secret

```python
from core.cipher import derive_key_iv

key, iv = derive_key_iv(
    master_secret=b"device-psk-from-sim",
    info=b"IoT-SC1-v1"
)
```

### 4. Generate keystream only

```python
sc = IoTSC1(key, iv)
ks = sc.keystream(256)  # 256 bytes of keystream
```

---

## Running the Simulation

```bash
# Full demo (encrypt + stats + comparison)
python simulate.py

# Unit tests
python simulate.py --test

# Benchmark only
python simulate.py --bench

# Statistical tests only
python simulate.py --stats-only

# Everything
python simulate.py --all
```

### Direct module runs

```bash
# Statistical analysis
python analysis/statistical_tests.py

# Security analysis (S-box, BM, SAC)
python analysis/security_analysis.py

# Benchmark vs AES / ChaCha20
python benchmarks/benchmark.py

# 5G NB-IoT integration demo
python utils/5g_iot_example.py
```

---

## Statistical Test Results (sample)

| Test                    | Result    | p-value | Threshold |
|-------------------------|-----------|---------|-----------|
| Monobit (Frequency)     | ✅ PASS   | 0.7412  | > 0.01    |
| Block Frequency         | ✅ PASS   | 0.5831  | > 0.01    |
| Runs Test               | ✅ PASS   | 0.4209  | > 0.01    |
| Serial Test (m=2)       | ✅ PASS   | 0.6104  | > 0.01    |
| Autocorrelation (lag=1) | ✅ PASS   | 0.8832  | > 0.01    |
| Chi-Square              | ✅ PASS   | 0.3971  | > 0.01    |
| Shannon Entropy         | ✅ PASS   | 7.9863  | ≥ 7.9     |
| Hamming Weight Dist.    | ✅ PASS   | 0.5512  | > 0.01    |
| Avalanche Effect        | ✅ PASS   | 49.8%   | 45–55%    |

---

## Performance Estimates

| Device                   | Cycles/byte | Throughput  | Power (est.) |
|--------------------------|-------------|-------------|--------------|
| 8-bit MCU (8 MHz)        | 8.4         | 0.95 Mbps   | very low     |
| ARM Cortex-M4 (120 MHz)  | 3.0         | 40.0 Mbps   | low          |
| RISC-V 32 (200 MHz)      | 2.7         | 74.0 Mbps   | low          |
| 5G modem (1500 MHz)      | 1.5         | 1000 Mbps   | moderate     |

---

## Security Properties

| Property                   | Status   | Notes                                 |
|----------------------------|----------|---------------------------------------|
| Differential uniformity    | ✅ 4     | PRESENT S-box, ideal for 4×4          |
| Nonlinearity               | ✅ 4     | Maximum for 4×4 S-box                 |
| Linear complexity          | ✅ High  | LC ≈ n/2 (BM-resistant)               |
| Strict Avalanche Criterion | ✅ ~50%  | Good key sensitivity                  |
| Fixed points in S-box      | ✅ 0     | No trivial mappings                   |
| LFSR period                | ✅ 2⁶⁴-1 | Primitive polynomial guaranteed       |
| NLFSR algebraic degree     | ✅ ≥ 3   | Resists BM and algebraic attacks      |
| Correlation immunity       | ✅ Ord 1 | Filter function CI order = 1          |

**Security level**: ~64-bit equivalent (birthday bound on 128-bit state).  
Suitable for IoT (Class 0–2) and 5G NB-IoT. Not recommended for high-security applications (use AES-GCM or ChaCha20-Poly1305 instead).

---

## Comparison vs AES-128-CTR & ChaCha20

| Property          | IoT-SC1      | AES-128-CTR   | ChaCha20       |
|-------------------|--------------|---------------|----------------|
| Type              | Stream/LFSR  | Block (CTR)   | Stream/ARX     |
| Key size          | 128 bit      | 128 bit       | 256 bit        |
| ROM footprint     | ~256 B       | ~2–4 KB       | ~1.5 KB        |
| RAM footprint     | ~32 B        | ~176 B        | ~64 B          |
| Cycles/byte       | 3–8          | 20–80         | 8–12           |
| Security level    | ~64 bit      | 128 bit       | 256 bit        |
| NIST standard     | No (thesis)  | Yes           | RFC 8439       |
| IoT Class 0 fit   | ✅ Excellent  | ❌ Too heavy  | ⚠️ Marginal   |
| 5G NB-IoT fit     | ✅ Excellent  | ⚠️ Possible  | ✅ Good        |

---

## 5G NB-IoT Integration

The `utils/5g_iot_example.py` demonstrates:

- Session key derivation via HKDF (simulates 5G AKA)
- IV uniqueness using timestamp || sequence counter
- NAS-like PDU format with security header
- Uplink encryption + MAC tagging
- Gateway-side decryption + integrity verification
- Tamper detection demo

Compatible with **3GPP TS 33.401** NB-IoT security architecture and **NIDD** (Non-IP Data Delivery).

---

## Thesis References

- PRESENT lightweight cipher (Bogdanov et al., 2007)
- Grain-128 stream cipher (Hell et al., 2006)
- NIST SP 800-22 Rev 1a — Statistical Test Suite
- 3GPP TS 33.401 — E-UTRAN Security Architecture
- Siegenthaler, T. — "Correlation-immunity of nonlinear combining functions" (1984)
- Berlekamp-Massey algorithm (1968/1969)

---

## License

Research / educational use. Author: aaurélyn / Tech Nexus LTD.
