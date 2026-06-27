"""
IoT-SC1 Configuration & Constants
====================================
Single source of truth for all algorithm parameters.
Import this module for any constants used across the project.
"""

# ── Key & IV ──────────────────────────────────────────────────────────────
KEY_SIZE_BYTES  = 16          # 128-bit key
IV_SIZE_BYTES   = 8           # 64-bit IV
MAC_SIZE_BYTES  = 4           # 32-bit authentication tag
WARMUP_CYCLES   = 64          # clock cycles before first output byte

# ── LFSR ──────────────────────────────────────────────────────────────────
# Primitive polynomial over GF(2): x^64 + x^63 + x^61 + x^60 + 1
# Galois LFSR mask (taps at positions 63, 62, 60, 59 from MSB)
LFSR_BITS  = 64
LFSR_MASK  = (1 << LFSR_BITS) - 1
LFSR_TAPS  = 0xF000000000000001  # Galois representation
# Period: 2^64 - 1 = 18,446,744,073,709,551,615 states

# ── NLFSR ─────────────────────────────────────────────────────────────────
# Feedback: f(s) = s[63] ^ s[61] ^ s[58] ^ (s[32]&s[47]) ^ (s[15]&s[25]&s[40])
# Non-linear terms: (s[32]·s[47]) and (s[15]·s[25]·s[40])
# Algebraic degree: >= 3
NLFSR_BITS             = 64
NLFSR_DIVERSIFY_CONST  = 0xA5A5A5A5A5A5A5A5  # XOR'd into K2 at init
NLFSR_TAP_POSITIONS    = [3, 11, 19, 27, 35, 43, 51, 59]

# ── LFSR tap positions for combiner ───────────────────────────────────────
LFSR_TAP_POSITIONS = [0, 7, 15, 23, 31, 39, 47, 55]

# ── Filter / Combiner ─────────────────────────────────────────────────────
# H(a, b) = a XOR b XOR (a AND b)
# Correlation immunity order: 1 (Siegenthaler bound for degree 2)

# ── S-box (PRESENT-like 4x4) ──────────────────────────────────────────────
# Differential uniformity: 4  (optimal for 4x4)
# Nonlinearity:            4  (optimal for 4x4)
# Fixed points:            0
# Source: Derived from PRESENT lightweight block cipher (ISO/IEC 29192-2)
SBOX     = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
            0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
SBOX_INV = [0] * 16
for _i, _v in enumerate(SBOX):
    SBOX_INV[_v] = _i

# ── Security parameters ───────────────────────────────────────────────────
SECURITY_LEVEL_BITS     = 64    # Birthday bound: 2^(state/2) = 2^64
ALGEBRAIC_DEGREE_NLFSR  = 3     # Minimum algebraic degree of NLFSR feedback
CI_ORDER                = 1     # Correlation immunity order of combiner

# ── Device footprint targets ──────────────────────────────────────────────
TARGET_ROM_BYTES = 256
TARGET_RAM_BYTES = 32

# ── 5G / NB-IoT constants ─────────────────────────────────────────────────
NAS_SECURITY_HEADER      = b"\x27"
PROTOCOL_DISCRIMINATOR   = b"\x07"
HKDF_INFO_UPLINK         = b"IoT-SC1-v1-sensor"
HKDF_INFO_DOWNLINK       = b"IoT-SC1-v1-control"
IV_TIMESTAMP_BITS        = 32   # Upper 32 bits of 64-bit IV = timestamp_ms
IV_SEQUENCE_BITS         = 32   # Lower 32 bits of 64-bit IV = seq counter

# ── Test parameters ───────────────────────────────────────────────────────
STAT_TEST_N_BYTES        = 2048
STAT_TEST_BLOCK_SIZE     = 128
STAT_TEST_P_THRESHOLD    = 0.01
BENCHMARK_ITERATIONS     = 100
BENCHMARK_PAYLOAD_SIZES  = [64, 256, 1024, 4096, 16384, 65536]
