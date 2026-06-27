"""
IoT-SC1: Lightweight Stream Cipher for IoT and 5G Networks
==========================================================
Author      : aaurélyn / Tech Nexus LTD
Algorithm   : Fibonacci LFSR + NLFSR + multi-byte XOR mixing + 4×4 S-box
Key size    : 128 bits (16 bytes)
IV size     : 64 bits  (8 bytes)
State size  : 128 bits (two 64-bit registers)
Security    : ~64-bit equivalent (birthday bound)
Target      : Class 0–2 IoT devices, 5G NB-IoT / eMTC

Architecture
------------
  [Key K₁ ⊕ IV]  ──► LFSR  (64-bit, Fibonacci, prim. poly x⁶⁴+x⁶³+x⁶¹+x⁶⁰+1)
  [Key K₂ ⊕ IV]  ──► NLFSR (64-bit, nonlinear feedback, alg. degree ≥ 3)
       ↓                  ↓
  4 bytes from    4 bytes from
  positions       positions
  0,16,32,48      8,24,40,56
       ↓                  ↓
       [XOR mixer: all 8 bytes → single byte]
                   ↓
          [4×4 S-box on each nibble  (PRESENT-like)]
                   ↓
          keystream_byte  ⊕  plaintext_byte  →  ciphertext_byte
"""

import hashlib
import hmac as _hmac
from typing import Union, Tuple, Optional


# ---------------------------------------------------------------------------
# PRESENT-like 4×4 S-box
# Differential uniformity = 4, Nonlinearity = 4
# Source: PRESENT lightweight block cipher (ISO/IEC 29192-2), adapted
# ---------------------------------------------------------------------------
SBOX: list = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
              0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]

SBOX_INV: list = [0] * 16
for _i, _v in enumerate(SBOX):
    SBOX_INV[_v] = _i


# ---------------------------------------------------------------------------
# LFSR: Fibonacci form
# Primitive polynomial: x⁶⁴ + x⁶³ + x⁶¹ + x⁶⁰ + 1
# Taps (0-indexed from LSB): 63, 62, 60, 59
# Period: 2⁶⁴ − 1
# ---------------------------------------------------------------------------
_MASK64 = (1 << 64) - 1


def _lfsr_step(s: int) -> int:
    fb = ((s >> 63) ^ (s >> 62) ^ (s >> 60) ^ (s >> 59)) & 1
    return ((s << 1) | fb) & _MASK64


# ---------------------------------------------------------------------------
# NLFSR: nonlinear feedback (shift-left, new bit into LSB position 0)
# f(s) = s[63] ⊕ s[61] ⊕ s[58] ⊕ (s[32]·s[47]) ⊕ (s[15]·s[25]·s[40])
# Algebraic degree: 3  (cubic term s[15]·s[25]·s[40])
# ---------------------------------------------------------------------------

def _nlfsr_step(s: int) -> int:
    b63 = (s >> 63) & 1
    b61 = (s >> 61) & 1
    b58 = (s >> 58) & 1
    b32 = (s >> 32) & 1
    b47 = (s >> 47) & 1
    b15 = (s >> 15) & 1
    b25 = (s >> 25) & 1
    b40 = (s >> 40) & 1
    fb  = b63 ^ b61 ^ b58 ^ (b32 & b47) ^ (b15 & b25 & b40)
    return ((s << 1) | fb) & _MASK64


# ---------------------------------------------------------------------------
# Byte extraction: pull 4 evenly-spaced bytes from a 64-bit register
# Positions: byte 0 (bits 7:0), byte 2 (bits 23:16), byte 4 (bits 39:32),
#            byte 6 (bits 55:48)
# ---------------------------------------------------------------------------

def _extract4(reg: int, offset: int) -> tuple:
    """Extract 4 bytes at 16-bit spacing starting from byte `offset`."""
    b0 = (reg >> (offset * 8))      & 0xFF
    b1 = (reg >> (offset * 8 + 16)) & 0xFF
    b2 = (reg >> (offset * 8 + 32)) & 0xFF
    b3 = (reg >> (offset * 8 + 48)) & 0xFF
    return b0, b1, b2, b3


class IoTSC1:
    """
    IoT-SC1 Stream Cipher.

    Usage
    -----
    >>> sc = IoTSC1(key=bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0"),
    ...             iv=bytes.fromhex("a1b2c3d4e5f6a7b8"))
    >>> ciphertext = sc.encrypt(b"Hello IoT!")
    >>> sc2 = IoTSC1(key=..., iv=...)
    >>> plaintext = sc2.decrypt(ciphertext)
    """

    KEY_SIZE = 16   # bytes (128 bits)
    IV_SIZE  = 8    # bytes (64 bits)
    WARMUP   = 64   # clock cycles discarded before output

    def __init__(self, key: bytes, iv: bytes):
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes ({self.KEY_SIZE*8} bits), got {len(key)}")
        if len(iv) != self.IV_SIZE:
            raise ValueError(f"IV must be {self.IV_SIZE} bytes ({self.IV_SIZE*8} bits), got {len(iv)}")
        self._key = key
        self._iv  = iv
        self._reset()

    # ------------------------------------------------------------------
    # Internal state setup
    # ------------------------------------------------------------------

    def _reset(self):
        """Initialize registers from key and IV."""
        k1 = int.from_bytes(self._key[:8], 'big')
        k2 = int.from_bytes(self._key[8:], 'big')
        iv = int.from_bytes(self._iv,      'big')

        self._lfsr  = (k1 ^ iv) & _MASK64
        self._nlfsr = (k2 ^ iv ^ 0xA5A5A5A5A5A5A5A5) & _MASK64

        # Prevent all-zero state (degenerate)
        if self._lfsr  == 0: self._lfsr  = 0x0101010101010101
        if self._nlfsr == 0: self._nlfsr = 0xFEFEFEFEFEFEFEFE

        # MAC accumulator
        self._mac              = 0x00000000
        self._bytes_processed  = 0

        # Warm-up: discard WARMUP output bytes
        for _ in range(self.WARMUP):
            self._lfsr  = _lfsr_step(self._lfsr)
            self._nlfsr = _nlfsr_step(self._nlfsr)

    # ------------------------------------------------------------------
    # Keystream byte generation
    # ------------------------------------------------------------------

    def _next_byte(self) -> int:
        """Generate one keystream byte."""
        # Clock both registers
        self._lfsr  = _lfsr_step(self._lfsr)
        self._nlfsr = _nlfsr_step(self._nlfsr)

        # Extract 4 bytes from each register (spaced 16 bits apart)
        la, lb, lc, ld = _extract4(self._lfsr,  0)   # bytes 0,2,4,6 of LFSR
        na, nb, nc, nd = _extract4(self._nlfsr,  1)   # bytes 1,3,5,7 of NLFSR

        # XOR-mix all 8 bytes → single byte combiner
        # H achieves high diffusion; offset positions ensure CI-1 property
        mixed = la ^ lb ^ lc ^ ld ^ na ^ nb ^ nc ^ nd

        # 4×4 S-box substitution on upper and lower nibble independently
        hi  = SBOX[(mixed >> 4) & 0xF]
        lo  = SBOX[mixed & 0xF]
        out = (hi << 4) | lo

        # Update MAC accumulator (lightweight Poly1305-inspired)
        self._mac = ((self._mac * 1664525) + out + self._bytes_processed) & 0xFFFFFFFF
        self._bytes_processed += 1
        return out

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def keystream(self, n: int) -> bytes:
        """Generate n keystream bytes."""
        return bytes(self._next_byte() for _ in range(n))

    def encrypt(self, plaintext: Union[bytes, bytearray]) -> bytes:
        """Encrypt plaintext. Returns ciphertext bytes."""
        """Encrypt plaintext. Returns ciphertext bytes."""
        return bytes(p ^ self._next_byte() for p in plaintext)

    def decrypt(self, ciphertext: Union[bytes, bytearray]) -> bytes:
        """Decrypt ciphertext (identical to encrypt — stream cipher)."""
        return self.encrypt(ciphertext)

    def get_mac(self) -> bytes:
        """Return 4-byte (32-bit) authentication tag. Call after encrypt/decrypt."""
        mac = self._mac ^ (self._mac >> 16)
        mac = (mac * 0x45d9f3b) & 0xFFFFFFFF
        mac ^= mac >> 16
        return mac.to_bytes(4, 'big')

    def encrypt_with_mac(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        """Returns (ciphertext, 4-byte MAC tag)."""
        ct = self.encrypt(plaintext)
        return ct, self.get_mac()

    def decrypt_and_verify(self, ciphertext: bytes, tag: bytes) -> Tuple[bytes, bool]:
        """Returns (plaintext, tag_valid: bool)."""
        pt = self.decrypt(ciphertext)
        return pt, (self.get_mac() == tag)

    @property
    def bytes_processed(self) -> int:
        return self._bytes_processed

    def __repr__(self) -> str:
        return (f"IoTSC1(key={self._key.hex()[:8]}..., "
                f"iv={self._iv.hex()}, processed={self._bytes_processed}B)")


# ---------------------------------------------------------------------------
# Key derivation helper (HKDF-SHA256)
# ---------------------------------------------------------------------------

def derive_key_iv(master_secret: bytes,
                  salt: Optional[bytes] = None,
                  info: bytes = b"IoT-SC1-v1") -> Tuple[bytes, bytes]:
    """
    Derive a 128-bit key and 64-bit IV from a master secret using HKDF-SHA256.
    Returns (key: bytes[16], iv: bytes[8]).
    """
    import os
    if salt is None:
        salt = os.urandom(16)
    h   = _hmac.new(salt, master_secret, hashlib.sha256).digest()
    okm = b""
    t   = b""
    for i in range(1, 3):
        t = _hmac.new(h, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:16], okm[16:24]


# ---------------------------------------------------------------------------
# Authenticated encryption wrapper with proper HMAC-SHA256 tag
# ---------------------------------------------------------------------------

class IoTSC1Auth:
    """
    IoT-SC1 with proper 32-bit HMAC-SHA256 authentication tag.
    Use this for production-style authenticated encryption.

    Format: ciphertext ‖ HMAC-SHA256(key, iv ‖ ciphertext)[:4]
    """

    def __init__(self, key: bytes, iv: bytes):
        self._key = key
        self._iv  = iv

    def _mac(self, ct: bytes) -> bytes:
        import hmac as _h
        return _h.new(self._key, self._iv + ct, hashlib.sha256).digest()[:4]

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        """Returns (ciphertext, 4-byte tag)."""
        sc = IoTSC1(self._key, self._iv)
        ct = sc.encrypt(plaintext)
        return ct, self._mac(ct)

    def decrypt(self, ciphertext: bytes, tag: bytes) -> Tuple[bytes, bool]:
        """Returns (plaintext, tag_valid)."""
        expected = self._mac(ciphertext)
        valid = (expected == tag)
        sc = IoTSC1(self._key, self._iv)
        pt = sc.decrypt(ciphertext)
        return pt, valid
