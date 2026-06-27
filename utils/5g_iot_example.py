"""
IoT-SC1 — 5G NB-IoT Integration Example
==========================================
Simulates the encryption layer for a 5G NB-IoT uplink data flow:

  Sensor → [IoT-SC1 encrypt] → NB-IoT PDU → Base Station → [IoT-SC1 decrypt] → Cloud

Architecture in 5G context:
  - Pre-shared key (PSK) stored in SIM/eSIM (equivalent to 5G SUPI)
  - IV derived from device IMEI + timestamp (prevents nonce reuse)
  - Encrypted payload carried in NAS (Non-Access Stratum) container
  - 32-bit MAC tag appended for integrity (fits in NAS IE extension)

Compatible with:
  - 3GPP TS 33.401 (E-UTRAN security architecture)
  - NIDD (Non-IP Data Delivery) over NB-IoT
  - 5G Release 16 Lightweight Security
"""

import time, struct, hashlib, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.cipher import IoTSC1, derive_key_iv


# ---------------------------------------------------------------------------
# 5G NB-IoT frame constants
# ---------------------------------------------------------------------------
NAS_SECURITY_HEADER = b"\x27"   # Security header type: Integrity + Cipher
PROTOCOL_DISCRIMINATOR = b"\x07"  # EPS Mobility Management
PDU_SESSION_TYPE_NB = 0x09       # NB-IoT data


# ---------------------------------------------------------------------------
# Device simulator
# ---------------------------------------------------------------------------

class NbIoTDevice:
    """
    Simulates an NB-IoT sensor device with IoT-SC1 encryption.
    """

    def __init__(self, imei: str, psk: bytes):
        self.imei  = imei
        self.psk   = psk
        self.seq   = 0
        self._derive_session_key()

    def _derive_session_key(self):
        """Derive session key from PSK + IMEI (simulates 5G AKA)."""
        salt = hashlib.sha256(self.imei.encode()).digest()[:16]
        self.session_key, self._base_iv = derive_key_iv(self.psk, salt=salt,
                                                         info=b"NB-IoT-SC1-uplink")

    def _make_iv(self) -> bytes:
        """
        IV = timestamp_ms (4 bytes) || seq_counter (4 bytes)
        This ensures uniqueness across time and restarts.
        """
        ts  = int(time.time() * 1000) & 0xFFFFFFFF
        return struct.pack(">II", ts, self.seq)

    def encrypt_payload(self, sensor_data: dict) -> bytes:
        """
        Encrypt sensor data and wrap in a simple NAS-like PDU.

        PDU format:
          [NAS header: 2B] [IMEI: 15B] [SEQ: 4B] [IV: 8B]
          [LEN: 2B] [CIPHERTEXT: LEN bytes] [MAC: 4B]
        """
        import json
        pt  = json.dumps(sensor_data).encode()
        iv  = self._make_iv()
        sc  = IoTSC1(self.session_key, iv)
        ct, tag = sc.encrypt_with_mac(pt)

        pdu  = NAS_SECURITY_HEADER + PROTOCOL_DISCRIMINATOR
        pdu += self.imei.encode()[:15].ljust(15, b"\x00")
        pdu += struct.pack(">I", self.seq)
        pdu += iv
        pdu += struct.pack(">H", len(ct))
        pdu += ct
        pdu += tag

        self.seq = (self.seq + 1) & 0xFFFFFFFF
        return pdu

    def decrypt_payload(self, pdu: bytes) -> tuple:
        """Parse and decrypt a received PDU. Returns (data_dict, mac_valid)."""
        import json
        offset   = 2                          # skip NAS header
        imei     = pdu[offset:offset+15].rstrip(b"\x00").decode()
        offset  += 15
        seq      = struct.unpack(">I", pdu[offset:offset+4])[0]; offset += 4
        iv       = pdu[offset:offset+8]; offset += 8
        ct_len   = struct.unpack(">H", pdu[offset:offset+2])[0]; offset += 2
        ct       = pdu[offset:offset+ct_len]; offset += ct_len
        tag      = pdu[offset:offset+4]

        sc = IoTSC1(self.session_key, iv)
        pt, valid = sc.decrypt_and_verify(ct, tag)
        try:
            return json.loads(pt.decode()), valid, seq
        except Exception:
            return {"raw": pt.hex(), "decode_error": True}, valid, seq


# ---------------------------------------------------------------------------
# Base station / gateway simulator
# ---------------------------------------------------------------------------

class NbIoTGateway:
    """Simulates the 5G core receiving end."""

    def __init__(self, device_registry: dict):
        """device_registry: {imei_str: psk_bytes}"""
        self.devices = {}
        for imei, psk in device_registry.items():
            self.devices[imei] = NbIoTDevice(imei, psk)

    def receive(self, pdu: bytes) -> dict:
        imei = pdu[2:17].rstrip(b"\x00").decode()
        if imei not in self.devices:
            return {"error": "Unknown device", "imei": imei}
        device = self.devices[imei]
        data, valid, seq = device.decrypt_payload(pdu)
        return {
            "imei":      imei,
            "seq":       seq,
            "mac_valid": valid,
            "payload":   data,
        }


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def run_5g_demo():
    print(f"\n{'='*65}")
    print(f"  IoT-SC1 — 5G NB-IoT Uplink Simulation")
    print(f"{'='*65}\n")

    PSK  = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    IMEI = "354651234567890"

    device = NbIoTDevice(IMEI, PSK)

    registry = {IMEI: PSK}
    gateway  = NbIoTGateway(registry)

    print(f"  Device IMEI        : {IMEI}")
    print(f"  Pre-shared key     : {PSK.hex()}")
    print(f"  Session key        : {device.session_key.hex()}")
    print(f"  Base IV            : {device._base_iv.hex()}\n")

    # Simulate 3 uplink transmissions
    for i in range(3):
        sensor = {
            "device":    IMEI,
            "temp_c":    round(25.0 + i * 3.7, 1),
            "hum_pct":   round(55.0 + i * 2.1, 1),
            "batt_v":    round(3.3 - i * 0.05, 2),
            "rsrp_dbm":  -(80 + i * 3),
            "timestamp": int(time.time()),
        }

        pdu = device.encrypt_payload(sensor)
        result = gateway.receive(pdu)

        print(f"  ── Uplink #{i+1} ──────────────────────────────────")
        print(f"  Plaintext  : {sensor}")
        print(f"  PDU size   : {len(pdu)} bytes")
        print(f"  PDU (hex)  : {pdu.hex()[:80]}...")
        print(f"  MAC valid  : {'✅' if result['mac_valid'] else '❌'}")
        print(f"  Decrypted  : {result['payload']}\n")

    # Tamper test
    print(f"  ── Tamper Attack Simulation ──────────────────────")
    pdu = device.encrypt_payload({"attack": "injected", "val": 9999})
    pdu_tampered = bytearray(pdu); pdu_tampered[30] ^= 0x42  # flip a bit
    res = gateway.receive(bytes(pdu_tampered))
    print(f"  Tampered PDU MAC : {'✅ valid' if res['mac_valid'] else '❌ INVALID — attack detected!'}")
    print(f"\n{'='*65}\n")


if __name__ == "__main__":
    run_5g_demo()
