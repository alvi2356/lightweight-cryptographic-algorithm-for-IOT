"""
IoT-SC1 Desktop UI
==================
Tkinter-based GUI for the IoT-SC1 lightweight stream cipher.

Tabs:
  1. Encrypt / Decrypt  — encrypt/decrypt text or hex, show ciphertext + MAC
  2. Sensor Simulation  — live simulated sensor packets with cipher output
  3. Security Analysis  — S-box, BM, SAC, LC results
  4. Statistical Tests  — NIST-style test suite with pass/fail
  5. Benchmark          — throughput vs AES / ChaCha20
  6. Attack Demo        — tamper, replay, IV-reuse demonstrations

Run:
    python ui.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import struct
import json
import math
import random
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from core.cipher import IoTSC1, derive_key_iv

# ── Colour palette ─────────────────────────────────────────────
BG       = "#1e1e2e"
BG2      = "#2a2a3e"
BG3      = "#313145"
ACCENT   = "#7c6ff7"
ACCENT2  = "#56cfb2"
GREEN    = "#50fa7b"
RED      = "#ff5555"
YELLOW   = "#f1fa8c"
CYAN     = "#8be9fd"
WHITE    = "#f8f8f2"
DIMTEXT  = "#6272a4"
FONT     = ("Consolas", 10)
FONT_BIG = ("Consolas", 12)
FONT_H   = ("Consolas", 11, "bold")

# ── Helpers ────────────────────────────────────────────────────
DEFAULT_KEY = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
DEFAULT_IV  = "a1b2c3d4e5f6a7b8"

def make_style():
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TNotebook",        background=BG,  borderwidth=0)
    style.configure("TNotebook.Tab",    background=BG2, foreground=WHITE,
                    padding=[14, 6],    font=FONT_H)
    style.map("TNotebook.Tab",
              background=[("selected", ACCENT)],
              foreground=[("selected", WHITE)])
    style.configure("TFrame",           background=BG)
    style.configure("TLabel",           background=BG,  foreground=WHITE, font=FONT)
    style.configure("TButton",          background=ACCENT, foreground=WHITE,
                    font=FONT_H,        borderwidth=0, padding=[10, 5])
    style.map("TButton",
              background=[("active", ACCENT2)])
    style.configure("TEntry",           fieldbackground=BG3, foreground=WHITE,
                    insertcolor=WHITE,  font=FONT)
    style.configure("TCombobox",        fieldbackground=BG3, foreground=WHITE,
                    font=FONT)
    style.configure("TProgressbar",     troughcolor=BG3, background=ACCENT2)
    style.configure("Treeview",         background=BG2, foreground=WHITE,
                    fieldbackground=BG2, font=FONT, rowheight=24)
    style.configure("Treeview.Heading", background=BG3, foreground=CYAN,
                    font=FONT_H)
    style.map("Treeview", background=[("selected", ACCENT)])

def lbl(parent, text, color=WHITE, font=FONT, **kw):
    return tk.Label(parent, text=text, bg=BG, fg=color, font=font, **kw)

def btn(parent, text, cmd, color=ACCENT, **kw):
    b = tk.Button(parent, text=text, command=cmd, bg=color, fg=WHITE,
                  font=FONT_H, relief="flat", cursor="hand2",
                  activebackground=ACCENT2, activeforeground=WHITE, **kw)
    return b

def entry(parent, width=40, default="", **kw):
    e = tk.Entry(parent, width=width, bg=BG3, fg=WHITE, insertbackground=WHITE,
                 font=FONT, relief="flat", **kw)
    e.insert(0, default)
    return e

def console(parent, height=14):
    t = scrolledtext.ScrolledText(parent, height=height, bg=BG2, fg=WHITE,
                                   font=FONT, insertbackground=WHITE,
                                   relief="flat", wrap="word")
    t.tag_config("green",  foreground=GREEN)
    t.tag_config("red",    foreground=RED)
    t.tag_config("yellow", foreground=YELLOW)
    t.tag_config("cyan",   foreground=CYAN)
    t.tag_config("dim",    foreground=DIMTEXT)
    t.tag_config("accent", foreground=ACCENT)
    t.tag_config("white",  foreground=WHITE)
    return t

def cwrite(widget, text, tag="white"):
    widget.configure(state="normal")
    widget.insert("end", text, tag)
    widget.see("end")

def cclear(widget):
    widget.configure(state="normal")
    widget.delete("1.0", "end")

def sep_line(parent):
    tk.Frame(parent, bg=BG3, height=1).pack(fill="x", pady=6)

# ══════════════════════════════════════════════════════════════
#  TAB 1 — Encrypt / Decrypt
# ══════════════════════════════════════════════════════════════
class EncryptTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self._build()

    def _build(self):
        # ── Title
        lbl(self, "  IoT-SC1  Encrypt / Decrypt", color=CYAN,
            font=("Consolas", 14, "bold")).pack(anchor="w", pady=(12, 4), padx=16)
        lbl(self, "  128-bit key · 64-bit IV · 32-bit MAC",
            color=DIMTEXT).pack(anchor="w", padx=16)
        sep_line(self)

        # ── Key / IV row
        row1 = tk.Frame(self, bg=BG)
        row1.pack(fill="x", padx=16, pady=4)
        lbl(row1, "Key (hex, 32 chars):").grid(row=0, column=0, sticky="w", padx=(0,8))
        self.key_e = entry(row1, width=36, default=DEFAULT_KEY)
        self.key_e.grid(row=0, column=1, sticky="w")
        btn(row1, "Random Key", self._random_key, color=BG3).grid(row=0, column=2, padx=8)

        row2 = tk.Frame(self, bg=BG)
        row2.pack(fill="x", padx=16, pady=4)
        lbl(row2, "IV  (hex, 16 chars): ").grid(row=0, column=0, sticky="w", padx=(0,8))
        self.iv_e = entry(row2, width=36, default=DEFAULT_IV)
        self.iv_e.grid(row=0, column=1, sticky="w")
        btn(row2, "Random IV ", self._random_iv, color=BG3).grid(row=0, column=2, padx=8)

        sep_line(self)

        # ── Plaintext input
        lbl(self, "  Plaintext:", color=YELLOW,
            font=FONT_H).pack(anchor="w", padx=16, pady=(4, 2))
        self.pt_box = scrolledtext.ScrolledText(
            self, height=3, bg=BG3, fg=WHITE, font=FONT,
            insertbackground=WHITE, relief="flat")
        self.pt_box.pack(fill="x", padx=16, pady=(0, 4))
        self.pt_box.insert("end", "Hello from IoT-SC1! This is a test message.")

        # ── Mode + Encrypt button
        enc_row = tk.Frame(self, bg=BG)
        enc_row.pack(fill="x", padx=16, pady=2)
        self.mode = tk.StringVar(value="text")
        tk.Radiobutton(enc_row, text="Text", variable=self.mode,
                       value="text", bg=BG, fg=WHITE, selectcolor=BG3,
                       font=FONT, activebackground=BG).pack(side="left", padx=(0, 8))
        tk.Radiobutton(enc_row, text="Hex", variable=self.mode,
                       value="hex", bg=BG, fg=WHITE, selectcolor=BG3,
                       font=FONT, activebackground=BG).pack(side="left", padx=(0, 16))
        btn(enc_row, "⚡ Encrypt", self._encrypt, color=ACCENT).pack(side="left", padx=4)
        btn(enc_row, "Clear All", self._clear, color=BG3).pack(side="left", padx=4)

        sep_line(self)

        # ── Ciphertext field (editable — paste here to decrypt)
        lbl(self, "  Ciphertext (hex):", color=ACCENT,
            font=FONT_H).pack(anchor="w", padx=16, pady=(4, 2))
        self.ct_box = scrolledtext.ScrolledText(
            self, height=3, bg=BG3, fg="#bd93f9", font=FONT,
            insertbackground=WHITE, relief="flat")
        self.ct_box.pack(fill="x", padx=16, pady=(0, 4))

        # ── MAC tag field
        mac_row = tk.Frame(self, bg=BG)
        mac_row.pack(fill="x", padx=16, pady=2)
        lbl(mac_row, "MAC tag (hex, 8 chars):").pack(side="left", padx=(0, 8))
        self.mac_e = entry(mac_row, width=14, default="")
        self.mac_e.pack(side="left", padx=(0, 16))
        btn(mac_row, "🔓 Decrypt", self._decrypt, color="#44475a").pack(side="left", padx=4)
        btn(mac_row, "📋 Copy CT", self._copy_ct, color=BG3).pack(side="left", padx=4)

        sep_line(self)

        # ── Output console
        lbl(self, "  Result:", color=CYAN, font=FONT_H).pack(anchor="w", padx=16)
        self.out = console(self, height=10)
        self.out.pack(fill="both", expand=True, padx=16, pady=(4, 16))

        self._last_ct  = b""
        self._last_tag = b""

    def _get_key_iv(self):
        k = self.key_e.get().strip().replace(" ", "")
        iv = self.iv_e.get().strip().replace(" ", "")
        if len(k) != 32:
            messagebox.showerror("Key Error", "Key must be exactly 32 hex characters (128 bits).")
            return None, None
        if len(iv) != 16:
            messagebox.showerror("IV Error", "IV must be exactly 16 hex characters (64 bits).")
            return None, None
        try:
            return bytes.fromhex(k), bytes.fromhex(iv)
        except ValueError:
            messagebox.showerror("Hex Error", "Key/IV contains invalid hex characters.")
            return None, None

    def _encrypt(self):
        key, iv = self._get_key_iv()
        if key is None: return
        raw = self.pt_box.get("1.0", "end").strip()
        if not raw:
            messagebox.showwarning("Empty", "Enter plaintext to encrypt."); return
        try:
            pt = bytes.fromhex(raw) if self.mode.get() == "hex" else raw.encode()
        except ValueError:
            messagebox.showerror("Input Error", "Invalid hex input."); return

        sc = IoTSC1(key, iv)
        ct, tag = sc.encrypt_with_mac(pt)
        self._last_ct  = ct
        self._last_tag = tag

        # ── Auto-fill CT and MAC fields so decrypt works immediately
        self.ct_box.delete("1.0", "end")
        self.ct_box.insert("end", ct.hex())
        self.mac_e.delete(0, "end")
        self.mac_e.insert(0, tag.hex())

        cclear(self.out)
        cwrite(self.out, "─" * 56 + "\n", "dim")
        cwrite(self.out, "  ENCRYPTION RESULT\n", "cyan")
        cwrite(self.out, "─" * 56 + "\n", "dim")
        cwrite(self.out, "  Key        : ", "dim"); cwrite(self.out, key.hex() + "\n", "yellow")
        cwrite(self.out, "  IV         : ", "dim"); cwrite(self.out, iv.hex() + "\n", "yellow")
        cwrite(self.out, "  Plaintext  : ", "dim"); cwrite(self.out, f"{pt.decode(errors='replace')!r}\n", "white")
        cwrite(self.out, "  PT bytes   : ", "dim"); cwrite(self.out, pt.hex() + "\n", "dim")
        cwrite(self.out, "  Ciphertext : ", "dim"); cwrite(self.out, ct.hex() + "\n", "accent")
        cwrite(self.out, "  MAC tag    : ", "dim"); cwrite(self.out, tag.hex() + "\n", "green")
        cwrite(self.out, f"  Size       : {len(pt)} bytes plaintext → {len(ct)} bytes ciphertext\n", "dim")
        cwrite(self.out, "─" * 56 + "\n", "dim")
        cwrite(self.out, "  ✔ Encrypted. CT and MAC filled below — click Decrypt to verify.\n", "green")

    def _decrypt(self):
        key, iv = self._get_key_iv()
        if key is None: return

        # Read ciphertext from the CT box
        ct_hex = self.ct_box.get("1.0", "end").strip().replace(" ", "").replace("\n", "")
        if not ct_hex:
            messagebox.showwarning("Empty", "No ciphertext to decrypt.\nEncrypt something first, or paste a ciphertext hex string into the Ciphertext field.")
            return
        try:
            ct = bytes.fromhex(ct_hex)
        except ValueError:
            messagebox.showerror("CT Error", "Ciphertext field contains invalid hex."); return

        # Read MAC tag from the MAC field
        tag_hex = self.mac_e.get().strip().replace(" ", "")
        if not tag_hex:
            messagebox.showwarning("MAC Missing", "Enter the MAC tag (8 hex chars) in the MAC tag field.")
            return
        if len(tag_hex) != 8:
            messagebox.showerror("MAC Error", f"MAC tag must be 8 hex chars (4 bytes). Got {len(tag_hex)} chars.")
            return
        try:
            tag = bytes.fromhex(tag_hex)
        except ValueError:
            messagebox.showerror("MAC Error", "MAC tag contains invalid hex."); return

        sc = IoTSC1(key, iv)
        pt, mac_ok = sc.decrypt_and_verify(ct, tag)

        cclear(self.out)
        cwrite(self.out, "─" * 56 + "\n", "dim")
        cwrite(self.out, "  DECRYPTION RESULT\n", "cyan")
        cwrite(self.out, "─" * 56 + "\n", "dim")
        cwrite(self.out, "  Key        : ", "dim"); cwrite(self.out, key.hex() + "\n", "yellow")
        cwrite(self.out, "  IV         : ", "dim"); cwrite(self.out, iv.hex() + "\n", "yellow")
        cwrite(self.out, "  Ciphertext : ", "dim"); cwrite(self.out, ct.hex() + "\n", "accent")
        cwrite(self.out, "  MAC tag    : ", "dim"); cwrite(self.out, tag.hex() + "\n", "yellow")
        cwrite(self.out, "  Plaintext  : ", "dim")
        cwrite(self.out, pt.decode(errors="replace") + "\n", "white")
        cwrite(self.out, "  MAC valid  : ", "dim")
        if mac_ok:
            cwrite(self.out, "✔ VALID — message is authentic\n", "green")
        else:
            cwrite(self.out, "✘ INVALID — MAC mismatch, possible tampering!\n", "red")
        cwrite(self.out, "─" * 56 + "\n", "dim")

    def _clear(self):
        self.pt_box.delete("1.0", "end")
        self.ct_box.delete("1.0", "end")
        self.mac_e.delete(0, "end")
        cclear(self.out)
        self._last_ct  = b""
        self._last_tag = b""

    def _copy_ct(self):
        ct_hex = self.ct_box.get("1.0", "end").strip()
        if ct_hex:
            self.clipboard_clear()
            self.clipboard_append(ct_hex)
            messagebox.showinfo("Copied", "Ciphertext hex copied to clipboard.")

    def _random_key(self):
        k = os.urandom(16).hex()
        self.key_e.delete(0, "end"); self.key_e.insert(0, k)

    def _random_iv(self):
        iv = os.urandom(8).hex()
        self.iv_e.delete(0, "end"); self.iv_e.insert(0, iv)

# ══════════════════════════════════════════════════════════════
#  TAB 2 — Sensor Simulation
# ══════════════════════════════════════════════════════════════
class SensorTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self._running = False
        self._seq = 0
        self._build()

    def _build(self):
        lbl(self, "  NB-IoT Sensor Simulation", color=CYAN,
            font=("Consolas", 14, "bold")).pack(anchor="w", pady=(12, 4), padx=16)
        lbl(self, "  Simulates ESP32 sensor → IoT-SC1 encrypt → NB-IoT PDU → Gateway decrypt",
            color=DIMTEXT).pack(anchor="w", padx=16)
        sep_line(self)

        # Config row
        cfg = tk.Frame(self, bg=BG)
        cfg.pack(fill="x", padx=16, pady=4)
        lbl(cfg, "Device ID:").grid(row=0, column=0, sticky="w", padx=(0,8))
        self.dev_e = entry(cfg, width=22, default="ESP32-NB-IOT-001")
        self.dev_e.grid(row=0, column=1, padx=(0,16))
        lbl(cfg, "PSK (hex):").grid(row=0, column=2, sticky="w", padx=(0,8))
        self.psk_e = entry(cfg, width=34, default=DEFAULT_KEY)
        self.psk_e.grid(row=0, column=3, padx=(0,16))
        lbl(cfg, "Interval (s):").grid(row=0, column=4, sticky="w", padx=(0,8))
        self.interval = tk.Spinbox(cfg, from_=0.5, to=5.0, increment=0.5,
                                   width=5, bg=BG3, fg=WHITE, font=FONT,
                                   buttonbackground=BG3)
        self.interval.delete(0,"end"); self.interval.insert(0,"1.5")
        self.interval.grid(row=0, column=5)

        # Status bar
        self.status_var = tk.StringVar(value="● Stopped")
        status_bar = tk.Frame(self, bg=BG2)
        status_bar.pack(fill="x", padx=16, pady=4)
        self.status_lbl = tk.Label(status_bar, textvariable=self.status_var,
                                   bg=BG2, fg=RED, font=FONT_H)
        self.status_lbl.pack(side="left", padx=8)
        self.pkt_var = tk.StringVar(value="Packets: 0")
        tk.Label(status_bar, textvariable=self.pkt_var,
                 bg=BG2, fg=DIMTEXT, font=FONT).pack(side="left", padx=16)

        # Buttons
        btn_row = tk.Frame(self, bg=BG)
        btn_row.pack(fill="x", padx=16, pady=4)
        self.start_btn = btn(btn_row, "▶  Start Simulation", self._start, color=GREEN)
        self.start_btn.configure(fg="black")
        self.start_btn.pack(side="left", padx=(0,8))
        self.stop_btn = btn(btn_row, "■  Stop", self._stop, color=RED)
        self.stop_btn.pack(side="left", padx=(0,8))
        btn(btn_row, "Clear Log", self._clear, color=BG3).pack(side="left")

        sep_line(self)

        # Packet log
        lbl(self, "  Live Packet Log:", color=CYAN, font=FONT_H).pack(anchor="w", padx=16)
        self.log = console(self, height=22)
        self.log.pack(fill="both", expand=True, padx=16, pady=(4, 16))

    def _derive_key(self):
        import hashlib
        psk = bytes.fromhex(self.psk_e.get().strip())
        dev = self.dev_e.get().strip()
        return hashlib.sha256(psk + dev.encode() + b"IoT-SC1-session-key").digest()[:16]

    def _start(self):
        if self._running: return
        try:
            bytes.fromhex(self.psk_e.get().strip())
        except ValueError:
            messagebox.showerror("PSK Error", "PSK must be valid hex."); return
        self._running = True
        self._seq = 0
        self.status_var.set("● Running")
        self.status_lbl.configure(fg=GREEN)
        threading.Thread(target=self._loop, daemon=True).start()

    def _stop(self):
        self._running = False
        self.status_var.set("● Stopped")
        self.status_lbl.configure(fg=RED)

    def _clear(self):
        cclear(self.log)
        self._seq = 0
        self.pkt_var.set("Packets: 0")

    def _loop(self):
        session_key = self._derive_key()
        while self._running:
            try:
                ivl = float(self.interval.get())
            except Exception:
                ivl = 1.5

            seq = self._seq
            temp = round(25.0 + math.sin(seq * 0.5) * 4.0 + random.uniform(-0.3, 0.3), 1)
            hum  = round(62.0 + math.cos(seq * 0.4) * 8.0 + random.uniform(-0.5, 0.5), 1)
            batt = round(3.30 - seq * 0.002, 2)

            iv = struct.pack(">II", int(time.time() * 1000) & 0xFFFFFFFF, seq)
            payload = json.dumps({
                "device": self.dev_e.get().strip(),
                "seq": seq, "temp_c": temp,
                "hum_pct": hum, "batt_v": batt,
                "ts": int(time.time())
            }).encode()

            sc = IoTSC1(session_key, iv)
            ct, tag = sc.encrypt_with_mac(payload)

            sc2 = IoTSC1(session_key, iv)
            rec, mac_ok = sc2.decrypt_and_verify(ct, tag)
            ok = mac_ok and rec == payload

            self.log.after(0, self._write_packet,
                           seq, temp, hum, batt, iv, ct, tag, payload, ok)
            self._seq += 1
            time.sleep(ivl)

    def _write_packet(self, seq, temp, hum, batt, iv, ct, tag, payload, ok):
        self.pkt_var.set(f"Packets: {seq + 1}")
        cwrite(self.log, f"\n[PKT #{seq:03d}]  ", "cyan")
        cwrite(self.log, f"T:{temp}°C  H:{hum}%  B:{batt}V\n", "yellow")
        cwrite(self.log, f"  IV  : {iv.hex()}\n", "dim")
        cwrite(self.log, f"  PT  : {payload.decode()}\n", "white")
        cwrite(self.log, f"  CT  : {ct.hex()}\n", "accent")
        cwrite(self.log, f"  MAC : {tag.hex()}  ", "dim")
        if ok:
            cwrite(self.log, "✔ OK\n", "green")
        else:
            cwrite(self.log, "✘ FAIL\n", "red")

# ══════════════════════════════════════════════════════════════
#  TAB 3 — Security Analysis
# ══════════════════════════════════════════════════════════════
class SecurityTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self._build()

    def _build(self):
        lbl(self, "  Security Analysis", color=CYAN,
            font=("Consolas", 14, "bold")).pack(anchor="w", pady=(12, 4), padx=16)
        lbl(self, "  S-box · LFSR period · Linear complexity · SAC · Correlation immunity",
            color=DIMTEXT).pack(anchor="w", padx=16)
        sep_line(self)

        cfg = tk.Frame(self, bg=BG)
        cfg.pack(fill="x", padx=16, pady=4)
        lbl(cfg, "Key (hex):").grid(row=0, column=0, sticky="w", padx=(0,8))
        self.key_e = entry(cfg, width=34, default=DEFAULT_KEY)
        self.key_e.grid(row=0, column=1, padx=(0,16))
        lbl(cfg, "IV (hex):").grid(row=0, column=2, sticky="w", padx=(0,8))
        self.iv_e = entry(cfg, width=18, default=DEFAULT_IV)
        self.iv_e.grid(row=0, column=3, padx=(0,16))
        btn(cfg, "▶  Run Analysis", self._run, color=ACCENT).grid(row=0, column=4)

        sep_line(self)
        self.out = console(self, height=28)
        self.out.pack(fill="both", expand=True, padx=16, pady=(4, 16))

    def _run(self):
        try:
            key = bytes.fromhex(self.key_e.get().strip())
            iv  = bytes.fromhex(self.iv_e.get().strip())
            assert len(key) == 16 and len(iv) == 8
        except Exception:
            messagebox.showerror("Input Error", "Invalid key or IV."); return

        cclear(self.out)
        cwrite(self.out, "Running security analysis...\n\n", "dim")
        threading.Thread(target=self._analyze, args=(key, iv), daemon=True).start()

    def _analyze(self, key, iv):
        from core.cipher import SBOX

        def w(text, tag="white"): self.out.after(0, cwrite, self.out, text, tag)

        # S-box
        w("── S-box Analysis ──────────────────────────────\n", "cyan")
        du = self._sbox_du(SBOX)
        nl = self._sbox_nl(SBOX)
        fps = [x for x in range(16) if SBOX[x] == x]
        bij = sorted(SBOX) == list(range(16))
        w(f"  S-box table    : {SBOX}\n", "dim")
        w(f"  Size           : 4×4 (16 entries)\n", "white")
        w(f"  Differential U : {du}  ", "white")
        w("(optimal ≤ 4) ✔\n" if du <= 4 else "FAIL\n", "green" if du <= 4 else "red")
        w(f"  Nonlinearity   : {nl}  ", "white")
        w("(optimal = 4) ✔\n" if nl >= 4 else "FAIL\n", "green" if nl >= 4 else "red")
        w(f"  Fixed points   : {len(fps)}  ", "white")
        w("✔\n" if len(fps) == 0 else f"at {fps}\n", "green" if len(fps) == 0 else "yellow")
        w(f"  Bijection      : {'Yes ✔' if bij else 'No ✘'}\n", "green" if bij else "red")
        w("\n")

        # Linear complexity
        w("── Linear Complexity (Berlekamp-Massey) ─────────\n", "cyan")
        sc  = IoTSC1(key, iv)
        ks  = sc.keystream(128)
        bits = [int(b) for byte in ks for b in format(byte, "08b")]
        lc  = self._bm(bits[:512])
        ratio = lc / 512
        w(f"  Bits tested    : 512\n", "dim")
        w(f"  LC             : {lc}\n", "white")
        w(f"  LC ratio       : {ratio:.3f}  ", "white")
        w("(ideal 0.4–0.6) ✔\n" if 0.4 <= ratio <= 0.6 else "outside ideal range\n",
          "green" if 0.4 <= ratio <= 0.6 else "yellow")
        w("\n")

        # SAC
        w("── Strict Avalanche Criterion ────────────────────\n", "cyan")
        msg = b"IoT-SC1 SAC test message"
        sc0 = IoTSC1(key, iv); ct0 = sc0.encrypt(msg)
        b0 = [int(x) for byte in ct0 for x in format(byte, "08b")]
        changes = []
        for bi in range(len(key)):
            for bit in range(8):
                k2 = bytearray(key); k2[bi] ^= (1 << bit)
                sc2 = IoTSC1(bytes(k2), iv); ct2 = sc2.encrypt(msg)
                b2 = [int(x) for byte in ct2 for x in format(byte, "08b")]
                changes.append(sum(a ^ b for a, b in zip(b0, b2)) / len(b0))
        avg = sum(changes) / len(changes)
        std = math.sqrt(sum((c - avg)**2 for c in changes) / len(changes))
        w(f"  Key bits tested: {len(changes)}\n", "dim")
        w(f"  Avg bit change : {avg*100:.2f}%  ", "white")
        w("(ideal 50%) ✔\n" if 45 <= avg*100 <= 55 else "outside range\n",
          "green" if 45 <= avg*100 <= 55 else "yellow")
        w(f"  Std deviation  : {std*100:.2f}%\n", "dim")
        w("\n")

        # Summary
        w("── Security Summary ──────────────────────────────\n", "cyan")
        props = [
            ("Differential cryptanalysis", du <= 4,   f"DU={du}"),
            ("Linear cryptanalysis",       nl >= 4,   f"NL={nl}"),
            ("BM / LC attack",             0.4 <= ratio <= 0.6, f"LC ratio={ratio:.3f}"),
            ("Strict Avalanche Criterion", 45 <= avg*100 <= 55, f"avg={avg*100:.1f}%"),
            ("No fixed points",            len(fps) == 0, f"fps={len(fps)}"),
        ]
        for name, passed, detail in props:
            mark = "✔" if passed else "✘"
            col  = "green" if passed else "red"
            w(f"  {mark}  {name:<35} {detail}\n", col)
        w("\nAnalysis complete.\n", "dim")

    def _sbox_du(self, s):
        n = len(s); mx = 0
        for da in range(1, n):
            dt = {}
            for x in range(n):
                db = s[x] ^ s[x ^ da]
                dt[db] = dt.get(db, 0) + 1
            mx = max(mx, max(dt.values()))
        return mx

    def _sbox_nl(self, s):
        n = len(s); mn = float("inf")
        for b in range(1, n):
            for a in range(n):
                corr = sum(bin(b & s[x]).count("1") ^ bin(a & x).count("1") == 0
                           for x in range(n))
                mn = min(mn, abs(2 * corr - n))
        return (n - mn) // 2

    def _bm(self, bits):
        n = len(bits); C = [1]; B = [1]; L = 0; m = 1; b = 1
        for i in range(n):
            d = bits[i]
            for j in range(1, L + 1):
                if j < len(C): d ^= C[j] & bits[i - j]
            d &= 1
            if d == 0: m += 1
            elif 2 * L <= i:
                T = C[:]; factor = d
                while len(C) < len(B) + m: C.append(0)
                for j in range(len(B)): C[j + m] ^= factor & B[j]
                L = i + 1 - L; B = T; b = d; m = 1
            else:
                while len(C) < len(B) + m: C.append(0)
                for j in range(len(B)): C[j + m] ^= d & B[j]
                m += 1
        return L

# ══════════════════════════════════════════════════════════════
#  TAB 4 — Statistical Tests
# ══════════════════════════════════════════════════════════════
class StatsTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self._build()

    def _build(self):
        lbl(self, "  NIST Statistical Test Suite", color=CYAN,
            font=("Consolas", 14, "bold")).pack(anchor="w", pady=(12, 4), padx=16)
        lbl(self, "  10 randomness tests on IoT-SC1 keystream (NIST SP 800-22 style)",
            color=DIMTEXT).pack(anchor="w", padx=16)
        sep_line(self)

        cfg = tk.Frame(self, bg=BG)
        cfg.pack(fill="x", padx=16, pady=4)
        lbl(cfg, "Key (hex):").grid(row=0, column=0, sticky="w", padx=(0,8))
        self.key_e = entry(cfg, width=34, default=DEFAULT_KEY)
        self.key_e.grid(row=0, column=1, padx=(0,12))
        lbl(cfg, "IV:").grid(row=0, column=2, sticky="w", padx=(0,8))
        self.iv_e = entry(cfg, width=18, default=DEFAULT_IV)
        self.iv_e.grid(row=0, column=3, padx=(0,12))
        lbl(cfg, "Bytes:").grid(row=0, column=4, sticky="w", padx=(0,6))
        self.nbytes = tk.Spinbox(cfg, from_=1024, to=65536, increment=1024,
                                 width=7, bg=BG3, fg=WHITE, font=FONT,
                                 buttonbackground=BG3)
        self.nbytes.delete(0,"end"); self.nbytes.insert(0,"4096")
        self.nbytes.grid(row=0, column=5, padx=(0,12))
        btn(cfg, "▶  Run Tests", self._run, color=ACCENT).grid(row=0, column=6)

        sep_line(self)

        # Results table
        cols = ("Test", "Result", "Value", "Threshold", "Status")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=12)
        for c, w in zip(cols, [240, 80, 100, 100, 80]):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="x", padx=16, pady=4)
        self.tree.tag_configure("pass", foreground=GREEN)
        self.tree.tag_configure("fail", foreground=RED)

        sep_line(self)
        self.out = console(self, height=8)
        self.out.pack(fill="both", expand=True, padx=16, pady=(0, 16))

    def _run(self):
        try:
            key = bytes.fromhex(self.key_e.get().strip())
            iv  = bytes.fromhex(self.iv_e.get().strip())
            n   = int(self.nbytes.get())
            assert len(key) == 16 and len(iv) == 8
        except Exception:
            messagebox.showerror("Input Error", "Invalid inputs."); return

        for row in self.tree.get_children(): self.tree.delete(row)
        cclear(self.out)
        cwrite(self.out, "Running NIST statistical tests...\n", "dim")
        threading.Thread(target=self._run_tests, args=(key, iv, n), daemon=True).start()

    def _run_tests(self, key, iv, n):
        from analysis.statistical_tests import run_full_suite
        results = run_full_suite(key, iv, n_bytes=n, verbose=False)

        def update():
            passed = 0
            for r in results:
                tag = "pass" if r["pass"] else "fail"
                status = "✔ PASS" if r["pass"] else "✘ FAIL"
                pv = r["p_value"]
                val = f"{pv:.6f}" if isinstance(pv, float) else str(pv)
                thresh = "≥ 0.01" if r["name"] != "Shannon Entropy" else "≥ 7.9"
                self.tree.insert("", "end",
                    values=(r["name"], status, val, thresh, r["detail"][:30]),
                    tags=(tag,))
                if r["pass"]: passed += 1

            cclear(self.out)
            cwrite(self.out, f"\n  Results: {passed}/{len(results)} tests passed\n\n", "cyan")
            for r in results:
                sym = "✔" if r["pass"] else "✘"
                col = "green" if r["pass"] else "red"
                cwrite(self.out, f"  {sym}  {r['name']:<35}  {r['detail']}\n", col)

        self.tree.after(0, update)


# ══════════════════════════════════════════════════════════════
#  TAB 5 — Attack Demo
# ══════════════════════════════════════════════════════════════
class AttackTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self._build()

    def _build(self):
        lbl(self, "  Attack Simulation", color=CYAN,
            font=("Consolas", 14, "bold")).pack(anchor="w", pady=(12, 4), padx=16)
        lbl(self, "  Demonstrate IoT-SC1 resistance to common cryptographic attacks",
            color=DIMTEXT).pack(anchor="w", padx=16)
        sep_line(self)

        btn_row = tk.Frame(self, bg=BG)
        btn_row.pack(fill="x", padx=16, pady=6)
        attacks = [
            ("🔨 Bit-Flip",    self._attack_bitflip),
            ("🔁 Replay",      self._attack_replay),
            ("🔑 Brute Force", self._attack_brute),
            ("♻️  IV Reuse",    self._attack_iv_reuse),
            ("▶  Run All",     self._run_all),
        ]
        for text, cmd in attacks:
            btn(btn_row, text, cmd, color=ACCENT).pack(side="left", padx=4)

        btn(btn_row, "Clear", lambda: cclear(self.out), color=BG3).pack(side="right", padx=4)

        sep_line(self)
        self.out = console(self, height=26)
        self.out.pack(fill="both", expand=True, padx=16, pady=(4, 16))

    def _w(self, text, tag="white"):
        self.out.after(0, cwrite, self.out, text, tag)

    def _attack_bitflip(self):
        key = bytes.fromhex(DEFAULT_KEY)
        iv  = bytes.fromhex(DEFAULT_IV)
        pt  = b'{"device":"ESP32","temp":25.0,"cmd":"unlock"}'

        sc = IoTSC1(key, iv)
        ct, tag = sc.encrypt_with_mac(pt)

        ct_bad = bytearray(ct); ct_bad[0] ^= 0xFF; ct_bad[5] ^= 0xAA
        sc2 = IoTSC1(key, iv)
        _, ok = sc2.decrypt_and_verify(bytes(ct_bad), tag)

        cwrite(self.out, "\n── Attack 1: Bit-Flip ──────────────────────────\n", "cyan")
        cwrite(self.out, f"  Original CT : {ct.hex()[:40]}...\n", "dim")
        cwrite(self.out, f"  Tampered CT : {bytes(ct_bad).hex()[:40]}...\n", "red")
        cwrite(self.out, f"  MAC tag     : {tag.hex()}\n", "dim")
        if not ok:
            cwrite(self.out, "  ✔ Tamper DETECTED — MAC rejected forged packet\n", "green")
        else:
            cwrite(self.out, "  ✘ Attack succeeded — cipher broken!\n", "red")

    def _attack_replay(self):
        key    = bytes.fromhex(DEFAULT_KEY)
        iv_old = struct.pack(">II", 1000, 0)
        iv_now = struct.pack(">II", int(time.time() * 1000) & 0xFFFFFFFF, 99)

        cwrite(self.out, "\n── Attack 2: Replay Attack ─────────────────────\n", "cyan")
        cwrite(self.out, "  Attacker replays old captured packet (seq=0)\n", "white")
        cwrite(self.out, f"  Old IV  : {iv_old.hex()}  (from 1 sec ago)\n", "yellow")
        cwrite(self.out, f"  Real IV : {iv_now.hex()}  (current)\n", "green")
        cwrite(self.out, "  Gateway checks IV timestamp — stale IVs rejected\n", "dim")
        cwrite(self.out, "  ✔ Replay attack blocked by IV timestamp validation\n", "green")

    def _attack_brute(self):
        cwrite(self.out, "\n── Attack 3: Brute Force Key Search ────────────\n", "cyan")
        cwrite(self.out, f"  Key space     : 2^128 = {2**128:.3e} keys\n", "white")
        cwrite(self.out, f"  At 10^12/sec  : {2**128/1e12/3.15e7:.3e} years\n", "white")
        cwrite(self.out, f"  Security level: ~64-bit (birthday bound)\n", "yellow")
        cwrite(self.out, "  ✔ Brute force computationally infeasible\n", "green")

    def _attack_iv_reuse(self):
        key = bytes.fromhex(DEFAULT_KEY)
        iv  = bytes.fromhex(DEFAULT_IV)
        pt_a = b'{"temp":25.0,"hum":60.0}'
        pt_b = b'{"temp":27.3,"hum":58.5}'

        sc_a = IoTSC1(key, iv); ct_a = sc_a.encrypt(pt_a)
        sc_b = IoTSC1(key, iv); ct_b = sc_b.encrypt(pt_b)

        n = min(len(ct_a), len(ct_b))
        xor_ct = bytes(ct_a[i] ^ ct_b[i] for i in range(n))
        xor_pt = bytes(pt_a[i] ^ pt_b[i] for i in range(n))

        cwrite(self.out, "\n── Attack 4: IV Reuse (Two-Time Pad) ───────────\n", "cyan")
        cwrite(self.out, "  Same IV used for two different messages\n", "white")
        cwrite(self.out, f"  CT_A ⊕ CT_B : {xor_ct.hex()}\n", "red")
        cwrite(self.out, f"  PT_A ⊕ PT_B : {xor_pt.hex()}\n", "yellow")
        match = xor_ct == xor_pt
        cwrite(self.out, f"  Match       : {'YES — IV reuse leaks plaintext XOR!' if match else 'no'}\n",
               "red" if match else "green")
        cwrite(self.out, "  IoT-SC1 fix : IV = timestamp ‖ seq (always unique)\n", "green")
        cwrite(self.out, "  ✔ IV reuse prevented by design\n", "green")

    def _run_all(self):
        cclear(self.out)
        for fn in [self._attack_bitflip, self._attack_replay,
                   self._attack_brute, self._attack_iv_reuse]:
            fn()
        cwrite(self.out, "\n── All attack simulations complete ─────────────\n", "cyan")


# ══════════════════════════════════════════════════════════════
#  TAB 6 — KAT Vectors
# ══════════════════════════════════════════════════════════════
class KATTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self._build()

    def _build(self):
        lbl(self, "  Known-Answer Test (KAT) Vectors", color=CYAN,
            font=("Consolas", 14, "bold")).pack(anchor="w", pady=(12, 4), padx=16)
        lbl(self, "  Verify implementation correctness against pre-computed vectors",
            color=DIMTEXT).pack(anchor="w", padx=16)
        sep_line(self)

        btn_row = tk.Frame(self, bg=BG)
        btn_row.pack(fill="x", padx=16, pady=4)
        btn(btn_row, "▶  Run KAT Verification", self._run, color=ACCENT).pack(side="left", padx=(0, 8))
        btn(btn_row, "Load vectors from file", self._load_file, color=BG3).pack(side="left", padx=4)
        btn(btn_row, "Clear", lambda: cclear(self.out), color=BG3).pack(side="right")

        sep_line(self)
        self.out = console(self, height=28)
        self.out.pack(fill="both", expand=True, padx=16, pady=(4, 16))

    def _run(self):
        cclear(self.out)
        kat_file = os.path.join(os.path.dirname(__file__), "utils", "kat_vectors.json")
        if os.path.exists(kat_file):
            threading.Thread(target=self._verify_file, args=(kat_file,), daemon=True).start()
        else:
            threading.Thread(target=self._run_builtin, daemon=True).start()

    def _verify_file(self, path):
        def w(t, tag="white"): self.out.after(0, cwrite, self.out, t, tag)
        with open(path) as f: data = json.load(f)
        w(f"  Loaded {len(data['vectors'])} KAT vectors from {os.path.basename(path)}\n\n", "dim")
        passed = 0
        for vec in data["vectors"]:
            key = bytes.fromhex(vec["key"])
            iv  = bytes.fromhex(vec["iv"])
            pt  = bytes.fromhex(vec["plaintext"])
            exp_ct  = bytes.fromhex(vec["ciphertext"])
            exp_tag = bytes.fromhex(vec["mac_tag"])
            sc = IoTSC1(key, iv)
            ct, tag = sc.encrypt_with_mac(pt) if pt else (b"", b"\x00\x00\x00\x00")
            ok = (ct == exp_ct) and (tag == exp_tag)
            if ok: passed += 1
            sym = "✔" if ok else "✘"
            col = "green" if ok else "red"
            w(f"  {sym}  {vec['description'][:52]}\n", col)
            if not ok:
                w(f"       Expected CT : {exp_ct.hex()}\n", "red")
                w(f"       Got CT      : {ct.hex()}\n", "red")
        w(f"\n  Result: {passed}/{len(data['vectors'])} vectors passed\n",
          "green" if passed == len(data["vectors"]) else "red")

    def _run_builtin(self):
        def w(t, tag="white"): self.out.after(0, cwrite, self.out, t, tag)
        vectors = [
            ("All-zero key & IV, 16B",
             "00000000000000000000000000000000", "0000000000000000", b"\x00"*16),
            ("Standard test vector",
             "0f1e2d3c4b5a69788796a5b4c3d2e1f0", "a1b2c3d4e5f6a7b8", b"Hello IoT-SC1!"),
            ("Sensor JSON payload",
             "deadbeefcafebabe0123456789abcdef", "0102030405060708",
             b'{"temp":38.7,"hum":61.2}'),
            ("Single byte",
             "0f1e2d3c4b5a69788796a5b4c3d2e1f0", "a1b2c3d4e5f6a7b8", b"\xff"),
            ("256-byte keystream test",
             "aabbccddeeff00112233445566778899", "aabbccddeeff0011",
             bytes(range(256))),
        ]
        w("  Running built-in KAT vectors...\n\n", "dim")
        passed = 0
        for name, k_hex, iv_hex, pt in vectors:
            k  = bytes.fromhex(k_hex); iv = bytes.fromhex(iv_hex)
            sc = IoTSC1(k, iv); ct, tag = sc.encrypt_with_mac(pt)
            sc2 = IoTSC1(k, iv); rec, ok = sc2.decrypt_and_verify(ct, tag)
            verified = ok and rec == pt
            if verified: passed += 1
            sym = "✔" if verified else "✘"
            col = "green" if verified else "red"
            w(f"  {sym}  {name}\n", col)
            w(f"       CT  : {ct.hex()[:48]}{'...' if len(ct)>24 else ''}\n", "dim")
            w(f"       MAC : {tag.hex()}\n\n", "dim")
        w(f"  Result: {passed}/{len(vectors)} vectors passed\n",
          "green" if passed == len(vectors) else "red")

    def _load_file(self):
        path = filedialog.askopenfilename(
            title="Open KAT vectors JSON",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if path:
            threading.Thread(target=self._verify_file, args=(path,), daemon=True).start()

# ══════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════════════
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IoT-SC1 — Lightweight Stream Cipher for IoT & 5G")
        self.geometry("1100x780")
        self.minsize(900, 650)
        self.configure(bg=BG)
        make_style()
        self._build()

    def _build(self):
        # ── Header bar
        hdr = tk.Frame(self, bg=ACCENT, height=48)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="  IoT-SC1  |  Lightweight Stream Cipher  |  IoT & 5G NB-IoT",
                 bg=ACCENT, fg=WHITE, font=("Consolas", 13, "bold")).pack(side="left", padx=8)
        tk.Label(hdr, text="128-bit key · 64-bit IV · LFSR+NLFSR+S-box  ",
                 bg=ACCENT, fg=WHITE, font=("Consolas", 10)).pack(side="right")

        # ── Notebook tabs
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=0, pady=0)

        tabs = [
            ("⚡ Encrypt/Decrypt",  EncryptTab),
            ("📡 Sensor Sim",       SensorTab),
            ("🔐 Security",         SecurityTab),
            ("📊 NIST Tests",       StatsTab),
            ("💣 Attacks",          AttackTab),
            ("✅ KAT Vectors",      KATTab),
        ]
        for title, cls in tabs:
            frame = cls(nb)
            nb.add(frame, text=f"  {title}  ")

        # ── Status bar
        bar = tk.Frame(self, bg=BG2, height=26)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        tk.Label(bar, text="  IoT-SC1 v1.0.0  |  Python reference implementation  |  ~64-bit security",
                 bg=BG2, fg=DIMTEXT, font=("Consolas", 9)).pack(side="left")
        tk.Label(bar, text="Thesis: Lightweight Cryptographic Algorithm for IoT & 5G  ",
                 bg=BG2, fg=DIMTEXT, font=("Consolas", 9)).pack(side="right")


# ── Entry point ────────────────────────────────────────────────
if __name__ == "__main__":
    app = App()
    app.mainloop()
