# IoT-SC1 Smart Parking Lot Simulation
# 3D car models, gate animation, encrypted IoT messages
# Run: python parking_simulation.py

import tkinter as tk
import threading
import time
import struct
import json
import random
import hashlib
import os
import sys
import math

sys.path.insert(0, os.path.dirname(__file__))
from core.cipher import IoTSC1

# ── Config ────────────────────────────────────────────────────
GATE_PSK = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")

# ── Colours ───────────────────────────────────────────────────
BG        = "#0d1117"
ASPHALT   = "#1a1d23"
ROAD_MID  = "#22252e"
GRASS     = "#0a1a0a"
MARKING   = "#f0c040"
WHITE     = "#f0f0f0"
GREEN     = "#2ecc71"
RED       = "#e74c3c"
YELLOW    = "#f1c40f"
CYAN      = "#00bcd4"
PURPLE    = "#9c27b0"
DIMTEXT   = "#44475a"
PANEL_BG  = "#11131a"
HACKER_BG = "#1a0808"
SERVER_BG = "#081a08"

CAR_PALETTE = [
    ("#c0392b","#e74c3c"),  # red
    ("#1565c0","#2196f3"),  # blue
    ("#1b5e20","#4caf50"),  # green
    ("#e65100","#ff9800"),  # orange
    ("#4a148c","#9c27b0"),  # purple
    ("#00695c","#009688"),  # teal
    ("#f57f17","#ffeb3b"),  # yellow
    ("#880e4f","#e91e63"),  # pink
]

# Canvas size
CW, CH = 860, 480

# ── Parking spot definitions (3D top-down perspective) ────────
# 3 spots left column (A), 3 spots right column (B)
# Each: id, col_x, row_y, label
RAW_SPOTS = [
    (1, 60,  80,  "A1"),
    (2, 60,  200, "A2"),
    (3, 60,  320, "A3"),
    (4, 680, 80,  "B1"),
    (5, 680, 200, "B2"),
    (6, 680, 320, "B3"),
]
SW, SH = 110, 90   # spot width, height

# Gate: bottom-centre of canvas
GATE_X  = CW // 2
GATE_Y  = CH - 50
GATE_W  = 140   # full opening width
BAR_LEN = 55    # half-barrier length

def derive_key(psk, dev):
    return hashlib.sha256(psk + dev.encode() + b"parking-iot-sc1").digest()[:16]

def make_iv(seq):
    ts = int(time.time() * 1000) & 0xFFFFFFFF
    return struct.pack(">II", ts, seq)


# ============================================================
#  3D Car Drawing
# ============================================================
def draw_3d_car(canvas, cx, cy, color_dark, color_light,
                scale=1.0, tag="car", facing="up"):
    """
    Draw a 3D-perspective car centred at (cx, cy).
    facing: 'up' (pointing toward top) or 'down' (toward bottom)
    """
    w  = int(32 * scale)
    h  = int(52 * scale)
    rh = int(18 * scale)   # roof height above body
    rw = int(20 * scale)   # roof width
    ww = int(8  * scale)   # wheel width
    wh = int(6  * scale)   # wheel height
    sh = int(6  * scale)   # shadow height

    if facing == "down":
        dy = 1
    else:
        dy = -1

    # ---- shadow
    canvas.create_oval(cx - w//2 + 4, cy + dy*(h//2 - 2),
                       cx + w//2 - 4, cy + dy*(h//2 + sh),
                       fill="#000000", outline="", stipple="gray25", tags=tag)

    # ---- body
    body_pts = [
        cx - w//2,       cy - dy*(h//2),
        cx + w//2,       cy - dy*(h//2),
        cx + w//2 + 4,   cy,
        cx + w//2,       cy + dy*(h//2),
        cx - w//2,       cy + dy*(h//2),
        cx - w//2 - 4,   cy,
    ]
    canvas.create_polygon(body_pts, fill=color_dark, outline="#111",
                          width=1, smooth=False, tags=tag)

    # ---- roof
    rx1 = cx - rw//2
    rx2 = cx + rw//2
    ry1 = cy - dy*(h//4 + rh)
    ry2 = cy - dy*(h//4)
    canvas.create_polygon(
        rx1 - 4, ry2,
        rx2 + 4, ry2,
        rx2,     ry1,
        rx1,     ry1,
        fill=color_light, outline="#111", width=1, tags=tag
    )

    # ---- windscreen (front)
    ws_y1 = cy - dy*(h//4 + rh - 2)
    ws_y2 = cy - dy*(h//4 + 2)
    canvas.create_polygon(
        rx1 + 2, ws_y2,
        rx2 - 2, ws_y2,
        rx2 - 2, ws_y1,
        rx1 + 2, ws_y1,
        fill="#aaddff", outline="", tags=tag
    )

    # ---- rear window
    rw_y1 = cy + dy*(h//5)
    rw_y2 = cy + dy*(h//5 + rh - 4)
    canvas.create_polygon(
        rx1 + 2, rw_y1,
        rx2 - 2, rw_y1,
        rx2 - 4, rw_y2,
        rx1 + 4, rw_y2,
        fill="#88aacc", outline="", tags=tag
    )

    # ---- headlights
    hl_y = cy - dy*(h//2 - 4)
    for hx in [cx - w//3, cx + w//3]:
        canvas.create_oval(hx - 5, hl_y - 3,
                           hx + 5, hl_y + 3,
                           fill="#ffffaa", outline="#888", tags=tag)

    # ---- tail lights
    tl_y = cy + dy*(h//2 - 4)
    for tx in [cx - w//3, cx + w//3]:
        canvas.create_oval(tx - 4, tl_y - 3,
                           tx + 4, tl_y + 3,
                           fill="#cc2222", outline="#555", tags=tag)

    # ---- wheels (4 corners)
    for wx, wy_side in [
        (cx - w//2 - 2, -1),
        (cx + w//2 + 2, -1),
        (cx - w//2 - 2,  1),
        (cx + w//2 + 2,  1),
    ]:
        wy = cy + wy_side * dy * (h//3)
        canvas.create_oval(wx - ww//2, wy - wh,
                           wx + ww//2, wy + wh,
                           fill="#222", outline="#555", tags=tag)
        # hub cap
        canvas.create_oval(wx - ww//4, wy - wh//2,
                           wx + ww//4, wy + wh//2,
                           fill="#888", outline="", tags=tag)

    # ---- door line
    canvas.create_line(cx, cy - dy*(h//2 - 8),
                       cx, cy + dy*(h//3),
                       fill="#222", width=1, tags=tag)

    # ---- highlight stripe
    canvas.create_line(cx - w//2 + 3, cy - dy*4,
                       cx + w//2 - 3, cy - dy*4,
                       fill=color_light, width=2, tags=tag)


# ============================================================
#  Parking App
# ============================================================
class ParkingApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IoT-SC1 -- Smart Parking Security Demo")
        self.resizable(False, False)
        self.configure(bg=BG)

        # State
        self.slots      = {s[0]: None for s in RAW_SPOTS}
        self.seq        = 0
        self.car_count  = 0
        self.running    = True
        self.gate_open  = False
        self.hacker_on  = tk.BooleanVar(value=True)
        self.stats      = {"arrived": 0, "departed": 0,
                           "occupied": 0, "blocked": 0}

        self._build_ui()
        self._draw_static()
        self._update_all_spots()
        self._draw_gate(open=False)
        self.after(2000, self._auto_loop)

    # ── Build UI ─────────────────────────────────────────────
    def _build_ui(self):
        # Title bar
        hdr = tk.Frame(self, bg="#161b22", height=40)
        hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr, text="  IoT-SC1  Smart Parking -- Encrypted Access Control",
                 bg="#161b22", fg=WHITE,
                 font=("Consolas", 12, "bold")).pack(side="left", padx=8)
        tk.Label(hdr, text="128-bit key | MAC integrity | Replay-proof  ",
                 bg="#161b22", fg=DIMTEXT,
                 font=("Consolas", 9)).pack(side="right")

        # Content row
        row = tk.Frame(self, bg=BG)
        row.pack(fill="both", expand=True)

        # ---- Canvas
        left = tk.Frame(row, bg=BG)
        left.pack(side="left", fill="both")
        self.canvas = tk.Canvas(left, width=CW, height=CH,
                                bg=ASPHALT, highlightthickness=0)
        self.canvas.pack(padx=6, pady=6)

        # Controls
        ctrl = tk.Frame(left, bg=BG)
        ctrl.pack(fill="x", padx=6, pady=(0, 6))
        self._btn(ctrl, "  Car Arrives  ", self._manual_arrive,
                  "#1b4d1b", GREEN).pack(side="left", padx=4)
        self._btn(ctrl, "  Car Departs  ", self._manual_depart,
                  "#4d1b1b", RED).pack(side="left", padx=4)
        tk.Checkbutton(ctrl, text=" Hacker Active",
                       variable=self.hacker_on,
                       bg=BG, fg=RED, selectcolor="#2a0808",
                       font=("Consolas", 10),
                       activebackground=BG,
                       cursor="hand2").pack(side="left", padx=12)
        self.status_lbl = tk.Label(ctrl, text="Ready",
                                   bg=BG, fg=GREEN,
                                   font=("Consolas", 10, "bold"))
        self.status_lbl.pack(side="right", padx=8)

        # ---- Right panels
        right = tk.Frame(row, bg=PANEL_BG, width=360)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        self._panel_label(right, "  Radio Channel (encrypted)",
                          PANEL_BG, CYAN)
        self.radio_log = self._make_log(right, PANEL_BG, 6)

        self._divider(right)
        self._panel_label(right, "  Hacker View  (intercept only)",
                          HACKER_BG, RED)
        self.hacker_log = self._make_log(right, HACKER_BG, 6, RED)

        self._divider(right)
        self._panel_label(right, "  Gate Controller  (decrypted)",
                          SERVER_BG, GREEN)
        self.server_log = self._make_log(right, SERVER_BG, 6, GREEN)

        self._divider(right)
        # Stats
        stats_f = tk.Frame(right, bg=PANEL_BG)
        stats_f.pack(fill="x", padx=6, pady=4)
        self.stat_vars = {}
        for label, key, color in [
            ("Arrived",  "arrived",  GREEN),
            ("Departed", "departed", YELLOW),
            ("Occupied", "occupied", CYAN),
            ("Blocked",  "blocked",  RED),
        ]:
            box = tk.Frame(stats_f, bg="#1c1f26")
            box.pack(side="left", expand=True, fill="x", padx=2, pady=2)
            tk.Label(box, text=label, bg="#1c1f26", fg=DIMTEXT,
                     font=("Consolas", 7)).pack()
            v = tk.StringVar(value="0")
            self.stat_vars[key] = v
            tk.Label(box, textvariable=v, bg="#1c1f26", fg=color,
                     font=("Consolas", 14, "bold")).pack()

    def _btn(self, parent, text, cmd, bg, fg):
        return tk.Button(parent, text=text, command=cmd,
                         bg=bg, fg=fg, font=("Consolas", 10, "bold"),
                         relief="flat", cursor="hand2", padx=8, pady=4,
                         activebackground="#2a2a2a", activeforeground=fg)

    def _panel_label(self, parent, text, bg, fg):
        tk.Label(parent, text=text, bg=bg, fg=fg,
                 font=("Consolas", 9, "bold"),
                 anchor="w").pack(fill="x", padx=8, pady=(6, 2))

    def _divider(self, parent):
        tk.Frame(parent, bg="#222233", height=1).pack(fill="x", padx=8, pady=2)

    def _make_log(self, parent, bg, height=6, fg=WHITE):
        t = tk.Text(parent, height=height, bg=bg, fg=fg,
                    font=("Consolas", 8), relief="flat",
                    wrap="char", state="disabled",
                    insertbackground=WHITE, padx=6, pady=3)
        t.pack(fill="x", padx=8)
        for tag, color in [("g", GREEN), ("r", RED), ("y", YELLOW),
                            ("c", CYAN),  ("d", DIMTEXT), ("w", WHITE)]:
            t.tag_config(tag, foreground=color)
        return t

    # ── Canvas drawing ────────────────────────────────────────
    def _draw_static(self):
        c = self.canvas

        # Grass borders
        c.create_rectangle(0, 0, 55, CH, fill=GRASS, outline="")
        c.create_rectangle(CW-55, 0, CW, CH, fill=GRASS, outline="")

        # Driving lane (centre)
        c.create_rectangle(200, 0, CW-200, CH, fill=ROAD_MID, outline="")

        # Spot areas background
        c.create_rectangle(55, 0, 200, CH, fill=ASPHALT, outline="")
        c.create_rectangle(CW-200, 0, CW-55, CH, fill=ASPHALT, outline="")

        # Centre dashes
        for y in range(20, CH-60, 28):
            c.create_line(CW//2, y, CW//2, y+14,
                          fill="#333", width=2, dash=(6, 6))

        # Column labels
        c.create_text(127, 22, text="COLUMN  A",
                      fill=DIMTEXT, font=("Consolas", 8, "bold"))
        c.create_text(CW-127, 22, text="COLUMN  B",
                      fill=DIMTEXT, font=("Consolas", 8, "bold"))

        # Entrance label at bottom
        c.create_text(CW//2, CH-18, text="< ENTRANCE >",
                      fill="#334", font=("Consolas", 9, "bold"))

    def _update_all_spots(self):
        for sid, sx, sy, label in RAW_SPOTS:
            self._draw_spot(sid, sx, sy, label)

    def _draw_spot(self, sid, sx, sy, label):
        c    = self.canvas
        tag  = f"spot_{sid}"
        c.delete(tag)
        free = (self.slots[sid] is None)

        # Spot box with perspective skew
        skew = 6
        pts = [
            sx+skew,    sy,
            sx+SW-skew, sy,
            sx+SW,      sy+SH,
            sx,         sy+SH,
        ]
        fill = "#0e2b0e" if free else "#2b0e0e"
        c.create_polygon(pts, fill=fill,
                         outline=MARKING, width=1, tags=tag)

        # Spot label
        c.create_text(sx + SW//2, sy + 14,
                      text=label, fill=MARKING,
                      font=("Consolas", 10, "bold"), tags=tag)

        # Status dot + text
        dot = GREEN if free else RED
        txt = "FREE" if free else "OCC"
        c.create_oval(sx+SW//2-18, sy+SH-20,
                      sx+SW//2-8,  sy+SH-10,
                      fill=dot, outline="", tags=tag)
        c.create_text(sx+SW//2+8, sy+SH-15,
                      text=txt, fill=dot,
                      font=("Consolas", 7), tags=tag)

        # Draw parked car if occupied
        if not free:
            car = self.slots[sid]
            draw_3d_car(c,
                        sx + SW//2,
                        sy + SH//2 + 5,
                        car["dark"], car["light"],
                        scale=0.75, tag=tag,
                        facing="up")

    def _draw_gate(self, open=False):
        c = self.canvas
        c.delete("gate")
        gx, gy = GATE_X, GATE_Y

        # Sensor pole left
        c.create_rectangle(gx-GATE_W//2-6, gy-38,
                            gx-GATE_W//2+6, gy+8,
                            fill="#888", outline="#555", tags="gate")
        # Sensor pole right
        c.create_rectangle(gx+GATE_W//2-6, gy-38,
                            gx+GATE_W//2+6, gy+8,
                            fill="#888", outline="#555", tags="gate")

        # IoT sensor box on left pole
        c.create_rectangle(gx-GATE_W//2-10, gy-52,
                            gx-GATE_W//2+10, gy-38,
                            fill=CYAN, outline="#005", tags="gate")
        c.create_text(gx-GATE_W//2, gy-45,
                      text="IoT", fill="#000",
                      font=("Consolas", 6, "bold"), tags="gate")

        # Gate barrier arm
        if not open:
            # Closed: horizontal bar
            c.create_line(gx-GATE_W//2+6, gy-28,
                          gx+GATE_W//2-6, gy-28,
                          fill=RED, width=6, tags="gate")
            # Red/white stripes on bar
            for i in range(6):
                bx = gx - GATE_W//2 + 6 + i*18
                c.create_line(bx, gy-31, bx+9, gy-25,
                              fill=WHITE, width=2, tags="gate")
            # CLOSED label
            c.create_text(gx, gy-40,
                          text="GATE CLOSED",
                          fill=RED, font=("Consolas", 8, "bold"),
                          tags="gate")
        else:
            # Open: bar raised (vertical on left pole)
            c.create_line(gx-GATE_W//2+6, gy-28,
                          gx-GATE_W//2+6, gy-28-BAR_LEN,
                          fill=GREEN, width=6, tags="gate")
            c.create_text(gx, gy-40,
                          text="GATE OPEN",
                          fill=GREEN, font=("Consolas", 8, "bold"),
                          tags="gate")

        # Road markings at gate
        for i in range(3):
            bx = gx - 30 + i*30
            c.create_rectangle(bx, gy+2, bx+18, gy+10,
                                fill=WHITE, outline="", tags="gate")

    # ── Encryption logic ──────────────────────────────────────
    def _encrypt_cmd(self, cmd_dict):
        pt  = json.dumps(cmd_dict).encode()
        key = derive_key(GATE_PSK, "PARKING-GATE-001")
        iv  = make_iv(self.seq)
        sc  = IoTSC1(key, iv)
        ct, tag = sc.encrypt_with_mac(pt)
        self.seq += 1
        return pt, iv, ct, tag, key

    def _decrypt_cmd(self, iv, ct, tag):
        key = derive_key(GATE_PSK, "PARKING-GATE-001")
        sc  = IoTSC1(key, iv)
        pt, ok = sc.decrypt_and_verify(ct, tag)
        return pt, ok

    # ── Log helpers ───────────────────────────────────────────
    def _log(self, w, text, tag="w"):
        w.configure(state="normal")
        w.insert("end", text, tag)
        w.see("end")
        w.configure(state="disabled")

    def _log_clr(self, w):
        w.configure(state="normal")
        w.delete("1.0", "end")
        w.configure(state="disabled")

    def _status(self, text, color=WHITE):
        self.status_lbl.configure(text=text, fg=color)

    def _upd_stats(self):
        for k, v in self.stat_vars.items():
            v.set(str(self.stats[k]))

    # ── Car arrival flow ──────────────────────────────────────
    def _process_arrival(self):
        # Find free slot
        free = [(s[0],s[1],s[2],s[3]) for s in RAW_SPOTS
                if self.slots[s[0]] is None]
        if not free:
            self._status("  Lot FULL", RED)
            self._log(self.server_log, "LOT FULL\n", "r")
            return

        slot_id, sx, sy, label = free[0]
        self.car_count += 1
        cid    = f"CAR-{self.car_count:03d}"
        dark, light = random.choice(CAR_PALETTE)

        # Build command
        cmd = {"action": "ASSIGN", "car": cid,
               "slot": label, "slot_id": slot_id,
               "seq": self.seq, "ts": int(time.time())}

        pt, iv, ct, tag, key = self._encrypt_cmd(cmd)

        # Radio log
        self._log(self.radio_log, f"\n[{cid}] UPLINK\n", "c")
        self._log(self.radio_log, f" IV : {iv.hex()}\n", "d")
        self._log(self.radio_log, f" CT : {ct.hex()[:32]}...\n", "y")
        self._log(self.radio_log, f" MAC: {tag.hex()}\n", "d")

        # Hacker intercept
        if self.hacker_on.get():
            self._log(self.hacker_log, f"\n[INTERCEPT {cid}]\n", "r")
            self._log(self.hacker_log,
                      f" RAW: {ct.hex()[:28]}...\n", "r")
            self._log(self.hacker_log,
                      " ??? NO KEY -- cannot read\n", "d")
            # Attempt injection
            fake = json.dumps({"action":"ASSIGN","car":"HACKER",
                               "slot":"A1","slot_id":1}).encode()
            fake_iv  = make_iv(self.seq + 999)
            fake_ct  = bytes(b ^ 0xFF for b in fake[:len(ct)])
            fake_tag = bytes(4)
            sc_v = IoTSC1(key, fake_iv)
            _, fake_ok = sc_v.decrypt_and_verify(fake_ct, fake_tag)
            self._log(self.hacker_log,
                      " [!] Inject fake cmd...\n", "r")
            self._log(self.hacker_log,
                      " MAC: BLOCKED -- rejected!\n" if not fake_ok
                      else " MAC: passed (error)\n", "r")
            if not fake_ok:
                self.stats["blocked"] += 1

        # Gate decrypts
        pt2, ok = self._decrypt_cmd(iv, ct, tag)
        decoded = json.loads(pt2.decode()) if ok else {}

        self._log(self.server_log, f"\n[{cid}] DECRYPTED\n", "g")
        self._log(self.server_log,
                  f" MAC : {'VALID' if ok else 'INVALID'}\n",
                  "g" if ok else "r")
        if ok:
            self._log(self.server_log,
                      f" Slot: {decoded.get('slot')} assigned\n", "c")

        if not ok:
            self._status("  MAC FAILED", RED)
            return

        # Show assignment on canvas, then animate
        self._status(f"  {cid} -> Slot {label}", CYAN)
        self._show_assignment_popup(cid, label, sx, sy)

        # Assign after popup delay
        def do_assign():
            time.sleep(1.2)
            self.slots[slot_id] = {"dark": dark, "light": light, "id": cid}
            self.stats["arrived"] += 1
            self.stats["occupied"] = sum(
                1 for v in self.slots.values() if v)
            # Open gate, animate car, close gate
            self.canvas.after(0, self._draw_gate, True)
            self._animate_car_in(sx, sy, label, dark, light, slot_id)

        threading.Thread(target=do_assign, daemon=True).start()
        self._upd_stats()

    def _show_assignment_popup(self, cid, label, sx, sy):
        """Flash a label over the target spot."""
        tag = "popup"
        self.canvas.delete(tag)
        px = sx + SW // 2
        py = sy + SH // 2

        self.canvas.create_oval(px-32, py-16, px+32, py+16,
                                fill="#003333", outline=CYAN,
                                width=2, tags=tag)
        self.canvas.create_text(px, py,
                                text=f"{label}",
                                fill=CYAN,
                                font=("Consolas", 13, "bold"),
                                tags=tag)

        def fade(count=0):
            if count >= 8:
                self.canvas.delete(tag)
                return
            self.canvas.after(150, lambda: fade(count+1))
        fade()

    def _animate_car_in(self, sx, sy, label, dark, light, slot_id):
        """Animate car from gate to parking spot."""
        c    = self.canvas
        atag = "animcar"
        c.delete(atag)

        # Start at gate
        start_x = GATE_X
        start_y = GATE_Y - 30

        # End at spot centre
        end_x = sx + SW // 2
        end_y = sy + SH // 2 + 5

        steps  = 40
        dx     = (end_x - start_x) / steps
        dy     = (end_y - start_y) / steps

        def draw_moving_car(px, py):
            c.delete(atag)
            draw_3d_car(c, px, py, dark, light,
                        scale=1.0, tag=atag, facing="up")

        def step(i=0):
            if not self.running:
                return
            if i > steps:
                c.delete(atag)
                # Close gate
                c.after(0, self._draw_gate, False)
                # Redraw spot with parked car
                for s in RAW_SPOTS:
                    if s[0] == slot_id:
                        c.after(0, self._draw_spot, s[0], s[1], s[2], s[3])
                        break
                self._status(f"  Parked -> {label}", GREEN)
                return
            px = start_x + dx * i
            py = start_y + dy * i
            c.after(0, draw_moving_car, int(px), int(py))
            self.after(35, lambda: step(i + 1))

        step()

    # ── Car departure flow ────────────────────────────────────
    def _process_departure(self):
        occ = [(s[0],s[1],s[2],s[3]) for s in RAW_SPOTS
               if self.slots[s[0]] is not None]
        if not occ:
            self._status("  Lot EMPTY", YELLOW)
            return

        slot_id, sx, sy, label = occ[0]
        car = self.slots[slot_id]
        cid = car["id"]

        cmd = {"action": "DEPART", "car": cid,
               "slot": label, "slot_id": slot_id,
               "seq": self.seq, "ts": int(time.time())}
        pt, iv, ct, tag, key = self._encrypt_cmd(cmd)

        self._log(self.radio_log, f"\n[{cid}] DEPART\n", "c")
        self._log(self.radio_log, f" CT : {ct.hex()[:32]}...\n", "y")

        if self.hacker_on.get():
            self._log(self.hacker_log,
                      f"\n[INTERCEPT DEPART]\n", "r")
            self._log(self.hacker_log,
                      f" RAW: {ct.hex()[:28]}...\n", "r")
            self._log(self.hacker_log,
                      " ??? encrypted -- cannot read\n", "d")

        _, ok = self._decrypt_cmd(iv, ct, tag)
        self._log(self.server_log, f"\n[{cid}] DEPARTS\n", "y")
        self._log(self.server_log, f" Slot {label} freed\n", "g")

        # Animate departure
        self._animate_car_out(sx, sy, label, slot_id,
                              car["dark"], car["light"])

        self.slots[slot_id] = None
        self.stats["departed"] += 1
        self.stats["occupied"] = sum(
            1 for v in self.slots.values() if v)
        self._upd_stats()
        self._status(f"  {cid} departed", YELLOW)

    def _animate_car_out(self, sx, sy, label, slot_id, dark, light):
        c    = self.canvas
        atag = "animcar_out"
        c.delete(atag)

        start_x = sx + SW // 2
        start_y = sy + SH // 2 + 5
        end_x   = GATE_X
        end_y   = GATE_Y + 30

        # Clear spot immediately
        for s in RAW_SPOTS:
            if s[0] == slot_id:
                c.after(0, self._draw_spot, s[0], s[1], s[2], s[3])
                break

        steps = 35
        dx = (end_x - start_x) / steps
        dy = (end_y - start_y) / steps

        c.after(0, self._draw_gate, True)  # open gate

        def step(i=0):
            if not self.running:
                return
            if i > steps:
                c.delete(atag)
                c.after(0, self._draw_gate, False)
                return
            px = start_x + dx * i
            py = start_y + dy * i
            c.delete(atag)
            draw_3d_car(c, int(px), int(py), dark, light,
                        scale=1.0, tag=atag, facing="down")
            self.after(35, lambda: step(i + 1))

        step()

    # ── Auto loop ─────────────────────────────────────────────
    def _auto_loop(self):
        if not self.running:
            return
        occ = sum(1 for v in self.slots.values() if v)
        if occ < 6:
            threading.Thread(
                target=self._process_arrival, daemon=True).start()
        else:
            threading.Thread(
                target=self._process_departure, daemon=True).start()
        self.after(random.randint(3000, 5000), self._auto_loop)

    def _manual_arrive(self):
        threading.Thread(
            target=self._process_arrival, daemon=True).start()

    def _manual_depart(self):
        threading.Thread(
            target=self._process_departure, daemon=True).start()

    def on_close(self):
        self.running = False
        self.destroy()


# ── Entry ─────────────────────────────────────────────────────
if __name__ == "__main__":
    app = ParkingApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
