# IoT-SC1 Traffic Simulation - Large Map, Working Traffic Lights
# Cars stop at red, go at green, proper collision avoidance
# Run: python traffic_simulation.py

import tkinter as tk
import threading
import time, struct, json, random, hashlib, os, sys, math
sys.path.insert(0, os.path.dirname(__file__))
from core.cipher import IoTSC1

# ── Crypto ────────────────────────────────────────────────────
PSK = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
def derive_key(psk, node):
    return hashlib.sha256(psk + node.encode() + b"v2x-iot-sc1").digest()[:16]
def make_iv(seq):
    return struct.pack(">II", int(time.time()*1000)&0xFFFFFFFF, seq&0xFFFFFFFF)

# ── Canvas & world ────────────────────────────────────────────
CW, CH  = 1100, 680   # canvas pixels
SCALE   = 1.0

# Isometric projection - larger scale for bigger map
ISO_TILE = 32   # pixels per world unit
OX, OY  = 550, 160   # isometric origin

def iso(wx, wy, wz=0):
    sx = OX + (wx - wy) * ISO_TILE * 0.7
    sy = OY + (wx + wy) * ISO_TILE * 0.35 - wz * ISO_TILE * 0.8
    return int(sx), int(sy)

def poly_pts(*world_pts, z=0):
    flat = []
    for wx, wy in world_pts:
        sx, sy = iso(wx, wy, z)
        flat += [sx, sy]
    return flat

def iso_face_top(c, pts_world, z, fill, outline="#111", tag="", w=1):
    flat = []
    for wx, wy in pts_world:
        sx, sy = iso(wx, wy, z)
        flat += [sx, sy]
    c.create_polygon(flat, fill=fill, outline=outline, width=w, tags=tag)

def iso_box(c, x, y, bw, bd, bh, top, left, right, ol="#111", tag="", lw=1):
    z = bh
    # top face
    iso_face_top(c, [(x,y),(x+bw,y),(x+bw,y+bd),(x,y+bd)], z, top, ol, tag, lw)
    # left face (y+bd wall)
    fl = []
    for wx, wy, wz in [(x,y+bd,0),(x+bw,y+bd,0),(x+bw,y+bd,z),(x,y+bd,z)]:
        sx,sy = iso(wx,wy,wz); fl+=[sx,sy]
    c.create_polygon(fl, fill=left, outline=ol, width=lw, tags=tag)
    # right face (x+bw wall)
    fr = []
    for wx,wy,wz in [(x+bw,y,0),(x+bw,y+bd,0),(x+bw,y+bd,z),(x+bw,y,z)]:
        sx,sy = iso(wx,wy,wz); fr+=[sx,sy]
    c.create_polygon(fr, fill=right, outline=ol, width=lw, tags=tag)

def dk(col, amt=40):
    r=max(0,int(col[1:3],16)-amt)
    g=max(0,int(col[3:5],16)-amt)
    b=max(0,int(col[5:7],16)-amt)
    return f"#{r:02x}{g:02x}{b:02x}"

def lt(col, amt=50):
    r=min(255,int(col[1:3],16)+amt)
    g=min(255,int(col[3:5],16)+amt)
    b=min(255,int(col[5:7],16)+amt)
    return f"#{r:02x}{g:02x}{b:02x}"

# ── World constants ───────────────────────────────────────────
# Road layout in world units
# Horizontal road: y = 8..13  (car), y=13..16 (bus/tram)
# Vertical road:   x = 8..13  (car), x=5..8  (other direction)
# Intersection:    x=8..13, y=8..13

ROAD_Y1, ROAD_Y2 = 8, 17    # horizontal road band
ROAD_X1, ROAD_X2 = 8, 17    # vertical road band
STOP_LINE_WE = 7.5           # stop line for west->east cars
STOP_LINE_EW = 17.5          # stop line for east->west cars
STOP_LINE_NS = 7.5           # stop line for north->south
STOP_LINE_SN = 17.5          # stop line for south->north

WORLD_W, WORLD_H = 38, 38   # world size

# ── Colours ───────────────────────────────────────────────────
C_ROAD     = "#3a3a42"
C_ROAD2    = "#44444c"
C_SIDEWALK = "#b8b0a0"
C_GRASS    = "#5a9a3a"
C_GRASS2   = "#4a8a2a"
C_MARK     = "#f0f0f0"
C_BIKE     = "#aa2020"
C_TRAM     = "#606068"
C_BLDG1    = "#c8a882"
C_BLDG2    = "#9098a8"
C_BLDG3    = "#b0b890"
C_WIN      = "#88ccff"
C_TREE     = "#3a8a1a"
C_TREE2    = "#2a7a0a"
C_TRUNK    = "#7a4a1a"
BG         = "#1a1d23"
WHITE      = "#f8f8f8"
GREEN_C    = "#00e040"
RED_C      = "#ff2020"
YELLOW_C   = "#ffdd00"
CYAN_C     = "#00d4ff"
DIM        = "#44475a"
PANEL_BG   = "#10121a"
HACK_BG    = "#1a0808"
SRV_BG     = "#081408"

# ============================================================
#  SCENE DRAWING
# ============================================================

def draw_scene(c, tl):
    """Draw the full static scene. tl = TrafficLight object."""
    c.delete("scene")

    # Ground base
    _ground(c)
    _roads(c)
    _markings(c)
    _buildings(c)
    _trees(c)
    _traffic_lights(c, tl)


def _ground(c):
    tag = "scene"
    # Large grass areas in all 4 quadrants
    quads = [
        # top-left
        [(0,0),(ROAD_X1,0),(ROAD_X1,ROAD_Y1),(0,ROAD_Y1)],
        # top-right
        [(ROAD_X2,0),(WORLD_W,0),(WORLD_W,ROAD_Y1),(ROAD_X2,ROAD_Y1)],
        # bottom-left
        [(0,ROAD_Y2),(ROAD_X1,ROAD_Y2),(ROAD_X1,WORLD_H),(0,WORLD_H)],
        # bottom-right
        [(ROAD_X2,ROAD_Y2),(WORLD_W,ROAD_Y2),(WORLD_W,WORLD_H),(ROAD_X2,WORLD_H)],
    ]
    colors = [C_GRASS, C_GRASS2, C_GRASS2, C_GRASS]
    for pts, col in zip(quads, colors):
        iso_face_top(c, pts, 0, col, "#111", tag, 1)

    # Sidewalks (thin strips bordering roads)
    sw = 1.5
    sidewalks = [
        [(0, ROAD_Y1-sw),(ROAD_X1, ROAD_Y1-sw),(ROAD_X1, ROAD_Y1),(0, ROAD_Y1)],
        [(ROAD_X2,ROAD_Y1-sw),(WORLD_W,ROAD_Y1-sw),(WORLD_W,ROAD_Y1),(ROAD_X2,ROAD_Y1)],
        [(0,ROAD_Y2),(ROAD_X1,ROAD_Y2),(ROAD_X1,ROAD_Y2+sw),(0,ROAD_Y2+sw)],
        [(ROAD_X2,ROAD_Y2),(WORLD_W,ROAD_Y2),(WORLD_W,ROAD_Y2+sw),(ROAD_X2,ROAD_Y2+sw)],
        [(ROAD_X1-sw,0),(ROAD_X1,0),(ROAD_X1,ROAD_Y1),(ROAD_X1-sw,ROAD_Y1)],
        [(ROAD_X2,0),(ROAD_X2+sw,0),(ROAD_X2+sw,ROAD_Y1),(ROAD_X2,ROAD_Y1)],
        [(ROAD_X1-sw,ROAD_Y2),(ROAD_X1,ROAD_Y2),(ROAD_X1,WORLD_H),(ROAD_X1-sw,WORLD_H)],
        [(ROAD_X2,ROAD_Y2),(ROAD_X2+sw,ROAD_Y2),(ROAD_X2+sw,WORLD_H),(ROAD_X2,WORLD_H)],
    ]
    for pts in sidewalks:
        iso_face_top(c, pts, 0, C_SIDEWALK, "#999", tag, 1)


def _roads(c):
    tag = "scene"
    # Horizontal road
    iso_face_top(c,
        [(0,ROAD_Y1),(WORLD_W,ROAD_Y1),(WORLD_W,ROAD_Y2),(0,ROAD_Y2)],
        0, C_ROAD, "#111", tag)
    # Vertical road
    iso_face_top(c,
        [(ROAD_X1,0),(ROAD_X2,0),(ROAD_X2,WORLD_H),(ROAD_X1,WORLD_H)],
        0, C_ROAD, "#111", tag)
    # Intersection (slightly different shade)
    iso_face_top(c,
        [(ROAD_X1,ROAD_Y1),(ROAD_X2,ROAD_Y1),(ROAD_X2,ROAD_Y2),(ROAD_X1,ROAD_Y2)],
        0, C_ROAD2, "#111", tag)

    # Bike lane (red strip on outer edge of horizontal road)
    iso_face_top(c,
        [(0,ROAD_Y1),(ROAD_X1,ROAD_Y1),(ROAD_X1,ROAD_Y1+1.5),(0,ROAD_Y1+1.5)],
        0.02, C_BIKE, "#800", tag)
    iso_face_top(c,
        [(ROAD_X2,ROAD_Y1),(WORLD_W,ROAD_Y1),(WORLD_W,ROAD_Y1+1.5),(ROAD_X2,ROAD_Y1+1.5)],
        0.02, C_BIKE, "#800", tag)

    # Tram track band (inside horizontal road, near centre)
    iso_face_top(c,
        [(0,ROAD_Y2-2.5),(ROAD_X1,ROAD_Y2-2.5),(ROAD_X1,ROAD_Y2),(0,ROAD_Y2)],
        0.02, C_TRAM, "#333", tag)
    iso_face_top(c,
        [(ROAD_X2,ROAD_Y2-2.5),(WORLD_W,ROAD_Y2-2.5),(WORLD_W,ROAD_Y2),(ROAD_X2,ROAD_Y2)],
        0.02, C_TRAM, "#333", tag)
    # Rails
    for ry in [ROAD_Y2-2.0, ROAD_Y2-0.8]:
        for seg in [(-2, ROAD_X1-0.1), (ROAD_X2+0.1, WORLD_W+2)]:
            p1 = iso(seg[0], ry, 0.05)
            p2 = iso(seg[1], ry, 0.05)
            c.create_line(p1[0],p1[1],p2[0],p2[1],
                          fill="#888", width=2, tags=tag)


def _markings(c):
    tag = "scene"
    # Centre dashes horizontal road
    mid_y = (ROAD_Y1 + ROAD_Y2) / 2
    for x in [x*1.5 for x in range(-2, 30)]:
        if ROAD_X1-0.5 < x < ROAD_X2+0.5: continue
        p1 = iso(x,       mid_y, 0.05)
        p2 = iso(x + 0.8, mid_y, 0.05)
        c.create_line(p1[0],p1[1],p2[0],p2[1],
                      fill=C_MARK, width=2, dash=(4,4), tags=tag)

    # Centre dashes vertical road
    mid_x = (ROAD_X1 + ROAD_X2) / 2
    for y in [y*1.5 for y in range(-2, 30)]:
        if ROAD_Y1-0.5 < y < ROAD_Y2+0.5: continue
        p1 = iso(mid_x, y,       0.05)
        p2 = iso(mid_x, y + 0.8, 0.05)
        c.create_line(p1[0],p1[1],p2[0],p2[1],
                      fill=C_MARK, width=2, dash=(4,4), tags=tag)

    # Crosswalk stripes at intersection
    for i in range(5):
        ox = ROAD_X1 + 0.8 + i * 1.5
        if ox + 1 > ROAD_X2: break
        iso_face_top(c,
            [(ox, ROAD_Y1-0.1),(ox+0.9, ROAD_Y1-0.1),
             (ox+0.9, ROAD_Y1+0.6),(ox, ROAD_Y1+0.6)],
            0.05, WHITE, "", tag)
        iso_face_top(c,
            [(ox, ROAD_Y2-0.6),(ox+0.9, ROAD_Y2-0.6),
             (ox+0.9, ROAD_Y2+0.1),(ox, ROAD_Y2+0.1)],
            0.05, WHITE, "", tag)

    # Stop lines
    for y0, y1 in [(ROAD_Y1, ROAD_Y1+0.3), (ROAD_Y2-0.3, ROAD_Y2)]:
        iso_face_top(c,
            [(ROAD_X1-0.1,y0),(ROAD_X1+0.2,y0),
             (ROAD_X1+0.2,y1),(ROAD_X1-0.1,y1)],
            0.06, WHITE, "", tag)
        iso_face_top(c,
            [(ROAD_X2-0.2,y0),(ROAD_X2+0.1,y0),
             (ROAD_X2+0.1,y1),(ROAD_X2-0.2,y1)],
            0.06, WHITE, "", tag)

    # Bike symbols
    for bx in [3, 5, 20, 24]:
        px, py = iso(bx, ROAD_Y1+0.8, 0.06)
        c.create_text(px, py, text="B", fill="#ff8888",
                      font=("Arial",8,"bold"), tags=tag)


def _buildings(c):
    tag = "scene"
    defs = [
        # top-left cluster
        (0.5, 0.5, 5, 4, 6,  C_BLDG1),
        (0.5, 5,   4, 2.5,4, C_BLDG2),
        (6,   0.5, 1.2,4,10, C_BLDG3),
        # top-right cluster
        (18.5, 0.5, 6, 5, 8, C_BLDG2),
        (25,   0.5, 5, 4, 5, C_BLDG1),
        (31,   0.5, 6, 4, 9, C_BLDG3),
        # bottom-right cluster
        (18.5,18.5, 6,6, 7, C_BLDG1),
        (25,  18.5, 5,5, 5, C_BLDG2),
        (31,  18.5, 6,5, 6, C_BLDG3),
        # bottom-left cluster
        (0.5, 18.5, 5,5, 4, C_BLDG2),
        (0.5, 24,   4,4, 6, C_BLDG1),
    ]
    for bx,by,bw,bd,bh,col in defs:
        top   = col
        left  = dk(col, 45)
        right = dk(col, 25)
        iso_box(c, bx,by,bw,bd,bh, top,left,right, tag=tag)
        _windows(c, bx,by,bw,bd,bh, tag)


def _windows(c, bx,by,bw,bd,bh, tag):
    rows = max(1, int(bh//2))
    cols = max(1, int(bw//1.8))
    for r in range(rows):
        wz = 0.8 + r * 2.0
        if wz+1 > bh: break
        for col in range(cols):
            wy = by + 0.6 + col * 1.8
            if wy+1 > by+bd: break
            pts = [(bx+bw, wy, wz),(bx+bw, wy+1, wz),
                   (bx+bw, wy+1, wz+1.2),(bx+bw, wy, wz+1.2)]
            flat = []
            for wx,wy2,wz2 in pts:
                sx,sy = iso(wx,wy2,wz2); flat+=[sx,sy]
            c.create_polygon(flat, fill=C_WIN, outline="#446",
                             width=1, tags=tag)


def _trees(c):
    tag = "scene"
    positions = [
        # along top of horizontal road
        (2,6.5),(4,6.5),(6,6.5),
        (18.5,6.5),(21,6.5),(24,6.5),(27,6.5),(30,6.5),(33,6.5),
        # along bottom
        (2,18),(4,18),(6,18),
        (18.5,18),(21,18),(24,18),(27,18),(30,18),(33,18),
        # along left of vertical road
        (6.5,2),(6.5,4),(6.5,6),
        (6.5,19),(6.5,22),(6.5,25),(6.5,28),(6.5,31),(6.5,34),
        # along right
        (18,2),(18,4),(18,6),
        (18,19),(18,22),(18,25),(18,28),(18,31),(18,34),
    ]
    for tx,ty in positions:
        _tree(c, tx, ty, tag)


def _tree(c, tx, ty, tag):
    # trunk
    iso_box(c, tx,ty, 0.4,0.4, 1.2,
            C_TRUNK, dk(C_TRUNK,20), dk(C_TRUNK,10), tag=tag)
    # canopy
    iso_box(c, tx-0.8,ty-0.8, 2.0,2.0, 1.8,
            C_TREE2, dk(C_TREE,15), C_TREE, ol="#1a4a0a", tag=tag)


def _traffic_lights(c, tl):
    tag = "scene"
    # 4 poles at intersection corners
    poles = [
        (ROAD_X1-1.2, ROAD_Y1-1.2),  # NW - controls NS flow
        (ROAD_X2+0.2, ROAD_Y1-1.2),  # NE - controls EW flow
        (ROAD_X1-1.2, ROAD_Y2+0.2),  # SW - controls EW flow
        (ROAD_X2+0.2, ROAD_Y2+0.2),  # SE - controls NS flow
    ]
    # Which signals control which direction
    # NS = north-south vehicles get tl.ns_state
    # EW = east-west vehicles get tl.ew_state
    pole_states = [tl.ns_state, tl.ew_state, tl.ew_state, tl.ns_state]

    for (px,py), state in zip(poles, pole_states):
        # Pole
        iso_box(c, px,py, 0.3,0.3, 3.5,
                "#777", "#555", "#666", tag=tag)
        # Light housing
        iso_box(c, px-0.15,py-0.15, 0.6,0.6, 2.8,
                "#111", "#0a0a0a", "#1a1a1a", tag=tag)

        # Three lights: red, yellow, green (top to bottom)
        for i, (lstate, lcolor_on, lcolor_off) in enumerate([
            ("red",    "#ff2020", "#330a0a"),
            ("yellow", "#ffdd00", "#333300"),
            ("green",  "#00e040", "#003310"),
        ]):
            lz = 2.8 - i * 0.8
            active = (state == lstate)
            col = lcolor_on if active else lcolor_off
            px2, py2 = iso(px+0.15, py+0.15, lz)
            r = 9 if active else 6
            c.create_oval(px2-r, py2-r, px2+r, py2+r,
                          fill=col, outline="#000", width=1, tags=tag)
            if active:
                # Glow effect
                c.create_oval(px2-r-4, py2-r-3,
                              px2+r+4, py2+r+3,
                              fill="", outline=col,
                              width=2, tags=tag)

        # Label sign above pole
        sx, sy = iso(px+0.15, py+0.15, 3.8)
        c.create_text(sx, sy, text=state.upper()[:1],
                      fill={"red":RED_C,"yellow":YELLOW_C,
                            "green":GREEN_C}[state],
                      font=("Arial",7,"bold"), tags=tag)

# ============================================================
#  TRAFFIC LIGHT CONTROLLER
# ============================================================
class TrafficLight:
    """
    Proper 4-phase traffic light controller.
    EW and NS alternate. Yellow is a brief transition.
    """
    PHASE_DURATION = {
        "ew_green":  180,   # ticks (~6 sec)
        "ew_yellow":  30,
        "ns_green":  180,
        "ns_yellow":  30,
    }
    PHASES = ["ew_green","ew_yellow","ns_green","ns_yellow"]

    def __init__(self):
        self.phase_idx = 0
        self.timer     = 0
        self._update_states()

    def _update_states(self):
        phase = self.PHASES[self.phase_idx]
        if phase == "ew_green":
            self.ew_state = "green";  self.ns_state = "red"
        elif phase == "ew_yellow":
            self.ew_state = "yellow"; self.ns_state = "red"
        elif phase == "ns_green":
            self.ew_state = "red";    self.ns_state = "green"
        elif phase == "ns_yellow":
            self.ew_state = "red";    self.ns_state = "yellow"

    def tick(self):
        self.timer += 1
        phase = self.PHASES[self.phase_idx]
        if self.timer >= self.PHASE_DURATION[phase]:
            self.timer    = 0
            self.phase_idx = (self.phase_idx + 1) % len(self.PHASES)
            self._update_states()

    def can_go_ew(self):
        return self.ew_state == "green"

    def can_go_ns(self):
        return self.ns_state == "green"


# ============================================================
#  VEHICLE
# ============================================================
CAR_COLORS = [
    ("#c0392b","#e74c3c"),("#1565c0","#2196f3"),
    ("#ffffff","#e8e8e8"),("#555555","#888888"),
    ("#e65100","#ff9800"),("#1b5e20","#4caf50"),
    ("#4a148c","#9c27b0"),("#880e4f","#e91e63"),
    ("#b8860b","#ffd700"),("#006064","#00bcd4"),
]

class Vehicle:
    _id = 0

    def __init__(self, vtype, route, color1, color2=None):
        Vehicle._id += 1
        self.vid    = f"{vtype[0].upper()}{Vehicle._id:03d}"
        self.vtype  = vtype
        self.route  = route
        self.wpt    = 1
        self.wx     = float(route[0][0])
        self.wy     = float(route[0][1])
        self.color1 = color1
        self.color2 = color2 or lt(color1, 40)
        self.tag    = f"veh_{Vehicle._id}"
        self.done   = False
        self.waiting = False
        self.speed  = {"car":0.12,"bus":0.07,"tram":0.05}[vtype]
        self.direction = "east"   # updated each step

    def _facing(self):
        if self.wpt >= len(self.route): return self.direction
        tx,ty = self.route[self.wpt]
        dx,dy = tx-self.wx, ty-self.wy
        if abs(dx) >= abs(dy):
            return "east" if dx>0 else "west"
        else:
            return "south" if dy>0 else "north"

    def in_intersection(self):
        return (ROAD_X1 < self.wx < ROAD_X2 and
                ROAD_Y1 < self.wy < ROAD_Y2)

    def is_ew(self):
        return self.direction in ("east", "west")

    def must_stop(self, tl):
        """
        True if vehicle must stop for red/yellow.
        Uses a 4-unit approach zone before the stop line.
        Once inside the intersection the vehicle always continues.
        """
        if self.in_intersection():
            return False        # never stop mid-crossing

        d    = self.direction
        ZONE = 4.0              # how far before stop line we start braking

        if d == "east":
            in_zone = ((STOP_LINE_WE - ZONE) <= self.wx <= STOP_LINE_WE
                       and ROAD_Y1 - 1 <= self.wy <= ROAD_Y2 + 1)
            return in_zone and not tl.can_go_ew()

        if d == "west":
            in_zone = (STOP_LINE_EW <= self.wx <= (STOP_LINE_EW + ZONE)
                       and ROAD_Y1 - 1 <= self.wy <= ROAD_Y2 + 1)
            return in_zone and not tl.can_go_ew()

        if d == "south":
            in_zone = ((STOP_LINE_NS - ZONE) <= self.wy <= STOP_LINE_NS
                       and ROAD_X1 - 1 <= self.wx <= ROAD_X2 + 1)
            return in_zone and not tl.can_go_ns()

        if d == "north":
            in_zone = (STOP_LINE_SN <= self.wy <= (STOP_LINE_SN + ZONE)
                       and ROAD_X1 - 1 <= self.wx <= ROAD_X2 + 1)
            return in_zone and not tl.can_go_ns()

        return False

    def clamp_stop(self):
        """Hard-clamp so vehicle never creeps past the stop line."""
        d = self.direction
        if d == "east"  and self.wx > STOP_LINE_WE: self.wx = STOP_LINE_WE
        if d == "west"  and self.wx < STOP_LINE_EW: self.wx = STOP_LINE_EW
        if d == "south" and self.wy > STOP_LINE_NS: self.wy = STOP_LINE_NS
        if d == "north" and self.wy < STOP_LINE_SN: self.wy = STOP_LINE_SN

    def step(self, tl, all_vehicles):
        if self.done: return
        if self.wpt >= len(self.route):
            self.done = True
            return

        # Always update direction first
        self.direction = self._facing()

        # Traffic light check — stop and hard-clamp
        if self.must_stop(tl):
            self.waiting = True
            self.clamp_stop()
            return

        # Collision avoidance — gap to next vehicle in same lane
        for other in all_vehicles:
            if other is self or other.done:
                continue
            if self._gap_to(other) < 1.8:
                self.waiting = True
                return

        self.waiting = False

        # Move toward next waypoint
        tx, ty = self.route[self.wpt]
        dx, dy = tx - self.wx, ty - self.wy
        dist   = math.hypot(dx, dy)
        if dist <= self.speed:
            self.wx, self.wy = tx, ty
            self.wpt += 1
        else:
            self.wx += dx / dist * self.speed
            self.wy += dy / dist * self.speed

    def _gap_to(self, other):
        """Distance to another vehicle in same direction band."""
        d = self.direction
        if d in ("east","west"):
            if abs(self.wy - other.wy) > 2.0: return 999
            if d == "east"  and other.wx > self.wx:
                return other.wx - self.wx
            if d == "west"  and other.wx < self.wx:
                return self.wx  - other.wx
        else:
            if abs(self.wx - other.wx) > 2.0: return 999
            if d == "south" and other.wy > self.wy:
                return other.wy - self.wy
            if d == "north" and other.wy < self.wy:
                return self.wy  - other.wy
        return 999

    def draw(self, c):
        c.delete(self.tag)
        if self.done: return
        x, y = int(self.wx*10)/10, int(self.wy*10)/10
        d = self.direction
        if self.vtype == "car":
            _draw_car(c, x, y, self.color1, self.color2, d, self.tag)
        elif self.vtype == "bus":
            _draw_bus(c, x, y, "#e8a800", d, self.tag)
        elif self.vtype == "tram":
            _draw_tram(c, x, y, d, self.tag)

        # Waiting indicator (red dot above)
        if self.waiting:
            px, py = iso(x + 0.5, y + 0.5, 3)
            c.create_oval(px-4, py-4, px+4, py+4,
                          fill=RED_C, outline="", tags=self.tag)

# ============================================================
#  3D Vehicle Drawing
# ============================================================

def _draw_car(c, wx, wy, col, col2, direction, tag):
    if direction == "east":
        bw,bd,bh = 2.2, 1.0, 0.5
        rox,roy  = 0.5, 0.1
        rw,rd    = 1.2, 0.8
    elif direction == "west":
        bw,bd,bh = 2.2, 1.0, 0.5
        wx -= bw
        rox,roy  = 0.5, 0.1
        rw,rd    = 1.2, 0.8
    elif direction == "south":
        bw,bd,bh = 1.0, 2.2, 0.5
        rox,roy  = 0.1, 0.5
        rw,rd    = 0.8, 1.2
    else:  # north
        bw,bd,bh = 1.0, 2.2, 0.5
        wy -= bd
        rox,roy  = 0.1, 0.5
        rw,rd    = 0.8, 1.2

    # Body
    iso_box(c, wx,wy, bw,bd,bh,
            col, dk(col,35), dk(col,18), tag=tag)
    # Roof
    iso_box(c, wx+rox,wy+roy, rw,rd, bh+0.4,
            col2, dk(col2,30), dk(col2,15), tag=tag)
    # Windscreen
    if direction == "east":
        pts = [(wx+bw, wy+0.1, bh),
               (wx+bw, wy+bd-0.1, bh),
               (wx+bw, wy+bd-0.15, bh+0.38),
               (wx+bw, wy+0.15, bh+0.38)]
        flat = []
        for ax,ay,az in pts:
            sx,sy = iso(ax,ay,az); flat+=[sx,sy]
        c.create_polygon(flat, fill="#aaddff", outline="#226", width=1, tags=tag)
    elif direction == "south":
        pts = [(wx+0.1, wy+bd, bh),
               (wx+bw-0.1, wy+bd, bh),
               (wx+bw-0.15, wy+bd, bh+0.38),
               (wx+0.15, wy+bd, bh+0.38)]
        flat = []
        for ax,ay,az in pts:
            sx,sy = iso(ax,ay,az); flat+=[sx,sy]
        c.create_polygon(flat, fill="#aaddff", outline="#226", width=1, tags=tag)

    # Headlights
    if direction == "east":
        px,py = iso(wx+bw, wy+bd/2, bh*0.6)
        c.create_oval(px-4,py-3,px+4,py+3,
                      fill="#ffffaa", outline="", tags=tag)
    elif direction == "south":
        px,py = iso(wx+bw/2, wy+bd, bh*0.6)
        c.create_oval(px-4,py-3,px+4,py+3,
                      fill="#ffffaa", outline="", tags=tag)
    # Brake lights
    if direction == "west":
        px,py = iso(wx, wy+bd/2, bh*0.6)
        c.create_oval(px-4,py-3,px+4,py+3,
                      fill=RED_C, outline="", tags=tag)
    elif direction == "north":
        px,py = iso(wx+bw/2, wy, bh*0.6)
        c.create_oval(px-4,py-3,px+4,py+3,
                      fill=RED_C, outline="", tags=tag)


def _draw_bus(c, wx, wy, col, direction, tag):
    if direction in ("east","west"):
        bw,bd,bh = 4.5, 1.3, 1.1
        if direction == "west": wx -= bw
        rw,rd = 4.5, 1.3
    else:
        bw,bd,bh = 1.3, 4.5, 1.1
        if direction == "north": wy -= bd
        rw,rd = 1.3, 4.5

    iso_box(c, wx,wy, bw,bd,bh,
            col, dk(col,45), dk(col,25), tag=tag)
    # Black roof
    iso_box(c, wx,wy, bw,bd, bh+0.2,
            "#111","#000","#0a0a0a", tag=tag)
    # Windows bank
    n = int(bw/0.9) if direction in ("east","west") else int(bd/0.9)
    for i in range(n-1):
        if direction in ("east","west"):
            wsx = wx + 0.5 + i*0.9
            wsy = wy
            pts = [(wsx, wsy+0.05, bh-0.05),(wsx+0.7, wsy+0.05, bh-0.05),
                   (wsx+0.7, wsy+0.05, bh+0.6),(wsx, wsy+0.05, bh+0.6)]
        else:
            wsx = wx
            wsy = wy + 0.5 + i*0.9
            pts = [(wsx+bw-0.05, wsy, bh-0.05),(wsx+bw-0.05, wsy+0.7, bh-0.05),
                   (wsx+bw-0.05, wsy+0.7, bh+0.6),(wsx+bw-0.05, wsy, bh+0.6)]
        flat = []
        for ax,ay,az in pts:
            sx,sy = iso(ax,ay,az); flat+=[sx,sy]
        c.create_polygon(flat, fill="#5588aa", outline="#224", width=1, tags=tag)


def _draw_tram(c, wx, wy, direction, tag):
    col = "#e8a800"
    if direction in ("east","west"):
        bw,bd,bh = 7.0, 1.3, 1.3
        if direction == "west": wx -= bw
    else:
        bw,bd,bh = 1.3, 7.0, 1.3
        if direction == "north": wy -= bd

    iso_box(c, wx,wy, bw,bd,bh,
            col, dk(col,50), dk(col,30), tag=tag)
    iso_box(c, wx,wy, bw,bd, bh+0.3,
            "#111","#000","#0a0a0a", tag=tag)
    n = int(bw/0.9) if direction in ("east","west") else int(bd/0.9)
    for i in range(n-1):
        if direction in ("east","west"):
            wsx = wx + 0.5 + i*0.9
            pts = [(wsx, wy+0.05, bh-0.1),(wsx+0.7, wy+0.05, bh-0.1),
                   (wsx+0.7, wy+0.05, bh+0.7),(wsx, wy+0.05, bh+0.7)]
        else:
            wsy = wy + 0.5 + i*0.9
            pts = [(wx+bw-0.05, wsy, bh-0.1),(wx+bw-0.05, wsy+0.7, bh-0.1),
                   (wx+bw-0.05, wsy+0.7, bh+0.7),(wx+bw-0.05, wsy, bh+0.7)]
        flat = []
        for ax,ay,az in pts:
            sx,sy = iso(ax,ay,az); flat+=[sx,sy]
        c.create_polygon(flat, fill="#2255aa", outline="#113", width=1, tags=tag)


def draw_pedestrian(c, wx, wy, col="#f0c080", tag="p"):
    px,py = iso(wx, wy, 0)
    c.create_line(px-3,py+4, px-1,py+10, fill="#444", width=2, tags=tag)
    c.create_line(px+3,py+4, px+1,py+10, fill="#444", width=2, tags=tag)
    c.create_rectangle(px-4,py-4, px+4,py+4, fill=col, outline="#333", tags=tag)
    c.create_oval(px-4,py-12, px+4,py-4, fill="#f0c080", outline="#555", tags=tag)


def draw_cyclist(c, wx, wy, col="#ffffff", tag="cy"):
    px,py = iso(wx, wy, 0)
    c.create_oval(px-9,py-4,  px-1,py+4,  fill="", outline="#555", width=2, tags=tag)
    c.create_oval(px+1,py-4,  px+9,py+4,  fill="", outline="#555", width=2, tags=tag)
    c.create_line(px-5,py,    px+5,py,     fill="#888", width=2, tags=tag)
    c.create_line(px,py,      px-2,py-9,   fill="#888", width=2, tags=tag)
    c.create_rectangle(px-4,py-15, px+4,py-7, fill=col, outline="#333", tags=tag)
    c.create_oval(px-4,py-21, px+4,py-14, fill="#f0c080", outline="#555", tags=tag)

# ============================================================
#  ROUTES
# ============================================================
# EW (east-west): y in 9..12 range
# NS (north-south): x in 9..12 range
# Tram: y ~15..16 range

def _ew_routes():
    return [
        # West to east, various lanes
        [(-2,9.5),(STOP_LINE_WE,9.5),(14,9.5),(25,9.5),(40,9.5)],
        [(-2,10.5),(STOP_LINE_WE,10.5),(14,10.5),(25,10.5),(40,10.5)],
        [(-2,11.5),(STOP_LINE_WE,11.5),(14,11.5),(25,11.5),(40,11.5)],
        # East to west
        [(40,13.5),(STOP_LINE_EW,13.5),(10,13.5),(0,13.5),(-2,13.5)],
        [(40,14.5),(STOP_LINE_EW,14.5),(10,14.5),(0,14.5),(-2,14.5)],
        # Turn right: west->east then turn south
        [(-2,9.5),(STOP_LINE_WE,9.5),(12.5,9.5),(12.5,14),(12.5,25),(12.5,40)],
        # Turn left: east->west then turn south
        [(40,13.5),(STOP_LINE_EW,13.5),(11,13.5),(11,14),(11,25),(11,40)],
    ]

def _ns_routes():
    return [
        # North to south
        [(9.5,-2),(9.5,STOP_LINE_NS),(9.5,14),(9.5,25),(9.5,40)],
        [(10.5,-2),(10.5,STOP_LINE_NS),(10.5,14),(10.5,25),(10.5,40)],
        # South to north
        [(12.5,40),(12.5,STOP_LINE_SN),(12.5,10),(12.5,0),(12.5,-2)],
        [(13.5,40),(13.5,STOP_LINE_SN),(13.5,10),(13.5,0),(13.5,-2)],
    ]

def _tram_routes():
    return [
        [(-2,15.5),(STOP_LINE_WE,15.5),(17,15.5),(25,15.5),(40,15.5)],
        [(40,16),(STOP_LINE_EW,16),(10,16),(0,16),(-2,16)],
    ]

def _bus_routes():
    return [
        [(-2,12),(STOP_LINE_WE,12),(17,12),(25,12),(40,12)],
        [(40,12.5),(STOP_LINE_EW,12.5),(10,12.5),(0,12.5),(-2,12.5)],
    ]

PED_ROUTES = [
    [(7.2,9),(7.2,17),(7.2,20)],
    [(7.2,20),(7.2,17),(7.2,9)],
    [(18,9),(18,17),(18,22)],
    [(9,7.2),(17,7.2),(22,7.2)],
    [(9,18),(17,18),(22,18)],
    [(22,7.2),(17,7.2),(9,7.2)],
]
CYC_ROUTES = [
    [(-2,8.5),(STOP_LINE_WE,8.5),(17,8.5),(25,8.5),(40,8.5)],
    [(40,9),(STOP_LINE_EW,9),(10,9),(0,9),(-2,9)],
]
PED_COLS = ["#f0c080","#d08050","#80a0f0","#f080a0",
            "#a0e0a0","#e0e0e0","#f0d080","#80d0d0"]


# ============================================================
#  MAIN APPLICATION
# ============================================================
class TrafficApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IoT-SC1 -- 3D Smart Traffic Simulation")
        self.resizable(False, False)
        self.configure(bg=BG)

        self.tl       = TrafficLight()
        self.vehicles = []
        self.walkers  = []
        self.seq      = 0
        self.tick_n   = 0
        self.running  = True
        self.hacker   = tk.BooleanVar(value=True)
        self.stats    = {"vehicles":0,"msgs":0,"mac_ok":0,"blocked":0}

        self._build_ui()
        self._spawn_scene()
        self._tick()

    # ── UI ────────────────────────────────────────────────────
    def _build_ui(self):
        hdr = tk.Frame(self, bg="#161b22", height=42)
        hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr,
                 text="  IoT-SC1  Smart Traffic Control  --  3D Isometric City",
                 bg="#161b22", fg=WHITE,
                 font=("Consolas",12,"bold")).pack(side="left", padx=8)
        tk.Label(hdr, text="V2X encrypted | MAC verified | Hacker blocked  ",
                 bg="#161b22", fg=DIM,
                 font=("Consolas",9)).pack(side="right")

        row = tk.Frame(self, bg=BG)
        row.pack(fill="both", expand=True)

        left = tk.Frame(row, bg=BG)
        left.pack(side="left")
        self.canvas = tk.Canvas(left, width=CW, height=CH,
                                bg="#5a9a3a",
                                highlightthickness=0)
        self.canvas.pack(padx=4, pady=4)

        ctrl = tk.Frame(left, bg=BG)
        ctrl.pack(fill="x", padx=4, pady=(0,4))

        def btn(t, cmd, bg2, fg2):
            return tk.Button(ctrl, text=t, command=cmd,
                             bg=bg2, fg=fg2,
                             font=("Consolas",9,"bold"),
                             relief="flat", cursor="hand2",
                             padx=8, pady=3,
                             activebackground="#333")

        btn("+Car",  self._add_car,  "#1b4d1b", GREEN_C).pack(side="left",padx=2)
        btn("+Bus",  self._add_bus,  "#1b2d4d", CYAN_C).pack(side="left",padx=2)
        btn("+Tram", self._add_tram, "#4d3d1b", YELLOW_C).pack(side="left",padx=2)
        btn("+Ped",  self._add_ped,  "#3d1b3d", "#cc88ff").pack(side="left",padx=2)
        btn("Clear", self._clear,    "#3d1b1b", RED_C).pack(side="left",padx=2)

        tk.Checkbutton(ctrl, text=" Hacker",
                       variable=self.hacker,
                       bg=BG, fg=RED_C, selectcolor="#2a0808",
                       font=("Consolas",9),
                       activebackground=BG).pack(side="left",padx=8)

        self.tl_lbl = tk.Label(ctrl, text="EW:GREEN  NS:RED",
                               bg=BG, fg=GREEN_C,
                               font=("Consolas",9,"bold"))
        self.tl_lbl.pack(side="right", padx=8)

        # Right panels
        right = tk.Frame(row, bg=PANEL_BG, width=320)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        def plbl(text, bg2, fg2):
            tk.Label(right, text=text, bg=bg2, fg=fg2,
                     font=("Consolas",9,"bold"),
                     anchor="w").pack(fill="x", padx=6, pady=(6,2))

        def mlog(bg2, h, fg2=WHITE):
            t = tk.Text(right, height=h, bg=bg2, fg=fg2,
                        font=("Consolas",8), relief="flat",
                        wrap="char", state="disabled", padx=4)
            t.pack(fill="x", padx=6)
            for tg,col in [("g",GREEN_C),("r",RED_C),("y",YELLOW_C),
                            ("c",CYAN_C),("d",DIM),("w",WHITE)]:
                t.tag_config(tg, foreground=col)
            return t

        def div():
            tk.Frame(right, bg="#222233", height=1).pack(fill="x",padx=6,pady=2)

        plbl("  V2X Radio (encrypted)", PANEL_BG, CYAN_C)
        self.rlog = mlog(PANEL_BG, 5)
        div()
        plbl("  Hacker (sees only ciphertext)", HACK_BG, RED_C)
        self.hlog = mlog(HACK_BG, 5, RED_C)
        div()
        plbl("  Traffic Controller (decrypted)", SRV_BG, GREEN_C)
        self.slog = mlog(SRV_BG, 6, GREEN_C)
        div()

        # Traffic light display
        tl_frame = tk.Frame(right, bg=PANEL_BG)
        tl_frame.pack(fill="x", padx=6, pady=4)
        tk.Label(tl_frame, text="  Traffic Light Status",
                 bg=PANEL_BG, fg=DIM,
                 font=("Consolas",8,"bold")).pack(anchor="w")
        tl_inner = tk.Frame(tl_frame, bg="#1c1f26")
        tl_inner.pack(fill="x", pady=2)
        self.ew_lbl = tk.Label(tl_inner, text="EW: GREEN",
                               bg="#1c1f26", fg=GREEN_C,
                               font=("Consolas",10,"bold"))
        self.ew_lbl.pack(side="left", expand=True)
        self.ns_lbl = tk.Label(tl_inner, text="NS: RED",
                               bg="#1c1f26", fg=RED_C,
                               font=("Consolas",10,"bold"))
        self.ns_lbl.pack(side="right", expand=True)

        div()
        sf = tk.Frame(right, bg=PANEL_BG)
        sf.pack(fill="x", padx=6, pady=4)
        self.svars = {}
        for label, key, col in [("Active","vehicles",CYAN_C),
                                 ("Msgs","msgs",WHITE),
                                 ("OK","mac_ok",GREEN_C),
                                 ("Blocked","blocked",RED_C)]:
            b = tk.Frame(sf, bg="#1c1f26")
            b.pack(side="left", expand=True, fill="x", padx=2)
            tk.Label(b, text=label, bg="#1c1f26", fg=DIM,
                     font=("Consolas",7)).pack()
            v = tk.StringVar(value="0")
            self.svars[key] = v
            tk.Label(b, textvariable=v, bg="#1c1f26", fg=col,
                     font=("Consolas",13,"bold")).pack()

    # ── Logging ───────────────────────────────────────────────
    def _log(self, w, text, tag="w"):
        w.configure(state="normal")
        w.insert("end", text, tag)
        w.see("end")
        w.configure(state="disabled")

    def _upd(self):
        active = sum(1 for v in self.vehicles if not v.done)
        self.stats["vehicles"] = active
        for k, v in self.svars.items():
            v.set(str(self.stats[k]))
        # Traffic light labels
        ew_col = {GREEN_C:"g",YELLOW_C:"y",RED_C:"r"}
        ns_col = {GREEN_C:"g",YELLOW_C:"y",RED_C:"r"}
        ew_state = self.tl.ew_state.upper()
        ns_state = self.tl.ns_state.upper()
        ew_c = {"GREEN":GREEN_C,"YELLOW":YELLOW_C,"RED":RED_C}[ew_state]
        ns_c = {"GREEN":GREEN_C,"YELLOW":YELLOW_C,"RED":RED_C}[ns_state]
        self.ew_lbl.configure(text=f"EW: {ew_state}", fg=ew_c)
        self.ns_lbl.configure(text=f"NS: {ns_state}", fg=ns_c)
        self.tl_lbl.configure(
            text=f"EW:{ew_state}  NS:{ns_state}",
            fg=ew_c)

    # ── Encrypted V2X message ─────────────────────────────────
    def _v2x(self, v):
        key = derive_key(PSK, "TL-NODE-001")
        iv  = make_iv(self.seq); self.seq += 1
        cmd = {"vid":v.vid,"type":v.vtype,
               "x":round(v.wx,1),"y":round(v.wy,1),
               "tl_ew":self.tl.ew_state,
               "tl_ns":self.tl.ns_state,
               "wait":v.waiting}
        pt  = json.dumps(cmd).encode()
        sc  = IoTSC1(key, iv)
        ct, tag = sc.encrypt_with_mac(pt)

        self._log(self.rlog,
                  f"[{v.vid}] {ct.hex()[:16]}... {tag.hex()}\n", "c")

        if self.hacker.get():
            self._log(self.hlog,
                      f"[{v.vid}] {ct.hex()[:14]}...\n", "r")
            fake_iv  = make_iv(self.seq+9999)
            fake_ct  = bytes(b^0xAA for b in ct)
            sc2 = IoTSC1(key, fake_iv)
            _, fok = sc2.decrypt_and_verify(fake_ct, bytes(4))
            if not fok:
                self._log(self.hlog, "  BLOCKED\n", "d")
                self.stats["blocked"] += 1

        sc3 = IoTSC1(key, iv)
        pt3, ok = sc3.decrypt_and_verify(ct, tag)
        if ok:
            self._log(self.slog,
                      f"[{v.vid}] {v.vtype} "
                      f"({round(v.wx,1)},{round(v.wy,1)}) "
                      f"wait={'Y' if v.waiting else 'N'}\n", "g")
            self.stats["mac_ok"] += 1
        self.stats["msgs"] += 1

    # ── Spawn ─────────────────────────────────────────────────
    def _make_car(self, route=None):
        r = route or random.choice(_ew_routes() + _ns_routes())
        c1, c2 = random.choice(CAR_COLORS)
        return Vehicle("car", r, c1, c2)

    def _make_bus(self):
        r = random.choice(_bus_routes())
        return Vehicle("bus", r, "#e8a800")

    def _make_tram(self):
        r = random.choice(_tram_routes())
        return Vehicle("tram", r, "#e8a800")

    def _add_car(self):
        self.vehicles.append(self._make_car())
    def _add_bus(self):
        self.vehicles.append(self._make_bus())
    def _add_tram(self):
        self.vehicles.append(self._make_tram())
    def _add_ped(self):
        from types import SimpleNamespace
        w = SimpleNamespace()
        w.route = list(random.choice(PED_ROUTES))
        w.wpt   = 0
        w.wx    = float(w.route[0][0])
        w.wy    = float(w.route[0][1])
        w.tag   = f"ped_{self.seq}"
        w.done  = False
        w.speed = 0.03
        w.color = random.choice(PED_COLS)
        w.wtype = random.choice(["ped","ped","cyclist"])
        self.walkers.append(w)

    def _clear(self):
        for v in self.vehicles: self.canvas.delete(v.tag)
        for w in self.walkers:  self.canvas.delete(w.tag)
        self.vehicles.clear()
        self.walkers.clear()

    def _spawn_scene(self):
        for _ in range(5): self._add_car()
        for _ in range(2): self._add_bus()
        self._add_tram()
        for _ in range(4): self._add_ped()

    # ── Main tick ─────────────────────────────────────────────
    def _tick(self):
        if not self.running: return
        self.tick_n += 1

        # Update traffic light
        self.tl.tick()

        # Move vehicles
        for v in self.vehicles:
            v.step(self.tl, self.vehicles)

        # Move walkers
        for w in self.walkers:
            if not w.done:
                if w.wpt < len(w.route):
                    tx,ty = w.route[w.wpt]
                    dx,dy = tx-w.wx, ty-w.wy
                    dist  = math.hypot(dx,dy)
                    if dist < w.speed:
                        w.wx,w.wy = tx,ty
                        w.wpt += 1
                    else:
                        w.wx += dx/dist*w.speed
                        w.wy += dy/dist*w.speed
                else:
                    w.done = True

        # Remove done entities
        for v in [x for x in self.vehicles if x.done]:
            self.canvas.delete(v.tag)
        self.vehicles = [v for v in self.vehicles if not v.done]
        for w in [x for x in self.walkers if x.done]:
            self.canvas.delete(w.tag)
        self.walkers = [w for w in self.walkers if not w.done]

        # Auto-spawn
        if self.tick_n % 120 == 0:
            self._add_car()
        if self.tick_n % 400 == 0:
            self._add_bus()
        if self.tick_n % 600 == 0:
            self._add_tram()
        if self.tick_n % 200 == 0:
            self._add_ped()

        # V2X message every 90 ticks
        if self.tick_n % 90 == 0 and self.vehicles:
            v = random.choice(self.vehicles)
            threading.Thread(target=self._v2x,
                             args=(v,), daemon=True).start()

        # Redraw
        self._redraw()
        self._upd()
        self.after(30, self._tick)

    def _redraw(self):
        c = self.canvas
        c.delete("scene","veh_","ped_","cy_","bus_","tram_")

        # Scene (static)
        draw_scene(c, self.tl)

        # Walkers
        for w in self.walkers:
            if not w.done:
                c.delete(w.tag)
                if w.wtype == "cyclist":
                    draw_cyclist(c, w.wx, w.wy, w.color, tag=w.tag)
                else:
                    draw_pedestrian(c, w.wx, w.wy, w.color, tag=w.tag)

        # Vehicles sorted by depth (y+x for correct iso layering)
        for v in sorted(self.vehicles,
                        key=lambda x: x.wx + x.wy):
            v.draw(c)

    def on_close(self):
        self.running = False
        self.destroy()


if __name__ == "__main__":
    app = TrafficApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
