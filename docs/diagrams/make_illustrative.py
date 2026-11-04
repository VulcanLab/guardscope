#!/usr/bin/env python3
"""Generate illustrative summary figures for guardscope's empirical measurement.

Six variants: scene concepts A (one gate, many roads), B (spotlight),
C (two panes), each in two styles: flat (paper vector) and sketch
(hand-drawn look). Output: SVG files in this directory.

Run: python3 make_illustrative.py
"""

import math
import random

# ---------------------------------------------------------------- palette
# Ordnance Survey GeoDataViz qualitative colours
INK = "#22303C"
HARNESS = "#009ADE"
CONTROL = "#AF58BA"
WORKLOAD = "#F28522"
RECON = "#FFC61E"
KERNEL = "#A0B1BA"
KERNEL_D = "#5D6B76"
CHECKED = "#00CD6C"
BYPASS = "#FF1F5B"
PREVENT = "#009ADE"
TRUTH = "#5D6B76"

FAMS = ["in-process", "subprocess", "net egress", "tool-server", "delegation", "deferred"]
# outcome pattern per family row (3 columns)
GRID_ROWS = [
    (BYPASS, BYPASS, CHECKED),
    (BYPASS, BYPASS, CHECKED),
    (BYPASS, PREVENT, CHECKED),
    (CHECKED, CHECKED, CHECKED),
    (BYPASS, BYPASS, CHECKED),
    (BYPASS, PREVENT, CHECKED),
]

FLAT_FONT = "Helvetica, Arial, sans-serif"
SKETCH_FONT = "'Segoe Print','Comic Sans MS','Segoe Print','Comic Neue',cursive"


class Pen:
    """Accumulates SVG elements for one figure, in one style."""

    def __init__(self, style):
        self.style = style  # "flat" | "sketch"
        self.parts = []
        self.rnd = random.Random(11)
        self.sw_extra = 1.0 if style == "sketch" else 0.0
        self.font = SKETCH_FONT if style == "sketch" else FLAT_FONT
        self.defs = []

    # ------------------------------------------------------------ primitives
    def line_d(self, x0, y0, x1, y1, amp=2.8, seg=55):
        if self.style == "flat":
            return f"M {x0:.1f},{y0:.1f} L {x1:.1f},{y1:.1f}"
        d = math.hypot(x1 - x0, y1 - y0)
        n = max(2, int(d / seg))
        pts = [(x0 + (x1 - x0) * i / n, y0 + (y1 - y0) * i / n) for i in range(n + 1)]
        out = [pts[0]]
        for p in pts[1:-1]:
            out.append((p[0] + self.rnd.uniform(-amp, amp), p[1] + self.rnd.uniform(-amp, amp)))
        out.append(pts[-1])
        return "M " + " L ".join(f"{x:.1f},{y:.1f}" for x, y in out)

    def poly_d(self, pts, closed=True, amp=2.8):
        """Wobbly (or exact) path through a list of corner points."""
        out = []
        for i in range(len(pts) - (0 if closed else 1)):
            a = pts[i]
            b = pts[(i + 1) % len(pts)]
            d = self.line_d(a[0], a[1], b[0], b[1], amp=amp)
            if out:
                d = d[2:]  # drop repeated M
                out.append("L " + d.split("L ", 1)[1] if "L " in d else "")
            else:
                out.append(d)
        d = " ".join(x for x in out if x)
        if closed and self.style == "sketch":
            d += " Z"
        elif closed:
            d += " Z"
        return d

    def rect(self, x, y, w, h, fill="none", fo=0.0, stroke=INK, sw=2.5, rx=0):
        if self.style == "flat":
            r = f' rx="{rx}"' if rx else ""
            self.parts.append(
                f'<rect x="{x}" y="{y}" width="{w}" height="{h}"{r} fill="{fill}"'
                + (f' fill-opacity="{fo}"' if fo else "")
                + f' stroke="{stroke}" stroke-width="{sw}"/>')
        else:
            pts = [(x, y), (x + w, y), (x + w, y + h), (x, y + h)]
            self.parts.append(
                f'<path d="{self.poly_d(pts)}" fill="{fill}"'
                + (f' fill-opacity="{fo}"' if fo else "")
                + f' stroke="{stroke}" stroke-width="{sw + self.sw_extra}"'
                + ' stroke-linejoin="round" stroke-linecap="round"/>')

    def circle(self, cx, cy, r, fill="none", fo=0.0, stroke=INK, sw=2.5):
        if self.style == "flat":
            self.parts.append(
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{fill}"'
                + (f' fill-opacity="{fo}"' if fo else "")
                + f' stroke="{stroke}" stroke-width="{sw}"/>')
        else:
            n = 9
            pts = []
            for i in range(n):
                ang = 2 * math.pi * i / n
                rr = r + self.rnd.uniform(-r * 0.06, r * 0.06)
                pts.append((cx + rr * math.cos(ang), cy + rr * math.sin(ang)))
            self.parts.append(
                f'<path d="{self.poly_d(pts)}" fill="{fill}"'
                + (f' fill-opacity="{fo}"' if fo else "")
                + f' stroke="{stroke}" stroke-width="{sw + self.sw_extra}"'
                + ' stroke-linejoin="round"/>')

    def path(self, d, stroke=INK, sw=2.5, fill="none", dash=None, marker=None, fo=None):
        attrs = f' fill="{fill}"' + (f' fill-opacity="{fo}"' if fo else "")
        attrs += f' stroke="{stroke}" stroke-width="{sw + self.sw_extra}"'
        if dash:
            attrs += f' stroke-dasharray="{dash}"'
        attrs += ' stroke-linecap="round" stroke-linejoin="round"'
        if marker:
            attrs += f' marker-end="url(#{marker})"'
        self.parts.append(f'<path d="{d}"{attrs}/>')

    def text(self, x, y, s, size=13, anchor="middle", fill=INK, weight="400"):
        self.parts.append(
            f'<text x="{x}" y="{y}" text-anchor="{anchor}" font-family="{self.font}" '
            f'font-size="{size}" font-weight="{weight}" fill="{fill}">{s}</text>')

    # ------------------------------------------------------------ icons
    def robot(self, cx, cy, color=HARNESS, fo=0.16):
        w, h = 64, 44
        self.rect(cx - w / 2, cy - h / 2, w, h, fill=color, fo=fo, stroke=color, sw=2.5, rx=10)
        # antenna
        self.path(self.line_d(cx, cy - h / 2, cx, cy - h / 2 - 16), stroke=color, sw=2.5)
        self.circle(cx, cy - h / 2 - 20, 3.5, fill=color, fo=1.0, stroke=color, sw=1.5)
        # eyes
        self.circle(cx - 12, cy - 3, 4.5, fill=INK, fo=1.0, stroke=INK, sw=1)
        self.circle(cx + 12, cy - 3, 4.5, fill=INK, fo=1.0, stroke=INK, sw=1)
        # mouth
        self.path(self.line_d(cx - 8, cy + 9, cx + 8, cy + 9), stroke=INK, sw=2)

    def eye(self, cx, cy, w=100):
        """Kernel sensor eye looking up."""
        hw = w / 2
        vh = w * 0.26
        if self.style == "flat":
            d = (f"M {cx - hw},{cy} Q {cx},{cy - vh} {cx + hw},{cy} "
                 f"Q {cx},{cy + vh} {cx - hw},{cy} Z")
        else:
            j = lambda: self.rnd.uniform(-2.5, 2.5)
            d = (f"M {cx - hw},{cy + j()} Q {cx},{cy - vh + j()} {cx + hw},{cy + j()} "
                 f"Q {cx},{cy + vh + j()} {cx - hw},{cy + j()} Z")
        self.path(d, stroke=KERNEL_D, sw=2.5, fill="#ffffff", fo=1.0)
        self.circle(cx, cy, w * 0.22, fill=KERNEL, fo=1.0, stroke=KERNEL_D, sw=1.5)
        self.circle(cx, cy, w * 0.10, fill=INK, fo=1.0, stroke=INK, sw=1)
        self.circle(cx + w * 0.05, cy - w * 0.06, w * 0.035, fill="#ffffff", fo=1.0, stroke="#ffffff", sw=0.5)

    def gate(self, cx, top=406, post_top=424, post_h=84):
        """Toll-gate: beam across + two posts."""
        self.rect(cx - 52, top, 104, 26, fill=CONTROL, fo=0.16, stroke=CONTROL, sw=2.5, rx=4)
        self.rect(cx - 41, post_top, 14, post_h, fill=CONTROL, fo=0.30, stroke=CONTROL, sw=2.5, rx=3)
        self.rect(cx + 27, post_top, 14, post_h, fill=CONTROL, fo=0.30, stroke=CONTROL, sw=2.5, rx=3)

    def doc(self, x, y, w=34, h=44):
        """Workload document with folded corner."""
        if self.style == "flat":
            d = (f"M {x},{y} L {x + w - 10},{y} L {x + w},{y + 10} "
                 f"L {x + w},{y + h} L {x},{y + h} Z")
            fold = f"M {x + w - 10},{y} L {x + w - 10},{y + 10} L {x + w},{y + 10}"
        else:
            j = lambda: self.rnd.uniform(-1.8, 1.8)
            d = self.poly_d([(x + j(), y + j()), (x + w - 10, y + j()),
                             (x + w, y + 10), (x + w + j(), y + h + j()),
                             (x + j(), y + h)])
            fold = (f"M {x + w - 10},{y} L {x + w - 10},{y + 10} L {x + w},{y + 10}")
        self.path(d, stroke=WORKLOAD, sw=2.5, fill=WORKLOAD, fo=0.16)
        self.path(fold, stroke=WORKLOAD, sw=1.5)
        for i in range(3):
            yy = y + 18 + i * 8
            self.path(self.line_d(x + 6, yy, x + w - 6, yy), stroke=WORKLOAD, sw=1.5)

    def burst(self, cx, cy, r=9):
        for i in range(8):
            a = math.pi * i / 4
            x0, y0 = cx + (r - 3) * math.cos(a), cy + (r - 3) * math.sin(a)
            x1, y1 = cx + (r + 4) * math.cos(a), cy + (r + 4) * math.sin(a)
            self.path(self.line_d(x0, y0, x1, y1, amp=1), stroke=KERNEL_D, sw=1.75)

    def lamp(self, cx, cy):
        """Control spotlight lamp."""
        pts = [(cx - 20, cy - 20), (cx + 20, cy - 20), (cx + 12, cy + 18), (cx - 12, cy + 18)]
        self.path(self.poly_d(pts), stroke=CONTROL, sw=2.5, fill=CONTROL, fo=0.35)
        # bulb hint
        self.path(self.line_d(cx, cy + 18, cx, cy + 26), stroke=CONTROL, sw=2.5)

    # ------------------------------------------------------------ composite
    def gridbox(self, x, y, w=220, h=245):
        self.rect(x, y, w, h, stroke=KERNEL_D, sw=1.5, fill="#ffffff", fo=1.0, rx=8)
        self.text(x + w / 2, y + 26, "Coverage grid", 14, weight="700")
        cw, ch, gap = 62, 22, 6
        x0 = x + 11
        y0 = y + 38
        for r, row in enumerate(GRID_ROWS):
            for c, col in enumerate(row):
                self.parts.append(
                    f'<rect x="{x0 + c * (cw + gap)}" y="{y0 + r * (ch + gap)}" '
                    f'width="{cw}" height="{ch}" fill="{col}"/>')
        ly = y0 + 6 * (ch + gap) + 12
        chips = [(CHECKED, "checked"), (BYPASS, "bypassed"), (PREVENT, "prevented")]
        cx = x0
        for col, name in chips:
            self.parts.append(f'<rect x="{cx}" y="{ly}" width="10" height="10" fill="{col}"/>')
            self.text(cx + 14, ly + 9, name, 11.5, anchor="start")
            cx += 75

    def reconciler(self, x, y, w=220, h=56):
        self.rect(x, y, w, h, fill=RECON, fo=0.20, stroke=RECON, sw=2.5, rx=8)
        self.text(x + w / 2, y + 34, "Reconciler", 16.5, weight="700")

    def legend(self, x, y):
        self.path(self.line_d(x, y, x + 44, y), stroke=TRUTH, sw=2, dash="7,5")
        self.text(x + 52, y + 4, "self-reported records", 12.5, anchor="start")
        self.path(self.line_d(x + 240, y, x + 284, y), stroke=TRUTH, sw=2)
        self.text(x + 292, y + 4, "kernel-observed events", 12.5, anchor="start")

    def arrowhead_defs(self):
        colors = {"ah": INK, "ahB": HARNESS, "ahP": CONTROL, "ahK": TRUTH}
        for k, c in colors.items():
            self.defs.append(
                f'<marker id="{k}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" '
                f'markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="{c}"/></marker>')

    def render(self, w, h, name):
        defs = "<defs>\n" + "\n".join(self.defs) + "\n</defs>\n" if self.defs else ""
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
               f'viewBox="0 0 {w} {h}" font-family="{self.font}">\n'
               + defs
               + f'<rect x="0" y="0" width="{w}" height="{h}" fill="#ffffff"/>\n'
               + "\n".join(self.parts)
               + "\n</svg>\n")
        with open(name, "w") as f:
            f.write(svg)


# ================================================================ scene A
def scene_a(style):
    p = Pen(style)
    p.arrowhead_defs()
    W, H = 1100, 770

    # ground slab (kernel)
    p.rect(60, 524, 780, 176, fill=KERNEL, fo=0.18, stroke=KERNEL, sw=2.5, rx=10)
    p.text(450, 692, "Host kernel · eBPF sensor", 15, weight="700", fill=KERNEL_D)

    # claims (dashed), drawn under the roads
    # agent dispatch records: arc over the top, down the right corridor
    p.path("M462,148 C 640,55 835,60 848,185 C 842,260 850,380 864,474",
           stroke=HARNESS, sw=2, dash="7,5", marker="ahB")
    # control decision records: from the gate beam
    p.path("M567,420 C 680,430 780,480 852,505",
           stroke=CONTROL, sw=2, dash="7,5", marker="ahP")
    # kernel truth: from the eye, along the ground, up to the reconciler
    p.path("M478,622 C 640,695 790,690 852,512",
           stroke=TRUTH, sw=2.5, marker="ahK")

    # action roads: agent bottom -> kernel slab
    starts = [(403, 172), (415, 172), (429, 172), (441, 172), (453, 172), (465, 172)]
    landings = [(130, 516), (250, 516), (370, 516), (540, 516), (700, 516), (800, 516)]
    for (sx, sy), (lx, ly) in zip(starts, landings):
        p.path(p.line_d(sx, sy, lx, ly), stroke=INK, sw=2, marker="ah")

    # family labels, inside the slab under each landing
    for (lx, _), fam in zip(landings, FAMS):
        p.text(lx, 560, fam, 13)

    # gate on the tool-server road
    p.gate(515)
    p.text(515, 396, "Runtime control", 14.5, weight="700")

    # workload -> agent
    p.doc(60, 105)
    p.text(77, 180, "fixed workload", 13.5)
    p.path(p.line_d(98, 127, 390, 147), stroke=INK, sw=2, marker="ah")

    # agent
    p.robot(430, 150)
    p.text(430, 92, "Agent harness", 16.5, weight="700")

    # kernel eye
    p.eye(450, 612)

    # strip
    p.gridbox(860, 200)
    p.reconciler(860, 480)
    p.path(p.line_d(970, 472, 970, 453), stroke=INK, sw=2, marker="ah")

    p.legend(60, 744)
    p.render(W, H, f"illustrative-a-{style}.svg")


# ================================================================ scene B
def scene_b(style):
    p = Pen(style)
    p.arrowhead_defs()
    W, H = 1120, 790

    # kernel floor
    p.rect(60, 560, 780, 170, fill=KERNEL, fo=0.18, stroke=KERNEL, sw=2.5, rx=10)
    p.text(400, 722, "Host kernel · eBPF sensor", 15, weight="700", fill=KERNEL_D)

    # action dots: (x, y)
    dots = {
        "in-process": (420, 330),
        "subprocess": (450, 470),
        "net egress": (540, 250),
        "tool-server": (680, 360),
        "delegation": (640, 520),
        "deferred": (790, 470),
    }
    lit = "tool-server"

    # streams from agent to each dot (thin)
    for fam, (dx, dy) in dots.items():
        p.path(p.line_d(232, 212, dx - 34, dy), stroke=KERNEL_D, sw=1.75)

    # effect rays: each dot down to the kernel floor
    for fam, (dx, dy) in dots.items():
        p.path(p.line_d(dx, dy + 34, dx, 552), stroke=KERNEL_D, sw=1.75, marker="ah")
        p.burst(dx, 572)

    # spotlight cone (under the dots' outlines, over the floor fill)
    cone = [(808, 188), (832, 188), (690, 430), (570, 270)]
    if style == "flat":
        d = "M " + " L ".join(f"{x},{y}" for x, y in cone) + " Z"
    else:
        d = p.poly_d(cone)
    p.parts.append(f'<path d="{d}" fill="{RECON}" fill-opacity="0.22" stroke="none"/>')

    # lamp (control) above the cone
    p.lamp(820, 170)
    p.text(820, 124, "Runtime control", 14.5, weight="700")

    # dots
    for fam, (dx, dy) in dots.items():
        if fam == lit:
            p.circle(dx, dy, 42, fill=RECON, fo=0.28, stroke=RECON, sw=0)  # glow
            p.circle(dx, dy, 30, fill="#ffffff", fo=1.0, stroke=INK, sw=2.5)
        else:
            p.circle(dx, dy, 30, fill=KERNEL, fo=0.30, stroke=KERNEL_D, sw=2.5)
        p.text(dx, dy + 52, fam, 13)

    # workload -> agent
    p.doc(70, 250)
    p.text(87, 316, "fixed workload", 13.5)
    p.path(p.line_d(106, 272, 162, 242), stroke=INK, sw=2, marker="ah")

    # agent
    p.robot(200, 210)
    p.text(200, 168, "Agent harness", 16.5, weight="700")

    # kernel eye
    p.eye(400, 650)

    # strip
    p.gridbox(880, 470)
    p.reconciler(880, 340)

    # claims (dashed)
    # agent: arc over the dots, down the corridor between scene and strip
    p.path("M210,166 C 430,60 830,75 856,200 C 860,250 868,320 874,358",
           stroke=HARNESS, sw=2, dash="7,5", marker="ahB")
    # control lamp: arc over the top right, down into the reconciler
    p.path("M824,144 C 880,95 940,120 954,210 C 956,255 957,300 957,336",
           stroke=CONTROL, sw=2, dash="7,5", marker="ahP")
    # kernel truth: from the eye, along the floor, up to the reconciler
    p.path("M448,655 C 640,745 800,740 852,620 C 866,560 872,500 879,400",
           stroke=TRUTH, sw=2.5, marker="ahK")

    p.path(p.line_d(990, 400, 990, 466), stroke=INK, sw=2, marker="ah")
    p.legend(60, 764)
    p.render(W, H, f"illustrative-b-{style}.svg")


# ================================================================ scene C
def scene_c(style):
    p = Pen(style)
    p.arrowhead_defs()
    W, H = 1150, 780

    xs = [230, 320, 410, 500, 590, 660]

    # ---- top pane: what the control claims
    p.rect(80, 100, 680, 250, fill=CONTROL, fo=0.05, stroke=CONTROL, sw=2.5, rx=12)
    p.text(420, 132, "Control's view", 15, weight="700", fill=CONTROL)
    p.robot(150, 180, fo=0.10)
    p.text(150, 150, "Agent harness", 12.5, weight="700")
    # faint dotted rays for every family
    for lx in xs:
        p.path(p.line_d(182, 180, lx, 344), stroke=KERNEL_D, sw=1.5, dash="2,6", fo=None)
    # the one road the control sees: solid purple through a mini gate
    p.path(p.line_d(182, 180, 500, 342), stroke=CONTROL, sw=3, marker="ahP")
    p.rect(419, 308, 114, 16, fill=CONTROL, fo=0.16, stroke=CONTROL, sw=2, rx=3)
    p.rect(424, 324, 10, 24, fill=CONTROL, fo=0.30, stroke=CONTROL, sw=2, rx=2)
    p.rect(518, 324, 10, 24, fill=CONTROL, fo=0.30, stroke=CONTROL, sw=2, rx=2)

    # ---- bottom pane: what the kernel observes
    p.rect(80, 420, 680, 250, fill=KERNEL, fo=0.08, stroke=KERNEL_D, sw=2.5, rx=12)
    p.text(420, 452, "Kernel's view", 15, weight="700", fill=KERNEL_D)
    p.robot(150, 500, fo=0.10)
    p.text(150, 470, "Agent harness", 12.5, weight="700")
    p.eye(150, 560, w=0.01) if False else None  # no eye here; rays speak
    for lx in xs:
        p.path(p.line_d(182, 500, lx, 662), stroke=KERNEL_D, sw=2, marker="ah")
        p.burst(lx, 664)
    for lx, fam in zip(xs, FAMS):
        p.text(lx, 696, fam, 13)

    # ---- strip
    p.gridbox(800, 470)
    p.reconciler(800, 340)
    # claims from the top pane (dashed)
    p.path("M766,240 C 780,270 788,310 794,352", stroke=CONTROL, sw=2, dash="7,5", marker="ahP")
    # truth from the bottom pane (solid)
    p.path("M766,558 C 782,530 794,460 802,402", stroke=TRUTH, sw=2.5, marker="ahK")
    p.path(p.line_d(910, 400, 910, 466), stroke=INK, sw=2, marker="ah")

    p.legend(80, 754)
    p.render(W, H, f"illustrative-c-{style}.svg")


if __name__ == "__main__":
    for style in ("flat", "sketch"):
        scene_a(style)
        scene_b(style)
        scene_c(style)
    print("wrote 6 svg files")
