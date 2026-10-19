"""Generated album covers for the showcase shots: abstract compositions drawn
with Pillow alone, one style per genre, the same on every run.

Each cover is 600x600. Shapes are drawn at twice the size and scaled down so
edges are smooth. Text is set in DejaVu, the face the dial's own renderer
uses. A style takes its random choices from a generator seeded with the
track's seed, so changing the seed changes that cover and nothing else.
"""
from __future__ import annotations

import io
import math
import random
import sys
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont

SIZE = 600
SCALE = 2
BIG = SIZE * SCALE

_FONT_DIRS = (
    "/usr/share/fonts/truetype/dejavu",
    "/usr/share/fonts/dejavu",
    "/usr/share/fonts/TTF",
    "C:/Windows/Fonts",
)
_FONT_FILES = {
    "sans": "DejaVuSans.ttf",
    "sans-bold": "DejaVuSans-Bold.ttf",
    "serif": "DejaVuSerif.ttf",
    "serif-bold": "DejaVuSerif-Bold.ttf",
    "mono": "DejaVuSansMono.ttf",
}


def font(kind: str, size: int):
    """A DejaVu face at *size* (in final, 600 px units)."""
    name = _FONT_FILES[kind]
    for folder in _FONT_DIRS:
        path = Path(folder) / name
        if path.exists():
            return ImageFont.truetype(str(path), int(size * SCALE))
    raise FileNotFoundError(f"{name} not found; install the DejaVu fonts")


def _mix(a, b, t):
    return tuple(int(round(a[i] + (b[i] - a[i]) * t)) for i in range(3))


def gradient(size, top, bottom, horizontal=False):
    """A linear two-colour gradient."""
    w, h = size
    strip = Image.new("RGB", (256, 1) if horizontal else (1, 256))
    for i in range(256):
        strip.putpixel((i, 0) if horizontal else (0, i), _mix(top, bottom, i / 255))
    return strip.resize((w, h), Image.BILINEAR)


def grain(img, rng, amount):
    """Film grain, the same on every run: seeded noise laid over the image."""
    w, h = img.size
    noise = Image.frombytes("L", (w, h), rng.randbytes(w * h))
    noise = Image.merge("RGB", (noise, noise, noise))
    return Image.blend(img, ImageChops.overlay(img, noise), min(1.0, amount / 100.0))


def _text_width(draw, text, f):
    box = draw.textbbox((0, 0), text, font=f)
    return box[2] - box[0]


def wrap(draw, text, f, max_w):
    lines, line = [], ""
    for word in text.split():
        trial = (line + " " + word).strip()
        if _text_width(draw, trial, f) <= max_w or not line:
            line = trial
        else:
            lines.append(line)
            line = word
    if line:
        lines.append(line)
    return lines


def fit_lines(draw, text, kind, max_size, min_size, max_w, max_lines):
    """The largest font (and its wrapped lines) at which *text* fits."""
    for size in range(max_size, min_size - 1, -2):
        f = font(kind, size)
        lines = wrap(draw, text, f, max_w * SCALE)
        if len(lines) <= max_lines and all(_text_width(draw, ln, f) <= max_w * SCALE for ln in lines):
            return f, lines
    f = font(kind, min_size)
    return f, wrap(draw, text, f, max_w * SCALE)[:max_lines]


def draw_block(draw, lines, f, x, y, fill, align="left", leading=1.12):
    """Draw *lines* from (x, y) in final units; returns the y after the block."""
    for line in lines:
        w = _text_width(draw, line, f) / SCALE
        px = x - w / 2 if align == "center" else x - w if align == "right" else x
        draw.text((px * SCALE, y * SCALE), line, font=f, fill=fill)
        y += f.size / SCALE * leading
    return y


def _finish(img, rng, grain_amount=0):
    out = img.resize((SIZE, SIZE), Image.LANCZOS)
    return grain(out, rng, grain_amount) if grain_amount else out


# --------------------------------------------------------------------------
# Styles. Each takes (track, rng) and returns a 600x600 RGB image.
# --------------------------------------------------------------------------

def style_blocks(track, rng):
    """Jazz: flat colour blocks, a big circle and heavy sans lettering."""
    ground = (233, 226, 208)
    img = Image.new("RGB", (BIG, BIG), ground)
    d = ImageDraw.Draw(img)
    teal, orange, ink = (24, 94, 104), (226, 112, 38), (24, 28, 36)
    d.rectangle((0, 0, BIG * 0.62, BIG), fill=teal)
    d.rectangle((BIG * 0.62, BIG * 0.38, BIG, BIG), fill=orange)
    d.ellipse((BIG * 0.34, BIG * 0.34, BIG * 0.90, BIG * 0.90), fill=ground)
    d.ellipse((BIG * 0.44, BIG * 0.44, BIG * 0.80, BIG * 0.80), fill=ink)
    for i in range(5):
        y = BIG * (0.46 + i * 0.075)
        d.rectangle((BIG * 0.80, y, BIG * 0.96, y + 5 * SCALE), fill=(244, 160, 90))
    f, lines = fit_lines(d, track.album.upper(), "sans-bold", 46, 26, 190, 3)
    y = draw_block(d, lines, f, 36, 175, ground, leading=1.08)
    fa, al = fit_lines(d, track.artist, "sans", 24, 14, 165, 3)
    draw_block(d, al, fa, 36, y + 10, ground)
    return _finish(img, rng, 10)


def _sprig(draw, base, angle, length, rng, leaf, stem):
    x, y = base
    ex, ey = x + math.cos(angle) * length, y + math.sin(angle) * length
    draw.line((x, y, ex, ey), fill=stem, width=5 * SCALE)
    for i in range(1, 10):
        t = i / 10
        px, py = x + (ex - x) * t, y + (ey - y) * t
        for side in (-1, 1):
            a = angle + side * (0.9 + rng.random() * 0.25)
            ll = (length / 7) * (1.2 - t * 0.6)
            qx, qy = px + math.cos(a) * ll, py + math.sin(a) * ll
            nx, ny = -math.sin(a), math.cos(a)
            w = ll * 0.28
            draw.polygon([(px, py), ((px + qx) / 2 + nx * w, (py + qy) / 2 + ny * w), (qx, qy),
                          ((px + qx) / 2 - nx * w, (py + qy) / 2 - ny * w)], fill=leaf)
    r = 14 * SCALE
    draw.ellipse((ex - r, ey - r, ex + r, ey + r), fill=(232, 178, 52))


def style_botanical(track, rng):
    """Folk: warm paper, grain and a spray of sprigs."""
    img = Image.new("RGB", (BIG, BIG), (236, 224, 198))
    d = ImageDraw.Draw(img, "RGBA")
    d.rectangle((24 * SCALE, 24 * SCALE, BIG - 24 * SCALE, BIG - 24 * SCALE),
                outline=(96, 74, 52), width=3 * SCALE)
    leaves = [(76, 104, 70), (104, 128, 84), (140, 150, 92), (66, 88, 78)]
    base = (BIG * 0.5, BIG * 0.90)
    for i in range(7):
        angle = -math.pi / 2 + (i - 3) * 0.26 + rng.uniform(-0.05, 0.05)
        _sprig(d, base, angle, BIG * rng.uniform(0.30, 0.36), rng, leaves[i % len(leaves)], (84, 70, 50))
    d.ellipse((BIG * 0.5 - 70 * SCALE, BIG * 0.89, BIG * 0.5 + 70 * SCALE, BIG * 0.89 + 26 * SCALE),
              fill=(120, 88, 58, 200))
    f, lines = fit_lines(d, track.album, "serif-bold", 50, 30, 440, 2)
    draw_block(d, [track.artist.upper()], font("serif", 22), 300, 172, (96, 74, 52), align="center")
    draw_block(d, lines, f, 300, 206, (70, 52, 38), align="center", leading=1.05)
    return _finish(img, rng, 16)


def style_sunburst(track, rng):
    """1970s rock: a banded setting sun over a dark horizon, chunky lettering."""
    img = gradient((BIG, BIG), (48, 22, 52), (214, 84, 56))
    d = ImageDraw.Draw(img)
    cx, cy, r = BIG * 0.5, BIG * 0.76, BIG * 0.24
    for i in range(14):
        rr = r * (1 - i * 0.06)
        d.ellipse((cx - rr, cy - rr, cx + rr, cy + rr), fill=_mix((250, 214, 96), (236, 96, 60), i / 14))
    d.rectangle((0, cy, BIG, BIG), fill=(30, 16, 36))
    for i in range(9):
        y = cy + i * (BIG * 0.045) + 6
        d.rectangle((0, y, BIG, y + (4 + i * 2.2) * SCALE), fill=(44, 22, 50))
    d.rectangle((0, cy - 2, BIG, cy + 2), fill=(250, 214, 96))
    for i in range(5):
        y = cy + 18 + i * 24
        d.rectangle((BIG * 0.12, y, BIG * 0.88, y + 6 * SCALE), fill=_mix((250, 140, 60), (150, 40, 80), i / 5))
    f, lines = fit_lines(d, track.artist.upper(), "sans-bold", 54, 30, 500, 2)
    y = draw_block(d, lines, f, 300, 175, (252, 232, 190), align="center", leading=1.0)
    draw_block(d, [track.album.upper()], font("sans-bold", 22), 300, y + 6, (250, 190, 120), align="center")
    return _finish(img, rng, 14)


def style_engraved(track, rng):
    """Classical: deep navy, a thin gilt frame and quiet centred serif text."""
    img = gradient((BIG, BIG), (14, 24, 48), (24, 40, 74))
    d = ImageDraw.Draw(img, "RGBA")
    gold = (200, 168, 96)
    for inset, w in ((30, 2), (42, 1)):
        d.rectangle((inset * SCALE, inset * SCALE, BIG - inset * SCALE, BIG - inset * SCALE),
                    outline=gold, width=w * SCALE)
    cx, cy = BIG * 0.5, BIG * 0.74
    for i in range(24):
        rr = (30 + i * 8) * SCALE
        d.ellipse((cx - rr, cy - rr, cx + rr, cy + rr), outline=gold + (max(150 - i * 5, 30),), width=SCALE)
    for i in range(5):
        y = BIG * 0.74 + (i - 2) * 11 * SCALE
        d.line((BIG * 0.14, y, BIG * 0.86, y), fill=gold + (160,), width=SCALE)
    f, lines = fit_lines(d, track.artist, "serif-bold", 38, 24, 440, 2)
    y = draw_block(d, lines, f, 300, 175, (236, 226, 200), align="center")
    fa, al = fit_lines(d, track.album, "serif", 30, 18, 440, 2)
    draw_block(d, al, fa, 300, y + 8, gold, align="center")
    return _finish(img, rng, 8)


def style_halftone(track, rng):
    """Soul: saturated ground, a halftone-dot sun and bold type."""
    img = Image.new("RGB", (BIG, BIG), (200, 48, 44))
    d = ImageDraw.Draw(img)
    cx, cy, big_r = BIG * 0.5, BIG * 0.80, BIG * 0.22
    step = 18 * SCALE
    cream = (250, 226, 170)
    for gy in range(0, BIG + step, step):
        for gx in range(0, BIG + step, step):
            px, py = gx + (step / 2 if (gy // step) % 2 else 0), gy
            t = max(0.0, 1 - math.hypot(px - cx, py - cy) / (big_r * 1.5))
            rad = step * 0.5 * t
            if rad > 1.2:
                d.ellipse((px - rad, py - rad, px + rad, py + rad), fill=cream)
    d.ellipse((cx - big_r * 0.5, cy - big_r * 0.5, cx + big_r * 0.5, cy + big_r * 0.5), fill=(34, 20, 28))
    f, lines = fit_lines(d, track.artist.upper(), "sans-bold", 40, 22, 500, 2)
    y = draw_block(d, lines, f, 300, 175, cream, align="center", leading=1.02)
    fa, al = fit_lines(d, track.album, "sans", 24, 16, 500, 1)
    draw_block(d, al, fa, 300, y + 8, (250, 170, 120), align="center")
    return _finish(img, rng, 14)


def style_grid(track, rng):
    """Electronic: a dark perspective grid under a neon gradient band."""
    img = gradient((BIG, BIG), (10, 8, 30), (36, 12, 64))
    horizon = int(BIG * 0.62)
    band = gradient((BIG, 46 * SCALE), (255, 80, 160), (80, 220, 255), horizontal=True)
    img.paste(band, (0, horizon - 23 * SCALE))
    d = ImageDraw.Draw(img, "RGBA")
    d.rectangle((0, horizon + 23 * SCALE, BIG, BIG), fill=(8, 6, 24))
    line = (90, 200, 255, 150)
    top = horizon + 23 * SCALE
    for i in range(-14, 15):
        d.line((BIG * 0.5 + i * BIG * 0.018, top, BIG * 0.5 + i * BIG * 0.16, BIG), fill=line, width=SCALE)
    y, gap = top, 8 * SCALE
    while y < BIG:
        d.line((0, y, BIG, y), fill=line, width=SCALE)
        gap *= 1.35
        y += gap
    for _ in range(40):
        x, yy = rng.uniform(0, BIG), rng.uniform(0, 150 * SCALE)
        rr = rng.choice((1, 1, 2, 3)) * SCALE
        d.ellipse((x - rr, yy - rr, x + rr, yy + rr), fill=(220, 230, 255, 200))
    f, lines = fit_lines(d, track.artist.upper(), "mono", 40, 22, 500, 2)
    y = draw_block(d, lines, f, 40, 175, (232, 240, 255), leading=1.1)
    draw_block(d, [track.album.lower()], font("mono", 22), 40, y + 6, (130, 220, 255))
    return _finish(img, rng, 10)


def style_haze(track, rng):
    """Ambient: soft out-of-focus discs on a pale gradient, small quiet type."""
    out = gradient((BIG, BIG), (214, 224, 226), (150, 176, 190))
    colours = [(250, 222, 190), (178, 206, 214), (244, 196, 170), (120, 156, 176), (255, 244, 224)]
    for i in range(9):
        cx, cy = rng.uniform(0.1, 0.9) * BIG, rng.uniform(0.15, 0.85) * BIG
        rr = rng.uniform(0.10, 0.26) * BIG
        m = Image.new("L", (BIG, BIG), 0)
        ImageDraw.Draw(m).ellipse((cx - rr, cy - rr, cx + rr, cy + rr), fill=int(rng.uniform(110, 190)))
        m = m.filter(ImageFilter.GaussianBlur(26 * SCALE))
        out = Image.composite(Image.new("RGB", (BIG, BIG), colours[i % len(colours)]), out, m)
    d = ImageDraw.Draw(out)
    draw_block(d, [track.artist.lower()], font("sans", 22), 40, 172, (40, 56, 66))
    fa, lines = fit_lines(d, track.album.lower(), "sans", 44, 26, 420, 2)
    draw_block(d, lines, fa, 40, 204, (34, 50, 60), leading=1.1)
    return _finish(out, rng, 12)


STYLES = {
    "blocks": style_blocks,
    "botanical": style_botanical,
    "sunburst": style_sunburst,
    "engraved": style_engraved,
    "halftone": style_halftone,
    "grid": style_grid,
    "haze": style_haze,
}


def render_cover(track) -> Image.Image:
    """The 600x600 cover for *track*."""
    return STYLES[track.style](track, random.Random(track.seed))


def cover_png(track) -> bytes:
    """The cover as PNG bytes, the same on every run."""
    buf = io.BytesIO()
    render_cover(track).save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def main(argv=None) -> int:
    """Write every cover to a folder: python covers.py [OUT_DIR]"""
    from music import TRACKS
    args = sys.argv[1:] if argv is None else argv
    out = Path(args[0] if args else "covers")
    out.mkdir(parents=True, exist_ok=True)
    for track in TRACKS:
        path = out / f"cover-{track.key}.png"
        path.write_bytes(cover_png(track))
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
