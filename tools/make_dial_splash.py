#!/usr/bin/env python3
"""Generate the boot and shutdown splash images for the dial's Plymouth theme.

A development tool, not installed on a dial. The committed images are the
output of one run; replacing the artwork later is a re-run (optionally with
--logo), not new code.

    python3 tools/make_dial_splash.py [--out DIR] [--logo PATH]

Needs Pillow and DejaVuSans-Bold.ttf (the fonts-dejavu-core package).

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

CANVAS = (1920, 1080)
BACKGROUND = "#0e2841"
TEXT_COLOUR = "#dce8f2"
FONT_SIZE = 96
FONT_PATHS = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "DejaVuSans-Bold.ttf",
)
LOGO_GAP = 48

# Output file name -> the words it carries.
IMAGES = {
    "starting.png": "Starting...",
    "shutting-down.png": "Shutting down...",
}

DEFAULT_OUT = Path(__file__).resolve().parents[1] / "system" / "plymouth" / "autostream-dial"


def _font() -> ImageFont.FreeTypeFont:
    for path in FONT_PATHS:
        try:
            return ImageFont.truetype(path, FONT_SIZE)
        except OSError:
            continue
    raise SystemExit("DejaVuSans-Bold.ttf not found (install fonts-dejavu-core)")


def render(text: str, logo: Path | None = None) -> Image.Image:
    """One splash image: the text centred on the background, with the logo
    centred above it when one is given."""
    image = Image.new("RGB", CANVAS, BACKGROUND)
    draw = ImageDraw.Draw(image)
    left, top, right, bottom = draw.textbbox((0, 0), text, font=_font())
    text_w, text_h = right - left, bottom - top
    block_h = text_h
    mark = None
    if logo is not None:
        mark = Image.open(logo).convert("RGBA")
        block_h += mark.height + LOGO_GAP
    y = (CANVAS[1] - block_h) // 2
    if mark is not None:
        image.paste(mark, ((CANVAS[0] - mark.width) // 2, y), mark)
        y += mark.height + LOGO_GAP
    draw.text(((CANVAS[0] - text_w) // 2 - left, y - top), text,
              font=_font(), fill=TEXT_COLOUR)
    return image


def generate(out: Path, logo: Path | None = None) -> list[Path]:
    """Write every image in IMAGES into OUT as an 8-bit palette PNG."""
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for name, text in IMAGES.items():
        path = out / name
        render(text, logo).quantize(colors=16).save(path, optimize=True)
        written.append(path)
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help="directory to write the images into (default: the theme directory)")
    parser.add_argument("--logo", type=Path, default=None,
                        help="optional logo image drawn above the text")
    args = parser.parse_args()
    for path in generate(args.out, args.logo):
        print(path)


if __name__ == "__main__":
    main()
