"""Shared helpers and the compositor fixture for the display compositor tests."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")
ImageChops = pytest.importorskip("PIL.ImageChops", reason="Pillow not installed")

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dial_display_views import RepeatViewState  # noqa: E402
from dial_display_compositor import DialDisplayCompositor  # noqa: E402
from dial_layout_metrics import metrics_for  # noqa: E402

# The profile sizes from dial_display_profiles.DISPLAY_PROFILES, and their
# confirmed mm_per_px (see the profiles module's design notes) — mirrors
# test_dial_touch_layout.py's own PROFILE_SIZES/confirmed-density pairing.
PROFILE_SIZES = [
    (160, 128),  # st7735s_160x128
    (128, 128),  # st7735s_128x128
    (240, 240),  # st7789_240x240
    (320, 240),  # st7789_320x240, ili9341_320x240 (same size)
]

# A confirmed rich panel (the shipped 320x240 density) and a confirmed large
# one (640x480), used by the rail-specific render/pressed-wash tests below.
_RICH_METRICS = metrics_for(320, 240, 0.1778)
_LARGE_METRICS = metrics_for(640, 480, 0.127)

# The two shipped compact panels — 1.3in 240x240 and 1.44in 128x128.
_COMPACT_240 = metrics_for(240, 240, 0.0973)
_COMPACT_128 = metrics_for(128, 128, 0.2021)


def _marked_image(size=(4, 4)):
    """A small asymmetric image so a 180 degree rotation is detectable."""
    image = Image.new("RGB", size, (0, 0, 0))
    image.putpixel((0, 0), (255, 0, 0))
    return image


def _diff_bbox(a: Image.Image, b: Image.Image):
    """Bounding box (left, upper, right, lower) of every pixel where *a* and
    *b* differ, or None when they are identical — a compact way to assert
    both "this drew something" and "it stayed inside its rect"."""
    from PIL import ImageChops

    return ImageChops.difference(a, b).getbbox()


@pytest.fixture
def compositor():
    return DialDisplayCompositor()


# ---------------------------------------------------------------------------
# compose_repeat — the repeat screen: enable layout ("Repeat Play" row,
# armed) and the replaying layout (Restart/Stop, position line over the
# current artwork/logo base image). Both layouts share the main screen's
# top band (dots, name, mute/volume readout).
# ---------------------------------------------------------------------------

def _repeat_state(**overrides) -> RepeatViewState:
    base = dict(
        name="Kitchen", layout="enable", armed=False, line="",
        start_enabled=False, stop_enabled=False, stop_pressed=False,
        volume=None, pressed=None,
    )
    base.update(overrides)
    return RepeatViewState(**base)


def _has_near_white_pixel(region) -> bool:
    """True if *region* contains a pixel close to the glyph colour
    (255, 255, 255) — a cheap proxy for "a glyph stroke was drawn here"."""
    return any(min(px) > 200 for px in region.getdata())
