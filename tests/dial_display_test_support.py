"""Helpers shared by the display's test files: fake backends, display builders and
frame comparisons that more than one of them use.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dial_network import NetworkView
from dial_test_support import (
    FakeBackend,
    _status_result,
    _track_id,
    make_display,
)


def _view(link, bars=0):
    return NetworkView(link=link, device_state="", bars=bars, updated_at=1.0)


def _fold(display):
    with display._lock:
        display._repaint_current_locked()


def _marked_image(size: tuple[int, int] = (4, 4)) -> "Image.Image":
    """A small asymmetric image so a 180° rotation is detectable pixel-wise."""
    image = Image.new("RGB", size, (0, 0, 0))
    image.putpixel((0, 0), (255, 0, 0))
    return image


def _poll_with_artwork(display, fb):
    """Drive one poll iteration that lands on identified artwork, faking out
    the network/decode/transform steps exactly like TestRotation does."""
    fake_image = _marked_image(size=(fb.width, fb.height))
    with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
         patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
         patch("dial_display.decode_artwork", return_value=fake_image), \
         patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
        display.fold_for_tests()


_REPLAY_AID = "a" * 20


_HINT_TIERS = [
    pytest.param(320, 240, 0.1778, id="rich_320x240"),
    pytest.param(128, 128, 25.9 / 128, id="compact_128x128"),
    pytest.param(160, 128, None, id="compact_160x128"),
    pytest.param(240, 240, 23.4 / 240, id="compact_240x240"),
]


def _poll_focused_with_repeat(display, fb, aid, repeat_obj):
    """Drive one poll that identifies artwork for appliance_id=aid and
    feeds repeat_obj into the store for it — leaves _now_playing and
    _reporting_appliance_id set to aid, mirroring toggle_repeat_screen()'s
    own precondition for opening."""
    fake_image = Image.new("RGB", (fb.width, fb.height))
    result = _status_result(track_id=_track_id(), appliance_id=aid)
    result["repeat"] = repeat_obj
    with patch("dial_test_support.fetch_target_status", return_value=result), \
         patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
         patch("dial_display.decode_artwork", return_value=fake_image), \
         patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
        display.fold_for_tests()


def _make_compact_display(targets=None, **overrides):
    fb = FakeBackend()
    fb.width, fb.height = 240, 240
    overrides.setdefault("screen_type", "st7789_240x240")
    overrides.setdefault("backend", fb)
    display, fb, gt = make_display(targets=targets or [], **overrides)
    return display, fb, gt
