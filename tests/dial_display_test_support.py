"""Helpers shared by the display's test files: fake backends, display builders and
frame comparisons that more than one of them use.
"""
from __future__ import annotations

import sys
import time
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

from dial_network import LINK_CONNECTED, NetworkView
from dial_test_support import (
    FakeBackend,
    _repeat_obj,
    _status_result,
    _target,
    _track_id,
    make_display,
    on_network_view,
    seed_repeat,
    set_roster,
)


def _view(link, bars=0):
    return NetworkView(link=link, bars=bars, updated_at=1.0)


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
    the network/decode/transform steps exactly like test_dial_display_panel.TestRotation does."""
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


def open_repeat_screen(state="idle", armed=False, appliance_id="5" * 20):
    """A display on the repeat screen of one repeat-capable appliance whose
    record is in *state*; returns (display, appliance_id)."""
    t = _target(name="Kitchen", service_name="Kitchen", appliance_id=appliance_id)
    display, fb, gt = make_display(targets=[t], repeat_capable=True)
    display.enable()
    _poll_focused_with_repeat(display, fb, appliance_id, _repeat_obj(state=state, armed=armed))
    display.cycle_pages()
    with display._lock:
        display._repaint_current_locked()
    assert display._screen == "repeat"
    return display, appliance_id


def selector_display(authorized_count=1):
    """A display that has polled *authorized_count* authorised appliances, one
    that refused this dial and one that has not said yet."""
    targets = [
        _target(name=f"T{i}", service_name=f"T{i}", appliance_id=str(i) * 20,
                auth="authorized", playing_since=float(i))
        for i in range(authorized_count)
    ]
    targets.append(_target(
        name="Lounge", service_name="Lounge", appliance_id="9" * 20, ip="192.168.1.99",
        auth="unauthorized", playing_since=50.0,
    ))
    targets.append(_target(
        name="Maybe", service_name="Maybe", appliance_id="8" * 20, ip="192.168.1.98", auth="unknown",
    ))
    display, fb, gt = make_display(targets=targets)
    display.enable()

    def reply(target, *args, **kwargs):
        # Maybe has not said yet whether this dial may use it.
        if target.appliance_id == "8" * 20:
            return dict(_status_result(track_id=None), access="unknown")
        return _status_result(track_id=None)
    with patch("dial_test_support.fetch_target_status", side_effect=reply):
        display.fold_for_tests()
    return display


def _refresh_selector(display, roster):
    """Give the core *roster* and let the view rebuild the selector's rows
    from the snapshot that carries it."""
    set_roster(display, roster)
    display._refresh_list_rows(display.core.snapshot())


def _refresh_picker(display, roster, now):
    """Give the core *roster*, each appliance reporting the repeat record
    seeded for it, then let the view rebuild the picker's rows from the
    snapshot."""
    set_roster(display, roster)
    display._refresh_list_rows(display.core.snapshot())


def picker_with_row(aid="a" * 20):
    """A display on the replay picker holding one repeat-capable appliance
    with a recording; returns (display, fb, gt)."""
    from dial_test_support import RosterEntry
    display, fb, gt = make_display(targets=[])
    display.enable()
    row = RosterEntry(
        appliance_id=aid, service_name="Kitchen", name="Kitchen", ip="10.0.0.9", port=8080,
        playing=False, repeat_capable=True, auth="authorized",
    )
    now = time.monotonic()
    seed_repeat(aid, _repeat_obj(state="hold", recording_seconds=12.0))
    _refresh_picker(display, [row], now)
    set_roster(display, [row])
    display.core.set_field_for_tests("idle_affordance", True)
    display.open_picker()
    with display._lock:
        display._repaint_current_locked()
    assert display._screen == "picker"
    return display, fb, gt


def idle_display(connected=True):
    """A display on the idle screen, with a link that was up since boot and is
    now lost unless *connected* is False; returns (display, fb)."""
    display, fb, gt = make_display(targets=[])
    display.enable()
    display.fold_for_tests()          # nothing playing: idle screen, _now_playing None
    _fold(display)
    if connected:
        # The common case for the incident tests: a link that was up since
        # boot and is now lost.
        on_network_view(display, _view(LINK_CONNECTED, bars=3))
    return display, fb
