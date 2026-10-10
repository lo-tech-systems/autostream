"""Tests for dial_display.py — display manager selection, fallback, and safety.

Covers: disabled config, no targets, unauthorized target suppression,
unsupported target, missing/omitted track_id treated as no artwork, provider
URL fetch eligibility (scheme, IP literal, .local, non-default port, unsafe
redirects), oversized response, decode failure fallback, oldest-playing
target stickiness, use of the single-target status helper (not
enrich_targets), later-target skip after first usable artwork, loop delay
measured from loop end, image dedupe, logo fallback, backend failure
degradation, and shutdown.
"""
from __future__ import annotations

import dataclasses
import functools
import io
import json
import math
import sys
import threading
import time
import urllib.error
from pathlib import Path
from unittest.mock import ANY, MagicMock, call, patch

import pytest

Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import logging

from dial_config import DialDisplayConfig
from dial_display_compositor import DEFAULT_MARK, OverlayState, WIFI_GREY, WIFI_OFF, WIFI_RED, WIFI_SIGNAL, _LIST_BG_RGB
from dial_display_profiles import (
    DEFAULT_PROFILE_KEY,
    effective_diagonal_inches,
    get_profile,
    layout_context_for,
    mm_per_px_for,
    mm_per_px_for_size,
)
from dial_network import LINK_CONNECTED, LINK_DOWN, LINK_IGNORED, LINK_UNKNOWN, NetworkView
from dial_sdhealth import SdHealthView, STATUS_OFF, STATUS_UNSUPPORTED, STATUS_VALID
from dial_touch_layout import TouchZone, layout_for, list_layout_for, metrics_for, repeat_layout_for
import dial_core_poll
from dial_core import DialCore, PollIO
import dial_display as dd
import dial_display_compositor as dd_compositor
from dial_core_state import (
    EqBand, NOWIFI_PROMPT_STREAK, NowPlaying, OutputRow, artwork_key,
)
from dial_display import (
    SCREEN_POLICIES,
    SELECTOR_TIMEOUT_SECONDS,
    WARNING_DESCRIPTORS,
    DialDisplay,
    DisplayBackend,
    NoOpBackend,
    _fetch_artwork,
    artwork_url_eligible,
    create_dial_display,
)
from dial_warnings import WarningManager, WarningStore
from dial_test_support import (
    FakeBackend,
    _FakeClock,
    _repeat_obj,
    _roster_entry,
    _status_result,
    _target,
    _track_id,
    apply_update_view,
    eq_optimistic,
    fold,
    make_display,
    on_eq_result,
    on_network_view,
    on_outputs_result,
    on_repeat_result,
    on_sd_health_view,
    patch_monotonic,
    pending_token,
    run_warning_action,
    seed_eq,
    seed_outputs,
    tap_output,
    set_eq_optimistic,
    set_focus_pending,
    tick_update_watch,
    tick_warnings,
    warning_active,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakeWindowBackend(FakeBackend):
    """A FakeBackend that can also write a window, the way the real SPI
    backend can. Records every window write as (x0, y0, x1, y1, region);
    `window_result` is what display_window() returns (False simulates a
    backend that cannot window-write right now) and `fail_window` makes it
    raise, so the manager's fall-back paths can be driven one at a time."""
    supports_window_write = True

    def __init__(self, window_result=True, fail_window=False, **kwargs):
        super().__init__(**kwargs)
        self.window_result = window_result
        self.fail_window = fail_window
        self.windows: list = []

    def display_window(self, region, x0, y0, x1, y1):
        if self.fail_window:
            raise RuntimeError("window write failed")
        if not self.window_result:
            return False
        self.windows.append((x0, y0, x1, y1, region))
        return True


def _refresh_selector(display, roster):
    """Give the core *roster* and let the view rebuild the selector's rows
    from the snapshot that carries it."""
    display.core.set_roster(roster)
    display._refresh_selector_rows(display.core.snapshot())


def _refresh_picker(display, roster, now):
    """Give the core *roster* and the repeat records the store holds for it
    (as a poll tick publishes them), then let the view rebuild the picker's
    rows from the snapshot."""
    display.core.set_roster(roster)
    display.core.publish_tick(
        polling=display.core.snapshot().polling,
        repeats={r.appliance_id: dd.repeat_store.get(r.appliance_id, now) for r in roster},
    )
    display._refresh_picker_rows(display.core.snapshot())


# ---------------------------------------------------------------------------
# Disabled config / no-op behavior
# ---------------------------------------------------------------------------

class TestDisabledConfig:
    def test_disabled_backend_never_opens(self):
        display, fb, gt = make_display(fitted=False)
        display.start()
        display.stop()
        assert fb.opened is False

    def test_disabled_status_shape(self):
        display, fb, gt = make_display(fitted=False)
        status = display.get_status()
        # screen_type is the ACTIVE profile, so it is empty while the display
        # is off — the configured key still reads back from GET /screen/settings.
        assert status == {
            "fitted": False, "rotate": False, "screen_type": "",
            "bgr": False, "always_show_controls": False,
            "active": False, "backend": "noop",
            "backend_loaded": False, "showing": "noop",
            "last_error": "", "last_error_at": None,
            "display_sleeping": False, "display_idle_seconds": 0,
        }

    def test_disabled_poll_does_not_query_targets(self):
        display, fb, gt = make_display(fitted=False)
        display._poll_once()
        gt.assert_not_called()


# ---------------------------------------------------------------------------
# A change of the now-playing line asks for a repaint.
# ---------------------------------------------------------------------------

class TestNowPlayingRepaintSignal:
    def test_now_playing_change_sets_overlay_signal(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        display._overlay_signal.clear()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())):
            display._poll_once()
        assert display._overlay_signal.is_set()
    def test_album_only_change_sets_overlay_signal(self):
        # Two polls differing only in album must still count as "now-playing
        # changed" — NowPlaying's == comparison sees every field.
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(album="First Album"))):
            display._poll_once()
        assert display.core.snapshot().now_playing.album == "First Album"

        display._overlay_signal.clear()
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(album="Second Album"))):
            display._poll_once()
        assert display.core.snapshot().now_playing.album == "Second Album"
        assert display._overlay_signal.is_set()


# Artwork URL eligibility and fetching now live in core/autostream_artwork.py,
# shared with the OwnTone metadata publisher; their tests moved to test_artwork.py.


# ---------------------------------------------------------------------------
# End-to-end artwork rendering via DialDisplay
# ---------------------------------------------------------------------------

class TestArtworkRendering:
    def test_successful_artwork_fetch_renders_and_dedupes(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        fb.displayed.clear()

        fake_image = Image.new("RGB", (128, 160))
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")) as mock_fetch_art, \
             patch("dial_display.decode_artwork", return_value=fake_image) as mock_decode, \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()
            display._poll_once()

        assert display.get_status()["showing"] == "artwork"
        mock_fetch_art.assert_called_once()  # second poll reused the cached image
        mock_decode.assert_called_once()
        # Display is only updated when the image identity changes — the
        # second poll's unchanged URL must not trigger a redundant redraw.
        assert len(fb.displayed) == 1

    def test_decode_failure_falls_back_to_logo(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"bad", "")), \
             patch("dial_display.decode_artwork", return_value=None):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"
        assert display.get_status()["last_error"] == "artwork_decode_failed"

    def test_decode_failure_downloads_the_artwork_again_next_poll(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())),              patch("dial_core_poll.default_fetch_artwork", return_value=(b"bad", "")) as mock_fetch_art,              patch("dial_display.decode_artwork", return_value=None):
            display._poll_once()
            assert display._core.snapshot().artwork is None
            display._poll_once()
        assert mock_fetch_art.call_count == 2

    def test_the_core_holds_one_artwork_copy_and_releases_it_at_the_logo(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        fake_image = Image.new("RGB", (128, 160))
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())),              patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")),              patch("dial_display.decode_artwork", return_value=fake_image),              patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()
        held = display._core.snapshot().artwork
        assert held is not None and held.data == b"jpegdata"
        assert display._source_artwork_key == held.key
        gt.return_value = []
        display._poll_once()
        assert display._core.snapshot().artwork is None

    def test_fetch_failure_falls_back_to_logo(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(None, "oversized")):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"
        assert display.get_status()["last_error"] == "artwork_fetch_failed"

    def test_ineligible_url_falls_back_to_logo_without_fetching(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=_track_id(artwork_url="http://provider.example/a.jpg"))
        with patch("dial_core.fetch_target_status", return_value=result), \
             patch("dial_core_poll.default_fetch_artwork") as mock_fetch_art:
            display._poll_once()
        mock_fetch_art.assert_not_called()
        assert display.get_status()["showing"] == "logo"


# ---------------------------------------------------------------------------
# Logo fallback
# ---------------------------------------------------------------------------

class TestLogoFallback:
    def test_logo_fallback_when_no_targets_visible(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_logo_fallback_while_playing_with_no_artwork(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_missing_logo_file_is_non_fatal(self):
        display, fb, gt = make_display(targets=[])
        display._logo_path = "/nonexistent/path/does-not-exist.png"
        display.enable()
        status = display.get_status()
        assert status["last_error"] == "logo_unavailable"
        assert status["showing"] in ("logo", "noop")


# ---------------------------------------------------------------------------
# Idle sleep — 5 minutes of no playing targets dims the display; any
# playing target (including erroring ones, but not unauthorized or
# identity-less ones) counts as activity.
# ---------------------------------------------------------------------------

class TestIdleSleep:
    def test_no_targets_starts_idle_timer_and_shows_logo(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display._poll_once()
            clock.t += 5.0
            status = display.get_status()
        assert status["showing"] == "logo"
        assert status["display_idle_seconds"] == 5

    def test_idle_below_threshold_does_not_sleep(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display._poll_once()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS - 1
            display._poll_once()
            status = display.get_status()
        assert status["display_sleeping"] is False
        assert fb.sleep_calls == 0

    def test_idle_at_threshold_sleeps_once(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display._poll_once()  # idle timer starts
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display._poll_once()  # crosses threshold -> sleep
            display._poll_once()  # still asleep -> no repeat sleep call
            status = display.get_status()
        assert status["display_sleeping"] is True
        assert status["showing"] == "sleeping"
        assert fb.sleep_calls == 1

    def test_sleeping_does_not_repaint(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display._poll_once()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display._poll_once()
            count_after_sleep = len(fb.displayed)
            display._poll_once()
            display._poll_once()
        assert len(fb.displayed) == count_after_sleep

    def test_idle_seconds_clamps_at_threshold_while_asleep(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display._poll_once()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display._poll_once()
            clock.t += 1000.0  # long past threshold while asleep
            status = display.get_status()
        assert status["display_idle_seconds"] == dd.DISPLAY_IDLE_SLEEP_SECONDS

    def test_target_appearing_wakes_before_next_frame(self):
        t = _target()
        display, fb, gt = make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display._poll_once()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display._poll_once()  # asleep now
            assert display.get_status()["display_sleeping"] is True

            gt.return_value = [t]
            with patch("dial_core.fetch_target_status",
                       return_value=_status_result(track_id=None)):
                display._poll_once()
            status = display.get_status()

        assert fb.wake_calls == 1
        assert status["display_sleeping"] is False
        assert status["display_idle_seconds"] == 0
        assert status["showing"] == "logo"

    def test_wake_repaints_same_artwork_url_as_before_sleep(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()

        fake_image = Image.new("RGB", (128, 160))
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()  # showing artwork
        assert display.get_status()["showing"] == "artwork"

        gt.return_value = []
        clock = _FakeClock()
        with patch_monotonic(clock):
            display._poll_once()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display._poll_once()  # asleep
        assert display.get_status()["display_sleeping"] is True

        gt.return_value = [t]
        displayed_before = len(fb.displayed)
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()  # wakes and repaints same artwork url

        assert fb.wake_calls == 1
        assert display.get_status()["display_sleeping"] is False
        assert display.get_status()["showing"] == "artwork"
        assert len(fb.displayed) > displayed_before

    def test_playing_target_no_artwork_never_sleeps(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock), \
             patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            for _ in range(5):
                display._poll_once()
                clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            status = display.get_status()
        assert status["showing"] == "logo"
        assert status["display_sleeping"] is False
        assert status["display_idle_seconds"] == 0
        assert fb.sleep_calls == 0

    def test_unauthorized_only_targets_do_not_hold_off_idle_sleep(self):
        t = _target(auth="unauthorized")
        display, fb, gt = make_display(targets=[t])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display._poll_once()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display._poll_once()
            status = display.get_status()
        assert status["display_sleeping"] is True
        assert fb.sleep_calls == 1

    def _asleep_display(self, clock):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with patch_monotonic(clock):
            display._poll_once()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display._poll_once()
        assert display.get_status()["display_sleeping"] is True
        return display, fb, gt

    def test_unauthorized_only_targets_do_not_wake_sleeping_panel(self):
        clock = _FakeClock()
        display, fb, gt = self._asleep_display(clock)
        gt.return_value = [_target(auth="unauthorized")]
        with patch_monotonic(clock):
            display._poll_once()
        assert display.get_status()["display_sleeping"] is True
        assert fb.wake_calls == 0

    def test_unauthorized_only_targets_keep_the_idle_clock_running(self):
        display, fb, gt = make_display(targets=[_target(auth="unauthorized")])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display._poll_once()
            clock.t += 5.0
            display._poll_once()
            status = display.get_status()
        assert status["display_idle_seconds"] == 5

    def test_unknown_identified_target_still_wakes_panel(self):
        clock = _FakeClock()
        display, fb, gt = self._asleep_display(clock)
        t = _target(auth="unknown")
        gt.return_value = [t]
        with patch_monotonic(clock),              patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        assert display.get_status()["display_sleeping"] is False
        assert fb.wake_calls == 1
        assert display.core.snapshot().focus.reporting_id == t.appliance_id

    def test_authorized_target_wakes_panel_alongside_unauthorized_one(self):
        clock = _FakeClock()
        display, fb, gt = self._asleep_display(clock)
        refused = _target(name="Lounge", auth="unauthorized", playing_since=1.0)
        ok = _target(name="Kitchen", auth="authorized", playing_since=2.0)
        gt.return_value = [refused, ok]
        with patch_monotonic(clock),              patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        assert display.get_status()["display_sleeping"] is False
        assert display.core.snapshot().focus.reporting_id == ok.appliance_id

    def test_unresolved_identityless_target_does_not_wake_panel(self):
        clock = _FakeClock()
        display, fb, gt = self._asleep_display(clock)
        gt.return_value = [_target(appliance_id="")]
        with patch_monotonic(clock),              patch("dial_core.fetch_target_status") as fetch:
            display._poll_once()
        fetch.assert_not_called()
        assert display.get_status()["display_sleeping"] is True
        assert fb.wake_calls == 0
        assert display.core.snapshot().focus.reporting_id is None

    def test_disable_while_asleep_resets_idle_and_sleep_state(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display._poll_once()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display._poll_once()
        assert display.get_status()["display_sleeping"] is True

        status = display.update_config(DialDisplayConfig(fitted=False))
        assert status["display_sleeping"] is False
        assert status["display_idle_seconds"] == 0
        assert display._idle_started_at is None


# ---------------------------------------------------------------------------
# Backend failure degradation
# ---------------------------------------------------------------------------

class TestBackendFailureDegradation:
    def test_backend_open_failure_degrades_to_noop(self):
        fb = FakeBackend(fail_open=True)
        display, _, gt = make_display(backend=fb)
        display.enable()
        status = display.get_status()
        assert status["backend_loaded"] is False
        assert status["showing"] == "noop"
        assert status["last_error"] == "backend_open_failed"

    def test_backend_display_failure_is_non_fatal(self):
        fb = FakeBackend(fail_display=True)
        display, _, gt = make_display(backend=fb)
        display.enable()  # logo render will fail silently at backend level
        status = display.get_status()
        assert status["last_error"] == "display_write_failed"

    def test_disabled_config_never_touches_backend(self):
        fb = FakeBackend()
        display, _, gt = make_display(fitted=False, backend=fb)
        display.update_config(DialDisplayConfig(fitted=False))
        assert fb.opened is False


class TestPushFrameLocked:
    def test_compose_raising_records_failure_and_skips_the_backend(self):
        display, fb, gt = make_display()
        display.enable()
        before = len(fb.displayed)

        def bad_compose():
            raise RuntimeError("compose blew up")

        with display._lock:
            display._push_frame_locked(bad_compose)
        assert display.get_status()["last_error"] == "display_write_failed"
        assert len(fb.displayed) == before

    def test_backend_raising_records_the_same_failure(self):
        display, fb, gt = make_display(backend=FakeBackend(fail_display=True))
        display.enable()
        with display._lock:
            display._push_frame_locked(lambda: object())
        assert display.get_status()["last_error"] == "display_write_failed"

    def test_success_pushes_exactly_once_and_records_no_error(self):
        display, fb, gt = make_display()
        display.enable()
        before = len(fb.displayed)
        # Sized to the backend's own dims so the push-time resample is
        # skipped (same size in and out) and the identical object reaches
        # the backend, unchanged — the point of this test.
        sentinel = Image.new("RGB", (fb.width, fb.height))
        with display._lock:
            display._push_frame_locked(lambda: sentinel)
        assert fb.displayed[-1] is sentinel
        assert len(fb.displayed) == before + 1
        assert display.get_status()["last_error"] == ""

    def test_success_sets_last_frame_to_the_pushed_object(self):
        display, fb, gt = make_display()
        display.enable()
        sentinel = Image.new("RGB", (fb.width, fb.height))
        with display._lock:
            display._push_frame_locked(lambda: sentinel)
        assert display._last_frame is sentinel

    def test_failed_push_keeps_the_previous_last_frame(self):
        display, fb, gt = make_display()
        display.enable()
        previous = display._last_frame
        assert previous is not None

        def bad_compose():
            raise RuntimeError("compose blew up")

        with display._lock:
            display._push_frame_locked(bad_compose)
        assert display._last_frame is previous


def _frame(fb, color):
    return Image.new("RGB", (fb.width, fb.height), color)


def _push(display, image):
    with display._lock:
        display._push_frame_locked(lambda: image)


class TestPushFrameWindowed:
    """_push_frame_locked's windowed-write path, gated on the backend's
    supports_window_write flag, so every FakeBackend-based test above (no
    such attribute) keeps taking the full-write path exactly as before."""

    def test_first_frame_after_open_is_a_full_write(self):
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        assert len(fb.displayed) == 1
        assert fb.windows == []
        assert display._last_frame is not None

    def test_identical_frame_sends_nothing(self):
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        a = _frame(fb, (10, 20, 30))
        _push(display, a)
        displayed_before = len(fb.displayed)
        windows_before = len(fb.windows)

        b = _frame(fb, (10, 20, 30))
        _push(display, b)

        assert len(fb.displayed) == displayed_before
        assert len(fb.windows) == windows_before
        assert display._last_frame is b
        assert display.get_status()["last_error"] == ""

    def test_small_change_writes_only_its_bounding_window(self):
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        a = _frame(fb, (0, 0, 0))
        _push(display, a)
        displayed_before = len(fb.displayed)
        windows_before = len(fb.windows)

        b = a.copy()
        b.paste((255, 0, 0), (100, 100, 110, 104))
        _push(display, b)

        assert len(fb.displayed) == displayed_before
        new_windows = fb.windows[windows_before:]
        assert len(new_windows) == 1
        x0, y0, x1, y1, region = new_windows[0]
        assert (x0, y0, x1, y1) == (100, 100, 109, 103)
        assert region.size == (10, 4)
        assert region.getpixel((0, 0)) == (255, 0, 0)
        assert display._last_frame is b

    def test_full_change_writes_a_full_size_window(self):
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        a = _frame(fb, (0, 0, 0))
        _push(display, a)
        windows_before = len(fb.windows)

        c = _frame(fb, (255, 255, 255))
        _push(display, c)

        new_windows = fb.windows[windows_before:]
        assert len(new_windows) == 1
        x0, y0, x1, y1, region = new_windows[0]
        assert (x0, y0, x1, y1) == (0, 0, fb.width - 1, fb.height - 1)
        assert region.size == (fb.width, fb.height)

    def test_size_mismatch_with_last_frame_falls_back_to_full_write(self):
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        with display._lock:
            display._last_frame = Image.new("RGB", (8, 8))
        displayed_before = len(fb.displayed)
        windows_before = len(fb.windows)

        a = _frame(fb, (10, 20, 30))
        _push(display, a)

        assert len(fb.displayed) == displayed_before + 1
        assert len(fb.windows) == windows_before

    def test_mode_mismatch_with_last_frame_falls_back_to_full_write(self):
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        with display._lock:
            display._last_frame = Image.new("L", (fb.width, fb.height))
        displayed_before = len(fb.displayed)
        windows_before = len(fb.windows)

        a = _frame(fb, (10, 20, 30))
        _push(display, a)

        assert len(fb.displayed) == displayed_before + 1
        assert len(fb.windows) == windows_before

    def test_backend_without_window_support_always_writes_the_full_frame(self):
        display, fb, gt = make_display(backend=FakeBackend())
        display.enable()
        displayed_before = len(fb.displayed)

        a = _frame(fb, (10, 20, 30))
        _push(display, a)
        _push(display, a)

        assert len(fb.displayed) == displayed_before + 2

    def test_window_write_returning_false_falls_back_to_full_write(self):
        display, fb, gt = make_display(backend=FakeWindowBackend(window_result=False))
        display.enable()
        a = _frame(fb, (10, 20, 30))
        _push(display, a)
        displayed_before = len(fb.displayed)

        b = _frame(fb, (40, 50, 60))
        _push(display, b)

        assert len(fb.displayed) == displayed_before + 1
        assert fb.windows == []
        assert display.get_status()["last_error"] == ""

    def test_window_write_raising_falls_back_to_full_write_without_error(self):
        display, fb, gt = make_display(backend=FakeWindowBackend(fail_window=True))
        display.enable()
        a = _frame(fb, (10, 20, 30))
        _push(display, a)
        displayed_before = len(fb.displayed)

        b = _frame(fb, (40, 50, 60))
        _push(display, b)

        assert len(fb.displayed) == displayed_before + 1
        assert display.get_status()["last_error"] == ""
        assert display._last_frame is b

    def test_full_write_failure_drops_last_frame(self):
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        a = _frame(fb, (10, 20, 30))
        _push(display, a)

        fb.fail_display = True
        fb.fail_window = True
        b = _frame(fb, (40, 50, 60))
        _push(display, b)

        assert display.get_status()["last_error"] == "display_write_failed"
        assert display._last_frame is None

    # test_compose_failure_keeps_last_frame is already covered by
    # test_failed_push_keeps_the_previous_last_frame above.

    def test_frame_after_a_dropped_last_frame_is_a_full_write(self):
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        a = _frame(fb, (10, 20, 30))
        _push(display, a)
        fb.fail_display = True
        fb.fail_window = True
        b = _frame(fb, (40, 50, 60))
        _push(display, b)
        assert display._last_frame is None

        fb.fail_display = False
        fb.fail_window = False
        displayed_before = len(fb.displayed)
        windows_before = len(fb.windows)
        c = _frame(fb, (70, 80, 90))
        _push(display, c)

        assert len(fb.displayed) == displayed_before + 1
        assert len(fb.windows) == windows_before

    def test_swap_reopens_with_a_full_write(self):
        t = _target()
        fb_old = FakeWindowBackend()
        fb_new = FakeWindowBackend()

        def builder(screen_type):
            return lambda: fb_new

        display, _, gt = make_display(
            targets=[t], backend=fb_old, backend_factory_builder=builder,
        )
        display.enable()
        with display._lock:
            display._rebuild_backend_factory_locked("st7789_240x240")
            display._swap_backend_locked()

        assert len(fb_new.displayed) == 1
        assert fb_new.windows == []

    def test_repushing_the_same_logo_sends_nothing(self):
        # The "free win": the logo re-render after enable() is byte-identical
        # to the one already on the panel, so the diff finds nothing to send.
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        displayed_before = len(fb.displayed)
        windows_before = len(fb.windows)
        with display._lock:
            display._render_logo_locked()
        assert len(fb.displayed) == displayed_before
        assert len(fb.windows) == windows_before

    # -----------------------------------------------------------------
    # _dirty_windows(): splitting one changed region into separately
    # written windows when the unchanged rows between them are wide
    # enough to be worth the extra write. The fake backend is 128 px
    # wide, so the row-count gap the split requires is ceil(4096/128) =
    # 32 rows; a change narrower than the full width needs proportionally
    # more unchanged rows to justify a split (see _dirty_windows).
    # -----------------------------------------------------------------

    def test_two_far_apart_changes_write_two_windows(self):
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        a = _frame(fb, (0, 0, 0))
        _push(display, a)
        displayed_before = len(fb.displayed)
        windows_before = len(fb.windows)

        b = a.copy()
        b.paste((255, 0, 0), (0, 0, fb.width, 8))
        b.paste((255, 0, 0), (30, 120, 60, 128))
        _push(display, b)

        new_windows = fb.windows[windows_before:]
        boxes = [(x0, y0, x1, y1) for x0, y0, x1, y1, _ in new_windows]
        assert boxes == [(0, 0, 127, 7), (30, 120, 59, 127)]
        assert len(fb.displayed) == displayed_before  # no full-frame fallback

    def test_close_changes_stay_one_window(self):
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        a = _frame(fb, (0, 0, 0))
        _push(display, a)
        windows_before = len(fb.windows)

        b = a.copy()
        b.paste((255, 0, 0), (0, 0, fb.width, 8))
        b.paste((255, 0, 0), (0, 20, fb.width, 28))
        _push(display, b)

        new_windows = fb.windows[windows_before:]
        boxes = [(x0, y0, x1, y1) for x0, y0, x1, y1, _ in new_windows]
        assert boxes == [(0, 0, 127, 27)]

    def test_narrow_changes_stay_one_window(self):
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        a = _frame(fb, (0, 0, 0))
        _push(display, a)
        windows_before = len(fb.windows)

        b = a.copy()
        b.paste((255, 0, 0), (10, 0, 20, 8))
        b.paste((255, 0, 0), (10, 120, 20, 128))
        _push(display, b)

        new_windows = fb.windows[windows_before:]
        boxes = [(x0, y0, x1, y1) for x0, y0, x1, y1, _ in new_windows]
        assert boxes == [(10, 0, 19, 127)]

    def test_four_bands_are_four_windows(self):
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        a = _frame(fb, (0, 0, 0))
        _push(display, a)
        windows_before = len(fb.windows)

        b = a.copy()
        for y in (0, 40, 80, 120):
            b.paste((255, 0, 0), (0, y, fb.width, min(y + 8, fb.height)))
        _push(display, b)

        new_windows = fb.windows[windows_before:]
        boxes = [(x0, y0, x1, y1) for x0, y0, x1, y1, _ in new_windows]
        assert boxes == [(0, 0, 127, 7), (0, 40, 127, 47), (0, 80, 127, 87), (0, 120, 127, 127)]

    def test_twelve_spots_fall_back_to_the_bounding_box(self):
        from PIL import ImageChops
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        a = _frame(fb, (0, 0, 0))
        _push(display, a)
        windows_before = len(fb.windows)
        displayed_before = len(fb.displayed)

        b = a.copy()
        for i in range(12):
            x = 4 + 30 * (i % 3)
            y = 4 + 12 * i
            b.paste((255, 0, 0), (x, y, x + 6, y + 4))
        _push(display, b)

        new_windows = fb.windows[windows_before:]
        boxes = [(x0, y0, x1, y1) for x0, y0, x1, y1, _ in new_windows]
        diff_bbox = ImageChops.difference(a, b).getbbox()
        assert boxes == [(diff_bbox[0], diff_bbox[1], diff_bbox[2] - 1, diff_bbox[3] - 1)]
        assert len(fb.displayed) == displayed_before

    def test_windows_are_written_top_to_bottom(self):
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        a = _frame(fb, (0, 0, 0))
        _push(display, a)
        windows_before = len(fb.windows)

        b = a.copy()
        b.paste((255, 0, 0), (30, 120, 60, 128))
        b.paste((255, 0, 0), (0, 0, fb.width, 8))
        _push(display, b)

        ys = [y0 for _, y0, _, _, _ in fb.windows[windows_before:]]
        assert len(ys) == 2
        assert ys == sorted(ys)

    def test_planner_unavailable_uses_the_bounding_box_path(self, monkeypatch, caplog):
        import logging
        monkeypatch.setattr(dd, "frame_words", lambda *a, **k: None)
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        a = _frame(fb, (0, 0, 0))
        _push(display, a)
        windows_before = len(fb.windows)

        b = a.copy()
        b.paste((255, 0, 0), (0, 0, fb.width, 8))
        b.paste((255, 0, 0), (30, 120, 60, 128))
        with caplog.at_level(logging.WARNING):
            _push(display, b)

        boxes = [(x0, y0, x1, y1) for x0, y0, x1, y1, _ in fb.windows[windows_before:]]
        assert boxes == [(0, 0, 127, 7), (30, 120, 59, 127)]
        assert not [r for r in caplog.records if "planning" in r.message]

    def test_planner_failure_is_logged_once_and_falls_back(self, monkeypatch, caplog):
        import logging

        def boom(*args, **kwargs):
            raise RuntimeError("plan exploded")

        monkeypatch.setattr(dd, "plan_windows", boom)
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        a = _frame(fb, (0, 0, 0))
        _push(display, a)
        windows_before = len(fb.windows)
        displayed_before = len(fb.displayed)

        with caplog.at_level(logging.WARNING):
            frame = a
            for i in range(3):
                frame = frame.copy()
                frame.paste((255, i * 40, 0), (10, 10, 30, 20))
                _push(display, frame)

        assert len(fb.windows) - windows_before == 3
        assert len(fb.displayed) == displayed_before
        assert len([r for r in caplog.records if "change-region planning failed" in r.message]) == 1

    def test_words_cache_follows_last_frame_identity(self):
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        a = _frame(fb, (0, 0, 0))
        _push(display, a)
        b = a.copy()
        b.paste((255, 0, 0), (10, 10, 20, 20))
        _push(display, b)
        assert display._panel_words[0] is display._last_frame
        assert display._last_frame is b

        displayed_before = len(fb.displayed)
        with display._lock:
            display._last_frame = None
        c = b.copy()
        c.paste((0, 255, 0), (30, 30, 40, 40))
        _push(display, c)
        assert len(fb.displayed) == displayed_before + 1  # nothing to diff against: whole frame
        assert display._panel_words is None

        d = c.copy()
        d.paste((0, 0, 255), (50, 50, 60, 60))
        windows_before = len(fb.windows)
        _push(display, d)
        assert [w[:4] for w in fb.windows[windows_before:]] == [(50, 50, 59, 59)]
        assert display._panel_words[0] is display._last_frame
        assert display._last_frame is d

    def test_stale_words_cache_is_rebuilt_from_last_frame(self):
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        a = _frame(fb, (0, 0, 0))
        _push(display, a)
        b = a.copy()
        b.paste((255, 0, 0), (10, 10, 20, 20))
        _push(display, b)
        # A cache naming some other frame must never be trusted.
        display._panel_words = (a, display._panel_words[1])
        c = b.copy()
        c.paste((0, 255, 0), (30, 30, 40, 40))
        windows_before = len(fb.windows)
        _push(display, c)
        assert [w[:4] for w in fb.windows[windows_before:]] == [(30, 30, 39, 39)]

    def test_partial_window_failure_drops_the_words_cache(self):
        class _RefusesSecondWindow(FakeWindowBackend):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                self._calls = 0

            def display_window(self, region, x0, y0, x1, y1):
                self._calls += 1
                if self._calls == 2:
                    return False
                return super().display_window(region, x0, y0, x1, y1)

        fb = _RefusesSecondWindow()
        display, fb, gt = make_display(backend=fb)
        display.enable()
        a = _frame(fb, (0, 0, 0))
        _push(display, a)
        displayed_before = len(fb.displayed)

        b = a.copy()
        b.paste((255, 0, 0), (0, 0, fb.width, 8))
        b.paste((255, 0, 0), (0, 120, fb.width, 128))
        _push(display, b)
        assert len(fb.displayed) == displayed_before + 1
        assert display._panel_words is None

        c = b.copy()
        c.paste((0, 255, 0), (10, 10, 20, 20))
        windows_before = len(fb.windows)
        _push(display, c)
        assert len(fb.displayed) == displayed_before + 1
        assert [w[:4] for w in fb.windows[windows_before:]] == [(10, 10, 19, 19)]
        assert display._panel_words[0] is display._last_frame
        assert display._last_frame is c

    def test_identical_frame_after_planner_sends_nothing_and_keeps_the_cache(self):
        display, fb, gt = make_display(backend=FakeWindowBackend())
        display.enable()
        a = _frame(fb, (0, 0, 0))
        _push(display, a)
        b = a.copy()
        b.paste((255, 0, 0), (10, 10, 20, 20))
        _push(display, b)
        displayed_before, windows_before = len(fb.displayed), len(fb.windows)

        c = b.copy()
        _push(display, c)

        assert len(fb.displayed) == displayed_before
        assert len(fb.windows) == windows_before
        assert display._last_frame is c
        assert display._panel_words[0] is c

    def test_window_refused_midway_falls_back_to_a_full_write(self):
        class _RefusesSecondWindow(FakeWindowBackend):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                self._calls = 0

            def display_window(self, region, x0, y0, x1, y1):
                self._calls += 1
                if self._calls == 1:
                    return True
                return False

        fb = _RefusesSecondWindow()
        display, fb, gt = make_display(backend=fb)
        display.enable()
        a = _frame(fb, (0, 0, 0))
        _push(display, a)
        displayed_before = len(fb.displayed)

        b = a.copy()
        b.paste((255, 0, 0), (0, 0, fb.width, 8))
        b.paste((255, 0, 0), (0, 120, fb.width, 128))
        _push(display, b)

        assert len(fb.displayed) == displayed_before + 1
        assert display._last_frame is b

    def test_dirty_windows_cover_every_changed_pixel(self):
        import random
        from dial_display import _dirty_windows

        rng = random.Random(12345)
        for _ in range(20):
            width, height = 128, 160
            base = Image.new("L", (width, height), 0)
            rects = []
            for _ in range(rng.randint(1, 4)):
                x0 = rng.randint(0, width - 2)
                y0 = rng.randint(0, height - 2)
                x1 = rng.randint(x0 + 1, width)
                y1 = rng.randint(y0 + 1, height)
                rects.append((x0, y0, x1, y1))
            diff = Image.new("L", (width, height), 0)
            for rect in rects:
                diff.paste(255, rect)
            bbox = diff.getbbox()
            if bbox is None:
                continue
            windows = _dirty_windows(diff, bbox)

            covered = Image.new("L", (width, height), 0)
            for win in windows:
                covered.paste(255, win)
            diff_data = list(diff.getdata())
            covered_data = list(covered.getdata())
            for pixel_diff, pixel_covered in zip(diff_data, covered_data):
                if pixel_diff:
                    assert pixel_covered

            # No two returned windows overlap.
            for i, win_a in enumerate(windows):
                for win_b in windows[i + 1 :]:
                    ax0, ay0, ax1, ay1 = win_a
                    bx0, by0, bx1, by1 = win_b
                    overlap = not (ax1 <= bx0 or bx1 <= ax0 or ay1 <= by0 or by1 <= ay0)
                    assert not overlap


# ---------------------------------------------------------------------------
# _last_frame lifecycle — retained across a push, dropped whenever the
# panel no longer shows it.
# ---------------------------------------------------------------------------

class TestLastFrameLifecycle:
    def test_none_on_a_fresh_display(self):
        display, fb, gt = make_display()
        assert display._last_frame is None

    def test_set_after_enable_renders_the_logo(self):
        display, fb, gt = make_display()
        display.enable()
        assert display._last_frame is not None
        assert display._last_frame.size == (fb.width, fb.height)

    def test_cleared_by_disable_locked(self):
        display, fb, gt = make_display()
        display.enable()
        assert display._last_frame is not None
        with display._lock:
            display._disable_locked()
        assert display._last_frame is None

    def test_cleared_by_sleep_locked(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        assert display._last_frame is not None
        with display._lock:
            display._sleep_locked()
        assert display._last_frame is None

    def test_cleared_by_clear_locked(self):
        display, fb, gt = make_display()
        display.enable()
        assert display._last_frame is not None
        with display._lock:
            display._clear_locked()
        assert display._last_frame is None

    def test_cleared_by_swap_backend_locked(self):
        t = _target()
        fb_old = FakeBackend()
        fb_new = FakeBackend()

        def builder(screen_type):
            return lambda: fb_new

        display, _, gt = make_display(
            targets=[t], backend=fb_old, backend_factory_builder=builder,
        )
        display.enable()
        assert display._last_frame is not None
        with display._lock:
            display._rebuild_backend_factory_locked("st7789_240x240")
            display._swap_backend_locked()
        # The reopen on the new backend renders the logo again, so a frame
        # is present once more — but it belongs to the NEW backend, not a
        # stale reference to the old one's dimensions.
        assert display._last_frame is not None
        assert display._last_frame.size == (fb_new.width, fb_new.height)


# ---------------------------------------------------------------------------
# latest_frame_png() — the one-shot screenshot accessor
# ---------------------------------------------------------------------------

class TestLatestFramePng:
    def test_none_before_any_push(self):
        display, fb, gt = make_display()
        assert display.latest_frame_png() is None

    def test_round_trips_a_decodable_png_at_the_backend_size(self):
        display, fb, gt = make_display()
        display.enable()
        marked = Image.new("RGB", (fb.width, fb.height), (10, 20, 30))
        with display._lock:
            display._push_frame_locked(lambda: marked)
        png_bytes = display.latest_frame_png()
        assert png_bytes is not None
        assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n")
        decoded = Image.open(io.BytesIO(png_bytes))
        decoded.load()
        assert decoded.convert("RGB").size == (fb.width, fb.height)
        assert decoded.convert("RGB").getpixel((0, 0)) == (10, 20, 30)

    def test_rotate_true_undoes_the_180_rotation(self):
        display, fb, gt = make_display(rotate=True)
        display.enable()
        # The cache holds the already-rotated frame (as the panel shows
        # it); a single corner marker makes a 180-degree undo visible.
        marked = Image.new("RGB", (fb.width, fb.height), (0, 0, 0))
        marked.putpixel((0, 0), (255, 0, 0))
        with display._lock:
            display._push_frame_locked(lambda: marked)
        decoded = Image.open(io.BytesIO(display.latest_frame_png())).convert("RGB")
        assert decoded.getpixel((fb.width - 1, fb.height - 1)) == (255, 0, 0)
        assert decoded.getpixel((0, 0)) == (0, 0, 0)

    def test_bgr_true_undoes_the_channel_swap(self):
        display, fb, gt = make_display(bgr=True)
        display.enable()
        marked = Image.new("RGB", (fb.width, fb.height), (10, 20, 30))
        with display._lock:
            display._push_frame_locked(lambda: marked)
        decoded = Image.open(io.BytesIO(display.latest_frame_png())).convert("RGB")
        assert decoded.getpixel((0, 0)) == (30, 20, 10)

    def test_cleared_state_reports_none(self):
        display, fb, gt = make_display()
        display.enable()
        assert display.latest_frame_png() is not None
        with display._lock:
            display._clear_locked()
        assert display.latest_frame_png() is None

    def test_encode_does_not_hold_the_lock(self):
        display, fb, gt = make_display()
        display.enable()
        observed = {}
        real_save = Image.Image.save

        def spying_save(img_self, *args, **kwargs):
            observed["locked"] = display._lock.locked()
            return real_save(img_self, *args, **kwargs)

        with patch.object(Image.Image, "save", spying_save):
            png_bytes = display.latest_frame_png()
        assert png_bytes is not None
        assert observed.get("locked") is False

    def test_encode_failure_is_swallowed(self):
        display, fb, gt = make_display()
        display.enable()
        with patch.object(Image.Image, "save", side_effect=RuntimeError("encode blew up")):
            assert display.latest_frame_png() is None


# ---------------------------------------------------------------------------
# update_config live apply
# ---------------------------------------------------------------------------

class TestUpdateConfig:
    def test_enable_via_update_config_opens_backend(self):
        display, fb, gt = make_display(fitted=False)
        status = display.update_config(DialDisplayConfig(fitted=True))
        assert fb.opened is True
        assert status["backend_loaded"] is True

    def test_disable_via_update_config_closes_backend(self):
        display, fb, gt = make_display(fitted=True)
        display.enable()
        assert fb.opened is True
        status = display.update_config(DialDisplayConfig(fitted=False))
        assert fb.closed is True
        assert status["showing"] == "noop"

    def test_poll_interval_change_wakes_the_poll_loop(self):
        display, fb, gt = make_display(fitted=False)
        display._core._poll_wake.clear()
        display.update_config(DialDisplayConfig(fitted=False, poll_interval_s=3))
        assert display._core._poll_interval == 3
        assert display._core._poll_wake.is_set()

    def test_fitted_is_the_cores_polling_setting(self):
        display, fb, gt = make_display(fitted=False)
        assert display._core.snapshot().polling is False
        display.update_config(DialDisplayConfig(fitted=True))
        assert display._core.snapshot().polling is True
        display.update_config(DialDisplayConfig(fitted=False))
        assert display._core.snapshot().polling is False

    def test_unchanged_poll_interval_does_not_wake_the_poll_loop(self):
        display, fb, gt = make_display(fitted=False)
        display._core._poll_wake.clear()
        display.update_config(DialDisplayConfig(fitted=False, rotate=True))
        assert not display._core._poll_wake.is_set()


# ---------------------------------------------------------------------------
# Screen-size setting (physical diagonal) — mm_per_px derivation and its
# plumbing into _metrics_locked() / redisplay-on-change. Density has no
# effect on rendered bytes in this stage (see test_dial_display_compositor.py
# for that invariant); these tests cover the manager's own bookkeeping.
# ---------------------------------------------------------------------------

class TestScreenSizeSetting:
    def test_init_derives_mm_per_px_from_profile_default(self):
        display, fb, gt = make_display(fitted=False, screen_type=DEFAULT_PROFILE_KEY)
        profile = get_profile(DEFAULT_PROFILE_KEY)
        expected = mm_per_px_for(profile, profile.default_diagonal_inches)
        assert display._mm_per_px == pytest.approx(expected)

    def test_init_derives_mm_per_px_from_override(self):
        display, fb, gt = make_display(fitted=False, screen_size_inches=3.5)
        profile = get_profile(DEFAULT_PROFILE_KEY)
        expected = mm_per_px_for(profile, 3.5)
        assert display._mm_per_px == pytest.approx(expected)

    def test_update_config_size_only_change_redisplays_synchronously(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], fitted=True)
        display.enable()

        fake_image = _marked_image(size=(fb.width, fb.height))
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()
        fb.displayed.clear()

        # A size-only change must take effect synchronously via
        # update_config — not via the 6s poll loop — same as rotate/bgr.
        with patch.object(display, "_poll_once") as mock_poll:
            status = display.update_config(DialDisplayConfig(fitted=True, screen_size_inches=3.5))
        mock_poll.assert_not_called()
        assert status["fitted"] is True
        assert len(fb.displayed) == 1

    def test_update_config_updates_mm_per_px(self):
        display, fb, gt = make_display(fitted=True)
        display.enable()
        profile = get_profile(DEFAULT_PROFILE_KEY)
        before = display._mm_per_px
        display.update_config(DialDisplayConfig(fitted=True, screen_size_inches=3.5))
        after = display._mm_per_px
        assert after != before
        assert after == pytest.approx(mm_per_px_for(profile, 3.5))

    def test_screen_type_change_updates_mm_per_px_to_new_profile_default(self):
        fb_old = FakeBackend()
        fb_old.width, fb_old.height = 160, 128
        fb_new = FakeBackend()
        fb_new.width, fb_new.height = 240, 240

        def builder(screen_type):
            return (lambda: fb_new) if screen_type == "st7789_240x240" else (lambda: fb_old)

        display, _, gt = make_display(
            fitted=True, screen_type="st7735s_160x128", backend=fb_old,
            backend_factory_builder=builder,
        )
        display.enable()
        display.update_config(DialDisplayConfig(fitted=True, screen_type="st7789_240x240"))

        new_profile = get_profile("st7789_240x240")
        expected = mm_per_px_for(new_profile, new_profile.default_diagonal_inches)
        assert display._mm_per_px == pytest.approx(expected)

    def test_metrics_locked_reflects_backend_dims_and_density(self):
        display, fb, gt = make_display(fitted=True, screen_size_inches=2.8)
        display.enable()
        profile = get_profile(DEFAULT_PROFILE_KEY)
        expected_mm = mm_per_px_for(profile, 2.8)
        with display._lock:
            m = display._metrics_locked()
        assert m.width == fb.width
        assert m.height == fb.height
        assert m.mm_per_px == pytest.approx(expected_mm)
        assert m == metrics_for(fb.width, fb.height, mm_per_px=expected_mm)


# ---------------------------------------------------------------------------
# Screen-type swap — closes the old backend, opens a new one built for the
# new profile, and clears cached state so the next frame recomposes at the
# new dimensions.
# ---------------------------------------------------------------------------

class TestScreenTypeSwap:
    def _swap_builder(self, fb_old, fb_new, new_key="st7789_240x240"):
        def builder(screen_type):
            return (lambda: fb_new) if screen_type == new_key else (lambda: fb_old)
        return builder

    def test_swap_closes_old_backend_and_opens_new_with_new_dims(self):
        fb_old = FakeBackend()
        fb_old.width, fb_old.height = 160, 128
        fb_new = FakeBackend()
        fb_new.width, fb_new.height = 240, 240

        display, _, gt = make_display(
            fitted=True, screen_type="st7735s_160x128", backend=fb_old,
            backend_factory_builder=self._swap_builder(fb_old, fb_new),
        )
        display.enable()
        assert fb_old.opened is True
        assert fb_new.opened is False

        status = display.update_config(
            DialDisplayConfig(fitted=True, screen_type="st7789_240x240")
        )

        assert fb_old.closed is True
        assert fb_new.opened is True
        assert status["screen_type"] == "st7789_240x240"
        assert display._backend is fb_new

    def test_screen_type_change_while_off_applies_at_next_enable(self):
        """A profile accepted while the display is off must be the one that
        opens when it is switched back on.

        The factory rebuild must not be gated on `fitted`: the later enable
        sees no screen_type change to react to, so a rebuild deferred until
        then never happens and the previous profile opens instead — silently,
        with status and on-disk config both naming the new one.
        """
        fb_old = FakeBackend()
        fb_old.width, fb_old.height = 160, 128
        fb_new = FakeBackend()
        fb_new.width, fb_new.height = 240, 240

        display, _, gt = make_display(
            fitted=True, screen_type="st7735s_160x128", backend=fb_old,
            backend_factory_builder=self._swap_builder(fb_old, fb_new),
        )
        display.enable()
        assert fb_old.opened is True

        # Turn the display off and change the profile in the same request.
        display.update_config(
            DialDisplayConfig(fitted=False, screen_type="st7789_240x240")
        )
        assert fb_old.closed is True
        assert fb_new.opened is False

        # Switching back on — same screen_type as the previous call, so there
        # is no change to detect here; the rebuild must already have happened.
        status = display.update_config(
            DialDisplayConfig(fitted=True, screen_type="st7789_240x240")
        )

        assert fb_new.opened is True, "the newly-selected profile must open"
        assert display._backend is fb_new
        assert status["screen_type"] == "st7789_240x240"

    def test_runtime_screen_type_is_active_not_requested(self):
        """runtime.screen_type must name the profile actually open, so a
        failed swap is visible as drift against the configured value."""
        fb_old = FakeBackend()

        class _FailingBackend(FakeBackend):
            def open(self):
                raise RuntimeError("no panel")

        fb_new = _FailingBackend()
        display, _, gt = make_display(
            fitted=True, screen_type="st7735s_160x128", backend=fb_old,
            backend_factory_builder=self._swap_builder(fb_old, fb_new),
        )
        display.enable()
        assert display.get_status()["screen_type"] == "st7735s_160x128"

        status = display.update_config(
            DialDisplayConfig(fitted=True, screen_type="st7789_240x240")
        )
        # The requested profile failed to open: nothing is active, so runtime
        # reports no profile rather than echoing the request.
        assert status["screen_type"] == ""
        assert status["last_error"] == "backend_open_failed"

    def test_swap_clears_cache_so_next_poll_recomposes(self):
        t = _target()
        fb_old = FakeBackend()
        fb_old.width, fb_old.height = 160, 128
        fb_new = FakeBackend()
        fb_new.width, fb_new.height = 240, 240

        display, _, gt = make_display(
            fitted=True, targets=[t], screen_type="st7735s_160x128", backend=fb_old,
            backend_factory_builder=self._swap_builder(fb_old, fb_new),
        )
        display.enable()

        fake_image = _marked_image(size=(fb_old.width, fb_old.height))
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()
        assert display.get_status()["showing"] == "artwork"
        assert display._current_rendered_image is not None

        display.update_config(DialDisplayConfig(fitted=True, screen_type="st7789_240x240"))

        assert display._current_rendered_image is None
        assert display._source_artwork_key == ""
        assert display.get_status()["showing"] == "logo"

    def test_combined_screen_type_and_rotate_change_never_redisplays_stale_dims(self):
        """A single update_config() carrying both a screen_type change and a
        rotate change must never push a frame sized for the OLD backend to
        the NEW backend — the swap branch must suppress the rotate/bgr
        synchronous-redisplay branch entirely."""
        t = _target()
        fb_old = FakeBackend()
        fb_old.width, fb_old.height = 160, 128
        fb_new = FakeBackend()
        fb_new.width, fb_new.height = 240, 240

        display, _, gt = make_display(
            fitted=True, targets=[t], screen_type="st7735s_160x128", rotate=False,
            backend=fb_old, backend_factory_builder=self._swap_builder(fb_old, fb_new),
        )
        display.enable()

        fake_image = _marked_image(size=(fb_old.width, fb_old.height))
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()
        fb_new.displayed.clear()

        display.update_config(
            DialDisplayConfig(fitted=True, screen_type="st7789_240x240", rotate=True)
        )

        for img in fb_new.displayed:
            assert img.size == (fb_new.width, fb_new.height), \
                "backend must never receive a frame at the superseded backend's dims"

    def test_swap_to_backend_that_fails_open_degrades_to_noop(self):
        fb_old = FakeBackend()
        fb_new = FakeBackend(fail_open=True)

        display, _, gt = make_display(
            fitted=True, screen_type="st7735s_160x128", backend=fb_old,
            backend_factory_builder=self._swap_builder(fb_old, fb_new),
        )
        display.enable()

        status = display.update_config(
            DialDisplayConfig(fitted=True, screen_type="st7789_240x240")
        )

        assert fb_old.closed is True
        assert status["backend"] == "noop"
        assert status["backend_loaded"] is False
        assert status["last_error"] == "backend_open_failed"

    def test_get_status_includes_screen_type_and_bgr(self):
        display, fb, gt = make_display(fitted=True, screen_type="st7789_240x240", bgr=True)
        display.enable()
        status = display.get_status()
        assert status["screen_type"] == "st7789_240x240"
        assert status["bgr"] is True


# ---------------------------------------------------------------------------
# Successful enable clears any stale last_error — a successful swap must not
# keep reporting an old, unrelated failure.
# ---------------------------------------------------------------------------

class TestLastErrorClearedOnSuccessfulEnable:
    def test_stale_error_cleared_after_successful_enable(self):
        fb = FakeBackend()
        display, _, gt = make_display(fitted=True, backend=fb)
        display._last_error = "some_stale_unrelated_error"
        display._last_error_at = 12345.0

        display.enable()

        status = display.get_status()
        assert status["last_error"] == ""
        assert status["last_error_at"] is None


# ---------------------------------------------------------------------------
# Rotation — applied manager-side at display hand-off, cache stays unrotated
# ---------------------------------------------------------------------------

def _marked_image(size: tuple[int, int] = (4, 4)) -> "Image.Image":
    """A small asymmetric image so a 180° rotation is detectable pixel-wise."""
    image = Image.new("RGB", size, (0, 0, 0))
    image.putpixel((0, 0), (255, 0, 0))
    return image


class TestRotation:
    def test_rotate_true_rotates_image_before_backend_display(self):
        img = _marked_image(size=(FakeBackend.width, FakeBackend.height))

        display_off, fb_off, _ = make_display(rotate=False)
        display_off.enable()
        fb_off.displayed.clear()
        display_off.display(img)

        display_on, fb_on, _ = make_display(rotate=True)
        display_on.enable()
        fb_on.displayed.clear()
        display_on.display(img)

        expected = img.transpose(Image.ROTATE_180)
        assert list(fb_off.displayed[-1].getdata()) == list(img.getdata())
        assert list(fb_on.displayed[-1].getdata()) == list(expected.getdata())

    def test_rotate_toggle_via_update_config_redisplays_synchronously(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], fitted=True, rotate=False)
        display.enable()

        fake_image = _marked_image(size=(fb.width, fb.height))
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()
        assert display.get_status()["showing"] == "artwork"
        fb.displayed.clear()

        # Toggling rotate must take effect synchronously via update_config —
        # not via the 6s poll loop.
        with patch.object(display, "_poll_once") as mock_poll:
            status = display.update_config(DialDisplayConfig(fitted=True, rotate=True))
        mock_poll.assert_not_called()

        assert status["rotate"] is True
        expected = fake_image.transpose(Image.ROTATE_180)
        assert len(fb.displayed) == 1
        assert list(fb.displayed[-1].getdata()) == list(expected.getdata())

    def test_cached_rendered_image_stays_unrotated(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], fitted=True, rotate=True)
        display.enable()

        fake_image = _marked_image(size=(fb.width, fb.height))
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()

        assert list(display._current_rendered_image.getdata()) == list(fake_image.getdata())

    def test_get_status_includes_rotate(self):
        display, fb, gt = make_display(fitted=True, rotate=True)
        display.enable()
        assert display.get_status()["rotate"] is True


# ---------------------------------------------------------------------------
# BGR colour-order toggle — applied manager-side at display hand-off,
# alongside (and composing with) rotate; cache stays untransformed.
# ---------------------------------------------------------------------------

class TestBgr:
    def test_bgr_true_swaps_channels_before_backend_display(self):
        img = _marked_image(size=(FakeBackend.width, FakeBackend.height))

        display_off, fb_off, _ = make_display(bgr=False)
        display_off.enable()
        fb_off.displayed.clear()
        display_off.display(img)

        display_on, fb_on, _ = make_display(bgr=True)
        display_on.enable()
        fb_on.displayed.clear()
        display_on.display(img)

        expected = Image.merge("RGB", img.split()[::-1])
        assert list(fb_off.displayed[-1].getdata()) == list(img.getdata())
        assert list(fb_on.displayed[-1].getdata()) == list(expected.getdata())

    def test_rotate_and_bgr_compose_together(self):
        img = _marked_image(size=(FakeBackend.width, FakeBackend.height))

        display, fb, _ = make_display(rotate=True, bgr=True)
        display.enable()
        fb.displayed.clear()
        display.display(img)

        expected = img.transpose(Image.ROTATE_180)
        expected = Image.merge("RGB", expected.split()[::-1])
        assert list(fb.displayed[-1].getdata()) == list(expected.getdata())

    def test_bgr_toggle_via_update_config_redisplays_synchronously(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], fitted=True, bgr=False)
        display.enable()

        fake_image = _marked_image(size=(fb.width, fb.height))
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()
        fb.displayed.clear()

        with patch.object(display, "_poll_once") as mock_poll:
            status = display.update_config(DialDisplayConfig(fitted=True, bgr=True))
        mock_poll.assert_not_called()

        assert status["bgr"] is True
        expected = Image.merge("RGB", fake_image.split()[::-1])
        assert len(fb.displayed) == 1
        assert list(fb.displayed[-1].getdata()) == list(expected.getdata())

    def test_cached_rendered_image_stays_untransformed_with_bgr(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], fitted=True, bgr=True)
        display.enable()

        fake_image = _marked_image(size=(fb.width, fb.height))
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()

        assert list(display._current_rendered_image.getdata()) == list(fake_image.getdata())

    def test_get_status_includes_bgr(self):
        display, fb, gt = make_display(fitted=True, bgr=True)
        display.enable()
        assert display.get_status()["bgr"] is True


# ---------------------------------------------------------------------------
# Swap race guard — a frame composed outside the lock against a backend
# that a concurrent swap has since superseded must be dropped, not shown at
# the wrong size.
# ---------------------------------------------------------------------------

class TestSuperseededFrameRaceGuard:
    def test_mismatched_size_frame_is_dropped_not_displayed(self):
        t = _target()
        fb = FakeBackend()
        fb.width, fb.height = 240, 240
        display, _, gt = make_display(targets=[t], backend=fb)
        display.enable()
        fb.displayed.clear()

        # transform_artwork_for_panel is mocked to return an image sized for
        # a DIFFERENT backend than the one now open — simulating a
        # screen_type swap that raced with the unlocked fetch/decode/
        # transform stretch in _show_artwork().
        stale_sized_image = Image.new("RGB", (160, 128))
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=Image.new("RGB", (300, 300))), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=stale_sized_image):
            display._poll_once()

        assert fb.displayed == []
        assert display.get_status()["showing"] != "artwork"
        assert display._current_rendered_image is None


# ---------------------------------------------------------------------------
# A fresh artwork URL arriving on the poll thread must not replace an open
# secondary screen (repeat/EQ/selector/...) with the main volume surface: it
# refreshes the base that screen draws over and asks for a repaint of that
# same screen. Regression: the repeat screen used to pop back to the volume
# screen (its page dots vanishing) whenever new artwork landed.
# ---------------------------------------------------------------------------

class TestArtworkDoesNotStompSecondaryScreen:
    @staticmethod
    def _show_fresh(display):
        """Download the fresh artwork into the core and draw it, as the end
        of a poll tick does."""
        io = PollIO()
        art = display._core.fetch_artwork(
            "https://provider.example/fresh.jpg", fetch=io.fetch_artwork,
            log_limiter=io.log_limiter, eligible=io.artwork_eligible, timeout=2.0,
        )
        display._show_artwork(art)

    def _to_artwork_on_main(self, fb):
        display, _, gt = make_display(targets=[_target()], backend=fb)
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=Image.new("RGB", (300, 300))):
            display._poll_once()
        assert display.get_status()["showing"] == "artwork"
        return display

    def test_fresh_artwork_keeps_the_secondary_screen(self):
        fb = FakeBackend()
        display = self._to_artwork_on_main(fb)
        # A secondary screen is now up.
        display._screen = "repeat"
        fb.displayed.clear()
        display._overlay_signal.clear()

        with patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata2", "")), \
             patch("dial_display.decode_artwork", return_value=Image.new("RGB", (301, 301))):
            self._show_fresh(display)

        # Stays on the repeat screen; no main-surface frame pushed here.
        assert display._screen == "repeat"
        assert fb.displayed == []
        # The base is refreshed and a repaint of the current screen requested.
        assert display._current_base_image is not None
        assert display._overlay_signal.is_set()
        assert display._source_artwork_key == artwork_key("https://provider.example/fresh.jpg")

    def test_fresh_artwork_on_main_still_paints(self):
        fb = FakeBackend()
        display = self._to_artwork_on_main(fb)
        fb.displayed.clear()
        with patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata2", "")), \
             patch("dial_display.decode_artwork", return_value=Image.new("RGB", (301, 301))):
            self._show_fresh(display)
        assert display._screen == "main"
        assert fb.displayed  # the main surface is still painted


# ---------------------------------------------------------------------------
# Threading: start/stop and loop delay from loop end
# ---------------------------------------------------------------------------

class TestThreadingLifecycle:
    def test_start_stop_clean_shutdown(self):
        display, fb, gt = make_display(targets=[])
        display.start()
        time.sleep(0.05)
        thread = display._core._thread
        assert thread is not None and thread.is_alive()
        assert thread.name == "dial-core"
        assert display._subscription is not None
        display.stop()
        assert fb.closed is True
        assert not thread.is_alive()
        assert not display._repaint_thread.is_alive()
        assert display._subscription is None

    def test_a_core_the_view_was_given_is_not_started_or_stopped_by_it(self):
        from dial_core import DialCore
        core = DialCore("dial-uuid", MagicMock(return_value=[]))
        display = dd.DialDisplay(
            config=DialDisplayConfig(fitted=False), get_display_targets=MagicMock(return_value=[]),
            dial_id="dial-uuid", backend_factory=lambda: FakeBackend(), core=core,
        )
        display.start()
        assert core._thread is None
        display.stop()

    def test_the_configured_poll_interval_is_the_cores(self):
        display, fb, gt = make_display(targets=[])
        assert display._core._poll_interval == dd.DISPLAY_POLL_INTERVAL_SECONDS

    @pytest.mark.parametrize("seconds", [2, 4, 6])
    def test_the_configured_poll_interval_reaches_the_core(self, seconds):
        display, fb, gt = make_display(targets=[])
        display.update_config(DialDisplayConfig(fitted=False, poll_interval_s=seconds))
        assert display._core._poll_interval == seconds

    def test_stop_is_idempotent(self):
        display, fb, gt = make_display(targets=[])
        display.start()
        display.stop()
        display.stop()  # must not raise


# ---------------------------------------------------------------------------
# create_dial_display() factory
# ---------------------------------------------------------------------------

class TestCreateDialDisplay:
    def test_factory_wires_config_and_dial_id(self):
        cfg = MagicMock()
        cfg.display = DialDisplayConfig(fitted=False)
        cfg.uuid = "abc123"
        core = DialCore("abc123", lambda: [])
        display = create_dial_display(cfg, core)
        assert isinstance(display, DialDisplay)
        assert display._dial_id == "abc123"
        assert display._config is cfg.display
        assert display.core is core
        assert display._owns_core is False

    def test_factory_uses_noop_backend(self):
        cfg = MagicMock()
        cfg.display = DialDisplayConfig(fitted=True)
        cfg.uuid = "abc123"
        display = create_dial_display(cfg, DialCore("abc123", lambda: []))
        display.enable()
        assert display.get_status()["backend"] == "noop"


# ---------------------------------------------------------------------------
# Rate-limited logging
# ---------------------------------------------------------------------------

class TestRateLimitedLogger:
    def test_first_occurrence_logs(self):
        limiter = dd._RateLimitedLogger()
        with patch("logging.log") as mock_log:
            limiter.log(30, "keyA", "msg %s", "x")
        mock_log.assert_called_once()

    def test_repeats_suppressed_until_tenth(self):
        limiter = dd._RateLimitedLogger()
        with patch("logging.log") as mock_log:
            for _ in range(9):
                limiter.log(30, "keyA", "msg")
        assert mock_log.call_count == 1  # only the first of these 9

    def test_tenth_repeat_logs(self):
        limiter = dd._RateLimitedLogger()
        with patch("logging.log") as mock_log:
            for _ in range(10):
                limiter.log(30, "keyA", "msg")
        assert mock_log.call_count == 2  # 1st and 10th

    def test_different_key_resets_and_logs_immediately(self):
        limiter = dd._RateLimitedLogger()
        with patch("logging.log") as mock_log:
            for _ in range(5):
                limiter.log(30, "keyA", "msg")
            limiter.log(30, "keyB", "other")
        assert mock_log.call_count == 2  # first of keyA, first of keyB


# ---------------------------------------------------------------------------
# Panel dimensions — base-class defaults and per-backend pass-through to the
# compose functions in dial_display_image.py
# ---------------------------------------------------------------------------

class TestPanelDimensionDefaults:
    def test_display_backend_dims_match_default_profile(self):
        profile = get_profile(DEFAULT_PROFILE_KEY)
        assert DisplayBackend.width == profile.width
        assert DisplayBackend.height == profile.height

    def test_noop_backend_dims_match_default_profile(self):
        profile = get_profile(DEFAULT_PROFILE_KEY)
        assert NoOpBackend.width == profile.width
        assert NoOpBackend.height == profile.height

    def test_active_panel_dims_falls_back_to_default_profile_when_backend_closed(self):
        display, fb, gt = make_display(targets=[])
        # Never enabled — self._backend is still None.
        profile = get_profile(DEFAULT_PROFILE_KEY)
        assert display._active_panel_dims() == (profile.width, profile.height)


class TestActiveBackendDimsPassthrough:
    """Proves the compose call sites use the open backend's own width/height
    rather than dial_display_image's module-level PANEL_WIDTH/PANEL_HEIGHT
    globals — these would fail if the call sites regressed to the globals,
    since FakeBackend here is set to a non-default size.
    """

    def test_artwork_frame_handed_to_backend_matches_active_backend_dims(self):
        t = _target()
        fb = FakeBackend()
        fb.width = 240
        fb.height = 240
        display, _, gt = make_display(targets=[t], backend=fb)
        display.enable()
        fb.displayed.clear()

        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=Image.new("RGB", (300, 300))):
            display._poll_once()

        assert display.get_status()["showing"] == "artwork"
        assert fb.displayed[-1].size == (240, 240)

    def test_logo_frame_handed_to_backend_matches_active_backend_dims(self):
        fb = FakeBackend()
        fb.width = 240
        fb.height = 200
        display, _, gt = make_display(targets=[], backend=fb)
        display.enable()  # renders the logo immediately

        assert fb.displayed
        assert fb.displayed[-1].size == (240, 200)


# ---------------------------------------------------------------------------
# Touch activity notification — mirrors the two lines _poll_once() already
# runs when it finds playing targets present.
# ---------------------------------------------------------------------------

class TestNotifyTouchActivity:
    def test_resets_idle_timer(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display._poll_once()  # idle timer starts (no targets)
            clock.t += 5.0
            assert display.get_status()["display_idle_seconds"] == 5
            display.notify_touch_activity()
            # Applied by the repaint thread (which holds the lock), not
            # inline on the touch thread — pump one repaint to apply it.
            with display._lock:
                display._repaint_current_locked()
            assert display._idle_started_at is None
            assert display.get_status()["display_idle_seconds"] == 0

    def test_wakes_a_sleeping_display(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display._poll_once()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display._poll_once()  # asleep now
        assert display.get_status()["display_sleeping"] is True

        display.notify_touch_activity()
        with display._lock:
            display._repaint_current_locked()

        assert display.get_status()["display_sleeping"] is False
        assert fb.wake_calls == 1

    def test_does_not_disable_future_sleep_only_resets_it(self):
        """Touch resets idle, it does not disable sleep — with nothing
        playing, the next poll tick restarts the idle countdown from the
        point of the touch activity."""
        display, fb, gt = make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display._poll_once()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS - 1
            display.notify_touch_activity()
            display._poll_once()  # restarts the idle timer from here
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display._poll_once()  # crosses threshold again -> sleeps
        assert display.get_status()["display_sleeping"] is True


# ---------------------------------------------------------------------------
# _effective_overlay_locked(): merges now-playing state (artist, the
# optimistic volume readout, mute belief fallback) into the touch-published
# overlay snapshot at compose time (A.4).
# ---------------------------------------------------------------------------

class TestEffectiveOverlayMerge:
    def test_invisible_snapshot_is_returned_unchanged(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        snapshot = OverlayState(visible=False, pressed=TouchZone.UP)
        result = display._effective_overlay_locked(snapshot)
        assert result is snapshot

    def test_no_now_playing_muted_is_always_false(self):
        """With nothing playing there is no reporting-from target, so muted
        is always False regardless of the observation store or whatever the
        touch-published snapshot itself carries."""
        import dial_volume as dv
        display, fb, gt = make_display(targets=[])
        display.enable()
        dv.observe_mute_state("svc", True)
        try:
            result = display._effective_overlay_locked(OverlayState(visible=True, muted=True))
            assert result.muted is False
        finally:
            dv.observe_mute_state(None, None)

    def test_muted_is_read_from_the_observation_store_for_now_playings_service(self):
        import dial_volume as dv
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display.core.set_field("now_playing", NowPlaying("svc", "Artist", "Title", 50))
        dv.observe_mute_state("svc", True)
        try:
            result = display._effective_overlay_locked(OverlayState(visible=True))
            assert result.muted is True
        finally:
            dv.observe_mute_state(None, None)

    def test_touch_snapshots_own_muted_field_is_ignored(self):
        """The observation store wins even when the touch-published
        snapshot explicitly carries the opposite value -- the optimistic
        echo of a press lives in the store itself (see
        dial_volume.enqueue_mute()), not in any field on the snapshot
        passed in here."""
        import dial_volume as dv
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display.core.set_field("now_playing", NowPlaying("svc", "Artist", "Title", 50))
        dv.observe_mute_state("svc", False)
        try:
            result = display._effective_overlay_locked(OverlayState(visible=True, muted=True))
            assert result.muted is False
        finally:
            dv.observe_mute_state(None, None)

    def test_visible_snapshot_merges_artist_and_readout_volume(self):
        import dial_volume as dv
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display.core.set_field("now_playing", NowPlaying("svc", "The Artist", "Title", 50))
        dv.observe_master_volume("svc", 50)
        try:
            result = display._effective_overlay_locked(OverlayState(visible=True, muted=False))
            assert result.artist == "The Artist"
            assert result.title == "Title"
            assert result.volume == 50
        finally:
            dv.observe_master_volume(None, None)

    def test_visible_snapshot_merges_album(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display.core.set_field("now_playing", NowPlaying("svc", "The Artist", "Title", 50, album="The Album"))
        result = display._effective_overlay_locked(OverlayState(visible=True, muted=False))
        assert result.album == "The Album"

    def test_no_now_playing_merges_empty_artist_and_none_volume(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        result = display._effective_overlay_locked(OverlayState(visible=True, muted=False))
        assert result.artist == ""
        assert result.title == ""
        assert result.volume is None
        assert result.album == ""

    def test_visible_field_survives_the_merge_unchanged(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        result = display._effective_overlay_locked(OverlayState(visible=True))
        assert result.visible is True

    def test_pressed_comes_from_the_channel_not_the_snapshot(self):
        display, fb, gt = make_display(targets=[])
        display.enable()

        display.set_pressed(TouchZone.DOWN)
        result = display._effective_overlay_locked(OverlayState(visible=True))
        assert result.pressed == TouchZone.DOWN

        # With nothing in the channel, a snapshot that sets pressed itself
        # is overridden to None — the channel is the single source now.
        display.set_pressed(None)
        result = display._effective_overlay_locked(OverlayState(visible=True, pressed=TouchZone.UP))
        assert result.pressed is None


class TestArtistRowFallbackRichLarge:
    """Rich/large only: an idle or pending focus reads "Idle"; a playing
    appliance with no identified title yet reads "Playing"; a real artist
    (or a title with no artist) is left exactly as the poll reported it.
    Base is unaffected -- its artist row stays byte-identical."""

    @pytest.mark.parametrize("tier", ["rich", "large"])
    def test_idle_or_pending_focus_shows_idle_text(self, tier):
        content_tier = dd.CONTENT_RICH if tier == "rich" else dd.CONTENT_LARGE
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display.core.set_field("now_playing", NowPlaying("svc", "", "", 50, playing=False))
        with patch.object(display, "_layout_metrics", return_value=MagicMock(content_tier=content_tier)):
            result = display._effective_overlay_locked(OverlayState(visible=True))
        assert result.artist == dd.IDLE_ARTIST_TEXT

    @pytest.mark.parametrize("tier", ["rich", "large"])
    def test_playing_with_no_title_shows_playing_text(self, tier):
        content_tier = dd.CONTENT_RICH if tier == "rich" else dd.CONTENT_LARGE
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display.core.set_field("now_playing", NowPlaying("svc", "", "", 50, playing=True))
        with patch.object(display, "_layout_metrics", return_value=MagicMock(content_tier=content_tier)):
            result = display._effective_overlay_locked(OverlayState(visible=True))
        assert result.artist == dd.PLAYING_ARTIST_TEXT

    def test_playing_with_title_and_no_artist_stays_empty(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display.core.set_field("now_playing", NowPlaying("svc", "", "Some Title", 50, playing=True))
        with patch.object(display, "_layout_metrics", return_value=MagicMock(content_tier=dd.CONTENT_RICH)):
            result = display._effective_overlay_locked(OverlayState(visible=True))
        assert result.artist == ""

    def test_playing_with_title_and_artist_keeps_the_real_artist(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display.core.set_field("now_playing", NowPlaying("svc", "Real Artist", "Some Title", 50, playing=True))
        with patch.object(display, "_layout_metrics", return_value=MagicMock(content_tier=dd.CONTENT_LARGE)):
            result = display._effective_overlay_locked(OverlayState(visible=True))
        assert result.artist == "Real Artist"

    def test_base_tier_artist_row_is_unaffected(self):
        # make_display defaults to the base (160x128) tier -- no patch
        # needed, this is the tier's own natural resolution.
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display.core.set_field("now_playing", NowPlaying("svc", "", "", 50, playing=False))
        result = display._effective_overlay_locked(OverlayState(visible=True))
        assert result.artist == ""


# ---------------------------------------------------------------------------
# Touch overlay — leaf-locked snapshot, dedicated repaint executor, and the
# non-composited-state notification for the touch side.
#
# LOCK ORDER under test: self._lock may enclose the SPI/backend push.
# self._overlay_snapshot_lock is acquired standalone by set_overlay() and is
# NEVER acquired while self._lock is held (see dial_display.py's __init__
# docstring comment for the full statement). The touch thread never takes
# self._lock at all.
# ---------------------------------------------------------------------------

class TestOverlaySetAndRepaintExecutor:
    def test_set_overlay_never_acquires_self_lock(self):
        """The touch-side entry point (set_overlay) must never touch
        self._lock — that is what keeps touch cadence off the lock a slow
        SPI frame push can hold for a while."""
        display, fb, gt = make_display(targets=[])
        display.enable()

        # threading.Lock instances are C objects with read-only attributes
        # (acquire can't be monkeypatched in place), so swap in a wrapper
        # that records acquisitions and delegates to a real lock.
        class _SpyLock:
            def __init__(self):
                self._real = threading.Lock()
                self.acquire_calls = 0

            def acquire(self, *args, **kwargs):
                self.acquire_calls += 1
                return self._real.acquire(*args, **kwargs)

            def release(self):
                return self._real.release()

            def __enter__(self):
                self.acquire()
                return self

            def __exit__(self, *exc_info):
                self.release()

        spy_lock = _SpyLock()
        display._lock = spy_lock
        display.set_overlay(OverlayState(visible=True, pressed=TouchZone.UP))

        assert spy_lock.acquire_calls == 0

    def test_no_touch_thread_entry_point_acquires_self_lock(self):
        """Every method the touch thread calls synchronously must be
        lock-free — not just set_overlay.

        The touch thread dispatches its callbacks inline, so if any of these
        took self._lock it would block behind a whole SPI frame push and
        delay the volume step the user just asked for. Spying on only one
        entry point previously let notify_touch_activity() take the lock
        while the suite stayed green.
        """
        display, fb, gt = make_display(targets=[])
        display.enable()

        class _SpyLock:
            def __init__(self):
                self._real = threading.Lock()
                self.acquire_calls = 0

            def acquire(self, *args, **kwargs):
                self.acquire_calls += 1
                return self._real.acquire(*args, **kwargs)

            def release(self):
                return self._real.release()

            def __enter__(self):
                self.acquire()
                return self

            def __exit__(self, *exc_info):
                self.release()

        spy_lock = _SpyLock()
        display._lock = spy_lock

        # Everything dial_main wires to the touch callbacks.
        display.set_overlay(OverlayState(visible=True, pressed=TouchZone.UP))
        display.notify_touch_activity()
        display.set_overlay(OverlayState(visible=False))
        display.set_pressed(TouchZone.UP)
        display.set_pressed(None)
        display.noncomposited_generation()

        assert spy_lock.acquire_calls == 0, (
            "a touch-thread entry point acquired the display lock"
        )

    def test_touch_activity_wakes_via_repaint_thread(self):
        """notify_touch_activity() defers the wake rather than doing it
        inline, so the wake must still actually happen."""
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display._display_sleeping = True
            display._idle_started_at = 123.0

        display.notify_touch_activity()
        # Nothing applied yet — the touch thread only set a flag.
        assert display._display_sleeping is True

        with display._lock:
            display._repaint_current_locked()
        assert display._display_sleeping is False
        assert display._idle_started_at is None

    def test_rapid_signals_coalesce_to_one_repaint_of_newest_snapshot(self):
        # A playing target, not an idle one: the idle screen has its own
        # compose_idle() path with no pressed-overlay content at
        # all, so this coalescing check needs the ordinary now-playing
        # overlay path to have a pressed zone worth asserting on.
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        _poll_with_artwork(display, fb)
        # Start the coalescing measurement from a clean slate: the poll
        # above may itself have left a signal pending for its own new frame.
        display._overlay_signal.clear()

        done = threading.Event()
        call_count = {"n": 0}
        orig_repaint = display._repaint_current_locked

        def counting_repaint():
            call_count["n"] += 1
            orig_repaint()
            done.set()

        display._repaint_current_locked = counting_repaint
        repaint_thread = threading.Thread(target=display._repaint_run, daemon=True)
        repaint_thread.start()
        try:
            with patch.object(
                display._compositor, "compose", wraps=display._compositor.compose
            ) as mock_compose:
                display.set_overlay(OverlayState(visible=True))
                # Several rapid signals before the repaint thread gets a
                # chance to wake — must coalesce into exactly one repaint,
                # of the LAST (newest) pressed value published.
                for zone in (TouchZone.MUTE, TouchZone.DOWN, TouchZone.UP):
                    display.set_pressed(zone)

                assert done.wait(timeout=2.0), "repaint thread never woke"
                # A window for a wrongly-duplicated repaint to also land.
                time.sleep(0.15)

                assert mock_compose.call_count == 1
                overlay_used = mock_compose.call_args.kwargs["overlay"]
                assert overlay_used.pressed == TouchZone.UP
        finally:
            display._repaint_stop_event.set()
            display._overlay_signal.set()
            repaint_thread.join(timeout=1.0)

        assert call_count["n"] == 1

    def test_poll_driven_repaint_keeps_visible_overlay(self):
        """A poll-driven repaint (e.g. a track change) while an overlay is
        visible must recompose it back in, not wipe it."""
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        display.set_overlay(OverlayState(visible=True))
        display.set_pressed(TouchZone.UP)

        fake_image = Image.new("RGB", (128, 160))
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image), \
             patch.object(
                 display._compositor, "compose", wraps=display._compositor.compose
             ) as mock_compose:
            display._poll_once()  # new artwork -> a real poll-driven push

        assert display.get_status()["showing"] == "artwork"
        assert mock_compose.called
        overlay_used = mock_compose.call_args.kwargs["overlay"]
        assert overlay_used.visible is True
        assert overlay_used.pressed == TouchZone.UP

    def test_repaint_start_stop_via_public_lifecycle(self):
        """display.start()/stop() manage the repaint thread alongside the
        existing poll thread."""
        display, fb, gt = make_display(targets=[])
        display.start()
        try:
            assert display._repaint_thread is not None
            assert display._repaint_thread.is_alive()
        finally:
            display.stop()
        assert not display._repaint_thread.is_alive()


# ---------------------------------------------------------------------------
# Non-composited-state notification — _clear_locked()/_sleep_locked() must
# only set an Event/generation, never call into the touch session
# synchronously (that would nest the overlay leaf lock inside self._lock).
# ---------------------------------------------------------------------------

class TestNoncompositedNotification:
    def test_clear_locked_bumps_generation_and_sets_event(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        gen_before = display.noncomposited_generation()
        display._noncomposited_event.clear()

        with display._lock:
            display._clear_locked()

        assert display.noncomposited_generation() == gen_before + 1
        assert display._noncomposited_event.is_set()

    def test_sleep_locked_bumps_generation_and_sets_event(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        gen_before = display.noncomposited_generation()
        display._noncomposited_event.clear()

        with display._lock:
            display._sleep_locked()

        assert display.noncomposited_generation() == gen_before + 1
        assert display._noncomposited_event.is_set()

    def test_mark_noncomposited_locked_only_mutates_its_own_state(self):
        """_mark_noncomposited_locked() must be a pure state update — it must
        never call out to anything touch-related (there is nothing for it to
        call: DialDisplay holds no reference to any touch object at all,
        which is what keeps the leaf lock from ever nesting inside
        self._lock from this direction)."""
        display, fb, gt = make_display(targets=[])
        display.enable()
        assert not hasattr(display, "_touch_source")
        assert not hasattr(display, "_touch_callback")

        with display._lock:
            display._mark_noncomposited_locked()
            display._mark_noncomposited_locked()

        assert display.noncomposited_generation() == 2


# ---------------------------------------------------------------------------
# "Always show controls" held-visible overlay: persistent_overlay_shown(),
# the "a controllable appliance is shown" gate (self._now_playing is not
# None) that _display_locked's base image no longer needs to track, and the
# forced-visible merge in _effective_overlay_locked().
# ---------------------------------------------------------------------------

def _poll_with_artwork(display, fb):
    """Drive one poll iteration that lands on identified artwork, faking out
    the network/decode/transform steps exactly like TestRotation does."""
    fake_image = _marked_image(size=(fb.width, fb.height))
    with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
         patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
         patch("dial_display.decode_artwork", return_value=fake_image), \
         patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
        display._poll_once()


class TestDeviceSwitchTransitionFrame:
    """Item 10: switching directly from one playing appliance to another
    must not leave the previous one's artwork on screen under the new
    appliance's name — see _maybe_show_transition()/_show_transition_locked()."""

    def _target_pair(self):
        aid_a, aid_b = "a" * 20, "b" * 20
        ta = _target(name="A", service_name="A", appliance_id=aid_a, auth="authorized", playing_since=1.0)
        tb = _target(name="B", service_name="B", appliance_id=aid_b, auth="authorized", playing_since=2.0)
        return ta, tb

    def test_switching_between_two_playing_appliances_pushes_a_grey_frame_first(self):
        ta, tb = self._target_pair()
        display, fb, gt = make_display(targets=[ta])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        before = len(fb.displayed)

        gt.return_value = [tb]
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()

        pushed = fb.displayed[before:]
        assert len(pushed) == 2
        transition_frame, logo_frame = pushed
        assert transition_frame.size == logo_frame.size
        cx, cy = transition_frame.width // 2, transition_frame.height // 2
        assert transition_frame.getpixel((cx, cy))[:3] == (32, 32, 32)

    def test_showing_is_waiting_while_the_new_logo_has_not_landed_yet(self):
        ta, tb = self._target_pair()
        display, fb, gt = make_display(targets=[ta])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()

        gt.return_value = [tb]
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)), \
             patch.object(display, "show_logo") as mock_show_logo:
            display._poll_once()
        mock_show_logo.assert_called_once()
        assert display._showing == "waiting"

    def test_no_transition_frame_when_reporting_id_unchanged(self):
        ta, _ = self._target_pair()
        display, fb, gt = make_display(targets=[ta])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        before = len(fb.displayed)
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        pushed = fb.displayed[before:]
        assert len(pushed) <= 1  # at most the (deduped-away) logo re-render, never a transition

    def test_no_transition_frame_on_the_very_first_poll(self):
        # enable() already rendered the logo; the first poll's own
        # show_logo() call dedupes against it (still "logo") -- no stale
        # artwork to guard against on a fresh start, so nothing more is
        # pushed at all, let alone a transition frame.
        ta, _ = self._target_pair()
        display, fb, gt = make_display(targets=[ta])
        display.enable()
        before = len(fb.displayed)
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        pushed = fb.displayed[before:]
        assert len(pushed) == 0

    def test_no_transition_frame_when_switching_to_nothing_playing(self):
        ta, _ = self._target_pair()
        display, fb, gt = make_display(targets=[ta])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        before = len(fb.displayed)
        gt.return_value = []
        display._poll_once()
        pushed = fb.displayed[before:]
        assert len(pushed) == 0  # still deduped against the same logo -- no transition either

    def test_show_transition_locked_is_a_noop_when_backend_closed(self):
        display, fb, gt = make_display(targets=[])
        with display._lock:
            display._show_transition_locked()
        assert fb.displayed == []


class TestLogoOverlayGating:
    """A track change swaps the base image to the placeholder logo and
    clears artist/title, but must not by itself drop a held overlay: the
    gate is "a controllable appliance is shown" (self._now_playing is not
    None), which stays true across that swap. Only the genuinely idle logo
    (nothing playing, self._now_playing is None) is bare."""

    def test_placeholder_logo_while_playing_keeps_held_overlay(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.core.snapshot().now_playing is not None
        with display._lock:
            # Simulate the track-change base-image swap to the placeholder
            # logo — self._now_playing is left as-is, exactly as the poll
            # does when it clears artist/title but keeps reporting a
            # playing appliance.
            display._render_logo_locked()
        assert display.get_status()["showing"] == "logo"
        assert display.persistent_overlay_shown() is True
        result = display._effective_overlay_locked(OverlayState(visible=False))
        assert result.visible is True

    def test_idle_logo_with_nothing_playing_is_bare(self):
        display, fb, gt = make_display(targets=[], always_show_controls=True)
        display.enable()
        assert display.core.snapshot().now_playing is None
        assert display.get_status()["showing"] == "logo"
        assert display.persistent_overlay_shown() is False
        result = display._effective_overlay_locked(OverlayState(visible=False))
        assert result.visible is False

    def test_redisplay_current_locked_renders_logo_when_nothing_cached(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display._redisplay_current_locked()
        assert display.get_status()["showing"] == "logo"

    def test_clear_sleep_disable_swap_leave_no_overlay_held(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.persistent_overlay_shown() is True
        with display._lock:
            display._clear_locked()
        assert display.persistent_overlay_shown() is False

        display2, fb2, gt2 = make_display(targets=[t], always_show_controls=True)
        display2.enable()
        _poll_with_artwork(display2, fb2)
        with display2._lock:
            display2._sleep_locked()
        assert display2.persistent_overlay_shown() is False

        display3, fb3, gt3 = make_display(targets=[t], always_show_controls=True)
        display3.enable()
        _poll_with_artwork(display3, fb3)
        with display3._lock:
            display3._disable_locked()
        assert display3.persistent_overlay_shown() is False

    def test_swap_backend_locked_reopens_on_the_main_screen(self):
        t = _target()
        fb_old = FakeBackend()
        fb_new = FakeBackend()

        def builder(screen_type):
            return lambda: fb_new

        display, _, gt = make_display(
            targets=[t], backend=fb_old, backend_factory_builder=builder,
        )
        display.enable()
        _poll_with_artwork(display, fb_old)
        assert display.get_status()["showing"] == "artwork"
        with display._lock:
            display._rebuild_backend_factory_locked("st7789_240x240")
            display._swap_backend_locked()
        # The swap drops the cached frame and reopens on the logo — the
        # reopened backend has nothing to base a "showing artwork" claim on.
        assert display.get_status()["showing"] == "logo"


class TestPersistentOverlayShown:
    def test_false_when_always_show_controls_off(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], always_show_controls=False)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.persistent_overlay_shown() is False

    def test_true_when_on_and_artwork_shown(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.persistent_overlay_shown() is True

    def test_false_over_the_logo(self):
        display, fb, gt = make_display(targets=[], always_show_controls=True)
        display.enable()
        assert display.get_status()["showing"] == "logo"
        assert display.persistent_overlay_shown() is False

    def test_false_when_backend_not_open(self):
        display, fb, gt = make_display(fitted=False, always_show_controls=True)
        assert display.persistent_overlay_shown() is False

    def test_false_when_sleeping(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.persistent_overlay_shown() is True
        with display._lock:
            display._sleep_locked()
        assert display.persistent_overlay_shown() is False

    def test_false_after_clear(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.persistent_overlay_shown() is True
        with display._lock:
            display._clear_locked()
        assert display.persistent_overlay_shown() is False

    def test_get_status_includes_always_show_controls(self):
        display, fb, gt = make_display(always_show_controls=True)
        display.enable()
        assert display.get_status()["always_show_controls"] is True


class TestHideControls:
    """Item 9: tapping the artwork hides the bands for CONTROLS_HIDE_
    SECONDS — see hide_controls()/_controls_hidden()."""

    def test_hide_controls_sets_deadline_and_signals(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        display._overlay_signal.clear()
        with patch("dial_display.time.monotonic", return_value=1000.0):
            display.hide_controls()
        assert display._controls_hidden_until == pytest.approx(1000.0 + dd.CONTROLS_HIDE_SECONDS)
        assert display._overlay_signal.is_set()

    def test_persistent_overlay_shown_false_during_window_true_after(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.persistent_overlay_shown() is True
        with patch("dial_display.time.monotonic", return_value=1000.0):
            display.hide_controls()
        with patch("dial_display.time.monotonic", return_value=1000.0 + dd.CONTROLS_HIDE_SECONDS - 0.1):
            assert display.persistent_overlay_shown() is False
        with patch("dial_display.time.monotonic", return_value=1000.0 + dd.CONTROLS_HIDE_SECONDS + 0.1):
            assert display.persistent_overlay_shown() is True

    def test_set_overlay_visible_ends_the_window_early(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.hide_controls()
        assert display._controls_hidden() is True
        display.set_overlay(dd.OverlayState(visible=True))
        assert display._controls_hidden() is False

    def test_set_overlay_invisible_does_not_end_the_window(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.hide_controls()
        display.set_overlay(dd.OverlayState(visible=False))
        assert display._controls_hidden() is True

    def test_frames_composed_during_the_window_have_no_overlay(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        held_frame = fb.displayed[-1]

        display.hide_controls()
        with display._lock:
            display._repaint_current_locked()
        hidden_frame = fb.displayed[-1]

        bare = display._compositor.compose(
            hidden_frame, hidden_frame.width, hidden_frame.height,
            rotate=False, bgr=False, is_artwork=False, overlay=None,
        )
        assert list(hidden_frame.getdata()) == list(bare.getdata())
        assert list(hidden_frame.getdata()) != list(held_frame.getdata())

    def test_tick_controls_hidden_signals_once_at_expiry(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with patch("dial_display.time.monotonic", return_value=1000.0):
            display.hide_controls()
        display._overlay_signal.clear()
        with patch("dial_display.time.monotonic", return_value=1000.0 + dd.CONTROLS_HIDE_SECONDS + 0.1):
            display._tick_controls_hidden()
        assert display._overlay_signal.is_set()
        assert display._controls_hidden_until == 0.0
        # One-shot: a second call after firing does not re-signal.
        display._overlay_signal.clear()
        with patch("dial_display.time.monotonic", return_value=1000.0 + dd.CONTROLS_HIDE_SECONDS + 0.2):
            display._tick_controls_hidden()
        assert not display._overlay_signal.is_set()

    def test_tick_controls_hidden_noop_before_deadline(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with patch("dial_display.time.monotonic", return_value=1000.0):
            display.hide_controls()
        display._overlay_signal.clear()
        with patch("dial_display.time.monotonic", return_value=1000.0 + 1.0):
            display._tick_controls_hidden()
        assert not display._overlay_signal.is_set()


# ---------------------------------------------------------------------------
# The artwork reveal: on the rich and large tiers the bands' chrome slides
# off the panel (the top band up, the bottom band down, the inter-band text
# fading, the artwork under them staying put) whenever the controls are due
# to go: an artwork tap in either controls mode, or the touch session's own
# dismiss. The slide starts on the repaint thread at the first frame that
# finds them due to go, ends on exactly the bare frame the hide window holds,
# and slides back in the same way whenever the controls return on the same
# screen (window expiry, a reveal tap, the first touch), a change of mind
# mid-slide continuing from where it had got. The base tier keeps its
# instant hide and show; the compact tier has no bands at all.
# ---------------------------------------------------------------------------

def _repaint(display) -> None:
    with display._lock:
        display._repaint_current_locked()


def _bare_frame(display, fb):
    return display._compositor.compose(
        display._current_base_image, fb.width, fb.height,
        rotate=False, bgr=False, is_artwork=False, overlay=None,
    )


def _pixels(image):
    return list(image.getdata())


def _rows_equal(a, b, box, tol=0):
    """Whether the *box* region of two same-size frames agrees within *tol*
    levels per channel."""
    ca, cb = a.crop(box), b.crop(box)
    return all(
        abs(x - y) <= tol
        for pa, pb in zip(ca.getdata(), cb.getdata())
        for x, y in zip(pa, pb)
    )


class TestArtworkReveal:
    def _shown_settled(self, display, fb):
        """Touch mode: reveal the controls and let the slide-in finish, on a
        private clock well before the tests' own; returns the settled frame."""
        clock = _FakeClock(500.0)
        with patch_monotonic(clock):
            display.set_overlay(OverlayState(visible=True))
            _repaint(display)
            clock.t += dd.REVEAL_ANIMATION_S + 0.1
            _repaint(display)
            display._tick_controls_reveal()
        assert display._reveal_started_at == 0.0
        return fb.displayed[-1]

    def _rich(self, always_show=True):
        display, fb, gt = _make_rich_display(targets=[_target()], always_show_controls=always_show)
        display.enable()
        _poll_with_artwork(display, fb)
        with display._lock:
            assert display._layout_metrics().content_tier == "rich"
        band_h = layout_for(fb.width, fb.height, metrics=display._layout_metrics()).top_band[3]
        return display, fb, gt, band_h

    def test_hide_controls_opens_the_window_and_stamps_nothing(self):
        display, fb, gt, _ = self._rich()
        display._overlay_signal.clear()
        with patch("dial_display.time.monotonic", return_value=1000.0):
            display.hide_controls()
        assert display._controls_hidden_until == pytest.approx(1000.0 + dd.CONTROLS_HIDE_SECONDS)
        assert display._reveal_started_at == 0.0
        assert display._overlay_signal.is_set()

    def test_hide_controls_is_a_noop_off_main(self):
        display, fb, gt, _ = self._rich()
        display._screen = "selector"
        display.hide_controls()
        assert display._controls_hidden_until == 0.0

    def test_ease_and_progress(self):
        assert dd._reveal_ease(0.0) == 0.0
        assert dd._reveal_ease(1.0) == 1.0
        assert dd._reveal_ease(0.5) == 0.5
        assert dd._reveal_ease(0.25) == 0.15625
        values = [dd._reveal_ease(t / 20) for t in range(21)]
        assert values == sorted(values)

        display, fb, gt, _ = self._rich()
        # No slide stamped yet: never animating.
        assert display._reveal_progress(1000.0) == 0.0
        display._reveal_started_at = 1000.0
        assert display._reveal_progress(1000.0) == 0.0
        assert display._reveal_progress(1000.0 + dd.REVEAL_ANIMATION_S / 2.0) == pytest.approx(0.5)
        assert display._reveal_progress(1000.0 + dd.REVEAL_ANIMATION_S) == 0.0

    def test_slide_starts_on_the_first_compose_after_a_tap_always_show(self):
        display, fb, gt, band_h = self._rich()
        held_frame = fb.displayed[-1]
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            # The first slide frame is the ordinary frame at progress 0,
            # and the slide is stamped by the compose, not by the tap.
            assert _pixels(fb.displayed[-1]) == _pixels(held_frame)
            assert display._reveal_started_at == 1000.0
            assert display._reveal_frame_at >= 1000.0

            clock.t = 1000.0 + dd.REVEAL_ANIMATION_S / 2.0
            _repaint(display)
            mid = fb.displayed[-1]
            bare = _bare_frame(display, fb)
            dy = round(0.5 * band_h)
            assert _pixels(mid) != _pixels(held_frame)
            assert _pixels(mid) != _pixels(bare)
            assert _rows_equal(mid, bare, (0, band_h - dy, fb.width, band_h))
            # The artwork under the band that is still there has not moved.
            assert _rows_equal(mid, held_frame, (0, 0, 4, band_h - dy), tol=2)
            assert _rows_equal(mid, held_frame, (0, fb.height - band_h + dy, 4, fb.height), tol=2)

            clock.t = 1000.0 + dd.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            assert _pixels(fb.displayed[-1]) == _pixels(bare)

            # The window's expiry slides the controls back in: the first
            # frame is the bare frame again, the last is the controls.
            t_expiry = 1000.0 + dd.CONTROLS_HIDE_SECONDS + 0.1
            clock.t = t_expiry
            display._tick_controls_hidden()
            _repaint(display)
            assert _pixels(fb.displayed[-1]) == _pixels(bare)
            assert display._reveal_started_at == t_expiry
            assert display._reveal_sliding_in is True

            clock.t = t_expiry + dd.REVEAL_ANIMATION_S / 2.0
            _repaint(display)
            assert _pixels(fb.displayed[-1]) != _pixels(bare)
            assert _pixels(fb.displayed[-1]) != _pixels(held_frame)
            assert display._reveal_progress(clock.t) == pytest.approx(0.5)

            clock.t = t_expiry + dd.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            assert _pixels(fb.displayed[-1]) == _pixels(held_frame)

    def test_slide_starts_after_a_tap_in_touch_mode(self):
        display, fb, gt, band_h = self._rich(always_show=False)
        shown_frame = self._shown_settled(display, fb)
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            # The window overrides the visible snapshot; the slide has begun.
            assert _pixels(fb.displayed[-1]) == _pixels(shown_frame)
            assert display._reveal_started_at == 1000.0

            clock.t = 1000.05
            display.set_overlay(OverlayState(visible=False))
            clock.t = 1000.0 + dd.REVEAL_ANIMATION_S / 2.0
            _repaint(display)
            bare = _bare_frame(display, fb)
            assert _pixels(fb.displayed[-1]) != _pixels(shown_frame)
            assert _pixels(fb.displayed[-1]) != _pixels(bare)

            clock.t = 1000.0 + dd.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            assert _pixels(fb.displayed[-1]) == _pixels(bare)

            clock.t = 1000.0 + dd.CONTROLS_HIDE_SECONDS + 0.1
            display._tick_controls_hidden()
            _repaint(display)
            # The session is hidden: no bands come back when the window ends.
            assert _pixels(fb.displayed[-1]) == _pixels(bare)

    def test_touch_dismiss_slides_without_a_window(self):
        display, fb, gt, band_h = self._rich(always_show=False)
        shown_frame = self._shown_settled(display, fb)
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.set_overlay(OverlayState(visible=False))
            _repaint(display)
            assert display._controls_hidden_until == 0.0
            assert display._reveal_started_at == 1000.0
            assert _pixels(fb.displayed[-1]) == _pixels(shown_frame)

            clock.t = 1000.0 + dd.REVEAL_ANIMATION_S / 2.0
            _repaint(display)
            bare = _bare_frame(display, fb)
            assert _pixels(fb.displayed[-1]) != _pixels(shown_frame)
            assert _pixels(fb.displayed[-1]) != _pixels(bare)

            clock.t = 1000.0 + dd.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            assert _pixels(fb.displayed[-1]) == _pixels(bare)

    @pytest.mark.parametrize("always_show", [True, False])
    def test_base_tier_hides_instantly_in_both_modes(self, always_show):
        display, fb, gt = make_display(targets=[_target()], always_show_controls=always_show)
        display.enable()
        _poll_with_artwork(display, fb)
        display.set_overlay(OverlayState(visible=True))
        _repaint(display)
        with patch("dial_display.time.monotonic", return_value=1000.0):
            display.hide_controls()
            _repaint(display)
        assert _pixels(fb.displayed[-1]) == _pixels(_bare_frame(display, fb))
        assert display._reveal_started_at == 0.0

    def test_compact_tier_never_hides_or_slides(self):
        display, fb, gt = _make_compact_display(targets=[_target()], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        display.hide_controls()
        assert display._controls_hidden_until == 0.0
        assert display._reveal_started_at == 0.0

    @pytest.mark.parametrize("always_show", [True, False])
    def test_reveal_tap_slides_the_controls_in(self, always_show):
        display, fb, gt, band_h = self._rich(always_show=always_show)
        held_frame = self._shown_settled(display, fb) if not always_show else fb.displayed[-1]
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            clock.t = 1000.0 + dd.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            bare = _bare_frame(display, fb)
            assert _pixels(fb.displayed[-1]) == _pixels(bare)
            display._tick_controls_reveal()
            assert display._reveal_started_at == 0.0

            # The reveal tap ends the window; the frame that finds the
            # controls back starts the slide and equals the bare frame.
            clock.t = 1002.0
            display.set_overlay(OverlayState(visible=True))
            assert display._controls_hidden_until == 0.0
            _repaint(display)
            assert display._reveal_started_at == 1002.0
            assert display._reveal_sliding_in is True
            assert _pixels(fb.displayed[-1]) == _pixels(bare)

            clock.t = 1002.0 + dd.REVEAL_ANIMATION_S / 2.0
            _repaint(display)
            mid = fb.displayed[-1]
            dy = round(0.5 * band_h)
            assert _pixels(mid) != _pixels(bare)
            assert _pixels(mid) != _pixels(held_frame)
            assert _rows_equal(mid, bare, (0, band_h - dy, fb.width, band_h))

            clock.t = 1002.0 + dd.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            assert _pixels(fb.displayed[-1]) == _pixels(held_frame)

    def test_progress_runs_backwards_while_sliding_in(self):
        display, fb, gt, _ = self._rich()
        display._reveal_started_at = 1000.0
        display._reveal_sliding_in = True
        assert display._reveal_progress(1000.0) == 1.0
        assert display._reveal_progress(1000.0 + dd.REVEAL_ANIMATION_S / 2.0) == pytest.approx(0.5)
        assert display._reveal_progress(1000.0 + 0.25 * dd.REVEAL_ANIMATION_S) == pytest.approx(
            1.0 - dd._reveal_ease(0.25))
        assert display._reveal_progress(1000.0 + dd.REVEAL_ANIMATION_S) == 0.0

    def test_reveal_tap_mid_slide_out_turns_around_without_a_jump(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            clock.t = 1000.2
            _repaint(display)
            out_progress = display._reveal_progress(1000.2)
            out_frame = fb.displayed[-1]
            assert display._reveal_sliding_in is False

            # The tap lands; the next frame continues from the same place.
            display.set_overlay(OverlayState(visible=True))
            assert display._reveal_started_at == 1000.0  # untouched by the tap
            _repaint(display)
            assert display._reveal_sliding_in is True
            assert display._reveal_progress(1000.2) == pytest.approx(out_progress)
            assert _pixels(fb.displayed[-1]) == _pixels(out_frame)

            # Then it runs back the way it came, over the remaining time.
            clock.t = 1000.2 + 0.1
            assert display._reveal_progress(clock.t) < out_progress
            # The reversed slide ends after the time the slide-out had run.
            assert display._reveal_started_at + dd.REVEAL_ANIMATION_S == pytest.approx(1000.2 + 0.2)
            clock.t = 1000.2 + 0.2 + 0.01
            _repaint(display)
            assert display._reveal_progress(clock.t) == 0.0

    def test_hide_mid_slide_in_turns_around_without_a_jump(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            clock.t = 1000.0 + dd.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            clock.t = 1002.0
            display.set_overlay(OverlayState(visible=True))
            _repaint(display)
            clock.t = 1002.0 + 0.1
            _repaint(display)
            in_progress = display._reveal_progress(clock.t)
            in_frame = fb.displayed[-1]
            assert 0.0 < in_progress < 1.0
            assert display._reveal_sliding_in is True

            display.hide_controls()
            _repaint(display)
            assert display._reveal_sliding_in is False
            assert display._reveal_progress(clock.t) == pytest.approx(in_progress)
            assert _pixels(fb.displayed[-1]) == _pixels(in_frame)

    def test_slide_start_is_never_zero(self):
        display, fb, gt, _ = self._rich()
        with display._lock:
            display._controls_last = True
            display._reveal_started_at = 0.0
            animating, progress = display._advance_reveal_locked(0.0, False, True)
        assert display._reveal_started_at != 0.0
        assert animating is True and progress == 0.0

    def test_first_frame_after_a_screen_change_does_not_slide(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.open_selector()
            _repaint(display)
            assert display._controls_last is None
            display.close_list()
            clock.t = 1000.2
            _repaint(display)
            assert display._screen == "main"
            assert display._reveal_started_at == 0.0
            assert display._controls_last is True

    def test_first_touch_after_a_screen_change_in_touch_mode_slides_in(self):
        display, fb, gt, _ = self._rich(always_show=False)
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.open_selector()
            _repaint(display)
            display.close_list()
            _repaint(display)
            assert display._reveal_started_at == 0.0
            assert display._controls_last is False
            clock.t = 1001.0
            display.set_overlay(OverlayState(visible=True))
            _repaint(display)
            assert display._reveal_started_at == 1001.0
            assert display._reveal_sliding_in is True

    def test_first_frame_after_waking_does_not_slide(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            with display._lock:
                display._sleep_locked()
            assert display._controls_last is None
            with display._lock:
                display._wake_locked()
            clock.t = 1001.0
            _repaint(display)
            assert display._reveal_started_at == 0.0
            assert display._controls_last is True

    def test_first_frame_after_the_idle_screen_does_not_slide(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            gt.return_value = []
            display._poll_once()
            _repaint(display)
            assert display._controls_last is None
            clock.t = 1001.0
            gt.return_value = [_target()]
            _poll_with_artwork(display, fb)
            assert display._reveal_started_at == 0.0
            assert display._controls_last is True

    @pytest.mark.parametrize("maker", ["base", "compact"])
    def test_base_and_compact_tiers_snap_back(self, maker):
        make = make_display if maker == "base" else _make_compact_display
        display, fb, gt = make(targets=[_target()], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        held_frame = fb.displayed[-1]
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.set_overlay(OverlayState(visible=True))
            display.hide_controls()
            _repaint(display)
            clock.t = 1000.0 + dd.CONTROLS_HIDE_SECONDS + 0.1
            display._tick_controls_hidden()
            _repaint(display)
            assert display._reveal_started_at == 0.0
            assert display._controls_last is None
            display.set_overlay(OverlayState(visible=True))
            _repaint(display)
            assert display._reveal_started_at == 0.0
            if maker == "base":
                assert _pixels(fb.displayed[-1]) == _pixels(held_frame)

    def test_frame_gap_is_short_and_the_deadline_uses_it(self):
        assert dd.REVEAL_FRAME_GAP_S == 0.001
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            display._reveal_frame_at = 1000.2
            clock.t = 1000.2
            assert display._next_repaint_deadline() == pytest.approx(1000.2 + 0.001)

    def test_deadline_paces_from_the_end_of_the_frame(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            display._reveal_frame_at = 1000.03
            clock.t = 1000.03
            assert display._next_repaint_deadline() == pytest.approx(1000.03 + dd.REVEAL_FRAME_GAP_S)

            # The slot has passed: at once, with no margin added to the gap.
            clock.t = 1000.1
            assert display._next_repaint_deadline() == pytest.approx(1000.1)

            # Near the end the slide's own end wins over the next slot.
            display._reveal_frame_at = 1000.5495
            clock.t = 1000.5495
            assert display._next_repaint_deadline() == pytest.approx(1000.0 + dd.REVEAL_ANIMATION_S + 0.005)

            # The last slide frame finished sending after the end: the
            # settled frame is due at once, never at the next unrelated wake.
            display._reveal_frame_at = 1000.56
            clock.t = 1000.56
            assert display._next_repaint_deadline() == pytest.approx(1000.56)

            # Once the end-of-slide tick has settled it, only the window's
            # end is left.
            display._tick_controls_reveal()
            assert display._reveal_started_at == 0.0
            assert display._next_repaint_deadline() == pytest.approx(1000.0 + dd.CONTROLS_HIDE_SECONDS + 0.005)

    def test_tick_signals_each_frame_and_once_at_the_end(self):
        display, fb, gt, _ = self._rich(always_show=False)
        # Showing the controls slides them in; that slide must be over on a
        # fake clock too, or a real clock reading later than the one below
        # would leave it apparently still running and the dismiss would turn
        # it round instead of starting afresh.
        self._shown_settled(display, fb)
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.set_overlay(OverlayState(visible=False))
            _repaint(display)
            assert display._reveal_started_at == 1000.0

            # A dismiss slide has no window; the tick must not end it early.
            display._overlay_signal.clear()
            clock.t = 1000.1
            display._tick_controls_reveal()
            assert display._overlay_signal.is_set()
            assert display._reveal_started_at == 1000.0

            display._overlay_signal.clear()
            clock.t = 1000.0 + dd.REVEAL_ANIMATION_S + 0.01
            display._tick_controls_reveal()
            assert display._overlay_signal.is_set()
            assert display._reveal_started_at == 0.0

            display._overlay_signal.clear()
            clock.t = 1000.0 + dd.REVEAL_ANIMATION_S + 0.05
            display._tick_controls_reveal()
            assert not display._overlay_signal.is_set()

    def test_second_tap_starts_a_new_slide_from_zero(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            clock.t = 1000.2
            display.set_overlay(OverlayState(visible=True))
            assert display._controls_hidden_until == 0.0
            _repaint(display)
            assert display._reveal_sliding_in is True

            clock.t = 1001.0
            _repaint(display)
            display.hide_controls()
            _repaint(display)
            assert display._reveal_started_at == 1001.0
            assert display._reveal_sliding_in is False
            assert display._reveal_progress(1001.0) == 0.0
            assert display._reveal_progress(1001.0 + dd.REVEAL_ANIMATION_S / 2.0) == pytest.approx(0.5)

    def test_end_of_slide_tick_does_not_clear_a_newer_slide(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            clock.t = 1000.0 + dd.REVEAL_ANIMATION_S + 0.01
            newer = clock.t

            class _Racer:
                """Stands in for the poll thread: stamps a new slide between
                the tick's read of the start and its reset."""

                def __enter__(self_inner):
                    display._reveal_started_at = newer
                    return self_inner

                def __exit__(self_inner, *exc):
                    return False

            real_lock = display._lock
            display._lock = _Racer()
            try:
                display._tick_controls_reveal()
            finally:
                display._lock = real_lock
            assert display._reveal_started_at == newer

            # Undisturbed, the tick still clears a finished slide.
            display._reveal_started_at = 1000.0
            display._tick_controls_reveal()
            assert display._reveal_started_at == 0.0

    def test_screen_change_resets_window_and_slide(self):
        display, fb, gt, _ = self._rich()
        held_frame = fb.displayed[-1]
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            assert display._reveal_started_at == 1000.0
            display.open_selector()
            _repaint(display)
            assert display._screen == "selector"
            assert display._controls_hidden_until == 0.0
            assert display._reveal_started_at == 0.0
            assert display._controls_last is None

            display.close_list()
            clock.t = 1000.2
            _repaint(display)
            assert display._screen == "main"
            # Back on main the ordinary frame shows, not bare artwork.
            assert _pixels(fb.displayed[-1]) == _pixels(held_frame)

    def test_now_playing_clear_mid_slide_takes_the_idle_path(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            clock.t = 1000.1
            gt.return_value = []
            display._poll_once()
            assert display.core.snapshot().now_playing is None
            _repaint(display)  # must not raise
            result = display._effective_overlay_locked(OverlayState())
            assert result.visible is False
            assert display._controls_last is None

    def test_resuming_after_idle_in_touch_mode_starts_no_phantom_slide(self):
        display, fb, gt, _ = self._rich(always_show=False)
        self._shown_settled(display, fb)
        assert display._controls_last is True
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            gt.return_value = []
            display._poll_once()
            assert display.core.snapshot().now_playing is None
            display.set_overlay(OverlayState(visible=False))
            clock.t = 1001.0
            gt.return_value = [_target()]
            _poll_with_artwork(display, fb)
            assert display._reveal_started_at == 0.0
            assert _pixels(fb.displayed[-1]) == _pixels(_bare_frame(display, fb))

    def test_poll_repaint_mid_slide_composes_under_the_chrome(self):
        display, fb, gt, band_h = self._rich()
        metrics = display._layout_metrics()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            clock.t = 1000.0 + dd.REVEAL_ANIMATION_S / 2.0
            new_image = Image.linear_gradient("L").resize((fb.width, fb.height)).convert("RGB")
            new_track_id = _track_id(artwork_url="https://provider.example/y.jpg")
            with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=new_track_id)), \
                 patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
                 patch("dial_display.decode_artwork", return_value=new_image), \
                 patch("dial_display_compositor.transform_artwork_for_panel", return_value=new_image):
                display._poll_once()
            frame = fb.displayed[-1]

            with display._lock:
                overlay = display._effective_overlay_locked(display._overlay_snapshot, now=clock.t, animating=False)
            assert overlay.visible is False
            shown = display._compositor.compose(
                new_image, fb.width, fb.height, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True), metrics=metrics,
            )
            dy = round(display._reveal_progress(clock.t) * band_h)
            assert dy > 0
            assert _rows_equal(frame, new_image, (0, band_h - dy, fb.width, band_h))
            # The new artwork sits under the band that is still there, at
            # the rows it always occupied.
            assert _rows_equal(frame, shown, (0, 0, 4, band_h - dy), tol=2)

    def test_chrome_change_mid_slide_rebuilds_layers_and_continues(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            with patch("dial_display.shown_volume", return_value=40):
                clock.t = 1000.1
                _repaint(display)
                clock.t = 1000.15
                _repaint(display)
                before = dd_compositor._reveal_layers.cache_info()
                with patch("dial_display.shown_volume", return_value=45):
                    clock.t = 1000.2
                    _repaint(display)
                after = dd_compositor._reveal_layers.cache_info()
            assert after.misses == before.misses + 1
            assert display._reveal_started_at == 1000.0
            assert display._reveal_progress(1000.2) == pytest.approx(dd._reveal_ease(0.2 / dd.REVEAL_ANIMATION_S))

    def test_sleep_mid_slide_resets(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            assert display._reveal_started_at == 1000.0
            with display._lock:
                display._sleep_locked()
            assert display._controls_hidden_until == 0.0
            assert display._reveal_started_at == 0.0
            assert display._controls_last is None

    def test_no_new_thread(self):
        display, fb, gt = _make_rich_display(targets=[])
        display.start()
        try:
            time.sleep(0.05)
            before = threading.active_count()
            display.hide_controls()
            time.sleep(0.05)
            after = threading.active_count()
            assert after == before
        finally:
            display.stop()

    def test_tick_controls_hidden_leaves_the_stamp_to_the_painters(self):
        display, fb, gt, _ = self._rich()
        with patch("dial_display.time.monotonic", return_value=1000.0):
            display.hide_controls()
            _repaint(display)
        assert display._reveal_started_at == 1000.0
        display._overlay_signal.clear()
        with patch("dial_display.time.monotonic", return_value=1000.0 + dd.CONTROLS_HIDE_SECONDS + 0.1):
            display._tick_controls_hidden()
        assert display._controls_hidden_until == 0.0
        assert display._reveal_started_at == 1000.0
        assert display._overlay_signal.is_set()

    def test_one_clock_read_per_compose(self):
        display, fb, gt, _ = self._rich()
        reads = []

        def clock():
            reads.append(1)
            return 1000.0

        with patch_monotonic(clock):
            display.hide_controls()
            reads.clear()
            with display._lock:
                display._display_locked(display._current_base_image)
        # The compose's own read, plus the stamp after the push.
        assert len(reads) <= 2


# ---------------------------------------------------------------------------
# The same reveal on the replay screen, exactly while a replay is running: a
# tap on the position line (or the artwork strip around it) slides the bands'
# chrome off and fades the line, the counter keeps counting underneath, a
# touch brings the controls back and never actuates a hidden Restart/Stop/
# dots, and the window ends with the replay, the screen or its own timeout.
# ---------------------------------------------------------------------------

class TestReplayReveal:
    AID = "31" * 10

    def _opened(self, maker=None, state="replaying", at=1000.0):
        display, fb, gt = (maker or _make_rich_display)(targets=[])
        display.enable()
        base = Image.linear_gradient("L").resize((fb.width, fb.height)).convert("RGB")
        with display._lock:
            display._screen = "repeat"
            display._repeat_screen = dd.RepeatScreenState(
                appliance_id=self.AID, service_name="Kitchen", ip="10.0.0.1", port=80, opened_at=at,
            )
            display._current_base_image = base
        self._seed(state, at)
        return display, fb, base

    def _seed(self, state, observed_at):
        import dial_repeat_store as drs
        drs.repeat_store.update(self.AID, drs.RepeatRecord(
            available=True, state=state, armed=True,
            recording_seconds=30.0, position_seconds=5.0, duration_seconds=30.0,
            observed_at=observed_at,
        ))

    def _bare(self, display, fb, base):
        metrics = display._layout_metrics()
        with display._lock:
            view = display._build_repeat_view_locked(display._repeat_screen, time.monotonic())
        return display._compositor.compose_repeat(
            fb.width, fb.height, view, rotate=False, bgr=False, base=base, metrics=metrics, controls=False,
        )

    def test_line_tap_while_replaying_hides(self):
        display, fb, base = self._opened()
        with patch("dial_display.time.monotonic", _FakeClock(1000.0)):
            display.repeat_toggle_tap()
            assert display._controls_hidden_until == pytest.approx(1000.0 + dd.CONTROLS_HIDE_SECONDS)

    def test_hold_and_enable_layouts_do_not_hide(self):
        display, fb, base = self._opened(state="hold")
        with patch("dial_display.time.monotonic", _FakeClock(1000.0)):
            display.repeat_toggle_tap()
            display.hide_controls()
            assert display._controls_hidden_until == 0.0
            self._seed("idle", 1000.0)
            display.repeat_toggle_tap()
            display.hide_controls()
            assert display._controls_hidden_until == 0.0

    def test_touch_surface_reports_hidden_while_the_window_holds(self):
        display, fb, base = self._opened()
        with patch("dial_display.time.monotonic", _FakeClock(1000.0)):
            assert display.touch_surface()[0] == "repeat"
            display.hide_controls()
            assert display.touch_surface() == ("hidden", True, display.core.snapshot().dots_active, display.core.snapshot().outputs_available)
            display.set_overlay(OverlayState(visible=True))
            assert display.touch_surface()[0] == "repeat"

    def test_repeat_frames_slide_then_bare(self):
        display, fb, base = self._opened()
        band_h = layout_for(fb.width, fb.height, metrics=display._layout_metrics()).top_band[3]
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            _repaint(display)
            shown = fb.displayed[-1]
            display.repeat_toggle_tap()
            _repaint(display)
            assert _pixels(fb.displayed[-1]) == _pixels(shown)
            assert display._reveal_started_at == 1000.0

            clock.t = 1000.0 + dd.REVEAL_ANIMATION_S / 2.0
            _repaint(display)
            mid = fb.displayed[-1]
            bare = self._bare(display, fb, base)
            dy = round(0.5 * band_h)
            assert _pixels(mid) != _pixels(shown)
            assert _pixels(mid) != _pixels(bare)
            assert _rows_equal(mid, bare, (0, band_h - dy, fb.width, band_h))
            line = repeat_layout_for(fb.width, fb.height, metrics=display._layout_metrics()).line
            assert _pixels(mid.crop(line)) != _pixels(bare.crop(line))
            assert _pixels(mid.crop(line)) != _pixels(shown.crop(line))

            clock.t = 1000.0 + dd.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            assert _pixels(fb.displayed[-1]) == _pixels(bare)

    def test_counter_keeps_ticking_while_hidden(self):
        display, fb, base = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            _repaint(display)
            display.repeat_toggle_tap()
            _repaint(display)
            clock.t = 1000.0 + dd.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            display._tick_controls_reveal()
            bare = self._bare(display, fb, base)
            painted = display._repeat_painted_second
            for step in (1.0, 2.0):
                clock.t = 1000.6 + step
                display._overlay_signal.clear()
                display._tick_repeat_line()
                assert display._overlay_signal.is_set()
                _repaint(display)
                assert display._repeat_painted_second == painted + int(step)
                assert display._next_repaint_deadline() > clock.t
                assert _pixels(fb.displayed[-1]) == _pixels(bare)

    def test_replay_end_ends_the_window(self):
        display, fb, base = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            _repaint(display)
            display.repeat_toggle_tap()
            _repaint(display)
            self._seed("hold", 1000.0)
            _repaint(display)
            assert display._controls_hidden_until == 0.0
            assert display._reveal_started_at == 0.0
            assert display.touch_surface()[0] == "repeat"
            assert _pixels(fb.displayed[-1]) != _pixels(self._bare(display, fb, base))

    def test_screen_change_ends_the_window(self):
        display, fb, base = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            _repaint(display)
            display.repeat_toggle_tap()
            _repaint(display)
            display.pop_secondary("repeat")
            _repaint(display)
            assert display._screen == "main"
            assert display._controls_hidden_until == 0.0
            assert display._reveal_started_at == 0.0

    def test_window_expiry_shows_controls(self):
        display, fb, base = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            _repaint(display)
            display.repeat_toggle_tap()
            _repaint(display)
            clock.t = 1000.0 + dd.CONTROLS_HIDE_SECONDS + 0.1
            self._seed("replaying", clock.t)
            display._tick_controls_hidden()
            _repaint(display)
            assert display.touch_surface()[0] == "repeat"

    def test_window_expiry_slides_the_controls_in(self):
        display, fb, base = self._opened()
        band_h = layout_for(fb.width, fb.height, metrics=display._layout_metrics()).top_band[3]
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            _repaint(display)
            shown = fb.displayed[-1]
            display.repeat_toggle_tap()
            _repaint(display)
            clock.t = 1000.0 + dd.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            bare = self._bare(display, fb, base)
            assert _pixels(fb.displayed[-1]) == _pixels(bare)

            t_expiry = 1000.0 + dd.CONTROLS_HIDE_SECONDS + 0.1
            clock.t = t_expiry
            self._seed("replaying", clock.t)
            display._tick_controls_hidden()
            _repaint(display)
            assert display._reveal_sliding_in is True
            assert display._reveal_started_at == t_expiry
            assert _pixels(fb.displayed[-1]) == _pixels(bare)

            clock.t = t_expiry + dd.REVEAL_ANIMATION_S / 2.0
            self._seed("replaying", clock.t)
            _repaint(display)
            mid = fb.displayed[-1]
            dy = round(0.5 * band_h)
            assert _pixels(mid) != _pixels(bare)
            assert _pixels(mid) != _pixels(shown)
            assert _rows_equal(mid, bare, (0, band_h - dy, fb.width, band_h))
            assert display.touch_surface()[0] == "repeat"

            clock.t = t_expiry + dd.REVEAL_ANIMATION_S + 0.05
            self._seed("replaying", clock.t)
            _repaint(display)
            assert display._reveal_progress(clock.t) == 0.0
            assert _pixels(fb.displayed[-1]) != _pixels(bare)

    def test_reveal_tap_slides_the_controls_in(self):
        display, fb, base = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            _repaint(display)
            display.repeat_toggle_tap()
            _repaint(display)
            clock.t = 1000.0 + dd.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            bare = self._bare(display, fb, base)

            clock.t = 1002.0
            self._seed("replaying", clock.t)
            display.set_overlay(OverlayState(visible=True))
            _repaint(display)
            assert display._reveal_sliding_in is True
            assert display._reveal_started_at == 1002.0
            assert _pixels(fb.displayed[-1]) == _pixels(bare)

            clock.t = 1002.0 + dd.REVEAL_ANIMATION_S / 2.0
            self._seed("replaying", clock.t)
            _repaint(display)
            assert _pixels(fb.displayed[-1]) != _pixels(bare)

    def test_reveal_tap_mid_slide_out_turns_around_without_a_jump(self):
        display, fb, base = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            _repaint(display)
            display.repeat_toggle_tap()
            _repaint(display)
            clock.t = 1000.2
            self._seed("replaying", clock.t)
            _repaint(display)
            out_progress = display._reveal_progress(clock.t)
            out_frame = fb.displayed[-1]
            display.set_overlay(OverlayState(visible=True))
            _repaint(display)
            assert display._reveal_sliding_in is True
            assert display._reveal_progress(clock.t) == pytest.approx(out_progress)
            assert _pixels(fb.displayed[-1]) == _pixels(out_frame)

    def test_replay_stopping_does_not_slide_the_controls_in(self):
        display, fb, base = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            _repaint(display)
            display.repeat_toggle_tap()
            _repaint(display)
            clock.t = 1000.0 + dd.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            self._seed("hold", clock.t)
            _repaint(display)
            assert display._controls_hidden_until == 0.0
            assert display._reveal_started_at == 0.0
            assert display._controls_last is None
            assert display._reveal_progress(clock.t) == 0.0
            plain = fb.displayed[-1]

            # Stopping mid slide-in snaps too.
            self._seed("replaying", clock.t)
            _repaint(display)
            display.repeat_toggle_tap()
            _repaint(display)
            clock.t += dd.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            clock.t += dd.CONTROLS_HIDE_SECONDS + 0.1
            self._seed("replaying", clock.t)
            display._tick_controls_hidden()
            _repaint(display)
            assert display._reveal_started_at == clock.t
            clock.t += 0.1
            self._seed("hold", clock.t)
            _repaint(display)
            assert display._reveal_started_at == 0.0
            assert _pixels(fb.displayed[-1]) == _pixels(plain)

    def test_base_tier_hides_instantly(self):
        display, fb, base = self._opened(maker=make_display)
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            _repaint(display)
            display.repeat_toggle_tap()
            _repaint(display)
            assert display._reveal_started_at == 0.0
            assert _pixels(fb.displayed[-1]) == _pixels(self._bare(display, fb, base))

    def test_compact_repeat_unaffected(self):
        display, fb, base = self._opened(maker=_make_compact_display)
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            _repaint(display)
            before = _pixels(fb.displayed[-1])
            display.repeat_toggle_tap()
            display.hide_controls()
            assert display._controls_hidden_until == 0.0
            _repaint(display)
            assert _pixels(fb.displayed[-1]) == before


class TestHeldOverlay:
    def test_held_visible_frame_differs_from_no_overlay_frame(self):
        t = _target()
        display_off, fb_off, _ = make_display(targets=[t], always_show_controls=False)
        display_off.enable()
        _poll_with_artwork(display_off, fb_off)
        no_overlay_frame = fb_off.displayed[-1]

        display_on, fb_on, _ = make_display(targets=[t], always_show_controls=True)
        display_on.enable()
        _poll_with_artwork(display_on, fb_on)
        held_frame = fb_on.displayed[-1]

        assert display_on.persistent_overlay_shown() is True
        assert list(held_frame.getdata()) != list(no_overlay_frame.getdata())

    def test_idle_logo_is_bare_even_when_always_show_controls_is_on(self):
        display, fb, gt = make_display(targets=[], always_show_controls=True)
        display.enable()
        fb.displayed.clear()
        with display._lock:
            display._render_logo_locked()
        logo_frame = fb.displayed[-1]

        # Compose the same base without any overlay merge for comparison —
        # with nothing playing, the held path must not have drawn anything
        # on top of the idle logo.
        expected = display._compositor.compose(
            logo_frame, logo_frame.width, logo_frame.height,
            rotate=False, bgr=False, is_artwork=False, overlay=None,
        )
        assert list(logo_frame.getdata()) == list(expected.getdata())

    def test_placeholder_logo_while_playing_gets_the_held_overlay(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.core.snapshot().now_playing is not None
        fb.displayed.clear()
        with display._lock:
            # A track change: the base image swaps to the placeholder logo,
            # but a controllable appliance is still on screen, so the held
            # overlay must be drawn over it, unlike the idle case above.
            display._render_logo_locked()
        logo_frame = fb.displayed[-1]

        bare = display._compositor.compose(
            display._current_base_image, logo_frame.width, logo_frame.height,
            rotate=False, bgr=False, is_artwork=False, overlay=None,
        )
        assert list(logo_frame.getdata()) != list(bare.getdata())

    def test_always_show_controls_false_and_snapshot_hidden_matches_no_overlay(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], always_show_controls=False)
        display.enable()
        _poll_with_artwork(display, fb)
        frame = fb.displayed[-1]
        expected = display._compositor.compose(
            display._current_base_image, fb.width, fb.height,
            rotate=False, bgr=False, is_artwork=False, overlay=OverlayState(visible=False),
        )
        assert list(frame.getdata()) == list(expected.getdata())

    def test_update_config_toggle_redisplays_synchronously(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], fitted=True, always_show_controls=False)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.get_status()["showing"] == "artwork"
        fb.displayed.clear()

        with patch.object(display, "_poll_once") as mock_poll:
            status = display.update_config(DialDisplayConfig(fitted=True, always_show_controls=True))
        mock_poll.assert_not_called()

        assert status["always_show_controls"] is True
        assert len(fb.displayed) == 1

    def test_effective_overlay_locked_forces_visible_when_held(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        result = display._effective_overlay_locked(OverlayState(visible=False))
        assert result.visible is True

    def test_effective_overlay_locked_not_held_returns_invisible_snapshot_unchanged(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], always_show_controls=False)
        display.enable()
        _poll_with_artwork(display, fb)
        snapshot = OverlayState(visible=False)
        result = display._effective_overlay_locked(snapshot)
        assert result is snapshot


# ---------------------------------------------------------------------------
# A pushed auth change and the sleeping panel.
# ---------------------------------------------------------------------------

class TestPushProbesOnScreen:
    def test_push_probe_that_promotes_while_asleep_wakes_and_resets_idle(self):
        aid = "e" * 20
        t = _target(appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with display._lock:
            display._display_sleeping = True
            display._idle_started_at = 123.0
        display.notify_auth_changed(aid)
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(appliance_id=aid, track_id=None)):
            result = display._core._drain_push_probes()
            # The promotion shows in the poll that follows, which wakes the panel.
            display._poll_once()
        assert result == "probed"
        assert display._display_sleeping is False
        assert display._idle_started_at is None
        assert fb.wake_calls == 1
    def test_push_probe_that_demotes_leaves_display_asleep(self):
        aid = "f" * 20
        t = _target(appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with display._lock:
            display._display_sleeping = True
        display.notify_auth_changed(aid)
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(status_error="unauthorized", appliance_id=aid)):
            result = display._core._drain_push_probes()
            display._poll_once()
        assert result == "probed"
        assert display._display_sleeping is True
        assert fb.wake_calls == 0


class TestRunPollGating:
    """The poll runs every tick, asleep or not: the tick itself wakes the
    panel for a playing target this dial may use and stays dark otherwise."""

    def _run_one_iteration(self, display):
        """One turn of the core's loop: the push probes, then the tick, and
        the view folding in the snapshot it ends in."""
        display._core._drain_push_probes()
        display._poll_once()

    def _asleep_display(self, clock):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with patch_monotonic(clock):
            display._poll_once()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display._poll_once()
        assert display.get_status()["display_sleeping"] is True
        return display, fb, gt

    def test_the_core_keeps_polling_while_the_view_sleeps(self):
        display, fb, gt = make_display(targets=[])
        display._display_sleeping = True
        display._core.set_poll_interval(0.02)
        polls = []
        with patch.object(display._core, "poll_once", side_effect=lambda: polls.append(1)):
            display._core.start()
            try:
                deadline = time.monotonic() + 2.0
                while len(polls) < 3 and time.monotonic() < deadline:
                    time.sleep(0.01)
            finally:
                display._core.stop()
        assert len(polls) >= 3
        assert display._display_sleeping is True

    def test_view_wakes_when_a_visible_target_appears_in_a_snapshot(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with display._lock:
            display._display_sleeping = True
            display._idle_started_at = 5.0
        before = display._applied
        display._core._announce_visible((t.appliance_id,))
        display._apply_pending_snapshot()
        assert display._applied is not before
        assert display._display_sleeping is False
        assert display._idle_started_at is None
        assert fb.wake_calls == 1

    def test_view_stays_dark_for_a_snapshot_with_nothing_visible(self):
        t = _target(auth="unauthorized")
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with display._lock:
            display._display_sleeping = True
        painted = len(fb.displayed)
        display._core.set_field("now_playing", NowPlaying("x", "", "", None))
        display._apply_pending_snapshot()
        assert display._display_sleeping is True
        assert fb.wake_calls == 0
        assert len(fb.displayed) == painted

    @pytest.mark.parametrize("auth", ["unknown", "authorized"])
    def test_asleep_dial_wakes_when_a_usable_target_starts_playing(self, auth):
        clock = _FakeClock()
        display, fb, gt = self._asleep_display(clock)
        gt.return_value = [_target(auth=auth)]
        with patch_monotonic(clock), \
             patch("dial_core.fetch_target_status",
                   return_value=_status_result(track_id=None)):
            self._run_one_iteration(display)
        assert fb.wake_calls == 1
        assert display.get_status()["display_sleeping"] is False

    def test_asleep_dial_stays_dark_for_a_confirmed_unauthorized_target(self):
        clock = _FakeClock()
        display, fb, gt = self._asleep_display(clock)
        gt.return_value = [_target(auth="unauthorized")]
        painted = len(fb.displayed)
        with patch_monotonic(clock), \
             patch("dial_core.fetch_target_status") as mock_fetch:
            self._run_one_iteration(display)
        mock_fetch.assert_not_called()
        assert fb.wake_calls == 0
        assert len(fb.displayed) == painted
        assert display.get_status()["display_sleeping"] is True

    def test_asleep_dial_with_nothing_playing_stays_dark(self):
        clock = _FakeClock()
        display, fb, gt = self._asleep_display(clock)
        painted = len(fb.displayed)
        with patch_monotonic(clock):
            self._run_one_iteration(display)
        assert fb.wake_calls == 0
        assert len(fb.displayed) == painted
        assert display.get_status()["display_sleeping"] is True

    def test_asleep_dial_still_wakes_on_an_auth_push(self):
        aid = "9" * 20
        t = _target(appliance_id=aid)
        clock = _FakeClock()
        display, fb, gt = self._asleep_display(clock)
        display.core.set_roster([t])
        display.notify_auth_changed(aid)
        with patch_monotonic(clock), \
             patch("dial_core.fetch_target_status",
                   return_value=_status_result(appliance_id=aid, track_id=None)):
            self._run_one_iteration(display)
        assert fb.wake_calls == 1
        assert display.get_status()["display_sleeping"] is False


# ---------------------------------------------------------------------------
# A refused first check neither wakes nor paints
# ---------------------------------------------------------------------------

class TestFirstCheckOrdering:
    def _asleep(self, targets):
        display, fb, gt = make_display(targets=targets)
        display.enable()
        with display._lock:
            display._sleep_locked()
        assert display._display_sleeping
        return display, fb, gt

    def test_first_check_refusal_never_wakes_or_paints_in_the_same_tick(self):
        t = _target(name="Fresh", auth="unknown")
        display, fb, gt = self._asleep([t])
        wakes, frames = fb.wake_calls, len(fb.displayed)
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(status_error="unauthorized",
                                               appliance_id=t.appliance_id)) as fetch:
            display._poll_once()
        assert fetch.call_count == 1
        assert fb.wake_calls == wakes
        assert len(fb.displayed) == frames
        assert display._display_sleeping

    def test_first_check_acceptance_wakes_with_a_single_request(self):
        t = _target(name="Fresh", auth="unknown")
        display, fb, gt = self._asleep([t])
        wakes = fb.wake_calls
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(track_id=None)) as fetch:
            display._poll_once()
        assert fetch.call_count == 1      # the walk reuses the first check's reply
        assert fb.wake_calls == wakes + 1
        assert not display._display_sleeping


# ---------------------------------------------------------------------------
# An accepted replay shown before its advertisement, and what follows it
# ---------------------------------------------------------------------------

_REPLAY_AID = "a" * 20


def _replay_display(state="hold", **display_kwargs):
    """A display following _REPLAY_AID, rostered and repeat-capable, with a
    repeat record in *state*. The caller patches the clock before calling
    this."""
    import dial_repeat_store as drs
    entry = _roster_entry(appliance_id=_REPLAY_AID, auth="authorized", repeat_capable=True)
    display, fb, gt = make_display(targets=[], roster=[entry], **display_kwargs)
    display.enable()
    display.core.set_roster([entry])
    display.core.set_field("manual_id", _REPLAY_AID)
    drs.repeat_store.update(
        _REPLAY_AID, drs.parse_repeat_object(_repeat_obj(state=state), dd.time.monotonic()),
    )
    display.request_poll = MagicMock()
    return display, fb, gt


def _accept_replay(display) -> None:
    on_repeat_result(display,
        "transport", _REPLAY_AID, 200,
        {"ok": True, "state": "replaying", "armed": False, "position_seconds": 0.0},
    )


class TestAcceptedReplayFrame:
    def test_accepted_replay_frame_has_no_title_or_artist(self):
        """The synthetic playing target has no identified track yet, so the
        first frame is the plain logo, playing, with nothing to name."""
        clock = _FakeClock()
        with patch_monotonic(clock):
            display, fb, gt = _replay_display()
            _accept_replay(display)
            with patch("dial_core.fetch_target_status",
                       return_value=_status_result(appliance_id=_REPLAY_AID)):
                display._poll_once()
        playing = display.core.snapshot().now_playing
        assert playing is not None and playing.playing
        assert playing.title == ""
        assert playing.artist == ""
        assert display.get_status()["showing"] == "logo"
        assert display._source_artwork_key == ""

    def test_replay_stop_never_paints_playing_over_the_logo(self):
        """Accepted replay -> the record fades out -> the target is gone and
        the record holds. From the poll that sees the stop, no composed
        frame carries the playing artist text and the base is the
        replay-available logo."""
        import dial_repeat_store as drs
        clock = _FakeClock()
        with patch_monotonic(clock):
            # A tier that draws the artist row, with the controls always shown.
            display, fb, gt = _replay_display(always_show_controls=True)
            base_metrics = display._layout_metrics
            display._layout_metrics = lambda: dataclasses.replace(
                base_metrics(), content_tier=dd.CONTENT_RICH,
            )
            # The playing frame must really carry the text, or this test
            # would pass for the wrong reason.
            frames = []
            real_compose = display._compositor.compose

            def record_compose(base, *a, **k):
                frames.append(("playing", k.get("overlay")))
                return real_compose(base, *a, **k)

            idle_bases = []
            real_idle = display._compositor.compose_idle

            def record_idle(base, *a, **k):
                idle_bases.append(base)
                frames.append(("idle", None))
                return real_idle(base, *a, **k)

            display._compositor.compose = record_compose
            display._compositor.compose_idle = record_idle

            _accept_replay(display)
            with patch("dial_core.fetch_target_status",
                       return_value=_status_result(appliance_id=_REPLAY_AID)):
                display._poll_once()
            with display._lock:
                display._repaint_current_locked()
            playing_overlays = [o for kind, o in frames if kind == "playing" and o is not None]
            assert any(o.artist == dd.PLAYING_ARTIST_TEXT for o in playing_overlays)

            # The replay is fading out: still playing, still the synthetic target.
            drs.repeat_store.update(_REPLAY_AID, drs.parse_repeat_object(
                _repeat_obj(state="fading_out", held=False,
                            replay={"active": True, "position_seconds": 29.0, "duration_seconds": 30.0}),
                clock.t,
            ))
            clock.t += 1.0
            with patch("dial_core.fetch_target_status",
                       return_value=_status_result(appliance_id=_REPLAY_AID)):
                display._poll_once()

            # Stopped: the record holds and the target is gone.
            drs.repeat_store.update(_REPLAY_AID, drs.parse_repeat_object(_repeat_obj(state="hold"), clock.t))
            clock.t += 1.0
            mark = len(frames)
            with patch("dial_core.fetch_target_status",
                       return_value=_status_result(appliance_id=_REPLAY_AID)), \
                 patch("dial_display.load_logo", side_effect=dd.load_logo) as load_logo:
                display._poll_once()
                with display._lock:
                    display._repaint_current_locked()
            after_stop = frames[mark:]
            assert not any(
                o is not None and o.artist == dd.PLAYING_ARTIST_TEXT for kind, o in after_stop
            )
            assert display.core.snapshot().now_playing is None
            assert display.core.snapshot().idle_affordance is True
            assert display._idle_chassis_due_locked() is True
            assert any(kind == "idle" for kind, _ in after_stop)
            assert load_logo.call_args_list[-1].args[0] == display._replay_logo_path


# ---------------------------------------------------------------------------
# A focus clear closes exactly the screens whose policy says so
# ---------------------------------------------------------------------------

_POLICY_SCREEN_NAMES = sorted(name for name in SCREEN_POLICIES if name != "main")


class TestFocusClearClosesPolicyScreens:
    def test_policy_rows_that_close_on_focus_clear(self):
        assert {n for n in _POLICY_SCREEN_NAMES if SCREEN_POLICIES[n].closes_on_focus_clear} == {
            "repeat", "eq", "outputs", "output",
        }

    @pytest.mark.parametrize("name", _POLICY_SCREEN_NAMES)
    def test_focus_clear_closes_only_policy_screens(self, name):
        policy = SCREEN_POLICIES[name]
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.core.set_field("manual_id", _REPLAY_AID)
        sentinel = object()
        with display._lock:
            display._screen = name
            if policy.state_attr is not None:
                setattr(display, policy.state_attr, sentinel)
        display._core.clear_focus("test")
        display._close_screens_for_cleared_focus()
        assert display.core.manual_focus_id() is None
        if policy.closes_on_focus_clear:
            assert display._screen == "main"
            if policy.state_attr is not None:
                assert getattr(display, policy.state_attr) is None
        else:
            assert display._screen == name
            if policy.state_attr is not None:
                assert getattr(display, policy.state_attr) is sentinel

    def test_a_tick_that_clears_the_focus_closes_the_screen(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.core.set_field("manual_id", _REPLAY_AID)      # not on the roster: the tick clears it
        with display._lock:
            display._screen = "outputs"
        display._poll_once()
        assert display.core.manual_focus_id() is None
        assert display._screen == "main"


# ---------------------------------------------------------------------------
# Artwork failures are logged first and tenth, and the URL stays out of
# status and logs
# ---------------------------------------------------------------------------

_SECRET_URL = "https://provider.example/art-token-7731/cover.jpg"


def _artwork_display(url=_SECRET_URL):
    t = _target()
    display, fb, gt = make_display(targets=[t])
    display.enable()
    result = _status_result(track_id=_track_id(artwork_url=url))
    return display, result


class TestArtworkLogging:
    def test_artwork_failures_log_first_and_tenth(self, caplog):
        display, result = _artwork_display()
        with patch("dial_core.fetch_target_status", return_value=result), \
                patch("dial_core_poll.default_fetch_artwork", return_value=(None, "timeout")) as fetch, \
                caplog.at_level(logging.WARNING):
            for _ in range(11):
                display._poll_once()
        assert fetch.call_count == 11           # every poll retries
        records = [r for r in caplog.records if "artwork fetch failed" in r.getMessage()]
        assert len(records) == 2
        assert display.get_status()["showing"] == "logo"
        assert display.get_status()["last_error"] == "artwork_fetch_failed"

    def test_artwork_decode_failures_log_first_and_tenth(self, caplog):
        display, result = _artwork_display()
        with patch("dial_core.fetch_target_status", return_value=result), \
                patch("dial_core_poll.default_fetch_artwork", return_value=(b"bad", "")), \
                patch("dial_display.decode_artwork", return_value=None), \
                caplog.at_level(logging.WARNING):
            for _ in range(11):
                display._poll_once()
        records = [r for r in caplog.records if "artwork decode failed" in r.getMessage()]
        assert len(records) == 2

    def test_artwork_url_never_stored_or_logged(self, caplog):
        """Status, every log record and every attribute of the display carry
        only the short artwork key: the URL is never stored on the display
        (the cache-reuse key is a hash), nor held by the core."""
        display, result = _artwork_display()
        fake_image = Image.new("RGB", (128, 160))
        with patch("dial_core.fetch_target_status", return_value=result), \
                caplog.at_level(logging.DEBUG):
            with patch("dial_core_poll.default_fetch_artwork", return_value=(None, "timeout")):
                for _ in range(3):
                    display._poll_once()
            with patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpeg", "")), \
                    patch("dial_display.decode_artwork", return_value=fake_image), \
                    patch("dial_display_compositor.transform_artwork_for_panel",
                          return_value=fake_image):
                display._poll_once()
        assert display.get_status()["showing"] == "artwork"
        assert caplog.records
        for record in caplog.records:
            assert "art-token-7731" not in record.getMessage()
            assert all("art-token-7731" not in str(a) for a in (record.args or ()))
        assert "art-token-7731" not in json.dumps(display.get_status())
        holders = [
            k for k, v in vars(display).items()
            if isinstance(v, str) and "art-token-7731" in v
        ]
        assert holders == []
        assert display._source_artwork_key == artwork_key(_SECRET_URL)
        held = display._core.snapshot().artwork
        assert held is not None and held.url == "" and held.key == artwork_key(_SECRET_URL)


# ---------------------------------------------------------------------------
# Appliance-selector screen (2.7, 2.5.5) — open/close/page/pick, row
# filtering, the inactivity timeout, and the screen's interaction with
# sleep/backend lifecycle and the touch-facing surfaces.
# ---------------------------------------------------------------------------

class TestSelectorRows:
    def test_page_preserved_across_rebuild_but_clamped_to_new_count(self):
        targets = [
            _target(name=f"T{i}", service_name=f"T{i}", appliance_id=str(i) * 20,
                     auth="authorized", playing_since=float(i))
            for i in range(5)
        ]
        display, fb, gt = make_display(targets=targets)
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        display.list_page(+1)  # page 1 (rows_per_page == 3 -> pages 0,1)
        with display._lock:
            display._repaint_current_locked()
        assert display._selector.page == 1

        # Roster shrinks to one row: the next poll's rebuild must clamp the
        # preserved page back down rather than raise or go negative.
        gt.return_value = [targets[0]]
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        assert display._selector.page == 0


class TestSelectorAndPickerRowsSignalRepaint:
    """A row rebuild that changes what would be painted must repaint even
    with nothing else moving on screen — see _refresh_selector_rows and
    _refresh_picker_rows."""

    def test_selector_signals_when_rows_change_and_screen_requested(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._screen_request = "selector"
        roster = [_roster_entry(name="A", appliance_id="a" * 20, auth="authorized", playing=True)]
        display._overlay_signal.clear()

        _refresh_selector(display, roster)

        assert [r.appliance_id for r in display._selector.rows] == ["a" * 20]
        assert display._overlay_signal.is_set()

    def test_selector_signals_when_rows_change_and_screen_showing(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "selector"
        roster = [_roster_entry(name="A", appliance_id="a" * 20, auth="authorized", playing=True)]
        display._overlay_signal.clear()

        _refresh_selector(display, roster)

        assert display._overlay_signal.is_set()

    def test_selector_no_signal_when_rows_unchanged(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._screen_request = "selector"
        roster = [_roster_entry(name="A", appliance_id="a" * 20, auth="authorized", playing=True)]
        _refresh_selector(display, roster)
        display._overlay_signal.clear()

        _refresh_selector(display, roster)

        assert not display._overlay_signal.is_set()

    def test_selector_no_signal_when_another_screen_showing(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        roster = [_roster_entry(name="A", appliance_id="a" * 20, auth="authorized", playing=True)]
        display._overlay_signal.clear()

        _refresh_selector(display, roster)

        assert display._overlay_signal.is_set() is False

    def test_picker_signals_when_rows_change_and_screen_requested(self):
        import dial_repeat_store as drs
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._screen_request = "picker"
        now = time.monotonic()
        row = _roster_entry(name="A", appliance_id="a" * 20, auth="authorized", repeat_capable=True)
        drs.repeat_store.update("a" * 20, drs.parse_repeat_object(_repeat_obj(state="hold"), now))
        display._overlay_signal.clear()

        _refresh_picker(display, [row], now)

        assert [r.appliance_id for r in display._picker.rows] == ["a" * 20]
        assert display._overlay_signal.is_set()

    def test_picker_no_signal_when_rows_unchanged(self):
        import dial_repeat_store as drs
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._screen_request = "picker"
        now = time.monotonic()
        row = _roster_entry(name="A", appliance_id="a" * 20, auth="authorized", repeat_capable=True)
        drs.repeat_store.update("a" * 20, drs.parse_repeat_object(_repeat_obj(state="hold"), now))
        _refresh_picker(display, [row], now)
        display._overlay_signal.clear()

        _refresh_picker(display, [row], now)

        assert not display._overlay_signal.is_set()


class TestSelectorOpenCloseAndRepaint:
    def _display_with_one_row(self, always_show_controls=False):
        a = _target(name="A", service_name="A", appliance_id="a" * 20, auth="authorized")
        display, fb, gt = make_display(targets=[a], always_show_controls=always_show_controls)
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        return display, fb, gt

    def test_open_selector_then_repaint_sets_screen_and_pushes_a_frame(self):
        display, fb, gt = self._display_with_one_row()
        before = len(fb.displayed)
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "selector"
        assert len(fb.displayed) == before + 1

    def test_repaint_calls_compose_list_while_open(self):
        display, fb, gt = self._display_with_one_row()
        with patch.object(
            display._compositor, "compose_list", wraps=display._compositor.compose_list,
        ) as spy:
            display.open_selector()
            with display._lock:
                display._repaint_current_locked()
        assert spy.call_count == 1

    def test_close_selector_returns_to_main(self):
        display, fb, gt = self._display_with_one_row()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "selector"

        display.close_list()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"
        assert display._selector is None

    def test_no_authorized_rows_shows_no_devices_placeholder(self):
        t = _target(auth="unknown")  # controllable (Phase 1), but never listed
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        width, height = display._active_panel_dims()
        with display._lock:
            list_state = display._build_list_state_locked(width, height)
        assert list_state.rows == (("No devices", False),)
        assert list_state.has_prev is False
        assert list_state.has_next is False

    def test_persistent_overlay_shown_false_while_open(self):
        display, fb, gt = self._display_with_one_row(always_show_controls=True)
        # Force the "a controllable appliance is shown" precondition
        # directly rather than faking a full artwork fetch — this test is
        # only about the selector's own gate on persistent_overlay_shown().
        with display._lock:
            display.core.set_field("now_playing", NowPlaying("T0", "Artist", "Title", 50))
        assert display.persistent_overlay_shown() is True
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        assert display.persistent_overlay_shown() is False


_HINT_TIERS = [
    pytest.param(320, 240, 0.1778, id="rich_320x240"),
    pytest.param(128, 128, 25.9 / 128, id="compact_128x128"),
    pytest.param(160, 128, None, id="compact_160x128"),
    pytest.param(240, 240, 23.4 / 240, id="compact_240x240"),
]


class TestSelectorUnauthorizedRows:
    def _display(self, proto=0, authorized_count=1):
        targets = [
            _target(name=f"T{i}", service_name=f"T{i}", appliance_id=str(i) * 20,
                    auth="authorized", playing_since=float(i))
            for i in range(authorized_count)
        ]
        targets.append(_target(
            name="Lounge", service_name="Lounge", appliance_id="9" * 20, ip="192.168.1.99",
            auth="unauthorized", dial_proto_version=proto, playing_since=50.0,
        ))
        targets.append(_target(
            name="Maybe", service_name="Maybe", appliance_id="8" * 20, ip="192.168.1.98", auth="unknown",
        ))
        display, fb, gt = make_display(targets=targets)
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        return display

    @pytest.mark.parametrize("proto", [0, 2])
    def test_the_list_marks_an_unauthorized_row(self, proto):
        display, fb, gt = make_display(targets=[])
        lounge = dataclasses.replace(
            _roster_entry(name="Lounge", appliance_id="9" * 20, auth="unauthorized"),
            dial_proto_version=proto,
        )
        _refresh_selector(display, [
            _roster_entry(name="T0", appliance_id="0" * 20, auth="authorized", playing=True),
            lounge,
        ])
        rows = display._selector.rows
        assert dd._selector_list_row(rows[1]) == ("Lounge", False, dd_compositor.NOT_AUTHORISED_TEXT)
        assert dd._selector_list_row(rows[0])[2] is dd.PLAY_GLYPH

    def test_selector_pick_on_unauthorized_opens_hint(self):
        display = self._display()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        display.selector_pick(1)  # the unauthorised row
        with display._lock:
            display._repaint_current_locked()
        assert display.core.manual_focus_id() is None
        assert display._screen == "info_value"
        assert display._info_value.hint == (
            dd_compositor.NOT_AUTHORISED_TEXT, "Allow this dial in Lounge's web UI (Setup, Dials)",
        )

    def test_hint_back_returns_to_selector_on_same_page(self):
        display = self._display(authorized_count=4)  # rows: T0..T3 then Lounge on page 1
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        display.list_page(+1)
        with display._lock:
            display._repaint_current_locked()
        assert display._selector.page == 1
        display.selector_pick(1)  # Lounge, the second row of page 1
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "info_value"
        display.close_list()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "selector"
        assert display._selector.page == 1
        assert display.core.manual_focus_id() is None

    def test_pick_on_authorized_row_still_sets_focus_and_closes(self):
        display = self._display()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        display.selector_pick(0)
        with display._lock:
            display._repaint_current_locked()
        assert display.core.manual_focus_id() == "0" * 20
        assert display._screen == "main"

    @pytest.mark.parametrize("width,height,mm_per_px", _HINT_TIERS)
    @pytest.mark.parametrize("name", ["Lounge", "CD Player", "Living Room Hi-Fi"])
    def test_hint_text_fits_without_truncation(self, width, height, mm_per_px, name):
        from PIL import ImageDraw
        from dial_touch_layout import info_value_layout_for

        metrics = metrics_for(width, height, mm_per_px)
        label, text = dd._unauthorised_hint(name)
        layout = info_value_layout_for(width, height, metrics=metrics)
        draw = ImageDraw.Draw(Image.new("RGB", (width, height)))
        lines, font = dd_compositor._fit_value_lines(
            draw, text, (metrics.font_readout, metrics.font_body), layout.value,
        )
        assert lines and font is not None
        assert " ".join(lines) == text  # nothing dropped, no ellipsis
        max_w = layout.value[2] - layout.value[0]
        for line in lines:
            assert dd_compositor._text_size(draw, line, font)[0] <= max_w
        # The title in the label band fits on one line too.
        title_w = dd_compositor._text_size(draw, label, dd_compositor._load_font(metrics.font_body))[0]
        assert title_w <= width - 2 * metrics.pad


class TestSelectorPickAndPage:
    def _opened_display(self, count=1):
        targets = [
            _target(name=f"T{i}", service_name=f"T{i}", appliance_id=str(i) * 20,
                     auth="authorized", playing_since=float(i))
            for i in range(count)
        ]
        display, fb, gt = make_display(targets=targets)
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        return display, fb, gt, targets

    def test_pick_sets_focus_and_closes(self):
        display, fb, gt, targets = self._opened_display(count=1)
        display.selector_pick(0)
        assert display.core.manual_focus_id() == "0" * 20
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"

    def test_stale_index_closes_without_setting_focus(self):
        display, fb, gt, targets = self._opened_display(count=1)
        display.selector_pick(5)  # out of range for a single row
        assert display.core.manual_focus_id() is None
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"

    def test_page_clamps_to_valid_range(self):
        display, fb, gt, targets = self._opened_display(count=5)  # rows_per_page == 3 -> pages 0, 1
        assert display._selector.page == 0

        display.list_page(-1)
        with display._lock:
            display._repaint_current_locked()
        assert display._selector.page == 0

        display.list_page(+5)
        with display._lock:
            display._repaint_current_locked()
        width, height = display._active_panel_dims()
        rows_per_page = list_layout_for(width, height).rows_per_page
        max_page = (len(targets) - 1) // rows_per_page
        assert display._selector.page == max_page

    def test_pick_addresses_the_current_page_not_page_zero(self):
        display, fb, gt, targets = self._opened_display(count=5)
        width, height = display._active_panel_dims()
        rows_per_page = list_layout_for(width, height).rows_per_page
        display.list_page(+1)
        with display._lock:
            display._repaint_current_locked()
        assert display._selector.page == 1

        display.selector_pick(0)  # row 0 of PAGE 1, not row 0 overall
        expected_id = targets[rows_per_page].appliance_id
        assert display.core.manual_focus_id() == expected_id


class TestListPagingMatchesPaintedRows:
    """Regression: the touch-thread page slice must use the SAME density-aware
    rows-per-page the repaint thread paints with. On a physically large panel
    whose short side puts it in the richer content tier the list paints five
    rows per page, not three; if the touch path still counts three, a tap on
    the fourth or fifth row reads as a miss and the second page starts rows
    late. Uses the 320x240 2.8-inch panel (band tall enough that the touch-
    floor veto does not pull it back to the base three-row layout)."""

    def _rich_opened(self, count):
        fb = FakeBackend()
        fb.width, fb.height = 320, 240
        targets = [
            _target(name=f"T{i}", service_name=f"T{i}", appliance_id=str(i) * 20,
                     auth="authorized", playing_since=float(i))
            for i in range(count)
        ]
        display, fb, gt = make_display(
            screen_type="ili9341_320x240", backend=fb, targets=targets,
        )
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        return display, fb, gt, targets

    def test_rows_per_page_matches_painted_metrics(self):
        display, fb, gt, targets = self._rich_opened(count=5)
        with display._lock:
            painted = display._metrics_locked().rows_per_page
        assert painted == 5  # richer tier on the 2.8-inch 320x240 panel
        assert display._rows_per_page() == painted

    def test_fourth_row_is_pickable_not_a_miss(self):
        display, fb, gt, targets = self._rich_opened(count=5)
        display.selector_pick(3)  # the fourth row of page 0
        assert display.core.manual_focus_id() == "3" * 20

    def test_second_page_starts_after_a_full_first_page(self):
        display, fb, gt, targets = self._rich_opened(count=6)
        display.list_page(+1)
        with display._lock:
            display._repaint_current_locked()
        assert display._selector.page == 1
        display.selector_pick(0)  # row 0 of PAGE 1 == the sixth target overall
        assert display.core.manual_focus_id() == "5" * 20


# ---------------------------------------------------------------------------
# Layout size — render at a logical size, resample to the panel. The None
# path is the regression corpus for byte-identity (see the pin below); the
# rest of this suite exercises a chosen size.
# ---------------------------------------------------------------------------

class TestResampleFilter:
    def test_shrinking_either_axis_uses_box(self):
        assert dd._resample_filter((640, 480), (320, 240)) is dd._RESAMPLE_BOX
        assert dd._resample_filter((640, 480), (640, 240)) is dd._RESAMPLE_BOX

    def test_growing_both_axes_uses_nearest(self):
        assert dd._resample_filter((160, 128), (320, 240)) is dd._RESAMPLE_NEAREST

    def test_equal_size_falls_on_the_nearest_branch(self):
        # Never actually reached in practice — _push_frame_locked skips the
        # call entirely when sizes already match — but the function's own
        # boundary behaviour is pinned here regardless.
        assert dd._resample_filter((320, 240), (320, 240)) is dd._RESAMPLE_NEAREST


class TestNoResizeWhenSizesMatch:
    """A composed size that already matches the physical panel is not resized,
    and _layout_metrics() equals metrics_for at the display's own density."""

    def test_no_resize_when_composed_size_already_matches_physical(self):
        fb = FakeBackend()
        fb.width, fb.height = 320, 240
        display, fb, gt = make_display(screen_type="ili9341_320x240", screen_size_inches=2.8, backend=fb)
        display.enable()
        fb.displayed.clear()
        sentinel = Image.new("RGB", (320, 240))
        with patch.object(display._compositor, "compose", return_value=sentinel), \
             patch("dial_display._resample_filter") as mock_resample:
            display._display_locked(sentinel)
        assert fb.displayed[-1] is sentinel
        mock_resample.assert_not_called()

    def test_layout_metrics_matches_metrics_for_default_formula(self):
        fb = FakeBackend()
        fb.width, fb.height = 320, 240
        display, fb, gt = make_display(screen_type="ili9341_320x240", screen_size_inches=2.8, backend=fb)
        display.enable()
        assert display._layout_metrics() == metrics_for(320, 240, mm_per_px=display._mm_per_px)


class TestRendersAtLogicalArrivesPhysical:
    def test_large_on_320x240_panel(self):
        fb = FakeBackend()
        fb.width, fb.height = 320, 240
        display, fb, gt = make_display(
            screen_type="ili9341_320x240", screen_size_inches=2.8, layout_size="large", backend=fb,
        )
        with patch("dial_display._resample_filter", wraps=dd._resample_filter) as spy:
            display.enable()
        assert display._current_base_image.size == (640, 480)
        assert fb.displayed[-1].size == (320, 240)
        spy.assert_called_with((640, 480), (320, 240))

    def test_small_on_320x240_panel(self):
        fb = FakeBackend()
        fb.width, fb.height = 320, 240
        display, fb, gt = make_display(
            screen_type="ili9341_320x240", screen_size_inches=2.8, layout_size="small", backend=fb,
        )
        display.enable()
        assert display._current_base_image.size == (160, 128)
        assert fb.displayed[-1].size == (320, 240)

    def test_medium_on_160x128_panel(self):
        fb = FakeBackend()
        fb.width, fb.height = 160, 128
        display, fb, gt = make_display(
            screen_type=DEFAULT_PROFILE_KEY, screen_size_inches=1.8, layout_size="medium", backend=fb,
        )
        display.enable()
        assert display._current_base_image.size == (320, 240)
        assert fb.displayed[-1].size == (160, 128)

    def test_large_artwork_poll_renders_at_logical_size(self):
        fb = FakeBackend()
        fb.width, fb.height = 320, 240
        t = _target()
        display, fb, gt = make_display(
            screen_type="ili9341_320x240", screen_size_inches=2.8, layout_size="large",
            backend=fb, targets=[t],
        )
        display.enable()
        fake_image = _marked_image(size=(640, 480))
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()
        assert display._current_rendered_image.size == (640, 480)
        assert fb.displayed[-1].size == (320, 240)


class TestMetricsFollowLayout:
    def test_large_on_320x240(self):
        display, fb, gt = make_display(
            screen_type="ili9341_320x240", screen_size_inches=2.8, layout_size="large",
        )
        m = display._layout_metrics()
        assert m.content_tier == "large"
        assert m.rows_per_page == 5
        assert m.supersample == 2
        assert m.mm_per_px == pytest.approx(0.0889, abs=1e-4)
        assert display._rows_per_page() == 5

    def test_small_on_320x240(self):
        display, fb, gt = make_display(
            screen_type="ili9341_320x240", screen_size_inches=2.8, layout_size="small",
        )
        m = display._layout_metrics()
        assert m.content_tier == "base"
        assert m.rows_per_page == 3
        assert display._rows_per_page() == 3


class TestArtworkGuardDropsStaleLayoutSizedFrame:
    def test_dropped_when_logical_size_changed_mid_fetch(self):
        fb = FakeBackend()
        fb.width, fb.height = 320, 240
        t = _target()
        display, fb, gt = make_display(
            screen_type="ili9341_320x240", screen_size_inches=2.8, backend=fb, targets=[t],
        )
        display.enable()
        before = len(fb.displayed)
        fake_image = _marked_image(size=(320, 240))
        # Simulates a layout_size change racing the fetch: _logical_dims()
        # returns the size active when the transform ran, then the new
        # (superseded) size for the guard check taken under the lock.
        with patch.object(display, "_logical_dims", side_effect=[(320, 240), (640, 480)]), \
             patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()
        assert display._current_rendered_image is None
        assert len(fb.displayed) == before


class TestUpdateConfigLayoutChange:
    def _opened_with_artwork(self, screen_type="ili9341_320x240", screen_size_inches=2.8):
        fb = FakeBackend()
        fb.width, fb.height = 320, 240
        t = _target()
        display, fb, gt = make_display(
            screen_type=screen_type, screen_size_inches=screen_size_inches, backend=fb, targets=[t],
        )
        display.enable()
        fake_image = _marked_image(size=(320, 240))
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()
        return display, fb, gt

    def test_none_to_large_drops_caches_and_shows_logo_at_new_size(self):
        display, fb, gt = self._opened_with_artwork()
        assert display._current_rendered_image is not None
        fb.displayed.clear()
        display._core._poll_wake.clear()

        status = display.update_config(DialDisplayConfig(
            fitted=True, screen_type="ili9341_320x240", screen_size_inches=2.8, layout_size="large",
        ))

        assert display._current_rendered_image is None
        assert display._source_artwork_key == ""
        assert display._screen == "main"
        assert len(fb.displayed) == 1
        assert display._current_base_image.size == (640, 480)
        assert fb.displayed[-1].size == (320, 240)
        assert display._core._poll_wake.is_set()

    def test_screen_size_only_change_still_redisplays_without_dropping_caches(self):
        display, fb, gt = self._opened_with_artwork()
        cached = display._current_rendered_image
        fb.displayed.clear()

        display.update_config(DialDisplayConfig(
            fitted=True, screen_type="ili9341_320x240", screen_size_inches=3.5,
        ))

        assert display._current_rendered_image is cached
        assert len(fb.displayed) == 1

    def test_none_to_none_other_field_change_does_not_drop_caches(self):
        display, fb, gt = self._opened_with_artwork()
        cached = display._current_rendered_image

        display.update_config(DialDisplayConfig(
            fitted=True, screen_type="ili9341_320x240", screen_size_inches=2.8, bgr=True,
        ))

        assert display._current_rendered_image is cached


class TestLayoutMetricsLockFree:
    def test_callable_while_lock_held_by_another_thread(self):
        display, fb, gt = make_display()
        result: dict = {}
        ready = threading.Event()
        release = threading.Event()

        def holder():
            with display._lock:
                ready.set()
                release.wait(timeout=2)

        t = threading.Thread(target=holder, daemon=True)
        t.start()
        try:
            assert ready.wait(timeout=2)
            result["metrics"] = display._layout_metrics()
        finally:
            release.set()
            t.join(timeout=2)
        assert "metrics" in result  # returned without blocking on self._lock


# ---------------------------------------------------------------------------
# Shared paging/list-state helpers — pure functions, exercised directly
# without a display instance where possible.
# ---------------------------------------------------------------------------

class TestClampPageAndPageSlice:
    def test_clamp_page_empty_rows_is_zero(self):
        assert dd._clamp_page(3, 0, 3) == 0

    def test_clamp_page_beyond_last_clamps(self):
        assert dd._clamp_page(10, 5, 3) == 1  # 5 rows at 3/page -> pages 0, 1

    def test_clamp_page_exact_multiple_has_no_extra_trailing_page(self):
        assert dd._clamp_page(2, 6, 3) == 1  # 6 rows at 3/page -> pages 0, 1 only

    def test_clamp_page_negative_clamps_to_zero(self):
        assert dd._clamp_page(-1, 5, 3) == 0

    def test_page_slice_returns_start_and_rows(self):
        rows = tuple(range(5))
        start, page_rows = dd._page_slice(rows, 1, 3)
        assert start == 3
        assert page_rows == (3, 4)

    def test_page_slice_stale_page_yields_empty_tuple(self):
        rows = tuple(range(5))
        _, page_rows = dd._page_slice(rows, 5, 3)  # well past the last page
        assert page_rows == ()


class TestListStateForHelper:
    def test_none_state_gives_placeholder(self):
        state = dd._list_state_for(None, 3, "No rows", lambda r: (r, False))
        assert state.rows == (("No rows", False),)
        assert state.has_prev is False
        assert state.has_next is False

    def test_empty_state_gives_placeholder(self):
        selector = dd.SelectorState(rows=(), page=0, opened_at=0.0)
        state = dd._list_state_for(selector, 3, "No devices", dd._selector_list_row)
        assert state.rows == (("No devices", False),)
        assert state.has_prev is False
        assert state.has_next is False

    def test_playing_selector_row_maps_to_play_glyph_triple(self):
        rows = (dd.SelectorRow(appliance_id="a", label="A", current=False, playing=True),)
        selector = dd.SelectorState(rows=rows, page=0, opened_at=0.0)
        state = dd._list_state_for(selector, 3, "No devices", dd._selector_list_row)
        assert state.rows == (("A", False, dd.PLAY_GLYPH),)

    def test_non_playing_selector_row_maps_to_pair(self):
        rows = (dd.SelectorRow(appliance_id="a", label="A", current=True, playing=False),)
        selector = dd.SelectorState(rows=rows, page=0, opened_at=0.0)
        state = dd._list_state_for(selector, 3, "No devices", dd._selector_list_row)
        assert state.rows == (("A", True),)

    def test_picker_row_maps_to_label_and_formatted_duration(self):
        rows = (dd.PickerRow(appliance_id="a", service_name="A", ip="1.2.3.4", port=80,
                              label="A", seconds=90.0),)
        picker = dd.PickerState(rows=rows, page=0, opened_at=0.0)
        state = dd._list_state_for(picker, 3, "Nothing to replay", dd._picker_list_row)
        assert state.rows == (("A", False, "1:30"),)

    def test_has_next_true_only_when_rows_remain_after_the_page(self):
        rows = tuple(
            dd.SelectorRow(appliance_id=str(i), label=str(i), current=False)
            for i in range(4)
        )
        first_page = dd._list_state_for(
            dd.SelectorState(rows=rows, page=0, opened_at=0.0), 3, "No devices", dd._selector_list_row,
        )
        assert first_page.has_next is True
        second_page = dd._list_state_for(
            dd.SelectorState(rows=rows, page=1, opened_at=0.0), 3, "No devices", dd._selector_list_row,
        )
        assert second_page.has_next is False

    def test_pressed_defaults_to_none(self):
        selector = dd.SelectorState(
            rows=(dd.SelectorRow(appliance_id="a", label="A", current=False),), page=0, opened_at=0.0,
        )
        state = dd._list_state_for(selector, 3, "No devices", dd._selector_list_row)
        assert state.pressed is None

    def test_pressed_passes_through_unchanged(self):
        selector = dd.SelectorState(
            rows=(dd.SelectorRow(appliance_id="a", label="A", current=False),), page=0, opened_at=0.0,
        )
        state = dd._list_state_for(
            selector, 3, "No devices", dd._selector_list_row, pressed=(TouchZone.LIST_ROW, 1),
        )
        assert state.pressed == (TouchZone.LIST_ROW, 1)


class TestCurrentPageRows:
    def test_selector_state_page_one(self):
        display, fb, gt = make_display(targets=[])
        rows = tuple(dd.SelectorRow(appliance_id=str(i), label=str(i), current=False) for i in range(5))
        selector = dd.SelectorState(rows=rows, page=1, opened_at=0.0)
        page_rows = display._current_page_rows(selector)
        assert [r.appliance_id for r in page_rows] == ["3", "4"]

    def test_picker_state_page_one(self):
        display, fb, gt = make_display(targets=[])
        rows = tuple(
            dd.PickerRow(appliance_id=str(i), service_name=str(i), ip="1.2.3.4", port=80,
                         label=str(i), seconds=float(i))
            for i in range(5)
        )
        picker = dd.PickerState(rows=rows, page=1, opened_at=0.0)
        page_rows = display._current_page_rows(picker)
        assert [r.appliance_id for r in page_rows] == ["3", "4"]


class TestDisplayListLockedRouting:
    def test_picker_screen_routes_to_the_picker_builder(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with patch.object(
            display._compositor, "compose_list", wraps=display._compositor.compose_list,
        ) as spy:
            with display._lock:
                display._screen = "picker"
                display._display_list_locked()
        assert spy.call_count == 1
        assert spy.call_args[0][2].rows == (("Nothing to replay", False),)

    def test_selector_screen_routes_to_the_selector_builder(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with patch.object(
            display._compositor, "compose_list", wraps=display._compositor.compose_list,
        ) as spy:
            with display._lock:
                display._screen = "selector"
                display._display_list_locked()
        assert spy.call_count == 1
        assert spy.call_args[0][2].rows == (("No devices", False),)


class TestSelectorTimeout:
    def _opened_display(self):
        a = _target(name="A", service_name="A", appliance_id="a" * 20, auth="authorized")
        display, fb, gt = make_display(targets=[a])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        return display

    def test_closes_after_timeout_of_inactivity(self):
        display = self._opened_display()
        opened_at = display._selector.opened_at
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS + 1):
            display._check_secondary_timeout()
        assert display._screen == "main"

    def test_stays_open_before_the_timeout(self):
        display = self._opened_display()
        opened_at = display._selector.opened_at
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS - 1):
            display._check_secondary_timeout()
        assert display._screen == "selector"

    def test_touch_activity_refreshes_the_deadline(self):
        display = self._opened_display()
        opened_at = display._selector.opened_at
        with patch("dial_display.time.monotonic", return_value=opened_at + 10):
            display.notify_touch_activity()
            with display._lock:
                display._repaint_current_locked()
        assert display._selector.opened_at == opened_at + 10

        # Well past the ORIGINAL deadline, but still short of a fresh one.
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS + 1):
            display._check_secondary_timeout()
        assert display._screen == "selector"


class TestSelectorAndSleepBackendLifecycle:
    def test_open_selector_defers_the_sleep_decision_like_the_picker(self):
        a = _target(name="A", service_name="A", appliance_id="a" * 20, auth="authorized")
        display, fb, gt = make_display(targets=[a])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "selector"

        gt.return_value = []  # nothing playing any more
        display._poll_once()
        # An open selector is never closed by a poll finding nothing
        # playing — only its own inactivity timeout does that.
        assert display._screen == "selector"
        assert display._selector is not None

    def test_selector_closed_by_timeout_then_next_idle_poll_sleeps(self):
        a = _target(name="A", service_name="A", appliance_id="a" * 20, auth="authorized")
        display, fb, gt = make_display(targets=[a])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "selector"

        gt.return_value = []  # nothing playing any more
        opened_at = display._selector.opened_at
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS + 1):
            display._check_secondary_timeout()
        assert display._screen == "main"

        # A whole second, so t0 + the sleep delay - t0 is exactly the delay:
        # with an arbitrary float clock reading that difference can round
        # to just under it and the threshold poll would not sleep.
        t0 = float(math.ceil(opened_at + SELECTOR_TIMEOUT_SECONDS + 1))
        with patch("dial_display.time.monotonic", return_value=t0):
            display._poll_once()  # starts the idle countdown now the list is closed
        assert display._display_sleeping is False

        with patch("dial_display.time.monotonic", return_value=t0 + dd.DISPLAY_IDLE_SLEEP_SECONDS):
            display._poll_once()
        assert display._display_sleeping is True

    def test_sleep_pops_to_main(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "selector"

        with display._lock:
            display._sleep_locked()
        assert display._screen == "main"
        assert display._selector is None

    def test_disable_pops_to_main(self):
        a = _target(name="A", service_name="A", appliance_id="a" * 20, auth="authorized")
        display, fb, gt = make_display(targets=[a])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "selector"

        display.disable()
        assert display._screen == "main"

    def test_swap_backend_pops_to_main(self):
        a = _target(name="A", service_name="A", appliance_id="a" * 20, auth="authorized")
        display, fb, gt = make_display(targets=[a])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "selector"

        with display._lock:
            display._swap_backend_locked()
        assert display._screen == "main"


class TestTouchSurface:
    def test_selector_while_open(self):
        a = _target(name="A", service_name="A", appliance_id="a" * 20, auth="authorized")
        display, fb, gt = make_display(targets=[a])
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        assert display.touch_surface() == ("selector", False, False, False)

    def test_hidden_with_name_active_when_something_is_playing(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.touch_surface() == ("hidden", True, False, False)

    def test_held_with_name_active(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.touch_surface() == ("held", True, False, False)

    def test_idle_with_name_inactive_when_nothing_playing(self):
        # The idle screen is one screen whenever nothing plays: the "i"
        # affordance must be reachable even with no replay held, so
        # the surface is "idle" here, not "hidden".
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._poll_once()
        assert display.touch_surface() == ("idle", False, False, False)

    def test_idle_when_affordance_drawn(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._poll_once()
        with display._lock:
            display.core.set_field("idle_affordance", True)
        assert display.touch_surface() == ("idle", False, False, False)

    def test_idle_regardless_of_affordance_when_nothing_playing(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.core.set_field("idle_affordance", False)
        display._poll_once()
        assert display.touch_surface()[0] == "idle"

    def test_repeat_screen_reports_repeat_with_dots_active(self):
        aid = "1" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        import dial_repeat_store as drs
        drs.repeat_store.update(aid, drs.RepeatRecord(
            available=True, state="recording", armed=False,
            recording_seconds=0.0, position_seconds=0.0, duration_seconds=0.0,
            observed_at=time.monotonic(),
        ))
        with display._lock:
            display._screen = "repeat"
        assert display.touch_surface() == ("repeat", True, True, False)

    def test_repeat_screen_outputs_active_follows_live_availability(self):
        aid = "1" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with display._lock:
            display._screen = "repeat"
            display.core.set_field("outputs_available", True)
        assert display.touch_surface() == ("repeat", True, True, True)
        with display._lock:
            display.core.set_field("outputs_available", False)
        assert display.touch_surface() == ("repeat", True, True, False)

    def test_picker_while_open(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "picker"
        assert display.touch_surface() == ("picker", False, False, False)

    def test_dots_active_reflects_fresh_available_record(self):
        aid = "2" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        import dial_repeat_store as drs
        result = _status_result(track_id=None, appliance_id=aid)
        result["repeat"] = {
            "available": True, "state": "idle", "armed": False, "held": False,
            "recording_seconds": 0.0,
            "replay": {"active": False, "position_seconds": 0.0, "duration_seconds": 0.0},
        }
        with patch("dial_core.fetch_target_status", return_value=result):
            display._poll_once()
        assert display.core.snapshot().dots_active is True
        surface, name_active, dots_active, outputs_active = display.touch_surface()
        assert dots_active is True

    def test_dots_inactive_when_record_unavailable(self):
        aid = "3" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=None, appliance_id=aid)
        with patch("dial_core.fetch_target_status", return_value=result):
            display._poll_once()
        assert display.core.snapshot().dots_active is False

    def test_idle_and_name_inactive_with_an_idle_roster_entry_but_nothing_shown(self):
        # An authorised idle appliance existing on the roster is not, by
        # itself, an entry point into the selector — the NAME zone stays
        # inert until something is actually shown (playing, or focused).
        # The surface itself is still "idle" (reachable regardless of
        # replay availability).
        idle_entry = _roster_entry(name="Kitchen", auth="authorized", playing=False)
        display, fb, gt = make_display(targets=[], roster=[idle_entry])
        display.enable()
        display._poll_once()
        assert display.touch_surface() == ("idle", False, False, False)

    def test_idle_affordance_still_drawn_with_an_idle_roster_entry(self):
        idle_entry = _roster_entry(name="Kitchen", auth="authorized", playing=False)
        display, fb, gt = make_display(targets=[], roster=[idle_entry])
        display.enable()
        display._poll_once()
        with display._lock:
            display.core.set_field("idle_affordance", True)
        assert display.touch_surface() == ("idle", False, False, False)

    def test_hidden_with_name_active_once_an_idle_focus_is_set(self):
        aid = "9" * 19 + "2"
        idle_entry = _roster_entry(name="Kitchen", service_name="Kitchen", appliance_id=aid, auth="authorized",
                                    playing=False)
        display, fb, gt = make_display(targets=[], roster=[idle_entry])
        display.enable()
        display.core.set_focus(aid)
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid)):
            display._poll_once()
        assert display.touch_surface() == ("hidden", True, False, False)

    def test_held_with_name_active_once_an_idle_focus_is_set_and_always_show(self):
        aid = "9" * 19 + "3"
        idle_entry = _roster_entry(name="Kitchen", service_name="Kitchen", appliance_id=aid, auth="authorized",
                                    playing=False)
        display, fb, gt = make_display(targets=[], roster=[idle_entry], always_show_controls=True)
        display.enable()
        display.core.set_focus(aid)
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid)):
            display._poll_once()
        assert display.touch_surface() == ("held", True, False, False)


class TestOverlayNameField:
    def test_name_populated_from_reporting_target_when_visible(self):
        t = _target(name="CD_Player", service_name="autostream on CD_Player")
        display, fb, gt = make_display(targets=[t])
        display.enable()
        _poll_with_artwork(display, fb)
        display.set_overlay(OverlayState(visible=True))
        with display._lock:
            overlay = display._effective_overlay_locked(display._overlay_snapshot)
        assert overlay.name == "CD Player"

    def test_name_empty_when_nothing_playing(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._poll_once()
        display.set_overlay(OverlayState(visible=True))
        with display._lock:
            overlay = display._effective_overlay_locked(display._overlay_snapshot)
        assert overlay.name == ""

    def test_name_active_unconditional_with_a_single_authorized_appliance(self):
        # Q4: the name (and its tap-zone) are always active whenever a
        # controllable appliance is shown, including the single-appliance
        # case — never gated on "two or more authorized" rows.
        t = _target(name="Solo", service_name="Solo", appliance_id="a" * 20, auth="authorized")
        display, fb, gt = make_display(targets=[t])
        display.enable()
        _poll_with_artwork(display, fb)
        assert len(display._selector.rows) == 1
        assert display.touch_surface() == ("hidden", True, False, False)


# ---------------------------------------------------------------------------
# Repeat screen: opening/closing, the ring/transport taps, its own compose
# path, no inactivity timeout, and closing when the focused appliance's
# manual focus clears.
# ---------------------------------------------------------------------------

def _poll_focused_with_repeat(display, fb, aid, repeat_obj):
    """Drive one poll that identifies artwork for appliance_id=aid and
    feeds repeat_obj into the store for it — leaves _now_playing and
    _reporting_appliance_id set to aid, mirroring toggle_repeat_screen()'s
    own precondition for opening."""
    fake_image = Image.new("RGB", (fb.width, fb.height))
    result = _status_result(track_id=_track_id(), appliance_id=aid)
    result["repeat"] = repeat_obj
    with patch("dial_core.fetch_target_status", return_value=result), \
         patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
         patch("dial_display.decode_artwork", return_value=fake_image), \
         patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
        display._poll_once()


class TestToggleRepeatScreen:
    def test_opens_when_record_available(self):
        aid = "1" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))

        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"
        assert display._repeat_screen.appliance_id == aid

    def test_does_not_open_with_no_record(self):
        aid = "2" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(), appliance_id=aid)):
            display._poll_once()

        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"

    def test_does_not_open_when_record_unavailable(self):
        aid = "3" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(available=False, state="idle"))

        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"

    def test_does_not_open_with_nothing_playing(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._poll_once()
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"

    def test_second_tap_closes_it(self):
        aid = "4" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"
        assert display._repeat_screen is None

    def test_close_arms_the_reveal_flag_open_does_not(self):
        """Item 1: closing the repeat screen via toggle_repeat_screen()
        (the DOTS tap) must arm the one-shot reveal flag the touch side
        consumes to bring back the main screen's volume overlay; opening
        it must not."""
        aid = "11" * 10
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))

        display.cycle_pages()  # open
        assert display.consume_repeat_close_reveal() is False

        with display._lock:
            display._repaint_current_locked()
        display.cycle_pages()  # close
        assert display.consume_repeat_close_reveal() is True
        # Read-and-clear: a second read finds nothing left to consume.
        assert display.consume_repeat_close_reveal() is False


class TestRepeatScreenTouchEntries:
    def _opened(self, state="idle", armed=False, appliance_id="5" * 20):
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=appliance_id)
        display, fb, gt = make_display(targets=[t], repeat_capable=True)
        display.enable()
        _poll_focused_with_repeat(display, fb, appliance_id, _repeat_obj(state=state, armed=armed))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"
        return display, appliance_id

    def test_toggle_tap_arms_in_idle(self):
        display, aid = self._opened(state="idle", armed=False)
        with patch("dial_core.enqueue_arm") as mock_arm:
            display.repeat_toggle_tap()
        mock_arm.assert_called_once()
        target, armed, token = mock_arm.call_args[0]
        assert target.appliance_id == aid
        assert armed is True
        assert token == display.core.snapshot().transport.requested_at

    def test_toggle_tap_disarms_when_already_armed(self):
        display, aid = self._opened(state="recording", armed=True)
        with patch("dial_core.enqueue_arm") as mock_arm:
            display.repeat_toggle_tap()
        mock_arm.assert_called_once()
        _, armed, _token = mock_arm.call_args[0]
        assert armed is False

    def test_toggle_tap_ignored_while_replaying(self):
        display, aid = self._opened(state="replaying")
        with patch("dial_core.enqueue_arm") as mock_arm:
            display.repeat_toggle_tap()
        mock_arm.assert_not_called()

    def test_start_tap_seeks_zero_while_hold(self):
        display, aid = self._opened(state="hold")
        with patch("dial_core.enqueue_transport") as mock_transport:
            display.repeat_start_tap()
        mock_transport.assert_called_once()
        target, action, position, token = mock_transport.call_args[0]
        assert target.appliance_id == aid
        assert action == "seek"
        assert position == 0.0

    def test_start_tap_seeks_zero_while_replaying(self):
        display, aid = self._opened(state="replaying")
        with patch("dial_core.enqueue_transport") as mock_transport:
            display.repeat_start_tap()
        mock_transport.assert_called_once()

    def test_start_tap_ignored_while_recording(self):
        display, aid = self._opened(state="recording")
        with patch("dial_core.enqueue_transport") as mock_transport:
            display.repeat_start_tap()
        mock_transport.assert_not_called()

    def test_stop_tap_stops_while_replaying(self):
        display, aid = self._opened(state="replaying")
        with patch("dial_core.enqueue_transport") as mock_transport:
            display.repeat_stop_tap()
        mock_transport.assert_called_once()
        target, action, position, token = mock_transport.call_args[0]
        assert target.appliance_id == aid
        assert action == "stop"

    def test_stop_tap_ignored_while_hold(self):
        display, aid = self._opened(state="hold")
        with patch("dial_core.enqueue_transport") as mock_transport:
            display.repeat_stop_tap()
        mock_transport.assert_not_called()

    def test_taps_are_noop_when_screen_not_open(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with patch("dial_core.enqueue_arm") as mock_arm, \
             patch("dial_core.enqueue_transport") as mock_transport:
            display.repeat_toggle_tap()
            display.repeat_start_tap()
            display.repeat_stop_tap()
        mock_arm.assert_not_called()
        mock_transport.assert_not_called()


class TestRepeatScreenComposePath:
    def _opened(self, state="idle", appliance_id="6" * 20):
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=appliance_id)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, appliance_id, _repeat_obj(state=state))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        return display, fb, gt, appliance_id

    def test_own_compose_path_used_never_the_main_overlay(self):
        display, fb, gt, aid = self._opened()
        with patch.object(display._compositor, "compose") as mock_compose, \
             patch.object(display._compositor, "compose_repeat",
                          wraps=display._compositor.compose_repeat) as mock_compose_repeat:
            display.set_overlay(OverlayState(visible=True))
            with display._lock:
                display._repaint_current_locked()
        mock_compose.assert_not_called()
        assert mock_compose_repeat.call_count >= 1

    def test_no_inactivity_timeout(self):
        display, fb, gt, aid = self._opened()
        opened_at = time.monotonic()
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS + 100):
            display._check_secondary_timeout()
        assert display._screen == "repeat"

    def test_closes_when_manual_focus_clears(self):
        aid = "7" * 20
        focus_t = _target(name="Focus", service_name="Focus", appliance_id=aid, playing_since=1.0)
        display, fb, gt = make_display(targets=[focus_t])
        display.enable()
        display.core.set_focus(aid)
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle"))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

        gt.return_value = []  # the appliance leaves the roster entirely
        display._poll_once()
        assert display.core.manual_focus_id() is None
        assert display._screen == "main"

    def test_closes_on_mid_tick_unauthorized_clear(self):
        aid = "8" * 20
        focus_t = _target(name="Focus", service_name="Focus", appliance_id=aid, playing_since=1.0)
        other_t = _target(name="Other", service_name="Other", playing_since=5.0)
        display, fb, gt = make_display(targets=[focus_t, other_t])
        display.enable()
        display.core.set_focus(aid)
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle"))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

        def fake_fetch(target, dial_id, timeout_seconds):
            if target is focus_t:
                return _status_result(status_error="unauthorized", appliance_id=aid)
            return _status_result(track_id=_track_id())

        with patch("dial_core.fetch_target_status", side_effect=fake_fetch):
            display._poll_once()

        assert display.core.manual_focus_id() is None
        assert display._screen == "main"

    def test_sleep_pops_repeat_screen(self):
        display, fb, gt, aid = self._opened()
        assert display._screen == "repeat"
        with display._lock:
            display._sleep_locked()
        assert display._screen == "main"
        assert display._repeat_screen is None

    def test_sleep_pops_picker(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.core.set_field("idle_affordance", True)
        display.open_picker()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "picker"
        with display._lock:
            display._sleep_locked()
        assert display._screen == "main"
        assert display._picker is None


class TestRepeatViewTopBandAndBaseImage:
    """Item 3 (the top band's muted/volume readout) and item 6 (the
    replaying layout's artwork/logo base image), as fed by
    _build_repeat_view_locked()/_display_repeat_locked()."""

    def _opened(self, state="idle", appliance_id="12" * 10):
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=appliance_id)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, appliance_id, _repeat_obj(state=state))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        return display, appliance_id

    def test_muted_and_volume_fed_from_the_repeat_screens_own_appliance(self):
        display, aid = self._opened(state="idle")
        with patch("dial_display.shown_muted", return_value=True) as mock_shown_muted, \
             patch("dial_display.shown_volume", return_value=37) as mock_shown_volume:
            with display._lock:
                view = display._build_repeat_view_locked(display._repeat_screen, time.monotonic())
        assert view.muted is True
        assert view.volume == 37
        mock_shown_muted.assert_called_once_with("Kitchen")
        mock_shown_volume.assert_called_once_with("Kitchen")

    def test_base_image_passed_through_to_compose_repeat(self):
        display, aid = self._opened(state="hold")
        sentinel_image = object()
        with display._lock:
            display._current_base_image = sentinel_image
        with patch.object(display._compositor, "compose_repeat", wraps=display._compositor.compose_repeat) as mock:
            with display._lock:
                display._display_repeat_locked()
        assert mock.call_args.kwargs["base"] is sentinel_image


class TestRepeatCounterLatency:
    """Item 8: the replaying position counter lags the true position by
    REPEAT_COUNTER_LATENCY_S, clamped at zero."""

    def _opened_replaying(self, position_seconds, appliance_id="13" * 10):
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=appliance_id)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(
            display, fb, appliance_id,
            _repeat_obj(
                state="replaying", armed=True,
                replay={"active": True, "position_seconds": position_seconds, "duration_seconds": 30.0},
            ),
        )
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        return display, appliance_id

    def test_reads_zero_for_the_first_latency_window_after_a_restart(self):
        display, aid = self._opened_replaying(position_seconds=1.0)
        with display._lock:
            view = display._build_repeat_view_locked(display._repeat_screen, time.monotonic())
        assert view.line.startswith("0:00 / ")

    def test_lags_the_true_position_once_past_the_latency_window(self):
        display, aid = self._opened_replaying(position_seconds=10.0)
        with display._lock:
            view = display._build_repeat_view_locked(display._repeat_screen, time.monotonic())
        # 10.0 true seconds in, minus the REPEAT_COUNTER_LATENCY_S lag —
        # allow the interpolation's own elapsed-time nudge either side of
        # the expected second by comparing the parsed minutes:seconds
        # rather than the exact string.
        shown = view.line.split(" / ")[0]
        minutes, seconds = (int(p) for p in shown.split(":"))
        shown_seconds = minutes * 60 + seconds
        assert shown_seconds == pytest.approx(10.0 - dd.REPEAT_COUNTER_LATENCY_S, abs=1)

    def test_hold_layout_already_reads_zero(self):
        aid = "14" * 10
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="hold"))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
            view = display._build_repeat_view_locked(display._repeat_screen, time.monotonic())
        assert view.line.startswith("0:00 / ")


class TestRepeatLineInterpolation:
    def test_wraps_at_duration_plus_loop_gap(self):
        import dial_repeat_store as drs
        rec = drs.RepeatRecord(
            available=True, state="replaying", armed=True,
            recording_seconds=10.0, position_seconds=9.0, duration_seconds=10.0,
            observed_at=100.0,
        )
        # 100.0 + 3.0 elapsed = 12.0 raw; wraps at (10 + 1.5) = 11.5 -> 0.5,
        # then clamped to <= duration (already under it).
        pos = dd._interpolate_repeat_position(rec, now=103.0)
        assert pos == pytest.approx(0.5)

    def test_clamped_to_duration_within_the_gap_window(self):
        import dial_repeat_store as drs
        rec = drs.RepeatRecord(
            available=True, state="replaying", armed=True,
            recording_seconds=10.0, position_seconds=9.5, duration_seconds=10.0,
            observed_at=100.0,
        )
        # 100.0 + 0.7 = 10.2 raw, under the 11.5 wrap point, but past
        # duration (10.0) — clamped, not wrapped, since it is still within
        # the inter-loop gap.
        pos = dd._interpolate_repeat_position(rec, now=100.7)
        assert pos == pytest.approx(10.0)

    def test_never_negative(self):
        import dial_repeat_store as drs
        rec = drs.RepeatRecord(
            available=True, state="replaying", armed=True,
            recording_seconds=10.0, position_seconds=0.0, duration_seconds=0.0,
            observed_at=100.0,
        )
        pos = dd._interpolate_repeat_position(rec, now=99.0)  # clock went backwards
        assert pos >= 0.0

    def _open_repeat_screen_directly(self, display, aid):
        """Set up the repeat screen's own state without going through a
        real poll, so the clock driving the replaying position can be
        fully controlled by the test."""
        with display._lock:
            display._screen = "repeat"
            display._repeat_screen = dd.RepeatScreenState(
                appliance_id=aid, service_name="Kitchen", ip="10.0.0.1", port=80, opened_at=1000.0,
            )

    def _seed_replaying(self, aid, position_seconds, observed_at=1000.0):
        import dial_repeat_store as drs
        drs.repeat_store.update(aid, drs.RepeatRecord(
            available=True, state="replaying", armed=True,
            recording_seconds=30.0, position_seconds=position_seconds, duration_seconds=30.0,
            observed_at=observed_at,
        ))

    def test_tick_repeat_line_signals_at_the_boundary(self):
        aid = "9" * 20
        display, fb, gt = make_display(targets=[])
        display.enable()
        self._open_repeat_screen_directly(display, aid)
        self._seed_replaying(aid, position_seconds=5.0, observed_at=1000.0)
        display._repeat_painted_second = 3
        # shown(now) = position + elapsed - REPEAT_COUNTER_LATENCY_S
        #            = 5.0 + 1.002 - 2.0 = 4.002 -- just past the 4.0 boundary.
        display._overlay_signal.clear()
        with patch("dial_display.time.monotonic", return_value=1001.002):
            display._tick_repeat_line()
        assert display._overlay_signal.is_set()

    def test_tick_repeat_line_does_not_signal_mid_second(self):
        aid = "9" * 20
        display, fb, gt = make_display(targets=[])
        display.enable()
        self._open_repeat_screen_directly(display, aid)
        self._seed_replaying(aid, position_seconds=5.0, observed_at=1000.0)
        display._repeat_painted_second = 4
        # shown(now) = 5.0 + 1.5 - 2.0 = 4.5 -- mid-second, 4 already painted, not due.
        display._overlay_signal.clear()
        with patch("dial_display.time.monotonic", return_value=1001.5):
            display._tick_repeat_line()
        assert not display._overlay_signal.is_set()

    def test_tick_repeat_line_noop_while_hold(self):
        aid = "10" * 10
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="hold"))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

        display._overlay_signal.clear()
        display._tick_repeat_line()
        assert not display._overlay_signal.is_set()


class TestNextRepaintDeadline:
    def _seed(self, aid, position_seconds, observed_at=1000.0):
        import dial_repeat_store as drs
        drs.repeat_store.update(aid, drs.RepeatRecord(
            available=True, state="replaying", armed=True,
            recording_seconds=30.0, position_seconds=position_seconds, duration_seconds=30.0,
            observed_at=observed_at,
        ))

    def _opened(self, aid):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "repeat"
            display._repeat_screen = dd.RepeatScreenState(
                appliance_id=aid, service_name="Kitchen", ip="10.0.0.1", port=80, opened_at=1000.0,
            )
        return display

    @pytest.mark.parametrize("shown, expected_remaining", [(2.3, 0.7), (2.999, 0.001), (3.0, 1.0)])
    def test_boundary_offset_from_shown_position(self, shown, expected_remaining):
        aid = "d" * 20
        display = self._opened(aid)
        # Chosen so shown(now) == `shown` exactly: shown = position +
        # elapsed - REPEAT_COUNTER_LATENCY_S, with elapsed fixed at 1.0.
        position = shown + dd.REPEAT_COUNTER_LATENCY_S - 1.0
        self._seed(aid, position_seconds=position, observed_at=1000.0)
        display._repeat_painted_second = math.floor(shown)
        now = 1001.0
        with patch("dial_display.time.monotonic", return_value=now):
            deadline = display._next_repaint_deadline()
        assert deadline == pytest.approx(now + expected_remaining + 0.005, abs=1e-6)

    def test_none_when_nothing_scheduled(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        assert display._next_repaint_deadline() is None

    def test_none_while_hold_not_replaying(self):
        aid = "f" * 20
        display = self._opened(aid)
        import dial_repeat_store as drs
        drs.repeat_store.update(aid, drs.RepeatRecord(
            available=True, state="hold", armed=False,
            recording_seconds=30.0, position_seconds=0.0, duration_seconds=30.0,
            observed_at=1000.0,
        ))
        with patch("dial_display.time.monotonic", return_value=1000.0):
            assert display._next_repaint_deadline() is None

    def test_controls_hidden_deadline_alone(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._controls_hidden_until = 1000.2
        with patch("dial_display.time.monotonic", return_value=1000.0):
            deadline = display._next_repaint_deadline()
        assert deadline == pytest.approx(1000.205)

    def test_earlier_of_repeat_and_controls_hidden_wins(self):
        aid = "e" * 20
        display = self._opened(aid)
        # shown(1000.0) == 2.0 exactly -> repeat deadline is 1000.0 + 1.0 + 0.005.
        self._seed(aid, position_seconds=2.0 + dd.REPEAT_COUNTER_LATENCY_S, observed_at=1000.0)
        display._repeat_painted_second = 2
        display._controls_hidden_until = 1000.3
        with patch("dial_display.time.monotonic", return_value=1000.0):
            deadline = display._next_repaint_deadline()
        assert deadline == pytest.approx(1000.305)


class TestRepeatCounterFloors:
    """The replaying position line floors rather than rounds, so the
    displayed second only ever advances once the full second has
    elapsed."""

    def test_position_floors_not_rounds(self):
        import dial_repeat_store as drs
        aid = "20" * 10
        display, fb, gt = make_display(targets=[])
        display.enable()
        screen = dd.RepeatScreenState(
            appliance_id=aid, service_name="Kitchen", ip="10.0.0.1", port=80, opened_at=1000.0,
        )
        for position, expected in [(2.0, "0:00"), (2.9, "0:00"), (3.0, "0:01"), (3.9, "0:01")]:
            drs.repeat_store.update(aid, drs.RepeatRecord(
                available=True, state="replaying", armed=True,
                recording_seconds=30.0, position_seconds=position,
                duration_seconds=30.0, observed_at=1000.0,
            ))
            with display._lock:
                view = display._build_repeat_view_locked(screen, 1000.0)
            assert view.line.startswith(expected + " / "), (position, view.line)

    def test_the_counter_follows_the_records_own_latency(self):
        import dial_repeat_store as drs
        aid = "22" * 10
        display, fb, gt = make_display(targets=[])
        display.enable()
        screen = dd.RepeatScreenState(
            appliance_id=aid, service_name="Kitchen", ip="10.0.0.1", port=80, opened_at=1000.0,
        )
        # (latency, reported position, expected counter)
        for latency, position, expected in [
            (0.3, 0.2, "0:00"), (0.3, 1.2, "0:00"), (0.3, 1.3, "0:01"), (0.3, 2.4, "0:02"),
            (3.5, 3.4, "0:00"), (3.5, 4.4, "0:00"), (3.5, 4.5, "0:01"), (3.5, 6.5, "0:03"),
            (3.5, 0.0, "0:00"),
        ]:
            drs.repeat_store.update(aid, drs.RepeatRecord(
                available=True, state="replaying", armed=True,
                recording_seconds=30.0, position_seconds=position,
                duration_seconds=30.0, observed_at=1000.0, latency_seconds=latency,
            ))
            with display._lock:
                view = display._build_repeat_view_locked(screen, 1000.0)
            assert view.line.startswith(expected + " / "), (latency, position, view.line)

    def test_the_counter_value_is_the_heard_position(self):
        import dial_repeat_store as drs
        rec = drs.RepeatRecord(
            available=True, state="replaying", armed=True, recording_seconds=30.0,
            position_seconds=1.0, duration_seconds=30.0, observed_at=1000.0,
            latency_seconds=3.5,
        )
        assert dd._repeat_counter_value(rec, 1000.0) == pytest.approx(-2.5)
        assert dd._repeat_counter_value(rec, 1005.0) == pytest.approx(2.5)


class TestRepeatCounterPaintedReference:
    """The replaying counter advances against the second last painted, not
    against a precomputed boundary: a late wake, a status re-sync that
    shifts the interpolated clock, or a signal repaint that straddles a
    boundary must never skip or repeat a second, and a small backward
    re-sync must never step the line back."""

    AID = "21" * 10
    DUR = 30.0

    def _opened(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "repeat"
            display._repeat_screen = dd.RepeatScreenState(
                appliance_id=self.AID, service_name="Kitchen", ip="10.0.0.1", port=80, opened_at=1000.0,
            )
        return display

    def _seed(self, position, observed_at, state="replaying"):
        import dial_repeat_store as drs
        drs.repeat_store.update(self.AID, drs.RepeatRecord(
            available=True, state=state, armed=True,
            recording_seconds=self.DUR, position_seconds=position, duration_seconds=self.DUR,
            observed_at=observed_at,
        ))

    def _resync(self, clock, shift):
        """What a status poll does: install a fresh record stamped now whose
        interpolated clock is `shift` seconds ahead (negative: behind) of
        the current record's."""
        import dial_repeat_store as drs
        rec = drs.repeat_store.get(self.AID, clock.t)
        self._seed(dd._interpolate_repeat_position(rec, clock.t) + shift, clock.t)

    def _paint(self, display):
        with display._lock:
            display._repaint_current_locked()
        return display._repeat_painted_second

    def _line(self, display, clock):
        with display._lock:
            return display._build_repeat_view_locked(display._repeat_screen, clock.t).line

    def _run(self, display, clock, seconds, *, late=0.0, before_tick=None):
        """_repaint_run's own sequence, without threads: deadline, wake at
        it (capped a second out, as the loop caps its wait), optional
        interference, tick, paint if signalled. Returns the seconds
        painted, in order."""
        painted = []
        end = clock.t + seconds
        steps = 0
        while clock.t < end:
            steps += 1
            assert steps < 10_000, "repaint loop did not converge"
            deadline = display._next_repaint_deadline()
            assert deadline is not None
            clock.t = max(clock.t, min(deadline, clock.t + 1.0)) + late
            if before_tick is not None:
                before_tick(clock)
            display._overlay_signal.clear()
            display._tick_repeat_line()
            if display._overlay_signal.is_set():
                painted.append(self._paint(display))
        return painted

    @staticmethod
    def _consecutive(seq):
        return all(b == a + 1 for a, b in zip(seq, seq[1:]))

    # -- the skip itself (forward re-sync between deadline and tick) --------

    def test_forward_resync_between_deadline_and_tick_never_skips(self):
        display = self._opened()
        clock = _FakeClock(1000.0)
        # Shifts well past the 15 ms window the old boundary gate accepted;
        # each lands after the wake was scheduled and before the tick runs,
        # exactly where a background status poll lands in production.
        shifts = iter([0.4, 0.3, 0.25, 0.12, 0.02, 0.45])

        def poll_lands(clk):
            s = next(shifts, None)
            if s is not None:
                self._resync(clk, +s)

        with patch_monotonic(clock):
            self._seed(position=5.0, observed_at=1000.0)      # counter reads 3
            assert self._paint(display) == 3
            painted = self._run(display, clock, 8.0, before_tick=poll_lands)
        assert painted[0] == 4
        assert self._consecutive(painted), painted
        # Eight real seconds plus ~1.5 s of forward shift: at least 9 paints,
        # none skipped, none repeated.
        assert len(painted) >= 9

    def test_late_wakes_never_skip(self):
        display = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            self._seed(position=5.0, observed_at=1000.0)
            assert self._paint(display) == 3
            painted = self._run(display, clock, 6.0, late=0.05)   # 50 ms late every wake
        assert painted[:6] == [4, 5, 6, 7, 8, 9]

    def test_signal_repaint_that_straddles_a_boundary_is_followed_at_once(self):
        display = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            self._seed(position=5.0, observed_at=1000.0)
            clock.t = 1001.99                       # counter 4.99: a signal repaint paints 4
            assert self._paint(display) == 4
            clock.t = 1002.01                       # compose+transmit crossed the 5.0 boundary
            assert display._next_repaint_deadline() == pytest.approx(1002.01)   # owed now
            display._overlay_signal.clear()
            display._tick_repeat_line()
            assert display._overlay_signal.is_set()
            assert self._paint(display) == 5
            assert display._next_repaint_deadline() == pytest.approx(1002.01 + 0.99 + 0.005)

    # -- backward guard ---------------------------------------------------

    def test_small_backward_resync_holds_the_painted_second(self):
        display = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            self._seed(position=5.0, observed_at=1000.0)
            assert self._paint(display) == 3
            clock.t = 1000.1
            self._resync(clock, -0.4)               # counter now 2.7, below the painted 3
            display._overlay_signal.clear()
            display._tick_repeat_line()
            assert not display._overlay_signal.is_set()          # not due: hold
            assert self._line(display, clock).startswith("0:03 / ")  # a signal repaint still reads 3
            assert display._next_repaint_deadline() == pytest.approx(1000.1 + (4 - 2.7) + 0.005)
            painted = self._run(display, clock, 3.0)
        assert painted[:3] == [4, 5, 6]             # no 2, no second 3

    def test_hold_is_bounded_by_the_hold_window(self):
        """A hold can never freeze the counter: the interpolated clock
        gains on the held value at 1 s/s, so the next second lands within
        1 + REPEAT_COUNTER_HOLD_S of the re-sync."""
        display = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            self._seed(position=5.0, observed_at=1000.0)
            assert self._paint(display) == 3
            clock.t = 1000.05
            self._resync(clock, -(dd.REPEAT_COUNTER_HOLD_S - 0.05))   # just inside the hold window
            t_hold = clock.t
            # Counter 2.1 held at 3; 4 is owed at value 4.0, i.e. 1.9 s on.
            # Run to just short of that so the loop exits on that paint.
            painted = self._run(display, clock, 1.9)
        assert painted == [4]
        assert clock.t - t_hold <= 1.0 + dd.REPEAT_COUNTER_HOLD_S + 0.01

    def test_restart_ack_re_anchors_to_zero(self):
        import dial_repeat_store as drs
        display = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            self._seed(position=9.0, observed_at=1000.0)
            assert self._paint(display) == 7
            clock.t = 1000.3
            drs.repeat_store.apply_ack(
                self.AID, {"ok": True, "state": "replaying", "armed": True, "position_seconds": 0.0}, clock.t,
            )
            assert display._next_repaint_deadline() == pytest.approx(clock.t)   # owed now
            display._overlay_signal.clear()
            display._tick_repeat_line()
            assert display._overlay_signal.is_set()
            assert self._paint(display) == 0
            assert self._line(display, clock).startswith("0:00 / ")

    def test_immediate_poll_reporting_the_ack_position_keeps_the_counter_at_zero(self):
        """The poll fired by a replaying ack reads a consistent appliance:
        replaying, at the ack position. Its re-stamp leaves the counter at
        zero, with no step back and no hold-state line."""
        import dial_repeat_store as drs
        display = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            self._seed(position=9.0, observed_at=1000.0)
            assert self._paint(display) == 7
            clock.t = 1000.2
            drs.repeat_store.apply_ack(
                self.AID, {"ok": True, "state": "replaying", "armed": True, "position_seconds": 0.0}, clock.t,
            )
            assert self._paint(display) == 0
            clock.t = 1000.5
            self._seed(position=0.0, observed_at=clock.t)
            display._overlay_signal.clear()
            display._tick_repeat_line()
            assert self._paint(display) == 0
            assert self._line(display, clock).startswith("0:00 / ")
            assert "hold" not in self._line(display, clock).lower()

    def test_loop_wrap_re_anchors_to_zero_then_counts_up(self):
        display = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            self._seed(position=29.5, observed_at=1000.0)    # counter 27.5; wraps at raw 31.5
            assert self._paint(display) == 27
            painted = self._run(display, clock, 6.0)
        # 28 (the clamp at duration - latency), then the wrap to 0, then up.
        assert painted[:3] == [28, 0, 1], painted
        assert self._consecutive(painted[1:])

    def test_large_backward_resync_is_shown_not_held(self):
        """A stalled source: every poll reports the same position, so each
        re-sync steps the clock back by a whole poll interval. That is a
        real change and must show; the guard only absorbs sub-second
        re-sync noise."""
        display = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            self._seed(position=5.0, observed_at=1000.0)
            assert self._paint(display) == 3
            painted = self._run(display, clock, 4.5)      # paints 4..8, last at 1005.005
            assert painted[-1] == 8
            self._seed(position=5.0, observed_at=clock.t)   # the poll: position unchanged
            display._overlay_signal.clear()
            display._tick_repeat_line()
            assert display._overlay_signal.is_set()
            assert self._paint(display) == 3

    # -- reset / re-anchor points -----------------------------------------

    def test_opening_the_screen_resets_the_reference(self):
        aid = "22" * 10
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            # Counter value 2.5 at the open; a stale painted 3 would be held
            # by the guard if the open did not reset it.
            _poll_focused_with_repeat(
                display, fb, aid,
                _repeat_obj(state="replaying", armed=True,
                            replay={"active": True, "position_seconds": 4.5, "duration_seconds": 30.0}),
            )
            display._repeat_painted_second = 3
            display.cycle_pages()
            with display._lock:
                display._repaint_current_locked()
        assert display._screen == "repeat"
        assert display._repeat_painted_second == 2

    def test_leaving_replaying_resets_and_a_return_re_anchors(self):
        display = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            self._seed(position=5.0, observed_at=1000.0)
            assert self._paint(display) == 3
            self._seed(position=0.0, observed_at=1000.0, state="hold")
            assert self._paint(display) is None
            assert self._line(display, clock).startswith("0:00 / ")
            # Back to replaying with the counter at 2.5: paints 2, not a held 3.
            self._seed(position=4.5, observed_at=1000.0)
            assert self._paint(display) == 2

    def test_unavailable_record_resets(self):
        import dial_repeat_store as drs
        display = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            self._seed(position=5.0, observed_at=1000.0)
            assert self._paint(display) == 3
            drs.repeat_store.update(self.AID, None)
            assert self._paint(display) is None
            assert display._repeat_layout_shown == "enable"

    def test_builder_never_writes_the_reference(self):
        display = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            self._seed(position=5.0, observed_at=1000.0)
            display._repeat_painted_second = 3
            clock.t = 1000.1
            self._resync(clock, -0.4)
            view_line = self._line(display, clock)
        assert view_line.startswith("0:03 / ")
        assert display._repeat_painted_second == 3

    # -- the deadline ---------------------------------------------------------

    def test_deadline_targets_the_painted_seconds_successor(self):
        display = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            self._seed(position=5.0, observed_at=1000.0)       # counter 3.0
            assert display._next_repaint_deadline() == pytest.approx(1000.0)   # nothing painted: owed
            assert self._paint(display) == 3
            assert display._next_repaint_deadline() == pytest.approx(1001.005)
            clock.t = 1000.4
            assert display._next_repaint_deadline() == pytest.approx(1001.005)


# ---------------------------------------------------------------------------
# The pressed channel: one set_pressed(zone, index) feeding every screen's
# own frame builder through the shared zone-rect table. The main and idle
# screens keep their own press handling; the selector, picker and repeat screens
# draw a wash for a genuine touch on any of their own zones.
# ---------------------------------------------------------------------------

class TestSetPressedStorage:
    def test_stores_the_zone_and_index(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._overlay_signal.clear()

        display.set_pressed(TouchZone.LIST_ROW, 2)

        assert display._pressed == (TouchZone.LIST_ROW, 2)
        assert display._overlay_signal.is_set()

    def test_index_defaults_to_none(self):
        display, fb, gt = make_display(targets=[])
        display.enable()

        display.set_pressed(TouchZone.UP)

        assert display._pressed == (TouchZone.UP, None)

    def test_none_zone_clears_the_channel(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.set_pressed(TouchZone.UP)
        display._overlay_signal.clear()

        display.set_pressed(None)

        assert display._pressed is None
        assert display._overlay_signal.is_set()


class TestPressedChannelFeedsEachScreen:
    def _opened_selector(self, count=3):
        targets = [
            _target(name=f"T{i}", service_name=f"T{i}", appliance_id=str(i) * 20,
                     auth="authorized", playing_since=float(i))
            for i in range(count)
        ]
        display, fb, gt = make_display(targets=targets)
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        return display, fb

    def test_selector_row_wash_confined_to_its_row(self):
        display, fb = self._opened_selector(count=3)
        width, height = display._active_panel_dims()
        unpressed = fb.displayed[-1]

        display.set_pressed(TouchZone.LIST_ROW, 1)
        with display._lock:
            display._repaint_current_locked()
        pressed = fb.displayed[-1]

        assert list(unpressed.getdata()) != list(pressed.getdata())
        layout = list_layout_for(width, height)
        for i, rect in enumerate(layout.rows):
            if i == 1:
                continue
            assert list(unpressed.crop(rect).getdata()) == list(pressed.crop(rect).getdata())

    def test_picker_back_wash_confined_to_the_bar(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.core.set_field("idle_affordance", True)
        display.open_picker()
        with display._lock:
            display._repaint_current_locked()
        width, height = display._active_panel_dims()
        unpressed = fb.displayed[-1]

        display.set_pressed(TouchZone.LIST_BACK)
        with display._lock:
            display._repaint_current_locked()
        pressed = fb.displayed[-1]

        layout = list_layout_for(width, height)
        assert list(unpressed.crop(layout.back).getdata()) != list(pressed.crop(layout.back).getdata())
        assert list(unpressed.crop(layout.down).getdata()) == list(pressed.crop(layout.down).getdata())
        assert list(unpressed.crop(layout.up).getdata()) == list(pressed.crop(layout.up).getdata())

    def test_foreign_zone_on_a_list_screen_washes_nothing(self):
        display, fb = self._opened_selector(count=1)
        unpressed = fb.displayed[-1]

        display.set_pressed(TouchZone.NAME)
        with display._lock:
            display._repaint_current_locked()
        pressed = fb.displayed[-1]

        assert list(unpressed.getdata()) == list(pressed.getdata())

    def test_main_screen_feeds_pressed_from_the_channel(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        _poll_with_artwork(display, fb)
        display.set_overlay(OverlayState(visible=True))
        display.set_pressed(TouchZone.UP)

        with patch.object(
            display._compositor, "compose", wraps=display._compositor.compose
        ) as mock_compose:
            with display._lock:
                display._repaint_current_locked()
        overlay_used = mock_compose.call_args.kwargs["overlay"]
        assert overlay_used.pressed == TouchZone.UP

    def test_repeat_screen_feeds_pressed_from_the_channel(self):
        aid = "9" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle"))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()

        display.set_pressed(TouchZone.REPEAT_PLAY)
        with display._lock:
            view = display._build_repeat_view_locked(display._repeat_screen, time.monotonic())
        assert view.pressed == TouchZone.REPEAT_PLAY

    def test_repeat_screen_name_wash_is_accepted(self):
        """The repeat screen shares DOTS/NAME/MUTE with the main screen's
        top band; the pressed channel surfaces a wash for them there
        too, matching what the compositor already renders for a main-screen
        press on the same zones."""
        aid = "9" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle"))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        unpressed = fb.displayed[-1]

        display.set_pressed(TouchZone.NAME)
        with display._lock:
            display._repaint_current_locked()
        pressed = fb.displayed[-1]

        width, height = display._active_panel_dims()
        from dial_touch_layout import repeat_layout_for
        layout = repeat_layout_for(width, height)
        assert list(unpressed.getdata()) != list(pressed.getdata())
        assert list(unpressed.crop(layout.dots).getdata()) == list(pressed.crop(layout.dots).getdata())
        assert list(unpressed.crop(layout.volume_cluster).getdata()) == list(
            pressed.crop(layout.volume_cluster).getdata()
        )
        assert list(unpressed.crop(layout.row).getdata()) == list(pressed.crop(layout.row).getdata())


class TestPressedChannelClears:
    def test_close_secondary_locked_empties_pressed(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.set_pressed(TouchZone.DOWN)

        with display._lock:
            display._close_secondary_locked()

        assert display._pressed is None

    def test_opening_a_secondary_screen_empties_pressed(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.set_pressed(TouchZone.UP)

        display.open_selector()
        with display._lock:
            display._apply_screen_requests_locked()

        assert display._screen == "selector"
        assert display._pressed is None

    def test_mark_noncomposited_locked_empties_pressed(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.set_pressed(TouchZone.UP)

        with display._lock:
            display._mark_noncomposited_locked()

        assert display._pressed is None


# ---------------------------------------------------------------------------
# Manual-focus pending grace: what the panel shows while it holds.
# ---------------------------------------------------------------------------

class TestFocusPendingOnScreen:
    def test_pending_focus_shows_logo_not_idle_screen(self):
        display, fb, gt = make_display(targets=[])
        aid = "c" * 20
        set_focus_pending(display, aid, "Kitchen")
        with display._lock:
            display.core.set_field("idle_affordance", True)  # would otherwise draw the idle-screen affordance
        display._poll_once()
        assert display._idle_chassis_due_locked() is False


class TestIdleFocusShownWhenNothingPlays:
    """The no-targets branch shows an idle focus in place of the plain idle
    screen: logo with the name and volume, selector rows refreshed, and the
    idle-sleep countdown still running underneath it."""

    def test_shows_logo_with_name_and_refreshes_selector_rows(self):
        aid = "7" * 20
        idle_entry = _roster_entry(name="Kitchen", service_name="Kitchen", appliance_id=aid, auth="authorized",
                                    playing=False)
        display, fb, gt = make_display(targets=[], roster=[idle_entry])
        display.enable()
        display.core.set_focus(aid)
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid)):
            display._poll_once()

        assert display.get_status()["showing"] == "logo"
        assert display.core.snapshot().now_playing is not None
        assert display.core.snapshot().now_playing.service_name == "Kitchen"
        assert [r.appliance_id for r in display._selector.rows] == [aid]
        assert [r.current for r in display._selector.rows] == [True]

    def test_idle_sleep_countdown_still_runs(self):
        aid = "8" * 20
        idle_entry = _roster_entry(name="Kitchen", service_name="Kitchen", appliance_id=aid, auth="authorized",
                                    playing=False)
        display, fb, gt = make_display(targets=[], roster=[idle_entry])
        display.enable()
        display.core.set_focus(aid)
        with patch("dial_core.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid)):
            # A whole second, so the threshold poll lands exactly on the
            # sleep delay rather than a rounding error short of it.
            t0 = float(math.ceil(time.monotonic()))
            with patch("dial_display.time.monotonic", return_value=t0):
                display._poll_once()
            assert display._display_sleeping is False

            with patch("dial_display.time.monotonic", return_value=t0 + dd.DISPLAY_IDLE_SLEEP_SECONDS):
                display._poll_once()
        assert display._display_sleeping is True


# ---------------------------------------------------------------------------
# The replay picker: rows from held+authorized+capable roster entries,
# picker_pick starting a replay with a pending focus, stale-index handling,
# and the shared inactivity timeout.
# ---------------------------------------------------------------------------

class TestReplayPickerRows:
    def test_open_picker_sets_screen_request(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.core.set_field("idle_affordance", True)
        display.open_picker()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "picker"

    def test_open_picker_refuses_without_a_held_replay(self):
        # A replay tap on a plain logo with nothing held stays inert.
        display, fb, gt = make_display(targets=[])
        display.enable()
        assert display.core.snapshot().idle_affordance is False
        display.open_picker()
        assert display._screen_request is None

    def test_picker_shows_placeholder_when_empty(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.core.set_field("idle_affordance", True)
        display.open_picker()
        with display._lock:
            display._repaint_current_locked()
        width, height = display._active_panel_dims()
        with display._lock:
            list_state = display._build_picker_list_state_locked(width, height)
        assert list_state.rows == (("Nothing to replay", False),)


class TestPickerPick:
    def _opened_with_row(self, aid="a" * 20):
        import dial_repeat_store as drs
        from dial_mdns import RosterEntry
        display, fb, gt = make_display(targets=[])
        display.enable()
        row = RosterEntry(
            appliance_id=aid, service_name="Kitchen", name="Kitchen", ip="10.0.0.9", port=8080,
            playing=False, repeat_capable=True, auth="authorized",
        )
        now = time.monotonic()
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="hold", recording_seconds=12.0), now))
        _refresh_picker(display, [row], now)
        display._core.set_roster([row])
        display.core.set_field("idle_affordance", True)
        display.open_picker()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "picker"
        return display, fb, gt

    def test_pick_sets_pending_focus_and_enqueues_seek(self):
        display, fb, gt = self._opened_with_row(aid="a" * 20)
        with patch("dial_core.enqueue_transport") as mock_transport:
            display.picker_pick(0)
        mock_transport.assert_called_once()
        target, action, position, token = mock_transport.call_args[0]
        assert target.appliance_id == "a" * 20
        assert action == "seek"
        assert position == 0.0
        assert display.core.manual_focus_id() == "a" * 20
        assert display.core.snapshot().focus.pending is not None

    def test_pick_closes_the_picker(self):
        display, fb, gt = self._opened_with_row()
        with patch("dial_core.enqueue_transport"):
            display.picker_pick(0)
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"

    def test_stale_index_is_back_no_focus_no_enqueue(self):
        display, fb, gt = self._opened_with_row()
        with patch("dial_core.enqueue_transport") as mock_transport:
            display.picker_pick(5)
        mock_transport.assert_not_called()
        assert display.core.manual_focus_id() is None
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"


class TestPickerTimeout:
    def test_closes_after_timeout(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.core.set_field("idle_affordance", True)
        display.open_picker()
        with display._lock:
            display._repaint_current_locked()
        opened_at = display._picker.opened_at
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS + 1):
            display._check_secondary_timeout()
        assert display._screen == "main"

    def test_stays_open_before_timeout(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.core.set_field("idle_affordance", True)
        display.open_picker()
        with display._lock:
            display._repaint_current_locked()
        opened_at = display._picker.opened_at
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS - 1):
            display._check_secondary_timeout()
        assert display._screen == "picker"


# ---------------------------------------------------------------------------
# A repeat-transport result: what it asks of the screen.
# ---------------------------------------------------------------------------

class TestOnRepeatResultOnScreen:
    def test_ok_true_applies_ack_and_signals_repaint(self):
        import dial_repeat_store as drs
        aid = "1" * 20
        display, fb, gt = make_display(targets=[])
        now = time.monotonic()
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="hold"), now))
        display._overlay_signal.clear()

        on_repeat_result(display,
            "transport", aid, 200,
            {"ok": True, "state": "replaying", "armed": True, "position_seconds": 0.0},
        )
        rec = drs.repeat_store.get(aid, time.monotonic())
        assert rec.state == "replaying"
        assert rec.armed is True
        assert display._overlay_signal.is_set()
    def test_takes_no_lock(self):
        """Regression guard for the invariant that on_repeat_result never
        takes DialDisplay._lock — simulated by holding the lock on this
        (the calling) thread and confirming the call still returns."""
        aid = "8" * 20
        display, fb, gt = make_display(targets=[])
        with display._lock:
            on_repeat_result(display, "transport", aid, 200, {"ok": True, "state": "hold",
                                                              "armed": False, "position_seconds": 0.0})


# ---------------------------------------------------------------------------
# _offerable: the outputs the outputs screen can offer.
# ---------------------------------------------------------------------------

class TestOfferableOutputs:
    def test_remote_in_use_row_dropped(self):
        rows = dd._offerable(dial_core_poll.parse_outputs_body(200, {"ok": True, "outputs": [
            {"id": "1", "name": "Bedroom", "selected": False, "volume": 0, "remote_in_use": True},
            {"id": "2", "name": "Kitchen", "selected": True, "volume": 50, "remote_in_use": False},
        ]}))
        assert [r.id for r in rows] == ["2"]


# ---------------------------------------------------------------------------
# on_outputs_result: fold a fetch result into the outputs snapshot.
# ---------------------------------------------------------------------------

class TestOnOutputsResult:
    def _outputs_display(self, appliance_id="a" * 20, rows=(), page=0, loaded=False, held=True):
        """A display with the outputs screen up for *appliance_id* and the
        core holding *rows* for it (nothing when *held* is False)."""
        display, fb, gt = make_display(targets=[])
        display._outputs = dd.OutputsState(
            appliance_id=appliance_id, service_name="Kitchen", ip="10.0.0.1", port=80,
            page=page, opened_at=time.monotonic(),
        )
        if held:
            display.core.adopt_outputs(appliance_id, rows, loaded)
            fold(display)
        return display

    def test_a_new_reading_repaints_the_list_and_the_screen_reads_it(self):
        display = self._outputs_display()
        display._overlay_signal.clear()
        rows = (OutputRow(id="1", name="Bedroom", selected=True, volume=40),)
        seed_outputs(display, rows)
        fold(display)
        assert display._rows_of(display._outputs) == rows
        assert display._overlay_signal.is_set()

    def test_page_clamped_when_row_count_shrinks(self):
        display = self._outputs_display(page=5, loaded=True)
        body = {"ok": True, "outputs": [
            {"id": "1", "name": "A", "selected": False, "volume": 0, "remote_in_use": False},
        ]}
        on_outputs_result(display, "fetch", "a" * 20, 200, body, {})
        assert display._outputs.page == 0

    def test_detail_row_vanishing_requests_the_outputs_list(self):
        display = self._outputs_display(
            rows=(OutputRow(id="1", name="Bedroom", selected=True, volume=40),), loaded=True,
        )
        display._output_detail = dd.OutputDetailState(
            appliance_id="a" * 20, output_id="1", opened_at=time.monotonic(),
        )
        display._screen = "output"
        on_outputs_result(display, "fetch", "a" * 20, 200, {"ok": True, "outputs": []}, {})
        assert display._screen_request == "outputs"

    def test_detail_row_still_present_leaves_screen_request_alone(self):
        row = OutputRow(id="1", name="Bedroom", selected=True, volume=40)
        display = self._outputs_display(rows=(row,), loaded=True)
        display._output_detail = dd.OutputDetailState(
            appliance_id="a" * 20, output_id="1", opened_at=time.monotonic(),
        )
        display._screen = "output"
        display._screen_request = None
        body = {"ok": True, "outputs": [
            {"id": "1", "name": "Bedroom", "selected": True, "volume": 45, "remote_in_use": False},
        ]}
        on_outputs_result(display, "fetch", "a" * 20, 200, body, {})
        assert display._screen_request is None


class TestIdleReplayLogo:
    """When a replay is available the idle screen renders the replay-logo
    (the arrows-on-disc image), not the plain logo or any text. Reached
    whenever nothing is playing, not only while a replay is available —
    see TestIdlePlainLogo for the no-affordance case."""

    def test_idle_render_requests_the_replay_logo(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display.core.set_field("idle_affordance", True)
            display._current_base_image = MagicMock()
            with patch("dial_display.load_logo", return_value=MagicMock()) as ll:
                display._display_idle_locked()
        assert ll.call_args_list[0].args[0] == display._replay_logo_path

    def test_idle_render_falls_back_to_plain_base_when_replay_logo_missing(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        base = MagicMock()
        with display._lock:
            display.core.set_field("idle_affordance", True)
            display._current_base_image = base
            with patch("dial_display.load_logo", return_value=None):
                # Must not raise when the replay image cannot be loaded.
                display._display_idle_locked()


class TestIdlePlainLogo:
    """The idle screen's own compose path is reached whenever
    nothing is playing, not only while a replay is available — a dial with
    no repeat-capable appliance still gets the "i" badge (see
    TestComposeIdle in the compositor suite), just over the plain logo
    rather than the replay-available one."""

    def test_plain_base_used_and_replay_logo_never_loaded_without_affordance(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        base = MagicMock()
        with display._lock:
            display.core.set_field("idle_affordance", False)
            display._current_base_image = base
            with patch("dial_display.load_logo") as ll:
                display._display_idle_locked()
        ll.assert_not_called()

    def test_idle_chassis_due_whenever_nothing_plays_regardless_of_affordance(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "main"
            display.core.set_field("now_playing", None)
            display.core.set_field("idle_affordance", False)
            assert display._idle_chassis_due_locked() is True
            display.core.set_field("idle_affordance", True)
            assert display._idle_chassis_due_locked() is True


class TestPickerSurvivesIdle:
    """The replay picker and the appliance selector are both idle-state
    screens for choosing what to replay or what to control, so a poll that
    finds nothing playing must NOT close either of them — their own
    inactivity timeout does."""

    def test_picker_stays_open_when_nothing_playing(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "picker"
        gt.return_value = []
        with patch.object(display, "_close_secondary_locked") as close:
            display._poll_once()
        close.assert_not_called()

    def test_pending_picker_open_not_clobbered_when_nothing_playing(self):
        # open_picker() ran on the touch thread (request pending) but the
        # repaint thread has not applied it yet: the idle poll must not close
        # it out from under the open.
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "main"
            display._screen_request = "picker"
        gt.return_value = []
        with patch.object(display, "_close_secondary_locked") as close:
            display._poll_once()
        close.assert_not_called()

    def test_selector_stays_open_when_nothing_playing(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "selector"
        gt.return_value = []
        with patch.object(display, "_close_secondary_locked") as close:
            display._poll_once()
        close.assert_not_called()

    def test_repeat_screen_closes_when_nothing_playing_and_no_focus(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "repeat"
        gt.return_value = []
        with patch.object(display, "_close_secondary_locked") as close:
            display._poll_once()
        close.assert_called()

    def test_repeat_screen_kept_when_an_idle_focus_is_set(self):
        aid = "9" * 20
        idle = _roster_entry(name="Kitchen", service_name="Kitchen", appliance_id=aid, auth="authorized")
        display, fb, gt = make_display(targets=[], roster=[idle])
        display.enable()
        display.core.set_focus(aid)
        with display._lock:
            display._screen = "repeat"
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None, appliance_id=aid)):
            display._poll_once()
        assert display._screen == "repeat"


# ---------------------------------------------------------------------------
# The idle affordance: the repaint a change of it asks for.
# ---------------------------------------------------------------------------

class TestIdleAffordanceRepaintSignal:
    def _roster_row(self, aid, auth="authorized", repeat_capable=True):
        from dial_mdns import RosterEntry
        return RosterEntry(
            appliance_id=aid, service_name="Kitchen", name="Kitchen", ip="10.0.0.9", port=8080,
            playing=False, repeat_capable=repeat_capable, auth=auth,
        )
    def test_change_signals_overlay(self):
        import dial_repeat_store as drs
        aid = "5" * 20
        display, fb, gt = make_display(targets=[], roster=[self._roster_row(aid)])
        display.enable()
        now = time.monotonic()
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="hold"), now))
        display._overlay_signal.clear()
        display._poll_once()
        assert display.core.snapshot().idle_affordance is True
        assert display._overlay_signal.is_set()
        display._overlay_signal.clear()
        display._poll_once()
        assert not display._overlay_signal.is_set()


# ---------------------------------------------------------------------------
# The outputs list and per-output detail screens: openers, touch-thread
# entries, and paint builders. Lifecycle/poll interactions (bound-appliance
# close, idle focus, timeouts) are covered by the trace corpus instead.
# ---------------------------------------------------------------------------

def _make_outputs_display(dial_outputs=True, auth="unknown", appliance_id="a" * 20):
    display, fb, gt = make_display(targets=[])
    display.core.set_field("reporting_id", appliance_id)
    display.core.set_roster([_roster_entry(
        appliance_id=appliance_id, auth=auth, dial_outputs=dial_outputs,
    )])
    return display


class TestOutputsOpener:
    def test_refuses_with_no_focus_or_reporting_id(self):
        display, fb, gt = make_display(targets=[])
        assert display._open_outputs_locked() is False
        assert display._outputs is None

    def test_refuses_without_dial_outputs_capability(self):
        display = _make_outputs_display(dial_outputs=False)
        assert display._open_outputs_locked() is False
        assert display._outputs is None

    def test_refuses_when_unauthorized(self):
        display = _make_outputs_display(auth="unauthorized")
        assert display._open_outputs_locked() is False

    def test_opens_for_an_authorized_capable_appliance(self):
        display = _make_outputs_display()
        assert display._open_outputs_locked() is True
        assert display._screen == "outputs"
        assert display._outputs.appliance_id == "a" * 20
        assert display._rows_of(display._outputs) == ()
        assert dd._held_outputs(display.core.snapshot(), display._outputs) is None

    def test_keeps_rows_on_reopen_for_the_same_appliance(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        rows = (OutputRow(id="1", name="Bedroom", selected=True, volume=40),)
        seed_outputs(display, rows)
        display._screen = "main"
        display._open_outputs_locked()
        assert display._rows_of(display._outputs) == rows
        assert dd._held_outputs(display.core.snapshot(), display._outputs).loaded is True

    def test_resets_rows_for_a_different_appliance(self):
        display = _make_outputs_display(appliance_id="a" * 20)
        display._open_outputs_locked()
        rows = (OutputRow(id="1", name="Bedroom", selected=True, volume=40),)
        seed_outputs(display, rows)
        display._screen = "main"
        display.core.set_field("reporting_id", "b" * 20)
        display.core.set_roster([_roster_entry(appliance_id="b" * 20, dial_outputs=True)])
        display._open_outputs_locked()
        assert display._outputs.appliance_id == "b" * 20
        assert display._rows_of(display._outputs) == ()
        assert dd._held_outputs(display.core.snapshot(), display._outputs) is None


class TestOutputDetailOpener:
    def test_refuses_without_a_chosen_id(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        seed_outputs(display, (OutputRow(id="1", name="Bedroom", selected=True, volume=40),), loaded=False)
        display._output_open_id = None
        assert display._open_output_locked() is False
        assert display._output_detail is None

    def test_refuses_when_id_not_in_rows(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        seed_outputs(display, (OutputRow(id="1", name="Bedroom", selected=True, volume=40),), loaded=False)
        display._output_open_id = "not-a-row"
        assert display._open_output_locked() is False
        assert display._output_detail is None
        # Consumed either way, refused or not.
        assert display._output_open_id is None

    def test_opens_for_a_valid_id(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        seed_outputs(display, (OutputRow(id="1", name="Bedroom", selected=True, volume=40),), loaded=False)
        display._output_open_id = "1"
        assert display._open_output_locked() is True
        assert display._screen == "output"
        assert display._output_detail.output_id == "1"
        assert display._output_detail.appliance_id == display._outputs.appliance_id
        assert display._output_open_id is None

    def test_refuses_with_no_outputs_state(self):
        display, fb, gt = make_display(targets=[])
        display._output_open_id = "1"
        assert display._open_output_locked() is False


class TestOutputsTouchEntries:
    def test_open_outputs_enqueues_fetch_and_requests_screen(self):
        display = _make_outputs_display()
        with patch("dial_core.enqueue_fetch") as mock_fetch:
            display.open_outputs()
        mock_fetch.assert_called_once()
        target = mock_fetch.call_args[0][0]
        assert target.appliance_id == "a" * 20
        assert display._screen_request == "outputs"

    def test_open_outputs_noop_without_capability(self):
        display = _make_outputs_display(dial_outputs=False)
        with patch("dial_core.enqueue_fetch") as mock_fetch:
            display.open_outputs()
        mock_fetch.assert_not_called()
        assert display._screen_request is None

    def test_outputs_row_tap_sets_open_id_and_requests_detail(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        seed_outputs(display, (OutputRow(id="1", name="Bedroom", selected=True, volume=40),), loaded=False)
        display.outputs_row_tap(0)
        assert display._output_open_id == "1"
        assert display._screen_request == "output"

    def test_outputs_row_tap_stale_index_closes_list(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        seed_outputs(display, (OutputRow(id="1", name="Bedroom", selected=True, volume=40),), loaded=False)
        display.outputs_row_tap(9)
        assert display._output_open_id is None
        # close_list() requests back_to for whatever screen is showing.
        assert display._screen_request == dd._policy(display._screen).back_to

    def _opened_detail(self, selected=True, volume=40):
        display = _make_outputs_display()
        display._open_outputs_locked()
        row = OutputRow(id="1", name="Bedroom", selected=selected, volume=volume)
        seed_outputs(display, (row,), loaded=False)
        display._output_detail = dd.OutputDetailState(
            appliance_id=display._outputs.appliance_id, output_id="1", opened_at=1000.0,
        )
        display._screen = "output"
        return display

    def test_output_toggle_tap_enqueues_and_sets_optimistic(self):
        display = self._opened_detail(selected=False, volume=0)
        with patch("dial_core.enqueue_set") as mock_set:
            display.output_toggle_tap()
        mock_set.assert_called_once()
        target, out_id = mock_set.call_args[0]
        kwargs = mock_set.call_args[1]
        assert out_id == "1"
        assert kwargs["selected"] is True
        assert kwargs["volume"] is None
        assert display.core.outputs_override()[0] == "1"
        assert display.core.outputs_override()[1] is True

    def test_output_toggle_tap_disables(self):
        display = self._opened_detail(selected=True, volume=40)
        with patch("dial_core.enqueue_set") as mock_set:
            display.output_toggle_tap()
        kwargs = mock_set.call_args[1]
        assert kwargs["selected"] is False
        assert display.core.outputs_override()[1] is False

    def test_output_toggle_tap_noop_without_row(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        display._output_detail = dd.OutputDetailState(
            appliance_id=display._outputs.appliance_id, output_id="missing", opened_at=1000.0,
        )
        with patch("dial_core.enqueue_set") as mock_set:
            display.output_toggle_tap()
        mock_set.assert_not_called()

    def test_output_volume_tap_steps_from_row_volume(self):
        display = self._opened_detail(selected=True, volume=40)
        with patch("dial_core.enqueue_set") as mock_set:
            display.output_volume_tap(+2)
        kwargs = mock_set.call_args[1]
        assert kwargs["selected"] is True
        assert kwargs["volume"] == 42
        assert display.core.outputs_override()[2] == 42

    def test_output_volume_tap_steps_from_optimistic_value(self):
        display = self._opened_detail(selected=True, volume=40)
        tap_output(display, "1", True, 42)
        with patch("dial_core.enqueue_set"):
            display.output_volume_tap(+2)
        assert display.core.outputs_override()[2] == 44

    def test_output_volume_tap_ignored_when_disabled(self):
        display = self._opened_detail(selected=False, volume=0)
        with patch("dial_core.enqueue_set") as mock_set:
            display.output_volume_tap(+2)
        mock_set.assert_not_called()
        assert display.core.outputs_override() is None

    def test_output_volume_tap_clamps_at_100(self):
        display = self._opened_detail(selected=True, volume=99)
        with patch("dial_core.enqueue_set") as mock_set:
            display.output_volume_tap(+10)
        assert mock_set.call_args[1]["volume"] == 100

    def test_output_volume_tap_clamps_at_0(self):
        display = self._opened_detail(selected=True, volume=1)
        with patch("dial_core.enqueue_set") as mock_set:
            display.output_volume_tap(-10)
        assert mock_set.call_args[1]["volume"] == 0


# ---------------------------------------------------------------------------
# The EQ page: availability, opener, touch entries, on_eq_result, cycle_pages.
# ---------------------------------------------------------------------------

def _make_eq_display(dial_eq=True, auth="unknown", appliance_id="a" * 20):
    display, fb, gt = make_display(targets=[])
    display.core.set_field("reporting_id", appliance_id)
    display.core.set_roster([_roster_entry(appliance_id=appliance_id, auth=auth, dial_eq=dial_eq)])
    display._core._update_availability(time.monotonic())
    return display


class TestEqOpener:
    def test_refuses_with_no_focus_or_reporting_id(self):
        display, fb, gt = make_display(targets=[])
        assert display._open_eq_locked() is False
        assert display._eq is None

    def test_refuses_without_dial_eq_capability(self):
        display = _make_eq_display(dial_eq=False)
        assert display._open_eq_locked() is False
        assert display._eq is None

    def test_refuses_when_unauthorized(self):
        display = _make_eq_display(auth="unauthorized")
        assert display._open_eq_locked() is False

    def test_refuses_on_the_compact_tier(self):
        display = _make_eq_display(dial_eq=True)
        display.core.set_field("eq_available", False)  # the compact veto, already computed by the poll
        assert display._open_eq_locked() is False

    def test_opens_for_an_authorized_capable_appliance(self):
        display = _make_eq_display()
        assert display._open_eq_locked() is True
        assert display._screen == "eq"
        assert display._eq.appliance_id == "a" * 20
        assert dd._held_eq(display.core.snapshot(), display._eq) is None

    def test_keeps_values_on_reopen_for_the_same_appliance(self):
        display = _make_eq_display()
        display._open_eq_locked()
        seed_eq(display, bass_db=2, treble_db=-1, loaded=True)
        display._screen = "main"
        display._open_eq_locked()
        held = dd._held_eq(display.core.snapshot(), display._eq)
        assert dd.eq_gain(held.bands, "bass") == 2
        assert dd.eq_gain(held.bands, "treble") == -1
        assert dd._eq_loaded(held) is True

    def test_resets_values_for_a_different_appliance(self):
        display = _make_eq_display(appliance_id="a" * 20)
        display._open_eq_locked()
        seed_eq(display, bass_db=2, treble_db=-1, loaded=True)
        display._screen = "main"
        display.core.set_field("reporting_id", "b" * 20)
        display.core.set_roster([_roster_entry(appliance_id="b" * 20, dial_eq=True)])
        display._core._update_availability(time.monotonic())
        display._open_eq_locked()
        assert display._eq.appliance_id == "b" * 20
        assert dd._held_eq(display.core.snapshot(), display._eq) is None


class TestEqStep:
    def _opened(self):
        display = _make_eq_display()
        display._open_eq_locked()
        display._sync_core_interest()
        return display

    def test_noop_without_an_open_eq_screen(self):
        display, fb, gt = make_display(targets=[])
        with patch("dial_core._enqueue_eq_set") as mock_set:
            display.eq_step("bass", +1)
        mock_set.assert_not_called()

    def test_the_shown_value_follows_the_tap_only_inside_its_window(self):
        display = self._opened()
        clock = _FakeClock(1000.0)
        seed_eq(display, bass_db=0, treble_db=0, loaded=True)
        set_eq_optimistic(display, (2, None, 1002.0))
        with patch_monotonic(clock):
            clock.t = 1001.99
            assert display._shown_eq(display._eq, "bass") == 2
            assert display._shown_eq(display._eq, "treble") == 0
            clock.t = 1002.01
            assert display._shown_eq(display._eq, "bass") == 0


class TestOnEqResult:
    def _opened(self, appliance_id="a" * 20):
        display = _make_eq_display(appliance_id=appliance_id)
        display._open_eq_locked()
        display._sync_core_interest()
        return display

    @staticmethod
    def _reading(display):
        """(bass, treble, loaded) the EQ page's appliance shows from the
        core's snapshot."""
        held = dd._held_eq(display.core.snapshot(), display._eq)
        if held is None:
            return None, None, False
        return dd.eq_gain(held.bands, "bass"), dd.eq_gain(held.bands, "treble"), dd._eq_loaded(held)

    def test_a_new_reading_repaints_the_page_and_the_screen_reads_it(self):
        display = self._opened()
        display._overlay_signal.clear()
        seed_eq(display, bass_db=2, treble_db=-1, loaded=True)
        fold(display)
        assert self._reading(display) == (2, -1, True)
        assert display._overlay_signal.is_set()


class TestEqViewBuild:
    def test_view_reads_the_override_then_the_state(self):
        display = _make_eq_display()
        display._open_eq_locked()
        seed_eq(display, bass_db=2, treble_db=-1, loaded=True)
        view = display._build_eq_view_locked(display._eq, time.monotonic())
        assert (view.bass_db, view.treble_db) == (2, -1)
        set_eq_optimistic(display, (5, None, time.monotonic() + 10.0))
        view = display._build_eq_view_locked(display._eq, time.monotonic())
        assert (view.bass_db, view.treble_db) == (5, -1)

    def test_none_screen_builds_a_blank_view(self):
        display, fb, gt = make_display(targets=[])
        view = display._build_eq_view_locked(None, time.monotonic())
        assert view.name == ""
        assert view.bass_db is None
        assert view.treble_db is None
        assert view.loaded is False


class TestCyclePages:
    def _setup(self, appliance_id="a" * 20, repeat_available=False, eq_available=False):
        t = _target(appliance_id=appliance_id)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=_track_id(), appliance_id=appliance_id)
        if repeat_available:
            result = dict(result)
            result["repeat"] = _repeat_obj(state="idle", available=True)
        roster = [_roster_entry(appliance_id=appliance_id, playing=True, dial_eq=eq_available)]
        with patch("dial_core.fetch_target_status", return_value=result), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=Image.new("RGB", (160, 128))), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=Image.new("RGB", (160, 128))):
            display.core.set_roster(roster)
            display._poll_once()
            display.core.set_roster(roster)
            display._core._update_availability(time.monotonic())
            display._core._update_availability(time.monotonic())
        return display

    def _apply(self, display):
        with display._lock:
            display._apply_screen_requests_locked()

    def test_main_to_repeat_to_eq_to_main_when_all_available(self):
        display = self._setup(repeat_available=True, eq_available=True)
        assert display._screen == "main"

        display.cycle_pages()
        self._apply(display)
        assert display._screen == "repeat"

        with patch("dial_core._enqueue_eq_fetch"):
            display.cycle_pages()
        self._apply(display)
        assert display._screen == "eq"

        display.cycle_pages()
        self._apply(display)
        assert display._screen == "main"

    def test_main_to_eq_to_main_when_no_repeat_record(self):
        display = self._setup(repeat_available=False, eq_available=True)
        with patch("dial_core._enqueue_eq_fetch"):
            display.cycle_pages()
        self._apply(display)
        assert display._screen == "eq"

        display.cycle_pages()
        self._apply(display)
        assert display._screen == "main"

    def test_main_to_repeat_to_main_when_no_eq(self):
        display = self._setup(repeat_available=True, eq_available=False)
        display.cycle_pages()
        self._apply(display)
        assert display._screen == "repeat"

        display.cycle_pages()
        self._apply(display)
        assert display._screen == "main"

    def test_noop_when_nothing_available(self):
        display = self._setup(repeat_available=False, eq_available=False)
        display._screen_request = None
        display.cycle_pages()
        assert display._screen_request is None
        assert display._screen == "main"

    def test_opening_eq_enqueues_one_fetch(self):
        display = self._setup(repeat_available=False, eq_available=True)
        with patch("dial_core._enqueue_eq_fetch") as mock_fetch:
            display.cycle_pages()
        mock_fetch.assert_called_once()

    def test_compact_always_two_way(self):
        """On the compact tier _eq_available is always False (see
        TestEqAvailable), so cycling never reaches "eq" -- a two-way
        main<->repeat toggle."""
        t = _target(appliance_id="a" * 20)
        roster = [_roster_entry(appliance_id="a" * 20, playing=True, dial_eq=True)]
        display, fb, gt = make_display(targets=[t], roster=roster, screen_size_inches=1.3)
        display.enable()
        result = _status_result(track_id=_track_id(), appliance_id="a" * 20)
        result["repeat"] = _repeat_obj(state="idle", available=True)
        with patch("dial_core.fetch_target_status", return_value=result), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=Image.new("RGB", (240, 240))), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=Image.new("RGB", (240, 240))):
            display._poll_once()
        assert display._compact_tier() is True
        assert display.core.snapshot().eq_available is False

        display.cycle_pages()
        self._apply(display)
        assert display._screen == "repeat"

        display.cycle_pages()
        self._apply(display)
        assert display._screen == "main"


class TestEqPageClosing:
    def test_closes_on_focus_clear(self):
        display = _make_eq_display()
        display._open_eq_locked()
        display._screen = "eq"
        assert dd._policy("eq").closes_on_focus_clear is True

    def test_closes_when_appliance_changes(self):
        display = _make_eq_display(appliance_id="a" * 20)
        display._open_eq_locked()
        display.core.set_field("reporting_id", "b" * 20)
        display._close_bound_screen_if_unfocused()
        assert display._screen == "main"
        assert display._eq is None

    def test_no_inactivity_timeout(self):
        assert dd._policy("eq").inactivity_timeout_s is None

    def test_touch_surface_reports_eq_with_outputs_gate(self):
        display = _make_eq_display()
        display._open_eq_locked()
        display.core.set_field("outputs_available", False)
        assert display.touch_surface() == ("eq", True, True, False)
        display.core.set_field("outputs_available", True)
        assert display.touch_surface() == ("eq", True, True, True)


class TestOutputsPaintBuilders:
    def test_list_row_enabled_shows_volume_right_aligned_slot(self):
        assert dd._output_list_row(
            OutputRow(id="1", name="Bedroom", selected=True, volume=42),
        ) == ("Bedroom", False, "42", "")

    def test_list_row_disabled_shows_blank(self):
        assert dd._output_list_row(
            OutputRow(id="1", name="Bedroom", selected=False, volume=0),
        ) == ("Bedroom", False, "", "")

    def test_output_list_row_marks_the_default_output(self):
        assert dd._output_list_row(
            OutputRow(id="1", name="Bedroom", selected=True, volume=42, is_default=True),
        ) == ("Bedroom", False, "42", DEFAULT_MARK)
        assert dd._output_list_row(
            OutputRow(id="2", name="Study", selected=True, volume=42),
        )[3] == ""

    def test_output_list_row_shows_the_level_only_when_selected(self):
        on = dd._output_list_row(OutputRow(id="1", name="A", selected=True, volume=7, is_default=True))
        off = dd._output_list_row(OutputRow(id="1", name="A", selected=False, volume=7, is_default=True))
        assert (on[2], off[2]) == ("7", "")

    def test_loading_placeholder_before_first_fetch(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        with display._lock:
            state = display._build_outputs_list_state_locked(160, 128)
        assert state.rows == (("Loading", False),)

    def test_no_outputs_placeholder_once_loaded_and_empty(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        seed_outputs(display, ())
        with display._lock:
            state = display._build_outputs_list_state_locked(160, 128)
        assert state.rows == (("No outputs", False),)

    def test_optimistic_override_applied_before_row_tuples(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        row = OutputRow(id="1", name="Bedroom", selected=False, volume=0)
        seed_outputs(display, (row,))
        tap_output(display, "1", True, 55)
        with display._lock:
            state = display._build_outputs_list_state_locked(160, 128)
        assert state.rows == (("Bedroom", False, "55", ""),)
        # Paint-time only: the manager's own row is never mutated.
        assert display._rows_of(display._outputs)[0].selected is False

    def test_output_view_reads_level_through_the_override(self):
        display = self._opened_with_row(selected=False, volume=0)
        tap_output(display, "1", True, 60)
        with display._lock:
            view = display._build_output_view_locked(1000.0)
        assert view.selected is True
        assert view.level == 60

    def test_output_view_level_none_when_disabled(self):
        display = self._opened_with_row(selected=False, volume=0)
        with display._lock:
            view = display._build_output_view_locked(1000.0)
        assert view.selected is False
        assert view.level is None

    def test_output_view_falls_back_when_row_vanished(self):
        display = self._opened_with_row(selected=True, volume=40)
        seed_outputs(display, (), loaded=False)
        with display._lock:
            view = display._build_output_view_locked(1000.0)
        assert view.selected is False
        assert view.level is None
        assert view.output_name == ""

    def _opened_with_row(self, selected, volume):
        display = _make_outputs_display()
        display._open_outputs_locked()
        row = OutputRow(id="1", name="Bedroom", selected=selected, volume=volume)
        seed_outputs(display, (row,))
        display._output_detail = dd.OutputDetailState(
            appliance_id=display._outputs.appliance_id, output_id="1", opened_at=1000.0,
        )
        return display


# ---------------------------------------------------------------------------
# The screen policy table itself: shape and cross-row consistency checks,
# independent of any particular screen's behaviour (covered above and by
# the trace corpus).
# ---------------------------------------------------------------------------

class TestScreenPolicyTable:
    def test_table_has_exactly_the_fifteen_screens(self):
        assert set(SCREEN_POLICIES) == {
            "main", "selector", "picker", "info", "info_value", "repeat", "eq", "outputs", "output",
            "nowifi", "restarting", "sdhealth", "update", "update_result", "appliance_warning",
        }

    def test_nowifi_and_restarting_rows(self):
        assert SCREEN_POLICIES["nowifi"].inactivity_timeout_s is None
        assert SCREEN_POLICIES["nowifi"].defers_sleep is False
        assert SCREEN_POLICIES["nowifi"].back_to == "main"
        assert SCREEN_POLICIES["nowifi"].surface == ("nowifi", False, False, False)
        assert SCREEN_POLICIES["restarting"].inactivity_timeout_s == dd.RESTARTING_TIMEOUT_SECONDS
        assert SCREEN_POLICIES["restarting"].touch_extends_timeout is False
        assert SCREEN_POLICIES["restarting"].surface == ("restarting", False, False, False)

    def test_sdhealth_row(self):
        assert SCREEN_POLICIES["sdhealth"].inactivity_timeout_s is None
        assert SCREEN_POLICIES["sdhealth"].defers_sleep is False
        assert SCREEN_POLICIES["sdhealth"].back_to == "main"
        assert SCREEN_POLICIES["sdhealth"].surface == ("sdhealth", False, False, False)

    def test_warning_rows_share_the_state_attr_and_open_via_the_shared_opener(self):
        for desc in WARNING_DESCRIPTORS:
            policy = SCREEN_POLICIES[desc.screen]
            assert policy.state_attr == "_warning_screen"
            assert policy.paint is DialDisplay._display_warning_locked
            assert policy.open.keywords == {"warning_id": desc.id}

    def test_info_value_back_to_is_info(self):
        # The compact info page's own drill-in returns to the list it
        # opened from, not to main.
        assert SCREEN_POLICIES["info_value"].back_to == "info"

    def test_state_attr_is_an_attribute_of_a_fresh_display(self):
        display, fb, gt = make_display(targets=[])
        for policy in SCREEN_POLICIES.values():
            if policy.state_attr is not None:
                assert hasattr(display, policy.state_attr)

    def test_open_and_paint_are_dial_display_methods(self):
        for policy in SCREEN_POLICIES.values():
            assert callable(policy.open)
            # A warning row's opener is bound per row with functools.partial
            # (see _warning_policy_row); unwrap it to the underlying method.
            open_func = policy.open.func if isinstance(policy.open, functools.partial) else policy.open
            assert open_func.__qualname__.startswith("DialDisplay.")
            if policy.paint is not None:
                assert callable(policy.paint)
                assert policy.paint.__qualname__.startswith("DialDisplay.")

    def test_back_to_names_a_table_key(self):
        for policy in SCREEN_POLICIES.values():
            assert policy.back_to in SCREEN_POLICIES

    def test_exactly_selector_picker_info_and_outputs_are_paged(self):
        paged = {name for name, policy in SCREEN_POLICIES.items() if policy.paged}
        assert paged == {"selector", "picker", "info", "outputs"}

    def test_picker_touch_extends_timeout_is_pinned_true(self):
        # Touch activity extends every list screen's clock — the picker's
        # own row now matches the selector/outputs lists rather than
        # keeping its older (never-extends) behaviour. Flip only as a
        # deliberate, reviewed product decision with its own test.
        assert SCREEN_POLICIES["picker"].touch_extends_timeout is True

    def test_bound_to_appliance_is_exactly_outputs_output_and_eq(self):
        bound = {name for name, policy in SCREEN_POLICIES.items() if policy.bound_to_appliance}
        assert bound == {"outputs", "output", "eq"}

    def test_surface_is_a_four_tuple_or_none_for_every_row(self):
        for policy in SCREEN_POLICIES.values():
            assert policy.surface is None or len(policy.surface) == 4

    def test_outputs_and_output_close_on_focus_clear(self):
        assert SCREEN_POLICIES["outputs"].closes_on_focus_clear is True
        assert SCREEN_POLICIES["output"].closes_on_focus_clear is True

    def test_output_back_to_is_outputs_not_main(self):
        assert SCREEN_POLICIES["output"].back_to == "outputs"

    def test_repeat_surface_tuple_opens_outputs_not_mute(self):
        # The repeat screen's top-right readout opens the outputs list, the
        # same as main -- mute is no longer reachable from this screen (the
        # physical button and DOTS-back-to-main still mute from anywhere).
        assert SCREEN_POLICIES["repeat"].surface == ("repeat", True, True, True)

    def test_only_repeat_has_a_replay_surface(self):
        with_replay = {name for name, policy in SCREEN_POLICIES.items() if policy.replay_surface is not None}
        assert with_replay == {"repeat"}
        assert SCREEN_POLICIES["repeat"].replay_surface == ("repeat_replay", True, True, False)


def _make_rich_display(targets=None, **overrides):
    """A display on the shipped 320x240 rich panel (2.8in ili9341), the
    tier the artwork-tap reveal animates on."""
    fb = FakeBackend()
    fb.width, fb.height = 320, 240
    overrides.setdefault("screen_type", "ili9341_320x240")
    overrides.setdefault("screen_size_inches", 2.8)
    overrides.setdefault("backend", fb)
    return make_display(targets=targets or [], **overrides)


# ---------------------------------------------------------------------------
# The compact content tier, wired through the manager: held-always,
# touch_surface()'s "held"/"repeat"/"repeat_replay" reporting, wrap paging,
# _display_list_locked's base passthrough, picker_pick and the time-tap-back
# close. Uses the shipped 1.3in 240x240 profile, whose default diagonal
# already resolves compact (see dial_touch_layout.metrics_for) — a custom
# FakeBackend matches its physical pixel size, following the same pattern
# TestListPagingMatchesPaintedRows uses for the rich tier.
# ---------------------------------------------------------------------------

def _make_compact_display(targets=None, **overrides):
    fb = FakeBackend()
    fb.width, fb.height = 240, 240
    overrides.setdefault("screen_type", "st7789_240x240")
    overrides.setdefault("backend", fb)
    display, fb, gt = make_display(targets=targets or [], **overrides)
    return display, fb, gt


class TestCompactPersistentOverlayAndSurface:
    """Compact controls start hidden (bare artwork) and only appear for a
    6 s window opened by a touch/reveal/screen change — see
    _show_compact_controls()/_compact_controls_hidden(). Inverted from the
    old "compact always held" behaviour."""

    def test_persistent_overlay_shown_false_until_a_reveal(self):
        t = _target()
        display, fb, gt = _make_compact_display(targets=[t], always_show_controls=False)
        display.enable()
        with display._lock:
            assert display._metrics_locked().content_tier == "compact"
        _poll_with_artwork(display, fb)
        assert display.persistent_overlay_shown() is False

    def test_touch_surface_reports_hidden_until_a_reveal(self):
        t = _target()
        display, fb, gt = _make_compact_display(targets=[t], always_show_controls=False)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.touch_surface() == ("hidden", False, False, False)

    def test_reveal_opens_the_window_shown_and_held(self):
        t = _target()
        display, fb, gt = _make_compact_display(targets=[t], always_show_controls=False)
        display.enable()
        _poll_with_artwork(display, fb)
        display.set_overlay(OverlayState(visible=True))
        assert display.persistent_overlay_shown() is True
        assert display.touch_surface()[0] == "held"

    def test_window_lapses_back_to_hidden_after_six_seconds(self):
        t = _target()
        display, fb, gt = _make_compact_display(targets=[t], always_show_controls=False)
        display.enable()
        _poll_with_artwork(display, fb)
        clock = _FakeClock(time.monotonic())
        with patch_monotonic(clock):
            display.set_overlay(OverlayState(visible=True))
            assert display.persistent_overlay_shown() is True
            clock.t += dd.CONTROLS_HIDE_SECONDS + 0.1
            assert display.persistent_overlay_shown() is False
            assert display.touch_surface()[0] == "hidden"

    def test_touch_activity_extends_the_window(self):
        t = _target()
        display, fb, gt = _make_compact_display(targets=[t], always_show_controls=False)
        display.enable()
        _poll_with_artwork(display, fb)
        clock = _FakeClock(time.monotonic())
        with patch_monotonic(clock):
            display.set_overlay(OverlayState(visible=True))
            clock.t += 5.0
            display.notify_touch_activity()
            with display._lock:
                display._repaint_current_locked()
            clock.t += 5.9  # 10.9s from the reveal -- would be hidden without the extension
            assert display.persistent_overlay_shown() is True

    def test_always_show_controls_is_ignored_on_compact(self):
        t = _target()
        display, fb, gt = _make_compact_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.persistent_overlay_shown() is False
        assert display.touch_surface()[0] == "hidden"

    def test_still_false_when_nothing_is_playing(self):
        # Compact does not hold an overlay over bare logo — same guard as
        # every other tier (self._now_playing is not None).
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        display._poll_once()
        assert display.persistent_overlay_shown() is False


class TestCompactRepeatControlsWindow:
    def _opened(self, aid):
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_compact_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        return display

    def test_opening_the_repeat_screen_shows_its_controls(self):
        display = self._opened("1" * 20)
        assert display._screen == "repeat"
        assert display.touch_surface()[0] == "repeat"

    def test_repeat_controls_hide_after_six_seconds(self):
        display = self._opened("2" * 20)
        clock = _FakeClock(time.monotonic())
        with patch_monotonic(clock):
            clock.t += dd.CONTROLS_HIDE_SECONDS + 0.1
            assert display.touch_surface()[0] == "hidden"

    def test_repeat_frame_falls_back_to_bare_base_once_hidden(self):
        display = self._opened("3" * 20)
        clock = _FakeClock(time.monotonic())
        with patch_monotonic(clock), \
             patch.object(display._compositor, "compose_repeat", wraps=display._compositor.compose_repeat) as spy:
            clock.t += dd.CONTROLS_HIDE_SECONDS + 0.1
            with display._lock:
                display._repaint_current_locked()
            assert spy.call_args.kwargs["controls"] is False

    def test_reveal_after_hidden_shows_repeat_again(self):
        display = self._opened("4" * 20)
        clock = _FakeClock(time.monotonic())
        with patch_monotonic(clock):
            clock.t += dd.CONTROLS_HIDE_SECONDS + 0.1
            assert display.touch_surface()[0] == "hidden"
            display.set_overlay(OverlayState(visible=True))
            assert display.touch_surface()[0] == "repeat"


class TestCompactStopFlow:
    def test_ok_stop_ack_closes_the_repeat_screen_to_main(self):
        import dial_repeat_store as drs
        aid = "5" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_compact_display(targets=[t], repeat_capable=True)
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

        drs.repeat_store.update(aid, drs.parse_repeat_object(
            _repeat_obj(state="replaying", replay={"active": True, "position_seconds": 1.0, "duration_seconds": 30.0}),
            time.monotonic(),
        ))
        with patch("dial_core.enqueue_transport"):
            display.repeat_stop_tap()
        on_repeat_result(display,
            "transport", aid, 200,
            {"ok": True, "state": "hold", "armed": False, "position_seconds": 0.0},
        )
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"
        assert display.touch_surface()[0] == "held"

    def test_rejected_stop_leaves_the_repeat_screen_open(self):
        import dial_repeat_store as drs
        aid = "6" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_compact_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()

        drs.repeat_store.update(aid, drs.parse_repeat_object(
            _repeat_obj(state="replaying", replay={"active": True, "position_seconds": 1.0, "duration_seconds": 30.0}),
            time.monotonic(),
        ))
        with patch("dial_core.enqueue_transport"):
            display.repeat_stop_tap()
        on_repeat_result(display, "transport", aid, 200, {"ok": False, "error": "fading_out"})
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

    def test_off_compact_the_same_ack_leaves_the_screen_on_repeat(self):
        import dial_repeat_store as drs
        aid = "7" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])  # base tier
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

        drs.repeat_store.update(aid, drs.parse_repeat_object(
            _repeat_obj(state="replaying", replay={"active": True, "position_seconds": 1.0, "duration_seconds": 30.0}),
            time.monotonic(),
        ))
        with patch("dial_core.enqueue_transport"):
            display.repeat_stop_tap()
        on_repeat_result(display,
            "transport", aid, 200,
            {"ok": True, "state": "hold", "armed": False, "position_seconds": 0.0},
        )
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"


class TestControlsShownDeadlineAndTick:
    def test_next_repaint_deadline_includes_the_window_end(self):
        t = _target()
        display, fb, gt = _make_compact_display(targets=[t], always_show_controls=False)
        display.enable()
        _poll_with_artwork(display, fb)
        clock = _FakeClock(time.monotonic())
        with patch_monotonic(clock):
            display.set_overlay(OverlayState(visible=True))
            deadline = display._next_repaint_deadline()
        assert deadline is not None
        assert deadline == pytest.approx(display._controls_shown_until + 0.005)

    def test_tick_controls_shown_signals_once_after_lapsing(self):
        t = _target()
        display, fb, gt = _make_compact_display(targets=[t], always_show_controls=False)
        display.enable()
        _poll_with_artwork(display, fb)
        clock = _FakeClock(time.monotonic())
        with patch_monotonic(clock):
            display.set_overlay(OverlayState(visible=True))
            clock.t += dd.CONTROLS_HIDE_SECONDS + 0.1
            display._overlay_signal.clear()
            display._tick_controls_shown()
            assert display._overlay_signal.is_set()
            assert display._controls_shown_until == 0.0
            display._overlay_signal.clear()
            display._tick_controls_shown()
            assert not display._overlay_signal.is_set()

    def test_off_compact_never_signals(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])  # base tier
        display.enable()
        _poll_with_artwork(display, fb)
        display._controls_shown_until = time.monotonic() - 1.0
        display._overlay_signal.clear()
        display._tick_controls_shown()
        assert not display._overlay_signal.is_set()


class TestCompactRepeatSurfaceFlip:
    def _opened(self, aid):
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_compact_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        return display

    def test_reports_repeat_while_the_enable_layout_is_shown(self):
        display = self._opened("1" * 20)
        assert display._screen == "repeat"
        assert display.touch_surface()[0] == "repeat"

    def test_flips_to_repeat_replay_once_a_replaying_view_is_painted(self):
        import dial_repeat_store as drs
        aid = "2" * 20
        display = self._opened(aid)
        drs.repeat_store.update(aid, drs.parse_repeat_object(
            _repeat_obj(state="replaying", replay={"active": True, "position_seconds": 1.0, "duration_seconds": 30.0}),
            time.monotonic(),
        ))
        with display._lock:
            display._repaint_current_locked()
        assert display.touch_surface()[0] == "repeat_replay"

    def test_hold_also_reports_repeat_replay(self):
        # "hold" builds the same "replaying" RepeatViewState.layout as a
        # running replay (see _build_repeat_view_locked) -- the compact
        # surface follows the layout, not the daemon state name.
        import dial_repeat_store as drs
        aid = "3" * 20
        display = self._opened(aid)
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="hold"), time.monotonic()))
        with display._lock:
            display._repaint_current_locked()
        assert display.touch_surface()[0] == "repeat_replay"

    def test_back_to_repeat_once_the_enable_layout_is_repainted(self):
        import dial_repeat_store as drs
        aid = "4" * 20
        display = self._opened(aid)
        drs.repeat_store.update(aid, drs.parse_repeat_object(
            _repeat_obj(state="replaying", replay={"active": True, "position_seconds": 1.0, "duration_seconds": 30.0}),
            time.monotonic(),
        ))
        with display._lock:
            display._repaint_current_locked()
        assert display.touch_surface()[0] == "repeat_replay"

        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="idle"), time.monotonic()))
        with display._lock:
            display._repaint_current_locked()
        assert display.touch_surface()[0] == "repeat"

    def test_never_reports_repeat_replay_off_compact(self):
        import dial_repeat_store as drs
        aid = "5" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])  # base tier, 160x128
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        drs.repeat_store.update(aid, drs.parse_repeat_object(
            _repeat_obj(state="replaying", replay={"active": True, "position_seconds": 1.0, "duration_seconds": 30.0}),
            time.monotonic(),
        ))
        with display._lock:
            display._repaint_current_locked()
        assert display.touch_surface()[0] == "repeat"


class TestCompactTimeTapBack:
    def test_a_dots_zone_tap_while_the_repeat_screen_is_open_closes_to_main(self):
        aid = "6" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_compact_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

        # dial_main.py's on_zone_tap routes every DOTS tap to this same
        # entry point regardless of which screen/layout drew the cell the
        # finger landed on -- the compact replaying layout's own "time"
        # strip is drawn there, but the dispatch is identical.
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"
        assert display.consume_repeat_close_reveal() is True


class TestCompactWrapPaging:
    def _opened_selector(self, count):
        targets = [
            _target(name=f"T{i}", service_name=f"T{i}", appliance_id=str(i) * 20,
                     auth="authorized", playing_since=float(i))
            for i in range(count)
        ]
        display, fb, gt = _make_compact_display(targets=targets)
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        return display, targets

    def test_rows_per_page_is_two(self):
        display, targets = self._opened_selector(count=3)
        with display._lock:
            assert display._metrics_locked().rows_per_page == 2

    def test_advancing_past_the_last_page_wraps_to_zero(self):
        display, targets = self._opened_selector(count=3)  # pages: [T0,T1], [T2]
        assert display._selector.page == 0
        display.list_page(+1)
        with display._lock:
            display._repaint_current_locked()
        assert display._selector.page == 1
        display.list_page(+1)
        with display._lock:
            display._repaint_current_locked()
        assert display._selector.page == 0

    def test_carried_paging_still_clamps_after_a_rebuild(self):
        # _carried_paging_locked() (a rebuild landing a stale page back into
        # range) keeps clamping even on compact -- only the touch-thread
        # advance itself wraps.
        display, targets = self._opened_selector(count=3)
        display.list_page(+1)
        with display._lock:
            display._repaint_current_locked()
        assert display._selector.page == 1
        _refresh_selector(display, [])
        assert display._selector.page == 0

    def test_off_compact_the_same_advance_clamps_instead(self):
        targets = [
            _target(name=f"T{i}", service_name=f"T{i}", appliance_id=str(i) * 20,
                     auth="authorized", playing_since=float(i))
            for i in range(5)
        ]
        display, fb, gt = make_display(targets=targets)  # base tier, rows_per_page == 3
        display.enable()
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        display.list_page(+5)
        with display._lock:
            display._repaint_current_locked()
        assert display._selector.page == 1  # clamped at the last page, not wrapped


class TestCompactDisplayListLockedPassesBase:
    def test_passes_the_current_base_image_through(self):
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        assert display._current_base_image is not None
        with patch.object(
            display._compositor, "compose_list", wraps=display._compositor.compose_list,
        ) as spy:
            with display._lock:
                display._screen = "picker"
                display._display_list_locked()
        assert spy.call_args.kwargs["base"] is display._current_base_image

    def test_base_tier_still_gets_the_same_argument_but_ignores_it(self):
        # The argument is passed unconditionally (see
        # _display_list_locked's own docstring); off compact it is simply
        # never read, so the rendered frame is unaffected.
        display, fb, gt = make_display(targets=[])
        display.enable()
        with patch.object(
            display._compositor, "compose_list", wraps=display._compositor.compose_list,
        ) as spy:
            with display._lock:
                display._screen = "picker"
                display._display_list_locked()
        assert spy.call_args.kwargs["base"] is display._current_base_image


class TestCompactPickerPick:
    def test_pick_index_one_starts_the_second_rows_replay(self):
        import dial_repeat_store as drs
        from dial_mdns import RosterEntry
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        rows = [
            RosterEntry(
                appliance_id="a" * 20, service_name="Kitchen", name="Kitchen",
                ip="10.0.0.9", port=8080, playing=False, repeat_capable=True, auth="authorized",
            ),
            RosterEntry(
                appliance_id="b" * 20, service_name="Lounge", name="Lounge",
                ip="10.0.0.10", port=8081, playing=False, repeat_capable=True, auth="authorized",
            ),
        ]
        now = time.monotonic()
        drs.repeat_store.update("a" * 20, drs.parse_repeat_object(_repeat_obj(state="hold", recording_seconds=12.0), now))
        drs.repeat_store.update("b" * 20, drs.parse_repeat_object(_repeat_obj(state="hold", recording_seconds=34.0), now))
        _refresh_picker(display, rows, now)
        display._core.set_roster(rows)
        display.core.set_field("idle_affordance", True)
        display.open_picker()
        with display._lock:
            display._repaint_current_locked()
        assert display._metrics_locked().rows_per_page == 2  # both rows fit on page 0

        with patch("dial_core.enqueue_transport") as mock_transport:
            display.picker_pick(1)
        target, action, position, token = mock_transport.call_args[0]
        assert target.appliance_id == "b" * 20
        assert action == "seek"
        assert position == 0.0
        assert display.core.manual_focus_id() == "b" * 20


# ---------------------------------------------------------------------------
# The idle screen's read-only info page: open_info()/_gather_info()/
# set_info_provider(), paging, lifetime, and the dead-row guard.
# ---------------------------------------------------------------------------

class TestInfoPage:
    def _opened(self, display) -> int:
        """open_info() with the gather thread never actually started (it is
        exercised directly, synchronously, by the tests that need it — the
        same discipline TestOnOutputsResult uses for its own worker-thread
        callback), then fold the pending screen request in. Returns the
        gather_seq this open captured."""
        with patch("dial_display.threading.Thread"):
            display.open_info()
        with display._lock:
            display._repaint_current_locked()
        return display._info_gather_seq

    def test_open_info_requests_the_screen_and_starts_one_gather_thread(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with patch("dial_display.threading.Thread") as mock_thread_cls:
            display.open_info()
        assert display._screen_request == "info"
        assert display._info_gather_seq == 1
        _, kwargs = mock_thread_cls.call_args
        assert kwargs["target"] == display._gather_info
        assert kwargs["args"] == (1,)
        assert kwargs["daemon"] is True
        mock_thread_cls.return_value.start.assert_called_once()

    def test_first_paint_shows_six_placeholder_rows(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        self._opened(display)
        assert display._screen == "info"
        assert display._info.rows == dd.INFO_PLACEHOLDER_ROWS

    def test_gather_fills_in_the_providers_rows(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        provided = (
            ("Dial name", "Kitchen"), ("Firmware", "1.0"), ("IPv4", "10.0.0.5"),
            ("WiFi", "HomeNet"), ("Signal", "Strong"), ("Disk free", "14.2 GB"),
        )
        display.set_info_provider(lambda: provided)
        seq = self._opened(display)
        display._gather_info(seq)
        assert tuple((r.label, r.value) for r in display._info.rows) == provided

    def test_provider_raising_leaves_the_placeholders(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.set_info_provider(MagicMock(side_effect=RuntimeError("boom")))
        seq = self._opened(display)
        display._gather_info(seq)
        assert display._info.rows == dd.INFO_PLACEHOLDER_ROWS

    def test_missing_provider_yields_placeholders(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        seq = self._opened(display)
        display._gather_info(seq)
        assert display._info.rows == dd.INFO_PLACEHOLDER_ROWS

    def test_stale_gather_after_close_reopen_is_dropped(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        stale_seq = self._opened(display)
        display.close_list()
        with display._lock:
            display._repaint_current_locked()
        display.set_info_provider(lambda: (("Dial name", "Fresh open"),) * 1)
        fresh_seq = self._opened(display)
        assert fresh_seq != stale_seq
        display._gather_info(stale_seq)
        assert display._info.rows == dd.INFO_PLACEHOLDER_ROWS

    def test_result_after_close_is_dropped(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        seq = self._opened(display)
        display.close_list()
        with display._lock:
            display._repaint_current_locked()
        assert display._info is None
        display.set_info_provider(lambda: (("Dial name", "Too late"),))
        display._gather_info(seq)  # must not raise, must not resurrect _info
        assert display._info is None

    def test_list_row_tap_on_info_is_a_no_op(self):
        # Rich/large: the row is dead at the geometry level too (GEOMETRY_
        # INFO carries no LIST_ROW entries there) — this is belt-and-braces
        # only. make_display() is a base/rich fixture, never compact.
        display, fb, gt = make_display(targets=[])
        display.enable()
        self._opened(display)
        with patch.object(display, "selector_pick") as sp, \
             patch.object(display, "picker_pick") as pp, \
             patch.object(display, "outputs_row_tap") as op, \
             patch.object(display, "info_row_tap") as ip:
            display.list_row_tap(0)
        sp.assert_not_called()
        pp.assert_not_called()
        op.assert_not_called()
        ip.assert_not_called()
        assert display._screen == "info"

    def test_list_row_tap_on_compact_info_calls_info_row_tap(self):
        # On the compact tier the row IS tappable — see TestInfoRowTap for
        # the actual index mapping.
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        self._opened(display)
        with patch.object(display, "info_row_tap") as ip:
            display.list_row_tap(1)
        ip.assert_called_once_with(1)


class TestInfoPagePaging:
    def test_rich_five_plus_two_across_two_pages(self):
        fb = FakeBackend()
        fb.width, fb.height = 320, 240
        display, fb, gt = make_display(screen_type="ili9341_320x240", backend=fb, targets=[])
        display.enable()
        with patch("dial_display.threading.Thread"):
            display.open_info()
        with display._lock:
            display._repaint_current_locked()
        with display._lock:
            metrics = display._metrics_locked()
            page0 = display._build_info_list_state_locked(metrics.width, metrics.height, metrics=metrics)
        assert metrics.rows_per_page == 5  # richer tier on this 2.8-inch 320x240 panel
        assert len(page0.rows) == 5
        assert page0.has_prev is False
        assert page0.has_next is True

        display.list_page(+1)
        with display._lock:
            display._repaint_current_locked()
        with display._lock:
            page1 = display._build_info_list_state_locked(metrics.width, metrics.height, metrics=metrics)
        assert len(page1.rows) == 2  # the seventh field ("SD health") spills onto page 1
        assert page1.has_prev is True
        assert page1.has_next is False

    def test_compact_two_per_page_across_four_pages_wraps(self):
        # Seven info fields at two per compact page: ceil(7/2) == 4 pages
        # (the seventh, "SD health", alone on the last page).
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        with patch("dial_display.threading.Thread"):
            display.open_info()
        with display._lock:
            display._repaint_current_locked()
        assert display._info.page == 0

        display.list_page(+1)
        with display._lock:
            display._repaint_current_locked()
        assert display._info.page == 1

        display.list_page(+1)
        with display._lock:
            display._repaint_current_locked()
        assert display._info.page == 2

        display.list_page(+1)
        with display._lock:
            display._repaint_current_locked()
        assert display._info.page == 3

        display.list_page(+1)  # wraps back to page 0 on compact
        with display._lock:
            display._repaint_current_locked()
        assert display._info.page == 0


class TestInfoPageLifetime:
    def _opened(self, display) -> None:
        with patch("dial_display.threading.Thread"):
            display.open_info()
        with display._lock:
            display._repaint_current_locked()

    def test_x_closes_to_main(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        self._opened(display)
        assert display._screen == "info"
        display.close_list()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"

    def test_closes_after_timeout(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        self._opened(display)
        opened_at = display._info.opened_at
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS + 1):
            display._check_secondary_timeout()
        assert display._screen == "main"

    def test_stays_open_before_timeout(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        self._opened(display)
        opened_at = display._info.opened_at
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS - 1):
            display._check_secondary_timeout()
        assert display._screen == "info"

    def test_touch_activity_extends_the_timeout(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        self._opened(display)
        old_opened_at = display._info.opened_at
        display.notify_touch_activity()
        with patch("dial_display.time.monotonic", return_value=old_opened_at + 1):
            with display._lock:
                display._apply_touch_activity_locked()
        assert display._info.opened_at > old_opened_at

    def test_sleep_is_deferred_while_open(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        self._opened(display)
        gt.return_value = []
        with patch.object(display, "_close_secondary_locked") as close:
            display._poll_once()
        close.assert_not_called()
        assert display._idle_started_at is None


class TestInfoRowTap:
    """info_row_tap(): the compact info list's own row->field mapping,
    including through paging and the compact wrap — see _current_page_rows/
    _rows_per_page, the same slice the repaint thread paints with."""

    def _opened(self, display) -> None:
        with patch("dial_display.threading.Thread"):
            display.open_info()
        with display._lock:
            display._repaint_current_locked()

    def test_maps_row_to_absolute_index_on_page_0(self):
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        self._opened(display)
        display.info_row_tap(1)
        assert display._info_value_index == 1
        assert display._screen_request == "info_value"

    def test_maps_row_to_absolute_index_on_page_2(self):
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        self._opened(display)
        display.list_page(+1)
        with display._lock:
            display._repaint_current_locked()
        display.list_page(+1)
        with display._lock:
            display._repaint_current_locked()
        assert display._info.page == 2
        display.info_row_tap(1)
        # Page 2's second row is field 2*2+1 == 5 — "Disk free".
        assert display._info_value_index == 5
        assert display._info.rows[5].label == "Disk free"

    def test_maps_correctly_after_a_wrap_back_to_page_0(self):
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        self._opened(display)
        for _ in range(4):  # 4 compact pages (7 rows / 2 per page): wraps
            display.list_page(+1)
            with display._lock:
                display._repaint_current_locked()
        assert display._info.page == 0
        display.info_row_tap(0)
        assert display._info_value_index == 0

    def test_stale_index_leaves_the_list_open_and_requests_nothing(self):
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        self._opened(display)
        # Only 2 rows on the current page (indices 0/1) — 5 is stale.
        display.info_row_tap(5)
        assert display._screen_request is None
        assert display._info_value_index is None
        assert display._screen == "info"

    def test_no_op_with_the_list_closed(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.info_row_tap(0)
        assert display._screen_request is None
        assert display._info_value_index is None


class TestInfoValueScreen:
    """InfoValueState / _open_info_value_locked / _display_info_value_locked:
    the compact info page's own drill-in lifecycle — opens from a row tap,
    reads its value fresh from self._info at every paint, times out and
    tap-backs like every other list screen, and preserves the list's page
    on return."""

    def _opened_list(self, display) -> None:
        with patch("dial_display.threading.Thread"):
            display.open_info()
        with display._lock:
            display._repaint_current_locked()

    def _opened_value(self, display, index: int = 0) -> None:
        self._opened_list(display)
        display.info_row_tap(index)
        with display._lock:
            display._repaint_current_locked()

    def test_opens_from_a_row_tap_and_keeps_the_list_as_its_parent(self):
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        self._opened_value(display, 0)
        assert display._screen == "info_value"
        assert display._info_value.index == 0
        assert display._info is not None

    def test_refuses_when_the_info_list_is_not_open(self):
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        display._info_value_index = 0
        display._screen_request = "info_value"
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"
        assert display._info_value is None

    def test_refuses_a_stale_index(self):
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        self._opened_list(display)
        display._info_value_index = 999
        display._screen_request = "info_value"
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "info"
        assert display._info_value is None

    def test_paint_shows_the_tapped_fields_fresh_label_and_value(self):
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        provided = (
            ("Dial name", "Kitchen"), ("Firmware", "1.0"), ("IPv4", "10.0.0.5"),
            ("WiFi", "HomeNet"), ("Signal", "Strong"), ("Disk free", "14.2 GB"),
        )
        display.set_info_provider(lambda: provided)
        self._opened_list(display)
        display._gather_info(display._info_gather_seq)
        display.list_page(+1)  # page 1: page-relative row 0 is field 2, "IPv4"
        with display._lock:
            display._repaint_current_locked()
        display.info_row_tap(0)
        with patch.object(
            display._compositor, "compose_info_value", wraps=display._compositor.compose_info_value,
        ) as spy:
            with display._lock:
                display._repaint_current_locked()
        assert display._screen == "info_value"
        view = spy.call_args.args[2]
        assert (view.label, view.value) == ("IPv4", "10.0.0.5")

    def test_a_gather_landing_while_open_updates_the_value_on_next_repaint(self):
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        self._opened_value(display, 0)  # "Dial name", placeholder "-"
        assert display._screen == "info_value"
        display.set_info_provider(lambda: (("Dial name", "Fresh Kitchen"),) + tuple(
            (r.label, r.value) for r in display._info.rows[1:]
        ))
        display._gather_info(display._info_gather_seq)
        with patch.object(
            display._compositor, "compose_info_value", wraps=display._compositor.compose_info_value,
        ) as spy:
            with display._lock:
                display._repaint_current_locked()
        view = spy.call_args.args[2]
        assert view.value == "Fresh Kitchen"

    def test_close_from_the_value_view_returns_to_info_at_the_same_page(self):
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        self._opened_list(display)
        display.list_page(+1)
        with display._lock:
            display._repaint_current_locked()
        assert display._info.page == 1
        display.info_row_tap(0)
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "info_value"
        display.close_list()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "info"
        assert display._info.page == 1

    def test_closes_after_timeout_and_clears_both_states(self):
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        self._opened_value(display, 0)
        opened_at = display._info_value.opened_at
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS + 1):
            display._check_secondary_timeout()
        assert display._screen == "main"
        assert display._info_value is None
        assert display._info is None

    def test_stays_open_before_timeout(self):
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        self._opened_value(display, 0)
        opened_at = display._info_value.opened_at
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS - 1):
            display._check_secondary_timeout()
        assert display._screen == "info_value"

    def test_touch_activity_extends_the_timeout(self):
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        self._opened_value(display, 0)
        old_opened_at = display._info_value.opened_at
        display.notify_touch_activity()
        with patch("dial_display.time.monotonic", return_value=old_opened_at + 1):
            with display._lock:
                display._apply_touch_activity_locked()
        assert display._info_value.opened_at > old_opened_at

    def test_sleep_is_deferred_while_open(self):
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        self._opened_value(display, 0)
        gt.return_value = []
        with patch.object(display, "_close_secondary_locked") as close:
            display._poll_once()
        close.assert_not_called()
        assert display._idle_started_at is None

    def test_touch_surface_reports_info_value(self):
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        self._opened_value(display, 0)
        assert display.touch_surface() == ("info_value", False, False, False)


# ---------------------------------------------------------------------------
# The Wi-Fi link state machine: the idle icon, the No-WiFi page and the
# "Restarting..." screen driven by dial_network's poller callback.
# ---------------------------------------------------------------------------

def _view(link, bars=0):
    return NetworkView(link=link, device_state="", bars=bars, updated_at=1.0)


def _fold(display):
    with display._lock:
        display._repaint_current_locked()


class TestNoWifiStateMachine:
    def _idle_display(self, connected=True):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._poll_once()          # nothing playing: idle screen, _now_playing None
        _fold(display)
        if connected:
            # The common case for the incident tests below: a link that was
            # up since boot and is now lost.
            on_network_view(display, _view(LINK_CONNECTED, bars=3))
        return display, fb

    def test_unknown_before_first_poll_draws_steady_grey(self):
        display, fb = self._idle_display(connected=False)
        with display._lock:
            assert display._idle_wifi_args_locked() == (0, WIFI_GREY)
        assert display._wifi_flashing() is False

    def test_connected_view_gives_steady_bars(self):
        display, fb = self._idle_display()
        on_network_view(display, _view(LINK_CONNECTED, bars=2))
        with display._lock:
            assert display._idle_wifi_args_locked() == (2, WIFI_SIGNAL)
        assert display._wifi_flashing() is False
        assert display._screen_request is None

    def test_down_after_a_connection_flashes_grey_red_with_the_monotonic_phase(self):
        display, fb = self._idle_display()
        on_network_view(display, _view(LINK_DOWN))
        assert display._wifi_flashing() is True
        with patch("dial_display.time.monotonic", return_value=1000.0):
            with display._lock:
                assert display._idle_wifi_args_locked() == (0, WIFI_RED)
        with patch("dial_display.time.monotonic", return_value=1000.5):
            with display._lock:
                assert display._idle_wifi_args_locked() == (0, WIFI_GREY)

    def test_flash_deadline_is_the_next_half_period(self):
        display, fb = self._idle_display()
        on_network_view(display, _view(LINK_DOWN))
        with patch("dial_display.time.monotonic", return_value=1000.2):
            assert display._next_repaint_deadline() == pytest.approx(1000.5 + 0.005)

    def test_tick_wifi_flash_signals_only_while_flashing(self):
        display, fb = self._idle_display()
        display._overlay_signal.clear()
        display._tick_wifi_flash()
        assert not display._overlay_signal.is_set()
        on_network_view(display, _view(LINK_DOWN))
        display._overlay_signal.clear()
        display._tick_wifi_flash()
        assert display._overlay_signal.is_set()

    def test_no_flash_off_the_idle_screen(self):
        display, fb = self._idle_display()
        on_network_view(display, _view(LINK_DOWN))
        with patch("dial_display.threading.Thread"):
            display.open_info()
        _fold(display)
        assert display._screen == "info"
        assert display._wifi_flashing() is False

    def test_streak_of_three_opens_the_page_from_main(self):
        display, fb = self._idle_display()
        for expected in (None, None, "nowifi"):
            on_network_view(display, _view(LINK_DOWN))
            assert display._screen_request == expected
        _fold(display)
        assert display._screen == "nowifi"
        assert display._warning_screen is not None and display._warning_screen.warning_id == "nowifi"
        assert display.touch_surface() == ("nowifi", False, False, False)

    def test_unknown_does_not_reset_or_advance_the_streak(self):
        display, fb = self._idle_display()
        on_network_view(display, _view(LINK_DOWN))
        on_network_view(display, _view(LINK_DOWN))
        on_network_view(display, _view(LINK_UNKNOWN))
        assert display.core.wifi_down_streak() == 2 and display._screen_request is None
        on_network_view(display, _view(LINK_DOWN))
        assert display._screen_request == "nowifi"

    def test_ignored_resets_the_streak_but_keeps_the_dismissal(self):
        display, fb = self._idle_display()
        display.core.warnings.dismiss("nowifi")
        on_network_view(display, _view(LINK_DOWN))
        on_network_view(display, _view(LINK_IGNORED))
        assert display.core.wifi_down_streak() == 0 and display.core.warnings.is_snoozed("nowifi")
        assert display._screen_request is None

    def test_connected_auto_closes_the_page_and_ends_the_incident(self):
        display, fb = self._idle_display()
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        _fold(display)
        assert display._screen == "nowifi"
        on_network_view(display, _view(LINK_CONNECTED, bars=3))
        assert display._screen_request == "main"
        _fold(display)
        assert display._screen == "main" and display._warning_screen is None
        assert display.core.wifi_down_streak() == 0 and not display.core.warnings.is_snoozed("nowifi")

    def test_connected_cancels_a_pending_open(self):
        display, fb = self._idle_display()
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        assert display._screen_request == "nowifi"
        on_network_view(display, _view(LINK_CONNECTED, bars=1))
        assert display._screen_request is None

    def test_dismiss_suppresses_reopen_until_connected(self):
        display, fb = self._idle_display()
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        _fold(display)
        run_warning_action(display, "nowifi", dd.ACTION_DISMISS)
        assert display.core.warnings.is_snoozed("nowifi")
        _fold(display)
        assert display._screen == "main"
        for _ in range(5):
            on_network_view(display, _view(LINK_DOWN))
        assert display._screen_request is None            # suppressed
        assert display._wifi_flashing() is True           # icon still flashes
        on_network_view(display, _view(LINK_CONNECTED, bars=2))
        on_network_view(display, _view(LINK_DOWN))
        on_network_view(display, _view(LINK_DOWN))
        assert display._screen_request is None
        on_network_view(display, _view(LINK_DOWN))
        assert display._screen_request == "nowifi"        # a fresh incident

    def test_icon_tap_opens_despite_dismissal_and_is_inert_while_connected(self):
        display, fb = self._idle_display()
        on_network_view(display, _view(LINK_CONNECTED, bars=3))
        display.open_nowifi()
        assert display._screen_request is None
        on_network_view(display, _view(LINK_DOWN))
        display.core.warnings.dismiss("nowifi")
        display.open_nowifi()
        assert display._screen_request == "nowifi"
        _fold(display)
        assert display._screen == "nowifi"

    def test_latch_survives_disable_and_enable(self):
        display, fb = self._idle_display()
        display.disable()
        display.enable()
        assert display.core.snapshot().wifi_ever_connected is True

    def test_never_connected_down_flashes_grey_off_with_the_monotonic_phase(self):
        display, fb = self._idle_display(connected=False)
        on_network_view(display, _view(LINK_DOWN))
        assert display._wifi_flashing() is True
        with patch("dial_display.time.monotonic", return_value=1000.0):
            with display._lock:
                assert display._idle_wifi_args_locked() == (0, WIFI_OFF)
        with patch("dial_display.time.monotonic", return_value=1000.5):
            with display._lock:
                assert display._idle_wifi_args_locked() == (0, WIFI_GREY)

    def test_flash_turns_red_once_a_connection_has_been_lost(self):
        display, fb = self._idle_display(connected=False)
        on_network_view(display, _view(LINK_DOWN))
        with patch("dial_display.time.monotonic", return_value=1000.0), display._lock:
            assert display._idle_wifi_args_locked() == (0, WIFI_OFF)
        on_network_view(display, _view(LINK_CONNECTED, bars=2))
        on_network_view(display, _view(LINK_DOWN))
        with patch("dial_display.time.monotonic", return_value=1000.0), display._lock:
            assert display._idle_wifi_args_locked() == (0, WIFI_RED)

    def test_no_auto_prompt_before_the_first_connection(self):
        display, fb = self._idle_display(connected=False)
        for _ in range(NOWIFI_PROMPT_STREAK + 3):
            on_network_view(display, _view(LINK_DOWN))
        assert display._screen_request is None
        assert display.core.wifi_down_streak() == NOWIFI_PROMPT_STREAK + 3   # still counted
        assert display._wifi_flashing() is True                        # icon still flashes
        _fold(display)
        assert display._screen == "main"

    def test_auto_prompt_after_a_loss_following_a_connection(self):
        display, fb = self._idle_display(connected=False)
        for _ in range(4):
            on_network_view(display, _view(LINK_DOWN))
        assert display._screen_request is None
        on_network_view(display, _view(LINK_CONNECTED, bars=3))
        for expected in (None, None, "nowifi"):
            on_network_view(display, _view(LINK_DOWN))
            assert display._screen_request == expected

    def test_icon_tap_opens_the_page_before_the_first_connection(self):
        display, fb = self._idle_display(connected=False)
        on_network_view(display, _view(LINK_DOWN))
        display.open_nowifi()
        assert display._screen_request == "nowifi"
        _fold(display)
        assert display._screen == "nowifi"
        assert display.touch_surface() == ("nowifi", False, False, False)

    def test_idle_frame_is_composed_with_the_off_style_on_the_blank_half(self):
        display, fb = self._idle_display(connected=False)
        on_network_view(display, _view(LINK_DOWN))
        with patch.object(display._compositor, "compose_idle",
                          wraps=display._compositor.compose_idle) as compose, \
             patch("dial_display.time.monotonic", return_value=1000.0):
            _fold(display)
        assert compose.call_args.kwargs["wifi_style"] == WIFI_OFF
        assert compose.call_args.kwargs["wifi_bars"] == 0

    def test_idle_frame_is_composed_with_the_red_style_after_a_loss(self):
        display, fb = self._idle_display()
        on_network_view(display, _view(LINK_DOWN))
        with patch.object(display._compositor, "compose_idle",
                          wraps=display._compositor.compose_idle) as compose, \
             patch("dial_display.time.monotonic", return_value=1000.0):
            _fold(display)
        assert compose.call_args.kwargs["wifi_style"] == WIFI_RED

    def test_auto_open_never_stomps_on_another_screen(self):
        display, fb = self._idle_display()
        with patch("dial_display.threading.Thread"):
            display.open_info()
        _fold(display)
        for _ in range(4):
            on_network_view(display, _view(LINK_DOWN))
        assert display._screen_request is None and display._screen == "info"
        display.close_list()
        _fold(display)
        on_network_view(display, _view(LINK_DOWN))
        assert display._screen_request == "nowifi"

    def test_page_has_no_timeout(self):
        display, fb = self._idle_display()
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        _fold(display)
        with patch("dial_display.time.monotonic", return_value=time.monotonic() + 3600):
            display._check_secondary_timeout()
        assert display._screen == "nowifi"

    def test_page_paints_a_frame(self):
        display, fb = self._idle_display()
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        before = len(fb.displayed)
        _fold(display)
        assert len(fb.displayed) == before + 1

    def test_page_does_not_defer_the_idle_sleep_clock(self):
        # defers_sleep=False: the No-WiFi page sleeps with the normal idle
        # timer rather than holding the panel lit for as long as the link
        # stays down. _idle_display() has already run one _poll_once() on
        # the bare idle screen, so the clock is already ticking; opening the
        # page must not reset it back to None the way an actual list screen
        # would.
        display, fb = self._idle_display()
        assert display._idle_started_at is not None
        started_at = display._idle_started_at
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        _fold(display)
        assert display._screen == "nowifi"
        display._poll_once()
        assert display._idle_started_at == started_at

    def test_sleeps_with_the_normal_idle_timer_and_the_wake_reraises(self):
        display, fb = self._idle_display()
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        _fold(display)
        assert display._screen == "nowifi"
        with patch("dial_display.time.monotonic",
                   return_value=time.monotonic() + dd.DISPLAY_IDLE_SLEEP_SECONDS + 1):
            display._poll_once()
        assert display._display_sleeping is True
        assert display._screen == "main" and display._warning_screen is None
        # The incident's streak is intact (sleeping never resets it, only a
        # connected/ignored poll does), but a poll while asleep sets no
        # request of its own: the request is the wake path's job.
        on_network_view(display, _view(LINK_DOWN))
        assert display._screen_request is None
        display.notify_touch_activity()
        _fold(display)
        assert display._screen == "nowifi"

    def test_restart_tap_shows_restarting_and_requests_the_reboot(self):
        display, fb = self._idle_display()
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        _fold(display)
        with patch("dial_display._request_reboot") as reboot:
            run_warning_action(display, "nowifi", dd.ACTION_RESTART)
        reboot.assert_called_once_with()
        _fold(display)
        assert display._screen == "restarting" and display._warning_screen is None
        assert display.touch_surface() == ("restarting", False, False, False)

    def test_nowifi_open_refused_while_restarting(self):
        display, fb = self._idle_display()
        on_network_view(display, _view(LINK_DOWN))
        with patch("dial_display._request_reboot"):
            run_warning_action(display, "nowifi", dd.ACTION_RESTART)
        _fold(display)
        on_network_view(display, _view(LINK_DOWN))
        on_network_view(display, _view(LINK_DOWN))
        on_network_view(display, _view(LINK_DOWN))
        assert display._screen_request is None            # not "main", so the streak gate holds
        display._screen_request = "nowifi"
        _fold(display)
        assert display._screen == "restarting"

    def test_restarting_falls_back_to_main_after_its_timeout(self):
        display, fb = self._idle_display()
        with patch("dial_display._request_reboot"):
            run_warning_action(display, "nowifi", dd.ACTION_RESTART)
        _fold(display)
        with patch("dial_display.time.monotonic", return_value=time.monotonic() + dd.RESTARTING_TIMEOUT_SECONDS + 1):
            display._check_secondary_timeout()
        assert display._screen == "main" and display._restarting is None

    def test_callback_never_raises(self):
        display, fb = self._idle_display()
        on_network_view(display, object())        # no .link attribute
        on_network_view(display, None)

    def test_sleep_pops_the_page(self):
        display, fb = self._idle_display()
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        _fold(display)
        with display._lock:
            display._sleep_locked()
        assert display._screen == "main" and display._warning_screen is None

    def test_restart_then_reboot_failure_timeout_lets_the_tick_reraise(self):
        display, fb = self._idle_display()
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        _fold(display)
        with patch("dial_display._request_reboot"):
            run_warning_action(display, "nowifi", dd.ACTION_RESTART)
        _fold(display)
        assert display._screen == "restarting"
        with patch("dial_display.time.monotonic",
                   return_value=time.monotonic() + dd.RESTARTING_TIMEOUT_SECONDS + 1):
            display._check_secondary_timeout()
            tick_warnings(display)
        assert display._screen_request == "nowifi"

    def test_warning_button_tap_routes_by_zone(self):
        display, fb = self._idle_display()
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        _fold(display)
        assert display._screen == "nowifi"
        with patch("dial_display._request_reboot") as reboot:
            display.warning_button_tap(TouchZone.NOWIFI_RESTART)
        reboot.assert_called_once_with()
        assert display._screen_request == "restarting"

        display2, fb2 = self._idle_display()
        for _ in range(3):
            on_network_view(display2, _view(LINK_DOWN))
        _fold(display2)
        assert display2._screen == "nowifi"
        display2.warning_button_tap(TouchZone.NOWIFI_DISMISS)
        assert display2.core.warnings.is_snoozed("nowifi")

    def test_stale_warning_zone_with_no_page_falls_back_to_the_registry_owner(self):
        display, fb = self._idle_display()
        assert display._warning_screen is None
        display.warning_button_tap(TouchZone.NOWIFI_DISMISS)
        assert display.core.warnings.is_snoozed("nowifi")

    def test_compact_page_paints(self):
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        display._poll_once()
        _fold(display)
        on_network_view(display, _view(LINK_CONNECTED, bars=3))
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        before = len(fb.displayed)
        _fold(display)
        assert display._screen == "nowifi" and len(fb.displayed) == before + 1


# ---------------------------------------------------------------------------
# The SD card warning: opened by on_sd_health_view(), same discipline as
# the No-WiFi page (see dial_sdhealth.py for is_low()'s hysteresis rule).
# ---------------------------------------------------------------------------

class _Clock:
    """A settable fake wall clock for the warning manager's snooze math:
    pass `.now` as WarningManager's clock= and move `.t` directly."""

    def __init__(self, t: float) -> None:
        self.t = t

    def now(self) -> float:
        return self.t


def _sd_view(status, percent=None, check="passed"):
    return SdHealthView(status=status, percent=percent, check=check, updated_at=1.0)


class TestSdHealthStateMachine:
    def _idle_display(self, **kwargs):
        display, fb, gt = make_display(targets=[], **kwargs)
        display.enable()
        display._poll_once()
        _fold(display)
        return display, fb

    def test_low_view_on_main_requests_sdhealth(self):
        display, fb = self._idle_display()
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        assert display._screen_request == "sdhealth"

    def test_folding_opens_it(self):
        display, fb = self._idle_display()
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        assert display._screen == "sdhealth"
        assert display._warning_screen is not None and display._warning_screen.warning_id == "sdhealth"
        assert display.touch_surface() == ("sdhealth", False, False, False)

    def test_second_low_view_does_not_re_request(self):
        display, fb = self._idle_display()
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        display._screen_request = None
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=14))
        # Passes because the page is already open (screen != "main"), not
        # because of any per-incident latch.
        assert display._screen == "sdhealth"
        assert display._screen_request is None

    def test_stale_dismiss_zone_with_no_page_falls_back_to_the_registry_owner(self):
        display, fb = self._idle_display()
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        assert display._warning_screen is None        # requested, not yet folded in
        display.warning_button_tap(TouchZone.SDHEALTH_DISMISS)
        assert display.core.warnings.is_snoozed("sdhealth")

    def test_dismiss_tap_requests_main(self):
        display, fb = self._idle_display()
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        run_warning_action(display, "sdhealth", dd.ACTION_DISMISS)
        assert display._screen_request == "main"
        assert display.core.warnings.is_snoozed("sdhealth")

    def test_recovered_view_closes_open_page_and_clears_latch(self):
        display, fb = self._idle_display()
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        assert display._screen == "sdhealth"
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=26))
        assert display._screen_request == "main"
        assert display.core.sd_low() is False
        _fold(display)
        assert display._screen == "main"

    def test_hysteresis_zone_after_recovery_does_not_reopen(self):
        display, fb = self._idle_display()
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=26))
        _fold(display)
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=23))
        assert display._screen_request is None

    def test_low_view_while_selector_open_does_not_request(self):
        display, fb = self._idle_display()
        display.open_selector()
        _fold(display)
        assert display._screen == "selector"
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=10))
        assert display._screen_request is None

    def test_low_view_while_info_open_does_not_request(self):
        display, fb = self._idle_display()
        with patch("dial_display.threading.Thread"):
            display.open_info()
        _fold(display)
        assert display._screen == "info"
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=10))
        assert display._screen_request is None

    def test_low_view_while_nowifi_open_does_not_request(self):
        display, fb = self._idle_display()
        on_network_view(display, _view(LINK_CONNECTED, bars=3))
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        _fold(display)
        assert display._screen == "nowifi"
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=10))
        assert display._screen_request is None

    def test_lower_priority_never_opens_over_a_higher_one(self):
        display, fb = self._idle_display()
        on_network_view(display, _view(LINK_CONNECTED, bars=3))
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        _fold(display)
        assert display._screen == "nowifi"
        with display._lock:
            assert display._open_warning_locked(warning_id="sdhealth") is False

    def test_no_timeout_holds_the_page(self):
        display, fb = self._idle_display()
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        with patch("dial_display.time.monotonic", return_value=time.monotonic() + 3600):
            display._check_secondary_timeout()
        assert display._screen == "sdhealth"

    def test_sleep_pops_it_and_wake_reshows_it(self):
        display, fb = self._idle_display()
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        with display._lock:
            display._sleep_locked()
        assert display._screen == "main" and display._warning_screen is None
        # Still latched low: a later poll must not re-raise on its own
        # (only a fresh on_sd_health_view decides, and the latch is
        # untouched by sleeping); the wake path brings the page back.
        assert display.core.sd_low() is True
        display.notify_touch_activity()
        _fold(display)
        assert display._screen == "sdhealth"

    def test_unsupported_view_ends_the_incident(self):
        display, fb = self._idle_display()
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        on_sd_health_view(display, _sd_view(STATUS_UNSUPPORTED, check="failed"))
        assert display.core.sd_low() is False
        assert display._screen_request == "main"

    def test_off_view_ends_the_incident(self):
        display, fb = self._idle_display()
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        on_sd_health_view(display, _sd_view(STATUS_OFF, check="none"))
        assert display.core.sd_low() is False
        assert display._screen_request == "main"

    def test_painter_calls_compose_sdhealth_with_current_percent(self):
        display, fb = self._idle_display()
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=17))
        _fold(display)
        assert display._screen == "sdhealth"
        with patch.object(
            display._compositor, "compose_warning", wraps=display._compositor.compose_warning,
        ) as mock_compose:
            with display._lock:
                display._display_warning_locked()
        assert mock_compose.call_args.args[3].message == "17%: Replace Soon"
        assert mock_compose.call_args.args[3].buttons == ("Dismiss",)

    def test_dismiss_then_wake_does_not_reshow(self):
        display, fb = self._idle_display()
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        run_warning_action(display, "sdhealth", dd.ACTION_DISMISS)
        _fold(display)
        assert display._screen == "main"
        display.notify_touch_activity()
        _fold(display)
        assert display._screen == "main"

    def test_snooze_expiry_reshows_via_the_tick(self):
        clock = _Clock(1_000_000.0)
        display, fb = self._idle_display(wall_clock=clock.now)
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        run_warning_action(display, "sdhealth", dd.ACTION_DISMISS)
        _fold(display)
        assert display._screen == "main"
        clock.t += 604801.0
        tick_warnings(display)
        assert display._screen_request == "sdhealth"

    def test_recovered_reading_forgets_the_snooze(self):
        display, fb = self._idle_display()
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        run_warning_action(display, "sdhealth", dd.ACTION_DISMISS)
        _fold(display)
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=26))
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=10))
        assert display._screen_request == "sdhealth"

    def test_dismiss_is_written_by_the_tick_not_the_tap(self, tmp_path):
        path = str(tmp_path / "w.json")
        warnings = WarningManager(WARNING_DESCRIPTORS, WarningStore(path))
        display, fb = self._idle_display(warnings=warnings)
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        run_warning_action(display, "sdhealth", dd.ACTION_DISMISS)
        assert not Path(path).exists()
        tick_warnings(display)
        assert json.loads(Path(path).read_text(encoding="utf-8")).keys() == {"sdhealth"}

    def test_persisted_snooze_suppresses_the_page_after_a_restart(self, tmp_path):
        path = tmp_path / "w.json"
        now = time.time()
        path.write_text(json.dumps({"sdhealth": now + 604800.0}), encoding="utf-8")
        warnings = WarningManager(WARNING_DESCRIPTORS, WarningStore(str(path)))
        display, fb = self._idle_display(warnings=warnings)
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        assert display._screen_request is None

        path.write_text(json.dumps({"sdhealth": now - 1.0}), encoding="utf-8")
        warnings2 = WarningManager(WARNING_DESCRIPTORS, WarningStore(str(path)))
        display2, fb2 = self._idle_display(warnings=warnings2)
        on_sd_health_view(display2, _sd_view(STATUS_VALID, percent=15))
        assert display2._screen_request == "sdhealth"

    def test_nowifi_outranks_sdhealth_when_both_become_due_at_once(self):
        display, fb = self._idle_display()
        on_network_view(display, _view(LINK_CONNECTED, bars=3))
        with patch("dial_display.threading.Thread"):
            display.open_info()
        _fold(display)
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=10))
        display.close_list()
        _fold(display)
        tick_warnings(display)
        _fold(display)
        assert display._screen == "nowifi"

    def test_stop_flushes_the_store(self, tmp_path):
        path = str(tmp_path / "w.json")
        warnings = WarningManager(WARNING_DESCRIPTORS, WarningStore(path))
        display, fb = self._idle_display(warnings=warnings)
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        run_warning_action(display, "sdhealth", dd.ACTION_DISMISS)
        assert not Path(path).exists()
        display.stop()
        assert json.loads(Path(path).read_text(encoding="utf-8")).keys() == {"sdhealth"}


# ---------------------------------------------------------------------------
# The boot splash: show_starting() opens the one backend and paints
# "Starting..." first; the first poll replaces it.
# ---------------------------------------------------------------------------

class TestBootSplash:
    def test_show_starting_opens_the_backend_and_paints_the_splash_first(self):
        display, fb, gt = make_display(targets=[])
        with patch.object(display._compositor, "compose_starting",
                          wraps=display._compositor.compose_starting) as compose:
            display.show_starting()
        assert fb.opened is True
        compose.assert_called_once()
        assert len(fb.displayed) == 1                       # no logo frame before it
        assert display.get_status()["showing"] == "starting"
        assert display.get_status()["active"] is True
        frame = fb.displayed[0]
        # Flat chassis with ink in the middle — the centred-label look.
        assert frame.getpixel((0, 0)) == _LIST_BG_RGB
        assert any(frame.getpixel((x, frame.height // 2)) != _LIST_BG_RGB for x in range(frame.width))

    def test_start_after_show_starting_reuses_the_open_backend(self):
        display, fb, gt = make_display(targets=[])
        display.show_starting()
        frames = len(fb.displayed)
        with display._lock:
            display._enable_locked()          # what start() does first
        assert len(fb.displayed) == frames    # no reopen, no logo repaint
        assert display.get_status()["showing"] == "starting"

    def test_first_poll_replaces_the_splash_with_the_logo(self):
        display, fb, gt = make_display(targets=[])
        display.show_starting()
        display._poll_once()
        assert display.get_status()["showing"] == "logo"
        assert len(fb.displayed) == 2

    def test_first_poll_with_artwork_replaces_the_splash(self):
        # The same artwork-path fixture the existing "showing == artwork"
        # test elsewhere in this file uses.
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.show_starting()
        fake_image = Image.new("RGB", (128, 160))
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()
        assert display.get_status()["showing"] == "artwork"
        assert len(fb.displayed) >= 2      # the splash, then artwork (a transition frame may sit between)

    def test_repaint_before_the_first_poll_keeps_the_splash(self):
        display, fb, gt = make_display(targets=[])
        display.show_starting()
        _fold(display)
        assert len(fb.displayed) == 1
        assert display.get_status()["showing"] == "starting"

    def test_unfitted_show_starting_is_a_noop(self):
        display, fb, gt = make_display(fitted=False)
        display.show_starting()
        assert fb.opened is False and fb.displayed == []
        assert display.get_status()["showing"] == "noop"

    def test_backend_open_failure_degrades_without_raising(self):
        display, fb, gt = make_display(backend=FakeBackend(fail_open=True))
        display.show_starting()
        status = display.get_status()
        assert status["showing"] == "noop" and status["active"] is False
        assert status["last_error"] == "backend_open_failed"

    def test_display_write_failure_is_recorded_not_raised(self):
        display, fb, gt = make_display(backend=FakeBackend(fail_display=True))
        display.show_starting()
        assert display.get_status()["last_error"] == "display_write_failed"

    def test_enable_alone_still_paints_the_logo_first(self):
        # The render_logo default is what every non-splash open relies on.
        display, fb, gt = make_display(targets=[])
        display.enable()
        assert len(fb.displayed) == 1
        assert display.get_status()["showing"] == "logo"


def _make_outputs_eq_display(appliance_id="a" * 20):
    """A display whose reporting appliance offers both the outputs list and
    the EQ page, so the outputs list can be opened from the EQ page."""
    display, fb, gt = make_display(targets=[])
    display.core.set_field("reporting_id", appliance_id)
    display.core.set_roster([_roster_entry(appliance_id=appliance_id, dial_outputs=True, dial_eq=True)])
    display._core._update_availability(time.monotonic())
    return display


class TestOutputsReturnToOpeningPage:
    """Closing the outputs list returns to whichever main page opened it."""

    @pytest.mark.parametrize("origin", ["main", "repeat", "eq"])
    def test_close_goes_back_to_the_opening_page(self, origin):
        display = _make_outputs_display()
        display._screen = origin
        assert display._open_outputs_locked() is True
        with patch("dial_core._enqueue_eq_fetch"):
            display.close_list()
        assert display._screen_request == origin

    def test_other_screens_return_to_main(self):
        display = _make_outputs_display()
        display._outputs_return = "eq"
        display._screen = "selector"
        display._open_outputs_locked()
        assert display._outputs_return == "main"

    def test_detail_page_keeps_the_opening_page(self):
        display = _make_outputs_display()
        display._screen = "repeat"
        display._open_outputs_locked()
        display._screen = "output"
        display._open_outputs_locked()
        assert display._outputs_return == "repeat"

    def test_detail_back_still_goes_to_the_list(self):
        display = _make_outputs_display()
        display._screen = "eq"
        display._open_outputs_locked()
        display._screen = "output"
        display.close_list()
        assert display._screen_request == "outputs"

    def test_back_to_eq_reopens_it_and_drops_the_outputs_state(self):
        display = _make_outputs_eq_display()
        with display._lock:
            assert display._open_eq_locked() is True
            assert display._open_outputs_locked() is True
        with patch("dial_core._enqueue_eq_fetch") as fetch:
            display.close_list()
        fetch.assert_called_once()
        with display._lock:
            display._apply_screen_requests_locked()
        assert display._screen == "eq"
        assert display._eq is not None
        assert display._outputs is None
        assert display._output_detail is None

    def test_back_to_a_page_that_cannot_open_falls_back_to_main(self):
        display = _make_outputs_display()
        display._screen = "repeat"
        with display._lock:
            display._open_outputs_locked()
        display.core.set_roster([])  # the appliance has gone: the repeat opener refuses
        display.close_list()
        with display._lock:
            display._apply_screen_requests_locked()
        assert display._screen == "main"
        assert display._outputs is None

    def test_timeout_goes_back_to_the_opening_page(self):
        display = _make_outputs_eq_display()
        with display._lock:
            display._open_eq_locked()
            display._open_outputs_locked()
        display._outputs = dataclasses.replace(display._outputs, opened_at=time.monotonic() - 3600)
        with patch("dial_core._enqueue_eq_fetch"):
            display._check_secondary_timeout()
        assert display._screen_request == "eq"
        assert display._screen == "outputs"

    def test_timeout_opened_from_main_still_closes(self):
        display = _make_outputs_display()
        with display._lock:
            display._open_outputs_locked()
        display._outputs = dataclasses.replace(display._outputs, opened_at=time.monotonic() - 3600)
        display._check_secondary_timeout()
        assert display._screen == "main"
        assert display._outputs is None


class TestReplayTimer:
    """The replay position line shown on the main page after a picker start."""

    AID = "a" * 20

    def _display(self, state="hold", **repeat):
        import dial_repeat_store as drs
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.core.set_field("manual_id", self.AID)
        now = time.monotonic()
        drs.repeat_store.update(self.AID, drs.parse_repeat_object(_repeat_obj(state=state, **repeat), now))
        display._arm_replay_timer(self.AID)
        return display, fb

    def test_picker_pick_arms_the_timer(self):
        display, fb, gt = TestPickerPick()._opened_with_row(aid=self.AID)
        with patch("dial_core.enqueue_transport"):
            display.picker_pick(0)
        assert display._replay_timer_id == self.AID
        assert display._replay_timer_shown_at == 0.0

    def test_shows_the_held_position_at_full_opacity(self):
        display, fb = self._display(recording_seconds=12.0)
        now = time.monotonic()
        with display._lock:
            timer = display._replay_timer_locked(now)
        assert timer == ("0:00 / 0:12", 1.0, None)
        assert display._replay_timer_shown_at == now

    def test_fades_after_the_show_window_then_ends(self):
        display, fb = self._display()
        now = time.monotonic()
        display._replay_timer_shown_at = now - dd.REPLAY_TIMER_SHOW_S - dd.REPLAY_TIMER_FADE_S / 2
        with display._lock:
            text, alpha, _ = display._replay_timer_locked(now)
        assert alpha == pytest.approx(0.5)
        display._replay_timer_shown_at = now - dd.REPLAY_TIMER_SHOW_S - dd.REPLAY_TIMER_FADE_S
        with display._lock:
            assert display._replay_timer_locked(now) is None
        assert display._replay_timer_id is None

    def test_not_drawn_for_another_shown_appliance(self):
        display, fb = self._display()
        display.core.set_field("manual_id", "b" * 20)
        with display._lock:
            assert display._replay_timer_locked(time.monotonic()) is None
        assert display._replay_timer_id == self.AID

    def test_not_drawn_on_the_compact_tier(self):
        display, fb = self._display()
        display._compact_tier = lambda: True
        with display._lock:
            assert display._replay_timer_locked(time.monotonic()) is None

    def test_dropped_when_nothing_shows_within_the_arm_window(self):
        display, fb = self._display(state="recording")
        now = time.monotonic()
        display._replay_timer_armed_at = now - dd.REPLAY_TIMER_ARM_S
        with display._lock:
            assert display._replay_timer_locked(now) is None
        assert display._replay_timer_id is None

    def test_a_rejected_seek_drops_it(self):
        display, fb = self._display()
        on_repeat_result(display, "transport", self.AID, 412, {"ok": False, "error": "no_recording"})
        assert display._replay_timer_id is None

    def test_main_paint_draws_it(self):
        display, fb = self._display(recording_seconds=12.0)
        compose = MagicMock(wraps=display._compositor.compose)
        display._compositor.compose = compose
        with display._lock:
            display._display_locked(display._current_base_image)
        assert compose.call_args.kwargs["timer_text"] == "0:00 / 0:12"
        assert compose.call_args.kwargs["timer_alpha"] == 1.0

    def test_deadline_waits_for_the_first_position_then_the_fade(self):
        display, fb = self._display()
        now = time.monotonic()
        assert display._replay_timer_deadline(now) == pytest.approx(now + 0.25)
        display._replay_timer_shown_at = now
        assert display._replay_timer_deadline(now) == pytest.approx(now + dd.REPLAY_TIMER_SHOW_S + 0.005)

    def test_deadline_is_floored_after_its_own_signal(self):
        display, fb = self._display()
        now = time.monotonic()
        display._replay_timer_shown_at = now - dd.REPLAY_TIMER_SHOW_S - 0.1
        display._replay_timer_signal_at = now
        assert display._replay_timer_deadline(now) >= now + dd.REPLAY_TIMER_FADE_GAP_S

    def test_deadline_drops_a_timer_whose_replay_ended(self):
        import dial_repeat_store as drs
        display, fb = self._display()
        display._replay_timer_shown_at = time.monotonic()
        drs.repeat_store.clear(self.AID)
        display._replay_timer_deadline(time.monotonic())
        assert display._replay_timer_id is None

    def test_no_deadline_off_the_main_page(self):
        display, fb = self._display()
        display._screen = "repeat"
        assert display._replay_timer_deadline(time.monotonic()) is None


class TestIdentifiedWithoutArtwork:
    """A track identified without artwork keeps the logo on the panel; its
    title and artist are drawn over it from the core's now-playing line."""

    def test_the_logo_stays_up_and_no_artwork_is_shown(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        no_art = _track_id(title="Song", artist="The Artist", album="LP", artwork_url="")
        with patch("dial_core.fetch_target_status", return_value=_status_result(track_id=no_art)), \
                patch.object(display, "_show_artwork") as show_artwork:
            display._poll_once()
        show_artwork.assert_not_called()
        assert display.get_status()["showing"] == "logo"


# ---------------------------------------------------------------------------
# Generic warning capabilities: title_for, progress_for, interrupting,
# auto_clear_after_s and the button-less notice form, driven through rows
# registered for the test only.
# ---------------------------------------------------------------------------

def _notice_descriptor(**overrides):
    from dial_touch_layout import GEOMETRY_NONE
    from dial_warnings import WarningDescriptor
    fields = dict(
        id="notice", priority=200, screen="notice", geometry=GEOMETRY_NONE,
        title="Working", message_for=lambda sev: f"step {sev}", buttons=(),
        persisted=False, snooze_for=None,
        title_for=lambda sev: f"Title {sev}", progress_for=lambda sev: sev * 10,
        interrupting=True, auto_clear_after_s=None,
    )
    fields.update(overrides)
    return WarningDescriptor(**fields)


class TestGenericWarningCapabilities:
    @pytest.fixture
    def rig(self):
        clock = _Clock(1_000_000.0)
        started = []

        def build(**overrides):
            notice = _notice_descriptor(**overrides)
            display, fb, gt = make_display(
                targets=[],
                warnings=WarningManager(WARNING_DESCRIPTORS + (notice,), WarningStore(None), clock=clock.now),
            )
            for p in (
                patch.dict(dd._WARNING_BY_ID, {notice.id: notice}),
                patch.dict(dd.SCREEN_POLICIES, {notice.screen: dd._warning_policy_row(notice)}),
            ):
                p.start()
                started.append(p)
            display.enable()
            display._poll_once()
            _fold(display)
            return display, fb, clock

        yield build
        for p in started:
            p.stop()

    def _painted_view(self, display):
        with patch.object(
            display._compositor, "compose_warning", wraps=display._compositor.compose_warning,
        ) as mock_compose:
            with display._lock:
                display._display_warning_locked()
        return mock_compose.call_args.args[3]

    def test_the_nowifi_and_sdhealth_rows_keep_the_default_descriptor_fields(self):
        for desc in (d for d in WARNING_DESCRIPTORS if d.id in ("nowifi", "sdhealth")):
            assert desc.title_for is None and desc.progress_for is None
            assert desc.interrupting is False and desc.auto_clear_after_s is None

    def test_painter_uses_title_for_and_progress_for(self, rig):
        display, fb, clock = rig()
        warning_active(display, "notice", severity=4)
        _fold(display)
        view = self._painted_view(display)
        assert view.title == "Title 4"
        assert view.message == "step 4"
        assert view.percent == 40
        assert view.buttons == ()

    def test_painter_falls_back_to_the_fixed_title_and_no_percent(self, rig):
        display, fb, clock = rig(title_for=None, progress_for=None)
        warning_active(display, "notice", severity=4)
        _fold(display)
        view = self._painted_view(display)
        assert view.title == "Working"
        assert view.percent is None

    def test_existing_warning_view_carries_no_percent(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._poll_once()
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        view = self._painted_view(display)
        assert view.percent is None and view.title == "microSD Health"

    def test_tick_warnings_clears_expired_rows(self, rig):
        display, fb, clock = rig(auto_clear_after_s=60.0)
        warning_active(display, "notice", severity=1)
        _fold(display)
        assert display._screen == "notice"
        clock.t += 59.0
        tick_warnings(display)
        assert display._screen_request is None and display._screen == "notice"
        clock.t += 2.0
        tick_warnings(display)
        assert not display.core.warnings.is_active("notice")
        assert display._screen_request == "main"
        _fold(display)
        assert display._screen == "main" and display._warning_screen is None

    def test_tick_warnings_clear_drops_a_pending_request(self, rig):
        display, fb, clock = rig(auto_clear_after_s=10.0)
        warning_active(display, "notice", severity=1)
        assert display._screen_request == "notice"
        clock.t += 11.0
        tick_warnings(display)
        assert display._screen_request is None

    def test_interrupting_opens_over_a_secondary_screen(self, rig):
        display, fb, clock = rig()
        display._screen_request = "selector"
        _fold(display)
        assert display._screen == "selector"
        warning_active(display, "notice", severity=2)
        assert display._screen_request == "notice"
        _fold(display)
        assert display._screen == "notice"
        assert display._selector is None

    def test_non_interrupting_does_not_open_over_a_secondary_screen(self, rig):
        display, fb, clock = rig(interrupting=False)
        display._screen_request = "selector"
        _fold(display)
        warning_active(display, "notice", severity=2)
        assert display._screen_request is None
        _fold(display)
        assert display._screen == "selector"

    def test_interrupting_wakes_a_sleeping_panel(self, rig):
        display, fb, clock = rig()
        with display._lock:
            display._sleep_locked()
        assert display._display_sleeping
        warning_active(display, "notice", severity=2)
        assert display._screen_request == "notice"
        _fold(display)
        assert not display._display_sleeping
        assert display._screen == "notice"

    def test_non_interrupting_does_not_wake_a_sleeping_panel(self, rig):
        display, fb, clock = rig(interrupting=False)
        with display._lock:
            display._sleep_locked()
        warning_active(display, "notice", severity=2)
        assert display._screen_request is None
        assert display._display_sleeping

    def test_interrupting_refresh_and_tick_do_not_rewake_after_sleep(self, rig):
        display, fb, clock = rig()
        warning_active(display, "notice", severity=2)
        _fold(display)
        with display._lock:
            display._sleep_locked()
        warning_active(display, "notice", severity=3)
        tick_warnings(display)
        assert display._screen_request is None and display._display_sleeping
        display.notify_touch_activity()
        _fold(display)
        assert not display._display_sleeping and display._screen == "notice"

    def test_interrupting_never_opens_over_restarting(self, rig):
        display, fb, clock = rig()
        display._screen_request = "restarting"
        _fold(display)
        assert display._screen == "restarting"
        warning_active(display, "notice", severity=2)
        assert display._screen_request is None
        _fold(display)
        assert display._screen == "restarting"

    def test_interrupting_does_not_request_again_while_showing(self, rig):
        display, fb, clock = rig()
        warning_active(display, "notice", severity=2)
        _fold(display)
        warning_active(display, "notice", severity=3)
        tick_warnings(display)
        assert display._screen_request is None

    def test_higher_priority_page_is_not_replaced_by_a_lower_interrupting_one(self, rig):
        display, fb, clock = rig(priority=10)
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        assert display._screen == "sdhealth"
        warning_active(display, "notice", severity=2)
        _fold(display)
        assert display._screen == "sdhealth"

    def test_higher_priority_interrupting_page_replaces_an_open_lower_one(self, rig):
        display, fb, clock = rig()
        for _ in range(3):
            on_network_view(display, _view(LINK_CONNECTED, bars=3))
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        assert display._screen == "sdhealth"
        warning_active(display, "notice", severity=2)
        _fold(display)
        assert display._screen == "notice"


# ---------------------------------------------------------------------------
# The software update cards: the update-result file mapped onto the "update"
# and "update_result" warning rows.
# ---------------------------------------------------------------------------

class TestUpdateWarnings:
    @pytest.fixture
    def rig(self, tmp_path):
        from dial_update_watch import UpdateWatcher
        clock = _Clock(1_000_000.0)
        display, fb, gt = make_display(
            targets=[],
            warnings=WarningManager(WARNING_DESCRIPTORS, WarningStore(None), clock=clock.now),
        )
        display.core.update_seen_path = str(tmp_path / "seen")
        display.core.update_watcher = UpdateWatcher(str(tmp_path / "update-result.env"))
        display.enable()
        display._poll_once()
        _fold(display)
        display.result_path = tmp_path / "update-result.env"
        display.seen_path = tmp_path / "seen"
        display.clock = clock
        return display

    @staticmethod
    def _progress(phase="packages", percent=45, **kw):
        from dial_update_watch import UpdateView
        return UpdateView(status="in_progress", percent=percent, phase=phase, tag="0.7.0",
                          previous_tag="0.6.0", message="a long message that must not be shown",
                          last_run_at="2000-01-01T00:00:00+00:00", **kw)

    @staticmethod
    def _finished(status="success", **kw):
        from dial_update_watch import UpdateView
        fields = dict(status=status, percent=100, phase="done", tag="0.7.0", previous_tag="0.6.0",
                      last_run_at="2000-01-01T01:00:00+00:00")
        fields.update(kw)
        return UpdateView(**fields)

    @staticmethod
    def _painted_view(display):
        with patch.object(
            display._compositor, "compose_warning", wraps=display._compositor.compose_warning,
        ) as mock_compose:
            with display._lock:
                display._display_warning_locked()
        return mock_compose.call_args.args[3]

    def test_in_progress_view_opens_update_card_over_selector_and_wakes(self, rig):
        display = rig
        display._screen_request = "selector"
        _fold(display)
        assert display._screen == "selector"
        with display._lock:
            display._sleep_locked()
        apply_update_view(display, self._progress())
        _fold(display)
        assert display._screen == "update"
        assert not display._display_sleeping
        assert display._selector is None

    def test_update_card_shows_title_phase_label_and_bar(self, rig):
        display = rig
        apply_update_view(display, self._progress(phase="packages", percent=45))
        _fold(display)
        view = self._painted_view(display)
        assert view.title == dd.UPDATING_TEXT == "Updating..."
        assert view.message == "Upgrading OS"
        assert view.percent == 45
        assert view.buttons == ()

    def test_phase_label_follows_the_phase_and_never_the_file_message(self, rig):
        display = rig
        for phase, label in (
            ("download", "Downloading"), ("packages", "Upgrading OS"), ("python", "Installing"),
            ("files", "Installing"), ("configure", "Installing"), ("staged", "Restarting"),
            ("something-new", "Please wait"), ("", "Please wait"),
        ):
            apply_update_view(display, self._progress(phase=phase))
            _fold(display)
            assert self._painted_view(display).message == label, phase

    def test_update_card_outranks_nowifi(self, rig):
        display = rig
        on_network_view(display, _view(LINK_CONNECTED, bars=3))
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        _fold(display)
        assert display._screen == "nowifi"
        apply_update_view(display, self._progress())
        _fold(display)
        assert display._screen == "update"
        # A later network poll cannot take the screen back while it runs.
        on_network_view(display, _view(LINK_DOWN))
        _fold(display)
        assert display._screen == "update"

    def test_update_card_has_no_buttons_and_geometry_none(self):
        from dial_touch import _GEOMETRY_FOR_SURFACE
        from dial_touch_layout import GEOMETRY_NONE
        desc = dd._WARNING_BY_ID["update"]
        assert desc.buttons == ()
        assert desc.geometry == GEOMETRY_NONE
        assert desc.interrupting is True and desc.auto_clear_after_s is None
        assert desc.priority > dd._WARNING_BY_ID["nowifi"].priority
        assert _GEOMETRY_FOR_SURFACE[dd.SCREEN_POLICIES["update"].surface[0]] == GEOMETRY_NONE

    def test_reboot_phase_switches_to_restarting_without_requesting_reboot(self, rig):
        display = rig
        apply_update_view(display, self._progress(phase="packages"))
        _fold(display)
        assert display._screen == "update"
        with patch("dial_display._request_reboot") as reboot:
            apply_update_view(display, self._progress(phase="reboot", percent=96))
            _fold(display)
        reboot.assert_not_called()
        assert display._screen == "restarting"
        assert not display.core.warnings.is_active("update")
        # Nothing opens over the restarting screen.
        apply_update_view(display, self._progress(phase="files"))
        _fold(display)
        assert display._screen == "restarting"

    def test_verify_phase_shows_nothing(self, rig):
        display = rig
        apply_update_view(display, self._progress(phase="verify", percent=96))
        assert display._screen_request is None
        _fold(display)
        assert display._screen == "main"
        assert not display.core.warnings.is_active("update")

    def test_success_shows_result_once_then_clears_after_an_hour(self, rig):
        display = rig
        apply_update_view(display, self._progress())
        _fold(display)
        apply_update_view(display, self._finished())
        _fold(display)
        assert display._screen == "update_result"
        assert not display.core.warnings.is_active("update")
        view = self._painted_view(display)
        assert (view.title, view.message, view.buttons) == ("Updated", "Version 0.7.0", ("Dismiss",))
        assert view.percent is None
        display.clock.t += dd.UPDATE_RESULT_SECONDS - 1
        tick_warnings(display)
        assert display.core.warnings.is_active("update_result")
        display.clock.t += 2
        tick_warnings(display)
        assert not display.core.warnings.is_active("update_result")
        _fold(display)
        assert display._screen == "main"
        # The same result arriving again (a restart re-reading the file) stays quiet.
        apply_update_view(display, self._finished())
        _fold(display)
        assert display._screen == "main"

    def test_result_card_dismiss_clears_it(self, rig):
        display = rig
        apply_update_view(display, self._finished())
        _fold(display)
        assert display._screen == "update_result"
        display.warning_button_tap(TouchZone.SDHEALTH_DISMISS)
        _fold(display)
        assert display._screen == "main"
        tick_warnings(display)
        _fold(display)
        assert display._screen == "main"

    def test_failure_rolled_back_message_names_previous_version(self, rig):
        display = rig
        apply_update_view(display, self._finished("failure", rolled_back=True, phase="rolled_back"))
        _fold(display)
        view = self._painted_view(display)
        assert (view.title, view.message) == ("Update failed", "Restored 0.6.0")

    def test_failure_not_rolled_back_message_says_previous_kept(self, rig):
        display = rig
        apply_update_view(display, self._finished("failure", phase="failed"))
        _fold(display)
        view = self._painted_view(display)
        assert (view.title, view.message) == ("Update failed", "0.6.0 kept")

    def test_seen_marker_suppresses_repeat_on_restart(self, rig):
        display = rig
        apply_update_view(display, self._finished())
        assert display.seen_path.read_text().strip() == "2000-01-01T01:00:00+00:00"
        # A new process: same result file, same marker.
        again, fb, gt = make_display(targets=[])
        again.core.update_seen_path = str(display.seen_path)
        again.enable()
        again._poll_once()
        _fold(again)
        apply_update_view(again, self._finished())
        _fold(again)
        assert again._screen == "main" and not again.core.warnings.is_active("update_result")
        # A different (later) result is shown.
        apply_update_view(again, self._finished("failure", last_run_at="2000-01-02T00:00:00+00:00"))
        _fold(again)
        assert again._screen == "update_result"

    def test_fresh_install_with_no_status_shows_nothing(self, rig):
        from dial_update_watch import UpdateView
        display = rig
        apply_update_view(display, UpdateView())
        _fold(display)
        assert display._screen == "main"
        assert not display.seen_path.exists()

    def test_tick_reads_the_file_once_per_change(self, rig):
        display = rig
        display.result_path.write_text(
            "STATUS=in_progress\nPERCENT_COMPLETE=30\nMESSAGE=x\nLAST_RUN_AT=t1\nPHASE=files\n",
        )
        tick_update_watch(display)
        _fold(display)
        assert display._screen == "update"
        assert display.core.warnings.severity("update").percent == 30
        display._screen_request = "main"
        _fold(display)
        tick_update_watch(display)
        assert display._screen_request is None

    def test_result_card_replaces_open_progress_card(self, rig):
        display = rig
        apply_update_view(display, self._progress())
        _fold(display)
        assert display._screen == "update"
        apply_update_view(display, self._finished())
        _fold(display)
        assert display._screen == "update_result"


class TestAsleepIdleTouchDoesNotPressAnything:
    """Real display plus real touch state machine: the touch that wakes a
    sleeping idle screen must not open the replay picker; the next one does."""

    def _tap(self, display, sm, xy, now):
        import dial_touch as dt
        from dial_touch_filter import TouchEvent, TouchEventType

        sm.set_surface(*display.touch_surface(), now)
        actions = sm.on_filter_event(TouchEvent(TouchEventType.PRESS, xy[0], xy[1], None), now)
        for a in actions:
            if a.kind == dt.ACTION_WAKE:
                display.notify_touch_activity()
            elif a.kind == dt.ACTION_ZONE_TAP and a.zone == TouchZone.IDLE_REPLAY:
                display.open_picker()
        sm.on_filter_event(TouchEvent(TouchEventType.RELEASE, xy[0], xy[1], None), now + 0.05)
        return actions

    def test_waking_touch_does_not_open_the_picker_next_touch_does(self):
        import dial_touch as dt

        display, fb, gt = make_display(targets=[])
        display.enable()
        display.core.set_field("idle_affordance", True)
        with display._lock:
            display._sleep_locked()
        assert display.is_sleeping() is True
        width, height = display._active_panel_dims()
        sm = dt.TouchStateMachine(width, height, is_asleep=display.is_sleeping)
        centre = (width // 2, height // 2)

        actions = self._tap(display, sm, centre, 1.0)
        assert [a.kind for a in actions] == [dt.ACTION_WAKE]
        with display._lock:
            display._apply_touch_activity_locked()
        assert display.is_sleeping() is False
        assert display._screen_request is None

        self._tap(display, sm, centre, 2.0)
        assert display._screen_request is not None


# ---------------------------------------------------------------------------
# Outputs, EQ and transport state held by the core
# ---------------------------------------------------------------------------

class TestOutputsHeldByTheCore:
    AID = "a" * 20

    def _body(self, *rows):
        return {"ok": True, "outputs": [
            {"id": i, "name": n, "selected": s, "volume": v, "remote_in_use": u,
             **({"remote_owner": "Hall"} if u else {})}
            for (i, n, s, v, u) in rows
        ]}

    def test_the_core_keeps_the_row_in_use_elsewhere_and_the_screen_does_not(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        display._sync_core_interest()
        on_outputs_result(display, "fetch", self.AID, 200, self._body(
            ("1", "Bedroom", True, 40, False), ("2", "Study", True, 10, True),
        ), {})
        core_rows = display._core.snapshot().outputs.rows
        assert [(r.id, r.remote_in_use, r.remote_owner) for r in core_rows] == [
            ("1", False, None), ("2", True, "Hall"),
        ]
        assert display._rows_of(display._outputs) == (OutputRow("1", "Bedroom", True, 40),)

    def test_a_result_with_a_row_in_use_paints_the_same_list_as_one_without(self):
        frames = []
        for rows in (
            (("1", "Bedroom", True, 40, False), ("2", "Study", True, 10, True)),
            (("1", "Bedroom", True, 40, False),),
        ):
            display = _make_outputs_display()
            display._open_outputs_locked()
            display._sync_core_interest()
            on_outputs_result(display, "fetch", self.AID, 200, self._body(*rows), {})
            with display._lock:
                frames.append(display._build_outputs_list_state_locked(160, 128))
        assert frames[0] == frames[1]

    def test_the_filtered_rows_equal_what_the_screen_always_parsed(self):
        body = self._body(("1", "Bedroom", True, 40, False), ("2", "Study", True, 10, True))
        assert dd._offerable(dial_core_poll.parse_outputs_body(200, body)) == (OutputRow("1", "Bedroom", True, 40),)

    def test_a_detail_row_taken_elsewhere_counts_as_vanished(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        display._sync_core_interest()
        on_outputs_result(display, "fetch", self.AID, 200, self._body(("1", "Bedroom", True, 40, False)), {})
        display._output_detail = dd.OutputDetailState(
            appliance_id=self.AID, output_id="1", opened_at=time.monotonic(),
        )
        display._screen = "output"
        on_outputs_result(display, "fetch", self.AID, 200, self._body(("1", "Bedroom", True, 40, True)), {})
        assert display._screen_request == "outputs"

    def test_the_screen_rows_follow_the_core_through_a_fold(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        display._sync_core_interest()
        on_outputs_result(display, "fetch", self.AID, 200, self._body(("1", "Bedroom", True, 40, False)), {})
        assert display._core.snapshot().outputs.rows[0].volume == 40
        on_outputs_result(display, "fetch", self.AID, 200, self._body(("1", "Bedroom", True, 41, False)), {})
        assert display._rows_of(display._outputs)[0].volume == 41
        assert display._core.snapshot().outputs.rows[0].volume == 41

    def test_a_tap_on_a_row_the_appliance_has_since_refused_sends_nothing(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        display._sync_core_interest()
        on_outputs_result(display, "fetch", self.AID, 200, self._body(("1", "Bedroom", True, 40, False)), {})
        display._output_detail = dd.OutputDetailState(
            appliance_id=self.AID, output_id="1", opened_at=time.monotonic(),
        )
        display._screen = "output"
        display.core.set_roster([_roster_entry(appliance_id=self.AID, auth="unauthorized", dial_outputs=True)])
        with patch("dial_core.enqueue_set") as send:
            display.output_toggle_tap()
            display.output_volume_tap(+1)
        send.assert_not_called()
        assert display.core.outputs_override() is None

    def test_the_override_lives_in_the_core(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        seed_outputs(display, (OutputRow(id="1", name="Bedroom", selected=False, volume=0),))
        assert display.core.outputs_override() is None
        tap_output(display, "1", True, 40)
        assert display._core.outputs_override()[:3] == ("1", True, 40)
        on_outputs_result(display, "set", "a" * 20, 200, {"ok": False, "error": "output_in_use"})
        assert display.core.outputs_override() is None


class TestOutputsInterest:
    AID = "a" * 20

    def _watch(self, display):
        return dict(display._core._state.outputs_watch)

    def test_opening_registers_interest_and_asks_once(self):
        display = _make_outputs_display()
        with patch("dial_core.enqueue_fetch") as fetch:
            display.open_outputs()
            with display._lock:
                display._apply_screen_requests_locked()
            display._sync_core_interest()
        assert fetch.call_count == 1
        assert self._watch(display) == {"spi": self.AID}
        assert display._core.snapshot().outputs.appliance_id == self.AID

    def test_interest_is_dropped_when_the_screen_closes(self):
        display = _make_outputs_display()
        with patch("dial_core.enqueue_fetch"):
            display.open_outputs()
            with display._lock:
                display._apply_screen_requests_locked()
            display._sync_core_interest()
            with display._lock:
                display._close_secondary_locked()
            display._sync_core_interest()
        assert self._watch(display) == {}
        assert display._core.snapshot().outputs is None

    def test_interest_survives_until_the_requested_screen_has_opened(self):
        display = _make_outputs_display()
        with patch("dial_core.enqueue_fetch"):
            display.open_outputs()
            display._sync_core_interest()
        assert self._watch(display) == {"spi": self.AID}

    def test_a_request_that_never_opens_gives_its_interest_back(self):
        display = _make_outputs_display()
        with patch("dial_core.enqueue_fetch"):
            display.open_outputs()
            display._screen_request = None
            display._sync_core_interest()
        assert self._watch(display) == {}

    def test_the_periodic_refresh_comes_from_the_core_and_only_while_showing(self):
        display = _make_outputs_display()
        with patch("dial_core.enqueue_fetch") as fetch:
            display._open_outputs_locked()
            display._screen = "main"
            display._tick_outputs_refresh()
            assert fetch.call_count == 0
            display._screen = "outputs"
            display._tick_outputs_refresh()
            assert fetch.call_count == 1
        assert self._watch(display) == {"spi": self.AID}

    def test_the_periodic_refresh_runs_for_the_detail_page_and_not_for_main(self):
        with patch("dial_core.enqueue_fetch") as fetch:
            display = _make_outputs_display()
            assert display._open_outputs_locked() is True
            display._screen = "output"
            display._tick_outputs_refresh()
            assert fetch.call_count == 1
            display = _make_outputs_display()
            assert display._open_outputs_locked() is True
            display._screen = "main"
            display._tick_outputs_refresh()
            assert fetch.call_count == 1

    def test_a_second_watcher_keeps_the_core_state_after_the_screen_closes(self):
        display = _make_outputs_display()
        with patch("dial_core.enqueue_fetch"):
            display.open_outputs()
            with display._lock:
                display._apply_screen_requests_locked()
            display._sync_core_interest()
            display._core.watch_outputs(self.AID, "hd", True)
            with display._lock:
                display._close_secondary_locked()
            display._sync_core_interest()
        assert self._watch(display) == {"hd": self.AID}
        assert display._core.snapshot().outputs is not None


class TestEqHeldByTheCore:
    AID = "a" * 20

    def _opened(self):
        display = _make_eq_display()
        display._open_eq_locked()
        display._sync_core_interest()
        return display

    @staticmethod
    def _reading(display):
        held = dd._held_eq(display.core.snapshot(), display._eq)
        return dd.eq_gain(held.bands, "bass"), dd.eq_gain(held.bands, "treble"), dd._eq_loaded(held)

    def test_the_fold_stores_bass_and_treble_as_two_bands(self):
        display = self._opened()
        on_eq_result(display, "fetch", self.AID, 200, {"ok": True, "bass_db": 2, "treble_db": -1}, {})
        bands = display._core.snapshot().eq.bands
        assert [(b.id, b.frequency_hz, b.gain_db, b.min_db, b.max_db) for b in bands] == [
            ("bass", None, 2, -6, 6), ("treble", None, -1, -6, 6),
        ]
        assert self._reading(display) == (2, -1, True)

    def test_a_reading_without_the_two_bands_leaves_the_page_loading(self):
        display = self._opened()
        other = (EqBand("peq1", 100, 3, -12, 12), EqBand("peq2", 250, 0, -12, 12))
        with patch("dial_core_poll.parse_eq_body", return_value=other):
            on_eq_result(display, "fetch", self.AID, 200, {"ok": True}, {})
        assert self._reading(display) == (None, None, False)
        with display._lock:
            view = display._build_eq_view_locked(display._eq, time.monotonic())
        assert view.loaded is False and view.bass_db is None and view.treble_db is None

    def test_the_override_maps_between_the_screen_pair_and_the_core_bands(self):
        display = self._opened()
        set_eq_optimistic(display, (5, None, 1002.0))
        assert display._core.eq_override() == ((("bass", 5),), 1002.0)
        assert eq_optimistic(display) == (5, None, 1002.0)
        set_eq_optimistic(display, (None, -2, 1003.0))
        assert display._core.eq_override() == ((("treble", -2),), 1003.0)
        set_eq_optimistic(display, None)
        assert display._core.eq_override() == ((), 0.0)
        assert eq_optimistic(display) is None

    def test_a_step_is_made_by_the_core_from_the_screen_readings(self):
        display = self._opened()
        seed_eq(display, bass_db=1, treble_db=-3, loaded=True)
        with patch("dial_core._enqueue_eq_set") as send:
            display.eq_step("treble", -9)
        assert send.call_args[0][1] == {"treble": -6}
        assert eq_optimistic(display)[:2] == (1, -6)

    def test_cycling_to_the_page_registers_interest_and_asks_once(self):
        display = _make_eq_display()
        with patch("dial_core._enqueue_eq_fetch") as fetch:
            display.cycle_pages()
            with display._lock:
                display._apply_screen_requests_locked()
            display._sync_core_interest()
        assert fetch.call_count == 1
        assert display._core._state.eq_watch == {"spi": self.AID}
        assert display._core.snapshot().eq.appliance_id == self.AID

    def test_closing_the_page_drops_the_interest(self):
        display = _make_eq_display()
        with patch("dial_core._enqueue_eq_fetch"):
            display.cycle_pages()
            with display._lock:
                display._apply_screen_requests_locked()
            display._sync_core_interest()
            with display._lock:
                display._close_secondary_locked()
            display._sync_core_interest()
        assert display._core._state.eq_watch == {}
        assert display._core.snapshot().eq is None


class TestTransportRecordedByTheTaps:
    def _opened(self, state="idle", armed=False):
        return TestRepeatScreenTouchEntries()._opened(state=state, armed=armed)

    def test_arm_is_recorded_pending(self):
        display, aid = self._opened(state="idle")
        with patch("dial_core.enqueue_arm"):
            display.repeat_toggle_tap()
        request = display._core.snapshot().transport
        assert (request.appliance_id, request.kind, request.state) == (aid, "arm", "pending")

    def test_start_is_recorded_as_a_seek(self):
        display, aid = self._opened(state="hold")
        with patch("dial_core.enqueue_transport"):
            display.repeat_start_tap()
        assert display._core.snapshot().transport.kind == "seek"

    def test_stop_is_recorded_and_its_own_ack_settles_it(self):
        display, aid = self._opened(state="replaying")
        with patch("dial_core.enqueue_transport"):
            display.repeat_stop_tap()
        assert display._core.snapshot().transport.kind == "stop"
        on_repeat_result(display, "transport", aid, 200, {"ok": True, "state": "hold"})
        assert display._core.snapshot().transport.state == "accepted"

    def test_a_rejected_seek_is_recorded_with_its_error(self):
        display, aid = self._opened(state="hold")
        with patch("dial_core.enqueue_transport"):
            display.repeat_start_tap()
        on_repeat_result(display, "transport", aid, 412, {"ok": False, "error": "fading_out"})
        request = display._core.snapshot().transport
        assert (request.state, request.error) == ("rejected", "fading_out")


class TestTapsCallTheCoreActions:
    """Each SPI tap resolves what is on screen to ids and hands the request
    to the core action; the action's own behaviour is tested on the core."""

    def _core_action(self, display, name, result=None):
        from dial_core_state import ActionResult
        return patch.object(display._core, name, return_value=result or ActionResult(True))

    def test_selector_pick_sets_the_focus_to_the_row_id(self):
        display = TestSelectorUnauthorizedRows()._display(authorized_count=2)
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        row = display._current_page_rows(display._selector)[1]
        with self._core_action(display, "set_focus") as action:
            display.selector_pick(1)
        action.assert_called_once_with(row.appliance_id)

    def test_selector_pick_shows_the_hint_when_the_core_says_unauthorized(self):
        from dial_core_state import ActionResult
        display = TestSelectorUnauthorizedRows()._display(authorized_count=2)
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        with self._core_action(display, "set_focus", ActionResult(False, "unauthorized")):
            display.selector_pick(0)
        assert display._screen_request == "info_value"

    def test_picker_pick_starts_the_row_replay_and_arms_the_timer(self):
        display, fb, gt = TestPickerPick()._opened_with_row(aid="a" * 20)
        with self._core_action(display, "start_replay") as action:
            display.picker_pick(0)
        action.assert_called_once_with("a" * 20)
        assert display._replay_timer_id == "a" * 20

    def test_picker_pick_drops_the_timer_when_the_core_refuses(self):
        from dial_core_state import ActionResult
        display, fb, gt = TestPickerPick()._opened_with_row(aid="a" * 20)
        with self._core_action(display, "start_replay", ActionResult(False, "wrong_state")):
            display.picker_pick(0)
        assert display._replay_timer_id is None

    def test_picker_pick_with_a_stale_index_calls_nothing(self):
        display, fb, gt = TestPickerPick()._opened_with_row()
        with self._core_action(display, "start_replay") as action:
            display.picker_pick(5)
        action.assert_not_called()

    def test_repeat_toggle_tap_arms_and_disarms_by_the_record(self):
        display, aid = TestRepeatScreenTouchEntries()._opened(state="idle", armed=False)
        with self._core_action(display, "set_repeat_armed") as action:
            display.repeat_toggle_tap()
        action.assert_called_once_with(aid, True)
        display, aid = TestRepeatScreenTouchEntries()._opened(state="recording", armed=True)
        with self._core_action(display, "set_repeat_armed") as action:
            display.repeat_toggle_tap()
        action.assert_called_once_with(aid, False)

    def test_repeat_toggle_tap_while_replaying_is_an_artwork_tap(self):
        display, aid = TestRepeatScreenTouchEntries()._opened(state="replaying")
        with self._core_action(display, "set_repeat_armed") as action:
            display.repeat_toggle_tap()
        action.assert_not_called()

    def test_repeat_start_tap_restarts_the_open_appliance(self):
        display, aid = TestRepeatScreenTouchEntries()._opened(state="hold")
        with self._core_action(display, "restart_replay") as action:
            display.repeat_start_tap()
        action.assert_called_once_with(aid)

    def test_repeat_stop_tap_stops_the_open_appliance(self):
        display, aid = TestRepeatScreenTouchEntries()._opened(state="replaying")
        with self._core_action(display, "stop_replay") as action:
            display.repeat_stop_tap()
        action.assert_called_once_with(aid)

    def test_output_taps_address_the_open_appliance_and_output(self):
        display = TestOutputsTouchEntries()._opened_detail(selected=True, volume=40)
        aid = display._outputs.appliance_id
        with self._core_action(display, "set_output") as action:
            display.output_toggle_tap()
        action.assert_called_once_with(aid, "1", selected=False)
        with self._core_action(display, "step_output_volume") as action:
            display.output_volume_tap(-2)
        action.assert_called_once_with(aid, "1", -2)

    def test_eq_step_addresses_the_open_appliance_and_band(self):
        display = TestEqStep()._opened()
        aid = display._eq.appliance_id
        with self._core_action(display, "step_eq") as action:
            display.eq_step("treble", -1)
        action.assert_called_once_with(aid, "treble", -1)

    def test_warning_buttons_call_dismiss_and_reboot(self):
        display = TestNoWifiStateMachine()._idle_display()[0]
        with self._core_action(display, "dismiss_warning") as action:
            display.warning_button_tap(TouchZone.NOWIFI_DISMISS)
        action.assert_called_once_with("nowifi")
        with patch.object(display._core, "request_dial_reboot", return_value=True) as action:
            display.warning_button_tap(TouchZone.NOWIFI_RESTART)
        action.assert_called_once_with()


_APP_AID = "a" * 20


def _app_warning(wid="stylus", severity="warning", title="Technics stylus",
                 message="Needs changing soon.", dismissal="week"):
    from dial_core_state import ApplianceWarning
    return ApplianceWarning(wid, severity, title, message, dismissal)


def _app_key(wid="stylus"):
    from dial_warning_text import appliance_warning_key
    return appliance_warning_key(_APP_AID, wid)


class TestApplianceWarningPaging:
    @pytest.fixture
    def rig(self, tmp_path):
        clock = _Clock(1_000_000.0)
        display, fb, gt = make_display(
            targets=[], roster=[_roster_entry(auth="authorized", appliance_id=_APP_AID)],
            warnings=WarningManager(
                WARNING_DESCRIPTORS, WarningStore(str(tmp_path / "warnings.json")), clock=clock.now,
            ),
        )
        display.enable()
        display._poll_once()
        _fold(display)
        display.clock = clock
        display.fb = fb
        display.snooze_file = tmp_path / "warnings.json"
        return display

    @staticmethod
    def _set(display, *warnings):
        assert display.core.set_appliance_warnings(_APP_AID, tuple(warnings)).accepted

    @staticmethod
    def _page(display):
        tick_warnings(display)
        _fold(display)

    @staticmethod
    def _painted_view(display):
        with patch.object(
            display._compositor, "compose_warning", wraps=display._compositor.compose_warning,
        ) as mock_compose:
            with display._lock:
                display._display_warning_locked()
        return mock_compose.call_args.args[3]

    @staticmethod
    def _dismiss(display):
        display.warning_button_tap(TouchZone.SDHEALTH_DISMISS)
        _fold(display)

    def test_a_due_appliance_warning_opens_on_main_through_the_shared_row(self, rig):
        display = rig
        self._set(display, _app_warning())
        assert display._screen_request is None            # the 1 s tick raises it, nothing else
        tick_warnings(display)
        assert display._screen_request == "appliance_warning"
        _fold(display)
        assert display._screen == "appliance_warning"
        assert display._warning_screen.warning_id == _app_key()
        assert display.touch_surface() == ("appliance_warning", False, False, False)

    def test_the_page_shows_the_appliance_text_with_its_source_and_one_dismiss(self, rig):
        display = rig
        self._set(display, _app_warning(title="Technics stylus", message="Needs changing soon."))
        self._page(display)
        view = self._painted_view(display)
        assert (view.title, view.message, view.source) == ("Technics stylus", "Needs changing soon.", "Kitchen")
        assert view.buttons == ("Dismiss",) and view.geometry == "sdhealth"

    def test_a_dial_warning_view_has_no_source(self, rig):
        display = rig
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        assert self._painted_view(display).source == ""

    def test_it_never_opens_over_a_list(self, rig):
        display = rig
        display._screen_request = "selector"
        _fold(display)
        self._set(display, _app_warning())
        tick_warnings(display)
        assert display._screen_request is None
        _fold(display)
        assert display._screen == "selector"
        display._screen_request = "main"
        _fold(display)
        tick_warnings(display)
        assert display._screen_request == "appliance_warning"

    def test_it_never_wakes_a_sleeping_panel(self, rig):
        display = rig
        with display._lock:
            display._sleep_locked()
        self._set(display, _app_warning(severity="critical"))
        display._request_due_warning(wake=True)
        tick_warnings(display)
        assert display._screen_request is None and display._display_sleeping
        _fold(display)
        assert display._display_sleeping and display._screen == "main"

    def test_a_dial_warning_pages_before_an_appliance_one_and_after_it_the_appliance_one(self, rig):
        display = rig
        self._set(display, _app_warning(severity="critical"))
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        assert display._screen == "sdhealth"
        self._dismiss(display)
        assert display._screen == "main"
        tick_warnings(display)
        _fold(display)
        assert display._screen == "appliance_warning"

    def test_an_appliance_page_is_not_replaced_by_a_dial_warning_that_arrives_later(self, rig):
        display = rig
        self._set(display, _app_warning())
        self._page(display)
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        assert display._screen_request is None
        _fold(display)
        assert display._screen == "appliance_warning"
        self._dismiss(display)
        tick_warnings(display)
        _fold(display)
        assert display._screen == "sdhealth"

    def test_appliance_warnings_page_by_severity_one_dismiss_at_a_time(self, rig):
        display = rig
        self._set(
            display, _app_warning("a", "info", "Info one"), _app_warning("c", "critical", "Critical one"),
            _app_warning("b", "warning", "Warning one"),
        )
        shown = []
        for _ in range(3):
            self._page(display)
            shown.append(display._warning_screen.warning_id)
            self._dismiss(display)
            assert display._screen == "main"
        assert shown == [_app_key("c"), _app_key("b"), _app_key("a")]
        self._page(display)
        assert display._screen == "main"

    def test_a_day_hint_snoozes_a_day_and_the_page_returns_after_it(self, rig):
        display = rig
        self._set(display, _app_warning(dismissal="day"))
        self._page(display)
        self._dismiss(display)
        display.core.flush_warnings()
        assert json.loads(display.snooze_file.read_text())[_app_key()] == pytest.approx(
            display.clock.t + 86400.0)
        display.clock.t += 86399.0
        self._page(display)
        assert display._screen == "main"
        display.clock.t += 2.0
        self._page(display)
        assert display._screen == "appliance_warning"

    def test_a_none_hint_shows_an_ok_cell_that_holds_until_the_appliance_clears_it(self, rig):
        display = rig
        self._set(display, _app_warning("n", "info", "Firmware", "Updated.", dismissal="none"))
        self._page(display)
        assert self._painted_view(display).buttons == ("OK",)
        self._dismiss(display)
        assert display._screen == "main"
        assert display.core.warnings.is_snoozed(_app_key("n"))
        display.core.flush_warnings()
        assert not display.snooze_file.exists() or _app_key("n") not in json.loads(display.snooze_file.read_text())
        display.clock.t += 400 * 86400.0
        self._page(display)
        assert display._screen == "main"
        self._set(display, _app_warning("n", "info", "Firmware", "Updated.", dismissal="none"))
        self._page(display)
        assert display._screen == "main"
        self._set(display)                                     # the appliance stops reporting it
        self._set(display, _app_warning("n", "info", "Firmware", "Updated.", dismissal="none"))
        self._page(display)
        assert display._screen == "appliance_warning"          # a new incident shows again

    def test_escalation_keeps_a_snooze_so_the_page_stays_away(self, rig):
        display = rig
        self._set(display, _app_warning(severity="warning"))
        self._page(display)
        self._dismiss(display)
        self._set(display, _app_warning(severity="critical"))
        from dial_warning_text import APPLIANCE_WARNING_PRIORITY
        assert display.core.warnings.descriptor(_app_key()).priority == APPLIANCE_WARNING_PRIORITY["critical"]
        self._page(display)
        assert display._screen == "main" and display._screen_request is None

    def test_a_warning_the_appliance_stops_reporting_closes_its_open_page(self, rig):
        display = rig
        self._set(display, _app_warning())
        self._page(display)
        assert display._screen == "appliance_warning"
        self._set(display)
        tick_warnings(display)
        assert display._screen_request == "main"
        _fold(display)
        assert display._screen == "main" and display._warning_screen is None

    def test_one_gone_warning_leaves_the_page_of_another_up(self, rig):
        display = rig
        self._set(display, _app_warning("a", "critical", "One"), _app_warning("b", "info", "Two"))
        self._page(display)
        assert display._warning_screen.warning_id == _app_key("a")
        self._set(display, _app_warning("a", "critical", "One"))
        tick_warnings(display)
        assert display._screen_request is None and display._screen == "appliance_warning"

    def test_a_descriptor_gone_at_paint_time_closes_the_page_without_painting(self, rig):
        display = rig
        self._set(display, _app_warning())
        self._page(display)
        display.core.warnings.unregister(_app_key())
        before = len(display.fb.displayed)
        with display._lock:
            display._display_warning_locked()
        assert display._screen_request == "main"
        assert len(display.fb.displayed) == before

    def test_a_request_for_a_warning_that_went_before_it_opened_is_refused(self, rig):
        display = rig
        self._set(display, _app_warning())
        tick_warnings(display)
        assert display._screen_request == "appliance_warning"
        self._set(display)
        _fold(display)
        assert display._screen == "main"

    def test_the_tap_dismisses_the_warning_on_screen_not_the_first_row_with_that_zone(self, rig):
        display = rig
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        _fold(display)
        self._dismiss(display)
        until = display.core.warnings._state["sdhealth"].dismissed_until
        display.clock.t += 60.0
        self._set(display, _app_warning())
        self._page(display)
        assert display._screen == "appliance_warning"
        self._dismiss(display)
        assert display.core.warnings.is_snoozed(_app_key())
        assert display.core.warnings._state["sdhealth"].dismissed_until == until

    def test_two_appliances_with_the_same_warning_id_page_separately(self, rig):
        display = rig
        other = "b" * 20
        display.core.set_roster([
            _roster_entry(auth="authorized", appliance_id=_APP_AID),
            _roster_entry(name="Lounge", auth="authorized", appliance_id=other, ip="192.168.1.11"),
        ])
        self._set(display, _app_warning())
        assert display.core.set_appliance_warnings(other, (_app_warning(),)).accepted
        sources = []
        for _ in range(2):
            self._page(display)
            assert display._screen == "appliance_warning"
            sources.append(self._painted_view(display).source)
            self._dismiss(display)
        assert sorted(sources) == ["Kitchen", "Lounge"]
        self._page(display)
        assert display._screen == "main"


_TIER_PANELS = {
    "base_160x128": (160, 128, None),
    "compact_128x128": (128, 128, 0.2021),
    "compact_240x240": (240, 240, 0.0973),
    "rich_320x240": (320, 240, 0.1778),
}


class TestApplianceWarningTouchZones:
    def test_the_shared_row_uses_the_one_cell_geometry_on_the_touch_surface(self):
        from dial_touch import _GEOMETRY_FOR_SURFACE
        from dial_touch_layout import GEOMETRY_SDHEALTH
        policy = SCREEN_POLICIES["appliance_warning"]
        assert policy.state_attr == "_warning_screen" and policy.paint is DialDisplay._display_warning_locked
        assert policy.open.keywords == {"warning_id": None}
        assert policy.inactivity_timeout_s is None and policy.defers_sleep is False and policy.back_to == "main"
        assert _GEOMETRY_FOR_SURFACE[policy.surface[0]] == GEOMETRY_SDHEALTH

    @pytest.mark.parametrize("tier", sorted(_TIER_PANELS))
    @pytest.mark.parametrize("dismissal", ["day", "week", "none"])
    def test_the_cell_is_hit_in_the_bottom_row_and_the_message_row_is_dead(self, tier, dismissal):
        from dial_touch_layout import hit_test, sdhealth_layout_for
        from dial_warning_text import appliance_warning_descriptor
        width, height, mm = _TIER_PANELS[tier]
        metrics = metrics_for(width, height, mm)
        desc = appliance_warning_descriptor(_APP_AID, _app_warning(dismissal=dismissal))
        (button,) = desc.buttons
        assert button.zone == TouchZone.SDHEALTH_DISMISS
        layout = sdhealth_layout_for(width, height, metrics=metrics)
        cx, cy = (layout.dismiss[0] + layout.dismiss[2]) // 2, (layout.dismiss[1] + layout.dismiss[3]) // 2
        entry = hit_test(desc.geometry, cx, cy, width, height, metrics=metrics)
        assert entry is not None and desc.button_for(entry.zone) is button
        mx, my = (layout.message[0] + layout.message[2]) // 2, (layout.message[1] + layout.message[3]) // 2
        assert hit_test(desc.geometry, mx, my, width, height, metrics=metrics) is None


class TestApplianceWarningsAndTheView:
    def test_a_dial_warning_still_pages_while_an_appliance_one_waits(self):
        from dial_core_state import ApplianceWarning
        display, fb, gt = make_display(targets=[], roster=[_roster_entry(auth="authorized")])
        display.enable()
        display._poll_once()
        _fold(display)
        aid = display._core.snapshot().appliances[0].appliance_id
        display._core.set_appliance_warnings(
            aid, (ApplianceWarning("stylus", "critical", "Replace stylus", "", "day"),))
        warning_active(display, "sdhealth", severity=40)
        assert display._screen_request == "sdhealth"


class TestRepeatResultsHandedStraightToTheCore:
    """The service hands the repeat worker's results to the core, not to
    this view: what they meant reaches the screen when the view next folds
    in what the core has published."""

    def test_the_compact_tier_closes_the_repeat_screen_on_its_own_stop_ack(self):
        import dial_repeat_store as drs
        aid = "6" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_compact_display(targets=[t], repeat_capable=True)
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"
        drs.repeat_store.update(aid, drs.parse_repeat_object(
            _repeat_obj(state="replaying", replay={"active": True, "position_seconds": 1.0, "duration_seconds": 30.0}),
            time.monotonic(),
        ))
        with patch("dial_core.enqueue_transport"):
            display.repeat_stop_tap()

        display._core.on_repeat_result(
            "transport", aid, 200, {"ok": True, "state": "hold"},
            {"token": pending_token(display, "transport")},
        )
        assert display._screen_request is None
        display._apply_pending_snapshot()
        assert display._screen_request == "main"

    def test_a_rejected_replay_drops_the_replay_timer(self):
        aid = "9" * 20
        display, fb, gt = make_display(targets=[])
        display._arm_replay_timer(aid)
        display._overlay_signal.clear()

        display._core.on_repeat_result("transport", aid, 412, {"ok": False, "error": "fading_out"})
        assert display._replay_timer_id == aid
        display._apply_pending_snapshot()
        assert display._replay_timer_id is None
        assert display._overlay_signal.is_set()
        assert display._core._reconcile_due is True

    def test_an_accepted_replay_the_dial_follows_polls_at_once(self):
        aid = "8" * 20
        display, fb, gt = make_display(targets=[])
        display.core.request_poll = MagicMock()
        with patch.object(display._core, "accept_replay", return_value=True):
            display._core.on_repeat_result(
                "transport", aid, 200,
                {"ok": True, "state": "replaying", "armed": False, "position_seconds": 0.0},
            )
        display.core.request_poll.assert_not_called()
        display._apply_pending_snapshot()
        display.core.request_poll.assert_called_once()


class TestOnInput:
    def test_a_physical_input_returns_the_repeat_screen_to_main(self):
        display, fb, gt = make_display(targets=[])
        display._screen = "repeat"
        display.on_input("volume")
        assert display._screen_request == "main"

    def test_it_leaves_any_other_screen_alone(self):
        display, fb, gt = make_display(targets=[])
        display._screen = "outputs"
        display.on_input("mute")
        assert display._screen_request is None


# ---------------------------------------------------------------------------
# The "Pair in Autostream" page: a speaker that needs a PIN cannot be paired
# on the small screen, so its output page gives way to a hint page.
# ---------------------------------------------------------------------------

class _SpyLock:
    """A lock that counts acquisitions and delegates to a real one."""

    def __init__(self):
        self._real = threading.Lock()
        self.acquire_calls = 0

    def acquire(self, *args, **kwargs):
        self.acquire_calls += 1
        return self._real.acquire(*args, **kwargs)

    def release(self):
        return self._real.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc_info):
        self.release()


class TestPairInAutostreamPage:
    AID = "a" * 20
    PIN_REQUIRED = {"ok": False, "pin_required": True, "error": "Output requires PIN"}

    def _detail(self, needs_auth_key=False, selected=False):
        display = _make_outputs_display()
        display._open_outputs_locked()
        row = OutputRow(id="1", name="Apple TV", selected=selected, volume=0, needs_auth_key=needs_auth_key)
        seed_outputs(display, (row,), loaded=False)
        display._output_detail = dd.OutputDetailState(
            appliance_id=self.AID, output_id="1", opened_at=time.monotonic(),
        )
        display._screen = "output"
        return display

    def _fold(self, display):
        display._apply_pending_snapshot()
        with display._lock:
            display._apply_screen_requests_locked()

    def _refuse(self, display, body):
        with patch("dial_core.enqueue_set"):
            result = display.core.set_output(self.AID, "1", selected=True)
        assert result.accepted
        display.core.on_outputs_result("set", self.AID, 200, body, {"token": result.token})
        self._fold(display)

    def test_pairing_hint_text(self):
        label, text = dd._pairing_hint("Lounge")
        assert label == dd_compositor.PAIR_IN_AUTOSTREAM_TEXT == "Pair in Autostream"
        assert text == "Enter the PIN in Lounge's web UI"

    @pytest.mark.parametrize("width,height,mm_per_px", _HINT_TIERS)
    @pytest.mark.parametrize("name", ["Lounge", "CD Player", "Living Room Hi-Fi"])
    def test_pairing_hint_text_fits_without_truncation(self, width, height, mm_per_px, name):
        from PIL import ImageDraw
        from dial_touch_layout import info_value_layout_for

        metrics = metrics_for(width, height, mm_per_px)
        label, text = dd._pairing_hint(name)
        layout = info_value_layout_for(width, height, metrics=metrics)
        draw = ImageDraw.Draw(Image.new("RGB", (width, height)))
        lines, font = dd_compositor._fit_value_lines(
            draw, text, (metrics.font_readout, metrics.font_body), layout.value,
        )
        assert lines and font is not None
        assert " ".join(lines) == text
        max_w = layout.value[2] - layout.value[0]
        for line in lines:
            assert dd_compositor._text_size(draw, line, font)[0] <= max_w
        title_w = dd_compositor._text_size(draw, label, dd_compositor._load_font(metrics.font_body))[0]
        assert title_w <= width - 2 * metrics.pad

    @pytest.mark.parametrize("key", [
        k for k, prof in __import__("dial_display_profiles").DISPLAY_PROFILES.items() if prof.surface == "spi"
    ])
    def test_pairing_hint_fits_every_spi_profile_at_its_default_size(self, key):
        from PIL import ImageDraw
        from dial_touch_layout import info_value_layout_for

        profile = get_profile(key)
        width, height = profile.width, profile.height
        metrics = metrics_for(width, height, mm_per_px_for(profile, profile.default_diagonal_inches))
        label, text = dd._pairing_hint("Living Room Hi-Fi")
        layout = info_value_layout_for(width, height, metrics=metrics)
        draw = ImageDraw.Draw(Image.new("RGB", (width, height)))
        lines, font = dd_compositor._fit_value_lines(
            draw, text, (metrics.font_readout, metrics.font_body), layout.value,
        )
        assert lines and font is not None and " ".join(lines) == text
        max_w = layout.value[2] - layout.value[0]
        assert all(dd_compositor._text_size(draw, line, font)[0] <= max_w for line in lines)
        title_w = dd_compositor._text_size(draw, label, dd_compositor._load_font(metrics.font_body))[0]
        assert title_w <= width - 2 * metrics.pad

    def test_a_pin_required_effect_opens_the_pair_page_over_the_output_page_and_back_returns_there(self):
        display = self._detail()
        self._refuse(display, self.PIN_REQUIRED)
        assert display._screen == "info_value"
        assert display._info_value.hint[0] == "Pair in Autostream"
        with display._lock:
            display._repaint_current_locked()
        display.close_list()
        self._fold(display)
        assert display._screen == "output"
        assert display._output_detail.output_id == "1"
        assert display._outputs is not None

    def test_the_page_times_out_to_the_main_page(self):
        display = self._detail()
        self._refuse(display, self.PIN_REQUIRED)
        opened_at = display._info_value.opened_at
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS - 1):
            display._check_secondary_timeout()
        assert display._screen == "info_value"
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS + 1):
            display._check_secondary_timeout()
        assert display._screen == "main"

    def test_the_effect_is_ignored_when_the_output_page_is_not_up(self):
        display = self._detail()
        display._screen = "outputs"
        display._output_detail = None
        self._refuse(display, self.PIN_REQUIRED)
        assert display._screen == "outputs"
        assert display._screen_request is None

    def test_the_effect_is_ignored_for_another_output_or_appliance(self):
        display = self._detail()
        for effect in (
            dd.OutputsEffect(self.AID, "9", "output_set", "rejected", "pin_required"),
            dd.OutputsEffect("b" * 20, "1", "output_set", "rejected", "pin_required"),
        ):
            display._apply_outputs_outcome(effect)
            assert display._screen_request is None

    @pytest.mark.parametrize("body", [
        {"ok": False, "error": "rate_limited", "retry_after_s": 7},
        {"ok": False, "error": "output_in_use"},
        {"ok": False, "error": "encoder_capacity"},
        {"ok": True},
    ])
    def test_any_other_outcome_shows_nothing(self, body):
        display = self._detail()
        self._refuse(display, body)
        assert display._screen == "output"
        assert display._screen_request is None

    def test_a_needs_pin_row_shows_the_pair_page_without_calling_the_core(self):
        display = self._detail(needs_auth_key=True)
        with patch("dial_core.enqueue_set") as send:
            display.output_toggle_tap()
        send.assert_not_called()
        assert display.core.outputs_override() is None
        assert display.core.snapshot().outputs_request is None
        self._fold(display)
        assert display._screen == "info_value"
        assert display._info_value.hint[0] == "Pair in Autostream"

    def test_switching_a_needs_pin_row_off_is_not_short_circuited(self):
        display = self._detail(needs_auth_key=True, selected=True)
        with patch("dial_core.enqueue_set") as send:
            display.output_toggle_tap()
        send.assert_called_once()
        assert display._screen_request is None

    def test_a_hint_cannot_open_over_the_main_page(self):
        display, fb, gt = make_display(targets=[])
        display._info_value_hint = dd._pairing_hint("Lounge")
        with display._lock:
            assert display._open_info_value_locked() is False
        assert display._screen == "main"
        assert display._info_value is None
        assert display._info_value_hint is None

    def test_a_hint_over_the_selector_still_returns_to_the_selector(self):
        display, fb, gt = make_display(targets=[])
        display._screen = "selector"
        display._info_value_hint = dd._unauthorised_hint("Lounge")
        with display._lock:
            assert display._open_info_value_locked() is True
        assert display._back_target("info_value") == "selector"

    def test_the_appliance_changing_while_the_page_is_up_closes_it(self):
        display = self._detail()
        self._refuse(display, self.PIN_REQUIRED)
        assert display._screen == "info_value"
        display.core.set_field("reporting_id", "b" * 20)
        display.core.set_roster([_roster_entry(appliance_id="b" * 20, dial_outputs=True)])
        with display._lock:
            display._close_secondary_locked()
        assert display._screen == "main"
        assert display._output_detail is None
        assert display._info_value is None

    def test_the_first_touch_of_a_sleeping_screen_only_wakes(self):
        import dial_touch as dt
        from dial_touch_filter import TouchEvent, TouchEventType

        display = self._detail()
        display.enable()
        self._refuse(display, self.PIN_REQUIRED)
        with display._lock:
            display._sleep_locked()
        assert display.is_sleeping() is True
        assert display._screen == "main"
        width, height = display._active_panel_dims()
        sm = dt.TouchStateMachine(width, height, is_asleep=display.is_sleeping)
        sm.set_surface(*display.touch_surface(), 1.0)
        actions = sm.on_filter_event(TouchEvent(TouchEventType.PRESS, width // 2, height // 2, None), 1.0)
        assert [a.kind for a in actions] == [dt.ACTION_WAKE]
        assert display._screen_request is None

    def test_the_entry_points_take_neither_the_view_lock_nor_the_core_lock(self):
        display = self._detail(needs_auth_key=True)
        view_spy, core_spy = _SpyLock(), _SpyLock()
        display._lock = view_spy
        display._core._lock = core_spy
        display.output_toggle_tap()
        display._apply_outputs_outcome(
            dd.OutputsEffect(self.AID, "1", "output_set", "rejected", "pin_required"),
        )
        assert view_spy.acquire_calls == 0
        assert core_spy.acquire_calls == 0
