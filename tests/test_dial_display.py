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

import json
import math
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

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
from dial_display_views import (
    OverlayState,
    WIFI_GREY,
    WIFI_OFF,
    WIFI_RED,
    WIFI_SIGNAL,
)
from dial_network import LINK_CONNECTED, LINK_DOWN, LINK_UNKNOWN
from dial_touch_layout import TouchZone
import dial_core
import dial_core_state
import dial_display as dd
from dial_core_state import NowPlaying, artwork_key
from dial_display import SCREEN_POLICIES
from dial_test_support import (
    FakeBackend,
    _FakeClock,
    _repeat_obj,
    _roster_entry,
    _status_result,
    _target,
    _track_id,
    make_display,
    on_network_view,
    patch_monotonic,
    seed_repeat,
    set_focus_pending,
)
from dial_display_test_support import _REPLAY_AID, _fold, _poll_with_artwork, _view, idle_display

# ---------------------------------------------------------------------------
# A change of the now-playing line asks for a repaint.
# ---------------------------------------------------------------------------

class TestNowPlayingRepaintSignal:
    def test_now_playing_change_sets_overlay_signal(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        display._overlay_signal.clear()
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())):
            display.fold_for_tests()
        assert display._overlay_signal.is_set()
    def test_album_only_change_sets_overlay_signal(self):
        # Two polls differing only in album must still count as "now-playing
        # changed" — NowPlaying's == comparison sees every field.
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_test_support.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(album="First Album"))):
            display.fold_for_tests()
        assert display.core.snapshot().now_playing.album == "First Album"

        display._overlay_signal.clear()
        with patch("dial_test_support.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(album="Second Album"))):
            display.fold_for_tests()
        assert display.core.snapshot().now_playing.album == "Second Album"
        assert display._overlay_signal.is_set()

    def test_mute_changed_elsewhere_sets_overlay_signal(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())):
            display.fold_for_tests()

        display._overlay_signal.clear()
        with patch("dial_test_support.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(), muted=True)):
            display.fold_for_tests()
        assert display._overlay_signal.is_set()

    def test_volume_changed_elsewhere_sets_overlay_signal(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())):
            display.fold_for_tests()

        display._overlay_signal.clear()
        louder = dict(_status_result(track_id=_track_id()), master_volume=60)
        with patch("dial_test_support.fetch_target_status", return_value=louder):
            display.fold_for_tests()
        assert display._overlay_signal.is_set()

    def test_unchanged_poll_leaves_overlay_signal_clear(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())):
            display.fold_for_tests()
            display._overlay_signal.clear()
            display.fold_for_tests()
        assert not display._overlay_signal.is_set()


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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")) as mock_fetch_art, \
             patch("dial_display.decode_artwork", return_value=fake_image) as mock_decode, \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display.fold_for_tests()
            display.fold_for_tests()

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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"bad", "")), \
             patch("dial_display.decode_artwork", return_value=None):
            display.fold_for_tests()
        assert display.get_status()["showing"] == "logo"
        assert display.get_status()["last_error"] == "artwork_decode_failed"

    def test_decode_failure_downloads_the_artwork_again_next_poll(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"bad", "")) as mock_fetch_art, \
             patch("dial_display.decode_artwork", return_value=None):
            display.fold_for_tests()
            assert display._core.snapshot().artwork is None
            display.fold_for_tests()
        assert mock_fetch_art.call_count == 2

    def test_the_core_holds_one_artwork_copy_and_releases_it_at_the_logo(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        fake_image = Image.new("RGB", (128, 160))
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())),              patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")),              patch("dial_display.decode_artwork", return_value=fake_image),              patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display.fold_for_tests()
        held = display._core.snapshot().artwork
        assert held is not None and held.data == b"jpegdata"
        assert display._source_artwork_key == held.key
        gt.return_value = []
        display.fold_for_tests()
        assert display._core.snapshot().artwork is None

    def test_fetch_failure_falls_back_to_logo(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(None, "oversized")):
            display.fold_for_tests()
        assert display.get_status()["showing"] == "logo"
        assert display.get_status()["last_error"] == "artwork_fetch_failed"

    def test_ineligible_url_falls_back_to_logo_without_fetching(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=_track_id(artwork_url="http://provider.example/a.jpg"))
        with patch("dial_test_support.fetch_target_status", return_value=result), \
             patch("dial_artwork.default_fetch_artwork") as mock_fetch_art:
            display.fold_for_tests()
        mock_fetch_art.assert_not_called()
        assert display.get_status()["showing"] == "logo"


# ---------------------------------------------------------------------------
# Logo fallback
# ---------------------------------------------------------------------------

class TestLogoFallback:
    def test_logo_fallback_when_no_targets_visible(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.fold_for_tests()
        assert display.get_status()["showing"] == "logo"

    def test_logo_fallback_while_playing_with_no_artwork(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
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
            display.fold_for_tests()
            clock.t += 5.0
            status = display.get_status()
        assert status["showing"] == "logo"
        assert status["display_idle_seconds"] == 5

    def test_idle_below_threshold_does_not_sleep(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display.fold_for_tests()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS - 1
            display.fold_for_tests()
            status = display.get_status()
        assert status["display_sleeping"] is False
        assert fb.sleep_calls == 0

    def test_idle_at_threshold_sleeps_once(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display.fold_for_tests()  # idle timer starts
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display.fold_for_tests()  # crosses threshold -> sleep
            display.fold_for_tests()  # still asleep -> no repeat sleep call
            status = display.get_status()
        assert status["display_sleeping"] is True
        assert status["showing"] == "sleeping"
        assert fb.sleep_calls == 1

    def test_sleeping_does_not_repaint(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display.fold_for_tests()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display.fold_for_tests()
            count_after_sleep = len(fb.displayed)
            display.fold_for_tests()
            display.fold_for_tests()
        assert len(fb.displayed) == count_after_sleep

    def test_idle_seconds_clamps_at_threshold_while_asleep(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display.fold_for_tests()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display.fold_for_tests()
            clock.t += 1000.0  # long past threshold while asleep
            status = display.get_status()
        assert status["display_idle_seconds"] == dd.DISPLAY_IDLE_SLEEP_SECONDS

    def test_target_appearing_wakes_before_next_frame(self):
        t = _target()
        display, fb, gt = make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display.fold_for_tests()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display.fold_for_tests()  # asleep now
            assert display.get_status()["display_sleeping"] is True

            gt.return_value = [t]
            with patch("dial_test_support.fetch_target_status",
                       return_value=_status_result(track_id=None)):
                display.fold_for_tests()
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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display.fold_for_tests()  # showing artwork
        assert display.get_status()["showing"] == "artwork"

        gt.return_value = []
        clock = _FakeClock()
        with patch_monotonic(clock):
            display.fold_for_tests()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display.fold_for_tests()  # asleep
        assert display.get_status()["display_sleeping"] is True

        gt.return_value = [t]
        displayed_before = len(fb.displayed)
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display.fold_for_tests()  # wakes and repaints same artwork url

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
             patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            for _ in range(5):
                display.fold_for_tests()
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
            display.fold_for_tests()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display.fold_for_tests()
            status = display.get_status()
        assert status["display_sleeping"] is True
        assert fb.sleep_calls == 1

    def _asleep_display(self, clock):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with patch_monotonic(clock):
            display.fold_for_tests()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display.fold_for_tests()
        assert display.get_status()["display_sleeping"] is True
        return display, fb, gt

    def test_unauthorized_only_targets_do_not_wake_sleeping_panel(self):
        clock = _FakeClock()
        display, fb, gt = self._asleep_display(clock)
        gt.return_value = [_target(auth="unauthorized")]
        with patch_monotonic(clock):
            display.fold_for_tests()
        assert display.get_status()["display_sleeping"] is True
        assert fb.wake_calls == 0

    def test_unauthorized_only_targets_keep_the_idle_clock_running(self):
        display, fb, gt = make_display(targets=[_target(auth="unauthorized")])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display.fold_for_tests()
            clock.t += 5.0
            display.fold_for_tests()
            status = display.get_status()
        assert status["display_idle_seconds"] == 5

    def test_unknown_identified_target_still_wakes_panel(self):
        clock = _FakeClock()
        display, fb, gt = self._asleep_display(clock)
        t = _target(auth="unknown")
        gt.return_value = [t]
        with patch_monotonic(clock),              patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
        assert display.get_status()["display_sleeping"] is False
        assert fb.wake_calls == 1
        assert display.core.snapshot().focus.reporting_id == t.appliance_id

    def test_authorized_target_wakes_panel_alongside_unauthorized_one(self):
        clock = _FakeClock()
        display, fb, gt = self._asleep_display(clock)
        refused = _target(name="Lounge", auth="unauthorized", playing_since=1.0)
        ok = _target(name="Kitchen", auth="authorized", playing_since=2.0)
        gt.return_value = [refused, ok]
        with patch_monotonic(clock),              patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
        assert display.get_status()["display_sleeping"] is False
        assert display.core.snapshot().focus.reporting_id == ok.appliance_id

    def test_unresolved_identityless_target_does_not_wake_panel(self):
        clock = _FakeClock()
        display, fb, gt = self._asleep_display(clock)
        gt.return_value = [_target(appliance_id="")]
        with patch_monotonic(clock),              patch("dial_test_support.fetch_target_status") as fetch:
            display.fold_for_tests()
        fetch.assert_not_called()
        assert display.get_status()["display_sleeping"] is True
        assert fb.wake_calls == 0
        assert display.core.snapshot().focus.reporting_id is None

    def test_disable_while_asleep_resets_idle_and_sleep_state(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display.fold_for_tests()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display.fold_for_tests()
        assert display.get_status()["display_sleeping"] is True

        status = display.update_config(DialDisplayConfig(fitted=False))
        assert status["display_sleeping"] is False
        assert status["display_idle_seconds"] == 0
        assert display._idle_started_at is None


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
        of a fold does."""
        display._core._artwork.follow("https://provider.example/fresh.jpg")
        display._show_artwork(display._core.snapshot().artwork)

    def _to_artwork_on_main(self, fb):
        display, _, gt = make_display(targets=[_target()], backend=fb)
        display.enable()
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=Image.new("RGB", (300, 300))):
            display.fold_for_tests()
        assert display.get_status()["showing"] == "artwork"
        return display

    def test_fresh_artwork_keeps_the_secondary_screen(self):
        fb = FakeBackend()
        display = self._to_artwork_on_main(fb)
        # A secondary screen is now up.
        display._screen = "repeat"
        fb.displayed.clear()
        display._overlay_signal.clear()

        with patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata2", "")), \
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
        with patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata2", "")), \
             patch("dial_display.decode_artwork", return_value=Image.new("RGB", (301, 301))):
            self._show_fresh(display)
        assert display._screen == "main"
        assert fb.displayed  # the main surface is still painted


# ---------------------------------------------------------------------------
# Touch activity notification — mirrors the two lines fold_for_tests() already
# runs when it finds playing targets present.
# ---------------------------------------------------------------------------

class TestNotifyTouchActivity:
    def test_resets_idle_timer(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch_monotonic(clock):
            display.fold_for_tests()  # idle timer starts (no targets)
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
            display.fold_for_tests()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display.fold_for_tests()  # asleep now
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
            display.fold_for_tests()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS - 1
            display.notify_touch_activity()
            display.fold_for_tests()  # restarts the idle timer from here
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display.fold_for_tests()  # crosses threshold again -> sleeps
        assert display.get_status()["display_sleeping"] is True


# ---------------------------------------------------------------------------
# _effective_overlay_locked(): merges now-playing state (artist, the
# optimistic volume readout, mute belief fallback) into the touch-published
# overlay snapshot at compose time.
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
            display.core.set_field_for_tests("now_playing", NowPlaying("svc", "Artist", "Title", 50))
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
            display.core.set_field_for_tests("now_playing", NowPlaying("svc", "Artist", "Title", 50))
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
            display.core.set_field_for_tests("now_playing", NowPlaying("svc", "The Artist", "Title", 50))
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
            display.core.set_field_for_tests("now_playing", NowPlaying("svc", "The Artist", "Title", 50, album="The Album"))
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
            display.core.set_field_for_tests("now_playing", NowPlaying("svc", "", "", 50, playing=False))
        with patch.object(display, "_layout_metrics", return_value=MagicMock(content_tier=content_tier)):
            result = display._effective_overlay_locked(OverlayState(visible=True))
        assert result.artist == dd.IDLE_ARTIST_TEXT

    @pytest.mark.parametrize("tier", ["rich", "large"])
    def test_playing_with_no_title_shows_playing_text(self, tier):
        content_tier = dd.CONTENT_RICH if tier == "rich" else dd.CONTENT_LARGE
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display.core.set_field_for_tests("now_playing", NowPlaying("svc", "", "", 50, playing=True))
        with patch.object(display, "_layout_metrics", return_value=MagicMock(content_tier=content_tier)):
            result = display._effective_overlay_locked(OverlayState(visible=True))
        assert result.artist == dial_core_state.PLAYING_TEXT

    @pytest.mark.parametrize("tier", ["rich", "large"])
    def test_playing_with_no_title_but_an_input_label_shows_the_label(self, tier):
        content_tier = dd.CONTENT_RICH if tier == "rich" else dd.CONTENT_LARGE
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display.core.set_field_for_tests(
                "now_playing", NowPlaying("svc", "", "", 50, playing=True, input_label="CD"))
        with patch.object(display, "_layout_metrics", return_value=MagicMock(content_tier=content_tier)):
            result = display._effective_overlay_locked(OverlayState(visible=True))
        assert result.artist == "CD"

    def test_playing_with_title_and_no_artist_stays_empty(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display.core.set_field_for_tests("now_playing", NowPlaying("svc", "", "Some Title", 50, playing=True))
        with patch.object(display, "_layout_metrics", return_value=MagicMock(content_tier=dd.CONTENT_RICH)):
            result = display._effective_overlay_locked(OverlayState(visible=True))
        assert result.artist == ""

    def test_playing_with_title_and_artist_keeps_the_real_artist(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display.core.set_field_for_tests("now_playing", NowPlaying("svc", "Real Artist", "Some Title", 50, playing=True))
        with patch.object(display, "_layout_metrics", return_value=MagicMock(content_tier=dd.CONTENT_LARGE)):
            result = display._effective_overlay_locked(OverlayState(visible=True))
        assert result.artist == "Real Artist"

    def test_base_tier_artist_row_is_unaffected(self):
        # make_display defaults to the base (160x128) tier -- no patch
        # needed, this is the tier's own natural resolution.
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display.core.set_field_for_tests("now_playing", NowPlaying("svc", "", "", 50, playing=False))
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

        # Everything dial_touch_wiring wires to the touch callbacks.
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
        with patch("dial_test_support.fetch_target_status",
                   return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image), \
             patch.object(
                 display._compositor, "compose", wraps=display._compositor.compose
             ) as mock_compose:
            display.fold_for_tests()  # new artwork -> a real poll-driven push

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
    def test_clear_locked_bumps_generation(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        gen_before = display.noncomposited_generation()

        with display._lock:
            display._clear_locked()

        assert display.noncomposited_generation() == gen_before + 1

    def test_sleep_locked_bumps_generation(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        gen_before = display.noncomposited_generation()

        with display._lock:
            display._sleep_locked()

        assert display.noncomposited_generation() == gen_before + 1

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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
        before = len(fb.displayed)

        gt.return_value = [tb]
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()

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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()

        gt.return_value = [tb]
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)), \
             patch.object(display, "show_logo") as mock_show_logo:
            display.fold_for_tests()
        mock_show_logo.assert_called_once()
        assert display._showing == "waiting"

    def test_no_transition_frame_when_reporting_id_unchanged(self):
        ta, _ = self._target_pair()
        display, fb, gt = make_display(targets=[ta])
        display.enable()
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
        before = len(fb.displayed)
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
        pushed = fb.displayed[before:]
        assert len(pushed) == 0

    def test_no_transition_frame_when_switching_to_nothing_playing(self):
        ta, _ = self._target_pair()
        display, fb, gt = make_display(targets=[ta])
        display.enable()
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
        before = len(fb.displayed)
        gt.return_value = []
        display.fold_for_tests()
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


# ---------------------------------------------------------------------------
# A pushed auth change and the sleeping panel.
# ---------------------------------------------------------------------------

class TestPushedAccessOnScreen:
    """An access change the appliance pushes reaches the panel through the
    fold that follows it."""

    def test_an_access_grant_while_asleep_wakes_and_resets_idle(self):
        aid = "e" * 20
        t = _target(appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_test_support.fetch_target_status",
                   return_value=_status_result(status_error="unauthorized", appliance_id=aid)):
            display.fold_for_tests()
        with display._lock:
            display._display_sleeping = True
            display._idle_started_at = 123.0
        with patch("dial_test_support.fetch_target_status",
                   return_value=_status_result(appliance_id=aid, track_id=None)):
            display.fold_for_tests()
        assert display._display_sleeping is False
        assert display._idle_started_at is None
        assert fb.wake_calls == 1

    def test_an_access_refusal_leaves_the_display_asleep(self):
        aid = "f" * 20
        t = _target(appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with display._lock:
            display._display_sleeping = True
        with patch("dial_test_support.fetch_target_status",
                   return_value=_status_result(status_error="unauthorized", appliance_id=aid)):
            display.fold_for_tests()
        assert display._display_sleeping is True
        assert fb.wake_calls == 0


class TestRunPollGating:
    """The core folds every interval, asleep or not: the fold itself wakes
    the panel for a playing target this dial may use and stays dark
    otherwise."""

    def _run_one_iteration(self, display):
        """One turn of the core's loop: the fold, and the view folding in the
        snapshot it ends in."""
        display.fold_for_tests()

    def _asleep_display(self, clock):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with patch_monotonic(clock):
            display.fold_for_tests()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display.fold_for_tests()
        assert display.get_status()["display_sleeping"] is True
        return display, fb, gt

    def test_the_core_keeps_folding_while_the_view_sleeps(self, monkeypatch):
        display, fb, gt = make_display(targets=[])
        display._display_sleeping = True
        monkeypatch.setattr(dial_core, "FOLD_INTERVAL_S", 0.02)
        folds = []
        with patch.object(display._core, "fold_once", side_effect=lambda: folds.append(1)):
            display._core.start()
            try:
                deadline = time.monotonic() + 2.0
                while len(folds) < 3 and time.monotonic() < deadline:
                    time.sleep(0.01)
            finally:
                display._core.stop()
        assert len(folds) >= 3
        assert display._display_sleeping is True

    def test_view_wakes_when_a_visible_target_appears_in_a_snapshot(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with display._lock:
            display._display_sleeping = True
            display._idle_started_at = 5.0
        before = display._applied
        display._core._publish(lambda state: setattr(state, "visible_playing", (t.appliance_id,)))
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
        display._core.set_field_for_tests("now_playing", NowPlaying("x", "", "", None))
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
             patch("dial_test_support.fetch_target_status",
                   return_value=_status_result(track_id=None)):
            self._run_one_iteration(display)
        assert fb.wake_calls == 1
        assert display.get_status()["display_sleeping"] is False

    def test_asleep_dial_stays_dark_for_a_confirmed_unauthorized_target(self):
        clock = _FakeClock()
        display, fb, gt = self._asleep_display(clock)
        gt.return_value = [_target(auth="unauthorized")]
        painted = len(fb.displayed)
        with patch_monotonic(clock):
            self._run_one_iteration(display)
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

    def test_asleep_dial_still_wakes_on_an_access_grant(self):
        aid = "9" * 20
        t = _target(appliance_id=aid)
        clock = _FakeClock()
        display, fb, gt = self._asleep_display(clock)
        gt.return_value = [t]
        with patch_monotonic(clock), \
             patch("dial_test_support.fetch_target_status",
                   return_value=_status_result(status_error="unauthorized", appliance_id=aid)):
            self._run_one_iteration(display)
        assert fb.wake_calls == 0
        with patch_monotonic(clock), \
             patch("dial_test_support.fetch_target_status",
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
        with patch("dial_test_support.fetch_target_status",
                   return_value=_status_result(status_error="unauthorized",
                                               appliance_id=t.appliance_id)) as fetch:
            display.fold_for_tests()
        assert fetch.call_count == 1
        assert fb.wake_calls == wakes
        assert len(fb.displayed) == frames
        assert display._display_sleeping

    def test_first_check_acceptance_wakes_with_a_single_request(self):
        t = _target(name="Fresh", auth="unknown")
        display, fb, gt = self._asleep([t])
        wakes = fb.wake_calls
        with patch("dial_test_support.fetch_target_status",
                   return_value=_status_result(track_id=None)) as fetch:
            display.fold_for_tests()
        assert fetch.call_count == 1      # the walk reuses the first check's reply
        assert fb.wake_calls == wakes + 1
        assert not display._display_sleeping


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
        display.core.set_field_for_tests("manual_id", _REPLAY_AID)
        sentinel = object()
        with display._lock:
            display._screen = name
            if policy.state_attr is not None:
                setattr(display, policy.state_attr, sentinel)
        display.core.set_focus(None)
        display._close_screens_for_cleared_focus()
        assert display.core.snapshot().focus.manual_id is None
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
        display.core.set_field_for_tests("manual_id", _REPLAY_AID)      # not on the roster: the tick clears it
        with display._lock:
            display._screen = "outputs"
        display.fold_for_tests()
        assert display.core.snapshot().focus.manual_id is None
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
    def test_artwork_failures_log_once_a_minute(self, caplog):
        display, result = _artwork_display()
        clock = [1000.0]
        with patch("dial_display.time.monotonic", lambda: clock[0]),                 patch("dial_test_support.fetch_target_status", return_value=result),                 patch("dial_artwork.default_fetch_artwork", return_value=(None, "timeout")) as fetch,                 caplog.at_level(logging.WARNING):
            for _ in range(11):
                display.fold_for_tests()
            clock[0] += 61.0
            display.fold_for_tests()
        assert fetch.call_count == 12           # every poll retries
        records = [r for r in caplog.records if "artwork fetch failed" in r.getMessage()]
        assert len(records) == 2
        assert display.get_status()["showing"] == "logo"
        assert display.get_status()["last_error"] == "artwork_fetch_failed"

    def test_artwork_decode_failures_log_once_a_minute(self, caplog):
        display, result = _artwork_display()
        clock = [1000.0]
        with patch("dial_display.time.monotonic", lambda: clock[0]),                 patch("dial_test_support.fetch_target_status", return_value=result),                 patch("dial_artwork.default_fetch_artwork", return_value=(b"bad", "")),                 patch("dial_display.decode_artwork", return_value=None),                 caplog.at_level(logging.WARNING):
            for _ in range(11):
                display.fold_for_tests()
            clock[0] += 61.0
            display.fold_for_tests()
        records = [r for r in caplog.records if "artwork decode failed" in r.getMessage()]
        assert len(records) == 2

    def test_artwork_url_never_stored_or_logged(self, caplog):
        """Status, every log record and every attribute of the display carry
        only the short artwork key: the URL is never stored on the display
        (the cache-reuse key is a hash), nor held by the core."""
        display, result = _artwork_display()
        fake_image = Image.new("RGB", (128, 160))
        with patch("dial_test_support.fetch_target_status", return_value=result), \
                caplog.at_level(logging.DEBUG):
            with patch("dial_artwork.default_fetch_artwork", return_value=(None, "timeout")):
                for _ in range(3):
                    display.fold_for_tests()
            with patch("dial_artwork.default_fetch_artwork", return_value=(b"jpeg", "")), \
                    patch("dial_display.decode_artwork", return_value=fake_image), \
                    patch("dial_display_compositor.transform_artwork_for_panel",
                          return_value=fake_image):
                display.fold_for_tests()
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


class TestTouchSurface:
    def test_selector_while_open(self):
        a = _target(name="A", service_name="A", appliance_id="a" * 20, auth="authorized")
        display, fb, gt = make_display(targets=[a])
        display.enable()
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        assert display.touch_surface() == ("selector", False, False, False, False)

    def test_hidden_with_name_active_when_something_is_playing(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.touch_surface() == ("hidden", True, False, False, False)

    def test_held_with_name_active(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.touch_surface() == ("held", True, False, False, False)

    def test_idle_with_name_inactive_when_nothing_playing(self):
        # The idle screen is one screen whenever nothing plays: the "i"
        # affordance must be reachable even with no replay held, so
        # the surface is "idle" here, not "hidden".
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.fold_for_tests()
        assert display.touch_surface() == ("idle", False, False, False, False)

    def test_idle_when_affordance_drawn(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.fold_for_tests()
        with display._lock:
            display.core.set_field_for_tests("idle_affordance", True)
        assert display.touch_surface() == ("idle", False, False, False, False)

    def test_idle_regardless_of_affordance_when_nothing_playing(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.core.set_field_for_tests("idle_affordance", False)
        display.fold_for_tests()
        assert display.touch_surface()[0] == "idle"

    def test_repeat_screen_reports_repeat_with_dots_active(self):
        aid = "1" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        import dial_repeat_store as drs
        seed_repeat(aid, drs.RepeatRecord(
            available=True, state="recording", armed=False,
            recording_seconds=0.0, position_seconds=0.0, duration_seconds=0.0,
            observed_at=time.monotonic(),
        ))
        with display._lock:
            display._screen = "repeat"
        assert display.touch_surface() == ("repeat", True, True, False, False)

    def test_repeat_screen_outputs_active_follows_live_availability(self):
        aid = "1" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with display._lock:
            display._screen = "repeat"
            display.core.set_field_for_tests("outputs_available", True)
        assert display.touch_surface() == ("repeat", True, True, True, False)
        with display._lock:
            display.core.set_field_for_tests("outputs_available", False)
        assert display.touch_surface() == ("repeat", True, True, False, False)

    def test_picker_while_open(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "picker"
        assert display.touch_surface() == ("picker", False, False, False, False)

    def test_dots_active_reflects_fresh_available_record(self):
        aid = "2" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=None, appliance_id=aid)
        result["repeat"] = {
            "available": True, "state": "idle", "armed": False, "held": False,
            "recording_seconds": 0.0,
            "replay": {"active": False, "position_seconds": 0.0, "duration_seconds": 0.0},
        }
        with patch("dial_test_support.fetch_target_status", return_value=result):
            display.fold_for_tests()
        assert display.core.snapshot().dots_active is True
        surface, name_active, dots_active, outputs_active, bell_active = display.touch_surface()
        assert dots_active is True

    def test_dots_inactive_when_record_unavailable(self):
        aid = "3" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=None, appliance_id=aid)
        with patch("dial_test_support.fetch_target_status", return_value=result):
            display.fold_for_tests()
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
        display.fold_for_tests()
        assert display.touch_surface() == ("idle", False, False, False, False)

    def test_idle_affordance_still_drawn_with_an_idle_roster_entry(self):
        idle_entry = _roster_entry(name="Kitchen", auth="authorized", playing=False)
        display, fb, gt = make_display(targets=[], roster=[idle_entry])
        display.enable()
        display.fold_for_tests()
        with display._lock:
            display.core.set_field_for_tests("idle_affordance", True)
        assert display.touch_surface() == ("idle", False, False, False, False)

    def test_hidden_with_name_active_once_an_idle_focus_is_set(self):
        aid = "9" * 19 + "2"
        idle_entry = _roster_entry(name="Kitchen", service_name="Kitchen", appliance_id=aid, auth="authorized",
                                    playing=False)
        display, fb, gt = make_display(targets=[], roster=[idle_entry])
        display.enable()
        display.core.set_focus(aid)
        with patch("dial_test_support.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid)):
            display.fold_for_tests()
        assert display.touch_surface() == ("hidden", True, False, False, False)

    def test_held_with_name_active_once_an_idle_focus_is_set_and_always_show(self):
        aid = "9" * 19 + "3"
        idle_entry = _roster_entry(name="Kitchen", service_name="Kitchen", appliance_id=aid, auth="authorized",
                                    playing=False)
        display, fb, gt = make_display(targets=[], roster=[idle_entry], always_show_controls=True)
        display.enable()
        display.core.set_focus(aid)
        with patch("dial_test_support.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid)):
            display.fold_for_tests()
        assert display.touch_surface() == ("held", True, False, False, False)


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
        display.fold_for_tests()
        display.set_overlay(OverlayState(visible=True))
        with display._lock:
            overlay = display._effective_overlay_locked(display._overlay_snapshot)
        assert overlay.name == ""

    def test_name_active_unconditional_with_a_single_authorized_appliance(self):
        # The name (and its tap-zone) are always active whenever a
        # controllable appliance is shown, including the single-appliance
        # case — never gated on "two or more authorized" rows.
        t = _target(name="Solo", service_name="Solo", appliance_id="a" * 20, auth="authorized")
        display, fb, gt = make_display(targets=[t])
        display.enable()
        _poll_with_artwork(display, fb)
        assert len(display._selector.rows) == 1
        assert display.touch_surface() == ("hidden", True, False, False, False)


# ---------------------------------------------------------------------------
# Manual-focus pending grace: what the panel shows while it holds.
# ---------------------------------------------------------------------------

class TestFocusPendingOnScreen:
    def test_pending_focus_shows_logo_not_idle_screen(self):
        display, fb, gt = make_display(targets=[])
        aid = "c" * 20
        set_focus_pending(display, aid, "Kitchen")
        with display._lock:
            display.core.set_field_for_tests("idle_affordance", True)  # would otherwise draw the idle-screen affordance
        display.fold_for_tests()
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
        with patch("dial_test_support.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid)):
            display.fold_for_tests()

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
        with patch("dial_test_support.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid)):
            # A whole second, so the threshold poll lands exactly on the
            # sleep delay rather than a rounding error short of it.
            t0 = float(math.ceil(time.monotonic()))
            with patch("dial_display.time.monotonic", return_value=t0):
                display.fold_for_tests()
            assert display._display_sleeping is False

            with patch("dial_display.time.monotonic", return_value=t0 + dd.DISPLAY_IDLE_SLEEP_SECONDS):
                display.fold_for_tests()
        assert display._display_sleeping is True


class TestIdleReplayLogo:
    """When a replay is available the idle screen renders the replay-logo
    (the arrows-on-disc image), not the plain logo or any text. Reached
    whenever nothing is playing, not only while a replay is available —
    see TestIdlePlainLogo for the no-affordance case."""

    def test_idle_render_requests_the_replay_logo(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display.core.set_field_for_tests("idle_affordance", True)
            display._current_base_image = MagicMock()
            with patch("dial_display.load_logo", return_value=MagicMock()) as ll:
                display._display_idle_locked()
        assert ll.call_args_list[0].args[0] == display._replay_logo_path

    def test_idle_render_falls_back_to_plain_base_when_replay_logo_missing(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        base = MagicMock()
        with display._lock:
            display.core.set_field_for_tests("idle_affordance", True)
            display._current_base_image = base
            with patch("dial_display.load_logo", return_value=None):
                # Must not raise when the replay image cannot be loaded.
                display._display_idle_locked()


class TestIdlePlainLogo:
    """The idle screen's own compose path is reached whenever
    nothing is playing, not only while a replay is available — a dial with
    no repeat-capable appliance still gets the "i" badge (see
    TestComposeIdle in test_dial_display_render.py), just over the plain logo
    rather than the replay-available one."""

    def test_plain_base_used_and_replay_logo_never_loaded_without_affordance(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        base = MagicMock()
        with display._lock:
            display.core.set_field_for_tests("idle_affordance", False)
            display._current_base_image = base
            with patch("dial_display.load_logo") as ll:
                display._display_idle_locked()
        ll.assert_not_called()

    def test_idle_chassis_due_whenever_nothing_plays_regardless_of_affordance(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "main"
            display.core.set_field_for_tests("now_playing", None)
            display.core.set_field_for_tests("idle_affordance", False)
            assert display._idle_chassis_due_locked() is True
            display.core.set_field_for_tests("idle_affordance", True)
            assert display._idle_chassis_due_locked() is True


# ---------------------------------------------------------------------------
# The idle affordance: the repaint a change of it asks for.
# ---------------------------------------------------------------------------

class TestIdleAffordanceRepaintSignal:
    def _roster_row(self, aid, auth="authorized", repeat_capable=True):
        from dial_test_support import RosterEntry
        return RosterEntry(
            appliance_id=aid, service_name="Kitchen", name="Kitchen", ip="10.0.0.9", port=8080,
            playing=False, repeat_capable=repeat_capable, auth=auth,
        )
    def test_change_signals_overlay(self):
        aid = "5" * 20
        display, fb, gt = make_display(targets=[], roster=[self._roster_row(aid)])
        display.enable()
        now = time.monotonic()
        seed_repeat(aid, _repeat_obj(state="hold"))
        display._overlay_signal.clear()
        display.fold_for_tests()
        assert display.core.snapshot().idle_affordance is True
        assert display._overlay_signal.is_set()
        display._overlay_signal.clear()
        display.fold_for_tests()
        assert not display._overlay_signal.is_set()


# ---------------------------------------------------------------------------
# The Wi-Fi link state machine: the idle icon and the No-WiFi warning driven
# by dial_network's poller callback (the warning is reached from the bell; see
# test_dial_display_warnings.py).
# ---------------------------------------------------------------------------

class TestNoWifiStateMachine:
    def _idle_display(self, connected=True):
        return idle_display(connected)

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
        display.fire_timer_for_tests("wifi_flash")
        assert not display._overlay_signal.is_set()
        on_network_view(display, _view(LINK_DOWN))
        display._overlay_signal.clear()
        display.fire_timer_for_tests("wifi_flash")
        assert display._overlay_signal.is_set()

    def test_no_flash_off_the_idle_screen(self):
        display, fb = self._idle_display()
        on_network_view(display, _view(LINK_DOWN))
        with patch("dial_display.threading.Thread"):
            display.open_info()
        _fold(display)
        assert display._screen == "info"
        assert display._wifi_flashing() is False

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

    def test_unknown_does_not_reset_or_advance_the_streak(self):
        display, fb = self._idle_display()
        on_network_view(display, _view(LINK_DOWN))
        on_network_view(display, _view(LINK_DOWN))
        on_network_view(display, _view(LINK_UNKNOWN))
        assert display.core._state.wifi_down_streak == 2
        assert not display.core.warnings.is_active("nowifi")
        on_network_view(display, _view(LINK_DOWN))
        assert display.core.warnings.is_active("nowifi")

    def test_a_streak_of_three_activates_the_warning_and_opens_nothing(self):
        display, fb = self._idle_display()
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        assert display.core.warnings.is_active("nowifi")
        assert display._screen_request is None
        _fold(display)
        assert display._screen == "main" and display._warning_screen is None

    def test_the_glyph_tap_is_the_info_page_and_never_the_warning(self):
        display, fb = self._idle_display()
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        with patch("dial_display.threading.Thread"):
            display.open_info()
        assert display._screen_request == "info"

    def test_callback_never_raises(self):
        display, fb = self._idle_display()
        on_network_view(display, object())        # no .link attribute
        on_network_view(display, None)


class TestIdentifiedWithoutArtwork:
    """A track identified without artwork keeps the logo on the panel; its
    title and artist are drawn over it from the core's now-playing line."""

    def test_the_logo_stays_up_and_no_artwork_is_shown(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        no_art = _track_id(title="Song", artist="The Artist", album="LP", artwork_url="")
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=no_art)), \
                patch.object(display, "_show_artwork") as show_artwork:
            display.fold_for_tests()
        show_artwork.assert_not_called()
        assert display.get_status()["showing"] == "logo"


class TestAsleepIdleTouchDoesNotPressAnything:
    """Real display plus real touch state machine: the touch that wakes a
    sleeping idle screen must not open the replay picker; the next one does."""

    def _tap(self, display, sm, xy, now):
        import dial_touch as dt
        from dial_touch_filter import TouchEvent, TouchEventType

        sm.set_surface(*display.touch_surface(), now)
        actions = sm.on_filter_event(TouchEvent(TouchEventType.PRESS, xy[0], xy[1]), now)
        for a in actions:
            if a.kind == dt.ACTION_WAKE:
                display.notify_touch_activity()
            elif a.kind == dt.ACTION_ZONE_TAP and a.zone == TouchZone.IDLE_REPLAY:
                display.open_picker()
        sm.on_filter_event(TouchEvent(TouchEventType.RELEASE, xy[0], xy[1]), now + 0.05)
        return actions

    def test_waking_touch_does_not_open_the_picker_next_touch_does(self):
        import dial_touch as dt

        display, fb, gt = make_display(targets=[])
        display.enable()
        display.core.set_field_for_tests("idle_affordance", True)
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
