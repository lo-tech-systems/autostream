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

import sys
import threading
import time
import urllib.error
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

from dial_config import DialDisplayConfig
from dial_display_compositor import OverlayState
from dial_display_profiles import DEFAULT_PROFILE_KEY, get_profile
from dial_mdns import PlayingTarget
from dial_touch_layout import TouchZone
import dial_display as dd
from dial_display import (
    DialDisplay,
    DisplayBackend,
    NoOpBackend,
    _fetch_artwork,
    artwork_url_eligible,
    create_dial_display,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _target(
    name="Kitchen", ip="192.168.1.10", port=80,
    dial_status=True, display_authorized=True,
    service_name=None, playing_since=100.0,
) -> PlayingTarget:
    return PlayingTarget(
        ip=ip, port=port, name=name,
        dial_api=True, audio_status=True, dial_status=dial_status,
        service_name=service_name or name,
        playing_since=playing_since,
        display_authorized=display_authorized,
    )


def _track_id(**overrides) -> dict:
    base = {
        "enabled": True, "state": "identified",
        "title": "Song", "artist": "Artist", "album": "Album",
        "artwork_url": "https://provider.example/x.jpg",
        "updated_at": 1.0, "last_attempt_at": 1.0,
    }
    base.update(overrides)
    return base


def _status_result(track_id=None, status_error=None) -> dict:
    return {
        "playing": True, "master_volume": 50, "selected_output_count": 1,
        "track_id": track_id, "status_error": status_error,
    }


_TEST_LOGO_PATH = str(REPO_ROOT / "images" / "autostream-logo-centred-dark.png")


class FakeBackend:
    name = "fake"
    width = 128
    height = 160

    def __init__(self, fail_open=False, fail_display=False, fail_sleep=False):
        self.fail_open = fail_open
        self.fail_display = fail_display
        self.fail_sleep = fail_sleep
        self.opened = False
        self.closed = False
        self.cleared = False
        self.displayed: list = []
        self.sleep_calls = 0
        self.wake_calls = 0

    def open(self):
        if self.fail_open:
            raise RuntimeError("open failed")
        self.opened = True

    def close(self):
        self.closed = True
        self.opened = False

    def clear(self):
        self.cleared = True

    def display(self, image):
        if self.fail_display:
            raise RuntimeError("display failed")
        self.displayed.append(image)

    def sleep(self):
        self.sleep_calls += 1
        if self.fail_sleep:
            raise RuntimeError("sleep failed")

    def wake(self):
        self.wake_calls += 1


def _make_display(
    fitted=True, rotate=False, bgr=False, screen_type=DEFAULT_PROFILE_KEY,
    targets=None, backend=None,
    get_targets=None, mark_unauthorized=None,
    backend_factory_builder=None,
) -> tuple[DialDisplay, FakeBackend, MagicMock, MagicMock]:
    cfg = DialDisplayConfig(fitted=fitted, rotate=rotate, bgr=bgr, screen_type=screen_type)
    fb = backend or FakeBackend()
    gt = get_targets or MagicMock(return_value=targets or [])
    mu = mark_unauthorized or MagicMock()
    display = DialDisplay(
        config=cfg,
        get_display_targets=gt,
        mark_display_target_unauthorized=mu,
        dial_id="dial-uuid",
        logo_path=_TEST_LOGO_PATH,
        backend_factory=lambda: fb,
        backend_factory_builder=backend_factory_builder,
    )
    return display, fb, gt, mu


# ---------------------------------------------------------------------------
# Disabled config / no-op behavior
# ---------------------------------------------------------------------------

class TestDisabledConfig:
    def test_disabled_backend_never_opens(self):
        display, fb, gt, mu = _make_display(fitted=False)
        display.start()
        display.stop()
        assert fb.opened is False

    def test_disabled_status_shape(self):
        display, fb, gt, mu = _make_display(fitted=False)
        status = display.get_status()
        # screen_type is the ACTIVE profile, so it is empty while the display
        # is off — the configured key still reads back from GET /screen/settings.
        assert status == {
            "fitted": False, "rotate": False, "screen_type": "",
            "bgr": False, "active": False, "backend": "noop",
            "backend_loaded": False, "showing": "noop",
            "last_error": "", "last_error_at": None,
            "display_sleeping": False, "display_idle_seconds": 0,
        }

    def test_disabled_poll_does_not_query_targets(self):
        display, fb, gt, mu = _make_display(fitted=False)
        display._poll_once()
        gt.assert_not_called()


# ---------------------------------------------------------------------------
# Target selection / fallback
# ---------------------------------------------------------------------------

class TestTargetSelectionFallback:
    def test_no_targets_shows_logo(self):
        display, fb, gt, mu = _make_display(targets=[])
        display.enable()
        display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_unauthorized_target_suppressed_shows_logo(self):
        t = _target(display_authorized=False)
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status") as mock_fetch:
            display._poll_once()
        mock_fetch.assert_not_called()
        assert display.get_status()["showing"] == "logo"

    def test_unsupported_target_skipped(self):
        t = _target(dial_status=False)
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status") as mock_fetch:
            display._poll_once()
        mock_fetch.assert_not_called()
        assert display.get_status()["showing"] == "logo"

    def test_missing_track_id_treated_as_no_artwork(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_omitted_artwork_url_treated_as_no_artwork(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=_track_id(artwork_url=""))
        with patch("dial_display.fetch_target_status", return_value=result):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_non_identified_state_treated_as_no_artwork(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=_track_id(state="analysing"))
        with patch("dial_display.fetch_target_status", return_value=result):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_unauthorized_status_error_marks_target(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(status_error="unauthorized")):
            display._poll_once()
        mu.assert_called_once_with(t)

    def test_other_status_error_skips_without_marking(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(status_error="timeout")):
            display._poll_once()
        mu.assert_not_called()
        assert display.get_status()["showing"] == "logo"

    def test_oldest_playing_target_stickiness_uses_target_order(self):
        """DialDisplay must iterate targets in the order get_display_targets() returns
        (oldest playing_since first) and stop at the first usable source."""
        t1 = _target(name="Older", playing_since=10.0)
        t2 = _target(name="Newer", playing_since=20.0)
        display, fb, gt, mu = _make_display(targets=[t1, t2])
        display.enable()

        calls = []

        def fake_fetch(target, dial_id, timeout_seconds):
            calls.append(target.name)
            return _status_result(track_id=_track_id())

        with patch("dial_display.fetch_target_status", side_effect=fake_fetch):
            display._poll_once()
        assert calls == ["Older"], "must stop polling after the first usable artwork source"

    def test_later_target_skipped_after_first_usable_artwork(self):
        t1 = _target(name="First", playing_since=10.0)
        t2 = _target(name="Second", playing_since=20.0)
        display, fb, gt, mu = _make_display(targets=[t1, t2])
        display.enable()

        calls = []

        def fake_fetch(target, dial_id, timeout_seconds):
            calls.append(target.name)
            if target.name == "First":
                return _status_result(track_id=_track_id())
            return _status_result(track_id=_track_id())

        with patch("dial_display.fetch_target_status", side_effect=fake_fetch):
            display._poll_once()
        assert calls == ["First"]

    def test_uses_single_target_helper_not_enrich_targets(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_target_status.enrich_targets") as mock_enrich, \
             patch("dial_display.fetch_target_status", return_value=_status_result()):
            display._poll_once()
        mock_enrich.assert_not_called()

    def test_fetch_target_status_called_with_dial_status_timeout(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result()) as mock_fetch:
            display._poll_once()
        _, kwargs = mock_fetch.call_args
        assert mock_fetch.call_args[0][0] is t
        assert mock_fetch.call_args[0][1] == "dial-uuid"
        assert kwargs["timeout_seconds"] == dd.DIAL_STATUS_TIMEOUT_SECONDS


# Artwork URL eligibility and fetching now live in core/autostream_artwork.py,
# shared with the OwnTone metadata publisher; their tests moved to test_artwork.py.


# ---------------------------------------------------------------------------
# End-to-end artwork rendering via DialDisplay
# ---------------------------------------------------------------------------

class TestArtworkRendering:
    def test_successful_artwork_fetch_renders_and_dedupes(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        fb.displayed.clear()

        fake_image = Image.new("RGB", (128, 160))
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")) as mock_fetch_art, \
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
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"bad", "")), \
             patch("dial_display.decode_artwork", return_value=None):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"
        assert display.get_status()["last_error"] == "artwork_decode_failed"

    def test_fetch_failure_falls_back_to_logo(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(None, "oversized")):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"
        assert display.get_status()["last_error"] == "artwork_fetch_failed"

    def test_ineligible_url_falls_back_to_logo_without_fetching(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=_track_id(artwork_url="http://provider.example/a.jpg"))
        with patch("dial_display.fetch_target_status", return_value=result), \
             patch("dial_display._fetch_artwork") as mock_fetch_art:
            display._poll_once()
        mock_fetch_art.assert_not_called()
        assert display.get_status()["showing"] == "logo"


# ---------------------------------------------------------------------------
# Logo fallback
# ---------------------------------------------------------------------------

class TestLogoFallback:
    def test_logo_fallback_when_no_targets_visible(self):
        display, fb, gt, mu = _make_display(targets=[])
        display.enable()
        display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_logo_fallback_while_playing_with_no_artwork(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_missing_logo_file_is_non_fatal(self):
        display, fb, gt, mu = _make_display(targets=[])
        display._logo_path = "/nonexistent/path/does-not-exist.png"
        display.enable()
        status = display.get_status()
        assert status["last_error"] == "logo_unavailable"
        assert status["showing"] in ("logo", "noop")


# ---------------------------------------------------------------------------
# Idle sleep — 15 minutes of no playing targets dims the display; any
# playing target (including unauthorized/erroring ones) counts as activity.
# ---------------------------------------------------------------------------

class _FakeClock:
    """Controllable stand-in for time.monotonic — advanced explicitly between
    polls so idle-elapsed math is deterministic instead of racing wall time.
    """

    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t


class TestIdleSleep:
    def test_no_targets_starts_idle_timer_and_shows_logo(self):
        display, fb, gt, mu = _make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch("dial_display.time.monotonic", clock):
            display._poll_once()
            clock.t += 5.0
            status = display.get_status()
        assert status["showing"] == "logo"
        assert status["display_idle_seconds"] == 5

    def test_idle_below_threshold_does_not_sleep(self):
        display, fb, gt, mu = _make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch("dial_display.time.monotonic", clock):
            display._poll_once()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS - 1
            display._poll_once()
            status = display.get_status()
        assert status["display_sleeping"] is False
        assert fb.sleep_calls == 0

    def test_idle_at_threshold_sleeps_once(self):
        display, fb, gt, mu = _make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch("dial_display.time.monotonic", clock):
            display._poll_once()  # idle timer starts
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display._poll_once()  # crosses threshold -> sleep
            display._poll_once()  # still asleep -> no repeat sleep call
            status = display.get_status()
        assert status["display_sleeping"] is True
        assert status["showing"] == "sleeping"
        assert fb.sleep_calls == 1

    def test_sleeping_does_not_repaint(self):
        display, fb, gt, mu = _make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch("dial_display.time.monotonic", clock):
            display._poll_once()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display._poll_once()
            count_after_sleep = len(fb.displayed)
            display._poll_once()
            display._poll_once()
        assert len(fb.displayed) == count_after_sleep

    def test_idle_seconds_clamps_at_threshold_while_asleep(self):
        display, fb, gt, mu = _make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch("dial_display.time.monotonic", clock):
            display._poll_once()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display._poll_once()
            clock.t += 1000.0  # long past threshold while asleep
            status = display.get_status()
        assert status["display_idle_seconds"] == dd.DISPLAY_IDLE_SLEEP_SECONDS

    def test_target_appearing_wakes_before_next_frame(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch("dial_display.time.monotonic", clock):
            display._poll_once()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display._poll_once()  # asleep now
            assert display.get_status()["display_sleeping"] is True

            gt.return_value = [t]
            with patch("dial_display.fetch_target_status",
                       return_value=_status_result(track_id=None)):
                display._poll_once()
            status = display.get_status()

        assert fb.wake_calls == 1
        assert status["display_sleeping"] is False
        assert status["display_idle_seconds"] == 0
        assert status["showing"] == "logo"

    def test_wake_repaints_same_artwork_url_as_before_sleep(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()

        fake_image = Image.new("RGB", (128, 160))
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()  # showing artwork
        assert display.get_status()["showing"] == "artwork"

        gt.return_value = []
        clock = _FakeClock()
        with patch("dial_display.time.monotonic", clock):
            display._poll_once()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display._poll_once()  # asleep
        assert display.get_status()["display_sleeping"] is True

        gt.return_value = [t]
        displayed_before = len(fb.displayed)
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()  # wakes and repaints same artwork url

        assert fb.wake_calls == 1
        assert display.get_status()["display_sleeping"] is False
        assert display.get_status()["showing"] == "artwork"
        assert len(fb.displayed) > displayed_before

    def test_playing_target_no_artwork_never_sleeps(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        clock = _FakeClock()
        with patch("dial_display.time.monotonic", clock), \
             patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            for _ in range(5):
                display._poll_once()
                clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            status = display.get_status()
        assert status["showing"] == "logo"
        assert status["display_sleeping"] is False
        assert status["display_idle_seconds"] == 0
        assert fb.sleep_calls == 0

    def test_unauthorized_target_present_counts_as_activity(self):
        t = _target(display_authorized=False)
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        clock = _FakeClock()
        with patch("dial_display.time.monotonic", clock):
            for _ in range(5):
                display._poll_once()
                clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            status = display.get_status()
        assert status["display_sleeping"] is False
        assert status["display_idle_seconds"] == 0
        assert fb.sleep_calls == 0

    def test_disable_while_asleep_resets_idle_and_sleep_state(self):
        display, fb, gt, mu = _make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch("dial_display.time.monotonic", clock):
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
        display, _, gt, mu = _make_display(backend=fb)
        display.enable()
        status = display.get_status()
        assert status["backend_loaded"] is False
        assert status["showing"] == "noop"
        assert status["last_error"] == "backend_open_failed"

    def test_backend_display_failure_is_non_fatal(self):
        fb = FakeBackend(fail_display=True)
        display, _, gt, mu = _make_display(backend=fb)
        display.enable()  # logo render will fail silently at backend level
        status = display.get_status()
        assert status["last_error"] == "display_write_failed"

    def test_disabled_config_never_touches_backend(self):
        fb = FakeBackend()
        display, _, gt, mu = _make_display(fitted=False, backend=fb)
        display.update_config(DialDisplayConfig(fitted=False))
        assert fb.opened is False


# ---------------------------------------------------------------------------
# update_config live apply
# ---------------------------------------------------------------------------

class TestUpdateConfig:
    def test_enable_via_update_config_opens_backend(self):
        display, fb, gt, mu = _make_display(fitted=False)
        status = display.update_config(DialDisplayConfig(fitted=True))
        assert fb.opened is True
        assert status["backend_loaded"] is True

    def test_disable_via_update_config_closes_backend(self):
        display, fb, gt, mu = _make_display(fitted=True)
        display.enable()
        assert fb.opened is True
        status = display.update_config(DialDisplayConfig(fitted=False))
        assert fb.closed is True
        assert status["showing"] == "noop"


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

        display, _, gt, mu = _make_display(
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

        display, _, gt, mu = _make_display(
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
        display, _, gt, mu = _make_display(
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

        display, _, gt, mu = _make_display(
            fitted=True, targets=[t], screen_type="st7735s_160x128", backend=fb_old,
            backend_factory_builder=self._swap_builder(fb_old, fb_new),
        )
        display.enable()

        fake_image = _marked_image(size=(fb_old.width, fb_old.height))
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()
        assert display.get_status()["showing"] == "artwork"
        assert display._current_rendered_image is not None

        display.update_config(DialDisplayConfig(fitted=True, screen_type="st7789_240x240"))

        assert display._current_rendered_image is None
        assert display._source_artwork_url == ""
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

        display, _, gt, mu = _make_display(
            fitted=True, targets=[t], screen_type="st7735s_160x128", rotate=False,
            backend=fb_old, backend_factory_builder=self._swap_builder(fb_old, fb_new),
        )
        display.enable()

        fake_image = _marked_image(size=(fb_old.width, fb_old.height))
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
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

        display, _, gt, mu = _make_display(
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
        display, fb, gt, mu = _make_display(fitted=True, screen_type="st7789_240x240", bgr=True)
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
        display, _, gt, mu = _make_display(fitted=True, backend=fb)
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
        img = _marked_image()

        display_off, fb_off, _, _ = _make_display(rotate=False)
        display_off.enable()
        fb_off.displayed.clear()
        display_off.display(img)

        display_on, fb_on, _, _ = _make_display(rotate=True)
        display_on.enable()
        fb_on.displayed.clear()
        display_on.display(img)

        expected = img.transpose(Image.ROTATE_180)
        assert list(fb_off.displayed[-1].getdata()) == list(img.getdata())
        assert list(fb_on.displayed[-1].getdata()) == list(expected.getdata())

    def test_rotate_toggle_via_update_config_redisplays_synchronously(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t], fitted=True, rotate=False)
        display.enable()

        fake_image = _marked_image(size=(fb.width, fb.height))
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
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
        display, fb, gt, mu = _make_display(targets=[t], fitted=True, rotate=True)
        display.enable()

        fake_image = _marked_image(size=(fb.width, fb.height))
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()

        assert list(display._current_rendered_image.getdata()) == list(fake_image.getdata())

    def test_get_status_includes_rotate(self):
        display, fb, gt, mu = _make_display(fitted=True, rotate=True)
        display.enable()
        assert display.get_status()["rotate"] is True


# ---------------------------------------------------------------------------
# BGR colour-order toggle — applied manager-side at display hand-off,
# alongside (and composing with) rotate; cache stays untransformed.
# ---------------------------------------------------------------------------

class TestBgr:
    def test_bgr_true_swaps_channels_before_backend_display(self):
        img = _marked_image()

        display_off, fb_off, _, _ = _make_display(bgr=False)
        display_off.enable()
        fb_off.displayed.clear()
        display_off.display(img)

        display_on, fb_on, _, _ = _make_display(bgr=True)
        display_on.enable()
        fb_on.displayed.clear()
        display_on.display(img)

        expected = Image.merge("RGB", img.split()[::-1])
        assert list(fb_off.displayed[-1].getdata()) == list(img.getdata())
        assert list(fb_on.displayed[-1].getdata()) == list(expected.getdata())

    def test_rotate_and_bgr_compose_together(self):
        img = _marked_image()

        display, fb, _, _ = _make_display(rotate=True, bgr=True)
        display.enable()
        fb.displayed.clear()
        display.display(img)

        expected = img.transpose(Image.ROTATE_180)
        expected = Image.merge("RGB", expected.split()[::-1])
        assert list(fb.displayed[-1].getdata()) == list(expected.getdata())

    def test_bgr_toggle_via_update_config_redisplays_synchronously(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t], fitted=True, bgr=False)
        display.enable()

        fake_image = _marked_image(size=(fb.width, fb.height))
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
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
        display, fb, gt, mu = _make_display(targets=[t], fitted=True, bgr=True)
        display.enable()

        fake_image = _marked_image(size=(fb.width, fb.height))
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()

        assert list(display._current_rendered_image.getdata()) == list(fake_image.getdata())

    def test_get_status_includes_bgr(self):
        display, fb, gt, mu = _make_display(fitted=True, bgr=True)
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
        display, _, gt, mu = _make_display(targets=[t], backend=fb)
        display.enable()
        fb.displayed.clear()

        # transform_artwork_for_panel is mocked to return an image sized for
        # a DIFFERENT backend than the one now open — simulating a
        # screen_type swap that raced with the unlocked fetch/decode/
        # transform stretch in _show_artwork().
        stale_sized_image = Image.new("RGB", (160, 128))
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=Image.new("RGB", (300, 300))), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=stale_sized_image):
            display._poll_once()

        assert fb.displayed == []
        assert display.get_status()["showing"] != "artwork"
        assert display._current_rendered_image is None


# ---------------------------------------------------------------------------
# Threading: start/stop and loop delay from loop end
# ---------------------------------------------------------------------------

class TestThreadingLifecycle:
    def test_start_stop_clean_shutdown(self):
        display, fb, gt, mu = _make_display(targets=[])
        display.start()
        time.sleep(0.05)
        display.stop()
        assert fb.closed is True
        assert display._thread is not None
        assert not display._thread.is_alive()

    def test_loop_waits_full_interval_after_poll_completes(self):
        display, fb, gt, mu = _make_display(targets=[])
        wait_calls = []

        def tracking_wait(timeout=None):
            wait_calls.append(timeout)
            display._stop_event.set()  # end the loop after the first wait
            return True

        with patch.object(display, "_poll_once") as mock_poll, \
             patch.object(display._stop_event, "wait", side_effect=tracking_wait):
            display._run()

        mock_poll.assert_called_once()
        assert wait_calls == [dd.DISPLAY_POLL_INTERVAL_SECONDS]

    def test_stop_is_idempotent(self):
        display, fb, gt, mu = _make_display(targets=[])
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
        gt = MagicMock()
        mu = MagicMock()
        display = create_dial_display(cfg, gt, mu)
        assert isinstance(display, DialDisplay)
        assert display._dial_id == "abc123"
        assert display._config is cfg.display

    def test_factory_uses_noop_backend(self):
        cfg = MagicMock()
        cfg.display = DialDisplayConfig(fitted=True)
        cfg.uuid = "abc123"
        display = create_dial_display(cfg, MagicMock(), MagicMock())
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
        display, fb, gt, mu = _make_display(targets=[])
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
        display, _, gt, mu = _make_display(targets=[t], backend=fb)
        display.enable()
        fb.displayed.clear()

        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=Image.new("RGB", (300, 300))):
            display._poll_once()

        assert display.get_status()["showing"] == "artwork"
        assert fb.displayed[-1].size == (240, 240)

    def test_logo_frame_handed_to_backend_matches_active_backend_dims(self):
        fb = FakeBackend()
        fb.width = 240
        fb.height = 200
        display, _, gt, mu = _make_display(targets=[], backend=fb)
        display.enable()  # renders the logo immediately

        assert fb.displayed
        assert fb.displayed[-1].size == (240, 200)


# ---------------------------------------------------------------------------
# Touch activity notification — mirrors the two lines _poll_once() already
# runs when it finds playing targets present.
# ---------------------------------------------------------------------------

class TestNotifyTouchActivity:
    def test_resets_idle_timer(self):
        display, fb, gt, mu = _make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch("dial_display.time.monotonic", clock):
            display._poll_once()  # idle timer starts (no targets)
            clock.t += 5.0
            assert display.get_status()["display_idle_seconds"] == 5
            display.notify_touch_activity()
            assert display._idle_started_at is None
            assert display.get_status()["display_idle_seconds"] == 0

    def test_wakes_a_sleeping_display(self):
        display, fb, gt, mu = _make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch("dial_display.time.monotonic", clock):
            display._poll_once()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display._poll_once()  # asleep now
        assert display.get_status()["display_sleeping"] is True

        display.notify_touch_activity()

        assert display.get_status()["display_sleeping"] is False
        assert fb.wake_calls == 1

    def test_does_not_disable_future_sleep_only_resets_it(self):
        """Touch resets idle, it does not disable sleep — with nothing
        playing, the next poll tick restarts the idle countdown from the
        point of the touch activity."""
        display, fb, gt, mu = _make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch("dial_display.time.monotonic", clock):
            display._poll_once()
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS - 1
            display.notify_touch_activity()
            display._poll_once()  # restarts the idle timer from here
            clock.t += dd.DISPLAY_IDLE_SLEEP_SECONDS
            display._poll_once()  # crosses threshold again -> sleeps
        assert display.get_status()["display_sleeping"] is True


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
        display, fb, gt, mu = _make_display(targets=[])
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

    def test_rapid_signals_coalesce_to_one_repaint_of_newest_snapshot(self):
        display, fb, gt, mu = _make_display(targets=[])
        display.enable()

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
                # Several rapid signals before the repaint thread gets a
                # chance to wake — must coalesce into exactly one repaint,
                # of the LAST (newest) snapshot published.
                for zone in (TouchZone.MUTE, TouchZone.DOWN, TouchZone.UP):
                    display.set_overlay(OverlayState(visible=True, pressed=zone))

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
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        display.set_overlay(OverlayState(visible=True, pressed=TouchZone.UP))

        fake_image = Image.new("RGB", (128, 160))
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
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
        display, fb, gt, mu = _make_display(targets=[])
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
        display, fb, gt, mu = _make_display(targets=[])
        display.enable()
        gen_before = display.noncomposited_generation()
        display._noncomposited_event.clear()

        with display._lock:
            display._clear_locked()

        assert display.noncomposited_generation() == gen_before + 1
        assert display._noncomposited_event.is_set()

    def test_sleep_locked_bumps_generation_and_sets_event(self):
        display, fb, gt, mu = _make_display(targets=[])
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
        display, fb, gt, mu = _make_display(targets=[])
        display.enable()
        assert not hasattr(display, "_touch_source")
        assert not hasattr(display, "_touch_callback")

        with display._lock:
            display._mark_noncomposited_locked()
            display._mark_noncomposited_locked()

        assert display.noncomposited_generation() == 2
