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

import dial_auth
from dial_config import DialDisplayConfig
from dial_display_compositor import OverlayState
from dial_display_profiles import DEFAULT_PROFILE_KEY, get_profile
from dial_mdns import PlayingTarget
from dial_touch_layout import TouchZone, list_layout_for
import dial_display as dd
from dial_display import (
    SELECTOR_TIMEOUT_SECONDS,
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
    dial_status=True, appliance_id="", auth="unknown",
    service_name=None, playing_since=100.0,
) -> PlayingTarget:
    return PlayingTarget(
        ip=ip, port=port, name=name,
        dial_api=True, audio_status=True, dial_status=dial_status,
        service_name=service_name or name,
        playing_since=playing_since,
        appliance_id=appliance_id,
        auth=auth,
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


def _status_result(track_id=None, status_error=None, appliance_id=None) -> dict:
    return {
        "playing": True, "master_volume": 50, "selected_output_count": 1,
        "track_id": track_id, "status_error": status_error,
        "appliance_id": appliance_id,
    }


def _repeat_obj(**overrides) -> dict:
    base = {
        "available": True, "state": "hold", "armed": False, "held": True,
        "recording_seconds": 30.0,
        "replay": {"active": False, "position_seconds": 0.0, "duration_seconds": 30.0},
    }
    base.update(overrides)
    return base


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


def _roster_from_targets(targets) -> list:
    """Default get_roster() stand-in for _make_display(): a RosterEntry per
    identity-carrying target, mirroring dial_mdns.get_roster()'s own "no id,
    never rostered" rule. Built fresh from whatever *targets* currently
    holds each time it is called (see _make_display's lambda below), so
    tests that mutate get_targets.return_value after construction (e.g. to
    simulate a re-poll) see a consistent roster without wiring get_roster
    explicitly."""
    from dial_mdns import RosterEntry
    return [
        RosterEntry(
            appliance_id=t.appliance_id, service_name=t.service_name, name=t.name,
            ip=t.ip, port=t.port, playing=True, repeat_capable=False,
            dial_api=t.dial_api, audio_status=t.audio_status, dial_status=t.dial_status,
            auth=t.auth,
        )
        for t in targets if t.appliance_id
    ]


def _make_display(
    fitted=True, rotate=False, bgr=False, screen_type=DEFAULT_PROFILE_KEY,
    always_show_controls=False,
    targets=None, backend=None,
    get_targets=None,
    get_roster=None,
    backend_factory_builder=None,
) -> tuple[DialDisplay, FakeBackend, MagicMock]:
    cfg = DialDisplayConfig(
        fitted=fitted, rotate=rotate, bgr=bgr, screen_type=screen_type,
        always_show_controls=always_show_controls,
    )
    fb = backend or FakeBackend()
    gt = get_targets or MagicMock(return_value=targets or [])
    gr = get_roster or (lambda: _roster_from_targets(gt()))
    display = DialDisplay(
        config=cfg,
        get_display_targets=gt,
        dial_id="dial-uuid",
        logo_path=_TEST_LOGO_PATH,
        backend_factory=lambda: fb,
        backend_factory_builder=backend_factory_builder,
        get_roster=gr,
    )
    return display, fb, gt


# ---------------------------------------------------------------------------
# Disabled config / no-op behavior
# ---------------------------------------------------------------------------

class TestDisabledConfig:
    def test_disabled_backend_never_opens(self):
        display, fb, gt = _make_display(fitted=False)
        display.start()
        display.stop()
        assert fb.opened is False

    def test_disabled_status_shape(self):
        display, fb, gt = _make_display(fitted=False)
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
        display, fb, gt = _make_display(fitted=False)
        display._poll_once()
        gt.assert_not_called()


# ---------------------------------------------------------------------------
# Target selection / fallback
# ---------------------------------------------------------------------------

class TestTargetSelectionFallback:
    def test_no_targets_shows_logo(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_unauthorized_target_suppressed_shows_logo(self):
        t = _target(auth="unauthorized")
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status") as mock_fetch:
            display._poll_once()
        mock_fetch.assert_not_called()
        assert display.get_status()["showing"] == "logo"

    def test_unsupported_target_skipped(self):
        t = _target(dial_status=False)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status") as mock_fetch:
            display._poll_once()
        mock_fetch.assert_not_called()
        assert display.get_status()["showing"] == "logo"

    def test_missing_track_id_treated_as_no_artwork(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_omitted_artwork_url_treated_as_no_artwork(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=_track_id(artwork_url=""))
        with patch("dial_display.fetch_target_status", return_value=result):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_non_identified_state_treated_as_no_artwork(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=_track_id(state="analysing"))
        with patch("dial_display.fetch_target_status", return_value=result):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_unauthorized_status_error_marks_target(self):
        aid = "a" * 20
        t = _target(appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(status_error="unauthorized", appliance_id=aid)):
            display._poll_once()
        assert dial_auth.auth_map.state(aid) == dial_auth.AUTH_UNAUTHORIZED

    def test_other_status_error_skips_without_marking(self):
        aid = "b" * 20
        t = _target(appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(status_error="timeout", appliance_id=aid)):
            display._poll_once()
        assert dial_auth.auth_map.state(aid) == dial_auth.AUTH_UNKNOWN
        assert display.get_status()["showing"] == "logo"

    def test_oldest_playing_target_stickiness_uses_target_order(self):
        """DialDisplay must iterate targets in the order get_display_targets() returns
        (oldest playing_since first) and stop at the first usable source."""
        t1 = _target(name="Older", playing_since=10.0)
        t2 = _target(name="Newer", playing_since=20.0)
        display, fb, gt = _make_display(targets=[t1, t2])
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
        display, fb, gt = _make_display(targets=[t1, t2])
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
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_target_status.enrich_targets") as mock_enrich, \
             patch("dial_display.fetch_target_status", return_value=_status_result()):
            display._poll_once()
        mock_enrich.assert_not_called()

    def test_fetch_target_status_called_with_dial_status_timeout(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result()) as mock_fetch:
            display._poll_once()
        _, kwargs = mock_fetch.call_args
        assert mock_fetch.call_args[0][0] is t
        assert mock_fetch.call_args[0][1] == "dial-uuid"
        assert kwargs["timeout_seconds"] == dd.DIAL_STATUS_TIMEOUT_SECONDS


# ---------------------------------------------------------------------------
# dial mute belief: free reconciliation from the status poll.
# master_volume > 0 seen on ANY target during this poll is definitive proof
# the fleet is audible;
# master_volume == 0 proves nothing about the rest of the fleet and must
# never be used to force the belief to muted.
# ---------------------------------------------------------------------------

class TestMuteBeliefReconciliationFromStatusPoll:
    def test_positive_master_volume_notifies_the_mute_belief(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=None)) as _, \
             patch("dial_display.note_master_volume_positive") as mock_note:
            display._poll_once()
        mock_note.assert_called_once()

    def test_zero_master_volume_does_not_notify_the_mute_belief(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=None)
        result["master_volume"] = 0
        with patch("dial_display.fetch_target_status", return_value=result), \
             patch("dial_display.note_master_volume_positive") as mock_note:
            display._poll_once()
        mock_note.assert_not_called()

    def test_none_master_volume_does_not_notify_the_mute_belief(self):
        # selected_output_count == 0 legitimately carries master_volume=None.
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=None)
        result["master_volume"] = None
        result["selected_output_count"] = 0
        with patch("dial_display.fetch_target_status", return_value=result), \
             patch("dial_display.note_master_volume_positive") as mock_note:
            display._poll_once()
        mock_note.assert_not_called()

    def test_status_error_response_does_not_notify_the_mute_belief(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(status_error="timeout")), \
             patch("dial_display.note_master_volume_positive") as mock_note:
            display._poll_once()
        mock_note.assert_not_called()

    def test_positive_volume_on_a_non_reporting_target_does_not_notify(self):
        """Two targets, neither identified: the reporting-from target is the
        oldest-playing (first) one. A positive volume on the OTHER, non-
        reporting target must not notify the belief — restricting the
        observation to the reporting-from target (C.5) is what stops a
        mixed-fleet false "unmuted" belief once volume/mute address a
        single target."""
        t_reporting = _target(name="Older", service_name="older", playing_since=10.0)
        t_other = _target(name="Newer", service_name="newer", playing_since=20.0)
        display, fb, gt = _make_display(targets=[t_reporting, t_other])
        display.enable()

        def fake_fetch(target, dial_id, timeout_seconds):
            result = _status_result(track_id=None)
            result["master_volume"] = 0 if target.service_name == "older" else 50
            return result

        with patch("dial_display.fetch_target_status", side_effect=fake_fetch), \
             patch("dial_display.note_master_volume_positive") as mock_note:
            display._poll_once()
        mock_note.assert_not_called()

    def test_fallback_reporting_target_is_oldest_when_nothing_identified(self):
        """With nothing identified, the reporting-from target is
        select_volume_target()'s fallback: targets[0], the oldest-playing
        one — not whichever target the loop happens to process last."""
        t_older = _target(name="Older", service_name="older", playing_since=10.0)
        t_newer = _target(name="Newer", service_name="newer", playing_since=20.0)
        display, fb, gt = _make_display(targets=[t_older, t_newer])
        display.enable()

        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)), \
             patch("dial_display.observe_master_volume") as mock_observe:
            display._poll_once()

        assert mock_observe.call_args[0][0] == "older"

    def test_positive_master_volume_actually_clears_the_real_belief(self):
        """End-to-end against the real dial_volume module (not a mock of
        note_master_volume_positive) — proves the two modules are actually
        wired together, not just that dial_display calls a same-named stub.
        dial_display imports note_master_volume_positive directly from
        dial_volume, so setting/reading dv._muted here observes exactly the
        state that function mutates."""
        import dial_volume as dv
        original = dv._muted
        dv._muted = True  # simulate an existing mute belief
        try:
            t = _target()
            display, fb, gt = _make_display(targets=[t])
            display.enable()
            with patch("dial_display.fetch_target_status",
                       return_value=_status_result(track_id=None)):
                display._poll_once()
            assert dv.is_muted() is False
        finally:
            dv._muted = original


# ---------------------------------------------------------------------------
# Now-playing state and artwork-source exposure (A.4): the poll thread keeps
# title/artist/master_volume that used to be discarded, and exposes the
# chosen artwork source's service name so the volume worker's resolver can
# address it (see dial_main._build_volume_targets_fn).
# ---------------------------------------------------------------------------

class TestNowPlayingAndSource:
    def test_identified_target_sets_source_and_now_playing(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(artist="The Artist"))), \
             patch("dial_display.observe_master_volume") as mock_observe:
            display._poll_once()

        assert display.current_source_service_name() == t.service_name
        assert display._now_playing is not None
        assert display._now_playing.artist == "The Artist"
        assert display._now_playing.service_name == t.service_name
        # The reporting target's master_volume (from _status_result's
        # default of 50) reaches observe_master_volume.
        mock_observe.assert_called_once_with(t.service_name, 50)

    def test_no_targets_clears_source_and_now_playing(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())):
            display._poll_once()
        assert display.current_source_service_name() is not None

        gt.return_value = []
        with patch("dial_display.observe_master_volume") as mock_observe:
            display._poll_once()

        assert display.current_source_service_name() is None
        assert display._now_playing is None
        mock_observe.assert_called_once_with(None, None)

    def test_not_fitted_clears_source_and_now_playing(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())):
            display._poll_once()
        assert display.current_source_service_name() is not None

        with display._lock:
            display._config = DialDisplayConfig(fitted=False)
        display._poll_once()

        assert display.current_source_service_name() is None
        assert display._now_playing is None

    def test_now_playing_change_sets_overlay_signal(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        display._overlay_signal.clear()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())):
            display._poll_once()
        assert display._overlay_signal.is_set()


# Artwork URL eligibility and fetching now live in core/autostream_artwork.py,
# shared with the OwnTone metadata publisher; their tests moved to test_artwork.py.


# ---------------------------------------------------------------------------
# End-to-end artwork rendering via DialDisplay
# ---------------------------------------------------------------------------

class TestArtworkRendering:
    def test_successful_artwork_fetch_renders_and_dedupes(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
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
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"bad", "")), \
             patch("dial_display.decode_artwork", return_value=None):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"
        assert display.get_status()["last_error"] == "artwork_decode_failed"

    def test_fetch_failure_falls_back_to_logo(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(None, "oversized")):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"
        assert display.get_status()["last_error"] == "artwork_fetch_failed"

    def test_ineligible_url_falls_back_to_logo_without_fetching(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
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
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_logo_fallback_while_playing_with_no_artwork(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_missing_logo_file_is_non_fatal(self):
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch("dial_display.time.monotonic", clock):
            display._poll_once()
            clock.t += 5.0
            status = display.get_status()
        assert status["showing"] == "logo"
        assert status["display_idle_seconds"] == 5

    def test_idle_below_threshold_does_not_sleep(self):
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[t])
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
        display, fb, gt = _make_display(targets=[t])
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
        t = _target(auth="unauthorized")
        display, fb, gt = _make_display(targets=[t])
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
        display, fb, gt = _make_display(targets=[])
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
        display, _, gt = _make_display(backend=fb)
        display.enable()
        status = display.get_status()
        assert status["backend_loaded"] is False
        assert status["showing"] == "noop"
        assert status["last_error"] == "backend_open_failed"

    def test_backend_display_failure_is_non_fatal(self):
        fb = FakeBackend(fail_display=True)
        display, _, gt = _make_display(backend=fb)
        display.enable()  # logo render will fail silently at backend level
        status = display.get_status()
        assert status["last_error"] == "display_write_failed"

    def test_disabled_config_never_touches_backend(self):
        fb = FakeBackend()
        display, _, gt = _make_display(fitted=False, backend=fb)
        display.update_config(DialDisplayConfig(fitted=False))
        assert fb.opened is False


# ---------------------------------------------------------------------------
# update_config live apply
# ---------------------------------------------------------------------------

class TestUpdateConfig:
    def test_enable_via_update_config_opens_backend(self):
        display, fb, gt = _make_display(fitted=False)
        status = display.update_config(DialDisplayConfig(fitted=True))
        assert fb.opened is True
        assert status["backend_loaded"] is True

    def test_disable_via_update_config_closes_backend(self):
        display, fb, gt = _make_display(fitted=True)
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

        display, _, gt = _make_display(
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

        display, _, gt = _make_display(
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
        display, _, gt = _make_display(
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

        display, _, gt = _make_display(
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

        display, _, gt = _make_display(
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

        display, _, gt = _make_display(
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
        display, fb, gt = _make_display(fitted=True, screen_type="st7789_240x240", bgr=True)
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
        display, _, gt = _make_display(fitted=True, backend=fb)
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

        display_off, fb_off, _ = _make_display(rotate=False)
        display_off.enable()
        fb_off.displayed.clear()
        display_off.display(img)

        display_on, fb_on, _ = _make_display(rotate=True)
        display_on.enable()
        fb_on.displayed.clear()
        display_on.display(img)

        expected = img.transpose(Image.ROTATE_180)
        assert list(fb_off.displayed[-1].getdata()) == list(img.getdata())
        assert list(fb_on.displayed[-1].getdata()) == list(expected.getdata())

    def test_rotate_toggle_via_update_config_redisplays_synchronously(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t], fitted=True, rotate=False)
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
        display, fb, gt = _make_display(targets=[t], fitted=True, rotate=True)
        display.enable()

        fake_image = _marked_image(size=(fb.width, fb.height))
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()

        assert list(display._current_rendered_image.getdata()) == list(fake_image.getdata())

    def test_get_status_includes_rotate(self):
        display, fb, gt = _make_display(fitted=True, rotate=True)
        display.enable()
        assert display.get_status()["rotate"] is True


# ---------------------------------------------------------------------------
# BGR colour-order toggle — applied manager-side at display hand-off,
# alongside (and composing with) rotate; cache stays untransformed.
# ---------------------------------------------------------------------------

class TestBgr:
    def test_bgr_true_swaps_channels_before_backend_display(self):
        img = _marked_image()

        display_off, fb_off, _ = _make_display(bgr=False)
        display_off.enable()
        fb_off.displayed.clear()
        display_off.display(img)

        display_on, fb_on, _ = _make_display(bgr=True)
        display_on.enable()
        fb_on.displayed.clear()
        display_on.display(img)

        expected = Image.merge("RGB", img.split()[::-1])
        assert list(fb_off.displayed[-1].getdata()) == list(img.getdata())
        assert list(fb_on.displayed[-1].getdata()) == list(expected.getdata())

    def test_rotate_and_bgr_compose_together(self):
        img = _marked_image()

        display, fb, _ = _make_display(rotate=True, bgr=True)
        display.enable()
        fb.displayed.clear()
        display.display(img)

        expected = img.transpose(Image.ROTATE_180)
        expected = Image.merge("RGB", expected.split()[::-1])
        assert list(fb.displayed[-1].getdata()) == list(expected.getdata())

    def test_bgr_toggle_via_update_config_redisplays_synchronously(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t], fitted=True, bgr=False)
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
        display, fb, gt = _make_display(targets=[t], fitted=True, bgr=True)
        display.enable()

        fake_image = _marked_image(size=(fb.width, fb.height))
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()

        assert list(display._current_rendered_image.getdata()) == list(fake_image.getdata())

    def test_get_status_includes_bgr(self):
        display, fb, gt = _make_display(fitted=True, bgr=True)
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
        display, _, gt = _make_display(targets=[t], backend=fb)
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
        display, fb, gt = _make_display(targets=[])
        display.start()
        time.sleep(0.05)
        display.stop()
        assert fb.closed is True
        assert display._thread is not None
        assert not display._thread.is_alive()

    def test_loop_waits_full_interval_after_poll_completes(self):
        display, fb, gt = _make_display(targets=[])
        wait_calls = []

        def tracking_wait(timeout=None):
            wait_calls.append(timeout)
            display._stop_event.set()  # end the loop after the first wait
            return True

        with patch.object(display, "_poll_once") as mock_poll, \
             patch.object(display._poll_wake, "wait", side_effect=tracking_wait):
            display._run()

        mock_poll.assert_called_once()
        assert wait_calls == [dd.DISPLAY_POLL_INTERVAL_SECONDS]

    def test_stop_is_idempotent(self):
        display, fb, gt = _make_display(targets=[])
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
        display = create_dial_display(cfg, gt)
        assert isinstance(display, DialDisplay)
        assert display._dial_id == "abc123"
        assert display._config is cfg.display

    def test_factory_uses_noop_backend(self):
        cfg = MagicMock()
        cfg.display = DialDisplayConfig(fitted=True)
        cfg.uuid = "abc123"
        display = create_dial_display(cfg, MagicMock())
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
        display, fb, gt = _make_display(targets=[])
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
        display, _, gt = _make_display(targets=[t], backend=fb)
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
        display, _, gt = _make_display(targets=[], backend=fb)
        display.enable()  # renders the logo immediately

        assert fb.displayed
        assert fb.displayed[-1].size == (240, 200)


# ---------------------------------------------------------------------------
# Touch activity notification — mirrors the two lines _poll_once() already
# runs when it finds playing targets present.
# ---------------------------------------------------------------------------

class TestNotifyTouchActivity:
    def test_resets_idle_timer(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch("dial_display.time.monotonic", clock):
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
        display, fb, gt = _make_display(targets=[])
        display.enable()
        clock = _FakeClock()
        with patch("dial_display.time.monotonic", clock):
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
        display, fb, gt = _make_display(targets=[])
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
# _effective_overlay_locked(): merges now-playing state (artist, the
# optimistic volume readout, mute belief fallback) into the touch-published
# overlay snapshot at compose time (A.4).
# ---------------------------------------------------------------------------

class TestEffectiveOverlayMerge:
    def test_invisible_snapshot_is_returned_unchanged(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        snapshot = OverlayState(visible=False, pressed=TouchZone.UP)
        result = display._effective_overlay_locked(snapshot)
        assert result is snapshot

    def test_muted_none_is_filled_from_the_belief(self):
        import dial_volume as dv
        display, fb, gt = _make_display(targets=[])
        display.enable()
        original = dv._muted
        dv._muted = True
        try:
            result = display._effective_overlay_locked(OverlayState(visible=True))
            assert result.muted is True
        finally:
            dv._muted = original

    def test_explicit_muted_false_is_not_overridden_by_the_belief(self):
        import dial_volume as dv
        display, fb, gt = _make_display(targets=[])
        display.enable()
        original = dv._muted
        dv._muted = True  # belief says muted...
        try:
            # ...but the touch snapshot explicitly says otherwise, and wins.
            result = display._effective_overlay_locked(OverlayState(visible=True, muted=False))
            assert result.muted is False
        finally:
            dv._muted = original

    def test_explicit_muted_true_is_not_overridden_by_the_belief(self):
        import dial_volume as dv
        display, fb, gt = _make_display(targets=[])
        display.enable()
        original = dv._muted
        dv._muted = False
        try:
            result = display._effective_overlay_locked(OverlayState(visible=True, muted=True))
            assert result.muted is True
        finally:
            dv._muted = original

    def test_visible_snapshot_merges_artist_and_readout_volume(self):
        import dial_volume as dv
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._now_playing = dd.NowPlaying("svc", "The Artist", "Title", 50)
        dv.observe_master_volume("svc", 50)
        try:
            result = display._effective_overlay_locked(OverlayState(visible=True, muted=False))
            assert result.artist == "The Artist"
            assert result.title == "Title"
            assert result.volume == 50
        finally:
            dv.observe_master_volume(None, None)

    def test_no_now_playing_merges_empty_artist_and_none_volume(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        result = display._effective_overlay_locked(OverlayState(visible=True, muted=False))
        assert result.artist == ""
        assert result.title == ""
        assert result.volume is None

    def test_pressed_and_visible_fields_survive_the_merge_unchanged(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        result = display._effective_overlay_locked(OverlayState(visible=True, pressed=TouchZone.DOWN))
        assert result.visible is True
        assert result.pressed == TouchZone.DOWN


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
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
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
        display.noncomposited_generation()

        assert spy_lock.acquire_calls == 0, (
            "a touch-thread entry point acquired the display lock"
        )

    def test_touch_activity_wakes_via_repaint_thread(self):
        """notify_touch_activity() defers the wake rather than doing it
        inline, so the wake must still actually happen."""
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[t])
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
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
        display.enable()
        gen_before = display.noncomposited_generation()
        display._noncomposited_event.clear()

        with display._lock:
            display._clear_locked()

        assert display.noncomposited_generation() == gen_before + 1
        assert display._noncomposited_event.is_set()

    def test_sleep_locked_bumps_generation_and_sets_event(self):
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
        display.enable()
        assert not hasattr(display, "_touch_source")
        assert not hasattr(display, "_touch_callback")

        with display._lock:
            display._mark_noncomposited_locked()
            display._mark_noncomposited_locked()

        assert display.noncomposited_generation() == 2


# ---------------------------------------------------------------------------
# "Always show controls" held-visible overlay (B/A.4 held-visible parts):
# persistent_overlay_shown(), _current_base_is_artwork tracking via
# _display_locked's is_artwork_base parameter, and the forced-visible merge
# in _effective_overlay_locked().
# ---------------------------------------------------------------------------

def _poll_with_artwork(display, fb):
    """Drive one poll iteration that lands on identified artwork, faking out
    the network/decode/transform steps exactly like TestRotation does."""
    fake_image = _marked_image(size=(fb.width, fb.height))
    with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
         patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
         patch("dial_display.decode_artwork", return_value=fake_image), \
         patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
        display._poll_once()


class TestIsArtworkBaseTracking:
    def test_render_logo_locked_clears_artwork_flag(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._current_base_is_artwork = True
            display._render_logo_locked()
        assert display._current_base_is_artwork is False

    def test_show_artwork_sets_artwork_flag(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        assert display._current_base_is_artwork is False
        _poll_with_artwork(display, fb)
        assert display._current_base_is_artwork is True

    def test_show_artwork_cached_reuse_path_keeps_artwork_flag(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_with_artwork(display, fb)
        assert display._current_base_is_artwork is True
        cached_url = display._source_artwork_url
        with display._lock:
            # Force past the "unchanged url + already showing artwork"
            # early no-op return so the call below actually reaches the
            # cached-reuse branch of _show_artwork (same url, cached image
            # still set, but _showing no longer says "artwork").
            display._showing = "logo"
            display._current_base_is_artwork = False
        display._show_artwork(cached_url)
        assert display._current_base_is_artwork is True

    def test_redisplay_current_locked_keeps_artwork_flag_true(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_with_artwork(display, fb)
        with display._lock:
            display._current_base_is_artwork = False
            display._redisplay_current_locked()
        assert display._current_base_is_artwork is True

    def test_redisplay_current_locked_renders_logo_when_nothing_cached(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._current_base_is_artwork = True
            display._redisplay_current_locked()
        assert display._current_base_is_artwork is False

    def test_repaint_current_locked_does_not_change_artwork_flag(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_with_artwork(display, fb)
        assert display._current_base_is_artwork is True
        with display._lock:
            display._repaint_current_locked()
        assert display._current_base_is_artwork is True

    def test_clear_sleep_disable_swap_clear_artwork_flag(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_with_artwork(display, fb)
        assert display._current_base_is_artwork is True
        with display._lock:
            display._clear_locked()
        assert display._current_base_is_artwork is False

        display2, fb2, gt2 = _make_display(targets=[t])
        display2.enable()
        _poll_with_artwork(display2, fb2)
        with display2._lock:
            display2._sleep_locked()
        assert display2._current_base_is_artwork is False

        display3, fb3, gt3 = _make_display(targets=[t])
        display3.enable()
        _poll_with_artwork(display3, fb3)
        with display3._lock:
            display3._disable_locked()
        assert display3._current_base_is_artwork is False

    def test_swap_backend_locked_clears_artwork_flag(self):
        t = _target()
        fb_old = FakeBackend()
        fb_new = FakeBackend()

        def builder(screen_type):
            return lambda: fb_new

        display, _, gt = _make_display(
            targets=[t], backend=fb_old, backend_factory_builder=builder,
        )
        display.enable()
        _poll_with_artwork(display, fb_old)
        assert display._current_base_is_artwork is True
        with display._lock:
            display._rebuild_backend_factory_locked("st7789_240x240")
            display._swap_backend_locked()
        # The swap itself calls _enable_locked() -> _render_logo_locked(),
        # which sets the flag back to False via is_artwork_base=False — the
        # net observable result is the same "no artwork on screen" state
        # _swap_backend_locked's own reset line guarantees even before that.
        assert display._current_base_is_artwork is False


class TestPersistentOverlayShown:
    def test_false_when_always_show_controls_off(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t], always_show_controls=False)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.persistent_overlay_shown() is False

    def test_true_when_on_and_artwork_shown(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.persistent_overlay_shown() is True

    def test_false_over_the_logo(self):
        display, fb, gt = _make_display(targets=[], always_show_controls=True)
        display.enable()
        assert display.get_status()["showing"] == "logo"
        assert display.persistent_overlay_shown() is False

    def test_false_when_backend_not_open(self):
        display, fb, gt = _make_display(fitted=False, always_show_controls=True)
        assert display.persistent_overlay_shown() is False

    def test_false_when_sleeping(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.persistent_overlay_shown() is True
        with display._lock:
            display._sleep_locked()
        assert display.persistent_overlay_shown() is False

    def test_false_after_clear(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.persistent_overlay_shown() is True
        with display._lock:
            display._clear_locked()
        assert display.persistent_overlay_shown() is False

    def test_get_status_includes_always_show_controls(self):
        display, fb, gt = _make_display(always_show_controls=True)
        display.enable()
        assert display.get_status()["always_show_controls"] is True


class TestHeldOverlay:
    def test_held_visible_frame_differs_from_no_overlay_frame(self):
        t = _target()
        display_off, fb_off, _ = _make_display(targets=[t], always_show_controls=False)
        display_off.enable()
        _poll_with_artwork(display_off, fb_off)
        no_overlay_frame = fb_off.displayed[-1]

        display_on, fb_on, _ = _make_display(targets=[t], always_show_controls=True)
        display_on.enable()
        _poll_with_artwork(display_on, fb_on)
        held_frame = fb_on.displayed[-1]

        assert display_on.persistent_overlay_shown() is True
        assert list(held_frame.getdata()) != list(no_overlay_frame.getdata())

    def test_logo_never_gets_the_overlay_even_when_held(self):
        display, fb, gt = _make_display(targets=[], always_show_controls=True)
        display.enable()
        fb.displayed.clear()
        with display._lock:
            display._render_logo_locked()
        logo_frame = fb.displayed[-1]

        # Compose the same base without any overlay merge for comparison —
        # the held path must not have drawn anything on top of the logo.
        expected = display._compositor.compose(
            logo_frame, logo_frame.width, logo_frame.height,
            rotate=False, bgr=False, is_artwork=False, overlay=None,
        )
        assert list(logo_frame.getdata()) == list(expected.getdata())

    def test_always_show_controls_false_and_snapshot_hidden_matches_no_overlay(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t], always_show_controls=False)
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
        display, fb, gt = _make_display(targets=[t], fitted=True, always_show_controls=False)
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
        display, fb, gt = _make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        result = display._effective_overlay_locked(OverlayState(visible=False))
        assert result.visible is True

    def test_effective_overlay_locked_not_held_returns_invisible_snapshot_unchanged(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t], always_show_controls=False)
        display.enable()
        _poll_with_artwork(display, fb)
        snapshot = OverlayState(visible=False)
        result = display._effective_overlay_locked(snapshot)
        assert result is snapshot


# ---------------------------------------------------------------------------
# Auth application during the sequential poll walk
# ---------------------------------------------------------------------------

class TestAuthApplicationDuringPoll:
    def test_412_matching_id_marks_unauthorized_and_moves_to_next_target_on_next_poll(self):
        aid = "1" * 20
        t1 = _target(name="First", service_name="First", appliance_id=aid, playing_since=1.0)
        t2 = _target(name="Second", service_name="Second", playing_since=2.0)
        display, fb, gt = _make_display(targets=[t1, t2])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(status_error="unauthorized", appliance_id=aid)):
            display._poll_once()
        assert dial_auth.auth_map.state(aid) == dial_auth.AUTH_UNAUTHORIZED

        # Next poll: as a real get_display_targets() would, the row now
        # comes back stamped unauthorized (this fixture's get_targets is a
        # bare mock, so simulate that re-stamp explicitly) and is skipped
        # outright — no fetch at all; the source moves to the next
        # controllable target.
        gt.return_value = [dataclasses.replace(t1, auth="unauthorized"), t2]
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id())) as mock_fetch:
            display._poll_once()
        mock_fetch.assert_called_once()
        assert mock_fetch.call_args[0][0] is t2
        assert display._source_service_name == "Second"

    def test_200_with_mismatched_appliance_id_leaves_map_unchanged(self):
        aid = "2" * 20
        other_id = "3" * 20
        t = _target(appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(), appliance_id=other_id)):
            display._poll_once()
        assert dial_auth.auth_map.state(aid) == dial_auth.AUTH_UNKNOWN


# ---------------------------------------------------------------------------
# Reconcile pass: concurrent fan-out over rows the sequential walk skipped.
# ---------------------------------------------------------------------------

class TestReconcilePass:
    def test_runs_first_tick_then_not_again_within_interval_then_again(self):
        aid1, aid2 = "4" * 20, "5" * 20
        t1 = _target(name="One", service_name="One", appliance_id=aid1, playing_since=10.0)
        t2 = _target(name="Two", service_name="Two", appliance_id=aid2, playing_since=20.0)
        display, fb, gt = _make_display(targets=[t1, t2])
        display.enable()
        clock = _FakeClock()

        def fake_enrich(targets, dial_id):
            return []

        with patch("dial_display.time.monotonic", clock), \
             patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display.enrich_targets", side_effect=fake_enrich) as mock_enrich:
            display._poll_once()  # sequential walk visits t1 only (breaks on its artwork)
        assert mock_enrich.call_count == 1
        pending_arg = mock_enrich.call_args[0][0]
        assert [t.service_name for t in pending_arg] == ["Two"]

        with patch("dial_display.time.monotonic", clock), \
             patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display.enrich_targets", side_effect=fake_enrich) as mock_enrich2:
            display._poll_once()  # same instant: within the 60s interval
        mock_enrich2.assert_not_called()

        clock.t += dd.RECONCILE_INTERVAL_SECONDS
        with patch("dial_display.time.monotonic", clock), \
             patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display.enrich_targets", side_effect=fake_enrich) as mock_enrich3:
            display._poll_once()
        mock_enrich3.assert_called_once()

    def test_only_probes_rows_not_visited_and_due(self):
        aid1, aid2, aid3 = "6" * 20, "7" * 20, "8" * 20
        t1 = _target(name="One", service_name="One", appliance_id=aid1, playing_since=1.0)
        t2 = _target(name="Two", service_name="Two", appliance_id=aid2, playing_since=2.0)
        t3 = _target(name="Three", service_name="Three", appliance_id=aid3, playing_since=3.0)
        display, fb, gt = _make_display(targets=[t1, t2, t3])
        display.enable()
        clock = _FakeClock(start=1000.0)
        # t2 is freshly on backoff (not due again until 1000 + 30s); t3 has
        # no entry yet, which is always due.
        dial_auth.auth_map.apply(aid2, dial_auth.OUTCOME_UNAUTHORIZED, aid2, clock.t)

        with patch("dial_display.time.monotonic", clock), \
             patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display.enrich_targets", return_value=[]) as mock_enrich:
            display._poll_once()
        pending_arg = mock_enrich.call_args[0][0]
        assert [t.service_name for t in pending_arg] == ["Three"]

    def test_applies_enrich_records_to_the_auth_map(self):
        aid = "9" * 20
        t1 = _target(name="One", service_name="One", playing_since=1.0)
        t2 = _target(name="Two", service_name="Two", appliance_id=aid, playing_since=2.0)
        display, fb, gt = _make_display(targets=[t1, t2])
        display.enable()

        def fake_enrich(targets, dial_id):
            return [
                {"name": "Two", "status_error": "unauthorized", "appliance_id": aid},
            ]

        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display.enrich_targets", side_effect=fake_enrich):
            display._poll_once()
        assert dial_auth.auth_map.state(aid) == dial_auth.AUTH_UNAUTHORIZED


# ---------------------------------------------------------------------------
# dial_repeat_store fed from both poll paths.
# ---------------------------------------------------------------------------

class TestRepeatStoreFeed:
    def _repeat_obj(self, **overrides) -> dict:
        base = {
            "available": True, "state": "hold", "armed": False, "held": True,
            "recording_seconds": 30.0,
            "replay": {"active": False, "position_seconds": 0.0, "duration_seconds": 30.0},
        }
        base.update(overrides)
        return base

    def test_artwork_walk_feeds_the_store_for_the_reporting_target(self):
        import dial_repeat_store as drs
        aid = "1" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=None, appliance_id=aid)
        result["repeat"] = self._repeat_obj()

        with patch("dial_display.fetch_target_status", return_value=result):
            display._poll_once()

        rec = drs.repeat_store.get(aid, now=time.monotonic())
        assert rec is not None
        assert rec.state == "hold"
        assert rec.recording_seconds == 30.0

    def test_confirmed_unauthorized_clears_the_stored_record(self):
        import dial_repeat_store as drs
        aid = "2" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        drs.repeat_store.update(aid, drs.parse_repeat_object(self._repeat_obj(), now=time.monotonic()))

        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(status_error="unauthorized", appliance_id=aid)):
            display._poll_once()

        assert drs.repeat_store.get(aid, now=time.monotonic()) is None

    def test_transient_error_leaves_the_stored_record_untouched(self):
        import dial_repeat_store as drs
        aid = "3" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        rec = drs.parse_repeat_object(self._repeat_obj(), now=time.monotonic())
        drs.repeat_store.update(aid, rec)

        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(status_error="timeout")):
            display._poll_once()

        assert drs.repeat_store.get(aid, now=time.monotonic()) == rec

    def test_reconcile_pass_feeds_the_store_for_idle_roster_rows_only(self):
        """An idle (non-playing) roster row is reconciled through
        enrich_targets — feeding the repeat store — but is never walked for
        artwork and never sets _now_playing; that stays exclusively the
        playing target's job."""
        import dial_repeat_store as drs
        from dial_mdns import RosterEntry

        aid_playing = "4" * 20
        aid_idle = "5" * 20
        t1 = _target(name="Playing", service_name="Playing",
                      appliance_id=aid_playing, playing_since=1.0)

        def get_roster():
            return [
                RosterEntry(
                    appliance_id=aid_playing, service_name="Playing", name="Playing",
                    ip=t1.ip, port=t1.port, playing=True, repeat_capable=False,
                    dial_api=True, audio_status=True, dial_status=True, auth="unknown",
                ),
                RosterEntry(
                    appliance_id=aid_idle, service_name="Idle", name="Idle",
                    ip="10.0.0.9", port=9999, playing=False, repeat_capable=True,
                ),
            ]

        display, fb, gt = _make_display(targets=[t1], get_roster=get_roster)
        display.enable()

        idle_repeat_obj = self._repeat_obj(state="replaying", armed=True,
                                            replay={"active": True, "position_seconds": 1.0,
                                                    "duration_seconds": 5.0})

        def fake_enrich(targets, dial_id):
            assert [t.service_name for t in targets] == ["Idle"]
            return [{
                "name": "Idle", "status_error": None, "appliance_id": aid_idle,
                "repeat": idle_repeat_obj,
            }]

        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(), appliance_id=aid_playing)), \
             patch("dial_display.enrich_targets", side_effect=fake_enrich):
            display._poll_once()

        idle_rec = drs.repeat_store.get(aid_idle, now=time.monotonic())
        assert idle_rec is not None
        assert idle_rec.state == "replaying"
        # The idle row never became the artwork base or the reporting target.
        assert display._now_playing is not None
        assert display._now_playing.service_name == "Playing"
        assert display._source_service_name == "Playing"

    def test_reconcile_pass_prunes_ids_not_in_the_roster(self):
        import dial_repeat_store as drs
        aid_gone = "6" * 20
        drs.repeat_store.update(aid_gone, drs.parse_repeat_object(self._repeat_obj(), now=time.monotonic()))
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id="7" * 20, playing_since=1.0)
        display, fb, gt = _make_display(targets=[t])
        display.enable()

        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())):
            display._poll_once()

        assert drs.repeat_store.get(aid_gone, now=time.monotonic()) is None


# ---------------------------------------------------------------------------
# Push probes and the poll loop's sleep gate.
# ---------------------------------------------------------------------------

class TestPushProbes:
    def test_notify_auth_changed_sets_poll_wake(self):
        display, fb, gt = _make_display(targets=[])
        assert not display._poll_wake.is_set()
        display.notify_auth_changed("a" * 20)
        assert display._poll_wake.is_set()

    def test_drain_push_probes_only_probes_rostered_ids(self):
        aid = "c" * 20
        t = _target(appliance_id=aid, service_name="Kit")
        display, fb, gt = _make_display(targets=[t])
        display.notify_auth_changed(aid)
        display.notify_auth_changed("d" * 20)  # not rostered: skipped, no fetch
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(appliance_id=aid, track_id=None)) as mock_fetch:
            result = display._drain_push_probes()
        mock_fetch.assert_called_once()
        assert mock_fetch.call_args[0][0] is t
        assert result == "probed"

    def test_drain_push_probes_is_noop_with_nothing_pending(self):
        display, fb, gt = _make_display(targets=[])
        with patch("dial_display.fetch_target_status") as mock_fetch:
            result = display._drain_push_probes()
        mock_fetch.assert_not_called()
        assert result == ""

    def test_push_probe_that_promotes_while_asleep_wakes_and_resets_idle(self):
        aid = "e" * 20
        t = _target(appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with display._lock:
            display._display_sleeping = True
            display._idle_started_at = 123.0
        display.notify_auth_changed(aid)
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(appliance_id=aid, track_id=None)):
            result = display._drain_push_probes()
        assert result == "woke"
        assert display._display_sleeping is False
        assert display._idle_started_at is None
        assert fb.wake_calls == 1

    def test_push_probe_that_demotes_leaves_display_asleep(self):
        aid = "f" * 20
        t = _target(appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with display._lock:
            display._display_sleeping = True
        display.notify_auth_changed(aid)
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(status_error="unauthorized", appliance_id=aid)):
            result = display._drain_push_probes()
        assert result == "probed"
        assert display._display_sleeping is True
        assert fb.wake_calls == 0


class TestRunPollGating:
    """_run()'s decision to call _poll_once() while asleep: only a push
    probe that actually promoted an authorization (pushed == "woke") may run
    the general poll while asleep — a plain probe or a revoke must not."""

    def _run_one_iteration(self, display):
        def once_wait(timeout=None):
            display._stop_event.set()
            return True
        with patch.object(display._poll_wake, "wait", side_effect=once_wait):
            display._run()

    def test_skips_poll_once_while_asleep_and_not_woken_by_push(self):
        display, fb, gt = _make_display(targets=[])
        display._display_sleeping = True
        with patch.object(display, "_drain_push_probes", return_value="probed"), \
             patch.object(display, "_poll_once") as mock_poll:
            self._run_one_iteration(display)
        mock_poll.assert_not_called()

    def test_calls_poll_once_when_push_probe_woke(self):
        display, fb, gt = _make_display(targets=[])
        display._display_sleeping = True
        with patch.object(display, "_drain_push_probes", return_value="woke"), \
             patch.object(display, "_poll_once") as mock_poll:
            self._run_one_iteration(display)
        mock_poll.assert_called_once()

    def test_calls_poll_once_when_awake_regardless_of_push_result(self):
        display, fb, gt = _make_display(targets=[])
        display._display_sleeping = False
        with patch.object(display, "_drain_push_probes", return_value=""), \
             patch.object(display, "_poll_once") as mock_poll:
            self._run_one_iteration(display)
        mock_poll.assert_called_once()


# ---------------------------------------------------------------------------
# Sticky manual focus.
# ---------------------------------------------------------------------------

class TestManualFocus:
    def test_set_manual_focus_sets_poll_wake_and_is_readable(self):
        display, fb, gt = _make_display(targets=[])
        assert not display._poll_wake.is_set()
        display.set_manual_focus("a" * 20)
        assert display._poll_wake.is_set()
        assert display.manual_focus_id() == "a" * 20

    def test_clear_manual_focus(self):
        display, fb, gt = _make_display(targets=[])
        display.set_manual_focus("a" * 20)
        display.set_manual_focus(None)
        assert display.manual_focus_id() is None

    def test_never_survives_a_new_display(self):
        display1, fb1, gt1 = _make_display(targets=[])
        display1.set_manual_focus("d" * 20)
        display2, fb2, gt2 = _make_display(targets=[])
        assert display2.manual_focus_id() is None

    def test_focus_pins_source_service_name_even_without_artwork(self):
        aid = "a" * 20
        focus_t = _target(name="Focus", service_name="Focus", appliance_id=aid, playing_since=5.0)
        other_t = _target(name="Other", service_name="Other", playing_since=1.0)
        display, fb, gt = _make_display(targets=[other_t, focus_t])
        display.enable()
        display.set_manual_focus(aid)

        call_order = []

        def fake_fetch(target, dial_id, timeout_seconds):
            call_order.append(target.service_name)
            if target is focus_t:
                return _status_result(track_id=None, appliance_id=aid)  # no artwork
            return _status_result(track_id=_track_id())  # other target HAS artwork

        with patch("dial_display.fetch_target_status", side_effect=fake_fetch):
            display._poll_once()

        # The focus target is polled first, and the walk never falls through
        # to the other target's artwork even though it has some.
        assert call_order == ["Focus"]
        assert display._source_service_name == "Focus"
        assert display._now_playing.service_name == "Focus"
        assert display.get_status()["showing"] == "logo"

    def test_focus_clears_when_target_leaves_roster(self):
        aid = "b" * 20
        display, fb, gt = _make_display(targets=[])
        display.set_manual_focus(aid)
        display._poll_once()
        assert display.manual_focus_id() is None

    def test_focus_clears_mid_tick_on_confirmed_unauthorized_and_falls_back(self):
        aid = "c" * 20
        focus_t = _target(name="Focus", service_name="Focus", appliance_id=aid, playing_since=1.0)
        other_t = _target(name="Other", service_name="Other", playing_since=5.0)
        display, fb, gt = _make_display(targets=[focus_t, other_t])
        display.enable()
        display.set_manual_focus(aid)

        def fake_fetch(target, dial_id, timeout_seconds):
            if target is focus_t:
                return _status_result(status_error="unauthorized", appliance_id=aid)
            return _status_result(track_id=_track_id())

        with patch("dial_display.fetch_target_status", side_effect=fake_fetch):
            display._poll_once()

        assert display.manual_focus_id() is None
        assert dial_auth.auth_map.state(aid) == dial_auth.AUTH_UNAUTHORIZED
        assert display._source_service_name == "Other"

    def test_focus_target_with_identified_artwork_is_shown(self):
        aid = "9" * 19 + "a"
        focus_t = _target(name="Focus", service_name="Focus", appliance_id=aid, playing_since=1.0)
        display, fb, gt = _make_display(targets=[focus_t])
        display.enable()
        display.set_manual_focus(aid)
        fake_image = Image.new("RGB", (fb.width, fb.height))
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(), appliance_id=aid)), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()
        assert display.get_status()["showing"] == "artwork"
        assert display._source_service_name == "Focus"


# ---------------------------------------------------------------------------
# Appliance-selector screen (2.7, 2.5.5) — open/close/page/pick, row
# filtering, the inactivity timeout, and the screen's interaction with
# sleep/backend lifecycle and the touch-facing surfaces.
# ---------------------------------------------------------------------------

class TestSelectorRows:
    def test_rows_only_authorized_targets_with_nonempty_id(self):
        good = _target(name="A", service_name="A", appliance_id="a" * 20, auth="authorized")
        unauth = _target(name="B", service_name="B", appliance_id="b" * 20, auth="unauthorized")
        unknown = _target(name="C", service_name="C", appliance_id="c" * 20, auth="unknown")
        no_id = _target(name="D", service_name="D", appliance_id="", auth="authorized")
        display, fb, gt = _make_display(targets=[good, unauth, unknown, no_id])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        assert [r.label for r in display._selector.rows] == ["A"]
        assert [r.appliance_id for r in display._selector.rows] == ["a" * 20]

    def test_current_follows_manual_focus(self):
        a = _target(name="A", service_name="A", appliance_id="a" * 20, auth="authorized", playing_since=1.0)
        b = _target(name="B", service_name="B", appliance_id="b" * 20, auth="authorized", playing_since=2.0)
        display, fb, gt = _make_display(targets=[a, b])
        display.enable()
        display.set_manual_focus("b" * 20)
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        current_ids = {r.appliance_id for r in display._selector.rows if r.current}
        assert current_ids == {"b" * 20}

    def test_current_follows_reporting_target_with_no_focus(self):
        a = _target(name="A", service_name="A", appliance_id="a" * 20, auth="authorized", playing_since=1.0)
        b = _target(name="B", service_name="B", appliance_id="b" * 20, auth="authorized", playing_since=2.0)
        display, fb, gt = _make_display(targets=[a, b])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        # No focus, no identified artwork -> select_volume_target falls back
        # to the oldest playing target (A).
        current_ids = {r.appliance_id for r in display._selector.rows if r.current}
        assert current_ids == {"a" * 20}

    def test_page_preserved_across_rebuild_but_clamped_to_new_count(self):
        targets = [
            _target(name=f"T{i}", service_name=f"T{i}", appliance_id=str(i) * 20,
                     auth="authorized", playing_since=float(i))
            for i in range(5)
        ]
        display, fb, gt = _make_display(targets=targets)
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        display.selector_page(+1)  # page 1 (rows_per_page == 3 -> pages 0,1)
        with display._lock:
            display._repaint_current_locked()
        assert display._selector.page == 1

        # Roster shrinks to one row: the next poll's rebuild must clamp the
        # preserved page back down rather than raise or go negative.
        gt.return_value = [targets[0]]
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        assert display._selector.page == 0


class TestSelectorOpenCloseAndRepaint:
    def _display_with_one_row(self, always_show_controls=False):
        a = _target(name="A", service_name="A", appliance_id="a" * 20, auth="authorized")
        display, fb, gt = _make_display(targets=[a], always_show_controls=always_show_controls)
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
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

        display.close_selector()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"
        assert display._selector is None

    def test_no_authorized_rows_shows_no_devices_placeholder(self):
        t = _target(auth="unknown")  # controllable (Phase 1), but never listed
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
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
        # Force the "artwork on screen" precondition directly rather than
        # faking a full artwork fetch — this test is only about the
        # selector's own gate on persistent_overlay_shown().
        with display._lock:
            display._current_base_is_artwork = True
        assert display.persistent_overlay_shown() is True
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        assert display.persistent_overlay_shown() is False


class TestSelectorPickAndPage:
    def _opened_display(self, count=1):
        targets = [
            _target(name=f"T{i}", service_name=f"T{i}", appliance_id=str(i) * 20,
                     auth="authorized", playing_since=float(i))
            for i in range(count)
        ]
        display, fb, gt = _make_display(targets=targets)
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        return display, fb, gt, targets

    def test_pick_sets_focus_and_closes(self):
        display, fb, gt, targets = self._opened_display(count=1)
        display.selector_pick(0)
        assert display.manual_focus_id() == "0" * 20
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"

    def test_stale_index_closes_without_setting_focus(self):
        display, fb, gt, targets = self._opened_display(count=1)
        display.selector_pick(5)  # out of range for a single row
        assert display.manual_focus_id() is None
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"

    def test_page_clamps_to_valid_range(self):
        display, fb, gt, targets = self._opened_display(count=5)  # rows_per_page == 3 -> pages 0, 1
        assert display._selector.page == 0

        display.selector_page(-1)
        with display._lock:
            display._repaint_current_locked()
        assert display._selector.page == 0

        display.selector_page(+5)
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
        display.selector_page(+1)
        with display._lock:
            display._repaint_current_locked()
        assert display._selector.page == 1

        display.selector_pick(0)  # row 0 of PAGE 1, not row 0 overall
        expected_id = targets[rows_per_page].appliance_id
        assert display.manual_focus_id() == expected_id


class TestSelectorTimeout:
    def _opened_display(self):
        a = _target(name="A", service_name="A", appliance_id="a" * 20, auth="authorized")
        display, fb, gt = _make_display(targets=[a])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
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
    def test_empty_target_branch_closes_selector_before_sleep_decision(self):
        a = _target(name="A", service_name="A", appliance_id="a" * 20, auth="authorized")
        display, fb, gt = _make_display(targets=[a])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "selector"

        gt.return_value = []  # nothing playing any more
        display._poll_once()
        assert display._screen == "main"
        assert display._selector is None

    def test_sleep_pops_to_main(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
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
        display, fb, gt = _make_display(targets=[a])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "selector"

        display.disable()
        assert display._screen == "main"

    def test_swap_backend_pops_to_main(self):
        a = _target(name="A", service_name="A", appliance_id="a" * 20, auth="authorized")
        display, fb, gt = _make_display(targets=[a])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
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
        display, fb, gt = _make_display(targets=[a])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        assert display.touch_surface() == ("selector", False, False)

    def test_hidden_with_name_active_when_something_is_playing(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.touch_surface() == ("hidden", True, False)

    def test_held_with_name_active(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.touch_surface() == ("held", True, False)

    def test_hidden_with_name_inactive_when_nothing_playing(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display._poll_once()
        assert display.touch_surface() == ("hidden", False, False)

    def test_idle_when_affordance_drawn(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display._poll_once()
        with display._lock:
            display._idle_affordance = True
        assert display.touch_surface() == ("idle", False, False)

    def test_hidden_not_idle_when_nothing_playing_and_no_affordance(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display._idle_affordance = False
        display._poll_once()
        assert display.touch_surface()[0] == "hidden"

    def test_repeat_screen_reports_repeat_with_dots_active(self):
        aid = "1" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        import dial_repeat_store as drs
        drs.repeat_store.update(aid, drs.RepeatRecord(
            available=True, state="recording", armed=False,
            recording_seconds=0.0, position_seconds=0.0, duration_seconds=0.0,
            observed_at=time.monotonic(),
        ))
        with display._lock:
            display._screen = "repeat"
        assert display.touch_surface() == ("repeat", True, True)

    def test_picker_while_open(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "picker"
        assert display.touch_surface() == ("picker", False, False)

    def test_dots_active_reflects_fresh_available_record(self):
        aid = "2" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        import dial_repeat_store as drs
        result = _status_result(track_id=None, appliance_id=aid)
        result["repeat"] = {
            "available": True, "state": "idle", "armed": False, "held": False,
            "recording_seconds": 0.0,
            "replay": {"active": False, "position_seconds": 0.0, "duration_seconds": 0.0},
        }
        with patch("dial_display.fetch_target_status", return_value=result):
            display._poll_once()
        assert display._dots_active is True
        surface, name_active, dots_active = display.touch_surface()
        assert dots_active is True

    def test_dots_inactive_when_record_unavailable(self):
        aid = "3" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=None, appliance_id=aid)
        with patch("dial_display.fetch_target_status", return_value=result):
            display._poll_once()
        assert display._dots_active is False


class TestOverlayNameField:
    def test_name_populated_from_reporting_target_when_visible(self):
        t = _target(name="CD_Player", service_name="autostream on CD_Player")
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_with_artwork(display, fb)
        display.set_overlay(OverlayState(visible=True))
        with display._lock:
            overlay = display._effective_overlay_locked(display._overlay_snapshot)
        assert overlay.name == "CD Player"

    def test_name_empty_when_nothing_playing(self):
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_with_artwork(display, fb)
        assert len(display._selector.rows) == 1
        assert display.touch_surface() == ("hidden", True, False)


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
    with patch("dial_display.fetch_target_status", return_value=result), \
         patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
         patch("dial_display.decode_artwork", return_value=fake_image), \
         patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
        display._poll_once()


class TestToggleRepeatScreen:
    def test_opens_when_record_available(self):
        aid = "1" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))

        display.toggle_repeat_screen()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"
        assert display._repeat_screen.appliance_id == aid

    def test_does_not_open_with_no_record(self):
        aid = "2" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(), appliance_id=aid)):
            display._poll_once()

        display.toggle_repeat_screen()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"

    def test_does_not_open_when_record_unavailable(self):
        aid = "3" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(available=False, state="idle"))

        display.toggle_repeat_screen()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"

    def test_does_not_open_with_nothing_playing(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display._poll_once()
        display.toggle_repeat_screen()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"

    def test_second_tap_closes_it(self):
        aid = "4" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))
        display.toggle_repeat_screen()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

        display.toggle_repeat_screen()
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
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))

        display.toggle_repeat_screen()  # open
        assert display.consume_repeat_close_reveal() is False

        with display._lock:
            display._repaint_current_locked()
        display.toggle_repeat_screen()  # close
        assert display.consume_repeat_close_reveal() is True
        # Read-and-clear: a second read finds nothing left to consume.
        assert display.consume_repeat_close_reveal() is False


class TestRepeatScreenTouchEntries:
    def _opened(self, state="idle", armed=False, appliance_id="5" * 20):
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=appliance_id)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, appliance_id, _repeat_obj(state=state, armed=armed))
        display.toggle_repeat_screen()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"
        return display, appliance_id

    def test_toggle_tap_arms_in_idle(self):
        display, aid = self._opened(state="idle", armed=False)
        with patch("dial_display.enqueue_arm") as mock_arm:
            display.repeat_toggle_tap()
        mock_arm.assert_called_once()
        target, armed = mock_arm.call_args[0]
        assert target.appliance_id == aid
        assert armed is True

    def test_toggle_tap_disarms_when_already_armed(self):
        display, aid = self._opened(state="recording", armed=True)
        with patch("dial_display.enqueue_arm") as mock_arm:
            display.repeat_toggle_tap()
        mock_arm.assert_called_once()
        _, armed = mock_arm.call_args[0]
        assert armed is False

    def test_toggle_tap_ignored_while_replaying(self):
        display, aid = self._opened(state="replaying")
        with patch("dial_display.enqueue_arm") as mock_arm:
            display.repeat_toggle_tap()
        mock_arm.assert_not_called()

    def test_start_tap_seeks_zero_while_hold(self):
        display, aid = self._opened(state="hold")
        with patch("dial_display.enqueue_transport") as mock_transport:
            display.repeat_start_tap()
        mock_transport.assert_called_once()
        target, action, position = mock_transport.call_args[0]
        assert target.appliance_id == aid
        assert action == "seek"
        assert position == 0.0

    def test_start_tap_seeks_zero_while_replaying(self):
        display, aid = self._opened(state="replaying")
        with patch("dial_display.enqueue_transport") as mock_transport:
            display.repeat_start_tap()
        mock_transport.assert_called_once()

    def test_start_tap_ignored_while_recording(self):
        display, aid = self._opened(state="recording")
        with patch("dial_display.enqueue_transport") as mock_transport:
            display.repeat_start_tap()
        mock_transport.assert_not_called()

    def test_stop_tap_stops_while_replaying(self):
        display, aid = self._opened(state="replaying")
        with patch("dial_display.enqueue_transport") as mock_transport:
            display.repeat_stop_tap()
        mock_transport.assert_called_once()
        target, action, position = mock_transport.call_args[0]
        assert target.appliance_id == aid
        assert action == "stop"

    def test_stop_tap_ignored_while_hold(self):
        display, aid = self._opened(state="hold")
        with patch("dial_display.enqueue_transport") as mock_transport:
            display.repeat_stop_tap()
        mock_transport.assert_not_called()

    def test_taps_are_noop_when_screen_not_open(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with patch("dial_display.enqueue_arm") as mock_arm, \
             patch("dial_display.enqueue_transport") as mock_transport:
            display.repeat_toggle_tap()
            display.repeat_start_tap()
            display.repeat_stop_tap()
        mock_arm.assert_not_called()
        mock_transport.assert_not_called()


class TestRepeatScreenComposePath:
    def _opened(self, state="idle", appliance_id="6" * 20):
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=appliance_id)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, appliance_id, _repeat_obj(state=state))
        display.toggle_repeat_screen()
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
        display, fb, gt = _make_display(targets=[focus_t])
        display.enable()
        display.set_manual_focus(aid)
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle"))
        display.toggle_repeat_screen()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

        gt.return_value = []  # the appliance leaves the roster entirely
        display._poll_once()
        assert display.manual_focus_id() is None
        assert display._screen == "main"

    def test_closes_on_mid_tick_unauthorized_clear(self):
        aid = "8" * 20
        focus_t = _target(name="Focus", service_name="Focus", appliance_id=aid, playing_since=1.0)
        other_t = _target(name="Other", service_name="Other", playing_since=5.0)
        display, fb, gt = _make_display(targets=[focus_t, other_t])
        display.enable()
        display.set_manual_focus(aid)
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle"))
        display.toggle_repeat_screen()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

        def fake_fetch(target, dial_id, timeout_seconds):
            if target is focus_t:
                return _status_result(status_error="unauthorized", appliance_id=aid)
            return _status_result(track_id=_track_id())

        with patch("dial_display.fetch_target_status", side_effect=fake_fetch):
            display._poll_once()

        assert display.manual_focus_id() is None
        assert display._screen == "main"

    def test_sleep_pops_repeat_screen(self):
        display, fb, gt, aid = self._opened()
        assert display._screen == "repeat"
        with display._lock:
            display._sleep_locked()
        assert display._screen == "main"
        assert display._repeat_screen is None

    def test_sleep_pops_picker(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
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
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, appliance_id, _repeat_obj(state=state))
        display.toggle_repeat_screen()
        with display._lock:
            display._repaint_current_locked()
        return display, appliance_id

    def test_muted_and_volume_fed_from_the_repeat_screens_own_appliance(self):
        display, aid = self._opened(state="idle")
        with patch("dial_display.is_muted", return_value=True), \
             patch("dial_display.shown_volume", return_value=37) as mock_shown_volume:
            with display._lock:
                view = display._build_repeat_view_locked(display._repeat_screen, time.monotonic())
        assert view.muted is True
        assert view.volume == 37
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
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(
            display, fb, appliance_id,
            _repeat_obj(
                state="replaying", armed=True,
                replay={"active": True, "position_seconds": position_seconds, "duration_seconds": 30.0},
            ),
        )
        display.toggle_repeat_screen()
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
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="hold"))
        display.toggle_repeat_screen()
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

    def test_tick_repeat_line_signals_only_while_replaying(self):
        aid = "9" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="replaying", armed=True))
        display.toggle_repeat_screen()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

        display._overlay_signal.clear()
        display._tick_repeat_line()
        assert display._overlay_signal.is_set()

    def test_tick_repeat_line_noop_while_hold(self):
        aid = "10" * 10
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="hold"))
        display.toggle_repeat_screen()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

        display._overlay_signal.clear()
        display._tick_repeat_line()
        assert not display._overlay_signal.is_set()


# ---------------------------------------------------------------------------
# Manual-focus pending grace: a picker-started replay's focus survives
# absence from the roster for FOCUS_PENDING_GRACE_S, converts to a normal
# focus once sighted, and clears on expiry or a failed transport.
# ---------------------------------------------------------------------------

class TestFocusPendingGrace:
    def test_pending_focus_survives_absence_within_grace(self):
        display, fb, gt = _make_display(targets=[])
        aid = "b" * 20
        display.set_manual_focus_pending(aid, "Kitchen")
        display._poll_once()
        assert display.manual_focus_id() == aid
        assert display._now_playing is not None
        assert display._now_playing.service_name == "Kitchen"

    def test_pending_focus_shows_logo_not_idle_screen(self):
        display, fb, gt = _make_display(targets=[])
        aid = "c" * 20
        display.set_manual_focus_pending(aid, "Kitchen")
        with display._lock:
            display._idle_affordance = True  # would otherwise draw the idle-screen affordance
        display._poll_once()
        assert display._idle_chassis_due_locked() is False

    def test_pending_focus_expires_after_grace(self):
        display, fb, gt = _make_display(targets=[])
        aid = "d" * 20
        clock = _FakeClock()
        with patch("dial_display.time.monotonic", clock):
            display.set_manual_focus_pending(aid, "Kitchen")
            display._poll_once()
            assert display.manual_focus_id() == aid
            clock.t += dd.FOCUS_PENDING_GRACE_S + 1
            display._poll_once()
        assert display.manual_focus_id() is None
        assert display._focus_pending is None

    def test_pending_focus_converts_to_normal_focus_when_sighted(self):
        aid = "e" * 20
        display, fb, gt = _make_display(targets=[])
        display.set_manual_focus_pending(aid, "Kitchen")
        display._poll_once()
        assert display._focus_pending is not None

        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid, playing_since=1.0)
        gt.return_value = [t]
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid)):
            display._poll_once()
        assert display.manual_focus_id() == aid
        assert display._focus_pending is None

    def test_on_repeat_result_failure_clears_pending_focus(self):
        aid = "f" * 20
        display, fb, gt = _make_display(targets=[])
        display.set_manual_focus_pending(aid, "Kitchen")
        display._poll_once()
        assert display.manual_focus_id() == aid

        display.on_repeat_result("transport", aid, 200, {"ok": False, "error": "source_active"})
        assert display.manual_focus_id() is None
        assert display._focus_pending is None

    def test_on_repeat_result_success_does_not_clear_pending_focus(self):
        aid = "1" * 20 + "a" * 0
        aid = "a" * 19 + "1"
        display, fb, gt = _make_display(targets=[])
        display.set_manual_focus_pending(aid, "Kitchen")
        display._poll_once()
        display.on_repeat_result(
            "transport", aid, 200,
            {"ok": True, "state": "replaying", "armed": True, "position_seconds": 0.0},
        )
        assert display.manual_focus_id() == aid
        assert display._focus_pending is not None


# ---------------------------------------------------------------------------
# The replay picker: rows from held+authorized+capable roster entries,
# picker_pick starting a replay with a pending focus, stale-index handling,
# and the shared inactivity timeout.
# ---------------------------------------------------------------------------

class TestReplayPickerRows:
    def _roster_row(self, aid, name, playing=False, repeat_capable=True, auth="authorized"):
        from dial_mdns import RosterEntry
        return RosterEntry(
            appliance_id=aid, service_name=name, name=name, ip="10.0.0.9", port=8080,
            playing=playing, repeat_capable=repeat_capable, auth=auth,
        )

    def test_rows_from_held_authorized_capable_only(self):
        import dial_repeat_store as drs
        display, fb, gt = _make_display(targets=[])
        now = time.monotonic()

        held_ok = self._roster_row("1" * 20, "Held")
        held_unauth = self._roster_row("2" * 20, "Unauth", auth="unknown")
        held_incapable = self._roster_row("3" * 20, "Incapable", repeat_capable=False)
        not_held = self._roster_row("4" * 20, "Idle")

        drs.repeat_store.update("1" * 20, drs.parse_repeat_object(_repeat_obj(state="hold", recording_seconds=42.0), now))
        drs.repeat_store.update("2" * 20, drs.parse_repeat_object(_repeat_obj(state="hold"), now))
        drs.repeat_store.update("3" * 20, drs.parse_repeat_object(_repeat_obj(state="hold"), now))
        drs.repeat_store.update("4" * 20, drs.parse_repeat_object(_repeat_obj(state="idle"), now))

        display._refresh_picker_rows(
            [held_ok, held_unauth, held_incapable, not_held], now,
        )
        assert [r.appliance_id for r in display._picker.rows] == ["1" * 20]
        assert display._picker.rows[0].seconds == 42.0

    def test_open_picker_sets_screen_request(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display.open_picker()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "picker"

    def test_picker_shows_placeholder_when_empty(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
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
        display, fb, gt = _make_display(targets=[])
        display.enable()
        row = RosterEntry(
            appliance_id=aid, service_name="Kitchen", name="Kitchen", ip="10.0.0.9", port=8080,
            playing=False, repeat_capable=True, auth="authorized",
        )
        now = time.monotonic()
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="hold", recording_seconds=12.0), now))
        display._refresh_picker_rows([row], now)
        display.open_picker()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "picker"
        return display, fb, gt

    def test_pick_sets_pending_focus_and_enqueues_seek(self):
        display, fb, gt = self._opened_with_row(aid="a" * 20)
        with patch("dial_display.enqueue_transport") as mock_transport:
            display.picker_pick(0)
        mock_transport.assert_called_once()
        target, action, position = mock_transport.call_args[0]
        assert target.appliance_id == "a" * 20
        assert action == "seek"
        assert position == 0.0
        assert display.manual_focus_id() == "a" * 20
        assert display._focus_pending is not None

    def test_pick_closes_the_picker(self):
        display, fb, gt = self._opened_with_row()
        with patch("dial_display.enqueue_transport"):
            display.picker_pick(0)
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"

    def test_stale_index_is_back_no_focus_no_enqueue(self):
        display, fb, gt = self._opened_with_row()
        with patch("dial_display.enqueue_transport") as mock_transport:
            display.picker_pick(5)
        mock_transport.assert_not_called()
        assert display.manual_focus_id() is None
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"


class TestPickerTimeout:
    def test_closes_after_timeout(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display.open_picker()
        with display._lock:
            display._repaint_current_locked()
        opened_at = display._picker.opened_at
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS + 1):
            display._check_secondary_timeout()
        assert display._screen == "main"

    def test_stays_open_before_timeout(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display.open_picker()
        with display._lock:
            display._repaint_current_locked()
        opened_at = display._picker.opened_at
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS - 1):
            display._check_secondary_timeout()
        assert display._screen == "picker"


# ---------------------------------------------------------------------------
# on_repeat_result: the worker-thread callback wired to dial_repeat.py.
# ---------------------------------------------------------------------------

class TestOnRepeatResult:
    def test_ok_true_applies_ack_and_signals_repaint(self):
        import dial_repeat_store as drs
        aid = "1" * 20
        display, fb, gt = _make_display(targets=[])
        now = time.monotonic()
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="hold"), now))
        display._overlay_signal.clear()

        display.on_repeat_result(
            "transport", aid, 200,
            {"ok": True, "state": "replaying", "armed": True, "position_seconds": 0.0},
        )
        rec = drs.repeat_store.get(aid, time.monotonic())
        assert rec.state == "replaying"
        assert rec.armed is True
        assert display._overlay_signal.is_set()

    def test_412_forces_due_and_requests_poll_never_touches_auth(self):
        aid = "2" * 20
        display, fb, gt = _make_display(targets=[])
        display._poll_wake.clear()
        with patch("dial_auth.auth_map.force_due") as mock_force_due, \
             patch("dial_auth.auth_map.apply") as mock_apply:
            display.on_repeat_result("transport", aid, 412, {"ok": False, "error": "dial_not_authorized"})
        mock_force_due.assert_called_once_with(aid)
        mock_apply.assert_not_called()
        assert display._poll_wake.is_set()
        assert display._reconcile_due is True

    def test_ok_false_source_active_clears_the_record(self):
        import dial_repeat_store as drs
        aid = "3" * 20
        display, fb, gt = _make_display(targets=[])
        now = time.monotonic()
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="hold"), now))

        display.on_repeat_result("transport", aid, 200, {"ok": False, "error": "source_active"})
        assert drs.repeat_store.get(aid, time.monotonic()) is None

    def test_ok_false_no_recording_clears_the_record(self):
        import dial_repeat_store as drs
        aid = "4" * 20
        display, fb, gt = _make_display(targets=[])
        now = time.monotonic()
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="hold"), now))

        display.on_repeat_result("transport", aid, 200, {"ok": False, "error": "no_recording"})
        assert drs.repeat_store.get(aid, time.monotonic()) is None

    def test_ok_false_other_error_leaves_the_record(self):
        import dial_repeat_store as drs
        aid = "5" * 20
        display, fb, gt = _make_display(targets=[])
        now = time.monotonic()
        rec = drs.parse_repeat_object(_repeat_obj(state="hold"), now)
        drs.repeat_store.update(aid, rec)

        display.on_repeat_result("transport", aid, 200, {"ok": False, "error": "fading_out"})
        assert drs.repeat_store.get(aid, time.monotonic()) == rec

    def test_transient_status_none_nudges_only_no_store_change(self):
        import dial_repeat_store as drs
        aid = "6" * 20
        display, fb, gt = _make_display(targets=[])
        now = time.monotonic()
        rec = drs.parse_repeat_object(_repeat_obj(state="hold"), now)
        drs.repeat_store.update(aid, rec)

        with patch("dial_auth.auth_map.force_due") as mock_force_due:
            display.on_repeat_result("transport", aid, None, None)
        mock_force_due.assert_called_once_with(aid)
        assert drs.repeat_store.get(aid, time.monotonic()) == rec

    def test_transient_other_http_code_nudges_only(self):
        aid = "7" * 20
        display, fb, gt = _make_display(targets=[])
        with patch("dial_auth.auth_map.force_due") as mock_force_due:
            display.on_repeat_result("transport", aid, 500, None)
        mock_force_due.assert_called_once_with(aid)

    def test_takes_no_lock(self):
        """Regression guard for the invariant that on_repeat_result never
        takes DialDisplay._lock — simulated by holding the lock on this
        (the calling) thread and confirming the call still returns."""
        aid = "8" * 20
        display, fb, gt = _make_display(targets=[])
        with display._lock:
            display.on_repeat_result("transport", aid, 200, {"ok": True, "state": "hold",
                                                              "armed": False, "position_seconds": 0.0})


# ---------------------------------------------------------------------------
# Playing-set shrink: a source that stops playing forces an immediate
# reconcile so its retained recording reaches the idle screen and picker.
# ---------------------------------------------------------------------------

class TestReconcileOnPlayingSetShrink:
    def test_shrinking_playing_set_forces_reconcile(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display._prev_playing_ids = {"a" * 20}
        display._reconcile_due = False
        display._last_reconcile_at = time.monotonic()  # cadence alone would NOT fire
        gt.return_value = []  # the source that was playing has stopped
        with patch.object(display, "_reconcile_pass") as rp:
            display._poll_once()
        rp.assert_called_once()

    def test_unchanged_playing_set_respects_cadence(self):
        aid = "a" * 20
        t = _target(appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        display._prev_playing_ids = {aid}
        display._reconcile_due = False
        display._last_reconcile_at = time.monotonic()  # cadence alone would NOT fire
        with patch.object(display, "_reconcile_pass") as rp, \
             patch("dial_display.fetch_target_status",
                   return_value=_status_result(appliance_id=aid)):
            display._poll_once()
        rp.assert_not_called()


class TestIdleReplayLogo:
    """When a replay is available the idle screen renders the replay-logo
    (the arrows-on-disc image), not the plain logo or any text."""

    def test_idle_render_requests_the_replay_logo(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._current_base_image = MagicMock()
            with patch("dial_display.load_logo", return_value=MagicMock()) as ll:
                display._display_idle_locked()
        assert ll.call_args_list[0].args[0] == display._replay_logo_path

    def test_idle_render_falls_back_to_plain_base_when_replay_logo_missing(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        base = MagicMock()
        with display._lock:
            display._current_base_image = base
            with patch("dial_display.load_logo", return_value=None):
                # Must not raise when the replay image cannot be loaded.
                display._display_idle_locked()


class TestPickerSurvivesIdle:
    """The replay picker is the idle-state screen for choosing a held
    recording, so a poll that finds nothing playing must NOT close it (the
    appliance selector, by contrast, is closed when nothing plays)."""

    def test_picker_stays_open_when_nothing_playing(self):
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "main"
            display._screen_request = "picker"
        gt.return_value = []
        with patch.object(display, "_close_secondary_locked") as close:
            display._poll_once()
        close.assert_not_called()

    def test_selector_closes_when_nothing_playing(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "selector"
        gt.return_value = []
        with patch.object(display, "_close_secondary_locked") as close:
            display._poll_once()
        close.assert_called()


# ---------------------------------------------------------------------------
# _refresh_idle_affordance: the idle screen's own "should I draw the
# affordance" computation.
# ---------------------------------------------------------------------------

class TestRefreshIdleAffordance:
    def _roster_row(self, aid, auth="authorized", repeat_capable=True):
        from dial_mdns import RosterEntry
        return RosterEntry(
            appliance_id=aid, service_name="Kitchen", name="Kitchen", ip="10.0.0.9", port=8080,
            playing=False, repeat_capable=repeat_capable, auth=auth,
        )

    def test_true_when_a_held_authorized_capable_row_exists(self):
        import dial_repeat_store as drs
        display, fb, gt = _make_display(targets=[])
        aid = "1" * 20
        now = time.monotonic()
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="hold"), now))
        display._refresh_idle_affordance([self._roster_row(aid)], now)
        assert display._idle_affordance is True

    def test_false_when_unauthorized(self):
        import dial_repeat_store as drs
        display, fb, gt = _make_display(targets=[])
        aid = "2" * 20
        now = time.monotonic()
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="hold"), now))
        display._refresh_idle_affordance([self._roster_row(aid, auth="unknown")], now)
        assert display._idle_affordance is False

    def test_false_when_not_repeat_capable(self):
        import dial_repeat_store as drs
        display, fb, gt = _make_display(targets=[])
        aid = "3" * 20
        now = time.monotonic()
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="hold"), now))
        display._refresh_idle_affordance([self._roster_row(aid, repeat_capable=False)], now)
        assert display._idle_affordance is False

    def test_false_when_not_held(self):
        import dial_repeat_store as drs
        display, fb, gt = _make_display(targets=[])
        aid = "4" * 20
        now = time.monotonic()
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="replaying"), now))
        display._refresh_idle_affordance([self._roster_row(aid)], now)
        assert display._idle_affordance is False

    def test_change_signals_overlay(self):
        import dial_repeat_store as drs
        display, fb, gt = _make_display(targets=[])
        aid = "5" * 20
        now = time.monotonic()
        drs.repeat_store.update(aid, drs.parse_repeat_object(_repeat_obj(state="hold"), now))
        display._overlay_signal.clear()
        display._refresh_idle_affordance([self._roster_row(aid)], now)
        assert display._overlay_signal.is_set()
