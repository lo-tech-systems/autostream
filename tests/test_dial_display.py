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
import io
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
from dial_display_profiles import (
    DEFAULT_PROFILE_KEY,
    effective_diagonal_inches,
    get_profile,
    layout_context_for,
    mm_per_px_for,
    mm_per_px_for_size,
)
from dial_mdns import PlayingTarget
from dial_touch_layout import TouchZone, list_layout_for, metrics_for
import dial_display as dd
from dial_display import (
    SCREEN_POLICIES,
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


def _roster_entry(
    name="Kitchen", ip="192.168.1.10", port=80,
    dial_status=True, appliance_id="a" * 20, auth="unknown",
    service_name=None, playing=False, repeat_capable=False, dial_outputs=False,
):
    """A merged-roster entry — the RosterEntry counterpart to _target(),
    for tests that need an idle (playing=False) or explicitly playing row
    without going through a PlayingTarget/get_display_targets at all."""
    from dial_mdns import RosterEntry
    return RosterEntry(
        appliance_id=appliance_id, service_name=service_name or name, name=name,
        ip=ip, port=port, playing=playing, repeat_capable=repeat_capable,
        dial_api=True, audio_status=True, dial_status=dial_status, dial_outputs=dial_outputs,
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


def _status_result(track_id=None, status_error=None, appliance_id=None, muted=False) -> dict:
    return {
        "playing": True, "master_volume": 50, "selected_output_count": 1,
        "track_id": track_id, "status_error": status_error,
        "appliance_id": appliance_id, "muted": muted,
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
    always_show_controls=False, screen_size_inches=None, layout_size=None,
    targets=None, backend=None,
    get_targets=None,
    get_roster=None,
    roster=None,
    backend_factory_builder=None,
) -> tuple[DialDisplay, FakeBackend, MagicMock]:
    cfg = DialDisplayConfig(
        fitted=fitted, rotate=rotate, bgr=bgr, screen_type=screen_type,
        always_show_controls=always_show_controls, screen_size_inches=screen_size_inches,
        layout_size=layout_size,
    )
    fb = backend or FakeBackend()
    gt = get_targets or MagicMock(return_value=targets or [])
    if get_roster is not None:
        gr = get_roster
    elif roster is not None:
        # Convenience for tests that want to supply the merged roster
        # directly (e.g. an idle appliance alongside the playing targets)
        # rather than building it from *targets*.
        gr = lambda: roster
    else:
        gr = lambda: _roster_from_targets(gt())
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

class TestMuteObservationFromStatusPoll:
    """The poll observes the reported `muted` flag into dial_volume's
    per-service observation store for every target it actually walked, not
    only the reporting-from one -- it never infers mute from a volume. Each
    target has its own entry, so one target's flag can never leak into
    another's; the glyph itself still reads back only the reporting/bound
    service's entry (see TestEffectiveOverlayMerge), unaffected by what else
    the store now holds (see dial_volume.observe_mute_state/shown_muted)."""

    def test_muted_field_observed_for_the_reporting_target(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=None, muted=True)), \
             patch("dial_display.observe_mute_state") as mock_observe:
            display._poll_once()
        mock_observe.assert_called_once_with(t.service_name, True)

    def test_unmuted_field_observed_as_false(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=None, muted=False)), \
             patch("dial_display.observe_mute_state") as mock_observe:
            display._poll_once()
        mock_observe.assert_called_once_with(t.service_name, False)

    def test_status_error_response_observes_none(self):
        """A status_error response is never stored in the poll's `records`
        map, so the reporting target's muted observation is None (unknown)
        -- never left stale from a previous successful poll's inference,
        and never a guess."""
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(status_error="timeout")), \
             patch("dial_display.observe_mute_state") as mock_observe:
            display._poll_once()
        mock_observe.assert_called_once_with(t.service_name, None)

    def test_muted_on_every_walked_target_is_observed(self):
        """Two targets, neither identified: the walk visits both before
        falling back to the oldest-playing (first) one as reporting-from --
        both targets' muted flags reach the (per-service) observation store,
        each in its own entry, not only the reporting one."""
        t_reporting = _target(name="Older", service_name="older", playing_since=10.0)
        t_other = _target(name="Newer", service_name="newer", playing_since=20.0)
        display, fb, gt = _make_display(targets=[t_reporting, t_other])
        display.enable()

        def fake_fetch(target, dial_id, timeout_seconds):
            return _status_result(track_id=None, muted=(target.service_name != "older"))

        with patch("dial_display.fetch_target_status", side_effect=fake_fetch), \
             patch("dial_display.observe_mute_state") as mock_observe:
            display._poll_once()
        mock_observe.assert_any_call("older", False)
        mock_observe.assert_any_call("newer", True)
        assert mock_observe.call_count == 2

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

    def test_forget_mute_states_except_called_with_current_playing_targets(self):
        """Each poll tick prunes the per-service store down to the targets
        actually playing this tick, so a target that has since stopped does
        not accumulate a stale entry forever."""
        t_a = _target(name="A", service_name="svc-a", playing_since=10.0)
        t_b = _target(name="B", service_name="svc-b", playing_since=20.0)
        display, fb, gt = _make_display(targets=[t_a, t_b])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=None, muted=False)), \
             patch("dial_display.forget_mute_states_except") as mock_forget:
            display._poll_once()
        mock_forget.assert_called_once()
        assert set(mock_forget.call_args[0][0]) == {"svc-a", "svc-b"}

    def test_muted_flag_actually_reaches_the_real_observation_store(self):
        """End-to-end against the real dial_volume module (not a mock of
        observe_mute_state) — proves the two modules are actually wired
        together, not just that dial_display calls a same-named stub."""
        import dial_volume as dv
        dv.observe_mute_state(None, None)
        try:
            t = _target()
            display, fb, gt = _make_display(targets=[t])
            display.enable()
            with patch("dial_display.fetch_target_status",
                       return_value=_status_result(track_id=None, muted=True)):
                display._poll_once()
            assert dv.shown_muted(t.service_name) is True
        finally:
            dv.observe_mute_state(None, None)


# ---------------------------------------------------------------------------
# NowPlaying's album field: defaulted and appended last, so every existing
# positional construction (display code and tests alike) keeps working
# unchanged, and an album-only difference still counts for the `!=` check
# _poll_once uses to decide whether to repaint.
# ---------------------------------------------------------------------------

class TestNowPlayingDataclass:
    def test_positional_construction_without_album_still_works(self):
        now_playing = dd.NowPlaying("svc", "A", "T", 50)
        assert now_playing.album == ""

    def test_album_only_difference_is_unequal(self):
        assert dd.NowPlaying("svc", "A", "T", 50, album="X") != dd.NowPlaying("svc", "A", "T", 50)

    def test_same_album_is_equal(self):
        assert dd.NowPlaying("svc", "A", "T", 50, album="X") == dd.NowPlaying("svc", "A", "T", 50, album="X")

    def test_playing_defaults_to_true(self):
        assert dd.NowPlaying("svc", "A", "T", 50).playing is True

    def test_playing_only_difference_is_unequal(self):
        # What triggers a repaint on a focused appliance starting or
        # stopping, even when every other field stays the same.
        assert dd.NowPlaying("svc", "", "", 50, playing=False) != dd.NowPlaying("svc", "", "", 50, playing=True)


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
        assert display._now_playing.album == "Album"
        assert display._now_playing.service_name == t.service_name
        # The reporting target's master_volume (from _status_result's
        # default of 50) reaches observe_master_volume.
        mock_observe.assert_called_once_with(t.service_name, 50)

    def test_identified_target_without_album_gives_empty_string(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(album=""))):
            display._poll_once()
        assert display._now_playing.album == ""

    def test_non_identified_target_gives_empty_album(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(state="pending"))):
            display._poll_once()
        assert display._now_playing.album == ""

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

    def test_album_only_change_sets_overlay_signal(self):
        # Two polls differing only in album must still count as "now-playing
        # changed" — NowPlaying's == comparison sees every field.
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(album="First Album"))):
            display._poll_once()
        assert display._now_playing.album == "First Album"

        display._overlay_signal.clear()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(album="Second Album"))):
            display._poll_once()
        assert display._now_playing.album == "Second Album"
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


class TestPushFrameLocked:
    def test_compose_raising_records_failure_and_skips_the_backend(self):
        display, fb, gt = _make_display()
        display.enable()
        before = len(fb.displayed)

        def bad_compose():
            raise RuntimeError("compose blew up")

        with display._lock:
            display._push_frame_locked(bad_compose)
        assert display.get_status()["last_error"] == "display_write_failed"
        assert len(fb.displayed) == before

    def test_backend_raising_records_the_same_failure(self):
        display, fb, gt = _make_display(backend=FakeBackend(fail_display=True))
        display.enable()
        with display._lock:
            display._push_frame_locked(lambda: object())
        assert display.get_status()["last_error"] == "display_write_failed"

    def test_success_pushes_exactly_once_and_records_no_error(self):
        display, fb, gt = _make_display()
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
        display, fb, gt = _make_display()
        display.enable()
        sentinel = Image.new("RGB", (fb.width, fb.height))
        with display._lock:
            display._push_frame_locked(lambda: sentinel)
        assert display._last_frame is sentinel

    def test_failed_push_keeps_the_previous_last_frame(self):
        display, fb, gt = _make_display()
        display.enable()
        previous = display._last_frame
        assert previous is not None

        def bad_compose():
            raise RuntimeError("compose blew up")

        with display._lock:
            display._push_frame_locked(bad_compose)
        assert display._last_frame is previous


# ---------------------------------------------------------------------------
# _last_frame lifecycle — retained across a push, dropped whenever the
# panel no longer shows it.
# ---------------------------------------------------------------------------

class TestLastFrameLifecycle:
    def test_none_on_a_fresh_display(self):
        display, fb, gt = _make_display()
        assert display._last_frame is None

    def test_set_after_enable_renders_the_logo(self):
        display, fb, gt = _make_display()
        display.enable()
        assert display._last_frame is not None
        assert display._last_frame.size == (fb.width, fb.height)

    def test_cleared_by_disable_locked(self):
        display, fb, gt = _make_display()
        display.enable()
        assert display._last_frame is not None
        with display._lock:
            display._disable_locked()
        assert display._last_frame is None

    def test_cleared_by_sleep_locked(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        assert display._last_frame is not None
        with display._lock:
            display._sleep_locked()
        assert display._last_frame is None

    def test_cleared_by_clear_locked(self):
        display, fb, gt = _make_display()
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

        display, _, gt = _make_display(
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
        display, fb, gt = _make_display()
        assert display.latest_frame_png() is None

    def test_round_trips_a_decodable_png_at_the_backend_size(self):
        display, fb, gt = _make_display()
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
        display, fb, gt = _make_display(rotate=True)
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
        display, fb, gt = _make_display(bgr=True)
        display.enable()
        marked = Image.new("RGB", (fb.width, fb.height), (10, 20, 30))
        with display._lock:
            display._push_frame_locked(lambda: marked)
        decoded = Image.open(io.BytesIO(display.latest_frame_png())).convert("RGB")
        assert decoded.getpixel((0, 0)) == (30, 20, 10)

    def test_cleared_state_reports_none(self):
        display, fb, gt = _make_display()
        display.enable()
        assert display.latest_frame_png() is not None
        with display._lock:
            display._clear_locked()
        assert display.latest_frame_png() is None

    def test_encode_does_not_hold_the_lock(self):
        display, fb, gt = _make_display()
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
        display, fb, gt = _make_display()
        display.enable()
        with patch.object(Image.Image, "save", side_effect=RuntimeError("encode blew up")):
            assert display.latest_frame_png() is None


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
# Screen-size setting (physical diagonal) — mm_per_px derivation and its
# plumbing into _metrics_locked() / redisplay-on-change. Density has no
# effect on rendered bytes in this stage (see test_dial_display_compositor.py
# for that invariant); these tests cover the manager's own bookkeeping.
# ---------------------------------------------------------------------------

class TestScreenSizeSetting:
    def test_init_derives_mm_per_px_from_profile_default(self):
        display, fb, gt = _make_display(fitted=False, screen_type=DEFAULT_PROFILE_KEY)
        profile = get_profile(DEFAULT_PROFILE_KEY)
        expected = mm_per_px_for(profile, profile.default_diagonal_inches)
        assert display._mm_per_px == pytest.approx(expected)

    def test_init_derives_mm_per_px_from_override(self):
        display, fb, gt = _make_display(fitted=False, screen_size_inches=3.5)
        profile = get_profile(DEFAULT_PROFILE_KEY)
        expected = mm_per_px_for(profile, 3.5)
        assert display._mm_per_px == pytest.approx(expected)

    def test_update_config_size_only_change_redisplays_synchronously(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t], fitted=True)
        display.enable()

        fake_image = _marked_image(size=(fb.width, fb.height))
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
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
        display, fb, gt = _make_display(fitted=True)
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

        display, _, gt = _make_display(
            fitted=True, screen_type="st7735s_160x128", backend=fb_old,
            backend_factory_builder=builder,
        )
        display.enable()
        display.update_config(DialDisplayConfig(fitted=True, screen_type="st7789_240x240"))

        new_profile = get_profile("st7789_240x240")
        expected = mm_per_px_for(new_profile, new_profile.default_diagonal_inches)
        assert display._mm_per_px == pytest.approx(expected)

    def test_metrics_locked_reflects_backend_dims_and_density(self):
        display, fb, gt = _make_display(fitted=True, screen_size_inches=2.8)
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
        img = _marked_image(size=(FakeBackend.width, FakeBackend.height))

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
        img = _marked_image(size=(FakeBackend.width, FakeBackend.height))

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
        img = _marked_image(size=(FakeBackend.width, FakeBackend.height))

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

    def test_no_now_playing_muted_is_always_false(self):
        """With nothing playing there is no reporting-from target, so muted
        is always False regardless of the observation store or whatever the
        touch-published snapshot itself carries."""
        import dial_volume as dv
        display, fb, gt = _make_display(targets=[])
        display.enable()
        dv.observe_mute_state("svc", True)
        try:
            result = display._effective_overlay_locked(OverlayState(visible=True, muted=True))
            assert result.muted is False
        finally:
            dv.observe_mute_state(None, None)

    def test_muted_is_read_from_the_observation_store_for_now_playings_service(self):
        import dial_volume as dv
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._now_playing = dd.NowPlaying("svc", "Artist", "Title", 50)
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
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._now_playing = dd.NowPlaying("svc", "Artist", "Title", 50)
        dv.observe_mute_state("svc", False)
        try:
            result = display._effective_overlay_locked(OverlayState(visible=True, muted=True))
            assert result.muted is False
        finally:
            dv.observe_mute_state(None, None)

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

    def test_visible_snapshot_merges_album(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._now_playing = dd.NowPlaying("svc", "The Artist", "Title", 50, album="The Album")
        result = display._effective_overlay_locked(OverlayState(visible=True, muted=False))
        assert result.album == "The Album"

    def test_no_now_playing_merges_empty_artist_and_none_volume(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        result = display._effective_overlay_locked(OverlayState(visible=True, muted=False))
        assert result.artist == ""
        assert result.title == ""
        assert result.volume is None
        assert result.album == ""

    def test_visible_field_survives_the_merge_unchanged(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        result = display._effective_overlay_locked(OverlayState(visible=True))
        assert result.visible is True

    def test_pressed_comes_from_the_channel_not_the_snapshot(self):
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._now_playing = dd.NowPlaying("svc", "", "", 50, playing=False)
        with patch.object(display, "_layout_metrics", return_value=MagicMock(content_tier=content_tier)):
            result = display._effective_overlay_locked(OverlayState(visible=True))
        assert result.artist == dd.IDLE_ARTIST_TEXT

    @pytest.mark.parametrize("tier", ["rich", "large"])
    def test_playing_with_no_title_shows_playing_text(self, tier):
        content_tier = dd.CONTENT_RICH if tier == "rich" else dd.CONTENT_LARGE
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._now_playing = dd.NowPlaying("svc", "", "", 50, playing=True)
        with patch.object(display, "_layout_metrics", return_value=MagicMock(content_tier=content_tier)):
            result = display._effective_overlay_locked(OverlayState(visible=True))
        assert result.artist == dd.PLAYING_ARTIST_TEXT

    def test_playing_with_title_and_no_artist_stays_empty(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._now_playing = dd.NowPlaying("svc", "", "Some Title", 50, playing=True)
        with patch.object(display, "_layout_metrics", return_value=MagicMock(content_tier=dd.CONTENT_RICH)):
            result = display._effective_overlay_locked(OverlayState(visible=True))
        assert result.artist == ""

    def test_playing_with_title_and_artist_keeps_the_real_artist(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._now_playing = dd.NowPlaying("svc", "Real Artist", "Some Title", 50, playing=True)
        with patch.object(display, "_layout_metrics", return_value=MagicMock(content_tier=dd.CONTENT_LARGE)):
            result = display._effective_overlay_locked(OverlayState(visible=True))
        assert result.artist == "Real Artist"

    def test_base_tier_artist_row_is_unaffected(self):
        # _make_display defaults to the base (160x128) tier -- no patch
        # needed, this is the tier's own natural resolution.
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._now_playing = dd.NowPlaying("svc", "", "", 50, playing=False)
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
        display.set_pressed(TouchZone.UP)
        display.set_pressed(None)
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
        # A playing target, not an idle one: the idle screen has its own
        # compose_idle() path with no pressed-overlay content at
        # all, so this coalescing check needs the ordinary now-playing
        # overlay path to have a pressed zone worth asserting on.
        t = _target()
        display, fb, gt = _make_display(targets=[t])
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
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        display.set_overlay(OverlayState(visible=True))
        display.set_pressed(TouchZone.UP)

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
# "Always show controls" held-visible overlay: persistent_overlay_shown(),
# the "a controllable appliance is shown" gate (self._now_playing is not
# None) that _display_locked's base image no longer needs to track, and the
# forced-visible merge in _effective_overlay_locked().
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
        display, fb, gt = _make_display(targets=[ta])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        before = len(fb.displayed)

        gt.return_value = [tb]
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()

        pushed = fb.displayed[before:]
        assert len(pushed) == 2
        transition_frame, logo_frame = pushed
        assert transition_frame.size == logo_frame.size
        cx, cy = transition_frame.width // 2, transition_frame.height // 2
        assert transition_frame.getpixel((cx, cy))[:3] == (32, 32, 32)

    def test_showing_is_waiting_while_the_new_logo_has_not_landed_yet(self):
        ta, tb = self._target_pair()
        display, fb, gt = _make_display(targets=[ta])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()

        gt.return_value = [tb]
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)), \
             patch.object(display, "show_logo") as mock_show_logo:
            display._poll_once()
        mock_show_logo.assert_called_once()
        assert display._showing == "waiting"

    def test_no_transition_frame_when_reporting_id_unchanged(self):
        ta, _ = self._target_pair()
        display, fb, gt = _make_display(targets=[ta])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        before = len(fb.displayed)
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        pushed = fb.displayed[before:]
        assert len(pushed) <= 1  # at most the (deduped-away) logo re-render, never a transition

    def test_no_transition_frame_on_the_very_first_poll(self):
        # enable() already rendered the logo; the first poll's own
        # show_logo() call dedupes against it (still "logo") -- no stale
        # artwork to guard against on a fresh start, so nothing more is
        # pushed at all, let alone a transition frame.
        ta, _ = self._target_pair()
        display, fb, gt = _make_display(targets=[ta])
        display.enable()
        before = len(fb.displayed)
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        pushed = fb.displayed[before:]
        assert len(pushed) == 0

    def test_no_transition_frame_when_switching_to_nothing_playing(self):
        ta, _ = self._target_pair()
        display, fb, gt = _make_display(targets=[ta])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        before = len(fb.displayed)
        gt.return_value = []
        display._poll_once()
        pushed = fb.displayed[before:]
        assert len(pushed) == 0  # still deduped against the same logo -- no transition either

    def test_show_transition_locked_is_a_noop_when_backend_closed(self):
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display._now_playing is not None
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
        display, fb, gt = _make_display(targets=[], always_show_controls=True)
        display.enable()
        assert display._now_playing is None
        assert display.get_status()["showing"] == "logo"
        assert display.persistent_overlay_shown() is False
        result = display._effective_overlay_locked(OverlayState(visible=False))
        assert result.visible is False

    def test_redisplay_current_locked_renders_logo_when_nothing_cached(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._redisplay_current_locked()
        assert display.get_status()["showing"] == "logo"

    def test_clear_sleep_disable_swap_leave_no_overlay_held(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.persistent_overlay_shown() is True
        with display._lock:
            display._clear_locked()
        assert display.persistent_overlay_shown() is False

        display2, fb2, gt2 = _make_display(targets=[t], always_show_controls=True)
        display2.enable()
        _poll_with_artwork(display2, fb2)
        with display2._lock:
            display2._sleep_locked()
        assert display2.persistent_overlay_shown() is False

        display3, fb3, gt3 = _make_display(targets=[t], always_show_controls=True)
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

        display, _, gt = _make_display(
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


class TestHideControls:
    """Item 9: tapping the artwork hides the bands for CONTROLS_HIDE_
    SECONDS — see hide_controls()/_controls_hidden()."""

    def test_hide_controls_sets_deadline_and_signals(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        display._overlay_signal.clear()
        with patch("dial_display.time.monotonic", return_value=1000.0):
            display.hide_controls()
        assert display._controls_hidden_until == pytest.approx(1000.0 + dd.CONTROLS_HIDE_SECONDS)
        assert display._overlay_signal.is_set()

    def test_persistent_overlay_shown_false_during_window_true_after(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t], always_show_controls=True)
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
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display.hide_controls()
        assert display._controls_hidden() is True
        display.set_overlay(dd.OverlayState(visible=True))
        assert display._controls_hidden() is False

    def test_set_overlay_invisible_does_not_end_the_window(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display.hide_controls()
        display.set_overlay(dd.OverlayState(visible=False))
        assert display._controls_hidden() is True

    def test_frames_composed_during_the_window_have_no_overlay(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t], always_show_controls=True)
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
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with patch("dial_display.time.monotonic", return_value=1000.0):
            display.hide_controls()
        display._overlay_signal.clear()
        with patch("dial_display.time.monotonic", return_value=1000.0 + 1.0):
            display._tick_controls_hidden()
        assert not display._overlay_signal.is_set()

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

    def test_idle_logo_is_bare_even_when_always_show_controls_is_on(self):
        display, fb, gt = _make_display(targets=[], always_show_controls=True)
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
        display, fb, gt = _make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display._now_playing is not None
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

    def test_focus_target_album_is_read_on_the_pinned_path(self):
        aid = "8" * 19 + "a"
        focus_t = _target(name="Focus", service_name="Focus", appliance_id=aid, playing_since=1.0)
        display, fb, gt = _make_display(targets=[focus_t])
        display.enable()
        display.set_manual_focus(aid)
        fake_image = Image.new("RGB", (fb.width, fb.height))
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(album="Focused Album"), appliance_id=aid)), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()
        assert display._now_playing.album == "Focused Album"

    def test_focus_clears_when_appliance_stops_but_stays_idle_on_roster(self):
        aid = "b" * 20
        playing = _target(name="A", service_name="A", appliance_id=aid, auth="authorized")
        idle_entry = _roster_entry(name="A", service_name="A", appliance_id=aid, auth="authorized", playing=False)
        display, fb, gt = _make_display(targets=[playing], roster=[idle_entry])
        display.enable()
        display.set_manual_focus(aid)
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid)):
            display._poll_once()
        assert display.manual_focus_id() == aid

        gt.return_value = []  # the appliance stopped playing but stays rostered idle
        display._poll_once()
        assert display.manual_focus_id() is None

    def test_focus_on_idle_appliance_is_kept_when_another_starts_playing(self):
        aid_idle = "c" * 20
        idle_entry = _roster_entry(name="Idle", service_name="Idle", appliance_id=aid_idle, auth="authorized",
                                    playing=False)
        display, fb, gt = _make_display(targets=[], roster=[idle_entry])
        display.enable()
        display.set_manual_focus(aid_idle)
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid_idle)):
            display._poll_once()
        assert display.manual_focus_id() == aid_idle

        other = _target(name="Other", service_name="Other", appliance_id="d" * 20, auth="authorized")
        gt.return_value = [other]
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        assert display.manual_focus_id() == aid_idle

    def test_picking_an_idle_row_shows_it_with_no_fetch_for_playing_targets(self):
        aid_idle = "e" * 20
        idle_entry = _roster_entry(name="Idle", service_name="Idle", appliance_id=aid_idle, auth="authorized",
                                    playing=False)
        other = _target(name="Other", service_name="Other", appliance_id="f" * 20, auth="authorized")
        display, fb, gt = _make_display(targets=[other], roster=[idle_entry])
        display.enable()
        display.set_manual_focus(aid_idle)  # simulates selector_pick's effect on an idle row

        calls = []

        def fake_fetch(target, dial_id, timeout_seconds):
            calls.append(target.service_name)
            return _status_result(track_id=None, appliance_id=target.appliance_id)

        with patch("dial_display.fetch_target_status", side_effect=fake_fetch):
            display._poll_once()

        assert calls == ["Idle"]
        assert display._now_playing == dd.NowPlaying("Idle", "", "", 50, playing=False)
        assert display._reporting_appliance_id == aid_idle
        assert display._source_service_name == "Idle"

    def test_idle_focus_unauthorized_clears_mid_tick_and_walk_falls_through(self):
        aid_idle = "5" * 20
        idle_entry = _roster_entry(name="Idle", service_name="Idle", appliance_id=aid_idle, auth="authorized",
                                    playing=False)
        other = _target(name="Other", service_name="Other", appliance_id="6" * 20, auth="authorized")
        display, fb, gt = _make_display(targets=[other], roster=[idle_entry])
        display.enable()
        display.set_manual_focus(aid_idle)

        def fake_fetch(target, dial_id, timeout_seconds):
            if target is idle_entry:
                return _status_result(status_error="unauthorized", appliance_id=aid_idle)
            return _status_result(track_id=None, appliance_id=target.appliance_id)

        with patch("dial_display.fetch_target_status", side_effect=fake_fetch):
            display._poll_once()

        assert display.manual_focus_id() is None
        assert display._now_playing is not None
        assert display._now_playing.service_name == "Other"
        assert display._reporting_appliance_id == "6" * 20

    def test_focus_volume_target_none_without_a_focus(self):
        display, fb, gt = _make_display(targets=[])
        display._last_roster = [_roster_entry(appliance_id="3" * 20, auth="authorized")]
        assert display.focus_volume_target() is None

    def test_focus_volume_target_returns_the_roster_entry_while_focused(self):
        aid = "4" * 20
        entry = _roster_entry(name="Kitchen", service_name="Kitchen", appliance_id=aid, auth="authorized",
                               playing=False)
        display, fb, gt = _make_display(targets=[])
        display._manual_focus_id = aid
        display._last_roster = [entry]
        assert display.focus_volume_target() is entry

    def test_focus_volume_target_none_when_entry_unauthorized(self):
        aid = "2" * 20
        entry = _roster_entry(name="Kitchen", service_name="Kitchen", appliance_id=aid, auth="unauthorized",
                               playing=False)
        display, fb, gt = _make_display(targets=[])
        display._manual_focus_id = aid
        display._last_roster = [entry]
        assert display.focus_volume_target() is None


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

    def test_idle_roster_entry_appears_unmarked_beside_a_playing_one(self):
        playing_target = _target(
            name="Playing", service_name="Playing", appliance_id="1" * 20, auth="authorized",
        )
        roster = [
            _roster_entry(
                name="Playing", service_name="Playing", appliance_id="1" * 20,
                auth="authorized", playing=True,
            ),
            _roster_entry(
                name="Idle", service_name="Idle", appliance_id="2" * 20,
                auth="authorized", playing=False,
            ),
        ]
        display, fb, gt = _make_display(targets=[playing_target], roster=roster)
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        rows = display._selector.rows
        # Roster order, not resorted here — playing first, then idle.
        assert [r.appliance_id for r in rows] == ["1" * 20, "2" * 20]
        assert [r.playing for r in rows] == [True, False]


class TestSelectorAndPickerRowsSignalRepaint:
    """A row rebuild that changes what would be painted must repaint even
    with nothing else moving on screen — see _refresh_selector_rows and
    _refresh_picker_rows."""

    def test_selector_signals_when_rows_change_and_screen_requested(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display._screen_request = "selector"
        roster = [_roster_entry(name="A", appliance_id="a" * 20, auth="authorized", playing=True)]
        display._overlay_signal.clear()

        display._refresh_selector_rows(roster, reporting_id=None)

        assert [r.appliance_id for r in display._selector.rows] == ["a" * 20]
        assert display._overlay_signal.is_set()

    def test_selector_signals_when_rows_change_and_screen_showing(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "selector"
        roster = [_roster_entry(name="A", appliance_id="a" * 20, auth="authorized", playing=True)]
        display._overlay_signal.clear()

        display._refresh_selector_rows(roster, reporting_id=None)

        assert display._overlay_signal.is_set()

    def test_selector_no_signal_when_rows_unchanged(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display._screen_request = "selector"
        roster = [_roster_entry(name="A", appliance_id="a" * 20, auth="authorized", playing=True)]
        display._refresh_selector_rows(roster, reporting_id=None)
        display._overlay_signal.clear()

        display._refresh_selector_rows(roster, reporting_id=None)

        assert not display._overlay_signal.is_set()

    def test_selector_no_signal_when_another_screen_showing(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        roster = [_roster_entry(name="A", appliance_id="a" * 20, auth="authorized", playing=True)]
        display._overlay_signal.clear()

        display._refresh_selector_rows(roster, reporting_id=None)

        assert display._overlay_signal.is_set() is False

    def test_picker_signals_when_rows_change_and_screen_requested(self):
        import dial_repeat_store as drs
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display._screen_request = "picker"
        now = time.monotonic()
        row = _roster_entry(name="A", appliance_id="a" * 20, auth="authorized", repeat_capable=True)
        drs.repeat_store.update("a" * 20, drs.parse_repeat_object(_repeat_obj(state="hold"), now))
        display._overlay_signal.clear()

        display._refresh_picker_rows([row], now)

        assert [r.appliance_id for r in display._picker.rows] == ["a" * 20]
        assert display._overlay_signal.is_set()

    def test_picker_no_signal_when_rows_unchanged(self):
        import dial_repeat_store as drs
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display._screen_request = "picker"
        now = time.monotonic()
        row = _roster_entry(name="A", appliance_id="a" * 20, auth="authorized", repeat_capable=True)
        drs.repeat_store.update("a" * 20, drs.parse_repeat_object(_repeat_obj(state="hold"), now))
        display._refresh_picker_rows([row], now)
        display._overlay_signal.clear()

        display._refresh_picker_rows([row], now)

        assert not display._overlay_signal.is_set()


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
        # Force the "a controllable appliance is shown" precondition
        # directly rather than faking a full artwork fetch — this test is
        # only about the selector's own gate on persistent_overlay_shown().
        with display._lock:
            display._now_playing = dd.NowPlaying("T0", "Artist", "Title", 50)
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
        display, fb, gt = _make_display(
            screen_type="ili9341_320x240", backend=fb, targets=targets,
        )
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
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
        assert display.manual_focus_id() == "3" * 20

    def test_second_page_starts_after_a_full_first_page(self):
        display, fb, gt, targets = self._rich_opened(count=6)
        display.selector_page(+1)
        with display._lock:
            display._repaint_current_locked()
        assert display._selector.page == 1
        display.selector_pick(0)  # row 0 of PAGE 1 == the sixth target overall
        assert display.manual_focus_id() == "5" * 20


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


class TestNonePathByteIdentity:
    """The None path must stay byte-identical to today: no resize, and
    _layout_metrics() computes exactly what _metrics_locked() always has."""

    def test_no_resize_when_composed_size_already_matches_physical(self):
        fb = FakeBackend()
        fb.width, fb.height = 320, 240
        display, fb, gt = _make_display(screen_type="ili9341_320x240", screen_size_inches=2.8, backend=fb)
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
        display, fb, gt = _make_display(screen_type="ili9341_320x240", screen_size_inches=2.8, backend=fb)
        display.enable()
        assert display._layout_metrics() == metrics_for(320, 240, mm_per_px=display._mm_per_px)


class TestRendersAtLogicalArrivesPhysical:
    def test_large_on_320x240_panel(self):
        fb = FakeBackend()
        fb.width, fb.height = 320, 240
        display, fb, gt = _make_display(
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
        display, fb, gt = _make_display(
            screen_type="ili9341_320x240", screen_size_inches=2.8, layout_size="small", backend=fb,
        )
        display.enable()
        assert display._current_base_image.size == (160, 128)
        assert fb.displayed[-1].size == (320, 240)

    def test_medium_on_160x128_panel(self):
        fb = FakeBackend()
        fb.width, fb.height = 160, 128
        display, fb, gt = _make_display(
            screen_type=DEFAULT_PROFILE_KEY, screen_size_inches=1.8, layout_size="medium", backend=fb,
        )
        display.enable()
        assert display._current_base_image.size == (320, 240)
        assert fb.displayed[-1].size == (160, 128)

    def test_large_artwork_poll_renders_at_logical_size(self):
        fb = FakeBackend()
        fb.width, fb.height = 320, 240
        t = _target()
        display, fb, gt = _make_display(
            screen_type="ili9341_320x240", screen_size_inches=2.8, layout_size="large",
            backend=fb, targets=[t],
        )
        display.enable()
        fake_image = _marked_image(size=(640, 480))
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()
        assert display._current_rendered_image.size == (640, 480)
        assert fb.displayed[-1].size == (320, 240)


class TestMetricsFollowLayout:
    def test_large_on_320x240(self):
        display, fb, gt = _make_display(
            screen_type="ili9341_320x240", screen_size_inches=2.8, layout_size="large",
        )
        m = display._layout_metrics()
        assert m.content_tier == "large"
        assert m.rows_per_page == 5
        assert m.supersample == 2
        assert m.mm_per_px == pytest.approx(0.0889, abs=1e-4)
        assert display._rows_per_page() == 5

    def test_small_on_320x240(self):
        display, fb, gt = _make_display(
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
        display, fb, gt = _make_display(
            screen_type="ili9341_320x240", screen_size_inches=2.8, backend=fb, targets=[t],
        )
        display.enable()
        before = len(fb.displayed)
        fake_image = _marked_image(size=(320, 240))
        # Simulates a layout_size change racing the fetch: _logical_dims()
        # returns the size active when the transform ran, then the new
        # (superseded) size for the guard check taken under the lock.
        with patch.object(display, "_logical_dims", side_effect=[(320, 240), (640, 480)]), \
             patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
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
        display, fb, gt = _make_display(
            screen_type=screen_type, screen_size_inches=screen_size_inches, backend=fb, targets=[t],
        )
        display.enable()
        fake_image = _marked_image(size=(320, 240))
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()
        return display, fb, gt

    def test_none_to_large_drops_caches_and_shows_logo_at_new_size(self):
        display, fb, gt = self._opened_with_artwork()
        assert display._current_rendered_image is not None
        fb.displayed.clear()
        display._poll_wake.clear()

        status = display.update_config(DialDisplayConfig(
            fitted=True, screen_type="ili9341_320x240", screen_size_inches=2.8, layout_size="large",
        ))

        assert display._current_rendered_image is None
        assert display._source_artwork_url == ""
        assert display._screen == "main"
        assert len(fb.displayed) == 1
        assert display._current_base_image.size == (640, 480)
        assert fb.displayed[-1].size == (320, 240)
        assert display._poll_wake.is_set()

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
        display, fb, gt = _make_display()
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
        display, fb, gt = _make_display(targets=[])
        rows = tuple(dd.SelectorRow(appliance_id=str(i), label=str(i), current=False) for i in range(5))
        selector = dd.SelectorState(rows=rows, page=1, opened_at=0.0)
        page_rows = display._current_page_rows(selector)
        assert [r.appliance_id for r in page_rows] == ["3", "4"]

    def test_picker_state_page_one(self):
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
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
    def test_open_selector_defers_the_sleep_decision_like_the_picker(self):
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
        # An open selector is never closed by a poll finding nothing
        # playing — only its own inactivity timeout does that.
        assert display._screen == "selector"
        assert display._selector is not None

    def test_selector_closed_by_timeout_then_next_idle_poll_sleeps(self):
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
        opened_at = display._selector.opened_at
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS + 1):
            display._check_secondary_timeout()
        assert display._screen == "main"

        t0 = opened_at + SELECTOR_TIMEOUT_SECONDS + 1
        with patch("dial_display.time.monotonic", return_value=t0):
            display._poll_once()  # starts the idle countdown now the list is closed
        assert display._display_sleeping is False

        with patch("dial_display.time.monotonic", return_value=t0 + dd.DISPLAY_IDLE_SLEEP_SECONDS):
            display._poll_once()
        assert display._display_sleeping is True

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
        assert display.touch_surface() == ("selector", False, False, False)

    def test_hidden_with_name_active_when_something_is_playing(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.touch_surface() == ("hidden", True, False, False)

    def test_held_with_name_active(self):
        t = _target()
        display, fb, gt = _make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.touch_surface() == ("held", True, False, False)

    def test_idle_with_name_inactive_when_nothing_playing(self):
        # The idle screen is one screen whenever nothing plays: the "i"
        # affordance must be reachable even with no replay held, so
        # the surface is "idle" here, not "hidden" — the pre-unification
        # behaviour this test used to pin.
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display._poll_once()
        assert display.touch_surface() == ("idle", False, False, False)

    def test_idle_when_affordance_drawn(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display._poll_once()
        with display._lock:
            display._idle_affordance = True
        assert display.touch_surface() == ("idle", False, False, False)

    def test_idle_regardless_of_affordance_when_nothing_playing(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display._idle_affordance = False
        display._poll_once()
        assert display.touch_surface()[0] == "idle"

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
        assert display.touch_surface() == ("repeat", True, True, False)

    def test_repeat_screen_outputs_active_follows_live_availability(self):
        aid = "1" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        with display._lock:
            display._screen = "repeat"
            display._outputs_available = True
        assert display.touch_surface() == ("repeat", True, True, True)
        with display._lock:
            display._outputs_available = False
        assert display.touch_surface() == ("repeat", True, True, False)

    def test_picker_while_open(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "picker"
        assert display.touch_surface() == ("picker", False, False, False)

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
        surface, name_active, dots_active, outputs_active = display.touch_surface()
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

    def test_idle_and_name_inactive_with_an_idle_roster_entry_but_nothing_shown(self):
        # An authorised idle appliance existing on the roster is not, by
        # itself, an entry point into the selector — the NAME zone stays
        # inert until something is actually shown (playing, or focused).
        # The surface itself is still "idle" (reachable regardless of
        # replay availability).
        idle_entry = _roster_entry(name="Kitchen", auth="authorized", playing=False)
        display, fb, gt = _make_display(targets=[], roster=[idle_entry])
        display.enable()
        display._poll_once()
        assert display.touch_surface() == ("idle", False, False, False)

    def test_idle_affordance_still_drawn_with_an_idle_roster_entry(self):
        idle_entry = _roster_entry(name="Kitchen", auth="authorized", playing=False)
        display, fb, gt = _make_display(targets=[], roster=[idle_entry])
        display.enable()
        display._poll_once()
        with display._lock:
            display._idle_affordance = True
        assert display.touch_surface() == ("idle", False, False, False)

    def test_hidden_with_name_active_once_an_idle_focus_is_set(self):
        aid = "9" * 19 + "2"
        idle_entry = _roster_entry(name="Kitchen", service_name="Kitchen", appliance_id=aid, auth="authorized",
                                    playing=False)
        display, fb, gt = _make_display(targets=[], roster=[idle_entry])
        display.enable()
        display.set_manual_focus(aid)
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid)):
            display._poll_once()
        assert display.touch_surface() == ("hidden", True, False, False)

    def test_held_with_name_active_once_an_idle_focus_is_set_and_always_show(self):
        aid = "9" * 19 + "3"
        idle_entry = _roster_entry(name="Kitchen", service_name="Kitchen", appliance_id=aid, auth="authorized",
                                    playing=False)
        display, fb, gt = _make_display(targets=[], roster=[idle_entry], always_show_controls=True)
        display.enable()
        display.set_manual_focus(aid)
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid)):
            display._poll_once()
        assert display.touch_surface() == ("held", True, False, False)


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
        display._idle_affordance = True
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
        display, fb, gt = _make_display(targets=[])
        display.enable()
        self._open_repeat_screen_directly(display, aid)
        self._seed_replaying(aid, position_seconds=5.0, observed_at=1000.0)
        # shown(now) = position + elapsed - REPEAT_COUNTER_LATENCY_S
        #            = 5.0 + 1.002 - 2.0 = 4.002 -- just past the 4.0 boundary.
        display._overlay_signal.clear()
        with patch("dial_display.time.monotonic", return_value=1001.002):
            display._tick_repeat_line()
        assert display._overlay_signal.is_set()

    def test_tick_repeat_line_does_not_signal_mid_second(self):
        aid = "9" * 20
        display, fb, gt = _make_display(targets=[])
        display.enable()
        self._open_repeat_screen_directly(display, aid)
        self._seed_replaying(aid, position_seconds=5.0, observed_at=1000.0)
        # shown(now) = 5.0 + 1.5 - 2.0 = 4.5 -- mid-second, not due.
        display._overlay_signal.clear()
        with patch("dial_display.time.monotonic", return_value=1001.5):
            display._tick_repeat_line()
        assert not display._overlay_signal.is_set()

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


class TestNextRepaintDeadline:
    def _seed(self, aid, position_seconds, observed_at=1000.0):
        import dial_repeat_store as drs
        drs.repeat_store.update(aid, drs.RepeatRecord(
            available=True, state="replaying", armed=True,
            recording_seconds=30.0, position_seconds=position_seconds, duration_seconds=30.0,
            observed_at=observed_at,
        ))

    def _opened(self, aid):
        display, fb, gt = _make_display(targets=[])
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
        now = 1001.0
        with patch("dial_display.time.monotonic", return_value=now):
            deadline = display._next_repaint_deadline()
        assert deadline == pytest.approx(now + expected_remaining + 0.005, abs=1e-6)

    def test_none_when_nothing_scheduled(self):
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
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


# ---------------------------------------------------------------------------
# The unified pressed channel: one set_pressed(zone, index) feeding every
# screen's own frame builder through the shared zone-rect table. The main
# and idle screens must stay byte-identical to before this channel existed;
# the selector, picker and repeat screens now draw a wash for a genuine
# touch on any of their own zones.
# ---------------------------------------------------------------------------

class TestSetPressedStorage:
    def test_stores_the_zone_and_index(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display._overlay_signal.clear()

        display.set_pressed(TouchZone.LIST_ROW, 2)

        assert display._pressed == (TouchZone.LIST_ROW, 2)
        assert display._overlay_signal.is_set()

    def test_index_defaults_to_none(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()

        display.set_pressed(TouchZone.UP)

        assert display._pressed == (TouchZone.UP, None)

    def test_none_zone_clears_the_channel(self):
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=targets)
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
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
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display._idle_affordance = True
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
        display, fb, gt = _make_display(targets=[t])
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
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle"))
        display.toggle_repeat_screen()
        with display._lock:
            display._repaint_current_locked()

        display.set_pressed(TouchZone.REPEAT_PLAY)
        with display._lock:
            view = display._build_repeat_view_locked(display._repeat_screen, time.monotonic())
        assert view.pressed == TouchZone.REPEAT_PLAY

    def test_repeat_screen_name_wash_is_accepted(self):
        """The repeat screen shares DOTS/NAME/MUTE with the main screen's
        top band; the unified channel now surfaces a wash for them there
        too, matching what the compositor already renders for a main-screen
        press on the same zones."""
        aid = "9" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle"))
        display.toggle_repeat_screen()
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
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display.set_pressed(TouchZone.DOWN)

        with display._lock:
            display._close_secondary_locked()

        assert display._pressed is None

    def test_opening_a_secondary_screen_empties_pressed(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display.set_pressed(TouchZone.UP)

        display.open_selector()
        with display._lock:
            display._apply_screen_requests_locked()

        assert display._screen == "selector"
        assert display._pressed is None

    def test_mark_noncomposited_locked_empties_pressed(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display.set_pressed(TouchZone.UP)

        with display._lock:
            display._mark_noncomposited_locked()

        assert display._pressed is None


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

    def test_pending_focus_expires_after_grace_without_rostered_appliance(self):
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

    def test_pending_focus_expires_after_grace_kept_as_idle_focus_when_rostered(self):
        aid = "d" * 19 + "1"
        idle_entry = _roster_entry(name="Kitchen", service_name="Kitchen", appliance_id=aid, auth="authorized",
                                    playing=False)
        display, fb, gt = _make_display(targets=[], roster=[idle_entry])
        clock = _FakeClock()
        with patch("dial_display.time.monotonic", clock), \
             patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid)):
            display.set_manual_focus_pending(aid, "Kitchen")
            display._poll_once()
            assert display.manual_focus_id() == aid
            clock.t += dd.FOCUS_PENDING_GRACE_S + 1
            display._poll_once()
        # The grace expired, but the appliance is rostered (idle): the
        # pending focus simply becomes an ordinary idle focus, not cleared.
        assert display.manual_focus_id() == aid
        assert display._focus_pending is None
        assert display._now_playing is not None
        assert display._now_playing.service_name == "Kitchen"

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


class TestIdleFocusShownWhenNothingPlays:
    """The no-targets branch shows an idle focus in place of the plain idle
    screen: logo with the name and volume, selector rows refreshed, and the
    idle-sleep countdown still running underneath it."""

    def test_shows_logo_with_name_and_refreshes_selector_rows(self):
        aid = "7" * 20
        idle_entry = _roster_entry(name="Kitchen", service_name="Kitchen", appliance_id=aid, auth="authorized",
                                    playing=False)
        display, fb, gt = _make_display(targets=[], roster=[idle_entry])
        display.enable()
        display.set_manual_focus(aid)
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid)):
            display._poll_once()

        assert display.get_status()["showing"] == "logo"
        assert display._now_playing is not None
        assert display._now_playing.service_name == "Kitchen"
        assert [r.appliance_id for r in display._selector.rows] == [aid]
        assert [r.current for r in display._selector.rows] == [True]

    def test_idle_sleep_countdown_still_runs(self):
        aid = "8" * 20
        idle_entry = _roster_entry(name="Kitchen", service_name="Kitchen", appliance_id=aid, auth="authorized",
                                    playing=False)
        display, fb, gt = _make_display(targets=[], roster=[idle_entry])
        display.enable()
        display.set_manual_focus(aid)
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(track_id=None, appliance_id=aid)):
            t0 = time.monotonic()
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
        display._idle_affordance = True
        display.open_picker()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "picker"

    def test_open_picker_refuses_without_a_held_replay(self):
        # The one deliberate behaviour change the idle-screen unification
        # requires: a replay tap on a plain logo with nothing held stays
        # inert, exactly as it was before the idle screen became reachable
        # on every idle dial.
        display, fb, gt = _make_display(targets=[])
        display.enable()
        assert display._idle_affordance is False
        display.open_picker()
        assert display._screen_request is None

    def test_picker_shows_placeholder_when_empty(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display._idle_affordance = True
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
        display._idle_affordance = True
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
        display._idle_affordance = True
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
        display._idle_affordance = True
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
# _parse_outputs_body: validate/convert a POST /api/dial/outputs response.
# ---------------------------------------------------------------------------

class TestParseOutputsBody:
    def test_valid_body_returns_rows(self):
        rows = dd._parse_outputs_body(200, {"ok": True, "outputs": [
            {"id": "1", "name": "Bedroom", "selected": True, "volume": 40, "remote_in_use": False},
            {"id": "2", "name": "Kitchen", "selected": False, "volume": 0, "remote_in_use": False},
        ]})
        assert rows == (
            dd.OutputRow(id="1", name="Bedroom", selected=True, volume=40),
            dd.OutputRow(id="2", name="Kitchen", selected=False, volume=0),
        )

    def test_remote_in_use_row_dropped(self):
        rows = dd._parse_outputs_body(200, {"ok": True, "outputs": [
            {"id": "1", "name": "Bedroom", "selected": False, "volume": 0, "remote_in_use": True},
            {"id": "2", "name": "Kitchen", "selected": True, "volume": 50, "remote_in_use": False},
        ]})
        assert [r.id for r in rows] == ["2"]

    def test_volume_clamped_into_0_100(self):
        rows = dd._parse_outputs_body(200, {"ok": True, "outputs": [
            {"id": "1", "name": "A", "selected": True, "volume": 500, "remote_in_use": False},
            {"id": "2", "name": "B", "selected": True, "volume": -5, "remote_in_use": False},
        ]})
        assert rows[0].volume == 100
        assert rows[1].volume == 0

    def test_empty_outputs_list_is_empty_tuple(self):
        assert dd._parse_outputs_body(200, {"ok": True, "outputs": []}) == ()

    def test_non_200_status_is_none(self):
        assert dd._parse_outputs_body(412, {"ok": True, "outputs": []}) is None

    def test_none_status_is_none(self):
        assert dd._parse_outputs_body(None, None) is None

    def test_ok_false_is_none(self):
        assert dd._parse_outputs_body(200, {"ok": False, "error": "backend_unavailable"}) is None

    def test_non_dict_body_is_none(self):
        assert dd._parse_outputs_body(200, None) is None

    def test_outputs_not_a_list_is_none(self):
        assert dd._parse_outputs_body(200, {"ok": True, "outputs": "nope"}) is None

    def test_malformed_row_is_none(self):
        assert dd._parse_outputs_body(200, {"ok": True, "outputs": [{"id": "1"}]}) is None

    def test_row_not_a_dict_is_none(self):
        assert dd._parse_outputs_body(200, {"ok": True, "outputs": ["bad"]}) is None

    def test_missing_id_is_none(self):
        assert dd._parse_outputs_body(200, {"ok": True, "outputs": [
            {"name": "A", "selected": True, "volume": 10, "remote_in_use": False},
        ]}) is None

    def test_non_bool_selected_is_none(self):
        assert dd._parse_outputs_body(200, {"ok": True, "outputs": [
            {"id": "1", "name": "A", "selected": "yes", "volume": 10, "remote_in_use": False},
        ]}) is None

    def test_non_int_volume_is_none(self):
        assert dd._parse_outputs_body(200, {"ok": True, "outputs": [
            {"id": "1", "name": "A", "selected": True, "volume": "10", "remote_in_use": False},
        ]}) is None


# ---------------------------------------------------------------------------
# on_outputs_result: fold a fetch result into the outputs snapshot.
# ---------------------------------------------------------------------------

class TestOnOutputsResult:
    def _outputs_state(self, appliance_id="a" * 20, rows=(), page=0, loaded=False):
        return dd.OutputsState(
            appliance_id=appliance_id, service_name="Kitchen", ip="10.0.0.1", port=80,
            rows=rows, page=page, opened_at=time.monotonic(), loaded=loaded,
        )

    def test_non_fetch_kind_is_a_no_op(self):
        display, fb, gt = _make_display(targets=[])
        state = self._outputs_state()
        display._outputs = state
        display.on_outputs_result("set", "a" * 20, 200, {"ok": True}, {"id": "1"})
        assert display._outputs is state

    def test_fetch_folds_rows_and_sets_loaded(self):
        display, fb, gt = _make_display(targets=[])
        display._outputs = self._outputs_state()
        display._overlay_signal.clear()
        body = {"ok": True, "outputs": [
            {"id": "1", "name": "Bedroom", "selected": True, "volume": 40, "remote_in_use": False},
        ]}
        display.on_outputs_result("fetch", "a" * 20, 200, body, {})
        assert display._outputs.loaded is True
        assert display._outputs.rows == (dd.OutputRow(id="1", name="Bedroom", selected=True, volume=40),)
        assert display._overlay_signal.is_set()

    def test_late_result_for_a_different_appliance_is_dropped(self):
        display, fb, gt = _make_display(targets=[])
        state = self._outputs_state(appliance_id="a" * 20)
        display._outputs = state
        display.on_outputs_result("fetch", "b" * 20, 200, {"ok": True, "outputs": []}, {})
        assert display._outputs is state

    def test_no_outputs_screen_open_is_a_no_op(self):
        display, fb, gt = _make_display(targets=[])
        display._outputs = None
        display.on_outputs_result("fetch", "a" * 20, 200, {"ok": True, "outputs": []}, {})
        assert display._outputs is None

    def test_malformed_result_keeps_the_last_snapshot(self):
        display, fb, gt = _make_display(targets=[])
        prior_rows = (dd.OutputRow(id="1", name="Bedroom", selected=True, volume=40),)
        display._outputs = self._outputs_state(rows=prior_rows, loaded=True)
        display.on_outputs_result("fetch", "a" * 20, 500, None, {})
        assert display._outputs.rows == prior_rows
        assert display._outputs.loaded is True

    def test_page_clamped_when_row_count_shrinks(self):
        display, fb, gt = _make_display(targets=[])
        display._outputs = self._outputs_state(page=5, loaded=True)
        body = {"ok": True, "outputs": [
            {"id": "1", "name": "A", "selected": False, "volume": 0, "remote_in_use": False},
        ]}
        display.on_outputs_result("fetch", "a" * 20, 200, body, {})
        assert display._outputs.page == 0

    def test_stale_optimistic_override_cleared(self):
        display, fb, gt = _make_display(targets=[])
        display._outputs = self._outputs_state(loaded=True)
        display._outputs_optimistic = ("1", True, 40, time.monotonic() - 1.0)
        display.on_outputs_result("fetch", "a" * 20, 200, {"ok": True, "outputs": []}, {})
        assert display._outputs_optimistic is None

    def test_future_stamped_optimistic_override_kept(self):
        """An optimistic override stamped for a moment still in the future
        (relative to when the fold runs) is not yet superseded."""
        display, fb, gt = _make_display(targets=[])
        display._outputs = self._outputs_state(loaded=True)
        override = ("1", True, 40, time.monotonic() + 10.0)
        display._outputs_optimistic = override
        display.on_outputs_result("fetch", "a" * 20, 200, {"ok": True, "outputs": []}, {})
        assert display._outputs_optimistic == override

    def test_detail_row_vanishing_requests_the_outputs_list(self):
        display, fb, gt = _make_display(targets=[])
        display._outputs = self._outputs_state(
            rows=(dd.OutputRow(id="1", name="Bedroom", selected=True, volume=40),), loaded=True,
        )
        display._output_detail = dd.OutputDetailState(
            appliance_id="a" * 20, output_id="1", opened_at=time.monotonic(),
        )
        display._screen = "output"
        display.on_outputs_result("fetch", "a" * 20, 200, {"ok": True, "outputs": []}, {})
        assert display._screen_request == "outputs"

    def test_detail_row_still_present_leaves_screen_request_alone(self):
        display, fb, gt = _make_display(targets=[])
        row = dd.OutputRow(id="1", name="Bedroom", selected=True, volume=40)
        display._outputs = self._outputs_state(rows=(row,), loaded=True)
        display._output_detail = dd.OutputDetailState(
            appliance_id="a" * 20, output_id="1", opened_at=time.monotonic(),
        )
        display._screen = "output"
        display._screen_request = None
        body = {"ok": True, "outputs": [
            {"id": "1", "name": "Bedroom", "selected": True, "volume": 45, "remote_in_use": False},
        ]}
        display.on_outputs_result("fetch", "a" * 20, 200, body, {})
        assert display._screen_request is None


# ---------------------------------------------------------------------------
# _outputs_available: whether the top-right OUTPUTS zone is currently live.
# ---------------------------------------------------------------------------

class TestOutputsAvailable:
    def test_reporting_appliance_advertises_dial_outputs(self):
        aid = "a" * 20
        t = _target(appliance_id=aid)
        roster = [_roster_entry(appliance_id=aid, playing=True, dial_outputs=True)]
        display, fb, gt = _make_display(targets=[t], roster=roster)
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(appliance_id=aid)):
            display._poll_once()
        assert display._reporting_appliance_id == aid
        assert display._outputs_available is True

    def test_reporting_appliance_without_dial_outputs(self):
        aid = "a" * 20
        t = _target(appliance_id=aid)
        roster = [_roster_entry(appliance_id=aid, playing=True, dial_outputs=False)]
        display, fb, gt = _make_display(targets=[t], roster=roster)
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(appliance_id=aid)):
            display._poll_once()
        assert display._reporting_appliance_id == aid
        assert display._outputs_available is False

    def test_manual_focus_on_an_idle_appliance_with_dial_outputs(self):
        aid = "a" * 20
        roster = [_roster_entry(appliance_id=aid, playing=False, dial_outputs=True)]
        display, fb, gt = _make_display(targets=[], roster=roster)
        display.enable()
        display.set_manual_focus(aid)
        with patch("dial_display.fetch_target_status", return_value=_status_result(appliance_id=aid)):
            display._poll_once()
        assert display._outputs_available is True

    def test_nothing_playing_no_focus_is_false(self):
        display, fb, gt = _make_display(targets=[], roster=[])
        display.enable()
        display._poll_once()
        assert display._outputs_available is False

    def test_unfitted_display_is_false(self):
        display, fb, gt = _make_display(fitted=False)
        display._outputs_available = True
        display._poll_once()
        assert display._outputs_available is False

    def test_unauthorized_reporting_entry_is_false(self):
        t = _target(appliance_id="a" * 20, auth="unauthorized")
        roster = [_roster_entry(appliance_id="a" * 20, playing=True, dial_outputs=True,
                                 auth="unauthorized")]
        display, fb, gt = _make_display(targets=[t], roster=roster)
        display.enable()
        display._poll_once()
        assert display._outputs_available is False


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
    (the arrows-on-disc image), not the plain logo or any text. Reached
    whenever nothing is playing, not only while a replay is available —
    see TestIdlePlainLogo for the no-affordance case."""

    def test_idle_render_requests_the_replay_logo(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._idle_affordance = True
            display._current_base_image = MagicMock()
            with patch("dial_display.load_logo", return_value=MagicMock()) as ll:
                display._display_idle_locked()
        assert ll.call_args_list[0].args[0] == display._replay_logo_path

    def test_idle_render_falls_back_to_plain_base_when_replay_logo_missing(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        base = MagicMock()
        with display._lock:
            display._idle_affordance = True
            display._current_base_image = base
            with patch("dial_display.load_logo", return_value=None):
                # Must not raise when the replay image cannot be loaded.
                display._display_idle_locked()


class TestIdlePlainLogo:
    """Fork 1: the idle screen's own compose path is reached whenever
    nothing is playing, not only while a replay is available — a dial with
    no repeat-capable appliance still gets the "i" badge (see
    TestComposeIdle in the compositor suite), just over the plain logo
    rather than the replay-available one."""

    def test_plain_base_used_and_replay_logo_never_loaded_without_affordance(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        base = MagicMock()
        with display._lock:
            display._idle_affordance = False
            display._current_base_image = base
            with patch("dial_display.load_logo") as ll:
                display._display_idle_locked()
        ll.assert_not_called()

    def test_idle_chassis_due_whenever_nothing_plays_regardless_of_affordance(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "main"
            display._now_playing = None
            display._idle_affordance = False
            assert display._idle_chassis_due_locked() is True
            display._idle_affordance = True
            assert display._idle_chassis_due_locked() is True


class TestPickerSurvivesIdle:
    """The replay picker and the appliance selector are both idle-state
    screens for choosing what to replay or what to control, so a poll that
    finds nothing playing must NOT close either of them — their own
    inactivity timeout does."""

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

    def test_selector_stays_open_when_nothing_playing(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "selector"
        gt.return_value = []
        with patch.object(display, "_close_secondary_locked") as close:
            display._poll_once()
        close.assert_not_called()

    def test_repeat_screen_closes_when_nothing_playing_and_no_focus(self):
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[], roster=[idle])
        display.enable()
        display.set_manual_focus(aid)
        with display._lock:
            display._screen = "repeat"
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None, appliance_id=aid)):
            display._poll_once()
        assert display._screen == "repeat"


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


# ---------------------------------------------------------------------------
# The outputs list and per-output detail screens: openers, touch-thread
# entries, and paint builders. Lifecycle/poll interactions (bound-appliance
# close, idle focus, timeouts) are covered by the trace corpus instead.
# ---------------------------------------------------------------------------

def _make_outputs_display(dial_outputs=True, auth="unknown", appliance_id="a" * 20):
    display, fb, gt = _make_display(targets=[])
    display._reporting_appliance_id = appliance_id
    display._last_roster = [_roster_entry(
        appliance_id=appliance_id, auth=auth, dial_outputs=dial_outputs,
    )]
    return display


class TestOutputsOpener:
    def test_refuses_with_no_focus_or_reporting_id(self):
        display, fb, gt = _make_display(targets=[])
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
        assert display._outputs.rows == ()
        assert display._outputs.loaded is False

    def test_keeps_rows_on_reopen_for_the_same_appliance(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        rows = (dd.OutputRow(id="1", name="Bedroom", selected=True, volume=40),)
        display._outputs = dataclasses.replace(display._outputs, rows=rows, loaded=True)
        display._screen = "main"
        display._open_outputs_locked()
        assert display._outputs.rows == rows
        assert display._outputs.loaded is True

    def test_resets_rows_for_a_different_appliance(self):
        display = _make_outputs_display(appliance_id="a" * 20)
        display._open_outputs_locked()
        rows = (dd.OutputRow(id="1", name="Bedroom", selected=True, volume=40),)
        display._outputs = dataclasses.replace(display._outputs, rows=rows, loaded=True)
        display._screen = "main"
        display._reporting_appliance_id = "b" * 20
        display._last_roster = [_roster_entry(appliance_id="b" * 20, dial_outputs=True)]
        display._open_outputs_locked()
        assert display._outputs.appliance_id == "b" * 20
        assert display._outputs.rows == ()
        assert display._outputs.loaded is False


class TestOutputDetailOpener:
    def test_refuses_without_a_chosen_id(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        display._outputs = dataclasses.replace(
            display._outputs,
            rows=(dd.OutputRow(id="1", name="Bedroom", selected=True, volume=40),),
        )
        display._output_open_id = None
        assert display._open_output_locked() is False
        assert display._output_detail is None

    def test_refuses_when_id_not_in_rows(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        display._outputs = dataclasses.replace(
            display._outputs,
            rows=(dd.OutputRow(id="1", name="Bedroom", selected=True, volume=40),),
        )
        display._output_open_id = "not-a-row"
        assert display._open_output_locked() is False
        assert display._output_detail is None
        # Consumed either way, refused or not.
        assert display._output_open_id is None

    def test_opens_for_a_valid_id(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        display._outputs = dataclasses.replace(
            display._outputs,
            rows=(dd.OutputRow(id="1", name="Bedroom", selected=True, volume=40),),
        )
        display._output_open_id = "1"
        assert display._open_output_locked() is True
        assert display._screen == "output"
        assert display._output_detail.output_id == "1"
        assert display._output_detail.appliance_id == display._outputs.appliance_id
        assert display._output_open_id is None

    def test_refuses_with_no_outputs_state(self):
        display, fb, gt = _make_display(targets=[])
        display._output_open_id = "1"
        assert display._open_output_locked() is False


class TestOutputsTouchEntries:
    def test_open_outputs_enqueues_fetch_and_requests_screen(self):
        display = _make_outputs_display()
        with patch("dial_display.enqueue_fetch") as mock_fetch:
            display.open_outputs()
        mock_fetch.assert_called_once()
        target = mock_fetch.call_args[0][0]
        assert target.appliance_id == "a" * 20
        assert display._screen_request == "outputs"

    def test_open_outputs_noop_without_capability(self):
        display = _make_outputs_display(dial_outputs=False)
        with patch("dial_display.enqueue_fetch") as mock_fetch:
            display.open_outputs()
        mock_fetch.assert_not_called()
        assert display._screen_request is None

    def test_outputs_row_tap_sets_open_id_and_requests_detail(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        display._outputs = dataclasses.replace(
            display._outputs,
            rows=(dd.OutputRow(id="1", name="Bedroom", selected=True, volume=40),),
        )
        display.outputs_row_tap(0)
        assert display._output_open_id == "1"
        assert display._screen_request == "output"

    def test_outputs_row_tap_stale_index_closes_list(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        display._outputs = dataclasses.replace(
            display._outputs,
            rows=(dd.OutputRow(id="1", name="Bedroom", selected=True, volume=40),),
        )
        display.outputs_row_tap(9)
        assert display._output_open_id is None
        # close_list() requests back_to for whatever screen is showing.
        assert display._screen_request == dd._policy(display._screen).back_to

    def _opened_detail(self, selected=True, volume=40):
        display = _make_outputs_display()
        display._open_outputs_locked()
        row = dd.OutputRow(id="1", name="Bedroom", selected=selected, volume=volume)
        display._outputs = dataclasses.replace(display._outputs, rows=(row,))
        display._output_detail = dd.OutputDetailState(
            appliance_id=display._outputs.appliance_id, output_id="1", opened_at=1000.0,
        )
        display._screen = "output"
        return display

    def test_output_toggle_tap_enqueues_and_sets_optimistic(self):
        display = self._opened_detail(selected=False, volume=0)
        with patch("dial_display.enqueue_set") as mock_set:
            display.output_toggle_tap()
        mock_set.assert_called_once()
        target, out_id = mock_set.call_args[0]
        kwargs = mock_set.call_args[1]
        assert out_id == "1"
        assert kwargs["selected"] is True
        assert kwargs["volume"] is None
        assert display._outputs_optimistic[0] == "1"
        assert display._outputs_optimistic[1] is True

    def test_output_toggle_tap_disables(self):
        display = self._opened_detail(selected=True, volume=40)
        with patch("dial_display.enqueue_set") as mock_set:
            display.output_toggle_tap()
        kwargs = mock_set.call_args[1]
        assert kwargs["selected"] is False
        assert display._outputs_optimistic[1] is False

    def test_output_toggle_tap_noop_without_row(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        display._output_detail = dd.OutputDetailState(
            appliance_id=display._outputs.appliance_id, output_id="missing", opened_at=1000.0,
        )
        with patch("dial_display.enqueue_set") as mock_set:
            display.output_toggle_tap()
        mock_set.assert_not_called()

    def test_output_volume_tap_steps_from_row_volume(self):
        display = self._opened_detail(selected=True, volume=40)
        with patch("dial_display.enqueue_set") as mock_set:
            display.output_volume_tap(+2)
        kwargs = mock_set.call_args[1]
        assert kwargs["selected"] is True
        assert kwargs["volume"] == 42
        assert display._outputs_optimistic[2] == 42

    def test_output_volume_tap_steps_from_optimistic_value(self):
        display = self._opened_detail(selected=True, volume=40)
        display._outputs_optimistic = ("1", True, 42, 1000.0)
        with patch("dial_display.enqueue_set"):
            display.output_volume_tap(+2)
        assert display._outputs_optimistic[2] == 44

    def test_output_volume_tap_ignored_when_disabled(self):
        display = self._opened_detail(selected=False, volume=0)
        with patch("dial_display.enqueue_set") as mock_set:
            display.output_volume_tap(+2)
        mock_set.assert_not_called()
        assert display._outputs_optimistic is None

    def test_output_volume_tap_clamps_at_100(self):
        display = self._opened_detail(selected=True, volume=99)
        with patch("dial_display.enqueue_set") as mock_set:
            display.output_volume_tap(+10)
        assert mock_set.call_args[1]["volume"] == 100

    def test_output_volume_tap_clamps_at_0(self):
        display = self._opened_detail(selected=True, volume=1)
        with patch("dial_display.enqueue_set") as mock_set:
            display.output_volume_tap(-10)
        assert mock_set.call_args[1]["volume"] == 0


class TestOutputsPaintBuilders:
    def test_list_row_enabled_shows_volume_right_aligned_slot(self):
        assert dd._output_list_row(
            dd.OutputRow(id="1", name="Bedroom", selected=True, volume=42),
        ) == ("Bedroom", False, "42")

    def test_list_row_disabled_shows_blank(self):
        assert dd._output_list_row(
            dd.OutputRow(id="1", name="Bedroom", selected=False, volume=0),
        ) == ("Bedroom", False, "")

    def test_loading_placeholder_before_first_fetch(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        with display._lock:
            state = display._build_outputs_list_state_locked(160, 128)
        assert state.rows == (("Loading", False),)

    def test_no_outputs_placeholder_once_loaded_and_empty(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        display._outputs = dataclasses.replace(display._outputs, loaded=True, rows=())
        with display._lock:
            state = display._build_outputs_list_state_locked(160, 128)
        assert state.rows == (("No outputs", False),)

    def test_optimistic_override_applied_before_row_tuples(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        row = dd.OutputRow(id="1", name="Bedroom", selected=False, volume=0)
        display._outputs = dataclasses.replace(display._outputs, rows=(row,), loaded=True)
        display._outputs_optimistic = ("1", True, 55, 1000.0)
        with display._lock:
            state = display._build_outputs_list_state_locked(160, 128)
        assert state.rows == (("Bedroom", False, "55"),)
        # Paint-time only: the manager's own row is never mutated.
        assert display._outputs.rows[0].selected is False

    def test_output_view_reads_level_through_the_override(self):
        display = self._opened_with_row(selected=False, volume=0)
        display._outputs_optimistic = ("1", True, 60, 1000.0)
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
        display._outputs = dataclasses.replace(display._outputs, rows=())
        with display._lock:
            view = display._build_output_view_locked(1000.0)
        assert view.selected is False
        assert view.level is None
        assert view.output_name == ""

    def _opened_with_row(self, selected, volume):
        display = _make_outputs_display()
        display._open_outputs_locked()
        row = dd.OutputRow(id="1", name="Bedroom", selected=selected, volume=volume)
        display._outputs = dataclasses.replace(display._outputs, rows=(row,), loaded=True)
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
    def test_table_has_exactly_the_seven_screens(self):
        assert set(SCREEN_POLICIES) == {
            "main", "selector", "picker", "info", "repeat", "outputs", "output",
        }

    def test_state_attr_is_an_attribute_of_a_fresh_display(self):
        display, fb, gt = _make_display(targets=[])
        for policy in SCREEN_POLICIES.values():
            if policy.state_attr is not None:
                assert hasattr(display, policy.state_attr)

    def test_open_and_paint_are_dial_display_methods(self):
        for policy in SCREEN_POLICIES.values():
            assert callable(policy.open)
            assert policy.open.__qualname__.startswith("DialDisplay.")
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

    def test_bound_to_appliance_is_exactly_outputs_and_output(self):
        bound = {name for name, policy in SCREEN_POLICIES.items() if policy.bound_to_appliance}
        assert bound == {"outputs", "output"}

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
    display, fb, gt = _make_display(targets=targets or [], **overrides)
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
        with patch("dial_display.time.monotonic", clock):
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
        with patch("dial_display.time.monotonic", clock):
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
        display.toggle_repeat_screen()
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
        with patch("dial_display.time.monotonic", clock):
            clock.t += dd.CONTROLS_HIDE_SECONDS + 0.1
            assert display.touch_surface()[0] == "hidden"

    def test_repeat_frame_falls_back_to_bare_base_once_hidden(self):
        display = self._opened("3" * 20)
        clock = _FakeClock(time.monotonic())
        with patch("dial_display.time.monotonic", clock), \
             patch.object(display._compositor, "compose_repeat", wraps=display._compositor.compose_repeat) as spy:
            clock.t += dd.CONTROLS_HIDE_SECONDS + 0.1
            with display._lock:
                display._repaint_current_locked()
            assert spy.call_args.kwargs["controls"] is False

    def test_reveal_after_hidden_shows_repeat_again(self):
        display = self._opened("4" * 20)
        clock = _FakeClock(time.monotonic())
        with patch("dial_display.time.monotonic", clock):
            clock.t += dd.CONTROLS_HIDE_SECONDS + 0.1
            assert display.touch_surface()[0] == "hidden"
            display.set_overlay(OverlayState(visible=True))
            assert display.touch_surface()[0] == "repeat"


class TestCompactStopFlow:
    def test_ok_stop_ack_closes_the_repeat_screen_to_main(self):
        import dial_repeat_store as drs
        aid = "5" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_compact_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))
        display.toggle_repeat_screen()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

        drs.repeat_store.update(aid, drs.parse_repeat_object(
            _repeat_obj(state="replaying", replay={"active": True, "position_seconds": 1.0, "duration_seconds": 30.0}),
            time.monotonic(),
        ))
        with patch("dial_display.enqueue_transport"):
            display.repeat_stop_tap()
        display.on_repeat_result(
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
        display.toggle_repeat_screen()
        with display._lock:
            display._repaint_current_locked()

        drs.repeat_store.update(aid, drs.parse_repeat_object(
            _repeat_obj(state="replaying", replay={"active": True, "position_seconds": 1.0, "duration_seconds": 30.0}),
            time.monotonic(),
        ))
        with patch("dial_display.enqueue_transport"):
            display.repeat_stop_tap()
        display.on_repeat_result("transport", aid, 200, {"ok": False, "error": "fading_out"})
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

    def test_off_compact_the_same_ack_leaves_the_screen_on_repeat(self):
        import dial_repeat_store as drs
        aid = "7" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_display(targets=[t])  # base tier
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))
        display.toggle_repeat_screen()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

        drs.repeat_store.update(aid, drs.parse_repeat_object(
            _repeat_obj(state="replaying", replay={"active": True, "position_seconds": 1.0, "duration_seconds": 30.0}),
            time.monotonic(),
        ))
        with patch("dial_display.enqueue_transport"):
            display.repeat_stop_tap()
        display.on_repeat_result(
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
        with patch("dial_display.time.monotonic", clock):
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
        with patch("dial_display.time.monotonic", clock):
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
        display, fb, gt = _make_display(targets=[t])  # base tier
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
        display.toggle_repeat_screen()
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
        display, fb, gt = _make_display(targets=[t])  # base tier, 160x128
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))
        display.toggle_repeat_screen()
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
        display.toggle_repeat_screen()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

        # dial_main.py's on_zone_tap routes every DOTS tap to this same
        # entry point regardless of which screen/layout drew the cell the
        # finger landed on -- the compact replaying layout's own "time"
        # strip is drawn there, but the dispatch is identical.
        display.toggle_repeat_screen()
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
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
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
        display.selector_page(+1)
        with display._lock:
            display._repaint_current_locked()
        assert display._selector.page == 1
        display.selector_page(+1)
        with display._lock:
            display._repaint_current_locked()
        assert display._selector.page == 0

    def test_carried_paging_still_clamps_after_a_rebuild(self):
        # _carried_paging_locked() (a rebuild landing a stale page back into
        # range) keeps clamping even on compact -- only the touch-thread
        # advance itself wraps.
        display, targets = self._opened_selector(count=3)
        display.selector_page(+1)
        with display._lock:
            display._repaint_current_locked()
        assert display._selector.page == 1
        display._refresh_selector_rows([], None)
        assert display._selector.page == 0

    def test_off_compact_the_same_advance_clamps_instead(self):
        targets = [
            _target(name=f"T{i}", service_name=f"T{i}", appliance_id=str(i) * 20,
                     auth="authorized", playing_since=float(i))
            for i in range(5)
        ]
        display, fb, gt = _make_display(targets=targets)  # base tier, rows_per_page == 3
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        display.selector_page(+5)
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
        # The argument is now passed unconditionally (see
        # _display_list_locked's own docstring); off compact it is simply
        # never read, so the rendered frame is unaffected -- proven by the
        # full pre-existing test suite passing unchanged.
        display, fb, gt = _make_display(targets=[])
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
        display._refresh_picker_rows(rows, now)
        display._idle_affordance = True
        display.open_picker()
        with display._lock:
            display._repaint_current_locked()
        assert display._metrics_locked().rows_per_page == 2  # both rows fit on page 0

        with patch("dial_display.enqueue_transport") as mock_transport:
            display.picker_pick(1)
        target, action, position = mock_transport.call_args[0]
        assert target.appliance_id == "b" * 20
        assert action == "seek"
        assert position == 0.0
        assert display.manual_focus_id() == "b" * 20


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
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
        display.enable()
        self._opened(display)
        assert display._screen == "info"
        assert display._info.rows == dd.INFO_PLACEHOLDER_ROWS

    def test_gather_fills_in_the_providers_rows(self):
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
        display.enable()
        display.set_info_provider(MagicMock(side_effect=RuntimeError("boom")))
        seq = self._opened(display)
        display._gather_info(seq)
        assert display._info.rows == dd.INFO_PLACEHOLDER_ROWS

    def test_missing_provider_yields_placeholders(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        seq = self._opened(display)
        display._gather_info(seq)
        assert display._info.rows == dd.INFO_PLACEHOLDER_ROWS

    def test_stale_gather_after_close_reopen_is_dropped(self):
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
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
        display, fb, gt = _make_display(targets=[])
        display.enable()
        self._opened(display)
        with patch.object(display, "selector_pick") as sp, \
             patch.object(display, "picker_pick") as pp, \
             patch.object(display, "outputs_row_tap") as op:
            display.list_row_tap(0)
        sp.assert_not_called()
        pp.assert_not_called()
        op.assert_not_called()
        assert display._screen == "info"


class TestInfoPagePaging:
    def test_rich_five_plus_one_across_two_pages(self):
        fb = FakeBackend()
        fb.width, fb.height = 320, 240
        display, fb, gt = _make_display(screen_type="ili9341_320x240", backend=fb, targets=[])
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
        assert len(page1.rows) == 1
        assert page1.has_prev is True
        assert page1.has_next is False

    def test_compact_two_per_page_across_three_pages_wraps(self):
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
        display, fb, gt = _make_display(targets=[])
        display.enable()
        self._opened(display)
        assert display._screen == "info"
        display.close_list()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"

    def test_closes_after_timeout(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        self._opened(display)
        opened_at = display._info.opened_at
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS + 1):
            display._check_secondary_timeout()
        assert display._screen == "main"

    def test_stays_open_before_timeout(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        self._opened(display)
        opened_at = display._info.opened_at
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS - 1):
            display._check_secondary_timeout()
        assert display._screen == "info"

    def test_touch_activity_extends_the_timeout(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        self._opened(display)
        old_opened_at = display._info.opened_at
        display.notify_touch_activity()
        with patch("dial_display.time.monotonic", return_value=old_opened_at + 1):
            with display._lock:
                display._apply_touch_activity_locked()
        assert display._info.opened_at > old_opened_at

    def test_sleep_is_deferred_while_open(self):
        display, fb, gt = _make_display(targets=[])
        display.enable()
        self._opened(display)
        gt.return_value = []
        with patch.object(display, "_close_secondary_locked") as close:
            display._poll_once()
        close.assert_not_called()
        assert display._idle_started_at is None
