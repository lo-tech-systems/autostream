"""Tests for the display's repeat screen and replay: the toggle and its touch entries,
the replaying counter and its deadlines, the compact tier's stop flow, and the main
page's replay timer line.
"""
from __future__ import annotations

import dataclasses
import math
import sys
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

from dial_display_views import OverlayState
from autostream_peer_client import PeerReply
import dial_core_state
import dial_repeat_store
import dial_display as dd
import dial_display_repeat_line as ddr
import dial_display_state as dds
from dial_display import SELECTOR_TIMEOUT_SECONDS
from dial_test_support import (
    _FakeClock,
    _repeat_obj,
    _roster_entry,
    _status_result,
    _target,
    _track_id,
    make_display,
    on_repeat_result,
    patch_monotonic,
    pending_token,
    repeat_of,
    seed_repeat,
    sent,
    set_roster,
)
from dial_display_test_support import (
    _REPLAY_AID, _make_compact_display, _poll_focused_with_repeat, open_repeat_screen, picker_with_row,
)


# ---------------------------------------------------------------------------
# An accepted replay shown before its advertisement, and what follows it
# ---------------------------------------------------------------------------

def _replay_display(state="hold", **display_kwargs):
    """A display following _REPLAY_AID, rostered and repeat-capable, with a
    repeat record in *state*. The caller patches the clock before calling
    this."""
    entry = _roster_entry(appliance_id=_REPLAY_AID, auth="authorized", repeat_capable=True)
    display, fb, gt = make_display(targets=[], roster=[entry], **display_kwargs)
    display.enable()
    set_roster(display, [entry])
    display.core.set_field_for_tests("manual_id", _REPLAY_AID)
    seed_repeat(_REPLAY_AID, _repeat_obj(state=state))
    display.request_poll = MagicMock()
    return display, fb, gt


def _replaying_reply() -> dict:
    """_REPLAY_AID's state once the replay it accepted has begun: replaying,
    with no session shown yet."""
    return dict(_status_result(appliance_id=_REPLAY_AID), repeat=_repeat_obj(
        state="replaying", held=False,
        replay={"active": True, "position_seconds": 0.0, "duration_seconds": 30.0}))


def _accept_replay(display) -> None:
    """Start a replay on _REPLAY_AID and have the appliance accept it."""
    with patch("dial_core.DialCore._send"):
        assert display.core.start_replay(_REPLAY_AID).accepted
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
            with patch("dial_test_support.fetch_target_status", return_value=_replaying_reply()):
                display.fold_for_tests()
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
            with patch("dial_test_support.fetch_target_status", return_value=_replaying_reply()):
                display.fold_for_tests()
            with display._lock:
                display._repaint_current_locked()
            playing_overlays = [o for kind, o in frames if kind == "playing" and o is not None]
            assert any(o.artist == dial_core_state.PLAYING_TEXT for o in playing_overlays)

            # The replay is fading out: still playing, still the synthetic target.
            seed_repeat(_REPLAY_AID, _repeat_obj(
                state="fading_out", held=False,
                replay={"active": True, "position_seconds": 29.0, "duration_seconds": 30.0}))
            clock.t += 1.0
            with patch("dial_test_support.fetch_target_status",
                       return_value=_status_result(appliance_id=_REPLAY_AID)):
                display.fold_for_tests()

            # Stopped: the record holds and the target is gone.
            seed_repeat(_REPLAY_AID, _repeat_obj(state="hold"))
            clock.t += 1.0
            mark = len(frames)
            with patch("dial_test_support.fetch_target_status",
                       return_value=_status_result(appliance_id=_REPLAY_AID)), \
                 patch("dial_display.load_logo", side_effect=dd.load_logo) as load_logo:
                display.fold_for_tests()
                with display._lock:
                    display._repaint_current_locked()
            after_stop = frames[mark:]
            assert not any(
                o is not None and o.artist == dial_core_state.PLAYING_TEXT for kind, o in after_stop
            )
            assert display.core.snapshot().now_playing is None
            assert display.core.snapshot().idle_affordance is True
            assert display._idle_chassis_due_locked() is True
            assert any(kind == "idle" for kind, _ in after_stop)
            assert load_logo.call_args_list[-1].args[0] == display._replay_logo_path


# ---------------------------------------------------------------------------
# Repeat screen: opening/closing, the ring/transport taps, its own compose
# path, no inactivity timeout, and closing when the focused appliance's
# manual focus clears.
# ---------------------------------------------------------------------------

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
        with patch("dial_test_support.fetch_target_status",
                   return_value=_status_result(track_id=_track_id(), appliance_id=aid)):
            display.fold_for_tests()

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
        display.fold_for_tests()
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
        return open_repeat_screen(state=state, armed=armed, appliance_id=appliance_id)

    def test_toggle_tap_arms_in_idle(self):
        display, aid = self._opened(state="idle", armed=False)
        with patch("dial_core.DialCore._send") as mock_arm:
            display.repeat_toggle_tap()
        mock_arm.assert_called_once()
        target, intent, token = sent(mock_arm)
        armed = intent.args["armed"]
        assert target.appliance_id == aid
        assert armed is True
        assert token == display.core.snapshot().transport.requested_at

    def test_toggle_tap_disarms_when_already_armed(self):
        display, aid = self._opened(state="recording", armed=True)
        with patch("dial_core.DialCore._send") as mock_arm:
            display.repeat_toggle_tap()
        mock_arm.assert_called_once()
        _, intent, _token = sent(mock_arm)
        armed = intent.args["armed"]
        assert armed is False

    def test_toggle_tap_ignored_while_replaying(self):
        display, aid = self._opened(state="replaying")
        with patch("dial_core.DialCore._send") as mock_arm:
            display.repeat_toggle_tap()
        mock_arm.assert_not_called()

    def test_start_tap_seeks_zero_while_hold(self):
        display, aid = self._opened(state="hold")
        with patch("dial_core.DialCore._send") as mock_transport:
            display.repeat_start_tap()
        mock_transport.assert_called_once()
        target, intent, token = sent(mock_transport)
        action = {"repeat.seek": "seek", "repeat.transport": "stop"}[intent.name]
        position = float(intent.args.get("position", 0.0))
        assert target.appliance_id == aid
        assert action == "seek"
        assert position == 0.0

    def test_start_tap_seeks_zero_while_replaying(self):
        display, aid = self._opened(state="replaying")
        with patch("dial_core.DialCore._send") as mock_transport:
            display.repeat_start_tap()
        mock_transport.assert_called_once()

    def test_start_tap_ignored_while_recording(self):
        display, aid = self._opened(state="recording")
        with patch("dial_core.DialCore._send") as mock_transport:
            display.repeat_start_tap()
        mock_transport.assert_not_called()

    def test_stop_tap_stops_while_replaying(self):
        display, aid = self._opened(state="replaying")
        with patch("dial_core.DialCore._send") as mock_transport:
            display.repeat_stop_tap()
        mock_transport.assert_called_once()
        target, intent, token = sent(mock_transport)
        action = {"repeat.seek": "seek", "repeat.transport": "stop"}[intent.name]
        position = float(intent.args.get("position", 0.0))
        assert target.appliance_id == aid
        assert action == "stop"

    def test_stop_tap_ignored_while_hold(self):
        display, aid = self._opened(state="hold")
        with patch("dial_core.DialCore._send") as mock_transport:
            display.repeat_stop_tap()
        mock_transport.assert_not_called()

    def test_taps_are_noop_when_screen_not_open(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with patch("dial_core.DialCore._send") as mock_arm, \
             patch("dial_core.DialCore._send") as mock_transport:
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
        display.fold_for_tests()
        assert display.core.snapshot().focus.manual_id is None
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

        with patch("dial_test_support.fetch_target_status", side_effect=fake_fetch):
            display.fold_for_tests()

        assert display.core.snapshot().focus.manual_id is None
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
        display.core.set_field_for_tests("idle_affordance", True)
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

    def test_volume_fed_from_the_repeat_screens_own_appliance(self):
        display, aid = self._opened(state="idle")
        with patch("dial_display.shown_volume", return_value=37) as mock_shown_volume:
            with display._lock:
                view = display._build_repeat_view_locked(display._repeat_screen, time.monotonic())
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
    DEFAULT_LATENCY_S, clamped at zero."""

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
        # 10.0 true seconds in, minus the DEFAULT_LATENCY_S lag —
        # allow the interpolation's own elapsed-time nudge either side of
        # the expected second by comparing the parsed minutes:seconds
        # rather than the exact string.
        shown = view.line.split(" / ")[0]
        minutes, seconds = (int(p) for p in shown.split(":"))
        shown_seconds = minutes * 60 + seconds
        assert shown_seconds == pytest.approx(10.0 - dial_repeat_store.DEFAULT_LATENCY_S, abs=1)

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
        pos = dial_repeat_store.interpolated_position(rec, now=103.0)
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
        pos = dial_repeat_store.interpolated_position(rec, now=100.7)
        assert pos == pytest.approx(10.0)

    def test_never_negative(self):
        import dial_repeat_store as drs
        rec = drs.RepeatRecord(
            available=True, state="replaying", armed=True,
            recording_seconds=10.0, position_seconds=0.0, duration_seconds=0.0,
            observed_at=100.0,
        )
        pos = dial_repeat_store.interpolated_position(rec, now=99.0)  # clock went backwards
        assert pos >= 0.0

    def _open_repeat_screen_directly(self, display, aid):
        """Set up the repeat screen's own state without going through a
        real poll, so the clock driving the replaying position can be
        fully controlled by the test."""
        with display._lock:
            display._screen = "repeat"
            display._repeat_screen = dds.ApplianceScreenState(
                appliance_id=aid, service_name="Kitchen", opened_at=1000.0,
            )

    def _seed_replaying(self, aid, position_seconds, observed_at=1000.0):
        import dial_repeat_store as drs
        seed_repeat(aid, drs.RepeatRecord(
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
        display._repeat_line.painted_second = 3
        # shown(now) = position + elapsed - DEFAULT_LATENCY_S
        #            = 5.0 + 1.002 - 2.0 = 4.002 -- just past the 4.0 boundary.
        display._overlay_signal.clear()
        with patch("dial_display.time.monotonic", return_value=1001.002):
            display.fire_timer_for_tests("repeat_line")
        assert display._overlay_signal.is_set()

    def test_tick_repeat_line_does_not_signal_mid_second(self):
        aid = "9" * 20
        display, fb, gt = make_display(targets=[])
        display.enable()
        self._open_repeat_screen_directly(display, aid)
        self._seed_replaying(aid, position_seconds=5.0, observed_at=1000.0)
        display._repeat_line.painted_second = 4
        # shown(now) = 5.0 + 1.5 - 2.0 = 4.5 -- mid-second, 4 already painted, not due.
        display._overlay_signal.clear()
        with patch("dial_display.time.monotonic", return_value=1001.5):
            display.fire_timer_for_tests("repeat_line")
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
        display.fire_timer_for_tests("repeat_line")
        assert not display._overlay_signal.is_set()


class TestNextRepaintDeadline:
    def _seed(self, aid, position_seconds, observed_at=1000.0):
        import dial_repeat_store as drs
        seed_repeat(aid, drs.RepeatRecord(
            available=True, state="replaying", armed=True,
            recording_seconds=30.0, position_seconds=position_seconds, duration_seconds=30.0,
            observed_at=observed_at,
        ))

    def _opened(self, aid):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "repeat"
            display._repeat_screen = dds.ApplianceScreenState(
                appliance_id=aid, service_name="Kitchen", opened_at=1000.0,
            )
        return display

    @pytest.mark.parametrize("shown, expected_remaining", [(2.3, 0.7), (2.999, 0.001), (3.0, 1.0)])
    def test_boundary_offset_from_shown_position(self, shown, expected_remaining):
        aid = "d" * 20
        display = self._opened(aid)
        # Chosen so shown(now) == `shown` exactly: shown = position +
        # elapsed - DEFAULT_LATENCY_S, with elapsed fixed at 1.0.
        position = shown + dial_repeat_store.DEFAULT_LATENCY_S - 1.0
        self._seed(aid, position_seconds=position, observed_at=1000.0)
        display._repeat_line.painted_second = math.floor(shown)
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
        seed_repeat(aid, drs.RepeatRecord(
            available=True, state="hold", armed=False,
            recording_seconds=30.0, position_seconds=0.0, duration_seconds=30.0,
            observed_at=1000.0,
        ))
        with patch("dial_display.time.monotonic", return_value=1000.0):
            assert display._next_repaint_deadline() is None

    def test_controls_hidden_deadline_alone(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._controls.hidden_until = 1000.2
        with patch("dial_display.time.monotonic", return_value=1000.0):
            deadline = display._next_repaint_deadline()
        assert deadline == pytest.approx(1000.205)

    def test_earlier_of_repeat_and_controls_hidden_wins(self):
        aid = "e" * 20
        display = self._opened(aid)
        # shown(1000.0) == 2.0 exactly -> repeat deadline is 1000.0 + 1.0 + 0.005.
        self._seed(aid, position_seconds=2.0 + dial_repeat_store.DEFAULT_LATENCY_S, observed_at=1000.0)
        display._repeat_line.painted_second = 2
        display._controls.hidden_until = 1000.3
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
        screen = dds.ApplianceScreenState(
            appliance_id=aid, service_name="Kitchen", opened_at=1000.0,
        )
        for position, expected in [(2.0, "0:00"), (2.9, "0:00"), (3.0, "0:01"), (3.9, "0:01")]:
            seed_repeat(aid, drs.RepeatRecord(
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
        screen = dds.ApplianceScreenState(
            appliance_id=aid, service_name="Kitchen", opened_at=1000.0,
        )
        # (latency, reported position, expected counter)
        for latency, position, expected in [
            (0.3, 0.2, "0:00"), (0.3, 1.2, "0:00"), (0.3, 1.3, "0:01"), (0.3, 2.4, "0:02"),
            (3.5, 3.4, "0:00"), (3.5, 4.4, "0:00"), (3.5, 4.5, "0:01"), (3.5, 6.5, "0:03"),
            (3.5, 0.0, "0:00"),
        ]:
            seed_repeat(aid, drs.RepeatRecord(
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
        assert dial_repeat_store.heard_position(rec, 1000.0) == pytest.approx(-2.5)
        assert dial_repeat_store.heard_position(rec, 1005.0) == pytest.approx(2.5)


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
            display._repeat_screen = dds.ApplianceScreenState(
                appliance_id=self.AID, service_name="Kitchen", opened_at=1000.0,
            )
        return display

    def _seed(self, position, observed_at, state="replaying"):
        import dial_repeat_store as drs
        seed_repeat(self.AID, drs.RepeatRecord(
            available=True, state=state, armed=True,
            recording_seconds=self.DUR, position_seconds=position, duration_seconds=self.DUR,
            observed_at=observed_at,
        ))

    def _resync(self, clock, shift):
        """What a status poll does: install a fresh record stamped now whose
        interpolated clock is `shift` seconds ahead (negative: behind) of
        the current record's."""
        rec = repeat_of(self.AID)
        self._seed(dial_repeat_store.interpolated_position(rec, clock.t) + shift, clock.t)

    def _paint(self, display):
        with display._lock:
            display._repaint_current_locked()
        return display._repeat_line.painted_second

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
            display.fire_timer_for_tests("repeat_line")
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
            display.fire_timer_for_tests("repeat_line")
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
            display.fire_timer_for_tests("repeat_line")
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
            self._resync(clock, -(ddr.REPEAT_COUNTER_HOLD_S - 0.05))   # just inside the hold window
            t_hold = clock.t
            # Counter 2.1 held at 3; 4 is owed at value 4.0, i.e. 1.9 s on.
            # Run to just short of that so the loop exits on that paint.
            painted = self._run(display, clock, 1.9)
        assert painted == [4]
        assert clock.t - t_hold <= 1.0 + ddr.REPEAT_COUNTER_HOLD_S + 0.01

    def test_restart_re_anchors_to_zero(self):
        # A restart reaches the screen as the record the appliance reports
        # once the seek is accepted: replaying, back at the start.
        display = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            self._seed(position=9.0, observed_at=1000.0)
            assert self._paint(display) == 7
            clock.t = 1000.3
            self._seed(position=0.0, observed_at=clock.t)
            assert display._next_repaint_deadline() == pytest.approx(clock.t)   # owed now
            display._overlay_signal.clear()
            display.fire_timer_for_tests("repeat_line")
            assert display._overlay_signal.is_set()
            assert self._paint(display) == 0
            assert self._line(display, clock).startswith("0:00 / ")

    def test_a_later_reading_at_the_restart_position_keeps_the_counter_at_zero(self):
        """A reading taken just after the restart is consistent with it:
        replaying, at the start. Its re-stamp leaves the counter at zero,
        with no step back and no hold-state line."""
        display = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            self._seed(position=9.0, observed_at=1000.0)
            assert self._paint(display) == 7
            clock.t = 1000.2
            self._seed(position=0.0, observed_at=clock.t)
            assert self._paint(display) == 0
            clock.t = 1000.5
            self._seed(position=0.0, observed_at=clock.t)
            display._overlay_signal.clear()
            display.fire_timer_for_tests("repeat_line")
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
            display.fire_timer_for_tests("repeat_line")
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
            display._repeat_line.painted_second = 3
            display.cycle_pages()
            with display._lock:
                display._repaint_current_locked()
        assert display._screen == "repeat"
        assert display._repeat_line.painted_second == 2

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
        display = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            self._seed(position=5.0, observed_at=1000.0)
            assert self._paint(display) == 3
            seed_repeat(self.AID, None)
            assert self._paint(display) is None
            assert display._repeat_layout_shown == "enable"

    def test_builder_never_writes_the_reference(self):
        display = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            self._seed(position=5.0, observed_at=1000.0)
            display._repeat_line.painted_second = 3
            clock.t = 1000.1
            self._resync(clock, -0.4)
            view_line = self._line(display, clock)
        assert view_line.startswith("0:03 / ")
        assert display._repeat_line.painted_second == 3

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
# A repeat-transport result: what it asks of the screen.
# ---------------------------------------------------------------------------

class TestOnRepeatResultOnScreen:
    def test_ok_true_records_the_acceptance_and_signals_repaint(self):
        aid = "1" * 20
        display, fb, gt = make_display(targets=[])
        seed_repeat(aid, _repeat_obj(state="hold"))
        display.core.begin_transport(aid, "seek")
        display._overlay_signal.clear()

        on_repeat_result(display,
            "transport", aid, 200,
            {"ok": True, "state": "replaying", "armed": True, "position_seconds": 0.0},
        )
        assert display.core.snapshot().transport.state == "accepted"
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


class TestCompactStopFlow:
    def test_ok_stop_ack_closes_the_repeat_screen_to_main(self):
        aid = "5" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_compact_display(targets=[t], repeat_capable=True)
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

        seed_repeat(aid, _repeat_obj(state="replaying", replay={"active": True, "position_seconds": 1.0, "duration_seconds": 30.0}))
        with patch("dial_core.DialCore._send"):
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
        aid = "6" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_compact_display(targets=[t])
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()

        seed_repeat(aid, _repeat_obj(state="replaying", replay={"active": True, "position_seconds": 1.0, "duration_seconds": 30.0}))
        with patch("dial_core.DialCore._send"):
            display.repeat_stop_tap()
        on_repeat_result(display, "transport", aid, 200, {"ok": False, "error": "fading_out"})
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

    def test_off_compact_the_same_ack_leaves_the_screen_on_repeat(self):
        aid = "7" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])  # base tier
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"

        seed_repeat(aid, _repeat_obj(state="replaying", replay={"active": True, "position_seconds": 1.0, "duration_seconds": 30.0}))
        with patch("dial_core.DialCore._send"):
            display.repeat_stop_tap()
        on_repeat_result(display,
            "transport", aid, 200,
            {"ok": True, "state": "hold", "armed": False, "position_seconds": 0.0},
        )
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"


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
        aid = "2" * 20
        display = self._opened(aid)
        seed_repeat(aid, _repeat_obj(state="replaying", replay={"active": True, "position_seconds": 1.0, "duration_seconds": 30.0}))
        with display._lock:
            display._repaint_current_locked()
        assert display.touch_surface()[0] == "repeat_replay"

    def test_hold_also_reports_repeat_replay(self):
        # "hold" builds the same "replaying" RepeatViewState.layout as a
        # running replay (see _build_repeat_view_locked) -- the compact
        # surface follows the layout, not the daemon state name.
        aid = "3" * 20
        display = self._opened(aid)
        seed_repeat(aid, _repeat_obj(state="hold"))
        with display._lock:
            display._repaint_current_locked()
        assert display.touch_surface()[0] == "repeat_replay"

    def test_back_to_repeat_once_the_enable_layout_is_repainted(self):
        aid = "4" * 20
        display = self._opened(aid)
        seed_repeat(aid, _repeat_obj(state="replaying", replay={"active": True, "position_seconds": 1.0, "duration_seconds": 30.0}))
        with display._lock:
            display._repaint_current_locked()
        assert display.touch_surface()[0] == "repeat_replay"

        seed_repeat(aid, _repeat_obj(state="idle"))
        with display._lock:
            display._repaint_current_locked()
        assert display.touch_surface()[0] == "repeat"

    def test_never_reports_repeat_replay_off_compact(self):
        aid = "5" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = make_display(targets=[t])  # base tier, 160x128
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        seed_repeat(aid, _repeat_obj(state="replaying", replay={"active": True, "position_seconds": 1.0, "duration_seconds": 30.0}))
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

        # dial_touch_wiring.py's on_zone_tap routes every DOTS tap to this same
        # entry point regardless of which screen/layout drew the cell the
        # finger landed on -- the compact replaying layout's own "time"
        # strip is drawn there, but the dispatch is identical.
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"
        assert display.consume_repeat_close_reveal() is True


class TestReplayTimer:
    """The replay position line shown on the main page after a picker start."""

    AID = "a" * 20

    def _display(self, state="hold", **repeat):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.core.set_field_for_tests("manual_id", self.AID)
        now = time.monotonic()
        seed_repeat(self.AID, _repeat_obj(state=state, **repeat))
        display._repeat_line.arm(self.AID, time.monotonic())
        return display, fb

    def test_picker_pick_arms_the_timer(self):
        display, fb, gt = picker_with_row(aid=self.AID)
        with patch("dial_core.DialCore._send"):
            display.picker_pick(0)
        assert display._repeat_line.timer_id == self.AID
        assert display._repeat_line.timer_shown_at == 0.0

    def test_shows_the_held_position_at_full_opacity(self):
        display, fb = self._display(recording_seconds=12.0)
        now = time.monotonic()
        with display._lock:
            timer = display._replay_timer_locked(now)
        assert timer == ("0:00 / 0:12", 1.0, None)
        assert display._repeat_line.timer_shown_at == now

    def test_fades_after_the_show_window_then_ends(self):
        display, fb = self._display()
        now = time.monotonic()
        display._repeat_line.timer_shown_at = now - ddr.REPLAY_TIMER_SHOW_S - ddr.REPLAY_TIMER_FADE_S / 2
        with display._lock:
            text, alpha, _ = display._replay_timer_locked(now)
        assert alpha == pytest.approx(0.5)
        display._repeat_line.timer_shown_at = now - ddr.REPLAY_TIMER_SHOW_S - ddr.REPLAY_TIMER_FADE_S
        with display._lock:
            assert display._replay_timer_locked(now) is None
        assert display._repeat_line.timer_id is None

    def test_not_drawn_for_another_shown_appliance(self):
        display, fb = self._display()
        display.core.set_field_for_tests("manual_id", "b" * 20)
        with display._lock:
            assert display._replay_timer_locked(time.monotonic()) is None
        assert display._repeat_line.timer_id == self.AID

    def test_not_drawn_on_the_compact_tier(self):
        display, fb = self._display()
        display._compact_tier = lambda: True
        with display._lock:
            assert display._replay_timer_locked(time.monotonic()) is None

    def test_dropped_when_nothing_shows_within_the_arm_window(self):
        display, fb = self._display(state="recording")
        now = time.monotonic()
        display._repeat_line.timer_armed_at = now - ddr.REPLAY_TIMER_ARM_S
        with display._lock:
            assert display._replay_timer_locked(now) is None
        assert display._repeat_line.timer_id is None

    def test_a_rejected_seek_drops_it(self):
        display, fb = self._display()
        display.core.begin_transport(self.AID, "seek")
        on_repeat_result(display, "transport", self.AID, 412, {"ok": False, "error": "no_recording"})
        assert display._repeat_line.timer_id is None

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
        display._repeat_line.timer_shown_at = now
        assert display._replay_timer_deadline(now) == pytest.approx(now + ddr.REPLAY_TIMER_SHOW_S + 0.005)

    def test_deadline_is_floored_after_its_own_signal(self):
        display, fb = self._display()
        now = time.monotonic()
        display._repeat_line.timer_shown_at = now - ddr.REPLAY_TIMER_SHOW_S - 0.1
        display._repeat_line.timer_signal_at = now
        assert display._replay_timer_deadline(now) >= now + ddr.REPLAY_TIMER_FADE_GAP_S

    def test_deadline_drops_a_timer_whose_replay_ended(self):
        display, fb = self._display()
        display._repeat_line.timer_shown_at = time.monotonic()
        seed_repeat(self.AID, None)
        display._replay_timer_deadline(time.monotonic())
        assert display._repeat_line.timer_id is None

    def test_no_deadline_off_the_main_page(self):
        display, fb = self._display()
        display._screen = "repeat"
        assert display._replay_timer_deadline(time.monotonic()) is None


class TestRepeatResultsHandedStraightToTheCore:
    """The service hands the repeat worker's results to the core, not to
    this view: what they meant reaches the screen when the view next folds
    in what the core has published."""

    def test_the_compact_tier_closes_the_repeat_screen_on_its_own_stop_ack(self):
        aid = "6" * 20
        t = _target(name="Kitchen", service_name="Kitchen", appliance_id=aid)
        display, fb, gt = _make_compact_display(targets=[t], repeat_capable=True)
        display.enable()
        _poll_focused_with_repeat(display, fb, aid, _repeat_obj(state="idle", available=True))
        display.cycle_pages()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "repeat"
        seed_repeat(aid, _repeat_obj(state="replaying", replay={"active": True, "position_seconds": 1.0, "duration_seconds": 30.0}))
        with patch("dial_core.DialCore._send"):
            display.repeat_stop_tap()

        display._core._fold_reply(
            aid, "stop", pending_token(display, "transport"),
            PeerReply(True, None, None, None, {"ok": True}, None),
        )
        assert display._screen_request is None
        display._apply_pending_snapshot()
        assert display._screen_request == "main"

    def test_a_rejected_replay_drops_the_replay_timer(self):
        aid = "9" * 20
        display, fb, gt = make_display(targets=[])
        display._repeat_line.arm(aid, time.monotonic())
        display._overlay_signal.clear()
        display._core._wake.clear()

        display._core._fold_reply(aid, "seek", 0.0, PeerReply(False, "fading_out", None, None, {}, None))
        assert display._repeat_line.timer_id == aid
        display._apply_pending_snapshot()
        assert display._repeat_line.timer_id is None
        assert display._overlay_signal.is_set()
        assert display._core._wake.is_set()

    def test_an_accepted_replay_the_dial_follows_folds_at_once(self):
        aid = "8" * 20
        display, fb, gt = make_display(targets=[])
        display.core.request_fold = MagicMock()
        with patch.object(display._core, "accept_replay", return_value=True):
            display._core._fold_reply(
                aid, "seek", 0.0,
                PeerReply(True, None, None, None, {"ok": True, "state": "replaying"}, None),
            )
        display.core.request_fold.assert_not_called()
        display._apply_pending_snapshot()
        display.core.request_fold.assert_called_once()


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
