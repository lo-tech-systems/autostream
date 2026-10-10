"""Tests for how the dial display folds the core's snapshots into the panel:
no frame for a snapshot nothing on screen depends on, exactly the frames a
real change needs, the wake rules for a sleeping panel, and the real threads
(the core's poll, the view's repaint loop) end to end."""
import contextlib
import time
from unittest.mock import patch

import pytest

Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")

from dial_test_support import (
    FakeBackend,
    _status_result,
    _target,
    _track_id,
    make_display,
)
import dial_display as dd
from dial_core import SourceEffects


def _fold(display):
    """Run the repaint loop's wakes for whatever is signalled, as its thread
    would, until nothing is left."""
    for _ in range(6):
        if not display._overlay_signal.is_set():
            return
        display._repaint_once()


class _Rig:
    """A fitted display with one authorised appliance playing, polled by hand
    with the repaint loop's wakes run after each tick."""

    def __init__(self, targets=None, fitted=True):
        self.target = _target(auth="authorized")
        targets = [self.target] if targets is None else targets
        self.display, self.fb, self.gt = make_display(targets=targets, fitted=fitted)
        self.display.enable()
        self.track = _track_id()
        _fold(self.display)

    def tick(self):
        picture = Image.new("RGB", (FakeBackend.width, FakeBackend.height))
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch(
                "dial_core.fetch_target_status",
                side_effect=lambda *a, **k: _status_result(track_id=self.track),
            ))
            stack.enter_context(patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpeg", "")))
            stack.enter_context(patch("dial_display.decode_artwork", return_value=picture))
            stack.enter_context(patch(
                "dial_display_compositor.transform_artwork_for_panel", return_value=picture,
            ))
            self.display._poll_once()
            _fold(self.display)

    def frames_for(self, action=None):
        """The frames pushed by *action* (default: one more tick)."""
        before = len(self.fb.displayed)
        (action or self.tick)()
        return len(self.fb.displayed) - before


class TestNoRedundantFrames:
    def test_quiet_ticks_push_no_frames(self):
        rig = _Rig()
        assert rig.frames_for() == 2           # the first sight of the track
        assert [rig.frames_for() for _ in range(6)] == [0] * 6

    def test_a_changed_title_pushes_one_frame(self):
        rig = _Rig()
        rig.tick()
        rig.track = _track_id(title="Another song")
        assert rig.frames_for() == 1
        assert rig.frames_for() == 0

    def test_a_new_picture_pushes_one_frame(self):
        rig = _Rig()
        rig.tick()
        rig.track = _track_id(artwork_url="https://provider.example/other.jpg")
        assert rig.frames_for() == 1
        assert rig.frames_for() == 0

    def test_playback_ending_pushes_the_logo_once_and_playing_again_pushes_the_track(self):
        rig = _Rig()
        rig.tick()
        rig.gt.return_value = []
        assert rig.frames_for() == 1
        assert [rig.frames_for() for _ in range(4)] == [0] * 4
        rig.gt.return_value = [rig.target]
        assert rig.frames_for() == 2
        assert rig.frames_for() == 0

    def test_a_list_left_open_over_an_idle_dial_pushes_no_frame_per_tick(self):
        rig = _Rig(targets=[])
        rig.tick()
        rig.display.open_selector()
        _fold(rig.display)
        rig.tick()
        assert rig.display._screen == "selector"
        assert [rig.frames_for() for _ in range(4)] == [0] * 4

    def test_a_snapshot_with_nothing_shown_in_it_pushes_no_frame(self):
        rig = _Rig()
        rig.tick()
        rig.tick()
        rig.display._subscription = rig.display._core.subscribe(rig.display._core_changed)
        frames = len(rig.fb.displayed)
        rig.display._core.set_field("eq_available", True)
        rig.display._core.set_field("outputs_available", True)
        assert rig.display._overlay_signal.is_set()        # the thread is woken ...
        _fold(rig.display)
        assert len(rig.fb.displayed) == frames             # ... and finds nothing to draw

    def test_a_tick_is_folded_once_however_often_the_core_publishes_after_it(self):
        rig = _Rig()
        rig.tick()
        with patch.object(rig.display, "show_logo") as show_logo, \
             patch.object(rig.display, "_show_artwork") as show_artwork:
            rig.display._core.set_field("eq_available", True)
            rig.display._apply_pending_snapshot()
            rig.display._core.set_field("eq_available", False)
            rig.display._apply_pending_snapshot()
        show_logo.assert_not_called()
        show_artwork.assert_not_called()

    def test_the_same_snapshot_is_folded_only_once(self):
        rig = _Rig()
        rig.tick()
        applied = rig.display._applied
        with patch.object(rig.display, "_apply_snapshot") as fold:
            rig.display._apply_pending_snapshot()
            rig.display._apply_pending_snapshot()
        fold.assert_not_called()
        assert rig.display._applied is applied


class TestSleepingPanel:
    def _asleep(self, rig):
        with rig.display._lock:
            rig.display._sleep_locked()
        _fold(rig.display)      # the repaint going to sleep asks for
        assert rig.display._display_sleeping

    def test_a_snapshot_that_is_not_a_wake_condition_paints_nothing_asleep(self):
        rig = _Rig(targets=[])
        rig.tick()
        self._asleep(rig)
        frames, wakes = len(rig.fb.displayed), rig.fb.wake_calls
        for _ in range(3):
            rig.tick()
        rig.display._core.set_field("eq_available", True)
        rig.display._apply_pending_snapshot()
        assert rig.display._display_sleeping
        assert (len(rig.fb.displayed), rig.fb.wake_calls) == (frames, wakes)

    def test_a_usable_playing_appliance_wakes_it_on_the_next_tick(self):
        rig = _Rig(targets=[])
        rig.tick()
        self._asleep(rig)
        rig.gt.return_value = [rig.target]
        rig.tick()
        assert not rig.display._display_sleeping
        assert rig.fb.wake_calls == 1

    def test_a_refused_appliance_playing_never_wakes_it(self):
        rig = _Rig(targets=[])
        rig.tick()
        self._asleep(rig)
        frames = len(rig.fb.displayed)
        rig.gt.return_value = [_target(auth="unauthorized")]
        for _ in range(3):
            rig.tick()
        assert rig.display._display_sleeping
        assert rig.fb.wake_calls == 0 and len(rig.fb.displayed) == frames

    def test_touch_wakes_it_and_asks_the_core_to_poll_and_reconcile(self):
        rig = _Rig(targets=[])
        rig.tick()
        self._asleep(rig)
        with patch.object(rig.display._core, "request_poll") as request_poll:
            rig.display.notify_touch_activity()
            _fold(rig.display)
        assert not rig.display._display_sleeping
        request_poll.assert_called_with(reconcile=True)

    def test_a_confirmed_push_wakes_it_even_with_nothing_playing(self):
        rig = _Rig(targets=[])
        rig.tick()
        self._asleep(rig)
        rig.display._core._publish(lambda state: setattr(state, "auth_promotions", 1))
        rig.display._apply_pending_snapshot()
        assert not rig.display._display_sleeping
        assert rig.display._idle_started_at is None


class TestSignal:
    def test_set_asks_for_a_repaint_and_poke_only_wakes(self):
        signal = dd._Signal()
        signal.poke()
        assert signal.is_set()
        assert signal.consume() is False and not signal.is_set()
        signal.set()
        assert signal.consume() is True and not signal.is_set()

    def test_a_request_made_with_a_poke_is_not_lost(self):
        signal = dd._Signal()
        signal.poke()
        signal.set()
        assert signal.consume() is True

    def test_clear_forgets_a_request(self):
        signal = dd._Signal()
        signal.set()
        signal.clear()
        assert signal.consume() is False

    def test_a_display_wakes_on_a_publish_without_asking_to_paint(self):
        display, fb, gt = make_display(targets=[])
        display._subscription = display._core.subscribe(display._core_changed)
        display._overlay_signal.clear()
        display._core.set_field("eq_available", True)
        assert display._overlay_signal.is_set()
        assert display._overlay_signal.consume() is False


class TestQueuedEffects:
    def test_what_the_housekeeping_queued_reaches_the_screen(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._core._effects.append(SourceEffects(restarting=True))
        display._core._publish(lambda state: None)
        display._apply_pending_snapshot()
        assert display._screen_request == "restarting"
        assert display._core.take_effects() == []


class TestRealThreads:
    def _wait_until(self, condition, limit=3.0):
        deadline = time.monotonic() + limit
        while not condition() and time.monotonic() < deadline:
            time.sleep(0.01)
        return condition()

    def _stable_frames(self, fb, quiet=0.3, limit=4.0):
        """The frame count once no frame has arrived for *quiet* seconds."""
        deadline = time.monotonic() + limit
        last, since = len(fb.displayed), time.monotonic()
        while time.monotonic() < deadline:
            time.sleep(0.02)
            if len(fb.displayed) != last:
                last, since = len(fb.displayed), time.monotonic()
            elif time.monotonic() - since >= quiet:
                break
        return last

    def test_core_and_view_threads_produce_a_frame_then_stay_quiet(self):
        target = _target(auth="authorized")
        display, fb, gt = make_display(targets=[target])
        picture = Image.new("RGB", (FakeBackend.width, FakeBackend.height))
        with patch("dial_core.fetch_target_status",
                   side_effect=lambda *a, **k: _status_result(track_id=_track_id())), \
             patch("dial_core_poll.default_fetch_artwork", return_value=(b"jpeg", "")), \
             patch("dial_display.decode_artwork", return_value=picture), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=picture):
            display._core.set_poll_interval(0.05)
            display.start()
            try:
                assert self._wait_until(lambda: len(fb.displayed) > 0, limit=2.0)
                settled = self._stable_frames(fb)
                ticks = display._core.snapshot().ticks
                assert self._wait_until(lambda: display._core.snapshot().ticks >= ticks + 6, limit=2.0)
                time.sleep(0.3)
                assert len(fb.displayed) == settled
            finally:
                display.stop()
        assert display.get_status()["showing"] in ("artwork", "logo", "noop")

    def test_a_sleeping_panel_wakes_while_the_walks_request_is_still_out(self):
        target = _target(auth="authorized")
        display, fb, gt = make_display(targets=[target])
        display.enable()
        with display._lock:
            display._sleep_locked()
        woke_during_request = []

        def slow_status(*args, **kwargs):
            # The panel must wake from the playing set, published before
            # this request returns.
            self._wait_until(lambda: fb.wake_calls >= 1, limit=2.0)
            woke_during_request.append(fb.wake_calls)
            return _status_result(track_id=None)

        with patch("dial_core.fetch_target_status", side_effect=slow_status):
            display.start()
            try:
                assert self._wait_until(lambda: woke_during_request, limit=3.0)
            finally:
                display.stop()
        assert woke_during_request[0] == 1

    def test_the_view_stops_cleanly_with_the_core_polling(self):
        display, fb, gt = make_display(targets=[])
        display._core.set_poll_interval(0.02)
        display.start()
        assert self._wait_until(lambda: display._core.snapshot().ticks >= 2)
        threads = [display._core._thread, display._repaint_thread]
        display.stop()
        assert not any(t.is_alive() for t in threads)
        assert display._subscription is None
