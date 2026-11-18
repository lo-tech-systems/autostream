"""Tests for the display's controls overlay: when it is held, the artwork-tap hide
window and the reveal slide, and the compact tier's own controls window.
"""
from __future__ import annotations

import sys
import threading
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

from dial_config import DialDisplayConfig
from dial_display_views import OverlayState
from dial_touch_layout import layout_for, repeat_layout_for
import dial_display as dd
import dial_display_controls as ddc
import dial_display_state as dds
import dial_display_compositor as dd_compositor
from dial_test_support import (
    FakeBackend,
    _FakeClock,
    _repeat_obj,
    _status_result,
    _target,
    _track_id,
    make_display,
    patch_monotonic,
    seed_repeat,
)
from dial_display_test_support import (
    _make_compact_display,
    _poll_focused_with_repeat,
    _poll_with_artwork,
)


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
    SECONDS — see hide_controls()/ControlsReveal.hidden()."""

    def test_hide_controls_sets_deadline_and_signals(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        display._overlay_signal.clear()
        with patch("dial_display.time.monotonic", return_value=1000.0):
            display.hide_controls()
        assert display._controls.hidden_until == pytest.approx(1000.0 + ddc.CONTROLS_HIDE_SECONDS)
        assert display._overlay_signal.is_set()

    def test_persistent_overlay_shown_false_during_window_true_after(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.persistent_overlay_shown() is True
        with patch("dial_display.time.monotonic", return_value=1000.0):
            display.hide_controls()
        with patch("dial_display.time.monotonic", return_value=1000.0 + ddc.CONTROLS_HIDE_SECONDS - 0.1):
            assert display.persistent_overlay_shown() is False
        with patch("dial_display.time.monotonic", return_value=1000.0 + ddc.CONTROLS_HIDE_SECONDS + 0.1):
            assert display.persistent_overlay_shown() is True

    def test_set_overlay_visible_ends_the_window_early(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.hide_controls()
        assert display._controls.hidden(time.monotonic()) is True
        display.set_overlay(dd.OverlayState(visible=True))
        assert display._controls.hidden(time.monotonic()) is False

    def test_set_overlay_invisible_does_not_end_the_window(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.hide_controls()
        display.set_overlay(dd.OverlayState(visible=False))
        assert display._controls.hidden(time.monotonic()) is True

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
        with patch("dial_display.time.monotonic", return_value=1000.0 + ddc.CONTROLS_HIDE_SECONDS + 0.1):
            display.fire_timer_for_tests("controls_hidden")
        assert display._overlay_signal.is_set()
        assert display._controls.hidden_until == 0.0
        # One-shot: a second call after firing does not re-signal.
        display._overlay_signal.clear()
        with patch("dial_display.time.monotonic", return_value=1000.0 + ddc.CONTROLS_HIDE_SECONDS + 0.2):
            display.fire_timer_for_tests("controls_hidden")
        assert not display._overlay_signal.is_set()

    def test_tick_controls_hidden_noop_before_deadline(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with patch("dial_display.time.monotonic", return_value=1000.0):
            display.hide_controls()
        display._overlay_signal.clear()
        with patch("dial_display.time.monotonic", return_value=1000.0 + 1.0):
            display.fire_timer_for_tests("controls_hidden")
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
            clock.t += ddc.REVEAL_ANIMATION_S + 0.1
            _repaint(display)
            display.fire_timer_for_tests("reveal")
        assert display._controls.started_at == 0.0
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
        assert display._controls.hidden_until == pytest.approx(1000.0 + ddc.CONTROLS_HIDE_SECONDS)
        assert display._controls.started_at == 0.0
        assert display._overlay_signal.is_set()

    def test_hide_controls_is_a_noop_off_main(self):
        display, fb, gt, _ = self._rich()
        display._screen = "selector"
        display.hide_controls()
        assert display._controls.hidden_until == 0.0

    def test_ease_and_progress(self):
        assert ddc.reveal_ease(0.0) == 0.0
        assert ddc.reveal_ease(1.0) == 1.0
        assert ddc.reveal_ease(0.5) == 0.5
        assert ddc.reveal_ease(0.25) == 0.15625
        values = [ddc.reveal_ease(t / 20) for t in range(21)]
        assert values == sorted(values)

        display, fb, gt, _ = self._rich()
        # No slide stamped yet: never animating.
        assert display._controls.progress(1000.0) == 0.0
        display._controls.started_at = 1000.0
        assert display._controls.progress(1000.0) == 0.0
        assert display._controls.progress(1000.0 + ddc.REVEAL_ANIMATION_S / 2.0) == pytest.approx(0.5)
        assert display._controls.progress(1000.0 + ddc.REVEAL_ANIMATION_S) == 0.0

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
            assert display._controls.started_at == 1000.0
            assert display._controls.frame_at >= 1000.0

            clock.t = 1000.0 + ddc.REVEAL_ANIMATION_S / 2.0
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

            clock.t = 1000.0 + ddc.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            assert _pixels(fb.displayed[-1]) == _pixels(bare)

            # The window's expiry slides the controls back in: the first
            # frame is the bare frame again, the last is the controls.
            t_expiry = 1000.0 + ddc.CONTROLS_HIDE_SECONDS + 0.1
            clock.t = t_expiry
            display.fire_timer_for_tests("controls_hidden")
            _repaint(display)
            assert _pixels(fb.displayed[-1]) == _pixels(bare)
            assert display._controls.started_at == t_expiry
            assert display._controls.sliding_in is True

            clock.t = t_expiry + ddc.REVEAL_ANIMATION_S / 2.0
            _repaint(display)
            assert _pixels(fb.displayed[-1]) != _pixels(bare)
            assert _pixels(fb.displayed[-1]) != _pixels(held_frame)
            assert display._controls.progress(clock.t) == pytest.approx(0.5)

            clock.t = t_expiry + ddc.REVEAL_ANIMATION_S + 0.05
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
            assert display._controls.started_at == 1000.0

            clock.t = 1000.05
            display.set_overlay(OverlayState(visible=False))
            clock.t = 1000.0 + ddc.REVEAL_ANIMATION_S / 2.0
            _repaint(display)
            bare = _bare_frame(display, fb)
            assert _pixels(fb.displayed[-1]) != _pixels(shown_frame)
            assert _pixels(fb.displayed[-1]) != _pixels(bare)

            clock.t = 1000.0 + ddc.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            assert _pixels(fb.displayed[-1]) == _pixels(bare)

            clock.t = 1000.0 + ddc.CONTROLS_HIDE_SECONDS + 0.1
            display.fire_timer_for_tests("controls_hidden")
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
            assert display._controls.hidden_until == 0.0
            assert display._controls.started_at == 1000.0
            assert _pixels(fb.displayed[-1]) == _pixels(shown_frame)

            clock.t = 1000.0 + ddc.REVEAL_ANIMATION_S / 2.0
            _repaint(display)
            bare = _bare_frame(display, fb)
            assert _pixels(fb.displayed[-1]) != _pixels(shown_frame)
            assert _pixels(fb.displayed[-1]) != _pixels(bare)

            clock.t = 1000.0 + ddc.REVEAL_ANIMATION_S + 0.05
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
        assert display._controls.started_at == 0.0

    def test_compact_tier_never_hides_or_slides(self):
        display, fb, gt = _make_compact_display(targets=[_target()], always_show_controls=True)
        display.enable()
        _poll_with_artwork(display, fb)
        display.hide_controls()
        assert display._controls.hidden_until == 0.0
        assert display._controls.started_at == 0.0

    @pytest.mark.parametrize("always_show", [True, False])
    def test_reveal_tap_slides_the_controls_in(self, always_show):
        display, fb, gt, band_h = self._rich(always_show=always_show)
        held_frame = self._shown_settled(display, fb) if not always_show else fb.displayed[-1]
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            clock.t = 1000.0 + ddc.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            bare = _bare_frame(display, fb)
            assert _pixels(fb.displayed[-1]) == _pixels(bare)
            display.fire_timer_for_tests("reveal")
            assert display._controls.started_at == 0.0

            # The reveal tap ends the window; the frame that finds the
            # controls back starts the slide and equals the bare frame.
            clock.t = 1002.0
            display.set_overlay(OverlayState(visible=True))
            assert display._controls.hidden_until == 0.0
            _repaint(display)
            assert display._controls.started_at == 1002.0
            assert display._controls.sliding_in is True
            assert _pixels(fb.displayed[-1]) == _pixels(bare)

            clock.t = 1002.0 + ddc.REVEAL_ANIMATION_S / 2.0
            _repaint(display)
            mid = fb.displayed[-1]
            dy = round(0.5 * band_h)
            assert _pixels(mid) != _pixels(bare)
            assert _pixels(mid) != _pixels(held_frame)
            assert _rows_equal(mid, bare, (0, band_h - dy, fb.width, band_h))

            clock.t = 1002.0 + ddc.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            assert _pixels(fb.displayed[-1]) == _pixels(held_frame)

    def test_progress_runs_backwards_while_sliding_in(self):
        display, fb, gt, _ = self._rich()
        display._controls.started_at = 1000.0
        display._controls.sliding_in = True
        assert display._controls.progress(1000.0) == 1.0
        assert display._controls.progress(1000.0 + ddc.REVEAL_ANIMATION_S / 2.0) == pytest.approx(0.5)
        assert display._controls.progress(1000.0 + 0.25 * ddc.REVEAL_ANIMATION_S) == pytest.approx(
            1.0 - ddc.reveal_ease(0.25))
        assert display._controls.progress(1000.0 + ddc.REVEAL_ANIMATION_S) == 0.0

    def test_reveal_tap_mid_slide_out_turns_around_without_a_jump(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            clock.t = 1000.2
            _repaint(display)
            out_progress = display._controls.progress(1000.2)
            out_frame = fb.displayed[-1]
            assert display._controls.sliding_in is False

            # The tap lands; the next frame continues from the same place.
            display.set_overlay(OverlayState(visible=True))
            assert display._controls.started_at == 1000.0  # untouched by the tap
            _repaint(display)
            assert display._controls.sliding_in is True
            assert display._controls.progress(1000.2) == pytest.approx(out_progress)
            assert _pixels(fb.displayed[-1]) == _pixels(out_frame)

            # Then it runs back the way it came, over the remaining time.
            clock.t = 1000.2 + 0.1
            assert display._controls.progress(clock.t) < out_progress
            # The reversed slide ends after the time the slide-out had run.
            assert display._controls.started_at + ddc.REVEAL_ANIMATION_S == pytest.approx(1000.2 + 0.2)
            clock.t = 1000.2 + 0.2 + 0.01
            _repaint(display)
            assert display._controls.progress(clock.t) == 0.0

    def test_hide_mid_slide_in_turns_around_without_a_jump(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            clock.t = 1000.0 + ddc.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            clock.t = 1002.0
            display.set_overlay(OverlayState(visible=True))
            _repaint(display)
            clock.t = 1002.0 + 0.1
            _repaint(display)
            in_progress = display._controls.progress(clock.t)
            in_frame = fb.displayed[-1]
            assert 0.0 < in_progress < 1.0
            assert display._controls.sliding_in is True

            display.hide_controls()
            _repaint(display)
            assert display._controls.sliding_in is False
            assert display._controls.progress(clock.t) == pytest.approx(in_progress)
            assert _pixels(fb.displayed[-1]) == _pixels(in_frame)

    def test_slide_start_is_never_zero(self):
        display, fb, gt, _ = self._rich()
        with display._lock:
            display._controls.last = True
            display._controls.started_at = 0.0
            animating, progress = display._controls.advance(0.0, False, True)
        assert display._controls.started_at != 0.0
        assert animating is True and progress == 0.0

    def test_first_frame_after_a_screen_change_does_not_slide(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.open_selector()
            _repaint(display)
            assert display._controls.last is None
            display.close_list()
            clock.t = 1000.2
            _repaint(display)
            assert display._screen == "main"
            assert display._controls.started_at == 0.0
            assert display._controls.last is True

    def test_first_touch_after_a_screen_change_in_touch_mode_slides_in(self):
        display, fb, gt, _ = self._rich(always_show=False)
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.open_selector()
            _repaint(display)
            display.close_list()
            _repaint(display)
            assert display._controls.started_at == 0.0
            assert display._controls.last is False
            clock.t = 1001.0
            display.set_overlay(OverlayState(visible=True))
            _repaint(display)
            assert display._controls.started_at == 1001.0
            assert display._controls.sliding_in is True

    def test_first_frame_after_waking_does_not_slide(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            with display._lock:
                display._sleep_locked()
            assert display._controls.last is None
            with display._lock:
                display._wake_locked()
            clock.t = 1001.0
            _repaint(display)
            assert display._controls.started_at == 0.0
            assert display._controls.last is True

    def test_first_frame_after_the_idle_screen_does_not_slide(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            gt.return_value = []
            display.fold_for_tests()
            _repaint(display)
            assert display._controls.last is None
            clock.t = 1001.0
            gt.return_value = [_target()]
            _poll_with_artwork(display, fb)
            assert display._controls.started_at == 0.0
            assert display._controls.last is True

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
            clock.t = 1000.0 + ddc.CONTROLS_HIDE_SECONDS + 0.1
            display.fire_timer_for_tests("controls_hidden")
            _repaint(display)
            assert display._controls.started_at == 0.0
            assert display._controls.last is None
            display.set_overlay(OverlayState(visible=True))
            _repaint(display)
            assert display._controls.started_at == 0.0
            if maker == "base":
                assert _pixels(fb.displayed[-1]) == _pixels(held_frame)

    def test_frame_gap_is_short_and_the_deadline_uses_it(self):
        assert ddc.REVEAL_FRAME_GAP_S == 0.001
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            display._controls.frame_at = 1000.2
            clock.t = 1000.2
            assert display._next_repaint_deadline() == pytest.approx(1000.2 + 0.001)

    def test_deadline_paces_from_the_end_of_the_frame(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            display._controls.frame_at = 1000.03
            clock.t = 1000.03
            assert display._next_repaint_deadline() == pytest.approx(1000.03 + ddc.REVEAL_FRAME_GAP_S)

            # The slot has passed: at once, with no margin added to the gap.
            clock.t = 1000.1
            assert display._next_repaint_deadline() == pytest.approx(1000.1)

            # Near the end the slide's own end wins over the next slot.
            display._controls.frame_at = 1000.5495
            clock.t = 1000.5495
            assert display._next_repaint_deadline() == pytest.approx(1000.0 + ddc.REVEAL_ANIMATION_S + 0.005)

            # The last slide frame finished sending after the end: the
            # settled frame is due at once, never at the next unrelated wake.
            display._controls.frame_at = 1000.56
            clock.t = 1000.56
            assert display._next_repaint_deadline() == pytest.approx(1000.56)

            # Once the end-of-slide tick has settled it, only the window's
            # end is left.
            display.fire_timer_for_tests("reveal")
            assert display._controls.started_at == 0.0
            assert display._next_repaint_deadline() == pytest.approx(1000.0 + ddc.CONTROLS_HIDE_SECONDS + 0.005)

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
            assert display._controls.started_at == 1000.0

            # A dismiss slide has no window; the tick must not end it early.
            display._overlay_signal.clear()
            clock.t = 1000.1
            display.fire_timer_for_tests("reveal")
            assert display._overlay_signal.is_set()
            assert display._controls.started_at == 1000.0

            display._overlay_signal.clear()
            clock.t = 1000.0 + ddc.REVEAL_ANIMATION_S + 0.01
            display.fire_timer_for_tests("reveal")
            assert display._overlay_signal.is_set()
            assert display._controls.started_at == 0.0

            display._overlay_signal.clear()
            clock.t = 1000.0 + ddc.REVEAL_ANIMATION_S + 0.05
            display.fire_timer_for_tests("reveal")
            assert not display._overlay_signal.is_set()

    def test_second_tap_starts_a_new_slide_from_zero(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            clock.t = 1000.2
            display.set_overlay(OverlayState(visible=True))
            assert display._controls.hidden_until == 0.0
            _repaint(display)
            assert display._controls.sliding_in is True

            clock.t = 1001.0
            _repaint(display)
            display.hide_controls()
            _repaint(display)
            assert display._controls.started_at == 1001.0
            assert display._controls.sliding_in is False
            assert display._controls.progress(1001.0) == 0.0
            assert display._controls.progress(1001.0 + ddc.REVEAL_ANIMATION_S / 2.0) == pytest.approx(0.5)

    def test_end_of_slide_tick_does_not_clear_a_newer_slide(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            clock.t = 1000.0 + ddc.REVEAL_ANIMATION_S + 0.01
            newer = clock.t

            class _Racer:
                """Stands in for the poll thread: stamps a new slide between
                the tick's read of the start and its reset."""

                def __enter__(self_inner):
                    display._controls.started_at = newer
                    return self_inner

                def __exit__(self_inner, *exc):
                    return False

            real_lock = display._lock
            display._lock = _Racer()
            try:
                display.fire_timer_for_tests("reveal")
            finally:
                display._lock = real_lock
            assert display._controls.started_at == newer

            # Undisturbed, the tick still clears a finished slide.
            display._controls.started_at = 1000.0
            display.fire_timer_for_tests("reveal")
            assert display._controls.started_at == 0.0

    def test_screen_change_resets_window_and_slide(self):
        display, fb, gt, _ = self._rich()
        held_frame = fb.displayed[-1]
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            assert display._controls.started_at == 1000.0
            display.open_selector()
            _repaint(display)
            assert display._screen == "selector"
            assert display._controls.hidden_until == 0.0
            assert display._controls.started_at == 0.0
            assert display._controls.last is None

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
            display.fold_for_tests()
            assert display.core.snapshot().now_playing is None
            _repaint(display)  # must not raise
            result = display._effective_overlay_locked(OverlayState())
            assert result.visible is False
            assert display._controls.last is None

    def test_resuming_after_idle_in_touch_mode_starts_no_phantom_slide(self):
        display, fb, gt, _ = self._rich(always_show=False)
        self._shown_settled(display, fb)
        assert display._controls.last is True
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            gt.return_value = []
            display.fold_for_tests()
            assert display.core.snapshot().now_playing is None
            display.set_overlay(OverlayState(visible=False))
            clock.t = 1001.0
            gt.return_value = [_target()]
            _poll_with_artwork(display, fb)
            assert display._controls.started_at == 0.0
            assert _pixels(fb.displayed[-1]) == _pixels(_bare_frame(display, fb))

    def test_poll_repaint_mid_slide_composes_under_the_chrome(self):
        display, fb, gt, band_h = self._rich()
        metrics = display._layout_metrics()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            clock.t = 1000.0 + ddc.REVEAL_ANIMATION_S / 2.0
            new_image = Image.linear_gradient("L").resize((fb.width, fb.height)).convert("RGB")
            new_track_id = _track_id(artwork_url="https://provider.example/y.jpg")
            with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=new_track_id)), \
                 patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
                 patch("dial_display.decode_artwork", return_value=new_image), \
                 patch("dial_display_compositor.transform_artwork_for_panel", return_value=new_image):
                display.fold_for_tests()
            frame = fb.displayed[-1]

            with display._lock:
                overlay = display._effective_overlay_locked(display._overlay_snapshot, now=clock.t, animating=False)
            assert overlay.visible is False
            shown = display._compositor.compose(
                new_image, fb.width, fb.height, rotate=False, bgr=False, is_artwork=False,
                overlay=OverlayState(visible=True), metrics=metrics,
            )
            dy = round(display._controls.progress(clock.t) * band_h)
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
            assert display._controls.started_at == 1000.0
            assert display._controls.progress(1000.2) == pytest.approx(ddc.reveal_ease(0.2 / ddc.REVEAL_ANIMATION_S))

    def test_sleep_mid_slide_resets(self):
        display, fb, gt, _ = self._rich()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            display.hide_controls()
            _repaint(display)
            assert display._controls.started_at == 1000.0
            with display._lock:
                display._sleep_locked()
            assert display._controls.hidden_until == 0.0
            assert display._controls.started_at == 0.0
            assert display._controls.last is None

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
        assert display._controls.started_at == 1000.0
        display._overlay_signal.clear()
        with patch("dial_display.time.monotonic", return_value=1000.0 + ddc.CONTROLS_HIDE_SECONDS + 0.1):
            display.fire_timer_for_tests("controls_hidden")
        assert display._controls.hidden_until == 0.0
        assert display._controls.started_at == 1000.0
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
            display._repeat_screen = dds.ApplianceScreenState(
                appliance_id=self.AID, service_name="Kitchen", opened_at=at,
            )
            display._current_base_image = base
        self._seed(state, at)
        return display, fb, base

    def _seed(self, state, observed_at):
        import dial_repeat_store as drs
        seed_repeat(self.AID, drs.RepeatRecord(
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
            assert display._controls.hidden_until == pytest.approx(1000.0 + ddc.CONTROLS_HIDE_SECONDS)

    def test_hold_and_enable_layouts_do_not_hide(self):
        display, fb, base = self._opened(state="hold")
        with patch("dial_display.time.monotonic", _FakeClock(1000.0)):
            display.repeat_toggle_tap()
            display.hide_controls()
            assert display._controls.hidden_until == 0.0
            self._seed("idle", 1000.0)
            display.repeat_toggle_tap()
            display.hide_controls()
            assert display._controls.hidden_until == 0.0

    def test_touch_surface_reports_hidden_while_the_window_holds(self):
        display, fb, base = self._opened()
        with patch("dial_display.time.monotonic", _FakeClock(1000.0)):
            assert display.touch_surface()[0] == "repeat"
            display.hide_controls()
            assert display.touch_surface() == ("hidden", True, display.core.snapshot().dots_active, display.core.snapshot().outputs_available, False)
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
            assert display._controls.started_at == 1000.0

            clock.t = 1000.0 + ddc.REVEAL_ANIMATION_S / 2.0
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

            clock.t = 1000.0 + ddc.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            assert _pixels(fb.displayed[-1]) == _pixels(bare)

    def test_counter_keeps_ticking_while_hidden(self):
        display, fb, base = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            _repaint(display)
            display.repeat_toggle_tap()
            _repaint(display)
            clock.t = 1000.0 + ddc.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            display.fire_timer_for_tests("reveal")
            bare = self._bare(display, fb, base)
            painted = display._repeat_line.painted_second
            for step in (1.0, 2.0):
                clock.t = 1000.6 + step
                display._overlay_signal.clear()
                display.fire_timer_for_tests("repeat_line")
                assert display._overlay_signal.is_set()
                _repaint(display)
                assert display._repeat_line.painted_second == painted + int(step)
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
            assert display._controls.hidden_until == 0.0
            assert display._controls.started_at == 0.0
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
            assert display._controls.hidden_until == 0.0
            assert display._controls.started_at == 0.0

    def test_window_expiry_shows_controls(self):
        display, fb, base = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            _repaint(display)
            display.repeat_toggle_tap()
            _repaint(display)
            clock.t = 1000.0 + ddc.CONTROLS_HIDE_SECONDS + 0.1
            self._seed("replaying", clock.t)
            display.fire_timer_for_tests("controls_hidden")
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
            clock.t = 1000.0 + ddc.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            bare = self._bare(display, fb, base)
            assert _pixels(fb.displayed[-1]) == _pixels(bare)

            t_expiry = 1000.0 + ddc.CONTROLS_HIDE_SECONDS + 0.1
            clock.t = t_expiry
            self._seed("replaying", clock.t)
            display.fire_timer_for_tests("controls_hidden")
            _repaint(display)
            assert display._controls.sliding_in is True
            assert display._controls.started_at == t_expiry
            assert _pixels(fb.displayed[-1]) == _pixels(bare)

            clock.t = t_expiry + ddc.REVEAL_ANIMATION_S / 2.0
            self._seed("replaying", clock.t)
            _repaint(display)
            mid = fb.displayed[-1]
            dy = round(0.5 * band_h)
            assert _pixels(mid) != _pixels(bare)
            assert _pixels(mid) != _pixels(shown)
            assert _rows_equal(mid, bare, (0, band_h - dy, fb.width, band_h))
            assert display.touch_surface()[0] == "repeat"

            clock.t = t_expiry + ddc.REVEAL_ANIMATION_S + 0.05
            self._seed("replaying", clock.t)
            _repaint(display)
            assert display._controls.progress(clock.t) == 0.0
            assert _pixels(fb.displayed[-1]) != _pixels(bare)

    def test_reveal_tap_slides_the_controls_in(self):
        display, fb, base = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            _repaint(display)
            display.repeat_toggle_tap()
            _repaint(display)
            clock.t = 1000.0 + ddc.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            bare = self._bare(display, fb, base)

            clock.t = 1002.0
            self._seed("replaying", clock.t)
            display.set_overlay(OverlayState(visible=True))
            _repaint(display)
            assert display._controls.sliding_in is True
            assert display._controls.started_at == 1002.0
            assert _pixels(fb.displayed[-1]) == _pixels(bare)

            clock.t = 1002.0 + ddc.REVEAL_ANIMATION_S / 2.0
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
            out_progress = display._controls.progress(clock.t)
            out_frame = fb.displayed[-1]
            display.set_overlay(OverlayState(visible=True))
            _repaint(display)
            assert display._controls.sliding_in is True
            assert display._controls.progress(clock.t) == pytest.approx(out_progress)
            assert _pixels(fb.displayed[-1]) == _pixels(out_frame)

    def test_replay_stopping_does_not_slide_the_controls_in(self):
        display, fb, base = self._opened()
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            _repaint(display)
            display.repeat_toggle_tap()
            _repaint(display)
            clock.t = 1000.0 + ddc.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            self._seed("hold", clock.t)
            _repaint(display)
            assert display._controls.hidden_until == 0.0
            assert display._controls.started_at == 0.0
            assert display._controls.last is None
            assert display._controls.progress(clock.t) == 0.0
            plain = fb.displayed[-1]

            # Stopping mid slide-in snaps too.
            self._seed("replaying", clock.t)
            _repaint(display)
            display.repeat_toggle_tap()
            _repaint(display)
            clock.t += ddc.REVEAL_ANIMATION_S + 0.05
            _repaint(display)
            clock.t += ddc.CONTROLS_HIDE_SECONDS + 0.1
            self._seed("replaying", clock.t)
            display.fire_timer_for_tests("controls_hidden")
            _repaint(display)
            assert display._controls.started_at == clock.t
            clock.t += 0.1
            self._seed("hold", clock.t)
            _repaint(display)
            assert display._controls.started_at == 0.0
            assert _pixels(fb.displayed[-1]) == _pixels(plain)

    def test_base_tier_hides_instantly(self):
        display, fb, base = self._opened(maker=make_display)
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            _repaint(display)
            display.repeat_toggle_tap()
            _repaint(display)
            assert display._controls.started_at == 0.0
            assert _pixels(fb.displayed[-1]) == _pixels(self._bare(display, fb, base))

    def test_compact_repeat_unaffected(self):
        display, fb, base = self._opened(maker=_make_compact_display)
        clock = _FakeClock(1000.0)
        with patch_monotonic(clock):
            _repaint(display)
            before = _pixels(fb.displayed[-1])
            display.repeat_toggle_tap()
            display.hide_controls()
            assert display._controls.hidden_until == 0.0
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

        status = display.update_config(DialDisplayConfig(fitted=True, always_show_controls=True))

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
# already resolves compact (see dial_layout_metrics.metrics_for) — a custom
# FakeBackend matches its physical pixel size, following the same pattern
# TestListPagingMatchesPaintedRows uses for the rich tier.
# ---------------------------------------------------------------------------

class TestCompactPersistentOverlayAndSurface:
    """Compact controls start hidden (bare artwork) and only appear for a
    6 s window opened by a touch/reveal/screen change — see
    ControlsReveal.show_compact()/_compact_controls_hidden(). Inverted from the
    old "compact always held" behaviour."""

    def test_persistent_overlay_shown_false_until_a_reveal(self):
        t = _target()
        display, fb, gt = _make_compact_display(targets=[t], always_show_controls=False)
        display.enable()
        with display._lock:
            assert display._layout_metrics().content_tier == "compact"
        _poll_with_artwork(display, fb)
        assert display.persistent_overlay_shown() is False

    def test_touch_surface_reports_hidden_until_a_reveal(self):
        t = _target()
        display, fb, gt = _make_compact_display(targets=[t], always_show_controls=False)
        display.enable()
        _poll_with_artwork(display, fb)
        assert display.touch_surface() == ("hidden", False, False, False, False)

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
            clock.t += ddc.CONTROLS_HIDE_SECONDS + 0.1
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
        display.fold_for_tests()
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
            clock.t += ddc.CONTROLS_HIDE_SECONDS + 0.1
            assert display.touch_surface()[0] == "hidden"

    def test_repeat_frame_falls_back_to_bare_base_once_hidden(self):
        display = self._opened("3" * 20)
        clock = _FakeClock(time.monotonic())
        with patch_monotonic(clock), \
             patch.object(display._compositor, "compose_repeat", wraps=display._compositor.compose_repeat) as spy:
            clock.t += ddc.CONTROLS_HIDE_SECONDS + 0.1
            with display._lock:
                display._repaint_current_locked()
            assert spy.call_args.kwargs["controls"] is False

    def test_reveal_after_hidden_shows_repeat_again(self):
        display = self._opened("4" * 20)
        clock = _FakeClock(time.monotonic())
        with patch_monotonic(clock):
            clock.t += ddc.CONTROLS_HIDE_SECONDS + 0.1
            assert display.touch_surface()[0] == "hidden"
            display.set_overlay(OverlayState(visible=True))
            assert display.touch_surface()[0] == "repeat"


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
        assert deadline == pytest.approx(display._controls.shown_until + 0.005)

    def test_tick_controls_shown_signals_once_after_lapsing(self):
        t = _target()
        display, fb, gt = _make_compact_display(targets=[t], always_show_controls=False)
        display.enable()
        _poll_with_artwork(display, fb)
        clock = _FakeClock(time.monotonic())
        with patch_monotonic(clock):
            display.set_overlay(OverlayState(visible=True))
            clock.t += ddc.CONTROLS_HIDE_SECONDS + 0.1
            display._overlay_signal.clear()
            display.fire_timer_for_tests("controls_shown")
            assert display._overlay_signal.is_set()
            assert display._controls.shown_until == 0.0
            display._overlay_signal.clear()
            display.fire_timer_for_tests("controls_shown")
            assert not display._overlay_signal.is_set()

    def test_off_compact_never_signals(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])  # base tier
        display.enable()
        _poll_with_artwork(display, fb)
        display._controls.shown_until = time.monotonic() - 1.0
        display._overlay_signal.clear()
        display.fire_timer_for_tests("controls_shown")
        assert not display._overlay_signal.is_set()
