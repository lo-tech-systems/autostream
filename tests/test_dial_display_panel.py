"""Tests for the display's panel side: the disabled and degraded backend, the push and
change-region transmit, the retained frame and its screenshot, live config and screen
type changes, rotation and colour order, the layout size, and the boot splash.
"""
from __future__ import annotations

import io
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

from dial_config import DialDisplayConfig
from dial_display_palette import LIST_BG_RGB
from dial_display_profiles import DEFAULT_PROFILE_KEY, get_profile, mm_per_px_for_size
from dial_layout_metrics import metrics_for
import dial_artwork
from dial_core import DialCore
import dial_display as dd
import dial_display_image as dd_image
from dial_display import DialDisplay, create_dial_display
from dial_display_backend import DisplayBackend, NoOpBackend
from dial_test_support import (
    FakeBackend,
    _status_result,
    _target,
    _track_id,
    make_display,
)
from dial_display_test_support import _fold, _marked_image


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
    # dirty_windows(): splitting one changed region into separately
    # written windows when the unchanged rows between them are wide
    # enough to be worth the extra write. The fake backend is 128 px
    # wide, so the row-count gap the split requires is ceil(4096/128) =
    # 32 rows; a change narrower than the full width needs proportionally
    # more unchanged rows to justify a split (see dirty_windows).
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
        from dial_display_windows import dirty_windows

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
            windows = dirty_windows(diff, bbox)

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


# ---------------------------------------------------------------------------
# Screen-size setting (physical diagonal) — mm_per_px derivation and its
# plumbing into _layout_metrics() / redisplay-on-change. Density has no
# effect on rendered bytes in this stage (see test_dial_display_compositor.py
# for that invariant); these tests cover the manager's own bookkeeping.
# ---------------------------------------------------------------------------

class TestScreenSizeSetting:
    def test_init_derives_mm_per_px_from_profile_default(self):
        display, fb, gt = make_display(fitted=False, screen_type=DEFAULT_PROFILE_KEY)
        profile = get_profile(DEFAULT_PROFILE_KEY)
        expected = mm_per_px_for_size(profile.default_diagonal_inches, profile.width, profile.height)
        assert display._mm_per_px == pytest.approx(expected)

    def test_init_derives_mm_per_px_from_override(self):
        display, fb, gt = make_display(fitted=False, screen_size_inches=3.5)
        profile = get_profile(DEFAULT_PROFILE_KEY)
        expected = mm_per_px_for_size(3.5, profile.width, profile.height)
        assert display._mm_per_px == pytest.approx(expected)

    def test_update_config_size_only_change_redisplays_synchronously(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], fitted=True)
        display.enable()

        fake_image = _marked_image(size=(fb.width, fb.height))
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display.fold_for_tests()
        fb.displayed.clear()

        # A size-only change must take effect synchronously via
        # update_config — not via the 6s poll loop — same as rotate/bgr.
        status = display.update_config(DialDisplayConfig(fitted=True, screen_size_inches=3.5))
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
        assert after == pytest.approx(mm_per_px_for_size(3.5, profile.width, profile.height))

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
        expected = mm_per_px_for_size(new_profile.default_diagonal_inches, new_profile.width, new_profile.height)
        assert display._mm_per_px == pytest.approx(expected)

    def test_layout_metrics_reflects_backend_dims_and_density(self):
        display, fb, gt = make_display(fitted=True, screen_size_inches=2.8)
        display.enable()
        profile = get_profile(DEFAULT_PROFILE_KEY)
        expected_mm = mm_per_px_for_size(2.8, profile.width, profile.height)
        with display._lock:
            m = display._layout_metrics()
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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display.fold_for_tests()
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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display.fold_for_tests()
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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display.fold_for_tests()
        assert display.get_status()["showing"] == "artwork"
        fb.displayed.clear()

        # Toggling rotate must take effect synchronously via update_config —
        # not via the 6s poll loop.
        status = display.update_config(DialDisplayConfig(fitted=True, rotate=True))

        assert status["rotate"] is True
        expected = fake_image.transpose(Image.ROTATE_180)
        assert len(fb.displayed) == 1
        assert list(fb.displayed[-1].getdata()) == list(expected.getdata())

    def test_cached_rendered_image_stays_unrotated(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], fitted=True, rotate=True)
        display.enable()

        fake_image = _marked_image(size=(fb.width, fb.height))
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display.fold_for_tests()

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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display.fold_for_tests()
        fb.displayed.clear()

        status = display.update_config(DialDisplayConfig(fitted=True, bgr=True))

        assert status["bgr"] is True
        expected = Image.merge("RGB", fake_image.split()[::-1])
        assert len(fb.displayed) == 1
        assert list(fb.displayed[-1].getdata()) == list(expected.getdata())

    def test_cached_rendered_image_stays_untransformed_with_bgr(self):
        t = _target()
        display, fb, gt = make_display(targets=[t], fitted=True, bgr=True)
        display.enable()

        fake_image = _marked_image(size=(fb.width, fb.height))
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display.fold_for_tests()

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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=Image.new("RGB", (300, 300))), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=stale_sized_image):
            display.fold_for_tests()

        assert fb.displayed == []
        assert display.get_status()["showing"] != "artwork"
        assert display._current_rendered_image is None


# ---------------------------------------------------------------------------
# Threading: start/stop and loop delay from loop end
# ---------------------------------------------------------------------------

class TestThreadingLifecycle:
    def test_start_stop_clean_shutdown(self):
        display, fb, gt = make_display(targets=[])
        display.core.start()
        display.start()
        time.sleep(0.05)
        thread = display._core._thread
        assert thread is not None and thread.is_alive()
        assert thread.name == "dial-core"
        assert display._subscription is not None
        display.stop()
        display.core.stop()
        assert fb.closed is True
        assert not thread.is_alive()
        assert not display._repaint_thread.is_alive()
        assert display._subscription is None

    def test_a_core_the_view_was_given_is_not_started_or_stopped_by_it(self):
        from dial_core import DialCore
        core = DialCore("dial-uuid")
        display = dd.DialDisplay(
            config=DialDisplayConfig(fitted=False),
            core=core, backend_factory=lambda: FakeBackend(),
        )
        display.start()
        assert core._thread is None
        display.stop()

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
        core = DialCore("abc123")
        display = create_dial_display(cfg, core)
        assert isinstance(display, DialDisplay)
        assert display._config is cfg.display
        assert display.core is core

    def test_factory_uses_noop_backend(self):
        cfg = MagicMock()
        cfg.display = DialDisplayConfig(fitted=True)
        cfg.uuid = "abc123"
        display = create_dial_display(cfg, DialCore("abc123"))
        display.enable()
        assert display.get_status()["backend"] == "noop"


# ---------------------------------------------------------------------------
# Rate-limited logging
# ---------------------------------------------------------------------------

class TestRateLimitedLogger:
    def _limiter(self):
        clock = [1000.0]
        return dial_artwork.RateLimitedLogger(clock=lambda: clock[0]), clock

    def test_first_occurrence_logs(self):
        limiter, _ = self._limiter()
        with patch("logging.log") as mock_log:
            limiter.log(30, "keyA", "msg %s", "x")
        mock_log.assert_called_once()

    def test_repeats_suppressed_within_the_interval(self):
        limiter, clock = self._limiter()
        with patch("logging.log") as mock_log:
            for _ in range(9):
                clock[0] += 1.0
                limiter.log(30, "keyA", "msg")
        assert mock_log.call_count == 1  # only the first of these 9

    def test_logs_again_after_the_interval(self):
        limiter, clock = self._limiter()
        with patch("logging.log") as mock_log:
            limiter.log(30, "keyA", "msg")
            clock[0] += limiter.LOG_INTERVAL_SECONDS
            limiter.log(30, "keyA", "msg")
        assert mock_log.call_count == 2

    def test_different_key_logs_immediately(self):
        limiter, _ = self._limiter()
        with patch("logging.log") as mock_log:
            for _ in range(5):
                limiter.log(30, "keyA", "msg")
            limiter.log(30, "keyB", "other")
            limiter.log(30, "keyA", "msg")
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

        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=Image.new("RGB", (300, 300))):
            display.fold_for_tests()

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
# Layout size — render at a logical size, resample to the panel. The None
# path is the regression corpus for byte-identity (see the pin below); the
# rest of this suite exercises a chosen size.
# ---------------------------------------------------------------------------

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
             patch("dial_display.resample_filter") as mock_resample:
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
        with patch("dial_display.resample_filter", wraps=dd_image.resample_filter) as spy:
            display.enable()
        assert display._current_base_image.size == (640, 480)
        assert fb.displayed[-1].size == (320, 240)
        spy.assert_called_with((640, 480), (320, 240))

    def test_compose_is_told_the_panel_size(self):
        # So a reveal slide's frames can be built at the panel's own size
        # rather than built large and shrunk each frame.
        fb = FakeBackend()
        fb.width, fb.height = 320, 240
        display, fb, gt = make_display(
            screen_type="ili9341_320x240", screen_size_inches=2.8, layout_size="large", backend=fb,
        )
        display.enable()
        compositor = display._compositor
        with patch.object(compositor, "compose", wraps=compositor.compose) as compose:
            with display._lock:
                display._display_locked(display._current_base_image)
        assert compose.call_args.kwargs["output_size"] == (320, 240)

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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display.fold_for_tests()
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
             patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display.fold_for_tests()
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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display.fold_for_tests()
        return display, fb, gt

    def test_none_to_large_drops_caches_and_shows_logo_at_new_size(self):
        display, fb, gt = self._opened_with_artwork()
        assert display._current_rendered_image is not None
        fb.displayed.clear()
        display._core._wake.clear()

        status = display.update_config(DialDisplayConfig(
            fitted=True, screen_type="ili9341_320x240", screen_size_inches=2.8, layout_size="large",
        ))

        assert display._current_rendered_image is None
        assert display._source_artwork_key == ""
        assert display._screen == "main"
        assert len(fb.displayed) == 1
        assert display._current_base_image.size == (640, 480)
        assert fb.displayed[-1].size == (320, 240)
        assert display._core._wake.is_set()

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
        assert frame.getpixel((0, 0)) == LIST_BG_RGB
        assert any(frame.getpixel((x, frame.height // 2)) != LIST_BG_RGB for x in range(frame.width))

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
        display.fold_for_tests()
        assert display.get_status()["showing"] == "logo"
        assert len(fb.displayed) == 2

    def test_first_poll_with_artwork_replaces_the_splash(self):
        # The same artwork-path fixture the existing "showing == artwork"
        # test elsewhere in this file uses.
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.show_starting()
        fake_image = Image.new("RGB", (128, 160))
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=fake_image), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=fake_image):
            display.fold_for_tests()
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
