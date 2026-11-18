"""Tests for the display's list screens: the appliance selector, the replay picker and
the info pages, their paging and timeouts, the pressed channel, and the screen policy
table.
"""
from __future__ import annotations

import dataclasses
import functools
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
from dial_layout_metrics import metrics_for
from dial_touch_layout import TouchZone, list_layout_for
import dial_core_state
import dial_display as dd
import dial_display_state as dds
import dial_display_draw as dd_draw
import dial_display_views as dd_views
from dial_core_state import NowPlaying
from dial_display import (
    SCREEN_POLICIES,
    SELECTOR_TIMEOUT_SECONDS,
    WARNING_DESCRIPTORS,
    DialDisplay,
)
from dial_warnings import KIND_STATUS
from dial_test_support import (
    FakeBackend,
    _repeat_obj,
    _roster_entry,
    _status_result,
    _target,
    make_display,
    seed_repeat,
    sent,
    set_roster,
)
from dial_display_test_support import (
    _HINT_TIERS,
    _make_compact_display,
    _poll_focused_with_repeat,
    _poll_with_artwork,
    _refresh_picker,
    _refresh_selector,
    picker_with_row,
    selector_display,
)


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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
        assert display._selector.page == 0


class TestSelectorAndPickerRowsSignalRepaint:
    """A row rebuild that changes what would be painted must repaint even
    with nothing else moving on screen — see _refresh_list_rows."""

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
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._screen_request = "picker"
        now = time.monotonic()
        row = _roster_entry(name="A", appliance_id="a" * 20, auth="authorized", repeat_capable=True)
        seed_repeat("a" * 20, _repeat_obj(state="hold"))
        display._overlay_signal.clear()

        _refresh_picker(display, [row], now)

        assert [r.appliance_id for r in display._picker.rows] == ["a" * 20]
        assert display._overlay_signal.is_set()

    def test_picker_no_signal_when_rows_unchanged(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display._screen_request = "picker"
        now = time.monotonic()
        row = _roster_entry(name="A", appliance_id="a" * 20, auth="authorized", repeat_capable=True)
        seed_repeat("a" * 20, _repeat_obj(state="hold"))
        _refresh_picker(display, [row], now)
        display._overlay_signal.clear()

        _refresh_picker(display, [row], now)

        assert not display._overlay_signal.is_set()


class TestSelectorOpenCloseAndRepaint:
    def _display_with_one_row(self, always_show_controls=False):
        a = _target(name="A", service_name="A", appliance_id="a" * 20, auth="authorized")
        display, fb, gt = make_display(targets=[a], always_show_controls=always_show_controls)
        display.enable()
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
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
        t = _target(auth="unknown")  # controllable, but never listed
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_test_support.fetch_target_status",
                   return_value=dict(_status_result(track_id=None), access="unknown")):
            display.fold_for_tests()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        width, height = display._active_panel_dims()
        with display._lock:
            list_state = display._build_row_list_state_locked("selector", width, height)
        assert list_state.rows == (("No devices", False),)
        assert list_state.has_prev is False
        assert list_state.has_next is False

    def test_persistent_overlay_shown_false_while_open(self):
        display, fb, gt = self._display_with_one_row(always_show_controls=True)
        # Force the "a controllable appliance is shown" precondition
        # directly rather than faking a full artwork fetch — this test is
        # only about the selector's own gate on persistent_overlay_shown().
        with display._lock:
            display.core.set_field_for_tests("now_playing", NowPlaying("T0", "Artist", "Title", 50))
        assert display.persistent_overlay_shown() is True
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        assert display.persistent_overlay_shown() is False


class TestSelectorUnauthorizedRows:
    def _display(self, authorized_count=1):
        return selector_display(authorized_count)

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
        assert dds.selector_list_row(rows[1]) == ("Lounge", False, dd_views.NOT_AUTHORISED_TEXT)
        assert dds.selector_list_row(rows[0])[2] is dd_views.PLAY_GLYPH

    def test_selector_pick_on_unauthorized_opens_hint(self):
        display = self._display()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        display.selector_pick(1)  # the unauthorised row
        with display._lock:
            display._repaint_current_locked()
        assert display.core.snapshot().focus.manual_id is None
        assert display._screen == "info_value"
        assert display._info_value.hint == (
            dd_views.NOT_AUTHORISED_TEXT, "Allow this dial in Lounge's web UI (Setup, Dials)",
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
        assert display.core.snapshot().focus.manual_id is None

    def test_pick_on_authorized_row_still_sets_focus_and_closes(self):
        display = self._display()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        display.selector_pick(0)
        with display._lock:
            display._repaint_current_locked()
        assert display.core.snapshot().focus.manual_id == "0" * 20
        assert display._screen == "main"

    @pytest.mark.parametrize("width,height,mm_per_px", _HINT_TIERS)
    @pytest.mark.parametrize("name", ["Lounge", "CD Player", "Living Room Hi-Fi"])
    def test_hint_text_fits_without_truncation(self, width, height, mm_per_px, name):
        from PIL import ImageDraw
        from dial_touch_layout import info_value_layout_for

        metrics = metrics_for(width, height, mm_per_px)
        label, text = dds.unauthorised_hint(name)
        layout = info_value_layout_for(width, height, metrics=metrics)
        draw = ImageDraw.Draw(Image.new("RGB", (width, height)))
        lines, font = dd_draw._fit_value_lines(
            draw, text, (metrics.font_readout, metrics.font_body), layout.value,
        )
        assert lines and font is not None
        assert " ".join(lines) == text  # nothing dropped, no ellipsis
        max_w = layout.value[2] - layout.value[0]
        for line in lines:
            assert dd_draw._text_size(draw, line, font)[0] <= max_w
        # The title in the label band fits on one line too.
        title_w = dd_draw._text_size(draw, label, dd_draw._load_font(metrics.font_body))[0]
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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        return display, fb, gt, targets

    def test_pick_sets_focus_and_closes(self):
        display, fb, gt, targets = self._opened_display(count=1)
        display.selector_pick(0)
        assert display.core.snapshot().focus.manual_id == "0" * 20
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"

    def test_stale_index_closes_without_setting_focus(self):
        display, fb, gt, targets = self._opened_display(count=1)
        display.selector_pick(5)  # out of range for a single row
        assert display.core.snapshot().focus.manual_id is None
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
        assert display.core.snapshot().focus.manual_id == expected_id


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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        return display, fb, gt, targets

    def test_rows_per_page_matches_painted_metrics(self):
        display, fb, gt, targets = self._rich_opened(count=5)
        with display._lock:
            painted = display._layout_metrics().rows_per_page
        assert painted == 5  # richer tier on the 2.8-inch 320x240 panel
        assert display._rows_per_page() == painted

    def test_fourth_row_is_pickable_not_a_miss(self):
        display, fb, gt, targets = self._rich_opened(count=5)
        display.selector_pick(3)  # the fourth row of page 0
        assert display.core.snapshot().focus.manual_id == "3" * 20

    def test_second_page_starts_after_a_full_first_page(self):
        display, fb, gt, targets = self._rich_opened(count=6)
        display.list_page(+1)
        with display._lock:
            display._repaint_current_locked()
        assert display._selector.page == 1
        display.selector_pick(0)  # row 0 of PAGE 1 == the sixth target overall
        assert display.core.snapshot().focus.manual_id == "5" * 20


class TestCurrentPageRows:
    def test_selector_state_page_one(self):
        display, fb, gt = make_display(targets=[])
        rows = tuple(dial_core_state.SelectorRow(appliance_id=str(i), label=str(i), current=False) for i in range(5))
        selector = dds.ListScreenState(rows=rows, page=1, opened_at=0.0)
        page_rows = display._current_page_rows(selector)
        assert [r.appliance_id for r in page_rows] == ["3", "4"]

    def test_picker_state_page_one(self):
        display, fb, gt = make_display(targets=[])
        rows = tuple(
            dial_core_state.PickerRow(appliance_id=str(i), service_name=str(i), ip="1.2.3.4", port=80,
                         label=str(i), seconds=float(i))
            for i in range(5)
        )
        picker = dds.ListScreenState(rows=rows, page=1, opened_at=0.0)
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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "selector"

        gt.return_value = []  # nothing playing any more
        display.fold_for_tests()
        # An open selector is never closed by a poll finding nothing
        # playing — only its own inactivity timeout does that.
        assert display._screen == "selector"
        assert display._selector is not None

    def test_selector_closed_by_timeout_then_next_idle_poll_sleeps(self):
        a = _target(name="A", service_name="A", appliance_id="a" * 20, auth="authorized")
        display, fb, gt = make_display(targets=[a])
        display.enable()
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
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
            display.fold_for_tests()  # starts the idle countdown now the list is closed
        assert display._display_sleeping is False

        with patch("dial_display.time.monotonic", return_value=t0 + dd.DISPLAY_IDLE_SLEEP_SECONDS):
            display.fold_for_tests()
        assert display._display_sleeping is True

    def test_sleep_pops_to_main(self):
        t = _target()
        display, fb, gt = make_display(targets=[t])
        display.enable()
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "selector"

        with display._lock:
            display._swap_backend_locked()
        assert display._screen == "main"


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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
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
        display.core.set_field_for_tests("idle_affordance", True)
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
# The replay picker: rows from held+authorized+capable roster entries,
# picker_pick starting a replay with a pending focus, stale-index handling,
# and the shared inactivity timeout.
# ---------------------------------------------------------------------------

class TestReplayPickerRows:
    def test_open_picker_sets_screen_request(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.core.set_field_for_tests("idle_affordance", True)
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
        display.core.set_field_for_tests("idle_affordance", True)
        display.open_picker()
        with display._lock:
            display._repaint_current_locked()
        width, height = display._active_panel_dims()
        with display._lock:
            list_state = display._build_row_list_state_locked("picker", width, height)
        assert list_state.rows == (("Nothing to replay", False),)


class TestPickerPick:
    def _opened_with_row(self, aid="a" * 20):
        return picker_with_row(aid)

    def test_pick_sets_pending_focus_and_enqueues_seek(self):
        display, fb, gt = self._opened_with_row(aid="a" * 20)
        with patch("dial_core.DialCore._send") as mock_transport:
            display.picker_pick(0)
        mock_transport.assert_called_once()
        target, intent, token = sent(mock_transport)
        action = {"repeat.seek": "seek", "repeat.transport": "stop"}[intent.name]
        position = float(intent.args.get("position", 0.0))
        assert target.appliance_id == "a" * 20
        assert action == "seek"
        assert position == 0.0
        assert display.core.snapshot().focus.manual_id == "a" * 20
        assert display.core.snapshot().focus.pending is not None

    def test_pick_closes_the_picker(self):
        display, fb, gt = self._opened_with_row()
        with patch("dial_core.DialCore._send"):
            display.picker_pick(0)
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"

    def test_stale_index_is_back_no_focus_no_enqueue(self):
        display, fb, gt = self._opened_with_row()
        with patch("dial_core.DialCore._send") as mock_transport:
            display.picker_pick(5)
        mock_transport.assert_not_called()
        assert display.core.snapshot().focus.manual_id is None
        with display._lock:
            display._repaint_current_locked()
        assert display._screen == "main"


class TestPickerTimeout:
    def test_closes_after_timeout(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.core.set_field_for_tests("idle_affordance", True)
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
        display.core.set_field_for_tests("idle_affordance", True)
        display.open_picker()
        with display._lock:
            display._repaint_current_locked()
        opened_at = display._picker.opened_at
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS - 1):
            display._check_secondary_timeout()
        assert display._screen == "picker"


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
            display.fold_for_tests()
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
            display.fold_for_tests()
        close.assert_not_called()

    def test_selector_stays_open_when_nothing_playing(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "selector"
        gt.return_value = []
        with patch.object(display, "_close_secondary_locked") as close:
            display.fold_for_tests()
        close.assert_not_called()

    def test_repeat_screen_closes_when_nothing_playing_and_no_focus(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        with display._lock:
            display._screen = "repeat"
        gt.return_value = []
        with patch.object(display, "_close_secondary_locked") as close:
            display.fold_for_tests()
        close.assert_called()

    def test_repeat_screen_kept_when_an_idle_focus_is_set(self):
        aid = "9" * 20
        idle = _roster_entry(name="Kitchen", service_name="Kitchen", appliance_id=aid, auth="authorized")
        display, fb, gt = make_display(targets=[], roster=[idle])
        display.enable()
        display.core.set_focus(aid)
        with display._lock:
            display._screen = "repeat"
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None, appliance_id=aid)):
            display.fold_for_tests()
        assert display._screen == "repeat"


# ---------------------------------------------------------------------------
# The screen policy table itself: shape and cross-row consistency checks,
# independent of any particular screen's behaviour (covered above and by
# the trace corpus).
# ---------------------------------------------------------------------------

class TestScreenPolicyTable:
    def test_table_has_exactly_the_thirteen_screens(self):
        assert set(SCREEN_POLICIES) == {
            "main", "selector", "picker", "info", "info_value", "repeat", "eq", "outputs", "output",
            "warnings", "restarting", "update", "update_result",
        }

    def test_restarting_row(self):
        assert SCREEN_POLICIES["restarting"].inactivity_timeout_s == dd.RESTARTING_TIMEOUT_SECONDS
        assert SCREEN_POLICIES["restarting"].touch_extends_timeout is False
        assert SCREEN_POLICIES["restarting"].surface == ("restarting", False, False, False)

    def test_warnings_row_times_out_like_info_and_lets_the_panel_sleep(self):
        row, info = SCREEN_POLICIES["warnings"], SCREEN_POLICIES["info"]
        assert row.inactivity_timeout_s == info.inactivity_timeout_s == SELECTOR_TIMEOUT_SECONDS
        assert row.touch_extends_timeout is True
        assert row.defers_sleep is False
        assert row.back_to == "main"
        assert row.state_attr == "_warnings_page"
        assert row.surface is None          # the card for the entry's button count, see touch_surface()

    def test_status_rows_share_the_state_attr_and_open_via_the_status_opener(self):
        statuses = [d for d in WARNING_DESCRIPTORS if d.kind == KIND_STATUS]
        assert [d.screen for d in statuses] == ["update", "update_result"]
        for desc in statuses:
            policy = SCREEN_POLICIES[desc.screen]
            assert policy.state_attr == "_warning_screen"
            assert policy.paint is DialDisplay._display_card_locked
            assert policy.open.keywords == {"warning_id": desc.id}
            assert policy.inactivity_timeout_s is None and policy.defers_sleep is False

    def test_status_surfaces_are_the_card_for_their_button_count(self):
        assert SCREEN_POLICIES["update"].surface == ("update", False, False, False)
        assert SCREEN_POLICIES["update_result"].surface == ("card1", False, False, False)

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


class TestCompactWrapPaging:
    def _opened_selector(self, count):
        targets = [
            _target(name=f"T{i}", service_name=f"T{i}", appliance_id=str(i) * 20,
                     auth="authorized", playing_since=float(i))
            for i in range(count)
        ]
        display, fb, gt = _make_compact_display(targets=targets)
        display.enable()
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        return display, targets

    def test_rows_per_page_is_two(self):
        display, targets = self._opened_selector(count=3)
        with display._lock:
            assert display._layout_metrics().rows_per_page == 2

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
        with patch("dial_test_support.fetch_target_status", return_value=_status_result(track_id=None)):
            display.fold_for_tests()
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
        from dial_test_support import RosterEntry
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
        seed_repeat("a" * 20, _repeat_obj(state="hold", recording_seconds=12.0))
        seed_repeat("b" * 20, _repeat_obj(state="hold", recording_seconds=34.0))
        _refresh_picker(display, rows, now)
        set_roster(display, rows)
        display.core.set_field_for_tests("idle_affordance", True)
        display.open_picker()
        with display._lock:
            display._repaint_current_locked()
        assert display._layout_metrics().rows_per_page == 2  # both rows fit on page 0

        with patch("dial_core.DialCore._send") as mock_transport:
            display.picker_pick(1)
        target, intent, token = sent(mock_transport)
        action = {"repeat.seek": "seek", "repeat.transport": "stop"}[intent.name]
        position = float(intent.args.get("position", 0.0))
        assert target.appliance_id == "b" * 20
        assert action == "seek"
        assert position == 0.0
        assert display.core.snapshot().focus.manual_id == "b" * 20


# ---------------------------------------------------------------------------
# The idle screen's read-only info page: open_info()/_gather_info()/
# set_info_provider(), paging, lifetime, and the dead-row guard.
# ---------------------------------------------------------------------------

class TestInfoPage:
    def _opened(self, display) -> int:
        """open_info() with the gather thread never actually started (it is
        exercised directly, synchronously, by the tests that need it — the
        same discipline test_dial_display_outputs.TestOnOutputsResult uses for its own worker-thread
        callback), then fold the pending screen request in. Returns the
        gather sequence this open captured."""
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
        assert display._info.rows == dds.INFO_PLACEHOLDER_ROWS

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
        assert display._info.rows == dds.INFO_PLACEHOLDER_ROWS

    def test_missing_provider_yields_placeholders(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        seq = self._opened(display)
        display._gather_info(seq)
        assert display._info.rows == dds.INFO_PLACEHOLDER_ROWS

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
        assert display._info.rows == dds.INFO_PLACEHOLDER_ROWS

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
            metrics = display._layout_metrics()
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
            display.fold_for_tests()
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
            display.fold_for_tests()
        close.assert_not_called()
        assert display._idle_started_at is None

    def test_touch_surface_reports_info_value(self):
        display, fb, gt = _make_compact_display(targets=[])
        display.enable()
        self._opened_value(display, 0)
        assert display.touch_surface() == ("info_value", False, False, False, False)
