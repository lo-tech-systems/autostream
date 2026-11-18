"""Tests for dial_display_state.py: paging arithmetic, the list-state builder and the
outputs filter the outputs screen offers.

These are pure functions, exercised without a display instance.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dial_touch_layout import TouchZone
import dial_core_state
import dial_display_state as dds
import dial_display_views as dd_views
from dial_test_support import outputs_rows


# ---------------------------------------------------------------------------
# Shared paging/list-state helpers — pure functions, exercised directly
# without a display instance where possible.
# ---------------------------------------------------------------------------

class TestClampPageAndPageSlice:
    def test_clamp_page_empty_rows_is_zero(self):
        assert dds.clamp_page(3, 0, 3) == 0

    def test_clamp_page_beyond_last_clamps(self):
        assert dds.clamp_page(10, 5, 3) == 1  # 5 rows at 3/page -> pages 0, 1

    def test_clamp_page_exact_multiple_has_no_extra_trailing_page(self):
        assert dds.clamp_page(2, 6, 3) == 1  # 6 rows at 3/page -> pages 0, 1 only

    def test_clamp_page_negative_clamps_to_zero(self):
        assert dds.clamp_page(-1, 5, 3) == 0

    def test_page_slice_returns_start_and_rows(self):
        rows = tuple(range(5))
        start, page_rows = dds.page_slice(rows, 1, 3)
        assert start == 3
        assert page_rows == (3, 4)

    def test_page_slice_stale_page_yields_empty_tuple(self):
        rows = tuple(range(5))
        _, page_rows = dds.page_slice(rows, 5, 3)  # well past the last page
        assert page_rows == ()


class TestListStateForHelper:
    def test_none_state_gives_placeholder(self):
        state = dds.list_state_for(None, 3, "No rows", lambda r: (r, False))
        assert state.rows == (("No rows", False),)
        assert state.has_prev is False
        assert state.has_next is False

    def test_empty_state_gives_placeholder(self):
        selector = dds.ListScreenState(rows=(), page=0, opened_at=0.0)
        state = dds.list_state_for(selector, 3, "No devices", dds.selector_list_row)
        assert state.rows == (("No devices", False),)
        assert state.has_prev is False
        assert state.has_next is False

    def test_playing_selector_row_maps_to_play_glyph_triple(self):
        rows = (dial_core_state.SelectorRow(appliance_id="a", label="A", current=False, playing=True),)
        selector = dds.ListScreenState(rows=rows, page=0, opened_at=0.0)
        state = dds.list_state_for(selector, 3, "No devices", dds.selector_list_row)
        assert state.rows == (("A", False, dd_views.PLAY_GLYPH),)

    def test_non_playing_selector_row_maps_to_pair(self):
        rows = (dial_core_state.SelectorRow(appliance_id="a", label="A", current=True, playing=False),)
        selector = dds.ListScreenState(rows=rows, page=0, opened_at=0.0)
        state = dds.list_state_for(selector, 3, "No devices", dds.selector_list_row)
        assert state.rows == (("A", True),)

    def test_picker_row_maps_to_label_and_formatted_duration(self):
        rows = (dial_core_state.PickerRow(appliance_id="a", service_name="A", ip="1.2.3.4", port=80,
                              label="A", seconds=90.0),)
        picker = dds.ListScreenState(rows=rows, page=0, opened_at=0.0)
        state = dds.list_state_for(picker, 3, "Nothing to replay", dds.picker_list_row)
        assert state.rows == (("A", False, "1:30"),)

    def test_has_next_true_only_when_rows_remain_after_the_page(self):
        rows = tuple(
            dial_core_state.SelectorRow(appliance_id=str(i), label=str(i), current=False)
            for i in range(4)
        )
        first_page = dds.list_state_for(
            dds.ListScreenState(rows=rows, page=0, opened_at=0.0), 3, "No devices", dds.selector_list_row,
        )
        assert first_page.has_next is True
        second_page = dds.list_state_for(
            dds.ListScreenState(rows=rows, page=1, opened_at=0.0), 3, "No devices", dds.selector_list_row,
        )
        assert second_page.has_next is False

    def test_pressed_defaults_to_none(self):
        selector = dds.ListScreenState(
            rows=(dial_core_state.SelectorRow(appliance_id="a", label="A", current=False),), page=0, opened_at=0.0,
        )
        state = dds.list_state_for(selector, 3, "No devices", dds.selector_list_row)
        assert state.pressed is None

    def test_pressed_passes_through_unchanged(self):
        selector = dds.ListScreenState(
            rows=(dial_core_state.SelectorRow(appliance_id="a", label="A", current=False),), page=0, opened_at=0.0,
        )
        state = dds.list_state_for(
            selector, 3, "No devices", dds.selector_list_row, pressed=(TouchZone.LIST_ROW, 1),
        )
        assert state.pressed == (TouchZone.LIST_ROW, 1)


# ---------------------------------------------------------------------------
# _offerable: the outputs the outputs screen can offer.
# ---------------------------------------------------------------------------

class TestOfferableOutputs:
    def test_remote_in_use_row_dropped(self):
        rows = dds.offerable(outputs_rows({"ok": True, "outputs": [
            {"id": "1", "name": "Bedroom", "selected": False, "volume": 0, "remote_in_use": True},
            {"id": "2", "name": "Kitchen", "selected": True, "volume": 50, "remote_in_use": False},
        ]}))
        assert [r.id for r in rows] == ["2"]
