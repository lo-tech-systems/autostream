"""Tests for the display's outputs and EQ screens: the lists and their openers, the
touch entries, what the core holds for them, the page cycle, and the pairing and start
failure notices.
"""
from __future__ import annotations

import dataclasses
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

from dial_display_views import DEFAULT_MARK
from dial_display_profiles import get_profile, mm_per_px_for_size
from dial_network import LINK_DOWN
from dial_layout_metrics import metrics_for
import dial_core_effects
import dial_display as dd
import dial_display_state as dds
import dial_display_draw as dd_draw
import dial_display_views as dd_views
from dial_core_state import OutputRow
from dial_display import SELECTOR_TIMEOUT_SECONDS
from dial_test_support import (
    _FakeClock,
    _repeat_obj,
    _roster_entry,
    _status_result,
    _target,
    _track_id,
    eq_optimistic,
    fold,
    make_display,
    on_eq_result,
    on_network_view,
    on_outputs_result,
    on_repeat_result,
    open_warnings_page,
    outputs_rows,
    patch_monotonic,
    seed_bands,
    seed_eq,
    seed_outputs,
    sent,
    sent_kwargs,
    set_eq_optimistic,
    set_roster,
    tap_card,
    tap_output,
    update_availability,
)
from dial_display_test_support import idle_display, open_repeat_screen, picker_with_row, selector_display
from dial_display_test_support import _HINT_TIERS, _view


# ---------------------------------------------------------------------------
# on_outputs_result: fold a fetch result into the outputs snapshot.
# ---------------------------------------------------------------------------

class TestOnOutputsResult:
    def _outputs_display(self, appliance_id="a" * 20, rows=(), page=0, loaded=False, held=True):
        """A display with the outputs screen up for *appliance_id* and the
        core holding *rows* for it (nothing when *held* is False)."""
        display, fb, gt = make_display(targets=[])
        display._outputs = dds.ApplianceScreenState(
            appliance_id=appliance_id, service_name="Kitchen",
            page=page, opened_at=time.monotonic(),
        )
        if held:
            seed_outputs(display, rows, loaded)
        return display

    def test_a_new_reading_repaints_the_list_and_the_screen_reads_it(self):
        display = self._outputs_display()
        display._overlay_signal.clear()
        rows = (OutputRow(id="1", name="Bedroom", selected=True, volume=40),)
        seed_outputs(display, rows)
        fold(display)
        assert display._rows_of(display._outputs) == rows
        assert display._overlay_signal.is_set()

    def test_page_clamped_when_row_count_shrinks(self):
        display = self._outputs_display(page=5, loaded=True)
        body = {"ok": True, "outputs": [
            {"id": "1", "name": "A", "selected": False, "volume": 0, "remote_in_use": False},
        ]}
        on_outputs_result(display, "fetch", "a" * 20, 200, body, {})
        assert display._outputs.page == 0

    def test_detail_row_vanishing_requests_the_outputs_list(self):
        display = self._outputs_display(
            rows=(OutputRow(id="1", name="Bedroom", selected=True, volume=40),), loaded=True,
        )
        display._output_detail = dds.OutputDetailState(
            appliance_id="a" * 20, output_id="1", opened_at=time.monotonic(),
        )
        display._screen = "output"
        on_outputs_result(display, "fetch", "a" * 20, 200, {"ok": True, "outputs": []}, {})
        assert display._screen_request == "outputs"

    def test_detail_row_still_present_leaves_screen_request_alone(self):
        row = OutputRow(id="1", name="Bedroom", selected=True, volume=40)
        display = self._outputs_display(rows=(row,), loaded=True)
        display._output_detail = dds.OutputDetailState(
            appliance_id="a" * 20, output_id="1", opened_at=time.monotonic(),
        )
        display._screen = "output"
        display._screen_request = None
        body = {"ok": True, "outputs": [
            {"id": "1", "name": "Bedroom", "selected": True, "volume": 45, "remote_in_use": False},
        ]}
        on_outputs_result(display, "fetch", "a" * 20, 200, body, {})
        assert display._screen_request is None


# ---------------------------------------------------------------------------
# The outputs list and per-output detail screens: openers, touch-thread
# entries, and paint builders. Lifecycle/poll interactions (bound-appliance
# close, idle focus, timeouts) are covered by the trace corpus instead.
# ---------------------------------------------------------------------------

def _make_outputs_display(dial_outputs=True, auth="unknown", appliance_id="a" * 20):
    display, fb, gt = make_display(targets=[])
    display.core.set_field_for_tests("reporting_id", appliance_id)
    set_roster(display, [_roster_entry(
        appliance_id=appliance_id, auth=auth, dial_outputs=dial_outputs,
    )])
    return display


class TestOutputsOpener:
    def test_refuses_with_no_focus_or_reporting_id(self):
        display, fb, gt = make_display(targets=[])
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
        assert display._rows_of(display._outputs) == ()
        assert dds.held_outputs(display.core.snapshot(), display._outputs) is None

    def test_keeps_rows_on_reopen_for_the_same_appliance(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        rows = (OutputRow(id="1", name="Bedroom", selected=True, volume=40),)
        seed_outputs(display, rows)
        display._screen = "main"
        display._open_outputs_locked()
        assert display._rows_of(display._outputs) == rows
        assert dds.held_outputs(display.core.snapshot(), display._outputs).loaded is True

    def test_resets_rows_for_a_different_appliance(self):
        display = _make_outputs_display(appliance_id="a" * 20)
        display._open_outputs_locked()
        rows = (OutputRow(id="1", name="Bedroom", selected=True, volume=40),)
        seed_outputs(display, rows)
        display._screen = "main"
        display.core.set_field_for_tests("reporting_id", "b" * 20)
        set_roster(display, [_roster_entry(appliance_id="b" * 20, dial_outputs=True)])
        display._open_outputs_locked()
        assert display._outputs.appliance_id == "b" * 20
        assert display._rows_of(display._outputs) == ()
        assert dds.held_outputs(display.core.snapshot(), display._outputs) is None


class TestOutputDetailOpener:
    def test_refuses_without_a_chosen_id(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        seed_outputs(display, (OutputRow(id="1", name="Bedroom", selected=True, volume=40),), loaded=False)
        display._output_open_id = None
        assert display._open_output_locked() is False
        assert display._output_detail is None

    def test_refuses_when_id_not_in_rows(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        seed_outputs(display, (OutputRow(id="1", name="Bedroom", selected=True, volume=40),), loaded=False)
        display._output_open_id = "not-a-row"
        assert display._open_output_locked() is False
        assert display._output_detail is None
        # Consumed either way, refused or not.
        assert display._output_open_id is None

    def test_opens_for_a_valid_id(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        seed_outputs(display, (OutputRow(id="1", name="Bedroom", selected=True, volume=40),), loaded=False)
        display._output_open_id = "1"
        assert display._open_output_locked() is True
        assert display._screen == "output"
        assert display._output_detail.output_id == "1"
        assert display._output_detail.appliance_id == display._outputs.appliance_id
        assert display._output_open_id is None

    def test_refuses_with_no_outputs_state(self):
        display, fb, gt = make_display(targets=[])
        display._output_open_id = "1"
        assert display._open_output_locked() is False


class TestOutputsTouchEntries:
    def test_open_outputs_requests_screen_and_sends_nothing(self):
        # The speakers are always held, so opening the list asks for nothing.
        display = _make_outputs_display()
        with patch("dial_core.DialCore._send") as send:
            display.open_outputs()
        send.assert_not_called()
        assert display._screen_request == "outputs"

    def test_open_outputs_noop_without_capability(self):
        display = _make_outputs_display(dial_outputs=False)
        with patch("dial_core.DialCore._send") as mock_fetch:
            display.open_outputs()
        mock_fetch.assert_not_called()
        assert display._screen_request is None

    def test_outputs_row_tap_sets_open_id_and_requests_detail(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        seed_outputs(display, (OutputRow(id="1", name="Bedroom", selected=True, volume=40),), loaded=False)
        display.outputs_row_tap(0)
        assert display._output_open_id == "1"
        assert display._screen_request == "output"

    def test_a_tap_on_a_paused_row_plays_it_again_and_keeps_the_list(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        seed_outputs(display, (OutputRow(id="1", name="Lounge", selected=True, volume=40, paused=True),),
                     loaded=False)
        display._screen_request = None
        with patch("dial_core.DialCore._send") as send:
            display.outputs_row_tap(0)
        target, intent, _token = sent(send)
        assert (intent.name, dict(intent.args)) == ("outputs.resume", {"id": "1"})
        assert target.appliance_id == display._outputs.appliance_id
        assert display._output_open_id is None
        assert display._screen_request is None
        assert display.core.outputs_override() is None

    def test_a_paused_row_another_appliance_has_taken_sends_nothing(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        seed_outputs(display, (OutputRow(id="1", name="Lounge", selected=True, volume=40, paused=True,
                                         remote_in_use=True, remote_owner="Kitchen"),), loaded=False)
        with patch("dial_core.DialCore._send") as send:
            display.outputs_row_tap(0)
        send.assert_not_called()

    def test_outputs_row_tap_stale_index_closes_list(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        seed_outputs(display, (OutputRow(id="1", name="Bedroom", selected=True, volume=40),), loaded=False)
        display.outputs_row_tap(9)
        assert display._output_open_id is None
        # close_list() requests back_to for whatever screen is showing.
        assert display._screen_request == dd._policy(display._screen).back_to

    def _opened_detail(self, selected=True, volume=40):
        display = _make_outputs_display()
        display._open_outputs_locked()
        row = OutputRow(id="1", name="Bedroom", selected=selected, volume=volume)
        seed_outputs(display, (row,), loaded=False)
        display._output_detail = dds.OutputDetailState(
            appliance_id=display._outputs.appliance_id, output_id="1", opened_at=1000.0,
        )
        display._screen = "output"
        return display

    def test_output_toggle_tap_enqueues_and_sets_optimistic(self):
        display = self._opened_detail(selected=False, volume=0)
        with patch("dial_core.DialCore._send") as mock_set:
            display.output_toggle_tap()
        mock_set.assert_called_once()
        target, intent, _token = sent(mock_set)
        out_id = intent.args["id"]
        kwargs = sent_kwargs(mock_set)
        assert out_id == "1"
        assert kwargs["selected"] is True
        assert kwargs["volume"] is None
        assert display.core.outputs_override()[0] == "1"
        assert display.core.outputs_override()[1] is True

    def test_output_toggle_tap_disables(self):
        display = self._opened_detail(selected=True, volume=40)
        with patch("dial_core.DialCore._send") as mock_set:
            display.output_toggle_tap()
        kwargs = sent_kwargs(mock_set)
        assert kwargs["selected"] is False
        assert display.core.outputs_override()[1] is False

    def test_output_toggle_tap_noop_without_row(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        display._output_detail = dds.OutputDetailState(
            appliance_id=display._outputs.appliance_id, output_id="missing", opened_at=1000.0,
        )
        with patch("dial_core.DialCore._send") as mock_set:
            display.output_toggle_tap()
        mock_set.assert_not_called()

    def test_output_volume_tap_steps_from_row_volume(self):
        display = self._opened_detail(selected=True, volume=40)
        with patch("dial_core.DialCore._send") as mock_set:
            display.output_volume_tap(+2)
        kwargs = sent_kwargs(mock_set)
        assert kwargs["selected"] is True
        assert kwargs["volume"] == 42
        assert display.core.outputs_override()[2] == 42

    def test_output_volume_tap_steps_from_optimistic_value(self):
        display = self._opened_detail(selected=True, volume=40)
        tap_output(display, "1", True, 42)
        with patch("dial_core.DialCore._send"):
            display.output_volume_tap(+2)
        assert display.core.outputs_override()[2] == 44

    def test_output_volume_tap_ignored_when_disabled(self):
        display = self._opened_detail(selected=False, volume=0)
        with patch("dial_core.DialCore._send") as mock_set:
            display.output_volume_tap(+2)
        mock_set.assert_not_called()
        assert display.core.outputs_override() is None

    def test_output_volume_tap_clamps_at_100(self):
        display = self._opened_detail(selected=True, volume=99)
        with patch("dial_core.DialCore._send") as mock_set:
            display.output_volume_tap(+10)
        assert sent_kwargs(mock_set)["volume"] == 100

    def test_output_volume_tap_clamps_at_0(self):
        display = self._opened_detail(selected=True, volume=1)
        with patch("dial_core.DialCore._send") as mock_set:
            display.output_volume_tap(-10)
        assert sent_kwargs(mock_set)["volume"] == 0


# ---------------------------------------------------------------------------
# The EQ page: availability, opener, touch entries, on_eq_result, cycle_pages.
# ---------------------------------------------------------------------------

def _make_eq_display(dial_eq=True, auth="unknown", appliance_id="a" * 20):
    display, fb, gt = make_display(targets=[])
    display.core.set_field_for_tests("reporting_id", appliance_id)
    set_roster(display, [_roster_entry(appliance_id=appliance_id, auth=auth, dial_eq=dial_eq)])
    update_availability(display)
    return display


class TestEqOpener:
    def test_refuses_with_no_focus_or_reporting_id(self):
        display, fb, gt = make_display(targets=[])
        assert display._open_eq_locked() is False
        assert display._eq is None

    def test_refuses_without_dial_eq_capability(self):
        display = _make_eq_display(dial_eq=False)
        assert display._open_eq_locked() is False
        assert display._eq is None

    def test_refuses_when_unauthorized(self):
        display = _make_eq_display(auth="unauthorized")
        assert display._open_eq_locked() is False

    def test_refuses_on_the_compact_tier(self):
        display = _make_eq_display(dial_eq=True)
        display.core.set_field_for_tests("eq_available", False)  # the compact veto, already computed by the poll
        assert display._open_eq_locked() is False

    def test_opens_for_an_authorized_capable_appliance(self):
        display = _make_eq_display()
        assert display._open_eq_locked() is True
        assert display._screen == "eq"
        assert display._eq.appliance_id == "a" * 20
        assert dds.held_eq(display.core.snapshot(), display._eq) is None

    def test_keeps_values_on_reopen_for_the_same_appliance(self):
        display = _make_eq_display()
        display._open_eq_locked()
        seed_eq(display, bass_db=2, treble_db=-1, loaded=True)
        display._screen = "main"
        display._open_eq_locked()
        held = dds.held_eq(display.core.snapshot(), display._eq)
        assert dd.eq_gain(held.bands, "bass") == 2
        assert dd.eq_gain(held.bands, "treble") == -1
        assert dds.eq_loaded(held) is True

    def test_resets_values_for_a_different_appliance(self):
        display = _make_eq_display(appliance_id="a" * 20)
        display._open_eq_locked()
        seed_eq(display, bass_db=2, treble_db=-1, loaded=True)
        display._screen = "main"
        display.core.set_field_for_tests("reporting_id", "b" * 20)
        set_roster(display, [_roster_entry(appliance_id="b" * 20, dial_eq=True)])
        update_availability(display)
        display._open_eq_locked()
        assert display._eq.appliance_id == "b" * 20
        assert dds.held_eq(display.core.snapshot(), display._eq) is None


class TestEqStep:
    def _opened(self):
        display = _make_eq_display()
        display._open_eq_locked()
        return display

    def test_noop_without_an_open_eq_screen(self):
        display, fb, gt = make_display(targets=[])
        with patch("dial_core.DialCore._send") as mock_set:
            display.eq_step("bass", +1)
        mock_set.assert_not_called()

    def test_the_shown_value_follows_the_tap_only_inside_its_window(self):
        display = self._opened()
        clock = _FakeClock(1000.0)
        seed_eq(display, bass_db=0, treble_db=0, loaded=True)
        set_eq_optimistic(display, (2, None, 1002.0))
        with patch_monotonic(clock):
            clock.t = 1001.99
            assert display._shown_eq(display._eq, "bass") == 2
            assert display._shown_eq(display._eq, "treble") == 0
            clock.t = 1002.01
            assert display._shown_eq(display._eq, "bass") == 0


class TestOnEqResult:
    def _opened(self, appliance_id="a" * 20):
        display = _make_eq_display(appliance_id=appliance_id)
        display._open_eq_locked()
        return display

    @staticmethod
    def _reading(display):
        """(bass, treble, loaded) the EQ page's appliance shows from the
        core's snapshot."""
        held = dds.held_eq(display.core.snapshot(), display._eq)
        if held is None:
            return None, None, False
        return dd.eq_gain(held.bands, "bass"), dd.eq_gain(held.bands, "treble"), dds.eq_loaded(held)

    def test_a_new_reading_repaints_the_page_and_the_screen_reads_it(self):
        display = self._opened()
        display._overlay_signal.clear()
        seed_eq(display, bass_db=2, treble_db=-1, loaded=True)
        fold(display)
        assert self._reading(display) == (2, -1, True)
        assert display._overlay_signal.is_set()


class TestEqViewBuild:
    def test_view_reads_the_override_then_the_state(self):
        display = _make_eq_display()
        display._open_eq_locked()
        seed_eq(display, bass_db=2, treble_db=-1, loaded=True)
        view = display._build_eq_view_locked(display._eq, time.monotonic())
        assert (view.bass_db, view.treble_db) == (2, -1)
        set_eq_optimistic(display, (5, None, time.monotonic() + 10.0))
        view = display._build_eq_view_locked(display._eq, time.monotonic())
        assert (view.bass_db, view.treble_db) == (5, -1)

    def test_none_screen_builds_a_blank_view(self):
        display, fb, gt = make_display(targets=[])
        view = display._build_eq_view_locked(None, time.monotonic())
        assert view.name == ""
        assert view.bass_db is None
        assert view.treble_db is None
        assert view.loaded is False


class TestCyclePages:
    def _setup(self, appliance_id="a" * 20, repeat_available=False, eq_available=False):
        t = _target(appliance_id=appliance_id)
        display, fb, gt = make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=_track_id(), appliance_id=appliance_id)
        if repeat_available:
            result = dict(result)
            result["repeat"] = _repeat_obj(state="idle", available=True)
        roster = [_roster_entry(appliance_id=appliance_id, playing=True, dial_eq=eq_available)]
        with patch("dial_test_support.fetch_target_status", return_value=result), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=Image.new("RGB", (160, 128))), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=Image.new("RGB", (160, 128))):
            set_roster(display, roster)
            display.fold_for_tests()
            set_roster(display, roster)
            update_availability(display)
            update_availability(display)
        return display

    def _apply(self, display):
        with display._lock:
            display._apply_screen_requests_locked()

    def test_main_to_repeat_to_eq_to_main_when_all_available(self):
        display = self._setup(repeat_available=True, eq_available=True)
        assert display._screen == "main"

        display.cycle_pages()
        self._apply(display)
        assert display._screen == "repeat"

        with patch("dial_core.DialCore._send"):
            display.cycle_pages()
        self._apply(display)
        assert display._screen == "eq"

        display.cycle_pages()
        self._apply(display)
        assert display._screen == "main"

    def test_main_to_eq_to_main_when_no_repeat_record(self):
        display = self._setup(repeat_available=False, eq_available=True)
        with patch("dial_core.DialCore._send"):
            display.cycle_pages()
        self._apply(display)
        assert display._screen == "eq"

        display.cycle_pages()
        self._apply(display)
        assert display._screen == "main"

    def test_main_to_repeat_to_main_when_no_eq(self):
        display = self._setup(repeat_available=True, eq_available=False)
        display.cycle_pages()
        self._apply(display)
        assert display._screen == "repeat"

        display.cycle_pages()
        self._apply(display)
        assert display._screen == "main"

    def test_noop_when_nothing_available(self):
        display = self._setup(repeat_available=False, eq_available=False)
        display._screen_request = None
        display.cycle_pages()
        assert display._screen_request is None
        assert display._screen == "main"

    def test_opening_eq_sends_nothing(self):
        # The EQ is always held, so opening its page asks for nothing.
        display = self._setup(repeat_available=False, eq_available=True)
        with patch("dial_core.DialCore._send") as send:
            display.cycle_pages()
        send.assert_not_called()
        assert display._screen_request == "eq"

    def test_compact_always_two_way(self):
        """On the compact tier the snapshot's eq_available is always False,
        so cycling never reaches "eq" -- a two-way main<->repeat toggle."""
        t = _target(appliance_id="a" * 20)
        roster = [_roster_entry(appliance_id="a" * 20, playing=True, dial_eq=True)]
        display, fb, gt = make_display(targets=[t], roster=roster, screen_size_inches=1.3)
        display.enable()
        result = _status_result(track_id=_track_id(), appliance_id="a" * 20)
        result["repeat"] = _repeat_obj(state="idle", available=True)
        with patch("dial_test_support.fetch_target_status", return_value=result), \
             patch("dial_artwork.default_fetch_artwork", return_value=(b"jpegdata", "")), \
             patch("dial_display.decode_artwork", return_value=Image.new("RGB", (240, 240))), \
             patch("dial_display_compositor.transform_artwork_for_panel", return_value=Image.new("RGB", (240, 240))):
            display.fold_for_tests()
        assert display._compact_tier() is True
        assert display.core.snapshot().eq_available is False

        display.cycle_pages()
        self._apply(display)
        assert display._screen == "repeat"

        display.cycle_pages()
        self._apply(display)
        assert display._screen == "main"


class TestEqPageClosing:
    def test_closes_on_focus_clear(self):
        display = _make_eq_display()
        display._open_eq_locked()
        display._screen = "eq"
        assert dd._policy("eq").closes_on_focus_clear is True

    def test_closes_when_appliance_changes(self):
        display = _make_eq_display(appliance_id="a" * 20)
        display._open_eq_locked()
        display.core.set_field_for_tests("reporting_id", "b" * 20)
        display._close_bound_screen_if_unfocused()
        assert display._screen == "main"
        assert display._eq is None

    def test_no_inactivity_timeout(self):
        assert dd._policy("eq").inactivity_timeout_s is None

    def test_touch_surface_reports_eq_with_outputs_gate(self):
        display = _make_eq_display()
        display._open_eq_locked()
        display.core.set_field_for_tests("outputs_available", False)
        assert display.touch_surface() == ("eq", True, True, False, False)
        display.core.set_field_for_tests("outputs_available", True)
        assert display.touch_surface() == ("eq", True, True, True, False)


class TestOutputsPaintBuilders:
    def test_list_row_enabled_shows_volume_right_aligned_slot(self):
        assert dds.output_list_row(
            OutputRow(id="1", name="Bedroom", selected=True, volume=42),
        ) == ("Bedroom", False, "42", "")

    def test_list_row_disabled_shows_blank(self):
        assert dds.output_list_row(
            OutputRow(id="1", name="Bedroom", selected=False, volume=0),
        ) == ("Bedroom", False, "", "")

    def test_list_row_of_a_speaker_that_paused_itself_says_paused(self):
        assert dds.output_list_row(
            OutputRow(id="1", name="Study TV", selected=True, volume=20, paused=True),
        ) == ("Study TV", False, dds.PAUSED_TEXT, "")
        assert dds.output_list_row(
            OutputRow(id="1", name="Study TV", selected=False, volume=20, paused=True),
        )[2] == ""

    def test_list_row_of_a_speaker_still_ending_its_session_says_stopping(self):
        assert dds.output_list_row(
            OutputRow(id="1", name="Den", selected=False, volume=20, stopping=True),
        ) == ("Den", False, dds.STOPPING_TEXT, "")
        assert dds.STOPPING_TEXT == "Stopping"

    def test_output_list_row_marks_the_default_output(self):
        assert dds.output_list_row(
            OutputRow(id="1", name="Bedroom", selected=True, volume=42, is_default=True),
        ) == ("Bedroom", False, "42", DEFAULT_MARK)
        assert dds.output_list_row(
            OutputRow(id="2", name="Study", selected=True, volume=42),
        )[3] == ""

    def test_output_list_row_shows_the_level_only_when_selected(self):
        on = dds.output_list_row(OutputRow(id="1", name="A", selected=True, volume=7, is_default=True))
        off = dds.output_list_row(OutputRow(id="1", name="A", selected=False, volume=7, is_default=True))
        assert (on[2], off[2]) == ("7", "")

    def test_loading_placeholder_before_first_fetch(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        with display._lock:
            state = display._build_outputs_list_state_locked(160, 128)
        assert state.rows == (("Loading", False),)

    def test_no_outputs_placeholder_once_loaded_and_empty(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        seed_outputs(display, ())
        with display._lock:
            state = display._build_outputs_list_state_locked(160, 128)
        assert state.rows == (("No outputs", False),)

    def test_optimistic_override_applied_before_row_tuples(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        row = OutputRow(id="1", name="Bedroom", selected=False, volume=0)
        seed_outputs(display, (row,))
        tap_output(display, "1", True, 55)
        with display._lock:
            state = display._build_outputs_list_state_locked(160, 128)
        assert state.rows == (("Bedroom", False, "55", ""),)
        # Paint-time only: the manager's own row is never mutated.
        assert display._rows_of(display._outputs)[0].selected is False

    def test_output_view_reads_level_through_the_override(self):
        display = self._opened_with_row(selected=False, volume=0)
        tap_output(display, "1", True, 60)
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
        seed_outputs(display, (), loaded=False)
        with display._lock:
            view = display._build_output_view_locked(1000.0)
        assert view.selected is False
        assert view.level is None
        assert view.output_name == ""

    def _opened_with_row(self, selected, volume):
        display = _make_outputs_display()
        display._open_outputs_locked()
        row = OutputRow(id="1", name="Bedroom", selected=selected, volume=volume)
        seed_outputs(display, (row,))
        display._output_detail = dds.OutputDetailState(
            appliance_id=display._outputs.appliance_id, output_id="1", opened_at=1000.0,
        )
        return display


def _make_outputs_eq_display(appliance_id="a" * 20):
    """A display whose reporting appliance offers both the outputs list and
    the EQ page, so the outputs list can be opened from the EQ page."""
    display, fb, gt = make_display(targets=[])
    display.core.set_field_for_tests("reporting_id", appliance_id)
    set_roster(display, [_roster_entry(appliance_id=appliance_id, dial_outputs=True, dial_eq=True)])
    update_availability(display)
    return display


class TestOutputsReturnToOpeningPage:
    """Closing the outputs list returns to whichever main page opened it."""

    @pytest.mark.parametrize("origin", ["main", "repeat", "eq"])
    def test_close_goes_back_to_the_opening_page(self, origin):
        display = _make_outputs_display()
        display._screen = origin
        assert display._open_outputs_locked() is True
        with patch("dial_core.DialCore._send"):
            display.close_list()
        assert display._screen_request == origin

    def test_other_screens_return_to_main(self):
        display = _make_outputs_display()
        display._outputs_return = "eq"
        display._screen = "selector"
        display._open_outputs_locked()
        assert display._outputs_return == "main"

    def test_detail_page_keeps_the_opening_page(self):
        display = _make_outputs_display()
        display._screen = "repeat"
        display._open_outputs_locked()
        display._screen = "output"
        display._open_outputs_locked()
        assert display._outputs_return == "repeat"

    def test_detail_back_still_goes_to_the_list(self):
        display = _make_outputs_display()
        display._screen = "eq"
        display._open_outputs_locked()
        display._screen = "output"
        display.close_list()
        assert display._screen_request == "outputs"

    def test_back_to_eq_reopens_it_and_drops_the_outputs_state(self):
        display = _make_outputs_eq_display()
        with display._lock:
            assert display._open_eq_locked() is True
            assert display._open_outputs_locked() is True
        with patch("dial_core.DialCore._send") as send:
            display.close_list()
        send.assert_not_called()
        with display._lock:
            display._apply_screen_requests_locked()
        assert display._screen == "eq"
        assert display._eq is not None
        assert display._outputs is None
        assert display._output_detail is None

    def test_back_to_a_page_that_cannot_open_falls_back_to_main(self):
        display = _make_outputs_display()
        display._screen = "repeat"
        with display._lock:
            display._open_outputs_locked()
        set_roster(display, [])  # the appliance has gone: the repeat opener refuses
        display.close_list()
        with display._lock:
            display._apply_screen_requests_locked()
        assert display._screen == "main"
        assert display._outputs is None

    def test_timeout_goes_back_to_the_opening_page(self):
        display = _make_outputs_eq_display()
        with display._lock:
            display._open_eq_locked()
            display._open_outputs_locked()
        display._outputs = dataclasses.replace(display._outputs, opened_at=time.monotonic() - 3600)
        with patch("dial_core.DialCore._send"):
            display._check_secondary_timeout()
        assert display._screen_request == "eq"
        assert display._screen == "outputs"

    def test_timeout_opened_from_main_still_closes(self):
        display = _make_outputs_display()
        with display._lock:
            display._open_outputs_locked()
        display._outputs = dataclasses.replace(display._outputs, opened_at=time.monotonic() - 3600)
        display._check_secondary_timeout()
        assert display._screen == "main"
        assert display._outputs is None


# ---------------------------------------------------------------------------
# Outputs, EQ and transport state held by the core
# ---------------------------------------------------------------------------

class TestOutputsHeldByTheCore:
    AID = "a" * 20

    def _body(self, *rows):
        return {"ok": True, "outputs": [
            {"id": i, "name": n, "selected": s, "volume": v, "remote_in_use": u,
             **({"remote_owner": "Hall"} if u else {})}
            for (i, n, s, v, u) in rows
        ]}

    def test_the_core_keeps_the_row_in_use_elsewhere_and_the_screen_does_not(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        on_outputs_result(display, "fetch", self.AID, 200, self._body(
            ("1", "Bedroom", True, 40, False), ("2", "Study", True, 10, True),
        ), {})
        core_rows = display._core.snapshot().outputs.rows
        assert [(r.id, r.remote_in_use, r.remote_owner) for r in core_rows] == [
            ("1", False, None), ("2", True, "Hall"),
        ]
        assert display._rows_of(display._outputs) == (OutputRow("1", "Bedroom", True, 40),)

    def test_a_result_with_a_row_in_use_paints_the_same_list_as_one_without(self):
        frames = []
        for rows in (
            (("1", "Bedroom", True, 40, False), ("2", "Study", True, 10, True)),
            (("1", "Bedroom", True, 40, False),),
        ):
            display = _make_outputs_display()
            display._open_outputs_locked()
            on_outputs_result(display, "fetch", self.AID, 200, self._body(*rows), {})
            with display._lock:
                frames.append(display._build_outputs_list_state_locked(160, 128))
        assert frames[0] == frames[1]

    def test_the_filtered_rows_equal_what_the_screen_always_parsed(self):
        body = self._body(("1", "Bedroom", True, 40, False), ("2", "Study", True, 10, True))
        assert dds.offerable(outputs_rows(body)) == (OutputRow("1", "Bedroom", True, 40),)

    def test_a_detail_row_taken_elsewhere_counts_as_vanished(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        on_outputs_result(display, "fetch", self.AID, 200, self._body(("1", "Bedroom", True, 40, False)), {})
        display._output_detail = dds.OutputDetailState(
            appliance_id=self.AID, output_id="1", opened_at=time.monotonic(),
        )
        display._screen = "output"
        on_outputs_result(display, "fetch", self.AID, 200, self._body(("1", "Bedroom", True, 40, True)), {})
        assert display._screen_request == "outputs"

    def test_the_screen_rows_follow_the_core_through_a_fold(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        on_outputs_result(display, "fetch", self.AID, 200, self._body(("1", "Bedroom", True, 40, False)), {})
        assert display._core.snapshot().outputs.rows[0].volume == 40
        on_outputs_result(display, "fetch", self.AID, 200, self._body(("1", "Bedroom", True, 41, False)), {})
        assert display._rows_of(display._outputs)[0].volume == 41
        assert display._core.snapshot().outputs.rows[0].volume == 41

    def test_a_tap_on_a_row_the_appliance_has_since_refused_sends_nothing(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        on_outputs_result(display, "fetch", self.AID, 200, self._body(("1", "Bedroom", True, 40, False)), {})
        display._output_detail = dds.OutputDetailState(
            appliance_id=self.AID, output_id="1", opened_at=time.monotonic(),
        )
        display._screen = "output"
        set_roster(display, [_roster_entry(appliance_id=self.AID, auth="unauthorized", dial_outputs=True)])
        with patch("dial_core.DialCore._send") as send:
            display.output_toggle_tap()
            display.output_volume_tap(+1)
        send.assert_not_called()
        assert display.core.outputs_override() is None

    def test_the_override_lives_in_the_core(self):
        display = _make_outputs_display()
        display._open_outputs_locked()
        seed_outputs(display, (OutputRow(id="1", name="Bedroom", selected=False, volume=0),))
        assert display.core.outputs_override() is None
        tap_output(display, "1", True, 40)
        assert display._core.outputs_override()[:3] == ("1", True, 40)
        on_outputs_result(display, "set", "a" * 20, 200, {"ok": False, "error": "output_in_use"})
        assert display.core.outputs_override() is None


class TestEqHeldByTheCore:
    AID = "a" * 20

    def _opened(self):
        display = _make_eq_display()
        display._open_eq_locked()
        return display

    @staticmethod
    def _reading(display):
        held = dds.held_eq(display.core.snapshot(), display._eq)
        return dd.eq_gain(held.bands, "bass"), dd.eq_gain(held.bands, "treble"), dds.eq_loaded(held)

    def test_the_fold_holds_the_bands_with_bass_and_treble_as_two_more(self):
        display = self._opened()
        on_eq_result(display, "fetch", self.AID, 200, {"ok": True, "bass_db": 2, "treble_db": -1}, {})
        bands = display._core.snapshot().eq.bands
        assert [(b.id, b.frequency_hz, b.gain_db, b.min_db, b.max_db)
                for b in bands if b.id in ("bass", "treble")] == [
            ("bass", None, 2, -6, 6), ("treble", None, -1, -6, 6),
        ]
        assert self._reading(display) == (2, -1, True)

    def test_a_reading_without_every_band_leaves_the_page_loading(self):
        display = self._opened()
        seed_bands(display, self.AID, [3, 0])
        assert self._reading(display) == (None, None, False)
        with display._lock:
            view = display._build_eq_view_locked(display._eq, time.monotonic())
        assert view.loaded is False and view.bass_db is None and view.treble_db is None

    def test_the_override_maps_between_the_screen_pair_and_the_core_bands(self):
        display = self._opened()
        set_eq_optimistic(display, (5, None, 1002.0))
        assert display._core.eq_override() == ((("bass", 5),), 1002.0)
        assert eq_optimistic(display) == (5, None, 1002.0)
        set_eq_optimistic(display, (None, -2, 1003.0))
        assert display._core.eq_override() == ((("treble", -2),), 1003.0)
        set_eq_optimistic(display, None)
        assert display._core.eq_override() == ((), 0.0)
        assert eq_optimistic(display) is None

    def test_a_step_is_made_by_the_core_from_the_screen_readings(self):
        display = self._opened()
        seed_eq(display, bass_db=1, treble_db=-3, loaded=True)
        with patch("dial_core.DialCore._send") as send:
            display.eq_step("treble", -9)
        _target, intent, _token = sent(send)
        assert intent.name == "output.eq.set"
        assert ("peq6_db", -6) in [tuple(field) for field in intent.args["fields"]]
        assert eq_optimistic(display)[:2] == (1, -6)


class TestTransportRecordedByTheTaps:
    def _opened(self, state="idle", armed=False):
        return open_repeat_screen(state=state, armed=armed)

    def test_arm_is_recorded_pending(self):
        display, aid = self._opened(state="idle")
        with patch("dial_core.DialCore._send"):
            display.repeat_toggle_tap()
        request = display._core.snapshot().transport
        assert (request.appliance_id, request.kind, request.state) == (aid, "arm", "pending")

    def test_start_is_recorded_as_a_seek(self):
        display, aid = self._opened(state="hold")
        with patch("dial_core.DialCore._send"):
            display.repeat_start_tap()
        assert display._core.snapshot().transport.kind == "seek"

    def test_stop_is_recorded_and_its_own_ack_settles_it(self):
        display, aid = self._opened(state="replaying")
        with patch("dial_core.DialCore._send"):
            display.repeat_stop_tap()
        assert display._core.snapshot().transport.kind == "stop"
        on_repeat_result(display, "transport", aid, 200, {"ok": True, "state": "hold"})
        assert display._core.snapshot().transport.state == "accepted"

    def test_a_rejected_seek_is_recorded_with_its_error(self):
        display, aid = self._opened(state="hold")
        with patch("dial_core.DialCore._send"):
            display.repeat_start_tap()
        on_repeat_result(display, "transport", aid, 412, {"ok": False, "error": "fading_out"})
        request = display._core.snapshot().transport
        assert (request.state, request.error) == ("rejected", "fading_out")


class TestTapsCallTheCoreActions:
    """Each SPI tap resolves what is on screen to ids and hands the request
    to the core action; the action's own behaviour is tested on the core."""

    def _core_action(self, display, name, result=None):
        from dial_core_state import ActionResult
        return patch.object(display._core, name, return_value=result or ActionResult(True))

    def test_selector_pick_sets_the_focus_to_the_row_id(self):
        display = selector_display(authorized_count=2)
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        row = display._current_page_rows(display._selector)[1]
        with self._core_action(display, "set_focus") as action:
            display.selector_pick(1)
        action.assert_called_once_with(row.appliance_id)

    def test_selector_pick_shows_the_hint_when_the_core_says_unauthorized(self):
        from dial_core_state import ActionResult
        display = selector_display(authorized_count=2)
        display.open_selector()
        with display._lock:
            display._repaint_current_locked()
        with self._core_action(display, "set_focus", ActionResult(False, "unauthorized")):
            display.selector_pick(0)
        assert display._screen_request == "info_value"

    def test_picker_pick_starts_the_row_replay_and_arms_the_timer(self):
        display, fb, gt = picker_with_row(aid="a" * 20)
        with self._core_action(display, "start_replay") as action:
            display.picker_pick(0)
        action.assert_called_once_with("a" * 20)
        assert display._repeat_line.timer_id == "a" * 20

    def test_picker_pick_drops_the_timer_when_the_core_refuses(self):
        from dial_core_state import ActionResult
        display, fb, gt = picker_with_row(aid="a" * 20)
        with self._core_action(display, "start_replay", ActionResult(False, "wrong_state")):
            display.picker_pick(0)
        assert display._repeat_line.timer_id is None

    def test_picker_pick_with_a_stale_index_calls_nothing(self):
        display, fb, gt = picker_with_row()
        with self._core_action(display, "start_replay") as action:
            display.picker_pick(5)
        action.assert_not_called()

    def test_repeat_toggle_tap_arms_and_disarms_by_the_record(self):
        display, aid = open_repeat_screen(state="idle", armed=False)
        with self._core_action(display, "set_repeat_armed") as action:
            display.repeat_toggle_tap()
        action.assert_called_once_with(aid, True)
        display, aid = open_repeat_screen(state="recording", armed=True)
        with self._core_action(display, "set_repeat_armed") as action:
            display.repeat_toggle_tap()
        action.assert_called_once_with(aid, False)

    def test_repeat_toggle_tap_while_replaying_is_an_artwork_tap(self):
        display, aid = open_repeat_screen(state="replaying")
        with self._core_action(display, "set_repeat_armed") as action:
            display.repeat_toggle_tap()
        action.assert_not_called()

    def test_repeat_start_tap_restarts_the_open_appliance(self):
        display, aid = open_repeat_screen(state="hold")
        with self._core_action(display, "restart_replay") as action:
            display.repeat_start_tap()
        action.assert_called_once_with(aid)

    def test_repeat_stop_tap_stops_the_open_appliance(self):
        display, aid = open_repeat_screen(state="replaying")
        with self._core_action(display, "stop_replay") as action:
            display.repeat_stop_tap()
        action.assert_called_once_with(aid)

    def test_output_taps_address_the_open_appliance_and_output(self):
        display = TestOutputsTouchEntries()._opened_detail(selected=True, volume=40)
        aid = display._outputs.appliance_id
        with self._core_action(display, "set_output") as action:
            display.output_toggle_tap()
        action.assert_called_once_with(aid, "1", selected=False)
        with self._core_action(display, "step_output_volume") as action:
            display.output_volume_tap(-2)
        action.assert_called_once_with(aid, "1", -2)

    def test_eq_step_addresses_the_open_appliance_and_band(self):
        display = TestEqStep()._opened()
        aid = display._eq.appliance_id
        with self._core_action(display, "step_eq") as action:
            display.eq_step("treble", -1)
        action.assert_called_once_with(aid, "treble", -1)

    def test_the_card_restart_button_calls_the_reboot(self):
        display = idle_display()[0]
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        open_warnings_page(display)
        with patch.object(display._core, "request_dial_reboot", return_value=True) as action:
            tap_card(display, 1)
        action.assert_called_once_with()


# ---------------------------------------------------------------------------
# The "Pair in Autostream" page: a speaker that needs a PIN cannot be paired
# on the small screen, so its output page gives way to a hint page.
# ---------------------------------------------------------------------------

class _SpyLock:
    """A lock that counts acquisitions and delegates to a real one."""

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


class TestOutputDetailLevel:
    """The speaker page's header level: none while the speaker is off or a
    switch-on is still to report the start level the appliance chose, then
    the speaker's own; and a repaint once the tap's shown value goes."""
    AID = "a" * 20

    def _detail(self, selected=False, volume=35):
        display = _make_outputs_display()
        display._open_outputs_locked()
        row = OutputRow(id="1", name="Kitchen", selected=selected, volume=volume)
        seed_outputs(display, (row,), loaded=True)
        display._output_detail = dds.OutputDetailState(
            appliance_id=self.AID, output_id="1", opened_at=time.monotonic(),
        )
        display._screen = "output"
        return display

    def _switch(self, display, selected):
        with patch("dial_core.DialCore._send"):
            assert display.core.set_output(self.AID, "1", selected=selected).accepted

    def test_a_speaker_that_is_off_shows_no_level(self):
        display = self._detail(selected=False, volume=35)
        view = display._build_output_view_locked(time.monotonic())
        assert (view.selected, view.level) == (False, None)

    def test_a_pending_switch_on_shows_on_with_no_level(self):
        display = self._detail(selected=False, volume=35)
        self._switch(display, True)
        view = display._build_output_view_locked(time.monotonic())
        assert (view.selected, view.level) == (True, None)
        row = display._row_with_optimistic_locked(dds.held_outputs(display.core.snapshot(), display._outputs).rows[0])
        assert dds.output_list_row(row)[2] == ""

    def test_a_playing_speaker_shows_its_own_level(self):
        display = self._detail(selected=True, volume=20)
        view = display._build_output_view_locked(time.monotonic())
        assert (view.selected, view.level) == (True, 20)

    def test_the_shown_value_going_repaints_an_open_speaker_page(self):
        import dataclasses
        display = self._detail(selected=False)
        self._switch(display, True)
        prev = display.core.snapshot()
        new = dataclasses.replace(prev, outputs_request=dataclasses.replace(prev.outputs_request, shown=None))
        display._overlay_signal.clear()
        display._follow_screen_data(prev, new)
        assert display._overlay_signal.is_set()

    def test_the_shown_value_going_leaves_other_screens_alone(self):
        import dataclasses
        display = self._detail(selected=False)
        self._switch(display, True)
        display._screen = "main"
        prev = display.core.snapshot()
        new = dataclasses.replace(prev, outputs_request=dataclasses.replace(prev.outputs_request, shown=None))
        display._overlay_signal.clear()
        display._follow_screen_data(prev, new)
        assert not display._overlay_signal.is_set()


class TestPairInAutostreamPage:
    AID = "a" * 20
    PIN_REQUIRED = {"ok": False, "pin_required": True, "error": "Output requires PIN"}

    def _detail(self, needs_auth_key=False, selected=False):
        display = _make_outputs_display()
        display._open_outputs_locked()
        row = OutputRow(id="1", name="Apple TV", selected=selected, volume=0, needs_auth_key=needs_auth_key)
        seed_outputs(display, (row,), loaded=False)
        display._output_detail = dds.OutputDetailState(
            appliance_id=self.AID, output_id="1", opened_at=time.monotonic(),
        )
        display._screen = "output"
        return display

    def _fold(self, display):
        display._apply_pending_snapshot()
        with display._lock:
            display._apply_screen_requests_locked()

    def _refuse(self, display, body):
        with patch("dial_core.DialCore._send"):
            result = display.core.set_output(self.AID, "1", selected=True)
        assert result.accepted
        on_outputs_result(display, "set", self.AID, 200, body, {"token": result.token})
        self._fold(display)

    def test_pairing_hint_text(self):
        label, text = dds.pairing_hint("Lounge")
        assert label == dd_views.PAIR_IN_AUTOSTREAM_TEXT == "Pair in Autostream"
        assert text == "Enter the PIN in Lounge's web UI"

    @pytest.mark.parametrize("width,height,mm_per_px", _HINT_TIERS)
    @pytest.mark.parametrize("name", ["Lounge", "CD Player", "Living Room Hi-Fi"])
    def test_pairing_hint_text_fits_without_truncation(self, width, height, mm_per_px, name):
        from PIL import ImageDraw
        from dial_touch_layout import info_value_layout_for

        metrics = metrics_for(width, height, mm_per_px)
        label, text = dds.pairing_hint(name)
        layout = info_value_layout_for(width, height, metrics=metrics)
        draw = ImageDraw.Draw(Image.new("RGB", (width, height)))
        lines, font = dd_draw._fit_value_lines(
            draw, text, (metrics.font_readout, metrics.font_body), layout.value,
        )
        assert lines and font is not None
        assert " ".join(lines) == text
        max_w = layout.value[2] - layout.value[0]
        for line in lines:
            assert dd_draw._text_size(draw, line, font)[0] <= max_w
        title_w = dd_draw._text_size(draw, label, dd_draw._load_font(metrics.font_body))[0]
        assert title_w <= width - 2 * metrics.pad

    @pytest.mark.parametrize("key", [
        k for k, prof in __import__("dial_display_profiles").DISPLAY_PROFILES.items() if prof.surface == "spi"
    ])
    def test_pairing_hint_fits_every_spi_profile_at_its_default_size(self, key):
        from PIL import ImageDraw
        from dial_touch_layout import info_value_layout_for

        profile = get_profile(key)
        width, height = profile.width, profile.height
        metrics = metrics_for(width, height, mm_per_px_for_size(profile.default_diagonal_inches, profile.width, profile.height))
        label, text = dds.pairing_hint("Living Room Hi-Fi")
        layout = info_value_layout_for(width, height, metrics=metrics)
        draw = ImageDraw.Draw(Image.new("RGB", (width, height)))
        lines, font = dd_draw._fit_value_lines(
            draw, text, (metrics.font_readout, metrics.font_body), layout.value,
        )
        assert lines and font is not None and " ".join(lines) == text
        max_w = layout.value[2] - layout.value[0]
        assert all(dd_draw._text_size(draw, line, font)[0] <= max_w for line in lines)
        title_w = dd_draw._text_size(draw, label, dd_draw._load_font(metrics.font_body))[0]
        assert title_w <= width - 2 * metrics.pad

    def test_a_pin_required_effect_opens_the_pair_page_over_the_output_page_and_back_returns_there(self):
        display = self._detail()
        self._refuse(display, self.PIN_REQUIRED)
        assert display._screen == "info_value"
        assert display._info_value.hint[0] == "Pair in Autostream"
        with display._lock:
            display._repaint_current_locked()
        display.close_list()
        self._fold(display)
        assert display._screen == "output"
        assert display._output_detail.output_id == "1"
        assert display._outputs is not None

    def test_the_page_times_out_to_the_main_page(self):
        display = self._detail()
        self._refuse(display, self.PIN_REQUIRED)
        opened_at = display._info_value.opened_at
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS - 1):
            display._check_secondary_timeout()
        assert display._screen == "info_value"
        with patch("dial_display.time.monotonic", return_value=opened_at + SELECTOR_TIMEOUT_SECONDS + 1):
            display._check_secondary_timeout()
        assert display._screen == "main"

    def test_the_effect_is_ignored_when_the_output_page_is_not_up(self):
        display = self._detail()
        display._screen = "outputs"
        display._output_detail = None
        self._refuse(display, self.PIN_REQUIRED)
        assert display._screen == "outputs"
        assert display._screen_request is None

    def test_the_effect_is_ignored_for_another_output_or_appliance(self):
        display = self._detail()
        for effect in (
            dial_core_effects.OutputsEffect(self.AID, "9", "output_set", "rejected", "pin_required"),
            dial_core_effects.OutputsEffect("b" * 20, "1", "output_set", "rejected", "pin_required"),
        ):
            display._apply_outputs_outcome(effect)
            assert display._screen_request is None

    @pytest.mark.parametrize("body", [
        {"ok": False, "error": "rate_limited", "retry_after_s": 7},
        {"ok": False, "error": "output_in_use"},
        {"ok": False, "error": "encoder_capacity"},
        {"ok": True},
    ])
    def test_any_other_outcome_shows_nothing(self, body):
        display = self._detail()
        self._refuse(display, body)
        assert display._screen == "output"
        assert display._screen_request is None

    def test_a_needs_pin_row_shows_the_pair_page_without_calling_the_core(self):
        display = self._detail(needs_auth_key=True)
        with patch("dial_core.DialCore._send") as send:
            display.output_toggle_tap()
        send.assert_not_called()
        assert display.core.outputs_override() is None
        assert display.core.snapshot().outputs_request is None
        self._fold(display)
        assert display._screen == "info_value"
        assert display._info_value.hint[0] == "Pair in Autostream"

    def test_switching_a_needs_pin_row_off_is_not_short_circuited(self):
        display = self._detail(needs_auth_key=True, selected=True)
        with patch("dial_core.DialCore._send") as send:
            display.output_toggle_tap()
        send.assert_called_once()
        assert display._screen_request is None

    def test_a_hint_cannot_open_over_the_main_page(self):
        display, fb, gt = make_display(targets=[])
        display._info_value_hint = dds.pairing_hint("Lounge")
        with display._lock:
            assert display._open_info_value_locked() is False
        assert display._screen == "main"
        assert display._info_value is None
        assert display._info_value_hint is None

    def test_a_hint_over_the_selector_still_returns_to_the_selector(self):
        display, fb, gt = make_display(targets=[])
        display._screen = "selector"
        display._info_value_hint = dds.unauthorised_hint("Lounge")
        with display._lock:
            assert display._open_info_value_locked() is True
        assert display._back_target("info_value") == "selector"

    def test_the_appliance_changing_while_the_page_is_up_closes_it(self):
        display = self._detail()
        self._refuse(display, self.PIN_REQUIRED)
        assert display._screen == "info_value"
        display.core.set_field_for_tests("reporting_id", "b" * 20)
        set_roster(display, [_roster_entry(appliance_id="b" * 20, dial_outputs=True)])
        with display._lock:
            display._close_secondary_locked()
        assert display._screen == "main"
        assert display._output_detail is None
        assert display._info_value is None

    def test_the_first_touch_of_a_sleeping_screen_only_wakes(self):
        import dial_touch as dt
        from dial_touch_filter import TouchEvent, TouchEventType

        display = self._detail()
        display.enable()
        self._refuse(display, self.PIN_REQUIRED)
        with display._lock:
            display._sleep_locked()
        assert display.is_sleeping() is True
        assert display._screen == "main"
        width, height = display._active_panel_dims()
        sm = dt.TouchStateMachine(width, height, is_asleep=display.is_sleeping)
        sm.set_surface(*display.touch_surface(), 1.0)
        actions = sm.on_filter_event(TouchEvent(TouchEventType.PRESS, width // 2, height // 2), 1.0)
        assert [a.kind for a in actions] == [dt.ACTION_WAKE]
        assert display._screen_request is None

    def test_the_entry_points_take_neither_the_view_lock_nor_the_core_lock(self):
        display = self._detail(needs_auth_key=True)
        view_spy, core_spy = _SpyLock(), _SpyLock()
        display._lock = view_spy
        display._core._lock = core_spy
        display.output_toggle_tap()
        display._apply_outputs_outcome(
            dial_core_effects.OutputsEffect(self.AID, "1", "output_set", "rejected", "pin_required"),
        )
        assert view_spy.acquire_calls == 0
        assert core_spy.acquire_calls == 0


class TestStartFailureNotice:
    AID = "a" * 20

    def _display(self, screen="main"):
        display = _make_outputs_display()
        if screen in ("outputs", "output"):
            display._open_outputs_locked()
            seed_outputs(display, (OutputRow(id="1", name="Patio", selected=False, volume=0),),
                         loaded=False)
            display._screen = screen
            if screen == "output":
                display._output_detail = dds.OutputDetailState(
                    appliance_id=self.AID, output_id="1", opened_at=time.monotonic())
        elif screen != "main":
            display._screen = screen
        return display

    @staticmethod
    def _effect(reason="refused", name="Speaker A", appliance_id="a" * 20):
        return dial_core_effects.StartFailureEffect(appliance_id, f"{appliance_id}:b:1", name, reason)

    def _fold(self, display):
        display._apply_pending_snapshot()
        with display._lock:
            display._apply_screen_requests_locked()

    def test_the_text_for_each_reason(self):
        assert dds.start_failure_hint("Speaker A", "refused") == (
            "Could not start", "Speaker A turned the request down")
        assert dds.start_failure_hint("Speaker A", "failed")[1] == "Speaker A did not start"
        assert dds.start_failure_hint("Speaker A", "timed_out")[1] == "Speaker A did not answer in time"
        assert dds.start_failure_hint("Speaker A", "encoder_capacity")[1] == "No capacity to stream to Speaker A"
        assert dds.start_failure_hint("Speaker A", "mystery")[1] == "Speaker A did not start"

    def test_braces_in_a_name_are_shown_as_written(self):
        assert dds.start_failure_hint("{0} {name} {", "refused")[1] == "{0} {name} { turned the request down"

    @pytest.mark.parametrize("screen", ["main", "outputs", "output"])
    def test_the_value_page_opens_over_the_main_screen_the_list_and_a_speakers_page(self, screen):
        display = self._display(screen)
        display._apply_start_failure(self._effect())
        self._fold(display)
        assert display._screen == "info_value"
        assert display._info_value.hint == ("Could not start", "Speaker A turned the request down")
        assert display._back_target("info_value") == screen

    @pytest.mark.parametrize("screen", ["repeat", "eq", "info", "picker"])
    def test_it_never_opens_over_the_other_screens(self, screen):
        display = self._display(screen)
        display._apply_start_failure(self._effect())
        self._fold(display)
        assert display._screen == screen

    def test_a_sleeping_screen_is_not_woken(self):
        display = self._display()
        with display._lock:
            display._sleep_locked()
        display._apply_start_failure(self._effect())
        assert display._screen_request is None and display._info_value_hint is None
        assert display.is_sleeping() is True

    def test_another_appliance_shows_nothing(self):
        display = self._display()
        display._apply_start_failure(self._effect(appliance_id="b" * 20))
        assert display._screen_request is None

    def test_the_effect_never_reaches_the_source_effects(self):
        display = self._display()
        with patch.object(display, "_apply_source_effects") as source:
            display.core._queue_effects(self._effect())
            display._drain_effects()
        source.assert_not_called()
        assert display._screen_request == "info_value"

    def test_the_notice_does_not_change_where_the_other_hints_open(self):
        display = self._display("main")
        display._apply_start_failure(self._effect())
        self._fold(display)
        display.close_list()
        self._fold(display)
        assert display._screen == "main"
        display._screen = "outputs"
        display._info_value_hint = dds.pairing_hint("Lounge")
        with display._lock:
            assert display._open_info_value_locked() is False


class TestLatePairingHint:
    AID = "a" * 20

    def _display(self, screen):
        display = _make_outputs_display()
        display._open_outputs_locked()
        seed_outputs(display, (OutputRow(id="1", name="Apple TV", selected=False, volume=0),
                               OutputRow(id="2", name="Patio", selected=False, volume=0)),
                     loaded=False)
        display._screen = screen
        if screen == "output":
            display._output_detail = dds.OutputDetailState(
                appliance_id=self.AID, output_id="2", opened_at=time.monotonic())
        return display

    def _late(self, display, output_id="1", late=True, appliance_id=None):
        display._apply_outputs_outcome(dial_core_effects.OutputsEffect(
            appliance_id or self.AID, output_id, "output_set", "rejected", "pin_required", 1.0, late))
        display._apply_pending_snapshot()
        with display._lock:
            display._apply_screen_requests_locked()

    def test_a_late_request_shows_the_hint_on_the_speaker_list(self):
        display = self._display("outputs")
        self._late(display)
        assert display._screen == "info_value"
        assert display._info_value.hint[0] == "Pair in Autostream"
        assert display._back_target("info_value") == "outputs"

    def test_a_late_request_shows_the_hint_on_another_speakers_page(self):
        display = self._display("output")
        self._late(display, output_id="1")
        assert display._screen == "info_value"
        assert display._back_target("info_value") == "output"

    def test_a_late_request_shows_nothing_on_the_main_screen(self):
        display, fb, gt = make_display(targets=[])
        display.core.set_field_for_tests("reporting_id", self.AID)
        self._late(display)
        assert display._screen == "main" and display._info_value is None

    def test_a_late_request_for_another_appliance_shows_nothing(self):
        display = self._display("outputs")
        self._late(display, appliance_id="b" * 20)
        assert display._screen == "outputs"

    def test_an_on_time_request_still_shows_only_on_that_speakers_page(self):
        display = self._display("outputs")
        self._late(display, late=False)
        assert display._screen == "outputs"
        display = self._display("output")
        self._late(display, output_id="1", late=False)
        assert display._screen == "output"
        self._late(display, output_id="2", late=False)
        assert display._screen == "info_value"

    def test_the_unauthorised_row_hint_still_opens_only_over_the_selector(self):
        display = self._display("outputs")
        display._info_value_hint = dds.unauthorised_hint("Lounge")
        with display._lock:
            assert display._open_info_value_locked() is False
