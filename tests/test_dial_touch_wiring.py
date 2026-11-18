"""The touch wiring: the zone table, the builder's callback wiring and the layout it builds at.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import sys
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "dial"))

from dial_touch_layout import BELL_ZONES, CARD_BUTTON_ZONES, TouchZone
from dial_touch_wiring import TouchWiring


def _wiring():
    return TouchWiring(
        MagicMock(), MagicMock(), step=lambda: 3, confirm_presence=lambda: None,
        overlay_state=MagicMock(),
    )


def test_zone_table_has_no_duplicate_zone():
    zones = [zone for zone, _action in _wiring()._zone_action_pairs()]
    assert len(zones) == len(set(zones))


def test_zone_table_covers_the_chains_zones():
    explicit = {
        TouchZone.NAME, TouchZone.LIST_BACK, TouchZone.LIST_DOWN, TouchZone.LIST_UP,
        TouchZone.LIST_ROW, TouchZone.DOTS,
        TouchZone.EQ_BASS_DOWN, TouchZone.EQ_BASS_UP,
        TouchZone.EQ_TREBLE_DOWN, TouchZone.EQ_TREBLE_UP,
        TouchZone.REPEAT_PLAY, TouchZone.REPEAT_START, TouchZone.REPEAT_STOP,
        TouchZone.IDLE_REPLAY, TouchZone.IDLE_WIFI,
        TouchZone.OUTPUTS, TouchZone.OUTPUT_BACK, TouchZone.OUTPUT_TOGGLE,
        TouchZone.OUTPUT_UP, TouchZone.OUTPUT_DOWN, TouchZone.ARTWORK,
    }
    assert len(explicit) == 21
    assert set(_wiring()._zone_actions) == explicit | set(BELL_ZONES) | set(CARD_BUTTON_ZONES)


class TestBuildTouchSourceWiring:
    """Direct tests of dial_touch_wiring.build_touch_source()'s callback wiring,
    with the hardware-touching pieces (open_driver, TouchEventSource's
    background thread) faked out."""

    @contextmanager
    def _built(self, confirm_presence=None, step_percent=None):
        """Construct via dial_touch_wiring.build_touch_source() with the mocks
        still active, yielding everything a test needs — the volume and
        mute calls are recorded on a mock core (its volume_step and
        mute_toggle), and the patches must still be in effect when a test
        actually invokes a captured callback."""
        import dial_touch_wiring
        from dial_config import DialDisplayConfig

        cfg = MagicMock()
        cfg.display = DialDisplayConfig(fitted=True, touch_type="xpt2046")
        cfg.step_percent = 3

        display = MagicMock()
        display.noncomposited_generation = MagicMock(return_value=0)
        core = MagicMock()

        captured = {}

        def fake_touch_event_source(driver, touch_filter, state_machine, **kwargs):
            captured["driver"] = driver
            captured["kwargs"] = kwargs
            instance = MagicMock()
            captured["instance"] = instance
            return instance

        with patch("dial_touch_drivers.open_driver") as mock_open, \
             patch("dial_touch_source.TouchEventSource", side_effect=fake_touch_event_source):
            result = dial_touch_wiring.build_touch_source(
                cfg, display, confirm_presence=confirm_presence, step_percent=step_percent,
                core=core,
            )
            yield (
                cfg, display, result, captured, mock_open,
                core.volume_step, core.mute_toggle,
            )

    def test_driver_opened_for_configured_controller(self):
        with self._built() as (cfg, display, result, captured, mock_open, *_):
            mock_open.assert_called_once_with("xpt2046")
            assert captured["driver"] is mock_open.return_value
            assert result is captured["instance"]

    def test_noncomposited_generation_getter_wired_to_display(self):
        with self._built() as (cfg, display, result, captured, *_):
            assert captured["kwargs"]["get_noncomposited_generation"] is display.noncomposited_generation

    def test_touch_surface_getter_wired_to_display(self):
        with self._built() as (cfg, display, result, captured, *_):
            assert captured["kwargs"]["get_touch_surface"] is display.touch_surface

    def test_repeat_close_reveal_getter_wired_to_display(self):
        with self._built() as (cfg, display, result, captured, *_):
            assert (
                captured["kwargs"]["consume_repeat_close_reveal"]
                is display.consume_repeat_close_reveal
            )

    def test_volume_up_steps_by_step_percent_and_notifies_activity(self):
        with self._built() as (cfg, display, result, captured, _open, mock_delta, mock_mute):
            captured["kwargs"]["on_volume_up"]()
            mock_delta.assert_called_once_with(3)
            display.notify_touch_activity.assert_called_once()

    def test_volume_down_steps_by_negative_step_percent(self):
        with self._built() as (cfg, display, result, captured, _open, mock_delta, mock_mute):
            captured["kwargs"]["on_volume_down"]()
            mock_delta.assert_called_once_with(-3)
            display.notify_touch_activity.assert_called_once()

    def test_volume_callbacks_enqueue_before_notifying(self):
        """The core's volume_step() must run BEFORE notify_touch_activity()
        — the reverse of the historical order — because
        notify_touch_activity() sets the repaint signal, and the repaint
        must see the readout's nudged pending value (see
        dial_volume.enqueue_delta())."""
        call_order = []
        with self._built() as (cfg, display, result, captured, _open, mock_delta, mock_mute):
            mock_delta.side_effect = lambda *a, **kw: call_order.append("enqueue_delta")
            display.notify_touch_activity.side_effect = lambda: call_order.append("notify_touch_activity")

            captured["kwargs"]["on_volume_up"]()
            assert call_order == ["enqueue_delta", "notify_touch_activity"]

            call_order.clear()
            captured["kwargs"]["on_volume_down"]()
            assert call_order == ["enqueue_delta", "notify_touch_activity"]

    def test_volume_up_uses_live_step_percent_callable_when_supplied(self):
        """A live step change via /configure must be honoured by touch, not
        just the encoder — see dial_http_server.DialHTTPServer.step_percent."""
        live_step = {"value": 3}
        with self._built(step_percent=lambda: live_step["value"]) as (
            cfg, display, result, captured, _open, mock_delta, mock_mute,
        ):
            captured["kwargs"]["on_volume_up"]()
            mock_delta.assert_called_once_with(3)

            live_step["value"] = 7
            captured["kwargs"]["on_volume_down"]()
            mock_delta.assert_called_with(-7)

    def test_volume_up_falls_back_to_cfg_step_percent_when_no_callable_supplied(self):
        with self._built(step_percent=None) as (cfg, display, result, captured, _open, mock_delta, mock_mute):
            captured["kwargs"]["on_volume_up"]()
            mock_delta.assert_called_once_with(cfg.step_percent)

    def test_mute_toggle_asks_the_core_to_toggle_mute(self):
        with self._built() as (cfg, display, result, captured, _open, mock_delta, mock_mute):
            captured["kwargs"]["on_mute_toggle"]()
            mock_mute.assert_called_once()
            display.notify_touch_activity.assert_called_once()

    def test_mute_toggle_hands_the_decision_to_the_core_with_no_arguments(self):
        """on_mute_toggle infers nothing of its own: which appliance, and
        whether this is a fleet toggle, is the core's decision (the same one
        the button's press makes)."""
        with self._built() as (cfg, display, result, captured, _open, mock_delta, mock_mute):
            captured["kwargs"]["on_mute_toggle"]()
            mock_mute.assert_called_once_with()

    def test_mute_toggle_reveals_the_overlay_without_publishing_muted(self):
        """The overlay is revealed with no muted field of its own -- the
        display's compose-time merge fills it in from the observation
        store (shown_muted()) for whichever appliance is reporting; the
        touch side has nothing further to publish."""
        with self._built() as (cfg, display, result, captured, _open, mock_delta, mock_mute):
            captured["kwargs"]["on_mute_toggle"]()

            display.set_overlay.assert_called_once()
            state = display.set_overlay.call_args[0][0]
            assert state.visible is True
            assert state.muted is None  # OverlayState's own tri-state default

    def test_reveal_overlay_sets_overlay_visible_and_signals_overlay_live(self):
        with self._built() as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_reveal_overlay"]()

            display.set_overlay.assert_called_once()
            state = display.set_overlay.call_args[0][0]
            assert state.visible is True
            assert state.pressed is None
            display.notify_touch_activity.assert_called_once()
            result.overlay_live.assert_called_once()

    def test_reveal_overlay_publishes_no_muted_field(self):
        """A reveal publishes only visible=True -- muted is filled in at
        compose time from the observation store (shown_muted()), never a
        belief kept here, so there is nothing for the touch side to read
        or publish about mute at reveal time."""
        with self._built() as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_reveal_overlay"]()

            state = display.set_overlay.call_args[0][0]
            assert state.muted is None

    def test_dismiss_overlay_sets_overlay_hidden(self):
        with self._built() as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_dismiss_overlay"]()

            state = display.set_overlay.call_args[0][0]
            assert state.visible is False

    def test_set_pressed_zone_records_the_zone(self):
        from dial_touch_layout import TouchZone

        with self._built() as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_set_pressed_zone"](TouchZone.UP)

            display.set_pressed.assert_called_once_with(TouchZone.UP, None)
            display.set_overlay.assert_not_called()
            display.notify_touch_activity.assert_called_once()

    def test_set_pressed_zone_passes_through_the_row_index(self):
        from dial_touch_layout import TouchZone

        with self._built() as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_set_pressed_zone"](TouchZone.LIST_ROW, 2)

            display.set_pressed.assert_called_once_with(TouchZone.LIST_ROW, 2)

    def test_reveal_overlay_confirms_presence(self):
        """The very first touch-down — reveal-only, nothing armed yet — must
        still confirm presence (see reveal-then-arm in dial_touch.py: a
        first contact may never reach on_set_pressed_zone at all)."""
        confirm = MagicMock()
        with self._built(confirm_presence=confirm) as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_reveal_overlay"]()
        confirm.assert_called_once()

    def test_set_pressed_zone_confirms_presence(self):
        """A press that arms immediately (overlay already visible) must also
        confirm presence."""
        from dial_touch_layout import TouchZone

        confirm = MagicMock()
        with self._built(confirm_presence=confirm) as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_set_pressed_zone"](TouchZone.DOWN)
        confirm.assert_called_once()

    def test_confirm_presence_is_optional(self):
        """confirm_presence defaults to None — callers/tests that don't pass
        it must not have on_reveal_overlay/on_set_pressed_zone raise."""
        from dial_touch_layout import TouchZone

        with self._built() as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_reveal_overlay"]()
            captured["kwargs"]["on_set_pressed_zone"](TouchZone.UP)

    def test_set_pressed_zone_for_a_list_zone_does_not_touch_the_main_overlay(self):
        """LIST_* zones report through the same unified pressed channel as
        every other zone — on_set_pressed_zone never publishes an
        OverlayState at all, so the main screen's snapshot is untouched."""
        from dial_touch_layout import TouchZone

        with self._built() as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_set_pressed_zone"](TouchZone.LIST_ROW)
            display.set_overlay.assert_not_called()
            display.set_pressed.assert_called_once_with(TouchZone.LIST_ROW, None)
            # Touch activity/presence are still genuine, though.
            display.notify_touch_activity.assert_called_once()

    # Every zone reports through the same unified pressed channel: the press
    # goes to set_pressed() and never publishes an OverlayState.
    @pytest.mark.parametrize("zone", [
        pytest.param("REPEAT_PLAY", id="repeat_play"),
        pytest.param("IDLE_REPLAY", id="idle_replay"),
        pytest.param("DOTS", id="dots"),
    ])
    def test_set_pressed_zone_records_the_zone_on_the_pressed_channel(self, zone):
        from dial_touch_layout import TouchZone

        with self._built() as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_set_pressed_zone"](TouchZone[zone])
            display.set_pressed.assert_called_once_with(TouchZone[zone], None)
            display.set_overlay.assert_not_called()

    # The single-shot flash's own clear (zone=None) goes through set_pressed()
    # too, whatever zone was pressed: it must never leak through as a stray
    # main-overlay update.
    @pytest.mark.parametrize("zone", [
        pytest.param("LIST_BACK", id="after_a_list_zone"),
        pytest.param("NAME", id="after_name"),
        pytest.param("REPEAT_START", id="after_secondary_zone"),
    ])
    def test_set_pressed_zone_clear_uses_the_pressed_channel(self, zone):
        from dial_touch_layout import TouchZone

        with self._built() as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_set_pressed_zone"](TouchZone[zone])
            captured["kwargs"]["on_set_pressed_zone"](None)
            display.set_overlay.assert_not_called()
            assert display.set_pressed.call_args_list == [
                call(TouchZone[zone], None), call(None, None),
            ]

    def test_on_zone_tap_name_opens_the_selector(self):
        from dial_touch_layout import TouchZone

        with self._built() as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_zone_tap"](TouchZone.NAME, None)
            display.open_selector.assert_called_once()
            display.notify_touch_activity.assert_called_once()

    # (zone, row index, display method, expected call args or None for "called once")
    @pytest.mark.parametrize("zone, row, method, args", [
        pytest.param("LIST_BACK", None, "close_list", None, id="list_back_closes_the_list_screen"),
        pytest.param("LIST_DOWN", None, "list_page", (1,), id="list_down_pages_forward"),
        pytest.param("LIST_UP", None, "list_page", (-1,), id="list_up_pages_backward"),
        pytest.param("LIST_ROW", 2, "list_row_tap", (2,), id="list_row_dispatches_to_list_row_tap"),
        pytest.param("DOTS", None, "cycle_pages", None, id="dots_cycles_pages"),
        pytest.param("EQ_BASS_DOWN", None, "eq_step", ("bass", -1), id="eq_bass_down_steps_bass_down"),
        pytest.param("EQ_BASS_UP", None, "eq_step", ("bass", +1), id="eq_bass_up_steps_bass_up"),
        pytest.param("EQ_TREBLE_DOWN", None, "eq_step", ("treble", -1), id="eq_treble_down_steps_treble_down"),
        pytest.param("EQ_TREBLE_UP", None, "eq_step", ("treble", +1), id="eq_treble_up_steps_treble_up"),
        pytest.param("REPEAT_PLAY", None, "repeat_toggle_tap", None, id="repeat_play_toggles_arm"),
        pytest.param("REPEAT_START", None, "repeat_start_tap", None, id="repeat_start_taps_start"),
        pytest.param("REPEAT_STOP", None, "repeat_stop_tap", None, id="repeat_stop_taps_stop"),
        pytest.param("IDLE_REPLAY", None, "open_picker", None, id="idle_replay_opens_the_picker"),
        pytest.param("IDLE_BELL", None, "open_warnings", None, id="idle_bell_opens_the_warnings_card"),
        pytest.param("BAND_BELL", None, "open_warnings", None, id="band_bell_opens_the_warnings_card"),
        pytest.param("DOTS_BELL", None, "open_warnings", None, id="dots_bell_opens_the_warnings_card"),
        pytest.param("ARTWORK_BELL", None, "open_warnings", None, id="artwork_bell_opens_the_warnings_card"),
        pytest.param("IDLE_WIFI", None, "open_info", None, id="idle_wifi_opens_the_info_page"),
        pytest.param("OUTPUTS", None, "open_outputs", None, id="outputs_opens_the_outputs_list"),
        pytest.param("OUTPUT_BACK", None, "close_list", None, id="output_back_closes_the_list_screen"),
        pytest.param("OUTPUT_TOGGLE", None, "output_toggle_tap", None, id="output_toggle_taps_the_output"),
        pytest.param("OUTPUT_UP", None, "output_volume_tap", (3,), id="output_up_steps_by_step_percent"),
        pytest.param("OUTPUT_DOWN", None, "output_volume_tap", (-3,), id="output_down_steps_by_negative_step_percent"),
    ])
    def test_on_zone_tap_dispatches_to_the_display(self, zone, row, method, args):
        from dial_touch_layout import TouchZone

        with self._built() as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_zone_tap"](TouchZone[zone], row)
            target = getattr(display, method)
            if args is None:
                target.assert_called_once()
            else:
                target.assert_called_once_with(*args)

    # The card buttons are handed to the card dispatch, zone and all.
    @pytest.mark.parametrize("zone", [
        pytest.param("CARD_BUTTON_0", id="first_card_button"),
        pytest.param("CARD_BUTTON_1", id="second_card_button"),
        pytest.param("CARD_BUTTON_2", id="third_card_button"),
    ])
    def test_on_zone_tap_card_buttons_go_to_the_card_dispatch(self, zone):
        from dial_touch_layout import TouchZone

        with self._built() as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_zone_tap"](TouchZone[zone], None)
            display.card_button_tap.assert_called_once_with(TouchZone[zone])

    def test_on_zone_tap_confirms_presence(self):
        from dial_touch_layout import TouchZone

        confirm = MagicMock()
        with self._built(confirm_presence=confirm) as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_zone_tap"](TouchZone.NAME, None)
        confirm.assert_called_once()

    def test_on_zone_tap_artwork_hides_the_controls(self):
        from dial_touch_layout import TouchZone

        with self._built() as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_zone_tap"](TouchZone.ARTWORK, None)
            display.hide_controls.assert_called_once()
            # The touch session is told the controls are gone too.
            captured["instance"].overlay_hidden.assert_called_once()

    def test_on_zone_tap_output_up_uses_live_step_percent_callable(self):
        from dial_touch_layout import TouchZone

        live_step = {"value": 7}
        with self._built(step_percent=lambda: live_step["value"]) as (
            cfg, display, result, captured, *_,
        ):
            captured["kwargs"]["on_zone_tap"](TouchZone.OUTPUT_UP, None)
            display.output_volume_tap.assert_called_once_with(7)


class TestAsleepTouchWiring:
    """A touch on a sleeping panel only wakes it (see
    dial_touch.TouchStateMachine._on_press)."""

    def test_state_machine_gets_the_displays_lock_free_sleep_predicate(self):
        import dial_touch_wiring
        from dial_config import DialDisplayConfig

        cfg = MagicMock()
        cfg.display = DialDisplayConfig(fitted=True, touch_type="xpt2046")
        display = MagicMock()
        with patch("dial_touch_drivers.open_driver"), \
             patch("dial_touch_source.TouchEventSource"), \
             patch("dial_touch.TouchStateMachine") as sm_cls:
            dial_touch_wiring.build_touch_source(cfg, display, core=MagicMock())
        assert sm_cls.call_args.kwargs["is_asleep"] is display.is_sleeping

    def test_on_wake_notifies_activity_and_confirms_presence_only(self):
        t = TestBuildTouchSourceWiring()
        confirm = MagicMock()
        with t._built(confirm_presence=confirm) as (cfg, display, result, captured, _open, mock_delta, mock_mute):
            captured["kwargs"]["on_wake"]()
            confirm.assert_called_once_with()
            display.notify_touch_activity.assert_called_once_with()
            display.set_overlay.assert_not_called()
            display.set_pressed.assert_not_called()
            display.open_picker.assert_not_called()
            mock_delta.assert_not_called()
            mock_mute.assert_not_called()

    def test_on_wake_without_confirm_presence_does_not_raise(self):
        t = TestBuildTouchSourceWiring()
        with t._built() as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_wake"]()


class TestBuildTouchSourceLayoutWiring:
    def _built_with_layout(self, screen_type, screen_size_inches, layout_size):
        import dial_touch_wiring
        from dial_config import DialDisplayConfig

        cfg = MagicMock()
        cfg.display = DialDisplayConfig(
            fitted=True, touch_type="xpt2046", screen_type=screen_type,
            screen_size_inches=screen_size_inches, layout_size=layout_size,
        )
        cfg.step_percent = 3
        display = MagicMock()
        display.noncomposited_generation = MagicMock(return_value=0)

        captured = {}

        def fake_touch_filter(*args, **kwargs):
            captured["filter_args"] = args
            captured["filter_kwargs"] = kwargs
            return MagicMock()

        def fake_state_machine(*args, **kwargs):
            captured["machine_args"] = args
            captured["machine_kwargs"] = kwargs
            return MagicMock()

        with patch("dial_touch_drivers.open_driver"), \
             patch("dial_touch_filter.TouchFilter", side_effect=fake_touch_filter), \
             patch("dial_touch.TouchStateMachine", side_effect=fake_state_machine), \
             patch("dial_touch_source.TouchEventSource"):
            dial_touch_wiring.build_touch_source(cfg, display, core=MagicMock())
        return captured

    def test_large_layout_size_builds_at_logical_with_physical_scaling(self):
        captured = self._built_with_layout("ili9341_320x240", 2.8, "large")
        assert captured["filter_args"][:2] == (640, 480)
        assert captured["filter_kwargs"]["physical_size"] == (320, 240)
        assert captured["machine_args"][:2] == (640, 480)
        assert captured["machine_kwargs"]["metrics"].content_tier == "large"

    def test_none_layout_size_matches_todays_construction(self):
        from dial_display_profiles import effective_diagonal_inches, get_profile, mm_per_px_for_size
        from dial_layout_metrics import metrics_for

        captured = self._built_with_layout("ili9341_320x240", 2.8, None)
        profile = get_profile("ili9341_320x240")
        assert captured["filter_args"][:2] == (profile.width, profile.height)
        # None path: physical_size equals the logical size, the short-circuit
        # (no-op scaling) case in TouchFilter._to_panel_xy().
        assert captured["filter_kwargs"]["physical_size"] == (profile.width, profile.height)
        expected_metrics = metrics_for(
            profile.width, profile.height,
            mm_per_px=mm_per_px_for_size(effective_diagonal_inches(profile, 2.8), profile.width, profile.height),
        )
        assert captured["machine_kwargs"]["metrics"] == expected_metrics
