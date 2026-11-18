"""Tests for the small screen's warnings: no warning opens by itself, the bell
opens a card that pages one entry at a time, Close only puts it away, Wi-Fi
opens Info, and a status screen still opens by itself.

The pure page logic is covered in test_dial_warning_page.py and the bell
model in test_dial_warning_bell.py; here the display's wiring of them.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("PIL.Image", reason="Pillow not installed")

REPO_ROOT = Path(__file__).parent.parent
for _p in (str(REPO_ROOT / "dial"), str(REPO_ROOT / "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import dial_display as dd  # noqa: E402
import dial_display_state as dds  # noqa: E402
from dial_appliance_warnings import ApplianceWarning  # noqa: E402
from dial_display_views import BellBadge  # noqa: E402
from dial_info import INFO_LABELS  # noqa: E402
from dial_network import LINK_CONNECTED, LINK_DOWN, NetworkView  # noqa: E402
from dial_sdhealth import STATUS_VALID, SdHealthView  # noqa: E402
from dial_test_support import (  # noqa: E402
    _roster_entry,
    apply_update_view,
    make_display,
    on_network_view,
    on_sd_health_view,
    open_warnings_page,
    set_appliance_warnings,
    set_roster,
    tap_card,
    tick_warnings,
    warning_active,
    warning_cleared,
)
from dial_touch_layout import CARD_BUTTON_ZONES  # noqa: E402
from dial_warning_text import appliance_warning_key  # noqa: E402

AID = "a" * 20


def _fold(display):
    with display._lock:
        display._repaint_current_locked()


def _link(link, bars=0):
    return NetworkView(link=link, device_state="", bars=bars, updated_at=1.0)


def _sd(percent):
    return SdHealthView(status=STATUS_VALID, percent=percent, check="passed", updated_at=1.0)


def _app_warning(wid="stylus", severity="warning", title="Technics stylus", message="Needs changing soon."):
    return ApplianceWarning(wid, severity, title, message)


def _rig(**kwargs):
    display, fb, gt = make_display(
        targets=[], roster=[_roster_entry(auth="authorized", appliance_id=AID)], **kwargs)
    display.enable()
    display.fold_for_tests()
    _fold(display)
    display.fb = fb
    return display


def _lose_wifi(display):
    on_network_view(display, _link(LINK_CONNECTED, bars=3))
    for _ in range(3):
        on_network_view(display, _link(LINK_DOWN))


def _painted(display):
    """The WarningView the card on screen paints."""
    with patch.object(
        display._compositor, "compose_warning", wraps=display._compositor.compose_warning,
    ) as compose:
        with display._lock:
            display._display_card_locked()
    return compose.call_args.args[3]


class TestNoWarningOpensByItself:
    def test_the_dial_warnings_open_nothing_over_idle(self):
        display = _rig()
        _lose_wifi(display)
        on_sd_health_view(display, _sd(15))
        display.core.warning_active("update_dial", ("Kitchen",))
        tick_warnings(display)
        assert display._screen_request is None
        _fold(display)
        assert display._screen == "main" and display._warnings_page is None

    def test_an_appliance_warning_opens_nothing(self):
        display = _rig()
        assert set_appliance_warnings(display, AID, (_app_warning(severity="critical"),)).accepted
        tick_warnings(display)
        assert display._screen_request is None
        _fold(display)
        assert display._screen == "main"

    def test_nothing_opens_over_a_secondary_screen_or_wakes_a_sleeping_panel(self):
        display = _rig()
        display.open_selector()
        _fold(display)
        on_sd_health_view(display, _sd(15))
        assert display._screen_request is None and display._screen == "selector"
        display.close_list()
        _fold(display)
        with display._lock:
            display._sleep_locked()
        warning_active(display, "nowifi")
        assert display._screen_request is None
        display.notify_touch_activity()
        _fold(display)
        assert display._screen == "main" and not display._display_sleeping

    def test_a_status_still_opens_by_itself(self):
        display = _rig()
        _lose_wifi(display)
        from dial_update_watch import UpdateView
        apply_update_view(display, UpdateView(status="in_progress", percent=10, phase="files", tag="1"))
        _fold(display)
        assert display._screen == "update"

    def test_a_status_opening_over_the_warnings_card_closes_it(self):
        display = _rig()
        on_sd_health_view(display, _sd(15))
        open_warnings_page(display)
        assert display._screen == "warnings"
        from dial_update_watch import UpdateView
        apply_update_view(display, UpdateView(status="in_progress", percent=10, phase="files", tag="1"))
        _fold(display)
        assert display._screen == "update" and display._warnings_page is None


class TestTheBell:
    def test_the_idle_surface_reports_the_bell_only_with_entries(self):
        display = _rig()
        assert display.touch_surface() == ("idle", False, False, False, False)
        on_sd_health_view(display, _sd(15))
        assert display.touch_surface() == ("idle", False, False, False, True)
        display.core.warning_cleared("sdhealth")
        assert display.touch_surface()[4] is False

    def test_it_counts_the_dial_and_every_rostered_appliance(self):
        display = _rig()
        on_sd_health_view(display, _sd(15))
        set_appliance_warnings(display, AID, (_app_warning("a"), _app_warning("b", "critical")))
        badge = display._bell_badge()
        assert badge == BellBadge("critical", 3)

    def test_the_idle_frame_is_composed_with_the_badge_or_none(self):
        display = _rig()
        with patch.object(display._compositor, "compose_idle", wraps=display._compositor.compose_idle) as compose:
            _fold(display)
            assert compose.call_args.kwargs["bell"] is None
            on_sd_health_view(display, _sd(15))
            _fold(display)
        assert compose.call_args.kwargs["bell"] == BellBadge("warning", 1)

    def test_a_change_in_the_bell_asks_for_a_repaint(self):
        display = _rig()
        display._apply_pending_snapshot()
        display._overlay_signal.clear()
        on_sd_health_view(display, _sd(15))
        display._apply_pending_snapshot()
        assert display._overlay_signal.is_set()
        display._overlay_signal.clear()
        display._apply_pending_snapshot()
        assert not display._overlay_signal.is_set()

    def test_the_bell_tap_requests_the_card_and_an_empty_bell_opens_nothing(self):
        display = _rig()
        display.open_warnings()
        assert display._screen_request == "warnings"
        _fold(display)
        assert display._screen == "main" and display._warnings_page is None

    def test_wifi_state_alone_adds_nothing_to_the_bell(self):
        display = _rig()
        on_network_view(display, _link(LINK_DOWN))
        assert display._bell_badge() is None


class TestTheCard:
    def test_a_dial_warning_card_shows_this_dial_and_close_alone(self):
        display = _rig()
        on_sd_health_view(display, _sd(15))
        open_warnings_page(display)
        assert display._screen == "warnings"
        assert display.touch_surface() == ("card1", False, False, False, False)
        view = _painted(display)
        assert (view.title, view.message, view.source, view.buttons) == (
            "microSD Health", "15%: Replace Soon", "This dial", ("Close",))

    def test_an_appliance_warning_card_names_the_appliance(self):
        display = _rig()
        set_appliance_warnings(display, AID, (_app_warning(),))
        open_warnings_page(display)
        view = _painted(display)
        assert (view.title, view.message, view.source, view.buttons) == (
            "Technics stylus", "Needs changing soon.", "Kitchen", ("Close",))

    def test_the_update_dial_warning_names_the_appliances_as_a_dial_entry(self):
        display = _rig()
        display.core.warning_active("update_dial", ("Lounge", "Kitchen"))
        open_warnings_page(display)
        view = _painted(display)
        assert (view.title, view.message, view.source) == (
            "Update this dial", "Lounge, Kitchen need a newer dial", "This dial")

    def test_no_wifi_has_restart_then_close(self):
        display = _rig()
        _lose_wifi(display)
        open_warnings_page(display)
        view = _painted(display)
        assert (view.title, view.buttons) == ("No WiFi", ("Restart", "Close"))
        assert display.touch_surface()[0] == "card2"

    def test_several_entries_page_with_next_and_wrap(self):
        display = _rig()
        _lose_wifi(display)
        on_sd_health_view(display, _sd(15))
        set_appliance_warnings(display, AID, (_app_warning(),))
        open_warnings_page(display)
        seen = []
        for _ in range(4):
            view = _painted(display)
            seen.append((view.title, view.source))
            tap_card(display, 0)             # Next is the first cell
            _fold(display)
        assert [t for t, _ in seen] == ["No WiFi", "microSD Health", "Technics stylus", "No WiFi"]
        assert seen[0][1] == "This dial · 1 of 3" and seen[2][1] == "Kitchen · 3 of 3"

    def test_no_wifi_among_others_has_three_cells(self):
        display = _rig()
        _lose_wifi(display)
        on_sd_health_view(display, _sd(15))
        open_warnings_page(display)
        assert _painted(display).buttons == ("Next", "Restart", "Close")
        assert display.touch_surface()[0] == "card3"
        tap_card(display, 0)
        _fold(display)
        assert _painted(display).buttons == ("Next", "Close")
        assert display.touch_surface()[0] == "card2"

    def test_the_text_follows_the_reading(self):
        display = _rig()
        on_sd_health_view(display, _sd(15))
        open_warnings_page(display)
        on_sd_health_view(display, _sd(12))
        _fold(display)
        assert _painted(display).message == "12%: Replace Soon"

    def test_the_pressed_cell_is_passed_to_the_compositor_by_index(self):
        display = _rig()
        on_sd_health_view(display, _sd(15))
        _lose_wifi(display)
        open_warnings_page(display)
        display.set_pressed(CARD_BUTTON_ZONES[1])
        assert _painted(display).pressed == 1
        display.set_pressed(None)
        assert _painted(display).pressed is None


class TestClosing:
    def test_close_puts_the_card_away_and_the_bell_still_counts_it(self):
        display = _rig()
        on_sd_health_view(display, _sd(15))
        open_warnings_page(display)
        tap_card(display, 0)
        assert display._screen_request == "main"
        _fold(display)
        assert display._screen == "main" and display._warnings_page is None
        assert display._bell_badge() == BellBadge("warning", 1)
        assert display.core.warnings.is_active("sdhealth")

    def test_close_is_not_remembered_the_bell_opens_it_again(self):
        display = _rig()
        on_sd_health_view(display, _sd(15))
        open_warnings_page(display)
        tap_card(display, 0)
        _fold(display)
        open_warnings_page(display)
        assert display._screen == "warnings" and _painted(display).title == "microSD Health"

    def test_restart_shows_the_restarting_screen_and_asks_for_the_reboot(self):
        display = _rig()
        _lose_wifi(display)
        open_warnings_page(display)
        with patch("dial_network.request_reboot") as reboot:
            tap_card(display, 0)
        reboot.assert_called_once_with()
        _fold(display)
        assert display._screen == "restarting" and display._warnings_page is None
        assert display.touch_surface() == ("restarting", False, False, False, False)

    def test_close_on_the_update_result_ends_the_status(self):
        display = _rig()
        warning_active(display, "update_result")
        _fold(display)
        assert display._screen == "update_result"
        tap_card(display, 0)
        _fold(display)
        assert display._screen == "main"
        assert not display.core.warnings.is_active("update_result")


class TestAnEntryClears:
    def test_the_card_moves_on_when_its_entry_clears(self):
        display = _rig()
        _lose_wifi(display)
        on_sd_health_view(display, _sd(15))
        open_warnings_page(display)
        assert _painted(display).title == "No WiFi"
        on_network_view(display, _link(LINK_CONNECTED, bars=3))
        display._apply_pending_snapshot()
        _fold(display)
        view = _painted(display)
        assert (view.title, view.buttons, view.source) == ("microSD Health", ("Close",), "This dial")
        assert display.touch_surface()[0] == "card1"

    def test_the_page_closes_when_the_last_entry_clears(self):
        display = _rig()
        on_sd_health_view(display, _sd(15))
        open_warnings_page(display)
        on_sd_health_view(display, _sd(40))
        display._apply_pending_snapshot()
        _fold(display)
        assert display._screen_request == "main"
        _fold(display)
        assert display._screen == "main" and display._warnings_page is None

    def test_an_appliance_that_stops_reporting_closes_the_card(self):
        display = _rig()
        set_appliance_warnings(display, AID, (_app_warning(),))
        open_warnings_page(display)
        set_appliance_warnings(display, AID, ())
        display._apply_pending_snapshot()
        _fold(display)
        assert display._screen_request == "main"

    def test_a_warning_that_appears_is_not_added_to_the_open_card(self):
        display = _rig()
        on_sd_health_view(display, _sd(15))
        open_warnings_page(display)
        _lose_wifi(display)
        _fold(display)
        assert _painted(display).buttons == ("Close",)


class TestLateTaps:
    def test_a_tap_after_the_card_closed_does_nothing(self):
        display = _rig()
        on_sd_health_view(display, _sd(15))
        open_warnings_page(display)
        tap_card(display, 0)
        _fold(display)
        assert display._screen == "main"
        display._screen_request = None
        tap_card(display, 0)
        assert display._screen_request is None

    def test_a_late_restart_never_reboots_when_the_link_came_back(self):
        display = _rig()
        _lose_wifi(display)
        open_warnings_page(display)
        on_network_view(display, _link(LINK_CONNECTED, bars=3))
        display._apply_pending_snapshot()
        _fold(display)
        assert display._screen_request == "main"
        _fold(display)
        with patch("dial_network.request_reboot") as reboot:
            tap_card(display, 0)
            tap_card(display, 1)
        reboot.assert_not_called()

    def test_a_tap_on_a_card_the_finger_did_not_see_is_dropped(self):
        display = _rig()
        _lose_wifi(display)
        on_sd_health_view(display, _sd(15))
        open_warnings_page(display)
        # Next is folded in but the new entry is not painted yet.
        tap_card(display, 0)
        display._screen_request = None
        with patch("dial_network.request_reboot") as reboot:
            with display._lock:
                display._apply_screen_requests_locked()
            tap_card(display, 1)
        reboot.assert_not_called()
        assert display._screen_request is None

    def test_a_tap_with_no_card_dropped_for_a_cell_it_does_not_have(self):
        display = _rig()
        on_sd_health_view(display, _sd(15))
        open_warnings_page(display)
        tap_card(display, 2)
        assert display._screen_request is None


class TestPolicy:
    def test_the_card_times_out_like_info(self):
        display = _rig()
        on_sd_health_view(display, _sd(15))
        open_warnings_page(display)
        later = time.monotonic() + dd.SELECTOR_TIMEOUT_SECONDS + 1
        with patch("dial_display.time.monotonic", return_value=later):
            display._check_secondary_timeout()
        assert display._screen == "main" and display._warnings_page is None

    def test_a_touch_extends_the_timeout(self):
        display = _rig()
        on_sd_health_view(display, _sd(15))
        open_warnings_page(display)
        opened = display._warnings_page.opened_at
        with patch("dial_display.time.monotonic", return_value=opened + 25):
            display.notify_touch_activity()
            with display._lock:
                display._apply_touch_activity_locked()
            assert display._warnings_page.opened_at == opened + 25
            display._check_secondary_timeout()
        assert display._screen == "warnings"

    def test_the_card_lets_the_panel_sleep_and_nothing_brings_it_back(self):
        display = _rig()
        on_sd_health_view(display, _sd(15))
        open_warnings_page(display)
        started = display._idle_started_at
        display.fold_for_tests()
        assert display._idle_started_at == started        # the idle clock is not held off
        with display._lock:
            display._sleep_locked()
        assert display._screen == "main" and display._warnings_page is None
        display.notify_touch_activity()
        _fold(display)
        assert display._screen == "main" and not display._display_sleeping

    def test_it_refuses_to_open_while_restarting(self):
        display = _rig()
        on_sd_health_view(display, _sd(15))
        display._screen_request = "restarting"
        _fold(display)
        display.open_warnings()
        _fold(display)
        assert display._screen == "restarting"

    def test_it_refuses_to_open_while_a_status_page_is_up(self):
        display = _rig()
        on_sd_health_view(display, _sd(15))
        warning_active(display, "update_result")
        _fold(display)
        display.open_warnings()
        _fold(display)
        assert display._screen == "update_result"

    def test_the_card_paints_a_frame_and_the_compact_tier_too(self):
        display = _rig()
        on_sd_health_view(display, _sd(15))
        before = len(display.fb.displayed)
        open_warnings_page(display)
        assert len(display.fb.displayed) == before + 1


class TestWifiOpensInfo:
    def test_the_info_rows_follow_one_order(self):
        assert INFO_LABELS == ("WiFi", "Signal", "IPv4", "Dial name", "Firmware", "Disk free", "SD health")
        assert tuple(row.label for row in dds.INFO_PLACEHOLDER_ROWS) == INFO_LABELS

    def test_the_info_page_opens_from_any_idle_dial(self):
        display = _rig()
        with patch("dial_display.threading.Thread"):
            display.open_info()
        _fold(display)
        assert display._screen == "info"


class TestTheBellStatePerAppliance:
    def test_the_bell_holds_each_rostered_appliance_and_the_dial_once(self):
        display = _rig()
        other = "b" * 20
        set_roster(display, [
            _roster_entry(auth="authorized", appliance_id=AID),
            _roster_entry(name="Lounge", auth="authorized", appliance_id=other, ip="192.168.1.11"),
        ])
        set_appliance_warnings(display, AID, (_app_warning(),))
        assert set_appliance_warnings(display, other, (_app_warning(),)).accepted
        keys = [e.key for e in display._bell().entries]
        assert sorted(keys) == sorted([appliance_warning_key(AID, "stylus"), appliance_warning_key(other, "stylus")])
        sources = {e.source for e in display._bell().entries}
        assert sources == {"Kitchen", "Lounge"}


class TestBellOnThePlayingScreen:
    """The bell off the idle screen: the surface flag for the touch side's one
    gate, and the bell carried in the overlay the compositor draws."""

    def _playing(self, **overrides):
        import test_dial_display as td
        from dial_test_support import _target
        display, fb, gt = make_display(targets=[_target()], **overrides)
        display.enable()
        td._poll_with_artwork(display, fb)
        return display

    def test_hidden_and_held_report_the_bell_flag(self):
        for overrides, surface in (({}, "hidden"), ({"always_show_controls": True}, "held")):
            display = self._playing(**overrides)
            assert display.touch_surface()[0] == surface and display.touch_surface()[4] is False
            on_sd_health_view(display, _sd(15))
            assert display.touch_surface()[4] is True

    def test_the_repeat_and_eq_screens_report_it_the_others_do_not(self):
        display = self._playing()
        on_sd_health_view(display, _sd(15))
        for screen, expected in (("repeat", True), ("eq", True), ("selector", False), ("info", False)):
            display._screen = screen
            assert display.touch_surface()[4] is expected, screen

    def test_the_overlay_carries_the_bell_hidden_or_visible(self):
        display = self._playing()
        on_sd_health_view(display, _sd(15))
        badge = BellBadge("warning", 1)
        with display._lock:
            hidden = display._effective_overlay_locked(dd.OverlayState())
            shown = display._effective_overlay_locked(dd.OverlayState(visible=True))
        assert hidden.bell == badge and not hidden.visible
        assert shown.bell == badge and shown.visible

    def test_a_hide_window_still_carries_the_bell(self):
        display = self._playing()
        on_sd_health_view(display, _sd(15))
        display.hide_controls()
        with display._lock:
            overlay = display._effective_overlay_locked(dd.OverlayState(visible=True))
        assert overlay.bell == BellBadge("warning", 1) and not overlay.visible

    def test_no_bell_leaves_the_overlay_object_untouched(self):
        display = self._playing()
        snapshot = dd.OverlayState()
        with display._lock:
            assert display._effective_overlay_locked(snapshot) is snapshot

    def test_the_playing_frame_is_composed_with_the_bell(self):
        display = self._playing()
        on_sd_health_view(display, _sd(15))
        with patch.object(display._compositor, "compose", wraps=display._compositor.compose) as compose:
            _fold(display)
        assert compose.call_args.kwargs["overlay"].bell == BellBadge("warning", 1)

    def test_the_repeat_and_eq_views_carry_the_bell(self):
        display = self._playing()
        on_sd_health_view(display, _sd(15))
        for method, painter in (("compose_repeat", display._display_repeat_locked), ("compose_eq", display._display_eq_locked)):
            with patch.object(display._compositor, method, wraps=getattr(display._compositor, method)) as compose:
                with display._lock:
                    painter()
            assert compose.call_args.args[2].bell == BellBadge("warning", 1)

    def test_the_compact_resting_artwork_reports_the_bell_only_on_main(self):
        import test_dial_display as td
        from dial_test_support import _target
        display, fb, gt = td._make_compact_display(targets=[_target()])
        display.enable()
        td._poll_with_artwork(display, fb)
        on_sd_health_view(display, _sd(15))
        display._controls_hidden_until = 0.0
        surface = display.touch_surface()
        assert surface[4] is True
