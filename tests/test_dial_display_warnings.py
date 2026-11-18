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
from dial_network import LINK_CONNECTED, LINK_DOWN  # noqa: E402
from dial_sdhealth import STATUS_VALID, SdHealthView  # noqa: E402
from dial_test_support import (  # noqa: E402
    WARNING_BY_ID,
    _roster_entry,
    apply_update_view,
    make_display,
    on_network_view,
    on_sd_health_view,
    open_warnings_page,
    set_appliance_warnings,
    set_roster,
    tap_card,
    tick_update_watch,
    tick_warnings,
    warning_active,
)
from dial_touch_layout import CARD_BUTTON_ZONES  # noqa: E402
from dial_warning_text import appliance_warning_key  # noqa: E402
import dial_warning_text as dwt  # noqa: E402
from dial_warning_text import WARNING_DESCRIPTORS  # noqa: E402
from dial_warnings import KIND_STATUS, WarningManager  # noqa: E402
from dial_display_test_support import _fold, _view  # noqa: E402

AID = "a" * 20


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
    on_network_view(display, _view(LINK_CONNECTED, bars=3))
    for _ in range(3):
        on_network_view(display, _view(LINK_DOWN))


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
        on_network_view(display, _view(LINK_DOWN))
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
            "microSD card", "15% life left, replace soon", "This Dial", ("Close",))

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
            "Update this dial", "Lounge, Kitchen need a newer dial", "This Dial")

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
        assert [t for t, _ in seen] == ["No WiFi", "microSD card", "Technics stylus", "No WiFi"]
        assert seen[0][1] == "This Dial · 1 of 3" and seen[2][1] == "Kitchen · 3 of 3"

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
        assert _painted(display).message == "12% life left, replace soon"

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
        assert display._screen == "warnings" and _painted(display).title == "microSD card"

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
        on_network_view(display, _view(LINK_CONNECTED, bars=3))
        display._apply_pending_snapshot()
        _fold(display)
        view = _painted(display)
        assert (view.title, view.buttons, view.source, view.severity) == (
            "microSD card", ("Close",), "This Dial", "warning")
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
        on_network_view(display, _view(LINK_CONNECTED, bars=3))
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
        import dial_display_test_support as td
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
        import dial_display_test_support as td
        from dial_test_support import _target
        display, fb, gt = td._make_compact_display(targets=[_target()])
        display.enable()
        td._poll_with_artwork(display, fb)
        on_sd_health_view(display, _sd(15))
        display._controls.hidden_until = 0.0
        surface = display.touch_surface()
        assert surface[4] is True


# ---------------------------------------------------------------------------
# Test helpers for the warnings: a settable clock and an SD health reading
# (see dial_sdhealth.py for wear_level()'s hysteresis rule).
# ---------------------------------------------------------------------------

class _Clock:
    """A settable fake wall clock for the warning manager: pass `.now` as
    WarningManager's clock= and move `.t` directly."""

    def __init__(self, t: float) -> None:
        self.t = t

    def now(self) -> float:
        return self.t


def _sd_view(status, percent=None, check="passed"):
    return SdHealthView(status=status, percent=percent, check=check, updated_at=1.0)


# ---------------------------------------------------------------------------
# Generic warning capabilities: title_for, progress_for, interrupting,
# auto_clear_after_s and the button-less form, driven through rows
# registered for the test only.
# ---------------------------------------------------------------------------

def _notice_descriptor(**overrides):
    from dial_warnings import WarningDescriptor
    fields = dict(
        id="notice", kind=KIND_STATUS, priority=200, screen="notice",
        title="Working", message_for=lambda sev: f"step {sev}", severity_for=lambda sev: "info",
        buttons=(),
        title_for=lambda sev: f"Title {sev}", progress_for=lambda sev: sev * 10,
        interrupting=True, auto_clear_after_s=None,
    )
    fields.update(overrides)
    return WarningDescriptor(**fields)


class TestGenericWarningCapabilities:
    @pytest.fixture
    def rig(self):
        clock = _Clock(1_000_000.0)
        started = []

        def build(**overrides):
            notice = _notice_descriptor(**overrides)
            display, fb, gt = make_display(
                targets=[],
                warnings=WarningManager(WARNING_DESCRIPTORS + (notice,), clock=clock.now),
            )
            for p in (
                patch.dict(dd.SCREEN_POLICIES, {notice.screen: dd._status_policy_row(notice)}),
            ):
                p.start()
                started.append(p)
            display.enable()
            display.fold_for_tests()
            _fold(display)
            return display, fb, clock

        yield build
        for p in started:
            p.stop()

    def _painted_view(self, display):
        with patch.object(
            display._compositor, "compose_warning", wraps=display._compositor.compose_warning,
        ) as mock_compose:
            with display._lock:
                display._display_card_locked()
        return mock_compose.call_args.args[3]

    def test_the_nowifi_and_sdhealth_rows_keep_the_default_descriptor_fields(self):
        for desc in (d for d in WARNING_DESCRIPTORS if d.id in ("nowifi", "sdhealth")):
            assert desc.title_for is None and desc.progress_for is None
            assert desc.interrupting is False and desc.auto_clear_after_s is None

    def test_painter_uses_title_for_and_progress_for(self, rig):
        display, fb, clock = rig()
        warning_active(display, "notice", severity=4)
        _fold(display)
        view = self._painted_view(display)
        assert view.title == "Title 4"
        assert view.message == "step 4"
        assert view.percent == 40
        assert view.buttons == ()

    def test_painter_falls_back_to_the_fixed_title_and_no_percent(self, rig):
        display, fb, clock = rig(title_for=None, progress_for=None)
        warning_active(display, "notice", severity=4)
        _fold(display)
        view = self._painted_view(display)
        assert view.title == "Working"
        assert view.percent is None

    def test_a_warning_card_carries_no_percent(self):
        display, fb, gt = make_display(targets=[])
        display.enable()
        display.fold_for_tests()
        on_sd_health_view(display, _sd_view(STATUS_VALID, percent=15))
        open_warnings_page(display)
        view = self._painted_view(display)
        assert view.percent is None and view.title == "microSD card"

    def test_tick_warnings_clears_expired_rows(self, rig):
        display, fb, clock = rig(auto_clear_after_s=60.0)
        warning_active(display, "notice", severity=1)
        _fold(display)
        assert display._screen == "notice"
        clock.t += 59.0
        tick_warnings(display)
        assert display._screen_request is None and display._screen == "notice"
        clock.t += 2.0
        tick_warnings(display)
        assert not display.core.warnings.is_active("notice")
        assert display._screen_request == "main"
        _fold(display)
        assert display._screen == "main" and display._warning_screen is None

    def test_tick_warnings_clear_drops_a_pending_request(self, rig):
        display, fb, clock = rig(auto_clear_after_s=10.0)
        warning_active(display, "notice", severity=1)
        assert display._screen_request == "notice"
        clock.t += 11.0
        tick_warnings(display)
        assert display._screen_request is None

    def test_interrupting_opens_over_a_secondary_screen(self, rig):
        display, fb, clock = rig()
        display._screen_request = "selector"
        _fold(display)
        assert display._screen == "selector"
        warning_active(display, "notice", severity=2)
        assert display._screen_request == "notice"
        _fold(display)
        assert display._screen == "notice"
        assert display._selector is None

    def test_non_interrupting_does_not_open_over_a_secondary_screen(self, rig):
        display, fb, clock = rig(interrupting=False)
        display._screen_request = "selector"
        _fold(display)
        warning_active(display, "notice", severity=2)
        assert display._screen_request is None
        _fold(display)
        assert display._screen == "selector"

    def test_interrupting_wakes_a_sleeping_panel(self, rig):
        display, fb, clock = rig()
        with display._lock:
            display._sleep_locked()
        assert display._display_sleeping
        warning_active(display, "notice", severity=2)
        assert display._screen_request == "notice"
        _fold(display)
        assert not display._display_sleeping
        assert display._screen == "notice"

    def test_non_interrupting_does_not_wake_a_sleeping_panel(self, rig):
        display, fb, clock = rig(interrupting=False)
        with display._lock:
            display._sleep_locked()
        warning_active(display, "notice", severity=2)
        assert display._screen_request is None
        assert display._display_sleeping

    def test_interrupting_refresh_and_tick_do_not_rewake_after_sleep(self, rig):
        display, fb, clock = rig()
        warning_active(display, "notice", severity=2)
        _fold(display)
        with display._lock:
            display._sleep_locked()
        warning_active(display, "notice", severity=3)
        tick_warnings(display)
        assert display._screen_request is None and display._display_sleeping
        display.notify_touch_activity()
        _fold(display)
        assert not display._display_sleeping and display._screen == "notice"

    def test_interrupting_never_opens_over_restarting(self, rig):
        display, fb, clock = rig()
        display._screen_request = "restarting"
        _fold(display)
        assert display._screen == "restarting"
        warning_active(display, "notice", severity=2)
        assert display._screen_request is None
        _fold(display)
        assert display._screen == "restarting"

    def test_interrupting_does_not_request_again_while_showing(self, rig):
        display, fb, clock = rig()
        warning_active(display, "notice", severity=2)
        _fold(display)
        warning_active(display, "notice", severity=3)
        tick_warnings(display)
        assert display._screen_request is None

    def test_higher_priority_page_is_not_replaced_by_a_lower_interrupting_one(self, rig):
        display, fb, clock = rig(priority=10)
        warning_active(display, "update_result")
        _fold(display)
        assert display._screen == "update_result"
        warning_active(display, "notice", severity=2)
        _fold(display)
        assert display._screen == "update_result"

    def test_higher_priority_interrupting_page_replaces_an_open_lower_one(self, rig):
        display, fb, clock = rig()
        warning_active(display, "update_result")
        _fold(display)
        assert display._screen == "update_result"
        warning_active(display, "notice", severity=2)
        _fold(display)
        assert display._screen == "notice"


# ---------------------------------------------------------------------------
# The software update cards: the update-result file mapped onto the "update"
# and "update_result" warning rows.
# ---------------------------------------------------------------------------

class TestUpdateWarnings:
    @pytest.fixture
    def rig(self, tmp_path):
        from dial_update_watch import UpdateWatcher
        clock = _Clock(1_000_000.0)
        display, fb, gt = make_display(
            targets=[],
            warnings=WarningManager(WARNING_DESCRIPTORS, clock=clock.now),
        )
        display.core.update_seen_path = str(tmp_path / "seen")
        display.core.update_watcher = UpdateWatcher(str(tmp_path / "update-result.env"))
        display.enable()
        display.fold_for_tests()
        _fold(display)
        display.result_path = tmp_path / "update-result.env"
        display.seen_path = tmp_path / "seen"
        display.clock = clock
        return display

    @staticmethod
    def _progress(phase="packages", percent=45, **kw):
        from dial_update_watch import UpdateView
        return UpdateView(status="in_progress", percent=percent, phase=phase, tag="0.7.0",
                          previous_tag="0.6.0", message="a long message that must not be shown",
                          last_run_at="2000-01-01T00:00:00+00:00", **kw)

    @staticmethod
    def _finished(status="success", **kw):
        from dial_update_watch import UpdateView
        fields = dict(status=status, percent=100, phase="done", tag="0.7.0", previous_tag="0.6.0",
                      last_run_at="2000-01-01T01:00:00+00:00")
        fields.update(kw)
        return UpdateView(**fields)

    @staticmethod
    def _painted_view(display):
        with patch.object(
            display._compositor, "compose_warning", wraps=display._compositor.compose_warning,
        ) as mock_compose:
            with display._lock:
                display._display_card_locked()
        return mock_compose.call_args.args[3]

    def test_in_progress_view_opens_update_card_over_selector_and_wakes(self, rig):
        display = rig
        display._screen_request = "selector"
        _fold(display)
        assert display._screen == "selector"
        with display._lock:
            display._sleep_locked()
        apply_update_view(display, self._progress())
        _fold(display)
        assert display._screen == "update"
        assert not display._display_sleeping
        assert display._selector is None

    def test_update_card_shows_title_phase_label_and_bar(self, rig):
        display = rig
        apply_update_view(display, self._progress(phase="packages", percent=45))
        _fold(display)
        view = self._painted_view(display)
        assert view.title == dwt.UPDATING_TEXT == "Updating..."
        assert view.message == "Upgrading OS"
        assert view.percent == 45
        assert view.buttons == ()

    def test_phase_label_follows_the_phase_and_never_the_file_message(self, rig):
        display = rig
        for phase, label in (
            ("download", "Downloading"), ("packages", "Upgrading OS"), ("python", "Installing"),
            ("files", "Installing"), ("configure", "Installing"), ("staged", "Restarting"),
            ("something-new", "Please wait"), ("", "Please wait"),
        ):
            apply_update_view(display, self._progress(phase=phase))
            _fold(display)
            assert self._painted_view(display).message == label, phase

    def test_update_card_replaces_an_open_warnings_card(self, rig):
        display = rig
        on_network_view(display, _view(LINK_CONNECTED, bars=3))
        for _ in range(3):
            on_network_view(display, _view(LINK_DOWN))
        open_warnings_page(display)
        assert display._screen == "warnings"
        apply_update_view(display, self._progress())
        _fold(display)
        assert display._screen == "update" and display._warnings_page is None
        # Nothing opens the warnings card back over it while it runs.
        on_network_view(display, _view(LINK_DOWN))
        display.open_warnings()
        _fold(display)
        assert display._screen == "update"

    def test_update_card_has_no_buttons_and_the_inert_surface(self):
        from dial_touch import _GEOMETRY_FOR_SURFACE
        from dial_touch_layout import GEOMETRY_NONE
        desc = WARNING_BY_ID["update"]
        assert desc.buttons == ()
        assert desc.interrupting is True and desc.auto_clear_after_s is None
        assert desc.priority > WARNING_BY_ID["update_result"].priority
        assert _GEOMETRY_FOR_SURFACE[dd.SCREEN_POLICIES["update"].surface[0]] == GEOMETRY_NONE

    def test_reboot_phase_switches_to_restarting_without_requesting_reboot(self, rig):
        display = rig
        apply_update_view(display, self._progress(phase="packages"))
        _fold(display)
        assert display._screen == "update"
        with patch("dial_network.request_reboot") as reboot:
            apply_update_view(display, self._progress(phase="reboot", percent=96))
            _fold(display)
        reboot.assert_not_called()
        assert display._screen == "restarting"
        assert not display.core.warnings.is_active("update")
        # Nothing opens over the restarting screen.
        apply_update_view(display, self._progress(phase="files"))
        _fold(display)
        assert display._screen == "restarting"

    def test_verify_phase_shows_nothing(self, rig):
        display = rig
        apply_update_view(display, self._progress(phase="verify", percent=96))
        assert display._screen_request is None
        _fold(display)
        assert display._screen == "main"
        assert not display.core.warnings.is_active("update")

    def test_success_shows_result_once_then_clears_after_an_hour(self, rig):
        display = rig
        apply_update_view(display, self._progress())
        _fold(display)
        apply_update_view(display, self._finished())
        _fold(display)
        assert display._screen == "update_result"
        assert not display.core.warnings.is_active("update")
        view = self._painted_view(display)
        assert (view.title, view.message, view.buttons) == ("Updated", "Version 0.7.0", ("Close",))
        assert view.percent is None
        display.clock.t += dwt.UPDATE_RESULT_SECONDS - 1
        tick_warnings(display)
        assert display.core.warnings.is_active("update_result")
        display.clock.t += 2
        tick_warnings(display)
        assert not display.core.warnings.is_active("update_result")
        _fold(display)
        assert display._screen == "main"
        # The same result arriving again (a restart re-reading the file) stays quiet.
        apply_update_view(display, self._finished())
        _fold(display)
        assert display._screen == "main"

    def test_result_card_close_ends_the_status(self, rig):
        display = rig
        apply_update_view(display, self._finished())
        _fold(display)
        assert display._screen == "update_result"
        assert display.touch_surface() == ("card1", False, False, False, False)
        tap_card(display, 0)
        _fold(display)
        assert display._screen == "main"
        assert not display.core.warnings.is_active("update_result")
        tick_warnings(display)
        _fold(display)
        assert display._screen == "main"

    def test_failure_rolled_back_message_names_previous_version(self, rig):
        display = rig
        apply_update_view(display, self._finished("failure", rolled_back=True, phase="rolled_back"))
        _fold(display)
        view = self._painted_view(display)
        assert (view.title, view.message) == ("Update failed", "Restored 0.6.0")

    def test_failure_not_rolled_back_message_says_previous_kept(self, rig):
        display = rig
        apply_update_view(display, self._finished("failure", phase="failed"))
        _fold(display)
        view = self._painted_view(display)
        assert (view.title, view.message) == ("Update failed", "0.6.0 kept")

    def test_seen_marker_suppresses_repeat_on_restart(self, rig):
        display = rig
        apply_update_view(display, self._finished())
        assert display.seen_path.read_text().strip() == "2000-01-01T01:00:00+00:00"
        # A new process: same result file, same marker.
        again, fb, gt = make_display(targets=[])
        again.core.update_seen_path = str(display.seen_path)
        again.enable()
        again.fold_for_tests()
        _fold(again)
        apply_update_view(again, self._finished())
        _fold(again)
        assert again._screen == "main" and not again.core.warnings.is_active("update_result")
        # A different (later) result is shown.
        apply_update_view(again, self._finished("failure", last_run_at="2000-01-02T00:00:00+00:00"))
        _fold(again)
        assert again._screen == "update_result"

    def test_fresh_install_with_no_status_shows_nothing(self, rig):
        from dial_update_watch import UpdateView
        display = rig
        apply_update_view(display, UpdateView())
        _fold(display)
        assert display._screen == "main"
        assert not display.seen_path.exists()

    def test_tick_reads_the_file_once_per_change(self, rig):
        display = rig
        display.result_path.write_text(
            "STATUS=in_progress\nPERCENT_COMPLETE=30\nMESSAGE=x\nLAST_RUN_AT=t1\nPHASE=files\n",
        )
        tick_update_watch(display)
        _fold(display)
        assert display._screen == "update"
        assert display.core.warnings.reading("update").percent == 30
        display._screen_request = "main"
        _fold(display)
        tick_update_watch(display)
        assert display._screen_request is None

    def test_result_card_replaces_open_progress_card(self, rig):
        display = rig
        apply_update_view(display, self._progress())
        _fold(display)
        assert display._screen == "update"
        apply_update_view(display, self._finished())
        _fold(display)
        assert display._screen == "update_result"
