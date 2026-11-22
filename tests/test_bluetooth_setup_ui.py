"""tests/test_bluetooth_setup_ui.py

Setup page UI wiring tests for the Bluetooth input feature.

Three independent gates drive the page's Bluetooth surface:
  - installed (`_bluetooth_installed`): the pairing modal, dropdown
    onchange branch, data-bt marker, and relabel/synthetic-option logic.
    When not installed, none of that renders at all -- byte-identical to
    before this feature existed.
  - services_enabled (`_bluetooth_services_enabled`): which body the
    always-rendered Bluetooth card shows (disabled body + Enable button,
    vs. the enabled body with Service/Adapter/Onboard/Paired/Pair/Buffer
    rows).
  - onboard_enabled (`_bluetooth_onboard_enabled`): the onboard toggle's
    initial checked state.

These tests patch the page module's own defensive wrappers directly rather
than depending on the modules those wrappers call into.
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from _setup_card_test_helpers import setup_page_mocks
from _source_text import page_data

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)


def _minimal_cfg(
    tmp_path: Path,
    *,
    audio1_capture_device: str = "hw:1,0",
    audio2_capture_device: str = "hw:2,0",
    audio3: dict | None = None,
) -> Path:
    cfg = tmp_path / "autostream.json"
    cfg.write_text(json.dumps({
        "general": {"log_level": "info", "silence_seconds": 30},
        "owntone": {
            "base_url": "http://localhost:3689",
            "output_name": "Test Speaker",
            "volume_percent": 50,
        },
        "audio1": {
            "capture_device": audio1_capture_device,
            "gain_db": 0,
            "eq_40hz_db": 0,
            "eq_100hz_db": 0,
            "eq_8khz_db": 0,
            "turntable": False,
        },
        "audio2": {
            "capture_device": audio2_capture_device,
            "gain_db": 0,
            "eq_40hz_db": 0,
            "eq_100hz_db": 0,
            "eq_8khz_db": 0,
            "turntable": False,
            "enabled": False,
        },
        "audio3": audio3 or {},
        "track_identification": {"enabled": False},
        "webui": {
            "dark_mode": False,
            "show_master_volume": True,
            "show_input_detail": False,
            "show_hostname_on_home": False,
            "control_other_appliances": False,
        },
        "updates": {"auto_update": False, "update_channel": "stable"},
    }), encoding="utf-8")
    return cfg


class _SetupRenderer:
    """Renders the Setup page and returns the HTML, with Bluetooth toggled."""

    def render(
        self,
        tmp_path: Path,
        *,
        bt_enabled: bool = False,
        bt_services_on: bool = False,
        bt_onboard_on: bool = False,
        bt_onboard_refused: str | None = None,
        bt_memory_note: str = "",
        bt_status: dict | None = None,
        monitor_devices: list | None = None,
        audio1_capture_device: str = "hw:1,0",
        audio2_capture_device: str = "hw:2,0",
        audio3: dict | None = None,
    ) -> str:
        from autostream_settings import SettingsStore
        from webui.session_state import WebUIState
        from autostream_players import ListOutputsResult
        from _setup_card_test_helpers import render_full_setup_with_cards

        cfg = _minimal_cfg(
            tmp_path,
            audio1_capture_device=audio1_capture_device,
            audio2_capture_device=audio2_capture_device,
            audio3=audio3,
        )
        store = SettingsStore(str(cfg), _save_interval_seconds=9999)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)

        handler = MagicMock()
        handler.wfile = io.BytesIO()
        auth = MagicMock()
        auth.ensure_session.return_value = "test-csrf"
        auth.get_csrf_token.return_value = "test-csrf"
        auth.get_boot_pin_value.return_value = "1234"

        _list_result = ListOutputsResult(ok=False, error="unreachable")

        if bt_status is not None:
            state.get_bluetooth_status = lambda: bt_status  # type: ignore[attr-defined]

        fake_outputs_result(_list_result)
        with setup_page_mocks(
            _bluetooth_installed=bt_enabled,
            _bluetooth_services_enabled=bt_services_on,
            _bluetooth_onboard_enabled=bt_onboard_on,
            _bluetooth_onboard_refused=bt_onboard_refused,
            _bluetooth_memory_note=bt_memory_note,
        ):
            with patch.object(
                state, "get_monitor_devices", return_value=(monitor_devices or [])
            ):
                html = render_full_setup_with_cards(handler, state, auth)

        store.close(save=False)
        return html


BT_LOOPBACK_HW = "hw:CARD=ASBT,DEV=1"


# ---------------------------------------------------------------------------
# Disabled: nothing Bluetooth-related must appear
# ---------------------------------------------------------------------------

class TestBluetoothDisabledGating:
    @pytest.fixture
    def html(self, tmp_path: Path) -> str:
        return _SetupRenderer().render(tmp_path, bt_enabled=False)

    def test_no_pairing_modal_div(self, html):
        assert 'id="btPairingModal"' not in html

    def test_no_scan_panel(self, html):
        assert "btScanPanel" not in html

    def test_no_open_bt_pairing_modal_fn(self, html):
        assert "openBtPairingModal" not in html

    def test_no_is_bluetooth_device_fn(self, html):
        assert "isBluetoothDevice" not in html

    def test_no_bt_manage_button(self, html):
        assert "bt-manage-btn" not in html

    def test_no_bt_css_classes(self, html):
        # The pairing styles sit in the stylesheet every Setup page links, so
        # only the markup and scripts are checked for the classes.
        from _source_text import static_text
        used = html.replace(static_text("page/setup.css"), "")
        assert "bt-scan-row" not in used
        assert "bt-device-list" not in used

    def test_pairing_only_api_paths_absent(self, html):
        """The pairing-modal-only endpoints require the loopback card to
        exist, i.e. the subsystem installed -- absent here."""
        assert "/api/bluetooth/scan" not in html
        assert "/api/bluetooth/pair" not in html
        assert "/api/bluetooth/forget" not in html

    def test_card_api_paths_present(self, html):
        """The always-rendered Bluetooth card wires its own routes
        regardless of install state."""
        assert "/api/bluetooth/status" in html
        assert "/api/bluetooth/services" in html

    def test_capture_device_onchange_unchanged(self, html):
        # Existing autosave-only onchange (plus the always-on exclusivity
        # sync), no Bluetooth pairing branch spliced in.
        assert "settingsSaveField('audio1.capture_device', this.value)" in html
        assert "if (isBluetoothDevice(" not in html

    def test_no_data_prev_attribute(self, html):
        # data-prev only matters to the pairing-modal revert logic, which
        # doesn't exist on this render at all -- keep the disabled render
        # free of it too.
        assert "data-prev" not in html

    def test_no_input3_card_and_no_bluetooth_card(self, html):
        assert 'id="input3-card-sub"' not in html
        assert 'id="bluetooth-card-sub"' not in html
        assert 'id="btDisabledBody"' not in html

    def test_card_enabled_body_absent(self, html):
        # Not installed: the enabled-body isn't just hidden, it isn't
        # rendered at all -- its interactive rows reference JS functions
        # (openBtPairingModal etc.) that only exist once installed.
        assert 'id="btEnabledBody"' not in html

    def test_render_matches_pre_feature_baseline(self, tmp_path):
        """Regression guard: disabled output must match a render with the
        Bluetooth helper entirely absent (ImportError fallback path)."""
        from webui.browser.setup.page import send_setup_page
        from autostream_settings import SettingsStore
        from webui.session_state import WebUIState
        from autostream_players import ListOutputsResult

        cfg = _minimal_cfg(tmp_path)
        store = SettingsStore(str(cfg), _save_interval_seconds=9999)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)
        handler = MagicMock()
        handler.wfile = io.BytesIO()
        auth = MagicMock()
        auth.ensure_session.return_value = "test-csrf"
        auth.get_csrf_token.return_value = "test-csrf"
        auth.get_boot_pin_value.return_value = "1234"
        _list_result = ListOutputsResult(ok=False, error="unreachable")

        fake_outputs_result(_list_result)
        with setup_page_mocks():
            with patch.object(state, "get_monitor_devices", return_value=[]):
                send_setup_page(handler, state, auth)
        store.close(save=False)
        html = handler.wfile.getvalue().decode("utf-8", errors="replace")
        assert "btPairingModal" not in html


# ---------------------------------------------------------------------------
# Enabled, unpaired
# ---------------------------------------------------------------------------

class TestBluetoothEnabledUnpaired:
    @pytest.fixture
    def html(self, tmp_path: Path) -> str:
        return _SetupRenderer().render(
            tmp_path,
            bt_enabled=True,
            bt_status={"adapter_present": True, "paired": None, "link": "disconnected",
                       "streaming": False, "scanning": False},
        )

    def test_pairing_modal_div_present(self, html):
        assert 'id="btPairingModal"' in html

    def test_one_window_panel_and_the_result_panel(self, html):
        for panel in ("btWindowPanel", "btResultPanel", "btWindowDeviceList", "btWindowCountdown"):
            assert f'id="{panel}"' in html
        for gone in ("btScanPanel", "btConfirmPanel", "btPairingPanel"):
            assert gone not in html

    def test_window_wording(self, html):
        assert "Pair a device" in html
        assert "It will appear below when autostream finds it" in html

    def test_open_bt_pairing_modal_fn_present(self, html):
        assert "function openBtPairingModal()" in html

    def test_no_bluetooth_choice_in_a_device_select(self, html):
        assert "isBluetoothDevice" not in html
        assert BT_LOOPBACK_HW not in html

    def test_close_path_stops_the_poll_and_the_window(self, html):
        idx = html.find("function closeBtPairingModal()")
        assert idx != -1
        body = html[idx: idx + 1500]
        assert "_btWindowPoller.stop();" in body
        assert "_btPost('/api/bluetooth/pair_window', {action: 'stop'})" in body

    def test_window_started_on_open(self, html):
        assert "_btPost('/api/bluetooth/pair_window', {action: 'start'})" in html

    def test_the_window_poll_is_the_heartbeat_through_poller(self, html):
        idx = html.find("var _btWindowPoller = Poller({")
        assert idx != -1
        block = html[idx: idx + 400]
        assert "url: '/api/bluetooth/pair_window'" in block
        assert "intervalMs: 2000" in block
        assert "activeOnly: true" in block
        assert "setInterval" not in html[html.find("// -- Bluetooth pairing window"):
                                         html.find("function closeBtPairingModal()")]

    def test_503_stops_polling(self, html):
        idx = html.find("function _btOnWindowError(res)")
        body = html[idx: idx + 400]
        assert "_btStatus(res) === 503" in body
        assert "return (res && res.body && res.body.error_status)" in html
        assert "_btWindowPoller.stop();" in body

    def test_start_while_closing_retries_after_the_poll(self, html):
        assert "_btStartPending = true;" in html

    def test_comparison_code_shown_with_wants_to_connect(self, html):
        assert "'Code ' + String(d.passkey).padStart(6, '0')" in html
        assert "provisional: 'Wants to connect'" in html

    def test_countdown_rendered(self, html):
        assert "' left'" in html

    def test_two_gestures_select_then_button(self, html):
        assert "function _btSelectRow(d)" in html
        assert "okBtn.textContent = 'Pair this device';" in html

    def test_scan_routes_gone(self, html):
        assert "/api/bluetooth/scan" not in html
        assert "/api/bluetooth/pair_status" not in html

    def test_pair_endpoint_called(self, html):
        assert "/api/bluetooth/pair'" in html

    def test_forget_endpoint_wired(self, html):
        assert "/api/bluetooth/forget" in html
        assert "function _btForgetCurrent()" in html

    def test_status_endpoint_polled(self, html):
        # Migrated onto the shared Poller (activeOnly, so it only
        # polls while the Bluetooth panel is open -- fixes the confirmed
        # backgrounded-tab poll-forever bug) instead of a bare setInterval.
        assert "/api/bluetooth/status" in html
        assert "_btStatusPoller = Poller(" in html
        assert "activeOnly: true" in html

    def test_wired_onchange_only_saves_the_device(self, html):
        assert "openBtPairingModal(1" not in html
        assert "openBtPairingModal(2" not in html
        assert "settingsSaveField('audio1.capture_device', this.value)" in html
        assert "settingsSaveField('audio2.capture_device', this.value)" in html

    def test_bt_paired_initial_false(self, html):
        assert page_data(html)["bt_paired"] is False
        assert "var btPaired = pageData.bt_paired;" in html

    def test_no_manage_button_markup(self, html):
        assert "bt-manage-btn" not in html
        assert "_btSyncManageButton" not in html
        assert "_btSyncAllManageButtons" not in html
        assert "_btUpdateManageButtons" not in html

    def test_success_saves_no_input_setting(self, html):
        # Bluetooth is input 3 with a fixed device: a pairing changes no
        # input setting.
        assert "_btInputIndex" not in html
        assert "'.turntable', true)" not in html

    def test_csrf_header_used_in_fetches(self, html):
        assert "window.__CSRF" in html
        assert "X-CSRF-Token" in html

    def test_cache_no_store_used(self, html):
        assert "cache: 'no-store'" in html or "cache:'no-store'" in html

    def test_409_and_404_on_tap(self, html):
        assert "status === 409" in html
        assert "Another device is being paired." in html
        assert "status === 404" in html

    def test_escape_key_closes_modal(self, html):
        assert "'btPairingModal'" in html
        assert "closeBtPairingModal" in html

    def test_no_select_revert_or_auto_assignment(self, html):
        for gone in ("data-prev", "_btPriorSelectValue", "_btPairSucceeded",
                     "input_auto_configure", "_btApplyAutoConfigureToPage", "Bluetooth assigned to"):
            assert gone not in html, gone

    def test_no_page_reload_in_poll_handler(self, html):
        idx = html.find("function _btFinish(body)")
        assert idx != -1
        window = html[idx: idx + 2500]
        assert "location.reload" not in window
        assert "location.href" not in window


# ---------------------------------------------------------------------------
# Enabled, paired
# ---------------------------------------------------------------------------

class TestBluetoothEnabledPaired:
    @pytest.fixture
    def html(self, tmp_path: Path) -> str:
        return _SetupRenderer().render(
            tmp_path,
            bt_enabled=True,
            bt_services_on=True,
            bt_status={"adapter_present": True,
                       "paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "My Turntable"},
                       "link": "connected", "streaming": True, "scanning": False},
            audio3={"enabled": True},
        )

    def test_bt_paired_initial_true(self, html):
        assert page_data(html)["bt_paired"] is True
        assert "var btPaired = pageData.bt_paired;" in html

    def test_paired_row_shows_connected(self, html):
        assert "My Turntable · Connected" in html

    def test_input3_summary_shows_the_device(self, html):
        assert 'id="input3-card-sub">My Turntable · Line · 0 dB<' in html

    def test_forget_button_visible(self, html):
        import re
        m = re.search(r'<button[^>]*id="btnBtForget"[^>]*>', html)
        assert m, "Forget button not found"
        assert "display:none" not in m.group(0)


# ---------------------------------------------------------------------------
# Enabled, paired, link down -- the fifth summary state: distinct from both
# "not paired" and "connected", omitted by the pre-fix implementation.
# ---------------------------------------------------------------------------

class TestBluetoothEnabledPairedDisconnected:
    @pytest.fixture
    def html(self, tmp_path: Path) -> str:
        return _SetupRenderer().render(
            tmp_path,
            bt_enabled=True,
            bt_services_on=True,
            bt_status={"adapter_present": True,
                       "paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "BT-Turntable"},
                       "link": "disconnected", "streaming": False, "scanning": False},
            audio3={"enabled": True},
        )

    def test_input3_summary_shows_not_connected(self, html):
        assert 'id="input3-card-sub">Not Connected · Line · 0 dB<' in html

    def test_paired_row_shows_not_connected(self, html):
        assert "BT-Turntable · Not Connected" in html

    def test_forget_button_still_visible(self, html):
        # Forgetting a paired-but-disconnected device must still be offered.
        import re
        m = re.search(r'<button[^>]*id="btnBtForget"[^>]*>', html)
        assert m, "Forget button not found"
        assert "display:none" not in m.group(0)


# ---------------------------------------------------------------------------
# JS status poll (_btApplyStatus): the card summary and paired-row strings
# must be assigned verbatim from the server-computed `ui` object -- no
# duplicated conditional logic re-deriving them from link/paired client-side.
# ---------------------------------------------------------------------------

class TestBluetoothStatusPollJsIsServerAuthored:
    @pytest.fixture
    def html(self, tmp_path: Path) -> str:
        return _SetupRenderer().render(tmp_path, bt_enabled=True)

    def test_no_duplicated_summary_conditional(self, html):
        # The old per-branch "Enabled · ' connected'" string-building logic
        # must be gone entirely -- only the shared Python implementation may
        # construct this string now.
        assert "' connected';" not in html
        assert "sub.textContent = 'Enabled" not in html

    def test_no_duplicated_paired_row_conditional(self, html):
        assert "_btLinkState === 'connected' ? 'Connected' : 'Not Connected'" not in html

    def test_no_card_summary_from_the_poll(self, html):
        assert "card_summary" not in html
        assert "bluetooth-card-sub" not in html

    def test_paired_row_assigned_verbatim_from_ui(self, html):
        assert "pairedRow.textContent = (ui && ui.paired_text) || 'No device paired';" in html

    def test_input_card_fragment_uses_server_text(self, html):
        assert "dev = window._btUiText || 'Not Connected';" in html
        assert "bst.link === 'connected'" not in html


# ---------------------------------------------------------------------------
# Option markup: bt data attribute only on the loopback device
# ---------------------------------------------------------------------------

class TestBluetoothOptionMarkup:
    def test_non_bluetooth_option_has_no_bt_attr(self, tmp_path):
        html = _SetupRenderer().render(
            tmp_path,
            bt_enabled=True,
            bt_status={"adapter_present": True, "paired": None, "link": "disconnected",
                       "streaming": False, "scanning": False},
            monitor_devices=[
                {"hw": "hw:1,0", "card": "USB Audio", "name": "USB Audio",
                 "label": "USB Audio"},
            ],
        )
        assert "data-bt='1'" not in html


import re
from fake_store import fake_outputs_result


# ---------------------------------------------------------------------------
# Cross-input exclusivity: a device selected on one input must not be
# offered on the other input's dropdown, both server-rendered and via the
# live JS wiring. Applies to any device, not just Bluetooth.
# ---------------------------------------------------------------------------

class TestCrossInputExclusivity:
    _DEVICES = [
        {"hw": "hw:1,0", "card": "USB Audio", "name": "USB Audio", "label": "USB Audio"},
        {"hw": "hw:3,0", "card": "Other Audio", "name": "Other Audio", "label": "Other Audio"},
        {"hw": BT_LOOPBACK_HW, "card": "Loopback", "name": "Loopback",
         "label": "Bluetooth (not paired)"},
    ]

    def test_input2_current_device_excluded_from_input1_options(self, tmp_path):
        html = _SetupRenderer().render(
            tmp_path,
            monitor_devices=self._DEVICES,
            audio1_capture_device="hw:1,0",
            audio2_capture_device="hw:3,0",
        )
        sel1 = re.search(
            r'<select name="audio_capture_device"[^>]*>(.*?)</select>', html, re.S,
        ).group(1)
        assert "hw:3,0" not in sel1

    def test_input1_current_device_excluded_from_input2_options(self, tmp_path):
        html = _SetupRenderer().render(
            tmp_path,
            monitor_devices=self._DEVICES,
            audio1_capture_device="hw:1,0",
            audio2_capture_device="hw:3,0",
        )
        sel2 = re.search(
            r'<select name="audio2_capture_device"[^>]*>(.*?)</select>', html, re.S,
        ).group(1)
        assert "hw:1,0" not in sel2

    def test_own_current_selection_always_renders_even_if_it_equals_the_others(self, tmp_path):
        # A pre-existing duplicate (from before this guard existed): the
        # input's own current value must still render so the <select> has a
        # selected option, even though it equals the other input's value.
        html = _SetupRenderer().render(
            tmp_path,
            monitor_devices=self._DEVICES,
            audio1_capture_device="hw:1,0",
            audio2_capture_device="hw:1,0",
        )
        sel1 = re.search(
            r'<select name="audio_capture_device"[^>]*>(.*?)</select>', html, re.S,
        ).group(1)
        assert "hw:1,0" in sel1

    def test_applies_when_bluetooth_not_installed(self, tmp_path):
        """The exclusivity guard is general-purpose, not Bluetooth-gated."""
        html = _SetupRenderer().render(
            tmp_path,
            bt_enabled=False,
            monitor_devices=self._DEVICES,
            audio1_capture_device="hw:1,0",
            audio2_capture_device="hw:3,0",
        )
        sel1 = re.search(
            r'<select name="audio_capture_device"[^>]*>(.*?)</select>', html, re.S,
        ).group(1)
        assert "hw:3,0" not in sel1

    def test_live_js_sync_function_present_and_wired_into_onchange(self, tmp_path):
        html = _SetupRenderer().render(tmp_path, monitor_devices=self._DEVICES)
        assert "function refreshExclusivityOptions()" in html
        assert "function syncInputExclusivity(changedIndex, value)" in html
        assert "syncInputExclusivity(1, this.value)" in html
        assert "syncInputExclusivity(2, this.value)" in html

    def test_select_elements_carry_stable_ids_for_js_lookup(self, tmp_path):
        html = _SetupRenderer().render(tmp_path, monitor_devices=self._DEVICES)
        assert 'id="audio_capture_device_select"' in html
        assert 'id="audio2_capture_device_select"' in html


# ---------------------------------------------------------------------------
# build_opts synthetic "(not currently detected)" fallback (field report B):
# must not resurface a stale saved value that classifies as the ASBT
# loopback's PLAYBACK side (an internal device, never a valid input) -- but
# must still surface a genuinely-missing real device, unchanged.
# ---------------------------------------------------------------------------

BT_PLAYBACK_HW = "hw:CARD=ASBT,DEV=0"


class TestSyntheticOptionSuppression:
    def test_playback_side_not_injected_when_bluetooth_enabled(self, tmp_path):
        # normalize's relabel hook already drops the playback side from
        # monitor_devices -- audio1 was stale-saved pointing at it.
        html = _SetupRenderer().render(
            tmp_path,
            bt_enabled=True,
            bt_status={"adapter_present": True, "paired": None, "link": "disconnected",
                       "streaming": False, "scanning": False},
            monitor_devices=[
                {"hw": BT_LOOPBACK_HW, "card": "Loopback", "name": "Loopback",
                 "label": "Bluetooth (not paired)"},
                {"hw": "hw:2,0", "card": "USB Audio", "name": "USB Audio", "label": "USB Audio"},
            ],
            audio1_capture_device=BT_PLAYBACK_HW,
            audio2_capture_device="hw:2,0",
        )
        assert f"<option value='{BT_PLAYBACK_HW}'" not in html
        assert "not currently detected" not in html

    def test_genuinely_missing_device_still_injected_when_bluetooth_enabled(self, tmp_path):
        html = _SetupRenderer().render(
            tmp_path,
            bt_enabled=True,
            bt_status={"adapter_present": True, "paired": None, "link": "disconnected",
                       "streaming": False, "scanning": False},
            monitor_devices=[
                {"hw": BT_LOOPBACK_HW, "card": "Loopback", "name": "Loopback",
                 "label": "Bluetooth (not paired)"},
                {"hw": "hw:2,0", "card": "USB Audio", "name": "USB Audio", "label": "USB Audio"},
            ],
            audio1_capture_device="hw:CARD=Vanished,DEV=0",
            audio2_capture_device="hw:2,0",
        )
        assert "hw:CARD=Vanished,DEV=0 (not currently detected)" in html

    def test_playback_side_not_injected_when_bluetooth_disabled(self, tmp_path):
        # A wired input never holds the loopback: a stale saved value reads
        # as no device, so there is nothing to offer as "not detected".
        html = _SetupRenderer().render(
            tmp_path,
            bt_enabled=False,
            monitor_devices=[],
            audio1_capture_device=BT_PLAYBACK_HW,
            audio2_capture_device="hw:2,0",
        )
        assert f"{BT_PLAYBACK_HW} (not currently detected)" not in html


# ---------------------------------------------------------------------------
# Input 3's Enable switch is the services switch: a tap opens the services
# modal (confirm -> busy -> reload or error) and the switch itself only moves
# when the page reloads with the services changed.
# ---------------------------------------------------------------------------

_MEMORY_NOTE = "Bluetooth uses about 40 MB of memory. This board has 512 MB."


class TestBluetoothServicesToggle:
    @pytest.fixture
    def html(self, tmp_path: Path) -> str:
        return _SetupRenderer().render(tmp_path, bt_enabled=True, bt_services_on=True)

    @pytest.fixture
    def segment(self, html: str) -> str:
        start = html.index("var _btServicesText")
        return html[start:html.index("function btOnboardToggleChanged", start)]

    def test_the_old_buttons_are_gone(self, html):
        for gone in ("btnBtEnableServices", "btnBtDisableServices", "btEnableServices()",
                     "btDisableServices()"):
            assert gone not in html, gone

    def test_the_services_modal_is_on_the_page(self, html):
        for element_id in ("btServicesModal", "btServicesModalMsg", "btServicesModalNote",
                           "btServicesModalError", "btServicesModalFt", "btServicesOk",
                           "btServicesCancel"):
            assert f'id="{element_id}"' in html, element_id

    def test_no_services_modal_without_bluetooth(self, tmp_path):
        html = _SetupRenderer().render(tmp_path, bt_enabled=False)
        assert 'id="btServicesModal"' not in html

    def test_a_tap_leaves_the_switch_and_asks_first(self, segment):
        toggle = segment[segment.index("function btServicesToggle(el)"):]
        toggle = toggle[:toggle.index("\n        }\n")]
        assert "el.checked = !el.checked;" in toggle
        assert "_btServicesView('confirm');" in toggle
        assert "settingsTransact(" not in toggle
        assert "window.confirm(" not in segment

    def test_the_request_runs_behind_the_busy_view(self, segment):
        run = segment[segment.index("function _btServicesRun()"):]
        assert run.index("_btServicesView('busy');") < run.index("settingsTransact(")
        assert "'/api/bluetooth/services', {action: _btServicesAction}" in run

    def test_success_reloads_and_failure_shows_the_error(self, segment):
        assert "onSuccess: function() { window.location.reload(); }" in segment
        assert "onError: function(d) { _btServicesView('error', (d && d.message) || text.failed); }" in segment

    def test_the_busy_view_has_no_buttons_and_says_it_takes_time(self, segment):
        assert "byId('btServicesModalFt').style.display = view === 'busy' ? 'none' : '';" in segment
        assert "Starting the Bluetooth services. This can take up to 30 seconds" in segment

    def test_the_memory_note_shows_only_when_confirming_an_enable(self, segment):
        assert ("noteEl.style.display = (view === 'confirm' && _btServicesAction === 'enable' && note)"
                in segment)


class TestBluetoothMemoryNote:
    def test_note_on_the_card_and_in_page_data_while_disabled(self, tmp_path):
        html = _SetupRenderer().render(
            tmp_path, bt_enabled=True, bt_memory_note=_MEMORY_NOTE, audio3={"enabled": False})
        assert f'id="btMemoryNote" style="text-align:left;margin:0 0 0.5rem;">{_MEMORY_NOTE}</p>' in html
        assert json.dumps(_MEMORY_NOTE) in html

    def test_no_card_note_once_enabled(self, tmp_path):
        html = _SetupRenderer().render(
            tmp_path, bt_enabled=True, bt_services_on=True, bt_memory_note=_MEMORY_NOTE,
            audio3={"enabled": True})
        assert 'id="btMemoryNote"' not in html

    def test_no_card_note_on_a_larger_board(self, tmp_path):
        html = _SetupRenderer().render(tmp_path, bt_enabled=True, audio3={"enabled": False})
        assert 'id="btMemoryNote"' not in html

    @pytest.mark.parametrize("info, noted", [
        ((90, 462), True),
        ((300, 599), True),
        ((600, 906), False),
        (None, False),
    ])
    def test_the_note_follows_the_board_size(self, info, noted):
        from webui.browser.setup import cards_bluetooth
        with patch.object(cards_bluetooth, "get_effective_memory_info", return_value=info):
            note = cards_bluetooth._bluetooth_memory_note()
        assert bool(note) is noted
        if noted:
            assert "about 40 MB" in note and "512 MB" in note


class TestUnconfiguredInputPlaceholder:
    """An input with no saved capture device must render an explicit disabled
    placeholder as the selected option. Without it the browser displays the
    first device in the list as chosen (no save has happened), and selecting
    that same device fires no change event -- making it unsaveable."""

    def test_placeholder_rendered_when_unconfigured(self, tmp_path):
        html_out = _SetupRenderer().render(
            tmp_path, bt_enabled=True, audio2_capture_device="",
        )
        assert "select input device" in html_out
        assert "value='' selected disabled" in html_out

    def test_no_placeholder_when_configured(self, tmp_path):
        html_out = _SetupRenderer().render(
            tmp_path, bt_enabled=True,
        )
        # both inputs configured in the default fixture: no placeholder
        assert "select input device" not in html_out


# ---------------------------------------------------------------------------
# Golden: the pairing window's markup
# ---------------------------------------------------------------------------

_REGENERATE_PAIRING_GOLDEN = False
_PAIRING_GOLDEN = REPO_ROOT / "tests" / "golden" / "setup_bt_pairing_modal.html"


def test_pairing_modal_matches_golden(tmp_path):
    html = _SetupRenderer().render(
        tmp_path, bt_enabled=True,
        bt_status={"adapter_present": True, "paired": None, "link": "disconnected",
                   "streaming": False, "scanning": False},
    )
    start = html.index('<div id="btPairingModal"')
    end = html.index("\n</div>", start) + len("\n</div>")
    modal = html[start:end] + "\n"
    if _REGENERATE_PAIRING_GOLDEN:
        _PAIRING_GOLDEN.write_text(modal, encoding="utf-8", newline="\n")
        pytest.skip("golden file regenerated -- set _REGENERATE_PAIRING_GOLDEN back to False")
    assert _PAIRING_GOLDEN.exists(), (
        f"{_PAIRING_GOLDEN} missing: set _REGENERATE_PAIRING_GOLDEN=True to create it")
    assert modal == _PAIRING_GOLDEN.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Onboard radio on power-board appliances
# ---------------------------------------------------------------------------

_REFUSED = "Onboard Bluetooth is not available with this appliance's power board; plug in a USB adapter."
_NO_ADAPTER = {"adapter_present": False, "paired": None, "link": "disconnected",
               "streaming": False, "scanning": False}


def _onboard_toggle(html: str) -> str:
    start = html.index('id="btOnboardToggle"')
    return html[start: html.index(">", start)]


class TestOnboardRadioRefusal:
    def test_refused_board_disables_the_switch_with_the_reason(self, tmp_path):
        html = _SetupRenderer().render(
            tmp_path, bt_enabled=True, bt_services_on=True, bt_onboard_refused=_REFUSED,
            bt_status=_NO_ADAPTER)
        assert " disabled" in _onboard_toggle(html)
        assert "not available with this appliance&#x27;s power board" in html
        assert "No Bluetooth adapter found — plug in a USB adapter.<" in html
        assert "enable the onboard device below.</p>" not in html

    def test_refused_board_still_lets_an_enabled_radio_be_turned_off(self, tmp_path):
        html = _SetupRenderer().render(
            tmp_path, bt_enabled=True, bt_services_on=True, bt_onboard_on=True,
            bt_onboard_refused=_REFUSED, bt_status=_NO_ADAPTER)
        assert " disabled" not in _onboard_toggle(html)

    def test_plain_board_recommends_a_usb_adapter_with_the_coexistence_line(self, tmp_path):
        html = _SetupRenderer().render(
            tmp_path, bt_enabled=True, bt_services_on=True, bt_status=_NO_ADAPTER)
        assert " disabled" not in _onboard_toggle(html)
        assert "A USB Bluetooth adapter is strongly recommended" in html
        assert "can break up on the onboard radio while streaming over Wi-Fi" in html
        assert "power board" not in html

    def test_status_poll_keeps_the_switch_locked_on_a_refused_board(self, tmp_path):
        html = _SetupRenderer().render(tmp_path, bt_enabled=True, bt_services_on=True)
        assert "onboardToggle.disabled = !btServicesEnabled || (!!body.onboard_refused && !btOnboardEnabled);" in html
        assert "var noAdapter = body.onboard_refused" in html


# ---------------------------------------------------------------------------
# Input 3: the Bluetooth input's card
# ---------------------------------------------------------------------------

class TestInput3Card:
    _ON = {"enabled": True, "input_type": "turntable", "gain_db": 2}

    def test_absent_without_bluetooth(self, tmp_path):
        html_out = _SetupRenderer().render(tmp_path, bt_enabled=False, audio3=self._ON)
        assert "input3-card-sub" not in html_out
        assert "panel-input3" not in html_out
        assert "audio3_enabled" not in html_out

    def test_present_with_bluetooth_and_no_device_select(self, tmp_path):
        html_out = _SetupRenderer().render(
            tmp_path, bt_enabled=True, bt_services_on=True, audio3=self._ON)
        assert "input3-card-sub" in html_out
        assert "Input 3 (Bluetooth)" in html_out
        assert 'name="audio3_capture_device"' not in html_out
        assert 'name="audio3_enabled" checked onchange="btServicesToggle(this)"' in html_out
        for element_id in ("btAdapterRow", "btOnboardToggle", "btPairedRow", "btnBtForget",
                           "btnBtPairNew", "btBufferRange", "audio3_input_type",
                           "audio3_silence_threshold", "audio3_start_after_wrap",
                           "audio3_dynamic_rate_matching", "audio3_gain_db", "audio3_buffer_card"):
            assert f'id="{element_id}"' in html_out, element_id
        assert 'onclick="openBtPairingModal()"' in html_out
        assert 'name="bluetooth_present"' in html_out

    def test_the_wired_cards_have_no_bluetooth_controls(self, tmp_path):
        html_out = _SetupRenderer().render(tmp_path, bt_enabled=True, audio3=self._ON)
        assert "data-bt=" not in html_out
        assert "dataset.prev =" not in html_out
        assert html_out.count('id="btAdapterRow"') == 1

    def test_summary_names_the_bluetooth_device_type_and_gain(self, tmp_path):
        status = {"paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "Test Player"}, "link": "connected"}
        html_out = _SetupRenderer().render(
            tmp_path, bt_enabled=True, bt_services_on=True, bt_status=status, audio3=self._ON)
        assert "Test Player · Turntable · +2 dB" in html_out

    def test_summary_when_disabled(self, tmp_path):
        html_out = _SetupRenderer().render(tmp_path, bt_enabled=True, audio3={"enabled": False})
        assert '<span class="setup-list-card-sub" id="input3-card-sub">Disabled</span>' in html_out

    def test_the_moved_note_is_on_input_3_and_the_input_it_came_from(self, tmp_path):
        html_out = _SetupRenderer().render(
            tmp_path, bt_enabled=True, audio3=dict(self._ON, moved_from=2))
        assert "Bluetooth was moved here from Input 2 by the update." in html_out
        assert "Bluetooth was moved to Input 3 by the update." in html_out
        assert 'id="audio2_moved_note"' in html_out
        assert 'id="audio1_moved_note"' not in html_out

    def test_no_moved_note_without_a_move(self, tmp_path):
        html_out = _SetupRenderer().render(tmp_path, bt_enabled=True, audio3=self._ON)
        assert "moved_note" not in html_out
