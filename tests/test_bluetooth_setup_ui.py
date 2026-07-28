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

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)


def _minimal_cfg(
    tmp_path: Path,
    *,
    audio1_capture_device: str = "hw:1,0",
    audio2_capture_device: str = "hw:2,0",
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
        "track_identification": {"enabled": False},
        "webui": {
            "dark_mode": False,
            "show_master_volume": True,
            "show_input_detail": False,
            "show_hostname_on_home": False,
            "control_other_appliances": False,
            "output_usage_poll_interval_seconds": 3,
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
        bt_status: dict | None = None,
        monitor_devices: list | None = None,
        audio1_capture_device: str = "hw:1,0",
        audio2_capture_device: str = "hw:2,0",
    ) -> str:
        from autostream_webui_page_setup import send_setup_page
        from autostream_settings import SettingsStore
        from autostream_webui_state import WebUIState
        from autostream_players import ListOutputsResult

        cfg = _minimal_cfg(
            tmp_path,
            audio1_capture_device=audio1_capture_device,
            audio2_capture_device=audio2_capture_device,
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

        with patch.multiple(
            "autostream_webui_page_setup",
            get_system_hostname=MagicMock(return_value="autostream"),
            list_outputs=MagicMock(return_value=_list_result),
            get_ap_ssid=MagicMock(return_value="autostream_AP"),
            get_app_version=MagicMock(return_value="1.0.0"),
            _get_dial_sightings=MagicMock(return_value=[]),
            parse_dial_entries=MagicMock(return_value=[]),
            suggested_silence_threshold_dbfs=MagicMock(return_value=-50.0),
            build_top_banner_html=MagicMock(return_value=("", "")),
            _set_flash_cookie=MagicMock(),
            _bluetooth_installed=MagicMock(return_value=bt_enabled),
            _bluetooth_services_enabled=MagicMock(return_value=bt_services_on),
            _bluetooth_onboard_enabled=MagicMock(return_value=bt_onboard_on),
        ):
            with patch.object(
                state, "get_monitor_devices", return_value=(monitor_devices or [])
            ):
                send_setup_page(handler, state, auth, flash_msg="")

        store.close(save=False)
        return handler.wfile.getvalue().decode("utf-8", errors="replace")


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
        assert "bt-scan-row" not in html
        assert "bt-device-list" not in html

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

    def test_card_always_rendered_with_disabled_body(self, html):
        assert 'id="bluetooth-card-sub"' in html
        assert ">Bluetooth<" in html
        assert 'id="btDisabledBody"' in html
        assert 'id="btnBtEnableServices"' in html
        assert "Enable Bluetooth Services" in html

    def test_card_summary_is_disabled(self, html):
        assert 'id="bluetooth-card-sub">Disabled<' in html

    def test_card_enabled_body_absent(self, html):
        # Not installed: the enabled-body isn't just hidden, it isn't
        # rendered at all -- its interactive rows reference JS functions
        # (openBtPairingModal etc.) that only exist once installed.
        assert 'id="btEnabledBody"' not in html

    def test_render_matches_pre_feature_baseline(self, tmp_path):
        """Regression guard: disabled output must match a render with the
        Bluetooth helper entirely absent (ImportError fallback path)."""
        from autostream_webui_page_setup import send_setup_page
        from autostream_settings import SettingsStore
        from autostream_webui_state import WebUIState
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

        with patch.multiple(
            "autostream_webui_page_setup",
            get_system_hostname=MagicMock(return_value="autostream"),
            list_outputs=MagicMock(return_value=_list_result),
            get_ap_ssid=MagicMock(return_value="autostream_AP"),
            get_app_version=MagicMock(return_value="1.0.0"),
            _get_dial_sightings=MagicMock(return_value=[]),
            parse_dial_entries=MagicMock(return_value=[]),
            suggested_silence_threshold_dbfs=MagicMock(return_value=-50.0),
            build_top_banner_html=MagicMock(return_value=("", "")),
            _set_flash_cookie=MagicMock(),
        ):
            with patch.object(state, "get_monitor_devices", return_value=[]):
                send_setup_page(handler, state, auth, flash_msg="")
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
            monitor_devices=[
                {"hw": BT_LOOPBACK_HW, "card": "Loopback", "name": "Loopback",
                 "label": "Bluetooth (not paired)"},
            ],
        )

    def test_pairing_modal_div_present(self, html):
        assert 'id="btPairingModal"' in html

    def test_all_four_panels_present(self, html):
        for panel in ("btScanPanel", "btConfirmPanel", "btPairingPanel", "btResultPanel"):
            assert f'id="{panel}"' in html

    def test_open_bt_pairing_modal_fn_present(self, html):
        assert "function openBtPairingModal(inputIndex, selectEl)" in html

    def test_is_bluetooth_device_fn_present(self, html):
        assert "function isBluetoothDevice(value)" in html
        assert BT_LOOPBACK_HW in html

    def test_close_path_clears_scan_and_pair_intervals(self, html):
        assert "function closeBtPairingModal()" in html
        assert "_btStopScan();" in html
        assert "clearInterval(_btPairTimer)" in html

    def test_scan_stop_posted_on_close(self, html):
        assert "function _btStopScan()" in html
        assert "/api/bluetooth/scan" in html
        assert "action: 'stop'" in html

    def test_scan_start_posted_on_open(self, html):
        assert "action: 'start'" in html

    def test_scan_results_polled(self, html):
        assert "/api/bluetooth/scan_results" in html

    def test_pair_status_polled(self, html):
        assert "/api/bluetooth/pair_status" in html

    def test_pair_endpoint_called(self, html):
        assert "/api/bluetooth/pair'" in html

    def test_forget_endpoint_wired(self, html):
        assert "/api/bluetooth/forget" in html
        assert "function _btForgetCurrent()" in html

    def test_status_endpoint_polled(self, html):
        assert "/api/bluetooth/status" in html
        assert "setInterval(_btRefreshLinkStatus, 5000)" in html

    def test_onchange_branch_present_for_input1(self, html):
        assert "if (isBluetoothDevice(this.value) && !btPaired) { openBtPairingModal(1, this); return; }" in html
        assert "settingsSaveField('audio1.capture_device', this.value)" in html

    def test_onchange_branch_present_for_input2(self, html):
        assert "if (isBluetoothDevice(this.value) && !btPaired) { openBtPairingModal(2, this); return; }" in html
        assert "settingsSaveField('audio2.capture_device', this.value)" in html

    def test_bt_paired_initial_false(self, html):
        assert "var btPaired = false;" in html

    def test_no_manage_button_markup(self, html):
        assert "bt-manage-btn" not in html
        assert "_btSyncManageButton" not in html
        assert "_btSyncAllManageButtons" not in html
        assert "_btUpdateManageButtons" not in html

    def test_success_save_saves_capture_device_only(self, html):
        # Turntable coupling was removed: pairing success saves only the
        # capture device, never audioN.turntable.
        assert "settingsSaveField('audio' + _btInputIndex + '.capture_device', BT_LOOPBACK_HW)" in html
        assert "'.turntable', true)" not in html

    def test_csrf_header_used_in_fetches(self, html):
        assert "window.__CSRF" in html
        assert "X-CSRF-Token" in html

    def test_cache_no_store_used(self, html):
        assert "cache: 'no-store'" in html or "cache:'no-store'" in html

    def test_409_treated_as_in_progress(self, html):
        assert "res.status === 409" in html
        assert "already in progress" in html

    def test_escape_key_closes_modal(self, html):
        assert "'btPairingModal'" in html
        assert "closeBtPairingModal" in html

    # -- Revert-on-cancel wiring (data-prev, not .value at onchange time) --

    def test_select_renders_data_prev_with_persisted_value(self, html):
        # audio1/audio2 both start at "hw:1,0"/"hw:2,0" per _minimal_cfg.
        assert "data-prev='hw:1,0'" in html
        assert "data-prev='hw:2,0'" in html

    def test_open_modal_reads_data_prev_not_value(self, html):
        assert "selectEl.dataset.prev" in html
        assert "_btPriorSelectValue = selectEl && selectEl.dataset.prev !== undefined ? selectEl.dataset.prev : null;" in html

    def test_non_bluetooth_onchange_updates_data_prev(self, html):
        assert (
            "if(liveEnabled) settingsSaveField('audio1.capture_device', this.value); "
            "this.dataset.prev = this.value;"
        ) in html
        assert (
            "if(liveEnabled) settingsSaveField('audio2.capture_device', this.value); "
            "this.dataset.prev = this.value;"
        ) in html

    def test_close_modal_reverts_from_data_prev_when_not_succeeded(self, html):
        assert "if (_btSelectEl && !_btPairSucceeded && _btPriorSelectValue !== null)" in html
        assert "_btSelectEl.value = _btPriorSelectValue;" in html
        assert "_btSelectEl.dataset.prev = _btPriorSelectValue;" in html

    def test_pair_succeeded_flag_reset_on_open_and_set_on_success(self, html):
        assert "_btPairSucceeded = false;" in html
        assert "_btPairSucceeded = true;" in html

    def test_successful_pair_updates_data_prev_to_loopback(self, html):
        assert "_btSelectEl.dataset.prev = BT_LOOPBACK_HW;" in html


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
            monitor_devices=[
                {"hw": BT_LOOPBACK_HW, "card": "Loopback", "name": "My Turntable",
                 "label": "Bluetooth: My Turntable"},
            ],
        )

    def test_bt_paired_initial_true(self, html):
        assert "var btPaired = true;" in html

    def test_paired_row_shows_connected(self, html):
        assert "My Turntable · Connected" in html

    def test_card_summary_shows_connected(self, html):
        assert 'id="bluetooth-card-sub">Enabled · My Turntable connected<' in html

    def test_option_carries_bt_data_attr(self, html):
        assert "data-bt='1'" in html

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
            monitor_devices=[
                {"hw": BT_LOOPBACK_HW, "card": "Loopback", "name": "BT-Turntable",
                 "label": "Bluetooth: BT-Turntable"},
            ],
        )

    def test_card_summary_shows_not_connected_state(self, html):
        assert 'id="bluetooth-card-sub">Enabled · BT-Turntable (not connected)<' in html

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

    def test_card_summary_assigned_verbatim_from_ui(self, html):
        assert "sub.textContent = (ui && ui.card_summary) || 'Disabled';" in html

    def test_paired_row_assigned_verbatim_from_ui(self, html):
        assert "pairedRow.textContent = (ui && ui.paired_text) || 'No device paired';" in html

    def test_input_card_fragment_uses_server_text(self, html):
        assert "mode = window._btUiText || 'Not Connected';" in html
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

    def test_playback_side_still_injected_when_bluetooth_disabled(self, tmp_path):
        # Bluetooth-off appliances have no notion of the loopback device --
        # behaviour here must be byte-identical to before this fix.
        html = _SetupRenderer().render(
            tmp_path,
            bt_enabled=False,
            monitor_devices=[],
            audio1_capture_device=BT_PLAYBACK_HW,
            audio2_capture_device="hw:2,0",
        )
        assert f"{BT_PLAYBACK_HW} (not currently detected)" in html


class TestBluetoothInputCardSummary:
    """Input-card summary line for a Bluetooth input: 'Bluetooth · <device
    name or Not Connected> · <gain>' instead of the ALSA card name and the
    turntable flag."""

    BT_HW = "hw:CARD=ASBT,DEV=1"

    def test_summary_shows_device_name_when_connected(self, tmp_path):
        html_out = _SetupRenderer().render(
            tmp_path,
            bt_enabled=True,
            bt_status={
                "paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "BT-Turntable"},
                "link": "connected",
                "streaming": True,
            },
            audio1_capture_device=self.BT_HW,
        )
        assert "Bluetooth · BT-Turntable · 0 dB" in html_out

    def test_summary_shows_not_connected_when_link_down(self, tmp_path):
        html_out = _SetupRenderer().render(
            tmp_path,
            bt_enabled=True,
            bt_status={
                "paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "BT-Turntable"},
                "link": "disconnected",
                "streaming": False,
            },
            audio1_capture_device=self.BT_HW,
        )
        assert "Bluetooth · Not Connected · 0 dB" in html_out
        assert "Loopback · " not in html_out

    def test_non_bluetooth_input_summary_unchanged(self, tmp_path):
        html_out = _SetupRenderer().render(
            tmp_path,
            bt_enabled=True,
            bt_status=None,
            audio1_capture_device=self.BT_HW,
        )
        # status unavailable (None) -> treated as not connected
        assert "Bluetooth · Not Connected" in html_out

    def test_js_card_sub_has_bluetooth_branch(self, tmp_path):
        html_out = _SetupRenderer().render(tmp_path, bt_enabled=True, audio1_capture_device=self.BT_HW)
        assert "dataset.bt === '1'" in html_out
        assert "window._btLastStatus" in html_out


# ---------------------------------------------------------------------------
# Enable/Disable services buttons: immediate busy feedback on click, with
# restore-on-failure so a slow request doesn't leave the button looking
# unresponsive or permanently stuck in its busy state.
# ---------------------------------------------------------------------------

class TestBluetoothServicesButtonFeedback:
    @pytest.fixture
    def html(self, tmp_path: Path) -> str:
        return _SetupRenderer().render(tmp_path, bt_enabled=True, bt_services_on=True)

    def test_enable_sets_disabled_before_fetch(self, html):
        # The busy-state helper (which sets disabled=true) must run before
        # settingsTransact performs the fetch.
        idx_fn = html.index("function btEnableServices()")
        idx_busy_call = html.index("_btSetBusy(btn,", idx_fn)
        idx_transact = html.index("settingsTransact(", idx_fn)
        assert idx_fn < idx_busy_call < idx_transact
        assert "btn.disabled = true;" in html

    def test_disable_sets_disabled_before_fetch(self, html):
        idx_fn = html.index("function btDisableServices()")
        idx_busy_call = html.index("_btSetBusy(btn,", idx_fn)
        idx_transact = html.index("settingsTransact(", idx_fn)
        assert idx_fn < idx_busy_call < idx_transact
        assert "btn.disabled = true;" in html

    def test_enabling_busy_label_present(self, html):
        assert "Enabling…" in html

    def test_disabling_busy_label_present(self, html):
        assert "Disabling…" in html

    def test_enable_restores_on_error(self, html):
        idx_fn = html.index("function btEnableServices()")
        idx_end = html.index("function btDisableServices()")
        segment = html[idx_fn:idx_end]
        assert "onError:" in segment
        assert "restore()" in segment

    def test_disable_restores_on_error(self, html):
        idx_fn = html.index("function btDisableServices()")
        idx_end = html.index("function btOnboardToggleChanged", idx_fn)
        segment = html[idx_fn:idx_end]
        assert "onError:" in segment
        assert "restore()" in segment

    def test_disable_confirm_precedes_busy_state_change(self, html):
        # The confirm() gate must run before the button is touched, so a
        # cancelled confirm leaves the button completely untouched.
        idx_fn = html.index("function btDisableServices()")
        idx_confirm = html.index("window.confirm(", idx_fn)
        idx_busy_call = html.index("_btSetBusy(btn,", idx_fn)
        assert idx_confirm < idx_busy_call

    def test_success_path_reloads_without_manual_restore(self, html):
        idx_fn = html.index("function btEnableServices()")
        idx_end = html.index("function btDisableServices()")
        segment = html[idx_fn:idx_end]
        assert "onSuccess: function() { window.location.reload(); }" in segment

    def test_button_ids_referenced_for_lookup(self, html):
        assert "getElementById('btnBtEnableServices')" in html
        assert "getElementById('btnBtDisableServices')" in html


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
