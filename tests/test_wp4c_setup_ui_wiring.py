"""tests/test_wp4c_setup_ui_wiring.py

WP4C acceptance tests: Setup UI cutover to autosave API.

Tests cover:
  - _audio_controls_card_html has settingsSaveFieldDebounced on gain and EQ sliders
  - Capture device selects are wired to settingsSaveField
  - Turntable checkboxes are wired to settingsSaveField
  - audio2.enabled checkbox is wired (via onAudio2Toggle)
  - Output name select is wired to settingsSaveField
  - syncVol calls settingsSaveFieldDebounced for owntone.volume_percent
  - syncSil calls settingsSaveFieldDebounced for general.silence_seconds
  - Track identification checkbox wired to settingsSaveField
  - syncTiLeadIn/Refresh/Silence call settingsSaveFieldDebounced
  - Dead legacy API calls (sendGainUpdate, sendEqUpdate) are absent
  - liveEnabled guard is present (false for initial_setup, true otherwise)
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_cfg(tmp_path: Path) -> Path:
    cfg = tmp_path / "autostream.json"
    cfg.write_text(json.dumps({
        "general": {"log_level": "info", "silence_seconds": 30},
        "owntone": {
            "base_url": "http://localhost:3689",
            "output_name": "Test Speaker",
            "volume_percent": 50,
        },
        "audio1": {
            "capture_device": "hw:1,0",
            "gain_db": 0,
            "eq_40hz_db": 0,
            "eq_100hz_db": 0,
            "eq_8khz_db": 0,
            "turntable": False,
        },
        "audio2": {
            "capture_device": "hw:2,0",
            "gain_db": 0,
            "eq_40hz_db": 0,
            "eq_100hz_db": 0,
            "eq_8khz_db": 0,
            "turntable": False,
            "enabled": False,
        },
        "track_identification": {
            "enabled": True,
            "analysis_lead_in_seconds": 5,
            "refresh_seconds": 300,
            "track_change_silence_seconds": 2.0,
        },
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
    """Renders the non-initial-setup page and returns the HTML."""

    def render(self, tmp_path: Path) -> str:
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
            unconfigured=MagicMock(return_value=False),
        ):
            with patch.object(state, "get_monitor_devices", return_value=[]):
                send_setup_page(handler, state, auth, flash_msg="")

        store.close(save=False)
        return handler.wfile.getvalue().decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# _audio_controls_card_html — gain and EQ wiring
# ---------------------------------------------------------------------------

class TestAudioControlsCardHtml:
    """Tests for the static card HTML helper. The debounced API call lives
    inside the syncGain/syncEq JS bodies emitted later; this card only
    contains the oninput=syncGain/syncEq wiring."""

    def _card(self, input_index: int = 1) -> str:
        from autostream_webui_page_setup import _audio_controls_card_html
        return _audio_controls_card_html(
            input_index=input_index,
            gain_db=0.0,
            eq_40hz_db=0.0,
            eq_100hz_db=0.0,
            eq_8khz_db=0.0,
        )

    def test_gain_slider_oninput_calls_syncgain(self):
        html = self._card(1)
        assert "syncGain(1, this.value)" in html

    def test_eq_40hz_oninput_calls_synceq(self):
        html = self._card(1)
        assert "syncEq(1, '40hz', this.value)" in html

    def test_eq_100hz_oninput_calls_synceq(self):
        html = self._card(1)
        assert "syncEq(1, '100hz', this.value)" in html

    def test_eq_8khz_oninput_calls_synceq(self):
        html = self._card(1)
        assert "syncEq(1, '8khz', this.value)" in html

    def test_audio2_gain_uses_index_2(self):
        html = self._card(2)
        assert "syncGain(2, this.value)" in html

    def test_gain_id_includes_prefix(self):
        html = self._card(1)
        assert 'id="audio1_gain_db"' in html

    def test_no_legacy_gain_endpoint_in_card(self):
        html = self._card(1)
        assert "/api/input_gain" not in html
        assert "/api/input_eq" not in html


# ---------------------------------------------------------------------------
# Full page — JS sync function bodies have autosave calls
# ---------------------------------------------------------------------------

class TestSetupPageJsSync:
    @pytest.fixture
    def html(self, tmp_path: Path) -> str:
        return _SetupRenderer().render(tmp_path)

    def test_sync_gain_calls_debounced(self, html):
        assert "settingsSaveFieldDebounced('audio' + inputIndex + '.gain_db'" in html

    def test_sync_gain_debounce_120ms(self, html):
        assert "'.gain_db', Number(value), 120" in html

    def test_sync_eq_calls_debounced_with_band(self, html):
        assert "settingsSaveFieldDebounced('audio' + inputIndex + '.eq_' + band + '_db'" in html

    def test_sync_eq_debounce_120ms(self, html):
        assert "'.eq_' + band + '_db', Number(value), 120" in html

    def test_sync_vol_calls_debounced(self, html):
        assert "settingsSaveFieldDebounced('owntone.volume_percent'" in html

    def test_sync_sil_calls_debounced(self, html):
        assert "settingsSaveFieldDebounced('general.silence_seconds'" in html

    def test_on_audio2_toggle_calls_save_field(self, html):
        assert "settingsSaveField('audio2.enabled', checked)" in html

    def test_sync_ti_lead_in_calls_debounced(self, html):
        assert "settingsSaveFieldDebounced('track_identification.analysis_lead_in_seconds'" in html

    def test_sync_ti_refresh_calls_debounced(self, html):
        assert "settingsSaveFieldDebounced('track_identification.refresh_seconds'" in html

    def test_sync_ti_silence_calls_debounced(self, html):
        assert "settingsSaveFieldDebounced('track_identification.track_change_silence_seconds'" in html

    def test_live_enabled_guard_present(self, html):
        assert "liveEnabled" in html

    def test_live_enabled_false_for_initial_setup(self, html):
        # In non-initial-setup context, liveEnabled is true
        assert "const liveEnabled = true;" in html

    def test_no_send_gain_update_fn(self, html):
        assert "sendGainUpdate" not in html

    def test_no_queue_gain_update_fn(self, html):
        assert "queueGainUpdate" not in html

    def test_no_gain_timers_var(self, html):
        assert "gainTimers" not in html

    def test_no_send_eq_update_fn(self, html):
        assert "sendEqUpdate" not in html

    def test_no_queue_eq_update_fn(self, html):
        assert "queueEqUpdate" not in html

    def test_no_eq_timers_var(self, html):
        assert "eqTimers" not in html

    def test_no_api_input_gain_fetch(self, html):
        assert "'/api/input_gain'" not in html

    def test_no_api_input_eq_fetch(self, html):
        assert "'/api/input_eq'" not in html


# ---------------------------------------------------------------------------
# Full page — HTML control wiring
# ---------------------------------------------------------------------------

class TestSetupPageHtmlControls:
    @pytest.fixture
    def html(self, tmp_path: Path) -> str:
        return _SetupRenderer().render(tmp_path)

    def test_capture_device_1_wired(self, html):
        assert "settingsSaveField('audio1.capture_device', this.value)" in html

    def test_capture_device_2_wired(self, html):
        assert "settingsSaveField('audio2.capture_device', this.value)" in html

    def test_turntable_1_wired(self, html):
        assert "settingsSaveField('audio1.turntable', this.checked)" in html

    def test_turntable_2_wired(self, html):
        assert "settingsSaveField('audio2.turntable', this.checked)" in html

    def test_output_select_wired(self, html):
        assert "settingsSaveField('owntone.output_name', this.value)" in html

    def test_track_id_checkbox_wired(self, html):
        assert "settingsSaveField('track_identification.enabled', this.checked)" in html

    def test_audio2_enabled_toggle_handler_present(self, html):
        assert "onAudio2Toggle(this.checked)" in html

    def test_gain_slider_oninput_present_in_rendered_html(self, html):
        assert "syncGain(1, this.value)" in html
        assert "syncGain(2, this.value)" in html

    def test_eq_slider_oninput_present_in_rendered_html(self, html):
        assert "syncEq(1, '40hz', this.value)" in html

    def test_silence_slider_uses_sync_sil(self, html):
        assert "syncSil(this.value)" in html

    def test_volume_slider_uses_sync_vol(self, html):
        assert "syncVol(this.value)" in html


# ---------------------------------------------------------------------------
# Initial-setup page — liveEnabled is false so autosave is no-op
# ---------------------------------------------------------------------------

class TestInitialSetupLiveDisabled:
    def _render_initial(self, tmp_path: Path) -> str:
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
            unconfigured=MagicMock(return_value=True),
        ):
            with patch.object(state, "get_monitor_devices", return_value=[]):
                send_setup_page(handler, state, auth)

        store.close(save=False)
        return handler.wfile.getvalue().decode("utf-8", errors="replace")

    def test_live_enabled_false_for_initial_setup(self, tmp_path):
        html = self._render_initial(tmp_path)
        assert "const liveEnabled = false;" in html

    def test_autosave_js_is_present_but_gated_by_live_enabled(self, tmp_path):
        html = self._render_initial(tmp_path)
        # AUTOSAVE_JS is included but all calls are guarded by liveEnabled=false.
        assert "window.settingsSaveField" in html
        assert "const liveEnabled = false;" in html
