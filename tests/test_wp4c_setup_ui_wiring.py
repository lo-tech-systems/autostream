"""tests/test_wp4c_setup_ui_wiring.py

WP4C acceptance tests: Setup UI cutover to autosave API.

Tests cover:
  - _audio_controls_card_html has settingsSaveFieldDebounced on gain and EQ sliders
  - Capture device selects are wired to settingsSaveField
  - Turntable checkboxes are wired to settingsSaveField
  - audio1.enabled / audio2.enabled checkboxes are wired (via onInputEnableToggle)
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
        from autostream_settings import SettingsStore
        from autostream_webui_state import WebUIState
        from autostream_players import ListOutputsResult
        from _setup_card_test_helpers import render_full_setup_with_cards

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
                html = render_full_setup_with_cards(handler, state, auth, flash_msg="")

        store.close(save=False)
        return html


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

    def test_on_input_enable_toggle_calls_save_field(self, html):
        assert "settingsSaveField('audio' + inputIndex + '.enabled', checked)" in html

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

    def test_audio1_enabled_toggle_handler_present(self, html):
        assert "onInputEnableToggle(1, this.checked)" in html

    def test_audio2_enabled_toggle_handler_present(self, html):
        assert "onInputEnableToggle(2, this.checked)" in html

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
# Input 1 enable toggle (mirrors input 2's existing pattern)
# ---------------------------------------------------------------------------

class TestInput1EnableToggle:
    def _render_with_audio1_enabled(self, tmp_path: Path, enabled: bool) -> str:
        cfg = _minimal_cfg(tmp_path)
        data = json.loads(cfg.read_text(encoding="utf-8"))
        data.setdefault("audio1", {})["enabled"] = enabled
        cfg.write_text(json.dumps(data), encoding="utf-8")

        from autostream_settings import SettingsStore
        from autostream_webui_state import WebUIState
        from autostream_players import ListOutputsResult
        from _setup_card_test_helpers import render_full_setup_with_cards

        store = SettingsStore(str(cfg), _save_interval_seconds=9999)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)

        handler = MagicMock()
        handler.wfile = io.BytesIO()
        auth = MagicMock()
        auth.ensure_session.return_value = "test-csrf"
        auth.get_csrf_token.return_value = "test-csrf"
        auth.get_boot_pin_value.return_value = "1234"

        with patch.multiple(
            "autostream_webui_page_setup",
            get_system_hostname=MagicMock(return_value="autostream"),
            list_outputs=MagicMock(return_value=ListOutputsResult(ok=False, error="unreachable")),
            get_ap_ssid=MagicMock(return_value="autostream_AP"),
            get_app_version=MagicMock(return_value="1.0.0"),
            _get_dial_sightings=MagicMock(return_value=[]),
            parse_dial_entries=MagicMock(return_value=[]),
            suggested_silence_threshold_dbfs=MagicMock(return_value=-50.0),
            build_top_banner_html=MagicMock(return_value=("", "")),
            _set_flash_cookie=MagicMock(),
        ):
            with patch.object(state, "get_monitor_devices", return_value=[]):
                html = render_full_setup_with_cards(handler, state, auth, flash_msg="")

        store.close(save=False)
        return html

    def test_input1_enable_checkbox_present(self, tmp_path):
        html = self._render_with_audio1_enabled(tmp_path, True)
        assert 'name="audio1_enabled"' in html
        checkbox_tag = html.split('name="audio1_enabled"', 1)[1].split('onchange', 1)[0]
        assert 'checked' in checkbox_tag

    def test_input1_enable_checkbox_unchecked_when_disabled(self, tmp_path):
        html = self._render_with_audio1_enabled(tmp_path, False)
        checkbox_tag = html.split('name="audio1_enabled"', 1)[1].split('onchange', 1)[0]
        assert 'checked' not in checkbox_tag

    def test_input1_settings_hidden_when_disabled(self, tmp_path):
        html = self._render_with_audio1_enabled(tmp_path, False)
        assert 'id="audio1_settings" style="display:none;"' in html

    def test_input1_settings_shown_when_enabled(self, tmp_path):
        html = self._render_with_audio1_enabled(tmp_path, True)
        assert 'id="audio1_settings" style="display:block;"' in html

    def test_input1_preamp_card_hidden_when_disabled(self, tmp_path):
        html = self._render_with_audio1_enabled(tmp_path, False)
        assert 'id="audio1_preamp_card" style="display:none;"' in html

    def test_input1_preamp_card_shown_when_enabled(self, tmp_path):
        html = self._render_with_audio1_enabled(tmp_path, True)
        assert 'id="audio1_preamp_card" style="display:block;"' in html

    def test_input1_card_summary_not_configured_when_disabled(self, tmp_path):
        html = self._render_with_audio1_enabled(tmp_path, False)
        assert '<span class="setup-list-card-sub" id="input1-card-sub">Not configured</span>' in html

    def test_input1_card_summary_shows_device_when_enabled(self, tmp_path):
        html = self._render_with_audio1_enabled(tmp_path, True)
        summary = html.split('id="input1-card-sub">', 1)[1].split('</span>', 1)[0]
        assert summary != "Not configured"

    def test_sync_input_ui_reads_audio1_enabled_checkbox(self, tmp_path):
        html = self._render_with_audio1_enabled(tmp_path, True)
        assert "const enabledName = prefix + '_enabled';" in html
        assert "document.querySelector('input[name=\"' + enabledName + '\"]')" in html


# ---------------------------------------------------------------------------
# Setup page — liveEnabled is always true (first-boot has its own pages)
# ---------------------------------------------------------------------------

class TestSetupPageLiveEnabled:
    def test_live_enabled_always_true(self, tmp_path):
        """The setup page always has liveEnabled=true; first-boot uses dedicated pages."""
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
                send_setup_page(handler, state, auth)

        store.close(save=False)
        html = handler.wfile.getvalue().decode("utf-8", errors="replace")
        assert "const liveEnabled = true;" in html
        assert "window.settingsSaveField" in html


# ---------------------------------------------------------------------------
# Audio Path card split
# ---------------------------------------------------------------------------

class TestPlaybackPanelCardSplit:
    """The old single playback fieldset is now four cards inside
    id="panel-playback": playback defaults, silence detection, repeat
    playback, and audio processing (Audio Path dropdown). Existing element
    ids/handlers must survive unchanged (see TestAudioControlsCardHtml etc.
    elsewhere in this file for the ids this must not disturb)."""

    def _playback_panel(self, html: str) -> str:
        return html.split('id="panel-playback"', 1)[1].split('id="panel-track-id"', 1)[0]

    def test_four_cards_render_in_playback_panel(self, tmp_path):
        with patch("autostream_webui_page_setup.is_high_performance_pi", return_value=True):
            html = _SetupRenderer().render(tmp_path)
        panel = self._playback_panel(html)
        # Four distinct settings_card_html() divs (identified by their
        # unique static content) inside the playback panel.
        assert 'id="owntone_output_select"' in panel
        assert 'id="sil_val"' in panel
        assert 'id="repeat_enabled"' in panel
        assert 'id="general_audio_path"' in panel

    def test_owntone_button_moved_below_cards(self, tmp_path):
        with patch("autostream_webui_page_setup.is_high_performance_pi", return_value=True):
            html = _SetupRenderer().render(tmp_path)
        panel = self._playback_panel(html)
        # The button must appear after the Audio Path select in document
        # order (i.e. below all four cards, not embedded inside one).
        button_idx = panel.index("More Owntone Settings")
        audio_path_idx = panel.index('id="general_audio_path"')
        assert button_idx > audio_path_idx

    def test_align_button_below_owntone_button(self, tmp_path):
        # The align entry point renders only when the backend supports
        # per-output offsets -- pin the capability so the assertion does
        # not depend on what (if anything) answers on the backend port.
        caps = MagicMock()
        caps.can_set_output_offset = True
        with patch("autostream_webui_page_setup.is_high_performance_pi", return_value=True), \
             patch("autostream_player_service.get_capabilities", return_value=caps):
            html = _SetupRenderer().render(tmp_path)
        panel = self._playback_panel(html)
        # "Run Speaker Synchronisation" links to /align and sits directly
        # below the "More Owntone Settings" button.
        owntone_idx = panel.index("More Owntone Settings")
        align_idx = panel.index("Run Speaker Synchronisation")
        assert align_idx > owntone_idx
        assert "/align" in panel

    def test_align_button_hidden_without_offset_support(self, tmp_path):
        caps = MagicMock()
        caps.can_set_output_offset = False
        with patch("autostream_webui_page_setup.is_high_performance_pi", return_value=True), \
             patch("autostream_player_service.get_capabilities", return_value=caps):
            html = _SetupRenderer().render(tmp_path)
        panel = self._playback_panel(html)
        assert "Run Speaker Synchronisation" not in panel
        assert "More Owntone Settings" in panel

    def test_audio_path_dropdown_offers_maximum_quality_on_high_perf(self, tmp_path):
        with patch("autostream_webui_page_setup.is_high_performance_pi", return_value=True):
            html = _SetupRenderer().render(tmp_path)
        panel = self._playback_panel(html)
        select_html = panel.split('id="general_audio_path"', 1)[1].split('</select>', 1)[0]
        assert "Best (highest CPU use and best quality)" in select_html
        assert "Balanced (moderate CPU use)" in select_html
        assert "Fast (lowest CPU use, fine for most sources)" in select_html

    def test_audio_path_dropdown_omits_maximum_quality_on_small_hardware(self, tmp_path):
        with patch("autostream_webui_page_setup.is_high_performance_pi", return_value=False):
            html = _SetupRenderer().render(tmp_path)
        panel = self._playback_panel(html)
        select_html = panel.split('id="general_audio_path"', 1)[1].split('</select>', 1)[0]
        assert "Best (highest CPU use and best quality)" not in select_html
        assert "Balanced (moderate CPU use)" in select_html
        assert "Fast (lowest CPU use, fine for most sources)" in select_html

    def test_audio_path_select_reflects_parsed_value(self, tmp_path):
        # _SetupRenderer always (re)writes a fresh minimal config, so this
        # test drives send_setup_page() directly against a config carrying
        # an explicit audio_path instead.
        from autostream_settings import SettingsStore
        from autostream_webui_state import WebUIState
        from autostream_players import ListOutputsResult
        from _setup_card_test_helpers import render_full_setup_with_cards

        cfg = _minimal_cfg(tmp_path)
        data = json.loads(cfg.read_text(encoding="utf-8"))
        data.setdefault("general", {})["audio_path"] = "fast"
        cfg.write_text(json.dumps(data), encoding="utf-8")

        store = SettingsStore(str(cfg), _save_interval_seconds=9999)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)

        handler = MagicMock()
        handler.wfile = io.BytesIO()
        auth = MagicMock()
        auth.ensure_session.return_value = "test-csrf"
        auth.get_csrf_token.return_value = "test-csrf"
        auth.get_boot_pin_value.return_value = "1234"

        with patch.multiple(
            "autostream_webui_page_setup",
            get_system_hostname=MagicMock(return_value="autostream"),
            list_outputs=MagicMock(return_value=ListOutputsResult(ok=False, error="unreachable")),
            get_ap_ssid=MagicMock(return_value="autostream_AP"),
            get_app_version=MagicMock(return_value="1.0.0"),
            _get_dial_sightings=MagicMock(return_value=[]),
            parse_dial_entries=MagicMock(return_value=[]),
            suggested_silence_threshold_dbfs=MagicMock(return_value=-50.0),
            build_top_banner_html=MagicMock(return_value=("", "")),
            _set_flash_cookie=MagicMock(),
            is_high_performance_pi=MagicMock(return_value=True),
        ):
            with patch.object(state, "get_monitor_devices", return_value=[]):
                html = render_full_setup_with_cards(handler, state, auth, flash_msg="")

        store.close(save=False)
        panel = self._playback_panel(html)
        select_html = panel.split('id="general_audio_path"', 1)[1].split('</select>', 1)[0]
        fast_option = select_html.split('value="fast"', 1)[1].split(">", 1)[0]
        assert "selected" in fast_option

    def test_audio_path_onchange_wired_to_settings_save_field(self, tmp_path):
        with patch("autostream_webui_page_setup.is_high_performance_pi", return_value=True):
            html = _SetupRenderer().render(tmp_path)
        panel = self._playback_panel(html)
        select_html = panel.split('id="general_audio_path"', 1)[1].split('</select>', 1)[0]
        assert "settingsSaveField('general.audio_path', this.value)" in select_html

    def test_helptext_present(self, tmp_path):
        with patch("autostream_webui_page_setup.is_high_performance_pi", return_value=True):
            html = _SetupRenderer().render(tmp_path)
        panel = self._playback_panel(html)
        assert "Applies immediately" in panel
        assert "playback stops and resumes automatically after a few seconds" in panel

    def test_existing_playback_panel_ids_survive_the_split(self, tmp_path):
        """Structural-only split: every id the pre-existing wiring tests
        depend on (repeat toggle, buffer target select, notes, volume
        slider) must still be present and inside the panel."""
        with patch("autostream_webui_page_setup.is_high_performance_pi", return_value=True):
            html = _SetupRenderer().render(tmp_path)
        panel = self._playback_panel(html)
        for expected_id in (
            "owntone_output_select",
            "owntone_output_hint",
            "vol_val",
            "owntone_volume_percent",
            "sil_val",
            "repeat_enabled",
            "repeat-target-row",
            "repeat_target_minutes",
            "repeat-max-time-note",
            "repeat-unavailable-note",
            "general_audio_path",
        ):
            assert f'id="{expected_id}"' in panel, expected_id
