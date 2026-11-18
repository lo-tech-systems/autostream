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
from _setup_card_test_helpers import setup_page_mocks
from _source_text import page_scripts
from fake_store import fake_outputs_result

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
        },
        "updates": {"auto_update": False, "update_channel": "stable"},
    }), encoding="utf-8")
    return cfg


class _SetupRenderer:
    """Renders the non-initial-setup page and returns the HTML."""

    def render(self, tmp_path: Path, audio1: dict | None = None) -> str:
        from autostream_settings import SettingsStore
        from webui.session_state import WebUIState
        from autostream_players import ListOutputsResult
        from _setup_card_test_helpers import render_full_setup_with_cards

        cfg = _minimal_cfg(tmp_path)
        if audio1:
            data = json.loads(cfg.read_text(encoding="utf-8"))
            data["audio1"].update(audio1)
            cfg.write_text(json.dumps(data), encoding="utf-8")
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
                html = render_full_setup_with_cards(handler, state, auth)

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
        from webui.browser.setup.cards_inputs import _audio_controls_card_html
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

    def test_input_type_1_wired(self, html):
        assert 'onchange="onInputTypeChange(1, this.value)"' in html
        assert "settingsSaveField('audio' + inputIndex + '.input_type', type)" in html

    def test_input_type_2_wired(self, html):
        assert 'onchange="onInputTypeChange(2, this.value)"' in html
        assert "settingsSaveField('audio' + inputIndex + '.input_type', type)" in html

    def test_sensitivity_slider_wired(self, html):
        assert 'oninput="syncSilenceThreshold(1, this.value)"' in html
        assert 'oninput="syncSilenceThreshold(2, this.value)"' in html
        assert (
            "settingsSaveFieldDebounced('audio' + inputIndex + '.silence_threshold', Number(value), 300)"
            in html
        )

    def test_input_type_select_options_and_selection(self, tmp_path):
        html = _SetupRenderer().render(tmp_path, audio1={"turntable": True})
        select = html.split('id="audio1_input_type"', 1)[1].split("</select>", 1)[0]
        assert '<option value="turntable" selected>Turntable</option>' in select
        assert '<option value="cd">CD</option>' in select
        assert '<option value="line">Line</option>' in select

    def test_slider_range_and_value(self, tmp_path):
        html = _SetupRenderer().render(tmp_path, audio1={"turntable": True})
        slider = html.split('<input type="range" min="-70"', 1)[1].split(">", 1)[0]
        assert 'max="-30" step="1" id="audio_silence_threshold"' in slider
        assert 'value="-45"' in slider
        assert '<span id="audio1_silence_threshold_val">-45 dB</span>' in html

    def test_presets_attribute_matches_config(self, html):
        import html as html_lib
        from autostream_config import INPUT_TYPE_SILENCE_THRESHOLD_DBFS

        raw = html.split('id="audio1_input_type"', 1)[1].split("data-presets='", 1)[1].split("'", 1)[0]
        assert json.loads(html_lib.unescape(raw)) == INPUT_TYPE_SILENCE_THRESHOLD_DBFS

    def test_level_span_present(self, html):
        assert 'id="audio1_level_val"' in html
        assert 'id="audio2_level_val"' in html

    @staticmethod
    def _start_after_block(html, n):
        return html.split(f'id="audio{n}_start_after_wrap"', 1)[1].split('class="helptext"', 1)[0]

    def test_start_after_stepper_for_both_inputs(self, html):
        for n in (1, 2):
            block = self._start_after_block(html, n)
            for step in (-100, -10, 10, 100):
                assert f'onclick="startAfterStep({n}, {step})"' in block
            assert f'onclick="startAfterReset({n})"' in block
            assert f'<span id="audio{n}_start_after_val"' in block
            assert 'data-ms="60">60</span><span class="unit">ms</span>' in block

    def test_start_after_sits_between_the_level_and_the_sample_rate(self, html):
        for n in (1, 2):
            level = html.index(f'id="audio{n}_level_val"')
            start_after = html.index(f'id="audio{n}_start_after_wrap"')
            rate = html.index(f'id="audio{n}_sample_rate"')
            assert level < start_after < rate

    def test_start_after_shows_the_saved_value(self, tmp_path):
        html = _SetupRenderer().render(tmp_path, audio1={"start_after_ms": 150})
        assert 'data-ms="150">150</span>' in self._start_after_block(html, 1)
        assert 'data-ms="60">60</span>' in self._start_after_block(html, 2)

    def test_start_after_buttons_disabled_only_at_the_ends(self, tmp_path):
        def disabled(block, step):
            button = block.split(f'data-step="{step}"', 1)[1].split(">", 1)[0]
            return "disabled" in button

        low = self._start_after_block(
            _SetupRenderer().render(tmp_path, audio1={"start_after_ms": 30}), 1)
        assert disabled(low, -100) and disabled(low, -10)
        assert not disabled(low, 10) and not disabled(low, 100)
        high = self._start_after_block(
            _SetupRenderer().render(tmp_path, audio1={"start_after_ms": 250}), 1)
        assert disabled(high, 10) and disabled(high, 100)
        assert not disabled(high, -100) and not disabled(high, -10)
        mid = self._start_after_block(
            _SetupRenderer().render(tmp_path, audio1={"start_after_ms": 200}), 1)
        assert not any(disabled(mid, s) for s in (-100, -10, 10, 100))

    def test_start_after_hidden_for_a_cd_input(self, tmp_path):
        html = _SetupRenderer().render(tmp_path, audio1={"input_type": "cd"})
        wrap = html.split('id="audio1_start_after_wrap"', 1)[1].split(">", 1)[0]
        assert "hidden" in wrap
        other = html.split('id="audio2_start_after_wrap"', 1)[1].split(">", 1)[0]
        assert "hidden" not in other

    def test_start_after_js_saves_and_follows_the_type(self, html):
        assert (
            "settingsSaveFieldDebounced('audio' + inputIndex + '.start_after_ms', ms, 300)"
            in html
        )
        assert "startAfter.hidden = (type === 'cd')" in html

    def test_start_after_js_limits_match_the_config(self, html):
        from autostream_config import (
            START_AFTER_MS_DEFAULT, START_AFTER_MS_MAX, START_AFTER_MS_MIN,
        )
        assert f"var START_AFTER_MIN_MS = {START_AFTER_MS_MIN};" in html
        assert f"var START_AFTER_MAX_MS = {START_AFTER_MS_MAX};" in html
        assert f"var START_AFTER_DEFAULT_MS = {START_AFTER_MS_DEFAULT};" in html

    def test_rate_matching_switch_wired_for_both_inputs(self, html):
        assert "settingsSaveField('audio1.dynamic_rate_matching', this.checked)" in html
        assert "settingsSaveField('audio2.dynamic_rate_matching', this.checked)" in html
        assert 'id="audio1_dynamic_rate_matching"' in html
        assert 'id="audio2_dynamic_rate_matching"' in html

    def test_rate_matching_switch_follows_the_config(self, tmp_path):
        default = _SetupRenderer().render(tmp_path)
        switch = default.split('id="audio1_dynamic_rate_matching"', 1)[1].split("onchange", 1)[0]
        assert "checked" in switch
        off = _SetupRenderer().render(tmp_path, audio1={"dynamic_rate_matching": False})
        switch = off.split('id="audio1_dynamic_rate_matching"', 1)[1].split("onchange", 1)[0]
        assert "checked" not in switch
        on = _SetupRenderer().render(tmp_path, audio1={"dynamic_rate_matching": True})
        switch = on.split('id="audio1_dynamic_rate_matching"', 1)[1].split("onchange", 1)[0]
        assert "checked" in switch
        other = on.split('id="audio2_dynamic_rate_matching"', 1)[1].split("onchange", 1)[0]
        assert "checked" in other

    def test_rate_matching_switch_and_note_follow_the_level_readout(self, html):
        level = html.index('id="audio1_level_val"')
        switch = html.index('id="audio1_dynamic_rate_matching"')
        note = html.index('id="audio1_rate_matching_note"')
        assert level < switch < note

    def test_sample_rate_line_sits_between_the_level_and_the_switch(self, html):
        for n in (1, 2):
            level = html.index(f'id="audio{n}_level_val"')
            rate = html.index(f'id="audio{n}_sample_rate"')
            switch = html.index(f'id="audio{n}_dynamic_rate_matching"')
            note = html.index(f'id="audio{n}_rate_matching_note"')
            assert level < rate < switch < note

    def test_sample_rate_line_is_styled_like_the_level_readout(self, html):
        level_div = html.split('id="audio1_level_val"', 1)[0].rsplit("<div", 1)[1]
        rate_div = html.split('id="audio1_sample_rate"', 1)[1].split(">", 1)[0]
        assert 'class="helptext" style="text-align:left;"' in level_div
        assert 'class="helptext" style="text-align:left;"' in rate_div

    def test_first_render_sample_rate_line_comes_from_the_inputs_part(self, tmp_path, fake_store):
        fake_store.inputs([
            fake_store.input_entry(
                n, rate_note=f"note {n}", sample_rate_text=f"Sample rate: text {n}")
            for n in (1, 2)])
        html = _SetupRenderer().render(tmp_path)
        for n in (1, 2):
            line = html.split(f'id="audio{n}_sample_rate"', 1)[1].split("</div>", 1)[0]
            assert f"Sample rate: text {n}" in line

    def test_default_first_render_reads_not_running(self, html):
        line = html.split('id="audio1_sample_rate"', 1)[1].split("</div>", 1)[0]
        assert "Sample rate: not running" in line

    def test_first_render_keeps_a_non_breaking_space_as_the_character(self, tmp_path, fake_store):
        fake_store.inputs([
            fake_store.input_entry(
                n, rate_note="note", sample_rate_text="Sample rate: 48 kHz")
            for n in (1, 2)])
        html = _SetupRenderer().render(tmp_path)
        line = html.split('id="audio1_sample_rate"', 1)[1].split("</div>", 1)[0]
        assert "48 kHz" in line
        assert "&nbsp;" not in line and "&#160;" not in line

    def test_rate_matching_label_and_default_note_present(self, html):
        from autostream_state import RATE_MATCHING_NOTE_DEFAULT
        assert "<span>Dynamic Rate Matching</span>" in html
        for n in (1, 2):
            note = html.split(f'id="audio{n}_rate_matching_note"', 1)[1].split("</div>", 1)[0]
            assert RATE_MATCHING_NOTE_DEFAULT in note

    def test_first_render_note_comes_from_the_inputs_part(self, tmp_path, fake_store):
        fake_store.inputs([
            fake_store.input_entry(
                n, rate_note=f"note for input {n}", sample_rate_text="Sample rate: x")
            for n in (1, 2)])
        html = _SetupRenderer().render(tmp_path)
        note1 = html.split('id="audio1_rate_matching_note"', 1)[1].split("</div>", 1)[0]
        note2 = html.split('id="audio2_rate_matching_note"', 1)[1].split("</div>", 1)[0]
        assert "note for input 1" in note1
        assert "note for input 2" in note2

    def test_level_poll_handler_writes_the_note(self, html):
        handler = html.split("function _applyInputLevels(body)", 1)[1].split("var _inputLevelPoller", 1)[0]
        assert "'_rate_matching_note'" in handler
        assert "item.rate_matching_note" in handler
        assert "textContent" in handler

    def test_level_poll_handler_writes_the_sample_rate_line(self, html):
        handler = html.split("function _applyInputLevels(body)", 1)[1].split("var _inputLevelPoller", 1)[0]
        assert "'_sample_rate'" in handler
        assert "item.sample_rate_text" in handler
        assert "rate.textContent = item.sample_rate_text" in handler

    def test_setup_opens_an_input_card_from_its_link_fragment(self, html):
        for n in (1, 2):
            assert f"if (location.hash === '#input{n}') openPanel('input{n}');" in html

    def test_no_hidden_threshold_field(self, html):
        assert 'type="hidden" id="audio_silence_threshold"' not in html

    def test_auto_start_removal_saves_the_remaining_set(self, html):
        assert "settingsSaveField('owntone.default_outputs'" in html
        assert "onclick='removeAutoStart(this)'" in html

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
        from webui.session_state import WebUIState
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

        fake_outputs_result(ListOutputsResult(ok=False, error="unreachable"))
        with setup_page_mocks():
            with patch.object(state, "get_monitor_devices", return_value=[]):
                html = render_full_setup_with_cards(handler, state, auth)

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
        html = page_scripts(handler.wfile.getvalue().decode("utf-8", errors="replace"))
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
        with patch("webui.browser.setup.cards_playback.is_high_performance_pi", return_value=True):
            html = _SetupRenderer().render(tmp_path)
        panel = self._playback_panel(html)
        # Four distinct settings_card_html() divs (identified by their
        # unique static content) inside the playback panel.
        assert 'id="autostart_members"' in panel
        assert 'id="sil_val"' in panel
        assert 'id="repeat_enabled"' in panel
        assert 'id="general_audio_path"' in panel

    def test_owntone_button_moved_below_cards(self, tmp_path):
        with patch("webui.browser.setup.cards_playback.is_high_performance_pi", return_value=True):
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
        with patch("webui.browser.setup.cards_playback.is_high_performance_pi", return_value=True), \
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
        with patch("webui.browser.setup.cards_playback.is_high_performance_pi", return_value=True), \
             patch("autostream_player_service.get_capabilities", return_value=caps):
            html = _SetupRenderer().render(tmp_path)
        panel = self._playback_panel(html)
        assert "Run Speaker Synchronisation" not in panel
        assert "More Owntone Settings" in panel

    def test_audio_path_dropdown_offers_maximum_quality_on_high_perf(self, tmp_path):
        with patch("webui.browser.setup.cards_playback.is_high_performance_pi", return_value=True):
            html = _SetupRenderer().render(tmp_path)
        panel = self._playback_panel(html)
        select_html = panel.split('id="general_audio_path"', 1)[1].split('</select>', 1)[0]
        assert "Best (highest CPU use and best quality)" in select_html
        assert "Balanced (moderate CPU use)" in select_html
        assert "Fast (lowest CPU use, fine for most sources)" in select_html

    def test_audio_path_dropdown_omits_maximum_quality_on_small_hardware(self, tmp_path):
        with patch("webui.browser.setup.cards_playback.is_high_performance_pi", return_value=False):
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
        from webui.session_state import WebUIState
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

        fake_outputs_result(ListOutputsResult(ok=False, error="unreachable"))
        with setup_page_mocks(is_high_performance_pi=True):
            with patch.object(state, "get_monitor_devices", return_value=[]):
                html = render_full_setup_with_cards(handler, state, auth)

        store.close(save=False)
        panel = self._playback_panel(html)
        select_html = panel.split('id="general_audio_path"', 1)[1].split('</select>', 1)[0]
        fast_option = select_html.split('value="fast"', 1)[1].split(">", 1)[0]
        assert "selected" in fast_option

    def test_audio_path_onchange_wired_to_settings_save_field(self, tmp_path):
        with patch("webui.browser.setup.cards_playback.is_high_performance_pi", return_value=True):
            html = _SetupRenderer().render(tmp_path)
        panel = self._playback_panel(html)
        select_html = panel.split('id="general_audio_path"', 1)[1].split('</select>', 1)[0]
        assert "settingsSaveField('general.audio_path', this.value)" in select_html

    def test_helptext_present(self, tmp_path):
        with patch("webui.browser.setup.cards_playback.is_high_performance_pi", return_value=True):
            html = _SetupRenderer().render(tmp_path)
        panel = self._playback_panel(html)
        assert "Applies immediately" in panel
        assert "playback stops and resumes automatically after a few seconds" in panel

    def test_existing_playback_panel_ids_survive_the_split(self, tmp_path):
        """Structural-only split: every id the pre-existing wiring tests
        depend on (repeat toggle, buffer target select, notes, volume
        slider) must still be present and inside the panel."""
        with patch("webui.browser.setup.cards_playback.is_high_performance_pi", return_value=True):
            html = _SetupRenderer().render(tmp_path)
        panel = self._playback_panel(html)
        for expected_id in (
            "autostart_members",
            "autostart_help",
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


# ---------------------------------------------------------------------------
# Personalisation card -- what a Pause pressed on a speaker does
# ---------------------------------------------------------------------------

class TestDevicePauseChoice:
    LABELS = ("Only that speaker pauses", "Mute the other speakers too")
    HELP = (
        "Applies to Pause on a HomePod or on an Apple TV remote. That speaker always pauses, "
        "and Play on it starts it again and unmutes the others. Switching it off and on again "
        "also starts it. A stereo pair, or an Apple TV with its HomePods, counts as one speaker."
    )

    @staticmethod
    def _card(scope="output", seconds=300, *, rows=None, events=True):
        import autostream_config
        from autostream_backend_events import ConnectInfo
        from autostream_state.outputs import get_authority
        from webui.browser.setup.cards_customise import _setup_customise_card_html
        from fake_store import FakeStore
        from output_fakes import homepods_row, row

        parsed = autostream_config.parse_config(
            {"outputs": {"device_pause_scope": scope, "pause_off_seconds": seconds}}, high_perf=False)
        FakeStore().outputs([homepods_row(1)] if rows is None else rows)
        if events:
            caps = frozenset({"device_volume", "receiver_command"})
            get_authority().on_connected(ConnectInfo("b0", 1, caps, "unix_socket"))
            get_authority().step(now=1000.0)
        return _setup_customise_card_html(parsed)

    @staticmethod
    def _select(html):
        start = html.index('<select id="device_pause_scope"')
        return html[start:html.index("</select>", start)]

    @staticmethod
    def _note(html):
        start = html.index('<span id="device_pause_off_note"')
        return html[start:html.index("</span>", start)]

    def test_the_two_options_have_the_exact_labels_and_values(self):
        sel = self._select(self._card())
        for value, label in zip(("output", "all"), self.LABELS):
            assert f'<option value="{value}"' in sel and f">{label}</option>" in sel
        assert sel.count("<option") == 2 and "Keep playing" not in sel

    def test_the_title_and_help_are_the_agreed_text(self):
        html = self._card()
        assert "When Pause is pressed on a speaker" in html
        assert self.HELP in html
        assert "\u2014" not in html and "&mdash;" not in html.split("When Pause is pressed")[1]

    @pytest.mark.parametrize("scope", ["output", "all"])
    def test_the_parsed_scope_is_the_selected_option(self, scope):
        sel = self._select(self._card(scope))
        assert sel.count(" selected") == 1
        assert f'<option value="{scope}" selected>' in sel

    def test_the_choice_saves_on_change_without_a_form_name(self):
        sel = self._select(self._card())
        assert "settingsSaveField('outputs.device_pause_scope', this.value)" in sel
        assert " name=" not in sel.split(">")[0]
        assert "liveEnabled" not in sel

    def test_the_select_is_enabled_when_the_player_reports_device_events(self):
        assert " disabled" not in self._select(self._card()).split(">")[0]

    def test_an_older_player_disables_it_with_the_version_text(self):
        from output_fakes import row
        html = self._card(rows=[row(1)], events=False)
        assert " disabled" in self._select(html).split(">")[0]
        assert "Needs owntone-mini 1.6 or above. The connected player handles Pause on its own." in html
        assert self.HELP not in html

    def test_a_closed_event_channel_disables_it_with_the_channel_text(self):
        html = self._card(events=False)
        assert " disabled" in self._select(html).split(">")[0]
        assert ("Needs owntone-mini's event channel, which is off or not connected. "
                "Pause on a speaker does nothing until it is.") in html.replace("&#x27;", "'")
        assert "Needs owntone-mini 1.6" not in html

    @pytest.mark.parametrize("scope", ["output", "all"])
    def test_the_timeout_sentence_is_shown_for_every_choice(self, scope):
        shown = self._note(self._card(scope)).split(">", 1)[1]
        assert shown == (" A paused speaker, and any speakers its Pause muted, are turned off "
                         "if Pause lasts longer than 5 minutes.")

    @pytest.mark.parametrize("seconds,words", [
        (30, "30 seconds"), (45, "45 seconds"), (60, "1 minute"), (120, "2 minutes"),
        (300, "5 minutes"), (90, "90 seconds"), (3600, "60 minutes"),
    ])
    def test_the_timeout_is_said_as_people_say_it(self, seconds, words):
        assert f"longer than {words}." in self._note(self._card("all", seconds))

    def test_changing_the_choice_only_saves_it(self):
        sel = self._select(self._card())
        assert "device_pause_off_note" not in sel

    def test_the_card_text_is_latin_1(self):
        self._card("all").encode("latin-1")


class TestSpeakerVolumeSwitch:
    LABEL = "Volume changes made at any speaker apply to all playing speakers"
    HELP = (
        "Applies to a speaker's own volume buttons, knob or app, and to an Apple TV "
        "remote. The other playing speakers move in proportion to their own levels, "
        "so they all reach silent together. Muted speakers stay muted. A stereo pair, "
        "or an Apple TV with its HomePods, counts as one speaker."
    )
    VERSION = ("Needs owntone-mini 1.6 or above. Until then a volume change at a speaker "
               "applies to that speaker only.")
    EVENTS = ("Needs owntone-mini's event channel, which is off or not connected. A volume "
              "change at a speaker applies to that speaker only until it is.")

    @staticmethod
    def _card(on=False, *, rows=None, events=True):
        import autostream_config
        from autostream_backend_events import ConnectInfo
        from autostream_state.outputs import get_authority
        from webui.browser.setup.cards_customise import _setup_customise_card_html
        from fake_store import FakeStore
        from output_fakes import homepods_row

        parsed = autostream_config.parse_config(
            {"outputs": {"speaker_volume_applies_to_all": on}}, high_perf=False)
        FakeStore().outputs([homepods_row(1)] if rows is None else rows)
        if events:
            caps = frozenset({"device_volume", "receiver_command"})
            get_authority().on_connected(ConnectInfo("b0", 1, caps, "unix_socket"))
            get_authority().step(now=1000.0)
        return _setup_customise_card_html(parsed)

    @staticmethod
    def _row(html):
        start = html.rindex('<div class="setup-customise-row"', 0, html.index('id="outputs_speaker_volume_applies_to_all"'))
        return html[start:html.index("</div>", start)]

    @staticmethod
    def _input(html):
        start = html.index('<input type="checkbox" name="outputs_speaker_volume_applies_to_all"')
        return html[start:html.index(">", start)]

    def test_the_label_and_help_are_the_agreed_text_without_a_dash(self):
        html = self._card().replace("&#x27;", "'")
        assert self.LABEL in html and self.HELP in html
        row = html[html.index(self.LABEL):]
        assert "\u2014" not in row and "&mdash;" not in row
        self._card().encode("latin-1")

    def test_it_is_checked_only_when_the_setting_is_on(self):
        assert " checked" in self._input(self._card(True))
        assert " checked" not in self._input(self._card(False))

    def test_the_input_saves_the_field_on_change(self):
        tag = self._input(self._card())
        assert "settingsSaveField('outputs.speaker_volume_applies_to_all', this.checked)" in tag
        assert "liveEnabled" not in tag

    def test_it_is_enabled_when_the_player_reports_device_events(self):
        html = self._card()
        assert " disabled" not in self._input(html)
        assert "opacity:0.4" not in self._row(html)

    def test_an_older_player_disables_it_with_the_version_text(self):
        from output_fakes import row
        html = self._card(rows=[row(1)], events=False)
        assert " disabled" in self._input(html)
        assert "opacity:0.4" in self._row(html)
        assert self.VERSION in html
        assert self.HELP not in html

    def test_a_closed_event_channel_disables_it_with_the_channel_text(self):
        html = self._card(events=False)
        assert " disabled" in self._input(html)
        assert self.EVENTS in html.replace("&#x27;", "'")
        assert self.VERSION not in html

    def test_a_stored_on_shows_checked_but_disabled_without_the_channel(self):
        tag = self._input(self._card(True, events=False))
        assert " checked" in tag and " disabled" in tag

    def test_the_row_comes_after_the_pause_row(self):
        html = self._card()
        assert html.index('id="device_pause_scope"') < html.index('id="outputs_speaker_volume_applies_to_all"')
