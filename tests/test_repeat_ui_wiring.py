"""tests/test_repeat_ui_wiring.py

Acceptance tests for the repeat-feature web UI.

The recorder tap sits PRE-DSP and replay applies the origin input's live
gain/EQ plus the shared OutputProcessor, so input gain/EQ cards and the
equaliser page's panes are never wrapped, greyed, or banner'd during replay --
TestSetupAudioControlsRepeatLock and TestEqualiserRepeatLock assert that
absence. The home page carries a single small-format "repeat button"
(#repeat-btn/updateRepeatButton/onRepeatButtonClick) in the top controls row,
styled like the appliance-selector button, with a blue active-outline when
armed/replaying; there is no separate Refresh button and no larger repeat
pill. No user-VISIBLE wording anywhere in the repeat UI uses
"recording"/"Recording" or a pulsing red dot -- copy is neutral "repeat
buffer"/"buffering" phrasing (internal API field names such as
repeat.recording.bytes are unchanged and are NOT what these wording tests
check).

Covers:
  - Setup page (/setup) Playback panel: enable checkbox ("Enable repeat
    playback"), max-buffer-time note hook, unavailable-reason note hook.
    The codec selector is not present in the UI at all -- repeat.codec
    remains a config-file/API-only setting.
  - Setup page: input gain/EQ cards are never wrapped/greyed/banner'd.
  - Setup page + home page: no user-visible "recording"/"Recording" wording
    anywhere in the repeat UI markup.
  - Home page (/): no Refresh button; repeat button rendered only when
    repeat.enabled, JS wiring into refreshStatus()/onRepeatButtonClick(),
    disabled/label/active-outline states.
  - Equaliser page (/equaliser): no repeat-replay-lock poll/banner.
"""
from __future__ import annotations

import io
import json
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)


# ---------------------------------------------------------------------------
# Setup page (P9) -- reuses the full-config-file rendering harness style of
# test_wp4c_setup_ui_wiring.py so parsed.repeat comes from real parse_config().
# ---------------------------------------------------------------------------

def _minimal_cfg(
    tmp_path: Path,
    *,
    repeat_enabled: bool = False,
    repeat_codec: str = "auto",
    repeat_target_minutes: int = 33,
    minimum_playback_seconds: int = 30,
) -> Path:
    cfg = tmp_path / "autostream.json"
    cfg.write_text(json.dumps({
        "general": {"log_level": "info", "silence_seconds": 30,
                    "minimum_playback_seconds": minimum_playback_seconds},
        "owntone": {
            "base_url": "http://localhost:3689",
            "output_name": "Test Speaker",
            "volume_percent": 50,
        },
        "audio1": {
            "capture_device": "hw:1,0", "gain_db": 0,
            "eq_40hz_db": 0, "eq_100hz_db": 0, "eq_8khz_db": 0, "turntable": False,
        },
        "audio2": {
            "capture_device": "hw:2,0", "gain_db": 0,
            "eq_40hz_db": 0, "eq_100hz_db": 0, "eq_8khz_db": 0,
            "turntable": False, "enabled": False,
        },
        "track_identification": {
            "enabled": False, "analysis_lead_in_seconds": 5,
            "refresh_seconds": 300, "track_change_silence_seconds": 2.0,
        },
        "webui": {
            "dark_mode": False, "show_master_volume": True, "show_input_detail": False,
            "show_hostname_on_home": False, "control_other_appliances": False,
            "output_usage_poll_interval_seconds": 3,
        },
        "updates": {"auto_update": False, "update_channel": "stable"},
        "repeat": {
            "enabled": repeat_enabled,
            "codec": repeat_codec,
            "target_minutes": repeat_target_minutes,
        },
    }), encoding="utf-8")
    return cfg


def _render_setup_page(
    tmp_path: Path,
    *,
    repeat_enabled: bool = False,
    repeat_codec: str = "auto",
    repeat_target_minutes: int = 33,
    minimum_playback_seconds: int = 30,
) -> str:
    from autostream_webui_page_setup import send_setup_page
    from autostream_settings import SettingsStore
    from autostream_webui_state import WebUIState
    from autostream_players import ListOutputsResult

    cfg = _minimal_cfg(
        tmp_path,
        repeat_enabled=repeat_enabled,
        repeat_codec=repeat_codec,
        repeat_target_minutes=repeat_target_minutes,
        minimum_playback_seconds=minimum_playback_seconds,
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
    return handler.wfile.getvalue().decode("utf-8", errors="replace")


class TestSetupCustomiseRepeatControls:
    """Despite the class name (kept to minimise churn), these controls
    live in the Playback panel, not Personalisation/Customise."""

    def test_enable_checkbox_present_unchecked_by_default(self, tmp_path):
        html = _render_setup_page(tmp_path, repeat_enabled=False)
        assert 'id="repeat_enabled"' in html
        assert 'name="repeat_enabled"' in html
        assert 'id="repeat_enabled"  checked' not in html

    def test_enable_checkbox_checked_when_enabled(self, tmp_path):
        html = _render_setup_page(tmp_path, repeat_enabled=True)
        assert 'id="repeat_enabled"  checked' in html

    def test_enable_checkbox_wired_to_settings_save_field(self, tmp_path):
        html = _render_setup_page(tmp_path)
        assert 'onchange="onRepeatEnabledToggle(this.checked)"' in html
        assert "function onRepeatEnabledToggle(checked)" in html
        assert "settingsSaveField('repeat.enabled', checked)" in html

    def test_enable_checkbox_label_is_repeat_playback(self, tmp_path):
        html = _render_setup_page(tmp_path)
        assert "Enable repeat playback" in html
        assert "Enable repeat buffering" not in html

    def test_enable_checkbox_rendered_in_playback_panel(self, tmp_path):
        html = _render_setup_page(tmp_path)
        playback_panel = html.split('id="panel-playback"', 1)[1].split('id="panel-track-id"', 1)[0]
        assert 'id="repeat_enabled"' in playback_panel
        customise_panel = html.split('id="panel-customise"', 1)[1].split('id="panel-system"', 1)[0]
        assert 'id="repeat_enabled"' not in customise_panel

    def test_codec_select_removed_from_ui(self, tmp_path):
        html = _render_setup_page(tmp_path)
        assert 'id="repeat_codec"' not in html
        assert "settingsSaveField('repeat.codec'" not in html
        assert 'id="repeat-codec-row"' not in html

    def test_enable_toggle_wrapper_retries_and_clears_on_disable(self, tmp_path):
        html = _render_setup_page(tmp_path)
        # Retry loop: bounded attempts, stopping early once the note populates.
        assert "maxAttempts" in html
        assert "refreshRepeatSetupNote().then(function(ok)" in html
        # Overlapping-toggle guard.
        assert "_repeatToggleToken" in html
        # Disable path clears both notes rather than leaving a stale value.
        assert "if (!checked) {" in html
        assert "function onRepeatEnabledToggle(checked)" in html
        toggle_start = html.find("function onRepeatEnabledToggle(checked)")
        toggle_body = html[toggle_start:toggle_start + 800]
        assert "noteEl.textContent = ''" in toggle_body
        assert "unavailEl.style.display = 'none'" in toggle_body

    def test_refresh_note_returns_populated_flag(self, tmp_path):
        html = _render_setup_page(tmp_path)
        assert "return false" in html
        assert "return populated" in html

    def test_max_recording_time_note_hook_present(self, tmp_path):
        html = _render_setup_page(tmp_path)
        assert 'id="repeat-max-time-note"' in html

    def test_unavailable_note_hook_present_and_initially_hidden(self, tmp_path):
        html = _render_setup_page(tmp_path)
        assert 'id="repeat-unavailable-note"' in html
        assert "repeat-unavailable-note\" style=\"display:none;" in html

    def test_refresh_note_fetches_status_on_panel_open(self, tmp_path):
        html = _render_setup_page(tmp_path)
        assert "refreshRepeatSetupNote()" in html
        assert "id === 'playback'" in html
        assert "fetch('/api/status'" in html

    def test_unavailable_reason_message_text_present_in_js(self, tmp_path):
        html = _render_setup_page(tmp_path)
        assert "Repeat unavailable: insufficient free memory" in html

    def test_note_updates_from_max_recording_seconds_alone_not_recording_active(self, tmp_path):
        """The note's gate must be "maxSecs > 0" against
        repeat.max_recording_seconds alone -- NOT additionally conditioned on
        repeat.recording.active. The daemon now reports a real (nonzero)
        max_recording_seconds whenever repeat.enabled is true, including at
        idle (no recording in progress), specifically so this note stops
        being stuck at its "-" placeholder forever until a recording starts.
        The JS itself was already written this way; this test guards against
        a future change re-coupling the note to recording.active."""
        html = _render_setup_page(tmp_path)
        assert "var maxSecs = Number(repeat.max_recording_seconds)" in html
        assert "Number.isFinite(maxSecs) && maxSecs > 0" in html
        # The note logic must not gate on recording state at all.
        assert "repeat.recording.active" not in html


class TestSetupBufferTargetSelect:
    """The buffer-target dropdown (Vinyl 33 / CD 80) added under the "Enable
    repeat playback" toggle row."""

    def test_select_present_with_both_options(self, tmp_path):
        html = _render_setup_page(tmp_path)
        assert 'id="repeat_target_minutes"' in html
        assert 'name="repeat_target_minutes"' in html
        assert '<option value="33"' in html
        assert 'Vinyl (33 minutes)' in html
        assert '<option value="80"' in html
        assert 'CD (80 minutes)' in html

    def test_vinyl_selected_for_default_33(self, tmp_path):
        html = _render_setup_page(tmp_path, repeat_target_minutes=33)
        select_html = html.split('id="repeat_target_minutes"', 1)[1].split('</select>', 1)[0]
        assert '<option value="33" selected>' in select_html
        assert '<option value="80" selected>' not in select_html

    def test_cd_selected_for_80(self, tmp_path):
        html = _render_setup_page(tmp_path, repeat_target_minutes=80)
        select_html = html.split('id="repeat_target_minutes"', 1)[1].split('</select>', 1)[0]
        assert '<option value="80" selected>' in select_html
        assert '<option value="33" selected>' not in select_html

    def test_custom_option_rendered_for_out_of_band_config_value(self, tmp_path):
        """A config-file value outside {33, 80} must still render (selected)
        as a third "Custom" option -- config-file freedom stays visible
        without offering a way to pick a custom value from the UI itself."""
        html = _render_setup_page(tmp_path, repeat_target_minutes=45)
        select_html = html.split('id="repeat_target_minutes"', 1)[1].split('</select>', 1)[0]
        assert '<option value="45" selected>Custom (45 minutes)</option>' in select_html
        assert '<option value="33"' in select_html
        assert '<option value="33" selected>' not in select_html
        assert '<option value="80"' in select_html
        assert '<option value="80" selected>' not in select_html

    def test_select_disabled_when_repeat_disabled(self, tmp_path):
        html = _render_setup_page(tmp_path, repeat_enabled=False)
        select_tag = html.split('<select id="repeat_target_minutes"', 1)[1].split('>', 1)[0]
        assert 'disabled' in select_tag

    def test_select_enabled_when_repeat_enabled(self, tmp_path):
        html = _render_setup_page(tmp_path, repeat_enabled=True)
        select_tag = html.split('<select id="repeat_target_minutes"', 1)[1].split('>', 1)[0]
        assert 'disabled' not in select_tag

    def test_row_dimmed_when_repeat_disabled(self, tmp_path):
        html = _render_setup_page(tmp_path, repeat_enabled=False)
        assert 'id="repeat-target-row"' in html
        row_tag = html.split('id="repeat-target-row"', 1)[1].split('>', 1)[0]
        assert 'opacity:0.4' in row_tag

    def test_onchange_saves_field(self, tmp_path):
        html = _render_setup_page(tmp_path)
        assert 'onchange="onRepeatTargetChange(this.value)"' in html
        assert "function onRepeatTargetChange(value)" in html
        assert "settingsSaveField('repeat.target_minutes', parseInt(value, 10))" in html

    def test_onchange_reuses_shared_poll_helper(self, tmp_path):
        html = _render_setup_page(tmp_path)
        assert "function pollRepeatNote()" in html
        change_start = html.find("function onRepeatTargetChange(value)")
        assert change_start != -1
        change_body = html[change_start:change_start + 200]
        assert "pollRepeatNote()" in change_body

    def test_toggle_handler_flips_select_disabled_state(self, tmp_path):
        html = _render_setup_page(tmp_path)
        toggle_start = html.find("function onRepeatEnabledToggle(checked)")
        assert toggle_start != -1
        toggle_body = html[toggle_start:toggle_start + 800]
        assert "getElementById('repeat_target_minutes')" in toggle_body
        assert "targetSelect.disabled = !checked" in toggle_body
        assert "getElementById('repeat-target-row')" in toggle_body


class TestSetupAudioControlsRepeatLock:
    """Replay applies the origin input's live gain/EQ, so these
    controls are never inert during replay -- the lock/banner/poll machinery
    must be completely absent, regardless of repeat.enabled."""

    def test_audio_controls_not_wrapped_in_lockable_class(self, tmp_path):
        html = _render_setup_page(tmp_path)
        assert 'class="repeat-lockable"' not in html
        assert "audio_controls_card_1" not in html
        assert "audio_controls_card_2" not in html

    def test_repeat_replay_banner_absent(self, tmp_path):
        html = _render_setup_page(tmp_path)
        assert "repeat-replay-banner" not in html
        assert "settings are applied at recording time" not in html

    def test_apply_repeat_replay_lock_js_absent_when_enabled(self, tmp_path):
        html = _render_setup_page(tmp_path, repeat_enabled=True)
        assert "function applyRepeatReplayLock(active)" not in html
        assert "repeat-replay-lock" not in html

    def test_repeat_lock_poll_absent_when_enabled(self, tmp_path):
        html = _render_setup_page(tmp_path, repeat_enabled=True)
        assert "_pollRepeatLockState" not in html

    def test_repeat_lock_poll_absent_when_disabled(self, tmp_path):
        html = _render_setup_page(tmp_path, repeat_enabled=False)
        assert "_pollRepeatLockState" not in html
        assert "function applyRepeatReplayLock(active)" not in html


# ---------------------------------------------------------------------------
# Home page (P10)
# ---------------------------------------------------------------------------

_LOCAL_ID = "00000000000000000000"


def _make_parsed(*, repeat_enabled: bool = True, repeat_codec: str = "auto"):
    parsed = MagicMock()
    parsed.owntone.base_url = "http://localhost:3689"
    parsed.owntone.output_name = "autostream"
    parsed.owntone.volume_percent = 20
    parsed.webui.show_master_volume = True
    parsed.webui.show_input_detail = False
    parsed.webui.show_hostname_on_home = False
    parsed.webui.control_other_appliances = False
    parsed.webui.hidden_outputs = []
    parsed.webui.dark_mode = False
    parsed.track_identification = MagicMock(enabled=False)
    parsed.repeat.enabled = repeat_enabled
    parsed.repeat.codec = repeat_codec
    return parsed


def _make_playback_snapshot():
    snap = MagicMock()
    snap.inputs = {}
    snap.stylus_banner_text = ""
    snap.belt_banner_text = ""
    snap.bearing_banner_text = ""
    snap.has_warning = False
    snap.to_public_dict.return_value = {}
    return snap


def _render_airplay_page(*, repeat_enabled: bool = True) -> str:
    from autostream_webui_page_airplay import send_airplay_page
    from track_id.models import disabled_snapshot

    handler = MagicMock()
    chunks: list = []
    handler.wfile.write = lambda d: chunks.append(d)
    handler._csrf_token = "testcsrf"
    handler._pending_set_cookies = []

    auth = MagicMock()
    auth.get_csrf_token.return_value = "testcsrf"

    state = MagicMock()
    state.config_path = "dummy.ini"

    parsed = _make_parsed(repeat_enabled=repeat_enabled)
    playback = _make_playback_snapshot()
    list_result = MagicMock(ok=False, outputs=[])
    buf_result = MagicMock(ok=True, value="2250")

    patches = [
        patch("autostream_webui_page_airplay._config_snapshot", return_value=parsed),
        patch("autostream_webui_page_airplay.get_appliance_id", return_value=_LOCAL_ID),
        patch("autostream_webui_page_airplay.get_all_appliances", return_value=[]),
        patch("autostream_webui_page_airplay.get_system_hostname", return_value="autostream"),
        patch("autostream_webui_page_airplay.get_monitor_levels_dbfs", return_value=[]),
        patch("autostream_webui_page_airplay.get_playback_snapshot", return_value=playback),
        patch("autostream_webui_page_airplay.list_outputs", return_value=list_result),
        patch("autostream_webui_page_airplay.get_setting", return_value=buf_result),
        patch("autostream_core.get_active_track_identification_snapshot",
              return_value=disabled_snapshot()),
        patch("autostream_webui_page_airplay.build_top_banner_html", return_value=("", "")),
    ]

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        send_airplay_page(handler, state, auth)

    return b"".join(chunks).decode("utf-8", errors="replace")


class TestTopControlsCssRegressions:
    """Two CSS regressions in the top controls row.

    1. .pill-btn { display: inline-block } is an author-origin rule, which
       beats the UA stylesheet's [hidden] { display: none } regardless of
       specificity -- so without an explicit [hidden] override the remote
       repeat pill (shown/hidden purely via the hidden attribute) can never
       be hidden.
    2. The appliance selector's right-justification must not depend on
       justify-content: space-between having a second flex item: with the
       repeat pill omitted (local, repeat disabled) or hidden (remote),
       a lone item is placed at main-start, i.e. flush left.
    """

    def test_hidden_pill_btn_has_display_none_override(self):
        html = _render_airplay_page(repeat_enabled=True)
        assert ".pill-btn[hidden]" in html
        override = html.split(".pill-btn[hidden]", 1)[1].split("}", 1)[0]
        assert "display: none" in override

    def test_appliance_selector_right_anchored_independently(self):
        html = _render_airplay_page(repeat_enabled=False)
        assert ".airplay-top-controls > .appliance-selector" in html
        rule = html.split(
            ".airplay-top-controls > .appliance-selector", 1
        )[1].split("}", 1)[0]
        # Must cover the display-only span fallback root as well.
        assert ".airplay-top-controls > .appliance-selector-btn" in rule
        assert "margin-left: auto" in rule


class TestHomeRefreshButtonRemoved:
    """A dedicated Refresh button would only reload the page, redundant with the
    1.5 s poll -- there is no such button, regardless of repeat.enabled."""

    def test_refresh_button_absent_when_repeat_enabled(self):
        html = _render_airplay_page(repeat_enabled=True)
        assert "Reload page to refresh speakers" not in html
        assert "↻ Refresh" not in html
        assert "onclick='location.reload();'" not in html

    def test_refresh_button_absent_when_repeat_disabled(self):
        html = _render_airplay_page(repeat_enabled=False)
        assert "Reload page to refresh speakers" not in html
        assert "↻ Refresh" not in html


class TestHomeRepeatPillRemoved:
    """A larger repeat pill (arm/disarm toggle + label/detail spans +
    pulsing red dot) is not part of the UI -- only the small repeat button is."""

    def test_pill_markup_absent(self):
        html = _render_airplay_page(repeat_enabled=True)
        assert 'id="repeat-pill"' not in html
        assert 'id="repeat-pill-label"' not in html
        assert 'id="repeat-pill-detail"' not in html
        assert 'id="repeat-armed-toggle"' not in html
        assert "onRepeatArmedToggle" not in html
        assert "updateRepeatPill" not in html

    def test_red_dot_markup_and_css_hook_absent(self):
        html = _render_airplay_page(repeat_enabled=True)
        assert "repeat-rec-dot" not in html


class TestHomeRepeatButton:
    """Single small-format repeat button in the top controls row,
    styled like the appliance-selector button, driven by the existing
    1.5 s refreshStatus() poll (d.repeat)."""

    def test_button_rendered_when_repeat_enabled(self):
        html = _render_airplay_page(repeat_enabled=True)
        assert 'id="repeat-btn"' in html

    def test_button_absent_when_repeat_disabled(self):
        html = _render_airplay_page(repeat_enabled=False)
        assert 'id="repeat-btn"' not in html

    def test_button_default_label_and_disabled_with_no_buffer(self):
        html = _render_airplay_page(repeat_enabled=True)
        assert "↻ Repeat Play" in html
        # Server-rendered default (before the first poll lands): no buffer
        # known yet, so the button starts disabled.
        assert '<button type="button" class="pill-btn small repeat-btn" id="repeat-btn"' in html
        assert "disabled" in html.split('id="repeat-btn"', 1)[1].split(">", 1)[0]

    def test_button_click_wired_to_post_api_repeat(self):
        html = _render_airplay_page(repeat_enabled=True)
        assert "onRepeatButtonClick()" in html
        assert "fetch(window.__REPEAT_URL || '/api/repeat'" in html
        assert "armed: newArmed" in html

    def test_refresh_status_calls_update_repeat_button(self):
        html = _render_airplay_page(repeat_enabled=True)
        assert "updateRepeatButton(d)" in html
        assert "updateRepeatPill" not in html

    def test_update_repeat_button_hides_when_repeat_absent_or_disabled(self):
        html = _render_airplay_page(repeat_enabled=True)
        assert (
            "if (!repeat || !repeat.enabled) {\n"
            "      btn.hidden = true;\n"
            "      __repeatOptimistic = null;\n"
            "      _setRepeatStopping(false);\n"
            "      return;\n"
            "    }" in html
        )

    def test_update_repeat_button_gates_disabled_on_buffer_bytes(self):
        html = _render_airplay_page(repeat_enabled=True)
        assert "var hasBuffer = Number(recording.bytes || 0) > 0;" in html
        assert "btn.disabled = stopping || (!hasBuffer && !replaying && !on);" in html

    def test_update_repeat_button_uses_replay_last_label_when_idle_with_buffer(self):
        html = _render_airplay_page(repeat_enabled=True)
        assert "↻ Replay Last" in html
        assert "btn.textContent = stopping ? 'Stopping…' : (showReplayLast ? '↻ Replay Last' : '↻ Repeat Play');" in html

    def test_update_repeat_button_applies_active_outline_when_armed_or_replaying(self):
        html = _render_airplay_page(repeat_enabled=True)
        assert "var polledOn = replaying || armed;" in html
        assert "btn.classList.toggle('active', on || stopping);" in html
        assert ".repeat-btn.active" in html or "repeat-btn.active" in html

    def test_update_repeat_button_shows_progress_and_truncated_hint_in_title(self):
        html = _render_airplay_page(repeat_enabled=True)
        assert "if (recording.truncated_head) title += ' · tail only';" in html
        assert "btn.title = title;" in html

    def test_click_handler_stops_replay_or_disarms_or_arms(self):
        html = _render_airplay_page(repeat_enabled=True)
        assert "var newArmed = (state === 'repeating' || state === 'armed') ? false : true;" in html

    def test_click_handler_reverts_active_state_on_post_failure(self):
        html = _render_airplay_page(repeat_enabled=True)
        assert "var wasActive = btn.classList.contains('active');" in html
        assert "btn.classList.toggle('active', wasActive);" in html


class TestRepeatUiWordingRegression:
    """No user-VISIBLE "recording"/"Recording"
    strings anywhere in the repeat UI markup of the home or setup pages.
    Internal API field names (repeat.recording.bytes, repeat.max_recording_seconds,
    etc.) are explicitly exempt -- this test strips known internal-field-name
    occurrences before asserting, so it only catches user-facing wording."""

    _INTERNAL_FIELD_TOKENS = (
        "var recording = repeat.recording",
        "repeat.recording",
        "recording.bytes",
        "recording.active",
        "recording.truncated_head",
        "recording.unavailable_reason",
        "recording.origin_input",  # replay-origin resolution for track-ID display
        "repeat.max_recording_seconds",
    )

    @staticmethod
    def _strip_internal_tokens(html: str) -> str:
        stripped = html
        for token in TestRepeatUiWordingRegression._INTERNAL_FIELD_TOKENS:
            stripped = stripped.replace(token, "")
        return stripped

    def test_home_page_has_no_user_visible_recording_wording(self):
        html = _render_airplay_page(repeat_enabled=True)
        stripped = self._strip_internal_tokens(html)
        assert "Recording" not in stripped
        assert "recording" not in stripped

    def test_setup_page_has_no_user_visible_recording_wording(self, tmp_path):
        html = _render_setup_page(tmp_path, repeat_enabled=True)
        stripped = self._strip_internal_tokens(html)
        assert "Recording" not in stripped
        assert "recording" not in stripped


# ---------------------------------------------------------------------------
# Equaliser page (P10)
# ---------------------------------------------------------------------------

def _render_equaliser_page(*, repeat_enabled: bool = True) -> str:
    from autostream_webui_page_equaliser import send_equaliser_page

    handler = MagicMock()
    chunks: list = []
    handler.wfile.write = lambda d: chunks.append(d)
    handler._csrf_token = "testcsrf"

    parsed = MagicMock()
    parsed.webui.dark_mode = False
    parsed.webui.show_hostname_on_home = False
    parsed.webui.control_other_appliances = False
    parsed.repeat.enabled = repeat_enabled
    output_eq = MagicMock()
    output_eq.gain_db = 0.0
    output_eq.auto_trim_enabled = False
    for key in ("peq1_db", "peq2_db", "peq3_db", "peq4_db", "peq5_db", "peq6_db"):
        setattr(output_eq, key, 0.0)
    parsed.output_eq = output_eq

    state = MagicMock()
    state.config_path = "dummy.ini"

    patches = [
        patch("autostream_webui_page_equaliser._config_snapshot", return_value=parsed),
        patch("autostream_webui_page_equaliser.get_appliance_id", return_value=_LOCAL_ID),
        patch("autostream_webui_page_equaliser.get_all_appliances", return_value=[]),
        patch("autostream_webui_page_equaliser.get_system_hostname", return_value="autostream"),
        patch("autostream_webui_page_equaliser.build_top_banner_html", return_value=("", "")),
    ]

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        send_equaliser_page(handler, state)

    return b"".join(chunks).decode("utf-8", errors="replace")


class TestEqualiserRepeatLock:
    """Replay applies both the origin input's live gain/EQ and
    this page's output EQ/gain via the shared OutputProcessor, so the EQ
    panes are never inert during replay -- the lock/banner/poll machinery
    must be completely absent, regardless of repeat.enabled."""

    def test_eq_panes_not_wrapped_in_lockable_container(self):
        html = _render_equaliser_page()
        assert "repeat-lockable" not in html

    def test_repeat_replay_banner_text_absent(self):
        html = _render_equaliser_page()
        assert "EQ unavailable during repeat playback" not in html
        assert "settings are applied at recording time" not in html

    def test_repeat_lock_poll_absent_when_enabled(self):
        html = _render_equaliser_page(repeat_enabled=True)
        assert "_pollRepeatLockState" not in html
        assert "applyRepeatReplayLock" not in html

    def test_repeat_lock_poll_absent_when_disabled(self):
        html = _render_equaliser_page(repeat_enabled=False)
        assert "_pollRepeatLockState" not in html
        assert "applyRepeatReplayLock" not in html


class TestSilenceSliderHoldGuidance:
    """The silence slider carries guidance that short timeouts are safe when
    the minimum playback hold is active; hidden when the hold is disabled."""

    def test_note_present_with_hold_value(self, tmp_path):
        html = _render_setup_page(tmp_path)
        assert "continues for at least 30s" in html
        assert "short settings (5-10s)" in html

    def test_note_reflects_configured_hold(self, tmp_path):
        html = _render_setup_page(tmp_path, minimum_playback_seconds=45)
        assert "continues for at least 45s" in html

    def test_note_hidden_when_hold_disabled(self, tmp_path):
        html = _render_setup_page(tmp_path, minimum_playback_seconds=0)
        assert "continues for at least" not in html
        assert "short settings (5-10s)" not in html
