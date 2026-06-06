#!/usr/bin/env python3
"""autostream_webui_page_setup.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Renderer for the main Setup page (/setup).

Contents:
  - _audio_controls_card_html -- render the gain/EQ sliders card for an input
  - send_setup_page           -- render and send the /setup page
"""

from __future__ import annotations

import html
import logging

from typing import Optional
from urllib.parse import parse_qs

from autostream_config import (
    CONFIG_IO_LOCK,
    mark_configured,
    parse_config,
    unconfigured,
)
from autostream_core import (
    update_live_owntone_runtime,
    update_playback_input_config,
)
from autostream_player_service import list_outputs
from autostream_playback_stats import (
    suggested_silence_threshold_dbfs,
)
from autostream_sysutils import get_ap_ssid, get_system_hostname, set_system_hostname
from autostream_webui_assets import (
    A2HS_SCRIPT,
    BANNER_HTML,
    COMMON_MODAL_CSS,
    PIN_MODAL_CSS,
)
from autostream_webui_common import (
    _set_flash_cookie,
    build_page_html,
    build_top_banner_html,
    get_app_version,
    locked_load_config,
    settings_card_html,
)
from autostream_webui_state import WebUIState


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _setup_page_header(title: str) -> str:
    return (
        "<div class='eq-page-header'>"
        "<div style='display:flex;align-items:center;gap:0.5rem;'>"
        f"<h1>{html.escape(title)}</h1>"
        "</div>"
        "</div>"
    )


def _setup_detail_header(title: str) -> str:
    return _setup_page_header(title)


def _audio_controls_card_html(
    *,
    input_index: int,
    gain_db: float,
    eq_40hz_db: float,
    eq_100hz_db: float,
    eq_10khz_db: float,
) -> str:
    prefix = f"audio{input_index}"
    inner_html = f"""
      <label><div class="slider-header"><span>Gain:</span><span id="{prefix}_gain_db_val">{gain_db:.0f} dB</span></div>
      <input type="range" min="-10" max="10" step="1" id="{prefix}_gain_db" name="{prefix}_gain_db" value="{gain_db:.0f}" oninput="syncGain({input_index}, this.value)"></label>
      <div class="slider-header" style="margin-top:.75rem;align-items:center;">
        <strong>Equaliser</strong>
      </div>
      <div class="eq-bands-wrap" style="margin-top:0.5rem;">
        <div class="eq-bands-row">
          <div class="eq-band">
            <span class="eq-band-freq">40Hz</span>
            <input
              type="range"
              class="eq-band-slider"
              min="-10"
              max="10"
              step="1"
              id="{prefix}_eq_40hz_db"
              name="{prefix}_eq_40hz_db"
              value="{eq_40hz_db:.0f}"
              aria-label="40Hz equaliser"
              oninput="syncEq({input_index}, '40hz', this.value)">
            <span class="eq-band-val" id="{prefix}_eq_40hz_db_val">{eq_40hz_db:.0f} dB</span>
          </div>
          <div class="eq-band">
            <span class="eq-band-freq">Bass</span>
            <input
              type="range"
              class="eq-band-slider"
              min="-10"
              max="10"
              step="1"
              id="{prefix}_eq_100hz_db"
              name="{prefix}_eq_100hz_db"
              value="{eq_100hz_db:.0f}"
              aria-label="Bass equaliser"
              oninput="syncEq({input_index}, '100hz', this.value)">
            <span class="eq-band-val" id="{prefix}_eq_100hz_db_val">{eq_100hz_db:.0f} dB</span>
          </div>
          <div class="eq-band">
            <span class="eq-band-freq">Treble</span>
            <input
              type="range"
              class="eq-band-slider"
              min="-10"
              max="10"
              step="1"
              id="{prefix}_eq_10khz_db"
              name="{prefix}_eq_10khz_db"
              value="{eq_10khz_db:.0f}"
              aria-label="Treble equaliser"
              oninput="syncEq({input_index}, '10khz', this.value)">
            <span class="eq-band-val" id="{prefix}_eq_10khz_db_val">{eq_10khz_db:.0f} dB</span>
          </div>
        </div>
      </div>
    """
    return settings_card_html(inner_html)



# -----------------------------------------------------------------------------
# Page renderer
# -----------------------------------------------------------------------------

def send_setup_page(
    handler,
    state: WebUIState,
    auth,
    saved_ok: bool = False,
    error: Optional[str] = None,
    flash_msg: Optional[str] = None,
    flash_type: str = "success",
) -> None:
    """Render the main setup page."""
    try:
        cfg = locked_load_config(state.config_path)
        parsed = parse_config(cfg)
    except Exception:
        try:
            handler.send_response(302)
            handler.send_header("Location", "/")
            handler.end_headers()
        except Exception:
            pass
        return

    initial_setup = unconfigured(state.config_path)
    h1 = "Initial Setup (2 of 2)" if initial_setup else "Setup"
    submit_label = "Finish"
    setup_form_id = "setupForm"
    owntone_button_html = "" if initial_setup else """
          <button type="button"
            onclick="window.location.href='/owntone-setup';"
            class="pill-btn small"
            style="width:100%;margin-top:0.5rem;">
            More Owntone Settings
          </button>
        """
    update_html = "" if initial_setup else """
          <label>Updates:
            <div style="display:flex;align-items:center;margin-top:.5rem">
              <button type="button" id="btnCheck" class="pill-btn small" style="margin-right:auto">Check</button>
              <button type="button" id="btnInst" class="pill-btn small" style="margin:auto" disabled>Install</button>
              <button type="button" class="pill-btn small" style="margin-left:auto" onclick="requestReboot()">Reboot</button>
            </div>
            <div id="updMsg" style="font-size:0.8rem;margin-top:0.3rem;"></div>
          </label>
          <div style="margin-top:0.75rem;">
            <button type="button" id="btnChangePin" class="pill-btn small" style="width:100%;">Change PIN</button>
          </div>
        """

    monitor_devices = state.get_monitor_devices()

    def build_opts(cur):
        opts = ""
        found = False
        cur_str = str(cur).strip()
        for dev in monitor_devices:
            hw = str(dev.get("hw") or "").strip()
            if not hw:
                continue
            label = str(dev.get("label") or hw).strip()
            card = str(dev.get("card") or "").strip()
            card_short = card.split(", ")[0].strip() if card else hw
            sel = " selected" if hw == cur_str else ""
            if sel:
                found = True
            opts += (
                f"<option value='{html.escape(hw)}' data-card='{html.escape(card_short)}'{sel}>"
                f"{html.escape(label)}</option>"
            )
        if not found and cur:
            missing = html.escape(cur_str)
            opts = (
                f"<option value='{missing}' selected>"
                f"{missing} (not currently detected)</option>"
            ) + opts
        return opts

    def input_fieldset_html(
        *,
        input_index: int,
        title: str,
        parsed_input,
        capture_name: str,
        threshold_name: str,
        turntable_name: str,
        enabled: bool = True,
        enabled_name: Optional[str] = None,
    ) -> str:
        prefix = "audio1" if input_index == 1 else "audio2"
        threshold_id = "audio_silence_threshold" if input_index == 1 else "audio2_silence_threshold"
        turntable_note_id = f"{prefix}_turntable_note"
        settings_wrap_id = f"{prefix}_settings"
        is_turntable = bool(parsed_input.is_turntable)
        threshold_preset = suggested_silence_threshold_dbfs(is_turntable)

        enabled_html = ""
        wrap_style = "block" if enabled else "none"
        if enabled_name:
            enabled_html = f"""
          <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" name="{enabled_name}" {'checked' if enabled else ''} onchange="onAudio2Toggle(this.checked)">
              <span class="switch"></span>
            </label>
            <span>Enable</span>
          </div>
            """

        settings_open = "" if enabled_name is None else f"<div id=\"{settings_wrap_id}\" style=\"display:{wrap_style};\">"
        settings_close = "" if enabled_name is None else "</div>"

        inner_html = f"""
          {enabled_html}
          {settings_open}
            <label>Input device: <select name="{capture_name}">{build_opts(parsed_input.capture_device)}</select></label>
            <div style="display:flex;align-items:center;gap:0.75rem;margin-top:0.9rem;">
              <label class="output-toggle" style="margin:0;">
                <input type="checkbox" name="{turntable_name}" {'checked' if is_turntable else ''} onchange="syncInputUi({input_index})">
                <span class="switch"></span>
              </label>
              <span>Turntable</span>
            </div>
            <div id="{turntable_note_id}" class="helptext" style="text-align:left;">
              Detection threshold preset: {threshold_preset:.0f} dB
            </div>
            <input type="hidden" id="{threshold_id}" name="{threshold_name}" value="{threshold_preset}">
          {settings_close}
        """
        if initial_setup:
            return f"""
        <fieldset><legend>{html.escape(title)}</legend>
          {inner_html}
        </fieldset>
        """
        return settings_card_html(inner_html, margin_top="0")

    owntone_outputs_html = ""
    outputs_result = list_outputs(parsed.owntone.base_url, timeout=3)
    if outputs_result.ok:
        hidden = {str(n).strip().casefold() for n in (parsed.webui.hidden_outputs or ()) if str(n).strip()}
        for out in outputs_result.outputs:
            nm = str(out.name or "")
            if not nm:
                continue
            if nm.strip().casefold() in hidden and nm != parsed.owntone.output_name:
                continue
            sel = " selected" if nm == parsed.owntone.output_name else ""
            owntone_outputs_html += f"<option value='{html.escape(nm)}'{sel}>{html.escape(nm)}</option>"

    lic_html, lic_spacer = build_top_banner_html(flash_msg=flash_msg, flash_type=flash_type)
    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""
    csrf_meta = f"<meta name='csrf-token' content='{html.escape(csrf_token)}'><script>window.__CSRF='{html.escape(csrf_token)}';</script>"
    pin_modal_setup_css = """
      #pinModal .pin-entry {
        -webkit-text-security: disc;
        text-security: disc;
      }
    """

    # Factory reset danger zone — only shown outside initial setup
    factory_reset_modal_css = ""
    factory_reset_zone = ""
    factory_reset_modal = ""
    factory_reset_js = ""
    reboot_modal = ""
    if not initial_setup:
        ap_ssid = get_ap_ssid()
        pin_val = auth.get_boot_pin_value()
        safe_ssid = html.escape(ap_ssid)
        if pin_val:
            modal_body_html = (
                f"This will erase all settings, including WiFi settings, and reboot "
                f"the appliance.<br><br>After reboot, connect to the WiFi network "
                f"<strong>{safe_ssid}</strong> to reconfigure the appliance. "
                f"You will need the factory-configured PIN "
                f"(<strong>{html.escape(pin_val)}</strong>). "
                f"<br><br>Do you wish to continue?"
            )
        else:
            modal_body_html = (
                f"This will erase all settings, including WiFi settings, and then reboot "
                f"the appliance. After reboot, please connect to the WiFi network "
                f"<strong>{safe_ssid}</strong> to reconfigure the appliance. "
                f"You will need the factory-configured PIN. "
                f"Do you wish to continue?"
            )

        factory_reset_modal_css = """
          #factoryResetModal .modal-panel{--modal-width:28rem;--modal-bg:var(--color-surface-raised);}
          #factoryResetModal .modal-hdr{--modal-title-color:var(--color-status-danger);}
        """

        factory_reset_zone = f"""
      <div style="margin-top:2rem;padding:1rem 1.25rem;border:1.5px solid var(--color-status-danger);border-radius:8px;">
        <p style="margin:0 0 0.5rem;font-weight:600;color:var(--color-status-danger);">Factory Reset</p>
        <p style="margin:0 0 0.75rem;font-size:0.95rem;color:var(--color-text);">Factory Reset returns the appliance to first-run Wi-Fi setup mode. All settings will be erased.</p>
        <button type="button"
          id="btnFactoryReset"
          class="pill-btn"
          style="width:100%;color:#fff;"
          onclick="showFactoryResetModal()">
          Factory Reset
        </button>
      </div>"""

        factory_reset_modal = f"""
      <div id="factoryResetModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="factoryResetModalTitle">
        <div class="panel modal-panel">
          <div class="hdr modal-hdr" id="factoryResetModalTitle">Factory Reset</div>
          <div class="bd modal-bd">
            <p id="factoryResetModalMsg">{modal_body_html}</p>
            <p id="factoryResetModalError" style="display:none;color:var(--color-status-danger);font-weight:600;"></p>
          </div>
          <div class="ft modal-ft">
            <button type="button" class="btn modal-btn modal-btn-secondary" id="factoryResetCancel"
              onclick="hideFactoryResetModal()">Cancel</button>
            <button type="button" class="btn modal-btn modal-btn-danger" id="factoryResetContinue"
              onclick="doFactoryReset()">Continue</button>
          </div>
        </div>
      </div>"""

        reboot_modal = """
      <div id="rebootModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="rebootModalTitle">
        <div class="panel modal-panel">
          <div class="hdr modal-hdr" id="rebootModalTitle">Reboot System</div>
          <div class="bd modal-bd">
            <p>This will reboot autostream. Please allow 90 seconds for the system to restart.</p>
          </div>
          <div class="ft modal-ft">
            <button type="button" class="btn modal-btn modal-btn-secondary" id="rebootModalCancel"
              onclick="hideRebootModal()">Cancel</button>
            <button type="button" class="btn modal-btn modal-btn-primary" id="rebootModalOk"
              onclick="confirmReboot()">Reboot</button>
          </div>
        </div>
      </div>"""

        factory_reset_js = f"""
      <script>
        function showFactoryResetModal() {{
          const m = document.getElementById('factoryResetModal');
          if (m) m.classList.add('show');
        }}
        function hideFactoryResetModal() {{
          const m = document.getElementById('factoryResetModal');
          if (m) m.classList.remove('show');
        }}
        function showRebootModal() {{
          const m = document.getElementById('rebootModal');
          if (m) m.classList.add('show');
        }}
        function hideRebootModal() {{
          const m = document.getElementById('rebootModal');
          if (m) m.classList.remove('show');
        }}
        async function confirmReboot() {{
          hideRebootModal();
          try {{
            fetch("/api/reboot", {{
              method: "POST",
              headers: {{"X-CSRF-Token": window.__CSRF || ""}},
              cache: "no-store",
              keepalive: true
            }});
          }} catch (e) {{}}
          window.location.replace("/offline/rebooting");
        }}
        async function doFactoryReset() {{
          const cont = document.getElementById('factoryResetContinue');
          const canc = document.getElementById('factoryResetCancel');
          const errEl = document.getElementById('factoryResetModalError');
          if (cont) cont.disabled = true;
          if (canc) canc.disabled = true;
          try {{
            const r = await fetch('/api/factory-reset', {{
              method: 'POST',
              headers: {{
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-Token': window.__CSRF || ''
              }},
              body: 'csrf_token=' + encodeURIComponent(window.__CSRF || ''),
              keepalive: true
            }});
            let ok = false;
            try {{ const j = await r.json(); ok = !!(j && j.ok); }} catch (e) {{}}
            if (ok) {{
              window.location.replace('/offline/resetting');
            }} else {{
              if (errEl) {{ errEl.textContent = 'Reset could not be scheduled. Please try again.'; errEl.style.display = ''; }}
              if (cont) cont.disabled = false;
              if (canc) canc.disabled = false;
            }}
          }} catch (e) {{
            // Network error: the service may have already started resetting.
            window.location.replace('/offline/resetting');
          }}
        }}
      </script>"""

    input1_html = input_fieldset_html(
        input_index=1,
        title="Input 1",
        parsed_input=parsed.audio1,
        capture_name="audio_capture_device",
        threshold_name="audio_silence_threshold",
        turntable_name="audio_turntable",
    )
    input2_html = input_fieldset_html(
        input_index=2,
        title="Input 2",
        parsed_input=parsed.audio2,
        capture_name="audio2_capture_device",
        threshold_name="audio2_silence_threshold",
        turntable_name="audio2_turntable",
        enabled=parsed.audio2_enabled,
        enabled_name="audio2_enabled",
    )

    # Fieldset fragments shared by both layout paths
    playback_inner_html = f"""
          <label>Default Speakers:
            <select id="owntone_output_select" name="owntone_output_name">
              {owntone_outputs_html}
            </select>
            <div id="owntone_output_hint" class="helptext" style="display:none;">
              Looking for speakers\u2026
            </div>
          </label>
          <label><div class="slider-header"><span>Default Volume:</span><span id="vol_val">{parsed.owntone.volume_percent}%</span></div>
          <input type="range" min="0" max="100" value="{parsed.owntone.volume_percent}" oninput="syncVol(this.value)">
          <input type="hidden" id="owntone_volume_percent" name="owntone_volume_percent" value="{parsed.owntone.volume_percent}"></label>
          <label><div class="slider-header"><span>Silence detection:</span><span id="sil_val">{parsed.general.silence_seconds}s</span></div>
          <input type="range" name="silence_seconds" min="10" max="300" value="{parsed.general.silence_seconds}" oninput="syncSil(this.value)"></label>
          {owntone_button_html}
        """
    playback_fieldset_html = (
        f"<fieldset><legend>Playback</legend>{playback_inner_html}</fieldset>"
        if initial_setup else
        settings_card_html(playback_inner_html, margin_top="0")
    )
    system_inner_html = f"""
          <label style="display:flex;align-items:center;gap:.75rem;">
            <span>Hostname:</span><input style="flex:1" type="text" name="system_hostname" value="{html.escape(get_system_hostname())}">
          </label>
          {update_html}
        """
    system_fieldset_html = (
        f"<fieldset><legend>System (build: {html.escape(get_app_version())})</legend>{system_inner_html}</fieldset>"
        if initial_setup else
        settings_card_html(system_inner_html, margin_top="0")
    )

    # Build the form body content — flat for initial setup, slide-panel for post-config
    if initial_setup:
        form_content_html = f"""{input1_html}
        {input2_html}
        {playback_fieldset_html}
        {system_fieldset_html}
        <p class="actions"><button type="submit">{submit_label}</button></p>"""
    else:
        def _friendly(hw) -> str:
            """Return shortened card name for use in sub-labels (first segment before ', ')."""
            for d in monitor_devices:
                if str(d.get("hw") or "").strip() == str(hw or "").strip():
                    c = str(d.get("card") or "").strip()
                    return c.split(", ")[0].strip() if c else str(hw)
            return str(hw) if hw else "Not configured"

        dev1 = _friendly(parsed.audio1.capture_device)
        mode1 = "Turntable" if parsed.audio1.is_turntable else "Line In"
        gain1 = int(parsed.audio1.gain_db)
        gain1_str = f"{gain1:+d} dB" if gain1 != 0 else "0 dB"
        input1_summary = html.escape(f"{dev1} \u00b7 {mode1} \u00b7 {gain1_str}")
        if not parsed.audio2_enabled:
            input2_summary = "Disabled"
        else:
            dev2 = _friendly(parsed.audio2.capture_device)
            mode2 = "Turntable" if parsed.audio2.is_turntable else "Line In"
            gain2 = int(parsed.audio2.gain_db)
            gain2_str = f"{gain2:+d} dB" if gain2 != 0 else "0 dB"
            input2_summary = html.escape(f"{dev2} \u00b7 {mode2} \u00b7 {gain2_str}")
        speaker = str(parsed.owntone.output_name or "No speaker selected")
        playback_summary = html.escape(f"{speaker} \u00b7 {parsed.owntone.volume_percent}%")
        system_summary = html.escape(f"{get_system_hostname()} \u00b7 v{get_app_version()}")
        customise_summary = html.escape(
            ("Master volume: On" if parsed.webui.show_master_volume else "Master volume: Off")
            + (" \u00b7 Input detail: On" if parsed.webui.show_input_detail else " \u00b7 Input detail: Off")
            + (" \u00b7 Dark mode: On" if parsed.webui.dark_mode else " \u00b7 Dark mode: Off")
            + (" \u00b7 Hostname: On" if parsed.webui.show_hostname_on_home else " \u00b7 Hostname: Off")
        )
        customise_card_html = settings_card_html(f"""
              <input type="hidden" name="webui_show_master_volume_present" value="1">
              <div class="setup-customise-row" style="margin-top:0.5rem;">
                <label class="output-toggle" style="margin:0;">
                  <input type="checkbox" name="webui_show_hostname_on_home" id="webui_show_hostname_on_home"{'  checked' if parsed.webui.show_hostname_on_home else ''} onchange="refreshCustomiseCardSub()">
                  <span class="switch"></span>
                </label>
                <span>Display Hostname</span>
              </div>
              <div class="setup-customise-row" style="margin-top:0.75rem;">
                <label class="output-toggle" style="margin:0;">
                  <input type="checkbox" name="webui_show_master_volume" id="webui_show_master_volume"{'  checked' if parsed.webui.show_master_volume else ''} onchange="refreshCustomiseCardSub()">
                  <span class="switch"></span>
                </label>
                <span>Show Master Volume Control</span>
              </div>
              <div class="setup-customise-row" style="margin-top:0.75rem;">
                <label class="output-toggle" style="margin:0;">
                  <input type="checkbox" name="webui_show_input_detail" id="webui_show_input_detail"{'  checked' if parsed.webui.show_input_detail else ''} onchange="refreshCustomiseCardSub()">
                  <span class="switch"></span>
                </label>
                <span>Display Input Detail</span>
              </div>
              <div class="setup-customise-row" style="margin-top:0.75rem;">
                <label class="output-toggle" style="margin:0;">
                  <input type="checkbox" name="webui_dark_mode" id="webui_dark_mode"{'  checked' if parsed.webui.dark_mode else ''} onchange="refreshCustomiseCardSub()">
                  <span class="switch"></span>
                </label>
                <span>Dark Mode</span>
              </div>
            """, margin_top="0")
        form_content_html = f"""<div class="setup-slide-viewport">
      <div class="setup-slide-track" id="setupSlideTrack">
        <div class="setup-slide-list">
          {_setup_page_header("Setup")}
          <p class="actions" style="display:flex;margin-bottom:1rem;">
            <button type="submit" form="{setup_form_id}" class="pill-btn small" style="width:auto;">Save</button>
          </p>
          <div class="setup-list-card" onclick="openPanel('input1')">
            <div class="setup-list-card-body">
              <span class="setup-list-card-title">Input 1</span>
              <span class="setup-list-card-sub" id="input1-card-sub">{input1_summary}</span>
            </div>
            <span class="setup-list-chevron">\u203a</span>
          </div>
          <div class="setup-list-card" onclick="openPanel('input2')">
            <div class="setup-list-card-body">
              <span class="setup-list-card-title">Input 2</span>
              <span class="setup-list-card-sub" id="input2-card-sub">{input2_summary}</span>
            </div>
            <span class="setup-list-chevron">\u203a</span>
          </div>
          <div class="setup-list-card" onclick="openPanel('playback')">
            <div class="setup-list-card-body">
              <span class="setup-list-card-title">Playback</span>
              <span class="setup-list-card-sub">{playback_summary}</span>
            </div>
            <span class="setup-list-chevron">\u203a</span>
          </div>
          <div class="setup-list-card" onclick="openPanel('customise')">
            <div class="setup-list-card-body">
              <span class="setup-list-card-title">Personalisation</span>
              <span class="setup-list-card-sub" id="customise-card-sub">{customise_summary}</span>
            </div>
            <span class="setup-list-chevron">\u203a</span>
          </div>
          <div class="setup-list-card" onclick="openPanel('system')">
            <div class="setup-list-card-body">
              <span class="setup-list-card-title">System</span>
              <span class="setup-list-card-sub">{system_summary}</span>
            </div>
            <span class="setup-list-chevron">\u203a</span>
          </div>
          <div class="setup-list-card" onclick="openPanel('factory-reset')">
            <div class="setup-list-card-body">
              <span class="setup-list-card-title">Factory Reset</span>
              <span class="setup-list-card-sub">Erase all settings and return to Wi-Fi setup</span>
            </div>
            <span class="setup-list-chevron">\u203a</span>
          </div>
        </div>
        <div class="setup-slide-panels">
          <div class="setup-detail-panel" id="panel-input1">
            <div class="setup-detail-back">
              <button type="button" class="pill-btn small" onclick="closePanel()">\u2190 Back</button>
            </div>
            {_setup_detail_header("Setup Input 1")}
            {input1_html}
            {_audio_controls_card_html(
              input_index=1,
              gain_db=parsed.audio1.gain_db,
              eq_40hz_db=parsed.audio1.eq_40hz_db,
              eq_100hz_db=parsed.audio1.eq_100hz_db,
              eq_10khz_db=parsed.audio1.eq_10khz_db,
            )}
          </div>
          <div class="setup-detail-panel" id="panel-input2">
            <div class="setup-detail-back">
              <button type="button" class="pill-btn small" onclick="closePanel()">\u2190 Back</button>
            </div>
            {_setup_detail_header("Setup Input 2")}
            {input2_html}
            <div id="audio2_preamp_card" style="display:{'block' if parsed.audio2_enabled else 'none'};">
              {_audio_controls_card_html(
                input_index=2,
                gain_db=parsed.audio2.gain_db,
                eq_40hz_db=parsed.audio2.eq_40hz_db,
                eq_100hz_db=parsed.audio2.eq_100hz_db,
                eq_10khz_db=parsed.audio2.eq_10khz_db,
              )}
            </div>
          </div>
          <div class="setup-detail-panel" id="panel-playback">
            <div class="setup-detail-back">
              <button type="button" class="pill-btn small" onclick="closePanel()">\u2190 Back</button>
            </div>
            {_setup_detail_header("Setup Playback Defaults")}
            {playback_fieldset_html}
          </div>
          <div class="setup-detail-panel" id="panel-system">
            <div class="setup-detail-back">
              <button type="button" class="pill-btn small" onclick="closePanel()">\u2190 Back</button>
            </div>
            {_setup_detail_header("System & Updates")}
            {system_fieldset_html}
          </div>
          <div class="setup-detail-panel" id="panel-customise">
            <div class="setup-detail-back">
              <button type="button" class="pill-btn small" onclick="closePanel()">\u2190 Back</button>
            </div>
            {_setup_detail_header("Personalisation")}
            {customise_card_html}
          </div>
          <div class="setup-detail-panel" id="panel-factory-reset">
            <div class="setup-detail-back">
              <button type="button" class="pill-btn small" onclick="closePanel()">\u2190 Back</button>
            </div>
            {factory_reset_zone}
          </div>
        </div>
      </div>
    </div>"""

    _extra_css = f"{COMMON_MODAL_CSS}\n{PIN_MODAL_CSS}\n{pin_modal_setup_css}\n{factory_reset_modal_css}"
    _pin_modal_div = """\
<div id="pinModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="pinModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="pinModalTitle">Change PIN</div>
    <div class="bd modal-bd">
      <p id="pinModalMessage">Enter your current PIN.</p>
      <p id="pinModalError" style="display:none;color:var(--color-status-danger);font-weight:600;"></p>
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-secondary" id="pinModalCancel">Cancel</button>
      <button type="button" class="btn modal-btn modal-btn-primary" id="pinModalOk">Apply</button>
    </div>
  </div>
</div>"""
    _body_prefix = f"{factory_reset_modal}\n{reboot_modal}\n{_pin_modal_div}"
    _page_heading_html = (
        f"{BANNER_HTML}<h1>{h1}</h1>"
        if initial_setup else
        ""
    )
    _body_html = (
        _page_heading_html
        + (f'<p class="actions" style="display:flex;justify-content:flex-end;"><a href="/logs" class="pill-btn">Logs</a></p>' if initial_setup else "")
        + (f"<p style='color:var(--color-status-success);'>Saved</p>" if saved_ok else "")
        + (f"<p style='color:var(--color-status-danger);'>{html.escape(error)}</p>" if error else "")
        + f'<form id="{setup_form_id}" method="POST" action="/setup" autocomplete="off">'
        + f'<input type="hidden" name="csrf_token" value="{html.escape(csrf_token)}">'
        + form_content_html
        + "</form>"
    )
    _body_suffix = f"""{A2HS_SCRIPT}
      <script>
        const pinChangeState = {{
          busy: false,
        }};
        function pinModalElements() {{
          return {{
            modal: document.getElementById('pinModal'),
            title: document.getElementById('pinModalTitle'),
            body: document.querySelector('#pinModal .bd'),
            message: document.getElementById('pinModalMessage'),
            error: document.getElementById('pinModalError'),
            newInput: document.getElementById('pinModalNew'),
            repeatInput: document.getElementById('pinModalRepeat'),
            cancel: document.getElementById('pinModalCancel'),
            ok: document.getElementById('pinModalOk'),
          }};
        }}
        function _makePinInput(id, placeholder) {{
          const input = document.createElement('input');
          input.id = id;
          input.name = 'v';
          input.type = 'text';
          input.className = 'pin-entry';
          input.setAttribute('readonly', 'readonly');
          input.setAttribute('inputmode', 'text');
          input.setAttribute('autocapitalize', 'off');
          input.setAttribute('autocomplete', 'off');
          input.setAttribute('autocorrect', 'off');
          input.setAttribute('spellcheck', 'false');
          input.setAttribute('data-form-type', 'other');
          input.setAttribute('placeholder', placeholder);
          return input;
        }}
        function _armPinInput(input) {{
          input.value = '';
          input.setAttribute('readonly', 'readonly');
          const enable = () => input.removeAttribute('readonly');
          input.addEventListener('pointerdown', enable, {{ once: true }});
          input.addEventListener('focus', enable, {{ once: true }});
        }}
        function ensurePinModalInputs() {{
          const els = pinModalElements();
          if (!els.body) return;
          if (!els.newInput) {{
            const newInput = _makePinInput('pinModalNew', 'New PIN');
            newInput.addEventListener('keydown', (ev) => {{
              if (ev.key === 'Enter') {{
                ev.preventDefault();
                const rep = document.getElementById('pinModalRepeat');
                if (rep) rep.focus();
              }}
            }});
            const err = els.error;
            if (err && err.parentNode === els.body) {{
              els.body.insertBefore(newInput, err.nextSibling);
            }} else {{
              els.body.appendChild(newInput);
            }}
          }}
          if (!els.repeatInput) {{
            const repeatInput = _makePinInput('pinModalRepeat', 'Repeat PIN');
            repeatInput.style.marginTop = '0.5rem';
            repeatInput.addEventListener('keydown', (ev) => {{
              if (ev.key === 'Enter') {{ ev.preventDefault(); handlePinModalOk(); }}
            }});
            const newInput = document.getElementById('pinModalNew');
            if (newInput) newInput.after(repeatInput);
            else els.body.appendChild(repeatInput);
          }}
        }}
        function setPinModalBusy(busy) {{
          pinChangeState.busy = !!busy;
          const els = pinModalElements();
          if (els.cancel) els.cancel.disabled = !!busy;
          if (els.ok) els.ok.disabled = !!busy;
          if (els.newInput) els.newInput.disabled = !!busy;
          if (els.repeatInput) els.repeatInput.disabled = !!busy;
        }}
        function showPinModalError(message) {{
          const els = pinModalElements();
          if (!els.error) return;
          if (message) {{
            els.error.style.display = '';
            els.error.textContent = message;
          }} else {{
            els.error.style.display = 'none';
            els.error.textContent = '';
          }}
        }}
        function closePinModal() {{
          const els = pinModalElements();
          if (!els.modal) return;
          els.modal.classList.remove('show');
          if (els.newInput) {{ els.newInput.value = ''; els.newInput.remove(); }}
          if (els.repeatInput) {{ els.repeatInput.value = ''; els.repeatInput.remove(); }}
          showPinModalError(null);
          els.message.textContent = '';
          els.ok.textContent = 'Apply';
          els.ok.style.display = '';
          els.cancel.textContent = 'Cancel';
          els.cancel.style.display = '';
          pinChangeState.busy = false;
        }}
        function openChangePinModal() {{
          pinChangeState.busy = false;
          const els = pinModalElements();
          if (!els.modal) return;
          ensurePinModalInputs();
          const inputs = pinModalElements();
          showPinModalError(null);
          els.message.textContent = '';
          els.ok.textContent = 'Apply';
          els.ok.style.display = '';
          els.cancel.textContent = 'Cancel';
          els.cancel.style.display = '';
          if (inputs.newInput) _armPinInput(inputs.newInput);
          if (inputs.repeatInput) _armPinInput(inputs.repeatInput);
          setPinModalBusy(false);
          els.modal.classList.add('show');
        }}
        async function submitPinChange(newPin, newPinCheck) {{
          const resp = await fetch('/api/pin/change', {{
            method: 'POST',
            headers: {{
              'Content-Type': 'application/json',
              'X-CSRF-Token': window.__CSRF || ''
            }},
            body: JSON.stringify({{ new_pin: newPin, new_pin_check: newPinCheck }})
          }});
          const body = await resp.json().catch(() => ({{ ok: false, error: 'Unable to change PIN' }}));
          return {{ status: resp.status, body: body }};
        }}
        function friendlyPinChangeError(message) {{
          const text = String(message || '').trim();
          if (!text) return 'Unable to change PIN.';
          if (text === 'PIN must be 4-20 characters using letters, numbers, or hyphens') return text;
          if (text === 'Values did not match') return 'The two PIN entries did not match.';
          if (text === 'Missing fields') return 'Enter your new PIN twice.';
          return text;
        }}
        async function handlePinModalOk() {{
          if (pinChangeState.busy) return;
          const els = pinModalElements();
          const newVal = ((els.newInput && els.newInput.value) || '').trim();
          const repeatVal = ((els.repeatInput && els.repeatInput.value) || '').trim();
          if (!newVal) {{
            showPinModalError('Enter a new PIN.');
            if (els.newInput) els.newInput.focus();
            return;
          }}
          if (!repeatVal) {{
            showPinModalError('Repeat the new PIN.');
            if (els.repeatInput) els.repeatInput.focus();
            return;
          }}
          if (newVal !== repeatVal) {{
            showPinModalError('The two PINs did not match. Please try again.');
            if (els.newInput) {{ _armPinInput(els.newInput); els.newInput.focus(); }}
            if (els.repeatInput) _armPinInput(els.repeatInput);
            return;
          }}
          setPinModalBusy(true);
          try {{
            const result = await submitPinChange(newVal, repeatVal);
            if (result.status === 200 && result.body.ok) {{
              if (els.newInput) {{ els.newInput.value = ''; els.newInput.style.display = 'none'; }}
              if (els.repeatInput) {{ els.repeatInput.value = ''; els.repeatInput.style.display = 'none'; }}
              showPinModalError(null);
              els.message.textContent = 'PIN changed successfully. Returning to the home screen\u2026';
              els.ok.style.display = 'none';
              els.cancel.textContent = 'Continue';
              setPinModalBusy(false);
              window.setTimeout(() => {{ window.location.href = '/'; }}, 900);
              return;
            }}
            showPinModalError(friendlyPinChangeError(result.body.error || 'Unable to change PIN.'));
          }} catch (e) {{
            showPinModalError('Unable to change PIN.');
          }} finally {{
            setPinModalBusy(false);
          }}
        }}
        function handlePinModalCancel() {{
          closePinModal();
        }}
        const gainTimers = {{}};
        const eqTimers = {{}};
        const eqLiveEnabled = {str(not initial_setup).lower()};
        function onAudio2Toggle(checked){{
          syncInputUi(2);
        }}
        function syncVol(v){{document.getElementById('owntone_volume_percent').value=v;document.getElementById('vol_val').textContent=v+'%';}}
        function thresholdPreset(checked){{ return checked ? -45 : -60; }}
        function syncInputUi(inputIndex){{
          const prefix = inputIndex === 1 ? 'audio1' : 'audio2';
          const turntableName = inputIndex === 1 ? 'audio_turntable' : 'audio2_turntable';
          const enabled = inputIndex === 1
            ? true
            : !!document.querySelector('input[name="audio2_enabled"]')?.checked;
          const turntable = !!document.querySelector('input[name="' + turntableName + '"]')?.checked;
          const settings = document.getElementById(prefix + '_settings');
          const preampCard = inputIndex === 2 ? document.getElementById('audio2_preamp_card') : null;
          const thresholdId = inputIndex === 1 ? 'audio_silence_threshold' : 'audio2_silence_threshold';
          const note = document.getElementById(prefix + '_turntable_note');
          const threshold = thresholdPreset(turntable);
          const hidden = document.getElementById(thresholdId);
          if (settings) settings.style.display = enabled ? 'block' : 'none';
          if (preampCard) preampCard.style.display = enabled ? 'block' : 'none';
          if (hidden) hidden.value = String(threshold);
          if (note) note.textContent = 'Detection threshold preset: ' + String(threshold) + ' dB';
        }}
        function eqPrefix(inputIndex){{ return inputIndex===1 ? 'audio1' : 'audio2'; }}
        function syncGain(inputIndex, value){{
          const prefix = eqPrefix(inputIndex);
          const inputEl = document.getElementById(prefix + '_gain_db');
          const valueEl = document.getElementById(prefix + '_gain_db_val');
          if (inputEl) inputEl.value = value;
          if (valueEl) valueEl.textContent = value + ' dB';
          if (eqLiveEnabled) queueGainUpdate(inputIndex);
        }}
        function gainPayload(inputIndex){{
          const prefix = eqPrefix(inputIndex);
          return {{
            input: inputIndex,
            gain_db: Number(document.getElementById(prefix + '_gain_db').value),
          }};
        }}
        async function sendGainUpdate(inputIndex){{
          if (!eqLiveEnabled) return;
          const payload = gainPayload(inputIndex);
          try {{
            await fetch('/api/input_gain', {{
              method: 'POST',
              headers: {{
                'Content-Type': 'application/json',
                'X-CSRF-Token': window.__CSRF || ''
              }},
              body: JSON.stringify(payload)
            }});
          }} catch (e) {{
          }}
        }}
        function queueGainUpdate(inputIndex){{
          if (gainTimers[inputIndex]) clearTimeout(gainTimers[inputIndex]);
          gainTimers[inputIndex] = setTimeout(() => sendGainUpdate(inputIndex), 120);
        }}
        function syncEq(inputIndex, band, value){{
          const prefix = eqPrefix(inputIndex);
          const valueEl = document.getElementById(prefix + '_eq_' + band + '_db_val');
          if (valueEl) valueEl.textContent = value + ' dB';
          if (eqLiveEnabled) queueEqUpdate(inputIndex);
        }}
        function eqPayload(inputIndex){{
          const prefix = eqPrefix(inputIndex);
          return {{
            input: inputIndex,
            eq_40hz_db: Number(document.getElementById(prefix + '_eq_40hz_db').value),
            eq_100hz_db: Number(document.getElementById(prefix + '_eq_100hz_db').value),
            eq_10khz_db: Number(document.getElementById(prefix + '_eq_10khz_db').value),
          }};
        }}
        async function sendEqUpdate(inputIndex){{
          if (!eqLiveEnabled) return;
          const payload = eqPayload(inputIndex);
          try {{
            await fetch('/api/input_eq', {{
              method: 'POST',
              headers: {{
                'Content-Type': 'application/json',
                'X-CSRF-Token': window.__CSRF || ''
              }},
              body: JSON.stringify(payload)
            }});
          }} catch (e) {{
          }}
        }}
        function queueEqUpdate(inputIndex){{
          if (eqTimers[inputIndex]) clearTimeout(eqTimers[inputIndex]);
          eqTimers[inputIndex] = setTimeout(() => sendEqUpdate(inputIndex), 120);
        }}
        function syncSil(v){{document.getElementById('sil_val').textContent=v+'s';}}
        window.addEventListener('DOMContentLoaded', () => {{
          const changePinBtn = document.getElementById('btnChangePin');
          const pinModalCancel = document.getElementById('pinModalCancel');
          const pinModalOk = document.getElementById('pinModalOk');
          if (changePinBtn) changePinBtn.addEventListener('click', openChangePinModal);
          if (pinModalCancel) pinModalCancel.addEventListener('click', handlePinModalCancel);
          if (pinModalOk) pinModalOk.addEventListener('click', handlePinModalOk);
          syncInputUi(1);
          syncInputUi(2);
        }});
        function requestReboot(){{
          showRebootModal();
        }}
        (async function(){{
          const msg = (t) => {{ document.getElementById("updMsg").textContent = t; }};
          const bCheck = document.getElementById("btnCheck"), bInst = document.getElementById("btnInst");
          let cand = null;
          // On page load, check persisted update status so any recent result is visible.
          async function checkPersistedStatus(){{
            try {{
              const r = await fetch("/api/update/status"); const j = await r.json();
              if(j.ok && j.status === "in_progress"){{
                if(j.stale){{
                  if(j.hung){{
                    msg("An update is still running but has been unresponsive for 30+ minutes. Power-cycle the device to recover — do not retry until after rebooting.");
                  }} else {{
                    msg("A previous update appears to have stalled. Power-cycle the device to trigger automatic recovery, or use Check for Updates to retry.");
                  }}
                }} else {{
                  // An update is already running — send the user to the progress page.
                  window.location.replace("/offline/updating");
                }}
                return;
              }}
              if(j.ok && j.status === "success"){{ msg("Last update: installed successfully."); }}
              else if(j.ok && (j.status === "failure" || j.status === "error")){{
                msg("Last update failed: " + (j.message || "unknown error"));
              }}
            }} catch(e) {{ /* ignore — no persisted status yet */ }}
          }}
          bCheck.onclick = async () => {{
            msg("Checking..."); bInst.disabled=true;
            try {{
              const r = await fetch("/api/update/check"); const j = await r.json();
              if(j.ok && j.update_available){{ cand=j.candidate; msg("Update available: "+j.candidate); bInst.disabled=false; }}
              else msg(j.ok?"No updates available.":"Check failed.");
            }} catch(e) {{ msg("Check failed."); }}
          }};
          bInst.onclick = async () => {{
            if(!cand) return;
            msg("Starting update..."); bCheck.disabled=true; bInst.disabled=true;
            try {{
              const r = await fetch("/api/update/apply",{{method:"POST",headers:{{"X-CSRF-Token":window.__CSRF||""}}}});
              const j = await r.json().catch(()=>({{ok:false}}));
              if(j.ok){{
                window.location.replace("/offline/updating");
              }} else {{
                msg("Failed to start update: " + (j.error || "unknown error"));
                bCheck.disabled=false;
              }}
            }} catch(e) {{
              // Network error: service may have already started the update.
              window.location.replace("/offline/updating");
            }}
          }};
          checkPersistedStatus();
        }})();
      </script>
      <script>
        async function refreshOwntoneOutputs() {{
          const sel = document.getElementById("owntone_output_select");
          const hint = document.getElementById("owntone_output_hint");
          if (!sel) return;

          // If the user is interacting with the dropdown, don't change it under them.
          if (document.activeElement === sel) return;

          let j = null;
          try {{
            const r = await fetch("/api/owntone/outputs", {{ cache: "no-store" }});
            j = await r.json();
          }} catch (e) {{
            return;
          }}
          if (!j || !j.ok) return;

          const outputs = Array.isArray(j.outputs) ? j.outputs : [];
          if (hint) hint.style.display = outputs.length ? "none" : "block";

          // If still empty, keep whatever is currently shown (don't wipe it).
          if (!outputs.length) return;

          const current = sel.value;
          const existing = Array.from(sel.options).map(o => o.value);

          // If the list hasn't changed, do nothing.
          const same =
            existing.length === outputs.length &&
            existing.every((v, i) => v === outputs[i]);
          if (same) return;

          // Rebuild options
          sel.innerHTML = "";
          for (const name of outputs) {{
            const opt = document.createElement("option");
            opt.value = name;
            opt.textContent = name;
            sel.appendChild(opt);
          }}

          // Preserve user's current selection if possible
          if (outputs.includes(current)) {{
            sel.value = current;
          }} else if (j.selected && outputs.includes(j.selected)) {{
            sel.value = j.selected;
          }} else {{
            sel.selectedIndex = 0;
          }}
        }}

        window.addEventListener("DOMContentLoaded", () => {{
          // Run once immediately, then every 2 seconds
          refreshOwntoneOutputs();
          setInterval(refreshOwntoneOutputs, 2000);
        }});
      </script>
      {f"""<script>
        function _inputCardSub(captureSelName, turntableName, gainId) {{
          var sel = document.querySelector('select[name="' + captureSelName + '"]');
          var opt = sel ? sel.options[sel.selectedIndex] : null;
          var dev = (opt && opt.dataset.card) ? opt.dataset.card : (sel && sel.value ? sel.value : 'Not configured');
          var turntable = document.querySelector('input[name="' + turntableName + '"]');
          var mode = (turntable && turntable.checked) ? 'Turntable' : 'Line In';
          var gainEl = document.getElementById(gainId);
          var gain = gainEl ? parseInt(gainEl.value, 10) : 0;
          var gainStr = gain > 0 ? '+' + gain + ' dB' : (gain < 0 ? gain + ' dB' : '0 dB');
          return dev + ' \u00b7 ' + mode + ' \u00b7 ' + gainStr;
        }}
        function refreshInputCardSubs() {{
          var s1 = document.getElementById('input1-card-sub');
          if (s1) s1.textContent = _inputCardSub('audio_capture_device', 'audio_turntable', 'audio1_gain_db');
          var s2 = document.getElementById('input2-card-sub');
          if (s2) {{
            var en = document.querySelector('input[name="audio2_enabled"]');
            if (en && !en.checked) {{
              s2.textContent = 'Disabled';
            }} else {{
              s2.textContent = _inputCardSub('audio2_capture_device', 'audio2_turntable', 'audio2_gain_db');
            }}
          }}
        }}
        function openPanel(id) {{
          document.querySelectorAll('.setup-detail-panel').forEach(function(p) {{ p.classList.remove('active'); }});
          var panel = document.getElementById('panel-' + id);
          if (panel) panel.classList.add('active');
          var track = document.getElementById('setupSlideTrack');
          if (track) track.classList.add('panel-open');
          window.scrollTo(0, 0);
        }}
        function refreshCustomiseCardSub() {{
          var sub = document.getElementById('customise-card-sub');
          if (!sub) return;
          var cb = document.getElementById('webui_show_master_volume');
          var cbDet = document.getElementById('webui_show_input_detail');
          var cbDark = document.getElementById('webui_dark_mode');
          var cbHost = document.getElementById('webui_show_hostname_on_home');
          var mv = (cb && cb.checked) ? 'Master volume: On' : 'Master volume: Off';
          var det = (cbDet && cbDet.checked) ? 'Input detail: On' : 'Input detail: Off';
          var dark = (cbDark && cbDark.checked) ? 'Dark mode: On' : 'Dark mode: Off';
          var host = (cbHost && cbHost.checked) ? 'Hostname: On' : 'Hostname: Off';
          sub.textContent = mv + ' \u00b7 ' + det + ' \u00b7 ' + dark + ' \u00b7 ' + host;
        }}
        function closePanel() {{
          refreshInputCardSubs();
          refreshCustomiseCardSub();
          var track = document.getElementById('setupSlideTrack');
          if (track) track.classList.remove('panel-open');
          window.scrollTo(0, 0);
        }}
      </script>""" if not initial_setup else ""}
      {factory_reset_js}"""
    html_body = build_page_html(
        "autostream",
        _body_html,
        extra_css=_extra_css,
        head_extra=csrf_meta,
        body_prefix=_body_prefix,
        body_suffix=_body_suffix,
        lic_html=lic_html,
        lic_spacer=lic_spacer,
        show_nav=not initial_setup,
        active_tab="setup",
        dark_mode=parsed.webui.dark_mode,
    )
    body_bytes = html_body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)
