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

from datetime import datetime, timezone
from typing import Optional
from urllib.parse import parse_qs

from autostream_config import (
    CONFIG_IO_LOCK,
    mark_configured,
    parse_config,
    unconfigured,
)
from autostream_dials import parse_dial_entries

try:
    from autostream_dials import get_all_sightings as _get_dial_sightings
except ImportError:
    def _get_dial_sightings() -> list:  # type: ignore[misc]
        return []

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
    eq_8khz_db: float,
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
              id="{prefix}_eq_8khz_db"
              name="{prefix}_eq_8khz_db"
              value="{eq_8khz_db:.0f}"
              aria-label="Treble equaliser"
              oninput="syncEq({input_index}, '8khz', this.value)">
            <span class="eq-band-val" id="{prefix}_eq_8khz_db_val">{eq_8khz_db:.0f} dB</span>
          </div>
        </div>
      </div>
    """
    return settings_card_html(inner_html)


# -----------------------------------------------------------------------------
# Dial card helpers
# -----------------------------------------------------------------------------

def _relative_time(iso_str: str) -> str:
    if not iso_str:
        return "never seen"
    try:
        parsed = datetime.fromisoformat(iso_str)
        now = datetime.now(timezone.utc)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        delta = now - parsed
        secs = int(delta.total_seconds())
        if secs < 60:
            return "just now"
        if secs < 3600:
            return f"{secs // 60}m ago"
        if secs < 86400:
            return f"{secs // 3600}h ago"
        return f"{secs // 86400}d ago"
    except (ValueError, TypeError):
        return "unknown"


def _dial_card_new_html(sighting) -> str:
    """Card for a dial seen on the network but not yet authorized."""
    su = html.escape(sighting.uuid)
    nv = html.escape(sighting.name or "")
    return settings_card_html(f"""
          <div class="dial-card" data-dial-uuid="{su}" data-pin-set="false">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:0.5rem;flex-wrap:wrap;">
            <span style="font-size:0.7rem;color:var(--color-text-muted);word-break:break-all;">UUID: {su}</span>
            <span class="dial-badge dial-badge-new">New</span>
          </div>
          <label style="display:block;margin-top:0.5rem;">Name
            <input type="text" class="dial-name" value="{nv}"
                   placeholder="e.g. Hallway Dial" style="margin-top:0.25rem;">
          </label>
          <div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.75rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" class="dial-allow" data-dial-action="toggle-allow">
              <span class="switch"></span>
            </label>
            <span>Allow control</span>
          </div>
          <div class="dial-card-msg" style="display:none;margin-top:0.5rem;"></div>
          </div>
        """, margin_top="0")


def _dial_card_offline_html(entry) -> str:
    """Card for an authorized dial that is currently offline."""
    su = html.escape(entry.uuid)
    dn = html.escape(entry.current_name or entry.name)
    ls = html.escape(_relative_time(entry.last_seen))
    return settings_card_html(f"""
          <div class="dial-card" data-dial-uuid="{su}" data-pin-set="false">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem;flex-wrap:wrap;">
            <span class="dial-card-title">{dn}</span>
            <span class="dial-badge dial-badge-offline">Offline</span>
          </div>
          <div style="font-size:0.75rem;color:var(--color-text-muted);margin-top:0.25rem;">
            Last seen: {ls}
          </div>
          <div style="font-size:0.7rem;color:var(--color-text-muted);word-break:break-all;margin-top:0.25rem;">
            UUID: {su}
          </div>
          <div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.75rem;flex-wrap:wrap;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" class="dial-allow" data-dial-action="toggle-allow" checked>
              <span class="switch"></span>
            </label>
            <span>Allow control</span>
            <button type="button" class="pill-btn small" style="margin-left:auto;"
                    data-dial-action="revoke">Revoke</button>
          </div>
          <div class="dial-card-msg" style="display:none;margin-top:0.5rem;"></div>
          </div>
        """, margin_top="0")


def _dial_card_online_html(entry, sighting, app_version: str) -> str:
    """Card for an authorized dial that is currently online."""
    su = html.escape(entry.uuid)
    dn = html.escape(entry.current_name or entry.name or sighting.name)
    fw = html.escape(sighting.version or "")
    nv = html.escape(entry.current_name or entry.name or sighting.name)
    needs_update = bool(sighting.version and app_version and sighting.version != app_version)
    update_btn = (
        f'<button type="button" class="pill-btn small" style="flex-shrink:0;"'
        f' data-dial-action="update">Update firmware</button>'
    ) if needs_update else ""
    fw_span = (
        f'<span style="font-size:0.75rem;color:var(--color-text-muted);'
        f'margin-left:0.4rem;">· Firmware {fw}</span>'
    ) if fw else ""
    return settings_card_html(f"""
          <div class="dial-card" data-dial-uuid="{su}" data-pin-set="false">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:0.5rem;flex-wrap:wrap;">
            <div><span class="dial-card-title">{dn}</span>{fw_span}</div>
            <div style="display:flex;gap:0.4rem;align-items:center;flex-shrink:0;">
              {update_btn}<span class="dial-badge dial-badge-online">Online</span>
            </div>
          </div>
          <div style="font-size:0.7rem;color:var(--color-text-muted);word-break:break-all;margin-top:0.25rem;">
            UUID: {su}
          </div>
          <label style="display:block;margin-top:0.5rem;">Name
            <input type="text" class="dial-name" value="{nv}"
                   placeholder="Display name" style="margin-top:0.25rem;"
                   data-dial-action="save-config">
          </label>
          <div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.5rem;">
            Step
            <input type="number" class="dial-step" min="1" max="10" value="2"
                   style="width:3.5rem;" data-dial-action="save-config">
            <span>% per click</span>
          </div>
          <div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.75rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" class="dial-allow" data-dial-action="toggle-allow" checked>
              <span class="switch"></span>
            </label>
            <span>Allow control</span>
          </div>
          <div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.5rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" class="dial-autoupdate" data-dial-action="save-config">
              <span class="switch"></span>
            </label>
            <span>Auto-update</span>
          </div>
          <div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.5rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" class="dial-channel" data-dial-action="save-config">
              <span class="switch"></span>
            </label>
            <span>Pre-release updates</span>
          </div>
          <div style="display:flex;gap:0.5rem;margin-top:0.75rem;flex-wrap:wrap;">
            <button type="button" class="pill-btn small"
                    data-dial-action="change-pin">Change PIN</button>
            <button type="button" class="pill-btn small"
                    data-dial-action="recover-pin">Reset lost PIN</button>
            <button type="button" class="pill-btn small" style="margin-left:auto;"
                    data-dial-action="revoke">Revoke</button>
          </div>
          <div class="dial-card-msg" style="display:none;margin-top:0.5rem;"></div>
          </div>
        """, margin_top="0")


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
    _auto_update_checked = " checked" if parsed.updates.auto_update else ""
    _prerelease_checked = " checked" if parsed.updates.update_channel == "dev" else ""
    update_html = "" if initial_setup else f"""
          <input type="hidden" name="updates_auto_update_present" value="1">
          <input type="hidden" name="updates_channel_present" value="1">
          <label>Updates:
            <div style="display:flex;align-items:center;margin-top:.5rem">
              <button type="button" id="btnCheck" class="pill-btn small" style="margin-right:auto">Check</button>
              <button type="button" id="btnInst" class="pill-btn small" style="margin:auto" disabled>Install</button>
              <button type="button" class="pill-btn small" style="margin-left:auto" onclick="requestReboot()">Reboot</button>
            </div>
            <div id="updMsg" style="font-size:0.8rem;margin-top:0.3rem;"></div>
            <div id="updNotes" style="font-size:0.75rem;color:#888;margin-top:0.2rem;font-style:italic;"></div>
          </label>
          <div style="display:flex;align-items:center;gap:.75rem;margin-top:.75rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" name="updates_auto_update" id="updates_auto_update"{_auto_update_checked}>
              <span class="switch"></span>
            </label>
            <span>Automatic updates</span>
          </div>
          <div style="display:flex;align-items:center;gap:.75rem;margin-top:.5rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" name="updates_prerelease_channel" id="updates_prerelease_channel"{_prerelease_checked}>
              <span class="switch"></span>
            </label>
            <span>Enable pre-release updates</span>
          </div>
          <div style="font-size:0.75rem;color:#888;margin-top:0.25rem;">Pre-release versions may be less stable.</div>
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

    _dial_onload_js = ""  # populated in the else branch below

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
        _au_state = "Auto-update: On" if parsed.updates.auto_update else "Auto-update: Off"
        if parsed.updates.update_channel == "dev":
            _au_state += " - Pre-release channel"
        system_summary = html.escape(f"{get_system_hostname()} \u00b7 v{get_app_version()} \u00b7 {_au_state}")
        _ctrl_other_effective = parsed.webui.show_hostname_on_home and parsed.webui.control_other_appliances
        customise_summary = html.escape(
            ("Master volume: On" if parsed.webui.show_master_volume else "Master volume: Off")
            + (" \u00b7 Input detail: On" if parsed.webui.show_input_detail else " \u00b7 Input detail: Off")
            + (" \u00b7 Dark mode: On" if parsed.webui.dark_mode else " \u00b7 Dark mode: Off")
            + (" \u00b7 Hostname: On" if parsed.webui.show_hostname_on_home else " \u00b7 Hostname: Off")
            + (" \u00b7 Control others: On" if _ctrl_other_effective else " \u00b7 Control others: Off")
            + (" \u00b7 Visible to peers: On" if parsed.webui.advertise_appliance else " \u00b7 Visible to peers: Off")
        )
        _ctrl_other_disabled = ' disabled' if not parsed.webui.show_hostname_on_home else ''
        _ctrl_other_row_style = "margin-top:0.75rem;opacity:0.4;" if not parsed.webui.show_hostname_on_home else "margin-top:0.75rem;"
        customise_card_html = settings_card_html(f"""
              <input type="hidden" name="webui_show_master_volume_present" value="1">
              <input type="hidden" name="webui_advertise_appliance_present" value="1">
              <input type="hidden" name="webui_control_other_appliances_present" value="1">
              <div class="setup-customise-row" style="margin-top:0.5rem;">
                <label class="output-toggle" style="margin:0;">
                  <input type="checkbox" name="webui_show_hostname_on_home" id="webui_show_hostname_on_home"{'  checked' if parsed.webui.show_hostname_on_home else ''} onchange="onHostnameToggle(this.checked)">
                  <span class="switch"></span>
                </label>
                <span>Display Hostname</span>
              </div>
              <div id="ctrl-other-row" class="setup-customise-row" style="{_ctrl_other_row_style}">
                <label class="output-toggle" style="margin:0;">
                  <input type="checkbox" name="webui_control_other_appliances" id="webui_control_other_appliances"{'  checked' if _ctrl_other_effective else ''}{_ctrl_other_disabled} onchange="refreshCustomiseCardSub()">
                  <span class="switch"></span>
                </label>
                <span>Allow control of other appliances</span>
              </div>
              <div class="setup-customise-row" style="margin-top:0.75rem;">
                <label class="output-toggle" style="margin:0;">
                  <input type="checkbox" name="webui_advertise_appliance" id="webui_advertise_appliance"{'  checked' if parsed.webui.advertise_appliance else ''} onchange="refreshCustomiseCardSub()">
                  <span class="switch"></span>
                </label>
                <span>Allow control of this from other appliances</span>
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
              <input type="hidden" name="webui_output_usage_poll_interval_present" value="1">
              <div class="setup-customise-row" style="margin-top:0.75rem;align-items:center;">
                <label style="margin:0;white-space:nowrap;">Output sharing refresh:</label>
                <input type="number" name="webui_output_usage_poll_interval_seconds"
                  id="webui_output_usage_poll_interval_seconds"
                  value="{parsed.webui.output_usage_poll_interval_seconds}"
                  min="1" max="30" step="1"
                  style="width:4rem;margin-left:0.5rem;text-align:right;">
                <span style="margin-left:0.4rem;">seconds</span>
              </div>
            """, margin_top="0")

        # Track identification card
        _ti = parsed.track_identification
        _ti_enabled = bool(_ti.enabled)
        track_id_summary = html.escape("On" if _ti_enabled else "Off")
        track_id_card_html = settings_card_html(f"""
              <input type="hidden" name="track_identification_present" value="1">
              <div class="setup-customise-row" style="margin-top:0.5rem;">
                <label class="output-toggle" style="margin:0;">
                  <input type="checkbox" name="track_identification_enabled" id="track_identification_enabled"{'  checked' if _ti_enabled else ''}>
                  <span class="switch"></span>
                </label>
                <span>Track identification</span>
              </div>
              <div style="font-size:0.75rem;color:var(--color-text-muted);margin-top:0.4rem;">
                Identifies playing tracks using Shazam via the vibra-mini service. Requires internet access.
              </div>
            """, margin_top="0")

        # Build dial cards data
        _all_sightings = _get_dial_sightings()
        _authorized_entries = parse_dial_entries()
        _sightings_by_uuid = {s.uuid: s for s in _all_sightings}
        _authorized_uuids = {e.uuid for e in _authorized_entries}
        _n_auth = len(_authorized_entries)
        _n_online = sum(1 for e in _authorized_entries if e.uuid in _sightings_by_uuid)
        _n_new = sum(1 for s in _all_sightings if s.uuid not in _authorized_uuids)
        if _n_auth == 0 and _n_new == 0:
            _dials_summary = "No dials"
        elif _n_auth == 0:
            _dials_summary = f"{_n_new} new"
        elif _n_new > 0:
            _dials_summary = f"{_n_auth} authorized · {_n_new} new"
        else:
            _dials_summary = f"{_n_auth} authorized" + (f" · {_n_online} online" if _n_online else "")
        _dials_summary = html.escape(_dials_summary)
        _app_ver = get_app_version()
        _dial_cards_html = ""
        for _entry in _authorized_entries:
            _sighting = _sightings_by_uuid.get(_entry.uuid)
            if _sighting:
                _dial_cards_html += _dial_card_online_html(_entry, _sighting, _app_ver)
            else:
                _dial_cards_html += _dial_card_offline_html(_entry)
        for _sighting in _all_sightings:
            if _sighting.uuid not in _authorized_uuids:
                _dial_cards_html += _dial_card_new_html(_sighting)
        if not _dial_cards_html:
            _dial_cards_html = (
                "<p style='color:var(--color-text-muted);font-style:italic;margin-top:0.5rem;'>"
                "No dials found on the network.</p>"
            )
        _dial_onload_js = (
            "document.querySelectorAll('.dial-card .dial-step').forEach(function(el) { "
            "dialLoadConfig(el.closest('.dial-card')); });"
        )

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
          <div class="setup-list-card" onclick="openPanel('dials')">
            <div class="setup-list-card-body">
              <span class="setup-list-card-title">Dials</span>
              <span class="setup-list-card-sub">{_dials_summary}</span>
            </div>
            <span class="setup-list-chevron">\u203a</span>
          </div>
          <div class="setup-list-card" onclick="openPanel('track-id')">
            <div class="setup-list-card-body">
              <span class="setup-list-card-title">Track Identification</span>
              <span class="setup-list-card-sub" id="track-id-card-sub">{track_id_summary}</span>
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
              eq_8khz_db=parsed.audio1.eq_8khz_db,
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
                eq_8khz_db=parsed.audio2.eq_8khz_db,
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
          <div class="setup-detail-panel" id="panel-dials">
            <div class="setup-detail-back">
              <button type="button" class="pill-btn small" onclick="closePanel()">\u2190 Back</button>
            </div>
            {_setup_detail_header("Dials")}
            {_dial_cards_html}
          </div>
          <div class="setup-detail-panel" id="panel-track-id">
            <div class="setup-detail-back">
              <button type="button" class="pill-btn small" onclick="closePanel()">\u2190 Back</button>
            </div>
            {_setup_detail_header("Track Identification")}
            {track_id_card_html}
          </div>
        </div>
      </div>
    </div>"""

    _dial_badge_css = """
.dial-badge{display:inline-flex;align-items:center;font-size:0.65rem;font-weight:600;
  padding:0.1rem 0.45rem;border-radius:0.75rem;letter-spacing:0.02em;white-space:nowrap;}
.dial-badge-new{background:var(--color-accent,#007bff);color:#fff;}
.dial-badge-online{background:var(--color-status-success,#28a745);color:#fff;}
.dial-badge-offline{background:var(--color-text-muted,#888);color:#fff;}
.dial-card-title{font-weight:600;font-size:0.9rem;}
.dial-card-msg{font-size:0.8rem;}
"""
    _extra_css = (
        f"{COMMON_MODAL_CSS}\n{PIN_MODAL_CSS}\n{pin_modal_setup_css}"
        f"\n{factory_reset_modal_css}\n{_dial_badge_css}"
    )
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
    _dial_pin_modal_div = ("""\
<div id="dialPinModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="dialPinModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="dialPinModalTitle">Change PIN</div>
    <div class="bd modal-bd">
      <p id="dialPinModalMsg"></p>
      <input type="password" id="dialPinModalCurrentInput" placeholder="Current PIN"
             autocomplete="current-password" style="margin-top:0.5rem;">
      <input type="password" id="dialPinModalInput" placeholder="New PIN"
             autocomplete="new-password" style="margin-top:0.5rem;">
      <p id="dialPinModalError" style="display:none;color:var(--color-status-danger);font-weight:600;margin-top:0.4rem;"></p>
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-secondary" id="dialPinModalCancel">Cancel</button>
      <button type="button" class="btn modal-btn modal-btn-primary" id="dialPinModalOk">Apply</button>
    </div>
  </div>
</div>""" if not initial_setup else "")
    _body_prefix = f"{factory_reset_modal}\n{reboot_modal}\n{_pin_modal_div}\n{_dial_pin_modal_div}"
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
        // Parse a fetch Response into a discriminated result object.
        // Does NOT catch a rejected fetch() promise — network failures propagate.
        // Returns: {{ok, transportStatus, body, error}}
        async function _parseDialResponse(response) {{
          var transportStatus = response.status;
          var ct = response.headers.get('Content-Type') || '';
          if (ct.toLowerCase().indexOf('application/json') === -1) {{
            try {{ await response.text(); }} catch(e) {{}}
            return {{ok: false, transportStatus: transportStatus, body: null, error: 'invalid_response'}};
          }}
          var body;
          try {{ body = await response.json(); }} catch(e) {{
            return {{ok: false, transportStatus: transportStatus, body: null, error: 'invalid_response'}};
          }}
          if (!body || typeof body !== 'object' || Array.isArray(body)) {{
            return {{ok: false, transportStatus: transportStatus, body: null, error: 'invalid_response'}};
          }}
          if (body.ok === false) {{
            return {{ok: false, transportStatus: transportStatus, body: body, error: String(body.error || 'unknown_error')}};
          }}
          if (transportStatus < 200 || transportStatus > 299) {{
            return {{ok: false, transportStatus: transportStatus, body: body, error: String(body.error || 'http_error')}};
          }}
          return {{ok: true, transportStatus: transportStatus, body: body, error: null}};
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
          return _parseDialResponse(resp);
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
            if (result.ok) {{
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
            showPinModalError(friendlyPinChangeError(result.error || 'Unable to change PIN.'));
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
            eq_8khz_db: Number(document.getElementById(prefix + '_eq_8khz_db').value),
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
          // Enforce hostname-dependent state on load
          const cbHost = document.getElementById('webui_show_hostname_on_home');
          if (cbHost) onHostnameToggle(cbHost.checked);
        }});
        function requestReboot(){{
          showRebootModal();
        }}
        (async function(){{
          const msg = (t) => {{ document.getElementById("updMsg").textContent = t; }};
          const notes = (t) => {{ document.getElementById("updNotes").textContent = t || ""; }};
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
            msg("Checking..."); notes(""); bInst.disabled=true;
            try {{
              const r = await fetch("/api/update/check"); const j = await r.json();
              if(j.ok && j.update_available){{
                cand=j.candidate;
                var chanNote = j.channel === "dev" ? " (pre-release channel)" : "";
                msg("Update available: " + j.candidate + chanNote);
                notes(j.release_notes||""); bInst.disabled=false;
              }} else {{ msg(j.ok?"No updates available.":"Check failed."); }}
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
        function onHostnameToggle(checked) {{
          var cb = document.getElementById('webui_control_other_appliances');
          var row = document.getElementById('ctrl-other-row');
          if (cb) {{
            if (!checked) {{
              cb.checked = false;
              cb.disabled = true;
            }} else {{
              cb.disabled = false;
            }}
          }}
          if (row) {{ row.style.opacity = checked ? '' : '0.4'; }}
          refreshCustomiseCardSub();
        }}
        function refreshCustomiseCardSub() {{
          var sub = document.getElementById('customise-card-sub');
          if (!sub) return;
          var cb = document.getElementById('webui_show_master_volume');
          var cbDet = document.getElementById('webui_show_input_detail');
          var cbDark = document.getElementById('webui_dark_mode');
          var cbHost = document.getElementById('webui_show_hostname_on_home');
          var cbCtrl = document.getElementById('webui_control_other_appliances');
          var cbAdv = document.getElementById('webui_advertise_appliance');
          var mv = (cb && cb.checked) ? 'Master volume: On' : 'Master volume: Off';
          var det = (cbDet && cbDet.checked) ? 'Input detail: On' : 'Input detail: Off';
          var dark = (cbDark && cbDark.checked) ? 'Dark mode: On' : 'Dark mode: Off';
          var host = (cbHost && cbHost.checked) ? 'Hostname: On' : 'Hostname: Off';
          var ctrl = (cbCtrl && cbCtrl.checked) ? 'Control others: On' : 'Control others: Off';
          var adv = (cbAdv && cbAdv.checked) ? 'Visible to peers: On' : 'Visible to peers: Off';
          sub.textContent = mv + ' \u00b7 ' + det + ' \u00b7 ' + dark + ' \u00b7 ' + host + ' \u00b7 ' + ctrl + ' \u00b7 ' + adv;
        }}
        function closePanel() {{
          refreshInputCardSubs();
          refreshCustomiseCardSub();
          var track = document.getElementById('setupSlideTrack');
          if (track) track.classList.remove('panel-open');
          window.scrollTo(0, 0);
        }}
      </script>
      <script>
        // ── Dial management ────────────────────────────────────────────────
        var _dialPinRecoveryTimer = null;
        var _dialPinModalCard = null;
        var _dialPinModalMode = null; // 'change' | 'recovery-wait' | 'recovery-set'

        function dialUUID(card) {{
          return card ? (card.dataset.dialUuid || '') : '';
        }}

        function dialMsg(card, msg, ok) {{
          var el = card ? card.querySelector('.dial-card-msg') : null;
          if (!el) return;
          el.textContent = msg;
          el.style.color = ok ? 'var(--color-status-success)' : 'var(--color-status-danger)';
          el.style.display = msg ? '' : 'none';
        }}

        function _dialErrorMessage(error) {{
          var map = {{
            'dial_offline': 'Dial is offline',
            'dial_unreachable': 'Dial could not be reached',
            'dial_bad_response': 'Dial returned an invalid response',
            'dial_unavailable': 'Dial is temporarily unavailable',
            'dial_timeout': 'Dial did not respond in time',
            'invalid_response': 'Appliance returned an unexpected response',
            'wrong_pin': 'Incorrect PIN',
            'too_many_attempts': 'Too many attempts; try again later',
          }};
          return map[String(error || '')] || String(error || 'Unknown error');
        }}

        async function _dialFetch(path, opts) {{
          var headers = Object.assign({{'X-CSRF-Token': window.__CSRF || ''}}, (opts.headers || {{}}));
          var r = await fetch(path, Object.assign({{}}, opts, {{headers: headers}}));
          return _parseDialResponse(r);
        }}

        async function _dialPost(path, body) {{
          return _dialFetch(path, {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify(body),
          }});
        }}

        async function dialToggleAllow(card, checked) {{
          var uuid = dialUUID(card);
          if (!uuid) return;
          if (checked) {{
            var nameEl = card.querySelector('.dial-name');
            var name = ((nameEl ? nameEl.value : '') || uuid.slice(0, 8)).trim();
            try {{
              var result = await _dialPost('/api/dial/authorize', {{uuid: uuid, name: name}});
              if (result.ok) {{ dialMsg(card, 'Authorized', true); setTimeout(function(){{ location.reload(); }}, 800); }}
              else {{
                dialMsg(card, _dialErrorMessage(result.error), false);
                var cb = card.querySelector('.dial-allow');
                if (cb) cb.checked = false;
              }}
            }} catch(e) {{
              dialMsg(card, 'Network error', false);
              var cb2 = card.querySelector('.dial-allow');
              if (cb2) cb2.checked = false;
            }}
          }} else {{
            if (confirm('Remove authorization for this dial?')) {{
              await dialRevoke(card);
            }} else {{
              var cb3 = card.querySelector('.dial-allow');
              if (cb3) cb3.checked = true;
            }}
          }}
        }}

        async function dialRevoke(card) {{
          var uuid = dialUUID(card);
          if (!uuid) return;
          try {{
            var result = await _dialPost('/api/dial/revoke', {{uuid: uuid}});
            if (result.ok) {{ dialMsg(card, 'Revoked', true); setTimeout(function(){{ location.reload(); }}, 800); }}
            else dialMsg(card, _dialErrorMessage(result.error), false);
          }} catch(e) {{ dialMsg(card, 'Network error', false); }}
        }}

        async function dialSaveConfig(card) {{
          var uuid = dialUUID(card);
          if (!uuid) return;
          var nameEl = card.querySelector('.dial-name');
          var stepEl = card.querySelector('.dial-step');
          var autoEl = card.querySelector('.dial-autoupdate');
          var chanEl = card.querySelector('.dial-channel');
          var body = {{uuid: uuid}};
          if (nameEl) body.name = nameEl.value.trim();
          if (stepEl) {{
            var step = parseInt(stepEl.value, 10);
            if (!Number.isInteger(step) || step < 1 || step > 10) {{
              dialMsg(card, 'Step must be between 1 and 10', false);
              return;
            }}
            body.step_percent = step;
          }}
          if (autoEl) body.auto_update = autoEl.checked;
          if (chanEl) body.update_channel = chanEl.checked ? 'dev' : 'stable';
          if (card.dataset.pinSet === 'true') {{
            var currentPin = window.prompt('Enter the current dial PIN to save this change:');
            if (currentPin === null) return;
            body.current_pin = currentPin.trim();
          }}
          try {{
            var result = await _dialPost('/api/dial/configure', body);
            if (result.ok) {{ dialMsg(card, 'Saved', true); setTimeout(function(){{ dialMsg(card, '', true); }}, 2000); }}
            else dialMsg(card, _dialErrorMessage(result.error), false);
          }} catch(e) {{ dialMsg(card, 'Network error', false); }}
        }}

        async function dialLoadConfig(card) {{
          var uuid = dialUUID(card);
          if (!uuid) return;
          try {{
            var r = await fetch('/api/dial/configure/' + encodeURIComponent(uuid), {{
              cache: 'no-store', headers: {{'X-CSRF-Token': window.__CSRF || ''}}
            }});
            var loadResult = await _parseDialResponse(r);
            if (!loadResult.ok) return;
            var j = loadResult.body;
            var stepEl = card.querySelector('.dial-step');
            var autoEl = card.querySelector('.dial-autoupdate');
            var chanEl = card.querySelector('.dial-channel');
            if (stepEl && j.step_percent != null) stepEl.value = j.step_percent;
            if (autoEl && j.auto_update != null) autoEl.checked = !!j.auto_update;
            if (chanEl && j.update_channel != null) chanEl.checked = (j.update_channel === 'dev');
            card.dataset.pinSet = j.pin_set ? 'true' : 'false';
          }} catch(e) {{}}
        }}

        async function dialUpdateFirmware(card) {{
          var uuid = dialUUID(card);
          if (!uuid) return;
          if (!confirm('Start firmware update? The dial will restart.')) return;
          try {{
            var r = await fetch('/api/dial/update/' + encodeURIComponent(uuid), {{
              method: 'POST', headers: {{'X-CSRF-Token': window.__CSRF || ''}}
            }});
            var updResult = await _parseDialResponse(r);
            if (updResult.ok) dialMsg(card, 'Update started', true);
            else dialMsg(card, _dialErrorMessage(updResult.error), false);
          }} catch(e) {{ dialMsg(card, 'Network error', false); }}
        }}

        function _openDialPinModal(card, mode, title, message) {{
          _dialPinModalCard = card;
          _dialPinModalMode = mode;
          var modal = document.getElementById('dialPinModal');
          if (!modal) return;
          document.getElementById('dialPinModalTitle').textContent = title;
          document.getElementById('dialPinModalMsg').textContent = message;
          var errEl = document.getElementById('dialPinModalError');
          errEl.style.display = 'none'; errEl.textContent = '';
          var currentInputEl = document.getElementById('dialPinModalCurrentInput');
          currentInputEl.value = '';
          currentInputEl.style.display = (
            mode === 'change' && card.dataset.pinSet === 'true'
          ) ? '' : 'none';
          var inputEl = document.getElementById('dialPinModalInput');
          inputEl.value = '';
          inputEl.style.display = mode === 'recovery-wait' ? 'none' : '';
          var okBtn = document.getElementById('dialPinModalOk');
          okBtn.disabled = mode === 'recovery-wait';
          document.getElementById('dialPinModalCancel').disabled = false;
          modal.classList.add('show');
          if (mode !== 'recovery-wait') setTimeout(function(){{
            (currentInputEl.style.display === 'none' ? inputEl : currentInputEl).focus();
          }}, 50);
        }}

        function _closeDialPinModal() {{
          _dialPinModalCard = null; _dialPinModalMode = null;
          if (_dialPinRecoveryTimer) {{ clearInterval(_dialPinRecoveryTimer); _dialPinRecoveryTimer = null; }}
          var modal = document.getElementById('dialPinModal');
          if (modal) modal.classList.remove('show');
        }}

        function dialChangePIN(card) {{
          _openDialPinModal(card, 'change', 'Change Dial PIN', 'Enter a new PIN (leave blank to remove):');
        }}

        function dialStartPINRecovery(card) {{
          var uuid = dialUUID(card);
          if (!uuid) return;
          _openDialPinModal(card, 'recovery-wait', 'Reset Lost PIN', 'Turn the dial clockwise to confirm…');
          _dialPinRecoveryTimer = setInterval(async function() {{
            try {{
              var r = await fetch('/api/dial/pin_recovery/status/' + encodeURIComponent(uuid), {{
                cache: 'no-store', headers: {{'X-CSRF-Token': window.__CSRF || ''}}
              }});
              var pollResult = await _parseDialResponse(r);
              // ok:true means active recovery with volume_confirmed; tunneled 404 (error_status:404)
              // means recovery not yet active — continue polling silently in both cases.
              if (pollResult.ok && pollResult.body && pollResult.body.volume_confirmed === true) {{
                clearInterval(_dialPinRecoveryTimer); _dialPinRecoveryTimer = null;
                _dialPinModalMode = 'recovery-set';
                document.getElementById('dialPinModalMsg').textContent = 'Confirmed. Enter your new PIN:';
                var inp = document.getElementById('dialPinModalInput');
                inp.style.display = ''; inp.focus();
                document.getElementById('dialPinModalOk').disabled = false;
              }}
            }} catch(e) {{}}
          }}, 2000);
        }}

        async function _handleDialPinModalOk() {{
          var card = _dialPinModalCard;
          var uuid = dialUUID(card);
          var mode = _dialPinModalMode;
          if (!uuid || mode === 'recovery-wait') return;
          var currentInputEl = document.getElementById('dialPinModalCurrentInput');
          var inputEl = document.getElementById('dialPinModalInput');
          var errEl = document.getElementById('dialPinModalError');
          var okBtn = document.getElementById('dialPinModalOk');
          var currentPin = (currentInputEl ? currentInputEl.value : '').trim();
          var pin = (inputEl ? inputEl.value : '').trim();
          okBtn.disabled = true; errEl.style.display = 'none';
          try {{
            var pinResult;
            if (mode === 'change') {{
              var body = {{uuid: uuid, new_pin: pin}};
              if (card.dataset.pinSet === 'true') body.current_pin = currentPin;
              pinResult = await _dialPost('/api/dial/configure', body);
            }} else {{
              pinResult = await _dialPost('/api/dial/pin_recovery/complete', {{uuid: uuid, new_pin: pin, pin_recovery: true}});
            }}
            if (pinResult.ok) {{
              card.dataset.pinSet = pin ? 'true' : 'false';
              dialMsg(card, mode === 'change' ? (pin ? 'PIN changed' : 'PIN removed') : 'PIN reset', true);
              _closeDialPinModal();
            }} else {{
              errEl.textContent = _dialErrorMessage(pinResult.error); errEl.style.display = '';
              okBtn.disabled = false;
            }}
          }} catch(e) {{
            errEl.textContent = 'Network error'; errEl.style.display = '';
            okBtn.disabled = false;
          }}
        }}

        document.addEventListener('DOMContentLoaded', function() {{
          var ok = document.getElementById('dialPinModalOk');
          var cancel = document.getElementById('dialPinModalCancel');
          if (ok) ok.addEventListener('click', _handleDialPinModalOk);
          if (cancel) cancel.addEventListener('click', _closeDialPinModal);
          document.querySelectorAll('.dial-card').forEach(function(card) {{
            card.addEventListener('change', function(ev) {{
              var action = ev.target.dataset.dialAction;
              if (action === 'toggle-allow') dialToggleAllow(card, ev.target.checked);
              if (action === 'save-config' && (
                ev.target.classList.contains('dial-autoupdate') ||
                ev.target.classList.contains('dial-channel')
              )) {{
                dialSaveConfig(card);
              }}
            }});
            card.addEventListener('focusout', function(ev) {{
              if (
                ev.target.dataset.dialAction === 'save-config'
                && !ev.target.classList.contains('dial-autoupdate')
                && !ev.target.classList.contains('dial-channel')
              ) {{
                dialSaveConfig(card);
              }}
            }});
            card.addEventListener('click', function(ev) {{
              var target = ev.target.closest('[data-dial-action]');
              if (!target || target.tagName === 'INPUT') return;
              var action = target.dataset.dialAction;
              if (action === 'revoke') dialRevoke(card);
              if (action === 'update') dialUpdateFirmware(card);
              if (action === 'change-pin') dialChangePIN(card);
              if (action === 'recover-pin') dialStartPINRecovery(card);
            }});
          }});
          document.addEventListener('keydown', function(ev) {{
            var m = document.getElementById('dialPinModal');
            if (ev.key === 'Escape' && m && m.classList.contains('show')) _closeDialPinModal();
          }});
          // Load current config for each online authorized dial
          {_dial_onload_js}
        }});
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
