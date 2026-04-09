#!/usr/bin/env python3
"""autostream_webui_page_setup.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Renderer for the main Setup page (/setup).

Contents:
  - _format_reset_timestamp   -- format stylus-reset ISO timestamp as a locale date
  - _settings_card_html       -- render a styled settings card div
  - _playback_summary_html    -- render a per-input stylus playback summary card
  - _audio_controls_card_html -- render the gain/EQ sliders card for an input
  - _stylus_reset_flash_text  -- build flash text describing a stylus reset outcome
  - send_setup_page           -- render and send the /setup page
"""

from __future__ import annotations

import html
import logging
import textwrap

import requests

from datetime import datetime
from typing import Optional
from urllib.parse import parse_qs

from autostream_config import (
    mark_configured,
    parse_config,
    unconfigured,
)
from autostream_core import (
    get_playback_snapshot,
    reset_input_stylus,
    update_live_owntone_runtime,
    update_playback_input_config,
)
from autostream_playback import (
    InputPlaybackSnapshot,
    format_hours,
    get_stylus_life_options,
    normalize_stylus_life_hours,
    suggested_silence_threshold_dbfs,
)
from autostream_sysutils import get_system_hostname, set_system_hostname
from autostream_webui_assets import (
    A2HS_SCRIPT,
    BANNER_HTML,
    PIN_MODAL_CSS,
    STYLE_CSS,
    VIEWPORT_META,
)
from autostream_webui_common import (
    CONFIG_IO_LOCK,
    _fallback_input_snapshot,
    _set_flash_cookie,
    build_top_banner_html,
    get_app_version,
    locked_load_config,
)
from autostream_webui_state import WebUIState


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _format_reset_timestamp(raw: Optional[str]) -> str:
    if not raw:
        return "Never"
    try:
        dt = datetime.fromisoformat(str(raw))
        try:
            return dt.astimezone().strftime("%x")
        except Exception:
            return dt.strftime("%x")
    except Exception:
        return str(raw)


def _settings_card_html(inner_html: str, *, margin_top: str = "0.75rem") -> str:
    return (
        f"<div style='margin-top:{margin_top};padding:0.75rem 0.85rem;border:1px solid #e4e4e4;"
        "border-radius:8px;background:#fafafa;font-size:0.95rem;line-height:1.5;'>"
        f"{inner_html}"
        "</div>"
    )


def _playback_summary_html(
    snapshot: InputPlaybackSnapshot,
    *,
    input_index: int,
    reset_button_html: str = "",
    stylus_life_hours: Optional[int] = None,
) -> str:
    def summary_row(
        label: str,
        value_html: str,
        *,
        row_id: str = "",
        value_id: str = "",
        hidden: bool = False,
        extra_attrs: str = "",
    ) -> str:
        row_attrs = ""
        if row_id:
            row_attrs += f" id='{html.escape(row_id)}'"
        if extra_attrs:
            row_attrs += f" {extra_attrs}"
        if hidden:
            row_attrs += " style='display:none;'"
        value_attrs = f" id='{html.escape(value_id)}'" if value_id else ""
        return (
            f"<div{row_attrs}><div style='display:flex;align-items:baseline;gap:0.75rem;"
            "justify-content:space-between;'>"
            f"<strong>{html.escape(label)}:</strong>"
            f"<span{value_attrs} style='margin-left:auto;text-align:right;'>{value_html}</span>"
            "</div></div>"
        )

    rows: list[str] = []
    prefix = f"audio{input_index}"

    life_hours = int(
        stylus_life_hours
        if stylus_life_hours is not None
        else snapshot.stylus_life_hours
    )
    used = format_hours(snapshot.stylus_playback_seconds)
    remaining_seconds = snapshot.stylus_remaining_seconds
    if remaining_seconds is None:
        remaining_seconds = (life_hours * 3600) - int(snapshot.stylus_playback_seconds)
    remaining_txt = "Due now"
    if remaining_seconds > 0:
        remaining_txt = format_hours(remaining_seconds)
    rows.append(
        summary_row(
            "Stylus Hours",
            (
                f"<span id='{prefix}_stylus_hours' data-used-seconds='{int(snapshot.stylus_playback_seconds)}'>"
                f"{html.escape(used)} / {life_hours} h"
                "</span>"
            ),
        )
    )
    rows.append(
        summary_row(
            "Stylus Life Remaining",
            f"<span id='{prefix}_stylus_remaining'>{html.escape(remaining_txt)}</span>",
        )
    )
    if snapshot.last_stylus_reset_at:
        rows.append(
            summary_row(
                "Last Reset",
                (
                    f"<span class='local-reset-date' data-reset-iso="
                    f"'{html.escape(str(snapshot.last_stylus_reset_at))}'>"
                    f"{html.escape(_format_reset_timestamp(snapshot.last_stylus_reset_at))}"
                    "</span>"
                ),
            )
        )
    else:
        rows.append(summary_row("Last Reset", "Never"))

    if not snapshot.enabled:
        rows.append(
            summary_row(
                "Status",
                "Disabled",
                row_id=f"{prefix}_status_row",
                value_id=f"{prefix}_status_value",
                extra_attrs="data-active='0'",
            )
        )
    elif snapshot.active:
        rows.append(
            summary_row(
                "Status",
                "Active now",
                row_id=f"{prefix}_status_row",
                value_id=f"{prefix}_status_value",
                extra_attrs="data-active='1'",
            )
        )
    else:
        rows.append(
            summary_row(
                "Status",
                "",
                row_id=f"{prefix}_status_row",
                value_id=f"{prefix}_status_value",
                extra_attrs="data-active='0'",
                hidden=True,
            )
        )

    if reset_button_html:
        rows.append(
            "<div style='margin-top:0.7rem;display:flex;justify-content:flex-end;'>"
            f"{reset_button_html}"
            "</div>"
        )

    return _settings_card_html("".join(rows))


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
      <label><div class="slider-header"><span>40Hz:</span><span id="{prefix}_eq_40hz_db_val">{eq_40hz_db:.0f} dB</span></div>
      <input type="range" min="-10" max="10" step="1" id="{prefix}_eq_40hz_db" name="{prefix}_eq_40hz_db" value="{eq_40hz_db:.0f}" oninput="syncEq({input_index}, '40hz', this.value)"></label>
      <label><div class="slider-header"><span>Bass:</span><span id="{prefix}_eq_100hz_db_val">{eq_100hz_db:.0f} dB</span></div>
      <input type="range" min="-10" max="10" step="1" id="{prefix}_eq_100hz_db" name="{prefix}_eq_100hz_db" value="{eq_100hz_db:.0f}" oninput="syncEq({input_index}, '100hz', this.value)"></label>
      <label><div class="slider-header"><span>Treble:</span><span id="{prefix}_eq_10khz_db_val">{eq_10khz_db:.0f} dB</span></div>
      <input type="range" min="-10" max="10" step="1" id="{prefix}_eq_10khz_db" name="{prefix}_eq_10khz_db" value="{eq_10khz_db:.0f}" oninput="syncEq({input_index}, '10khz', this.value)"></label>
    """
    return _settings_card_html(inner_html)


def _stylus_reset_flash_text(
    input_index: int,
    result,
    *,
    settings_saved: bool = False,
) -> str:
    if result is None:
        return (
            f"Settings saved, but Input {input_index} stylus reset failed"
            if settings_saved
            else f"Input {input_index} stylus reset failed"
        )
    if result.applied and result.persisted:
        return f"Input {input_index} stylus reset"
    if result.applied:
        return (
            f"Input {input_index} stylus reset, but it could not be saved "
            "and may be lost after restart"
        )
    return (
        f"Settings saved, but Input {input_index} stylus reset failed"
        if settings_saved
        else f"Input {input_index} stylus reset failed"
    )


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
    submit_label = "Finish" if initial_setup else "Save Settings"
    nav_html = "" if initial_setup else """<a href="/" class="pill-btn">← Done</a>"""
    playback_snapshot = get_playback_snapshot()
    input1_snapshot = playback_snapshot.inputs.get(1) or _fallback_input_snapshot(
        parsed.audio1,
        1,
        enabled=True,
    )
    input2_snapshot = playback_snapshot.inputs.get(2) or _fallback_input_snapshot(
        parsed.audio2,
        2,
        enabled=parsed.audio2_enabled,
    )
    owntone_button_html = "" if initial_setup else """
          <button type="button"
            onclick="window.location.href='/owntone-setup';"
            style="width:100%;padding:0.8rem;border-radius:999px;background:#6c757d;opacity:1;color:#fff;border:none;font-weight:600;margin-top:0.5rem;font-size:1.1rem;">
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
            sel = " selected" if hw == cur_str else ""
            if sel:
                found = True
            opts += (
                f"<option value='{html.escape(hw)}'{sel}>"
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
        snapshot: InputPlaybackSnapshot,
        capture_name: str,
        threshold_name: str,
        turntable_name: str,
        stylus_life_name: str,
        enabled: bool = True,
        enabled_name: Optional[str] = None,
    ) -> str:
        prefix = "audio1" if input_index == 1 else "audio2"
        threshold_id = "audio_silence_threshold" if input_index == 1 else "audio2_silence_threshold"
        turntable_note_id = f"{prefix}_turntable_note"
        stylus_wrap_id = f"{prefix}_stylus_wrap"
        playback_wrap_id = f"{prefix}_playback_wrap"
        settings_wrap_id = f"{prefix}_settings"
        is_turntable = bool(parsed_input.is_turntable)
        threshold_preset = suggested_silence_threshold_dbfs(is_turntable)
        stylus_life_hours = normalize_stylus_life_hours(parsed_input.stylus_life_hours)
        stylus_options_html = "".join(
            f"<option value='{hours}'{' selected' if hours == stylus_life_hours else ''}>{hours} hours</option>"
            for hours in get_stylus_life_options()
        )

        reset_button_html = ""
        if not initial_setup:
            reset_button_html = (
                f"<button type='submit' name='stylus_reset_input' value='{input_index}' "
                "class='pill-btn small' style='padding:0.32rem 0.7rem;font-size:0.85rem;' "
                f"onclick=\"return confirm('Mark {html.escape(title)} stylus as changed?');\">"
                "Mark Stylus Changed</button>"
            )

        show_playback_card = not initial_setup
        playback_html = (
            _playback_summary_html(
                snapshot,
                input_index=input_index,
                reset_button_html=reset_button_html,
                stylus_life_hours=stylus_life_hours,
            )
            if show_playback_card
            else ""
        )

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

        return f"""
        <fieldset><legend>{html.escape(title)}</legend>
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
            <div id="{stylus_wrap_id}" style="display:{'block' if is_turntable else 'none'};">
              <label>Stylus Rated Life:
                <select name="{stylus_life_name}" onchange="syncInputUi({input_index})">
                  {stylus_options_html}
                </select>
              </label>
            </div>
            <div id="{playback_wrap_id}" style="display:{'block' if show_playback_card and is_turntable else 'none'};">
              {playback_html}
            </div>
            {_audio_controls_card_html(
                input_index=input_index,
                gain_db=parsed_input.gain_db,
                eq_40hz_db=parsed_input.eq_40hz_db,
                eq_100hz_db=parsed_input.eq_100hz_db,
                eq_10khz_db=parsed_input.eq_10khz_db,
            ) if not initial_setup else ""}
          {settings_close}
        </fieldset>
        """

    owntone_outputs_html = ""
    try:
        resp = requests.get(parsed.owntone.base_url.rstrip("/") + "/api/outputs", timeout=3)
        if resp.status_code == 200:
            outputs = resp.json().get("outputs", [])
            hidden = {str(n).strip().casefold() for n in (parsed.webui.hidden_outputs or ()) if str(n).strip()}
            for out in outputs:
                nm = out.get("name", "")
                if not nm: continue
                if nm.strip().casefold() in hidden and nm != parsed.owntone.output_name: continue
                sel = " selected" if nm == parsed.owntone.output_name else ""
                owntone_outputs_html += f"<option value='{html.escape(nm)}'{sel}>{html.escape(nm)}</option>"
    except Exception:
        pass

    lic_html, lic_spacer = build_top_banner_html(flash_msg=flash_msg, flash_type=flash_type)
    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""
    csrf_meta = f"<meta name='csrf-token' content='{html.escape(csrf_token)}'><script>window.__CSRF='{html.escape(csrf_token)}';</script>"
    pin_modal_setup_css = """
      #pinModal .pin-entry {
        -webkit-text-security: disc;
        text-security: disc;
      }
    """
    input1_html = input_fieldset_html(
        input_index=1,
        title="Input 1",
        parsed_input=parsed.audio1,
        snapshot=input1_snapshot,
        capture_name="audio_capture_device",
        threshold_name="audio_silence_threshold",
        turntable_name="audio_turntable",
        stylus_life_name="audio_stylus_life_hours",
    )
    input2_html = input_fieldset_html(
        input_index=2,
        title="Input 2",
        parsed_input=parsed.audio2,
        snapshot=input2_snapshot,
        capture_name="audio2_capture_device",
        threshold_name="audio2_silence_threshold",
        turntable_name="audio2_turntable",
        stylus_life_name="audio2_stylus_life_hours",
        enabled=parsed.audio2_enabled,
        enabled_name="audio2_enabled",
    )

    html_body = textwrap.dedent(f"""\
      <!DOCTYPE html><html><head><meta charset="utf-8">{VIEWPORT_META}
      <title>autostream</title><style>{STYLE_CSS}\n{PIN_MODAL_CSS}\n{pin_modal_setup_css}</style>{csrf_meta}
      </head>
      <body>{lic_html}{lic_spacer}<div class="container">{BANNER_HTML}<h1>{h1}</h1>
      <p class="actions" style="display:flex;justify-content:space-between;gap:0.75rem;">
        {nav_html}
        <a href="/logs" class="pill-btn">Logs</a>
      </p>
      {f"<p style='color:green;'>Saved</p>" if saved_ok else ""}
      {f"<p style='color:red;'>{html.escape(error)}</p>" if error else ""}
      <form method="POST" action="/setup" autocomplete="off">
        <input type="hidden" name="csrf_token" value="{html.escape(csrf_token)}">
        {input1_html}
        {input2_html}
        <fieldset><legend>Playback</legend>
          <label>Default Speakers:
            <select id="owntone_output_select" name="owntone_output_name">
              {owntone_outputs_html}
            </select>
            <div id="owntone_output_hint" class="helptext" style="display:none;">
              Looking for speakers…
            </div>
          </label>
          <label><div class="slider-header"><span>Default Volume:</span><span id="vol_val">{parsed.owntone.volume_percent}%</span></div>
          <input type="range" min="0" max="100" value="{parsed.owntone.volume_percent}" oninput="syncVol(this.value)">
          <input type="hidden" id="owntone_volume_percent" name="owntone_volume_percent" value="{parsed.owntone.volume_percent}"></label>
          <label><div class="slider-header"><span>Silence detection:</span><span id="sil_val">{parsed.general.silence_seconds}s</span></div>
          <input type="range" name="silence_seconds" min="10" max="300" value="{parsed.general.silence_seconds}" oninput="syncSil(this.value)"></label>
          {owntone_button_html}
        </fieldset>
        <fieldset><legend>System (build: {html.escape(get_app_version())})</legend>
          <label style="display:flex;align-items:center;gap:.75rem;">
            <span>Hostname:</span><input style="flex:1" type="text" name="system_hostname" value="{html.escape(get_system_hostname())}">
          </label>
          {update_html}
        </fieldset>
        <p class="actions"><button type="submit">{submit_label}</button></p>
      </form></div>
      <div id="pinModal" role="dialog" aria-modal="true" aria-labelledby="pinModalTitle">
        <div class="panel">
          <div class="hdr" id="pinModalTitle">Change PIN</div>
          <div class="bd">
            <p id="pinModalMessage">Enter your current PIN.</p>
            <p id="pinModalError" style="display:none;color:#b00020;font-weight:600;"></p>
          </div>
          <div class="ft">
            <button type="button" class="btn cancel" id="pinModalCancel">Cancel</button>
            <button type="button" class="btn ok" id="pinModalOk">Continue</button>
          </div>
        </div>
      </div>
      {A2HS_SCRIPT}
      </body>
      <script>
        const pinChangeState = {{
          step: 'idle',
          newPin: '',
          busy: false,
        }};
        function pinModalElements() {{
          return {{
            modal: document.getElementById('pinModal'),
            title: document.getElementById('pinModalTitle'),
            body: document.querySelector('#pinModal .bd'),
            message: document.getElementById('pinModalMessage'),
            error: document.getElementById('pinModalError'),
            input: document.getElementById('pinModalValue'),
            cancel: document.getElementById('pinModalCancel'),
            ok: document.getElementById('pinModalOk'),
          }};
        }}
        function ensurePinModalInput() {{
          const els = pinModalElements();
          if (!els.body) return null;
          if (els.input) return els.input;
          const input = document.createElement('input');
          input.id = 'pinModalValue';
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
          input.setAttribute('placeholder', '');
          input.addEventListener('keydown', (ev) => {{
            if (ev.key === 'Enter') {{
              ev.preventDefault();
              handlePinModalOk();
            }}
          }});
          const err = els.error;
          if (err && err.parentNode === els.body) {{
            els.body.insertBefore(input, err.nextSibling);
          }} else {{
            els.body.appendChild(input);
          }}
          return input;
        }}
        function armPinModalInput() {{
          const input = ensurePinModalInput();
          if (!input) return;
          input.setAttribute('name', 'v');
          const enable = () => input.removeAttribute('readonly');
          input.addEventListener('pointerdown', enable, {{ once: true }});
          input.addEventListener('focus', enable, {{ once: true }});
        }}
        function resetPinChangeState() {{
          pinChangeState.step = 'idle';
          pinChangeState.newPin = '';
          pinChangeState.busy = false;
        }}
        function setPinModalBusy(busy) {{
          pinChangeState.busy = !!busy;
          const els = pinModalElements();
          if (!els.cancel || !els.ok || !els.input) return;
          els.cancel.disabled = !!busy;
          els.ok.disabled = !!busy;
          els.input.disabled = !!busy;
        }}
        function showPinModalStep(step, options) {{
          const opts = options || {{}};
          ensurePinModalInput();
          const els = pinModalElements();
          if (!els.modal) return;
          pinChangeState.step = step;
          els.modal.classList.add('show');
          els.title.textContent = opts.title || 'Change PIN';
          els.message.textContent = opts.message || '';
          if (opts.error) {{
            els.error.style.display = '';
            els.error.textContent = opts.error;
          }} else {{
            els.error.style.display = 'none';
            els.error.textContent = '';
          }}
          els.input.style.display = opts.showInput === false ? 'none' : '';
          els.input.type = opts.inputType || 'text';
          els.input.placeholder = opts.placeholder || '';
          els.input.value = '';
          els.input.setAttribute('readonly', 'readonly');
          els.cancel.textContent = opts.cancelLabel || 'Cancel';
          els.cancel.style.display = opts.showCancel === false ? 'none' : '';
          els.ok.textContent = opts.okLabel || 'Continue';
          els.ok.style.display = opts.showOk === false ? 'none' : '';
          setPinModalBusy(false);
          armPinModalInput();
          if (opts.showInput === false) {{
            els.input.blur();
          }}
        }}
        function closePinModal() {{
          const els = pinModalElements();
          if (!els.modal) return;
          els.modal.classList.remove('show');
          if (els.input) {{
            els.input.value = '';
            els.input.remove();
          }}
          els.error.style.display = 'none';
          els.error.textContent = '';
          resetPinChangeState();
        }}
        function openChangePinModal() {{
          resetPinChangeState();
          showPinModalStep('new', {{
            title: 'Change PIN',
            message: 'Enter your new PIN.',
            placeholder: 'New',
            cancelLabel: 'Cancel',
            okLabel: 'Continue',
          }});
        }}
        function pinModalFailure(message) {{
          showPinModalStep('failure', {{
            title: 'Change PIN',
            message: message || 'Unable to change PIN.',
            showInput: false,
            cancelLabel: 'Cancel',
            showOk: false,
          }});
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
          const value = (els.input.value || '').trim();
          els.input.value = '';
          if (pinChangeState.step === 'new') {{
            if (!value) {{
              showPinModalStep('new', {{
                title: 'Change PIN',
                message: 'Enter your new PIN.',
                placeholder: 'New',
                cancelLabel: 'Cancel',
                okLabel: 'Continue',
                error: 'Enter a new PIN.',
              }});
              return;
            }}
            pinChangeState.newPin = value;
            showPinModalStep('confirm', {{
              title: 'Change PIN',
              message: 'Enter the new PIN again.',
              placeholder: 'Repeat',
              cancelLabel: 'Cancel',
              okLabel: 'Apply',
            }});
            return;
          }}
          if (pinChangeState.step === 'confirm') {{
            if (!value) {{
              showPinModalStep('confirm', {{
                title: 'Change PIN',
                message: 'Enter the new PIN again.',
                placeholder: 'Repeat',
                cancelLabel: 'Cancel',
                okLabel: 'Apply',
                error: 'Enter the new PIN again.',
              }});
              return;
            }}
            if (pinChangeState.newPin !== value) {{
              showPinModalStep('mismatch', {{
                title: 'Change PIN',
                message: 'Values did not match.',
                showInput: false,
                cancelLabel: 'Cancel',
                showOk: false,
              }});
              return;
            }}
            setPinModalBusy(true);
            try {{
              const result = await submitPinChange(pinChangeState.newPin, value);
              if (result.status === 200 && result.body.ok) {{
                showPinModalStep('success', {{
                  title: 'Change PIN',
                  message: 'PIN changed successfully. Returning to the home screen…',
                  showInput: false,
                  cancelLabel: 'Continue',
                  showOk: false,
                }});
                window.setTimeout(() => {{
                  window.location.href = '/';
                }}, 900);
                return;
              }}
              pinModalFailure(friendlyPinChangeError(result.body.error || 'Unable to change PIN.'));
            }} catch (e) {{
              pinModalFailure('Unable to change PIN.');
            }} finally {{
              setPinModalBusy(false);
            }}
          }}
        }}
        function handlePinModalCancel() {{
          if (pinChangeState.step === 'success') {{
            window.location.href = '/';
            return;
          }}
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
        function syncStylusLife(inputIndex, value){{
          const prefix = inputIndex === 1 ? 'audio1' : 'audio2';
          const hoursEl = document.getElementById(prefix + '_stylus_hours');
          const remainingEl = document.getElementById(prefix + '_stylus_remaining');
          if (!hoursEl || !remainingEl) return;
          const lifeHours = Math.max(1, parseInt(value, 10) || 500);
          const usedSeconds = parseInt(hoursEl.getAttribute('data-used-seconds') || '0', 10) || 0;
          const usedHours = (Math.max(0, usedSeconds) / 3600).toFixed(1);
          hoursEl.textContent = usedHours + ' h / ' + String(lifeHours) + ' h';
          const remainingSeconds = (lifeHours * 3600) - Math.max(0, usedSeconds);
          remainingEl.textContent = remainingSeconds > 0
            ? ((remainingSeconds / 3600).toFixed(1) + ' h')
            : 'Due now';
        }}
        function syncInputUi(inputIndex){{
          const prefix = inputIndex === 1 ? 'audio1' : 'audio2';
          const turntableName = inputIndex === 1 ? 'audio_turntable' : 'audio2_turntable';
          const stylusLifeName = inputIndex === 1 ? 'audio_stylus_life_hours' : 'audio2_stylus_life_hours';
          const enabled = inputIndex === 1
            ? true
            : !!document.querySelector('input[name="audio2_enabled"]')?.checked;
          const turntable = !!document.querySelector('input[name="' + turntableName + '"]')?.checked;
          const settings = document.getElementById(prefix + '_settings');
          const thresholdId = inputIndex === 1 ? 'audio_silence_threshold' : 'audio2_silence_threshold';
          const note = document.getElementById(prefix + '_turntable_note');
          const wrap = document.getElementById(prefix + '_stylus_wrap');
          const playbackWrap = document.getElementById(prefix + '_playback_wrap');
          const statusRow = document.getElementById(prefix + '_status_row');
          const statusValue = document.getElementById(prefix + '_status_value');
          const threshold = thresholdPreset(turntable);
          const hidden = document.getElementById(thresholdId);
          if (settings) settings.style.display = enabled ? 'block' : 'none';
          if (hidden) hidden.value = String(threshold);
          if (note) note.textContent = 'Detection threshold preset: ' + String(threshold) + ' dB';
          if (wrap) wrap.style.display = enabled && turntable ? 'block' : 'none';
          if (playbackWrap) playbackWrap.style.display = enabled && turntable ? 'block' : 'none';
          if (statusRow && statusValue) {{
            const rowWasActive = statusRow.dataset.active === '1';
            if (!enabled) {{
              statusRow.style.display = '';
              statusValue.textContent = 'Disabled';
            }} else if (rowWasActive) {{
              statusRow.style.display = '';
              statusValue.textContent = 'Active now';
            }} else {{
              statusRow.style.display = 'none';
              statusValue.textContent = '';
            }}
          }}
          if (enabled && turntable) {{
            const lifeSel = document.querySelector('select[name="' + stylusLifeName + '"]');
            if (lifeSel) syncStylusLife(inputIndex, lifeSel.value);
          }}
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
        function localizeResetDates(){{
          document.querySelectorAll('.local-reset-date[data-reset-iso]').forEach((el) => {{
            const raw = String(el.getAttribute('data-reset-iso') || '').trim();
            if (!raw) return;
            const dt = new Date(raw);
            if (!Number.isNaN(dt.getTime())) {{
              try {{
                el.textContent = dt.toLocaleDateString();
              }} catch (e) {{
              }}
            }}
          }});
        }}
        window.addEventListener('DOMContentLoaded', () => {{
          const changePinBtn = document.getElementById('btnChangePin');
          const pinModalCancel = document.getElementById('pinModalCancel');
          const pinModalOk = document.getElementById('pinModalOk');
          if (changePinBtn) changePinBtn.addEventListener('click', openChangePinModal);
          if (pinModalCancel) pinModalCancel.addEventListener('click', handlePinModalCancel);
          if (pinModalOk) pinModalOk.addEventListener('click', handlePinModalOk);
          syncInputUi(1);
          syncInputUi(2);
          localizeResetDates();
        }});
        function requestReboot(){{
          if(!confirm("Reboot system?")) return;
          // Navigate to the holding page first so it can be served before the reboot begins.
          // The holding page will POST /api/reboot and then auto-return to '/' when ready.
          window.location.href = "/rebooting";
        }}
        (async function(){{
          const msg = (t) => {{ document.getElementById("updMsg").textContent = t; }};
          const bCheck = document.getElementById("btnCheck"), bInst = document.getElementById("btnInst");
          let cand = null;
          async function poll(){{
            const r = await fetch("/api/update/status"); const j = await r.json();
            if(j.running){{ msg("Installing update..."); bCheck.disabled=true; bInst.disabled=true; setTimeout(poll,2000); return; }}
            bCheck.disabled=false;
            if(j.last_result){{ msg(j.last_result.ok?"Update installed.":"Update failed: "+j.last_result.error); }}
          }}
          bCheck.onclick = async () => {{
            msg("Checking..."); bInst.disabled=true;
            const r = await fetch("/api/update/check"); const j = await r.json();
            if(j.ok && j.update_available){{ cand=j.candidate; msg("Update available: "+j.candidate); bInst.disabled=false; }}
            else msg(j.ok?"No updates available.":"Check failed.");
          }};
          bInst.onclick = async () => {{ if(!cand)return; msg("Starting..."); bCheck.disabled=true; bInst.disabled=true; await fetch("/api/update/apply",{{method:"POST",headers:{{"X-CSRF-Token":window.__CSRF||""}}}}); poll(); }};
          poll();
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
      </html>
    """)
    body_bytes = html_body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)
