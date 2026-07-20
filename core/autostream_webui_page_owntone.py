#!/usr/bin/env python3
"""autostream_webui_page_owntone.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Owntone setup page, restart async support, and the restarting holding page.

Contents:
  - wait_for_owntone_api         -- poll OwnTone /api/outputs until ready
  - _owntone_ready_quick         -- single fast readiness probe
  - _restart_owntone_worker      -- background restart + wait loop
  - start_owntone_restart_async  -- fire-and-forget restart
  - send_owntone_ready_json      -- GET /api/owntone/ready
  - send_owntone_restarting_page -- GET /owntone-restarting
  - send_owntone_setup_page      -- GET /owntone-setup
"""

from __future__ import annotations

import html
import json
import threading
import time

from typing import Optional
from urllib.parse import parse_qs, quote, urlparse

from autostream_config import (
    BUFFERED_AIRPLAY_MODES,
    DEFAULT_AIRPLAY_MODE,
    load_state,
    parse_config,
)
from autostream_players import (
    SETTING_BUFFERED_AUDIO_ENABLED,
    SETTING_START_BUFFER_MS,
    SETTING_START_BUFFER_MS_DEFAULT,
    SETTING_START_BUFFER_MS_MAX,
    SETTING_START_BUFFER_MS_MIN,
    SETTING_START_BUFFER_MS_STEP,
    SETTING_UNCOMPRESSED_ALAC,
)
from autostream_player_service import (
    get_capabilities,
    get_setting,
    list_outputs,
    output_supported_config_modes,
)
from autostream_sysutils import run_admin_cmd
from autostream_webui_common import _config_snapshot, build_page_html, build_top_banner_html, locked_load_config
from autostream_webui_assets import AUTOSAVE_JS
from autostream_webui_state import WebUIState
from autostream_webui_api import send_json


# -----------------------------------------------------------------------------
# OwnTone readiness helpers
# -----------------------------------------------------------------------------

def wait_for_owntone_api(base_url: str, timeout_s: float = 10.0) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout_s
    last_err = ""
    while time.monotonic() < deadline:
        result = list_outputs(base_url, timeout=1)
        if result.ok:
            return True, ""
        last_err = result.message or "unavailable"
        time.sleep(0.5)
    return False, f"Owntone is still starting ({last_err})"


def _owntone_ready_quick(base_url: str, timeout_s: float = 0.6) -> tuple[bool, str]:
    """Fast readiness probe used by /api/owntone/ready."""
    result = list_outputs(base_url, timeout=timeout_s)
    if result.ok:
        return True, "Owntone is responding"
    return False, result.message or "unavailable"


# -----------------------------------------------------------------------------
# Async restart support
# -----------------------------------------------------------------------------

def _restart_owntone_worker(state, token: int) -> None:
    """Background restart + wait loop. Updates state when done."""
    try:
        p = run_admin_cmd(["restart-owntone"], timeout=20.0)
        if p.returncode != 0:
            raise RuntimeError(
                f"autostream-admin restart-owntone failed (rc={p.returncode}): {(p.stderr or '').strip()}"
            )
    except Exception as e:
        state.finish_owntone_restart(token, ok=False, message=f"Restart command failed: {e}")
        return

    # After restart command, wait for API to come back (more generous than the UI poll).
    try:
        parsed = _config_snapshot(state)
        ok, msg = wait_for_owntone_api(parsed.owntone.base_url, timeout_s=20.0)
    except Exception as e:
        ok, msg = False, str(e)

    state.finish_owntone_restart(
        token, ok=bool(ok), message=msg if msg else ("Ready" if ok else "Not ready")
    )


_restart_timer_lock: threading.Lock = threading.Lock()
_restart_timer: Optional[threading.Timer] = None


def start_owntone_restart_async(state, delay_s: float = 0.75) -> None:
    """Schedule a background OwnTone restart, coalescing rapid calls within delay_s.

    Multiple calls within delay_s of each other are collapsed into one restart.
    The restart token is acquired only when the timer fires, ensuring the
    WebUIState in_progress flag is accurate.
    """
    global _restart_timer
    with _restart_timer_lock:
        if _restart_timer is not None:
            _restart_timer.cancel()

        def _fire() -> None:
            global _restart_timer
            with _restart_timer_lock:
                _restart_timer = None
            token = state.begin_owntone_restart()
            t = threading.Thread(
                target=_restart_owntone_worker, args=(state, token), daemon=True
            )
            t.start()

        _restart_timer = threading.Timer(delay_s, _fire)
        _restart_timer.daemon = True
        _restart_timer.start()


# -----------------------------------------------------------------------------
# JSON endpoint
# -----------------------------------------------------------------------------

def send_owntone_ready_json(handler, state) -> None:
    """JSON endpoint polled by /owntone-restarting."""
    try:
        parsed = _config_snapshot(state)
        ready, ready_msg = _owntone_ready_quick(parsed.owntone.base_url, timeout_s=0.6)
    except Exception as e:
        ready, ready_msg = False, str(e)

    restart = state.get_owntone_restart_state()
    payload = {
        "ok": bool(ready),
        "probe": ready_msg,
        "restart": {
            "in_progress": bool(restart["in_progress"]),
            "started_at": float(restart["started_at"]),
            "finished_at": float(restart["finished_at"]),
            "ok": bool(restart["ok"]),
            "message": str(restart["message"]),
        },
    }
    send_json(handler, 200, payload)


# -----------------------------------------------------------------------------
# Restarting holding page
# -----------------------------------------------------------------------------

def send_owntone_restarting_page(handler, state) -> None:
    """Simple 'restarting' page that polls /api/owntone/ready and redirects when ready."""
    # Allow a caller-provided next target, defaulting to owntone setup.
    qs = parse_qs(urlparse(handler.path).query)
    next_path = (qs.get("next", []) or ["/owntone-setup"])[0]
    next_path_html = html.escape(next_path, quote=True)
    next_path_js = json.dumps(next_path)  # safe for embedding in a JS string literal

    body = f"""<!doctype html>
      <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Restarting Owntone</title>
        <style>
          body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; }}
          .box {{ max-width: 42rem; padding: 1.25rem; border: 1px solid #ddd; border-radius: 12px; }}
          .muted {{ color: #666; }}
          code {{ background: #f6f6f6; padding: 0.15rem 0.35rem; border-radius: 6px; }}
        </style>
      </head>
      <body>
        <div class="box">
          <h1>Restarting Owntone…</h1>
          <p class="muted">This can take a few seconds on a Pi Zero. We'll continue automatically when it's ready.</p>
          <p id="status" class="muted">Checking…</p>
          <p class="muted">If this doesn't move on, you can <a href="{next_path_html}">try continuing</a>.</p>
        </div>
        <script>
          const nextPath = {next_path_js};
          async function poll() {{
            try {{
              const r = await fetch("/api/owntone/ready", {{ cache: "no-store" }});
              const j = await r.json();
              const msg = (j.restart && j.restart.message) ? j.restart.message : "";
              const probe = j.probe ? j.probe : "";
              document.getElementById("status").textContent =
                (j.ok ? "Ready. Redirecting…" : ("Not ready yet. " + (msg || probe || "")));
              if (j.ok) {{
                window.location.replace(nextPath);
                return;
              }}
            }} catch (e) {{
              document.getElementById("status").textContent = "Not ready yet. (" + e + ")";
            }}
            setTimeout(poll, 800);
          }}
          poll();
        </script>
      </body>
      </html>
    """
    body_bytes = body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)


# -----------------------------------------------------------------------------
# Owntone setup page
# -----------------------------------------------------------------------------

def send_owntone_setup_page(
    handler,
    state: WebUIState,
    auth,
    saved_ok: bool = False,
    error: Optional[str] = None,
    flash_msg: Optional[str] = None,
) -> None:
    """Render Owntone setup."""
    try:
        state_data = load_state(state.state_path)
        if getattr(state, "settings", None) is not None:
            raw = state.settings.raw_snapshot()
            parsed = parse_config(raw, state_data)
        else:
            cfg = locked_load_config(state.config_path)
            parsed = parse_config(cfg, state_data)
    except Exception:
        try:
            handler.send_response(302)
            handler.send_header("Location", "/")
            handler.end_headers()
        except Exception:
            pass
        return

    hidden_set = {str(n).strip().casefold() for n in (parsed.webui.hidden_outputs or ()) if str(n).strip()}
    outputs_result = list_outputs(parsed.owntone.base_url, timeout=3)
    outputs = list(outputs_result.outputs) if outputs_result.ok else []
    capabilities = get_capabilities(parsed.owntone.base_url, timeout=3)

    known_outputs = dict(parsed.owntone.known_outputs)
    discovered_ids: set[str] = set()
    row_specs: list[dict[str, object]] = []

    for output in outputs:
        name = str(output.name or "").strip()
        out_id_s = str(output.id or "").strip()
        if not name or not out_id_s:
            continue
        known_outputs[out_id_s] = name
        discovered_ids.add(out_id_s)
        row_specs.append(
            {
                "id": out_id_s,
                "name": name,
                "output": output,
                "discovered": True,
            }
        )

    for out_id_s, name in known_outputs.items():
        key = str(out_id_s).strip()
        disp = str(name).strip()
        if not key or not disp or key in discovered_ids:
            continue
        row_specs.append(
            {
                "id": key,
                "name": disp,
                "output": None,
                "discovered": False,
            }
        )

    known_row_names = {str(spec["name"]).casefold() for spec in row_specs if spec.get("name")}
    for hidden_name in (parsed.webui.hidden_outputs or ()):
        h_s = str(hidden_name).strip()
        if not h_s or h_s.casefold() in known_row_names:
            continue
        row_specs.append(
            {
                "id": "",
                "name": h_s,
                "output": None,
                "discovered": False,
            }
        )

    row_specs.sort(
        key=lambda spec: (
            0 if str(spec["name"]).casefold() not in hidden_set else 1,
            str(spec["name"]).casefold(),
        ),
    )

    uncompressed_result = get_setting(
        parsed.owntone.base_url,
        SETTING_UNCOMPRESSED_ALAC,
        timeout=3,
    )
    uncompressed_supported = bool(uncompressed_result.ok)
    uncompressed = bool(uncompressed_result.value) if uncompressed_result.ok else False

    buffered_audio_result = get_setting(
        parsed.owntone.base_url,
        SETTING_BUFFERED_AUDIO_ENABLED,
        timeout=3,
    )
    buffered_audio_supported = bool(buffered_audio_result.ok)
    # Hide the toggle only when the backend genuinely lacks the setting. A transient
    # read failure (timeout, connection refused) must not make the control silently
    # vanish, or a momentary outage looks identical to "your backend can't do this".
    buffered_audio_unavailable = bool(
        not buffered_audio_result.ok and not buffered_audio_result.unsupported
    )
    buffered_audio_enabled = bool(buffered_audio_result.value) if buffered_audio_result.ok else False

    start_buffer_result = get_setting(
        parsed.owntone.base_url,
        SETTING_START_BUFFER_MS,
        timeout=3,
    )
    if start_buffer_result.ok:
        try:
            _buf_raw = int(start_buffer_result.value)
        except Exception:
            _buf_raw = None
    else:
        _buf_raw = None
    if _buf_raw is not None:
        start_buffer_ms = max(SETTING_START_BUFFER_MS_MIN, min(SETTING_START_BUFFER_MS_MAX,
            round(_buf_raw / SETTING_START_BUFFER_MS_STEP) * SETTING_START_BUFFER_MS_STEP))
    else:
        start_buffer_ms = SETTING_START_BUFFER_MS_DEFAULT
    start_buffer_available = bool(start_buffer_result.ok)

    speakers_html = ""
    for i, row in enumerate(row_specs):
        spk = str(row["name"])
        show = spk.casefold() not in hidden_set
        output = row.get("output")
        out_id = str(row.get("id") or "").strip()
        discovered = bool(row.get("discovered"))
        saved_runtime_mode = parsed.owntone.output_airplay_modes.get(out_id, DEFAULT_AIRPLAY_MODE)
        supported_config_modes = (
            output_supported_config_modes(output)
            if output is not None and out_id
            else (DEFAULT_AIRPLAY_MODE,)
        )
        # Buffered-transport modes are only selectable while buffered audio is on.
        # Dropping them here also coerces an output still saved as one back to Auto
        # for display, via the unsupported-mode fallback below.
        if not buffered_audio_enabled:
            supported_config_modes = tuple(
                mode for mode in supported_config_modes
                if mode not in BUFFERED_AIRPLAY_MODES
            ) or (DEFAULT_AIRPLAY_MODE,)

        mode_note_html = ""
        current_mode = saved_runtime_mode or DEFAULT_AIRPLAY_MODE
        if current_mode not in supported_config_modes and discovered and output is not None:
            current_mode = DEFAULT_AIRPLAY_MODE
        if out_id and not discovered:
            mode_note_html = (
                "<div class='storage-meta'>Speaker not currently discovered. "
                "Saved mode will be applied when it reappears.</div>"
            )
        elif out_id and len(supported_config_modes) == 1:
            mode_note_html = (
                "<div class='storage-meta'>Only Auto mode is currently exposed by this backend. "
                "Additional protocols will appear here when supported.</div>"
            )
        elif not out_id:
            mode_note_html = (
                "<div class='storage-meta'>Speaker id is not known yet. Rediscover the speaker before changing its mode.</div>"
            )

        can_edit_mode = bool(out_id and discovered and output is not None and capabilities.can_set_output_mode)

        offset_html = ""
        if capabilities.can_set_output_offset and out_id and (
            (output is not None and output.offset_ms is not None)
            or out_id in parsed.owntone.output_offsets_ms
        ):
            try:
                cur_off = parsed.owntone.output_offsets_ms.get(out_id, 0)
            except Exception:
                cur_off = 0
            cur_off = max(-2000, min(2000, int(cur_off)))
            offset_html = f"""
                  <label style="display:block;margin-top:0.5rem;">
                    <div class="slider-header">
                      <span>Offset:</span>
                      <span id="off_val_{i}">{cur_off} ms</span>
                    </div>
                    <input type="range"
                           name="offset_{i}"
                           min="-2000" max="2000" step="10"
                           value="{cur_off}"
                           oninput="document.getElementById('off_val_{i}').textContent=this.value+' ms';
                                    if(liveEnabled) _owntoneOffsetDebounced({json.dumps(out_id)}, parseInt(this.value,10));">
                  </label>
                """

        _out_id_js = json.dumps(out_id)
        _out_name_js = json.dumps(spk)

        if can_edit_mode:
            mode_options = ""
            for supported_mode in supported_config_modes:
                label = "Auto"
                if supported_mode == "raop":
                    label = "AirPlay"
                elif supported_mode == "airplay2":
                    label = "AirPlay 2"
                elif supported_mode == "airplay2_buffered":
                    label = "AirPlay 2 (buffered)"
                elif supported_mode == "airplay2_surround_stereo":
                    label = "AirPlay 2 (stereo for 5.1 systems)"
                elif supported_mode == "airplay2_surround_upmix":
                    label = "AirPlay 2 (5.1 upmix)"
                mode_options += (
                    f'<option value="{supported_mode}"'
                    f'{" selected" if current_mode == supported_mode else ""}>{label}</option>'
                )
            _mode_change = (
                f"if(liveEnabled) settingsTransact('/api/owntone/output-mode',"
                f"{{output_id:{_out_id_js},mode:this.value}});"
            )
            mode_html = f"""
            <label style="display:block;margin-bottom:0.5rem;">
              <span>Mode</span>
              <select name="mode_{i}"{' disabled' if len(supported_config_modes) <= 1 else ''}
                      onchange="{html.escape(_mode_change)}">{mode_options}</select>
            </label>{mode_note_html}"""
        else:
            mode_html = (
                f'<input type="hidden" name="mode_{i}" value="{current_mode}">{mode_note_html}'
            )

        _vis_change = (
            f"onShowToggle({i}, this.checked);"
            f"if(liveEnabled) settingsTransact('/api/owntone/output-visibility',"
            f"{{output_name:{_out_name_js},output_id:{_out_id_js},visible:this.checked}});"
        )
        speakers_html += f"""
          <fieldset><legend>{html.escape(spk)}</legend>
          <input type="hidden" name="spk_id_{i}" value="{html.escape(out_id)}">
          <input type="hidden" name="spk_{i}" value="{html.escape(spk)}">
          <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" name="show_{i}" {'checked' if show else ''}
                     onchange="{html.escape(_vis_change)}">
                <span class="switch"></span>
            </label>
            <span>Show in autostream</span>
          </div>
          <div id="spk_settings_{i}" style="display:{'block' if show else 'none'};">
            {mode_html}
            {offset_html}
          </div>
          </fieldset>
        """

    lic_html, lic_spacer = build_top_banner_html(flash_msg=flash_msg)
    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""
    csrf_meta = f"<meta name='csrf-token' content='{html.escape(csrf_token)}'><script>window.__CSRF='{html.escape(csrf_token)}';</script>"

    page_heading_html = "<h1>Owntone Setup</h1>"

    # Uncompressed audio: autosave onchange in configured mode
    _uncomp_onchange_attr = ""
    if uncompressed_supported:
        _oc = "if(liveEnabled) settingsTransact('/api/owntone/uncompressed-audio', {value: this.checked});"
        _uncomp_onchange_attr = f" onchange='{html.escape(_oc)}'"
    _uncomp_input = (
        f"<input type='checkbox' name='uncompressed_alac' {'checked' if uncompressed else ''}"
        f"{' disabled' if not uncompressed_supported else ''}"
        f"{_uncomp_onchange_attr}>"
    )

    # Buffered audio: omitted entirely when the backend does not expose the setting,
    # but rendered disabled-with-a-note when the read merely failed (see above).
    _buffered_audio_html = ""
    if buffered_audio_supported or buffered_audio_unavailable:
        _ba_onchange_attr = ""
        if buffered_audio_supported:
            # Reload on success: the per-output mode selects were rendered against
            # the previous state, so they still offer (or still omit) the buffered
            # modes until the page is rebuilt.
            _ba_oc = (
                "if(liveEnabled) settingsTransact('/api/owntone/buffered-audio',"
                " {value: this.checked},"
                " {onSuccess: function(){ window.location.reload(); }});"
            )
            _ba_onchange_attr = f" onchange='{html.escape(_ba_oc)}'"
        _buffered_audio_input = (
            f"<input type='checkbox' name='buffered_audio_enabled' {'checked' if buffered_audio_enabled else ''}"
            f"{' disabled' if not buffered_audio_supported else ''}"
            f"{_ba_onchange_attr}>"
        )
        _buffered_audio_html = (
            "<div style='display:flex;align-items:center;gap:0.75rem;margin-top:0.75rem;'>"
            f"<label class='output-toggle' style='margin:0;'>"
            + _buffered_audio_input
            + "<span class='switch'></span>"
            + "</label>"
            + "<span>Enable AirPlay 2 Buffered Audio</span>"
            + "</div>"
        )
        if buffered_audio_unavailable:
            _buffered_audio_html += (
                '<div class="storage-meta">Could not read the buffered-audio setting '
                'from the backend just now. Refresh to try again.</div>'
            )

    # Start buffer: autosave (debounced) in configured mode
    _buf_oninput = (
        f"document.getElementById('start_buffer_val').textContent=this.value+' ms';"
        f"if(liveEnabled) _owntoneNativeDebounced('start_buffer', this.value, '/api/owntone/start-buffer');"
    )
    _buf_html = (
        '<label style="display:block;margin-top:0.75rem;">'
        '<div class="slider-header"><span>Start Buffer (ms):</span>'
        f'<span id="start_buffer_val">{start_buffer_ms} ms</span></div>'
        f'<input type="range" name="start_buffer_ms"'
        f' min="{SETTING_START_BUFFER_MS_MIN}" max="{SETTING_START_BUFFER_MS_MAX}"'
        f' step="{SETTING_START_BUFFER_MS_STEP}" value="{start_buffer_ms}"'
        f' oninput="{html.escape(_buf_oninput)}"></label>'
    ) if start_buffer_available else (
        '<div class="storage-meta" style="margin-top:0.75rem;">'
        'This backend does not currently expose start-buffer control.</div>'
    )

    _body_html = (
        page_heading_html
        + (f"<p style='color:var(--color-status-success);'>Saved</p>" if saved_ok else "")
        + (f"<p style='color:var(--color-status-danger);'>{html.escape(error)}</p>" if error else "")
        + f"<p class='actions' style='margin:1rem 0;display:flex;justify-content:space-between;align-items:center;gap:0.75rem;'>"
        + f"<a href='/owntone-setup' class='pill-btn small' style='font-weight:500;border:1px solid #ccc;'>\u21bb Refresh</a>"
        + f"</p>"
        + f"<div>"
        + speakers_html
        + f"<fieldset><legend>Audio</legend>"
        + _buffered_audio_html
        + f"<div style='display:flex;align-items:center;gap:0.75rem;'>"
        + f"<label class='output-toggle' style='margin:0;'>"
        + _uncomp_input
        + f"<span class='switch'></span>"
        + f"</label>"
        + f"<span>Use uncompressed audio</span>"
        + f"</div>"
        + ('<div class="storage-meta">This backend does not currently expose uncompressed-audio control.</div>' if not uncompressed_supported else '')
        + _buf_html
        + f"</fieldset>"
        + f"</div>"
    )
    _body_suffix = f"""\
{AUTOSAVE_JS}
<script>
  const liveEnabled = true;
  function onShowToggle(i, checked) {{
    document.getElementById('spk_settings_' + i).style.display = checked ? 'block' : 'none';
  }}
  var _owntoneTimers = {{}};
  function _owntoneOffsetDebounced(outputId, offsetMs) {{
    clearTimeout(_owntoneTimers['offset_' + outputId]);
    _owntoneTimers['offset_' + outputId] = setTimeout(function() {{
      settingsTransact('/api/owntone/output-offset', {{output_id: outputId, offset_ms: offsetMs}});
    }}, 300);
  }}
  function _owntoneNativeDebounced(key, rawValue, url) {{
    clearTimeout(_owntoneTimers[key]);
    _owntoneTimers[key] = setTimeout(function() {{
      settingsTransact(url, {{value: parseInt(rawValue, 10)}});
    }}, 500);
  }}
</script>"""
    html_body = build_page_html(
        "Owntone Setup",
        _body_html,
        lic_html=lic_html,
        lic_spacer=lic_spacer,
        body_suffix=_body_suffix,
        show_nav=True,
        active_tab="setup",
        dark_mode=parsed.webui.dark_mode,
        head_extra=csrf_meta,
    )
    body_bytes = html_body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)
