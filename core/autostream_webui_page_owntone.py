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
import logging
import textwrap
import threading
import time

import requests

from typing import Optional
from urllib.parse import parse_qs, quote, urlparse

from autostream_config import (
    DEFAULT_AIRPLAY_MODE,
    DEFAULT_OWNTONE_PROTOCOL_API_STATE,
    normalize_airplay_mode,
    parse_config,
    unconfigured,
)
from autostream_owntone import (
    _coerce_owntone_bool,
    _coerce_owntone_int,
    build_owntone_output_update_payload,
    owntone_fetch_outputs,
    owntone_get_setting,
    owntone_output_protocol_support,
    owntone_put_setting,
    read_airplay2_for_speaker,
    read_and_set_global_pipe_directory,
    read_and_set_global_uncompressed_audio,
    resolve_owntone_output_airplay_mode,
    resolve_owntone_protocol_api_state,
    write_airplay2_for_speaker,
    write_and_set_global_uncompressed_audio,
    OWNTONE_CONF_PATH,
)
from autostream_sysutils import run_admin_cmd
from autostream_webui_assets import (
    BANNER_HTML,
    STYLE_CSS,
    VIEWPORT_META,
)
from autostream_webui_common import build_top_banner_html, locked_load_config
from autostream_webui_state import WebUIState
from autostream_webui_api import send_json


# -----------------------------------------------------------------------------
# OwnTone readiness helpers
# -----------------------------------------------------------------------------

def wait_for_owntone_api(base_url: str, timeout_s: float = 10.0) -> tuple[bool, str]:
    url = base_url.rstrip("/") + "/api/outputs"
    deadline = time.time() + timeout_s
    last_err = ""
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=1)
            if r.status_code == 200:
                return True, ""
            last_err = f"HTTP {r.status_code}"
        except Exception as e:
            last_err = str(e)
        time.sleep(0.5)
    return False, f"Owntone is still starting ({last_err})"


def _owntone_ready_quick(base_url: str, timeout_s: float = 0.6) -> tuple[bool, str]:
    """Fast readiness probe used by /api/owntone/ready."""
    try:
        url = base_url.rstrip("/") + "/api/outputs"
        r = requests.get(url, timeout=timeout_s)
        if 200 <= r.status_code < 300:
            return True, "Owntone is responding"
        return False, f"Owntone returned HTTP {r.status_code}"
    except Exception as e:
        return False, str(e)


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
        parsed = parse_config(locked_load_config(state.config_path))
        ok, msg = wait_for_owntone_api(parsed.owntone.base_url, timeout_s=20.0)
    except Exception as e:
        ok, msg = False, str(e)

    state.finish_owntone_restart(
        token, ok=bool(ok), message=msg if msg else ("Ready" if ok else "Not ready")
    )


def start_owntone_restart_async(state) -> None:
    """Start a background restart if one isn't already running (or supersede it)."""
    token = state.begin_owntone_restart()
    t = threading.Thread(target=_restart_owntone_worker, args=(state, token), daemon=True)
    t.start()


# -----------------------------------------------------------------------------
# JSON endpoint
# -----------------------------------------------------------------------------

def send_owntone_ready_json(handler, state) -> None:
    """JSON endpoint polled by /owntone-restarting."""
    try:
        parsed = parse_config(locked_load_config(state.config_path))
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
    next_path_js = html.escape(next_path, quote=True)

    body = f"""<!doctype html>
      <html>
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
          <p class="muted">If this doesn't move on, you can <a href="{next_path_js}">try continuing</a>.</p>
        </div>
        <script>
          const nextPath = "{next_path_js}";
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

    hidden_set = {str(n).strip().casefold() for n in (parsed.webui.hidden_outputs or ()) if str(n).strip()}
    outputs_result = owntone_fetch_outputs(parsed.owntone.base_url, timeout=3)
    outputs = outputs_result or []
    protocol_api_state = resolve_owntone_protocol_api_state(
        outputs_result,
        parsed.owntone.protocol_api_state,
    )

    known_outputs = dict(parsed.owntone.known_outputs)
    discovered_ids: set[str] = set()
    row_specs: list[dict[str, object]] = []

    for out_obj in outputs:
        name = str(out_obj.get("name") or "").strip()
        out_id = out_obj.get("id")
        if not name or out_id is None:
            continue
        out_id_s = str(out_id).strip()
        if not out_id_s:
            continue
        known_outputs[out_id_s] = name
        discovered_ids.add(out_id_s)
        row_specs.append(
            {
                "id": out_id_s,
                "name": name,
                "out_obj": out_obj,
                "discovered": True,
                "name_only": False,
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
                "out_obj": None,
                "discovered": False,
                "name_only": False,
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
                "out_obj": None,
                "discovered": False,
                "name_only": True,
            }
        )

    row_specs.sort(
        key=lambda spec: (
            0 if str(spec["name"]).casefold() not in hidden_set else 1,
            str(spec["name"]).casefold(),
        ),
    )

    # Try API first (requires OwnTone settings endpoint); fall back to conf file.
    _uncompressed_api = owntone_get_setting(
        parsed.owntone.base_url, "airplay", "uncompressed_alac"
    )
    _uncompressed_api_bool = _coerce_owntone_bool(_uncompressed_api.value)
    uncompressed = (
        bool(_uncompressed_api_bool)
        if _uncompressed_api.available and _uncompressed_api.ok and _uncompressed_api_bool is not None
        else bool(read_and_set_global_uncompressed_audio(OWNTONE_CONF_PATH))
    )

    _START_BUFFER_MIN = 300
    _START_BUFFER_MAX = 3500
    _START_BUFFER_STEP = 50
    _START_BUFFER_DEFAULT = 2250
    _buf_api = owntone_get_setting(parsed.owntone.base_url, "general", "start_buffer_ms")
    _buf_raw = _coerce_owntone_int(_buf_api.value) if (_buf_api.available and _buf_api.ok) else None
    if _buf_raw is not None:
        # Snap to nearest step within slider range.
        start_buffer_ms = max(_START_BUFFER_MIN, min(_START_BUFFER_MAX,
            round(_buf_raw / _START_BUFFER_STEP) * _START_BUFFER_STEP))
    else:
        start_buffer_ms = _START_BUFFER_DEFAULT
    start_buffer_available = _buf_api.available and _buf_api.ok

    speakers_html = ""
    for i, row in enumerate(row_specs):
        spk = str(row["name"])
        show = spk.casefold() not in hidden_set
        out_obj = row.get("out_obj") if isinstance(row.get("out_obj"), dict) else None
        out_id = str(row.get("id") or "").strip()
        discovered = bool(row.get("discovered"))
        name_only = bool(row.get("name_only"))
        saved_runtime_mode = (
            resolve_owntone_output_airplay_mode(
                out_id,
                output_airplay_modes=parsed.owntone.output_airplay_modes,
            )
            if out_id
            else None
        )
        has_saved_runtime_mode = saved_runtime_mode is not None

        # Newer OwnTone builds advertise per-output protocol capability.
        protocol_support = owntone_output_protocol_support(out_obj)
        supports_protocol_api = protocol_support.supports_runtime_protocol
        supports_raop = protocol_support.supports_raop if supports_protocol_api else None
        supports_ap2 = protocol_support.supports_airplay2 if supports_protocol_api else None

        mode_note_html = ""
        if supports_protocol_api and out_id:
            current_mode = saved_runtime_mode or DEFAULT_AIRPLAY_MODE
        elif protocol_api_state == "legacy":
            if out_id or not name_only:
                current_mode = (
                    "airplay2"
                    if (read_airplay2_for_speaker(spk, OWNTONE_CONF_PATH) or False)
                    else DEFAULT_AIRPLAY_MODE
                )
                mode_note_html = (
                    "<div class='storage-meta'>Older OwnTone build: saved in owntone.conf and applied after restart.</div>"
                )
            else:
                current_mode = DEFAULT_AIRPLAY_MODE
                mode_note_html = (
                    "<div class='storage-meta'>Speaker id is not known yet. Rediscover the speaker before changing its mode.</div>"
                )
        else:
            current_mode = saved_runtime_mode or DEFAULT_AIRPLAY_MODE
            if out_id and has_saved_runtime_mode and not discovered:
                mode_note_html = (
                    "<div class='storage-meta'>Speaker not currently discovered. "
                    "Saved mode will be applied when it reappears.</div>"
                )
            elif out_id and has_saved_runtime_mode:
                mode_note_html = (
                    "<div class='storage-meta'>Speaker capability metadata is unavailable right now. "
                    "Saved mode will be kept and applied when capability can be confirmed.</div>"
                )
            elif out_id and not discovered:
                mode_note_html = (
                    "<div class='storage-meta'>Speaker not currently discovered and recent AirPlay capability "
                    "could not be confirmed. Rediscover the speaker before changing its mode.</div>"
                )
            elif out_id:
                mode_note_html = (
                    "<div class='storage-meta'>Speaker capability metadata is unavailable right now. "
                    "Rediscover the speaker before changing its mode.</div>"
                )
            else:
                mode_note_html = (
                    "<div class='storage-meta'>Speaker id is not known yet. Rediscover the speaker before changing its mode.</div>"
                )

        can_edit_mode = bool(
            out_id and (supports_protocol_api or has_saved_runtime_mode)
        ) or (
            protocol_api_state == "legacy" and not name_only
        )
        show_raop = True if (not supports_protocol_api and can_edit_mode) else supports_raop
        show_airplay2 = True if (not supports_protocol_api and can_edit_mode) else supports_ap2
        is_airplay_output = show_raop or show_airplay2

        # Offset slider is only shown if the output object includes offset_ms.
        offset_html = ""
        if out_id and (
            (out_obj and ("offset_ms" in out_obj))
            or out_id in parsed.owntone.output_offsets_ms
        ):
            try:
                cur_off = cfg.getint("owntone_offsets", out_id, fallback=0)
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
                           oninput="document.getElementById('off_val_{i}').textContent=this.value+' ms';">
                  </label>
                """

        if is_airplay_output:
            mode_options = (
                f'<option value="{DEFAULT_AIRPLAY_MODE}"'
                f'{" selected" if current_mode == DEFAULT_AIRPLAY_MODE else ""}>Auto</option>'
            )
            if show_raop:
                mode_options += f'<option value="raop"{" selected" if current_mode == "raop" else ""}>AirPlay</option>'
            if show_airplay2:
                mode_options += f'<option value="airplay2"{" selected" if current_mode == "airplay2" else ""}>AirPlay 2</option>'
            mode_html = f"""
            <label style="display:block;margin-bottom:0.5rem;">
              <span>Mode</span>
              <select name="mode_{i}">{mode_options}</select>
            </label>{mode_note_html}"""
        else:
            mode_html = (
                f'<input type="hidden" name="mode_{i}" value="{DEFAULT_AIRPLAY_MODE}">'
            )

        speakers_html += f"""
          <fieldset><legend>{html.escape(spk)}</legend>
          <input type="hidden" name="spk_id_{i}" value="{html.escape(out_id)}">
          <input type="hidden" name="spk_{i}" value="{html.escape(spk)}">
          <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" name="show_{i}" {'checked' if show else ''} onchange="onShowToggle({i}, this.checked)">
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

    initial_setup = unconfigured(state.config_path)
    h1 = "Initial Setup (1 of 2)" if initial_setup else "Owntone Setup"
    back_html = "" if initial_setup else '<a href="/setup" class="pill-btn">← Back</a>'
    submit_label = "Continue..." if initial_setup else "Save Settings"

    html_body = textwrap.dedent(f"""\
      <!DOCTYPE html><html><head><meta charset="utf-8">{VIEWPORT_META}
      <title>Owntone Setup</title><style>{STYLE_CSS}</style></head>
      <body>{lic_html}{lic_spacer}<div class="container">{BANNER_HTML}<h1>{h1}</h1>
      {f"<p style='color:green;'>Saved</p>" if saved_ok else ""}
      {f"<p style='color:red;'>{html.escape(error)}</p>" if error else ""}
      <p class="actions" style="margin:1rem 0;display:flex;justify-content:space-between;align-items:center;gap:0.75rem;">
        {back_html}
        <a href="/owntone-setup" class="pill-btn" style="font-size:0.95rem;font-weight:500;border:1px solid #ccc;">↻ Refresh</a>
      </p>
      <form method="POST" action="/owntone-setup">
        <input type="hidden" name="csrf_token" value="{html.escape(csrf_token)}">
        {speakers_html}
        <fieldset><legend>Audio</legend>
          <div style="display:flex;align-items:center;gap:0.75rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" name="uncompressed_alac" {'checked' if uncompressed else ''}>
              <span class="switch"></span>
            </label>
            <span>Use uncompressed audio</span>
          </div>
          {'<label style="display:block;margin-top:0.75rem;"><div class="slider-header"><span>Start Buffer (ms):</span><span id="start_buffer_val">' + str(start_buffer_ms) + ' ms</span></div><input type="range" name="start_buffer_ms" min="' + str(_START_BUFFER_MIN) + '" max="' + str(_START_BUFFER_MAX) + '" step="' + str(_START_BUFFER_STEP) + '" value="' + str(start_buffer_ms) + '" oninput="document.getElementById(\'start_buffer_val\').textContent=this.value+\' ms\';"></label>' if start_buffer_available else ''}
        </fieldset>
        <p class="actions"><button type="submit">{submit_label}</button></p>
      </form></div>
      <script>
        function onShowToggle(i, checked){{
          document.getElementById('spk_settings_' + i).style.display = checked ? 'block' : 'none';
        }}
      </script>
      </body></html>
    """)
    body_bytes = html_body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)
