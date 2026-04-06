#!/usr/bin/env python3
"""autostream_webui_pages.py

Page rendering and API handlers for the autostream Web UI.
"""

from __future__ import annotations

import logging
import subprocess
import os
import threading
import time
from pathlib import Path
import json
import html
import textwrap
from datetime import datetime
import requests
from urllib.parse import quote, parse_qs, urlparse
from typing import Optional

from autostream_core import (
    any_monitor_capturing,
    get_monitor_levels_dbfs,
    get_playback_snapshot,
    reset_input_stylus,
    set_live_input_eq,
    set_live_input_gain,
    update_live_platform_log_level,
    update_live_owntone_runtime,
    update_playback_input_config,
)

from autostream_auth import FLASH_COOKIE_NAME

from autostream_config import (
    DEFAULT_AIRPLAY_MODE,
    DEFAULT_OWNTONE_PROTOCOL_API_STATE,
    get_log_level_options,
    load_config,
    normalize_airplay_mode,
    normalize_log_level,
    parse_config,
    mark_configured,
    unconfigured,
)

from autostream_sysutils import (
    run_cmd,
    get_root_disk_usage,
    fmt_bytes,
    get_sdcard_health_percent,
    tail_lines,
    get_system_hostname,
    set_system_hostname,
    run_admin_cmd,
)

from autostream_rpi import (
    cpu_is_licensed,
    get_cpu_temperature_c,
    get_psu_warning_text,
    LICENSE_CHECK,
)

from autostream_owntone import (
    build_owntone_output_update_payload,
    read_and_set_global_pipe_directory,
    write_and_set_global_pipe_directory,
    read_and_set_global_uncompressed_audio,
    write_and_set_global_uncompressed_audio,
    read_log_level_from_conf,
    read_airplay2_for_speaker,
    write_log_level_to_conf,
    write_airplay2_for_speaker,
    _coerce_owntone_bool,
    _coerce_owntone_int,
    owntone_apply_log_level,
    owntone_fetch_outputs,
    owntone_get_output,
    owntone_get_setting,
    owntone_output_protocol_support,
    owntone_put_setting,
    owntone_restart_service,
    resolve_owntone_protocol_api_state,
    resolve_owntone_output_airplay_mode,
    OWNTONE_CONF_PATH,
)
from autostream_playback import (
    InputPlaybackSnapshot,
    format_hours,
    get_stylus_life_options,
    normalize_stylus_life_hours,
    suggested_silence_threshold_dbfs,
)

from autostream_webui_assets import (
    STYLE_CSS,
    LICENSE_BANNER_CSS,
    A2HS_PROMPT_HTML,
    A2HS_SCRIPT,
    BANNER_HTML,
    VIEWPORT_META,
    PIN_MODAL_CSS,
)

from autostream_webui_state import WebUIState

#
# Privileged helper / log allowlist hardening
#
AUTOSTREAM_ADMIN_BIN = os.environ.get("AUTOSTREAM_ADMIN_BIN", "/usr/local/libexec/autostream/autostream-admin")
LOG_BASE_DIR = Path("/var/log/autostream").resolve()

def _resolve_allowed_log_path(log_file_cfg: str) -> Path:
    """Resolve and validate the configured log path, restricting it to /var/log/autostream/*."""
    p = Path(log_file_cfg.strip())
    if not p.is_absolute():
        p = LOG_BASE_DIR / p
    resolved = p.resolve(strict=True)
    if LOG_BASE_DIR not in resolved.parents:
        raise PermissionError("Log file path outside allowed directory")
    if not resolved.is_file():
       raise FileNotFoundError("Log file not found")
    return resolved


# -----------------------------------------------------------------------------
# Thread-safety for ThreadingHTTPServer:
# Protect config file I/O (and coupled owntone.conf edits) from interleaving
# across concurrent requests.
# -----------------------------------------------------------------------------
CONFIG_IO_LOCK = threading.Lock()

def locked_load_config(path: str):
    """Load config under a global lock to avoid reading partial writes."""
    with CONFIG_IO_LOCK:
        return load_config(path)

# -----------------------------------------------------------------------------
# status message cookie (produces e.g., settings saved banner)
# -----------------------------------------------------------------------------

def _set_flash_cookie(handler, message: str, *, max_age: int = 30) -> None:
    """
    Set a short-lived flash cookie to be consumed (and cleared) on the next GET.
    Stored URL-escaped to keep it cookie-safe.
    """
    val = quote(message, safe="")
    cookie = (
        f"{FLASH_COOKIE_NAME}={val}; Max-Age={max_age}; Path=/; HttpOnly; SameSite=Lax"
    )
    pending = getattr(handler, "_pending_set_cookies", None)
    if pending is None:
        handler._pending_set_cookies = [cookie]
    else:
        pending.append(cookie)


# -----------------------------------------------------------------------------
# Owntone restart async support
# -----------------------------------------------------------------------------

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
          <p class="muted">This can take a few seconds on a Pi Zero. We’ll continue automatically when it’s ready.</p>
          <p id="status" class="muted">Checking…</p>
          <p class="muted">If this doesn’t move on, you can <a href="{next_path_js}">try continuing</a>.</p>
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

def send_rebooting_page(handler, state: WebUIState, auth) -> None:
    """
    "Holding" page shown while a reboot is initiated.

    Behaviour:
      - On load, POSTs /api/reboot (CSRF protected) to schedule a reboot with delay.
      - Waits a minimum time before trying to return to '/', to avoid bouncing
        back to the UI before the reboot has actually started.
      - Then polls '/' until reachable and redirects back.
    """
    # Minimum time (ms) before we even attempt to return to '/'. Must be > reboot delay.
    # The reboot API schedules with 3s delay; but shutdown takes time especially on older Pi.
    # Hence wait 30s before attempting to redirect user.
    min_wait_ms = 30000

    lic_html, lic_spacer = build_top_banner_html(flash_msg=None)
    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""
    csrf_meta = (
        f"<meta name='csrf-token' content='{html.escape(csrf_token)}'>"
        f"<script>window.__CSRF='{html.escape(csrf_token)}';</script>"
    )

    body = f"""<!doctype html>
      <html>
      <head>
        <meta charset="utf-8">{VIEWPORT_META}
        <title>Rebooting…</title>
        <style>
          {STYLE_CSS}
          body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }}
          .box {{ max-width: 42rem; margin: 2rem auto; padding: 1.25rem; border: 1px solid #ddd; border-radius: 12px; background:#fff; }}
          .muted {{ color: #666; }}
          .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }}
        </style>
        {csrf_meta}
      </head>
      <body>{lic_html}{lic_spacer}
        <div class="box">
          <h1>Rebooting…</h1>
          <p class="muted">Your device is restarting. This page will return you to the app automatically when it’s ready.</p>
          <p id="status" class="muted">Requesting reboot…</p>
          <p class="muted">If you are not redirected, try <a href="/">opening the app</a> again in a moment.</p>
        </div>

        <script>
          const minWaitMs = {int(min_wait_ms)};
          const startedAt = Date.now();
          const statusEl = document.getElementById("status");

          function setStatus(t) {{
            if (statusEl) statusEl.textContent = t;
          }}

          async function requestReboot() {{
            try {{
              // keepalive improves odds the POST is delivered even if the browser navigates/reloads
              const r = await fetch("/api/reboot", {{
                method: "POST",
                headers: {{ "X-CSRF-Token": window.__CSRF || "" }},
                cache: "no-store",
                keepalive: true
              }});
              // Even if we can't parse JSON, the request may have been accepted.
              try {{
                const j = await r.json();
                if (j && j.ok) {{
                  setStatus("Reboot scheduled. Waiting for restart…");
                  return;
                }}
              }} catch (e) {{}}
              setStatus("Reboot requested. Waiting for restart…");
            }} catch (e) {{
              // If the reboot is already in progress, fetch may fail — that's fine.
              setStatus("Waiting for restart…");
            }}
          }}

          async function pollRoot() {{
            const elapsed = Date.now() - startedAt;
            if (elapsed < minWaitMs) {{
              const s = Math.ceil((minWaitMs - elapsed) / 1000);
              setStatus("Reboot scheduled. Restarting in ~" + s + "s…");
              setTimeout(pollRoot, 700);
              return;
            }}

            setStatus("Checking if the app is back…");
            try {{
              const r = await fetch("/", {{ cache: "no-store" }});
              if (r && r.ok) {{
                window.location.replace("/");
                return;
              }}
            }} catch (e) {{
              // Not up yet
            }}
            setTimeout(pollRoot, 1200);
          }}

          requestReboot();
          pollRoot();
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


# ----------------------------
# Internal Helpers
# ----------------------------

def build_top_banner_html(flash_msg: Optional[str] = None, flash_type: str = "success") -> tuple[str, str]:
    """Returns (banner_html, spacer_html). Handles persistent and flash messages."""

    # Priority 1: User-triggered flash messages (e.g. "Settings saved" / errors)
    if flash_msg:
        banner_id = "green-banner"
        banner_spacer = "green-banner-spacer"
        if flash_type == "error":
            banner_id = "red-banner"
            banner_spacer = "red-banner-spacer"

        return (f"<div id='{banner_id}'>{html.escape(flash_msg)}</div>",
                f"<div id='{banner_spacer}'></div>")

    # Priority 2: System-level PSU warning
    warn = get_psu_warning_text()
    if warn:
        return (f"<div id='red-banner'>{html.escape(warn)}</div>",
                "<div id='red-banner-spacer'></div>")

    # Priority 3: Licensing
    if LICENSE_CHECK and (not cpu_is_licensed()):
        return ("<div id='red-banner'>This system is unlicensed</div>",
                "<div id='red-banner-spacer'></div>")

    return ("", "")


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


def _format_reset_date(raw: Optional[str]) -> str:
    if not raw:
        return "Never"
    try:
        dt = datetime.fromisoformat(str(raw))
        try:
            return dt.astimezone().strftime("%b-%y")
        except Exception:
            return dt.strftime("%b-%y")
    except Exception:
        raw_s = str(raw)
        if "T" in raw_s:
            raw_s = raw_s.split("T", 1)[0]
        parts = raw_s.split("-")
        if len(parts) >= 2:
            year = parts[0][-2:] if len(parts[0]) >= 2 else parts[0]
            month = parts[1]
            month_map = {
                "01": "Jan", "02": "Feb", "03": "Mar", "04": "Apr",
                "05": "May", "06": "Jun", "07": "Jul", "08": "Aug",
                "09": "Sep", "10": "Oct", "11": "Nov", "12": "Dec",
            }
            if month in month_map:
                return f"{month_map[month]}-{year}"
        return raw_s


def _fallback_input_snapshot(
    parsed_input,
    input_index: int,
    *,
    enabled: bool = True,
) -> InputPlaybackSnapshot:
    is_turntable = bool(getattr(parsed_input, "is_turntable", False))
    stylus_life_hours = int(getattr(parsed_input, "stylus_life_hours", 500))
    return InputPlaybackSnapshot(
        input_index=input_index,
        label=f"Input {input_index}",
        active=False,
        enabled=bool(enabled),
        is_turntable=is_turntable,
        total_playback_seconds=0,
        total_playback_hours=0.0,
        stylus_playback_seconds=0,
        stylus_playback_hours=0.0,
        stylus_life_hours=stylus_life_hours,
        stylus_remaining_seconds=(stylus_life_hours * 3600 if is_turntable else None),
        stylus_remaining_hours=(float(stylus_life_hours) if is_turntable else None),
        stylus_warning=False,
        stylus_overdue=False,
        last_stylus_reset_at=None,
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


def _settings_card_html(inner_html: str, *, margin_top: str = "0.75rem") -> str:
    return (
        f"<div style='margin-top:{margin_top};padding:0.75rem 0.85rem;border:1px solid #e4e4e4;"
        "border-radius:8px;background:#fafafa;font-size:0.95rem;line-height:1.5;'>"
        f"{inner_html}"
        "</div>"
    )


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


def _stylus_box_html(
    *,
    title: str,
    snapshot: InputPlaybackSnapshot,
) -> str:
    life_total_seconds = max(1, int(snapshot.stylus_life_hours) * 3600)
    remaining_seconds = max(0, int(snapshot.stylus_remaining_seconds or 0))
    remaining_hours = max(0.0, remaining_seconds / 3600.0)
    remaining_pct = max(0.0, min(100.0, (remaining_seconds / life_total_seconds) * 100.0))
    bar_color = "#dc3545" if remaining_pct <= 10.0 else ("#f0ad4e" if remaining_pct <= 20.0 else "#28a745")
    meta_text = f"{remaining_hours:.1f} hours remaining"
    return f"""
      <fieldset><legend>{html.escape(title)}</legend>
        <div class='bar-label'><strong>Life Remaining:</strong> {remaining_pct:.1f}%</div>
        <div class='storage-bar'><div class='used' style='width:{remaining_pct}%;background:{bar_color};'></div></div>
        <div class='storage-meta'>{html.escape(meta_text)}</div>
      </fieldset>
    """


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


def _status_text_for_home(is_playing: bool, input_levels: list[dict]) -> str:
    """Return home-page status text based on the currently active input."""
    if not is_playing:
        return "Waiting"

    active_label = ""
    for lv in input_levels:
        if lv.get("is_above_threshold"):
            active_label = str(lv.get("label") or "").strip()
            break

    if active_label.startswith("In") and active_label[2:].isdigit():
        return f"Playing Input {active_label[2:]}"
    if active_label:
        return f"Playing {active_label}"
    return "Playing"

def get_app_version() -> str:
    """Return application version from ./version file."""
    try:
        with open("version", "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return "unknown"

def send_json(handler, code: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    try:
        handler.send_response(code)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)
    except (BrokenPipeError, ConnectionResetError):
        # Client navigated away / refreshed / closed the tab mid-response.
        return
        


def run_updater(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
    cmd = ["/usr/bin/sudo", "-n", "/usr/local/libexec/autostream/autostream_updater.py", *args]
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    return p.returncode, p.stdout, p.stderr

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

def send_owntone_outputs_json(handler, state: WebUIState) -> None:
    """Return available Owntone output names for async refresh on /setup."""
    try:
        cfg = locked_load_config(state.config_path)
        parsed = parse_config(cfg)
    except Exception as e:
        send_json(handler, 500, {"ok": False, "error": str(e), "outputs": []})
        return

    outputs = []

    url = parsed.owntone.base_url.rstrip("/") + "/api/outputs"
    logging.info("Owntone API request: GET %s", url)

    try:
        resp = requests.get(url, timeout=2)

        logging.info(
            "Owntone API response: status=%s body=%s",
            resp.status_code,
            (resp.text or "").strip(),
        )

        if resp.status_code == 200:
            outputs = resp.json().get("outputs", [])
        else:
            outputs = []

    except Exception as e:
        logging.error("Owntone API request failed: %s", e)
        outputs = []

    hidden = {str(n).strip().casefold() for n in (parsed.webui.hidden_outputs or ()) if str(n).strip()}

    names = []
    for out in outputs:
        nm = (out.get("name") or "").strip()
        if not nm:
            continue
        # Mirror existing behavior: hide hidden outputs unless it is the configured default
        if nm.casefold() in hidden and nm != parsed.owntone.output_name:
            continue
        names.append(nm)

    send_json(handler, 200, {
        "ok": True,
        "outputs": names,
        "selected": parsed.owntone.output_name,
    })

def send_owntone_outputs_state_json(handler, state: WebUIState) -> None:
    """Return Owntone outputs (id/name/selected/volume) for live refresh on '/'."""
    try:
        cfg = locked_load_config(state.config_path)
        parsed = parse_config(cfg)
    except Exception as e:
        send_json(handler, 500, {"ok": False, "error": str(e), "outputs": []})
        return

    outputs = []
    try:
        resp = requests.get(parsed.owntone.base_url.rstrip("/") + "/api/outputs", timeout=2)
        if resp.status_code == 200:
            outputs = resp.json().get("outputs", [])
        else:
            send_json(handler, 200, {"ok": False, "error": f"HTTP {resp.status_code}", "outputs": []})
            return
    except Exception as e:
        send_json(handler, 200, {"ok": False, "error": str(e), "outputs": []})
        return

    default_output_name = parsed.owntone.output_name
    hidden = {str(n).strip().casefold() for n in (parsed.webui.hidden_outputs or ()) if str(n).strip()}

    filtered = []
    for out in outputs:
        out_id = out.get("id")
        name = (out.get("name") or "").strip()
        if out_id is None or not name:
            continue

        selected = bool(out.get("selected", False))
        # Mirror '/' page behaviour: hide hidden outputs unless selected or default
        if name.casefold() in hidden and not selected and name != default_output_name:
            continue

        vol = max(0, min(100, int(out.get("volume", 25))))
        filtered.append({
            "id": str(out_id),
            "name": name,
            "selected": selected,
            "volume": vol,
            "is_default": (name == default_output_name),
        })

    # Sort: default first (matching '/' render)
    if default_output_name:
        filtered.sort(key=lambda o: (0 if o["is_default"] else 1, o["name"].casefold()))

    send_json(handler, 200, {"ok": True, "outputs": filtered})


# ----------------------------
# Page Handlers
# ----------------------------

def send_airplay_page(handler, state: WebUIState, auth, error: Optional[str] = None, flash_msg: Optional[str] = None) -> None:
    """Render the main AirPlay control page."""
    try:
        cfg = locked_load_config(state.config_path)
        parsed = parse_config(cfg)
    except Exception:
        # If we're here something bad happened - user should have been redirected to the setup page
        # if the INI is missing. Hence, take the nuclear option and inform the user that something
        # went wrong - then reboot the system. This code serves only inline code in case the file
        # system is dead (which is likely). Reboot may therefore also fail.
        body = textwrap.dedent(f"""\
          <!DOCTYPE html><html><head><meta charset="utf-8"><title>Logs</title>
          <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
          <style>{STYLE_CSS}
          body {{ font-size: 14px !important; }}
          </style></head>
          <body>
            <h1>System Error</h1>
            <p>Unfortunately, an unrecoverable error has occurred:
            autostream was unable to read the configuration file.</p>
            <p><strong>autostream will now try to reboot.</strong></p>
            <p>Please check back in a few minutes. If the system does not recover, 
            please power-cycle autostream and try again. If the problem persists,
            please replace the SD card and reinstall autostream.</p>
          </body>
        """)

        # Best-effort response; never prevent reboot.
        try:
            handler.send_response(500)
            handler.send_header("Content-Type", "text/html; charset=utf-8")
            body_bytes = body.encode("utf-8")
            handler.send_header("Content-Length", str(len(body_bytes)))
            handler.end_headers()
            handler.wfile.write(body_bytes)
            try:
                handler.wfile.flush()
            except Exception:
                pass
        except Exception:
            pass

        # Best-effort log; never prevent reboot.
        try:
            logging.error(
                "Config load error, rebooting system",
                exc_info=True
            )
        except Exception:
            pass
        reboot_system(reason = "UserRequestSystemError")
        return

    owntone_base_url = parsed.owntone.base_url
    default_output_name = parsed.owntone.output_name
    hidden_output_names = {str(n).strip().casefold() for n in (parsed.webui.hidden_outputs or ()) if str(n).strip()}

    try:
        is_playing = any_monitor_capturing()
    except Exception:
        is_playing = False

    try:
        input_levels = get_monitor_levels_dbfs()
    except Exception:
        input_levels = []

    playback_snapshot = get_playback_snapshot()
    stylus_banner_text = playback_snapshot.banner_text or ""
    setup_button_style = (
        "flex:1;text-align:center;background:#c00000;color:#fff;border-color:#c00000;"
        if stylus_banner_text else
        "flex:1;text-align:center;"
    )
    status_text = _status_text_for_home(is_playing, input_levels)
    status_class = "playing" if is_playing else "waiting"

    input_levels_html = ""
    for lv in input_levels:
        label = html.escape(str(lv.get("label", "Input ")))
        dbfs = float(lv.get("dbfs", -90.0))
        detected_hz = float(lv.get("detected_hz", 0.0)) / 1000.0
        hz_txt = f" ({detected_hz:.3f} kHz)" if detected_hz > 0 else ""
        extra_cls = " input-level-pill-active" if lv.get("is_above_threshold") else ""
        input_levels_html += (
            f'<span class="pill status-pill input-level-pill{extra_cls}">'
            f'{label}{hz_txt}: {dbfs:.1f} dB</span>'
        )

    outputs = []
    try:
        resp = requests.get(owntone_base_url.rstrip("/") + "/api/outputs", timeout=3)
        if resp.status_code == 200:
            outputs = resp.json().get("outputs", [])
        else:
            error = error or f"Owntone returned HTTP {resp.status_code}"
    except Exception as e:
        error = error or f"Could not reach Owntone at {owntone_base_url}"

    # Keep the configured default output at the top; otherwise use a stable
    # alphabetical order regardless of whether an output is currently enabled.
    outputs = sorted(
        outputs,
        key=lambda o: (
            0 if (o.get("name") == default_output_name) else 1,
            str(o.get("name") or "").casefold(),
        ),
    )

    outputs_html = ""
    for out in outputs:
        out_id = out.get("id")
        if out_id is None: continue
        out_id = str(out_id)
        name = out.get("name", f"Output {out_id}")
        selected = bool(out.get("selected", False))
        if str(name).strip().casefold() in hidden_output_names and not selected and name != default_output_name:
            continue

        volume = max(0, min(100, int(out.get("volume", 25))))
        safe_name = html.escape(str(name))
        default_badge = '<span class="output-card-default">Default</span>' if name == default_output_name else ""
        state_text = "On" if selected else "Off"
        state_cls = "on" if selected else "off"
        card_state_cls = "output-card-on" if selected else "output-card-off"
        is_default = "1" if name == default_output_name else "0"
        outputs_html += f"""
          <div class="output-card {card_state_cls}" id="output_card_{out_id}" data-output-id="{out_id}" data-is-default="{is_default}">
            <div class="output-card-head">
              <div class="output-card-meta">
                <div class="output-card-name">{safe_name}</div>
                {default_badge}
                <span class="output-state-chip {state_cls}" id="output_state_{out_id}">{state_text}</span>
              </div>
              <label class="output-toggle" onclick="event.stopPropagation();">
                <input type="checkbox" id="output_enabled_{out_id}"{' checked' if selected else ''} onchange="onToggleOutput('{out_id}')">
                <span class="switch" aria-hidden="true"></span>
              </label>
            </div>
            <div class="output-slider-wrap" id="output_slider_wrap_{out_id}" onclick="event.stopPropagation();"{' hidden' if not selected else ''}>
              <div class="slider-header"><span>Volume:</span><span id="vol_label_{out_id}" data-volume-label-for="{out_id}"></span></div>
              <input type="range" id="vol_slider_{out_id}" min="0" max="100" step="1" value="{volume}" oninput="updateVolumeLabel('{out_id}', this.value)" onchange="onVolumeChange('{out_id}', this.value)">
            </div>
          </div>
        """

    lic_html, lic_spacer = build_top_banner_html(flash_msg=flash_msg)
    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""
    preset_volume = max(0, min(100, int(parsed.owntone.volume_percent or 20)))
    csrf_meta = f"<meta name='csrf-token' content='{html.escape(csrf_token)}'><script>window.__CSRF='{html.escape(csrf_token)}';window.__PRESET_VOLUME={preset_volume};</script>"

    html_body = textwrap.dedent(f"""\
      <!DOCTYPE html><html><head><meta charset="utf-8">{VIEWPORT_META}
      <title>autostream</title><style>{STYLE_CSS}\n{PIN_MODAL_CSS}</style>{csrf_meta}

      <script>
        function normalizeVolume(v){{
          const n = Number(v);
          if (!Number.isFinite(n)) return 0;
          return Math.max(0, Math.min(100, Math.round(n)));
        }}
        function formatVolume(v){{
          return String(normalizeVolume(v)) + '%';
        }}
        function updateVolumeLabel(id,v){{var s=document.getElementById('vol_label_'+id);if(s)s.textContent=formatVolume(v);}}
        function reorderOutputCards(){{
          const list = document.getElementById('outputs-list');
          if (!list) return;
          const cards = Array.from(list.querySelectorAll('.output-card'));
          cards.sort((a, b) => {{
            const da = a.getAttribute('data-is-default') === '1' ? 1 : 0;
            const db = b.getAttribute('data-is-default') === '1' ? 1 : 0;
            if (db !== da) return db - da;
            const la = a.querySelector('.output-card-name');
            const lb = b.querySelector('.output-card-name');
            const na = ((la && la.textContent) || '').trim().toLowerCase();
            const nb = ((lb && lb.textContent) || '').trim().toLowerCase();
            return na.localeCompare(nb);
          }});
          cards.forEach(card => list.appendChild(card));
        }}
        function updateOutputStateVisual(id, selected){{
          const chip = document.getElementById('output_state_' + id);
          const card = document.getElementById('output_card_' + id);
          const wrap = document.getElementById('output_slider_wrap_' + id);
          if (chip) {{
            chip.textContent = selected ? 'On' : 'Off';
            chip.classList.toggle('on', !!selected);
            chip.classList.toggle('off', !selected);
          }}
          if (card) {{
            card.classList.toggle('output-card-on', !!selected);
            card.classList.toggle('output-card-off', !selected);
          }}
          if (wrap) {{
            wrap.hidden = !selected;
          }}
        }}

        function showPinModal(outputName){{
          return new Promise((resolve) => {{
            const m = document.getElementById('pinModal');
            const title = document.getElementById('pinModalTitle');
            const input = document.getElementById('pinModalInput');
            const btnOk = document.getElementById('pinModalOk');
            const btnCancel = document.getElementById('pinModalCancel');
            if (!m || !input || !btnOk || !btnCancel) {{
              // Fallback to native prompt if our modal is missing for any reason.
              const v = window.prompt('Enter PIN shown on your device' + (outputName ? ' ('+outputName+')' : '') + ':', '');
              resolve(v && String(v).trim() ? String(v).trim() : null);
              return;
            }}
            title.textContent = outputName ? ('Enter PIN for ' + outputName) : 'Enter PIN';
            input.value = '';
            m.classList.add('show');
            // iOS: defer focus slightly so the keyboard reliably appears.
            setTimeout(() => {{ try {{ input.focus(); }} catch (e) {{}} }}, 60);

            const cleanup = (val) => {{
              m.classList.remove('show');
              btnOk.onclick = null;
              btnCancel.onclick = null;
              input.onkeydown = null;
              resolve(val);
            }};
            btnCancel.onclick = () => cleanup(null);
            btnOk.onclick = () => {{
              const v = (input.value || '').trim();
              cleanup(v ? v : null);
            }};
            input.onkeydown = (ev) => {{
              if (ev.key === 'Enter') {{ ev.preventDefault(); btnOk.click(); }}
              else if (ev.key === 'Escape') {{ ev.preventDefault(); btnCancel.click(); }}
            }};
          }});
        }}

        async function postOutputUpdate(id, selected, volume){{
          const r = await fetch('/api/output',{{
            method:'POST',
            credentials:'same-origin',
            signal: AbortSignal.timeout(5000),
            headers:{{
              'Content-Type':'application/json',
              'X-CSRF-Token':window.__CSRF||''
            }},
            body:JSON.stringify({{
              id:id,
              selected:!!selected,
              volume:parseInt(volume||0,10)||0,
              csrf_token: window.__CSRF||''
            }})
          }});
          if (handleHomeSessionRejected(r)) return {{ ok:false, _http:r.status, session_rejected:true }};
          // Server replies JSON for this endpoint (including failures)
          let j = null;
          try {{ j = await r.json(); }} catch (e) {{ j = {{ ok: r.ok }}; }}
          j._http = r.status;
          return j;
        }}

        function handleHomeSessionRejected(response){{
          const status = Number(response && response.status);
          if (status !== 401 && status !== 403) return false;
          if (window.__HOME_SESSION_REFRESHING) return true;
          window.__HOME_SESSION_REFRESHING = true;
          window.location.reload();
          return true;
        }}

        async function postPinOnly(id, pin) {{
          const r = await fetch('/api/output', {{
            method:'POST',
            credentials:'same-origin',
            signal: AbortSignal.timeout(5000),
            headers:{{
              'Content-Type':'application/json',
              'X-CSRF-Token':window.__CSRF||''
            }},
            body:JSON.stringify({{
              op:'pin',
              id:id,
              pin: String(pin||'').trim(),
              csrf_token: window.__CSRF||''
            }})
          }});
          if (handleHomeSessionRejected(r)) return {{ ok:false, _http:r.status, session_rejected:true }};
          let j = null;
          try {{ j = await r.json(); }} catch (e) {{ j = {{ ok: r.ok }}; }}
          j._http = r.status;
          return j;
        }}

        async function sendUpdate(id){{
          const c=document.getElementById('output_enabled_'+id), s=document.getElementById('vol_slider_'+id);
          const selected = c?c.checked:false;
          const volume = s?normalizeVolume(parseInt(s.value,10)):0;
          window.__PENDING_OUTPUTS.add(String(id));
          try {{
            let j = null;
            try {{
              j = await postOutputUpdate(id, selected, volume);
            }} catch (e) {{
              // Network error or 5 s abort -> let periodic refresh reconcile UI.
              return;
            }}

            // If OwnTone requires a PIN, prompt and do PIN-only verification.
            // On wrong PIN (still 400), re-prompt; on success, retry the original enable.
            if (selected && j && j.pin_required) {{
              // Temporarily revert the toggle until fully enabled.
              if (c) {{
                c.checked = false;
                updateOutputStateVisual(String(id), false);
              }}

              let nm = '';
              try {{
                const card = c ? c.closest('.output-card') : null;
                const label = card ? card.querySelector('.output-card-name') : null;
                nm = label ? (label.textContent || '').trim() : '';
              }} catch (e) {{}}

              while (true) {{
                const pin = await showPinModal(nm || 'this speaker');
                if (!pin) return; // user cancelled

                let jpin = null;
                try {{
                  jpin = await postPinOnly(id, pin);
                }} catch (e) {{
                  // treat as failure; keep disabled
                  if (c) {{
                    c.checked = false;
                    updateOutputStateVisual(String(id), false);
                  }}
                  return;
                }}

                if (jpin && jpin.ok) {{
                  // PIN accepted -> retry the original enable request (without pin)
                  try {{
                    const jen = await postOutputUpdate(id, true, volume);
                    if (jen && jen.ok) {{
                      if (c) {{
                        c.checked = true;
                        updateOutputStateVisual(String(id), true);
                      }}
                      return;
                    }}
                    // If it still asks for PIN, loop again.
                    if (jen && jen.pin_required) {{
                      if (c) {{
                        c.checked = false;
                        updateOutputStateVisual(String(id), false);
                      }}
                      continue;
                    }}
                  }} catch (e) {{
                    if (c) {{
                      c.checked = false;
                      updateOutputStateVisual(String(id), false);
                    }}
                  }}
                  return;
                }}

                // Wrong PIN -> re-prompt
                if (jpin && jpin.pin_invalid) {{
                  continue;
                }}

                // Other error -> stop
                return;
              }}
            }}
          }} finally {{
            window.__PENDING_OUTPUTS.delete(String(id));
          }}
        }}

        function onToggleOutput(id){{
          const cb = document.getElementById('output_enabled_' + id);
          if (cb) updateOutputStateVisual(String(id), !!cb.checked);
          if (cb && cb.checked) {{
            const sl = document.getElementById('vol_slider_' + id);
            if (sl) {{ sl.value = String(window.__PRESET_VOLUME || 20); updateVolumeLabel(id, sl.value); }}
          }}
          reorderOutputCards();
          sendUpdate(id);
        }}
        function onVolumeChange(id,v){{
          updateVolumeLabel(id,v);
          sendUpdate(id);
        }}
        function escapeHtml(s){{
          return String(s||'').replace(/[&<>"']/g, function(ch){{
            return {{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[ch] || ch;
          }});
        }}
        function renderInputLevels(levels){{
          var row = document.getElementById('input-level-row');
          var wrap = document.getElementById('home-input-level-wrap');
          if(!row) return;
          if(!Array.isArray(levels) || levels.length===0){{
            row.hidden = true;
            if (wrap) wrap.hidden = true;
            row.innerHTML = '';
            return;
          }}
          row.hidden = false;
          if (wrap) wrap.hidden = false;
          row.innerHTML = levels.map(function(lv){{
            var label = escapeHtml(String((lv && lv.label) || 'Input '));
            var db = Number(lv && lv.dbfs);
            var hz = Number(lv && lv.detected_hz);
            var txt = Number.isFinite(db) ? db.toFixed(1) + ' dB' : '-- dB';
            var hzTxt = '';
            if (Number.isFinite(hz) && hz > 0) hzTxt = ' (' + (hz / 1000).toFixed(3) + ' kHz)';
            var cls = (lv && lv.is_above_threshold) ? ' input-level-pill-active' : '';
            return '<span class="pill status-pill input-level-pill' + cls + '">' + label + hzTxt + ': ' + txt + '</span>';
          }}).join('');
        }}
        function refreshStatus(){{
          fetch('/api/status').then(r=>r.json()).then(d=>{{
            var p=document.getElementById('status-pill');if(!p)return;
            p.textContent=d.status_text; p.classList.remove('status-playing','status-waiting');
            p.classList.add('status-'+d.status_class);
            renderInputLevels(d.input_levels || []);
            var warn=document.getElementById('stylus-warning-banner');
            var setupBtn=document.getElementById('setup-pill-btn');
            if (warn) {{
              var txt = String((d && d.playback_banner_text) || '').trim();
              warn.hidden = !txt;
              warn.textContent = txt;
              if (setupBtn) {{
                if (txt) {{
                  setupBtn.style.background = '#c00000';
                  setupBtn.style.color = '#fff';
                  setupBtn.style.borderColor = '#c00000';
                }} else {{
                  setupBtn.style.background = '';
                  setupBtn.style.color = '';
                  setupBtn.style.borderColor = '';
                }}
              }}
            }}
          }});
        }}
        function isActiveControl(el) {{
          return el && document.activeElement === el;
        }}

        async function refreshOutputsState() {{
          let j = null;
          try {{
            const r = await fetch("/api/owntone/outputs_state", {{ cache: "no-store" }});
            j = await r.json();
          }} catch (e) {{
            return;
          }}
          if (!j || !j.ok || !Array.isArray(j.outputs)) return;

          for (const o of j.outputs) {{
            const id = String(o.id);

            // Skip outputs with a request in flight; sendUpdate's finally block
            // will remove the id once the request settles (or aborts after 5 s).
            if (window.__PENDING_OUTPUTS && window.__PENDING_OUTPUTS.has(id)) continue;

            const cb = document.getElementById("output_enabled_" + id);
            const sl = document.getElementById("vol_slider_" + id);

            if (cb) cb.checked = !!o.selected;
            updateOutputStateVisual(id, !!o.selected);

            if (sl && !isActiveControl(sl)) {{
              const v = normalizeVolume(o.volume);
              const vstr = String(v);
              if (sl.value !== vstr) sl.value = vstr;
              updateVolumeLabel(id, v);
            }}
          }}
          reorderOutputCards();
        }}

        window.addEventListener('DOMContentLoaded',function(){{
          window.__PENDING_OUTPUTS = new Set();
          document.querySelectorAll('[data-volume-label-for]').forEach(s=>{{
            var i=s.getAttribute('data-volume-label-for'), sl=document.getElementById('vol_slider_'+i);
            if(sl)updateVolumeLabel(i, sl.value);
            var cb=document.getElementById('output_enabled_'+i);
            if(cb) updateOutputStateVisual(String(i), !!cb.checked);
          }});
          reorderOutputCards();
          setInterval(() => {{ refreshStatus(); refreshOutputsState(); }}, 2000);
          refreshStatus();
          refreshOutputsState();
        }});
      </script></head>
      <body>{lic_html}{lic_spacer}
      <div id="pinModal" role="dialog" aria-modal="true" aria-labelledby="pinModalTitle">
        <div class="panel">
          <div class="hdr" id="pinModalTitle">Enter PIN</div>
          <div class="bd">
            <p>Enter the PIN shown on your Apple TV (or other AirPlay device) to enable playback.</p>
            <input id="pinModalInput" inputmode="numeric" autocomplete="one-time-code" placeholder="PIN" />
          </div>
          <div class="ft">
            <button type="button" class="btn cancel" id="pinModalCancel">Cancel</button>
            <button type="button" class="btn ok" id="pinModalOk">OK</button>
          </div>
        </div>
      </div>
      <div class="container">
      <div class="airplay-masthead">
        <div class="airplay-brand">{BANNER_HTML}</div>
      </div>
      <div class="airplay-top-controls">
        <div class="airplay-refresh-wrap">
          <button type="button"
                  class="pill-btn"
                  onclick="location.reload();"
                  title="Reload page to refresh speakers">
            ↻ Refresh
          </button>
        </div>
        <span id="status-pill"
              class="pill status-pill status-{status_class}">
          {html.escape(status_text)}
        </span>
      </div>
      <div id="stylus-warning-banner" {'hidden' if not stylus_banner_text else ''} style="margin:0.85rem 0 0.35rem;padding:0.8rem 1rem;border-radius:8px;background:#c00000;color:#fff;font-weight:700;text-align:center;">
        {html.escape(stylus_banner_text)}
      </div>
      {f"<p style='color:red;'>{html.escape(error)}</p>" if error else ""}
      {A2HS_PROMPT_HTML}
      <div id="outputs-list">{outputs_html}</div>
      <div class="home-input-level-wrap" id="home-input-level-wrap" {'hidden' if not input_levels_html else ''}>
        <div id="input-level-row" class="pill-row input-level-row">
          {input_levels_html}
        </div>
      </div>
      <br />
      <p class="actions" style="margin-top:1rem;display:flex;gap:0.75rem;">
        <a href="/about" class="pill-btn" style="flex:1;text-align:center;">About</a>
        <a href="/setup" id="setup-pill-btn" class="pill-btn" style="{setup_button_style}">Setup</a>
      </p>
      <p style="margin-top:0.25rem; text-align:center;">
        <small>Copyright &copy; Lo-tech Systems Limited.<br><strong>lo-tech.co.uk/autostream</strong></small>
      </p></div>{A2HS_SCRIPT}</body></html>
    """)
    body_bytes = html_body.encode("utf-8")
    try:
        handler.send_response(200)
        handler.send_header("Content-Type", "text/html; charset=utf-8")
        handler.send_header("Content-Length", str(len(body_bytes)))
        handler.end_headers()
        handler.wfile.write(body_bytes)
    except (BrokenPipeError, ConnectionResetError):
        logging.info("Client disconnected before airplay page response completed.")
    except Exception:
        logging.exception("Failed sending airplay page response.")


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
      <title>autostream</title><style>{STYLE_CSS}\n{PIN_MODAL_CSS}</style>{csrf_meta}
      </head>
      <body>{lic_html}{lic_spacer}<div class="container">{BANNER_HTML}<h1>{h1}</h1>
      <p class="actions" style="display:flex;justify-content:space-between;gap:0.75rem;">
        {nav_html}
        <a href="/logs" class="pill-btn">Logs</a>
      </p>
      {f"<p style='color:green;'>Saved</p>" if saved_ok else ""}
      {f"<p style='color:red;'>{html.escape(error)}</p>" if error else ""}
      <form method="POST" action="/setup">
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
      {A2HS_SCRIPT}
      </body>
      <script>
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

def send_owntone_setup_page(handler, state: WebUIState, auth, saved_ok: bool = False, error: Optional[str] = None, flash_msg: Optional[str] = None) -> None:
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
        # Offline rows are keyed by stable output id when known; name-only rows
        # are retained only so hidden outputs can still be unhidden later.
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

        # Only expose the runtime mode selector when capability is currently
        # advertised, or when this stable output id already has a saved runtime
        # AirPlay preference. That avoids showing protocol controls for offline
        # non-AirPlay outputs that happen to share the same generic row layout.
        can_edit_mode = bool(
            out_id and (supports_protocol_api or has_saved_runtime_mode)
        ) or (
            protocol_api_state == "legacy" and not name_only
        )
        show_raop = True if (not supports_protocol_api and can_edit_mode) else supports_raop
        show_airplay2 = True if (not supports_protocol_api and can_edit_mode) else supports_ap2
        is_airplay_output = show_raop or show_airplay2

        # Offset slider is only shown if the output object includes offset_ms.
        # Saved value (default 0) is stored in autostream.ini [owntone_offsets] by output id.
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

        # Build the protocol-mode select, filtered by capability flags.
        # Hidden for non-AirPlay outputs (both flags explicitly False).
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

def send_about_page(handler, state: WebUIState) -> None:
    version = get_app_version()
    lic_html, lic_spacer = build_top_banner_html()
    playback_snapshot = get_playback_snapshot()
    total_playback_seconds = sum(
        int(snap.total_playback_seconds)
        for idx, snap in playback_snapshot.inputs.items()
        if int(idx) in (1, 2)
    )
    total_playback_hours = total_playback_seconds / 3600.0
    cpu_temp_c = get_cpu_temperature_c()
    cpu_temp_text = (
        f"{cpu_temp_c:.1f}\N{DEGREE SIGN}C"
        if cpu_temp_c is not None
        else "Unavailable"
    )
    parsed = None
    try:
        parsed = parse_config(locked_load_config(state.config_path))
    except Exception:
        parsed = None
    du = get_root_disk_usage()
    storage_html = ""
    if du:
        tot, usd, fre = du
        pct = (usd/tot)*100 if tot else 0
        clr = "#28a745" if pct<60 else ("#f0ad4e" if pct<80 else "#dc3545")
        storage_html = f"<div class='bar-label'><strong>Disk Usage:</strong> {pct:.1f}%</div><div class='storage-bar'><div class='used' style='width:{pct}%;background:{clr};'></div></div><div class='storage-meta'>Free: {fmt_bytes(fre)} / {fmt_bytes(tot)}</div>"
    
    sd_health = get_sdcard_health_percent()
    sd_html = ""
    if sd_health is not None:
        clr = "#dc3545" if sd_health<=10 else ("#f0ad4e" if sd_health<=30 else "#28a745")
        sd_html = f"<div class='bar-label'><strong>SD Health:</strong> {sd_health}%</div><div class='storage-bar'><div class='used' style='width:{sd_health}%;background:{clr};'></div></div>"

    stylus_html = ""
    if parsed is not None:
        stylus_rows: list[str] = []
        input1_snapshot = playback_snapshot.inputs.get(1) or _fallback_input_snapshot(
            parsed.audio1,
            1,
            enabled=True,
        )
        show_input1_stylus = bool(parsed.audio1.is_turntable)
        if show_input1_stylus:
            input1_title = "Input 1 Stylus"
            if input1_snapshot.last_stylus_reset_at:
                input1_title += f" (last changed {_format_reset_date(input1_snapshot.last_stylus_reset_at)})"
            stylus_rows.append(
                _stylus_box_html(
                    title=input1_title,
                    snapshot=input1_snapshot,
                )
            )

        input2_snapshot = playback_snapshot.inputs.get(2) or _fallback_input_snapshot(
            parsed.audio2,
            2,
            enabled=parsed.audio2_enabled,
        )
        show_input2_stylus = bool(parsed.audio2_enabled and parsed.audio2.is_turntable)
        if show_input2_stylus:
            input2_title = "Input 2 Stylus"
            if input2_snapshot.last_stylus_reset_at:
                input2_title += f" (last changed {_format_reset_date(input2_snapshot.last_stylus_reset_at)})"
            stylus_rows.append(
                _stylus_box_html(
                    title=input2_title,
                    snapshot=input2_snapshot,
                )
            )

        stylus_html = "".join(stylus_rows)

    html_body = textwrap.dedent(f"""\
      <!DOCTYPE html><html><head><meta charset="utf-8">{VIEWPORT_META}
      <title>About</title><style>{STYLE_CSS}</style></head><body>{lic_html}{lic_spacer}<div class='container'>{BANNER_HTML}<h1>About</h1>
      <p class="actions" style="margin:1rem 0;display:flex;justify-content:space-between;align-items:center;gap:0.75rem;"><a href="/" class="pill-btn">← Back</a><a href="/license" class="pill-btn" style="background:#6c757d;color:#fff;border-color:#6c757d;">License</a></p>
      <fieldset><legend>Overview</legend>
          <p><strong>autostream</strong> brings AirPlay compatibility to any turntable, CD player, or other analogue Hi-Fi device.</p>
      </fieldset>
      {stylus_html}
      <fieldset><legend>System (build {html.escape(version)})</legend>
        <div class='bar-label'><strong>Total Playback Time:</strong> {total_playback_hours:.1f} hours</div>
        <div class='bar-label'><strong>CPU temperature:</strong> {html.escape(cpu_temp_text)}</div>
        {storage_html}{sd_html}
      </fieldset>
      <fieldset><legend>Copyright</legend>
          <p><strong>autostream</strong> is Copyright &copy; 2025-2026 Lo-tech Systems Limited.</p>
          <p><strong>autostream</strong> and the autostream logo are trademarks of Lo-tech Systems Limited.</p>
          <p><strong>autostream</strong> depends on components provided by the Raspberry Pi OS distribution, including OwnTone and ALSA audio libraries. These components are redistributed under the terms of their respective open-source licences, which are included with Raspberry Pi OS in <code>/usr/share/doc</code>.</p>
          <p>AirPlay and AirPlay&nbsp;2 are trademarks of Apple Inc., registered in the U.S. and other countries. Raspberry Pi is a trademark of Raspberry Pi Ltd. All other trademarks are the property of their respective owners.</p>
      </fieldset>
      </div></body></html>
    """)
    body_bytes = html_body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)

def send_logs_page(
    handler,
    state: WebUIState,
    flash_msg: Optional[str] = None,
    flash_type: str = "success",
) -> None:
    lic_html, lic_spacer = build_top_banner_html(flash_msg=flash_msg, flash_type=flash_type)
    current_log_level = "info"
    try:
        cfg = locked_load_config(state.config_path)
        parsed = parse_config(cfg)
        current_log_level = parsed.general.log_level
        log_path = _resolve_allowed_log_path(parsed.general.log_file)
        lines = tail_lines(str(log_path), 100)
        log_content = "\n".join(lines)
    except Exception as e:
        logging.warning("Logs page: denied/failed reading configured log: %s", e)
        log_content = "Error reading logs (access denied or unavailable)."

    csrf_token = getattr(handler, "_csrf_token", "") or ""
    log_level_options_html = "".join(
        (
            f"<option value=\"{html.escape(level)}\""
            f"{' selected' if level == current_log_level else ''}>"
            f"{html.escape(level)}</option>"
        )
        for level in get_log_level_options()
    )

    html_body = textwrap.dedent(f"""\
      <!DOCTYPE html><html><head><meta charset="utf-8"><title>Logs</title>
      <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
      <style>{STYLE_CSS}
      body {{ font-size: 14px !important; }}
      .log-controls {{ display:flex; gap:0.6rem; align-items:flex-end; margin:0.8rem 0 1rem; flex-wrap:wrap; }}
      .log-controls .field {{ flex:1 1 200px; }}
      .log-controls label {{ display:block; margin-bottom:0.25rem; font-weight:600; }}
      .log-controls select {{ width:100%; }}
      .log-wrapper {{ background:#111; color:#f5f5f5; padding:0.65rem; border-radius:6px; font-family:monospace; font-size:0.65rem; max-height:60vh; overflow:auto; white-space:pre-wrap; }}
      </style></head><body>{lic_html}{lic_spacer}<div class="container">{BANNER_HTML}<h1>Logs</h1>
      <p class="actions" style="display:flex;justify-content:space-between;"><a href="/setup" class="pill-btn">← Back</a> <a href="/logs" class="pill-btn">↻ Refresh</a></p>
      <form method="post" action="/logs" class="log-controls">
        <input type="hidden" name="csrf_token" value="{html.escape(csrf_token)}">
        <div class="field">
          <label for="log_level">Log Level</label>
          <select id="log_level" name="log_level">{log_level_options_html}</select>
        </div>
        <button type="submit" class="pill-btn">Save</button>
      </form>
      <div class="log-wrapper" id="logWrapper"><pre>{html.escape(log_content)}</pre></div>
      <p class="actions"><a href="/offline/download-logs" class="pill-btn" id="logDlBtn" style="display:block;width:100%;text-align:center;box-sizing:border-box;">Download Log Bundle</a></p>
      <script>
        window.addEventListener('load', function() {{
          var w = document.getElementById('logWrapper');
          var b = document.getElementById('logDlBtn');

          // Hide "Download Log Bundle" on iPhone when running as a PWA (standalone)
          var ua = navigator.userAgent || "";
          var isIPhone = /iPhone/.test(ua);
          var isStandalone =
            (window.navigator && window.navigator.standalone === true) ||
            (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches);

          if (b && isIPhone && isStandalone) {{
            b.style.display = "none";
          }}

          // Keep existing width-matching behaviour if still visible
          if (w && b && b.style.display !== "none") {{
            b.style.width = w.offsetWidth + 'px';
          }}
        }});
      </script>
      </div></body></html>
    """)
    body_bytes = html_body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)


def handle_logs_post(handler, state: WebUIState, body: str) -> None:
    try:
        form = parse_qs(body, keep_blank_values=True)
        new_log_level = normalize_log_level((form.get("log_level") or [""])[0])

        with CONFIG_IO_LOCK:
            cfg = load_config(state.config_path)
            parsed = parse_config(cfg)
            if not cfg.has_section("general"):
                cfg.add_section("general")
            cfg.set("general", "log_level", new_log_level)
            with open(state.config_path, "w", encoding="utf-8") as fh:
                cfg.write(fh)

        applied_log_level, monitor_updated = update_live_platform_log_level(new_log_level)
        owntone_res = None
        needs_owntone_restart = False
        if parsed.owntone.base_url:
            owntone_res = owntone_apply_log_level(
                parsed.owntone.base_url,
                applied_log_level,
            )
            if not owntone_res.available:
                with CONFIG_IO_LOCK:
                    conf_level = read_log_level_from_conf(OWNTONE_CONF_PATH)
                    if conf_level != applied_log_level:
                        if not write_log_level_to_conf(applied_log_level, OWNTONE_CONF_PATH):
                            raise RuntimeError("Failed writing OwnTone loglevel to owntone.conf")
                        needs_owntone_restart = True

        if needs_owntone_restart and not owntone_restart_service():
            flash_text = (
                "Log level saved, but OwnTone restart failed"
                if monitor_updated
                else "Log level saved, but OwnTone restart failed and monitor runtime update failed"
            )
            _set_flash_cookie(handler, flash_text, max_age=30)
            handler.send_response(302)
            handler.send_header("Location", "/logs")
            handler.end_headers()
            return

        flash_text = (
            "Log level saved"
            if monitor_updated
            else "Log level saved, but monitor runtime log level was not updated"
        )
        owntone_still_needs_attention = (
            owntone_res is not None
            and not owntone_res.ok
            and not (owntone_res.available is False and not needs_owntone_restart)
        )
        if owntone_still_needs_attention:
            flash_text = (
                "Log level saved; OwnTone restarted"
                if needs_owntone_restart
                else "Log level saved, but OwnTone was not updated"
            )
            if not monitor_updated:
                flash_text += " and monitor runtime update failed"

        _set_flash_cookie(handler, flash_text, max_age=30)
        handler.send_response(302)
        handler.send_header("Location", "/logs")
        handler.end_headers()
    except Exception:
        logging.exception("Failed saving log level from Logs page.")
        send_logs_page(handler, state, flash_msg="Save failed", flash_type="error")


def send_status_json(handler, state: Optional[WebUIState] = None) -> None:
    is_playing = any_monitor_capturing()
    try:
        input_levels = get_monitor_levels_dbfs()
    except Exception:
        input_levels = []
    playback = get_playback_snapshot()
    send_json(handler, 200, {
        "playing": is_playing,
        "status_text": _status_text_for_home(is_playing, input_levels),
        "status_class": "playing" if is_playing else "waiting",
        "input_levels": input_levels,
        "playback": playback.to_public_dict(),
        "playback_banner_text": playback.banner_text,
    })

def send_update_check_json(handler) -> None:
    rc, out, err = run_updater(["check"], timeout=60)
    if rc != 0:
        send_json(handler, 200, {"ok": False, "error": "check failed"})
        return
    try:
        send_json(handler, 200, json.loads(out))
    except Exception:
        send_json(handler, 200, {"ok": False})

def send_update_status_json(handler, state: WebUIState) -> None:
    send_json(handler, 200, state.get_update_status())

def handle_output_update(handler, state: WebUIState, body: str) -> None:
    try:
        payload = json.loads(body)
        out_id = payload.get("id")
        op = (payload.get("op") or "").strip().lower()
        selected = bool(payload.get("selected", False))
        volume = max(0, min(100, int(payload.get("volume", 50))))

        # PIN may arrive as string or number depending on client implementation.
        pin_raw = payload.get("pin") if isinstance(payload, dict) else None
        pin = (str(pin_raw).strip() if pin_raw is not None else "")

        cfg = locked_load_config(state.config_path)
        parsed = parse_config(cfg)
        base_url = parsed.owntone.base_url.rstrip("/")
        url = base_url + f"/api/outputs/{out_id}"

        # Two modes:
        #   (1) Normal output update: selected/volume plus autostream-managed
        #       runtime settings like offset/protocol (never send pin here)
        #   (2) PIN verification: pin ONLY (no selected/volume)
        if op == "pin":
            if not pin:
                send_json(handler, 200, {"ok": False, "error": "Missing PIN", "id": str(out_id)})
                return
            out_payload = {"pin": pin}

            logging.info("Owntone API call: PUT %s json={\"pin\":\"***\"}", url)
            resp = requests.put(url, json=out_payload, timeout=3)
            logging.info("Owntone API response: status=%s body=%s",
                         getattr(resp, "status_code", None),
                         (getattr(resp, "text", "") or "").strip())

            # Mode (2): PIN-only verification.
            # OwnTone returns 400 if the PIN was wrong/failed; client should re-prompt.
            if resp.status_code == 400:
                send_json(handler, 200, {
                    "ok": False,
                    "id": str(out_id),
                    "pin_invalid": True,
                    "status": int(resp.status_code),
                    "error": (resp.text or "").strip(),
                })
                return
            if not resp.ok:
                send_json(handler, 200, {
                    "ok": False,
                    "id": str(out_id),
                    "status": int(resp.status_code),
                    "error": (resp.text or "").strip(),
                })
                return
            send_json(handler, 200, {"ok": True, "id": str(out_id)})
            return

        if selected:
            outputs = owntone_fetch_outputs(base_url, timeout=3)
            out_obj = owntone_get_output(
                base_url,
                out_id,
                outputs=outputs,
                timeout=3,
            )
            mode = resolve_owntone_output_airplay_mode(
                out_id,
                output_airplay_modes=parsed.owntone.output_airplay_modes,
            )
            payload_result = build_owntone_output_update_payload(
                out_obj,
                selected=True,
                volume=volume,
                offset_ms=parsed.owntone.output_offsets_ms.get(str(out_id)),
                protocol_mode=mode,
            )
            out_payload = payload_result.payload
            if payload_result.protocol_coerced:
                logging.warning(
                    "OwnTone output %s does not support the configured runtime protocol; coercing to default.",
                    out_id,
                )
            if payload_result.protocol_requested and not payload_result.protocol_included:
                if payload_result.output_known:
                    logging.info(
                        "Skipping runtime protocol for OwnTone output %s because this build does not advertise protocol capability.",
                        out_id,
                    )
                else:
                    logging.warning(
                        "Skipping runtime protocol for OwnTone output %s because output metadata was unavailable.",
                        out_id,
                    )
            logging.info("Owntone API call: PUT %s json=%s", url, out_payload)
            resp = requests.put(url, json=out_payload, timeout=3)
            logging.info("Owntone API response: status=%s body=%s",
                         getattr(resp, "status_code", None),
                         (getattr(resp, "text", "") or "").strip())

            # OwnTone returns HTTP 400 when an output enable requires device PIN verification.
            if resp.status_code == 400:
                send_json(handler, 200, {
                    "ok": False,
                    "pin_required": True,
                    "id": str(out_id),
                    "output_name": str(payload.get("name") or ""),
                    "status": int(resp.status_code),
                    "error": (resp.text or "").strip(),
                })
                return

            if not resp.ok:
                send_json(handler, 200, {
                    "ok": False,
                    "id": str(out_id),
                    "status": int(resp.status_code),
                    "error": (resp.text or "").strip(),
                    "pin_invalid": False,
                })
                return

            send_json(handler, 200, {"ok": True, "id": str(out_id)})
            return

        # Disable path: preserve all other currently-selected outputs by using /api/outputs/set.
        outputs_url = base_url + "/api/outputs"
        set_url = base_url + "/api/outputs/set"
        list_resp = requests.get(outputs_url, timeout=3)
        if not list_resp.ok:
            send_json(handler, 200, {
                "ok": False,
                "id": str(out_id),
                "status": int(list_resp.status_code),
                "error": (list_resp.text or "").strip(),
            })
            return

        outputs = (list_resp.json() or {}).get("outputs", [])
        remaining = [str(o.get("id")) for o in outputs if o.get("selected") and str(o.get("id")) != str(out_id)]

        set_payload = {"outputs": remaining}
        logging.info("Owntone API call: PUT %s json=%s", set_url, set_payload)
        resp = requests.put(set_url, json=set_payload, timeout=3)
        logging.info("Owntone API response: status=%s body=%s",
                     getattr(resp, "status_code", None),
                     (getattr(resp, "text", "") or "").strip())
        if not resp.ok:
            send_json(handler, 200, {
                "ok": False,
                "id": str(out_id),
                "status": int(resp.status_code),
                "error": (resp.text or "").strip(),
                "pin_invalid": False,
            })
            return

        send_json(handler, 200, {"ok": True, "id": str(out_id)})
    except Exception as e:
        logging.error("Update failed: %s", e)
        send_json(handler, 200, {"ok": False, "error": str(e)})

def handle_setup_post(handler, state: WebUIState, auth, body: str) -> None:
    form = parse_qs(body)
    def fld(n, d=""): return (form.get(n, []) or [d])[0]
    try:
        cfg = locked_load_config(state.config_path)
        p = parse_config(cfg)

        # Snapshot daemon-relevant values before any changes so we can decide
        # whether a full coordinator reload is needed after saving.
        old_audio1_device    = p.audio1.capture_device
        old_audio1_threshold = p.audio1.silence_threshold_dbfs
        old_audio2_enabled   = p.audio2_enabled
        old_audio2_device    = p.audio2.capture_device
        old_audio2_threshold = p.audio2.silence_threshold_dbfs
        old_silence_seconds  = p.general.silence_seconds
        new_audio2_enabled   = "audio2_enabled" in form
        new_audio1_turntable = "audio_turntable" in form
        new_audio2_turntable = "audio2_turntable" in form
        new_audio1_threshold = suggested_silence_threshold_dbfs(new_audio1_turntable)
        new_audio2_threshold = suggested_silence_threshold_dbfs(new_audio2_turntable)
        new_audio1_stylus_life = normalize_stylus_life_hours(
            fld("audio_stylus_life_hours", str(p.audio1.stylus_life_hours))
        )
        new_audio2_stylus_life = normalize_stylus_life_hours(
            fld("audio2_stylus_life_hours", str(p.audio2.stylus_life_hours))
        )
        reset_stylus_input_raw = fld("stylus_reset_input", "").strip()

        # Hostname
        old_hn = get_system_hostname()
        nh = fld("system_hostname").strip()
        hostname_changed = bool(nh and nh != old_hn)
        if hostname_changed:
            set_system_hostname(nh)

        # Config updates
        if not cfg.has_section("audio1"): cfg.add_section("audio1")
        cfg.set("audio1", "capture_device", fld("audio_capture_device", p.audio1.capture_device))
        cfg.set("audio1", "silence_threshold", str(new_audio1_threshold))
        cfg.set("audio1", "turntable", "yes" if new_audio1_turntable else "no")
        cfg.set("audio1", "stylus_life_hours", str(new_audio1_stylus_life))
        cfg.set("audio1", "gain_db", fld("audio1_gain_db", str(p.audio1.gain_db)))
        cfg.set("audio1", "eq_40hz_db", fld("audio1_eq_40hz_db", str(p.audio1.eq_40hz_db)))
        cfg.set("audio1", "eq_100hz_db", fld("audio1_eq_100hz_db", str(p.audio1.eq_100hz_db)))
        cfg.set("audio1", "eq_10khz_db", fld("audio1_eq_10khz_db", str(p.audio1.eq_10khz_db)))

        if not cfg.has_section("audio2"): cfg.add_section("audio2")
        cfg.set("audio2", "enabled", "yes" if new_audio2_enabled else "no")
        cfg.set("audio2", "capture_device", fld("audio2_capture_device", p.audio2.capture_device))
        cfg.set("audio2", "silence_threshold", str(new_audio2_threshold))
        cfg.set("audio2", "turntable", "yes" if new_audio2_turntable else "no")
        cfg.set("audio2", "stylus_life_hours", str(new_audio2_stylus_life))
        cfg.set("audio2", "gain_db", fld("audio2_gain_db", str(p.audio2.gain_db)))
        cfg.set("audio2", "eq_40hz_db", fld("audio2_eq_40hz_db", str(p.audio2.eq_40hz_db)))
        cfg.set("audio2", "eq_100hz_db", fld("audio2_eq_100hz_db", str(p.audio2.eq_100hz_db)))
        cfg.set("audio2", "eq_10khz_db", fld("audio2_eq_10khz_db", str(p.audio2.eq_10khz_db)))

        if not cfg.has_section("owntone"): cfg.add_section("owntone")
        cfg.set("owntone", "output_name", fld("owntone_output_name", p.owntone.output_name))
        cfg.set("owntone", "volume_percent", fld("owntone_volume_percent", str(p.owntone.volume_percent)))

        if not cfg.has_section("general"): cfg.add_section("general")
        cfg.set("general", "silence_seconds", fld("silence_seconds", str(p.general.silence_seconds)))

        # Persist defaults into the INI the first time it is created (or if missing)
        if not cfg.get("general", "log_file", fallback="").strip():
            cfg.set("general", "log_file", p.general.log_file)

        if not cfg.get("general", "fifo_path", fallback="").strip():
            cfg.set("general", "fifo_path", p.general.fifo_path)

        # Atomicity across concurrent requests/tabs:
        with CONFIG_IO_LOCK:
            with open(state.config_path, "w", encoding="utf-8") as f:
                cfg.write(f)
            mark_configured(state.config_path)

        update_live_owntone_runtime(
            output_name=fld("owntone_output_name", p.owntone.output_name),
            volume_percent=fld(
                "owntone_volume_percent",
                str(p.owntone.volume_percent),
            ),
            output_offsets_ms=p.owntone.output_offsets_ms,
            output_airplay_modes=p.owntone.output_airplay_modes,
        )
        update_playback_input_config(
            1,
            enabled=True,
            is_turntable=new_audio1_turntable,
            stylus_life_hours=new_audio1_stylus_life,
        )
        update_playback_input_config(
            2,
            enabled=new_audio2_enabled,
            is_turntable=new_audio2_turntable,
            stylus_life_hours=new_audio2_stylus_life,
        )

        reset_stylus_result = None
        reset_stylus_input: Optional[int] = None
        if reset_stylus_input_raw:
            try:
                reset_stylus_input = int(reset_stylus_input_raw)
            except ValueError:
                reset_stylus_input = None
            if reset_stylus_input in (1, 2):
                reset_stylus_result = reset_input_stylus(reset_stylus_input)

        flash_text = "Settings saved"
        if reset_stylus_input is not None and reset_stylus_result is not None:
            flash_text = _stylus_reset_flash_text(
                reset_stylus_input,
                reset_stylus_result,
                settings_saved=True,
            )

        # One-shot success banner (cookie-based) to avoid sticky URLs in iOS A2HS/PWA.
        _set_flash_cookie(handler, flash_text, max_age=30)

        # Redirect back to / on save
        next_path = "/"

        if hostname_changed:
            host_header = handler.headers.get("Host", "")
            port = host_header.rsplit(":", 1)[1] if ":" in host_header else None
            host_p = f"{nh}.local:{port}" if port else f"{nh}.local"
            redirect_url = f"http://{host_p}{next_path}"

            # Render a redirect page
            # Note: Green "saved" banner will appear once on the destination page
            # via the flash cookie set above.
            lic_html, lic_spacer = build_top_banner_html(flash_msg=None)
            safe_url = html.escape(redirect_url)

            body = textwrap.dedent(f"""\
              <!DOCTYPE html><html><head><meta charset="utf-8">{VIEWPORT_META}
              <title>Hostname changed</title>
              <meta http-equiv="refresh" content="5;url={safe_url}">
              <style>{STYLE_CSS}</style></head>
              <body>{lic_html}{lic_spacer}<div class="container">{BANNER_HTML}
                <h1>Hostname changed</h1>
                <div class="card">
                  <p>Your device hostname is now <strong>{html.escape(nh)}.local</strong>.</p>
                  <p>Redirecting you to {safe_url}</p>
                  <p style="word-break:break-word;">
                    <a class="pill-btn" href="{safe_url}">Tap here to continue</a>
                  </p>
                </div>
              </div></body></html>
            """)
            body_bytes = body.encode("utf-8")

            # Best-effort response (don’t let a broken client prevent flow).
            try:
                handler.send_response(200)
                handler.send_header("Content-Type", "text/html; charset=utf-8")
                handler.send_header("Content-Length", str(len(body_bytes)))
                handler.end_headers()
                handler.wfile.write(body_bytes)
                try:
                    handler.wfile.flush()
                except Exception:
                    pass
            except Exception:
                pass
        else:
            handler.send_response(302)
            handler.send_header("Location",  next_path)
            handler.send_header("Content-Length", "0")
            handler.end_headers()
        
        # Only restart the coordinator if a setting that requires daemon
        # reconfiguration actually changed.  EQ, gain, output name, volume,
        # hostname, and silence detection period changes should take effect
        # without disrupting playback.
        try:
            new_silence_seconds = int(fld("silence_seconds", str(old_silence_seconds)))
        except ValueError:
            new_silence_seconds = old_silence_seconds

        daemon_changed = (
            fld("audio_capture_device", old_audio1_device) != old_audio1_device
            or new_audio1_threshold != old_audio1_threshold
            or new_audio2_enabled != old_audio2_enabled
            or fld("audio2_capture_device", old_audio2_device) != old_audio2_device
            or new_audio2_threshold != old_audio2_threshold
        )
        silence_seconds_changed = new_silence_seconds != old_silence_seconds

        if silence_seconds_changed and not daemon_changed:
            from autostream_core import update_live_silence_seconds
            if not update_live_silence_seconds(new_silence_seconds):
                daemon_changed = True

        if daemon_changed:
            from autostream_core import request_config_reload
            request_config_reload()
    except Exception as e:
        send_setup_page(handler, state, auth, flash_msg="Save failed", flash_type="error")

def handle_live_input_eq_update(handler, state: WebUIState, body: str) -> None:
    """Apply live per-input EQ changes to autostream_monitor."""
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    try:
        input_index = int(payload.get("input", 0))
        eq_40hz_db = float(payload.get("eq_40hz_db", 0.0))
        eq_100hz_db = float(payload.get("eq_100hz_db", 0.0))
        eq_10khz_db = float(payload.get("eq_10khz_db", 0.0))
    except Exception:
        send_json(handler, 400, {"ok": False, "error": "Invalid EQ payload"})
        return

    if input_index not in (1, 2):
        send_json(handler, 400, {"ok": False, "error": "input must be 1 or 2"})
        return

    for val in (eq_40hz_db, eq_100hz_db, eq_10khz_db):
        if val < -10.0 or val > 10.0:
            send_json(handler, 400, {"ok": False, "error": "EQ gain must be between -10 and 10 dB"})
            return

    ok = set_live_input_eq(
        input_index=input_index,
        eq_40hz_db=eq_40hz_db,
        eq_100hz_db=eq_100hz_db,
        eq_10khz_db=eq_10khz_db,
    )
    if not ok:
        send_json(handler, 200, {"ok": False, "error": "Could not update live EQ"})
        return

    send_json(handler, 200, {
        "ok": True,
        "input": input_index,
        "eq_40hz_db": eq_40hz_db,
        "eq_100hz_db": eq_100hz_db,
        "eq_10khz_db": eq_10khz_db,
    })


def handle_live_input_gain_update(handler, state: WebUIState, body: str) -> None:
    """Apply live per-input gain changes to autostream_monitor."""
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    try:
        input_index = int(payload.get("input", 0))
        gain_db = float(payload.get("gain_db", 0.0))
    except Exception:
        send_json(handler, 400, {"ok": False, "error": "Invalid gain payload"})
        return

    if input_index not in (1, 2):
        send_json(handler, 400, {"ok": False, "error": "input must be 1 or 2"})
        return

    if gain_db < -10.0 or gain_db > 10.0:
        send_json(handler, 400, {"ok": False, "error": "Gain must be between -10 and 10 dB"})
        return

    ok = set_live_input_gain(
        input_index=input_index,
        gain_db=gain_db,
    )
    if not ok:
        send_json(handler, 200, {"ok": False, "error": "Could not update live gain"})
        return

    send_json(handler, 200, {
        "ok": True,
        "input": input_index,
        "gain_db": gain_db,
    })

def handle_owntone_setup_post(handler, state: WebUIState, auth, body: str) -> None:
    form = parse_qs(body)

    def fld(n, d=""):
        return (form.get(n, []) or [d])[0]

    try:
        cfg = locked_load_config(state.config_path)

        # Tuple: (stable_output_id, display_name, show, mode, offset_ms_or_none)
        speakers: list[tuple[str, str, bool, str, Optional[int]]] = []
        valid_airplay_modes = {DEFAULT_AIRPLAY_MODE, "raop", "airplay2"}
        i = 0
        while f"spk_{i}" in form:
            speaker_id = fld(f"spk_id_{i}", "").strip()
            name = fld(f"spk_{i}")
            show = (f"show_{i}" in form)
            mode = fld(f"mode_{i}", DEFAULT_AIRPLAY_MODE).strip().lower()
            if mode not in valid_airplay_modes:
                mode = DEFAULT_AIRPLAY_MODE
            offset_ms: Optional[int] = None
            if f"offset_{i}" in form:
                raw_off = fld(f"offset_{i}", "0")
                try:
                    offset_ms = int(str(raw_off).strip())
                except Exception:
                    offset_ms = 0
                offset_ms = max(-2000, min(2000, offset_ms))
            speakers.append((speaker_id, name, show, mode, offset_ms))

            i += 1

        speakers.sort(key=lambda t: t[1].casefold())

        hidden = [
            spk_name
            for (_spk_id, spk_name, show, _mode, _offset) in speakers
            if not show
        ]
        if not cfg.has_section("webui"):
            cfg.add_section("webui")
        if hidden:
            cfg.set("webui", "hidden_outputs", "\n    " + "\n    ".join(hidden))
        else:
            cfg.set("webui", "hidden_outputs", "")

        base_url = cfg.get("owntone", "base_url", fallback="http://localhost:3689")
        current_outputs = owntone_fetch_outputs(base_url, timeout=3)
        current_outputs_list = current_outputs or []
        outputs_by_id = {
            str(o.get("id")).strip(): o
            for o in current_outputs_list
            if o.get("id") is not None
        }
        persisted_protocol_api_state = cfg.get(
            "owntone",
            "protocol_api_state",
            fallback=DEFAULT_OWNTONE_PROTOCOL_API_STATE,
        )
        protocol_api_state = resolve_owntone_protocol_api_state(
            current_outputs,
            persisted_protocol_api_state,
        )
        if current_outputs is None:
            logging.warning(
                "OwnTone setup save: output metadata was unavailable; reusing last-known protocol compatibility state %r.",
                protocol_api_state,
            )
        elif not current_outputs_list:
            logging.info(
                "OwnTone setup save: no outputs are currently discovered; reusing last-known protocol compatibility state %r.",
                protocol_api_state,
            )

        existing_parsed = parse_config(cfg)
        # Preserve entries for currently undiscovered outputs so a temporary
        # disappearance does not erase the user's saved id-based preference.
        offsets_by_id = dict(existing_parsed.owntone.output_offsets_ms)
        runtime_airplay_modes_by_id = dict(existing_parsed.owntone.output_airplay_modes)
        existing_runtime_mode_ids = set(runtime_airplay_modes_by_id.keys())
        known_outputs = dict(existing_parsed.owntone.known_outputs)
        conf_airplay_writes: list[tuple[str, bool]] = []
        if protocol_api_state == "legacy":
            runtime_airplay_modes_by_id = {}
        for out_id, spk, _show, mode, offset_ms in speakers:
            out_id = str(out_id or "").strip()
            out_obj = outputs_by_id.get(out_id) if out_id else None
            if out_id and spk.strip():
                known_outputs[out_id] = spk.strip()
            if out_id:
                if offset_ms is not None:
                    offsets_by_id[out_id] = offset_ms

            normalized_mode = normalize_airplay_mode(mode)
            if protocol_api_state == "runtime":
                if not out_id:
                    logging.warning(
                        "OwnTone speaker %r has no stable output id yet; cannot save runtime protocol preference.",
                        spk,
                    )
                    continue
                protocol_support = owntone_output_protocol_support(out_obj)
                if protocol_support.supports_runtime_protocol:
                    if normalized_mode == "raop" and not protocol_support.supports_raop:
                        logging.warning(
                            "OwnTone speaker %r does not support AirPlay 1; coercing mode to default.",
                            spk,
                        )
                        normalized_mode = DEFAULT_AIRPLAY_MODE
                    elif normalized_mode == "airplay2" and not protocol_support.supports_airplay2:
                        logging.warning(
                            "OwnTone speaker %r does not support AirPlay 2; coercing mode to default.",
                            spk,
                        )
                        normalized_mode = DEFAULT_AIRPLAY_MODE
                    logging.info(
                        "OwnTone speaker %r will use runtime protocol preference %r on output id %s.",
                        spk,
                        normalized_mode,
                        out_id,
                    )
                elif out_obj is None:
                    if out_id not in existing_runtime_mode_ids:
                        logging.warning(
                            "OwnTone speaker %r is not currently discovered and has no previously confirmed runtime AirPlay mode; leaving its mode unchanged.",
                            spk,
                        )
                        continue
                    logging.info(
                        "OwnTone speaker %r is not currently discovered; saving runtime protocol preference %r on output id %s for later.",
                        spk,
                        normalized_mode,
                        out_id,
                        )
                else:
                    if out_id not in existing_runtime_mode_ids:
                        logging.warning(
                            "OwnTone speaker %r did not provide protocol capability metadata and has no previously confirmed runtime AirPlay mode; leaving its mode unchanged.",
                            spk,
                        )
                        continue
                    logging.warning(
                        "OwnTone speaker %r did not provide protocol capability metadata during this save; keeping runtime preference %r on output id %s pending.",
                        spk,
                        normalized_mode,
                        out_id,
                    )
                runtime_airplay_modes_by_id[out_id] = normalized_mode
                continue

            if protocol_api_state == "legacy":
                if not spk.strip():
                    logging.warning(
                        "OwnTone speaker %r has no usable display name; cannot apply legacy owntone.conf mode handling.",
                        out_id,
                    )
                    continue
                if out_id:
                    runtime_airplay_modes_by_id.pop(out_id, None)
                conf_airplay_writes.append((spk, normalized_mode == "airplay2"))
                logging.info(
                    "OwnTone speaker %r will use legacy owntone.conf AirPlay mode handling.",
                    spk,
                )
                continue

            if not out_id:
                logging.warning(
                    "OwnTone speaker %r has no stable output id and compatibility is still unknown; mode change will be ignored for now.",
                    spk,
                )
                continue
            if out_id not in existing_runtime_mode_ids:
                logging.warning(
                    "OwnTone speaker %r compatibility is still unknown and it has no previously confirmed runtime AirPlay mode; leaving its mode unchanged.",
                    spk,
                )
                continue
            runtime_airplay_modes_by_id[out_id] = normalized_mode
            logging.warning(
                "OwnTone speaker %r compatibility could not be confirmed; saving pending runtime protocol preference %r on output id %s only.",
                spk,
                normalized_mode,
                out_id,
            )

        if cfg.has_section("owntone_offsets"):
            cfg.remove_section("owntone_offsets")
        cfg.add_section("owntone_offsets")
        for oid, off in sorted(offsets_by_id.items(), key=lambda kv: kv[0]):
            try:
                cfg.set("owntone_offsets", str(oid), str(int(off)))
            except Exception:
                cfg.set("owntone_offsets", str(oid), "0")

        if cfg.has_section("owntone_airplay_modes"):
            cfg.remove_section("owntone_airplay_modes")
        cfg.add_section("owntone_airplay_modes")
        for oid, mode in sorted(runtime_airplay_modes_by_id.items(), key=lambda kv: kv[0]):
            cfg.set("owntone_airplay_modes", str(oid), mode)

        if cfg.has_section("owntone_airplay_modes_by_name"):
            cfg.remove_section("owntone_airplay_modes_by_name")

        if cfg.has_section("owntone_known_outputs"):
            cfg.remove_section("owntone_known_outputs")
        cfg.add_section("owntone_known_outputs")
        for oid, name in sorted(known_outputs.items(), key=lambda kv: kv[0]):
            cfg.set("owntone_known_outputs", str(oid), str(name))

        if not cfg.has_section("owntone"):
            cfg.add_section("owntone")
        cfg.set("owntone", "protocol_api_state", protocol_api_state)

        want_uncompressed_audio = ("uncompressed_alac" in form)
        api_set_uncompressed = owntone_put_setting(
            base_url, "airplay", "uncompressed_alac", want_uncompressed_audio
        )
        if api_set_uncompressed.available and not api_set_uncompressed.ok:
            raise RuntimeError("Could not update OwnTone uncompressed_alac via API")

        restart_required = False

        _START_BUFFER_MIN = 300
        _START_BUFFER_MAX = 3500
        _START_BUFFER_STEP = 50
        if "start_buffer_ms" in form:
            try:
                want_buffer = int(fld("start_buffer_ms", "2250").strip())
            except (ValueError, TypeError):
                want_buffer = 2250
            want_buffer = max(
                _START_BUFFER_MIN,
                min(
                    _START_BUFFER_MAX,
                    round(want_buffer / _START_BUFFER_STEP) * _START_BUFFER_STEP,
                ),
            )
            cur_buf_res = owntone_get_setting(base_url, "general", "start_buffer_ms")
            cur_buf = (
                _coerce_owntone_int(cur_buf_res.value)
                if (cur_buf_res.available and cur_buf_res.ok)
                else None
            )
            if cur_buf is None or want_buffer != cur_buf:
                api_set_buffer = owntone_put_setting(
                    base_url, "general", "start_buffer_ms", want_buffer
                )
                if api_set_buffer.available and not api_set_buffer.ok:
                    raise RuntimeError("Could not update OwnTone start_buffer_ms via API")
                if api_set_buffer.ok:
                    restart_required = True

        with CONFIG_IO_LOCK:
            with open(state.config_path, "w", encoding="utf-8") as f:
                cfg.write(f)

            for spk, ap2 in conf_airplay_writes:
                current_ap2 = read_airplay2_for_speaker(spk, OWNTONE_CONF_PATH)
                if current_ap2 is None or bool(current_ap2) != bool(ap2):
                    if not write_airplay2_for_speaker(spk, ap2, OWNTONE_CONF_PATH):
                        raise RuntimeError(
                            f"Could not update AirPlay mode for speaker {spk!r}"
                        )
                    restart_required = True

            if not api_set_uncompressed.available:
                current_uncompressed = bool(
                    read_and_set_global_uncompressed_audio(OWNTONE_CONF_PATH)
                )
                if current_uncompressed != bool(want_uncompressed_audio):
                    if not write_and_set_global_uncompressed_audio(
                        enabled=want_uncompressed_audio,
                        conf_path=OWNTONE_CONF_PATH,
                    ):
                        raise RuntimeError("Could not update OwnTone uncompressed_alac setting")
                    restart_required = True

        saved_parsed = parse_config(cfg)
        update_live_owntone_runtime(
            output_name=cfg.get("owntone", "output_name", fallback=""),
            volume_percent=cfg.get("owntone", "volume_percent", fallback="20"),
            output_offsets_ms=saved_parsed.owntone.output_offsets_ms,
            output_airplay_modes=saved_parsed.owntone.output_airplay_modes,
        )

        if restart_required:
            start_owntone_restart_async(state)

        _set_flash_cookie(handler, "Settings saved", max_age=30)

        next_path = "/setup"
        loc = (
            "/owntone-restarting?next=" + quote(next_path, safe="/?=&")
            if restart_required
            else next_path
        )

        handler.send_response(303)
        handler.send_header("Location", loc)
        handler.send_header("Content-Length", "0")
        handler.end_headers()
    except Exception:
        send_owntone_setup_page(
            handler,
            state,
            auth,
            flash_msg="Save failed",
            flash_type="error",
        )
