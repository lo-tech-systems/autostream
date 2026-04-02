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
    update_playback_input_config,
)

from autostream_auth import FLASH_COOKIE_NAME

from autostream_config import (
    load_config,
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
    get_psu_warning_text,
    LICENSE_CHECK,
)

from autostream_owntone import (
    read_and_set_global_pipe_directory,
    write_and_set_global_pipe_directory,
    read_and_set_global_uncompressed_audio,
    write_and_set_global_uncompressed_audio,
    read_airplay2_for_speaker,
    write_airplay2_for_speaker,
    _coerce_owntone_bool,
    _coerce_owntone_int,
    owntone_get_setting,
    owntone_put_setting,
    owntone_set_airplay_mode,
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
# Shared PIN modal CSS (used by multiple pages)
# -----------------------------------------------------------------------------

VIEWPORT_META = '<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">'

PIN_MODAL_CSS = """
  #pinModal{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:rgba(0,0,0,.45);z-index:9999;padding:1.25rem;}
  #pinModal.show{display:flex;}
  #pinModal .panel{width:min(22rem,100%);background:#fff;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,.25);overflow:hidden;}
  #pinModal .hdr{padding:0.9rem 1rem;border-bottom:1px solid #eee;font-weight:700;}
  #pinModal .bd{padding:1rem;}
  #pinModal .bd p{margin:0 0 .75rem 0;}
  #pinModal input{width:100%;font-size:1.2rem;padding:.65rem .75rem;border:1px solid #ccc;border-radius:12px;outline:none;}
  #pinModal .ft{display:flex;gap:.75rem;padding:0.9rem 1rem;border-top:1px solid #eee;}
  #pinModal .btn{flex:1;border:none;border-radius:999px;padding:.8rem .9rem;font-weight:700;font-size:1rem;}
  #pinModal .btn.cancel{background:#f1f1f1;color:#111;}
  #pinModal .btn.ok{background:#0d6efd;color:#fff;}
"""


# -----------------------------------------------------------------------------
# Owntone restart async support
# -----------------------------------------------------------------------------
OWNTONE_RESTART_LOCK = threading.RLock()
OWNTONE_RESTART_STATE = {
    "in_progress": False,
    "started_at": 0.0,
    "finished_at": 0.0,
    "ok": False,
    "message": "",
    "token": 0,  # increments each time we start a restart
}

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
    """Background restart + wait loop. Updates OWNTONE_RESTART_STATE when done."""
    try:
        p = run_admin_cmd(["restart-owntone"], timeout=20.0)
        if p.returncode != 0:
            raise RuntimeError(
                f"autostream-admin restart-owntone failed (rc={p.returncode}): {(p.stderr or '').strip()}"
            )
    except Exception as e:
        with OWNTONE_RESTART_LOCK:
            # Only update if this is the latest restart attempt
            if OWNTONE_RESTART_STATE.get("token") == token:
                OWNTONE_RESTART_STATE["in_progress"] = False
                OWNTONE_RESTART_STATE["finished_at"] = time.time()
                OWNTONE_RESTART_STATE["ok"] = False
                OWNTONE_RESTART_STATE["message"] = f"Restart command failed: {e}"
        return

    # After restart command, wait for API to come back (more generous than the UI poll).
    try:
        parsed = parse_config(locked_load_config(state.config_path))
        ok, msg = wait_for_owntone_api(parsed.owntone.base_url, timeout_s=20.0)
    except Exception as e:
        ok, msg = False, str(e)

    with OWNTONE_RESTART_LOCK:
        if OWNTONE_RESTART_STATE.get("token") == token:
            OWNTONE_RESTART_STATE["in_progress"] = False
            OWNTONE_RESTART_STATE["finished_at"] = time.time()
            OWNTONE_RESTART_STATE["ok"] = bool(ok)
            OWNTONE_RESTART_STATE["message"] = msg if msg else ("Ready" if ok else "Not ready")

def start_owntone_restart_async(state) -> None:
    """Start a background restart if one isn't already running (or supersede it)."""
    with OWNTONE_RESTART_LOCK:
        OWNTONE_RESTART_STATE["in_progress"] = True
        OWNTONE_RESTART_STATE["started_at"] = time.time()
        OWNTONE_RESTART_STATE["finished_at"] = 0.0
        OWNTONE_RESTART_STATE["ok"] = False
        OWNTONE_RESTART_STATE["message"] = "Restarting Owntone…"
        OWNTONE_RESTART_STATE["token"] = int(OWNTONE_RESTART_STATE.get("token", 0)) + 1
        token = OWNTONE_RESTART_STATE["token"]

    t = threading.Thread(target=_restart_owntone_worker, args=(state, token), daemon=True)
    t.start()

def send_owntone_ready_json(handler, state) -> None:
    """JSON endpoint polled by /owntone-restarting."""
    try:
        parsed = parse_config(locked_load_config(state.config_path))
        ready, ready_msg = _owntone_ready_quick(parsed.owntone.base_url, timeout_s=0.6)
    except Exception as e:
        ready, ready_msg = False, str(e)

    with OWNTONE_RESTART_LOCK:
        payload = {
            "ok": bool(ready),
            "probe": ready_msg,
            "restart": {
                "in_progress": bool(OWNTONE_RESTART_STATE.get("in_progress")),
                "started_at": float(OWNTONE_RESTART_STATE.get("started_at", 0.0)),
                "finished_at": float(OWNTONE_RESTART_STATE.get("finished_at", 0.0)),
                "ok": bool(OWNTONE_RESTART_STATE.get("ok")),
                "message": str(OWNTONE_RESTART_STATE.get("message", "")),
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
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(raw)


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


def _playback_summary_html(snapshot: InputPlaybackSnapshot) -> str:
    total = format_hours(snapshot.total_playback_seconds)
    rows = [f"<div><strong>Playback Hours:</strong> {html.escape(total)}</div>"]

    if snapshot.is_turntable:
        used = format_hours(snapshot.stylus_playback_seconds)
        remaining_txt = "Due now"
        if snapshot.stylus_remaining_seconds is not None and snapshot.stylus_remaining_seconds > 0:
            remaining_txt = format_hours(snapshot.stylus_remaining_seconds)
        rows.append(
            f"<div><strong>Stylus Used:</strong> {html.escape(used)} / {int(snapshot.stylus_life_hours)} h</div>"
        )
        rows.append(
            f"<div><strong>Stylus Remaining:</strong> {html.escape(remaining_txt)}</div>"
        )
        rows.append(
            f"<div><strong>Last Reset:</strong> {html.escape(_format_reset_timestamp(snapshot.last_stylus_reset_at))}</div>"
        )

    if not snapshot.enabled:
        rows.append("<div><strong>Status:</strong> Disabled</div>")
    elif snapshot.active:
        rows.append("<div><strong>Status:</strong> Active now</div>")

    return (
        "<div style='margin-top:0.75rem;padding:0.75rem 0.85rem;border:1px solid #e4e4e4;"
        "border-radius:8px;background:#fafafa;font-size:0.95rem;line-height:1.5;'>"
        + "".join(rows)
        + "</div>"
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
        
def send_json_(handler, code: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def send_owntone_artwork_proxy(handler, state: WebUIState) -> None:
    """Proxy /artwork/... requests to OwnTone so authenticated Web UI sessions can fetch artwork."""
    try:
        cfg = locked_load_config(state.config_path)
        parsed = parse_config(cfg)
        target = parsed.owntone.base_url.rstrip("/") + handler.path
    except Exception as e:
        handler.send_error(500, f"Could not resolve OwnTone artwork URL: {e}")
        return

    try:
        resp = requests.get(target, timeout=5, allow_redirects=False)
    except Exception as e:
        handler.send_error(502, f"Could not reach OwnTone: {e}")
        return

    body = resp.content or b""

    try:
        handler.send_response(resp.status_code)
        content_type = (resp.headers.get("Content-Type") or "application/octet-stream").split(";", 1)[0]
        handler.send_header("Content-Type", content_type)
        cache_control = resp.headers.get("Cache-Control")
        if cache_control:
            handler.send_header("Cache-Control", cache_control)
        etag = resp.headers.get("ETag")
        if etag:
            handler.send_header("ETag", etag)
        last_modified = resp.headers.get("Last-Modified")
        if last_modified:
            handler.send_header("Last-Modified", last_modified)
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        if body:
            handler.wfile.write(body)
    except (BrokenPipeError, ConnectionResetError):
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
    csrf_meta = f"<meta name='csrf-token' content='{html.escape(csrf_token)}'><script>window.__CSRF='{html.escape(csrf_token)}';</script>"

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
          // Server replies JSON for this endpoint (including failures)
          let j = null;
          try {{ j = await r.json(); }} catch (e) {{ j = {{ ok: r.ok }}; }}
          j._http = r.status;
          return j;
        }}

        async function postPinOnly(id, pin) {{
          const r = await fetch('/api/output', {{
            method:'POST',
            credentials:'same-origin',
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
          let j = null;
          try {{ j = await r.json(); }} catch (e) {{ j = {{ ok: r.ok }}; }}
          j._http = r.status;
          return j;
        }}

        async function sendUpdate(id){{
          const c=document.getElementById('output_enabled_'+id), s=document.getElementById('vol_slider_'+id);
          const selected = c?c.checked:false;
          const volume = s?normalizeVolume(parseInt(s.value,10)):0;
          let j = null;
          try {{
            j = await postOutputUpdate(id, selected, volume);
          }} catch (e) {{
            // Network error -> let periodic refresh reconcile UI.
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
        }}

        function onToggleOutput(id){{
          const cb = document.getElementById('output_enabled_' + id);
          if (cb) updateOutputStateVisual(String(id), !!cb.checked);
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
            if (warn) {{
              var txt = String((d && d.playback_banner_text) || '').trim();
              warn.hidden = !txt;
              warn.textContent = txt;
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

            const cb = document.getElementById("output_enabled_" + id);
            const sl = document.getElementById("vol_slider_" + id);

            // Avoid fighting the user while interacting
            if (cb && !isActiveControl(cb)) {{
              cb.checked = !!o.selected;
            }}
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
        <a href="/setup" class="pill-btn" style="flex:1;text-align:center;">Setup</a>
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

    def eq_controls(prefix: str, eq40: float, eq100: float, eq10k: float, input_index: int) -> str:
        return f"""
          <div class="slider-header" style="margin-top:.6rem;align-items:center;">
            <span>Equaliser</span>
            <button type="button"
              class="pill-btn small"
              style="margin-left:auto;padding:0.35rem 0.7rem;"
              onclick="undoEq({input_index})">Reset</button>
          </div>
          <label><div class="slider-header"><span>40Hz:</span><span id="{prefix}_eq_40hz_db_val">{eq40:.0f} dB</span></div>
          <input type="range" min="-10" max="10" step="1" id="{prefix}_eq_40hz_db" name="{prefix}_eq_40hz_db" value="{eq40:.0f}" oninput="syncEq({input_index}, '40hz', this.value)"></label>
          <label><div class="slider-header"><span>Bass:</span><span id="{prefix}_eq_100hz_db_val">{eq100:.0f} dB</span></div>
          <input type="range" min="-10" max="10" step="1" id="{prefix}_eq_100hz_db" name="{prefix}_eq_100hz_db" value="{eq100:.0f}" oninput="syncEq({input_index}, '100hz', this.value)"></label>
          <label><div class="slider-header"><span>Treble:</span><span id="{prefix}_eq_10khz_db_val">{eq10k:.0f} dB</span></div>
          <input type="range" min="-10" max="10" step="1" id="{prefix}_eq_10khz_db" name="{prefix}_eq_10khz_db" value="{eq10k:.0f}" oninput="syncEq({input_index}, '10khz', this.value)"></label>
        """

    def gain_control(prefix: str, gain_db: float, input_index: int) -> str:
        return f"""
          <div class="slider-header" style="margin-top:.6rem;align-items:center;">
            <span>Input Gain</span>
            <button type="button"
              class="pill-btn small"
              style="margin-left:auto;padding:0.35rem 0.7rem;"
              onclick="resetGain({input_index})">Reset</button>
          </div>
          <label><div class="slider-header"><span>Gain:</span><span id="{prefix}_gain_db_val">{gain_db:.0f} dB</span></div>
          <input type="range" min="-10" max="10" step="1" id="{prefix}_gain_db" name="{prefix}_gain_db" value="{gain_db:.0f}" oninput="syncGain({input_index}, this.value)"></label>
        """

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
        settings_wrap_id = f"{prefix}_settings"
        is_turntable = bool(parsed_input.is_turntable)
        threshold_preset = suggested_silence_threshold_dbfs(is_turntable)
        stylus_life_hours = normalize_stylus_life_hours(parsed_input.stylus_life_hours)
        stylus_options_html = "".join(
            f"<option value='{hours}'{' selected' if hours == stylus_life_hours else ''}>{hours} hours</option>"
            for hours in get_stylus_life_options()
        )

        reset_button_html = ""
        if (not initial_setup) and is_turntable:
            reset_button_html = (
                f"<button type='submit' name='stylus_reset_input' value='{input_index}' "
                "class='pill-btn small' style='margin-top:0.65rem;width:100%;' "
                f"onclick=\"return confirm('Mark {html.escape(title)} stylus as changed?');\">"
                "Mark Stylus Changed</button>"
            )

        playback_html = "" if initial_setup else (_playback_summary_html(snapshot) + reset_button_html)

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
                <input type="checkbox" name="{turntable_name}" {'checked' if is_turntable else ''} onchange="syncTurntable({input_index}, this.checked)">
                <span class="switch"></span>
              </label>
              <span>Turntable</span>
            </div>
            <div id="{turntable_note_id}" class="helptext" style="text-align:left;">
              Detection threshold preset: {threshold_preset:.0f} dB
            </div>
            <input type="hidden" id="{threshold_id}" name="{threshold_name}" value="{threshold_preset}">
            <div id="{stylus_wrap_id}" style="display:{'block' if is_turntable else 'none'};">
              <label>Stylus Life:
                <select name="{stylus_life_name}">
                  {stylus_options_html}
                </select>
              </label>
            </div>
            {playback_html}
            {gain_control(prefix, parsed_input.gain_db, input_index) if not initial_setup else ""}
            {eq_controls(prefix, parsed_input.eq_40hz_db, parsed_input.eq_100hz_db, parsed_input.eq_10khz_db, input_index) if not initial_setup else ""}
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
        const savedGain = {{
          1: {parsed.audio1.gain_db:.0f},
          2: {parsed.audio2.gain_db:.0f},
        }};
        const savedEq = {{
          1: {{ eq_40hz_db: {parsed.audio1.eq_40hz_db:.0f}, eq_100hz_db: {parsed.audio1.eq_100hz_db:.0f}, eq_10khz_db: {parsed.audio1.eq_10khz_db:.0f} }},
          2: {{ eq_40hz_db: {parsed.audio2.eq_40hz_db:.0f}, eq_100hz_db: {parsed.audio2.eq_100hz_db:.0f}, eq_10khz_db: {parsed.audio2.eq_10khz_db:.0f} }},
        }};
        const gainTimers = {{}};
        const eqTimers = {{}};
        const eqLiveEnabled = {str(not initial_setup).lower()};
        function onAudio2Toggle(checked){{document.getElementById('audio2_settings').style.display=checked?'block':'none';}}
        function syncVol(v){{document.getElementById('owntone_volume_percent').value=v;document.getElementById('vol_val').textContent=v+'%';}}
        function thresholdPreset(checked){{ return checked ? -45 : -60; }}
        function syncTurntable(inputIndex, checked){{
          const prefix = inputIndex === 1 ? 'audio1' : 'audio2';
          const thresholdId = inputIndex === 1 ? 'audio_silence_threshold' : 'audio2_silence_threshold';
          const note = document.getElementById(prefix + '_turntable_note');
          const wrap = document.getElementById(prefix + '_stylus_wrap');
          const threshold = thresholdPreset(!!checked);
          const hidden = document.getElementById(thresholdId);
          if (hidden) hidden.value = String(threshold);
          if (note) note.textContent = 'Detection threshold preset: ' + String(threshold) + ' dB';
          if (wrap) wrap.style.display = checked ? 'block' : 'none';
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
        function resetGain(inputIndex){{
          if (!eqLiveEnabled) return;
          syncGain(inputIndex, String(savedGain[inputIndex]));
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
        function undoEq(inputIndex){{
          if (!eqLiveEnabled) return;
          const prefix = eqPrefix(inputIndex);
          const saved = savedEq[inputIndex];
          document.getElementById(prefix + '_eq_40hz_db').value = String(saved.eq_40hz_db);
          document.getElementById(prefix + '_eq_100hz_db').value = String(saved.eq_100hz_db);
          document.getElementById(prefix + '_eq_10khz_db').value = String(saved.eq_10khz_db);
          syncEq(inputIndex, '40hz', String(saved.eq_40hz_db));
          syncEq(inputIndex, '100hz', String(saved.eq_100hz_db));
          syncEq(inputIndex, '10khz', String(saved.eq_10khz_db));
        }}
        function syncSil(v){{document.getElementById('sil_val').textContent=v+'s';}}
        window.addEventListener('DOMContentLoaded', () => {{
          const tt1 = document.querySelector('input[name="audio_turntable"]');
          const tt2 = document.querySelector('input[name="audio2_turntable"]');
          if (tt1) syncTurntable(1, !!tt1.checked);
          if (tt2) syncTurntable(2, !!tt2.checked);
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
    outputs = []
    try:
        resp = requests.get(parsed.owntone.base_url.rstrip("/") + "/api/outputs", timeout=3)
        if resp.status_code == 200:
            outputs = resp.json().get("outputs", [])
    except Exception: pass

    # Unified list of names: prefer Owntone's case, append others from hidden list
    output_names = {o.get("name", "").strip() for o in outputs if o.get("name")}
    outputs_by_name = {str(o.get("name","")).strip().casefold(): o for o in outputs if o.get("name")}
    all_names_map = {n.casefold(): n for n in output_names}
    for h in (parsed.webui.hidden_outputs or ()):
        h_s = str(h).strip()
        if h_s and h_s.casefold() not in all_names_map:
            all_names_map[h_s.casefold()] = h_s
            
    all_names = sorted(
        all_names_map.values(),
        key=lambda name: (
            0 if name.casefold() not in hidden_set else 1,
            name.casefold(),
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
    
    valid_airplay_modes = {"auto", "raop", "airplay2"}
    speakers_html = ""
    for i, spk in enumerate(all_names):
        show = spk.casefold() not in hidden_set
        out_obj = outputs_by_name.get(spk.casefold())
        out_id = str(out_obj.get("id", "")).strip() if out_obj else ""

        # Read airplay_mode from the API response when available (PR field).
        # Fall back to conf-file raop_disable for older OwnTone builds.
        if out_obj and "airplay_mode" in out_obj:
            mode_value = str(out_obj.get("airplay_mode") or "").strip().lower()
            current_mode = mode_value if mode_value in valid_airplay_modes else "auto"
        else:
            current_mode = (
                "airplay2"
                if (read_airplay2_for_speaker(spk, OWNTONE_CONF_PATH) or False)
                else "auto"
            )

        # Capability flags — present on new OwnTone builds; absent (None) on older ones.
        # None means unknown: show all options rather than hide valid choices.
        supports_raop = out_obj.get("supports_raop") if out_obj else None
        supports_ap2  = out_obj.get("supports_airplay2") if out_obj else None
        # Treat explicit False as "known unsupported"; None/True as "available".
        show_raop    = supports_raop    is not False
        show_airplay2 = supports_ap2   is not False
        is_airplay_output = show_raop or show_airplay2

        # Offset slider is only shown if the output object includes offset_ms.
        # Saved value (default 0) is stored in autostream.ini [owntone_offsets] by output id.
        offset_html = ""
        if out_obj and ("offset_ms" in out_obj) and out_id:
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
            mode_options = f'<option value="auto"{" selected" if current_mode == "auto" else ""}>Auto</option>'
            if show_raop:
                mode_options += f'<option value="raop"{" selected" if current_mode == "raop" else ""}>AirPlay</option>'
            if show_airplay2:
                mode_options += f'<option value="airplay2"{" selected" if current_mode == "airplay2" else ""}>AirPlay 2</option>'
            mode_html = f"""
            <label style="display:block;margin-bottom:0.5rem;">
              <span>Mode</span>
              <select name="mode_{i}">{mode_options}</select>
            </label>"""
        else:
            mode_html = f'<input type="hidden" name="mode_{i}" value="auto">'

        # Emit the output id for every discovered speaker so the POST handler
        # can call PUT /api/outputs/{id} regardless of which controls are shown.
        outid_html = (
            f'<input type="hidden" name="outid_{i}" value="{html.escape(out_id)}">'
            if out_id else ""
        )

        speakers_html += f"""
          <fieldset><legend>{html.escape(spk)}</legend>
          <input type="hidden" name="spk_{i}" value="{html.escape(spk)}">
          {outid_html}
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

    licence_text = ""
    licence_html = ""
    for fname in ("LICENCE", "LICENSE"):
        try:
            with open(fname, "r", encoding="utf-8") as f:
                licence_text = f.read().strip()
            if licence_text:
                break
        except FileNotFoundError:
            continue
        except Exception:
            # Any other error: don't break About page
            continue
    if licence_text:
        licence_html = f"""
          <fieldset><legend>Licence</legend>
            <div class="licence-pane"><pre class="licence-text">{html.escape(licence_text)}</pre></div>
          </fieldset>
        """

    usage_html = ""
    if parsed is not None:
        usage_rows: list[str] = []
        playback_snapshot = get_playback_snapshot()
        input1_snapshot = playback_snapshot.inputs.get(1) or _fallback_input_snapshot(
            parsed.audio1,
            1,
            enabled=True,
        )
        usage_rows.append(
            "<div style='margin-bottom:1rem;'>"
            f"<strong>Input 1</strong><br>"
            f"{'Turntable' if parsed.audio1.is_turntable else 'Line input'}"
            f"{_playback_summary_html(input1_snapshot)}"
            "</div>"
        )

        input2_snapshot = playback_snapshot.inputs.get(2) or _fallback_input_snapshot(
            parsed.audio2,
            2,
            enabled=parsed.audio2_enabled,
        )
        input2_kind = "Turntable" if parsed.audio2.is_turntable else "Line input"
        if not parsed.audio2_enabled:
            input2_kind += " (currently disabled)"
        usage_rows.append(
            "<div>"
            f"<strong>Input 2</strong><br>"
            f"{html.escape(input2_kind)}"
            f"{_playback_summary_html(input2_snapshot)}"
            "</div>"
        )

        usage_html = (
            "<fieldset><legend>Usage</legend>"
            + "".join(usage_rows)
            + "</fieldset>"
        )

    html_body = textwrap.dedent(f"""\
      <!DOCTYPE html><html><head><meta charset="utf-8">{VIEWPORT_META}
      <title>About</title><style>{STYLE_CSS}
      /* About: render licence text directly in the pane (no scrollable black code box). */
      .licence-pane {{ background: transparent !important; color: inherit !important; max-height: none !important; overflow: visible !important; }}
      .licence-pane .licence-text {{ margin: 0; padding: 0; background: transparent; color: inherit; border: 0; white-space: pre-wrap; overflow-wrap: anywhere; font: inherit; }}
      </style></head><body>{lic_html}{lic_spacer}<div class='container'>{BANNER_HTML}<h1>About</h1>
      <p class="actions" style="margin:1rem 0;"><a href="/" class="pill-btn">← Back</a></p>
      <fieldset><legend>Overview</legend>
          <p><strong>autostream</strong> turns almost any CD player, turntable, cassette deck, or analogue Hi-Fi device into a wireless AirPlay / AirPlay&nbsp;2 multi-room audio source — automatically, once set up.</p>
      </fieldset>
      <fieldset><legend>System (build {html.escape(version)})</legend>
        {storage_html}{sd_html}
      </fieldset>
      {usage_html}
      <fieldset><legend>Copyright</legend>
          <p><strong>autostream</strong> is Copyright &copy; 2025-2026 Lo-tech Systems Limited.</p>
          <p><strong>autostream</strong> and the autostream logo are trademarks of Lo-tech Systems Limited.</p>
          <p><strong>autostream</strong> depends on components provided by the Raspberry Pi OS distribution, including OwnTone and ALSA audio libraries. These components are redistributed under the terms of their respective open-source licences, which are included with Raspberry Pi OS in <code>/usr/share/doc</code>.</p>
          <p>AirPlay and AirPlay&nbsp;2 are trademarks of Apple Inc., registered in the U.S. and other countries. Raspberry Pi is a trademark of Raspberry Pi Ltd. All other trademarks are the property of their respective owners.</p>
      </fieldset>
      {licence_html}
      </div></body></html>
    """)
    body_bytes = html_body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)

def send_logs_page(handler, state: WebUIState) -> None:
    lic_html, lic_spacer = build_top_banner_html()
    try:
        cfg = locked_load_config(state.config_path)
        log_file_cfg = parse_config(cfg).general.log_file
        log_path = _resolve_allowed_log_path(log_file_cfg)
        lines = tail_lines(str(log_path), 100)
        log_content = "\n".join(lines)
    except Exception as e:
        logging.warning("Logs page: denied/failed reading configured log: %s", e)
        log_content = "Error reading logs (access denied or unavailable)."

    html_body = textwrap.dedent(f"""\
      <!DOCTYPE html><html><head><meta charset="utf-8"><title>Logs</title>
      <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
      <style>{STYLE_CSS}
      body {{ font-size: 14px !important; }}
      .log-wrapper {{ background:#111; color:#f5f5f5; padding:0.65rem; border-radius:6px; font-family:monospace; font-size:0.65rem; max-height:60vh; overflow:auto; white-space:pre-wrap; }}
      </style></head><body>{lic_html}{lic_spacer}<div class="container">{BANNER_HTML}<h1>Logs</h1>
      <p class="actions" style="display:flex;justify-content:space-between;"><a href="/setup" class="pill-btn">← Back</a> <a href="/logs" class="pill-btn">↻ Refresh</a></p>
      <div class="log-wrapper" id="logWrapper"><pre>{html.escape(log_content)}</pre></div>
      <p class="actions"><a href="/api/log_file" class="pill-btn" id="logDlBtn" style="display:block;width:100%;text-align:center;box-sizing:border-box;">Download Log Bundle</a></p>
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

def send_log_file(handler, state: WebUIState) -> None:
    try:
        cfg = locked_load_config(state.config_path)
        log_file_cfg = parse_config(cfg).general.log_file
        log_path = _resolve_allowed_log_path(log_file_cfg)
        with log_path.open("rb") as f:
            data = f.read()
        handler.send_response(200)
        handler.send_header("Content-Type", "text/plain; charset=utf-8")
        handler.send_header("Content-Length", str(len(data)))
        handler.send_header("Content-Disposition", f'attachment; filename="{log_path.name}"')
        handler.end_headers()
        handler.wfile.write(data)
    except Exception as e:
        logging.warning("Log download denied/failed: %s", e)
        handler.send_error(403, "Log file access denied")

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
        #   (1) Normal output update: selected/volume ONLY (never send pin here)
        #   (2) PIN verification: pin ONLY (no selected/volume)
        if op == "pin":
            if not pin:
                send_json(handler, 200, {"ok": False, "error": "Missing PIN", "id": str(out_id)})
                return
            out_payload = {"pin": pin}

            logging.info("Owntone API call: PUT %s json=%s", url, out_payload)
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
            out_payload = {"selected": True, "volume": volume}
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
            with open(state.config_path, "w") as f:
                cfg.write(f)
            mark_configured(state.config_path)

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
            if reset_stylus_result.applied and reset_stylus_result.persisted:
                flash_text = f"Input {reset_stylus_input} stylus reset"
            elif reset_stylus_result.applied:
                flash_text = (
                    f"Input {reset_stylus_input} stylus reset, but it could not be saved "
                    "and may be lost after restart"
                )
            else:
                flash_text = (
                    f"Settings saved, but Input {reset_stylus_input} stylus reset failed"
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
        # and hostname changes take effect without disrupting playback.
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
            or new_silence_seconds != old_silence_seconds
        )
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
    def fld(n, d=""): return (form.get(n, []) or [d])[0]
    try:
        cfg = locked_load_config(state.config_path)
        
        # Build a list of speakers from the submitted form.
        # Tuple: (name, show, mode, out_id)  — out_id is "" when not discovered.
        speakers: list[tuple[str, bool, str, str]] = []
        offsets_by_id: dict[str, int] = {}
        valid_airplay_modes = {"auto", "raop", "airplay2"}
        i = 0
        while f"spk_{i}" in form:
            name = fld(f"spk_{i}")
            show = (f"show_{i}" in form)
            mode = fld(f"mode_{i}", "auto").strip().lower()
            if mode not in valid_airplay_modes:
                mode = "auto"
            out_id = fld(f"outid_{i}", "").strip()
            speakers.append((name, show, mode, out_id))

            # Optional per-output offset (only present when UI rendered it)
            if out_id and f"offset_{i}" in form:
                raw_off = fld(f"offset_{i}", "0")
                try:
                    off = int(str(raw_off).strip())
                except Exception:
                    off = 0
                off = max(-2000, min(2000, off))
                offsets_by_id[out_id] = off

            i += 1

        # Deterministic order
        speakers.sort(key=lambda t: t[0].casefold())

        # Update INI denylist
        hidden = [spk for (spk, show, _mode, _oid) in speakers if not show]
        
        if not cfg.has_section("webui"): cfg.add_section("webui")
        if hidden:
            cfg.set("webui", "hidden_outputs", "\n    " + "\n    ".join(hidden))
        else:
            cfg.set("webui", "hidden_outputs", "")

        # Persist Owntone per-output offsets (default 0).
        # Stored by output id as returned by GET /api/outputs.
        if cfg.has_section("owntone_offsets"):
            cfg.remove_section("owntone_offsets")
        cfg.add_section("owntone_offsets")
        for oid, off in sorted(offsets_by_id.items(), key=lambda kv: kv[0]):
            try:
                cfg.set("owntone_offsets", str(oid), str(int(off)))
            except Exception:
                cfg.set("owntone_offsets", str(oid), "0")

        # uncompressed_alac: try API first (takes effect next AirPlay session,
        # no restart needed); fall back to conf write if endpoint unavailable.
        want_uncompressed_audio = ("uncompressed_alac" in form)
        base_url = cfg.get("owntone", "base_url", fallback="http://localhost:3689")
        api_set_uncompressed = owntone_put_setting(
            base_url, "airplay", "uncompressed_alac", want_uncompressed_audio
        )
        if api_set_uncompressed.available and not api_set_uncompressed.ok:
            raise RuntimeError("Could not update OwnTone uncompressed_alac via API")

        restart_required = False

        # start_buffer_ms: restart-required setting; only present when API supports it
        # (slider is hidden otherwise so the field will not be submitted).
        _START_BUFFER_MIN = 300
        _START_BUFFER_MAX = 3500
        _START_BUFFER_STEP = 50
        if "start_buffer_ms" in form:
            try:
                want_buffer = int(fld("start_buffer_ms", "2250").strip())
            except (ValueError, TypeError):
                want_buffer = 2250
            want_buffer = (
                max(_START_BUFFER_MIN, min(_START_BUFFER_MAX,
                    round(want_buffer / _START_BUFFER_STEP) * _START_BUFFER_STEP))
            )
            # Only restart when the value actually changed; read current value first.
            cur_buf_res = owntone_get_setting(base_url, "general", "start_buffer_ms")
            cur_buf = _coerce_owntone_int(cur_buf_res.value) if (cur_buf_res.available and cur_buf_res.ok) else None
            if cur_buf is None or want_buffer != cur_buf:
                api_set_buffer = owntone_put_setting(
                    base_url, "general", "start_buffer_ms", want_buffer
                )
                if api_set_buffer.available and not api_set_buffer.ok:
                    raise RuntimeError("Could not update OwnTone start_buffer_ms via API")
                if api_set_buffer.ok:
                    restart_required = True

        # Set AirPlay mode per speaker.  Always try the API when an output ID is
        # known; owntone_set_airplay_mode returns available=False on 404 so older
        # builds fall through cleanly to the conf-file path (restart required).
        # Older conf-file fallback can only represent:
        #   airplay2 -> raop_disable=true
        #   auto/raop -> raop_disable=false
        conf_airplay_writes: list[tuple[str, bool]] = []
        for spk, _show, mode, out_id in speakers:
            if out_id:
                result = owntone_set_airplay_mode(base_url, out_id, mode)
                if result.available:
                    if not result.ok:
                        raise RuntimeError(
                            f"Could not set AirPlay mode for speaker {spk!r} via API"
                        )
                    # API succeeded — no conf write, no restart needed for this speaker.
                    continue
            # No ID yet, or API returned 404 (older build) — queue conf write.
            conf_airplay_writes.append((spk, mode == "airplay2"))

        # Keep config write + owntone.conf edits together under one lock, so two
        # concurrent saves can't interleave and produce inconsistent results.
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

        # Restart Owntone only when a conf-backed setting actually changed.
        if restart_required:
            # Important on slower hardware like Pi Zero: do restart asynchronously.
            start_owntone_restart_async(state)

        # One-shot success banner (cookie-based) to avoid sticky URLs in iOS A2HS/PWA.
        _set_flash_cookie(handler, "Settings saved", max_age=30)

        next_path = "/setup"
        loc = (
            "/owntone-restarting?next=" + quote(next_path, safe="/?=&")
            if restart_required
            else next_path
        )

        handler.send_response(303)  # See Other (safe after POST)
        handler.send_header("Location", loc)
        handler.send_header("Content-Length", "0")
        handler.end_headers()
    except Exception as e:
        send_owntone_setup_page(handler, state, auth, flash_msg="Save failed", flash_type="error")
