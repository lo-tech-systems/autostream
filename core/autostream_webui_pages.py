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
import requests
from urllib.parse import quote, parse_qs, urlparse
from typing import Optional
from urllib.parse import quote as urlquote

from autostream_core import (
    any_monitor_capturing,
)

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
    OWNTONE_CONF_PATH,
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
CONFIG_IO_LOCK = threading.RLock()

def locked_load_config(path: str):
    """Load config under a global lock to avoid reading partial writes."""
    with CONFIG_IO_LOCK:
        return load_config(path)

# -----------------------------------------------------------------------------
# status message cookie (produces e.g., settings saved banner)
# -----------------------------------------------------------------------------

FLASH_COOKIE_NAME = "autostream_flash"

def _set_flash_cookie(handler, message: str, *, max_age: int = 30) -> None:
    """
    Set a short-lived flash cookie to be consumed (and cleared) on the next GET.
    Stored URL-escaped to keep it cookie-safe.
    """
    val = urlquote(message, safe="")
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

    status_text = "Playing" if is_playing else "Waiting"
    status_class = "playing" if is_playing else "waiting"

    outputs = []
    try:
        resp = requests.get(owntone_base_url.rstrip("/") + "/api/outputs", timeout=3)
        if resp.status_code == 200:
            outputs = resp.json().get("outputs", [])
        else:
            error = error or f"Owntone returned HTTP {resp.status_code}"
    except Exception as e:
        error = error or f"Could not reach Owntone at {owntone_base_url}"

    # Sort: default first
    if default_output_name:
        preferred = [o for o in outputs if o.get("name") == default_output_name]
        others = [o for o in outputs if o.get("name") != default_output_name]
        outputs = preferred + others

    outputs_html = ""
    for out in outputs:
        out_id = out.get("id")
        if out_id is None: continue
        name = out.get("name", f"Output {out_id}")
        selected = bool(out.get("selected", False))
        if str(name).strip().casefold() in hidden_output_names and not selected and name != default_output_name:
            continue

        volume = max(0, min(100, int(out.get("volume", 25))))
        safe_name = html.escape(str(name))
        default = " (default)" if name == default_output_name else ""
        outputs_html += f"""
          <fieldset>
            <legend>{safe_name}{default}</legend>
            <label style="display:flex;align-items:center;gap:0.5rem;margin-top:0.5rem;">
              <input type="checkbox" id="output_enabled_{out_id}"{' checked' if selected else ''} onchange="onToggleOutput('{out_id}')">
              <span>Enabled</span>
            </label>
            <label style="display:block;margin-top:0.5rem;">
              <div class="slider-header"><span>Volume:</span><span id="vol_label_{out_id}" data-volume-label-for="{out_id}"></span></div>
              <input type="range" id="vol_slider_{out_id}" min="0" max="100" value="{volume}" oninput="updateVolumeLabel('{out_id}', this.value)" onchange="onVolumeChange('{out_id}', this.value)">
            </label>
          </fieldset>
        """

    lic_html, lic_spacer = build_top_banner_html(flash_msg=flash_msg)
    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""
    csrf_meta = f"<meta name='csrf-token' content='{html.escape(csrf_token)}'><script>window.__CSRF='{html.escape(csrf_token)}';</script>"

    html_body = textwrap.dedent(f"""\
      <!DOCTYPE html><html><head><meta charset="utf-8">{VIEWPORT_META}
      <title>autostream</title><style>{STYLE_CSS}\n{PIN_MODAL_CSS}</style>{csrf_meta}

      <script>
        function updateVolumeLabel(id,v){{var s=document.getElementById('vol_label_'+id);if(s)s.textContent=v+'%';}}

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
          const volume = s?parseInt(s.value,10):0;
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
            if (c) c.checked = false;

            let nm = '';
            try {{
              const fs = c ? c.closest('fieldset') : null;
              const lg = fs ? fs.querySelector('legend') : null;
              nm = lg ? (lg.textContent || '').trim() : '';
            }} catch (e) {{}}

            while (true) {{
              const pin = await showPinModal(nm || 'this speaker');
              if (!pin) return; // user cancelled

              let jpin = null;
              try {{
                jpin = await postPinOnly(id, pin);
              }} catch (e) {{
                // treat as failure; keep disabled
                if (c) c.checked = false;
                return;
              }}

              if (jpin && jpin.ok) {{
                // PIN accepted -> retry the original enable request (without pin)
                try {{
                  const jen = await postOutputUpdate(id, true, volume);
                  if (jen && jen.ok) {{
                    if (c) c.checked = true;
                    return;
                  }}
                  // If it still asks for PIN, loop again.
                  if (jen && jen.pin_required) {{
                    if (c) c.checked = false;
                    continue;
                  }}
                }} catch (e) {{
                  if (c) c.checked = false;
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

        function onToggleOutput(id){{sendUpdate(id);}}
        function onVolumeChange(id,v){{updateVolumeLabel(id,v);sendUpdate(id);}}
        function refreshStatus(){{
          fetch('/api/status').then(r=>r.json()).then(d=>{{
            var p=document.getElementById('status-pill');if(!p)return;
            p.textContent=d.status_text; p.classList.remove('status-playing','status-waiting');
            p.classList.add('status-'+d.status_class);
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

            if (sl && !isActiveControl(sl)) {{
              const v = String(o.volume);
              if (sl.value !== v) sl.value = v;
              updateVolumeLabel(id, v);
            }}
          }}
        }}

        window.addEventListener('DOMContentLoaded',function(){{
          document.querySelectorAll('[data-volume-label-for]').forEach(s=>{{
            var i=s.getAttribute('data-volume-label-for'), sl=document.getElementById('vol_slider_'+i);
            if(sl)s.textContent=sl.value+'%';
          }});
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
      <div class="container">{BANNER_HTML}
      <div class="pill-row">
        <button type="button"
                class="pill-btn"
                onclick="location.reload();"
                title="Reload page to refresh speakers">
          ↻ Refresh
        </button>
        <span id="status-pill"
              class="pill status-pill status-{status_class}">
          {html.escape(status_text)}
        </span>
      </div>
      {f"<p style='color:red;'>{html.escape(error)}</p>" if error else ""}
      {A2HS_PROMPT_HTML}<p>Toggle speakers on/off and adjust their volume.</p>{outputs_html}
      <p class="actions" style="margin-top:1rem;display:flex;gap:0.75rem;">
        <a href="/about" class="pill-btn" style="flex:1;text-align:center;">About</a>
        <a href="/setup" class="pill-btn" style="flex:1;text-align:center;">Setup</a>
      </p>
      <p style="margin-top:0.25rem; text-align:center;">
        <small>Copyright &copy; 2025 Lo-tech Systems Limited.<br><strong>lo-tech.co.uk/autostream</strong></small>
      </p></div>{A2HS_SCRIPT}</body></html>
    """)
    body_bytes = html_body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)


def send_setup_page(handler, state: WebUIState, auth, saved_ok: bool = False, error: Optional[str] = None, flash_msg: Optional[str] = None) -> None:
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
    
    pcm_devices = state.get_pcm_devices()
    def build_opts(cur):
        opts = ""
        found = False
        for d in pcm_devices:
            sel = " selected" if str(d)==str(cur) else ""
            if sel: found = True
            opts += f"<option value='{html.escape(str(d))}'{sel}>{html.escape(str(d))}</option>"
        if not found and cur:
            opts = f"<option value='{html.escape(str(cur))}' selected>{html.escape(str(cur))} (not detected)</option>" + opts
        return opts

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

    lic_html, lic_spacer = build_top_banner_html(flash_msg=flash_msg)
    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""
    csrf_meta = f"<meta name='csrf-token' content='{html.escape(csrf_token)}'><script>window.__CSRF='{html.escape(csrf_token)}';</script>"

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
        <fieldset><legend>Audio input #1</legend>
          <label>Input device: <select name="audio_capture_device">{build_opts(parsed.audio1.capture_device)}</select></label>
          <label>Format: <select name="audio_arecord_format">
            <option value="dat"{' selected' if parsed.audio1.arecord_format=='dat' else ''}>DAT (48kHz)</option>
            <option value="cd"{' selected' if parsed.audio1.arecord_format=='cd' else ''}>CD (44.1kHz)</option>
          </select></label>
          <label><div class="slider-header"><span>Threshold:</span><span id="audio_silence_threshold_val">{parsed.audio1.silence_threshold_dbfs} dB</span></div>
          <input type="range" min="-90" max="0" value="{parsed.audio1.silence_threshold_dbfs}" oninput="syncThr(1,this.value)">
          <input type="hidden" id="audio_silence_threshold" name="audio_silence_threshold" value="{parsed.audio1.silence_threshold_dbfs}"></label>
        </fieldset>
        <fieldset><legend>Audio input #2 (optional)</legend>
          <label><input type="checkbox" name="audio2_enabled" {'checked' if parsed.audio2_enabled else ''}> Enable</label>
          <label>Input device: <select name="audio2_capture_device">{build_opts(parsed.audio2.capture_device)}</select></label>
          <label>Format: <select name="audio2_arecord_format">
            <option value="dat"{' selected' if parsed.audio2.arecord_format=='dat' else ''}>DAT (48kHz)</option>
            <option value="cd"{' selected' if parsed.audio2.arecord_format=='cd' else ''}>CD (44.1kHz)</option>
          </select></label>
          <label><div class="slider-header"><span>Threshold:</span><span id="audio2_silence_threshold_val">{parsed.audio2.silence_threshold_dbfs} dB</span></div>
          <input type="range" min="-90" max="0" value="{parsed.audio2.silence_threshold_dbfs}" oninput="syncThr(2,this.value)">
          <input type="hidden" id="audio2_silence_threshold" name="audio2_silence_threshold" value="{parsed.audio2.silence_threshold_dbfs}"></label>
        </fieldset>
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
          <label>FFmpeg Output Rate: <select name="ffmpeg_out_rate">
            <option value="44100"{' selected' if str(parsed.ffmpeg.out_rate)=='44100' else ''}>44.1kHz</option>
            <option value="48000"{' selected' if str(parsed.ffmpeg.out_rate)=='48000' else ''}>48.0kHz</option>
          </select></label>
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
        function syncVol(v){{document.getElementById('owntone_volume_percent').value=v;document.getElementById('vol_val').textContent=v+'%';}}
        function syncThr(w,v){{var i=w==1?'audio_silence_threshold':'audio2_silence_threshold';document.getElementById(i).value=v;document.getElementById(i+'_val').textContent=v+' dB';}}
        function syncSil(v){{document.getElementById('sil_val').textContent=v+'s';}}
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
    all_names_map = {n.casefold(): n for n in output_names}
    for h in (parsed.webui.hidden_outputs or ()):
        h_s = str(h).strip()
        if h_s and h_s.casefold() not in all_names_map:
            all_names_map[h_s.casefold()] = h_s
            
    all_names = sorted(all_names_map.values(), key=lambda x: x.casefold())
    
    uncompressed = bool(read_and_set_global_uncompressed_audio(OWNTONE_CONF_PATH))
    
    speakers_html = ""
    for i, spk in enumerate(all_names):
        show = spk.casefold() not in hidden_set
        ap2 = read_airplay2_for_speaker(spk, OWNTONE_CONF_PATH) or False
        speakers_html += f"""
          <fieldset><legend>{html.escape(spk)}</legend>
          <input type="hidden" name="spk_{i}" value="{html.escape(spk)}">
          <label style="display:flex;align-items:center;gap:0.5rem;"><input type="checkbox" name="show_{i}" {'checked' if show else ''}> Show in autostream</label>
          <label style="display:flex;align-items:center;gap:0.5rem;"><input type="checkbox" name="ap2_{i}" {'checked' if ap2 else ''}> Use AirPlay2</label>
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
          <label style="display:flex;align-items:center;gap:0.5rem;"><input type="checkbox" name="uncompressed_alac" {'checked' if uncompressed else ''}> Use uncompressed audio</label>
        </fieldset>
        <p class="actions"><button type="submit">{submit_label}</button></p>
      </form></div></body></html>
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
            <div class="licence-pane">{html.escape(licence_text)}</div>
          </fieldset>
        """

    html_body = textwrap.dedent(f"""\
      <!DOCTYPE html><html><head><meta charset="utf-8">{VIEWPORT_META}
      <title>About</title><style>{STYLE_CSS}</style></head><body>{lic_html}{lic_spacer}<div class='container'>{BANNER_HTML}<h1>About</h1>
      <p class="actions" style="margin:1rem 0;"><a href="/" class="pill-btn">← Back</a></p>
      <fieldset><legend>Overview</legend>
          <p><strong>autostream</strong> turns almost any CD player, turntable, cassette deck, or analogue Hi-Fi device into a wireless AirPlay / AirPlay&nbsp;2 multi-room audio source — automatically, once set up.</p>
      </fieldset>
      <fieldset><legend>System (build {html.escape(version)})</legend>
        {storage_html}{sd_html}
      </fieldset>
      <fieldset><legend>Copyright</legend>
          <p><strong>autostream</strong> is Copyright &copy; 2025 Lo-tech Systems Limited.</p>
          <p><strong>autostream</strong> and the autostream logo are trademarks of Lo-tech Systems Limited.</p>
          <p><strong>autostream</strong> depends on components provided by the Raspberry Pi OS distribution, including FFmpeg and OwnTone. These components are redistributed under the terms of their respective open-source licences, which are included with Raspberry Pi OS in <code>/usr/share/doc</code>.</p>
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

def send_status_json(handler) -> None:
    is_playing = any_monitor_capturing()
    send_json(handler, 200, {
        "playing": is_playing,
        "status_text": "Playing" if is_playing else "Waiting",
        "status_class": "playing" if is_playing else "waiting"
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
        url = parsed.owntone.base_url.rstrip("/") + f"/api/outputs/{out_id}"

        # Two modes:
        #   (1) Normal output update: selected/volume ONLY (never send pin here)
        #   (2) PIN verification: pin ONLY (no selected/volume)
        if op == "pin":
            if not pin:
                send_json(handler, 200, {"ok": False, "error": "Missing PIN", "id": str(out_id)})
                return
            out_payload = {"pin": pin}
        else:
            out_payload = {"selected": selected, "volume": volume}

        # Log the exact Owntone API call so we can debug PIN / selection issues.
        # (Do not log headers/cookies; URL + JSON body are enough for tracing.)
        logging.info("Owntone API call: PUT %s json=%s", url, out_payload)
        resp = requests.put(url, json=out_payload, timeout=3)
        logging.info("Owntone API response: status=%s body=%s",
                     getattr(resp, "status_code", None),
                     (getattr(resp, "text", "") or "").strip())

        # Mode (2): PIN-only verification.
        # OwnTone returns 400 if the PIN was wrong/failed; client should re-prompt.
        if op == "pin":
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

        # Mode (1): normal enable/disable/volume.
        # OwnTone returns HTTP 400 when an output enable requires device PIN verification.
        # We surface this to the Web UI so it can prompt the user and then do PIN-only verification.
        if selected and resp.status_code == 400:
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
                # pin_invalid is only meaningful for op=="pin" now
                "pin_invalid": False,            })
            return

        send_json(handler, 200, {"ok": True, "id": str(out_id)})
    except Exception as e:
        logging.error("Update failed: %s", e)
        send_json(handler, 200, {"ok": False, "error": str(e)})

def handle_setup_post(handler, state: WebUIState, auth, body: str) -> None:
    form = parse_qs(body)
    def fld(n, d=""): return (form.get(n, []) or [d])[0]
    try:
        was_initial_setup = unconfigured(state.config_path)
        cfg = locked_load_config(state.config_path)
        p = parse_config(cfg)
        
        # Hostname
        old_hn = get_system_hostname()
        nh = fld("system_hostname").strip()
        hostname_changed = bool(nh and nh != old_hn)
        if hostname_changed:
            set_system_hostname(nh)

        # Config updates
        if not cfg.has_section("audio1"): cfg.add_section("audio1")
        cfg.set("audio1", "capture_device", fld("audio_capture_device", p.audio1.capture_device))
        cfg.set("audio1", "arecord_format", fld("audio_arecord_format", p.audio1.arecord_format))
        cfg.set("audio1", "silence_threshold", fld("audio_silence_threshold", str(p.audio1.silence_threshold_dbfs)))

        if not cfg.has_section("audio2"): cfg.add_section("audio2")
        cfg.set("audio2", "enabled", "yes" if "audio2_enabled" in form else "no")
        cfg.set("audio2", "capture_device", fld("audio2_capture_device", p.audio2.capture_device))
        cfg.set("audio2", "silence_threshold", fld("audio2_silence_threshold", str(p.audio2.silence_threshold_dbfs)))

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

        if not cfg.has_section("ffmpeg"): cfg.add_section("ffmpeg")
        cfg.set("ffmpeg", "ffmpeg_out_rate", fld("ffmpeg_out_rate", str(p.ffmpeg.out_rate)))

        # Atomicity across concurrent requests/tabs:
        with CONFIG_IO_LOCK:
            with open(state.config_path, "w") as f:
                cfg.write(f)
            mark_configured(state.config_path)        

        # One-shot success banner (cookie-based) to avoid sticky URLs in iOS A2HS/PWA.
        _set_flash_cookie(handler, "Settings saved", max_age=30)

        # Redirect back to / on save
        next_path = "/"

        if hostname_changed:
            host_header = handler.headers.get("Host", "")
            port = host_header.rsplit(":", 1)[1] if ":" in host_header else None
            host_p = f"{nh}.local:{port}" if port else f"{nh}.local"
            redirect_url = f"{handler.headers.get('X-Forwarded-Proto', 'http')}://{host_p}{next_path}"

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
        
        from autostream_webui import restart_self_soon
        restart_self_soon(1)
    except Exception as e:
        send_setup_page(handler, state, auth, flash_msg="Save failed", flash_type="error")

def handle_owntone_setup_post(handler, state: WebUIState, auth, body: str) -> None:
    form = parse_qs(body)
    def fld(n, d=""): return (form.get(n, []) or [d])[0]
    try:
        was_initial_setup = unconfigured(state.config_path)
        cfg = locked_load_config(state.config_path)
        
        # Build a list of speakers from the submitted form.
        speakers: list[tuple[str, bool, bool]] = []
        i = 0
        while f"spk_{i}" in form:
            name = fld(f"spk_{i}")
            show = (f"show_{i}" in form)
            ap2 = (f"ap2_{i}" in form)
            speakers.append((name, show, ap2))
            i += 1

        # Deterministic order
        speakers.sort(key=lambda t: t[0].casefold())

        # Update INI denylist
        hidden = [spk for (spk, show, _ap2) in speakers if not show]
        
        if not cfg.has_section("webui"): cfg.add_section("webui")
        if hidden:
            cfg.set("webui", "hidden_outputs", "\n    " + "\n    ".join(hidden))
        else:
            cfg.set("webui", "hidden_outputs", "")
            
        # Keep config write + owntone.conf edits together under one lock, so two
        # concurrent saves can't interleave and produce inconsistent results.
        with CONFIG_IO_LOCK:
            with open(state.config_path, "w", encoding="utf-8") as f:
                cfg.write(f)

            # Update owntone.conf
            for spk, _show, ap2 in speakers:
                write_airplay2_for_speaker(spk, ap2, OWNTONE_CONF_PATH)

            want_uncompressed_audio = ("uncompressed_alac" in form)
            write_and_set_global_uncompressed_audio(
                enabled=want_uncompressed_audio,
                conf_path=OWNTONE_CONF_PATH,
            )

        # Restart Owntone asynchronously so we don't hold the POST open during restart
        # (important when running behind nginx on slower hardware like Pi Zero).
        start_owntone_restart_async(state)

        # One-shot success banner (cookie-based) to avoid sticky URLs in iOS A2HS/PWA.
        _set_flash_cookie(handler, "Settings saved", max_age=30)

       # Redirect immediately to a restarting page which polls /api/owntone/ready.
        next_path = "/setup"
        loc = "/owntone-restarting?next=" + quote(next_path, safe="/?=&")

        handler.send_response(303)  # See Other (safe after POST)
        handler.send_header("Location", loc)
        handler.send_header("Content-Length", "0")
        handler.end_headers()
    except Exception as e:
        send_owntone_setup_page(handler, state, auth, flash_msg="Save failed", flash_type="error")
