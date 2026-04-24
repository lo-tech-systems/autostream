#!/usr/bin/env python3
"""autostream_webui_page_logs.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

Page renderer and POST handler for the /logs route.

Responsibilities:
  - Render the Logs page (log file tail, log-level selector card)
  - Handle log-level form submission (save config, apply live, restart
    OwnTone if required)
"""

from __future__ import annotations

import html
import logging
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs

from autostream_config import (
    CONFIG_IO_LOCK,
    get_log_level_options,
    load_config,
    normalize_log_level,
    parse_config,
)

from autostream_core import update_live_platform_log_level

from autostream_player_service import save_log_level

from autostream_sysutils import tail_lines

from autostream_webui_assets import (
    BANNER_HTML,
)

from autostream_webui_common import (
    _set_flash_cookie,
    build_page_html,
    build_top_banner_html,
    locked_load_config,
)

from autostream_webui_state import WebUIState


# -----------------------------------------------------------------------------
# Privileged log path allowlist hardening
#
# Log files served via this page are restricted to /var/log/autostream/ to
# prevent path-traversal reads of arbitrary files on the host.
# -----------------------------------------------------------------------------

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
# Page renderer
# -----------------------------------------------------------------------------

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

    _extra_css = (
        "body { font-size: 14px !important; }\n"
        ".log-wrapper { background:#111; color:#f5f5f5; padding:0.65rem; border-radius:6px;"
        " font-family:monospace; font-size:0.65rem; max-height:60vh; overflow:auto; white-space:pre-wrap; }\n"
        "#applyingOverlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,0.45);"
        " z-index:9999; align-items:center; justify-content:center; }\n"
        "#applyingOverlay.visible { display:flex; }\n"
        "#applyingBox { background:#fff; color:#222; padding:1.4rem 2rem; border-radius:10px;"
        " font-size:1.1rem; font-weight:600; box-shadow:0 4px 24px rgba(0,0,0,0.25); }"
    )
    _body_prefix = (
        "<div id='applyingOverlay' role='status' aria-live='polite'>"
        "<div id='applyingBox'>Applying Change\u2026</div>"
        "</div>"
    )
    _body_html = (
        f"{BANNER_HTML}<h1>Logs</h1>"
        f"<p class='actions' style='display:flex;justify-content:flex-end;'>"
        f"<a href='/logs' class='pill-btn small'>\u21bb Refresh</a></p>"
        f"<form method='post' action='/logs' id='logLevelForm' onsubmit='showApplying()'>"
        f"<input type='hidden' name='csrf_token' value='{html.escape(csrf_token)}'>"
        f"<fieldset><legend>Log Level</legend>"
        f"<label for='log_level'>Log Level"
        f"<select id='log_level' name='log_level'>{log_level_options_html}</select>"
        f"</label>"
        f"<button type='submit' class='pill-btn' style='margin-top:0.75rem;'>Save</button>"
        f"</fieldset>"
        f"</form>"
        f"<div class='log-wrapper' id='logWrapper'><pre>{html.escape(log_content)}</pre></div>"
        f"<p class='actions'><a href='/offline/download-logs' class='pill-btn' id='logDlBtn'"
        f" style='display:block;width:100%;text-align:center;box-sizing:border-box;'>"
        f"Download Log Bundle</a></p>"
    )
    _body_suffix = """\
<script>
  function showApplying() {
    var overlay = document.getElementById('applyingOverlay');
    if (overlay) overlay.classList.add('visible');
  }
  window.addEventListener('load', function() {
    var w = document.getElementById('logWrapper');
    var b = document.getElementById('logDlBtn');

    // Hide "Download Log Bundle" on iPhone when running as a PWA (standalone)
    var ua = navigator.userAgent || "";
    var isIPhone = /iPhone/.test(ua);
    var isStandalone =
      (window.navigator && window.navigator.standalone === true) ||
      (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches);

    if (b && isIPhone && isStandalone) {
      b.style.display = "none";
    }

    // Keep existing width-matching behaviour if still visible
    if (w && b && b.style.display !== "none") {
      b.style.width = w.offsetWidth + 'px';
    }
  });
</script>"""
    html_body = build_page_html(
        "Logs",
        _body_html,
        extra_css=_extra_css,
        body_prefix=_body_prefix,
        body_suffix=_body_suffix,
        lic_html=lic_html,
        lic_spacer=lic_spacer,
        active_tab="logs",
    )
    body_bytes = html_body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)


# -----------------------------------------------------------------------------
# POST handler
# -----------------------------------------------------------------------------

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
        player_setting_res = None
        if parsed.owntone.base_url:
            player_setting_res = save_log_level(
                parsed.owntone.base_url,
                applied_log_level,
            )

        flash_text = (
            "Log level saved"
            if monitor_updated
            else "Log level saved, but monitor runtime log level was not updated"
        )
        player_needs_attention = (
            player_setting_res is not None
            and not player_setting_res.ok
            and not player_setting_res.unsupported
        )
        if player_needs_attention:
            flash_text = "Log level saved, but OwnTone was not updated"
            if not monitor_updated:
                flash_text += " and monitor runtime update failed"
        elif player_setting_res is not None and player_setting_res.unsupported and not monitor_updated:
            flash_text = "Log level saved, but monitor runtime log level was not updated"

        _set_flash_cookie(handler, flash_text, max_age=30)
        handler.send_response(302)
        handler.send_header("Location", "/logs")
        handler.end_headers()
    except Exception:
        logging.exception("Failed saving log level from Logs page.")
        send_logs_page(handler, state, flash_msg="Save failed", flash_type="error")
