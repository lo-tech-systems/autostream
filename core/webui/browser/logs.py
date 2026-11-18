#!/usr/bin/env python3
"""webui/browser/logs.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

Page renderer for the /logs route.

Responsibilities:
  - Render the Logs page (log file tail, log-level selector card with API
    integration)
  - Log bundle download
"""

from __future__ import annotations

import html
import logging
import os
import shutil
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path

from autostream_config import get_log_level_options

from autostream_sysutils import tail_lines

from webui import static
from webui.common import (
    build_page_html,
    build_top_banner_html,
)

from webui.session_state import WebUIState
from webui import common


# -----------------------------------------------------------------------------
# Small view helpers
# -----------------------------------------------------------------------------

def _logs_detail_header(title: str) -> str:
    return (
        "<div class='eq-page-header'>"
        "<div style='display:flex;align-items:center;gap:0.5rem;'>"
        f"<h1>{html.escape(title)}</h1>"
        "</div>"
        "</div>"
    )


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

def send_logs_page(handler, state: WebUIState) -> None:
    lic_html, lic_spacer = build_top_banner_html()
    dark_mode = False
    try:
        parsed = common._config_snapshot(state)
        dark_mode = parsed.webui.dark_mode
        log_path = _resolve_allowed_log_path(parsed.general.log_file)
        lines = tail_lines(str(log_path), 100)
        log_content = "\n".join(lines)
    except Exception as e:
        logging.warning("Logs page: denied/failed reading configured log: %s", e)
        log_content = "Error reading logs (access denied or unavailable)."

    csrf_token = getattr(handler, "_csrf_token", "") or ""
    log_level_options_html = "".join(
        f"<option value=\"{html.escape(level)}\">{html.escape(level)}</option>"
        for level in get_log_level_options()
    )

    _body_prefix = (
        "<div id='applyingOverlay' role='status' aria-live='polite'>"
        "<div id='applyingBox'>Applying Change\u2026</div>"
        "</div>"
    )
    _body_html = (
        f"<div class='setup-detail-back'>"
        f"<a href='/about' class='pill-btn small'>&larr; Back</a>"
        f"<a href='/logs' class='pill-btn small' style='margin-left:auto;'>&#8635; Refresh</a>"
        f"</div>"
        f"{_logs_detail_header('Logs')}"
        f"<div class='logs-level-card'>"
        f"<div class='logs-level-row'>"
        f"<label for='log_level'>"
        f"<span>Log Level</span>"
        f"<select id='log_level' name='log_level'>{log_level_options_html}</select>"
        f"</label>"
        f"</div>"
        f"<p id='logLevelMeta' class='logs-level-meta'></p>"
        f"<div class='logs-level-actions'>"
        f"<button type='button' id='logLevelSaveBtn' class='pill-btn'>Save</button>"
        f"<span id='logLevelMsg' class='logs-apply-msg' aria-live='polite'></span>"
        f"</div>"
        f"</div>"
        f"<div class='log-wrapper' id='logWrapper'><pre>{html.escape(log_content)}</pre></div>"
        f"<p class='actions'><a href='/logs/download' class='pill-btn' id='logDlBtn'"
        f" style='display:block;width:100%;text-align:center;box-sizing:border-box;'>"
        f"Download Log Bundle</a></p>"
    )
    _body_suffix = static.script_tag("page/logs.js")
    html_body = build_page_html(
        "Logs",
        _body_html,
        style_files=("page/logs.css",),
        head_extra=static.page_data_island({"csrf_token": csrf_token}),
        body_prefix=_body_prefix,
        body_suffix=_body_suffix,
        lic_html=lic_html,
        lic_spacer=lic_spacer,
        active_tab="about",
        dark_mode=dark_mode,
    )
    common.send_html(handler, 200, html_body)


BUNDLE_LOG_DIR = Path("/var/log/autostream")
BUNDLE_OWNTONE_LOG = Path("/var/log/owntone.log")

# A log's three most recent rotations. Logs rotate with delaycompress, so the
# newest rotation is .1 and older ones are .N.gz; either form is accepted.
_RECENT_ROTATION_SUFFIXES = (".1", ".1.gz", ".2", ".2.gz", ".3", ".3.gz")


def _bundle_members(log_dir: Path, owntone_log: Path) -> list[tuple[Path, str]]:
    """(file, name in the zip) for every log the bundle carries: everything
    in *log_dir*, every rotation included, since the appliance's journal is
    volatile and these files are its history; and *owntone_log* with its
    three most recent rotations."""
    members = [(p, f"autostream/{p.name}") for p in sorted(log_dir.glob("*")) if p.is_file()]
    for p in [owntone_log, *(owntone_log.with_name(owntone_log.name + s) for s in _RECENT_ROTATION_SUFFIXES)]:
        if p.is_file():
            members.append((p, f"owntone/{p.name}"))
    return members


def handle_logs_download(handler) -> None:
    """Build and stream a zip bundle of autostream log files."""
    fname = f"autostream-logs-{datetime.now().strftime('%Y%m%d%H%M%S')}.zip"
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="autostream-logs-", suffix=".zip")
    try:
        os.close(tmp_fd)
        with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for path, arcname in _bundle_members(BUNDLE_LOG_DIR, BUNDLE_OWNTONE_LOG):
                try:
                    zf.write(path, arcname)
                except OSError:
                    pass
        size = os.path.getsize(tmp_path)
        handler.send_response(200)
        handler.send_header("Content-Type", "application/octet-stream")
        handler.send_header("Content-Disposition", f'attachment; filename="{fname}"')
        handler.send_header("Content-Length", str(size))
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("X-Content-Type-Options", "nosniff")
        handler.end_headers()
        with open(tmp_path, "rb") as fh:
            shutil.copyfileobj(fh, handler.wfile, length=65536)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# -----------------------------------------------------------------------------
# Route-table adapters: the calling convention the dispatcher uses (handler,
# state[, body]) in front of the senders above.
# -----------------------------------------------------------------------------


def _route_get_logs(handler, state):
    send_logs_page(handler, state)


def _route_get_logs_download(handler, state):
    handle_logs_download(handler)
