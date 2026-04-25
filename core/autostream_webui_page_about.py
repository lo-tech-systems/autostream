#!/usr/bin/env python3
"""autostream_webui_page_about.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Page renderer for the /about route.

Responsibilities:
  - Render the About page: system information (build version, total playback
    hours, CPU temperature, disk usage, SD card health), and copyright/license.
  - Provides a Logs button to reach the log viewer.

Shared helpers (imported from autostream_webui_common):
  - get_app_version  -- read installed application version
  - load_license_text -- read the LICENSE / LICENCE file
  - render_license_md -- convert the LICENSE Markdown to HTML
"""

from __future__ import annotations

import html

from autostream_config import parse_config
from autostream_core import get_playback_snapshot
from autostream_rpi import get_cpu_temperature_c
from autostream_sysutils import fmt_bytes, get_root_disk_usage, get_sdcard_health_percent

from autostream_webui_assets import (
    BANNER_HTML,
)

from autostream_webui_common import (
    build_page_html,
    build_top_banner_html,
    get_app_version,
    load_license_text,
    locked_load_config,
    render_license_md,
)

from autostream_webui_state import WebUIState



# -----------------------------------------------------------------------------
# Page renderer
# -----------------------------------------------------------------------------

def send_about_page(handler, state: WebUIState) -> None:
    """Render and send the About page."""
    version = get_app_version()
    lic_html, lic_spacer = build_top_banner_html()

    # Playback totals across both inputs (indices 1 and 2).
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

    # Config is read defensively; the page degrades gracefully if it fails.
    parsed = None
    try:
        parsed = parse_config(locked_load_config(state.config_path))
    except Exception:
        parsed = None

    # Disk usage bar.
    du = get_root_disk_usage()
    storage_html = ""
    if du:
        tot, usd, fre = du
        pct = (usd / tot) * 100 if tot else 0
        disk_status = "healthy" if pct < 60 else ("warning" if pct < 80 else "critical")
        storage_html = (
            f"<div class='bar-label'><strong>Disk Usage:</strong> {pct:.1f}%</div>"
            f"<div class='storage-bar'><div class='used' style='width:{pct}%;' data-status='{disk_status}'></div></div>"
            f"<div class='storage-meta'>Free: {fmt_bytes(fre)} / {fmt_bytes(tot)}</div>"
        )

    # SD card health bar (only present when the platform reports it).
    sd_health = get_sdcard_health_percent()
    sd_html = ""
    if sd_health is not None:
        sd_status = "critical" if sd_health <= 10 else ("warning" if sd_health <= 30 else "healthy")
        sd_html = (
            f"<div class='bar-label'><strong>SD Health:</strong> {sd_health}%</div>"
            f"<div class='storage-bar'><div class='used' style='width:{sd_health}%;' data-status='{sd_status}'></div></div>"
        )

    license_text = load_license_text()
    if license_text:
        license_inner = f'<div class="licence-pane">{render_license_md(license_text)}</div>'
    else:
        license_inner = "<p>License text is unavailable.</p>"

    _extra_css = (
        ".licence-pane p { margin: 0.1rem 0 0.3rem; }\n"
        ".licence-pane h2, .licence-pane h3 { margin: 0.5rem 0 0.15rem; }\n"
        ".licence-pane ul { margin: 0.1rem 0 0.3rem; padding-left: 1.4rem; }\n"
        ".licence-pane hr { margin: 0.5rem 0; border: 0; border-top: 1px solid currentColor; opacity: 0.2; }\n"
        ".about-slide-viewport { overflow: hidden; width: 100%; }\n"
        ".about-slide-track { display: flex; width: 200%; transition: transform 0.35s cubic-bezier(0.4, 0, 0.2, 1); }\n"
        ".about-slide-track.panel-open { transform: translateX(-50%); }\n"
        ".about-slide-list, .about-slide-detail { width: 50%; flex-shrink: 0; min-width: 0; }\n"
    )

    # System panel content
    _system_panel_html = (
        f"<fieldset><legend>System (build {html.escape(version)})</legend>"
        f"<div class='bar-label'><strong>Total Playback Time:</strong> {total_playback_hours:.1f} hours</div>"
        f"<div class='bar-label'><strong>CPU temperature:</strong> {html.escape(cpu_temp_text)}</div>"
        f"{storage_html}{sd_html}"
        f"</fieldset>"
    )

    # Copyright panel content
    _copyright_panel_html = (
        f"<fieldset><legend>Copyright</legend>"
        f"<p><strong>autostream</strong> is Copyright &copy; 2025&#8211;2026 Lo-tech Systems Limited."
        f" autostream and the autostream logo are trademarks of Lo-tech Systems Limited.</p>"
        f"<p>autostream uses OwnTone and ALSA, redistributed under the terms of their respective"
        f" open-source licences. AirPlay and AirPlay&nbsp;2 are trademarks of Apple Inc."
        f" All other trademarks are the property of their respective owners.</p>"
        f"</fieldset>"
    )

    # License panel content
    _license_panel_html = (
        f"<fieldset><legend>License</legend>"
        f"{license_inner}"
        f"</fieldset>"
    )

    _dark_mode = parsed.webui.dark_mode if parsed else False
    _logo_src = "/lo-tech-logo-dark.png" if _dark_mode else "/lo-tech-logo.png"
    _powered_by_html = (
        f"<div style='padding:4rem 0 3rem;text-align:center;'>"
        f"<p style='font-size:0.95rem;color:#fff;margin:0 0 0.5rem;'>POWERED BY</p>"
        f"<img src='{_logo_src}' alt='Lo-tech Systems' style='max-height:40px;width:auto;'>"
        f"</div>"
    )

    _body_html = (
        f"{BANNER_HTML}"
        f"<div style='padding-top:4rem;'>"
        f"<div class='about-slide-viewport'>"
        f"<div class='about-slide-track' id='aboutSlideTrack'>"
        f"<div class='about-slide-list'>"
        f"<div class='setup-list-card' onclick='openAboutPanel(\"system\")'>"
        f"<div class='setup-list-card-body'><span class='setup-list-card-title'>System</span></div>"
        f"<span class='setup-list-chevron'>\u203a</span>"
        f"</div>"
        f"<div class='setup-list-card' onclick='openAboutPanel(\"copyright\")'>"
        f"<div class='setup-list-card-body'><span class='setup-list-card-title'>Copyright</span></div>"
        f"<span class='setup-list-chevron'>\u203a</span>"
        f"</div>"
        f"<div class='setup-list-card' onclick='openAboutPanel(\"license\")'>"
        f"<div class='setup-list-card-body'><span class='setup-list-card-title'>License</span></div>"
        f"<span class='setup-list-chevron'>\u203a</span>"
        f"</div>"
        f"<a href='/logs' class='setup-list-card' style='text-decoration:none;'>"
        f"<div class='setup-list-card-body'><span class='setup-list-card-title'>Logs</span></div>"
        f"<span class='setup-list-chevron'>\u203a</span>"
        f"</a>"
        f"</div>"
        f"<div class='about-slide-detail'>"
        f"<div class='setup-detail-panel' id='about-panel-system'>"
        f"<div class='setup-detail-back'>"
        f"<button type='button' class='pill-btn small' onclick='closeAboutPanel()'>\u2190 Back</button>"
        f"</div>"
        f"{_system_panel_html}"
        f"</div>"
        f"<div class='setup-detail-panel' id='about-panel-copyright'>"
        f"<div class='setup-detail-back'>"
        f"<button type='button' class='pill-btn small' onclick='closeAboutPanel()'>\u2190 Back</button>"
        f"</div>"
        f"{_copyright_panel_html}"
        f"</div>"
        f"<div class='setup-detail-panel' id='about-panel-license'>"
        f"<div class='setup-detail-back'>"
        f"<button type='button' class='pill-btn small' onclick='closeAboutPanel()'>\u2190 Back</button>"
        f"</div>"
        f"{_license_panel_html}"
        f"</div>"
        f"</div>"
        f"</div>"
        f"</div>"
        f"</div>"
        f"{_powered_by_html}"
        f"<script>"
        f"function openAboutPanel(name){{"
        f"document.querySelectorAll('.setup-detail-panel').forEach(function(p){{p.classList.remove('active');}});"
        f"var panel=document.getElementById('about-panel-'+name);"
        f"if(panel)panel.classList.add('active');"
        f"document.getElementById('aboutSlideTrack').classList.add('panel-open');"
        f"window.scrollTo(0,0);"
        f"}}"
        f"function closeAboutPanel(){{"
        f"document.querySelectorAll('.setup-detail-panel').forEach(function(p){{p.classList.remove('active');}});"
        f"document.getElementById('aboutSlideTrack').classList.remove('panel-open');"
        f"window.scrollTo(0,0);"
        f"}}"
        f"</script>"
    )
    html_body = build_page_html(
        "About",
        _body_html,
        extra_css=_extra_css,
        lic_html=lic_html,
        lic_spacer=lic_spacer,
        active_tab="about",
        dark_mode=_dark_mode,
    )
    body_bytes = html_body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)
