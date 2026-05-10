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
import json

from autostream_config import parse_config
from autostream_core import get_monitor_runtime_info, get_playback_snapshot
from autostream_player_service import get_owntone_runtime_info
from autostream_rpi import get_cpu_temperature_c
from autostream_sysutils import fmt_bytes, get_root_disk_usage, get_sdcard_health_percent

from autostream_webui_common import (
    build_page_html,
    build_top_banner_html,
    get_app_version,
    load_license_text,
    locked_load_config,
    render_license_md,
)

from autostream_webui_state import WebUIState


def _about_detail_header(title: str) -> str:
    return (
        "<div class='eq-page-header'>"
        "<div style='display:flex;align-items:center;gap:0.5rem;'>"
        f"<h1>{html.escape(title)}</h1>"
        "</div>"
        "</div>"
    )


# -----------------------------------------------------------------------------
# Page renderer
# -----------------------------------------------------------------------------

def send_about_page(handler, state: WebUIState) -> None:
    """Render and send the About page."""
    version = get_app_version()
    monitor_info = get_monitor_runtime_info()
    monitor_build_text = monitor_info.monitor_build or "unknown"
    if not monitor_info.connected and monitor_build_text != "unknown":
        monitor_build_text += " (last seen)"
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

    owntone_info = get_owntone_runtime_info(
        parsed.owntone.base_url if parsed else "",
    )
    owntone_build_text = owntone_info.version or "unknown"
    if not owntone_info.connected and owntone_build_text != "unknown":
        owntone_build_text += " (last seen)"

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
        license_inner = f'<div class="about-license-text">{render_license_md(license_text)}</div>'
    else:
        license_inner = "<div class='about-license-text'><p>License text is unavailable.</p></div>"
    license_text_js = json.dumps(license_text or "")

    _extra_css = (
        ".about-license-text { min-height:calc(100svh - 17rem); color:var(--color-text-secondary); font-size:0.95rem; padding-bottom:4.5rem; }\n"
        ".about-license-text p { margin: 0.1rem 0 0.3rem; }\n"
        ".about-license-text h2, .about-license-text h3, .about-license-text h4 { margin: 0.5rem 0 0.15rem; }\n"
        ".about-license-text ul { margin: 0.1rem 0 0.3rem; padding-left: 1.4rem; }\n"
        ".about-license-text hr { margin: 0.5rem 0; border: 0; border-top: 1px solid currentColor; opacity: 0.2; }\n"
        ".about-license-text blockquote { margin: 0 0 1rem; padding: 0.9rem 1rem 1rem; border-radius: 10px; border: 1px solid var(--color-border-card); background: var(--color-surface-raised); color: var(--color-text); }\n"
        ".about-license-text blockquote p:first-child { font-weight: 700; font-size: 1rem; color: var(--color-text-strong); margin: 0 0 0.5rem; }\n"
        ".about-license-text blockquote p { margin: 0 0 0.5rem; }\n"
        ".about-license-text blockquote ul { padding-left: 1.2rem; margin: 0.2rem 0 0; }\n"
        ".about-page { min-height:calc(100svh - 9.5rem); }\n"
        ".about-hero { text-align:center; padding:2.25rem 0 1.5rem; }\n"
        ".about-hero-logo { display:block; width:min(100%, 250px); height:auto; margin:0 auto; }\n"
        ".about-hero-powered-by, .about-hero-version { font-size:0.78rem; letter-spacing:0.12em; text-transform:uppercase; color:var(--color-text-secondary); }\n"
        ".about-hero-powered-by { display:block; margin:2.6rem 0 0.4rem; }\n"
        ".about-hero-partner-logo { display:block; max-height:44px; width:auto; margin:0 auto; }\n"
        ".about-hero-meta { margin:0.45rem 0 0; color:var(--color-text-secondary); }\n"
        ".about-hero-version { margin-top:0.4rem; }\n"
        ".about-slide-viewport { overflow: hidden; width: 100%; }\n"
        ".about-slide-track { display: flex; width: 200%; transition: transform 0.35s cubic-bezier(0.4, 0, 0.2, 1); }\n"
        ".about-slide-track.panel-open { transform: translateX(-50%); }\n"
        ".about-slide-list, .about-slide-detail { width: 50%; flex-shrink: 0; min-width: 0; }\n"
        ".about-slide-list { display:flex; flex-direction:column; min-height:calc(100svh - 12.5rem); }\n"
        ".about-list-cards { margin-top:auto; padding:1rem 0 0; }\n"
        ".about-slide-detail { padding-top:0.25rem; }\n"
        ".about-info-card { margin-bottom:1.25rem; padding:1rem 0.9rem 1.1rem; border-radius:8px; border:1px solid var(--color-border); background:var(--color-surface-raised); }\n"
    )

    # System panel content
    _system_panel_parts = [
        f"<div class='about-info-card'>",
        f"<div class='bar-label'><strong>Autostream Build</strong><span>{html.escape(version)}</span></div>",
        f"<div class='bar-label' style='margin-top:0.65rem;'><strong>Autostream Monitor Build</strong><span>{html.escape(monitor_build_text)}</span></div>",
        f"<div class='bar-label' style='margin-top:0.65rem;'><strong>OwnTone Build</strong><span>{html.escape(owntone_build_text)}</span></div>",
        f"<div class='bar-label' style='margin-top:0.65rem;'><strong>Total Playback Time</strong><span>{total_playback_hours:.1f} hours</span></div>",
        f"<div class='bar-label' style='margin-top:1.3rem;'><strong>CPU Temperature</strong><span>{html.escape(cpu_temp_text)}</span></div>",
    ]
    if storage_html:
        _system_panel_parts.append(f"<div style='margin-top:1.3rem;'>{storage_html}</div>")
    if sd_html:
        _system_panel_parts.append(f"<div style='margin-top:1.3rem;'>{sd_html}</div>")
    _system_panel_parts.append("</div>")
    _system_panel_html = "".join(_system_panel_parts)

    # Copyright panel content
    _copyright_panel_html = (
        f"<p style='margin:0.5rem 0 0.85rem;color:var(--color-text-secondary);font-size:0.95rem;'>"
        f"<strong>autostream</strong> is Copyright &copy; 2025&#8211;2026 Lo-tech Systems Limited. "
        f"autostream and the autostream logo are trademarks of Lo-tech Systems Limited."
        f"</p>"
        f"<p style='margin:0.5rem 0 0.85rem;color:var(--color-text-secondary);font-size:0.95rem;'>"
        f"autostream uses OwnTone and ALSA, redistributed under the terms of their respective "
        f"open-source licences. AirPlay and AirPlay&nbsp;2 are trademarks of Apple Inc. "
        f"All other trademarks are the property of their respective owners."
        f"</p>"
    )

    # License panel content
    _license_panel_html = license_inner

    _dark_mode = parsed.webui.dark_mode if parsed else False
    _autostream_logo_src = (
        "/autostream-logo-centred-dark.png"
        if _dark_mode else
        "/autostream-logo-centred.png"
    )
    _lo_tech_logo_src = "/lo-tech-logo-dark.png" if _dark_mode else "/lo-tech-logo.png"
    _hero_html = (
        f"<div class='about-hero'>"
        f"<img src='{_autostream_logo_src}' alt='autostream' class='about-hero-logo'>"
        f"<p class='about-hero-powered-by'>Powered By</p>"
        f"<img src='{_lo_tech_logo_src}' alt='Lo-tech Systems' class='about-hero-partner-logo'>"
        f"<p class='about-hero-meta about-hero-version'>{html.escape(version)}</p>"
        f"</div>"
    )

    _body_html = (
        f"<div class='about-page'>"
        f"<div class='about-slide-viewport'>"
        f"<div class='about-slide-track' id='aboutSlideTrack'>"
        f"<div class='about-slide-list'>"
        f"{_hero_html}"
        f"<div class='about-list-cards'>"
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
        f"</div>"
        f"<div class='about-slide-detail'>"
        f"<div class='setup-detail-panel' id='about-panel-system'>"
        f"<div class='setup-detail-back'>"
        f"<button type='button' class='pill-btn small' onclick='closeAboutPanel()'>\u2190 Back</button>"
        f"</div>"
        f"{_about_detail_header('System Info')}"
        f"{_system_panel_html}"
        f"</div>"
        f"<div class='setup-detail-panel' id='about-panel-copyright'>"
        f"<div class='setup-detail-back'>"
        f"<button type='button' class='pill-btn small' onclick='closeAboutPanel()'>\u2190 Back</button>"
        f"</div>"
        f"{_about_detail_header('Copyright Info')}"
        f"{_copyright_panel_html}"
        f"</div>"
        f"<div class='setup-detail-panel' id='about-panel-license'>"
        f"<div class='setup-detail-back'>"
        f"<button type='button' class='pill-btn small' onclick='closeAboutPanel()'>\u2190 Back</button>"
        f"<button type='button' class='pill-btn small' id='copyLicenseBtn' onclick='copyLicenseText()' style='margin-left:auto;'>Copy</button>"
        f"</div>"
        f"{_about_detail_header('License Info')}"
        f"{_license_panel_html}"
        f"</div>"
        f"</div>"
        f"</div>"
        f"</div>"
        f"</div>"
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
        f"async function copyLicenseText(){{"
        f"var btn=document.getElementById('copyLicenseBtn');"
        f"var original=btn?btn.textContent:'Copy';"
        f"var text={license_text_js};"
        f"if(!text){{if(btn){{btn.textContent='Unavailable';setTimeout(function(){{btn.textContent=original;}},1200);}}return;}}"
        f"try{{"
        f"if(navigator.clipboard&&navigator.clipboard.writeText){{"
        f"await navigator.clipboard.writeText(text);"
        f"}}else{{"
        f"var ta=document.createElement('textarea');"
        f"ta.value=text;"
        f"ta.setAttribute('readonly','');"
        f"ta.style.position='fixed';"
        f"ta.style.opacity='0';"
        f"document.body.appendChild(ta);"
        f"ta.select();"
        f"document.execCommand('copy');"
        f"document.body.removeChild(ta);"
        f"}}"
        f"if(btn){{btn.textContent='Copied';setTimeout(function(){{btn.textContent=original;}},1200);}}"
        f"}}catch(e){{"
        f"if(btn){{btn.textContent='Failed';setTimeout(function(){{btn.textContent=original;}},1200);}}"
        f"}}"
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
