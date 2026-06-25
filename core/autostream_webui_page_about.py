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
import logging
import math
import subprocess
from typing import Optional

from autostream_core import get_monitor_runtime_info, get_playback_snapshot
from autostream_player_service import get_owntone_runtime_info
from autostream_rpi import get_cpu_temperature_c
from autostream_sysutils import fmt_bytes, get_root_disk_usage, get_sdcard_health_percent
from track_id.vibra_shazam import get_vibra_runtime_info

from autostream_webui_common import (
    _config_snapshot,
    build_page_html,
    build_top_banner_html,
    get_app_version,
    load_license_text,
    render_license_md,
)

from autostream_webui_state import WebUIState

_log = logging.getLogger(__name__)


# Fixed service list; order and membership are immutable constants — never
# derived from request data.
_SERVICES = (
    ("autostream.service",              "Autostream"),
    ("autostream_monitor.service",      "Audio Monitor"),
    ("autostream_wifi_watcher.service", "Wi-Fi Watcher"),
    ("owntone.service",                 None),      # label selected at runtime
    ("vibra-mini.service",              "Vibra Mini"),
    ("nginx.service",                   "NGINX"),
)


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
    lic_html, lic_spacer = build_top_banner_html()

    # Config is read defensively; the page degrades gracefully if it fails.
    parsed = None
    try:
        parsed = _config_snapshot(state)
    except Exception:
        parsed = None

    license_text = load_license_text()
    if license_text:
        license_inner = f'<div class="about-license-text">{render_license_md(license_text)}</div>'
    else:
        license_inner = "<div class='about-license-text'><p>License text is unavailable.</p></div>"
    license_text_js = json.dumps(license_text or "")

    # Pre-render service rows from the fixed service list.  The OwnTone label
    # defaults to "OwnTone" here; JS updates it to "OwnTone Mini" if needed.
    _svc_rows_html = "".join(
        f"<div class='about-svc-row' data-service-unit='{html.escape(unit)}'>"
        f"<span class='about-svc-label'>{html.escape(label if label is not None else 'OwnTone')}</span>"
        f"<span class='about-svc-state about-svc-loading'>Loading...</span>"
        f"</div>"
        for unit, label in _SERVICES
    )

    # System Info panel: static placeholders with stable DOM IDs.
    # All values are populated by the DOMContentLoaded fetch below; no live
    # probes run during page rendering.  Disk and SD sections start hidden and
    # become visible only when the API reports available=true.
    _system_panel_html = (
        "<div aria-live='polite'>"
        "<div class='about-info-card'>"
        "<div class='bar-label'><strong>autostream Build</strong>"
        "<span id='aboutBuildAutostream'>Loading...</span></div>"
        "<div class='bar-label' style='margin-top:0.65rem;'>"
        "<strong>Total Playback Time</strong>"
        "<span id='aboutPlaybackHours'>Loading...</span></div>"
        "<div class='bar-label' style='margin-top:0.65rem;'>"
        "<strong>CPU Temperature</strong>"
        "<span id='aboutCpuTemperature'>Loading...</span></div>"
        "<div id='aboutDiskSection' style='display:none;margin-top:1.3rem;'>"
        "<div id='aboutDiskLabel' class='bar-label'></div>"
        "<div class='storage-bar'><div id='aboutDiskBar' class='used' style='width:0%'></div></div>"
        "<div id='aboutDiskMeta' class='storage-meta'></div>"
        "</div>"
        "<div id='aboutSdSection' style='display:none;margin-top:1.3rem;'>"
        "<div id='aboutSdLabel' class='bar-label'></div>"
        "<div class='storage-bar'><div id='aboutSdBar' class='used' style='width:0%'></div></div>"
        "</div>"
        "</div>"
        "<div class='about-info-card'>"
        "<h3 class='about-services-heading'>Services</h3>"
        f"<div id='aboutServices'>{_svc_rows_html}</div>"
        "</div>"
        "</div>"
    )

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
        ".about-services-heading { margin:0 0 0.6rem; font-size:0.95rem; font-weight:600; color:var(--color-text-strong); }\n"
        ".about-svc-row { display:flex; align-items:center; justify-content:space-between; padding:0.4rem 0; border-bottom:1px solid var(--color-border); }\n"
        ".about-svc-row:last-child { border-bottom:none; }\n"
        ".about-svc-label { font-size:0.9rem; }\n"
        ".about-svc-state { font-size:0.8rem; font-weight:600; padding:0.15rem 0.5rem; border-radius:4px; }\n"
        ".about-svc-state[data-state='ok'] { color:var(--color-status-success); background:color-mix(in srgb,var(--color-status-success) 15%,transparent); }\n"
        ".about-svc-state[data-state='failed'] { color:var(--color-status-danger); background:color-mix(in srgb,var(--color-status-danger) 15%,transparent); }\n"
        ".about-svc-loading { color:var(--color-text-secondary); font-weight:400; font-size:0.85rem; }\n"
    )

    # DOMContentLoaded fetch: populates System Info and Services from /api/about/system.
    # Uses textContent throughout — never innerHTML.
    _fetch_js = (
        "(function(){"
        "function _s(id,t){var e=document.getElementById(id);if(e)e.textContent=t;}"
        "function _gib(b){return(b/1073741824).toFixed(1)+' GB';}"
        "function _clamp(v){var n=Number(v);return isNaN(n)?0:Math.max(0,Math.min(100,n));}"
        "var _VS={healthy:1,warning:1,critical:1};"
        "function _ss(s){return _VS[s]?String(s):'healthy';}"
        "function _fail(){"
        "['aboutBuildAutostream','aboutPlaybackHours','aboutCpuTemperature'].forEach(function(id){"
        "var e=document.getElementById(id);"
        "if(e&&e.textContent==='Loading...')e.textContent='Unavailable';});"
        "document.querySelectorAll('#aboutServices [data-service-unit] .about-svc-state')"
        ".forEach(function(e){"
        "if(e.textContent==='Loading...'){"
        "e.textContent='Failed';e.setAttribute('data-state','failed');"
        "e.classList.remove('about-svc-loading');}});}"
        "document.addEventListener('DOMContentLoaded',function(){"
        "fetch('/api/about/system',{cache:'no-store',headers:{'Accept':'application/json'}})"
        ".then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();})"
        ".then(function(d){"
        "if(d.ok!==true)throw new Error('ok!=true');"
        "var b=d.builds||{};"
        "_s('aboutBuildAutostream',String(b.autostream||'unknown'));"
        "_s('aboutPlaybackHours',typeof d.playback_hours==='number'"
        "?d.playback_hours.toFixed(1)+' hours':'Unavailable');"
        "_s('aboutCpuTemperature',typeof d.cpu_temperature_c==='number'"
        "?d.cpu_temperature_c.toFixed(1)+'°C':'Unavailable');"
        "var dk=d.disk||{};"
        "if(dk.available===true){"
        "var dp=_clamp(dk.used_percent);"
        "_s('aboutDiskLabel','Disk Usage: '+dp.toFixed(1)+'%');"
        "var db=document.getElementById('aboutDiskBar');"
        "if(db){db.style.width=dp+'%';db.setAttribute('data-status',_ss(dk.status));}"
        "_s('aboutDiskMeta','Free: '"
        "+_gib(typeof dk.free_bytes==='number'?dk.free_bytes:0)"
        "+'  /  '"
        "+_gib(typeof dk.total_bytes==='number'?dk.total_bytes:0));"
        "var ds=document.getElementById('aboutDiskSection');if(ds)ds.style.display='';}"
        "var sd=d.sd_card||{};"
        "if(sd.available===true){"
        "var sp=_clamp(sd.health_percent);"
        "_s('aboutSdLabel','SD Health: '+Math.round(sp)+'%');"
        "var sb=document.getElementById('aboutSdBar');"
        "if(sb){sb.style.width=sp+'%';sb.setAttribute('data-status',_ss(sd.status));}"
        "var ss=document.getElementById('aboutSdSection');if(ss)ss.style.display='';}"
        "var svcs=Array.isArray(d.services)?d.services:[];"
        "document.querySelectorAll('#aboutServices [data-service-unit]').forEach(function(row){"
        "var unit=row.getAttribute('data-service-unit');"
        "var svc=null;"
        "for(var i=0;i<svcs.length;i++){if(svcs[i].unit===unit){svc=svcs[i];break;}}"
        "if(!svc)return;"
        "var lbl=row.querySelector('.about-svc-label');"
        "if(lbl&&svc.label)lbl.textContent=String(svc.label);"
        "var st=row.querySelector('.about-svc-state');"
        "if(st){var ok=svc.state==='ok';"
        "st.textContent=ok?(svc.version?String(svc.version)+' - OK':'OK'):'Failed';"
        "st.setAttribute('data-state',ok?'ok':'failed');"
        "st.classList.remove('about-svc-loading');}});})"
        ".catch(function(){_fail();});"
        "});"
        "}());"
    )

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
        f"<script>{_fetch_js}</script>"
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


# -----------------------------------------------------------------------------
# /api/about/system — asynchronous System Info JSON endpoint
# -----------------------------------------------------------------------------

def send_about_system_json(handler) -> None:
    """Collect and send the JSON payload for /api/about/system."""
    from autostream_webui_api import send_json
    try:
        payload = _collect_system_info()
        send_json(handler, 200, payload)
    except Exception:
        _log.exception("about/system: unexpected collector error")
        send_json(handler, 500, {"ok": False, "error": "system_info_unavailable"})


def _build_text(version: str, connected: bool) -> str:
    """Format a build/version string, appending '(last seen)' when disconnected."""
    v = str(version or "").strip() or "unknown"
    if not connected and v != "unknown":
        return v + " (last seen)"
    return v


def _collect_system_info() -> dict:
    """Collect all System Info fields.  Partial failures degrade individual fields."""
    # 1. Autostream version (cached, immutable for process lifetime)
    try:
        autostream_version = get_app_version()
    except Exception:
        autostream_version = "unknown"

    # 2. Monitor build — read in-memory snapshot, no protocol I/O
    try:
        monitor_info = get_monitor_runtime_info()
        monitor_build = _build_text(monitor_info.monitor_build, monitor_info.connected)
    except Exception:
        monitor_build = "unknown"

    # 3. OwnTone build — read in-memory snapshot, no OwnTone HTTP traffic
    owntone_build = "unknown"
    owntone_backend_id = "unknown"
    try:
        owntone_info = get_owntone_runtime_info(refresh_if_stale=False)
        owntone_build = _build_text(owntone_info.version, owntone_info.connected)
        owntone_backend_id = str(owntone_info.backend_id or "").strip() or "unknown"
    except Exception:
        pass

    # 4. Vibra Mini build — read in-memory snapshot, no socket I/O
    try:
        vibra_info = get_vibra_runtime_info()
        vibra_build = _build_text(vibra_info.version, vibra_info.connected)
    except Exception:
        vibra_build = "unknown"

    # 5. Playback totals across inputs 1 and 2
    playback_hours = 0.0
    try:
        playback_snapshot = get_playback_snapshot()
        total_seconds = sum(
            int(snap.total_playback_seconds)
            for idx, snap in playback_snapshot.inputs.items()
            if int(idx) in (1, 2)
        )
        playback_hours = round(total_seconds / 3600.0, 1)
    except Exception:
        pass

    # 6. CPU temperature (on-demand, cheap sysfs read)
    cpu_temp_c: Optional[float] = None
    try:
        t = get_cpu_temperature_c()
        if t is not None and math.isfinite(float(t)):
            cpu_temp_c = float(t)
    except Exception:
        pass

    # 7. Root disk usage (on-demand)
    disk: dict = {"available": False}
    try:
        du = get_root_disk_usage()
        if du is not None:
            tot, usd, fre = du
            pct = round((usd / tot) * 100.0, 1) if tot else 0.0
            pct = max(0.0, min(100.0, pct))
            status = "healthy" if pct < 60 else ("warning" if pct < 80 else "critical")
            disk = {
                "available": True,
                "total_bytes": tot,
                "free_bytes": fre,
                "used_percent": pct,
                "status": status,
            }
    except Exception:
        pass

    # 8. SD card health (on-demand file read)
    sd_card: dict = {"available": False}
    try:
        sd_health = get_sdcard_health_percent()
        if sd_health is not None:
            sd_status = (
                "critical" if sd_health <= 10
                else ("warning" if sd_health <= 30 else "healthy")
            )
            sd_card = {
                "available": True,
                "health_percent": sd_health,
                "status": sd_status,
            }
    except Exception:
        pass

    # 9. systemd service states (on-demand query)
    _service_versions = {
        "autostream.service": autostream_version,
        "autostream_monitor.service": monitor_build,
        "owntone.service": owntone_build,
        "vibra-mini.service": vibra_build,
    }
    services = _collect_service_states(owntone_backend_id, _service_versions)

    return {
        "ok": True,
        "builds": {
            "autostream": autostream_version,
            "monitor": monitor_build,
            "owntone": owntone_build,
            "vibra_mini": vibra_build,
        },
        "playback_hours": playback_hours,
        "cpu_temperature_c": cpu_temp_c,
        "disk": disk,
        "sd_card": sd_card,
        "services": services,
    }


def _collect_service_states(owntone_backend_id: str, service_versions: dict) -> list:
    """Query systemd for the six fixed service units and return state list."""
    unit_names = [unit for unit, _ in _SERVICES]
    parsed: dict = {}
    try:
        result = subprocess.run(
            [
                "systemctl", "show", "--no-pager",
                "--property=Id",
                "--property=ActiveState",
            ] + unit_names,
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
        parsed = _parse_systemctl_output(result.stdout or "")
    except Exception:
        _log.debug("about/system: systemctl query failed", exc_info=True)

    services = []
    for unit, label in _SERVICES:
        if label is None:
            label = "OwnTone Mini" if owntone_backend_id == "owntone-mini" else "OwnTone"
        block = parsed.get(unit, {})
        active_state = block.get("ActiveState", "")
        state = "ok" if active_state == "active" else "failed"
        entry: dict = {"unit": unit, "label": label, "state": state}
        version = service_versions.get(unit)
        if version and version not in ("unknown", ""):
            entry["version"] = version
        services.append(entry)
    return services


def _parse_systemctl_output(stdout: str) -> dict:
    """Parse blank-line-separated systemctl show output into {Id: {prop: val}}."""
    blocks: dict = {}
    current: dict = {}
    for line in stdout.splitlines():
        line = line.rstrip()
        if not line:
            if current:
                unit_id = current.get("Id", "")
                if unit_id:
                    blocks[unit_id] = current
                current = {}
        elif "=" in line:
            key, _, value = line.partition("=")
            current[key.strip()] = value
    if current:
        unit_id = current.get("Id", "")
        if unit_id:
            blocks[unit_id] = current
    return blocks
