#!/usr/bin/env python3
"""autostream_webui_page_about.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Page renderer for the /about route.

Responsibilities:
  - Render the About page: system information (build version, total playback
    hours, CPU temperature, CPU load, memory, disk usage, SD card health), and
    copyright/license.
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

from autostream_bluetooth_client import (
    BLUETOOTH_SERVICE_VERSION,
    BluetoothClient,
    bluetooth_installed,
    bluetooth_services_enabled,
)
from autostream_core import get_monitor_runtime_info, get_playback_snapshot
from autostream_player_service import get_owntone_runtime_info
from autostream_rpi import get_cpu_busy_percent, get_cpu_temperature_c
from autostream_sysutils import (
    fmt_bytes,
    get_effective_memory_info,
    get_root_disk_usage,
    get_sdcard_health_percent,
    get_static_system_facts,
)
from track_id.vibra_shazam import get_vibra_runtime_info

from autostream_webui_common import (
    _config_snapshot,
    build_page_html,
    build_top_banner_html,
    get_app_version,
    load_license_text,
    render_license_md,
    send_html,
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

# The one genuinely optional in-family service: spliced into _SERVICES only
# when the Bluetooth-input subsystem is installed on this appliance, always
# immediately before the NGINX row (NGINX is the fixed last entry).
# _SERVICES itself stays a fixed 6-tuple so existing call sites/tests that
# assume a static list are unaffected when the feature isn't installed
# (the common case today).
_BLUETOOTH_SERVICE_ROW = ("autostream_bluetooth.service", "Bluetooth Service")


def _effective_services() -> tuple:
    """Return _SERVICES, with the Bluetooth row spliced in before the
    trailing NGINX entry when the subsystem is installed."""
    try:
        if bluetooth_installed():
            return _SERVICES[:-1] + (_BLUETOOTH_SERVICE_ROW,) + _SERVICES[-1:]
    except Exception:
        pass
    return _SERVICES


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
        for unit, label in _effective_services()
    )

    # System Info panel: static placeholders with stable DOM IDs.
    # All values are populated by the DOMContentLoaded fetch below; no live
    # probes run during page rendering.  CPU load, memory, disk, and SD
    # sections start hidden and become visible only when the API reports
    # available=true.
    _system_panel_html = (
        "<div aria-live='polite'>"
        "<div class='about-info-card'>"
        "<div class='bar-label'><strong>autostream Build</strong>"
        "<span id='aboutBuildAutostream'>Loading...</span></div>"
        "<div class='bar-label' style='margin-top:0.65rem;'>"
        "<strong>Device</strong>"
        "<span id='aboutDeviceModel'>Loading...</span></div>"
        "<div class='bar-label' style='margin-top:0.65rem;'>"
        "<strong>OS Build</strong>"
        "<span id='aboutOsBuild'>Loading...</span></div>"
        "<div class='bar-label' style='margin-top:0.65rem;'>"
        "<strong>Total Playback Time</strong>"
        "<span id='aboutPlaybackHours'>Loading...</span></div>"
        "<div id='aboutTempSection' style='display:none;margin-top:1.3rem;'>"
        "<div id='aboutTempLabel' class='bar-label'></div>"
        "<div class='storage-bar'><div id='aboutTempBar' class='used' style='width:0%'></div></div>"
        "</div>"
        "<div id='aboutCpuSection' style='display:none;margin-top:1.3rem;'>"
        "<div id='aboutCpuLabel' class='bar-label'></div>"
        "<div class='storage-bar'><div id='aboutCpuBar' class='used' style='width:0%'></div></div>"
        "</div>"
        "<div id='aboutMemSection' style='display:none;margin-top:1.3rem;'>"
        "<div id='aboutMemLabel' class='bar-label'></div>"
        "<div class='storage-bar'><div id='aboutMemBar' class='used' style='width:0%'></div></div>"
        "<div id='aboutMemMeta' class='storage-meta'></div>"
        "</div>"
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
        ".about-svc-state[data-state='disabled'] { color:var(--color-text-secondary); background:color-mix(in srgb,var(--color-text-secondary) 12%,transparent); }\n"
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
        "['aboutBuildAutostream','aboutDeviceModel','aboutOsBuild',"
        "'aboutPlaybackHours'].forEach(function(id){"
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
        "var dev=d.device||{};"
        "var os=d.os||{};"
        "_s('aboutBuildAutostream',String(b.autostream||'unknown'));"
        "_s('aboutDeviceModel',String(dev.model||'unknown'));"
        "_s('aboutOsBuild',String(os.pretty_name||os.version_codename||'unknown'));"
        "_s('aboutPlaybackHours',typeof d.playback_hours==='number'"
        "?d.playback_hours.toFixed(1)+' hours':'Unavailable');"
        "var temp=d.cpu_temperature||{};"
        "if(temp.available===true){"
        "var tp=_clamp(temp.percent);"
        "_s('aboutTempLabel','CPU Temperature: '+Number(temp.celsius).toFixed(1)+'°C');"
        "var tb=document.getElementById('aboutTempBar');"
        "if(tb){tb.style.width=tp+'%';tb.setAttribute('data-status',_ss(temp.status));}"
        "var ts=document.getElementById('aboutTempSection');if(ts)ts.style.display='';}"
        "var cl=d.cpu_load||{};"
        "if(cl.available===true){"
        "var cp=_clamp(cl.percent);"
        "_s('aboutCpuLabel','CPU Load: '+cp.toFixed(1)+'%');"
        "var cb=document.getElementById('aboutCpuBar');"
        "if(cb){cb.style.width=cp+'%';cb.setAttribute('data-status',_ss(cl.status));}"
        "var cs=document.getElementById('aboutCpuSection');if(cs)cs.style.display='';}"
        "var mem=d.memory||{};"
        "if(mem.available===true){"
        "var mp=_clamp(mem.used_percent);"
        "_s('aboutMemLabel','Memory Usage: '+mp.toFixed(1)+'%');"
        "var mb=document.getElementById('aboutMemBar');"
        "if(mb){mb.style.width=mp+'%';mb.setAttribute('data-status',_ss(mem.status));}"
        "_s('aboutMemMeta',"
        "(typeof mem.free_mib==='number'?mem.free_mib:0)+' MB free of '"
        "+(typeof mem.total_mib==='number'?mem.total_mib:0)+' MB');"
        "var ms=document.getElementById('aboutMemSection');if(ms)ms.style.display='';}"
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
        "if(st){var state=svc.state;var suffix=state==='ok'?' - OK':"
        "(state==='disabled'?' - Disabled':' - Failed');"
        "var base=state==='ok'?'OK':(state==='disabled'?'Disabled':'Failed');"
        "st.textContent=svc.version?String(svc.version)+suffix:base;"
        "st.setAttribute('data-state',"
        "(state==='ok'||state==='disabled')?state:'failed');"
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
        f"autostream includes third-party and separately licensed components, including "
        f"various open-source libraries, ALSA, FFmpeg, owntone-mini, and vibra-mini."
        f"</p>"
        f"<ul style='margin:0.25rem 0 0.85rem 1.2rem;color:var(--color-text-secondary);font-size:0.95rem;'>"
        f"<li>OwnTone Server: https://github.com/owntone/owntone-server</li>"
        f"<li>owntone-mini is a simplified fork of OwnTone Server, installed by default with autostream.</li>"
        f"<li>vibra-mini is a daemon-focused fork of vibra: https://github.com/bayernmuller/vibra</li>"
        f"</ul>"
        f"<p style='margin:0.5rem 0 0.85rem;color:var(--color-text-secondary);font-size:0.95rem;'>"
        f"AirPlay and AirPlay&nbsp;2 are trademarks of Apple Inc. autostream is not "
        f"affiliated with, sponsored by, or endorsed by Apple Inc."
        f"</p>"
        f"<p style='margin:0.5rem 0 0.85rem;color:var(--color-text-secondary);font-size:0.95rem;'>"
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
    send_html(handler, 200, html_body)


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


def _get_wifi_watcher_version() -> str:
    try:
        from autostream_webui_api import get_wifi_watcher_version
        return get_wifi_watcher_version()
    except Exception:
        return "unknown"


def _get_bluetooth_version() -> str:
    """Bounded control-socket probe for the running daemon's version.

    ``BluetoothClient`` already swallows every failure mode (socket absent,
    daemon down, timeout, malformed reply) and returns ``None`` quietly, so
    this simply falls back to the pinned client-side constant whenever the
    live query didn't yield a usable version -- callers never need to check
    whether the service is installed/enabled/running first.
    """
    try:
        status = BluetoothClient().status()
    except Exception:
        status = None
    if isinstance(status, dict):
        version = str(status.get("version") or "").strip()
        if version:
            return version
    return BLUETOOTH_SERVICE_VERSION


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

    # Wi-Fi watcher build - fixed loopback request to its token-protected API
    try:
        wifi_watcher_build = _get_wifi_watcher_version()
    except Exception:
        wifi_watcher_build = "unknown"

    # Bluetooth service build - cheap, bounded control-socket probe when the
    # daemon is reachable; falls back to the pinned client-side constant
    # otherwise (disabled/stopped/never started), so the row always has a
    # version even when the daemon can't be asked directly.
    try:
        bluetooth_build = _get_bluetooth_version()
    except Exception:
        bluetooth_build = BLUETOOTH_SERVICE_VERSION

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

    # 6b. CPU temperature bar block -- mirrors cpu_temp_c above but adds the
    # bar-fill percent and status; cpu_temperature_c stays untouched for
    # existing callers/tests.
    cpu_temperature: dict = {"available": False}
    try:
        if cpu_temp_c is not None:
            # Fixed 85C full-scale reference -- the Raspberry Pi soft-throttle
            # point -- so the bar reads as "how close to throttling", not an
            # arbitrary 0-100 range.
            temp_pct = max(0.0, min(100.0, (cpu_temp_c / 85.0) * 100.0))
            # Status keyed on absolute Celsius, inclusive both ends of the
            # warning band (same inclusivity convention as memory): <70
            # healthy, 70-78 warning, >78 critical.
            if cpu_temp_c < 70:
                temp_status = "healthy"
            elif cpu_temp_c <= 78:
                temp_status = "warning"
            else:
                temp_status = "critical"
            cpu_temperature = {
                "available": True,
                "celsius": cpu_temp_c,
                "percent": temp_pct,
                "status": temp_status,
            }
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

    # 7b. CPU utilisation, htop-style busy% (on-demand /proc/stat read).
    # Wire field name "cpu_load" is kept stable for JS compatibility even
    # though the value is now busy% rather than scheduler load average.
    cpu_load: dict = {"available": False}
    try:
        load_pct = get_cpu_busy_percent()
        if load_pct is not None:
            load_status = (
                "healthy" if load_pct < 70
                else ("warning" if load_pct < 85 else "critical")
            )
            cpu_load = {
                "available": True,
                "percent": load_pct,
                "status": load_status,
            }
    except Exception:
        pass

    # 7c. Effective memory (on-demand /proc/meminfo read)
    memory: dict = {"available": False}
    try:
        mem_info = get_effective_memory_info()
        if mem_info is not None:
            free_mib, total_mib = mem_info
            used_pct = round(((total_mib - free_mib) / total_mib) * 100.0) if total_mib else 0
            # Status keyed on absolute free MiB, not percentage: >96 healthy,
            # 64-96 warning (inclusive of both boundaries), <64 critical.
            if free_mib > 96:
                mem_status = "healthy"
            elif free_mib >= 64:
                mem_status = "warning"
            else:
                mem_status = "critical"
            memory = {
                "available": True,
                "free_mib": free_mib,
                "total_mib": total_mib,
                "used_percent": used_pct,
                "status": mem_status,
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

    # 9. Startup-collected static system facts
    try:
        facts = get_static_system_facts()
    except Exception:
        from autostream_sysutils import StaticSystemFacts
        facts = StaticSystemFacts()

    # 10. systemd service states (on-demand query)
    _service_versions = {
        "autostream.service": autostream_version,
        "autostream_monitor.service": monitor_build,
        "autostream_wifi_watcher.service": wifi_watcher_build,
        "owntone.service": owntone_build,
        "vibra-mini.service": vibra_build,
        "autostream_bluetooth.service": bluetooth_build,
        "nginx.service": facts.nginx_version,
    }
    services = _collect_service_states(owntone_backend_id, _service_versions)

    return {
        "ok": True,
        "builds": {
            "autostream": autostream_version,
            "monitor": monitor_build,
            "wifi_watcher": wifi_watcher_build,
            "owntone": owntone_build,
            "vibra_mini": vibra_build,
        },
        "playback_hours": playback_hours,
        "cpu_temperature_c": cpu_temp_c,
        "cpu_temperature": cpu_temperature,
        "device": {
            "model": facts.raspberry_pi_model,
        },
        "os": {
            "pretty_name": facts.os_pretty_name,
            "version_id": facts.os_version_id,
            "version_codename": facts.os_version_codename,
        },
        "cpu_load": cpu_load,
        "memory": memory,
        "disk": disk,
        "sd_card": sd_card,
        "services": services,
    }


def _collect_service_states(owntone_backend_id: str, service_versions: dict) -> list:
    """Query systemd for the fixed service units and return state list.

    Units queried are _SERVICES plus the Bluetooth row when the subsystem is
    installed (_effective_services()); the six-unit case is unchanged from
    before this feature existed.
    """
    services_list = _effective_services()
    unit_names = [unit for unit, _ in services_list]
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
    for unit, label in services_list:
        if label is None:
            label = "OwnTone Mini" if owntone_backend_id == "owntone-mini" else "OwnTone"
        block = parsed.get(unit, {})
        active_state = block.get("ActiveState", "")
        if unit == _BLUETOOTH_SERVICE_ROW[0]:
            state = _bluetooth_row_state(active_state)
        else:
            state = "ok" if active_state == "active" else "failed"
        entry: dict = {"unit": unit, "label": label, "state": state}
        version = service_versions.get(unit)
        if version and version not in ("unknown", ""):
            entry["version"] = version
        services.append(entry)
    return services


def _bluetooth_row_state(active_state: str) -> str:
    """Bluetooth row's three-way state, distinct from every other row's
    plain ok/failed mapping.

    systemd reports the same ActiveState ("inactive") for "unit never
    enabled" and "enabled but not currently running", so the row would
    otherwise render a never-installed-in-anger service as "Failed".
    ``bluetooth_services_enabled()`` disambiguates the two: a disabled unit
    reads "disabled" regardless of ActiveState; only once enabled does the
    ordinary active/not-active check (mirroring every other row) apply.
    """
    try:
        enabled = bluetooth_services_enabled()
    except Exception:
        enabled = False
    if not enabled:
        return "disabled"
    return "ok" if active_state == "active" else "failed"


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
