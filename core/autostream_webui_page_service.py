#!/usr/bin/env python3
"""autostream_webui_page_service.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Page renderer for the /service route.

Responsibilities:
  - Render the Service page: per-input stylus tracking configuration,
    usage reporting, and stylus reset action.
  - No PIN required; /service is in the auth allowlist.
"""

from __future__ import annotations

import html
from typing import Optional
from datetime import datetime

from autostream_config import parse_config, VALID_STYLUS_LIFE_HOURS
from autostream_core import get_playback_snapshot
from autostream_playback_stats import InputPlaybackSnapshot, format_hours

from autostream_webui_assets import BANNER_HTML

from autostream_webui_common import (
    _fallback_input_snapshot,
    build_page_html,
    build_top_banner_html,
    locked_load_config,
)

from autostream_webui_state import WebUIState


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

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


def _tracking_selector_html(
    name: str,
    current_life_hours: int,
    *,
    input_index: int = 0,
    playback_seconds: int = 0,
) -> str:
    """Render the stylus tracking dropdown."""
    opts = f"<option value='0'{'  selected' if current_life_hours == 0 else ''}>Don't track usage</option>"
    for hours in VALID_STYLUS_LIFE_HOURS:
        sel = "  selected" if hours == current_life_hours else ""
        opts += f"<option value='{hours}'{sel}>{hours} hours</option>"
    return (
        f"<label style='display:flex;align-items:center;gap:0.75rem;margin-bottom:0.75rem;'>"
        f"<span style='min-width:6rem;'>Stylus Life</span>"
        f"<select name='{name}' style='flex:1;' "
        f"data-playback-seconds='{playback_seconds}' "
        f"onchange='updateStylusStats({input_index})'>{opts}</select>"
        f"</label>"
    )


def _summary_row(label: str, value: str, *, warn: bool = False, value_id: str = "") -> str:
    colour = "color:var(--color-status-danger);" if warn else ""
    id_attr = f" id='{value_id}'" if value_id else ""
    style = f" style='margin-left:auto;text-align:right;{colour}'"
    return (
        f"<div style='display:flex;align-items:baseline;justify-content:space-between;"
        f"gap:0.75rem;margin-bottom:0.2rem;'>"
        f"<span>{html.escape(label)}:</span>"
        f"<span{id_attr}{style}>{value}</span>"
        f"</div>"
    )


def _input_panel_html(
    *,
    input_index: int,
    title: str,
    is_turntable: bool,
    snapshot: InputPlaybackSnapshot,
    stylus_life_hours: int,
    csrf_token: str,
) -> str:
    """Render the detail panel content for one input."""
    life_name = f"service_stylus_life_input{input_index}"

    panel_title = html.escape(title) + " Stylus Wear Tracking"

    if not is_turntable:
        return (
            f"<fieldset><legend>{panel_title}</legend>"
            f"<p style='margin:0.5rem 0;color:var(--color-text-secondary);font-size:0.95rem;'>"
            f"Set this input to Turntable in Setup to enable stylus tracking."
            f"</p></fieldset>"
        )

    playback_secs = int(snapshot.stylus_playback_seconds)
    tracking_off = stylus_life_hours == 0

    # Tracking selector — always present; carries playback_seconds for JS.
    tracking_html = _tracking_selector_html(
        life_name, stylus_life_hours,
        input_index=input_index,
        playback_seconds=playback_secs,
    )

    # Compute bar / stats using the current life setting, or the first valid
    # option as a preview for when the user picks one from "Don't track".
    _life_for_calc = stylus_life_hours if stylus_life_hours > 0 else VALID_STYLUS_LIFE_HOURS[0]
    _remaining_seconds = snapshot.stylus_remaining_seconds
    if _remaining_seconds is None or tracking_off:
        _remaining_seconds = (_life_for_calc * 3600) - playback_secs
    _remaining_seconds = max(0, _remaining_seconds)
    _remaining_pct = min(100.0, (_remaining_seconds / max(1, _life_for_calc * 3600)) * 100.0)
    _bar_status = (
        "critical" if _remaining_pct <= 10.0
        else ("warning" if _remaining_pct <= 20.0 else "healthy")
    )
    warn_state = not tracking_off and (snapshot.stylus_overdue or snapshot.stylus_warning)
    used_txt = format_hours(playback_secs)
    life_txt = f"{_life_for_calc} h"
    remaining_txt = "Due now" if _remaining_seconds <= 0 else format_hours(_remaining_seconds)

    # "Tracking off" message — visible when tracking_off, hidden by JS on change.
    off_display = "" if tracking_off else "display:none;"
    off_msg_html = (
        f"<p id='stylus-off-{input_index}' "
        f"style='margin:0.5rem 0 0.75rem;color:var(--color-text-secondary);"
        f"font-size:0.95rem;{off_display}'>"
        f"Usage tracking is off for this input."
        f"</p>"
    )

    # Live section (bar + stats + reset) — hidden when tracking_off, shown by JS on change.
    live_display = "display:none;" if tracking_off else ""

    active_row = ""
    if not tracking_off:
        if snapshot.active:
            active_row = _summary_row("Status", "Active now")
        elif not snapshot.enabled:
            active_row = _summary_row("Status", "Disabled")

    reset_date_txt = html.escape(_format_reset_timestamp(snapshot.last_stylus_reset_at))
    warn_btn_style = (
        "width:100%;border-color:var(--color-status-danger);"
        "background:var(--color-status-danger);color:#fff;"
        if warn_state else "width:100%;"
    )

    live_html = (
        f"<div id='stylus-live-{input_index}' style='{live_display}'>"
        f"<div class='bar-label' style='font-size:0.95rem;'>"
        f"<span>Life Remaining:</span>"
        f" <span id='stylus-bar-pct-{input_index}'>{_remaining_pct:.1f}%</span>"
        f"</div>"
        f"<div class='storage-bar' style='margin-bottom:0.75rem;'>"
        f"<div id='stylus-bar-fill-{input_index}' class='used'"
        f" style='width:{_remaining_pct:.1f}%;' data-status='{_bar_status}'></div>"
        f"</div>"
        f"<div style='margin-bottom:0.75rem;font-size:0.95rem;'>"
        + _summary_row("Used",
                       f"{html.escape(used_txt)} / {html.escape(life_txt)}",
                       value_id=f"stylus-used-val-{input_index}")
        + _summary_row("Remaining",
                       html.escape(remaining_txt),
                       warn=warn_state,
                       value_id=f"stylus-remaining-val-{input_index}")
        + _summary_row("Last changed", reset_date_txt)
        + active_row
        + f"</div>"
        f"<div style='margin-top:0.5rem;'>"
        f"<button id='stylus-reset-btn-{input_index}' "
        f"type='submit' name='service_reset_stylus_input' value='{input_index}' "
        f"class='pill-btn small' style='{warn_btn_style}' "
        f"onclick=\"return confirm('Mark {html.escape(title)} stylus as changed?');\">"
        f"Mark stylus changed"
        f"</button>"
        f"</div>"
        f"</div>"
    )

    return (
        f"<fieldset><legend>{panel_title}</legend>"
        f"{tracking_html}"
        f"{off_msg_html}"
        f"{live_html}"
        f"</fieldset>"
    )


def _input_card_sub(
    *,
    is_turntable: bool,
    stylus_life_hours: int,
    snapshot: InputPlaybackSnapshot,
) -> str:
    """Build the sub-label shown on the list card."""
    if not is_turntable:
        return "Line In"
    if stylus_life_hours == 0:
        return "Turntable \u00b7 Tracking off"
    # tracking on
    used_txt = format_hours(snapshot.stylus_playback_seconds)
    remaining_seconds = snapshot.stylus_remaining_seconds
    if remaining_seconds is None:
        remaining_seconds = (stylus_life_hours * 3600) - int(snapshot.stylus_playback_seconds)
    if remaining_seconds <= 0:
        return f"Turntable \u00b7 Due now"
    remaining_txt = format_hours(remaining_seconds)
    return f"Turntable \u00b7 {used_txt} used \u00b7 {remaining_txt} remaining"


def _list_card(
    panel_name: str,
    title: str,
    sub: str,
    card_style: str,
    text_style: str,
    disabled: bool,
) -> str:
    """Render one input list card, optionally disabled (no onclick, no chevron)."""
    onclick = "" if disabled else f" onclick='openServicePanel(\"{panel_name}\")'"
    chevron = (
        ""
        if disabled
        else f"<span class='setup-list-chevron'{text_style}>\u203a</span>"
    )
    return (
        f"<div class='setup-list-card'{onclick}{card_style}>"
        f"<div class='setup-list-card-body'>"
        f"<span class='setup-list-card-title'{text_style}>{html.escape(title)}</span>"
        f"<span class='setup-list-card-sub'>{html.escape(sub)}</span>"
        f"</div>"
        f"{chevron}"
        f"</div>"
    )


# -----------------------------------------------------------------------------
# Page renderer
# -----------------------------------------------------------------------------

def send_service_page(
    handler,
    state: WebUIState,
    flash_msg: Optional[str] = None,
    flash_type: str = "success",
) -> None:
    """Render and send the Service page."""
    lic_html, lic_spacer = build_top_banner_html(flash_msg=flash_msg, flash_type=flash_type)

    parsed = None
    try:
        parsed = parse_config(locked_load_config(state.config_path))
    except Exception:
        parsed = None

    playback_snapshot = get_playback_snapshot()
    service_warn = playback_snapshot.has_warning

    csrf_token = getattr(handler, "_csrf_token", None) or ""

    # ── Input 1 ──────────────────────────────────────────────────────────────
    if parsed is not None:
        is_turntable1 = bool(parsed.audio1.is_turntable)
        life1 = int(parsed.audio1.stylus_life_hours)
        snap1 = playback_snapshot.inputs.get(1) or _fallback_input_snapshot(
            parsed.audio1, 1, enabled=True,
        )
        warn1 = snap1.stylus_warning or snap1.stylus_overdue
        sub1 = _input_card_sub(is_turntable=is_turntable1, stylus_life_hours=life1, snapshot=snap1)
        panel1_html = _input_panel_html(
            input_index=1,
            title="Input 1",
            is_turntable=is_turntable1,
            snapshot=snap1,
            stylus_life_hours=life1,
            csrf_token=csrf_token,
        )
    else:
        is_turntable1 = False
        warn1 = False
        sub1 = "Unavailable"
        panel1_html = "<p>Configuration unavailable.</p>"

    # ── Input 2 ──────────────────────────────────────────────────────────────
    if parsed is not None:
        is_turntable2 = bool(parsed.audio2_enabled and parsed.audio2.is_turntable)
        life2 = int(parsed.audio2.stylus_life_hours) if parsed.audio2_enabled else 0
        snap2 = playback_snapshot.inputs.get(2) or _fallback_input_snapshot(
            parsed.audio2, 2, enabled=parsed.audio2_enabled,
        )
        warn2 = snap2.stylus_warning or snap2.stylus_overdue
        if not parsed.audio2_enabled:
            sub2 = "Disabled"
        else:
            sub2 = _input_card_sub(is_turntable=is_turntable2, stylus_life_hours=life2, snapshot=snap2)
        panel2_html = _input_panel_html(
            input_index=2,
            title="Input 2",
            is_turntable=is_turntable2,
            snapshot=snap2,
            stylus_life_hours=life2,
            csrf_token=csrf_token,
        ) if parsed.audio2_enabled else (
            "<fieldset><legend>Input 2</legend>"
            "<p style='margin:0.5rem 0;color:var(--color-text-secondary);font-size:0.95rem;'>"
            "Input 2 is disabled.</p></fieldset>"
        )
    else:
        warn2 = False
        sub2 = "Unavailable"
        panel2_html = "<p>Configuration unavailable.</p>"

    card1_disabled = parsed is None or not is_turntable1
    card2_disabled = parsed is None or not parsed.audio2_enabled or not is_turntable2

    def _card_style(warn: bool, disabled: bool) -> str:
        parts = []
        if warn:
            parts.append("border-color:var(--color-status-danger);")
        if disabled:
            parts.append("opacity:0.55;pointer-events:none;cursor:default;")
        return f' style="{" ".join(parts)}"' if parts else ""

    def _text_style(warn: bool) -> str:
        return ' style="color:var(--color-status-danger);"' if warn else ""

    i1_card_style = _card_style(warn1, card1_disabled)
    i1_text_style = _text_style(warn1)
    i2_card_style = _card_style(warn2, card2_disabled)
    i2_text_style = _text_style(warn2)

    _extra_css = (
        ".service-slide-viewport { overflow: hidden; width: 100%; }\n"
        ".service-slide-track { display: flex; width: 200%;"
        " transition: transform 0.35s cubic-bezier(0.4, 0, 0.2, 1); }\n"
        ".service-slide-track.panel-open { transform: translateX(-50%); }\n"
        ".service-slide-list, .service-slide-detail { width: 50%; flex-shrink: 0; min-width: 0; }\n"
    )

    _body_html = (
        f"{BANNER_HTML}"
        f"<form id='serviceForm' method='POST' action='/service' autocomplete='off'>"
        f"<input type='hidden' name='csrf_token' value='{html.escape(csrf_token)}'>"
        f"<div class='service-slide-viewport'>"
        f"<div class='service-slide-track' id='serviceSlideTrack'>"
        f"<div class='service-slide-list'>"
        f"<p style='margin:0.5rem 0 0.85rem;color:var(--color-text-secondary);font-size:0.95rem;'>"
        f"Autostream can keep track of maintenance items for turntables, and remind you when a service item is due."
        f"</p>"
        + _list_card("input1", "Input 1", sub1, i1_card_style, i1_text_style, card1_disabled)
        + _list_card("input2", "Input 2", sub2, i2_card_style, i2_text_style, card2_disabled)
        + "</div>"
        f"<div class='service-slide-detail'>"
        f"<div class='setup-detail-panel' id='service-panel-input1'>"
        f"<div class='setup-detail-back'>"
        f"<button type='submit' class='pill-btn small' style='width:auto;'>Save</button>"
        f"</div>"
        f"{panel1_html}"
        f"</div>"
        f"<div class='setup-detail-panel' id='service-panel-input2'>"
        f"<div class='setup-detail-back'>"
        f"<button type='submit' class='pill-btn small' style='width:auto;'>Save</button>"
        f"</div>"
        f"{panel2_html}"
        f"</div>"
        f"</div>"
        f"</div>"
        f"</div>"
        f"</form>"
        f"<script>"
        f"function openServicePanel(name){{"
        f"document.querySelectorAll('.setup-detail-panel').forEach(function(p){{p.classList.remove('active');}});"
        f"var panel=document.getElementById('service-panel-'+name);"
        f"if(panel)panel.classList.add('active');"
        f"document.getElementById('serviceSlideTrack').classList.add('panel-open');"
        f"window.scrollTo(0,0);"
        f"}}"
        f"function closeServicePanel(){{"
        f"document.querySelectorAll('.setup-detail-panel').forEach(function(p){{p.classList.remove('active');}});"
        f"document.getElementById('serviceSlideTrack').classList.remove('panel-open');"
        f"window.scrollTo(0,0);"
        f"}}"
        f"function updateStylusStats(idx){{"
        f"var sel=document.querySelector('[name=\"service_stylus_life_input'+idx+'\"]');"
        f"if(!sel)return;"
        f"var lifeHours=parseInt(sel.value,10);"
        f"var playSecs=parseInt(sel.getAttribute('data-playback-seconds')||'0',10);"
        f"var offMsg=document.getElementById('stylus-off-'+idx);"
        f"var liveDiv=document.getElementById('stylus-live-'+idx);"
        f"if(lifeHours===0){{"
        f"if(offMsg)offMsg.style.display='';"
        f"if(liveDiv)liveDiv.style.display='none';"
        f"return;"
        f"}}"
        f"if(offMsg)offMsg.style.display='none';"
        f"if(liveDiv)liveDiv.style.display='';"
        f"var lifeSecs=lifeHours*3600;"
        f"var remSecs=Math.max(0,lifeSecs-playSecs);"
        f"var remPct=Math.min(100,remSecs/lifeSecs*100);"
        f"var usedH=(Math.max(0,playSecs)/3600).toFixed(1);"
        f"var remH=(remSecs/3600).toFixed(1);"
        f"var remTxt=remSecs<=0?'Due now':remH+' h';"
        f"var barStatus=remPct<=10?'critical':(remPct<=20?'warning':'healthy');"
        f"var warnColor=remPct<=20?'var(--color-status-danger)':'';"
        f"var warnBg=remPct<=20?'var(--color-status-danger)':'';"
        f"var el;"
        f"el=document.getElementById('stylus-bar-pct-'+idx);"
        f"if(el)el.textContent=remPct.toFixed(1)+'%';"
        f"el=document.getElementById('stylus-bar-fill-'+idx);"
        f"if(el){{el.style.width=remPct.toFixed(1)+'%';el.setAttribute('data-status',barStatus);}}"
        f"el=document.getElementById('stylus-used-val-'+idx);"
        f"if(el)el.textContent=usedH+' h / '+lifeHours+' h';"
        f"el=document.getElementById('stylus-remaining-val-'+idx);"
        f"if(el){{el.textContent=remTxt;el.style.color=warnColor;}}"
        f"el=document.getElementById('stylus-reset-btn-'+idx);"
        f"if(el){{"
        f"el.style.borderColor=warnBg;"
        f"el.style.background=warnBg;"
        f"el.style.color=warnBg?'#fff':'';"
        f"}}"
        f"}}"
        f"</script>"
    )

    html_body = build_page_html(
        "Service",
        _body_html,
        extra_css=_extra_css,
        lic_html=lic_html,
        lic_spacer=lic_spacer,
        active_tab="service",
        service_warn=service_warn,
        dark_mode=parsed.webui.dark_mode if parsed else False,
    )
    body_bytes = html_body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)
