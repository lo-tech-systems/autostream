#!/usr/bin/env python3
"""autostream_webui_page_service.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Page renderer for the /service route.

Responsibilities:
  - Render the Service page: per-input maintenance tracking configuration
    (stylus, drive belt, main bearing oil), usage reporting, and reset actions.
  - No PIN required; /service is in the auth allowlist.
  - Settings are saved automatically via POST /api/service/config (AJAX).
  - Live display values are returned by the API (no client-side recalculation).

Schema / display logic:
  All maintenance-item metadata and display calculations live in
  autostream_webui_service_schema so they are shared with autostream_webui_api
  without either module depending on the other.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from typing import Optional

from autostream_config import (
    VALID_STYLUS_LIFE_HOURS,
    VALID_MAINTENANCE_LIFE_HOURS,
    VALID_BEARING_LIFE_HOURS,
    VALID_MAINTENANCE_LIFE_YEARS,
)
from autostream_core import get_playback_snapshot
from autostream_playback_stats import InputPlaybackSnapshot

from autostream_webui_assets import SERVICE_CSS, SERVICE_JS

from autostream_webui_common import (
    _config_snapshot,
    _fallback_input_snapshot,
    build_page_html,
    build_top_banner_html,
)

from autostream_webui_service_schema import (
    _SERVICE_ITEMS,
    _SNAP_TIME_ATTRS,
    _card_display,
    _format_reset_timestamp,
    _hours_display,
    _time_display,
)

from autostream_webui_state import WebUIState


# Confirm modal HTML (rendered once per request, referenced by SERVICE_JS).
_CONFIRM_MODAL_HTML = (
    "<div id='svcConfirmModal' class='modal-overlay' role='dialog' aria-modal='true' aria-labelledby='svcConfirmTitle'>"
    "<div class='panel modal-panel'>"
    "<div class='hdr modal-hdr' id='svcConfirmTitle'>Confirm</div>"
    "<div class='ft modal-ft'>"
    "<button type='button' class='btn modal-btn modal-btn-secondary' id='svcConfirmCancel'>Cancel</button>"
    "<button type='button' class='btn modal-btn modal-btn-primary' id='svcConfirmOk'>Yes</button>"
    "</div></div></div>"
)


# -----------------------------------------------------------------------------
# Data-gathering helper
# -----------------------------------------------------------------------------

@dataclass
class _InputRenderData:
    is_turntable: bool
    cards_disabled: bool
    stylus_warn: bool
    belt_warn: bool
    bearing_warn: bool
    stylus_sub: str
    belt_sub: str
    bearing_sub: str
    stylus_html: str
    belt_html: str
    bearing_html: str


_UNAVAILABLE_INPUT = _InputRenderData(
    is_turntable=False,
    cards_disabled=True,
    stylus_warn=False,
    belt_warn=False,
    bearing_warn=False,
    stylus_sub="Unavailable",
    belt_sub="Unavailable",
    bearing_sub="Unavailable",
    stylus_html="<p>Configuration unavailable.</p>",
    belt_html="<p>Configuration unavailable.</p>",
    bearing_html="<p>Configuration unavailable.</p>",
)


def _gather_input_render_data(parsed, playback_snapshot, input_index: int, *, enabled: bool) -> _InputRenderData:
    """Compute all render data for one input channel."""
    if not enabled:
        return _InputRenderData(
            is_turntable=False,
            cards_disabled=True,
            stylus_warn=False, belt_warn=False, bearing_warn=False,
            stylus_sub="Disabled", belt_sub="Disabled", bearing_sub="Disabled",
            stylus_html=(
                "<p style='margin:0.5rem 0;color:var(--color-text-secondary);font-size:0.95rem;'>"
                "Input 2 is disabled.</p>"
            ),
            belt_html="",
            bearing_html="",
        )

    audio = parsed.audio1 if input_index == 1 else parsed.audio2
    snap = playback_snapshot.inputs.get(input_index) or _fallback_input_snapshot(
        audio, input_index, enabled=True,
    )
    is_turntable  = bool(audio.is_turntable)
    stylus_life   = int(audio.stylus_life_hours)
    belt_hours    = int(audio.belt_life_hours)
    belt_years    = int(audio.belt_life_years)
    bearing_hours = int(audio.bearing_life_hours)
    bearing_years = int(audio.bearing_life_years)

    # Card state derived from the same display dicts used by the detail panels
    # and the live API updates, ensuring the overview and detail are always consistent.
    stylus_cd  = _card_display("stylus",
        _hours_display("stylus",  stylus_life,   snap),
        _time_display("stylus",   0,             snap),
        is_turntable)
    belt_cd    = _card_display("belt",
        _hours_display("belt",    belt_hours,    snap),
        _time_display("belt",     belt_years,    snap),
        is_turntable)
    bearing_cd = _card_display("bearing",
        _hours_display("bearing", bearing_hours, snap),
        _time_display("bearing",  bearing_years, snap),
        is_turntable)

    title = f"Input {input_index}"
    stylus_html = _stylus_panel_html(
        input_index=input_index, title=title,
        is_turntable=is_turntable, snapshot=snap, stylus_life_hours=stylus_life,
    )
    belt_html = _maintenance_item_panel_html(
        input_index=input_index, item="belt", legend="Drive Belt",
        is_turntable=is_turntable, life_hours=belt_hours, life_years=belt_years, snap=snap,
    )
    bearing_html = _maintenance_item_panel_html(
        input_index=input_index, item="bearing", legend="Main Bearing Oil",
        is_turntable=is_turntable, life_hours=bearing_hours, life_years=bearing_years, snap=snap,
        life_hours_options=VALID_BEARING_LIFE_HOURS,
    )

    return _InputRenderData(
        is_turntable=is_turntable,
        cards_disabled=not is_turntable,
        stylus_warn=stylus_cd["card_warn"],
        belt_warn=belt_cd["card_warn"],
        bearing_warn=bearing_cd["card_warn"],
        stylus_sub=stylus_cd["card_sub"],
        belt_sub=belt_cd["card_sub"],
        bearing_sub=bearing_cd["card_sub"],
        stylus_html=stylus_html,
        belt_html=belt_html,
        bearing_html=bearing_html,
    )


# -----------------------------------------------------------------------------
# HTML fragment helpers
# -----------------------------------------------------------------------------

def _tracking_selector_html(
    name: str,
    current_life_hours: int,
    *,
    input_index: int = 0,
) -> str:
    """Render the stylus tracking hours dropdown."""
    opts = f"<option value='0'{'  selected' if current_life_hours == 0 else ''}>Don't track usage</option>"
    for hours in VALID_STYLUS_LIFE_HOURS:
        sel = "  selected" if hours == current_life_hours else ""
        opts += f"<option value='{hours}'{sel}>{hours} hours</option>"
    return (
        f"<label style='display:flex;align-items:center;gap:0.75rem;margin-bottom:0.75rem;'>"
        f"<span style='min-width:6rem;'>Stylus Life</span>"
        f"<select name='{name}' style='flex:1;' "
        f"onchange='_updateResetBtnState(\"stylus\",{input_index});_autoSaveField(this.name,this.value)'>"
        f"{opts}</select>"
        f"</label>"
    )


def _maintenance_hours_selector_html(
    name: str,
    current_hours: int,
    *,
    input_index: int,
    item: str,
    label: str,
    options: tuple = VALID_MAINTENANCE_LIFE_HOURS,
) -> str:
    """Render a maintenance item hours threshold dropdown."""
    is_belt = (item == "belt")
    off_label = "Don't track / Direct Drive" if is_belt else "Don't track"
    opts = f"<option value='0'{'  selected' if current_hours == 0 else ''}>{off_label}</option>"
    for h in options:
        if h == 0:
            continue
        sel = "  selected" if h == current_hours else ""
        opts += f"<option value='{h}'{sel}>{h} hours</option>"
    return (
        f"<label style='display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;'>"
        f"<span style='min-width:6rem;'>{html.escape(label)}</span>"
        f"<select name='{name}' style='flex:1;' "
        f"onchange='_updateResetBtnState(\"{item}\",{input_index});_autoSaveField(this.name,this.value)'>"
        f"{opts}</select>"
        f"</label>"
    )


def _maintenance_years_selector_html(
    name: str,
    current_years: int,
    *,
    input_index: int,
    item: str,
    label: str,
) -> str:
    """Render a maintenance item elapsed-time threshold dropdown."""
    is_belt = (item == "belt")
    off_label = "Don't track / Direct Drive" if is_belt else "Don't track"
    opts = f"<option value='0'{'  selected' if current_years == 0 else ''}>{off_label}</option>"
    for y in VALID_MAINTENANCE_LIFE_YEARS:
        if y == 0:
            continue
        sel = "  selected" if y == current_years else ""
        opts += f"<option value='{y}'{sel}>{y} year{'s' if y != 1 else ''}</option>"
    return (
        f"<label style='display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;'>"
        f"<span style='min-width:6rem;'>{html.escape(label)}</span>"
        f"<select name='{name}' style='flex:1;' "
        f"onchange='_updateResetBtnState(\"{item}\",{input_index});_autoSaveField(this.name,this.value)'>"
        f"{opts}</select>"
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


def _maintenance_item_panel_html(
    *,
    input_index: int,
    item: str,                              # "belt" or "bearing"
    legend: str,                            # "Drive Belt" or "Main Bearing Oil"
    is_turntable: bool,
    life_hours: int,
    life_years: int,
    snap: InputPlaybackSnapshot,
    life_hours_options: tuple = VALID_MAINTENANCE_LIFE_HOURS,
) -> str:
    """Render one maintenance fieldset (belt or bearing) for an input.

    Display values are derived from _hours_display / _time_display — the same
    functions used by the live JSON API — so the initial render and any
    subsequent auto-save or reset updates are always calculated identically.
    """
    if not is_turntable:
        return (
            f"<div class='service-control-card'>"
            f"<div class='service-control-card-title'>{html.escape(legend)}</div>"
            f"<p style='margin:0.5rem 0;color:var(--color-text-secondary);font-size:0.95rem;'>"
            f"Set this input to Turntable in Setup to enable maintenance tracking."
            f"</p></div>"
        )

    hours_name = f"service_{item}_life_hours_input{input_index}"
    years_name = f"service_{item}_life_years_input{input_index}"

    hd = _hours_display(item, life_hours, snap)
    td = _time_display(item, life_years, snap)

    hours_tracking_off = not hd["hours_live"]
    years_tracking_off = not td["time_live"]
    warn_state         = hd["hours_remaining_warn"] or td["remaining_warn"]

    # ── Hours selector + live section ─────────────────────────────────────────
    hours_selector = _maintenance_hours_selector_html(
        hours_name, life_hours,
        input_index=input_index,
        item=item,
        label="Hours Life",
        options=life_hours_options,
    )

    hours_live_display = "display:none;" if hours_tracking_off else ""
    hours_live_html = (
        f"<div id='{item}-hours-live-{input_index}' style='{hours_live_display}'>"
        f"<div class='bar-label' style='font-size:0.95rem;'>"
        f"<span>Life Remaining:</span>"
        f" <span id='{item}-hours-bar-pct-{input_index}'>{hd['hours_bar_pct']}%</span>"
        f"</div>"
        f"<div class='storage-bar' style='margin-bottom:0.5rem;'>"
        f"<div id='{item}-hours-bar-fill-{input_index}' class='used'"
        f" style='width:{hd['hours_bar_pct']}%;' data-status='{hd['hours_bar_status']}'></div>"
        f"</div>"
        f"<div style='margin-bottom:0.5rem;font-size:0.95rem;'>"
        + _summary_row(
            "Used",
            html.escape(hd["hours_used"]),
            value_id=f"{item}-hours-used-val-{input_index}",
        )
        + _summary_row(
            "Remaining",
            html.escape(hd["hours_remaining"]),
            warn=hd["hours_remaining_warn"],
            value_id=f"{item}-hours-remaining-val-{input_index}",
        )
        + "</div></div>"
    )

    # ── Years selector + live section ─────────────────────────────────────────
    years_selector = _maintenance_years_selector_html(
        years_name, life_years,
        input_index=input_index,
        item=item,
        label="Time Life",
    )

    years_live_display = "display:none;" if years_tracking_off else ""
    years_live_html = (
        f"<div id='{item}-time-live-{input_index}' style='{years_live_display}'>"
        f"<div class='bar-label' style='font-size:0.95rem;'>"
        f"<span>Time Remaining:</span>"
        f" <span id='{item}-time-bar-pct-{input_index}'>{td['time_bar_pct']}%</span>"
        f"</div>"
        f"<div class='storage-bar' style='margin-bottom:0.5rem;'>"
        f"<div id='{item}-time-bar-fill-{input_index}' class='used'"
        f" style='width:{td['time_bar_pct']}%;' data-status='{td['time_bar_status']}'></div>"
        f"</div>"
        f"<div style='margin-bottom:0.5rem;font-size:0.95rem;'>"
        + _summary_row("Age",       html.escape(td["age"]),
                       value_id=f"{item}-time-age-val-{input_index}")
        + _summary_row("Remaining", html.escape(td["remaining"]),
                       warn=td["remaining_warn"],
                       value_id=f"{item}-time-remaining-val-{input_index}")
        + _summary_row("Due",       html.escape(td["due"]),
                       value_id=f"{item}-time-due-val-{input_index}")
        + "</div></div>"
    )

    # ── Reset section ─────────────────────────────────────────────────────────
    _, svc_attr = _SNAP_TIME_ATTRS.get(item, ("", ""))
    last_service_at = getattr(snap, svc_attr, None) if svc_attr else None

    reset_label  = "Mark Belt Replaced" if item == "belt" else "Mark Bearing Oiled"
    warn_btn_style = (
        "width:100%;border-color:var(--color-status-danger);"
        "background:var(--color-status-danger);color:#fff;"
        if warn_state else "width:100%;"
    )
    disabled_attr = " disabled" if (hours_tracking_off and years_tracking_off) else ""

    reset_html = (
        f"<div style='margin-top:0.5rem;font-size:0.95rem;'>"
        + _summary_row(
            "Last service",
            html.escape(_format_reset_timestamp(last_service_at)),
            value_id=f"{item}-last-service-val-{input_index}",
        )
        + f"<div style='margin-top:0.5rem;'>"
        f"<button id='{item}-reset-btn-{input_index}' type='button'"
        f" class='pill-btn small' style='{warn_btn_style}'"
        f" onclick=\"doServiceReset('{item}',{input_index});\"{disabled_attr}>"
        f"{reset_label}"
        f"</button>"
        f"</div>"
        f"</div>"
    )

    return (
        f"<div class='service-control-card'>"
        f"<div class='service-control-card-title'>{html.escape(legend)}</div>"
        f"{hours_selector}{hours_live_html}"
        f"<div style='margin-top:0.5rem;'>"
        f"{years_selector}{years_live_html}"
        f"</div>"
        f"{reset_html}"
        f"</div>"
    )


def _stylus_panel_html(
    *,
    input_index: int,
    title: str,
    is_turntable: bool,
    snapshot: InputPlaybackSnapshot,
    stylus_life_hours: int,
) -> str:
    """Render the stylus wear tracking fieldset for one input.

    Display values are derived from _hours_display — the same function used by
    the live JSON API — so the initial render and any subsequent updates are
    always calculated identically.
    """
    life_name   = f"service_stylus_life_hours_input{input_index}"
    panel_title = html.escape(title) + " Stylus Wear Tracking"

    if not is_turntable:
        return (
            f"<div class='service-control-card'>"
            f"<div class='service-control-card-title'>{panel_title}</div>"
            f"<p style='margin:0.5rem 0;color:var(--color-text-secondary);font-size:0.95rem;'>"
            f"Set this input to Turntable in Setup to enable maintenance tracking."
            f"</p></div>"
        )

    hd           = _hours_display("stylus", stylus_life_hours, snapshot)
    tracking_off = not hd["hours_live"]
    warn_state   = hd["hours_remaining_warn"]

    live_display = "display:none;" if tracking_off else ""
    active_row   = ""
    if not tracking_off:
        if snapshot.active:
            active_row = _summary_row("Status", "Active now")
        elif not snapshot.enabled:
            active_row = _summary_row("Status", "Disabled")

    warn_btn_style = (
        "width:100%;border-color:var(--color-status-danger);"
        "background:var(--color-status-danger);color:#fff;"
        if warn_state else "width:100%;"
    )

    live_html = (
        f"<div id='stylus-hours-live-{input_index}' style='{live_display}'>"
        f"<div class='bar-label' style='font-size:0.95rem;'>"
        f"<span>Life Remaining:</span>"
        f" <span id='stylus-hours-bar-pct-{input_index}'>{hd['hours_bar_pct']}%</span>"
        f"</div>"
        f"<div class='storage-bar' style='margin-bottom:0.75rem;'>"
        f"<div id='stylus-hours-bar-fill-{input_index}' class='used'"
        f" style='width:{hd['hours_bar_pct']}%;' data-status='{hd['hours_bar_status']}'></div>"
        f"</div>"
        f"<div style='margin-bottom:0.75rem;font-size:0.95rem;'>"
        + _summary_row(
            "Used",
            html.escape(hd["hours_used"]),
            value_id=f"stylus-hours-used-val-{input_index}",
        )
        + _summary_row(
            "Remaining",
            html.escape(hd["hours_remaining"]),
            warn=warn_state,
            value_id=f"stylus-hours-remaining-val-{input_index}",
        )
        + _summary_row(
            "Last changed",
            html.escape(_format_reset_timestamp(snapshot.last_stylus_reset_at)),
            value_id=f"stylus-last-service-val-{input_index}",
        )
        + active_row
        + f"</div>"
        f"<div style='margin-top:0.5rem;font-size:0.95rem;'>"
        f"<button id='stylus-reset-btn-{input_index}' type='button'"
        f" class='pill-btn small' style='{warn_btn_style}'"
        f" onclick=\"doServiceReset('stylus',{input_index});\""
        + (" disabled" if tracking_off else "")
        + f">Mark stylus changed</button>"
        f"</div>"
        f"</div>"
    )

    return (
        f"<div class='service-control-card'>"
        f"<div class='service-control-card-title'>{panel_title}</div>"
        + _tracking_selector_html(life_name, stylus_life_hours, input_index=input_index)
        + live_html
        + f"</div>"
    )


def _service_list_card(item: str, idx: int, title: str, sub: str, warn: bool, disabled: bool) -> str:
    """Render one list card in pane 1 that navigates to the detail panel."""
    if disabled:
        return (
            f"<div class='setup-list-card' id='svc-list-card-{item}-{idx}'"
            f" style='opacity:0.55;pointer-events:none;cursor:default;'>"
            f"<div class='setup-list-card-body'>"
            f"<span class='setup-list-card-title'>{html.escape(title)}</span>"
            f"<span class='setup-list-card-sub'>{html.escape(sub)}</span>"
            f"</div></div>"
        )
    warn_border = "border-color:var(--color-status-danger);" if warn else ""
    warn_colour = " style='color:var(--color-status-danger);'" if warn else ""
    card_style  = f" style='{warn_border}'" if warn_border else ""
    chevron     = f"<span class='setup-list-chevron'{warn_colour}>\u203a</span>"
    return (
        f"<div class='setup-list-card' id='svc-list-card-{item}-{idx}'"
        f" onclick=\"openServiceDetail('{item}',{idx})\"{card_style}>"
        f"<div class='setup-list-card-body'>"
        f"<span class='setup-list-card-title'{warn_colour}>{html.escape(title)}</span>"
        f"<span class='setup-list-card-sub'>{html.escape(sub)}</span>"
        f"</div>"
        f"{chevron}"
        f"</div>"
    )


def _back_bar() -> str:
    return (
        "<div class='setup-detail-back'>"
        "<button type='button' class='pill-btn small' style='width:auto;'"
        " onclick='closeServiceDetail()'>← Back</button>"
        "</div>"
    )


def _service_page_header(title: str) -> str:
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
        parsed = _config_snapshot(state)
    except Exception:
        parsed = None

    playback_snapshot = get_playback_snapshot()
    service_warn = playback_snapshot.has_warning
    csrf_token = getattr(handler, "_csrf_token", None) or ""

    if parsed is not None:
        d1 = _gather_input_render_data(parsed, playback_snapshot, 1, enabled=True)
        d2 = _gather_input_render_data(parsed, playback_snapshot, 2, enabled=bool(parsed.audio2_enabled))
    else:
        d1 = d2 = _UNAVAILABLE_INPUT

    _back = _back_bar()
    _page_header = _service_page_header("Service")

    # ── Pane 1: flat card list (one per item × input, divided by input) ────────
    list_cards = ""
    for inp_idx, inp_data in ((1, d1), (2, d2)):
        for si in _SERVICE_ITEMS:
            sub  = getattr(inp_data, f"{si.key}_sub")
            warn = getattr(inp_data, f"{si.key}_warn")
            list_cards += _service_list_card(
                si.key, inp_idx, f"Input {inp_idx} {si.card_title}",
                sub, warn, inp_data.cards_disabled,
            )
        if inp_idx == 1:
            list_cards += "<hr class='service-divider'>"

    # ── Pane 2: detail panels (one per item × input) ───────────────────────────
    detail_panels = ""
    for inp_idx, inp_data in ((1, d1), (2, d2)):
        for si in _SERVICE_ITEMS:
            panel_html = getattr(inp_data, f"{si.key}_html")
            panel_title = f"Input {inp_idx} {si.card_title}"
            detail_panels += (
                f"<div class='setup-detail-panel' id='service-detail-{si.key}-{inp_idx}'>"
                + _back + _service_page_header(panel_title) + panel_html
                + "</div>"
            )

    _body_html = (
        f"{_CONFIRM_MODAL_HTML}"
        f"<input type='hidden' id='_csrfField' value='{html.escape(csrf_token)}'>"
        f"<div class='service-slide-viewport'>"
        f"<div class='service-slide-track' id='serviceSlideTrack'>"
        f"<div class='service-slide-list'>"
        f"{_page_header}"
        f"<p style='margin:0.5rem 0 0.85rem;color:var(--color-text-secondary);font-size:0.95rem;'>"
        f"Autostream can keep track of maintenance items for turntables, and remind you when a service item is due."
        f"</p>"
        + list_cards
        + "</div>"
        f"<div class='service-slide-detail'>"
        + detail_panels
        + "</div>"
        f"</div>"
        f"</div>"
        f"<script>{SERVICE_JS}</script>"
    )

    html_body = build_page_html(
        "Service",
        _body_html,
        extra_css=SERVICE_CSS,
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
