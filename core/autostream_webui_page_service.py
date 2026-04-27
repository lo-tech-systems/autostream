#!/usr/bin/env python3
"""autostream_webui_page_service.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Page renderer for the /service route.

Responsibilities:
  - Render the Service page: per-input maintenance tracking configuration
    (stylus, drive belt, main bearing oil), usage reporting, and reset actions.
  - No PIN required; /service is in the auth allowlist.
  - Settings are saved automatically via POST /api/service/config (AJAX).
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from autostream_config import (
    parse_config,
    VALID_STYLUS_LIFE_HOURS,
    VALID_MAINTENANCE_LIFE_HOURS,
    VALID_BEARING_LIFE_HOURS,
    VALID_MAINTENANCE_LIFE_YEARS,
)
from autostream_core import get_playback_snapshot
from autostream_playback_stats import InputPlaybackSnapshot, format_hours

from autostream_webui_assets import BANNER_HTML, PIN_MODAL_CSS

from autostream_webui_common import (
    _fallback_input_snapshot,
    build_page_html,
    build_top_banner_html,
    locked_load_config,
)

from autostream_webui_state import WebUIState


# -----------------------------------------------------------------------------
# Module-level constants (CSS, HTML fragments, JavaScript)
# -----------------------------------------------------------------------------

_SERVICE_CSS = (
    ".service-slide-viewport { overflow: hidden; width: 100%; }\n"
    ".service-slide-track { display: flex; width: 200%;"
    " transition: transform 0.35s cubic-bezier(0.4, 0, 0.2, 1); }\n"
    ".service-slide-track.panel-detail { transform: translateX(-50%); }\n"
    ".service-slide-list, .service-slide-detail"
    " { width: 50%; flex-shrink: 0; min-width: 0; }\n"
    ".service-divider { border: none; border-top: 1px solid var(--color-border-nav); margin: 0.4rem 0; }\n"
    "#svcConfirmModal{position:fixed;inset:0;display:none;align-items:center;justify-content:center;"
    "background:rgba(0,0,0,.45);z-index:9999;padding:1.25rem;}\n"
    "#svcConfirmModal.show{display:flex;}\n"
    "#svcConfirmModal .panel{width:min(22rem,100%);background:var(--color-surface);border-radius:16px;"
    "box-shadow:0 10px 30px rgba(0,0,0,.25);overflow:hidden;}\n"
    "#svcConfirmModal .hdr{padding:0.9rem 1rem;border-bottom:1px solid var(--color-border-nav);font-weight:700;}\n"
    "#svcConfirmModal .ft{display:flex;gap:.75rem;padding:0.9rem 1rem;border-top:1px solid var(--color-border-nav);}\n"
    "#svcConfirmModal .btn{flex:1;border:none;border-radius:999px;padding:.8rem .9rem;font-weight:700;"
    "font-size:1rem;background:var(--color-btn-bg);color:#fff;box-shadow:0 2px 6px rgba(0,0,0,0.05);}\n"
    "#svcConfirmModal .btn.cancel{background:var(--color-surface-alt,rgba(128,128,128,0.25));color:var(--color-text);}\n"
    + PIN_MODAL_CSS
)

_CONFIRM_MODAL_HTML = (
    "<div id='svcConfirmModal' role='dialog' aria-modal='true' aria-labelledby='svcConfirmTitle'>"
    "<div class='panel'>"
    "<div class='hdr' id='svcConfirmTitle'>Confirm</div>"
    "<div class='ft'>"
    "<button type='button' class='btn cancel' id='svcConfirmCancel'>Cancel</button>"
    "<button type='button' class='btn ok' id='svcConfirmOk'>Yes</button>"
    "</div></div></div>"
)

# Plain string — no Python substitutions needed; CSRF token is read from DOM.
_SERVICE_JS = """
var _csrfToken = document.getElementById('_csrfField').value;

function openServiceDetail(item, idx) {
  document.querySelectorAll('.service-slide-detail .setup-detail-panel').forEach(function(p) {
    p.classList.remove('active');
  });
  var panel = document.getElementById('service-detail-' + item + '-' + idx);
  if (panel) panel.classList.add('active');
  document.getElementById('serviceSlideTrack').classList.add('panel-detail');
  window.scrollTo(0, 0);
}

function closeServiceDetail() {
  document.getElementById('serviceSlideTrack').classList.remove('panel-detail');
  window.scrollTo(0, 0);
}

function _autoSaveField(name, value) {
  fetch('/api/service/config', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken},
    body: JSON.stringify({field: name, value: value})
  }).catch(function() {});
}

function _updateMaintHours(item, idx) {
  var sel = document.querySelector('[name="service_' + item + '_life_hours_input' + idx + '"]');
  if (!sel) return;
  var lifeHours = parseInt(sel.value, 10);
  var playSecs = parseInt(sel.getAttribute('data-playback-seconds') || '0', 10);
  var liveDiv = document.getElementById(item + '-hours-live-' + idx);
  if (lifeHours === 0) {
    if (liveDiv) liveDiv.style.display = 'none';
    return;
  }
  if (liveDiv) liveDiv.style.display = '';
  var lifeSecs = lifeHours * 3600;
  var remSecs = Math.max(0, lifeSecs - playSecs);
  var remPct = Math.min(100, remSecs / lifeSecs * 100);
  var usedH = (Math.max(0, playSecs) / 3600).toFixed(1);
  var remH = (remSecs / 3600).toFixed(1);
  var remTxt = remSecs <= 0 ? 'Due now' : remH + ' h';
  var barStatus = remPct <= 10 ? 'critical' : (remPct <= 20 ? 'warning' : 'healthy');
  var warnColor = remPct <= 20 ? 'var(--color-status-danger)' : '';
  var el;
  el = document.getElementById(item + '-hours-bar-pct-' + idx);
  if (el) el.textContent = remPct.toFixed(1) + '%';
  el = document.getElementById(item + '-hours-bar-fill-' + idx);
  if (el) { el.style.width = remPct.toFixed(1) + '%'; el.setAttribute('data-status', barStatus); }
  el = document.getElementById(item + '-hours-used-val-' + idx);
  if (el) el.textContent = usedH + ' h / ' + lifeHours + ' h';
  el = document.getElementById(item + '-hours-remaining-val-' + idx);
  if (el) { el.textContent = remTxt; el.style.color = warnColor; }
}

function _updateMaintTime(item, idx) {
  var sel = document.querySelector('[name="service_' + item + '_life_years_input' + idx + '"]');
  if (!sel) return;
  var lifeYears = parseInt(sel.value, 10);
  var elapsedDays = parseInt(sel.getAttribute('data-elapsed-days') || '-1', 10);
  var serviceAt = sel.getAttribute('data-service-at') || '';
  var liveDiv = document.getElementById(item + '-time-live-' + idx);
  if (lifeYears === 0) {
    if (liveDiv) liveDiv.style.display = 'none';
    return;
  }
  if (liveDiv) liveDiv.style.display = '';
  var dueEl = document.getElementById(item + '-time-due-val-' + idx);
  if (dueEl && serviceAt) {
    try {
      var dueDate = new Date(serviceAt);
      dueDate.setDate(dueDate.getDate() + lifeYears * 365);
      dueEl.textContent = dueDate.toLocaleDateString();
    } catch(e) {}
  }
  if (elapsedDays < 0) return;
  var totalDays = lifeYears * 365;
  var remDays = Math.max(0, totalDays - elapsedDays);
  var remPct = Math.min(100, remDays / totalDays * 100);
  var barStatus = remPct <= 10 ? 'critical' : (remPct <= 20 ? 'warning' : 'healthy');
  var warnColor = remPct <= 20 ? 'var(--color-status-danger)' : '';
  var el;
  el = document.getElementById(item + '-time-bar-pct-' + idx);
  if (el) el.textContent = remPct.toFixed(1) + '%';
  el = document.getElementById(item + '-time-bar-fill-' + idx);
  if (el) { el.style.width = remPct.toFixed(1) + '%'; el.setAttribute('data-status', barStatus); }
  el = document.getElementById(item + '-time-remaining-val-' + idx);
  if (el) { el.textContent = remDays <= 0 ? 'Overdue' : (remDays + ' days remaining'); el.style.color = warnColor; }
}

function _updateResetBtnState(item, idx) {
  var hSel = document.querySelector('[name="service_' + item + '_life_hours_input' + idx + '"]');
  var ySel = document.querySelector('[name="service_' + item + '_life_years_input' + idx + '"]');
  var btn = document.getElementById(item + '-reset-btn-' + idx);
  if (!btn) return;
  var hOff = !hSel || parseInt(hSel.value, 10) === 0;
  var yOff = !ySel || parseInt(ySel.value, 10) === 0;
  btn.disabled = hOff && yOff;
}

function updateStylusStats(idx) { _updateMaintHours('stylus', idx); _updateResetBtnState('stylus', idx); }
function updateBeltStats(idx)   { _updateMaintHours('belt', idx);   _updateMaintTime('belt', idx);   _updateResetBtnState('belt', idx); }
function updateBearingStats(idx){ _updateMaintHours('bearing', idx); _updateMaintTime('bearing', idx); _updateResetBtnState('bearing', idx); }

function _showServiceConfirm(msg) {
  return new Promise(function(resolve) {
    var m = document.getElementById('svcConfirmModal');
    var title = document.getElementById('svcConfirmTitle');
    var btnOk = document.getElementById('svcConfirmOk');
    var btnCancel = document.getElementById('svcConfirmCancel');
    if (!m || !btnOk || !btnCancel) { resolve(true); return; }
    if (title) title.textContent = msg;
    m.classList.add('show');
    var cleanup = function(val) {
      m.classList.remove('show');
      btnOk.onclick = null; btnCancel.onclick = null;
      resolve(val);
    };
    btnCancel.onclick = function() { cleanup(false); };
    btnOk.onclick    = function() { cleanup(true);  };
  });
}

function doServiceReset(item, idx) {
  var labels = {
    stylus:  'Mark stylus as changed?',
    belt:    'Mark drive belt as replaced?',
    bearing: 'Mark bearing as oiled?'
  };
  var msg = labels[item] || 'Confirm reset?';
  _showServiceConfirm(msg).then(function(confirmed) {
    if (!confirmed) return;
    var btn = document.getElementById(item + '-reset-btn-' + idx);
    if (btn) btn.disabled = true;
    fetch('/api/service/reset', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken},
      body: JSON.stringify({item: item, input: idx})
    }).then(function(r) { return r.json(); }).then(function(d) {
      if (!d.ok) { if (btn) btn.disabled = false; return; }
      var hSel = document.querySelector('[name="service_' + item + '_life_hours_input' + idx + '"]');
      if (hSel) hSel.setAttribute('data-playback-seconds', '0');
      var ySel = document.querySelector('[name="service_' + item + '_life_years_input' + idx + '"]');
      if (ySel) {
        ySel.setAttribute('data-elapsed-days', '0');
        ySel.setAttribute('data-service-at', d.last_service_at || '');
      }
      var dateKey = item === 'stylus' ? 'stylus-last-service-val-' : item + '-last-service-val-';
      var dateEl = document.getElementById(dateKey + idx);
      if (dateEl && d.last_service_at) {
        try { var dt = new Date(d.last_service_at); dateEl.textContent = dt.toLocaleDateString(); }
        catch(e) { dateEl.textContent = d.last_service_at; }
      }
      var ageEl = document.getElementById(item + '-time-age-val-' + idx);
      if (ageEl) ageEl.textContent = '0 months';
      var card = document.getElementById('svc-list-card-' + item + '-' + idx);
      if (card) {
        card.style.borderColor = '';
        var cardTitle = card.querySelector('.setup-list-card-title');
        if (cardTitle) cardTitle.style.color = '';
        var cardChevron = card.querySelector('.setup-list-chevron');
        if (cardChevron) cardChevron.style.color = '';
        var cardSub = card.querySelector('.setup-list-card-sub');
        if (cardSub) cardSub.textContent = 'Tracking on';
      }
      if (item === 'stylus') {
        _updateMaintHours('stylus', idx);
        _updateResetBtnState('stylus', idx);
      } else {
        _updateMaintHours(item, idx);
        _updateMaintTime(item, idx);
        _updateResetBtnState(item, idx);
      }
      if (btn) {
        btn.style.borderColor = ''; btn.style.background = ''; btn.style.color = '';
        btn.disabled = false;
      }
    }).catch(function() { if (btn) btn.disabled = false; });
  });
}
"""


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
    is_turntable = bool(audio.is_turntable)
    stylus_life = int(audio.stylus_life_hours)
    belt_hours  = int(audio.belt_life_hours)
    belt_years  = int(audio.belt_life_years)
    bearing_hours = int(audio.bearing_life_hours)
    bearing_years = int(audio.bearing_life_years)

    stylus_warn = is_turntable and (snap.stylus_warning or snap.stylus_overdue)
    belt_warn = is_turntable and (
        snap.belt_hours_overdue or snap.belt_time_overdue
        or snap.belt_hours_warning or snap.belt_time_warning
    )
    bearing_warn = is_turntable and (
        snap.bearing_hours_overdue or snap.bearing_time_overdue
        or snap.bearing_hours_warning or snap.bearing_time_warning
    )

    stylus_sub  = _stylus_card_sub(snap, stylus_life, is_turntable)
    belt_sub    = _maint_card_sub(snap, "belt",    belt_hours,    belt_years,    is_turntable)
    bearing_sub = _maint_card_sub(snap, "bearing", bearing_hours, bearing_years, is_turntable)

    title = f"Input {input_index}"
    stylus_html = _stylus_panel_html(
        input_index=input_index, title=title,
        is_turntable=is_turntable, snapshot=snap, stylus_life_hours=stylus_life,
    )
    belt_html = _maintenance_item_panel_html(
        input_index=input_index, item="belt", legend="Drive Belt",
        is_turntable=is_turntable, life_hours=belt_hours, life_years=belt_years,
        playback_seconds=int(snap.belt_playback_seconds),
        elapsed_days=snap.belt_elapsed_days, last_service_at=snap.last_belt_service_at,
        hours_overdue=snap.belt_hours_overdue, hours_warning=snap.belt_hours_warning,
        time_overdue=snap.belt_time_overdue,  time_warning=snap.belt_time_warning,
    )
    bearing_html = _maintenance_item_panel_html(
        input_index=input_index, item="bearing", legend="Main Bearing Oil",
        is_turntable=is_turntable, life_hours=bearing_hours, life_years=bearing_years,
        playback_seconds=int(snap.bearing_playback_seconds),
        elapsed_days=snap.bearing_elapsed_days, last_service_at=snap.last_bearing_service_at,
        hours_overdue=snap.bearing_hours_overdue, hours_warning=snap.bearing_hours_warning,
        time_overdue=snap.bearing_time_overdue,   time_warning=snap.bearing_time_warning,
        life_hours_options=VALID_BEARING_LIFE_HOURS,
    )

    return _InputRenderData(
        is_turntable=is_turntable,
        cards_disabled=not is_turntable,
        stylus_warn=stylus_warn,
        belt_warn=belt_warn,
        bearing_warn=bearing_warn,
        stylus_sub=stylus_sub,
        belt_sub=belt_sub,
        bearing_sub=bearing_sub,
        stylus_html=stylus_html,
        belt_html=belt_html,
        bearing_html=bearing_html,
    )


# -----------------------------------------------------------------------------
# Formatting helpers
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


def _format_elapsed_days(days: Optional[int]) -> str:
    """Return a human-readable elapsed time string from a day count (used for remaining-time labels)."""
    if days is None:
        return "Unknown"
    if days == 0:
        return "Today"
    if days < 30:
        return f"{days} day{'s' if days != 1 else ''}"
    if days < 365:
        months = days // 30
        return f"~{months} month{'s' if months != 1 else ''}"
    years = days // 365
    remaining_months = (days - years * 365) // 30
    if remaining_months > 0:
        return f"{years} yr {remaining_months} mo"
    return f"{years} year{'s' if years != 1 else ''}"


def _format_age_months(days: Optional[int]) -> str:
    """Return a month count string for the maintenance Age display."""
    if days is None:
        return "Unknown"
    months = days // 30
    return f"{months} month{'s' if months != 1 else ''}"


def _format_due_date(service_at: Optional[str], life_years: int) -> str:
    """Return an approximate due date string from a service timestamp and threshold."""
    if not service_at or life_years <= 0:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(str(service_at))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        due = dt + timedelta(days=life_years * 365)
        try:
            return due.astimezone().strftime("%x")
        except Exception:
            return due.strftime("%x")
    except Exception:
        return "Unknown"


# -----------------------------------------------------------------------------
# HTML fragment helpers
# -----------------------------------------------------------------------------

def _tracking_selector_html(
    name: str,
    current_life_hours: int,
    *,
    input_index: int = 0,
    playback_seconds: int = 0,
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
        f"data-playback-seconds='{playback_seconds}' "
        f"onchange='updateStylusStats({input_index});_autoSaveField(this.name,this.value)'>{opts}</select>"
        f"</label>"
    )


def _maintenance_hours_selector_html(
    name: str,
    current_hours: int,
    *,
    input_index: int,
    item: str,
    playback_seconds: int,
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
        f"data-playback-seconds='{playback_seconds}' "
        f"onchange='update{item.capitalize()}Stats({input_index});_autoSaveField(this.name,this.value)'>{opts}</select>"
        f"</label>"
    )


def _maintenance_years_selector_html(
    name: str,
    current_years: int,
    *,
    input_index: int,
    item: str,
    elapsed_days: Optional[int],
    label: str,
    service_at: Optional[str] = None,
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
    elapsed_attr = str(elapsed_days) if elapsed_days is not None else "-1"
    service_at_attr = html.escape(str(service_at or ""))
    return (
        f"<label style='display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;'>"
        f"<span style='min-width:6rem;'>{html.escape(label)}</span>"
        f"<select name='{name}' style='flex:1;' "
        f"data-elapsed-days='{elapsed_attr}' "
        f"data-service-at='{service_at_attr}' "
        f"onchange='update{item.capitalize()}Stats({input_index});_autoSaveField(this.name,this.value)'>{opts}</select>"
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
    playback_seconds: int,
    elapsed_days: Optional[int],
    last_service_at: Optional[str],
    hours_overdue: bool,
    hours_warning: bool,
    time_overdue: bool,
    time_warning: bool,
    life_hours_options: tuple = VALID_MAINTENANCE_LIFE_HOURS,
) -> str:
    """Render one maintenance fieldset (belt or bearing) for an input."""
    if not is_turntable:
        return (
            f"<fieldset><legend>{html.escape(legend)}</legend>"
            f"<p style='margin:0.5rem 0;color:var(--color-text-secondary);font-size:0.95rem;'>"
            f"Set this input to Turntable in Setup to enable maintenance tracking."
            f"</p></fieldset>"
        )

    hours_name = f"service_{item}_life_hours_input{input_index}"
    years_name = f"service_{item}_life_years_input{input_index}"

    hours_tracking_off = life_hours == 0
    years_tracking_off = life_years == 0
    warn_state = hours_overdue or hours_warning or time_overdue or time_warning

    # ── Hours selector + live section ─────────────────────────────────────────
    hours_selector = _maintenance_hours_selector_html(
        hours_name, life_hours,
        input_index=input_index,
        item=item,
        playback_seconds=playback_seconds,
        label="Hours Life",
        options=life_hours_options,
    )

    hours_live_display = "display:none;" if hours_tracking_off else ""
    _life_for_calc = life_hours if life_hours > 0 else next((h for h in life_hours_options if h > 0), 1000)
    _rem_secs = max(0, (_life_for_calc * 3600) - playback_seconds)
    _rem_pct = min(100.0, (_rem_secs / max(1, _life_for_calc * 3600)) * 100.0)
    _bar_status = "critical" if _rem_pct <= 10.0 else ("warning" if _rem_pct <= 20.0 else "healthy")
    hours_warn_state = not hours_tracking_off and (hours_overdue or hours_warning)

    hours_live_html = (
        f"<div id='{item}-hours-live-{input_index}' style='{hours_live_display}'>"
        f"<div class='bar-label' style='font-size:0.95rem;'>"
        f"<span>Life Remaining:</span>"
        f" <span id='{item}-hours-bar-pct-{input_index}'>{_rem_pct:.1f}%</span>"
        f"</div>"
        f"<div class='storage-bar' style='margin-bottom:0.5rem;'>"
        f"<div id='{item}-hours-bar-fill-{input_index}' class='used'"
        f" style='width:{_rem_pct:.1f}%;' data-status='{_bar_status}'></div>"
        f"</div>"
        f"<div style='margin-bottom:0.5rem;font-size:0.95rem;'>"
        + _summary_row(
            "Used",
            f"{html.escape(format_hours(playback_seconds))} / {_life_for_calc} h",
            value_id=f"{item}-hours-used-val-{input_index}",
        )
        + _summary_row(
            "Remaining",
            html.escape("Due now" if _rem_secs <= 0 else format_hours(_rem_secs)),
            warn=hours_warn_state,
            value_id=f"{item}-hours-remaining-val-{input_index}",
        )
        + "</div></div>"
    )

    # ── Years selector + live section ─────────────────────────────────────────
    years_selector = _maintenance_years_selector_html(
        years_name, life_years,
        input_index=input_index,
        item=item,
        elapsed_days=elapsed_days,
        label="Time Life",
        service_at=last_service_at,
    )

    years_live_display = "display:none;" if years_tracking_off else ""
    time_warn_state = not years_tracking_off and (time_overdue or time_warning)

    if elapsed_days is not None and life_years > 0:
        _total_days = life_years * 365
        _rem_days = max(0, _total_days - elapsed_days)
        _time_rem_pct = min(100.0, (_rem_days / max(1, _total_days)) * 100.0)
        _time_bar_status = "critical" if _time_rem_pct <= 10.0 else ("warning" if _time_rem_pct <= 20.0 else "healthy")
        elapsed_txt = _format_age_months(elapsed_days)
        due_date_txt = _format_due_date(last_service_at, life_years)
        _time_rem_label = "Overdue" if _rem_days == 0 else _format_elapsed_days(_rem_days) + " remaining"
    elif life_years > 0:
        _time_rem_pct = 100.0
        _time_bar_status = "healthy"
        elapsed_txt = "Not recorded"
        due_date_txt = "Not set"
        _time_rem_label = f"{life_years} year{'s' if life_years != 1 else ''} remaining"
    else:
        _time_rem_pct = 100.0
        _time_bar_status = "healthy"
        elapsed_txt = "N/A"
        due_date_txt = "N/A"
        _time_rem_label = "N/A"

    years_live_html = (
        f"<div id='{item}-time-live-{input_index}' style='{years_live_display}'>"
        f"<div class='bar-label' style='font-size:0.95rem;'>"
        f"<span>Time Remaining:</span>"
        f" <span id='{item}-time-bar-pct-{input_index}'>{_time_rem_pct:.1f}%</span>"
        f"</div>"
        f"<div class='storage-bar' style='margin-bottom:0.5rem;'>"
        f"<div id='{item}-time-bar-fill-{input_index}' class='used'"
        f" style='width:{_time_rem_pct:.1f}%;' data-status='{_time_bar_status}'></div>"
        f"</div>"
        f"<div style='margin-bottom:0.5rem;font-size:0.95rem;'>"
        + _summary_row("Age", html.escape(elapsed_txt), value_id=f"{item}-time-age-val-{input_index}")
        + _summary_row("Remaining", html.escape(_time_rem_label), warn=time_warn_state,
                       value_id=f"{item}-time-remaining-val-{input_index}")
        + _summary_row("Due", html.escape(due_date_txt), value_id=f"{item}-time-due-val-{input_index}")
        + "</div></div>"
    )

    # ── Reset section ─────────────────────────────────────────────────────────
    reset_label = "Mark Belt Replaced" if item == "belt" else "Mark Bearing Oiled"
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
        f"<fieldset><legend>{html.escape(legend)}</legend>"
        f"{hours_selector}{hours_live_html}"
        f"<div style='margin-top:0.5rem;'>"
        f"{years_selector}{years_live_html}"
        f"</div>"
        f"{reset_html}"
        f"</fieldset>"
    )


def _stylus_panel_html(
    *,
    input_index: int,
    title: str,
    is_turntable: bool,
    snapshot: InputPlaybackSnapshot,
    stylus_life_hours: int,
) -> str:
    """Render the stylus wear tracking fieldset for one input."""
    life_name = f"service_stylus_life_hours_input{input_index}"
    panel_title = html.escape(title) + " Stylus Wear Tracking"

    if not is_turntable:
        return (
            f"<fieldset><legend>{panel_title}</legend>"
            f"<p style='margin:0.5rem 0;color:var(--color-text-secondary);font-size:0.95rem;'>"
            f"Set this input to Turntable in Setup to enable maintenance tracking."
            f"</p></fieldset>"
        )

    playback_secs = int(snapshot.stylus_playback_seconds)
    tracking_off = stylus_life_hours == 0
    _life_for_calc = stylus_life_hours if stylus_life_hours > 0 else VALID_STYLUS_LIFE_HOURS[0]
    _remaining_seconds = snapshot.stylus_remaining_seconds
    if _remaining_seconds is None or tracking_off:
        _remaining_seconds = (_life_for_calc * 3600) - playback_secs
    _remaining_seconds = max(0, _remaining_seconds)
    _remaining_pct = min(100.0, (_remaining_seconds / max(1, _life_for_calc * 3600)) * 100.0)
    _bar_status = "critical" if _remaining_pct <= 10.0 else ("warning" if _remaining_pct <= 20.0 else "healthy")
    warn_state = not tracking_off and (snapshot.stylus_overdue or snapshot.stylus_warning)

    live_display = "display:none;" if tracking_off else ""
    active_row = ""
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
        f" <span id='stylus-hours-bar-pct-{input_index}'>{_remaining_pct:.1f}%</span>"
        f"</div>"
        f"<div class='storage-bar' style='margin-bottom:0.75rem;'>"
        f"<div id='stylus-hours-bar-fill-{input_index}' class='used'"
        f" style='width:{_remaining_pct:.1f}%;' data-status='{_bar_status}'></div>"
        f"</div>"
        f"<div style='margin-bottom:0.75rem;font-size:0.95rem;'>"
        + _summary_row(
            "Used",
            f"{html.escape(format_hours(playback_secs))} / {_life_for_calc} h",
            value_id=f"stylus-hours-used-val-{input_index}",
        )
        + _summary_row(
            "Remaining",
            html.escape("Due now" if _remaining_seconds <= 0 else format_hours(_remaining_seconds)),
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
        f"<fieldset><legend>{panel_title}</legend>"
        + _tracking_selector_html(
            life_name, stylus_life_hours,
            input_index=input_index,
            playback_seconds=playback_secs,
        )
        + live_html
        + f"</fieldset>"
    )


def _stylus_card_sub(snapshot: InputPlaybackSnapshot, life_hours: int, is_turntable: bool) -> str:
    """Return sub-text for a stylus list card."""
    if not is_turntable:
        return "Not a turntable"
    if life_hours == 0:
        return "Tracking off"
    if snapshot.stylus_overdue:
        return "Stylus due now"
    if snapshot.stylus_warning:
        remaining_secs = snapshot.stylus_remaining_seconds
        if remaining_secs is not None:
            return f"Stylus due soon ({format_hours(remaining_secs)} left)"
        return "Stylus due soon"
    return "Tracking on"


def _maint_card_sub(
    snapshot: InputPlaybackSnapshot,
    item: str,
    life_hours: int,
    life_years: int,
    is_turntable: bool,
) -> str:
    """Return sub-text for a belt or bearing list card."""
    if not is_turntable:
        return "Not a turntable"
    if item == "belt":
        overdue = snapshot.belt_hours_overdue or snapshot.belt_time_overdue
        warning = snapshot.belt_hours_warning or snapshot.belt_time_warning
    else:
        overdue = snapshot.bearing_hours_overdue or snapshot.bearing_time_overdue
        warning = snapshot.bearing_hours_warning or snapshot.bearing_time_warning

    if life_hours == 0 and life_years == 0:
        return "Tracking off"
    if overdue:
        return "Service due now"
    if warning:
        return "Service due soon"
    return "Tracking on"


def _service_list_card(item: str, idx: int, title: str, sub: str, warn: bool, disabled: bool) -> str:
    """Render one list card in pane 1 that navigates to the detail panel."""
    if disabled:
        return (
            f"<div class='setup-list-card'"
            f" style='opacity:0.55;pointer-events:none;cursor:default;'>"
            f"<div class='setup-list-card-body'>"
            f"<span class='setup-list-card-title'>{html.escape(title)}</span>"
            f"<span class='setup-list-card-sub'>{html.escape(sub)}</span>"
            f"</div></div>"
        )
    warn_border = "border-color:var(--color-status-danger);" if warn else ""
    warn_colour = " style='color:var(--color-status-danger);'" if warn else ""
    card_style = f" style='{warn_border}'" if warn_border else ""
    chevron = (
        f"<span class='setup-list-chevron'{warn_colour}>\u203a</span>"
    )
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

    if parsed is not None:
        d1 = _gather_input_render_data(parsed, playback_snapshot, 1, enabled=True)
        d2 = _gather_input_render_data(parsed, playback_snapshot, 2, enabled=bool(parsed.audio2_enabled))
    else:
        d1 = d2 = _UNAVAILABLE_INPUT

    _back = _back_bar()

    _body_html = (
        f"{BANNER_HTML}"
        f"{_CONFIRM_MODAL_HTML}"
        f"<input type='hidden' id='_csrfField' value='{html.escape(csrf_token)}'>"
        f"<div class='service-slide-viewport'>"
        f"<div class='service-slide-track' id='serviceSlideTrack'>"
        # ── Pane 1: flat 6-card list ──────────────────────────────────────────
        f"<div class='service-slide-list'>"
        f"<p style='margin:0.5rem 0 0.85rem;color:var(--color-text-secondary);font-size:0.95rem;'>"
        f"Autostream can keep track of maintenance items for turntables, and remind you when a service item is due."
        f"</p>"
        + _service_list_card("stylus",  1, "Input 1 Stylus Tracking",     d1.stylus_sub,  d1.stylus_warn,  d1.cards_disabled)
        + _service_list_card("belt",    1, "Input 1 Belt Tracking",        d1.belt_sub,    d1.belt_warn,    d1.cards_disabled)
        + _service_list_card("bearing", 1, "Input 1 Bearing Oil Tracking", d1.bearing_sub, d1.bearing_warn, d1.cards_disabled)
        + "<hr class='service-divider'>"
        + _service_list_card("stylus",  2, "Input 2 Stylus Tracking",     d2.stylus_sub,  d2.stylus_warn,  d2.cards_disabled)
        + _service_list_card("belt",    2, "Input 2 Belt Tracking",        d2.belt_sub,    d2.belt_warn,    d2.cards_disabled)
        + _service_list_card("bearing", 2, "Input 2 Bearing Oil Tracking", d2.bearing_sub, d2.bearing_warn, d2.cards_disabled)
        + "</div>"
        # ── Pane 2: detail panels ─────────────────────────────────────────────
        f"<div class='service-slide-detail'>"
        f"<div class='setup-detail-panel' id='service-detail-stylus-1'>"
        + _back + d1.stylus_html
        + "</div>"
        f"<div class='setup-detail-panel' id='service-detail-belt-1'>"
        + _back + d1.belt_html
        + "</div>"
        f"<div class='setup-detail-panel' id='service-detail-bearing-1'>"
        + _back + d1.bearing_html
        + "</div>"
        f"<div class='setup-detail-panel' id='service-detail-stylus-2'>"
        + _back + d2.stylus_html
        + "</div>"
        f"<div class='setup-detail-panel' id='service-detail-belt-2'>"
        + _back + d2.belt_html
        + "</div>"
        f"<div class='setup-detail-panel' id='service-detail-bearing-2'>"
        + _back + d2.bearing_html
        + "</div>"
        f"</div>"
        f"</div>"
        f"</div>"
        f"<script>{_SERVICE_JS}</script>"
    )

    html_body = build_page_html(
        "Service",
        _body_html,
        extra_css=_SERVICE_CSS,
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
