#!/usr/bin/env python3
"""autostream_webui_page_equaliser.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Page renderer for the /equaliser route.

Responsibilities:
  - Render the shared output Equaliser page: output gain, auto-trim toggle,
    live trim readout, and six parametric EQ band sliders.
  - No PIN required; /equaliser is in the auth allowlist.
  - Settings are saved automatically via POST /api/output_eq/config (AJAX).
  - Live trim status is polled every 2 seconds from GET /api/output_eq/status.
"""

from __future__ import annotations

import html
import json
import math
from typing import Optional

from autostream_appliances import get_all_appliances
from autostream_config import parse_config
from autostream_core import OUTPUT_PEQ_BANDS
from autostream_rpi import get_appliance_id
from autostream_sysutils import get_system_hostname
from autostream_webui_assets import APPLIANCE_SELECTOR_CSS
from autostream_webui_common import (
    build_appliance_selector_html,
    build_page_html,
    build_top_banner_html,
    locked_load_config,
)
from autostream_webui_state import WebUIState


def _build_eq_appliances_for_selector() -> list:
    """Return the bound-first appliance list for the equaliser selector widget."""
    local_id = get_appliance_id() or ""
    hostname = str(get_system_hostname() or "").strip()
    if hostname.lower().endswith(".local"):
        hostname = hostname[:-6]
    bound = {
        "id": local_id,
        "hostname": hostname.strip() or "autostream",
        "is_bound": True,
        "home_path": "/",
        "equaliser_path": "/equaliser",
    }
    peers = get_all_appliances()
    result = [bound]
    for s in peers:
        if s.id == local_id:
            continue
        peer_hostname = str(s.hostname or "").strip()
        if peer_hostname.lower().endswith(".local"):
            peer_hostname = peer_hostname[:-6]
        result.append({
            "id": s.id,
            "hostname": peer_hostname or "autostream",
            "is_bound": False,
            "home_path": f"/a/{s.id}/",
            "equaliser_path": f"/a/{s.id}/equaliser",
        })
    return result


# -----------------------------------------------------------------------------
# SVG curve constants — shared between _eq_curve_html() (Python geometry) and
# _EQUALISER_CURVE_JS (JavaScript evaluation).  Both must use identical values.
# -----------------------------------------------------------------------------
_CURVE_W        = 320      # SVG viewBox width  (px)
_CURVE_H        = 120      # SVG viewBox height (px)
_CURVE_F_MIN    = 20.0     # left edge frequency (Hz)
_CURVE_F_MAX    = 20000.0  # right edge frequency (Hz)
_CURVE_DB_RANGE = 12.0     # ± dB range shown
_CURVE_PAD_Y    = 3        # vertical padding (px) so ±12 dB paths aren't clipped
_CURVE_FS       = 44100    # sample rate used by autostream_monitor OUTPUT_RATE
_CURVE_N_PTS    = 200      # number of log-spaced frequency points in the path


def _cx(f: float) -> float:
    """Frequency → SVG x coordinate (log scale)."""
    return _CURVE_W * math.log(f / _CURVE_F_MIN) / math.log(_CURVE_F_MAX / _CURVE_F_MIN)


def _cy(db: float) -> float:
    """dB value → SVG y coordinate."""
    return _CURVE_H / 2.0 - db * (_CURVE_H / 2.0 - _CURVE_PAD_Y) / _CURVE_DB_RANGE


# -----------------------------------------------------------------------------
# JavaScript band-config serialiser
# -----------------------------------------------------------------------------

def _eq_band_config_js() -> str:
    """Return a JS const declaration embedding the static band parameters.

    The gain values are intentionally omitted here; they are read from the
    live slider elements at draw time so the curve always reflects the current
    UI state without a round-trip.
    """
    bands = [
        {"key": b["key"], "type": b["type"], "freq_hz": b["freq_hz"], "q": b["q"],
         "label": b.get("label", "")}
        for b in OUTPUT_PEQ_BANDS
    ]
    return f"var _EQ_BANDS = {json.dumps(bands)};\n"


# -----------------------------------------------------------------------------
# SVG frequency-response curve HTML
# -----------------------------------------------------------------------------

def _eq_curve_html() -> str:
    """Return the static SVG markup for the EQ frequency-response display.

    All dynamic elements (curve path, band handles) carry ids that
    _drawEqCurve() in _EQUALISER_CURVE_JS targets on every slider event.
    """
    W, H = _CURVE_W, _CURVE_H

    # 0 dB centre (X axis) and left edge (Y axis)
    y0 = f"{_cy(0):.1f}"
    axes = (
        f"<line x1='0' y1='{y0}' x2='{W}' y2='{y0}' class='eq-axis eq-axis-x'/>"
        f"<line x1='0' y1='0' x2='0' y2='{H}' class='eq-axis eq-axis-y'/>"
    )

    # Static handle circles at each band frequency
    handles: list[str] = []
    for band in OUTPUT_PEQ_BANDS:
        x = f"{_cx(band['freq_hz']):.1f}"
        handles.append(
            f"<circle id='eq-handle-{band['key']}' cx='{x}' cy='{y0}'"
            f" r='4' class='eq-handle'/>"
        )
    handle_svg = "".join(handles)

    # Gradient defs for glow fill below the curve
    defs = (
        "<defs>"
        "<linearGradient id='eq-glow-grad' x1='0' y1='0' x2='0' y2='1'>"
        "<stop offset='0%' class='eq-glow-stop-top'/>"
        "<stop offset='100%' class='eq-glow-stop-bottom'/>"
        "</linearGradient>"
        "</defs>"
    )

    return (
        f"<div class='eq-curve-wrap'>"
        f"<svg class='eq-curve-svg' viewBox='0 0 {W} {H}'"
        f" preserveAspectRatio='none' xmlns='http://www.w3.org/2000/svg'>"
        f"{defs}"
        f"<rect width='{W}' height='{H}' class='eq-curve-bg'/>"
        f"{axes}"
        f"<path id='eq-curve-fill' d='' class='eq-curve-fill'/>"
        f"<path id='eq-curve-path' d='' class='eq-curve-path'/>"
        f"{handle_svg}"
        f"</svg>"
        f"</div>"
    )


# -----------------------------------------------------------------------------
# HTML helpers
# -----------------------------------------------------------------------------

def _eq_cards_html(output_eq, selector_html: str = "") -> str:
    """Render the page header, Equaliser band card, and Gain card."""
    gain_db = float(output_eq.gain_db)
    auto_trim = bool(output_eq.auto_trim_enabled)
    checked = " checked" if auto_trim else ""

    # --- Page header: title + optional appliance selector ---
    page_header = (
        "<div class='eq-page-header'>"
        "<div style='display:flex;align-items:center;gap:0.5rem;'>"
        "<h1>Equaliser</h1>"
        "</div>"
        f"{selector_html}"
        "</div>"
    )

    # --- Equaliser card: vertical band sliders ---
    band_cols = ""
    for band in OUTPUT_PEQ_BANDS:
        key = band["key"]
        label = html.escape(band["label"])
        val = float(getattr(output_eq, key))
        sign = "+" if val > 0 else ""
        band_cols += (
            "<div class='eq-band'>"
            f"<span class='eq-band-freq'>{label}</span>"
            f"<input type='range' class='eq-band-slider' min='-12' max='12' step='1'"
            f" id='{key}' value='{val:.0f}'"
            f" oninput=\"syncOutputPeq('{key}', this.value)\">"
            f"<span class='eq-band-val' id='{key}_val'>{sign}{val:.0f} dB</span>"
            "</div>"
        )
    eq_card = (
        "<div class='eq-section'>"
        "<div class='eq-section-header'>"
        "<span></span>"
        "<button class='pill-btn small' id='eq-flat-btn' onclick='resetEq()'>Flat</button>"
        "</div>"
        + _eq_curve_html()
        + "<div class='eq-bands-wrap'>"
        f"<div class='eq-bands-row'>{band_cols}</div>"
        "</div>"
        "</div>"
    )

    # --- Gain card: auto-trim toggle + output gain slider ---
    trim_status_html = (
        f"<div class='eq-auto-trim-subtitle' id='output_trim_status'"
        f" style='display:none;'></div>"
    ) if not auto_trim else (
        f"<div class='eq-auto-trim-subtitle' id='output_trim_status'>"
        f"Calculating\u2026</div>"
    )
    gain_sign = "+" if gain_db > 0 else ""
    gain_card = (
        "<div class='eq-section'>"
        "<div class='eq-auto-trim-row'>"
        "<div class='eq-auto-trim-labels'>"
        "<div class='eq-auto-trim-title'>Automatically trim gain</div>"
        "<div class='eq-auto-trim-subtitle'>"
        "Prevent clipping by adjusting output level automatically</div>"
        f"{trim_status_html}"
        "</div>"
        "<label class='output-toggle' style='flex-shrink:0;margin-top:2px;'>"
        f"<input type='checkbox' id='output_auto_trim'{checked}"
        " onchange='setOutputAutoTrim(this.checked)'>"
        "<span class='switch'></span>"
        "</label>"
        "</div>"
        "<div class='eq-gain-row'>"
        "<span class='eq-gain-label'>Output gain</span>"
        f"<span class='eq-gain-value' id='output_gain_db_val'>{gain_sign}{gain_db:.1f} dB</span>"
        "</div>"
        f"<input type='range' min='-12' max='12' step='0.5' id='output_gain_db'"
        f" value='{gain_db:.1f}' oninput=\"syncOutputGain(this.value)\">"
        "<div class='eq-gain-ticks'>"
        "<span>-12 dB</span><span>0 dB</span><span>+12 dB</span>"
        "</div>"
        "</div>"
    )

    return page_header + eq_card + gain_card


# -----------------------------------------------------------------------------
# EQ curve JavaScript — biquad math + SVG draw
# -----------------------------------------------------------------------------
# Uses f-string so _CURVE_* Python constants are embedded directly, keeping
# the JS and Python geometry in sync without any runtime injection.

_EQUALISER_CURVE_JS = f"""
// ── EQ frequency-response curve ─────────────────────────────────────────────
// Constants mirror the Python _CURVE_* values in this module.
var _EQ_FS        = {_CURVE_FS};
var _SVG_W        = {_CURVE_W};
var _SVG_H        = {_CURVE_H};
var _SVG_F_MIN    = {_CURVE_F_MIN};
var _SVG_F_MAX    = {_CURVE_F_MAX};
var _SVG_DB_RANGE = {_CURVE_DB_RANGE};
var _SVG_PAD_Y    = {_CURVE_PAD_Y};
var _SVG_N_PTS    = {_CURVE_N_PTS};

function _freqToX(f) {{
  return _SVG_W * Math.log(f / _SVG_F_MIN) / Math.log(_SVG_F_MAX / _SVG_F_MIN);
}}

function _dbToY(db) {{
  var c = Math.max(-_SVG_DB_RANGE, Math.min(_SVG_DB_RANGE, db));
  return _SVG_H / 2 - c * (_SVG_H / 2 - _SVG_PAD_Y) / _SVG_DB_RANGE;
}}

// RBJ Audio EQ Cookbook biquad coefficients.
// Mirrors BiquadFilter::configure() in autostream_monitor_dsp.cpp exactly.
function _biquadCoeffs(type, f0, q, gainDb) {{
  var A      = Math.pow(10.0, gainDb / 40.0);
  var w0     = 2.0 * Math.PI * f0 / _EQ_FS;
  var cos_w0 = Math.cos(w0);
  var sin_w0 = Math.sin(w0);
  var alpha  = sin_w0 / (2.0 * q);
  var b0, b1, b2, a0, a1, a2;
  if (type === 'peak') {{
    b0 = 1.0 + alpha * A;  b1 = -2.0 * cos_w0;  b2 = 1.0 - alpha * A;
    a0 = 1.0 + alpha / A;  a1 = -2.0 * cos_w0;  a2 = 1.0 - alpha / A;
  }} else if (type === 'low_shelf') {{
    var t = 2.0 * Math.sqrt(A) * alpha;
    b0 =      A * ((A+1) - (A-1)*cos_w0 + t);
    b1 =  2*A   * ((A-1) - (A+1)*cos_w0    );
    b2 =      A * ((A+1) - (A-1)*cos_w0 - t);
    a0 =          ((A+1) + (A-1)*cos_w0 + t);
    a1 = -2.0   * ((A-1) + (A+1)*cos_w0    );
    a2 =          ((A+1) + (A-1)*cos_w0 - t);
  }} else if (type === 'high_shelf') {{
    var t = 2.0 * Math.sqrt(A) * alpha;
    b0 =      A * ((A+1) + (A-1)*cos_w0 + t);
    b1 = -2*A   * ((A-1) + (A+1)*cos_w0    );
    b2 =      A * ((A+1) + (A-1)*cos_w0 - t);
    a0 =          ((A+1) - (A-1)*cos_w0 + t);
    a1 =  2.0   * ((A-1) - (A+1)*cos_w0    );
    a2 =          ((A+1) - (A-1)*cos_w0 - t);
  }} else {{
    // Unity passthrough
    return {{b0:1, b1:0, b2:0, a1:0, a2:0}};
  }}
  return {{b0:b0/a0, b1:b1/a0, b2:b2/a0, a1:a1/a0, a2:a2/a0}};
}}

// Magnitude response in dB of a normalised biquad at frequency f Hz.
function _biquadMagDb(c, f) {{
  var w   = 2.0 * Math.PI * f / _EQ_FS;
  var cw  = Math.cos(w),  c2w = Math.cos(2*w);
  var sw  = Math.sin(w),  s2w = Math.sin(2*w);
  var nr  = c.b0 + c.b1*cw  + c.b2*c2w;
  var ni  =      -(c.b1*sw  + c.b2*s2w);
  var dr  = 1.0  + c.a1*cw  + c.a2*c2w;
  var di  =      -(c.a1*sw  + c.a2*s2w);
  var m2  = (nr*nr + ni*ni) / Math.max(dr*dr + di*di, 1e-30);
  return 10.0 * Math.log(m2) / Math.LN10;
}}

function _drawEqCurve() {{
  var pathEl = document.getElementById('eq-curve-path');
  if (!pathEl || typeof _EQ_BANDS === 'undefined') return;

  // Build normalised biquad coefficients for every band from current slider values.
  var coeffs = _EQ_BANDS.map(function(b) {{
    var sl = document.getElementById(b.key);
    return _biquadCoeffs(b.type, b.freq_hz, b.q, sl ? parseFloat(sl.value) : 0.0);
  }});

  // Evaluate total dB at _SVG_N_PTS log-spaced frequencies and build SVG path.
  var d = '';
  for (var i = 0; i <= _SVG_N_PTS; i++) {{
    var f  = _SVG_F_MIN * Math.pow(_SVG_F_MAX / _SVG_F_MIN, i / _SVG_N_PTS);
    var db = 0.0;
    for (var j = 0; j < coeffs.length; j++) {{ db += _biquadMagDb(coeffs[j], f); }}
    var px = _freqToX(f), py = _dbToY(db);
    d += (i === 0 ? 'M' : 'L') + px.toFixed(2) + ' ' + py.toFixed(2);
  }}
  pathEl.setAttribute('d', d);

  // Update glow fill — same path closed down to the bottom of the SVG.
  var fillEl = document.getElementById('eq-curve-fill');
  if (fillEl) {{
    fillEl.setAttribute('d', d + ' L' + _SVG_W + ' ' + _SVG_H + ' L0 ' + _SVG_H + ' Z');
  }}

  // Move each handle to the total curve magnitude at its band's centre frequency.
  _EQ_BANDS.forEach(function(b, i) {{
    var handle = document.getElementById('eq-handle-' + b.key);
    if (!handle) return;
    var db = 0.0;
    for (var j = 0; j < coeffs.length; j++) {{ db += _biquadMagDb(coeffs[j], b.freq_hz); }}
    handle.setAttribute('cy', _dbToY(db).toFixed(2));
  }});
}}
"""


# -----------------------------------------------------------------------------
# Page JavaScript
# -----------------------------------------------------------------------------

_EQUALISER_JS = r"""
var _csrfToken = document.getElementById('_csrfField').value;
var _EQ_BAND_KEYS = ['peq1_db','peq2_db','peq3_db','peq4_db','peq5_db','peq6_db'];

function _fmtDb(v, decimals) {
  var s = v.toFixed(decimals !== undefined ? decimals : 0);
  return (v > 0 ? '+' : '') + s + ' dB';
}

function _saveEqField(field, value) {
  fetch('/api/output_eq/config', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken},
    body: JSON.stringify({field: field, value: value})
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (!d.ok) { console.warn('Output EQ save failed:', field, d.error); }
  }).catch(function(e) { console.warn('Output EQ save error:', e); });
}

function syncOutputGain(value) {
  var v = parseFloat(value);
  document.getElementById('output_gain_db_val').textContent = _fmtDb(v, 1);
  _saveEqField('gain_db', v);
}

function syncOutputPeq(key, value) {
  var v = parseInt(value, 10);
  document.getElementById(key + '_val').textContent = _fmtDb(v, 0);
  _saveEqField(key, v);
  _drawEqCurve();
}

function setOutputAutoTrim(enabled) {
  _saveEqField('auto_trim_enabled', enabled ? 'true' : 'false');
  var el = document.getElementById('output_trim_status');
  if (!el) return;
  if (!enabled) {
    el.style.display = 'none';
    el.textContent = '';
  } else {
    el.style.display = '';
    el.textContent = 'Calculating\u2026';
    _pollTrimStatus();
  }
}

function resetEq() {
  fetch('/api/output_eq/reset', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken},
    body: '{}'
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (!d.ok) { console.warn('EQ reset failed:', d.error); return; }
    _EQ_BAND_KEYS.forEach(function(key) {
      var slider = document.getElementById(key);
      if (slider) slider.value = 0;
      var val = document.getElementById(key + '_val');
      if (val) val.textContent = '0 dB';
    });
    var gainSlider = document.getElementById('output_gain_db');
    if (gainSlider) gainSlider.value = 0;
    var gainVal = document.getElementById('output_gain_db_val');
    if (gainVal) gainVal.textContent = '0.0 dB';
    _drawEqCurve();
  }).catch(function(e) { console.warn('EQ reset error:', e); });
}

function _pollTrimStatus() {
  fetch('/api/output_eq/status', {credentials: 'same-origin'})
    .then(function(r) { return r.json(); })
    .then(function(d) {
      var el = document.getElementById('output_trim_status');
      if (!el) return;
      var cb = document.getElementById('output_auto_trim');
      if (!cb || !cb.checked) { el.style.display = 'none'; el.textContent = ''; return; }
      el.style.display = '';
      if (!d.ok) { el.textContent = 'Auto-trim: unavailable'; return; }
      var db = parseFloat(d.output_auto_trim_db);
      el.textContent = 'Auto-trim: ' + db.toFixed(1) + ' dB applied';
    })
    .catch(function() {
      var el = document.getElementById('output_trim_status');
      if (el) { el.style.display = 'none'; el.textContent = ''; }
    });
}

document.addEventListener('DOMContentLoaded', function() {
  _pollTrimStatus();
  setInterval(_pollTrimStatus, 2000);
  _drawEqCurve();
  initApplianceSelector();
  refreshApplianceSelector();
  setInterval(function(){if(!document.hidden)refreshApplianceSelector();}, 15000);
  document.addEventListener('visibilitychange', function(){
    if(!document.hidden) refreshApplianceSelector();
  });
});

function initApplianceSelector(){
  var btn=document.getElementById('appliance-selector-btn');
  var dd=document.getElementById('appliance-selector-dropdown');
  if(!btn||!dd) return;
  btn.addEventListener('click',function(e){
    e.stopPropagation();
    var open=!dd.hidden;
    dd.hidden=open;
    btn.setAttribute('aria-expanded',String(!open));
    if(!open) refreshApplianceSelector();
  });
  document.addEventListener('click',function(){
    if(!dd.hidden){dd.hidden=true;btn.setAttribute('aria-expanded','false');}
  });
  dd.addEventListener('keydown',function(e){
    var opts=Array.from(dd.querySelectorAll('.appliance-selector-option'));
    var idx=opts.indexOf(document.activeElement);
    if(e.key==='ArrowDown'){e.preventDefault();var n=opts[idx+1]||opts[0];if(n)n.focus();}
    else if(e.key==='ArrowUp'){e.preventDefault();var p=opts[idx-1]||opts[opts.length-1];if(p)p.focus();}
    else if(e.key==='Escape'){dd.hidden=true;btn.setAttribute('aria-expanded','false');btn.focus();}
  });
}

function updateSelectorFromAppliances(appliances,currentId,currentPage){
  var dd=document.getElementById('appliance-selector-dropdown');
  var nameEl=document.getElementById('appliance-selector-current');
  if(!dd) return;
  dd.innerHTML='';
  var dividerAdded=false;
  appliances.forEach(function(a){
    var isBound=!!a.is_bound;
    if(!isBound&&!dividerAdded){
      dividerAdded=true;
      var divEl=document.createElement('div');
      divEl.className='appliance-selector-divider';
      divEl.setAttribute('role','separator');
      divEl.setAttribute('aria-hidden','true');
      dd.appendChild(divEl);
    }
    var href=currentPage==='equaliser'
      ?(a.equaliser_path||'/a/'+a.id+'/equaliser')
      :(a.home_path||(isBound?'/':'/a/'+a.id+'/'));
    var opt=document.createElement('a');
    opt.href=href;
    opt.setAttribute('role','option');
    opt.setAttribute('aria-selected',a.id===currentId?'true':'false');
    opt.className='appliance-selector-option'+(a.id===currentId?' appliance-selector-option-active':'');
    if(isBound) opt.style.fontWeight='700';
    opt.textContent=String(a.hostname||'autostream');
    dd.appendChild(opt);
  });
  var cur=appliances.find(function(a){return a.id===currentId;});
  if(nameEl&&cur) nameEl.textContent=String(cur.hostname||'autostream');
}

function refreshApplianceSelector(){
  fetch('/api/appliances',{cache:'no-store'})
    .then(function(r){return r.json();})
    .then(function(data){
      if(!data||!data.ok||!Array.isArray(data.appliances)) return;
      var el=document.getElementById('appliance-selector');
      var currentId=el?(el.getAttribute('data-current-id')||window.__LOCAL_ID||''):(window.__LOCAL_ID||'');
      var currentPage=el?(el.getAttribute('data-current-page')||'equaliser'):'equaliser';
      updateSelectorFromAppliances(data.appliances,currentId,currentPage);
    })
    .catch(function(){});
}
"""


# -----------------------------------------------------------------------------
# Page renderer
# -----------------------------------------------------------------------------

def send_equaliser_page(
    handler,
    state: WebUIState,
    flash_msg: Optional[str] = None,
    flash_type: str = "success",
) -> None:
    """Render and send the /equaliser page."""
    lic_html, lic_spacer = build_top_banner_html(flash_msg=flash_msg, flash_type=flash_type)

    parsed = None
    try:
        parsed = parse_config(locked_load_config(state.config_path))
    except Exception:
        pass

    csrf_token = getattr(handler, "_csrf_token", None) or ""
    dark_mode = parsed.webui.dark_mode if parsed is not None else False

    _local_appliances = _build_eq_appliances_for_selector()
    _local_id = str(get_appliance_id() or "")

    if parsed is not None:
        _show_hostname = parsed.webui.show_hostname_on_home
        _effective_control = _show_hostname and parsed.webui.control_other_appliances
        if _show_hostname:
            _selector_html = build_appliance_selector_html(
                _local_appliances, _local_id, "equaliser",
                display_only=not _effective_control,
            )
        else:
            _selector_html = ""
        card_html = _eq_cards_html(parsed.output_eq, selector_html=_selector_html)
    else:
        card_html = (
            "<p style='color:var(--color-text-secondary);'>"
            "Configuration unavailable.</p>"
        )

    _head_extra = (
        f"<script>window.__LOCAL_ID='{html.escape(_local_id)}';</script>"
    )

    body_html = (
        f"<input type='hidden' id='_csrfField' value='{html.escape(csrf_token)}'>"
        f"{card_html}"
        f"<script>"
        f"{_eq_band_config_js()}"
        f"{_EQUALISER_CURVE_JS}"
        f"{_EQUALISER_JS}"
        f"</script>"
    )

    page = build_page_html(
        "Equaliser",
        body_html,
        extra_css=APPLIANCE_SELECTOR_CSS,
        head_extra=_head_extra,
        lic_html=lic_html,
        lic_spacer=lic_spacer,
        active_tab="equaliser",
        dark_mode=dark_mode,
    )
    body_bytes = page.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)


# -----------------------------------------------------------------------------
# Remote Equaliser JS — plain string (no f-string), references window.__* vars
# set in head_extra of send_remote_equaliser_page.
# -----------------------------------------------------------------------------

_REMOTE_EQUALISER_SCRIPT = """<script>
var _EQ_BAND_KEYS=['peq1_db','peq2_db','peq3_db','peq4_db','peq5_db','peq6_db'];
var _eqWriteSeq={};
var _eqFailCount=0;
var _eqPollTimer=null;
var _eqPolling=true;
var __EQ_DEFINITIVE_ERRORS=['not_found','appliance_unconfigured','appliance_conflicted','appliance_identity_unavailable'];
var __EQ_TRANSPORT_ERRORS=['remote_timeout','remote_bad_response','appliance_offline'];

function _fmtDb(v,decimals){var s=v.toFixed(decimals!==undefined?decimals:0);return(v>0?'+':'')+s+' dB';}

function _eqRedirectWithFlash(msg){window.location.href='/?msg='+encodeURIComponent('error:'+msg);}

function _eqHandleError(error){
  var hostname=window.__REMOTE_HOSTNAME||'autostream';
  if(__EQ_DEFINITIVE_ERRORS.indexOf(error)>=0){
    var msgs={
      'not_found':'The selected appliance address is invalid. Returned to this appliance.',
      'appliance_unconfigured':hostname+' is not ready for remote control. Returned to this appliance.',
      'appliance_conflicted':hostname+' has a network identity conflict and cannot be selected safely. Returned to this appliance.',
      'appliance_identity_unavailable':hostname+' cannot currently provide multi-appliance access. Returned to this appliance.'
    };
    _eqRedirectWithFlash(msgs[error]||(hostname+' is unavailable. Returned to this appliance.'));
    return true;
  }
  if(__EQ_TRANSPORT_ERRORS.indexOf(error)>=0){
    _eqFailCount++;
    if(_eqFailCount>=3){_eqRedirectWithFlash(hostname+' is unavailable. Returned to this appliance.');return true;}
  }
  return false;
}

function _saveEqField(field,value){
  if(!_eqWriteSeq[field])_eqWriteSeq[field]=0;
  var seq=++_eqWriteSeq[field];
  fetch(window.__SAVE_URL,{
    method:'POST',credentials:'same-origin',
    signal:AbortSignal.timeout(5000),
    headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF||''},
    body:JSON.stringify({field:field,value:value})
  }).then(function(r){return r.json();}).then(function(d){
    if(_eqWriteSeq[field]!==seq)return;
    if(!d||!d.ok){var err=(d&&d.error)||'remote_bad_response';_eqHandleError(err);}
    else{_eqFailCount=0;}
  }).catch(function(e){
    if(_eqWriteSeq[field]!==seq)return;
    _eqFailCount++;
    if(_eqFailCount>=3)_eqRedirectWithFlash((window.__REMOTE_HOSTNAME||'autostream')+' is unavailable. Returned to this appliance.');
  });
}

function syncOutputGain(value){
  var v=parseFloat(value);
  var el=document.getElementById('output_gain_db_val');
  if(el)el.textContent=_fmtDb(v,1);
  _saveEqField('gain_db',v);
}

function syncOutputPeq(key,value){
  var v=parseInt(value,10);
  var el=document.getElementById(key+'_val');
  if(el)el.textContent=_fmtDb(v,0);
  _saveEqField(key,v);
  if(typeof _drawEqCurve==='function')_drawEqCurve();
}

function setOutputAutoTrim(enabled){
  _saveEqField('auto_trim_enabled',enabled?'true':'false');
  var el=document.getElementById('output_trim_status');
  if(!el)return;
  if(!enabled){el.style.display='none';el.textContent='';}
  else{el.style.display='';el.textContent='Calculating…';_pollTrimStatus();}
}

function resetEq(){
  fetch(window.__RESET_URL,{
    method:'POST',credentials:'same-origin',
    signal:AbortSignal.timeout(5000),
    headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF||''},
    body:'{}'
  }).then(function(r){return r.json();}).then(function(d){
    if(!d||!d.ok){var err=(d&&d.error)||'remote_bad_response';_eqHandleError(err);return;}
    _eqFailCount=0;
    _EQ_BAND_KEYS.forEach(function(key){
      var sl=document.getElementById(key);if(sl)sl.value=0;
      var vl=document.getElementById(key+'_val');if(vl)vl.textContent='0 dB';
    });
    var gs=document.getElementById('output_gain_db');if(gs)gs.value=0;
    var gv=document.getElementById('output_gain_db_val');if(gv)gv.textContent='0.0 dB';
    if(typeof _drawEqCurve==='function')_drawEqCurve();
  }).catch(function(){
    _eqFailCount++;
    if(_eqFailCount>=3)_eqRedirectWithFlash((window.__REMOTE_HOSTNAME||'autostream')+' is unavailable. Returned to this appliance.');
  });
}

function _pollTrimStatus(){
  fetch(window.__STATUS_URL,{credentials:'same-origin',signal:AbortSignal.timeout(5000)})
    .then(function(r){return r.json();})
    .then(function(d){
      if(!d||!d.ok){
        var err=(d&&d.error)||'remote_bad_response';
        if(err!=='remote_backoff')_eqHandleError(err);
        return;
      }
      _eqFailCount=0;
      var el=document.getElementById('output_trim_status');if(!el)return;
      var cb=document.getElementById('output_auto_trim');
      if(!cb||!cb.checked){el.style.display='none';el.textContent='';return;}
      el.style.display='';
      var db=parseFloat(d.output_auto_trim_db);
      el.textContent='Auto-trim: '+(Number.isFinite(db)?db.toFixed(1)+' dB applied':'unavailable');
    })
    .catch(function(){
      _eqFailCount++;
      if(_eqFailCount>=3)_eqRedirectWithFlash((window.__REMOTE_HOSTNAME||'autostream')+' is unavailable. Returned to this appliance.');
    });
}

function _scheduleEqPoll(){
  if(_eqPollTimer)clearTimeout(_eqPollTimer);
  _eqPollTimer=setTimeout(function(){
    if(!_eqPolling||document.hidden)return;
    _pollTrimStatus();
    _scheduleEqPoll();
  },3000);
}

function renderEqFromState(data){
  var bandContainer=document.getElementById('eq-bands-container');
  var gainSection=document.getElementById('eq-gain-section');
  var loading=document.getElementById('eq-loading-msg');
  var resetBtn=document.getElementById('eq-flat-btn');
  if(loading)loading.hidden=true;
  if(resetBtn)resetBtn.disabled=false;
  if(bandContainer&&!bandContainer.querySelector('input')&&typeof _EQ_BANDS!=='undefined'){
    bandContainer.innerHTML='';
    _EQ_BANDS.forEach(function(b){
      var key=b.key;var label=b.label||(b.freq_hz+' Hz');
      var val=data[key]!==undefined?parseFloat(data[key]):0;
      var sign=val>0?'+':'';
      var col=document.createElement('div');col.className='eq-band';
      col.innerHTML='<span class="eq-band-freq">'+label+'</span>'+
        '<input type="range" class="eq-band-slider" min="-12" max="12" step="1"'+
        ' id="'+key+'" value="'+val.toFixed(0)+'"'+
        ' oninput="syncOutputPeq(\\''+key+'\\',this.value)">'+
        '<span class="eq-band-val" id="'+key+'_val">'+sign+val.toFixed(0)+' dB</span>';
      bandContainer.appendChild(col);
    });
  }
  if(gainSection&&!gainSection.querySelector('input')){
    var gainDb=data.gain_db!==undefined?parseFloat(data.gain_db):0;
    var autoTrim=!!data.auto_trim_enabled;
    var gsign=gainDb>0?'+':'';
    gainSection.innerHTML=
      '<div class="eq-auto-trim-row">'+
      '<div class="eq-auto-trim-labels">'+
      '<div class="eq-auto-trim-title">Automatically trim gain</div>'+
      '<div class="eq-auto-trim-subtitle">Prevent clipping by adjusting output level automatically</div>'+
      '<div class="eq-auto-trim-subtitle" id="output_trim_status"'+(autoTrim?'':' style="display:none;"')+'>'+
      (autoTrim?'Calculating…':'')+
      '</div></div>'+
      '<label class="output-toggle" style="flex-shrink:0;margin-top:2px;">'+
      '<input type="checkbox" id="output_auto_trim"'+(autoTrim?' checked':'')+
      ' onchange="setOutputAutoTrim(this.checked)"><span class="switch"></span></label>'+
      '</div>'+
      '<div class="eq-gain-row">'+
      '<span class="eq-gain-label">Output gain</span>'+
      '<span class="eq-gain-value" id="output_gain_db_val">'+gsign+gainDb.toFixed(1)+' dB</span>'+
      '</div>'+
      '<input type="range" min="-12" max="12" step="0.5" id="output_gain_db"'+
      ' value="'+gainDb.toFixed(1)+'" oninput="syncOutputGain(this.value)">'+
      '<div class="eq-gain-ticks"><span>-12 dB</span><span>0 dB</span><span>+12 dB</span></div>';
  }
  if(typeof _drawEqCurve==='function')_drawEqCurve();
}

async function _loadInitialEqState(){
  try{
    var r=await fetch(window.__POLL_URL,{cache:'no-store',signal:AbortSignal.timeout(5000)});
    var data=await r.json();
    if(!data||!data.ok){var err=(data&&data.error)||'remote_bad_response';_eqHandleError(err);return;}
    _eqFailCount=0;
    renderEqFromState(data);
    var cb=document.getElementById('output_auto_trim');
    if(cb&&cb.checked)_pollTrimStatus();
    _scheduleEqPoll();
  }catch(e){
    _eqFailCount++;
    _eqRedirectWithFlash((window.__REMOTE_HOSTNAME||'autostream')+' is unavailable. Returned to this appliance.');
  }
}

function initApplianceSelector(){
  var btn=document.getElementById('appliance-selector-btn');
  var dd=document.getElementById('appliance-selector-dropdown');
  if(!btn||!dd)return;
  btn.addEventListener('click',function(e){
    e.stopPropagation();var open=!dd.hidden;dd.hidden=open;
    btn.setAttribute('aria-expanded',String(!open));
    if(!open)refreshApplianceSelector();
  });
  document.addEventListener('click',function(){
    if(!dd.hidden){dd.hidden=true;btn.setAttribute('aria-expanded','false');}
  });
  dd.addEventListener('keydown',function(e){
    var opts=Array.from(dd.querySelectorAll('.appliance-selector-option'));
    var idx=opts.indexOf(document.activeElement);
    if(e.key==='ArrowDown'){e.preventDefault();var n=opts[idx+1]||opts[0];if(n)n.focus();}
    else if(e.key==='ArrowUp'){e.preventDefault();var p=opts[idx-1]||opts[opts.length-1];if(p)p.focus();}
    else if(e.key==='Escape'){dd.hidden=true;btn.setAttribute('aria-expanded','false');btn.focus();}
  });
}
function updateSelectorFromAppliances(appliances,currentId,currentPage){
  var dd=document.getElementById('appliance-selector-dropdown');
  var nameEl=document.getElementById('appliance-selector-current');
  if(!dd)return;dd.innerHTML='';var dividerAdded=false;
  appliances.forEach(function(a){
    var isBound=!!a.is_bound;
    if(!isBound&&!dividerAdded){dividerAdded=true;var divEl=document.createElement('div');divEl.className='appliance-selector-divider';divEl.setAttribute('role','separator');divEl.setAttribute('aria-hidden','true');dd.appendChild(divEl);}
    var href=currentPage==='equaliser'?(a.equaliser_path||'/a/'+a.id+'/equaliser'):(a.home_path||(isBound?'/':'/a/'+a.id+'/'));
    var opt=document.createElement('a');opt.href=href;opt.setAttribute('role','option');
    opt.setAttribute('aria-selected',a.id===currentId?'true':'false');
    opt.className='appliance-selector-option'+(a.id===currentId?' appliance-selector-option-active':'');
    if(isBound)opt.style.fontWeight='700';opt.textContent=String(a.hostname||'autostream');dd.appendChild(opt);
  });
  var cur=appliances.find(function(a){return a.id===currentId;});
  if(nameEl&&cur)nameEl.textContent=String(cur.hostname||'autostream');
}
function refreshApplianceSelector(){
  fetch('/api/appliances',{cache:'no-store'})
    .then(function(r){return r.json();})
    .then(function(data){
      if(!data||!data.ok||!Array.isArray(data.appliances))return;
      var el=document.getElementById('appliance-selector');
      var currentId=el?(el.getAttribute('data-current-id')||window.__REMOTE_AID||''):(window.__REMOTE_AID||'');
      var currentPage=el?(el.getAttribute('data-current-page')||'equaliser'):'equaliser';
      updateSelectorFromAppliances(data.appliances,currentId,currentPage);
    }).catch(function(){});
}
window.addEventListener('DOMContentLoaded',function(){
  initApplianceSelector();refreshApplianceSelector();
  setInterval(function(){if(!document.hidden)refreshApplianceSelector();},15000);
  document.addEventListener('visibilitychange',function(){
    if(!document.hidden){_eqPolling=true;_eqFailCount=0;refreshApplianceSelector();}
    else{_eqPolling=false;if(_eqPollTimer){clearTimeout(_eqPollTimer);_eqPollTimer=null;}}
  });
  _loadInitialEqState();
});
</script>"""


# -----------------------------------------------------------------------------
# Remote Equaliser page renderer
# -----------------------------------------------------------------------------

def send_remote_equaliser_page(handler, state: WebUIState, appliance_id: str) -> None:
    """Render the remote Equaliser shell for a remote appliance.

    Serves a client-side loading shell.  JavaScript fetches
    /api/appliances/<id>/equaliser on DOMContentLoaded, renders the sliders,
    then polls /api/appliances/<id>/equaliser/status every 3 seconds.
    Writes go to /api/appliances/<id>/equaliser/config and
    /api/appliances/<id>/equaliser/reset via the gateway.
    After 3 consecutive transport failures the browser returns to /.
    Definitive errors return immediately to /.
    """
    try:
        cfg = locked_load_config(state.config_path)
        parsed = parse_config(cfg)
    except Exception:
        try:
            handler.send_error(500, "Configuration unavailable")
        except Exception:
            pass
        return

    csrf_token = getattr(handler, "_csrf_token", None) or ""
    dark_mode = parsed.webui.dark_mode

    appliances = _build_eq_appliances_for_selector()
    _local_id = str(get_appliance_id() or "")

    _remote_hostname = "autostream"
    for a in appliances:
        if a.get("id") == appliance_id:
            _remote_hostname = str(a.get("hostname") or "autostream")
            break

    poll_url = f"/api/appliances/{appliance_id}/equaliser"
    save_url = f"/api/appliances/{appliance_id}/equaliser/config"
    reset_url = f"/api/appliances/{appliance_id}/equaliser/reset"
    status_url = f"/api/appliances/{appliance_id}/equaliser/status"

    _selector_html = build_appliance_selector_html(appliances, appliance_id, "equaliser")

    _head_extra = (
        f"<meta name='csrf-token' content='{html.escape(csrf_token)}'>"
        f"<script>"
        f"window.__CSRF='{html.escape(csrf_token)}';"
        f"window.__POLL_URL='{html.escape(poll_url)}';"
        f"window.__SAVE_URL='{html.escape(save_url)}';"
        f"window.__RESET_URL='{html.escape(reset_url)}';"
        f"window.__STATUS_URL='{html.escape(status_url)}';"
        f"window.__REMOTE_AID='{html.escape(appliance_id)}';"
        f"window.__REMOTE_HOSTNAME='{html.escape(_remote_hostname)}';"
        f"window.__LOCAL_ID='{html.escape(_local_id)}';"
        f"</script>\n"
        + _REMOTE_EQUALISER_SCRIPT
    )

    page_header = (
        "<div class='eq-page-header'>"
        "<div style='display:flex;align-items:center;gap:0.5rem;'>"
        "<h1>Equaliser</h1>"
        "</div>"
        f"{_selector_html}"
        "</div>"
    )

    body_html = (
        f"<input type='hidden' id='_csrfField' value='{html.escape(csrf_token)}'>"
        + page_header
        + "<div class='eq-section'>"
        + "<div class='eq-section-header'>"
        + "<span></span>"
        + "<button class='pill-btn small' disabled id='eq-flat-btn' onclick='resetEq()'>Flat</button>"
        + "</div>"
        + _eq_curve_html()
        + "<div class='eq-bands-wrap'>"
        + "<div class='eq-bands-row' id='eq-bands-container'></div>"
        + "</div></div>"
        + "<div class='eq-section' id='eq-gain-section'></div>"
        + "<p id='eq-loading-msg' style='text-align:center;"
        "color:var(--color-text-muted,#888);padding:1.5rem 0;margin:0;'>Connecting…</p>"
        + f"<script>{_eq_band_config_js()}{_EQUALISER_CURVE_JS}</script>"
    )

    page = build_page_html(
        f"Equaliser — {html.escape(_remote_hostname)}",
        body_html,
        extra_css=APPLIANCE_SELECTOR_CSS,
        head_extra=_head_extra,
        active_tab="equaliser",
        dark_mode=dark_mode,
        remote_id=appliance_id,
    )
    body_bytes = page.encode("utf-8")
    try:
        handler.send_response(200)
        handler.send_header("Content-Type", "text/html; charset=utf-8")
        handler.send_header("Content-Length", str(len(body_bytes)))
        handler.end_headers()
        handler.wfile.write(body_bytes)
    except (BrokenPipeError, ConnectionResetError):
        pass
    except Exception:
        pass
