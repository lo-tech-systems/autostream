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

from autostream_config import parse_config
from autostream_core import OUTPUT_PEQ_BANDS
from autostream_webui_common import (
    build_page_html,
    build_top_banner_html,
    locked_load_config,
)
from autostream_webui_state import WebUIState


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
        {"key": b["key"], "type": b["type"], "freq_hz": b["freq_hz"], "q": b["q"]}
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

def _eq_cards_html(output_eq) -> str:
    """Render the page header, Equaliser band card, and Gain card."""
    gain_db = float(output_eq.gain_db)
    auto_trim = bool(output_eq.auto_trim_enabled)
    checked = " checked" if auto_trim else ""

    # --- Page header: back button + title + Reset button ---
    page_header = (
        "<div class='eq-page-header'>"
        "<div style='display:flex;align-items:center;gap:0.5rem;'>"
        "<h1>Equaliser</h1>"
        "</div>"
        "<button class='pill-btn small' onclick='resetEq()'>Reset</button>"
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
        "<div class='eq-section-title'>Gain</div>"
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
});
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

    if parsed is not None:
        card_html = _eq_cards_html(parsed.output_eq)
    else:
        card_html = (
            "<p style='color:var(--color-text-secondary);'>"
            "Configuration unavailable.</p>"
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
