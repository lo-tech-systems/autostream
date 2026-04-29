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
# HTML helpers
# -----------------------------------------------------------------------------

def _eq_cards_html(output_eq) -> str:
    """Render the Equaliser card (PEQ sliders) followed by the Gain card."""
    gain_db = float(output_eq.gain_db)
    auto_trim = bool(output_eq.auto_trim_enabled)
    checked = " checked" if auto_trim else ""
    # Initial legend suffix: placeholder shown only when auto-trim is enabled;
    # JS replaces it on the first poll.
    legend_suffix = " (auto-trim: \u2014)" if auto_trim else ""

    # --- Equaliser card ---
    peq_inner = ""
    for band in OUTPUT_PEQ_BANDS:
        key = band["key"]
        label = html.escape(band["label"])
        val = float(getattr(output_eq, key))
        peq_inner += (
            "<label>"
            "<div class='slider-header'>"
            f"<span>{label}:</span>"
            f"<span id='{key}_val'>{val:.0f} dB</span>"
            "</div>"
            f"<input type='range' min='-10' max='10' step='1' id='{key}'"
            f" value='{val:.0f}' oninput=\"syncOutputPeq('{key}', this.value)\">"
            "</label>"
        )
    eq_card = f"<fieldset><legend>Equaliser</legend>{peq_inner}</fieldset>"

    # --- Gain card ---
    # Auto-trim toggle is first, gain slider below it.
    gain_inner = (
        "<div style='display:flex;align-items:center;justify-content:space-between;'>"
        "<span>Automatically trim gain</span>"
        "<label class='output-toggle'>"
        f"<input type='checkbox' id='output_auto_trim'{checked}"
        " onchange='setOutputAutoTrim(this.checked)'>"
        "<span class='switch'></span>"
        "</label>"
        "</div>"
        "<label>"
        "<div class='slider-header' style='margin-top:0.75rem;'>"
        "<span>Gain:</span>"
        f"<span id='output_gain_db_val'>{gain_db:.0f} dB</span>"
        "</div>"
        f"<input type='range' min='-10' max='10' step='1' id='output_gain_db'"
        f" value='{gain_db:.0f}' oninput=\"syncOutputGain(this.value)\">"
        "</label>"
    )
    gain_legend = (
        f"Gain<span id='output_trim_legend_suffix'"
        f" style='font-weight:normal;font-size:0.9rem;'>"
        f"{html.escape(legend_suffix)}</span>"
    )
    gain_card = f"<fieldset><legend>{gain_legend}</legend>{gain_inner}</fieldset>"

    return eq_card + gain_card


# -----------------------------------------------------------------------------
# Page JavaScript
# -----------------------------------------------------------------------------

_EQUALISER_JS = r"""
var _csrfToken = document.getElementById('_csrfField').value;

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
  var v = parseInt(value, 10);
  document.getElementById('output_gain_db_val').textContent = v + ' dB';
  _saveEqField('gain_db', v);
}

function syncOutputPeq(key, value) {
  var v = parseInt(value, 10);
  document.getElementById(key + '_val').textContent = v + ' dB';
  _saveEqField(key, v);
}

function setOutputAutoTrim(enabled) {
  _saveEqField('auto_trim_enabled', enabled ? 'true' : 'false');
  if (!enabled) {
    var el = document.getElementById('output_trim_legend_suffix');
    if (el) el.textContent = '';
  } else {
    _pollTrimStatus();
  }
}

function _pollTrimStatus() {
  fetch('/api/output_eq/status', {credentials: 'same-origin'})
    .then(function(r) { return r.json(); })
    .then(function(d) {
      var el = document.getElementById('output_trim_legend_suffix');
      if (!el) return;
      var cb = document.getElementById('output_auto_trim');
      if (!cb || !cb.checked) { el.textContent = ''; return; }
      if (!d.ok) { el.textContent = ' (auto-trim: unavailable)'; return; }
      var db = parseFloat(d.output_auto_trim_db);
      el.textContent = ' (auto-trim: ' + db.toFixed(1) + ' dB)';
    })
    .catch(function() {
      var el = document.getElementById('output_trim_legend_suffix');
      if (el) { el.textContent = ''; }
    });
}

document.addEventListener('DOMContentLoaded', function() {
  _pollTrimStatus();
  setInterval(_pollTrimStatus, 2000);
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
        f"<script>{_EQUALISER_JS}</script>"
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
