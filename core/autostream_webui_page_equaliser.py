#!/usr/bin/env python3
"""autostream_webui_page_equaliser.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Page renderer for the /equaliser route.

Responsibilities:
  - Render the shared output Equaliser page: output gain, auto-trim toggle,
    live trim readout, and six parametric EQ band sliders.
  - No PIN required; /equaliser is in the auth allowlist.
  - Settings are saved automatically via POST /api/output_eq/config (AJAX).
  - Full EQ state (all bands, gain, auto-trim) is polled every 3 s (10 s in
    degraded mode) via GET /api/appliances/<local_id>/equaliser.
"""

from __future__ import annotations

import html
import math
from typing import Optional

from autostream_appliances import get_all_appliances
from autostream_state.live import get_live_monitor_output_rate
from autostream_eq_bands import OUTPUT_PEQ_BANDS
from autostream_rpi import get_appliance_id
from autostream_sysutils import get_system_hostname
from webui import static
from webui.common import (
    build_appliance_selector_html,
    build_page_html,
    build_top_banner_html,
)
from webui.session_state import WebUIState
from webui import common


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
# equaliser_curve.js (JavaScript evaluation, fed through the page's data
# island by _curve_data()).  Both must use identical values.
# -----------------------------------------------------------------------------
_CURVE_W        = 320      # SVG viewBox width  (px)
_CURVE_H        = 120      # SVG viewBox height (px)
_CURVE_F_MIN    = 20.0     # left edge frequency (Hz)
_CURVE_F_MAX    = 20000.0  # right edge frequency (Hz)
_CURVE_DB_RANGE = 12.0     # ± dB range shown
_CURVE_PAD_Y    = 3        # vertical padding (px) so ±12 dB paths aren't clipped
_CURVE_FS_FALLBACK = 48000  # used only when the monitor is unreachable
_CURVE_N_PTS    = 200      # number of log-spaced frequency points in the path


def _curve_fs() -> int:
    """Return the sample rate to use for the EQ curve's biquad math.

    Sourced live from the monitor's get_status() "output_rate" field (see
    autostream_state.live.get_live_monitor_output_rate()) so this stays in sync
    with the daemon's actual OUTPUT_RATE instead of a hand-synced constant.
    Falls back to _CURVE_FS_FALLBACK when the monitor is unreachable.
    """
    return get_live_monitor_output_rate(fallback=_CURVE_FS_FALLBACK)


def _cx(f: float) -> float:
    """Frequency → SVG x coordinate (log scale)."""
    return _CURVE_W * math.log(f / _CURVE_F_MIN) / math.log(_CURVE_F_MAX / _CURVE_F_MIN)


def _cy(db: float) -> float:
    """dB value → SVG y coordinate."""
    return _CURVE_H / 2.0 - db * (_CURVE_H / 2.0 - _CURVE_PAD_Y) / _CURVE_DB_RANGE


# -----------------------------------------------------------------------------
# Data the curve script reads from the page's data island
# -----------------------------------------------------------------------------

def _eq_bands_data() -> list:
    """Return the static band parameters for the curve script.

    The gain values are intentionally omitted here; they are read from the
    live slider elements at draw time so the curve always reflects the current
    UI state without a round-trip.
    """
    return [
        {"key": b["key"], "type": b["type"], "freq_hz": b["freq_hz"], "q": b["q"],
         "label": b.get("label", "")}
        for b in OUTPUT_PEQ_BANDS
    ]


def _curve_data() -> dict:
    """Return the curve geometry the curve script mirrors from the _CURVE_* values."""
    return {
        "w": _CURVE_W,
        "h": _CURVE_H,
        "f_min": _CURVE_F_MIN,
        "f_max": _CURVE_F_MAX,
        "db_range": _CURVE_DB_RANGE,
        "pad_y": _CURVE_PAD_Y,
        "n_pts": _CURVE_N_PTS,
    }


# -----------------------------------------------------------------------------
# SVG frequency-response curve HTML
# -----------------------------------------------------------------------------

def _eq_curve_html() -> str:
    """Return the static SVG markup for the EQ frequency-response display.

    All dynamic elements (curve path, band handles) carry ids that
    _drawEqCurve() in equaliser_curve.js targets on every slider event.
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

    # The recorder tap sits PRE-DSP, so replay applies the origin
    # input's LIVE gain/EQ plus this page's own output EQ/gain via the shared
    # OutputProcessor -- these controls are never locked during replay.
    eq_panes = f"{eq_card}{gain_card}"

    return page_header + eq_panes


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
        parsed = common._config_snapshot(state)
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

    _head_extra = static.page_data_island({
        "local_id": _local_id,
        "selector_current_page": "equaliser",
        "poll_url": f"/api/appliances/{_local_id}/equaliser",
        "eq_bands": _eq_bands_data(),
        "eq_fs": _curve_fs(),
        "curve": _curve_data(),
    })

    body_html = (
        f"<input type='hidden' id='_csrfField' value='{html.escape(csrf_token)}'>"
        f"{card_html}"
        + static.script_tag("page/equaliser_curve.js")
        + static.script_tag("page/equaliser.js")
        + static.script_tag("page/appliance_selector.js")
    )

    page = build_page_html(
        "Equaliser",
        body_html,
        style_files=("page/appliance_selector.css",),
        head_extra=_head_extra,
        lic_html=lic_html,
        lic_spacer=lic_spacer,
        active_tab="equaliser",
        dark_mode=dark_mode,
    )
    common.send_html(handler, 200, page)


# -----------------------------------------------------------------------------
# Remote Equaliser page renderer
# -----------------------------------------------------------------------------

def send_remote_equaliser_page(handler, state: WebUIState, appliance_id: str) -> None:
    """Render the remote Equaliser shell for a remote appliance.

    Serves a client-side loading shell.  JavaScript fetches
    /api/appliances/<id>/equaliser on DOMContentLoaded (with retry schedule
    [500, 500, 1000, 1000, 2000, 3000] ms before handing off to background
    polling), renders the sliders, then polls every 3 s (10 s in degraded mode).
    Writes go to /api/appliances/<id>/equaliser/config and
    /api/appliances/<id>/equaliser/reset via the gateway.
    Transient transport failures enter degraded mode; only definitive errors
    (appliance_unconfigured, identity conflicts, etc.) return to /.
    """
    try:
        parsed = common._config_snapshot(state)
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
        f"<script>window.__CSRF='{html.escape(csrf_token)}';</script>"
        + static.script_tag("page/csrf_recovery.js")
        + static.page_data_island({
            "poll_url": poll_url,
            "save_url": save_url,
            "reset_url": reset_url,
            "status_url": status_url,
            "remote_aid": appliance_id,
            "remote_hostname": _remote_hostname,
            "local_id": _local_id,
            "selector_current_page": "equaliser",
            "eq_bands": _eq_bands_data(),
            "eq_fs": _curve_fs(),
            "curve": _curve_data(),
        })
        + static.script_tag("page/remote_equaliser.js")
        + static.script_tag("page/appliance_selector.js")
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
        "color:var(--color-text-muted,#888);padding:1.5rem 0;margin:0;'>Connecting&hellip;</p>"
        + static.script_tag("page/equaliser_curve.js")
    )

    page = build_page_html(
        f"Equaliser — {html.escape(_remote_hostname)}",
        body_html,
        style_files=("page/appliance_selector.css",),
        head_extra=_head_extra,
        active_tab="equaliser",
        dark_mode=dark_mode,
        remote_id=appliance_id,
    )
    try:
        common.send_html(handler, 200, page)
    except Exception:
        pass
