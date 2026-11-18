#!/usr/bin/env python3
"""webui/browser/setup/cards_track_id.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The Track Identification card of the Setup page.
"""

from __future__ import annotations

import html

from autostream_webui_common import settings_card_html
from webui.browser.setup import context


def _setup_track_id_card_html(parsed) -> str:
    """Track Identification detail-panel card."""
    _ti = parsed.track_identification
    _ti_enabled = bool(_ti.enabled)
    _ti_controls_style = ' style="opacity:0.4;pointer-events:none;"' if not _ti_enabled else ''
    _ti_disabled = ' disabled' if not _ti_enabled else ''
    _ti_lead_in_val = max(0, min(30, _ti.analysis_lead_in_seconds))
    _ti_refresh_val = max(60, min(900, _ti.refresh_seconds))
    _ti_refresh_label = round(_ti_refresh_val / 60)
    _ti_silence_val = max(1.0, min(3.0, _ti.track_change_silence_seconds))
    track_id_card_html = settings_card_html(f"""
          <input type="hidden" name="track_identification_present" value="1">
          <div class="setup-customise-row" style="margin-top:0.5rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" name="track_identification_enabled" id="track_identification_enabled"{'  checked' if _ti_enabled else ''} onchange="onTiToggle(this.checked); if(liveEnabled) settingsSaveField('track_identification.enabled', this.checked);">
              <span class="switch"></span>
            </label>
            <span>Track identification</span>
          </div>
          <div class="eq-auto-trim-subtitle" style="margin-top:0.4rem;">
            A compact frequency fingerprint is derived from a short audio sample and sent to
            Apple&#39;s Shazam using vibra-mini. No raw audio leaves the device. The use of this
            feature requires internet access and may be subject to third-party terms of service.
          </div>
          <div id="ti-controls"{_ti_controls_style}>
            <div class="eq-auto-trim-title" style="margin-top:1rem;">Lead-in before analysis</div>
            <div class="eq-auto-trim-subtitle">
              When a track change is detected, audio will be ignored for this period of time.
              Higher values reduce API usage by helping first-time identification.
            </div>
            <div class="slider-header" style="margin-top:0.4rem;">
              <span>Lead-in:</span><span id="ti_lead_in_val">{_ti_lead_in_val} s</span>
            </div>
            <input type="hidden" name="ti_analysis_lead_in_seconds" id="ti_analysis_lead_in_seconds" value="{_ti_lead_in_val}">
            <input type="range" id="ti_lead_in_range"
              min="0" max="30" step="1" value="{_ti_lead_in_val}"{_ti_disabled}
              oninput="syncTiLeadIn(this.value)">
            <div class="eq-auto-trim-title" style="margin-top:1rem;">Re-identify Period</div>
            <div class="eq-auto-trim-subtitle">
              The current track will be periodically re-identified when no track changes are detected.
              This setting helps with continuous records and noisy records. Lower values will increase API usage.
            </div>
            <div class="slider-header" style="margin-top:0.4rem;">
              <span>Re-identify every:</span><span id="ti_refresh_val">{_ti_refresh_label} min</span>
            </div>
            <input type="hidden" name="ti_refresh_seconds" id="ti_refresh_seconds" value="{_ti_refresh_val}">
            <input type="range" id="ti_refresh_range"
              min="60" max="900" step="60" value="{_ti_refresh_val}"{_ti_disabled}
              oninput="syncTiRefresh(this.value)">
            <div class="eq-auto-trim-title" style="margin-top:1rem;">Track-change Detection</div>
            <div class="eq-auto-trim-subtitle">
              A silence period of this length is used to detect a track change, after which
              re-identification is performed automatically.
            </div>
            <div class="slider-header" style="margin-top:0.4rem;">
              <span>Silence gap:</span><span id="ti_silence_val">{_ti_silence_val:.2f} s</span>
            </div>
            <input type="hidden" name="ti_track_change_silence_seconds" id="ti_track_change_silence_seconds" value="{_ti_silence_val:.2f}">
            <input type="range" id="ti_silence_range"
              min="1.0" max="3.0" step="0.25" value="{_ti_silence_val:.2f}"{_ti_disabled}
              oninput="syncTiSilence(this.value)">
          </div>
        """, margin_top="0")
    return track_id_card_html


def summary_track_id(ctx: context.SetupCtx) -> str:
    return html.escape("On" if ctx.parsed.track_identification.enabled else "Off")


def detail_track_id(ctx: context.SetupCtx) -> str:
    return _setup_track_id_card_html(ctx.parsed)
