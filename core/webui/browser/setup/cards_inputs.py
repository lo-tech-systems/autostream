#!/usr/bin/env python3
"""webui/browser/setup/cards_inputs.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The Input 1 and Input 2 cards of the Setup page, with the silence-detection
slider maps and the gain/equaliser controls they share.
"""

from __future__ import annotations

import html
import json
import math
from typing import Optional

from autostream_config import (
    INPUT_TYPES,
    INPUT_TYPE_LABELS,
    INPUT_TYPE_SILENCE_THRESHOLD_DBFS,
    SILENCE_THRESHOLD_MAX_DBFS,
    SILENCE_THRESHOLD_MIN_DBFS,
    input_type_label,
    normalize_input_type,
)
from autostream_state import store
from webui.common import settings_card_html
from webui.browser.setup import cards_bluetooth, context


# -----------------------------------------------------------------------------
# Silence-detection slider — logarithmic position<->seconds mapping.
#
# The slider's on-screen position (0-100) is exponential in seconds so that
# dragging near the low end gives fine control (short, turntable-friendly
# timeouts) while the high end covers a wide range in fewer, coarser steps.
# The submitted/persisted value is always plain whole seconds; only the
# handle's position on the track is nonlinear.
# -----------------------------------------------------------------------------

SILENCE_SECONDS_MIN = 5
SILENCE_SECONDS_MAX = 300


def _silence_pos_to_seconds(pos: float) -> int:
    """Map a 0-100 slider position to whole seconds (exponential curve).

    Snaps to coarser steps as the value grows, since a 1s difference matters
    much less at 200s than it does at 6s.
    """
    pos = max(0.0, min(100.0, pos))
    seconds = SILENCE_SECONDS_MIN * ((SILENCE_SECONDS_MAX / SILENCE_SECONDS_MIN) ** (pos / 100.0))
    if seconds < 30:
        seconds = round(seconds)
    elif seconds < 120:
        seconds = round(seconds / 5) * 5
    else:
        seconds = round(seconds / 10) * 10
    return int(max(SILENCE_SECONDS_MIN, min(SILENCE_SECONDS_MAX, seconds)))


def _silence_seconds_to_pos(seconds: float) -> float:
    """Inverse of _silence_pos_to_seconds(), used to position the slider for
    an already-saved value (including values that don't fall on a snap
    point, e.g. a config file edited by hand or carried over from an older
    build)."""
    seconds = max(SILENCE_SECONDS_MIN, min(SILENCE_SECONDS_MAX, seconds))
    return 100.0 * math.log(seconds / SILENCE_SECONDS_MIN) / math.log(SILENCE_SECONDS_MAX / SILENCE_SECONDS_MIN)


def _audio_controls_card_html(
    *,
    input_index: int,
    gain_db: float,
    eq_40hz_db: float,
    eq_100hz_db: float,
    eq_8khz_db: float,
) -> str:
    prefix = f"audio{input_index}"
    inner_html = f"""
      <label><div class="slider-header"><span>Gain:</span><span id="{prefix}_gain_db_val">{gain_db:.0f} dB</span></div>
      <input type="range" min="-10" max="10" step="1" id="{prefix}_gain_db" name="{prefix}_gain_db" value="{gain_db:.0f}" oninput="syncGain({input_index}, this.value)"></label>
      <div class="slider-header" style="margin-top:.75rem;align-items:center;">
        <strong>Equaliser</strong>
      </div>
      <div class="eq-bands-wrap" style="margin-top:0.5rem;">
        <div class="eq-bands-row">
          <div class="eq-band">
            <span class="eq-band-freq">40Hz</span>
            <input
              type="range"
              class="eq-band-slider"
              min="-10"
              max="10"
              step="1"
              id="{prefix}_eq_40hz_db"
              name="{prefix}_eq_40hz_db"
              value="{eq_40hz_db:.0f}"
              aria-label="40Hz equaliser"
              oninput="syncEq({input_index}, '40hz', this.value)">
            <span class="eq-band-val" id="{prefix}_eq_40hz_db_val">{eq_40hz_db:.0f} dB</span>
          </div>
          <div class="eq-band">
            <span class="eq-band-freq">Bass</span>
            <input
              type="range"
              class="eq-band-slider"
              min="-10"
              max="10"
              step="1"
              id="{prefix}_eq_100hz_db"
              name="{prefix}_eq_100hz_db"
              value="{eq_100hz_db:.0f}"
              aria-label="Bass equaliser"
              oninput="syncEq({input_index}, '100hz', this.value)">
            <span class="eq-band-val" id="{prefix}_eq_100hz_db_val">{eq_100hz_db:.0f} dB</span>
          </div>
          <div class="eq-band">
            <span class="eq-band-freq">Treble</span>
            <input
              type="range"
              class="eq-band-slider"
              min="-10"
              max="10"
              step="1"
              id="{prefix}_eq_8khz_db"
              name="{prefix}_eq_8khz_db"
              value="{eq_8khz_db:.0f}"
              aria-label="Treble equaliser"
              oninput="syncEq({input_index}, '8khz', this.value)">
            <span class="eq-band-val" id="{prefix}_eq_8khz_db_val">{eq_8khz_db:.0f} dB</span>
          </div>
        </div>
      </div>
    """
    # The recorder tap sits PRE-DSP and replay applies the origin
    # input's LIVE gain/EQ, so these controls are never locked during replay.
    return settings_card_html(inner_html)


def _setup_input_card_html(
    *,
    input_index: int,
    title: str,
    parsed_input,
    capture_name: str,
    threshold_name: str,
    type_name: str,
    enabled: bool = True,
    enabled_name: Optional[str] = None,
    bt_enabled: bool = False,
    other_capture_device: Optional[str] = None,
    monitor_devices,
) -> str:
    """Input 1 / Input 2 detail-panel card (shared render function -- one
    per instance, called twice)."""
    def _is_bt_loopback_playback_value(value: str) -> bool:
        """True when ``value`` is the ASBT loopback's PLAYBACK side.

        Guarded the same way as ``_bluetooth_installed()`` elsewhere on
        this page: defensive import, quiet fallback to False so the page
        keeps rendering identically wherever the Bluetooth helper module or
        the feature itself is absent.
        """
        if not bt_enabled:
            return False
        try:
            from autostream_bluetooth_client import is_loopback_playback
        except ImportError:
            return False
        try:
            return bool(is_loopback_playback(value))
        except Exception:
            return False

    def build_opts(cur, other_value: Optional[str] = None):
        opts = ""
        found = False
        cur_str = str(cur).strip() if cur else ""
        other_str = str(other_value or "").strip()
        if not cur_str:
            # An unconfigured input must not implicitly display the first
            # device in the list as selected: the browser would show it as
            # chosen without any save having happened, and re-selecting the
            # displayed option fires no change event, so the user could never
            # actually save that device. An explicit disabled placeholder
            # keeps the displayed state truthful and makes any real choice a
            # change event.
            opts += (
                "<option value='' selected disabled>"
                "&#8212; select input device &#8212;</option>"
            )
            found = True
        for dev in monitor_devices:
            hw = str(dev.get("hw") or "").strip()
            if not hw:
                continue
            if other_str and hw == other_str and hw != cur_str:
                # Cross-input exclusivity (server render): a device already
                # selected on the other input is not offered here, so the
                # same physical device can never be attached to both inputs.
                # This input's own current selection always still renders,
                # even if it happens to equal the other input's value (a
                # pre-existing duplicate from before this guard existed).
                continue
            label = str(dev.get("label") or hw).strip()
            card = str(dev.get("card") or "").strip()
            card_short = card.split(", ")[0].strip() if card else hw
            sel = " selected" if hw == cur_str else ""
            if sel:
                found = True
            bt_attr = " data-bt='1'" if hw == cards_bluetooth.BLUETOOTH_LOOPBACK_HW else ""
            opts += (
                f"<option value='{html.escape(hw)}' data-card='{html.escape(card_short)}'{bt_attr}{sel}>"
                f"{html.escape(label)}</option>"
            )
        if not found and cur and not _is_bt_loopback_playback_value(cur_str):
            # A stale saved capture_device pointing at the loopback PLAYBACK side (an
            # internal device the pump feeds, never a valid input) must not
            # resurface as a bare "hw:CARD=ASBT,DEV=0 (not currently
            # detected)" option -- the normalize relabel hook already
            # correctly drops that side from monitor_devices, so injecting it
            # back here via the synthetic-fallback path would defeat that.
            # Genuinely-missing real devices are unaffected and still get the
            # synthetic option below.
            missing = html.escape(cur_str)
            opts = (
                f"<option value='{missing}' selected>"
                f"{missing} (not currently detected)</option>"
            ) + opts
        return opts

    def input_fieldset_html(
        *,
        input_index: int,
        title: str,
        parsed_input,
        capture_name: str,
        threshold_name: str,
        type_name: str,
        enabled: bool = True,
        enabled_name: Optional[str] = None,
        bt_enabled: bool = False,
        other_capture_device: Optional[str] = None,
    ) -> str:
        prefix = "audio1" if input_index == 1 else "audio2"
        threshold_id = "audio_silence_threshold" if input_index == 1 else "audio2_silence_threshold"
        settings_wrap_id = f"{prefix}_settings"
        input_type = normalize_input_type(getattr(parsed_input, "input_type", "line"))
        threshold = float(parsed_input.silence_threshold_dbfs)
        rate_matching = bool(getattr(parsed_input, "dynamic_rate_matching", True))
        rate_matching_note_raw, sample_rate_line_raw = store().snapshot().inputs.rate_texts(input_index)
        rate_matching_note = html.escape(rate_matching_note_raw)
        sample_rate_line = html.escape(sample_rate_line_raw)
        type_options = "".join(
            f'<option value="{t}"{" selected" if t == input_type else ""}>{INPUT_TYPE_LABELS[t]}</option>'
            for t in INPUT_TYPES
        )
        presets_json = json.dumps(INPUT_TYPE_SILENCE_THRESHOLD_DBFS)

        enabled_html = ""
        wrap_style = "block" if enabled else "none"
        if enabled_name:
            enabled_html = f"""
          <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" name="{enabled_name}" {'checked' if enabled else ''} onchange="onInputEnableToggle({input_index}, this.checked)">
              <span class="switch"></span>
            </label>
            <span>Enable</span>
          </div>
            """

        settings_open = "" if enabled_name is None else f"<div id=\"{settings_wrap_id}\" style=\"display:{wrap_style};\">"
        settings_close = "" if enabled_name is None else "</div>"

        if bt_enabled:
            capture_onchange = (
                f"if (isBluetoothDevice(this.value) && !btPaired) {{ openBtPairingModal({input_index}, this); return; }} "
                f"if(liveEnabled) settingsSaveField('audio{input_index}.capture_device', this.value); "
                f"this.dataset.prev = this.value; syncInputExclusivity({input_index}, this.value);"
            )
        else:
            capture_onchange = (
                f"if(liveEnabled) settingsSaveField('audio{input_index}.capture_device', this.value); "
                f"syncInputExclusivity({input_index}, this.value);"
            )

        data_prev_attr = (
            f" data-prev='{html.escape(str(parsed_input.capture_device or '').strip())}'" if bt_enabled else ""
        )
        inner_html = f"""
          {enabled_html}
          {settings_open}
            <label>Input device: <select name="{capture_name}" id="{capture_name}_select" data-input-index="{input_index}"{data_prev_attr} onchange="{capture_onchange}">{build_opts(parsed_input.capture_device, other_capture_device)}</select></label>
            <label>Input type: <select name="{type_name}" id="{prefix}_input_type" data-current-type="{input_type}" data-presets='{presets_json}' onchange="onInputTypeChange({input_index}, this.value)">{type_options}</select></label>
            <label><div class="slider-header"><span>Sensitivity:</span><span id="{prefix}_silence_threshold_val">{threshold:.0f} dB</span></div>
            <input type="range" min="{SILENCE_THRESHOLD_MIN_DBFS:.0f}" max="{SILENCE_THRESHOLD_MAX_DBFS:.0f}" step="1" id="{threshold_id}" name="{threshold_name}" value="{threshold:.0f}" oninput="syncSilenceThreshold({input_index}, this.value)"></label>
            <div id="{prefix}_sensitivity_note" class="helptext" style="text-align:left;">
              Further left picks up quieter audio; further right ignores more background noise.
            </div>
            <div class="helptext" style="text-align:left;">
              Level: <span id="{prefix}_level_val">no level</span>
            </div>
            <div id="{prefix}_sample_rate" class="helptext" style="text-align:left;">
              {sample_rate_line}
            </div>
            <div style="display:flex;align-items:center;gap:0.75rem;margin-top:0.9rem;">
              <label class="output-toggle" style="margin:0;">
                <input type="checkbox" id="{prefix}_dynamic_rate_matching" {'checked' if rate_matching else ''} onchange="if(liveEnabled) settingsSaveField('audio{input_index}.dynamic_rate_matching', this.checked);">
                <span class="switch"></span>
              </label>
              <span>Dynamic Rate Matching</span>
            </div>
            <div id="{prefix}_rate_matching_note" class="helptext" style="text-align:left;">
              {rate_matching_note}
            </div>
          {settings_close}
        """
        return settings_card_html(inner_html, margin_top="0")
    return input_fieldset_html(
        input_index=input_index,
        title=title,
        parsed_input=parsed_input,
        capture_name=capture_name,
        threshold_name=threshold_name,
        type_name=type_name,
        enabled=enabled,
        enabled_name=enabled_name,
        bt_enabled=bt_enabled,
        other_capture_device=other_capture_device,
    )


def _setup_input_summary_text(
    parsed_input,
    *,
    enabled: bool,
    disabled_text: str,
    monitor_devices,
    bt_enabled: bool,
    bt_status: Optional[dict],
) -> str:
    """Input 1 / Input 2 list-card summary text (collapsed-row subtitle)."""
    if not enabled:
        return disabled_text
    def _friendly(hw) -> str:
        """Return shortened card name for use in sub-labels (first segment before ', ')."""
        for d in monitor_devices:
            if str(d.get("hw") or "").strip() == str(hw or "").strip():
                c = str(d.get("card") or "").strip()
                return c.split(", ")[0].strip() if c else str(hw)
        return str(hw) if hw else "Not configured"

    def _input_card_summary(parsed_input) -> str:
        dev = _friendly(parsed_input.capture_device)
        mode = input_type_label(getattr(parsed_input, "input_type", "line"))
        if bt_enabled and parsed_input.capture_device == cards_bluetooth.BLUETOOTH_LOOPBACK_HW:
            # Bluetooth input: the ALSA card name ("Loopback") and the
            # input type are implementation detail here \u2014 show the
            # connected device's name (or the connection state) instead.
            dev = "Bluetooth"
            mode = cards_bluetooth._bluetooth_input_fragment_text(bt_status)
        gain = int(parsed_input.gain_db)
        gain_str = f"{gain:+d} dB" if gain != 0 else "0 dB"
        return html.escape(f"{dev} \u00b7 {mode} \u00b7 {gain_str}")
    return _input_card_summary(parsed_input)


def summary_input1(ctx: context.SetupCtx) -> str:
    return _setup_input_summary_text(
        ctx.parsed.audio1,
        enabled=ctx.parsed.audio1_enabled,
        disabled_text="Not configured",
        monitor_devices=ctx.monitor_devices,
        bt_enabled=ctx.bt_enabled,
        bt_status=ctx.bt_status,
    )


def detail_input1(ctx: context.SetupCtx) -> str:
    input1_html = _setup_input_card_html(
        input_index=1,
        title="Input 1",
        parsed_input=ctx.parsed.audio1,
        capture_name="audio_capture_device",
        threshold_name="audio_silence_threshold",
        type_name="audio1_input_type",
        enabled=ctx.parsed.audio1_enabled,
        enabled_name="audio1_enabled",
        bt_enabled=ctx.bt_enabled,
        other_capture_device=ctx.parsed.audio2.capture_device,
        monitor_devices=ctx.monitor_devices,
    )
    return input1_html + (
        f'<div id="audio1_preamp_card" style="display:{"block" if ctx.parsed.audio1_enabled else "none"};">'
        + _audio_controls_card_html(
            input_index=1,
            gain_db=ctx.parsed.audio1.gain_db,
            eq_40hz_db=ctx.parsed.audio1.eq_40hz_db,
            eq_100hz_db=ctx.parsed.audio1.eq_100hz_db,
            eq_8khz_db=ctx.parsed.audio1.eq_8khz_db,
        )
        + "</div>"
    )


def summary_input2(ctx: context.SetupCtx) -> str:
    return _setup_input_summary_text(
        ctx.parsed.audio2,
        enabled=ctx.parsed.audio2_enabled,
        disabled_text="Disabled",
        monitor_devices=ctx.monitor_devices,
        bt_enabled=ctx.bt_enabled,
        bt_status=ctx.bt_status,
    )


def detail_input2(ctx: context.SetupCtx) -> str:
    input2_html = _setup_input_card_html(
        input_index=2,
        title="Input 2",
        parsed_input=ctx.parsed.audio2,
        capture_name="audio2_capture_device",
        threshold_name="audio2_silence_threshold",
        type_name="audio2_input_type",
        enabled=ctx.parsed.audio2_enabled,
        enabled_name="audio2_enabled",
        bt_enabled=ctx.bt_enabled,
        other_capture_device=ctx.parsed.audio1.capture_device,
        monitor_devices=ctx.monitor_devices,
    )
    return input2_html + (
        f'<div id="audio2_preamp_card" style="display:{"block" if ctx.parsed.audio2_enabled else "none"};">'
        + _audio_controls_card_html(
            input_index=2,
            gain_db=ctx.parsed.audio2.gain_db,
            eq_40hz_db=ctx.parsed.audio2.eq_40hz_db,
            eq_100hz_db=ctx.parsed.audio2.eq_100hz_db,
            eq_8khz_db=ctx.parsed.audio2.eq_8khz_db,
        )
        + "</div>"
    )
