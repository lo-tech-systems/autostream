#!/usr/bin/env python3
"""webui/browser/setup/cards_inputs.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The input cards of the Setup page (Inputs 1 and 2 wired, Input 3 Bluetooth),
with the silence-detection slider maps and the gain/equaliser controls they
share.
"""

from __future__ import annotations

import html
import json
import math
from functools import partial
from typing import Optional

from autostream_config import (
    BLUETOOTH_INPUT_INDEX,
    INPUT_TYPES,
    INPUT_TYPE_LABELS,
    INPUT_TYPE_SILENCE_THRESHOLD_DBFS,
    SILENCE_THRESHOLD_MAX_DBFS,
    SILENCE_THRESHOLD_MIN_DBFS,
    START_AFTER_MS_DEFAULT,
    START_AFTER_MS_MAX,
    START_AFTER_MS_MIN,
    WIRED_INPUT_INDICES,
    input_type_label,
    normalize_input_type,
    normalize_start_after_ms,
)
from autostream_state import store
from webui import common
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


def _start_after_html(input_index: int, prefix: str, input_type: str, start_after_ms: int) -> str:
    """The input card's Start after stepper. Hidden for a CD input, which
    starts on its first sound. A step stops at the range's end, so a button
    is disabled only when the value is already there."""
    v = normalize_start_after_ms(start_after_ms)
    buttons = {}
    for step, label, aria in (
        (-100, "&minus;100", "100 ms sooner"),
        (-10, "&minus;10", "10 ms sooner"),
        (10, "+10", "10 ms later"),
        (100, "+100", "100 ms later"),
    ):
        at_end = v <= START_AFTER_MS_MIN if step < 0 else v >= START_AFTER_MS_MAX
        disabled = " disabled" if at_end else ""
        buttons[step] = (
            f'<button type="button" class="pill-btn" data-step="{step}" aria-label="{aria}"'
            f' onclick="startAfterStep({input_index}, {step})"{disabled}>{label}</button>'
        )
    hidden = " hidden" if input_type == "cd" else ""
    return f"""
            <div id="{prefix}_start_after_wrap"{hidden}>
              <div class="slider-header">
                <span>Start after:</span>
                <button type="button" class="pill-btn small" onclick="startAfterReset({input_index})">Reset</button>
              </div>
              <div class="value-stepper" id="{prefix}_start_after_stepper" role="group" aria-label="Start after">
                {buttons[-100]}
                {buttons[-10]}
                <div class="value-stepper-value" aria-live="polite"><span id="{prefix}_start_after_val"
                     data-ms="{v}">{v}</span><span class="unit">ms</span></div>
                {buttons[10]}
                {buttons[100]}
              </div>
              <div class="helptext" style="text-align:left;">
                Playback starts once the level has been above Sensitivity for this long within one second. Longer ignores more clicks and knocks; shorter cuts less from the start of a record.
              </div>
            </div>"""


# -----------------------------------------------------------------------------
# One card per input. Inputs 1 and 2 are wired: each has a capture device
# chosen from the monitor's list. Input 3 is Bluetooth: its device is fixed,
# its enable is the Bluetooth services switch, and its card carries the
# adapter, pairing and buffer controls. Its card exists only where Bluetooth
# is installed.
# -----------------------------------------------------------------------------

# Form field names that predate the numbering scheme: input 1's device and
# threshold fields carry no number. Every other field is "audio<N>_<base>".
LEGACY_INPUT_FIELDS = {
    1: {"capture_device": "audio_capture_device", "silence_threshold": "audio_silence_threshold"},
}
LEGACY_INPUT_FIELDS_JSON = {str(i): names for i, names in LEGACY_INPUT_FIELDS.items()}

# What a disabled input's summary says. Input 1's wording predates the others'.
_DISABLED_SUMMARY = {1: "Not configured"}
DISABLED_SUMMARY_JSON = {str(i): text for i, text in _DISABLED_SUMMARY.items()}


def input_field_name(index: int, base: str) -> str:
    """The form field name (and element id) of input *index*'s *base* field."""
    return LEGACY_INPUT_FIELDS.get(index, {}).get(base, f"audio{index}_{base}")


def present_input_indices(ctx: context.SetupCtx) -> list:
    """The inputs that have a card on this appliance: the wired ones, and
    input 3 where Bluetooth is installed."""
    return common.present_input_indices(ctx.bt_enabled)


def _moved_note_html(index: int, moved_from: Optional[int]) -> str:
    """The note an update leaves on input 3's card and on the card of the
    wired input Bluetooth was moved from, until either is next changed."""
    if moved_from is None:
        return ""
    if index == BLUETOOTH_INPUT_INDEX:
        text = f"Bluetooth was moved here from Input {moved_from} by the update."
    elif index == moved_from:
        text = f"Bluetooth was moved to Input {BLUETOOTH_INPUT_INDEX} by the update."
    else:
        return ""
    return (
        f'<p id="audio{index}_moved_note" class="helptext" style="text-align:left;margin:0 0 0.75rem;">'
        f"{html.escape(text)}</p>"
    )


def _device_options_html(cur: str, taken: set, monitor_devices) -> str:
    """The capture-device options of a wired input: every listed device but
    the ones another wired input has taken, with this input's own choice
    selected (offered as "not currently detected" when it is not listed)."""
    opts = ""
    found = False
    cur_str = str(cur or "").strip()
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
        if hw in taken and hw != cur_str:
            # Cross-input exclusivity (server render): a device already
            # selected on another wired input is not offered here, so the
            # same physical device can never be attached to two inputs.
            # This input's own current selection always still renders,
            # even if it happens to equal another input's value (a
            # pre-existing duplicate from before this guard existed).
            continue
        label = str(dev.get("label") or hw).strip()
        card = str(dev.get("card") or "").strip()
        card_short = card.split(", ")[0].strip() if card else hw
        sel = " selected" if hw == cur_str else ""
        if sel:
            found = True
        opts += (
            f"<option value='{html.escape(hw)}' data-card='{html.escape(card_short)}'{sel}>"
            f"{html.escape(label)}</option>"
        )
    if not found:
        missing = html.escape(cur_str)
        opts = (
            f"<option value='{missing}' selected>"
            f"{missing} (not currently detected)</option>"
        ) + opts
    return opts


def _enable_toggle_html(index: int, enabled: bool, bluetooth: bool) -> str:
    """The Enable switch. Input 3's is the Bluetooth services switch, which
    reloads the page once the services have changed."""
    onchange = "btServicesToggle(this)" if bluetooth else f"onInputEnableToggle({index}, this.checked)"
    help_html = (
        '<p class="helptext" style="text-align:left;margin:0 0 0.5rem;">Connect a Bluetooth device '
        "(such as a turntable with Bluetooth output) as an audio input.</p>"
        if bluetooth else ""
    )
    return f"""
          <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" name="audio{index}_enabled" {'checked' if enabled else ''} onchange="{onchange}">
              <span class="switch"></span>
            </label>
            <span>Enable</span>
          </div>
          {help_html}"""


def _setup_input_card_html(ctx: context.SetupCtx, index: int) -> str:
    """An input's detail-panel card: the enable switch, then the device (a
    wired input's select, or input 3's Bluetooth rows), the input type,
    sensitivity with the level, Start after and Dynamic Rate Matching."""
    parsed_input = ctx.parsed.audio_section(index)
    enabled = ctx.parsed.audio_enabled(index)
    bluetooth = index == BLUETOOTH_INPUT_INDEX
    prefix = f"audio{index}"
    threshold_name = input_field_name(index, "silence_threshold")
    input_type = normalize_input_type(getattr(parsed_input, "input_type", "line"))
    threshold = float(parsed_input.silence_threshold_dbfs)
    rate_matching = bool(getattr(parsed_input, "dynamic_rate_matching", True))
    rate_matching_note_raw, sample_rate_line_raw = store().snapshot().inputs.rate_texts(index)
    rate_matching_note = html.escape(rate_matching_note_raw)
    sample_rate_line = html.escape(sample_rate_line_raw)
    type_options = "".join(
        f'<option value="{t}"{" selected" if t == input_type else ""}>{INPUT_TYPE_LABELS[t]}</option>'
        for t in INPUT_TYPES
    )
    presets_json = json.dumps(INPUT_TYPE_SILENCE_THRESHOLD_DBFS)
    start_after_html = _start_after_html(
        index, prefix, input_type,
        getattr(parsed_input, "start_after_ms", START_AFTER_MS_DEFAULT),
    )

    if bluetooth:
        device_html = cards_bluetooth._bluetooth_rows_html(ctx)
    else:
        capture_name = input_field_name(index, "capture_device")
        taken = {
            ctx.parsed.audio_section(other).capture_device
            for other in WIRED_INPUT_INDICES if other != index
        } - {""}
        capture_onchange = (
            f"if(liveEnabled) settingsSaveField('{prefix}.capture_device', this.value); "
            f"syncInputExclusivity({index}, this.value);"
        )
        options = _device_options_html(parsed_input.capture_device, taken, ctx.monitor_devices)
        device_html = (
            f'<label>Input device: <select name="{capture_name}" id="{capture_name}_select" '
            f'data-input-index="{index}" onchange="{capture_onchange}">{options}</select></label>'
        )

    inner_html = f"""
          {_moved_note_html(index, ctx.parsed.bluetooth_moved_from)}
          {_enable_toggle_html(index, enabled, bluetooth)}
          <div id="{prefix}_settings" style="display:{'block' if enabled else 'none'};">
            {device_html}
            <label>Input type: <select name="{prefix}_input_type" id="{prefix}_input_type" data-current-type="{input_type}" data-presets='{presets_json}' onchange="onInputTypeChange({index}, this.value)">{type_options}</select></label>
            <label><div class="slider-header"><span>Sensitivity:</span><span id="{prefix}_silence_threshold_val">{threshold:.0f} dB</span></div>
            <input type="range" min="{SILENCE_THRESHOLD_MIN_DBFS:.0f}" max="{SILENCE_THRESHOLD_MAX_DBFS:.0f}" step="1" id="{threshold_name}" name="{threshold_name}" value="{threshold:.0f}" oninput="syncSilenceThreshold({index}, this.value)"></label>
            <div id="{prefix}_sensitivity_note" class="helptext" style="text-align:left;">
              Further left picks up quieter audio; further right ignores more background noise.
            </div>
            <div class="helptext" style="text-align:left;">
              Level: <span id="{prefix}_level_val">no level</span>
            </div>
            {start_after_html}
            <div id="{prefix}_sample_rate" class="helptext" style="text-align:left;">
              {sample_rate_line}
            </div>
            <div style="display:flex;align-items:center;gap:0.75rem;margin-top:0.9rem;">
              <label class="output-toggle" style="margin:0;">
                <input type="checkbox" id="{prefix}_dynamic_rate_matching" {'checked' if rate_matching else ''} onchange="if(liveEnabled) settingsSaveField('{prefix}.dynamic_rate_matching', this.checked);">
                <span class="switch"></span>
              </label>
              <span>Dynamic Rate Matching</span>
            </div>
            <div id="{prefix}_rate_matching_note" class="helptext" style="text-align:left;">
              {rate_matching_note}
            </div>
          </div>
        """
    return settings_card_html(inner_html, margin_top="0")


def _friendly_device(hw, monitor_devices) -> str:
    """Shortened card name for a device in a summary line (the first
    segment of the card description before ', ')."""
    for d in monitor_devices:
        if str(d.get("hw") or "").strip() == str(hw or "").strip():
            c = str(d.get("card") or "").strip()
            return c.split(", ")[0].strip() if c else str(hw)
    return str(hw) if hw else "Not configured"


def summary_input(index: int, ctx: context.SetupCtx) -> str:
    """An input's list-card summary text (collapsed-row subtitle): its
    device (or, for input 3, the Bluetooth device or connection state),
    type and gain."""
    if not ctx.parsed.audio_enabled(index):
        return _DISABLED_SUMMARY.get(index, "Disabled")
    parsed_input = ctx.parsed.audio_section(index)
    if index == BLUETOOTH_INPUT_INDEX:
        dev = cards_bluetooth._bluetooth_input_fragment_text(ctx.bt_status)
    else:
        dev = _friendly_device(parsed_input.capture_device, ctx.monitor_devices)
    mode = input_type_label(getattr(parsed_input, "input_type", "line"))
    gain = int(parsed_input.gain_db)
    gain_str = f"{gain:+d} dB" if gain != 0 else "0 dB"
    return html.escape(f"{dev} · {mode} · {gain_str}")


def detail_input(index: int, ctx: context.SetupCtx) -> str:
    """An input's detail panel: its card, then its gain and equaliser card,
    and for input 3 the Bluetooth audio buffer."""
    a = ctx.parsed.audio_section(index)
    enabled = ctx.parsed.audio_enabled(index)
    preamp_html = (
        f'<div id="audio{index}_preamp_card" style="display:{"block" if enabled else "none"};">'
        + _audio_controls_card_html(
            input_index=index,
            gain_db=a.gain_db,
            eq_40hz_db=a.eq_40hz_db,
            eq_100hz_db=a.eq_100hz_db,
            eq_8khz_db=a.eq_8khz_db,
        )
        + "</div>"
    )
    buffer_html = cards_bluetooth._bluetooth_buffer_card_html(ctx) if index == BLUETOOTH_INPUT_INDEX else ""
    return _setup_input_card_html(ctx, index) + preamp_html + buffer_html


def register_input_card(index: int) -> None:
    """Add input *index*'s card to the Setup page's registry."""
    bluetooth = index == BLUETOOTH_INPUT_INDEX
    context.register_card(
        f"input{index}",
        f"Input {index} (Bluetooth)" if bluetooth else f"Input {index}",
        partial(summary_input, index),
        partial(detail_input, index),
        detail_header=f"Setup Input {index}",
        present=(lambda ctx: index in present_input_indices(ctx)) if bluetooth else None,
    )
