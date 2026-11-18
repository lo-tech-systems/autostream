#!/usr/bin/env python3
"""webui/browser/setup/cards_customise.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The Personalisation card of the Setup page, with its device pause row and
the switch that applies a volume change made at a speaker to all.
"""

from __future__ import annotations

import html

from autostream_state import store
from webui.common import settings_card_html
from webui.components import toggle_html
from webui.browser.setup import context


_DEVICE_PAUSE_OPTIONS = (
    ("ignore", "Keep playing"),
    ("output", "Mute that speaker"),
    ("all", "Mute all playing speakers"),
    ("off_all", "Turn off all speakers"),
)
_DEVICE_PAUSE_HELP = (
    "Applies to Pause on a HomePod or on an Apple TV remote. Play on the same "
    "speaker undoes the mute. A stereo pair, or an Apple TV with its HomePods, "
    "counts as one speaker. \"Turn off all speakers\" keeps them off until you "
    "turn one on again."
)
_DEVICE_PAUSE_NEEDS_VERSION = (
    "Needs owntone-mini 1.6 or above. The connected player handles Pause on its own."
)
_DEVICE_PAUSE_NEEDS_EVENTS = (
    "Needs owntone-mini's event channel, which is off or not connected. "
    "Pause on a speaker does nothing until it is."
)
_SPEAKER_VOLUME_LABEL = "Volume changes made at any speaker apply to all playing speakers"
_SPEAKER_VOLUME_HELP = (
    "Applies to a speaker's own volume buttons, knob or app, and to an Apple TV "
    "remote. The other playing speakers move in proportion to their own levels, "
    "so they all reach silent together. Muted speakers stay muted. A stereo pair, "
    "or an Apple TV with its HomePods, counts as one speaker."
)
_SPEAKER_VOLUME_NEEDS_VERSION = (
    "Needs owntone-mini 1.6 or above. Until then a volume change at a speaker "
    "applies to that speaker only."
)
_SPEAKER_VOLUME_NEEDS_EVENTS = (
    "Needs owntone-mini's event channel, which is off or not connected. A volume "
    "change at a speaker applies to that speaker only until it is."
)


def _pause_off_duration_text(seconds: int) -> str:
    """The pause timeout as people say it: whole minutes where it is one."""
    if seconds >= 60 and seconds % 60 == 0:
        minutes = seconds // 60
        return "1 minute" if minutes == 1 else f"{minutes} minutes"
    return f"{seconds} seconds"


def _device_pause_row_html(parsed, outputs_part) -> str:
    """The Pause choice: what a Pause pressed on a speaker does."""
    scope = parsed.outputs.device_pause_scope
    if not outputs_part.include_tv_supported:
        unavailable = _DEVICE_PAUSE_NEEDS_VERSION
    elif not outputs_part.device_events:
        unavailable = _DEVICE_PAUSE_NEEDS_EVENTS
    else:
        unavailable = ""
    options = "".join(
        f'<option value="{value}"{" selected" if value == scope else ""}>{label}</option>'
        for value, label in _DEVICE_PAUSE_OPTIONS
    )
    off_text = html.escape(
        "Speakers that Pause muted are turned off if Pause lasts longer than "
        + _pause_off_duration_text(parsed.outputs.pause_off_seconds) + "."
    )
    if unavailable:
        help_html = html.escape(unavailable)
    else:
        shown = " " + off_text if scope in ("output", "all") else ""
        help_html = (
            html.escape(_DEVICE_PAUSE_HELP)
            + f'<span id="device_pause_off_note" data-text="{off_text}">{shown}</span>'
        )
    return f"""
          <div class="setup-customise-row" style="margin-top:0.75rem;">
            <label style="margin:0;flex:1;">When Pause is pressed on a speaker
              <select id="device_pause_scope"{' disabled' if unavailable else ''} onchange="var n=document.getElementById('device_pause_off_note'); if(n) n.textContent = (this.value === 'output' || this.value === 'all') ? ' ' + n.getAttribute('data-text') : ''; settingsSaveField('outputs.device_pause_scope', this.value);">
                {options}
              </select>
            </label>
          </div>
          <div class="helptext">{help_html}</div>"""


def _speaker_volume_row_html(parsed, outputs_part) -> str:
    """The switch that applies a volume change made at a speaker to all."""
    if not outputs_part.include_tv_supported:
        unavailable = _SPEAKER_VOLUME_NEEDS_VERSION
    elif not outputs_part.device_events:
        unavailable = _SPEAKER_VOLUME_NEEDS_EVENTS
    else:
        unavailable = ""
    style = "margin-top:0.75rem;opacity:0.4;" if unavailable else "margin-top:0.75rem;"
    toggle = toggle_html(
        name="outputs_speaker_volume_applies_to_all",
        id="outputs_speaker_volume_applies_to_all",
        checked=parsed.outputs.speaker_volume_applies_to_all,
        disabled=bool(unavailable),
        onchange="settingsSaveField('outputs.speaker_volume_applies_to_all', this.checked)",
    )
    return f"""
          <div class="setup-customise-row" style="{style}">
{toggle}
            <span>{html.escape(_SPEAKER_VOLUME_LABEL)}</span>
          </div>
          <div class="helptext">{html.escape(unavailable or _SPEAKER_VOLUME_HELP)}</div>"""


def _setup_customise_card_html(parsed) -> str:
    """Personalisation detail-panel card."""
    outputs_part = store().snapshot().outputs
    _ctrl_other_effective = parsed.webui.show_hostname_on_home and parsed.webui.control_other_appliances
    _ctrl_other_disabled = ' disabled' if not parsed.webui.show_hostname_on_home else ''
    _ctrl_other_row_style = "margin-top:0.75rem;opacity:0.4;" if not parsed.webui.show_hostname_on_home else "margin-top:0.75rem;"
    customise_card_html = settings_card_html(f"""
          <input type="hidden" name="webui_show_master_volume_present" value="1">
          <input type="hidden" name="webui_advertise_appliance_present" value="1">
          <input type="hidden" name="webui_control_other_appliances_present" value="1">
          <div class="setup-customise-row" style="margin-top:0.5rem;">
{toggle_html(name="webui_show_hostname_on_home", id="webui_show_hostname_on_home", checked=parsed.webui.show_hostname_on_home, onchange="onHostnameToggle(this.checked); settingsSaveField('webui.show_hostname_on_home', this.checked)")}
            <span>Display Hostname</span>
          </div>
          <div id="ctrl-other-row" class="setup-customise-row" style="{_ctrl_other_row_style}">
{toggle_html(name="webui_control_other_appliances", id="webui_control_other_appliances", checked=_ctrl_other_effective, disabled=not parsed.webui.show_hostname_on_home, onchange="refreshCustomiseCardSub(); settingsSaveField('webui.control_other_appliances', this.checked)")}
            <span>Allow control of other appliances</span>
          </div>
          <div class="setup-customise-row" style="margin-top:0.75rem;">
{toggle_html(name="webui_advertise_appliance", id="webui_advertise_appliance", checked=parsed.webui.advertise_appliance, onchange="refreshCustomiseCardSub(); if(liveEnabled) settingsTransact('/api/settings/advertisement', {value: this.checked});")}
            <span>Allow control of this from other appliances</span>
          </div>
          <div class="setup-customise-row" style="margin-top:0.75rem;">
{toggle_html(name="webui_show_master_volume", id="webui_show_master_volume", checked=parsed.webui.show_master_volume, onchange="refreshCustomiseCardSub(); settingsSaveField('webui.show_master_volume', this.checked)")}
            <span>Show Master Volume Control</span>
          </div>
          <div class="setup-customise-row" style="margin-top:0.75rem;">
{toggle_html(name="webui_show_input_detail", id="webui_show_input_detail", checked=parsed.webui.show_input_detail, onchange="refreshCustomiseCardSub(); settingsSaveField('webui.show_input_detail', this.checked)")}
            <span>Display Input Detail</span>
          </div>
          <div class="setup-customise-row" style="margin-top:0.75rem;">
{toggle_html(name="webui_dark_mode", id="webui_dark_mode", checked=parsed.webui.dark_mode, onchange="applyDarkMode(this.checked); refreshCustomiseCardSub(); settingsSaveField('webui.dark_mode', this.checked)")}
            <span>Dark Mode</span>
          </div>{_device_pause_row_html(parsed, outputs_part)}{_speaker_volume_row_html(parsed, outputs_part)}
        """, margin_top="0")
    return customise_card_html


def summary_customise(ctx: context.SetupCtx) -> str:
    _ctrl_other_effective = ctx.parsed.webui.show_hostname_on_home and ctx.parsed.webui.control_other_appliances
    return html.escape(
        ("Master volume: On" if ctx.parsed.webui.show_master_volume else "Master volume: Off")
        + (" · Input detail: On" if ctx.parsed.webui.show_input_detail else " · Input detail: Off")
        + (" · Dark mode: On" if ctx.parsed.webui.dark_mode else " · Dark mode: Off")
        + (" · Hostname: On" if ctx.parsed.webui.show_hostname_on_home else " · Hostname: Off")
        + (" · Control others: On" if _ctrl_other_effective else " · Control others: Off")
        + (" · Peer control: On" if ctx.parsed.webui.advertise_appliance else " · Peer control: Off")
    )


def detail_customise(ctx: context.SetupCtx) -> str:
    return _setup_customise_card_html(ctx.parsed)
