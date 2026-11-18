#!/usr/bin/env python3
"""webui/browser/setup/cards_customise.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The Personalisation panel of the Setup page: its Display, Appliance control
and Speaker controls cards. Each row has its label on the left and its
control on the right.
"""

from __future__ import annotations

import html

from autostream_config import DEVICE_PAUSE_ALL
from autostream_state import store
from webui.common import settings_card_html
from webui.components import toggle_html
from webui.browser.setup import context


# The stop times offered for paused speakers, in seconds.
PAUSE_OFF_CHOICES = (60, 180, 300, 600)

_SPEAKER_CONTROLS_NEEDS_VERSION = (
    "Needs owntone-mini 1.6 or above. Until then the connected player handles "
    "Pause on its own, and a volume change at a speaker applies to that speaker only."
)
_SPEAKER_CONTROLS_NEEDS_EVENTS = (
    "Needs owntone-mini's event channel, which is off or not connected. Until it "
    "is, Pause on a speaker does nothing and a volume change at a speaker applies "
    "to that speaker only."
)


def _minutes_text(seconds: int) -> str:
    minutes = seconds // 60
    return "1 minute" if minutes == 1 else f"{minutes} minutes"


def _nearest_pause_off_choice(seconds: int) -> int:
    """The offered stop time nearest a stored one; a tie goes to the longer."""
    return min(PAUSE_OFF_CHOICES, key=lambda c: (abs(c - seconds), -c))


def _card_title_html(title: str) -> str:
    return f'<div class="setup-card-title">{html.escape(title)}</div>'


def _toggle_row_html(*, row_id: str = "", label: str, name: str, checked: bool,
                     onchange: str, disabled: bool = False) -> str:
    """One label-left, switch-right row. The text is a label for the switch,
    so tapping it flips the switch."""
    classes = "setup-pref-row is-disabled" if disabled else "setup-pref-row"
    id_attr = f' id="{row_id}"' if row_id else ""
    toggle = toggle_html(name=name, id=name, checked=checked, disabled=disabled,
                         onchange=onchange)
    return f"""
          <div class="{classes}"{id_attr}>
            <label class="setup-pref-label" for="{name}">{html.escape(label)}</label>
{toggle}
          </div>"""


def _display_card_html(parsed) -> str:
    w = parsed.webui
    return settings_card_html(
        _card_title_html("Display")
        + _toggle_row_html(
            label="Display hostname", name="webui_show_hostname_on_home",
            checked=w.show_hostname_on_home,
            onchange="onHostnameToggle(this.checked); settingsSaveField('webui.show_hostname_on_home', this.checked)")
        + _toggle_row_html(
            label="Show master volume control", name="webui_show_master_volume",
            checked=w.show_master_volume,
            onchange="refreshCustomiseCardSub(); settingsSaveField('webui.show_master_volume', this.checked)")
        + _toggle_row_html(
            label="Display input detail", name="webui_show_input_detail",
            checked=w.show_input_detail,
            onchange="refreshCustomiseCardSub(); settingsSaveField('webui.show_input_detail', this.checked)")
        + _toggle_row_html(
            label="Dark mode", name="webui_dark_mode", checked=w.dark_mode,
            onchange="applyDarkMode(this.checked); refreshCustomiseCardSub(); settingsSaveField('webui.dark_mode', this.checked)"),
        margin_top="0",
    )


def _appliance_control_card_html(parsed) -> str:
    w = parsed.webui
    # Controlling other appliances goes through the hostname pill, so it is
    # off and greyed out while the hostname is not shown.
    return settings_card_html(
        _card_title_html("Appliance control")
        + _toggle_row_html(
            row_id="ctrl-other-row",
            label="Allow control of other appliances", name="webui_control_other_appliances",
            checked=w.show_hostname_on_home and w.control_other_appliances,
            disabled=not w.show_hostname_on_home,
            onchange="refreshCustomiseCardSub(); settingsSaveField('webui.control_other_appliances', this.checked)")
        + _toggle_row_html(
            label="Allow control of this from other appliances", name="webui_advertise_appliance",
            checked=w.advertise_appliance,
            onchange="refreshCustomiseCardSub(); if(liveEnabled) settingsTransact('/api/settings/advertisement', {value: this.checked});"),
    )


def _speaker_controls_card_html(parsed, outputs_part) -> str:
    o = parsed.outputs
    if not outputs_part.include_tv_supported:
        unavailable = _SPEAKER_CONTROLS_NEEDS_VERSION
    elif not outputs_part.device_events:
        unavailable = _SPEAKER_CONTROLS_NEEDS_EVENTS
    else:
        unavailable = ""
    off = bool(unavailable)
    note = (f'<div class="helptext setup-card-note" id="speaker_controls_note">'
            f'{html.escape(unavailable)}</div>') if off else ""

    chosen = _nearest_pause_off_choice(o.pause_off_seconds)
    options = "".join(
        f'<option value="{s}"{" selected" if s == chosen else ""}>{_minutes_text(s)}</option>'
        for s in PAUSE_OFF_CHOICES
    )
    stop_row = f"""
          <div class="setup-pref-row{' is-disabled' if off else ''}">
            <label class="setup-pref-label" for="pause_off_seconds">Stop paused speakers after</label>
            <select id="pause_off_seconds"{' disabled' if off else ''} onchange="settingsSaveField('outputs.pause_off_seconds', Number(this.value));">{options}</select>
          </div>"""

    return settings_card_html(
        _card_title_html("Speaker controls")
        + note
        + _toggle_row_html(
            label="Pause all speakers when pause is pressed on a speaker", name="device_pause_all",
            checked=o.device_pause_scope == DEVICE_PAUSE_ALL, disabled=off,
            onchange="settingsSaveField('outputs.device_pause_scope', this.checked ? 'all' : 'output')")
        + stop_row
        + _toggle_row_html(
            label="Apply volume changes made at any speaker to all playing speakers",
            name="outputs_speaker_volume_applies_to_all",
            checked=o.speaker_volume_applies_to_all, disabled=off,
            onchange="settingsSaveField('outputs.speaker_volume_applies_to_all', this.checked)"),
    )


def _setup_customise_card_html(parsed) -> str:
    """Personalisation detail panel: the Display, Appliance control and
    Speaker controls cards."""
    outputs_part = store().snapshot().outputs
    return (
        _display_card_html(parsed)
        + _appliance_control_card_html(parsed)
        + _speaker_controls_card_html(parsed, outputs_part)
    )


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
