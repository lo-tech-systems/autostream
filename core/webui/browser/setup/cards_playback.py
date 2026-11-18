#!/usr/bin/env python3
"""webui/browser/setup/cards_playback.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The Playback card of the Setup page: OwnTone settings, playback defaults,
silence detection, repeat and audio processing.
"""

from __future__ import annotations

import html

from autostream_rpi import is_high_performance_pi
from webui.common import settings_card_html
from webui.browser.setup import cards_inputs, context


def _setup_owntone_more_settings_html(parsed) -> str:
    """"More Owntone Settings" / "Run Speaker Synchronisation" button block."""
    _align_supported = True
    try:
        from autostream_state.live import get_capabilities as _get_capabilities
        _align_supported = bool(
            _get_capabilities(parsed.owntone.base_url, timeout=3).can_set_output_offset
        )
    except Exception:
        pass
    _align_button_html = (
        """
          <button type="button"
            onclick="flushPendingToServer().then(function() { window.location.href='/align'; })"
            class="pill-btn small"
            style="width:100%;margin-top:0.5rem;">
            Run Speaker Synchronisation
          </button>"""
        if _align_supported
        else ""
    )
    owntone_button_html = f"""
          <button type="button"
            onclick="flushPendingToServer().then(function() {{ window.location.href='/owntone-setup'; }})"
            class="pill-btn small"
            style="width:100%;margin-top:0.5rem;">
            More Owntone Settings
          </button>{_align_button_html}
        """
    return owntone_button_html


def _auto_start_row_html(member, only_one: bool) -> str:
    """One Auto-Start member: its name and level, and a button to remove it.
    The last member cannot be removed, since the appliance needs one."""
    name = html.escape(member.name)
    return (
        "<div class='autostart-row'>"
        f"<span class='autostart-name'>{name} &middot; {int(member.volume)}%</span>"
        f"<button type='button' class='pill-btn small autostart-remove' aria-label='Remove {name}'"
        f" data-id='{html.escape(member.id)}' data-name='{name}' data-volume='{int(member.volume)}'"
        f" onclick='removeAutoStart(this)'{' disabled' if only_one else ''}>Remove</button>"
        "</div>"
    )


AUTO_START_HELP = "To change it, choose speakers on Home, then tap the pin."
AUTO_START_LAST_MEMBER = " At least one speaker is needed."


def _setup_playback_defaults_card_html(parsed) -> str:
    """Playback panel -- "Auto-Start Speakers" list and "Start volume" card.

    The list is read-only apart from removing a member; the set is chosen on
    Home. The start volume is for speakers outside the set."""
    members = list(parsed.owntone.default_outputs)
    rows = "".join(_auto_start_row_html(m, len(members) == 1) for m in members) or (
        "<div class='autostart-none'>None.</div>"
    )
    last = AUTO_START_LAST_MEMBER if len(members) <= 1 else ""
    playback_defaults_inner_html = f"""
          <div id="autostart_members"><strong>Auto-Start Speakers</strong>{rows}</div>
          <div id="autostart_help" class="helptext">{AUTO_START_HELP}<span id="autostart_last">{last}</span></div>
          <label><div class="slider-header"><span>Start volume for other speakers:</span><span id="vol_val">{parsed.owntone.volume_percent}%</span></div>
          <input type="range" min="0" max="100" value="{parsed.owntone.volume_percent}" oninput="syncVol(this.value)">
          <input type="hidden" id="owntone_volume_percent" name="owntone_volume_percent" value="{parsed.owntone.volume_percent}"></label>
        """
    return settings_card_html(playback_defaults_inner_html, margin_top="0")


def _setup_silence_detection_card_html(parsed) -> str:
    """Playback panel -- silence-detection slider card."""
    # Guidance under the silence slider: with the minimum playback hold
    # active, short timeouts are safe even for automatic turntables whose
    # start button causes a transient long before music. Hidden when the
    # hold is disabled in the config file.
    _min_hold = parsed.general.minimum_playback_seconds
    _silence_hold_note_html = (
        f'<div class="helptext">Once playback starts it continues for at least '
        f'{_min_hold}s, so short settings (5-10s) work well even for automatic '
        f'turntables.</div>'
    ) if _min_hold > 0 else ""
    _sil_pos = cards_inputs._silence_seconds_to_pos(parsed.general.silence_seconds)
    silence_detection_inner_html = f"""
          <label><div class="slider-header"><span>Silence detection:</span><span id="sil_val">{parsed.general.silence_seconds}s</span></div>
          <input type="range" id="sil_range" min="0" max="100" step="0.5" value="{_sil_pos:.1f}" oninput="syncSil(this.value)">
          <input type="hidden" name="silence_seconds" id="silence_seconds" value="{parsed.general.silence_seconds}"></label>
          {_silence_hold_note_html}
        """
    return settings_card_html(silence_detection_inner_html)


def _setup_repeat_playback_card_html(parsed) -> str:
    """Playback panel -- repeat-playback buffer-target card."""
    # Buffer-target select: Vinyl (33) / CD (80), plus a third "Custom" option
    # that surfaces (selected) only when the config file holds some other
    # value -- direct config-file edits keep their freedom without exposing a
    # way to pick a custom value from the UI itself.
    _repeat_target = parsed.repeat.target_minutes
    _repeat_target_options = [(33, "Vinyl (33 minutes)"), (80, "CD (80 minutes)")]
    if _repeat_target not in (33, 80):
        _repeat_target_options.append((_repeat_target, f"Custom ({_repeat_target} minutes)"))
    repeat_target_options_html = "".join(
        f'<option value="{v}"{" selected" if v == _repeat_target else ""}>{html.escape(label)}</option>'
        for v, label in _repeat_target_options
    )
    repeat_playback_inner_html = f"""
          <div class="setup-customise-row">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" name="repeat_enabled" id="repeat_enabled"{'  checked' if parsed.repeat.enabled else ''} onchange="onRepeatEnabledToggle(this.checked)">
              <span class="switch"></span>
            </label>
            <span>Enable repeat playback</span>
          </div>
          <div class="setup-customise-row" id="repeat-target-row" style="margin-top:0.4rem;{'opacity:0.4;' if not parsed.repeat.enabled else ''}">
            <label style="margin:0;flex:1;">Buffer target:
              <select id="repeat_target_minutes" name="repeat_target_minutes"{'' if parsed.repeat.enabled else ' disabled'} onchange="onRepeatTargetChange(this.value)">
                {repeat_target_options_html}
              </select>
            </label>
          </div>
          <div class="helptext" id="repeat-max-time-note">Buffer: &mdash;</div>
          <div class="helptext" id="repeat-unavailable-note" style="display:none;color:var(--color-status-danger);"></div>
        """
    return settings_card_html(repeat_playback_inner_html)


def _setup_audio_processing_card_html(parsed) -> str:
    """Playback panel -- Audio Path card."""
    # Input Resampling Quality options: the Best tier is filtered out of the rendered
    # list on non-Pi4/5-class hardware -- mandatory, not cosmetic, since the
    # top SRC tier is unaffordable there;
    # the server-side validator (_validate_audio_path in
    # the live-config module) is the enforcement backstop for a stale
    # browser tab or a hand-crafted request.
    _audio_path_options = []
    if is_high_performance_pi():
        _audio_path_options.append(("max", "Best (highest CPU use and best quality)"))
    _audio_path_options.append(("balanced", "Balanced (moderate CPU use)"))
    _audio_path_options.append(("fast", "Fast (lowest CPU use, fine for most sources)"))
    audio_path_options_html = "".join(
        f'<option value="{v}"{" selected" if v == parsed.general.audio_path else ""}>{html.escape(label)}</option>'
        for v, label in _audio_path_options
    )
    audio_processing_inner_html = f"""
          <label>Input Resampling Quality:
            <select id="general_audio_path" name="general_audio_path" onchange="if(liveEnabled) settingsSaveField('general.audio_path', this.value);">
              {audio_path_options_html}
            </select>
          </label>
          <div class="helptext">Applies immediately &mdash; playback stops and resumes automatically after a few seconds.</div>
        """
    return settings_card_html(audio_processing_inner_html)


def summary_playback(ctx: context.SetupCtx) -> str:
    speaker = ", ".join(m.name for m in ctx.parsed.owntone.default_outputs) or "No speaker selected"
    return html.escape(f"{speaker} · {ctx.parsed.owntone.volume_percent}%")


def detail_playback(ctx: context.SetupCtx) -> str:
    return (
        _setup_playback_defaults_card_html(ctx.parsed)
        + _setup_silence_detection_card_html(ctx.parsed)
        + _setup_repeat_playback_card_html(ctx.parsed)
        + _setup_audio_processing_card_html(ctx.parsed)
        + _setup_owntone_more_settings_html(ctx.parsed)
    )
