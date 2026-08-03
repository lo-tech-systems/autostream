#!/usr/bin/env python3
"""autostream_webui_page_setup.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Renderer for the main Setup page (/setup).

Contents:
  - _audio_controls_card_html -- render the gain/EQ sliders card for an input
  - send_setup_page           -- render and send the /setup page
"""

from __future__ import annotations

import html
import json
import logging
import math

from datetime import datetime, timezone
from typing import Optional
from urllib.parse import parse_qs

from autostream_config import (
    mark_configured,
)
from autostream_dials import parse_dial_entries

try:
    from autostream_dials import get_all_sightings as _get_dial_sightings
except ImportError:
    def _get_dial_sightings() -> list:  # type: ignore[misc]
        return []

from autostream_core import (
    update_live_owntone_runtime,
    update_playback_input_config,
)
from autostream_player_service import list_outputs
from autostream_players import (
    SETTING_DEVICE_REMOVAL_GRACE_PERIOD_DEFAULT_MINUTES,
    SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MAX_MINUTES,
    SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MIN_MINUTES,
)
from autostream_playback_stats import (
    suggested_silence_threshold_dbfs,
)
from autostream_rpi import is_high_performance_pi
from autostream_sysutils import get_ap_ssid, get_system_hostname
from autostream_webui_assets import (
    A2HS_SCRIPT,
    AUTOSAVE_JS,
    COMMON_MODAL_CSS,
    DIAL_LOCKED_SECTION_CSS,
    ICON_PADLOCK_LOCKED,
    ICON_PADLOCK_UNLOCKED,
    INFO_MODAL_HTML,
    INFO_MODAL_SCRIPT,
    PIN_MODAL_CSS,
)
from autostream_webui_common import (
    _config_snapshot,
    _set_flash_cookie,
    build_page_html,
    build_top_banner_html,
    get_app_version,
    no_input_configured_notice_html,
    settings_card_html,
)
from autostream_webui_state import WebUIState


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


# -----------------------------------------------------------------------------
# Bluetooth input — Setup page surface (the always-rendered Bluetooth card,
# plus the Input cards' dropdown/pairing-modal wiring).
#
# Three independent gates:
#   - installed:        the Bluetooth-input subsystem's unit file exists.
#                        Drives the dropdown/relabel/pairing-modal surface
#                        (the loopback card exists once installed, whether
#                        or not the service itself is enabled).
#   - services_enabled:  the systemd unit is enabled/running. Drives the
#                        Bluetooth card's enabled-vs-disabled body.
#   - onboard_enabled:   the onboard radio (vs. a USB adapter) is in use.
#
# All three lookups are defensive (getattr + try/except) so this page keeps
# rendering identically wherever the helper module is absent.
# -----------------------------------------------------------------------------

BLUETOOTH_LOOPBACK_HW = "hw:CARD=ASBT,DEV=1"
BLUETOOTH_BUFFER_MS_DEFAULT = 200
BLUETOOTH_BUFFER_MS_MIN = 100
BLUETOOTH_BUFFER_MS_MAX = 500


def _bluetooth_installed() -> bool:
    """Whether the optional Bluetooth-input subsystem is installed."""
    try:
        from autostream_bluetooth_client import bluetooth_installed as _real_check
    except ImportError:
        return False
    try:
        return bool(_real_check())
    except Exception:
        return False


def _bluetooth_services_enabled() -> bool:
    """Whether the Bluetooth-input systemd unit is enabled/running."""
    try:
        from autostream_bluetooth_client import bluetooth_services_enabled as _real_check
    except ImportError:
        return False
    try:
        return bool(_real_check())
    except Exception:
        return False


def _bluetooth_onboard_enabled() -> bool:
    """Whether the onboard Bluetooth radio (vs. a USB adapter) is in use."""
    try:
        from autostream_bluetooth_client import bluetooth_onboard_enabled as _real_check
    except ImportError:
        return False
    try:
        return bool(_real_check())
    except Exception:
        return False


def _bluetooth_status_from_state(state: WebUIState) -> Optional[dict]:
    """Fetch the cached Bluetooth status dict from WebUIState, defensively.

    Returns None if the helper is absent or raises -- the caller treats that
    the same as "no Bluetooth device paired / status unknown".
    """
    getter = getattr(state, "get_bluetooth_status", None)
    if not callable(getter):
        return None
    try:
        status = getter()
    except Exception:
        return None
    return status if isinstance(status, dict) else None


def _bluetooth_card_summary(services_enabled: bool, bt_status: Optional[dict]) -> str:
    """Bluetooth card summary line -- delegates to the single shared implementation.

    Defensive-import wrapper, same pattern as the gate checks above: falls
    back to a state derivable from ``services_enabled`` alone wherever the
    helper module is absent, so this page keeps rendering wherever the
    Bluetooth subsystem isn't installed at all.
    """
    try:
        from autostream_bluetooth_client import bluetooth_card_summary as _real
    except ImportError:
        return "Disabled" if not services_enabled else "Enabled · No adapter found"
    try:
        return _real(services_enabled, bt_status)
    except Exception:
        return "Disabled" if not services_enabled else "Enabled · No adapter found"


def _bluetooth_paired_row_text(bt_status: Optional[dict]) -> str:
    """Card 'Paired' row text -- delegates to the single shared implementation."""
    try:
        from autostream_bluetooth_client import bluetooth_paired_row_text as _real
    except ImportError:
        return "No device paired"
    try:
        return _real(bt_status)
    except Exception:
        return "No device paired"


def _bluetooth_input_fragment_text(bt_status: Optional[dict]) -> str:
    """Input-card Bluetooth fragment text -- delegates to the single shared implementation."""
    try:
        from autostream_bluetooth_client import bluetooth_input_fragment_text as _real
    except ImportError:
        return "Not Connected"
    try:
        return _real(bt_status)
    except Exception:
        return "Not Connected"


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _setup_page_header(title: str) -> str:
    return (
        "<div class='eq-page-header'>"
        "<div style='display:flex;align-items:center;gap:0.5rem;'>"
        f"<h1>{html.escape(title)}</h1>"
        "</div>"
        "</div>"
    )


def _setup_detail_header(title: str) -> str:
    return _setup_page_header(title)


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


# -----------------------------------------------------------------------------
# Dial card helpers
# -----------------------------------------------------------------------------

def _relative_time(iso_str: str) -> str:
    if not iso_str:
        return "never seen"
    try:
        parsed = datetime.fromisoformat(iso_str)
        now = datetime.now(timezone.utc)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        delta = now - parsed
        secs = int(delta.total_seconds())
        if secs < 60:
            return "just now"
        if secs < 3600:
            return f"{secs // 60}m ago"
        if secs < 86400:
            return f"{secs // 3600}h ago"
        return f"{secs // 86400}d ago"
    except (ValueError, TypeError):
        return "unknown"


def _dial_card_html(
    *,
    uuid: str,
    name: str = "",
    authorized: bool,
    online: bool,
    last_seen: str = "",
    fw_version: str = "",
    needs_update: bool = False,
) -> str:
    """Normalised dial card for any authorization/online state.

    Root element attributes allow JS to update cards in place without reload:
      data-authorized  "true" | "false"
      data-online      "true" | "false"
      data-new         present when authorized is False
    """
    su = html.escape(uuid)
    nv = html.escape(name or "")

    if authorized and online:
        badge_cls, badge_text = "dial-badge-online", "Online"
    elif authorized:
        badge_cls, badge_text = "dial-badge-offline", "Offline"
    else:
        badge_cls, badge_text = "dial-badge-new", "New"

    title_text = html.escape(name if name else uuid[:16])
    fw_span = (
        f'<span style="font-size:0.75rem;color:var(--color-text-muted);'
        f'margin-left:0.4rem;">· Firmware {html.escape(fw_version)}</span>'
    ) if (fw_version and authorized and online) else ""
    allow_checked = " checked" if authorized else ""
    config_display = "" if authorized else ' style="display:none;"'
    data_new = ' data-new="true"' if not authorized else ""
    last_seen_html = ""
    if authorized and not online and last_seen:
        ls = html.escape(_relative_time(last_seen))
        last_seen_html = (
            f'<div style="font-size:0.75rem;color:var(--color-text-muted);'
            f'margin-top:0.25rem;">Last seen: {ls}</div>'
        )
    fw_update_btn = (
        '<button type="button" class="pill-btn small" style="width:100%;margin-top:0.75rem;"'
        ' data-dial-action="update">Update firmware</button>'
    ) if (online and needs_update) else ""
    pin_btn_margin_top = "0.5rem" if fw_update_btn else "0.75rem"
    current_name_display = nv if nv else html.escape("(unnamed)")

    return settings_card_html(f"""
          <div class="dial-card" data-dial-uuid="{su}"
               data-authorized="{'true' if authorized else 'false'}"
               data-online="{'true' if online else 'false'}"{data_new}
               data-pin-set="false">
            <div class="dial-card-top">
              <div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem;">
                <div>
                  <span class="dial-card-title">{title_text}</span>{fw_span}
                </div>
                <span class="dial-badge {badge_cls}">{badge_text}</span>
              </div>
              <div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.5rem;">
                <label class="output-toggle" style="margin:0;">
                  <input type="checkbox" class="dial-allow"
                         data-dial-action="toggle-allow"{allow_checked}>
                  <span class="switch"></span>
                </label>
                <span>Allow dial to control this appliance</span>
              </div>
            </div>
            {last_seen_html}<div style="font-size:0.7rem;color:var(--color-text-muted);word-break:break-all;margin-top:0.25rem;">UUID: {su}</div>
            <input type="hidden" class="dial-name" value="{nv}">
            <div style="margin-top:0.5rem;font-size:0.9rem;">Current name: <strong class="dial-current-name">{current_name_display}</strong></div>
            <div class="dial-config"{config_display}>
              <div class="dial-locked-section dial-section-locked">
                <div class="dial-locked-header">
                  <span class="dial-locked-label">Settings</span>
                  <button type="button" class="dial-lock-btn" data-dial-action="toggle-lock"
                          aria-label="Unlock settings">{ICON_PADLOCK_LOCKED}</button>
                </div>
                <div class="dial-locked-controls">
                  <button type="button" class="pill-btn small" style="width:100%;margin-top:0.5rem;"
                          data-dial-action="change-name">Change Dial Name</button>
                  <div style="margin-top:0.75rem;">
                    <div class="slider-header">
                      <span>Step:</span>
                      <span class="dial-step-val">2% per click</span>
                    </div>
                    <input type="range" class="dial-step" min="1" max="10" step="1" value="2"
                           oninput="syncDialStep(this)" data-dial-action="save-config" disabled>
                  </div>
                  <div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.75rem;">
                    <label class="output-toggle" style="margin:0;">
                      <input type="checkbox" class="dial-autoupdate" data-dial-action="save-config" disabled>
                      <span class="switch"></span>
                    </label>
                    <span>Auto-update</span>
                  </div>
                  <div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.5rem;">
                    <label class="output-toggle" style="margin:0;">
                      <input type="checkbox" class="dial-channel" data-dial-action="save-config" disabled>
                      <span class="switch"></span>
                    </label>
                    <span>Pre-release updates</span>
                  </div>
                  <div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.5rem;">
                    <label class="output-toggle" style="margin:0;">
                      <input type="checkbox" class="dial-screen-fitted" data-dial-action="save-screen" disabled>
                      <span class="switch"></span>
                    </label>
                    <span>Has Screen Fitted</span>
                  </div>
                  <button type="button" class="pill-btn small" style="width:100%;margin-top:0.75rem;"
                          data-dial-action="change-pin">Change Dial PIN</button>
                </div>
              </div>
              {fw_update_btn}
              <button type="button" class="pill-btn small" style="width:100%;margin-top:{pin_btn_margin_top};"
                      data-dial-action="recover-pin">Reset Lost PIN</button>
            </div>
            <div class="dial-card-msg" style="display:none;margin-top:0.5rem;"></div>
          </div>
        """, margin_top="0")






# -----------------------------------------------------------------------------
# Page renderer
# -----------------------------------------------------------------------------

def send_setup_page(
    handler,
    state: WebUIState,
    auth,
    saved_ok: bool = False,
    error: Optional[str] = None,
    flash_msg: Optional[str] = None,
    flash_type: str = "success",
) -> None:
    """Render the main setup page."""
    try:
        parsed = _config_snapshot(state)
    except Exception:
        try:
            handler.send_response(302)
            handler.send_header("Location", "/")
            handler.end_headers()
        except Exception:
            pass
        return

    h1 = "Setup"
    owntone_button_html = """
          <button type="button"
            onclick="flushPendingToServer().then(function() { window.location.href='/owntone-setup'; })"
            class="pill-btn small"
            style="width:100%;margin-top:0.5rem;">
            More Owntone Settings
          </button>
        """
    _auto_update_checked = " checked" if parsed.updates.auto_update else ""
    _prerelease_checked = " checked" if parsed.updates.update_channel == "dev" else ""
    update_html = f"""
          <input type="hidden" name="updates_auto_update_present" value="1">
          <input type="hidden" name="updates_channel_present" value="1">
          <div>
            <div style="display:flex;align-items:center;">
              <button type="button" id="btnCheck" class="pill-btn small" style="margin-right:auto">Check</button>
              <button type="button" id="btnInst" class="pill-btn small" style="margin:auto" disabled>Install</button>
              <button type="button" class="pill-btn small" style="margin-left:auto" onclick="requestReboot()">Reboot</button>
            </div>
            <div id="updMsg" style="font-size:0.8rem;margin-top:0.3rem;"></div>
          </div>
          <div style="display:flex;align-items:center;gap:.75rem;margin-top:.75rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" name="updates_auto_update" id="updates_auto_update"{_auto_update_checked} onchange="refreshSystemCardSub(); if(liveEnabled) settingsTransact('/api/settings/auto-update', {{value: this.checked}});">
              <span class="switch"></span>
            </label>
            <span>Automatic updates</span>
          </div>
          <div style="display:flex;align-items:center;gap:.75rem;margin-top:.5rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" name="updates_prerelease_channel" id="updates_prerelease_channel"{_prerelease_checked} onchange="if(window.resetUpdateCheckState)resetUpdateCheckState(); refreshSystemCardSub(); settingsSaveField('updates.update_channel', this.checked ? 'dev' : 'stable')">
              <span class="switch"></span>
            </label>
            <span>Enable pre-release updates</span>
          </div>
          <div style="font-size:0.75rem;color:#888;margin-top:0.25rem;">Pre-release versions may be less stable.</div>
        """

    monitor_devices = state.get_monitor_devices()

    bt_enabled = _bluetooth_installed()
    bt_status = _bluetooth_status_from_state(state) if bt_enabled else None
    bt_paired = bool(bt_status and bt_status.get("paired"))
    bt_services_on = _bluetooth_services_enabled() if bt_enabled else False
    bt_onboard_on = _bluetooth_onboard_enabled() if bt_enabled else False
    bt_buffer_ms = BLUETOOTH_BUFFER_MS_DEFAULT
    try:
        if isinstance(bt_status, dict) and isinstance(bt_status.get("buffer_ms"), int):
            bt_buffer_ms = max(
                BLUETOOTH_BUFFER_MS_MIN, min(BLUETOOTH_BUFFER_MS_MAX, int(bt_status["buffer_ms"]))
            )
    except Exception:
        bt_buffer_ms = BLUETOOTH_BUFFER_MS_DEFAULT
    bt_card_summary = _bluetooth_card_summary(bt_services_on, bt_status)
    bt_paired_row_text = _bluetooth_paired_row_text(bt_status)

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
            bt_attr = " data-bt='1'" if hw == BLUETOOTH_LOOPBACK_HW else ""
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
        turntable_name: str,
        enabled: bool = True,
        enabled_name: Optional[str] = None,
        bt_enabled: bool = False,
        other_capture_device: Optional[str] = None,
    ) -> str:
        prefix = "audio1" if input_index == 1 else "audio2"
        threshold_id = "audio_silence_threshold" if input_index == 1 else "audio2_silence_threshold"
        turntable_note_id = f"{prefix}_turntable_note"
        settings_wrap_id = f"{prefix}_settings"
        is_turntable = bool(parsed_input.is_turntable)
        threshold_preset = suggested_silence_threshold_dbfs(is_turntable)

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
            <div style="display:flex;align-items:center;gap:0.75rem;margin-top:0.9rem;">
              <label class="output-toggle" style="margin:0;">
                <input type="checkbox" name="{turntable_name}" {'checked' if is_turntable else ''} onchange="syncInputUi({input_index}); if(liveEnabled) settingsSaveField('audio{input_index}.turntable', this.checked);">
                <span class="switch"></span>
              </label>
              <span>Turntable</span>
            </div>
            <div id="{turntable_note_id}" class="helptext" style="text-align:left;">
              Detection threshold preset: {threshold_preset:.0f} dB
            </div>
            <input type="hidden" id="{threshold_id}" name="{threshold_name}" value="{threshold_preset}">
          {settings_close}
        """
        return settings_card_html(inner_html, margin_top="0")

    owntone_outputs_html = ""
    outputs_result = list_outputs(parsed.owntone.base_url, timeout=3)
    if outputs_result.ok:
        hidden = {str(n).strip().casefold() for n in (parsed.webui.hidden_outputs or ()) if str(n).strip()}
        for out in outputs_result.outputs:
            nm = str(out.name or "")
            if not nm:
                continue
            if nm.strip().casefold() in hidden and nm != parsed.owntone.output_name:
                continue
            sel = " selected" if nm == parsed.owntone.output_name else ""
            owntone_outputs_html += f"<option value='{html.escape(nm)}'{sel}>{html.escape(nm)}</option>"

    lic_html, lic_spacer = build_top_banner_html(flash_msg=flash_msg, flash_type=flash_type)
    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""
    csrf_meta = f"<meta name='csrf-token' content='{html.escape(csrf_token)}'><script>window.__CSRF='{html.escape(csrf_token)}';</script>"
    pin_modal_setup_css = """
      #pinModal .pin-entry {
        -webkit-text-security: disc;
        text-security: disc;
      }
      #savingModal .modal-panel {
        --modal-width: 18rem;
      }
      .saving-modal-body {
        display: flex;
        align-items: center;
        gap: 0.85rem;
      }
      .saving-spinner {
        width: 1.4rem;
        height: 1.4rem;
        flex: 0 0 auto;
        border: 3px solid var(--color-border-nav);
        border-top-color: var(--color-btn-bg);
        border-radius: 50%;
        animation: saving-spin 0.8s linear infinite;
      }
      @keyframes saving-spin {
        to { transform: rotate(360deg); }
      }
      @media (prefers-reduced-motion: reduce) {
        .saving-spinner { animation-duration: 1.6s; }
      }
    """

    # Factory reset danger zone
    factory_reset_modal_css = ""
    factory_reset_zone = ""
    factory_reset_modal = ""
    factory_reset_js = ""
    reboot_modal = ""
    ap_ssid = get_ap_ssid()
    pin_val = auth.get_boot_pin_value()
    safe_ssid = html.escape(ap_ssid)
    if pin_val:
        modal_body_html = (
            f"This will erase all settings, including WiFi settings, and reboot "
            f"the appliance.<br><br>After reboot, connect to the WiFi network "
            f"<strong>{safe_ssid}</strong> to reconfigure the appliance. "
            f"You will need the factory-configured PIN "
            f"(<strong>{html.escape(pin_val)}</strong>). "
            f"<br><br>Do you wish to continue?"
        )
    else:
        modal_body_html = (
            f"This will erase all settings, including WiFi settings, and then reboot "
            f"the appliance. After reboot, please connect to the WiFi network "
            f"<strong>{safe_ssid}</strong> to reconfigure the appliance. "
            f"You will need the factory-configured PIN. "
            f"Do you wish to continue?"
        )

    factory_reset_modal_css = """
      #factoryResetModal .modal-panel{--modal-width:28rem;--modal-bg:var(--color-surface-raised);}
      #factoryResetModal .modal-hdr{--modal-title-color:var(--color-status-danger);}
    """

    factory_reset_zone = f"""
      <div style="margin-top:2rem;padding:1rem 1.25rem;border:1.5px solid var(--color-status-danger);border-radius:8px;">
        <p style="margin:0 0 0.5rem;font-weight:600;color:var(--color-status-danger);">Factory Reset</p>
        <p style="margin:0 0 0.75rem;font-size:0.95rem;color:var(--color-text);">Factory Reset returns the appliance to first-run Wi-Fi setup mode. All settings will be erased.</p>
        <button type="button"
          id="btnFactoryReset"
          class="pill-btn"
          style="width:100%;color:#fff;"
          onclick="showFactoryResetModal()">
          Factory Reset
        </button>
      </div>"""

    factory_reset_modal = f"""
      <div id="factoryResetModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="factoryResetModalTitle">
        <div class="panel modal-panel">
          <div class="hdr modal-hdr" id="factoryResetModalTitle">Factory Reset</div>
          <div class="bd modal-bd">
            <p id="factoryResetModalMsg">{modal_body_html}</p>
            <p id="factoryResetModalError" style="display:none;color:var(--color-status-danger);font-weight:600;"></p>
          </div>
          <div class="ft modal-ft">
            <button type="button" class="btn modal-btn modal-btn-secondary" id="factoryResetCancel"
              onclick="hideFactoryResetModal()">Cancel</button>
            <button type="button" class="btn modal-btn modal-btn-danger" id="factoryResetContinue"
              onclick="doFactoryReset()">Continue</button>
          </div>
        </div>
      </div>"""

    reboot_modal = """
      <div id="rebootModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="rebootModalTitle">
        <div class="panel modal-panel">
          <div class="hdr modal-hdr" id="rebootModalTitle">Reboot System</div>
          <div class="bd modal-bd">
            <p>This will reboot autostream. Please allow 90 seconds for the system to restart.</p>
          </div>
          <div class="ft modal-ft">
            <button type="button" class="btn modal-btn modal-btn-secondary" id="rebootModalCancel"
              onclick="hideRebootModal()">Cancel</button>
            <button type="button" class="btn modal-btn modal-btn-primary" id="rebootModalOk"
              onclick="confirmReboot()">Reboot</button>
          </div>
        </div>
      </div>"""

    factory_reset_js = f"""
      <script>
        function showFactoryResetModal() {{
          const m = document.getElementById('factoryResetModal');
          if (m) m.classList.add('show');
        }}
        function hideFactoryResetModal() {{
          const m = document.getElementById('factoryResetModal');
          if (m) m.classList.remove('show');
        }}
        function showRebootModal() {{
          const m = document.getElementById('rebootModal');
          if (m) m.classList.add('show');
        }}
        function hideRebootModal() {{
          const m = document.getElementById('rebootModal');
          if (m) m.classList.remove('show');
        }}
        async function confirmReboot() {{
          hideRebootModal();
          try {{
            fetch("/api/reboot", {{
              method: "POST",
              headers: {{"X-CSRF-Token": window.__CSRF || ""}},
              cache: "no-store",
              keepalive: true
            }});
          }} catch (e) {{}}
          window.location.replace("/offline/rebooting");
        }}
        async function doFactoryReset() {{
          const cont = document.getElementById('factoryResetContinue');
          const canc = document.getElementById('factoryResetCancel');
          const errEl = document.getElementById('factoryResetModalError');
          if (cont) cont.disabled = true;
          if (canc) canc.disabled = true;
          try {{
            const r = await fetch('/api/factory-reset', {{
              method: 'POST',
              headers: {{
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-Token': window.__CSRF || ''
              }},
              body: 'csrf_token=' + encodeURIComponent(window.__CSRF || ''),
              keepalive: true
            }});
            let ok = false;
            try {{ const j = await r.json(); ok = !!(j && j.ok); }} catch (e) {{}}
            if (ok) {{
              window.location.replace('/offline/resetting');
            }} else {{
              if (errEl) {{ errEl.textContent = 'Reset could not be scheduled. Please try again.'; errEl.style.display = ''; }}
              if (cont) cont.disabled = false;
              if (canc) canc.disabled = false;
            }}
          }} catch (e) {{
            // Network error: the service may have already started resetting.
            window.location.replace('/offline/resetting');
          }}
        }}
      </script>"""

    input1_html = input_fieldset_html(
        input_index=1,
        title="Input 1",
        parsed_input=parsed.audio1,
        capture_name="audio_capture_device",
        threshold_name="audio_silence_threshold",
        turntable_name="audio_turntable",
        enabled=parsed.audio1_enabled,
        enabled_name="audio1_enabled",
        bt_enabled=bt_enabled,
        other_capture_device=parsed.audio2.capture_device,
    )
    input2_html = input_fieldset_html(
        input_index=2,
        title="Input 2",
        parsed_input=parsed.audio2,
        capture_name="audio2_capture_device",
        threshold_name="audio2_silence_threshold",
        turntable_name="audio2_turntable",
        enabled=parsed.audio2_enabled,
        enabled_name="audio2_enabled",
        bt_enabled=bt_enabled,
        other_capture_device=parsed.audio1.capture_device,
    )

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

    # Audio Path options: Maximum Quality is filtered out of the rendered
    # list on non-Pi4/5-class hardware -- mandatory, not cosmetic, since the
    # top SRC tier is unaffordable there;
    # the server-side validator (_validate_audio_path in
    # autostream_webui_api.py) is the enforcement backstop for a stale
    # browser tab or a hand-crafted request.
    _audio_path_options = []
    if is_high_performance_pi():
        _audio_path_options.append(("max", "Maximum Quality"))
    _audio_path_options.append(("balanced", "Balanced"))
    _audio_path_options.append(("fast", "Fast"))
    audio_path_options_html = "".join(
        f'<option value="{v}"{" selected" if v == parsed.general.audio_path else ""}>{html.escape(label)}</option>'
        for v, label in _audio_path_options
    )

    # Fieldset fragments shared by both layout paths -- split into four
    # untitled cards (playback defaults / silence detection / repeat
    # playback / audio processing) rather than one combined fieldset;
    # structural split only, every existing element id/handler below is
    # unchanged so existing wiring (JS + tests) keeps working.
    playback_defaults_inner_html = f"""
          <label>Default Speakers:
            <select id="owntone_output_select" name="owntone_output_name" onchange="refreshPlaybackCardSub(); if(liveEnabled) settingsSaveField('owntone.output_name', this.value);">
              {owntone_outputs_html}
            </select>
            <div id="owntone_output_hint" class="helptext" style="display:none;">
              Looking for speakers…
            </div>
          </label>
          <label><div class="slider-header"><span>Default Volume:</span><span id="vol_val">{parsed.owntone.volume_percent}%</span></div>
          <input type="range" min="0" max="100" value="{parsed.owntone.volume_percent}" oninput="syncVol(this.value)">
          <input type="hidden" id="owntone_volume_percent" name="owntone_volume_percent" value="{parsed.owntone.volume_percent}"></label>
        """
    _sil_pos = _silence_seconds_to_pos(parsed.general.silence_seconds)
    silence_detection_inner_html = f"""
          <label><div class="slider-header"><span>Silence detection:</span><span id="sil_val">{parsed.general.silence_seconds}s</span></div>
          <input type="range" id="sil_range" min="0" max="100" step="0.5" value="{_sil_pos:.1f}" oninput="syncSil(this.value)">
          <input type="hidden" name="silence_seconds" id="silence_seconds" value="{parsed.general.silence_seconds}"></label>
          {_silence_hold_note_html}
        """
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
          <div class="helptext" id="repeat-max-time-note">Buffer: —</div>
          <div class="helptext" id="repeat-unavailable-note" style="display:none;color:var(--color-status-danger);"></div>
        """
    audio_processing_inner_html = f"""
          <label>Audio Path:
            <select id="general_audio_path" name="general_audio_path" onchange="if(liveEnabled) settingsSaveField('general.audio_path', this.value);">
              {audio_path_options_html}
            </select>
          </label>
          <div class="helptext">Applies immediately — playback stops and resumes automatically after a few seconds.</div>
        """
    playback_fieldset_html = (
        settings_card_html(playback_defaults_inner_html, margin_top="0")
        + settings_card_html(silence_detection_inner_html)
        + settings_card_html(repeat_playback_inner_html)
        + settings_card_html(audio_processing_inner_html)
        + owntone_button_html
    )
    # Network card (Section 9.x): active-adapter information + Change Wi-Fi
    # Network action.  This is informational, not a selector; the active adapter
    # is fetched from the authenticated network-status API on panel open.
    network_card_inner_html = """
          <div id="networkCard">
            <p id="networkCardTitle" style="margin:0 0 0.5rem;font-weight:700;">Network</p>
            <p id="networkAdapterInfo" style="margin:0 0 0.25rem;font-size:0.9rem;color:var(--color-text);white-space:pre-line;">Checking status...</p>
            <p id="networkAddressInfo" style="display:none;margin:0 0 0.25rem;font-size:0.8rem;color:var(--color-text-muted,#888);"></p>
            <p id="networkWarning" style="display:none;margin:0.25rem 0 0;font-size:0.8rem;font-weight:600;"></p>
            <p id="networkSupportDetail" style="display:none;margin:0.15rem 0 0.5rem;font-size:0.75rem;color:var(--color-text-muted,#888);"></p>
            <p id="networkUsbPending" style="display:none;margin:0.25rem 0 0.5rem;font-size:0.8rem;color:var(--color-text-muted,#888);">autostream will switch to the USB adapter when playback stops. You will need to close and re-open the autostream app to reconnect.</p>
            <div style="display:flex;align-items:center;gap:.75rem;margin-top:.5rem;">
              <label class="output-toggle" style="margin:0;">
                <input type="checkbox" name="network_roaming_managed" id="networkRoamingManaged" onchange="setRoamingManagement(this.checked)">
                <span class="switch"></span>
              </label>
              <span>Manage USB adapter roaming</span>
            </div>
            <div style="font-size:0.75rem;color:#888;margin-top:0.25rem;">This may improve connection stability for some USB adapters.</div>
            <button type="button" class="pill-btn small" style="width:100%;margin-top:0.5rem;" onclick="changeWifiNetwork()">Change Wi-Fi Network</button>
            <p id="networkSetupMsg" style="margin:0.5rem 0 0;font-size:0.8rem;color:var(--color-text-muted,#888);"></p>
          </div>
        """
    current_hostname = get_system_hostname()
    try:
        mdns_grace_period_minutes = max(
            SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MIN_MINUTES,
            min(
                SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MAX_MINUTES,
                round(int(parsed.general.mdns_grace_period_seconds) / 60),
            ),
        )
    except Exception:
        mdns_grace_period_minutes = SETTING_DEVICE_REMOVAL_GRACE_PERIOD_DEFAULT_MINUTES
    _mdns_grace_oninput = (
        "document.getElementById('mdns_grace_period_val').textContent=this.value+' min';"
        "if(liveEnabled) syncMdnsGracePeriod(this.value);"
    )
    system_card_inner_html = f"""
          <div>
            <div style="display:flex;align-items:center;gap:.75rem;">
            <span>Hostname:</span>
            <strong id="systemHostnameValue" style="flex:1;min-width:8rem;word-break:break-word;">{html.escape(current_hostname)}</strong>
            </div>
            <button type="button" id="btnChangeHostname" class="pill-btn small" style="width:100%;margin-top:0.5rem;">Change Hostname</button>
            <button type="button" id="btnChangePin" class="pill-btn small" style="width:100%;margin-top:0.5rem;">Change PIN</button>
            <label style="display:block;margin-top:0.75rem;">
              <div class="slider-header">
                <span>mDNS Grace Period:</span>
                <span id="mdns_grace_period_val">{mdns_grace_period_minutes} min</span>
              </div>
              <input type="range" name="mdns_grace_period_minutes"
                min="{SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MIN_MINUTES}"
                max="{SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MAX_MINUTES}"
                step="1"
                value="{mdns_grace_period_minutes}"
                oninput="{html.escape(_mdns_grace_oninput)}">
              <div class="storage-meta">Minutes to keep stale appliance discovery records before removal.</div>
            </label>
          </div>
        """
    system_card_html = settings_card_html(
        "<p style=\"margin:0 0 0.5rem;font-weight:700;\">System</p>"
        + system_card_inner_html,
        margin_top="0",
    )
    network_card_html = settings_card_html(network_card_inner_html, margin_top="0.75rem")
    updates_card_html = settings_card_html(
        "<p style=\"margin:0 0 0.5rem;font-weight:700;\">Updates</p>"
        + update_html,
        margin_top="0.75rem",
    )
    system_fieldset_html = system_card_html + network_card_html + updates_card_html

    _dial_onload_js = ""

    def _friendly(hw) -> str:
        """Return shortened card name for use in sub-labels (first segment before ', ')."""
        for d in monitor_devices:
            if str(d.get("hw") or "").strip() == str(hw or "").strip():
                c = str(d.get("card") or "").strip()
                return c.split(", ")[0].strip() if c else str(hw)
        return str(hw) if hw else "Not configured"

    def _input_card_summary(parsed_input) -> str:
        dev = _friendly(parsed_input.capture_device)
        mode = "Turntable" if parsed_input.is_turntable else "Line In"
        if bt_enabled and parsed_input.capture_device == BLUETOOTH_LOOPBACK_HW:
            # Bluetooth input: the ALSA card name ("Loopback") and the
            # turntable flag are implementation detail here \u2014 show the
            # connected device's name (or the connection state) instead.
            dev = "Bluetooth"
            mode = _bluetooth_input_fragment_text(bt_status)
        gain = int(parsed_input.gain_db)
        gain_str = f"{gain:+d} dB" if gain != 0 else "0 dB"
        return html.escape(f"{dev} \u00b7 {mode} \u00b7 {gain_str}")

    if not parsed.audio1_enabled:
        input1_summary = "Not configured"
    else:
        input1_summary = _input_card_summary(parsed.audio1)
    if not parsed.audio2_enabled:
        input2_summary = "Disabled"
    else:
        input2_summary = _input_card_summary(parsed.audio2)

    # ── Bluetooth card (setup page §2) ──────────────────────────────────────
    _bt_adapter_present = bool(bt_status and bt_status.get("adapter_present"))
    _bt_adapter_kind = str((bt_status or {}).get("adapter_kind") or "") if bt_status else ""
    if not _bt_adapter_present:
        _bt_adapter_text = "No Bluetooth adapter found — plug in a USB adapter, or enable the onboard device below."
    elif _bt_adapter_kind == "usb":
        _bt_adapter_text = "USB adapter"
    elif _bt_adapter_kind == "onboard":
        _bt_adapter_text = "Onboard"
    else:
        _bt_adapter_text = "Detected"
    _bt_no_adapter_grey = "" if _bt_adapter_present else "opacity:0.4;pointer-events:none;"
    _bt_onboard_disabled_attr = "" if bt_services_on else " disabled"
    _bt_forget_style = "" if bt_paired else "display:none;"
    # The enabled-body's interactive rows (Forget/Pair/Buffer) reference JS
    # functions (openBtPairingModal, _btPost, ...) that only exist when the
    # subsystem is installed -- bt_services_on can only be True when
    # bt_enabled is also True, so this body is otherwise unreachable, but it
    # is only emitted at all when installed to avoid dead references to
    # functions that were never rendered.
    _bt_enabled_body = ""
    if bt_enabled:
        _bt_enabled_body = f"""
          <div id="btEnabledBody" style="display:{'block' if bt_services_on else 'none'};">
            <div style="display:flex;align-items:center;gap:.75rem;">
              <span>Bluetooth services: Enabled</span>
              <button type="button" id="btnBtDisableServices" class="pill-btn small" style="margin-left:auto;"
                onclick="btDisableServices()">Disable</button>
            </div>
            <p id="btAdapterRow" style="margin:0.5rem 0;font-size:0.9rem;">Adapter: {html.escape(_bt_adapter_text)}</p>
            <div style="display:flex;align-items:center;gap:.75rem;margin-top:.5rem;">
              <label class="output-toggle" style="margin:0;">
                <input type="checkbox" id="btOnboardToggle"{' checked' if bt_onboard_on else ''}{_bt_onboard_disabled_attr}
                  onchange="btOnboardToggleChanged(this.checked)">
                <span class="switch"></span>
              </label>
              <span>Use onboard bluetooth device</span>
            </div>
            <div style="font-size:0.75rem;color:#888;margin-top:0.25rem;">
              A USB Bluetooth adapter is strongly recommended. Changing this restarts the appliance.
            </div>
            <div id="btAdapterGatedRow" style="margin-top:0.75rem;{_bt_no_adapter_grey}">
              <p id="btPairedRow" style="margin:0 0 0.5rem;">{html.escape(bt_paired_row_text)}</p>
              <button type="button" id="btnBtForget" class="pill-btn small" style="width:100%;{_bt_forget_style}"
                onclick="btForgetFromCard()">Forget</button>
              <button type="button" id="btnBtPairNew" class="pill-btn small" style="width:100%;margin-top:0.5rem;"
                onclick="openBtPairingModal(null, null)">Pair new device…</button>
              <label style="display:block;margin-top:0.75rem;">
                <div class="slider-header"><span>Bluetooth Audio Buffer:</span><span id="btBufferVal">{bt_buffer_ms} ms</span></div>
                <input type="range" id="btBufferRange" min="{BLUETOOTH_BUFFER_MS_MIN}" max="{BLUETOOTH_BUFFER_MS_MAX}"
                  step="10" value="{bt_buffer_ms}" oninput="btBufferInput(this.value)">
                <div class="helptext">Larger values ride out wireless glitches; smaller values reduce the
                  delay before you hear the needle drop.</div>
              </label>
            </div>
          </div>
        """
    bluetooth_card_inner_html = f"""
          <input type="hidden" name="bluetooth_present" value="1">
          <div id="btDisabledBody" style="display:{'none' if bt_services_on else 'block'};">
            <p style="margin:0 0 0.5rem;">Connect a Bluetooth device (such as a turntable with Bluetooth
              output) as an audio input.</p>
            <button type="button" id="btnBtEnableServices" class="pill-btn small" style="width:100%;"
              onclick="btEnableServices()">Enable Bluetooth Services</button>
          </div>
          {_bt_enabled_body}
        """
    bluetooth_card_html = settings_card_html(bluetooth_card_inner_html, margin_top="0")

    speaker = str(parsed.owntone.output_name or "No speaker selected")
    playback_summary = html.escape(f"{speaker} \u00b7 {parsed.owntone.volume_percent}%")
    _au_state = "Auto-update: On" if parsed.updates.auto_update else "Auto-update: Off"
    if parsed.updates.update_channel == "dev":
        _au_state += " - Pre-release channel"
    system_summary = html.escape(f"{current_hostname} \u00b7 v{get_app_version()} \u00b7 {_au_state}")
    _ctrl_other_effective = parsed.webui.show_hostname_on_home and parsed.webui.control_other_appliances
    customise_summary = html.escape(
        ("Master volume: On" if parsed.webui.show_master_volume else "Master volume: Off")
        + (" \u00b7 Input detail: On" if parsed.webui.show_input_detail else " \u00b7 Input detail: Off")
        + (" \u00b7 Dark mode: On" if parsed.webui.dark_mode else " \u00b7 Dark mode: Off")
        + (" \u00b7 Hostname: On" if parsed.webui.show_hostname_on_home else " \u00b7 Hostname: Off")
        + (" \u00b7 Control others: On" if _ctrl_other_effective else " \u00b7 Control others: Off")
        + (" \u00b7 Visible to peers: On" if parsed.webui.advertise_appliance else " \u00b7 Visible to peers: Off")
    )
    _ctrl_other_disabled = ' disabled' if not parsed.webui.show_hostname_on_home else ''
    _ctrl_other_row_style = "margin-top:0.75rem;opacity:0.4;" if not parsed.webui.show_hostname_on_home else "margin-top:0.75rem;"
    customise_card_html = settings_card_html(f"""
          <input type="hidden" name="webui_show_master_volume_present" value="1">
          <input type="hidden" name="webui_advertise_appliance_present" value="1">
          <input type="hidden" name="webui_control_other_appliances_present" value="1">
          <div class="setup-customise-row" style="margin-top:0.5rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" name="webui_show_hostname_on_home" id="webui_show_hostname_on_home"{'  checked' if parsed.webui.show_hostname_on_home else ''} onchange="onHostnameToggle(this.checked); settingsSaveField('webui.show_hostname_on_home', this.checked)">
              <span class="switch"></span>
            </label>
            <span>Display Hostname</span>
          </div>
          <div id="ctrl-other-row" class="setup-customise-row" style="{_ctrl_other_row_style}">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" name="webui_control_other_appliances" id="webui_control_other_appliances"{'  checked' if _ctrl_other_effective else ''}{_ctrl_other_disabled} onchange="refreshCustomiseCardSub(); settingsSaveField('webui.control_other_appliances', this.checked)">
              <span class="switch"></span>
            </label>
            <span>Allow control of other appliances</span>
          </div>
          <div class="setup-customise-row" style="margin-top:0.75rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" name="webui_advertise_appliance" id="webui_advertise_appliance"{'  checked' if parsed.webui.advertise_appliance else ''} onchange="refreshCustomiseCardSub(); if(liveEnabled) settingsTransact('/api/settings/advertisement', {{value: this.checked}});">
              <span class="switch"></span>
            </label>
            <span>Allow control of this from other appliances</span>
          </div>
          <div class="setup-customise-row" style="margin-top:0.75rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" name="webui_show_master_volume" id="webui_show_master_volume"{'  checked' if parsed.webui.show_master_volume else ''} onchange="refreshCustomiseCardSub(); settingsSaveField('webui.show_master_volume', this.checked)">
              <span class="switch"></span>
            </label>
            <span>Show Master Volume Control</span>
          </div>
          <div class="setup-customise-row" style="margin-top:0.75rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" name="webui_show_input_detail" id="webui_show_input_detail"{'  checked' if parsed.webui.show_input_detail else ''} onchange="refreshCustomiseCardSub(); settingsSaveField('webui.show_input_detail', this.checked)">
              <span class="switch"></span>
            </label>
            <span>Display Input Detail</span>
          </div>
          <div class="setup-customise-row" style="margin-top:0.75rem;">
            <label class="output-toggle" style="margin:0;">
              <input type="checkbox" name="webui_dark_mode" id="webui_dark_mode"{'  checked' if parsed.webui.dark_mode else ''} onchange="applyDarkMode(this.checked); refreshCustomiseCardSub(); settingsSaveField('webui.dark_mode', this.checked)">
              <span class="switch"></span>
            </label>
            <span>Dark Mode</span>
          </div>
        """, margin_top="0")

    # Track identification card
    _ti = parsed.track_identification
    _ti_enabled = bool(_ti.enabled)
    track_id_summary = html.escape("On" if _ti_enabled else "Off")
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

    # Build dial cards data
    _all_sightings = _get_dial_sightings()
    _authorized_entries = parse_dial_entries()
    _sightings_by_uuid = {s.uuid: s for s in _all_sightings}
    _authorized_uuids = {e.uuid for e in _authorized_entries}
    _n_auth = len(_authorized_entries)
    _n_online = sum(1 for e in _authorized_entries if e.uuid in _sightings_by_uuid)
    _n_new = sum(1 for s in _all_sightings if s.uuid not in _authorized_uuids)
    if _n_auth == 0 and _n_new == 0:
        _dials_summary = "No dials"
    elif _n_auth == 0:
        _dials_summary = f"{_n_new} new"
    elif _n_new > 0:
        _dials_summary = f"{_n_auth} authorized · {_n_new} new"
    else:
        _dials_summary = f"{_n_auth} authorized" + (f" · {_n_online} online" if _n_online else "")
    _dials_summary = html.escape(_dials_summary)
    _app_ver = get_app_version()
    _dial_cards_html = ""
    for _entry in _authorized_entries:
        _sighting = _sightings_by_uuid.get(_entry.uuid)
        _is_online = _sighting is not None
        _name = _entry.current_name or _entry.name or (_sighting.name if _sighting else "")
        _fw = (_sighting.version or "") if _sighting else ""
        _needs_upd = bool(_sighting and _sighting.version and _app_ver and _sighting.version != _app_ver)
        _ls = str(getattr(_entry, "last_seen", "") or "")
        _dial_cards_html += _dial_card_html(
            uuid=_entry.uuid,
            name=_name,
            authorized=True,
            online=_is_online,
            last_seen=_ls,
            fw_version=_fw,
            needs_update=_needs_upd,
        )
    for _sighting in _all_sightings:
        if _sighting.uuid not in _authorized_uuids:
            _new_fw = _sighting.version or ""
            _new_needs_upd = bool(_new_fw and _app_ver and _new_fw != _app_ver)
            _dial_cards_html += _dial_card_html(
                uuid=_sighting.uuid,
                name=_sighting.name or "",
                authorized=False,
                online=True,
                fw_version=_new_fw,
                needs_update=_new_needs_upd,
            )
    if not _dial_cards_html:
        _dial_cards_html = (
            "<p style='color:var(--color-text-muted);font-style:italic;margin-top:0.5rem;'>"
            "No dials found on the network.</p>"
        )
    _dial_onload_js = (
        'document.querySelectorAll(\'.dial-card[data-authorized="true"]\').forEach(function(card) { '
        "dialLoadConfig(card); dialLoadScreenSettings(card); });"
    )

    form_content_html = f"""<div class="setup-slide-viewport">
  <div class="setup-slide-track" id="setupSlideTrack">
    <div class="setup-slide-list">
      {_setup_page_header("Setup")}
      <div id="autosave-status" aria-live="polite" style="font-size:0.85rem;color:var(--color-text-dim);min-height:1.2em;margin-bottom:0.25rem;"></div>
      {no_input_configured_notice_html(parsed)}
      <div class="setup-list-card" onclick="openPanel('input1')">
        <div class="setup-list-card-body">
          <span class="setup-list-card-title">Input 1</span>
          <span class="setup-list-card-sub" id="input1-card-sub">{input1_summary}</span>
        </div>
        <span class="setup-list-chevron">\u203a</span>
      </div>
      <div class="setup-list-card" onclick="openPanel('input2')">
        <div class="setup-list-card-body">
          <span class="setup-list-card-title">Input 2</span>
          <span class="setup-list-card-sub" id="input2-card-sub">{input2_summary}</span>
        </div>
        <span class="setup-list-chevron">\u203a</span>
      </div>
      <div class="setup-list-card" onclick="openPanel('bluetooth')">
        <div class="setup-list-card-body">
          <span class="setup-list-card-title">Bluetooth</span>
          <span class="setup-list-card-sub" id="bluetooth-card-sub">{bt_card_summary}</span>
        </div>
        <span class="setup-list-chevron">›</span>
      </div>
      <div class="setup-list-card" onclick="openPanel('playback')">
        <div class="setup-list-card-body">
          <span class="setup-list-card-title">Playback</span>
          <span class="setup-list-card-sub" id="playback-card-sub">{playback_summary}</span>
        </div>
        <span class="setup-list-chevron">\u203a</span>
      </div>
      <div class="setup-list-card" onclick="openPanel('track-id')">
        <div class="setup-list-card-body">
          <span class="setup-list-card-title">Track Identification</span>
          <span class="setup-list-card-sub" id="track-id-card-sub">{track_id_summary}</span>
        </div>
        <span class="setup-list-chevron">\u203a</span>
      </div>
      <div class="setup-list-card" onclick="openPanel('dials')">
        <div class="setup-list-card-body">
          <span class="setup-list-card-title">Dials</span>
          <span class="setup-list-card-sub" id="dials-card-sub">{_dials_summary}</span>
        </div>
        <span class="setup-list-chevron">\u203a</span>
      </div>
      <div class="setup-list-card" onclick="openPanel('customise')">
        <div class="setup-list-card-body">
          <span class="setup-list-card-title">Personalisation</span>
          <span class="setup-list-card-sub" id="customise-card-sub">{customise_summary}</span>
        </div>
        <span class="setup-list-chevron">\u203a</span>
      </div>
      <div class="setup-list-card" onclick="openPanel('system')">
        <div class="setup-list-card-body">
          <span class="setup-list-card-title">System</span>
          <span class="setup-list-card-sub" id="system-card-sub">{system_summary}</span>
        </div>
        <span class="setup-list-chevron">\u203a</span>
      </div>
      <div class="setup-list-card" onclick="openPanel('factory-reset')">
        <div class="setup-list-card-body">
          <span class="setup-list-card-title">Factory Reset</span>
          <span class="setup-list-card-sub">Erase all settings and return to Wi-Fi setup</span>
        </div>
        <span class="setup-list-chevron">\u203a</span>
      </div>
    </div>
    <div class="setup-slide-panels">
      <div class="setup-detail-panel" id="panel-input1">
        <div class="setup-detail-back">
          <button type="button" class="pill-btn small" onclick="closePanel()">\u2190 Back</button>
        </div>
        {_setup_detail_header("Setup Input 1")}
        {input1_html}
        <div id="audio1_preamp_card" style="display:{'block' if parsed.audio1_enabled else 'none'};">
          {_audio_controls_card_html(
            input_index=1,
            gain_db=parsed.audio1.gain_db,
            eq_40hz_db=parsed.audio1.eq_40hz_db,
            eq_100hz_db=parsed.audio1.eq_100hz_db,
            eq_8khz_db=parsed.audio1.eq_8khz_db,
          )}
        </div>
      </div>
      <div class="setup-detail-panel" id="panel-input2">
        <div class="setup-detail-back">
          <button type="button" class="pill-btn small" onclick="closePanel()">\u2190 Back</button>
        </div>
        {_setup_detail_header("Setup Input 2")}
        {input2_html}
        <div id="audio2_preamp_card" style="display:{'block' if parsed.audio2_enabled else 'none'};">
          {_audio_controls_card_html(
            input_index=2,
            gain_db=parsed.audio2.gain_db,
            eq_40hz_db=parsed.audio2.eq_40hz_db,
            eq_100hz_db=parsed.audio2.eq_100hz_db,
            eq_8khz_db=parsed.audio2.eq_8khz_db,
          )}
        </div>
      </div>
      <div class="setup-detail-panel" id="panel-bluetooth">
        <div class="setup-detail-back">
          <button type="button" class="pill-btn small" onclick="closePanel()">\u2190 Back</button>
        </div>
        {_setup_detail_header("Bluetooth")}
        {bluetooth_card_html}
      </div>
      <div class="setup-detail-panel" id="panel-playback">
        <div class="setup-detail-back">
          <button type="button" class="pill-btn small" onclick="closePanel()">\u2190 Back</button>
        </div>
        {_setup_detail_header("Setup Playback Defaults")}
        {playback_fieldset_html}
      </div>
      <div class="setup-detail-panel" id="panel-track-id">
        <div class="setup-detail-back">
          <button type="button" class="pill-btn small" onclick="closePanel()">\u2190 Back</button>
        </div>
        {_setup_detail_header("Track Identification")}
        {track_id_card_html}
      </div>
      <div class="setup-detail-panel" id="panel-dials">
        <div class="setup-detail-back">
          <button type="button" class="pill-btn small" onclick="closePanel()">\u2190 Back</button>
        </div>
        {_setup_detail_header("Dials")}
        {_dial_cards_html}
      </div>
      <div class="setup-detail-panel" id="panel-customise">
        <div class="setup-detail-back">
          <button type="button" class="pill-btn small" onclick="closePanel()">\u2190 Back</button>
        </div>
        {_setup_detail_header("Personalisation")}
        {customise_card_html}
      </div>
      <div class="setup-detail-panel" id="panel-system">
        <div class="setup-detail-back">
          <button type="button" class="pill-btn small" onclick="closePanel()">\u2190 Back</button>
        </div>
        {_setup_detail_header("System & Updates")}
        {system_fieldset_html}
      </div>
      <div class="setup-detail-panel" id="panel-factory-reset">
        <div class="setup-detail-back">
          <button type="button" class="pill-btn small" onclick="closePanel()">\u2190 Back</button>
        </div>
        {factory_reset_zone}
      </div>
    </div>
  </div>
</div>"""

    _dial_badge_css = """
.dial-badge{display:inline-flex;align-items:center;font-size:0.65rem;font-weight:600;
  padding:0.1rem 0.45rem;border-radius:0.75rem;letter-spacing:0.02em;white-space:nowrap;}
.dial-badge-new{background:var(--color-accent,#007bff);color:#fff;}
.dial-badge-online{background:var(--color-status-success,#28a745);color:#fff;}
.dial-badge-offline{background:var(--color-text-muted,#888);color:#fff;}
.dial-card-title{font-weight:600;font-size:0.9rem;}
.dial-card-msg{font-size:0.8rem;}
"""
    _bt_pairing_modal_css = ""
    if bt_enabled:
        _bt_pairing_modal_css = """
      .bt-device-list{margin-top:0.5rem;max-height:14rem;overflow-y:auto;}
      .bt-scan-row{padding:0.5rem 0.6rem;border:1px solid var(--color-border-nav);
        border-radius:6px;margin-bottom:0.4rem;cursor:pointer;}
      .bt-scan-row:hover{background:var(--color-surface-raised);}
      .bt-scan-empty{color:var(--color-text-muted,#888);font-style:italic;}
    """
    # Extra clearance below the "More Owntone Settings" button so it doesn't
    # sit behind the fixed bottom nav bar -- same mechanism as the About
    # page's license panel (.about-license-text's padding-bottom:4.5rem).
    _playback_panel_bottom_pad_css = "#panel-playback { padding-bottom: 4.5rem; }\n"
    _extra_css = (
        f"{COMMON_MODAL_CSS}\n{PIN_MODAL_CSS}\n{pin_modal_setup_css}"
        f"\n{factory_reset_modal_css}\n{_dial_badge_css}\n{DIAL_LOCKED_SECTION_CSS}"
        f"\n{_bt_pairing_modal_css}\n{_playback_panel_bottom_pad_css}"
    )
    _pin_modal_div = """\
<div id="pinModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="pinModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="pinModalTitle">Change PIN</div>
    <div class="bd modal-bd">
      <p id="pinModalMessage">Enter your current PIN.</p>
      <p id="pinModalError" style="display:none;color:var(--color-status-danger);font-weight:600;"></p>
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-secondary" id="pinModalCancel">Cancel</button>
      <button type="button" class="btn modal-btn modal-btn-primary" id="pinModalOk">Apply</button>
    </div>
  </div>
</div>"""
    _hostname_modal_div = f"""\
<div id="hostnameModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="hostnameModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="hostnameModalTitle">Change Hostname</div>
    <div class="bd modal-bd">
      <p>Enter the new hostname for this appliance.</p>
      <input type="text" id="hostnameModalInput" value="{html.escape(current_hostname)}"
             autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false">
      <p id="hostnameModalError" style="display:none;color:var(--color-status-danger);font-weight:600;margin-top:0.4rem;"></p>
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-secondary" id="hostnameModalCancel">Cancel</button>
      <button type="button" class="btn modal-btn modal-btn-primary" id="hostnameModalOk">Change</button>
    </div>
  </div>
</div>"""
    _dial_pin_modal_div = ("""\
<div id="dialPinModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="dialPinModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="dialPinModalTitle">Change Dial PIN</div>
    <div class="bd modal-bd">
      <p id="dialPinModalMsg"></p>
      <input type="password" id="dialPinModalCurrentInput" placeholder="Current PIN"
             autocomplete="current-password" style="margin-top:0.5rem;">
      <input type="password" id="dialPinModalInput" placeholder="New PIN"
             autocomplete="new-password" style="margin-top:0.5rem;">
      <input type="password" id="dialPinModalConfirmInput" placeholder="Confirm PIN"
             autocomplete="new-password" style="margin-top:0.5rem;">
      <p id="dialPinModalError" style="display:none;color:var(--color-status-danger);font-weight:600;margin-top:0.4rem;"></p>
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-secondary" id="dialPinModalCancel">Cancel</button>
      <button type="button" class="btn modal-btn modal-btn-primary" id="dialPinModalOk">Apply</button>
    </div>
  </div>
</div>""")
    _dial_name_modal_div = """\
<div id="dialNameModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="dialNameModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="dialNameModalTitle">Change Dial Name</div>
    <div class="bd modal-bd">
      <p>Enter the new name for this dial.</p>
      <input type="text" id="dialNameModalInput" placeholder="e.g. Hallway Dial"
             autocomplete="off" autocapitalize="words" autocorrect="off" spellcheck="false">
      <p id="dialNameModalError" style="display:none;color:var(--color-status-danger);font-weight:600;margin-top:0.4rem;"></p>
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-secondary" id="dialNameModalCancel">Cancel</button>
      <button type="button" class="btn modal-btn modal-btn-primary" id="dialNameModalOk">Change</button>
    </div>
  </div>
</div>"""
    _dial_pin_recovery_modal_div = """\
<div id="dialPinRecoveryModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="dialPinRecoveryModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="dialPinRecoveryModalTitle">Reset Dial PIN</div>
    <div class="bd modal-bd">
      <div id="dialPinRecoveryWaitPanel">
        <p id="dialPinRecoveryWaitMsg">To reset the Dial PIN, start by power-cycling the Dial now. Once it restarts, you have 10 minutes to confirm access by turning the Dial clockwise.</p>
      </div>
      <div id="dialPinRecoverySetPanel" style="display:none;">
        <p>Enter a new Dial PIN.</p>
        <input type="password" id="dialPinRecoveryNewInput" placeholder="New PIN"
               autocomplete="new-password" style="margin-top:0.5rem;">
        <input type="password" id="dialPinRecoveryConfirmInput" placeholder="Confirm PIN"
               autocomplete="new-password" style="margin-top:0.5rem;">
        <p id="dialPinRecoveryError" style="display:none;color:var(--color-status-danger);font-weight:600;margin-top:0.4rem;"></p>
      </div>
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-secondary" id="dialPinRecoveryCancel">Cancel</button>
      <button type="button" class="btn modal-btn modal-btn-primary" id="dialPinRecoveryOk" disabled>Waiting for Dial…</button>
    </div>
  </div>
</div>"""
    _wifi_hotspot_modal_div = """\
<div id="wifiHotspotModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="wifiHotspotModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="wifiHotspotModalTitle">Change Wi-Fi Network</div>
    <div class="bd modal-bd">
      <p>This will start the Wi-Fi hotspot. Please connect to
        <strong id="wifiHotspotSsid">autostream_XXXX</strong>
        to continue Wi-Fi setup.</p>
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-secondary" onclick="cancelChangeWifiNetwork()">Cancel</button>
      <button type="button" class="btn modal-btn modal-btn-primary" onclick="confirmChangeWifiNetwork()">Continue</button>
    </div>
  </div>
</div>"""
    _bt_pairing_modal_div = ""
    if bt_enabled:
        _bt_pairing_modal_div = """\
<div id="btPairingModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="btPairingModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="btPairingModalTitle">Pair Bluetooth Turntable</div>
    <div class="bd modal-bd">
      <div id="btScanPanel">
        <p>Put your turntable in pairing mode. Available devices:</p>
        <div id="btScanDeviceList" class="bt-device-list">
          <p class="bt-scan-empty">Scanning…</p>
        </div>
      </div>
      <div id="btConfirmPanel" style="display:none;">
        <p>Pair with <strong id="btConfirmDeviceName"></strong>?</p>
        <p id="btConfirmWarning" style="display:none;color:var(--color-status-danger);font-weight:600;"></p>
      </div>
      <div id="btPairingPanel" style="display:none;">
        <p id="btPairingStatusMsg">Pairing…</p>
      </div>
      <div id="btResultPanel" style="display:none;">
        <p id="btResultMsg"></p>
        <p id="btResultError" style="display:none;color:var(--color-status-danger);font-weight:600;"></p>
      </div>
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-secondary" id="btPairingForget" style="display:none;">Forget</button>
      <button type="button" class="btn modal-btn modal-btn-secondary" id="btPairingCancel">Cancel</button>
      <button type="button" class="btn modal-btn modal-btn-primary" id="btPairingOk" style="display:none;">Pair</button>
    </div>
  </div>
</div>"""
    _body_prefix = (
        f"{factory_reset_modal}\n{reboot_modal}\n{_pin_modal_div}\n{_hostname_modal_div}\n"
        f"{_dial_pin_modal_div}\n{_dial_pin_recovery_modal_div}\n{_dial_name_modal_div}\n{_wifi_hotspot_modal_div}\n"
        f"{_bt_pairing_modal_div}\n"
        f"{INFO_MODAL_HTML}"
    )
    _body_html = (
        (f"<p style='color:var(--color-status-success);'>Saved</p>" if saved_ok else "")
        + (f"<p style='color:var(--color-status-danger);'>{html.escape(error)}</p>" if error else "")
        + form_content_html
    )
    _bt_pairing_js = ""
    if bt_enabled:
        _bt_link_state_initial = str((bt_status or {}).get("link") or "disconnected")
        _bt_paired_js = "true" if bt_paired else "false"
        _bt_pairing_js = f"""
      <script>
        // ── Bluetooth input pairing ──────────────────────────────────────
        var BT_LOOPBACK_HW = {BLUETOOTH_LOOPBACK_HW!r};
        var btPaired = {_bt_paired_js};
        var _btLinkState = {_bt_link_state_initial!r};
        var _btScanTimer = null;
        var _btPairTimer = null;
        var _btInputIndex = null;
        var _btSelectEl = null;
        var _btSelectedMac = null;
        var _btSelectedName = null;
        var _btPriorSelectValue = null;
        var _btPairSucceeded = false;

        function isBluetoothDevice(value) {{ return value === BT_LOOPBACK_HW; }}

        async function _btFetch(path, opts) {{
          opts = opts || {{}};
          var headers = Object.assign({{'X-CSRF-Token': window.__CSRF || ''}}, (opts.headers || {{}}));
          try {{
            var r = await fetch(path, Object.assign({{cache: 'no-store'}}, opts, {{headers: headers}}));
            var body = null;
            try {{ body = await r.json(); }} catch (e) {{}}
            return {{status: r.status, body: body}};
          }} catch (e) {{
            return {{status: 0, body: null}};
          }}
        }}

        function _btPost(path, payload) {{
          return _btFetch(path, {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify(payload || {{}})
          }});
        }}

        function _btShowPanel(name) {{
          ['Scan', 'Confirm', 'Pairing', 'Result'].forEach(function(p) {{
            var el = document.getElementById('bt' + p + 'Panel');
            if (el) el.style.display = (p === name) ? '' : 'none';
          }});
        }}

        async function btForgetFromCard() {{
          if (!window.confirm('Forget the currently paired Bluetooth device?')) return;
          await _btPost('/api/bluetooth/forget', {{}});
          _btRefreshLinkStatus();
        }}

        function _btStopScan() {{
          if (_btScanTimer) {{ clearInterval(_btScanTimer); _btScanTimer = null; }}
          _btPost('/api/bluetooth/scan', {{action: 'stop'}});
        }}

        function _btRenderScanList(devices) {{
          var list = document.getElementById('btScanDeviceList');
          if (!list) return;
          if (!devices || !devices.length) {{
            list.innerHTML = '<p class="bt-scan-empty">Scanning…</p>';
            return;
          }}
          list.innerHTML = '';
          devices.forEach(function(d) {{
            var row = document.createElement('div');
            row.className = 'bt-scan-row';
            var label = (d.name || d.mac || 'Unknown device');
            row.textContent = d.paired ? (label + ' (paired)') : label;
            row.addEventListener('click', function() {{ _btSelectDevice(d.mac, d.name || d.mac); }});
            list.appendChild(row);
          }});
        }}

        async function _btPollScan() {{
          var res = await _btFetch('/api/bluetooth/scan_results', {{}});
          var body = res.body;
          if (!body || body.ok === false) return;
          _btRenderScanList(body.devices || []);
        }}

        async function _btStartScan() {{
          _btShowPanel('Scan');
          var list = document.getElementById('btScanDeviceList');
          if (list) list.innerHTML = '<p class="bt-scan-empty">Scanning…</p>';
          await _btPost('/api/bluetooth/scan', {{action: 'start'}});
          _btPollScan();
          if (_btScanTimer) {{ clearInterval(_btScanTimer); _btScanTimer = null; }}
          _btScanTimer = setInterval(_btPollScan, 2000);
        }}

        function _btSelectDevice(mac, name) {{
          _btStopScan();
          _btSelectedMac = mac;
          _btSelectedName = name;
          var nameEl = document.getElementById('btConfirmDeviceName');
          if (nameEl) nameEl.textContent = name;
          var warnEl = document.getElementById('btConfirmWarning');
          if (warnEl) {{
            if (btPaired) {{
              warnEl.textContent = 'The currently paired device will be forgotten.';
              warnEl.style.display = '';
            }} else {{
              warnEl.style.display = 'none';
            }}
          }}
          var okBtn = document.getElementById('btPairingOk');
          if (okBtn) {{ okBtn.style.display = ''; okBtn.textContent = 'Pair'; okBtn.onclick = _btConfirmPair; }}
          var forgetBtn = document.getElementById('btPairingForget');
          if (forgetBtn) forgetBtn.style.display = 'none';
          var titleEl = document.getElementById('btPairingModalTitle');
          if (titleEl) titleEl.textContent = 'Confirm Pairing';
          _btShowPanel('Confirm');
        }}

        async function _btConfirmPair() {{
          _btShowPanel('Pairing');
          var titleEl = document.getElementById('btPairingModalTitle');
          if (titleEl) titleEl.textContent = 'Pairing…';
          var okBtn = document.getElementById('btPairingOk');
          if (okBtn) okBtn.style.display = 'none';
          var res = await _btPost('/api/bluetooth/pair', {{address: _btSelectedMac}});
          if (res.status === 409) {{
            _btShowResult(false, 'Pairing already in progress.');
            return;
          }}
          if (res.status === 0 || (res.body && res.body.ok === false && res.status >= 400)) {{
            _btShowResult(false, (res.body && res.body.error) || 'Unable to start pairing.');
            return;
          }}
          if (_btPairTimer) {{ clearInterval(_btPairTimer); _btPairTimer = null; }}
          _btPairTimer = setInterval(_btPollPairStatus, 2000);
        }}

        async function _btPollPairStatus() {{
          var res = await _btFetch('/api/bluetooth/pair_status', {{}});
          var body = res.body;
          if (!body || body.ok === false) return;
          if (body.state === 'done') {{
            clearInterval(_btPairTimer); _btPairTimer = null;
            _btShowResult(true, 'Paired with ' + (_btSelectedName || 'device') + '.');
          }} else if (body.state === 'failed') {{
            clearInterval(_btPairTimer); _btPairTimer = null;
            _btShowResult(false, body.error || 'Pairing failed.');
          }}
        }}

        function _btShowResult(success, message) {{
          _btShowPanel('Result');
          var titleEl = document.getElementById('btPairingModalTitle');
          var msgEl = document.getElementById('btResultMsg');
          var errEl = document.getElementById('btResultError');
          var okBtn = document.getElementById('btPairingOk');
          if (success) {{
            if (titleEl) titleEl.textContent = 'Paired';
            if (msgEl) msgEl.textContent = message;
            if (errEl) errEl.style.display = 'none';
            btPaired = true;
            _btPairSucceeded = true;
            _btLinkState = 'connected';
            if (_btSelectEl && _btInputIndex) {{
              _btSelectEl.value = BT_LOOPBACK_HW;
              _btSelectEl.dataset.prev = BT_LOOPBACK_HW;
              if (liveEnabled) {{
                settingsSaveField('audio' + _btInputIndex + '.capture_device', BT_LOOPBACK_HW);
              }}
              syncInputExclusivity(_btInputIndex, BT_LOOPBACK_HW);
            }}
            _btRefreshLinkStatus();
            if (okBtn) {{ okBtn.style.display = ''; okBtn.textContent = 'Done'; okBtn.onclick = closeBtPairingModal; }}
          }} else {{
            if (titleEl) titleEl.textContent = 'Pairing Failed';
            if (msgEl) msgEl.textContent = '';
            if (errEl) {{ errEl.textContent = message; errEl.style.display = ''; }}
            if (_btSelectEl && _btPriorSelectValue !== null) {{
              _btSelectEl.value = _btPriorSelectValue;
            }}
            if (okBtn) {{
              okBtn.style.display = '';
              okBtn.textContent = 'Retry';
              okBtn.onclick = function() {{ _btStartScan(); }};
            }}
          }}
        }}

        async function _btForgetCurrent() {{
          if (!window.confirm('Forget the currently paired Bluetooth device?')) return;
          await _btPost('/api/bluetooth/forget', {{}});
          btPaired = false;
          _btLinkState = 'disconnected';
          _btRefreshLinkStatus();
          closeBtPairingModal();
        }}

        function openBtPairingModal(inputIndex, selectEl) {{
          _btInputIndex = inputIndex;
          _btSelectEl = selectEl || null;
          // Revert target is the last known-committed value (data-prev), not
          // .value -- by the time this fires the onchange event has already
          // set .value to the newly-selected (Bluetooth) option.
          _btPriorSelectValue = selectEl && selectEl.dataset.prev !== undefined ? selectEl.dataset.prev : null;
          _btPairSucceeded = false;
          _btSelectedMac = null;
          _btSelectedName = null;
          var modal = document.getElementById('btPairingModal');
          if (!modal) return;
          var titleEl = document.getElementById('btPairingModalTitle');
          if (titleEl) titleEl.textContent = 'Pair Bluetooth Turntable';
          var okBtn = document.getElementById('btPairingOk');
          if (okBtn) okBtn.style.display = 'none';
          var forgetBtn = document.getElementById('btPairingForget');
          if (forgetBtn) {{
            forgetBtn.style.display = btPaired ? '' : 'none';
            forgetBtn.onclick = _btForgetCurrent;
          }}
          modal.classList.add('show');
          _btStartScan();
        }}

        function closeBtPairingModal() {{
          _btStopScan();
          if (_btPairTimer) {{ clearInterval(_btPairTimer); _btPairTimer = null; }}
          // Cancel/dismiss without a successful pairing in this session: undo
          // the onchange event's already-committed selection change.  A no-op
          // when the select's value/data-prev already match (e.g. opening the
          // modal from the card's "Pair new device…" button, which has no
          // associated select, or after a failed pairing already reverted it
          // below in _btShowResult).
          if (_btSelectEl && !_btPairSucceeded && _btPriorSelectValue !== null) {{
            _btSelectEl.value = _btPriorSelectValue;
            _btSelectEl.dataset.prev = _btPriorSelectValue;
          }}
          var modal = document.getElementById('btPairingModal');
          if (modal) modal.classList.remove('show');
        }}

        document.addEventListener('DOMContentLoaded', function() {{
          var cancelBtn = document.getElementById('btPairingCancel');
          if (cancelBtn) cancelBtn.addEventListener('click', closeBtPairingModal);
          document.addEventListener('keydown', function(ev) {{
            var m = document.getElementById('btPairingModal');
            if (ev.key === 'Escape' && m && m.classList.contains('show')) closeBtPairingModal();
          }});
        }});
      </script>
    """

    # ── Bluetooth card + cross-input exclusivity JS ─────────────────────────
    # Unconditional (rendered regardless of bt_enabled/installed): the card
    # itself is always present per the Setup page's Bluetooth card contract,
    # and the same-device exclusivity guard between Input 1/2 applies to any
    # device, not just Bluetooth.
    _bt_status_json = json.dumps(bt_status) if isinstance(bt_status, dict) else "null"
    _bt_card_js = f"""
      <script>
        var btServicesEnabled = {"true" if bt_services_on else "false"};
        var btOnboardEnabled = {"true" if bt_onboard_on else "false"};
        if (typeof btPaired === 'undefined') var btPaired = {"true" if bt_paired else "false"};
        if (typeof _btLinkState === 'undefined') var _btLinkState = {str((bt_status or {}).get("link") or "disconnected")!r};
        window._btLastStatus = {_bt_status_json};
        window._btUiText = {json.dumps(_bluetooth_input_fragment_text(bt_status))};

        function refreshExclusivityOptions() {{
          var sel1 = document.getElementById('audio_capture_device_select');
          var sel2 = document.getElementById('audio2_capture_device_select');
          if (!sel1 || !sel2) return;
          [[sel1, sel2], [sel2, sel1]].forEach(function(pair) {{
            var self = pair[0], other = pair[1];
            var otherVal = other.value;
            Array.prototype.forEach.call(self.options, function(opt) {{
              var conflict = otherVal && opt.value === otherVal && opt.value !== self.value;
              opt.disabled = !!conflict;
              opt.hidden = !!conflict;
            }});
          }});
        }}

        function syncInputExclusivity(changedIndex, value) {{
          refreshExclusivityOptions();
        }}

        function _btSetBusy(btn, busyLabel) {{
          if (!btn) return null;
          var prevLabel = btn.textContent;
          var prevDisabled = btn.disabled;
          btn.disabled = true;
          btn.textContent = busyLabel;
          return function _btRestore() {{
            btn.disabled = prevDisabled;
            btn.textContent = prevLabel;
          }};
        }}

        function btEnableServices() {{
          var btn = document.getElementById('btnBtEnableServices');
          var restore = _btSetBusy(btn, 'Enabling…');
          settingsTransact('/api/bluetooth/services', {{action: 'enable'}}, {{
            onSuccess: function() {{ window.location.reload(); }},
            onError: function() {{ if (restore) restore(); }}
          }});
        }}

        function btDisableServices() {{
          if (!window.confirm('Disable Bluetooth services? Any active Bluetooth stream will stop immediately.')) return;
          var btn = document.getElementById('btnBtDisableServices');
          var restore = _btSetBusy(btn, 'Disabling…');
          settingsTransact('/api/bluetooth/services', {{action: 'disable'}}, {{
            onSuccess: function() {{ window.location.reload(); }},
            onError: function() {{ if (restore) restore(); }}
          }});
        }}

        function btOnboardToggleChanged(checked) {{
          if (!window.confirm('Changing this restarts the appliance. Continue?')) {{
            var t = document.getElementById('btOnboardToggle');
            if (t) t.checked = !checked;
            return;
          }}
          settingsTransact('/api/bluetooth/onboard', {{enabled: checked}}, {{
            onSuccess: function(d) {{
              if (d && d.reboot_required) {{ window.location.href = '/rebooting'; }}
            }},
            onError: function() {{
              var t = document.getElementById('btOnboardToggle');
              if (t) t.checked = !checked;
            }}
          }});
        }}

        var _btBufferTimer = null;
        function btBufferInput(value) {{
          var lbl = document.getElementById('btBufferVal');
          if (lbl) lbl.textContent = value + ' ms';
          if (_btBufferTimer) clearTimeout(_btBufferTimer);
          _btBufferTimer = setTimeout(function() {{
            settingsTransact('/api/bluetooth/buffer', {{buffer_ms: parseInt(value, 10)}});
          }}, 500);
        }}

        function _btApplyStatus(body) {{
          if (!body) return;
          btServicesEnabled = !!body.services_enabled;
          btOnboardEnabled = !!body.onboard_enabled;
          var daemon = body.daemon || null;
          window._btLastStatus = daemon;
          var ui = body.ui || null;
          window._btUiText = (ui && ui.bt_input_text) || 'Not Connected';
          btPaired = !!(daemon && daemon.paired);
          _btLinkState = (daemon && daemon.link) || 'disconnected';
          var adapterPresent = !!(daemon && daemon.adapter_present);

          var dis = document.getElementById('btDisabledBody');
          var en = document.getElementById('btEnabledBody');
          if (dis) dis.style.display = btServicesEnabled ? 'none' : 'block';
          if (en) en.style.display = btServicesEnabled ? 'block' : 'none';

          var adapterRow = document.getElementById('btAdapterRow');
          if (adapterRow) {{
            var kind = daemon && daemon.adapter_kind;
            var text = !adapterPresent
              ? 'No Bluetooth adapter found — plug in a USB adapter, or enable the onboard device below.'
              : (kind === 'usb' ? 'USB adapter' : (kind === 'onboard' ? 'Onboard' : 'Detected'));
            adapterRow.textContent = 'Adapter: ' + text;
          }}
          var onboardToggle = document.getElementById('btOnboardToggle');
          if (onboardToggle) {{
            onboardToggle.checked = btOnboardEnabled;
            onboardToggle.disabled = !btServicesEnabled;
          }}
          var gatedRow = document.getElementById('btAdapterGatedRow');
          if (gatedRow) {{
            gatedRow.style.opacity = adapterPresent ? '' : '0.4';
            gatedRow.style.pointerEvents = adapterPresent ? '' : 'none';
          }}
          var pairedRow = document.getElementById('btPairedRow');
          if (pairedRow) pairedRow.textContent = (ui && ui.paired_text) || 'No device paired';
          var forgetBtn = document.getElementById('btnBtForget');
          if (forgetBtn) forgetBtn.style.display = btPaired ? '' : 'none';

          var sub = document.getElementById('bluetooth-card-sub');
          if (sub) sub.textContent = (ui && ui.card_summary) || 'Disabled';
          if (typeof refreshInputCardSubs === 'function') refreshInputCardSubs();
        }}

        async function _btRefreshLinkStatus() {{
          var res, body = null;
          try {{
            res = await fetch('/api/bluetooth/status', {{
              cache: 'no-store',
              headers: {{'X-CSRF-Token': window.__CSRF || ''}}
            }});
            body = await res.json();
          }} catch (e) {{
            return;
          }}
          if (!body || body.ok !== true) return;
          _btApplyStatus(body);
        }}

        document.addEventListener('DOMContentLoaded', function() {{
          refreshExclusivityOptions();
        }});
        _btRefreshLinkStatus();
        setInterval(_btRefreshLinkStatus, 5000);
      </script>
    """

    _body_suffix = f"""{A2HS_SCRIPT}
      {AUTOSAVE_JS}
      {INFO_MODAL_SCRIPT}
      <script>
        const pinChangeState = {{
          busy: false,
        }};
        function pinModalElements() {{
          return {{
            modal: document.getElementById('pinModal'),
            title: document.getElementById('pinModalTitle'),
            body: document.querySelector('#pinModal .bd'),
            message: document.getElementById('pinModalMessage'),
            error: document.getElementById('pinModalError'),
            newInput: document.getElementById('pinModalNew'),
            repeatInput: document.getElementById('pinModalRepeat'),
            cancel: document.getElementById('pinModalCancel'),
            ok: document.getElementById('pinModalOk'),
          }};
        }}
        function _makePinInput(id, placeholder) {{
          const input = document.createElement('input');
          input.id = id;
          input.name = 'v';
          input.type = 'text';
          input.className = 'pin-entry';
          input.setAttribute('readonly', 'readonly');
          input.setAttribute('inputmode', 'text');
          input.setAttribute('autocapitalize', 'off');
          input.setAttribute('autocomplete', 'off');
          input.setAttribute('autocorrect', 'off');
          input.setAttribute('spellcheck', 'false');
          input.setAttribute('data-form-type', 'other');
          input.setAttribute('placeholder', placeholder);
          return input;
        }}
        function _armPinInput(input) {{
          input.value = '';
          input.setAttribute('readonly', 'readonly');
          const enable = () => input.removeAttribute('readonly');
          input.addEventListener('pointerdown', enable, {{ once: true }});
          input.addEventListener('focus', enable, {{ once: true }});
        }}
        function ensurePinModalInputs() {{
          const els = pinModalElements();
          if (!els.body) return;
          if (!els.newInput) {{
            const newInput = _makePinInput('pinModalNew', 'New PIN');
            newInput.addEventListener('keydown', (ev) => {{
              if (ev.key === 'Enter') {{
                ev.preventDefault();
                const rep = document.getElementById('pinModalRepeat');
                if (rep) rep.focus();
              }}
            }});
            const err = els.error;
            if (err && err.parentNode === els.body) {{
              els.body.insertBefore(newInput, err.nextSibling);
            }} else {{
              els.body.appendChild(newInput);
            }}
          }}
          if (!els.repeatInput) {{
            const repeatInput = _makePinInput('pinModalRepeat', 'Repeat PIN');
            repeatInput.style.marginTop = '0.5rem';
            repeatInput.addEventListener('keydown', (ev) => {{
              if (ev.key === 'Enter') {{ ev.preventDefault(); handlePinModalOk(); }}
            }});
            const newInput = document.getElementById('pinModalNew');
            if (newInput) newInput.after(repeatInput);
            else els.body.appendChild(repeatInput);
          }}
        }}
        function setPinModalBusy(busy) {{
          pinChangeState.busy = !!busy;
          const els = pinModalElements();
          if (els.cancel) els.cancel.disabled = !!busy;
          if (els.ok) els.ok.disabled = !!busy;
          if (els.newInput) els.newInput.disabled = !!busy;
          if (els.repeatInput) els.repeatInput.disabled = !!busy;
        }}
        function showPinModalError(message) {{
          const els = pinModalElements();
          if (!els.error) return;
          if (message) {{
            els.error.style.display = '';
            els.error.textContent = message;
          }} else {{
            els.error.style.display = 'none';
            els.error.textContent = '';
          }}
        }}
        function closePinModal() {{
          const els = pinModalElements();
          if (!els.modal) return;
          els.modal.classList.remove('show');
          if (els.newInput) {{ els.newInput.value = ''; els.newInput.remove(); }}
          if (els.repeatInput) {{ els.repeatInput.value = ''; els.repeatInput.remove(); }}
          showPinModalError(null);
          els.message.textContent = '';
          els.ok.textContent = 'Apply';
          els.ok.style.display = '';
          els.cancel.textContent = 'Cancel';
          els.cancel.style.display = '';
          pinChangeState.busy = false;
        }}
        function openChangePinModal() {{
          pinChangeState.busy = false;
          const els = pinModalElements();
          if (!els.modal) return;
          ensurePinModalInputs();
          const inputs = pinModalElements();
          showPinModalError(null);
          els.message.textContent = '';
          els.ok.textContent = 'Apply';
          els.ok.style.display = '';
          els.cancel.textContent = 'Cancel';
          els.cancel.style.display = '';
          if (inputs.newInput) _armPinInput(inputs.newInput);
          if (inputs.repeatInput) _armPinInput(inputs.repeatInput);
          setPinModalBusy(false);
          els.modal.classList.add('show');
        }}
        // Parse a fetch Response into a discriminated result object.
        // Does NOT catch a rejected fetch() promise — network failures propagate.
        // Returns: {{ok, transportStatus, body, error}}
        async function _parseDialResponse(response) {{
          var transportStatus = response.status;
          var ct = response.headers.get('Content-Type') || '';
          if (ct.toLowerCase().indexOf('application/json') === -1) {{
            try {{ await response.text(); }} catch(e) {{}}
            return {{ok: false, transportStatus: transportStatus, body: null, error: 'invalid_response'}};
          }}
          var body;
          try {{ body = await response.json(); }} catch(e) {{
            return {{ok: false, transportStatus: transportStatus, body: null, error: 'invalid_response'}};
          }}
          if (!body || typeof body !== 'object' || Array.isArray(body)) {{
            return {{ok: false, transportStatus: transportStatus, body: null, error: 'invalid_response'}};
          }}
          if (body.ok === false) {{
            return {{ok: false, transportStatus: transportStatus, body: body, error: String(body.error || 'unknown_error')}};
          }}
          if (transportStatus < 200 || transportStatus > 299) {{
            return {{ok: false, transportStatus: transportStatus, body: body, error: String(body.error || 'http_error')}};
          }}
          return {{ok: true, transportStatus: transportStatus, body: body, error: null}};
        }}

        async function submitPinChange(newPin, newPinCheck) {{
          const resp = await fetch('/api/pin/change', {{
            method: 'POST',
            headers: {{
              'Content-Type': 'application/json',
              'X-CSRF-Token': window.__CSRF || ''
            }},
            body: JSON.stringify({{ new_pin: newPin, new_pin_check: newPinCheck }})
          }});
          return _parseDialResponse(resp);
        }}
        function friendlyPinChangeError(message) {{
          const text = String(message || '').trim();
          if (!text) return 'Unable to change PIN.';
          if (text === 'PIN must be 4-20 characters using letters, numbers, or hyphens') return text;
          if (text === 'Values did not match') return 'The two PIN entries did not match.';
          if (text === 'Missing fields') return 'Enter your new PIN twice.';
          return text;
        }}
        async function handlePinModalOk() {{
          if (pinChangeState.busy) return;
          const els = pinModalElements();
          const newVal = ((els.newInput && els.newInput.value) || '').trim();
          const repeatVal = ((els.repeatInput && els.repeatInput.value) || '').trim();
          if (!newVal) {{
            showPinModalError('Enter a new PIN.');
            if (els.newInput) els.newInput.focus();
            return;
          }}
          if (!repeatVal) {{
            showPinModalError('Repeat the new PIN.');
            if (els.repeatInput) els.repeatInput.focus();
            return;
          }}
          if (newVal !== repeatVal) {{
            showPinModalError('The two PINs did not match. Please try again.');
            if (els.newInput) {{ _armPinInput(els.newInput); els.newInput.focus(); }}
            if (els.repeatInput) _armPinInput(els.repeatInput);
            return;
          }}
          setPinModalBusy(true);
          try {{
            const result = await submitPinChange(newVal, repeatVal);
            if (result.ok) {{
              if (els.newInput) {{ els.newInput.value = ''; els.newInput.style.display = 'none'; }}
              if (els.repeatInput) {{ els.repeatInput.value = ''; els.repeatInput.style.display = 'none'; }}
              showPinModalError(null);
              els.message.textContent = 'PIN changed successfully. Returning to the home screen\u2026';
              els.ok.style.display = 'none';
              els.cancel.textContent = 'Continue';
              setPinModalBusy(false);
              window.setTimeout(() => {{ window.location.href = '/'; }}, 900);
              return;
            }}
            showPinModalError(friendlyPinChangeError(result.error || 'Unable to change PIN.'));
          }} catch (e) {{
            showPinModalError('Unable to change PIN.');
          }} finally {{
            setPinModalBusy(false);
          }}
        }}
        function handlePinModalCancel() {{
          closePinModal();
        }}
        const hostnameChangeState = {{
          busy: false,
        }};
        function hostnameModalElements() {{
          return {{
            modal: document.getElementById('hostnameModal'),
            input: document.getElementById('hostnameModalInput'),
            error: document.getElementById('hostnameModalError'),
            cancel: document.getElementById('hostnameModalCancel'),
            ok: document.getElementById('hostnameModalOk'),
          }};
        }}
        function currentDisplayedHostname() {{
          const el = document.getElementById('systemHostnameValue');
          return ((el && el.textContent) || 'autostream').trim() || 'autostream';
        }}
        function setHostnameModalBusy(busy) {{
          hostnameChangeState.busy = !!busy;
          const els = hostnameModalElements();
          if (els.cancel) els.cancel.disabled = !!busy;
          if (els.ok) els.ok.disabled = !!busy;
          if (els.input) els.input.disabled = !!busy;
        }}
        function showHostnameModalError(message) {{
          const els = hostnameModalElements();
          if (!els.error) return;
          if (message) {{
            els.error.style.display = '';
            els.error.textContent = message;
          }} else {{
            els.error.style.display = 'none';
            els.error.textContent = '';
          }}
        }}
        function openChangeHostnameModal() {{
          const els = hostnameModalElements();
          if (!els.modal) return;
          showHostnameModalError(null);
          if (els.input) {{
            els.input.value = currentDisplayedHostname();
            els.input.disabled = false;
          }}
          setHostnameModalBusy(false);
          els.modal.classList.add('show');
          setTimeout(function() {{
            if (els.input) {{
              els.input.focus();
              els.input.select();
            }}
          }}, 50);
        }}
        function closeHostnameModal() {{
          const els = hostnameModalElements();
          if (els.modal) els.modal.classList.remove('show');
          showHostnameModalError(null);
          setHostnameModalBusy(false);
        }}
        function friendlyHostnameChangeError(message) {{
          const text = String(message || '').trim();
          if (!text) return 'Unable to change hostname.';
          if (text === 'Invalid hostname') return 'Enter a valid hostname using letters, numbers, and hyphens.';
          return text;
        }}
        function handleHostnameModalOk() {{
          if (hostnameChangeState.busy) return;
          const els = hostnameModalElements();
          const value = ((els.input && els.input.value) || '').trim();
          if (!value) {{
            showHostnameModalError('Enter a hostname.');
            if (els.input) els.input.focus();
            return;
          }}
          setHostnameModalBusy(true);
          settingsTransact('/api/settings/hostname', {{value: value}}, {{
            onSuccess: function(data) {{
              const display = document.getElementById('systemHostnameValue');
              if (display) display.textContent = value;
              refreshSystemCardSub();
              closeHostnameModal();
            }},
            onError: function(data) {{
              showHostnameModalError(friendlyHostnameChangeError(data && data.error));
              setHostnameModalBusy(false);
              if (els.input) els.input.focus();
            }}
          }});
        }}
        const liveEnabled = true;
        function onInputEnableToggle(inputIndex, checked){{
          syncInputUi(inputIndex);
          if (liveEnabled) settingsSaveField('audio' + inputIndex + '.enabled', checked);
        }}
        function syncVol(v){{
          document.getElementById('owntone_volume_percent').value=v;
          document.getElementById('vol_val').textContent=v+'%';
          refreshPlaybackCardSub();
          if (liveEnabled) settingsSaveFieldDebounced('owntone.volume_percent', parseInt(v, 10), 300);
        }}
        function thresholdPreset(checked){{ return checked ? -45 : -60; }}
        function syncInputUi(inputIndex){{
          const prefix = inputIndex === 1 ? 'audio1' : 'audio2';
          const enabledName = prefix + '_enabled';
          const turntableName = inputIndex === 1 ? 'audio_turntable' : 'audio2_turntable';
          const enabled = !!document.querySelector('input[name="' + enabledName + '"]')?.checked;
          const turntable = !!document.querySelector('input[name="' + turntableName + '"]')?.checked;
          const settings = document.getElementById(prefix + '_settings');
          const preampCard = document.getElementById(prefix + '_preamp_card');
          const thresholdId = inputIndex === 1 ? 'audio_silence_threshold' : 'audio2_silence_threshold';
          const note = document.getElementById(prefix + '_turntable_note');
          const threshold = thresholdPreset(turntable);
          const hidden = document.getElementById(thresholdId);
          if (settings) settings.style.display = enabled ? 'block' : 'none';
          if (preampCard) preampCard.style.display = enabled ? 'block' : 'none';
          if (hidden) hidden.value = String(threshold);
          if (note) note.textContent = 'Detection threshold preset: ' + String(threshold) + ' dB';
        }}
        function eqPrefix(inputIndex){{ return inputIndex===1 ? 'audio1' : 'audio2'; }}
        function syncGain(inputIndex, value){{
          const prefix = eqPrefix(inputIndex);
          const inputEl = document.getElementById(prefix + '_gain_db');
          const valueEl = document.getElementById(prefix + '_gain_db_val');
          if (inputEl) inputEl.value = value;
          if (valueEl) valueEl.textContent = value + ' dB';
          if (liveEnabled) settingsSaveFieldDebounced('audio' + inputIndex + '.gain_db', Number(value), 120);
        }}
        function syncEq(inputIndex, band, value){{
          const prefix = eqPrefix(inputIndex);
          const valueEl = document.getElementById(prefix + '_eq_' + band + '_db_val');
          if (valueEl) valueEl.textContent = value + ' dB';
          if (liveEnabled) settingsSaveFieldDebounced('audio' + inputIndex + '.eq_' + band + '_db', Number(value), 120);
        }}
        function silSecondsFromPos(pos){{
          // Mirrors _silence_pos_to_seconds() in autostream_webui_page_setup.py --
          // exponential position->seconds curve, snapped to coarser steps as
          // the value grows.
          var minS = 5, maxS = 300;
          pos = Math.max(0, Math.min(100, Number(pos)));
          var s = minS * Math.pow(maxS / minS, pos / 100);
          if (s < 30) s = Math.round(s);
          else if (s < 120) s = Math.round(s / 5) * 5;
          else s = Math.round(s / 10) * 10;
          return Math.max(minS, Math.min(maxS, s));
        }}
        function syncSil(v){{
          var s = silSecondsFromPos(v);
          document.getElementById('sil_val').textContent=s+'s';
          document.getElementById('silence_seconds').value=s;
          if (liveEnabled) settingsSaveFieldDebounced('general.silence_seconds', s, 500);
        }}
        let mdnsGraceTimer = null;
        function syncMdnsGracePeriod(v){{
          clearTimeout(mdnsGraceTimer);
          mdnsGraceTimer = setTimeout(function(){{
            settingsTransact('/api/settings/mdns-grace-period', {{value: parseInt(v, 10)}});
          }}, 500);
        }}
        function syncTiLeadIn(v){{
          document.getElementById('ti_lead_in_val').textContent=v+' s';
          document.getElementById('ti_analysis_lead_in_seconds').value=v;
          if (liveEnabled) settingsSaveFieldDebounced('track_identification.analysis_lead_in_seconds', Number(v), 500);
        }}
        function syncTiRefresh(v){{
          document.getElementById('ti_refresh_val').textContent=Math.round(v/60)+' min';
          document.getElementById('ti_refresh_seconds').value=v;
          if (liveEnabled) settingsSaveFieldDebounced('track_identification.refresh_seconds', Number(v), 500);
        }}
        function syncTiSilence(v){{
          document.getElementById('ti_silence_val').textContent=parseFloat(v).toFixed(2)+' s';
          document.getElementById('ti_track_change_silence_seconds').value=v;
          if (liveEnabled) settingsSaveFieldDebounced('track_identification.track_change_silence_seconds', Number(v), 500);
        }}
        function onTiToggle(checked){{
          var body=document.getElementById('ti-controls');
          if(!body)return;
          body.style.opacity=checked?'':'0.4';
          body.style.pointerEvents=checked?'':'none';
          body.querySelectorAll('input[type="range"]').forEach(function(el){{el.disabled=!checked;}});
          refreshTrackIdCardSub();
        }}
        window.addEventListener('DOMContentLoaded', () => {{
          const changePinBtn = document.getElementById('btnChangePin');
          const pinModalCancel = document.getElementById('pinModalCancel');
          const pinModalOk = document.getElementById('pinModalOk');
          const changeHostnameBtn = document.getElementById('btnChangeHostname');
          const hostnameModalCancel = document.getElementById('hostnameModalCancel');
          const hostnameModalOk = document.getElementById('hostnameModalOk');
          const hostnameModalInput = document.getElementById('hostnameModalInput');
          if (changePinBtn) changePinBtn.addEventListener('click', openChangePinModal);
          if (pinModalCancel) pinModalCancel.addEventListener('click', handlePinModalCancel);
          if (pinModalOk) pinModalOk.addEventListener('click', handlePinModalOk);
          if (changeHostnameBtn) changeHostnameBtn.addEventListener('click', openChangeHostnameModal);
          if (hostnameModalCancel) hostnameModalCancel.addEventListener('click', closeHostnameModal);
          if (hostnameModalOk) hostnameModalOk.addEventListener('click', handleHostnameModalOk);
          if (hostnameModalInput) hostnameModalInput.addEventListener('keydown', function(ev) {{
            if (ev.key === 'Enter') {{ ev.preventDefault(); handleHostnameModalOk(); }}
          }});
          syncInputUi(1);
          syncInputUi(2);
          // Enforce hostname-dependent state on load
          const cbHost = document.getElementById('webui_show_hostname_on_home');
          if (cbHost) onHostnameToggle(cbHost.checked);
        }});
        async function requestReboot(){{
          if (liveEnabled) {{
            try {{
              const saveR = await fetch('/api/settings/save', {{method:'POST', headers:{{'X-CSRF-Token':window.__CSRF||''}}}});
              const saveJ = await saveR.json().catch(()=>({{ok:false}}));
              if (!saveJ.ok) {{
                alert('Settings could not be saved before rebooting: ' + (saveJ.error || 'unknown error'));
                return;
              }}
            }} catch(e) {{
              // Network error — fall through; reboot will reload config from disk
            }}
          }}
          showRebootModal();
        }}
        (async function(){{
          const msg = (t) => {{ document.getElementById("updMsg").textContent = t; }};
          const bCheck = document.getElementById("btnCheck"), bInst = document.getElementById("btnInst");
          let cand = null;
          // Info mode: a check found an update, so the button now opens the
          // release-notes modal instead of re-checking. Cleared back to the
          // default checking behaviour whenever a check finds no update.
          let infoMode = false;
          let notesHtml = "";
          let notesText = "";
          // Shared reset: also invoked from outside this IIFE (channel
          // toggle) since switching channels invalidates any candidate
          // found under the previous channel.
          function resetUpdateCheckState(){{
            infoMode = false;
            notesHtml = ""; notesText = "";
            cand = null;
            bCheck.textContent = "Check";
            bInst.disabled = true;
            msg("");
          }}
          window.resetUpdateCheckState = resetUpdateCheckState;
          // On page load, check persisted update status so any recent result is visible.
          async function checkPersistedStatus(){{
            try {{
              const r = await fetch("/api/update/status"); const j = await r.json();
              if(j.ok && j.status === "in_progress"){{
                if(j.stale){{
                  if(j.hung){{
                    msg("An update is still running but has been unresponsive for 30+ minutes. Power-cycle the device to recover — do not retry until after rebooting.");
                  }} else {{
                    msg("A previous update appears to have stalled. Power-cycle the device to trigger automatic recovery, or use Check for Updates to retry.");
                  }}
                }} else {{
                  // An update is already running — send the user to the progress page.
                  window.location.replace("/offline/updating");
                }}
                return;
              }}
              if(j.ok && j.status === "success"){{ msg("Last update: installed successfully."); }}
              else if(j.ok && (j.status === "failure" || j.status === "error")){{
                msg("Last update failed: " + (j.message || "unknown error"));
              }}
            }} catch(e) {{ /* ignore — no persisted status yet */ }}
          }}
          bCheck.onclick = async () => {{
            if (infoMode) {{
              var infoMsg = notesHtml || notesText || "No release notes provided.";
              showInfoModal("Release Notes", infoMsg, !!notesHtml);
              return;
            }}
            msg("Checking..."); bInst.disabled=true;
            try {{
              const r = await fetch("/api/update/check"); const j = await r.json();
              if(j.ok && j.update_available){{
                cand=j.candidate;
                var chanNote = j.channel === "dev" ? " (pre-release channel)" : "";
                msg("Update available: " + j.candidate + chanNote);
                notesHtml = j.release_notes_html || "";
                notesText = j.release_notes || "";
                infoMode = true;
                bCheck.textContent = "Info";
                bInst.disabled=false;
              }} else {{
                resetUpdateCheckState();
                msg(j.ok?"No updates available.":"Check failed.");
              }}
            }} catch(e) {{
              resetUpdateCheckState();
              msg("Check failed.");
            }}
          }};
          bInst.onclick = async () => {{
            if(!cand) return;
            msg("Saving settings..."); bCheck.disabled=true; bInst.disabled=true;
            try {{
              const saveR = await fetch("/api/settings/save",{{method:"POST",headers:{{"X-CSRF-Token":window.__CSRF||""}}}});
              const saveJ = await saveR.json().catch(()=>({{ok:false}}));
              if(!saveJ.ok){{
                msg("Could not save settings before update: " + (saveJ.error || "unknown error"));
                bCheck.disabled=false; bInst.disabled=false;
                return;
              }}
            }} catch(e) {{
              msg("Could not save settings before update");
              bCheck.disabled=false; bInst.disabled=false;
              return;
            }}
            msg("Starting update...");
            try {{
              const r = await fetch("/api/update/apply",{{method:"POST",headers:{{"X-CSRF-Token":window.__CSRF||""}}}});
              const j = await r.json().catch(()=>({{ok:false}}));
              if(j.accepted){{
                window.location.replace("/offline/updating");
              }} else {{
                msg("Failed to start update: " + (j.error || "unknown error"));
                bCheck.disabled=false;
              }}
            }} catch(e) {{
              // Network error: service may have already started the update.
              window.location.replace("/offline/updating");
            }}
          }};
          checkPersistedStatus();
        }})();
      </script>
      <script>
        async function refreshOwntoneOutputs() {{
          const sel = document.getElementById("owntone_output_select");
          const hint = document.getElementById("owntone_output_hint");
          if (!sel) return;

          // If the user is interacting with the dropdown, don't change it under them.
          if (document.activeElement === sel) return;

          let j = null;
          try {{
            const r = await fetch("/api/owntone/outputs", {{ cache: "no-store" }});
            j = await r.json();
          }} catch (e) {{
            return;
          }}
          if (!j || !j.ok) return;

          const outputs = Array.isArray(j.outputs) ? j.outputs : [];
          if (hint) hint.style.display = outputs.length ? "none" : "block";

          // If still empty, keep whatever is currently shown (don't wipe it).
          if (!outputs.length) return;

          const current = sel.value;
          const existing = Array.from(sel.options).map(o => o.value);

          // If the list hasn't changed, do nothing.
          const same =
            existing.length === outputs.length &&
            existing.every((v, i) => v === outputs[i]);
          if (same) return;

          // Rebuild options
          sel.innerHTML = "";
          for (const name of outputs) {{
            const opt = document.createElement("option");
            opt.value = name;
            opt.textContent = name;
            sel.appendChild(opt);
          }}

          // Preserve user's current selection if possible
          if (outputs.includes(current)) {{
            sel.value = current;
          }} else if (j.selected && outputs.includes(j.selected)) {{
            sel.value = j.selected;
          }} else {{
            sel.selectedIndex = 0;
          }}
          refreshPlaybackCardSub();
        }}

        window.addEventListener("DOMContentLoaded", () => {{
          // Run once immediately, then every 2 seconds
          refreshOwntoneOutputs();
          setInterval(refreshOwntoneOutputs, 2000);
        }});
      </script>
      <script>
        function _inputCardSub(captureSelName, turntableName, gainId) {{
          var sel = document.querySelector('select[name="' + captureSelName + '"]');
          var opt = sel ? sel.options[sel.selectedIndex] : null;
          var dev = (opt && opt.dataset.card) ? opt.dataset.card : (sel && sel.value ? sel.value : 'Not configured');
          var turntable = document.querySelector('input[name="' + turntableName + '"]');
          var mode = (turntable && turntable.checked) ? 'Turntable' : 'Line In';
          if (opt && opt.dataset.bt === '1') {{
            // Bluetooth input: show the connected device name (or connection
            // state) instead of the ALSA card name and turntable flag. The
            // string itself comes verbatim from the status poll's server-
            // computed ui.bt_input_text -- never re-derived from link/paired
            // here, so it can't drift from the card summary's own state.
            dev = 'Bluetooth';
            mode = window._btUiText || 'Not Connected';
          }}
          var gainEl = document.getElementById(gainId);
          var gain = gainEl ? parseInt(gainEl.value, 10) : 0;
          var gainStr = gain > 0 ? '+' + gain + ' dB' : (gain < 0 ? gain + ' dB' : '0 dB');
          return dev + ' \u00b7 ' + mode + ' \u00b7 ' + gainStr;
        }}
        function refreshInputCardSubs() {{
          var s1 = document.getElementById('input1-card-sub');
          if (s1) {{
            var en1 = document.querySelector('input[name="audio1_enabled"]');
            if (en1 && !en1.checked) {{
              s1.textContent = 'Not configured';
            }} else {{
              s1.textContent = _inputCardSub('audio_capture_device', 'audio_turntable', 'audio1_gain_db');
            }}
          }}
          var s2 = document.getElementById('input2-card-sub');
          if (s2) {{
            var en = document.querySelector('input[name="audio2_enabled"]');
            if (en && !en.checked) {{
              s2.textContent = 'Disabled';
            }} else {{
              s2.textContent = _inputCardSub('audio2_capture_device', 'audio2_turntable', 'audio2_gain_db');
            }}
          }}
        }}
        function openPanel(id) {{
          document.querySelectorAll('.setup-detail-panel').forEach(function(p) {{ p.classList.remove('active'); }});
          var panel = document.getElementById('panel-' + id);
          if (panel) panel.classList.add('active');
          var track = document.getElementById('setupSlideTrack');
          if (track) track.classList.add('panel-open');
          window.scrollTo(0, 0);
          if (id === 'system') refreshNetworkAdapterInfo();
          if (id === 'playback') refreshRepeatSetupNote();
        }}
        function _repeatCodecLabel(codec) {{
          if (!codec) return '';
          var m = /^mp2_(\\d+)$/.exec(String(codec));
          if (m) return m[1] + 'Kbps MP2';
          if (codec === 'pcm' || codec === 'pcm_s16') return '16-bit PCM';
          return String(codec);
        }}
        async function refreshRepeatSetupNote() {{
          var noteEl = document.getElementById('repeat-max-time-note');
          var unavailEl = document.getElementById('repeat-unavailable-note');
          var populated = false;
          try {{
            var r = await fetch('/api/status', {{ cache: 'no-store' }});
            var d = await r.json();
            var repeat = (d && d.repeat) || null;
            if (!repeat) return false;  // absent on old monitor binaries -- feature unsupported
            var maxSecs = Number(repeat.max_recording_seconds);
            if (noteEl && Number.isFinite(maxSecs) && maxSecs > 0) {{
              // effective_codec: the tier the estimate assumes (monitor
              // status, e.g. "mp2_256" or "pcm"); absent/empty on older
              // monitor builds -> omit the parenthetical.
              var codecLabel = _repeatCodecLabel(repeat.effective_codec);
              noteEl.textContent = 'Buffer: ' + Math.round(maxSecs / 60) + ' mins'
                                   + (codecLabel ? ' (' + codecLabel + ')' : '');
              populated = true;
            }}
            var reason = repeat.recording && repeat.recording.unavailable_reason;
            if (unavailEl) {{
              if (reason) {{
                unavailEl.textContent = 'Repeat unavailable: insufficient free memory';
                unavailEl.style.display = '';
              }} else {{
                unavailEl.style.display = 'none';
                unavailEl.textContent = '';
              }}
            }}
          }} catch (e) {{ return false; }}
          return populated;
        }}
        var _repeatToggleToken = 0;
        // The daemon takes a few seconds to compute the buffer estimate after
        // repeat is (re-)enabled or its target changes, and the status cache
        // backing /api/status only refreshes on its own ~1-2s poll -- retry
        // briefly rather than leaving the note stale until the panel is reopened.
        function pollRepeatNote() {{
          var myToken = ++_repeatToggleToken;
          var attempts = 0;
          var maxAttempts = 8;
          (function poll() {{
            if (myToken !== _repeatToggleToken) return;  // superseded by a later change
            attempts++;
            refreshRepeatSetupNote().then(function(ok) {{
              if (ok || myToken !== _repeatToggleToken || attempts >= maxAttempts) return;
              setTimeout(poll, 1000);
            }});
          }})();
        }}
        function onRepeatEnabledToggle(checked) {{
          settingsSaveField('repeat.enabled', checked);
          var targetSelect = document.getElementById('repeat_target_minutes');
          var targetRow = document.getElementById('repeat-target-row');
          if (targetSelect) targetSelect.disabled = !checked;
          if (targetRow) targetRow.style.opacity = checked ? '' : '0.4';
          if (!checked) {{
            _repeatToggleToken++;  // cancel any in-flight poll
            var noteEl = document.getElementById('repeat-max-time-note');
            var unavailEl = document.getElementById('repeat-unavailable-note');
            if (noteEl) noteEl.textContent = '';
            if (unavailEl) {{
              unavailEl.textContent = '';
              unavailEl.style.display = 'none';
            }}
            return;
          }}
          pollRepeatNote();
        }}
        function onRepeatTargetChange(value) {{
          settingsSaveField('repeat.target_minutes', parseInt(value, 10));
          pollRepeatNote();
        }}
        function onHostnameToggle(checked) {{
          var cb = document.getElementById('webui_control_other_appliances');
          var row = document.getElementById('ctrl-other-row');
          if (cb) {{
            if (!checked) {{
              cb.checked = false;
              cb.disabled = true;
            }} else {{
              cb.disabled = false;
            }}
          }}
          if (row) {{ row.style.opacity = checked ? '' : '0.4'; }}
          refreshCustomiseCardSub();
        }}
        function refreshCustomiseCardSub() {{
          var sub = document.getElementById('customise-card-sub');
          if (!sub) return;
          var cb = document.getElementById('webui_show_master_volume');
          var cbDet = document.getElementById('webui_show_input_detail');
          var cbDark = document.getElementById('webui_dark_mode');
          var cbHost = document.getElementById('webui_show_hostname_on_home');
          var cbCtrl = document.getElementById('webui_control_other_appliances');
          var cbAdv = document.getElementById('webui_advertise_appliance');
          var mv = (cb && cb.checked) ? 'Master volume: On' : 'Master volume: Off';
          var det = (cbDet && cbDet.checked) ? 'Input detail: On' : 'Input detail: Off';
          var dark = (cbDark && cbDark.checked) ? 'Dark mode: On' : 'Dark mode: Off';
          var host = (cbHost && cbHost.checked) ? 'Hostname: On' : 'Hostname: Off';
          var ctrl = (cbCtrl && cbCtrl.checked) ? 'Control others: On' : 'Control others: Off';
          var adv = (cbAdv && cbAdv.checked) ? 'Visible to peers: On' : 'Visible to peers: Off';
          sub.textContent = mv + ' \u00b7 ' + det + ' \u00b7 ' + dark + ' \u00b7 ' + host + ' \u00b7 ' + ctrl + ' \u00b7 ' + adv;
        }}
        function refreshPlaybackCardSub() {{
          var sub = document.getElementById('playback-card-sub');
          if (!sub) return;
          var sel = document.getElementById('owntone_output_select');
          var speaker = sel ? (sel.value || 'No speaker selected') : 'No speaker selected';
          var volEl = document.getElementById('owntone_volume_percent');
          var vol = volEl ? volEl.value : '0';
          sub.textContent = speaker + ' · ' + vol + '%';
        }}
        function refreshTrackIdCardSub() {{
          var sub = document.getElementById('track-id-card-sub');
          if (!sub) return;
          var cb = document.getElementById('track_identification_enabled');
          sub.textContent = (cb && cb.checked) ? 'On' : 'Off';
        }}
        function applyDarkMode(enabled) {{
          document.documentElement.setAttribute('data-theme', enabled ? 'dark' : 'light');
        }}
        function refreshSystemCardSub() {{
          var sub = document.getElementById('system-card-sub');
          if (!sub) return;
          var hn = document.getElementById('systemHostnameValue');
          var hostname = hn ? (hn.textContent.trim() || 'autostream') : 'autostream';
          var cbAu = document.getElementById('updates_auto_update');
          var cbPre = document.getElementById('updates_prerelease_channel');
          var auState = (cbAu && cbAu.checked) ? 'Auto-update: On' : 'Auto-update: Off';
          if (cbPre && cbPre.checked) auState += ' - Pre-release channel';
          sub.textContent = hostname + ' · v{_app_ver} · ' + auState;
        }}
        function refreshSetupCardSubs() {{
          refreshInputCardSubs();
          refreshPlaybackCardSub();
          refreshTrackIdCardSub();
          refreshCustomiseCardSub();
          refreshSystemCardSub();
          refreshDialsCardSub();
        }}
        function closePanel() {{
          refreshSetupCardSubs();
          var track = document.getElementById('setupSlideTrack');
          if (track) track.classList.remove('panel-open');
          window.scrollTo(0, 0);
        }}
      </script>
      <script>
        // ── Dial management ────────────────────────────────────────────────
        var _dialPinRecoveryTimer = null;
        var _dialPinModalCard = null;
        var _dialPinModalMode = null; // 'change' | 'unlock'
        var _dialPinRecoveryModalCard = null;
        var _dialNameModalCard = null;
        var _dialUnlockedPins = new WeakMap(); // card → '' (no PIN) | 'XXXX' (PIN stored) | absent (locked)
        var _ICON_PADLOCK_LOCKED = `{ICON_PADLOCK_LOCKED}`;
        var _ICON_PADLOCK_UNLOCKED = `{ICON_PADLOCK_UNLOCKED}`;

        function setDialAuthorized(card, authorized) {{
          card.dataset.authorized = authorized ? 'true' : 'false';
          if (authorized) {{ delete card.dataset.new; }} else {{ card.dataset.new = 'true'; }}
          var allow = card.querySelector('.dial-allow');
          if (allow) allow.checked = authorized;
          var config = card.querySelector('.dial-config');
          if (config) config.style.display = authorized ? '' : 'none';
          var badge = card.querySelector('.dial-badge');
          if (badge) {{
            var online = card.dataset.online === 'true';
            badge.className = 'dial-badge ' + (authorized
              ? (online ? 'dial-badge-online' : 'dial-badge-offline')
              : 'dial-badge-new');
            badge.textContent = authorized ? (online ? 'Online' : 'Offline') : 'New';
          }}
          if (authorized) {{
            var titleEl = card.querySelector('.dial-card-title');
            var nameInput = card.querySelector('.dial-name');
            if (nameInput && nameInput.value.trim()) {{
              if (titleEl) titleEl.textContent = nameInput.value.trim();
              var nameDisplayEl = card.querySelector('.dial-current-name');
              if (nameDisplayEl) nameDisplayEl.textContent = nameInput.value.trim();
            }}
          }}
        }}
        function syncDialStep(input) {{
          var card = input.closest('.dial-card');
          if (!card) return;
          var valEl = card.querySelector('.dial-step-val');
          if (valEl) valEl.textContent = input.value + '% per click';
        }}

        function _dialLockSection(card) {{
          _dialUnlockedPins.delete(card);
          var section = card.querySelector('.dial-locked-section');
          if (!section) return;
          section.classList.add('dial-section-locked');
          var btn = section.querySelector('.dial-lock-btn');
          if (btn) {{ btn.innerHTML = _ICON_PADLOCK_LOCKED; btn.setAttribute('aria-label', 'Unlock settings'); }}
          section.querySelectorAll('input').forEach(function(el) {{ el.disabled = true; }});
        }}

        function _dialUnlockSection(card, pin) {{
          _dialUnlockedPins.set(card, pin);
          var section = card.querySelector('.dial-locked-section');
          if (!section) return;
          section.classList.remove('dial-section-locked');
          var btn = section.querySelector('.dial-lock-btn');
          if (btn) {{
            if (card.dataset.pinSet === 'true') {{
              btn.innerHTML = _ICON_PADLOCK_UNLOCKED;
              btn.setAttribute('aria-label', 'Lock settings');
              btn.style.display = '';
            }} else {{
              btn.style.display = 'none';
            }}
          }}
          section.querySelectorAll('input').forEach(function(el) {{ el.disabled = false; }});
        }}

        function _updateDialLockVisibility(card) {{
          if (card.dataset.pinSet !== 'true') {{
            _dialUnlockSection(card, '');
          }} else if (!_dialUnlockedPins.has(card)) {{
            _dialLockSection(card);
          }}
          var hasPin = card.dataset.pinSet === 'true';
          var pinBtn = card.querySelector('[data-dial-action="change-pin"]');
          if (pinBtn) pinBtn.textContent = hasPin ? 'Change Dial PIN' : 'Set Dial PIN';
          var recoverBtn = card.querySelector('[data-dial-action="recover-pin"]');
          if (recoverBtn) recoverBtn.disabled = !hasPin;
        }}

        function refreshDialsCardSub() {{
          var sub = document.getElementById('dials-card-sub');
          if (!sub) return;
          var all = document.querySelectorAll('.dial-card');
          var nAuth = 0, nOnline = 0, nNew = 0;
          all.forEach(function(c) {{
            if (c.dataset.authorized === 'true') {{
              nAuth++;
              if (c.dataset.online === 'true') nOnline++;
            }} else {{ nNew++; }}
          }});
          var text;
          if (nAuth === 0 && nNew === 0) {{ text = 'No dials'; }}
          else if (nAuth === 0) {{ text = nNew + ' new'; }}
          else if (nNew > 0) {{ text = nAuth + ' authorized · ' + nNew + ' new'; }}
          else {{ text = nAuth + ' authorized' + (nOnline ? ' · ' + nOnline + ' online' : ''); }}
          sub.textContent = text;
        }}

        function dialUUID(card) {{
          return card ? (card.dataset.dialUuid || '') : '';
        }}

        function dialMsg(card, msg, ok) {{
          var el = card ? card.querySelector('.dial-card-msg') : null;
          if (!el) return;
          el.textContent = msg;
          el.style.color = ok ? 'var(--color-status-success)' : 'var(--color-status-danger)';
          el.style.display = msg ? '' : 'none';
        }}

        function _dialErrorMessage(error) {{
          var map = {{
            'dial_offline': 'Dial is offline',
            'dial_unreachable': 'Dial could not be reached',
            'dial_bad_response': 'Dial returned an invalid response',
            'dial_unavailable': 'Dial is temporarily unavailable',
            'dial_timeout': 'Dial did not respond in time',
            'invalid_response': 'Appliance returned an unexpected response',
            'wrong_pin': 'Incorrect PIN',
            'too_many_attempts': 'Too many attempts; try again later',
          }};
          return map[String(error || '')] || String(error || 'Unknown error');
        }}

        async function _dialFetch(path, opts) {{
          var headers = Object.assign({{'X-CSRF-Token': window.__CSRF || ''}}, (opts.headers || {{}}));
          var r = await fetch(path, Object.assign({{}}, opts, {{headers: headers}}));
          return _parseDialResponse(r);
        }}

        async function _dialPost(path, body) {{
          return _dialFetch(path, {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify(body),
          }});
        }}

        async function dialToggleAllow(card, checked) {{
          var uuid = dialUUID(card);
          if (!uuid) return;
          if (checked) {{
            var nameEl = card.querySelector('.dial-name');
            var name = ((nameEl ? nameEl.value : '') || uuid.slice(0, 8)).trim();
            try {{
              var result = await _dialPost('/api/dial/authorize', {{uuid: uuid, name: name}});
              if (result.ok) {{
                setDialAuthorized(card, true);
                dialLoadConfig(card);
                dialLoadScreenSettings(card);
                refreshDialsCardSub();
                dialMsg(card, 'Authorized', true);
                setTimeout(function() {{ dialMsg(card, '', true); }}, 2000);
              }} else {{
                dialMsg(card, _dialErrorMessage(result.error), false);
                var cb = card.querySelector('.dial-allow');
                if (cb) cb.checked = false;
              }}
            }} catch(e) {{
              dialMsg(card, 'Network error', false);
              var cb2 = card.querySelector('.dial-allow');
              if (cb2) cb2.checked = false;
            }}
          }} else {{
            if (confirm('Remove authorization for this dial?')) {{
              await dialRevoke(card);
            }} else {{
              var cb3 = card.querySelector('.dial-allow');
              if (cb3) cb3.checked = true;
            }}
          }}
        }}

        async function dialRevoke(card) {{
          var uuid = dialUUID(card);
          if (!uuid) return;
          try {{
            var result = await _dialPost('/api/dial/revoke', {{uuid: uuid}});
            if (result.ok) {{
              setDialAuthorized(card, false);
              refreshDialsCardSub();
              dialMsg(card, 'Revoked', true);
              setTimeout(function() {{ dialMsg(card, '', true); }}, 2000);
            }} else {{
              dialMsg(card, _dialErrorMessage(result.error), false);
              var cb = card.querySelector('.dial-allow');
              if (cb) cb.checked = true;
            }}
          }} catch(e) {{
            dialMsg(card, 'Network error', false);
            var cb = card.querySelector('.dial-allow');
            if (cb) cb.checked = true;
          }}
        }}

        async function dialSaveConfig(card) {{
          var uuid = dialUUID(card);
          if (!uuid) return;
          var nameEl = card.querySelector('.dial-name');
          var stepEl = card.querySelector('.dial-step');
          var autoEl = card.querySelector('.dial-autoupdate');
          var chanEl = card.querySelector('.dial-channel');
          var body = {{uuid: uuid}};
          if (nameEl) body.name = nameEl.value.trim();
          if (stepEl) {{
            var step = parseInt(stepEl.value, 10);
            if (!Number.isInteger(step) || step < 1 || step > 10) {{
              dialMsg(card, 'Step must be between 1 and 10', false);
              return;
            }}
            body.step_percent = step;
          }}
          if (autoEl) body.auto_update = autoEl.checked;
          if (chanEl) body.update_channel = chanEl.checked ? 'dev' : 'stable';
          if (card.dataset.pinSet === 'true') {{
            var unlockedPin = _dialUnlockedPins.has(card) ? _dialUnlockedPins.get(card) : null;
            if (!unlockedPin) {{ dialMsg(card, 'Unlock settings first', false); return; }}
            body.current_pin = unlockedPin;
          }}
          try {{
            var result = await _dialPost('/api/dial/configure', body);
            if (result.ok) {{ dialMsg(card, 'Saved', true); setTimeout(function(){{ dialMsg(card, '', true); }}, 2000); }}
            else {{ dialMsg(card, _dialErrorMessage(result.error), false); }}
          }} catch(e) {{
            dialMsg(card, 'Network error', false);
          }}
        }}

        async function dialLoadConfig(card) {{
          var uuid = dialUUID(card);
          if (!uuid) return;
          try {{
            var r = await fetch('/api/dial/configure/' + encodeURIComponent(uuid), {{
              cache: 'no-store', headers: {{'X-CSRF-Token': window.__CSRF || ''}}
            }});
            var loadResult = await _parseDialResponse(r);
            if (!loadResult.ok) return;
            var j = loadResult.body;
            var stepEl = card.querySelector('.dial-step');
            var autoEl = card.querySelector('.dial-autoupdate');
            var chanEl = card.querySelector('.dial-channel');
            if (stepEl && j.step_percent != null) {{
              stepEl.value = j.step_percent;
              var stepValEl = card.querySelector('.dial-step-val');
              if (stepValEl) stepValEl.textContent = j.step_percent + '% per click';
            }}
            if (autoEl && j.auto_update != null) autoEl.checked = !!j.auto_update;
            if (chanEl && j.update_channel != null) chanEl.checked = (j.update_channel === 'dev');
            card.dataset.pinSet = j.pin_set ? 'true' : 'false';
            _updateDialLockVisibility(card);
          }} catch(e) {{}}
        }}

        async function dialLoadScreenSettings(card) {{
          var uuid = dialUUID(card);
          if (!uuid) return;
          try {{
            var r = await fetch('/api/dial/screen/settings/' + encodeURIComponent(uuid), {{
              cache: 'no-store', headers: {{'X-CSRF-Token': window.__CSRF || ''}}
            }});
            var loadResult = await _parseDialResponse(r);
            if (!loadResult.ok) return;
            var j = loadResult.body;
            var fittedEl = card.querySelector('.dial-screen-fitted');
            if (fittedEl && j.screen && j.screen.fitted != null) {{
              fittedEl.checked = !!j.screen.fitted;
            }}
          }} catch(e) {{}}
        }}

        async function dialSaveScreenSettings(card) {{
          var uuid = dialUUID(card);
          if (!uuid) return;
          var fittedEl = card.querySelector('.dial-screen-fitted');
          if (!fittedEl) return;
          var body = {{uuid: uuid, screen: {{fitted: fittedEl.checked}}}};
          if (card.dataset.pinSet === 'true') {{
            var unlockedPin = _dialUnlockedPins.has(card) ? _dialUnlockedPins.get(card) : null;
            if (!unlockedPin) {{ dialMsg(card, 'Unlock settings first', false); return; }}
            body.current_pin = unlockedPin;
          }}
          try {{
            var result = await _dialPost('/api/dial/screen/settings', body);
            if (result.ok) {{ dialMsg(card, 'Saved', true); setTimeout(function(){{ dialMsg(card, '', true); }}, 2000); }}
            else {{
              dialMsg(card, _dialErrorMessage(result.error), false);
              fittedEl.checked = !fittedEl.checked;
            }}
          }} catch(e) {{
            dialMsg(card, 'Network error', false);
            fittedEl.checked = !fittedEl.checked;
          }}
        }}

        async function dialUpdateFirmware(card) {{
          var uuid = dialUUID(card);
          if (!uuid) return;
          if (!confirm('Start firmware update? The dial will restart.')) return;
          try {{
            var r = await fetch('/api/dial/update/' + encodeURIComponent(uuid), {{
              method: 'POST', headers: {{'X-CSRF-Token': window.__CSRF || ''}}
            }});
            var updResult = await _parseDialResponse(r);
            if (updResult.ok) dialMsg(card, 'Update started', true);
            else dialMsg(card, _dialErrorMessage(updResult.error), false);
          }} catch(e) {{ dialMsg(card, 'Network error', false); }}
        }}

        function _openDialPinModal(card, mode, title, message) {{
          _dialPinModalCard = card;
          _dialPinModalMode = mode;
          var modal = document.getElementById('dialPinModal');
          if (!modal) return;
          document.getElementById('dialPinModalTitle').textContent = title;
          document.getElementById('dialPinModalMsg').textContent = message;
          var errEl = document.getElementById('dialPinModalError');
          errEl.style.display = 'none'; errEl.textContent = '';
          var currentInputEl = document.getElementById('dialPinModalCurrentInput');
          currentInputEl.value = '';
          // unlock: current PIN is the only field; change: current PIN not shown (stored from unlock)
          currentInputEl.style.display = mode === 'unlock' ? '' : 'none';
          var inputEl = document.getElementById('dialPinModalInput');
          inputEl.value = '';
          inputEl.style.display = mode === 'unlock' ? 'none' : '';
          var confirmInputEl = document.getElementById('dialPinModalConfirmInput');
          confirmInputEl.value = '';
          confirmInputEl.style.display = mode === 'unlock' ? 'none' : '';
          var okBtn = document.getElementById('dialPinModalOk');
          okBtn.textContent = mode === 'unlock' ? 'Unlock' : (card.dataset.pinSet !== 'true' ? 'Set PIN' : 'Change PIN');
          okBtn.disabled = false;
          document.getElementById('dialPinModalCancel').disabled = false;
          modal.classList.add('show');
          setTimeout(function(){{
            (mode === 'unlock' ? currentInputEl : inputEl).focus();
          }}, 50);
        }}

        function _closeDialPinModal() {{
          _dialPinModalCard = null; _dialPinModalMode = null;
          var modal = document.getElementById('dialPinModal');
          if (modal) modal.classList.remove('show');
        }}

        function dialChangePIN(card) {{
          var hasPin = card.dataset.pinSet === 'true';
          _openDialPinModal(card, 'change',
            hasPin ? 'Change Dial PIN' : 'Set Dial PIN',
            hasPin ? 'Enter a new PIN (leave blank to remove):' : 'Enter a new PIN:');
        }}

        function openDialNameModal(card) {{
          _dialNameModalCard = card;
          var modal = document.getElementById('dialNameModal');
          if (!modal) return;
          var nameInput = card.querySelector('.dial-name');
          var currentName = (nameInput ? nameInput.value : '') || '';
          var inp = document.getElementById('dialNameModalInput');
          var errEl = document.getElementById('dialNameModalError');
          if (inp) {{ inp.value = currentName; inp.disabled = false; }}
          if (errEl) {{ errEl.style.display = 'none'; errEl.textContent = ''; }}
          var ok = document.getElementById('dialNameModalOk');
          var cancel = document.getElementById('dialNameModalCancel');
          if (ok) ok.disabled = false;
          if (cancel) cancel.disabled = false;
          modal.classList.add('show');
          setTimeout(function() {{ if (inp) {{ inp.focus(); inp.select(); }} }}, 50);
        }}

        function closeDialNameModal() {{
          _dialNameModalCard = null;
          var modal = document.getElementById('dialNameModal');
          if (modal) modal.classList.remove('show');
        }}

        async function handleDialNameModalOk() {{
          var card = _dialNameModalCard;
          if (!card) return;
          var uuid = dialUUID(card);
          if (!uuid) return;
          var inp = document.getElementById('dialNameModalInput');
          var errEl = document.getElementById('dialNameModalError');
          var ok = document.getElementById('dialNameModalOk');
          var cancel = document.getElementById('dialNameModalCancel');
          var newName = (inp ? inp.value : '').trim();
          if (!newName) {{
            if (errEl) {{ errEl.textContent = 'Enter a name.'; errEl.style.display = ''; }}
            if (inp) inp.focus();
            return;
          }}
          var body = {{uuid: uuid, name: newName}};
          if (card.dataset.pinSet === 'true') {{
            var storedPin = _dialUnlockedPins.has(card) ? _dialUnlockedPins.get(card) : null;
            if (storedPin) body.current_pin = storedPin;
          }}
          if (ok) ok.disabled = true;
          if (cancel) cancel.disabled = true;
          if (errEl) {{ errEl.style.display = 'none'; errEl.textContent = ''; }}
          try {{
            var result = await _dialPost('/api/dial/configure', body);
            if (result.ok) {{
              var nameInput = card.querySelector('.dial-name');
              if (nameInput) nameInput.value = newName;
              var titleEl = card.querySelector('.dial-card-title');
              if (titleEl) titleEl.textContent = newName;
              var nameDisplayEl = card.querySelector('.dial-current-name');
              if (nameDisplayEl) nameDisplayEl.textContent = newName;
              dialMsg(card, 'Name changed', true);
              setTimeout(function() {{ dialMsg(card, '', true); }}, 2000);
              closeDialNameModal();
            }} else {{
              if (errEl) {{ errEl.textContent = _dialErrorMessage(result.error); errEl.style.display = ''; }}
              if (ok) ok.disabled = false;
              if (cancel) cancel.disabled = false;
            }}
          }} catch(e) {{
            if (errEl) {{ errEl.textContent = 'Network error'; errEl.style.display = ''; }}
            if (ok) ok.disabled = false;
            if (cancel) cancel.disabled = false;
          }}
        }}

        function openDialPinRecoveryModal(card) {{
          _dialPinRecoveryModalCard = card;
          var uuid = dialUUID(card);
          var modal = document.getElementById('dialPinRecoveryModal');
          if (!modal || !uuid) return;
          document.getElementById('dialPinRecoveryModalTitle').textContent = 'Reset Dial PIN';
          document.getElementById('dialPinRecoveryWaitPanel').style.display = '';
          document.getElementById('dialPinRecoverySetPanel').style.display = 'none';
          document.getElementById('dialPinRecoveryWaitMsg').textContent =
            'To reset the Dial PIN, start by power-cycling the Dial now. Once it restarts, you have 10 minutes to confirm access by turning the Dial clockwise.';
          var newInp = document.getElementById('dialPinRecoveryNewInput');
          var confInp = document.getElementById('dialPinRecoveryConfirmInput');
          var errEl = document.getElementById('dialPinRecoveryError');
          if (newInp) newInp.value = '';
          if (confInp) confInp.value = '';
          if (errEl) {{ errEl.style.display = 'none'; errEl.textContent = ''; }}
          var okBtn = document.getElementById('dialPinRecoveryOk');
          var cancelBtn = document.getElementById('dialPinRecoveryCancel');
          if (okBtn) {{ okBtn.disabled = true; okBtn.textContent = 'Waiting for Dial…'; }}
          if (cancelBtn) cancelBtn.disabled = false;
          modal.classList.add('show');
          if (_dialPinRecoveryTimer) {{ clearInterval(_dialPinRecoveryTimer); _dialPinRecoveryTimer = null; }}
          _dialPinRecoveryTimer = setInterval(async function() {{
            try {{
              var r = await fetch('/api/dial/pin_recovery/status/' + encodeURIComponent(uuid), {{
                cache: 'no-store', headers: {{'X-CSRF-Token': window.__CSRF || ''}}
              }});
              var pollResult = await _parseDialResponse(r);
              if (!pollResult.ok) return; // offline, unreachable, or not yet in recovery — wait silently
              var body = pollResult.body || {{}};
              if (body.volume_confirmed === true) {{
                clearInterval(_dialPinRecoveryTimer); _dialPinRecoveryTimer = null;
                _dialPinRecoveryTransitionToSet();
              }} else if (body.active === true) {{
                document.getElementById('dialPinRecoveryWaitMsg').textContent =
                  'Turn the Dial clockwise once to confirm access.';
              }}
            }} catch(e) {{}}
          }}, 2000);
        }}

        function _dialPinRecoveryTransitionToSet() {{
          document.getElementById('dialPinRecoveryModalTitle').textContent = 'Set New Dial PIN';
          document.getElementById('dialPinRecoveryWaitPanel').style.display = 'none';
          document.getElementById('dialPinRecoverySetPanel').style.display = '';
          var okBtn = document.getElementById('dialPinRecoveryOk');
          if (okBtn) {{ okBtn.disabled = false; okBtn.textContent = 'Set PIN'; }}
          setTimeout(function() {{
            var newInp = document.getElementById('dialPinRecoveryNewInput');
            if (newInp) newInp.focus();
          }}, 50);
        }}

        function closeDialPinRecoveryModal() {{
          _dialPinRecoveryModalCard = null;
          if (_dialPinRecoveryTimer) {{ clearInterval(_dialPinRecoveryTimer); _dialPinRecoveryTimer = null; }}
          var modal = document.getElementById('dialPinRecoveryModal');
          if (modal) modal.classList.remove('show');
        }}

        async function handleDialPinRecoveryOk() {{
          var card = _dialPinRecoveryModalCard;
          if (!card) return;
          var uuid = dialUUID(card);
          if (!uuid) return;
          var newInp = document.getElementById('dialPinRecoveryNewInput');
          var confInp = document.getElementById('dialPinRecoveryConfirmInput');
          var errEl = document.getElementById('dialPinRecoveryError');
          var okBtn = document.getElementById('dialPinRecoveryOk');
          var cancelBtn = document.getElementById('dialPinRecoveryCancel');
          var newPin = (newInp ? newInp.value : '').trim();
          var confPin = (confInp ? confInp.value : '').trim();
          if (!/^\\d{{4,8}}$/.test(newPin)) {{
            if (errEl) {{ errEl.textContent = 'Enter 4–8 digits.'; errEl.style.display = ''; }}
            if (newInp) newInp.focus();
            return;
          }}
          if (newPin !== confPin) {{
            if (errEl) {{ errEl.textContent = 'The two PIN entries did not match.'; errEl.style.display = ''; }}
            if (confInp) confInp.focus();
            return;
          }}
          if (errEl) {{ errEl.style.display = 'none'; errEl.textContent = ''; }}
          if (okBtn) okBtn.disabled = true;
          if (cancelBtn) cancelBtn.disabled = true;
          try {{
            var result = await _dialPost('/api/dial/pin_recovery/complete', {{uuid: uuid, new_pin: newPin, pin_recovery: true}});
            if (result.ok) {{
              card.dataset.pinSet = 'true';
              _updateDialLockVisibility(card);
              dialMsg(card, 'PIN reset', true);
              closeDialPinRecoveryModal();
            }} else {{
              if (errEl) {{ errEl.textContent = _dialErrorMessage(result.error); errEl.style.display = ''; }}
              if (okBtn) okBtn.disabled = false;
              if (cancelBtn) cancelBtn.disabled = false;
            }}
          }} catch(e) {{
            if (errEl) {{ errEl.textContent = 'Network error'; errEl.style.display = ''; }}
            if (okBtn) okBtn.disabled = false;
            if (cancelBtn) cancelBtn.disabled = false;
          }}
        }}

        async function _handleDialPinModalOk() {{
          var card = _dialPinModalCard;
          var uuid = dialUUID(card);
          var mode = _dialPinModalMode;
          if (!uuid) return;
          var currentInputEl = document.getElementById('dialPinModalCurrentInput');
          var inputEl = document.getElementById('dialPinModalInput');
          var errEl = document.getElementById('dialPinModalError');
          var okBtn = document.getElementById('dialPinModalOk');
          var currentPin = (currentInputEl ? currentInputEl.value : '').trim();
          var pin = (inputEl ? inputEl.value : '').trim();
          okBtn.disabled = true; errEl.style.display = 'none';
          try {{
            var pinResult;
            if (mode === 'unlock') {{
              // Verify PIN by saving the current config values — same payload as dialSaveConfig.
              // The dial validates the PIN against a real request; values are unchanged.
              var verifyBody = {{uuid: uuid, current_pin: currentPin}};
              var nameEl2 = card.querySelector('.dial-name');
              var stepEl2 = card.querySelector('.dial-step');
              var autoEl2 = card.querySelector('.dial-autoupdate');
              var chanEl2 = card.querySelector('.dial-channel');
              if (nameEl2) verifyBody.name = nameEl2.value.trim();
              if (stepEl2) {{
                var step2 = parseInt(stepEl2.value, 10);
                if (Number.isInteger(step2)) verifyBody.step_percent = step2;
              }}
              if (autoEl2) verifyBody.auto_update = autoEl2.checked;
              if (chanEl2) verifyBody.update_channel = chanEl2.checked ? 'dev' : 'stable';
              pinResult = await _dialPost('/api/dial/configure', verifyBody);
              if (pinResult.ok) {{
                _dialUnlockSection(card, currentPin);
                dialLoadScreenSettings(card);
                _closeDialPinModal();
              }} else {{
                errEl.textContent = _dialErrorMessage(pinResult.error); errEl.style.display = '';
                okBtn.disabled = false;
              }}
            }} else {{
              var confirmInputEl = document.getElementById('dialPinModalConfirmInput');
              var confirmPin = (confirmInputEl ? confirmInputEl.value : '').trim();
              if (pin !== confirmPin) {{
                errEl.textContent = 'The two PIN entries did not match.'; errEl.style.display = '';
                okBtn.disabled = false;
                if (confirmInputEl) confirmInputEl.focus();
                return;
              }}
              var body = {{uuid: uuid, new_pin: pin}};
              if (card.dataset.pinSet === 'true') {{
                var storedPin = _dialUnlockedPins.has(card) ? _dialUnlockedPins.get(card) : null;
                if (storedPin) body.current_pin = storedPin;
              }}
              pinResult = await _dialPost('/api/dial/configure', body);
              if (pinResult.ok) {{
                card.dataset.pinSet = pin ? 'true' : 'false';
                dialMsg(card, pin ? 'PIN changed' : 'PIN removed', true);
                _closeDialPinModal();
                _updateDialLockVisibility(card);
              }} else {{
                errEl.textContent = _dialErrorMessage(pinResult.error); errEl.style.display = '';
                okBtn.disabled = false;
              }}
            }}
          }} catch(e) {{
            errEl.textContent = 'Network error'; errEl.style.display = '';
            okBtn.disabled = false;
          }}
        }}

        document.addEventListener('DOMContentLoaded', function() {{
          var ok = document.getElementById('dialPinModalOk');
          var cancel = document.getElementById('dialPinModalCancel');
          var pinConfirmInp = document.getElementById('dialPinModalConfirmInput');
          if (ok) ok.addEventListener('click', _handleDialPinModalOk);
          if (cancel) cancel.addEventListener('click', _closeDialPinModal);
          if (pinConfirmInp) pinConfirmInp.addEventListener('keydown', function(ev) {{
            if (ev.key === 'Enter') {{ ev.preventDefault(); _handleDialPinModalOk(); }}
          }});
          var recoveryOk = document.getElementById('dialPinRecoveryOk');
          var recoveryCancel = document.getElementById('dialPinRecoveryCancel');
          var recoveryConfirmInp = document.getElementById('dialPinRecoveryConfirmInput');
          if (recoveryOk) recoveryOk.addEventListener('click', handleDialPinRecoveryOk);
          if (recoveryCancel) recoveryCancel.addEventListener('click', closeDialPinRecoveryModal);
          if (recoveryConfirmInp) recoveryConfirmInp.addEventListener('keydown', function(ev) {{
            if (ev.key === 'Enter') {{ ev.preventDefault(); handleDialPinRecoveryOk(); }}
          }});
          var dialNameOk = document.getElementById('dialNameModalOk');
          var dialNameCancel = document.getElementById('dialNameModalCancel');
          var dialNameInput = document.getElementById('dialNameModalInput');
          if (dialNameOk) dialNameOk.addEventListener('click', handleDialNameModalOk);
          if (dialNameCancel) dialNameCancel.addEventListener('click', closeDialNameModal);
          if (dialNameInput) dialNameInput.addEventListener('keydown', function(ev) {{
            if (ev.key === 'Enter') {{ ev.preventDefault(); handleDialNameModalOk(); }}
          }});
          document.querySelectorAll('.dial-card').forEach(function(card) {{
            card.addEventListener('change', function(ev) {{
              var action = ev.target.dataset.dialAction;
              if (action === 'toggle-allow') dialToggleAllow(card, ev.target.checked);
              if (action === 'save-config' && (
                ev.target.classList.contains('dial-autoupdate') ||
                ev.target.classList.contains('dial-channel') ||
                ev.target.classList.contains('dial-step')
              )) dialSaveConfig(card);
              if (action === 'save-screen') dialSaveScreenSettings(card);
            }});
            card.addEventListener('focusout', function(ev) {{
              if (ev.target.dataset.dialAction === 'save-config'
                  && !ev.target.classList.contains('dial-autoupdate')
                  && !ev.target.classList.contains('dial-channel')
                  && !ev.target.classList.contains('dial-step')) {{
                dialSaveConfig(card);
              }}
            }});
            var lockedSection = card.querySelector('.dial-locked-section');
            if (lockedSection) {{
              lockedSection.addEventListener('focusout', function(ev) {{
                setTimeout(function() {{
                  if (!lockedSection.contains(document.activeElement)) {{
                    if (card.dataset.pinSet === 'true') _dialLockSection(card);
                  }}
                }}, 0);
              }});
            }}
            card.addEventListener('click', function(ev) {{
              var target = ev.target.closest('[data-dial-action]');
              if (!target || target.tagName === 'INPUT') return;
              var action = target.dataset.dialAction;
              if (action === 'revoke') dialRevoke(card);
              if (action === 'update') dialUpdateFirmware(card);
              if (action === 'change-pin') dialChangePIN(card);
              if (action === 'recover-pin') openDialPinRecoveryModal(card);
              if (action === 'change-name') openDialNameModal(card);
              if (action === 'toggle-lock') {{
                if (_dialUnlockedPins.has(card) && card.dataset.pinSet === 'true') {{
                  _dialLockSection(card);
                }} else if (!_dialUnlockedPins.has(card)) {{
                  _openDialPinModal(card, 'unlock', 'Unlock Settings', 'Enter your Dial PIN:');
                }}
              }}
            }});
          }});
          document.addEventListener('keydown', function(ev) {{
            var m = document.getElementById('dialPinModal');
            if (ev.key === 'Escape' && m && m.classList.contains('show')) _closeDialPinModal();
            var hm = document.getElementById('hostnameModal');
            if (ev.key === 'Escape' && hm && hm.classList.contains('show')) closeHostnameModal();
            var wm = document.getElementById('wifiHotspotModal');
            if (ev.key === 'Escape' && wm && wm.classList.contains('show')) cancelChangeWifiNetwork();
            var rm = document.getElementById('dialPinRecoveryModal');
            if (ev.key === 'Escape' && rm && rm.classList.contains('show')) closeDialPinRecoveryModal();
            var nm = document.getElementById('dialNameModal');
            if (ev.key === 'Escape' && nm && nm.classList.contains('show')) closeDialNameModal();
          }});
          // Load current config for each online authorized dial
          {_dial_onload_js}
        }});
      </script>
      <script>
        // ── Network adapter status and Change Wi-Fi ─────────────────
        async function refreshNetworkAdapterInfo() {{
          var adapterEl = document.getElementById('networkAdapterInfo');
          var addressEl = document.getElementById('networkAddressInfo');
          var warningEl = document.getElementById('networkWarning');
          var supportEl = document.getElementById('networkSupportDetail');
          var titleEl = document.getElementById('networkCardTitle');
          var pendingEl = document.getElementById('networkUsbPending');
          var roamingEl = document.getElementById('networkRoamingManaged');
          function networkStatusFailed() {{
            if (titleEl) titleEl.textContent = 'Network';
            if (adapterEl) {{
              adapterEl.textContent = 'Could not check network status';
              adapterEl.style.display = '';
            }}
            if (addressEl) addressEl.style.display = 'none';
            if (warningEl) warningEl.style.display = 'none';
            if (supportEl) supportEl.style.display = 'none';
          }}
          try {{
            var r = await fetch('/api/network/status', {{
              credentials: 'same-origin',
              cache: 'no-store',
              headers: {{ 'X-CSRF-Token': (window.__CSRF || '') }}
            }});
            var j = await r.json().catch(function() {{ return null; }});
            if (!r.ok || !j || j.ok === false || j.error || j.error_status) {{
              networkStatusFailed();
              return;
            }}
            if (titleEl) titleEl.textContent = j.title || 'Network';
            if (adapterEl) {{
              if (Array.isArray(j.interface_lines) && j.interface_lines.length) {{
                adapterEl.textContent = j.interface_lines.join('\\n');
                adapterEl.style.display = '';
              }} else if (j.display) {{
                adapterEl.textContent = j.display;
                adapterEl.style.display = '';
              }} else {{
                adapterEl.style.display = 'none';
              }}
            }}
            if (addressEl) {{
              if (Array.isArray(j.interface_lines) && j.interface_lines.length) {{
                addressEl.style.display = 'none';
              }} else if (j.detail) {{
                addressEl.textContent = j.detail;
                addressEl.style.display = '';
              }} else {{
                addressEl.style.display = 'none';
              }}
            }}
            if (warningEl) {{
              if (j.warning) {{
                warningEl.textContent = j.warning;
                warningEl.style.color = (j.warning_severity === 'danger')
                  ? 'var(--color-status-danger,#c00)'
                  : 'var(--color-warning,#b26b00)';
                warningEl.style.display = '';
              }} else {{
                warningEl.style.display = 'none';
              }}
            }}
            if (supportEl) {{
              if (j.support_detail) {{
                supportEl.textContent = j.support_detail;
                supportEl.style.display = '';
              }} else {{
                supportEl.style.display = 'none';
              }}
            }}
            if (pendingEl) pendingEl.style.display = j.usb_adoption_pending ? '' : 'none';
            if (roamingEl) roamingEl.checked = !!(j.roaming && j.roaming.managed);
            if (j.ap_ssid) {{
              var ssidEl = document.getElementById('wifiHotspotSsid');
              if (ssidEl) ssidEl.textContent = j.ap_ssid;
            }}
          }} catch (e) {{ networkStatusFailed(); }}
        }}
        refreshNetworkAdapterInfo();
        setInterval(refreshNetworkAdapterInfo, 5000);

        async function setRoamingManagement(managed) {{
          try {{
            var r = await fetch('/api/network/roaming', {{
              method: 'POST',
              credentials: 'same-origin',
              headers: {{
                'Content-Type': 'application/json',
                'X-CSRF-Token': (window.__CSRF || '')
              }},
              body: JSON.stringify({{ managed: managed, csrf_token: (window.__CSRF || '') }})
            }});
            var j = await r.json().catch(function() {{ return {{}}; }});
            if (!r.ok || !j || j.ok !== true) {{
              refreshNetworkAdapterInfo();
            }}
          }} catch (e) {{
            refreshNetworkAdapterInfo();
          }}
        }}

        function changeWifiNetwork() {{
          var modal = document.getElementById('wifiHotspotModal');
          if (modal) modal.classList.add('show');
        }}

        function cancelChangeWifiNetwork() {{
          var modal = document.getElementById('wifiHotspotModal');
          if (modal) modal.classList.remove('show');
        }}

        async function confirmChangeWifiNetwork() {{
          var modal = document.getElementById('wifiHotspotModal');
          if (modal) modal.classList.remove('show');
          var btn = document.querySelector('#networkCard .pill-btn');
          var msg = document.getElementById('networkSetupMsg');
          if (btn) btn.disabled = true;
          if (msg) {{ msg.textContent = 'Starting setup hotspot…'; msg.style.color = ''; }}
          try {{
            var r = await fetch('/api/network/setup', {{
              method: 'POST',
              credentials: 'same-origin',
              headers: {{
                'Content-Type': 'application/json',
                'X-CSRF-Token': (window.__CSRF || '')
              }},
              body: JSON.stringify({{ action: 'start_setup', csrf_token: (window.__CSRF || '') }})
            }});
            var j = await r.json().catch(function() {{ return {{}}; }});
            if (r.ok && j && j.ok) {{
              if (msg) {{ msg.textContent = 'Hotspot starting. Connect to the “autostream-setup” network to complete setup.'; msg.style.color = ''; }}
            }} else if (r.status === 409) {{
              if (msg) {{ msg.textContent = 'A network change is already in progress.'; msg.style.color = 'var(--color-error,#c00)'; }}
              if (btn) btn.disabled = false;
            }} else {{
              if (msg) {{ msg.textContent = 'Could not start setup. Please try again.'; msg.style.color = 'var(--color-error,#c00)'; }}
              if (btn) btn.disabled = false;
            }}
          }} catch (e) {{
            if (msg) {{ msg.textContent = 'Network error. Please try again.'; msg.style.color = 'var(--color-error,#c00)'; }}
            if (btn) btn.disabled = false;
          }}
        }}
      </script>
      {factory_reset_js}
      {_bt_pairing_js}
      {_bt_card_js}"""
    html_body = build_page_html(
        "autostream",
        _body_html,
        extra_css=_extra_css,
        head_extra=csrf_meta,
        body_prefix=_body_prefix,
        body_suffix=_body_suffix,
        lic_html=lic_html,
        lic_spacer=lic_spacer,
        show_nav=True,
        active_tab="setup",
        dark_mode=parsed.webui.dark_mode,
    )
    body_bytes = html_body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)
