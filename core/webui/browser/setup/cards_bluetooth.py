#!/usr/bin/env python3
"""webui/browser/setup/cards_bluetooth.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The Bluetooth card of the Setup page, the Bluetooth gates and text helpers the
Input cards also read, and the SD card health rows.
"""

from __future__ import annotations

import html
from typing import Optional

from autostream_sysutils import SDCARD_HEALTH_METHODS
from webui.common import settings_card_html
from webui.session_state import WebUIState
from webui.browser.setup import context


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


def _setup_compute_bluetooth_state(state: WebUIState) -> dict:
    """Shared Bluetooth state used by the Input cards, the Bluetooth card,
    and the Bluetooth JS blocks. Returns a dict rather than a dataclass to
    keep this a pure mechanical relocation of the original locals."""
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
    return {
        "bt_enabled": bt_enabled,
        "bt_status": bt_status,
        "bt_paired": bt_paired,
        "bt_services_on": bt_services_on,
        "bt_onboard_on": bt_onboard_on,
        "bt_buffer_ms": bt_buffer_ms,
        "bt_card_summary": bt_card_summary,
        "bt_paired_row_text": bt_paired_row_text,
    }


def _sdcard_health_status_line(sd_health: dict) -> str:
    if not sd_health.get("tool_present"):
        return "Tool not installed"
    if not sd_health.get("timer_enabled"):
        return "Not monitored"
    percent = sd_health.get("health_percent")
    if sd_health.get("check") == "passed" and percent is not None:
        when = sd_health.get("last_sampled_at") or sd_health.get("at") or "unknown"
        return f"Monitored, {percent} % endurance remaining, last checked {when}"
    return "Not monitored"


def _sdcard_health_card_line(sd_health: dict) -> str:
    card = sd_health.get("card") or {}
    name = str(card.get("name") or "").strip()
    manfid = card.get("manfid")
    if not name or manfid is None:
        return "support unknown"
    line = f"{name}, manufacturer 0x{manfid:02x}"
    if card.get("likely_supported"):
        line += ", likely supported"
    return line


def _setup_sdcard_health_row_html(sd_health: dict) -> str:
    """SD card health monitoring row in the System card."""
    tool_present = bool(sd_health.get("tool_present"))
    timer_enabled = bool(sd_health.get("timer_enabled"))
    method = str(sd_health.get("method") or "auto")
    if method not in SDCARD_HEALTH_METHODS:
        method = "auto"

    status_line = html.escape(_sdcard_health_status_line(sd_health))
    card_line = html.escape(_sdcard_health_card_line(sd_health))

    method_options = "".join(
        f'<option value="{m}"{" selected" if m == method else ""}>{m}</option>'
        for m in sorted(SDCARD_HEALTH_METHODS)
    )
    controls_disabled = "" if tool_present else " disabled"
    button_label = "Disable" if timer_enabled else "Enable"
    button_onclick = "sdHealthDisable()" if timer_enabled else "showSdHealthModal()"

    return f"""
      <div id="sdHealthRow" style="margin-top:1.25rem;padding-top:1rem;border-top:1px solid var(--color-border-nav);">
        <p style="margin:0 0 0.35rem;font-weight:600;">SD card health monitoring</p>
        <p id="sdHealthStatusLine" style="margin:0 0 0.35rem;">{status_line}</p>
        <p id="sdHealthCardLine" style="margin:0 0 0.5rem;font-size:0.8rem;color:#888;">{card_line}</p>
        <div style="display:flex;align-items:center;gap:0.5rem;">
          <select id="sdHealthMethod"{" disabled" if timer_enabled or not tool_present else ""}>
            {method_options}
          </select>
          <button type="button" id="sdHealthActionBtn" class="pill-btn small" style="flex:0 0 auto;"{controls_disabled}
            onclick="{button_onclick}">{button_label}</button>
        </div>
      </div>"""


def _setup_bluetooth_card_html(
    *,
    bt_enabled: bool,
    bt_status: Optional[dict],
    bt_paired: bool,
    bt_services_on: bool,
    bt_onboard_on: bool,
    bt_buffer_ms: int,
    bt_paired_row_text: str,
) -> str:
    """Bluetooth detail-panel card."""
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
                onclick="openBtPairingModal(null, null)">Pair a device&hellip;</button>
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
    return bluetooth_card_html


def summary_bluetooth(ctx: context.SetupCtx) -> str:
    return ctx.bt_card_summary


def detail_bluetooth(ctx: context.SetupCtx) -> str:
    return _setup_bluetooth_card_html(
        bt_enabled=ctx.bt_enabled,
        bt_status=ctx.bt_status,
        bt_paired=ctx.bt_paired,
        bt_services_on=ctx.bt_services_on,
        bt_onboard_on=ctx.bt_onboard_on,
        bt_buffer_ms=ctx.bt_buffer_ms,
        bt_paired_row_text=ctx.bt_paired_row_text,
    )
