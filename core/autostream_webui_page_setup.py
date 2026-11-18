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

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import parse_qs

from autostream_config import (
    INPUT_TYPES,
    INPUT_TYPE_LABELS,
    INPUT_TYPE_SILENCE_THRESHOLD_DBFS,
    SILENCE_THRESHOLD_MAX_DBFS,
    SILENCE_THRESHOLD_MIN_DBFS,
    input_type_label,
    mark_configured,
    normalize_input_type,
)
from autostream_dials import parse_dial_entries, sighting_needs_update

try:
    from autostream_dials import get_all_sightings as _get_dial_sightings
except ImportError:
    def _get_dial_sightings() -> list:  # type: ignore[misc]
        return []

from autostream_state import store
from autostream_players import (
    SETTING_DEVICE_REMOVAL_GRACE_PERIOD_DEFAULT_MINUTES,
    SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MAX_MINUTES,
    SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MIN_MINUTES,
)
from autostream_rpi import is_high_performance_pi
from autostream_sysutils import (
    SDCARD_HEALTH_METHODS,
    get_ap_ssid,
    get_system_hostname,
    sdcard_health_state,
)
from autostream_webui_assets import (
    ICON_PADLOCK_LOCKED,
    ICON_PADLOCK_UNLOCKED,
    INFO_MODAL_HTML,
)
import autostream_webui_static as static
from autostream_webui_common import (
    _config_snapshot,
    _set_flash_cookie,
    build_page_html,
    build_top_banner_html,
    get_app_version,
    send_html,
    settings_card_html,
)
from autostream_webui_api import send_json
from autostream_webui_components import toggle_html
from autostream_webui_state import WebUIState


# -----------------------------------------------------------------------------
# Setup card registry.
#
# ``SetupCtx`` bundles the per-request state every card's summary/detail
# renderer needs -- the same values ``send_setup_page()`` used to compute
# as inline locals before this split. It is built once by
# ``_setup_build_ctx()``: ``send_setup_page()`` uses it to render every
# card's *summary* row (cheap: no detail-panel HTML is built), and the
# lazy per-card fetch route (``handle_setup_card_get()``) uses a freshly
# built one to render a single card's *detail* panel HTML on demand.
#
# The initial /setup response does not inline all nine detail panels
# (only their collapsed summary rows + an empty per-panel body
# placeholder); opening a card fetches `GET /api/setup/card/<key>` the
# first time, caching the result client-side thereafter. Every card's
# field-level auto-save endpoints are unchanged -- only how the detail
# markup itself reaches the browser changes.
# -----------------------------------------------------------------------------


@dataclass
class SetupCtx:
    """Shared, per-request context for the Setup page's card registry."""

    handler: object
    state: WebUIState
    auth: object
    parsed: object
    monitor_devices: list
    bt_enabled: bool
    bt_status: Optional[dict]
    bt_paired: bool
    bt_services_on: bool
    bt_onboard_on: bool
    bt_buffer_ms: int
    bt_card_summary: str
    bt_paired_row_text: str
    sd_health: dict
    current_hostname: str
    factory_reset: dict
    dial_cards_html: str
    dials_summary: str


def _setup_build_ctx(handler, state: WebUIState, auth) -> SetupCtx:
    """Build the shared per-request context every card renderer reads from.

    May raise (a broken/partial config, per ``_config_snapshot()``'s own
    contract) -- callers are responsible for the "swallow and log, degrade
    gracefully" handling send_setup_page() has always done for this.
    """
    parsed = _config_snapshot(state)
    monitor_devices = state.get_monitor_devices()
    _bt_state = _setup_compute_bluetooth_state(state)
    try:
        sd_health = sdcard_health_state()
    except Exception:
        logging.exception("_setup_build_ctx: sdcard_health_state failed")
        sd_health = {
            "tool_present": False,
            "timer_enabled": False,
            "method": "auto",
            "check": "none",
            "serial": "",
            "at": "",
            "reason": "",
            "card": {"manfid": None, "oemid": None, "name": "", "serial": "", "likely_supported": False},
            "health_percent": None,
            "last_sampled_at": None,
        }
    current_hostname = get_system_hostname()
    factory_reset = _setup_factory_reset_html(auth)
    dial_cards_html, dials_summary = _setup_dial_cards_html()
    return SetupCtx(
        handler=handler,
        state=state,
        auth=auth,
        parsed=parsed,
        monitor_devices=monitor_devices,
        bt_enabled=_bt_state["bt_enabled"],
        bt_status=_bt_state["bt_status"],
        bt_paired=_bt_state["bt_paired"],
        bt_services_on=_bt_state["bt_services_on"],
        bt_onboard_on=_bt_state["bt_onboard_on"],
        bt_buffer_ms=_bt_state["bt_buffer_ms"],
        bt_card_summary=_bt_state["bt_card_summary"],
        bt_paired_row_text=_bt_state["bt_paired_row_text"],
        sd_health=sd_health,
        current_hostname=current_hostname,
        factory_reset=factory_reset,
        dial_cards_html=dial_cards_html,
        dials_summary=dials_summary,
    )


@dataclass(frozen=True)
class Card:
    """One row of the Setup page's card registry.

    ``render_summary``/``render_detail`` both take a ``SetupCtx`` and
    return HTML fragments: the collapsed list-row's sub-text, and the
    detail panel's body (fetched lazily -- see module docstring above)
    respectively. ``detail_header`` is the title passed to
    ``_setup_detail_header()`` for the detail panel's heading; ``None``
    means the card's own detail HTML supplies its own heading (only
    Factory Reset does this today).
    """

    key: str
    title: str
    render_summary: Callable[[SetupCtx], str]
    render_detail: Callable[[SetupCtx], str]
    detail_header: Optional[str] = None


CARDS: list = []


def _register_card(
    key: str,
    title: str,
    render_summary: Callable[[SetupCtx], str],
    render_detail: Callable[[SetupCtx], str],
    detail_header: Optional[str] = None,
) -> None:
    CARDS.append(
        Card(
            key=key,
            title=title,
            render_summary=render_summary,
            render_detail=render_detail,
            detail_header=detail_header,
        )
    )


def _setup_list_row_html(card: Card, summary_html: str) -> str:
    return f"""
      <div class="setup-list-card" onclick="openPanel('{card.key}')">
        <div class="setup-list-card-body">
          <span class="setup-list-card-title">{html.escape(card.title)}</span>
          <span class="setup-list-card-sub" id="{card.key}-card-sub">{summary_html}</span>
        </div>
        <span class="setup-list-chevron">&rsaquo;</span>
      </div>"""


def _setup_panel_shell_html(card: Card) -> str:
    header = _setup_detail_header(card.detail_header) if card.detail_header else ""
    return f"""
      <div class="setup-detail-panel" id="panel-{card.key}">
        <div class="setup-detail-back">
          <button type="button" class="pill-btn small" onclick="closePanel()">&larr; Back</button>
        </div>
        {header}
        <div class="setup-detail-panel-body" id="panel-body-{card.key}"></div>
      </div>"""


def handle_setup_card_get(handler, state: WebUIState, auth, key: str) -> None:
    """`GET /api/setup/card/<key>` -- the lazy per-card detail fetch.

    Same FULL auth + commissioning gating as `/setup` itself (see the
    route table registration); this handler only has to worry about the
    card key itself once dispatch() has already let the request through.
    """
    card = next((c for c in CARDS if c.key == key), None)
    if card is None:
        send_json(handler, 404, {"ok": False, "error": "unknown_card"})
        return
    try:
        ctx = _setup_build_ctx(handler, state, auth)
    except Exception:
        logging.exception("handle_setup_card_get: failed to build setup context for card %r", key)
        send_json(handler, 200, {"ok": False, "error": "config_error"})
        return
    send_json(handler, 200, {"ok": True, "html": card.render_detail(ctx)})


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
    needs_update_protocol: bool = False,
    pin_recovery: bool = False,
    ip: str = "",
    sdmon: bool = False,
) -> str:
    """Normalised dial card for any authorization/online state.

    Root element attributes allow JS to update cards in place without reload:
      data-authorized  "true" | "false"
      data-online      "true" | "false"
      data-new         present when authorized is False

    pin_recovery renders an additional "Recovery Active" badge alongside the
    online/offline/new badge, reflecting the dial's mDNS pin_recovery=1 TXT
    flag as known at page-render time. Callers must not pass True for a dial
    with no live sighting (offline dials cannot be advertising a recovery
    window). Because this snapshot can go stale within the 10-minute
    recovery window, the PIN-recovery modal's own status poller keeps the
    badge in sync (add/remove) for a card while that modal is open -- see
    openDialPinRecoveryModal()/_dialSetRecoveryBadge() below.

    ip is the live mDNS-resolved address, shown under "Current name" only
    while the dial is online; display-only, no persisted copy.

    sdmon renders the SD card health monitoring row; True only for a live
    sighting that advertises `dial_sdmon=v1`.
    """
    su = html.escape(uuid)
    nv = html.escape(name or "")

    if authorized and online:
        badge_cls, badge_text = "dial-badge-online", "Online"
    elif authorized:
        badge_cls, badge_text = "dial-badge-offline", "Offline"
    else:
        badge_cls, badge_text = "dial-badge-new", "New"

    recovery_badge_html = (
        '<span class="dial-badge dial-badge-recovery">Recovery Active</span>'
        if pin_recovery else ""
    )

    protocol_update = bool(online and needs_update_protocol)
    data_needs_update = ' data-needs-update="true"' if protocol_update else ""
    update_badge_html = (
        '<span class="dial-badge dial-badge-update">Needs update</span>'
        if protocol_update else ""
    )

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
    ) if (online and (needs_update or needs_update_protocol)) else ""
    show_screen_btn = (
        '<button type="button" class="pill-btn small" style="width:100%;margin-top:0.75rem;"'
        ' data-dial-action="show-screen">Show dial screen</button>'
    ) if online else ""
    pin_btn_margin_top = "0.5rem" if (fw_update_btn or show_screen_btn) else "0.75rem"
    current_name_display = nv if nv else html.escape("(unnamed)")
    ip_html = (
        f'<div style="margin-top:0.25rem;font-size:0.8rem;color:var(--color-text-muted);">'
        f'IP: <span class="dial-current-ip">{html.escape(ip)}</span></div>'
    ) if (online and ip) else ""

    sd_method_options = "".join(
        f'<option value="{m}"{" selected" if m == "auto" else ""}>{m}</option>'
        for m in sorted(SDCARD_HEALTH_METHODS)
    )
    sd_health_row = (f"""
                  <div class="dial-sdhealth-row" style="margin-top:0.75rem;padding-top:0.5rem;border-top:1px solid var(--color-border-nav);">
                    <p style="margin:0 0 0.25rem;font-weight:600;">SD card health monitoring</p>
                    <p class="dial-sdhealth-status" style="margin:0 0 0.35rem;font-size:0.85em;">Loading...</p>
                    <div style="display:flex;align-items:center;gap:0.5rem;">
                      <select class="dial-sdhealth-method" disabled>{sd_method_options}</select>
                      <button type="button" class="pill-btn small dial-sdhealth-btn" style="flex:0 0 auto;"
                              data-dial-action="sdhealth-toggle" disabled>Enable</button>
                    </div>
                  </div>""") if sdmon else ""

    card_html = settings_card_html(f"""
          <div class="dial-card" data-dial-uuid="{su}"
               data-authorized="{'true' if authorized else 'false'}"
               data-online="{'true' if online else 'false'}"{data_new}{data_needs_update}
               data-pin-set="false">
            <div class="dial-card-top">
              <div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem;">
                <div>
                  <span class="dial-card-title">{title_text}</span>{fw_span}
                </div>
                <span style="display:flex;align-items:center;gap:0.35rem;">
                  <span class="dial-badge {badge_cls}">{badge_text}</span>
                  {recovery_badge_html}
                  {update_badge_html}
                </span>
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
            {ip_html}
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
                  <div class="dial-mute-all-row" style="display:none;align-items:center;gap:0.5rem;margin-top:0.5rem;">
                    <label class="output-toggle" style="margin:0;">
                      <input type="checkbox" class="dial-mute-all" data-dial-action="save-config" disabled>
                      <span class="switch"></span>
                    </label>
                    <span>Mute all playing devices</span>
                  </div>
                  <div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.5rem;">
                    <label class="output-toggle" style="margin:0;">
                      <input type="checkbox" class="dial-screen-fitted" data-dial-action="save-screen" disabled>
                      <span class="switch"></span>
                    </label>
                    <span>Has Screen Fitted</span>
                  </div>
                  <div class="dial-screen-rotate-row dial-screen-ctl-row" style="display:flex;align-items:center;gap:0.5rem;margin-top:0.5rem;">
                    <label class="output-toggle" style="margin:0;">
                      <input type="checkbox" class="dial-screen-rotate" data-dial-action="save-screen" disabled>
                      <span class="switch"></span>
                    </label>
                    <span>Rotate Screen</span>
                  </div>
                  <div class="dial-screen-bgr-row dial-screen-ctl-row" style="display:none;align-items:center;gap:0.5rem;margin-top:0.5rem;">
                    <label class="output-toggle" style="margin:0;">
                      <input type="checkbox" class="dial-screen-bgr" data-dial-action="save-screen" disabled>
                      <span class="switch"></span>
                    </label>
                    <span>Swap Red/Blue (BGR)</span>
                  </div>
                  <div class="dial-screen-type-row dial-screen-ctl-row" style="display:none;align-items:center;gap:0.5rem;margin-top:0.5rem;">
                    <span>Screen Type:</span>
                    <select class="dial-screen-type" data-dial-action="save-screen" disabled></select>
                  </div>
                  <p class="dial-screen-hd-note dial-screen-ctl-row" style="display:none;margin:0.25rem 0 0;font-size:0.85em;color:var(--color-text-secondary,#888);">Needs the HD kiosk install; see the HD dial guide.</p>
                  <div class="dial-screen-size-row dial-screen-ctl-row" style="display:none;align-items:center;gap:0.5rem;margin-top:0.5rem;">
                    <span>Screen Size (inches):</span>
                    <input type="number" class="dial-screen-size" step="0.1" min="0.5" max="20"
                           data-dial-action="save-screen" disabled style="width:5rem;">
                  </div>
                  <div class="dial-screen-layout-row dial-screen-ctl-row" style="display:none;align-items:center;gap:0.5rem;margin-top:0.5rem;">
                    <span>Layout Size:</span>
                    <select class="dial-screen-layout" data-dial-action="save-screen" disabled></select>
                  </div>
                  <p class="dial-screen-layout-note dial-screen-ctl-row" style="display:none;margin:0.25rem 0 0;font-size:0.85em;color:var(--color-text-secondary,#888);"></p>
                  <p class="dial-screen-touch-warning dial-screen-ctl-row" style="display:none;margin:0.25rem 0 0;font-size:0.85em;color:var(--color-warning,#c98a00);"></p>
                  <div class="dial-screen-touch-row dial-screen-ctl-row" style="display:none;align-items:center;gap:0.5rem;margin-top:0.5rem;">
                    <span>Touch Panel:</span>
                    <select class="dial-screen-touch" data-dial-action="save-screen" disabled></select>
                  </div>
                  <div class="dial-screen-brightness-row dial-screen-ctl-row" style="display:none;align-items:center;gap:0.5rem;margin-top:0.5rem;">
                    <span>Brightness:</span>
                    <input type="range" class="dial-screen-brightness" min="5" max="100" step="5"
                           data-dial-action="save-screen" disabled style="flex:1;min-width:0;">
                    <span class="dial-screen-brightness-val"></span>
                  </div>
                  <div class="dial-screen-sleep-row dial-screen-ctl-row" style="display:none;align-items:center;gap:0.5rem;margin-top:0.5rem;">
                    <span>Sleep after:</span>
                    <select class="dial-screen-sleep" data-dial-action="save-screen" disabled>
                      <option value="60">1 min</option>
                      <option value="300">5 min</option>
                      <option value="900">15 min</option>
                      <option value="0">Never</option>
                    </select>
                  </div>
                  <div class="dial-screen-panel-off-row" style="display:none;align-items:center;gap:0.5rem;margin-top:0.5rem;">
                    <label class="output-toggle" style="margin:0;">
                      <input type="checkbox" class="dial-screen-panel-off" data-dial-action="save-screen" disabled>
                      <span class="switch"></span>
                    </label>
                    <span>Switch the panel off when asleep</span>
                  </div>
                  <div class="dial-screen-controls-row dial-screen-ctl-row" style="display:none;align-items:center;gap:0.5rem;margin-top:0.5rem;">
                    <label class="output-toggle" style="margin:0;">
                      <input type="checkbox" class="dial-screen-always-controls" data-dial-action="save-screen" disabled>
                      <span class="switch"></span>
                    </label>
                    <span>Always show on-screen controls</span>
                  </div>
                  <div class="dial-screen-scope-row dial-screen-ctl-row" style="display:none;align-items:center;gap:0.5rem;margin-top:0.5rem;">
                    <span>Volume action:</span>
                    <select class="dial-volume-scope" data-dial-action="save-screen" disabled>
                      <option value="current">Current Appliance</option>
                      <option value="all">All Appliances</option>
                    </select>
                  </div>
                  <div class="dial-screen-scope-row dial-screen-ctl-row" style="display:none;align-items:center;gap:0.5rem;margin-top:0.5rem;">
                    <span>Mute action:</span>
                    <select class="dial-mute-scope" data-dial-action="save-screen" disabled>
                      <option value="current">Current Appliance</option>
                      <option value="all">All Appliances</option>
                    </select>
                  </div>
                  {sd_health_row}
                  <button type="button" class="pill-btn small" style="width:100%;margin-top:0.75rem;"
                          data-dial-action="change-pin">Change Dial PIN</button>
                </div>
              </div>
              {show_screen_btn}{fw_update_btn}
              <button type="button" class="pill-btn small" style="width:100%;margin-top:{pin_btn_margin_top};"
                      data-dial-action="recover-pin">Reset Lost PIN</button>
              <p class="dial-pin-no-confirm-msg" style="display:none;margin-top:0.5rem;font-size:0.85em;color:var(--color-text-secondary,#888);">
                This dial has no rotary control, button or touch panel, so a PIN could not be reset if forgotten.
              </p>
            </div>
            <div class="dial-card-msg" style="display:none;margin-top:0.5rem;"></div>
            <div class="dial-update-bar" style="display:none;" role="progressbar"
                 aria-valuemin="0" aria-valuemax="100"><div class="dial-update-bar-fill"></div></div>
          </div>
        """, margin_top="0")
    # Spacing between dial cards follows the setup list cards: a bottom margin
    # on each card rather than a top margin, so the first card still sits
    # flush under the panel header. settings_card_html only offers margin_top,
    # hence the wrapper — the card it emits is the bordered element that has
    # to carry the gap.
    return f'<div class="dial-card-wrap">{card_html}</div>'






# -----------------------------------------------------------------------------
# Page renderer
# -----------------------------------------------------------------------------


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


def _setup_factory_reset_html(auth) -> dict:
    """Factory Reset danger-zone card + its modal and reboot-modal siblings.

    Returns a dict since these pieces are consumed at different points in
    the surrounding page (the zone in the Factory Reset detail panel, the
    modals in the page's modal scaffolding). The modal's script and style
    are static files (setup_factory_reset.js, setup.css).
    """
    # Factory reset danger zone
    factory_reset_zone = ""
    factory_reset_modal = ""
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

    return {
        "zone": factory_reset_zone,
        "modal": factory_reset_modal,
        "reboot_modal": reboot_modal,
    }


def _setup_playback_defaults_card_html(parsed) -> str:
    """Playback panel -- "Default Speakers" / "Default Volume" card."""
    owntone_outputs_html = ""
    outputs_part = store().snapshot().outputs
    if outputs_part.connected:
        hidden = {str(n).strip().casefold() for n in (parsed.webui.hidden_outputs or ()) if str(n).strip()}
        for out in outputs_part.reported_rows():
            nm = str(out.name or "")
            if not nm:
                continue
            if nm.strip().casefold() in hidden and nm != parsed.owntone.output_name:
                continue
            sel = " selected" if nm == parsed.owntone.output_name else ""
            owntone_outputs_html += f"<option value='{html.escape(nm)}'{sel}>{html.escape(nm)}</option>"
    playback_defaults_inner_html = f"""
          <label>Default Speakers:
            <select id="owntone_output_select" name="owntone_output_name" onchange="refreshPlaybackCardSub(); if(liveEnabled) settingsSaveField('owntone.output_name', this.value);">
              {owntone_outputs_html}
            </select>
            <div id="owntone_output_hint" class="helptext" style="display:none;">
              Looking for speakers&hellip;
            </div>
          </label>
          <label><div class="slider-header"><span>Default Volume:</span><span id="vol_val">{parsed.owntone.volume_percent}%</span></div>
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
    _sil_pos = _silence_seconds_to_pos(parsed.general.silence_seconds)
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
    # autostream_webui_api.py) is the enforcement backstop for a stale
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


def _setup_network_card_html() -> str:
    """System & Updates panel -- Network card (informational, JS-populated)."""
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
    return settings_card_html(network_card_inner_html, margin_top="0.75rem")


def _setup_system_card_html(parsed, current_hostname: str, sd_health: dict) -> str:
    """System & Updates panel -- System card (hostname/PIN/mDNS grace/SD card health)."""
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
            {_setup_sdcard_health_row_html(sd_health)}
          </div>
        """
    system_card_html = settings_card_html(
        "<p style=\"margin:0 0 0.5rem;font-weight:700;\">System</p>"
        + system_card_inner_html,
        margin_top="0",
    )
    return system_card_html


def _setup_updates_card_html(parsed) -> str:
    """System & Updates panel -- Updates card."""
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
    updates_card_html = settings_card_html(
        "<p style=\"margin:0 0 0.5rem;font-weight:700;\">Updates</p>"
        + update_html,
        margin_top="0.75rem",
    )
    return updates_card_html


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
        if bt_enabled and parsed_input.capture_device == BLUETOOTH_LOOPBACK_HW:
            # Bluetooth input: the ALSA card name ("Loopback") and the
            # input type are implementation detail here \u2014 show the
            # connected device's name (or the connection state) instead.
            dev = "Bluetooth"
            mode = _bluetooth_input_fragment_text(bt_status)
        gain = int(parsed_input.gain_db)
        gain_str = f"{gain:+d} dB" if gain != 0 else "0 dB"
        return html.escape(f"{dev} \u00b7 {mode} \u00b7 {gain_str}")
    return _input_card_summary(parsed_input)


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
                onclick="openBtPairingModal(null, null)">Pair new device&hellip;</button>
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


def _setup_customise_card_html(parsed) -> str:
    """Personalisation detail-panel card."""
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
          </div>{_device_pause_row_html(parsed, store().snapshot().outputs)}
        """, margin_top="0")
    return customise_card_html


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


def _setup_dial_cards_html() -> tuple:
    """Dials detail-panel content. Returns (dial_cards_html, dials_summary)."""
    # Build dial cards data
    _all_sightings = _get_dial_sightings()
    _authorized_entries = parse_dial_entries()
    _sightings_by_uuid = {s.uuid: s for s in _all_sightings}
    _authorized_uuids = {e.uuid for e in _authorized_entries}
    _n_auth = len(_authorized_entries)
    _n_online = sum(1 for e in _authorized_entries if e.uuid in _sightings_by_uuid)
    _n_new = sum(1 for s in _all_sightings if s.uuid not in _authorized_uuids)
    _n_needs_update = sum(1 for s in _all_sightings if sighting_needs_update(s))
    if _n_auth == 0 and _n_new == 0:
        _dials_summary = "No dials"
    elif _n_auth == 0:
        _dials_summary = f"{_n_new} new"
    elif _n_new > 0:
        _dials_summary = f"{_n_auth} authorized · {_n_new} new"
    else:
        _dials_summary = f"{_n_auth} authorized" + (f" · {_n_online} online" if _n_online else "")
    if _n_needs_update:
        _dials_summary += f" · {_n_needs_update} need update"
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
        _pin_recovery = bool(_sighting.pin_recovery) if _sighting is not None else False
        _dial_cards_html += _dial_card_html(
            uuid=_entry.uuid,
            name=_name,
            authorized=True,
            online=_is_online,
            last_seen=_ls,
            fw_version=_fw,
            needs_update=_needs_upd,
            needs_update_protocol=bool(_sighting is not None and sighting_needs_update(_sighting)),
            pin_recovery=_pin_recovery,
            ip=(_sighting.ip if _sighting else ""),
            sdmon=bool(getattr(_sighting, "sdmon", False)) if _sighting is not None else False,
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
                needs_update_protocol=sighting_needs_update(_sighting),
                pin_recovery=bool(_sighting.pin_recovery),
                ip=_sighting.ip,
                sdmon=bool(getattr(_sighting, "sdmon", False)) if _sighting is not None else False,
            )
    if not _dial_cards_html:
        _dial_cards_html = (
            "<p style='color:var(--color-text-muted);font-style:italic;margin-top:0.5rem;'>"
            "No dials found on the network.</p>"
        )
    return _dial_cards_html, _dials_summary


# -----------------------------------------------------------------------------
# Card registry entries -- one summary/detail pair per card, each a thin
# ctx-parameterised wrapper around the existing per-card render function
# above. Registered in the same order the cards appear
# on the page today, matching send_setup_page()'s previous hand-sequenced
# list-row/panel order exactly.
# -----------------------------------------------------------------------------


def _card_summary_input1(ctx: SetupCtx) -> str:
    return _setup_input_summary_text(
        ctx.parsed.audio1,
        enabled=ctx.parsed.audio1_enabled,
        disabled_text="Not configured",
        monitor_devices=ctx.monitor_devices,
        bt_enabled=ctx.bt_enabled,
        bt_status=ctx.bt_status,
    )


def _card_detail_input1(ctx: SetupCtx) -> str:
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


def _card_summary_input2(ctx: SetupCtx) -> str:
    return _setup_input_summary_text(
        ctx.parsed.audio2,
        enabled=ctx.parsed.audio2_enabled,
        disabled_text="Disabled",
        monitor_devices=ctx.monitor_devices,
        bt_enabled=ctx.bt_enabled,
        bt_status=ctx.bt_status,
    )


def _card_detail_input2(ctx: SetupCtx) -> str:
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


def _card_summary_bluetooth(ctx: SetupCtx) -> str:
    return ctx.bt_card_summary


def _card_detail_bluetooth(ctx: SetupCtx) -> str:
    return _setup_bluetooth_card_html(
        bt_enabled=ctx.bt_enabled,
        bt_status=ctx.bt_status,
        bt_paired=ctx.bt_paired,
        bt_services_on=ctx.bt_services_on,
        bt_onboard_on=ctx.bt_onboard_on,
        bt_buffer_ms=ctx.bt_buffer_ms,
        bt_paired_row_text=ctx.bt_paired_row_text,
    )


def _card_summary_playback(ctx: SetupCtx) -> str:
    speaker = str(ctx.parsed.owntone.output_name or "No speaker selected")
    return html.escape(f"{speaker} · {ctx.parsed.owntone.volume_percent}%")


def _card_detail_playback(ctx: SetupCtx) -> str:
    return (
        _setup_playback_defaults_card_html(ctx.parsed)
        + _setup_silence_detection_card_html(ctx.parsed)
        + _setup_repeat_playback_card_html(ctx.parsed)
        + _setup_audio_processing_card_html(ctx.parsed)
        + _setup_owntone_more_settings_html(ctx.parsed)
    )


def _card_summary_track_id(ctx: SetupCtx) -> str:
    return html.escape("On" if ctx.parsed.track_identification.enabled else "Off")


def _card_detail_track_id(ctx: SetupCtx) -> str:
    return _setup_track_id_card_html(ctx.parsed)


def _card_summary_dials(ctx: SetupCtx) -> str:
    return ctx.dials_summary


def _card_detail_dials(ctx: SetupCtx) -> str:
    return ctx.dial_cards_html


def _card_summary_customise(ctx: SetupCtx) -> str:
    _ctrl_other_effective = ctx.parsed.webui.show_hostname_on_home and ctx.parsed.webui.control_other_appliances
    return html.escape(
        ("Master volume: On" if ctx.parsed.webui.show_master_volume else "Master volume: Off")
        + (" · Input detail: On" if ctx.parsed.webui.show_input_detail else " · Input detail: Off")
        + (" · Dark mode: On" if ctx.parsed.webui.dark_mode else " · Dark mode: Off")
        + (" · Hostname: On" if ctx.parsed.webui.show_hostname_on_home else " · Hostname: Off")
        + (" · Control others: On" if _ctrl_other_effective else " · Control others: Off")
        + (" · Peer control: On" if ctx.parsed.webui.advertise_appliance else " · Peer control: Off")
    )


def _card_detail_customise(ctx: SetupCtx) -> str:
    return _setup_customise_card_html(ctx.parsed)


def _card_summary_system(ctx: SetupCtx) -> str:
    _au_state = "Auto-update: On" if ctx.parsed.updates.auto_update else "Auto-update: Off"
    if ctx.parsed.updates.update_channel == "dev":
        _au_state += " - Pre-release channel"
    return html.escape(f"{ctx.current_hostname} · v{get_app_version()} · {_au_state}")


def _card_detail_system(ctx: SetupCtx) -> str:
    return (
        _setup_system_card_html(ctx.parsed, ctx.current_hostname, ctx.sd_health)
        + _setup_network_card_html()
        + _setup_updates_card_html(ctx.parsed)
    )


def _card_summary_factory_reset(ctx: SetupCtx) -> str:
    return "Erase all settings and return to Wi-Fi setup"


def _card_detail_factory_reset(ctx: SetupCtx) -> str:
    return ctx.factory_reset["zone"]


_register_card("input1", "Input 1", _card_summary_input1, _card_detail_input1, detail_header="Setup Input 1")
_register_card("input2", "Input 2", _card_summary_input2, _card_detail_input2, detail_header="Setup Input 2")
_register_card("bluetooth", "Bluetooth", _card_summary_bluetooth, _card_detail_bluetooth, detail_header="Bluetooth")
_register_card(
    "playback", "Playback", _card_summary_playback, _card_detail_playback,
    detail_header="Setup Playback Defaults",
)
_register_card(
    "track-id", "Track Identification", _card_summary_track_id, _card_detail_track_id,
    detail_header="Track Identification",
)
_register_card("dials", "Dials", _card_summary_dials, _card_detail_dials, detail_header="Dials")
_register_card(
    "customise", "Personalisation", _card_summary_customise, _card_detail_customise,
    detail_header="Personalisation",
)
_register_card(
    "system", "System", _card_summary_system, _card_detail_system,
    detail_header="System & Updates",
)
_register_card(
    "factory-reset", "Factory Reset", _card_summary_factory_reset, _card_detail_factory_reset,
    detail_header=None,
)


def send_setup_page(
    handler,
    state: WebUIState,
    auth,
    saved_ok: bool = False,
    error: Optional[str] = None,
    flash_msg: Optional[str] = None,
    flash_type: str = "success",
) -> None:
    """Render the main setup page.

    Composes the page from the ``CARDS`` registry -- every card's
    *summary* row is rendered eagerly (cheap), but detail-panel bodies are
    not inlined here. Each panel starts as an empty placeholder div
    that the browser fills in on first open via
    ``GET /api/setup/card/<key>`` (``handle_setup_card_get()`` above).
    """
    try:
        ctx = _setup_build_ctx(handler, state, auth)
    except Exception:
        try:
            handler.send_response(302)
            handler.send_header("Location", "/")
            handler.end_headers()
        except Exception:
            pass
        return

    parsed = ctx.parsed
    monitor_devices = ctx.monitor_devices
    bt_enabled = ctx.bt_enabled
    bt_status = ctx.bt_status
    bt_paired = ctx.bt_paired
    bt_services_on = ctx.bt_services_on
    bt_onboard_on = ctx.bt_onboard_on
    bt_buffer_ms = ctx.bt_buffer_ms
    bt_card_summary = ctx.bt_card_summary
    bt_paired_row_text = ctx.bt_paired_row_text
    sd_health = ctx.sd_health
    current_hostname = ctx.current_hostname

    h1 = "Setup"

    lic_html, lic_spacer = build_top_banner_html(flash_msg=flash_msg, flash_type=flash_type)
    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""
    csrf_meta = f"<meta name='csrf-token' content='{html.escape(csrf_token)}'><script>window.__CSRF='{html.escape(csrf_token)}';</script>" + static.script_tag("page/csrf_recovery.js")
    factory_reset_modal = ctx.factory_reset["modal"]
    reboot_modal = ctx.factory_reset["reboot_modal"]

    _app_ver = get_app_version()

    # Every card's collapsed summary row is rendered eagerly
    # (cheap -- no detail-panel HTML is built for cards the user hasn't
    # opened); each panel starts as an empty body placeholder filled in by
    # the browser's lazy `GET /api/setup/card/<key>` fetch on first open.
    list_rows_html = "".join(
        _setup_list_row_html(card, card.render_summary(ctx)) for card in CARDS
    )
    panel_shells_html = "".join(_setup_panel_shell_html(card) for card in CARDS)

    form_content_html = f"""<div class="setup-slide-viewport">
  <div class="setup-slide-track" id="setupSlideTrack">
    <div class="setup-slide-list">
      {_setup_page_header("Setup")}
      <div id="autosave-status" aria-live="polite" style="font-size:0.85rem;color:var(--color-text-dim);min-height:1.2em;margin-bottom:0.25rem;"></div>
      {list_rows_html}
    </div>
    <div class="setup-slide-panels">
      {panel_shells_html}
    </div>
  </div>
</div>"""

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
    _sd_health_modal_div = """\
<div id="sdHealthModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="sdHealthModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="sdHealthModalTitle">SD Card Health Check</div>
    <div class="bd modal-bd">
      <p id="sdHealthModalMsg"></p>
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-secondary" id="sdHealthModalCancel"
        onclick="hideSdHealthModal()">Cancel</button>
      <button type="button" class="btn modal-btn modal-btn-primary" id="sdHealthModalOk"
        onclick="confirmSdHealthEnable()">Continue</button>
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
    _dial_result_modal_div = """\
<div id="dialResultModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="dialResultModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="dialResultModalTitle">Dial</div>
    <div class="bd modal-bd">
      <p id="dialResultModalMsg"></p>
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-primary" id="dialResultModalOk">OK</button>
    </div>
  </div>
</div>"""
    _dial_panel_off_modal_div = """\
<div id="dialPanelOffModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="dialPanelOffModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="dialPanelOffModalTitle">Switch the panel off when asleep</div>
    <div class="bd modal-bd">
      <p>Please test sleep with your panel; some panels may be damaged by extended periods powered-down</p>
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-secondary" id="dialPanelOffCancel">Cancel</button>
      <button type="button" class="btn modal-btn modal-btn-primary" id="dialPanelOffOk">Continue</button>
    </div>
  </div>
</div>"""
    _dial_screen_modal_div = """\
<div id="dialScreenModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="dialScreenModalTitle">
  <div class="panel modal-panel" style="--modal-width:44rem;">
    <div class="hdr modal-hdr" id="dialScreenModalTitle">Dial screen</div>
    <div class="bd modal-bd" style="text-align:center;">
      <p id="dialScreenModalMsg" style="color:var(--color-text-muted);"></p>
      <img id="dialScreenModalImg" alt="Current dial screen"
           style="display:none;max-width:100%;height:auto;image-rendering:pixelated;border:1px solid #000;border-radius:8px;">
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-secondary" id="dialScreenModalRefresh">Refresh</button>
      <button type="button" class="btn modal-btn modal-btn-primary" id="dialScreenModalClose">Close</button>
    </div>
  </div>
</div>"""
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
      <div id="dialPinRecoveryConfirmPanel">
        <p id="dialPinRecoveryConfirmMsg">This feature can be used to reset a lost PIN. Continue?</p>
      </div>
      <div id="dialPinRecoveryWaitPanel" style="display:none;">
        <p id="dialPinRecoveryWaitMsg">To reset the Dial PIN, start by power-cycling the Dial now. Once it restarts, you have 10 minutes to confirm you are at the device.</p>
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
      <button type="button" class="btn modal-btn modal-btn-primary" id="dialPinRecoveryOk" disabled>Waiting for Dial&hellip;</button>
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
          <p class="bt-scan-empty">Scanning&hellip;</p>
        </div>
      </div>
      <div id="btConfirmPanel" style="display:none;">
        <p>Pair with <strong id="btConfirmDeviceName"></strong>?</p>
        <p id="btConfirmWarning" style="display:none;color:var(--color-status-danger);font-weight:600;"></p>
      </div>
      <div id="btPairingPanel" style="display:none;">
        <p id="btPairingStatusMsg">Pairing&hellip;</p>
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
        f"{factory_reset_modal}\n{reboot_modal}\n{_pin_modal_div}\n{_sd_health_modal_div}\n{_hostname_modal_div}\n"
        f"{_dial_pin_modal_div}\n{_dial_pin_recovery_modal_div}\n{_dial_name_modal_div}\n{_dial_result_modal_div}\n"
        f"{_dial_panel_off_modal_div}\n{_dial_screen_modal_div}\n{_wifi_hotspot_modal_div}\n"
        f"{_bt_pairing_modal_div}\n"
        f"{INFO_MODAL_HTML}"
    )
    _body_html = (
        (f"<p style='color:var(--color-status-success);'>Saved</p>" if saved_ok else "")
        + (f"<p style='color:var(--color-status-danger);'>{html.escape(error)}</p>" if error else "")
        + form_content_html
    )
    _script_files = [
        "a2hs.js", "autosave.js", "info_modal.js",
        "setup_controls.js", "setup_outputs.js", "setup_panels.js", "setup_dials.js", "setup_network.js",
        "setup_factory_reset.js",
    ]
    if bt_enabled:
        _script_files.append("setup_bt_pairing.js")
    _script_files.append("setup_bt_card.js")
    _body_suffix = "\n".join(static.script_tag(f"page/{name}") for name in _script_files)
    # The values the scripts read at load; the files themselves are the same on every page.
    _island = static.page_data_island({
        "app_version": _app_ver,
        "icons": {"padlock_locked": ICON_PADLOCK_LOCKED, "padlock_unlocked": ICON_PADLOCK_UNLOCKED},
        "bt_loopback_hw": BLUETOOTH_LOOPBACK_HW,
        "bt_paired": bool(bt_paired),
        "bt_link_state": str((bt_status or {}).get("link") or "disconnected"),
        "bt_services_enabled": bool(bt_services_on),
        "bt_onboard_enabled": bool(bt_onboard_on),
        "bt_status": bt_status if isinstance(bt_status, dict) else None,
        "bt_ui_text": _bluetooth_input_fragment_text(bt_status),
        "sd_health": sd_health,
    })
    _poll_js_src = static.script_tag("poll.js")
    html_body = build_page_html(
        "autostream",
        _body_html,
        style_files=("page/modal.css", "page/setup.css"),
        head_extra=csrf_meta + _island + _poll_js_src,
        body_prefix=_body_prefix,
        body_suffix=_body_suffix,
        lic_html=lic_html,
        lic_spacer=lic_spacer,
        show_nav=True,
        active_tab="setup",
        dark_mode=parsed.webui.dark_mode,
    )
    send_html(handler, 200, html_body)
