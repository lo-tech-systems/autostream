#!/usr/bin/env python3
"""webui/browser/setup/cards_dials.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The Dials card of the Setup page.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from autostream_dials import parse_dial_entries, sighting_needs_update
from autostream_sysutils import SDCARD_HEALTH_METHODS
from autostream_webui_assets import ICON_PADLOCK_LOCKED
from autostream_webui_common import settings_card_html
import autostream_webui_common
from webui.browser.setup import context

try:
    from autostream_dials import get_all_sightings as _get_dial_sightings
except ImportError:
    def _get_dial_sightings() -> list:  # type: ignore[misc]
        return []


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
    _app_ver = autostream_webui_common.get_app_version()
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


def summary_dials(ctx: context.SetupCtx) -> str:
    return ctx.dials_summary


def detail_dials(ctx: context.SetupCtx) -> str:
    return ctx.dial_cards_html
