#!/usr/bin/env python3
"""webui/browser/setup/cards_system.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The System card of the Setup page: network, system and updates.
"""

from __future__ import annotations

import html

from autostream_players import (
    SETTING_DEVICE_REMOVAL_GRACE_PERIOD_DEFAULT_MINUTES,
    SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MAX_MINUTES,
    SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MIN_MINUTES,
)
from webui.common import settings_card_html
from webui.browser.setup import cards_bluetooth, context
from webui.system import updates


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
            {cards_bluetooth._setup_sdcard_health_row_html(sd_health)}
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


def summary_system(ctx: context.SetupCtx) -> str:
    _au_state = "Auto-update: On" if ctx.parsed.updates.auto_update else "Auto-update: Off"
    if ctx.parsed.updates.update_channel == "dev":
        _au_state += " - Pre-release channel"
    return html.escape(f"{ctx.current_hostname} · v{updates.get_app_version()} · {_au_state}")


def detail_system(ctx: context.SetupCtx) -> str:
    return (
        _setup_system_card_html(ctx.parsed, ctx.current_hostname, ctx.sd_health)
        + _setup_network_card_html()
        + _setup_updates_card_html(ctx.parsed)
    )
