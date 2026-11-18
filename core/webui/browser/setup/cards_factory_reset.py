#!/usr/bin/env python3
"""webui/browser/setup/cards_factory_reset.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The Factory Reset card of the Setup page: the danger zone, its modal and the
reboot modal.
"""

from __future__ import annotations

import html

from autostream_sysutils import get_ap_ssid
from webui.browser.setup import context


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


def summary_factory_reset(ctx: context.SetupCtx) -> str:
    return "Erase all settings and return to Wi-Fi setup"


def detail_factory_reset(ctx: context.SetupCtx) -> str:
    return ctx.factory_reset["zone"]
