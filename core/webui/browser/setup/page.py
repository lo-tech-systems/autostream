#!/usr/bin/env python3
"""webui/browser/setup/page.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The Setup page (/setup): the card registrations, the lazy per-card detail fetch and
the page renderer.

Importing this module fills the card registry, so anything that reads the
registry through it sees every card (the Input 3 card is registered on every
appliance and shown only where Bluetooth is installed).
"""

from __future__ import annotations

import html
import logging
from typing import Optional

from autostream_config import BLUETOOTH_INPUT_INDEX, INPUT_INDICES
from autostream_state import MISSING_RATE_TEXTS
from webui.assets import ICON_PADLOCK_LOCKED, ICON_PADLOCK_UNLOCKED, INFO_MODAL_HTML
from webui import static
from webui.common import build_page_html, build_top_banner_html
from webui import session_state
from webui.session_state import WebUIState
from webui.browser.setup import (
    cards_bluetooth,
    cards_customise,
    cards_dials,
    cards_factory_reset,
    cards_inputs,
    cards_playback,
    cards_system,
    cards_track_id,
    context,
)
from webui import common
from webui.system import updates


def handle_setup_card_get(handler, state: WebUIState, auth, key: str) -> None:
    """`GET /api/setup/card/<key>` -- the lazy per-card detail fetch.

    Same FULL auth + commissioning gating as `/setup` itself (see the
    route table registration); this handler only has to worry about the
    card key itself once dispatch() has already let the request through.
    """
    card = next((c for c in context.CARDS if c.key == key), None)
    if card is None:
        common.send_json(handler, 404, {"ok": False, "error": "unknown_card"})
        return
    try:
        ctx = context._setup_build_ctx(handler, state, auth)
    except Exception:
        logging.exception("handle_setup_card_get: failed to build setup context for card %r", key)
        common.send_json(handler, 200, {"ok": False, "error": "config_error"})
        return
    if not card.is_present(ctx):
        common.send_json(handler, 404, {"ok": False, "error": "unknown_card"})
        return
    common.send_json(handler, 200, {"ok": True, "html": card.render_detail(ctx)})


# -----------------------------------------------------------------------------
# Card registry entries -- one summary/detail pair per card, each a thin
# ctx-parameterised wrapper in its card module around the per-card render
# functions. Registered in the order the cards appear on the page.
# -----------------------------------------------------------------------------


for _index in INPUT_INDICES:
    cards_inputs.register_input_card(_index)
context.register_card(
    "playback", "Playback", cards_playback.summary_playback, cards_playback.detail_playback,
    detail_header="Setup Playback Defaults",
)
context.register_card(
    "track-id", "Track Identification", cards_track_id.summary_track_id, cards_track_id.detail_track_id,
    detail_header="Track Identification",
)
context.register_card("dials", "Dials", cards_dials.summary_dials, cards_dials.detail_dials, detail_header="Dials")
context.register_card(
    "customise", "Personalisation", cards_customise.summary_customise, cards_customise.detail_customise,
    detail_header="Personalisation",
)
context.register_card(
    "system", "System", cards_system.summary_system, cards_system.detail_system,
    detail_header="System & Updates",
)
context.register_card(
    "factory-reset", "Factory Reset", cards_factory_reset.summary_factory_reset, cards_factory_reset.detail_factory_reset,
    detail_header=None,
)


def send_setup_page(
    handler,
    state: WebUIState,
    auth,
    saved_ok: bool = False,
    error: Optional[str] = None,
) -> None:
    """Render the main setup page.

    Composes the page from the ``CARDS`` registry -- every card's
    *summary* row is rendered eagerly (cheap), but detail-panel bodies are
    not inlined here. Each panel starts as an empty placeholder div
    that the browser fills in on first open via
    ``GET /api/setup/card/<key>`` (``handle_setup_card_get()`` above).
    """
    try:
        ctx = context._setup_build_ctx(handler, state, auth)
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
    bt_paired_row_text = ctx.bt_paired_row_text
    sd_health = ctx.sd_health
    current_hostname = ctx.current_hostname

    h1 = "Setup"

    lic_html, lic_spacer = build_top_banner_html()
    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""
    csrf_meta = f"<meta name='csrf-token' content='{html.escape(csrf_token)}'><script>window.__CSRF='{html.escape(csrf_token)}';</script>" + static.script_tag("page/csrf_recovery.js")
    factory_reset_modal = ctx.factory_reset["modal"]
    reboot_modal = ctx.factory_reset["reboot_modal"]

    _app_ver = updates.get_app_version()

    # Every card's collapsed summary row is rendered eagerly
    # (cheap -- no detail-panel HTML is built for cards the user hasn't
    # opened); each panel starts as an empty body placeholder filled in by
    # the browser's lazy `GET /api/setup/card/<key>` fetch on first open.
    cards = context.present_cards(ctx)
    list_rows_html = "".join(
        context._setup_list_row_html(card, card.render_summary(ctx)) for card in cards
    )
    panel_shells_html = "".join(context._setup_panel_shell_html(card) for card in cards)

    form_content_html = f"""<div class="setup-slide-viewport">
  <div class="setup-slide-track" id="setupSlideTrack">
    <div class="setup-slide-list">
      {context._setup_page_header("Setup")}
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
<div id="btServicesModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="btServicesModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="btServicesModalTitle">Bluetooth</div>
    <div class="bd modal-bd">
      <p id="btServicesModalMsg"></p>
      <p id="btServicesModalNote" class="helptext" style="display:none;text-align:left;"></p>
      <p id="btServicesModalError" style="display:none;color:var(--color-status-danger);font-weight:600;"></p>
    </div>
    <div class="ft modal-ft" id="btServicesModalFt">
      <button type="button" class="btn modal-btn modal-btn-secondary" id="btServicesCancel">Cancel</button>
      <button type="button" class="btn modal-btn modal-btn-primary" id="btServicesOk">Enable</button>
    </div>
  </div>
</div>
""" + """\
<div id="btPairingModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="btPairingModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="btPairingModalTitle">Pair a device</div>
    <div class="bd modal-bd">
      <div id="btWindowPanel">
        <p>Put your device in pairing mode. It will appear below when autostream finds it
          or when it tries to connect.</p>
        <p id="btWindowCountdown" class="bt-window-countdown"></p>
        <div id="btWindowDeviceList" class="bt-device-list">
          <p class="bt-scan-empty">Searching&hellip;</p>
        </div>
        <p id="btWindowError" style="display:none;color:var(--color-status-danger);font-weight:600;"></p>
      </div>
      <div id="btResultPanel" style="display:none;">
        <p id="btResultMsg"></p>
        <p id="btResultError" style="display:none;color:var(--color-status-danger);font-weight:600;"></p>
      </div>
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-secondary" id="btPairingForget" style="display:none;">Forget</button>
      <button type="button" class="btn modal-btn modal-btn-secondary" id="btPairingCancel">Cancel</button>
      <button type="button" class="btn modal-btn modal-btn-primary" id="btPairingOk" style="display:none;">Pair this device</button>
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
        "setup_controls.js", "setup_panels.js", "setup_dials.js", "setup_network.js",
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
        # The inputs whose cards are on this page, and the form field names
        # that predate the numbering scheme, for the scripts' inputField().
        "input_indices": cards_inputs.present_input_indices(ctx),
        "bluetooth_input_index": BLUETOOTH_INPUT_INDEX,
        "legacy_input_fields": cards_inputs.LEGACY_INPUT_FIELDS_JSON,
        "input_disabled_text": cards_inputs.DISABLED_SUMMARY_JSON,
        "bt_paired": bool(bt_paired),
        "bt_link_state": str((bt_status or {}).get("link") or "disconnected"),
        "bt_services_enabled": bool(bt_services_on),
        "bt_onboard_enabled": bool(bt_onboard_on),
        "bt_memory_note": ctx.bt_memory_note,
        "bt_status": bt_status if isinstance(bt_status, dict) else None,
        "bt_ui_text": cards_bluetooth._bluetooth_input_fragment_text(bt_status),
        "sd_health": sd_health,
        "missing_rate_texts": list(MISSING_RATE_TEXTS),
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
    common.send_html(handler, 200, html_body)


# -----------------------------------------------------------------------------
# Route-table adapters: the calling convention the dispatcher uses (handler,
# state[, body]) in front of the senders above.
# -----------------------------------------------------------------------------


def _route_get_setup(handler, state):
    send_setup_page(handler, state, session_state.AUTH)


def _route_get_setup_card(handler, state):
    key = handler._normalized_path().rsplit("/", 1)[-1]
    handle_setup_card_get(handler, state, session_state.AUTH, key)
