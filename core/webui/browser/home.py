#!/usr/bin/env python3
"""webui/browser/home.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Renderer for the main AirPlay control page (/).
"""

from __future__ import annotations

import html
import logging

from typing import Optional

from autostream_appliances import resolve
from autostream_state.live import get_setting
from autostream_players import SETTING_START_BUFFER_MS, SETTING_START_BUFFER_MS_DEFAULT
import autostream_appliance_identity as identity
from autostream_sysutils import get_system_hostname, reboot_system
from webui.components import slider_html
from webui.protocol.state import state_for_page
from webui import static
from webui.assets import (
    A2HS_PROMPT_HTML,
    BANNER_LOGO_HTML,
    ICON_BLUETOOTH,
    ICON_CD,
    ICON_LINE_LEVEL,
    ICON_TURNTABLE,
    INFO_MODAL_HTML,
)
from webui.common import (
    appliance_selector_entries,
    build_appliance_selector_html,
    build_page_html,
    build_top_banner_html,
)
from webui.session_state import WebUIState
from webui import common
from webui import session_state
import re
from webui.browser import equaliser
from webui.peer import relay


# Stylesheets both Home renderers link: the shared modal and selector styles and
# the Home page's own rules.
_HOME_PAGE_STYLE_FILES = ("page/modal.css", "page/appliance_selector.css", "page/home.css")


_PIN_ICON = (
    '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor"'
    ' stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round" aria-hidden="true">'
    '<path d="M15 4.5V9c0 1.7 1.3 3 3 3v1.5H6V12c1.7 0 3-1.3 3-3V4.5H8V3h8v1.5z"/>'
    '<path d="M12 13.5V21"/></svg>'
)

_AUTO_START_MODAL = """
<div id="autoStartModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="autoStartModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="autoStartModalTitle">Auto-Start</div>
    <div class="bd modal-bd"><p id="autoStartText"></p></div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-secondary" id="autoStartCancel">Cancel</button>
      <button type="button" class="btn modal-btn modal-btn-primary" id="autoStartYes">Yes</button>
    </div>
  </div>
</div>"""

_PIN_MODAL = """
<div id="pinModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="pinModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="pinModalTitle">Enter PIN</div>
    <div class="bd modal-bd">
      <p>Enter the PIN shown on your Apple TV (or other AirPlay device) to enable playback.</p>
      <input id="pinModalInput" inputmode="numeric" autocomplete="one-time-code" placeholder="PIN" pattern="[0-9]*" maxlength="8" />
      <div id="pinModalNote" class="modal-note" hidden></div>
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-secondary" id="pinModalCancel">Cancel</button>
      <button type="button" class="btn modal-btn modal-btn-primary" id="pinModalOk">OK</button>
    </div>
  </div>
</div>"""


def send_airplay_page(
    handler,
    state: WebUIState,
    auth,
    error: Optional[str] = None,
    peer=None,
) -> None:
    """Render the main AirPlay control page: the shell the browser fills from
    the state it starts with and the change stream (the page-data island).
    With *peer* (an appliance.resolve result for another appliance) the shell
    is that appliance's: its state, and the relay's routes as its base."""
    try:
        parsed = common._config_snapshot(state)
    except Exception:
        # If we're here something bad happened - user should have been redirected to the setup page
        # if the INI is missing. Hence, take the nuclear option and inform the user that something
        # went wrong - then reboot the system. This code serves only inline code in case the file
        # system is dead (which is likely). Reboot may therefore also fail.
        #
        # This page deliberately does not go through build_page_html()/the shared
        # extra_css channel: it must still render something
        # readable if the filesystem itself is failing, so it cannot depend on the
        # shared theme.css asset or any other autostream module state.
        body = (
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>System Error</title>"
            "<style>body{font-family:system-ui,sans-serif;margin:2rem;}</style>"
            "</head><body>"
            "<h1>System Error</h1>"
            "<p>Unfortunately, an unrecoverable error has occurred: "
            "autostream was unable to read the configuration file.</p>"
            "<p><strong>autostream will now try to reboot.</strong></p>"
            "<p>Please check back in a few minutes. If the system does not recover, "
            "please power-cycle autostream and try again. If the problem persists, "
            "please replace the SD card and reinstall autostream.</p>"
            "</body></html>"
        )

        # Best-effort response; never prevent reboot.
        try:
            common.send_html(handler, 500, body)
            try:
                handler.wfile.flush()
            except Exception:
                pass
        except Exception:
            pass

        # Best-effort log; never prevent reboot.
        try:
            logging.error(
                "Config load error, rebooting system",
                exc_info=True
            )
        except Exception:
            pass
        reboot_system(reason="UserRequestSystemError")
        return

    owntone_base_url = parsed.owntone.base_url
    show_master_volume = parsed.webui.show_master_volume
    show_input_detail = parsed.webui.show_input_detail and peer is None
    show_hostname_on_home = parsed.webui.show_hostname_on_home
    effective_control = show_hostname_on_home and parsed.webui.control_other_appliances

    # Fetch the OwnTone start-buffer setting so the VU meter can be aligned to
    # the AirPlay playback delay.  Fall back to the default if OwnTone is
    # unreachable (e.g. still starting) or if the backend does not support it.
    try:
        _buf_result = get_setting(owntone_base_url, SETTING_START_BUFFER_MS, timeout=1)
        vu_delay_ms = int(_buf_result.value) if _buf_result.ok else SETTING_START_BUFFER_MS_DEFAULT
    except Exception:
        vu_delay_ms = SETTING_START_BUFFER_MS_DEFAULT

    snap = peer.client.snapshot() if peer is not None else None
    if snap is None:
        lic_html, lic_spacer = build_top_banner_html()
    else:
        lic_html, lic_spacer = build_top_banner_html(entries=(snap.parts.get("warnings") or {}).get("entries") or [])
    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""
    preset_volume = max(0, min(100, int(parsed.owntone.volume_percent or 20)))
    _local_id = str(identity.get_appliance_id() or "")
    _selector = appliance_selector_entries(_local_id, get_system_hostname())
    if peer is not None:
        _top_right_html = build_appliance_selector_html(_selector, peer.sighting.id, "home")
    elif show_hostname_on_home:
        _top_right_html = build_appliance_selector_html(
            _selector, _local_id, "home", display_only=not effective_control)
    else:
        _top_right_html = ""
    csrf_meta = (
        f"<meta name='csrf-token' content='{html.escape(csrf_token)}'>"
        f"<script>window.__CSRF='{html.escape(csrf_token)}';</script>"
    ) + static.script_tag("page/csrf_recovery.js")

    _island = static.page_data_island({
        "state": state_for_page() if peer is None else relay.state_body(snap),
        "base": "/api/v1" if peer is None else f"/api/v1/peers/{peer.sighting.id}",
        "own": peer is None,
        "selector": _selector,
        "csrf": csrf_token,
        "prefs": {
            "show_master_volume": bool(show_master_volume),
            "show_input_detail": bool(show_input_detail),
            "preset_volume": preset_volume,
            "vu_delay_ms": int(vu_delay_ms),
            "control_other_appliances": bool(effective_control),
        },
        "icons": {
            "turntable": ICON_TURNTABLE,
            "bluetooth": ICON_BLUETOOTH,
            "cd": ICON_CD,
            "line_level": ICON_LINE_LEVEL,
        },
        "local_id": _local_id,
    })
    _head_extra = (
        csrf_meta
        + _island
        + "\n"
        + static.script_tag("page/info_modal.js")
        + static.module_tag("page/home/home_main.js")
    )
    _body_prefix = _PIN_MODAL + INFO_MODAL_HTML + _AUTO_START_MODAL

    # Repeat control: a small pill-style button, shown by the page when the
    # state says the feature is enabled.
    _repeat_btn_html = (
        '<button type="button" class="pill-btn small repeat-btn" id="repeat-btn"'
        ' data-state="off" disabled hidden>&#8635; Repeat Play</button>'
    )
    _top_controls_html = f"<div class='airplay-top-controls'>{_repeat_btn_html}{_top_right_html}</div>"

    # The Auto-Start pin: in the Master Volume header when that is shown,
    # otherwise in a row of its own above the speaker list.
    _autostart_pin_html = (
        '<button id="autostart-pin" class="icon-btn" type="button"'
        ' aria-label="Auto-Start these speakers" aria-pressed="false" hidden>'
        f'{_PIN_ICON}</button>'
    )

    # Master volume wrapper embedded inside the Now Playing card.
    _np_vol_html = (
        '<div class="np-volume-wrap master-volume-inactive" id="master-volume-card">'
        f'<div class="slider-header"><span>Master Volume</span>{_autostart_pin_html}</div>'
        + slider_html(id="master_vol_slider", value=preset_volume, disabled=True)
        + '</div>'
    ) if show_master_volume else ""
    _vu_bar_html = '<div class="vu-bar"></div>' * 7
    _vu_meter_html = (
        '<div class="vu-meter" id="np-vu" aria-hidden="true">'
        f'<div class="vu-col" id="np-vu-l">{_vu_bar_html}</div>'
        f'<div class="vu-col" id="np-vu-r">{_vu_bar_html}</div>'
        '</div>'
    ) if show_input_detail else ""
    _now_playing_card_html = (
        '<div class="now-playing-card np-ready" id="now-playing-card">'
        '<div class="now-playing-hdr" id="np-hdr">Ready</div>'
        '<div class="now-playing-body">'
        '<div class="now-playing-icon" id="np-icon"></div>'
        '<div class="now-playing-meta">'
        '<div class="now-playing-name" id="np-name"></div>'
        '<div class="now-playing-signal" id="np-signal"></div>'
        '</div>'
        f'<div class="np-level" id="np-level">{_vu_meter_html}</div>'
        '</div>'
        f'{_np_vol_html}'
        '</div>'
    )
    _autostart_html = "" if show_master_volume else f'<div class="autostart-row">{_autostart_pin_html}</div>'
    _body_html = (
        f"<div class='airplay-masthead'><div class='airplay-brand'>{BANNER_LOGO_HTML}</div></div>"
        + _top_controls_html
        + "<div id='warnings-strip' hidden></div>"
        + _now_playing_card_html
        + _autostart_html
        + "<p id='outputs-placeholder' hidden"
        " style='text-align:center;color:var(--color-text-muted,#888);padding:1.5rem 0;margin:0;'></p>"
        + A2HS_PROMPT_HTML
        + "<div id='outputs-list'></div>"
    )
    html_body = build_page_html(
        "autostream" if peer is None else "autostream — " + peer.sighting.hostname,
        _body_html,
        style_files=_HOME_PAGE_STYLE_FILES,
        head_extra=_head_extra,
        body_prefix=_body_prefix,
        body_suffix=static.script_tag("page/a2hs.js"),
        lic_html=lic_html,
        lic_spacer=lic_spacer,
        active_tab="home",
        service_severity=common.service_severity() if peer is None else None,
        dark_mode=parsed.webui.dark_mode,
        remote_id="" if peer is None else peer.sighting.id,
    )
    try:
        common.send_html(handler, 200, html_body)
    except Exception:
        logging.exception("Failed sending airplay page response.")


# -----------------------------------------------------------------------------
# Route-table adapters: the calling convention the dispatcher uses (handler,
# state[, body]) in front of the senders above.
# -----------------------------------------------------------------------------


_REMOTE_PAGE_PREFIX = "/a/"
_APPLIANCE_ID_RE = re.compile(r"^[0-9a-f]{20}$")


def _route_get_home(handler, state):
    send_airplay_page(handler, state, session_state.AUTH)


def _redirect(handler, location: str) -> None:
    handler.send_response(302)
    handler.send_header("Location", location)
    handler.send_header("Content-Length", "0")
    handler.end_headers()


def _route_get_remote_page(handler, state):
    path = handler._normalized_path()
    tail = path[len(_REMOTE_PAGE_PREFIX):]
    parts = tail.split("/", 1)
    aid = parts[0]
    sub = parts[1] if len(parts) > 1 else ""
    if not _APPLIANCE_ID_RE.match(aid):
        handler.send_error(404, "Not found")
        return
    local_id = identity.get_appliance_id() or ""
    if aid == local_id:
        # Canonical redirect for bound appliance
        _redirect(handler, "/equaliser" if sub == "equaliser" else "/")
    elif not common._effective_control_other_appliances(state):
        _redirect(handler, "/")
    else:
        peer = resolve(aid)
        if peer.kind != "remote" or not peer.client.snapshot().protocol_ok or peer.client.snapshot().boot is None:
            _redirect(handler, "/")
        elif sub == "equaliser":
            equaliser.send_equaliser_page(handler, state, peer=peer)
        else:
            send_airplay_page(handler, state, session_state.AUTH, peer=peer)
