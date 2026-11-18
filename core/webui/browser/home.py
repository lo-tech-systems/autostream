#!/usr/bin/env python3
"""webui/browser/home.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Renderer for the main AirPlay control page (/).
"""

from __future__ import annotations

import html
import json
import logging

from typing import Optional

from autostream_appliances import get_all_appliances
from autostream_state import store
from autostream_state.live import get_setting
from autostream_players import SETTING_START_BUFFER_MS, SETTING_START_BUFFER_MS_DEFAULT
import autostream_rpi as rpi
from autostream_sysutils import get_system_hostname, reboot_system
from webui.components import slider_html
from webui.protocol import hub as hub_module
from webui.protocol.state import state_json
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
    build_appliance_selector_html,
    build_page_html,
    build_top_banner_html,
)
from webui.session_state import WebUIState
from webui import common
from webui import session_state
import re
from webui.browser import equaliser


# Wall-clock tolerance, in seconds, for transient emptiness of the backend's
# reported outputs list (for example while a stereo pair is reforming, the
# device list can briefly shrink to zero before settling back). Both the
# local page poll and the remote/proxy home-state poll debounce an observed
# empty-outputs state against this tolerance before clearing the displayed
# output cards and showing the "no outputs" placeholder. Not exposed via any
# UI or settings surface.
OUTPUTS_EMPTY_TOLERANCE_SECONDS = 6.0


# Stylesheets both Home renderers link: the shared modal and selector styles and
# the Home page's own rules.
_HOME_PAGE_STYLE_FILES = ("page/modal.css", "page/appliance_selector.css", "page/home.css")


def _build_appliances_for_selector() -> list:
    """Return the bound-first appliance list suitable for the selector widget.

    Format matches the /api/appliances JSON response so the same JS update
    function works for both server-rendered initial state and polled updates.
    """
    local_id = rpi.get_appliance_id() or ""
    hostname = str(get_system_hostname() or "").strip()
    if hostname.lower().endswith(".local"):
        hostname = hostname[:-6]
    bound = {
        "id": local_id,
        "hostname": hostname.strip() or "autostream",
        "is_bound": True,
        "home_path": "/",
        "equaliser_path": "/equaliser",
    }
    peers = get_all_appliances()
    result = [bound]
    for s in peers:
        if s.id == local_id:
            continue
        result.append({
            "id": s.id,
            "hostname": s.hostname or "autostream",
            "is_bound": False,
            "home_path": f"/a/{s.id}/",
            "equaliser_path": f"/a/{s.id}/equaliser",
        })
    return result


def _state_for_island() -> dict:
    """The state body the page starts from: the hub's cached one, else one
    built from the store (no hub yet)."""
    hub = hub_module.current()
    if hub is not None:
        try:
            return json.loads(hub.state_body())
        except Exception:
            logging.warning("home: the hub's state body is unreadable", exc_info=True)
    return state_json(store().snapshot(), clients=0)


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
    flash_msg: Optional[str] = None,
    flash_type: str = "success",
) -> None:
    """Render the main AirPlay control page: the shell the browser fills from
    the state it starts with and the change stream (the page-data island)."""
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
    show_input_detail = parsed.webui.show_input_detail
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

    lic_html, lic_spacer = build_top_banner_html(flash_msg=flash_msg, flash_type=flash_type)
    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""
    preset_volume = max(0, min(100, int(parsed.owntone.volume_percent or 20)))
    _local_id = str(rpi.get_appliance_id() or "")
    if show_hostname_on_home:
        _top_right_html = build_appliance_selector_html(
            _build_appliances_for_selector(), _local_id, "home",
            display_only=not effective_control,
        )
    else:
        _top_right_html = ""
    csrf_meta = (
        f"<meta name='csrf-token' content='{html.escape(csrf_token)}'>"
        f"<script>window.__CSRF='{html.escape(csrf_token)}';</script>"
    ) + static.script_tag("page/csrf_recovery.js")

    _island = static.page_data_island({
        "state": _state_for_island(),
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

    # Master volume wrapper embedded inside the Now Playing card.
    _np_vol_html = (
        '<div class="np-volume-wrap master-volume-inactive" id="master-volume-card">'
        '<div class="slider-header"><span>Master Volume</span></div>'
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
    _autostart_html = (
        '<div class="autostart-row"><button id="autostart-pin" class="icon-btn" type="button"'
        ' aria-label="Auto-Start these speakers" aria-pressed="false" hidden>'
        f'{_PIN_ICON}</button></div>'
    )
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
        "autostream",
        _body_html,
        style_files=_HOME_PAGE_STYLE_FILES,
        head_extra=_head_extra,
        body_prefix=_body_prefix,
        body_suffix=static.script_tag("page/a2hs.js") + static.script_tag("page/banner_dismiss.js"),
        lic_html=lic_html,
        lic_spacer=lic_spacer,
        active_tab="home",
        dark_mode=parsed.webui.dark_mode,
    )
    try:
        common.send_html(handler, 200, html_body)
    except Exception:
        logging.exception("Failed sending airplay page response.")


# ---------------------------------------------------------------------------
# Remote Home page — /a/<appliance_id>/
# ---------------------------------------------------------------------------

def send_remote_home_page(handler, state: WebUIState, appliance_id: str) -> None:
    """Render the remote Home shell for a remote appliance.

    Serves a client-side polling shell. JavaScript fetches
    /api/appliances/<id>/home every 3 seconds and updates the DOM.
    Output mutations go to /api/appliances/<id>/output via the gateway.
    After 3 consecutive transport failures the browser returns to /.
    Definitive resolution errors (not_found, etc.) return immediately to /.
    """
    try:
        parsed = common._config_snapshot(state)
    except Exception:
        try:
            handler.send_error(500, "Configuration unavailable")
        except Exception:
            pass
        return

    csrf_token = getattr(handler, "_csrf_token", None) or ""
    preset_volume = max(0, min(100, int(parsed.owntone.volume_percent or 20)))
    dark_mode = parsed.webui.dark_mode
    effective_control = parsed.webui.show_hostname_on_home and parsed.webui.control_other_appliances

    appliances = _build_appliances_for_selector()
    _local_id = str(rpi.get_appliance_id() or "")

    poll_url = f"/api/appliances/{appliance_id}/home"
    output_url = f"/api/appliances/{appliance_id}/output"
    repeat_url = f"/api/appliances/{appliance_id}/repeat"

    _selector_html = build_appliance_selector_html(appliances, appliance_id, "home")

    # Resolve remote hostname for page title and JS failure messages
    _remote_hostname = "autostream"
    for a in appliances:
        if a.get("id") == appliance_id:
            _remote_hostname = str(a.get("hostname") or "autostream")
            break
    if _remote_hostname.lower().endswith(".local"):
        _remote_hostname = _remote_hostname[:-6]

    _warn_style_base = (
        "padding:0.85rem 0.9rem;border-radius:12px;"
        "border:1px solid var(--color-status-danger);"
        "background:var(--color-surface-raised);"
        "color:var(--color-text);font-size:0.99rem;"
        "text-align:center;text-decoration:none;"
    )

    _island = static.page_data_island({
        "preset_volume": preset_volume,
        "show_input_detail": False,
        "vu_delay_ms": 2250,
        "icons": {
            "turntable": ICON_TURNTABLE,
            "bluetooth": ICON_BLUETOOTH,
            "cd": ICON_CD,
            "line_level": ICON_LINE_LEVEL,
        },
        "local_id": _local_id,
        "selector_current_id": appliance_id,
        "output_url": output_url,
        "repeat_url": repeat_url,
        "outputs_empty_tolerance_ms": int(OUTPUTS_EMPTY_TOLERANCE_SECONDS * 1000),
        "pin_prompt_fallback": "Enter PIN",
        "control_other_appliances": bool(effective_control),
        "remote_aid": appliance_id,
        "remote_hostname": _remote_hostname,
        "poll_url": poll_url,
    })

    _head_extra = (
        f"<meta name='csrf-token' content='{html.escape(csrf_token)}'>"
        f"<script>window.__CSRF='{html.escape(csrf_token)}';</script>"
        + static.script_tag("page/csrf_recovery.js")
        + _island
        + "\n"
        + static.script_tag("render_fragments.js") + "\n"
        + static.script_tag("page/home_cards.js")
        + static.script_tag("page/appliance_selector.js")
        + static.script_tag("page/info_modal.js")
        + static.script_tag("page/start_failure.js")
        + static.script_tag("page/remote_home.js")
    )

    _body_prefix = """
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
</div>""" + INFO_MODAL_HTML

    _np_icon_svg = ICON_LINE_LEVEL

    # Repeat control -- same small pill-style button as the local page, but
    # hidden until the polled home feed's "repeat" block confirms the remote
    # appliance actually has the feature enabled (updateRepeatButton, shared
    # via home_cards.js, un-hides it from renderHomeState). An older
    # remote appliance that never reports a "repeat" block simply leaves the
    # pill hidden -- no error shown. Navigation back to the bound appliance
    # is via the logo (BANNER_LOGO_HTML links to "/"), so this slot no longer
    # needs a dedicated "Home" button.
    _repeat_btn_html = (
        '<button type="button" class="pill-btn small repeat-btn" id="repeat-btn"'
        ' data-state="off" disabled hidden'
        ' onclick="onRepeatButtonClick()">&#8635; Repeat Play</button>'
    )

    _top_controls_html = (
        f"<div class='airplay-top-controls'>"
        f"{_repeat_btn_html}"
        f"{_selector_html}"
        f"</div>"
    )

    _now_playing_card_html = (
        f'<div class="now-playing-card np-ready" id="now-playing-card">'
        f'<div class="now-playing-hdr" id="np-hdr">Ready · {html.escape(_remote_hostname)}</div>'
        f'<div class="now-playing-body">'
        f'<div class="now-playing-icon" id="np-icon" data-np-icon-key="svg:line">'
        f'{_np_icon_svg}'
        f'</div>'
        f'<div class="now-playing-meta">'
        f'<div class="now-playing-name" id="np-name">Connecting&hellip;</div>'
        f'<div class="now-playing-signal" id="np-signal"></div>'
        f'</div>'
        f'<div class="np-level" id="np-level"></div>'
        f'</div>'
        f'<div class="np-volume-wrap master-volume-inactive" id="master-volume-card" hidden>'
        f'<div class="slider-header"><span>Master Volume</span></div>'
        + slider_html(
            id="master_vol_slider",
            value=preset_volume,
            disabled=True,
            extra_attrs=(
                ' oninput="onMasterVolumeInput(this.value)"'
                ' onchange="onMasterVolumeChange(this.value)"'
                ' onmousedown="onMasterVolumeDragStart()"'
                ' ontouchstart="onMasterVolumeDragStart()"'
            ),
        )
        + f'</div>'
        f'</div>'
    )

    _body_html = (
        f"<div class='airplay-masthead'><div class='airplay-brand'>{BANNER_LOGO_HTML}</div></div>"
        + _top_controls_html
        + _now_playing_card_html
        + f"<a id='stylus-warning-banner' href='#'"
        f" style='display:none;margin:0.85rem 0 0.35rem;{_warn_style_base}'></a>"
        + f"<a id='belt-warning-banner' href='#'"
        f" style='display:none;margin:0.35rem 0 0.35rem;{_warn_style_base}'></a>"
        + f"<a id='bearing-warning-banner' href='#'"
        f" style='display:none;margin:0.35rem 0 0.35rem;{_warn_style_base}'></a>"
        + f"<p id='outputs-placeholder' style='text-align:center;"
        f"color:var(--color-text-muted,#888);padding:1.5rem 0;margin:0;'>"
        f"Connecting&hellip;</p>"
        + f"<div id='outputs-list'></div>"
    )

    html_body = build_page_html(
        f"autostream — {html.escape(_remote_hostname)}",
        _body_html,
        style_files=_HOME_PAGE_STYLE_FILES,
        head_extra=_head_extra,
        body_prefix=_body_prefix,
        body_suffix=static.script_tag("page/a2hs.js") + static.script_tag("page/banner_dismiss.js"),
        active_tab="home",
        dark_mode=dark_mode,
        remote_id=appliance_id,
    )
    try:
        common.send_html(handler, 200, html_body)
    except Exception:
        logging.exception("Failed sending remote home page response.")


# -----------------------------------------------------------------------------
# Route-table adapters: the calling convention the dispatcher uses (handler,
# state[, body]) in front of the senders above.
# -----------------------------------------------------------------------------


_REMOTE_PAGE_PREFIX = "/a/"
_APPLIANCE_ID_RE = re.compile(r"^[0-9a-f]{20}$")


def _route_get_home(handler, state):
    msg, flash_type = common._route_flash_msg_and_type(handler)
    send_airplay_page(handler, state, session_state.AUTH, flash_msg=msg, flash_type=flash_type)


def _route_get_remote_page(handler, state):
    path = handler._normalized_path()
    tail = path[len(_REMOTE_PAGE_PREFIX):]
    parts = tail.split("/", 1)
    aid = parts[0]
    sub = parts[1] if len(parts) > 1 else ""
    if not _APPLIANCE_ID_RE.match(aid):
        handler.send_error(404, "Not found")
        return
    local_id = rpi.get_appliance_id() or ""
    if aid == local_id:
        # Canonical redirect for bound appliance
        location = "/equaliser" if sub == "equaliser" else "/"
        handler.send_response(302)
        handler.send_header("Location", location)
        handler.send_header("Content-Length", "0")
        handler.end_headers()
    elif not common._effective_control_other_appliances(state):
        handler._redirect_with_error_flash("Controlling other appliances is disabled.", "/")
    elif sub == "equaliser":
        equaliser.send_remote_equaliser_page(handler, state, aid)
    else:
        send_remote_home_page(handler, state, aid)
