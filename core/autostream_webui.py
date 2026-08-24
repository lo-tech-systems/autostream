#!/usr/bin/env python3
"""autostream_webui.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Front-end for autostream. This script will start autostream_core.py and should be used to
start autostream.

Listens on 127.0.0.1:8080. NGINX is recommended (as a reverse proxy) to provide access to the webui
on the network generally e.g. on port 80.

Usage:

# python3 autostream_webui.py /location/to/autostream.json

"""

from __future__ import annotations

import html
import logging
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse, unquote, quote
import json

# When executed as a script (the appliance entrypoint) this module is
# registered in sys.modules as "__main__" only. A later
# `import autostream_webui` — autostream_webui_routes.dispatch() does this at
# request time to resolve AUTH/STATE/handlers patch-friendly — would load a
# SECOND copy of this module whose AUTH/STATE globals are never set, and every
# dispatched request would crash on AUTH=None (found live on-appliance;
# invisible to tests, which import this module by name). Alias the running
# module under its import name, before any project import can recurse into us,
# so both routes resolve to the same module object.
if __name__ == "__main__":
    sys.modules.setdefault("autostream_webui", sys.modules[__name__])

from autostream_core import (
    get_available_monitor_devices,
    run_autostream,
    stop_flag,
)

from autostream_bluetooth_client import BluetoothClient, bluetooth_installed

from autostream_sysutils import (
    reboot_system,
)

from autostream_webui_assets import (
    LICENSE_BANNER_CSS,
    BANNER_HTML,
)

from autostream_auth import AuthManager, parse_cookie_header, FLASH_COOKIE_NAME

from autostream_webui_state import WebUIState
from autostream_webui_api import (
    run_updater,
    send_audio_status_json,
    send_browser_api_error,
    send_dial_mute_post_json,
    send_dial_status_post_json,
    send_dial_volume_post_json,
    send_federation_eq_config_json,
    send_federation_eq_reset_json,
    send_federation_eq_status_json,
    send_federation_equaliser_json,
    send_federation_home_json,
    send_federation_output_json,
    send_federation_repeat_json,
    send_federation_session_json,
    send_json,
    send_output_eq_config_json,
    send_output_eq_reset_json,
    send_output_eq_status_json,
    send_owntone_outputs_json,
    send_owntone_outputs_state_json,
    send_service_config_json,
    send_service_reset_json,
    send_advertisement_post_json,
    send_auto_update_post_json,
    send_hostname_post_json,
    send_settings_mdns_grace_period_json,
    send_save_now_json,
    send_settings_get_json,
    send_settings_post_json,
    send_status_json,
    send_update_check_json,
    send_update_status_json,
    send_owntone_output_visibility_json,
    send_owntone_output_mode_json,
    send_owntone_output_offset_json,
    send_owntone_uncompressed_json,
    send_owntone_buffered_audio_json,
    send_owntone_start_buffer_json,
    send_owntone_user_agent_json,
    send_owntone_grace_period_json,
    send_log_level_get_json,
    send_log_level_put_json,
    send_network_setup_json,
    send_network_status_json,
    send_network_roaming_json,
    send_playing_status_json,
    send_repeat_post_json,
    send_bluetooth_status_json,
    send_bluetooth_scan_results_json,
    send_bluetooth_pair_status_json,
    send_bluetooth_scan_post_json,
    send_bluetooth_pair_post_json,
    send_bluetooth_forget_post_json,
    send_bluetooth_services_post_json,
    send_bluetooth_onboard_post_json,
    send_bluetooth_buffer_post_json,
)
import autostream_federation
from autostream_webui_dials import (
    dispatch_dial_management_post,
    handle_dial_configure_get,
    handle_dial_pin_recovery_status,
    handle_dial_screen_settings_get,
    handle_dial_screen_settings_post,
    handle_dial_update_post,
    handle_dial_update_status,
)
from autostream_webui_common import build_nav_bar_html, send_html
from autostream_webui_routes import (
    dispatch as _route_dispatch,
    is_poll_log as _route_is_poll_log,
    _read_and_parse_body as _route_read_and_parse_body,
)
from autostream_webui_page_about import send_about_page, send_about_system_json
from autostream_webui_page_align import (
    send_align_abort_json,
    send_align_apply_json,
    send_align_discard_json,
    send_align_page,
    send_align_result_get,
    send_align_start_json,
    send_align_status_json,
)
from autostream_webui_page_equaliser import send_equaliser_page, send_remote_equaliser_page
from autostream_webui_page_airplay import send_airplay_page, send_remote_home_page
from autostream_webui_page_logs import handle_logs_download, send_logs_page
from autostream_webui_page_owntone import (
    send_owntone_ready_json,
    send_owntone_restarting_page,
    send_owntone_setup_page,
)
from autostream_webui_page_first_boot import (
    send_first_boot_owntone_page,
    send_first_boot_appliance_page,
    handle_first_boot_continue_post,
    handle_first_boot_finish_post,
)
from autostream_webui_page_rebooting import send_rebooting_page
from autostream_webui_page_service import send_service_page
from autostream_webui_page_setup import handle_setup_card_get, send_setup_page
from autostream_webui_post_handlers import (
    handle_factory_reset_post,
    handle_live_input_eq_update,
    handle_live_input_gain_update,
    handle_output_update,
    handle_setup_post,
)

from autostream_config import STATE_PATH
from autostream_commissioning import is_commissioning_required, required_first_boot_step
from autostream_rpi import get_appliance_id
from autostream_appliance_gateway import (
    send_appliances_json,
    send_gateway_eq_config_json,
    send_gateway_eq_reset_json,
    send_gateway_eq_status_json,
    send_gateway_equaliser_json,
    send_gateway_home_json,
    send_gateway_output_json,
    send_gateway_repeat_json,
)

_FEDERATION_PREFIX = "/api/federation/v1"
_GATEWAY_PREFIX = "/api/appliances"
_REMOTE_PAGE_PREFIX = "/a/"
_APPLIANCE_ID_RE = re.compile(r"^[0-9a-f]{20}$")
_FEDERATION_BODY_MAX = 4096  # bytes

# High-frequency polling endpoints. Access-log lines for these are demoted to
# DEBUG (see ConfigWebHandler.log_message) since they dominate the resting
# INFO log volume without carrying diagnostic value.
#
# All of these polling paths (/api/status, /api/audio/status,
# /api/owntone/outputs_state, /api/owntone/outputs, /api/network/status,
# /api/appliances, /api/playing-status, GET /api/log-level) are now
# declared poll_log=True on their route-table entries instead (PUT
# /api/log-level stays poll_log=False, preserving the GET-only demotion
# the method check below used to implement). This tuple is empty now;
# log_message() falls back to routes_mod.is_poll_log() for every path.
_POLLING_LOG_PATHS: tuple = ()


def _settings_save_barrier(state) -> bool:
    """Flush dirty SettingsStore to disk before a destructive operation.

    Returns True if save succeeded.
    Returns False if the store exists and save_now() failed or timed out.
    If no SettingsStore is attached, logs an error and allows the action to
    proceed; this indicates a program wiring fault rather than a user- or
    network-facing risk.
    """
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if not isinstance(settings, _SettingsStore):
        import logging as _logging
        _logging.error("_settings_save_barrier: no SettingsStore attached; skipping flush")
        return True
    return settings.save_now()


def _effective_control_other_appliances(state) -> bool:
    """Return True if this appliance is configured to allow controlling other appliances.

    Fails open (returns True) on any config read error so a misconfiguration
    never inadvertently locks out functionality.
    """
    try:
        from autostream_webui_common import _config_snapshot
        parsed = _config_snapshot(state)
        return parsed.webui.show_hostname_on_home and parsed.webui.control_other_appliances
    except Exception:
        return True


# -----------------------------------------------------------------------------
# Route-table GET adapters
# -----------------------------------------------------------------------------
#
# autostream_webui_routes.dispatch() calls every GET handler as
# fn(handler, STATE) -- matching the sender functions whose signature is
# already exactly that. The senders below need something else (the module
# AUTH singleton, the flash message/type, the raw query string), so each
# gets a thin same-signature adapter here instead of dispatch() growing a
# per-route calling convention. Kept together, one route each, so ROUTES'
# handler names stay greppable back to their real sender.


def _route_flash_msg_and_type(handler) -> tuple:
    """Reproduces do_GET's former shared flash-message preamble for a
    single migrated page route: msg from ?msg=, else the one-shot flash
    cookie (consumed on read). Only used by routes that used to fall
    within do_GET's cookie-consuming branch (i.e. not /owntone-restarting
    and not any /api/* path) -- see that former preamble's comment, now
    only reachable for the handful of legacy paths still in do_GET's
    elif chain.
    """
    query = urlparse(handler.path).query
    qs = parse_qs(query)
    msg = (qs.get("msg") or [""])[0]
    flash_type = "success"
    if msg:
        colon = msg.find(":")
        if colon > 0 and msg[:colon] in ("error", "warning"):
            flash_type = msg[:colon]
            msg = msg[colon + 1:]
    if not msg:
        cookies = parse_cookie_header(handler.headers.get("Cookie"))
        raw = cookies.get(FLASH_COOKIE_NAME, "")
        if raw:
            try:
                decoded = unquote(raw)
            except Exception:
                decoded = raw
            colon = decoded.find(":")
            if colon > 0 and decoded[:colon] in ("error", "warning"):
                flash_type = decoded[:colon]
                msg = decoded[colon + 1:]
            else:
                msg = decoded
            clear_cookie = f"{FLASH_COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
            pending = getattr(handler, "_pending_set_cookies", None)
            if pending is None:
                handler._pending_set_cookies = [clear_cookie]
            else:
                pending.append(clear_cookie)
    return msg, flash_type


def _route_get_home(handler, state):
    msg, flash_type = _route_flash_msg_and_type(handler)
    send_airplay_page(handler, state, AUTH, flash_msg=msg, flash_type=flash_type)


def _route_get_equaliser(handler, state):
    msg, flash_type = _route_flash_msg_and_type(handler)
    send_equaliser_page(handler, state, flash_msg=msg, flash_type=flash_type)


def _route_get_service(handler, state):
    msg, flash_type = _route_flash_msg_and_type(handler)
    send_service_page(handler, state, flash_msg=msg, flash_type=flash_type)


def _route_get_setup(handler, state):
    msg, _flash_type = _route_flash_msg_and_type(handler)
    send_setup_page(handler, state, AUTH, flash_msg=msg)


def _route_get_setup_card(handler, state):
    key = handler._normalized_path().rsplit("/", 1)[-1]
    handle_setup_card_get(handler, state, AUTH, key)


def _route_get_logs(handler, state):
    msg, _flash_type = _route_flash_msg_and_type(handler)
    send_logs_page(handler, state, flash_msg=msg)


def _route_get_owntone_setup(handler, state):
    msg, _flash_type = _route_flash_msg_and_type(handler)
    send_owntone_setup_page(handler, state, AUTH, flash_msg=msg)


def _route_get_align_result(handler, state):
    # self.path, not a normalized path: the measurement payload arrives in
    # the query string and must survive a login round-trip (dispatch()'s
    # kind="page" redirect already uses handler.path for the same reason).
    qs = parse_qs(urlparse(handler.path).query)
    send_align_result_get(handler, state, qs)


def _route_get_rebooting(handler, state):
    send_rebooting_page(handler, state, AUTH)


def _route_get_about_system(handler, state):
    send_about_system_json(handler)


def _route_get_output_eq_status(handler, state):
    send_output_eq_status_json(handler)


def _route_get_network_status(handler, state):
    send_network_status_json(handler)


def _route_get_bluetooth_scan_results(handler, state):
    send_bluetooth_scan_results_json(handler)


def _route_get_update_status(handler, state):
    send_update_status_json(handler)


# -----------------------------------------------------------------------------
# Route-table POST adapters
# -----------------------------------------------------------------------------
#
# dispatch() calls every POST/PUT handler as fn(handler, STATE, body_str).
# Most senders already match that signature exactly and are
# registered directly by name below with no adapter. The ones here don't:
# either their sender takes json_obj (already parsed by do_POST) instead of
# body_str, takes no body at all, needs an extra arg (AUTH), or has
# route-specific pre/post logic that used to live inline in the do_POST elif
# arm itself (the settings-save barrier ahead of /api/reboot and
# /api/update/apply).


def _route_post_json_obj(handler):
    """The JSON body object already parsed by do_POST's shared body-parse
    step (stashed on the handler as ``_parsed_body`` for dispatch()'s
    duration -- see dispatch()'s and do_POST's own comments), for adapters
    whose sender takes json_obj rather than body_str. Falls back to None if
    no cached parse is present (a caller invoking dispatch() directly
    without pre-populating _parsed_body, e.g. a test).
    """
    cached = getattr(handler, "_parsed_body", None)
    if cached is not None:
        return cached[2]
    return None


def _route_post_settings(handler, state, body_str):
    # Legacy inline check (do_POST's former /api/settings arm): unlike the
    # generic requires_body gate (which only rejects an *empty* body), this
    # route requires the body to have parsed as a JSON object -- a
    # form-urlencoded body (json_obj stays None) is rejected too.
    json_obj = _route_post_json_obj(handler)
    if not isinstance(json_obj, dict):
        handler.send_error(400, "JSON object required")
        return
    send_settings_post_json(handler, state, json_obj)


def _route_post_settings_save(handler, state, body_str):
    send_save_now_json(handler, state)


def _route_post_output_eq_reset(handler, state, body_str):
    send_output_eq_reset_json(handler, state)


def _route_post_align_abort(handler, state, body_str):
    send_align_abort_json(handler, state)


def _route_post_align_discard(handler, state, body_str):
    send_align_discard_json(handler, state)


def _route_post_network_setup(handler, state, body_str):
    send_network_setup_json(handler, _route_post_json_obj(handler))


def _route_post_network_roaming(handler, state, body_str):
    send_network_roaming_json(handler, _route_post_json_obj(handler))


def _route_post_bluetooth_scan(handler, state, body_str):
    send_bluetooth_scan_post_json(handler, _route_post_json_obj(handler))


def _route_post_bluetooth_pair(handler, state, body_str):
    send_bluetooth_pair_post_json(handler, _route_post_json_obj(handler))


def _route_post_bluetooth_forget(handler, state, body_str):
    send_bluetooth_forget_post_json(handler)


def _route_post_bluetooth_services(handler, state, body_str):
    send_bluetooth_services_post_json(handler, _route_post_json_obj(handler))


def _route_post_bluetooth_onboard(handler, state, body_str):
    send_bluetooth_onboard_post_json(handler, _route_post_json_obj(handler))


def _route_post_bluetooth_buffer(handler, state, body_str):
    send_bluetooth_buffer_post_json(handler, _route_post_json_obj(handler))


def _route_post_update_apply(handler, state, body_str):
    # Legacy inline pre-logic (do_POST's former /api/update/apply arm):
    # flush dirty settings to disk before staging an update.
    if not _settings_save_barrier(state):
        send_json(handler, 200, {"ok": False, "error": "Settings could not be saved before update"})
        return
    handler._start_update_apply()


def _route_post_reboot(handler, state, body_str):
    # Legacy inline pre-logic (do_POST's former /api/reboot arm): flush
    # dirty settings to disk before rebooting, then trigger the reboot
    # (delayed 3s so this response can flush first) and reply immediately.
    if not _settings_save_barrier(state):
        send_json(handler, 200, {"ok": False, "error": "Settings could not be saved before reboot"})
        return
    reboot_system("UserRequestNormal", delay_s=3)
    send_json(handler, 200, {"ok": True})


def _route_post_factory_reset(handler, state, body_str):
    handle_factory_reset_post(handler, state, AUTH)


# -----------------------------------------------------------------------------
# Route-table adapters -- special schemes + stateful routes
# -----------------------------------------------------------------------------
#
# Non-browser-scheme handlers (see Route.scheme) are always called as
# fn(handler, STATE) -- dispatch() does no body pre-parsing for them, so any
# adapter that needs the request body reads it itself, reproducing (not
# sharing) do_GET/do_POST/do_PUT's former inline logic for that exact path,
# since in every case here the legacy call site ran ahead of one or more
# checks the generic parse performs (see each adapter's own comment).

# --- Federation (bearer) ----------------------------------------------------


def _route_get_federation(handler, state):
    handler._dispatch_federation("GET", handler._normalized_path())


def _route_post_federation(handler, state):
    # Reproduces do_POST's former universal body-read (steps 2-3) up to and
    # including the "Invalid JSON" check -- but NOT the later "JSON object
    # required" non-dict-body check (do_POST's own former federation branch
    # returned before ever reaching that check, so a federation POST never
    # saw it either). _dispatch_federation only consumes body_str; any
    # further JSON validation (e.g. POST /session's own isinstance check)
    # stays inside it, unchanged.
    body_bytes = handler._read_post_body_bytes()
    if body_bytes is None:
        return  # error already sent
    try:
        body_str = body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        handler.send_error(400, "Request body is not valid UTF-8")
        return
    content_type = (handler.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
    if body_str and content_type == "application/json":
        try:
            json.loads(body_str)
        except json.JSONDecodeError:
            handler.send_error(400, "Invalid JSON")
            return
    handler._dispatch_federation("POST", handler._normalized_path(), body_str)


# --- Dial-device protocol (dial) --------------------------------------------


def _route_dial_parse_json_obj(handler, *, reject_non_dict: bool):
    """Body read + JSON parse for the UUID-auth dial endpoints, reproducing
    do_POST's former universal body-read (steps 2-3) plus the dial-specific
    guard that used to run just ahead of the volume/mute/status branches.
    Returns a dict (parsed object, or {} if the body wasn't a JSON object
    and rejection wasn't requested), or None if an error response was
    already sent.
    """
    body_bytes = handler._read_post_body_bytes()
    if body_bytes is None:
        return None
    try:
        body_str = body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        handler.send_error(400, "Request body is not valid UTF-8")
        return None
    content_type = (handler.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
    json_obj = None
    if body_str and content_type == "application/json":
        try:
            json_obj = json.loads(body_str)
        except json.JSONDecodeError:
            handler.send_error(400, "Invalid JSON")
            return None
        if reject_non_dict and not isinstance(json_obj, dict):
            handler.send_error(400, "JSON object required")
            return None
    return json_obj if isinstance(json_obj, dict) else {}


def _route_post_dial_volume(handler, state):
    json_obj = _route_dial_parse_json_obj(handler, reject_non_dict=True)
    if json_obj is None:
        return
    send_dial_volume_post_json(handler, state, json_obj)


def _route_post_dial_mute(handler, state):
    json_obj = _route_dial_parse_json_obj(handler, reject_non_dict=True)
    if json_obj is None:
        return
    send_dial_mute_post_json(handler, state, json_obj)


def _route_post_dial_status(handler, state):
    json_obj = _route_dial_parse_json_obj(handler, reject_non_dict=False)
    send_dial_status_post_json(handler, state, json_obj)


# --- Loopback-aware fast paths ----------------------------------------------


def _route_commissioning_redirect_get(handler, state):
    step = required_first_boot_step(state.config_path, state.state_path)
    location = f"/first-boot/{step}" if step else "/first-boot/owntone"
    handler.send_response(302)
    handler.send_header("Location", location)
    handler.end_headers()


def _route_get_playing_status(handler, state):
    if handler._is_direct_local():
        send_playing_status_json(handler)
        return
    # Proxied caller: reproduce the commissioning gate and the general "gate
    # protected pages" redirect-to-auth check that a proxied request used to
    # fall through to (this path is not in AUTH.ALLOWLIST_PATHS).
    if handler._commissioning_required():
        _route_commissioning_redirect_get(handler, state)
        return
    if AUTH.requires_auth("/api/playing-status") and not AUTH.is_authenticated(handler.headers):
        AUTH.redirect_to_auth(handler, next_path=handler.path)
        return
    handler._csrf_token = AUTH.ensure_session(handler)
    send_playing_status_json(handler)


def _route_get_log_level(handler, state):
    if handler._is_direct_local():
        send_log_level_get_json(handler, state)
        return
    # Proxied caller: reproduce the commissioning gate. No auth gate --
    # "/api/log-level" is in AUTH.ALLOWLIST_PATHS, so requires_auth() is
    # always False for it.
    if handler._commissioning_required():
        _route_commissioning_redirect_get(handler, state)
        return
    handler._csrf_token = AUTH.ensure_session(handler)
    send_log_level_get_json(handler, state)


def _route_put_log_level(handler, state):
    # Reproduces do_PUT verbatim: its own bespoke body-read (Content-Type
    # must be application/json -> 415, distinct from every other route's
    # parse), no commissioning gate at all, and CSRF-only (no PIN) for a
    # proxied caller.
    body_bytes = handler._read_post_body_bytes()
    if body_bytes is None:
        return
    try:
        body_str = body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        handler.send_error(400, "Request body is not valid UTF-8")
        return

    ct = (handler.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
    if ct != "application/json":
        handler.send_error(415, "Content-Type must be application/json")
        return

    if not body_str:
        handler.send_error(400, "Missing request body")
        return

    try:
        json_obj = json.loads(body_str)
    except json.JSONDecodeError:
        handler.send_error(400, "Invalid JSON")
        return

    if not isinstance(json_obj, dict):
        handler.send_error(400, "JSON object required")
        return

    if handler._is_direct_local():
        send_log_level_put_json(handler, state, json_obj, "system")
        return

    csrf_token = handler._extract_csrf_token(None, json_obj)
    if not AUTH.validate_csrf(handler, csrf_token):
        send_browser_api_error(handler, 403, "CSRF validation failed")
        return

    send_log_level_put_json(handler, state, json_obj, "user")


# --- Gateway (browser session surface) --------------------------------------


def _route_get_appliances_list(handler, state):
    send_appliances_json(handler, state)


def _route_get_gateway_sub(handler, state):
    path = handler._normalized_path()
    tail = path[len(_GATEWAY_PREFIX) + 1:]  # strip "/api/appliances/"
    parts = tail.split("/", 1)
    aid = parts[0]
    sub = parts[1] if len(parts) > 1 else ""
    local_id = get_appliance_id() or ""
    if aid != local_id and not _effective_control_other_appliances(state):
        send_json(handler, 403, {"ok": False, "error": "control_disabled"})
    elif sub == "home":
        send_gateway_home_json(handler, state, aid)
    elif sub == "equaliser":
        send_gateway_equaliser_json(handler, state, aid)
    elif sub == "equaliser/status":
        send_gateway_eq_status_json(handler, state, aid)
    else:
        handler.send_error(404, "Not found")


def _route_post_gateway(handler, state, body_str):
    path = handler._normalized_path()
    tail = path[len(_GATEWAY_PREFIX) + 1:]
    parts = tail.split("/", 1)
    aid = parts[0]
    sub = parts[1] if len(parts) > 1 else ""
    local_id = get_appliance_id() or ""
    if aid != local_id and not _effective_control_other_appliances(state):
        send_json(handler, 403, {"ok": False, "error": "control_disabled"})
    elif sub == "output":
        if not body_str:
            handler.send_error(400, "Missing request body")
            return
        send_gateway_output_json(handler, state, aid, body_str)
    elif sub == "equaliser/config":
        if not body_str:
            handler.send_error(400, "Missing request body")
            return
        send_gateway_eq_config_json(handler, state, aid, body_str)
    elif sub == "equaliser/reset":
        send_gateway_eq_reset_json(handler, state, aid)
    elif sub == "repeat":
        if not body_str:
            handler.send_error(400, "Missing request body")
            return
        send_gateway_repeat_json(handler, state, aid, body_str)
    else:
        handler.send_error(404, "Not found")


# --- Remote pages -------------------------------------------------------------


def _route_get_remote_page(handler, state):
    path = handler._normalized_path()
    tail = path[len(_REMOTE_PAGE_PREFIX):]
    parts = tail.split("/", 1)
    aid = parts[0]
    sub = parts[1] if len(parts) > 1 else ""
    if not _APPLIANCE_ID_RE.match(aid):
        handler.send_error(404, "Not found")
        return
    local_id = get_appliance_id() or ""
    if aid == local_id:
        # Canonical redirect for bound appliance
        location = "/equaliser" if sub == "equaliser" else "/"
        handler.send_response(302)
        handler.send_header("Location", location)
        handler.send_header("Content-Length", "0")
        handler.end_headers()
    elif not _effective_control_other_appliances(state):
        handler._redirect_with_error_flash("Controlling other appliances is disabled.", "/")
    elif sub == "equaliser":
        send_remote_equaliser_page(handler, state, aid)
    else:
        send_remote_home_page(handler, state, aid)


# --- Auth flow ----------------------------------------------------------------


def _route_get_auth(handler, state):
    if not AUTH.is_enabled():
        handler.send_response(302)
        handler.send_header("Location", "/")
        handler.send_header("Content-Length", "0")
        handler.end_headers()
        return
    query = urlparse(handler.path).query
    AUTH.handle_auth_get(handler, query)


def _route_post_auth_verify(handler, state, body_str):
    AUTH.handle_auth_verify(handler, body_str.encode("utf-8"))


def _route_post_pin_change(handler, state, body_str):
    AUTH.handle_pin_change(handler, body_str.encode("utf-8"))


# --- Stateful pages: setup / owntone-setup form posts ------------------------


def _route_post_setup_form(handler, state, body_str):
    send_json(handler, 405, {"ok": False, "error": "form_post_disabled"})


def _route_post_owntone_setup_form(handler, state, body_str):
    send_json(handler, 405, {"ok": False, "error": "form_post_disabled"})


# --- Stateful pages: first-boot GET + POST pairs ------------------------------


def _route_get_first_boot_owntone(handler, state):
    send_first_boot_owntone_page(handler, state, AUTH)


def _route_get_first_boot_appliance(handler, state):
    send_first_boot_appliance_page(handler, state, AUTH)


def _route_post_first_boot_continue(handler, state, body_str):
    handle_first_boot_continue_post(handler, state, AUTH, body_str)


def _route_post_first_boot_finish(handler, state, body_str):
    handle_first_boot_finish_post(handler, state, AUTH, body_str)


# --- Logs download -------------------------------------------------------------


def _route_get_logs_download(handler, state):
    handle_logs_download(handler)


# --- Dial management (browser, PIN-gated) --------------------------------------


def _route_post_dial_management(handler, state, body_str):
    dispatch_dial_management_post(handler, handler._normalized_path(), _route_post_json_obj(handler))


def _route_post_dial_update(handler, state, body_str):
    path = handler._normalized_path()
    dial_id = path.rsplit("/", 1)[-1]
    if not dial_id:
        handler.send_error(404, "Not found")
        return
    handle_dial_update_post(handler, dial_id)


def _route_post_dial_screen_settings(handler, state, body_str):
    json_obj = _route_post_json_obj(handler)
    handle_dial_screen_settings_post(handler, json_obj if isinstance(json_obj, dict) else {})


def _route_get_dial_configure(handler, state):
    handle_dial_configure_get(handler, handler._normalized_path().rsplit("/", 1)[-1])


def _route_get_dial_pin_recovery_status(handler, state):
    handle_dial_pin_recovery_status(handler, handler._normalized_path().rsplit("/", 1)[-1])


def _route_get_dial_update_status(handler, state):
    handle_dial_update_status(handler, handler._normalized_path().rsplit("/", 1)[-1])


def _route_get_dial_screen_settings(handler, state):
    handle_dial_screen_settings_get(handler, handler._normalized_path().rsplit("/", 1)[-1])


# send_html() (matching send_json()'s shape) now lives in
# autostream_webui_common.py -- imported above -- so page modules can use it
# without importing this file (avoids a circular import back into here).

# Global state
STATE: Optional[WebUIState] = None
AUTH: Optional[AuthManager] = None

# -----------------------------------------------------------------------------
# Background update-apply state
# -----------------------------------------------------------------------------

# Guards against a second POST /api/update/apply starting a concurrent
# staging run while one is already in flight. The installer itself is
# flock-protected once scheduled, so this only needs to cover the staging
# window that now runs off the request thread.
_update_apply_lock = threading.Lock()
_update_apply_in_progress = False

# Where the installer (autostream_install.sh) persists apply progress/result;
# read by autostream_admin's "update-status" command for the /offline/updating
# page. Root-owned, so this (unprivileged) process cannot write it directly.
# autostream_updater (run as root via sudo) now owns every write to this file
# for the phases before the installer takes over — including the failure/
# timeout cases below — so this process only needs to log those outcomes.
_UPDATE_RESULT_FILE = Path("/var/lib/autostream/update-result.env")


def _update_apply_mark_finished() -> None:
    global _update_apply_in_progress
    with _update_apply_lock:
        _update_apply_in_progress = False


def _run_update_apply_background() -> None:
    """Run the updater's apply step off the request thread.

    Started as a daemon thread by _start_update_apply once the response has
    already been sent to the client. Always clears the in-flight guard on
    the way out, regardless of outcome.
    """
    try:
        try:
            rc, out, err = run_updater(["apply"], timeout=180)
        except subprocess.TimeoutExpired:
            # The updater subprocess (invoked via sudo) is not guaranteed to
            # die with its parent, so a timeout here does not mean the apply
            # itself failed — staging or the installer hand-off may still be
            # under way. autostream_updater (running as root) is the sole
            # writer of update-result.env for this window; if it is still
            # progressing, its own writes continue to land regardless of this
            # process losing track of the subprocess, so nothing needs to be
            # written here — only logged.
            logging.error("update apply: timed out waiting for updater subprocess")
            return
        except Exception as e:
            # As above: autostream_updater owns update-result.env, including
            # any failure state, so only logging is needed here.
            logging.error("update apply: background apply raised: %s", e)
            return

        if rc == 0:
            try:
                result = json.loads(out or "{}")
            except Exception:
                result = {"ok": True}
            if not result.get("ok", True):
                # The updater has already written its own failure (or, for a
                # detected concurrent update, deliberately left the running
                # instance's own progress untouched) — log only.
                logging.error("update apply: updater reported failure: %s", result)
            return

        try:
            result = json.loads(out or "{}")
            message = str(result.get("error") or "Update failed")
        except Exception:
            message = "Update failed"
        if err.strip():
            message = f"{message}: {err.strip()}"
        # The updater owns update-result.env; a non-zero exit before it could
        # write anything is rare (e.g. sudo/exec failure) but even then there
        # is nothing this unprivileged process can do about the result file.
        logging.error("update apply: updater exited rc=%s: %s", rc, message)
    finally:
        _update_apply_mark_finished()




class ConfigWebHandler(BaseHTTPRequestHandler):
    """Simple HTTP interface (port 8080) to view and edit autostream.json."""

    protocol_version = "HTTP/1.1"
    MAX_POST_SIZE: int = 64 * 1024

    def _get_client_ip(self):
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()

        xri = self.headers.get("X-Real-IP")
        if xri:
            return xri.strip()

        return self.client_address[0]

    def _is_direct_local(self) -> bool:
        """Return True iff this request arrived directly on the loopback socket.

        Three conditions must all hold:
        1. Socket peer is a loopback address (127.x.x.x or ::1).
        2. No X-Forwarded-For header (NGINX always sets this for proxied requests).
        3. No X-Real-IP header.

        Content-Type is intentionally not checked here: GET requests carry no body
        and no Content-Type, so requiring it would break GET callers (e.g. the
        storage guard's _api_get). Conditions 2 and 3 are sufficient because NGINX
        always sets both headers when proxying browser requests over loopback.

        Do NOT use _get_client_ip() here — it trusts proxy headers intentionally
        for logging, which would defeat this security check.
        """
        peer = self.client_address[0]
        is_loopback = peer.startswith("127.") or peer == "::1"
        if not is_loopback:
            return False
        if self.headers.get("X-Forwarded-For"):
            return False
        if self.headers.get("X-Real-IP"):
            return False
        return True

    def _extract_csrf_token(self, form, json_obj) -> str:
        """Extract the CSRF token from the header, falling back to the body.

        Header (``X-CSRF-Token``) takes precedence over body; within the
        body, a parsed form (if present) takes precedence over a JSON
        object. Shared by do_POST and do_PUT so this precedence can't drift
        between the two independently-parsed call sites.
        """
        token_from_header = self.headers.get("X-CSRF-Token", "") or ""

        token_from_body = ""
        if form:
            token_from_body = (form.get("csrf_token") or [""])[0]
        elif isinstance(json_obj, dict):
            token_from_body = str(json_obj.get("csrf_token") or "")

        return token_from_header or token_from_body

    def _commissioning_required(self) -> bool:
        """Whether this appliance is still mid first-boot commissioning.

        Single per-request home for the is_commissioning_required() check;
        do_GET and do_POST each call this once instead of independently
        re-invoking the underlying config/state-path check.
        """
        return is_commissioning_required(STATE.config_path, STATE.state_path)

    def _read_post_body_bytes(self) -> Optional[bytes]:
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self.send_error(400, "Invalid Content-Length")
            return None
        if not (0 <= length <= self.MAX_POST_SIZE):
            self.send_error(413, "Request body too large")
            return None
        try:
            data = self.rfile.read(length)
        except Exception as e:
            logging.error("Error reading POST body: %s", e)
            try:
                self.send_error(400, "Request body unreadable")
            except Exception:
                pass
            return None
        if length > 0 and len(data) < length:
            try:
                self.send_error(400, "Request body truncated")
            except Exception:
                pass
            return None
        return data

    def _normalized_path(self) -> str:
        # Strip query string and trailing slash
        path = urlparse(self.path).path or "/"
        if path.endswith("/") and path != "/":
            path = path[:-1]
        return path

    def _start_update_apply(self) -> None:
        """Accept an update-apply request and run it in the background.

        Staging the release tarball can take long enough on slow hardware to
        exceed the reverse proxy's read timeout, so this no longer blocks the
        request: it starts run_updater("apply") on a daemon thread and
        responds immediately with {ok: True, accepted: True}. The JS client
        treats "accepted" the same way it used to treat a synchronous
        success and navigates to /offline/updating, which polls the update
        status autostream_updater (running as root) and, once scheduled,
        the installer write to update-result.env. This process cannot write
        that root-owned file itself, so _run_update_apply_background only
        logs outcomes rather than persisting them there.

        A second POST while an apply is already in flight does not start a
        concurrent run — it returns already_in_progress=True instead. The
        installer itself is flock-protected once scheduled; this guard only
        needs to cover the staging window that now runs here.
        """
        global _update_apply_in_progress
        with _update_apply_lock:
            if _update_apply_in_progress:
                send_json(self, 200, {"ok": True, "accepted": True, "already_in_progress": True})
                return
            _update_apply_in_progress = True

        try:
            threading.Thread(
                target=_run_update_apply_background,
                name="update-apply",
                daemon=True,
            ).start()
        except Exception as e:
            # The guard must never outlive a run that was never started, or
            # every later apply would be refused as already_in_progress.
            _update_apply_mark_finished()
            logging.error("update apply: could not start background thread: %s", e)
            send_json(self, 200, {"ok": False, "error": "Could not start update"})
            return
        send_json(self, 200, {"ok": True, "accepted": True})

    # Reduce noisy TLS/HTTPS probes hitting this plain-HTTP server
    def log_error(self, format, *args):  # noqa: A003
        msg = format % args if args else format
        if "Bad request version" in msg:
            logging.debug("Ignored non-HTTP traffic: %s", msg)
            return
        logging.error("%s - - [%s] %s", self._get_client_ip(), self.log_date_time_string(), msg)

    def log_message(self, format, *args):
        line = "%s - - [%s] %s" % (self._get_client_ip(), self.log_date_time_string(), format % args)
        method = getattr(self, "command", "") or ""
        # Every former _POLLING_LOG_PATHS entry is now a migrated route with
        # its own poll_log flag (see that tuple's docstring) -- including the
        # GET-only demotion for /api/log-level, expressed by GET's route
        # having poll_log=True and PUT's having poll_log=False (the default).
        is_polling = _route_is_poll_log(self._normalized_path(), method)
        if is_polling:
            logging.debug(line)
        else:
            logging.info(line)

    def end_headers(self) -> None:
        """
        Flushes any pending cookies (AuthManager + other one-shot cookies).
        Must be called after status line, before body.
        """
        # AuthManager uses a single pending cookie string.
        cookie = getattr(self, "_pending_auth_cookie", None)
        if cookie:
            self.send_header("Set-Cookie", cookie)
            self._pending_auth_cookie = None

        # Generic support for multiple Set-Cookie headers.
        pending = getattr(self, "_pending_set_cookies", None)
        if pending:
            for c in pending:
                self.send_header("Set-Cookie", c)
            self._pending_set_cookies = []

        super().end_headers()

    def _redirect_with_error_flash(self, message: str, location: str = "/") -> None:
        """Send a 302 redirect and set a one-shot error flash cookie."""
        val = quote(f"error:{message}", safe="")
        cookie = f"{FLASH_COOKIE_NAME}={val}; Max-Age=30; Path=/; HttpOnly; SameSite=Lax"
        pending = getattr(self, "_pending_set_cookies", None)
        if pending is None:
            self._pending_set_cookies = [cookie]
        else:
            pending.append(cookie)
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _dispatch_federation(self, method: str, path: str, body_str: str = "") -> None:
        """Dispatch a federation API request before browser auth/CSRF.

        Never redirects to /auth, never reads or sets browser cookies, and
        never creates a browser UI session.  Source-IP-bound bearer tokens
        are the only acceptable credential on all routes except POST /session.
        """
        source_ip = self._get_client_ip()

        # Unavailable during commissioning or when identity is missing.
        # 404 per the documented federation wire contract (peers key off the
        # "error" body field, never the status code).
        if is_commissioning_required(STATE.config_path, STATE.state_path):
            send_json(self, 404, {"ok": False, "error": "appliance_unconfigured"})
            return
        if not get_appliance_id():
            send_json(self, 404, {"ok": False, "error": "appliance_unconfigured"})
            return

        # POST /session: no bearer token required
        if path == f"{_FEDERATION_PREFIX}/session":
            if method != "POST":
                send_json(self, 405, {"ok": False, "error": "method_not_allowed"})
                return
            if body_str:
                if len(body_str) > _FEDERATION_BODY_MAX:
                    send_json(self, 400, {"ok": False, "error": "body_too_large"})
                    return
                try:
                    obj = json.loads(body_str)
                except json.JSONDecodeError:
                    send_json(self, 400, {"ok": False, "error": "invalid_json"})
                    return
                if not isinstance(obj, dict) or obj:
                    send_json(self, 400, {"ok": False, "error": "invalid_request_body"})
                    return
            send_federation_session_json(self, source_ip)
            return

        # All other federation endpoints require a valid bearer token
        auth_header = self.headers.get("Authorization") or ""
        token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else ""
        if not autostream_federation.validate_session(token, source_ip):
            send_json(self, 401, {"ok": False, "error": "unauthorized"})
            return

        if method == "GET":
            if path == f"{_FEDERATION_PREFIX}/home":
                send_federation_home_json(self, STATE)
            elif path == f"{_FEDERATION_PREFIX}/equaliser":
                send_federation_equaliser_json(self, STATE)
            elif path == f"{_FEDERATION_PREFIX}/equaliser/status":
                send_federation_eq_status_json(self, STATE)
            else:
                send_json(self, 400, {"ok": False, "error": "invalid_endpoint"})
            return

        if method == "POST":
            if len(body_str) > _FEDERATION_BODY_MAX:
                send_json(self, 400, {"ok": False, "error": "body_too_large"})
                return
            if path == f"{_FEDERATION_PREFIX}/output":
                if not body_str:
                    send_json(self, 400, {"ok": False, "error": "missing_body"})
                    return
                send_federation_output_json(self, STATE, body_str)
            elif path == f"{_FEDERATION_PREFIX}/equaliser/config":
                if not body_str:
                    send_json(self, 400, {"ok": False, "error": "missing_body"})
                    return
                send_federation_eq_config_json(self, STATE, body_str)
            elif path == f"{_FEDERATION_PREFIX}/equaliser/reset":
                send_federation_eq_reset_json(self, STATE)
            elif path == f"{_FEDERATION_PREFIX}/repeat":
                if not body_str:
                    send_json(self, 400, {"ok": False, "error": "missing_body"})
                    return
                send_federation_repeat_json(self, STATE, body_str)
            else:
                send_json(self, 400, {"ok": False, "error": "invalid_endpoint"})
            return

        send_json(self, 405, {"ok": False, "error": "method_not_allowed"})

    def do_GET(self):  # noqa: N802
        path = self._normalized_path()

        # Route-table dispatch (see autostream_webui_routes.py). This
        # covers every GET path/scheme the server recognizes (browser
        # pages/APIs, federation, dial protocol/management, the
        # loopback-aware fast paths, the gateway, remote pages, first-boot,
        # /auth, /logs/download). Falls through untouched for anything not
        # in ROUTES.
        if _route_dispatch(self, "GET", path):
            return

        # Nothing matched: reproduce do_GET's former catch-all tail exactly
        # (now unreachable for every literal path this batch and its
        # predecessors migrated, but a genuinely unknown/unrouted path still
        # gets the same commissioning redirect, then protected-page gate,
        # then 404 -- including the session-cookie side effect of
        # ensure_session(), which legacy ran unconditionally ahead of its
        # own now-removed elif chain).
        if self._commissioning_required():
            allowed = (
                path.startswith("/auth")
                or path.startswith("/api/auth/")
                or path.startswith("/api/owntone/outputs")
                or path.startswith("/api/owntone/outputs_state")
                or path.startswith("/api/owntone/ready")
                or path.startswith("/first-boot/")
                or path.startswith("/owntone-restarting")
                or path.startswith("/rebooting")
                or path.startswith("/logs")
            )
            if not allowed:
                step = required_first_boot_step(STATE.config_path, STATE.state_path)
                location = f"/first-boot/{step}" if step else "/first-boot/owntone"
                self.send_response(302)
                self.send_header("Location", location)
                self.end_headers()
                return
        else:
            # Already configured — redirect away from first-boot pages.
            if path.startswith("/first-boot/"):
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

        # Gate protected pages
        if AUTH.requires_auth(path) and not AUTH.is_authenticated(self.headers):
            AUTH.redirect_to_auth(self, next_path=self.path)
            return

        # Ensure UI session / CSRF exists
        self._csrf_token = AUTH.ensure_session(self)

        self.send_error(404, "Not found")

    def do_POST(self):  # noqa: N802
        path = self._normalized_path()

        # Route-table dispatch (see autostream_webui_routes.py). This
        # covers every POST path/scheme the server recognizes.
        # Falls through untouched for anything not in ROUTES.
        if _route_dispatch(self, "POST", path):
            return

        # Nothing matched: reproduce do_POST's former catch-all tail --
        # still read/parse the body, still gate on CSRF and commissioning,
        # before the terminal 404 (e.g. POST /logs must plain-404, but only
        # after passing those checks like any other still-recognized POST --
        # see test_webui_auth_routing.py's test_logs_post_returns_404).
        body_bytes = self._read_post_body_bytes()
        if body_bytes is None:
            return  # error already sent
        try:
            body_str = body_bytes.decode("utf-8")
        except UnicodeDecodeError:
            self.send_error(400, "Request body is not valid UTF-8")
            return

        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()

        form = {}
        json_obj = None
        if body_str:
            if content_type == "application/x-www-form-urlencoded":
                form = parse_qs(body_str)
            elif content_type == "application/json":
                try:
                    json_obj = json.loads(body_str)
                except json.JSONDecodeError:
                    self.send_error(400, "Invalid JSON")
                    return

        if content_type == "application/json" and body_str and not isinstance(json_obj, dict):
            self.send_error(400, "JSON object required")
            return

        csrf_token = self._extract_csrf_token(form, json_obj)
        if not AUTH.validate_csrf(self, csrf_token):
            if path in ("/setup", "/owntone-setup", "/service"):
                self._redirect_with_error_flash("Settings not saved, please try again")
            elif path.startswith("/api/"):
                fresh_csrf = AUTH.ensure_session(self)
                send_json(self, 403, {
                    "ok": False,
                    "error": "csrf_stale",
                    "csrf_token": fresh_csrf,
                })
            else:
                self.send_error(403, "CSRF validation failed")
            return

        _is_commissioning = self._commissioning_required()
        if _is_commissioning:
            _post_commissioning_allowed = (
                path.startswith("/api/owntone/")
                or path.startswith("/api/auth/")
                or path == "/first-boot/owntone/continue"
                or path == "/first-boot/appliance/finish"
                or path == "/api/output"
                or path == "/api/output_eq/reset"
                or path == "/api/service/reset"
            )
            if not _post_commissioning_allowed:
                send_json(self, 409, {"ok": False, "error": "appliance_unconfigured"})
                return
        else:
            if path in ("/first-boot/owntone/continue", "/first-boot/appliance/finish"):
                send_json(self, 409, {"ok": False, "error": "already_configured"})
                return

        self.send_error(404, "Not found")

    def do_PUT(self):  # noqa: N802
        path = self._normalized_path()

        # Route-table dispatch (see autostream_webui_routes.py).
        # PUT /api/log-level (scheme="loopback_aware") is the only PUT
        # route the server has ever recognized.
        if _route_dispatch(self, "PUT", path):
            return

        self.send_error(404, "Not found")


# Cooldown between lockout-triggered config reloads (_lockout_heal_check):
# a reload bounces the monitor's inputs, which is disruptive if repeated
# faster than the other end could plausibly release and re-pin the cable.
LOCKOUT_RELOAD_COOLDOWN_SECONDS = 120.0


def _bluetooth_input_configured(state) -> bool:
    """True when either monitor input is configured on the Bluetooth
    loopback's capture side."""
    from autostream_bluetooth_client import classify_loopback_hw
    from autostream_webui_common import _config_snapshot
    try:
        cfg = _config_snapshot(state)
    except Exception:
        return False
    return any(
        classify_loopback_hw(dev) == "capture"
        for dev in (cfg.audio1.capture_device, cfg.audio2.capture_device)
        if dev
    )


def _rate_follow_check(state, bluetooth_status: Optional[dict],
                       last_cable_rate: Optional[int]) -> Optional[int]:
    """One rate-follow step: returns the updated last-seen cable rate.

    The loopback cable's rate follows the Bluetooth transport, and the
    monitor's capture side can only renegotiate by being reopened -- so a
    rate change while a Bluetooth input is configured triggers a
    coordinator config reload, which bounces the inputs through the same
    gated start-up path used at boot (the monitor reopens after the pump
    already holds the cable at the new rate).

    ``sample_rate`` is only present in the status while a transport is
    active; polls without it (transport gaps, unreachable service) leave
    the last-seen value untouched, so a plain reconnect at the same rate
    never triggers a reload -- only an observed rate CHANGE does.
    """
    rate = (bluetooth_status or {}).get("sample_rate")
    if not isinstance(rate, int) or isinstance(rate, bool) or rate <= 0:
        return last_cable_rate
    if (
        last_cable_rate is not None
        and rate != last_cable_rate
        and _bluetooth_input_configured(state)
    ):
        from autostream_core import request_config_reload
        logging.info(
            "Bluetooth transport rate changed %d Hz -> %d Hz; "
            "reloading monitor inputs to renegotiate the loopback.",
            last_cable_rate, rate,
        )
        request_config_reload()
    return rate


def _lockout_heal_check(state, bluetooth_status: Optional[dict],
                        lockout_streak: int,
                        last_heal_reload: Optional[float]) -> tuple:
    """One lockout-healing step: returns the updated
    ``(lockout_streak, last_heal_reload)``.

    A sustained ``loopback_locked_out`` means the pump's capture-side peer
    pinned the shared cable at incompatible parameters while the pump was
    absent, and the pump alone cannot force a release -- only the monitor
    reopening its capture side renegotiates the cable. Reloading on the
    first observed lockout would over-react to a single transient poll, so
    the reload fires only once the lockout has been seen on two consecutive
    polls (and only while a Bluetooth input is actually configured), and no
    more often than ``LOCKOUT_RELOAD_COOLDOWN_SECONDS``.
    """
    locked_out = bool((bluetooth_status or {}).get("loopback_locked_out", False))
    if not locked_out:
        return 0, last_heal_reload

    lockout_streak += 1
    now = time.monotonic()
    cooldown_elapsed = (
        last_heal_reload is None or now - last_heal_reload >= LOCKOUT_RELOAD_COOLDOWN_SECONDS
    )
    if (
        lockout_streak >= 2
        and cooldown_elapsed
        and _bluetooth_input_configured(state)
    ):
        from autostream_core import request_config_reload
        logging.info(
            "Bluetooth loopback held at incompatible parameters with a "
            "Bluetooth input configured; reloading monitor inputs to "
            "renegotiate the cable.",
        )
        request_config_reload()
        lockout_streak = 0
        last_heal_reload = now
    return lockout_streak, last_heal_reload


def _scan_monitor_devices_loop() -> None:
    """Background loop: refresh visible ALSA capture devices (and, when
    the Bluetooth-input subsystem is installed, the autostream_bluetooth
    daemon status) every 15 s. Each poll also runs the Bluetooth
    rate-follow step (_rate_follow_check) and the lockout-healing step
    (_lockout_heal_check).
    """
    last_cable_rate: Optional[int] = None
    lockout_streak = 0
    last_heal_reload: Optional[float] = None
    while not stop_flag.is_set():
        bluetooth_status: Optional[dict] = None
        if bluetooth_installed():
            try:
                bluetooth_status = BluetoothClient().status()
            except Exception as e:
                logging.error(
                    "Web UI: error querying autostream_bluetooth status: %s", e,
                )
                bluetooth_status = None

        try:
            devices = get_available_monitor_devices(bluetooth_status=bluetooth_status)
        except Exception as e:
            logging.error(
                "Web UI: error scanning autostream_monitor devices: %s", e,
            )
            devices = []

        state = STATE
        if state is None:
            return

        try:
            last_cable_rate = _rate_follow_check(state, bluetooth_status, last_cable_rate)
        except Exception:
            logging.debug("bluetooth rate-follow check failed", exc_info=True)

        try:
            lockout_streak, last_heal_reload = _lockout_heal_check(
                state, bluetooth_status, lockout_streak, last_heal_reload,
            )
        except Exception:
            logging.debug("bluetooth lockout-heal check failed", exc_info=True)

        state.set_monitor_devices(devices)
        state.set_bluetooth_status(bluetooth_status)
        time.sleep(15)


def start_webui_background(
    config_path: str,
    host: str = "127.0.0.1",
    port: int = 8080,
    *,
    settings=None,
) -> threading.Thread:
    """Start the configuration web UI on a background thread.

    ``settings`` is the SettingsStore shared with the coordinator.  If None,
    a store is created locally (used when the webui runs standalone or in tests).
    """
    from autostream_settings import SettingsStore
    from autostream_webui_common import get_app_version
    global STATE, AUTH

    if settings is None:
        settings = SettingsStore(config_path)
    STATE = WebUIState(config_path, STATE_PATH, settings=settings)
    # Same theme.css <link>/cache-bust convention as build_page_html(); the
    # login page keeps LICENSE_BANNER_CSS inline rather than folding it into
    # the shared theme (it is currently empty, but stays page-specific).
    style_link = f'<link rel="stylesheet" href="/static/theme.css?v={html.escape(get_app_version())}">'
    if LICENSE_BANNER_CSS.strip():
        style_link += f'<style>{LICENSE_BANNER_CSS}</style>'
    AUTH = AuthManager(
        config_path=config_path,
        state_path=STATE_PATH,
        style_link=style_link,
        banner_html=BANNER_HTML,
        nav_html=build_nav_bar_html("setup"),
        title="autostream",
    )

    def _reconcile_announcement_loop() -> None:
        """Periodically reconcile the _autostream._tcp service file (every 60 s)."""
        from autostream_appliance_gateway import sweep_token_cache
        from autostream_appliances import reconcile_appliance_announcement
        from autostream_federation import sweep_sessions
        from autostream_webui_common import _config_snapshot, get_app_version
        while not stop_flag.is_set():
            stop_flag.wait(60)
            if stop_flag.is_set():
                break
            try:
                sweep_sessions()
            except Exception:
                logging.debug("sweep_sessions: error", exc_info=True)
            try:
                sweep_token_cache()
            except Exception:
                logging.debug("sweep_token_cache: error", exc_info=True)
            try:
                cfg = _config_snapshot(STATE)
                reconcile_appliance_announcement(
                    get_app_version(), cfg.webui.advertise_appliance
                )
            except Exception:
                logging.debug("reconcile_announcement_loop: error", exc_info=True)

    def _serve() -> None:
        try:
            from autostream_dials import start_dial_scanner
            from autostream_appliances import (
                reconcile_appliance_announcement,
                start_appliance_scanner,
            )
            from autostream_webui_common import _config_snapshot, get_app_version
            from autostream_webui_api import apply_mdns_grace_period_startup

            from autostream_core import stop_flag as _stop_flag
            start_dial_scanner(shutdown_event=_stop_flag)
            start_appliance_scanner(shutdown_event=_stop_flag)
            apply_mdns_grace_period_startup(STATE)

            scanner_thread = threading.Thread(
                target=_scan_monitor_devices_loop, daemon=True,
            )
            scanner_thread.start()

            # Initial announcement reconciliation (best-effort; errors are logged)
            try:
                cfg = _config_snapshot(STATE)
                reconcile_appliance_announcement(
                    get_app_version(), cfg.webui.advertise_appliance
                )
            except Exception:
                logging.debug("startup reconcile_announcement: error", exc_info=True)

            reconcile_thread = threading.Thread(
                target=_reconcile_announcement_loop, daemon=True,
            )
            reconcile_thread.start()

            # Prime the app-version cache before the HTTP server starts so the
            # first /api/about/system request never incurs the helper timeout.
            get_app_version()

            # Best-effort one-shot Vibra Mini version discovery before accepting
            # requests.  Runs in a daemon thread so it never delays startup.
            from track_id.vibra_shazam import refresh_vibra_runtime_info
            threading.Thread(
                target=refresh_vibra_runtime_info,
                name="vibra-runtime-refresh",
                daemon=True,
            ).start()

            httpd = ThreadingHTTPServer((host, port), ConfigWebHandler)
            logging.info("Web UI available at http://%s:%d", host, port)
            httpd.serve_forever()
        except Exception:
            logging.exception("Web UI server error")
            raise

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    return thread

if __name__ == "__main__":
    # (The sys.modules["autostream_webui"] alias guarding against a dual
    # module copy is applied at the top of this file, before any project
    # import.)
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} PATH_TO_CONFIG.json")
        sys.exit(1)

    config_path = sys.argv[1]
    run_autostream(config_path, start_webui=start_webui_background)
