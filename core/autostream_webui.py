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

import logging
import sys
import threading
import time
from typing import Optional
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse, unquote, quote
import json

from autostream_core import (
    get_available_monitor_devices,
    run_autostream,
    stop_flag,
)

from autostream_sysutils import (
    reboot_system,
)

from autostream_webui_assets import (
    STYLE_CSS,
    LICENSE_BANNER_CSS,
    BANNER_HTML,
)

from autostream_auth import AuthManager, parse_cookie_header, FLASH_COOKIE_NAME

from autostream_webui_state import WebUIState
from autostream_webui_api import (
    run_updater,
    send_audio_status_json,
    send_dial_mute_post_json,
    send_dial_volume_post_json,
    send_federation_eq_config_json,
    send_federation_eq_reset_json,
    send_federation_eq_status_json,
    send_federation_equaliser_json,
    send_federation_home_json,
    send_federation_output_json,
    send_federation_session_json,
    send_json,
    send_output_eq_config_json,
    send_output_eq_reset_json,
    send_output_eq_status_json,
    send_owntone_outputs_json,
    send_owntone_outputs_state_json,
    send_service_config_json,
    send_service_reset_json,
    send_status_json,
    send_update_check_json,
    send_update_status_json,
)
import autostream_federation
from autostream_webui_dials import (
    dispatch_dial_management_post,
    handle_dial_configure_get,
    handle_dial_pin_recovery_status,
    handle_dial_update_post,
    handle_dial_update_status,
)
from autostream_webui_common import build_nav_bar_html
from autostream_webui_page_about import send_about_page
from autostream_webui_page_equaliser import send_equaliser_page
from autostream_webui_page_airplay import send_airplay_page
from autostream_webui_page_logs import handle_logs_download, handle_logs_post, send_logs_page
from autostream_webui_page_owntone import (
    send_owntone_ready_json,
    send_owntone_restarting_page,
    send_owntone_setup_page,
)
from autostream_webui_page_rebooting import send_rebooting_page
from autostream_webui_page_service import send_service_page
from autostream_webui_page_setup import send_setup_page
from autostream_webui_post_handlers import (
    handle_factory_reset_post,
    handle_live_input_eq_update,
    handle_live_input_gain_update,
    handle_output_update,
    handle_owntone_setup_post,
    handle_setup_post,
)

from autostream_config import unconfigured, STATE_PATH
from autostream_rpi import get_appliance_id
from autostream_appliance_gateway import (
    send_appliances_json,
    send_gateway_eq_config_json,
    send_gateway_eq_reset_json,
    send_gateway_eq_status_json,
    send_gateway_equaliser_json,
    send_gateway_home_json,
    send_gateway_output_json,
)

_FEDERATION_PREFIX = "/api/federation/v1"
_GATEWAY_PREFIX = "/api/appliances"
_FEDERATION_BODY_MAX = 4096  # bytes

# Global state
STATE: Optional[WebUIState] = None
AUTH: Optional[AuthManager] = None

# initial_setup values:
# 0 - not in initial setup
# 1 - initial setup needed and page 1 not complete
# 2 - initial setup needed and page 1 completed (so user on page 2)
initial_setup = 0
_setup_lock = threading.Lock()



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
        """Stage the latest release and schedule the installer.

        Runs run_updater("apply") in the handler's own thread (ThreadingHTTPServer
        gives each request its own thread). The updater downloads and extracts the
        release tarball, schedules autostream_install.sh --update via systemd-run,
        and returns a JSON result. On success the JS client redirects to
        /offline/updating; on failure the error is shown on the page.
        """
        try:
            rc, out, err = run_updater(["apply"], timeout=180)
            if rc == 0:
                try:
                    result = json.loads(out or "{}")
                    result.setdefault("ok", True)
                except Exception:
                    result = {"ok": True}
            else:
                try:
                    result = json.loads(out or "{}")
                    result.setdefault("ok", False)
                except Exception:
                    result = {"ok": False, "error": "apply failed"}
                if not result.get("ok") and err.strip():
                    result.setdefault("details", err.strip())
        except Exception as e:
            result = {"ok": False, "error": "apply failed", "details": str(e)}
        send_json(self, 200, result)

    # Reduce noisy TLS/HTTPS probes hitting this plain-HTTP server
    def log_error(self, format, *args):  # noqa: A003
        msg = format % args if args else format
        if "Bad request version" in msg:
            logging.debug("Ignored non-HTTP traffic: %s", msg)
            return
        logging.error("%s - - [%s] %s", self._get_client_ip(), self.log_date_time_string(), msg)

    def log_message(self, format, *args):
        logging.info("%s - - [%s] %s", self._get_client_ip(), self.log_date_time_string(), format % args)

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

        # Unavailable during initial/AP setup or when identity is missing
        if unconfigured(STATE.config_path):
            send_json(self, 409, {"ok": False, "error": "appliance_unconfigured"})
            return
        global initial_setup
        with _setup_lock:
            in_setup = initial_setup != 0
        if in_setup:
            send_json(self, 409, {"ok": False, "error": "appliance_unconfigured"})
            return
        if not get_appliance_id():
            send_json(self, 409, {"ok": False, "error": "appliance_unconfigured"})
            return

        # POST /session: no bearer token required
        if path == f"{_FEDERATION_PREFIX}/session":
            if method != "POST":
                self.send_error(405, "Method not allowed")
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
                self.send_error(404, "Not found")
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
            else:
                self.send_error(404, "Not found")
            return

        self.send_error(405, "Method not allowed")

    def do_GET(self):  # noqa: N802
        global initial_setup

        path = self._normalized_path()

        # Federation routes bypass browser auth/CSRF and initial-setup redirect.
        if path.startswith(_FEDERATION_PREFIX):
            self._dispatch_federation("GET", path)
            return

        # If INI missing, force setup except for the setup/auth endpoints + auth verify API
        if unconfigured(STATE.config_path):
            with _setup_lock:
                if initial_setup == 0:
                    initial_setup = 1
                setup_stage = initial_setup
            allowed = (
                path.startswith("/auth")
                or path.startswith("/api/auth/")
                or path.startswith("/api/owntone/outputs")
                or path.startswith("/api/owntone/outputs_state")
                or path.startswith("/api/owntone/ready")
                or path.startswith("/owntone-setup")
                or path.startswith("/owntone-restarting")
                or path.startswith("/rebooting")
                or path.startswith("/logs")
            )
            if setup_stage == 2:
                allowed = allowed or path.startswith("/setup")
            if not allowed:
                self.send_response(302)
                self.send_header("Location", "/owntone-setup")
                self.end_headers()
                return
        else:
            # Config exists, so we are not in initial setup anymore
            with _setup_lock:
                initial_setup = 0

        # Serve auth page — if auth is disabled (no PIN), redirect to home.
        if path == "/auth":
            if not AUTH.is_enabled():
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            query = urlparse(self.path).query
            AUTH.handle_auth_get(self, query)
            return

        # Gate protected pages
        if AUTH.requires_auth(path) and not AUTH.is_authenticated(self.headers):
            AUTH.redirect_to_auth(self, next_path=self.path)
            return

        # Ensure UI session / CSRF exists
        self._csrf_token = AUTH.ensure_session(self)

        # page handlers
        query = urlparse(self.path).query
        qs = parse_qs(query)
        msg = (qs.get("msg") or [""])[0]
        flash_type = "success"

        # One-shot flash message (cookie-based). This avoids "sticky" URLs in iOS A2HS/PWA.
        # Priority: explicit ?msg=... wins; otherwise consume the cookie once.
        if not msg:
            path = self._normalized_path()
            # Don't consume the flash cookie on pages that don't render it
            if path != "/owntone-restarting" and not path.startswith("/api/"):
                cookies = parse_cookie_header(self.headers.get("Cookie"))
                raw = cookies.get(FLASH_COOKIE_NAME, "")
                if raw:
                    try:
                        decoded = unquote(raw)
                    except Exception:
                        decoded = raw
                    # Decode optional '<type>:' prefix written by _set_flash_cookie.
                    colon = decoded.find(":")
                    if colon > 0 and decoded[:colon] in ("error", "warning"):
                        flash_type = decoded[:colon]
                        msg = decoded[colon + 1:]
                    else:
                        msg = decoded
                    # Clear cookie so the flash is one-shot.
                    clear_cookie = (
                        f"{FLASH_COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
                    )
                    pending = getattr(self, "_pending_set_cookies", None)
                    if pending is None:
                        self._pending_set_cookies = [clear_cookie]
                    else:
                        pending.append(clear_cookie)

        if path == "/":
            send_airplay_page(self, STATE, AUTH, flash_msg=msg, flash_type=flash_type)
        elif path == "/equaliser":
            send_equaliser_page(self, STATE, flash_msg=msg, flash_type=flash_type)
        elif path == "/setup":
            send_setup_page(self, STATE, AUTH, flash_msg=msg)
        elif path == "/owntone-setup":
            send_owntone_setup_page(self, STATE, AUTH, flash_msg=msg)
        elif path == "/about":
            send_about_page(self, STATE)
        elif path == "/service":
            send_service_page(self, STATE, flash_msg=msg, flash_type=flash_type)
        elif path == "/logs":
            send_logs_page(self, STATE, flash_msg=msg)
        elif path == "/logs/download":
            handle_logs_download(self)
        elif path == "/api/output_eq/status":
            send_output_eq_status_json(self)
        elif path == "/api/status":
            send_status_json(self)
        elif path == "/api/update/check":
            send_update_check_json(self)
        elif path == "/api/update/status":
            send_update_status_json(self)
        elif path == "/api/owntone/outputs":
            send_owntone_outputs_json(self, STATE)
        elif path == "/api/owntone/outputs_state":
            send_owntone_outputs_state_json(self, STATE)
        elif path == "/api/owntone/ready":
            send_owntone_ready_json(self, STATE)
        elif path == "/owntone-restarting":
            send_owntone_restarting_page(self, STATE)
        elif path == "/rebooting":
            send_rebooting_page(self, STATE, AUTH)
        elif path == "/api/audio/status":
            send_audio_status_json(self, STATE)
        elif path == _GATEWAY_PREFIX:
            send_appliances_json(self, STATE)
        elif path.startswith(_GATEWAY_PREFIX + "/"):
            tail = path[len(_GATEWAY_PREFIX) + 1:]  # strip "/api/appliances/"
            parts = tail.split("/", 1)
            aid = parts[0]
            sub = parts[1] if len(parts) > 1 else ""
            if sub == "home":
                send_gateway_home_json(self, STATE, aid)
            elif sub == "equaliser":
                send_gateway_equaliser_json(self, STATE, aid)
            elif sub == "equaliser/status":
                send_gateway_eq_status_json(self, STATE, aid)
            else:
                self.send_error(404, "Not found")
        elif path.startswith("/api/dial/configure/"):
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            handle_dial_configure_get(self, path.rsplit("/", 1)[-1])
        elif path.startswith("/api/dial/pin_recovery/status/"):
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            handle_dial_pin_recovery_status(self, path.rsplit("/", 1)[-1])
        elif path.startswith("/api/dial/update/status/"):
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            handle_dial_update_status(self, path.rsplit("/", 1)[-1])
        else:
            self.send_error(404, "Not found")


    def do_POST(self):  # noqa: N802
        global initial_setup

        path = self._normalized_path()


        # --- 1) Auth verify ---
        if path == "/api/auth/verify":
            body = self._read_post_body_bytes()
            if body is None:
                return  # error already sent
            if not body:
                self.send_error(400, "Missing request body")
                return
            AUTH.handle_auth_verify(self, body)
            return

        # --- 2) Read body once (may be empty) ---
        body_bytes = self._read_post_body_bytes()
        if body_bytes is None:
            return  # error already sent
        try:
            body_str = body_bytes.decode("utf-8")
        except UnicodeDecodeError:
            self.send_error(400, "Request body is not valid UTF-8")
            return

        # Normalize content-type (ignore charset, etc.)
        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()

        # --- 3) Parse body (if any) ---
        form = {}
        json_obj = None

        if body_str:
            if content_type == "application/x-www-form-urlencoded":
                # parse_qs -> dict[str, list[str]]
                form = parse_qs(body_str)

            elif content_type == "application/json":
                try:
                    json_obj = json.loads(body_str)
                except json.JSONDecodeError:
                    self.send_error(400, "Invalid JSON")
                    return

            else:
                # Unknown content type; leave as raw body_str
                pass

        # ── UUID-auth dial endpoints (no session/CSRF required) ───────────
        if path in ("/api/dial/volume", "/api/dial/mute"):
            if content_type == "application/json" and body_str and not isinstance(json_obj, dict):
                self.send_error(400, "JSON object required")
                return

        if path == "/api/dial/volume":
            send_dial_volume_post_json(self, STATE, json_obj if isinstance(json_obj, dict) else {})
            return

        if path == "/api/dial/mute":
            send_dial_mute_post_json(self, STATE, json_obj if isinstance(json_obj, dict) else {})
            return

        # ── Federation routes (bearer-token protected, no browser CSRF) ──────
        if path.startswith(_FEDERATION_PREFIX):
            self._dispatch_federation("POST", path, body_str)
            return

        # For all remaining JSON routes, a non-object top-level value is malformed.
        if content_type == "application/json" and body_str and not isinstance(json_obj, dict):
            self.send_error(400, "JSON object required")
            return

        # --- 4) CSRF: accept header OR body (form/json) ---
        token_from_header = self.headers.get("X-CSRF-Token", "") or ""

        token_from_body = ""
        if form:
            token_from_body = (form.get("csrf_token") or [""])[0]
        elif isinstance(json_obj, dict):
            token_from_body = str(json_obj.get("csrf_token") or "")

        csrf_token = token_from_header or token_from_body

        if not AUTH.validate_csrf(self, csrf_token):
            if path in ("/setup", "/owntone-setup", "/logs", "/service"):
                self._redirect_with_error_flash("Settings not saved, please try again")
            else:
                self.send_error(403, "CSRF validation failed")
            return

        # --- 5) Route: enforce body only where needed ---
        if path.startswith(_GATEWAY_PREFIX + "/"):
            tail = path[len(_GATEWAY_PREFIX) + 1:]
            parts = tail.split("/", 1)
            aid = parts[0]
            sub = parts[1] if len(parts) > 1 else ""
            if sub == "output":
                if not body_str:
                    self.send_error(400, "Missing request body")
                    return
                send_gateway_output_json(self, STATE, aid, body_str)
            elif sub == "equaliser/config":
                if not body_str:
                    self.send_error(400, "Missing request body")
                    return
                send_gateway_eq_config_json(self, STATE, aid, body_str)
            elif sub == "equaliser/reset":
                send_gateway_eq_reset_json(self, STATE, aid)
            else:
                self.send_error(404, "Not found")

        elif path == "/api/output":
            if not body_str:
                self.send_error(400, "Missing request body")
                return

            handle_output_update(self, STATE, body_str)

        elif path == "/api/input_eq":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            if not body_str:
                self.send_error(400, "Missing request body")
                return
            handle_live_input_eq_update(self, STATE, body_str)

        elif path == "/api/input_gain":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            if not body_str:
                self.send_error(400, "Missing request body")
                return
            handle_live_input_gain_update(self, STATE, body_str)

        elif path == "/setup":
            if not AUTH.require_authenticated_if_pin_enabled(self, redirect_path="/setup"):
                return
            if not body_str:
                self.send_error(400, "Missing request body")
                return
            handle_setup_post(self, STATE, AUTH, body_str)
            with _setup_lock:
                initial_setup = 0

        elif path == "/owntone-setup":
            if not AUTH.require_authenticated_if_pin_enabled(self, redirect_path="/owntone-setup"):
                return
            if not body_str:
                self.send_error(400, "Missing request body")
                return
            handle_owntone_setup_post(self, STATE, AUTH, body_str)
            with _setup_lock:
                if initial_setup == 1:
                    initial_setup = 2

        elif path == "/logs":
            if not AUTH.require_authenticated_if_pin_enabled(self, redirect_path="/logs"):
                return
            if not body_str:
                self.send_error(400, "Missing request body")
                return
            handle_logs_post(self, STATE, body_str)

        elif path == "/api/output_eq/config":
            if not body_str:
                self.send_error(400, "Missing request body")
                return
            send_output_eq_config_json(self, STATE, body_str)

        elif path == "/api/output_eq/reset":
            send_output_eq_reset_json(self, STATE)

        elif path == "/api/service/reset":
            if not body_str:
                self.send_error(400, "Missing request body")
                return
            send_service_reset_json(self, STATE, body_str)

        elif path == "/api/service/config":
            if not body_str:
                self.send_error(400, "Missing request body")
                return
            send_service_config_json(self, STATE, body_str)

        elif path == "/api/update/apply":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            self._start_update_apply()

        elif path == "/api/pin/change":
            if not body_str:
                self.send_error(400, "Missing request body")
                return
            AUTH.handle_pin_change(self, body_bytes)

        elif path == "/api/reboot":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            reboot_system("UserRequestNormal", delay_s=3)
            send_json(self, 200, {"ok": True})

        elif path == "/api/factory-reset":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            handle_factory_reset_post(self, STATE, AUTH)

        elif path in ("/api/dial/authorize", "/api/dial/revoke", "/api/dial/configure",
                      "/api/dial/pin_recovery/complete"):
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            dispatch_dial_management_post(self, path, json_obj)

        elif path.startswith("/api/dial/update/") and len(path) > len("/api/dial/update/"):
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            handle_dial_update_post(self, path.rsplit("/", 1)[-1])

        else:
            self.send_error(404, "Not found")


def _scan_monitor_devices_loop() -> None:
    """Background loop: refresh the list of visible ALSA capture devices every 15 s."""
    while not stop_flag.is_set():
        try:
            devices = get_available_monitor_devices()
        except Exception as e:
            logging.error(
                "Web UI: error scanning autostream_monitor devices: %s", e,
            )
            devices = []

        STATE.set_monitor_devices(devices)
        time.sleep(15)


def start_webui_background(config_path: str, host: str = "127.0.0.1", port: int = 8080) -> threading.Thread:
    """Start the configuration web UI on a background thread."""
    global STATE, AUTH

    STATE = WebUIState(config_path, STATE_PATH)
    AUTH = AuthManager(
        config_path=config_path,
        state_path=STATE_PATH,
        style_css=STYLE_CSS + "\n" + LICENSE_BANNER_CSS,
        banner_html=BANNER_HTML,
        nav_html=build_nav_bar_html("setup"),
        title="autostream",
    )

    def _reconcile_announcement_loop() -> None:
        """Periodically reconcile the _autostream._tcp service file (every 60 s)."""
        from autostream_appliances import reconcile_appliance_announcement
        from autostream_config import load_config, parse_config
        from autostream_webui_common import get_app_version
        while not stop_flag.is_set():
            stop_flag.wait(60)
            if stop_flag.is_set():
                break
            try:
                cfg = parse_config(load_config(STATE.config_path))
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
            from autostream_config import load_config, parse_config
            from autostream_webui_common import get_app_version

            start_dial_scanner()
            start_appliance_scanner()

            scanner_thread = threading.Thread(
                target=_scan_monitor_devices_loop, daemon=True,
            )
            scanner_thread.start()

            # Initial announcement reconciliation (best-effort; errors are logged)
            try:
                cfg = parse_config(load_config(config_path))
                reconcile_appliance_announcement(
                    get_app_version(), cfg.webui.advertise_appliance
                )
            except Exception:
                logging.debug("startup reconcile_announcement: error", exc_info=True)

            reconcile_thread = threading.Thread(
                target=_reconcile_announcement_loop, daemon=True,
            )
            reconcile_thread.start()

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
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} PATH_TO_CONFIG.json")
        sys.exit(1)

    config_path = sys.argv[1]
    # Initialize globals for local execution
    STATE = WebUIState(config_path, STATE_PATH)
    AUTH = AuthManager(
        config_path=config_path,
        state_path=STATE_PATH,
        style_css=STYLE_CSS + "\n" + LICENSE_BANNER_CSS,
        banner_html=BANNER_HTML,
        nav_html=build_nav_bar_html("setup"),
        title="autostream",
    )
    run_autostream(config_path, start_webui=start_webui_background)
