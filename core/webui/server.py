#!/usr/bin/env python3
"""webui/server.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The autostream web server: the request handler and the thread that serves it.

Listens on 127.0.0.1:8080. NGINX is recommended (as a reverse proxy) to provide access to the webui
on the network generally e.g. on port 80.

Every module the route table names is imported below, at module level, so
that importing this module loads the whole table and runs every
import-time registration (service and settings schema rows, the Setup page's
cards) before the first request. Nothing is imported while serving.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional
from urllib.parse import parse_qs, quote, urlparse

from autostream_auth import AuthManager, FLASH_COOKIE_NAME
import autostream_commissioning as commissioning
from autostream_settings import SettingsView

import webui.browser.about
import webui.browser.align
import webui.browser.api_owntone
import webui.browser.api_service
import webui.browser.api_settings
import webui.browser.auth
import webui.browser.equaliser
import webui.browser.first_boot
import webui.browser.home
import webui.browser.home_api
import webui.browser.logs
import webui.browser.owntone
import webui.browser.post_handlers
import webui.browser.rebooting
import webui.browser.service
import webui.browser.setup.page
import webui.dial.api
import webui.dial.management
import webui.peer.federation
import webui.peer.gateway
import webui.repeat
import webui.system.bluetooth
import webui.system.network
import webui.system.power
import webui.system.sdcard
import webui.system.updates
import webui.routes

from webui import common, session_state
from webui.peer import federation
from webui.routes import dispatch as _route_dispatch, is_poll_log as _route_is_poll_log
from webui.system import updates

# The modules the route table names, in the order they are imported above.
_ROUTE_MODULES = (
    webui.browser.about,
    webui.browser.align,
    webui.browser.api_owntone,
    webui.browser.api_service,
    webui.browser.api_settings,
    webui.browser.auth,
    webui.browser.equaliser,
    webui.browser.first_boot,
    webui.browser.home,
    webui.browser.home_api,
    webui.browser.logs,
    webui.browser.owntone,
    webui.browser.post_handlers,
    webui.browser.rebooting,
    webui.browser.service,
    webui.browser.setup.page,
    webui.dial.api,
    webui.dial.management,
    webui.peer.federation,
    webui.peer.gateway,
    webui.repeat,
    webui.system.bluetooth,
    webui.system.network,
    webui.system.power,
    webui.system.sdcard,
    webui.system.updates,
)

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
# log_message() falls back to webui.routes.is_poll_log() for every path.
_POLLING_LOG_PATHS: tuple = ()


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

        Do NOT use _get_client_ip() here -- it trusts proxy headers intentionally
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
        return commissioning.is_commissioning_required(session_state.STATE.config_path, session_state.STATE.state_path)

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
        """Accept an update-apply request and run it in the background."""
        updates.start_update_apply(self)

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
        """Dispatch a federation API request before browser auth/CSRF."""
        federation.dispatch(self, method, path, body_str)

    def do_GET(self):  # noqa: N802
        path = self._normalized_path()

        # Route-table dispatch (see webui/routes.py). This
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
                step = commissioning.required_first_boot_step(session_state.STATE.config_path, session_state.STATE.state_path)
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
        if session_state.AUTH.requires_auth(path) and not session_state.AUTH.is_authenticated(self.headers):
            session_state.AUTH.redirect_to_auth(self, next_path=self.path)
            return

        # Ensure UI session / CSRF exists
        self._csrf_token = session_state.AUTH.ensure_session(self)

        self.send_error(404, "Not found")

    def do_POST(self):  # noqa: N802
        path = self._normalized_path()

        # Route-table dispatch (see webui/routes.py). This
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
        if not session_state.AUTH.validate_csrf(self, csrf_token):
            if path in ("/setup", "/owntone-setup", "/service"):
                self._redirect_with_error_flash("Settings not saved, please try again")
            elif path.startswith("/api/"):
                fresh_csrf = session_state.AUTH.ensure_session(self)
                common.send_json(self, 403, {
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
                common.send_json(self, 409, {"ok": False, "error": "appliance_unconfigured"})
                return
        else:
            if path in ("/first-boot/owntone/continue", "/first-boot/appliance/finish"):
                common.send_json(self, 409, {"ok": False, "error": "already_configured"})
                return

        self.send_error(404, "Not found")

    def do_PUT(self):  # noqa: N802
        path = self._normalized_path()

        # Route-table dispatch (see webui/routes.py).
        # PUT /api/log-level (scheme="loopback_aware") is the only PUT
        # route the server has ever recognized.
        if _route_dispatch(self, "PUT", path):
            return

        self.send_error(404, "Not found")



@dataclass(frozen=True)
class WebUIDeps:
    """What the web server needs from the process that starts it.

    ``settings`` must be a read-only view of the coordinator's settings, never
    the store. ``startup``, when given, is called once with the web state on
    the server thread, before the server starts serving.
    """

    config_path: str
    state_path: str
    settings: SettingsView
    startup: Optional[Callable[[session_state.WebUIState], None]] = None
    host: str = "127.0.0.1"
    port: int = 8080


def start_server(deps: WebUIDeps) -> threading.Thread:
    """Start the configuration web UI on a daemon thread and return it."""
    if not isinstance(deps.settings, SettingsView):
        raise TypeError("start_server needs a settings view, not the settings store")
    session_state.STATE = session_state.WebUIState(deps.config_path, deps.state_path, settings=deps.settings)
    session_state.AUTH = AuthManager(
        config_path=deps.config_path,
        state_path=deps.state_path,
    )

    def _serve() -> None:
        try:
            if deps.startup is not None:
                deps.startup(session_state.STATE)

            # Prime the app-version cache before the HTTP server starts so the
            # first /api/about/system request never incurs the helper timeout.
            updates.get_app_version()

            httpd = ThreadingHTTPServer((deps.host, deps.port), ConfigWebHandler)
            logging.info("Web UI available at http://%s:%d", deps.host, deps.port)
            httpd.serve_forever()
        except Exception:
            logging.exception("Web UI server error")
            raise

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    return thread
