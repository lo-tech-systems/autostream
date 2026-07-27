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
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse, unquote, quote
import json

from autostream_core import (
    get_available_monitor_devices,
    run_autostream,
    stop_flag,
)

from autostream_bluetooth_client import BluetoothClient, bluetooth_installed

from autostream_sysutils import (
    atomic_write_file,
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
from autostream_webui_common import build_nav_bar_html
from autostream_webui_page_about import send_about_page, send_about_system_json
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
from autostream_webui_page_setup import send_setup_page
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
_POLLING_LOG_PATHS = (
    "/api/status",
    "/api/audio/status",
    "/api/owntone/outputs_state",
    "/api/owntone/outputs",
    "/api/appliances",
    "/api/network/status",
    "/api/playing-status",
    "/api/log-level",
)


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
# page. Owned by the "autostream" user (same as this process), so it can be
# written directly without going through sudo.
_UPDATE_RESULT_FILE = Path("/var/lib/autostream/update-result.env")


def _update_apply_mark_finished() -> None:
    global _update_apply_in_progress
    with _update_apply_lock:
        _update_apply_in_progress = False


def _write_update_apply_result(status: str, message: str) -> None:
    """Best-effort write of a webui-observed apply outcome into update-result.env.

    Only used for failures that happen before the installer itself has a
    chance to write anything (e.g. release staging failing, or the apply
    subprocess never returning). Once the installer is actually scheduled and
    starts, it immediately overwrites this file with STATUS=in_progress and
    then its own final result, so a write made here can only ever be visible
    for the (bounded) window before that happens — it can never mask a
    success that has already completed, because that success write always
    comes after and last.
    """
    run_at = datetime.now().astimezone().isoformat(timespec="seconds")
    safe_message = message.replace('"', "'")

    def _writer(fh) -> None:
        fh.write(f'LAST_RUN_AT="{run_at}"\n')
        fh.write(f'STATUS="{status}"\n')
        fh.write(f'MESSAGE="{safe_message}"\n')
        fh.write('PERCENT_COMPLETE=""\n')

    try:
        atomic_write_file(_UPDATE_RESULT_FILE, _writer)
    except Exception:
        logging.exception(
            "update apply: failed to write %s result to %s", status, _UPDATE_RESULT_FILE
        )


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
            # under way. Record "error" rather than "failure" to avoid
            # asserting a failure that may not have happened; if the apply
            # does go on to schedule the installer, that installer's first
            # write (STATUS=in_progress) supersedes this one, and this entry
            # is only ever visible for the window until it does.
            logging.error("update apply: timed out waiting for updater subprocess")
            _write_update_apply_result(
                "error",
                "Update status could not be confirmed after a timeout. "
                "Check back shortly before retrying.",
            )
            return
        except Exception as e:
            logging.error("update apply: background apply raised: %s", e)
            _write_update_apply_result("failure", f"Update failed to start: {e}")
            return

        if rc == 0:
            try:
                result = json.loads(out or "{}")
            except Exception:
                result = {"ok": True}
            if not result.get("ok", True):
                logging.error("update apply: updater reported failure: %s", result)
                _write_update_apply_result(
                    "failure", str(result.get("error") or "Update failed")
                )
            return

        try:
            result = json.loads(out or "{}")
            message = str(result.get("error") or "Update failed")
        except Exception:
            message = "Update failed"
        if err.strip():
            message = f"{message}: {err.strip()}"
        logging.error("update apply: updater exited rc=%s: %s", rc, message)
        _write_update_apply_result("failure", message)
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
        status the installer (and, for failures before the installer takes
        over, this background thread) writes to update-result.env.

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
        path = getattr(self, "path", "") or ""
        method = getattr(self, "command", "") or ""
        # /api/log-level is only high-frequency on GET (UI polling); a PUT is a
        # rare state change worth keeping visible at INFO.
        is_polling = any(path.startswith(p) for p in _POLLING_LOG_PATHS) and (
            not path.startswith("/api/log-level") or method == "GET"
        )
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

        # Unavailable during commissioning or when identity is missing
        if is_commissioning_required(STATE.config_path, STATE.state_path):
            send_json(self, 409, {"ok": False, "error": "appliance_unconfigured"})
            return
        if not get_appliance_id():
            send_json(self, 409, {"ok": False, "error": "appliance_unconfigured"})
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

        # Federation routes bypass browser auth/CSRF and commissioning redirect.
        if path.startswith(_FEDERATION_PREFIX):
            self._dispatch_federation("GET", path)
            return

        # Direct-local callers (loopback, no proxy headers) bypass browser auth
        # and commissioning redirect for playing-status and log-level reads.
        # This must come before the commissioning gate so the storage guard can
        # reach these APIs over loopback even during first-boot setup.
        if self._is_direct_local():
            if path == "/api/playing-status":
                send_playing_status_json(self)
                return
            if path == "/api/log-level":
                send_log_level_get_json(self, STATE)
                return

        # During commissioning, only permit auth and first-boot routes.
        if is_commissioning_required(STATE.config_path, STATE.state_path):
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
        # Parse type prefix from ?msg= parameter (mirrors flash cookie format for JS-side redirects).
        if msg:
            _colon = msg.find(":")
            if _colon > 0 and msg[:_colon] in ("error", "warning"):
                flash_type = msg[:_colon]
                msg = msg[_colon + 1:]

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
        elif path == "/first-boot/owntone":
            if not AUTH.require_authenticated_if_pin_enabled(self): return
            send_first_boot_owntone_page(self, STATE, AUTH)
        elif path == "/first-boot/appliance":
            if not AUTH.require_authenticated_if_pin_enabled(self): return
            send_first_boot_appliance_page(self, STATE, AUTH)
        elif path == "/about":
            send_about_page(self, STATE)
        elif path == "/api/about/system":
            send_about_system_json(self)
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
            send_update_check_json(self, STATE)
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
        elif path == "/api/log-level":
            send_log_level_get_json(self, STATE)
        elif path == "/api/playing-status":
            send_playing_status_json(self)
        elif path == "/api/network/status":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            send_network_status_json(self)
        elif path == "/api/settings":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            send_settings_get_json(self, STATE)
        elif path == "/api/bluetooth/status":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            send_bluetooth_status_json(self, STATE)
        elif path == "/api/bluetooth/scan_results":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            send_bluetooth_scan_results_json(self)
        elif path == "/api/bluetooth/pair_status":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            send_bluetooth_pair_status_json(self)
        elif path == _GATEWAY_PREFIX:
            send_appliances_json(self, STATE)
        elif path.startswith(_GATEWAY_PREFIX + "/"):
            tail = path[len(_GATEWAY_PREFIX) + 1:]  # strip "/api/appliances/"
            parts = tail.split("/", 1)
            aid = parts[0]
            sub = parts[1] if len(parts) > 1 else ""
            local_id = get_appliance_id() or ""
            if aid != local_id and not _effective_control_other_appliances(STATE):
                send_json(self, 403, {"ok": False, "error": "control_disabled"})
            elif sub == "home":
                send_gateway_home_json(self, STATE, aid)
            elif sub == "equaliser":
                send_gateway_equaliser_json(self, STATE, aid)
            elif sub == "equaliser/status":
                send_gateway_eq_status_json(self, STATE, aid)
            else:
                self.send_error(404, "Not found")
        elif path.startswith(_REMOTE_PAGE_PREFIX):
            tail = path[len(_REMOTE_PAGE_PREFIX):]  # e.g. "aabbccdd1122334455aa" or "aabbccdd1122334455aa/equaliser"
            parts = tail.split("/", 1)
            aid = parts[0]
            sub = parts[1] if len(parts) > 1 else ""
            if not _APPLIANCE_ID_RE.match(aid):
                self.send_error(404, "Not found")
            else:
                local_id = get_appliance_id() or ""
                if aid == local_id:
                    # Canonical redirect for bound appliance
                    location = "/equaliser" if sub == "equaliser" else "/"
                    self.send_response(302)
                    self.send_header("Location", location)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                elif not _effective_control_other_appliances(STATE):
                    self._redirect_with_error_flash(
                        "Controlling other appliances is disabled.", "/"
                    )
                elif sub == "equaliser":
                    send_remote_equaliser_page(self, STATE, aid)
                else:
                    send_remote_home_page(self, STATE, aid)
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
        elif path.startswith("/api/dial/screen/settings/"):
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            handle_dial_screen_settings_get(self, path.rsplit("/", 1)[-1])
        else:
            self.send_error(404, "Not found")


    def do_POST(self):  # noqa: N802
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
        # /api/dial/volume and /api/dial/mute: return HTTP 400 for non-object
        # JSON bodies so that malformed requests are rejected before UUID auth.
        # /api/dial/status: non-object JSON bodies are passed as {} to the
        # handler, which returns HTTP 403 for missing dial_id (per spec §3.4).
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

        if path == "/api/dial/status":
            send_dial_status_post_json(self, STATE, json_obj if isinstance(json_obj, dict) else {})
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
            if path in ("/setup", "/owntone-setup", "/service"):
                self._redirect_with_error_flash("Settings not saved, please try again")
            else:
                self.send_error(403, "CSRF validation failed")
            return

        # --- 5) Commissioning gate ---
        _is_commissioning = is_commissioning_required(STATE.config_path, STATE.state_path)
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

        # --- 6) Route: enforce body only where needed ---
        if path.startswith(_GATEWAY_PREFIX + "/"):
            tail = path[len(_GATEWAY_PREFIX) + 1:]
            parts = tail.split("/", 1)
            aid = parts[0]
            sub = parts[1] if len(parts) > 1 else ""
            local_id = get_appliance_id() or ""
            if aid != local_id and not _effective_control_other_appliances(STATE):
                send_json(self, 403, {"ok": False, "error": "control_disabled"})
            elif sub == "output":
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
            elif sub == "repeat":
                if not body_str:
                    self.send_error(400, "Missing request body")
                    return
                send_gateway_repeat_json(self, STATE, aid, body_str)
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

        elif path == "/api/repeat":
            # Deliberately NOT auth-gated: the repeat button lives on the
            # home page, which is public consumer surface (like /api/output's
            # enable/volume controls just above). Arm/disarm is a playback
            # action of the same sensitivity class as toggling an output --
            # requiring a PIN here would make the button 401 for any visitor
            # who had not opened the (gated) setup pages, and silently after
            # every autostream restart (in-memory sessions).
            if not body_str:
                self.send_error(400, "Missing request body")
                return
            send_repeat_post_json(self, STATE, body_str)

        elif path == "/setup":
            if is_commissioning_required(STATE.config_path, STATE.state_path):
                if not AUTH.require_authenticated_if_pin_enabled(self, redirect_path="/setup"):
                    return
                if not body_str:
                    self.send_error(400, "Missing request body")
                    return
                handle_setup_post(self, STATE, AUTH, body_str)
            else:
                send_json(self, 405, {"ok": False, "error": "form_post_disabled"})

        elif path == "/owntone-setup":
            send_json(self, 405, {"ok": False, "error": "form_post_disabled"})

        elif path == "/first-boot/owntone/continue":
            if not AUTH.require_authenticated_if_pin_enabled(self): return
            handle_first_boot_continue_post(self, STATE, AUTH, body_str)

        elif path == "/first-boot/appliance/finish":
            if not AUTH.require_authenticated_if_pin_enabled(self): return
            handle_first_boot_finish_post(self, STATE, AUTH, body_str)

        elif path == "/api/settings":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            if not isinstance(json_obj, dict):
                self.send_error(400, "JSON object required")
                return
            send_settings_post_json(self, STATE, json_obj)

        elif path == "/api/settings/hostname":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            send_hostname_post_json(self, STATE, body_str)

        elif path == "/api/settings/advertisement":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            send_advertisement_post_json(self, STATE, body_str)

        elif path == "/api/settings/auto-update":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            send_auto_update_post_json(self, STATE, body_str)

        elif path == "/api/settings/mdns-grace-period":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            send_settings_mdns_grace_period_json(self, STATE, body_str)

        elif path == "/api/settings/save":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            send_save_now_json(self, STATE)

        elif path == "/api/owntone/output-visibility":
            if not AUTH.require_authenticated_if_pin_enabled(self): return
            send_owntone_output_visibility_json(self, STATE, body_str)

        elif path == "/api/owntone/output-mode":
            if not AUTH.require_authenticated_if_pin_enabled(self): return
            send_owntone_output_mode_json(self, STATE, body_str)

        elif path == "/api/owntone/output-offset":
            if not AUTH.require_authenticated_if_pin_enabled(self): return
            send_owntone_output_offset_json(self, STATE, body_str)

        elif path == "/api/owntone/uncompressed-audio":
            if not AUTH.require_authenticated_if_pin_enabled(self): return
            send_owntone_uncompressed_json(self, STATE, body_str)

        elif path == "/api/owntone/buffered-audio":
            if not AUTH.require_authenticated_if_pin_enabled(self): return
            send_owntone_buffered_audio_json(self, STATE, body_str)

        elif path == "/api/owntone/start-buffer":
            if not AUTH.require_authenticated_if_pin_enabled(self): return
            send_owntone_start_buffer_json(self, STATE, body_str)

        elif path == "/api/owntone/grace-period":
            if not AUTH.require_authenticated_if_pin_enabled(self): return
            send_owntone_grace_period_json(self, STATE, body_str)

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
            if not _settings_save_barrier(STATE):
                send_json(self, 200, {"ok": False, "error": "Settings could not be saved before update"})
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
            if not _settings_save_barrier(STATE):
                send_json(self, 200, {"ok": False, "error": "Settings could not be saved before reboot"})
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

        elif path == "/api/dial/screen/settings":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            handle_dial_screen_settings_post(self, json_obj if isinstance(json_obj, dict) else {})

        elif path == "/api/network/setup":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            send_network_setup_json(self, json_obj)

        elif path == "/api/network/roaming":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            send_network_roaming_json(self, json_obj)

        elif path == "/api/bluetooth/scan":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            send_bluetooth_scan_post_json(self, json_obj)

        elif path == "/api/bluetooth/pair":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            send_bluetooth_pair_post_json(self, json_obj)

        elif path == "/api/bluetooth/forget":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            send_bluetooth_forget_post_json(self)

        elif path == "/api/bluetooth/services":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            send_bluetooth_services_post_json(self, json_obj)

        elif path == "/api/bluetooth/onboard":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            send_bluetooth_onboard_post_json(self, json_obj)

        elif path == "/api/bluetooth/buffer":
            if not AUTH.require_authenticated_if_pin_enabled(self):
                return
            send_bluetooth_buffer_post_json(self, json_obj)

        else:
            self.send_error(404, "Not found")

    def do_PUT(self):  # noqa: N802
        path = self._normalized_path()

        if path != "/api/log-level":
            self.send_error(404, "Not found")
            return

        # Read and parse the body
        body_bytes = self._read_post_body_bytes()
        if body_bytes is None:
            return  # error already sent
        try:
            body_str = body_bytes.decode("utf-8")
        except UnicodeDecodeError:
            self.send_error(400, "Request body is not valid UTF-8")
            return

        ct = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ct != "application/json":
            self.send_error(415, "Content-Type must be application/json")
            return

        if not body_str:
            self.send_error(400, "Missing request body")
            return

        try:
            json_obj = json.loads(body_str)
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
            return

        if not isinstance(json_obj, dict):
            self.send_error(400, "JSON object required")
            return

        # Classify the request origin.
        if self._is_direct_local():
            # System caller (loopback, no proxy headers, JSON content-type).
            send_log_level_put_json(self, STATE, json_obj, "system")
            return

        # Browser-proxied path: require CSRF, but not PIN authentication.
        token_from_header = self.headers.get("X-CSRF-Token", "") or ""
        token_from_body = str(json_obj.get("csrf_token") or "")
        csrf_token = token_from_header or token_from_body

        if not AUTH.validate_csrf(self, csrf_token):
            send_browser_api_error(self, 403, "CSRF validation failed")
            return

        send_log_level_put_json(self, STATE, json_obj, "user")


def _scan_monitor_devices_loop() -> None:
    """Background loop: refresh visible ALSA capture devices (and, when
    the Bluetooth-input subsystem is installed, the autostream_bluetooth
    daemon status) every 15 s.
    """
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
    global STATE, AUTH

    if settings is None:
        settings = SettingsStore(config_path)
    STATE = WebUIState(config_path, STATE_PATH, settings=settings)
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
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} PATH_TO_CONFIG.json")
        sys.exit(1)

    config_path = sys.argv[1]
    run_autostream(config_path, start_webui=start_webui_background)
