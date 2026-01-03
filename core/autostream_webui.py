#!/usr/bin/env python3
"""autostream_webui.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Front-end for autostream. This script will start autostream_core.py and should be used to
start autostream.

Listens on 127.0.0.1:8080. NGINX is recommended (as a reverse proxy) to provide access to the webui
on the network generally e.g. on port 80.

Usage:

# python3 autostream_webui.py /location/to/autostream.ini

"""

import logging
import os
import sys
import threading
import time
from typing import Optional
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import re
import json

from autostream_core import (
    run_autostream,
)

from autostream_sysutils import (
    reboot_system,
)

from autostream_webui_assets import (
    STYLE_CSS,
    LICENSE_BANNER_CSS,
    BANNER_HTML,
)

from autostream_auth import AuthManager
from autostream_webui_state import WebUIState
import autostream_webui_pages as pages

from autostream_config import unconfigured

# Global state
STATE: Optional[WebUIState] = None
AUTH: Optional[AuthManager] = None

try:
    import sounddevice as sd
except ImportError:  # sounddevice is optional
    sd = None

# initial_setup values:
# 0 - not in initial setup
# 1 - initial setup needed and page 1 not complete
# 2 - imitial setup needed and page 1 completed (so user on page 2)
initial_setup = 0


def restart_self_soon(delay: float = 1.0) -> None:
    """Restart this script in-place after a short delay."""
    def _do_restart() -> None:
        time.sleep(delay)
        logging.info("Restarting self...")
        os.execv(sys.executable, [sys.executable, *sys.argv])

    threading.Thread(target=_do_restart, daemon=True).start()

class ConfigWebHandler(BaseHTTPRequestHandler):
    """Simple HTTP interface (port 8080) to view and edit autostream.ini."""

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
            if length > self.MAX_POST_SIZE:
                self.send_error(413, "Request body too large")
                return None
            return self.rfile.read(length)
        except Exception as e:
            logging.error("Error reading POST body: %s", e)
            return None

    def _normalized_path(self) -> str:
        # Strip query string and trailing slash
        path = urlparse(self.path).path or "/"
        if path.endswith("/") and path != "/":
            path = path[:-1]
        return path

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
        """Flushes any pending cookies from the AuthManager."""
        cookie = getattr(self, "_pending_auth_cookie", None)
        if cookie:
            self.send_header("Set-Cookie", cookie)
            self._pending_auth_cookie = None
        super().end_headers()

    def do_GET(self):  # noqa: N802
        global initial_setup
        
        path = self._normalized_path()

        # If INI missing, force setup except for the setup/auth endpoints + auth verify API
        if unconfigured(STATE.config_path):
            if initial_setup == 0:
                initial_setup = 1
            allowed = (
                path.startswith("/auth")
                or path.startswith("/api/auth/")
                or path.startswith("/api/owntone/outputs")
                or path.startswith("/api/owntone/outputs_state")
                or path.startswith("/api/owntone/ready")
                or path.startswith("/owntone-setup")
                or path.startswith("/owntone-restarting")
                or path.startswith("/logs")
            )
            if initial_setup == 2:
                allowed = allowed or path.startswith("/setup") 
            if not allowed:
                self.send_response(302)
                self.send_header("Location", "/owntone-setup")
                self.end_headers()
                return
        else:
            # Config exists, so we are not in initial setup anymore
            initial_setup = 0

        # Serve auth page
        if path == "/auth":
            query = urlparse(self.path).query
            AUTH.handle_auth_get(self, query)
            return

        # Gate protected pages
        if AUTH.requires_auth(path) and not AUTH.is_authenticated(self.headers):
            AUTH.redirect_to_auth(self, next_path=self.path)
            return

        # Ensure UI session / CSRF exists
        AUTH.ensure_session(self)

        # page handlers
        query = urlparse(self.path).query
        qs = parse_qs(query)
        msg = (qs.get("msg") or [""])[0]

        if path == "/":
            pages.send_airplay_page(self, STATE, AUTH, flash_msg=msg)
        elif path == "/setup":
            pages.send_setup_page(self, STATE, AUTH, flash_msg=msg)
        elif path == "/owntone-setup":
            pages.send_owntone_setup_page(self, STATE, AUTH, flash_msg=msg)
        elif path == "/about":
            pages.send_about_page(self, STATE)
        elif path == "/logs":
            pages.send_logs_page(self, STATE)
        elif path == "/api/status":
            pages.send_status_json(self)
        elif path == "/api/update/check":
            pages.send_update_check_json(self)
        elif path == "/api/update/status":
            pages.send_update_status_json(self, STATE)
        elif path == "/api/owntone/outputs":
            pages.send_owntone_outputs_json(self, STATE)
        elif path == "/api/owntone/outputs_state":
            pages.send_owntone_outputs_state_json(self, STATE)
        elif path == "/api/owntone/ready":
            pages.send_owntone_ready_json(self, STATE)
        elif path == "/owntone-restarting":
            pages.send_owntone_restarting_page(self, STATE)
        elif path == "/api/log_file":
            pages.send_log_file(self, STATE)
        else:
            self.send_error(404, "Not found")


    def do_POST(self):  # noqa: N802
        global initial_setup

        path = self._normalized_path()

        # --- 1) Special-case auth verify (kept close to your original) ---
        if path == "/api/auth/verify":
            body = self._read_post_body_bytes()
            if body:
                AUTH.handle_auth_verify(self, body)
            return

        # --- 2) Read body once (may be empty) ---
        body_bytes = self._read_post_body_bytes() or b""
        body_str = body_bytes.decode("utf-8", errors="ignore")

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

        # --- 4) CSRF: accept header OR body (form/json) ---
        token_from_header = self.headers.get("X-CSRF-Token", "") or ""

        token_from_body = ""
        if form:
            token_from_body = (form.get("csrf_token") or [""])[0]
        elif isinstance(json_obj, dict):
            token_from_body = str(json_obj.get("csrf_token") or "")

        csrf_token = token_from_header or token_from_body

        if not AUTH.validate_csrf(self, csrf_token):
            self.send_error(403, "CSRF validation failed")
            return

        # --- 5) Route: enforce body only where needed ---
        if path == "/api/output":
            # If your frontend sends JSON for /api/output, enforce it.
            # If you still sometimes send form bodies, you can relax this.
            if not body_str:
                self.send_error(400, "Missing request body")
                return

            # Option A (minimal change): keep existing handler signature
            pages.handle_output_update(self, STATE, body_str)

            # Option B (recommended, if you want): pass parsed JSON too
            # pages.handle_output_update(self, STATE, body_str, json_obj=json_obj, form=form)

        elif path == "/setup":
            if not body_str:
                self.send_error(400, "Missing request body")
                return
            pages.handle_setup_post(self, STATE, AUTH, body_str)
            initial_setup = 0

        elif path == "/owntone-setup":
            if not body_str:
                self.send_error(400, "Missing request body")
                return
            pages.handle_owntone_setup_post(self, STATE, AUTH, body_str)
            if initial_setup == 1:
                initial_setup = 2

        elif path == "/api/update/apply":
            # Body optional
            self._start_update_apply()

        elif path == "/api/reboot":
            # Body optional
            # Goes via autostream-admin (sudo) through autostream_sysutils.reboot_system()
            reboot_system("UserRequestNormal")
            pages.send_json(self, 200, {"ok": True})

        else:
            self.send_error(404, "Not found")


def start_webui_background(config_path: str, host: str = "127.0.0.1", port: int = 8080) -> None:
    """Start the configuration web UI on a background thread."""
    global STATE, AUTH
    
    STATE = WebUIState(config_path)
    AUTH = AuthManager(
        style_css=STYLE_CSS + "\n" + LICENSE_BANNER_CSS,
        banner_html=BANNER_HTML,
        title="autostream",
    )

    def canonical_name(dev: dict) -> str:
        """Strip the volatile (hw:X,Y) suffix from PortAudio device names."""
        return re.sub(r"\s*\(hw:\d+,\d+\)", "", dev.get("name", ""))

    def _serve() -> None:
        try:
            def _scan_devices_loop() -> None:
                while True:
                    devices = []
                    try:
                        if sd:
                            all_devs = sd.query_devices()
                            for idx, dev in enumerate(all_devs):
                                if dev.get("max_input_channels", 0) <= 0:
                                    continue
                                name = dev.get("name", f"Device {idx}")
                                lname = name.lower()
                                if "hw:" not in lname and "usb" not in lname:
                                    continue
                                devices.append(canonical_name(dev))
                    except Exception as e:
                        logging.error("Web UI: error scanning sounddevice devices: %s", e)

                    STATE.set_pcm_devices(devices)
                    time.sleep(15)

            scanner_thread = threading.Thread(target=_scan_devices_loop, daemon=True)
            scanner_thread.start()
            
            httpd = ThreadingHTTPServer((host, port), ConfigWebHandler)
            logging.info("Web UI available at http://%s:%d", host, port)
            httpd.serve_forever()
        except Exception as e:
            logging.error("Web UI server error: %s", e)

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} PATH_TO_CONFIG.ini")
        sys.exit(1)

    config_path = sys.argv[1]
    # Initialize globals for local execution
    STATE = WebUIState(config_path)
    AUTH = AuthManager(
        style_css=STYLE_CSS + "\n" + LICENSE_BANNER_CSS,
        banner_html=BANNER_HTML,
        title="autostream",
    )
    run_autostream(config_path, start_webui=start_webui_background)
