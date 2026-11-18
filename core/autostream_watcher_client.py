"""autostream_watcher_client.py -- the Web UI's bounded client for the root Wi-Fi watcher.

A leaf module (standard library only).  The watcher listens on a localhost
control interface; this module sends it bounded JSON requests to a fixed set of
paths and forwards the application log level to it.
"""
from __future__ import annotations

import json
import logging
import os


# The watcher's localhost control interface.  The normal Web UI never executes
# nmcli or reads/writes network.json directly; it proxies bounded JSON requests
# to the root watcher and supplies the per-boot control token from the
# root:autostream-readable token file.
WATCHER_CONTROL_BASE = os.environ.get(
    "APP_WATCHER_CONTROL_BASE", "http://127.0.0.1:9080"
)
WATCHER_CONTROL_TOKEN_PATH = os.environ.get(
    "APP_WIFI_CONTROL_TOKEN", "/run/autostream/wifi-control.token"
)
WATCHER_CONTROL_HEADER = "X-Autostream-Wifi-Control"
_WATCHER_TIMEOUT = 4.0


def _read_watcher_control_token() -> str:
    try:
        with open(WATCHER_CONTROL_TOKEN_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def watcher_request(method: str, path: str, body: dict | None = None):
    """Perform a bounded request to a *fixed* watcher control path.

    Only the known fixed paths are permitted; arbitrary paths/commands are never
    forwarded.  Uses the Python standard library only.  Returns (status, data)
    or raises on transport failure.
    """
    import urllib.request as _ur
    import urllib.error as _ue

    if path not in ("/network_status", "/network_control", "/version"):
        raise ValueError("disallowed watcher path")
    token = _read_watcher_control_token()
    url = WATCHER_CONTROL_BASE + path
    data = None
    headers = {WATCHER_CONTROL_HEADER: token}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = _ur.Request(url, data=data, method=method, headers=headers)
    try:
        with _ur.urlopen(req, timeout=_WATCHER_TIMEOUT) as resp:
            raw = resp.read()
            status = resp.status
    except _ue.HTTPError as e:
        raw = e.read()
        status = e.code
    try:
        parsed = json.loads(raw) if raw else {}
    except ValueError:
        parsed = {}
    return status, parsed


_WATCHER_LEVEL_MAP = {
    "spam": "debug", "debug": "debug",
    "info": "info",
    "warning": "warning", "log": "warning", "fatal": "warning",
}
_WATCHER_DEBUG_TTL_SECONDS = 3600


def forward_log_level_to_watcher(app_level: str) -> bool:
    """Best-effort: map and forward *app_level* to the watcher's control API.

    Maps the app's log-level vocabulary to the watcher's runtime vocabulary
    (warning/info/debug) and POSTs a set_log_level action to the watcher's
    /network_control endpoint. A forwarded debug level carries the watcher's
    maximum TTL (1 hour); info/warning are forwarded without a TTL. Never
    raises: any failure (unknown level, missing token, transport error,
    non-success response) is logged and reported as False so a forwarding
    failure never blocks the app-level change that triggered it.
    """
    watcher_level = _WATCHER_LEVEL_MAP.get(str(app_level or "").strip().lower())
    if watcher_level is None:
        logging.warning("forward_log_level_to_watcher: unknown app level %r", app_level)
        return False

    if not _read_watcher_control_token():
        logging.debug("forward_log_level_to_watcher: no watcher control token available")
        return False

    body: dict = {"action": "set_log_level", "level": watcher_level}
    if watcher_level == "debug":
        body["ttl_seconds"] = _WATCHER_DEBUG_TTL_SECONDS

    try:
        status, data = watcher_request("POST", "/network_control", body)
    except Exception as e:
        logging.warning("forward_log_level_to_watcher: request failed: %s", e)
        return False

    if status != 200 or not isinstance(data, dict) or data.get("ok") is not True:
        logging.warning(
            "forward_log_level_to_watcher: watcher rejected request (status=%s, data=%r)",
            status, data,
        )
        return False

    return True


def get_wifi_watcher_version() -> str:
    """Return the root watcher's code-defined component version, if available."""
    if not _read_watcher_control_token():
        return "unknown"
    try:
        status, data = watcher_request("GET", "/version")
    except Exception:
        return "unknown"
    if status != 200 or not isinstance(data, dict) or data.get("ok") is not True:
        return "unknown"
    version = str(data.get("version") or "").strip()
    return version or "unknown"
