#!/usr/bin/env python3
"""webui/system/bluetooth.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Bluetooth input endpoints.

Contents:
  - send_bluetooth_status_json         -- GET /api/bluetooth/status
  - send_bluetooth_pair_window_json    -- GET /api/bluetooth/pair_window
  - send_bluetooth_*_post_json         -- the Bluetooth POST endpoints
"""

from __future__ import annotations

from __future__ import annotations

import logging
import re


from autostream_bluetooth_client import (
    BluetoothClient,
    bluetooth_capture_label,
    bluetooth_card_summary,
    bluetooth_input_fragment_text,
    bluetooth_installed,
    bluetooth_onboard_enabled,
    bluetooth_paired_row_text,
    bluetooth_services_enabled,
    onboard_radio_refused,
)
from autostream_sysutils import bt_onboard_set, bt_services_disable, bt_services_enable
from webui import common

# -----------------------------------------------------------------------------
# Bluetooth input — thin translations onto BluetoothClient plus the
# sysutils enable/disable/onboard wrappers.  The pairing/forget
# handlers below return {"ok": false, "error": "bluetooth_unavailable"}
# (tunneled through send_browser_api_error as a semantic 503, following the
# same pattern as send_network_status_json) when the subsystem isn't
# installed, the daemon socket is absent, or the daemon reply is malformed
# -- callers never see a bare exception.
# -----------------------------------------------------------------------------

_BLUETOOTH_WINDOW_ALLOWED_ACTIONS = frozenset({"start", "stop"})
_BLUETOOTH_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
_BLUETOOTH_SERVICES_ALLOWED_ACTIONS = frozenset({"enable", "disable"})
_BLUETOOTH_BUFFER_MS_MIN = 100
_BLUETOOTH_BUFFER_MS_MAX = 500


def send_bluetooth_status_json(handler, state) -> None:
    """GET /api/bluetooth/status -- install/enable/onboard flags + daemon status.

    Always returns HTTP 200 with ``ok: true`` -- the daemon being down
    (expected whenever services are disabled) is reported as ``daemon:
    null``, not as a request failure, so the Bluetooth card can render its
    disabled state from a single successful poll rather than special-casing
    an error response.

    When installed, attempts a live daemon query first (freshest); falls
    back to the cache populated by the webui's background scan loop
    (``WebUIState.get_bluetooth_status``) if the live query fails.

    Also returns a ``ui`` object -- ``card_summary``, ``paired_text``,
    ``bt_input_text`` -- computed from the same ``services_enabled``/
    ``daemon`` data by the single shared presentation-string implementation
    also used by the Setup page's server render, so the card's summary line
    can never disagree between the initial render and this poll.
    """
    installed = bluetooth_installed()
    services_enabled = bluetooth_services_enabled() if installed else False
    onboard_enabled = bluetooth_onboard_enabled() if installed else False
    onboard_refused = onboard_radio_refused() if installed else None

    daemon = None
    if installed:
        try:
            daemon = BluetoothClient().status()
        except Exception:
            daemon = None
        if not isinstance(daemon, dict) or daemon.get("ok") is not True:
            cached = state.get_bluetooth_status() if state is not None else None
            daemon = cached if isinstance(cached, dict) and cached.get("ok") is True else None

    common.send_json(handler, 200, {
        "ok": True,
        "installed": installed,
        "services_enabled": services_enabled,
        "onboard_enabled": onboard_enabled,
        # Why the onboard radio may not be turned on here, or null.
        "onboard_refused": onboard_refused,
        "daemon": daemon,
        "ui": {
            "card_summary": bluetooth_card_summary(services_enabled, daemon),
            "paired_text": bluetooth_paired_row_text(daemon),
            "bt_input_text": bluetooth_input_fragment_text(daemon),
            # Label for the loopback entry in the capture-device dropdowns,
            # so the poll can relabel it live ("Bluetooth: <name>" after a
            # pair, back to unpaired after a forget) without a page reload.
            "capture_label": bluetooth_capture_label(daemon),
        },
    })


def send_bluetooth_pair_window_json(handler, state=None) -> None:
    """GET /api/bluetooth/pair_window -- the pairing screen's poll.

    One round trip to the daemon that is both the window's heartbeat (the
    daemon closes the window when these stop for thirty seconds) and its
    list. There is no separate heartbeat route, and this process keeps no
    window state, so a short WebUI restart is invisible to the window.
    """
    if not bluetooth_installed():
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    result = BluetoothClient().window_poll()
    if not isinstance(result, dict) or result.get("ok") is not True:
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    common.send_json(handler, 200, result)


def send_bluetooth_pair_window_post_json(handler, json_obj) -> None:
    """POST /api/bluetooth/pair_window {"action": "start"|"stop"}.

    ``start`` opens the window (or attaches to one already open); a daemon
    still cleaning up the last window replies ``window_closing``, surfaced
    as a 409 for the screen to retry on its next poll. ``stop`` is best
    effort and always succeeds when the daemon answers: a window that has
    already closed is the goal state. Anything else is a 503
    ``bluetooth_unavailable``.
    """
    if not bluetooth_installed():
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    if not isinstance(json_obj, dict):
        common.send_browser_api_error(handler, 400, "JSON object required")
        return
    action = json_obj.get("action")
    extra = set(json_obj.keys()) - {"action", "csrf_token"}
    if action not in _BLUETOOTH_WINDOW_ALLOWED_ACTIONS or extra:
        common.send_browser_api_error(handler, 400, "Invalid action")
        return

    client = BluetoothClient()
    result = client.window_start() if action == "start" else client.window_stop()
    if not isinstance(result, dict):
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    error = result.get("error")
    if result.get("ok") is True or (action == "stop" and error == "no_window"):
        common.send_json(handler, 200, {"ok": True, "action": action})
        return
    if error == "window_closing":
        common.send_browser_api_error(handler, 409, "window_closing")
        return
    common.send_browser_api_error(handler, 503, "bluetooth_unavailable")


# Daemon refusals of a tap -> HTTP status. Anything else is a 503.
_BLUETOOTH_PAIR_ERRORS = {
    "window_adopting": 409,
    "no_window": 409,
    "unknown_device": 404,
}


def send_bluetooth_pair_post_json(handler, json_obj) -> None:
    """POST /api/bluetooth/pair {"address": <mac>} -- the user's tap on an
    entry in the pairing window's list; server-side MAC validation.

    This only means the daemon has *started* adopting the device; the
    outcome arrives through ``GET /api/bluetooth/pair_window``. A tap while
    another is running is a 409 ``window_adopting``, a tap with no window
    open a 409 ``no_window``, and a device no longer in the list a 404
    ``unknown_device``.
    """
    if not bluetooth_installed():
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    if not isinstance(json_obj, dict):
        common.send_browser_api_error(handler, 400, "JSON object required")
        return
    address = json_obj.get("address")
    extra = set(json_obj.keys()) - {"address", "csrf_token"}
    if not isinstance(address, str) or not _BLUETOOTH_MAC_RE.match(address) or extra:
        common.send_browser_api_error(handler, 400, "Invalid address")
        return

    result = BluetoothClient().pair(address)
    if not isinstance(result, dict):
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    if result.get("ok") is not True:
        error = str(result.get("error") or "")
        status = _BLUETOOTH_PAIR_ERRORS.get(error)
        if status is not None:
            common.send_browser_api_error(handler, status, error)
        else:
            common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return

    common.send_json(handler, 200, {"ok": True})


def send_bluetooth_forget_post_json(handler) -> None:
    """POST /api/bluetooth/forget — RemoveDevice + clear daemon state."""
    if not bluetooth_installed():
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    result = BluetoothClient().forget()
    if not isinstance(result, dict) or result.get("ok") is not True:
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    common.send_json(handler, 200, {"ok": True})


def send_bluetooth_services_post_json(handler, json_obj) -> None:
    """POST /api/bluetooth/services {"action": "enable"|"disable"}.

    Thin wrapper over the ``autostream_sysutils`` privileged-path
    functions, which each return ``(ok, message)``. Disabling implicitly
    stops any active stream -- that is handled inside the systemd unit
    stop, not here. Closed action set, extra keys rejected.
    """
    if not bluetooth_installed():
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    if not isinstance(json_obj, dict):
        common.send_browser_api_error(handler, 400, "JSON object required")
        return
    action = json_obj.get("action")
    extra = set(json_obj.keys()) - {"action", "csrf_token"}
    if action not in _BLUETOOTH_SERVICES_ALLOWED_ACTIONS or extra:
        common.send_browser_api_error(handler, 400, "Invalid action")
        return

    try:
        ok, message = bt_services_enable() if action == "enable" else bt_services_disable()
    except Exception as e:
        logging.exception("send_bluetooth_services_post_json: %s failed", action)
        common.send_json(handler, 200, {"ok": False, "message": str(e)})
        return
    common.send_json(handler, 200, {"ok": bool(ok), "message": str(message)})


def send_bluetooth_onboard_post_json(handler, json_obj) -> None:
    """POST /api/bluetooth/onboard {"enabled": bool}.

    Edits ``dtoverlay=disable-bt`` in config.txt via ``bt_onboard_set()``.
    On success, ``reboot_required: true`` tells the frontend to drive the
    existing reboot holding-page flow -- this handler does not reboot.

    Turning the radio on is refused on a board whose power hardware leaves
    it on the mini UART (``onboard_radio_refused``), so the API cannot do
    what the Setup card does not offer. Turning it off is always allowed.
    """
    if not bluetooth_installed():
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    if not isinstance(json_obj, dict):
        common.send_browser_api_error(handler, 400, "JSON object required")
        return
    enabled = json_obj.get("enabled")
    extra = set(json_obj.keys()) - {"enabled", "csrf_token"}
    if not isinstance(enabled, bool) or extra:
        common.send_browser_api_error(handler, 400, "Invalid enabled value")
        return

    refused = onboard_radio_refused() if enabled else None
    if refused:
        common.send_json(handler, 200, {"ok": False, "message": refused})
        return

    try:
        ok, message = bt_onboard_set(enabled)
    except Exception as e:
        logging.exception("send_bluetooth_onboard_post_json: bt_onboard_set failed")
        common.send_json(handler, 200, {"ok": False, "message": str(e)})
        return
    resp: dict = {"ok": bool(ok), "message": str(message)}
    if ok:
        resp["reboot_required"] = True
    common.send_json(handler, 200, resp)


def send_bluetooth_buffer_post_json(handler, json_obj) -> None:
    """POST /api/bluetooth/buffer {"buffer_ms": int} -- daemon configure passthrough.

    Server-side range validation (100-500 ms, matching the card's slider)
    happens before ever touching the daemon; the daemon's own
    ``invalid_buffer_ms`` rejection (defence in depth) is surfaced as 400
    too. An unreachable daemon is a 503 ``bluetooth_unavailable``.
    """
    if not bluetooth_installed():
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    if not isinstance(json_obj, dict):
        common.send_browser_api_error(handler, 400, "JSON object required")
        return
    buffer_ms = json_obj.get("buffer_ms")
    extra = set(json_obj.keys()) - {"buffer_ms", "csrf_token"}
    if (
        isinstance(buffer_ms, bool)
        or not isinstance(buffer_ms, int)
        or not (_BLUETOOTH_BUFFER_MS_MIN <= buffer_ms <= _BLUETOOTH_BUFFER_MS_MAX)
        or extra
    ):
        common.send_browser_api_error(handler, 400, "invalid_buffer_ms")
        return

    result = BluetoothClient().configure(buffer_ms)
    if not isinstance(result, dict):
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    if result.get("ok") is not True:
        if result.get("error") == "invalid_buffer_ms":
            common.send_browser_api_error(handler, 400, "invalid_buffer_ms")
            return
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    common.send_json(handler, 200, {"ok": True, "buffer_ms": buffer_ms})

# -----------------------------------------------------------------------------
# Route-table adapters
# -----------------------------------------------------------------------------


def _route_post_bluetooth_pair_window(handler, state, body_str):
    send_bluetooth_pair_window_post_json(handler, common._route_post_json_obj(handler))


def _route_post_bluetooth_pair(handler, state, body_str):
    send_bluetooth_pair_post_json(handler, common._route_post_json_obj(handler))


def _route_post_bluetooth_forget(handler, state, body_str):
    send_bluetooth_forget_post_json(handler)


def _route_post_bluetooth_services(handler, state, body_str):
    send_bluetooth_services_post_json(handler, common._route_post_json_obj(handler))


def _route_post_bluetooth_onboard(handler, state, body_str):
    send_bluetooth_onboard_post_json(handler, common._route_post_json_obj(handler))


def _route_post_bluetooth_buffer(handler, state, body_str):
    send_bluetooth_buffer_post_json(handler, common._route_post_json_obj(handler))
