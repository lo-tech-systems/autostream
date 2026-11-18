#!/usr/bin/env python3
"""webui/system/bluetooth.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Bluetooth input endpoints.

Contents:
  - send_bluetooth_status_json         -- GET /api/bluetooth/status
  - send_bluetooth_pair_status_json    -- GET /api/bluetooth/pair_status
  - send_bluetooth_*_post_json         -- the Bluetooth POST endpoints
"""

from __future__ import annotations

from __future__ import annotations

import logging
import re

from typing import Optional


from autostream_bluetooth_client import (
    BLUETOOTH_CAPTURE_DEVICE,
    BluetoothClient,
    bluetooth_capture_label,
    bluetooth_card_summary,
    bluetooth_input_fragment_text,
    bluetooth_installed,
    bluetooth_onboard_enabled,
    bluetooth_paired_row_text,
    bluetooth_services_enabled,
    classify_loopback_hw,
)
from autostream_config import is_valid_monitor_device_id
from autostream_intents import Intent, submit
from autostream_settings import SettingsView
from autostream_state import Origin
from autostream_sysutils import bt_onboard_set, bt_services_disable, bt_services_enable
from webui import common
from webui.browser import api_settings

# -----------------------------------------------------------------------------
# Bluetooth input — thin translations onto BluetoothClient plus the
# sysutils enable/disable/onboard wrappers.  The pairing/scan/forget
# handlers below return {"ok": false, "error": "bluetooth_unavailable"}
# (tunneled through send_browser_api_error as a semantic 503, following the
# same pattern as send_network_status_json) when the subsystem isn't
# installed, the daemon socket is absent, or the daemon reply is malformed
# -- callers never see a bare exception.
# -----------------------------------------------------------------------------

_BLUETOOTH_SCAN_ALLOWED_ACTIONS = frozenset({"start", "stop"})
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


def send_bluetooth_scan_results_json(handler) -> None:
    """GET /api/bluetooth/scan_results — live device list from the daemon."""
    if not bluetooth_installed():
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    result = BluetoothClient().scan_results()
    if not isinstance(result, dict) or result.get("ok") is not True:
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    common.send_json(handler, 200, result)


def send_bluetooth_pair_status_json(handler, state=None) -> None:
    """GET /api/bluetooth/pair_status -- live pairing-attempt state from the daemon.

    A ``pair`` POST reply only means pairing *started*; the daemon's own
    reported outcome ("done" vs "failed") is only known here, via the
    polled status. So this is the hook point for the post-pairing input
    auto-enable rules (see ``_bt_pair_auto_configure``), not the POST
    handler: once the daemon reports ``state == "done"``, apply the rules
    and surface the outcome under ``input_auto_configure`` so the pairing
    UI (which polls this endpoint) can show the user what changed. Never
    fires on "failed" or "in_progress".

    The UI keeps polling this endpoint every couple of seconds until it
    observes "done" or "failed" and may therefore see "done" more than
    once (e.g. a slow client tick); that's safe to re-run here because the
    rules themselves are idempotent -- an input already on the loopback
    device short-circuits to ``already_configured`` with no further
    change.
    """
    if not bluetooth_installed():
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    result = BluetoothClient().pair_status()
    if not isinstance(result, dict) or result.get("ok") is not True:
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    if result.get("state") == "done":
        try:
            auto = _bt_pair_auto_configure(state)
        except Exception:
            logging.exception("send_bluetooth_pair_status_json: auto-configure step failed")
            auto = None
        if auto is not None:
            result["input_auto_configure"] = auto
    common.send_json(handler, 200, result)


def send_bluetooth_scan_post_json(handler, json_obj) -> None:
    """POST /api/bluetooth/scan {"action": "start"|"stop"} -- closed action set.

    Mirrors ``send_network_setup_json``'s ``_NETWORK_SETUP_ALLOWED_ACTIONS``
    rejection style: unknown actions or extra keys are rejected before ever
    touching the daemon.  A daemon reply of ``{"ok": false, "error":
    "scan_in_progress"}`` (another scan already active) is surfaced as a 409,
    mirroring ``send_network_setup_json``'s watcher-busy 409; any other
    non-ok reply stays a 503 ``bluetooth_unavailable``.
    """
    if not bluetooth_installed():
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    if not isinstance(json_obj, dict):
        common.send_browser_api_error(handler, 400, "JSON object required")
        return
    action = json_obj.get("action")
    extra = set(json_obj.keys()) - {"action", "csrf_token"}
    if action not in _BLUETOOTH_SCAN_ALLOWED_ACTIONS or extra:
        common.send_browser_api_error(handler, 400, "Invalid action")
        return

    client = BluetoothClient()
    result = client.scan_start() if action == "start" else client.scan_stop()
    if not isinstance(result, dict) or result.get("ok") is not True:
        if isinstance(result, dict) and result.get("error") == "scan_in_progress":
            common.send_browser_api_error(handler, 409, "scan_in_progress")
            return
        common.send_browser_api_error(handler, 503, "bluetooth_unavailable")
        return
    common.send_json(handler, 200, {"ok": True, "action": action})


def _bt_pairing_set_field(state, settings, field: str, value) -> tuple[bool, Optional[str]]:
    """Write one settings field through the same validator/mutator/live-effect
    machinery as ``POST /api/settings`` (see ``send_settings_post_json`` and
    ``_SETTINGS_FIELDS``), so this non-browser-initiated caller still goes
    through the coordinator-reload debounce and the cross-input exclusivity
    guard exactly like a user editing the Setup page would. Returns ``(ok,
    error_or_None)``; never raises.
    """
    validator = api_settings._SETTINGS_FIELDS[field][2]
    try:
        normalized = validator(value)
    except ValueError as e:
        return False, str(e)

    # Enabling input 1 requires a valid capture device already on record
    # (mirrors the completeness gates and send_settings_post_json's own
    # guard) -- relevant here only as a defensive backstop, since the
    # caller below always writes the capture device before the enable flag.
    if field == "audio1.enabled" and normalized:
        try:
            current_device = str(settings.snapshot().audio1.capture_device or "").strip()
        except Exception:
            current_device = ""
        if not is_valid_monitor_device_id(current_device):
            return False, "input 1 has no valid capture device on record"

    # Cross-input exclusivity guard: the same capture device must never be
    # assigned to both inputs at once. Fast-path check against the live
    # snapshot; the authoritative, race-proof check is repeated inside the
    # mutator below, under the store lock.
    if field in ("audio1.capture_device", "audio2.capture_device") and normalized:
        other_section = "audio2" if field == "audio1.capture_device" else "audio1"
        try:
            other_value = str(getattr(settings.snapshot(), other_section).capture_device or "").strip()
        except Exception:
            other_value = ""
        if other_value == normalized:
            return False, "that device is already assigned to the other input"

    # The schema row's own cross-validation repeats the duplicate-device check
    # under the store lock, and its live effect runs with the commit.
    reply = submit(Intent(
        "settings.apply", {"changes": ((field, normalized),)}, Origin.USER, "webui",
        context=state))
    if not reply.ok:
        if "invalid" in reply.result:
            return False, reply.result["invalid"]
        return False, "internal error"

    return True, None


_BT_PAIR_NOTICE = "Bluetooth paired — assign the Bluetooth input on the Setup page."


def _bt_pair_auto_configure(state) -> Optional[dict]:
    """Apply the post-pairing input auto-enable rules, once the daemon has
    confirmed a successful pair. Never auto-disables anything.

    Rules, evaluated against the settings snapshot at the moment pairing
    completes:
      a. Input 1 disabled -> point it at the loopback capture device and
         enable it (overwrites any stale device value already on record).
      b. Input 1 enabled on a non-loopback device, and input 2 is unmapped
         (disabled, or has no capture device on record) -> map input 2 to
         the loopback and enable it.
      c. Either input already on the loopback -> already wired; no change,
         no notice.
      d. Otherwise (both inputs occupied by real devices, or a weird
         pre-existing state rules a/b can't safely resolve) -> change
         nothing; the result carries a notice for the caller to surface.

    Returns a dict describing the outcome (for embedding in the pairing
    API response), or ``None`` when there is no settings store to act on
    (nothing could be determined or changed).
    """
    settings = getattr(state, "settings", None)
    if not isinstance(settings, SettingsView):
        return None

    try:
        snap = settings.snapshot()
        a1_enabled = bool(snap.audio1_enabled)
        a1_device = str(snap.audio1.capture_device or "").strip()
        a2_enabled = bool(snap.audio2_enabled)
        a2_device = str(snap.audio2.capture_device or "").strip()
    except Exception:
        logging.exception("_bt_pair_auto_configure: could not read settings snapshot")
        return None

    a1_on_loopback = classify_loopback_hw(a1_device) == "capture"
    a2_on_loopback = classify_loopback_hw(a2_device) == "capture"

    # Rule c takes priority over a/b unconditionally: if either input is
    # already wired to the loopback, nothing further can be done without
    # risking both inputs ending up on the loopback at once (the one
    # invariant that must never happen), so a weird pre-existing state
    # (e.g. input 1 disabled while input 2 already holds the loopback)
    # bails here rather than letting rule a fire underneath it.
    if a1_on_loopback or a2_on_loopback:
        return {"action": "already_configured"}

    if not a1_enabled:
        target_input, device_field, enabled_field = "audio1", "audio1.capture_device", "audio1.enabled"
    elif a1_device and (not a2_enabled or not a2_device):
        target_input, device_field, enabled_field = "audio2", "audio2.capture_device", "audio2.enabled"
    else:
        return {"action": "notice", "notice": _BT_PAIR_NOTICE}

    device_ok, device_err = _bt_pairing_set_field(state, settings, device_field, BLUETOOTH_CAPTURE_DEVICE)
    if not device_ok:
        logging.warning(
            "_bt_pair_auto_configure: could not set %s to the loopback device: %s",
            device_field, device_err,
        )
        return {"action": "notice", "notice": _BT_PAIR_NOTICE}

    enabled_ok, enabled_err = _bt_pairing_set_field(state, settings, enabled_field, True)
    if not enabled_ok:
        # The device is now on record but the input stays disabled -- a
        # legal state (capture_device may be set while disabled) -- rather
        # than leaving a half-applied change or raising out of a pairing
        # response.
        logging.warning(
            "_bt_pair_auto_configure: set %s but could not enable %s: %s",
            device_field, enabled_field, enabled_err,
        )
        return {"action": "device_set_only", "input": target_input}

    return {"action": "enabled", "input": target_input}


def send_bluetooth_pair_post_json(handler, json_obj) -> None:
    """POST /api/bluetooth/pair {"address": <mac>} -- server-side MAC validation.

    A daemon reply of ``{"ok": false, "error": "pair_in_progress"}`` (a
    pairing attempt already active) is surfaced as a 409, mirroring
    ``send_network_setup_json``'s watcher-busy 409; any other non-ok reply
    stays a 503 ``bluetooth_unavailable``.

    This only means the daemon has *started* pairing, not that it
    succeeded -- the real outcome is only known once the client polls
    ``GET /api/bluetooth/pair_status`` and sees ``state == "done"``. It no
    longer applies the input auto-enable rules for that reason (see
    ``send_bluetooth_pair_status_json``, which does); this handler's
    response stays the plain ``{"ok": True}`` shape.
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
    if not isinstance(result, dict) or result.get("ok") is not True:
        if isinstance(result, dict) and result.get("error") == "pair_in_progress":
            common.send_browser_api_error(handler, 409, "pair_in_progress")
            return
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


def _route_get_bluetooth_scan_results(handler, state):
    send_bluetooth_scan_results_json(handler)


def _route_post_bluetooth_scan(handler, state, body_str):
    send_bluetooth_scan_post_json(handler, common._route_post_json_obj(handler))


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
