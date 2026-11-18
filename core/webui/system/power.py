#!/usr/bin/env python3
"""webui/system/power.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Power actions requested from the Web UI.

Contents:
  - handle_factory_reset_post     -- POST /api/factory-reset
  - _settings_save_barrier        -- flush the settings before a destructive action
  - _route_post_reboot            -- POST /api/reboot
"""

from __future__ import annotations

import logging

from autostream_intents import Intent, Origin, submit
from autostream_sysutils import factory_reset_system, reboot_system

from webui import common, session_state
from webui.session_state import WebUIState


def handle_factory_reset_post(handler, state: WebUIState, auth) -> None:
    """POST /api/factory-reset -- schedule factory reset via privileged helper.

    The privileged helper schedules the actual reset as a transient systemd
    unit (escaping the autostream.service cgroup) and returns immediately, so
    this handler completes before the reset sequence begins.

    The client should navigate to /offline/resetting immediately after
    issuing this request and must not wait for a meaningful response body,
    since the service will be stopped as part of the reset sequence.

    Dirty in-memory settings are discarded rather than flushed; factory reset
    wipes the config file anyway so saving first would be misleading.
    """
    submit(Intent("settings.discard", {}, Origin.USER, "webui", context=state))
    try:
        factory_reset_system()
        common.send_json(handler, 200, {"ok": True})
    except Exception as e:
        logging.error("handle_factory_reset_post: scheduling failed: %s", e)
        common.send_json(handler, 500, {"ok": False, "error": "Factory reset could not be scheduled", "detail": str(e)})


def _settings_save_barrier(state) -> bool:
    """Flush dirty SettingsStore to disk before a destructive operation.

    Returns True if save succeeded.
    Returns False if the store exists and save_now() failed or timed out.
    If no SettingsStore is attached, logs an error and allows the action to
    proceed; this indicates a program wiring fault rather than a user- or
    network-facing risk.
    """
    from autostream_settings import SettingsView
    if not isinstance(getattr(state, "settings", None), SettingsView):
        import logging as _logging
        _logging.error("_settings_save_barrier: no SettingsStore attached; skipping flush")
        return True
    return submit(Intent("settings.save", {"timeout": 10.0}, Origin.USER, "webui", context=state)).ok

# -----------------------------------------------------------------------------
# Route-table adapters
# -----------------------------------------------------------------------------


def _route_post_reboot(handler, state, body_str):
    # Legacy inline pre-logic (do_POST's former /api/reboot arm): flush
    # dirty settings to disk before rebooting, then trigger the reboot
    # (delayed 3s so this response can flush first) and reply immediately.
    if not _settings_save_barrier(state):
        common.send_json(handler, 200, {"ok": False, "error": "Settings could not be saved before reboot"})
        return
    reboot_system("UserRequestNormal", delay_s=3)
    common.send_json(handler, 200, {"ok": True})


def _route_post_factory_reset(handler, state, body_str):
    handle_factory_reset_post(handler, state, session_state.AUTH)

