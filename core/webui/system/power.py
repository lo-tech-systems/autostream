#!/usr/bin/env python3
"""webui/system/power.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Power actions requested from the Web UI.

Contents:
  - handle_factory_reset_post     -- POST /api/factory-reset
"""

from __future__ import annotations

import logging

from autostream_intents import Intent, Origin, submit
from autostream_sysutils import factory_reset_system

from webui import common
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
