#!/usr/bin/python3
"""wifi_hotspot.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

The single source of hotspot *mechanics* for the Autostream Wi-Fi watcher.

The hotspot exists as four representations that must stay resynchronised —
``STATE.setup_mode``, ``STATE.hotspot``, the ``/tmp/apmode`` nginx flag, and the
nmcli AP connection plus dnsmasq service — with the "bring the AP back" resync
needed both by the credential-apply AP rebuild and the worker self-undo.
``HotspotController`` centralises the start/stop/rebuild/clear-stale sequencing
and, above all, the *ordering invariants* those resync sites must not break:

  * the AP is torn down **before** the nginx flag is removed, so nginx never
    routes portal traffic to the main web UI while the setup SSID still
    broadcasts;
  * the flag is set **only** when the AP genuinely started (never on an abort);
  * dnsmasq start/stop stays inside the AP primitives, so it never observes a
    missing/stale or half-deleted runtime config.

Session *policy* (``PURPOSE_TABLE`` and the purposes/deadlines/probe rules) stays
in ``wifi_policy``; session *state* (``STATE.hotspot``) stays on the watcher.  The
controller drives the watcher's AP primitives through a :class:`HotspotContext` —
nothing else of the watcher is reachable from this module.  Deployed beside the
watcher on the system Python.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass
class HotspotContext:
    """Narrow view of the watcher that the hotspot controller depends on.

    Constructed once by the watcher and passed to :class:`HotspotController`;
    nothing else of the watcher is reachable from this module.
    """

    STATE: object
    state_lock: object
    nm: object
    AP_CONNECTION_NAME: str
    start_ap_mode: Callable
    stop_ap_mode: Callable
    update_apmode_flag: Callable
    clear_apmode_flag: Callable


class HotspotController:
    """Owns the hotspot bring-up / teardown / rebuild sequencing and flag order."""

    def __init__(self, ctx: HotspotContext) -> None:
        self.ctx = ctx

    def start(self) -> None:
        """Bring up the AP, then set the nginx flag only if setup is still active.

        ``start_ap_mode`` may abort (no suitable adapter, or setup cleared under
        the lock before the AP could start), clearing ``setup_mode``; the flag is
        set only when the AP genuinely started.
        """
        ctx = self.ctx
        ctx.start_ap_mode()
        with ctx.state_lock:
            still_in_setup = ctx.STATE.setup_mode
        if still_in_setup:
            ctx.update_apmode_flag(True)

    def stop(self) -> None:
        """Tear the AP down, then remove the nginx flag (in that order)."""
        ctx = self.ctx
        ctx.stop_ap_mode()
        ctx.update_apmode_flag(False)

    def rebuild(self) -> None:
        """Restore the AP after a failed client attempt dropped it.

        The single home for the "recreate the hotspot" resync needed by both the
        credential-apply candidate walk and the activation worker's self-undo.
        Re-asserts ``setup_mode`` (the session was never torn down — only the
        nmcli AP was), brings the AP back, and re-sets the flag — but only when
        ``start_ap_mode`` actually succeeded; like ``start()``, a failed nmcli
        add/up clears ``setup_mode`` again, and the flag must not be recreated
        for an AP that never came back up.
        """
        ctx = self.ctx
        with ctx.state_lock:
            ctx.STATE.setup_mode = True
        ctx.start_ap_mode()
        with ctx.state_lock:
            still_in_setup = ctx.STATE.setup_mode
        if still_in_setup:
            ctx.update_apmode_flag(True)

    def clear_stale(self) -> None:
        """Startup cleanup: delete any lingering AP connection and stale flag."""
        ctx = self.ctx
        ctx.nm.delete_connection(ctx.AP_CONNECTION_NAME)
        ctx.clear_apmode_flag()
