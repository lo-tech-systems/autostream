#!/usr/bin/python3
"""wifi_hotspot.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

The single source of hotspot *mechanics* for the Autostream Wi-Fi watcher.

The hotspot previously existed as four representations resynchronised by hand —
``STATE.setup_mode``, ``STATE.hotspot``, the ``/tmp/apmode`` nginx flag, and the
nmcli AP connection plus dnsmasq service — with the "bring the AP back" resync
duplicated across the credential-apply AP rebuild and the worker self-undo.
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
controller drives the watcher's AP primitives (``start_ap_mode`` / ``stop_ap_mode``
/ ``update_apmode_flag`` / ``clear_apmode_flag`` / ``nm``) through the ``w`` seam,
so existing per-function test patches keep intercepting.  Deployed beside the
watcher on the system Python.
"""
from __future__ import annotations


class HotspotController:
    """Owns the hotspot bring-up / teardown / rebuild sequencing and flag order."""

    def __init__(self, w) -> None:
        self.w = w

    def start(self) -> None:
        """Bring up the AP, then set the nginx flag only if setup is still active.

        ``start_ap_mode`` may abort (no suitable adapter, or setup cleared under
        the lock before the AP could start), clearing ``setup_mode``; the flag is
        set only when the AP genuinely started.
        """
        w = self.w
        w.start_ap_mode()
        with w.state_lock:
            still_in_setup = w.STATE.setup_mode
        if still_in_setup:
            w.update_apmode_flag(True)

    def stop(self) -> None:
        """Tear the AP down, then remove the nginx flag (in that order)."""
        w = self.w
        w.stop_ap_mode()
        w.update_apmode_flag(False)

    def rebuild(self) -> None:
        """Restore the AP after a failed client attempt dropped it.

        The single home for the "recreate the hotspot" resync that used to be
        duplicated in the credential-apply candidate walk and the activation
        worker's self-undo.  Re-asserts ``setup_mode`` (the session was never torn
        down — only the nmcli AP was), brings the AP back, and re-sets the flag.
        """
        w = self.w
        with w.state_lock:
            w.STATE.setup_mode = True
        w.start_ap_mode()
        w.update_apmode_flag(True)

    def clear_stale(self) -> None:
        """Startup cleanup: delete any lingering AP connection and stale flag."""
        w = self.w
        w.nm.delete_connection(w.AP_CONNECTION_NAME)
        w.clear_apmode_flag()
