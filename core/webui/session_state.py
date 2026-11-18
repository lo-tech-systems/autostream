#!/usr/bin/env python3
"""webui/session_state.py

Shared state and locks for the autostream Web UI.
"""

from __future__ import annotations

import threading
import time
from typing import Optional

from autostream_auth import AuthManager
from autostream_settings import SettingsView, as_view
from autostream_state import store, thaw


class WebUIState:
    """Holds shared state and locks for the Web UI components."""

    def __init__(
        self,
        config_path: str,
        state_path: str,
        *,
        settings: "SettingsView",
    ) -> None:
        self.config_path = config_path
        self.state_path = state_path
        # The canonical in-memory settings shared with the coordinator, seen
        # read-only: a store assigned here is wrapped in a view.  Page
        # renderers call state.settings.snapshot() rather than re-reading the
        # config file; writes go through the settings intents.
        self.settings = settings
        if not isinstance(self._settings, SettingsView):
            raise TypeError("WebUIState needs a settings view")

        # OwnTone restart state
        self._init_owntone_restart()

    @property
    def settings(self) -> "SettingsView":
        return self._settings

    @settings.setter
    def settings(self, value) -> None:
        self._settings = as_view(value)

    # -------------------------------------------------------------------------
    # Devices part: capture devices and the Bluetooth daemon status
    # -------------------------------------------------------------------------

    def get_monitor_devices(self) -> list[dict[str, str]]:
        """The capture devices the last scan found, as fresh dicts."""
        return [dict(dev) for dev in store().snapshot().devices.monitor_devices]

    def get_bluetooth_status(self) -> Optional[dict]:
        """The Bluetooth daemon's last status reply (None when it was not
        fetched or the service did not answer), as a fresh copy."""
        status = store().snapshot().devices.bluetooth_status
        return thaw(status) if status is not None else None

    # -------------------------------------------------------------------------
    # OwnTone restart state
    # -------------------------------------------------------------------------

    def _init_owntone_restart(self) -> None:
        self._owntone_restart_lock = threading.RLock()
        self._owntone_restart_in_progress: bool = False
        self._owntone_restart_started_at: float = 0.0
        self._owntone_restart_finished_at: float = 0.0
        self._owntone_restart_ok: bool = False
        self._owntone_restart_message: str = ""
        self._owntone_restart_token: int = 0

    def begin_owntone_restart(self) -> int:
        """Mark a restart as in-progress, increment the token, return the token.

        The token is used by the background worker to detect whether it has
        been superseded by a later restart request.
        """
        with self._owntone_restart_lock:
            self._owntone_restart_in_progress = True
            self._owntone_restart_started_at = time.time()
            self._owntone_restart_finished_at = 0.0
            self._owntone_restart_ok = False
            self._owntone_restart_message = "Restarting Owntone…"
            self._owntone_restart_token += 1
            return self._owntone_restart_token

    def finish_owntone_restart(self, token: int, ok: bool, message: str) -> None:
        """Record the outcome of a restart attempt.

        Ignored if ``token`` does not match the current token, meaning a newer
        restart superseded this one.
        """
        with self._owntone_restart_lock:
            if self._owntone_restart_token != token:
                return
            self._owntone_restart_in_progress = False
            self._owntone_restart_finished_at = time.time()
            self._owntone_restart_ok = bool(ok)
            self._owntone_restart_message = message

    def get_owntone_restart_state(self) -> dict:
        """Return a snapshot of the current restart state."""
        with self._owntone_restart_lock:
            return {
                "in_progress": self._owntone_restart_in_progress,
                "started_at": self._owntone_restart_started_at,
                "finished_at": self._owntone_restart_finished_at,
                "ok": self._owntone_restart_ok,
                "message": self._owntone_restart_message,
            }


# The running server's state and auth manager: set once when the server
# starts, and read by every request adapter through this module.
STATE: Optional[WebUIState] = None
AUTH: Optional[AuthManager] = None
