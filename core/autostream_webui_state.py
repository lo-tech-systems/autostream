#!/usr/bin/env python3
"""autostream_webui_state.py

Shared state and locks for the autostream Web UI.
"""

from __future__ import annotations

import threading
import time


class WebUIState:
    """Holds shared state and locks for the Web UI components."""

    def __init__(self, config_path: str, state_path: str):
        self.config_path = config_path
        self.state_path = state_path

        # Audio device list as reported by autostream_monitor.
        # Each entry is a dict containing at least:
        #   hw, card, name, label
        self.monitor_devices: list[dict[str, str]] = []
        self.monitor_devices_lock = threading.Lock()

        # OwnTone restart state
        self._init_owntone_restart()

    def set_monitor_devices(self, devices: list[dict[str, str]]) -> None:
        """Store normalized autostream_monitor devices for the Web UI."""
        cleaned: list[dict[str, str]] = []
        for dev in devices:
            if not isinstance(dev, dict):
                continue
            hw = str(dev.get("hw") or "").strip()
            if not hw:
                continue
            cleaned.append({
                "hw": hw,
                "card": str(dev.get("card") or "").strip(),
                "name": str(dev.get("name") or "").strip(),
                "label": str(dev.get("label") or hw).strip(),
            })

        with self.monitor_devices_lock:
            self.monitor_devices = cleaned

    def get_monitor_devices(self) -> list[dict[str, str]]:
        with self.monitor_devices_lock:
            return [dict(dev) for dev in self.monitor_devices]

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
