#!/usr/bin/env python3
"""autostream_webui_state.py

Shared state and locks for the autostream Web UI.
"""

from __future__ import annotations

import threading
import time


class WebUIState:
    """Holds shared state and locks for the Web UI components."""

    def __init__(self, config_path: str):
        self.config_path = config_path

        # Audio device list as reported by autostream_monitor.
        # Each entry is a dict containing at least:
        #   hw, card, name, label
        self.monitor_devices: list[dict[str, str]] = []
        self.monitor_devices_lock = threading.Lock()

        # Updater state
        self.update_lock = threading.Lock()
        self.update_state = {
            "running": False,
            "last_result": None,   # dict or None
            "last_error": None,    # str or None
            "started_at": None,    # float or None
            "finished_at": None,   # float or None
        }

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

    def start_update(self):
        with self.update_lock:
            if self.update_state.get("running"):
                return False
            self.update_state.update({
                "running": True, 
                "last_result": None, 
                "last_error": None, 
                "started_at": time.time(), 
                "finished_at": None
            })
            return True

    def finish_update(self, result, error):
        with self.update_lock:
            self.update_state["last_result"] = result
            self.update_state["last_error"] = error
            self.update_state["running"] = False
            self.update_state["finished_at"] = time.time()

    def get_update_status(self) -> dict:
        with self.update_lock:
            return dict(self.update_state)
