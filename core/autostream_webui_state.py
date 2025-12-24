#!/usr/bin/env python3
"""autostream_webui_state.py

Shared state and locks for the autostream Web UI.
"""

import threading
import time

class WebUIState:
    """Holds shared state and locks for the Web UI components."""
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        
        # Audio device list
        self.pcm_devices = []
        self.pcm_devices_lock = threading.Lock()
        
        # Updater state
        self.update_lock = threading.Lock()
        self.update_state = {
            "running": False,
            "last_result": None,   # dict or None
            "last_error": None,    # str or None
            "started_at": None,    # float or None
            "finished_at": None,   # float or None
        }

    def set_pcm_devices(self, devices: list[str]):
        with self.pcm_devices_lock:
            self.pcm_devices = devices

    def get_pcm_devices(self) -> list[str]:
        with self.pcm_devices_lock:
            return list(self.pcm_devices)

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
