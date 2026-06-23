#!/usr/bin/env python3
"""autostream_commissioning.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

Commissioning-state helpers for first-boot detection, step derivation,
and state-file marker management.

Contents:
  - is_technically_complete   -- config satisfies all required-field checks
  - is_commissioning_required -- combined config + state marker check
  - required_first_boot_step  -- "owntone" | "appliance" | None
  - ensure_commissioning_marker -- idempotent marker init for incomplete configs
  - mark_commissioning_complete -- write completed=true after successful Finish
"""

from __future__ import annotations

import json
import logging

from autostream_config import (
    CONFIG_IO_LOCK,
    load_state,
    save_state,
    is_valid_monitor_device_id,
)


# ---------------------------------------------------------------------------
# Technical completeness
# ---------------------------------------------------------------------------

def is_technically_complete(config_path: str) -> bool:
    """Return True iff the on-disk config satisfies all required-field checks.

    Required fields:
      - general.fifo_path   (non-empty string)
      - audio1.capture_device  (valid ALSA hw:* id)
      - owntone.output_name  (non-empty string)

    Reads the file each call (no mtime cache). Callers that need performance
    should cache the result themselves or use autostream_config.unconfigured()
    for the hot path.
    """
    try:
        with open(config_path, encoding="utf-8") as f:
            data = json.load(f)
        fifo_path = str((data.get("general") or {}).get("fifo_path", "") or "").strip()
        audio1_dev = str((data.get("audio1") or {}).get("capture_device", "") or "").strip()
        output_name = str((data.get("owntone") or {}).get("output_name", "") or "").strip()
        return bool(
            fifo_path
            and is_valid_monitor_device_id(audio1_dev)
            and output_name
        )
    except Exception:
        return False


def _read_commissioning_marker(state_path: str) -> tuple[bool | None, bool | None]:
    """Read the first_boot marker from the state file.

    Returns (required, completed) where each may be None if absent or malformed.
    """
    try:
        state = load_state(state_path)
        fb = state.get("first_boot")
        if fb is None:
            return None, None
        if not isinstance(fb, dict):
            return None, None  # malformed
        required = fb.get("required")
        completed = fb.get("completed")
        if not isinstance(required, bool) or not isinstance(completed, bool):
            return None, None  # malformed
        return required, completed
    except Exception:
        return None, None


def is_commissioning_required(config_path: str, state_path: str) -> bool:
    """Return True iff the system needs first-boot commissioning.

    Policy:
      - Missing or technically incomplete config → True always.
      - Technically complete + no first_boot marker in state → False (legacy).
      - Technically complete + malformed marker → False (fail safe, legacy).
      - Technically complete + required=True, completed=False → True.
      - Technically complete + required=True, completed=True → False.
      - Technically complete + required=False → False.
    """
    if not is_technically_complete(config_path):
        return True

    required, completed = _read_commissioning_marker(state_path)
    if required is None:
        return False  # no marker or malformed — treat as legacy configured
    if required and not completed:
        return True
    return False


def required_first_boot_step(config_path: str, state_path: str) -> str | None:
    """Return the first-boot page step required, or None if configured.

    Returns:
      "owntone"   — OwnTone output selection step
      "appliance" — ALSA device and FIFO setup step
      None        — commissioning complete / device configured
    """
    if not is_commissioning_required(config_path, state_path):
        return None
    try:
        with open(config_path, encoding="utf-8") as f:
            data = json.load(f)
        output_name = str((data.get("owntone") or {}).get("output_name", "") or "").strip()
    except Exception:
        output_name = ""

    if not output_name:
        return "owntone"
    return "appliance"


# ---------------------------------------------------------------------------
# State marker helpers
# ---------------------------------------------------------------------------

def ensure_commissioning_marker(state_path: str) -> None:
    """Idempotently write first_boot.required=true, completed=false.

    Called at startup when the config is missing or incomplete. Skips the
    write if the marker is already in the correct state.
    """
    try:
        with CONFIG_IO_LOCK:
            state = load_state(state_path)
            fb = state.get("first_boot")
            if (
                isinstance(fb, dict)
                and fb.get("required") is True
                and fb.get("completed") is False
            ):
                return  # already correct, no-op
            state["first_boot"] = {"required": True, "completed": False}
            save_state(state_path, state)
    except Exception:
        logging.exception("ensure_commissioning_marker: failed to update state file")


def mark_commissioning_complete(state_path: str) -> None:
    """Write first_boot.required=true, completed=true after successful Finish.

    Re-reads the state file inside CONFIG_IO_LOCK to preserve concurrent
    changes (PIN, known_outputs, etc.).
    """
    try:
        with CONFIG_IO_LOCK:
            state = load_state(state_path)
            state.setdefault("first_boot", {})["required"] = True
            state["first_boot"]["completed"] = True
            save_state(state_path, state)
    except Exception:
        logging.exception("mark_commissioning_complete: failed to update state file")
        raise
