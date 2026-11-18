"""dial_admin.py: the one way the dial runs the privileged admin helper.

Every call goes through the dial's sudo grant. Fire-and-forget launches
(spawn_admin) and the power-off use `sudo -n`, so a misconfigured sudo fails
at once instead of waiting on a password prompt nobody can answer; the other
verbs are bounded by their own timeouts. Callers keep their own error
handling and log texts.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import subprocess

ADMIN_CMD = "/usr/local/libexec/autostream/autostream_admin"


def run_admin(verb: str, *args: str, timeout: float, no_prompt: bool = False,
              capture: bool = False) -> subprocess.CompletedProcess:
    """Run one admin verb and wait for it. no_prompt adds sudo's -n; capture
    collects the helper's output instead of letting it through."""
    command = ["sudo", *(["-n"] if no_prompt else []), ADMIN_CMD, verb, *args]
    return subprocess.run(command, timeout=timeout, **({"capture_output": True} if capture else {}))


def spawn_admin(verb: str) -> subprocess.Popen:
    """Start one admin verb and do not wait for it (sudo -n)."""
    return subprocess.Popen(["sudo", "-n", ADMIN_CMD, verb])


def announce(cfg, version: str, *, pin_recovery: bool = False) -> None:
    """Write or update this dial's avahi service file. Never raises."""
    try:
        run_admin("update-dial-service", version, cfg.uuid, cfg.name or cfg.uuid,
                  *(["--pin-recovery"] if pin_recovery else []), timeout=5)
    except Exception as e:
        logging.warning("update-dial-service failed: %s", e)
