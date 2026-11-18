"""Tests for dial_admin.py: the dial's one way to run the privileged admin helper.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import dial_admin

CMD = "/usr/local/libexec/autostream/autostream_admin"


def test_run_admin_builds_a_plain_sudo_command():
    with patch("subprocess.run") as run:
        dial_admin.run_admin("toggle-dial-update-timer", "enable", timeout=5)
    run.assert_called_once_with(["sudo", CMD, "toggle-dial-update-timer", "enable"], timeout=5)


def test_run_admin_can_capture_and_skip_the_prompt():
    with patch("subprocess.run") as run:
        dial_admin.run_admin("poweroff", no_prompt=True, capture=True, timeout=15.0)
    run.assert_called_once_with(["sudo", "-n", CMD, "poweroff"], timeout=15.0, capture_output=True)


def test_run_admin_returns_what_subprocess_returns():
    done = MagicMock(returncode=3)
    with patch("subprocess.run", return_value=done):
        assert dial_admin.run_admin("run-updater", timeout=5, capture=True) is done


def test_spawn_admin_starts_without_waiting():
    with patch("subprocess.Popen") as popen:
        dial_admin.spawn_admin("restart-dial-service")
    popen.assert_called_once_with(["sudo", "-n", CMD, "restart-dial-service"])


def test_announce_passes_the_version_uuid_and_name():
    cfg = SimpleNamespace(uuid="u-1", name="Lounge")
    with patch("subprocess.run") as run:
        dial_admin.announce(cfg, "1.2.3")
    run.assert_called_once_with(["sudo", CMD, "update-dial-service", "1.2.3", "u-1", "Lounge"], timeout=5)


def test_announce_falls_back_to_the_uuid_for_a_blank_name():
    cfg = SimpleNamespace(uuid="u-1", name="")
    with patch("subprocess.run") as run:
        dial_admin.announce(cfg, "1.2.3", pin_recovery=True)
    assert run.call_args[0][0] == [
        "sudo", CMD, "update-dial-service", "1.2.3", "u-1", "u-1", "--pin-recovery"]


def test_announce_logs_and_swallows_a_failure(caplog):
    cfg = SimpleNamespace(uuid="u-1", name="x")
    with patch("subprocess.run", side_effect=OSError("no sudo")), caplog.at_level(logging.WARNING):
        dial_admin.announce(cfg, "1.2.3")
    assert "update-dial-service failed" in caplog.text
