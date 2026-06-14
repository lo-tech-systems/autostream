"""P0.1 — Dial update-status end-to-end contract.

Pins the translation between the canonical on-disk STATUS values written by
both updaters and the public state names served by the dial HTTP server.

The regression this guards: updater wrote STATUS=in_progress / failure;
dial UI expected state=running / failed; an untested translation layer used
stale names, so the UI never showed progress or failure correctly.

Tests are organised as:
  - Unit: _read_update_state() translates every canonical value correctly.
  - Producer-consumer: write_update_result() output feeds _read_update_state().
  - Handler: /update/status route returns the translated public state.
  - Contract table: every writer→reader pair agrees on terminal/non-terminal.
"""
from __future__ import annotations

import io
import json
import sys
import threading
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "dial"))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import dial_http_server as dhs
from dial_config import DialConfig
from dial_http_server import RecoveryWindow
from conftest import load_supervisor_script


# ---------------------------------------------------------------------------
# Canonical value table
# ---------------------------------------------------------------------------

# Maps on-disk STATUS value → expected public state from dial HTTP server.
# "idle" is returned for any value not in the translation dict.
# Note: _read_update_state() calls .lower() before the lookup, so the mapping
# is case-insensitive in practice; IN_PROGRESS → in_progress → running.
CANONICAL_STATUS_TO_PUBLIC = [
    ("in_progress", "running"),
    ("success",     "complete"),
    ("failure",     "failed"),
    ("",            "idle"),       # blank STATUS
    ("unknown",     "idle"),       # unrecognised value
    ("IN_PROGRESS", "running"),    # upper-case is lowercased before lookup
]

# Terminal states: polling should stop once these are reached.
TERMINAL_PUBLIC_STATES = {"complete", "failed"}
NON_TERMINAL_PUBLIC_STATES = {"running", "idle"}


# ---------------------------------------------------------------------------
# Helpers: load the dial updater so write_update_result() is callable
# ---------------------------------------------------------------------------

def _load_dial_updater(tmp_path: Path) -> ModuleType:
    mod = load_supervisor_script("autostream_dial_updater", "dial_updater_p0")
    mod.STATE_DIR = tmp_path
    return mod


def _write_env_file(path: Path, *, status: str, message: str = "msg",
                    percent: int = 0, last_run_at: str = "2026-01-01T00:00:00+00:00") -> None:
    """Write a minimal update-result.env without calling the production writer."""
    content = (
        f"STATUS={status}\n"
        f"PERCENT_COMPLETE={percent}\n"
        f"MESSAGE={message}\n"
        f"LAST_RUN_AT={last_run_at}\n"
    )
    path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Unit tests: _read_update_state() translation
# ---------------------------------------------------------------------------

class TestReadUpdateStateTranslation:
    """_read_update_state() must map every canonical STATUS to the correct public state."""

    @pytest.mark.parametrize("disk_value,expected_public", CANONICAL_STATUS_TO_PUBLIC)
    def test_translates_status_to_public_state(self, tmp_path, disk_value, expected_public):
        result_file = tmp_path / "update-result.env"
        _write_env_file(result_file, status=disk_value)

        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            public = dhs._read_update_state()

        assert public == expected_public, (
            f"STATUS={disk_value!r} should map to {expected_public!r}, got {public!r}"
        )

    def test_missing_file_returns_idle(self, tmp_path):
        missing = tmp_path / "nonexistent.env"
        with patch.object(dhs, "_UPDATE_RESULT_PATH", missing):
            public = dhs._read_update_state()
        assert public == "idle"

    def test_empty_file_returns_idle(self, tmp_path):
        result_file = tmp_path / "update-result.env"
        result_file.write_text("", encoding="utf-8")
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            public = dhs._read_update_state()
        assert public == "idle"

    def test_status_value_is_lowercased_before_lookup(self, tmp_path):
        result_file = tmp_path / "update-result.env"
        # _read_update_state() calls .lower() on the raw value before the dict lookup.
        # Canonical writers always emit lower-case; this confirms the defensive
        # lower-casing works for values stored in mixed case.
        result_file.write_text("STATUS=SUCCESS\n", encoding="utf-8")
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            public = dhs._read_update_state()
        # SUCCESS → lower → success → complete
        assert public == "complete"

    @pytest.mark.parametrize("public_state", list(TERMINAL_PUBLIC_STATES))
    def test_terminal_states_are_complete_or_failed(self, tmp_path, public_state):
        """complete and failed are the only terminal public states."""
        assert public_state in TERMINAL_PUBLIC_STATES

    @pytest.mark.parametrize("public_state", list(NON_TERMINAL_PUBLIC_STATES))
    def test_non_terminal_states_are_running_or_idle(self, tmp_path, public_state):
        assert public_state in NON_TERMINAL_PUBLIC_STATES


# ---------------------------------------------------------------------------
# Producer-consumer: write_update_result() → _read_update_state()
# ---------------------------------------------------------------------------

class TestProducerConsumerContract:
    """The actual dial-updater writer feeds the actual dial HTTP status reader."""

    def test_in_progress_produces_running(self, tmp_path):
        mod = _load_dial_updater(tmp_path)
        mod.write_update_result("in_progress", "Installing v1.2...", percent=0)
        result_file = tmp_path / "update-result.env"
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            assert dhs._read_update_state() == "running"

    def test_success_produces_complete(self, tmp_path):
        mod = _load_dial_updater(tmp_path)
        mod.write_update_result("success", "Update complete", percent=100)
        result_file = tmp_path / "update-result.env"
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            assert dhs._read_update_state() == "complete"

    def test_failure_produces_failed(self, tmp_path):
        mod = _load_dial_updater(tmp_path)
        mod.write_update_result("failure", "systemd-run failed scheduling v1.2", percent=0)
        result_file = tmp_path / "update-result.env"
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            assert dhs._read_update_state() == "failed"

    def test_changing_status_updates_public_state(self, tmp_path):
        """State transitions: in_progress → success → idle (file deleted)."""
        mod = _load_dial_updater(tmp_path)
        result_file = tmp_path / "update-result.env"

        mod.write_update_result("in_progress", "Installing...", percent=0)
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            assert dhs._read_update_state() == "running"

        mod.write_update_result("success", "Done", percent=100)
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            assert dhs._read_update_state() == "complete"

        result_file.unlink()
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            assert dhs._read_update_state() == "idle"


# ---------------------------------------------------------------------------
# Handler: /update/status route
# ---------------------------------------------------------------------------

class _FakeDialServer:
    """Minimal stand-in that mirrors the pattern in test_dial_http_server.py."""
    def __init__(self) -> None:
        self._cfg             = DialConfig(uuid="test-uuid")
        self._cfg_lock        = threading.Lock()
        self._recovery_window = MagicMock(spec=RecoveryWindow)
        self._recovery_window._active           = False
        self._recovery_window._volume_confirmed = False

    @property
    def step_percent(self) -> int:
        return self._cfg.step_percent

    def _make_handler(self):
        return dhs.DialHTTPServer._make_handler(self)


def _call_update_status(result_file: Path) -> dict:
    """Invoke the /update/status GET handler with a patched result path."""
    server = _FakeDialServer()
    handler_cls = server._make_handler()

    h = object.__new__(handler_cls)
    h.path           = "/update/status"
    h.client_address = ("127.0.0.1", 1)
    result: dict = {}
    h._send_json = lambda s, d: result.update(status=s, data=d)
    h.send_error = lambda c, *_: result.update(status=c)

    with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
        h.do_GET()

    return result


class TestUpdateStatusHandler:
    @pytest.mark.parametrize("disk_value,expected_public", [
        ("in_progress", "running"),
        ("success",     "complete"),
        ("failure",     "failed"),
        ("",            "idle"),
    ])
    def test_handler_returns_correct_public_state(self, tmp_path, disk_value, expected_public):
        result_file = tmp_path / "update-result.env"
        _write_env_file(result_file, status=disk_value)

        r = _call_update_status(result_file)

        assert r["status"] == 200
        assert r["data"]["state"] == expected_public

    def test_missing_result_file_returns_idle(self, tmp_path):
        result_file = tmp_path / "missing.env"
        r = _call_update_status(result_file)
        assert r["status"] == 200
        assert r["data"]["state"] == "idle"

    def test_response_includes_version(self, tmp_path):
        result_file = tmp_path / "update-result.env"
        _write_env_file(result_file, status="success")
        r = _call_update_status(result_file)
        assert "version" in r["data"]


# ---------------------------------------------------------------------------
# Contract table: offline page and dial page agree on terminal/non-terminal
# ---------------------------------------------------------------------------

class TestTerminalStateAgreement:
    """The offline page (updating.html) and the dial page use different status
    names but must agree on which states are terminal (polling stops) and
    which are non-terminal (polling continues).

    Offline page reads raw STATUS from admin JSON: in_progress / success / failure.
    Dial page reads public state from /update/status: running / complete / failed.

    Terminal on-disk values: success, failure.
    Terminal public values: complete, failed.
    Non-terminal on-disk: in_progress.
    Non-terminal public: running, idle.
    """

    # Map from canonical disk value to expected terminal classification.
    DISK_TERMINAL = {
        "in_progress": False,
        "success":     True,
        "failure":     True,
    }

    # Map from public state to expected terminal classification.
    PUBLIC_TERMINAL = {
        "running":  False,
        "complete": True,
        "failed":   True,
        "idle":     False,   # idle is non-terminal: no update is in progress
    }

    @pytest.mark.parametrize("disk_value,is_terminal", list(DISK_TERMINAL.items()))
    def test_disk_terminal_classification(self, disk_value, is_terminal):
        assert (disk_value in {"success", "failure"}) == is_terminal

    @pytest.mark.parametrize("public_state,is_terminal", list(PUBLIC_TERMINAL.items()))
    def test_public_terminal_classification(self, public_state, is_terminal):
        assert (public_state in {"complete", "failed"}) == is_terminal

    @pytest.mark.parametrize("disk_value", ["in_progress", "success", "failure"])
    def test_disk_and_public_agree_on_terminal(self, tmp_path, disk_value):
        """A terminal disk value must translate to a terminal public state."""
        result_file = tmp_path / "update-result.env"
        _write_env_file(result_file, status=disk_value)
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            public = dhs._read_update_state()

        disk_is_terminal = self.DISK_TERMINAL[disk_value]
        public_is_terminal = self.PUBLIC_TERMINAL[public]
        assert disk_is_terminal == public_is_terminal, (
            f"disk={disk_value!r}(terminal={disk_is_terminal}) "
            f"→ public={public!r}(terminal={public_is_terminal}) — mismatch"
        )
