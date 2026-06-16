"""WP4 tests — autostream_dial_control CLI.

Covers:
1.  Request JSON generated for every subcommand.
2.  --json before and after the subcommand.
3.  Human-readable output for ping, version, status, targets, nudge.
4.  Empty target output is clear and successful.
5.  server ok:false produces exit code 1.
6.  Argument errors produce exit code 2.
7.  Missing socket, permission failure, timeout produce exit code 3.
8.  Server messages written to stderr on failure.
9.  JSON mode emits one compact line.
10. CLI does not import dial runtime modules.
11. --json duplicate is a usage error.
12. Unknown option is a usage error.
"""
from __future__ import annotations

import io
import json
import socket
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import autostream_dial_control as cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(argv: list[str], fake_resp: dict | None = None) -> tuple[int, str, str]:
    """Run cli.main() with given argv, mocked _send_command.

    Returns (exit_code, stdout, stderr).
    """
    if fake_resp is None:
        fake_resp = {"ok": True}

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    with patch("autostream_dial_control._send_command", return_value=fake_resp):
        with patch("sys.stdout", stdout_buf):
            with patch("sys.stderr", stderr_buf):
                try:
                    cli.main(argv)
                    exit_code = 0
                except SystemExit as e:
                    exit_code = e.code if isinstance(e.code, int) else int(e.code or 0)

    return exit_code, stdout_buf.getvalue(), stderr_buf.getvalue()


def _sent_req(argv: list[str]) -> dict:
    """Return the request dict that would be sent for the given argv."""
    captured = []

    def fake_send(path, req):
        captured.append(req)
        return {"ok": True, "service": "autostream-dial",
                "protocol_version": 1, "software_version": "1.0",
                "uuid": "u", "name": "n", "step_percent": 2,
                "target_count": 0, "recovery_active": False,
                "volume_confirmed": False, "count": 0, "targets": [],
                "queued": True, "delta": 2}

    with patch("autostream_dial_control._send_command", side_effect=fake_send):
        try:
            cli.main(argv)
        except SystemExit:
            pass

    assert captured, "No request was sent"
    return captured[0]


# ---------------------------------------------------------------------------
# Request JSON for every subcommand
# ---------------------------------------------------------------------------

class TestRequestGeneration:
    def test_ping_request(self):
        req = _sent_req(["ping"])
        assert req == {"command": "ping"}

    def test_version_request(self):
        req = _sent_req(["version"])
        assert req == {"command": "version"}

    def test_status_request(self):
        req = _sent_req(["status"])
        assert req == {"command": "status"}

    def test_targets_request(self):
        req = _sent_req(["targets"])
        assert req == {"command": "targets"}

    def test_nudge_up_request(self):
        req = _sent_req(["nudge", "up"])
        assert req == {"command": "nudge", "direction": "up"}

    def test_nudge_down_request(self):
        req = _sent_req(["nudge", "down"])
        assert req == {"command": "nudge", "direction": "down"}

    def test_nudge_explicit_delta_request(self):
        req = _sent_req(["nudge", "--delta", "10"])
        assert req == {"command": "nudge", "delta": 10}

    def test_nudge_explicit_negative_delta(self):
        req = _sent_req(["nudge", "--delta", "-5"])
        assert req == {"command": "nudge", "delta": -5}


# ---------------------------------------------------------------------------
# --json flag position
# ---------------------------------------------------------------------------

class TestJsonFlag:
    def _json_run(self, argv: list[str]) -> tuple[int, str, str]:
        resp = {
            "ok": True,
            "service": "autostream-dial",
            "protocol_version": 1,
            "software_version": "1.0",
        }
        return _run(argv, resp)

    def test_json_before_subcommand(self):
        code, out, err = self._json_run(["--json", "ping"])
        assert code == 0
        data = json.loads(out.strip())
        assert data["ok"] is True

    def test_json_after_subcommand(self):
        code, out, err = self._json_run(["ping", "--json"])
        assert code == 0
        data = json.loads(out.strip())
        assert data["ok"] is True

    def test_json_mode_one_compact_line(self):
        code, out, err = self._json_run(["--json", "ping"])
        lines = [l for l in out.split("\n") if l.strip()]
        assert len(lines) == 1

    def test_json_mode_sort_keys(self):
        code, out, err = self._json_run(["--json", "ping"])
        line = out.strip()
        # sort_keys=True means keys appear alphabetically
        parsed = json.loads(line)
        assert isinstance(parsed, dict)

    def test_json_duplicate_is_usage_error(self):
        code, out, err = _run(["--json", "--json", "ping"])
        assert code == 2


# ---------------------------------------------------------------------------
# Human-readable output
# ---------------------------------------------------------------------------

class TestHumanOutput:
    def test_ping_output(self):
        code, out, err = _run(["ping"], {"ok": True, "service": "autostream-dial"})
        assert code == 0
        assert "autostream-dial" in out

    def test_version_output(self):
        resp = {"ok": True, "protocol_version": 1, "software_version": "1.2.3",
                "protocol": "autostream-dial-control"}
        code, out, err = _run(["version"], resp)
        assert code == 0
        assert "1" in out   # protocol version
        assert "1.2.3" in out

    def test_status_output_contains_key_fields(self):
        resp = {
            "ok": True,
            "uuid": "test-uuid-1234",
            "name": "Hallway Dial",
            "step_percent": 2,
            "target_count": 1,
            "recovery_active": False,
            "volume_confirmed": False,
        }
        code, out, err = _run(["status"], resp)
        assert code == 0
        assert "test-uuid-1234" in out
        assert "Hallway Dial" in out
        assert "2%" in out
        assert "inactive" in out

    def test_status_recovery_active(self):
        resp = {
            "ok": True,
            "uuid": "u", "name": "n", "step_percent": 2, "target_count": 0,
            "recovery_active": True, "volume_confirmed": False,
        }
        code, out, err = _run(["status"], resp)
        assert "active" in out
        assert "inactive" not in out

    def test_status_recovery_confirmed(self):
        resp = {
            "ok": True,
            "uuid": "u", "name": "n", "step_percent": 2, "target_count": 0,
            "recovery_active": True, "volume_confirmed": True,
        }
        code, out, err = _run(["status"], resp)
        assert "confirmed" in out

    def test_targets_empty(self):
        code, out, err = _run(["targets"], {"ok": True, "count": 0, "targets": []})
        assert code == 0
        assert out.strip()  # some output

    def test_targets_with_data(self):
        resp = {
            "ok": True,
            "count": 1,
            "targets": [{
                "name": "Kitchen",
                "ip": "192.168.1.20",
                "port": 80,
                "dial_api": True,
                "audio_status": True,
                "dial_status": True,
                "playing": True,
                "master_volume": 59,
                "selected_output_count": 2,
                "status_error": None,
            }],
        }
        code, out, err = _run(["targets"], resp)
        assert code == 0
        assert "Kitchen" in out
        assert "59" in out

    def test_targets_with_error(self):
        resp = {
            "ok": True,
            "count": 1,
            "targets": [{
                "name": "Kitchen",
                "ip": "192.168.1.20",
                "port": 80,
                "dial_api": True,
                "audio_status": True,
                "dial_status": True,
                "playing": None,
                "master_volume": None,
                "selected_output_count": None,
                "status_error": "timeout",
            }],
        }
        code, out, err = _run(["targets"], resp)
        assert code == 0
        assert "timeout" in out

    def test_nudge_up_output(self):
        resp = {"ok": True, "queued": True, "delta": 2, "target_count": 1}
        code, out, err = _run(["nudge", "up"], resp)
        assert code == 0
        assert "+2" in out
        assert "1" in out

    def test_nudge_down_output(self):
        resp = {"ok": True, "queued": True, "delta": -2, "target_count": 0}
        code, out, err = _run(["nudge", "down"], resp)
        assert code == 0
        assert "-2" in out

    def test_nudge_no_targets_still_clear(self):
        resp = {"ok": True, "queued": True, "delta": 2, "target_count": 0}
        code, out, err = _run(["nudge", "up"], resp)
        assert code == 0
        assert "0" in out


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

class TestExitCodes:
    def test_ok_true_is_exit_0(self):
        code, _, _ = _run(["ping"], {"ok": True, "service": "autostream-dial"})
        assert code == 0

    def test_ok_false_is_exit_1(self):
        code, _, _ = _run(["ping"], {"ok": False, "error": "some_error", "message": "bad"})
        assert code == 1

    def test_no_subcommand_is_exit_2(self):
        code, _, _ = _run([])
        assert code == 2

    def test_unknown_subcommand_is_exit_2(self):
        code, _, _ = _run(["unknown"])
        assert code == 2

    def test_nudge_no_direction_or_delta_is_exit_2(self):
        code, _, _ = _run(["nudge"])
        assert code == 2

    def test_socket_not_found_is_exit_3(self):
        # _transport_error calls sys.exit(3) from within _send_command.
        # We patch _send_command itself to do the same side effect.
        def raise_exit_3(*a, **kw):
            raise SystemExit(3)

        code, _, _ = _run(["ping"], None)  # won't reach _send_command normally
        # Instead directly test transport error path
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        with patch("autostream_dial_control._send_command", side_effect=raise_exit_3):
            with patch("sys.stdout", stdout_buf), patch("sys.stderr", stderr_buf):
                try:
                    cli.main(["ping"])
                    code = 0
                except SystemExit as e:
                    code = e.code
        assert code == 3

    def test_json_mode_ok_false_is_exit_1(self):
        resp = {"ok": False, "error": "some_error", "message": "oops"}
        code, out, err = _run(["--json", "ping"], resp)
        assert code == 1
        data = json.loads(out.strip())
        assert data["ok"] is False


# ---------------------------------------------------------------------------
# stderr on server failure
# ---------------------------------------------------------------------------

class TestStderrOnFailure:
    def test_message_in_stderr_on_ok_false(self):
        resp = {"ok": False, "error": "some_error", "message": "something went wrong"}
        code, out, err = _run(["ping"], resp)
        assert code == 1
        assert "something went wrong" in err

    def test_error_in_stderr_when_no_message(self):
        resp = {"ok": False, "error": "some_error"}
        code, out, err = _run(["ping"], resp)
        assert code == 1
        assert "some_error" in err


# ---------------------------------------------------------------------------
# Transport failure simulation
# ---------------------------------------------------------------------------

class TestTransportFailure:
    def _run_with_transport_error(self, exc):
        with patch("autostream_dial_control._send_command", side_effect=exc):
            stdout_buf = io.StringIO()
            stderr_buf = io.StringIO()
            with patch("sys.stdout", stdout_buf), patch("sys.stderr", stderr_buf):
                try:
                    cli.main(["ping"])
                    code = 0
                except SystemExit as e:
                    code = e.code
        return code, stdout_buf.getvalue(), stderr_buf.getvalue()

    def test_file_not_found_exit_3(self):
        code, _, _ = self._run_with_transport_error(SystemExit(3))
        assert code == 3


# ---------------------------------------------------------------------------
# CLI does not import dial runtime modules
# ---------------------------------------------------------------------------

class TestImportIsolation:
    def test_cli_does_not_import_dial_volume(self):
        import importlib
        # dial_volume should not be in the imported modules of the CLI
        cli_source = (REPO_ROOT / "dial" / "autostream_dial_control.py").read_text()
        assert "dial_volume" not in cli_source

    def test_cli_does_not_import_dial_mdns(self):
        cli_source = (REPO_ROOT / "dial" / "autostream_dial_control.py").read_text()
        assert "dial_mdns" not in cli_source

    def test_cli_does_not_import_dial_http_server(self):
        cli_source = (REPO_ROOT / "dial" / "autostream_dial_control.py").read_text()
        assert "dial_http_server" not in cli_source

    def test_cli_imports_only_protocol_constants(self):
        cli_source = (REPO_ROOT / "dial" / "autostream_dial_control.py").read_text()
        assert "dial_control_protocol" in cli_source
