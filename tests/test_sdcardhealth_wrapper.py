"""autostream_sdcardhealth wrapper tests.

Covers the pure parts of the wrapper: state-file key rewriting, marker
read/write/remove, status-file assembly, the guarded probe's success/
failure/timeout outcomes, the marker-based hang detection shared by `run`
and `check`, `boot-check`'s stale-vs-matching marker handling, and the
`enable`/`disable` verbs. All systemctl calls are stubbed so these tests
never touch the real service manager.
"""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "tests"))
from conftest import load_supervisor_script

m = load_supervisor_script("autostream_sdcardhealth", "sdcardhealth_wrapper")


@pytest.fixture(autouse=True)
def _isolated_paths(tmp_path, monkeypatch):
    """Point every wrapper path at a scratch directory for each test."""
    monkeypatch.setattr(m, "STATE_DIR", tmp_path)
    monkeypatch.setattr(m, "STATE_FILE", tmp_path / "install-state.env")
    monkeypatch.setattr(m, "MARKER_FILE", tmp_path / "sdcardhealth.inflight")
    monkeypatch.setattr(m, "STATUS_FILE", tmp_path / "sdcardhealth-status.json")
    monkeypatch.setattr(m, "HEALTH_JSON_FILE", tmp_path / "sdcardhealth.json")
    monkeypatch.setattr(m, "SERIAL_FILE", tmp_path / "serial")
    monkeypatch.setattr(m, "SDMON_BIN", str(tmp_path / "sdmon"))
    monkeypatch.setattr(m, "PROBE_TIMEOUT_SECONDS", 1)
    # Never touch the real service manager; individual tests that care about
    # the systemctl calls made patch this back with a recording stub.
    monkeypatch.setattr(m, "_systemctl", lambda *args: 0)
    monkeypatch.setattr(m, "_timer_is_enabled", lambda: False)
    return tmp_path


def _make_sdmon(tmp_path, body: str) -> str:
    path = tmp_path / "sdmon"
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


# ---------------------------------------------------------------------------
# read_card_serial
# ---------------------------------------------------------------------------

class TestReadCardSerial:
    def test_missing_file_returns_empty(self):
        assert m.read_card_serial() == ""

    def test_reads_and_strips_serial(self, tmp_path):
        m.SERIAL_FILE.write_text("0xABCDEF\n", encoding="utf-8")
        assert m.read_card_serial() == "0xABCDEF"


# ---------------------------------------------------------------------------
# Marker file
# ---------------------------------------------------------------------------

class TestMarker:
    def test_no_marker_returns_none(self):
        assert m.read_marker() is None

    def test_write_then_read_round_trips(self):
        m.write_marker("serial-1", "sandisk")
        marker = m.read_marker()
        assert marker["serial"] == "serial-1"
        assert marker["method"] == "sandisk"
        assert "at" in marker

    def test_remove_marker_is_idempotent(self):
        m.write_marker("serial-1", "auto")
        m.remove_marker()
        assert m.read_marker() is None
        m.remove_marker()  # no error on a second call

    def test_unparsable_marker_returns_empty_dict(self):
        m.MARKER_FILE.write_text("not json", encoding="utf-8")
        assert m.read_marker() == {}


# ---------------------------------------------------------------------------
# install-state.env: in-place key rewriting
# ---------------------------------------------------------------------------

class TestUpdateStateFile:
    def test_creates_file_when_absent(self):
        m.update_state_file({"SDMON_METHOD": "auto"})
        text = m.STATE_FILE.read_text(encoding="utf-8")
        assert 'SDMON_METHOD="auto"' in text

    def test_preserves_other_lines_and_order(self):
        m.STATE_FILE.write_text(
            "# comment\n"
            "AUTOSTREAM_PRODUCT=autostream\n"
            "OWNTONE_MODE=\"mini\"\n"
            "SDMON_METHOD=\"old\"\n"
            "FETCH_AUTOSTREAM=\"0\"\n",
            encoding="utf-8",
        )
        m.update_state_file({"SDMON_METHOD": "sandisk"})
        lines = m.STATE_FILE.read_text(encoding="utf-8").splitlines()
        assert lines == [
            "# comment",
            "AUTOSTREAM_PRODUCT=autostream",
            'OWNTONE_MODE="mini"',
            'SDMON_METHOD="sandisk"',
            'FETCH_AUTOSTREAM="0"',
        ]

    def test_adds_missing_keys_at_end(self):
        m.STATE_FILE.write_text("AUTOSTREAM_PRODUCT=autostream\n", encoding="utf-8")
        m.update_state_file({"SDMON_CHECK": "passed", "SDMON_CHECK_SERIAL": "abc"})
        lines = m.STATE_FILE.read_text(encoding="utf-8").splitlines()
        assert lines[0] == "AUTOSTREAM_PRODUCT=autostream"
        assert 'SDMON_CHECK="passed"' in lines
        assert 'SDMON_CHECK_SERIAL="abc"' in lines

    def test_only_touches_requested_keys(self):
        m.STATE_FILE.write_text(
            'SDMON_METHOD="auto"\nSDMON_CHECK="failed"\n', encoding="utf-8"
        )
        m.update_state_file({"SDMON_METHOD": "sandisk"})
        text = m.STATE_FILE.read_text(encoding="utf-8")
        assert 'SDMON_METHOD="sandisk"' in text
        assert 'SDMON_CHECK="failed"' in text

    def test_sanitizes_newlines_and_quotes_in_value(self):
        m.update_state_file({"SDMON_CHECK_REASON": 'bad "quote"\nand newline'})
        text = m.STATE_FILE.read_text(encoding="utf-8")
        assert "\n" not in text.strip().split("=", 1)[1]
        assert text.count('"') == 2  # only the wrapping quotes survive

    def test_file_is_written_atomically(self):
        m.update_state_file({"SDMON_METHOD": "auto"})
        tmp = m.STATE_FILE.with_suffix(m.STATE_FILE.suffix + ".tmp")
        assert not tmp.exists()
        assert m.STATE_FILE.exists()


class TestReadStateValue:
    def test_missing_file_returns_default(self):
        assert m.read_state_value("SDMON_METHOD", "auto") == "auto"

    def test_reads_quoted_value(self):
        m.STATE_FILE.write_text('SDMON_METHOD="sandisk"\n', encoding="utf-8")
        assert m.read_state_value("SDMON_METHOD") == "sandisk"

    def test_missing_key_returns_default(self):
        m.STATE_FILE.write_text('OWNTONE_MODE="mini"\n', encoding="utf-8")
        assert m.read_state_value("SDMON_METHOD", "none") == "none"


# ---------------------------------------------------------------------------
# Status file
# ---------------------------------------------------------------------------

class TestWriteStatusFile:
    def test_writes_expected_shape(self):
        m.STATE_FILE.write_text(
            'SDMON_METHOD="sandisk"\n'
            'SDMON_CHECK="passed"\n'
            'SDMON_CHECK_SERIAL="abc123"\n'
            'SDMON_CHECK_AT="2026-01-01T00:00:00Z"\n'
            'SDMON_CHECK_REASON=""\n',
            encoding="utf-8",
        )
        m.write_status_file()
        payload = json.loads(m.STATUS_FILE.read_text(encoding="utf-8"))
        assert payload == {
            "tool_present": False,
            "timer_enabled": False,
            "method": "sandisk",
            "check": "passed",
            "serial": "abc123",
            "at": "2026-01-01T00:00:00Z",
            "reason": "",
        }

    def test_defaults_check_to_none_when_state_file_absent(self):
        m.write_status_file()
        payload = json.loads(m.STATUS_FILE.read_text(encoding="utf-8"))
        assert payload["check"] == "none"
        assert payload["method"] == ""

    def test_written_atomically_and_world_readable(self):
        m.write_status_file()
        tmp = m.STATUS_FILE.with_suffix(m.STATUS_FILE.suffix + ".tmp")
        assert not tmp.exists()
        mode = m.STATUS_FILE.stat().st_mode & 0o777
        assert mode == 0o644

    def test_reflects_tool_present(self, tmp_path):
        sdmon = _make_sdmon(tmp_path, "#!/bin/sh\nexit 0\n")
        m.SDMON_BIN = sdmon
        m.write_status_file()
        payload = json.loads(m.STATUS_FILE.read_text(encoding="utf-8"))
        assert payload["tool_present"] is True


# ---------------------------------------------------------------------------
# do_probe: success, failure, timeout
# ---------------------------------------------------------------------------

class TestDoProbe:
    def test_success_returns_payload(self, tmp_path):
        m.SDMON_BIN = _make_sdmon(
            tmp_path, '#!/bin/sh\necho \'{"success": true, "percent": 87}\'\nexit 0\n'
        )
        ok, reason, payload = m.do_probe("auto", "serial-1")
        assert ok is True
        assert reason == ""
        assert payload == {"success": True, "percent": 87}
        assert m.read_marker() is None  # cleaned up after the probe

    def test_failure_with_json_reason(self, tmp_path):
        m.SDMON_BIN = _make_sdmon(
            tmp_path,
            '#!/bin/sh\necho \'{"success": false, "reason": "card not supported"}\'\nexit 1\n',
        )
        ok, reason, payload = m.do_probe("auto", "serial-1")
        assert ok is False
        assert reason == "card not supported"
        assert payload["success"] is False

    def test_failure_with_plain_text_reason(self, tmp_path):
        m.SDMON_BIN = _make_sdmon(
            tmp_path, "#!/bin/sh\necho 'device or resource busy' 1>&2\nexit 1\n"
        )
        ok, reason, payload = m.do_probe("auto", "serial-1")
        assert ok is False
        assert "device or resource busy" in reason
        assert payload is None

    def test_reason_truncated_to_200_chars(self, tmp_path):
        long_reason = "x" * 500
        m.SDMON_BIN = _make_sdmon(
            tmp_path, f"#!/bin/sh\necho '{long_reason}' 1>&2\nexit 1\n"
        )
        _, reason, _ = m.do_probe("auto", "serial-1")
        assert len(reason) == 200

    def test_timeout_is_failed_not_hung(self, tmp_path):
        m.SDMON_BIN = _make_sdmon(tmp_path, "#!/bin/sh\nsleep 3\n")
        ok, reason, payload = m.do_probe("auto", "serial-1")
        assert ok is False
        assert "no response" in reason
        assert payload is None
        assert m.read_marker() is None  # marker removed even on timeout

    def test_2step_method_adds_dash_a(self, tmp_path):
        # A script that just dumps its argv lets us confirm -a is present.
        m.SDMON_BIN = _make_sdmon(
            tmp_path,
            '#!/bin/sh\necho "{\\"success\\": true, \\"args\\": \\"$*\\"}"\n',
        )
        ok, _, payload = m.do_probe("2step", "serial-1")
        assert ok is True
        assert "-a" in payload["args"]


# ---------------------------------------------------------------------------
# run / check: marker-based hang detection
# ---------------------------------------------------------------------------

class TestProbeAndRecord:
    def test_run_hung_marker_disables_timer_and_exits_4(self):
        m.write_marker("serial-1", "auto")
        m.SERIAL_FILE.write_text("serial-1\n", encoding="utf-8")
        calls = []
        with patch.object(m, "_systemctl", side_effect=lambda *a: calls.append(a) or 0):
            rc = m.cmd_run(None)
        assert rc == 4
        assert m.read_marker() is None
        assert m.read_state_value("SDMON_CHECK") == "hung"
        assert calls and calls[0] == ("disable", "--now", m.TIMER_UNIT)

    def test_check_hung_marker_never_touches_timer(self):
        m.write_marker("serial-1", "auto")
        m.SERIAL_FILE.write_text("serial-1\n", encoding="utf-8")
        with patch.object(m, "_systemctl") as mock_systemctl:
            rc = m.cmd_check(None)
        assert rc == 4
        mock_systemctl.assert_not_called()
        assert m.read_state_value("SDMON_CHECK") == "hung"

    def test_stale_marker_for_different_card_is_removed_and_probe_proceeds(self, tmp_path):
        m.write_marker("other-serial", "auto")
        m.SERIAL_FILE.write_text("serial-1\n", encoding="utf-8")
        m.SDMON_BIN = _make_sdmon(tmp_path, '#!/bin/sh\necho \'{"success": true}\'\n')
        rc = m.cmd_check(None)
        assert rc == 0
        assert m.read_state_value("SDMON_CHECK") == "passed"
        assert m.read_state_value("SDMON_CHECK_SERIAL") == "serial-1"

    def test_tool_missing_returns_2(self):
        rc = m.cmd_run(None)
        assert rc == 2
        assert m.STATUS_FILE.exists()

    def test_run_success_records_passed_and_writes_health_json(self, tmp_path):
        m.SDMON_BIN = _make_sdmon(
            tmp_path, '#!/bin/sh\necho \'{"success": true, "percent": 91}\'\n'
        )
        m.SERIAL_FILE.write_text("serial-9\n", encoding="utf-8")
        rc = m.cmd_run(None)
        assert rc == 0
        assert m.read_state_value("SDMON_CHECK") == "passed"
        assert json.loads(m.HEALTH_JSON_FILE.read_text(encoding="utf-8"))["percent"] == 91

    def test_check_failure_returns_3_and_records_reason(self, tmp_path):
        m.SDMON_BIN = _make_sdmon(
            tmp_path,
            '#!/bin/sh\necho \'{"success": false, "reason": "unsupported"}\'\nexit 1\n',
        )
        rc = m.cmd_check("sandisk")
        assert rc == 3
        assert m.read_state_value("SDMON_CHECK") == "failed"
        assert m.read_state_value("SDMON_CHECK_REASON") == "unsupported"

    def test_uses_saved_method_when_none_given(self, tmp_path):
        m.STATE_FILE.write_text('SDMON_METHOD="innodisk"\n', encoding="utf-8")
        seen = {}

        def fake_do_probe(method, serial):
            seen["method"] = method
            return True, "", {"success": True}

        with patch.object(m, "_tool_present", return_value=True), \
             patch.object(m, "do_probe", side_effect=fake_do_probe):
            m.cmd_check(None)
        assert seen["method"] == "innodisk"

    def test_defaults_to_auto_when_nothing_saved(self):
        seen = {}

        def fake_do_probe(method, serial):
            seen["method"] = method
            return True, "", {"success": True}

        with patch.object(m, "_tool_present", return_value=True), \
             patch.object(m, "do_probe", side_effect=fake_do_probe):
            m.cmd_check(None)
        assert seen["method"] == "auto"


# ---------------------------------------------------------------------------
# boot-check
# ---------------------------------------------------------------------------

class TestBootCheck:
    def test_no_marker_does_nothing_but_writes_status(self):
        with patch.object(m, "_systemctl") as mock_systemctl:
            rc = m.cmd_boot_check()
        assert rc == 0
        mock_systemctl.assert_not_called()
        assert m.STATUS_FILE.exists()
        assert m.read_state_value("SDMON_CHECK", "none") == "none"

    def test_matching_marker_records_hung_and_disables_timer(self):
        m.write_marker("serial-1", "auto")
        m.SERIAL_FILE.write_text("serial-1\n", encoding="utf-8")
        calls = []
        with patch.object(m, "_systemctl", side_effect=lambda *a: calls.append(a) or 0):
            rc = m.cmd_boot_check()
        assert rc == 0
        assert m.read_marker() is None
        assert m.read_state_value("SDMON_CHECK") == "hung"
        assert calls == [("disable", "--now", m.TIMER_UNIT)]

    def test_mismatched_marker_is_removed_without_recording(self):
        m.write_marker("other-serial", "auto")
        m.SERIAL_FILE.write_text("serial-1\n", encoding="utf-8")
        with patch.object(m, "_systemctl") as mock_systemctl:
            rc = m.cmd_boot_check()
        assert rc == 0
        assert m.read_marker() is None
        mock_systemctl.assert_not_called()
        assert m.read_state_value("SDMON_CHECK", "none") == "none"

    def test_always_exits_0(self):
        m.write_marker("serial-1", "auto")
        m.SERIAL_FILE.write_text("serial-1\n", encoding="utf-8")
        assert m.cmd_boot_check() == 0


# ---------------------------------------------------------------------------
# enable / disable
# ---------------------------------------------------------------------------

class TestEnableDisable:
    def test_enable_rejects_invalid_method(self):
        rc = m.cmd_enable("bogus")
        assert rc == 1
        assert m.read_state_value("SDMON_METHOD", "") == ""

    def test_enable_rejects_missing_method(self):
        assert m.cmd_enable(None) == 1

    def test_enable_saves_method_and_enables_timer(self):
        calls = []
        with patch.object(m, "_systemctl", side_effect=lambda *a: calls.append(a) or 0):
            rc = m.cmd_enable("sandisk")
        assert rc == 0
        assert m.read_state_value("SDMON_METHOD") == "sandisk"
        assert ("enable", "--now", m.TIMER_UNIT) in calls
        assert ("start", "--no-block", m.SERVICE_UNIT) in calls

    def test_enable_failure_to_enable_timer_returns_1(self):
        with patch.object(m, "_systemctl", return_value=1):
            rc = m.cmd_enable("sandisk")
        assert rc == 1

    def test_disable_clears_method_keeps_check_fields(self):
        m.STATE_FILE.write_text(
            'SDMON_METHOD="sandisk"\n'
            'SDMON_CHECK="passed"\n'
            'SDMON_CHECK_SERIAL="abc"\n',
            encoding="utf-8",
        )
        calls = []
        with patch.object(m, "_systemctl", side_effect=lambda *a: calls.append(a) or 0):
            rc = m.cmd_disable()
        assert rc == 0
        assert m.read_state_value("SDMON_METHOD") == ""
        assert m.read_state_value("SDMON_CHECK") == "passed"
        assert m.read_state_value("SDMON_CHECK_SERIAL") == "abc"
        assert ("disable", "--now", m.TIMER_UNIT) in calls


# ---------------------------------------------------------------------------
# main() / parse_args: mode and exit-code wiring
# ---------------------------------------------------------------------------

class TestMainDispatch:
    @pytest.mark.parametrize("mode", ["run", "check", "boot-check", "enable", "disable"])
    def test_mode_parses(self, mode):
        argv = [mode] if mode != "enable" else [mode, "--method", "auto"]
        args = m.parse_args(argv)
        assert args.mode == mode

    def test_main_run_dispatches(self):
        with patch.object(m, "cmd_run", return_value=0) as mock_fn:
            rc = m.main(["run"])
        mock_fn.assert_called_once_with(None)
        assert rc == 0

    def test_main_check_passes_method(self):
        with patch.object(m, "cmd_check", return_value=3) as mock_fn:
            rc = m.main(["check", "--method", "sandisk"])
        mock_fn.assert_called_once_with("sandisk")
        assert rc == 3

    def test_main_boot_check_dispatches(self):
        with patch.object(m, "cmd_boot_check", return_value=0) as mock_fn:
            rc = m.main(["boot-check"])
        mock_fn.assert_called_once()
        assert rc == 0

    def test_main_enable_dispatches(self):
        with patch.object(m, "cmd_enable", return_value=0) as mock_fn:
            rc = m.main(["enable", "--method", "auto"])
        mock_fn.assert_called_once_with("auto")
        assert rc == 0

    def test_main_disable_dispatches(self):
        with patch.object(m, "cmd_disable", return_value=0) as mock_fn:
            rc = m.main(["disable"])
        mock_fn.assert_called_once()
        assert rc == 0
