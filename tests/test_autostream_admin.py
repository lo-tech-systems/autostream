"""Priority 8 — autostream_admin privileged helper tests.

Covers hostname update, NetworkDown rate limiting, delayed reboot scheduling,
product detection, product-specific factory reset (service stopping, file
deletion, log rotation), two-stage product validation (schedule + execute),
log rotation policy selection, update-status installer-log selection,
Avahi XML escaping, and update status parsing.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

# Load the extensionless supervisor script via the shared helper.
sys.path.insert(0, str(Path(__file__).parent.parent / "tests"))
from conftest import load_supervisor_script

# Use a unique alias so we don't stomp on other imports.
m = load_supervisor_script("autostream_admin", "admin_p8")


# ---------------------------------------------------------------------------
# validate_hostname
# ---------------------------------------------------------------------------

class TestValidateHostname:
    def test_valid_hostname(self):
        ok, why = m.validate_hostname("autostream")
        assert ok is True

    def test_hostname_with_hyphen(self):
        ok, why = m.validate_hostname("my-device-01")
        assert ok is True

    def test_dot_rejected(self):
        ok, why = m.validate_hostname("my.device")
        assert ok is False
        assert "dot" in why or "single" in why

    def test_leading_hyphen_rejected(self):
        ok, why = m.validate_hostname("-bad")
        assert ok is False

    def test_trailing_hyphen_rejected(self):
        ok, why = m.validate_hostname("bad-")
        assert ok is False

    def test_too_long_rejected(self):
        ok, why = m.validate_hostname("a" * 64)
        assert ok is False
        assert "long" in why

    def test_empty_rejected(self):
        ok, why = m.validate_hostname("")
        assert ok is False

    def test_leading_whitespace_rejected(self):
        ok, why = m.validate_hostname(" autostream")
        assert ok is False
        assert "whitespace" in why


# ---------------------------------------------------------------------------
# update_etc_hosts
# ---------------------------------------------------------------------------

class TestUpdateEtcHosts:
    def _call_update_hosts(self, hosts_content: str, new_name: str):
        """Helper: patch atomic_write_text + read_text, call update_etc_hosts."""
        written = []
        import pathlib

        orig_read = pathlib.Path.read_text
        def patched_read_text(self, *args, **kwargs):
            return hosts_content

        with patch.object(m, "atomic_write_text",
                          side_effect=lambda path, text, mode=0o644: written.append(text)), \
             patch.object(pathlib.Path, "read_text", patched_read_text):
            m.update_etc_hosts(new_name)

        return written[0] if written else ""

    def test_replaces_existing_127_0_1_1(self):
        hosts = "127.0.0.1\tlocalhost\n127.0.1.1\told-hostname\n"
        result = self._call_update_hosts(hosts, "new-hostname")
        assert "127.0.1.1\tnew-hostname" in result
        assert "old-hostname" not in result
        assert "localhost" in result

    def test_appends_if_no_127_0_1_1_present(self):
        hosts = "127.0.0.1\tlocalhost\n"
        result = self._call_update_hosts(hosts, "autostream-new")
        assert "127.0.1.1\tautostream-new" in result

    def test_preserves_comment_lines(self):
        hosts = "# This is a comment\n127.0.0.1\tlocalhost\n127.0.1.1\told-name\n"
        result = self._call_update_hosts(hosts, "myhost")
        assert "# This is a comment" in result

    def test_preserves_127_0_1_1_inline_comment(self):
        hosts = "127.0.1.1\told-name # this is the appliance\n"
        result = self._call_update_hosts(hosts, "new-name")
        assert "new-name" in result
        assert "appliance" in result


# ---------------------------------------------------------------------------
# NetworkDown rate limiting
# ---------------------------------------------------------------------------

class TestNetworkDownRateLimit:
    def test_no_stamp_file_not_rate_limited(self, tmp_path):
        stamp = tmp_path / "reboot_networkdown.stamp"
        with patch.object(m, "NETWORKDOWN_STAMP", stamp), \
             patch.object(m, "STAMP_DIR", tmp_path):
            limited, remaining = m.should_rate_limit_networkdown()
        assert limited is False

    def test_recent_stamp_rate_limits(self, tmp_path):
        import time
        stamp = tmp_path / "reboot_networkdown.stamp"
        stamp.touch()
        with patch.object(m, "NETWORKDOWN_STAMP", stamp), \
             patch.object(m, "STAMP_DIR", tmp_path):
            limited, remaining = m.should_rate_limit_networkdown()
        assert limited is True
        assert remaining is not None and remaining > 0

    def test_old_stamp_not_rate_limited(self, tmp_path):
        import time
        stamp = tmp_path / "reboot_networkdown.stamp"
        stamp.touch()
        # Set mtime to 2 hours ago
        old_time = time.time() - 7200
        import os
        os.utime(stamp, (old_time, old_time))
        with patch.object(m, "NETWORKDOWN_STAMP", stamp), \
             patch.object(m, "STAMP_DIR", tmp_path):
            limited, remaining = m.should_rate_limit_networkdown()
        assert limited is False


# ---------------------------------------------------------------------------
# reboot_host: reason validation
# ---------------------------------------------------------------------------

class TestRebootHost:
    def test_invalid_reason_returns_false(self):
        result = m.reboot_host("ClearlyInvalidReason")
        assert result is False

    def test_valid_reason_calls_reboot(self, tmp_path):
        stamp = tmp_path / "reboot_networkdown.stamp"
        reboot_bin = tmp_path / "reboot"
        reboot_bin.write_text("#!/bin/sh\nexit 0\n")
        with patch.object(m, "NETWORKDOWN_STAMP", stamp), \
             patch.object(m, "STAMP_DIR", tmp_path), \
             patch.object(m.Path, "exists", return_value=True), \
             patch.object(m, "run_cmd", return_value=(0, "", "")):
            result = m.reboot_host("UserRequestNormal")
        assert result is True

    def test_missing_reboot_bin_returns_false(self, tmp_path):
        with patch.object(m.Path, "exists", return_value=False):
            result = m.reboot_host("UserRequestNormal")
        assert result is False

    def test_networkdown_rate_limited_returns_none_without_reboot(self, tmp_path):
        import time
        stamp = tmp_path / "reboot_networkdown.stamp"
        stamp.touch()
        run_calls = []
        with patch.object(m, "NETWORKDOWN_STAMP", stamp), \
             patch.object(m, "STAMP_DIR", tmp_path), \
             patch.object(m, "run_cmd",
                          side_effect=lambda cmd: run_calls.append(cmd) or (0, "", "")):
            result = m.reboot_host("NetworkDown")
        assert result is None, "rate-limited reboot_host must return None, not True"
        assert not any(
            "reboot" in str(c).lower() for c in run_calls
        ), "reboot should not be called when rate limited"


# ---------------------------------------------------------------------------
# schedule_delayed_reboot
# ---------------------------------------------------------------------------

class TestScheduleDelayedReboot:
    def test_zero_delay_calls_reboot_host(self):
        with patch.object(m, "reboot_host", return_value=True) as mock_rb:
            result = m.schedule_delayed_reboot(0, "UserRequestNormal")
        mock_rb.assert_called_once_with("UserRequestNormal")
        assert result is True

    def test_delay_too_large_returns_false(self):
        result = m.schedule_delayed_reboot(24 * 60 * 60 + 1, "UserRequestNormal")
        assert result is False

    def test_positive_delay_uses_systemd_run(self):
        cmd_args = []

        def fake_find_systemd_run():
            return "/usr/bin/systemd-run"

        def fake_run_cmd(cmd):
            cmd_args.extend(cmd)
            return (0, "", "")

        with patch.object(m, "find_systemd_run", side_effect=fake_find_systemd_run), \
             patch.object(m, "run_cmd", side_effect=fake_run_cmd):
            result = m.schedule_delayed_reboot(60, "AutostreamUpdate")

        assert result is True
        assert "--on-active=60" in cmd_args
        assert "AutostreamUpdate" in cmd_args
        assert "--quiet" in cmd_args
        assert "--collect" in cmd_args

    def test_systemd_run_failure_returns_false(self):
        with patch.object(m, "find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch.object(m, "run_cmd", return_value=(1, "", "error")):
            result = m.schedule_delayed_reboot(30, "UserRequestNormal")
        assert result is False

    def test_no_systemd_run_returns_false(self):
        with patch.object(m, "find_systemd_run", return_value=None):
            result = m.schedule_delayed_reboot(30, "UserRequestNormal")
        assert result is False


# ---------------------------------------------------------------------------
# Factory reset: lock, allowlist, wifi type filter
# ---------------------------------------------------------------------------

class TestFactoryResetHelpers:
    def test_acquire_reset_lock_returns_file_object(self, tmp_path):
        lock_dir = tmp_path / "run" / "autostream"
        lock_file = lock_dir / "factory-reset.lock"
        with patch.object(m, "FACTORY_RESET_LOCK_DIR", lock_dir), \
             patch.object(m, "FACTORY_RESET_LOCK_FILE", lock_file):
            fd = m._acquire_reset_lock()
        if fd is None:
            pytest.skip("fcntl not available on this platform")
        assert fd is not None
        fd.close()

    def test_delete_reset_files_deletes_only_allowlist(self, tmp_path):
        # Create dummy allowlist files
        allowlist = []
        for p in m.FACTORY_RESET_DELETE_FILES:
            fake = tmp_path / p.name
            fake.write_text("data")
            allowlist.append(fake)

        extra = tmp_path / "should-not-be-deleted.txt"
        extra.write_text("keep me")

        with patch.object(m, "FACTORY_RESET_DELETE_FILES", tuple(allowlist)):
            m._delete_reset_files()

        for p in allowlist:
            assert not p.exists(), f"{p.name} should be deleted"
        assert extra.exists(), "non-allowlist file must not be deleted"

    def test_delete_wifi_connections_filters_by_wifi_type(self):
        nmcli_output = (
            "NAME:My-WiFi\n"
            "TYPE:802-11-wireless\n"
            "NAME:WiredConn\n"
            "TYPE:802-3-ethernet\n"
        )
        deleted = []

        def fake_run_cmd(cmd):
            if "connection" in cmd and "show" in cmd:
                return (0, nmcli_output, "")
            if "delete" in cmd:
                deleted.append(cmd[-1])
                return (0, "", "")
            return (0, "", "")

        with patch.object(m, "find_nmcli", return_value="/usr/bin/nmcli"), \
             patch.object(m, "run_cmd", side_effect=fake_run_cmd):
            m._delete_wifi_connections()

        assert "My-WiFi" in deleted
        assert "WiredConn" not in deleted

    def test_execute_factory_reset_lock_held_prevents_double_reset(self):
        with patch.object(m, "_acquire_reset_lock", return_value=None):
            result = m._execute_factory_reset()
        assert result is False


# ---------------------------------------------------------------------------
# Avahi XML escaping: _write_playing_service and _update_dial_service
# ---------------------------------------------------------------------------

class TestAvahiXmlEscaping:
    def test_playing_service_escapes_version_html(self, tmp_path):
        svc_dir = tmp_path / "avahi"
        svc_dir.mkdir()
        svc_file = svc_dir / "autostream-playing.service"

        args = MagicMock()
        args.version = "<script>bad</script>"

        with patch.object(m, "_AVAHI_SERVICES_DIR", svc_dir), \
             patch.object(m, "_PLAYING_SERVICE", svc_file):
            m._write_playing_service(args)

        assert svc_file.exists(), "_write_playing_service did not write anything"
        content = svc_file.read_text(encoding="utf-8")
        assert "<script>" not in content
        assert "&lt;script&gt;" in content

    def test_dial_service_rejects_semicolon_in_name(self, tmp_path):
        template = tmp_path / "template.xml"
        template.write_text(
            "<txt-record>__DIAL_UUID__</txt-record>"
            "<txt-record>__DIAL_NAME__</txt-record>"
            "<txt-record>__AUTOSTREAM_RELEASE_TAG__</txt-record>"
            "</service>",
            encoding="utf-8",
        )
        args = MagicMock()
        args.version = "v1.0"
        args.uuid = "some-uuid"
        args.name = "bad;name"
        args.pin_recovery = False

        with patch.object(m, "_DIAL_TEMPLATE", template):
            with pytest.raises(ValueError):
                m._update_dial_service(args)

    def test_dial_service_rejects_pipe_in_name(self, tmp_path):
        template = tmp_path / "template.xml"
        template.write_text("<txt-record>__DIAL_NAME__</txt-record>", encoding="utf-8")
        args = MagicMock()
        args.version = "v1.0"
        args.uuid = "some-uuid"
        args.name = "bad|name"
        args.pin_recovery = False

        with patch.object(m, "_DIAL_TEMPLATE", template):
            with pytest.raises(ValueError):
                m._update_dial_service(args)

    def test_dial_service_escapes_html_in_uuid(self, tmp_path):
        template = tmp_path / "template.xml"
        template.write_text(
            "__AUTOSTREAM_RELEASE_TAG__ __DIAL_UUID__ __DIAL_NAME__ </service>",
            encoding="utf-8",
        )
        svc_dir = tmp_path / "avahi"
        svc_dir.mkdir()
        svc_file = svc_dir / "autostream-dial.service"

        args = MagicMock()
        args.version = "v1.0"
        args.uuid = '<uuid>"special"</uuid>'
        args.name = "Good Name"
        args.pin_recovery = False

        with patch.object(m, "_DIAL_TEMPLATE", template), \
             patch.object(m, "_AVAHI_SERVICES_DIR", svc_dir), \
             patch.object(m, "_DIAL_SERVICE", svc_file):
            m._update_dial_service(args)

        content = svc_file.read_text(encoding="utf-8")
        assert "<uuid>" not in content or "&lt;uuid&gt;" in content

    def test_validate_dial_name_accepts_normal_name(self):
        m._validate_dial_name("Living Room")

    def test_validate_dial_name_rejects_semicolon(self):
        with pytest.raises(ValueError):
            m._validate_dial_name("bad;name")

    def test_validate_dial_name_rejects_pipe(self):
        with pytest.raises(ValueError):
            m._validate_dial_name("bad|name")


# ---------------------------------------------------------------------------
# read_update_status: env file parsing
# ---------------------------------------------------------------------------

class TestReadUpdateStatus:
    def test_missing_update_file_returns_ok_unknown(self, tmp_path, capsys):
        result_file = tmp_path / "update-result.env"
        with patch.object(m, "UPDATE_RESULT_FILE", result_file):
            rc = m.read_update_status()
        out = capsys.readouterr().out
        data = json.loads(out.strip())
        assert rc == 0
        assert data["ok"] is True
        assert data["status"] == "unknown"

    def test_status_parsed_from_env_file(self, tmp_path, capsys):
        result_file = tmp_path / "update-result.env"
        result_file.write_text(
            "STATUS=success\n"
            "MESSAGE=Update complete\n"
            "PERCENT_COMPLETE=100\n"
            "LAST_RUN_AT=2026-01-01T12:00:00+00:00\n",
            encoding="utf-8",
        )
        with patch.object(m, "UPDATE_RESULT_FILE", result_file), \
             patch.object(m, "_read_log_tail", return_value=""), \
             patch.object(m, "_is_stale_in_progress", return_value=False):
            rc = m.read_update_status()
        out = capsys.readouterr().out
        data = json.loads(out.strip())
        assert rc == 0
        assert data["status"] == "success"
        assert data["percent"] == 100
        assert data["message"] == "Update complete"

    def test_percent_clamped_to_0_100(self, tmp_path, capsys):
        result_file = tmp_path / "update-result.env"
        result_file.write_text(
            "STATUS=in_progress\nPERCENT_COMPLETE=200\n",
            encoding="utf-8",
        )
        with patch.object(m, "UPDATE_RESULT_FILE", result_file), \
             patch.object(m, "_read_log_tail", return_value=""), \
             patch.object(m, "_is_stale_in_progress", return_value=False):
            m.read_update_status()
        out = capsys.readouterr().out
        data = json.loads(out.strip())
        assert data["percent"] == 100

    def test_log_tail_bounded_to_configured_lines(self, tmp_path):
        """_read_log_tail returns at most _LOG_TAIL_LINES lines."""
        log_file = tmp_path / "install.log"
        # Write more lines than the limit
        n_lines = m._LOG_TAIL_LINES + 20
        log_file.write_bytes(b"\n".join(f"line {i}".encode() for i in range(n_lines)))
        with patch.object(m, "_INSTALL_LOG", log_file):
            result = m._read_log_tail()
        actual_lines = [l for l in result.splitlines() if l]
        assert len(actual_lines) <= m._LOG_TAIL_LINES

    def test_log_tail_strips_ansi_escape_sequences(self, tmp_path):
        log_file = tmp_path / "install.log"
        log_file.write_bytes(b"\x1b[32mGreen text\x1b[0m\nPlain text\n")
        with patch.object(m, "_INSTALL_LOG", log_file):
            result = m._read_log_tail()
        assert "\x1b" not in result
        assert "Green text" in result
        assert "Plain text" in result

    def test_log_tail_tolerates_invalid_utf8(self, tmp_path):
        log_file = tmp_path / "install.log"
        log_file.write_bytes(b"valid line\n\xff\xfe invalid bytes\nfinal line\n")
        with patch.object(m, "_INSTALL_LOG", log_file):
            result = m._read_log_tail()
        assert "valid line" in result
        assert "final line" in result

    def test_log_tail_missing_file_returns_empty(self, tmp_path):
        with patch.object(m, "_INSTALL_LOG", tmp_path / "nonexistent.log"):
            result = m._read_log_tail()
        assert result == ""

    def test_malformed_percent_defaults_to_zero(self, tmp_path, capsys):
        result_file = tmp_path / "update-result.env"
        result_file.write_text(
            "STATUS=success\nPERCENT_COMPLETE=not-a-number\n",
            encoding="utf-8",
        )
        with patch.object(m, "UPDATE_RESULT_FILE", result_file), \
             patch.object(m, "_read_log_tail", return_value=""), \
             patch.object(m, "_is_stale_in_progress", return_value=False):
            m.read_update_status()
        out = capsys.readouterr().out
        data = json.loads(out.strip())
        assert data["percent"] == 0


# ---------------------------------------------------------------------------
# Factory reset scheduling: _schedule_factory_reset
# ---------------------------------------------------------------------------

class TestScheduleFactoryReset:
    def test_no_systemd_run_returns_false(self):
        with patch.object(m, "_read_product", return_value="autostream"), \
             patch.object(m, "find_systemd_run", return_value=None):
            result = m._schedule_factory_reset()
        assert result is False

    def test_systemd_run_success_returns_true(self):
        with patch.object(m, "_read_product", return_value="autostream"), \
             patch.object(m, "find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch.object(m, "run_cmd", return_value=(0, "", "")):
            result = m._schedule_factory_reset()
        assert result is True

    def test_systemd_run_failure_returns_false(self):
        with patch.object(m, "_read_product", return_value="autostream"), \
             patch.object(m, "find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch.object(m, "run_cmd", return_value=(1, "", "permission denied")):
            result = m._schedule_factory_reset()
        assert result is False

    def test_command_includes_execute_flag(self):
        captured_cmds = []

        def fake_run_cmd(cmd, *a, **kw):
            captured_cmds.append(cmd)
            return (0, "", "")

        with patch.object(m, "_read_product", return_value="autostream"), \
             patch.object(m, "find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch.object(m, "run_cmd", side_effect=fake_run_cmd):
            m._schedule_factory_reset()

        assert captured_cmds
        cmd_str = " ".join(captured_cmds[0])
        assert "--execute" in cmd_str or "factory-reset" in cmd_str

    def test_command_includes_systemd_run_path(self):
        captured_cmds = []

        def fake_run_cmd(cmd, *a, **kw):
            captured_cmds.append(cmd)
            return (0, "", "")

        with patch.object(m, "_read_product", return_value="autostream"), \
             patch.object(m, "find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch.object(m, "run_cmd", side_effect=fake_run_cmd):
            m._schedule_factory_reset()

        assert captured_cmds[0][0] == "/usr/bin/systemd-run"

    def test_unknown_product_returns_false_without_scheduling(self):
        """_schedule_factory_reset must fail closed for unknown product values."""
        with patch.object(m, "_read_product",
                          side_effect=ValueError("Unknown AUTOSTREAM_PRODUCT")):
            result = m._schedule_factory_reset()
        assert result is False

    def test_missing_product_returns_false_without_scheduling(self):
        """_schedule_factory_reset must fail closed when install-state.env is absent."""
        with patch.object(m, "_read_product",
                          side_effect=ValueError("install-state.env not found")):
            result = m._schedule_factory_reset()
        assert result is False

    def test_dial_product_schedules_successfully(self):
        """_schedule_factory_reset must succeed for the autostream-dial product."""
        with patch.object(m, "_read_product", return_value="autostream-dial"), \
             patch.object(m, "find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch.object(m, "run_cmd", return_value=(0, "", "")):
            result = m._schedule_factory_reset()
        assert result is True


# ---------------------------------------------------------------------------
# _execute_factory_reset: stop ordering and best-effort failures
# ---------------------------------------------------------------------------

class TestExecuteFactoryReset:
    """Tests for the main autostream product reset sequence via _execute_factory_reset()."""

    def test_stop_service_autostream_called_first(self, tmp_path):
        """For autostream product: autostream.service stops before wifi_watcher.service."""
        order = []
        with patch.object(m, "_acquire_reset_lock", return_value=object()), \
             patch.object(m, "_read_product", return_value="autostream"), \
             patch.object(m, "_rotate_logs"), \
             patch.object(m, "_stop_service",
                          side_effect=lambda name: order.append(name) or True), \
             patch.object(m, "_stop_owntone",
                          side_effect=lambda: order.append("_stop_owntone")), \
             patch.object(m, "_sync_owntone_conf"), \
             patch.object(m, "_delete_reset_files"), \
             patch.object(m, "_delete_wifi_connections"), \
             patch.object(m, "run_cmd", return_value=(0, "", "")), \
             patch("pathlib.Path.exists", return_value=True):
            m._execute_factory_reset()

        # autostream.service must be stopped before wifi_watcher
        assert "autostream.service" in order
        assert "autostream_wifi_watcher.service" in order
        assert order.index("autostream.service") < order.index("autostream_wifi_watcher.service")
        # Both must precede _stop_owntone
        assert "_stop_owntone" in order
        assert order.index("autostream_wifi_watcher.service") < order.index("_stop_owntone")

    def test_no_reboot_binary_returns_false(self):
        """Missing /sbin/reboot returns False after product-specific sequence completes."""
        with patch.object(m, "_acquire_reset_lock", return_value=object()), \
             patch.object(m, "_read_product", return_value="autostream"), \
             patch.object(m, "_rotate_logs"), \
             patch.object(m, "_stop_service", return_value=True), \
             patch.object(m, "_stop_owntone"), \
             patch.object(m, "_sync_owntone_conf"), \
             patch.object(m, "_delete_reset_files"), \
             patch.object(m, "_delete_wifi_connections"), \
             patch("pathlib.Path.exists", return_value=False):
            result = m._execute_factory_reset()
        assert result is False

    def test_continues_despite_best_effort_stop_failure(self, tmp_path):
        """For autostream product: _delete_reset_files is called even when stop fails."""
        delete_called = []
        with patch.object(m, "_acquire_reset_lock", return_value=object()), \
             patch.object(m, "_read_product", return_value="autostream"), \
             patch.object(m, "_rotate_logs"), \
             patch.object(m, "_stop_service", return_value=False), \
             patch.object(m, "_stop_owntone"), \
             patch.object(m, "_sync_owntone_conf"), \
             patch.object(m, "_delete_reset_files",
                          side_effect=lambda: delete_called.append(True)), \
             patch.object(m, "_delete_wifi_connections"), \
             patch.object(m, "run_cmd", return_value=(0, "", "")), \
             patch("pathlib.Path.exists", return_value=True):
            result = m._execute_factory_reset()
        assert delete_called, "_delete_reset_files must be called despite stop failure"

    def test_lock_not_held_aborts(self):
        """Lock contention aborts before product validation and any destructive action."""
        with patch.object(m, "_acquire_reset_lock", return_value=None):
            result = m._execute_factory_reset()
        assert result is False

    def test_full_stop_sync_delete_reboot_order(self, tmp_path):
        """For autostream product: all six operations occur in documented sequence."""
        order = []
        with patch.object(m, "_acquire_reset_lock", return_value=object()), \
             patch.object(m, "_read_product", return_value="autostream"), \
             patch.object(m, "_rotate_logs"), \
             patch.object(m, "_stop_service",
                          side_effect=lambda name: order.append(name) or True), \
             patch.object(m, "_stop_owntone",
                          side_effect=lambda: order.append("_stop_owntone")), \
             patch.object(m, "_sync_owntone_conf",
                          side_effect=lambda: order.append("_sync_owntone_conf")), \
             patch.object(m, "_delete_reset_files",
                          side_effect=lambda: order.append("_delete_reset_files")), \
             patch.object(m, "_delete_wifi_connections",
                          side_effect=lambda: order.append("_delete_wifi_connections")), \
             patch.object(m, "run_cmd",
                          side_effect=lambda cmd, **kw: order.append("reboot") or (0, "", "")), \
             patch("pathlib.Path.exists", return_value=True):
            result = m._execute_factory_reset()

        # Expected relative order for autostream product:
        # autostream.service → wifi_watcher.service → _stop_owntone
        #   → _sync_owntone_conf → _delete_reset_files → _delete_wifi_connections → reboot
        assert order.index("autostream.service") < order.index("autostream_wifi_watcher.service")
        assert order.index("autostream_wifi_watcher.service") < order.index("_stop_owntone")
        assert order.index("_stop_owntone") < order.index("_sync_owntone_conf")
        assert order.index("_sync_owntone_conf") < order.index("_delete_reset_files")
        assert order.index("_delete_reset_files") < order.index("_delete_wifi_connections")
        assert order.index("_delete_wifi_connections") < order.index("reboot")
        assert result is True

    def test_invalid_product_at_execution_aborts_without_destructive_actions(self):
        """Product re-validation inside the transient unit must abort if product changed."""
        delete_called = []
        with patch.object(m, "_acquire_reset_lock", return_value=object()), \
             patch.object(m, "_read_product",
                          side_effect=ValueError("install-state.env not found")), \
             patch.object(m, "_delete_reset_files",
                          side_effect=lambda: delete_called.append(True)), \
             patch.object(m, "_delete_wifi_connections",
                          side_effect=lambda: delete_called.append(True)):
            result = m._execute_factory_reset()
        assert result is False
        assert not delete_called, "No destructive action must run when product is invalid"


# ---------------------------------------------------------------------------
# Product detection
# ---------------------------------------------------------------------------

class TestProductDetection:
    def test_autostream_product_parsed(self, tmp_path):
        """AUTOSTREAM_PRODUCT=autostream is returned as-is."""
        state = tmp_path / "install-state.env"
        state.write_text("AUTOSTREAM_PRODUCT=autostream\n")
        with patch.object(m, "INSTALL_STATE_FILE", state):
            product = m._read_product()
        assert product == "autostream"

    def test_dial_product_parsed(self, tmp_path):
        """AUTOSTREAM_PRODUCT=autostream-dial is returned as-is."""
        state = tmp_path / "install-state.env"
        state.write_text("AUTOSTREAM_PRODUCT=autostream-dial\nDIAL_UUID=abc\n")
        with patch.object(m, "INSTALL_STATE_FILE", state):
            product = m._read_product()
        assert product == "autostream-dial"

    def test_missing_file_raises_value_error(self, tmp_path):
        """Missing install-state.env raises ValueError (fail-closed)."""
        state = tmp_path / "nonexistent-state.env"
        with patch.object(m, "INSTALL_STATE_FILE", state):
            with pytest.raises(ValueError, match="not found"):
                m._read_product()

    def test_empty_product_raises_value_error(self, tmp_path):
        """Empty AUTOSTREAM_PRODUCT raises ValueError (fail-closed)."""
        state = tmp_path / "install-state.env"
        state.write_text("AUTOSTREAM_PRODUCT=\n")
        with patch.object(m, "INSTALL_STATE_FILE", state):
            with pytest.raises(ValueError, match="missing or empty"):
                m._read_product()

    def test_unknown_product_raises_value_error(self, tmp_path):
        """An unrecognised AUTOSTREAM_PRODUCT value raises ValueError (fail-closed)."""
        state = tmp_path / "install-state.env"
        state.write_text("AUTOSTREAM_PRODUCT=autostream-speaker\n")
        with patch.object(m, "INSTALL_STATE_FILE", state):
            with pytest.raises(ValueError, match="Unknown AUTOSTREAM_PRODUCT"):
                m._read_product()

    def test_missing_key_raises_value_error(self, tmp_path):
        """A state file without AUTOSTREAM_PRODUCT key raises ValueError."""
        state = tmp_path / "install-state.env"
        state.write_text("DIAL_UUID=abc\nAUTOSTREAM_RELEASE_TAG=1.0\n")
        with patch.object(m, "INSTALL_STATE_FILE", state):
            with pytest.raises(ValueError, match="missing or empty"):
                m._read_product()


# ---------------------------------------------------------------------------
# Product-specific factory reset: dial sequence
# ---------------------------------------------------------------------------

class TestDialFactoryReset:
    def _dial_reset(self, stop_calls, delete_calls, run_ok=True):
        """Run _execute_factory_reset() as autostream-dial and capture side-effects."""
        with patch.object(m, "_acquire_reset_lock", return_value=object()), \
             patch.object(m, "_read_product", return_value="autostream-dial"), \
             patch.object(m, "_rotate_logs"), \
             patch.object(m, "_stop_service",
                          side_effect=lambda name: stop_calls.append(name) or True), \
             patch.object(m, "_stop_owntone",
                          side_effect=lambda: stop_calls.append("_stop_owntone")), \
             patch.object(m, "_sync_owntone_conf",
                          side_effect=lambda: stop_calls.append("_sync_owntone_conf")), \
             patch.object(m, "_delete_reset_files",
                          side_effect=lambda: delete_calls.append("_delete_reset_files")), \
             patch.object(m, "_delete_wifi_connections"), \
             patch.object(m, "run_cmd", return_value=(0 if run_ok else 1, "", "")), \
             patch("pathlib.Path.exists", return_value=True):
            return m._execute_factory_reset()

    def test_dial_stops_dial_service(self):
        """autostream-dial reset stops autostream_dial.service."""
        stops = []
        self._dial_reset(stops, [])
        assert "autostream_dial.service" in stops

    def test_dial_stops_wifi_watcher_service(self):
        """autostream-dial reset stops autostream_dial_wifi_watcher.service."""
        stops = []
        self._dial_reset(stops, [])
        assert "autostream_dial_wifi_watcher.service" in stops

    def test_dial_stops_dnsmasq_service(self):
        """autostream-dial reset stops autostream_dial_dnsmasq.service."""
        stops = []
        self._dial_reset(stops, [])
        assert "autostream_dial_dnsmasq.service" in stops

    def test_dial_does_not_stop_owntone(self):
        """autostream-dial reset must not stop OwnTone (not installed on dial)."""
        stops = []
        self._dial_reset(stops, [])
        assert "_stop_owntone" not in stops

    def test_dial_does_not_sync_owntone_conf(self):
        """autostream-dial reset must not run _sync_owntone_conf."""
        stops = []
        self._dial_reset(stops, [])
        assert "_sync_owntone_conf" not in stops

    def test_dial_does_not_call_delete_reset_files(self):
        """autostream-dial reset must not call _delete_reset_files (main-product allowlist)."""
        deletes = []
        self._dial_reset([], deletes)
        assert "_delete_reset_files" not in deletes

    def test_dial_deletes_dial_settings_json(self, tmp_path):
        """autostream-dial reset deletes /var/lib/autostream/dial-settings.json."""
        settings = tmp_path / "dial-settings.json"
        settings.write_text('{"name": "test"}')
        ssid = tmp_path / "ssid"
        ssid.write_text("MyNetwork")

        dial_files = (settings, ssid)

        with patch.object(m, "_acquire_reset_lock", return_value=object()), \
             patch.object(m, "_read_product", return_value="autostream-dial"), \
             patch.object(m, "_rotate_logs"), \
             patch.object(m, "_stop_service", return_value=True), \
             patch.object(m, "_delete_wifi_connections"), \
             patch.object(m, "run_cmd", return_value=(0, "", "")), \
             patch.object(m, "FACTORY_RESET_DIAL_DELETE_FILES", dial_files), \
             patch("pathlib.Path.exists", return_value=True):
            m._execute_factory_reset()

        assert not settings.exists(), "dial-settings.json must be deleted"
        assert not ssid.exists(), "/opt/autostream/ssid must be deleted"

    def test_dial_reset_returns_true_on_success(self):
        """autostream-dial reset returns True on successful execution."""
        result = self._dial_reset([], [])
        assert result is True


# ---------------------------------------------------------------------------
# Two-stage product validation: state-change between schedule and execute
# ---------------------------------------------------------------------------

class TestFactoryResetTwoStageValidation:
    def test_valid_at_schedule_invalid_at_execute_aborts(self):
        """Product validity at schedule time does not excuse invalid state at execute time."""
        # Scheduling succeeds; execution is refused because product is now unknown.
        with patch.object(m, "_read_product", return_value="autostream"), \
             patch.object(m, "find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch.object(m, "run_cmd", return_value=(0, "", "")):
            schedule_ok = m._schedule_factory_reset()
        assert schedule_ok is True

        # Simulate state-file removal between scheduling and execution.
        with patch.object(m, "_acquire_reset_lock", return_value=object()), \
             patch.object(m, "_read_product",
                          side_effect=ValueError("install-state.env not found")):
            execute_ok = m._execute_factory_reset()
        assert execute_ok is False


# ---------------------------------------------------------------------------
# Log rotation policy selection
# ---------------------------------------------------------------------------

class TestLogRotateProductSelection:
    def _capture_logrotate_policies(self, product):
        """Run _rotate_logs(product) and return the list of policy paths attempted."""
        policies_used = []

        def fake_run_cmd(cmd):
            # Last arg is the policy file path
            if len(cmd) >= 3 and "logrotate" in cmd[0]:
                policies_used.append(cmd[-1])
            return (0, "", "")

        with patch.object(m, "find_logrotate", return_value="/usr/sbin/logrotate"), \
             patch("os.path.exists", return_value=True), \
             patch.object(m, "run_cmd", side_effect=fake_run_cmd):
            m._rotate_logs(product)
        return policies_used

    def test_autostream_rotates_autostream_and_owntone(self):
        """autostream product rotates /etc/logrotate.d/autostream and owntone."""
        policies = self._capture_logrotate_policies("autostream")
        assert "/etc/logrotate.d/autostream" in policies
        assert "/etc/logrotate.d/owntone" in policies

    def test_autostream_does_not_rotate_dial_policy(self):
        """autostream product must not rotate the dial logrotate policy."""
        policies = self._capture_logrotate_policies("autostream")
        assert not any("autostream-dial" in p for p in policies)

    def test_dial_rotates_only_dial_policy(self):
        """autostream-dial product rotates only /etc/logrotate.d/autostream-dial."""
        policies = self._capture_logrotate_policies("autostream-dial")
        assert policies == ["/etc/logrotate.d/autostream-dial"]

    def test_dial_does_not_rotate_owntone(self):
        """autostream-dial product must not rotate the owntone logrotate policy."""
        policies = self._capture_logrotate_policies("autostream-dial")
        assert not any("owntone" in p for p in policies)

    def test_no_logrotate_binary_skips_rotation(self):
        """Missing logrotate binary logs a warning and returns without error."""
        with patch.object(m, "find_logrotate", return_value=None):
            m._rotate_logs("autostream")  # must not raise


# ---------------------------------------------------------------------------
# update-status: product-specific installer log selection
# ---------------------------------------------------------------------------

class TestUpdateStatusLogSelection:
    def _run_update_status(self, tmp_path, product_env_content, *, install_log_name):
        """Write install-state.env and update-result.env, run read_update_status()."""
        state_file = tmp_path / "install-state.env"
        state_file.write_text(product_env_content)
        result_file = tmp_path / "update-result.env"
        result_file.write_text("STATUS=success\nMESSAGE=done\nPERCENT_COMPLETE=100\n")
        log_file = tmp_path / install_log_name
        log_file.write_text("last log line\n")

        read_tail_calls = []

        def fake_read_tail(log_path=None):
            read_tail_calls.append(log_path)
            if log_path is not None and log_path.exists():
                return log_path.read_text().strip()
            return ""

        with patch.object(m, "INSTALL_STATE_FILE", state_file), \
             patch.object(m, "UPDATE_RESULT_FILE", result_file), \
             patch.object(m, "_read_log_tail", side_effect=fake_read_tail), \
             patch.object(m, "_is_stale_in_progress", return_value=False):
            m.read_update_status()

        return read_tail_calls

    def test_autostream_product_uses_main_install_log(self, tmp_path):
        """autostream product reads /var/log/autostream/autostream_install.log."""
        calls = self._run_update_status(
            tmp_path,
            "AUTOSTREAM_PRODUCT=autostream\n",
            install_log_name="autostream_install.log",
        )
        assert calls, "read_log_tail must be called"
        log_path = calls[0]
        assert log_path is not None
        assert "autostream_install.log" in str(log_path)

    def test_dial_product_uses_dial_install_log(self, tmp_path):
        """autostream-dial product reads /var/log/autostream/dial-install.log."""
        calls = self._run_update_status(
            tmp_path,
            "AUTOSTREAM_PRODUCT=autostream-dial\n",
            install_log_name="dial-install.log",
        )
        assert calls, "read_log_tail must be called"
        log_path = calls[0]
        assert log_path is not None
        assert "dial-install.log" in str(log_path)

    def test_missing_product_falls_back_to_default(self, tmp_path):
        """Missing install-state.env falls back to default log without crashing."""
        result_file = tmp_path / "update-result.env"
        result_file.write_text("STATUS=success\nPERCENT_COMPLETE=100\n")

        with patch.object(m, "INSTALL_STATE_FILE", tmp_path / "nonexistent.env"), \
             patch.object(m, "UPDATE_RESULT_FILE", result_file), \
             patch.object(m, "_read_log_tail", return_value=""), \
             patch.object(m, "_is_stale_in_progress", return_value=False):
            rc = m.read_update_status()
        assert rc == 0  # must not raise


# ---------------------------------------------------------------------------
# _is_stale_in_progress: decision matrix
# ---------------------------------------------------------------------------

import datetime as _dt


def _recent_ts(minutes_ago: float = 1) -> str:
    """Return an ISO timestamp `minutes_ago` minutes in the past."""
    ts = _dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(minutes=minutes_ago)
    return ts.isoformat()


def _old_ts(minutes_ago: float = 200) -> str:
    return _recent_ts(minutes_ago)


class TestIsStaleInProgress:
    """Matrix from the docstring of _is_stale_in_progress."""

    def test_unit_active_log_recent_not_stale(self):
        # Unit active + log recent (< 30 min) → healthy, not stale
        with patch.object(m, "_update_unit_active", return_value=True), \
             patch.object(m, "_install_log_recently_modified", return_value=True):
            result = m._is_stale_in_progress(_recent_ts())
        assert result is False

    def test_unit_active_log_silent_stale(self):
        # Unit active + log silent (≥ 30 min) → hung, stale
        with patch.object(m, "_update_unit_active", return_value=True), \
             patch.object(m, "_install_log_recently_modified", return_value=False):
            result = m._is_stale_in_progress(_recent_ts())
        assert result is True

    def test_unit_inactive_log_recent_not_stale(self):
        # Unit inactive + log recent (< 5 min) → just finished, not stale
        # The second call to _install_log_recently_modified (5 min) must return True
        call_count = {"n": 0}

        def log_recent(now, within_minutes=5, log_path=None):
            call_count["n"] += 1
            return True  # recent in both 30-min and 5-min windows

        with patch.object(m, "_update_unit_active", return_value=False), \
             patch.object(m, "_install_log_recently_modified", side_effect=log_recent):
            result = m._is_stale_in_progress(_recent_ts())
        assert result is False

    def test_unit_inactive_log_silent_old_timestamp_stale(self):
        # Unit inactive + log silent + timestamp > STALE_MINUTES → stale
        with patch.object(m, "_update_unit_active", return_value=False), \
             patch.object(m, "_install_log_recently_modified", return_value=False), \
             patch("pathlib.Path.read_text", return_value="99999.0 0.0"):
            result = m._is_stale_in_progress(_old_ts(200))
        assert result is True

    def test_unit_inactive_log_silent_recent_timestamp_not_stale(self):
        # Unit inactive + log silent + timestamp < STALE_MINUTES (90) and after boot → not stale.
        # uptime = 7200s (2 hours) → boot was 2 hours ago;
        # last_run_at = 10 min ago → is after boot → not pre-boot, and < 90 min → not old.
        with patch.object(m, "_update_unit_active", return_value=False), \
             patch.object(m, "_install_log_recently_modified", return_value=False), \
             patch("pathlib.Path.read_text", return_value="7200.0 0.0"):
            result = m._is_stale_in_progress(_recent_ts(10))
        assert result is False

    def test_pre_boot_timestamp_stale(self):
        # last_run_at before boot time → stale.
        # uptime = 1800s (30 min) → boot was 30 min ago;
        # last_run_at = 60 min ago → is BEFORE boot → pre-boot stale.
        # Age check: 60 min < 90 min STALE_MINUTES → doesn't trigger age-check stale.
        with patch.object(m, "_update_unit_active", return_value=False), \
             patch.object(m, "_install_log_recently_modified", return_value=False), \
             patch("pathlib.Path.read_text", return_value="1800.0 0.0"):
            result = m._is_stale_in_progress(_recent_ts(60))
        assert result is True

    def test_malformed_timestamp_stale(self):
        # Unparseable timestamp → treat as stale
        with patch.object(m, "_update_unit_active", return_value=False), \
             patch.object(m, "_install_log_recently_modified", return_value=False):
            result = m._is_stale_in_progress("not-a-timestamp")
        assert result is True


# ---------------------------------------------------------------------------
# Appliance service management: write-appliance-service, remove-appliance-service
# ---------------------------------------------------------------------------

class TestApplianceService:
    def test_write_fixed_service_skips_identical_content(self, tmp_path):
        svc_dir = tmp_path / "avahi"
        svc_dir.mkdir()
        svc_file = svc_dir / "autostream.service"
        content = "<service-group />\n"
        svc_file.write_text(content, encoding="utf-8")

        with patch.object(m, "_AVAHI_SERVICES_DIR", svc_dir):
            changed = m._write_fixed_service(svc_file, content)

        assert changed is False
        assert svc_file.read_text(encoding="utf-8") == content
        assert not (svc_dir / "autostream.service.tmp").exists()

    def test_write_appliance_service_creates_xml(self, tmp_path):
        svc_dir = tmp_path / "avahi"
        svc_dir.mkdir()
        svc_file = svc_dir / "autostream.service"

        args = MagicMock()
        args.version = "v1.2.3"
        args.id = "a1b2c3d4e5f6a1b2c3d4"

        with patch.object(m, "_AVAHI_SERVICES_DIR", svc_dir), \
             patch.object(m, "_APPLIANCE_SERVICE", svc_file):
            rc = m._write_appliance_service(args)

        assert rc == 0
        assert svc_file.exists()
        content = svc_file.read_text(encoding="utf-8")
        assert "_autostream._tcp" in content
        assert "id=" + args.id in content
        assert "ui=v1" in content
        assert "federation=v1" in content
        assert "version=" + args.version in content

    def test_write_appliance_service_suppresses_unchanged_log(self, tmp_path):
        svc_dir = tmp_path / "avahi"
        svc_dir.mkdir()
        svc_file = svc_dir / "autostream.service"

        args = MagicMock()
        args.version = "v1.2.3"
        args.id = "a1b2c3d4e5f6a1b2c3d4"

        with patch.object(m, "_AVAHI_SERVICES_DIR", svc_dir), \
             patch.object(m, "_APPLIANCE_SERVICE", svc_file):
            assert m._write_appliance_service(args) == 0
            with patch.object(m, "log") as mock_log:
                rc = m._write_appliance_service(args)

        assert rc == 0
        mock_log.assert_not_called()

    def test_write_appliance_service_rejects_invalid_id(self):
        args = MagicMock()
        args.version = "v1.0"
        args.id = "not-valid-id"

        rc = m._write_appliance_service(args)
        assert rc == 1

    def test_write_appliance_service_rejects_uppercase_hex(self):
        args = MagicMock()
        args.version = "v1.0"
        args.id = "A1B2C3D4E5F6A1B2C3D4"  # uppercase → rejected

        rc = m._write_appliance_service(args)
        assert rc == 1

    def test_write_appliance_service_rejects_short_id(self):
        args = MagicMock()
        args.version = "v1.0"
        args.id = "a1b2c3d4e5"  # only 10 chars

        rc = m._write_appliance_service(args)
        assert rc == 1

    def test_write_appliance_service_escapes_version_html(self, tmp_path):
        svc_dir = tmp_path / "avahi"
        svc_dir.mkdir()
        svc_file = svc_dir / "autostream.service"

        args = MagicMock()
        args.version = "<script>bad</script>"
        args.id = "a1b2c3d4e5f6a1b2c3d4"

        with patch.object(m, "_AVAHI_SERVICES_DIR", svc_dir), \
             patch.object(m, "_APPLIANCE_SERVICE", svc_file):
            rc = m._write_appliance_service(args)

        assert rc == 0
        content = svc_file.read_text(encoding="utf-8")
        assert "<script>" not in content
        assert "&lt;script&gt;" in content

    def test_remove_appliance_service_removes_file(self, tmp_path):
        svc_dir = tmp_path / "avahi"
        svc_dir.mkdir()
        svc_file = svc_dir / "autostream.service"
        svc_file.write_text("existing content", encoding="utf-8")

        with patch.object(m, "_APPLIANCE_SERVICE", svc_file):
            rc = m._remove_appliance_service(MagicMock())

        assert rc == 0
        assert not svc_file.exists()

    def test_remove_appliance_service_no_error_if_absent(self, tmp_path):
        svc_file = tmp_path / "autostream.service"

        with patch.object(m, "_APPLIANCE_SERVICE", svc_file):
            rc = m._remove_appliance_service(MagicMock())

        assert rc == 0


# ---------------------------------------------------------------------------
# Bluetooth: unit discovery
# ---------------------------------------------------------------------------

class TestFindFirstExistingUnit:
    def test_returns_first_loaded_candidate(self):
        def fake_run_cmd(cmd):
            unit = cmd[-1]
            if unit == "bluealsad.service":
                return (0, "loaded", "")
            return (0, "not-found", "")

        with patch.object(m, "run_cmd", side_effect=fake_run_cmd):
            result = m._find_first_existing_unit(
                "/bin/systemctl", ("bluealsad.service", "bluealsa.service")
            )
        assert result == "bluealsad.service"

    def test_falls_through_to_second_candidate(self):
        def fake_run_cmd(cmd):
            unit = cmd[-1]
            if unit == "bluealsa.service":
                return (0, "loaded", "")
            return (0, "not-found", "")

        with patch.object(m, "run_cmd", side_effect=fake_run_cmd):
            result = m._find_first_existing_unit(
                "/bin/systemctl", ("bluealsad.service", "bluealsa.service")
            )
        assert result == "bluealsa.service"

    def test_returns_none_if_neither_found(self):
        with patch.object(m, "run_cmd", return_value=(0, "not-found", "")):
            result = m._find_first_existing_unit(
                "/bin/systemctl", ("bluealsad.service", "bluealsa.service")
            )
        assert result is None

    def test_returns_none_on_command_failure(self):
        with patch.object(m, "run_cmd", return_value=(1, "", "error")):
            result = m._find_first_existing_unit(
                "/bin/systemctl", ("bluealsad.service",)
            )
        assert result is None


# ---------------------------------------------------------------------------
# Bluetooth: bt-services-enable / bt-services-disable
# ---------------------------------------------------------------------------

class TestBtServicesEnable:
    def _run(self, bluealsa_state="loaded", rc_map=None):
        """Run bt_services_enable() with systemctl calls stubbed.

        rc_map maps a substring of the argv (joined) to an rc; defaults to 0.
        """
        rc_map = rc_map or {}
        calls = []

        def fake_run_cmd(cmd):
            calls.append(cmd)
            joined = " ".join(cmd)
            if "show" in cmd and "LoadState" in cmd:
                unit = cmd[-1]
                if unit.startswith("bluealsa"):
                    return (0, bluealsa_state, "")
                return (0, "not-found", "")
            for key, rc in rc_map.items():
                if key in joined:
                    return (rc, "", "boom" if rc else "")
            return (0, "", "")

        with patch.object(m, "find_systemctl", return_value="/bin/systemctl"), \
             patch.object(m, "run_cmd", side_effect=fake_run_cmd):
            result = m.bt_services_enable()
        return result, calls

    def test_no_systemctl_returns_false(self):
        with patch.object(m, "find_systemctl", return_value=None):
            assert m.bt_services_enable() is False

    def test_happy_path_returns_true(self):
        result, calls = self._run()
        assert result is True

    def test_enable_attempts_rfkill_unblock_before_service_work(self):
        """A persisted type-level rfkill soft-block must be cleared before
        the service set is brought up, or a blocked adapter can never be
        powered by bluetoothd."""
        result, calls = self._run()
        joined = [" ".join(c) for c in calls]
        unblock_idx = next(
            (i for i, j in enumerate(joined) if "unblock" in j and "bluetooth" in j), None
        )
        unmask_idx = next((i for i, j in enumerate(joined) if "unmask" in j), None)
        assert unblock_idx is not None
        assert unmask_idx is not None and unblock_idx < unmask_idx

    def test_calls_unmask_then_enable_bluetooth(self):
        _, calls = self._run()
        joined = [" ".join(c) for c in calls]
        unmask_idx = next(i for i, c in enumerate(joined) if "unmask" in c)
        enable_bt_idx = next(
            i for i, c in enumerate(joined)
            if "enable" in c and "--now" in c and c.endswith("bluetooth.service")
        )
        assert unmask_idx < enable_bt_idx

    def test_enables_discovered_bluealsa_unit(self):
        _, calls = self._run(bluealsa_state="loaded")
        joined = [" ".join(c) for c in calls]
        assert any("enable --now bluealsad.service" in c for c in joined)

    def test_disables_bluealsa_aplay(self):
        _, calls = self._run()
        joined = [" ".join(c) for c in calls]
        assert any("disable --now bluealsa-aplay.service" in c for c in joined)

    def test_enables_autostream_bluetooth_last(self):
        _, calls = self._run()
        joined = [" ".join(c) for c in calls]
        assert joined[-1] == "/bin/systemctl enable --now autostream_bluetooth.service"

    def test_missing_bluealsa_unit_tolerated(self):
        result, calls = self._run(bluealsa_state="not-found")
        assert result is True  # non-fatal

    def test_unmask_failure_tolerated(self):
        result, _ = self._run(rc_map={"unmask": 1})
        assert result is True

    def test_bluetooth_enable_failure_tolerated(self):
        result, _ = self._run(rc_map={"enable --now bluetooth.service": 1})
        assert result is True

    def test_bluealsa_aplay_disable_failure_tolerated(self):
        result, _ = self._run(rc_map={"bluealsa-aplay": 1})
        assert result is True

    def test_autostream_bluetooth_failure_is_fatal(self):
        result, _ = self._run(rc_map={"autostream_bluetooth.service": 1})
        assert result is False


class TestBtServicesDisable:
    def _run(self, bluealsa_state="loaded", rc_map=None):
        rc_map = rc_map or {}
        calls = []

        def fake_run_cmd(cmd):
            calls.append(cmd)
            joined = " ".join(cmd)
            if "show" in cmd and "LoadState" in cmd:
                unit = cmd[-1]
                if unit.startswith("bluealsa"):
                    return (0, bluealsa_state, "")
                return (0, "not-found", "")
            for key, rc in rc_map.items():
                if key in joined:
                    return (rc, "", "boom" if rc else "")
            return (0, "", "")

        with patch.object(m, "find_systemctl", return_value="/bin/systemctl"), \
             patch.object(m, "run_cmd", side_effect=fake_run_cmd):
            result = m.bt_services_disable()
        return result, calls

    def test_no_systemctl_returns_false(self):
        with patch.object(m, "find_systemctl", return_value=None):
            assert m.bt_services_disable() is False

    def test_happy_path_returns_true(self):
        result, _ = self._run()
        assert result is True

    def test_disables_autostream_bluetooth_first(self):
        _, calls = self._run()
        joined = [" ".join(c) for c in calls if "show" not in c]
        assert joined[0] == "/bin/systemctl disable --now autostream_bluetooth.service"

    def test_disables_bluetooth_service(self):
        _, calls = self._run()
        joined = [" ".join(c) for c in calls]
        assert any(c == "/bin/systemctl disable --now bluetooth.service" for c in joined)

    def test_disables_discovered_bluealsa_unit(self):
        _, calls = self._run(bluealsa_state="loaded")
        joined = [" ".join(c) for c in calls]
        assert any("disable --now bluealsad.service" in c for c in joined)

    def test_all_failures_tolerated(self):
        result, _ = self._run(rc_map={
            "autostream_bluetooth.service": 1,
            "bluealsad.service": 1,
            "bluetooth.service": 1,
        })
        assert result is True  # disable is entirely best-effort/tolerant

    def test_missing_bluealsa_unit_tolerated(self):
        result, _ = self._run(bluealsa_state="not-found")
        assert result is True


# ---------------------------------------------------------------------------
# Bluetooth: onboard radio config.txt strip/insert
# ---------------------------------------------------------------------------

_CONFIG_WITH_ALL_AND_BT = (
    "# comment\n"
    "[all]\n"
    "dtparam=watchdog=on\n"
    "dtoverlay=disable-bt\n"
    "gpu_mem=128\n"
)

_CONFIG_WITH_ALL_NO_BT = (
    "# comment\n"
    "[all]\n"
    "dtparam=watchdog=on\n"
    "gpu_mem=128\n"
)

_CONFIG_NO_ALL_SECTION = (
    "dtparam=watchdog=on\n"
    "gpu_mem=128\n"
)


class TestBtOnboardSetConfig:
    def test_enable_onboard_strips_disable_bt_line(self, tmp_path):
        cfg = tmp_path / "config.txt"
        cfg.write_text(_CONFIG_WITH_ALL_AND_BT, encoding="utf-8")

        ok, changed = m.bt_onboard_set_config(cfg, enable_onboard=True)

        assert ok is True
        assert changed is True
        result = cfg.read_text(encoding="utf-8")
        assert "disable-bt" not in result
        assert "dtparam=watchdog=on" in result
        assert "gpu_mem=128" in result
        assert "# comment" in result

    def test_enable_onboard_idempotent_when_already_absent(self, tmp_path):
        cfg = tmp_path / "config.txt"
        cfg.write_text(_CONFIG_WITH_ALL_NO_BT, encoding="utf-8")

        ok, changed = m.bt_onboard_set_config(cfg, enable_onboard=True)

        assert ok is True
        assert changed is False
        assert cfg.read_text(encoding="utf-8") == _CONFIG_WITH_ALL_NO_BT

    def test_disable_onboard_inserts_after_all_header(self, tmp_path):
        cfg = tmp_path / "config.txt"
        cfg.write_text(_CONFIG_WITH_ALL_NO_BT, encoding="utf-8")

        ok, changed = m.bt_onboard_set_config(cfg, enable_onboard=False)

        assert ok is True
        assert changed is True
        result = cfg.read_text(encoding="utf-8")
        lines = result.splitlines()
        all_idx = lines.index("[all]")
        assert lines[all_idx + 1] == "dtoverlay=disable-bt"
        assert "dtparam=watchdog=on" in result
        assert "gpu_mem=128" in result

    def test_disable_onboard_idempotent_on_repeated_call(self, tmp_path):
        """A second consecutive bt-onboard-off call is a true no-op.

        The verb's contract is "strip any existing occurrence, then insert
        after [all]" (always normalising position), so idempotency is
        guaranteed from the *second* call onward, not from an arbitrary
        starting position where the line might sit elsewhere in the file.
        """
        cfg = tmp_path / "config.txt"
        cfg.write_text(_CONFIG_WITH_ALL_AND_BT, encoding="utf-8")

        ok1, changed1 = m.bt_onboard_set_config(cfg, enable_onboard=False)
        assert ok1 is True

        after_first = cfg.read_text(encoding="utf-8")
        ok2, changed2 = m.bt_onboard_set_config(cfg, enable_onboard=False)

        assert ok2 is True
        assert changed2 is False
        assert cfg.read_text(encoding="utf-8") == after_first

    def test_disable_onboard_dedupes_multiple_existing_lines(self, tmp_path):
        cfg = tmp_path / "config.txt"
        cfg.write_text(
            "[all]\ndtoverlay=disable-bt\ndtparam=watchdog=on\ndtoverlay=disable-bt\n",
            encoding="utf-8",
        )

        ok, changed = m.bt_onboard_set_config(cfg, enable_onboard=False)

        assert ok is True
        assert changed is True
        result = cfg.read_text(encoding="utf-8")
        assert result.count("dtoverlay=disable-bt") == 1

    def test_disable_onboard_creates_all_section_if_absent(self, tmp_path):
        cfg = tmp_path / "config.txt"
        cfg.write_text(_CONFIG_NO_ALL_SECTION, encoding="utf-8")

        ok, changed = m.bt_onboard_set_config(cfg, enable_onboard=False)

        assert ok is True
        assert changed is True
        result = cfg.read_text(encoding="utf-8")
        lines = result.splitlines()
        assert lines[0] == "[all]"
        assert lines[1] == "dtoverlay=disable-bt"
        assert "dtparam=watchdog=on" in result
        assert "gpu_mem=128" in result

    def test_preserves_watchdog_line_byte_for_byte(self, tmp_path):
        cfg = tmp_path / "config.txt"
        cfg.write_text(_CONFIG_WITH_ALL_AND_BT, encoding="utf-8")

        m.bt_onboard_set_config(cfg, enable_onboard=True)

        result = cfg.read_text(encoding="utf-8")
        assert "dtparam=watchdog=on\n" in result

    def test_missing_file_returns_false(self, tmp_path):
        cfg = tmp_path / "does-not-exist.txt"
        ok, changed = m.bt_onboard_set_config(cfg, enable_onboard=True)
        assert ok is False
        assert changed is False

    def test_comma_suffixed_disable_bt_line_stripped(self, tmp_path):
        """Some overlays allow parameterised dtoverlay lines (e.g. disable-bt,foo)."""
        cfg = tmp_path / "config.txt"
        cfg.write_text("[all]\ndtoverlay=disable-bt,extra-param\n", encoding="utf-8")

        ok, changed = m.bt_onboard_set_config(cfg, enable_onboard=True)

        assert ok is True
        assert changed is True
        assert "disable-bt" not in cfg.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Bluetooth: onboard verb dispatch (marker printing)
# ---------------------------------------------------------------------------

class TestBtOnboardVerbs:
    def test_bt_onboard_on_attempts_rfkill_unblock(self, tmp_path):
        """Enabling the onboard radio clears any persisted type-level rfkill
        block, otherwise the radio stays powered off after the reboot."""
        cfg = tmp_path / "config.txt"
        cfg.write_text(_CONFIG_WITH_ALL_AND_BT, encoding="utf-8")
        calls = []
        with patch.object(m, "FIRMWARE_CONFIG_PATH", cfg), \
             patch.object(m, "run_cmd", side_effect=lambda c: (calls.append(c), (0, "", ""))[1]):
            rc = m._bt_onboard_on(MagicMock())
        assert rc == 0
        assert any("unblock" in " ".join(c) and "bluetooth" in " ".join(c) for c in calls)

    def test_bt_onboard_on_prints_reboot_required_when_changed(self, tmp_path, capsys):
        cfg = tmp_path / "config.txt"
        cfg.write_text(_CONFIG_WITH_ALL_AND_BT, encoding="utf-8")
        with patch.object(m, "FIRMWARE_CONFIG_PATH", cfg):
            rc = m._bt_onboard_on(MagicMock())
        out = capsys.readouterr().out
        assert rc == 0
        assert "reboot-required" in out

    def test_bt_onboard_on_prints_no_change_when_already_absent(self, tmp_path, capsys):
        cfg = tmp_path / "config.txt"
        cfg.write_text(_CONFIG_WITH_ALL_NO_BT, encoding="utf-8")
        with patch.object(m, "FIRMWARE_CONFIG_PATH", cfg):
            rc = m._bt_onboard_on(MagicMock())
        out = capsys.readouterr().out
        assert rc == 0
        assert "no-change" in out

    def test_bt_onboard_off_prints_reboot_required_when_changed(self, tmp_path, capsys):
        cfg = tmp_path / "config.txt"
        cfg.write_text(_CONFIG_WITH_ALL_NO_BT, encoding="utf-8")
        with patch.object(m, "FIRMWARE_CONFIG_PATH", cfg):
            rc = m._bt_onboard_off(MagicMock())
        out = capsys.readouterr().out
        assert rc == 0
        assert "reboot-required" in out

    def test_bt_onboard_off_prints_no_change_on_repeated_call(self, tmp_path, capsys):
        cfg = tmp_path / "config.txt"
        cfg.write_text(_CONFIG_WITH_ALL_AND_BT, encoding="utf-8")
        with patch.object(m, "FIRMWARE_CONFIG_PATH", cfg):
            m._bt_onboard_off(MagicMock())
            capsys.readouterr()  # discard first call's output
            rc = m._bt_onboard_off(MagicMock())
        out = capsys.readouterr().out
        assert rc == 0
        assert "no-change" in out

    def test_bt_onboard_on_missing_file_returns_error(self, tmp_path, capsys):
        with patch.object(m, "FIRMWARE_CONFIG_PATH", tmp_path / "missing.txt"):
            rc = m._bt_onboard_on(MagicMock())
        assert rc == 1


# ---------------------------------------------------------------------------
# Bluetooth: sudoers verb dispatch presence
# ---------------------------------------------------------------------------

class TestBtVerbDispatch:
    """Verify all four Bluetooth verbs parse and route in main()/parse_args()."""

    @pytest.mark.parametrize("verb", [
        "bt-services-enable", "bt-services-disable",
        "bt-onboard-on", "bt-onboard-off",
    ])
    def test_verb_parses(self, verb):
        args = m.parse_args([verb])
        assert args.command == verb

    def test_bt_services_enable_dispatches(self):
        with patch("os.geteuid", return_value=0, create=True), \
             patch.object(m, "bt_services_enable", return_value=True) as mock_fn:
            rc = m.main(["bt-services-enable"])
        mock_fn.assert_called_once()
        assert rc == 0

    def test_bt_services_disable_dispatches(self):
        with patch("os.geteuid", return_value=0, create=True), \
             patch.object(m, "bt_services_disable", return_value=True) as mock_fn:
            rc = m.main(["bt-services-disable"])
        mock_fn.assert_called_once()
        assert rc == 0

    def test_bt_onboard_on_dispatches(self):
        with patch("os.geteuid", return_value=0, create=True), \
             patch.object(m, "_bt_onboard_on", return_value=0) as mock_fn:
            rc = m.main(["bt-onboard-on"])
        mock_fn.assert_called_once()
        assert rc == 0

    def test_bt_onboard_off_dispatches(self):
        with patch("os.geteuid", return_value=0, create=True), \
             patch.object(m, "_bt_onboard_off", return_value=0) as mock_fn:
            rc = m.main(["bt-onboard-off"])
        mock_fn.assert_called_once()
        assert rc == 0


# ---------------------------------------------------------------------------
# Sudoers: new Bluetooth Cmnd_Alias entries present
# ---------------------------------------------------------------------------

class TestBtSudoersEntries:
    SUDOERS_PATH = Path(__file__).parent.parent / "system" / "sudoers" / "autostream_admin"

    def test_sudoers_file_exists(self):
        assert self.SUDOERS_PATH.exists()

    def test_contains_bt_services_enable_alias(self):
        text = self.SUDOERS_PATH.read_text(encoding="utf-8")
        assert "autostream_admin bt-services-enable" in text

    def test_contains_bt_services_disable_alias(self):
        text = self.SUDOERS_PATH.read_text(encoding="utf-8")
        assert "autostream_admin bt-services-disable" in text

    def test_contains_bt_onboard_on_alias(self):
        text = self.SUDOERS_PATH.read_text(encoding="utf-8")
        assert "autostream_admin bt-onboard-on" in text

    def test_contains_bt_onboard_off_alias(self):
        text = self.SUDOERS_PATH.read_text(encoding="utf-8")
        assert "autostream_admin bt-onboard-off" in text

    def test_new_aliases_included_in_full_admin_list(self):
        text = self.SUDOERS_PATH.read_text(encoding="utf-8")
        assert "AUTOSTREAM_ADMIN_BT_SVC_ENABLE" in text
        assert "AUTOSTREAM_ADMIN_BT_SVC_DISABLE" in text
        assert "AUTOSTREAM_ADMIN_BT_ONBOARD_ON" in text
        assert "AUTOSTREAM_ADMIN_BT_ONBOARD_OFF" in text
