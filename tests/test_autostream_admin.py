"""Priority 8 — autostream_admin privileged helper tests.

Covers hostname update, NetworkDown rate limiting, delayed reboot scheduling,
factory reset lock/allowlist/wifi, Avahi XML escaping, and update status parsing.
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

    def test_networkdown_rate_limited_returns_true_without_reboot(self, tmp_path):
        import time
        stamp = tmp_path / "reboot_networkdown.stamp"
        stamp.touch()
        run_calls = []
        with patch.object(m, "NETWORKDOWN_STAMP", stamp), \
             patch.object(m, "STAMP_DIR", tmp_path), \
             patch.object(m, "run_cmd",
                          side_effect=lambda cmd: run_calls.append(cmd) or (0, "", "")):
            result = m.reboot_host("NetworkDown")
        assert result is True
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
        with patch.object(m, "find_systemd_run", return_value=None):
            result = m._schedule_factory_reset()
        assert result is False

    def test_systemd_run_success_returns_true(self):
        with patch.object(m, "find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch.object(m, "run_cmd", return_value=(0, "", "")):
            result = m._schedule_factory_reset()
        assert result is True

    def test_systemd_run_failure_returns_false(self):
        with patch.object(m, "find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch.object(m, "run_cmd", return_value=(1, "", "permission denied")):
            result = m._schedule_factory_reset()
        assert result is False

    def test_command_includes_execute_flag(self):
        captured_cmds = []

        def fake_run_cmd(cmd, *a, **kw):
            captured_cmds.append(cmd)
            return (0, "", "")

        with patch.object(m, "find_systemd_run", return_value="/usr/bin/systemd-run"), \
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

        with patch.object(m, "find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch.object(m, "run_cmd", side_effect=fake_run_cmd):
            m._schedule_factory_reset()

        assert captured_cmds[0][0] == "/usr/bin/systemd-run"


# ---------------------------------------------------------------------------
# _execute_factory_reset: stop ordering and best-effort failures
# ---------------------------------------------------------------------------

class TestExecuteFactoryReset:
    def _base_patches(self, tmp_path, reboot_ok=True):
        """Return a context-manager dict that patches away all side-effects."""
        reboot_bin = tmp_path / "reboot"
        reboot_bin.write_text("#!/bin/sh\n")

        return {
            "_acquire_reset_lock": patch.object(m, "_acquire_reset_lock",
                                                return_value=object()),  # non-None
            "_rotate_logs": patch.object(m, "_rotate_logs"),
            "_stop_service": patch.object(m, "_stop_service", return_value=True),
            "_stop_owntone": patch.object(m, "_stop_owntone"),
            "_sync_owntone_conf": patch.object(m, "_sync_owntone_conf"),
            "_delete_reset_files": patch.object(m, "_delete_reset_files"),
            "_delete_wifi_connections": patch.object(m, "_delete_wifi_connections"),
            "reboot_bin": patch.object(m.Path("/sbin/reboot"), "exists",
                                       return_value=True) if hasattr(m.Path, "exists") else None,
            "run_cmd": patch.object(m, "run_cmd",
                                    return_value=(0 if reboot_ok else 1, "", "")),
        }

    def test_stop_service_autostream_called_first(self, tmp_path):
        order = []
        with patch.object(m, "_acquire_reset_lock", return_value=object()), \
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
        with patch.object(m, "_acquire_reset_lock", return_value=object()), \
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
        """Even when _stop_service fails, the sequence continues to reboot."""
        delete_called = []
        with patch.object(m, "_acquire_reset_lock", return_value=object()), \
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
        # _delete_reset_files must still be called even if stop failed
        assert delete_called, "_delete_reset_files must be called despite stop failure"

    def test_lock_not_held_aborts(self):
        with patch.object(m, "_acquire_reset_lock", return_value=None):
            result = m._execute_factory_reset()
        assert result is False
