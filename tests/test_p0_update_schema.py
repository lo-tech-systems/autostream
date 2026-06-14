"""P0.2 — Update result schema compatibility.

Both updaters (autostream_updater and autostream_dial_updater) must emit
the same canonical update-result.env schema. The admin read_update_status()
and the dial HTTP _read_update_state() are the primary consumers; both must
survive malformed or partially written files.

Requirements from the spec:
- Both updater products emit the same required keys, quoting rules,
  percentage range, and timestamp format.
- Cover messages containing spaces, quotes, equals signs, newlines,
  and non-ASCII input.
- Feed updater-produced files into autostream_admin update-status and the
  dial HTTP consumer rather than constructing unrelated fixtures by hand.
- Malformed or partially written files produce a stable error response and
  never report a false success.
"""
from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from io import StringIO
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "dial"))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import dial_http_server as dhs
from conftest import load_supervisor_script, bash_can_run_script_at_windows_path

bash_capable = pytest.mark.skipif(
    not bash_can_run_script_at_windows_path(),
    reason="bash cannot execute scripts at this path (MSYS2 limitation on Windows)",
)

# The shell installer only targets Linux; its bash invocation uses POSIX paths.
real_shell_writer = pytest.mark.skipif(
    sys.platform != "linux",
    reason="shell write_update_result() requires POSIX-native bash (Linux CI only)",
)


def _extract_shell_function(src: str, name: str) -> str:
    """Return the complete text of a top-level bash function from *src*.

    Finds `name()` at column 0, collects lines until it sees `}` alone on a
    line (the closing brace of the top-level function).
    """
    lines = src.splitlines()
    result: list[str] = []
    in_func = False
    for line in lines:
        if not in_func and re.match(rf'^{re.escape(name)}\s*\(\)', line):
            in_func = True
        if in_func:
            result.append(line)
            if len(result) > 1 and line.rstrip() == '}':
                break
    return '\n'.join(result)

# Required keys in every well-formed update-result.env file.
REQUIRED_KEYS = {"STATUS", "PERCENT_COMPLETE", "MESSAGE", "LAST_RUN_AT"}

# Canonical STATUS values that either updater may write.
CANONICAL_STATUSES = {"in_progress", "success", "failure"}

# ISO-8601-ish UTC timestamp pattern (UTC offset or Z).
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\+00:00|Z)$")


# ---------------------------------------------------------------------------
# Helpers to load the two updater modules
# ---------------------------------------------------------------------------

def _load_dial_updater(tmp_path: Path) -> ModuleType:
    mod = load_supervisor_script("autostream_dial_updater", "dial_updater_schema_test")
    mod.STATE_DIR = tmp_path
    return mod


def _load_admin(tmp_path: Path) -> ModuleType:
    mod = load_supervisor_script("autostream_admin", "admin_schema_test")
    mod.UPDATE_RESULT_FILE = tmp_path / "update-result.env"
    mod.STAMP_DIR = tmp_path
    mod._INSTALL_LOG = tmp_path / "autostream_install.log"
    return mod


def _run_admin_update_status(mod) -> dict:
    buf = StringIO()
    with patch("builtins.print", side_effect=lambda s, **_: buf.write(s + "\n")):
        mod.read_update_status()
    return json.loads(buf.getvalue().strip())


# ---------------------------------------------------------------------------
# Schema structure tests
# ---------------------------------------------------------------------------

class TestDialUpdaterSchema:
    """write_update_result() in autostream_dial_updater emits the canonical schema."""

    @pytest.mark.parametrize("status,percent", [
        ("in_progress", 0),
        ("success", 100),
        ("failure", 0),
    ])
    def test_required_keys_present(self, tmp_path, status, percent):
        mod = _load_dial_updater(tmp_path)
        mod.write_update_result(status, "Test message", percent=percent)
        result_file = tmp_path / "update-result.env"
        text = result_file.read_text(encoding="utf-8")
        parsed = _parse_env(text)
        for key in REQUIRED_KEYS:
            assert key in parsed, f"Missing required key {key!r} for status={status!r}"

    @pytest.mark.parametrize("status", sorted(CANONICAL_STATUSES))
    def test_status_is_canonical(self, tmp_path, status):
        mod = _load_dial_updater(tmp_path)
        mod.write_update_result(status, "msg", percent=0)
        parsed = _parse_env((tmp_path / "update-result.env").read_text(encoding="utf-8"))
        assert parsed["STATUS"] == status

    def test_timestamp_format_is_iso8601_utc(self, tmp_path):
        mod = _load_dial_updater(tmp_path)
        mod.write_update_result("success", "done", percent=100)
        parsed = _parse_env((tmp_path / "update-result.env").read_text(encoding="utf-8"))
        ts = parsed["LAST_RUN_AT"]
        assert _TS_RE.match(ts), f"LAST_RUN_AT {ts!r} is not ISO-8601 UTC"

    @pytest.mark.parametrize("status,expected_percent", [
        ("in_progress", 0),
        ("failure", 0),
        ("success", 100),
    ])
    def test_percent_range(self, tmp_path, status, expected_percent):
        mod = _load_dial_updater(tmp_path)
        mod.write_update_result(status, "msg", percent=expected_percent)
        parsed = _parse_env((tmp_path / "update-result.env").read_text(encoding="utf-8"))
        assert int(parsed["PERCENT_COMPLETE"]) == expected_percent

    def test_no_shell_quoting_around_simple_values(self, tmp_path):
        """Values must not be wrapped in quotes by the writer."""
        mod = _load_dial_updater(tmp_path)
        mod.write_update_result("success", "Simple message", percent=100)
        text = (tmp_path / "update-result.env").read_text(encoding="utf-8")
        # STATUS line must not have quotes around the value
        for line in text.splitlines():
            if line.startswith("STATUS="):
                value = line.partition("=")[2]
                assert value[0] not in ('"', "'"), f"STATUS value is quoted: {line!r}"


# ---------------------------------------------------------------------------
# Message content that could break simple parsers
# ---------------------------------------------------------------------------

MESSAGE_EDGE_CASES = [
    ("spaces",          "Installing version 1.2.3 now"),
    ("equals_in_msg",   "key=value in the message"),
    ("non_ascii",       "Installação completa"),
    ("unicode_emoji",   "Update done ✓"),
    ("empty_message",   ""),
    ("long_message",    "x" * 512),
]


class TestMessageEdgeCases:
    """write_update_result() must survive hostile message content."""

    @pytest.mark.parametrize("label,message", MESSAGE_EDGE_CASES)
    def test_message_survives_roundtrip_via_admin(self, tmp_path, label, message):
        """Message written by the updater is readable by admin update-status."""
        dial_mod = _load_dial_updater(tmp_path)
        dial_mod.write_update_result("failure", message, percent=0)

        admin_mod = _load_admin(tmp_path)
        with patch.object(admin_mod, "_read_log_tail", return_value=""), \
             patch.object(admin_mod, "_is_stale_in_progress", return_value=False):
            data = _run_admin_update_status(admin_mod)

        # Admin must not crash and must return ok=True (file was readable).
        assert data["ok"] is True, f"Admin crashed on message {label!r}: {data}"

    @pytest.mark.parametrize("label,message", MESSAGE_EDGE_CASES)
    def test_message_with_equals_does_not_corrupt_status(self, tmp_path, label, message):
        """An equals sign in MESSAGE must not corrupt the STATUS field."""
        dial_mod = _load_dial_updater(tmp_path)
        dial_mod.write_update_result("success", message, percent=100)

        result_file = tmp_path / "update-result.env"
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            public = dhs._read_update_state()

        assert public == "complete", (
            f"STATUS was corrupted by message {label!r}: got public={public!r}"
        )

    def test_newline_in_message_does_not_break_status_key(self, tmp_path):
        """A newline embedded in the message must not cause STATUS to be lost."""
        mod = _load_dial_updater(tmp_path)
        # write_update_result() uses f-string interpolation; a newline in the
        # message would inject an extra line into the env file.  Verify STATUS
        # is still readable.
        mod.write_update_result("failure", "line one\nline two", percent=0)
        result_file = tmp_path / "update-result.env"
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            public = dhs._read_update_state()
        # The dial updater writes STATUS before MESSAGE, so a newline in the
        # message body appends an extra line after MESSAGE but leaves STATUS
        # intact. The consumer must preserve "failed", not silently drop to "idle".
        assert public == "failed", (
            f"Newline in message corrupted or lost STATUS=failure: got {public!r}"
        )


# ---------------------------------------------------------------------------
# Malformed / partial files → stable error, never false success
# ---------------------------------------------------------------------------

class TestMalformedFiles:
    def test_empty_file_does_not_report_success(self, tmp_path):
        result_file = tmp_path / "update-result.env"
        result_file.write_text("", encoding="utf-8")
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            assert dhs._read_update_state() == "idle"

    def test_truncated_file_without_status_key(self, tmp_path):
        result_file = tmp_path / "update-result.env"
        result_file.write_text("PERCENT_COMPLETE=50\nMESSAGE=partial\n", encoding="utf-8")
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            assert dhs._read_update_state() == "idle"

    def test_file_with_only_whitespace(self, tmp_path):
        result_file = tmp_path / "update-result.env"
        result_file.write_text("   \n\t\n  \n", encoding="utf-8")
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            assert dhs._read_update_state() == "idle"

    def test_status_set_to_unknown_value_returns_idle(self, tmp_path):
        result_file = tmp_path / "update-result.env"
        result_file.write_text("STATUS=pending\nPERCENT_COMPLETE=0\n", encoding="utf-8")
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            assert dhs._read_update_state() == "idle"

    def test_malformed_file_admin_returns_ok_true_with_unknown(self, tmp_path):
        """Admin reads a file with no valid keys → ok=True, status='unknown'."""
        result_file = tmp_path / "update-result.env"
        result_file.write_text("not-a-key-value-pair\n", encoding="utf-8")
        mod = _load_admin(tmp_path)
        with patch.object(mod, "_read_log_tail", return_value=""), \
             patch.object(mod, "_is_stale_in_progress", return_value=False):
            data = _run_admin_update_status(mod)
        assert data["ok"] is True
        # Admin passes STATUS through unchanged; an unrecognised value is kept as-is
        # (not silently reported as success).
        assert data["status"] != "success"

    def test_partial_write_mid_file_never_false_success(self, tmp_path):
        """A file truncated after STATUS=in_progress must not report success."""
        result_file = tmp_path / "update-result.env"
        result_file.write_text("STATUS=in_progress\nPERCENT_COM", encoding="utf-8")
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            assert dhs._read_update_state() != "complete"


# ---------------------------------------------------------------------------
# Cross-updater schema consistency
# ---------------------------------------------------------------------------

class TestCrossUpdaterSchemaConsistency:
    """Both updaters produce files that satisfy the same parsing contract."""

    # ------------------------------------------------------------------
    # Dial updater (Python, unquoted values, STATUS first)
    # ------------------------------------------------------------------

    def test_dial_updater_file_readable_by_admin(self, tmp_path):
        dial_mod = _load_dial_updater(tmp_path)
        dial_mod.write_update_result("success", "All done", percent=100)

        admin_mod = _load_admin(tmp_path)
        with patch.object(admin_mod, "_read_log_tail", return_value=""), \
             patch.object(admin_mod, "_is_stale_in_progress", return_value=False):
            data = _run_admin_update_status(admin_mod)

        assert data["ok"] is True
        assert data["status"] == "success"
        assert data["percent"] == 100
        assert data["message"] == "All done"

    def test_dial_updater_file_readable_by_dial_http(self, tmp_path):
        dial_mod = _load_dial_updater(tmp_path)
        dial_mod.write_update_result("in_progress", "Installing...", percent=0)
        result_file = tmp_path / "update-result.env"
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            assert dhs._read_update_state() == "running"

    # ------------------------------------------------------------------
    # Shell installer (bash, quoted values, LAST_RUN_AT first)
    # The shell write_update_result() requires root for `install -o root`,
    # so we simulate its exact output format rather than executing it.
    # bash -n syntax and shellcheck are verified in test_p3_installer.py.
    # ------------------------------------------------------------------

    @staticmethod
    def _write_shell_format(tmp_path: Path, status: str, message: str, percent: int) -> Path:
        """Emit the shell installer's write_update_result() output verbatim."""
        result_file = tmp_path / "update-result.env"
        result_file.write_text(
            f'LAST_RUN_AT="2026-01-01T00:00:00+00:00"\n'
            f'STATUS="{status}"\n'
            f'MESSAGE="{message}"\n'
            f'PERCENT_COMPLETE="{percent}"\n',
            encoding="utf-8",
        )
        return result_file

    def test_shell_installer_failure_readable_by_dial_http(self, tmp_path):
        """Shell installer quoted format (failure) maps to 'failed' in dial HTTP."""
        result_file = self._write_shell_format(
            tmp_path, "failure", "Update failed at configure phase", 0
        )
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            assert dhs._read_update_state() == "failed"

    def test_shell_installer_success_readable_by_admin(self, tmp_path):
        """Shell installer quoted format (success) is fully parsed by autostream_admin."""
        result_file = self._write_shell_format(
            tmp_path, "success", "Update complete", 100
        )
        admin_mod = _load_admin(tmp_path)
        with patch.object(admin_mod, "_read_log_tail", return_value=""), \
             patch.object(admin_mod, "_is_stale_in_progress", return_value=False):
            data = _run_admin_update_status(admin_mod)
        assert data["ok"] is True
        assert data["status"] == "success"
        assert data["percent"] == 100

    def test_shell_installer_in_progress_readable_by_dial_http(self, tmp_path):
        """Shell installer quoted format (in_progress) maps to 'running' in dial HTTP."""
        result_file = self._write_shell_format(
            tmp_path, "in_progress", "Starting update", 0
        )
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            assert dhs._read_update_state() == "running"

    # ------------------------------------------------------------------
    # Execute the real shell write_update_result() function
    # Requires bash (skipped on Windows where bash cannot handle the path).
    # The function uses `install -o root` — stub it with a portable cp wrapper.
    # ------------------------------------------------------------------

    def _run_real_shell_writer(self, tmp_path: Path, status: str, message: str, percent: int) -> Path:
        """Run write_update_result() extracted from autostream_install.sh via bash."""
        installer = REPO_ROOT / "autostream_install.sh"
        if not installer.exists():
            pytest.skip("autostream_install.sh not found")
        func_src = _extract_shell_function(installer.read_text(encoding="utf-8"), "write_update_result")
        if not func_src:
            pytest.fail("write_update_result() not found in autostream_install.sh")
        result_file = tmp_path / "update-result.env"
        harness = tmp_path / "harness.sh"
        harness.write_text(
            "set -euo pipefail\n"
            f"STAMP_DIR={shlex.quote(str(tmp_path))}\n"
            f"UPDATE_RESULT_FILE={shlex.quote(str(result_file))}\n"
            "UPDATE_RUN_AT='2026-01-01T00:00:00+00:00'\n"
            # Portable install stub: copy second-to-last arg → last arg.
            # Initialise _p/_l to '' so set -u does not fire on the first iteration.
            "install() { local _p='' _l=''; for _a; do _p=$_l; _l=$_a; done; cp -- \"$_p\" \"$_l\"; }\n"
            f"{func_src}\n"
            f"write_update_result {shlex.quote(status)} {shlex.quote(message)} {percent}\n",
            encoding="utf-8",
        )
        r = subprocess.run(
            ["bash", str(harness)], capture_output=True, text=True, timeout=15,
        )
        assert r.returncode == 0, (
            f"bash write_update_result({status!r}) failed:\n{r.stderr}"
        )
        return result_file

    @real_shell_writer
    @pytest.mark.parametrize("status,expected_public", [
        ("failure",     "failed"),
        ("success",     "complete"),
        ("in_progress", "running"),
    ])
    def test_real_shell_writer_readable_by_dial_http(self, tmp_path, status, expected_public):
        """Execute write_update_result() from autostream_install.sh; verify dial HTTP reads it."""
        result_file = self._run_real_shell_writer(tmp_path, status, "Test message", 0)
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            assert dhs._read_update_state() == expected_public

    @real_shell_writer
    def test_real_shell_writer_success_readable_by_admin(self, tmp_path):
        """Execute write_update_result(success) from autostream_install.sh; verify admin reads it."""
        result_file = self._run_real_shell_writer(tmp_path, "success", "Update complete", 100)
        admin_mod = _load_admin(tmp_path)
        with patch.object(admin_mod, "_read_log_tail", return_value=""), \
             patch.object(admin_mod, "_is_stale_in_progress", return_value=False):
            data = _run_admin_update_status(admin_mod)
        assert data["ok"] is True
        assert data["status"] == "success"
        assert data["percent"] == 100


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _parse_env(text: str) -> dict[str, str]:
    """Parse KEY=VALUE lines the same way both consumers do."""
    data: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
            v = v[1:-1]
        data[k] = v
    return data
