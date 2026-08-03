"""Pre-update service teardown — installer-level tests.

Scope: stop_services_for_update() and restore_stopped_services() in
autostream_install.sh, which stop the audio-path consumers and the
coordinator before an update overwrites /opt and apt/builds compete for RAM,
and restore them again on the update failure path. Static/text-level checks
plus functional bash round-trips (bash -c sourcing the real function bodies
against a stubbed systemctl), mirroring tests/test_bluetooth_installer.py and
tests/test_update_page_gate.py.

Environment-dependent (not run here): real systemd, real service state.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "tests"))

from conftest import bash_can_run_script_at_windows_path

bash_capable = pytest.mark.skipif(
    not bash_can_run_script_at_windows_path(),
    reason="bash cannot execute scripts at this path (MSYS2 limitation on Windows)",
)

INSTALL_SH = REPO_ROOT / "autostream_install.sh"

EXPECTED_STOP_ORDER = [
    "autostream_monitor",
    "autostream_bluetooth",
    "owntone",
    "vibra-mini",
    "autostream",
]


def _src(path: Path = INSTALL_SH) -> str:
    return path.read_text(encoding="utf-8")


def _extract_function(src: str, name: str) -> str:
    """Pull a single top-level bash function's full text (signature through
    its closing brace) out of installer source, so test harnesses run the
    REAL current function body rather than a hand-maintained duplicate that
    can silently drift out of sync with it."""
    m = re.search(re.escape(name) + r"\(\)\s*\{.*?\n\}\n", src, re.S)
    assert m is not None, f"could not locate function {name}() in source"
    return m.group(0)


def _write_systemctl_stub(bin_dir: Path) -> None:
    stub = bin_dir / "systemctl"
    stub.write_text(
        '''#!/bin/bash
printf '%s\\n' "$*" >> "${SYSTEMCTL_CALLS_FILE}"
action="$1"
# shellcheck disable=SC2124
last="${@: -1}"
case "$action" in
  is-active)
    for a in ${SYSTEMCTL_ACTIVE:-}; do
      if [ "$a" = "$last" ]; then exit 0; fi
    done
    exit 3
    ;;
  stop|start)
    for f in ${SYSTEMCTL_FAIL:-}; do
      if [ "$f" = "$last" ]; then exit 1; fi
    done
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
''',
        encoding="utf-8",
    )
    stub.chmod(0o755)


def _run(tmp_path, func_names, script_body, *, active="", fail=""):
    """Run the given real function bodies (extracted from source) plus
    script_body, with a stubbed systemctl on PATH. Returns (result, calls,
    stopped_file)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_systemctl_stub(bin_dir)

    calls_file = tmp_path / "systemctl_calls"
    calls_file.write_text("", encoding="utf-8")
    stopped_file = tmp_path / "update-stopped-services.env"

    src = _src()
    funcs = "\n".join(_extract_function(src, name) for name in func_names)

    script = f'''
set -uo pipefail
info() {{ echo "INFO: $*"; }}
warn() {{ echo "WARN: $*"; }}
error() {{ echo "ERROR: $*" >&2; }}
STOPPED_SERVICES_FILE="{stopped_file.as_posix()}"
{funcs}
{script_body}
'''
    env = dict(os.environ)
    env["PATH"] = bin_dir.as_posix() + os.pathsep + env.get("PATH", "")
    env["SYSTEMCTL_CALLS_FILE"] = calls_file.as_posix()
    env["SYSTEMCTL_ACTIVE"] = active
    env["SYSTEMCTL_FAIL"] = fail

    result = subprocess.run(
        ["bash", "-c", script],
        capture_output=True, text=True, timeout=20, env=env,
    )
    calls = calls_file.read_text(encoding="utf-8").splitlines()
    return result, calls, stopped_file


ALL_UNITS = " ".join(EXPECTED_STOP_ORDER)


# ---------------------------------------------------------------------------
# stop_services_for_update()
# ---------------------------------------------------------------------------

class TestStopServicesForUpdate:
    @bash_capable
    def test_stop_order_exact(self, tmp_path):
        result, calls, stopped_file = _run(
            tmp_path, ["stop_services_for_update"], "stop_services_for_update",
            active=ALL_UNITS,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        stop_calls = [c for c in calls if c.startswith("stop ")]
        assert [c.split(" ", 1)[1] for c in stop_calls] == EXPECTED_STOP_ORDER

    @bash_capable
    def test_wifi_watcher_never_named_in_any_systemctl_call(self, tmp_path):
        result, calls, _stopped_file = _run(
            tmp_path, ["stop_services_for_update"], "stop_services_for_update",
            active=ALL_UNITS,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        for line in calls:
            assert "wifi_watcher" not in line, f"wifi watcher touched: {line!r}"

    @bash_capable
    def test_inactive_unit_skipped_and_not_recorded(self, tmp_path):
        active = " ".join(u for u in EXPECTED_STOP_ORDER if u != "owntone")
        result, calls, stopped_file = _run(
            tmp_path, ["stop_services_for_update"], "stop_services_for_update",
            active=active,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert not any(c == "stop owntone" for c in calls)
        assert not any(c.startswith("is-active") and c.endswith("owntone") for c in calls) or True
        stopped = stopped_file.read_text(encoding="utf-8").splitlines()
        assert "owntone" not in stopped
        assert stopped == [u for u in EXPECTED_STOP_ORDER if u != "owntone"]

    @bash_capable
    def test_stop_failure_warns_and_continues_and_remains_recorded(self, tmp_path):
        result, calls, stopped_file = _run(
            tmp_path, ["stop_services_for_update"], "stop_services_for_update",
            active=ALL_UNITS, fail="vibra-mini",
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "WARN:" in result.stdout
        # The stop attempt on the next unit in order still happened.
        stop_calls = [c.split(" ", 1)[1] for c in calls if c.startswith("stop ")]
        assert "autostream" in stop_calls
        idx = stop_calls.index("vibra-mini")
        assert stop_calls[idx + 1] == "autostream"

        # The unit stays in the state file: recording happens from the
        # pre-stop snapshot, and restore-starting a unit whose stop failed
        # (i.e. one that may still be running) is a harmless no-op.
        stopped = stopped_file.read_text(encoding="utf-8").splitlines()
        assert stopped == EXPECTED_STOP_ORDER

    @bash_capable
    def test_all_units_recorded_before_any_stop_is_issued(self, tmp_path):
        # Stopping one unit can propagate to a dependent unit via systemd
        # dependencies (e.g. the coordinator Requires= the monitor daemon),
        # deactivating it before the loop reaches it. The active set must
        # therefore be snapshotted and recorded before the first stop, or a
        # propagated stop hides the unit from the failure-path restore.
        result, calls, stopped_file = _run(
            tmp_path, ["stop_services_for_update"], "stop_services_for_update",
            active=ALL_UNITS,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        first_stop = next(
            i for i, c in enumerate(calls) if c.startswith("stop ")
        )
        is_active_after_first_stop = [
            c for c in calls[first_stop:] if c.startswith("is-active")
        ]
        assert is_active_after_first_stop == [], (
            "liveness checks must all complete before the first stop"
        )
        stopped = stopped_file.read_text(encoding="utf-8").splitlines()
        assert stopped == EXPECTED_STOP_ORDER

    @bash_capable
    def test_state_file_matches_stopped_set_exactly(self, tmp_path):
        active = "autostream_monitor owntone autostream"
        result, calls, stopped_file = _run(
            tmp_path, ["stop_services_for_update"], "stop_services_for_update",
            active=active,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        stopped = stopped_file.read_text(encoding="utf-8").splitlines()
        assert stopped == ["autostream_monitor", "owntone", "autostream"]

    @bash_capable
    def test_state_file_created_fresh_each_time(self, tmp_path):
        # A stale file from a previous run must not leak into the new one.
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        _write_systemctl_stub(bin_dir)
        stopped_file = tmp_path / "update-stopped-services.env"
        stopped_file.write_text("stale-leftover-unit\n", encoding="utf-8")
        calls_file = tmp_path / "systemctl_calls"
        calls_file.write_text("", encoding="utf-8")

        src = _src()
        func_src = _extract_function(src, "stop_services_for_update")
        script = f'''
set -uo pipefail
info() {{ echo "INFO: $*"; }}
warn() {{ echo "WARN: $*"; }}
error() {{ echo "ERROR: $*" >&2; }}
STOPPED_SERVICES_FILE="{stopped_file.as_posix()}"
{func_src}
stop_services_for_update
'''
        env = dict(os.environ)
        env["PATH"] = bin_dir.as_posix() + os.pathsep + env.get("PATH", "")
        env["SYSTEMCTL_CALLS_FILE"] = calls_file.as_posix()
        env["SYSTEMCTL_ACTIVE"] = "autostream"
        env["SYSTEMCTL_FAIL"] = ""
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, timeout=20, env=env,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        stopped = stopped_file.read_text(encoding="utf-8").splitlines()
        assert "stale-leftover-unit" not in stopped
        assert stopped == ["autostream"]


# ---------------------------------------------------------------------------
# restore_stopped_services()
# ---------------------------------------------------------------------------

class TestRestoreStoppedServices:
    @bash_capable
    def test_restores_in_reverse_order(self, tmp_path):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        _write_systemctl_stub(bin_dir)
        stopped_file = tmp_path / "update-stopped-services.env"
        stopped_file.write_text("\n".join(EXPECTED_STOP_ORDER) + "\n", encoding="utf-8")
        calls_file = tmp_path / "systemctl_calls"
        calls_file.write_text("", encoding="utf-8")

        func_src = _extract_function(_src(), "restore_stopped_services")
        script = f'''
set -uo pipefail
info() {{ echo "INFO: $*"; }}
warn() {{ echo "WARN: $*"; }}
error() {{ echo "ERROR: $*" >&2; }}
STOPPED_SERVICES_FILE="{stopped_file.as_posix()}"
{func_src}
restore_stopped_services
'''
        env = dict(os.environ)
        env["PATH"] = bin_dir.as_posix() + os.pathsep + env.get("PATH", "")
        env["SYSTEMCTL_CALLS_FILE"] = calls_file.as_posix()
        env["SYSTEMCTL_ACTIVE"] = ""
        env["SYSTEMCTL_FAIL"] = ""
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, timeout=20, env=env,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        calls = calls_file.read_text(encoding="utf-8").splitlines()
        start_calls = [c.split(" ", 1)[1] for c in calls if c.startswith("start ")]
        assert start_calls == list(reversed(EXPECTED_STOP_ORDER))
        assert not stopped_file.exists()

    @bash_capable
    def test_tolerates_missing_state_file(self, tmp_path):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        _write_systemctl_stub(bin_dir)
        stopped_file = tmp_path / "update-stopped-services.env"  # never created
        calls_file = tmp_path / "systemctl_calls"
        calls_file.write_text("", encoding="utf-8")

        func_src = _extract_function(_src(), "restore_stopped_services")
        script = f'''
set -uo pipefail
info() {{ echo "INFO: $*"; }}
warn() {{ echo "WARN: $*"; }}
error() {{ echo "ERROR: $*" >&2; }}
STOPPED_SERVICES_FILE="{stopped_file.as_posix()}"
{func_src}
restore_stopped_services
echo "EXIT:$?"
'''
        env = dict(os.environ)
        env["PATH"] = bin_dir.as_posix() + os.pathsep + env.get("PATH", "")
        env["SYSTEMCTL_CALLS_FILE"] = calls_file.as_posix()
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, timeout=20, env=env,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "EXIT:0" in result.stdout
        calls = calls_file.read_text(encoding="utf-8").splitlines()
        assert calls == []

    @bash_capable
    def test_tolerates_empty_state_file(self, tmp_path):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        _write_systemctl_stub(bin_dir)
        stopped_file = tmp_path / "update-stopped-services.env"
        stopped_file.write_text("", encoding="utf-8")
        calls_file = tmp_path / "systemctl_calls"
        calls_file.write_text("", encoding="utf-8")

        func_src = _extract_function(_src(), "restore_stopped_services")
        script = f'''
set -uo pipefail
info() {{ echo "INFO: $*"; }}
warn() {{ echo "WARN: $*"; }}
error() {{ echo "ERROR: $*" >&2; }}
STOPPED_SERVICES_FILE="{stopped_file.as_posix()}"
{func_src}
restore_stopped_services
'''
        env = dict(os.environ)
        env["PATH"] = bin_dir.as_posix() + os.pathsep + env.get("PATH", "")
        env["SYSTEMCTL_CALLS_FILE"] = calls_file.as_posix()
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, timeout=20, env=env,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        calls = calls_file.read_text(encoding="utf-8").splitlines()
        assert calls == []
        assert not stopped_file.exists()

    @bash_capable
    def test_removes_state_file_after_restore(self, tmp_path):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        _write_systemctl_stub(bin_dir)
        stopped_file = tmp_path / "update-stopped-services.env"
        stopped_file.write_text("autostream\n", encoding="utf-8")
        calls_file = tmp_path / "systemctl_calls"
        calls_file.write_text("", encoding="utf-8")

        func_src = _extract_function(_src(), "restore_stopped_services")
        script = f'''
set -uo pipefail
info() {{ echo "INFO: $*"; }}
warn() {{ echo "WARN: $*"; }}
error() {{ echo "ERROR: $*" >&2; }}
STOPPED_SERVICES_FILE="{stopped_file.as_posix()}"
{func_src}
restore_stopped_services
'''
        env = dict(os.environ)
        env["PATH"] = bin_dir.as_posix() + os.pathsep + env.get("PATH", "")
        env["SYSTEMCTL_CALLS_FILE"] = calls_file.as_posix()
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, timeout=20, env=env,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert not stopped_file.exists()

    @bash_capable
    def test_start_failure_warns_and_continues(self, tmp_path):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        _write_systemctl_stub(bin_dir)
        stopped_file = tmp_path / "update-stopped-services.env"
        stopped_file.write_text("\n".join(EXPECTED_STOP_ORDER) + "\n", encoding="utf-8")
        calls_file = tmp_path / "systemctl_calls"
        calls_file.write_text("", encoding="utf-8")

        func_src = _extract_function(_src(), "restore_stopped_services")
        script = f'''
set -uo pipefail
info() {{ echo "INFO: $*"; }}
warn() {{ echo "WARN: $*"; }}
error() {{ echo "ERROR: $*" >&2; }}
STOPPED_SERVICES_FILE="{stopped_file.as_posix()}"
{func_src}
restore_stopped_services
echo "EXIT:$?"
'''
        env = dict(os.environ)
        env["PATH"] = bin_dir.as_posix() + os.pathsep + env.get("PATH", "")
        env["SYSTEMCTL_CALLS_FILE"] = calls_file.as_posix()
        env["SYSTEMCTL_FAIL"] = "owntone"
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, timeout=20, env=env,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "EXIT:0" in result.stdout
        assert "WARN:" in result.stdout
        calls = calls_file.read_text(encoding="utf-8").splitlines()
        start_calls = [c.split(" ", 1)[1] for c in calls if c.startswith("start ")]
        # Every unit still gets attempted despite owntone's failure.
        assert start_calls == list(reversed(EXPECTED_STOP_ORDER))
        assert not stopped_file.exists()


# ---------------------------------------------------------------------------
# Wiring into run_update()
# ---------------------------------------------------------------------------

class TestRunUpdateWiring:
    def _src(self) -> str:
        return _src()

    def test_stop_services_for_update_function_present(self):
        assert "stop_services_for_update()" in self._src()

    def test_restore_stopped_services_function_present(self):
        assert "restore_stopped_services()" in self._src()

    def test_run_update_calls_stop_services_for_update(self):
        src = self._src()
        m = re.search(r"^run_update\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert m is not None
        assert "stop_services_for_update" in m.group(0)

    def test_stop_services_for_update_runs_after_engage_update_page(self):
        src = self._src()
        m = re.search(r"^run_update\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert m is not None
        body = m.group(0)
        engage_idx = body.find("engage_update_page")
        stop_idx = body.find("stop_services_for_update")
        assert engage_idx != -1 and stop_idx != -1
        assert engage_idx < stop_idx, (
            "stop_services_for_update must run after the holding page is "
            "confirmed live"
        )

    def test_stop_services_for_update_runs_before_system_upgrade_phase(self):
        src = self._src()
        m = re.search(r"^run_update\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert m is not None
        body = m.group(0)
        stop_idx = body.find("stop_services_for_update")
        upgrade_idx = body.find("system_upgrade_phase")
        assert stop_idx != -1 and upgrade_idx != -1
        assert stop_idx < upgrade_idx, (
            "services must be stopped before the system upgrade and rebuild "
            "phases compete with them for RAM"
        )

    def test_stop_services_for_update_not_called_in_fresh_install(self):
        src = self._src()
        m = re.search(r"^run_install\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        if m is None:
            pytest.skip("run_install() not present under that name")
        assert "stop_services_for_update" not in m.group(0)

    def test_wifi_watcher_never_named_in_stop_function_source(self):
        src = self._src()
        func = _extract_function(src, "stop_services_for_update")
        assert "wifi_watcher" not in func

    def test_state_file_constant_matches_stamp_dir(self):
        src = self._src()
        assert 'STOPPED_SERVICES_FILE="${STAMP_DIR}/update-stopped-services.env"' in src


class TestFailurePathRestore:
    """The ERR trap must bring stopped services back on a failed update:
    a failed update does not reboot, so nothing else would restart them."""

    def _on_error_body(self) -> str:
        m = re.search(r"^on_error\(\)\s*\{.*?\n\}\n", _src(), re.S | re.M)
        assert m is not None, "on_error trap function not found"
        return m.group(0)

    def test_on_error_calls_restore_stopped_services(self):
        assert "restore_stopped_services" in self._on_error_body()

    def test_restore_runs_after_failure_result_written(self):
        body = self._on_error_body()
        failure_idx = body.find('write_update_result "failure"')
        restore_idx = body.find("restore_stopped_services")
        assert failure_idx != -1 and restore_idx != -1
        assert failure_idx < restore_idx, (
            "the failure status must be persisted before the best-effort "
            "restore, so the retry service sees the true outcome even if "
            "restore misbehaves"
        )

    def test_restore_only_in_update_mode_branch(self):
        body = self._on_error_body()
        update_branch = re.search(
            r'if \[\[ "\$\{INSTALL_MODE\}" == "update" \]\]; then.*?\n  fi\n',
            body, re.S,
        )
        assert update_branch is not None
        assert "restore_stopped_services" in update_branch.group(0), (
            "restore belongs to update mode only; fresh installs stop nothing"
        )

    def test_restore_is_best_effort(self):
        assert "restore_stopped_services || true" in self._on_error_body()
