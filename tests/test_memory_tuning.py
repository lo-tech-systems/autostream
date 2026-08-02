"""Memory/swap tuning — installer-level tests.

Scope: tune_memory_behaviour() in autostream_install.sh, which masks
rpi-zram-writeback.timer and drops a vm.swappiness sysctl override so every
appliance converges on the same swap/zram tuning on fresh install and update.
Static/text-level checks plus functional bash round-trips (bash -c sourcing
the real function body against stubbed systemctl/sysctl), mirroring
tests/test_update_teardown.py and tests/test_update_page_gate.py.

Environment-dependent (not run here): real systemd unit state, real sysctl
application.
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
if [ -n "${SYSTEMCTL_MASK_FAIL:-}" ] && [ "$1" = "mask" ]; then
  exit 1
fi
exit 0
''',
        encoding="utf-8",
    )
    stub.chmod(0o755)


def _write_sysctl_stub(bin_dir: Path, *, fail: bool = False) -> None:
    stub = bin_dir / "sysctl"
    body = '''#!/bin/bash
printf '%s\\n' "$*" >> "${SYSCTL_CALLS_FILE}"
'''
    if fail:
        body += "exit 1\n"
    else:
        body += "exit 0\n"
    stub.write_text(body, encoding="utf-8")
    stub.chmod(0o755)


def _run_tune_memory_behaviour(tmp_path, *, mask_fail: bool = False, sysctl_fail: bool = False):
    """Run the real tune_memory_behaviour() body with stubbed systemctl and
    sysctl on PATH, and SWAPPINESS_SYSCTL_CONF redirected under tmp_path so
    the test never touches a real /etc file.

    Returns (result, conf_path, systemctl_calls, sysctl_calls).
    """
    tmp_path.mkdir(parents=True, exist_ok=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_systemctl_stub(bin_dir)
    _write_sysctl_stub(bin_dir, fail=sysctl_fail)

    conf_path = tmp_path / "90-autostream-swappiness.conf"
    systemctl_calls_file = tmp_path / "systemctl_calls"
    systemctl_calls_file.write_text("", encoding="utf-8")
    sysctl_calls_file = tmp_path / "sysctl_calls"
    sysctl_calls_file.write_text("", encoding="utf-8")

    func_src = _extract_function(_src(), "tune_memory_behaviour")
    script = f'''
set -uo pipefail
info() {{ echo "INFO: $*"; }}
warn() {{ echo "WARN: $*"; }}
error() {{ echo "ERROR: $*" >&2; }}
SWAPPINESS_SYSCTL_CONF="{conf_path.as_posix()}"
{func_src}
tune_memory_behaviour
echo "EXIT:$?"
'''
    env = dict(os.environ)
    env["PATH"] = bin_dir.as_posix() + os.pathsep + env.get("PATH", "")
    env["SYSTEMCTL_CALLS_FILE"] = systemctl_calls_file.as_posix()
    env["SYSCTL_CALLS_FILE"] = sysctl_calls_file.as_posix()
    if mask_fail:
        env["SYSTEMCTL_MASK_FAIL"] = "1"

    result = subprocess.run(
        ["bash", "-c", script],
        capture_output=True, text=True, timeout=20, env=env,
    )
    systemctl_calls = systemctl_calls_file.read_text(encoding="utf-8").splitlines()
    sysctl_calls = sysctl_calls_file.read_text(encoding="utf-8").splitlines()
    return result, conf_path, systemctl_calls, sysctl_calls


# ---------------------------------------------------------------------------
# tune_memory_behaviour() functional behaviour
# ---------------------------------------------------------------------------

class TestTuneMemoryBehaviour:
    @bash_capable
    def test_masks_zram_writeback_timer_with_now(self, tmp_path):
        result, _conf, systemctl_calls, _sysctl_calls = _run_tune_memory_behaviour(tmp_path)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "EXIT:0" in result.stdout
        assert any(
            c == "mask --now rpi-zram-writeback.timer" for c in systemctl_calls
        ), systemctl_calls

    @bash_capable
    def test_mask_failure_warns_and_continues(self, tmp_path):
        result, _conf, _systemctl_calls, _sysctl_calls = _run_tune_memory_behaviour(
            tmp_path, mask_fail=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "EXIT:0" in result.stdout
        assert "WARN:" in result.stdout

    @bash_capable
    def test_drop_in_written_with_expected_content(self, tmp_path):
        result, conf, _systemctl_calls, _sysctl_calls = _run_tune_memory_behaviour(tmp_path)
        assert result.returncode == 0, result.stdout + result.stderr
        assert conf.exists()
        content = conf.read_text(encoding="utf-8")
        assert "vm.swappiness=20" in content
        assert re.search(r"^#.*spike absorber", content, re.M), content

    def test_drop_in_installed_with_mode_0644_root_owned(self):
        # Functional mode/ownership verification requires real root privilege
        # (install -o root -g root is a no-op-with-warning under an
        # unprivileged test runner), so this is a source-level check that the
        # right install invocation is used, mirroring the mode assertions on
        # the other root-owned drop-ins configure_phase installs.
        func_src = _extract_function(_src(), "tune_memory_behaviour")
        assert 'install -m 0644 -o root -g root "${tmp}" "${conf}"' in func_src

    @bash_capable
    def test_drop_in_rewrite_is_idempotent(self, tmp_path):
        result, conf, _systemctl_calls, _sysctl_calls = _run_tune_memory_behaviour(
            tmp_path / "run1",
        )
        assert result.returncode == 0, result.stdout + result.stderr
        first_content = conf.read_text(encoding="utf-8")

        result2, conf2, _sc2, _syc2 = _run_tune_memory_behaviour(tmp_path / "run2")
        assert result2.returncode == 0, result2.stdout + result2.stderr
        assert conf2.read_text(encoding="utf-8") == first_content

    @bash_capable
    def test_sysctl_p_called_with_drop_in_path(self, tmp_path):
        result, conf, _systemctl_calls, sysctl_calls = _run_tune_memory_behaviour(tmp_path)
        assert result.returncode == 0, result.stdout + result.stderr
        assert any(c == f"-p {conf.as_posix()}" for c in sysctl_calls), sysctl_calls

    @bash_capable
    def test_sysctl_failure_warns_and_still_returns_zero(self, tmp_path):
        result, _conf, _systemctl_calls, _sysctl_calls = _run_tune_memory_behaviour(
            tmp_path, sysctl_fail=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "EXIT:0" in result.stdout
        assert "WARN:" in result.stdout


# ---------------------------------------------------------------------------
# Wiring into configure_phase() / run_install() / run_update()
# ---------------------------------------------------------------------------

class TestConfigurePhaseWiring:
    def _src(self) -> str:
        return _src()

    def test_tune_memory_behaviour_function_present(self):
        assert "tune_memory_behaviour()" in self._src()

    def test_configure_phase_calls_tune_memory_behaviour(self):
        src = self._src()
        m = re.search(r"^configure_phase\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert m is not None
        assert "tune_memory_behaviour" in m.group(0)

    def test_run_install_reaches_tune_memory_behaviour_via_configure_phase(self):
        src = self._src()
        m = re.search(r"^run_install\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert m is not None
        assert "configure_phase" in m.group(0), (
            "run_install must call configure_phase, the shared phase that "
            "carries tune_memory_behaviour"
        )

    def test_run_update_reaches_tune_memory_behaviour_via_configure_phase(self):
        src = self._src()
        m = re.search(r"^run_update\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert m is not None
        assert "configure_phase" in m.group(0), (
            "run_update must call configure_phase, the shared phase that "
            "carries tune_memory_behaviour"
        )

    def test_swappiness_conf_constant_matches_sysctl_d_convention(self):
        src = self._src()
        assert (
            'SWAPPINESS_SYSCTL_CONF="/etc/sysctl.d/90-autostream-swappiness.conf"'
            in src
        )
