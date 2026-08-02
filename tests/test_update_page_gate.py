"""Update-page gate — installer-level tests.

Scope: engage_update_page() in autostream_install.sh, which switches the
appliance's web UI over to nginx's "updating" holding page and verifies the
redirect is actually live before run_update() does anything destructive.
Static/text-level checks plus functional bash round-trips (bash -c sourcing
the real function body), mirroring tests/test_bluetooth_installer.py.

Environment-dependent (not run here): actual nginx serving, real network
calls to localhost.
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


def _write_curl_stub(bin_dir: Path, body: str) -> None:
    curl_path = bin_dir / "curl"
    curl_path.write_text(body, encoding="utf-8")
    curl_path.chmod(0o755)


def _run_engage_update_page(tmp_path, curl_body: str):
    """Run the real engage_update_page() body with a stubbed curl on PATH.

    Fidelity matters here and has bitten before, so the harness reproduces
    the installer's execution conditions exactly: `set -e` with an ERR trap
    (the function is called at top level, as run_update() calls it, so a
    nonzero return or any failing inner command reaches the trap), and curl
    stubs that emit NO trailing newline — real `curl -w` does not add one,
    and a newline-adding stub masks EOF-handling bugs in the reply parsing.

    Returns (result, flag_path). On the success path stdout ends with
    "EXIT:0" (preceded by "MODE:<octal>" while the flag file exists); on the
    failure path the ERR trap prints "ERRTRAP" and the script exits nonzero
    without printing "EXIT:0".
    """
    flag = tmp_path / "autostream-updating"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_curl_stub(bin_dir, curl_body)

    func_src = _extract_function(_src(), "engage_update_page")
    script = f'''
set -e
trap 'echo "ERRTRAP"' ERR
info() {{ echo "INFO: $*"; }}
warn() {{ echo "WARN: $*"; }}
error() {{ echo "ERROR: $*" >&2; }}
UPDATING_FLAG_FILE="{flag.as_posix()}"
{func_src}
engage_update_page
if [ -e "${{UPDATING_FLAG_FILE}}" ]; then
  echo "MODE:$(stat -c '%a' "${{UPDATING_FLAG_FILE}}")"
fi
echo "EXIT:0"
'''
    env = dict(os.environ)
    env["PATH"] = bin_dir.as_posix() + os.pathsep + env.get("PATH", "")
    result = subprocess.run(
        ["bash", "-c", script],
        capture_output=True, text=True, timeout=20, env=env,
    )
    return result, flag


# Stubs print WITHOUT a trailing newline, exactly like `curl -w`.
SUCCESS_CURL = '#!/bin/bash\nprintf "%s" "302 http://localhost/offline/updating"\n'
FAIL_200_CURL = '#!/bin/bash\nprintf "%s" "200 "\n'
FAIL_CONN_CURL = '#!/bin/bash\nprintf "%s" "000 "\nexit 0\n'


# ---------------------------------------------------------------------------
# engage_update_page() functional behaviour
# ---------------------------------------------------------------------------

class TestEngageUpdatePage:
    @bash_capable
    def test_flag_written_before_verification_with_correct_mode(self, tmp_path):
        result, flag = _run_engage_update_page(tmp_path, SUCCESS_CURL)
        assert "EXIT:0" in result.stdout, result.stdout + result.stderr
        assert flag.exists()
        assert "MODE:644" in result.stdout, result.stdout

    @bash_capable
    def test_verification_pass_returns_zero_and_leaves_flag(self, tmp_path):
        result, flag = _run_engage_update_page(tmp_path, SUCCESS_CURL)
        assert "EXIT:0" in result.stdout, result.stdout + result.stderr
        assert flag.exists(), "flag must remain in place on success"

    @bash_capable
    def test_verification_fail_200_trips_err_trap_and_removes_flag(self, tmp_path):
        result, flag = _run_engage_update_page(tmp_path, FAIL_200_CURL)
        assert "EXIT:0" not in result.stdout
        assert "ERRTRAP" in result.stdout, result.stdout + result.stderr
        assert result.returncode != 0
        assert not flag.exists(), "flag must be removed when verification fails"

    @bash_capable
    def test_verification_fail_no_connection_trips_err_trap_and_removes_flag(self, tmp_path):
        result, flag = _run_engage_update_page(tmp_path, FAIL_CONN_CURL)
        assert "ERRTRAP" in result.stdout, result.stdout + result.stderr
        assert result.returncode != 0
        assert not flag.exists()

    @bash_capable
    def test_success_survives_newline_less_curl_under_set_e(self, tmp_path):
        """A healthy 302 reply must pass verification on the FIRST attempt
        with real curl semantics (no trailing newline, set -e, ERR trap):
        the reply parsing must not itself be a failing command."""
        counter_file = tmp_path / "curl_calls"
        counting_success = f'''#!/bin/bash
COUNTER="{counter_file.as_posix()}"
n=0
if [ -e "$COUNTER" ]; then
  n=$(cat "$COUNTER")
fi
n=$((n + 1))
printf "%s" "$n" > "$COUNTER"
printf "%s" "302 http://localhost/offline/updating"
'''
        result, flag = _run_engage_update_page(tmp_path, counting_success)
        assert "ERRTRAP" not in result.stdout, result.stdout + result.stderr
        assert "EXIT:0" in result.stdout, result.stdout + result.stderr
        assert counter_file.read_text(encoding="utf-8").strip() == "1", (
            "verification must succeed on the first attempt, not via retries"
        )
        assert flag.exists()

    @bash_capable
    def test_verification_failure_logs_an_error(self, tmp_path):
        result, _flag = _run_engage_update_page(tmp_path, FAIL_200_CURL)
        assert "ERROR:" in result.stderr, result.stdout + result.stderr

    @bash_capable
    def test_retries_and_recovers_on_second_attempt(self, tmp_path):
        counter_file = tmp_path / "curl_calls"
        retry_curl = f'''#!/bin/bash
COUNTER="{counter_file.as_posix()}"
n=0
if [ -e "$COUNTER" ]; then
  n=$(cat "$COUNTER")
fi
n=$((n + 1))
echo "$n" > "$COUNTER"
if [ "$n" -lt 2 ]; then
  printf "%s" "000 "
else
  printf "%s" "302 http://localhost/offline/updating"
fi
'''
        result, flag = _run_engage_update_page(tmp_path, retry_curl)
        assert "EXIT:0" in result.stdout, result.stdout + result.stderr
        assert flag.exists()
        assert counter_file.read_text(encoding="utf-8").strip() == "2", (
            "expected exactly one retry before success"
        )


# ---------------------------------------------------------------------------
# Wiring into run_update()
# ---------------------------------------------------------------------------

class TestRunUpdateWiring:
    def _src(self) -> str:
        return _src()

    def test_engage_update_page_function_present(self):
        assert "engage_update_page()" in self._src()

    def test_run_update_calls_engage_update_page(self):
        src = self._src()
        m = re.search(r"^run_update\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert m is not None
        assert "engage_update_page" in m.group(0)

    def test_engage_update_page_runs_before_system_upgrade_phase(self):
        src = self._src()
        m = re.search(r"^run_update\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        assert m is not None
        body = m.group(0)
        engage_idx = body.find("engage_update_page")
        upgrade_idx = body.find("system_upgrade_phase")
        assert engage_idx != -1 and upgrade_idx != -1
        assert engage_idx < upgrade_idx, (
            "engage_update_page must run before system_upgrade_phase so the "
            "holding page is live before anything destructive starts"
        )

    def test_engage_update_page_not_called_in_fresh_install(self):
        src = self._src()
        m = re.search(r"^run_install\(\)\s*\{.*?\n\}\n", src, re.S | re.M)
        if m is None:
            pytest.skip("run_install() not present under that name")
        assert "engage_update_page" not in m.group(0)

    def test_on_exit_and_engage_update_page_share_the_same_flag_constant(self):
        src = self._src()
        assert 'UPDATING_FLAG_FILE="/tmp/autostream-updating"' in src
        assert "rm -f /tmp/autostream-updating" not in src, (
            "on_exit must reference the shared UPDATING_FLAG_FILE constant, "
            "not a hardcoded literal, so the two sites cannot drift apart"
        )
