"""The appliance installer's OS release check, on an install and on an update.

The real require_rpi_os_trixie() body is run in bash against a scratch
os-release file, with the terminal helpers replaced so the prompt can be
answered; the checks that read script text say so in their names.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from conftest import bash_can_run_script_at_windows_path  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "autostream_install.sh"

bash_capable = pytest.mark.skipif(
    not bash_can_run_script_at_windows_path(),
    reason="bash cannot execute scripts at this path (MSYS2 limitation on Windows)",
)


def _function(text: str, name: str) -> str:
    m = re.search(r"^" + re.escape(name) + r"\(\) \{.*?\n\}\n", text, re.S | re.M)
    assert m is not None, name
    return m.group(0)


def _run(tmp_path: Path, codename: str | None, mode: str, *, tty: bool = False,
         answer: str = ""):
    """Run the check; returns (result, whether the prompt was shown)."""
    release = tmp_path / "os-release"
    release.write_text(f"VERSION_CODENAME={codename}\n" if codename else "ID=raspbian\n",
                       encoding="utf-8")
    prompted = tmp_path / "prompted"
    func = _function(INSTALLER.read_text(encoding="utf-8"), "require_rpi_os_trixie")
    func = func.replace("/etc/os-release", release.as_posix())
    script = f'''
set -uo pipefail
info() {{ echo "INFO: $*"; }}
warn() {{ echo "WARN: $*"; }}
error() {{ echo "ERROR: $*"; }}
has_tty() {{ {"true" if tty else "false"}; }}
tty_read() {{ : > "{prompted.as_posix()}"; printf -v "$2" '%s' "{answer}"; }}
INSTALL_MODE={mode}
{func}
require_rpi_os_trixie
echo "REACHED"
'''
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=20)
    return r, prompted.exists()


@bash_capable
class TestInstall:
    def test_trixie_passes_quietly(self, tmp_path):
        r, prompted = _run(tmp_path, "trixie", "install")
        assert "REACHED" in r.stdout and "WARN" not in r.stdout and not prompted

    def test_another_release_with_no_terminal_is_refused(self, tmp_path):
        r, prompted = _run(tmp_path, "bookworm", "install")
        assert r.returncode == 1 and "REACHED" not in r.stdout
        assert "refusing to override" in r.stdout

    def test_another_release_with_a_terminal_asks_and_continues_on_the_typed_word(self, tmp_path):
        r, prompted = _run(tmp_path, "bookworm", "install", tty=True, answer="TRIXIE")
        assert prompted and "REACHED" in r.stdout

    def test_another_release_with_a_terminal_aborts_on_any_other_answer(self, tmp_path):
        r, prompted = _run(tmp_path, "bookworm", "install", tty=True, answer="yes")
        assert prompted and r.returncode == 1 and "REACHED" not in r.stdout


@bash_capable
class TestUpdate:
    def test_trixie_passes_quietly(self, tmp_path):
        r, prompted = _run(tmp_path, "trixie", "update")
        assert "REACHED" in r.stdout and "WARN" not in r.stdout and not prompted

    @pytest.mark.parametrize("codename", ["bookworm", "bullseye", None])
    def test_another_release_warns_and_the_update_carries_on(self, tmp_path, codename):
        r, prompted = _run(tmp_path, codename, "update")
        assert r.returncode == 0, r.stdout
        assert "REACHED" in r.stdout
        assert "WARN: This installer is intended ONLY for Raspberry Pi OS (Trixie)." in r.stdout
        assert "not blocked" in r.stdout

    def test_another_release_never_prompts_even_when_a_terminal_exists(self, tmp_path):
        r, prompted = _run(tmp_path, "bookworm", "update", tty=True, answer="no")
        assert not prompted and "REACHED" in r.stdout


class TestWiring:
    def test_text_check_an_update_runs_the_check_before_it_changes_anything(self):
        text = INSTALLER.read_text(encoding="utf-8")
        update = _function(text, "run_update")
        assert "require_rpi_os_trixie" in update
        assert update.index("require_rpi_os_trixie") < update.index("stop_services_for_update")

    def test_text_check_a_fresh_install_still_runs_the_check(self):
        text = INSTALLER.read_text(encoding="utf-8")
        assert "require_rpi_os_trixie" in _function(text, "run_install")
