"""set_spidev_bufsiz() — the dial installer's kernel command-line edit that
raises the spidev per-transfer limit for the display.

cmdline.txt is a single line the firmware hands to the kernel verbatim, so
the helper must never add a second line, duplicate the token, or disturb the
other parameters, and must correct a stale value in place.

Functional bash round-trips against a temp cmdline.txt, following the pattern
in tests/test_dial_installer_spi1.py.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from conftest import bash_can_run_script_at_windows_path  # noqa: E402

bash_capable = pytest.mark.skipif(
    not bash_can_run_script_at_windows_path(),
    reason="bash cannot execute scripts at this path (MSYS2 limitation on Windows)",
)

HELPERS = Path(__file__).resolve().parents[1] / "installer" / "dial" / "helpers.sh"
TOKEN = "spidev.bufsiz=65536"
BASE = "console=serial0,115200 console=tty1 root=PARTUUID=00000000-02 rootfstype=ext4 fsck.repair=yes rootwait"


def _run(cmdline: Path) -> subprocess.CompletedProcess:
    script = f'set -e; source "{HELPERS.as_posix()}"; set_spidev_bufsiz "{cmdline.as_posix()}"'
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)


@bash_capable
class TestSetSpidevBufsiz:
    @pytest.mark.parametrize("ending", ["\n", ""])
    def test_appends_the_token_to_the_single_line(self, tmp_path, ending):
        cmdline = tmp_path / "cmdline.txt"
        cmdline.write_text(BASE + ending, encoding="utf-8")
        r = _run(cmdline)
        assert r.returncode == 0, r.stderr
        text = cmdline.read_text(encoding="utf-8")
        assert text == f"{BASE} {TOKEN}{ending}"

    def test_is_idempotent(self, tmp_path):
        cmdline = tmp_path / "cmdline.txt"
        cmdline.write_text(BASE + "\n", encoding="utf-8")
        _run(cmdline)
        _run(cmdline)
        text = cmdline.read_text(encoding="utf-8")
        assert text.count(TOKEN) == 1
        assert text.count("\n") == 1

    @pytest.mark.parametrize("stale", ["spidev.bufsiz=4096", "spidev.bufsiz=", "spidev.bufsiz=262144"])
    def test_replaces_a_stale_value_in_place(self, tmp_path, stale):
        cmdline = tmp_path / "cmdline.txt"
        cmdline.write_text(f"{BASE} {stale} quiet\n", encoding="utf-8")
        r = _run(cmdline)
        assert r.returncode == 0, r.stderr
        assert cmdline.read_text(encoding="utf-8") == f"{BASE} {TOKEN} quiet\n"

    def test_leaves_other_parameters_alone(self, tmp_path):
        cmdline = tmp_path / "cmdline.txt"
        cmdline.write_text(BASE + " cfg80211.ieee80211_regdom=GB\n", encoding="utf-8")
        _run(cmdline)
        assert cmdline.read_text(encoding="utf-8") == f"{BASE} cfg80211.ieee80211_regdom=GB {TOKEN}\n"

    def test_missing_cmdline_is_non_fatal(self, tmp_path):
        r = _run(tmp_path / "absent.txt")
        assert r.returncode == 0
        assert "WARNING" in r.stderr
