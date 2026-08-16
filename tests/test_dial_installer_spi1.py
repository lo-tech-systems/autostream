"""enable_spi1() — the dial installer's SPI1 overlay management.

The touch controller sits on SPI1, and its chip select is a plain GPIO the
driver owns. The kernel claims whichever pin the overlay names, so the
overlay's cs0_pin MUST NOT be the touch chip select (GPIO16) or the display
backlight (GPIO18). A stale value silently collides and leaves touch dead
with no obvious cause, which is why the installer rewrites the line rather
than leaving whatever it finds.

Functional bash round-trips against a temp config.txt, following the pattern
in tests/test_bluetooth_installer.py.

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
EXPECTED = "dtoverlay=spi1-1cs,cs0_pin=12"


def _run_enable_spi1(cfg_path: Path) -> subprocess.CompletedProcess:
    script = f'set -e; source "{HELPERS.as_posix()}"; enable_spi1 "{cfg_path.as_posix()}"'
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)


@bash_capable
class TestEnableSpi1:
    def test_appends_the_documented_overlay_when_absent(self, tmp_path):
        cfg = tmp_path / "config.txt"
        cfg.write_text("[all]\nenable_uart=1\n", encoding="utf-8")
        r = _run_enable_spi1(cfg)
        assert r.returncode == 0, r.stderr
        assert EXPECTED in cfg.read_text(encoding="utf-8")

    def test_is_idempotent_when_already_correct(self, tmp_path):
        cfg = tmp_path / "config.txt"
        cfg.write_text(f"[all]\nenable_uart=1\n{EXPECTED}\n", encoding="utf-8")
        _run_enable_spi1(cfg)
        assert cfg.read_text(encoding="utf-8").count(EXPECTED) == 1

    @pytest.mark.parametrize("stale", [
        "dtoverlay=spi1-1cs",                 # overlay default: takes GPIO18, the backlight
        "dtoverlay=spi1-1cs,cs0_pin=16",      # an earlier layout: collides with touch CS
        "dtoverlay=spi1-2cs",
        "  dtoverlay=spi1-1cs,cs0_pin=26  ",
    ])
    def test_rewrites_a_stale_overlay_to_the_current_numbering(self, tmp_path, stale):
        cfg = tmp_path / "config.txt"
        cfg.write_text(f"[all]\nenable_uart=1\n{stale}\n", encoding="utf-8")
        r = _run_enable_spi1(cfg)
        assert r.returncode == 0, r.stderr
        text = cfg.read_text(encoding="utf-8")
        assert EXPECTED in text
        assert text.count("dtoverlay=spi1") == 1, "stale overlay line survived"

    def test_never_parks_chip_select_on_a_pin_the_dial_uses(self, tmp_path):
        """cs0_pin must avoid GPIO16 (touch CS) and GPIO18 (backlight)."""
        cfg = tmp_path / "config.txt"
        cfg.write_text("[all]\n", encoding="utf-8")
        _run_enable_spi1(cfg)
        line = [
            ln for ln in cfg.read_text(encoding="utf-8").splitlines()
            if "dtoverlay=spi1" in ln
        ][0]
        assert "cs0_pin=" in line, "an unparameterised overlay would claim GPIO18"
        assert "cs0_pin=16" not in line
        assert "cs0_pin=18" not in line

    def test_missing_config_is_non_fatal(self, tmp_path):
        r = _run_enable_spi1(tmp_path / "does-not-exist.txt")
        assert r.returncode == 0
        assert "WARNING" in r.stderr

    def test_leaves_unrelated_lines_alone(self, tmp_path):
        cfg = tmp_path / "config.txt"
        cfg.write_text(
            "dtparam=spi=on\ndtoverlay=disable-bt\ndtoverlay=spi1-1cs,cs0_pin=16\n",
            encoding="utf-8",
        )
        _run_enable_spi1(cfg)
        text = cfg.read_text(encoding="utf-8")
        assert "dtparam=spi=on" in text
        assert "dtoverlay=disable-bt" in text
