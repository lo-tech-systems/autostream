"""Installer tests: legacy now-playing hints migration and artwork deps.

Covers remove_legacy_default_nowplaying_hints() in autostream_install.sh:
the updater must delete a fielded hints file ONLY when it is provably the
legacy shipped default (every entry equal to the turntable default entry),
only under --owntone=mini, and must leave customised, extended, malformed,
empty, or full-mode files untouched. Runs the REAL function body extracted
from installer source (same harness as test_system_services_trim.py).
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from conftest import bash_can_run_script_at_windows_path

REPO_ROOT = Path(__file__).parent.parent
INSTALL_SH = REPO_ROOT / "autostream_install.sh"

bash_capable = pytest.mark.skipif(
    not bash_can_run_script_at_windows_path(),
    reason="bash cannot execute scripts at this path (MSYS2 limitation on Windows)",
)

LEGACY_ENTRY = {
    "title": "Enjoy",
    "artist": "Turntable",
    "album": "Vinyl LP",
    "artwork_path": "/opt/autostream/images/autostream-badge.png",
}


def _extract_function(src: str, name: str) -> str:
    """Like test_system_services_trim's extractor, but heredoc-aware: this
    function's body embeds a python heredoc whose dict literals close with a
    column-0 brace, so match through the heredoc terminator to the real
    closing brace instead of the first brace-at-column-0."""
    m = re.search(re.escape(name) + r"\(\)\s*\{.*?\nPYHINTS\n\}\n", src, re.S)
    if m is None:
        m = re.search(re.escape(name) + r"\(\)\s*\{.*?\n\}\n", src, re.S)
    assert m is not None, f"could not locate function {name}() in source"
    return m.group(0)


def _run_migration(tmp_path, *, mode: str, etc_content=None, opt_content=None):
    """Run the real remove_legacy_default_nowplaying_hints() body against a
    scratch pair of hints paths. Returns (result, etc_path, opt_path)."""
    etc_path = tmp_path / "etc-hints.json"
    opt_path = tmp_path / "opt-hints.json"
    for path, content in ((etc_path, etc_content), (opt_path, opt_content)):
        if content is not None:
            if isinstance(content, str):
                path.write_text(content, encoding="utf-8")
            else:
                path.write_text(json.dumps(content), encoding="utf-8")

    func_src = _extract_function(
        INSTALL_SH.read_text(encoding="utf-8"),
        "remove_legacy_default_nowplaying_hints",
    )
    script = (
        f'OWNTONE_MODE="{mode}"\n'
        f'export AUTOSTREAM_HINTS_FILE="{etc_path.as_posix()}"\n'
        f'export AUTOSTREAM_LEGACY_HINTS_FILE="{opt_path.as_posix()}"\n'
        f"{func_src}\n"
        "remove_legacy_default_nowplaying_hints\n"
    )
    driver = tmp_path / "driver.sh"
    driver.write_text(script, encoding="utf-8")
    result = subprocess.run(
        ["bash", str(driver)], capture_output=True, text=True, timeout=60,
    )
    return result, etc_path, opt_path


@bash_capable
class TestLegacyHintsMigration:
    def test_legacy_default_removed_from_both_locations(self, tmp_path):
        legacy = {"default": dict(LEGACY_ENTRY), "USB AUDIO  CODEC: Audio": dict(LEGACY_ENTRY)}
        result, etc_path, opt_path = _run_migration(
            tmp_path, mode="mini", etc_content=legacy, opt_content=legacy,
        )
        assert result.returncode == 0, result.stderr
        assert not etc_path.exists()
        assert not opt_path.exists()

    def test_single_legacy_entry_removed(self, tmp_path):
        result, etc_path, _ = _run_migration(
            tmp_path, mode="mini", etc_content={"default": dict(LEGACY_ENTRY)},
        )
        assert result.returncode == 0, result.stderr
        assert not etc_path.exists()

    def test_customised_file_preserved(self, tmp_path):
        customised = {"default": {**LEGACY_ENTRY, "title": "My Deck"}}
        result, etc_path, _ = _run_migration(
            tmp_path, mode="mini", etc_content=customised,
        )
        assert result.returncode == 0, result.stderr
        assert etc_path.exists()
        assert json.loads(etc_path.read_text(encoding="utf-8")) == customised

    def test_extended_file_preserved(self, tmp_path):
        extended = {"default": dict(LEGACY_ENTRY), "Line In": {"title": "Aux"}}
        result, etc_path, _ = _run_migration(
            tmp_path, mode="mini", etc_content=extended,
        )
        assert result.returncode == 0, result.stderr
        assert etc_path.exists()

    def test_malformed_file_preserved(self, tmp_path):
        result, etc_path, _ = _run_migration(
            tmp_path, mode="mini", etc_content="{ not valid json",
        )
        assert result.returncode == 0, result.stderr
        assert etc_path.exists()

    def test_empty_object_preserved(self, tmp_path):
        result, etc_path, _ = _run_migration(tmp_path, mode="mini", etc_content={})
        assert result.returncode == 0, result.stderr
        assert etc_path.exists()

    def test_absent_files_are_a_noop(self, tmp_path):
        result, etc_path, opt_path = _run_migration(tmp_path, mode="mini")
        assert result.returncode == 0, result.stderr
        assert not etc_path.exists()
        assert not opt_path.exists()

    def test_full_owntone_mode_never_touches_the_file(self, tmp_path):
        legacy = {"default": dict(LEGACY_ENTRY)}
        result, etc_path, _ = _run_migration(
            tmp_path, mode="full", etc_content=legacy,
        )
        assert result.returncode == 0, result.stderr
        assert etc_path.exists()

    def test_skip_mode_never_touches_the_file(self, tmp_path):
        legacy = {"default": dict(LEGACY_ENTRY)}
        result, etc_path, _ = _run_migration(
            tmp_path, mode="skip", etc_content=legacy,
        )
        assert result.returncode == 0, result.stderr
        assert etc_path.exists()


class TestArtworkInstallerDeps:
    def test_pillow_in_main_appliance_deps(self):
        src = INSTALL_SH.read_text(encoding="utf-8")
        deps = _extract_function(src, "ensure_build_deps")
        assert "python3-pil" in deps

    def test_migration_runs_in_configure_phase(self):
        src = INSTALL_SH.read_text(encoding="utf-8")
        configure = _extract_function(src, "configure_phase")
        assert "remove_legacy_default_nowplaying_hints" in configure
