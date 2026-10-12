"""Rewriting cmdline.txt and config.txt without ever leaving one empty.

The boot partition is FAT. A file that is truncated and then written is empty
if the power goes between the two, and an empty cmdline.txt is a board that
will not boot. Every installer function that rewrites one of these files must
write the new content to a temporary file in the same directory and rename it
over the old one. These tests run the real functions in bash against scratch
files, with the commands that would fail replaced by recorders.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from conftest import bash_can_run_script_at_windows_path  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
HARDWARE = REPO_ROOT / "installer" / "lib" / "hardware.sh"
DIAL_HELPERS = REPO_ROOT / "installer" / "dial" / "helpers.sh"

bash_capable = pytest.mark.skipif(
    not bash_can_run_script_at_windows_path(),
    reason="bash cannot execute scripts at this path (MSYS2 limitation on Windows)",
)
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file semantics")

PRELUDE = '''
set -uo pipefail
IFS=$'\\n\\t'
info() { echo "INFO: $*"; }
warn() { echo "WARN: $*"; }
error() { echo "ERROR: $*"; }
'''

CMDLINE = "console=tty1 root=PARTUUID=abcd-02 rootfstype=ext4 rootwait"
CONFIG = "dtparam=audio=on\n[all]\narm_freq=700\narm_boost=0\nforce_turbo=0\nover_voltage=2\n"


def _bash(body: str, tmp_path: Path, library: Path = HARDWARE, path: str | None = None,
          **env: str):
    script = f'{PRELUDE}\nsource "{library.as_posix()}"\n{body}'
    e = dict(os.environ)
    e.update(env)
    if path is not None:
        e["PATH"] = path + os.pathsep + e["PATH"]
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          timeout=30, env=e, cwd=tmp_path)


def _write(path: Path, data: bytes | str) -> Path:
    path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
    return path


def _shim(tmp_path: Path, name: str, body: str) -> str:
    """A directory holding a fake NAME, to put first on PATH."""
    d = tmp_path / "shims"
    d.mkdir(exist_ok=True)
    f = d / name
    f.write_text("#!/bin/bash\n" + body, encoding="utf-8")
    f.chmod(0o755)
    return str(d)


def _only(tmp_path: Path, *names: str) -> list[str]:
    return sorted(p.name for p in tmp_path.iterdir() if p.name not in ("shims",) and
                  p.name not in names)


@bash_capable
class TestCmdlineLineEndings:
    @pytest.mark.parametrize("before, after", [
        (CMDLINE + "\n", CMDLINE + " maxcpus=2\n"),
        (CMDLINE + "\r\n", CMDLINE + " maxcpus=2\n"),
        (CMDLINE + "\r\r\n", CMDLINE + " maxcpus=2\n"),
        (CMDLINE, CMDLINE + " maxcpus=2"),
        (CMDLINE + "\r", CMDLINE + " maxcpus=2"),
    ], ids=["lf", "crlf", "double-cr", "no-newline", "bare-cr-at-end"])
    def test_the_result_is_one_line_with_no_carriage_return(self, tmp_path, before, after):
        f = _write(tmp_path / "cmdline.txt", before)
        r = _bash(f'ensure_cmdline_option maxcpus 2 "{f.as_posix()}"', tmp_path)
        assert r.returncode == 0, r.stderr
        assert f.read_bytes() == after.encode()
        assert b"\r" not in f.read_bytes()

    def test_removing_a_token_from_a_crlf_file_also_writes_lf(self, tmp_path):
        f = _write(tmp_path / "cmdline.txt", "console=tty1 maxcpus=2 rootwait\r\n")
        r = _bash(f'remove_cmdline_option maxcpus 2 "{f.as_posix()}"', tmp_path)
        assert r.returncode == 0, r.stderr
        assert f.read_bytes() == b"console=tty1 rootwait\n"

    def test_a_crlf_file_that_needs_no_change_is_left_byte_for_byte_alone(self, tmp_path):
        f = _write(tmp_path / "cmdline.txt", "console=tty1 maxcpus=2 rootwait\r\n")
        r = _bash(f'ensure_cmdline_option maxcpus 2 "{f.as_posix()}"', tmp_path)
        assert r.returncode == 0, r.stderr
        assert f.read_bytes() == b"console=tty1 maxcpus=2 rootwait\r\n"


@bash_capable
@posix_only
class TestFilesAreReplacedByRename:
    def test_cmdline_gets_a_new_inode(self, tmp_path):
        f = _write(tmp_path / "cmdline.txt", CMDLINE + "\n")
        before = f.stat().st_ino
        _bash(f'ensure_cmdline_option maxcpus 2 "{f.as_posix()}"', tmp_path)
        assert f.read_text() == CMDLINE + " maxcpus=2\n"
        assert f.stat().st_ino != before

    def test_removing_the_low_power_settings_gives_both_files_new_inodes(self, tmp_path):
        cfg = _write(tmp_path / "config.txt", CONFIG)
        cmd = _write(tmp_path / "cmdline.txt", CMDLINE + " maxcpus=2\n")
        before = (cfg.stat().st_ino, cmd.stat().st_ino)
        r = _bash(f'remove_low_power_settings "{cfg.as_posix()}" "{cmd.as_posix()}"', tmp_path)
        assert r.returncode == 0, r.stderr
        assert (cfg.stat().st_ino, cmd.stat().st_ino) != before
        assert cfg.stat().st_ino != before[0] and cmd.stat().st_ino != before[1]
        assert cfg.read_text() == "dtparam=audio=on\n[all]\nover_voltage=2\n"

    def test_the_firmware_settings_update_gives_config_a_new_inode(self, tmp_path):
        cfg = _write(tmp_path / "config.txt", CONFIG)
        before = cfg.stat().st_ino
        r = _bash(f'update_pi_firmware_config "{cfg.as_posix()}" install 0', tmp_path)
        assert r.returncode == 0, r.stderr
        assert cfg.stat().st_ino != before
        assert "dtparam=watchdog=on" in cfg.read_text()

    def test_a_file_that_needs_no_change_keeps_its_inode(self, tmp_path):
        f = _write(tmp_path / "cmdline.txt", CMDLINE + " maxcpus=2\n")
        before = f.stat().st_ino
        _bash(f'ensure_cmdline_option maxcpus 2 "{f.as_posix()}"', tmp_path)
        assert f.stat().st_ino == before

    def test_the_target_is_never_opened_for_writing(self, tmp_path):
        """The only thing written is the temporary file; the target is only read
        and then replaced by mv. Checked with a shell whose redirections to the
        target would show: the target is made read-only, and a truncating write
        would fail, while a rename over it (which needs the directory, not the
        file) still works."""
        f = _write(tmp_path / "cmdline.txt", CMDLINE + "\n")
        f.chmod(0o444)
        r = _bash(f'ensure_cmdline_option maxcpus 2 "{f.as_posix()}"', tmp_path)
        assert r.returncode == 0, r.stderr
        assert f.read_text() == CMDLINE + " maxcpus=2\n"

    def test_the_temporary_file_is_made_beside_the_target_not_in_tmp(self, tmp_path):
        f = _write(tmp_path / "cmdline.txt", CMDLINE + "\n")
        log = tmp_path / "mv.log"
        mv = _shim(tmp_path, "mv", f'echo "$@" >> "{log.as_posix()}"\nexec /bin/mv "$@"\n')
        unusable = tmp_path / "no-such-tmp"
        r = _bash(f'ensure_cmdline_option maxcpus 2 "{f.as_posix()}"', tmp_path, path=mv,
                  TMPDIR=str(unusable))
        assert r.returncode == 0, r.stderr
        assert f.read_text() == CMDLINE + " maxcpus=2\n"
        args = log.read_text().split()
        sources = [a for a in args if a.startswith(str(tmp_path)) and a != str(f)]
        assert sources and all(Path(a).parent == tmp_path for a in sources)

    @pytest.mark.parametrize("mode", [0o644, 0o755, 0o600])
    def test_the_mode_is_carried_across(self, tmp_path, mode):
        f = _write(tmp_path / "cmdline.txt", CMDLINE + "\n")
        f.chmod(mode)
        _bash(f'ensure_cmdline_option maxcpus 2 "{f.as_posix()}"', tmp_path)
        assert stat.S_IMODE(f.stat().st_mode) == mode
        cfg = _write(tmp_path / "config.txt", CONFIG)
        cfg.chmod(mode)
        _bash(f'update_pi_firmware_config "{cfg.as_posix()}" install 0', tmp_path)
        assert stat.S_IMODE(cfg.stat().st_mode) == mode


@bash_capable
@posix_only
class TestAFailureLeavesTheOriginalAndNoTemporaryFile:
    @pytest.mark.parametrize("body, names", [
        ('ensure_cmdline_option maxcpus 3 "{cmd}"', ("cmdline.txt", "cmdline.txt.autostream-bak")),
        ('remove_cmdline_option maxcpus 2 "{cmd}"', ("cmdline.txt", "cmdline.txt.autostream-bak")),
        ('remove_low_power_settings "{cfg}" "{cmd}"',
         ("cmdline.txt", "config.txt", "cmdline.txt.autostream-bak")),
        ('update_pi_firmware_config "{cfg}" install 0',
         ("cmdline.txt", "config.txt", "cmdline.txt.autostream-bak")),
    ], ids=["ensure", "remove", "remove-low-power", "firmware"])
    def test_a_failed_rename_leaves_the_files_as_they_were(self, tmp_path, body, names):
        cmd = _write(tmp_path / "cmdline.txt", CMDLINE + " maxcpus=2\n")
        cfg = _write(tmp_path / "config.txt", CONFIG)
        cmd_ino, cfg_ino = cmd.stat().st_ino, cfg.stat().st_ino
        mv = _shim(tmp_path, "mv", "exit 1\n")
        r = _bash(body.format(cmd=cmd.as_posix(), cfg=cfg.as_posix()), tmp_path, path=mv)
        assert "WARN" in r.stdout or r.returncode != 0
        assert cmd.read_text() == CMDLINE + " maxcpus=2\n"
        assert cfg.read_text() == CONFIG
        assert (cmd.stat().st_ino, cfg.stat().st_ino) == (cmd_ino, cfg_ino)
        assert _only(tmp_path, "cmdline.txt", "config.txt", "cmdline.txt.autostream-bak") == []

    def test_a_failure_while_flushing_leaves_the_files_as_they_were(self, tmp_path):
        cmd = _write(tmp_path / "cmdline.txt", CMDLINE + "\n")
        sync = _shim(tmp_path, "sync", "exit 1\n")
        r = _bash(f'ensure_cmdline_option maxcpus 2 "{cmd.as_posix()}"', tmp_path, path=sync)
        assert "WARN" in r.stdout
        assert cmd.read_text() == CMDLINE + "\n"
        assert _only(tmp_path, "cmdline.txt", "cmdline.txt.autostream-bak") == []

    def test_a_failure_to_write_the_temporary_file_leaves_the_original(self, tmp_path):
        cmd = _write(tmp_path / "cmdline.txt", CMDLINE + "\n")
        mktemp = _shim(tmp_path, "mktemp", "exit 1\n")
        r = _bash(f'ensure_cmdline_option maxcpus 2 "{cmd.as_posix()}"', tmp_path, path=mktemp)
        assert "WARN" in r.stdout
        assert cmd.read_text() == CMDLINE + "\n"

    def test_a_power_cut_between_the_two_steps_cannot_leave_an_empty_file(self, tmp_path):
        """The writer is killed as soon as it has made the temporary file, which
        is the instant a truncate-then-write editor would have emptied the
        target."""
        cmd = _write(tmp_path / "cmdline.txt", CMDLINE + "\n")
        mv = _shim(tmp_path, "mv", 'kill -9 $PPID\nexit 1\n')
        _bash(f'ensure_cmdline_option maxcpus 2 "{cmd.as_posix()}"', tmp_path, path=mv)
        assert cmd.read_text() == CMDLINE + "\n"


@bash_capable
@posix_only
class TestDialBootConfigEditors:
    def _run(self, tmp_path, body, **kw):
        return _bash(body, tmp_path, library=DIAL_HELPERS, **kw)

    def test_rewriting_a_key_renames_a_finished_file_into_place(self, tmp_path):
        cfg = _write(tmp_path / "config.txt", "gpu_mem=16\ndtparam=audio=on\ngpu_mem=64\n")
        before = cfg.stat().st_ino
        r = self._run(tmp_path, f'write_boot_config_line gpu_mem 128 "{cfg.as_posix()}"')
        assert r.returncode == 0, r.stderr
        assert cfg.read_text() == "gpu_mem=128\ndtparam=audio=on\n"
        assert cfg.stat().st_ino != before

    def test_removing_a_key_renames_a_finished_file_into_place(self, tmp_path):
        cfg = _write(tmp_path / "config.txt", "disable_splash=1\ndtparam=audio=on\n")
        before = cfg.stat().st_ino
        r = self._run(tmp_path, f'remove_boot_config_line disable_splash "{cfg.as_posix()}"')
        assert r.returncode == 0, r.stderr
        assert cfg.read_text() == "dtparam=audio=on\n"
        assert cfg.stat().st_ino != before

    def test_a_failed_rename_leaves_the_original_and_no_temporary_file(self, tmp_path):
        cfg = _write(tmp_path / "config.txt", "gpu_mem=16\n")
        mv = _shim(tmp_path, "mv", "exit 1\n")
        r = self._run(tmp_path, f'write_boot_config_line gpu_mem 128 "{cfg.as_posix()}"',
                      path=mv)
        assert "could not rewrite gpu_mem" in r.stderr
        assert cfg.read_text() == "gpu_mem=16\n"
        assert _only(tmp_path, "config.txt") == []

    def test_a_failed_rename_on_removal_leaves_the_original_and_no_temporary_file(self, tmp_path):
        cfg = _write(tmp_path / "config.txt", "disable_splash=1\n")
        mv = _shim(tmp_path, "mv", "exit 1\n")
        r = self._run(tmp_path, f'remove_boot_config_line disable_splash "{cfg.as_posix()}"',
                      path=mv)
        assert "could not remove disable_splash" in r.stderr
        assert cfg.read_text() == "disable_splash=1\n"
        assert _only(tmp_path, "config.txt") == []

    def test_a_file_that_needs_no_change_is_not_replaced(self, tmp_path):
        cfg = _write(tmp_path / "config.txt", "gpu_mem=128\n")
        before = cfg.stat().st_ino
        self._run(tmp_path, f'write_boot_config_line gpu_mem 128 "{cfg.as_posix()}"')
        assert cfg.stat().st_ino == before
        assert _only(tmp_path, "config.txt") == []


@posix_only
class TestPrivilegedHelperBootConfigWrite:
    """The helper that switches the onboard Bluetooth radio edits config.txt by
    writing a sibling and renaming it, which cannot truncate the file."""

    def _admin(self):
        from conftest import load_supervisor_script
        return load_supervisor_script("autostream_admin", "admin_boot_files")

    def test_the_change_is_made_by_rename(self, tmp_path):
        m = self._admin()
        cfg = _write(tmp_path / "config.txt", "[all]\nenable_uart=1\n")
        before = cfg.stat().st_ino
        ok, changed = m.bt_onboard_set_config(cfg, enable_onboard=False)
        assert (ok, changed) == (True, True)
        assert "dtoverlay=disable-bt" in cfg.read_text()
        assert cfg.stat().st_ino != before
        assert sorted(p.name for p in tmp_path.iterdir()) == ["config.txt"]

    def test_a_failed_write_leaves_the_file_and_no_temporary_file(self, tmp_path):
        from unittest.mock import patch
        m = self._admin()
        cfg = _write(tmp_path / "config.txt", "[all]\nenable_uart=1\n")
        with patch.object(m.os, "fsync", side_effect=OSError("io error")):
            ok, changed = m.bt_onboard_set_config(cfg, enable_onboard=False)
        assert (ok, changed) == (False, False)
        assert cfg.read_text() == "[all]\nenable_uart=1\n"
        assert sorted(p.name for p in tmp_path.iterdir()) == ["config.txt"]
