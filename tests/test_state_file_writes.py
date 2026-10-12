"""The installers' root writes into the service account's state directory.

/var/lib/autostream belongs to the service account, which can put a link, or
any other file, at any name in it. The installers write their state files
through installer/lib/state_files.sh: a new file with an unpredictable name
beside the old one, mode and owner set on the open file, then a rename. These
tests plant links at the destination and at the names the earlier code used
for its temporary files, and check that nothing they point at is touched, that
content, mode and owner are what was asked for, and that a failure leaves the
old file in place and no temporary file behind.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_dial_staged_install import (  # noqa: E402
    Env, REPO_ROOT, bash_capable, posix_only,
)
from test_dial_installer_hardening import _real_python3  # noqa: E402
from test_dial_installer_hd import _dry_run  # noqa: E402

STATE_FILES = REPO_ROOT / "installer" / "lib" / "state_files.sh"
INSTALLER = REPO_ROOT / "autostream_dial_install.sh"
SECRET = "root-only-contents\n"


def _run(tmp_path: Path, body: str, stubs: dict | None = None):
    """Run BODY in bash with state_files.sh sourced and chown recorded."""
    bin_dir = tmp_path / "stubs"
    bin_dir.mkdir(exist_ok=True)
    chown = bin_dir / "chown"
    chown.write_text('#!/bin/sh\necho "$@" >> "$CHOWN_LOG"\n', encoding="utf-8")
    chown.chmod(0o755)
    for name, text in (stubs or {}).items():
        (bin_dir / name).write_text(text, encoding="utf-8")
        (bin_dir / name).chmod(0o755)
    e = dict(os.environ)
    e["PATH"] = bin_dir.as_posix() + os.pathsep + e["PATH"]
    e["CHOWN_LOG"] = (tmp_path / "chown.log").as_posix()
    (tmp_path / "chown.log").touch()
    return subprocess.run(
        ["bash", "-c", f'set -euo pipefail\nsource "{STATE_FILES.as_posix()}"\n{body}'],
        capture_output=True, text=True, timeout=30, env=e, cwd=tmp_path)


@pytest.fixture
def victim(tmp_path):
    path = tmp_path / "victim"
    path.write_text(SECRET, encoding="utf-8")
    path.chmod(0o600)
    return path


def _only(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


@bash_capable
@posix_only
class TestWriteStateFile:
    def test_content_mode_and_owner_are_what_was_asked_for(self, tmp_path):
        d = tmp_path / "state"
        d.mkdir()
        (d / "f.env").write_text("old\n", encoding="utf-8")
        (d / "f.env").chmod(0o600)
        r = _run(tmp_path, f'printf "A=1\\nB=2\\n" | write_state_file "{d}/f.env" 0644 root:autostream')
        assert r.returncode == 0, r.stderr
        assert (d / "f.env").read_text(encoding="utf-8") == "A=1\nB=2\n"
        assert stat.S_IMODE((d / "f.env").stat().st_mode) == 0o644
        # chown is given the owner as asked, once, on the open file.
        calls = (tmp_path / "chown.log").read_text(encoding="utf-8").splitlines()
        assert len(calls) == 1 and calls[0].startswith("root:autostream /proc/")
        assert _only(d) == ["f.env"]

    def test_no_owner_means_no_chown_and_a_private_mode_is_kept(self, tmp_path):
        d = tmp_path / "state"
        d.mkdir()
        r = _run(tmp_path, f'echo secret | write_state_file "{d}/f.env" 0600')
        assert r.returncode == 0, r.stderr
        assert stat.S_IMODE((d / "f.env").stat().st_mode) == 0o600
        assert (tmp_path / "chown.log").read_text(encoding="utf-8") == ""

    def test_a_link_at_the_destination_is_replaced_not_followed(self, tmp_path, victim):
        d = tmp_path / "state"
        d.mkdir()
        (d / "f.env").symlink_to(victim)
        r = _run(tmp_path, f'echo new | write_state_file "{d}/f.env" 0644')
        assert r.returncode == 0, r.stderr
        assert victim.read_text(encoding="utf-8") == SECRET
        assert stat.S_IMODE(victim.stat().st_mode) == 0o600
        assert not (d / "f.env").is_symlink()
        assert (d / "f.env").read_text(encoding="utf-8") == "new\n"

    def test_links_at_the_names_the_earlier_code_used_are_left_alone(self, tmp_path, victim):
        d = tmp_path / "state"
        d.mkdir()
        old_names = ["f.env.tmp", ".f.env.tmp", "f.env.tmp.1", "f.tmp", "f.env.new"]
        for name in old_names:
            (d / name).symlink_to(victim)
        r = _run(tmp_path, f'echo new | write_state_file "{d}/f.env" 0644')
        assert r.returncode == 0, r.stderr
        assert victim.read_text(encoding="utf-8") == SECRET
        assert stat.S_IMODE(victim.stat().st_mode) == 0o600
        assert all((d / name).is_symlink() for name in old_names)

    def test_the_temporary_name_is_not_the_same_twice(self, tmp_path):
        d = tmp_path / "state"
        d.mkdir()
        r = _run(tmp_path, f'''
for i in 1 2 3; do mktemp -u -- "{d}/.f.env.XXXXXXXXXX"; done | sort -u | wc -l''')
        assert r.stdout.strip() == "3"

    def test_a_failed_rename_leaves_the_old_file_and_no_temporary(self, tmp_path):
        d = tmp_path / "state"
        d.mkdir()
        (d / "f.env").write_text("old\n", encoding="utf-8")
        (d / "f.env").chmod(0o640)
        r = _run(tmp_path, f'echo new | write_state_file "{d}/f.env" 0644',
                 stubs={"mv": "#!/bin/sh\nexit 1\n"})
        assert r.returncode != 0
        assert (d / "f.env").read_text(encoding="utf-8") == "old\n"
        assert stat.S_IMODE((d / "f.env").stat().st_mode) == 0o640
        assert _only(d) == ["f.env"]

    def test_a_destination_that_cannot_be_replaced_fails_cleanly(self, tmp_path):
        d = tmp_path / "state"
        (d / "f.env").mkdir(parents=True)
        r = _run(tmp_path, f'echo new | write_state_file "{d}/f.env" 0644')
        assert r.returncode != 0
        assert _only(d) == ["f.env"] and (d / "f.env").is_dir()

    def test_a_failed_chown_leaves_the_old_file_and_no_temporary(self, tmp_path):
        d = tmp_path / "state"
        d.mkdir()
        (d / "f.env").write_text("old\n", encoding="utf-8")
        r = _run(tmp_path, f'echo new | write_state_file "{d}/f.env" 0644 nobody',
                 stubs={"chown": "#!/bin/sh\nexit 1\n"})
        assert r.returncode != 0
        assert (d / "f.env").read_text(encoding="utf-8") == "old\n"
        assert _only(d) == ["f.env"]

    def test_a_missing_directory_fails_without_creating_anything(self, tmp_path):
        r = _run(tmp_path, f'echo new | write_state_file "{tmp_path}/nope/f.env" 0644')
        assert r.returncode != 0
        assert _only(tmp_path) == ["chown.log", "stubs"]


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


@bash_capable
@posix_only
class TestTheInstallersWritersUseIt:
    def test_the_dial_install_state_is_not_written_through_a_link(self, env, victim):
        env.install_state.symlink_to(victim)
        (env.state / "install-state.env.tmp").symlink_to(victim)
        env.fake("chown", "#!/bin/bash\n")
        r = env.run('VENV_LOCK_SHA256=abc123\nwrite_install_state uuid1')
        assert r.returncode == 0, r.stderr
        assert victim.read_text(encoding="utf-8") == SECRET
        assert not env.install_state.is_symlink()
        text = env.install_state.read_text(encoding="utf-8")
        assert "DIAL_UUID=uuid1" in text and "root-only-contents" not in text
        assert stat.S_IMODE(env.install_state.stat().st_mode) == 0o644

    def test_the_dial_install_state_keeps_the_sdmon_lines_and_loses_no_line(self, env):
        env.install_state.write_text("DIAL_UUID=x\nSDMON_METHOD=fast\n", encoding="utf-8")
        env.fake("chown", "#!/bin/bash\n")
        r = env.run('write_install_state uuid1')
        assert r.returncode == 0, r.stderr
        assert env.install_state.read_text(encoding="utf-8").splitlines()[-1] == "SDMON_METHOD=fast"

    def test_the_dial_update_result_is_not_written_through_a_link(self, env, victim):
        env.result.symlink_to(victim)
        for name in ("update-result.env.tmp", f"update-result.env.tmp.{os.getpid()}"):
            (env.state / name).symlink_to(victim)
        env.fake("chown", "#!/bin/bash\n")
        r = env.run('write_update_result in_progress "working" 5 PHASE=packages')
        assert r.returncode == 0, r.stderr
        assert victim.read_text(encoding="utf-8") == SECRET
        assert not env.result.is_symlink()
        assert "STATUS=in_progress" in env.result.read_text(encoding="utf-8")

    def test_the_dial_update_result_does_not_carry_over_a_linked_file(self, env, victim):
        victim.write_text("PHASE=leaked-phase\nTAG=leaked-tag\n", encoding="utf-8")
        env.result.symlink_to(victim)
        env.fake("chown", "#!/bin/bash\n")
        r = env.run('write_update_result in_progress "working" 5')
        assert r.returncode == 0, r.stderr
        assert "leaked" not in env.result.read_text(encoding="utf-8")

    def test_the_dial_update_result_keeps_its_keys_and_its_owner(self, env):
        env.result.write_text("STATUS=in_progress\nTAG=1.2.3\nATTEMPT=2\n", encoding="utf-8")
        env.fake("chown", '#!/bin/bash\necho "$@" >> "$TRACE"\n')
        r = env.run('write_update_result in_progress "next" 6 PHASE=install')
        assert r.returncode == 0, r.stderr
        text = env.result.read_text(encoding="utf-8")
        assert "TAG=1.2.3" in text and "ATTEMPT=2" in text and "PHASE=install" in text
        assert any(re.fullmatch(rf"{os.getuid()}:{os.getgid()} /proc/\d+/fd/1", c)
                   for c in env.calls())
        assert stat.S_IMODE(env.result.stat().st_mode) == 0o644

    def test_the_installed_tag_and_result_values_are_not_read_through_a_link(
            self, env, victim):
        victim.write_text("AUTOSTREAM_RELEASE_TAG=leaked\nATTEMPT=leaked\n", encoding="utf-8")
        env.install_state.symlink_to(victim)
        env.result.symlink_to(victim)
        r = env.run('echo "[$(_installed_release_tag)][$(_update_result_value ATTEMPT)]"')
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == "[][]"

    def test_the_fresh_install_result_file_is_written_through_the_helper(self):
        text = INSTALLER.read_text(encoding="utf-8")
        assert 'write_state_file "$_result_file" 0644 root:autostream' in text
        assert '> "$_result_file"' not in text

    def test_the_no_serial_fallback_id_is_not_written_through_a_link(
            self, env, victim, tmp_path):
        _real_python3(env)
        site = tmp_path / "site"
        site.mkdir()
        # The test is not root; make the descriptor-level ownership change a no-op.
        (site / "sitecustomize.py").write_text(
            "import os\nos.fchown = lambda *a: None\n", encoding="utf-8")
        env.put("proc/cpuinfo", "processor\t: 0\n")
        for name in ("dial-id", "dial-id.tmp", ".dial-id.tmp"):
            (env.state / name).symlink_to(victim)
        r = env.run("generate_dial_id", update="false", PYTHONPATH=site.as_posix())
        assert r.returncode == 0, r.stderr
        created = (env.state / "dial-id")
        assert not created.is_symlink()
        assert re.fullmatch(r"[0-9a-f]{20}", created.read_text(encoding="utf-8"))
        assert r.stdout.strip() == created.read_text(encoding="utf-8")
        assert stat.S_IMODE(created.stat().st_mode) == 0o644
        assert victim.read_text(encoding="utf-8") == SECRET
        assert (env.state / "dial-id.tmp").is_symlink()
        assert sorted(p.name for p in env.state.iterdir() if p.name.startswith(".dial-id.")
                      and not p.is_symlink()) == []

    def test_the_appliance_state_is_not_written_through_a_link(self, tmp_path, victim):
        from test_low_power_mode import _installer_run, _state_value
        link_first = (f'ln -s "{victim.as_posix()}" "$STATE_FILE"; '
                      f'ln -s "{victim.as_posix()}" "$STATE_FILE.tmp"; '
                      'parse_args; save_state')
        r, state = _installer_run(tmp_path, link_first)
        assert r.returncode == 0, r.stdout + r.stderr
        assert victim.read_text(encoding="utf-8") == SECRET
        assert not state.is_symlink()
        assert _state_value(state, "OWNTONE_MODE") == "mini"

    def test_the_appliance_state_writer_uses_the_helper(self):
        text = (REPO_ROOT / "autostream_install.sh").read_text(encoding="utf-8")
        assert 'write_state_file "${STATE_FILE}" 0644 root:root' in text
        assert 'source "${INSTALLER_LIB}/state_files.sh"' in text
        assert 'cat > "${STATE_FILE}"' not in text


@bash_capable
@posix_only
class TestTheStoredDialIdentityIsChecked:
    STORED = "feedfacefeedfacefeed"
    DERIVED = "0123456789abcdef0123"  # what the stubbed derivation returns

    def _update(self, tmp_path, state):
        r, calls = _dry_run(tmp_path, update=True, state_text=state)
        assert r.returncode == 0, r.stderr
        return r, calls

    def test_a_well_formed_identity_is_used_as_it_is(self, tmp_path):
        r, calls = self._update(tmp_path, f"DIAL_UUID={self.STORED}\n")
        assert f"write_install_state {self.STORED}" in calls
        assert "malformed" not in r.stdout + r.stderr

    @pytest.mark.parametrize("state", [
        pytest.param("DIAL_UUID=\n", id="empty"),
        pytest.param("AUTOSTREAM_PRODUCT=autostream-dial\n", id="absent"),
        pytest.param("DIAL_UUID=FEEDFACEFEEDFACEFEED\n", id="upper-case"),
        pytest.param("DIAL_UUID=feedfacefeedfacefee\n", id="too-short"),
        pytest.param("DIAL_UUID=feedfacefeedfacefeed0\n", id="too-long"),
        pytest.param("DIAL_UUID=feedfacefeedfacefeed \n", id="trailing-space"),
        pytest.param("DIAL_UUID=feedfacefeedfacefeed\nDIAL_UUID=feedfacefeedfacefeed\n",
                     id="two-lines"),
        pytest.param("DIAL_UUID=zzzzzzzzzzzzzzzzzzzz\n", id="not-hex"),
        pytest.param("DIAL_UUID=feedfacefeedfacefe$(id)\n", id="shell-syntax"),
    ])
    def test_anything_else_is_replaced_by_the_derivation_with_a_warning(
            self, tmp_path, state):
        r, calls = self._update(tmp_path, state)
        assert f"write_install_state {self.DERIVED}" in calls
        assert "malformed" in r.stdout + r.stderr
