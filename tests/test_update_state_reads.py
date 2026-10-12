"""State files root reads back are read without following a link.

The install state and the update result are in /var/lib/autostream, where the
service account can put a link at either name. The installers and the settings
tool read them as root and act on what they find (the tag recorded for the
previous release, the dial identity, the low power record, the saved SD card
health lines), so a link must read as absent: the content of the file it points
at is neither used nor copied. Each reader is exercised with a link planted at
its file, as that account would plant it.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_dial_staged_install import (  # noqa: E402
    Env, RECORDER, REPO_ROOT, bash_capable, posix_only,
)
from test_dial_installer_hardening import _function_text  # noqa: E402
from test_dial_installer_hd import _dry_run  # noqa: E402,F401

pytestmark = posix_only

UNINSTALLER = REPO_ROOT / "autostream_uninstall.sh"
DIAL_INSTALLER = REPO_ROOT / "autostream_dial_install.sh"
SETTINGS_APPLY = REPO_ROOT / "tools" / "autostream_settings_apply.py"


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def _secret(env: Env, text: str) -> Path:
    """A file the service account cannot read, and a link to it at the state file."""
    target = env.tmp / "root-only.env"
    target.write_text(text, encoding="utf-8")
    return target


@bash_capable
class TestDialInstallerReaders:
    def test_the_installed_tag_is_read_from_a_regular_file(self, env):
        env.install_state.write_text("AUTOSTREAM_RELEASE_TAG=1.2.0\n", encoding="utf-8")
        assert env.run("_installed_release_tag").stdout.strip() == "1.2.0"

    def test_the_installed_tag_is_not_read_through_a_link(self, env):
        env.install_state.symlink_to(_secret(env, "AUTOSTREAM_RELEASE_TAG=leaked\n"))
        r = env.run("_installed_release_tag")
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == ""

    def test_an_install_state_value_is_not_read_through_a_link(self, env):
        env.install_state.symlink_to(_secret(env, "REQUIREMENTS_LOCK_SHA256=abc\n"))
        r = env.run("_install_state_value REQUIREMENTS_LOCK_SHA256")
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == ""
        env.install_state.unlink()
        env.install_state.write_text("REQUIREMENTS_LOCK_SHA256=abc\n", encoding="utf-8")
        assert env.run("_install_state_value REQUIREMENTS_LOCK_SHA256").stdout.strip() == "abc"

    def test_an_update_result_value_is_not_read_through_a_link(self, env):
        env.result.symlink_to(_secret(env, "PREVIOUS_TAG=leaked\nATTEMPT=3\n"))
        r = env.run("_update_result_value PREVIOUS_TAG; _update_result_value ATTEMPT")
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == ""

    def test_the_result_carry_over_does_not_copy_a_linked_file_in(self, env):
        target = _secret(env, "PHASE=leaked\nTAG=leaked\nATTEMPT=9\n")
        env.result.symlink_to(target)
        r = env.run('write_update_result in_progress "Working" 10')
        assert r.returncode == 0, r.stderr
        text = env.result.read_text(encoding="utf-8")
        assert "leaked" not in text and "ATTEMPT=9" not in text
        assert not env.result.is_symlink()
        assert target.read_text(encoding="utf-8").startswith("PHASE=leaked")

    def test_the_saved_sd_health_lines_are_not_taken_through_a_link(self, env):
        env.fake("chown", RECORDER)
        env.install_state.symlink_to(_secret(env, "SDMON_METHOD=leaked\nSDMON_CHECK=passed\n"))
        r = env.run("VENV_LOCK_SHA256=; AUTOSTREAM_RELEASE_TAG=1.3.0; write_install_state "
                    "0123456789abcdef0123")
        assert r.returncode == 0, r.stderr
        text = env.install_state.read_text(encoding="utf-8")
        assert "SDMON_" not in text
        assert "DIAL_UUID=0123456789abcdef0123" in text

    def test_the_saved_sd_health_lines_are_carried_over_from_a_regular_file(self, env):
        env.fake("chown", RECORDER)
        env.install_state.write_text("DIAL_UUID=x\nSDMON_METHOD=auto\nOTHER=1\n", encoding="utf-8")
        r = env.run("VENV_LOCK_SHA256=; AUTOSTREAM_RELEASE_TAG=1.3.0; write_install_state "
                    "0123456789abcdef0123")
        assert r.returncode == 0, r.stderr
        text = env.install_state.read_text(encoding="utf-8")
        assert "SDMON_METHOD=auto" in text and "OTHER" not in text

    def test_the_identity_is_read_without_following_a_link(self, env):
        text = DIAL_INSTALLER.read_text(encoding="utf-8")
        block = text[text.index("Parse without source"):]
        assert 'read_state_file' in block[:block.index("DIAL_UUID=$(grep")]
        assert "grep '^DIAL_UUID=' \\\n" not in block
        env.install_state.symlink_to(_secret(env, "DIAL_UUID=0123456789abcdef0123\n"))
        r = env.run('read_state_file "$INSTALL_STATE_FILE" || echo absent')
        assert r.returncode == 0 and r.stdout.strip() == "absent"

    def test_the_dial_name_is_opened_without_following_a_link(self):
        text = DIAL_INSTALLER.read_text(encoding="utf-8")
        block = text[text.index("DIAL_NAME=$(python3"):]
        block = block[:block.index("|| true)")]
        assert "O_NOFOLLOW" in block and "json.load(open(" not in block


@bash_capable
class TestTheTagTheHandOffCarries:
    @pytest.mark.parametrize("tag,kept", [
        ("1.2.0", True), ("0.7.0-beta.1", True), ("v1.2.3", True),
        ("1.2.0; reboot", False), ("$(id)", False), ("../x", False), ("", False),
        ("a" * 70, False),
    ])
    def test_a_tag_is_kept_only_when_it_is_a_version(self, env, tag, kept):
        r = env.run(f"_tag_or_empty {tag!r}")
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == (tag if kept else "")

    def test_a_forged_previous_tag_in_the_result_does_not_reach_the_hand_off(self, env):
        env.result.write_text("STATUS=in_progress\nPREVIOUS_TAG=1.2.0; touch /tmp/x\n",
                              encoding="utf-8")
        r = env.run("PREVIOUS_RELEASE_TAG=1.1.0; NEW_VENV=v; PREVIOUS_VENV=w\nwrite_update_swap")
        assert r.returncode == 0, r.stderr
        lines = env.swap.read_text(encoding="utf-8").splitlines()
        assert "PREVIOUS_TAG=1.1.0" in lines
        assert not any("touch" in ln for ln in lines)

    def test_a_forged_previous_tag_and_nothing_to_fall_back_on_leaves_it_empty(self, env):
        env.result.write_text("PREVIOUS_TAG=$(id)\n", encoding="utf-8")
        r = env.run("NEW_VENV=v; PREVIOUS_VENV=w\nwrite_update_swap")
        assert r.returncode == 0, r.stderr
        assert "PREVIOUS_TAG=\n" in env.swap.read_text(encoding="utf-8")


@bash_capable
class TestApplianceUninstallerLowPowerRecord:
    def _run(self, env: Env, state: Path):
        func = _function_text(UNINSTALLER, "revert_low_power_if_used")
        body = (f'info() {{ echo "info: $*"; }}; warn() {{ echo "warn: $*"; }}\n'
                'remove_low_power_settings() { echo REMOVED; }\n'
                f'INSTALL_STATE_FILE="{state.as_posix()}"\n{func}\nrevert_low_power_if_used')
        return subprocess.run(["bash", "-c", body], capture_output=True, text=True, timeout=20)

    def test_the_record_in_a_regular_file_is_acted_on(self, env):
        env.install_state.write_text('LOW_POWER="1"\n', encoding="utf-8")
        assert "REMOVED" in self._run(env, env.install_state).stdout

    def test_a_link_to_a_file_with_that_line_is_not(self, env):
        env.install_state.symlink_to(_secret(env, 'LOW_POWER="1"\n'))
        r = self._run(env, env.install_state)
        assert r.returncode == 0
        assert "REMOVED" not in r.stdout


class TestSettingsToolOldTag:
    @pytest.fixture
    def tool(self):
        spec = importlib.util.spec_from_file_location("settings_apply_under_test", SETTINGS_APPLY)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        return mod

    def test_a_regular_state_file_gives_its_tag(self, tool, tmp_path):
        state = tmp_path / "install-state.env"
        state.write_text('AUTOSTREAM_RELEASE_TAG="0.6.1"\n', encoding="utf-8")
        assert tool._read_old_release_tag(state) == "0.6.1"

    def test_a_link_reads_as_no_tag(self, tool, tmp_path):
        target = tmp_path / "elsewhere"
        target.write_text('AUTOSTREAM_RELEASE_TAG="9.9.9"\n', encoding="utf-8")
        state = tmp_path / "install-state.env"
        state.symlink_to(target)
        assert tool._read_old_release_tag(state) is None

    def test_a_pipe_reads_as_no_tag_and_does_not_block(self, tool, tmp_path):
        state = tmp_path / "install-state.env"
        os.mkfifo(state)
        assert tool._read_old_release_tag(state) is None

    def test_an_absent_file_reads_as_no_tag(self, tool, tmp_path):
        assert tool._read_old_release_tag(tmp_path / "none.env") is None
