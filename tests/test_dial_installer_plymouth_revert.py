"""Dial boot splash revert: revert_plymouth() undoes exactly what the install
recorded, and the uninstaller runs it while the state file still exists.

Functional bash round-trips against a scratch root with fake commands; the
uninstaller itself is only checked structurally and for syntax.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_dial_installer_plymouth import (  # noqa: E402
    CMDLINE, CONFIG, KERNEL, MODULES, THEME_NAME, SplashEnv,
)
from test_dial_staged_install import REPO_ROOT, bash_capable  # noqa: E402

UNINSTALLER = REPO_ROOT / "autostream_dial_uninstall.sh"
CONF = "[Daemon]\nTheme=bgrt\n"

FAKE_SETTHEME = r"""#!/bin/bash
if [[ $# -eq 0 ]]; then cat "$THEME_FILE"; exit 0; fi
echo "plymouth-set-default-theme $*" >> "$TRACE"
if [[ "$1" == "-r" ]]; then echo bgrt > "$THEME_FILE"; else echo "$1" > "$THEME_FILE"; fi
"""


def _installed_env(tmp_path: Path, *, cmdline: str = CMDLINE, packages: str = "initramfs-tools\n"):
    """A scratch root after one full install run."""
    env = SplashEnv(tmp_path, cmdline=cmdline)
    env.fake("plymouth-set-default-theme", FAKE_SETTHEME)
    env.dpkg.write_text(packages, encoding="utf-8")
    env.conf.parent.mkdir(parents=True, exist_ok=True)
    env.conf.write_text(CONF, encoding="utf-8")
    originals = {p: p.read_bytes() for p in (env.cmdline, env.config, env.modules, env.conf)}
    r = env.run("install_plymouth_packages; configure_plymouth", update="false")
    assert r.returncode == 0, r.stderr
    assert env.plystate.exists()
    env.trace.write_text("", encoding="utf-8")
    return env, originals


def _revert(env):
    return env.run("revert_plymouth", update="false")


@bash_capable
class TestRevert:
    @pytest.mark.parametrize("ending", ["", "\n"])
    def test_every_edit_is_undone_byte_for_byte(self, tmp_path, ending):
        env, originals = _installed_env(tmp_path, cmdline=CMDLINE + ending)
        assert env.cmdline.read_bytes() != originals[env.cmdline]
        r = _revert(env)
        assert r.returncode == 0, r.stderr
        for path, content in originals.items():
            assert path.read_bytes() == content, path.name
        assert env.cmdline.read_text(encoding="utf-8") == CMDLINE + ending
        assert env.config.read_text(encoding="utf-8") == CONFIG
        assert env.modules.read_text(encoding="utf-8") == MODULES
        assert env.conf.read_text(encoding="utf-8") == CONF

    def test_dropin_theme_directory_and_state_are_gone(self, tmp_path):
        env, _ = _installed_env(tmp_path)
        assert env.dropin.exists() and env.theme_dir.exists()
        _revert(env)
        assert not env.dropin.exists()
        assert not env.dropin.parent.exists()
        assert not env.theme_dir.exists()
        assert not env.plystate.exists()
        assert not (env.state / "plymouthd.conf.orig").exists()

    def test_purges_exactly_the_recorded_packages(self, tmp_path):
        env, _ = _installed_env(tmp_path, packages="initramfs-tools\n")
        _revert(env)
        assert "apt-get purge -y plymouth plymouth-themes" in env.calls()
        assert not [c for c in env.calls() if "initramfs-tools" in c and "purge" in c]

    def test_no_purge_when_nothing_was_installed_by_us(self, tmp_path):
        env, _ = _installed_env(tmp_path,
                                packages="plymouth\nplymouth-themes\ninitramfs-tools\n")
        _revert(env)
        assert not [c for c in env.calls() if c.startswith("apt-get")]

    def test_resets_the_default_theme_and_rebuilds_for_the_running_kernel(self, tmp_path):
        env, _ = _installed_env(tmp_path)
        _revert(env)
        assert "plymouth-set-default-theme -r" in env.calls()
        assert f"update-initramfs -u -k {KERNEL}" in env.calls()
        assert env.theme_file.read_text(encoding="utf-8").strip() == "bgrt"

    def test_another_default_theme_is_left_alone(self, tmp_path):
        env, _ = _installed_env(tmp_path)
        env.theme_file.write_text("spinner\n", encoding="utf-8")
        _revert(env)
        assert "plymouth-set-default-theme -r" not in env.calls()
        assert env.theme_file.read_text(encoding="utf-8").strip() == "spinner"

    def test_a_created_conf_is_deleted(self, tmp_path):
        env = SplashEnv(tmp_path)
        env.fake("plymouth-set-default-theme", FAKE_SETTHEME)
        env.run("configure_plymouth", update="false")
        assert env.state_map()["plymouthd_conf"] == "created"
        assert env.conf.exists()
        _revert(env)
        assert not env.conf.exists()

    def test_options_the_owner_set_themselves_survive(self, tmp_path):
        env = SplashEnv(tmp_path, cmdline=CMDLINE + " loglevel=7 quiet",
                        config="[all]\ndisable_splash=0\n", modules="vc4\n")
        env.fake("plymouth-set-default-theme", FAKE_SETTHEME)
        env.run("configure_plymouth", update="false")
        env.trace.write_text("", encoding="utf-8")
        _revert(env)
        words = env.cmdline.read_text(encoding="utf-8").split()
        assert "loglevel=7" in words and "quiet" in words
        assert "splash" not in words and "loglevel=3" not in words
        assert "disable_splash=1" in env.config.read_text(encoding="utf-8")
        assert "vc4" in env.modules.read_text(encoding="utf-8").split()
        assert "i2c_bcm2835" not in env.modules.read_text(encoding="utf-8").split()

    def test_a_token_that_is_part_of_another_word_is_not_stripped(self, tmp_path):
        env, _ = _installed_env(tmp_path, cmdline=CMDLINE + " myquiet")
        _revert(env)
        assert env.cmdline.read_text(encoding="utf-8") == CMDLINE + " myquiet"

    def test_second_run_is_a_no_op(self, tmp_path):
        env, _ = _installed_env(tmp_path)
        _revert(env)
        files = (env.cmdline, env.config, env.modules, env.conf)
        snapshot = {p: p.read_bytes() for p in files}
        env.trace.write_text("", encoding="utf-8")
        r = _revert(env)
        assert r.returncode == 0, r.stderr
        assert env.calls() == []
        assert {p: p.read_bytes() for p in files} == snapshot

    def test_no_state_file_is_a_no_op(self, tmp_path):
        env = SplashEnv(tmp_path)
        files = (env.cmdline, env.config, env.modules)
        snapshot = {p: p.read_bytes() for p in files}
        r = _revert(env)
        assert r.returncode == 0, r.stderr
        assert env.calls() == []
        assert {p: p.read_bytes() for p in files} == snapshot

    def test_steps_that_find_things_already_gone_still_succeed(self, tmp_path):
        env, _ = _installed_env(tmp_path)
        env.dropin.unlink()
        env.cmdline.unlink()
        env.config.unlink()
        env.modules.unlink()
        env.conf.unlink()
        r = env.run("set -e; revert_plymouth; echo survived", update="false")
        assert "survived" in r.stdout, r.stderr
        assert not env.plystate.exists()

    def test_failing_commands_do_not_abort_the_revert(self, tmp_path):
        env, _ = _installed_env(tmp_path)
        for name in ("apt-get", "update-initramfs"):
            env.fake(name, "#!/bin/bash\nexit 1\n")
        r = env.run("set -e; revert_plymouth; echo survived", update="false")
        assert "survived" in r.stdout, r.stderr
        assert not env.plystate.exists()

    def test_theme_name_matches_the_installed_one(self, tmp_path):
        env, _ = _installed_env(tmp_path)
        assert env.state_map()["theme"] == THEME_NAME


class TestUninstaller:
    def setup_method(self):
        self.text = UNINSTALLER.read_text(encoding="utf-8")

    def test_sources_the_helpers_from_the_checkout(self):
        assert 'source "$SCRIPT_DIR/installer/dial/helpers.sh"' in self.text
        assert self.text.index("SCRIPT_DIR=") < self.text.index("source ")

    def test_reverts_the_splash_before_the_state_directory_goes(self):
        assert self.text.count("revert_plymouth") == 1
        call = self.text.index("\nrevert_plymouth\n")
        assert call < self.text.index("rm -rf /var/lib/autostream\n")

    def test_one_daemon_reload_covers_the_dropin_removal(self):
        call = self.text.index("\nrevert_plymouth\n")
        assert call < self.text.index("systemctl daemon-reload")
        assert self.text.count("systemctl daemon-reload") == 1
