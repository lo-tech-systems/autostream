"""The last root writes and reads in the service account's state directory.

/var/lib/autostream belongs to the service account, which can put a link, or
any other file, at any name in it. These are the places the installers and the
dial updater still wrote or read there by plain redirect: the sdmon version
marker, the creation of the dial authorization store, the boot splash state
file and the saved copy of its configuration, and the dial updater's read of
the dial settings. Each is exercised with a link planted at its name, as that
account would plant it, and checked for what the link points at being left
alone. The splash state is also checked for what the uninstaller accepts back
from it, and for a dial installed before this change still reverting.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_dial_staged_install import REPO_ROOT, bash_capable, posix_only  # noqa: E402
from test_dial_installer_plymouth import CMDLINE, CONFIG, MODULES, SplashEnv  # noqa: E402
from test_dial_installer_plymouth_revert import FAKE_SETTHEME, _installed_env, _revert  # noqa: E402
from test_dial_update_channel import _load_script  # noqa: E402
from test_low_power_mode import _function  # noqa: E402

pytestmark = posix_only

STATE_FILES = REPO_ROOT / "installer" / "lib" / "state_files.sh"
APPLIANCE_INSTALLER = REPO_ROOT / "autostream_install.sh"
DIAL_HELPERS = REPO_ROOT / "installer" / "dial" / "helpers.sh"
SECRET = "root-only-contents\n"
REF = "8a70aed673f4b319972b3a2cfac043e3b171653a"


@pytest.fixture
def victim(tmp_path):
    path = tmp_path / "victim"
    path.write_text(SECRET, encoding="utf-8")
    path.chmod(0o600)
    return path


# ---------------------------------------------------------------------------
# The appliance installer: the sdmon marker and the dial authorization store
# ---------------------------------------------------------------------------

def _appliance(tmp_path: Path, body: str, *, functions=("sdmon_marker_matches",
               "record_sdmon_marker", "ensure_dials_store"), sdmon_binary: Path | None = None):
    """Run BODY with the installer's own functions over a scratch state directory,
    chown recorded instead of run."""
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    stubs = tmp_path / "stubs"
    stubs.mkdir(exist_ok=True)
    (stubs / "chown").write_text('#!/bin/sh\necho "$@" >> "$CHOWN_LOG"\n', encoding="utf-8")
    (stubs / "chown").chmod(0o755)
    (tmp_path / "chown.log").touch()
    text = APPLIANCE_INSTALLER.read_text(encoding="utf-8")
    code = "\n".join(_function(text, name) for name in functions)
    if sdmon_binary is not None:
        code = code.replace("/usr/local/sbin/sdmon", sdmon_binary.as_posix())
    e = dict(os.environ)
    e["PATH"] = stubs.as_posix() + os.pathsep + e["PATH"]
    e["CHOWN_LOG"] = (tmp_path / "chown.log").as_posix()
    script = (f'set -euo pipefail\nSTAMP_DIR="{state.as_posix()}"\n'
              f'source "{STATE_FILES.as_posix()}"\n{code}\n{body}')
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          timeout=30, env=e), state


class TestApplianceSdmonMarker:
    def test_the_marker_is_not_written_through_a_link(self, tmp_path, victim):
        state = tmp_path / "state"
        state.mkdir()
        (state / "sdmon-version").symlink_to(victim)
        r, state = _appliance(tmp_path, f"record_sdmon_marker {REF}")
        assert r.returncode == 0, r.stderr
        assert victim.read_text(encoding="utf-8") == SECRET
        marker = state / "sdmon-version"
        assert not marker.is_symlink()
        assert marker.read_text(encoding="utf-8") == REF + "\n"
        assert stat.S_IMODE(marker.stat().st_mode) == 0o644

    def test_the_marker_is_created_when_absent(self, tmp_path):
        r, state = _appliance(tmp_path, f"record_sdmon_marker {REF}")
        assert r.returncode == 0, r.stderr
        assert (state / "sdmon-version").read_text(encoding="utf-8") == REF + "\n"

    def test_a_marker_that_names_the_ref_matches(self, tmp_path):
        binary = tmp_path / "sdmon"
        binary.write_text("#!/bin/sh\n", encoding="utf-8")
        binary.chmod(0o755)
        r, _ = _appliance(
            tmp_path, f"record_sdmon_marker {REF}\nsdmon_marker_matches {REF} && echo MATCH",
            sdmon_binary=binary)
        assert "MATCH" in r.stdout, r.stderr

    def test_a_marker_that_is_a_link_does_not_match(self, tmp_path, victim):
        binary = tmp_path / "sdmon"
        binary.write_text("#!/bin/sh\n", encoding="utf-8")
        binary.chmod(0o755)
        victim.write_text(REF + "\n", encoding="utf-8")
        state = tmp_path / "state"
        state.mkdir()
        (state / "sdmon-version").symlink_to(victim)
        r, _ = _appliance(tmp_path, f"sdmon_marker_matches {REF} && echo MATCH || echo NO-MATCH",
                          sdmon_binary=binary)
        assert "NO-MATCH" in r.stdout, r.stderr

    def test_the_phase_uses_the_helpers_and_no_plain_redirect_text(self):
        text = APPLIANCE_INSTALLER.read_text(encoding="utf-8")
        body = text[text.index("sdmon_phase() {"):]
        body = body[:body.index("\n}\n")]
        assert "sdmon_marker_matches" in body and "record_sdmon_marker" in body
        assert '> "${marker}"' not in body and 'cat "${marker}"' not in body


class TestApplianceDialsStore:
    def test_it_is_created_with_its_owner_and_mode_on_the_open_file(self, tmp_path):
        r, state = _appliance(tmp_path, "ensure_dials_store")
        assert r.returncode == 0, r.stderr
        store = state / "dials.json"
        assert store.read_text(encoding="utf-8") == "{}\n"
        assert stat.S_IMODE(store.stat().st_mode) == 0o600
        log = (tmp_path / "chown.log").read_text(encoding="utf-8").split()
        assert log[0] == "autostream:autostream" and re.fullmatch(r"/proc/\d+/fd/1", log[1])

    def test_an_existing_store_is_left_exactly_as_it_is(self, tmp_path):
        state = tmp_path / "state"
        state.mkdir()
        (state / "dials.json").write_text('{"dial": "authorised"}\n', encoding="utf-8")
        (state / "dials.json").chmod(0o640)
        r, state = _appliance(tmp_path, "ensure_dials_store")
        assert r.returncode == 0, r.stderr
        assert (state / "dials.json").read_text(encoding="utf-8") == '{"dial": "authorised"}\n'
        assert stat.S_IMODE((state / "dials.json").stat().st_mode) == 0o640
        assert (tmp_path / "chown.log").read_text(encoding="utf-8") == ""

    def test_a_link_to_a_file_is_replaced_and_the_file_left_alone(self, tmp_path, victim):
        state = tmp_path / "state"
        state.mkdir()
        (state / "dials.json").symlink_to(victim)
        r, state = _appliance(tmp_path, "ensure_dials_store")
        assert r.returncode == 0, r.stderr
        assert victim.read_text(encoding="utf-8") == SECRET
        assert stat.S_IMODE(victim.stat().st_mode) == 0o600
        assert not (state / "dials.json").is_symlink()
        assert (state / "dials.json").read_text(encoding="utf-8") == "{}\n"
        assert str(victim) not in (tmp_path / "chown.log").read_text(encoding="utf-8")

    def test_a_dangling_link_does_not_create_what_it_points_at(self, tmp_path):
        target = tmp_path / "created-by-a-link"
        state = tmp_path / "state"
        state.mkdir()
        (state / "dials.json").symlink_to(target)
        r, state = _appliance(tmp_path, "ensure_dials_store")
        assert r.returncode == 0, r.stderr
        assert not target.exists()
        assert not (state / "dials.json").is_symlink()

    def test_the_configure_phase_calls_it_and_no_longer_redirects_into_the_store(self):
        text = APPLIANCE_INSTALLER.read_text(encoding="utf-8")
        body = text[text.index("configure_phase() {"):text.index("services_phase() {")]
        assert "ensure_dials_store" in body
        assert "> \"${STAMP_DIR}/dials.json\"" not in text


# ---------------------------------------------------------------------------
# The dial installer: the sdmon marker
# ---------------------------------------------------------------------------

class TestDialSdmonMarkerText:
    def test_the_marker_is_read_and_written_through_the_helpers_text(self):
        text = DIAL_HELPERS.read_text(encoding="utf-8")
        body = text[text.index("install_sdmon() {"):]
        body = body[:body.index("\n}\n")]
        assert 'read_state_file "${marker}"' in body
        assert 'write_state_file "${marker}" 0644' in body
        assert '> "${marker}"' not in body and 'cat "${marker}"' not in body
        assert 'chmod 0644 "${marker}"' not in body


# ---------------------------------------------------------------------------
# The dial installer: the boot splash state
# ---------------------------------------------------------------------------

def _splash_installed(tmp_path: Path):
    return _installed_env(tmp_path, packages="initramfs-tools\n")


class TestSplashStateWrites:
    def test_the_state_file_is_not_written_through_a_link(self, tmp_path, victim):
        env = SplashEnv(tmp_path)
        env.state.mkdir(parents=True, exist_ok=True)
        env.plystate.symlink_to(victim)
        r = env.step("_plymouth_state_set theme autostream-dial")
        assert r.returncode == 0, r.stderr
        assert victim.read_text(encoding="utf-8") == SECRET
        assert not env.plystate.is_symlink()
        assert env.state_map() == {"theme": "autostream-dial"}

    def test_a_link_to_a_file_with_lines_does_not_lend_them_to_the_state(self, tmp_path, victim):
        victim.write_text("packages_installed=openssh-server\n", encoding="utf-8")
        env = SplashEnv(tmp_path)
        env.plystate.symlink_to(victim)
        env.step("_plymouth_state_set theme autostream-dial")
        assert env.state_map() == {"theme": "autostream-dial"}

    def test_setting_a_key_keeps_the_others_and_replaces_its_own(self, tmp_path):
        env = SplashEnv(tmp_path)
        env.step("_plymouth_state_set theme autostream-dial; _plymouth_state_set dropin 1; "
                 "_plymouth_state_set theme autostream-dial")
        assert env.state_map() == {"theme": "autostream-dial", "dropin": "1"}
        assert stat.S_IMODE(env.plystate.stat().st_mode) == 0o644

    def test_the_saved_configuration_is_not_written_through_a_link(self, tmp_path, victim):
        env = SplashEnv(tmp_path)
        env.conf.parent.mkdir(parents=True, exist_ok=True)
        env.conf.write_text("[Daemon]\nTheme=bgrt\n", encoding="utf-8")
        (env.state).mkdir(parents=True, exist_ok=True)
        (env.state / "plymouthd.conf.orig").symlink_to(victim)
        r = env.step(f'rc=0; set_plymouth_device_timeout "{env.conf.as_posix()}" || rc=$?; '
                     'echo "rc=$rc"')
        assert "rc=10" in r.stdout, r.stderr          # 10: the file was changed
        assert victim.read_text(encoding="utf-8") == SECRET
        saved = env.state / "plymouthd.conf.orig"
        assert not saved.is_symlink()
        assert saved.read_text(encoding="utf-8") == "[Daemon]\nTheme=bgrt\n"
        assert env.state_map()["plymouthd_conf"] == "backup"

    def test_the_state_helpers_use_the_state_file_helpers_text(self):
        text = DIAL_HELPERS.read_text(encoding="utf-8")
        for name in ("_plymouth_state_get", "_plymouth_state_set"):
            body = text[text.index(f"{name}() {{"):]
            body = body[:body.index("\n}\n")]
            assert "state_file" in body
        assert 'cp -p "${file}" "$(_state_dir)/plymouthd.conf.orig"' not in text
        assert 'cp -p "${orig}" "${conf}"' not in text


class TestSplashStateReads:
    def _planted(self, tmp_path, lines: str, **kw):
        env, originals = _splash_installed(tmp_path)
        env.plystate.write_text(lines, encoding="utf-8")
        env.trace.write_text("", encoding="utf-8")
        return env, originals

    def test_only_the_packages_the_installer_could_have_added_are_purged(self, tmp_path):
        env, _ = self._planted(tmp_path, "packages_installed=plymouth openssh-server sudo "
                                         "plymouth-themes --allow-remove-essential\n")
        r = _revert(env)
        assert r.returncode == 0, r.stderr
        assert "apt-get purge -y plymouth plymouth-themes" in env.calls()
        assert not [c for c in env.calls() if "openssh" in c or "sudo" in c or "--allow" in c]

    def test_only_the_command_line_tokens_the_installer_could_have_added_are_removed(
            self, tmp_path):
        env, _ = self._planted(tmp_path, "cmdline_added=quiet root=PARTUUID=00000000-02 rootwait\n")
        env.cmdline.write_text(CMDLINE + " quiet\n", encoding="utf-8")
        _revert(env)
        words = env.cmdline.read_text(encoding="utf-8").split()
        assert "quiet" not in words
        assert "root=PARTUUID=00000000-02" in words and "rootwait" in words

    def test_only_the_modules_the_installer_could_have_added_are_removed(self, tmp_path):
        env, _ = self._planted(tmp_path, "modules_added=vc4 snd-bcm2835\n")
        env.modules.write_text(MODULES + "vc4\n", encoding="utf-8")
        _revert(env)
        lines = env.modules.read_text(encoding="utf-8").splitlines()
        assert "vc4" not in lines and "snd-bcm2835" in lines

    def test_only_the_config_line_the_installer_could_have_added_is_removed(self, tmp_path):
        env, _ = self._planted(tmp_path, "config_added=disable_splash=1 dtoverlay=vc4-kms-v3d\n")
        env.config.write_text(CONFIG + "disable_splash=1\n", encoding="utf-8")
        _revert(env)
        text = env.config.read_text(encoding="utf-8")
        assert "disable_splash" not in text and "dtoverlay=vc4-kms-v3d" in text

    def test_a_state_file_that_is_a_link_is_not_believed(self, tmp_path, victim):
        env, _ = self._planted(tmp_path, "")
        env.plystate.unlink()
        victim.write_text("packages_installed=plymouth\ncmdline_added=quiet splash\n",
                          encoding="utf-8")
        env.plystate.symlink_to(victim)
        before = env.cmdline.read_text(encoding="utf-8")
        r = _revert(env)
        assert r.returncode == 0, r.stderr
        assert not [c for c in env.calls() if c.startswith("apt-get purge")]
        assert env.cmdline.read_text(encoding="utf-8") == before
        assert victim.read_text(encoding="utf-8").startswith("packages_installed=")

    def test_a_saved_configuration_that_is_a_link_is_not_copied_into_the_live_one(
            self, tmp_path, victim):
        env, _ = _splash_installed(tmp_path)
        saved = env.state / "plymouthd.conf.orig"
        saved.unlink()
        saved.symlink_to(victim)
        _revert(env)
        assert SECRET not in env.conf.read_text(encoding="utf-8")

    def test_a_saved_configuration_that_is_not_one_is_not_put_back(self, tmp_path):
        env, _ = _splash_installed(tmp_path)
        live = env.conf.read_text(encoding="utf-8")
        (env.state / "plymouthd.conf.orig").write_text(
            "[Daemon]\nTheme=bgrt\n$(touch /tmp/x)\nbad line without equals\n", encoding="utf-8")
        r = _revert(env)
        assert r.returncode == 0, r.stderr
        assert env.conf.read_text(encoding="utf-8") == live
        assert "does not look like a plymouthd.conf" in r.stderr

    def test_a_dial_installed_before_this_change_still_reverts_completely(self, tmp_path):
        """State files written as the earlier installer wrote them: plain files in
        the same place with the same keys and formats."""
        env = SplashEnv(tmp_path)
        env.fake("plymouth-set-default-theme", FAKE_SETTHEME)
        env.conf.parent.mkdir(parents=True, exist_ok=True)
        env.conf.write_text("[Daemon]\nTheme=autostream-dial\nDeviceTimeout=20\n", encoding="utf-8")
        env.cmdline.write_text(CMDLINE + " quiet splash loglevel=3\n", encoding="utf-8")
        env.modules.write_text(MODULES + "i2c_bcm2835\nvc4\n", encoding="utf-8")
        env.config.write_text(CONFIG + "disable_splash=1\n", encoding="utf-8")
        env.dropin.parent.mkdir(parents=True, exist_ok=True)
        env.dropin.write_text("[Service]\n", encoding="utf-8")
        env.theme_dir.mkdir(parents=True, exist_ok=True)
        env.theme_file.write_text("autostream-dial\n", encoding="utf-8")
        (env.state / "plymouthd.conf.orig").write_text("[Daemon]\nTheme=bgrt\n", encoding="utf-8")
        env.plystate.write_text(
            "cmdline_added=loglevel=3 quiet splash\nconfig_added=disable_splash=1\n"
            "dropin=1\ninitramfs_kernel=6.18.34+rpt-rpi-v7\nmodules_added=i2c_bcm2835 vc4\n"
            "packages_installed=plymouth plymouth-themes\nplymouthd_conf=backup\n"
            "theme=autostream-dial\n", encoding="utf-8")
        r = _revert(env)
        assert r.returncode == 0, r.stderr
        assert env.conf.read_text(encoding="utf-8") == "[Daemon]\nTheme=bgrt\n"
        assert env.cmdline.read_text(encoding="utf-8").split() == CMDLINE.split()
        assert env.modules.read_text(encoding="utf-8") == MODULES
        assert "disable_splash" not in env.config.read_text(encoding="utf-8")
        assert not env.dropin.exists() and not env.theme_dir.exists()
        assert "apt-get purge -y plymouth plymouth-themes" in env.calls()
        assert not env.plystate.exists()
        assert not (env.state / "plymouthd.conf.orig").exists()

    def test_the_state_is_read_back_as_it_was_written(self, tmp_path):
        env = SplashEnv(tmp_path)
        r = env.step(
            '_plymouth_state_add packages_installed plymouth-themes plymouth\n'
            '_plymouth_state_add cmdline_added splash quiet\n'
            '_plymouth_state_set initramfs_kernel 6.18.34+rpt-rpi-v7\n'
            'echo "p=$(_plymouth_state_get packages_installed)"\n'
            'echo "c=$(_plymouth_state_get cmdline_added)"\n'
            'echo "k=$(_plymouth_state_get initramfs_kernel)"')
        assert "p=plymouth plymouth-themes" in r.stdout, r.stderr
        assert "c=quiet splash" in r.stdout
        assert "k=6.18.34+rpt-rpi-v7" in r.stdout


# ---------------------------------------------------------------------------
# The dial updater's read of the dial settings
# ---------------------------------------------------------------------------

@pytest.fixture
def updater(tmp_path):
    mod = _load_script("autostream_dial_updater")
    state = tmp_path / "state"
    state.mkdir()
    mod.STATE_DIR = state
    return mod, state


class TestDialUpdaterSettings:
    def test_a_plain_settings_file_is_read(self, updater):
        mod, state = updater
        (state / "dial-settings.json").write_text(
            json.dumps({"update_channel": "dev", "auto_update": True}), encoding="utf-8")
        assert mod._read_dial_channel() == "dev"
        assert json.loads(mod._read_dial_settings())["auto_update"] is True

    def test_a_link_at_the_settings_file_is_not_followed(self, updater, tmp_path):
        mod, state = updater
        elsewhere = tmp_path / "elsewhere.json"
        elsewhere.write_text(json.dumps({"update_channel": "dev", "auto_update": True}),
                             encoding="utf-8")
        (state / "dial-settings.json").symlink_to(elsewhere)
        assert mod._read_dial_channel() == "stable"
        with pytest.raises(ValueError):
            mod._read_dial_settings()

    def test_an_absent_file_gives_the_default(self, updater):
        mod, _ = updater
        assert mod._read_dial_channel() == "stable"
        with pytest.raises(FileNotFoundError):
            mod._read_dial_settings()

    def test_the_auto_update_flag_is_not_read_through_a_link(self, updater, tmp_path):
        mod, state = updater
        elsewhere = tmp_path / "elsewhere.json"
        elsewhere.write_text(json.dumps({"auto_update": True}), encoding="utf-8")
        (state / "dial-settings.json").symlink_to(elsewhere)
        mod.APMODE_FLAG = tmp_path / "no-ap-flag"
        result = mod.cmd_apply(auto=True)
        # Read as unreadable, which is the fail-closed path: nothing is applied.
        assert result == {"ok": True}

    def test_neither_read_uses_the_plain_reader_text(self):
        text = (REPO_ROOT / "supervisor" / "autostream_dial_updater").read_text(encoding="utf-8")
        assert "settings_path.read_text" not in text
        assert text.count("_read_dial_settings()") >= 3
