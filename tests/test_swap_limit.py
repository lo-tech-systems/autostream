"""The swap file limit: the shared drop-in, the library function that installs
it, and where the appliance and dial installers and uninstallers use it.

Functional bash round-trips against a scratch /etc/rpi with fake commands on
PATH; the checks that read script text say so in their names.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_dial_staged_install import Env, REPO_ROOT, bash_capable, HELPERS, INSTALLER  # noqa: E402

SWAP_LIB = REPO_ROOT / "installer" / "lib" / "swap.sh"
DROP_IN = REPO_ROOT / "system" / "rpi-swap" / "99-autostream-swap.conf"
APPLIANCE_INSTALLER = REPO_ROOT / "autostream_install.sh"
APPLIANCE_UNINSTALLER = REPO_ROOT / "autostream_uninstall.sh"
DEST = "/etc/rpi/swap.conf.d/99-autostream-swap.conf"

# dpkg that knows rpi-swap only when RPI_SWAP_INSTALLED is set.
FAKE_DPKG = r"""#!/bin/bash
echo "dpkg $*" >> "$TRACE"
[[ "$1" == "-s" && "$2" == "rpi-swap" && -n "${RPI_SWAP_INSTALLED:-}" ]] && exit 0
exit 1
"""


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.fake("dpkg", FAKE_DPKG)
    return e


def _install(env: Env, rpi: Path, src: Path = DROP_IN, **extra: str):
    return env.run(f'source "{SWAP_LIB.as_posix()}"\n'
                   f'install_swap_limit "{src.as_posix()}" "{rpi.as_posix()}"',
                   **extra)


def _settings(path: Path) -> dict[str, dict[str, str]]:
    """The sections and keys of an ini-style file, comments dropped."""
    out: dict[str, dict[str, str]] = {}
    section = None
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.fullmatch(r"\[(.+)\]", line)
        if m:
            section = m.group(1)
            out[section] = {}
        else:
            k, _, v = line.partition("=")
            out[section][k.strip()] = v.strip()
    return out


class TestDropInContent:
    def test_the_drop_in_sets_only_the_file_size_limit_to_512_mib(self):
        assert _settings(DROP_IN) == {"File": {"MaxSizeMiB": "512"}}

    def test_the_drop_in_says_why_and_when_it_takes_effect(self):
        text = DROP_IN.read_text(encoding="utf-8")
        assert "reboot" in text
        assert "2048" in text


@bash_capable
class TestInstallSwapLimit:
    def test_a_device_with_rpi_swap_gets_the_drop_in_with_the_source_content(self, env):
        rpi = env.root / "etc" / "rpi"
        rpi.mkdir(parents=True)
        (rpi / "swap.conf").write_text("[Main]\nMechanism=auto\n", encoding="utf-8")
        r = _install(env, rpi)
        assert r.returncode == 0, r.stderr
        dest = rpi / "swap.conf.d" / "99-autostream-swap.conf"
        assert dest.read_text(encoding="utf-8") == DROP_IN.read_text(encoding="utf-8")
        assert "takes effect at the next reboot" in r.stdout

    @pytest.mark.skipif(sys.platform == "win32", reason="file modes are meaningful on POSIX only")
    def test_the_drop_in_is_installed_with_mode_0644(self, env):
        rpi = env.root / "etc" / "rpi"
        rpi.mkdir(parents=True)
        (rpi / "swap.conf").write_text("x", encoding="utf-8")
        _install(env, rpi)
        assert ((rpi / "swap.conf.d" / "99-autostream-swap.conf").stat().st_mode & 0o777) == 0o644

    def test_the_package_alone_is_enough_when_its_config_file_is_not_there(self, env):
        rpi = env.root / "etc" / "rpi"
        r = _install(env, rpi, RPI_SWAP_INSTALLED="1")
        assert r.returncode == 0, r.stderr
        assert (rpi / "swap.conf.d" / "99-autostream-swap.conf").is_file()

    def test_a_device_without_rpi_swap_is_left_alone_and_etc_rpi_is_not_created(self, env):
        rpi = env.root / "etc" / "rpi"
        r = _install(env, rpi)
        assert r.returncode == 0, r.stderr
        assert not rpi.exists()
        assert "leaving the swap settings alone" in r.stdout

    def test_other_drop_ins_and_the_main_config_are_left_as_they_are(self, env):
        rpi = env.root / "etc" / "rpi"
        (rpi / "swap.conf.d").mkdir(parents=True)
        (rpi / "swap.conf").write_text("[Main]\nMechanism=auto\n", encoding="utf-8")
        (rpi / "swap.conf.d" / "90-zram-only.conf").write_text("[Main]\nMechanism=zram\n",
                                                               encoding="utf-8")
        _install(env, rpi)
        assert (rpi / "swap.conf").read_text(encoding="utf-8") == "[Main]\nMechanism=auto\n"
        assert (rpi / "swap.conf.d" / "90-zram-only.conf").read_text(encoding="utf-8") \
            == "[Main]\nMechanism=zram\n"

    def test_running_it_again_replaces_a_changed_drop_in_with_the_current_one(self, env):
        rpi = env.root / "etc" / "rpi"
        (rpi / "swap.conf.d").mkdir(parents=True)
        (rpi / "swap.conf").write_text("x", encoding="utf-8")
        dest = rpi / "swap.conf.d" / "99-autostream-swap.conf"
        dest.write_text("[File]\nMaxSizeMiB=2048\n", encoding="utf-8")
        _install(env, rpi)
        assert dest.read_text(encoding="utf-8") == DROP_IN.read_text(encoding="utf-8")

    def test_a_missing_source_file_warns_and_installs_nothing(self, env):
        rpi = env.root / "etc" / "rpi"
        rpi.mkdir(parents=True)
        (rpi / "swap.conf").write_text("x", encoding="utf-8")
        r = _install(env, rpi, src=env.tmp / "nope.conf")
        assert r.returncode == 0, r.stderr
        assert "was not installed" in r.stderr
        assert not (rpi / "swap.conf.d").exists()


@bash_capable
class TestWhereTheLimitIsUsed:
    def test_a_fresh_dial_install_installs_the_limit(self, tmp_path):
        from test_dial_installer_hd import _dry_run
        r, calls = _dry_run(tmp_path, update=False)
        assert r.returncode == 0, r.stderr
        want = f"install_swap_limit {tmp_path.as_posix()}/deploy/system/rpi-swap/99-autostream-swap.conf"
        assert [c for c in calls if c.startswith("install_swap_limit")] == [want]

    def test_a_dial_update_installs_the_limit(self, tmp_path):
        from test_dial_installer_hd import _dry_run
        r, calls = _dry_run(tmp_path, update=True)
        assert r.returncode == 0, r.stderr
        assert len([c for c in calls if c.startswith("install_swap_limit")]) == 1

    def test_the_dial_update_backup_covers_the_drop_in(self, env):
        r = env.run("owned_files_list")
        assert DEST in r.stdout.splitlines()

    def test_the_dial_uninstaller_removes_the_drop_in(self, env):
        from test_dial_installer_hardening import _uninstall_sandbox, _run_uninstaller
        script = _uninstall_sandbox(env)
        r = _run_uninstaller(env, script, "--yes")
        assert r.returncode == 0, r.stderr
        assert f"rm -f {DEST}" in env.calls()

    def test_dial_helpers_text_sources_the_shared_library(self):
        assert 'source "${BASH_SOURCE[0]%/*}/../lib/swap.sh"' in HELPERS.read_text(encoding="utf-8")

    def test_appliance_installer_text_sources_the_library_and_installs_the_drop_in(self):
        text = APPLIANCE_INSTALLER.read_text(encoding="utf-8")
        assert 'source "${INSTALLER_LIB}/swap.sh"' in text
        configure = text[text.index("configure_phase() {"):]
        assert 'install_swap_limit "${AUTOSTREAM_DIR}/system/rpi-swap/99-autostream-swap.conf"' in configure

    def test_appliance_uninstaller_text_removes_the_drop_in(self):
        assert f"remove_path {DEST}" in APPLIANCE_UNINSTALLER.read_text(encoding="utf-8")

    def test_both_installers_text_use_the_same_shipped_file(self):
        shipped = "system/rpi-swap/99-autostream-swap.conf"
        assert shipped in APPLIANCE_INSTALLER.read_text(encoding="utf-8")
        assert shipped in INSTALLER.read_text(encoding="utf-8")
