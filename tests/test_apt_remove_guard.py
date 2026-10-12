"""Removing a package asks apt what else would go, and refuses if it is more.

A package can have a dependant nobody expected, and an operating system update
can add one. Every removal the installers and uninstallers make goes through
apt_remove_guarded (installer/lib/apt.sh), which runs a simulation first and
removes nothing when it lists a package that was not named, or cannot be run.
The splash uninstall also never purges the initramfs tooling, whatever its
state file says.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_dial_installer_plymouth_revert import _installed_env, _revert  # noqa: E402
from test_dial_staged_install import Env, REPO_ROOT, bash_capable  # noqa: E402

APT_LIB = REPO_ROOT / "installer" / "lib" / "apt.sh"
TUNING_LIB = REPO_ROOT / "installer" / "lib" / "system_tuning.sh"

# An apt-get that records every call. A simulation (-s) prints SIM_LINES, one
# per line, and exits SIM_RC; a real call exits 0.
FAKE_APT = r"""#!/bin/bash
echo "apt-get $*" >> "$TRACE"
if [[ "$1" == "-s" ]]; then
    [[ -z "${SIM_LINES:-}" ]] || printf '%b\n' "${SIM_LINES}"
    exit "${SIM_RC:-0}"
fi
exit 0
"""

FAKE_DPKG = r"""#!/bin/bash
for p in ${PRESENT:-}; do [[ "$p" == "$2" ]] && exit 0; done
exit 1
"""

SHIM = 'info() { echo "INFO: $*"; }; warn() { echo "WARN: $*" >&2; }\n'


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.fake("apt-get", FAKE_APT)
    e.fake("dpkg", FAKE_DPKG)
    return e


def _guard(env: Env, body: str, **extra: str):
    return env.run(f'{SHIM}source "{APT_LIB.as_posix()}"\n{body}', **extra)


def _real_calls(env: Env) -> list[str]:
    return [c for c in env.calls() if c.startswith("apt-get") and not c.startswith("apt-get -s")]


@bash_capable
class TestTheGuard:
    def test_a_clean_simulation_removes_exactly_the_named_packages(self, env):
        r = _guard(env, "apt_remove_guarded remove alpha beta",
                   SIM_LINES="Remv alpha [1.0]\\nRemv beta [2.0]")
        assert r.returncode == 0, r.stderr
        assert _real_calls(env) == ["apt-get remove -y alpha beta"]
        assert env.calls()[0].startswith("apt-get -s remove")

    def test_a_simulation_that_lists_another_package_removes_nothing(self, env):
        r = _guard(env, "apt_remove_guarded remove alpha || echo rc=$?",
                   SIM_LINES="Remv alpha [1.0]\\nRemv gamma [3.0]")
        assert "rc=1" in r.stdout
        assert _real_calls(env) == []
        assert "gamma" in r.stderr

    def test_a_purge_simulation_is_read_the_same_way(self, env):
        r = _guard(env, "apt_remove_guarded purge alpha || echo rc=$?",
                   SIM_LINES="Purg alpha [1.0]\\nPurg linux-image-rpi-v8 [6.1]")
        assert "rc=1" in r.stdout
        assert _real_calls(env) == []

    def test_an_architecture_suffix_is_not_another_package(self, env):
        r = _guard(env, "apt_remove_guarded remove alpha",
                   SIM_LINES="Remv alpha:armhf [1.0]")
        assert r.returncode == 0, r.stderr
        assert _real_calls(env) == ["apt-get remove -y alpha"]

    def test_a_simulation_that_cannot_run_removes_nothing(self, env):
        r = _guard(env, "apt_remove_guarded remove alpha || echo rc=$?", SIM_RC="100")
        assert "rc=1" in r.stdout
        assert _real_calls(env) == []

    def test_nothing_named_does_nothing(self, env):
        r = _guard(env, "apt_remove_guarded remove")
        assert r.returncode == 0
        assert env.calls() == []

    def test_a_refusal_does_not_stop_a_script_with_errexit_that_handles_it(self, env):
        r = _guard(env, "set -e\napt_remove_guarded remove alpha || echo refused\necho after",
                   SIM_LINES="Remv alpha [1.0]\\nRemv gamma [3.0]")
        assert "refused" in r.stdout and "after" in r.stdout


@bash_capable
class TestEveryRemovalUsesIt:
    def test_the_unneeded_packages_are_removed_only_when_the_simulation_is_clean(self, env):
        r = _guard(env, f'source "{TUNING_LIB.as_posix()}"\nremove_unneeded_packages',
                   PRESENT="modemmanager udisks2")
        assert r.returncode == 0, r.stderr
        assert _real_calls(env) == ["apt-get remove -y modemmanager",
                                    "apt-get remove -y udisks2"]

    def test_an_unexpected_dependant_keeps_the_package_and_the_run_goes_on(self, env):
        r = _guard(env, f'source "{TUNING_LIB.as_posix()}"\nset -e\nremove_unneeded_packages\n'
                        'echo finished',
                   PRESENT="modemmanager udisks2",
                   SIM_LINES="Remv modemmanager [1.0]\\nRemv udisks2 [2.0]\\nRemv something-else [1]")
        assert r.returncode == 0, r.stderr
        assert "finished" in r.stdout
        assert _real_calls(env) == []
        assert "something-else" in r.stderr

    @pytest.mark.parametrize("path", [
        "autostream_install.sh", "autostream_dial_install.sh", "autostream_uninstall.sh",
        "autostream_dial_uninstall.sh", "installer/dial/helpers.sh",
        "installer/lib/owntone.sh", "installer/lib/system_tuning.sh",
        "installer/lib/vibra.sh", "installer/lib/helpers.sh",
        "installer/lib/bluetooth.sh", "installer/lib/hardware.sh",
    ])
    def test_no_script_runs_apt_get_remove_or_purge_directly(self, path):
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        for line in text.splitlines():
            code = line.split("#", 1)[0]
            if re.search(r"\b(warn|echo|info|error)\b", code):
                continue          # a message, not a command
            assert not any(f"apt-get {verb}" in code or f"apt {verb}" in code
                           for verb in ("remove", "purge", "autoremove")), line

    def test_the_apt_library_is_the_only_place_that_removes(self):
        text = APT_LIB.read_text(encoding="utf-8")
        assert 'apt-get "${action}" -y "$@"' in text


def _plant(env, packages: str) -> None:
    env.plystate.write_text(f"packages_installed={packages}\n", encoding="utf-8")
    env.trace.write_text("", encoding="utf-8")


@bash_capable
class TestTheSplashUninstall:
    @pytest.mark.parametrize("planted", [
        "initramfs-tools",
        "initramfs-tools plymouth plymouth-themes",
        "plymouth initramfs-tools",
    ])
    def test_the_initramfs_tooling_is_never_purged_whatever_the_state_file_says(
            self, tmp_path, planted):
        env, _ = _installed_env(tmp_path)
        env.fake("apt-get", FAKE_APT)
        _plant(env, planted)
        r = _revert(env)
        assert r.returncode == 0, r.stderr
        assert not [c for c in env.calls() if "initramfs-tools" in c and "purge" in c]
        assert not [c for c in env.calls() if "initramfs-tools" in c and c.startswith("apt-get")]

    def test_the_other_recorded_packages_are_purged_when_the_simulation_is_clean(
            self, tmp_path):
        env, _ = _installed_env(tmp_path)
        env.fake("apt-get", FAKE_APT)
        _plant(env, "initramfs-tools plymouth plymouth-themes")
        r = env.run("revert_plymouth", update="false",
                    SIM_LINES="Purg plymouth [1]\\nPurg plymouth-themes [1]")
        assert r.returncode == 0, r.stderr
        assert "apt-get purge -y plymouth plymouth-themes" in env.calls()

    def test_nothing_is_purged_when_the_simulation_lists_anything_else(self, tmp_path):
        env, _ = _installed_env(tmp_path)
        env.fake("apt-get", FAKE_APT)
        _plant(env, "plymouth plymouth-themes")
        r = env.run("revert_plymouth", update="false",
                    SIM_LINES="Purg plymouth [1]\\nPurg plymouth-themes [1]\\nPurg raspberrypi-ui-mods [1]")
        assert r.returncode == 0, r.stderr
        assert not [c for c in env.calls() if c.startswith("apt-get purge")]
        assert "raspberrypi-ui-mods" in r.stderr
        # The rest of the revert still happened.
        assert not env.plystate.exists()
        assert not env.theme_dir.exists()

    def test_a_package_the_installer_never_records_is_not_purged(self, tmp_path):
        env, _ = _installed_env(tmp_path)
        env.fake("apt-get", FAKE_APT)
        _plant(env, "plymouth openssh-server")
        env.run("revert_plymouth", update="false", SIM_LINES="Purg plymouth [1]")
        assert not [c for c in env.calls() if "openssh" in c]


@bash_capable
class TestTheUninstallers:
    def test_the_appliance_uninstaller_asks_before_removing_the_packaged_owntone(self, tmp_path):
        body = (REPO_ROOT / "autostream_uninstall.sh").read_text(encoding="utf-8")
        start = body.index("apt_remove_owntone() {")
        func = body[start:body.index("\n}\n", start) + 3]
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        for name, text in (("apt-get", FAKE_APT),):
            (bin_dir / name).write_text(text, encoding="utf-8")
            (bin_dir / name).chmod(0o755)
        trace = tmp_path / "trace"
        trace.touch()
        script = (f'set -euo pipefail\ninfo() {{ :; }}; warn() {{ echo "WARN: $*"; }}\n'
                  f'source "{APT_LIB.as_posix()}"\n{func}\napt_remove_owntone\n')
        e = dict(os.environ, TRACE=trace.as_posix(),
                 PATH=bin_dir.as_posix() + os.pathsep + os.environ["PATH"],
                 SIM_LINES="Remv owntone [1]\\nRemv owntone-extras [1]")
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=e,
                           timeout=30)
        assert r.returncode == 0, r.stderr
        calls = trace.read_text(encoding="utf-8").splitlines()
        assert calls and not [c for c in calls if c.startswith("apt-get remove")]
