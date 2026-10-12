"""The NetworkManager dispatcher script that turns Wi-Fi power saving off and
sets the transmit power, and the packages it needs.

The script calls `iw` for both settings, so both installers must put `iw` on the
device: if it is missing the script only logs that the setting is "not
supported" and the setting never applies. The script is run here against a
scratch /sys/class/net, by pointing a copy of the script at it, with recorders
for `iw` and `logger`.

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
from test_dial_staged_install import (  # noqa: E402
    Env, RECORDER, REPO_ROOT, bash_capable, posix_only,
)

SCRIPT = REPO_ROOT / "system" / "NetworkManager" / "99-wlan-fix"
APPLIANCE_INSTALLER = REPO_ROOT / "autostream_install.sh"
DIAL_INSTALLER = REPO_ROOT / "autostream_dial_install.sh"
DIAL_HELPERS = REPO_ROOT / "installer" / "dial" / "helpers.sh"


def _function(path: Path, name: str) -> str:
    text = path.read_text(encoding="utf-8")
    start = text.index(f"{name}() {{")
    return text[start: text.index("\n}\n", start) + 3]


class TestPackagesCarryTheTool:
    def test_the_script_uses_iw_alone(self):
        text = SCRIPT.read_text(encoding="utf-8")
        assert "iwconfig" not in text
        assert re.search(r"^\s*iw dev \"\$IFACE\" set txpower fixed 1200", text, re.M)
        assert re.search(r"^iw \"\$IFACE\" set power_save off", text, re.M)

    def test_no_installer_asks_for_the_deprecated_wireless_tools(self):
        for path in (APPLIANCE_INSTALLER, DIAL_INSTALLER, DIAL_HELPERS):
            assert "wireless-tools" not in path.read_text(encoding="utf-8"), path.name

    def test_the_appliance_package_step_that_runs_on_install_and_update_has_iw(self):
        body = _function(APPLIANCE_INSTALLER, "ensure_build_deps")
        assert re.search(r"apt_install [^\n]*(\\\n[^\n]*)*\biw\b", body)
        text = APPLIANCE_INSTALLER.read_text(encoding="utf-8")
        # ensure_build_deps is called from both the first-time and the update phase.
        assert text.count("ensure_build_deps") >= 3

    @bash_capable
    @posix_only
    def test_the_appliance_step_asks_apt_for_iw(self, tmp_path):
        body = _function(APPLIANCE_INSTALLER, "ensure_build_deps")
        script = f'apt_install() {{ echo "apt_install $*"; }}\n{body}\nensure_build_deps\n'
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
        assert "iw" in r.stdout.split()

    @bash_capable
    @posix_only
    @pytest.mark.parametrize("hd", ["true", "false"])
    def test_the_dial_installs_iw_for_both_device_types(self, tmp_path, hd):
        env = Env(tmp_path)
        env.fake("apt-get", RECORDER)
        env.fake("usermod", RECORDER)
        r = env.run(f"HD={hd}\ninstall_recovery_packages", update="false")
        assert r.returncode == 0, r.stderr
        installs = [c for c in env.calls() if c.startswith("apt-get install")]
        assert installs and any(" iw" in c and "--no-install-recommends" in c for c in installs)

    def test_the_dial_package_step_is_not_inside_the_hd_or_the_fresh_install_branch(self):
        text = DIAL_INSTALLER.read_text(encoding="utf-8")
        line = [ln for ln in text.splitlines() if ln.startswith("install_recovery_packages")]
        assert line, "install_recovery_packages must be called at the top level"


@bash_capable
@posix_only
class TestDispatcherScript:
    def _world(self, tmp_path: Path, *, wireless: bool = True, usb: bool = False,
               iw_fails: bool = False):
        net = tmp_path / "net"
        (net / "wlan0").mkdir(parents=True)
        if wireless:
            (net / "wlan0" / "wireless").mkdir()
        bus = tmp_path / ("usb1" if usb else "mmc0") / "dev"
        bus.mkdir(parents=True)
        (net / "wlan0" / "device").symlink_to(bus)
        shims = tmp_path / "shims"
        shims.mkdir()
        trace = tmp_path / "trace.log"
        trace.touch()
        for name, rc in (("iw", 1 if iw_fails else 0), ("logger", 0)):
            f = shims / name
            f.write_text(f'#!/bin/bash\necho "{name} $*" >> "{trace.as_posix()}"\nexit {rc}\n',
                         encoding="utf-8")
            f.chmod(0o755)
        return net, shims, trace

    @staticmethod
    def _copy_for(net: Path, text: str | None = None) -> Path:
        """A copy of the script that looks in NET instead of /sys/class/net."""
        text = SCRIPT.read_text(encoding="utf-8") if text is None else text
        copy = net.parent / "wlan-fix"
        copy.write_text(text.replace("/sys/class/net", str(net)), encoding="utf-8")
        return copy

    def _run(self, net, shims, *args):
        env = {"PATH": f"{shims}{os.pathsep}/usr/bin:/bin"}
        return subprocess.run(["bash", str(self._copy_for(net)), *args], capture_output=True,
                              text=True, timeout=30, env=env)

    def _calls(self, trace: Path) -> list[str]:
        return trace.read_text(encoding="utf-8").splitlines()

    def test_the_built_in_radio_gets_power_save_off_and_twelve_dbm(self, tmp_path):
        net, shims, trace = self._world(tmp_path)
        r = self._run(net, shims, "wlan0", "up")
        assert r.returncode == 0, r.stderr
        calls = self._calls(trace)
        assert "iw wlan0 set power_save off" in calls
        assert "iw dev wlan0 set txpower fixed 1200" in calls

    def test_a_usb_adapter_gets_power_save_off_but_no_transmit_power(self, tmp_path):
        net, shims, trace = self._world(tmp_path, usb=True)
        r = self._run(net, shims, "wlan0", "up")
        assert r.returncode == 0, r.stderr
        calls = self._calls(trace)
        assert "iw wlan0 set power_save off" in calls
        assert not [c for c in calls if "txpower" in c and c.startswith("iw")]

    def test_a_step_that_is_not_supported_is_logged_and_the_script_still_succeeds(self, tmp_path):
        net, shims, trace = self._world(tmp_path, iw_fails=True)
        r = self._run(net, shims, "wlan0", "up")
        assert r.returncode == 0, r.stderr
        logged = [c for c in self._calls(trace) if c.startswith("logger") and "ignored" in c]
        assert any("power_save off not supported" in c for c in logged)
        assert any("txpower set not supported" in c for c in logged)

    def test_the_script_reads_nothing_from_its_environment_to_find_the_interfaces(self):
        text = SCRIPT.read_text(encoding="utf-8")
        assert "NET_SYSFS" not in text
        assert "/sys/class/net/${IFACE}/wireless" in text

    def test_an_environment_variable_cannot_redirect_where_it_looks(self, tmp_path):
        net, shims, trace = self._world(tmp_path, wireless=False)
        other = tmp_path / "other"
        (other / "wlan0" / "wireless").mkdir(parents=True)
        env = {"PATH": f"{shims}{os.pathsep}/usr/bin:/bin", "NET_SYSFS": str(other)}
        r = subprocess.run(["bash", str(self._copy_for(net)), "wlan0", "up"],
                           capture_output=True, text=True, timeout=30, env=env)
        assert r.returncode == 0, r.stderr
        assert self._calls(trace) == []

    def test_an_interface_going_down_is_left_alone(self, tmp_path):
        net, shims, trace = self._world(tmp_path)
        assert self._run(net, shims, "wlan0", "down").returncode == 0
        assert self._calls(trace) == []

    def test_an_interface_that_is_not_wireless_is_left_alone(self, tmp_path):
        net, shims, trace = self._world(tmp_path, wireless=False)
        assert self._run(net, shims, "wlan0", "up").returncode == 0
        assert self._calls(trace) == []

    def test_the_system_directories_are_on_the_path_when_the_caller_gave_none(self, tmp_path):
        net, shims, trace = self._world(tmp_path)
        text = SCRIPT.read_text(encoding="utf-8")
        assert re.search(r'^PATH="[^"]*/usr/sbin[^"]*"', text, re.M)
        # A bare environment still finds a command that is only in /usr/sbin.
        sbin = tmp_path / "sbin"
        sbin.mkdir()
        probe = sbin / "iw"
        probe.write_text(f'#!/bin/bash\necho "found $*" >> "{trace.as_posix()}"\n',
                         encoding="utf-8")
        probe.chmod(0o755)
        patched = self._copy_for(net, text.replace("/usr/local/sbin", str(sbin), 1))
        env = {"PATH": ""}
        r = subprocess.run(["/bin/bash", str(patched), "wlan0", "up"], capture_output=True,
                           text=True, timeout=30, env=env)
        assert r.returncode == 0, r.stderr
        assert any(c.startswith("found") for c in self._calls(trace))
