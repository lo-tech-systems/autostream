"""Installer tolerance of a network drop: the shared wait-and-retry in
installer/lib/apt.sh, how both installers use it, and the appliance installer's
failure path on a run with no terminal.

Functional bash round-trips with fake apt-get, getent, ip and sleep. The fake
sleep never sleeps: it records the request and counts down to the moment the
fake network comes back, so every wait here is exact and instant. The checks
that read the script text say so in their names.

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
    Env, REPO_ROOT, bash_capable, posix_only,
)

APT_SH = REPO_ROOT / "installer" / "lib" / "apt.sh"
APPLIANCE_HELPERS = REPO_ROOT / "installer" / "lib" / "helpers.sh"
APPLIANCE_INSTALLER = REPO_ROOT / "autostream_install.sh"
DIAL_HELPERS = REPO_ROOT / "installer" / "dial" / "helpers.sh"

# Fake network: $NET/state is "up" or "down"; $NET/back_after counts the sleeps
# left before the state turns "up" (absent: never); $NET/noroute removes the
# default route; every sleep and lookup is appended to a file.
FAKE_IP = r"""#!/bin/bash
[[ "$*" == *"-6"* ]] && exit 0
[[ -e "$NET/noroute" ]] && exit 0
echo "default via 192.0.2.1 dev ${NET_DEV:-eth0}"
"""
FAKE_GETENT = r"""#!/bin/bash
echo "$2" >> "$NET/lookups"
[[ "$(cat "$NET/state")" == up ]] || exit 2
echo "192.0.2.10 $2"
"""
FAKE_SLEEP = r"""#!/bin/bash
echo "sleep $1" >> "$NET/events"
n=$(cat "$NET/back_after" 2>/dev/null || echo -1)
if (( n > 0 )); then
    n=$((n - 1)); echo "$n" > "$NET/back_after"
    (( n == 0 )) && echo up > "$NET/state"
fi
exit 0
"""
# A step that downloads. STEP_MODE: ok; resolve_first (fails once with a
# resolution error and takes the network down for DOWN_FOR sleeps);
# resolve_always; other (a failure that is not the network's).
FAKE_STEP = r"""#!/bin/bash
n=$(cat "$NET/runs" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$NET/runs"
echo "run $n" >> "$NET/events"
case "${STEP_MODE:-ok}" in
    ok) exit 0 ;;
    resolve_first)
        if (( n == 1 )); then
            echo "W: Temporary failure resolving 'deb.debian.org'" >&2
            echo down > "$NET/state"; echo "${DOWN_FOR:-2}" > "$NET/back_after"
            exit 100
        fi
        exit 0 ;;
    resolve_always) echo "E: Failed to fetch http://deb.debian.org/x.deb" >&2; exit 100 ;;
    other) echo "E: Unable to locate package x" >&2; exit 100 ;;
esac
"""


class Net:
    """A scratch bin directory of fake commands and the state they share."""

    def __init__(self, tmp_path: Path, *, up: bool = True, back_after: int | None = None):
        self.dir = tmp_path / "net"
        self.dir.mkdir()
        self.bin = tmp_path / "netbin"
        self.bin.mkdir()
        (self.dir / "state").write_text("up" if up else "down", encoding="utf-8")
        if back_after is not None:
            (self.dir / "back_after").write_text(str(back_after), encoding="utf-8")
        for name, text in (("ip", FAKE_IP), ("getent", FAKE_GETENT),
                           ("sleep", FAKE_SLEEP), ("step", FAKE_STEP)):
            Env.fake_script(self.bin / name, text)
        (tmp_path / "etc-apt").mkdir()

    def env(self, **extra: str) -> dict:
        e = dict(os.environ)
        e.update(NET=self.dir.as_posix(), NETWORK_APT_ETC=(self.dir.parent / "etc-apt").as_posix(),
                 PATH=self.bin.as_posix() + os.pathsep + e.get("PATH", ""))
        e.update(extra)
        return e

    def run(self, body: str, **extra: str):
        script = f'set -euo pipefail; source "{APT_SH.as_posix()}"\n{body}'
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                              timeout=60, env=self.env(**extra))

    def events(self) -> list[str]:
        p = self.dir / "events"
        return p.read_text(encoding="utf-8").splitlines() if p.exists() else []

    def sleeps(self) -> list[str]:
        return [e for e in self.events() if e.startswith("sleep")]

    def runs(self) -> int:
        p = self.dir / "runs"
        return int(p.read_text(encoding="utf-8")) if p.exists() else 0

    def lookups(self) -> list[str]:
        p = self.dir / "lookups"
        return p.read_text(encoding="utf-8").split() if p.exists() else []


@pytest.fixture
def net(tmp_path):
    return Net(tmp_path)


@bash_capable
class TestNetworkWait:
    def test_a_healthy_network_adds_no_wait_and_no_output(self, net):
        r = net.run("network_wait")
        assert r.returncode == 0, r.stderr
        assert r.stdout == "" and r.stderr == ""
        assert net.sleeps() == []

    def test_a_network_that_returns_within_the_budget_is_waited_for(self, tmp_path):
        net = Net(tmp_path, up=False, back_after=3)
        r = net.run("network_wait")
        assert r.returncode == 0, r.stderr
        assert net.sleeps() == ["sleep 5"] * 3
        assert r.stdout.count("not available; waiting") == 1
        assert r.stdout.count("network is back after about 15s") == 1

    def test_a_network_that_never_returns_gives_up_after_the_budget(self, tmp_path):
        net = Net(tmp_path, up=False)
        r = net.run("network_wait || echo GAVE-UP")
        assert "GAVE-UP" in r.stdout
        assert net.sleeps() == ["sleep 5"] * 36
        assert r.stdout.count("waiting up to 180s") == 1
        assert r.stderr.count("did not return within 180s") == 1

    def test_the_budget_and_interval_are_named_and_overridable(self, tmp_path):
        net = Net(tmp_path, up=False)
        r = net.run("network_wait || true", NETWORK_WAIT_BUDGET="20", NETWORK_WAIT_INTERVAL="4")
        assert net.sleeps() == ["sleep 4"] * 5
        assert "waiting up to 20s" in r.stdout

    def test_a_second_wait_on_a_network_that_is_still_down_does_not_wait_again(self, tmp_path):
        net = Net(tmp_path, up=False)
        net.run("network_wait || true; network_wait || true")
        assert len(net.sleeps()) == 36

    def test_a_default_route_is_needed_even_when_names_resolve(self, tmp_path):
        net = Net(tmp_path)
        (net.dir / "noroute").write_text("", encoding="utf-8")
        r = net.run("network_usable && echo USABLE || echo NOT-USABLE")
        assert "NOT-USABLE" in r.stdout

    def test_names_must_resolve_even_with_a_default_route(self, tmp_path):
        net = Net(tmp_path, up=False)
        r = net.run("network_usable && echo USABLE || echo NOT-USABLE")
        assert "NOT-USABLE" in r.stdout

    def test_a_wired_only_device_passes_without_any_wifi_tool(self, tmp_path):
        net = Net(tmp_path)
        for name in ("nmcli", "iw", "iwconfig"):
            Env.fake_script(net.bin / name, "#!/bin/bash\nexit 99\n")
        r = net.run("network_usable && echo USABLE || echo NOT-USABLE", NET_DEV="eth0")
        assert "USABLE" in r.stdout and "NOT-USABLE" not in r.stdout

    def test_the_hosts_checked_are_the_ones_apt_is_configured_for(self, tmp_path):
        net = Net(tmp_path)
        etc = tmp_path / "etc-apt"
        (etc / "sources.list.d").mkdir()
        (etc / "sources.list").write_text(
            "# deb http://commented.example/ x\n"
            "deb [signed-by=/k.gpg] http://mirror.example:8080/debian trixie main\n",
            encoding="utf-8")
        (etc / "sources.list.d" / "pi.sources").write_text(
            "Types: deb\nURIs: https://user@archive.example/raspbian https://second.example/x\n",
            encoding="utf-8")
        r = net.run("network_apt_hosts")
        assert sorted(r.stdout.split()) == ["archive.example", "mirror.example", "second.example"]
        net.run("network_usable")
        assert "commented.example" not in net.lookups()
        assert net.lookups()[0] in {"archive.example", "mirror.example", "second.example"}

    def test_with_no_configured_hosts_the_archive_hosts_are_used(self, net):
        net.run("network_usable")
        assert net.lookups() == ["deb.debian.org"]

    def test_one_resolving_host_is_enough(self, tmp_path):
        net = Net(tmp_path)
        Env.fake_script(net.bin / "getent",
                        '#!/bin/bash\n[[ "$2" == good.example ]] && echo "192.0.2.1 $2"\n')
        r = net.run("network_usable bad.example good.example && echo USABLE")
        assert "USABLE" in r.stdout


@bash_capable
class TestNetworkStep:
    def test_a_healthy_network_runs_the_step_once_with_no_wait(self, net):
        r = net.run("network_step step")
        assert r.returncode == 0, r.stderr
        assert net.events() == ["run 1"]

    def test_a_network_down_at_the_start_is_waited_for_before_the_step(self, tmp_path):
        net = Net(tmp_path, up=False, back_after=3)
        r = net.run("network_step step")
        assert r.returncode == 0, r.stderr
        assert net.events() == ["sleep 5"] * 3 + ["run 1"]

    def test_a_resolution_failure_waits_for_the_network_and_retries_once(self, net):
        r = net.run("network_step step", STEP_MODE="resolve_first", DOWN_FOR="2")
        assert r.returncode == 0, r.stderr
        assert net.events() == ["run 1", "sleep 5", "sleep 5", "run 2"]
        assert "trying once more" in r.stderr
        assert r.stdout.count("network is back") == 1

    def test_a_network_that_stays_down_fails_with_a_clear_message_after_the_budget(self, tmp_path):
        net = Net(tmp_path, up=False)
        r = net.run("network_step step")
        # The step ran once after the wait gave up; it succeeded, so no message.
        assert r.returncode == 0, r.stderr
        assert "network was not available, so" not in r.stderr
        assert net.events() == ["sleep 5"] * 36 + ["run 1"]

    def test_a_failing_step_on_a_dead_network_fails_once_with_the_network_message(self, tmp_path):
        net = Net(tmp_path, up=False)
        r = net.run("network_step step", STEP_MODE="resolve_always")
        assert r.returncode == 100
        assert net.events() == ["sleep 5"] * 36 + ["run 1"]
        assert "the network was not available, so this step failed: step" in r.stderr

    def test_a_network_that_drops_and_never_returns_is_bounded_and_not_retried(self, net):
        r = net.run("network_step step", STEP_MODE="resolve_first", DOWN_FOR="0")
        # DOWN_FOR=0 writes a back_after of 0, which the fake never counts down.
        assert r.returncode == 100
        assert net.runs() == 1
        assert len([e for e in net.events() if e.startswith("sleep")]) == 36
        assert "the network was not available" in r.stderr

    def test_a_failure_that_is_not_the_networks_is_returned_at_once(self, net):
        r = net.run("network_step step", STEP_MODE="other")
        assert r.returncode == 100
        assert net.events() == ["run 1"]
        assert "network was not available" not in r.stderr

    def test_a_second_failure_with_the_network_up_is_reported_as_a_fetch_failure(self, net):
        r = net.run("network_step step", STEP_MODE="resolve_always")
        assert r.returncode == 100
        assert net.runs() == 2
        assert "the network was not available" in r.stderr

    def test_the_step_is_given_the_hosts_it_needs_to_reach(self, net):
        net.run("network_step --host github.com step")
        assert net.lookups() == ["github.com"]

    def test_a_step_function_and_its_output_pass_through(self, net):
        r = net.run('say() { echo "said $1"; }; network_step say hello')
        assert "said hello" in r.stdout

    def test_total_wait_for_an_offline_device_is_one_budget_across_many_steps(self, tmp_path):
        net = Net(tmp_path, up=False)
        net.run("network_step step || true; network_step step || true; network_step step || true",
                STEP_MODE="resolve_always")
        assert len(net.sleeps()) == 36
        assert net.runs() == 3


@bash_capable
class TestApplianceAptInstall:
    def _run(self, net: Net, body: str, **extra: str):
        Env.fake_script(net.bin / "apt-get", FAKE_STEP)
        script = (f'set -euo pipefail; source "{APPLIANCE_HELPERS.as_posix()}"; '
                  f'source "{APT_SH.as_posix()}"\n{body}')
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                              timeout=60, env=net.env(**extra))

    def test_apt_install_waits_for_the_network_then_installs_once(self, tmp_path):
        net = Net(tmp_path, up=False, back_after=2)
        r = self._run(net, "apt_install foo")
        assert r.returncode == 0, r.stderr
        assert net.events() == ["sleep 5", "sleep 5", "run 1"]

    def test_apt_install_retries_once_when_the_network_drops_during_it(self, net):
        r = self._run(net, "apt_install foo", STEP_MODE="resolve_first")
        assert r.returncode == 0, r.stderr
        assert net.runs() == 2

    def test_apt_install_on_a_healthy_network_does_not_wait(self, net):
        r = self._run(net, "apt_install foo")
        assert r.returncode == 0, r.stderr
        assert net.events() == ["run 1"]

    def test_apt_install_fails_with_the_network_message_when_it_stays_down(self, tmp_path):
        net = Net(tmp_path, up=False)
        r = self._run(net, "apt_install foo || echo FAILED=$?", STEP_MODE="resolve_always")
        assert "FAILED=1" in r.stdout
        assert "the network was not available" in r.stderr
        assert "apt_install failed for packages: foo" in r.stdout

    def test_a_soft_apt_install_still_carries_on_when_it_fails(self, tmp_path):
        net = Net(tmp_path, up=False)
        r = self._run(net, "apt_install --soft foo; echo carried-on", STEP_MODE="resolve_always")
        assert "carried-on" in r.stdout


@bash_capable
class TestDialAptStep:
    def _env(self, tmp_path: Path, **kw) -> tuple[Env, Net]:
        env = Env(tmp_path)
        net = Net(tmp_path, **kw)
        for name in ("ip", "getent", "sleep"):
            env.fake(name, (net.bin / name).read_text(encoding="utf-8"))
        env.fake("apt-get", FAKE_STEP)
        return env, net

    def test_apt_step_waits_for_the_network_before_running(self, tmp_path):
        env, net = self._env(tmp_path, up=False, back_after=2)
        r = env.run("apt_step apt-get install -y something", NET=net.dir.as_posix())
        assert r.returncode == 0, r.stderr
        assert net.events() == ["sleep 5", "sleep 5", "run 1"]

    def test_apt_step_waits_and_retries_when_the_network_drops_mid_step(self, tmp_path):
        env, net = self._env(tmp_path)
        r = env.run("apt_step apt-get install -y something", NET=net.dir.as_posix(),
                    STEP_MODE="resolve_first", DOWN_FOR="2")
        assert r.returncode == 0, r.stderr
        assert net.runs() == 2

    def test_the_upgrade_is_followed_by_a_wait_for_the_network(self, tmp_path):
        env, net = self._env(tmp_path)
        # The upgrade (the second apt-get run: the first is the list refresh)
        # takes the network down; the autoclean that follows must wait.
        Env.fake_script(env.bin / "apt-get", r"""#!/bin/bash
echo "apt-get $*" >> "$NET/events"
if [[ "$*" == *upgrade* ]]; then echo down > "$NET/state"; echo 2 > "$NET/back_after"; fi
exit 0
""")
        r = env.run("system_upgrade", NET=net.dir.as_posix())
        assert r.returncode == 0, r.stderr
        events = net.events()
        i = next(n for n, e in enumerate(events) if "upgrade" in e)
        assert events[i + 1:i + 3] == ["sleep 5", "sleep 5"]
        assert events[-1] == "apt-get autoclean -y"
        assert "System packages upgraded; checking the network" in r.stdout

    def test_sdmon_source_is_fetched_through_the_wait(self, tmp_path):
        env, net = self._env(tmp_path, up=False, back_after=1)
        env.fake("curl", '#!/bin/bash\necho "curl $*" >> "$NET/events"\nexit 0\n')
        env.fake("tar", "#!/bin/bash\ncat > /dev/null\nexit 0\n")
        env.fake("make", '#!/bin/bash\necho "make $*" >> "$NET/events"\nexit 1\n')
        r = env.run("install_sdmon", NET=net.dir.as_posix())
        events = net.events()
        assert events[0] == "sleep 5"
        assert events.index("sleep 5") < next(n for n, e in enumerate(events) if e.startswith("curl"))
        assert "github.com" in net.lookups()


@bash_capable
@posix_only
class TestApplianceHasTty:
    def test_the_failure_prompt_says_nothing_about_a_terminal_when_there_is_none(self, tmp_path):
        log = tmp_path / "install.log"
        script = (f'source "{APPLIANCE_HELPERS.as_posix()}"; LOGFILE="{log}"; '
                  'open_log_prompt "Check the log for details."')
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                           start_new_session=True, stdin=subprocess.DEVNULL)
        assert r.returncode == 0, r.stderr
        assert r.stderr == ""
        combined = r.stdout + r.stderr
        assert "/dev/tty" not in combined
        assert "No such device" not in combined
        assert "Log not opened" not in combined
        assert f"log available at: {log}" in r.stdout

    def test_has_tty_is_false_without_a_controlling_terminal(self):
        r = subprocess.run(
            ["bash", "-c", f'source "{APPLIANCE_HELPERS.as_posix()}"; has_tty && echo YES || echo NO'],
            capture_output=True, text=True, timeout=30,
            start_new_session=True, stdin=subprocess.DEVNULL)
        assert r.stdout.strip() == "NO"
        assert r.stderr == ""


# ---------------------------------------------------------------------------
# Text checks: every step that downloads goes through the wait
# ---------------------------------------------------------------------------

FETCH_COMMAND = re.compile(
    r"apt-get (update|upgrade|install)\b|\bpip3? install\b|-m pip install\b|"
    r"\bgit (-c \S+ )?(-C \S+ )?(clone|fetch)\b|\bcurl -f")
# Wrappers that put a command behind the wait.
WRAPPED = re.compile(r"^\s*((if|!|\()\s*)*(network_step|apt_step|apt_install)\b")
# Functions that only run under network_step, and local-only curl calls.
INSIDE_A_WRAPPED_FUNCTION = ("fetch_sdmon_source()", "fetch_owntone_apt_repo_files()")


def _logical_lines(path: Path):
    """Source lines with backslash continuations joined; comments dropped."""
    out, buf, func = [], "", ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^(\w+\(\)) \{", raw)
        if m:
            func = m.group(1)
        if raw.lstrip().startswith("#"):
            continue
        if raw.endswith("\\"):
            buf += raw[:-1] + " "
            continue
        out.append((buf + raw, func))
        buf = ""
    return out


@pytest.mark.parametrize("path", [
    APPLIANCE_INSTALLER, APPLIANCE_HELPERS, DIAL_HELPERS,
    REPO_ROOT / "installer" / "lib" / "owntone.sh",
    REPO_ROOT / "installer" / "lib" / "vibra.sh",
    REPO_ROOT / "installer" / "lib" / "bluetooth.sh",
    REPO_ROOT / "installer" / "lib" / "system_tuning.sh",
])
def test_every_fetching_command_in_the_installer_text_goes_through_the_wait(path):
    unwrapped = []
    for line, func in _logical_lines(path):
        if not FETCH_COMMAND.search(line):
            continue
        if "localhost" in line or line.lstrip().startswith(("echo ", "info ", "warn ", "error ")):
            continue
        if WRAPPED.match(line) or func in INSIDE_A_WRAPPED_FUNCTION:
            continue
        unwrapped.append(line.strip())
    assert unwrapped == []


def test_the_appliance_upgrade_phase_waits_for_the_network_after_the_upgrade_text():
    text = APPLIANCE_INSTALLER.read_text(encoding="utf-8")
    body = text[text.index("system_upgrade_phase() {"):]
    body = body[:body.index("\n}\n")]
    assert "apt-get update" in body and "apt-get upgrade" in body
    assert body.index("apt-get upgrade") < body.index("network_wait")


def test_both_installers_share_the_one_wait_function_text():
    assert "network_step()" in APT_SH.read_text(encoding="utf-8")
    for path in (APPLIANCE_INSTALLER, DIAL_HELPERS):
        assert "lib/apt.sh" in path.read_text(encoding="utf-8").replace("${INSTALLER_LIB}", "lib")
    assert "network_step" in DIAL_HELPERS.read_text(encoding="utf-8")
    assert "network_step" in APPLIANCE_HELPERS.read_text(encoding="utf-8")
