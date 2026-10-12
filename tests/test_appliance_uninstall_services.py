"""The appliance uninstaller stops and removes the track identification daemon
and the service account.

vibra-mini.service was left running and enabled, and the autostream account
left behind, after an uninstall. The daemon's binary, version stamp and log live
under the directories the uninstaller already removes; its unit file and socket
did not, and nothing stopped it. The account is removed the way the dial
uninstaller removes its own, tolerating one that is missing or still in use.

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
from test_dial_staged_install import Env, REPO_ROOT, bash_capable  # noqa: E402

UNINSTALLER = REPO_ROOT / "autostream_uninstall.sh"
DOC = REPO_ROOT / "docs" / "UNINSTALL.md"


def _function(name: str) -> str:
    m = re.search(r"^" + re.escape(name) + r"\(\) \{.*?\n\}\n", UNINSTALLER.read_text(encoding="utf-8"),
                  re.S | re.M)
    assert m is not None, name
    return m.group(0)


def _main_calls(tmp_path: Path) -> list[str]:
    """Run the real main() with every action replaced by a recorder."""
    trace = tmp_path / "trace"
    trace.write_text("", encoding="utf-8")
    t = trace.as_posix()
    stubs = "\n".join(
        f'{name}() {{ echo "{name} $*" >> "{t}"; }}'
        for name in ("require_sudo", "prompt_continue", "stop_and_disable_service", "restore_wifi_profiles",
                     "revert_low_power_if_used", "remove_bluetooth_if_enabled", "remove_path",
                     "apt_remove_owntone", "remove_service_account", "prompt_reboot", "info", "warn"))
    script = f'''
set -u
{stubs}
systemctl() {{ echo "systemctl $*" >> "{t}"; }}
{_function("main")}
main
'''
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return [c for c in trace.read_text(encoding="utf-8").splitlines() if not c.startswith(("info", "warn"))]


@bash_capable
class TestMain:
    def test_the_daemon_is_stopped_and_disabled_with_the_other_services(self, tmp_path):
        calls = _main_calls(tmp_path)
        stop = calls.index("stop_and_disable_service vibra-mini.service")
        assert calls.index("stop_and_disable_service autostream_monitor.service") < stop
        assert stop < calls.index("remove_path /opt/autostream")

    def test_its_unit_file_and_socket_are_removed(self, tmp_path):
        calls = _main_calls(tmp_path)
        assert "remove_path /etc/systemd/system/vibra-mini.service" in calls
        assert "remove_path /tmp/vibra-mini.sock" in calls

    def test_the_account_goes_after_everything_it_owned_and_before_the_manager_is_reloaded(self, tmp_path):
        calls = _main_calls(tmp_path)
        account = calls.index("remove_service_account autostream")
        for owned in ("/opt/autostream", "/var/lib/autostream", "/var/log/autostream", "/etc/autostream"):
            assert calls.index(f"remove_path {owned}") < account, owned
        assert calls.index("remove_path /etc/systemd/system/vibra-mini.service") < account
        assert account < calls.index("systemctl daemon-reload")

    def test_the_binary_stamp_and_log_are_under_directories_that_are_removed(self):
        vibra = (REPO_ROOT / "installer" / "lib" / "vibra.sh").read_text(encoding="utf-8")
        assert 'VIBRA_INSTALL_PREFIX="/opt/autostream/vibra"' in vibra
        assert 'VIBRA_VERSION_STAMP="/var/lib/autostream/vibra-mini-version"' in vibra
        unit = (REPO_ROOT / "system" / "systemd" / "vibra-mini.service").read_text(encoding="utf-8")
        assert "/var/log/autostream/vibra-mini.log" in unit


def _run_with_fakes(tmp_path: Path, body: str, *, passwd: bool = True, group: bool = True,
                    userdel_rc: int = 0, list_units: bool = True):
    env = Env(tmp_path)
    env.fake("getent", '#!/bin/bash\necho "getent $*" >> "$TRACE"\n'
                       '[[ "$1" == passwd ]] && exit "$((${HAVE_PASSWD:-1} == 1 ? 0 : 2))"\n'
                       '[[ "$1" == group ]] && exit "$((${HAVE_GROUP:-1} == 1 ? 0 : 2))"\nexit 2\n')
    env.fake("userdel", f'#!/bin/bash\necho "userdel $*" >> "$TRACE"\nexit {userdel_rc}\n')
    env.fake("groupdel", '#!/bin/bash\necho "groupdel $*" >> "$TRACE"\n')
    env.fake("systemctl", '#!/bin/bash\necho "systemctl $*" >> "$TRACE"\n'
                          '[[ "$1" == list-unit-files ]] && exit "${LIST_RC:-0}"\nexit 0\n')
    script = (f'set -u\ninfo() {{ echo "INFO: $*"; }}\nwarn() {{ echo "WARN: $*"; }}\n'
              f'{_function("stop_and_disable_service")}\n{_function("remove_service_account")}\n{body}')
    e = env.env(HAVE_PASSWD="1" if passwd else "0", HAVE_GROUP="1" if group else "0",
                LIST_RC="0" if list_units else "1")
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30, env=e)
    return r, env.calls()


@bash_capable
class TestRemoveServiceAccount:
    def test_the_account_and_its_group_are_removed(self, tmp_path):
        r, calls = _run_with_fakes(tmp_path, "remove_service_account autostream")
        assert r.returncode == 0, r.stderr
        assert "userdel autostream" in calls and "groupdel autostream" in calls

    def test_an_account_that_is_missing_is_skipped(self, tmp_path):
        r, calls = _run_with_fakes(tmp_path, "remove_service_account autostream", passwd=False)
        assert r.returncode == 0
        assert "not present; skipping" in r.stdout
        assert not [c for c in calls if c.startswith(("userdel", "groupdel"))]

    def test_an_account_still_in_use_stays_and_the_owner_is_told_what_to_run(self, tmp_path):
        r, calls = _run_with_fakes(tmp_path, "remove_service_account autostream\necho AFTER", userdel_rc=8)
        assert "AFTER" in r.stdout
        assert "WARN: Could not remove the autostream account (userdel exit 8)" in r.stdout
        assert "userdel autostream" in r.stdout          # the command to run, in the message
        assert "groupdel autostream" not in calls

    def test_a_group_that_is_already_gone_is_not_an_error(self, tmp_path):
        r, calls = _run_with_fakes(tmp_path, "remove_service_account autostream", group=False)
        assert r.returncode == 0
        assert "groupdel autostream" not in calls


@bash_capable
class TestDaemonNotInstalled:
    def test_stopping_a_daemon_that_is_not_installed_is_quiet_and_not_an_error(self, tmp_path):
        r, calls = _run_with_fakes(tmp_path, "stop_and_disable_service vibra-mini.service\necho AFTER",
                                   list_units=False)
        assert "AFTER" in r.stdout
        assert "not present; skipping" in r.stdout
        assert "WARN" not in r.stdout
        assert "systemctl stop vibra-mini.service" not in calls

    def test_an_installed_daemon_is_stopped_then_disabled(self, tmp_path):
        r, calls = _run_with_fakes(tmp_path, "stop_and_disable_service vibra-mini.service")
        assert calls.index("systemctl stop vibra-mini.service") < \
            calls.index("systemctl disable vibra-mini.service")


class TestDocs:
    def test_the_guide_names_the_daemon_and_the_account(self):
        text = DOC.read_text(encoding="utf-8")
        assert "`vibra-mini.service`" in text
        assert "`autostream` service account" in text

    def test_the_guide_lists_what_is_left_deliberately(self):
        text = DOC.read_text(encoding="utf-8")
        tail = text[text.index("deliberately not reversed"):]
        for left in ("90-autostream-swappiness.conf", "rpi-zram-writeback.timer", "cloud-init.disabled",
                     "modemmanager"):
            assert left in tail, left
