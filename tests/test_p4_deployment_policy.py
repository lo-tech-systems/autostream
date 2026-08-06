"""P4 — Deployment policy and service graph.

What runs here (offline, no root, no Linux required):
  - Parse all systemd unit files and verify required sections, ExecStart
    paths, ordering/dependency relationships, and user policy.
  - Parse nginx configs and verify every SCRIPT_FILENAME reference points
    to a CGI script that exists in the repo.
  - Parse sudoers fragments and verify permitted/denied command matrices
    for autostream and www-data; no wildcard on destructive verbs.
  - Verify CGI-to-sudoers permission matrix: each CGI that invokes sudo
    calls a verb that is explicitly listed in the sudoers fragment.
  - Parse Avahi XML, dnsmasq, logrotate, watchdog, and NetworkManager
    config files for required directives and security properties.

Environment-dependent (Linux CI only):
  - systemd-analyze verify — requires systemd on PATH
  - nginx -t — requires nginx on PATH
  - visudo -cf — requires visudo on PATH
  CI mechanism: ubuntu-latest GitHub Actions runner.
"""
from __future__ import annotations

import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).parent.parent
SYSTEMD_DIR = REPO_ROOT / "system" / "systemd"
NGINX_DIR = REPO_ROOT / "system" / "nginx"
SUDOERS_DIR = REPO_ROOT / "system" / "sudoers"
CGI_DIR = REPO_ROOT / "nginx" / "cgi"
AVAHI_DIR = REPO_ROOT / "system" / "avahi"
DNSMASQ_DIR = REPO_ROOT / "system" / "dnsmasq"
LOGROTATE_DIR = REPO_ROOT / "system" / "logrotate"
WATCHDOG_DIR = REPO_ROOT / "system" / "watchdog"
NM_DIR = REPO_ROOT / "system" / "NetworkManager"
INSTALL_SH = REPO_ROOT / "autostream_install.sh"


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _join_continuations(text: str) -> str:
    """Join backslash-continuation lines in shell/systemd config."""
    lines: list[str] = []
    acc = ""
    for line in text.splitlines():
        if acc:
            line = acc + " " + line.strip()
            acc = ""
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            acc = stripped[:-1].rstrip()
        else:
            lines.append(line)
    if acc:
        lines.append(acc)
    return "\n".join(lines)


def _unit_section(path: Path, section: str) -> dict[str, list[str]]:
    """Return all key→[values] pairs from *section* of a systemd unit file."""
    text = _join_continuations(path.read_text(encoding="utf-8"))
    in_sec = False
    result: dict[str, list[str]] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_sec = stripped == f"[{section}]"
            continue
        if not in_sec or not stripped or stripped.startswith("#"):
            continue
        if "=" in stripped:
            k, _, v = stripped.partition("=")
            result.setdefault(k.strip(), []).append(v.strip())
    return result


def _unit_field(path: Path, section: str, key: str) -> str:
    """Return the first value of *key* in *section*, or '' if absent."""
    vals = _unit_section(path, section).get(key, [])
    return vals[0] if vals else ""


def _unit_has_section(path: Path, section: str) -> bool:
    text = path.read_text(encoding="utf-8")
    return re.search(rf"^\[{re.escape(section)}\]", text, re.MULTILINE) is not None


def _nginx_cgi_scripts(conf_path: Path) -> list[str]:
    """Return all SCRIPT_FILENAME paths from an nginx config."""
    text = conf_path.read_text(encoding="utf-8")
    return re.findall(r"fastcgi_param\s+SCRIPT_FILENAME\s+(\S+);", text)


def _sudoers_lines_for_user(path: Path, user: str) -> list[str]:
    """Return non-comment lines that grant permissions to *user*."""
    return [
        ln.strip()
        for ln in path.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
        and re.match(rf"^{re.escape(user)}\s", ln.strip())
    ]


def _sudoers_cmnd_alias(path: Path, alias_name: str) -> str:
    """Resolve a Cmnd_Alias value by name; return '' if not found."""
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(
            rf"^\s*Cmnd_Alias\s+{re.escape(alias_name)}\s*=\s*(.+)$", line.strip()
        )
        if m:
            return m.group(1).strip()
    return ""


# ---------------------------------------------------------------------------
# Fixtures — list of all .service unit files
# ---------------------------------------------------------------------------

ALL_UNITS = sorted(SYSTEMD_DIR.glob("*.service"))
ALL_UNITS_IDS = [p.name for p in ALL_UNITS]

MAIN_UNITS = [
    SYSTEMD_DIR / "autostream.service",
    SYSTEMD_DIR / "autostream_monitor.service",
    SYSTEMD_DIR / "autostream_wifi_watcher.service",
    SYSTEMD_DIR / "autostream_dnsmasq.service",
    SYSTEMD_DIR / "autostream_updater.service",
    SYSTEMD_DIR / "autostream_update_retry.service",
]
DIAL_UNITS = [
    SYSTEMD_DIR / "autostream_dial.service",
    SYSTEMD_DIR / "autostream_dial_wifi_watcher.service",
    SYSTEMD_DIR / "autostream_dial_dnsmasq.service",
    SYSTEMD_DIR / "autostream_dial_updater.service",
    SYSTEMD_DIR / "autostream_dial_update_recover.service",
]


# ---------------------------------------------------------------------------
# Systemd unit structure
# ---------------------------------------------------------------------------

class TestSystemdUnitStructure:
    """Every .service file must have the three required sections."""

    @pytest.mark.parametrize("unit", ALL_UNITS, ids=ALL_UNITS_IDS)
    def test_has_unit_section(self, unit):
        assert _unit_has_section(unit, "Unit"), f"{unit.name} missing [Unit]"

    @pytest.mark.parametrize("unit", ALL_UNITS, ids=ALL_UNITS_IDS)
    def test_has_service_section(self, unit):
        assert _unit_has_section(unit, "Service"), f"{unit.name} missing [Service]"

    @pytest.mark.parametrize("unit", ALL_UNITS, ids=ALL_UNITS_IDS)
    def test_has_install_section(self, unit):
        # Timer-triggered services don't need [Install] — the .timer unit is the installable unit.
        timer = unit.with_suffix(".timer")
        if timer.exists():
            pytest.skip(f"{unit.name} is timer-triggered; [Install] lives in the .timer file")
        assert _unit_has_section(unit, "Install"), f"{unit.name} missing [Install]"

    @pytest.mark.parametrize("unit", ALL_UNITS, ids=ALL_UNITS_IDS)
    def test_execstart_is_not_empty(self, unit):
        exec_start = _unit_field(unit, "Service", "ExecStart")
        assert exec_start, f"{unit.name} has no ExecStart"

    @pytest.mark.parametrize("unit", ALL_UNITS, ids=ALL_UNITS_IDS)
    def test_restart_policy_is_set(self, unit):
        svc = _unit_section(unit, "Service")
        type_ = (svc.get("Type") or ["simple"])[0]
        restart = (svc.get("Restart") or [""])[0]
        # Oneshot services typically do not restart (or "on-failure").
        # Simple/forking services must have a Restart policy.
        if type_ != "oneshot":
            assert restart, f"{unit.name}: non-oneshot service missing Restart="

    def test_python_units_use_venv_interpreter(self):
        """Units that run Python scripts must use the venv interpreter."""
        for unit in ALL_UNITS:
            exec_start = _unit_field(unit, "Service", "ExecStart")
            if "python" in exec_start and "/opt/autostream" in exec_start:
                assert "/opt/autostream/venv/bin/python" in exec_start, (
                    f"{unit.name}: Python script not using venv: {exec_start!r}"
                )


class TestMallocArenaCap:
    """autostream.service and autostream_bluetooth.service run multi-threaded
    CPython daemons on a 415 MB appliance; MALLOC_ARENA_MAX=2 caps glibc's
    per-thread malloc arenas to curb fragmentation-driven RSS growth. The
    wifi watcher unit is deliberately excluded (not a threaded CPython
    daemon)."""

    CAPPED_UNITS = [
        SYSTEMD_DIR / "autostream.service",
        SYSTEMD_DIR / "autostream_bluetooth.service",
    ]

    @pytest.mark.parametrize("unit", CAPPED_UNITS, ids=lambda u: u.name)
    def test_malloc_arena_max_set(self, unit):
        env = _unit_section(unit, "Service").get("Environment", [])
        assert "MALLOC_ARENA_MAX=2" in env, (
            f"{unit.name}: missing Environment=MALLOC_ARENA_MAX=2"
        )

    def test_wifi_watcher_not_arena_capped(self):
        """The wifi watcher is deliberately excluded from the arena cap."""
        unit = SYSTEMD_DIR / "autostream_wifi_watcher.service"
        env = _unit_section(unit, "Service").get("Environment", [])
        assert "MALLOC_ARENA_MAX=2" not in env, (
            f"{unit.name}: unexpectedly has MALLOC_ARENA_MAX=2"
        )


class TestWifiWatcherProcessRecovery:
    """With profile autoconnect disabled, the watcher is the sole reconnection
    agent, so its unit must survive crash *and* clean exit and never give up."""

    WATCHER_UNITS = [
        SYSTEMD_DIR / "autostream_wifi_watcher.service",
        SYSTEMD_DIR / "autostream_dial_wifi_watcher.service",
    ]

    @pytest.mark.parametrize("unit", WATCHER_UNITS, ids=lambda u: u.name)
    def test_restart_always(self, unit):
        restart = (_unit_section(unit, "Service").get("Restart") or [""])[0]
        assert restart == "always", (
            f"{unit.name}: the sole-reconnection-agent design needs Restart=always (a clean exit must restart "
            f"the sole reconnection agent), found {restart!r}"
        )

    @pytest.mark.parametrize("unit", WATCHER_UNITS, ids=lambda u: u.name)
    def test_start_limit_disabled(self, unit):
        interval = (_unit_section(unit, "Unit").get("StartLimitIntervalSec") or [""])[0]
        assert interval == "0", (
            f"{unit.name}: StartLimitIntervalSec=0 required so the watcher can never "
            f"land in start-limit-hit and stop retrying, found {interval!r}"
        )


# ---------------------------------------------------------------------------
# Systemd dependency ordering
# ---------------------------------------------------------------------------

class TestSystemdDependencyOrdering:
    """Critical ordering and dependency relationships between units."""

    def test_autostream_does_not_require_monitor(self):
        """autostream.service must NOT hard-Require= autostream_monitor.service.

        With a hard Requires=, `systemctl restart autostream_monitor`
        (routine -- fired by reconcile_monitor_format()'s "restart-monitor"
        admin verb) stops-then-starts the monitor unit, and systemd
        propagates that stop to every unit that Requires= it -- taking
        autostream.service down with it, killing the very admin call that
        requested the restart. autostream's MonitorClient already has
        reconnect/resync machinery built to ride out exactly this kind of
        monitor restart, so the hard dependency is unnecessary and actively
        harmful. Wants= (see test_autostream_wants_monitor below) plus
        After= still give correct boot ordering without coupling the two
        services' running state.
        """
        unit = SYSTEMD_DIR / "autostream.service"
        requires = _unit_field(unit, "Unit", "Requires")
        assert "autostream_monitor.service" not in requires, (
            "autostream.service must not Require= autostream_monitor.service "
            "-- a monitor restart/stop must not take autostream down with it"
        )

    def test_autostream_wants_monitor(self):
        unit = SYSTEMD_DIR / "autostream.service"
        wants = _unit_field(unit, "Unit", "Wants")
        assert "autostream_monitor.service" in wants

    def test_autostream_after_monitor(self):
        """After= (boot ordering only, no running-state coupling) must still
        be present so autostream starts after the monitor at boot."""
        unit = SYSTEMD_DIR / "autostream.service"
        after = _unit_field(unit, "Unit", "After")
        assert "autostream_monitor.service" in after

    def test_update_retry_before_monitor(self):
        """autostream_update_retry must finish before monitor starts (ordering invariant)."""
        unit = SYSTEMD_DIR / "autostream_update_retry.service"
        before = _unit_field(unit, "Unit", "Before")
        assert "autostream_monitor.service" in before, (
            "autostream_update_retry.service must have Before=autostream_monitor.service"
        )

    def test_dial_update_recover_before_dial_service(self):
        unit = SYSTEMD_DIR / "autostream_dial_update_recover.service"
        before = _unit_field(unit, "Unit", "Before")
        assert "autostream_dial.service" in before, (
            "autostream_dial_update_recover.service must run Before=autostream_dial.service"
        )

    def test_dial_update_recover_before_dial_updater(self):
        unit = SYSTEMD_DIR / "autostream_dial_update_recover.service"
        before = _unit_field(unit, "Unit", "Before")
        assert "autostream_dial_updater.service" in before, (
            "autostream_dial_update_recover.service must run Before=autostream_dial_updater.service"
        )

    def test_wifi_watcher_after_network_manager(self):
        unit = SYSTEMD_DIR / "autostream_wifi_watcher.service"
        after = _unit_field(unit, "Unit", "After")
        assert "NetworkManager.service" in after

    def test_wifi_watcher_after_update_retry(self):
        unit = SYSTEMD_DIR / "autostream_wifi_watcher.service"
        after = _unit_field(unit, "Unit", "After")
        assert "autostream_update_retry.service" in after, (
            "autostream_wifi_watcher.service must wait for boot-time update recovery"
        )

    def test_dial_wifi_watcher_after_network_manager(self):
        unit = SYSTEMD_DIR / "autostream_dial_wifi_watcher.service"
        after = _unit_field(unit, "Unit", "After")
        assert "NetworkManager.service" in after

    def test_installer_deploys_wifi_watcher_to_unit_execstart_path(self):
        unit = SYSTEMD_DIR / "autostream_wifi_watcher.service"
        exec_start = _unit_field(unit, "Service", "ExecStart")
        installer = INSTALL_SH.read_text(encoding="utf-8")
        assert exec_start == "/opt/autostream/autostream_wifi_watcher"
        assert '"${INSTALL_DIR}/autostream_wifi_watcher"' in installer
        assert '"${AUTOSTREAM_DIR}/platform/wifi_watcher.py"' in installer

    def test_update_restarts_wifi_watcher_after_deploy(self):
        installer = INSTALL_SH.read_text(encoding="utf-8")
        assert "systemctl restart autostream_wifi_watcher.service" in installer

    def test_installers_deploy_every_watcher_sibling_module(self):
        """Every platform/wifi_*.py the watcher imports must be copied to
        /opt/autostream by BOTH installers, or the deployed watcher crashes on
        import (this guards the wifi_mdns split and the wifi_policy gap it
        surfaced)."""
        import re
        watcher = (REPO_ROOT / "platform" / "wifi_watcher.py").read_text(encoding="utf-8")
        siblings = sorted({
            m1 or m2
            for m1, m2 in re.findall(
                r"^\s*(?:import (wifi_\w+)|from (wifi_\w+) import)",
                watcher, re.MULTILINE)
            if (REPO_ROOT / "platform" / f"{m1 or m2}.py").exists()
        })
        assert "wifi_mdns" in siblings and "wifi_policy" in siblings, siblings
        assert "wifi_state" in siblings, siblings
        appliance = INSTALL_SH.read_text(encoding="utf-8")
        dial = (REPO_ROOT / "autostream_dial_install.sh").read_text(encoding="utf-8")
        for mod in siblings:
            assert f"platform/{mod}.py" in appliance, (
                f"autostream_install.sh does not deploy platform/{mod}.py"
            )
            assert f"platform/{mod}.py" in dial, (
                f"autostream_dial_install.sh does not deploy platform/{mod}.py"
            )

    def test_installers_normalize_wifi_watcher_line_endings(self):
        appliance_installer = INSTALL_SH.read_text(encoding="utf-8")
        dial_installer = (REPO_ROOT / "autostream_dial_install.sh").read_text(
            encoding="utf-8"
        )
        assert r"sed -i 's/\r$//' " in appliance_installer
        assert r"sed -i 's/\r$//' " in dial_installer

    def test_dial_after_avahi_daemon(self):
        """autostream_dial must start after avahi-daemon to publish mDNS."""
        unit = SYSTEMD_DIR / "autostream_dial.service"
        after = _unit_field(unit, "Unit", "After")
        assert "avahi-daemon.service" in after, (
            "autostream_dial.service must declare After=avahi-daemon.service"
        )

    def test_update_retry_after_local_fs(self):
        unit = SYSTEMD_DIR / "autostream_update_retry.service"
        after = _unit_field(unit, "Unit", "After")
        assert "local-fs.target" in after

    def test_dial_update_recover_after_local_fs(self):
        unit = SYSTEMD_DIR / "autostream_dial_update_recover.service"
        after = _unit_field(unit, "Unit", "After")
        assert "local-fs.target" in after


# ---------------------------------------------------------------------------
# Systemd user / security policy
# ---------------------------------------------------------------------------

class TestSystemdUserPolicy:
    """Services must run as the correct user to enforce least privilege."""

    def test_monitor_runs_as_autostream(self):
        unit = SYSTEMD_DIR / "autostream_monitor.service"
        assert _unit_field(unit, "Service", "User") == "autostream"

    def test_webui_runs_as_autostream(self):
        unit = SYSTEMD_DIR / "autostream.service"
        assert _unit_field(unit, "Service", "User") == "autostream"

    def test_dial_runs_as_autostream(self):
        unit = SYSTEMD_DIR / "autostream_dial.service"
        assert _unit_field(unit, "Service", "User") == "autostream"

    def test_updater_runs_as_root(self):
        """Installer requires root; updater must run as root."""
        unit = SYSTEMD_DIR / "autostream_updater.service"
        assert _unit_field(unit, "Service", "User") == "root"

    def test_dial_updater_runs_as_root(self):
        unit = SYSTEMD_DIR / "autostream_dial_updater.service"
        assert _unit_field(unit, "Service", "User") == "root"

    def test_update_retry_has_no_user_drop(self):
        """Update retry runs as the default user (root) — no User= drop."""
        unit = SYSTEMD_DIR / "autostream_update_retry.service"
        user = _unit_field(unit, "Service", "User")
        # No explicit User= means it runs as root (the default for system services).
        assert user in ("", "root"), (
            f"autostream_update_retry.service unexpectedly drops to user {user!r}"
        )


# ---------------------------------------------------------------------------
# Nginx CGI cross-reference
# ---------------------------------------------------------------------------

class TestNginxCgiCrossReference:
    """Every SCRIPT_FILENAME in nginx configs must point to an existing script."""

    @pytest.mark.parametrize("conf", [
        NGINX_DIR / "autostream-nginx.conf",
        NGINX_DIR / "autostream-dial-nginx.conf",
    ], ids=["main", "dial"])
    def test_all_cgi_scripts_exist(self, conf):
        scripts = _nginx_cgi_scripts(conf)
        assert scripts, f"No CGI scripts found in {conf.name}"
        for script_path in scripts:
            # Map /opt/autostream/nginx/cgi/name.cgi → nginx/cgi/name.cgi in repo
            name = Path(script_path).name
            repo_cgi = CGI_DIR / name
            assert repo_cgi.exists(), (
                f"{conf.name} references {script_path!r} but {repo_cgi} not found in repo"
            )

    def test_all_cgi_scripts_have_cgi_extension(self):
        for conf in [NGINX_DIR / "autostream-nginx.conf",
                     NGINX_DIR / "autostream-dial-nginx.conf"]:
            for path in _nginx_cgi_scripts(conf):
                assert path.endswith(".cgi"), (
                    f"Non-.cgi script referenced in {conf.name}: {path!r}"
                )

    def test_cgi_socket_is_fcgiwrap(self):
        """All CGI endpoints must use the fcgiwrap socket (not a raw TCP port)."""
        for conf in [NGINX_DIR / "autostream-nginx.conf",
                     NGINX_DIR / "autostream-dial-nginx.conf"]:
            text = conf.read_text(encoding="utf-8")
            for socket in re.findall(r"fastcgi_pass\s+(\S+);", text):
                assert "fcgiwrap" in socket, (
                    f"{conf.name}: unexpected fastcgi_pass target {socket!r}"
                )

    def test_main_and_dial_nginx_reference_same_cgi_scripts(self):
        """Main and dial nginx configs share the same CGI scripts."""
        main_scripts = {Path(p).name for p in _nginx_cgi_scripts(
            NGINX_DIR / "autostream-nginx.conf")}
        dial_scripts = {Path(p).name for p in _nginx_cgi_scripts(
            NGINX_DIR / "autostream-dial-nginx.conf")}
        assert main_scripts == dial_scripts, (
            f"CGI script sets differ between main and dial nginx:\n"
            f"  main only: {main_scripts - dial_scripts}\n"
            f"  dial only: {dial_scripts - main_scripts}"
        )


# ---------------------------------------------------------------------------
# Sudoers policy
# ---------------------------------------------------------------------------

MAIN_SUDOERS = SUDOERS_DIR / "autostream_admin"
DIAL_SUDOERS = SUDOERS_DIR / "autostream_dial"
UPDATER_SUDOERS = SUDOERS_DIR / "autostream_updater"


class TestSudoersPolicy:
    """Sudoers fragments must enforce least privilege for each user."""

    def test_www_data_reboot_has_no_wildcard(self):
        """www-data reboot rule must have exact reason, not *."""
        for path in [MAIN_SUDOERS, DIAL_SUDOERS]:
            text = path.read_text(encoding="utf-8")
            # Find every line that mentions www-data and reboot.
            for line in text.splitlines():
                if "www-data" in line and "reboot" in line and not line.strip().startswith("#"):
                    assert not re.search(r"reboot\s+\*", line), (
                        f"{path.name}: wildcard on reboot grant for www-data: {line!r}"
                    )

    def test_www_data_factory_reset_has_no_wildcard(self):
        for path in [MAIN_SUDOERS, DIAL_SUDOERS]:
            text = path.read_text(encoding="utf-8")
            for line in text.splitlines():
                if "www-data" in line and "factory-reset" in line \
                        and not line.strip().startswith("#"):
                    assert not re.search(r"factory-reset\s+\*", line), (
                        f"{path.name}: wildcard on factory-reset for www-data: {line!r}"
                    )

    def test_www_data_cannot_call_run_updater(self):
        """www-data must never gain access to run-updater (privilege escalation)."""
        for path in [MAIN_SUDOERS, DIAL_SUDOERS, UPDATER_SUDOERS]:
            text = path.read_text(encoding="utf-8")
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or "www-data" not in stripped:
                    continue
                assert "run-updater" not in stripped, (
                    f"{path.name}: www-data gains run-updater: {stripped!r}"
                )

    def test_www_data_cannot_call_toggle_update_timer(self):
        """www-data must not be able to enable/disable the update timer."""
        for path in [MAIN_SUDOERS, DIAL_SUDOERS, UPDATER_SUDOERS]:
            text = path.read_text(encoding="utf-8")
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or "www-data" not in stripped:
                    continue
                assert "toggle" not in stripped, (
                    f"{path.name}: www-data gains toggle-timer verb: {stripped!r}"
                )

    def test_update_status_permitted_for_www_data_in_main(self):
        text = MAIN_SUDOERS.read_text(encoding="utf-8")
        assert "update-status" in text, (
            "autostream_admin sudoers must permit www-data to call update-status"
        )

    def test_update_status_permitted_for_www_data_in_dial(self):
        text = DIAL_SUDOERS.read_text(encoding="utf-8")
        assert "update-status" in text, (
            "autostream_dial sudoers must permit www-data to call update-status"
        )

    def test_sethostname_wildcard_is_expected_and_isolated(self):
        """sethostname * is intentional (admin enforces format internally)."""
        text = MAIN_SUDOERS.read_text(encoding="utf-8")
        assert "sethostname *" in text or "sethostname\t*" in text, (
            "autostream_admin sudoers must include a sethostname wildcard rule"
        )
        # The wildcard rule must be on sethostname ONLY — not on reboot or reset.
        for line in text.splitlines():
            if re.search(r"sethostname\s+\*", line) and not line.strip().startswith("#"):
                assert "reboot" not in line and "factory-reset" not in line, (
                    f"Wildcard sethostname rule unexpectedly co-grants destructive verbs: {line!r}"
                )

    def test_autostream_user_can_call_sethostname(self):
        text = MAIN_SUDOERS.read_text(encoding="utf-8")
        # User_Alias AUTOSTREAM_WEB = autostream
        assert "AUTOSTREAM_WEB" in text or "autostream" in text

    def test_autostream_updater_sudoers_grants_autostream_user(self):
        text = UPDATER_SUDOERS.read_text(encoding="utf-8")
        assert "autostream" in text and "autostream_updater" in text


# ---------------------------------------------------------------------------
# CGI-to-sudoers permission matrix
# ---------------------------------------------------------------------------

class TestCgiSudoMatrix:
    """Each CGI script that invokes sudo must call a command permitted in sudoers."""

    def _cgi_text(self, name: str) -> str:
        return (CGI_DIR / name).read_text(encoding="utf-8")

    def test_reboot_cgi_uses_sudo_n(self):
        text = self._cgi_text("reboot.cgi")
        assert "sudo" in text and "-n" in text

    def test_reboot_cgi_calls_reboot_verb(self):
        text = self._cgi_text("reboot.cgi")
        assert "reboot" in text

    def test_reboot_cgi_command_permitted_in_main_sudoers(self):
        """reboot.cgi uses 'reboot --delay 3 UserRequestSystemError' — this must be in sudoers."""
        cgi = self._cgi_text("reboot.cgi")
        # Extract the reason used by the CGI
        m = re.search(r'REASON="?(\w+)"?', cgi)
        assert m, "reboot.cgi has no REASON variable"
        reason = m.group(1)
        # Verify sudoers covers this exact reason
        sudoers_text = MAIN_SUDOERS.read_text(encoding="utf-8")
        assert reason in sudoers_text, (
            f"reboot.cgi uses REASON={reason!r} but autostream_admin sudoers has no matching rule"
        )

    def test_factory_reset_cgi_uses_sudo_n(self):
        text = self._cgi_text("factory-reset.cgi")
        assert "sudo" in text and "-n" in text

    def test_factory_reset_cgi_command_permitted_in_main_sudoers(self):
        text = self._cgi_text("factory-reset.cgi")
        assert "factory-reset" in text
        assert "factory-reset" in MAIN_SUDOERS.read_text(encoding="utf-8")

    def test_factory_reset_cgi_command_permitted_in_dial_sudoers(self):
        text = self._cgi_text("factory-reset.cgi")
        assert "factory-reset" in text
        assert "factory-reset" in DIAL_SUDOERS.read_text(encoding="utf-8")

    def test_update_status_cgi_uses_sudo_n(self):
        text = self._cgi_text("update-status.cgi")
        assert "sudo" in text and "-n" in text

    def test_update_status_cgi_command_permitted_in_dial_sudoers(self):
        """update-status needs sudo because /var/lib/autostream is 0750."""
        text = self._cgi_text("update-status.cgi")
        assert "update-status" in text
        assert "update-status" in DIAL_SUDOERS.read_text(encoding="utf-8")

    def test_download_logs_cgi_does_not_use_sudo(self):
        """download-logs.cgi reads log files directly (www-data is in adm group)."""
        text = self._cgi_text("download-logs.cgi")
        assert "sudo" not in text, (
            "download-logs.cgi must not use sudo — www-data reads logs via adm group membership"
        )

    def test_cgi_uses_full_sudo_path(self):
        """CGIs in fcgiwrap have minimal PATH; must use /usr/bin/sudo explicitly."""
        for name in ["reboot.cgi", "factory-reset.cgi", "update-status.cgi"]:
            text = self._cgi_text(name)
            assert "/usr/bin/sudo" in text, (
                f"{name} must reference /usr/bin/sudo (not just 'sudo') for fcgiwrap PATH safety"
            )


# ---------------------------------------------------------------------------
# Avahi XML validation
# ---------------------------------------------------------------------------

class TestAvahiXml:
    """Avahi service XML must be parseable and contain required elements."""

    def _parse(self, name: str) -> ET.Element:
        path = AVAHI_DIR / name
        try:
            tree = ET.parse(str(path))
            return tree.getroot()
        except ET.ParseError as exc:
            pytest.fail(f"{name} is not valid XML: {exc}")

    def test_dial_avahi_is_valid_xml(self):
        root = self._parse("autostream-dial.service")
        assert root.tag == "service-group"

    def test_dial_avahi_has_service_element(self):
        root = self._parse("autostream-dial.service")
        assert root.find("service") is not None

    def test_dial_avahi_service_type(self):
        root = self._parse("autostream-dial.service")
        svc_type = root.find("service/type")
        assert svc_type is not None and svc_type.text == "_autostream-dial._tcp"

    def test_dial_avahi_port_is_numeric(self):
        root = self._parse("autostream-dial.service")
        port_el = root.find("service/port")
        assert port_el is not None
        assert port_el.text and port_el.text.isdigit()

    def test_dial_avahi_has_required_placeholders(self):
        text = (AVAHI_DIR / "autostream-dial.service").read_text(encoding="utf-8")
        for placeholder in ["__DIAL_UUID__", "__DIAL_NAME__", "__AUTOSTREAM_RELEASE_TAG__"]:
            assert placeholder in text, (
                f"autostream-dial.service Avahi XML missing placeholder {placeholder!r}"
            )

    def test_playing_avahi_is_valid_xml(self):
        root = self._parse("autostream-playing.service")
        assert root.tag == "service-group"

    def test_playing_avahi_service_type(self):
        root = self._parse("autostream-playing.service")
        svc_type = root.find("service/type")
        assert svc_type is not None and svc_type.text == "_autostream-playing._tcp"

    def test_playing_avahi_port_80(self):
        root = self._parse("autostream-playing.service")
        port_el = root.find("service/port")
        assert port_el is not None and port_el.text == "80"

    def test_playing_avahi_has_version_placeholder(self):
        text = (AVAHI_DIR / "autostream-playing.service").read_text(encoding="utf-8")
        assert "__AUTOSTREAM_RELEASE_TAG__" in text


# ---------------------------------------------------------------------------
# Dnsmasq configuration
# ---------------------------------------------------------------------------

class TestDnsmasqConfig:
    def _conf(self, name: str) -> str:
        return (DNSMASQ_DIR / name).read_text(encoding="utf-8")

    def test_setup_conf_has_interface(self):
        text = self._conf("autostream-setup.conf")
        assert re.search(r"^\s*interface\s*=", text, re.MULTILINE), (
            "autostream-setup.conf must bind to a specific interface"
        )

    def test_setup_conf_has_dhcp_range(self):
        text = self._conf("autostream-setup.conf")
        assert re.search(r"^\s*dhcp-range\s*=", text, re.MULTILINE)

    def test_setup_conf_has_dns_hijack(self):
        """address=/#/... hijacks all DNS to the captive portal IP."""
        text = self._conf("autostream-setup.conf")
        assert re.search(r"^\s*address=/#/", text, re.MULTILINE), (
            "autostream-setup.conf must have address=/#/<IP> to intercept all DNS"
        )

    def test_setup_conf_disables_resolv(self):
        text = self._conf("autostream-setup.conf")
        assert "no-resolv" in text, (
            "autostream-setup.conf must set no-resolv to prevent DNS leaking in AP mode"
        )

    def test_setup_conf_has_bind_interfaces(self):
        text = self._conf("autostream-setup.conf")
        assert "bind-interfaces" in text

    def test_dial_setup_conf_exists(self):
        assert (DNSMASQ_DIR / "autostream-dial-setup.conf").exists()

    def test_dial_setup_conf_has_interface(self):
        text = self._conf("autostream-dial-setup.conf")
        assert re.search(r"^\s*interface\s*=", text, re.MULTILINE)

    def test_dial_setup_conf_has_dhcp_range(self):
        text = self._conf("autostream-dial-setup.conf")
        assert re.search(r"^\s*dhcp-range\s*=", text, re.MULTILINE)

    # --- Runtime interface-binding template mechanism ---

    def test_setup_conf_uses_interface_token(self):
        text = self._conf("autostream-setup.conf")
        assert "interface=__AUTOSTREAM_WIFI_IFACE__" in text, (
            "template must use the interface token, not a literal wlan0"
        )
        assert "interface=wlan0" not in text

    def test_dial_setup_conf_uses_interface_token(self):
        text = self._conf("autostream-dial-setup.conf")
        assert "interface=__AUTOSTREAM_WIFI_IFACE__" in text
        assert "interface=wlan0" not in text

    def test_setup_conf_dhcp_dns_unchanged(self):
        text = self._conf("autostream-setup.conf")
        assert "dhcp-range=192.168.4.50,192.168.4.200,255.255.255.0,12h" in text
        assert "dhcp-option=option:router,192.168.4.1" in text
        assert "address=/#/192.168.4.1" in text

    def test_dnsmasq_services_read_runtime_config(self):
        main = (SYSTEMD_DIR / "autostream_dnsmasq.service").read_text(encoding="utf-8")
        dial = (SYSTEMD_DIR / "autostream_dial_dnsmasq.service").read_text(encoding="utf-8")
        assert "/run/autostream/autostream-setup.conf" in main
        assert "/etc/dnsmasq.d/autostream-setup.conf" not in main
        assert "/run/autostream/autostream-dial-setup.conf" in dial
        assert "/etc/dnsmasq.d/autostream-dial-setup.conf" not in dial

    def test_installers_deploy_templates_and_remove_obsolete(self):
        main = (REPO_ROOT / "autostream_install.sh").read_text(encoding="utf-8")
        dial = (REPO_ROOT / "autostream_dial_install.sh").read_text(encoding="utf-8")
        assert "/usr/local/share/autostream/dnsmasq/autostream-setup.conf" in main
        assert "rm -f /etc/dnsmasq.d/autostream-setup.conf" in main
        assert "/usr/local/share/autostream/dnsmasq/autostream-dial-setup.conf" in dial
        assert "rm -f /etc/dnsmasq.d/autostream-dial-setup.conf" in dial


class TestDispatcherPowerSave:
    def _text(self):
        return (NM_DIR / "99-wlan-fix").read_text(encoding="utf-8")

    def test_not_limited_to_literal_wlan0(self):
        text = self._text()
        # Must not gate the whole action on IFACE == wlan0.
        assert 'IFACE" = "wlan0"' not in text

    def test_powersave_disabled_generically(self):
        assert "power_save off" in self._text()

    def test_usb_txpower_guarded(self):
        text = self._text()
        # txpower must not be applied unconditionally to USB adapters.
        assert "IS_USB" in text or "usb" in text.lower()


# ---------------------------------------------------------------------------
# Logrotate configuration
# ---------------------------------------------------------------------------

class TestLogrotateConfig:
    def _conf(self, name: str) -> str:
        return (LOGROTATE_DIR / name).read_text(encoding="utf-8")

    def test_main_logrotate_has_daily_rotation(self):
        text = self._conf("autostream")
        assert "daily" in text

    def test_main_logrotate_has_rotate_count(self):
        text = self._conf("autostream")
        assert re.search(r"^\s*rotate\s+\d+", text, re.MULTILINE)

    def test_main_logrotate_has_compress(self):
        text = self._conf("autostream")
        assert "compress" in text

    def test_main_logrotate_covers_log_dir(self):
        text = self._conf("autostream")
        assert "/var/log/autostream/" in text

    def test_dial_logrotate_has_rotate_count(self):
        text = self._conf("autostream-dial")
        assert re.search(r"^\s*rotate\s+\d+", text, re.MULTILINE)

    def test_dial_logrotate_has_create_with_permissions(self):
        """Dial admin logs are root:adm 0640; create directive must set this."""
        text = self._conf("autostream-dial")
        assert re.search(r"^\s*create\s+0640\s+root\s+adm", text, re.MULTILINE), (
            "autostream-dial logrotate must have create 0640 root adm"
        )

    def test_dial_service_logrotate_has_service_create_permissions(self):
        """The running dial service writes its own log as autostream:adm 0640."""
        text = self._conf("autostream-dial")
        assert "autostream-dial.log" in text
        assert re.search(r"^\s*create\s+0640\s+autostream\s+adm", text, re.MULTILINE), (
            "autostream-dial service logrotate must have create 0640 autostream adm"
        )
        assert "copytruncate" in text

    def test_dial_logrotate_covers_update_log(self):
        text = self._conf("autostream-dial")
        assert "dial-update.log" in text or "dial-install.log" in text

    def test_dial_logrotate_covers_wifi_watcher_log(self):
        text = self._conf("autostream-dial")
        assert "autostream_wifi_watcher.log" in text


# ---------------------------------------------------------------------------
# Watchdog configuration
# ---------------------------------------------------------------------------

class TestWatchdogConfig:
    def _conf(self) -> str:
        return (WATCHDOG_DIR / "watchdog.conf").read_text(encoding="utf-8")

    def test_has_watchdog_device(self):
        text = self._conf()
        assert re.search(r"^\s*watchdog-device\s*=", text, re.MULTILINE)

    def test_interval_less_than_timeout(self):
        text = self._conf()
        interval_m = re.search(r"^\s*interval\s*=\s*(\d+)", text, re.MULTILINE)
        timeout_m = re.search(r"^\s*watchdog-timeout\s*=\s*(\d+)", text, re.MULTILINE)
        assert interval_m and timeout_m, "watchdog.conf must set interval and watchdog-timeout"
        assert int(interval_m.group(1)) < int(timeout_m.group(1)), (
            "Watchdog interval must be < timeout to avoid false reboot triggers"
        )

    def test_has_max_temperature(self):
        text = self._conf()
        assert re.search(r"^\s*max-temperature\s*=\s*\d+", text, re.MULTILINE)

    def test_realtime_is_enabled(self):
        """realtime=yes prevents watchdog being swapped out under memory pressure."""
        text = self._conf()
        assert re.search(r"^\s*realtime\s*=\s*yes", text, re.MULTILINE), (
            "watchdog.conf must set realtime=yes"
        )

    def test_max_load_thresholds_present(self):
        text = self._conf()
        assert re.search(r"^\s*max-load-1\s*=", text, re.MULTILINE), (
            "watchdog.conf should set max-load-1 threshold"
        )


# ---------------------------------------------------------------------------
# NetworkManager configuration
# ---------------------------------------------------------------------------

class TestNetworkManagerConfig:
    def test_mdns_conf_enables_mdns(self):
        text = (NM_DIR / "mdns.conf").read_text(encoding="utf-8")
        assert "mdns=2" in text or "connection.mdns=2" in text, (
            "mdns.conf must enable mDNS (connection.mdns=2)"
        )

    def test_wifi_powersave_conf_disables_powersave(self):
        text = (NM_DIR / "wifi-powersave.conf").read_text(encoding="utf-8")
        assert "powersave" in text.lower(), (
            "wifi-powersave.conf should reference wifi.powersave setting"
        )
        assert "2" in text, "wifi.powersave=2 (disable) must be set to prevent WiFi dropouts"

    def test_installer_installs_networkmanager_files_root_owned(self):
        text = INSTALL_SH.read_text(encoding="utf-8")
        assert re.search(
            r"install\s+-m\s+0755\s+-o\s+root\s+-g\s+root\s+\\\n"
            r'\s+"\$\{AUTOSTREAM_DIR\}/system/NetworkManager/99-wlan-fix"\s+\\\n'
            r"\s+/etc/NetworkManager/dispatcher\.d/99-wlan-fix",
            text,
        ), "99-wlan-fix must be installed root-owned and executable"
        assert re.search(
            r"install\s+-m\s+0644\s+-o\s+root\s+-g\s+root\s+\\\n"
            r'\s+"\$\{AUTOSTREAM_DIR\}/system/NetworkManager/mdns\.conf"\s+\\\n'
            r"\s+/etc/NetworkManager/conf\.d/mdns\.conf",
            text,
        ), "mdns.conf must be installed root-owned"
        assert re.search(
            r"install\s+-m\s+0644\s+-o\s+root\s+-g\s+root\s+\\\n"
            r'\s+"\$\{AUTOSTREAM_DIR\}/system/NetworkManager/wifi-powersave\.conf"\s+\\\n'
            r"\s+/etc/NetworkManager/conf\.d/wifi-powersave\.conf",
            text,
        ), "wifi-powersave.conf must be installed root-owned"


# ---------------------------------------------------------------------------
# Linux CI-only live validation
# ---------------------------------------------------------------------------

def _tool_ok(name: str) -> bool:
    try:
        return subprocess.run(
            [name, "--version"], capture_output=True, timeout=5
        ).returncode == 0
    except Exception:
        return False


linux_only = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Live config validation requires Linux (run in CI: ubuntu-latest)",
)

systemd_available = pytest.mark.skipif(
    not _tool_ok("systemd-analyze"),
    reason="systemd-analyze not available",
)

_autostream_installed = Path("/opt/autostream").exists()
autostream_installed = pytest.mark.skipif(
    not _autostream_installed,
    reason="autostream not installed at /opt/autostream — run on a deployed appliance",
)

nginx_available = pytest.mark.skipif(
    not _tool_ok("nginx"),
    reason="nginx not available",
)

visudo_available = pytest.mark.skipif(
    not _tool_ok("visudo"),
    reason="visudo not available",
)


NGINX_SNIPPETS = [
    NGINX_DIR / "autostream-nginxd.conf",
    NGINX_DIR / "autostream-nginx.conf",
    NGINX_DIR / "autostream-dial-nginx.conf",
]


class TestNginxSyntax:
    """nginx -t validates every nginx config snippet via a minimal wrapper."""

    @linux_only
    @nginx_available
    @pytest.mark.parametrize("snippet", NGINX_SNIPPETS, ids=[p.name for p in NGINX_SNIPPETS])
    def test_nginx_t_validates_snippet(self, snippet, tmp_path):
        if not snippet.exists():
            pytest.skip(f"{snippet.name} not found")
        # Wrap the snippet in a minimal nginx.conf so nginx -t can parse it.
        # All three snippets contain http-context directives (map{} or server{}).
        wrapper = tmp_path / "nginx.conf"
        wrapper.write_text(
            'events {}\n'
            'http {\n'
            f'    include "{snippet.as_posix()}";\n'
            '}\n',
            encoding="utf-8",
        )
        r = subprocess.run(
            ["nginx", "-t", "-c", str(wrapper)],
            capture_output=True, text=True, timeout=15,
        )
        assert r.returncode == 0, (
            f"nginx -t failed for {snippet.name}:\n{r.stdout}\n{r.stderr}"
        )


class TestLinuxServiceValidation:
    @linux_only
    @systemd_available
    @autostream_installed
    @pytest.mark.parametrize("unit", MAIN_UNITS, ids=[u.name for u in MAIN_UNITS])
    def test_systemd_analyze_verify_main_unit(self, unit, tmp_path):
        r = subprocess.run(
            ["systemd-analyze", "verify", str(unit)],
            capture_output=True, text=True, timeout=30,
        )
        assert r.returncode == 0, (
            f"systemd-analyze verify failed for {unit.name}:\n{r.stdout}\n{r.stderr}"
        )

    @linux_only
    @systemd_available
    @autostream_installed
    @pytest.mark.parametrize("unit", DIAL_UNITS, ids=[u.name for u in DIAL_UNITS])
    def test_systemd_analyze_verify_dial_unit(self, unit):
        r = subprocess.run(
            ["systemd-analyze", "verify", str(unit)],
            capture_output=True, text=True, timeout=30,
        )
        assert r.returncode == 0, (
            f"systemd-analyze verify failed for {unit.name}:\n{r.stdout}\n{r.stderr}"
        )

    @linux_only
    @visudo_available
    @pytest.mark.parametrize("sudoers", [
        MAIN_SUDOERS, DIAL_SUDOERS, UPDATER_SUDOERS,
    ], ids=["autostream_admin", "autostream_dial", "autostream_updater"])
    def test_visudo_validates_sudoers(self, sudoers):
        r = subprocess.run(
            ["visudo", "-cf", str(sudoers)],
            capture_output=True, text=True, timeout=10,
        )
        assert r.returncode == 0, (
            f"visudo -cf failed for {sudoers.name}:\n{r.stdout}\n{r.stderr}"
        )
