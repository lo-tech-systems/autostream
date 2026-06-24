"""tests/test_storage_guard_deployment.py

WP4 deployment policy tests: verify that all system files referenced by
the installer and uninstaller scripts are present in the source tree with
the correct names, paths, and basic content expectations.

These tests run without any OS-level privileges and exercise the artifacts
on disk rather than live system state.
"""
from __future__ import annotations

import configparser
import re
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent

# ── helpers ──────────────────────────────────────────────────────────────────

def _read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def _installer() -> str:
    return _read("autostream_install.sh")


def _uninstaller() -> str:
    return _read("autostream_uninstall.sh")


# ── 1. Supervisor script present ─────────────────────────────────────────────

def test_storage_guard_supervisor_script_exists():
    assert (REPO / "supervisor" / "autostream_storage_guard").is_file()


def test_storage_guard_supervisor_script_has_main():
    src = _read("supervisor/autostream_storage_guard")
    assert "def main(" in src


# ── 2. systemd unit files ─────────────────────────────────────────────────────

def test_storage_guard_service_unit_exists():
    assert (REPO / "system" / "systemd" / "autostream_storage_guard.service").is_file()


def test_storage_guard_timer_unit_exists():
    assert (REPO / "system" / "systemd" / "autostream_storage_guard.timer").is_file()


def test_storage_guard_service_is_oneshot():
    text = _read("system/systemd/autostream_storage_guard.service")
    assert "Type=oneshot" in text


def test_storage_guard_service_runs_as_root():
    text = _read("system/systemd/autostream_storage_guard.service")
    assert "User=root" in text


def test_storage_guard_service_exec_path():
    text = _read("system/systemd/autostream_storage_guard.service")
    assert "/usr/local/libexec/autostream/autostream_storage_guard" in text


def test_storage_guard_service_low_priority():
    text = _read("system/systemd/autostream_storage_guard.service")
    assert "IOSchedulingClass=idle" in text
    assert "CPUWeight=10" in text


def test_storage_guard_service_no_new_privileges():
    text = _read("system/systemd/autostream_storage_guard.service")
    assert "NoNewPrivileges=true" in text


def test_storage_guard_timer_oncalendar():
    text = _read("system/systemd/autostream_storage_guard.timer")
    assert "OnCalendar=" in text


def test_storage_guard_timer_randomized_delay():
    text = _read("system/systemd/autostream_storage_guard.timer")
    assert "RandomizedDelaySec=" in text


def test_storage_guard_timer_persistent():
    text = _read("system/systemd/autostream_storage_guard.timer")
    assert "Persistent=true" in text


def test_storage_guard_timer_install_section():
    text = _read("system/systemd/autostream_storage_guard.timer")
    assert "[Install]" in text
    assert "WantedBy=timers.target" in text


# ── 3. journald drop-in ────────────────────────────────────────────────────────

def test_journald_dropin_exists():
    assert (REPO / "system" / "journald" / "99-autostream-storage.conf").is_file()


def test_journald_dropin_journal_section():
    text = _read("system/journald/99-autostream-storage.conf")
    assert "[Journal]" in text


def test_journald_dropin_compress():
    text = _read("system/journald/99-autostream-storage.conf")
    assert "Compress=yes" in text


def test_journald_dropin_max_use():
    text = _read("system/journald/99-autostream-storage.conf")
    assert "SystemMaxUse=" in text


def test_journald_dropin_keep_free():
    text = _read("system/journald/99-autostream-storage.conf")
    assert "SystemKeepFree=" in text


def test_journald_dropin_no_max_level():
    # Must NOT set MaxLevelStore or MaxLevelSystem as active directives
    non_comment_lines = [
        ln for ln in _read("system/journald/99-autostream-storage.conf").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    joined = "\n".join(non_comment_lines)
    assert "MaxLevelStore" not in joined
    assert "MaxLevelSystem" not in joined


def test_journald_dropin_retention():
    text = _read("system/journald/99-autostream-storage.conf")
    assert "MaxRetentionSec=" in text


# ── 4. NGINX access-log conf ──────────────────────────────────────────────────

def test_nginx_access_log_conf_exists():
    assert (REPO / "system" / "nginx" / "99-autostream-access-log.conf").is_file()


def test_nginx_access_log_conf_has_map():
    text = _read("system/nginx/99-autostream-access-log.conf")
    assert "map $status $autostream_access_log_level" in text


def test_nginx_access_log_conf_suppresses_2xx():
    text = _read("system/nginx/99-autostream-access-log.conf")
    # 2xx should map to 0 (suppressed)
    assert re.search(r"~\^2\s+0", text)


def test_nginx_access_log_conf_default_logged():
    text = _read("system/nginx/99-autostream-access-log.conf")
    assert re.search(r"default\s+1", text)


def test_nginx_vhost_uses_conditional_access_log():
    text = _read("system/nginx/autostream-nginx.conf")
    assert "if=$autostream_access_log_level" in text


def test_nginx_vhost_references_access_log_var():
    text = _read("system/nginx/autostream-nginx.conf")
    assert "$autostream_access_log_level" in text


# ── 5. sudoers entries for NGINX log switching ─────────────────────────────────

def test_sudoers_has_nginx_log_verbose():
    text = _read("system/sudoers/autostream_admin")
    assert "set-nginx-access-log verbose" in text


def test_sudoers_has_nginx_log_normal():
    text = _read("system/sudoers/autostream_admin")
    assert "set-nginx-access-log normal" in text


def test_sudoers_nginx_log_aliases_in_admin_list():
    text = _read("system/sudoers/autostream_admin")
    assert "AUTOSTREAM_ADMIN_NGINX_LOG_V" in text
    assert "AUTOSTREAM_ADMIN_NGINX_LOG_N" in text
    # Both must appear in the AUTOSTREAM_ADMIN Cmnd_Alias expansion
    admin_block = re.search(
        r"Cmnd_Alias AUTOSTREAM_ADMIN\s*=(.*?)(?=\n\n|\nDefaults|\Z)",
        text,
        re.DOTALL,
    )
    assert admin_block is not None
    block = admin_block.group(1)
    assert "AUTOSTREAM_ADMIN_NGINX_LOG_V" in block
    assert "AUTOSTREAM_ADMIN_NGINX_LOG_N" in block


# ── 6. Installer wires up all new artifacts ───────────────────────────────────

def test_installer_installs_storage_guard_script():
    text = _installer()
    assert "autostream_storage_guard" in text
    assert "install_text_linux" in text
    # The script must be installed to libexec
    assert re.search(
        r'install_text_linux.*autostream_storage_guard.*0755\s+root\s+root',
        text,
    )


def test_installer_installs_storage_guard_service():
    text = _installer()
    assert "autostream_storage_guard.service" in text
    assert "/etc/systemd/system/" in text


def test_installer_installs_storage_guard_timer():
    text = _installer()
    assert "autostream_storage_guard.timer" in text


def test_installer_enables_storage_guard_timer():
    text = _installer()
    assert "systemctl enable --now autostream_storage_guard.timer" in text


def test_installer_installs_journald_dropin():
    text = _installer()
    assert "99-autostream-storage.conf" in text
    assert "journald.conf.d" in text


def test_installer_restarts_journald():
    text = _installer()
    assert "systemctl restart systemd-journald" in text


def test_installer_installs_nginx_access_log_conf():
    text = _installer()
    assert "99-autostream-access-log.conf" in text
    assert "/etc/nginx/conf.d/" in text


# ── 7. Uninstaller removes all new artifacts ──────────────────────────────────

def test_uninstaller_stops_storage_guard_timer():
    text = _uninstaller()
    assert "autostream_storage_guard.timer" in text


def test_uninstaller_stops_storage_guard_service():
    text = _uninstaller()
    assert "autostream_storage_guard.service" in text


def test_uninstaller_removes_storage_guard_systemd_units():
    text = _uninstaller()
    assert re.search(
        r"remove_path.*/etc/systemd/system/autostream_storage_guard\.service",
        text,
    )
    assert re.search(
        r"remove_path.*/etc/systemd/system/autostream_storage_guard\.timer",
        text,
    )


def test_uninstaller_removes_nginx_access_log_conf():
    text = _uninstaller()
    assert re.search(
        r"remove_path.*/etc/nginx/conf\.d/99-autostream-access-log\.conf",
        text,
    )


def test_uninstaller_removes_journald_dropin():
    text = _uninstaller()
    assert re.search(
        r"remove_path.*/etc/systemd/journald\.conf\.d/99-autostream-storage\.conf",
        text,
    )


def test_uninstaller_restarts_journald_after_removal():
    text = _uninstaller()
    # journald restart must come after the drop-in removal
    dropin_pos = text.find("99-autostream-storage.conf")
    restart_pos = text.find("systemctl restart systemd-journald")
    assert dropin_pos != -1 and restart_pos != -1
    assert restart_pos > dropin_pos


def test_uninstaller_stops_before_removes():
    text = _uninstaller()
    # stop/disable must come before remove_path
    stop_pos = text.find("stop_and_disable_service autostream_storage_guard.timer")
    remove_pos = text.find("remove_path /etc/systemd/system/autostream_storage_guard")
    assert stop_pos != -1 and remove_pos != -1
    assert stop_pos < remove_pos
