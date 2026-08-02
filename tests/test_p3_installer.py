"""P3 — Installer / upgrade / uninstall lifecycle tests.

What runs here:
  - bash -n syntax check for every installer/uninstaller/library script
    (bash is available on Windows via Git for Windows)
  - shellcheck (skipped when not installed; run in CI: apt-get install shellcheck)
  - detect_install_version() function (installer/dial/helpers.sh)
  - Main installer write_update_result() schema is compatible with all consumers:
    the installer quotes its values; consumers must strip quotes correctly.
  - Quoted vs unquoted schema round-trip: both formats reach all readers correctly.

Environment-dependent (not run here):
  - Installer helper unit tests with stub binaries in PATH: require bash that
    can execute scripts at POSIX paths (i.e. Linux CI, not MSYS2 on Windows).
    CI mechanism: ubuntu-latest GitHub Actions runner.
  - Image-level tests: fresh install, repeated update, factory reset, uninstall
    in a Raspberry Pi OS-compatible container/VM. CI: dedicated Pi OS image job.
    Reason cannot run here: requires systemd, apt-get, root access, Pi OS image.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "tests"))

from conftest import load_supervisor_script, bash_can_run_script_at_windows_path

# All shell scripts that should pass `bash -n`
INSTALLER_SCRIPTS = [
    REPO_ROOT / "autostream_install.sh",
    REPO_ROOT / "autostream_dial_install.sh",
    REPO_ROOT / "autostream_uninstall.sh",
    REPO_ROOT / "autostream_dial_uninstall.sh",
    REPO_ROOT / "bootstrap.sh",
    REPO_ROOT / "installer" / "lib" / "helpers.sh",
    REPO_ROOT / "installer" / "lib" / "owntone.sh",
    REPO_ROOT / "installer" / "lib" / "vibra.sh",
    REPO_ROOT / "installer" / "lib" / "hardware.sh",
    REPO_ROOT / "installer" / "dial" / "helpers.sh",
    REPO_ROOT / "nginx" / "cgi" / "update-status.cgi",
]

bash_capable = pytest.mark.skipif(
    not bash_can_run_script_at_windows_path(),
    reason="bash cannot execute scripts at this path (MSYS2 limitation on Windows)",
)

def _shellcheck_ok() -> bool:
    try:
        return subprocess.run(
            ["shellcheck", "--version"], capture_output=True, timeout=5
        ).returncode == 0
    except Exception:
        return False


shellcheck_available = pytest.mark.skipif(
    not _shellcheck_ok(),
    reason="shellcheck not installed — run in CI (apt-get install shellcheck)",
)


# ---------------------------------------------------------------------------
# bash -n syntax checks
# ---------------------------------------------------------------------------

class TestShellSyntax:
    """Every installer shell script must pass `bash -n` (syntax only, no execution)."""

    @bash_capable
    @pytest.mark.parametrize("script", INSTALLER_SCRIPTS, ids=[p.name for p in INSTALLER_SCRIPTS])
    def test_bash_n_syntax(self, script):
        if not script.exists():
            pytest.skip(f"{script.name} does not exist in this checkout")
        result = subprocess.run(
            ["bash", "-n", str(script)],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0, (
            f"bash -n failed for {script.name}:\n{result.stderr.strip()}"
        )


class TestVibraMiniInstallContract:
    """Autostream must launch the executable installed by vibra-mini."""

    def test_service_executes_vibra_mini_binary(self):
        unit = (
            REPO_ROOT / "system" / "systemd" / "vibra-mini.service"
        ).read_text(encoding="utf-8")
        assert (
            "ExecStart=/opt/autostream/vibra/bin/vibra-mini "
            "--socket /tmp/vibra-mini.sock"
        ) in unit
        assert "StandardOutput=append:/var/log/autostream/vibra-mini.log" in unit
        assert "StandardError=append:/var/log/autostream/vibra-mini.log" in unit

    def test_installer_verifies_vibra_mini_binary(self):
        installer = (
            REPO_ROOT / "installer" / "lib" / "vibra.sh"
        ).read_text(encoding="utf-8")
        assert '${VIBRA_INSTALL_PREFIX}/bin/vibra-mini' in installer

    def test_vibra_release_is_pinned(self):
        installer = (
            REPO_ROOT / "installer" / "lib" / "vibra.sh"
        ).read_text(encoding="utf-8")
        assert 'VIBRA_VERSION="v1.0.0"' in installer
        assert '--branch "${VIBRA_VERSION}"' in installer
        assert "--depth 1" in installer
        assert 'VIBRA_BRANCH=' not in installer

    def test_installer_summary_names_pinned_vibra_release(self):
        installer = (REPO_ROOT / "autostream_install.sh").read_text(encoding="utf-8")
        assert (
            "Build and install vibra-mini ${VIBRA_VERSION} "
            "for optional track identification"
        ) in installer


class TestVibraMiniUpdateFastPath:
    """update_vibra_from_source() must skip the fetch/build/deploy cycle when
    the running daemon already reports the pinned release, mirroring
    install_owntone_mini_from_source()'s version probe (installer/lib/owntone.sh)."""

    VIBRA_SH = REPO_ROOT / "installer" / "lib" / "vibra.sh"

    @staticmethod
    def _serve_once(sock_path: str, reply: str | None) -> "threading.Thread":
        """Bind a Unix socket, accept exactly one connection, optionally send
        *reply*, then close. Runs in a background thread so the bash-side
        client can connect to a real, live socket."""
        import socket as socket_mod
        import threading

        srv = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM)
        srv.bind(sock_path)
        srv.listen(1)

        def _run():
            conn, _ = srv.accept()
            try:
                conn.recv(4096)
                if reply is not None:
                    conn.sendall((reply + "\n").encode())
            finally:
                conn.close()
                srv.close()

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return t

    def _run_update(
        self,
        tmp_path,
        sock_path: str,
        stamp_path: str | None = None,
        stamp_content: str | None = None,
        binary_present: bool = False,
    ) -> subprocess.CompletedProcess:
        # Stamp path and install prefix are always pinned into tmp_path: a
        # real stamp/binary left on the machine running these tests must
        # never leak into the result.
        stamp_path = stamp_path or str(tmp_path / "vibra-mini-version")
        install_prefix = tmp_path / "vibra-install-prefix"
        if binary_present:
            bin_dir = install_prefix / "bin"
            bin_dir.mkdir(parents=True, exist_ok=True)
            binary = bin_dir / "vibra-mini"
            binary.write_text("#!/bin/sh\n", encoding="utf-8")
            binary.chmod(0o755)
        if stamp_content is not None:
            Path(stamp_path).write_text(stamp_content, encoding="utf-8")

        script = f'''
set -euo pipefail
info() {{ echo "INFO: $*"; }}
warn() {{ echo "WARN: $*"; }}
error() {{ echo "ERROR: $*"; }}
source "{self.VIBRA_SH.as_posix()}"
VIBRA_SOCKET_PATH="{sock_path}"
VIBRA_VERSION_STAMP="{Path(stamp_path).as_posix()}"
VIBRA_INSTALL_PREFIX="{install_prefix.as_posix()}"
build_and_install_vibra_from_source() {{ echo "BUILD_CALLED"; }}
update_vibra_from_source
'''
        return subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, timeout=15,
        )

    @bash_capable
    def test_matching_version_skips_build(self, tmp_path):
        sock_path = str(tmp_path / "vibra-mini.sock")
        self._serve_once(sock_path, '{"ok": true, "type": "pong", "version": "1.0.0"}')
        result = self._run_update(tmp_path, sock_path)
        assert result.returncode == 0, result.stderr
        assert "already installed; skipping" in result.stdout
        assert "(running daemon)" in result.stdout
        assert "BUILD_CALLED" not in result.stdout

    @bash_capable
    def test_matching_version_daemon_skip_writes_stamp(self, tmp_path):
        # Seeding the stamp here lets a subsequent update converge to the
        # (version stamp) fast path even if the daemon is stopped first.
        sock_path = str(tmp_path / "vibra-mini.sock")
        stamp_path = str(tmp_path / "vibra-mini-version")
        self._serve_once(sock_path, '{"ok": true, "type": "pong", "version": "1.0.0"}')
        result = self._run_update(tmp_path, sock_path, stamp_path=stamp_path)
        assert result.returncode == 0, result.stderr
        assert Path(stamp_path).read_text(encoding="utf-8") == "v1.0.0"

    @bash_capable
    def test_mismatched_version_runs_full_build(self, tmp_path):
        sock_path = str(tmp_path / "vibra-mini.sock")
        self._serve_once(sock_path, '{"ok": true, "type": "pong", "version": "0.9.0"}')
        result = self._run_update(tmp_path, sock_path)
        assert result.returncode == 0, result.stderr
        assert "already installed; skipping" not in result.stdout
        assert "BUILD_CALLED" in result.stdout
        assert "Updating vibra-mini" in result.stdout

    @bash_capable
    def test_probe_failure_runs_full_build(self, tmp_path):
        # Server accepts the connection but sends no reply: the handshake
        # yields no usable version, so the probe must be treated as a miss.
        sock_path = str(tmp_path / "vibra-mini.sock")
        self._serve_once(sock_path, None)
        result = self._run_update(tmp_path, sock_path)
        assert result.returncode == 0, result.stderr
        assert "already installed; skipping" not in result.stdout
        assert "BUILD_CALLED" in result.stdout

    @bash_capable
    def test_fresh_install_no_socket_runs_full_build(self, tmp_path):
        # Nothing has ever been installed: no socket file exists at all.
        sock_path = str(tmp_path / "vibra-mini.sock")
        result = self._run_update(tmp_path, sock_path)
        assert result.returncode == 0, result.stderr
        assert "already installed; skipping" not in result.stdout
        assert "BUILD_CALLED" in result.stdout

    @bash_capable
    def test_socket_down_stamp_matches_and_binary_present_skips_build(self, tmp_path):
        # The daemon was stopped ahead of this step (no socket at all), but
        # a prior successful build's stamp plus its binary are still there.
        sock_path = str(tmp_path / "vibra-mini.sock")
        result = self._run_update(
            tmp_path, sock_path, stamp_content="v1.0.0", binary_present=True,
        )
        assert result.returncode == 0, result.stderr
        assert "already installed; skipping" in result.stdout
        assert "(version stamp)" in result.stdout
        assert "BUILD_CALLED" not in result.stdout

    @bash_capable
    def test_socket_down_stamp_matches_but_binary_missing_runs_full_build(self, tmp_path):
        # Stamp says the pinned release was built, but the binary it names
        # is gone -- do not trust the stamp alone.
        sock_path = str(tmp_path / "vibra-mini.sock")
        result = self._run_update(
            tmp_path, sock_path, stamp_content="v1.0.0", binary_present=False,
        )
        assert result.returncode == 0, result.stderr
        assert "already installed; skipping" not in result.stdout
        assert "BUILD_CALLED" in result.stdout

    @bash_capable
    def test_socket_down_stamp_stale_runs_full_build(self, tmp_path):
        sock_path = str(tmp_path / "vibra-mini.sock")
        result = self._run_update(
            tmp_path, sock_path, stamp_content="v0.9.0", binary_present=True,
        )
        assert result.returncode == 0, result.stderr
        assert "already installed; skipping" not in result.stdout
        assert "BUILD_CALLED" in result.stdout

    @bash_capable
    def test_successful_build_writes_stamp(self, tmp_path):
        # The stamp write is real function code, not stubbed away: only the
        # network/compiler-dependent inner steps are replaced with no-ops.
        stamp_path = tmp_path / "vibra-mini-version"
        install_prefix = tmp_path / "vibra-install-prefix"
        script = f'''
set -euo pipefail
info() {{ echo "INFO: $*"; }}
warn() {{ echo "WARN: $*"; }}
error() {{ echo "ERROR: $*"; }}
source "{self.VIBRA_SH.as_posix()}"
VIBRA_VERSION_STAMP="{stamp_path.as_posix()}"
VIBRA_INSTALL_PREFIX="{install_prefix.as_posix()}"
install_vibra_build_dependencies() {{ :; }}
clone_vibra_source() {{ mkdir -p "$1"; }}
cmake() {{
  mkdir -p "${{VIBRA_INSTALL_PREFIX}}/bin"
  : > "${{VIBRA_INSTALL_PREFIX}}/bin/vibra-mini"
  chmod +x "${{VIBRA_INSTALL_PREFIX}}/bin/vibra-mini"
}}
build_and_install_vibra_from_source
'''
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, result.stderr
        assert stamp_path.read_text(encoding="utf-8") == "v1.0.0"


class TestOwntoneMiniPinnedRelease:
    """The owntone-mini build is bound to a tagged release, for installs and
    updates alike, mirroring the vibra-mini pin."""

    def _installer_text(self) -> str:
        return (
            REPO_ROOT / "installer" / "lib" / "owntone.sh"
        ).read_text(encoding="utf-8")

    def test_owntone_mini_release_is_pinned(self):
        installer = self._installer_text()
        assert re.search(r'^OWNTONE_MINI_VERSION="\d+\.\d+\.\d+"', installer, re.M)
        assert '--branch "${OWNTONE_MINI_VERSION}"' in installer
        assert "--depth 1" in installer
        assert "--branch minimal" not in installer

    def test_exact_tag_verified_after_clone(self):
        installer = self._installer_text()
        assert "describe --tags --exact-match" in installer
        assert 'checked_out_tag}" != "${OWNTONE_MINI_VERSION}"' in installer

    def test_skip_fast_path_keyed_on_product_and_pinned_version(self):
        # An appliance already running the pinned release must not pay the
        # ~10-minute source rebuild on update; the probe must match both the
        # product name (stock OwnTone is not a match) and the exact version.
        installer = self._installer_text()
        assert '"owntone-mini ${OWNTONE_MINI_VERSION}"' in installer

    def test_update_tool_default_matches_installer_pin(self):
        installer = self._installer_text()
        pin = re.search(r'^OWNTONE_MINI_VERSION="([^"]+)"', installer, re.M)
        assert pin is not None
        tool = (
            REPO_ROOT / "tools" / "owntone_mini_update.sh"
        ).read_text(encoding="utf-8")
        default = re.search(r'^DEFAULT_REF="([^"]+)"', tool, re.M)
        assert default is not None, (
            "tools/owntone_mini_update.sh must declare DEFAULT_REF"
        )
        assert default.group(1) == pin.group(1), (
            "tools/owntone_mini_update.sh DEFAULT_REF must match "
            "installer/lib/owntone.sh OWNTONE_MINI_VERSION"
        )


class TestOwntoneMiniUpdateFastPath:
    """install_owntone_mini_from_source() must skip the fetch/build/deploy
    cycle both when the running daemon already reports the pinned release
    and, when that probe misses (e.g. the daemon was stopped ahead of an
    update), when a prior build's version stamp plus its binary confirm the
    pinned release is still in place; mirrors update_vibra_from_source()
    (installer/lib/vibra.sh)."""

    OWNTONE_SH = REPO_ROOT / "installer" / "lib" / "owntone.sh"

    def _run_install(
        self,
        tmp_path,
        reported_identity: str = "",
        stamp_path: str | None = None,
        stamp_content: str | None = None,
        binary_present: bool = False,
    ) -> subprocess.CompletedProcess:
        # Stamp path and binary path are always pinned into tmp_path: a real
        # stamp/binary left on the machine running these tests must never
        # leak into the result.
        stamp_path = stamp_path or str(tmp_path / "owntone-mini-version")
        binary_path = tmp_path / "owntone-binary" / "owntone"
        if binary_present:
            binary_path.parent.mkdir(parents=True, exist_ok=True)
            binary_path.write_text("#!/bin/sh\n", encoding="utf-8")
            binary_path.chmod(0o755)
        if stamp_content is not None:
            Path(stamp_path).write_text(stamp_content, encoding="utf-8")

        script = f'''
set -euo pipefail
info() {{ echo "INFO: $*"; }}
warn() {{ echo "WARN: $*"; }}
error() {{ echo "ERROR: $*"; }}
update_progress() {{ :; }}
apt_install() {{ echo "APT_INSTALL $*"; }}
dpkg() {{ return 1; }}
systemctl() {{ echo "SYSTEMCTL $*"; }}
git() {{
  if [[ "$1" == "clone" ]]; then
    local dest="${{@: -1}}"
    mkdir -p "$dest"
    printf '#!/bin/sh\\nexit 0\\n' > "$dest/configure"
    chmod +x "$dest/configure"
    return 0
  elif [[ "$1" == "-C" ]]; then
    echo "${{OWNTONE_MINI_VERSION}}"
    return 0
  fi
}}
autoreconf() {{ :; }}
make() {{ echo "MAKE_CALLED $*"; }}
source "{self.OWNTONE_SH.as_posix()}"
OWNTONE_MINI_VERSION_STAMP="{Path(stamp_path).as_posix()}"
OWNTONE_MINI_BINARY="{binary_path.as_posix()}"
owntone_mini_reported_identity() {{ printf '%s' "{reported_identity}"; }}
install_owntone_mini_from_source
'''
        return subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, timeout=15,
        )

    @bash_capable
    def test_daemon_reports_pinned_version_skips_build(self, tmp_path):
        result = self._run_install(
            tmp_path, reported_identity="owntone-mini 1.1.1",
        )
        assert result.returncode == 0, result.stderr
        assert "already installed; skipping source rebuild" in result.stdout
        assert "(running daemon)" in result.stdout
        assert "MAKE_CALLED" not in result.stdout

    @bash_capable
    def test_daemon_reports_pinned_version_skip_writes_stamp(self, tmp_path):
        # Seeding the stamp here lets a subsequent update converge to the
        # (version stamp) fast path even if the daemon is stopped first.
        stamp_path = str(tmp_path / "owntone-mini-version")
        result = self._run_install(
            tmp_path, reported_identity="owntone-mini 1.1.1", stamp_path=stamp_path,
        )
        assert result.returncode == 0, result.stderr
        assert Path(stamp_path).read_text(encoding="utf-8") == "1.1.1"

    @bash_capable
    def test_daemon_down_stamp_matches_and_binary_present_skips_build(self, tmp_path):
        # The daemon was stopped ahead of this step (empty probe reply), but
        # a prior successful build's stamp plus its binary are still there.
        result = self._run_install(
            tmp_path, reported_identity="", stamp_content="1.1.1", binary_present=True,
        )
        assert result.returncode == 0, result.stderr
        assert "already installed; skipping source rebuild" in result.stdout
        assert "(version stamp)" in result.stdout
        assert "MAKE_CALLED" not in result.stdout

    @bash_capable
    def test_stamp_matches_but_binary_missing_runs_full_build(self, tmp_path):
        # Stamp says the pinned release was built, but the binary it names
        # is gone -- do not trust the stamp alone.
        result = self._run_install(
            tmp_path, reported_identity="", stamp_content="1.1.1", binary_present=False,
        )
        assert result.returncode == 0, result.stderr
        assert "already installed; skipping source rebuild" not in result.stdout
        assert "MAKE_CALLED" in result.stdout
        assert "Installing OwnTone Mini" in result.stdout

    @bash_capable
    def test_stamp_stale_runs_full_build(self, tmp_path):
        result = self._run_install(
            tmp_path, reported_identity="", stamp_content="1.1.0", binary_present=True,
        )
        assert result.returncode == 0, result.stderr
        assert "already installed; skipping source rebuild" not in result.stdout
        assert "MAKE_CALLED" in result.stdout

    @bash_capable
    def test_no_stamp_no_daemon_runs_full_build(self, tmp_path):
        # Nothing has ever been installed: no daemon answers, no stamp exists.
        result = self._run_install(tmp_path, reported_identity="")
        assert result.returncode == 0, result.stderr
        assert "already installed; skipping source rebuild" not in result.stdout
        assert "MAKE_CALLED" in result.stdout

    @bash_capable
    def test_successful_build_writes_stamp(self, tmp_path):
        # The stamp write is real function code, not stubbed away: only the
        # network/compiler-dependent inner steps are replaced with no-ops.
        result = self._run_install(tmp_path, reported_identity="")
        assert result.returncode == 0, result.stderr
        stamp_path = tmp_path / "owntone-mini-version"
        assert stamp_path.read_text(encoding="utf-8") == "1.1.1"


# ---------------------------------------------------------------------------
# Uninstaller hands Wi-Fi profiles back to NetworkManager
# ---------------------------------------------------------------------------

class TestUninstallRestoresWifiProfiles:
    """autostream_uninstall.sh must undo the wifi watcher's autoconnect=no
    policy (migrate_client_profiles_autoconnect_no in platform/wifi_config.py)
    and any BSSID/interface-name pins, and must remove leftover AP profiles,
    so a Wi-Fi-only headless device is not stranded after uninstall."""

    def _uninstall_text(self) -> str:
        return (REPO_ROOT / "autostream_uninstall.sh").read_text(encoding="utf-8")

    def test_restores_autoconnect(self):
        text = self._uninstall_text()
        assert "connection.autoconnect yes" in text, (
            "uninstaller must restore connection.autoconnect yes on Wi-Fi client profiles"
        )

    def test_clears_bssid_pin(self):
        text = self._uninstall_text()
        assert "802-11-wireless.bssid" in text, (
            "uninstaller must clear any 802-11-wireless.bssid pin left by the wifi watcher"
        )

    def test_clears_interface_name_restriction(self):
        text = self._uninstall_text()
        assert "connection.interface-name" in text, (
            "uninstaller must clear any connection.interface-name restriction"
        )

    def test_deletes_ap_mode_profiles(self):
        text = self._uninstall_text()
        assert re.search(r'802-11-wireless\.mode', text), (
            "uninstaller must inspect 802-11-wireless.mode to distinguish AP from client profiles"
        )
        assert re.search(r'"ap"', text), (
            "uninstaller must check for mode \"ap\" to identify leftover AP/Hotspot profiles"
        )
        assert "nmcli connection delete" in text, (
            "uninstaller must delete leftover AP-mode profiles rather than restoring autoconnect on them"
        )

    def test_sweep_filters_on_wifi_connection_type(self):
        text = self._uninstall_text()
        assert "802-11-wireless" in text
        assert "TYPE" in text or "-f UUID,TYPE" in text, (
            "uninstaller must filter the connection sweep to Wi-Fi (TYPE=802-11-wireless) "
            "so wired/ethernet connections are provably untouched"
        )

    def test_sweep_is_placed_before_path_removal(self):
        """The Wi-Fi handback must run while nmcli/NetworkManager state is still
        addressable, i.e. before the uninstaller starts ripping out autostream's
        own files."""
        text = self._uninstall_text()
        restore_idx = text.find("restore_wifi_profiles")
        remove_idx = text.find('info "Removing autostream application files"')
        assert restore_idx != -1 and remove_idx != -1
        assert restore_idx < remove_idx

    def test_sweep_is_best_effort_without_nmcli(self):
        text = self._uninstall_text()
        assert "command -v nmcli" in text, (
            "uninstaller must guard the sweep with command -v nmcli so a missing "
            "nmcli does not abort the uninstall"
        )

    @bash_capable
    def test_bash_n_syntax(self):
        result = subprocess.run(
            ["bash", "-n", str(REPO_ROOT / "autostream_uninstall.sh")],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0, (
            f"bash -n failed for autostream_uninstall.sh:\n{result.stderr.strip()}"
        )


# ---------------------------------------------------------------------------
# shellcheck (skipped when not installed)
# ---------------------------------------------------------------------------

class TestShellCheck:
    @shellcheck_available
    @pytest.mark.parametrize("script", INSTALLER_SCRIPTS, ids=[p.name for p in INSTALLER_SCRIPTS])
    def test_shellcheck(self, script):
        if not script.exists():
            pytest.skip(f"{script.name} does not exist")
        result = subprocess.run(
            ["shellcheck", "--severity=error", str(script)],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, (
            f"shellcheck errors in {script.name}:\n{result.stdout}"
        )


# ---------------------------------------------------------------------------
# detect_install_version — installer/dial/helpers.sh
# ---------------------------------------------------------------------------

class TestDetectInstallVersion:
    """detect_install_version() strips refs/tags/ prefix and v prefix."""

    def _detect(self, tag: str | None) -> str:
        env_extra = f'AUTOSTREAM_RELEASE_TAG={tag!r} ' if tag is not None else ''
        script = f"""
set -euo pipefail
source "{(REPO_ROOT / 'installer' / 'dial' / 'helpers.sh').as_posix()}"
{f'AUTOSTREAM_RELEASE_TAG={tag!r}' if tag is not None else 'unset AUTOSTREAM_RELEASE_TAG'}
detect_install_version
"""
        r = subprocess.run(
            ["bash", "-c", script],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            pytest.fail(f"bash script failed: {r.stderr}")
        return r.stdout.strip()

    @bash_capable
    def test_refs_tags_prefix_stripped(self):
        assert self._detect("refs/tags/v2.1.0") == "2.1.0"

    @bash_capable
    def test_v_prefix_stripped(self):
        assert self._detect("v2.1.0") == "2.1.0"

    @bash_capable
    def test_plain_version_unchanged(self):
        assert self._detect("2.1.0") == "2.1.0"

    @bash_capable
    def test_unset_tag_returns_unknown(self):
        assert self._detect(None) == "unknown"

    @bash_capable
    def test_empty_tag_returns_unknown(self):
        assert self._detect("") == "unknown"


# ---------------------------------------------------------------------------
# Schema compatibility: installer writes quoted values, consumers strip quotes
# ---------------------------------------------------------------------------

def _load_dial_updater(tmp_path: Path) -> ModuleType:
    mod = load_supervisor_script("autostream_dial_updater", "dial_updater_p3")
    mod.STATE_DIR = tmp_path
    return mod


def _load_admin(tmp_path: Path) -> ModuleType:
    import io
    mod = load_supervisor_script("autostream_admin", "admin_p3")
    mod.UPDATE_RESULT_FILE = tmp_path / "update-result.env"
    mod.STAMP_DIR = tmp_path
    mod._INSTALL_LOG = tmp_path / "autostream_install.log"
    return mod


def _run_admin_update_status(mod) -> dict:
    import io
    from io import StringIO
    buf = StringIO()
    with patch("builtins.print", side_effect=lambda s, **_: buf.write(s + "\n")):
        mod.read_update_status()
    return json.loads(buf.getvalue().strip())


sys.path.insert(0, str(REPO_ROOT / "dial"))
import dial_http_server as dhs


class TestInstallerWriteUpdateResultSchema:
    """Main installer uses quoted KEY="value" format.
    All consumers must correctly strip those quotes.
    """

    def _write_installer_format(self, tmp_path: Path, status: str, message: str,
                                percent: int) -> Path:
        """Mimic the installer's write_update_result quoting style."""
        result_file = tmp_path / "update-result.env"
        result_file.write_text(
            f'LAST_RUN_AT="2026-01-01T00:00:00+00:00"\n'
            f'STATUS="{status}"\n'
            f'MESSAGE="{message}"\n'
            f'PERCENT_COMPLETE="{percent}"\n',
            encoding="utf-8",
        )
        return result_file

    @pytest.mark.parametrize("status,expected_public", [
        ("in_progress", "running"),
        ("success",     "complete"),
        ("failure",     "failed"),
    ])
    def test_quoted_status_readable_by_dial_http(self, tmp_path, status, expected_public):
        result_file = self._write_installer_format(tmp_path, status, "msg", 0)
        with patch.object(dhs, "_UPDATE_RESULT_PATH", result_file):
            public = dhs._read_update_state()
        assert public == expected_public, (
            f'Quoted STATUS="{status}" should map to {expected_public!r}, got {public!r}'
        )

    @pytest.mark.parametrize("status", ["in_progress", "success", "failure"])
    def test_quoted_status_readable_by_admin(self, tmp_path, status):
        result_file = self._write_installer_format(tmp_path, status, "Test message", 50)
        mod = _load_admin(tmp_path)
        with patch.object(mod, "_read_log_tail", return_value=""), \
             patch.object(mod, "_is_stale_in_progress", return_value=False):
            data = _run_admin_update_status(mod)
        assert data["ok"] is True
        assert data["status"] == status

    def test_quoted_percent_is_parsed_as_integer(self, tmp_path):
        result_file = self._write_installer_format(tmp_path, "success", "done", 100)
        mod = _load_admin(tmp_path)
        with patch.object(mod, "_read_log_tail", return_value=""), \
             patch.object(mod, "_is_stale_in_progress", return_value=False):
            data = _run_admin_update_status(mod)
        assert data["percent"] == 100

    def test_quoted_message_with_spaces_is_preserved(self, tmp_path):
        msg = "Installing new version 2.1.0"
        result_file = self._write_installer_format(tmp_path, "in_progress", msg, 25)
        mod = _load_admin(tmp_path)
        with patch.object(mod, "_read_log_tail", return_value=""), \
             patch.object(mod, "_is_stale_in_progress", return_value=False):
            data = _run_admin_update_status(mod)
        assert data["message"] == msg

    def test_unquoted_and_quoted_formats_produce_same_status(self, tmp_path):
        """Both formats must reach the same public state for in_progress."""
        # Unquoted (dial updater style)
        unquoted = tmp_path / "unquoted.env"
        unquoted.write_text(
            "STATUS=in_progress\nPERCENT_COMPLETE=0\nMESSAGE=msg\nLAST_RUN_AT=2026-01-01T00:00:00+00:00\n",
            encoding="utf-8",
        )
        # Quoted (main installer style)
        quoted = tmp_path / "quoted.env"
        quoted.write_text(
            'STATUS="in_progress"\nPERCENT_COMPLETE="0"\nMESSAGE="msg"\nLAST_RUN_AT="2026-01-01T00:00:00+00:00"\n',
            encoding="utf-8",
        )
        with patch.object(dhs, "_UPDATE_RESULT_PATH", unquoted):
            unquoted_public = dhs._read_update_state()
        with patch.object(dhs, "_UPDATE_RESULT_PATH", quoted):
            quoted_public = dhs._read_update_state()
        assert unquoted_public == quoted_public == "running", (
            f"Quoted and unquoted formats diverged: {unquoted_public!r} vs {quoted_public!r}"
        )


# ---------------------------------------------------------------------------
# CGI script existence and executability
# ---------------------------------------------------------------------------

class TestCgiScripts:
    def test_update_status_cgi_exists(self):
        cgi = REPO_ROOT / "nginx" / "cgi" / "update-status.cgi"
        assert cgi.exists(), "update-status.cgi not found"

    def test_update_status_cgi_has_bash_shebang(self):
        cgi = REPO_ROOT / "nginx" / "cgi" / "update-status.cgi"
        first_line = cgi.read_text(encoding="utf-8").splitlines()[0]
        assert first_line.startswith("#!"), "CGI script must have a shebang line"
        assert "bash" in first_line or "sh" in first_line, (
            f"CGI shebang must reference bash or sh: {first_line!r}"
        )

    @bash_capable
    def test_cgi_script_passes_bash_n(self):
        cgi = REPO_ROOT / "nginx" / "cgi" / "update-status.cgi"
        result = subprocess.run(
            ["bash", "-n", str(cgi)],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0, (
            f"bash -n failed for update-status.cgi:\n{result.stderr}"
        )

    def test_cgi_references_autostream_admin(self):
        cgi = REPO_ROOT / "nginx" / "cgi" / "update-status.cgi"
        content = cgi.read_text(encoding="utf-8")
        assert "autostream_admin" in content, (
            "update-status.cgi must reference autostream_admin"
        )

    def test_cgi_uses_sudo_n_for_unprivileged_execution(self):
        cgi = REPO_ROOT / "nginx" / "cgi" / "update-status.cgi"
        content = cgi.read_text(encoding="utf-8")
        assert "sudo" in content and ("-n" in content or "--non-interactive" in content), (
            "CGI must use sudo -n to run autostream_admin without a password"
        )
