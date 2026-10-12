"""A dial's identity: one derivation everywhere, and a new identity on factory reset.

The same set of vectors runs against the three places that derive a dial's
identity (the privileged helper, the installer's shell function and the core
identity module), so they cannot drift apart. The reset, the start-up
reconcile, update, reinstall and uninstall are then checked on the files they
touch, in a scratch root.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from conftest import load_supervisor_script  # noqa: E402
from test_dial_staged_install import (  # noqa: E402
    Env, REPO_ROOT, bash_capable, posix_only,
)
from test_dial_installer_hardening import (  # noqa: E402
    WORKING_RM, _real_python3, _run_uninstaller, _uninstall_sandbox,
)

for _p in (REPO_ROOT / "core", REPO_ROOT / "dial"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import autostream_appliance_identity as identity  # noqa: E402
import autostream_dials  # noqa: E402
import dial_config  # noqa: E402

m = load_supervisor_script("autostream_admin", "admin_dial_identity")

SERIAL = "00000000abcdef12"
FALLBACK = "0123456789abcdef0123"
SALT_A = "00112233445566778899aabbccddeeff"
SALT_B = "ffeeddccbbaa99887766554433221100"

# serial, fallback id file, salt, identity. The first row is the identity every
# dial installed so far has: the same value the original derivation gives.
VECTORS = [
    pytest.param(SERIAL, None, None, "fa54e5a89180d01053e0", id="unsalted-serial"),
    pytest.param(SERIAL, None, SALT_A, "5a51ead2f359f9ad69d5", id="salted-serial-a"),
    pytest.param(SERIAL, None, SALT_B, "7f05b4c5571831a46a48", id="salted-serial-b"),
    pytest.param("", FALLBACK, None, FALLBACK, id="unsalted-fallback"),
    pytest.param("", FALLBACK, SALT_A, "0798dc5ed63feab9393b", id="salted-fallback"),
]

BAD_SALTS = [
    pytest.param("", id="empty"),
    pytest.param("  \n", id="blank"),
    pytest.param("not hex at all", id="not-hex"),
    pytest.param(SALT_A.upper(), id="upper-case"),
    pytest.param(SALT_A[:-1], id="too-short"),
    pytest.param(SALT_A + "0", id="too-long"),
    pytest.param(SALT_A + "\n" + SALT_B, id="two-lines"),
]

OLD_UUID = "fa54e5a89180d01053e0"
HW = {"clk_gpio": 5, "dt_gpio": 6, "sw_gpio": 13, "led_gpio": None, "port": 7842,
      "uuid": OLD_UUID, "display": {"fitted": True, "screen_type": "hd_kiosk"}}
INSTALL_STATE = ("AUTOSTREAM_PRODUCT=autostream-dial\n"
                 f"DIAL_UUID={OLD_UUID}\n"
                 "AUTOSTREAM_RELEASE_TAG=1.2.0\n"
                 "SDMON_METHOD=fast\n")


# ---------------------------------------------------------------------------
# The privileged helper, over a scratch root
# ---------------------------------------------------------------------------

class _Dial:
    """The files of a dial, under a scratch directory."""

    def __init__(self, tmp: Path, monkeypatch):
        self.state = tmp / "var" / "lib" / "autostream"
        self.etc = tmp / "etc" / "autostream"
        self.proc = tmp / "proc"
        for d in (self.state, self.etc, self.proc):
            d.mkdir(parents=True)
        self.salt = self.etc / "dial-id-salt"
        self.legacy_salt = self.state / "dial-id-salt"
        self.fallback = self.state / "dial-id"
        self.hw = self.etc / "autostream-dial.json"
        self.install_state = self.state / "install-state.env"
        self.cpuinfo = self.proc / "cpuinfo"
        self.chowns: list[tuple[str, int, int]] = []
        monkeypatch.setattr(m, "DIAL_ID_SALT_FILE", self.salt)
        monkeypatch.setattr(m, "LEGACY_DIAL_ID_SALT_FILE", self.legacy_salt, raising=False)
        # Tests run unprivileged: the files they make belong to the invoking user,
        # who stands in for root.
        monkeypatch.setattr(m, "ROOT_UID", os.getuid(), raising=False)
        monkeypatch.setattr(m, "DIAL_ID_FALLBACK_FILE", self.fallback)
        monkeypatch.setattr(m, "DIAL_HW_CONFIG_FILE", self.hw)
        monkeypatch.setattr(m, "INSTALL_STATE_FILE", self.install_state)
        monkeypatch.setattr(m, "CPUINFO_FILE", self.cpuinfo)
        monkeypatch.setattr(m, "DEVICE_TREE_SERIAL_FILE", self.proc / "serial-number")
        monkeypatch.setattr(m.os, "chown",
                            lambda p, u, g: self.chowns.append((Path(p).name, u, g)),
                            raising=False)
        monkeypatch.setattr(m.os, "fchown",
                            lambda fd, u, g: self.chowns.append((u, g)), raising=False)
        self.set_serial(SERIAL)
        self.hw.write_text(json.dumps(HW, indent=2), encoding="utf-8")
        self.install_state.write_text(INSTALL_STATE, encoding="utf-8")

    def set_serial(self, serial: str) -> None:
        self.cpuinfo.write_text(
            "processor\t: 0\n" + (f"Serial\t\t: {serial}\n" if serial else ""),
            encoding="utf-8")

    def hw_uuid(self) -> str:
        return json.loads(self.hw.read_text(encoding="utf-8"))["uuid"]

    def state_uuid(self) -> str:
        for line in self.install_state.read_text(encoding="utf-8").splitlines():
            if line.startswith("DIAL_UUID="):
                return line.split("=", 1)[1]
        return ""

    def snapshot(self) -> dict:
        return {p.name: p.read_bytes() for p in (self.hw, self.install_state, self.salt)
                if p.exists()}


@pytest.fixture
def dial(tmp_path, monkeypatch):
    return _Dial(tmp_path, monkeypatch)


@posix_only
class TestHelperDerivation:
    @pytest.mark.parametrize("serial, fallback, salt, expected", VECTORS)
    def test_the_helper_derives_the_pinned_identity(self, dial, serial, fallback, salt, expected):
        dial.set_serial(serial)
        if fallback:
            dial.fallback.write_text(fallback, encoding="utf-8")
        assert m.derive_dial_id(salt) == expected

    def test_a_board_with_no_serial_and_no_fallback_has_no_identity(self, dial):
        dial.set_serial("")
        assert m.derive_dial_id(None) is None
        assert m.derive_dial_id(SALT_A) is None

    def test_a_damaged_fallback_file_is_not_used(self, dial):
        dial.set_serial("")
        dial.fallback.write_text("short", encoding="utf-8")
        assert m.derive_dial_id(None) is None

    def test_the_serial_is_read_from_the_device_tree_when_cpuinfo_has_none(self, dial):
        dial.set_serial("")
        (dial.proc / "serial-number").write_bytes(SERIAL.encode() + b"\x00")
        assert m.derive_dial_id(None) == "fa54e5a89180d01053e0"

    def test_a_salt_changes_the_identity_and_the_same_salt_gives_it_again(self, dial):
        unsalted = m.derive_dial_id(None)
        first = m.derive_dial_id(SALT_A)
        assert first != unsalted
        assert m.derive_dial_id(SALT_A) == first
        assert m.derive_dial_id(SALT_B) != first

    def test_the_identity_keeps_its_length_and_alphabet_for_any_salt(self, dial):
        import secrets
        for _ in range(100):
            assert re.fullmatch(r"[0-9a-f]{20}", m.derive_dial_id(secrets.token_hex(16)))


@posix_only
class TestHelperSaltRule:
    def test_no_salt_file_means_an_unsalted_dial(self, dial):
        assert m._read_dial_id_salt() is None

    def test_a_valid_salt_is_read_back(self, dial):
        dial.salt.write_text(SALT_A + "\n", encoding="utf-8")
        assert m._read_dial_id_salt() == SALT_A

    @pytest.mark.parametrize("text", BAD_SALTS)
    def test_a_malformed_salt_is_an_error_not_another_identity(self, dial, text):
        dial.salt.write_text(text, encoding="utf-8")
        with pytest.raises(ValueError):
            m._read_dial_id_salt()

    @pytest.mark.parametrize("text", BAD_SALTS)
    def test_reconcile_leaves_every_copy_alone_when_the_salt_is_malformed(self, dial, text):
        dial.salt.write_text(text, encoding="utf-8")
        before = dial.snapshot()
        assert m.reconcile_dial_identity() is False
        assert dial.snapshot() == before


# ---------------------------------------------------------------------------
# The installer's shell function and the core module give the same answers
# ---------------------------------------------------------------------------

@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def _installer_identity(env: Env, serial: str, fallback, salt):
    _real_python3(env)
    env.put("proc/cpuinfo", "processor\t: 0\n" + (f"Serial\t\t: {serial}\n" if serial else ""))
    if fallback:
        env.put("var/lib/autostream/dial-id", fallback)
    if salt is not None:
        env.put("etc/autostream/dial-id-salt", salt)
    return env.run("generate_dial_id", update="false")


@bash_capable
class TestInstallerDerivation:
    @pytest.mark.parametrize("serial, fallback, salt, expected", VECTORS)
    def test_the_installer_derives_the_pinned_identity(self, env, serial, fallback, salt, expected):
        r = _installer_identity(env, serial, fallback, salt)
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == expected

    @pytest.mark.parametrize("text", BAD_SALTS)
    def test_a_malformed_salt_stops_the_installer_with_no_identity(self, env, text):
        r = _installer_identity(env, SERIAL, None, text)
        assert r.returncode != 0
        assert r.stdout.strip() == ""
        assert "does not hold a valid salt" in r.stderr

    def test_the_installer_never_creates_or_changes_a_salt(self, env):
        _installer_identity(env, SERIAL, None, None)
        assert not (env.root / "etc/autostream/dial-id-salt").exists()
        env.put("etc/autostream/dial-id-salt", SALT_A + "\n")
        before = (env.root / "etc/autostream/dial-id-salt").read_bytes()
        env.run("generate_dial_id", update="false")
        assert (env.root / "etc/autostream/dial-id-salt").read_bytes() == before


class TestCoreDerivation:
    @staticmethod
    def _identity(tmp_path, serial, fallback, salt):
        salt_file = tmp_path / "dial-id-salt"
        fb_file = tmp_path / "dial-id"
        if salt is not None:
            salt_file.write_text(salt, encoding="utf-8")
        if fallback:
            fb_file.write_text(fallback, encoding="utf-8")
        with patch.object(identity, "get_cpu_serial", return_value=serial), \
             patch.object(identity, "DIAL_ID_SALT_FILE", salt_file), \
             patch.object(identity, "DIAL_ID_FILE", fb_file), \
             patch.object(identity, "_dial_id_cache", None), \
             patch.object(identity, "_dial_id_cache_set", False), \
             patch.object(identity, "_dial_id_error_logged", False):
            return identity.get_dial_id()

    @pytest.mark.parametrize("serial, fallback, salt, expected", VECTORS)
    def test_the_core_module_derives_the_pinned_identity(self, tmp_path, serial, fallback, salt,
                                                         expected):
        assert self._identity(tmp_path, serial, fallback, salt) == expected

    @pytest.mark.parametrize("text", BAD_SALTS)
    def test_a_malformed_salt_gives_no_identity(self, tmp_path, text):
        assert self._identity(tmp_path, SERIAL, None, text) is None


# ---------------------------------------------------------------------------
# The new identity is accepted wherever an identity is used
# ---------------------------------------------------------------------------

@posix_only
class TestNewIdentityIsAccepted:
    def test_the_appliance_reads_it_from_the_announcement(self, dial, monkeypatch):
        m._reset_dial_identity()
        uuid = dial.hw_uuid()
        monkeypatch.setattr(autostream_dials, "update_dial_sighting", lambda *a: None)
        parts = ["="] + [""] * 6 + ["10.0.0.9", "7842"]
        got = autostream_dials._parse_dial_event(parts, {"id": uuid, "name": "n"})
        assert got is not None and got[0] == uuid

    def test_the_dial_loads_it_as_its_own_identity(self, dial, tmp_path, monkeypatch):
        m._reset_dial_identity()
        monkeypatch.setattr(dial_config, "HW_CONFIG_PATH", dial.hw)
        monkeypatch.setattr(dial_config, "SETTINGS_PATH", tmp_path / "none.json")
        monkeypatch.setattr(dial_config, "INSTALL_STATE_PATH", dial.install_state)
        assert dial_config.load_config().uuid == dial.hw_uuid() != OLD_UUID

    def test_the_avahi_record_carries_it(self, dial, tmp_path, monkeypatch):
        m._reset_dial_identity()
        template = tmp_path / "template.service"
        template.write_text("<txt-record>id=__DIAL_UUID__</txt-record>"
                            "<txt-record>name=__DIAL_NAME__</txt-record>"
                            "<txt-record>version=__AUTOSTREAM_RELEASE_TAG__</txt-record>",
                            encoding="utf-8")
        service = tmp_path / "autostream-dial.service"
        monkeypatch.setattr(m, "_DIAL_TEMPLATE", template)
        monkeypatch.setattr(m, "_DIAL_SERVICE", service)
        monkeypatch.setattr(m, "_AVAHI_SERVICES_DIR", tmp_path)

        class Args:
            version, name, pin_recovery = "1.0", "Lounge", False
            uuid = dial.hw_uuid()

        assert m._update_dial_service(Args) == 0
        assert f"id={dial.hw_uuid()}<" in service.read_text(encoding="utf-8")

    def test_the_old_identity_stays_authorised_and_the_new_one_is_not(self, dial, tmp_path,
                                                                     monkeypatch):
        monkeypatch.setattr(autostream_dials, "DIALS_PATH", tmp_path / "dials.json")
        (tmp_path / "dials.json").write_text(
            json.dumps({OLD_UUID: {"name": "Lounge", "authorized_at": "x"}}), encoding="utf-8")
        m._reset_dial_identity()
        assert autostream_dials.dial_authorization(OLD_UUID) == autostream_dials.AUTH_AUTHORIZED
        assert autostream_dials.dial_authorization(dial.hw_uuid()) == \
            autostream_dials.AUTH_NOT_AUTHORIZED


# ---------------------------------------------------------------------------
# Factory reset
# ---------------------------------------------------------------------------

@posix_only
class TestFactoryResetIdentity:
    def test_a_reset_writes_a_fresh_salt_readable_by_root_only_to_change(self, dial):
        assert m._reset_dial_identity() is True
        salt = dial.salt.read_text(encoding="utf-8").strip()
        assert re.fullmatch(r"[0-9a-f]{32}", salt)
        assert oct(dial.salt.stat().st_mode & 0o777) == "0o644"
        assert (m.ROOT_UID, 0) in dial.chowns

    def test_every_stored_copy_holds_the_identity_derived_from_the_new_salt(self, dial):
        m._reset_dial_identity()
        salt = dial.salt.read_text(encoding="utf-8").strip()
        expected = m.derive_dial_id(salt)
        assert dial.hw_uuid() == expected
        assert dial.state_uuid() == expected
        assert expected != OLD_UUID

    def test_the_rest_of_the_hardware_config_and_install_state_survive(self, dial):
        m._reset_dial_identity()
        cfg = json.loads(dial.hw.read_text(encoding="utf-8"))
        assert {k: v for k, v in cfg.items() if k != "uuid"} == \
            {k: v for k, v in HW.items() if k != "uuid"}
        lines = dial.install_state.read_text(encoding="utf-8").splitlines()
        assert lines[0] == "AUTOSTREAM_PRODUCT=autostream-dial"
        assert lines[2:] == ["AUTOSTREAM_RELEASE_TAG=1.2.0", "SDMON_METHOD=fast"]

    def test_the_hardware_config_keeps_its_mode_and_owner(self, dial):
        dial.hw.chmod(0o640)
        st = dial.hw.stat()
        m._reset_dial_identity()
        assert oct(dial.hw.stat().st_mode & 0o777) == "0o640"
        assert (st.st_uid, st.st_gid) in dial.chowns

    def test_two_resets_give_two_different_identities(self, dial):
        m._reset_dial_identity()
        first = dial.hw_uuid()
        m._reset_dial_identity()
        assert dial.hw_uuid() != first
        assert dial.state_uuid() == dial.hw_uuid()

    def test_a_dial_that_cannot_derive_an_identity_keeps_the_one_it_has(self, dial):
        dial.set_serial("")
        before = dial.snapshot()
        assert m._reset_dial_identity() is False
        assert dial.snapshot() == before
        assert not dial.salt.exists()

    def test_the_whole_reset_runs_the_identity_step_after_the_services_stop(self, dial):
        order: list[str] = []
        real = m._reset_dial_identity

        def identity_step():
            order.append("identity")
            return real()

        with patch.object(m, "_acquire_reset_lock", return_value=object()), \
             patch.object(m, "_read_product", return_value="autostream-dial"), \
             patch.object(m, "_rotate_logs"), \
             patch.object(m, "_stop_service", side_effect=lambda n: order.append("stop") or True), \
             patch.object(m, "_reset_dial_identity", side_effect=identity_step), \
             patch.object(m, "_delete_wifi_connections", side_effect=lambda: order.append("wifi")), \
             patch.object(m, "FACTORY_RESET_DIAL_DELETE_FILES", ()), \
             patch.object(m, "run_cmd", return_value=(0, "", "")), \
             patch("pathlib.Path.exists", return_value=True):
            assert m._execute_factory_reset() is True
        assert order == ["stop", "stop", "stop", "identity", "wifi"]
        assert dial.hw_uuid() != OLD_UUID

    def test_a_failed_identity_step_does_not_stop_the_rest_of_the_reset(self, dial, tmp_path):
        dial.set_serial("")
        settings = tmp_path / "dial-settings.json"
        settings.write_text("{}", encoding="utf-8")
        with patch.object(m, "_acquire_reset_lock", return_value=object()), \
             patch.object(m, "_read_product", return_value="autostream-dial"), \
             patch.object(m, "_rotate_logs"), \
             patch.object(m, "_stop_service", return_value=True), \
             patch.object(m, "_delete_wifi_connections"), \
             patch.object(m, "FACTORY_RESET_DIAL_DELETE_FILES", (settings,)), \
             patch.object(m, "run_cmd", return_value=(0, "", "")), \
             patch("pathlib.Path.exists", return_value=True):
            assert m._execute_factory_reset() is True
        assert not settings.exists()
        assert dial.hw_uuid() == OLD_UUID

    def test_the_dial_forgets_the_appliance_records_it_keeps_on_disk(self):
        import dial_warnings
        assert Path(dial_warnings.WARNINGS_PATH) in m.FACTORY_RESET_DIAL_DELETE_FILES


@posix_only
class TestInterruptedResetHeals:
    def test_a_power_cut_after_the_salt_leaves_copies_that_the_next_start_repairs(self, dial):
        with patch.object(m, "_apply_dial_id", side_effect=RuntimeError("power cut")):
            with pytest.raises(RuntimeError):
                m._reset_dial_identity()
        assert dial.salt.exists()
        assert dial.hw_uuid() == OLD_UUID and dial.state_uuid() == OLD_UUID
        assert m.reconcile_dial_identity() is True
        expected = m.derive_dial_id(dial.salt.read_text(encoding="utf-8").strip())
        assert dial.hw_uuid() == expected == dial.state_uuid() != OLD_UUID

    def test_a_power_cut_between_the_two_copies_is_repaired_the_same_way(self, dial):
        real = m.write_file_safely

        def fail_on_install_state(path, *a, **kw):
            if path == dial.install_state:
                raise OSError("power cut")
            return real(path, *a, **kw)

        with patch.object(m, "write_file_safely", side_effect=fail_on_install_state):
            assert m._reset_dial_identity() is False
        assert dial.hw_uuid() != dial.state_uuid()
        assert m.reconcile_dial_identity() is True
        assert dial.hw_uuid() == dial.state_uuid()

    def test_reconcile_changes_nothing_when_the_copies_already_agree(self, dial):
        m._reset_dial_identity()
        before = dial.snapshot()
        with patch.object(m, "write_file_safely") as write:
            assert m.reconcile_dial_identity() is True
        write.assert_not_called()
        assert dial.snapshot() == before

    def test_reconcile_never_touches_a_dial_that_has_no_salt(self, dial):
        dial.hw.write_text(json.dumps({**HW, "uuid": "feedfacefeedfacefeed"}), encoding="utf-8")
        before = dial.snapshot()
        with patch.object(m, "write_file_safely") as write:
            assert m.reconcile_dial_identity() is True
        write.assert_not_called()
        assert dial.snapshot() == before

    def test_reconcile_runs_before_the_dial_service_starts(self):
        unit = (REPO_ROOT / "system" / "systemd" / "autostream_dial.service").read_text(
            encoding="utf-8").splitlines()
        pre = next(i for i, ln in enumerate(unit) if ln.startswith("ExecStartPre="))
        start = next(i for i, ln in enumerate(unit) if ln.startswith("ExecStart="))
        assert unit[pre] == ("ExecStartPre=-+/usr/local/libexec/autostream/autostream_admin "
                             "reconcile-dial-identity")
        assert pre < start

    def test_the_reconcile_verb_is_dispatched(self, dial):
        with patch.object(m.os, "geteuid", return_value=0, create=True):
            assert m.main(["reconcile-dial-identity"]) == 0


# ---------------------------------------------------------------------------
# What the service account can leave in its own directory does not steer root
# ---------------------------------------------------------------------------

@pytest.fixture
def victim(tmp_path):
    path = tmp_path / "victim"
    path.write_text("precious\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _untouched(victim: Path) -> bool:
    return (victim.read_text(encoding="utf-8") == "precious\n"
            and oct(victim.stat().st_mode & 0o777) == "0o600")


@posix_only
class TestRootWritesStayWhereTheyAreMeant:
    TEMP_NAMES = ("{n}.tmp", ".{n}.tmp", ".{n}.tmp.{pid}")

    def _plant_links(self, directory: Path, name: str, victim: Path) -> None:
        for pattern in self.TEMP_NAMES:
            (directory / pattern.format(n=name, pid=os.getpid())).symlink_to(victim)

    def test_a_reset_writes_nothing_through_links_at_the_temporary_names(self, dial, victim):
        self._plant_links(dial.state, "install-state.env", victim)
        self._plant_links(dial.state, "dial-id-salt", victim)
        self._plant_links(dial.etc, "dial-id-salt", victim)
        self._plant_links(dial.etc, "autostream-dial.json", victim)
        assert m._reset_dial_identity() is True
        assert _untouched(victim)
        assert dial.state_uuid() == dial.hw_uuid() != OLD_UUID

    def test_a_reconcile_writes_nothing_through_links_at_the_temporary_names(self, dial, victim):
        dial.salt.write_text(SALT_A + "\n", encoding="utf-8")
        self._plant_links(dial.state, "install-state.env", victim)
        self._plant_links(dial.etc, "autostream-dial.json", victim)
        assert m.reconcile_dial_identity() is True
        assert _untouched(victim)
        assert dial.state_uuid() == dial.hw_uuid() == m.derive_dial_id(SALT_A)

    def test_a_link_where_install_state_should_be_is_neither_read_nor_written_through(
            self, dial, victim):
        dial.salt.write_text(SALT_A + "\n", encoding="utf-8")
        victim.write_text("precious\nDIAL_UUID=" + OLD_UUID + "\n", encoding="utf-8")
        dial.install_state.unlink()
        dial.install_state.symlink_to(victim)
        assert m.reconcile_dial_identity() is False
        assert dial.install_state.is_symlink()
        assert victim.read_text(encoding="utf-8") == "precious\nDIAL_UUID=" + OLD_UUID + "\n"
        assert dial.hw_uuid() == m.derive_dial_id(SALT_A)

    def test_a_reset_replaces_a_link_where_install_state_is_and_leaves_its_target(
            self, dial, victim):
        dial.install_state.unlink()
        dial.install_state.symlink_to(victim)
        m._reset_dial_identity()
        assert _untouched(victim)

    def test_only_well_formed_lines_of_a_replaced_install_state_are_carried_over(self, dial):
        dial.salt.write_text(SALT_A + "\n", encoding="utf-8")
        dial.install_state.write_text(
            "AUTOSTREAM_PRODUCT=autostream-dial\n"
            f"DIAL_UUID={OLD_UUID}\n"
            "not a setting\n"
            "lower=case\n"
            "A B=C\n"
            "AUTOSTREAM_RELEASE_TAG=1.2.0\n", encoding="utf-8")
        assert m.reconcile_dial_identity() is True
        assert dial.install_state.read_text(encoding="utf-8").splitlines() == [
            "AUTOSTREAM_PRODUCT=autostream-dial",
            f"DIAL_UUID={m.derive_dial_id(SALT_A)}",
            "AUTOSTREAM_RELEASE_TAG=1.2.0",
        ]

    def test_the_identity_written_is_never_taken_from_a_file_the_service_account_can_write(
            self, dial):
        dial.salt.write_text(SALT_A + "\n", encoding="utf-8")
        planted = "feedfacefeedfacefeed"
        dial.install_state.write_text(f"DIAL_UUID={planted}\n", encoding="utf-8")
        dial.fallback.write_text(planted, encoding="utf-8")
        m.reconcile_dial_identity()
        assert dial.hw_uuid() == dial.state_uuid() == m.derive_dial_id(SALT_A) != planted

    def test_a_link_at_the_salt_is_refused(self, dial, tmp_path):
        elsewhere = tmp_path / "elsewhere"
        elsewhere.write_text(SALT_A + "\n", encoding="utf-8")
        dial.salt.symlink_to(elsewhere)
        before = dial.snapshot()
        with pytest.raises(ValueError):
            m._read_dial_id_salt()
        assert m.reconcile_dial_identity() is False
        assert dial.snapshot() == before

    def test_a_salt_the_service_account_owns_is_refused(self, dial, monkeypatch):
        dial.salt.write_text(SALT_A + "\n", encoding="utf-8")
        monkeypatch.setattr(m, "ROOT_UID", os.getuid() + 1)
        before = dial.snapshot()
        with pytest.raises(ValueError):
            m._read_dial_id_salt()
        assert m.reconcile_dial_identity() is False
        assert dial.snapshot() == before

    @pytest.mark.parametrize("mode", [0o664, 0o646, 0o666])
    def test_a_salt_that_others_can_write_is_refused(self, dial, mode):
        dial.salt.write_text(SALT_A + "\n", encoding="utf-8")
        dial.salt.chmod(mode)
        with pytest.raises(ValueError):
            m._read_dial_id_salt()
        assert m.reconcile_dial_identity() is False

    def test_a_salt_in_a_directory_others_can_write_is_refused(self, dial):
        dial.salt.write_text(SALT_A + "\n", encoding="utf-8")
        dial.etc.chmod(0o777)
        try:
            with pytest.raises(ValueError):
                m._read_dial_id_salt()
        finally:
            dial.etc.chmod(0o755)

    def test_a_salt_in_the_service_accounts_directory_is_not_used_as_the_salt(self, dial):
        dial.legacy_salt.write_text(SALT_A + "\n", encoding="utf-8")
        dial.legacy_salt.chmod(0o666)
        assert m.reconcile_dial_identity() is True
        assert not dial.salt.exists()
        assert dial.hw_uuid() == OLD_UUID
        assert dial.legacy_salt.exists()

    def test_a_link_in_place_of_the_fallback_id_gives_no_identity(self, dial, tmp_path):
        dial.set_serial("")
        elsewhere = tmp_path / "elsewhere"
        elsewhere.write_text(FALLBACK, encoding="utf-8")
        dial.fallback.symlink_to(elsewhere)
        assert m.derive_dial_id(None) is None

    def test_a_reset_refuses_nothing_and_changes_only_the_root_owned_salt(self, dial):
        m._reset_dial_identity()
        assert not dial.legacy_salt.exists()
        assert dial.salt.exists()
        assert [p.name for p in dial.state.iterdir() if p.name.endswith(".tmp")] == []
        assert [p.name for p in dial.etc.iterdir() if p.name.endswith(".tmp")] == []


@posix_only
class TestSaltMovesOutOfTheServiceAccountsDirectory:
    def test_a_salt_root_wrote_there_is_moved_and_applied(self, dial):
        dial.legacy_salt.write_text(SALT_A + "\n", encoding="utf-8")
        assert m.reconcile_dial_identity() is True
        assert dial.salt.read_text(encoding="utf-8") == SALT_A + "\n"
        assert not dial.legacy_salt.exists()
        assert dial.hw_uuid() == dial.state_uuid() == m.derive_dial_id(SALT_A)

    def test_a_salt_that_is_not_root_owned_is_left_alone_and_not_moved(self, dial, monkeypatch):
        dial.legacy_salt.write_text(SALT_A + "\n", encoding="utf-8")
        monkeypatch.setattr(m, "ROOT_UID", os.getuid() + 1)
        before = dial.snapshot()
        m._migrate_legacy_dial_id_salt()
        assert not dial.salt.exists()
        assert dial.legacy_salt.exists()
        assert dial.snapshot() == before

    def test_a_link_there_is_not_moved(self, dial, tmp_path):
        elsewhere = tmp_path / "elsewhere"
        elsewhere.write_text(SALT_A + "\n", encoding="utf-8")
        dial.legacy_salt.symlink_to(elsewhere)
        m._migrate_legacy_dial_id_salt()
        assert not dial.salt.exists()

    def test_a_malformed_salt_there_is_not_moved(self, dial):
        dial.legacy_salt.write_text("nonsense\n", encoding="utf-8")
        m._migrate_legacy_dial_id_salt()
        assert not dial.salt.exists()

    def test_a_salt_already_in_the_root_owned_place_wins_and_the_old_one_stays(self, dial):
        dial.salt.write_text(SALT_B + "\n", encoding="utf-8")
        dial.legacy_salt.write_text(SALT_A + "\n", encoding="utf-8")
        m._migrate_legacy_dial_id_salt()
        assert dial.salt.read_text(encoding="utf-8") == SALT_B + "\n"
        assert dial.legacy_salt.exists()


# ---------------------------------------------------------------------------
# The announced identity is the dial's own
# ---------------------------------------------------------------------------

@posix_only
class TestAnnouncementIsDerived:
    def _announce(self, dial, tmp_path, monkeypatch, given: str):
        template = tmp_path / "template.service"
        template.write_text("<txt-record>id=__DIAL_UUID__</txt-record>", encoding="utf-8")
        service = tmp_path / "autostream-dial.service"
        monkeypatch.setattr(m, "_DIAL_TEMPLATE", template)
        monkeypatch.setattr(m, "_DIAL_SERVICE", service)
        monkeypatch.setattr(m, "_AVAHI_SERVICES_DIR", tmp_path)

        class Args:
            version, name, pin_recovery = "1.0", "Lounge", False
            uuid = given

        return m._update_dial_service(Args), service

    def test_an_unsalted_dial_announces_the_identity_derived_from_its_board(
            self, dial, tmp_path, monkeypatch):
        rc, service = self._announce(dial, tmp_path, monkeypatch, "feedfacefeedfacefeed")
        assert rc == 0
        assert f"id={OLD_UUID}<" in service.read_text(encoding="utf-8")

    def test_a_salted_dial_announces_the_identity_derived_from_its_salt(
            self, dial, tmp_path, monkeypatch):
        dial.salt.write_text(SALT_A + "\n", encoding="utf-8")
        rc, service = self._announce(dial, tmp_path, monkeypatch, OLD_UUID)
        assert rc == 0
        assert f"id={m.derive_dial_id(SALT_A)}<" in service.read_text(encoding="utf-8")

    def test_the_value_the_dial_passes_is_accepted_when_it_matches(
            self, dial, tmp_path, monkeypatch):
        rc, service = self._announce(dial, tmp_path, monkeypatch, OLD_UUID)
        assert rc == 0
        assert f"id={OLD_UUID}<" in service.read_text(encoding="utf-8")

    def test_nothing_is_announced_when_the_salt_cannot_be_trusted(
            self, dial, tmp_path, monkeypatch):
        dial.salt.write_text(SALT_A + "\n", encoding="utf-8")
        dial.salt.chmod(0o666)
        rc, service = self._announce(dial, tmp_path, monkeypatch, OLD_UUID)
        assert rc == 1
        assert not service.exists()

    def test_nothing_is_announced_when_no_identity_can_be_derived(
            self, dial, tmp_path, monkeypatch):
        dial.set_serial("")
        dial.hw.write_text(json.dumps({k: v for k, v in HW.items() if k != "uuid"}),
                           encoding="utf-8")
        rc, service = self._announce(dial, tmp_path, monkeypatch, OLD_UUID)
        assert rc == 1
        assert not service.exists()


# ---------------------------------------------------------------------------
# Update, reinstall, uninstall
# ---------------------------------------------------------------------------

def _salted_dial(env: Env, salt: str = SALT_A) -> str:
    _real_python3(env)
    env.put("proc/cpuinfo", f"Serial\t\t: {SERIAL}\n")
    env.put("etc/autostream/dial-id-salt", salt + "\n")
    return {SALT_A: "5a51ead2f359f9ad69d5", SALT_B: "7f05b4c5571831a46a48"}[salt]


REINSTALL = ('U=$(generate_dial_id)\nwrite_dial_hw_config "$U"\nwrite_install_state "$U"\n'
             'echo "$U"')


@bash_capable
class TestUpdateReinstallUninstall:
    def test_a_reinstall_over_a_salted_dial_keeps_its_salt_and_identity(self, env):
        expected = _salted_dial(env)
        env.put("etc/autostream/autostream-dial.json", json.dumps({**HW, "uuid": expected}))
        salt_before = (env.root / "etc/autostream/dial-id-salt").read_bytes()
        r = env.run(REINSTALL, update="false")
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == expected
        assert (env.root / "etc/autostream/dial-id-salt").read_bytes() == salt_before
        hw = json.loads((env.root / "etc/autostream/autostream-dial.json").read_text())
        assert hw["uuid"] == expected and hw["clk_gpio"] == 5
        assert f"DIAL_UUID={expected}" in env.install_state.read_text().splitlines()

    def test_a_reinstall_over_an_unsalted_dial_keeps_the_identity_it_has_always_had(self, env):
        _real_python3(env)
        env.put("proc/cpuinfo", f"Serial\t\t: {SERIAL}\n")
        env.put("etc/autostream/autostream-dial.json", json.dumps(HW))
        r = env.run(REINSTALL, update="false")
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == OLD_UUID
        assert not (env.root / "etc/autostream/dial-id-salt").exists()

    def test_an_update_keeps_the_stored_identity_and_asks_for_no_new_one(self, tmp_path):
        from test_dial_installer_hd import _dry_run, _names
        r, calls = _dry_run(tmp_path, update=True)
        assert r.returncode == 0, r.stderr
        assert "write_dial_hw_config" not in _names(calls)
        assert "write_install_state feedfacefeedfacefeed" in calls

    def test_the_installer_script_never_writes_a_salt(self):
        text = (REPO_ROOT / "autostream_dial_install.sh").read_text(encoding="utf-8")
        assert "dial-id-salt" not in text

    def test_uninstalling_a_salted_dial_keeps_its_salt_and_removes_the_rest(self, env):
        script = _uninstall_sandbox(env)
        env.fake("rm", WORKING_RM)
        env.put("etc/autostream/dial-id-salt", SALT_A + "\n")
        env.put("etc/autostream/autostream-dial.json", "{}")
        env.put("etc/autostream/sub/other", "x")
        r = _run_uninstaller(env, script, "--yes")
        assert r.returncode == 0, r.stderr
        assert [p.name for p in (env.root / "etc/autostream").iterdir()] == ["dial-id-salt"]
        assert (env.root / "etc/autostream/dial-id-salt").read_text() == SALT_A + "\n"
        assert "rm -rf /etc/autostream" not in env.calls()
        assert "rm -rf /var/lib/autostream" in env.calls()
        assert "Kept the dial identity salt" in r.stdout

    def test_a_fresh_install_after_uninstalling_a_salted_dial_gets_the_salted_identity(self, env):
        script = _uninstall_sandbox(env)
        expected = _salted_dial(env)
        assert _run_uninstaller(env, script, "--yes").returncode == 0
        r = env.run("generate_dial_id", update="false")
        assert r.stdout.strip() == expected != OLD_UUID

    def test_uninstalling_an_unsalted_dial_removes_both_directories_whole(self, env):
        script = _uninstall_sandbox(env)
        r = _run_uninstaller(env, script, "--yes")
        assert r.returncode == 0, r.stderr
        assert "rm -rf /etc/autostream" in env.calls()
        assert "rm -rf /var/lib/autostream" in env.calls()
        assert "Kept the dial identity salt" not in r.stdout

    def test_a_fresh_install_after_uninstalling_an_unsalted_dial_gets_the_same_identity(self, env):
        script = _uninstall_sandbox(env)
        _real_python3(env)
        env.put("proc/cpuinfo", f"Serial\t\t: {SERIAL}\n")
        assert _run_uninstaller(env, script, "--yes").returncode == 0
        assert env.run("generate_dial_id", update="false").stdout.strip() == OLD_UUID


# ---------------------------------------------------------------------------
# The announced identity is the one the dial already holds
# ---------------------------------------------------------------------------

LEGACY_RANDOM = "feedfacefeedfacefeed"


def _set_stored(dial, uuid) -> None:
    """Put UUID in both stored copies (None removes the hardware config key)."""
    cfg = dict(HW)
    if uuid is None:
        cfg.pop("uuid")
    else:
        cfg["uuid"] = uuid
    dial.hw.write_text(json.dumps(cfg), encoding="utf-8")
    dial.install_state.write_text(
        INSTALL_STATE.replace(OLD_UUID, str(uuid)), encoding="utf-8")


@posix_only
class TestAnnouncementUsesTheStoredIdentity:
    _announce = TestAnnouncementIsDerived._announce

    def test_a_dial_with_a_stored_identity_of_its_own_keeps_announcing_it(
            self, dial, tmp_path, monkeypatch, capsys):
        _set_stored(dial, LEGACY_RANDOM)
        rc, service = self._announce(dial, tmp_path, monkeypatch, LEGACY_RANDOM)
        assert rc == 0
        assert f"id={LEGACY_RANDOM}<" in service.read_text(encoding="utf-8")
        assert "stored in" in capsys.readouterr().out

    def test_the_value_the_caller_gives_is_ignored_and_the_difference_is_logged(
            self, dial, tmp_path, monkeypatch, capsys):
        _set_stored(dial, LEGACY_RANDOM)
        rc, service = self._announce(dial, tmp_path, monkeypatch, "0" * 20)
        assert rc == 0
        assert f"id={LEGACY_RANDOM}<" in service.read_text(encoding="utf-8")
        assert "differs" in capsys.readouterr().err

    @pytest.mark.parametrize("stored", [
        pytest.param("FEEDFACEFEEDFACEFEED", id="upper-case"),
        pytest.param(LEGACY_RANDOM[:-1], id="too-short"),
        pytest.param(LEGACY_RANDOM + "0", id="too-long"),
        pytest.param(LEGACY_RANDOM + "\n", id="trailing-newline"),
        pytest.param("zzzzzzzzzzzzzzzzzzzz", id="not-hex"),
        pytest.param(12345, id="not-text"),
        pytest.param(None, id="absent"),
    ])
    def test_an_unusable_stored_identity_falls_back_to_the_derivation(
            self, dial, tmp_path, monkeypatch, capsys, stored):
        if stored is None:
            _set_stored(dial, None)
        else:
            cfg = dict(HW, uuid=stored)
            dial.hw.write_text(json.dumps(cfg), encoding="utf-8")
        rc, service = self._announce(dial, tmp_path, monkeypatch, LEGACY_RANDOM)
        assert rc == 0
        assert f"id={OLD_UUID}<" in service.read_text(encoding="utf-8")
        assert "derived from the board" in capsys.readouterr().out

    @pytest.mark.parametrize("text", ["not json", "[1, 2]", ""])
    def test_a_damaged_hardware_config_falls_back_to_the_derivation(
            self, dial, tmp_path, monkeypatch, text):
        dial.hw.write_text(text, encoding="utf-8")
        rc, service = self._announce(dial, tmp_path, monkeypatch, LEGACY_RANDOM)
        assert rc == 0
        assert f"id={OLD_UUID}<" in service.read_text(encoding="utf-8")

    def test_a_missing_hardware_config_falls_back_to_the_derivation(
            self, dial, tmp_path, monkeypatch):
        dial.hw.unlink()
        rc, service = self._announce(dial, tmp_path, monkeypatch, LEGACY_RANDOM)
        assert rc == 0
        assert f"id={OLD_UUID}<" in service.read_text(encoding="utf-8")

    def test_a_hardware_config_others_can_write_is_not_believed(
            self, dial, tmp_path, monkeypatch):
        _set_stored(dial, LEGACY_RANDOM)
        dial.hw.chmod(0o666)
        rc, service = self._announce(dial, tmp_path, monkeypatch, LEGACY_RANDOM)
        assert rc == 0
        assert f"id={OLD_UUID}<" in service.read_text(encoding="utf-8")

    def test_a_stored_identity_in_a_directory_others_can_write_is_not_believed(
            self, dial, tmp_path, monkeypatch):
        _set_stored(dial, LEGACY_RANDOM)
        dial.etc.chmod(0o777)
        try:
            rc, service = self._announce(dial, tmp_path, monkeypatch, LEGACY_RANDOM)
        finally:
            dial.etc.chmod(0o755)
        assert rc == 0
        assert f"id={OLD_UUID}<" in service.read_text(encoding="utf-8")


# Which identity wins, by what the dial holds. A salt means a reset has started
# or finished, so the identity derived from it wins and the stored copies are
# brought into line; with no salt the stored identity wins and nothing is
# rewritten.  The announcement and the start-up reconcile follow the same rule.
@posix_only
class TestWhichIdentityWins:
    @pytest.mark.parametrize("salted, stored, wins, rewritten", [
        pytest.param(False, LEGACY_RANDOM, "stored", False, id="no-salt-legacy-random-id"),
        pytest.param(False, OLD_UUID, "stored", False, id="no-salt-stored-equals-derived"),
        pytest.param(True, "derived", "derived", False, id="salt-stored-equals-derived"),
        pytest.param(True, OLD_UUID, "derived", True, id="salt-stored-differs"),
    ])
    def test_the_announcement_and_reconcile_agree(
            self, dial, tmp_path, monkeypatch, salted, stored, wins, rewritten):
        derived = None
        if salted:
            dial.salt.write_text(SALT_A + "\n", encoding="utf-8")
            derived = m.derive_dial_id(SALT_A)
        if stored == "derived":
            stored = derived
        _set_stored(dial, stored)
        before = dial.snapshot()
        winner = stored if wins == "stored" else derived

        rc, service = TestAnnouncementIsDerived._announce(
            self, dial, tmp_path, monkeypatch, LEGACY_RANDOM)
        assert rc == 0
        assert f"id={winner}<" in service.read_text(encoding="utf-8")
        assert dial.snapshot() == before  # announcing changes no stored copy

        with patch.object(m, "write_file_safely", wraps=m.write_file_safely) as write:
            assert m.reconcile_dial_identity() is True
        assert write.called is rewritten
        assert dial.hw_uuid() == winner
        assert dial.state_uuid() == winner
        if not rewritten:
            assert dial.snapshot() == before


# ---------------------------------------------------------------------------
# An absent salt is "no salt", whatever the directory looks like; a present
# salt in a directory others can write is refused. The privileged helper and
# the installer's shell function follow the same cases.
# ---------------------------------------------------------------------------

SALT_DIRECTORY_CASES = [
    # directory mode, salt text (None: no file), outcome
    pytest.param(0o755, None, "unsalted", id="trusted-directory-no-salt"),
    pytest.param(0o775, None, "unsalted", id="group-writable-directory-no-salt"),
    pytest.param(0o777, None, "unsalted", id="world-writable-directory-no-salt"),
    pytest.param(0o755, SALT_A + "\n", "salted", id="trusted-directory-salt"),
    pytest.param(0o775, SALT_A + "\n", "refused", id="group-writable-directory-salt"),
    pytest.param(0o777, SALT_A + "\n", "refused", id="world-writable-directory-salt"),
]


@posix_only
class TestAbsentSaltInAnUntrustedDirectory:
    @pytest.mark.parametrize("mode, salt, outcome", SALT_DIRECTORY_CASES)
    def test_the_privileged_helper(self, dial, tmp_path, monkeypatch, mode, salt, outcome):
        if salt is not None:
            dial.salt.write_text(salt, encoding="utf-8")
        dial.etc.chmod(mode)
        try:
            if outcome == "refused":
                with pytest.raises(ValueError):
                    m._read_dial_id_salt()
                return
            assert m._read_dial_id_salt() == (None if outcome == "unsalted" else SALT_A)
        finally:
            dial.etc.chmod(0o755)

    @pytest.mark.parametrize("mode", [0o775, 0o777])
    def test_announcing_still_works_with_no_salt_in_an_untrusted_directory(
            self, dial, tmp_path, monkeypatch, mode):
        dial.etc.chmod(mode)
        try:
            rc, service = TestAnnouncementIsDerived._announce(
                self, dial, tmp_path, monkeypatch, OLD_UUID)
        finally:
            dial.etc.chmod(0o755)
        assert rc == 0
        assert f"id={OLD_UUID}<" in service.read_text(encoding="utf-8")

    @bash_capable
    @pytest.mark.parametrize("mode, salt, outcome", SALT_DIRECTORY_CASES)
    def test_the_installer_function(self, env, mode, salt, outcome):
        _real_python3(env)
        env.put("proc/cpuinfo", f"processor\t: 0\nSerial\t\t: {SERIAL}\n")
        etc = env.root / "etc" / "autostream"
        etc.mkdir(parents=True, exist_ok=True)
        if salt is not None:
            env.put("etc/autostream/dial-id-salt", salt)
        etc.chmod(mode)
        try:
            r = env.run("generate_dial_id", update="false")
        finally:
            etc.chmod(0o755)
        if outcome == "refused":
            assert r.returncode != 0 and r.stdout.strip() == ""
        elif outcome == "salted":
            assert r.returncode == 0, r.stderr
            assert r.stdout.strip() == "5a51ead2f359f9ad69d5"
        else:
            assert r.returncode == 0, r.stderr
            assert r.stdout.strip() == OLD_UUID
