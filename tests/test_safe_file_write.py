"""Root writing into a directory an unprivileged account owns.

write_file_safely and read_file_if_trusted keep a privileged helper from being
steered by what the unprivileged account leaves in its own directory: a link
at the name of the temporary file or of the destination, a file it owns where
a root-owned file should be, or a file with loose permissions. The tests run
unprivileged, so "root" is the invoking user and the owner check is exercised
by asking for a different user.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "supervisor"))
import autostream_update_support as support  # noqa: E402

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file semantics")

ME = os.getuid() if hasattr(os, "getuid") else 0


@pytest.fixture
def victim(tmp_path):
    path = tmp_path / "victim"
    path.write_text("precious\n", encoding="utf-8")
    path.chmod(0o600)
    return path


@posix_only
class TestWriteFileSafely:
    def test_the_content_and_mode_are_what_was_asked(self, tmp_path):
        dest = tmp_path / "state.env"
        old_umask = os.umask(0o077)
        try:
            support.write_file_safely(dest, "A=1\n", 0o644)
        finally:
            os.umask(old_umask)
        assert dest.read_text(encoding="utf-8") == "A=1\n"
        assert stat.S_IMODE(dest.stat().st_mode) == 0o644

    def test_bytes_are_written_as_they_are(self, tmp_path):
        dest = tmp_path / "blob"
        support.write_file_safely(dest, b"\x00\x01\xff", 0o600)
        assert dest.read_bytes() == b"\x00\x01\xff"

    def test_an_existing_file_is_replaced_by_rename_not_rewritten(self, tmp_path):
        dest = tmp_path / "state.env"
        dest.write_text("old\n", encoding="utf-8")
        before = dest.stat().st_ino
        held_open = open(dest, "r", encoding="utf-8")
        try:
            support.write_file_safely(dest, "new\n", 0o644)
            assert held_open.read() == "old\n"
        finally:
            held_open.close()
        assert dest.read_text(encoding="utf-8") == "new\n"
        assert dest.stat().st_ino != before

    def test_a_link_at_the_destination_is_replaced_and_its_target_left_alone(self, tmp_path,
                                                                             victim):
        dest = tmp_path / "state.env"
        dest.symlink_to(victim)
        support.write_file_safely(dest, "new\n", 0o644)
        assert not dest.is_symlink()
        assert dest.read_text(encoding="utf-8") == "new\n"
        assert victim.read_text(encoding="utf-8") == "precious\n"
        assert stat.S_IMODE(victim.stat().st_mode) == 0o600

    def test_links_at_the_names_an_older_writer_used_for_its_temporary_file_are_ignored(
            self, tmp_path, victim):
        dest = tmp_path / "state.env"
        for name in ("state.env.tmp", ".state.env.tmp", f".state.env.tmp.{os.getpid()}"):
            (tmp_path / name).symlink_to(victim)
        support.write_file_safely(dest, "new\n", 0o644)
        assert victim.read_text(encoding="utf-8") == "precious\n"
        assert stat.S_IMODE(victim.stat().st_mode) == 0o600

    def test_the_temporary_file_is_created_exclusively_and_without_following_links(
            self, tmp_path):
        opened: list[tuple[str, int]] = []
        real_open = os.open

        def spy(path, flags, *a, **kw):
            opened.append((str(path), flags))
            return real_open(path, flags, *a, **kw)

        with patch.object(support.os, "open", side_effect=spy):
            support.write_file_safely(tmp_path / "state.env", "x\n", 0o644)
        tmp_open = next(f for p, f in opened if p.endswith(".tmp"))
        assert tmp_open & os.O_EXCL and tmp_open & os.O_CREAT
        assert tmp_open & os.O_NOFOLLOW

    def test_the_temporary_name_is_not_the_same_twice(self, tmp_path):
        names: list[str] = []
        real_rename = os.rename

        def spy(src, dst):
            names.append(Path(src).name)
            return real_rename(src, dst)

        with patch.object(support.os, "rename", side_effect=spy):
            support.write_file_safely(tmp_path / "state.env", "1\n", 0o644)
            support.write_file_safely(tmp_path / "state.env", "2\n", 0o644)
        assert len(set(names)) == 2

    def test_mode_and_owner_are_set_on_the_descriptor_not_the_name(self, tmp_path):
        calls: list[str] = []
        with patch.object(support.os, "fchown", side_effect=lambda *a: calls.append("fchown")), \
             patch.object(support.os, "chown", side_effect=AssertionError("by name")), \
             patch.object(support.os, "chmod", side_effect=AssertionError("by name")):
            support.write_file_safely(tmp_path / "state.env", "x\n", 0o640, (ME, 0))
        assert calls == ["fchown"]
        assert stat.S_IMODE((tmp_path / "state.env").stat().st_mode) == 0o640

    def test_no_temporary_file_is_left_when_the_rename_fails(self, tmp_path):
        dest = tmp_path / "state.env"
        dest.write_text("old\n", encoding="utf-8")
        with patch.object(support.os, "rename", side_effect=OSError("no space")):
            with pytest.raises(OSError):
                support.write_file_safely(dest, "new\n", 0o644)
        assert dest.read_text(encoding="utf-8") == "old\n"
        assert [p.name for p in tmp_path.iterdir()] == ["state.env"]

    def test_no_temporary_file_is_left_when_the_data_cannot_be_flushed(self, tmp_path):
        with patch.object(support.os, "fsync", side_effect=OSError("io error")):
            with pytest.raises(OSError):
                support.write_file_safely(tmp_path / "state.env", "new\n", 0o644)
        assert list(tmp_path.iterdir()) == []

    def test_a_directory_at_the_destination_is_an_error_and_leaves_nothing_behind(self, tmp_path):
        dest = tmp_path / "state.env"
        dest.mkdir()
        (dest / "keep").write_text("x", encoding="utf-8")
        with pytest.raises(OSError):
            support.write_file_safely(dest, "new\n", 0o644)
        assert [p.name for p in tmp_path.iterdir()] == ["state.env"]

    def test_the_directory_entry_is_flushed_after_the_rename(self, tmp_path):
        order: list[str] = []
        real_rename, real_fsync = os.rename, os.fsync

        def rename(src, dst):
            order.append("rename")
            return real_rename(src, dst)

        def fsync(fd):
            order.append("fsync-dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "fsync-file")
            return real_fsync(fd)

        with patch.object(support.os, "rename", side_effect=rename), \
             patch.object(support.os, "fsync", side_effect=fsync):
            support.write_file_safely(tmp_path / "state.env", "x\n", 0o644)
        assert order == ["fsync-file", "rename", "fsync-dir"]


@posix_only
class TestReadFileIfTrusted:
    def _file(self, tmp_path, text="value\n", mode=0o644):
        path = tmp_path / "f"
        path.write_text(text, encoding="utf-8")
        path.chmod(mode)
        return path

    def test_a_plain_file_of_the_right_owner_is_read(self, tmp_path):
        path = self._file(tmp_path)
        assert support.read_file_if_trusted(path, ME) == "value\n"

    def test_an_absent_file_is_reported_as_absent(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            support.read_file_if_trusted(tmp_path / "nope", ME)

    def test_a_link_is_refused_even_to_a_good_file(self, tmp_path):
        good = self._file(tmp_path)
        link = tmp_path / "link"
        link.symlink_to(good)
        with pytest.raises(ValueError):
            support.read_file_if_trusted(link, ME)

    def test_a_file_owned_by_someone_else_is_refused(self, tmp_path):
        path = self._file(tmp_path)
        with pytest.raises(ValueError):
            support.read_file_if_trusted(path, ME + 1)

    @pytest.mark.parametrize("mode", [0o664, 0o646, 0o666, 0o620, 0o602])
    def test_a_file_others_can_write_is_refused(self, tmp_path, mode):
        path = self._file(tmp_path, mode=mode)
        with pytest.raises(ValueError):
            support.read_file_if_trusted(path, ME)

    def test_the_owner_rule_can_be_waived_but_a_link_still_is_not_followed(self, tmp_path):
        path = self._file(tmp_path, mode=0o666)
        assert support.read_file_if_trusted(path, None) == "value\n"
        link = tmp_path / "link"
        link.symlink_to(path)
        with pytest.raises(ValueError):
            support.read_file_if_trusted(link, None)

    def test_a_pipe_is_refused_without_blocking(self, tmp_path):
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo)
        with pytest.raises(ValueError):
            support.read_file_if_trusted(fifo, ME)

    def test_a_directory_is_refused(self, tmp_path):
        with pytest.raises(ValueError):
            support.read_file_if_trusted(tmp_path, ME)

    def test_an_oversized_file_is_refused(self, tmp_path):
        path = self._file(tmp_path, text="x" * 100)
        with pytest.raises(ValueError):
            support.read_file_if_trusted(path, ME, max_bytes=10)

    def test_a_directory_that_others_can_write_is_refused_when_asked(self, tmp_path):
        d = tmp_path / "d"
        d.mkdir()
        (d / "f").write_text("v\n", encoding="utf-8")
        d.chmod(0o777)
        assert support.read_file_if_trusted(d / "f", ME) == "v\n"
        with pytest.raises(ValueError):
            support.read_file_if_trusted(d / "f", ME, check_directory=True)
        d.chmod(0o755)
        assert support.read_file_if_trusted(d / "f", ME, check_directory=True) == "v\n"

    def test_a_directory_of_the_wrong_owner_is_refused_when_asked(self, tmp_path):
        d = tmp_path / "d"
        d.mkdir()
        (d / "f").write_text("v\n", encoding="utf-8")
        with pytest.raises(ValueError):
            support.read_file_if_trusted(d / "f", ME + 1, check_directory=True)


# ---------------------------------------------------------------------------
# The privileged scripts that write into the service account's directory
# ---------------------------------------------------------------------------

sys.path.insert(0, str(Path(__file__).resolve().parent))
from conftest import load_supervisor_script  # noqa: E402


def _plant(directory: Path, name: str, victim: Path) -> None:
    for pattern in (f"{name}.tmp", f".{name}.tmp", f".{name}.tmp.{os.getpid()}",
                    f"{name}.tmp.{os.getpid()}"):
        link = directory / pattern
        if not link.exists() and not link.is_symlink():
            link.symlink_to(victim)


@posix_only
class TestScriptsDoNotWriteThroughLinks:
    def test_the_dial_updater_result_and_swap_files(self, tmp_path, victim):
        mod = load_supervisor_script("autostream_dial_updater", "dial_updater_links")
        mod.STATE_DIR = tmp_path
        _plant(tmp_path, "update-result.env", victim)
        _plant(tmp_path, "update-swap.env", victim)
        mod.write_update_result("in_progress", "working", 10)
        mod._atomic_write(tmp_path / "update-swap.env", "PHASE=x\n")
        assert victim.read_text(encoding="utf-8") == "precious\n"
        assert (tmp_path / "update-result.env").read_text(encoding="utf-8").startswith("STATUS=")
        assert (tmp_path / "update-swap.env").read_text(encoding="utf-8") == "PHASE=x\n"

    def test_the_appliance_updater_result_file(self, tmp_path, victim):
        mod = load_supervisor_script("autostream_updater", "appliance_updater_links")
        mod.UPDATE_RESULT_FILE = tmp_path / "update-result.env"
        _plant(tmp_path, "update-result.env", victim)
        mod._write_update_result("in_progress", 5, "working")
        assert victim.read_text(encoding="utf-8") == "precious\n"
        assert 'STATUS="in_progress"' in (tmp_path / "update-result.env").read_text(
            encoding="utf-8")

    def test_the_retry_helper_files(self, tmp_path, victim):
        mod = load_supervisor_script("autostream_update_retry", "update_retry_links")
        (tmp_path / "staging").mkdir()
        mod.STAMP_DIR = tmp_path
        mod.UPDATE_RESULT_FILE = tmp_path / "update-result.env"
        mod.RETRY_COUNT_FILE = tmp_path / "staging" / "retry_count"
        _plant(tmp_path, "update-result.env", victim)
        _plant(tmp_path / "staging", "retry_count", victim)
        with patch.object(mod.os, "fchown", lambda *a: None):
            mod._write_update_result("failure", "x", 0, "now")
        mod._write_retry_count(2)
        assert victim.read_text(encoding="utf-8") == "precious\n"
        assert mod.RETRY_COUNT_FILE.read_text(encoding="utf-8") == "2\n"

    def test_the_sd_card_health_files(self, tmp_path, victim):
        mod = load_supervisor_script("autostream_sdcardhealth", "sdcardhealth_links")
        mod.STATE_DIR = tmp_path
        mod.STATE_FILE = tmp_path / "install-state.env"
        mod.MARKER_FILE = tmp_path / "sdcardhealth.inflight"
        mod.STATUS_FILE = tmp_path / "sdcardhealth-status.json"
        mod.HEALTH_JSON_FILE = tmp_path / "sdcardhealth.json"
        mod.STATE_FILE.write_text("AUTOSTREAM_PRODUCT=autostream\n", encoding="utf-8")
        _plant(tmp_path, "install-state.env", victim)
        _plant(tmp_path, "sdcardhealth-status.json", victim)
        _plant(tmp_path, "sdcardhealth.json", victim)
        (tmp_path / "sdcardhealth.inflight").symlink_to(victim)
        mod.update_state_file({"SDMON_CHECK": "pass"})
        mod.write_health_json({"a": 1})
        mod.write_marker("serial", "fast")
        assert victim.read_text(encoding="utf-8") == "precious\n"
        assert 'SDMON_CHECK="pass"' in mod.STATE_FILE.read_text(encoding="utf-8")
        assert not mod.MARKER_FILE.is_symlink()

    def test_the_storage_guard_state(self, tmp_path, victim):
        mod = load_supervisor_script("autostream_storage_guard", "storage_guard_links")
        mod.STATE_PATH = tmp_path / "storage-guard.json"
        _plant(tmp_path, "storage-guard.json", victim)
        assert mod.save_state({"a": 1}) is True
        assert victim.read_text(encoding="utf-8") == "precious\n"


SECRET_LINES = (
    "root-only-secret-line\n"
    "AUTOSTREAM_PRODUCT=leaked-product\n"
    "AUTOSTREAM_RELEASE_TAG=leaked-installed-tag\n"
    "STATUS=leaked-status\n"
    "MESSAGE=leaked-message\n"
    "TAG=leaked-tag\n"
    "PREVIOUS_TAG=leaked-previous\n"
    "PHASE=leaked-phase\n"
)
SECRET_JSON = '{"serial": "leaked-serial", "leaked": "leaked-json"}\n'


@pytest.fixture
def secret(tmp_path):
    """A stand-in for a file only root may read, outside the state directory."""
    outside = tmp_path / "root-only"
    outside.mkdir()
    path = outside / "secret"
    path.write_text(SECRET_LINES, encoding="utf-8")
    return path


@pytest.fixture
def state_dir(tmp_path):
    path = tmp_path / "state"
    path.mkdir()
    return path


def _assert_no_leak(text: str) -> None:
    assert "leaked" not in text
    assert "root-only-secret-line" not in text


@posix_only
class TestRootReadsDoNotFollowLinks:
    """A root-run helper reading a file in a directory the service account
    owns must not follow a link that account placed there."""

    def _sd(self, state_dir):
        mod = load_supervisor_script("autostream_sdcardhealth", "sdcardhealth_reads")
        mod.STATE_DIR = state_dir
        mod.STATE_FILE = state_dir / "install-state.env"
        mod.MARKER_FILE = state_dir / "sdcardhealth.inflight"
        return mod

    def test_sd_health_state_update_does_not_copy_a_linked_file(self, state_dir, secret):
        mod = self._sd(state_dir)
        mod.STATE_FILE.symlink_to(secret)
        mod.update_state_file({"SDMON_CHECK": "pass"})
        written = mod.STATE_FILE.read_text(encoding="utf-8")
        _assert_no_leak(written)
        assert not mod.STATE_FILE.is_symlink()
        assert 'SDMON_CHECK="pass"' in written

    def test_sd_health_state_read_ignores_a_linked_file(self, state_dir, secret):
        mod = self._sd(state_dir)
        mod.STATE_FILE.symlink_to(secret)
        assert mod.read_state_value("AUTOSTREAM_PRODUCT", "fallback") == "fallback"

    def test_sd_health_marker_read_ignores_a_linked_file(self, state_dir, tmp_path):
        mod = self._sd(state_dir)
        target = tmp_path / "root-only" / "marker.json"
        target.parent.mkdir()
        target.write_text(SECRET_JSON, encoding="utf-8")
        mod.MARKER_FILE.symlink_to(target)
        assert mod.read_marker() == {}

    def test_sd_health_ordinary_reads_are_unchanged(self, state_dir):
        mod = self._sd(state_dir)
        mod.STATE_FILE.write_text('AUTOSTREAM_PRODUCT="autostream"\nOTHER=1\n',
                                  encoding="utf-8")
        assert mod.read_state_value("AUTOSTREAM_PRODUCT") == "autostream"
        assert mod.read_state_value("MISSING", "d") == "d"
        mod.update_state_file({"OTHER": "2", "NEW": "x"})
        assert mod.STATE_FILE.read_text(encoding="utf-8") == (
            'AUTOSTREAM_PRODUCT="autostream"\nOTHER="2"\nNEW="x"\n')
        mod.MARKER_FILE.write_text('{"serial": "abc"}', encoding="utf-8")
        assert mod.read_marker() == {"serial": "abc"}
        mod.MARKER_FILE.unlink()
        assert mod.read_marker() is None

    def test_the_dial_updater_result_does_not_carry_over_a_linked_file(
            self, state_dir, secret):
        mod = load_supervisor_script("autostream_dial_updater", "dial_updater_reads")
        mod.STATE_DIR = state_dir
        (state_dir / "update-result.env").symlink_to(secret)
        mod.write_update_result("in_progress", "working", percent=5)
        written = (state_dir / "update-result.env").read_text(encoding="utf-8")
        _assert_no_leak(written)
        assert "STATUS=in_progress" in written

    def test_the_dial_updater_result_still_carries_its_own_keys_over(self, state_dir):
        mod = load_supervisor_script("autostream_dial_updater", "dial_updater_reads_ok")
        mod.STATE_DIR = state_dir
        mod.write_update_result("in_progress", "one", percent=5, tag="1.2.3")
        mod.write_update_result("in_progress", "two", percent=6)
        written = (state_dir / "update-result.env").read_text(encoding="utf-8")
        assert "TAG=1.2.3" in written
        assert "MESSAGE=two" in written

    def test_the_installed_tag_is_not_taken_from_a_linked_file(self, state_dir, secret):
        mod = load_supervisor_script("autostream_dial_updater", "dial_updater_tag")
        mod.STATE_DIR = state_dir
        (state_dir / "install-state.env").symlink_to(secret)
        assert "leaked" not in mod._read_installed_tag()
        (state_dir / "install-state.env").unlink()
        (state_dir / "install-state.env").write_text(
            "AUTOSTREAM_RELEASE_TAG=1.2.3\n", encoding="utf-8")
        assert mod._read_installed_tag() == "1.2.3"

    def test_the_appliance_updater_tag_is_not_taken_from_a_linked_file(
            self, state_dir, secret):
        mod = load_supervisor_script("autostream_updater", "appliance_updater_tag")
        mod.INSTALL_STATE_FILE = state_dir / "install-state.env"
        mod.INSTALL_STATE_FILE.symlink_to(secret)
        assert "leaked" not in mod._read_installed_release_tag()
        mod.INSTALL_STATE_FILE.unlink()
        mod.INSTALL_STATE_FILE.write_text("AUTOSTREAM_RELEASE_TAG=1.2.3\n", encoding="utf-8")
        assert mod._read_installed_release_tag() == "1.2.3"

    def test_the_shared_env_reader_ignores_a_link(self, state_dir, secret):
        (state_dir / "x.env").symlink_to(secret)
        assert support._read_env_file(state_dir / "x.env") == {}
        (state_dir / "y.env").write_text("A=1\n", encoding="utf-8")
        assert support._read_env_file(state_dir / "y.env") == {"A": "1"}
        assert support._read_env_file(state_dir / "absent.env") == {}

    def test_update_status_reports_nothing_from_linked_files(
            self, state_dir, secret, capsys):
        import json
        mod = load_supervisor_script("autostream_admin", "admin_reads_status")
        mod.STAMP_DIR = state_dir
        mod.INSTALL_STATE_FILE = state_dir / "install-state.env"
        mod.UPDATE_RESULT_FILE = state_dir / "update-result.env"
        mod._INSTALL_LOG = state_dir / "autostream_install.log"
        mod.UPDATE_RESULT_FILE.symlink_to(secret)
        mod._INSTALL_LOG.symlink_to(secret)
        mod.read_update_status()
        _assert_no_leak(capsys.readouterr().out)
        mod.UPDATE_RESULT_FILE.unlink()
        mod.UPDATE_RESULT_FILE.write_text(
            "STATUS=success\nMESSAGE=done\nPERCENT_COMPLETE=100\n", encoding="utf-8")
        mod._INSTALL_LOG.unlink()
        mod._INSTALL_LOG.write_text("line one\nline two\n", encoding="utf-8")
        mod.read_update_status()
        data = json.loads(capsys.readouterr().out)
        assert data["status"] == "success"
        assert data["log_tail"] == "line one\nline two"

    def test_version_info_reports_nothing_from_a_linked_file(
            self, state_dir, secret, capsys):
        mod = load_supervisor_script("autostream_admin", "admin_reads_version")
        mod.INSTALL_STATE_FILE = state_dir / "install-state.env"
        mod.INSTALL_STATE_FILE.symlink_to(secret)
        mod.read_version_info()
        _assert_no_leak(capsys.readouterr().out)

    def test_the_storage_guard_state_is_not_loaded_from_a_linked_file(
            self, state_dir, tmp_path):
        mod = load_supervisor_script("autostream_storage_guard", "storage_guard_reads")
        target = tmp_path / "root-only" / "state.json"
        target.parent.mkdir()
        target.write_text(SECRET_JSON, encoding="utf-8")
        mod.STATE_PATH = state_dir / "storage-guard.json"
        mod.STATE_PATH.symlink_to(target)
        assert mod.load_state() == {}
        mod.STATE_PATH.unlink()
        mod.STATE_PATH.write_text('{"a": 1}', encoding="utf-8")
        assert mod.load_state() == {"a": 1}
