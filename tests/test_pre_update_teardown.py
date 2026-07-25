"""Pre-update teardown tests.

Covers the two host-only best-effort helpers added to
autostream_update_support (stop_owntone_playback, free_repeat_buffer) and
their wiring into the two host update choke points that schedule the
installer's heavy work (apt + OwnTone build): autostream_updater.cmd_apply
and autostream_update_retry.main.

Neither helper is called by autostream_dial_updater -- the dial product has
no OwnTone backend and no autostream_monitor daemon.

Both helpers are best-effort: they never raise, and a failure (OwnTone down,
monitor socket absent, or an old monitor binary rejecting the commands)
returns (False, <message>) rather than raising, so the update itself is
never blocked.
"""
from __future__ import annotations

import json
import socket
import sys
import tarfile
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "tests"))

_SUPERVISOR_DIR = str(REPO_ROOT / "supervisor")
if _SUPERVISOR_DIR not in sys.path:
    sys.path.insert(0, _SUPERVISOR_DIR)

import autostream_update_support as _asu
from autostream_update_support import free_repeat_buffer, stop_owntone_playback

from conftest import load_supervisor_script


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _http_mock_response(status: int = 204, body: bytes = b""):
    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.status = status
    mock_resp.read.return_value = body
    return mock_resp


class _FakeUnixSocket:
    """Stand-in for socket.socket(AF_UNIX, SOCK_STREAM) used as a context manager."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.sent = []
        self.connected_path = None
        self.timeout = None

    def settimeout(self, t):
        self.timeout = t

    def connect(self, path):
        self.connected_path = path

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, n):
        if not self._responses:
            return b""
        return self._responses.pop(0)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _patch_af_unix():
    """AF_UNIX is always present on the target Linux appliance but may be
    absent from the Python build running these tests (e.g. some Windows
    Python builds) -- patch it in so socket.socket(socket.AF_UNIX, ...) can
    be constructed/mocked without the real platform capability."""
    return patch("socket.AF_UNIX", getattr(socket, "AF_UNIX", 1), create=True)


def _fake_socket_factory(responses_per_call):
    """Return a socket.socket() replacement yielding one canned response per call."""
    calls = {"n": 0}

    def _factory(*args, **kwargs):
        idx = calls["n"]
        calls["n"] += 1
        resp = responses_per_call[idx] if idx < len(responses_per_call) else b""
        return _FakeUnixSocket([resp])

    return _factory


def _ack(command: str, ok: bool, error: str | None = None) -> bytes:
    payload = {"type": "ack", "command": command, "ok": ok}
    if error is not None:
        payload["error"] = error
    return (json.dumps(payload) + "\n").encode("utf-8")


# ---------------------------------------------------------------------------
# stop_owntone_playback
# ---------------------------------------------------------------------------

class TestStopOwntonePlayback:
    def test_success_stops_and_deselects(self):
        with patch("urllib.request.urlopen", return_value=_http_mock_response(204)) as m:
            ok, msg = stop_owntone_playback()
        assert ok is True
        assert "stopped" in msg.lower()
        urls = [c.args[0].full_url for c in m.call_args_list]
        assert any("/api/player/stop" in u for u in urls)
        assert any("/api/outputs/set" in u for u in urls)

    def test_owntone_down_returns_false_not_raise(self):
        with patch("urllib.request.urlopen", side_effect=OSError("Connection refused")):
            ok, msg = stop_owntone_playback()
        assert ok is False
        assert "stop failed" in msg.lower()

    def test_partial_failure_reports_both_calls_attempted(self):
        """If /api/player/stop fails, /api/outputs/set must still be attempted."""
        call_log = []

        def _urlopen(req, timeout=None):
            call_log.append(req.full_url)
            if "/api/player/stop" in req.full_url:
                raise OSError("stop unreachable")
            return _http_mock_response(204)

        with patch("urllib.request.urlopen", side_effect=_urlopen):
            ok, msg = stop_owntone_playback()
        assert ok is False
        assert len(call_log) == 2, "both endpoints must be attempted even if the first fails"
        assert "stop failed" in msg.lower()

    def test_unexpected_http_status_is_reported(self):
        with patch("urllib.request.urlopen", return_value=_http_mock_response(500)):
            ok, msg = stop_owntone_playback()
        assert ok is False
        assert "500" in msg


# ---------------------------------------------------------------------------
# free_repeat_buffer
# ---------------------------------------------------------------------------

class TestFreeRepeatBuffer:
    def test_success_disarms_and_disables(self):
        responses = [
            _ack("set_repeat_armed", True),
            _ack("set_repeat_enabled", True),
        ]
        with _patch_af_unix(), \
             patch("socket.socket", side_effect=_fake_socket_factory(responses)):
            ok, msg = free_repeat_buffer()
        assert ok is True
        assert "set_repeat_armed: ok" in msg
        assert "set_repeat_enabled: ok" in msg

    def test_socket_absent_tolerated(self):
        """Monitor stopped (socket file missing) must not raise and must
        report failure without blocking the update."""
        with _patch_af_unix(), \
             patch("socket.socket", side_effect=OSError("No such file or directory")):
            ok, msg = free_repeat_buffer()
        assert ok is False
        assert "socket unavailable" in msg

    def test_old_binary_rejection_tolerated(self):
        """An old monitor binary predating this feature that rejects the
        commands (unknown command) must not raise; failure is reported and
        logged by the caller, never fatal."""
        responses = [
            _ack("unknown", False, error="unknown command: set_repeat_armed"),
            _ack("unknown", False, error="unknown command: set_repeat_enabled"),
        ]
        with _patch_af_unix(), \
             patch("socket.socket", side_effect=_fake_socket_factory(responses)):
            ok, msg = free_repeat_buffer()
        assert ok is False
        assert "rejected" in msg

    def test_both_commands_attempted_even_if_first_rejected(self):
        responses = [
            _ack("unknown", False, error="unknown command"),
            _ack("set_repeat_enabled", True),
        ]
        with _patch_af_unix(), \
             patch("socket.socket", side_effect=_fake_socket_factory(responses)):
            ok, msg = free_repeat_buffer()
        assert ok is False
        assert "set_repeat_armed" in msg and "rejected" in msg
        assert "set_repeat_enabled: ok" in msg


# ---------------------------------------------------------------------------
# Wiring: autostream_updater.cmd_apply calls both helpers before scheduling
# ---------------------------------------------------------------------------

def _make_tarball(tmp_path: Path, installer_name: str = "autostream_install.sh") -> Path:
    src = tmp_path / "build" / "myrepo-v1.2.3"
    src.mkdir(parents=True)
    script = src / installer_name
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o755)
    (src / "system").mkdir()
    tar_path = tmp_path / "release.tgz"
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(str(src), arcname="myrepo-v1.2.3")
    return tar_path


def _copy_tarball_to(src_tar: Path):
    def _download(url, dst, ua, timeout=120):
        import shutil
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src_tar), str(dst))
    return _download


def _fake_release(tag="v1.2.3", tarball_url="http://example.com/r.tgz"):
    return (True, tag, tarball_url, "http://example.com/releases/v1.2.3", None)


def _load_host(tmp_path: Path) -> ModuleType:
    mod = load_supervisor_script("autostream_updater", "pre_update_teardown_host")
    mod.STAGING_DIR = tmp_path / "staging"
    mod.UPDATE_LOCK_FILE = tmp_path / "update.lock"
    mod.UPDATE_RESULT_FILE = tmp_path / "update-result.env"
    mod.LOG_PATH = tmp_path / "update.log"
    mod.APMODE_FLAG = tmp_path / "_apmode_absent"
    mod.PLAYING_SERVICE = tmp_path / "_playing_absent"
    mod.CONFIG_PATH = tmp_path / "autostream.json"
    return mod


def _with_lock(mod):
    from contextlib import contextmanager

    @contextmanager
    def _ctx():
        with patch.object(mod, "fcntl") as mk:
            mk.LOCK_EX = 2
            mk.LOCK_NB = 4
            mk.LOCK_UN = 8
            mk.flock.return_value = None
            yield mk
    return _ctx()


class TestHostApplyCallsPreUpdateTeardown:
    def _run(self, tmp_path, stop_result=(True, "ok"), free_result=(True, "ok")):
        mod = _load_host(tmp_path)
        tar = _make_tarball(tmp_path)
        stop_mock = MagicMock(return_value=stop_result)
        free_mock = MagicMock(return_value=free_result)
        with patch.object(mod, "_update_unit_active", return_value=False), \
             patch.object(mod, "_resolve_release", return_value=_fake_release()), \
             patch.object(mod, "_read_installed_release_tag", return_value="missing"), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(_asu, "_download_file", side_effect=_copy_tarball_to(tar)), \
             patch.object(_asu, "_run", return_value=(0, "", "")), \
             patch.object(mod, "stop_owntone_playback", stop_mock), \
             patch.object(mod, "free_repeat_buffer", free_mock), \
             _with_lock(mod):
            result = mod.cmd_apply(auto=False)
        return result, mod, stop_mock, free_mock

    def test_both_helpers_called_on_successful_apply(self, tmp_path):
        result, mod, stop_mock, free_mock = self._run(tmp_path)
        assert result["ok"] is True
        stop_mock.assert_called_once()
        free_mock.assert_called_once()

    def test_helpers_called_before_scheduling(self, tmp_path):
        """Both teardown helpers must run before systemd-run schedules the installer."""
        order = []
        mod = _load_host(tmp_path)
        tar = _make_tarball(tmp_path)

        def _stop(*a, **kw):
            order.append("stop")
            return (True, "ok")

        def _free(*a, **kw):
            order.append("free")
            return (True, "ok")

        def _run(cmd, timeout=15):
            order.append("schedule")
            return (0, "", "")

        with patch.object(mod, "_update_unit_active", return_value=False), \
             patch.object(mod, "_resolve_release", return_value=_fake_release()), \
             patch.object(mod, "_read_installed_release_tag", return_value="missing"), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(_asu, "_download_file", side_effect=_copy_tarball_to(tar)), \
             patch.object(_asu, "_run", side_effect=_run), \
             patch.object(mod, "stop_owntone_playback", side_effect=_stop), \
             patch.object(mod, "free_repeat_buffer", side_effect=_free), \
             _with_lock(mod):
            result = mod.cmd_apply(auto=False)

        assert result["ok"] is True
        assert order == ["stop", "free", "schedule"], (
            f"expected teardown before scheduling, got order={order}"
        )

    def test_teardown_failure_does_not_block_update(self, tmp_path):
        """Both helpers returning ok=False must not prevent the installer
        from being scheduled -- these are best-effort, never fatal."""
        result, mod, stop_mock, free_mock = self._run(
            tmp_path,
            stop_result=(False, "owntone down"),
            free_result=(False, "monitor socket unavailable"),
        )
        assert result["ok"] is True
        assert result.get("staged_tag") == "1.2.3"

    def test_teardown_exception_does_not_block_update(self, tmp_path):
        """An unexpected exception raised out of either helper must be caught
        and logged, never propagate and abort the update."""
        mod = _load_host(tmp_path)
        tar = _make_tarball(tmp_path)
        with patch.object(mod, "_update_unit_active", return_value=False), \
             patch.object(mod, "_resolve_release", return_value=_fake_release()), \
             patch.object(mod, "_read_installed_release_tag", return_value="missing"), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(_asu, "_download_file", side_effect=_copy_tarball_to(tar)), \
             patch.object(_asu, "_run", return_value=(0, "", "")), \
             patch.object(mod, "stop_owntone_playback", side_effect=RuntimeError("boom")), \
             patch.object(mod, "free_repeat_buffer", side_effect=RuntimeError("boom2")), \
             _with_lock(mod):
            result = mod.cmd_apply(auto=False)
        assert result["ok"] is True


# ---------------------------------------------------------------------------
# Wiring: autostream_update_retry.main calls both helpers before scheduling
# ---------------------------------------------------------------------------

def _load_retry(tmp_path: Path) -> ModuleType:
    mod = load_supervisor_script("autostream_update_retry", "pre_update_teardown_retry")
    mod.STAMP_DIR = tmp_path
    mod.UPDATE_RESULT_FILE = tmp_path / "update-result.env"
    mod.STAGING_DIR = tmp_path / "staging"
    mod.RELEASE_TAG_FILE = tmp_path / "staging" / "release_tag"
    mod.RETRY_COUNT_FILE = tmp_path / "staging" / "retry_count"
    mod.UPDATING_FLAG = tmp_path / "autostream-updating"
    mod.LOG_PATH = tmp_path / "update.log"
    mod.UPDATE_LOCK_FILE = tmp_path / "update.lock"
    return mod


def _make_installer(staging_dir: Path) -> Path:
    src = staging_dir / "src" / "myrepo-v1.2.3"
    src.mkdir(parents=True)
    installer = src / "autostream_install.sh"
    installer.write_text("#!/bin/sh\nexit 0\n")
    installer.chmod(0o755)
    return installer


def _geteuid_root():
    return patch("os.geteuid", return_value=0, create=True)


def _old_timestamp() -> str:
    from datetime import datetime, timedelta, timezone
    return (datetime.now(tz=timezone.utc) - timedelta(hours=2)).isoformat()


def _write_result(tmp_path: Path, status: str, last_run_at: str = "") -> None:
    (tmp_path / "update-result.env").write_text(
        f'STATUS="{status}"\nLAST_RUN_AT="{last_run_at}"\nMESSAGE="test"\nPERCENT_COMPLETE="0"\n',
        encoding="utf-8",
    )


class TestRetryCallsPreUpdateTeardown:
    def test_both_helpers_called_before_scheduling(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir(parents=True, exist_ok=True)
        _make_installer(mod.STAGING_DIR)
        mod.RETRY_COUNT_FILE.write_text("0\n")
        mod.RELEASE_TAG_FILE.write_text("v1.2.3\n")

        order = []

        def _stop(*a, **kw):
            order.append("stop")
            return (True, "ok")

        def _free(*a, **kw):
            order.append("free")
            return (True, "ok")

        def _run(cmd, timeout=15):
            order.append("schedule")
            return (0, "", "")

        with _geteuid_root(), \
             patch.object(mod, "_is_pre_boot", return_value=True), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_run", side_effect=_run), \
             patch.object(mod, "stop_owntone_playback", side_effect=_stop), \
             patch.object(mod, "free_repeat_buffer", side_effect=_free), \
             patch("os.chown", return_value=None, create=True):
            rc = mod.main()

        assert rc == 0
        assert order == ["stop", "free", "schedule"]

    def test_teardown_failure_does_not_block_retry(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir(parents=True, exist_ok=True)
        _make_installer(mod.STAGING_DIR)
        mod.RETRY_COUNT_FILE.write_text("0\n")
        mod.RELEASE_TAG_FILE.write_text("v1.2.3\n")

        with _geteuid_root(), \
             patch.object(mod, "_is_pre_boot", return_value=True), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_run", return_value=(0, "", "")), \
             patch.object(mod, "stop_owntone_playback", return_value=(False, "owntone down")), \
             patch.object(mod, "free_repeat_buffer", return_value=(False, "socket unavailable")), \
             patch("os.chown", return_value=None, create=True):
            rc = mod.main()

        assert rc == 0

    def test_teardown_exception_does_not_block_retry(self, tmp_path):
        mod = _load_retry(tmp_path)
        _write_result(tmp_path, "in_progress", _old_timestamp())
        mod.STAGING_DIR.mkdir(parents=True, exist_ok=True)
        _make_installer(mod.STAGING_DIR)
        mod.RETRY_COUNT_FILE.write_text("0\n")
        mod.RELEASE_TAG_FILE.write_text("v1.2.3\n")

        with _geteuid_root(), \
             patch.object(mod, "_is_pre_boot", return_value=True), \
             patch.object(mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(mod, "_run", return_value=(0, "", "")), \
             patch.object(mod, "stop_owntone_playback", side_effect=RuntimeError("boom")), \
             patch.object(mod, "free_repeat_buffer", side_effect=RuntimeError("boom2")), \
             patch("os.chown", return_value=None, create=True):
            rc = mod.main()

        assert rc == 0


# ---------------------------------------------------------------------------
# Sanity: autostream_dial_updater does not import/call either helper
# ---------------------------------------------------------------------------

class TestDialUpdaterUnaffected:
    def test_dial_updater_does_not_import_teardown_helpers(self):
        """The dial product has no OwnTone backend and no autostream_monitor
        daemon, so autostream_dial_updater must not reference either helper."""
        mod = load_supervisor_script("autostream_dial_updater", "dial_no_teardown_check")
        assert not hasattr(mod, "stop_owntone_playback")
        assert not hasattr(mod, "free_repeat_buffer")
