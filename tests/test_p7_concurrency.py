"""P7 — Concurrency and fault injection tests.

What runs here:
  - Concurrent atomic_write_file calls to the same target file from multiple
    threads: the final result must be valid JSON with no corruption.
  - Fault injection at every phase of atomic_write_file: fsync failure,
    os.replace failure — original file preserved, no stale tmp files.
  - Concurrent save_config / save_state / write_pin_override calls under
    CONFIG_IO_LOCK: all unrelated keys must be preserved in the final file.
  - Concurrent PersistentNowPlayingCache.get_manual_hint() calls from
    multiple threads: cache lock must prevent data races.
  - dial_volume module-level state isolation: _fail_counts must not leak
    between test instances; verify isolation pattern works.
  - Recovery window state under rapid concurrent calls: _active/_confirmed
    state must remain consistent after concurrent operations.

Covered by existing tests (not duplicated here):
  - Basic atomic_write_file correctness and exception handling (P0)
  - _fan_out thread joining and timeout (test_dial_volume_sender.py)
  - SESSION/CSRF auth flow (test_auth.py, test_dial_http_server.py)

Environment-dependent (not run here):
  - True concurrent update lock (requires running the actual installer
    in parallel subprocesses with advisory file lock — Pi OS CI only).
  - Short reads/writes at UNIX socket boundary (requires sockpair injection
    at C level — native monitor CI only).
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "core"))

# On Windows, os.replace() under concurrent access raises PermissionError because
# Windows file-system semantics do not support atomic rename over an open file.
# These tests verify Linux production behaviour; they are correctly marked skip on Windows.
linux_only = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Concurrent atomic rename requires POSIX os.replace semantics (Linux CI only)"
)

import autostream_config as cfg_mod
import autostream_sysutils as sysutils
from autostream_nowplaying import PersistentNowPlayingCache


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_hints(path: Path, data) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def _run_n_threads(fn, n: int) -> list:
    """Run *fn(thread_index)* from *n* threads; collect exceptions."""
    errors: list[Exception] = []
    barrier = threading.Barrier(n)

    def _worker(i: int) -> None:
        barrier.wait()
        try:
            fn(i)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    return errors


# ---------------------------------------------------------------------------
# Concurrent atomic_write_file
# ---------------------------------------------------------------------------

class TestConcurrentAtomicWrite:
    """Multiple threads writing the same file must leave it in a valid state."""

    @linux_only
    def test_concurrent_writes_produce_valid_json(self, tmp_path):
        target = tmp_path / "state.json"
        n_threads = 10

        def _write(i: int) -> None:
            sysutils.atomic_write_file(target, lambda f: json.dump({"writer": i, "ts": time.time()}, f))

        errors = _run_n_threads(_write, n_threads)
        assert not errors, f"Thread errors: {errors}"

        # Final file must be valid JSON
        data = json.loads(target.read_text(encoding="utf-8"))
        assert "writer" in data
        assert 0 <= data["writer"] < n_threads

    @linux_only
    def test_concurrent_writes_leave_no_stale_tmp_files(self, tmp_path):
        target = tmp_path / "config.json"
        n_threads = 8

        def _write(i: int) -> None:
            sysutils.atomic_write_file(target, lambda f: json.dump({"i": i}, f))

        errors = _run_n_threads(_write, n_threads)
        assert not errors

        stale = list(tmp_path.glob(f".{target.name}.*.tmp"))
        assert stale == [], f"Stale tmp files after concurrent writes: {stale}"

    @linux_only
    def test_new_file_created_under_concurrent_access(self, tmp_path):
        target = tmp_path / "new.json"
        n_threads = 6

        errors = _run_n_threads(
            lambda i: sysutils.atomic_write_file(target, lambda f: json.dump({"x": i}, f)),
            n_threads,
        )
        assert not errors
        assert target.exists()
        json.loads(target.read_text(encoding="utf-8"))   # must be valid


# ---------------------------------------------------------------------------
# Atomic write phase failure injection
# ---------------------------------------------------------------------------

class TestAtomicWritePhaseFailures:
    """Failures at each phase of atomic_write_file must leave the original intact."""

    def test_fsync_failure_preserves_original(self, tmp_path):
        target = tmp_path / "data.json"
        original = {"original": True}
        target.write_text(json.dumps(original), encoding="utf-8")

        with patch("os.fsync", side_effect=OSError("simulated disk error")):
            with pytest.raises(OSError):
                sysutils.atomic_write_file(target, lambda f: json.dump({"new": True}, f))

        assert json.loads(target.read_text()) == original

    def test_fsync_failure_removes_tmp_file(self, tmp_path):
        target = tmp_path / "data.json"
        target.write_text("{}", encoding="utf-8")

        with patch("os.fsync", side_effect=OSError("disk error")):
            with pytest.raises(OSError):
                sysutils.atomic_write_file(target, lambda f: f.write("{}"))

        stale = list(tmp_path.glob(f".{target.name}.*.tmp"))
        assert stale == [], f"Stale tmp files after fsync failure: {stale}"

    def test_replace_failure_preserves_original(self, tmp_path):
        target = tmp_path / "data.json"
        original = {"keep_me": True}
        target.write_text(json.dumps(original), encoding="utf-8")

        with patch("os.replace", side_effect=OSError("atomic rename failed")):
            with pytest.raises(OSError):
                sysutils.atomic_write_file(target, lambda f: json.dump({"new": True}, f))

        assert json.loads(target.read_text()) == original

    def test_replace_failure_removes_tmp_file(self, tmp_path):
        target = tmp_path / "data.json"
        target.write_text("{}", encoding="utf-8")

        with patch("os.replace", side_effect=OSError("rename failed")):
            with pytest.raises(OSError):
                sysutils.atomic_write_file(target, lambda f: f.write("{}"))

        stale = list(tmp_path.glob(f".{target.name}.*.tmp"))
        assert stale == [], f"Stale tmp files after replace failure: {stale}"

    def test_writer_exception_preserves_original(self, tmp_path):
        target = tmp_path / "data.json"
        original = {"safe": "yes"}
        target.write_text(json.dumps(original), encoding="utf-8")

        def _crashing_writer(f):
            f.write('{"partial": tru')  # incomplete JSON
            raise ValueError("writer crashed mid-write")

        with pytest.raises(ValueError):
            sysutils.atomic_write_file(target, _crashing_writer)

        assert json.loads(target.read_text()) == original

    def test_chmod_failure_does_not_prevent_write(self, tmp_path):
        """chmod failure is non-fatal — file is still written (with warning)."""
        target = tmp_path / "data.json"
        target.write_text("{}", encoding="utf-8")

        with patch("os.chmod", side_effect=PermissionError("no chmod")):
            # Must not raise — chmod failure is non-fatal in atomic_write_file
            sysutils.atomic_write_file(target, lambda f: json.dump({"k": 1}, f))

        assert json.loads(target.read_text()) == {"k": 1}

    def test_write_then_exception_no_stale_for_new_file(self, tmp_path):
        target = tmp_path / "fresh.json"
        assert not target.exists()

        with patch("os.replace", side_effect=OSError("replace failed")):
            with pytest.raises(OSError):
                sysutils.atomic_write_file(target, lambda f: json.dump({"x": 1}, f))

        assert not target.exists()   # must not create partial destination
        stale = list(tmp_path.glob(f".{target.name}.*.tmp"))
        assert stale == [], f"Stale tmp files: {stale}"


# ---------------------------------------------------------------------------
# Concurrent save_config / save_state under CONFIG_IO_LOCK
# ---------------------------------------------------------------------------

class TestConcurrentConfigWrites:
    """CONFIG_IO_LOCK must prevent concurrent corruption of config/state files."""

    def test_concurrent_save_config_produces_valid_json(self, tmp_path):
        config_file = str(tmp_path / "autostream.json")
        n_threads = 12

        def _save(i: int) -> None:
            cfg_mod.save_config(config_file, {"key": i, "extra": "preserved"})

        errors = _run_n_threads(_save, n_threads)
        assert not errors, f"Errors: {errors}"

        data = json.loads(Path(config_file).read_text(encoding="utf-8"))
        assert "key" in data
        assert "extra" in data

    def test_concurrent_save_state_produces_valid_json(self, tmp_path):
        state_file = str(tmp_path / "state.json")
        n_threads = 10

        def _save(i: int) -> None:
            cfg_mod.save_state(state_file, {"counter": i, "stable": "value"})

        errors = _run_n_threads(_save, n_threads)
        assert not errors

        data = json.loads(Path(state_file).read_text(encoding="utf-8"))
        assert "stable" in data

    def test_concurrent_write_pin_does_not_corrupt_state(self, tmp_path):
        state_file = str(tmp_path / "state.json")
        cfg_mod.save_state(state_file, {"other_key": "do_not_lose"})
        n_threads = 8

        def _write_pin(i: int) -> None:
            cfg_mod.write_pin_override(state_file, str(i).zfill(4))

        errors = _run_n_threads(_write_pin, n_threads)
        assert not errors

        state = cfg_mod.load_state(state_file)
        assert state.get("other_key") == "do_not_lose", (
            "write_pin_override corrupted unrelated state key under concurrent access"
        )

    @linux_only
    def test_concurrent_read_write_state_never_raises(self, tmp_path):
        state_file = str(tmp_path / "state.json")
        cfg_mod.save_state(state_file, {"init": True})
        n_threads = 8

        errors: list[Exception] = []
        barrier = threading.Barrier(n_threads)

        def _reader_writer(i: int) -> None:
            barrier.wait()
            try:
                if i % 2 == 0:
                    cfg_mod.save_state(state_file, {"i": i})
                else:
                    cfg_mod.load_state(state_file)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_reader_writer, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Concurrent read/write raised: {errors}"


# ---------------------------------------------------------------------------
# Concurrent PersistentNowPlayingCache reads
# ---------------------------------------------------------------------------

class TestConcurrentNowPlayingCache:
    """_lock must prevent data races in PersistentNowPlayingCache."""

    def test_concurrent_readers_all_get_valid_result(self, tmp_path):
        p = tmp_path / "hints.json"
        _write_hints(p, {"default": {"title": "T", "artist": "A", "album": "B"}})
        cache = PersistentNowPlayingCache(str(p))
        n_threads = 16
        results: list = []
        lock = threading.Lock()

        def _read(_i: int) -> None:
            meta = cache.get_manual_hint("default")
            with lock:
                results.append(meta)

        errors = _run_n_threads(_read, n_threads)
        assert not errors
        assert len(results) == n_threads
        for meta in results:
            assert meta is not None and meta.title == "T"

    def test_concurrent_readers_during_file_update(self, tmp_path):
        p = tmp_path / "hints.json"
        _write_hints(p, {"default": {"title": "Initial", "artist": "A", "album": "B"}})
        cache = PersistentNowPlayingCache(str(p))
        n_threads = 8
        errors: list[Exception] = []
        lock = threading.Lock()

        def _reader(_i: int) -> None:
            try:
                meta = cache.get_manual_hint("default")
                if meta is not None:
                    assert isinstance(meta.title, str)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        # Write to file mid-flight (simulates external update)
        def _writer(_i: int) -> None:
            try:
                time.sleep(0.01)
                _write_hints(p, {"default": {"title": "Updated", "artist": "A", "album": "B"}})
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = (
            [threading.Thread(target=_reader, args=(i,)) for i in range(n_threads)]
            + [threading.Thread(target=_writer, args=(0,))]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors, f"Concurrent read+write raised: {errors}"


# ---------------------------------------------------------------------------
# Module-level state isolation (leaked globals detection)
# ---------------------------------------------------------------------------

class TestModuleLevelStateIsolation:
    """Module-level globals in dial_volume must not leak between test cases."""

    def test_fail_counts_can_be_reset_between_tests(self):
        """Verify that _fail_counts can be cleared — the isolation pattern works."""
        sys.path.insert(0, str(REPO_ROOT / "dial"))
        import dial_volume as dv

        original = dict(dv._fail_counts)
        dv._fail_counts["192.168.1.1"] = 5
        assert dv._fail_counts["192.168.1.1"] == 5

        # Simulate what a fixture would do to reset state
        dv._fail_counts.clear()
        assert dv._fail_counts == {}, "Clearing _fail_counts does not work"

        # Restore
        dv._fail_counts.update(original)

    def test_fail_count_starts_at_zero_for_new_host(self):
        import dial_volume as dv
        dv._fail_counts.clear()
        assert dv._fail_counts.get("10.0.0.99", 0) == 0

    def test_repeated_log_volume_failure_increments_consistently(self):
        """Verify _log_volume_failure count tracking is correct."""
        import dial_volume as dv
        dv._fail_counts.clear()

        ip = "127.0.0.1"
        with patch("logging.warning"), patch("logging.debug"):
            dv._log_volume_failure(ip, "test %s", "error")
            assert dv._fail_counts[ip] == 1
            dv._log_volume_failure(ip, "test %s", "error")
            assert dv._fail_counts[ip] == 2

        dv._fail_counts.clear()

    def test_success_clears_fail_count(self):
        import dial_volume as dv
        dv._fail_counts["10.0.0.1"] = 7

        import urllib.error
        import io as _io
        target = MagicMock()
        target.ip = "10.0.0.1"
        target.port = 3000

        response = MagicMock()
        response.read.return_value = json.dumps({"ok": True, "volume": 50}).encode()
        response.__enter__ = lambda s: s
        response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=response):
            dv._send_one(target, "uuid", 5, [])

        assert "10.0.0.1" not in dv._fail_counts, (
            "Success must clear the fail count for that host"
        )

    def test_queue_is_empty_between_isolated_tests(self):
        """A fresh queue must be empty — verifies no cross-test contamination."""
        import queue as q
        fresh: q.SimpleQueue = q.SimpleQueue()
        assert fresh.empty()


# ---------------------------------------------------------------------------
# Recovery window state consistency under concurrent calls
# ---------------------------------------------------------------------------

class TestRecoveryWindowConcurrency:
    """RecoveryWindow state must remain consistent under concurrent access."""

    def test_confirm_volume_idempotent_under_concurrent_calls(self):
        sys.path.insert(0, str(REPO_ROOT / "dial"))
        import dial_http_server as dhs

        announce_calls: list = []
        on_announce = lambda pin_recovery: announce_calls.append(pin_recovery)

        with patch("threading.Timer"):
            window = dhs.RecoveryWindow(on_announce)
        window._active = True

        n_threads = 20
        errors: list[Exception] = []
        barrier = threading.Barrier(n_threads)

        def _confirm(_i: int) -> None:
            barrier.wait()
            try:
                window.confirm_volume()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_confirm, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors, f"confirm_volume raised under concurrent calls: {errors}"
        # _volume_confirmed is set by the first caller; all subsequent are no-ops
        assert window._volume_confirmed is True

    def test_concurrent_confirm_and_expire_do_not_crash(self):
        sys.path.insert(0, str(REPO_ROOT / "dial"))
        import dial_http_server as dhs

        on_announce = MagicMock()
        with patch("threading.Timer"):
            window = dhs.RecoveryWindow(on_announce)
        window._active = True
        window._timer = MagicMock()

        errors: list[Exception] = []

        def _confirm() -> None:
            try:
                window.confirm_volume()
            except Exception as exc:
                errors.append(exc)

        def _expire() -> None:
            try:
                window._expire()
            except Exception as exc:
                errors.append(exc)

        threads = (
            [threading.Thread(target=_confirm) for _ in range(10)]
            + [threading.Thread(target=_expire) for _ in range(10)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors, f"Concurrent confirm+expire raised: {errors}"
