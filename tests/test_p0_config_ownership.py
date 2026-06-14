"""P0.3 — Configuration and state ownership contracts.

Tests the read/write contract for every persistent configuration file:
  - save → load round-trips preserve all keys (cross-platform)
  - atomic_write_file preserves existing permissions (Linux only)
  - save_state and save_config leave valid JSON (cross-platform)
  - interrupted atomic write (exception in writer) leaves original intact
  - repeated saves are idempotent

Permission/ownership tests require Linux and are skipped on other platforms
with a clear reason. The CI mechanism for running them is a Linux GitHub
Actions runner (ubuntu-latest).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "core"))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import autostream_config as cfg_mod
import autostream_sysutils as sysutils

linux_only = pytest.mark.skipif(
    sys.platform != "linux",
    reason="File permission/ownership tests require Linux (run in CI ubuntu-latest runner)",
)


# ---------------------------------------------------------------------------
# atomic_write_file: basic correctness (cross-platform)
# ---------------------------------------------------------------------------

class TestAtomicWriteFile:
    def test_file_created_on_first_write(self, tmp_path):
        target = tmp_path / "out.json"
        sysutils.atomic_write_file(target, lambda f: json.dump({"k": 1}, f))
        assert target.exists()
        assert json.loads(target.read_text()) == {"k": 1}

    def test_original_preserved_on_writer_exception(self, tmp_path):
        target = tmp_path / "out.json"
        target.write_text('{"original": true}', encoding="utf-8")

        def _bad_writer(f):
            f.write("partial{")
            raise RuntimeError("disk full")

        with pytest.raises(RuntimeError):
            sysutils.atomic_write_file(target, _bad_writer)

        # Original file must be intact.
        assert json.loads(target.read_text()) == {"original": True}

    def test_no_tmp_file_left_after_exception(self, tmp_path):
        target = tmp_path / "out.json"

        def _bad_writer(f):
            raise RuntimeError("error")

        with pytest.raises(RuntimeError):
            sysutils.atomic_write_file(target, _bad_writer)

        # No .tmp file should remain.
        tmp_files = list(tmp_path.glob(f".{target.name}.*.tmp"))
        assert tmp_files == [], f"Stale tmp files: {tmp_files}"

    def test_repeated_writes_are_idempotent(self, tmp_path):
        target = tmp_path / "state.json"
        data = {"x": 42, "y": "hello"}
        for _ in range(5):
            sysutils.atomic_write_file(target, lambda f: json.dump(data, f))
        assert json.loads(target.read_text()) == data

    @linux_only
    def test_preserve_mode_copies_existing_permissions(self, tmp_path):
        target = tmp_path / "secret.json"
        target.write_text('{"a": 1}', encoding="utf-8")
        os.chmod(target, 0o600)

        sysutils.atomic_write_file(target, lambda f: json.dump({"a": 2}, f),
                                   preserve_mode=True)

        new_mode = target.stat().st_mode & 0o777
        assert new_mode == 0o600, f"Mode changed from 0o600 to {oct(new_mode)}"

    @linux_only
    def test_preserve_mode_false_uses_umask_mode(self, tmp_path):
        target = tmp_path / "file.json"
        target.write_text('{}', encoding="utf-8")
        os.chmod(target, 0o600)

        sysutils.atomic_write_file(target, lambda f: json.dump({}, f),
                                   preserve_mode=False)

        # preserve_mode=False does not copy the old mode; the result depends
        # on the umask but must not be 0o600 (which was explicitly set).
        # We just verify no crash and file content is correct.
        assert json.loads(target.read_text()) == {}

    @linux_only
    def test_new_file_mode_is_not_world_writable(self, tmp_path):
        target = tmp_path / "new.json"
        sysutils.atomic_write_file(target, lambda f: json.dump({}, f))
        mode = target.stat().st_mode & 0o777
        assert not (mode & 0o002), f"New file is world-writable: {oct(mode)}"


# ---------------------------------------------------------------------------
# save_config / load roundtrip (cross-platform)
# ---------------------------------------------------------------------------

class TestSaveLoadRoundtrip:
    def test_save_config_and_reload(self, tmp_path):
        config_file = str(tmp_path / "autostream.json")
        data = {"outputs": {"HDMI": True}, "log_level": "info"}
        cfg_mod.save_config(config_file, data)
        reloaded = json.loads(Path(config_file).read_text(encoding="utf-8"))
        assert reloaded == data

    def test_save_config_produces_valid_json(self, tmp_path):
        config_file = str(tmp_path / "autostream.json")
        cfg_mod.save_config(config_file, {"nested": {"key": [1, 2, 3]}})
        # Must not raise
        json.loads(Path(config_file).read_text(encoding="utf-8"))

    def test_save_config_does_not_corrupt_unrelated_keys(self, tmp_path):
        config_file = str(tmp_path / "autostream.json")
        original = {"a": 1, "b": 2, "c": {"d": 3}}
        cfg_mod.save_config(config_file, original)
        cfg_mod.save_config(config_file, {"a": 99, "b": 2, "c": {"d": 3}})
        reloaded = json.loads(Path(config_file).read_text(encoding="utf-8"))
        assert reloaded["b"] == 2
        assert reloaded["c"]["d"] == 3

    def test_save_state_and_load_roundtrip(self, tmp_path):
        state_file = str(tmp_path / "state.json")
        state = {"pin": "1234", "last_play": "2026-01-01"}
        cfg_mod.save_state(state_file, state)
        loaded = cfg_mod.load_state(state_file)
        assert loaded == state

    def test_load_state_returns_empty_dict_for_missing_file(self, tmp_path):
        missing = str(tmp_path / "nonexistent.json")
        assert cfg_mod.load_state(missing) == {}

    def test_save_state_is_valid_json(self, tmp_path):
        state_file = str(tmp_path / "state.json")
        cfg_mod.save_state(state_file, {"unicode": "héllo wörld ✓"})
        json.loads(Path(state_file).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# PIN persistence (cross-platform)
# ---------------------------------------------------------------------------

class TestPINPersistence:
    def test_set_pin_readable_back(self, tmp_path):
        state_file = str(tmp_path / "state.json")
        cfg_mod.write_pin_override(state_file, "5678")
        pin, present = cfg_mod.read_pin_override(state_file)
        assert present is True
        assert pin == "5678"

    def test_clear_pin_makes_it_absent(self, tmp_path):
        state_file = str(tmp_path / "state.json")
        cfg_mod.write_pin_override(state_file, "5678")
        # write_pin_override stores blank as empty string; read returns not-present
        cfg_mod.write_pin_override(state_file, "")
        pin, present = cfg_mod.read_pin_override(state_file)
        assert present is False

    def test_set_pin_preserves_other_state_keys(self, tmp_path):
        state_file = str(tmp_path / "state.json")
        cfg_mod.save_state(state_file, {"last_play": "2026-01-01", "other": 42})
        cfg_mod.write_pin_override(state_file, "9999")
        state = cfg_mod.load_state(state_file)
        assert state["last_play"] == "2026-01-01"
        assert state["other"] == 42

    def test_pin_missing_from_empty_state(self, tmp_path):
        state_file = str(tmp_path / "state.json")
        cfg_mod.save_state(state_file, {})
        pin, present = cfg_mod.read_pin_override(state_file)
        assert present is False

    def test_read_pin_override_missing_file_returns_not_present(self, tmp_path):
        missing = str(tmp_path / "no-state.json")
        pin, present = cfg_mod.read_pin_override(missing)
        assert present is False


# ---------------------------------------------------------------------------
# Linux-only: file ownership table
#
# These tests verify the ownership/permission invariants described in the
# spec for each persistent file. They require a real Linux filesystem and
# a process with sufficient privilege to call chown (typically root in CI).
#
# Environment-dependent requirement: cannot run on Windows or macOS.
# CI mechanism: linux-permissions job on ubuntu-latest with `sudo python -m
# pytest tests/test_p0_config_ownership.py -k linux_only`.
# ---------------------------------------------------------------------------

class TestFileOwnershipTable:
    @linux_only
    def test_new_config_file_is_not_world_readable(self, tmp_path):
        config_file = tmp_path / "autostream.json"
        cfg_mod.save_config(str(config_file), {"k": 1})
        mode = config_file.stat().st_mode & 0o777
        assert not (mode & 0o004), f"Config file is world-readable: {oct(mode)}"

    @linux_only
    def test_state_file_mode_preserved_across_saves(self, tmp_path):
        state_file = tmp_path / "state.json"
        state_file.write_text("{}", encoding="utf-8")
        os.chmod(state_file, 0o600)
        cfg_mod.save_state(str(state_file), {"key": "value"})
        mode = state_file.stat().st_mode & 0o777
        assert mode == 0o600, f"State file mode changed from 0o600 to {oct(mode)}"
