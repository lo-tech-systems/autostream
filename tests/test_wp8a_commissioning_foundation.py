"""tests/test_wp8a_commissioning_foundation.py

WP8A acceptance tests: commissioning-state foundation.

Tests cover:
  - is_technically_complete: missing/empty/invalid config, all fields present
  - is_commissioning_required:
      * missing/incomplete config → True
      * technically complete + no marker → False (legacy compatible)
      * technically complete + malformed marker → False (fail safe)
      * technically complete + required=True, completed=False → True
      * technically complete + required=True, completed=True → False
      * technically complete + required=False → False
  - required_first_boot_step: OwnTone vs Appliance vs None
  - ensure_commissioning_marker: idempotent, preserves other state keys
  - mark_commissioning_complete: preserves concurrent state, re-reads under lock
"""
from __future__ import annotations

import json
import os
import sys
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))


# ── Helpers ────────────────────────────────────────────────────────────────────

VALID_ALSA = "hw:0,0"

def _write_config(path: str, data: dict) -> None:
    with open(path, "w") as f:
        json.dump(data, f)


def _write_state(path: str, data: dict) -> None:
    with open(path, "w") as f:
        json.dump(data, f)


def _complete_config() -> dict:
    return {
        "general": {"fifo_path": "/tmp/fifo"},
        "audio1": {"capture_device": VALID_ALSA},
        "owntone": {"output_name": "Kitchen"},
    }


# ── is_technically_complete ───────────────────────────────────────────────────

class TestIsTechnicallyComplete:
    def test_missing_file_returns_false(self, tmp_path):
        from autostream_commissioning import is_technically_complete
        assert is_technically_complete(str(tmp_path / "nonexistent.json")) is False

    def test_empty_file_returns_false(self, tmp_path):
        from autostream_commissioning import is_technically_complete
        path = str(tmp_path / "config.json")
        with open(path, "w") as f:
            f.write("")
        assert is_technically_complete(path) is False

    def test_empty_json_object_returns_false(self, tmp_path):
        from autostream_commissioning import is_technically_complete
        path = str(tmp_path / "config.json")
        _write_config(path, {})
        assert is_technically_complete(path) is False

    def test_missing_fifo_path_returns_false(self, tmp_path):
        from autostream_commissioning import is_technically_complete
        path = str(tmp_path / "config.json")
        cfg = _complete_config()
        cfg["general"].pop("fifo_path")
        _write_config(path, cfg)
        assert is_technically_complete(path) is False

    def test_invalid_alsa_device_returns_false(self, tmp_path):
        from autostream_commissioning import is_technically_complete
        path = str(tmp_path / "config.json")
        cfg = _complete_config()
        cfg["audio1"]["capture_device"] = "not-alsa"
        _write_config(path, cfg)
        assert is_technically_complete(path) is False

    def test_missing_output_name_returns_false(self, tmp_path):
        from autostream_commissioning import is_technically_complete
        path = str(tmp_path / "config.json")
        cfg = _complete_config()
        cfg["owntone"].pop("output_name")
        _write_config(path, cfg)
        assert is_technically_complete(path) is False

    def test_complete_config_returns_true(self, tmp_path):
        from autostream_commissioning import is_technically_complete
        path = str(tmp_path / "config.json")
        _write_config(path, _complete_config())
        assert is_technically_complete(path) is True

    def test_audio1_disabled_with_no_device_returns_true(self, tmp_path):
        from autostream_commissioning import is_technically_complete
        path = str(tmp_path / "config.json")
        cfg = _complete_config()
        cfg["audio1"] = {"enabled": False}
        _write_config(path, cfg)
        assert is_technically_complete(path) is True

    def test_audio1_disabled_with_invalid_device_returns_true(self, tmp_path):
        from autostream_commissioning import is_technically_complete
        path = str(tmp_path / "config.json")
        cfg = _complete_config()
        cfg["audio1"] = {"enabled": False, "capture_device": "not-alsa"}
        _write_config(path, cfg)
        assert is_technically_complete(path) is True

    def test_audio1_enabled_explicit_true_with_invalid_device_returns_false(self, tmp_path):
        from autostream_commissioning import is_technically_complete
        path = str(tmp_path / "config.json")
        cfg = _complete_config()
        cfg["audio1"] = {"enabled": True, "capture_device": "not-alsa"}
        _write_config(path, cfg)
        assert is_technically_complete(path) is False


# ── is_commissioning_required ─────────────────────────────────────────────────

class TestIsCommissioningRequired:
    def _paths(self, tmp_path, config_data=None, state_data=None):
        cfg_path = str(tmp_path / "config.json")
        state_path = str(tmp_path / "state.json")
        if config_data is not None:
            _write_config(cfg_path, config_data)
        if state_data is not None:
            _write_state(state_path, state_data)
        else:
            _write_state(state_path, {})
        return cfg_path, state_path

    def test_missing_config_requires_commissioning(self, tmp_path):
        from autostream_commissioning import is_commissioning_required
        cfg_path = str(tmp_path / "missing.json")
        state_path = str(tmp_path / "state.json")
        _write_state(state_path, {})
        assert is_commissioning_required(cfg_path, state_path) is True

    def test_incomplete_config_requires_commissioning(self, tmp_path):
        from autostream_commissioning import is_commissioning_required
        cfg_path, state_path = self._paths(tmp_path, config_data={})
        assert is_commissioning_required(cfg_path, state_path) is True

    def test_complete_no_marker_is_legacy_configured(self, tmp_path):
        from autostream_commissioning import is_commissioning_required
        cfg_path, state_path = self._paths(tmp_path, _complete_config(), {})
        assert is_commissioning_required(cfg_path, state_path) is False

    def test_complete_malformed_marker_is_configured(self, tmp_path):
        from autostream_commissioning import is_commissioning_required
        cfg_path, state_path = self._paths(
            tmp_path, _complete_config(), {"first_boot": "bad_value"}
        )
        assert is_commissioning_required(cfg_path, state_path) is False

    def test_complete_malformed_inner_marker_is_configured(self, tmp_path):
        from autostream_commissioning import is_commissioning_required
        cfg_path, state_path = self._paths(
            tmp_path, _complete_config(),
            {"first_boot": {"required": "yes", "completed": "no"}}
        )
        assert is_commissioning_required(cfg_path, state_path) is False

    def test_complete_required_true_completed_false_requires_commissioning(self, tmp_path):
        from autostream_commissioning import is_commissioning_required
        cfg_path, state_path = self._paths(
            tmp_path, _complete_config(),
            {"first_boot": {"required": True, "completed": False}}
        )
        assert is_commissioning_required(cfg_path, state_path) is True

    def test_complete_required_true_completed_true_is_configured(self, tmp_path):
        from autostream_commissioning import is_commissioning_required
        cfg_path, state_path = self._paths(
            tmp_path, _complete_config(),
            {"first_boot": {"required": True, "completed": True}}
        )
        assert is_commissioning_required(cfg_path, state_path) is False

    def test_complete_required_false_is_configured(self, tmp_path):
        from autostream_commissioning import is_commissioning_required
        cfg_path, state_path = self._paths(
            tmp_path, _complete_config(),
            {"first_boot": {"required": False, "completed": False}}
        )
        assert is_commissioning_required(cfg_path, state_path) is False

    def test_audio1_disabled_no_marker_is_legacy_configured(self, tmp_path):
        from autostream_commissioning import is_commissioning_required
        cfg = _complete_config()
        cfg["audio1"] = {"enabled": False}
        cfg_path, state_path = self._paths(tmp_path, cfg, {})
        assert is_commissioning_required(cfg_path, state_path) is False

    def test_incomplete_config_with_completed_marker_still_requires_commissioning(self, tmp_path):
        from autostream_commissioning import is_commissioning_required
        cfg_path, state_path = self._paths(
            tmp_path, {},
            {"first_boot": {"required": True, "completed": True}}
        )
        assert is_commissioning_required(cfg_path, state_path) is True


# ── required_first_boot_step ──────────────────────────────────────────────────

class TestRequiredFirstBootStep:
    def _paths(self, tmp_path, config_data, state_data):
        cfg_path = str(tmp_path / "config.json")
        state_path = str(tmp_path / "state.json")
        _write_config(cfg_path, config_data)
        _write_state(state_path, state_data)
        return cfg_path, state_path

    def test_configured_device_returns_none(self, tmp_path):
        from autostream_commissioning import required_first_boot_step
        cfg_path, state_path = self._paths(tmp_path, _complete_config(), {})
        assert required_first_boot_step(cfg_path, state_path) is None

    def test_missing_output_name_returns_owntone(self, tmp_path):
        from autostream_commissioning import required_first_boot_step
        cfg = _complete_config()
        cfg["owntone"]["output_name"] = ""
        cfg_path, state_path = self._paths(
            tmp_path, cfg,
            {"first_boot": {"required": True, "completed": False}}
        )
        assert required_first_boot_step(cfg_path, state_path) == "owntone"

    def test_output_set_but_alsa_missing_returns_appliance(self, tmp_path):
        from autostream_commissioning import required_first_boot_step
        cfg = _complete_config()
        cfg["audio1"]["capture_device"] = ""
        cfg_path, state_path = self._paths(
            tmp_path, cfg,
            {"first_boot": {"required": True, "completed": False}}
        )
        assert required_first_boot_step(cfg_path, state_path) == "appliance"

    def test_missing_config_returns_owntone(self, tmp_path):
        from autostream_commissioning import required_first_boot_step
        cfg_path = str(tmp_path / "missing.json")
        state_path = str(tmp_path / "state.json")
        _write_state(state_path, {})
        assert required_first_boot_step(cfg_path, state_path) == "owntone"


# ── ensure_commissioning_marker ────────────────────────────────────────────────

class TestEnsureCommissioningMarker:
    def test_writes_marker_when_absent(self, tmp_path):
        from autostream_commissioning import ensure_commissioning_marker
        state_path = str(tmp_path / "state.json")
        _write_state(state_path, {"other": "data"})
        ensure_commissioning_marker(state_path)
        with open(state_path) as f:
            state = json.load(f)
        assert state["first_boot"]["required"] is True
        assert state["first_boot"]["completed"] is False
        assert state["other"] == "data"

    def test_idempotent_when_marker_already_correct(self, tmp_path):
        from autostream_commissioning import ensure_commissioning_marker
        state_path = str(tmp_path / "state.json")
        _write_state(state_path, {"first_boot": {"required": True, "completed": False}, "x": 1})
        import time
        mtime_before = os.path.getmtime(state_path)
        time.sleep(0.05)
        ensure_commissioning_marker(state_path)
        mtime_after = os.path.getmtime(state_path)
        assert mtime_after == pytest.approx(mtime_before, abs=0.01)

    def test_overwrites_malformed_marker(self, tmp_path):
        from autostream_commissioning import ensure_commissioning_marker
        state_path = str(tmp_path / "state.json")
        _write_state(state_path, {"first_boot": "bad"})
        ensure_commissioning_marker(state_path)
        with open(state_path) as f:
            state = json.load(f)
        assert state["first_boot"]["required"] is True
        assert state["first_boot"]["completed"] is False

    def test_preserves_concurrent_state_keys(self, tmp_path):
        from autostream_commissioning import ensure_commissioning_marker
        state_path = str(tmp_path / "state.json")
        _write_state(state_path, {"owntone": {"known_outputs": {"42": "Kitchen"}}, "pin": "secret"})
        ensure_commissioning_marker(state_path)
        with open(state_path) as f:
            state = json.load(f)
        assert state["owntone"]["known_outputs"]["42"] == "Kitchen"
        assert state["pin"] == "secret"


# ── mark_commissioning_complete ────────────────────────────────────────────────

class TestMarkCommissioningComplete:
    def test_writes_completed_true(self, tmp_path):
        from autostream_commissioning import mark_commissioning_complete
        state_path = str(tmp_path / "state.json")
        _write_state(state_path, {"first_boot": {"required": True, "completed": False}})
        mark_commissioning_complete(state_path)
        with open(state_path) as f:
            state = json.load(f)
        assert state["first_boot"]["required"] is True
        assert state["first_boot"]["completed"] is True

    def test_preserves_other_state_keys(self, tmp_path):
        from autostream_commissioning import mark_commissioning_complete
        state_path = str(tmp_path / "state.json")
        _write_state(state_path, {
            "first_boot": {"required": True, "completed": False},
            "owntone": {"known_outputs": {"1": "Lounge"}},
            "pin": "1234",
        })
        mark_commissioning_complete(state_path)
        with open(state_path) as f:
            state = json.load(f)
        assert state["owntone"]["known_outputs"]["1"] == "Lounge"
        assert state["pin"] == "1234"

    def test_process_like_reload_returns_configured(self, tmp_path):
        """After mark_commissioning_complete, a cold re-read returns is_commissioning_required=False."""
        from autostream_commissioning import mark_commissioning_complete, is_commissioning_required
        cfg_path = str(tmp_path / "config.json")
        state_path = str(tmp_path / "state.json")
        _write_config(cfg_path, _complete_config())
        _write_state(state_path, {"first_boot": {"required": True, "completed": False}})
        assert is_commissioning_required(cfg_path, state_path) is True
        mark_commissioning_complete(state_path)
        assert is_commissioning_required(cfg_path, state_path) is False
