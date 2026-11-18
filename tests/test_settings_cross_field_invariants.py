"""Tests for cross-field settings invariants folded into schema-declared
``FieldSpec.cross_validate`` callables, used by ``POST /api/settings``.

Covers:
  1. The two cross_validate callables in isolation
    (autostream_settings_schema.py).
  2. SettingsStore.set()/_set_normalized() enforcing the duplicate-device
     invariant atomically (the route-level cases are in
     test_settings_route_ports.py).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_settings_schema import (
    CrossFieldValidationError,
    cross_validate_capture_device_unique,
    cross_validate_hostname_visibility_cascade,
)


# ---------------------------------------------------------------------------
# 1. Cross-field callables in isolation
# ---------------------------------------------------------------------------

class TestCrossValidateCaptureDeviceUnique:
    def test_raises_when_other_input_has_same_device(self):
        raw = {"audio1": {"capture_device": "hw:0,0"}, "audio2": {"capture_device": "hw:0,0"}}
        with pytest.raises(CrossFieldValidationError, match="already assigned to the other input"):
            cross_validate_capture_device_unique(raw, "audio1", "capture_device", "hw:0,0")

    def test_no_raise_when_devices_differ(self):
        raw = {"audio1": {"capture_device": "hw:0,0"}, "audio2": {"capture_device": "hw:1,0"}}
        cross_validate_capture_device_unique(raw, "audio1", "capture_device", "hw:0,0")  # no raise

    def test_empty_value_never_raises(self):
        raw = {"audio1": {"capture_device": ""}, "audio2": {"capture_device": ""}}
        cross_validate_capture_device_unique(raw, "audio1", "capture_device", "")  # no raise

    def test_checks_correct_other_section_for_audio2(self):
        raw = {"audio1": {"capture_device": "hw:2,0"}, "audio2": {"capture_device": "hw:2,0"}}
        with pytest.raises(CrossFieldValidationError):
            cross_validate_capture_device_unique(raw, "audio2", "capture_device", "hw:2,0")


class TestCrossValidateHostnameVisibilityCascade:
    def test_turning_off_forces_control_other_appliances_false(self):
        raw = {"webui": {"control_other_appliances": True}}
        cross_validate_hostname_visibility_cascade(raw, "webui", "show_hostname_on_home", False)
        assert raw["webui"]["control_other_appliances"] is False

    def test_turning_on_does_not_touch_control_other_appliances(self):
        raw = {"webui": {"control_other_appliances": True}}
        cross_validate_hostname_visibility_cascade(raw, "webui", "show_hostname_on_home", True)
        assert raw["webui"]["control_other_appliances"] is True

    def test_creates_webui_block_if_absent(self):
        raw = {}
        cross_validate_hostname_visibility_cascade(raw, "webui", "show_hostname_on_home", False)
        assert raw["webui"]["control_other_appliances"] is False


# ---------------------------------------------------------------------------
# 2. SettingsStore.set() enforces the invariant atomically
# ---------------------------------------------------------------------------

class TestSettingsStoreSetEnforcesDuplicateDevice:
    def _make_store(self, tmp_path, raw):
        import json
        import webui.browser.api_settings  # noqa: F401
        import webui.browser.api_service  # noqa: F401
        from autostream_settings import SettingsStore
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps(raw))
        return SettingsStore(str(p), _save_interval_seconds=60.0, _writer=lambda path, data: None)

    def test_set_rejects_duplicate_device_assignment(self, tmp_path):
        store = self._make_store(tmp_path, {
            "audio1": {"capture_device": "hw:0,0"},
            "audio2": {"capture_device": "hw:1,0"},
        })
        try:
            with pytest.raises(CrossFieldValidationError):
                store.set("audio2.capture_device", "hw:0,0")
            # Rejected write must not have been committed.
            assert store.raw_snapshot()["audio2"]["capture_device"] == "hw:1,0"
        finally:
            store.close(save=False)

    def test_set_allows_distinct_device_assignment(self, tmp_path):
        store = self._make_store(tmp_path, {
            "audio1": {"capture_device": "hw:0,0"},
            "audio2": {"capture_device": "hw:1,0"},
        })
        try:
            store.set("audio2.capture_device", "hw:2,0")
            assert store.raw_snapshot()["audio2"]["capture_device"] == "hw:2,0"
        finally:
            store.close(save=False)
