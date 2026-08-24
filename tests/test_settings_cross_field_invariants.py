"""Tests for cross-field settings invariants folded into schema-declared
``FieldSpec.cross_validate`` callables, used by BOTH ``POST /api/settings``
and ``POST /setup``.

Covers:
  1. The two cross_validate callables in isolation
    (autostream_settings_schema.py).
  2. SettingsStore.set()/_set_normalized() enforcing the duplicate-device
     invariant atomically (already covered indirectly by
     test_wp3/4_settings_api.py; this file adds a direct unit test).
  3. The confirmed behaviour fix: POST /setup (handle_setup_post) now
     rejects a duplicate capture-device assignment exactly as
     POST /api/settings always has. Previously this was a silent gap --
     the setup form accepted the same device on both inputs with no
     rejection.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import urlencode

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
        import autostream_webui_api  # noqa: F401 -- registers SETTINGS_SCHEMA rows
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


# ---------------------------------------------------------------------------
# 3. handle_setup_post (POST /setup) now enforces the same invariant --
#    the confirmed behaviour fix.
# ---------------------------------------------------------------------------

def _minimal_config():
    return {
        "audio1": {"capture_device": "hw:0,0", "silence_threshold": -50,
                   "turntable": False, "gain_db": 0.0,
                   "eq_40hz_db": 0.0, "eq_100hz_db": 0.0, "eq_8khz_db": 0.0},
        "audio2": {"enabled": False, "capture_device": "hw:1,0", "silence_threshold": -50,
                   "turntable": False, "gain_db": 0.0,
                   "eq_40hz_db": 0.0, "eq_100hz_db": 0.0, "eq_8khz_db": 0.0},
        "owntone": {"base_url": "http://localhost:3689",
                    "output_name": "Default", "volume_percent": 50},
        "general": {"silence_seconds": 10},
        "updates": {"auto_update": False},
    }


def _call_setup_post(form_data: dict):
    """Call handle_setup_post, returning saved configs and the flash calls
    made to send_setup_page (mirrors test_control_other_appliances.py's
    _call_setup_post_control helper)."""
    from autostream_webui_post_handlers import handle_setup_post

    body = urlencode(form_data)
    cfg = _minimal_config()
    saved_cfgs = []
    setup_page_calls = []

    def fake_save(path, data):
        saved_cfgs.append(dict(data))

    def fake_send_setup_page(handler, state, auth, flash_msg=None, flash_type=None):
        setup_page_calls.append({"flash_msg": flash_msg, "flash_type": flash_type})

    with patch("autostream_webui_post_handlers.load_config", return_value=cfg), \
         patch("autostream_webui_post_handlers.parse_config") as mock_parse, \
         patch("autostream_webui_post_handlers.save_config", side_effect=fake_save), \
         patch("autostream_webui_post_handlers.mark_configured"), \
         patch("autostream_webui_post_handlers.get_system_hostname", return_value="host"), \
         patch("autostream_webui_post_handlers.set_system_hostname") as mock_set_hostname, \
         patch("autostream_webui_post_handlers.run_admin_cmd",
               return_value=MagicMock(returncode=0, stderr="")), \
         patch("autostream_webui_post_handlers.update_live_owntone_runtime"), \
         patch("autostream_webui_post_handlers.update_playback_input_config"), \
         patch("autostream_webui_post_handlers.send_setup_page", side_effect=fake_send_setup_page), \
         patch("autostream_webui_post_handlers._set_flash_cookie"), \
         patch("autostream_webui_post_handlers.build_top_banner_html", return_value=("", "")), \
         patch("autostream_webui_post_handlers.request_config_reload"):
        p = mock_parse.return_value
        p.audio1.capture_device = "hw:0,0"
        p.audio1.silence_threshold_dbfs = -50.0
        for attr in ("gain_db", "eq_40hz_db", "eq_100hz_db", "eq_8khz_db",
                     "stylus_life_hours", "belt_life_hours", "belt_life_years",
                     "bearing_life_hours", "bearing_life_years"):
            setattr(p.audio1, attr, 0.0)
        p.audio2.capture_device = "hw:1,0"
        p.audio2.silence_threshold_dbfs = -50.0
        for attr in ("gain_db", "eq_40hz_db", "eq_100hz_db", "eq_8khz_db",
                     "stylus_life_hours", "belt_life_hours", "belt_life_years",
                     "bearing_life_hours", "bearing_life_years"):
            setattr(p.audio2, attr, 0.0)
        p.audio2_enabled = False
        p.owntone.output_name = "Default"
        p.owntone.volume_percent = 50
        p.owntone.base_url = "http://localhost:3689"
        p.owntone.output_offsets_ms = {}
        p.owntone.output_airplay_modes = {}
        p.general.silence_seconds = 10
        p.general.log_file = "/var/log/autostream.log"
        p.general.fifo_path = "/run/autostream/audio.fifo"
        p.updates.auto_update = False
        p.webui.advertise_appliance = True
        handle_setup_post(MagicMock(), MagicMock(), MagicMock(), body)

    return {
        "saved": saved_cfgs,
        "setup_page_calls": setup_page_calls,
        "set_hostname": mock_set_hostname,
    }


class TestSetupPostRejectsDuplicateDevice:
    def test_same_device_on_both_inputs_is_rejected(self):
        """Confirmed behaviour fix: previously, the
        setup form silently accepted assigning the same capture device to
        both inputs; POST /api/settings already rejected it. Both paths now
        share the same schema-declared invariant."""
        form = {
            "audio_capture_device": "hw:0,0",
            "audio2_enabled": "1",
            "audio2_capture_device": "hw:0,0",  # duplicate of input 1
            "silence_seconds": "10",
            "owntone_output_name": "Speaker",
            "owntone_volume_percent": "50",
        }
        result = _call_setup_post(form)
        assert not result["saved"], "save_config must NOT be called when devices collide"
        assert result["setup_page_calls"], "an error page must be rendered"
        call = result["setup_page_calls"][0]
        assert call["flash_type"] == "error"
        assert "already assigned to the other input" in call["flash_msg"]

    def test_rejection_happens_before_the_hostname_is_written(self):
        """The rejection must land before set_system_hostname(), which writes
        to the live system and is not rolled back by the error page."""
        form = {
            "system_hostname": "brand-new-name",
            "audio_capture_device": "hw:0,0",
            "audio2_enabled": "1",
            "audio2_capture_device": "hw:0,0",  # duplicate of input 1
            "silence_seconds": "10",
            "owntone_output_name": "Speaker",
            "owntone_volume_percent": "50",
        }
        result = _call_setup_post(form)
        assert not result["saved"]
        result["set_hostname"].assert_not_called()

    def test_distinct_devices_still_saves_normally(self):
        """Control case: distinct devices are unaffected by the new check."""
        form = {
            "audio_capture_device": "hw:0,0",
            "audio2_enabled": "1",
            "audio2_capture_device": "hw:1,0",
            "silence_seconds": "10",
            "owntone_output_name": "Speaker",
            "owntone_volume_percent": "50",
        }
        result = _call_setup_post(form)
        assert result["saved"], "save_config must be called for non-colliding devices"
        saved = result["saved"][0]
        assert saved["audio1"]["capture_device"] == "hw:0,0"
        assert saved["audio2"]["capture_device"] == "hw:1,0"
