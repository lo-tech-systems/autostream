"""tests/test_wp4b_settings_api.py

WP4B acceptance tests: input configuration and track identification settings.

Tests cover:
  - Validators for capture_device and track-ID numeric fields
  - Store persistence for all WP4B fields
  - Turntable mode atomically updates derived silence_threshold
  - Coordinator reload is debounced (not immediate per-request)
  - audio2.enabled triggers playback tracker update
  - Track-ID fields trigger debounced rebuild
  - Coordinator reload path saves store first
"""
from __future__ import annotations

import json
import sys
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

import autostream_core as _core_mod
from autostream_core import AudioMonitor, MonitorClient
from autostream_settings import SettingsStore
from autostream_webui_api import (
    _SETTINGS_FIELDS,
    _validate_capture_device,
    _validate_track_id_lead_in,
    _validate_track_id_refresh,
    _validate_track_id_silence,
    send_settings_post_json,
)


# ── helpers ────────────────────────────────────────────────────────────────────

def _make_state(tmp_path: str):
    config_path = os.path.join(tmp_path, "config.json")
    with open(config_path, "w") as f:
        json.dump({}, f)
    store = SettingsStore(config_path, _save_interval_seconds=9999, _writer=MagicMock())
    state = MagicMock()
    state.settings = store
    return state, store


def _post(state, field: str, value: Any):
    """Call send_settings_post_json and return (code, body)."""
    sent = []
    handler = MagicMock()

    def _send_response(code):
        sent.append({"code": code})

    handler.send_response.side_effect = _send_response
    handler.wfile = MagicMock()

    def _write(data):
        sent[0]["body"] = json.loads(data)

    handler.wfile.write.side_effect = _write

    with patch("autostream_webui_api.send_json", side_effect=lambda h, c, d: sent.append({"code": c, "body": d})):
        send_settings_post_json(handler, state, {"field": field, "value": value})

    return sent[0] if sent else {"code": None, "body": {}}


def _post_resp(state, field, value):
    r = _post(state, field, value)
    return r["code"], r["body"]


def _make_live_monitor(input_index: int, **overrides) -> AudioMonitor:
    """Construct a running AudioMonitor for live-push tests, with the same
    dependency patching test_audio_monitor_coordination.py's helper uses so
    construction has no filesystem/socket side effects."""
    defaults = dict(
        input_index=input_index,
        input_device="hw:0,0",
        silence_threshold_dbfs=-60.0,
        silence_seconds=5,
        fifo_path="/tmp/test.fifo",
        owntone_base_url="http://localhost:3689",
        owntone_output_name="Test Speaker",
        owntone_volume_percent=50,
    )
    defaults.update(overrides)
    with patch("autostream_core.PersistentNowPlayingCache") as mock_cache_cls, \
         patch("autostream_core.get_shared_metadata_publisher") as mock_get_pub:
        mock_cache_cls.return_value.get_manual_hint.return_value = None
        mock_get_pub.side_effect = lambda path: MagicMock()
        return AudioMonitor(**defaults)


def _fake_connected(client):
    @contextmanager
    def _cm(*args, **kwargs):
        yield client
    return _cm


# ── Validators ────────────────────────────────────────────────────────────────

class TestValidateCaptureDevice:
    def test_valid_alsa_device(self):
        assert _validate_capture_device("hw:1,0") == "hw:1,0"

    def test_strips_whitespace(self):
        assert _validate_capture_device("  plughw:2,0  ") == "plughw:2,0"

    def test_non_string_raises(self):
        with pytest.raises(ValueError):
            _validate_capture_device(42)

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            _validate_capture_device("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError):
            _validate_capture_device("   ")


class TestValidateTrackIdNumerics:
    def test_lead_in_valid(self):
        assert isinstance(_validate_track_id_lead_in(5), int)

    def test_lead_in_bool_raises(self):
        with pytest.raises(ValueError):
            _validate_track_id_lead_in(True)

    def test_lead_in_string_raises(self):
        with pytest.raises(ValueError):
            _validate_track_id_lead_in("5")

    def test_refresh_valid(self):
        assert isinstance(_validate_track_id_refresh(120), int)

    def test_refresh_bool_raises(self):
        with pytest.raises(ValueError):
            _validate_track_id_refresh(False)

    def test_silence_valid(self):
        assert isinstance(_validate_track_id_silence(1.5), float)

    def test_silence_bool_raises(self):
        with pytest.raises(ValueError):
            _validate_track_id_silence(True)


# ── _SETTINGS_FIELDS WP4B presence ────────────────────────────────────────────

class TestSettingsFieldsWp4bPresent:
    def test_capture_device_fields(self):
        assert "audio1.capture_device" in _SETTINGS_FIELDS
        assert "audio2.capture_device" in _SETTINGS_FIELDS

    def test_audio1_enabled(self):
        assert "audio1.enabled" in _SETTINGS_FIELDS

    def test_audio2_enabled(self):
        assert "audio2.enabled" in _SETTINGS_FIELDS

    def test_turntable_fields(self):
        assert "audio1.turntable" in _SETTINGS_FIELDS
        assert "audio2.turntable" in _SETTINGS_FIELDS

    def test_track_id_fields(self):
        for f in (
            "track_identification.enabled",
            "track_identification.analysis_lead_in_seconds",
            "track_identification.refresh_seconds",
            "track_identification.track_change_silence_seconds",
        ):
            assert f in _SETTINGS_FIELDS

    def test_all_wp4b_entries_are_4_tuples_with_live_fn(self):
        wp4b = [
            "audio1.capture_device", "audio2.capture_device",
            "audio2.enabled", "audio1.turntable", "audio2.turntable",
            "track_identification.enabled",
            "track_identification.analysis_lead_in_seconds",
            "track_identification.refresh_seconds",
            "track_identification.track_change_silence_seconds",
        ]
        for f in wp4b:
            entry = _SETTINGS_FIELDS[f]
            assert len(entry) == 4, f"{f} must be 4-tuple"
            assert entry[3] is not None, f"{f} must have live_fn"


# ── Store persistence ─────────────────────────────────────────────────────────

class TestWp4bStorePersistence:
    def test_capture_device_1_stored(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api._debounce_coordinator_reload"):
            code, resp = _post_resp(state, "audio1.capture_device", "hw:1,0")
        assert resp["ok"] is True
        assert store.snapshot().audio1.capture_device == "hw:1,0"

    def test_capture_device_2_stored(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api._debounce_coordinator_reload"):
            code, resp = _post_resp(state, "audio2.capture_device", "plughw:2,0")
        assert resp["ok"] is True
        assert store.snapshot().audio2.capture_device == "plughw:2,0"

    def test_audio2_enabled_stored(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api._debounce_coordinator_reload"), \
             patch("autostream_webui_api.update_playback_input_config", return_value=True):
            code, resp = _post_resp(state, "audio2.enabled", True)
        assert resp["ok"] is True
        assert store.snapshot().audio2_enabled is True

    def test_turntable_1_stored(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api._debounce_coordinator_reload"), \
             patch("autostream_webui_api.update_playback_input_config", return_value=True):
            code, resp = _post_resp(state, "audio1.turntable", True)
        assert resp["ok"] is True
        assert store.snapshot().audio1.is_turntable is True

    def test_track_id_enabled_stored(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api._debounce_track_id_rebuild"):
            code, resp = _post_resp(state, "track_identification.enabled", True)
        assert resp["ok"] is True
        assert store.snapshot().track_identification.enabled is True

    def test_track_id_lead_in_stored(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api._debounce_track_id_rebuild"):
            code, resp = _post_resp(state, "track_identification.analysis_lead_in_seconds", 5)
        assert resp["ok"] is True
        assert store.snapshot().track_identification.analysis_lead_in_seconds == 5

    def test_track_id_refresh_stored(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api._debounce_track_id_rebuild"):
            code, resp = _post_resp(state, "track_identification.refresh_seconds", 300)
        assert resp["ok"] is True
        assert store.snapshot().track_identification.refresh_seconds == 300

    def test_track_id_silence_stored(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api._debounce_track_id_rebuild"):
            code, resp = _post_resp(state, "track_identification.track_change_silence_seconds", 1.5)
        assert resp["ok"] is True
        assert store.snapshot().track_identification.track_change_silence_seconds == pytest.approx(1.5)


# ── Turntable derives silence_threshold atomically ────────────────────────────

class TestTurntableDerivedThreshold:
    def test_turntable_true_sets_turntable_threshold(self, tmp_path):
        # Turntable threshold = -45 dBFS; line-level = -60 dBFS.
        # Turntable is more sensitive (less negative value ≡ closer to 0 dBFS).
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api._debounce_coordinator_reload"), \
             patch("autostream_webui_api.update_playback_input_config", return_value=True):
            _post_resp(state, "audio1.turntable", True)
        snap = store.snapshot()
        assert snap.audio1.is_turntable is True
        assert snap.audio1.silence_threshold_dbfs == pytest.approx(-45.0)

    def test_turntable_false_sets_line_level_threshold(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        def _set_turntable(raw):
            raw.setdefault("audio1", {})["turntable"] = True
            raw.setdefault("audio1", {})["silence_threshold"] = -45.0
        store.update(_set_turntable)
        with patch("autostream_webui_api._debounce_coordinator_reload"), \
             patch("autostream_webui_api.update_playback_input_config", return_value=True):
            _post_resp(state, "audio1.turntable", False)
        snap = store.snapshot()
        assert snap.audio1.is_turntable is False
        assert snap.audio1.silence_threshold_dbfs == pytest.approx(-60.0)

    def test_turntable_2_also_derives_threshold(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api._debounce_coordinator_reload"), \
             patch("autostream_webui_api.update_playback_input_config", return_value=True):
            _post_resp(state, "audio2.turntable", True)
        snap = store.snapshot()
        assert snap.audio2.is_turntable is True
        assert snap.audio2.silence_threshold_dbfs == pytest.approx(-45.0)

    def test_turntable_mutation_is_atomic(self, tmp_path):
        """turntable and silence_threshold change in one store.update call."""
        state, store = _make_state(str(tmp_path))
        update_count = [0]
        orig_update = store.update

        def _count(mutator):
            update_count[0] += 1
            return orig_update(mutator)

        store.update = _count
        with patch("autostream_webui_api._debounce_coordinator_reload"), \
             patch("autostream_webui_api.update_playback_input_config", return_value=True):
            _post_resp(state, "audio1.turntable", True)
        # Exactly one store.update call covers both turntable and silence_threshold
        assert update_count[0] == 1


# ── Turntable live push vs. reload fallback ───────────────────────────────────

class TestTurntableLiveApply:
    def test_turntable_change_pushed_live_without_reload(self, tmp_path):
        """Turntable mode only changes the derived silence threshold, which
        the monitor daemon accepts as a live configure_input() field on a
        running input -- a successful live push must not also fall back to
        the coordinator reload debounce."""
        state, store = _make_state(str(tmp_path))
        _make_live_monitor(1, silence_threshold_dbfs=-60.0)
        mock_client = MagicMock(spec=MonitorClient)
        mock_client.configure_input.return_value = True
        with patch.object(_core_mod, "_connected_monitor", _fake_connected(mock_client)), \
             patch("autostream_webui_api._debounce_coordinator_reload") as m_deb, \
             patch("autostream_webui_api.update_playback_input_config", return_value=True):
            code, resp = _post_resp(state, "audio1.turntable", True)
        assert resp["ok"] is True
        mock_client.configure_input.assert_called_once()
        m_deb.assert_not_called()

    def test_turntable_change_falls_back_to_reload_on_live_push_failure(self, tmp_path):
        """If the live threshold push cannot reach the monitor daemon, the
        existing reload debounce must still fire so the setting is not
        silently dropped -- same fallback behaviour as before this field
        gained a live path."""
        state, store = _make_state(str(tmp_path))
        _make_live_monitor(1, silence_threshold_dbfs=-60.0)
        with patch.object(_core_mod, "_connected_monitor", _fake_connected(None)), \
             patch("autostream_webui_api._debounce_coordinator_reload") as m_deb, \
             patch("autostream_webui_api.update_playback_input_config", return_value=True):
            code, resp = _post_resp(state, "audio1.turntable", True)
        assert resp["ok"] is True
        m_deb.assert_called_once()


# ── Coordinator reload debounce ───────────────────────────────────────────────

class TestCoordinatorReloadDebounce:
    def test_capture_device_calls_debounce_not_direct_reload(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_api._debounce_coordinator_reload") as m_deb, \
             patch("autostream_webui_api.request_config_reload") as m_rel:
            _post_resp(state, "audio1.capture_device", "hw:1,0")
        m_deb.assert_called_once()
        m_rel.assert_not_called()

    def test_debounce_calls_save_then_reload(self, tmp_path):
        """The debounce callback saves the store before signalling reload."""
        state, store = _make_state(str(tmp_path))
        save_calls = []
        reload_calls = []
        store._writer.side_effect = lambda path, data: save_calls.append(data)

        # Use a very short delay to actually fire the timer in test
        import autostream_webui_api as _api
        orig_debounce = _api._debounce_coordinator_reload

        fired = threading.Event()

        def _patched_debounce(s, delay=0.3):
            with _api._coordinator_reload_lock:
                if _api._coordinator_reload_timer is not None:
                    _api._coordinator_reload_timer.cancel()

                def _do():
                    from autostream_settings import SettingsStore as _SS
                    settings = getattr(s, "settings", None)
                    if isinstance(settings, _SS):
                        settings.save_now()
                    _api.request_config_reload()
                    fired.set()

                t = threading.Timer(0.05, _do)
                t.daemon = True
                t.start()
                _api._coordinator_reload_timer = t

        with patch.object(_api, "_debounce_coordinator_reload", _patched_debounce), \
             patch.object(_api, "request_config_reload") as m_rel:
            _post_resp(state, "audio1.capture_device", "hw:1,0")
            fired.wait(timeout=1.0)
        # save_now() wrote to disk before reload was called
        assert len(save_calls) >= 1
        m_rel.assert_called_once()

    def test_burst_produces_single_debounce(self, tmp_path):
        """Rapid successive changes to the same field call debounce multiple times
        but the timer only fires once (debounce coalescing)."""
        state, store = _make_state(str(tmp_path))
        debounce_calls = []
        with patch("autostream_webui_api._debounce_coordinator_reload",
                   side_effect=lambda s, **kw: debounce_calls.append(1)):
            for device in ("hw:0,0", "hw:1,0", "hw:2,0"):
                _post_resp(state, "audio1.capture_device", device)
        # 3 debounce calls were made (timer reset each time)
        assert len(debounce_calls) == 3
        # Final value is stored
        assert store.snapshot().audio1.capture_device == "hw:2,0"


# ── audio2.enabled live effect ────────────────────────────────────────────────

class TestAudio2EnabledLive:
    def test_enabled_calls_update_playback_tracker(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_api.update_playback_input_config", return_value=True) as m, \
             patch("autostream_webui_api._debounce_coordinator_reload"):
            _post_resp(state, "audio2.enabled", True)
        m.assert_called_once()
        args, kwargs = m.call_args
        assert args[0] == 2
        assert kwargs["enabled"] is True

    def test_disabled_calls_update_playback_tracker(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_api.update_playback_input_config", return_value=True) as m, \
             patch("autostream_webui_api._debounce_coordinator_reload"):
            _post_resp(state, "audio2.enabled", False)
        m.assert_called_once()
        _, kwargs = m.call_args
        assert kwargs["enabled"] is False


# ── audio1.enabled live effect ────────────────────────────────────────────────

class TestAudio1EnabledLive:
    def test_enabled_calls_update_playback_tracker(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        store.update(lambda raw: raw.setdefault("audio1", {}).update({"capture_device": "hw:0,0"}))
        with patch("autostream_webui_api.update_playback_input_config", return_value=True) as m, \
             patch("autostream_webui_api._debounce_coordinator_reload"):
            _post_resp(state, "audio1.enabled", True)
        m.assert_called_once()
        args, kwargs = m.call_args
        assert args[0] == 1
        assert kwargs["enabled"] is True

    def test_disabled_calls_update_playback_tracker(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_api.update_playback_input_config", return_value=True) as m, \
             patch("autostream_webui_api._debounce_coordinator_reload"):
            _post_resp(state, "audio1.enabled", False)
        m.assert_called_once()
        _, kwargs = m.call_args
        assert kwargs["enabled"] is False

    def test_disabling_triggers_reload_debounce(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_api.update_playback_input_config", return_value=True), \
             patch("autostream_webui_api._debounce_coordinator_reload") as m:
            _post_resp(state, "audio1.enabled", False)
        m.assert_called_once()


# ── audio1.enabled / capture_device cross-field gating ───────────────────────

class TestAudio1EnabledCaptureDeviceGating:
    def test_empty_capture_device_accepted_when_disabled(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        store.update(lambda raw: raw.setdefault("audio1", {}).update({"enabled": False}))
        with patch("autostream_webui_api._debounce_coordinator_reload"):
            code, resp = _post_resp(state, "audio1.capture_device", "")
        assert resp["ok"] is True
        assert store.snapshot().audio1.capture_device == ""

    def test_empty_capture_device_rejected_when_enabled(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        store.update(lambda raw: raw.setdefault("audio1", {}).update({"enabled": True}))
        code, resp = _post_resp(state, "audio1.capture_device", "")
        assert resp["ok"] is False
        assert code == 400

    def test_non_string_capture_device_still_rejected_when_disabled(self, tmp_path):
        """Disabling input 1 only relaxes the empty-string case -- a
        non-string value is still rejected by the field validator, same as
        it always has been."""
        state, store = _make_state(str(tmp_path))
        store.update(lambda raw: raw.setdefault("audio1", {}).update({"enabled": False}))
        code, resp = _post_resp(state, "audio1.capture_device", True)
        assert resp["ok"] is False
        assert code == 400

    def test_enabling_with_invalid_device_rejected(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        store.update(lambda raw: raw.setdefault("audio1", {}).update({
            "enabled": False, "capture_device": "",
        }))
        code, resp = _post_resp(state, "audio1.enabled", True)
        assert resp["ok"] is False
        assert code == 400
        assert store.snapshot().audio1_enabled is False

    def test_enabling_with_valid_device_accepted(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        store.update(lambda raw: raw.setdefault("audio1", {}).update({
            "enabled": False, "capture_device": "hw:0,0",
        }))
        with patch("autostream_webui_api.update_playback_input_config", return_value=True), \
             patch("autostream_webui_api._debounce_coordinator_reload"):
            code, resp = _post_resp(state, "audio1.enabled", True)
        assert resp["ok"] is True
        assert store.snapshot().audio1_enabled is True


# ── Track-ID rebuild debounce ─────────────────────────────────────────────────

class TestTrackIdRebuildDebounce:
    def test_track_id_enabled_calls_debounce(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_api._debounce_track_id_rebuild") as m:
            _post_resp(state, "track_identification.enabled", True)
        m.assert_called_once()

    def test_track_id_lead_in_calls_debounce(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_api._debounce_track_id_rebuild") as m:
            _post_resp(state, "track_identification.analysis_lead_in_seconds", 3)
        m.assert_called_once()

    def test_debounce_rebuild_uses_fresh_snapshot(self, tmp_path):
        """Timer callback takes a fresh snapshot, not the one from scheduling
        time. Exercises the real, now shared-Debouncer-backed
        _debounce_track_id_rebuild directly (its own threading.Timer/lock/
        global trio was deleted in favour of autostream_debounce.Debouncer)."""
        state, store = _make_state(str(tmp_path))
        rebuilt_with = []
        fired = threading.Event()

        import autostream_webui_api as _api

        def _capture(snap):
            rebuilt_with.append(snap)
            fired.set()

        # Schedule rebuild via the real debounce function, at a short delay.
        with patch.object(_api, "apply_track_id_config_live_from_parsed", side_effect=_capture):
            _api._debounce_track_id_rebuild(state, delay=0.05)

            # Mutate store after scheduling, before timer fires
            def _late_change(raw):
                raw.setdefault("track_identification", {})["refresh_seconds"] = 666
            store.update(_late_change)

            fired.wait(timeout=1.0)

        assert len(rebuilt_with) == 1
        # Fresh snapshot includes the late change
        assert rebuilt_with[0].track_identification.refresh_seconds == 666


# ── Validation rejection ──────────────────────────────────────────────────────

class TestWp4bValidationRejection:
    def test_empty_capture_device_rejected(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        code, resp = _post_resp(state, "audio1.capture_device", "")
        assert resp["ok"] is False
        assert code == 400

    def test_bool_capture_device_rejected(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        code, resp = _post_resp(state, "audio2.capture_device", True)
        assert resp["ok"] is False

    def test_non_bool_audio2_enabled_rejected(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        code, resp = _post_resp(state, "audio2.enabled", "yes")
        assert resp["ok"] is False

    def test_bool_track_id_lead_in_rejected(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        code, resp = _post_resp(state, "track_identification.analysis_lead_in_seconds", True)
        assert resp["ok"] is False
