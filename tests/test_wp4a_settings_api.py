"""tests/test_wp4a_settings_api.py

WP4A acceptance tests: live audio and playback-default settings via /api/settings.

Tests cover:
  - Validator functions (_validate_gain_db, _validate_volume_percent,
    _validate_silence_seconds, _validate_output_name)
  - Store persistence for all WP4A fields
  - Live-effect calls with _live_* functions
  - Live-failure path (live_fn returns False / raises)
  - Legacy /api/input_gain thin adapter (store write + live apply)
  - Legacy /api/input_eq thin adapter (atomic 3-band store write + live apply)
"""
from __future__ import annotations

import io
import json
import sys
import os
import tempfile
from typing import Any
from unittest.mock import MagicMock, patch, call

import pytest

# ── path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from autostream_settings import SettingsStore
from autostream_webui_api import (
    _SETTINGS_FIELDS,
    _validate_gain_db,
    _validate_output_name,
    _validate_silence_seconds,
    _validate_volume_percent,
    send_settings_post_json,
)
from autostream_webui_post_handlers import (
    handle_live_input_eq_update,
    handle_live_input_gain_update,
)


# ── helpers ────────────────────────────────────────────────────────────────────

def _make_state(tmp_path: str, with_store: bool = True):
    config_path = os.path.join(tmp_path, "config.json")
    with open(config_path, "w") as f:
        json.dump({}, f)
    state = MagicMock()
    state.config_path = config_path
    if with_store:
        store = SettingsStore(
            config_path,
            _save_interval_seconds=9999,
            _writer=MagicMock(),
        )
        state.settings = store
        return state, store
    state.settings = MagicMock()  # not a SettingsStore
    return state, None


def _handler(responses: list):
    """Return a fake HTTP handler that records send_json calls."""
    handler = MagicMock()
    handler.wfile = MagicMock()
    handler.wfile.write = MagicMock()

    _sent = {}

    def _send_response(code):
        _sent["code"] = code

    def _wfile_write(data):
        _sent["body"] = json.loads(data)

    handler.send_response.side_effect = _send_response
    handler.wfile.write.side_effect = _wfile_write
    responses.append(_sent)
    return handler


def _post(state, field: str, value: Any):
    """Call send_settings_post_json and return the response body dict."""
    responses: list = []
    h = _handler(responses)
    send_settings_post_json(h, state, {"field": field, "value": value})
    return responses[0].get("body", {})


# ── Validator: _validate_gain_db ──────────────────────────────────────────────

class TestValidateGainDb:
    def test_zero(self):
        assert _validate_gain_db(0) == 0.0

    def test_int_in_range(self):
        assert _validate_gain_db(5) == 5.0

    def test_float_in_range(self):
        assert _validate_gain_db(-3.5) == -3.5

    def test_boundary_minus_ten(self):
        assert _validate_gain_db(-10) == -10.0

    def test_boundary_plus_ten(self):
        assert _validate_gain_db(10) == 10.0

    def test_float_above_range_raises(self):
        with pytest.raises(ValueError):
            _validate_gain_db(10.01)

    def test_float_below_range_raises(self):
        with pytest.raises(ValueError):
            _validate_gain_db(-10.5)

    def test_bool_raises(self):
        with pytest.raises(ValueError):
            _validate_gain_db(True)

    def test_string_raises(self):
        with pytest.raises(ValueError):
            _validate_gain_db("5")

    def test_none_raises(self):
        with pytest.raises(ValueError):
            _validate_gain_db(None)

    def test_nan_raises(self):
        import math
        with pytest.raises(ValueError):
            _validate_gain_db(math.nan)

    def test_inf_raises(self):
        import math
        with pytest.raises(ValueError):
            _validate_gain_db(math.inf)


# ── Validator: _validate_volume_percent ───────────────────────────────────────

class TestValidateVolumePercent:
    def test_zero(self):
        assert _validate_volume_percent(0) == 0

    def test_hundred(self):
        assert _validate_volume_percent(100) == 100

    def test_midrange(self):
        assert _validate_volume_percent(50) == 50

    def test_truncates_float(self):
        assert _validate_volume_percent(33.9) == 33

    def test_negative_raises(self):
        with pytest.raises(ValueError):
            _validate_volume_percent(-1)

    def test_over_hundred_raises(self):
        with pytest.raises(ValueError):
            _validate_volume_percent(101)

    def test_bool_raises(self):
        with pytest.raises(ValueError):
            _validate_volume_percent(True)

    def test_string_raises(self):
        with pytest.raises(ValueError):
            _validate_volume_percent("50")


# ── Validator: _validate_silence_seconds ──────────────────────────────────────

class TestValidateSilenceSeconds:
    def test_minimum(self):
        assert _validate_silence_seconds(10) == 10

    def test_maximum(self):
        assert _validate_silence_seconds(300) == 300

    def test_midrange(self):
        assert _validate_silence_seconds(60) == 60

    def test_truncates_float(self):
        assert _validate_silence_seconds(30.9) == 30

    def test_below_minimum_raises(self):
        with pytest.raises(ValueError):
            _validate_silence_seconds(4)

    def test_above_maximum_raises(self):
        with pytest.raises(ValueError):
            _validate_silence_seconds(301)

    def test_bool_raises(self):
        with pytest.raises(ValueError):
            _validate_silence_seconds(True)

    def test_string_raises(self):
        with pytest.raises(ValueError):
            _validate_silence_seconds("30")


# ── Validator: _validate_output_name ─────────────────────────────────────────

class TestValidateOutputName:
    def test_valid_name(self):
        assert _validate_output_name("Living Room") == "Living Room"

    def test_strips_whitespace(self):
        assert _validate_output_name("  Deck  ") == "Deck"

    def test_non_string_raises(self):
        with pytest.raises(ValueError):
            _validate_output_name(123)

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            _validate_output_name("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError):
            _validate_output_name("   ")


# ── _SETTINGS_FIELDS presence ─────────────────────────────────────────────────

class TestSettingsFieldsWp4aPresent:
    def test_gain_fields(self):
        assert "audio1.gain_db" in _SETTINGS_FIELDS
        assert "audio2.gain_db" in _SETTINGS_FIELDS

    def test_eq_fields(self):
        for f in ("audio1.eq_40hz_db", "audio1.eq_100hz_db", "audio1.eq_8khz_db",
                  "audio2.eq_40hz_db", "audio2.eq_100hz_db", "audio2.eq_8khz_db"):
            assert f in _SETTINGS_FIELDS

    def test_owntone_fields(self):
        assert "owntone.output_name" in _SETTINGS_FIELDS
        assert "owntone.volume_percent" in _SETTINGS_FIELDS

    def test_silence_field(self):
        assert "general.silence_seconds" in _SETTINGS_FIELDS

    def test_all_wp4a_entries_are_4_tuples(self):
        wp4a_fields = [
            "audio1.gain_db", "audio2.gain_db",
            "audio1.eq_40hz_db", "audio1.eq_100hz_db", "audio1.eq_8khz_db",
            "audio2.eq_40hz_db", "audio2.eq_100hz_db", "audio2.eq_8khz_db",
            "owntone.output_name", "owntone.volume_percent",
            "general.silence_seconds",
        ]
        for f in wp4a_fields:
            entry = _SETTINGS_FIELDS[f]
            assert len(entry) == 4, f"{f} entry should be a 4-tuple"
            assert entry[3] is not None, f"{f} should have a live_fn"

    def test_wp3_entries_have_none_live_fn(self):
        wp3_fields = [
            "webui.dark_mode", "webui.show_master_volume",
            "webui.show_input_detail", "webui.show_hostname_on_home",
            "webui.control_other_appliances",
            "webui.output_usage_poll_interval_seconds", "updates.update_channel",
        ]
        for f in wp3_fields:
            entry = _SETTINGS_FIELDS[f]
            assert len(entry) == 4, f"{f} entry should be a 4-tuple"
            assert entry[3] is None, f"{f} should have no live_fn"


# ── Store persistence ─────────────────────────────────────────────────────────

class TestWp4aStorePersistence:
    def test_gain_written_to_store(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api.set_live_input_gain", return_value=True):
            resp = _post(state, "audio1.gain_db", 3.5)
        assert resp["ok"] is True
        assert store.snapshot().audio1.gain_db == 3.5

    def test_eq_40hz_written_to_store(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api.set_live_input_eq", return_value=True):
            resp = _post(state, "audio1.eq_40hz_db", -2.0)
        assert resp["ok"] is True
        assert store.snapshot().audio1.eq_40hz_db == -2.0

    def test_eq_100hz_written_to_store(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api.set_live_input_eq", return_value=True):
            resp = _post(state, "audio2.eq_100hz_db", 1.5)
        assert resp["ok"] is True
        assert store.snapshot().audio2.eq_100hz_db == 1.5

    def test_owntone_volume_written_to_store(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api.update_live_owntone_runtime", return_value=True):
            resp = _post(state, "owntone.volume_percent", 42)
        assert resp["ok"] is True
        assert store.snapshot().owntone.volume_percent == 42

    def test_owntone_output_name_written_to_store(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api.update_live_owntone_runtime", return_value=True):
            resp = _post(state, "owntone.output_name", "Deck Speakers")
        assert resp["ok"] is True
        assert store.snapshot().owntone.output_name == "Deck Speakers"

    def test_silence_seconds_written_to_store(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api.update_live_silence_seconds", return_value=True):
            resp = _post(state, "general.silence_seconds", 60)
        assert resp["ok"] is True
        assert store.snapshot().general.silence_seconds == 60


# ── Live effects ──────────────────────────────────────────────────────────────

class TestWp4aLiveEffects:
    def test_gain1_calls_set_live_input_gain(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_api.set_live_input_gain", return_value=True) as m:
            resp = _post(state, "audio1.gain_db", 2.0)
        m.assert_called_once_with(1, 2.0)
        assert resp["live"] is True

    def test_gain2_calls_set_live_input_gain(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_api.set_live_input_gain", return_value=True) as m:
            resp = _post(state, "audio2.gain_db", -1.0)
        m.assert_called_once_with(2, -1.0)
        assert resp["live"] is True

    def test_eq1_calls_set_live_input_eq_with_all_bands(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        # Pre-set other bands in the store
        def _setup(raw):
            raw.setdefault("audio1", {})["eq_100hz_db"] = 1.5
            raw.setdefault("audio1", {})["eq_8khz_db"] = -0.5
        store.update(_setup)
        with patch("autostream_webui_api.set_live_input_eq", return_value=True) as m:
            resp = _post(state, "audio1.eq_40hz_db", 3.0)
        # Should call with all 3 bands from the post-mutation snapshot
        m.assert_called_once_with(1, eq_40hz_db=3.0, eq_100hz_db=1.5, eq_8khz_db=-0.5)
        assert resp["live"] is True

    def test_eq2_calls_set_live_input_eq(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        def _setup(raw):
            raw.setdefault("audio2", {})["eq_40hz_db"] = 0.0
            raw.setdefault("audio2", {})["eq_8khz_db"] = 2.0
        store.update(_setup)
        with patch("autostream_webui_api.set_live_input_eq", return_value=True) as m:
            resp = _post(state, "audio2.eq_100hz_db", -1.0)
        m.assert_called_once_with(2, eq_40hz_db=0.0, eq_100hz_db=-1.0, eq_8khz_db=2.0)
        assert resp["live"] is True

    def test_owntone_name_calls_update_live_runtime(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        def _setup(raw):
            raw.setdefault("owntone", {})["volume_percent"] = 30
        store.update(_setup)
        with patch("autostream_webui_api.update_live_owntone_runtime", return_value=True) as m:
            resp = _post(state, "owntone.output_name", "Kitchen")
        args = m.call_args
        assert args.kwargs.get("output_name") == "Kitchen" or args[1].get("output_name") == "Kitchen"
        assert resp["live"] is True

    def test_owntone_volume_calls_update_live_runtime(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        def _setup(raw):
            raw.setdefault("owntone", {})["output_name"] = "Main"
        store.update(_setup)
        with patch("autostream_webui_api.update_live_owntone_runtime", return_value=True) as m:
            resp = _post(state, "owntone.volume_percent", 75)
        args = m.call_args
        assert args.kwargs.get("volume_percent") == 75 or args[1].get("volume_percent") == 75
        assert resp["live"] is True

    def test_silence_calls_update_live_silence_seconds(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_api.update_live_silence_seconds", return_value=True) as m:
            resp = _post(state, "general.silence_seconds", 45)
        m.assert_called_once_with(45)
        assert resp["live"] is True


# ── Live failure ──────────────────────────────────────────────────────────────

class TestWp4aLiveFailure:
    def test_live_returns_false_sets_live_false(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_api.set_live_input_gain", return_value=False):
            resp = _post(state, "audio1.gain_db", 1.0)
        assert resp["ok"] is True          # store write succeeded
        assert resp["live"] is False
        assert "live_error" in resp

    def test_live_raises_exception_sets_live_false(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_api.set_live_input_gain", side_effect=RuntimeError("monitor down")):
            resp = _post(state, "audio1.gain_db", 1.0)
        assert resp["ok"] is True
        assert resp["live"] is False
        assert "live_error" in resp

    def test_store_still_persists_when_live_fails(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api.set_live_input_gain", return_value=False):
            _post(state, "audio1.gain_db", 4.0)
        assert store.snapshot().audio1.gain_db == 4.0


# ── Validation rejection ──────────────────────────────────────────────────────

class TestWp4aValidationRejection:
    def test_gain_out_of_range_rejected(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        resp = _post(state, "audio1.gain_db", 15.0)
        assert resp["ok"] is False
        assert "field" in resp

    def test_volume_negative_rejected(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        resp = _post(state, "owntone.volume_percent", -5)
        assert resp["ok"] is False

    def test_silence_too_small_rejected(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        resp = _post(state, "general.silence_seconds", 4)
        assert resp["ok"] is False

    def test_output_name_empty_rejected(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        resp = _post(state, "owntone.output_name", "   ")
        assert resp["ok"] is False

    def test_gain_bool_rejected(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        resp = _post(state, "audio1.gain_db", True)
        assert resp["ok"] is False


# ── Legacy /api/input_gain thin adapter ──────────────────────────────────────

class TestLegacyGainAdapter:
    def _call(self, state, body: dict):
        responses: list = []
        h = _handler(responses)
        handle_live_input_gain_update(h, state, json.dumps(body))
        return responses[0].get("body", {})

    def test_valid_gain_persists_to_store(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api.set_live_input_gain", return_value=True):
            resp = self._call(state, {"input": 1, "gain_db": 2.5})
        assert resp["ok"] is True
        assert store.snapshot().audio1.gain_db == 2.5

    def test_valid_gain_input2(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api.set_live_input_gain", return_value=True):
            resp = self._call(state, {"input": 2, "gain_db": -1.0})
        assert resp["ok"] is True
        assert store.snapshot().audio2.gain_db == -1.0

    def test_invalid_input_index(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        resp = self._call(state, {"input": 3, "gain_db": 0.0})
        assert resp["ok"] is False

    def test_invalid_json_body(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        responses: list = []
        h = _handler(responses)
        handle_live_input_gain_update(h, state, "not json")
        assert responses[0]["body"]["ok"] is False

    def test_bool_index_rejected(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        resp = self._call(state, {"input": True, "gain_db": 0.0})
        assert resp["ok"] is False

    def test_live_gain_called(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_api.set_live_input_gain", return_value=True) as m:
            self._call(state, {"input": 1, "gain_db": 3.0})
        m.assert_called_once_with(1, 3.0)


# ── Legacy /api/input_eq thin adapter ────────────────────────────────────────

class TestLegacyEqAdapter:
    def _call(self, state, body: dict):
        responses: list = []
        h = _handler(responses)
        handle_live_input_eq_update(h, state, json.dumps(body))
        return responses[0].get("body", {})

    def test_valid_eq_persists_all_bands_to_store(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_post_handlers.set_live_input_eq", return_value=True):
            resp = self._call(state, {
                "input": 1,
                "eq_40hz_db": 1.0, "eq_100hz_db": -2.0, "eq_8khz_db": 0.5,
            })
        assert resp["ok"] is True
        snap = store.snapshot()
        assert snap.audio1.eq_40hz_db == 1.0
        assert snap.audio1.eq_100hz_db == -2.0
        assert snap.audio1.eq_8khz_db == 0.5

    def test_valid_eq_input2(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_post_handlers.set_live_input_eq", return_value=True):
            resp = self._call(state, {
                "input": 2,
                "eq_40hz_db": -3.0, "eq_100hz_db": 0.0, "eq_8khz_db": 2.0,
            })
        assert resp["ok"] is True
        snap = store.snapshot()
        assert snap.audio2.eq_40hz_db == -3.0

    def test_live_eq_called(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_post_handlers.set_live_input_eq", return_value=True) as m:
            self._call(state, {
                "input": 1,
                "eq_40hz_db": 1.0, "eq_100hz_db": 2.0, "eq_8khz_db": 3.0,
            })
        m.assert_called_once_with(
            input_index=1,
            eq_40hz_db=1.0, eq_100hz_db=2.0, eq_8khz_db=3.0,
        )

    def test_live_eq_failure_returns_error(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_post_handlers.set_live_input_eq", return_value=False):
            resp = self._call(state, {
                "input": 1,
                "eq_40hz_db": 0.0, "eq_100hz_db": 0.0, "eq_8khz_db": 0.0,
            })
        assert resp["ok"] is False

    def test_invalid_input_index(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        resp = self._call(state, {
            "input": 5, "eq_40hz_db": 0.0, "eq_100hz_db": 0.0, "eq_8khz_db": 0.0,
        })
        assert resp["ok"] is False

    def test_out_of_range_eq_value_rejected(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        resp = self._call(state, {
            "input": 1, "eq_40hz_db": 20.0, "eq_100hz_db": 0.0, "eq_8khz_db": 0.0,
        })
        assert resp["ok"] is False

    def test_bool_band_value_rejected(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        resp = self._call(state, {
            "input": 1, "eq_40hz_db": True, "eq_100hz_db": 0.0, "eq_8khz_db": 0.0,
        })
        assert resp["ok"] is False

    def test_eq_atomic_write_three_bands(self, tmp_path):
        """All 3 bands in one store update (atomic)."""
        state, store = _make_state(str(tmp_path))
        update_calls = []
        original_update = store.update

        def _spy(mutator):
            raw = store.raw_snapshot()
            mutator(raw)
            update_calls.append(raw)
            return original_update(mutator)

        store.update = _spy
        with patch("autostream_webui_post_handlers.set_live_input_eq", return_value=True):
            self._call(state, {
                "input": 1,
                "eq_40hz_db": 1.0, "eq_100hz_db": 2.0, "eq_8khz_db": 3.0,
            })
        # Should be exactly one store.update call containing all 3 bands
        assert len(update_calls) == 1
        a1 = update_calls[0].get("audio1", {})
        assert a1.get("eq_40hz_db") == 1.0
        assert a1.get("eq_100hz_db") == 2.0
        assert a1.get("eq_8khz_db") == 3.0
