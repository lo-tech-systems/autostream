"""tests/test_repeat_api.py

Acceptance tests for the Python coordinator, config, and web API layer of
the "repeat" feature.

The C++ daemon side is mocked throughout -- these tests exercise the
Python contract against a MonitorClient/socket double, not a real daemon.

Tests cover:
  P1 - Settings five-file contract (repeat.enabled/repeat.codec)
  P2 - Live apply, not reload
  P3 - POST /api/repeat validation + auth (auth enforcement lives in
       tests/test_webui_auth_routing.py's protected-route manifest)
  P4 - /api/status repeat + session passthrough (present verbatim / omitted
       when absent; session always present)
  P5 - Unified playback-session tracker: the source_vector
       {input1, input2, replay} diff and its three events (session_started /
       session_ended / source_changed) driving idle-stop gating and
       replay-end/OwnTone-stop handling uniformly. Named acceptance tests
       map directly to observable symptoms (see class docstrings below).
  P6 - Resync re-push
  P7 - Reload teardown disarm-before-stop_input ordering
  P8 - Playback-hours accrual during replay
"""
from __future__ import annotations

import inspect
import json
import sys
import os
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ── path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from autostream_config import (
    RepeatConfig,
    parse_config,
    normalize_repeat_codec,
    normalize_repeat_target_minutes,
    REPEAT_CODEC_CHOICES,
    REPEAT_TARGET_MINUTES_DEFAULT,
    REPEAT_TARGET_MINUTES_MIN,
    REPEAT_TARGET_MINUTES_MAX,
)
from autostream_settings import SettingsStore
from autostream_webui_api import (
    _SETTINGS_FIELDS,
    _validate_repeat_codec,
    _validate_repeat_target_minutes,
    send_repeat_post_json,
    send_settings_get_json,
    send_settings_post_json,
    send_status_json,
)
import autostream_core as core
from autostream_core import (
    AudioMonitor,
    MonitorClient,
    _dispatch_session_event,
    _replay_origin_input,
    _resync_monitor_daemon,
    _session_nowplaying_end,
    _session_nowplaying_start,
    _SessionTracker,
    _set_repeat_status,
    _set_session_state,
    _start_session_owntone,
    get_repeat_status,
    get_session_state,
    set_live_repeat_armed,
    set_live_repeat_enabled,
)


# ── shared helpers ─────────────────────────────────────────────────────────────

def _make_state(tmp_path: str):
    config_path = os.path.join(tmp_path, "config.json")
    with open(config_path, "w") as f:
        json.dump({}, f)
    state = MagicMock()
    state.config_path = config_path
    store = SettingsStore(config_path, _save_interval_seconds=9999, _writer=MagicMock())
    state.settings = store
    return state, store


def _handler(responses: list):
    handler = MagicMock()
    handler.wfile = MagicMock()
    _sent = {}

    def _send_response(code):
        _sent["code"] = code

    def _wfile_write(data):
        _sent["body"] = json.loads(data)

    handler.send_response.side_effect = _send_response
    handler.wfile.write.side_effect = _wfile_write
    responses.append(_sent)
    return handler


def _post_settings(state, field: str, value: Any):
    responses: list = []
    h = _handler(responses)
    send_settings_post_json(h, state, {"field": field, "value": value})
    return responses[0].get("body", {}), responses[0].get("code")


def _make_monitor(**overrides) -> AudioMonitor:
    defaults = dict(
        input_index=1,
        input_device="hw:0,0",
        silence_threshold_dbfs=-50.0,
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
        # Fresh MagicMock per call: see test_audio_monitor_coordination.py's
        # _make_monitor for why this doesn't just use a shared return_value.
        mock_get_pub.side_effect = lambda path: MagicMock()
        mon = AudioMonitor(**defaults)
    return mon


# ── P1: Settings five-file contract ───────────────────────────────────────────

class TestP1ConfigDefaults:
    def test_parse_config_defaults_when_section_missing(self):
        cfg = parse_config({})
        assert cfg.repeat.enabled is False
        assert cfg.repeat.codec == "auto"

    def test_parse_config_reads_persisted_values(self):
        cfg = parse_config({"repeat": {"enabled": True, "codec": "mp2_192"}})
        assert cfg.repeat.enabled is True
        assert cfg.repeat.codec == "mp2_192"

    def test_parse_config_rejects_unknown_codec(self):
        cfg = parse_config({"repeat": {"codec": "flac_lossless"}})
        assert cfg.repeat.codec == "auto"

    @pytest.mark.parametrize("codec", list(REPEAT_CODEC_CHOICES))
    def test_normalize_repeat_codec_accepts_all_choices(self, codec):
        assert normalize_repeat_codec(codec) == codec

    def test_normalize_repeat_codec_defaults_on_garbage(self):
        assert normalize_repeat_codec("nonsense") == "auto"
        assert normalize_repeat_codec(None) == "auto"

    @pytest.mark.parametrize("codec", ("mp2_256", "mp2_320", "mp2_384"))
    def test_extended_mp2_tiers_are_valid_codec_choices(self, codec):
        """The extended MP2 tiers must be accepted by both the choices tuple
        and the normaliser."""
        assert codec in REPEAT_CODEC_CHOICES
        assert normalize_repeat_codec(codec) == codec


class TestP1TargetMinutes:
    """repeat.target_minutes -- config-level clamp [10, 600]; the browser-
    editable Settings-page field is narrower (33 or 80 only, see
    TestP1SettingsFieldsPresent / TestTargetMinutesValidator)."""

    def test_default_when_section_missing(self):
        cfg = parse_config({})
        assert cfg.repeat.target_minutes == REPEAT_TARGET_MINUTES_DEFAULT == 33

    def test_reads_persisted_value(self):
        cfg = parse_config({"repeat": {"target_minutes": 45}})
        assert cfg.repeat.target_minutes == 45

    def test_clamps_below_min(self):
        cfg = parse_config({"repeat": {"target_minutes": 1}})
        assert cfg.repeat.target_minutes == REPEAT_TARGET_MINUTES_MIN == 10

    def test_clamps_above_max(self):
        cfg = parse_config({"repeat": {"target_minutes": 100000}})
        assert cfg.repeat.target_minutes == REPEAT_TARGET_MINUTES_MAX == 600

    def test_defaults_on_garbage(self):
        assert normalize_repeat_target_minutes("not-a-number") == REPEAT_TARGET_MINUTES_DEFAULT
        assert normalize_repeat_target_minutes(None) == REPEAT_TARGET_MINUTES_DEFAULT

    def test_is_in_browser_editable_settings_fields(self):
        """The buffer-target dropdown (Vinyl 33 / CD 80) makes this field
        browser-editable, unlike before."""
        assert "repeat.target_minutes" in _SETTINGS_FIELDS


class TestTargetMinutesValidator:
    """Browser-side validator: only 33 or 80, unlike the wider config-file
    clamp exercised by TestP1TargetMinutes above."""

    @pytest.mark.parametrize("value", [33, 80, "33", "80", 33.0])
    def test_accepts_33_or_80(self, value):
        result = _validate_repeat_target_minutes(value)
        assert result in (33, 80)
        assert result == int(float(value))

    @pytest.mark.parametrize("value", [45, 0, -1, 600, "garbage", None, [], {}, True, False])
    def test_rejects_everything_else(self, value):
        with pytest.raises(ValueError):
            _validate_repeat_target_minutes(value)


class TestP1SettingsFieldsPresent:
    def test_enabled_and_codec_present(self):
        assert "repeat.enabled" in _SETTINGS_FIELDS
        assert "repeat.codec" in _SETTINGS_FIELDS
        assert "repeat.target_minutes" in _SETTINGS_FIELDS

    def test_entries_are_4_tuples_with_live_fn(self):
        for f in ("repeat.enabled", "repeat.codec", "repeat.target_minutes"):
            entry = _SETTINGS_FIELDS[f]
            assert len(entry) == 4
            assert entry[3] is not None, f"{f} must have a live_fn"

    def test_codec_validator_rejects_unknown(self):
        with pytest.raises(ValueError):
            _validate_repeat_codec("flac_lossless")

    def test_codec_validator_rejects_non_string(self):
        with pytest.raises(ValueError):
            _validate_repeat_codec(160)

    @pytest.mark.parametrize("codec", list(REPEAT_CODEC_CHOICES))
    def test_codec_validator_accepts_choices(self, codec):
        assert _validate_repeat_codec(codec) == codec


class TestP1GetApiSettings:
    def test_values_include_repeat_keys(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        responses: list = []
        h = _handler(responses)
        send_settings_get_json(h, state)
        body = responses[0]["body"]
        assert body["ok"] is True
        assert body["values"]["repeat.enabled"] is False
        assert body["values"]["repeat.codec"] == "auto"
        assert body["values"]["repeat.target_minutes"] == 33


class TestP1StoreRoundTrip:
    def test_enabled_round_trip(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api.set_live_repeat_enabled", return_value=True):
            resp, code = _post_settings(state, "repeat.enabled", True)
        assert resp["ok"] is True
        assert store.snapshot().repeat.enabled is True

    def test_codec_round_trip(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api.set_live_repeat_enabled", return_value=True):
            resp, code = _post_settings(state, "repeat.codec", "mp2_224")
        assert resp["ok"] is True
        assert store.snapshot().repeat.codec == "mp2_224"

    def test_codec_round_trip_rejects_bad_value(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        resp, code = _post_settings(state, "repeat.codec", "wav")
        assert resp["ok"] is False
        assert code == 400  # validation failure (API-ERROR-CONTRACT: non-intercepted native 4xx)
        assert store.snapshot().repeat.codec == "auto"

    def test_target_minutes_round_trip(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api.set_live_repeat_enabled", return_value=True):
            resp, code = _post_settings(state, "repeat.target_minutes", 80)
        assert resp["ok"] is True
        assert store.snapshot().repeat.target_minutes == 80

    def test_target_minutes_round_trip_rejects_bad_value(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        resp, code = _post_settings(state, "repeat.target_minutes", 45)
        assert resp["ok"] is False
        assert code == 400
        assert store.snapshot().repeat.target_minutes == 33


# ── P2: Live apply, not reload ────────────────────────────────────────────────

class TestP2LiveApplyNotReload:
    def test_enabled_calls_live_setter(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_api.set_live_repeat_enabled", return_value=True) as m:
            resp, _ = _post_settings(state, "repeat.enabled", True)
        m.assert_called_once_with(True, "auto", 33)
        assert resp["live"] is True

    def test_codec_calls_live_setter_with_current_enabled(self, tmp_path):
        """Enabled, and the daemon-reported codec differs from the newly
        saved value: this exercises the off/on pulse (see
        TestP2LiveCodecPulse for the full matrix)."""
        state, store = _make_state(str(tmp_path))
        store.update(lambda raw: raw.setdefault("repeat", {}).update({"enabled": True}))
        with patch("autostream_webui_api.get_repeat_status", return_value={"codec": "auto"}), \
             patch("autostream_webui_api.set_live_repeat_enabled", return_value=True) as m:
            resp, _ = _post_settings(state, "repeat.codec", "pcm")
        assert m.call_count == 2
        assert m.call_args_list[0].args == (False, "pcm", 33)
        assert m.call_args_list[1].args == (True, "pcm", 33)
        assert resp["live"] is True

    def test_enabled_does_not_debounce_coordinator_reload(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_api.set_live_repeat_enabled", return_value=True), \
             patch("autostream_webui_api._debounce_coordinator_reload") as m_deb, \
             patch("autostream_webui_api.request_config_reload") as m_rel:
            _post_settings(state, "repeat.enabled", True)
        m_deb.assert_not_called()
        m_rel.assert_not_called()

    def test_codec_does_not_debounce_coordinator_reload(self, tmp_path):
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_api.set_live_repeat_enabled", return_value=True), \
             patch("autostream_webui_api._debounce_coordinator_reload") as m_deb, \
             patch("autostream_webui_api.request_config_reload") as m_rel:
            _post_settings(state, "repeat.codec", "mp2_160")
        m_deb.assert_not_called()
        m_rel.assert_not_called()

    def test_live_failure_reports_live_error_but_still_persists(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        with patch("autostream_webui_api.set_live_repeat_enabled", return_value=False):
            resp, _ = _post_settings(state, "repeat.enabled", True)
        assert resp["ok"] is True
        assert resp["live"] is False
        assert "live_error" in resp
        assert store.snapshot().repeat.enabled is True


class TestP2LiveTargetMinutesPulse:
    """_live_repeat_target_minutes: the daemon-reported target_minutes
    (get_repeat_status()) is used as the "previous value" for the
    changed/unchanged comparison, because by the time this live_fn runs the
    settings store already holds the NEW value (send_settings_post_json
    commits the store before calling live_fn) -- comparing against the
    snapshot would always see "no change"."""

    def test_disabled_makes_no_daemon_calls(self, tmp_path):
        """Repeat currently off: the new target just persists; the enable
        path forwards it later, so nothing should be pushed now."""
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_api.get_repeat_status", return_value={"target_minutes": 80}), \
             patch("autostream_webui_api.set_live_repeat_enabled") as m:
            resp, _ = _post_settings(state, "repeat.target_minutes", 80)
        assert resp["ok"] is True
        assert resp["live"] is True
        m.assert_not_called()

    def test_unchanged_value_makes_no_daemon_calls(self, tmp_path):
        """Enabled, and the daemon already reports the same target the
        browser just saved: no pulse."""
        state, store = _make_state(str(tmp_path))
        store.update(lambda raw: raw.setdefault("repeat", {}).update({"enabled": True}))
        with patch("autostream_webui_api.get_repeat_status", return_value={"target_minutes": 80}), \
             patch("autostream_webui_api.set_live_repeat_enabled") as m:
            resp, _ = _post_settings(state, "repeat.target_minutes", 80)
        assert resp["ok"] is True
        assert resp["live"] is True
        m.assert_not_called()

    def test_changed_value_pulses_off_then_on_exactly_once_each(self, tmp_path):
        """Enabled, and the daemon-reported target differs from the newly
        saved value: exactly one off call followed by exactly one on call,
        both carrying the new target and the current codec."""
        state, store = _make_state(str(tmp_path))
        store.update(lambda raw: raw.setdefault("repeat", {}).update({"enabled": True, "codec": "mp2_224"}))
        with patch("autostream_webui_api.get_repeat_status", return_value={"target_minutes": 80}), \
             patch("autostream_webui_api.set_live_repeat_enabled", return_value=True) as m:
            resp, _ = _post_settings(state, "repeat.target_minutes", 33)
        assert resp["ok"] is True
        assert resp["live"] is True
        assert m.call_count == 2
        assert m.call_args_list[0].args == (False, "mp2_224", 33)
        assert m.call_args_list[1].args == (True, "mp2_224", 33)

    def test_pulse_failure_reports_live_error(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        store.update(lambda raw: raw.setdefault("repeat", {}).update({"enabled": True}))
        with patch("autostream_webui_api.get_repeat_status", return_value={"target_minutes": 80}), \
             patch("autostream_webui_api.set_live_repeat_enabled", side_effect=[True, False]):
            resp, _ = _post_settings(state, "repeat.target_minutes", 33)
        assert resp["ok"] is True
        assert resp["live"] is False
        assert "live_error" in resp

    def test_unknown_daemon_status_treated_as_changed(self, tmp_path):
        """No cached daemon status (old binary / never polled yet): the
        safer default is to pulse rather than silently skip the daemon
        push."""
        state, store = _make_state(str(tmp_path))
        store.update(lambda raw: raw.setdefault("repeat", {}).update({"enabled": True}))
        with patch("autostream_webui_api.get_repeat_status", return_value=None), \
             patch("autostream_webui_api.set_live_repeat_enabled", return_value=True) as m:
            resp, _ = _post_settings(state, "repeat.target_minutes", 33)
        assert resp["live"] is True
        assert m.call_count == 2


class TestP2LiveCodecPulse:
    """_live_repeat_codec: mirrors _live_repeat_target_minutes -- the
    daemon-reported codec (get_repeat_status()) is used as the "previous
    value" for the changed/unchanged comparison, because by the time this
    live_fn runs the settings store already holds the NEW value (comparing
    against the snapshot would always see "no change")."""

    def test_disabled_makes_no_daemon_calls(self, tmp_path):
        """Repeat currently off: the new codec just persists; the enable
        path forwards it later, so nothing should be pushed now."""
        state, _ = _make_state(str(tmp_path))
        with patch("autostream_webui_api.get_repeat_status", return_value={"codec": "mp2_192"}), \
             patch("autostream_webui_api.set_live_repeat_enabled") as m:
            resp, _ = _post_settings(state, "repeat.codec", "mp2_192")
        assert resp["ok"] is True
        assert resp["live"] is True
        m.assert_not_called()

    def test_unchanged_value_makes_no_daemon_calls(self, tmp_path):
        """Enabled, and the daemon already reports the same codec the
        browser just saved: no pulse."""
        state, store = _make_state(str(tmp_path))
        store.update(lambda raw: raw.setdefault("repeat", {}).update({"enabled": True}))
        with patch("autostream_webui_api.get_repeat_status", return_value={"codec": "mp2_192"}), \
             patch("autostream_webui_api.set_live_repeat_enabled") as m:
            resp, _ = _post_settings(state, "repeat.codec", "mp2_192")
        assert resp["ok"] is True
        assert resp["live"] is True
        m.assert_not_called()

    def test_changed_value_pulses_off_then_on_exactly_once_each(self, tmp_path):
        """Enabled, and the daemon-reported codec differs from the newly
        saved value: exactly one off call followed by exactly one on call,
        both carrying the new codec and the current target_minutes."""
        state, store = _make_state(str(tmp_path))
        store.update(lambda raw: raw.setdefault("repeat", {}).update({"enabled": True, "target_minutes": 80}))
        with patch("autostream_webui_api.get_repeat_status", return_value={"codec": "mp2_192"}), \
             patch("autostream_webui_api.set_live_repeat_enabled", return_value=True) as m:
            resp, _ = _post_settings(state, "repeat.codec", "pcm")
        assert resp["ok"] is True
        assert resp["live"] is True
        assert m.call_count == 2
        assert m.call_args_list[0].args == (False, "pcm", 80)
        assert m.call_args_list[1].args == (True, "pcm", 80)

    def test_pulse_failure_reports_live_error(self, tmp_path):
        state, store = _make_state(str(tmp_path))
        store.update(lambda raw: raw.setdefault("repeat", {}).update({"enabled": True}))
        with patch("autostream_webui_api.get_repeat_status", return_value={"codec": "mp2_192"}), \
             patch("autostream_webui_api.set_live_repeat_enabled", side_effect=[True, False]):
            resp, _ = _post_settings(state, "repeat.codec", "pcm")
        assert resp["ok"] is True
        assert resp["live"] is False
        assert "live_error" in resp

    def test_unknown_daemon_status_treated_as_changed(self, tmp_path):
        """No cached daemon status (old binary / never polled yet): the
        safer default is to pulse rather than silently skip the daemon
        push."""
        state, store = _make_state(str(tmp_path))
        store.update(lambda raw: raw.setdefault("repeat", {}).update({"enabled": True}))
        with patch("autostream_webui_api.get_repeat_status", return_value=None), \
             patch("autostream_webui_api.set_live_repeat_enabled", return_value=True) as m:
            resp, _ = _post_settings(state, "repeat.codec", "pcm")
        assert resp["live"] is True
        assert m.call_count == 2


# ── P3: /api/repeat endpoint ───────────────────────────────────────────────────
# Auth/PIN enforcement for this route is asserted in
# tests/test_webui_auth_routing.py (added to _PROTECTED there).

class TestP3RepeatEndpoint:
    def test_valid_armed_true_calls_live_setter(self):
        responses: list = []
        h = _handler(responses)
        with patch("autostream_webui_api.set_live_repeat_armed", return_value=True) as m:
            send_repeat_post_json(h, MagicMock(), json.dumps({"armed": True}))
        m.assert_called_once_with(True)
        body = responses[0]["body"]
        assert body == {"ok": True, "armed": True}
        assert responses[0]["code"] == 200

    def test_valid_armed_false_calls_live_setter(self):
        responses: list = []
        h = _handler(responses)
        with patch("autostream_webui_api.set_live_repeat_armed", return_value=True) as m:
            send_repeat_post_json(h, MagicMock(), json.dumps({"armed": False}))
        m.assert_called_once_with(False)
        assert responses[0]["body"]["ok"] is True

    def test_missing_armed_is_400(self):
        responses: list = []
        h = _handler(responses)
        send_repeat_post_json(h, MagicMock(), json.dumps({}))
        assert responses[0]["code"] == 400
        assert responses[0]["body"]["ok"] is False

    def test_non_bool_armed_is_400(self):
        responses: list = []
        h = _handler(responses)
        send_repeat_post_json(h, MagicMock(), json.dumps({"armed": "yes"}))
        assert responses[0]["code"] == 400

    def test_invalid_json_is_400(self):
        responses: list = []
        h = _handler(responses)
        send_repeat_post_json(h, MagicMock(), "{not json")
        assert responses[0]["code"] == 400

    def test_non_object_json_is_400(self):
        responses: list = []
        h = _handler(responses)
        send_repeat_post_json(h, MagicMock(), json.dumps([1, 2, 3]))
        assert responses[0]["code"] == 400

    def test_daemon_rejection_returns_ok_false_200(self):
        responses: list = []
        h = _handler(responses)
        with patch("autostream_webui_api.set_live_repeat_armed", return_value=False):
            send_repeat_post_json(h, MagicMock(), json.dumps({"armed": True}))
        assert responses[0]["code"] == 200
        assert responses[0]["body"]["ok"] is False


# ── P4: Status passthrough ─────────────────────────────────────────────────────

class TestP4StatusPassthrough:
    def test_repeat_block_present_when_cached(self):
        repeat_block = {
            "enabled": True, "armed": True, "codec": "mp2_192",
            "max_recording_seconds": 4440,
            "recording": {"active": False, "seconds": 0, "bytes": 0,
                          "truncated_head": False, "origin_input": 1,
                          "unavailable_reason": None},
            "replay": {"active": True, "position_seconds": 12.0,
                       "duration_seconds": 60.0, "loop_count": 1},
        }
        _set_repeat_status(repeat_block)
        try:
            responses: list = []
            h = _handler(responses)
            with patch("autostream_webui_api.get_playback_snapshot") as gp:
                gp.return_value.to_public_dict.return_value = {}
                gp.return_value.stylus_banner_text = ""
                gp.return_value.belt_banner_text = ""
                gp.return_value.bearing_banner_text = ""
                send_status_json(h)
            body = responses[0]["body"]
            assert body["repeat"] == repeat_block
        finally:
            _set_repeat_status(None)

    def test_repeat_block_omitted_when_absent(self):
        _set_repeat_status(None)
        responses: list = []
        h = _handler(responses)
        with patch("autostream_webui_api.get_playback_snapshot") as gp:
            gp.return_value.to_public_dict.return_value = {}
            gp.return_value.stylus_banner_text = ""
            gp.return_value.belt_banner_text = ""
            gp.return_value.bearing_banner_text = ""
            send_status_json(h)
        body = responses[0]["body"]
        assert "repeat" not in body

    def test_get_repeat_status_ignores_non_dict(self):
        _set_repeat_status("not-a-dict")  # e.g. malformed daemon response
        try:
            assert get_repeat_status() is None
        finally:
            _set_repeat_status(None)

    # -- session: always present, unlike "repeat" above --

    def test_session_always_present_and_playing_follows_session_active(self):
        """session.active true + source='replay' while replaying; the
        top-level "playing" flag is session.active-driven, not a raw
        is_capturing check (this is the fix for "UI playing flag false
        during replay")."""
        _set_session_state(True, "replay")
        try:
            responses: list = []
            h = _handler(responses)
            with patch("autostream_webui_api.get_playback_snapshot") as gp, \
                 patch("autostream_webui_api.any_monitor_capturing", return_value=False):
                gp.return_value.to_public_dict.return_value = {}
                gp.return_value.stylus_banner_text = ""
                gp.return_value.belt_banner_text = ""
                gp.return_value.bearing_banner_text = ""
                send_status_json(h)
            body = responses[0]["body"]
            assert body["session"] == {"active": True, "source": "replay"}
            assert body["playing"] is True, (
                "playing must follow session.active even though no input is "
                "capturing (any_monitor_capturing() is mocked False here)"
            )
        finally:
            _set_session_state(False, None)

    def test_session_present_when_no_repeat_feature(self):
        """session must not be gated on the "repeat" block's presence (old
        binary / repeat never enabled) -- unlike "repeat", it is always
        emitted."""
        _set_repeat_status(None)
        _set_session_state(False, None)
        responses: list = []
        h = _handler(responses)
        with patch("autostream_webui_api.get_playback_snapshot") as gp:
            gp.return_value.to_public_dict.return_value = {}
            gp.return_value.stylus_banner_text = ""
            gp.return_value.belt_banner_text = ""
            gp.return_value.bearing_banner_text = ""
            send_status_json(h)
        body = responses[0]["body"]
        assert body["session"] == {"active": False, "source": None}
        assert body["playing"] is False
        assert "repeat" not in body


# ── P5: Unified playback-session tracker ─────────────────────────────────────
#
# _SessionTracker diffs the {input1, input2, replay} source vector between
# poll cycles into exactly one of session_started / session_ended /
# source_changed / None. _dispatch_session_event() is the one place that
# turns an event into OwnTone/now-playing side effects (the coordinator poll
# loop's single call site); tests below exercise the tracker and the
# dispatcher directly, which together fully cover the poll loop's session
# wiring without needing to run run_autostream()'s socket-connected loop.

BASE_URL = "http://localhost:3689"


def _status(*, replay_active=False, origin_input=1):
    """Build a repeat_status block reflecting one poll cycle's replay state."""
    return {
        "armed": replay_active,
        "replay": {"active": replay_active},
        "recording": {"bytes": 100 if replay_active else 0, "origin_input": origin_input},
    }


class TestSessionTrackerVector:
    """Pure _SessionTracker.update() diff behaviour."""

    def test_idle_to_idle_no_event(self):
        mon1 = _make_monitor(input_index=1)
        tracker = _SessionTracker()
        event, prev, new, source = tracker.update([mon1], None)
        assert event is None
        assert source is None

    def test_input_capture_start_is_session_started(self):
        mon1 = _make_monitor(input_index=1)
        tracker = _SessionTracker()
        tracker.update([mon1], None)  # idle baseline
        mon1.is_capturing = True
        event, prev, new, source = tracker.update([mon1], None)
        assert event == "session_started"
        assert prev is None
        assert new is mon1
        assert source == "input1"

    def test_replay_start_from_idle_is_session_started_attributed_to_origin(self):
        """replay-start from idle fires session_started, resolved to the
        origin input's AudioMonitor even though that monitor's is_capturing
        is False (this is what makes replay-triggered output-enable possible
        at all)."""
        mon1 = _make_monitor(input_index=1)
        mon2 = _make_monitor(input_index=2)
        tracker = _SessionTracker()
        tracker.update([mon1, mon2], None)  # idle baseline
        status = _status(replay_active=True, origin_input=1)
        event, prev, new, source = tracker.update([mon1, mon2], status)
        assert event == "session_started"
        assert prev is None
        assert new is mon1
        assert source == "replay"

    def test_input_handoff_is_source_changed(self):
        mon1 = _make_monitor(input_index=1)
        mon2 = _make_monitor(input_index=2)
        tracker = _SessionTracker()
        mon1.is_capturing = True
        tracker.update([mon1, mon2], None)  # session started on input1
        mon1.is_capturing = False
        mon2.is_capturing = True
        event, prev, new, source = tracker.update([mon1, mon2], None)
        assert event == "source_changed"
        assert prev is mon1
        assert new is mon2
        assert source == "input2"

    def test_capture_end_to_replay_handoff_is_source_changed(self):
        """Capture-stop -> replay-start atomic within one snapshot (daemon
        guarantee): the vector goes straight from input1-capturing to
        replay-active-for-input1 in a single update() call, so this is a
        source_changed, never a session_ended followed by a session_started."""
        mon1 = _make_monitor(input_index=1)
        tracker = _SessionTracker()
        mon1.is_capturing = True
        tracker.update([mon1], None)
        mon1.is_capturing = False
        status = _status(replay_active=True, origin_input=1)
        event, prev, new, source = tracker.update([mon1], status)
        assert event == "source_changed"
        assert prev is mon1
        assert new is mon1
        assert source == "replay"

    def test_live_interrupt_of_replay_is_source_changed(self):
        """a live capture interrupting replay -- the vector shows the
        replay ending and a capture starting in the same snapshot, so this is
        source_changed, not session_ended+session_started."""
        mon1 = _make_monitor(input_index=1)
        mon2 = _make_monitor(input_index=2)
        tracker = _SessionTracker()
        status = _status(replay_active=True, origin_input=1)
        tracker.update([mon1, mon2], status)  # session started via replay
        mon2.is_capturing = True  # input2 interrupts; daemon has already ended replay
        event, prev, new, source = tracker.update([mon1, mon2], None)
        assert event == "source_changed"
        assert prev is mon1
        assert new is mon2
        assert source == "input2"

    def test_disarm_during_replay_is_session_ended(self):
        mon1 = _make_monitor(input_index=1)
        tracker = _SessionTracker()
        status = _status(replay_active=True, origin_input=1)
        tracker.update([mon1], status)
        event, prev, new, source = tracker.update([mon1], None)  # disarmed, no capture
        assert event == "session_ended"
        assert prev is mon1
        assert new is None
        assert source is None

    def test_capture_stop_to_idle_is_session_ended(self):
        mon1 = _make_monitor(input_index=1)
        tracker = _SessionTracker()
        mon1.is_capturing = True
        tracker.update([mon1], None)
        mon1.is_capturing = False
        event, prev, new, source = tracker.update([mon1], None)
        assert event == "session_ended"
        assert prev is mon1
        assert new is None

    def test_no_repeat_block_degrades_to_inputs_only(self):
        """Old binary / repeat never reporting: vector is inputs-only,
        session events behave exactly as before repeat existed."""
        mon1 = _make_monitor(input_index=1)
        tracker = _SessionTracker()
        for _ in range(3):
            event, *_ = tracker.update([mon1], None)
            assert event is None
        mon1.is_capturing = True
        event, prev, new, source = tracker.update([mon1], None)
        assert event == "session_started"
        assert source == "input1"

    def test_reset_after_idle_produces_no_spurious_event(self):
        """Reconnect/resync edge discipline: resetting while nothing was
        active must not manufacture an event on the next cycle."""
        mon1 = _make_monitor(input_index=1)
        tracker = _SessionTracker()
        tracker.update([mon1], None)
        tracker.reset()
        event, prev, new, source = tracker.update([mon1], None)
        assert event is None
        assert source is None

    def test_reset_during_active_session_reports_started_next_cycle(self):
        """Documented choice: if a session is genuinely still
        active across a reconnect, reset() makes the next cycle report it as
        a fresh session_started -- consistent with reconnect already forcing
        a full OwnTone re-validation for every monitor."""
        mon1 = _make_monitor(input_index=1)
        tracker = _SessionTracker()
        mon1.is_capturing = True
        tracker.update([mon1], None)
        tracker.reset()
        event, prev, new, source = tracker.update([mon1], None)
        assert event == "session_started"
        assert prev is None
        assert new is mon1


class TestDispatchSessionEvent:
    """_dispatch_session_event(): the poll loop's single event -> side-effect
    mapping. Patches the underlying primitives so each event's action set can
    be asserted precisely."""

    def _mon(self, **overrides):
        return _make_monitor(**overrides)

    def test_session_started_input_sourced_invokes_output_enable_once(self):
        mon = self._mon(owntone_base_url=BASE_URL)
        with patch.object(core, "_start_session_owntone") as start_mock, \
             patch.object(core, "_stop_and_disable_owntone") as stop_mock, \
             patch.object(mon, "_nowplaying_publisher") as pub:
            _dispatch_session_event("session_started", None, mon, BASE_URL)
        start_mock.assert_called_once_with(mon)
        stop_mock.assert_not_called()
        pub.publish_start.assert_called_once()

    def test_session_started_replay_sourced_invokes_output_enable_once(self):
        """replay-start from idle: session_started fires the
        output-enable path through the origin input's AudioMonitor exactly
        once -- same call as the input-sourced case, no duplicated logic."""
        origin_mon = self._mon(input_index=1, owntone_base_url=BASE_URL)
        origin_mon.is_capturing = False  # replay, not a live capture
        with patch.object(core, "_start_session_owntone") as start_mock, \
             patch.object(origin_mon, "_nowplaying_publisher") as pub:
            _dispatch_session_event("session_started", None, origin_mon, BASE_URL)
        start_mock.assert_called_once_with(origin_mon)
        pub.publish_start.assert_called_once()

    def test_session_ended_stops_and_disables_once(self):
        """Disarm-during-replay (or any session end) -> stop fired exactly once."""
        mon = self._mon(owntone_base_url=BASE_URL)
        with patch.object(core, "_stop_and_disable_owntone") as stop_mock, \
             patch.object(core, "_start_session_owntone") as start_mock, \
             patch.object(mon, "_nowplaying_publisher") as pub:
            _dispatch_session_event("session_ended", mon, None, BASE_URL)
        stop_mock.assert_called_once_with(BASE_URL, "session ended")
        start_mock.assert_not_called()
        pub.publish_end.assert_called_once()

    def test_session_ended_without_base_url_skips_stop(self):
        mon = self._mon(owntone_base_url=BASE_URL)
        with patch.object(core, "_stop_and_disable_owntone") as stop_mock, \
             patch.object(mon, "_nowplaying_publisher"):
            _dispatch_session_event("session_ended", mon, None, "")
        stop_mock.assert_not_called()

    def test_source_changed_fires_no_output_or_volume_action(self):
        """live interrupt during replay (and, equally, capture-end ->
        replay handoff / input1<->input2 handoff): source_changed must never
        touch OwnTone output selection or volume."""
        prev_mon = self._mon(input_index=1, owntone_base_url=BASE_URL)
        new_mon = self._mon(input_index=2, owntone_base_url=BASE_URL)
        with patch.object(core, "_stop_and_disable_owntone") as stop_mock, \
             patch.object(core, "_start_session_owntone") as start_mock, \
             patch.object(prev_mon, "_nowplaying_publisher") as prev_pub, \
             patch.object(new_mon, "_nowplaying_publisher") as new_pub:
            _dispatch_session_event("source_changed", prev_mon, new_mon, BASE_URL)
        stop_mock.assert_not_called()
        start_mock.assert_not_called()
        prev_pub.publish_end.assert_called_once()
        new_pub.publish_start.assert_called_once()

    def test_none_event_is_a_no_op(self):
        with patch.object(core, "_stop_and_disable_owntone") as stop_mock, \
             patch.object(core, "_start_session_owntone") as start_mock:
            _dispatch_session_event(None, None, None, BASE_URL)
        stop_mock.assert_not_called()
        start_mock.assert_not_called()

    def test_publish_end_failure_is_logged_not_swallowed(self, caplog):
        """publish_end() failures must be logged, not swallowed by a
        bare except: pass."""
        import logging as _logging
        mon = self._mon()
        with patch.object(mon, "_nowplaying_publisher") as pub:
            pub.publish_end.side_effect = RuntimeError("boom")
            with caplog.at_level(_logging.DEBUG):
                _dispatch_session_event("session_ended", mon, None, "")  # must not raise
        assert any(
            "publish_end failed" in r.message and str(mon.input_index) in r.message
            for r in caplog.records
        )

    def test_session_started_replay_sourced_arms_track_identification(self):
        """session_started landing on the replay source must
        arm the origin input's identification cycle, since is_capturing
        never transitions to True for a replay-sourced session (the only
        other arming site, _on_capture_started, would otherwise never fire)."""
        origin_mon = self._mon(input_index=1, owntone_base_url=BASE_URL)
        origin_mon.is_capturing = False
        with patch.object(core, "_start_session_owntone"), \
             patch.object(origin_mon, "_nowplaying_publisher"), \
             patch.object(origin_mon, "_arm_track_identification_for_replay") as arm_mock:
            _dispatch_session_event(
                "session_started", None, origin_mon, BASE_URL, new_source="replay",
            )
        arm_mock.assert_called_once()

    def test_source_changed_to_replay_arms_track_identification(self):
        prev_mon = self._mon(input_index=1, owntone_base_url=BASE_URL)
        origin_mon = self._mon(input_index=2, owntone_base_url=BASE_URL)
        origin_mon.is_capturing = False
        with patch.object(prev_mon, "_nowplaying_publisher"), \
             patch.object(origin_mon, "_nowplaying_publisher"), \
             patch.object(origin_mon, "_arm_track_identification_for_replay") as arm_mock:
            _dispatch_session_event(
                "source_changed", prev_mon, origin_mon, BASE_URL, new_source="replay",
            )
        arm_mock.assert_called_once()

    def test_session_started_input_sourced_does_not_arm_replay_identification(self):
        """A live-capture session start must not go through the replay-arming
        path -- _on_capture_started (fired separately per-input) already
        handles it."""
        mon = self._mon(input_index=1, owntone_base_url=BASE_URL)
        with patch.object(core, "_start_session_owntone"), \
             patch.object(mon, "_nowplaying_publisher"), \
             patch.object(mon, "_arm_track_identification_for_replay") as arm_mock:
            _dispatch_session_event(
                "session_started", None, mon, BASE_URL, new_source="input1",
            )
        arm_mock.assert_not_called()


class TestStartSessionOwntone:
    """_start_session_owntone(): the reused was_idle-equivalent output path."""

    def test_replay_origin_forces_maybe_retry_despite_not_capturing(self):
        """The core bug fix: a replay-sourced monitor is not "capturing", so
        _maybe_retry_owntone must be driven with replay_origin=True or the
        retry silently no-ops (the "replay never enables outputs" symptom)."""
        mon = _make_monitor(owntone_base_url=BASE_URL)
        mon.is_capturing = False
        with patch.object(core, "_stop_and_disable_owntone"), \
             patch.object(mon, "_maybe_retry_owntone") as retry_mock:
            _start_session_owntone(mon)
        retry_mock.assert_called_once()
        assert retry_mock.call_args.kwargs.get("replay_origin") is True

    def test_resets_owntone_enabled_ok_and_forces_immediate_attempt(self):
        mon = _make_monitor(owntone_base_url=BASE_URL)
        mon._owntone_enabled_ok = True
        mon._owntone_last_attempt = time.time()
        with patch.object(core, "_stop_and_disable_owntone"), \
             patch.object(mon, "_maybe_retry_owntone"):
            _start_session_owntone(mon)
        assert mon._owntone_enabled_ok is False
        assert mon._owntone_last_attempt == 0.0

    def test_clears_previous_output_selection(self):
        mon = _make_monitor(owntone_base_url=BASE_URL)
        with patch.object(core, "_stop_and_disable_owntone") as stop_mock, \
             patch.object(mon, "_maybe_retry_owntone"):
            _start_session_owntone(mon)
        stop_mock.assert_called_once_with(BASE_URL, "session start")

    def test_no_base_url_skips_stop_but_still_retries(self):
        mon = _make_monitor(owntone_base_url="")
        with patch.object(core, "_stop_and_disable_owntone") as stop_mock, \
             patch.object(mon, "_maybe_retry_owntone") as retry_mock:
            _start_session_owntone(mon)
        stop_mock.assert_not_called()
        retry_mock.assert_called_once()


class TestMaybeRetryOwntoneReplayOrigin:
    def test_replay_origin_bypasses_is_capturing_guard(self):
        mon = _make_monitor(owntone_base_url=BASE_URL)
        mon.is_capturing = False
        with patch.object(core, "reconcile_fifo_with_backend") as rf:
            rf.return_value = MagicMock(ok=False, message="stop here")
            mon._maybe_retry_owntone(time.time(), replay_origin=True)
        rf.assert_called_once()  # proceeded past the is_capturing guard

    def test_default_false_preserves_pre_wpr6_behaviour(self):
        mon = _make_monitor(owntone_base_url=BASE_URL)
        mon.is_capturing = False
        with patch.object(core, "reconcile_fifo_with_backend") as rf:
            mon._maybe_retry_owntone(time.time())
        rf.assert_not_called()  # bailed out on the is_capturing guard, as before


# ── P6: Resync re-push ────────────────────────────────────────────────────────

class TestP6ResyncRepush:
    def _mock_client_for_resync(self) -> MagicMock:
        c = MagicMock(spec=MonitorClient)
        c.set_fifo.return_value = True
        c.set_log_level.return_value = True
        c.stop_input.return_value = True
        c.configure_input.return_value = True
        c.start_input.return_value = True
        c.set_allow_capture.return_value = True
        c.set_repeat_enabled.return_value = True
        return c

    def test_resync_pushes_set_repeat_enabled_with_current_config(self):
        client = self._mock_client_for_resync()
        with patch("autostream_core.reconcile_fifo_with_backend") as rf, \
             patch("autostream_core.apply_input_gain", return_value=True), \
             patch("autostream_core.apply_input_eq", return_value=True), \
             patch("autostream_core._apply_output_eq_config", return_value=True):
            rf.return_value = MagicMock(ok=True, message="")
            ok = _resync_monitor_daemon(
                client, [], "/tmp/test.fifo", "http://localhost:3689",
                MagicMock(), repeat_enabled=True, repeat_codec="mp2_224",
            )
        assert ok is True
        client.set_repeat_enabled.assert_called_once_with(True, "mp2_224", None)

    def test_resync_pushes_target_minutes_through(self):
        """repeat_target_minutes flows through _resync_monitor_daemon to
        MonitorClient.set_repeat_enabled's target_minutes argument."""
        client = self._mock_client_for_resync()
        with patch("autostream_core.reconcile_fifo_with_backend") as rf, \
             patch("autostream_core.apply_input_gain", return_value=True), \
             patch("autostream_core.apply_input_eq", return_value=True), \
             patch("autostream_core._apply_output_eq_config", return_value=True):
            rf.return_value = MagicMock(ok=True, message="")
            ok = _resync_monitor_daemon(
                client, [], "/tmp/test.fifo", "http://localhost:3689",
                MagicMock(), repeat_enabled=True, repeat_codec="mp2_224",
                repeat_target_minutes=45,
            )
        assert ok is True
        client.set_repeat_enabled.assert_called_once_with(True, "mp2_224", 45)

    def test_resync_tolerates_old_binary_rejecting_repeat_command(self):
        """set_repeat_enabled failing (old binary) must not fail the whole resync."""
        client = self._mock_client_for_resync()
        client.set_repeat_enabled.return_value = False
        with patch("autostream_core.reconcile_fifo_with_backend") as rf, \
             patch("autostream_core.apply_input_gain", return_value=True), \
             patch("autostream_core.apply_input_eq", return_value=True), \
             patch("autostream_core._apply_output_eq_config", return_value=True):
            rf.return_value = MagicMock(ok=True, message="")
            ok = _resync_monitor_daemon(
                client, [], "/tmp/test.fifo", "http://localhost:3689",
                MagicMock(), repeat_enabled=False, repeat_codec="auto",
            )
        assert ok is True, "an old binary rejecting set_repeat_enabled must not fail resync"

    # ── Pipe-format reconcile wiring ────────────────────────────────────────
    #
    # reconcile_pipe_format_with_backend() (autostream_player_service.py) is
    # sequenced right after reconcile_fifo_with_backend() inside
    # _resync_monitor_daemon -- a monitor reconnect is exactly the moment the
    # daemon's compile-time output format could have changed (upgraded
    # binary), same reasoning as the FIFO-path reconcile it sits next to.

    def test_resync_calls_format_reconcile_with_status_after_fifo_ok(self):
        """Format reconcile is called with the base_url and the client's live
        get_status() dict, only once the FIFO-path reconcile has succeeded."""
        client = self._mock_client_for_resync()
        status_dict = {"output_rate": 48000, "output_bits": 32}
        client.get_status.return_value = status_dict
        with patch("autostream_core.reconcile_fifo_with_backend") as rf, \
             patch("autostream_core.reconcile_monitor_format") as monfmt, \
             patch("autostream_core.reconcile_pipe_format_with_backend") as fmt, \
             patch("autostream_core.apply_input_gain", return_value=True), \
             patch("autostream_core.apply_input_eq", return_value=True), \
             patch("autostream_core._apply_output_eq_config", return_value=True):
            rf.return_value = MagicMock(ok=True, message="")
            monfmt.return_value = MagicMock(ok=True, error="", error_code="")
            fmt.return_value = MagicMock(ok=True, error="", error_code="")
            ok = _resync_monitor_daemon(
                client, [], "/tmp/test.fifo", "http://localhost:3689",
                MagicMock(), repeat_enabled=True, repeat_codec="mp2_224",
            )
        assert ok is True
        fmt.assert_called_once_with("http://localhost:3689", status_dict, timeout=3.0)
        # Sequenced after the FIFO reconcile, not before.
        assert rf.call_count == 1

    def test_resync_format_reconcile_skipped_when_fifo_reconcile_fails(self):
        """A failed FIFO-path reconcile must abort resync before the format
        reconcile is ever attempted (mirrors the existing early-return)."""
        client = self._mock_client_for_resync()
        with patch("autostream_core.reconcile_fifo_with_backend") as rf, \
             patch("autostream_core.reconcile_pipe_format_with_backend") as fmt:
            rf.return_value = MagicMock(ok=False, message="fifo down")
            ok = _resync_monitor_daemon(
                client, [], "/tmp/test.fifo", "http://localhost:3689",
                MagicMock(), repeat_enabled=False, repeat_codec="auto",
            )
        assert ok is False
        fmt.assert_not_called()

    def test_resync_format_reconcile_noop_when_monitor_status_unavailable(self):
        """A monitor that fails get_status() (unreachable/EOF) must still
        resolve to a clean no-op: resync proceeds, no exception, and the
        (real, unmocked) reconcile function is handed None rather than being
        skipped -- it owns the "no format info" no-op behaviour itself."""
        client = self._mock_client_for_resync()
        client.get_status.return_value = None
        with patch("autostream_core.reconcile_fifo_with_backend") as rf, \
             patch("autostream_core.reconcile_pipe_format_with_backend") as fmt, \
             patch("autostream_core.apply_input_gain", return_value=True), \
             patch("autostream_core.apply_input_eq", return_value=True), \
             patch("autostream_core._apply_output_eq_config", return_value=True):
            rf.return_value = MagicMock(ok=True, message="")
            fmt.return_value = MagicMock(ok=True, error="", error_code="")
            ok = _resync_monitor_daemon(
                client, [], "/tmp/test.fifo", "http://localhost:3689",
                MagicMock(), repeat_enabled=False, repeat_codec="auto",
            )
        assert ok is True
        fmt.assert_called_once_with("http://localhost:3689", None, timeout=3.0)

    def test_resync_format_reconcile_real_function_noop_on_missing_status(self):
        """End-to-end (unmocked reconcile_pipe_format_with_backend): a monitor
        that can't report get_status() must not touch the playback backend at
        all -- no resolve_backend/get_setting/save_setting call, and resync
        still reports ok."""
        client = self._mock_client_for_resync()
        client.get_status.return_value = None
        with patch("autostream_core.reconcile_fifo_with_backend") as rf, \
             patch("autostream_core.apply_input_gain", return_value=True), \
             patch("autostream_core.apply_input_eq", return_value=True), \
             patch("autostream_core._apply_output_eq_config", return_value=True), \
             patch("autostream_player_service.resolve_backend") as resolve_mock:
            rf.return_value = MagicMock(ok=True, message="")
            ok = _resync_monitor_daemon(
                client, [], "/tmp/test.fifo", "http://localhost:3689",
                MagicMock(), repeat_enabled=False, repeat_codec="auto",
            )
        assert ok is True
        resolve_mock.assert_not_called()


# ── Monitor-format reconcile wiring, sequenced before ──────────────────────
#    the owntone-mini pipe-format reconcile above.
#
# reconcile_monitor_format() (autostream_player_service.py, FIFO
# format-switch) is sequenced right before
# reconcile_pipe_format_with_backend() inside _resync_monitor_daemon: a
# monitor restart it triggers tears down this very connection and
# re-enters _resync_monitor_daemon via the reconnect path, so the
# pipe-format reconcile immediately after it would otherwise chase a
# monitor report that is about to change out from under it.

class TestMonitorFormatReconcileWiring:
    def _mock_client_for_resync(self) -> MagicMock:
        c = MagicMock(spec=MonitorClient)
        c.set_fifo.return_value = True
        c.set_log_level.return_value = True
        c.stop_input.return_value = True
        c.configure_input.return_value = True
        c.start_input.return_value = True
        c.set_allow_capture.return_value = True
        c.set_repeat_enabled.return_value = True
        return c

    def test_resync_calls_monitor_format_reconcile_with_status_after_fifo_ok(self):
        client = self._mock_client_for_resync()
        status_dict = {"output_format": "native"}
        client.get_status.return_value = status_dict
        with patch("autostream_core.reconcile_fifo_with_backend") as rf, \
             patch("autostream_core.reconcile_monitor_format") as monfmt, \
             patch("autostream_core.reconcile_pipe_format_with_backend") as fmt, \
             patch("autostream_core.push_resample_quality"), \
             patch("autostream_core.sync_monitor_args_for_audio_path"), \
             patch("autostream_core.apply_input_gain", return_value=True), \
             patch("autostream_core.apply_input_eq", return_value=True), \
             patch("autostream_core._apply_output_eq_config", return_value=True):
            rf.return_value = MagicMock(ok=True, message="")
            monfmt.return_value = MagicMock(ok=True, error="", error_code="")
            fmt.return_value = MagicMock(ok=True, error="", error_code="")
            ok = _resync_monitor_daemon(
                client, [], "/tmp/test.fifo", "http://localhost:3689",
                MagicMock(), repeat_enabled=True, repeat_codec="mp2_224",
            )
        assert ok is True
        monfmt.assert_called_once_with(
            "http://localhost:3689", status_dict, timeout=3.0, audio_path="balanced",
        )

    def test_resync_monitor_format_reconcile_runs_before_pipe_format_reconcile(self):
        """Ordering proof: monitor_format must be called strictly before
        pipe_format on the same _resync_monitor_daemon pass."""
        client = self._mock_client_for_resync()
        client.get_status.return_value = {"output_format": "compatible"}
        manager = MagicMock()
        with patch("autostream_core.reconcile_fifo_with_backend") as rf, \
             patch("autostream_core.reconcile_monitor_format") as monfmt, \
             patch("autostream_core.reconcile_pipe_format_with_backend") as fmt, \
             patch("autostream_core.push_resample_quality"), \
             patch("autostream_core.sync_monitor_args_for_audio_path"), \
             patch("autostream_core.apply_input_gain", return_value=True), \
             patch("autostream_core.apply_input_eq", return_value=True), \
             patch("autostream_core._apply_output_eq_config", return_value=True):
            rf.return_value = MagicMock(ok=True, message="")
            monfmt.return_value = MagicMock(ok=True, error="", error_code="")
            fmt.return_value = MagicMock(ok=True, error="", error_code="")
            manager.attach_mock(monfmt, "monitor_format")
            manager.attach_mock(fmt, "pipe_format")
            ok = _resync_monitor_daemon(
                client, [], "/tmp/test.fifo", "http://localhost:3689",
                MagicMock(), repeat_enabled=False, repeat_codec="auto",
            )
        assert ok is True
        call_names = [c[0] for c in manager.mock_calls]
        assert "monitor_format" in call_names
        assert "pipe_format" in call_names
        assert call_names.index("monitor_format") < call_names.index("pipe_format")

    def test_resync_monitor_format_reconcile_skipped_when_fifo_reconcile_fails(self):
        client = self._mock_client_for_resync()
        with patch("autostream_core.reconcile_fifo_with_backend") as rf, \
             patch("autostream_core.reconcile_monitor_format") as monfmt, \
             patch("autostream_core.reconcile_pipe_format_with_backend") as fmt:
            rf.return_value = MagicMock(ok=False, message="fifo down")
            ok = _resync_monitor_daemon(
                client, [], "/tmp/test.fifo", "http://localhost:3689",
                MagicMock(), repeat_enabled=False, repeat_codec="auto",
            )
        assert ok is False
        monfmt.assert_not_called()
        fmt.assert_not_called()

    def test_resync_monitor_format_reconcile_noop_when_monitor_status_unavailable(self):
        """A monitor that fails get_status() must still resolve to a clean
        no-op: resync proceeds, and the (real, unmocked)
        reconcile_monitor_format() is handed None rather than being skipped
        -- it owns the "no status" no-op behaviour itself."""
        client = self._mock_client_for_resync()
        client.get_status.return_value = None
        with patch("autostream_core.reconcile_fifo_with_backend") as rf, \
             patch("autostream_core.apply_input_gain", return_value=True), \
             patch("autostream_core.apply_input_eq", return_value=True), \
             patch("autostream_core._apply_output_eq_config", return_value=True), \
             patch("autostream_player_service.resolve_backend") as resolve_mock:
            rf.return_value = MagicMock(ok=True, message="")
            ok = _resync_monitor_daemon(
                client, [], "/tmp/test.fifo", "http://localhost:3689",
                MagicMock(), repeat_enabled=False, repeat_codec="auto",
            )
        assert ok is True
        resolve_mock.assert_not_called()


# ── P7: Reload teardown ───────────────────────────────────────────────────────

class TestP7ReloadTeardown:
    def test_set_repeat_armed_false_precedes_stop_input_in_source(self):
        """Disarm must be sent before stop_input() in the finally teardown."""
        src = inspect.getsource(core.run_autostream)
        idx_disarm = src.find("client.set_repeat_armed(False)")
        idx_stop_input = src.find("client.stop_input(m.input_index)")
        assert idx_disarm != -1, "teardown must call client.set_repeat_armed(False)"
        assert idx_stop_input != -1
        assert idx_disarm < idx_stop_input

    def test_teardown_disarm_call_does_not_raise_when_client_fails(self):
        """The exception path around the disarm call must not break teardown."""
        client = MagicMock(spec=MonitorClient)
        client.set_repeat_armed.side_effect = RuntimeError("socket gone")
        try:
            client.set_repeat_armed(False)
        except Exception:
            pass  # exercising the same guard the source wraps this call in
        # The real assertion is structural: the call site must be wrapped in
        # try/except in the source (see test above's ordering check combined
        # with this file's own review of the finally block).
        src = inspect.getsource(core.run_autostream)
        # crude locality check: a try: appears shortly before the disarm call
        idx_disarm = src.find("client.set_repeat_armed(False)")
        preceding = src[max(0, idx_disarm - 120):idx_disarm]
        assert "try:" in preceding


# ── P8: Playback-hours during replay ──────────────────────────────────────────

class TestP8PlaybackHoursDuringReplay:
    def _with_tracker(self):
        tracker = MagicMock()
        original = core._playback_tracker
        core._playback_tracker = tracker
        return tracker, original

    def _restore(self, original):
        core._playback_tracker = original

    def test_accrues_during_replay_for_origin_input(self):
        mon = _make_monitor(input_index=1)
        mon.is_capturing = False
        mon.is_silent = True
        mon._tracker_playback_active = False
        mon._tracker_wear_active = False
        tracker, original = self._with_tracker()
        repeat_status = {
            "replay": {"active": True},
            "recording": {"origin_input": 1, "bytes": 100},
        }
        try:
            mon._sync_playback_tracker_state(repeat_status)
            # Total playback hours accrue for replay of the origin input...
            tracker.on_playback_started.assert_called_once_with(1)
            assert mon._tracker_playback_active is True
            # ...but wear (stylus/belt/bearing) does not: replay is buffered
            # audio, not physical turntable activity.
            tracker.on_wear_started.assert_not_called()
            assert mon._tracker_wear_active is False
        finally:
            self._restore(original)

    def test_replay_with_silent_adc_accrues_total_not_wear(self):
        """Mixed case: replay active while the ADC on the origin input hears
        silence (e.g. a quiet passage on the physical turntable, or the
        turntable simply idle). Total hours must keep accruing from the
        replay; wear must not accrue since there is no real input capture."""
        mon = _make_monitor(input_index=1)
        mon.is_capturing = False
        mon.is_silent = True
        mon._tracker_playback_active = False
        mon._tracker_wear_active = False
        tracker, original = self._with_tracker()
        repeat_status = {
            "replay": {"active": True},
            "recording": {"origin_input": 1, "bytes": 100},
        }
        try:
            mon._sync_playback_tracker_state(repeat_status)
            tracker.on_playback_started.assert_called_once_with(1)
            assert mon._tracker_playback_active is True
            tracker.on_wear_started.assert_not_called()
            assert mon._tracker_wear_active is False
        finally:
            self._restore(original)

    def test_live_capture_during_replay_accrues_both(self):
        """Real input capture resumes on the origin input while replay is
        still reported active (e.g. the daemon has not yet cut the replay
        over). Both total and wear must accrue since real audio is present."""
        mon = _make_monitor(input_index=1)
        mon.is_capturing = True
        mon.is_silent = False
        mon._tracker_playback_active = True   # already accruing via replay
        mon._tracker_wear_active = False
        tracker, original = self._with_tracker()
        repeat_status = {
            "replay": {"active": True},
            "recording": {"origin_input": 1, "bytes": 100},
        }
        try:
            mon._sync_playback_tracker_state(repeat_status)
            # Playback was already active (via replay) -- no redundant call.
            tracker.on_playback_started.assert_not_called()
            assert mon._tracker_playback_active is True
            # Wear turns on now that real capture is audible.
            tracker.on_wear_started.assert_called_once_with(1)
            assert mon._tracker_wear_active is True
        finally:
            self._restore(original)

    def test_live_capture_accrues_both_without_replay(self):
        """Ordinary live capture (no repeat replay in play): both total and
        wear accrue together."""
        mon = _make_monitor(input_index=1)
        mon.is_capturing = True
        mon.is_silent = False
        mon._tracker_playback_active = False
        mon._tracker_wear_active = False
        tracker, original = self._with_tracker()
        try:
            mon._sync_playback_tracker_state(None)
            tracker.on_playback_started.assert_called_once_with(1)
            assert mon._tracker_playback_active is True
            tracker.on_wear_started.assert_called_once_with(1)
            assert mon._tracker_wear_active is True
        finally:
            self._restore(original)

    def test_does_not_accrue_for_non_origin_input_during_replay(self):
        mon = _make_monitor(input_index=2)
        mon.is_capturing = False
        mon.is_silent = True
        mon._tracker_playback_active = False
        tracker, original = self._with_tracker()
        repeat_status = {
            "replay": {"active": True},
            "recording": {"origin_input": 1, "bytes": 100},
        }
        try:
            mon._sync_playback_tracker_state(repeat_status)
            tracker.on_playback_started.assert_not_called()
            assert mon._tracker_playback_active is False
        finally:
            self._restore(original)

    def test_stops_accruing_when_replay_ends(self):
        mon = _make_monitor(input_index=1)
        mon.is_capturing = False
        mon.is_silent = True
        mon._tracker_playback_active = True  # was accruing via replay
        tracker, original = self._with_tracker()
        repeat_status = {"replay": {"active": False}, "recording": {"origin_input": 1, "bytes": 100}}
        try:
            mon._sync_playback_tracker_state(repeat_status)
            tracker.on_playback_stopped.assert_called_once_with(1)
            assert mon._tracker_playback_active is False
        finally:
            self._restore(original)

    def test_no_repeat_status_behaves_like_pre_wp5(self):
        mon = _make_monitor(input_index=1)
        mon.is_capturing = True
        mon.is_silent = False
        mon._tracker_playback_active = False
        tracker, original = self._with_tracker()
        try:
            mon._sync_playback_tracker_state(None)
            tracker.on_playback_started.assert_called_once_with(1)
        finally:
            self._restore(original)


# ── Live setter unit tests (MonitorClient socket commands) ────────────────────

class TestLiveSetters:
    def test_set_live_repeat_enabled_sends_command(self):
        mock_client = MagicMock()
        mock_client.set_repeat_enabled.return_value = True
        with patch("autostream_core._connected_monitor") as cm:
            cm.return_value.__enter__.return_value = mock_client
            ok = set_live_repeat_enabled(True, "mp2_160")
        assert ok is True
        mock_client.set_repeat_enabled.assert_called_once_with(True, "mp2_160", None)

    def test_set_live_repeat_enabled_forwards_target_minutes(self):
        mock_client = MagicMock()
        mock_client.set_repeat_enabled.return_value = True
        with patch("autostream_core._connected_monitor") as cm:
            cm.return_value.__enter__.return_value = mock_client
            ok = set_live_repeat_enabled(True, "mp2_160", 45)
        assert ok is True
        mock_client.set_repeat_enabled.assert_called_once_with(True, "mp2_160", 45)

    def test_set_live_repeat_enabled_no_client_returns_false(self):
        with patch("autostream_core._connected_monitor") as cm:
            cm.return_value.__enter__.return_value = None
            ok = set_live_repeat_enabled(True, "auto")
        assert ok is False

    def test_set_live_repeat_armed_sends_command(self):
        mock_client = MagicMock()
        mock_client.set_repeat_armed.return_value = True
        with patch("autostream_core._connected_monitor") as cm:
            cm.return_value.__enter__.return_value = mock_client
            ok = set_live_repeat_armed(True)
        assert ok is True
        mock_client.set_repeat_armed.assert_called_once_with(True)

    def test_monitor_client_set_repeat_enabled_command_shape(self):
        client = MonitorClient.__new__(MonitorClient)
        client._sock = MagicMock()
        client._lock = __import__("threading").Lock()
        with patch.object(client, "_command", return_value={"ok": True}) as cmd:
            assert client.set_repeat_enabled(True, "pcm") is True
        cmd.assert_called_once_with({"type": "set_repeat_enabled", "enabled": True, "codec": "pcm"})

    def test_monitor_client_set_repeat_armed_command_shape(self):
        client = MonitorClient.__new__(MonitorClient)
        client._sock = MagicMock()
        client._lock = __import__("threading").Lock()
        with patch.object(client, "_command", return_value={"ok": True}) as cmd:
            assert client.set_repeat_armed(True) is True
        cmd.assert_called_once_with({"type": "set_repeat_armed", "armed": True})
