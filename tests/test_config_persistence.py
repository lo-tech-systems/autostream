"""Priority 1 — Configuration and state persistence tests.

Covers load_config, load_state, save_config, save_state, parse_config,
mark_configured, unconfigured, is_valid_monitor_device_id, load_and_parse,
read_pin_override, and write_pin_override.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_config as c


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------

class TestLoadConfig:
    def test_missing_file_returns_empty_dict(self, tmp_path):
        assert c.load_config(str(tmp_path / "absent.json")) == {}

    def test_valid_config_returned(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text('{"general": {"log_level": "debug"}}')
        assert c.load_config(str(p)) == {"general": {"log_level": "debug"}}

    def test_non_dict_root_returns_empty_dict(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text("[1, 2, 3]")
        assert c.load_config(str(p)) == {}

    def test_malformed_json_raises_value_error(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text("{bad}")
        with pytest.raises(ValueError):
            c.load_config(str(p))

    def test_permission_error_raises_value_error(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text("{}")
        with patch("builtins.open", side_effect=PermissionError("no")):
            with pytest.raises(ValueError):
                c.load_config(str(p))


# ---------------------------------------------------------------------------
# load_state (largely covered by test_config.py; we add the missing paths)
# ---------------------------------------------------------------------------

class TestLoadStateMalformed:
    def test_malformed_json_raises(self, tmp_path):
        p = tmp_path / "state.json"
        p.write_text("{bad}")
        with pytest.raises(json.JSONDecodeError):
            c.load_state(str(p))


# ---------------------------------------------------------------------------
# save_config / save_state (atomic writes)
# ---------------------------------------------------------------------------

class TestSaveConfig:
    def test_round_trip(self, tmp_path):
        p = tmp_path / "cfg.json"
        data = {"general": {"log_level": "info"}, "extra": 42}
        c.save_config(str(p), data)
        assert c.load_config(str(p)) == data

    def test_preserves_sibling_keys(self, tmp_path):
        p = tmp_path / "cfg.json"
        initial = {"a": 1, "b": 2}
        c.save_config(str(p), initial)
        updated = {"a": 99, "b": 2}
        c.save_config(str(p), updated)
        result = c.load_config(str(p))
        assert result["a"] == 99
        assert result["b"] == 2

    def test_produces_valid_json(self, tmp_path):
        p = tmp_path / "cfg.json"
        c.save_config(str(p), {"x": [1, 2, 3]})
        parsed = json.loads(p.read_text())
        assert parsed == {"x": [1, 2, 3]}

    def test_write_failure_leaves_original_intact(self, tmp_path):
        p = tmp_path / "cfg.json"
        original = {"version": 1}
        c.save_config(str(p), original)
        with patch("autostream_sysutils.os.replace", side_effect=OSError("disk full")):
            with pytest.raises(Exception):
                c.save_config(str(p), {"version": 2})
        # Original must still be readable
        assert c.load_config(str(p)) == original


class TestSaveState:
    def test_round_trip(self, tmp_path):
        p = tmp_path / "state.json"
        data = {"auth": {"pin_override": "9876"}}
        c.save_state(str(p), data)
        assert c.load_state(str(p)) == data

    def test_produces_valid_json_terminated(self, tmp_path):
        p = tmp_path / "state.json"
        c.save_state(str(p), {"k": "v"})
        text = p.read_text()
        parsed = json.loads(text)
        assert parsed == {"k": "v"}


# ---------------------------------------------------------------------------
# parse_config — defaults and normalization
# ---------------------------------------------------------------------------

class TestParseConfigDefaults:
    def test_empty_dict_returns_defaults(self):
        cfg = c.parse_config({})
        assert cfg.general.log_level == "info"
        assert cfg.general.silence_seconds == 30
        assert cfg.general.fifo_path == c.FIFO_PATH
        assert cfg.owntone.base_url == "http://localhost:3689"
        assert cfg.owntone.volume_percent == 20
        assert cfg.audio1.is_turntable is False
        assert cfg.audio1.stylus_life_hours == c.DEFAULT_STYLUS_LIFE_HOURS
        assert cfg.audio2_enabled is False
        assert cfg.updates.auto_update is False
        assert cfg.updates.update_channel == "stable"

    def test_stored_fifo_path_is_ignored(self):
        # The FIFO is a fixed appliance path, so a path carried by an older
        # config must not win: it may point into /tmp, which gets cleaned.
        cfg = c.parse_config({"general": {"fifo_path": "/tmp/autostream-pipes/autostream.fifo"}})
        assert cfg.general.fifo_path == c.FIFO_PATH

    def test_audio1_eq_and_gain_defaults(self):
        cfg = c.parse_config({})
        assert cfg.audio1.gain_db == 0.0
        assert cfg.audio1.eq_40hz_db == 0.0
        assert cfg.audio1.eq_100hz_db == 0.0
        assert cfg.audio1.eq_8khz_db == 0.0

    def test_output_eq_defaults(self):
        cfg = c.parse_config({})
        assert cfg.output_eq.gain_db == 0.0
        assert cfg.output_eq.auto_trim_enabled is False
        for i in range(1, 7):
            assert getattr(cfg.output_eq, f"peq{i}_db") == 0.0

    def test_webui_defaults(self):
        cfg = c.parse_config({})
        assert cfg.webui.show_master_volume is True
        assert cfg.webui.show_input_detail is False
        assert cfg.webui.dark_mode is False
        assert cfg.webui.hidden_outputs == ()
        assert cfg.webui.advertise_appliance is True

    def test_webui_advertise_appliance_explicit_false(self):
        cfg = c.parse_config({"webui": {"advertise_appliance": False}})
        assert cfg.webui.advertise_appliance is False

    def test_webui_advertise_appliance_explicit_true(self):
        cfg = c.parse_config({"webui": {"advertise_appliance": True}})
        assert cfg.webui.advertise_appliance is True

    def test_output_usage_poll_interval_default(self):
        cfg = c.parse_config({})
        assert cfg.webui.output_usage_poll_interval_seconds == 3

    def test_output_usage_poll_interval_explicit_valid(self):
        cfg = c.parse_config({"webui": {"output_usage_poll_interval_seconds": 10}})
        assert cfg.webui.output_usage_poll_interval_seconds == 10

    def test_output_usage_poll_interval_below_min_normalizes(self):
        cfg = c.parse_config({"webui": {"output_usage_poll_interval_seconds": 0}})
        assert cfg.webui.output_usage_poll_interval_seconds == 3

    def test_output_usage_poll_interval_above_max_normalizes(self):
        cfg = c.parse_config({"webui": {"output_usage_poll_interval_seconds": 100}})
        assert cfg.webui.output_usage_poll_interval_seconds == 3

    def test_output_usage_poll_interval_string_invalid_normalizes(self):
        cfg = c.parse_config({"webui": {"output_usage_poll_interval_seconds": "bad"}})
        assert cfg.webui.output_usage_poll_interval_seconds == 3

    def test_output_usage_poll_interval_bool_normalizes(self):
        # bool is a subclass of int; True=1 is within range, should be preserved
        cfg = c.parse_config({"webui": {"output_usage_poll_interval_seconds": True}})
        assert cfg.webui.output_usage_poll_interval_seconds == 1

    def test_output_usage_poll_interval_min_boundary(self):
        cfg = c.parse_config({"webui": {"output_usage_poll_interval_seconds": 1}})
        assert cfg.webui.output_usage_poll_interval_seconds == 1

    def test_output_usage_poll_interval_max_boundary(self):
        cfg = c.parse_config({"webui": {"output_usage_poll_interval_seconds": 30}})
        assert cfg.webui.output_usage_poll_interval_seconds == 30

    def test_update_channel_normalised_to_stable_for_unknown(self):
        cfg = c.parse_config({"updates": {"update_channel": "nightly"}})
        assert cfg.updates.update_channel == "stable"

    def test_update_channel_dev_accepted(self):
        cfg = c.parse_config({"updates": {"update_channel": "dev"}})
        assert cfg.updates.update_channel == "dev"

    def test_log_level_normalised(self):
        cfg = c.parse_config({"general": {"log_level": "DEBUG"}})
        assert cfg.general.log_level == "debug"

    def test_log_level_invalid_falls_back_to_info(self):
        cfg = c.parse_config({"general": {"log_level": "verbose"}})
        assert cfg.general.log_level == "info"


class TestParseConfigAudio:
    def test_audio1_turntable_flag(self):
        cfg = c.parse_config({"audio1": {"turntable": True}})
        assert cfg.audio1.is_turntable is True

    def test_audio2_enabled_flag(self):
        cfg = c.parse_config({"audio2": {"enabled": True, "capture_device": "hw:1,0"}})
        assert cfg.audio2_enabled is True
        assert cfg.audio2.capture_device == "hw:1,0"

    def test_legacy_eq_10khz_fallback(self):
        cfg = c.parse_config({"audio1": {"eq_10khz_db": 3.0}})
        assert cfg.audio1.eq_8khz_db == 3.0

    def test_eq_8khz_takes_precedence_over_legacy(self):
        cfg = c.parse_config({"audio1": {"eq_8khz_db": 1.5, "eq_10khz_db": 9.9}})
        assert cfg.audio1.eq_8khz_db == 1.5

    def test_turntable_without_explicit_threshold_gets_turntable_preset(self):
        cfg = c.parse_config({"audio1": {"turntable": True}})
        assert cfg.audio1.silence_threshold_dbfs == c.TURNTABLE_SILENCE_THRESHOLD_DBFS

    def test_line_level_without_explicit_threshold_gets_line_level_preset(self):
        cfg = c.parse_config({"audio1": {"turntable": False}})
        assert cfg.audio1.silence_threshold_dbfs == c.LINE_LEVEL_SILENCE_THRESHOLD_DBFS

    def test_explicit_threshold_is_not_clobbered_by_derivation(self):
        cfg = c.parse_config({"audio1": {"turntable": True, "silence_threshold": -30.0}})
        assert cfg.audio1.silence_threshold_dbfs == -30.0

    def test_stored_zero_threshold_is_preserved(self):
        cfg = c.parse_config({"audio1": {"turntable": False, "silence_threshold": 0.0}})
        assert cfg.audio1.silence_threshold_dbfs == 0.0


class TestSetInputMode:
    def test_turntable_true_writes_both_keys_and_returns_threshold(self):
        raw = {}
        result = c.set_input_mode(raw, 1, True)
        assert raw["audio1"]["turntable"] is True
        assert raw["audio1"]["silence_threshold"] == c.TURNTABLE_SILENCE_THRESHOLD_DBFS
        assert result == c.TURNTABLE_SILENCE_THRESHOLD_DBFS

    def test_turntable_false_writes_line_level_preset(self):
        raw = {}
        result = c.set_input_mode(raw, 2, False)
        assert raw["audio2"]["turntable"] is False
        assert raw["audio2"]["silence_threshold"] == c.LINE_LEVEL_SILENCE_THRESHOLD_DBFS
        assert result == c.LINE_LEVEL_SILENCE_THRESHOLD_DBFS

    def test_preserves_other_keys_in_section(self):
        raw = {"audio1": {"capture_device": "hw:0,0"}}
        c.set_input_mode(raw, 1, True)
        assert raw["audio1"]["capture_device"] == "hw:0,0"


class TestParseConfigOwntone:
    def test_output_offsets_parsed(self):
        cfg = c.parse_config({"owntone": {"offsets": {"Living Room": 100, "Kitchen": -50}}})
        assert cfg.owntone.output_offsets_ms["Living Room"] == 100
        assert cfg.owntone.output_offsets_ms["Kitchen"] == -50

    def test_output_airplay_modes_normalised(self):
        cfg = c.parse_config({"owntone": {"airplay_modes": {"Bedroom": "AIRPLAY2", "Hall": "bad"}}})
        assert cfg.owntone.output_airplay_modes["Bedroom"] == "airplay2"
        assert cfg.owntone.output_airplay_modes["Hall"] == "default"

    def test_known_outputs_from_state(self):
        state = {"owntone": {"known_outputs": {"abc123": "My Speaker"}}}
        cfg = c.parse_config({}, state=state)
        assert cfg.owntone.known_outputs["abc123"] == "My Speaker"

    def test_non_dict_offsets_silently_ignored(self):
        cfg = c.parse_config({"owntone": {"offsets": "bad"}})
        assert cfg.owntone.output_offsets_ms == {}


# ---------------------------------------------------------------------------
# Config/state separation — PIN in state only
# ---------------------------------------------------------------------------

class TestPinSeparation:
    def test_pin_read_from_state_file(self, tmp_path):
        sp = tmp_path / "state.json"
        sp.write_text('{"auth": {"pin_override": "1234"}}')
        pin, present = c.read_pin_override(str(sp))
        assert present is True
        assert pin == "1234"

    def test_pin_absent_returns_none_false(self, tmp_path):
        sp = tmp_path / "state.json"
        sp.write_text('{}')
        pin, present = c.read_pin_override(str(sp))
        assert present is False
        assert pin is None

    def test_write_pin_override_preserves_other_state_keys(self, tmp_path):
        sp = tmp_path / "state.json"
        sp.write_text('{"other": "value"}')
        c.write_pin_override(str(sp), "5678")
        data = json.loads(sp.read_text())
        assert data["auth"]["pin_override"] == "5678"
        assert data["other"] == "value"

    def test_malformed_state_does_not_mutate_config_dict(self, tmp_path):
        sp = tmp_path / "state.json"
        sp.write_text("[1,2,3]")  # non-object root
        pin, present = c.read_pin_override(str(sp))
        assert present is False


# ---------------------------------------------------------------------------
# is_valid_monitor_device_id
# ---------------------------------------------------------------------------

class TestMonitorDeviceId:
    @pytest.mark.parametrize("dev", [
        "hw:0,0", "hw:1,0", "hw:10,2",
        "hw:CARD=Device,DEV=0",
        "hw:card=MyCard,DEV=1",
    ])
    def test_valid_forms_accepted(self, dev):
        assert c.is_valid_monitor_device_id(dev) is True

    @pytest.mark.parametrize("dev", [
        "", "hw:", "hw:0", "hw:a,b",
        "plughw:0,0", "/dev/snd",
        "hw:0,0;rm -rf /", "hw: 0,0",
    ])
    def test_invalid_forms_rejected(self, dev):
        assert c.is_valid_monitor_device_id(dev) is False

    def test_whitespace_rejected(self):
        assert c.is_valid_monitor_device_id("hw:0, 0") is False


# ---------------------------------------------------------------------------
# mark_configured / unconfigured
# ---------------------------------------------------------------------------

class TestUnconfigured:
    def _minimal_config(self, tmp_path) -> Path:
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps({
            "general": {"fifo_path": "/tmp/autostream.fifo"},
            "audio1": {"capture_device": "hw:0,0"},
            "owntone": {"output_name": "My Speaker"},
        }))
        return p

    def test_missing_file_is_unconfigured(self, tmp_path):
        assert c.unconfigured(str(tmp_path / "absent.json")) is True

    def test_valid_config_is_not_unconfigured(self, tmp_path):
        p = self._minimal_config(tmp_path)
        assert c.unconfigured(str(p)) is False

    def test_missing_output_name_is_unconfigured(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps({
            "general": {"fifo_path": "/tmp/x.fifo"},
            "audio1": {"capture_device": "hw:0,0"},
            "owntone": {},
        }))
        assert c.unconfigured(str(p)) is True

    def test_invalid_capture_device_is_unconfigured(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps({
            "general": {"fifo_path": "/tmp/x.fifo"},
            "audio1": {"capture_device": "default"},
            "owntone": {"output_name": "X"},
        }))
        assert c.unconfigured(str(p)) is True

    def test_mark_configured_overrides_result(self, tmp_path):
        p = self._minimal_config(tmp_path)
        c.mark_configured(str(p))
        assert c.unconfigured(str(p)) is False

    def test_empty_file_is_unconfigured(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text("")
        assert c.unconfigured(str(p)) is True


# ---------------------------------------------------------------------------
# load_and_parse
# ---------------------------------------------------------------------------

class TestLoadAndParse:
    def test_combines_config_and_state(self, tmp_path):
        cp = tmp_path / "cfg.json"
        sp = tmp_path / "state.json"
        cp.write_text(json.dumps({
            "general": {"fifo_path": "/tmp/x.fifo", "log_level": "debug"},
            "owntone": {"base_url": "http://localhost:3689"},
        }))
        sp.write_text(json.dumps({
            "owntone": {"known_outputs": {"abc": "Speaker"}}
        }))
        cfg = c.load_and_parse(str(cp), str(sp))
        assert cfg.general.log_level == "debug"
        assert cfg.owntone.known_outputs["abc"] == "Speaker"

    def test_missing_state_path_is_ignored(self, tmp_path):
        cp = tmp_path / "cfg.json"
        cp.write_text("{}")
        cfg = c.load_and_parse(str(cp))
        assert cfg.owntone.known_outputs == {}

    def test_malformed_config_raises(self, tmp_path):
        cp = tmp_path / "cfg.json"
        cp.write_text("{bad}")
        with pytest.raises(ValueError):
            c.load_and_parse(str(cp))


# ---------------------------------------------------------------------------
# autostream_playback_stats re-exports
# ---------------------------------------------------------------------------

class TestPlaybackStatsReexports:
    def test_reexported_objects_are_the_same_as_config(self):
        import autostream_playback_stats as ps
        assert ps.TURNTABLE_SILENCE_THRESHOLD_DBFS is c.TURNTABLE_SILENCE_THRESHOLD_DBFS
        assert ps.LINE_LEVEL_SILENCE_THRESHOLD_DBFS is c.LINE_LEVEL_SILENCE_THRESHOLD_DBFS
        assert ps.suggested_silence_threshold_dbfs is c.suggested_silence_threshold_dbfs
