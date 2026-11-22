"""tests/test_input3_config.py

Input 3 in the configuration and settings: the input numbers come from one
place, input 3's device is always the Bluetooth loopback, the wired inputs
never hold it, input 3's rows have no device and its enable is the Bluetooth
services switch, and device uniqueness covers the wired inputs only.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_config as config
import autostream_live_config as live_config
from autostream_bluetooth_client import BLUETOOTH_CAPTURE_DEVICE, BLUETOOTH_PLAYBACK_DEVICE
from autostream_config import (
    BLUETOOTH_INPUT_INDEX,
    INPUT_INDICES,
    WIRED_INPUT_INDICES,
    audio_section_name,
    parse_config,
)
from autostream_settings import SettingsStore
from autostream_settings_schema import (
    CrossFieldValidationError,
    cross_validate_capture_device_unique,
    get_field_spec,
)


def _parse(data: dict):
    return parse_config(data, high_perf=False)


class TestInputNumbers:
    def test_one_source_of_truth(self):
        assert INPUT_INDICES == (1, 2, 3)
        assert WIRED_INPUT_INDICES == (1, 2)
        assert BLUETOOTH_INPUT_INDEX == 3
        assert set(WIRED_INPUT_INDICES) | {BLUETOOTH_INPUT_INDEX} == set(INPUT_INDICES)

    @pytest.mark.parametrize("index", INPUT_INDICES)
    def test_section_names(self, index):
        assert audio_section_name(index) == f"audio{index}"


class TestParse:
    def test_input3_defaults_off_with_the_loopback(self):
        cfg = _parse({})
        assert cfg.audio3_enabled is False
        assert cfg.audio3.capture_device == BLUETOOTH_CAPTURE_DEVICE
        assert cfg.audio_enabled(3) is False
        assert cfg.audio_section(3) is cfg.audio3

    def test_input3_device_is_fixed_whatever_the_section_says(self):
        cfg = _parse({"audio3": {"enabled": True, "capture_device": "hw:1,0",
                                 "input_type": "turntable", "gain_db": 2.0}})
        assert cfg.audio3_enabled is True
        assert cfg.audio3.capture_device == BLUETOOTH_CAPTURE_DEVICE
        assert cfg.audio3.input_type == "turntable"
        assert cfg.audio3.gain_db == 2.0

    def test_enabled_defaults_per_input(self):
        cfg = _parse({})
        assert [cfg.audio_enabled(i) for i in INPUT_INDICES] == [True, False, False]

    @pytest.mark.parametrize("section", ["audio1", "audio2"])
    @pytest.mark.parametrize("device", [BLUETOOTH_CAPTURE_DEVICE, BLUETOOTH_PLAYBACK_DEVICE])
    def test_a_wired_loopback_reads_as_no_device_with_one_warning(self, section, device, caplog):
        config._warned_wired_loopback.discard(section)
        with caplog.at_level(logging.WARNING):
            first = _parse({section: {"enabled": True, "capture_device": device}})
            _parse({section: {"enabled": True, "capture_device": device}})
        assert getattr(first, section).capture_device == ""
        warnings = [r for r in caplog.records if section in r.getMessage() and "input 3" in r.getMessage()]
        assert len(warnings) == 1

    def test_a_wired_device_is_kept(self):
        cfg = _parse({"audio1": {"capture_device": "hw:1,0"}, "audio2": {"capture_device": "hw:2,0"}})
        assert cfg.audio_section(1).capture_device == "hw:1,0"
        assert cfg.audio_section(2).capture_device == "hw:2,0"

    @pytest.mark.parametrize("index", [0, 4, "1"])
    def test_an_unknown_input_is_refused(self, index):
        cfg = _parse({})
        with pytest.raises(ValueError):
            cfg.audio_section(index)
        with pytest.raises(ValueError):
            cfg.audio_enabled(index)


class TestSchemaRows:
    _PER_INPUT = ("gain_db", "eq_40hz_db", "eq_100hz_db", "eq_8khz_db", "enabled",
                  "input_type", "silence_threshold", "start_after_ms", "dynamic_rate_matching")

    @pytest.mark.parametrize("index", INPUT_INDICES)
    @pytest.mark.parametrize("key", _PER_INPUT)
    def test_every_input_has_its_rows(self, index, key):
        spec = get_field_spec(f"audio{index}.{key}")
        assert spec is not None
        assert (spec.section, spec.key) == (f"audio{index}", key)

    def test_only_the_wired_inputs_have_a_device(self):
        assert get_field_spec("audio1.capture_device") is not None
        assert get_field_spec("audio2.capture_device") is not None
        assert get_field_spec("audio3.capture_device") is None

    @pytest.mark.parametrize("index", INPUT_INDICES)
    def test_live_effects_are_for_their_own_input(self, index):
        with patch("autostream_monitor_control.set_live_input_gain", return_value=True) as gain, \
                patch.object(live_config, "update_live_start_after_ms", return_value=True) as start:
            get_field_spec(f"audio{index}.gain_db").live_fn(None, 1.5)
            get_field_spec(f"audio{index}.start_after_ms").live_fn(None, 90)
        gain.assert_called_once_with(index, 1.5)
        start.assert_called_once_with(index, 90)

    @pytest.mark.parametrize("value", [BLUETOOTH_CAPTURE_DEVICE, BLUETOOTH_PLAYBACK_DEVICE])
    def test_the_device_validator_refuses_the_loopback(self, value):
        with pytest.raises(ValueError, match="Input 3"):
            get_field_spec("audio1.capture_device").validate(value)


class TestUniqueness:
    def test_the_other_wired_input_is_checked(self):
        raw = {"audio1": {"capture_device": "hw:1,0"}}
        with pytest.raises(CrossFieldValidationError):
            cross_validate_capture_device_unique(raw, "audio2", "capture_device", "hw:1,0")

    def test_the_same_input_is_not_a_conflict(self):
        raw = {"audio1": {"capture_device": "hw:1,0"}}
        cross_validate_capture_device_unique(raw, "audio1", "capture_device", "hw:1,0")

    def test_input3_takes_no_part(self):
        raw = {"audio3": {"capture_device": "hw:1,0"}}
        cross_validate_capture_device_unique(raw, "audio1", "capture_device", "hw:1,0")


class TestInput3EnableIsTheServicesSwitch:
    def _store(self, tmp_path, enabled: bool) -> SettingsStore:
        path = tmp_path / "autostream.json"
        path.write_text('{"audio3": {"enabled": %s}}' % ("true" if enabled else "false"),
                        encoding="utf-8")
        return SettingsStore(str(path), _save_interval_seconds=9999)

    @pytest.mark.parametrize("value,verb", [(True, "enable"), (False, "disable")])
    def test_switches_the_services_then_reloads(self, tmp_path, value, verb):
        store = self._store(tmp_path, not value)
        state = SimpleNamespace(settings=store)
        try:
            with patch.object(live_config, "bt_services_enable", return_value=(True, "ok")) as en, \
                    patch.object(live_config, "bt_services_disable", return_value=(True, "ok")) as dis, \
                    patch.object(live_config, "_debounce_coordinator_reload") as reload, \
                    patch.object(live_config.playback_tracking, "update_playback_input_config") as track:
                outcome = store.set("audio3.enabled", value, state=state)
            assert outcome.live is True
            assert (en if verb == "enable" else dis).call_count == 1
            assert (dis if verb == "enable" else en).call_count == 0
            reload.assert_called_once_with(state)
            assert track.call_args.args[0] == 3
            assert track.call_args.kwargs["is_bluetooth"] is True
            assert store.snapshot().audio3_enabled is value
        finally:
            store.close(save=False)

    def test_a_failed_switch_puts_the_flag_back_and_does_not_reload(self, tmp_path):
        store = self._store(tmp_path, False)
        state = SimpleNamespace(settings=store)
        try:
            with patch.object(live_config, "bt_services_enable", return_value=(False, "no")), \
                    patch.object(live_config, "_debounce_coordinator_reload") as reload:
                outcome = store.set("audio3.enabled", True, state=state)
            assert outcome.live is False
            assert outcome.live_error
            reload.assert_not_called()
            assert store.snapshot().audio3_enabled is False
        finally:
            store.close(save=False)
