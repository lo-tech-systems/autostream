"""Priority 7 — appliance_models unit tests.

Covers build_output_list (filtering, ordering, normalization),
build_equaliser_state (schema, live status, config load failure),
apply_eq_field / apply_eq_reset (validation, clamping, persistence,
live-apply routing), and the federation deadline timeout policy for
build_home_state.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_appliance_models as models


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _out(
    id_: str,
    name: str,
    selected: bool = False,
    volume: int = 50,
    needs_auth_key: bool = False,
    requires_auth: bool = False,
    pin_pending: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=id_, name=name, selected=selected, volume_percent=volume,
        needs_auth_key=needs_auth_key, requires_auth=requires_auth,
        pin_pending=pin_pending,
    )


def _parsed(
    output_name: str = "",
    hidden_outputs: list | None = None,
    show_master_volume: bool = True,
    show_input_detail: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        owntone=SimpleNamespace(
            output_name=output_name,
            output_offsets_ms={},
            output_airplay_modes={},
            base_url="http://localhost:3689",
        ),
        webui=SimpleNamespace(
            hidden_outputs=hidden_outputs or [],
            show_master_volume=show_master_volume,
            show_input_detail=show_input_detail,
            advertise_appliance=True,
        ),
        output_eq=SimpleNamespace(
            gain_db=0.0,
            auto_trim_enabled=False,
            peq1_db=0.0,
            peq2_db=0.0,
            peq3_db=0.0,
            peq4_db=0.0,
            peq5_db=0.0,
            peq6_db=0.0,
        ),
    )


def _minimal_cfg():
    return {
        "general": {"silence_seconds": 30},
        "owntone": {"base_url": "http://localhost:3689"},
        "audio1": {
            "capture_device": "hw:0,0",
            "silence_threshold": -66,
            "turntable": False,
            "stylus_life_hours": 500,
            "belt_life_hours": 0,
            "bearing_life_hours": 0,
            "belt_life_years": 0,
            "bearing_life_years": 0,
            "gain_db": 0,
            "eq_40hz_db": 0,
            "eq_100hz_db": 0,
            "eq_8khz_db": 0,
        },
        "audio2": {
            "capture_device": "hw:1,0",
            "silence_threshold": -66,
            "turntable": False,
            "stylus_life_hours": 250,
            "belt_life_hours": 0,
            "bearing_life_hours": 0,
            "belt_life_years": 0,
            "bearing_life_years": 0,
            "gain_db": 0,
            "eq_40hz_db": 0,
            "eq_100hz_db": 0,
            "eq_8khz_db": 0,
        },
        "output_eq": {
            "gain_db": 0.0,
            "peq1_db": 0.0, "peq2_db": 0.0, "peq3_db": 0.0,
            "peq4_db": 0.0, "peq5_db": 0.0, "peq6_db": 0.0,
            "auto_trim_enabled": False,
        },
    }


def _make_config_file(tmp_path: Path, extra: dict | None = None) -> Path:
    cfg = _minimal_cfg()
    if extra:
        _deep_update(cfg, extra)
    p = tmp_path / "autostream.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    return p


def _deep_update(d: dict, u: dict) -> dict:
    for k, v in u.items():
        if isinstance(v, dict) and isinstance(d.get(k), dict):
            _deep_update(d[k], v)
        else:
            d[k] = v
    return d


# ---------------------------------------------------------------------------
# build_output_list — filtering and ordering
# ---------------------------------------------------------------------------

class TestBuildOutputList:
    def test_empty_owntone_outputs_returns_empty(self):
        assert models.build_output_list(_parsed(), []) == []

    def test_output_without_id_or_name_excluded(self):
        raw = [_out("", ""), _out("1", ""), _out("", "AirPlay")]
        result = models.build_output_list(_parsed(), raw)
        assert result == []

    def test_all_valid_outputs_included(self):
        raw = [_out("1", "Bedroom"), _out("2", "Kitchen")]
        result = models.build_output_list(_parsed(), raw)
        assert len(result) == 2

    def test_hidden_unselected_non_default_excluded(self):
        raw = [_out("1", "Bedroom"), _out("2", "Kitchen")]
        result = models.build_output_list(_parsed(hidden_outputs=["Bedroom"]), raw)
        assert len(result) == 1
        assert result[0]["name"] == "Kitchen"

    def test_hidden_but_selected_still_included(self):
        raw = [_out("1", "Bedroom", selected=True), _out("2", "Kitchen")]
        result = models.build_output_list(_parsed(hidden_outputs=["Bedroom"]), raw)
        assert any(o["name"] == "Bedroom" for o in result)

    def test_hidden_case_insensitive(self):
        raw = [_out("1", "Bedroom"), _out("2", "Kitchen")]
        result = models.build_output_list(_parsed(hidden_outputs=["BEDROOM"]), raw)
        assert all(o["name"] != "Bedroom" for o in result)

    def test_default_output_sorted_first(self):
        raw = [_out("2", "Zulu"), _out("1", "Alpha"), _out("3", "Garden")]
        result = models.build_output_list(_parsed(output_name="Zulu"), raw)
        assert result[0]["name"] == "Zulu"
        assert result[0]["is_default"] is True

    def test_non_default_alphabetical_after_default(self):
        raw = [_out("3", "Zulu"), _out("1", "Charlie"), _out("2", "Alpha")]
        result = models.build_output_list(_parsed(output_name="Zulu"), raw)
        assert result[0]["name"] == "Zulu"
        assert [o["name"] for o in result[1:]] == ["Alpha", "Charlie"]

    def test_volume_clamped_to_0_100(self):
        raw = [_out("1", "A", volume=200), _out("2", "B", volume=-5)]
        result = models.build_output_list(_parsed(), raw)
        assert result[0]["volume"] == 100
        assert result[1]["volume"] == 0

    def test_result_dict_has_required_keys(self):
        raw = [_out("1", "Room")]
        result = models.build_output_list(_parsed(), raw)
        assert set(result[0].keys()) == {
            "id", "name", "selected", "volume", "is_default",
            "needs_auth_key", "requires_auth", "pin_pending", "pin_claim",
        }

    def test_selected_flag_preserved(self):
        raw = [_out("1", "Room", selected=True)]
        result = models.build_output_list(_parsed(), raw)
        assert result[0]["selected"] is True

    def test_needs_auth_key_true_passed_through(self):
        raw = [_out("1", "Apple TV", needs_auth_key=True, requires_auth=True, pin_pending=True)]
        result = models.build_output_list(_parsed(), raw)
        assert result[0]["needs_auth_key"] is True
        assert result[0]["requires_auth"] is True
        assert result[0]["pin_pending"] is True

    def test_needs_auth_key_false_passed_through(self):
        raw = [_out("1", "Room")]
        result = models.build_output_list(_parsed(), raw)
        assert result[0]["needs_auth_key"] is False
        assert result[0]["requires_auth"] is False
        assert result[0]["pin_pending"] is False


# ---------------------------------------------------------------------------
# build_equaliser_state — schema and live status
# ---------------------------------------------------------------------------

class TestBuildEqualizerState:
    def test_ok_true_on_valid_config(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_appliance_models.get_live_output_eq_status", return_value=None):
            result = models.build_equaliser_state(str(cfg_path))
        assert result["ok"] is True

    def test_required_keys_present(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_appliance_models.get_live_output_eq_status", return_value=None):
            result = models.build_equaliser_state(str(cfg_path))
        for field in ("gain_db", "auto_trim_enabled", "peq1_db", "peq2_db",
                      "peq3_db", "peq4_db", "peq5_db", "peq6_db"):
            assert field in result, f"Missing key: {field}"

    def test_config_values_returned(self, tmp_path):
        cfg_path = _make_config_file(tmp_path, {"output_eq": {"gain_db": 3.5, "peq2_db": -1.0}})
        with patch("autostream_appliance_models.get_live_output_eq_status", return_value=None):
            result = models.build_equaliser_state(str(cfg_path))
        assert result["gain_db"] == pytest.approx(3.5)
        assert result["peq2_db"] == pytest.approx(-1.0)

    def test_live_status_merged_when_available(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        live = {"output_auto_trim_enabled": True, "output_auto_trim_db": -1.2}
        with patch("autostream_appliance_models.get_live_output_eq_status", return_value=live):
            result = models.build_equaliser_state(str(cfg_path))
        assert result.get("output_auto_trim_enabled") is True
        assert result.get("output_auto_trim_db") == pytest.approx(-1.2)

    def test_config_load_exception_returns_ok_false(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_appliance_models.locked_load_config",
                   side_effect=OSError("read error")), \
             patch("autostream_appliance_models.get_live_output_eq_status", return_value=None):
            result = models.build_equaliser_state(str(cfg_path))
        assert result["ok"] is False
        assert "error" in result


# ---------------------------------------------------------------------------
# apply_eq_field — validation, clamping, persistence, routing
# ---------------------------------------------------------------------------

class TestApplyEqField:
    def test_unknown_field_raises_value_error(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with pytest.raises(ValueError, match="Unknown field"):
            models.apply_eq_field(str(cfg_path), "no_such_field", "1.0")

    def test_non_numeric_db_raises_value_error(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with pytest.raises(ValueError, match="numeric"):
            models.apply_eq_field(str(cfg_path), "gain_db", "abc")

    def test_gain_clamped_to_max(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_appliance_models.set_live_output_gain"), \
             patch("autostream_appliance_models.save_config"):
            ok, norm, err = models.apply_eq_field(str(cfg_path), "gain_db", "99")
        assert ok is True
        assert float(norm) <= 12.0

    def test_gain_clamped_to_min(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_appliance_models.set_live_output_gain"), \
             patch("autostream_appliance_models.save_config"):
            ok, norm, err = models.apply_eq_field(str(cfg_path), "gain_db", "-99")
        assert float(norm) >= -12.0

    def test_gain_change_calls_set_live_output_gain(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        gain_calls = []
        with patch("autostream_appliance_models.set_live_output_gain",
                   side_effect=lambda v: gain_calls.append(v)), \
             patch("autostream_appliance_models.save_config"):
            models.apply_eq_field(str(cfg_path), "gain_db", "2.5")
        assert gain_calls == [pytest.approx(2.5)]

    def test_peq_change_calls_set_live_output_eq(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        eq_calls = []
        with patch("autostream_appliance_models.set_live_output_eq",
                   side_effect=lambda *a: eq_calls.append(a)), \
             patch("autostream_appliance_models.save_config"):
            models.apply_eq_field(str(cfg_path), "peq3_db", "4.0")
        assert eq_calls, "set_live_output_eq must be called"
        assert len(eq_calls[0]) == 6

    def test_peq_change_does_not_call_set_live_output_gain(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        gain_calls = []
        with patch("autostream_appliance_models.set_live_output_gain",
                   side_effect=lambda v: gain_calls.append(v)), \
             patch("autostream_appliance_models.set_live_output_eq"), \
             patch("autostream_appliance_models.save_config"):
            models.apply_eq_field(str(cfg_path), "peq1_db", "1.0")
        assert not gain_calls

    def test_auto_trim_true_string_parsed(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_appliance_models.set_live_output_auto_trim"), \
             patch("autostream_appliance_models.save_config"):
            ok, norm, err = models.apply_eq_field(str(cfg_path), "auto_trim_enabled", "true")
        assert ok is True
        assert norm == "true"

    def test_auto_trim_false_string_parsed(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_appliance_models.set_live_output_auto_trim"), \
             patch("autostream_appliance_models.save_config"):
            ok, norm, err = models.apply_eq_field(str(cfg_path), "auto_trim_enabled", "0")
        assert norm == "false"

    def test_save_failure_returns_ok_false(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_appliance_models.set_live_output_gain"), \
             patch("autostream_appliance_models.save_config",
                   side_effect=OSError("disk full")):
            ok, norm, err = models.apply_eq_field(str(cfg_path), "gain_db", "1.0")
        assert ok is False
        assert err


# ---------------------------------------------------------------------------
# apply_eq_reset
# ---------------------------------------------------------------------------

class TestApplyEqReset:
    def test_ok_true_on_success(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_appliance_models.set_live_output_gain"), \
             patch("autostream_appliance_models.set_live_output_eq"):
            ok, err = models.apply_eq_reset(str(cfg_path))
        assert ok is True
        assert err == ""

    def test_all_db_fields_zeroed_in_file(self, tmp_path):
        cfg_path = _make_config_file(tmp_path, {
            "output_eq": {"gain_db": 5.0, "peq1_db": 3.0, "peq6_db": -2.0}
        })
        with patch("autostream_appliance_models.set_live_output_gain"), \
             patch("autostream_appliance_models.set_live_output_eq"):
            models.apply_eq_reset(str(cfg_path))
        saved = json.loads(cfg_path.read_text())
        for f in ("peq1_db", "peq2_db", "peq3_db", "peq4_db", "peq5_db", "peq6_db"):
            assert saved["output_eq"][f] == 0.0, f"{f} not zeroed"
        assert saved["output_eq"]["gain_db"] == 5.0, "gain_db must not be changed by Flat reset"

    def test_reset_does_not_call_set_live_output_gain(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        gain_calls = []
        with patch("autostream_appliance_models.set_live_output_gain",
                   side_effect=lambda v: gain_calls.append(v)), \
             patch("autostream_appliance_models.set_live_output_eq"):
            models.apply_eq_reset(str(cfg_path))
        assert gain_calls == [], "set_live_output_gain must not be called by Flat reset"

    def test_reset_calls_set_live_output_eq_all_zeros(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        eq_calls = []
        with patch("autostream_appliance_models.set_live_output_gain"), \
             patch("autostream_appliance_models.set_live_output_eq",
                   side_effect=lambda *a: eq_calls.append(a)):
            models.apply_eq_reset(str(cfg_path))
        assert eq_calls and all(v == 0.0 for v in eq_calls[0])

    def test_save_failure_returns_ok_false(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_appliance_models.save_config",
                   side_effect=OSError("disk full")):
            ok, err = models.apply_eq_reset(str(cfg_path))
        assert ok is False
        assert err


# ---------------------------------------------------------------------------
# build_home_state — local mode
# ---------------------------------------------------------------------------

class TestBuildHomeStateLocal:
    def _patch_home(self, cfg_path, *, outputs=None, vu_ms=100):
        buf_result = MagicMock(ok=True, value=str(vu_ms))
        out_result = MagicMock(ok=True, outputs=outputs or [])
        playback = MagicMock()
        playback.to_public_dict.return_value = {}
        playback.stylus_banner_text = ""
        playback.belt_banner_text = ""
        playback.bearing_banner_text = ""
        return (
            patch("autostream_appliance_models.get_setting", return_value=buf_result),
            patch("autostream_appliance_models.list_outputs", return_value=out_result),
            patch("autostream_appliance_models.get_monitor_levels_dbfs", return_value=[]),
            patch("autostream_appliance_models.get_playback_snapshot", return_value=playback),
            patch("autostream_appliance_models.get_appliance_id", return_value="aabbccdd1122"),
            patch("autostream_appliance_models.get_system_hostname", return_value="test-host"),
            patch("autostream_appliance_models.get_app_version", return_value="2.0.0"),
        )

    def test_ok_true_returned(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        patches = self._patch_home(cfg_path)
        with patches[0], patches[1], patches[2], patches[3], \
             patches[4], patches[5], patches[6]:
            result = models.build_home_state(str(cfg_path))
        assert result["ok"] is True

    def test_required_keys_present(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        patches = self._patch_home(cfg_path)
        with patches[0], patches[1], patches[2], patches[3], \
             patches[4], patches[5], patches[6]:
            result = models.build_home_state(str(cfg_path))
        for key in ("appliance", "preferences", "playback", "input_levels",
                    "warnings", "outputs", "vu_delay_ms"):
            assert key in result, f"Missing key: {key}"

    def test_warnings_carry_the_sample_rate_banner_text(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        patches = self._patch_home(cfg_path)
        with patches[0], patches[1], patches[2], patches[3], \
             patches[4], patches[5], patches[6], \
             patch("autostream_appliance_models.sample_rate_warning_text",
                   return_value="banner text"):
            result = models.build_home_state(str(cfg_path))
        assert result["warnings"]["sample_rate"] == "banner text"

    def test_sample_rate_warning_is_empty_with_no_mismatch(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        patches = self._patch_home(cfg_path)
        with patches[0], patches[1], patches[2], patches[3], \
             patches[4], patches[5], patches[6]:
            result = models.build_home_state(str(cfg_path))
        assert result["warnings"]["sample_rate"] == ""

    def test_failure_path_has_an_empty_sample_rate_warning(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_appliance_models.locked_load_config",
                   side_effect=OSError("read error")), \
             patch("autostream_appliance_models.get_appliance_id", return_value=""), \
             patch("autostream_appliance_models.get_system_hostname", return_value=""), \
             patch("autostream_appliance_models.get_app_version", return_value=""):
            result = models.build_home_state(str(cfg_path))
        assert result["warnings"]["sample_rate"] == ""

    def test_vu_delay_ms_from_owntone_setting(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        patches = self._patch_home(cfg_path, vu_ms=350)
        with patches[0], patches[1], patches[2], patches[3], \
             patches[4], patches[5], patches[6]:
            result = models.build_home_state(str(cfg_path))
        assert result["vu_delay_ms"] == 350

    def test_appliance_info_shape(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        patches = self._patch_home(cfg_path)
        with patches[0], patches[1], patches[2], patches[3], \
             patches[4], patches[5], patches[6]:
            result = models.build_home_state(str(cfg_path))
        app = result["appliance"]
        assert "id" in app and "hostname" in app and "version" in app
        assert app["hostname"] == "test-host"
        assert app["version"] == "2.0.0"

    def test_hostname_local_suffix_stripped(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        patches = self._patch_home(cfg_path)
        with patches[0], patches[1], patches[2], patches[3], \
             patches[4], patches[5], \
             patch("autostream_appliance_models.get_app_version", return_value="1.0"):
            with patch("autostream_appliance_models.get_system_hostname",
                       return_value="mybox.local"):
                result = models.build_home_state(str(cfg_path))
        assert result["appliance"]["hostname"] == "mybox"

    def test_config_load_failure_returns_ok_false(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_appliance_models.locked_load_config",
                   side_effect=OSError("read error")), \
             patch("autostream_appliance_models.get_appliance_id", return_value=""), \
             patch("autostream_appliance_models.get_system_hostname", return_value=""), \
             patch("autostream_appliance_models.get_app_version", return_value=""):
            result = models.build_home_state(str(cfg_path))
        assert result["ok"] is False

    def test_session_key_always_present(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        patches = self._patch_home(cfg_path)
        session = {"active": True, "source": "replay"}
        with patches[0], patches[1], patches[2], patches[3], \
             patches[4], patches[5], patches[6], \
             patch("autostream_appliance_models.get_session_state", return_value=session), \
             patch("autostream_appliance_models.get_repeat_status", return_value=None):
            result = models.build_home_state(str(cfg_path))
        assert result["session"] == session

    def test_repeat_key_present_when_daemon_reports_it(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        patches = self._patch_home(cfg_path)
        repeat_block = {"enabled": True, "armed": False}
        with patches[0], patches[1], patches[2], patches[3], \
             patches[4], patches[5], patches[6], \
             patch("autostream_appliance_models.get_session_state",
                   return_value={"active": False, "source": None}), \
             patch("autostream_appliance_models.get_repeat_status", return_value=repeat_block):
            result = models.build_home_state(str(cfg_path))
        assert result["repeat"] == repeat_block

    def test_repeat_requested_minutes_survives_passthrough(self, tmp_path):
        """requested_minutes (the requested-vs-delivered honesty surface)
        is a new daemon-side field with no local whitelist to update --
        the repeat block is passed through verbatim, so it must survive
        untouched like any other repeat key."""
        cfg_path = _make_config_file(tmp_path)
        patches = self._patch_home(cfg_path)
        repeat_block = {
            "enabled": True, "armed": False,
            "requested_minutes": 80, "max_recording_seconds": 3120,
        }
        with patches[0], patches[1], patches[2], patches[3], \
             patches[4], patches[5], patches[6], \
             patch("autostream_appliance_models.get_session_state",
                   return_value={"active": False, "source": None}), \
             patch("autostream_appliance_models.get_repeat_status", return_value=repeat_block):
            result = models.build_home_state(str(cfg_path))
        assert result["repeat"]["requested_minutes"] == 80
        assert result["repeat"] == repeat_block

    def test_repeat_key_absent_when_daemon_never_reported(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        patches = self._patch_home(cfg_path)
        with patches[0], patches[1], patches[2], patches[3], \
             patches[4], patches[5], patches[6], \
             patch("autostream_appliance_models.get_session_state",
                   return_value={"active": False, "source": None}), \
             patch("autostream_appliance_models.get_repeat_status", return_value=None):
            result = models.build_home_state(str(cfg_path))
        assert "repeat" not in result

    def test_session_falls_back_to_any_monitor_capturing_on_exception(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        patches = self._patch_home(cfg_path)
        with patches[0], patches[1], patches[2], patches[3], \
             patches[4], patches[5], patches[6], \
             patch("autostream_appliance_models.get_session_state",
                   side_effect=RuntimeError("cache unavailable")), \
             patch("autostream_appliance_models.any_monitor_capturing", return_value=True):
            result = models.build_home_state(str(cfg_path))
        assert result["session"] == {"active": True, "source": None}

    def test_config_load_failure_still_includes_session_key(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_appliance_models.locked_load_config",
                   side_effect=OSError("read error")), \
             patch("autostream_appliance_models.get_appliance_id", return_value=""), \
             patch("autostream_appliance_models.get_system_hostname", return_value=""), \
             patch("autostream_appliance_models.get_app_version", return_value=""), \
             patch("autostream_appliance_models.get_session_state",
                   return_value={"active": False, "source": None}):
            result = models.build_home_state(str(cfg_path))
        assert "session" in result


# ---------------------------------------------------------------------------
# build_home_state — federation deadline mode
# ---------------------------------------------------------------------------

class TestBuildHomeStateFederation:
    def test_federation_completes_within_budget(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        buf_result = MagicMock(ok=True, value="100")
        out_result = MagicMock(ok=True, outputs=[])
        playback = MagicMock()
        playback.to_public_dict.return_value = {}
        playback.stylus_banner_text = ""
        playback.belt_banner_text = ""
        playback.bearing_banner_text = ""
        deadline = time.monotonic() + 5.0

        with patch("autostream_appliance_models.get_setting", return_value=buf_result), \
             patch("autostream_appliance_models.list_outputs", return_value=out_result), \
             patch("autostream_appliance_models.get_monitor_levels_dbfs", return_value=[]), \
             patch("autostream_appliance_models.get_playback_snapshot", return_value=playback), \
             patch("autostream_appliance_models.get_appliance_id", return_value=""), \
             patch("autostream_appliance_models.get_system_hostname", return_value=""), \
             patch("autostream_appliance_models.get_app_version", return_value=""):
            result = models.build_home_state(str(cfg_path), deadline=deadline)

        assert result["ok"] is True
        assert time.monotonic() < deadline

    def test_expired_deadline_returns_ok_true_with_defaults(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        playback = MagicMock()
        playback.to_public_dict.return_value = {}
        playback.stylus_banner_text = ""
        playback.belt_banner_text = ""
        playback.bearing_banner_text = ""
        deadline = time.monotonic() - 1.0  # already expired

        with patch("autostream_appliance_models.get_monitor_levels_dbfs", return_value=[]), \
             patch("autostream_appliance_models.get_playback_snapshot", return_value=playback), \
             patch("autostream_appliance_models.get_appliance_id", return_value=""), \
             patch("autostream_appliance_models.get_system_hostname", return_value=""), \
             patch("autostream_appliance_models.get_app_version", return_value=""):
            result = models.build_home_state(str(cfg_path), deadline=deadline)

        assert result["ok"] is True
        assert result["outputs"] == []


# ---------------------------------------------------------------------------
# build_home_state — remote occupancy annotation
# ---------------------------------------------------------------------------

class TestBuildHomeStateAnnotation:
    """Tests that build_home_state annotates outputs with remote_in_use fields."""

    def _patch_home_with_outputs(self, cfg_path, owntone_outputs, *, usage_snapshot=None):
        """Returns context manager that patches all required dependencies."""
        from types import SimpleNamespace
        from unittest.mock import MagicMock, patch
        import autostream_output_usage as ou

        buf_result = MagicMock(ok=True, value="100")
        out_result = MagicMock(ok=True, outputs=owntone_outputs)
        playback = MagicMock()
        playback.to_public_dict.return_value = {}
        playback.stylus_banner_text = ""
        playback.belt_banner_text = ""
        playback.bearing_banner_text = ""

        # Build an annotate_outputs based on a fake snapshot.
        snapshot = usage_snapshot or {}

        def _fake_annotate(outputs):
            result = []
            for out in outputs:
                out = dict(out)
                key = out.get("name", "").lower()
                usage = snapshot.get(key)
                locally_selected = bool(out.get("selected"))
                if usage and not locally_selected:
                    out["remote_in_use"] = True
                    out["remote_owner"] = usage.owner_name
                    out["remote_owner_service"] = usage.service_name
                else:
                    out["remote_in_use"] = False
                    out["remote_owner"] = ""
                    out["remote_owner_service"] = ""
                result.append(out)
            return result

        from contextlib import contextmanager

        @contextmanager
        def _ctx():
            with patch("autostream_appliance_models.get_setting", return_value=buf_result), \
                 patch("autostream_appliance_models.list_outputs", return_value=out_result), \
                 patch("autostream_appliance_models.get_monitor_levels_dbfs", return_value=[]), \
                 patch("autostream_appliance_models.get_playback_snapshot", return_value=playback), \
                 patch("autostream_appliance_models.get_appliance_id", return_value=""), \
                 patch("autostream_appliance_models.get_system_hostname", return_value="host"), \
                 patch("autostream_appliance_models.get_app_version", return_value="1.0"), \
                 patch("autostream_output_usage.get_usage_snapshot", return_value=snapshot), \
                 patch("autostream_output_usage.annotate_outputs", side_effect=_fake_annotate):
                yield

        return _ctx()

    def _make_out(self, id_, name, selected=False):
        return SimpleNamespace(
            id=id_, name=name, selected=selected, volume_percent=50,
            needs_auth_key=False, requires_auth=False, pin_pending=False,
        )

    def test_unselected_occupied_output_marked_remote_in_use(self, tmp_path):
        from unittest.mock import MagicMock
        import autostream_output_usage as ou

        cfg_path = _make_config_file(tmp_path)
        kitchen_usage = MagicMock()
        kitchen_usage.owner_name = "living-room"
        kitchen_usage.service_name = "living-room"
        snapshot = {"kitchen": kitchen_usage}

        outputs = [self._make_out("1", "Kitchen", selected=False)]
        with self._patch_home_with_outputs(cfg_path, outputs, usage_snapshot=snapshot):
            result = models.build_home_state(str(cfg_path))

        assert result["ok"] is True
        out_dict = result["outputs"][0]
        assert out_dict["remote_in_use"] is True
        assert out_dict["remote_owner"] == "living-room"

    def test_locally_selected_output_not_marked_remote_in_use(self, tmp_path):
        from unittest.mock import MagicMock
        import autostream_output_usage as ou

        cfg_path = _make_config_file(tmp_path)
        kitchen_usage = MagicMock()
        kitchen_usage.owner_name = "living-room"
        kitchen_usage.service_name = "living-room"
        snapshot = {"kitchen": kitchen_usage}

        outputs = [self._make_out("1", "Kitchen", selected=True)]
        with self._patch_home_with_outputs(cfg_path, outputs, usage_snapshot=snapshot):
            result = models.build_home_state(str(cfg_path))

        out_dict = result["outputs"][0]
        assert out_dict["remote_in_use"] is False

    def test_unoccupied_output_has_false_fields(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        outputs = [self._make_out("1", "Bedroom", selected=False)]
        with self._patch_home_with_outputs(cfg_path, outputs, usage_snapshot={}):
            result = models.build_home_state(str(cfg_path))

        out_dict = result["outputs"][0]
        assert out_dict["remote_in_use"] is False
        assert out_dict["remote_owner"] == ""
        assert out_dict["remote_owner_service"] == ""

    def test_sorting_preserved_default_first(self, tmp_path):
        cfg_path = _make_config_file(tmp_path,
                                     extra={"owntone": {"output_name": "Zulu"}})
        outputs = [
            self._make_out("3", "Zulu"),
            self._make_out("1", "Alpha"),
            self._make_out("2", "Mango"),
        ]
        with self._patch_home_with_outputs(cfg_path, outputs, usage_snapshot={}):
            result = models.build_home_state(str(cfg_path))

        names = [o["name"] for o in result["outputs"]]
        assert names[0] == "Zulu"
        assert names[1:] == sorted(names[1:])

    def test_annotate_outputs_not_called_with_refresh(self, tmp_path):
        """annotate_outputs must be cache-only — no refresh_now call."""
        cfg_path = _make_config_file(tmp_path)
        import autostream_output_usage as ou
        refresh_calls = []
        orig_refresh = ou.refresh_now
        ou.refresh_now = lambda *a, **kw: refresh_calls.append(True)
        try:
            outputs = [self._make_out("1", "Kitchen")]
            with self._patch_home_with_outputs(cfg_path, outputs, usage_snapshot={}):
                models.build_home_state(str(cfg_path))
        finally:
            ou.refresh_now = orig_refresh
        assert not refresh_calls, "build_home_state must not trigger refresh_now"


# ---------------------------------------------------------------------------
# PIN pairing: sanitiser rule, claim in the list, combined pin-and-enable
# ---------------------------------------------------------------------------

import logging as _logging

import autostream_pin_pairing as _pairing


def _result(ok: bool, error_code: str = "", message: str = ""):
    return SimpleNamespace(ok=ok, error_code=error_code, message=message)


_BAD_PINS = [
    "123", "123456789", "12a4", "１２３４", " 1234", "1234\n",
    "", "1234 ", "-123", None, 1234, 12.5, ["1", "2", "3", "4"], {"a": 1}, True,
]


class TestSanitizePin:
    def test_sanitize_pin_accepts_digits_and_rejects_everything_else(self):
        for pin in ("1234", "0000", "12345678"):
            assert models.sanitize_output_body({"id": "1", "op": "pin", "pin": pin}) == (
                {"id": "1", "op": "pin", "pin": pin}, None)
        for pin in _BAD_PINS:
            assert models.sanitize_output_body(
                {"id": "1", "op": "pin", "pin": pin}) == (None, "invalid_request_body"), repr(pin)
        assert models.sanitize_output_body({"id": "1", "op": "pin"}) == (
            None, "invalid_request_body")

    def test_sanitize_pin_keeps_selected_and_volume_when_given(self):
        assert models.sanitize_output_body(
            {"id": "1", "op": "pin", "pin": "1234", "selected": True, "volume": 30, "x": 1},
        ) == ({"id": "1", "op": "pin", "pin": "1234", "selected": True, "volume": 30}, None)
        s, err = models.sanitize_output_body(
            {"id": "1", "op": "pin", "pin": "1234", "selected": True, "volume": 500})
        assert err is None and s["volume"] == 100
        s, _ = models.sanitize_output_body(
            {"id": "1", "op": "pin", "pin": "1234", "selected": True, "volume": "x"})
        assert s["volume"] == 50
        s, _ = models.sanitize_output_body(
            {"id": "1", "op": "pin", "pin": "1234", "selected": True})
        assert s["volume"] == 50
        s, _ = models.sanitize_output_body({"id": "1", "op": "pin", "pin": "1234"})
        assert "selected" not in s and "volume" not in s

    def test_sanitize_pin_rejects_a_non_bool_selected(self):
        for sel in ("true", 1, 0, None, []):
            assert models.sanitize_output_body(
                {"id": "1", "op": "pin", "pin": "1234", "selected": sel},
            ) == (None, "invalid_request_body"), repr(sel)

    def test_sanitize_plain_shape_is_unchanged(self):
        assert models.sanitize_output_body({"id": " 7 ", "selected": True, "volume": 20}) == (
            {"id": "7", "selected": True, "volume": 20}, None)
        assert models.sanitize_output_body({"id": "7", "selected": False}) == (
            {"id": "7", "selected": False, "volume": 50}, None)
        assert models.sanitize_output_body({"id": "7", "selected": True, "volume": 999}) == (
            {"id": "7", "selected": True, "volume": 100}, None)
        assert models.sanitize_output_body({"id": "7", "selected": "yes"}) == (
            None, "invalid_request_body")
        assert models.sanitize_output_body({"id": "", "selected": True}) == (
            None, "missing_output_id")
        assert models.sanitize_output_body({"id": "7", "op": "weird"}) == (
            None, "invalid_request_body")


class TestPinClaimInList:
    def test_output_list_rows_carry_the_pairing_claim(self):
        clock = SimpleNamespace(t=100.0)
        fresh = _pairing.PairingState(clock=lambda: clock.t)
        fresh.claim("1", "dial:abc")
        with patch.object(_pairing, "STATE", fresh):
            rows = models.build_output_list(
                _parsed(), [_out("1", "Bedroom"), _out("2", "Kitchen")])
        by_id = {r["id"]: r for r in rows}
        assert by_id["1"]["pin_claim"] == "dial:abc"
        assert by_id["2"]["pin_claim"] == ""


class TestPinMutation:
    _BASE = "http://x"

    def _run(self, body, *, requester=None, pin_result=None, update_result=None):
        with patch("autostream_appliance_models.submit_output_pin",
                   return_value=pin_result or _result(True)) as pin_mock, \
             patch("autostream_appliance_models.update_output",
                   return_value=update_result or _result(True)) as upd_mock, \
             patch("autostream_appliance_models._resolve_output_info",
                   return_value=("Speaker", False)), \
             patch("autostream_appliance_models._update_cached_selected"), \
             patch("autostream_appliance_models.request_nowplaying_republish"), \
             patch("autostream_appliance_models.clear_user_silence_latch"), \
             patch("autostream_appliance_models.note_user_output_action"):
            res = models.apply_output_mutation(
                self._BASE, body.get("id", "o1"), body, initiated_by="user",
                requester=requester)
        return res, pin_mock, upd_mock

    def test_pin_required_records_the_claim_for_a_requester_and_not_for_none(self):
        need = _result(False, "pin_required", "needs pin")
        res, _, _ = self._run({"id": "o1", "selected": True}, requester="dial:a",
                              update_result=need)
        assert res["pin_required"] is True
        assert _pairing.holder("o1") == "dial:a"
        res, _, _ = self._run({"id": "o2", "selected": True}, requester=None,
                              update_result=need)
        assert res["pin_required"] is True
        assert _pairing.holder("o2") == ""

    def test_a_good_pin_releases_the_claim(self):
        _pairing.claim("o1", "webui")
        res, _, _ = self._run({"id": "o1", "op": "pin", "pin": "1234"}, requester="webui")
        assert res == {"ok": True, "id": "o1"}
        assert _pairing.holder("o1") == ""

    def test_a_wrong_pin_keeps_the_claim(self):
        _pairing.claim("o1", "webui")
        res, _, _ = self._run({"id": "o1", "op": "pin", "pin": "1234"}, requester="webui",
                              pin_result=_result(False, "pin_invalid", "Wrong PIN"))
        assert res["pin_invalid"] is True
        assert _pairing.holder("o1") == "webui"

    def test_pin_then_selected_enables_in_the_same_call(self):
        res, pin_mock, upd_mock = self._run(
            {"id": "o1", "op": "pin", "pin": "1234", "selected": True, "volume": 35},
            requester="dial:a")
        assert res == {"ok": True, "id": "o1"}
        pin_mock.assert_called_once()
        upd_mock.assert_called_once()
        assert upd_mock.call_args.kwargs["enabled"] is True
        assert upd_mock.call_args.kwargs["volume_percent"] == 35

    def test_a_wrong_pin_does_not_enable(self):
        res, _, upd_mock = self._run(
            {"id": "o1", "op": "pin", "pin": "1234", "selected": True},
            pin_result=_result(False, "pin_invalid", "Wrong PIN"))
        assert res["ok"] is False and res["pin_invalid"] is True
        upd_mock.assert_not_called()

    def test_pin_only_still_returns_ok_without_enabling(self):
        res, pin_mock, upd_mock = self._run({"id": "o1", "op": "pin", "pin": "1234"})
        assert res == {"ok": True, "id": "o1"}
        pin_mock.assert_called_once()
        upd_mock.assert_not_called()

    def test_pin_then_selected_can_ask_for_a_pin_again(self):
        res, _, _ = self._run(
            {"id": "o1", "op": "pin", "pin": "1234", "selected": True},
            requester="dial:a", update_result=_result(False, "pin_required", "again"))
        assert res["pin_required"] is True
        assert _pairing.holder("o1") == "dial:a"

    def test_a_malformed_pin_is_refused_before_the_player_is_called(self):
        for pin in _BAD_PINS:
            res, pin_mock, upd_mock = self._run({"id": "o1", "op": "pin", "pin": pin})
            assert res == {"ok": False, "error": "invalid_pin", "id": "o1"}, repr(pin)
            pin_mock.assert_not_called()
            upd_mock.assert_not_called()

    def test_the_sixth_pin_in_a_minute_is_rate_limited_before_the_player_is_called(self):
        for _ in range(5):
            res, _, _ = self._run({"id": "o1", "op": "pin", "pin": "1234"},
                                  pin_result=_result(False, "pin_invalid", "Wrong"))
            assert res["pin_invalid"] is True
        res, pin_mock, upd_mock = self._run({"id": "o1", "op": "pin", "pin": "1234"})
        assert res["ok"] is False and res["error"] == "rate_limited"
        assert res["id"] == "o1"
        assert isinstance(res["retry_after_s"], int) and res["retry_after_s"] >= 1
        pin_mock.assert_not_called()
        upd_mock.assert_not_called()

    def test_the_webui_requester_is_used_when_none_is_given(self):
        for _ in range(5):
            self._run({"id": "o1", "op": "pin", "pin": "1234"})
        # the shared budget is the WebUI's, whichever way the call names it
        res, _, _ = self._run({"id": "o1", "op": "pin", "pin": "1234"}, requester="webui")
        assert res["error"] == "rate_limited"
        res, _, _ = self._run({"id": "o1", "op": "pin", "pin": "1234"}, requester="dial:a")
        assert res == {"ok": True, "id": "o1"}

    def test_nothing_logged_by_the_mutation_contains_the_pin(self, caplog):
        pin = "73519"
        with caplog.at_level(_logging.DEBUG):
            self._run({"id": "o1", "op": "pin", "pin": pin}, requester="webui",
                      pin_result=_result(False, "pin_invalid", "Wrong PIN"))
            self._run({"id": "o1", "op": "pin", "pin": pin, "selected": True},
                      requester="webui")
            for _ in range(6):
                self._run({"id": "o3", "op": "pin", "pin": pin})
        assert pin not in caplog.text
