"""Priority 7 — appliance_models unit tests.

Covers apply_eq_field / apply_eq_reset (validation, clamping, persistence,
live-apply routing).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_config import DefaultOutput, parse_config
from autostream_players import ActionResult, OutputInfo
from fake_store import FakeStore


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
) -> OutputInfo:
    return OutputInfo(
        id=id_, name=name, selected=selected, volume_percent=volume,
        needs_auth_key=needs_auth_key, requires_auth=requires_auth,
        pin_pending=pin_pending,
    )


def _units(rows):
    """The authority's units for *rows*, as the readers receive them."""
    return FakeStore().outputs(list(rows)).outputs.units


def _hold_set(members) -> None:
    """Give the output authority the Auto-Start set the settings hold."""
    if members:
        from autostream_state.outputs import get_authority
        get_authority().set_default_members([(m.id, m.name, m.volume) for m in members], 20)


def _parsed(
    output_name: str = "",
    members: tuple = (),
    hidden_outputs: list | None = None,
    show_master_volume: bool = True,
    show_input_detail: bool = False,
) -> SimpleNamespace:
    members = members or ((DefaultOutput("", output_name, 20),) if output_name else ())
    _hold_set(members)
    return SimpleNamespace(
        owntone=SimpleNamespace(
            default_outputs=members,
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


def _parsed_from(cfg_path: Path):
    """The settings the file at *cfg_path* holds, parsed."""
    parsed = parse_config(json.loads(Path(cfg_path).read_text(encoding="utf-8")))
    _hold_set(parsed.owntone.default_outputs)
    return parsed


def _deep_update(d: dict, u: dict) -> dict:
    for k, v in u.items():
        if isinstance(v, dict) and isinstance(d.get(k), dict):
            _deep_update(d[k], v)
        else:
            d[k] = v
    return d


# ---------------------------------------------------------------------------
# apply_eq_field — validation, clamping, persistence, routing
# ---------------------------------------------------------------------------

class TestApplyEqField:
    def test_unknown_field_raises_value_error(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with pytest.raises(ValueError, match="Unknown field"):
            monitor_control.apply_eq_field(str(cfg_path), "no_such_field", "1.0")

    def test_non_numeric_db_raises_value_error(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with pytest.raises(ValueError, match="numeric"):
            monitor_control.apply_eq_field(str(cfg_path), "gain_db", "abc")

    def test_gain_clamped_to_max(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_monitor_control.set_live_output_gain"), \
             patch("autostream_monitor_control.save_config"):
            ok, norm, err = monitor_control.apply_eq_field(str(cfg_path), "gain_db", "99")
        assert ok is True
        assert float(norm) <= 12.0

    def test_gain_clamped_to_min(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_monitor_control.set_live_output_gain"), \
             patch("autostream_monitor_control.save_config"):
            ok, norm, err = monitor_control.apply_eq_field(str(cfg_path), "gain_db", "-99")
        assert float(norm) >= -12.0

    def test_gain_change_calls_set_live_output_gain(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        gain_calls = []
        with patch("autostream_monitor_control.set_live_output_gain",
                   side_effect=lambda v, **kw: gain_calls.append(v)), \
             patch("autostream_monitor_control.save_config"):
            monitor_control.apply_eq_field(str(cfg_path), "gain_db", "2.5")
        assert gain_calls == [pytest.approx(2.5)]

    def test_peq_change_calls_set_live_output_eq(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        eq_calls = []
        with patch("autostream_monitor_control.set_live_output_eq",
                   side_effect=lambda *a, **kw: eq_calls.append(a)), \
             patch("autostream_monitor_control.save_config"):
            monitor_control.apply_eq_field(str(cfg_path), "peq3_db", "4.0")
        assert eq_calls, "set_live_output_eq must be called"
        assert len(eq_calls[0]) == 6

    def test_peq_change_does_not_call_set_live_output_gain(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        gain_calls = []
        with patch("autostream_monitor_control.set_live_output_gain",
                   side_effect=lambda v, **kw: gain_calls.append(v)), \
             patch("autostream_monitor_control.set_live_output_eq"), \
             patch("autostream_monitor_control.save_config"):
            monitor_control.apply_eq_field(str(cfg_path), "peq1_db", "1.0")
        assert not gain_calls

    def test_auto_trim_true_string_parsed(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_monitor_control.set_live_output_auto_trim"), \
             patch("autostream_monitor_control.save_config"):
            ok, norm, err = monitor_control.apply_eq_field(str(cfg_path), "auto_trim_enabled", "true")
        assert ok is True
        assert norm == "true"

    def test_auto_trim_false_string_parsed(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_monitor_control.set_live_output_auto_trim"), \
             patch("autostream_monitor_control.save_config"):
            ok, norm, err = monitor_control.apply_eq_field(str(cfg_path), "auto_trim_enabled", "0")
        assert norm == "false"

    def test_save_failure_returns_ok_false(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_monitor_control.set_live_output_gain"), \
             patch("autostream_monitor_control.save_config",
                   side_effect=OSError("disk full")):
            ok, norm, err = monitor_control.apply_eq_field(str(cfg_path), "gain_db", "1.0")
        assert ok is False
        assert err


# ---------------------------------------------------------------------------
# apply_eq_reset
# ---------------------------------------------------------------------------

class TestApplyEqReset:
    def test_ok_true_on_success(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_monitor_control.set_live_output_gain"), \
             patch("autostream_monitor_control.set_live_output_eq"):
            ok, err = monitor_control.apply_eq_reset(str(cfg_path))
        assert ok is True
        assert err == ""

    def test_all_db_fields_zeroed_in_file(self, tmp_path):
        cfg_path = _make_config_file(tmp_path, {
            "output_eq": {"gain_db": 5.0, "peq1_db": 3.0, "peq6_db": -2.0}
        })
        with patch("autostream_monitor_control.set_live_output_gain"), \
             patch("autostream_monitor_control.set_live_output_eq"):
            monitor_control.apply_eq_reset(str(cfg_path))
        saved = json.loads(cfg_path.read_text())
        for f in ("peq1_db", "peq2_db", "peq3_db", "peq4_db", "peq5_db", "peq6_db"):
            assert saved["output_eq"][f] == 0.0, f"{f} not zeroed"
        assert saved["output_eq"]["gain_db"] == 5.0, "gain_db must not be changed by Flat reset"

    def test_reset_does_not_call_set_live_output_gain(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        gain_calls = []
        with patch("autostream_monitor_control.set_live_output_gain",
                   side_effect=lambda v, **kw: gain_calls.append(v)), \
             patch("autostream_monitor_control.set_live_output_eq"):
            monitor_control.apply_eq_reset(str(cfg_path))
        assert gain_calls == [], "set_live_output_gain must not be called by Flat reset"

    def test_reset_calls_set_live_output_eq_all_zeros(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        eq_calls = []
        with patch("autostream_monitor_control.set_live_output_gain"), \
             patch("autostream_monitor_control.set_live_output_eq",
                   side_effect=lambda *a, **kw: eq_calls.append(a)):
            monitor_control.apply_eq_reset(str(cfg_path))
        assert eq_calls and all(v == 0.0 for v in eq_calls[0])

    def test_save_failure_returns_ok_false(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_monitor_control.save_config",
                   side_effect=OSError("disk full")):
            ok, err = monitor_control.apply_eq_reset(str(cfg_path))
        assert ok is False
        assert err


# ---------------------------------------------------------------------------
# PIN pairing: combined pin-and-enable
# ---------------------------------------------------------------------------

import logging as _logging

import autostream_pin_pairing as _pairing
import autostream_monitor_control as monitor_control
import webui.browser.home_model as webui_home_model


def _result(ok: bool, error_code: str = "", message: str = ""):
    return ActionResult(ok=ok, error_code=error_code, error=message)


_BAD_PINS = [
    "123", "123456789", "12a4", "１２３４", " 1234", "1234\n",
    "", "1234 ", "-123", None, 1234, 12.5, ["1", "2", "3", "4"], {"a": 1}, True,
]


class TestPinMutation:
    def _run(self, body, *, requester=None, pin_result=None, update_result=None):
        """Submit *body* as the Web UI; *requester* is the pairing identity
        that may enter a PIN (None when the caller cannot)."""
        import autostream_player_service as ps
        FakeStore().outputs([FakeStore.output_row(i, "Speaker " + i, selected=False, volume_percent=0)
                             for i in ("o1", "o2", "o3")])
        pin_mock = MagicMock(return_value=pin_result or _result(True))
        upd_mock = MagicMock(return_value=update_result or _result(True))
        with patch.object(ps, "submit_output_pin", pin_mock), \
             patch.object(ps, "update_output", upd_mock):
            res = webui_home_model.submit_output_change(
                body, requester="webui", pin_requester=requester)
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
