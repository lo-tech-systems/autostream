"""Priority 7 — webui post handlers tests.

Covers handle_output_update (output ID, PIN auth, pin_required/pin_invalid,
offset/mode forwarding) and handle_live_input_eq_update / handle_live_input_gain_update
(malformed JSON, bool-as-number, NaN/Infinity, invalid input IDs, out-of-range).
"""
from __future__ import annotations

import inspect
import json
import math
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import _source_text

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_webui_post_handlers as ph
from autostream_webui_post_handlers import (
    handle_live_input_eq_update,
    handle_live_input_gain_update,
    handle_output_update,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_state(tmp_path: Path) -> MagicMock:
    cfg_path = tmp_path / "autostream.json"
    cfg_path.write_text(json.dumps({"general": {}, "owntone": {"base_url": "http://localhost:3689"}}))
    state = MagicMock()
    state.config_path = cfg_path
    return state


def _make_result_ok():
    from autostream_players import ActionResult
    return ActionResult(ok=True)


def _make_result_err(code: str, msg: str = "err"):
    from autostream_players import ActionResult
    return ActionResult(ok=False, error=msg, error_code=code)


def _call_output_update(body: dict, *, tmp_path: Path,
                        update_result=None, disable_result=None,
                        pin_result=None, speakers=None,
                        offsets=None, modes=None) -> dict:
    """Run the output route's handler against a patched player.

    *speakers* are the OutputInfo rows the authority knows; by default the
    body's own id is arranged as a speaker that is off. The reply is in
    "calls"; every write the player received is in "writes"."""
    from autostream_players import ActionResult
    from fake_store import FakeStore

    sent = []
    writes = []
    handler = MagicMock()
    state = _make_state(tmp_path)

    def fake_send_json(h, code, data):
        sent.append((code, data))

    ok_result = ActionResult(ok=True)

    def fake_update_output(base_url, out_id, **kwargs):
        writes.append(("update_output", out_id, kwargs))
        if kwargs.get("enabled") is False:
            return disable_result or ok_result
        return update_result or ok_result

    def fake_submit_output_pin(base_url, out_id, pin, timeout=None):
        writes.append(("submit_output_pin", out_id, pin))
        return pin_result or ok_result

    if speakers is None:
        out_id = str(body.get("id") or "") or "0"
        speakers = [FakeStore.output_row(out_id, "Kitchen", selected=False, volume_percent=0)]
    FakeStore().outputs(speakers)

    with patch("autostream_webui_post_handlers.send_json", side_effect=fake_send_json), \
         patch("autostream_webui_post_handlers.locked_load_config",
               return_value={"general": {}, "owntone": {"base_url": "http://localhost:3689"}}), \
         patch("autostream_webui_post_handlers.parse_config") as mock_parse, \
         patch("autostream_player_service.update_output", side_effect=fake_update_output), \
         patch("autostream_player_service.submit_output_pin", side_effect=fake_submit_output_pin):
        mock_parse.return_value.owntone.base_url = "http://localhost:3689"
        mock_parse.return_value.owntone.output_offsets_ms = offsets or {}
        mock_parse.return_value.owntone.output_airplay_modes = modes or {}
        handle_output_update(handler, state, json.dumps(body))

    return {"calls": sent, "writes": writes}


def _call_eq(body: str | dict, tmp_path: Path) -> dict:
    if isinstance(body, dict):
        body = json.dumps(body)
    sent = []

    def fake_send_json(h, code, data):
        sent.append((code, data))

    with patch("autostream_webui_post_handlers.send_json", side_effect=fake_send_json), \
         patch("autostream_monitor_control.set_live_input_eq", return_value=True):
        handle_live_input_eq_update(MagicMock(), MagicMock(), body)

    return sent[0] if sent else (None, {})


def _call_gain(body: str | dict, tmp_path: Path) -> tuple:
    if isinstance(body, dict):
        body = json.dumps(body)
    sent = []

    def fake_send_json(h, code, data):
        sent.append((code, data))

    # handle_live_input_gain_update partially validates (JSON, input index) and
    # then delegates to send_settings_post_json in autostream_webui_api. Patch
    # both paths so all send_json calls are captured.
    # Provide a real SettingsStore so valid requests reach the success path.
    import tempfile, os
    from autostream_settings import SettingsStore
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
        tf.write("{}")
        cfg_path = tf.name
    try:
        store = SettingsStore(cfg_path, _save_interval_seconds=9999, _writer=MagicMock())
        state = MagicMock()
        state.settings = store
        with patch("autostream_webui_post_handlers.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_monitor_control.set_live_input_gain", return_value=True):
            handle_live_input_gain_update(MagicMock(), state, body)
    finally:
        store.close(save=False)
        try:
            os.unlink(cfg_path)
        except OSError:
            pass

    return sent[0] if sent else (None, {})


# ---------------------------------------------------------------------------
# handle_output_update: output ID validation
# ---------------------------------------------------------------------------

class TestOutputUpdateValidation:
    def test_missing_output_id_returns_error(self, tmp_path):
        r = _call_output_update({"selected": True}, tmp_path=tmp_path)
        code, data = r["calls"][0]
        assert code == 200
        assert data["ok"] is False
        assert "id" in data["error"].lower() or "id" in str(data).lower()

    def test_empty_output_id_returns_error(self, tmp_path):
        r = _call_output_update({"id": "", "selected": True}, tmp_path=tmp_path)
        code, data = r["calls"][0]
        assert data["ok"] is False

    def test_valid_deselect_returns_ok(self, tmp_path):
        r = _call_output_update({"id": "42", "selected": False}, tmp_path=tmp_path)
        _, data = r["calls"][0]
        assert data["ok"] is True
        assert data["id"] == "42"

    def test_valid_select_returns_ok(self, tmp_path):
        r = _call_output_update({"id": "42", "selected": True, "volume": 50},
                                 tmp_path=tmp_path)
        _, data = r["calls"][0]
        assert data["ok"] is True


# ---------------------------------------------------------------------------
# handle_output_update: PIN auth
# ---------------------------------------------------------------------------

class TestOutputUpdatePIN:
    def test_pin_op_missing_pin_returns_error(self, tmp_path):
        r = _call_output_update({"id": "1", "op": "pin"}, tmp_path=tmp_path)
        _, data = r["calls"][0]
        assert data["ok"] is False
        assert data.get("error") == "invalid_pin"

    def test_pin_op_invalid_pin_returns_pin_invalid(self, tmp_path):
        r = _call_output_update(
            {"id": "1", "op": "pin", "pin": "0000"},
            tmp_path=tmp_path,
            pin_result=_make_result_err("pin_invalid", "Wrong PIN"),
        )
        _, data = r["calls"][0]
        assert data["ok"] is False
        assert data.get("pin_invalid") is True

    def test_pin_op_success_returns_ok(self, tmp_path):
        r = _call_output_update(
            {"id": "1", "op": "pin", "pin": "1234"},
            tmp_path=tmp_path,
            pin_result=_make_result_ok(),
        )
        _, data = r["calls"][0]
        assert data["ok"] is True

    def test_pin_required_response_includes_pin_required_flag(self, tmp_path):
        r = _call_output_update(
            {"id": "1", "selected": True, "volume": 50},
            tmp_path=tmp_path,
            update_result=_make_result_err("pin_required", "PIN required"),
        )
        _, data = r["calls"][0]
        assert data["ok"] is False
        assert data.get("pin_required") is True


# ---------------------------------------------------------------------------
# handle_live_input_eq_update: input validation
# ---------------------------------------------------------------------------

class TestLiveInputEQValidation:
    def test_malformed_json_returns_400(self, tmp_path):
        code, data = _call_eq("not-json", tmp_path)
        assert code == 400
        assert data["ok"] is False

    def test_invalid_input_id_0_returns_400(self, tmp_path):
        code, data = _call_eq({"input": 0, "eq_40hz_db": 0}, tmp_path)
        assert code == 400
        assert "input" in data["error"]

    def test_invalid_input_id_3_returns_400(self, tmp_path):
        code, data = _call_eq({"input": 3, "eq_40hz_db": 0}, tmp_path)
        assert code == 400

    def test_eq_too_low_returns_400(self, tmp_path):
        code, data = _call_eq({"input": 1, "eq_40hz_db": -11}, tmp_path)
        assert code == 400

    def test_eq_too_high_returns_400(self, tmp_path):
        code, data = _call_eq({"input": 1, "eq_40hz_db": 11}, tmp_path)
        assert code == 400

    def test_eq_boundary_10_accepted(self, tmp_path):
        code, data = _call_eq({"input": 1, "eq_40hz_db": 10.0,
                                "eq_100hz_db": 0, "eq_8khz_db": 0}, tmp_path)
        assert code == 200
        assert data["ok"] is True

    def test_eq_boundary_minus10_accepted(self, tmp_path):
        code, data = _call_eq({"input": 2, "eq_40hz_db": -10.0,
                                "eq_100hz_db": 0, "eq_8khz_db": 0}, tmp_path)
        assert code == 200

    def _call_eq_with_mock_eq(self, body, tmp_path):
        """Return (code, data, mock_set_live_input_eq) so callers can assert not called."""
        if isinstance(body, dict):
            body = json.dumps(body)
        sent = []
        mock_fn = MagicMock(return_value=True)

        def fake_send_json(h, code, data):
            sent.append((code, data))

        with patch("autostream_webui_post_handlers.send_json", side_effect=fake_send_json), \
             patch("autostream_monitor_control.set_live_input_eq", mock_fn):
            handle_live_input_eq_update(MagicMock(), MagicMock(), body)

        code, data = sent[0] if sent else (None, {})
        return code, data, mock_fn

    def test_bool_as_number_rejected(self, tmp_path):
        # Boolean True must not be accepted as an EQ value (float(True)=1.0 would slip through
        # a naive range check). The handler must reject booleans explicitly.
        code, data, mock_eq = self._call_eq_with_mock_eq(
            {"input": 1, "eq_40hz_db": True, "eq_100hz_db": 0, "eq_8khz_db": 0}, tmp_path
        )
        assert code == 400
        assert data["ok"] is False
        mock_eq.assert_not_called()

    def test_false_as_number_rejected(self, tmp_path):
        code, data, mock_eq = self._call_eq_with_mock_eq(
            {"input": 1, "eq_40hz_db": False, "eq_100hz_db": 0, "eq_8khz_db": 0}, tmp_path
        )
        assert code == 400
        mock_eq.assert_not_called()

    def test_nan_value_rejected(self, tmp_path):
        # Inject NaN via json.loads patching; the handler must reject it with 400
        # and must NOT call set_live_input_eq.
        body = json.dumps({"input": 1, "eq_40hz_db": 0, "eq_100hz_db": 0, "eq_8khz_db": 0})
        sent = []
        mock_eq = MagicMock(return_value=True)

        import autostream_webui_post_handlers as _ph
        orig_loads = _ph.json.loads

        def patched_loads(s, **kw):
            result = orig_loads(s, **kw)
            if isinstance(result, dict):
                result["eq_40hz_db"] = float("nan")
            return result

        with patch("autostream_webui_post_handlers.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_monitor_control.set_live_input_eq", mock_eq), \
             patch.object(_ph.json, "loads", side_effect=patched_loads):
            handle_live_input_eq_update(MagicMock(), MagicMock(), body)

        code, data = sent[0]
        assert code == 400
        assert data["ok"] is False
        mock_eq.assert_not_called()

    def test_infinity_rejected(self, tmp_path):
        # math.inf > 10.0 is True so range check should catch it; confirm 400 + no monitor call.
        body = json.dumps({"input": 1, "eq_40hz_db": 0, "eq_100hz_db": 0, "eq_8khz_db": 0})
        sent = []
        mock_eq = MagicMock(return_value=True)
        import autostream_webui_post_handlers as _ph
        orig_loads = _ph.json.loads

        def patched_loads(s, **kw):
            result = orig_loads(s, **kw)
            if isinstance(result, dict):
                result["eq_8khz_db"] = float("inf")
            return result

        with patch("autostream_webui_post_handlers.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_monitor_control.set_live_input_eq", mock_eq), \
             patch.object(_ph.json, "loads", side_effect=patched_loads):
            handle_live_input_eq_update(MagicMock(), MagicMock(), body)

        code, data = sent[0]
        assert code == 400
        mock_eq.assert_not_called()

    def test_negative_infinity_rejected(self, tmp_path):
        body = json.dumps({"input": 1, "eq_40hz_db": 0, "eq_100hz_db": 0, "eq_8khz_db": 0})
        sent = []
        mock_eq = MagicMock(return_value=True)
        import autostream_webui_post_handlers as _ph
        orig_loads = _ph.json.loads

        def patched_loads(s, **kw):
            result = orig_loads(s, **kw)
            if isinstance(result, dict):
                result["eq_100hz_db"] = float("-inf")
            return result

        with patch("autostream_webui_post_handlers.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_monitor_control.set_live_input_eq", mock_eq), \
             patch.object(_ph.json, "loads", side_effect=patched_loads):
            handle_live_input_eq_update(MagicMock(), MagicMock(), body)

        code, data = sent[0]
        assert code == 400
        mock_eq.assert_not_called()

    def test_valid_eq_returns_200_with_values(self, tmp_path):
        code, data = _call_eq(
            {"input": 1, "eq_40hz_db": 3.5, "eq_100hz_db": -2.0, "eq_8khz_db": 1.0},
            tmp_path,
        )
        assert code == 200
        assert data["ok"] is True
        assert data["eq_40hz_db"] == pytest.approx(3.5)
        assert data["input"] == 1


# ---------------------------------------------------------------------------
# handle_live_input_gain_update: input validation
# ---------------------------------------------------------------------------

class TestLiveInputGainValidation:
    def test_malformed_json_returns_400(self, tmp_path):
        code, data = _call_gain("not-json", tmp_path)
        assert code == 400

    def test_invalid_input_0_returns_400(self, tmp_path):
        code, data = _call_gain({"input": 0, "gain_db": 0}, tmp_path)
        assert code == 400

    def test_invalid_input_3_returns_400(self, tmp_path):
        code, data = _call_gain({"input": 3, "gain_db": 0}, tmp_path)
        assert code == 400

    def test_gain_too_low_returns_400(self, tmp_path):
        code, data = _call_gain({"input": 1, "gain_db": -11}, tmp_path)
        assert code == 400

    def test_gain_too_high_returns_400(self, tmp_path):
        code, data = _call_gain({"input": 1, "gain_db": 11}, tmp_path)
        assert code == 400

    def test_gain_boundary_10_accepted(self, tmp_path):
        code, data = _call_gain({"input": 1, "gain_db": 10.0}, tmp_path)
        assert code == 200

    def test_gain_boundary_minus10_accepted(self, tmp_path):
        code, data = _call_gain({"input": 2, "gain_db": -10.0}, tmp_path)
        assert code == 200

    def test_valid_gain_returns_200_with_values(self, tmp_path):
        code, data = _call_gain({"input": 2, "gain_db": 5.5}, tmp_path)
        assert code == 200
        assert data["ok"] is True
        # handle_live_input_gain_update delegates to send_settings_post_json;
        # response uses "field"/"value" instead of "input"/"gain_db".
        assert data["value"] == pytest.approx(5.5)
        assert data["field"] == "audio2.gain_db"

    def _call_gain_with_mock(self, body, tmp_path):
        if isinstance(body, dict):
            body = json.dumps(body)
        sent = []
        mock_fn = MagicMock(return_value=True)

        def fake_send_json(h, code, data):
            sent.append((code, data))

        # Delegate path now goes through autostream_webui_api; patch there.
        with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_monitor_control.set_live_input_gain", mock_fn):
            handle_live_input_gain_update(MagicMock(), MagicMock(), body)

        code, data = sent[0] if sent else (None, {})
        return code, data, mock_fn

    def test_gain_bool_true_rejected(self, tmp_path):
        code, data, mock_gain = self._call_gain_with_mock(
            {"input": 1, "gain_db": True}, tmp_path
        )
        assert code == 400
        assert data["ok"] is False
        mock_gain.assert_not_called()

    def test_gain_nan_rejected(self, tmp_path):
        body = json.dumps({"input": 1, "gain_db": 0})
        sent = []
        import autostream_webui_post_handlers as _ph
        orig_loads = _ph.json.loads

        def patched_loads(s, **kw):
            result = orig_loads(s, **kw)
            if isinstance(result, dict):
                result["gain_db"] = float("nan")
            return result

        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_monitor_control.set_live_input_gain", return_value=True), \
             patch.object(_ph.json, "loads", side_effect=patched_loads):
            handle_live_input_gain_update(MagicMock(), MagicMock(), body)

        code, data = sent[0]
        assert code == 400
        assert data["ok"] is False

    def test_gain_infinity_rejected(self, tmp_path):
        body = json.dumps({"input": 1, "gain_db": 0})
        sent = []
        import autostream_webui_post_handlers as _ph
        orig_loads = _ph.json.loads

        def patched_loads(s, **kw):
            result = orig_loads(s, **kw)
            if isinstance(result, dict):
                result["gain_db"] = float("inf")
            return result

        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_monitor_control.set_live_input_gain", return_value=True), \
             patch.object(_ph.json, "loads", side_effect=patched_loads):
            handle_live_input_gain_update(MagicMock(), MagicMock(), body)

        code, data = sent[0]
        assert code == 400


# ---------------------------------------------------------------------------
# handle_output_update: offset and mode forwarding
# ---------------------------------------------------------------------------

class TestOutputUpdateForwarding:
    def test_offset_and_mode_forwarded_to_update_output(self, tmp_path):
        """update_output receives the per-output offset_ms and mode from config."""
        r = _call_output_update(
            {"id": "99", "selected": True, "volume": 75}, tmp_path=tmp_path,
            offsets={"99": 200}, modes={"99": "alac"},
        )
        (name, out_id, kwargs), = r["writes"]
        assert (name, out_id) == ("update_output", "99")
        assert kwargs["offset_ms"] == 200
        assert kwargs["mode"] is not None
        assert kwargs["volume_percent"] == 75


# ---------------------------------------------------------------------------
# handle_setup_post
# ---------------------------------------------------------------------------

from urllib.parse import urlencode
from autostream_webui_post_handlers import handle_setup_post


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


def _call_setup_post(form_data: dict, tmp_path: Path,
                     hostname_failure: bool = False,
                     save_failure: bool = False,
                     admin_rc: int = 0) -> dict:
    """Call handle_setup_post with a URL-encoded body, returning captured state."""
    body = urlencode(form_data)
    cfg = _minimal_config()
    saved_cfgs = []
    redirects = []
    flash_calls = []

    def fake_save(path, data):
        if save_failure:
            raise OSError("disk full")
        saved_cfgs.append(dict(data))

    def fake_set_hostname(hn):
        if hostname_failure:
            raise RuntimeError("nmcli failed")

    with patch("autostream_webui_post_handlers.load_config", return_value=cfg), \
         patch("autostream_webui_post_handlers.parse_config") as mock_parse, \
         patch("autostream_webui_post_handlers.save_config", side_effect=fake_save), \
         patch("autostream_webui_post_handlers.mark_configured"), \
         patch("autostream_webui_post_handlers.get_system_hostname", return_value="old-host"), \
         patch("autostream_webui_post_handlers.set_system_hostname", side_effect=fake_set_hostname), \
         patch("autostream_webui_post_handlers.run_admin_cmd",
               return_value=MagicMock(returncode=admin_rc, stderr="")), \
         patch("autostream_live_config.update_live_owntone_runtime"), \
         patch("autostream_live_config.identification"), \
         patch("autostream_webui_post_handlers.send_setup_page",
               side_effect=lambda h, s, a, **kw: flash_calls.append(kw)), \
         patch("autostream_webui_post_handlers._set_flash_cookie"), \
         patch("autostream_webui_post_handlers.build_top_banner_html", return_value=("", "")), \
         patch("autostream_runtime.request_config_reload"):
        # Configure parse_config mock to return something plausible
        p = mock_parse.return_value
        p.audio1.capture_device = "hw:0,0"
        p.audio1.silence_threshold_dbfs = -50.0
        p.audio1.gain_db = 0.0
        p.audio1.eq_40hz_db = 0.0
        p.audio1.eq_100hz_db = 0.0
        p.audio1.eq_8khz_db = 0.0
        p.audio1.stylus_life_hours = 500
        p.audio1.belt_life_hours = 2000
        p.audio1.belt_life_years = 5
        p.audio1.bearing_life_hours = 5000
        p.audio1.bearing_life_years = 10
        p.audio2.capture_device = "hw:1,0"
        p.audio2.silence_threshold_dbfs = -50.0
        p.audio2.gain_db = 0.0
        p.audio2.eq_40hz_db = 0.0
        p.audio2.eq_100hz_db = 0.0
        p.audio2.eq_8khz_db = 0.0
        p.audio2.stylus_life_hours = 500
        p.audio2.belt_life_hours = 2000
        p.audio2.belt_life_years = 5
        p.audio2.bearing_life_hours = 5000
        p.audio2.bearing_life_years = 10
        p.audio2_enabled = False
        p.owntone.output_name = "Default"
        p.owntone.volume_percent = 50
        p.owntone.base_url = "http://localhost:3689"
        p.owntone.output_offsets_ms = {}
        p.owntone.output_airplay_modes = {}
        p.general.silence_seconds = 10
        p.general.log_file = "/var/log/autostream.log"
        p.general.fifo_path = "/run/autostream/audio.fifo"
        p.updates.auto_update = False  # existing value; form may change it

        handle_setup_post(MagicMock(), MagicMock(), MagicMock(), body)

    return {
        "saved": saved_cfgs,
        "flash_calls": flash_calls,
    }


class TestSetupPost:
    def test_saves_both_audio_sections(self, tmp_path):
        form = {
            "audio_capture_device": "hw:0,0",
            "audio2_capture_device": "hw:1,0",
            "silence_seconds": "10",
            "owntone_output_name": "Speaker",
            "owntone_volume_percent": "50",
        }
        result = _call_setup_post(form, tmp_path)
        assert result["saved"], "save_config must be called"
        saved = result["saved"][0]
        assert "audio1" in saved
        assert "audio2" in saved

    def test_turntable_flag_and_threshold_agree_on_save(self, tmp_path):
        form = {
            "audio_capture_device": "hw:0,0",
            "audio_turntable": "on",
            "audio2_capture_device": "hw:1,0",
            "silence_seconds": "10",
            "owntone_output_name": "Speaker",
            "owntone_volume_percent": "50",
        }
        result = _call_setup_post(form, tmp_path)
        saved = result["saved"][0]
        assert saved["audio1"]["turntable"] is True
        assert saved["audio1"]["silence_threshold"] == -45.0
        assert saved["audio2"]["turntable"] is False
        assert saved["audio2"]["silence_threshold"] == -60.0

    def test_removes_legacy_eq_10khz_key_from_audio1(self, tmp_path):
        form = {"audio_capture_device": "hw:0,0", "silence_seconds": "10",
                "owntone_output_name": "S", "owntone_volume_percent": "50"}
        # Pre-seed cfg with legacy key
        with patch("autostream_webui_post_handlers.load_config",
                   return_value={**_minimal_config(), "audio1": {**_minimal_config()["audio1"],
                                                                  "eq_10khz_db": 1.5}}), \
             patch("autostream_webui_post_handlers.parse_config") as mp, \
             patch("autostream_webui_post_handlers.save_config") as mock_save, \
             patch("autostream_webui_post_handlers.mark_configured"), \
             patch("autostream_webui_post_handlers.get_system_hostname", return_value="h"), \
             patch("autostream_webui_post_handlers.set_system_hostname"), \
             patch("autostream_webui_post_handlers.run_admin_cmd",
                   return_value=MagicMock(returncode=0, stderr="")), \
             patch("autostream_live_config.update_live_owntone_runtime"), \
             patch("autostream_live_config.identification"), \
             patch("autostream_webui_post_handlers._set_flash_cookie"), \
             patch("autostream_webui_post_handlers.build_top_banner_html", return_value=("", "")), \
             patch("autostream_runtime.request_config_reload"):
            p = mp.return_value
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
            p.owntone.output_name = "S"
            p.owntone.volume_percent = 50
            p.owntone.base_url = "http://localhost:3689"
            p.owntone.output_offsets_ms = {}
            p.owntone.output_airplay_modes = {}
            p.general.silence_seconds = 10
            p.general.log_file = "/var/log/autostream.log"
            p.general.fifo_path = "/run/autostream/audio.fifo"
            p.updates.auto_update = False
            handle_setup_post(MagicMock(), MagicMock(), MagicMock(), urlencode(form))
            assert mock_save.called
            saved_cfg = mock_save.call_args[0][1]
            assert "eq_10khz_db" not in saved_cfg.get("audio1", {})

    def test_webui_panel_preserved_when_sentinel_absent(self, tmp_path):
        # Without webui_show_master_volume_present, the webui section must not be overwritten.
        form = {"audio_capture_device": "hw:0,0", "silence_seconds": "10",
                "owntone_output_name": "S", "owntone_volume_percent": "50"}
        result = _call_setup_post(form, tmp_path)
        if result["saved"]:
            assert "webui" not in result["saved"][0]

    def test_auto_update_rollback_on_timer_failure(self, tmp_path):
        # When auto_update changes and run_admin_cmd fails, the handler rolls back
        # and calls send_setup_page (not the success cookie path).
        form = {
            "audio_capture_device": "hw:0,0", "silence_seconds": "10",
            "owntone_output_name": "S", "owntone_volume_percent": "50",
            "updates_auto_update_present": "1",
            "updates_auto_update": "1",   # toggle to True
        }
        result = _call_setup_post(form, tmp_path, admin_rc=1)
        # Timer failure triggers send_setup_page with error flash
        assert result["flash_calls"], "send_setup_page must be called on timer failure"
        flash = result["flash_calls"][0]
        assert flash.get("flash_type") == "error"

    def test_save_failure_calls_error_page(self, tmp_path):
        form = {"audio_capture_device": "hw:0,0", "silence_seconds": "10",
                "owntone_output_name": "S", "owntone_volume_percent": "50"}
        result = _call_setup_post(form, tmp_path, save_failure=True)
        # The handler catches the OSError and calls send_setup_page with "Save failed"
        assert result["flash_calls"], "send_setup_page must be called on save failure"
        flash = result["flash_calls"][0]
        assert flash.get("flash_type") == "error"

    def test_hostname_failure_calls_error_page(self, tmp_path):
        # set_system_hostname raises → exception caught → send_setup_page "Save failed"
        form = {"audio_capture_device": "hw:0,0", "silence_seconds": "10",
                "owntone_output_name": "S", "owntone_volume_percent": "50",
                "system_hostname": "new-hostname"}  # triggers hostname change
        result = _call_setup_post(form, tmp_path, hostname_failure=True)
        assert result["flash_calls"], "send_setup_page must be called on hostname failure"
        flash = result["flash_calls"][0]
        assert flash.get("flash_type") == "error"

    def test_mark_configured_failure_calls_error_page(self, tmp_path):
        form = {"audio_capture_device": "hw:0,0", "silence_seconds": "10",
                "owntone_output_name": "S", "owntone_volume_percent": "50"}
        from unittest.mock import patch as _patch
        flash_calls = []
        cfg = _minimal_config()

        with _patch("autostream_webui_post_handlers.load_config", return_value=cfg), \
             _patch("autostream_webui_post_handlers.parse_config") as mp, \
             _patch("autostream_webui_post_handlers.save_config"), \
             _patch("autostream_webui_post_handlers.mark_configured",
                    side_effect=OSError("permission denied")), \
             _patch("autostream_webui_post_handlers.get_system_hostname", return_value="host"), \
             _patch("autostream_webui_post_handlers.set_system_hostname"), \
             _patch("autostream_webui_post_handlers.run_admin_cmd",
                    return_value=MagicMock(returncode=0, stderr="")), \
             _patch("autostream_live_config.update_live_owntone_runtime"), \
             _patch("autostream_live_config.identification"), \
             _patch("autostream_webui_post_handlers.send_setup_page",
                    side_effect=lambda h, s, a, **kw: flash_calls.append(kw)), \
             _patch("autostream_webui_post_handlers._set_flash_cookie"), \
             _patch("autostream_webui_post_handlers.build_top_banner_html", return_value=("", "")), \
             _patch("autostream_runtime.request_config_reload"):
            p = mp.return_value
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
            p.owntone.output_name = "S"
            p.owntone.volume_percent = 50
            p.owntone.base_url = "http://localhost:3689"
            p.owntone.output_offsets_ms = {}
            p.owntone.output_airplay_modes = {}
            p.general.silence_seconds = 10
            p.general.log_file = "/var/log/autostream.log"
            p.general.fifo_path = "/run/autostream/audio.fifo"
            p.updates.auto_update = False
            handle_setup_post(MagicMock(), MagicMock(), MagicMock(), urlencode(form))

        assert flash_calls, "send_setup_page must be called when mark_configured fails"
        assert flash_calls[0].get("flash_type") == "error"

    def test_updates_panel_absent_does_not_overwrite_auto_update(self, tmp_path):
        # Without updates_auto_update_present, the auto_update config key must not change.
        form = {"audio_capture_device": "hw:0,0", "silence_seconds": "10",
                "owntone_output_name": "S", "owntone_volume_percent": "50"}
        # (no updates_auto_update_present)
        result = _call_setup_post(form, tmp_path)
        if result["saved"]:
            saved = result["saved"][0]
            # auto_update should remain False (the initial value in _minimal_config)
            updates = saved.get("updates", {})
            if "auto_update" in updates:
                assert updates["auto_update"] is False

    def test_timer_rollback_writes_old_auto_update_value(self, tmp_path):
        # Timer fails → rollback must write old (False) auto_update back, not new (True) value.
        form = {
            "audio_capture_device": "hw:0,0", "silence_seconds": "10",
            "owntone_output_name": "S", "owntone_volume_percent": "50",
            "updates_auto_update_present": "1",
            "updates_auto_update": "1",  # toggles to True
        }
        result = _call_setup_post(form, tmp_path, admin_rc=1)
        # saved[0] is the initial save (auto_update=True), saved[1] is the rollback (auto_update=False)
        assert len(result["saved"]) >= 2, "rollback must write a second save_config call"
        rollback_cfg = result["saved"][1]
        assert rollback_cfg.get("updates", {}).get("auto_update") is False

    def test_device_change_triggers_config_reload(self, tmp_path):
        # Changing audio_capture_device must trigger request_config_reload()
        form = {"audio_capture_device": "hw:2,0",  # different from default hw:0,0
                "silence_seconds": "10",
                "owntone_output_name": "S", "owntone_volume_percent": "50"}
        from unittest.mock import patch as _patch
        reload_calls = []
        cfg = _minimal_config()

        with _patch("autostream_webui_post_handlers.load_config", return_value=cfg), \
             _patch("autostream_webui_post_handlers.parse_config") as mp, \
             _patch("autostream_webui_post_handlers.save_config"), \
             _patch("autostream_webui_post_handlers.mark_configured"), \
             _patch("autostream_webui_post_handlers.get_system_hostname", return_value="host"), \
             _patch("autostream_webui_post_handlers.set_system_hostname"), \
             _patch("autostream_webui_post_handlers.run_admin_cmd",
                    return_value=MagicMock(returncode=0, stderr="")), \
             _patch("autostream_live_config.update_live_owntone_runtime"), \
             _patch("autostream_live_config.identification"), \
             _patch("autostream_webui_post_handlers.send_setup_page"), \
             _patch("autostream_webui_post_handlers._set_flash_cookie"), \
             _patch("autostream_webui_post_handlers.build_top_banner_html", return_value=("", "")), \
             _patch("autostream_runtime.request_config_reload",
                    side_effect=lambda: reload_calls.append(True)):
            p = mp.return_value
            p.audio1.capture_device = "hw:0,0"   # old device
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
            p.owntone.output_name = "S"
            p.owntone.volume_percent = 50
            p.owntone.base_url = "http://localhost:3689"
            p.owntone.output_offsets_ms = {}
            p.owntone.output_airplay_modes = {}
            p.general.silence_seconds = 10
            p.general.log_file = "/var/log/autostream.log"
            p.general.fifo_path = "/run/autostream/audio.fifo"
            p.updates.auto_update = False
            handle_setup_post(MagicMock(), MagicMock(), MagicMock(), urlencode(form))

        assert reload_calls, "request_config_reload must be called when device changes"

    def test_silence_seconds_only_change_triggers_live_update_not_reload(self, tmp_path):
        # Only silence_seconds changed — should call update_live_silence_seconds, not reload.
        # threshold must match LINE_LEVEL_SILENCE_THRESHOLD_DBFS (-60.0) so daemon_changed=False.
        form = {"audio_capture_device": "hw:0,0",  # same device
                "silence_seconds": "30",             # changed from 10
                "owntone_output_name": "S", "owntone_volume_percent": "50"}
        from unittest.mock import patch as _patch
        silence_calls = []
        reload_calls = []
        cfg = _minimal_config()

        with _patch("autostream_webui_post_handlers.load_config", return_value=cfg), \
             _patch("autostream_webui_post_handlers.parse_config") as mp, \
             _patch("autostream_webui_post_handlers.save_config"), \
             _patch("autostream_webui_post_handlers.mark_configured"), \
             _patch("autostream_webui_post_handlers.get_system_hostname", return_value="host"), \
             _patch("autostream_webui_post_handlers.set_system_hostname"), \
             _patch("autostream_webui_post_handlers.run_admin_cmd",
                    return_value=MagicMock(returncode=0, stderr="")), \
             _patch("autostream_live_config.update_live_owntone_runtime"), \
             _patch("autostream_live_config.identification"), \
             _patch("autostream_webui_post_handlers.send_setup_page"), \
             _patch("autostream_webui_post_handlers._set_flash_cookie"), \
             _patch("autostream_webui_post_handlers.build_top_banner_html", return_value=("", "")), \
             _patch("autostream_live_config.update_live_silence_seconds",
                    side_effect=lambda s: silence_calls.append(s) or True), \
             _patch("autostream_runtime.request_config_reload",
                    side_effect=lambda: reload_calls.append(True)):
            p = mp.return_value
            p.audio1.capture_device = "hw:0,0"
            p.audio1.silence_threshold_dbfs = -60.0  # must match LINE_LEVEL_SILENCE_THRESHOLD_DBFS
            for attr in ("gain_db", "eq_40hz_db", "eq_100hz_db", "eq_8khz_db",
                         "stylus_life_hours", "belt_life_hours", "belt_life_years",
                         "bearing_life_hours", "bearing_life_years"):
                setattr(p.audio1, attr, 0.0)
            p.audio2.capture_device = "hw:1,0"
            p.audio2.silence_threshold_dbfs = -60.0
            for attr in ("gain_db", "eq_40hz_db", "eq_100hz_db", "eq_8khz_db",
                         "stylus_life_hours", "belt_life_hours", "belt_life_years",
                         "bearing_life_hours", "bearing_life_years"):
                setattr(p.audio2, attr, 0.0)
            p.audio2_enabled = False
            p.owntone.output_name = "S"
            p.owntone.volume_percent = 50
            p.owntone.base_url = "http://localhost:3689"
            p.owntone.output_offsets_ms = {}
            p.owntone.output_airplay_modes = {}
            p.general.silence_seconds = 10   # old value
            p.general.log_file = "/var/log/autostream.log"
            p.general.fifo_path = "/run/autostream/audio.fifo"
            p.updates.auto_update = False
            handle_setup_post(MagicMock(), MagicMock(), MagicMock(), urlencode(form))

        assert silence_calls, "update_live_silence_seconds must be called"
        assert not reload_calls, "request_config_reload must NOT be called when only silence_seconds changed and live update succeeds"

    def test_silence_seconds_live_update_failure_triggers_reload(self, tmp_path):
        # update_live_silence_seconds returns False → fallback to request_config_reload
        form = {"audio_capture_device": "hw:0,0",
                "silence_seconds": "30",
                "owntone_output_name": "S", "owntone_volume_percent": "50"}
        from unittest.mock import patch as _patch
        reload_calls = []
        cfg = _minimal_config()

        with _patch("autostream_webui_post_handlers.load_config", return_value=cfg), \
             _patch("autostream_webui_post_handlers.parse_config") as mp, \
             _patch("autostream_webui_post_handlers.save_config"), \
             _patch("autostream_webui_post_handlers.mark_configured"), \
             _patch("autostream_webui_post_handlers.get_system_hostname", return_value="host"), \
             _patch("autostream_webui_post_handlers.set_system_hostname"), \
             _patch("autostream_webui_post_handlers.run_admin_cmd",
                    return_value=MagicMock(returncode=0, stderr="")), \
             _patch("autostream_live_config.update_live_owntone_runtime"), \
             _patch("autostream_live_config.identification"), \
             _patch("autostream_webui_post_handlers.send_setup_page"), \
             _patch("autostream_webui_post_handlers._set_flash_cookie"), \
             _patch("autostream_webui_post_handlers.build_top_banner_html", return_value=("", "")), \
             _patch("autostream_live_config.update_live_silence_seconds",
                    return_value=False), \
             _patch("autostream_runtime.request_config_reload",
                    side_effect=lambda: reload_calls.append(True)):
            p = mp.return_value
            p.audio1.capture_device = "hw:0,0"
            p.audio1.silence_threshold_dbfs = -60.0  # must match LINE_LEVEL_SILENCE_THRESHOLD_DBFS
            for attr in ("gain_db", "eq_40hz_db", "eq_100hz_db", "eq_8khz_db",
                         "stylus_life_hours", "belt_life_hours", "belt_life_years",
                         "bearing_life_hours", "bearing_life_years"):
                setattr(p.audio1, attr, 0.0)
            p.audio2.capture_device = "hw:1,0"
            p.audio2.silence_threshold_dbfs = -60.0
            for attr in ("gain_db", "eq_40hz_db", "eq_100hz_db", "eq_8khz_db",
                         "stylus_life_hours", "belt_life_hours", "belt_life_years",
                         "bearing_life_hours", "bearing_life_years"):
                setattr(p.audio2, attr, 0.0)
            p.audio2_enabled = False
            p.owntone.output_name = "S"
            p.owntone.volume_percent = 50
            p.owntone.base_url = "http://localhost:3689"
            p.owntone.output_offsets_ms = {}
            p.owntone.output_airplay_modes = {}
            p.general.silence_seconds = 10   # old value
            p.general.log_file = "/var/log/autostream.log"
            p.general.fifo_path = "/run/autostream/audio.fifo"
            p.updates.auto_update = False
            handle_setup_post(MagicMock(), MagicMock(), MagicMock(), urlencode(form))

        assert reload_calls, "request_config_reload must be called when update_live_silence_seconds fails"


# ---------------------------------------------------------------------------
# handle_setup_post — advertisement preference (advertise_appliance)
# ---------------------------------------------------------------------------

def _call_setup_post_advertise(
    form_data: dict,
    tmp_path: Path,
    old_advertise: bool = True,
    reconcile_ok: bool = True,
    second_save_fail: bool = False,
) -> dict:
    """Minimal helper focused on the advertise_appliance field-level update."""
    from urllib.parse import urlencode
    from autostream_webui_post_handlers import handle_setup_post

    body = urlencode(form_data)
    cfg = _minimal_config()
    saved_cfgs = []
    flash_calls = []
    reconcile_calls = []
    save_count = [0]

    def fake_save(path, data):
        save_count[0] += 1
        if second_save_fail and save_count[0] >= 2:
            raise OSError("disk full")
        saved_cfgs.append(dict(data))

    def fake_reconcile(version, advertise):
        reconcile_calls.append(advertise)
        return reconcile_ok

    with patch("autostream_webui_post_handlers.load_config", return_value=cfg), \
         patch("autostream_webui_post_handlers.parse_config") as mock_parse, \
         patch("autostream_webui_post_handlers.save_config", side_effect=fake_save), \
         patch("autostream_live_config.load_config", return_value=cfg), \
         patch("autostream_live_config.save_config", side_effect=fake_save), \
         patch("autostream_webui_post_handlers.mark_configured"), \
         patch("autostream_webui_post_handlers.get_system_hostname", return_value="host"), \
         patch("autostream_webui_post_handlers.set_system_hostname"), \
         patch("autostream_webui_post_handlers.run_admin_cmd",
               return_value=MagicMock(returncode=0, stderr="")), \
         patch("autostream_live_config.update_live_owntone_runtime"), \
         patch("autostream_live_config.identification"), \
         patch("autostream_webui_post_handlers.send_setup_page",
               side_effect=lambda h, s, a, **kw: flash_calls.append(kw)), \
         patch("autostream_webui_post_handlers._set_flash_cookie"), \
         patch("autostream_webui_post_handlers.build_top_banner_html", return_value=("", "")), \
         patch("autostream_runtime.request_config_reload"), \
         patch("autostream_appliances.reconcile_appliance_announcement",
               side_effect=fake_reconcile), \
         patch("autostream_webui_common.get_app_version", return_value="v1.0"):
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
        p.webui.advertise_appliance = old_advertise

        handle_setup_post(MagicMock(), MagicMock(), MagicMock(), body)

    return {
        "saved": saved_cfgs,
        "flash_calls": flash_calls,
        "reconcile_calls": reconcile_calls,
    }


class TestSetupPostAdvertisePreference:
    def test_no_sentinel_skips_reconcile(self, tmp_path):
        # When webui_advertise_appliance_present is absent, reconcile must not be called.
        form = {
            "audio_capture_device": "hw:0,0",
            "silence_seconds": "10",
            "owntone_output_name": "Speaker",
            "owntone_volume_percent": "50",
        }
        result = _call_setup_post_advertise(form, tmp_path, old_advertise=True)
        assert result["reconcile_calls"] == []

    def test_sentinel_present_value_unchanged_skips_reconcile(self, tmp_path):
        # Sentinel present but value didn't change → no reconcile call.
        form = {
            "audio_capture_device": "hw:0,0",
            "silence_seconds": "10",
            "owntone_output_name": "Speaker",
            "owntone_volume_percent": "50",
            "webui_advertise_appliance_present": "1",
            "webui_advertise_appliance": "1",   # checkbox checked → True, same as old_advertise=True
        }
        result = _call_setup_post_advertise(form, tmp_path, old_advertise=True)
        assert result["reconcile_calls"] == []

    def test_sentinel_present_value_changes_true_to_false(self, tmp_path):
        # old=True, form says disabled → reconcile(False) called.
        form = {
            "audio_capture_device": "hw:0,0",
            "silence_seconds": "10",
            "owntone_output_name": "Speaker",
            "owntone_volume_percent": "50",
            "webui_advertise_appliance_present": "1",
            # checkbox absent → new_advertise = False
        }
        result = _call_setup_post_advertise(form, tmp_path, old_advertise=True)
        assert result["reconcile_calls"] == [False]

    def test_sentinel_present_value_changes_false_to_true(self, tmp_path):
        # old=False, form says enabled → reconcile(True) called.
        form = {
            "audio_capture_device": "hw:0,0",
            "silence_seconds": "10",
            "owntone_output_name": "Speaker",
            "owntone_volume_percent": "50",
            "webui_advertise_appliance_present": "1",
            "webui_advertise_appliance": "1",  # checkbox checked → True
        }
        result = _call_setup_post_advertise(form, tmp_path, old_advertise=False)
        assert result["reconcile_calls"] == [True]

    def test_admin_failure_shows_error_flash(self, tmp_path):
        # When reconcile returns False, an error flash should be shown.
        form = {
            "audio_capture_device": "hw:0,0",
            "silence_seconds": "10",
            "owntone_output_name": "Speaker",
            "owntone_volume_percent": "50",
            "webui_advertise_appliance_present": "1",
        }
        result = _call_setup_post_advertise(form, tmp_path, old_advertise=True, reconcile_ok=False)
        assert result["flash_calls"], "expected an error flash when admin call fails"
        flash = result["flash_calls"][0]
        assert flash.get("flash_type") == "error"

    def test_field_level_save_on_success(self, tmp_path):
        # On success the field-level save must write advertise_appliance.
        form = {
            "audio_capture_device": "hw:0,0",
            "silence_seconds": "10",
            "owntone_output_name": "Speaker",
            "owntone_volume_percent": "50",
            "webui_advertise_appliance_present": "1",
        }
        result = _call_setup_post_advertise(form, tmp_path, old_advertise=True, reconcile_ok=True)
        # At least the field-level save (second save) must have run
        assert len(result["saved"]) >= 2, "expected field-level re-save after successful admin call"
        last_saved = result["saved"][-1]
        assert last_saved.get("webui", {}).get("advertise_appliance") is False


# ---------------------------------------------------------------------------
# handle_setup_post — output usage poll interval persistence
# ---------------------------------------------------------------------------

class TestSetupPostOutputUsagePollInterval:
    def test_poll_interval_persisted_when_sentinel_present(self, tmp_path):
        form = {
            "audio_capture_device": "hw:0,0",
            "silence_seconds": "10",
            "owntone_output_name": "S",
            "owntone_volume_percent": "50",
            "webui_show_master_volume_present": "1",
            "webui_output_usage_poll_interval_present": "1",
            "webui_output_usage_poll_interval_seconds": "7",
        }
        result = _call_setup_post(form, tmp_path)
        assert result["saved"], "save_config must be called"
        saved = result["saved"][0]
        assert saved.get("webui", {}).get("output_usage_poll_interval_seconds") == 7

    def test_poll_interval_not_persisted_when_sentinel_absent(self, tmp_path):
        form = {
            "audio_capture_device": "hw:0,0",
            "silence_seconds": "10",
            "owntone_output_name": "S",
            "owntone_volume_percent": "50",
            # no webui_output_usage_poll_interval_present
        }
        result = _call_setup_post(form, tmp_path)
        if result["saved"]:
            saved = result["saved"][0]
            assert "output_usage_poll_interval_seconds" not in saved.get("webui", {})

    def test_poll_interval_normalized_on_invalid_input(self, tmp_path):
        form = {
            "audio_capture_device": "hw:0,0",
            "silence_seconds": "10",
            "owntone_output_name": "S",
            "owntone_volume_percent": "50",
            "webui_show_master_volume_present": "1",
            "webui_output_usage_poll_interval_present": "1",
            "webui_output_usage_poll_interval_seconds": "999",  # above max
        }
        result = _call_setup_post(form, tmp_path)
        assert result["saved"]
        saved = result["saved"][0]
        # out-of-range → normalized to default (3)
        assert saved.get("webui", {}).get("output_usage_poll_interval_seconds") == 3

    def test_webui_sentinel_behavior_preserved(self, tmp_path):
        # When webui_show_master_volume_present is absent, webui section must not be created.
        form = {
            "audio_capture_device": "hw:0,0",
            "silence_seconds": "10",
            "owntone_output_name": "S",
            "owntone_volume_percent": "50",
            # No sentinel at all
        }
        result = _call_setup_post(form, tmp_path)
        if result["saved"]:
            assert "webui" not in result["saved"][0]


# ---------------------------------------------------------------------------
# Output changes: occupancy protection
# ---------------------------------------------------------------------------

import autostream_appliance_models as _am
from autostream_state import Origin


def _speaker(id_: str, name: str, *, selected: bool = False):
    from fake_store import FakeStore
    return FakeStore.output_row(
        id_, name, selected=selected, volume_percent=40 if selected else 0)


def _make_usage(owner_name: str = "living-room"):
    from autostream_output_usage import OutputUsage
    import time
    now = time.monotonic()
    return OutputUsage(
        output_name="Kitchen",
        owner_name=owner_name,
        owner_ip="192.168.1.10",
        owner_port=5353,
        service_name="living-room._autostream-playing._tcp.local.",
        observed_at=now,
        expires_at=now + 10,
    )


@pytest.fixture
def player_writes(monkeypatch):
    """Record every write the player service receives; all succeed unless
    the test queues an answer."""
    import autostream_player_service as ps
    from types import SimpleNamespace
    rec = SimpleNamespace(calls=[], answers=[])

    def answer():
        return rec.answers.pop(0) if rec.answers else _make_result_ok()

    def update_output(base_url, out_id, **kwargs):
        rec.calls.append(("update_output", out_id, kwargs))
        return answer()

    def submit_output_pin(base_url, out_id, pin, timeout=None):
        rec.calls.append(("submit_output_pin", out_id, pin))
        return answer()

    monkeypatch.setattr(ps, "update_output", update_output)
    monkeypatch.setattr(ps, "submit_output_pin", submit_output_pin)
    return rec


def _coordinator_change(body):
    return _am.submit_output_change(
        body, requester="coordinator", pin_requester=None, origin=Origin.SYSTEM)


class TestOutputMutationOccupancyProtection:
    def _call(self, body, *, usage=None, speakers=None):
        from fake_store import FakeStore
        FakeStore().outputs(speakers if speakers is not None else [_speaker("42", "Kitchen")])
        with patch("autostream_output_usage.usage_for_output", return_value=usage):
            return _coordinator_change(body)

    def test_enabling_occupied_output_returns_output_in_use(self, player_writes):
        result = self._call({"id": "42", "selected": True, "volume": 50},
                            usage=_make_usage("living-room"))
        assert result["ok"] is False
        assert result["error"] == "output_in_use"
        assert result["owner"] == "living-room"
        assert player_writes.calls == []

    def test_disabling_occupied_output_is_allowed(self, player_writes):
        result = self._call({"id": "42", "selected": False},
                            usage=_make_usage("living-room"),
                            speakers=[_speaker("42", "Kitchen", selected=True)])
        assert result["ok"] is True

    def test_pin_op_bypasses_occupancy_check(self, player_writes):
        from fake_store import FakeStore
        FakeStore().outputs([_speaker("42", "Kitchen")])
        with patch("autostream_output_usage.usage_for_output",
                   return_value=_make_usage("living-room")):
            result = _am.submit_output_change(
                {"id": "42", "op": "pin", "pin": "1234"},
                requester="webui", pin_requester="webui")
        assert result["ok"] is True, result

    def test_enabling_unoccupied_output_succeeds(self, player_writes):
        result = self._call({"id": "42", "selected": True, "volume": 50}, usage=None)
        assert result["ok"] is True

    def test_failing_occupancy_check_fails_open(self, player_writes):
        """When the usage check raises, the enable proceeds."""
        from fake_store import FakeStore
        FakeStore().outputs([_speaker("42", "Kitchen")])
        with patch("autostream_output_usage.usage_for_output",
                   side_effect=RuntimeError("timeout")):
            result = _coordinator_change({"id": "42", "selected": True, "volume": 50})
        assert result["ok"] is True

    def test_occupancy_check_is_cache_only_no_refresh(self, player_writes):
        """usage_for_output is called but refresh_now is never called."""
        from fake_store import FakeStore
        FakeStore().outputs([_speaker("42", "Kitchen")])
        refresh_calls = []
        with patch("autostream_output_usage.usage_for_output", return_value=None), \
             patch("autostream_output_usage.refresh_now",
                   side_effect=lambda *a, **k: refresh_calls.append(1)):
            _coordinator_change({"id": "42", "selected": True, "volume": 50})
        assert refresh_calls == [], "refresh_now must not be called from mutation path"

    def test_browser_supplied_name_cannot_bypass_occupancy(self, player_writes):
        """The browser's body.name is ignored; the check uses the name the
        appliance has for the speaker."""
        from fake_store import FakeStore
        FakeStore().outputs([_speaker("42", "Kitchen")])
        asked = []

        def usage_for(name):
            asked.append(name)
            return _make_usage("living-room")

        with patch("autostream_output_usage.usage_for_output", side_effect=usage_for):
            result = _coordinator_change(
                {"id": "42", "selected": True, "volume": 50, "name": "not-occupied"})
        assert result["error"] == "output_in_use"
        assert asked == ["Kitchen"]

    def test_volume_change_on_already_selected_output_is_allowed(self, player_writes):
        """selected:true for an already-on output must not be blocked by occupancy."""
        result = self._call({"id": "42", "selected": True, "volume": 80},
                            usage=_make_usage("living-room"),
                            speakers=[_speaker("42", "Kitchen", selected=True)])
        assert result["ok"] is True
        assert player_writes.calls == [
            ("update_output", "42", dict(volume_percent=80, timeout=3.0))]

    def test_successful_enable_shows_the_speaker_selected(self, player_writes):
        from output_fakes import snap
        self._call({"id": "42", "selected": True, "volume": 50})
        assert snap().unit("42").selected is True

    def test_successful_disable_shows_the_speaker_not_selected(self, player_writes):
        from output_fakes import snap
        self._call({"id": "42", "selected": False},
                   speakers=[_speaker("42", "Kitchen", selected=True)])
        assert snap().unit("42").selected is False

    def test_failed_enable_leaves_the_speaker_not_selected(self, player_writes):
        from output_fakes import snap
        player_writes.answers.append(_make_result_err("owntone_error", "OwnTone refused"))
        result = self._call({"id": "42", "selected": True, "volume": 50})
        assert result == {"ok": False, "id": "42", "error": "OwnTone refused",
                          "pin_invalid": False}
        assert snap().unit("42").selected is False

    def test_failed_disable_reports_the_player_error(self, player_writes):
        player_writes.answers.append(_make_result_err("owntone_error", "OwnTone refused"))
        result = self._call({"id": "42", "selected": False},
                            speakers=[_speaker("42", "Kitchen", selected=True)])
        assert result["ok"] is False
        assert result["error"] == "OwnTone refused"

    def test_pin_required_replies_with_the_flag_and_leaves_the_speaker_off(self, player_writes):
        from output_fakes import snap
        player_writes.answers.append(_make_result_err("pin_required", "PIN required"))
        result = self._call({"id": "42", "selected": True, "volume": 50})
        assert result == {"ok": False, "pin_required": True, "id": "42",
                          "output_name": "", "error": "PIN required"}
        assert snap().unit("42").selected is False

    def test_encoder_capacity_maps_to_error_and_leaves_the_speaker_off(self, player_writes):
        """Encoder-capacity rejection maps to {ok:False, error:"encoder_capacity"} (output not enabled)."""
        from output_fakes import snap
        player_writes.answers.append(_make_result_err(
            "encoder_capacity", "Output declined: appliance CPU cannot encode another stream"))
        result = self._call({"id": "42", "selected": True, "volume": 50})
        assert result == {"ok": False, "id": "42", "error": "encoder_capacity"}
        assert snap().unit("42").selected is False

    def test_subsequent_enable_after_disable_blocked_when_occupied(self, player_writes):
        """Disable then re-enable: the occupancy check fires because the
        disable left the speaker not selected."""
        self._call({"id": "42", "selected": False},
                   speakers=[_speaker("42", "Kitchen", selected=True)])
        with patch("autostream_output_usage.usage_for_output",
                   return_value=_make_usage("living-room")):
            result = _coordinator_change({"id": "42", "selected": True, "volume": 50})
        assert result["error"] == "output_in_use"


# ---------------------------------------------------------------------------
# handle_output_update: the user's choice of silence
#
# A successful user disable that leaves no speaker selected sets
# snapshot.outputs.silence_chosen; a successful user enable clears it. A
# change the coordinator makes itself does not set it, and a PIN submission
# alone does not touch it.
# ---------------------------------------------------------------------------

class TestOutputUpdateSilenceChosen:
    def test_disable_to_zero_outputs_chooses_silence(self, tmp_path):
        from output_fakes import snap
        r = _call_output_update(
            {"id": "42", "selected": False}, tmp_path=tmp_path,
            speakers=[_speaker("42", "Kitchen", selected=True)])
        _, data = r["calls"][0]
        assert data["ok"] is True
        assert snap().silence_chosen is True

    def test_disable_with_another_output_still_selected_is_not_a_choice(self, tmp_path):
        from output_fakes import snap
        r = _call_output_update(
            {"id": "42", "selected": False}, tmp_path=tmp_path,
            speakers=[_speaker("42", "Kitchen", selected=True),
                      _speaker("43", "Bedroom", selected=True)])
        _, data = r["calls"][0]
        assert data["ok"] is True
        assert snap().silence_chosen is False

    def test_enable_ends_the_choice(self, tmp_path):
        from output_fakes import snap
        speakers = [_speaker("42", "Kitchen", selected=True)]
        _call_output_update({"id": "42", "selected": False}, tmp_path=tmp_path,
                            speakers=speakers)
        assert snap().silence_chosen is True

        r = _call_output_update({"id": "42", "selected": True, "volume": 50},
                                tmp_path=tmp_path, speakers=speakers)
        _, data = r["calls"][0]
        assert data["ok"] is True
        assert snap().silence_chosen is False

    def test_pin_op_alone_does_not_touch_it(self, tmp_path):
        from output_fakes import snap
        _call_output_update(
            {"id": "42", "selected": False}, tmp_path=tmp_path,
            speakers=[_speaker("42", "Kitchen", selected=True)])
        assert snap().silence_chosen is True
        r = _call_output_update(
            {"id": "42", "op": "pin", "pin": "1234"},
            tmp_path=tmp_path,
            pin_result=_make_result_ok(),
        )
        _, data = r["calls"][0]
        assert data["ok"] is True
        assert snap().silence_chosen is True


# ---------------------------------------------------------------------------
# Output changes: who is acting (origin) decides whether silence is chosen
# ---------------------------------------------------------------------------

class TestOutputChangeOrigin:
    def test_coordinator_switch_off_is_not_a_choice_of_silence(self, player_writes):
        from fake_store import FakeStore
        from output_fakes import snap
        FakeStore().outputs([_speaker("42", "Kitchen", selected=True)])
        result = _coordinator_change({"id": "42", "selected": False})
        assert result["ok"] is True
        assert snap().silence_chosen is False

    def test_user_pin_op_leaves_the_choice_alone(self, player_writes):
        from fake_store import FakeStore
        from output_fakes import snap
        FakeStore().outputs([_speaker("42", "Kitchen")])
        result = _am.submit_output_change(
            {"id": "42", "op": "pin", "pin": "1234"},
            requester="webui", pin_requester="webui")
        assert result["ok"] is True
        assert snap().silence_chosen is False

    def test_user_disable_to_zero_chooses_silence(self, player_writes):
        from fake_store import FakeStore
        from output_fakes import snap
        FakeStore().outputs([_speaker("42", "Kitchen", selected=True)])
        _am.submit_output_change(
            {"id": "42", "selected": False}, requester="webui", pin_requester="webui")
        assert snap().silence_chosen is True


# ---------------------------------------------------------------------------
# Poll-driven PIN prompt: source-string checks (same "grep the source"
# style used elsewhere for embedded JS -- there is no browser/DOM harness
# in this test suite).
# ---------------------------------------------------------------------------

class TestPollDrivenPinPromptSource:
    def test_home_cards_script_defines_run_pin_flow(self):
        from autostream_webui_assets import HOME_CARDS_SCRIPT
        assert "function runPinFlow" in HOME_CARDS_SCRIPT

    def test_home_cards_script_defines_maybe_prompt_for_pin(self):
        from autostream_webui_assets import HOME_CARDS_SCRIPT
        assert "function maybePromptForPin" in HOME_CARDS_SCRIPT

    def test_airplay_page_calls_maybe_prompt_for_pin_from_outputs_poll(self):
        source = _source_text.module_text("autostream_webui_page_airplay")
        assert "maybePromptForPin(j.outputs)" in source


class TestOutputRequesterPassed:
    def test_the_local_handler_names_the_webui_as_requester(self, tmp_path):
        state = _make_state(tmp_path)
        with patch("autostream_webui_post_handlers.send_json"), \
             patch("autostream_webui_post_handlers.locked_load_config",
                   return_value={"general": {}, "owntone": {"base_url": "http://localhost:3689"}}), \
             patch("autostream_webui_post_handlers.parse_config") as mock_parse, \
             patch("autostream_appliance_models.submit_output_change",
                   return_value={"ok": True}) as mut:
            mock_parse.return_value.owntone.base_url = "http://localhost:3689"
            mock_parse.return_value.owntone.output_offsets_ms = {}
            mock_parse.return_value.owntone.output_airplay_modes = {}
            handle_output_update(MagicMock(), state, json.dumps({"id": "1", "selected": True}))
        assert mut.call_args.kwargs["requester"] == "webui"
        assert mut.call_args.kwargs["pin_requester"] == "webui"

    def test_the_federation_route_names_the_webui_as_requester(self):
        import autostream_webui_api as api
        parsed = MagicMock()
        parsed.owntone.base_url = "http://localhost:3689"
        parsed.owntone.output_offsets_ms = {}
        parsed.owntone.output_airplay_modes = {}
        with patch("autostream_webui_api.send_json"), \
             patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.submit_output_change",
                   return_value={"ok": True}) as mut:
            api.send_federation_output_json(
                MagicMock(), MagicMock(), json.dumps({"id": "1", "selected": True}))
        assert mut.call_args.kwargs["requester"] == "peer"
        assert mut.call_args.kwargs["pin_requester"] == "webui"


# ---------------------------------------------------------------------------
# Home page PIN dialog (page script text)
# ---------------------------------------------------------------------------

class TestHomePinDialogScript:
    def test_pin_flow_posts_one_pair_and_enable_request(self):
        import autostream_webui_assets as assets
        src = assets.HOME_CARDS_SCRIPT
        assert "postPairAndEnable" in src
        assert "selected: true" in src
        assert "op:'pin'" in src
        assert "postPinOnly" not in src
        # The pin-only second request is gone: a good PIN is the last call.
        flow = src[src.index("async function runPinFlow"):src.index("async function maybePromptForPin")]
        assert "postOutputUpdate" not in flow

    def test_poll_prompt_stands_down_for_a_foreign_claim(self):
        import autostream_webui_assets as assets
        src = assets.HOME_CARDS_SCRIPT
        body = src[src.index("async function maybePromptForPin"):src.index("async function sendUpdate")]
        assert "pin_claim" in body
        assert "'webui'" in body

    def test_pin_dialog_input_is_numeric_and_bounded(self):
        import autostream_webui_page_airplay as page
        src = inspect.getsource(page)
        assert src.count('pattern="[0-9]*" maxlength="8"') == 2
        assert 'id="pinModalNote"' in src

    def test_rate_limited_reply_shows_the_wait(self):
        import autostream_webui_assets as assets
        src = assets.HOME_CARDS_SCRIPT
        assert "rate_limited" in src
        assert "retry_after_s" in src
        assert "before retry" in src
