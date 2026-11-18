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
from settings_fixtures import fixed_view

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from webui.browser.post_handlers import handle_output_update
from webui.browser.post_handlers import handle_live_input_gain_update
from webui.browser.post_handlers import handle_live_input_eq_update


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_state(tmp_path: Path, *, offsets=None, modes=None, config_file=True) -> MagicMock:
    cfg = {"general": {}, "owntone": {"base_url": "http://localhost:3689",
                                      "offsets": offsets or {}, "airplay_modes": modes or {}}}
    cfg_path = tmp_path / "autostream.json"
    if config_file:
        cfg_path.write_text(json.dumps(cfg))
    state = MagicMock()
    state.config_path = cfg_path
    state.settings = fixed_view(cfg)
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
                        offsets=None, modes=None, config_file=True) -> dict:
    """Run the output route's handler against a patched player.

    *speakers* are the OutputInfo rows the authority knows; by default the
    body's own id is arranged as a speaker that is off. The reply is in
    "calls"; every write the player received is in "writes"."""
    from autostream_players import ActionResult
    from fake_store import FakeStore

    sent = []
    writes = []
    handler = MagicMock()
    state = _make_state(tmp_path, offsets=offsets, modes=modes, config_file=config_file)

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

    with patch("webui.common.send_json", side_effect=fake_send_json), \
         patch("autostream_player_service.update_output", side_effect=fake_update_output), \
         patch("autostream_player_service.submit_output_pin", side_effect=fake_submit_output_pin):
        handle_output_update(handler, state, json.dumps(body))

    return {"calls": sent, "writes": writes}


def _call_eq(body: str | dict, tmp_path: Path) -> dict:
    if isinstance(body, dict):
        body = json.dumps(body)
    sent = []

    def fake_send_json(h, code, data):
        sent.append((code, data))

    with patch("webui.common.send_json", side_effect=fake_send_json), \
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
    from autostream_settings import SettingsStore, as_view
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
        tf.write("{}")
        cfg_path = tf.name
    try:
        store = SettingsStore(cfg_path, _save_interval_seconds=9999, _writer=MagicMock())
        state = MagicMock()
        state.settings = as_view(store)
        with patch("webui.common.send_json", side_effect=fake_send_json), \
             patch("webui.common.send_json", side_effect=fake_send_json), \
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

        with patch("webui.common.send_json", side_effect=fake_send_json), \
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

        import webui.browser.post_handlers as _ph
        orig_loads = webui_post_handlers.json.loads

        def patched_loads(s, **kw):
            result = orig_loads(s, **kw)
            if isinstance(result, dict):
                result["eq_40hz_db"] = float("nan")
            return result

        with patch("webui.common.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_monitor_control.set_live_input_eq", mock_eq), \
             patch.object(webui_post_handlers.json, "loads", side_effect=patched_loads):
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
        import webui.browser.post_handlers as _ph
        orig_loads = webui_post_handlers.json.loads

        def patched_loads(s, **kw):
            result = orig_loads(s, **kw)
            if isinstance(result, dict):
                result["eq_8khz_db"] = float("inf")
            return result

        with patch("webui.common.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_monitor_control.set_live_input_eq", mock_eq), \
             patch.object(webui_post_handlers.json, "loads", side_effect=patched_loads):
            handle_live_input_eq_update(MagicMock(), MagicMock(), body)

        code, data = sent[0]
        assert code == 400
        mock_eq.assert_not_called()

    def test_negative_infinity_rejected(self, tmp_path):
        body = json.dumps({"input": 1, "eq_40hz_db": 0, "eq_100hz_db": 0, "eq_8khz_db": 0})
        sent = []
        mock_eq = MagicMock(return_value=True)
        import webui.browser.post_handlers as _ph
        orig_loads = webui_post_handlers.json.loads

        def patched_loads(s, **kw):
            result = orig_loads(s, **kw)
            if isinstance(result, dict):
                result["eq_100hz_db"] = float("-inf")
            return result

        with patch("webui.common.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_monitor_control.set_live_input_eq", mock_eq), \
             patch.object(webui_post_handlers.json, "loads", side_effect=patched_loads):
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
        with patch("webui.common.send_json", side_effect=fake_send_json), \
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
        import webui.browser.post_handlers as _ph
        orig_loads = webui_post_handlers.json.loads

        def patched_loads(s, **kw):
            result = orig_loads(s, **kw)
            if isinstance(result, dict):
                result["gain_db"] = float("nan")
            return result

        with patch("webui.common.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_monitor_control.set_live_input_gain", return_value=True), \
             patch.object(webui_post_handlers.json, "loads", side_effect=patched_loads):
            handle_live_input_gain_update(MagicMock(), MagicMock(), body)

        code, data = sent[0]
        assert code == 400
        assert data["ok"] is False

    def test_gain_infinity_rejected(self, tmp_path):
        body = json.dumps({"input": 1, "gain_db": 0})
        sent = []
        import webui.browser.post_handlers as _ph
        orig_loads = webui_post_handlers.json.loads

        def patched_loads(s, **kw):
            result = orig_loads(s, **kw)
            if isinstance(result, dict):
                result["gain_db"] = float("inf")
            return result

        with patch("webui.common.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_monitor_control.set_live_input_gain", return_value=True), \
             patch.object(webui_post_handlers.json, "loads", side_effect=patched_loads):
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

    def test_a_missing_configuration_file_does_not_stop_a_switch(self, tmp_path):
        """The offset and mode come from the in-memory settings, not the file."""
        r = _call_output_update(
            {"id": "99", "selected": True, "volume": 75}, tmp_path=tmp_path,
            offsets={"99": 200}, modes={"99": "alac"}, config_file=False,
        )
        assert r["calls"][0][1].get("ok") is not False
        (name, out_id, kwargs), = r["writes"]
        assert kwargs["offset_ms"] == 200


# ---------------------------------------------------------------------------
# Output changes: occupancy protection
# ---------------------------------------------------------------------------

from autostream_state import Origin
import webui.browser.home_model as webui_home_model
import webui.browser.post_handlers as webui_post_handlers


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
    return webui_home_model.submit_output_change(
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
            result = webui_home_model.submit_output_change(
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
        result = webui_home_model.submit_output_change(
            {"id": "42", "op": "pin", "pin": "1234"},
            requester="webui", pin_requester="webui")
        assert result["ok"] is True
        assert snap().silence_chosen is False

    def test_user_disable_to_zero_chooses_silence(self, player_writes):
        from fake_store import FakeStore
        from output_fakes import snap
        FakeStore().outputs([_speaker("42", "Kitchen", selected=True)])
        webui_home_model.submit_output_change(
            {"id": "42", "selected": False}, requester="webui", pin_requester="webui")
        assert snap().silence_chosen is True


# ---------------------------------------------------------------------------
# Poll-driven PIN prompt: source-string checks (same "grep the source"
# style used elsewhere for embedded JS -- there is no browser/DOM harness
# in this test suite).
# ---------------------------------------------------------------------------

class TestPollDrivenPinPromptSource:
    def test_home_cards_script_defines_run_pin_flow(self):
        assert "function runPinFlow" in _source_text.static_text("page/home_cards.js")

    def test_home_cards_script_defines_maybe_prompt_for_pin(self):
        assert "function maybePromptForPin" in _source_text.static_text("page/home_cards.js")

    def test_airplay_page_calls_maybe_prompt_for_pin_from_outputs_poll(self):
        assert "maybePromptForPin(j.outputs)" in _source_text.static_text("page/home.js")


class TestOutputRequesterPassed:
    def test_the_local_handler_names_the_webui_as_requester(self, tmp_path):
        state = _make_state(tmp_path)
        with patch("webui.common.send_json"), \
             patch("webui.browser.home_model.submit_output_change",
                   return_value={"ok": True}) as mut:
            handle_output_update(MagicMock(), state, json.dumps({"id": "1", "selected": True}))
        assert mut.call_args.kwargs["requester"] == "webui"
        assert mut.call_args.kwargs["pin_requester"] == "webui"

    def test_the_federation_route_names_the_webui_as_requester(self):
        import autostream_webui_api as api
        parsed = MagicMock()
        parsed.owntone.base_url = "http://localhost:3689"
        parsed.owntone.output_offsets_ms = {}
        parsed.owntone.output_airplay_modes = {}
        with patch("webui.common.send_json"), \
             patch("webui.common._config_snapshot", return_value=parsed), \
             patch("webui.browser.home_model.submit_output_change",
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
        src = _source_text.static_text("page/home_cards.js")
        assert "postPairAndEnable" in src
        assert "selected: true" in src
        assert "op:'pin'" in src
        assert "postPinOnly" not in src
        # The pin-only second request is gone: a good PIN is the last call.
        flow = src[src.index("async function runPinFlow"):src.index("async function maybePromptForPin")]
        assert "postOutputUpdate" not in flow

    def test_poll_prompt_stands_down_for_a_foreign_claim(self):
        src = _source_text.static_text("page/home_cards.js")
        body = src[src.index("async function maybePromptForPin"):src.index("async function sendUpdate")]
        assert "pin_claim" in body
        assert "'webui'" in body

    def test_pin_dialog_input_is_numeric_and_bounded(self):
        import webui.browser.home as page
        src = inspect.getsource(page)
        assert src.count('pattern="[0-9]*" maxlength="8"') == 2
        assert 'id="pinModalNote"' in src

    def test_rate_limited_reply_shows_the_wait(self):
        src = _source_text.static_text("page/home_cards.js")
        assert "rate_limited" in src
        assert "retry_after_s" in src
        assert "before retry" in src
