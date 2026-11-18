"""Priority 7 — webui post handlers tests.

Covers the output change the browser routes make (output ID, PIN auth,
pin_required/pin_invalid, offset/mode forwarding, occupancy protection).
"""
from __future__ import annotations

import inspect
import json
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

from webui import common
from webui.browser import home_model


def handle_output_update(handler, state, body: str) -> None:
    """The output change the browser routes make: the request's speaker with its
    configured offset and mode, applied through submit_output_change."""
    try:
        payload = json.loads(body)
        out_id = str(payload.get("id") or "").strip()
        start = common.output_start_args(state, out_id) if out_id else {}
        result = home_model.submit_output_change(
            payload, requester="webui", pin_requester="webui",
            offset_ms=start.get("offset_ms"), mode=start.get("mode"),
        )
        common.send_json(handler, 200, result)
    except Exception as e:
        common.send_json(handler, 200, {"ok": False, "error": str(e)})


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


def _speaker(id_: str, name: str, *, selected: bool = False):
    from fake_store import FakeStore
    return FakeStore.output_row(
        id_, name, selected=selected, volume_percent=40 if selected else 0)


def _occupy(owner_name: str = "living-room") -> None:
    """Another appliance, by hostname, is playing Kitchen."""
    from autostream_state.outputs import get_authority
    get_authority().set_remote_usage({"kitchen": ("a" * 20, owner_name)})


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
    def _call(self, body, *, occupied_by=None, speakers=None):
        from fake_store import FakeStore
        FakeStore().outputs(speakers if speakers is not None else [_speaker("42", "Kitchen")])
        if occupied_by is not None:
            _occupy(occupied_by)
        return _coordinator_change(body)

    def test_enabling_occupied_output_returns_output_in_use(self, player_writes):
        result = self._call({"id": "42", "selected": True, "volume": 50},
                            occupied_by="living-room")
        assert result["ok"] is False
        assert result["error"] == "output_in_use"
        assert result["owner"] == "living-room"
        assert player_writes.calls == []

    def test_disabling_occupied_output_is_allowed(self, player_writes):
        result = self._call({"id": "42", "selected": False},
                            occupied_by="living-room",
                            speakers=[_speaker("42", "Kitchen", selected=True)])
        assert result["ok"] is True

    def test_pin_op_bypasses_occupancy_check(self, player_writes):
        from fake_store import FakeStore
        FakeStore().outputs([_speaker("42", "Kitchen")])
        _occupy("living-room")
        result = webui_home_model.submit_output_change(
            {"id": "42", "op": "pin", "pin": "1234"},
            requester="webui", pin_requester="webui")
        assert result["ok"] is True, result

    def test_enabling_unoccupied_output_succeeds(self, player_writes):
        result = self._call({"id": "42", "selected": True, "volume": 50})
        assert result["ok"] is True

    def test_browser_supplied_name_cannot_bypass_occupancy(self, player_writes):
        """The browser's body.name is ignored; the check uses the name the
        appliance has for the speaker."""
        result = self._call({"id": "42", "selected": True, "volume": 50, "name": "not-occupied"},
                            occupied_by="living-room")
        assert result["error"] == "output_in_use"

    def test_volume_change_on_already_selected_output_is_allowed(self, player_writes):
        """selected:true for an already-on output must not be blocked by occupancy."""
        result = self._call({"id": "42", "selected": True, "volume": 80},
                            occupied_by="living-room",
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
        _occupy("living-room")
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


class TestOutputRequesterPassed:
    def test_the_local_handler_names_the_webui_as_requester(self, tmp_path):
        state = _make_state(tmp_path)
        with patch("webui.common.send_json"), \
             patch("webui.browser.home_model.submit_output_change",
                   return_value={"ok": True}) as mut:
            handle_output_update(MagicMock(), state, json.dumps({"id": "1", "selected": True}))
        assert mut.call_args.kwargs["requester"] == "webui"
        assert mut.call_args.kwargs["pin_requester"] == "webui"

# ---------------------------------------------------------------------------
# Home page PIN dialog (page script text)
# ---------------------------------------------------------------------------

class TestHomePinDialogScript:
    def test_pin_dialog_input_is_numeric_and_bounded(self):
        import webui.browser.home as page
        src = inspect.getsource(page)
        assert src.count('pattern="[0-9]*" maxlength="8"') == 1
        assert 'id="pinModalNote"' in src

    def test_rate_limited_reply_shows_the_wait(self):
        src = _source_text.static_text("page/home/home_speakers.js")
        assert "rate_limited" in src
        assert "retry_after_s" in src
        assert "before retry" in src
