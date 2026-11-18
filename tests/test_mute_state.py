"""Tests for the per-speaker mute: how the output authority holds it, the
dial's mute and volume routes that drive it, the status fields that report it,
the output-change rules, the end of a session, and the WebUI's now-playing header/level slot (the volume slider
is the WebUI's only unmute path).

Covers:
1.  The authority's mute model: a mute remembers each speaker's level, a
    muted selection reads as muted, a speaker joining it comes on silent, a
    user level change ends one speaker's mute, a deselect forgets it.
2.  POST /api/dial/mute: mute, restore, partial failures, idempotence.
3.  POST /api/dial/volume: a non-positive delta while muted is a no-op that
    reports the intended level and muted:true; a positive delta while muted
    restores with no step added and reports muted:false; the unmuted path
    is unchanged apart from carrying muted:false.
4.  POST /api/dial/status: master_volume/muted while muted and unmuted.
5.  submit_output_change(): enable-while-muted stays silent and remembers
    the requested level; a non-user volume-only write on a muted output
    remembers instead of writing; an explicit user volume write on a muted
    output ends its mute and writes normally; disable forgets the mute.
6.  build_output_list()/build_home_state(): intended levels and the muted
    flag.
7.  The end of a session clears every mute.
8.  The WebUI now-playing header text (not a separate control) is the only
    mute indication; the old mute button/icon and the browser POST /api/mute
    route are both gone.
9.  The now-playing level slot markup: VU meter only, no mute button, in
    both the local and remote-shell renders.
10. The now-playing header gains " (Muted)" while playing and muted, never
    on "Ready", and never when unmuted.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_player_service as player_service
from fake_store import (
    FakeStore, fake_levels, fake_outputs, fake_playback, fake_playback_mock, fake_repeat,
    fake_session, fake_track,
)
from autostream_players import ActionResult, OutputInfo
from autostream_state import Origin, store
from autostream_state.outputs import PlayerServiceBackend, get_authority


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _output(id_: str, volume: int, selected: bool = True):
    return OutputInfo(id=id_, name=id_, selected=selected, volume_percent=volume)


def _update_result(ok=True):
    return ActionResult(
        ok=ok, error="" if ok else "connection refused", error_code="" if ok else "request_failed")


def _parsed_config(volume_percent=20):
    parsed = SimpleNamespace()
    parsed.owntone = SimpleNamespace(base_url="http://localhost:3689", volume_percent=volume_percent)
    return parsed


def _handler():
    h = MagicMock()
    h.wfile = io.BytesIO()
    return h


def _disabled_track_id_snapshot():
    from track_id.models import disabled_snapshot
    return disabled_snapshot()


@pytest.fixture
def writes(monkeypatch):
    """The player service: every volume write is recorded as (id, kwargs) in
    order, and answered from `results` (default: ok)."""
    rec = SimpleNamespace(calls=[], results=[])

    def update_output(base_url, out_id, **kwargs):
        rec.calls.append((out_id, kwargs))
        return rec.results.pop(0) if rec.results else _update_result(True)

    monkeypatch.setattr(player_service, "update_output", update_output)
    rec.levels = lambda: [(i, kw.get("volume_percent")) for i, kw in rec.calls]
    return rec


def _arrange(*outputs):
    FakeStore().outputs(list(outputs))


def _muted(writes, *outputs):
    """Adopt *outputs* and mute the selected ones, remembering their levels."""
    _arrange(*outputs)
    get_authority().mute_all(Origin.USER)
    writes.calls.clear()


def _dial(fn, body, parsed=None):
    """Drive a dial route and return what it sent."""
    import autostream_webui_api as api
    captured = {}

    def fake_send_json(h, code, payload):
        captured["code"] = code
        captured["body"] = payload

    with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
         patch("autostream_webui_api.dial_authorization",
               return_value=__import__("autostream_dials").AUTH_AUTHORIZED), \
         patch("autostream_webui_api._config_snapshot", return_value=parsed or _parsed_config()), \
         patch("autostream_webui_api.get_appliance_id", return_value=None):
        getattr(api, fn)(_handler(), MagicMock(), {"dial_id": "uid", **body})
    return captured


def snap():
    return store().snapshot().outputs


# ---------------------------------------------------------------------------
# 1. The authority's mute model
# ---------------------------------------------------------------------------

class TestMuteModel:
    def test_starts_unmuted(self, writes):
        _arrange(_output("o1", 40))
        assert snap().muted_all is False and snap().unit("o1").muted is False

    def test_a_mute_remembers_the_level_and_reports_it_as_the_volume(self, writes):
        _muted(writes, _output("o1", 40))
        assert snap().muted_all is True
        assert snap().unit("o1").volume == 40
        assert snap().unit("o1").muted is True

    def test_a_second_mute_never_overwrites_the_remembered_level(self, writes):
        _muted(writes, _output("o1", 40))
        get_authority().mute_all(Origin.USER)
        assert snap().unit("o1").volume == 40
        assert writes.calls == []

    def test_a_speaker_switched_on_while_muted_comes_on_silent_and_remembers_its_level(self, writes):
        _muted(writes, _output("o1", 40), _output("o2", 0, selected=False))
        get_authority().select("o2", Origin.USER, volume=55)
        assert writes.levels() == [("o2", 0)]
        assert snap().unit("o2").muted is True and snap().unit("o2").volume == 55

    def test_a_user_level_change_ends_the_mute_of_that_speaker_only(self, writes):
        _muted(writes, _output("o1", 40), _output("o2", 60))
        get_authority().set_volume("o1", 25, Origin.USER)
        assert writes.levels() == [("o1", 25)]
        assert snap().unit("o1").muted is False and snap().unit("o2").muted is True
        assert snap().muted_all is False

    def test_a_level_change_by_anyone_else_only_moves_what_a_restore_brings_back(self, writes):
        _muted(writes, _output("o1", 40))
        get_authority().set_volume("o1", 25, Origin.SYSTEM)
        assert writes.calls == []
        assert snap().unit("o1").volume == 25 and snap().unit("o1").muted is True

    def test_switching_a_speaker_off_forgets_its_mute(self, writes):
        _muted(writes, _output("o1", 40), _output("o2", 60))
        get_authority().deselect("o1", Origin.USER)
        assert snap().unit("o1").muted is False
        assert snap().unit("o2").muted is True

    def test_a_mute_with_nothing_selected_is_still_held_until_the_session_ends(self, writes):
        _muted(writes, _output("o1", 40))
        get_authority().deselect("o1", Origin.USER)
        assert snap().muted_all is True
        get_authority().deselect_all(Origin.SESSION)
        assert snap().muted_all is False

    def test_the_end_of_a_session_clears_every_mute(self, writes):
        _muted(writes, _output("o1", 40), _output("o2", 60))
        get_authority().deselect_all(Origin.SESSION)
        assert all(u.muted is False for u in snap().units)
        assert snap().muted_all is False

    def test_the_next_sessions_default_speaker_starts_unmuted_at_the_configured_volume(self, writes):
        import autostream_output_intents  # noqa: F401 -- binds the rows
        from autostream_intents import Intent, submit
        _muted(writes, _output("Kitchen", 40))
        with patch.object(player_service, "stop_and_disable_all", return_value=ActionResult(ok=True)), \
             patch("autostream_output_usage.refresh_now"), \
             patch("autostream_output_usage.usage_for_output", return_value=None):
            get_authority().deselect_all(Origin.SESSION)
            reply = submit(Intent(
                "outputs.select_default", {"name": "Kitchen", "volume": 30}, Origin.SESSION, "coordinator"))
        assert reply.ok is True
        assert writes.levels() == [("Kitchen", 30)]
        assert snap().unit("Kitchen").muted is False and snap().unit("Kitchen").volume == 30

    def test_a_volume_set_on_the_speaker_itself_ends_that_speakers_mute(self, writes):
        _muted(writes, _output("o1", 40), _output("o2", 60))
        FakeStore().outputs([_output("o1", 15), _output("o2", 0)])
        get_authority().device_volume_seen("o1")
        assert snap().unit("o1").muted is False and snap().unit("o1").volume == 15
        assert snap().unit("o2").muted is True
        assert writes.calls == []


# ---------------------------------------------------------------------------
# 2. POST /api/dial/mute
# ---------------------------------------------------------------------------

class TestDialMute:
    def _mute(self, action, default_vol=20):
        return _dial("send_dial_mute_post_json", {"action": action}, _parsed_config(default_vol))["body"]

    def test_mute_zeroes_audible_outputs_and_remembers(self, writes):
        _arrange(_output("o1", 40))
        assert self._mute("mute") == {"ok": True, "muted": True}
        assert writes.levels() == [("o1", 0)]
        assert snap().unit("o1").volume == 40

    def test_mute_on_a_silent_selection_is_a_no_op_reporting_true(self, writes):
        _arrange(_output("o1", 0))
        assert self._mute("mute") == {"ok": True, "muted": True}
        assert writes.calls == []

    def test_restore_uses_the_remembered_level(self, writes):
        _muted(writes, _output("o1", 70))
        assert self._mute("restore") == {"ok": True, "muted": False}
        assert writes.levels() == [("o1", 70)]
        assert snap().muted_all is False

    def test_restore_falls_back_to_the_default_for_a_silent_unremembered_output(self, writes):
        _arrange(_output("o1", 0))
        assert self._mute("restore", default_vol=35) == {"ok": True, "muted": False}
        assert writes.levels() == [("o1", 35)]

    def test_restore_leaves_an_audible_unremembered_output_alone(self, writes):
        _arrange(_output("o1", 55))
        assert self._mute("restore") == {"ok": True, "muted": False}
        assert writes.calls == []

    def test_mute_all_fail_reports_all_outputs_failed(self, writes):
        _arrange(_output("o1", 40))
        writes.results.append(_update_result(False))
        assert self._mute("mute") == {"ok": False, "error": "all_outputs_failed"}

    def test_restore_all_fail_reports_all_outputs_failed(self, writes):
        _muted(writes, _output("o1", 40))
        writes.results.append(_update_result(False))
        assert self._mute("restore") == {"ok": False, "error": "all_outputs_failed"}

    def test_no_active_outputs(self, writes):
        _arrange(_output("o1", 40, selected=False))
        assert self._mute("mute") == {"ok": False, "error": "no_active_outputs"}

    def test_backend_unavailable(self, writes):
        FakeStore().outputs_unreachable()
        assert self._mute("mute") == {"ok": False, "error": "backend_unavailable"}

    def test_config_error(self, writes):
        import autostream_webui_api as api
        captured = {}
        with patch("autostream_webui_api.send_json", side_effect=lambda h, c, b: captured.update(body=b)), \
             patch("autostream_webui_api.dial_authorization",
                   return_value=__import__("autostream_dials").AUTH_AUTHORIZED), \
             patch("autostream_webui_api._config_snapshot", side_effect=RuntimeError("boom")):
            api.send_dial_mute_post_json(_handler(), MagicMock(), {"dial_id": "uid", "action": "mute"})
        assert captured["body"] == {"ok": False, "error": "config_error"}

    def test_a_partly_failed_mute_keeps_the_mute_and_says_partial(self, writes):
        _arrange(_output("o1", 40), _output("o2", 60))
        writes.results.extend([_update_result(True), _update_result(False)])
        assert self._mute("mute") == {"ok": True, "muted": True, "partial": True}
        assert snap().muted_all is True

    def test_an_invalid_action_is_refused_before_anything_is_written(self, writes):
        _arrange(_output("o1", 40))
        result = _dial("send_dial_mute_post_json", {"action": "toggle"})
        assert result["code"] == 400 and result["body"] == {"ok": False, "error": "invalid_action"}
        assert writes.calls == []


# ---------------------------------------------------------------------------
# 3. POST /api/dial/volume, mute-aware
# ---------------------------------------------------------------------------

class TestVolumeDeltaWhileMuted:
    def _step(self, delta, default_vol=20):
        return _dial("send_dial_volume_post_json", {"delta": delta}, _parsed_config(default_vol))["body"]

    def test_a_negative_delta_while_muted_is_ignored(self, writes):
        _muted(writes, _output("o1", 40))
        assert self._step(-5) == {"ok": True, "volume": 40, "muted": True}
        assert writes.calls == []
        assert snap().muted_all is True

    def test_a_zero_delta_while_muted_is_ignored(self, writes):
        _muted(writes, _output("o1", 40))
        body = self._step(0)
        assert body["muted"] is True and body["volume"] == 40

    def test_a_positive_delta_while_muted_restores_with_no_step(self, writes):
        _muted(writes, _output("o1", 40))
        body = self._step(7)
        assert body == {"ok": True, "muted": False, "volume": 40}
        assert writes.levels() == [("o1", 40)]
        assert snap().muted_all is False

    def test_the_unmuted_delta_carries_muted_false(self, writes):
        _arrange(_output("o1", 40))
        assert self._step(5) == {"ok": True, "volume": 45, "muted": False}
        assert writes.levels() == [("o1", 45)]

    def test_the_unmuted_step_scales_up_from_zero(self, writes):
        _arrange(_output("o1", 0))
        assert self._step(4) == {"ok": True, "volume": 4, "muted": False}

    def test_a_partial_failure_carries_muted_false(self, writes):
        _arrange(_output("o1", 40), _output("o2", 60))
        writes.results.extend([_update_result(True), _update_result(False)])
        assert self._step(5) == {"ok": True, "volume": 55, "partial": True, "muted": False}

    def test_every_write_failing_is_reported(self, writes):
        _arrange(_output("o1", 40))
        writes.results.append(_update_result(False))
        assert self._step(5) == {"ok": False, "error": "all_outputs_failed"}

    def test_no_selected_output(self, writes):
        _arrange(_output("o1", 40, selected=False))
        assert self._step(5) == {"ok": False, "error": "no_active_outputs"}

    def test_backend_unavailable(self, writes):
        FakeStore().outputs_unreachable()
        assert self._step(5) == {"ok": False, "error": "backend_unavailable"}

    def test_a_non_integer_delta_is_refused(self, writes):
        _arrange(_output("o1", 40))
        assert _dial("send_dial_volume_post_json", {"delta": "5"})["body"] == {
            "ok": False, "error": "invalid_delta"}

    def test_the_route_holds_no_volume_lock_of_its_own(self):
        import autostream_webui_api as api
        assert not hasattr(api, "_volume_lock")
        assert not hasattr(api, "apply_mute_action")


# ---------------------------------------------------------------------------
# 4. POST /api/dial/status, mute-aware
# ---------------------------------------------------------------------------

class TestStatusMuteAware:
    def _call(self, outputs, muted_before=False):
        import autostream_webui_api as api
        captured = {}

        def fake_send_json(h, code, body):
            captured["code"] = code
            captured["body"] = body

        with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.dial_authorization",
                   return_value=__import__("autostream_dials").AUTH_AUTHORIZED), \
             patch("autostream_webui_api._config_snapshot", return_value=_parsed_config()), \
             fake_outputs(outputs), \
             patch("autostream_webui_api.get_appliance_id", return_value=None), \
             patch("autostream_webui_api._session_playing", return_value=False), \
             fake_repeat(None), \
             fake_track(_disabled_track_id_snapshot()):
            if muted_before:
                get_authority().mute_all(Origin.USER)
            api.send_dial_status_post_json(_handler(), MagicMock(), {"dial_id": "uid"})
        return captured

    def test_unmuted_reports_actual_and_false(self, writes):
        result = self._call([_output("o1", 40), _output("o2", 60)])
        assert result["body"]["master_volume"] == 50
        assert result["body"]["muted"] is False

    def test_muted_reports_intended_level_and_true(self, writes):
        result = self._call([_output("o1", 20), _output("o2", 60)], muted_before=True)
        assert result["body"]["master_volume"] == 40
        assert result["body"]["muted"] is True


# ---------------------------------------------------------------------------
# 5. Output changes and the mute
# ---------------------------------------------------------------------------

class TestOutputChangeMuteHooks:
    @staticmethod
    def _arrange_one(selected: bool, volume: int = 30):
        FakeStore().outputs([FakeStore.output_row("o1", "Speaker", selected=selected, volume_percent=volume)])

    def test_enable_while_muted_comes_on_silent_and_remembers_the_level(self, writes):
        import autostream_appliance_models as models
        FakeStore().outputs([
            FakeStore.output_row("o2", "Other", selected=True, volume_percent=30),
            FakeStore.output_row("o1", "Speaker", selected=False, volume_percent=0),
        ])
        get_authority().mute_all(Origin.USER)
        writes.calls.clear()
        result = models.submit_output_change(
            {"id": "o1", "selected": True, "volume": 55},
            requester="coordinator", pin_requester=None, origin=Origin.SYSTEM,
        )
        assert result == {"ok": True, "id": "o1"}
        assert [kw.get("volume_percent") for _i, kw in writes.calls] == [0]
        assert snap().unit("o1").volume == 55 and snap().unit("o1").muted is True

    def test_a_system_level_write_while_muted_is_remembered_and_not_sent(self, writes):
        import autostream_appliance_models as models
        self._arrange_one(selected=True, volume=40)
        get_authority().mute_all(Origin.USER)
        writes.calls.clear()
        result = models.submit_output_change(
            {"id": "o1", "selected": True, "volume": 12},
            requester="coordinator", pin_requester=None, origin=Origin.SYSTEM,
        )
        assert result == {"ok": True, "id": "o1"}
        assert writes.calls == []
        assert snap().unit("o1").volume == 12 and snap().muted_all is True

    def test_a_user_level_write_while_muted_ends_the_mute_and_writes(self, writes):
        """The WebUI has no unmute control: an explicit user volume set on a
        muted speaker is its unmute; the write is made for real."""
        import autostream_appliance_models as models
        self._arrange_one(selected=True, volume=40)
        get_authority().mute_all(Origin.USER)
        writes.calls.clear()
        result = models.submit_output_change(
            {"id": "o1", "selected": True, "volume": 65}, requester="webui", pin_requester=None,
        )
        assert result == {"ok": True, "id": "o1"}
        assert [kw.get("volume_percent") for _i, kw in writes.calls] == [65]
        assert snap().muted_all is False

    def test_a_level_write_while_unmuted_is_unchanged(self, writes):
        import autostream_appliance_models as models
        self._arrange_one(selected=True)
        result = models.submit_output_change(
            {"id": "o1", "selected": True, "volume": 12},
            requester="coordinator", pin_requester=None, origin=Origin.SYSTEM,
        )
        assert result == {"ok": True, "id": "o1"}
        assert len(writes.calls) == 1

    def test_disable_forgets_the_mute(self, writes):
        import autostream_appliance_models as models
        self._arrange_one(selected=True, volume=40)
        get_authority().mute_all(Origin.USER)
        result = models.submit_output_change(
            {"id": "o1", "selected": False}, requester="webui", pin_requester=None,
        )
        assert result == {"ok": True, "id": "o1"}
        assert snap().unit("o1").muted is False


# ---------------------------------------------------------------------------
# 6. build_output_list() / build_home_state()
# ---------------------------------------------------------------------------

class TestBuildOutputListAndHomeStateMuteAware:
    def test_build_output_list_reports_the_intended_level_while_muted(self, writes):
        import autostream_appliance_models as models
        FakeStore().outputs([OutputInfo(id="o1", name="Speaker", selected=True, volume_percent=40)])
        get_authority().mute_all(Origin.USER)
        parsed = SimpleNamespace(
            owntone=SimpleNamespace(output_name="Speaker"),
            webui=SimpleNamespace(hidden_outputs=()),
        )
        rows = models.build_output_list(parsed, snap().units)
        assert rows[0]["volume"] == 40

    def test_build_output_list_reports_the_actual_level_while_unmuted(self, writes):
        import autostream_appliance_models as models
        parsed = SimpleNamespace(
            owntone=SimpleNamespace(output_name="Speaker"),
            webui=SimpleNamespace(hidden_outputs=()),
        )
        out = OutputInfo(id="o1", name="Speaker", selected=True, volume_percent=33)
        rows = models.build_output_list(parsed, FakeStore().outputs([out]).outputs.units)
        assert rows[0]["volume"] == 33

    def test_build_home_state_carries_the_muted_flag(self, writes):
        import autostream_appliance_models as models
        FakeStore().outputs([OutputInfo(id="o1", name="Speaker", selected=True, volume_percent=40)])
        get_authority().mute_all(Origin.USER)
        with patch("autostream_appliance_models.locked_load_config", return_value={}), \
             patch("autostream_appliance_models.parse_config") as mock_parse, \
             fake_levels([]), \
             fake_playback_mock() as mock_playback, \
             patch("autostream_appliance_models.get_setting") as mock_setting, \
             patch("autostream_appliance_models.active_track") as mock_ti, \
             fake_session({"active": False, "source": None}), \
             fake_repeat(None), \
             patch("autostream_appliance_models.get_system_hostname", return_value="host"), \
             patch("autostream_appliance_models.get_app_version", return_value="1.0"), \
             patch("autostream_appliance_models.get_appliance_id", return_value="id"):
            mock_parse.return_value = SimpleNamespace(
                owntone=SimpleNamespace(base_url="http://x", output_name="Speaker"),
                webui=SimpleNamespace(show_master_volume=True, show_input_detail=False, hidden_outputs=()),
            )
            mock_playback.return_value = SimpleNamespace(
                to_public_dict=lambda: {}, stylus_banner_text="", belt_banner_text="", bearing_banner_text="",
            )
            mock_setting.return_value = SimpleNamespace(ok=False, value=None)
            mock_ti.return_value = SimpleNamespace(to_public_dict=lambda: {})
            home = models.build_home_state("dummy.json")
        assert home["muted"] is True

    def test_owntone_outputs_state_route_carries_muted(self):
        import autostream_webui_api as api
        captured = {}

        def fake_send_json(h, code, body):
            captured["code"] = code
            captured["body"] = body

        with patch("autostream_webui_api.build_home_state",
                   return_value={"ok": True, "outputs": [], "muted": True}), \
             patch("autostream_webui_api.send_json", side_effect=fake_send_json):
            api.send_owntone_outputs_state_json(_handler(), MagicMock())
        assert captured["body"]["muted"] is True


# ---------------------------------------------------------------------------
# 7. The end of a session
# ---------------------------------------------------------------------------

class TestSessionEndClearsMute:
    def test_the_end_of_a_session_clears_every_mute(self, writes):
        auth = get_authority()
        _arrange(_output("o1", 40))
        auth.mute_all(Origin.USER)
        assert snap().muted_all is True
        with patch.object(player_service, "stop_and_disable_all", return_value=ActionResult(ok=True)):
            auth.deselect_all(Origin.SESSION)
        assert snap().muted_all is False


# ---------------------------------------------------------------------------
# 8. The WebUI mute button/route are gone; the header text is the only
# mute indication and the volume slider is the only unmute path.
# ---------------------------------------------------------------------------

class TestWebUIMuteControlRemoved:
    def test_browser_mute_route_is_gone(self):
        import autostream_webui_routes as routes_mod
        matches = [r for r in routes_mod.ROUTES if r.path == "/api/mute"]
        assert matches == []

    def test_send_mute_post_json_handler_is_gone(self):
        import autostream_webui_api as api
        assert not hasattr(api, "send_mute_post_json")

    def test_dial_mute_route_still_present(self):
        """The dial's own mute button keeps its route."""
        import autostream_webui_routes as routes_mod
        matches = [r for r in routes_mod.ROUTES if r.path == "/api/dial/mute" and "POST" in r.methods]
        assert len(matches) == 1

    def test_mute_icon_markup_and_slash_path(self):
        """ICON_SPEAKER_MUTED itself is kept (matches the dial's own glyph)
        even though the WebUI no longer renders it anywhere."""
        from autostream_webui_assets import ICON_SPEAKER_MUTED
        assert "<svg" in ICON_SPEAKER_MUTED
        assert "currentColor" in ICON_SPEAKER_MUTED
        # The slash is centred on the speaker body, matching the dial's own
        # shifted glyph (see dial_display_compositor._draw_speaker_glyph).
        assert 'd="M1 5l14 14"' in ICON_SPEAKER_MUTED

    def test_page_js_no_longer_contains_mute_indicator_functions(self):
        import autostream_webui_assets as assets
        src = inspect_source(assets)
        assert "updateMuteIndicator" not in src
        assert "unmuteMaster" not in src

    def test_page_airplay_js_no_longer_calls_mute_indicator_functions(self):
        import autostream_webui_page_airplay as page_airplay
        src = inspect_source(page_airplay)
        assert "updateMuteIndicator" not in src
        assert "unmuteMaster" not in src

    def test_page_js_header_shows_muted_suffix(self):
        import autostream_webui_assets as assets
        src = inspect_source(assets)
        assert "(Muted)" in src


def inspect_source(module) -> str:
    import inspect
    return inspect.getsource(module)


# ---------------------------------------------------------------------------
# 9. WebUI now-playing level slot: the VU meter and the mute indicator share
# one fixed-width slot (see _VU_STEREO_CSS's .np-level rule) so muting never
# shifts the name/signal text beside it.
# ---------------------------------------------------------------------------

def _hold_mute() -> None:
    """One speaker on and muted, as the page finds it when it is rendered."""
    FakeStore().outputs([FakeStore.output_row("o1", "Speaker", selected=True, volume_percent=30)])
    with patch.object(player_service, "update_output", return_value=ActionResult(ok=True)):
        get_authority().mute_all(Origin.USER)


def _render_airplay_page_html(show_input_detail: bool = True, playing: bool = False) -> str:
    """Invoke send_airplay_page() with every external dependency mocked and
    return the rendered HTML — trimmed down from test_track_id_home_render.py's
    own helper, this module's own copy so it stands on its own."""
    from autostream_webui_page_airplay import send_airplay_page

    handler = MagicMock()
    chunks: list[bytes] = []
    handler.wfile.write = lambda d: chunks.append(d)
    handler._csrf_token = "testcsrf"
    handler._pending_set_cookies = []

    auth = MagicMock()
    auth.get_csrf_token.return_value = "testcsrf"

    state = MagicMock()
    state.config_path = "dummy.ini"

    parsed = MagicMock()
    parsed.owntone.base_url = "http://localhost:3689"
    parsed.owntone.output_name = "autostream"
    parsed.owntone.volume_percent = 20
    parsed.webui.show_master_volume = False
    parsed.webui.show_input_detail = show_input_detail
    parsed.webui.show_hostname_on_home = False
    parsed.webui.control_other_appliances = False
    parsed.webui.hidden_outputs = []
    parsed.webui.dark_mode = False
    parsed.track_identification = MagicMock(enabled=False)

    playback = MagicMock()
    playback.inputs = {}
    playback.stylus_banner_text = ""
    playback.belt_banner_text = ""
    playback.bearing_banner_text = ""
    playback.has_warning = False
    playback.to_public_dict.return_value = {}

    buf_result = MagicMock(ok=True, value="2250")
    input_levels = (
        [{"label": "Input 1", "is_above_threshold": True, "detected_hz": 0.0}]
        if playing else []
    )

    from contextlib import ExitStack
    patches = [
        patch("autostream_webui_page_airplay._config_snapshot", return_value=parsed),
        patch("autostream_webui_page_airplay.get_appliance_id", return_value="0" * 20),
        patch("autostream_webui_page_airplay.get_all_appliances", return_value=[]),
        patch("autostream_webui_page_airplay.get_system_hostname", return_value="autostream"),
        fake_levels(input_levels),
        fake_playback(playback),
        fake_outputs([], connected=False),
        patch("autostream_webui_page_airplay.get_setting", return_value=buf_result),
        fake_track(_disabled_ti_snapshot()),
        patch("autostream_webui_page_airplay.build_top_banner_html", return_value=("", "")),
    ]
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        send_airplay_page(handler, state, auth)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _render_airplay_page_html_playing() -> str:
    return _render_airplay_page_html(show_input_detail=True, playing=True)


def _disabled_ti_snapshot():
    from track_id.models import disabled_snapshot
    return disabled_snapshot()


def _render_remote_home_html() -> str:
    from autostream_webui_page_airplay import send_remote_home_page

    handler = MagicMock()
    chunks: list[bytes] = []
    handler.wfile.write = lambda d: chunks.append(d)
    handler._csrf_token = "testcsrf"
    handler._pending_set_cookies = []

    state = MagicMock()
    state.config_path = "dummy.ini"

    parsed = MagicMock()
    parsed.owntone.volume_percent = 20
    parsed.webui.dark_mode = False
    parsed.webui.show_hostname_on_home = False
    parsed.webui.control_other_appliances = False

    from contextlib import ExitStack
    patches = [
        patch("autostream_webui_page_airplay._config_snapshot", return_value=parsed),
        patch("autostream_webui_page_airplay.get_appliance_id", return_value="1" * 20),
        patch("autostream_webui_page_airplay.get_all_appliances", return_value=[]),
        patch("autostream_webui_page_airplay.get_system_hostname", return_value="autostream"),
    ]
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        send_remote_home_page(handler, state, "a" * 20)
    return b"".join(chunks).decode("utf-8", errors="replace")


class TestNowPlayingLevelSlotMarkup:
    def test_airplay_page_has_np_level_with_meter_and_no_mute_button(self):
        html = _render_airplay_page_html(show_input_detail=True)
        assert 'id="np-level"' in html
        assert 'id="np-vu"' in html
        assert 'id="np_mute_btn"' not in html
        assert 'np-mute-btn' not in html

    def test_airplay_page_omits_the_meter_without_input_detail_and_has_no_button(self):
        html = _render_airplay_page_html(show_input_detail=False)
        assert 'id="np-level"' in html
        assert 'id="np-vu"' not in html
        assert 'id="np_mute_btn"' not in html

    def test_master_card_no_longer_has_a_mute_button(self):
        html = _render_airplay_page_html()
        assert 'master-volume-card' in html  # the card itself still renders
        assert 'master_mute_btn' not in html
        assert 'master-mute-btn' not in html

    def test_remote_placeholder_page_mirrors_the_level_slot(self):
        html = _render_remote_home_html()
        assert 'id="np-level"' in html
        assert 'id="np_mute_btn"' not in html
        assert 'master_mute_btn' not in html


# ---------------------------------------------------------------------------
# 10. The now-playing header text is the mute indication.
# ---------------------------------------------------------------------------

class TestNowPlayingHeaderMutedSuffix:
    def test_header_gains_muted_suffix_when_playing_and_muted(self):
        _hold_mute()
        html = _render_airplay_page_html_playing()
        assert '>Now Playing (Muted)<' in html

    def test_header_has_no_muted_suffix_when_playing_and_unmuted(self):
        html = _render_airplay_page_html_playing()
        assert '>Now Playing<' in html
        assert '(Muted)<' not in html

    def test_ready_header_never_gets_the_muted_suffix(self):
        """Not playing: mute is real but there is no active session to
        annotate, so "Ready" is shown plain, exactly as when unmuted."""
        _hold_mute()
        html = _render_airplay_page_html(show_input_detail=True)
        assert '>Ready<' in html
        assert '(Muted)<' not in html
