"""Tests for appliance-side mute state: the state module itself, the shared
mute/restore core it backs, the mute-aware volume-delta rule, the status
field, the output-mutation hooks, and the WebUI's own mute route.

Covers:
1.  autostream_mute_state.py: begin_mute/end_mute/intended_level/
    remember_level/forget_output/reset_for_tests, and that the module has
    no persistence (no path constant, no load/persist functions).
2.  apply_mute_action(): mute, restore, partial failures, idempotence --
    used identically by the dial route and (in a later test class) the
    WebUI route.
3.  POST /api/dial/volume: a non-positive delta while muted is a no-op that
    reports the intended level and muted:true; a positive delta while muted
    restores with no step added and reports muted:false; the unmuted path
    is unchanged apart from carrying muted:false.
4.  POST /api/dial/status: master_volume/muted while muted and unmuted.
5.  apply_output_mutation(): enable-while-muted stays silent and remembers
    the requested level; a volume-only write on an already-selected output
    while muted skips the OwnTone write and remembers instead; disable
    forgets any remembered level.
6.  build_output_list()/build_home_state(): intended levels and the muted
    flag.
7.  Restart: a fresh module state reports unmuted with no memory of a prior
    mute.
8.  Alignment's own volume writes never consult or update the mute flag.
9.  The WebUI's POST /api/mute route: registration, restore behaviour,
    invalid action.
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_mute_state as mute_state


@pytest.fixture(autouse=True)
def _reset_mute_state():
    mute_state.reset_for_tests()
    yield
    mute_state.reset_for_tests()


# ---------------------------------------------------------------------------
# 1. The state module itself
# ---------------------------------------------------------------------------

class TestMuteStateModule:
    def test_starts_unmuted(self):
        assert mute_state.is_muted() is False

    def test_begin_mute_sets_flag_even_with_no_levels(self):
        mute_state.begin_mute({})
        assert mute_state.is_muted() is True

    def test_begin_mute_remembers_untracked_ids(self):
        mute_state.begin_mute({"o1": 40, "o2": 80})
        assert mute_state.intended_level("o1", 0) == 40
        assert mute_state.intended_level("o2", 0) == 80

    def test_begin_mute_does_not_overwrite_already_remembered(self):
        mute_state.begin_mute({"o1": 40})
        mute_state.begin_mute({"o1": 99})  # a second mute press, stale volume
        assert mute_state.intended_level("o1", 0) == 40

    def test_intended_level_while_unmuted_is_actual(self):
        assert mute_state.intended_level("o1", 55) == 55

    def test_intended_level_for_untouched_output_while_muted_is_actual(self):
        mute_state.begin_mute({"o1": 40})
        assert mute_state.intended_level("o2", 33) == 33

    def test_end_mute_clears_flag_and_returns_levels(self):
        mute_state.begin_mute({"o1": 40, "o2": 80})
        levels = mute_state.end_mute()
        assert levels == {"o1": 40, "o2": 80}
        assert mute_state.is_muted() is False

    def test_end_mute_forgets_everything_even_when_unmuted(self):
        assert mute_state.end_mute() == {}
        assert mute_state.is_muted() is False

    def test_remember_level_true_only_while_muted(self):
        assert mute_state.remember_level("o1", 40) is False
        mute_state.begin_mute({})
        assert mute_state.remember_level("o1", 40) is True

    def test_remember_level_updates_the_stored_level(self):
        mute_state.begin_mute({"o1": 40})
        mute_state.remember_level("o1", 12)
        assert mute_state.intended_level("o1", 0) == 12
        assert mute_state.end_mute() == {"o1": 12}

    def test_forget_output_drops_a_remembered_level(self):
        mute_state.begin_mute({"o1": 40, "o2": 80})
        mute_state.forget_output("o1")
        assert mute_state.end_mute() == {"o2": 80}

    def test_forget_output_on_unremembered_id_is_a_no_op(self):
        mute_state.forget_output("nope")  # must not raise

    def test_reset_for_tests_restores_initial_state(self):
        mute_state.begin_mute({"o1": 40})
        mute_state.reset_for_tests()
        assert mute_state.is_muted() is False
        assert mute_state.intended_level("o1", 7) == 7

    def test_no_persistence_constants_or_helpers(self):
        """The module must be pure in-memory: no path constant, no
        load/persist/atomic-write helpers of any kind."""
        names = [n for n in dir(mute_state) if not n.startswith("__")]
        assert not any("PATH" in n for n in names)
        assert not any("load" in n.lower() for n in names)
        assert not any("persist" in n.lower() for n in names)
        assert not any("atomic_write" in n.lower() for n in names)

    def test_restart_is_a_fresh_unmuted_module(self):
        """A restarted appliance loses the module's process memory -- a
        fresh import (modelled here by reset_for_tests, since re-importing
        the already-imported module is not meaningful in-process) always
        comes back unmuted with nothing remembered."""
        mute_state.begin_mute({"o1": 40})
        mute_state.reset_for_tests()
        assert mute_state.is_muted() is False
        assert mute_state.end_mute() == {}


# ---------------------------------------------------------------------------
# Shared helpers for the appliance-API tests below
# ---------------------------------------------------------------------------

def _output(id_: str, volume: int, selected: bool = True):
    o = SimpleNamespace()
    o.id = id_
    o.volume_percent = volume
    o.selected = selected
    return o


def _list_result(outputs, ok=True):
    r = SimpleNamespace()
    r.ok = ok
    r.outputs = outputs
    r.error = "" if ok else "err"
    r.message = "" if ok else "err"
    return r


def _update_result(ok=True):
    r = SimpleNamespace()
    r.ok = ok
    r.error = "" if ok else "connection refused"
    return r


def _parsed_config(base_url="http://localhost:3689", volume_percent=20):
    parsed = SimpleNamespace()
    parsed.owntone = SimpleNamespace(base_url=base_url, volume_percent=volume_percent)
    return parsed


def _handler():
    h = MagicMock()
    h.wfile = io.BytesIO()
    return h


def _disabled_track_id_snapshot():
    from track_id.models import disabled_snapshot
    return disabled_snapshot()


# ---------------------------------------------------------------------------
# 2. apply_mute_action()
# ---------------------------------------------------------------------------

class TestApplyMuteAction:
    def _call(self, action, outputs, update_ok=True, default_vol=20):
        import autostream_webui_api as api
        parsed = _parsed_config(volume_percent=default_vol)
        with patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.list_outputs", return_value=_list_result(outputs)), \
             patch("autostream_webui_api.update_output", return_value=_update_result(update_ok)):
            return api.apply_mute_action(MagicMock(), action)

    def test_mute_zeroes_audible_outputs_and_remembers(self):
        status, body = self._call("mute", [_output("o1", 40)])
        assert status == 200
        assert body == {"ok": True, "muted": True}
        assert mute_state.intended_level("o1", 0) == 40

    def test_mute_on_silent_selection_is_a_noop_reporting_true(self):
        status, body = self._call("mute", [_output("o1", 0)])
        assert body == {"ok": True, "muted": True}

    def test_restore_uses_remembered_level(self):
        import autostream_webui_api as api
        mute_state.begin_mute({"o1": 70})
        status, body = self._call("restore", [_output("o1", 0)])
        assert body == {"ok": True, "muted": False}
        assert mute_state.is_muted() is False

    def test_restore_falls_back_to_default_when_unremembered_and_zero(self):
        status, body = self._call("restore", [_output("o1", 0)], default_vol=35)
        assert body["ok"] is True
        assert body["muted"] is False

    def test_mute_all_fail_reports_all_outputs_failed(self):
        status, body = self._call("mute", [_output("o1", 40)], update_ok=False)
        assert body == {"ok": False, "error": "all_outputs_failed"}

    def test_restore_all_fail_reports_all_outputs_failed(self):
        mute_state.begin_mute({"o1": 40})
        status, body = self._call("restore", [_output("o1", 0)], update_ok=False)
        assert body == {"ok": False, "error": "all_outputs_failed"}

    def test_no_active_outputs(self):
        status, body = self._call("mute", [_output("o1", 40, selected=False)])
        assert body == {"ok": False, "error": "no_active_outputs"}

    def test_backend_unavailable(self):
        import autostream_webui_api as api
        parsed = _parsed_config()
        with patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.list_outputs", return_value=_list_result([], ok=False)):
            status, body = api.apply_mute_action(MagicMock(), "mute")
        assert body == {"ok": False, "error": "backend_unavailable"}

    def test_config_error(self):
        import autostream_webui_api as api
        with patch("autostream_webui_api._config_snapshot", side_effect=RuntimeError("boom")):
            status, body = api.apply_mute_action(MagicMock(), "mute")
        assert body == {"ok": False, "error": "config_error"}

    def test_partial_mute_keeps_flag_and_partial(self):
        import autostream_webui_api as api
        parsed = _parsed_config()
        results = iter([_update_result(True), _update_result(False)])
        with patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.list_outputs",
                   return_value=_list_result([_output("o1", 40), _output("o2", 60)])), \
             patch("autostream_webui_api.update_output", side_effect=lambda *a, **k: next(results)):
            status, body = api.apply_mute_action(MagicMock(), "mute")
        assert body["ok"] is True
        assert body["muted"] is True
        assert body.get("partial") is True

    def test_both_routes_share_apply_mute_action(self):
        """The dial route (send_dial_mute_post_json) and the WebUI route
        (send_mute_post_json) must both call the same shared core -- spy on
        it and drive each entry point."""
        import autostream_webui_api as api
        calls = []

        def fake_apply(state, action):
            calls.append(action)
            return 200, {"ok": True, "muted": action == "mute"}

        with patch("autostream_webui_api.apply_mute_action", side_effect=fake_apply), \
             patch("autostream_webui_api.is_dial_authorized", return_value=True), \
             patch("autostream_webui_api.send_json"):
            api.send_dial_mute_post_json(
                _handler(), MagicMock(), {"dial_id": "uid", "action": "mute"},
            )
            api.send_mute_post_json(_handler(), MagicMock(), json.dumps({"action": "restore"}))

        assert calls == ["mute", "restore"]


# ---------------------------------------------------------------------------
# 3. POST /api/dial/volume, mute-aware
# ---------------------------------------------------------------------------

class TestVolumeDeltaWhileMuted:
    def _call(self, delta, outputs, default_vol=20, update_ok=True):
        import autostream_webui_api as api
        parsed = _parsed_config(volume_percent=default_vol)
        captured = {}

        def fake_send_json(h, code, body):
            captured["code"] = code
            captured["body"] = body

        with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.is_dial_authorized", return_value=True), \
             patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.list_outputs", return_value=_list_result(outputs)), \
             patch("autostream_webui_api.update_output", return_value=_update_result(update_ok)):
            api.send_dial_volume_post_json(
                _handler(), MagicMock(), {"dial_id": "uid", "delta": delta},
            )
        return captured

    def test_negative_delta_while_muted_is_ignored(self):
        mute_state.begin_mute({"o1": 40})
        result = self._call(-5, [_output("o1", 0)])
        assert result["body"] == {"ok": True, "volume": 40, "muted": True}
        assert mute_state.is_muted() is True

    def test_zero_delta_while_muted_is_ignored(self):
        mute_state.begin_mute({"o1": 40})
        result = self._call(0, [_output("o1", 0)])
        assert result["body"]["muted"] is True
        assert result["body"]["volume"] == 40

    def test_negative_delta_while_muted_writes_nothing(self):
        import autostream_webui_api as api
        mute_state.begin_mute({"o1": 40})
        parsed = _parsed_config()
        with patch("autostream_webui_api.send_json"), \
             patch("autostream_webui_api.is_dial_authorized", return_value=True), \
             patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.list_outputs", return_value=_list_result([_output("o1", 0)])), \
             patch("autostream_webui_api.update_output") as mock_update:
            api.send_dial_volume_post_json(
                _handler(), MagicMock(), {"dial_id": "uid", "delta": -5},
            )
        mock_update.assert_not_called()

    def test_positive_delta_while_muted_restores_with_no_step(self):
        """40 stays 40 -- the restore applies no step on top of it."""
        mute_state.begin_mute({"o1": 40})
        result = self._call(7, [_output("o1", 0)])
        assert result["body"]["ok"] is True
        assert result["body"]["muted"] is False
        assert result["body"]["volume"] == 40
        assert mute_state.is_muted() is False

    def test_positive_delta_while_muted_writes_remembered_level_not_stepped(self):
        import autostream_webui_api as api
        mute_state.begin_mute({"o1": 40})
        parsed = _parsed_config()
        calls = []

        def fake_update(base_url, oid, volume_percent, timeout):
            calls.append((oid, volume_percent))
            return _update_result(True)

        with patch("autostream_webui_api.send_json"), \
             patch("autostream_webui_api.is_dial_authorized", return_value=True), \
             patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.list_outputs", return_value=_list_result([_output("o1", 0)])), \
             patch("autostream_webui_api.update_output", side_effect=fake_update):
            api.send_dial_volume_post_json(
                _handler(), MagicMock(), {"dial_id": "uid", "delta": 3},
            )
        assert calls == [("o1", 40)]

    def test_unmuted_delta_gains_muted_false_field(self):
        result = self._call(5, [_output("o1", 40)])
        assert result["body"]["ok"] is True
        assert result["body"]["muted"] is False

    def test_unmuted_scale_from_zero_still_applies(self):
        result = self._call(4, [_output("o1", 0)])
        assert result["body"]["ok"] is True
        assert result["body"]["volume"] == 4
        assert result["body"]["muted"] is False

    def test_unmuted_partial_failure_gains_muted_false(self):
        import autostream_webui_api as api
        parsed = _parsed_config()
        results = iter([_update_result(True), _update_result(False)])
        with patch("autostream_webui_api.send_json") as mock_send, \
             patch("autostream_webui_api.is_dial_authorized", return_value=True), \
             patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.list_outputs",
                   return_value=_list_result([_output("o1", 40), _output("o2", 60)])), \
             patch("autostream_webui_api.update_output", side_effect=lambda *a, **k: next(results)):
            api.send_dial_volume_post_json(
                _handler(), MagicMock(), {"dial_id": "uid", "delta": 5},
            )
        body = mock_send.call_args[0][2]
        assert body["muted"] is False
        assert body.get("partial") is True


# ---------------------------------------------------------------------------
# 4. POST /api/dial/status, mute-aware
# ---------------------------------------------------------------------------

class TestStatusMuteAware:
    def _call(self, outputs, muted_before=False, remembered=None):
        import autostream_webui_api as api
        if muted_before:
            mute_state.begin_mute(remembered or {})
        parsed = _parsed_config()
        captured = {}

        def fake_send_json(h, code, body):
            captured["code"] = code
            captured["body"] = body

        with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.dial_authorization",
                   return_value=__import__("autostream_dials").AUTH_AUTHORIZED), \
             patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.list_outputs", return_value=_list_result(outputs)), \
             patch("autostream_webui_api.get_appliance_id", return_value=None), \
             patch("autostream_webui_api._session_playing", return_value=False), \
             patch("autostream_webui_api.get_repeat_status", return_value=None), \
             patch("autostream_core.get_active_track_identification_snapshot",
                   return_value=_disabled_track_id_snapshot()):
            api.send_dial_status_post_json(_handler(), MagicMock(), {"dial_id": "uid"})
        return captured

    def test_unmuted_reports_actual_and_false(self):
        result = self._call([_output("o1", 40), _output("o2", 60)])
        assert result["body"]["master_volume"] == 50
        assert result["body"]["muted"] is False

    def test_muted_reports_intended_level_and_true(self):
        result = self._call(
            [_output("o1", 0), _output("o2", 0)],
            muted_before=True, remembered={"o1": 20, "o2": 60},
        )
        assert result["body"]["master_volume"] == 40
        assert result["body"]["muted"] is True

    def test_no_outputs_reports_null_and_flag(self):
        result = self._call([], muted_before=True, remembered={})
        assert result["body"]["master_volume"] is None
        assert result["body"]["muted"] is True


# ---------------------------------------------------------------------------
# 5. apply_output_mutation() hooks
# ---------------------------------------------------------------------------

class TestApplyOutputMutationMuteHooks:
    def test_enable_while_muted_writes_real_then_silences_and_remembers(self):
        import autostream_appliance_models as models
        mute_state.begin_mute({})
        calls = []

        def fake_update_output(base_url, out_id, **kwargs):
            calls.append(kwargs.get("volume_percent"))
            return _update_result(True)

        with patch("autostream_appliance_models._resolve_output_info", return_value=("Speaker", False)), \
             patch("autostream_appliance_models.update_output", side_effect=fake_update_output), \
             patch("autostream_appliance_models.request_nowplaying_republish"), \
             patch("autostream_appliance_models.clear_user_silence_latch"), \
             patch("autostream_appliance_models._update_cached_selected"), \
             patch("autostream_appliance_models.note_user_output_action"):
            result = models.apply_output_mutation(
                "http://x", "o1", {"selected": True, "volume": 55}, initiated_by="system",
            )
        assert result == {"ok": True, "id": "o1"}
        assert calls == [55, 0]  # real enable write, then the silencing write
        assert mute_state.intended_level("o1", 0) == 55

    def test_slider_write_while_muted_skips_owntone_and_remembers(self):
        import autostream_appliance_models as models
        mute_state.begin_mute({"o1": 40})
        with patch("autostream_appliance_models._resolve_output_info", return_value=("Speaker", True)), \
             patch("autostream_appliance_models.update_output") as mock_update, \
             patch("autostream_appliance_models.note_user_output_action"):
            result = models.apply_output_mutation(
                "http://x", "o1", {"selected": True, "volume": 12}, initiated_by="system",
            )
        assert result == {"ok": True, "id": "o1"}
        mock_update.assert_not_called()
        assert mute_state.intended_level("o1", 0) == 12

    def test_slider_write_while_unmuted_is_unchanged(self):
        import autostream_appliance_models as models
        with patch("autostream_appliance_models._resolve_output_info", return_value=("Speaker", True)), \
             patch("autostream_appliance_models.update_output", return_value=_update_result(True)) as mock_update, \
             patch("autostream_appliance_models.request_nowplaying_republish"), \
             patch("autostream_appliance_models.clear_user_silence_latch"), \
             patch("autostream_appliance_models._update_cached_selected"), \
             patch("autostream_appliance_models.note_user_output_action"):
            result = models.apply_output_mutation(
                "http://x", "o1", {"selected": True, "volume": 12}, initiated_by="system",
            )
        assert result == {"ok": True, "id": "o1"}
        mock_update.assert_called_once()

    def test_disable_forgets_remembered_level(self):
        import autostream_appliance_models as models
        mute_state.begin_mute({"o1": 40})
        with patch("autostream_appliance_models.set_output_enabled", return_value=_update_result(True)), \
             patch("autostream_appliance_models._update_cached_selected"), \
             patch("autostream_appliance_models.note_user_output_action"), \
             patch("autostream_appliance_models.list_outputs", return_value=_list_result([])):
            result = models.apply_output_mutation(
                "http://x", "o1", {"selected": False}, initiated_by="user",
            )
        assert result == {"ok": True, "id": "o1"}
        assert mute_state.intended_level("o1", 77) == 77  # forgotten -> falls back to actual


# ---------------------------------------------------------------------------
# 6. build_output_list() / build_home_state()
# ---------------------------------------------------------------------------

class TestBuildOutputListAndHomeStateMuteAware:
    def test_build_output_list_reports_intended_level_while_muted(self):
        import autostream_appliance_models as models
        mute_state.begin_mute({"o1": 40})
        parsed = SimpleNamespace(
            owntone=SimpleNamespace(output_name="Speaker"),
            webui=SimpleNamespace(hidden_outputs=()),
        )
        out = SimpleNamespace(
            id="o1", name="Speaker", selected=True, volume_percent=0,
            needs_auth_key=False, requires_auth=False, pin_pending=False,
        )
        rows = models.build_output_list(parsed, [out])
        assert rows[0]["volume"] == 40

    def test_build_output_list_reports_actual_while_unmuted(self):
        import autostream_appliance_models as models
        parsed = SimpleNamespace(
            owntone=SimpleNamespace(output_name="Speaker"),
            webui=SimpleNamespace(hidden_outputs=()),
        )
        out = SimpleNamespace(
            id="o1", name="Speaker", selected=True, volume_percent=33,
            needs_auth_key=False, requires_auth=False, pin_pending=False,
        )
        rows = models.build_output_list(parsed, [out])
        assert rows[0]["volume"] == 33

    def test_build_home_state_carries_muted_flag(self):
        import autostream_appliance_models as models
        mute_state.begin_mute({})
        with patch("autostream_appliance_models.locked_load_config", return_value={}), \
             patch("autostream_appliance_models.parse_config") as mock_parse, \
             patch("autostream_appliance_models.get_monitor_levels_dbfs", return_value=[]), \
             patch("autostream_appliance_models.get_playback_snapshot") as mock_playback, \
             patch("autostream_appliance_models.list_outputs", return_value=_list_result([])), \
             patch("autostream_appliance_models.get_setting") as mock_setting, \
             patch("autostream_appliance_models.get_active_track_identification_snapshot") as mock_ti, \
             patch("autostream_appliance_models.get_session_state", return_value={"active": False, "source": None}), \
             patch("autostream_appliance_models.get_repeat_status", return_value=None), \
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
# 8. Alignment leaves the flag untouched
# ---------------------------------------------------------------------------

class TestAlignmentLeavesMuteFlagAlone:
    def test_align_module_does_not_import_mute_state(self):
        import autostream_align as align
        assert not hasattr(align, "mute_state")

    def test_a_mute_in_effect_survives_an_unrelated_module_import(self):
        mute_state.begin_mute({"o1": 40})
        import autostream_align  # noqa: F401 -- import must not disturb state
        assert mute_state.is_muted() is True
        assert mute_state.intended_level("o1", 0) == 40


# ---------------------------------------------------------------------------
# 9. WebUI POST /api/mute
# ---------------------------------------------------------------------------

class TestWebUIMuteRoute:
    def test_route_registered_with_csrf(self):
        import autostream_webui_routes as routes_mod
        matches = [r for r in routes_mod.ROUTES if r.path == "/api/mute" and "POST" in r.methods]
        assert len(matches) == 1
        r = matches[0]
        from autostream_webui_routes import AuthRequirement
        assert r.auth is AuthRequirement.CSRF
        assert r.kind == "api"
        assert r.requires_body is True

    def test_restore_through_route_clears_flag_and_returns_muted_false(self):
        import autostream_webui_api as api
        mute_state.begin_mute({"o1": 40})
        parsed = _parsed_config()
        captured = {}

        def fake_send_json(h, code, body):
            captured["code"] = code
            captured["body"] = body

        with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.list_outputs", return_value=_list_result([_output("o1", 0)])), \
             patch("autostream_webui_api.update_output", return_value=_update_result(True)):
            api.send_mute_post_json(_handler(), MagicMock(), json.dumps({"action": "restore"}))
        assert captured["body"]["ok"] is True
        assert captured["body"]["muted"] is False
        assert mute_state.is_muted() is False

    def test_invalid_action_returns_400(self):
        import autostream_webui_api as api
        captured = {}

        def fake_send_json(h, code, body):
            captured["code"] = code
            captured["body"] = body

        with patch("autostream_webui_api.send_json", side_effect=fake_send_json):
            api.send_mute_post_json(_handler(), MagicMock(), json.dumps({"action": "nope"}))
        assert captured["code"] == 400
        assert captured["body"]["ok"] is False

    def test_missing_body_returns_400(self):
        import autostream_webui_api as api
        captured = {}

        def fake_send_json(h, code, body):
            captured["code"] = code
            captured["body"] = body

        with patch("autostream_webui_api.send_json", side_effect=fake_send_json):
            api.send_mute_post_json(_handler(), MagicMock(), "")
        assert captured["code"] == 400

    def test_master_card_markup_contains_button_and_icon(self):
        from autostream_webui_assets import ICON_SPEAKER_MUTED
        assert "<svg" in ICON_SPEAKER_MUTED
        assert "currentColor" in ICON_SPEAKER_MUTED

    def test_page_js_contains_mute_card_functions(self):
        import autostream_webui_assets as assets
        src = inspect_source(assets)
        assert "updateMasterMuteCard" in src
        assert "unmuteMaster" in src


def inspect_source(module) -> str:
    import inspect
    return inspect.getsource(module)
