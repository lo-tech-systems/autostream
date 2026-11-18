"""tests/test_settings_route_ports.py

Settings behaviours that are live through the per-field settings route
(POST /api/settings), written as route tests: the update channel, the
control-other-appliances flag, the capture-device uniqueness rule and the
track-identification switch and bounds.
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_CORE = str(Path(__file__).parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_config import TRACK_ID_MAX_ANALYSIS_LEAD_IN_SECONDS
from autostream_settings import SettingsStore
from autostream_webui_api import send_settings_post_json
from autostream_webui_state import WebUIState


def _state(tmp_path: Path, raw: dict):
    cfg = tmp_path / "autostream.json"
    cfg.write_text(json.dumps(raw), encoding="utf-8")
    store = SettingsStore(str(cfg), _save_interval_seconds=9999, _writer=MagicMock())
    return WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store), store


def _post(state, field: str, value):
    handler = MagicMock()
    handler.wfile = io.BytesIO()
    send_settings_post_json(handler, state, {"field": field, "value": value})
    return handler.send_response.call_args[0][0], json.loads(handler.wfile.getvalue())


class TestUpdateChannelRoute:
    def test_a_channel_change_does_not_switch_the_update_timer(self, tmp_path):
        state, store = _state(tmp_path, {"updates": {"auto_update": False, "update_channel": "stable"}})
        try:
            with patch("autostream_live_config.run_admin_cmd") as live_cmd, \
                    patch("autostream_sysutils.run_admin_cmd") as sys_cmd:
                code, body = _post(state, "updates.update_channel", "dev")
            snapshot = store.snapshot()
        finally:
            store.close(save=False)
        assert (code, body["ok"]) == (200, True)
        assert snapshot.updates.update_channel == "dev"
        assert snapshot.updates.auto_update is False
        live_cmd.assert_not_called()
        sys_cmd.assert_not_called()


class TestControlOtherAppliancesRoute:
    @pytest.mark.parametrize("value", [True, False])
    def test_the_flag_is_stored_as_given_while_the_hostname_is_shown(self, tmp_path, value):
        state, store = _state(tmp_path, {"webui": {
            "show_hostname_on_home": True, "control_other_appliances": not value}})
        try:
            code, body = _post(state, "webui.control_other_appliances", value)
            stored = store.snapshot().webui.control_other_appliances
        finally:
            store.close(save=False)
        assert (code, body["ok"]) == (200, True)
        assert stored is value


class TestDuplicateCaptureDeviceRoute:
    _RAW = {"audio1": {"capture_device": "hw:0,0"}, "audio2": {"capture_device": "hw:1,0"}}

    def test_the_same_device_on_both_inputs_is_refused_and_not_stored(self, tmp_path):
        state, store = _state(tmp_path, self._RAW)
        try:
            with patch("autostream_live_config._debounce_coordinator_reload") as reload_:
                code, body = _post(state, "audio2.capture_device", "hw:0,0")
            stored = store.raw_snapshot()["audio2"]["capture_device"]
        finally:
            store.close(save=False)
        assert code == 400
        assert body["ok"] is False
        assert "already assigned to the other input" in body["error"]
        assert stored == "hw:1,0"
        reload_.assert_not_called()

    def test_a_distinct_device_is_stored(self, tmp_path):
        state, store = _state(tmp_path, self._RAW)
        try:
            with patch("autostream_live_config._debounce_coordinator_reload"):
                code, body = _post(state, "audio2.capture_device", "hw:2,0")
            stored = store.raw_snapshot()["audio2"]["capture_device"]
        finally:
            store.close(save=False)
        assert (code, body["ok"]) == (200, True)
        assert stored == "hw:2,0"


class TestTrackIdentificationRoute:
    def test_switching_it_off_is_stored(self, tmp_path):
        state, store = _state(tmp_path, {"track_identification": {"enabled": True}})
        try:
            with patch("autostream_live_config._debounce_track_id_rebuild"):
                code, body = _post(state, "track_identification.enabled", False)
            stored = store.snapshot().track_identification.enabled
        finally:
            store.close(save=False)
        assert (code, body["ok"]) == (200, True)
        assert stored is False

    def test_an_out_of_range_lead_in_is_clamped_not_refused(self, tmp_path):
        state, store = _state(tmp_path, {})
        try:
            with patch("autostream_live_config._debounce_track_id_rebuild"):
                code, body = _post(state, "track_identification.analysis_lead_in_seconds", 999)
            stored = store.snapshot().track_identification.analysis_lead_in_seconds
        finally:
            store.close(save=False)
        assert (code, body["ok"]) == (200, True)
        assert stored == TRACK_ID_MAX_ANALYSIS_LEAD_IN_SECONDS


class TestOtherSectionsRoute:
    def test_a_write_keeps_the_include_tv_and_output_policy_sections(self, tmp_path):
        raw = {"owntone": {"include_tv": {"1": False}}, "outputs": {"device_pause_scope": "all"}}
        state, store = _state(tmp_path, raw)
        try:
            code, body = _post(state, "webui.dark_mode", True)
            kept = store.raw_snapshot()
        finally:
            store.close(save=False)
        assert (code, body["ok"]) == (200, True)
        assert kept["owntone"]["include_tv"] == {"1": False}
        assert kept["outputs"] == {"device_pause_scope": "all"}
