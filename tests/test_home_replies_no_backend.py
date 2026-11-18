"""tests/test_home_replies_no_backend.py

The Home status reply and the speaker list reply are built from one snapshot
of the state and the in-memory settings. They ask the player for nothing, read
no configuration file and look up no hostname, so every one of those calls can
fail and the replies are the same as when they all work.
"""
from __future__ import annotations

import json
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_webui_api as api
from autostream_settings import SettingsStore, as_view
from fake_store import FakeStore, fake_levels


@pytest.fixture
def state(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "owntone": {"base_url": "http://player:3689", "output_name": "Speaker B"},
        "webui": {"hidden_outputs": ["Speaker C"]},
    }), encoding="utf-8")
    store = SettingsStore(str(path), _save_interval_seconds=9999, _writer=MagicMock())
    state = MagicMock()
    state.config_path = str(path)
    state.settings = as_view(store)
    yield state
    store.close(save=False)


def _arrange():
    fake = FakeStore()
    fake.outputs([
        FakeStore.output_row("o1", "Speaker A", selected=True, volume_percent=30),
        FakeStore.output_row("o2", "Speaker B", selected=False, volume_percent=0),
        FakeStore.output_row("o3", "Speaker C", selected=False, volume_percent=0),
    ])
    fake_levels([])


def _reply(route, state):
    sent: dict = {}
    with patch("autostream_webui_api.send_json",
               side_effect=lambda h, code, body: sent.update(code=code, body=body)):
        route(MagicMock(), state)
    return sent["code"], sent["body"]


def _backend_down() -> ExitStack:
    boom = RuntimeError("must not be asked")
    stack = ExitStack()
    for target in (
        "autostream_player_service.get_setting",
        "autostream_webui_common.locked_load_config",
        "autostream_config.load_config",
        "autostream_appliance_models.get_system_hostname",
        "autostream_sysutils.get_system_hostname",
    ):
        stack.enter_context(patch(target, side_effect=boom))
    return stack


@pytest.mark.parametrize("route", [api.send_status_json, api.send_owntone_outputs_state_json])
def test_a_reply_is_the_same_whether_or_not_the_backend_answers(route, state):
    _arrange()
    expected = _reply(route, state)
    with _backend_down():
        assert _reply(route, state) == expected
    assert expected[0] == 200


def test_the_speaker_list_follows_the_in_memory_settings(state):
    _arrange()
    code, body = _reply(api.send_owntone_outputs_state_json, state)
    assert code == 200
    names = [o["name"] for o in body["outputs"]]
    # The default speaker leads and the hidden one is left out.
    assert names == ["Speaker B", "Speaker A"]
    assert body["muted"] is False
    assert [o["is_default"] for o in body["outputs"]] == [True, False]


def test_the_speaker_list_is_empty_while_the_player_is_unreachable(state):
    FakeStore().outputs_unreachable()
    code, body = _reply(api.send_owntone_outputs_state_json, state)
    assert (code, body["outputs"]) == (200, [])


def test_the_status_reply_carries_its_fields_from_the_snapshot(state):
    _arrange()
    code, body = _reply(api.send_status_json, state)
    assert code == 200
    for key in ("input_levels", "playback", "track_identification", "playback_banner_text",
                "belt_banner_text", "bearing_banner_text", "dial_update_banner_text",
                "sample_rate_banner_text"):
        assert key in body, key
