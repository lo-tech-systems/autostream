"""tests/test_peer_replies_no_file.py

The federation home and equaliser replies, and the gateway's bound home,
output and equaliser branches, are built from one snapshot and the in-memory
settings. They read no configuration file and never wait on the player, so
every such read can fail and the replies are the same.
"""
from __future__ import annotations

import json
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_appliance_gateway as gw
import autostream_webui_api as api
from autostream_settings import SettingsStore, as_view
from fake_store import FakeStore, fake_levels

APPLIANCE_ID = "a" * 20


@pytest.fixture
def state(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "owntone": {"base_url": "http://player:3689", "output_name": "Speaker B"},
        "output_eq": {"gain_db": 2.5},
    }), encoding="utf-8")
    store = SettingsStore(str(path), _save_interval_seconds=9999, _writer=MagicMock())
    state = MagicMock()
    state.config_path = str(path)
    state.settings = as_view(store)
    yield state
    store.close(save=False)


def _arrange():
    FakeStore().outputs([
        FakeStore.output_row("o1", "Speaker A", selected=True, volume_percent=30),
        FakeStore.output_row("o2", "Speaker B", selected=False, volume_percent=0),
    ])
    fake_levels([])


def _files_and_player_fail(*, cached_buffer: bool = True) -> ExitStack:
    boom = RuntimeError("must not be asked")
    stack = ExitStack()
    for target in (
        "autostream_start_buffer_cache._fetch",
        "autostream_webui_common.locked_load_config",
        "autostream_config.load_config",
    ):
        stack.enter_context(patch(target, side_effect=boom))
    stack.enter_context(patch("autostream_appliance_models.get_live_output_eq_status", return_value=None))
    if cached_buffer:
        stack.enter_context(patch("autostream_start_buffer_cache.current_ms", return_value=2250))
    return stack


def _reply(route, *args):
    sent: dict = {}
    with patch("autostream_webui_api.send_json",
               side_effect=lambda h, code, body: sent.update(code=code, body=body)), \
         patch("autostream_appliance_gateway.send_json",
               side_effect=lambda h, code, body: sent.update(code=code, body=body)), \
         patch("autostream_appliance_gateway.resolve_appliance", return_value=("bound", None)):
        route(MagicMock(), *args)
    return sent["code"], sent["body"]


def test_the_federation_home_reads_no_file_and_asks_no_player(state):
    _arrange()
    with _files_and_player_fail():
        code, body = _reply(api.send_federation_home_json, state)
    assert code == 200
    assert body["ok"] is True
    assert body["vu_delay_ms"] == 2250
    assert sorted(o["name"] for o in body["outputs"]) == ["Speaker A", "Speaker B"]


def test_the_federation_home_never_waits_on_the_player(state):
    _arrange()
    import autostream_start_buffer_cache as cache
    cache.reset()
    with _files_and_player_fail(cached_buffer=False), \
         patch("autostream_start_buffer_cache._fetch", side_effect=lambda *a, **k: time.sleep(2)):
        started = time.monotonic()
        try:
            code, _ = _reply(api.send_federation_home_json, state)
        finally:
            cache.reset()
    assert code == 200
    assert time.monotonic() - started < 1.0


def test_the_federation_equaliser_reads_no_file(state):
    with _files_and_player_fail():
        code, body = _reply(api.send_federation_equaliser_json, state)
    assert code == 200
    assert body["ok"] is True
    assert body["gain_db"] == pytest.approx(2.5)


def test_the_gateway_bound_home_reads_no_file_and_asks_no_player(state):
    _arrange()
    with _files_and_player_fail():
        code, body = _reply(gw.send_gateway_home_json, state, APPLIANCE_ID)
    assert code == 200
    assert body["vu_delay_ms"] == 2250


def test_the_gateway_bound_equaliser_reads_no_file(state):
    with _files_and_player_fail():
        code, body = _reply(gw.send_gateway_equaliser_json, state, APPLIANCE_ID)
    assert code == 200
    assert body["gain_db"] == pytest.approx(2.5)


def test_the_gateway_bound_output_reads_the_settings_view(state):
    _arrange()
    with _files_and_player_fail(), \
         patch("autostream_appliance_gateway.submit_output_change",
               return_value={"ok": True}) as change:
        code, body = _reply(gw.send_gateway_output_json, state, APPLIANCE_ID,
                            json.dumps({"id": "o1", "selected": True}))
    assert (code, body) == (200, {"ok": True})
    assert change.call_args.kwargs["requester"] == "webui"


@pytest.mark.parametrize("route, args, expected", [
    (api.send_federation_home_json, (), {"ok": False, "error": "boom"}),
    (api.send_federation_equaliser_json, (), {"ok": False, "error": "boom"}),
    (gw.send_gateway_home_json, (APPLIANCE_ID,), {"ok": False, "error": "internal_error"}),
    (gw.send_gateway_equaliser_json, (APPLIANCE_ID,), {"ok": False, "error": "internal_error"}),
])
def test_a_settings_view_that_fails_gives_a_500(state, route, args, expected):
    with patch("autostream_webui_api._config_snapshot", side_effect=RuntimeError("boom")), \
         patch("autostream_appliance_gateway._config_snapshot", side_effect=RuntimeError("boom")):
        code, body = _reply(route, state, *args)
    assert (code, body) == (500, expected)
