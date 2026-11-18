"""tests/test_backend_setting_intents.py

The backend setting intent: what the handler returns for each setting, whether
it asks for a restart, and that a value that cannot be frozen is refused.  The
routes' replies are pinned by their own tests.
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_core  # noqa: F401  (binds the coordinator hooks)
import autostream_live_config as live_config
from autostream_intents import Intent, Origin, submit
from autostream_players import (
    SETTING_UNCOMPRESSED_ALAC,
    ActionResult,
    BackendCapabilities,
    SaveSettingResult,
)
from autostream_settings import SettingsStore

BASE = "http://localhost:3689"


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"owntone": {"base_url": BASE}}), encoding="utf-8")
    s = SettingsStore(str(path), _save_interval_seconds=9999, _writer=MagicMock())
    yield s
    s.close(save=False)


@pytest.fixture
def ctx(store, tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({"owntone": {"known_outputs": {}}}), encoding="utf-8")
    return SimpleNamespace(
        settings=store, config_path=str(tmp_path / "config.json"), state_path=str(state_path))


def _set(ctx, setting, value, output_id=None, origin=Origin.USER):
    args = {"setting": setting, "value": value}
    if output_id is not None:
        args["output_id"] = output_id
    return submit(Intent("backend.setting.set", args, origin, "webui", context=ctx))


def _saved(**kwargs):
    return SaveSettingResult(**{"ok": True, **kwargs})


# ------------------------------------------------------------ native settings

def test_a_native_setting_is_pushed_and_reports_whether_a_restart_is_needed(ctx):
    with patch("autostream_live_config.save_setting", return_value=_saved(restart_required=True)) as save:
        reply = _set(ctx, "uncompressed_audio", True)
    assert reply.ok is True and reply.result == {"restart_required": True}
    assert save.call_args.args[:3] == (BASE, SETTING_UNCOMPRESSED_ALAC, True)


def test_a_backend_failure_is_reported_with_its_message(ctx):
    with patch("autostream_live_config.save_setting",
               return_value=_saved(ok=False, error="backend said no")):
        reply = _set(ctx, "uncompressed_audio", True)
    assert (reply.ok, reply.error) == (False, "backend said no")


def test_an_unsupported_setting_is_tolerated_unless_the_control_is_backend_gated(ctx):
    unsupported = _saved(ok=False, unsupported=True)
    with patch("autostream_live_config.save_setting", return_value=unsupported):
        assert _set(ctx, "uncompressed_audio", True).ok is True
        assert _set(ctx, "user_agent", "x").ok is False
        assert _set(ctx, "buffered_audio", True).ok is False


def test_buffered_audio_off_resets_the_outputs_saved_with_a_buffered_mode(ctx, store):
    store.update(lambda raw: raw.setdefault("owntone", {}).update(
        {"airplay_modes": {"1": "airplay2_buffered", "2": "raop"}}))
    with patch("autostream_live_config.save_setting", return_value=_saved()), \
            patch("autostream_live_config.update_live_owntone_runtime"):
        off = _set(ctx, "buffered_audio", False)
        on = _set(ctx, "buffered_audio", True)
    assert off.result["reset_outputs"] == ["1"]
    assert on.result["reset_outputs"] == []
    assert store.snapshot().owntone.output_airplay_modes["1"] == "default"
    assert store.snapshot().owntone.output_airplay_modes["2"] == "raop"


def test_the_start_buffer_cache_follows_only_a_saved_value(ctx):
    with patch("autostream_live_config.save_setting", return_value=_saved()), \
            patch("autostream_live_config.start_buffer_cache.note_saved") as note:
        _set(ctx, "start_buffer_ms", 1500)
    note.assert_called_once_with(1500)
    with patch("autostream_live_config.save_setting", return_value=_saved(ok=False, error="no")), \
            patch("autostream_live_config.start_buffer_cache.note_saved") as note:
        assert _set(ctx, "start_buffer_ms", 1500).ok is False
    note.assert_not_called()


# ------------------------------------------------------------ mDNS grace period

def test_the_grace_period_is_stored_applied_to_discovery_and_forwarded(ctx, store):
    with patch("autostream_live_config.save_setting", return_value=_saved()), \
            patch("autostream_appliances.set_grace_period") as browser:
        reply = _set(ctx, "mdns_grace_period", 240)
    assert reply.ok is True and reply.result == {"restart_required": False}
    browser.assert_called_once_with(240)
    assert store.snapshot().general.mdns_grace_period_seconds == 240


def test_a_failed_forward_is_a_warning_not_a_failure(ctx):
    with patch("autostream_live_config.save_setting", return_value=_saved(ok=False, error="down")), \
            patch("autostream_appliances.set_grace_period"):
        reply = _set(ctx, "mdns_grace_period", 240)
    assert reply.ok is True
    assert reply.result == {"restart_required": False, "warning": "down"}


def test_the_grace_period_needs_a_store():
    reply = _set(SimpleNamespace(settings=None, config_path=""), "mdns_grace_period", 240)
    assert (reply.ok, reply.error) == (False, "Settings store unavailable")


# ------------------------------------------------------------ per-output settings

def test_a_buffered_mode_is_refused_while_buffered_audio_is_off(ctx, store):
    with patch("autostream_live_config._buffered_audio_is_enabled", return_value=False):
        reply = _set(ctx, "output_mode", "airplay2_buffered", "7")
    assert reply.ok is False and "Buffered audio is disabled" in reply.error
    assert "7" not in store.snapshot().owntone.output_airplay_modes


def test_an_output_mode_is_stored_and_applied_live(ctx, store):
    with patch("autostream_live_config._buffered_audio_is_enabled", return_value=True), \
            patch("autostream_live_config.update_live_owntone_runtime") as live:
        reply = _set(ctx, "output_mode", "airplay2_buffered", "7")
    assert reply.ok is True and reply.result == {"output_id": "7", "mode": "airplay2_buffered"}
    assert store.snapshot().owntone.output_airplay_modes["7"] == "airplay2_buffered"
    live.assert_called_once()


def test_hiding_and_showing_an_output_is_case_insensitive_and_remembers_its_id(ctx, store):
    hide = _set(ctx, "output_visibility", {"output_name": "Speaker A", "visible": False}, "7")
    assert hide.result == {"output_name": "Speaker A", "visible": False}
    assert store.snapshot().webui.hidden_outputs == ("Speaker A",)
    assert json.loads(Path(ctx.state_path).read_text())["owntone"]["known_outputs"] == {"7": "Speaker A"}
    _set(ctx, "output_visibility", {"output_name": "speaker a", "visible": True})
    assert store.snapshot().webui.hidden_outputs == ()


def test_hiding_an_output_tells_the_output_authority(ctx):
    with patch("autostream_live_config.get_authority") as authority:
        _set(ctx, "output_visibility", {"output_name": "Speaker A", "visible": False})
    authority.return_value.set_hidden_outputs.assert_called_once_with(("Speaker A",))


def test_an_offset_is_stored_and_reaches_the_speaker_only_when_the_backend_can(ctx, store):
    live = BackendCapabilities(can_set_output_offset=True)
    with patch("autostream_live_config.update_live_owntone_runtime"), \
            patch("autostream_player_service.get_capabilities", return_value=live), \
            patch("autostream_player_service.supports_live_offset", return_value=True), \
            patch("autostream_player_service.update_output", return_value=ActionResult(ok=True)) as push:
        reply = _set(ctx, "output_offset", 250, "7")
    assert reply.result == {"output_id": "7", "offset_ms": 250, "applied_live": True}
    push.assert_called_once_with(BASE, "7", offset_ms=250, timeout=2)
    assert store.snapshot().owntone.output_offsets_ms["7"] == 250

    with patch("autostream_live_config.update_live_owntone_runtime"), \
            patch("autostream_player_service.get_capabilities",
                  return_value=BackendCapabilities(can_set_output_offset=False)), \
            patch("autostream_player_service.update_output") as push:
        reply = _set(ctx, "output_offset", 300, "7")
    assert reply.result["applied_live"] is False
    push.assert_not_called()
    assert store.snapshot().owntone.output_offsets_ms["7"] == 300


def test_an_offset_without_an_output_is_reported_as_missing_one(ctx):
    reply = _set(ctx, "output_offset", 10, "")
    assert (reply.ok, reply.error) == (False, "output_id required")



# ------------------------------------------------------------ include_tv

def _tv_units(playing=True, supported=True):
    """The outputs part of a player whose rows say whether HomePods are present."""
    from fake_store import FakeStore
    from autostream_players import OutputInfo
    rows = [OutputInfo(id="7", name="TV A", selected=playing,
                       session_state="streaming" if playing else "stopped",
                       has_homepods=True if supported else None)]
    FakeStore().outputs(rows)


def test_an_include_tv_change_is_stored_and_restarts_a_playing_group(ctx, store):
    from autostream_state.outputs import get_authority
    _tv_units()
    with patch.object(get_authority(), "reselect") as reselect:
        reselect.return_value = SimpleNamespace(refused=None)
        reply = _set(ctx, "output_include_tv", False, "7")
    assert reply.result == {"output_id": "7", "include_tv": False, "reselected": True}
    assert store.snapshot().owntone.include_tv == {"7": False}
    reselect.assert_called_once_with("7", Origin.USER, requester="webui")


def test_an_include_tv_change_on_a_group_that_is_not_playing_restarts_nothing(ctx, store):
    from autostream_state.outputs import get_authority
    _tv_units(playing=False)
    with patch.object(get_authority(), "reselect") as reselect:
        reply = _set(ctx, "output_include_tv", False, "7")
    assert reply.result["reselected"] is False
    assert store.snapshot().owntone.include_tv == {"7": False}
    reselect.assert_not_called()


def test_an_unchanged_include_tv_choice_restarts_nothing(ctx, store):
    from autostream_state.outputs import get_authority
    _tv_units()
    with patch.object(get_authority(), "reselect") as reselect:
        reply = _set(ctx, "output_include_tv", True, "7")
    assert reply.result["reselected"] is False
    reselect.assert_not_called()
    assert store.snapshot().owntone.include_tv == {}


def test_include_tv_is_refused_when_the_player_cannot_do_it(ctx, store):
    _tv_units(playing=False, supported=False)
    reply = _set(ctx, "output_include_tv", False, "7")
    assert (reply.ok, reply.error) == (False, "Not supported by the connected player")
    assert store.snapshot().owntone.include_tv == {}


def test_include_tv_without_an_output_is_reported_as_missing_one(ctx):
    _tv_units(playing=False)
    reply = _set(ctx, "output_include_tv", False, "")
    assert (reply.ok, reply.error) == (False, "output_id required")


# ------------------------------------------------------------ the row

def test_a_value_that_cannot_be_frozen_is_refused_not_raised(ctx):
    reply = _set(ctx, "output_offset", object(), "7")
    assert (reply.ok, reply.error) == (False, "invalid_args")


def test_an_unknown_setting_is_refused(ctx):
    assert _set(ctx, "bogus", 1).error == "invalid_setting"


def test_users_and_the_system_may_change_a_backend_setting_and_nobody_else(ctx):
    with patch("autostream_live_config.save_setting", return_value=_saved()):
        assert _set(ctx, "uncompressed_audio", True, origin=Origin.SYSTEM).ok is True
        assert _set(ctx, "uncompressed_audio", True, origin=Origin.SESSION).error == "origin_not_allowed"


def test_the_startup_grace_period_asks_for_a_restart_only_through_its_callback(ctx):
    restarts = []
    done = threading.Event()

    def fake_push(state, key, value, reject_unsupported=False):
        done.set()
        return True, True, ""

    with patch("autostream_live_config._push_owntone_native_setting", fake_push), \
            patch("autostream_appliances.set_grace_period") as browser:
        live_config.apply_mdns_grace_period_startup(ctx, on_restart=restarts.append)
        assert done.wait(2.0)
        for thread in threading.enumerate():
            if thread.name == "mdns-grace-startup":
                thread.join(2.0)
    browser.assert_called_once()
    assert restarts == [ctx]
