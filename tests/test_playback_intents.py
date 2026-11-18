"""tests/test_playback_intents.py

The rows that reset a service counter and hand an input's playback settings
to the tracker: what each calls, what it replies, what it logs, and who may
ask.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_core  # noqa: F401  (binds every handler)
import autostream_playback_tracking as playback_tracking
import autostream_runtime as runtime
from autostream_intents import Intent, submit
from autostream_playback_stats import MaintenanceResetResult
from autostream_state import Origin

APPLIED = MaintenanceResetResult(applied=True, persisted=True, last_service_at="1999-12-31T00:00:00")
NOT_APPLIED = MaintenanceResetResult(applied=False, persisted=False)

SETTINGS = {
    "enabled": True,
    "is_turntable": True,
    "input_type": "turntable",
    "stylus_life_hours": 500,
    "belt_life_hours": 0,
    "belt_life_years": 0,
    "bearing_life_hours": 0,
    "bearing_life_years": 0,
}


def _reset(input_index=1, item="stylus", origin=Origin.USER):
    return submit(Intent("input.counters.reset", {"input": input_index, "item": item}, origin, "webui"))


def _set(input_index=1, origin=Origin.USER, **settings):
    return submit(Intent("input.playback_config.set", {"input": input_index, **settings}, origin, "webui"))


@pytest.mark.parametrize("item,name", [
    ("stylus", "reset_input_stylus"), ("belt", "reset_input_belt"), ("bearing", "reset_input_bearing"),
])
def test_a_reset_calls_the_matching_reset_with_the_index(item, name):
    with patch.object(playback_tracking, name, return_value=APPLIED) as fn:
        reply = _reset(2, item)
    fn.assert_called_once_with(2)
    assert reply.ok is True and reply.error is None
    assert reply.result["reset"] == APPLIED


def test_a_reset_that_is_not_applied_replies_not_applied_with_the_result():
    with patch.object(playback_tracking, "reset_input_belt", return_value=NOT_APPLIED):
        reply = _reset(1, "belt")
    assert (reply.ok, reply.error) == (False, "not_applied")
    assert reply.result["reset"] == NOT_APPLIED


@pytest.mark.parametrize("input_index,item,error", [
    (3, "stylus", "Input must be 1 or 2"),
    ("1", "stylus", "Input must be 1 or 2"),
    (1, "needle", "invalid_item"),
])
def test_a_bad_input_or_item_is_refused_before_any_call(input_index, item, error):
    with patch.object(playback_tracking, "reset_input_stylus") as stylus, \
            patch.object(playback_tracking, "reset_input_belt") as belt, \
            patch.object(playback_tracking, "reset_input_bearing") as bearing:
        reply = _reset(input_index, item)
    assert (reply.ok, reply.error) == (False, error)
    assert not (stylus.called or belt.called or bearing.called)


def test_a_reset_with_no_tracker_is_refused_at_info(caplog):
    runtime._playback_tracker = None
    with caplog.at_level(logging.DEBUG, logger="autostream.intents"):
        reply = _reset(1, "stylus")
    assert (reply.ok, reply.error) == (False, "not_applied")
    lines = [r for r in caplog.records if r.name == "autostream.intents"]
    assert len(lines) == 1 and lines[0].levelno == logging.INFO
    assert "result=not_applied" in lines[0].getMessage()


def test_the_settings_are_passed_through_unchanged():
    with patch.object(playback_tracking, "update_playback_input_config", return_value=True) as fn:
        reply = _set(2, **SETTINGS)
    fn.assert_called_once_with(2, **SETTINGS)
    assert reply.ok is True and reply.result["updated"] is True


def test_is_bluetooth_is_passed_when_given_and_left_out_when_not():
    with patch.object(playback_tracking, "update_playback_input_config", return_value=True) as fn:
        _set(1, is_bluetooth=True, **SETTINGS)
        _set(1, **SETTINGS)
    assert fn.call_args_list[0].kwargs["is_bluetooth"] is True
    assert "is_bluetooth" not in fn.call_args_list[1].kwargs


def test_no_tracker_replies_ok_with_updated_false():
    runtime._playback_tracker = None
    reply = _set(1, **SETTINGS)
    assert reply.ok is True and reply.result["updated"] is False


def test_each_accepted_intent_logs_one_debug_line(caplog):
    with patch.object(playback_tracking, "update_playback_input_config", return_value=True), \
            patch.object(playback_tracking, "reset_input_stylus", return_value=APPLIED), \
            caplog.at_level(logging.DEBUG, logger="autostream.intents"):
        _set(1, **SETTINGS)
        _reset(1, "stylus")
    lines = [r for r in caplog.records if r.name == "autostream.intents"]
    assert [r.levelno for r in lines] == [logging.DEBUG, logging.DEBUG]
    assert "intent input.playback_config.set origin=user requester=webui result=ok" in lines[0].getMessage()
    assert "intent input.counters.reset origin=user requester=webui result=ok" in lines[1].getMessage()


@pytest.mark.parametrize("origin", [Origin.SYSTEM, Origin.SESSION, Origin.DEVICE])
def test_only_users_may_ask(origin):
    with patch.object(playback_tracking, "update_playback_input_config") as update, \
            patch.object(playback_tracking, "reset_input_stylus") as reset:
        assert _reset(1, "stylus", origin).error == "origin_not_allowed"
        assert _set(1, origin=origin, **SETTINGS).error == "origin_not_allowed"
    assert not (update.called or reset.called)


@pytest.mark.parametrize("settings", [
    {**SETTINGS, "enabled": 1},
    {**SETTINGS, "is_turntable": "yes"},
    {**{k: v for k, v in SETTINGS.items() if k != "input_type"}},
    {**SETTINGS, "extra": 1},
])
def test_bad_settings_are_refused_before_any_call(settings):
    with patch.object(playback_tracking, "update_playback_input_config") as update:
        reply = _set(1, **settings)
    assert reply.ok is False and reply.error
    assert not update.called


def test_the_service_route_logs_a_refused_settings_submit_at_debug(caplog):
    import autostream_webui_api as api
    from unittest.mock import MagicMock
    refused = MagicMock(ok=False, error="invalid_args")
    with patch.object(api, "submit", return_value=refused), \
            caplog.at_level(logging.DEBUG):
        api._submit_playback_config(1, **SETTINGS)
    assert any(
        r.levelno == logging.DEBUG
        and r.getMessage() == "playback settings for input 1 not applied: invalid_args"
        for r in caplog.records
    )
