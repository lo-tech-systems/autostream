"""tests/test_settings_intents.py

The settings intents: what the handlers return for a live, a reload and a
passive row, for the advertisement and automatic-update switches, for saving
and reloading, and for the Setup form's live steps.  The routes' replies are
pinned by their own tests.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_core  # noqa: F401  (binds the intent handlers)
import autostream_live_config as live_config
import autostream_state as state
import autostream_webui_api  # noqa: F401  (registers the personalisation rows)
from autostream_config import parse_config
from autostream_intents import Intent, Origin, submit
from autostream_settings import SettingsStore


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({}), encoding="utf-8")
    s = SettingsStore(str(path), _save_interval_seconds=9999, _writer=MagicMock())
    yield s
    s.close(save=False)


@pytest.fixture
def ctx(store, tmp_path):
    return SimpleNamespace(settings=store, config_path=str(tmp_path / "config.json"))


def _apply(ctx, *changes, origin=Origin.USER):
    return submit(Intent("settings.apply", {"changes": changes}, origin, "webui", context=ctx))


# ------------------------------------------------------------------ settings.apply

def test_a_live_row_reports_that_its_live_effect_ran(ctx, store):
    with patch("autostream_live_config.update_live_silence_seconds", return_value=True) as live:
        reply = _apply(ctx, ("general.silence_seconds", 30))
    assert reply.ok is True
    assert reply.result["outcomes"] == [
        {"persisted": True, "live": True, "live_error": None, "reload_scheduled": False}]
    live.assert_called_once_with(30)
    assert store.snapshot().general.silence_seconds == 30


def test_a_live_effect_that_fails_is_reported_with_its_error(ctx):
    with patch("autostream_live_config.update_live_silence_seconds", return_value=False):
        reply = _apply(ctx, ("general.silence_seconds", 30))
    assert reply.ok is True
    assert reply.result["outcomes"][0]["live"] is False
    assert reply.result["outcomes"][0]["live_error"] == "Live effect could not be applied"


def test_a_live_effect_that_raises_is_a_failed_live_effect_not_a_failed_save(ctx, store):
    with patch("autostream_live_config.update_live_silence_seconds", side_effect=RuntimeError("x")):
        reply = _apply(ctx, ("general.silence_seconds", 45))
    assert reply.ok is True and reply.result["outcomes"][0]["live"] is False
    assert store.snapshot().general.silence_seconds == 45


def test_a_passive_row_has_no_live_effect_and_no_error(ctx, store):
    reply = _apply(ctx, ("webui.dark_mode", True))
    assert reply.result["outcomes"] == [
        {"persisted": True, "live": False, "live_error": None, "reload_scheduled": False}]
    assert store.snapshot().webui.dark_mode is True


def test_a_reload_row_schedules_the_debounced_reload(ctx):
    with patch("autostream_live_config._debounce_coordinator_reload") as debounce:
        reply = _apply(ctx, ("audio1.capture_device", "hw:1,0"))
    assert reply.result["outcomes"][0]["reload_scheduled"] is True
    debounce.assert_called_once_with(ctx)


def test_changes_are_applied_in_order_and_each_has_an_outcome(ctx, store):
    reply = _apply(ctx, ("webui.dark_mode", True), ("webui.show_input_detail", True))
    assert len(reply.result["outcomes"]) == 2
    snap = store.snapshot()
    assert snap.webui.dark_mode is True and snap.webui.show_input_detail is True


def test_the_reply_carries_the_store_version(ctx):
    reply = _apply(ctx, ("webui.dark_mode", True))
    assert reply.version == state.store().snapshot().version


def test_a_cross_field_failure_is_reported_as_invalid_with_its_text(ctx):
    _apply(ctx, ("audio2.capture_device", "hw:2,0"))
    with patch("autostream_live_config._debounce_coordinator_reload"):
        reply = _apply(ctx, ("audio1.capture_device", "hw:2,0"))
    assert reply.ok is False
    assert reply.result["invalid"] == reply.error
    assert "already" in reply.error.lower() or "same" in reply.error.lower()


def test_a_missing_store_is_reported_as_unavailable():
    reply = _apply(SimpleNamespace(settings=None, config_path=""), ("webui.dark_mode", True))
    assert (reply.ok, reply.error) == (False, "Settings store unavailable")


def test_a_store_failure_is_reported_as_an_internal_error(ctx, store):
    with patch.object(store, "update", side_effect=OSError("disk")):
        reply = _apply(ctx, ("webui.dark_mode", True))
    assert (reply.ok, reply.error) == (False, "Internal error")
    assert reply.result == {"internal": True}


def test_apply_is_for_users_and_the_system_only(ctx):
    assert _apply(ctx, ("webui.dark_mode", True), origin=Origin.SYSTEM).ok is True
    assert _apply(ctx, ("webui.dark_mode", True), origin=Origin.SESSION).error == "origin_not_allowed"


# ------------------------------------------------------------------ save and reload

def test_save_flushes_the_store(ctx, store):
    with patch.object(store, "save_now", return_value=True) as flush:
        reply = submit(Intent("settings.save", {}, Origin.USER, "webui", context=ctx))
    assert reply.ok is True
    flush.assert_called_once()


def test_a_save_that_fails_says_so(ctx, store):
    with patch.object(store, "save_now", return_value=False):
        reply = submit(Intent("settings.save", {}, Origin.USER, "webui", context=ctx))
    assert (reply.ok, reply.error) == (False, "Settings could not be saved")


def test_save_without_a_store_says_so():
    reply = submit(Intent("settings.save", {}, Origin.USER, "webui",
                          context=SimpleNamespace(settings=None)))
    assert (reply.ok, reply.error) == (False, "Settings store not available")


def test_the_system_may_ask_for_a_reload():
    with patch("autostream_runtime.request_config_reload") as reload:
        reply = submit(Intent("settings.reload", {"reason": "device scan"}, Origin.SYSTEM, "coordinator"))
    assert reply.ok is True
    reload.assert_called_once_with()


def test_a_reload_needs_a_reason():
    reply = submit(Intent("settings.reload", {}, Origin.USER, "webui"))
    assert reply.error == "invalid_args"


def test_the_debounced_reload_saves_first_and_then_reloads(ctx, store, monkeypatch):
    monkeypatch.setattr(live_config, "_coordinator_reload_timer", None)
    seen = []
    with patch.object(store, "save_now", side_effect=lambda *a, **k: seen.append("save") or True), \
            patch("autostream_runtime.request_config_reload", side_effect=lambda: seen.append("reload")), \
            patch("autostream_live_config.threading.Timer") as timer:
        live_config._debounce_coordinator_reload(ctx)
        timer.call_args.args[1]()
    assert seen == ["save", "reload"]


# ------------------------------------------------------------------ advertisement

def _advertise(ctx, value=True, **extra):
    return submit(Intent("settings.advertisement", {"value": value, "version": "1.0", **extra},
                         Origin.USER, "webui", context=ctx))


def test_the_preference_is_stored_only_after_the_announcement_worked(ctx, store):
    held = []
    with patch("autostream_appliances.reconcile_appliance_announcement",
               side_effect=lambda *a: held.append(live_config._advertise_lock.locked()) or True) as rec:
        reply = _advertise(ctx, False)
    assert reply.ok is True
    rec.assert_called_once_with("1.0", False)
    assert held == [True]
    assert store.snapshot().webui.advertise_appliance is False


def test_a_failed_announcement_leaves_the_store_alone(ctx, store):
    before = store.snapshot().webui.advertise_appliance
    with patch("autostream_appliances.reconcile_appliance_announcement", return_value=False):
        reply = _advertise(ctx, not before)
    assert (reply.ok, reply.error) == (False, "apply_failed")
    assert store.snapshot().webui.advertise_appliance is before


def test_a_store_write_that_fails_still_reports_success_with_a_warning(ctx, store):
    with patch("autostream_appliances.reconcile_appliance_announcement", return_value=True), \
            patch.object(store, "update", side_effect=OSError("disk")):
        reply = _advertise(ctx, False)
    assert reply.ok is True
    assert "could not be saved" in reply.result["warning"]


def test_the_form_path_writes_the_file_and_restores_the_old_preference_on_failure(ctx):
    with patch("autostream_appliances.reconcile_appliance_announcement", return_value=True) as rec, \
            patch("autostream_live_config.load_config", return_value={}), \
            patch("autostream_live_config.save_config", side_effect=OSError("disk")):
        reply = _advertise(ctx, False, rollback_to=True)
    assert (reply.ok, reply.error) == (False, "save_failed")
    assert [c.args for c in rec.call_args_list] == [("1.0", False), ("1.0", True)]


def test_the_form_path_persists_to_the_configuration_file(ctx):
    saved = {}
    with patch("autostream_appliances.reconcile_appliance_announcement", return_value=True), \
            patch("autostream_live_config.load_config", return_value={}), \
            patch("autostream_live_config.save_config", side_effect=lambda p, c: saved.update(c)):
        reply = _advertise(ctx, False, rollback_to=True)
    assert reply.ok is True
    assert saved == {"webui": {"advertise_appliance": False}}


def test_a_value_that_is_not_a_boolean_is_refused(ctx):
    reply = _advertise(ctx, "yes")
    assert reply.error == "value must be a boolean"


# ------------------------------------------------------------------ automatic updates

def _auto_update(ctx, value=True):
    return submit(Intent("settings.auto_update", {"value": value}, Origin.USER, "webui", context=ctx))


def test_the_timer_is_switched_before_the_preference_is_stored(ctx, store):
    done = SimpleNamespace(returncode=0, stderr="")
    with patch("autostream_live_config.run_admin_cmd", return_value=done) as admin:
        reply = _auto_update(ctx, True)
    assert reply.ok is True
    admin.assert_called_once_with(["toggle-update-timer", "enable"], timeout=5.0)
    assert store.snapshot().updates.auto_update is True


def test_a_failed_timer_call_does_not_store_the_preference(ctx, store):
    before = store.snapshot().updates.auto_update
    failed = SimpleNamespace(returncode=1, stderr="no")
    with patch("autostream_live_config.run_admin_cmd", return_value=failed):
        reply = _auto_update(ctx, not before)
    assert (reply.ok, reply.error) == (False, f"Auto-update timer could not be {'enable' if not before else 'disable'}d")
    assert store.snapshot().updates.auto_update is before


# ------------------------------------------------------------------ the Setup form's live steps

def _form(cfg, *steps):
    return submit(Intent("settings.form_apply", {"steps": steps}, Origin.USER, "webui", context=cfg))


def test_the_steps_run_in_order_with_the_forms_values():
    cfg = parse_config({})
    order = []
    with patch("autostream_live_config.update_live_owntone_runtime",
               side_effect=lambda **kw: order.append(("owntone", kw["output_name"], kw["volume_percent"])) or True), \
            patch("autostream_playback_tracking.update_playback_input_config",
                  side_effect=lambda i, **kw: order.append(("input", i, kw["enabled"], kw["input_type"])) or True), \
            patch("autostream_live_config.update_live_silence_seconds",
                  side_effect=lambda s: order.append(("silence", s)) or True):
        reply = _form(
            cfg,
            ("owntone_runtime", {"output_name": "Speaker A", "volume_percent": "35"}),
            ("playback_input", {"input": 1, "enabled": True, "is_turntable": True}),
            ("playback_input", {"input": 2, "enabled": False, "is_turntable": False}),
            ("silence_seconds", 20),
        )
    assert reply.ok is True and reply.result["results"] == [True, True, True, True]
    assert order == [
        ("owntone", "Speaker A", "35"),
        ("input", 1, True, "turntable"),
        ("input", 2, False, "line"),
        ("silence", 20),
    ]


def test_a_step_that_is_not_applied_makes_the_outcome_not_ok():
    with patch("autostream_live_config.update_live_silence_seconds", return_value=False):
        reply = _form(parse_config({}), ("silence_seconds", 20))
    assert reply.ok is False and reply.result["results"] == [False]


def test_the_track_identification_step_rebuilds_from_the_config_file():
    with patch("autostream_live_config.identification") as hooks:
        reply = _form(parse_config({}), ("track_id", "/etc/example.json"))
    assert reply.ok is True
    hooks.apply_track_id_config_live.assert_called_once_with("/etc/example.json")


def test_an_unknown_step_is_refused():
    assert _form(parse_config({}), ("bogus", 1)).error == "invalid_steps"


def test_the_form_is_for_users_only():
    reply = submit(Intent("settings.form_apply", {"steps": ()}, Origin.SYSTEM, "coordinator",
                          context=parse_config({})))
    assert reply.error == "origin_not_allowed"


# ------------------------------------------------------------------ the output policy settings

@pytest.mark.parametrize("path,value,read", [
    ("outputs.device_pause_scope", "off_all", lambda c: c.outputs.device_pause_scope),
    ("outputs.pause_off_seconds", 90, lambda c: c.outputs.pause_off_seconds),
    ("outputs.play_after_metadata_ignore_seconds", 2.5, lambda c: c.outputs.play_after_metadata_ignore_seconds),
])
def test_an_output_policy_setting_is_stored_and_reported_live(ctx, store, path, value, read):
    reply = _apply(ctx, (path, value))
    assert reply.ok is True
    assert reply.result["outcomes"] == [
        {"persisted": True, "live": True, "live_error": None, "reload_scheduled": False}]
    assert read(store.snapshot()) == value


def test_the_output_policy_settings_are_read_by_the_next_event(ctx, store):
    live_config.bind_settings_store(store)
    assert live_config.output_policy_settings().device_pause_scope == "ignore"
    _apply(ctx, ("outputs.device_pause_scope", "all"), ("outputs.pause_off_seconds", 45))
    got = live_config.output_policy_settings()
    assert (got.device_pause_scope, got.pause_off_seconds) == ("all", 45)
