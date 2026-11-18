"""tests/test_settings_view.py

The read-only view of the settings that the web pages hold, the helpers that
reach the store behind it, the two code scans that keep store-type checks and
private store reads out of the web modules, and the rows that write through
the store on behalf of the pages.
"""
from __future__ import annotations

import ast
import json
import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from dataclasses import replace
from unittest.mock import MagicMock, patch

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_CORE = _ROOT / "core"
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

import autostream_core  # noqa: F401  (binds the intent handlers)
import webui.browser.api_settings  # noqa: F401
import webui.browser.api_service  # noqa: F401
from autostream_intents import Intent, Origin, submit
from autostream_settings import SettingsStore, SettingsView, as_view, writable_store
from webui.session_state import WebUIState
from settings_fixtures import fixed_view


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({}), encoding="utf-8")
    s = SettingsStore(str(path), _save_interval_seconds=9999, _writer=MagicMock())
    yield s
    s.close(save=False)


@pytest.fixture
def ctx(store):
    return SimpleNamespace(settings=as_view(store), config_path=store.config_path)


# ---------------------------------------------------------------- the view

def test_the_view_reads_what_the_store_holds(store):
    view = SettingsView(store)
    assert view.snapshot().general.silence_seconds == store.snapshot().general.silence_seconds
    assert view.raw_snapshot() == store.raw_snapshot()
    assert view.generation == store.generation
    assert view.config_path == store.config_path


@pytest.mark.parametrize("name", ["set", "update", "save_now", "close", "reload_from_disk"])
def test_the_view_has_no_way_to_write(store, name):
    view = SettingsView(store)
    with pytest.raises(AttributeError):
        getattr(view, name)


def test_the_view_refuses_new_attributes(store):
    with pytest.raises(AttributeError):
        SettingsView(store).extra = 1


def test_writable_store_resolves_a_view_and_a_store_and_nothing_else(store):
    assert writable_store(SettingsView(store)) is store
    assert writable_store(store) is store
    assert writable_store(None) is None
    assert writable_store(MagicMock()) is None
    assert writable_store(object()) is None


def test_as_view_wraps_a_store_and_passes_anything_else_through(store):
    view = as_view(store)
    assert isinstance(view, SettingsView)
    assert as_view(view) is view
    assert as_view(None) is None
    mock = MagicMock()
    assert as_view(mock) is mock


def test_the_web_state_holds_a_view_however_it_is_given_the_store(store, tmp_path):
    built = WebUIState(store.config_path, str(tmp_path / "state.json"), settings=store)
    assert isinstance(built.settings, SettingsView)
    assert writable_store(built.settings) is store

    later = WebUIState(store.config_path, str(tmp_path / "state.json"), settings=fixed_view())
    later.settings = store
    assert isinstance(later.settings, SettingsView)
    assert writable_store(later.settings) is store

    mock = MagicMock()
    later.settings = mock
    assert later.settings is mock


# ------------------------------------------------------------- code scans

def _core_modules():
    return sorted(_CORE.rglob("*.py"))


def test_no_module_outside_settings_tests_the_store_type():
    offenders = []
    for path in _core_modules():
        if path.name == "autostream_settings.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "isinstance" and len(node.args) == 2):
                kind = node.args[1]
                names = [kind] if not isinstance(kind, ast.Tuple) else list(kind.elts)
                if any(isinstance(n, ast.Name) and n.id in ("SettingsStore", "_SettingsStore")
                       for n in names):
                    offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []


def test_no_web_module_reads_the_private_store_of_a_view():
    offenders = []
    for path in _core_modules():
        if not (path.name.startswith("autostream_webui") or path.parent.relative_to(_CORE).parts[:1] == ("webui",)):
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Attribute) and node.attr == "_store":
                offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []


# ----------------------------------------------- behaviour through a view

def test_a_live_effect_still_finds_its_store_through_a_view(ctx, store):
    import autostream_live_config as live_config
    assert live_config._store_of(ctx) is store
    with patch("autostream_live_config.monitor_control.set_live_repeat_enabled",
               return_value=True) as live:
        assert live_config._live_repeat_enabled(ctx, True) is True
    live.assert_called_once()


# ----------------------------------------------------------------- the rows

def _first_boot(ctx, **args):
    return submit(Intent("first_boot.commit", args, Origin.USER, "webui", context=ctx))


def test_first_boot_records_the_chosen_output(ctx, store):
    reply = _first_boot(ctx, step="output", output_name="Speaker A")
    assert reply.ok is True
    assert [m.name for m in store.snapshot().owntone.default_outputs] == ["Speaker A"]


def test_first_boot_finish_records_the_input_the_volume_and_the_fifo(ctx, store):
    reply = _first_boot(ctx, step="finish", capture_device="hw:1,0", input_type="line",
                        skip_input1=False, volume_percent=35)
    assert reply.ok is True
    snap = store.snapshot()
    assert snap.audio1.capture_device == "hw:1,0"
    assert snap.audio1_enabled is True
    assert snap.owntone.volume_percent == 35
    assert snap.general.fifo_path


def test_first_boot_skip_only_clears_the_enabled_flag(ctx, store):
    store.update(lambda raw: raw.setdefault("audio1", {}).update(
        {"capture_device": "hw:2,0", "enabled": True}))
    reply = _first_boot(ctx, step="finish", skip_input1=True, volume_percent=10)
    assert reply.ok is True
    snap = store.snapshot()
    assert snap.audio1_enabled is False
    assert snap.audio1.capture_device == "hw:2,0"


def test_first_boot_clamps_the_volume(ctx, store):
    assert _first_boot(ctx, step="finish", skip_input1=True, volume_percent=250).ok is True
    assert store.snapshot().owntone.volume_percent == 100


def test_first_boot_refuses_a_step_without_its_values(ctx):
    assert _first_boot(ctx, step="output").error == "invalid_args"
    assert _first_boot(ctx, step="finish", skip_input1=False, volume_percent=10).error == "invalid_args"
    assert _first_boot(ctx, step="other").error == "invalid_request_body"


def test_first_boot_without_a_store_is_refused_and_logged(caplog):
    with caplog.at_level(logging.INFO):
        reply = _first_boot(SimpleNamespace(settings=None, config_path=""),
                            step="output", output_name="Speaker A")
    assert (reply.ok, reply.error) == (False, "Settings store unavailable")
    assert reply.result == {"unavailable": True}
    assert any("first_boot.commit" in r.getMessage() for r in caplog.records)


def _service_field(ctx, path, value):
    return submit(Intent("settings.service_field.set", {"path": path, "value": value},
                         Origin.USER, "webui", context=ctx))


def test_a_service_field_is_normalised_by_its_own_row_and_stored(ctx, store):
    reply = _service_field(ctx, "service_stylus_life_hours_input1", "300")
    assert reply.ok is True
    assert reply.result["value"] == 300
    assert store.snapshot().audio1.stylus_life_hours == 300


def test_an_unknown_or_unrelated_field_is_refused(ctx, store):
    assert _service_field(ctx, "nonexistent", "1").result == {"unknown": True}
    assert _service_field(ctx, "general.silence_seconds", "1").result == {"unknown": True}


def test_a_value_the_normaliser_rejects_is_refused_with_its_message(ctx, store, monkeypatch):
    from autostream_settings_schema import SETTINGS_SCHEMA

    def refuse(value):
        raise ValueError("not a number")

    path = "service_stylus_life_hours_input1"
    monkeypatch.setitem(SETTINGS_SCHEMA, path, replace(SETTINGS_SCHEMA[path], normalise=refuse))
    reply = _service_field(ctx, path, "x")
    assert reply.ok is False
    assert reply.result["invalid"] == reply.error == "Invalid value: not a number"


def test_a_service_field_without_a_store_is_refused_and_logged(caplog):
    with caplog.at_level(logging.INFO):
        reply = _service_field(SimpleNamespace(settings=None, config_path=""),
                               "service_stylus_life_hours_input1", "300")
    assert (reply.ok, reply.error) == (False, "Settings store unavailable")
    assert any("settings.service_field.set" in r.getMessage() for r in caplog.records)


def test_discard_closes_the_store_without_saving(ctx, store):
    store.update(lambda raw: raw.setdefault("webui", {}).update({"dark_mode": True}))
    store._writer.reset_mock()
    reply = submit(Intent("settings.discard", {}, Origin.USER, "webui", context=ctx))
    assert reply.ok is True
    store._writer.assert_not_called()


def test_discard_without_a_store_is_refused(caplog):
    with caplog.at_level(logging.INFO):
        reply = submit(Intent("settings.discard", {}, Origin.USER, "webui",
                              context=SimpleNamespace(settings=None)))
    assert reply.ok is False
    assert any("settings.discard" in r.getMessage() for r in caplog.records)


def test_save_takes_an_optional_timeout(ctx, store):
    saved = []
    store.save_now = lambda timeout=10.0: saved.append(timeout) or True
    assert submit(Intent("settings.save", {}, Origin.USER, "webui", context=ctx)).ok is True
    assert submit(Intent("settings.save", {"timeout": 5.0}, Origin.USER, "webui", context=ctx)).ok is True
    assert saved == [10.0, 5.0]
    assert submit(Intent("settings.save", {"timeout": 0.0}, Origin.USER, "webui",
                         context=ctx)).error == "invalid_timeout"


# ------------------------------------------------ pages read only the settings

def test_the_snapshot_helper_refuses_settings_that_are_not_a_view():
    from webui.common import _config_snapshot
    state = MagicMock()
    state.settings = MagicMock()
    with pytest.raises(TypeError):
        _config_snapshot(state)


def test_a_web_state_cannot_be_built_without_a_view(tmp_path):
    with pytest.raises(TypeError):
        WebUIState(str(tmp_path / "cfg.json"), str(tmp_path / "state.json"))

