"""tests/test_eq_intents.py

The output equaliser intents: what the handler returns for each shape of
request, who may ask, and that the requester reaches the published change.
The routes' replies are pinned by their own tests.
"""
from __future__ import annotations

import contextlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_monitor_control as control
import autostream_state as state
from autostream_intents import Intent, Origin, submit


@pytest.fixture
def ctx(tmp_path):
    path = tmp_path / "autostream.json"
    path.write_text(json.dumps({"output_eq": {}}), encoding="utf-8")
    return SimpleNamespace(config_path=str(path), settings=None)


@pytest.fixture
def daemon():
    client = MagicMock()
    for name in ("set_output_eq", "set_output_gain", "set_output_auto_trim"):
        getattr(client, name).return_value = True

    @contextlib.contextmanager
    def connected(path=None):
        yield client

    with patch("autostream_monitor_client._connected_monitor", connected):
        yield client


def _set(ctx, fields, requester="webui", origin=Origin.USER):
    return submit(Intent("output.eq.set", {"fields": fields}, origin, requester, context=ctx))


def test_one_field_replies_with_its_normalised_value(ctx, daemon):
    reply = _set(ctx, (("peq2_db", "3"),))
    assert reply.ok is True
    assert reply.result == {"ok": True, "field": "peq2_db", "value": "3.0", "error": ""}


def test_a_value_past_the_range_is_clamped_not_refused(ctx, daemon):
    assert _set(ctx, (("gain_db", "99"),)).result["value"] == "12.0"


def test_a_boolean_field_replies_true_or_false(ctx, daemon):
    assert _set(ctx, (("auto_trim_enabled", "yes"),)).result["value"] == "true"
    assert _set(ctx, (("auto_trim_enabled", "no"),)).result["value"] == "false"


def test_several_fields_are_one_write_of_the_merged_bands(ctx, daemon):
    reply = _set(ctx, (("peq1_db", 2.0), ("peq2_db", 2.0)))
    assert reply.ok is True and reply.result == {"ok": True, "error": ""}
    daemon.set_output_eq.assert_called_once()


def test_an_unknown_field_or_a_non_numeric_value_is_reported_as_invalid(ctx, daemon):
    unknown = _set(ctx, (("bogus", "1"),))
    assert (unknown.ok, unknown.result) == (False, {"invalid": "Unknown field: 'bogus'"})
    loud = _set(ctx, (("peq1_db", "loud"),))
    assert (loud.ok, loud.result) == (False, {"invalid": "Value must be numeric"})
    daemon.set_output_eq.assert_not_called()


def test_a_failing_save_replies_with_its_error(ctx, daemon):
    with patch("autostream_monitor_control.save_config", side_effect=OSError("disk full")):
        reply = _set(ctx, (("peq1_db", "1"),))
    assert reply.ok is False
    assert reply.result["ok"] is False and reply.result["error"] == "disk full"


def test_reset_zeroes_the_bands_only(ctx, daemon):
    reply = submit(Intent("output.eq.reset", {}, Origin.USER, "webui", context=ctx))
    assert reply.ok is True and reply.result == {"ok": True, "error": ""}
    daemon.set_output_eq.assert_called_once()
    daemon.set_output_gain.assert_not_called()
    daemon.set_output_auto_trim.assert_not_called()


def test_only_a_user_may_change_the_equaliser(ctx, daemon):
    assert _set(ctx, (("peq1_db", "1"),), origin=Origin.SYSTEM).error == "origin_not_allowed"
    assert submit(Intent("output.eq.reset", {}, Origin.SESSION, "coordinator",
                         context=ctx)).error == "origin_not_allowed"


def test_the_requester_reaches_the_published_change(ctx, daemon):
    seen = []
    _set(ctx, (("peq1_db", "1"),))
    state.store().subscribe(seen.append)
    _set(ctx, (("peq1_db", "4"),), requester="dial:abc")
    assert [c.requester for c in seen if "eq" in c.parts] == ["dial:abc"]
