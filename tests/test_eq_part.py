"""tests/test_eq_part.py

The equaliser values as a part of the state snapshot: what is published, when
(only after the daemon acknowledged, and after the connection to it is
closed), and what a dial is told.
"""
from __future__ import annotations

import contextlib
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_dial_push as dp
import autostream_monitor_control as control
import autostream_state as state
from autostream_state import eq_band_digest


def eq():
    return state.store().snapshot().eq


def collect():
    seen = []
    state.store().subscribe(seen.append)
    return seen


def client(ok=True):
    c = MagicMock()
    for name in ("set_eq", "set_gain", "set_output_eq", "set_output_gain", "set_output_auto_trim"):
        getattr(c, name).return_value = ok
    return c


def connected(c):
    @contextlib.contextmanager
    def _connected(path=None):
        yield c
    return _connected


def test_the_part_starts_empty():
    assert eq().input_bands == {} and eq().input_gain == {}
    assert eq().output_bands == () and eq().output_gain_db is None
    assert eq().auto_trim_enabled is None


def test_an_input_equaliser_is_published_when_acked():
    seen = collect()
    assert control.apply_input_eq(client(), 1, 1.0, -2.0, 3.5) is True
    assert eq().input_bands == {1: (1.0, -2.0, 3.5)}
    assert [c.parts for c in seen] == [frozenset({"eq"})]


def test_an_input_gain_is_published_when_acked():
    assert control.apply_input_gain(client(), 2, -4.0) is True
    assert eq().input_gain == {2: -4.0}


def test_the_output_values_are_published_when_acked():
    c = client()
    assert control.apply_output_eq(c, 1, 2, 3, 4, 5, 6) is True
    assert control.apply_output_gain(c, -1.5) is True
    assert control.apply_output_auto_trim(c, True) is True
    assert eq().output_bands == (1.0, 2.0, 3.0, 4.0, 5.0, 6.0)
    assert eq().output_gain_db == -1.5 and eq().auto_trim_enabled is True


def test_a_write_the_daemon_refused_publishes_nothing():
    seen = collect()
    c = client(ok=False)
    assert control.apply_input_eq(c, 1, 1, 1, 1) is False
    assert control.apply_input_gain(c, 1, 1) is False
    assert control.apply_output_eq(c, 1, 1, 1, 1, 1, 1) is False
    assert control.apply_output_gain(c, 1) is False
    assert control.apply_output_auto_trim(c, True) is False
    assert seen == []
    assert eq() == state.EqPart()


def test_the_live_setters_publish_the_acked_values():
    c = client()
    with patch("autostream_monitor_client._connected_monitor", connected(c)):
        assert control.set_live_input_eq(2, 1.0, 2.0, 3.0) is True
        assert control.set_live_input_gain(2, 0.5) is True
        assert control.set_live_output_eq(0, 1, 2, 3, 4, 5) is True
        assert control.set_live_output_gain(-2.0) is True
        assert control.set_live_output_auto_trim(False) is True
    assert eq().input_bands == {2: (1.0, 2.0, 3.0)} and eq().input_gain == {2: 0.5}
    assert eq().output_bands == (0.0, 1.0, 2.0, 3.0, 4.0, 5.0)
    assert eq().output_gain_db == -2.0 and eq().auto_trim_enabled is False


def test_a_live_setter_publishes_nothing_when_the_daemon_is_away_or_refuses():
    seen = collect()
    with patch("autostream_monitor_client._connected_monitor", connected(None)):
        assert control.set_live_output_gain(1.0) is False
        assert control.set_live_input_eq(1, 0, 0, 0) is False
    with patch("autostream_monitor_client._connected_monitor", connected(client(ok=False))):
        assert control.set_live_output_eq(1, 1, 1, 1, 1, 1) is False
        assert control.set_live_input_gain(1, 1.0) is False
    assert seen == []


def test_startup_and_resync_publish_the_persisted_values():
    cfg = SimpleNamespace(gain_db=-3.0, peq1_db=1.0, peq2_db=0.0, peq3_db=0.0, peq4_db=0.0,
                          peq5_db=0.0, peq6_db=-1.0, auto_trim_enabled=True)
    assert control._apply_output_eq_config(client(), cfg) is True
    assert eq().output_gain_db == -3.0 and eq().auto_trim_enabled is True
    assert eq().output_bands == (1.0, 0.0, 0.0, 0.0, 0.0, -1.0)


def test_the_publish_happens_after_the_connection_is_closed():
    open_ = [False]
    during = []

    @contextlib.contextmanager
    def tracked(path=None):
        open_[0] = True
        try:
            yield client()
        finally:
            open_[0] = False

    state.store().subscribe(lambda change: during.append(open_[0]))
    with patch("autostream_monitor_client._connected_monitor", tracked):
        control.set_live_output_gain(-1.0)
        control.set_live_input_eq(1, 1.0, 1.0, 1.0)
    assert during == [False, False]


class Hints:
    """The state-hints subscriber with a recorder in place of the coalescer."""

    def __init__(self):
        self.calls = []
        state.store().subscribe(dp.StateHints(notify=lambda *k, **kw: self.calls.append((k, kw))))


def test_a_change_of_the_output_bands_hints_eq_once():
    h = Hints()
    c = client()
    control.apply_output_eq(c, 0, 0, 0, 0, 0, 0)       # the baseline
    assert h.calls == []
    control.apply_output_eq(c, 1, 0, 0, 0, 0, 0)
    assert h.calls == [(("eq",), {"except_dial": None})]


def test_gain_auto_trim_and_input_values_do_not_hint():
    h = Hints()
    c = client()
    control.apply_output_eq(c, 0, 0, 0, 0, 0, 0)
    control.apply_output_gain(c, -1.0)
    control.apply_output_auto_trim(c, True)
    control.apply_input_eq(c, 1, 3, 3, 3)
    control.apply_input_gain(c, 1, 2.0)
    assert h.calls == []


def test_the_band_digest_covers_the_output_bands_only():
    a = state.EqPart(output_bands=(1.0,), output_gain_db=0.0)
    b = state.EqPart(output_bands=(1.0,), output_gain_db=5.0)
    assert eq_band_digest(a) == eq_band_digest(b)
    assert eq_band_digest(a) != eq_band_digest(state.EqPart(output_bands=(2.0,)))


def test_the_input_equaliser_intent_stores_the_bands_then_applies_them():
    from autostream_intents import Intent, Origin, submit
    from autostream_settings import SettingsStore

    store = MagicMock(spec=SettingsStore)
    ctx = SimpleNamespace(settings=store)
    args = {"input": 2, "eq_40hz_db": 1.0, "eq_100hz_db": -1.0, "eq_8khz_db": 2.5}
    with patch("autostream_monitor_control.set_live_input_eq", return_value=True) as live:
        reply = submit(Intent("input.eq.set", args, Origin.USER, "webui", context=ctx))
    assert reply.ok is True
    store.update.assert_called_once()
    raw = {}
    store.update.call_args.args[0](raw)
    assert raw == {"audio2": {"eq_40hz_db": 1.0, "eq_100hz_db": -1.0, "eq_8khz_db": 2.5}}
    live.assert_called_once_with(input_index=2, eq_40hz_db=1.0, eq_100hz_db=-1.0, eq_8khz_db=2.5)


def test_the_input_equaliser_intent_refuses_what_the_route_refuses():
    from autostream_intents import Intent, Origin, submit

    base = {"input": 1, "eq_40hz_db": 0.0, "eq_100hz_db": 0.0, "eq_8khz_db": 0.0}
    with patch("autostream_monitor_control.set_live_input_eq") as live:
        bad_input = submit(Intent("input.eq.set", dict(base, input=3), Origin.USER, "webui"))
        too_loud = submit(Intent("input.eq.set", dict(base, eq_8khz_db=10.5), Origin.USER, "webui"))
    assert bad_input.error == "input must be 1 or 2"
    assert too_loud.error == "EQ gain must be between -10 and 10 dB"
    live.assert_not_called()


def test_a_daemon_that_refuses_the_input_equaliser_gives_the_routes_error():
    from autostream_intents import Intent, Origin, submit

    args = {"input": 1, "eq_40hz_db": 0.0, "eq_100hz_db": 0.0, "eq_8khz_db": 0.0}
    with patch("autostream_monitor_control.set_live_input_eq", return_value=False):
        reply = submit(Intent("input.eq.set", args, Origin.USER, "webui"))
    assert (reply.ok, reply.error) == (False, "Could not update live EQ")
