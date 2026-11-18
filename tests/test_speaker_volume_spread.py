"""tests/test_speaker_volume_spread.py

A volume change made at one speaker, applied to the other playing speakers:
the arithmetic (autostream_state.spread) and how the output authority arms,
consumes and spreads a report, with the fake clock and backend of the output
authority tests.
"""
from __future__ import annotations

import dataclasses
import logging
import sys
from pathlib import Path

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_state as state
import autostream_state.outputs as outputs
from autostream_state import Origin, spread
from autostream_backend_events import ConnectInfo, DeviceEvent
from output_fakes import error, group_row, row, snap
from test_output_authority import T0, at, put, w  # noqa: F401  (w is the fixture)


# ---------------------------------------------------------------------------
# The arithmetic
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("base,old,new,expected", [
    ({"B": 40, "C": 20}, 30, 15, {"B": 20, "C": 10}),
    ({"B": 40, "C": 20}, 30, 0, {"B": 0, "C": 0}),
    ({"B": 40, "C": 20}, 30, 1, {"B": 1, "C": 1}),
    ({"B": 80}, 50, 100, {"B": 100}),
    ({"B": 80}, 50, 50, {"B": 80}),
    ({"B": 5}, 2, 1, {"B": 2}),
    ({"B": 0, "C": 30}, 30, 60, {"B": 0, "C": 60}),
    ({"B": 40, "C": 20}, 0, 6, {"B": 48, "C": 24}),
    ({"B": 0, "C": 0}, 0, 7, {"B": 7, "C": 7}),
    ({}, 30, 15, {}),
])
def test_spread_levels(base, old, new, expected):
    assert spread.spread_levels(base, old, new) == expected


def test_spread_levels_keeps_the_order_of_base():
    got = spread.spread_levels({"z": 10, "a": 20, "m": 30}, 10, 5)
    assert list(got) == ["z", "a", "m"]


def test_a_burst_expires_at_exactly_the_quiet_time():
    b = spread.Burst("1", 30, {"2": 40}, {"2": 0}, last_at=10.0)
    assert not b.expired(10.0 + spread.SPREAD_QUIET_S - 0.01)
    assert b.expired(10.0 + spread.SPREAD_QUIET_S)


def test_a_burst_notes_its_last_spread_and_lists_what_moved():
    b = spread.Burst("1", 30, {"2": 40, "3": 20, "4": 10}, {"2": 0, "3": 0, "4": 0}, last_at=1.0)
    assert b.moved() == []
    b.note_spread(2.0, 15, {"2": (1, 20), "3": (1, 20), "4": (1, 5)})
    assert b.last_at == 2.0 and b.reporter_new == 15
    assert b.seqs == {"2": 1, "3": 1, "4": 1}
    assert b.moved() == ["2", "4"]


def test_the_hold_and_report_windows_follow_the_authority_constants():
    assert spread.SPREAD_HOLD_S == outputs.DEBOUNCE_S + outputs.DEVICE_VOLUME_MARK_S
    assert spread.SPREAD_REPORT_S == spread.SPREAD_HOLD_S + outputs.WRITE_TIMEOUT_S


# ---------------------------------------------------------------------------
# The authority
# ---------------------------------------------------------------------------

def arm(w, reader=lambda: True):
    w.a.note_session(True)
    w.a._handle_connected(ConnectInfo("b0", 1, frozenset({"device_volume", "receiver_command"}), "unix_socket"))
    w.a.set_spread_reader(reader)
    at(w, 0)


def setup3(w, levels=(30, 40, 20), reader=lambda: True):
    """Three selected speakers, seen playing before the hold, session active,
    device events delivered, the setting read through *reader*."""
    w.t[0] = T0 - spread.SPREAD_HOLD_S - 1
    put(w, [row(i + 1, selected=True, volume_percent=v) for i, v in enumerate(levels)])
    w.t[0] = T0
    arm(w, reader)


def set_level(w, uid, level, **fields):
    w.fb.rows = [dataclasses.replace(r, volume_percent=level, **fields) if r.id == uid else r
                 for r in w.fb.rows]


def report(w, uid, level, at_s, *, event=True, read=True, **fields):
    """The speaker *uid* now reports *level*; its event and the notice reach
    the worker together."""
    set_level(w, uid, level, **fields)
    if event:
        w.a.on_device_event(DeviceEvent("device_volume", uid, None, "volumedown", str(level), 1, 1.0))
    if read:
        w.a.on_outputs_changed()
    at(w, at_s)


def land_writes(w):
    """A volume write updates the row as the player would, and the player
    says its outputs changed."""
    def on_update(output_id, fields):
        if "volume_percent" in fields:
            set_level(w, output_id, fields["volume_percent"])
            w.a.on_outputs_changed()
    w.fb.on_update = on_update


def volume_writes(w):
    return [(uid, f["volume_percent"]) for uid, f in w.fb.updates() if "volume_percent" in f]


def level(uid):
    return snap().unit(uid).volume


def spread_lines(caplog):
    return [r.getMessage() for r in caplog.records if "applied to all" in r.getMessage()]


FIRST_LINE = "Speaker volume applied to all: Speaker 1 30 -> 15; moved Speaker 2 40 -> 20, Speaker 3 20 -> 10"


def test_off_changes_only_the_speaker_pressed(w):
    setup3(w, reader=lambda: False)
    land_writes(w)
    report(w, "1", 15, 1.0)
    assert [level(i) for i in "123"] == [15, 40, 20]
    assert volume_writes(w) == []


def test_on_applies_the_change_to_the_other_speakers(w):
    setup3(w)
    land_writes(w)
    report(w, "1", 15, 1.0)
    assert [level(i) for i in "123"] == [15, 20, 10]
    assert all(snap().unit(i).cause is Origin.DEVICE for i in "123")
    assert volume_writes(w) == [("2", 20), ("3", 10)]
    assert all(set(f) == {"volume_percent", "timeout"} for _, f in w.fb.updates())


def test_a_spread_is_one_publish_with_every_new_level(w):
    setup3(w)
    land_writes(w)
    seen = []

    def on_change(change):
        seen.append((change, [level(i) for i in "123"]))

    state.store().subscribe(on_change)
    report(w, "1", 15, 1.0)
    device = [(c, lv) for c, lv in seen if c.origin is Origin.DEVICE]
    assert len(device) == 1
    change, levels = device[0]
    assert change.requester == "device:1"
    assert levels == [15, 20, 10]


def test_the_pass_does_not_adopt_the_old_rows_of_the_targets(w):
    setup3(w)
    report(w, "1", 15, 1.0)
    assert (level("2"), level("3")) == (20, 10)


def test_a_burst_scales_from_its_snapshot(w):
    setup3(w)
    land_writes(w)
    report(w, "1", 1, 1.0)
    assert [level(i) for i in "123"] == [1, 1, 1]
    report(w, "1", 30, 1.5)
    assert [level(i) for i in "123"] == [30, 40, 20]


def test_a_burst_is_logged_once_when_it_ends(w, caplog):
    setup3(w)
    land_writes(w)
    with caplog.at_level(logging.INFO, logger="autostream.outputs"):
        report(w, "1", 15, 1.0)
        assert spread_lines(caplog) == []
        at(w, 1.0 + spread.SPREAD_QUIET_S)
        assert spread_lines(caplog) == [FIRST_LINE]
        report(w, "1", 30, 5.0)
        assert [level(i) for i in "123"] == [30, 40, 20]
        at(w, 8.0)
    assert len(spread_lines(caplog)) == 2
    assert spread_lines(caplog)[1] == (
        "Speaker volume applied to all: Speaker 1 15 -> 30; moved Speaker 2 20 -> 40, Speaker 3 10 -> 20")


def test_a_speakers_confirmation_of_our_write_is_not_a_report(w):
    setup3(w)
    land_writes(w)
    report(w, "1", 15, 1.0)
    writes = len(volume_writes(w))
    report(w, "2", 20, 2.0)
    assert len(volume_writes(w)) == writes
    report(w, "2", 25, 3.5)
    assert len(volume_writes(w)) == writes
    assert (level("1"), level("2"), level("3")) == (15, 25, 10)
    assert snap().unit("2").cause is Origin.DEVICE
    report(w, "2", 10, 5.5)
    assert (level("1"), level("2"), level("3")) == (6, 10, 4)


def test_an_arm_is_used_once_whether_or_not_the_level_moved(w):
    # (a) a report that spread, then a row change with no event
    setup3(w)
    land_writes(w)
    report(w, "1", 15, 1.0)
    writes = len(volume_writes(w))
    report(w, "1", 12, 3.5, event=False)
    assert level("1") == 12 and snap().unit("1").cause is Origin.BACKEND
    assert len(volume_writes(w)) == writes


def test_an_arm_used_by_an_unmoved_level_does_not_spread_a_later_change(w):
    # (b) the event and read agree with the level already held
    setup3(w)
    land_writes(w)
    report(w, "1", 30, 1.0)
    report(w, "1", 25, 3.5, event=False)
    assert level("1") == 25 and snap().unit("1").cause is Origin.BACKEND
    assert volume_writes(w) == []


def test_an_arm_used_while_the_setting_was_off_does_not_spread_later(w):
    # (c) the setting is off for the report and on for the change after it
    on = [False]
    setup3(w, reader=lambda: on[0])
    land_writes(w)
    report(w, "1", 15, 1.0)
    on[0] = True
    report(w, "1", 12, 3.5, event=False)
    assert level("1") == 12 and snap().unit("1").cause is Origin.BACKEND
    assert volume_writes(w) == []


def test_the_event_may_come_before_the_read(w):
    setup3(w)
    land_writes(w)
    w.a.on_device_event(DeviceEvent("device_volume", "1", None, "volumedown", "15", 1, 1.0))
    at(w, 0.1)
    assert level("1") == 30 and volume_writes(w) == []
    set_level(w, "1", 15)
    w.t[0] = T0 + 6.0
    w.a.merge_for_tests(list(w.fb.rows), boot="b0", now=w.t[0])
    at(w, 6.0)
    assert [level(i) for i in "123"] == [15, 20, 10]


def test_a_read_after_the_report_window_does_not_spread(w):
    setup3(w)
    land_writes(w)
    w.a.on_device_event(DeviceEvent("device_volume", "1", None, "volumedown", "15", 1, 1.0))
    at(w, 0.1)
    set_level(w, "1", 15)
    w.t[0] = T0 + 7.2
    w.a.merge_for_tests(list(w.fb.rows), boot="b0", now=w.t[0])
    at(w, 7.2)
    assert [level(i) for i in "123"] == [15, 40, 20]
    assert volume_writes(w) == []


def test_a_report_for_all_speakers_spreads_nothing(w):
    setup3(w)
    land_writes(w)
    for uid in "123":
        set_level(w, uid, 10)
    w.a.on_device_event(DeviceEvent("device_volume", "0", None, "volumedown", "10", 1, 1.0))
    w.a.on_outputs_changed()
    at(w, 1.0)
    assert [level(i) for i in "123"] == [10, 10, 10]
    assert volume_writes(w) == []


def test_a_row_change_with_no_event_does_not_spread(w):
    setup3(w)
    land_writes(w)
    report(w, "1", 15, 1.0, event=False)
    assert [level(i) for i in "123"] == [15, 40, 20]
    assert volume_writes(w) == []


@pytest.mark.parametrize("how", ["no_session", "no_events"])
def test_no_spread_without_a_session_or_device_events(w, how):
    setup3(w)
    land_writes(w)
    if how == "no_session":
        w.a.note_session(False)
    else:
        w.a._handle_connected(ConnectInfo("b0", 1, frozenset(), "unix_socket"))
    report(w, "1", 15, 1.0)
    assert [level(i) for i in "123"] == [15, 40, 20]
    assert volume_writes(w) == []


def session_rows(states, levels):
    return [group_row(i + 1, s, selected=(s != "stopped"), volume_percent=v)
            for i, (s, v) in enumerate(zip(states, levels))]


def test_a_speaker_that_is_still_starting_is_not_a_reporter(w):
    w.t[0] = T0 - spread.SPREAD_HOLD_S - 1
    put(w, session_rows(["startup", "streaming", "streaming"], (30, 40, 20)))
    w.t[0] = T0
    arm(w)
    land_writes(w)
    report(w, "1", 15, 1.0)
    assert [level(i) for i in "123"] == [15, 40, 20]
    assert volume_writes(w) == []


def test_a_slow_start_report_does_not_spread_and_the_next_press_does(w):
    w.t[0] = T0 - spread.SPREAD_HOLD_S - 1
    put(w, session_rows(["stopped", "streaming", "streaming"], (0, 40, 20)))
    w.t[0] = T0
    arm(w)
    w.a.select("1", Origin.USER, volume=30)
    land_writes(w)
    w.fb.rows = session_rows(["startup", "streaming", "streaming"], (30, 40, 20))
    for t in (1.0, 4.0):
        w.a.on_outputs_changed()
        at(w, t)
    report(w, "1", 31, 8.0, session_state="streaming")
    assert [level(i) for i in "123"] == [31, 40, 20]
    assert [uid for uid, _ in volume_writes(w) if uid != "1"] == []
    report(w, "1", 15, 12.5)
    assert [level(i) for i in "123"] == [15, 19, 10]


def test_a_volume_write_that_timed_out_holds_the_unit(w):
    setup3(w)
    land_writes(w)
    w.fb.results = [error("timeout")]
    report(w, "1", 15, 1.0)
    assert w.a._units["2"].own_write_at == T0 + 1.0
    writes = len(volume_writes(w))
    report(w, "2", 5, 2.0)
    assert len(volume_writes(w)) == writes


def test_a_muted_speaker_is_not_moved(w):
    setup3(w)
    land_writes(w)
    w.a.mute("3", Origin.USER)
    w.fb.calls.clear()
    report(w, "1", 15, 1.0)
    assert volume_writes(w) == [("2", 20)]
    u3 = snap().unit("3")
    assert u3.muted and u3.volume == 20


@pytest.mark.parametrize("at_s", [1.0, 5.0])
def test_a_device_volume_on_a_muted_unit_neither_unmutes_it_nor_spreads(w, at_s):
    setup3(w)
    land_writes(w)
    w.a.mute("1", Origin.USER)
    set_level(w, "1", 30, muted=True)
    w.fb.calls.clear()
    report(w, "1", 10, at_s, muted=True)
    report(w, "1", 20, at_s + 0.5, muted=True)
    assert snap().unit("1").muted is True
    assert (level("2"), level("3")) == (40, 20)
    assert volume_writes(w) == []


def test_from_silence_the_others_step_up_together(w):
    setup3(w, levels=(0, 40, 20))
    land_writes(w)
    report(w, "1", 6, 1.0)
    assert [level(i) for i in "123"] == [6, 48, 24]


def test_a_speaker_the_player_has_no_row_for_is_not_moved(w):
    setup3(w)
    land_writes(w)
    w.t[0] = T0 + 0.5
    put(w, [r for r in w.fb.rows if r.id != "3"])
    report(w, "1", 15, 1.0)
    assert volume_writes(w) == [("2", 20)]
    assert level("3") == 20


def test_a_speaker_joining_mid_burst_waits_for_the_next_burst(w):
    setup3(w)
    land_writes(w)
    report(w, "1", 15, 1.0)
    w.t[0] = T0 + 1.2
    put(w, w.fb.rows + [row(4, volume_percent=10)])
    at(w, 1.2)
    w.a.select("4", Origin.USER, volume=10)
    w.t[0] = T0 + 1.4
    put(w, [dataclasses.replace(r, selected=True) if r.id == "4" else r for r in w.fb.rows])
    at(w, 1.4)
    report(w, "1", 10, 2.5)
    assert (level("1"), level("2"), level("3"), level("4")) == (10, 13, 7, 10)
    report(w, "1", 5, 6.0)
    assert (level("1"), level("2"), level("3"), level("4")) == (5, 6, 4, 5)


def test_a_change_made_elsewhere_during_a_burst_starts_a_new_one(w, caplog):
    setup3(w)
    land_writes(w)
    with caplog.at_level(logging.INFO, logger="autostream.outputs"):
        report(w, "1", 15, 1.0)
        w.t[0] = T0 + 1.5
        w.a.set_volume("3", 50, Origin.USER)
        report(w, "1", 5, 2.5)
    assert spread_lines(caplog) == [FIRST_LINE]
    assert (level("1"), level("2"), level("3")) == (5, 7, 17)


def test_a_master_change_holds_the_reporter(w):
    setup3(w)
    land_writes(w)
    report(w, "1", 15, 1.0)
    w.t[0] = T0 + 1.5
    w.a.set_master(50, Origin.USER, default_level=20)
    w.fb.calls.clear()
    report(w, "1", 10, 3.6)
    assert level("1") == 10
    assert volume_writes(w) == []


def test_the_setting_going_off_ends_and_logs_the_burst(w, caplog):
    on = [True]
    setup3(w, reader=lambda: on[0])
    land_writes(w)
    with caplog.at_level(logging.INFO, logger="autostream.outputs"):
        report(w, "1", 15, 1.0)
        on[0] = False
        at(w, 1.5)
        assert spread_lines(caplog) == [FIRST_LINE]
        w.fb.calls.clear()
        report(w, "1", 5, 2.0)
    assert volume_writes(w) == []
    assert (level("2"), level("3")) == (20, 10)


def test_the_reader_is_called_without_the_authority_lock(w):
    seen = []

    def reader():
        seen.append(w.a._lock_held_by_current_thread())
        return True

    setup3(w, reader=reader)
    land_writes(w)
    report(w, "1", 15, 1.0)
    assert seen and not any(seen)
    assert [level(i) for i in "123"] == [15, 20, 10]


def test_a_player_restart_ends_and_logs_the_burst(w, caplog):
    setup3(w)
    land_writes(w)
    with caplog.at_level(logging.INFO, logger="autostream.outputs"):
        report(w, "1", 15, 1.0)
        w.t[0] = T0 + 1.5
        put(w, list(w.fb.rows), boot="b1")
    assert spread_lines(caplog) == [FIRST_LINE]
