"""The intent path: validators, the table, the limiter, replies and the log line."""
from __future__ import annotations

import logging
import math
import re
import sys
import threading
from pathlib import Path

import pytest

_core = str(Path(__file__).parent.parent / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_intents as intents
import autostream_state
from autostream_intents import table, validate as v
from autostream_intents.table import HandlerTaken, Intent, Outcome, RateLimit, Row, _Table
from autostream_state import FrozenDict, Origin


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ok_handler(intent, wait):
    return Outcome(ok=True)


def one_row_table(**row_kw):
    """A table of its own with one row, so no test touches the module's bindings."""
    row = Row(
        name="thing.set",
        args={"level": v.integer(0, 10, error="bad_level")},
        required=frozenset({"level"}),
        origins=frozenset({Origin.USER, Origin.SESSION}),
        **row_kw,
    )
    return _Table(rows={"thing.set": row})


def ask(tbl, args=None, *, origin=Origin.USER, requester="webui", name="thing.set", **kw):
    return tbl.submit(Intent(name, {"level": 3} if args is None else args, origin, requester), **kw)


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

class TestValidators:
    def test_boolean_accepts_only_bools(self):
        check = v.boolean(error="bad")
        assert check(True) is True and check(False) is False
        for wrong in (0, 1, "true", None, 1.0):
            with pytest.raises(v.Invalid) as err:
                check(wrong)
            assert err.value.error == "bad"

    def test_integer_is_not_a_bool_and_not_a_float(self):
        check = v.integer(0, 10, error="bad")
        assert check(7) == 7
        for wrong in (True, False, 3.0, "3", None):
            with pytest.raises(v.Invalid):
                check(wrong)

    def test_integer_range_refuses_or_clamps(self):
        with pytest.raises(v.Invalid):
            v.integer(0, 10, error="bad")(11)
        clamped = v.integer(0, 10, error="bad", clamp=True)
        assert (clamped(11), clamped(-5), clamped(4)) == (10, 0, 4)

    def test_number_refuses_nan_infinity_and_bools(self):
        check = v.number(-1.0, 1.0, error="bad")
        assert check(0.5) == 0.5 and check(1) == 1
        for wrong in (math.nan, math.inf, -math.inf, True, "0.5", None):
            with pytest.raises(v.Invalid):
                check(wrong)

    def test_number_clamps_when_asked(self):
        check = v.number(-1.0, 1.0, error="bad", clamp=True)
        assert (check(5), check(-5.5)) == (1.0, -1.0)
        with pytest.raises(v.Invalid):
            check(math.nan)

    def test_text_is_returned_stripped(self):
        assert v.text(error="bad")("  hello ") == "hello"

    def test_text_refuses_non_strings_empty_and_too_long(self):
        check = v.text(error="bad", max_len=5)
        for wrong in (5, None, b"abc", "", "   ", "abcdefg"):
            with pytest.raises(v.Invalid):
                check(wrong)
        assert v.text(error="bad", allow_empty=True)("  ") == ""

    def test_text_pattern_is_matched_before_stripping(self):
        check = v.text(error="bad", pattern=re.compile(r"^[0-9]{4}\Z"))
        assert check("1234") == "1234"
        for wrong in ("12345", " 1234", "1234\n", "abcd"):
            with pytest.raises(v.Invalid):
                check(wrong)

    def test_choice_compares_by_value_and_type(self):
        check = v.choice("mute", "restore", error="bad")
        assert check("mute") == "mute"
        for wrong in ("MUTE", "", None, 1):
            with pytest.raises(v.Invalid):
                check(wrong)
        assert v.choice(1, error="bad")(1) == 1
        with pytest.raises(v.Invalid):
            v.choice(1, error="bad")(True)

    def test_optional_lets_none_through(self):
        check = v.optional(v.integer(0, 10, error="bad"))
        assert check(None) is None and check(4) == 4
        with pytest.raises(v.Invalid):
            check(99)

    def test_pairs_become_a_tuple_of_tuples(self):
        check = v.pairs(error="bad", max_items=2)
        assert check([["a", 1], ("b", [2])]) == (("a", 1), ("b", [2]))
        for wrong in ("ab", [["a"]], [[1, 2]], [["a", 1, 2]], [["a", 1]] * 3, None):
            with pytest.raises(v.Invalid):
                check(wrong)

    def test_anything_passes_the_value_on(self):
        marker = object()
        assert v.anything()(marker) is marker


# ---------------------------------------------------------------------------
# The rows
# ---------------------------------------------------------------------------

class TestRows:
    def test_the_table_names_the_output_repeat_and_equaliser_rows(self):
        assert set(table.ROWS) == {
            "outputs.set", "output.pin.submit", "outputs.select_default",
            "outputs.deselect_all", "volume.step", "mute.set",
            "repeat.arm", "repeat.transport", "repeat.seek", "input.eq.set",
        }

    @pytest.mark.parametrize("name", sorted(table.ROWS))
    @pytest.mark.parametrize("origin", [Origin.ADOPTED, Origin.BACKEND])
    def test_adopted_and_backend_are_refused_by_every_row(self, name, origin):
        assert origin not in table.ROWS[name].origins
        tbl = _Table()
        tbl.bind(name, ok_handler, owner="test")
        reply = tbl.submit(Intent(name, {}, origin, "coordinator"))
        assert (reply.ok, reply.error) == (False, "origin_not_allowed")

    def _submit_real(self, name, args, origin=Origin.USER):
        tbl = _Table()
        seen = []
        tbl.bind(name, lambda intent, wait: seen.append((intent, wait)) or Outcome(ok=True), owner="test")
        reply = tbl.submit(Intent(name, args, origin, "webui"))
        return reply, seen

    def test_pin_rows_check_the_pin_shape(self):
        reply, seen = self._submit_real("output.pin.submit", {"id": "1", "pin": "12"})
        assert (reply.ok, reply.error, seen) == (False, "invalid_pin", [])
        reply, seen = self._submit_real("output.pin.submit", {"id": "1", "pin": "1234"})
        assert reply.ok and seen[0][0].args["pin"] == "1234"

    def test_mute_rows_check_the_action(self):
        reply, _ = self._submit_real("mute.set", {"action": "toggle", "default_level": 50})
        assert reply.error == "invalid_action"
        reply, _ = self._submit_real("mute.set", {"action": "mute", "default_level": 50})
        assert reply.ok

    def test_the_volume_step_is_clamped_and_must_be_an_int(self):
        reply, seen = self._submit_real("volume.step", {"delta": 500, "default_level": 30})
        assert reply.ok and seen[0][0].args["delta"] == 100
        reply, _ = self._submit_real("volume.step", {"delta": True, "default_level": 30})
        assert reply.error == "invalid_delta"

    def test_an_output_row_clamps_the_volume_and_needs_an_id(self):
        reply, seen = self._submit_real("outputs.set", {"id": "7", "selected": True, "volume": 400})
        assert reply.ok and seen[0][0].args["volume"] == 100
        reply, _ = self._submit_real("outputs.set", {"id": " ", "selected": True})
        assert reply.error == "missing_output_id"
        reply, _ = self._submit_real("outputs.set", {"id": "7", "selected": 1})
        assert reply.error == "invalid_request_body"

    def test_rows_that_take_no_arguments_refuse_any(self):
        reply, _ = self._submit_real("outputs.deselect_all", {"force": True}, Origin.SESSION)
        assert reply.error == "invalid_args"
        reply, _ = self._submit_real("outputs.deselect_all", {}, Origin.POLICY)
        assert reply.ok

    def test_wait_defaults_come_from_the_row(self):
        _, seen = self._submit_real("outputs.set", {"id": "7", "selected": False})
        assert seen[0][1] == 3.0
        _, seen = self._submit_real("outputs.deselect_all", {}, Origin.SESSION)
        assert seen[0][1] == 0.0


# ---------------------------------------------------------------------------
# Submit
# ---------------------------------------------------------------------------

class TestSubmit:
    def test_an_unknown_intent_is_refused(self):
        tbl = one_row_table()
        reply = ask(tbl, name="nothing.here")
        assert (reply.ok, reply.error, reply.result) == (False, "unknown_intent", {})

    def test_an_origin_outside_the_row_is_refused(self):
        tbl = one_row_table()
        tbl.bind("thing.set", ok_handler, owner="test")
        assert ask(tbl, origin=Origin.DEVICE).error == "origin_not_allowed"
        assert ask(tbl, origin=Origin.USER).ok

    def test_an_unknown_argument_is_refused(self):
        tbl = one_row_table()
        tbl.bind("thing.set", ok_handler, owner="test")
        assert ask(tbl, {"level": 3, "extra": 1}).error == "invalid_args"

    def test_a_missing_required_argument_is_refused(self):
        tbl = one_row_table()
        tbl.bind("thing.set", ok_handler, owner="test")
        assert ask(tbl, {}).error == "invalid_args"

    def test_arguments_that_are_not_a_mapping_are_refused(self):
        tbl = one_row_table()
        tbl.bind("thing.set", ok_handler, owner="test")
        assert ask(tbl, [("level", 3)]).error == "invalid_args"

    def test_a_validator_error_is_the_reply_error(self):
        tbl = one_row_table()
        tbl.bind("thing.set", ok_handler, owner="test")
        assert ask(tbl, {"level": 99}).error == "bad_level"

    def test_a_refused_intent_never_reaches_the_handler(self):
        tbl = one_row_table()
        called = []
        tbl.bind("thing.set", lambda i, w: called.append(i) or Outcome(ok=True), owner="test")
        ask(tbl, {"level": 99})
        ask(tbl, origin=Origin.BACKEND)
        assert called == []

    def test_validated_arguments_are_frozen(self):
        row = Row("thing.set", {"items": v.pairs(error="bad"), "level": v.anything()},
                  frozenset(), frozenset({Origin.USER}))
        tbl = _Table(rows={"thing.set": row})
        seen = []
        tbl.bind("thing.set", lambda i, w: seen.append(i) or Outcome(ok=True), owner="test")
        payload = {"items": [["a", 1]], "level": {"x": [1, 2]}}
        tbl.submit(Intent("thing.set", payload, Origin.USER, "webui"))
        args = seen[0].args
        assert isinstance(args, FrozenDict)
        assert isinstance(args["level"], FrozenDict) and args["level"]["x"] == (1, 2)
        with pytest.raises(TypeError):
            args["level"] = 1
        payload["level"]["x"].append(3)
        assert args["level"]["x"] == (1, 2)

    def test_the_context_reaches_the_handler(self):
        tbl = one_row_table()
        seen = []
        tbl.bind("thing.set", lambda i, w: seen.append(i.context) or Outcome(ok=True), owner="test")
        marker = object()
        tbl.submit(Intent("thing.set", {"level": 1}, Origin.USER, "webui", context=marker))
        assert seen == [marker]

    def test_wait_none_takes_the_row_default_and_a_value_overrides_it(self):
        tbl = one_row_table(wait=3.0)
        seen = []
        tbl.bind("thing.set", lambda i, w: seen.append(w) or Outcome(ok=True), owner="test")
        ask(tbl)
        ask(tbl, wait=0.5)
        assert seen == [3.0, 0.5]

    def test_no_handler_raises_intent_not_bound(self):
        tbl = one_row_table()
        with pytest.raises(intents.IntentNotBound):
            ask(tbl)

    def test_a_raising_handler_gives_internal_error(self, caplog):
        tbl = one_row_table()

        def boom(intent, wait):
            raise RuntimeError("handler broke")

        tbl.bind("thing.set", boom, owner="test")
        with caplog.at_level(logging.DEBUG, logger="autostream.intents"):
            reply = ask(tbl)
        assert (reply.ok, reply.error) == (False, "internal_error")
        assert any(r.exc_info for r in caplog.records)

    def test_a_handler_returning_the_wrong_type_gives_internal_error(self):
        tbl = one_row_table()
        tbl.bind("thing.set", lambda i, w: {"ok": True}, owner="test")
        assert ask(tbl).error == "internal_error"

    def test_the_reply_carries_the_outcome_and_the_store_boot(self):
        tbl = one_row_table()
        tbl.bind("thing.set", lambda i, w: Outcome(ok=True, result={"id": "x"}), owner="test")
        reply = ask(tbl)
        snap = autostream_state.store().snapshot()
        assert (reply.ok, reply.error, dict(reply.result)) == (True, None, {"id": "x"})
        assert (reply.version, reply.boot) == (snap.version, snap.boot)

    def test_the_reply_version_is_the_outcomes_when_it_has_one(self):
        tbl = one_row_table()
        tbl.bind("thing.set", lambda i, w: Outcome(ok=True, version=41), owner="test")
        assert ask(tbl).version == 41

    def test_a_refusal_carries_the_current_version_and_boot(self):
        tbl = one_row_table()
        reply = ask(tbl, name="nothing.here")
        snap = autostream_state.store().snapshot()
        assert (reply.version, reply.boot) == (snap.version, snap.boot)

    def test_a_failed_outcome_is_passed_on(self):
        tbl = one_row_table()
        tbl.bind("thing.set", lambda i, w: Outcome(ok=False, error="pin_required"), owner="test")
        reply = ask(tbl)
        assert (reply.ok, reply.error) == (False, "pin_required")

    def test_no_lock_is_held_while_the_handler_runs(self):
        tbl = one_row_table(limit=RateLimit(1.0))
        free = []

        def handler(intent, wait):
            got = tbl._limit_lock.acquire(blocking=False)
            if got:
                tbl._limit_lock.release()
            free.append(got)
            return Outcome(ok=True)

        tbl.bind("thing.set", handler, owner="test")
        ask(tbl)
        assert free == [True]


# ---------------------------------------------------------------------------
# The limiter
# ---------------------------------------------------------------------------

class TestLimiter:
    def test_inside_the_interval_is_refused_and_after_it_accepted(self):
        clock = Clock()
        tbl = one_row_table(limit=RateLimit(1.0))
        tbl.set_clock_for_tests(clock)
        tbl.bind("thing.set", ok_handler, owner="test")
        assert ask(tbl).ok
        clock.now += 0.5
        reply = ask(tbl)
        assert (reply.ok, reply.error) == (False, "rate_limited")
        clock.now += 0.6
        assert ask(tbl).ok

    def test_the_limit_names_its_own_error(self):
        clock = Clock()
        tbl = one_row_table(limit=RateLimit(1.0, error="slow_down"))
        tbl.set_clock_for_tests(clock)
        tbl.bind("thing.set", ok_handler, owner="test")
        ask(tbl)
        assert ask(tbl).error == "slow_down"

    def test_the_stamp_is_taken_before_the_handler_runs(self):
        clock = Clock()
        tbl = one_row_table(limit=RateLimit(1.0))
        tbl.set_clock_for_tests(clock)
        stamps = []
        tbl.bind("thing.set", lambda i, w: stamps.append(dict(tbl._last)) or Outcome(ok=True), owner="test")
        ask(tbl)
        assert stamps == [{"thing.set": 100.0}]

    def test_a_failed_handler_still_counts_against_the_limit(self):
        clock = Clock()
        tbl = one_row_table(limit=RateLimit(1.0))
        tbl.set_clock_for_tests(clock)
        tbl.bind("thing.set", lambda i, w: Outcome(ok=False, error="nope"), owner="test")
        ask(tbl)
        assert ask(tbl).error == "rate_limited"

    def test_a_limit_that_does_not_apply_skips_the_check(self):
        clock = Clock()
        tbl = one_row_table(limit=RateLimit(10.0, applies=lambda args: args["level"] > 5))
        tbl.set_clock_for_tests(clock)
        tbl.bind("thing.set", ok_handler, owner="test")
        assert ask(tbl, {"level": 1}).ok
        assert ask(tbl, {"level": 1}).ok
        assert ask(tbl, {"level": 9}).ok
        assert ask(tbl, {"level": 9}).error == "rate_limited"
        assert ask(tbl, {"level": 1}).ok

    def test_a_refused_intent_does_not_take_a_slot(self):
        clock = Clock()
        tbl = one_row_table(limit=RateLimit(10.0))
        tbl.set_clock_for_tests(clock)
        tbl.bind("thing.set", ok_handler, owner="test")
        assert ask(tbl, {"level": 99}).error == "bad_level"
        assert ask(tbl).ok

    def test_each_row_keeps_its_own_timestamp(self):
        clock = Clock()
        rows = {
            name: Row(name, {}, frozenset(), frozenset({Origin.USER}), limit=RateLimit(10.0))
            for name in ("a.set", "b.set")
        }
        tbl = _Table(rows=rows)
        tbl.set_clock_for_tests(clock)
        for name in rows:
            tbl.bind(name, ok_handler, owner="test")
        assert tbl.submit(Intent("a.set", {}, Origin.USER, "webui")).ok
        assert tbl.submit(Intent("b.set", {}, Origin.USER, "webui")).ok
        assert tbl.submit(Intent("a.set", {}, Origin.USER, "webui")).error == "rate_limited"


# ---------------------------------------------------------------------------
# Binding
# ---------------------------------------------------------------------------

class TestBinding:
    def test_the_same_owner_may_rebind(self):
        tbl = one_row_table()
        tbl.bind("thing.set", lambda i, w: Outcome(ok=False, error="old"), owner="mod")
        tbl.bind("thing.set", lambda i, w: Outcome(ok=False, error="new"), owner="mod")
        assert ask(tbl).error == "new"

    def test_a_second_owner_is_refused(self):
        tbl = one_row_table()
        tbl.bind("thing.set", ok_handler, owner="mod_a")
        with pytest.raises(HandlerTaken):
            tbl.bind("thing.set", ok_handler, owner="mod_b")

    def test_a_row_that_does_not_exist_cannot_be_bound(self):
        with pytest.raises(ValueError):
            one_row_table().bind("other.set", ok_handler, owner="mod")

    def test_the_module_level_bind_goes_to_the_module_table(self, monkeypatch):
        monkeypatch.setattr(table._table, "_handlers", {})
        monkeypatch.setattr(table._table, "_owners", {})
        table.bind("mute.set", ok_handler, owner="test")
        assert table._table._handlers["mute.set"] is ok_handler
        with pytest.raises(HandlerTaken):
            table.bind("mute.set", ok_handler, owner="someone else")

    def test_a_module_table_without_a_handler_raises_not_bound(self, monkeypatch):
        monkeypatch.setattr(table._table, "_handlers", {})
        with pytest.raises(intents.IntentNotBound):
            intents.submit(Intent("mute.set", {"action": "mute", "default_level": 50}, Origin.USER, "webui"))


class TestResetForTests:
    def test_it_clears_stamps_restores_the_clock_and_keeps_bindings(self):
        clock = Clock()
        tbl = one_row_table(limit=RateLimit(10.0))
        tbl.set_clock_for_tests(clock)
        tbl.bind("thing.set", ok_handler, owner="test")
        ask(tbl)
        assert ask(tbl).error == "rate_limited"
        tbl.reset_for_tests()
        assert tbl._clock is not clock
        assert ask(tbl).ok

    def test_it_does_nothing_when_nothing_was_touched(self):
        tbl = one_row_table()
        marker = tbl._last
        tbl.reset_for_tests()
        assert tbl._last is marker and tbl._dirty is False

    def test_the_test_fixture_resets_the_module_table(self):
        # Runs after other tests that may have set the module clock: a fresh
        # table state is what the fixture hands every test.
        assert table._table._last == {}
        assert table._table._dirty is False


# ---------------------------------------------------------------------------
# The log line
# ---------------------------------------------------------------------------

class TestLogLine:
    def _lines(self, caplog):
        return [r for r in caplog.records if r.name == "autostream.intents"]

    def test_an_accepted_intent_logs_one_debug_line(self, caplog):
        tbl = one_row_table()
        tbl.bind("thing.set", lambda i, w: Outcome(ok=True, version=12), owner="test")
        with caplog.at_level(logging.DEBUG, logger="autostream.intents"):
            ask(tbl, requester="dial:abc")
        lines = self._lines(caplog)
        assert len(lines) == 1
        assert lines[0].levelno == logging.DEBUG
        assert lines[0].getMessage() == "intent thing.set origin=user requester=dial:abc result=ok version=12"

    def test_a_refused_intent_logs_one_info_line_with_the_reason(self, caplog):
        tbl = one_row_table()
        tbl.bind("thing.set", ok_handler, owner="test")
        with caplog.at_level(logging.DEBUG, logger="autostream.intents"):
            ask(tbl, {"level": 99}, origin=Origin.SESSION, requester="coordinator")
        lines = self._lines(caplog)
        assert len(lines) == 1 and lines[0].levelno == logging.INFO
        message = lines[0].getMessage()
        assert "intent thing.set origin=session requester=coordinator result=bad_level version=" in message

    def test_every_refusal_step_logs_at_info(self, caplog):
        tbl = one_row_table(limit=RateLimit(10.0))
        tbl.set_clock_for_tests(Clock())
        tbl.bind("thing.set", ok_handler, owner="test")
        with caplog.at_level(logging.DEBUG, logger="autostream.intents"):
            ask(tbl, name="no.such")
            ask(tbl, origin=Origin.BACKEND)
            ask(tbl, {})
            ask(tbl)
            ask(tbl)
        levels = [r.levelno for r in self._lines(caplog)]
        assert levels == [logging.INFO, logging.INFO, logging.INFO, logging.DEBUG, logging.INFO]

    def test_a_failed_outcome_logs_at_info_with_its_error(self, caplog):
        tbl = one_row_table()
        tbl.bind("thing.set", lambda i, w: Outcome(ok=False, error="pin_required"), owner="test")
        with caplog.at_level(logging.DEBUG, logger="autostream.intents"):
            ask(tbl)
        line = self._lines(caplog)[0]
        assert line.levelno == logging.INFO and "result=pin_required" in line.getMessage()

    def test_argument_values_and_the_context_are_never_logged(self, caplog):
        row = Row("pin.send", {"pin": v.text(error="bad")}, frozenset({"pin"}), frozenset({Origin.USER}))
        tbl = _Table(rows={"pin.send": row})
        tbl.bind("pin.send", ok_handler, owner="test")
        with caplog.at_level(logging.DEBUG, logger="autostream.intents"):
            tbl.submit(Intent("pin.send", {"pin": "424242"}, Origin.USER, "webui", context="session-secret"))
            tbl.submit(Intent("pin.send", {"pin": 424242}, Origin.USER, "webui", context="session-secret"))
        text = " ".join(r.getMessage() for r in self._lines(caplog))
        assert "424242" not in text and "session-secret" not in text
        assert len(self._lines(caplog)) == 2
