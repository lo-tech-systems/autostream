"""The appliance's real replies to a speaker PIN, read by the dial.

Drives the appliance's dial outputs routes (with the player mutation
patched to return each documented outcome) and feeds what they send to the
dial's reply readers and core, so a change on either side that the other
cannot read fails here. Also pins the two rules that must agree across the
two code bases: the PIN's shape and how long a pairing outcome stays
answerable against how long the appliance counts attempts.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
for _p in (str(REPO_ROOT / "dial"), str(REPO_ROOT / "core"), str(Path(__file__).parent)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import autostream_pin_pairing as pairing
import dial_core_poll as cp
import dial_core_state as cs
from autostream_players import OutputInfo
from dial_core import DialCore, OutputsEffect
from test_webui_dial_outputs import DIAL_ID, _invoke_list, _invoke_set, _ok_list

AID = "a" * 20

# What the mutation returns for each outcome the set route documents, and
# the id and wait the dial must read from the route's reply.
OUTCOMES = [
    ({"ok": True, "id": "1"}, None, 0),
    ({"ok": False, "pin_required": True, "id": "1", "output_name": "Den",
      "error": "Output requires PIN"}, "pin_required", 0),
    ({"ok": False, "pin_invalid": True, "id": "1", "error": "Wrong PIN"}, "pin_invalid", 0),
    ({"ok": False, "error": "output_in_use", "owner": "Den", "id": "1"}, "output_in_use", 0),
    ({"ok": False, "error": "encoder_capacity", "id": "1"}, "encoder_capacity", 0),
    ({"ok": False, "error": "rate_limited", "retry_after_s": 42, "id": "1"}, "rate_limited", 42),
    ({"ok": False, "error": "invalid_pin", "id": "1"}, "invalid_pin", 0),
    ({"ok": False, "error": "config_error"}, "config_error", 0),
    ({"ok": False, "error": "Backend returned HTTP 500", "id": "1"}, "backend_error", 0),
]


class TestTheDialReadsTheRoutesReplies:
    @pytest.mark.parametrize("result, error_id, wait", OUTCOMES)
    def test_each_documented_outcome(self, result, error_id, wait):
        code, body, _mutation, _mode = _invoke_set(
            {"dial_id": DIAL_ID, "id": "1", "selected": True}, mutation_result=result)
        assert code == 200
        assert cp.reply_error_id(code, body) == error_id
        assert cp.reply_retry_after(body) == wait

    @pytest.mark.parametrize("json_obj", [
        {"dial_id": DIAL_ID, "id": "1", "op": "pin", "pin": "12"},
        {"dial_id": DIAL_ID, "id": "1", "op": "pin", "pin": "123456789"},
        {"dial_id": DIAL_ID, "id": "1", "op": "pin", "pin": "12ab"},
        {"dial_id": DIAL_ID, "id": "1", "op": "pin", "pin": 1234},
        {"dial_id": DIAL_ID, "id": "1", "op": "pin"},
        {"dial_id": DIAL_ID, "id": "1", "op": "wipe", "pin": "1234"},
        {"dial_id": DIAL_ID, "id": "1"},
    ])
    def test_the_routes_400s_are_typed_rejections(self, json_obj):
        code, body, mutation, _mode = _invoke_set(json_obj)
        assert code == 400
        error = cp.reply_error_id(code, body)
        assert error not in (None, "unreachable") and error != "backend_error"
        mutation.assert_not_called()

    def test_a_missing_output_id_is_a_typed_rejection(self):
        code, body, _m, _mode = _invoke_set({"dial_id": DIAL_ID, "selected": True})
        assert code == 400 and cp.reply_error_id(code, body) == "missing_output_id"

    def test_an_unauthorised_dial_is_a_typed_rejection(self):
        from autostream_dials import AUTH_NOT_AUTHORIZED
        code, body, _m, _mode = _invoke_set(
            {"dial_id": DIAL_ID, "id": "1", "selected": True}, auth_state=AUTH_NOT_AUTHORIZED)
        assert code == 412 and cp.reply_error_id(code, body) == "dial_not_authorized"

    def test_a_pin_the_dial_accepts_is_one_the_route_accepts(self):
        for pin in ("1234", "12345678", "0000"):
            assert cs.PIN_RE.match(pin)
            code, _body, mutation, _mode = _invoke_set(
                {"dial_id": DIAL_ID, "id": "1", "op": "pin", "pin": pin, "selected": True})
            assert code == 200
            assert mutation.call_args[0][2]["pin"] == pin
        for pin in ("123", "123456789", "12a4", "1234\n"):
            assert not cs.PIN_RE.match(pin)
            code, _body, mutation, _mode = _invoke_set(
                {"dial_id": DIAL_ID, "id": "1", "op": "pin", "pin": pin, "selected": True})
            assert code == 400
            mutation.assert_not_called()

    @pytest.mark.parametrize("result, error_id, wait", OUTCOMES[1:])
    def test_the_core_resolves_its_request_from_the_routes_reply(self, result, error_id, wait):
        _code, body, _m, _mode = _invoke_set(
            {"dial_id": DIAL_ID, "id": "1", "selected": True}, mutation_result=result)
        core = _core_with_a_pending_request()
        assert core.on_outputs_result("set", AID, 200, body)
        held = core.snapshot().outputs_request
        assert (held.state, held.error, held.retry_after_s) == ("rejected", error_id, wait)
        assert core.snapshot().outputs.optimistic is None
        assert core.take_effects() == [OutputsEffect(AID, "1", "output_set", "rejected", error_id)]

    def test_the_core_accepts_the_routes_ok_reply(self):
        _code, body, _m, _mode = _invoke_set({"dial_id": DIAL_ID, "id": "1", "selected": True})
        core = _core_with_a_pending_request()
        assert core.on_outputs_result("set", AID, 200, body)
        assert core.snapshot().outputs_request.state == "accepted"


def _core_with_a_pending_request():
    from dial_mdns import RosterEntry
    from dial_auth import AUTH_AUTHORIZED
    core = DialCore("dial-1", lambda: [], lambda: [])
    core.set_roster([RosterEntry(
        appliance_id=AID, service_name="Kitchen", name="Kitchen", ip="192.0.2.10", port=80,
        playing=False, repeat_capable=False, dial_api=True, audio_status=True, dial_status=True,
        dial_outputs=True, auth=AUTH_AUTHORIZED)])
    core.set_field("reporting_id", AID)
    with patch("dial_core.enqueue_fetch"):
        core.watch_outputs(AID, "spi", True)
    core.on_outputs_result("fetch", AID, 200, {"ok": True, "outputs": [
        {"id": "1", "name": "Den", "selected": False, "volume": 0}]})
    with patch("dial_core.enqueue_set"):
        assert core.set_output(AID, "1", selected=True).accepted
    return core


class TestTheDialReadsTheList:
    def test_needs_auth_key_survives_the_route_and_the_parser(self):
        rows_in = (
            OutputInfo(id="1", name="Bedroom", selected=False, pin_pending=True, needs_auth_key=True),
            OutputInfo(id="2", name="Kitchen", selected=False),
        )
        code, body = _invoke_list({"dial_id": DIAL_ID}, list_result=_ok_list(*rows_in))
        assert code == 200
        rows = {r.name: r for r in cp.parse_outputs_body(code, body)}
        assert rows["Bedroom"].needs_auth_key is True
        assert rows["Kitchen"].needs_auth_key is False


class TestSharedRules:
    def test_both_sides_apply_the_same_pin_rule(self):
        assert cs.PIN_RE.pattern == pairing.PIN_RE.pattern

    def test_the_dial_window_covers_the_appliance_attempt_window(self):
        assert cs.PIN_WINDOW_S >= pairing.PIN_ATTEMPTS_WINDOW_S

    def test_the_dial_window_covers_the_appliance_claim(self):
        assert cs.PIN_WINDOW_S >= pairing.PIN_CLAIM_S

    def test_the_longest_reply_wait_the_dial_reads_covers_the_attempt_window(self):
        assert cp.RETRY_AFTER_MAX_S >= pairing.PIN_ATTEMPTS_WINDOW_S
