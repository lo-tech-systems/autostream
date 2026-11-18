"""tests/test_output_intents.py

The output handlers of the intent table: switching a speaker on and off,
changing its volume, and the PIN path. A speaker is arranged through the
authority's snapshot; the player's answers come from a patched player service,
and the authority (without threads) writes inline, so the reply is complete
when the call returns. The real-thread cases use the started_authority fixture
and a backend that waits on an Event.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_appliance_models as models
import autostream_mute_state as mute_state
import autostream_output_intents as intents_mod
import autostream_pin_pairing as pairing
import autostream_runtime as runtime
import autostream_state as state
from autostream_intents import Intent, submit
from autostream_players import ActionResult
from autostream_state import Origin
from autostream_state.outputs import get_authority
from fake_store import FakeStore
from output_fakes import FakeBackend, row, snap

ID = "42"


def ok():
    return ActionResult(ok=True)


def err(code, message="err"):
    return ActionResult(ok=False, error_code=code, error=message)


@pytest.fixture
def player(monkeypatch):
    """The player service: records every write and answers from a queue."""
    import autostream_player_service as ps

    rec = SimpleNamespace(calls=[], answers=[], default=ok())

    def answer():
        return rec.answers.pop(0) if rec.answers else rec.default

    def update_output(base_url, out_id, **kwargs):
        rec.calls.append(("update_output", out_id, kwargs))
        return answer()

    def submit_output_pin(base_url, out_id, pin, timeout=None):
        rec.calls.append(("submit_output_pin", out_id, pin))
        return answer()

    monkeypatch.setattr(ps, "update_output", update_output)
    monkeypatch.setattr(ps, "submit_output_pin", submit_output_pin)
    return rec


def arrange(*rows):
    FakeStore().outputs(list(rows) or [row(ID, "Kitchen")])


def change(body, **kw):
    kw.setdefault("requester", "webui")
    kw.setdefault("pin_requester", pairing.REQUESTER_WEBUI)
    return models.submit_output_change(body, **kw)


def on(**extra):
    return {"id": ID, "selected": True, **extra}


@pytest.fixture(autouse=True)
def _fresh():
    mute_state.reset_for_tests()
    pairing.reset_for_tests() if hasattr(pairing, "reset_for_tests") else None
    yield
    mute_state.reset_for_tests()


# ---------------------------------------------------------------------------
# Switching a speaker on
# ---------------------------------------------------------------------------

class TestEnable:
    def test_it_writes_the_selection_with_the_volume_offset_and_mode(self, player):
        arrange()
        r = change(on(volume=35), offset_ms=120, mode="airplay2")
        assert r == {"ok": True, "id": ID}
        (name, out_id, kw), = player.calls
        assert (name, out_id) == ("update_output", ID)
        assert kw == dict(enabled=True, volume_percent=35, offset_ms=120, mode="airplay2", timeout=3.0)

    def test_the_list_shows_the_speaker_on_as_soon_as_the_call_returns(self, player):
        arrange()
        change(on(volume=35))
        u = snap().unit(ID)
        assert u.selected and u.volume == 35 and u.cause is Origin.USER

    def test_a_missing_volume_is_fifty(self, player):
        arrange()
        change(on())
        assert player.calls[0][2]["volume_percent"] == 50

    def test_a_volume_is_clamped_to_the_scale(self, player):
        arrange()
        change(on(volume=250))
        assert player.calls[0][2]["volume_percent"] == 100

    def test_an_output_the_appliance_never_listed_is_refused(self, player):
        arrange(row("7", "Other"))
        assert change(on()) == {"ok": False, "id": ID, "error": "unknown_output"}
        assert player.calls == []

    def test_a_start_the_player_is_still_working_on_replies_ok(self, player):
        arrange()
        player.answers.append(err("timeout", "slow"))
        assert change(on()) == {"ok": True, "id": ID}
        assert snap().unit(ID).selected is True
        assert snap().unit(ID).availability == "starting"

    def test_a_speaker_that_refuses_to_start_is_turned_back_off_at_once(self, player):
        arrange()
        player.answers.append(err("http_error", "No route"))
        r = change(on())
        assert r == {"ok": False, "id": ID, "error": "No route", "pin_invalid": False}
        u = snap().unit(ID)
        assert u.selected is False
        f = snap().start_failure
        assert (f.unit_id, f.name, f.reason, f.seq) == (ID, "Kitchen", "refused", 1)

    def test_a_second_refusal_gets_the_next_sequence_number(self, player):
        arrange()
        player.default = err("http_error", "No route")
        change(on())
        change(on())
        assert snap().start_failure.seq == 2

    def test_encoder_capacity_is_reported_by_name(self, player):
        arrange()
        player.answers.append(err("encoder_capacity", "full"))
        assert change(on()) == {"ok": False, "id": ID, "error": "encoder_capacity"}
        assert snap().unit(ID).selected is False
        assert snap().start_failure.reason == "encoder_capacity"

    def test_a_pin_protected_speaker_asks_for_a_pin_and_claims_it_for_the_requester(self, player):
        arrange()
        player.answers.append(err("pin_required", "PIN needed"))
        r = change(on(name="Kitchen"), pin_requester="dial:abc")
        assert r == {"ok": False, "pin_required": True, "id": ID, "output_name": "Kitchen", "error": "PIN needed"}
        assert pairing.holder(ID) == "dial:abc"
        assert snap().unit(ID).availability == "password"
        assert snap().start_failure.reason == "pin_required"

    def test_no_claim_is_made_for_a_caller_that_cannot_enter_a_pin(self, player):
        arrange()
        player.answers.append(err("pin_required", "PIN needed"))
        r = change(on(), pin_requester=None)
        assert r["pin_required"] is True and r["output_name"] == ""
        assert pairing.holder(ID) == ""

    def test_the_request_is_logged_as_an_intent_with_the_requester(self, player, caplog):
        arrange()
        with caplog.at_level("DEBUG", logger="autostream.intents"):
            change(on(), requester="dial:abc")
        assert any("outputs.set" in m and "requester=dial:abc" in m for m in caplog.messages)

    def test_the_hint_names_the_requesting_dial(self, player):
        arrange()
        seen = []
        state.store().subscribe(lambda c: seen.append(c))
        change(on(), requester="dial:abc")
        assert any(c.requester == "dial:abc" and "outputs" in c.parts for c in seen)


class TestOccupancy:
    def occupied(self):
        return patch("autostream_output_usage.usage_for_output",
                     return_value=SimpleNamespace(owner_name="Other Player"))

    def test_a_speaker_in_use_elsewhere_is_not_switched_on(self, player):
        arrange()
        with self.occupied():
            r = change(on())
        assert r == {"ok": False, "id": ID, "error": "output_in_use", "owner": "Other Player"}
        assert player.calls == []

    def test_a_volume_change_on_a_speaker_that_is_on_is_allowed(self, player):
        arrange(row(ID, "Kitchen", selected=True, volume_percent=20))
        with self.occupied():
            assert change(on(volume=60)) == {"ok": True, "id": ID}
        assert player.calls[0][2]["volume_percent"] == 60

    def test_switching_off_is_allowed(self, player):
        arrange(row(ID, "Kitchen", selected=True))
        with self.occupied():
            assert change({"id": ID, "selected": False}) == {"ok": True, "id": ID}

    def test_the_check_is_by_the_name_the_appliance_listed(self, player):
        arrange()
        with patch("autostream_output_usage.usage_for_output", return_value=None) as lookup:
            change(on(name="Not the real name"))
        lookup.assert_called_once_with("Kitchen")

    def test_a_check_that_fails_lets_the_request_through(self, player):
        arrange()
        with patch("autostream_output_usage.usage_for_output", side_effect=RuntimeError("down")):
            assert change(on()) == {"ok": True, "id": ID}


# ---------------------------------------------------------------------------
# Volume on a speaker that is on
# ---------------------------------------------------------------------------

class TestVolume:
    def test_it_writes_the_level_only(self, player):
        arrange(row(ID, "Kitchen", selected=True, volume_percent=20))
        assert change(on(volume=45), offset_ms=10, mode="x") == {"ok": True, "id": ID}
        assert player.calls == [("update_output", ID, dict(volume_percent=45, timeout=3.0))]
        assert snap().unit(ID).volume == 45

    def test_a_user_level_change_while_muted_ends_the_mute_and_sounds(self, player):
        arrange(row(ID, "Kitchen", selected=True, volume_percent=0))
        mute_state.begin_mute({ID: 30})
        change(on(volume=45))
        assert mute_state.is_muted() is False
        assert player.calls[0][2]["volume_percent"] == 45

    def test_a_coordinator_level_change_while_muted_is_remembered_and_not_written(self, player):
        arrange(row(ID, "Kitchen", selected=True, volume_percent=0))
        mute_state.begin_mute({ID: 30})
        r = change(on(volume=45), requester="coordinator", origin=Origin.SYSTEM)
        assert r == {"ok": True, "id": ID}
        assert player.calls == []
        assert mute_state.intended_level(ID, 0) == 45

    def test_a_speaker_switched_on_while_muted_starts_then_is_silenced_and_remembered(self, player):
        arrange()
        mute_state.begin_mute({})
        assert change(on(volume=40)) == {"ok": True, "id": ID}
        assert [c[2].get("volume_percent") for c in player.calls] == [40, 0]
        assert mute_state.intended_level(ID, 0) == 40

    def test_a_silencing_write_that_fails_is_logged_and_the_request_still_succeeds(self, player, caplog):
        arrange()
        mute_state.begin_mute({})
        player.answers.extend([ok(), err("http_error", "nope")])
        assert change(on(volume=40)) == {"ok": True, "id": ID}
        assert "could not silence" in caplog.text


# ---------------------------------------------------------------------------
# Switching a speaker off
# ---------------------------------------------------------------------------

class TestDisable:
    def test_it_writes_the_deselect_and_forgets_the_remembered_level(self, player):
        arrange(row(ID, "Kitchen", selected=True, volume_percent=20))
        mute_state.begin_mute({ID: 30})
        assert change({"id": ID, "selected": False}) == {"ok": True, "id": ID}
        assert player.calls == [("update_output", ID, dict(enabled=False, timeout=3.0))]
        assert snap().unit(ID).selected is False
        assert mute_state.intended_level(ID, 7) == 7

    def test_a_failure_carries_the_player_s_text(self, player):
        arrange(row(ID, "Kitchen", selected=True))
        player.answers.append(err("http_error", "gone"))
        assert change({"id": ID, "selected": False}) == {"ok": False, "id": ID, "error": "gone"}

    def test_an_unlisted_output_is_refused(self, player):
        arrange()
        assert change({"id": "9", "selected": False})["error"] == "unknown_output"
        assert player.calls == []


# ---------------------------------------------------------------------------
# The PIN
# ---------------------------------------------------------------------------

class TestPin:
    def pin(self, **extra):
        return {"id": ID, "op": "pin", "pin": "1234", **extra}

    def test_a_good_pin_is_sent_and_releases_the_claim(self, player):
        arrange()
        pairing.claim(ID, "webui")
        assert change(self.pin()) == {"ok": True, "id": ID}
        assert player.calls == [("submit_output_pin", ID, "1234")]
        assert pairing.holder(ID) == ""

    def test_a_wrong_pin_is_flagged_and_keeps_the_claim(self, player):
        arrange()
        pairing.claim(ID, "webui")
        player.answers.append(err("pin_invalid", "wrong"))
        assert change(self.pin()) == {"ok": False, "id": ID, "pin_invalid": True, "error": "wrong"}
        assert pairing.holder(ID) == "webui"

    def test_another_failure_is_a_plain_error(self, player):
        arrange()
        player.answers.append(err("http_error", "boom"))
        assert change(self.pin()) == {"ok": False, "id": ID, "error": "boom"}

    def test_a_pin_with_selected_switches_the_speaker_on_after_it(self, player):
        arrange()
        assert change(self.pin(selected=True, volume=55)) == {"ok": True, "id": ID}
        assert [c[0] for c in player.calls] == ["submit_output_pin", "update_output"]
        assert player.calls[1][2]["volume_percent"] == 55

    def test_a_pin_with_selected_false_does_not_switch_anything_off(self, player):
        arrange(row(ID, "Kitchen", selected=True))
        assert change(self.pin(selected=False)) == {"ok": True, "id": ID}
        assert [c[0] for c in player.calls] == ["submit_output_pin"]

    def test_a_pin_that_is_not_four_to_eight_digits_never_reaches_the_player(self, player):
        arrange()
        r = change({"id": ID, "op": "pin", "pin": "12"})
        assert r == {"ok": False, "error": "invalid_pin", "id": ID}
        assert player.calls == []

    def test_the_sixth_pin_in_a_minute_is_rate_limited(self, player):
        arrange()
        for _ in range(5):
            change(self.pin())
        r = change(self.pin())
        assert r["error"] == "rate_limited" and r["retry_after_s"] > 0 and r["ok"] is False
        assert len(player.calls) == 5

    def test_a_caller_without_a_pin_identity_is_counted_against_the_web_page(self, player):
        arrange()
        for _ in range(5):
            change(self.pin(), pin_requester=None)
        assert change(self.pin(), pin_requester="webui")["error"] == "rate_limited"

    def test_nothing_logged_contains_the_pin(self, player, caplog):
        arrange()
        with caplog.at_level("DEBUG"):
            change(self.pin(pin="987654"))
        assert "987654" not in caplog.text


# ---------------------------------------------------------------------------
# The user's choice of silence
# ---------------------------------------------------------------------------

class TestSilenceChosen:
    def test_switching_off_the_last_speaker_is_a_choice_of_silence(self, player):
        arrange(row(ID, "Kitchen", selected=True))
        change({"id": ID, "selected": False})
        assert snap().silence_chosen is True

    def test_switching_off_one_of_two_is_not(self, player):
        arrange(row(ID, "Kitchen", selected=True), row("7", "Den", selected=True))
        change({"id": ID, "selected": False})
        assert snap().silence_chosen is False

    def test_switching_a_speaker_on_again_ends_the_choice(self, player):
        arrange(row(ID, "Kitchen", selected=True))
        change({"id": ID, "selected": False})
        change(on())
        assert snap().silence_chosen is False

    def test_a_coordinator_switch_off_is_not_a_choice(self, player):
        arrange(row(ID, "Kitchen", selected=True))
        change({"id": ID, "selected": False}, requester="coordinator", origin=Origin.SYSTEM)
        assert snap().silence_chosen is False

    def test_the_session_end_clears_it(self, player):
        arrange(row(ID, "Kitchen", selected=True))
        change({"id": ID, "selected": False})
        get_authority().note_session(False)
        assert snap().silence_chosen is False

    def test_a_pin_alone_changes_nothing_about_it(self, player):
        arrange(row(ID, "Kitchen", selected=True))
        change({"id": ID, "selected": False})
        change({"id": ID, "op": "pin", "pin": "1234"})
        assert snap().silence_chosen is True


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------

class TestRows:
    def test_a_missing_id_is_the_page_s_text(self, player):
        assert change({"selected": True}) == {"ok": False, "error": "Missing output id"}

    def test_a_dial_cannot_send_an_origin_the_row_does_not_allow(self, player):
        arrange()
        reply = submit(Intent("outputs.set", {"id": ID, "selected": True}, Origin.SESSION, "coordinator"))
        assert reply.ok is False and reply.error == "origin_not_allowed"

    def test_the_reply_carries_the_store_version_that_shows_the_change(self, player):
        arrange()
        reply = submit(Intent("outputs.set", {"id": ID, "selected": True, "volume": 30}, Origin.USER, "webui"))
        assert reply.ok and reply.version == state.store().snapshot().version


# ---------------------------------------------------------------------------
# A player that is slow to answer
# ---------------------------------------------------------------------------

class TestSlowPlayer:
    def test_an_expired_wait_replies_ok_with_the_desired_state(self, started_authority):
        a = started_authority
        fb = FakeBackend(a)
        fb.rows = [row(ID, "Kitchen")]
        a.start(fb)
        a.merge_for_tests(fb.rows, boot="b0")
        fb.gate = threading.Event()
        try:
            reply = submit(
                Intent("outputs.set", {"id": ID, "selected": True, "volume": 30}, Origin.USER, "webui"),
                wait=0.05,
            )
            assert reply.ok is True and reply.result == {"ok": True, "id": ID}
            assert snap().unit(ID).selected is True and snap().unit(ID).volume == 30
        finally:
            fb.gate.set()

    def test_volume_writes_queued_during_a_stall_become_one_with_the_last_level(self, started_authority):
        a = started_authority
        fb = FakeBackend(a)
        fb.rows = [row(ID, "Kitchen", selected=True, volume_percent=10)]
        a.start(fb)
        a.merge_for_tests(fb.rows, boot="b0")
        fb.gate = threading.Event()
        blocker = threading.Thread(target=lambda: a.set_volume(ID, 11, Origin.USER), daemon=True)
        blocker.start()
        assert fb.entered.wait(5)
        for level in range(20, 30):
            submit(
                Intent("outputs.set", {"id": ID, "selected": True, "volume": level}, Origin.USER, "dial:x"),
                wait=0.01,
            )
        fb.gate.set()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and len(fb.calls) < 2:
            time.sleep(0.01)
        time.sleep(0.1)
        levels = [c[2].get("volume_percent") for c in fb.calls]
        assert levels == [11, 29]


# ---------------------------------------------------------------------------
# The default speaker and the clear-all request from the session edges
# ---------------------------------------------------------------------------

def _default(name="Kitchen", volume=42, **extra):
    args = {"name": name, "volume": volume, **extra}
    return submit(Intent("outputs.select_default", args, Origin.SESSION, "coordinator"))


@pytest.fixture
def usage(monkeypatch):
    """The usage check: records its calls in order; no speaker is occupied."""
    rec = SimpleNamespace(order=[], owner=None, refresh_error=None)

    def refresh_now(*a, **k):
        rec.order.append("refresh")
        if rec.refresh_error is not None:
            raise rec.refresh_error

    def usage_for_output(name):
        rec.order.append("check")
        return None if rec.owner is None else SimpleNamespace(owner_name=rec.owner)

    monkeypatch.setattr(intents_mod.output_usage, "refresh_now", refresh_now)
    monkeypatch.setattr(intents_mod.output_usage, "usage_for_output", usage_for_output)
    return rec


class TestSelectDefault:
    def test_an_empty_name_is_no_default(self, player, usage):
        arrange()
        reply = _default(name="  ")
        assert reply.ok is False and reply.error == "no_default"
        assert player.calls == []

    def test_a_name_that_matches_no_speaker_is_not_found(self, player, usage):
        arrange()
        reply = _default(name="Missing")
        assert reply.ok is False and reply.error == "not_found"
        assert player.calls == []

    def test_the_speaker_is_found_by_name(self, player, usage):
        arrange(row("1", "Hall"), row("2", "Kitchen"))
        assert _default("Kitchen").ok is True
        assert [c[1] for c in player.calls] == ["2"]

    def test_a_speaker_waiting_for_a_pin_is_not_asked_again(self, player, usage):
        arrange(row(ID, "Kitchen", needs_auth_key=True))
        reply = _default()
        assert reply.ok is False and reply.error == "pin_pending"
        assert player.calls == []

    def test_an_occupied_speaker_is_left_alone(self, player, usage):
        arrange()
        usage.owner = "Hall"
        reply = _default()
        assert reply.ok is False and reply.error == "in_use"
        assert reply.result == {"owner": "Hall"}
        assert player.calls == []

    def test_the_usage_is_refreshed_before_it_is_checked(self, player, usage):
        arrange()
        _default()
        assert usage.order == ["refresh", "check"]

    def test_a_failing_usage_check_does_not_stop_the_selection(self, player, usage):
        arrange()
        usage.refresh_error = RuntimeError("unavailable")
        assert _default().ok is True
        assert len(player.calls) == 1

    def test_the_write_carries_the_volume_offset_and_mode(self, player, usage):
        arrange()
        assert _default(volume=42, offset_ms=120, mode="airplay2").ok is True
        assert player.calls == [(
            "update_output", ID,
            dict(enabled=True, volume_percent=42, offset_ms=120, mode="airplay2", timeout=3.0),
        )]

    def test_offset_and_mode_are_optional(self, player, usage):
        arrange()
        _default(volume=30)
        kw = player.calls[0][2]
        assert kw["enabled"] is True and kw["volume_percent"] == 30
        assert kw["offset_ms"] is None and kw["mode"] is None

    def test_a_pin_request_from_the_speaker_is_reported_as_such(self, player, usage):
        arrange()
        player.answers = [err("pin_required")]
        reply = _default()
        assert reply.ok is False and reply.error == "pin_required"

    def test_any_other_failure_carries_the_player_s_text(self, player, usage):
        arrange()
        player.answers = [err("rejected", "no answer")]
        reply = _default()
        assert reply.ok is False and reply.error == "failed"
        assert reply.result == {"message": "no answer"}

    def test_only_the_session_may_ask(self, player, usage):
        arrange()
        reply = submit(Intent("outputs.select_default", {"name": "Kitchen", "volume": 5}, Origin.USER, "webui"))
        assert reply.ok is False and reply.error == "origin_not_allowed"


class TestDeselectAll:
    @pytest.fixture
    def clearing(self, monkeypatch):
        import autostream_player_service as ps

        rec = SimpleNamespace(stops=[], lists=[])
        monkeypatch.setattr(
            ps, "stop_and_disable_all",
            lambda base_url, timeout=None: rec.stops.append(timeout) or ok(),
        )
        monkeypatch.setattr(
            ps, "set_selected_outputs",
            lambda base_url, ids, timeout=None: rec.lists.append(list(ids)) or ok(),
        )
        return rec

    def test_a_session_edge_stops_the_player_and_clears_every_unit(self, clearing, player):
        arrange(row("1", "Hall"), row("2", "Kitchen"))
        get_authority().select("1", Origin.USER, volume=20)
        get_authority().select("2", Origin.USER, volume=30)
        reply = submit(Intent("outputs.deselect_all", {}, Origin.SESSION, "coordinator"))
        assert reply.ok is True
        assert len(clearing.stops) == 1
        assert clearing.lists == []
        assert not any(u.selected for u in snap().units)

    def test_a_user_request_clears_the_list_without_stopping_the_player(self, clearing, player):
        arrange(row("1", "Hall"))
        get_authority().select("1", Origin.USER, volume=20)
        reply = submit(Intent("outputs.deselect_all", {}, Origin.USER, "webui"))
        assert reply.ok is True
        assert clearing.stops == []
        assert clearing.lists == [[]]
        assert not any(u.selected for u in snap().units)
