"""tests/test_output_intents.py

The output handlers of the intent table: switching a speaker on and off,
changing its volume, the PIN path, volume steps and mute. A speaker is arranged through the
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
import webui.browser.home_model as webui_home_model

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
    return webui_home_model.submit_output_change(body, **kw)


def on(**extra):
    return {"id": ID, "selected": True, **extra}


@pytest.fixture(autouse=True)
def _fresh():
    pairing.reset_for_tests() if hasattr(pairing, "reset_for_tests") else None
    yield


def hold_mute(player):
    """Mute every selected speaker through the authority; the writes it makes
    are not what the test is about."""
    get_authority().mute_all(Origin.USER)
    player.calls.clear()


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

    def test_a_missing_volume_is_the_configured_start_volume(self, player):
        arrange()
        get_authority().set_default_output("Lounge", 35)
        change(on())
        assert player.calls[0][2]["volume_percent"] == 35

    def test_a_missing_volume_in_the_intent_is_the_configured_start_volume(self, player):
        arrange()
        get_authority().set_default_output("Lounge", 22)
        submit(Intent("outputs.set", {"id": ID, "selected": True}, Origin.USER, "webui"))
        assert player.calls[0][2]["volume_percent"] == 22

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
        arrange(row(ID, "Kitchen", selected=True, volume_percent=30))
        hold_mute(player)
        change(on(volume=45))
        assert snap().muted_all is False and snap().unit(ID).muted is False
        assert player.calls[0][2]["volume_percent"] == 45

    def test_a_coordinator_level_change_while_muted_is_remembered_and_not_written(self, player):
        arrange(row(ID, "Kitchen", selected=True, volume_percent=30))
        hold_mute(player)
        r = change(on(volume=45), requester="coordinator", origin=Origin.SYSTEM)
        assert r == {"ok": True, "id": ID}
        assert player.calls == []
        assert snap().unit(ID).muted is True and snap().unit(ID).volume == 45

    def test_a_speaker_switched_on_while_muted_starts_silent_and_remembers_its_level(self, player):
        arrange(row("7", "Other", selected=True, volume_percent=25), row(ID, "Kitchen"))
        hold_mute(player)
        assert change(on(volume=40)) == {"ok": True, "id": ID}
        assert [c[2].get("volume_percent") for c in player.calls] == [0]
        assert snap().unit(ID).muted is True and snap().unit(ID).volume == 40
        assert snap().muted_all is True


# ---------------------------------------------------------------------------
# Switching a speaker off
# ---------------------------------------------------------------------------

class TestDisable:
    def test_it_writes_the_deselect_and_forgets_the_remembered_level(self, player):
        arrange(row(ID, "Kitchen", selected=True, volume_percent=20))
        hold_mute(player)
        assert change({"id": ID, "selected": False}) == {"ok": True, "id": ID}
        assert player.calls == [("update_output", ID, dict(enabled=False, timeout=3.0))]
        assert snap().unit(ID).selected is False
        assert snap().unit(ID).muted is False

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
# A PIN request that arrives after the wait
# ---------------------------------------------------------------------------

def _wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


class TestLatePin:
    def _stalled_select(self, a, fb, *, context):
        """Start a select that the player answers after the caller stopped
        waiting; return once the reply ("pending", ok) has been sent."""
        fb.rows = [row(ID, "Kitchen")]
        a.start(fb)
        # The worker's first read must finish its merge before the select, or
        # it could land after the refusal and show the speaker as available.
        assert _wait_for(lambda: not a._dirty)
        with a._lock:
            pass
        a.merge_for_tests(fb.rows, boot="b0")
        fb.gate = threading.Event()
        fb.results.append(err("pin_required", "needs a PIN"))
        reply = submit(
            Intent("outputs.set", {"id": ID, "selected": True, "volume": 30}, Origin.USER, "dial:abc",
                   context=context),
            wait=0.05,
        )
        assert reply.ok is True and reply.result == {"ok": True, "id": ID}
        return reply

    def test_a_late_pin_request_claims_the_pairing_for_the_asker_and_is_published(self, started_authority):
        a = started_authority
        fb = FakeBackend(a)
        self._stalled_select(a, fb, context="dial:abc")
        assert pairing.holder(ID) == ""
        fb.gate.set()
        assert _wait_for(lambda: snap().start_failure is not None)
        assert _wait_for(lambda: pairing.holder(ID) == "dial:abc")
        failure = snap().start_failure
        assert failure.reason == "pin_required" and failure.requester == "dial:abc"
        assert failure.unit_id == ID
        assert snap().unit(ID).selected is False and snap().unit(ID).availability == "password"

    def test_a_late_pin_request_sends_no_deselect(self, started_authority):
        a = started_authority
        fb = FakeBackend(a)
        self._stalled_select(a, fb, context="dial:abc")
        fb.gate.set()
        assert _wait_for(lambda: pairing.holder(ID) == "dial:abc")
        time.sleep(0.1)
        # The speaker deselects itself while it waits for the PIN.
        assert [kw.get("enabled") for _i, kw in fb.updates()] == [True]

    def test_a_late_pin_request_from_a_caller_that_cannot_enter_a_pin_claims_nothing(self, started_authority):
        a = started_authority
        fb = FakeBackend(a)
        self._stalled_select(a, fb, context=None)
        fb.gate.set()
        assert _wait_for(lambda: snap().start_failure is not None)
        time.sleep(0.1)
        assert pairing.holder(ID) == ""
        assert snap().start_failure.requester == "dial:abc"

    def test_a_pin_request_inside_the_wait_is_claimed_once_and_in_the_reply(self, player):
        arrange()
        player.answers.append(err("pin_required", "needs a PIN"))
        r = change(on(name="Kitchen"), requester="dial:abc", pin_requester="dial:abc")
        assert r["pin_required"] is True and r["id"] == ID
        assert pairing.holder(ID) == "dial:abc"
        assert snap().start_failure.requester == "dial:abc"

    def test_the_state_package_does_not_import_the_pairing_module(self):
        import ast
        from pathlib import Path as P
        # Only the live reads may ask it, for who holds a PIN claim; the part
        # publishers and the authority never do.
        for path in (P(intents_mod.__file__).parent / "autostream_state").glob("*.py"):
            if path.name == "live.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            names = {
                n.names[0].name if isinstance(n, ast.Import) else (n.module or "")
                for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
            }
            assert "autostream_pin_pairing" not in names, path


# ---------------------------------------------------------------------------
# Volume steps and mute as intents
# ---------------------------------------------------------------------------

def _step(delta, *, default_level=20, wait=None):
    return submit(
        Intent("volume.step", {"delta": delta, "default_level": default_level}, Origin.USER, "dial:abc"),
        wait=wait,
    )


def _mute(action, *, default_level=20, wait=None):
    return submit(
        Intent("mute.set", {"action": action, "default_level": default_level}, Origin.USER, "dial:abc"),
        wait=wait,
    )


class TestVolumeStepAndMute:
    def test_a_step_down_while_muted_changes_nothing_and_reports_the_intended_master(self, player):
        arrange(row("1", "A", selected=True, volume_percent=40), row("2", "B", selected=True, volume_percent=20))
        assert _mute("mute").result == {"ok": True, "muted": True}
        player.calls.clear()
        assert _step(-5).result == {"ok": True, "volume": 30, "muted": True}
        assert player.calls == []

    def test_a_step_up_while_muted_is_a_plain_restore(self, player):
        arrange(row("1", "A", selected=True, volume_percent=40))
        _mute("mute")
        player.calls.clear()
        assert _step(9).result == {"ok": True, "muted": False, "volume": 40}
        assert [c[2]["volume_percent"] for c in player.calls] == [40]

    def test_a_step_from_silence_lifts_every_speaker_to_the_step(self, player):
        arrange(row("1", "A", selected=True, volume_percent=0), row("2", "B", selected=True, volume_percent=0))
        assert _step(6).result == {"ok": True, "volume": 6, "muted": False}
        assert [c[2]["volume_percent"] for c in player.calls] == [6, 6]

    def test_a_step_scales_each_speaker_in_proportion(self, player):
        arrange(row("1", "A", selected=True, volume_percent=60), row("2", "B", selected=True, volume_percent=40))
        assert _step(10).result == {"ok": True, "volume": 60, "muted": False}
        assert sorted((c[1], c[2]["volume_percent"]) for c in player.calls) == [("1", 72), ("2", 48)]

    def test_a_step_with_one_failed_write_is_partial_and_with_all_failed_is_an_error(self, player):
        arrange(row("1", "A", selected=True, volume_percent=50), row("2", "B", selected=True, volume_percent=50))
        player.answers.extend([ok(), err("http_error", "x")])
        assert _step(10).result == {"ok": True, "volume": 60, "partial": True, "muted": False}
        player.answers.extend([err("http_error", "x"), err("http_error", "x")])
        assert _step(10).result == {"ok": False, "error": "all_outputs_failed"}

    def test_a_step_or_a_mute_with_nothing_selected_or_no_player_is_refused(self, player):
        arrange(row("1", "A"))
        assert _step(5).result == {"ok": False, "error": "no_active_outputs"}
        assert _mute("mute").result == {"ok": False, "error": "no_active_outputs"}
        FakeStore().outputs_unreachable()
        assert _step(5).result == {"ok": False, "error": "backend_unavailable"}
        assert _mute("restore").result == {"ok": False, "error": "backend_unavailable"}

    def test_a_mute_is_idempotent_and_reports_a_partial_failure(self, player):
        arrange(row("1", "A", selected=True, volume_percent=50), row("2", "B", selected=True, volume_percent=50))
        player.answers.extend([ok(), err("http_error", "x")])
        assert _mute("mute").result == {"ok": True, "muted": True, "partial": True}
        player.calls.clear()
        assert _mute("mute").result == {"ok": True, "muted": True}
        assert player.calls == []

    def test_only_a_user_may_ask_for_a_step_or_a_mute(self, player):
        arrange(row("1", "A", selected=True, volume_percent=50))
        for name, args in (("volume.step", {"delta": 1, "default_level": 20}),
                           ("mute.set", {"action": "mute", "default_level": 20})):
            reply = submit(Intent(name, args, Origin.SESSION, "coordinator"))
            assert reply.ok is False and reply.error == "origin_not_allowed"

    def test_an_expired_wait_replies_from_the_desired_state(self, started_authority):
        a = started_authority
        fb = FakeBackend(a)
        fb.rows = [row("1", "A", selected=True, volume_percent=40), row("2", "B", selected=True, volume_percent=20)]
        a.start(fb)
        a.merge_for_tests(fb.rows, boot="b0")
        fb.gate = threading.Event()
        try:
            reply = _step(10, wait=0.05)
            assert reply.result == {"ok": True, "volume": 40, "muted": False}
            reply = _mute("mute", wait=0.05)
            assert reply.result == {"ok": True, "muted": True}
        finally:
            fb.gate.set()

    def test_knob_turns_during_a_blocked_write_become_one_write_per_speaker(self, started_authority):
        a = started_authority
        fb = FakeBackend(a)
        fb.rows = [row("1", "A", selected=True, volume_percent=10), row("2", "B", selected=True, volume_percent=10)]
        a.start(fb)
        a.merge_for_tests(fb.rows, boot="b0")
        fb.gate = threading.Event()
        blocker = threading.Thread(target=lambda: a.set_volume("1", 11, Origin.USER), daemon=True)
        blocker.start()
        assert fb.entered.wait(5)
        for _ in range(8):
            _step(2, wait=0.01)
        fb.gate.set()
        assert _wait_for(lambda: len(fb.calls) >= 3)
        time.sleep(0.1)
        by_unit = {}
        for unit_id, kw in fb.updates():
            by_unit.setdefault(unit_id, []).append(kw.get("volume_percent"))
        assert by_unit["1"][0] == 11 and by_unit["1"][-1] == snap().unit("1").volume
        assert len(by_unit["2"]) == 1 and by_unit["2"][0] == snap().unit("2").volume


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


# ---------------------------------------------------------------------------
# The default speaker's card while the player has no row for it
# ---------------------------------------------------------------------------

class TestOfflineDefault:
    CARD = "default:Kitchen"

    @pytest.fixture(autouse=True)
    def _configured(self):
        get_authority().set_default_output("Kitchen", 42)

    def test_select_default_does_not_find_a_card_with_no_row(self, player, usage):
        arrange(row("1", "Hall"))
        reply = _default()
        assert reply.ok is False and reply.error == "not_found"
        assert player.calls == []

    def test_select_default_does_not_find_a_default_whose_row_went_away(self, player, usage):
        arrange(row("1", "Hall"), row("2", "Kitchen", selected=True))
        arrange(row("1", "Hall"))
        assert snap().unit("2").offline
        reply = _default()
        assert reply.ok is False and reply.error == "not_found"
        assert player.calls == []

    def test_a_tap_on_the_card_is_a_choice_and_writes_nothing(self, player):
        arrange(row("1", "Hall"))
        get_authority().note_session(True)
        assert change({"id": self.CARD, "selected": False}) == {"ok": True}
        assert snap().silence_chosen is True and snap().units[-1].selected is False
        assert change({"id": self.CARD, "selected": True, "volume": 30}) == {"ok": True}
        assert snap().silence_chosen is False and snap().units[-1].selected is True
        assert player.calls == []

    def test_a_tap_on_the_card_by_the_session_is_not_allowed(self, player):
        arrange(row("1", "Hall"))
        reply = submit(Intent("outputs.want_default", {"wanted": True}, Origin.SESSION, "coordinator"))
        assert reply.ok is False and reply.error == "origin_not_allowed"

    def test_a_card_id_means_a_unit_once_the_row_is_there(self, player):
        arrange(row("1", "Hall"), row("2", "Kitchen"))
        change({"id": "2", "selected": True, "volume": 30})
        assert player.calls and player.calls[0][1] == "2"
