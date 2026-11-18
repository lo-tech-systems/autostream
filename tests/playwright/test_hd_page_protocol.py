"""Playwright tests for the HD page as a client of the dial's two-part state:
speaker rows as the browser draws them, the roster's "Not allowed" and
"Needs an update" rows, Auto-Start on the speakers sheet, values held until
the appliance's answer, and the words a refusal shows.

Like the other HD page tests these run against the production HdServer over a
FakeCore and check what the page sends on the wire. Without Playwright or its
pytest plugin they skip.
"""
from __future__ import annotations

import dataclasses
import re
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_hd_dial import (  # noqa: E402,F401  (fixtures shared with the page smoke tests)
    _PLAYWRIGHT_INSTALLED, Watcher, browser_context_args, hd_server,
)
from test_hd_page_main import (  # noqa: E402,F401
    card, cards, fulfil, hd, open_page, rows, watch_actions, watch_intents,
)

pytestmark = pytest.mark.skipif(not _PLAYWRIGHT_INSTALLED, reason="playwright not installed")

if _PLAYWRIGHT_INSTALLED:
    from playwright.sync_api import expect

import hd_scenarios as hs  # noqa: E402
from autostream_peer_client import PeerReply  # noqa: E402

LOUNGE = hs.LOUNGE
PLAYING = hs.SCENARIOS["playing_artwork"]
OWN_CLAIM = "dial:" + hs.DIAL.uuid
AUTO_START_TEXT = "Auto-Start playing for future sessions with the current playing devices?"


def unit(uid, name, **fields):
    return {"id": uid, "name": name, "selected": False, "volume": 30, "availability": "ok", **fields}


def with_units(*units, default_matches=False, scenario=PLAYING, **peer):
    outputs = {"connected": True, "master_volume": 42, "muted_all": False, "units": list(units),
               "default_matches": default_matches}
    return scenario.with_peer(outputs=outputs, **peer)


def toggle(page, name):
    return card(page, name).locator("input[type=checkbox]")


@pytest.fixture
def core(hd):
    yield hd.core
    hd.core.intent_reply = None


class TestSpeakerRows:
    def test_a_starting_speaker_reads_connecting_and_an_absent_one_offline(self, page, hd):
        hd.show(with_units(
            unit("u1", "Lounge", selected=True, connecting=True),
            unit("u2", "Patio", auto_start=True, offline=True),
        ))
        open_page(page, hd)
        expect(card(page, "Lounge").locator(".output-card-name")).to_have_text("Lounge (Connecting)")
        expect(card(page, "Lounge").locator(".output-state-chip")).to_have_text("On")
        expect(card(page, "Lounge").locator(".output-state-chip")).to_have_class(re.compile(r"\bconnecting\b"))
        expect(card(page, "Patio").locator(".output-card-name")).to_have_text("Patio (offline)")
        expect(card(page, "Patio").locator(".output-state-chip")).to_have_class(re.compile(r"\boffline\b"))
        expect(card(page, "Patio").locator(".output-card-default")).to_have_text("Auto-Start")

    def test_a_speaker_that_paused_itself_reads_paused(self, page, hd):
        hd.show(with_units(unit("u1", "Lounge", selected=True, held=True), unit("u2", "Patio", selected=True)))
        open_page(page, hd)
        expect(card(page, "Lounge").locator(".output-state-chip")).to_have_text("Paused")
        expect(card(page, "Lounge").locator(".output-state-chip")).to_have_class(re.compile(r"\bpaused\b"))
        expect(card(page, "Lounge").locator(".output-card-name")).to_have_text("Lounge")
        expect(card(page, "Patio").locator(".output-state-chip")).to_have_text("On")

    def test_an_offline_speaker_outside_the_auto_start_set_is_not_listed(self, page, hd):
        hd.show(with_units(unit("u1", "Lounge", selected=True), unit("u2", "Patio", offline=True)))
        open_page(page, hd)
        expect(cards(page)).to_have_count(1)

    def test_a_pin_being_entered_elsewhere_leaves_the_switch_alone(self, page, hd):
        hd.show(with_units(
            unit("u1", "Lounge", selected=True),
            unit("u2", "Patio", pin_claim="webui", reported={"pin_pending": True}),
        ))
        open_page(page, hd)
        expect(card(page, "Patio").locator(".output-state-chip")).to_have_text("Off")
        expect(toggle(page, "Patio")).to_be_disabled()
        expect(toggle(page, "Lounge")).to_be_enabled()

    def test_a_pin_this_dial_is_entering_keeps_the_switch(self, page, hd):
        hd.show(with_units(
            unit("u1", "Lounge", selected=True),
            unit("u2", "Patio", pin_claim=OWN_CLAIM, reported={"pin_pending": True}),
        ))
        open_page(page, hd)
        expect(toggle(page, "Patio")).to_be_enabled()

    def test_an_appliance_with_no_speakers_says_so(self, page, hd):
        hd.show(with_units())
        open_page(page, hd)
        expect(page.locator("#speakers-note")).to_have_text("No speakers on this appliance.")


class TestRosterRows:
    def test_an_appliance_that_has_not_allowed_this_dial_reads_not_allowed(self, page, hd):
        hd.show(hs.SCENARIOS["unauthorized"])
        open_page(page, hd)
        expect(rows(page).filter(has_text="Kitchen").locator(".state")).to_have_text("Not allowed")

    def test_an_appliance_on_another_protocol_reads_needs_an_update_and_has_no_controls(self, page, hd):
        hd.show(hs.SCENARIOS["appliance_needs_update"])
        open_page(page, hd)
        row = rows(page).first
        expect(row.locator(".state")).to_have_text("Needs an update")
        expect(row).to_have_class(re.compile(r"\bbad\b"))
        expect(cards(page)).to_have_count(0)
        expect(page.locator("#master")).to_be_disabled()
        expect(page.locator("#autostart-pin")).to_be_hidden()


class TestAutoStart:
    def test_the_pin_is_shaded_while_the_speakers_on_are_the_saved_set(self, page, hd):
        assert PLAYING.snapshot.focused_peer.parts["outputs"]["default_matches"] is True
        open_page(page, hd)
        pin = page.locator("#autostart-pin")
        expect(pin).to_be_visible()
        expect(pin).to_have_attribute("aria-label", "Auto-Start these speakers")
        expect(pin).to_have_attribute("aria-pressed", "true")
        expect(pin).to_have_class(re.compile(r"\bis-set\b"))
        assert pin.inner_text().strip() == ""
        hd.show(with_units(unit("u1", "Lounge", selected=True, auto_start=True), unit("u2", "Patio", selected=True)))
        expect(pin).to_have_attribute("aria-pressed", "false")
        expect(pin).not_to_have_class(re.compile(r"\bis-set\b"))

    def test_the_pin_is_hidden_with_nothing_playing(self, page, hd):
        hd.show(PLAYING.with_peer(session={"active": False, "source": ""}))
        open_page(page, hd)
        expect(page.locator("#autostart-pin")).to_be_hidden()

    def test_the_pin_asks_first_and_cancel_sends_nothing(self, page, hd):
        sent = watch_intents(page)
        open_page(page, hd)
        page.locator("#autostart-pin").click()
        expect(page.locator("#modal")).to_be_visible()
        expect(page.locator("#card-title")).to_have_text("Auto-Start")
        expect(page.locator("#card-message")).to_have_text(AUTO_START_TEXT)
        assert page.locator("#card-buttons button").all_text_contents() == ["Cancel", "Yes"]
        page.locator("#card-buttons button", has_text="Cancel").click()
        expect(page.locator("#modal")).to_be_hidden()
        page.wait_for_timeout(200)
        assert sent == []

    def test_yes_saves_the_speakers_playing_now(self, page, hd, core):
        sent = watch_intents(page)
        open_page(page, hd)
        page.locator("#autostart-pin").click()
        page.locator("#card-buttons button", has_text="Yes").click()
        expect(page.locator("#modal")).to_be_hidden()
        page.wait_for_timeout(200)
        assert sent == [("outputs.save_default", {})]
        assert core.intents()[-1] == (LOUNGE, "outputs.save_default", {})

    def test_a_refused_save_says_why(self, page, hd):
        fulfil(page, "/api/v1/intents/outputs.save_default", {"ok": False, "error": "nothing_selected"})
        open_page(page, hd)
        page.locator("#autostart-pin").click()
        page.locator("#card-buttons button", has_text="Yes").click()
        expect(page.locator("#toast")).to_have_text("Turn on at least one speaker first.")


class TestHeldValues:
    def test_a_switch_holds_until_the_appliance_reaches_the_version_it_answered_with(self, page, hd, core):
        core.intent_reply = PeerReply(True, None, hs.PEER_VERSION + 3, hs.PEER_BOOT, {}, None)
        open_page(page, hd)
        toggle(page, "Patio").click(force=True)
        expect(toggle(page, "Patio")).to_be_checked()
        # A state from before the answer's version: still held.
        hd.show(PLAYING.with_peer(version=hs.PEER_VERSION + 2, track={"entries": {"1": {
            "enabled": True, "state": "identified", "title": "T1", "artist": "A"}}}))
        expect(page.locator("#title")).to_have_text("T1")
        expect(toggle(page, "Patio")).to_be_checked()
        # The appliance has reached it and says the speaker is off: the state wins.
        hd.show(PLAYING.with_peer(version=hs.PEER_VERSION + 3))
        expect(toggle(page, "Patio")).not_to_be_checked()

    def test_a_value_held_for_one_appliance_is_dropped_when_the_focus_moves(self, page, hd, core):
        core.intent_reply = PeerReply(True, None, hs.PEER_VERSION + 50, hs.PEER_BOOT, {}, None)
        open_page(page, hd)
        toggle(page, "Patio").click(force=True)
        expect(toggle(page, "Patio")).to_be_checked()
        hd.show(hs.SCENARIOS["replay_elsewhere"])
        expect(page.locator("#speakers-label")).to_have_text("Speakers on Kitchen")
        hd.show(PLAYING)
        expect(page.locator("#speakers-label")).to_have_text("Speakers on Lounge")
        expect(toggle(page, "Patio")).not_to_be_checked()

    def test_an_answer_from_another_run_of_the_appliance_lets_go_at_once(self, page, hd, core):
        core.intent_reply = PeerReply(True, None, hs.PEER_VERSION + 50, "another-boot", {}, None)
        open_page(page, hd)
        toggle(page, "Patio").click(force=True)
        expect(toggle(page, "Patio")).not_to_be_checked()

    def test_a_refused_intent_rolls_back_and_says_why(self, page, hd, core):
        core.intent_reply = PeerReply(False, "unreachable", None, None, {}, None)
        open_page(page, hd)
        toggle(page, "Patio").click(force=True)
        expect(page.locator("#toast")).to_have_text("The appliance did not answer.")
        expect(toggle(page, "Patio")).not_to_be_checked()

    def test_an_appliance_refusal_reads_from_the_shared_words(self, page, hd):
        fulfil(page, "/api/v1/intents/outputs.set", {"ok": False, "error": "encoder_capacity"})
        open_page(page, hd)
        toggle(page, "Patio").click(force=True)
        expect(page.locator("#toast")).to_contain_text("CPU cannot encode another stream")

    def test_the_dials_timeout_says_nothing_and_the_value_runs_out(self, page, hd):
        fulfil(page, "/api/v1/intents/outputs.set", {"ok": False, "error": "timeout"}, status=504)
        page.clock.install()
        open_page(page, hd)
        toggle(page, "Patio").click(force=True)
        page.clock.run_for(1000)
        expect(toggle(page, "Patio")).to_be_checked()
        expect(page.locator("#toast")).not_to_have_class(re.compile(r"\bshow\b"))
        page.clock.run_for(8000)
        expect(toggle(page, "Patio")).not_to_be_checked()

    def test_an_answer_after_the_page_gave_up_leaves_the_row_to_the_stream(self, page, hd, core):
        gate = threading.Event()
        core.intent_reply = lambda name, args: (
            gate.wait(5), PeerReply(True, None, hs.PEER_VERSION + 1, hs.PEER_BOOT, {}, None))[1]
        page.clock.install()
        try:
            open_page(page, hd)
            toggle(page, "Patio").click(force=True)
            expect(toggle(page, "Patio")).to_be_checked()
            # The page's own wait runs out before the appliance answers.
            page.clock.run_for(8100)
            expect(toggle(page, "Patio")).not_to_be_checked()
            expect(page.locator("#toast")).not_to_have_class(re.compile(r"\bshow\b"))
            # The appliance did switch it on: the stream says so.
            rows_on = tuple(dataclasses.replace(r, selected=True) if r.id == "o2" else r for r in hs.rows())
            hd.show(PLAYING.with_snapshot(outputs=dataclasses.replace(PLAYING.snapshot.outputs, rows=rows_on)))
            expect(toggle(page, "Patio")).to_be_checked()
        finally:
            gate.set()
        page.wait_for_timeout(200)
        expect(page.locator("#toast")).not_to_have_class(re.compile(r"\bshow\b"))


class TestRefusalWords:
    def test_a_dial_action_refused_as_wrong_state_says_so(self, page, hd):
        hd.show(hs.SCENARIOS["replay_elsewhere"])
        fulfil(page, "/api/v1/actions/focus", {"ok": False, "error": "wrong_state"}, status=409)
        open_page(page, hd)
        rows(page).nth(1).click()
        expect(page.locator("#toast")).to_have_text("Not possible right now.")

    def test_an_unknown_reason_reads_as_the_fallback(self, page, hd):
        fulfil(page, "/api/v1/intents/outputs.set", {"ok": False, "error": "surprise"})
        open_page(page, hd)
        toggle(page, "Patio").click(force=True)
        expect(page.locator("#toast")).to_have_text("That did not work.")
