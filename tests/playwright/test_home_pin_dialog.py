"""Playwright tests: the Home page PIN dialog pairs and enables in one request.

The page comes from the real Home renderer; the state parts and the intent
replies are stubbed. Every PIN attempt is one ``output.pin.submit`` carrying
the PIN and selected:true. A wrong PIN shows a note and asks again, a
rate-limited reply shows a counting-down wait with the input disabled, and the
prompt a speaker's own request for a PIN opens leaves a row claimed by a dial
alone.
"""
from __future__ import annotations

import pytest
import _home_stub as stub
from _home_stub import start_server
from _home_helpers import intents, open_home, outputs, speaker, wait_for

try:
    from playwright.sync_api import Page, expect  # type: ignore[attr-defined]
    _PLAYWRIGHT_INSTALLED = True
except ImportError:
    _PLAYWRIGHT_INSTALLED = False
    Page = object  # type: ignore[misc,assignment]
    expect = None  # type: ignore[assignment]

_requires_browser = pytest.mark.skipif(
    not _PLAYWRIGHT_INSTALLED, reason="playwright not installed"
)

_OPEN = "modal-overlay show"
_NEEDS_PIN = {"ok": False, "result": {"pin_required": True}}
_WRONG_PIN = {"ok": False, "result": {"pin_invalid": True}}


def _limited(seconds: int) -> dict:
    return {"ok": False, "error": "rate_limited", "retry_after_s": seconds,
            "result": {"error": "rate_limited", "retry_after_s": seconds}}


@pytest.fixture(scope="module")
def home_url():
    server, url = start_server(b"")
    try:
        yield url
    finally:
        server.shutdown()


def _open(page: "Page", base: str, replies: list, *units: dict, cards: bool = True) -> None:
    open_home(page, base, {"outputs": outputs(*(units or (speaker(name="Lounge TV"),)))}, wait_cards=cards)
    stub.REPLIES[:] = replies


def _pause_clock(page: "Page") -> None:
    page.clock.pause_at(page.evaluate("Date.now()") / 1000 + 1)


def _toggle_on(page: "Page") -> None:
    page.evaluate(
        "() => { const c = document.getElementById('output_enabled_tv');"
        " c.checked = true; c.dispatchEvent(new Event('change', {bubbles: true})); }"
    )


def _type_pin(page: "Page", digits: str) -> None:
    page.locator("#pinModalInput").fill(digits)


@_requires_browser
class TestHomePinDialog:
    def test_switching_on_a_speaker_that_needs_a_pin_opens_the_dialog_and_one_request_pairs_and_enables(
        self, page: "Page", home_url: str
    ):
        _open(page, home_url, [_NEEDS_PIN, {}])
        _toggle_on(page)
        expect(page.locator("#pinModal")).to_have_class(_OPEN)
        expect(page.locator("#pinModalTitle")).to_have_text("Enter PIN for Lounge TV")
        assert intents() == [("outputs.set", {"id": "tv", "selected": True, "volume": 20, "name": "Lounge TV"})]
        _type_pin(page, "2718")
        page.locator("#pinModalOk").click()
        expect(page.locator("#pinModal")).not_to_have_class(_OPEN)
        expect(page.locator("#output_enabled_tv")).to_be_checked()
        assert intents()[1:] == [("output.pin.submit", {
            "id": "tv", "pin": "2718", "selected": True, "volume": 20, "name": "Lounge TV"})]
        page.wait_for_timeout(300)
        assert len(stub.POSTS) == 2

    def test_a_wrong_pin_re_prompts_with_the_note(self, page: "Page", home_url: str):
        _open(page, home_url, [_NEEDS_PIN, _WRONG_PIN, {}])
        _toggle_on(page)
        _type_pin(page, "1111")
        page.locator("#pinModalOk").click()
        expect(page.locator("#pinModalNote")).to_have_text("That PIN was not accepted. Try again.")
        expect(page.locator("#pinModalInput")).to_have_value("")
        expect(page.locator("#pinModalOk")).to_be_disabled()
        _type_pin(page, "2718")
        page.locator("#pinModalOk").click()
        expect(page.locator("#output_enabled_tv")).to_be_checked()
        assert [a.get("pin") for _, a in intents()[1:]] == ["1111", "2718"]

    def test_a_wrong_pin_that_brought_up_a_new_one_says_so(self, page: "Page", home_url: str):
        wrong_new = {"ok": False, "result": {"pin_invalid": True, "new_pin": True}}
        _open(page, home_url, [_NEEDS_PIN, wrong_new, {}])
        _toggle_on(page)
        _type_pin(page, "1111")
        page.locator("#pinModalOk").click()
        expect(page.locator("#pinModalNote")).to_have_text(
            "That PIN was not accepted. A new PIN is showing on the TV.")
        _type_pin(page, "2718")
        page.locator("#pinModalOk").click()
        expect(page.locator("#output_enabled_tv")).to_be_checked()

    def test_a_pin_the_speaker_was_too_busy_to_take_asks_again_with_the_note(self, page: "Page", home_url: str):
        busy = {"ok": False, "error": "busy", "result": {"ok": False, "id": "tv", "busy": True, "error": "busy"}}
        _open(page, home_url, [_NEEDS_PIN, busy, {}])
        _toggle_on(page)
        _type_pin(page, "2718")
        page.locator("#pinModalOk").click()
        expect(page.locator("#pinModalNote")).to_have_text("The speaker is busy. Try the PIN again in a moment.")
        expect(page.locator("#pinModal")).to_have_class(_OPEN)
        expect(page.locator("#output_enabled_tv")).not_to_be_checked()
        _type_pin(page, "2718")
        page.locator("#pinModalOk").click()
        expect(page.locator("#output_enabled_tv")).to_be_checked()
        assert [a.get("pin") for _, a in intents()[1:]] == ["2718", "2718"]

    def test_a_wrong_pin_refused_after_a_pending_reply_reopens_with_the_new_pin_line(
        self, page: "Page", home_url: str
    ):
        _open(page, home_url, [_NEEDS_PIN, {"ok": True, "result": {"ok": True, "id": "tv", "pending": True}}])
        _toggle_on(page)
        _type_pin(page, "1111")
        page.locator("#pinModalOk").click()
        expect(page.locator("#pinModal")).not_to_have_class(_OPEN)
        # The verdict comes after the reply: the switch shows the reply was taken
        expect(page.locator("#output_enabled_tv")).to_be_checked()
        failure = {"seq": 1, "unit_id": "tv", "name": "Speaker A", "reason": "pin_invalid",
                   "requester": "webui", "at": page.evaluate("Date.now()") / 1000}
        stub.push({"outputs": outputs(speaker(pin_pending=True), start_failure=failure)})
        expect(page.locator("#pinModal")).to_have_class(_OPEN)
        expect(page.locator("#pinModalNote")).to_have_text(
            "That PIN was not accepted. A new PIN is showing on the TV.")

    def test_a_rate_limited_reply_shows_the_wait_and_counts_down(self, page: "Page", home_url: str):
        page.clock.install()
        _open(page, home_url, [_NEEDS_PIN, _limited(3), {}])
        _pause_clock(page)
        _toggle_on(page)
        _type_pin(page, "1111")
        page.locator("#pinModalOk").click()
        note = page.locator("#pinModalNote")
        expect(note).to_have_text("Wait 3 seconds before retry")
        expect(page.locator("#pinModalInput")).to_be_disabled()
        expect(page.locator("#pinModalOk")).to_be_disabled()
        page.clock.run_for(1000)
        expect(note).to_have_text("Wait 2 seconds before retry")
        page.clock.run_for(1000)
        expect(note).to_have_text("Wait 1 second before retry")
        assert len(stub.POSTS) == 2
        page.clock.run_for(1000)
        expect(note).to_be_hidden()
        expect(page.locator("#pinModalInput")).to_be_enabled()
        expect(page.locator("#pinModalOk")).to_be_disabled()
        _type_pin(page, "2718")
        page.locator("#pinModalOk").click()
        expect(page.locator("#output_enabled_tv")).to_be_checked()
        assert len(stub.POSTS) == 3
        assert intents()[2][1]["pin"] == "2718"

    def test_ok_stays_disabled_under_four_digits_and_letters_are_refused(self, page: "Page", home_url: str):
        _open(page, home_url, [_NEEDS_PIN])
        _toggle_on(page)
        field = page.locator("#pinModalInput")
        ok = page.locator("#pinModalOk")
        expect(ok).to_be_disabled()
        field.press_sequentially("12a3")
        expect(field).to_have_value("123")
        expect(ok).to_be_disabled()
        field.press_sequentially("45678999")
        expect(field).to_have_value("12345678")
        expect(ok).to_be_enabled()
        field.fill("12")
        expect(ok).to_be_disabled()
        field.fill("1234")
        expect(ok).to_be_enabled()

    def test_cancel_during_the_wait_closes_the_dialog_and_turns_the_switch_off(
        self, page: "Page", home_url: str
    ):
        page.clock.install()
        _open(page, home_url, [_NEEDS_PIN, _limited(5)])
        _pause_clock(page)
        _toggle_on(page)
        _type_pin(page, "1111")
        page.locator("#pinModalOk").click()
        expect(page.locator("#pinModalNote")).to_have_text("Wait 5 seconds before retry")
        page.locator("#pinModalCancel").click()
        expect(page.locator("#pinModal")).not_to_have_class(_OPEN)
        expect(page.locator("#output_enabled_tv")).not_to_be_checked()
        page.clock.run_for(10000)
        expect(page.locator("#pinModal")).not_to_have_class(_OPEN)
        assert len(stub.POSTS) == 2

    def test_the_pin_field_fits_inside_the_dialog_on_a_phone(self, page: "Page", home_url: str):
        page.set_viewport_size({"width": 360, "height": 740})
        _open(page, home_url, [_NEEDS_PIN])
        _toggle_on(page)
        expect(page.locator("#pinModal")).to_have_class(_OPEN)
        field = page.locator("#pinModalInput").bounding_box()
        body = page.locator("#pinModal .modal-bd").bounding_box()
        assert field["x"] >= body["x"]
        assert field["x"] + field["width"] <= body["x"] + body["width"]
        assert field["x"] + field["width"] <= 360

    def test_escape_cancels_the_dialog(self, page: "Page", home_url: str):
        _open(page, home_url, [_NEEDS_PIN])
        _toggle_on(page)
        expect(page.locator("#pinModal")).to_have_class(_OPEN)
        page.keyboard.press("Escape")
        expect(page.locator("#pinModal")).not_to_have_class(_OPEN)
        expect(page.locator("#output_enabled_tv")).not_to_be_checked()

    def test_a_row_asking_for_a_pin_claimed_by_a_dial_is_left_alone(self, page: "Page", home_url: str):
        _open(page, home_url, [], speaker(pin_pending=True, pin_claim="dial:x"))
        page.wait_for_timeout(1500)
        expect(page.locator("#pinModal")).not_to_have_class(_OPEN)
        assert stub.POSTS == []

    @pytest.mark.parametrize("claim", ["", "webui"])
    def test_a_row_asking_for_a_pin_that_nobody_else_is_entering_opens_the_dialog(
        self, page: "Page", home_url: str, claim: str
    ):
        _open(page, home_url, [], speaker(pin_pending=True, pin_claim=claim))
        expect(page.locator("#pinModal")).to_have_class(_OPEN)

    def test_a_cancelled_prompt_does_not_come_back_until_the_speaker_asks_again(
        self, page: "Page", home_url: str
    ):
        stub.stream_on()
        _open(page, home_url, [], speaker(pin_pending=True))
        expect(page.locator("#pinModal")).to_have_class(_OPEN)
        page.locator("#pinModalCancel").click()
        stub.push({"outputs": outputs(speaker(pin_pending=True, volume=25))})
        page.wait_for_timeout(500)
        expect(page.locator("#pinModal")).not_to_have_class(_OPEN)
        stub.push({"outputs": outputs(speaker())})
        stub.push({"outputs": outputs(speaker(pin_pending=True))})
        expect(page.locator("#pinModal")).to_have_class(_OPEN)

    def test_an_accepted_pin_is_not_asked_for_again_before_the_state_catches_up(
        self, page: "Page", home_url: str
    ):
        stub.stream_on()
        _open(page, home_url, [{}], speaker(pin_pending=True))
        expect(page.locator("#pinModal")).to_have_class(_OPEN)
        _type_pin(page, "2718")
        page.locator("#pinModalOk").click()
        expect(page.locator("#pinModal")).not_to_have_class(_OPEN)
        # The reply came first: the copy still has the speaker asking
        page.wait_for_timeout(500)
        expect(page.locator("#pinModal")).not_to_have_class(_OPEN)
        stub.push({"outputs": outputs(speaker(selected=True))})
        page.wait_for_timeout(2500)
        expect(page.locator("#pinModal")).not_to_have_class(_OPEN)
        # Once caught up, a new request for a PIN is asked for again
        stub.push({"outputs": outputs(speaker(pin_pending=True))})
        expect(page.locator("#pinModal")).to_have_class(_OPEN)


def _input(input_type: str, is_turntable: bool = False) -> dict:
    return {"is_turntable": is_turntable, "is_bluetooth": False, "input_type": input_type}


@_requires_browser
class TestHomeNowPlayingCard:
    def test_the_card_reads_the_entry_of_the_inputs_own_number(self, page: "Page", home_url: str):
        entry = {"index": 2, "device": "hw:1,0", "input_type": "cd", "capturing": True,
                 "level": {"index": 2, "label": "Input 2", "dbfs": -30.0, "is_above_threshold": True}}
        parts = {
            "session": {"active": True, "source": "input2"},
            "inputs": {"entries": [entry], "sample_rate_mismatch_input": 0, "sample_rate_warning_text": ""},
            "playback": {"inputs": {"1": _input("turntable", True), "2": _input("cd")}},
        }
        open_home(page, home_url, {**parts, "outputs": outputs()}, wait_cards=False)
        expect(page.locator("#np-name")).to_have_text("Input 2 · CD")
        expect(page.locator("#np-icon")).to_have_attribute("data-np-icon-key", "svg:cd")
        expect(page.locator("#np-hdr")).to_have_text("Now Playing")


def _signal_parts(**level) -> dict:
    entry = {"index": 1, "device": "hw:0,0", "input_type": "line", "capturing": True,
             "level": {"index": 1, "label": "Input 1", "is_above_threshold": True, **level}}
    return {"session": {"active": True, "source": "input1"},
            "inputs": {"entries": [entry], "sample_rate_mismatch_input": 0, "sample_rate_warning_text": ""}}


@_requires_browser
class TestInputCardRateText:
    def test_the_text_shows_with_input_detail_and_follows_the_state(self, page: "Page", home_url: str):
        open_home(page, home_url, _signal_parts(rate_lock="locked", detected_khz="48 kHz"),
                  show_input_detail=True, wait_cards=False)
        stub.stream_on()
        expect(page.locator("#np-signal")).to_have_text("Locked \u00b7 48 kHz")
        wait_for(page, lambda: stub.open_streams() >= 1, "the stream")
        stub.push({"inputs": _signal_parts(rate_lock="mismatch", rate_mismatch_khz="44.1 kHz")["inputs"]})
        expect(page.locator("#np-signal")).to_have_text("Mismatch \u00b7 44.1 kHz")

    def test_no_text_without_input_detail(self, page: "Page", home_url: str):
        open_home(page, home_url, _signal_parts(rate_lock="locked", detected_khz="48 kHz"), wait_cards=False)
        page.wait_for_timeout(300)
        expect(page.locator("#np-signal")).to_have_text("")
