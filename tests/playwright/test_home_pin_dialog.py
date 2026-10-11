"""Playwright tests: the Home page PIN dialog pairs and enables in one request.

The page comes from the real Home renderer; the outputs poll and the output
POST are stubbed. Every PIN attempt is one POST carrying the PIN and
selected:true. A wrong PIN shows a note and asks again, a rate-limited reply
shows a counting-down wait with the input disabled, and the poll-driven
prompt leaves a row claimed by a dial alone.
"""
from __future__ import annotations

import pytest
from _home_stub import (
    OUTPUTS as _OUTPUTS,
    POLLS as _POLLS,
    POSTS as _POSTS,
    REPLIES as _REPLIES,
    STATUS as _STATUS,
    render_home,
    start_server,
)

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


def _row(**extra) -> dict:
    row = {"id": "tv", "name": "Lounge TV", "selected": False, "volume": 20,
           "pin_pending": False}
    row.update(extra)
    return row


@pytest.fixture(scope="module")
def home_url():
    server, url = start_server(render_home())
    try:
        yield url
    finally:
        server.shutdown()


def _open_home(page: "Page", base: str, outputs: list, replies: list, *, cards: bool = True) -> None:
    _OUTPUTS[:] = outputs
    _REPLIES[:] = replies
    _POSTS.clear()
    _POLLS.clear()
    page.goto(f"{base}/")
    if cards:
        page.wait_for_selector("#output_enabled_tv", state="attached")


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
        _open_home(page, home_url, [_row()],
                   [{"ok": False, "pin_required": True}, {"ok": True}])
        _toggle_on(page)
        expect(page.locator("#pinModal")).to_have_class("modal-overlay show")
        assert len(_POSTS) == 1
        assert "op" not in _POSTS[0]
        _type_pin(page, "2718")
        page.locator("#pinModalOk").click()
        expect(page.locator("#pinModal")).not_to_have_class("modal-overlay show")
        expect(page.locator("#output_enabled_tv")).to_be_checked()
        assert len(_POSTS) == 2
        second = _POSTS[1]
        assert second["id"] == "tv"
        assert second["op"] == "pin"
        assert second["pin"] == "2718"
        assert second["selected"] is True
        assert second["volume"] == 20
        page.wait_for_timeout(300)
        assert len(_POSTS) == 2

    def test_a_wrong_pin_re_prompts_with_the_note(self, page: "Page", home_url: str):
        _open_home(page, home_url, [_row()],
                   [{"ok": False, "pin_required": True},
                    {"ok": False, "pin_invalid": True},
                    {"ok": True}])
        _toggle_on(page)
        _type_pin(page, "1111")
        page.locator("#pinModalOk").click()
        note = page.locator("#pinModalNote")
        expect(note).to_have_text("That PIN was not accepted. Try again.")
        expect(page.locator("#pinModalInput")).to_have_value("")
        expect(page.locator("#pinModalOk")).to_be_disabled()
        _type_pin(page, "2718")
        page.locator("#pinModalOk").click()
        expect(page.locator("#output_enabled_tv")).to_be_checked()
        assert [p.get("pin") for p in _POSTS[1:]] == ["1111", "2718"]

    def test_a_rate_limited_reply_shows_the_wait_and_counts_down(
        self, page: "Page", home_url: str
    ):
        page.clock.install()
        _open_home(page, home_url, [_row()],
                   [{"ok": False, "pin_required": True},
                    {"ok": False, "error": "rate_limited", "retry_after_s": 3},
                    {"ok": True}])
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
        assert len(_POSTS) == 2
        page.clock.run_for(1000)
        expect(note).to_be_hidden()
        expect(page.locator("#pinModalInput")).to_be_enabled()
        expect(page.locator("#pinModalOk")).to_be_disabled()
        _type_pin(page, "2718")
        page.locator("#pinModalOk").click()
        expect(page.locator("#output_enabled_tv")).to_be_checked()
        assert len(_POSTS) == 3
        assert _POSTS[2]["pin"] == "2718"

    def test_ok_stays_disabled_under_four_digits_and_letters_are_refused(
        self, page: "Page", home_url: str
    ):
        _open_home(page, home_url, [_row()], [{"ok": False, "pin_required": True}])
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
        _open_home(page, home_url, [_row()],
                   [{"ok": False, "pin_required": True},
                    {"ok": False, "error": "rate_limited", "retry_after_s": 5}])
        _pause_clock(page)
        _toggle_on(page)
        _type_pin(page, "1111")
        page.locator("#pinModalOk").click()
        expect(page.locator("#pinModalNote")).to_have_text("Wait 5 seconds before retry")
        page.locator("#pinModalCancel").click()
        expect(page.locator("#pinModal")).not_to_have_class("modal-overlay show")
        expect(page.locator("#output_enabled_tv")).not_to_be_checked()
        page.clock.run_for(10000)
        expect(page.locator("#pinModal")).not_to_have_class("modal-overlay show")
        assert len(_POSTS) == 2

    def test_the_poll_prompt_skips_a_row_claimed_by_a_dial(self, page: "Page", home_url: str):
        _open_home(page, home_url, [_row(pin_pending=True, pin_claim="dial:x")], [])
        start = len(_POLLS)
        deadline_polls = start + 2
        for _ in range(60):
            if len(_POLLS) >= deadline_polls:
                break
            page.wait_for_timeout(100)
        assert len(_POLLS) >= deadline_polls
        expect(page.locator("#pinModal")).not_to_have_class("modal-overlay show")
        assert _POSTS == []

    def test_the_poll_prompt_opens_for_an_unclaimed_row(self, page: "Page", home_url: str):
        # The open prompt holds back the card render, so there is no card to wait for.
        _open_home(page, home_url, [_row(pin_pending=True, pin_claim="")], [], cards=False)
        expect(page.locator("#pinModal")).to_have_class("modal-overlay show")


def _input_snapshot(input_type: str, label: str) -> dict:
    return {"is_turntable": input_type == "turntable", "is_bluetooth": False,
            "input_type": input_type, "type_label": label}


@_requires_browser
class TestHomeNowPlayingCard:
    def test_the_card_reads_the_snapshot_of_the_levels_own_input_number(
        self, page: "Page", home_url: str
    ):
        _STATUS.update({
            "ok": True,
            "input_levels": [{"index": 2, "label": "Input 2", "dbfs": -30.0,
                              "detected_hz": 0, "is_above_threshold": True}],
            "playback": {"inputs": {"1": _input_snapshot("turntable", "Turntable"),
                                    "2": _input_snapshot("cd", "CD")}},
            "track_identification": {"enabled": False},
            "session": {"active": True, "source": "live"},
        })
        try:
            _open_home(page, home_url, [], [], cards=False)
            expect(page.locator("#np-name")).to_have_text("Input 2 · CD")
            expect(page.locator("#np-icon")).to_have_attribute("data-np-icon-key", "svg:cd")
        finally:
            _STATUS.clear()
