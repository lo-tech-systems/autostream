"""Playwright tests for three things the HD page does on a person's request:
the title shown while an appliance plays without naming the track, the replay
buttons held down until the appliance has answered, and the pull-down's
Shut down button with its confirmation.

Like the other page tests these run against the production HdServer over a
FakeCore and against the offline mock, and check what the page sends on the
wire. Without Playwright or its pytest plugin they skip.
"""
from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_hd_dial import (  # noqa: E402,F401  (fixtures shared with the page smoke tests)
    _PLAYWRIGHT_INSTALLED, Watcher, browser_context_args, hd_mock, hd_real,
)
from test_hd_page_main import (  # noqa: E402,F401
    Driver, SIZES, hd, open_page, scenario, watch_actions,
)
from test_hd_page_extras import (  # noqa: E402,F401
    PLAY, REWIND, STOP, modal_card, open_sheet, replay_button, replay_timer, watch_posts,
)

pytestmark = pytest.mark.skipif(not _PLAYWRIGHT_INSTALLED, reason="playwright not installed")

if _PLAYWRIGHT_INSTALLED:
    from playwright.sync_api import expect

import hd_scenarios as hs  # noqa: E402
from dial_core_state import NowPlaying, TransportRequest  # noqa: E402

LOUNGE, KITCHEN, NOW = hs.LOUNGE, hs.KITCHEN, hs.NOW


def size_id(size) -> str:
    return f"{size[0]}x{size[1]}"


def answer(page, name, body=None, status=200) -> list:
    """Answer the page's *name* action itself (so neither backend moves on to
    another state), and return the bodies it was sent."""
    seen: list = []

    def handler(route):
        seen.append(route.request.post_data_json)
        route.fulfill(status=status, content_type="application/json",
                      body=json.dumps(body if body is not None else {"ok": True}))

    page.route(f"**/api/v1/actions/{name}", handler)
    return seen


# ---------------------------------------------------------------------------
# The title while an appliance plays and has not named the track
# ---------------------------------------------------------------------------

def untitled(artist="", album=""):
    """The Lounge playing with no title yet, and what else it said."""
    return hs.SCENARIOS["playing_untitled"].with_snapshot(
        now_playing=NowPlaying("Lounge", artist, "", 42, album=album))


class TestUntitledTrack:
    def test_a_playing_appliance_with_no_title_reads_playing(self, page, hd):
        hd.show(hs.SCENARIOS["playing_untitled"])
        open_page(page, hd)
        expect(page.locator("#title")).to_have_text("Playing")
        expect(page.locator("#sub")).to_have_text("")

    def test_nothing_playing_still_says_so(self, page, hd):
        hd.show(hs.SCENARIOS["nothing_playing"])
        open_page(page, hd)
        expect(page.locator("#title")).to_have_text("Nothing playing")

    def test_an_idle_appliance_still_reads_nothing_playing(self, page, hd):
        idle = hs.SCENARIOS["playing_untitled"].with_snapshot(
            now_playing=NowPlaying("Lounge", "", "", 42, playing=False))
        hd.show(idle)
        open_page(page, hd)
        expect(page.locator("#title")).to_have_text("Nothing playing")

    def test_a_track_change_passes_through_playing_to_the_new_title(self, page, hd):
        hd.show(hs.SCENARIOS["playing_artwork"])
        open_page(page, hd)
        expect(page.locator("#title")).to_have_text("Tunnel of Love")
        hd.show(hs.SCENARIOS["playing_untitled"])
        expect(page.locator("#title")).to_have_text("Playing")
        hd.show(hs.SCENARIOS["playing_artwork"])
        expect(page.locator("#title")).to_have_text("Tunnel of Love")

    def test_what_the_appliance_did_say_stays_under_it(self, page, hd):
        hd.show(untitled(artist="Dire Straits", album="Making Movies"))
        open_page(page, hd)
        expect(page.locator("#title")).to_have_text("Playing")
        expect(page.locator("#sub")).to_have_text("Dire Straits · Making Movies")

    def test_a_real_title_is_never_replaced(self, page, hd):
        hd.show(hs.SCENARIOS["playing_no_artwork"])
        open_page(page, hd)
        expect(page.locator("#title")).to_have_text("Tunnel of Love")
        expect(page.locator("#sub")).to_have_text("Dire Straits · Making Movies")


# ---------------------------------------------------------------------------
# A replay button held down until the appliance has answered
# ---------------------------------------------------------------------------

def seek(state, *, requested=NOW + 1, changed=None, error=None, kind="seek"):
    """The dial's latest replay request, in *state*."""
    return TransportRequest(
        LOUNGE, kind, requested, state, requested if changed is None else changed, error)


def replay_state(title, *, transport, observed=NOW - 1.0, state="replaying", **repeat):
    """The Lounge's replay row in *state*, its record last reported at
    *observed* and the dial's latest request *transport*, under a title the
    test can wait for."""
    repeat = {"position": 40.0, "duration": 1100.0, "latency": 0.0, **repeat}
    if state == "hold":
        repeat = {"recording": 1122.0}
    base = hs.replay_scenario("held", state, **repeat)
    appliance = base.snapshot.appliances[0]
    record = dataclasses.replace(appliance.repeat, observed_at=observed)
    return base.with_snapshot(
        appliances=(dataclasses.replace(appliance, repeat=record),),
        transport=transport,
        now_playing=NowPlaying("Lounge", "Dire Straits", title, 42, playing=state != "hold"),
    )


# The request the page last saw before the press, as the corpus has it.
EARLIER = hs.SCENARIOS["replaying"].snapshot.transport

BUSY = "aria-busy"


def shown(page, hd, title, scenario):
    """Show *scenario* and wait until the page has drawn it."""
    hd.show(scenario)
    expect(page.locator("#title")).to_have_text(title)


def start_held(page, hd, *, answer_with=None, status=200):
    """Open the page on a running replay (the Lounge) and press Back to the
    start, the appliance's answer to the press itself held back."""
    seen = answer(page, "replay_restart", answer_with, status)
    hd.show(replay_state("T0", transport=EARLIER))
    open_page(page, hd)
    expect(page.locator("#title")).to_have_text("T0")
    expect(replay_button(page, REWIND)).to_have_attribute(BUSY, "false")
    replay_button(page, REWIND).click()
    return seen


class TestStartButtonHeld:
    def test_it_is_held_from_the_press_until_the_replay_starts_and_then_let_go(self, page, hd):
        seen = start_held(page, hd)
        rewind = replay_button(page, REWIND)
        # At once: nothing has come back yet.
        expect(rewind).to_have_attribute(BUSY, "true")
        assert seen == [{"appliance_id": LOUNGE}]
        # The dial has the request in hand.
        shown(page, hd, "T1", replay_state("T1", transport=seek("pending")))
        expect(rewind).to_have_attribute(BUSY, "true")
        # The appliance has accepted it, but its next report has not come.
        shown(page, hd, "T2", replay_state("T2", transport=seek("accepted", changed=NOW + 2)))
        expect(rewind).to_have_attribute(BUSY, "true")
        # The report: replaying from the start.
        shown(page, hd, "T3", replay_state(
            "T3", transport=seek("accepted", changed=NOW + 2), observed=NOW + 2.5, position=0.0))
        expect(rewind).to_have_attribute(BUSY, "false")
        expect(rewind).to_be_enabled()

    def test_it_stays_held_through_states_that_say_nothing_new(self, page, hd):
        start_held(page, hd)
        for n in range(1, 4):
            shown(page, hd, f"T{n}", replay_state(f"T{n}", transport=EARLIER))
            expect(replay_button(page, REWIND)).to_have_attribute(BUSY, "true")
        # A fresh report alone is not the answer to this press: the request has
        # not been seen yet.
        shown(page, hd, "T4", replay_state("T4", transport=EARLIER, observed=NOW + 9))
        expect(replay_button(page, REWIND)).to_have_attribute(BUSY, "true")

    def test_it_looks_pushed(self, page, hd):
        start_held(page, hd)
        rewind, stop = replay_button(page, REWIND), replay_button(page, STOP)
        expect(rewind).to_have_attribute(BUSY, "true")
        style = "e => { const s = getComputedStyle(e); return [s.backgroundColor, s.borderTopColor]; }"
        theme = page.evaluate(
            """() => {
                const s = getComputedStyle(document.documentElement);
                const probe = document.createElement('div');
                document.body.appendChild(probe);
                const read = (v) => { probe.style.color = s.getPropertyValue(v); return getComputedStyle(probe).color; };
                const out = [read('--color-surface-selected'), read('--color-accent')];
                probe.remove();
                return out;
            }""")
        assert rewind.evaluate(style) == theme
        assert stop.evaluate(style) != theme
        assert rewind.bounding_box()["width"] == stop.bounding_box()["width"]

    def test_a_second_press_while_held_sends_nothing(self, page, hd):
        seen = start_held(page, hd)
        replay_button(page, REWIND).click(force=True)
        replay_button(page, REWIND).click(force=True)
        page.wait_for_timeout(200)
        assert len(seen) == 1

    @pytest.mark.parametrize("after", [
        seek("rejected", error="unreachable", changed=NOW + 2),
        seek("pending", requested=NOW + 5, kind="stop"),
        seek("pending", requested=NOW + 5),
    ], ids=["rejected", "replaced by another kind", "replaced by another seek"])
    def test_it_is_let_go_by_the_state(self, page, hd, after):
        start_held(page, hd)
        shown(page, hd, "T1", replay_state("T1", transport=seek("pending")))
        expect(replay_button(page, REWIND)).to_have_attribute(BUSY, "true")
        shown(page, hd, "T2", replay_state("T2", transport=after))
        expect(replay_button(page, REWIND)).to_have_attribute(BUSY, "false")

    @pytest.mark.parametrize("state,kwargs", [("fading_out", {"position": 1099.0}), ("hold", {})])
    def test_it_is_let_go_when_the_appliance_stops(self, page, hd, state, kwargs):
        start_held(page, hd)
        shown(page, hd, "T1", replay_state("T1", transport=EARLIER, state=state, **kwargs))
        expect(page.locator("#replay-row button[aria-busy=true]")).to_have_count(0)
        # And it stays let go if the replay is later running again.
        shown(page, hd, "T2", replay_state("T2", transport=EARLIER))
        expect(replay_button(page, REWIND)).to_have_attribute(BUSY, "false")

    def test_it_is_let_go_when_the_focus_moves_to_another_appliance(self, page, hd):
        start_held(page, hd)
        shown(page, hd, "Blue", hs.SCENARIOS["replay_elsewhere"])
        expect(page.locator("#replay-row button")).to_have_count(0)
        shown(page, hd, "T1", replay_state("T1", transport=EARLIER))
        expect(replay_button(page, REWIND)).to_have_attribute(BUSY, "false")

    def test_it_is_let_go_when_the_reply_is_a_refusal(self, page, hd):
        start_held(page, hd, answer_with={"ok": False, "error": "wrong_state"}, status=409)
        expect(page.locator("#toast")).to_have_text("Not possible right now.")
        expect(replay_button(page, REWIND)).to_have_attribute(BUSY, "false")

    def test_it_is_let_go_when_the_reply_is_lost(self, page, hd):
        page.route("**/api/v1/actions/replay_restart", lambda route: route.abort())
        hd.show(replay_state("T0", transport=EARLIER))
        open_page(page, hd)
        expect(page.locator("#title")).to_have_text("T0")
        replay_button(page, REWIND).click()
        expect(page.locator("#toast")).to_have_text("No connection to the dial.")
        expect(replay_button(page, REWIND)).to_have_attribute(BUSY, "false")

    def test_pressing_stop_lets_it_go(self, page, hd):
        answer(page, "replay_stop")
        start_held(page, hd)
        expect(replay_button(page, REWIND)).to_have_attribute(BUSY, "true")
        replay_button(page, STOP).click()
        expect(replay_button(page, REWIND)).to_have_attribute(BUSY, "false")

    def test_play_from_a_held_recording_is_held_too(self, page, hd):
        seen = answer(page, "replay_start")
        hd.show(replay_state("T0", transport=EARLIER, state="hold"))
        open_page(page, hd)
        expect(page.locator("#title")).to_have_text("T0")
        replay_button(page, PLAY).click()
        expect(replay_button(page, PLAY)).to_have_attribute(BUSY, "true")
        assert seen == [{"appliance_id": LOUNGE}]
        shown(page, hd, "T1", replay_state("T1", transport=seek("pending"), state="hold"))
        expect(replay_button(page, PLAY)).to_have_attribute(BUSY, "true")
        shown(page, hd, "T2", replay_state(
            "T2", transport=seek("accepted", changed=NOW + 2), observed=NOW + 2.5, position=0.0))
        expect(page.locator("#replay-row button[aria-busy=true]")).to_have_count(0)
        expect(replay_button(page, REWIND)).to_be_enabled()
        assert replay_button(page, PLAY).count() == 0

    def test_the_timer_still_runs_behind_by_the_start_buffer(self, page, hd):
        start_held(page, hd)
        shown(page, hd, "T1", replay_state("T1", transport=seek("pending"), latency=2.0))
        expect(replay_timer(page)).to_have_text("0:39 / 18:20")


# ---------------------------------------------------------------------------
# The pull-down's Shut down button
# ---------------------------------------------------------------------------

def overlap(a, b) -> bool:
    return (a["x"] < b["x"] + b["width"] and b["x"] < a["x"] + a["width"]
            and a["y"] < b["y"] + b["height"] and b["y"] < a["y"] + a["height"])


SHUT_DOWN = "#card-buttons button"


class TestPowerButton:
    @pytest.mark.parametrize("size", SIZES, ids=size_id)
    def test_it_sits_at_the_top_right_of_the_pull_down_and_disturbs_nothing(self, page, hd_mock, size):
        hd = Driver("mock", hd_mock)
        open_page(page, hd, size)
        open_sheet(page)
        sheet = page.locator("#sheet").bounding_box()
        power = page.locator("#power").bounding_box()
        assert power["y"] - sheet["y"] <= 16
        assert sheet["x"] + sheet["width"] - (power["x"] + power["width"]) <= 24
        assert power["x"] + power["width"] <= size[0]
        # At least as large as the page's other icon buttons.
        mute = page.locator("#mute").bounding_box()
        assert power["width"] >= mute["width"] and power["height"] >= mute["height"]
        assert power["width"] >= 55 and power["height"] >= 55
        # Over none of the sheet's content (a heading is its text, not its row).
        content = page.evaluate(
            """() => {
                const box = (r) => ({x: r.x, y: r.y, width: r.width, height: r.height});
                const text = (n) => { const range = document.createRange(); range.selectNodeContents(n);
                    return box(range.getBoundingClientRect()); };
                const sheet = document.getElementById('sheet');
                return Array.from(sheet.querySelectorAll('h2')).map(text).concat(
                    Array.from(sheet.querySelectorAll('.setting, .setting-row, .info-row, .seg button'))
                        .map((n) => box(n.getBoundingClientRect())));
            }""")
        assert content and not [box for box in content if overlap(box, power)]
        assert page.evaluate(
            "[document.documentElement.scrollWidth, document.documentElement.scrollHeight]") == list(size)
        hd.cleanup()

    def test_it_carries_the_standard_power_icon_and_a_label(self, page, hd):
        open_page(page, hd)
        open_sheet(page)
        button = page.locator("#power")
        expect(button).to_have_attribute("aria-label", "Shut down")
        assert button.locator("svg").count() == 1
        assert button.locator("svg path").count() == 2

    def test_the_other_settings_are_still_there(self, page, hd):
        open_page(page, hd)
        open_sheet(page)
        for selector in ("#sleep-now", "#sleep-after", "#brightness", "#info"):
            expect(page.locator(selector)).to_be_visible()

    def test_pressing_it_asks_first_and_sends_nothing(self, page, hd):
        sent = watch_actions(page)
        open_page(page, hd)
        open_sheet(page)
        page.locator("#power").click()
        expect(modal_card(page)).to_be_visible()
        expect(page.locator("#card-title")).to_have_text("Shut down?")
        assert page.locator("#card-message").inner_text().strip()
        assert [b.inner_text() for b in page.locator(SHUT_DOWN).all()] == ["Cancel", "Shut down"]
        page.wait_for_timeout(200)
        assert sent == []

    def test_cancel_closes_the_card_and_sends_nothing(self, page, hd):
        sent = watch_actions(page)
        open_page(page, hd)
        open_sheet(page)
        page.locator("#power").click()
        page.locator(SHUT_DOWN, has_text="Cancel").click()
        expect(modal_card(page)).to_be_hidden()
        expect(page.locator("#sheet")).to_be_visible()
        expect(page.locator("#power")).to_be_enabled()
        page.wait_for_timeout(200)
        assert sent == []

    def test_the_dimmed_area_cancels_it_too(self, page, hd):
        sent = watch_actions(page)
        open_page(page, hd)
        open_sheet(page)
        page.locator("#power").click()
        page.mouse.click(5, 5)
        expect(modal_card(page)).to_be_hidden()
        page.wait_for_timeout(200)
        assert sent == []

    def test_confirming_sends_exactly_one_shutdown_and_shows_the_wait(self, page, hd):
        seen = answer(page, "dial_shutdown")
        open_page(page, hd)
        open_sheet(page)
        page.locator("#power").click()
        page.locator(SHUT_DOWN, has_text="Shut down").click()
        expect(page.locator("#card-title")).to_have_text("Shutting down...")
        expect(page.locator(SHUT_DOWN)).to_have_count(0)
        expect(page.locator("#sheet")).to_be_hidden()
        # Nothing on the page can ask for it again, or dismiss the wait.
        page.mouse.click(5, 5)
        page.wait_for_timeout(300)
        expect(page.locator("#card-title")).to_have_text("Shutting down...")
        assert seen == [{}]

    def test_the_request_reaches_the_dial_as_the_shutdown_action(self, page, hd):
        sent = watch_actions(page)
        open_page(page, hd)
        open_sheet(page)
        page.locator("#power").click()
        page.locator(SHUT_DOWN, has_text="Shut down").click()
        expect(page.locator("#card-title")).to_have_text("Shutting down...")
        page.wait_for_timeout(300)
        assert sent == [("dial_shutdown", {})]
        if hd.kind == "real":
            assert ("request_dial_shutdown", (), {}) in hd.backend.core.calls

    @pytest.mark.parametrize("status,body,toast", [
        (403, {"ok": False, "error": "local_only"}, "That can only be done on the dial's own screen."),
        (409, {"ok": False, "error": "wrong_state"}, "Not possible right now."),
    ], ids=["refused off the dial's own screen", "refused as not possible"])
    def test_a_refusal_ends_the_wait_and_says_so(self, page, hd, status, body, toast):
        answer(page, "dial_shutdown", body, status)
        open_page(page, hd)
        open_sheet(page)
        page.locator("#power").click()
        page.locator(SHUT_DOWN, has_text="Shut down").click()
        expect(page.locator("#toast")).to_have_text(toast)
        expect(modal_card(page)).to_be_hidden()
        open_sheet(page)
        expect(page.locator("#power")).to_be_enabled()

    def test_a_lost_reply_ends_the_wait(self, page, hd):
        page.route("**/api/v1/actions/dial_shutdown", lambda route: route.abort())
        open_page(page, hd)
        open_sheet(page)
        page.locator("#power").click()
        page.locator(SHUT_DOWN, has_text="Shut down").click()
        expect(page.locator("#toast")).to_have_text("No connection to the dial.")
        expect(modal_card(page)).to_be_hidden()

    @pytest.mark.parametrize("size", SIZES, ids=size_id)
    def test_the_card_fits_the_screen(self, page, hd_mock, size):
        hd = Driver("mock", hd_mock)
        open_page(page, hd, size)
        open_sheet(page)
        page.locator("#power").click()
        box = page.locator("#card").bounding_box()
        assert box["x"] >= 0 and box["y"] >= 0
        assert box["x"] + box["width"] <= size[0] and box["y"] + box["height"] <= size[1]
        for button in page.locator(SHUT_DOWN).all():
            assert button.bounding_box()["height"] >= 44
        hd.cleanup()
