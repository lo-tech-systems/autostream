"""Playwright tests for the HD page's main layout: the appliance list, the
speakers, now playing, the master volume row, optimistic controls and the
event stream client.

Each test runs against the production HdServer over a FakeCore and against
the offline mock server (the two share the scenario corpus and the
serialiser). What the page sends is checked on the wire, so the assertions
hold for both. Without Playwright or its pytest plugin the tests skip.

Set HD_SHOTS_DIR to a directory to have test_screenshots write the review
screenshots there (it does nothing otherwise).
"""
from __future__ import annotations

import dataclasses
import json
import re
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_hd_dial import (  # noqa: E402,F401  (fixtures shared with the page smoke tests)
    _PLAYWRIGHT_INSTALLED, Watcher, browser_context_args, hd_mock, hd_real,
)

pytestmark = pytest.mark.skipif(not _PLAYWRIGHT_INSTALLED, reason="playwright not installed")

if _PLAYWRIGHT_INSTALLED:
    from playwright.sync_api import expect

import hd_scenarios as hs  # noqa: E402
from dial_core_state import NowPlaying, OutputRow, OutputsState  # noqa: E402

LOUNGE, KITCHEN = hs.LOUNGE, hs.KITCHEN
SIZES = [(800, 480), (1024, 600), (1280, 800)]


# ---------------------------------------------------------------------------
# A server-neutral handle on the two backends
# ---------------------------------------------------------------------------

class Driver:
    def __init__(self, kind, backend) -> None:
        self.kind = kind
        self.backend = backend
        self.url = backend.url
        self._count = 0
        self._temp: list = []

    def show(self, scenario) -> None:
        """Make *scenario* the state the dial reports now."""
        if self.kind == "real":
            self.backend.muted[0] = scenario.muted
            self.backend.core.publish(snapshot=scenario.snapshot)
        else:
            self._count += 1
            name = f"_page_test_{self._count}"
            hs.SCENARIOS[name] = scenario
            self._temp.append(name)
            self.backend.set_scenario(name)

    def cleanup(self) -> None:
        for name in self._temp:
            hs.SCENARIOS.pop(name, None)
        self._temp.clear()


@pytest.fixture(params=["real", "mock"])
def hd(request):
    backend = request.getfixturevalue("hd_real" if request.param == "real" else "hd_mock")
    driver = Driver(request.param, backend)
    driver.show(hs.SCENARIOS["playing_artwork"])
    yield driver
    driver.cleanup()


def scenario(name, **snapshot_changes):
    base = hs.SCENARIOS[name]
    return base.with_snapshot(**snapshot_changes) if snapshot_changes else base


def watch_actions(page) -> list:
    """Every action the page POSTs from now on, as (name, body)."""
    sent: list = []

    def seen(request) -> None:
        if request.method == "POST" and "/api/v1/actions/" in request.url:
            sent.append((request.url.rsplit("/", 1)[1], request.post_data_json))

    page.on("request", seen)
    return sent


def open_page(page, hd, size=(800, 480)):
    page.set_viewport_size({"width": size[0], "height": size[1]})
    page.goto(hd.url + "/")
    expect(page.locator("#title")).not_to_have_text("")
    return page


def rows(page):
    return page.locator("#appliances .appliance")


def cards(page):
    return page.locator("#speakers .output-card")


def card(page, name):
    return cards(page).filter(has=page.locator(".output-card-name", has_text=name))


def drag_input(page, selector, values, final=None):
    """Fire input events for *values* in one go, then a change for *final*."""
    page.evaluate(
        """([selector, values, final]) => {
            const s = document.querySelector(selector);
            for (const v of values) { s.value = v; s.dispatchEvent(new Event('input', {bubbles: true})); }
            if (final !== null) { s.value = final; s.dispatchEvent(new Event('change', {bubbles: true})); }
        }""",
        [selector, list(values), final],
    )


def outputs_with(*rows_):
    return OutputsState(LOUNGE, tuple(rows_), True, hs.NOW - 1, None)


# ---------------------------------------------------------------------------
# Journey states
# ---------------------------------------------------------------------------

class TestStates:
    def test_playing_with_artwork(self, page, hd):
        watcher = Watcher(page)
        open_page(page, hd)
        expect(page.locator("#title")).to_have_text("Tunnel of Love")
        expect(page.locator("#sub")).to_have_text("Dire Straits · Making Movies")
        art = page.locator("#art")
        expect(art).to_have_attribute("src", re.compile(r"^/api/v1/artwork/[0-9a-f]{16}$"))
        expect(art).not_to_have_class(re.compile("logo"))
        page.wait_for_function("document.getElementById('art').complete")
        assert page.evaluate("document.getElementById('art').naturalWidth") == 1
        assert rows(page).count() == 1
        expect(rows(page).first.locator(".state")).to_have_text("Playing")
        expect(rows(page).first).to_have_attribute("aria-current", "true")
        expect(page.locator("#speakers-label")).to_have_text("Speakers on Lounge")
        assert cards(page).count() == 3
        assert watcher.errors == []
        assert page.evaluate("window.__csp || []") == []

    def test_artwork_sits_in_an_outlined_frame_capped_in_height(self, page, hd):
        open_page(page, hd)
        frame = page.locator(".art-frame")
        box = frame.bounding_box()
        assert box["height"] <= 480 * 0.54 + 1
        assert abs(box["width"] - box["height"]) <= 1
        assert page.evaluate("getComputedStyle(document.querySelector('.art-frame')).borderTopWidth") == "1px"

    def test_nothing_playing_shows_the_logo(self, page, hd):
        hd.show(hs.SCENARIOS["nothing_playing"])
        open_page(page, hd)
        expect(page.locator("#title")).to_have_text("Nothing playing")
        expect(page.locator("#sub")).to_have_text("")
        expect(page.locator("#art")).to_have_attribute("src", "/static/logo.png")
        expect(page.locator("#art")).to_have_class(re.compile("logo"))
        expect(rows(page).first.locator(".state")).to_have_text("Idle")
        expect(page.locator("#master")).to_be_disabled()
        expect(page.locator("#mute")).to_be_disabled()
        expect(page.locator("#master-num")).to_have_text("--")
        assert cards(page).count() == 0
        expect(page.locator("#eq-open")).to_be_hidden()

    def test_starting(self, page, hd):
        hd.show(hs.SCENARIOS["starting"])
        open_page(page, hd)
        expect(page.locator("#title")).to_have_text("Starting...")
        assert rows(page).count() == 0

    def test_title_only(self, page, hd):
        hd.show(scenario("playing_no_artwork", now_playing=NowPlaying("Lounge", "", "Tunnel of Love", 42)))
        open_page(page, hd)
        expect(page.locator("#title")).to_have_text("Tunnel of Love")
        expect(page.locator("#sub")).to_have_text("")
        expect(page.locator("#art")).to_have_attribute("src", "/static/logo.png")

    def test_equaliser_icon_follows_the_capability(self, page, hd):
        open_page(page, hd)
        expect(page.locator("#eq-open")).to_be_visible()
        hd.show(hs.SCENARIOS["eq_none"])
        expect(page.locator("#eq-open")).to_be_hidden()

    def test_not_authorised_row(self, page, hd):
        hd.show(hs.SCENARIOS["unauthorized"])
        sent = watch_actions(page)
        open_page(page, hd)
        row = rows(page).filter(has_text="Kitchen")
        expect(row.locator(".state")).to_have_text("Not authorised")
        row.click()
        expect(page.locator("#toast")).to_have_text(
            "Allow this dial in Kitchen's web UI (Setup, Dials): http://192.0.2.20:80/")
        page.wait_for_timeout(200)
        assert sent == []

    def test_not_responding_disables_the_controls(self, page, hd):
        hd.show(hs.SCENARIOS["unreachable"])
        open_page(page, hd)
        expect(rows(page).first.locator(".state")).to_have_text("Not responding")
        expect(page.locator("#master")).to_be_disabled()
        expect(page.locator("#mute")).to_be_disabled()
        assert cards(page).count() == 3
        for i in range(3):
            expect(cards(page).nth(i).locator("input[type=checkbox]")).to_be_disabled()

    def test_in_use_speaker_is_dimmed_and_locked(self, page, hd):
        hd.show(hs.SCENARIOS["in_use_speaker"])
        sent = watch_actions(page)
        open_page(page, hd)
        bedroom = card(page, "Bedroom")
        expect(bedroom).to_have_class(re.compile("output-card-in-use"))
        expect(bedroom.locator(".output-state-chip")).to_have_text("In Use by Kitchen")
        expect(bedroom.locator("input[type=checkbox]")).to_be_disabled()
        expect(bedroom.locator(".level-row")).to_be_hidden()
        assert page.evaluate(
            "getComputedStyle(document.querySelector('.output-card-in-use')).opacity") == "0.7"
        bedroom.click(force=True)
        page.wait_for_timeout(150)
        assert sent == []

    def test_held_recording_badge(self, page, hd):
        hd.show(hs.SCENARIOS["replay_hold"])
        open_page(page, hd)
        expect(rows(page).first.locator(".badge")).to_have_text("Replay 18:42")

    def test_replay_row_slot_sits_below_the_artwork(self, page, hd):
        open_page(page, hd)
        slot = page.locator("#replay-row")
        assert slot.count() == 1
        order = page.evaluate(
            "[...document.querySelectorAll('#right > *')].map(e => e.className.split(' ')[0])")
        assert order == ["art-frame", "replay-row", "track-row", "volume-row"]

    def test_markup_in_appliance_text_stays_text(self, page, hd):
        evil = "<img src=x onerror=alert(1)>"
        outputs = outputs_with(OutputRow("o1", evil, True, 45))
        playing = scenario("playing_artwork")
        appliances = tuple(dataclasses.replace(a, name=evil) for a in playing.snapshot.appliances)
        hd.show(playing.with_snapshot(
            appliances=appliances, outputs=outputs,
            now_playing=NowPlaying("Lounge", evil, evil, 42, album=evil)))
        open_page(page, hd)
        expect(page.locator("#title")).to_have_text(evil)
        expect(rows(page).first.locator(".name")).to_have_text(evil)
        expect(card(page, "onerror").locator(".output-card-name")).to_have_text(evil)
        assert page.locator("#app img").count() == 1
        assert page.locator("#app [onerror]").count() == 0


# ---------------------------------------------------------------------------
# Actions, optimistic values
# ---------------------------------------------------------------------------

class TestFocus:
    def test_tap_sends_focus_and_moves_the_highlight(self, page, hd):
        hd.show(hs.SCENARIOS["replay_elsewhere"])
        sent = watch_actions(page)
        open_page(page, hd)
        kitchen, lounge = rows(page).nth(0), rows(page).nth(1)
        expect(kitchen).to_have_attribute("aria-current", "true")
        lounge.click()
        expect(lounge).to_have_attribute("aria-current", "true")
        expect(kitchen).to_have_attribute("aria-current", "false")
        assert sent == [("focus", {"appliance_id": LOUNGE})]

    def test_tapping_the_current_appliance_sends_nothing(self, page, hd):
        sent = watch_actions(page)
        open_page(page, hd)
        rows(page).first.click()
        page.wait_for_timeout(200)
        assert sent == []

    def test_highlight_returns_when_the_state_never_follows(self, page, hd):
        hd.show(hs.SCENARIOS["replay_elsewhere"])
        page.clock.install()
        open_page(page, hd)
        rows(page).nth(1).click()
        expect(rows(page).nth(1)).to_have_attribute("aria-current", "true")
        page.clock.run_for(2500)
        expect(rows(page).nth(0)).to_have_attribute("aria-current", "true")

    def test_refused_focus_toasts_and_rolls_back(self, page, hd):
        hd.show(hs.SCENARIOS["replay_elsewhere"])
        page.route("**/api/v1/actions/focus", lambda route: route.fulfill(
            status=409, content_type="application/json",
            body=json.dumps({"ok": False, "error": "not_focused"})))
        open_page(page, hd)
        rows(page).nth(1).click()
        expect(page.locator("#toast")).to_have_text("Select that appliance first.")
        expect(rows(page).nth(0)).to_have_attribute("aria-current", "true")

    def test_state_change_moves_the_highlight(self, page, hd):
        hd.show(hs.SCENARIOS["replay_elsewhere"])
        open_page(page, hd)
        expect(rows(page).nth(0)).to_have_attribute("aria-current", "true")
        hd.show(hs.SCENARIOS["replay_elsewhere"].with_snapshot(
            focus=dataclasses.replace(
                hs.SCENARIOS["replay_elsewhere"].snapshot.focus, reporting_id=LOUNGE)))
        expect(rows(page).nth(1)).to_have_attribute("aria-current", "true")


class TestVolume:
    def test_drag_cadence_and_final_value(self, page, hd):
        sent = watch_actions(page)
        open_page(page, hd)
        drag_input(page, "#master", range(50, 60))
        page.wait_for_timeout(350)
        assert sent == [("volume_set", {"appliance_id": LOUNGE, "level": 50}),
                        ("volume_set", {"appliance_id": LOUNGE, "level": 59})]
        drag_input(page, "#master", [], final=60)
        page.wait_for_timeout(100)
        assert sent[-1] == ("volume_set", {"appliance_id": LOUNGE, "level": 60})
        assert len(sent) == 3

    def test_number_follows_the_thumb_at_once(self, page, hd):
        open_page(page, hd)
        drag_input(page, "#master", [64])
        expect(page.locator("#master-num")).to_have_text("64")

    def test_real_drag_ends_near_the_target(self, page, hd):
        sent = watch_actions(page)
        open_page(page, hd)
        box = page.locator("#master").bounding_box()
        y = box["y"] + box["height"] / 2
        page.mouse.move(box["x"] + box["width"] * 0.2, y)
        page.mouse.down()
        for fraction in (0.3, 0.4, 0.5, 0.6, 0.7):
            page.mouse.move(box["x"] + box["width"] * fraction, y, steps=4)
        page.mouse.up()
        page.wait_for_timeout(300)
        levels = [body["level"] for name, body in sent if name == "volume_set"]
        assert levels and abs(levels[-1] - 70) <= 6
        assert len(levels) <= 14

    def test_confirmed_by_the_state_it_stays(self, page, hd):
        page.clock.install()
        open_page(page, hd)
        drag_input(page, "#master", [], final=77)
        hd.show(scenario("playing_artwork", volume_readout=("Lounge", 77)))
        page.wait_for_function("fetch('/api/v1/state').then(r => r.json()).then(s => s.volume.level === 77)")
        page.wait_for_timeout(300)
        page.clock.run_for(2500)
        expect(page.locator("#master-num")).to_have_text("77")

    def test_unconfirmed_it_rolls_back(self, page, hd):
        page.clock.install()
        open_page(page, hd)
        drag_input(page, "#master", [], final=77)
        expect(page.locator("#master-num")).to_have_text("77")
        page.clock.run_for(2500)
        expect(page.locator("#master-num")).to_have_text("42")
        assert page.evaluate("document.getElementById('master').value") == "42"

    def test_refusal_rolls_back_and_toasts(self, page, hd):
        page.route("**/api/v1/actions/volume_set", lambda route: route.fulfill(
            status=409, content_type="application/json",
            body=json.dumps({"ok": False, "error": "wrong_state"})))
        open_page(page, hd)
        drag_input(page, "#master", [], final=88)
        expect(page.locator("#toast")).to_have_text("Not possible right now.")
        expect(page.locator("#master-num")).to_have_text("42")


class TestMute:
    def test_click_sends_and_shows_muted_at_once(self, page, hd):
        sent = watch_actions(page)
        open_page(page, hd)
        mute = page.locator("#mute")
        expect(mute).to_have_attribute("aria-pressed", "false")
        mute.click()
        expect(mute).to_have_attribute("aria-pressed", "true")
        expect(page.locator("#volume-row")).to_have_class(re.compile("muted"))
        assert sent == [("mute_toggle", {"appliance_id": LOUNGE})]

    def test_confirmed_by_the_state_it_stays(self, page, hd):
        page.clock.install()
        open_page(page, hd)
        page.locator("#mute").click()
        hd.show(dataclasses.replace(hs.SCENARIOS["playing_artwork"], muted=True))
        page.wait_for_function("fetch('/api/v1/state').then(r => r.json()).then(s => s.volume.muted === true)")
        page.wait_for_timeout(300)
        page.clock.run_for(2500)
        expect(page.locator("#mute")).to_have_attribute("aria-pressed", "true")

    def test_unconfirmed_it_rolls_back(self, page, hd):
        page.clock.install()
        open_page(page, hd)
        page.locator("#mute").click()
        expect(page.locator("#mute")).to_have_attribute("aria-pressed", "true")
        page.clock.run_for(2500)
        expect(page.locator("#mute")).to_have_attribute("aria-pressed", "false")

    def test_muted_state_is_shown(self, page, hd):
        hd.show(dataclasses.replace(hs.SCENARIOS["playing_artwork"], muted=True))
        open_page(page, hd)
        expect(page.locator("#mute")).to_have_attribute("aria-pressed", "true")
        expect(page.locator("#mute")).to_have_attribute("aria-label", "Unmute")


class TestSpeakers:
    def test_cards_show_state_and_levels(self, page, hd):
        open_page(page, hd)
        lounge = card(page, "Lounge L + R")
        expect(lounge.locator("input[type=checkbox]")).to_be_checked()
        expect(lounge.locator(".level-row")).to_be_visible()
        expect(lounge.locator(".level-num")).to_have_text("45")
        patio = card(page, "Patio")
        expect(patio.locator("input[type=checkbox]")).not_to_be_checked()
        expect(patio.locator(".level-row")).to_be_hidden()

    def test_toggle_sends_output_and_shows_the_slider(self, page, hd):
        sent = watch_actions(page)
        open_page(page, hd)
        patio = card(page, "Patio")
        patio.locator(".output-toggle").click()
        expect(patio.locator(".level-row")).to_be_visible()
        expect(patio.locator(".level-num")).to_have_text("30")
        assert sent == [("output", {"appliance_id": LOUNGE, "output_id": "o2", "selected": True})]

    def test_toggle_confirmed_by_the_state(self, page, hd):
        page.clock.install()
        open_page(page, hd)
        card(page, "Patio").locator(".output-toggle").click()
        hd.show(scenario("playing_artwork", outputs=outputs_with(
            OutputRow("o1", "Lounge L + R", True, 45), OutputRow("o2", "Patio", True, 30),
            OutputRow("o3", "Bedroom", False, 20))))
        page.wait_for_timeout(300)
        page.clock.run_for(2500)
        expect(card(page, "Patio").locator("input[type=checkbox]")).to_be_checked()

    def test_toggle_unconfirmed_rolls_back(self, page, hd):
        page.clock.install()
        open_page(page, hd)
        card(page, "Patio").locator(".output-toggle").click()
        expect(card(page, "Patio").locator("input[type=checkbox]")).to_be_checked()
        page.clock.run_for(2500)
        expect(card(page, "Patio").locator("input[type=checkbox]")).not_to_be_checked()

    def test_refused_toggle_rolls_back_at_once(self, page, hd):
        page.route("**/api/v1/actions/output", lambda route: route.fulfill(
            status=409, content_type="application/json",
            body=json.dumps({"ok": False, "error": "wrong_state"})))
        open_page(page, hd)
        card(page, "Patio").locator(".output-toggle").click()
        expect(page.locator("#toast")).to_have_text("Not possible right now.")
        expect(card(page, "Patio").locator("input[type=checkbox]")).not_to_be_checked()

    def test_level_slider_sends_the_output_volume(self, page, hd):
        sent = watch_actions(page)
        open_page(page, hd)
        drag_input(page, "#speakers .output-card-on input[type=range]", [], final=55)
        expect(card(page, "Lounge L + R").locator(".level-num")).to_have_text("55")
        assert sent == [("output", {"appliance_id": LOUNGE, "output_id": "o1", "volume": 55})]

    def test_state_update_leaves_a_dragged_slider_alone(self, page, hd):
        open_page(page, hd)
        box = page.locator("#speakers .output-card-on input[type=range]").bounding_box()
        page.mouse.move(box["x"] + box["width"] * 0.45, box["y"] + box["height"] / 2)
        page.mouse.down()
        page.mouse.move(box["x"] + box["width"] * 0.8, box["y"] + box["height"] / 2, steps=3)
        before = page.evaluate("document.querySelector('#speakers .output-card-on input[type=range]').value")
        hd.show(scenario("playing_artwork"))
        page.wait_for_timeout(300)
        after = page.evaluate("document.querySelector('#speakers .output-card-on input[type=range]').value")
        page.mouse.up()
        assert before == after


# ---------------------------------------------------------------------------
# The event stream
# ---------------------------------------------------------------------------

class TestStream:
    def test_a_new_state_is_drawn(self, page, hd):
        open_page(page, hd)
        hd.show(hs.SCENARIOS["nothing_playing"])
        expect(page.locator("#title")).to_have_text("Nothing playing")
        hd.show(hs.SCENARIOS["playing_artwork"])
        expect(page.locator("#title")).to_have_text("Tunnel of Love")

    def test_reconnects_with_last_event_id(self, page, hd_mock):
        hd = Driver("mock", hd_mock)
        hd.show(hs.SCENARIOS["playing_artwork"])
        requests: list = []
        page.on("request", lambda r: requests.append(r) if "/api/v1/events" in r.url else None)
        open_page(page, hd)
        seq = page.evaluate("fetch('/api/v1/state').then(r => r.json()).then(s => s.seq)")
        hd_mock.cut_streams()
        for _ in range(80):
            if len(requests) >= 2:
                break
            page.wait_for_timeout(100)
        assert len(requests) >= 2
        assert requests[1].all_headers().get("last-event-id") == str(seq)
        hd.show(hs.SCENARIOS["nothing_playing"])
        expect(page.locator("#title")).to_have_text("Nothing playing")
        expect(page.locator("#offline")).to_be_hidden()
        hd.cleanup()

    def test_offline_indicator_and_recovery(self, page, hd):
        def refuse(route):
            route.abort()

        page.route("**/api/v1/events", refuse)
        page.route("**/api/v1/state", refuse)
        page.clock.install()
        page.goto(hd.url + "/")
        page.clock.run_for(11000)
        expect(page.locator("#offline")).to_be_visible()
        expect(page.locator("#offline")).to_have_text("Reconnecting...")
        expect(page.locator("#master")).to_be_disabled()
        page.unroute("**/api/v1/state", refuse)
        page.clock.run_for(6000)
        expect(page.locator("#offline")).to_be_hidden()
        expect(page.locator("#title")).to_have_text("Tunnel of Love")


# ---------------------------------------------------------------------------
# Layout at the supported sizes
# ---------------------------------------------------------------------------

class TestLayout:
    @pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s[0]}x{s[1]}")
    def test_fits_the_screen_with_finger_sized_targets(self, page, hd, size):
        hd.show(hs.SCENARIOS["in_use_speaker"])
        open_page(page, hd, size)
        width, height = size
        assert page.evaluate("[document.documentElement.scrollWidth, document.documentElement.scrollHeight]") \
            == [width, height]
        frame = page.locator(".art-frame").bounding_box()
        assert frame["height"] <= height * 0.54 + 1
        assert frame["x"] >= width * 0.4 and frame["x"] + frame["width"] <= width
        volume = page.locator("#volume-row").bounding_box()
        assert volume["y"] + volume["height"] <= height
        assert page.locator("#master").bounding_box()["x"] + page.locator("#master").bounding_box()["width"] <= width
        for selector in ("#mute", "#appliances .appliance"):
            box = page.locator(selector).first.bounding_box()
            assert box["height"] >= 55 and box["width"] >= 55
        toggle = page.locator("#speakers .output-toggle").first.bounding_box()
        assert toggle["height"] >= 48 and toggle["width"] >= 48

    @pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s[0]}x{s[1]}")
    def test_left_column_scrolls_as_one(self, page, hd, size):
        open_page(page, hd, size)
        info = page.evaluate(
            "(() => { const l = document.getElementById('left');"
            " return [getComputedStyle(l).overflowY, l.scrollHeight >= l.clientHeight]; })()")
        assert info == ["auto", True]


def column_boxes(page) -> list:
    """The right column's visible blocks, top to bottom, as (name, box)."""
    boxes = page.evaluate(
        """() => ['.art-frame', '#replay-row', '.track-row', '#volume-row'].map(sel => {
            const e = document.querySelector(sel);
            if (!e || getComputedStyle(e).display === 'none') { return null; }
            const r = e.getBoundingClientRect();
            return [sel, {x: r.x, y: r.y, width: r.width, height: r.height}];
        }).filter(Boolean)"""
    )
    return boxes


def assert_column_sound(boxes, size) -> None:
    width, height = size
    assert [name for name, _ in boxes][0] == ".art-frame"
    for _name, box in boxes:
        assert box["y"] >= -0.5 and box["y"] + box["height"] <= height + 0.5
        assert box["x"] >= -0.5 and box["x"] + box["width"] <= width + 0.5
    for (_a, upper), (_b, lower) in zip(boxes, boxes[1:]):
        assert lower["y"] >= upper["y"] + upper["height"] - 0.5, (upper, lower)
    frame, below = boxes[0][1], boxes[1][1]
    assert below["y"] - (frame["y"] + frame["height"]) <= 24
    assert frame["height"] <= height * 0.54 + 1 and abs(frame["width"] - frame["height"]) <= 1


class TestRightColumn:
    @pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s[0]}x{s[1]}")
    @pytest.mark.parametrize("name", hs.SCENARIO_NAMES)
    def test_group_never_overlaps(self, page, hd_mock, name, size):
        hd = Driver("mock", hd_mock)
        hd.show(hs.SCENARIOS[name])
        open_page(page, hd, size)
        page.wait_for_function("document.getElementById('art').complete")
        assert_column_sound(column_boxes(page), size)
        hd.cleanup()

    @pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s[0]}x{s[1]}")
    def test_frame_is_the_same_size_for_artwork_and_logo(self, page, hd_mock, size):
        hd = Driver("mock", hd_mock)
        sizes = []
        for name in ("playing_artwork", "nothing_playing"):
            hd.show(hs.SCENARIOS[name])
            open_page(page, hd, size)
            page.wait_for_function("document.getElementById('art').complete")
            sizes.append(page.locator(".art-frame").bounding_box())
        hd.cleanup()
        assert sizes[0] == sizes[1]

    @pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s[0]}x{s[1]}")
    def test_a_filled_replay_row_shrinks_the_artwork_not_the_rows(self, page, hd_mock, size):
        hd = Driver("mock", hd_mock)
        hd.show(hs.SCENARIOS["replaying"])
        open_page(page, hd, size)
        empty = column_boxes(page)
        assert [n for n, _ in empty] == [".art-frame", ".track-row", "#volume-row"]
        page.evaluate(
            "(() => { const b = document.createElement('button'); b.textContent = 'Stop';"
            " document.getElementById('replay-row').appendChild(b); })()")
        filled = column_boxes(page)
        assert [n for n, _ in filled] == [".art-frame", "#replay-row", ".track-row", "#volume-row"]
        assert_column_sound(filled, size)
        assert filled[0][1]["height"] <= empty[0][1]["height"]
        hd.cleanup()


# ---------------------------------------------------------------------------
# On demand: the review screenshots
# ---------------------------------------------------------------------------

SHOT_SCENARIOS = ("playing_artwork", "nothing_playing", "in_use_speaker", "unauthorized")


def _gradient_png(side: int = 96) -> bytes:
    """A small colourful PNG standing in for cover art (the corpus's artwork is one pixel)."""
    import struct
    import zlib

    raw = b"".join(
        b"\x00" + b"".join(bytes((x * 255 // side, y * 255 // side, 160)) for x in range(side))
        for y in range(side)
    )

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", side, side, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


@pytest.mark.skipif(not os.environ.get("HD_SHOTS_DIR"), reason="HD_SHOTS_DIR not set")
@pytest.mark.parametrize("name", SHOT_SCENARIOS)
@pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s[0]}x{s[1]}")
def test_screenshots(page, hd_mock, name, size):
    hd = Driver("mock", hd_mock)
    art = _gradient_png()
    page.route("**/api/v1/artwork/*", lambda route: route.fulfill(status=200, content_type="image/png", body=art))
    hd.show(hs.SCENARIOS[name])
    open_page(page, hd, size)
    page.wait_for_function(
        "(() => { const a = document.getElementById('art'); return a.complete; })()")
    page.screenshot(path=str(Path(os.environ["HD_SHOTS_DIR"]) / f"hd_{name}_{size[0]}x{size[1]}.png"))
    hd.cleanup()
