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
from dial_core_state import Artwork, NowPlaying, OutputRow, OutputsState, artwork_key  # noqa: E402

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
            for descriptor in scenario.descriptors:
                self.backend.core.warnings.register(descriptor)
            window = self.backend.management._recovery_window
            window.complete()
            active, confirmed = scenario.recovery
            if active:
                window.open()
                if confirmed:
                    window.confirm_volume()
            self.backend.panel.set_view(
                bool(scenario.panel.get("asleep")), scenario.panel.get("backlight", "sysfs"),
                bool(scenario.panel.get("kiosk")))
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
# Screen states
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
        expect(page.locator("#card-title")).to_have_text("Not authorised")
        expect(page.locator("#card-message")).to_have_text("Allow this dial in Kitchen's web UI (Setup, Dials)")
        expect(page.locator("#card-source")).to_have_text("http://192.0.2.20:80/")
        expect(page.locator("#toast")).not_to_have_class(re.compile("show"))
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
        assert order == ["art-zone", "replay-row", "track-row", "volume-row"]

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
        assert page.locator("#app img").count() == len(PICTURE_IDS)
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

    @pytest.mark.parametrize("scope", ["current", "all"])
    @pytest.mark.parametrize("name", ["playing_artwork", "replaying"])
    def test_a_mute_stays_shown_through_the_states_that_follow(self, page, hd, name, scope):
        """Mute pressed while playing live or replaying. The dial's state
        says muted a moment later (under the broadcast scope only once the
        dial has asked the appliances, so a state from before that still
        says unmuted), and states keep arriving afterwards."""
        def state(muted, title):
            base = hs.SCENARIOS[name]
            return dataclasses.replace(base.with_snapshot(
                dial=dataclasses.replace(base.snapshot.dial, mute_scope=scope),
                now_playing=dataclasses.replace(base.snapshot.now_playing, title=title),
            ), muted=muted)

        def shown(title, muted):
            expect(page.locator("#title")).to_have_text(title)
            expect(page.locator("#mute")).to_have_attribute("aria-pressed", "true" if muted else "false")
            if muted:
                expect(page.locator("#volume-row")).to_have_class(re.compile("muted"))
                assert "line-through" in page.evaluate(
                    "getComputedStyle(document.getElementById('master-num')).textDecorationLine")
            else:
                expect(page.locator("#volume-row")).not_to_have_class(re.compile("muted"))

        hd.show(state(False, "T0"))
        page.clock.install()
        sent = watch_actions(page)
        open_page(page, hd)
        shown("T0", False)
        page.locator("#mute").click()
        shown("T0", True)
        if scope == "all":
            hd.show(state(False, "T1"))
            shown("T1", True)
            page.clock.run_for(800)
        hd.show(state(True, "T2"))
        shown("T2", True)
        # Well past the time the page's own guess stands for.
        page.clock.run_for(3000)
        shown("T2", True)
        for title in ("T3", "T4"):
            hd.show(state(True, title))
            shown(title, True)
            page.clock.run_for(2500)
            shown(title, True)

        expect(page.locator("#mute")).to_be_visible()
        shown("T4", True)
        page.locator("#mute").click()
        shown("T4", False)
        hd.show(state(False, "T5"))
        page.clock.run_for(3000)
        shown("T5", False)
        hd.show(state(False, "T6"))
        shown("T6", False)
        assert [name_ for name_, _body in sent] == ["mute_toggle", "mute_toggle"]


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

    def test_the_default_speaker_carries_a_default_badge(self, page, hd):
        open_page(page, hd)
        badge = card(page, "Lounge L + R").locator(".output-card-default")
        expect(badge).to_be_visible()
        expect(badge).to_have_text("Default")
        expect(card(page, "Patio").locator(".output-card-default")).to_be_hidden()
        chip = card(page, "Lounge L + R").locator(".output-state-chip")
        assert abs(badge.bounding_box()["y"] - chip.bounding_box()["y"]) < 2

    def test_the_badge_does_not_change_the_card_height(self, page, hd):
        open_page(page, hd)
        marked = card(page, "Patio").bounding_box()["height"]
        hd.show(scenario("playing_artwork", outputs=outputs_with(
            OutputRow("o1", "Lounge L + R", True, 45),
            OutputRow("o2", "Patio", False, 30, is_default=True))))
        expect(card(page, "Patio").locator(".output-card-default")).to_be_visible()
        assert abs(card(page, "Patio").bounding_box()["height"] - marked) < 2

    def test_a_state_without_the_field_shows_no_badge(self, page, hd):
        open_page(page, hd)
        hd.show(scenario("playing_artwork", outputs=outputs_with(OutputRow("x", "Old", True, 10))))
        expect(card(page, "Old")).to_be_visible()
        expect(card(page, "Old").locator(".output-card-default")).to_be_hidden()

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
    def test_left_column_lists_scroll_separately(self, page, hd, size):
        hd.show(crowded(8, 6))
        open_page(page, hd, size)
        expect(rows(page)).to_have_count(8)
        info = page.evaluate(
            """() => {
                const css = id => getComputedStyle(document.getElementById(id)).overflowY;
                const h = id => document.getElementById(id).getBoundingClientRect().height;
                return [css('left'), css('appliances-list'), css('speakers-list'),
                        h('appliances-region'), h('speakers-region'), h('left')];
            }""")
        assert info[:3] == ["visible", "auto", "auto"]
        assert abs(info[3] - info[5] / 3) <= 2
        assert abs(info[4] - info[5] * 2 / 3) <= 2
        page.evaluate("document.getElementById('speakers-list').scrollTop = 120")
        assert page.evaluate("document.getElementById('speakers-list').scrollTop") > 0
        assert page.evaluate("document.getElementById('appliances-list').scrollTop") == 0


LIST_IDS = ["a%d" % n for n in range(1, 13)]


def crowded(appliance_count, speaker_count):
    """The playing scenario with *appliance_count* appliances (the first is
    focused) and *speaker_count* speakers on it."""
    playing = scenario("playing_artwork")
    first = playing.snapshot.appliances[0]
    others = tuple(
        dataclasses.replace(first, appliance_id=LIST_IDS[n], service_name="Unit %d" % n,
                            name="Unit %d" % n, playing=False)
        for n in range(1, appliance_count))
    speakers = [OutputRow("o%d" % n, "Speaker %d" % n, n % 2 == 0, 30 + n) for n in range(speaker_count)]
    return playing.with_snapshot(
        appliances=(first,) + others, outputs=outputs_with(*speakers))


def refocus(scenario_, appliance_id):
    return scenario_.with_snapshot(
        focus=dataclasses.replace(scenario_.snapshot.focus, reporting_id=appliance_id))


def box(page, selector):
    return page.evaluate(
        "(s) => { const r = document.querySelector(s).getBoundingClientRect();"
        " return {top: r.top, bottom: r.bottom}; }", selector)


def scroll_list(page, list_id, to="end"):
    page.evaluate(
        "([id, to]) => { const l = document.getElementById(id);"
        " l.scrollTop = to === 'end' ? l.scrollHeight : to; }", [list_id, to])


class TestListCues:
    def test_fade_classes_follow_the_scroll_position(self, page, hd):
        hd.show(crowded(8, 6))
        open_page(page, hd)
        expect(rows(page)).to_have_count(8)
        lst = page.locator("#appliances-list")
        expect(lst).to_have_class(re.compile(r"\bmore-below\b"))
        assert "more-above" not in lst.get_attribute("class")
        mask = page.evaluate(
            "(() => { const s = getComputedStyle(document.getElementById('appliances-list'));"
            " return s.maskImage || s.webkitMaskImage; })()")
        assert "linear-gradient" in mask
        scroll_list(page, "appliances-list")
        expect(lst).to_have_class(re.compile(r"\bmore-above\b"))
        assert "more-below" not in lst.get_attribute("class")

    def test_a_short_list_has_no_cue(self, page, hd):
        open_page(page, hd)
        expect(rows(page)).to_have_count(1)
        cls = page.locator("#appliances-list").get_attribute("class")
        assert "more-above" not in cls and "more-below" not in cls

    def test_the_top_region_shows_two_cards_and_a_peek_at_800x480(self, page, hd):
        hd.show(crowded(3, 2))
        open_page(page, hd, (800, 480))
        expect(rows(page)).to_have_count(3)
        region = box(page, "#appliances-region")
        first, second, third = (
            page.evaluate(
                "(i) => { const r = document.querySelectorAll('#appliances .appliance')[i]"
                ".getBoundingClientRect(); return {top: r.top, bottom: r.bottom}; }", i)
            for i in range(3))
        for row in (first, second):
            assert row["top"] >= region["top"] and row["bottom"] <= region["bottom"]
        # The third card starts in the band the list shares with the speakers label.
        shown = box(page, "#appliances-list")
        assert region["bottom"] <= third["top"] < shown["bottom"] < third["bottom"]
        expect(page.locator("#appliances-list")).to_have_class(re.compile(r"\bmore-below\b"))

    def test_the_speakers_label_overlaps_the_last_visible_card_and_lets_taps_through(self, page, hd):
        hd.show(crowded(3, 2))
        open_page(page, hd, (800, 480))
        expect(rows(page)).to_have_count(3)
        label = box(page, "#speakers-label")
        third = page.evaluate(
            "(() => { const r = document.querySelectorAll('#appliances .appliance')[2]"
            ".getBoundingClientRect(); return {top: r.top, bottom: r.bottom, x: r.left + 40}; })()")
        assert third["top"] < label["bottom"] and third["bottom"] > label["top"]
        sent = watch_actions(page)
        y = (max(third["top"], label["top"]) + min(third["bottom"], label["bottom"])) / 2
        page.mouse.click(third["x"], y)
        page.wait_for_timeout(200)
        assert [(name, body["appliance_id"]) for name, body in sent] == [("focus", LIST_IDS[2])]

    def test_end_padding_lets_the_last_card_clear_the_divider(self, page, hd):
        hd.show(crowded(8, 6))
        open_page(page, hd, (800, 480))
        expect(rows(page)).to_have_count(8)
        scroll_list(page, "appliances-list")
        last = page.evaluate(
            "(() => { const l = document.querySelectorAll('#appliances .appliance');"
            " return l[l.length - 1].getBoundingClientRect().bottom; })()")
        assert last <= box(page, "#speakers-label")["top"] + 1

    def test_focus_from_the_state_scrolls_the_row_into_view(self, page, hd):
        hd.show(crowded(8, 6))
        open_page(page, hd, (800, 480))
        expect(rows(page)).to_have_count(8)
        hd.show(refocus(crowded(8, 6), LIST_IDS[7]))
        expect(rows(page).nth(7)).to_have_attribute("aria-current", "true")
        page.wait_for_timeout(400)
        region = box(page, "#appliances-region")
        last = page.evaluate(
            "document.querySelectorAll('#appliances .appliance')[7].getBoundingClientRect().bottom")
        assert last <= region["bottom"] + 1

    def test_a_recent_user_scroll_holds_the_focus_follow(self, page, hd):
        hd.show(crowded(8, 6))
        page.clock.install()
        open_page(page, hd, (800, 480))
        expect(rows(page)).to_have_count(8)
        page.clock.run_for(5000)
        scroll_list(page, "appliances-list", 20)
        page.wait_for_timeout(200)
        before = page.evaluate("document.getElementById('appliances-list').scrollTop")
        hd.show(refocus(crowded(8, 6), LIST_IDS[7]))
        expect(rows(page).nth(7)).to_have_attribute("aria-current", "true")
        page.wait_for_timeout(300)
        assert page.evaluate("document.getElementById('appliances-list').scrollTop") == before
        page.clock.run_for(3100)
        hd.show(refocus(crowded(8, 6), LIST_IDS[6]))
        expect(rows(page).nth(6)).to_have_attribute("aria-current", "true")
        page.wait_for_timeout(300)
        assert page.evaluate("document.getElementById('appliances-list').scrollTop") > before

    def test_scroll_positions_survive_a_state_event(self, page, hd):
        hd.show(crowded(8, 6))
        open_page(page, hd, (800, 480))
        expect(rows(page)).to_have_count(8)
        scroll_list(page, "appliances-list", 40)
        scroll_list(page, "speakers-list", 60)
        page.wait_for_timeout(100)
        before = page.evaluate(
            "['appliances-list', 'speakers-list'].map(i => document.getElementById(i).scrollTop)")
        assert before[0] > 0 and before[1] > 0
        hd.show(crowded(8, 6).with_snapshot(volume_readout=("Lounge", 61)))
        page.wait_for_timeout(500)
        assert page.evaluate(
            "['appliances-list', 'speakers-list'].map(i => document.getElementById(i).scrollTop)") == before


COLUMN_SELECTORS = [".art-zone", ".art-frame", "#replay-row", ".track-row", "#volume-row"]


def column_boxes(page) -> list:
    """The right column's visible blocks, top to bottom, as (name, box)."""
    boxes = page.evaluate(
        """(selectors) => selectors.map(sel => {
            const e = document.querySelector(sel);
            if (!e || getComputedStyle(e).display === 'none') { return null; }
            const r = e.getBoundingClientRect();
            return [sel, {x: r.x, y: r.y, width: r.width, height: r.height}];
        }).filter(Boolean)""",
        COLUMN_SELECTORS,
    )
    return boxes


def assert_column_sound(boxes, size) -> None:
    width, height = size
    assert [name for name, _ in boxes][:2] == [".art-zone", ".art-frame"]
    for _name, box in boxes:
        assert box["y"] >= -0.5 and box["y"] + box["height"] <= height + 0.5
        assert box["x"] >= -0.5 and box["x"] + box["width"] <= width + 0.5
    zone, frame = boxes[0][1], boxes[1][1]
    # The frame sits inside the zone, centred in it.
    assert frame["x"] >= zone["x"] - 0.5 and frame["y"] >= zone["y"] - 0.5
    assert frame["x"] + frame["width"] <= zone["x"] + zone["width"] + 0.5
    assert frame["y"] + frame["height"] <= zone["y"] + zone["height"] + 0.5
    assert abs((frame["x"] + frame["width"] / 2) - (zone["x"] + zone["width"] / 2)) <= 1
    assert abs((frame["y"] + frame["height"] / 2) - (zone["y"] + zone["height"] / 2)) <= 1
    # The zone starts the column; the rows follow it in order without overlap.
    assert zone["y"] == min(box["y"] for _name, box in boxes)
    below = [boxes[0]] + boxes[2:]
    for (_a, upper), (_b, lower) in zip(below, below[1:]):
        assert lower["y"] >= upper["y"] + upper["height"] - 0.5, (upper, lower)
    assert below[1][1]["y"] - (zone["y"] + zone["height"]) <= 24
    assert frame["height"] <= height * 0.54 + 1 and abs(frame["width"] - frame["height"]) <= 1
    # The zone is most of the column even with the replay row showing.
    assert zone["height"] >= (height - 34) * 0.55


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
        hd.show(hs.SCENARIOS["playing_artwork"])
        open_page(page, hd, size)
        empty = column_boxes(page)
        assert [n for n, _ in empty] == [".art-zone", ".art-frame", ".track-row", "#volume-row"]
        states = [hs.SCENARIOS[name] for name in ("replaying", "replay_hold", "fading_out")]
        states += [hs.replay_scenario("idle", "idle"), hs.replay_scenario("live", "recording")]
        for state in states:
            hd.show(state)
            expect(page.locator("#replay-row")).to_be_visible()
            expect(page.locator("#replay-row > *").first).to_be_visible()
            filled = column_boxes(page)
            assert [n for n, _ in filled] == [
                ".art-zone", ".art-frame", "#replay-row", ".track-row", "#volume-row"]
            assert_column_sound(filled, size)
            assert filled[0][1]["height"] <= empty[0][1]["height"] - 56
            assert filled[1][1]["height"] <= empty[1][1]["height"]
            # The track and volume rows do not move when the replay row fills.
            assert dict(filled)[".track-row"]["height"] == dict(empty)[".track-row"]["height"]
            assert dict(filled)["#volume-row"]["height"] == dict(empty)["#volume-row"]["height"]
        hd.cleanup()


def real_cover(hd, name="cover") -> None:
    """On the real server, hold a cover it can decode (the corpus's one is a
    stand-in the imaging library rejects), under a key of its own."""
    if hd.kind != "real":
        return
    key = artwork_key(f"https://provider.example/art/{name}.jpg")
    held = Artwork("", key, _gradient_png(), "", hs.NOW - 5)
    hd.backend.core.publish(artwork=held)


class TestBackdrop:
    def test_the_backdrop_layer_shows_the_artworks_backdrop(self, page, hd):
        real_cover(hd)
        open_page(page, hd)
        backdrop = page.locator("#backdrop")
        key = page.evaluate("document.getElementById('art').getAttribute('src')").rsplit("/", 1)[1]
        expect(backdrop).to_have_attribute("src", f"/api/v1/artwork/{key}/backdrop")
        wait_settled(page)
        assert page.evaluate("document.getElementById('backdrop').naturalWidth") > 0
        assert page.evaluate("getComputedStyle(document.getElementById('backdrop')).opacity") == "1"
        assert backdrop.bounding_box() == page.locator(".art-zone").bounding_box()

    def test_nothing_playing_shows_the_logo_backdrop(self, page, hd):
        hd.show(hs.SCENARIOS["nothing_playing"])
        open_page(page, hd)
        expect(page.locator("#backdrop")).to_have_attribute("src", "/api/v1/logo/backdrop")
        expect(page.locator("#art")).to_have_class(re.compile("logo"))
        page.wait_for_function("document.getElementById('backdrop').complete")
        assert page.evaluate("document.getElementById('backdrop').naturalWidth") > 0

    @pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s[0]}x{s[1]}")
    def test_the_zone_holds_the_backdrop_at_every_size(self, page, hd_mock, size):
        hd = Driver("mock", hd_mock)
        hd.show(hs.SCENARIOS["playing_artwork"])
        open_page(page, hd, size)
        zone = page.locator(".art-zone").bounding_box()
        assert page.locator("#backdrop").bounding_box() == zone
        first_row = page.locator(".track-row").bounding_box()
        assert zone["y"] + zone["height"] <= first_row["y"]
        hd.cleanup()

    @pytest.mark.parametrize("scenario_name,share", [("playing_artwork", 1.0), ("nothing_playing", 0.84)])
    def test_the_picture_fills_the_frame(self, page, hd_mock, scenario_name, share):
        hd = Driver("mock", hd_mock)
        hd.show(hs.SCENARIOS[scenario_name])
        open_page(page, hd)
        page.wait_for_function("document.getElementById('art').complete")
        frame = page.locator(".art-frame").bounding_box()
        art = page.locator("#art").bounding_box()
        inner = frame["width"] - 16
        assert abs(art["width"] - inner * share) <= 1 and abs(art["height"] - inner * share) <= 1
        assert abs((art["x"] + art["width"] / 2) - (frame["x"] + frame["width"] / 2)) <= 1
        assert abs((art["y"] + art["height"] / 2) - (frame["y"] + frame["height"] / 2)) <= 1
        hd.cleanup()


PICTURE_IDS = ("art", "art-prev", "backdrop", "backdrop-prev")
LOGO_URL = "/static/logo.png"
LOGO_BACKDROP = "/api/v1/logo/backdrop"

SETTLED_JS = """() => {
    const o = id => getComputedStyle(document.getElementById(id)).opacity;
    return o('art') === '1' && o('backdrop') === '1' && o('art-prev') === '0'
        && o('backdrop-prev') === '0' && !document.querySelector('.loading');
}"""


def wait_settled(page, timeout=5000) -> None:
    """Both fronts shown, both ghosts gone, nothing still loading."""
    page.wait_for_function(SETTLED_JS, timeout=timeout)


WATCH_CLASSES = """
(() => {
    window.__classLog = [];
    document.addEventListener('DOMContentLoaded', () => {
        const watcher = new MutationObserver(records => {
            for (const r of records) {
                window.__classLog.push([r.target.id, r.target.className, performance.now()]);
            }
        });
        for (const id of ['art', 'art-prev', 'backdrop', 'backdrop-prev']) {
            watcher.observe(document.getElementById(id), {attributes: true, attributeFilter: ['class']});
        }
    });
})();
"""

SAMPLE_OPACITIES = """() => {
    window.__seen = [];
    const sample = () => {
        window.__seen.push(['art', 'art-prev', 'backdrop', 'backdrop-prev'].map(
            id => getComputedStyle(document.getElementById(id)).opacity));
        requestAnimationFrame(sample);
    };
    sample();
}"""


def not_found(route) -> None:
    route.fulfill(status=404, content_type="application/json", body='{"ok":false}')


ARTWORK_BACKDROP_URL = re.compile(r"/api/v1/artwork/[0-9a-f]{16}/backdrop$")
LOGO_PICTURE_URLS = re.compile(r"/api/v1/logo/backdrop$|/static/logo\.png$")


class TestPictureSwap:
    def test_a_change_cross_fades_both_pictures(self, page, hd):
        real_cover(hd)
        page.add_init_script(WATCH_CLASSES)
        open_page(page, hd)
        wait_settled(page)
        artwork_src = page.locator("#art").get_attribute("src")
        backdrop_src = page.locator("#backdrop").get_attribute("src")
        assert artwork_src.startswith("/api/v1/artwork/") and backdrop_src.endswith("/backdrop")
        page.evaluate("window.__classLog.length = 0")

        hd.show(hs.SCENARIOS["nothing_playing"])
        expect(page.locator("#art")).to_have_attribute("src", LOGO_URL)
        expect(page.locator("#backdrop")).to_have_attribute("src", LOGO_BACKDROP)
        expect(page.locator("#art-prev")).to_have_attribute("src", artwork_src)
        expect(page.locator("#backdrop-prev")).to_have_attribute("src", backdrop_src)
        wait_settled(page)

        # Both pairs flip in the same step.
        ends = {}
        log = page.evaluate("window.__classLog")
        for ident, classes, at in log:
            names = classes.split()
            if ident.endswith("-prev") and "showing" not in names:
                ends[ident] = at
            if not ident.endswith("-prev") and "loading" not in names:
                ends[ident] = at
        assert set(ends) == set(PICTURE_IDS), log
        assert max(ends.values()) - min(ends.values()) < 50, ends

        hd.show(hs.SCENARIOS["playing_artwork"])
        expect(page.locator("#art")).to_have_attribute("src", re.compile("/api/v1/artwork/"))
        expect(page.locator("#art-prev")).to_have_attribute("src", LOGO_URL)
        wait_settled(page)
        assert page.evaluate("document.getElementById('backdrop').naturalWidth") > 0

    def test_the_ghost_passes_through_intermediate_opacities(self, page, hd):
        real_cover(hd)
        open_page(page, hd)
        wait_settled(page)
        page.evaluate(SAMPLE_OPACITIES)
        hd.show(hs.SCENARIOS["nothing_playing"])
        expect(page.locator("#art")).to_have_attribute("src", LOGO_URL)
        wait_settled(page)
        seen = [float(frame[1]) for frame in page.evaluate("window.__seen")]
        assert any(0.05 < value < 0.95 for value in seen), seen

    def test_reduced_motion_cuts(self, page, hd):
        real_cover(hd)
        page.emulate_media(reduced_motion="reduce")
        open_page(page, hd)
        wait_settled(page)
        page.evaluate(SAMPLE_OPACITIES)
        hd.show(hs.SCENARIOS["nothing_playing"])
        expect(page.locator("#art")).to_have_attribute("src", LOGO_URL)
        wait_settled(page)
        page.wait_for_timeout(100)
        seen = page.evaluate("window.__seen")
        assert all(value in ("0", "1") for frame in seen for value in frame), seen
        assert seen[-1] == ["1", "0", "1", "0"]

    def test_a_missing_backdrop_falls_back_to_the_logo_backdrop(self, page, hd):
        real_cover(hd)
        page.route(ARTWORK_BACKDROP_URL, not_found)
        open_page(page, hd)
        expect(page.locator("#backdrop")).to_have_attribute("src", LOGO_BACKDROP)
        wait_settled(page)
        assert page.locator("#art").get_attribute("src").startswith("/api/v1/artwork/")
        assert page.evaluate("document.getElementById('backdrop').naturalWidth") > 0

    def test_nothing_sticks_when_everything_fails(self, page, hd):
        real_cover(hd)
        page.route(re.compile(r"/api/v1/artwork/"), not_found)
        page.route(re.compile(r"/api/v1/logo/backdrop$"), not_found)
        open_page(page, hd)
        expect(page.locator("#art")).to_have_attribute("src", LOGO_URL)
        expect(page.locator("#art")).to_have_class(re.compile("logo"))
        wait_settled(page, 3000)

    def test_a_stalled_load_settles(self, page, hd):
        hd.show(hs.SCENARIOS["nothing_playing"])
        page.clock.install()
        open_page(page, hd)
        held = []
        page.route(ARTWORK_BACKDROP_URL, lambda route: held.append(route))
        hd.show(hs.SCENARIOS["playing_artwork"])
        real_cover(hd)
        expect(page.locator("#backdrop")).to_have_class(re.compile("loading"))
        page.clock.run_for(2500)
        expect(page.locator("#backdrop")).not_to_have_class(re.compile("loading"))
        expect(page.locator("#art")).not_to_have_class(re.compile("loading"))
        for route in held:
            route.abort()

    def test_a_quick_second_change_keeps_the_last_shown_picture_in_the_ghost(self, page, hd):
        real_cover(hd)
        open_page(page, hd)
        wait_settled(page)
        shown = page.locator("#art").get_attribute("src")
        held = []
        page.route(LOGO_PICTURE_URLS, lambda route: held.append(route))
        hd.show(hs.SCENARIOS["nothing_playing"])
        expect(page.locator("#art")).to_have_attribute("src", LOGO_URL)
        expect(page.locator("#art-prev")).to_have_attribute("src", shown)
        expect(page.locator("#art-prev")).to_have_class(re.compile("showing"))
        # Back to the first picture while the logo is still loading.
        hd.show(hs.SCENARIOS["playing_artwork"])
        real_cover(hd)
        expect(page.locator("#art")).to_have_attribute("src", shown)
        expect(page.locator("#art-prev")).to_have_attribute("src", shown)
        wait_settled(page)
        assert page.locator("#art-prev").get_attribute("src") == shown
        for route in held:
            route.abort()


# ---------------------------------------------------------------------------
# On demand: the review screenshots
# ---------------------------------------------------------------------------

SHOT_SCENARIOS = ("playing_artwork", "nothing_playing", "replaying", "in_use_speaker", "unauthorized")


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


def _backdrop_bodies(art: bytes) -> tuple:
    """Real backdrop renders for the cover and the logo when the imaging
    library is here, else the corpus's stand-in."""
    try:
        import dial_display_image as images
    except ImportError:
        return hs.BACKDROP_BYTES, hs.BACKDROP_BYTES
    logo = Path(__file__).resolve().parents[2] / "images" / "autostream-logo-centred-dark.png"
    return images.render_artwork_backdrop(art), images.render_logo_backdrop(str(logo))


@pytest.mark.skipif(not os.environ.get("HD_SHOTS_DIR"), reason="HD_SHOTS_DIR not set")
@pytest.mark.parametrize("name", SHOT_SCENARIOS)
@pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s[0]}x{s[1]}")
def test_screenshots(page, hd_mock, name, size):
    hd = Driver("mock", hd_mock)
    art = _gradient_png()
    cover_backdrop, logo_backdrop = _backdrop_bodies(art)
    seen = []

    def answer(body, kind):
        def handler(route):
            seen.append((kind, route.request.url))
            route.fulfill(status=200, content_type=kind, body=body)
        return handler

    # The glob's * stops at a slash, so the artwork and its backdrop are separate routes.
    page.route("**/api/v1/artwork/*", answer(art, "image/png"))
    page.route("**/api/v1/artwork/*/backdrop", answer(cover_backdrop, "image/jpeg"))
    page.route("**/api/v1/logo/backdrop", answer(logo_backdrop, "image/jpeg"))
    hd.show(hs.SCENARIOS[name])
    open_page(page, hd, size)
    wait_settled(page)
    assert any(kind == "image/jpeg" for kind, _url in seen)
    page.screenshot(path=str(Path(os.environ["HD_SHOTS_DIR"]) / f"hd_{name}_{size[0]}x{size[1]}.png"))
    hd.cleanup()
