"""Playwright tests for the HD page's replay row, equaliser page, pull-down
settings, warning and notice cards, sleep shield, panel activity reports and
the hiding of idle controls.

Like the main-layout tests these run against the production HdServer over a
FakeCore and against the offline mock (they share the scenario corpus and the
serialiser), and check what the page sends on the wire. Without Playwright
or its pytest plugin they skip.
"""
from __future__ import annotations

import dataclasses
import json
import re
import sys
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_hd_dial import (  # noqa: E402,F401  (fixtures shared with the page smoke tests)
    _PLAYWRIGHT_INSTALLED, Watcher, browser_context_args, hd_mock, hd_real,
)
from test_hd_page_main import (  # noqa: E402,F401
    Driver, SIZES, card, cards, drag_input, hd, open_page, rows, scenario, watch_actions,
)

pytestmark = pytest.mark.skipif(not _PLAYWRIGHT_INSTALLED, reason="playwright not installed")

if _PLAYWRIGHT_INSTALLED:
    from playwright.sync_api import expect

import hd_scenarios as hs  # noqa: E402
from dial_core_state import EqBand, EqState, FocusState, NowPlaying  # noqa: E402

LOUNGE, KITCHEN = hs.LOUNGE, hs.KITCHEN
LOUNGE_STYLUS = f"appliance:{LOUNGE}:stylus_in1"


def watch_posts(page) -> list:
    """Every state-changing request the page makes from now on, as (name,
    body): the action name, "settings", or "panel_<name>"."""
    sent: list = []

    def name_of(url: str) -> str:
        if "/api/v1/actions/" in url:
            return url.rsplit("/", 1)[1]
        if url.endswith("/api/v1/settings"):
            return "settings"
        return "panel_" + url.rsplit("/", 1)[1]

    def seen(request) -> None:
        if request.method == "POST" and "/api/v1/" in request.url:
            sent.append((name_of(request.url), request.post_data_json))

    page.on("request", seen)
    return sent


def only(sent: list, *names) -> list:
    return [item for item in sent if item[0] in names]


def centre(page, selector) -> tuple:
    box = page.locator(selector).bounding_box()
    return box["x"] + box["width"] / 2, box["y"] + box["height"] / 2


def tap(page, selector) -> None:
    """A mouse click on the middle of *selector*, whatever is on top of it."""
    page.mouse.click(*centre(page, selector))


def post_settings(url: str, body: dict) -> None:
    request = urllib.request.Request(
        url + "/api/v1/settings", data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json", "X-Requested-With": "autostream-hd"})
    urllib.request.urlopen(request, timeout=5).read()


def current_state(page) -> dict:
    return page.evaluate("fetch('/api/v1/state').then(r => r.json())")


# ---------------------------------------------------------------------------
# The replay row
# ---------------------------------------------------------------------------

# The transport buttons by their spoken labels.
PLAY, REWIND, STOP = "Play the recording", "Back to the start", "Stop the replay"


def replay_row(page):
    return page.locator("#replay-row")


def replay_button(page, label):
    return page.locator(f'#replay-row button[aria-label="{label}"]')


def replay_timer(page):
    return page.locator("#replay-row .replay-counter")


def row_layout(page) -> list:
    """The replay row's controls left to right: a button's label, or
    "timer" / "arm", with whether it is disabled and its box."""
    return page.evaluate(
        """() => Array.from(document.getElementById('replay-row').children).map(node => {
            const r = node.getBoundingClientRect();
            const name = node.tagName === 'BUTTON' ? node.getAttribute('aria-label')
                : node.classList.contains('replay-counter') ? 'timer' : 'arm';
            return {name: name, disabled: !!node.disabled, x: r.x, width: r.width, height: r.height,
                    svg: node.querySelectorAll('svg').length, text: node.tagName === 'BUTTON' ? node.textContent : ''};
        })"""
    )


def timer_seconds(page) -> int:
    """The position the timer shows, in seconds."""
    parts = [int(p) for p in replay_timer(page).text_content().split(" / ")[0].split(":")]
    return sum(value * 60 ** power for power, value in enumerate(reversed(parts)))


def replaying_at(position, title="Tunnel of Love", duration=1100.0):
    """The Lounge replaying at *position* seconds (the state reports it a
    second on, as a reading a second old, with no start-buffer offset), under
    a title a test can wait for."""
    base = hs.replay_scenario("r", "replaying", position=position - 1.0, duration=duration,
                              latency=0.0)
    return base.with_snapshot(now_playing=NowPlaying("Lounge", "Dire Straits", title, 42))


def freeze_clock(page) -> None:
    """Stop the page's clock, so that only run_for() moves it."""
    page.clock.pause_at(page.evaluate("Date.now()") / 1000 + 1)


class TestReplayRow:
    @pytest.mark.parametrize("armed", [True, False])
    @pytest.mark.parametrize("state", ["recording", "pending"])
    def test_playing_live_shows_the_arm_toggle_only(self, page, hd, state, armed):
        hd.show(hs.replay_scenario("r", state, armed=armed))
        open_page(page, hd)
        toggle = page.locator("#replay-row .repeat-arm")
        expect(toggle).to_be_visible()
        expect(toggle).to_contain_text("Repeat Play")
        assert [item["name"] for item in row_layout(page)] == ["arm"]
        checked = page.locator("#replay-row .repeat-arm input")
        if armed:
            expect(checked).to_be_checked()
        else:
            expect(checked).not_to_be_checked()

    def test_nothing_held_shows_the_transport_greyed_out(self, page, hd):
        hd.show(hs.replay_scenario("r", "idle"))
        sent = watch_actions(page)
        open_page(page, hd)
        expect(replay_row(page)).to_be_visible()
        layout = row_layout(page)
        assert [(item["name"], item["disabled"]) for item in layout] == [
            (PLAY, True), (STOP, True), ("timer", False)]
        expect(replay_timer(page)).to_have_text("-:-- / -:--")
        expect(replay_timer(page)).to_have_class(re.compile("frozen"))
        assert page.locator("#replay-row .repeat-arm").count() == 0
        for label in (PLAY, STOP):
            tap(page, f'#replay-row button[aria-label="{label}"]')
        page.wait_for_timeout(150)
        assert sent == []
        hd.show(hs.replay_scenario("r", "recording"))
        expect(page.locator("#replay-row .repeat-arm")).to_be_visible()
        assert [item["name"] for item in row_layout(page)] == ["arm"]

    def test_arm_toggle_sends_and_follows_the_state(self, page, hd):
        hd.show(hs.replay_scenario("r", "recording", armed=False))
        sent = watch_actions(page)
        open_page(page, hd)
        box = page.locator("#replay-row .repeat-arm input")
        page.locator("#replay-row .repeat-arm").click()
        expect(box).to_be_checked()
        assert sent == [("repeat_arm", {"appliance_id": LOUNGE, "armed": True})]
        hd.show(hs.replay_scenario("r", "recording", armed=True))
        expect(box).to_be_checked()

    def test_arm_toggle_rolls_back_when_the_state_never_follows(self, page, hd):
        hd.show(hs.replay_scenario("r", "recording", armed=False))
        page.clock.install()
        open_page(page, hd)
        page.locator("#replay-row .repeat-arm").click()
        expect(page.locator("#replay-row .repeat-arm input")).to_be_checked()
        page.clock.run_for(2500)
        expect(page.locator("#replay-row .repeat-arm input")).not_to_be_checked()

    def test_a_held_recording_offers_play_with_its_length(self, page, hd):
        hd.show(hs.SCENARIOS["replay_hold"])
        sent = watch_actions(page)
        open_page(page, hd)
        expect(replay_timer(page)).to_have_text("0:00 / 18:42")
        expect(replay_timer(page)).not_to_have_class(re.compile("frozen"))
        assert [(item["name"], item["disabled"]) for item in row_layout(page)] == [
            (PLAY, False), (STOP, True), ("timer", False)]
        assert page.locator("#replay-row .repeat-arm").count() == 0
        tap(page, f'#replay-row button[aria-label="{STOP}"]')
        replay_button(page, PLAY).click()
        page.wait_for_timeout(150)
        assert sent == [("replay_start", {"appliance_id": LOUNGE})]

    def test_play_starts_the_replay_and_the_row_becomes_the_running_one(self, page, hd):
        hd.show(hs.SCENARIOS["replay_hold"])
        open_page(page, hd)
        replay_button(page, PLAY).click()
        if hd.kind == "real":       # the mock moves to the replaying state by itself
            hd.show(hs.SCENARIOS["replaying"])
        expect(replay_button(page, REWIND)).to_be_enabled()
        expect(replay_button(page, STOP)).to_be_enabled()
        assert replay_button(page, PLAY).count() == 0
        expect(replay_timer(page)).to_have_text(re.compile(r"^(1:59|2:0[0-9]) / 18:20$"))

    def test_a_recording_of_an_hour_or_more_shows_hours(self, page, hd):
        hd.show(hs.replay_scenario("r", "hold", recording=3725.0))
        open_page(page, hd)
        expect(replay_timer(page)).to_have_text("0:00 / 1:02:05")
        hd.show(hs.replay_scenario("r", "replaying", position=3600.0, duration=7384.0, latency=0.0))
        expect(replay_timer(page)).to_have_text(re.compile(r"^1:00:0[0-9] / 2:03:04$"))

    def test_the_badge_of_an_hour_long_recording_elsewhere_shows_hours(self, page, hd):
        base = hs.SCENARIOS["replay_elsewhere"]
        lounge = dataclasses.replace(
            base.snapshot.appliances[1], playing=False, repeat=hs.repeat_record("hold", recording=3600.0))
        hd.show(base.with_snapshot(appliances=(base.snapshot.appliances[0], lounge)))
        open_page(page, hd)
        expect(rows(page).filter(has_text="Lounge").locator(".badge")).to_have_text("Replay 1:00:00")

    def test_replaying_shows_rewind_stop_and_the_timer_in_that_order(self, page, hd):
        hd.show(hs.SCENARIOS["replaying"])
        sent = watch_actions(page)
        open_page(page, hd)
        expect(replay_timer(page)).to_have_text(re.compile(r"^(1:59|2:0[0-9]) / 18:20$"))
        layout = row_layout(page)
        assert [(item["name"], item["disabled"]) for item in layout] == [
            (REWIND, False), (STOP, False), ("timer", False)]
        # Left to right on the screen too, without overlapping.
        for left, right in zip(layout, layout[1:]):
            assert left["x"] + left["width"] <= right["x"]
        assert page.locator("#replay-row .repeat-arm").count() == 0
        replay_button(page, REWIND).click()
        page.wait_for_timeout(150)
        expect(page.locator("#modal")).to_be_hidden()      # no confirmation
        assert sent == [("replay_restart", {"appliance_id": LOUNGE})]
        replay_button(page, STOP).click()
        page.wait_for_timeout(150)
        assert sent[-1] == ("replay_stop", {"appliance_id": LOUNGE})

    @pytest.mark.parametrize("name", ["replay_hold", "replaying"])
    def test_the_transport_buttons_are_icons_with_labels(self, page, hd, name):
        hd.show(hs.SCENARIOS[name])
        open_page(page, hd)
        buttons = [item for item in row_layout(page) if item["name"] != "timer"]
        assert len(buttons) == 2
        for item in buttons:
            assert item["name"] in (PLAY, REWIND, STOP)
            assert item["svg"] == 1 and item["text"] == ""
        shapes = page.evaluate(
            """() => Array.from(document.querySelectorAll('#replay-row button svg')).map(svg => ({
                hidden: svg.getAttribute('aria-hidden'), box: svg.getAttribute('viewBox'),
                paths: svg.querySelectorAll('path').length,
                drawn: svg.querySelector('path').getBBox().width > 8}))"""
        )
        assert shapes == [{"hidden": "true", "box": "0 0 24 24", "paths": 1, "drawn": True}] * 2
        # The two icons of a row are different pictures.
        assert len(set(page.evaluate(
            "Array.from(document.querySelectorAll('#replay-row button path')).map(p => p.getAttribute('d'))"
        ))) == 2

    @pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s[0]}x{s[1]}")
    def test_the_transport_buttons_are_finger_sized(self, page, hd_mock, size):
        hd = Driver("mock", hd_mock)
        for scenario_ in (hs.SCENARIOS["replay_hold"], hs.SCENARIOS["replaying"], hs.replay_scenario("i", "idle")):
            hd.show(scenario_)
            open_page(page, hd, size)
            expect(replay_timer(page)).to_be_visible()
            buttons = [item for item in row_layout(page) if item["name"] != "timer"]
            assert len(buttons) == 2
            for item in buttons:
                assert item["width"] >= 56 and item["height"] >= 56
            box = replay_row(page).bounding_box()
            assert box["height"] <= buttons[0]["height"] + 0.5
        hd.cleanup()

    @pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s[0]}x{s[1]}")
    @pytest.mark.parametrize("name", ["replay_hold", "replaying", "fading_out"])
    def test_the_timer_is_set_as_the_artist_line_is(self, page, hd_mock, name, size):
        hd = Driver("mock", hd_mock)
        hd.show(hs.SCENARIOS[name])
        open_page(page, hd, size)
        expect(page.locator("#sub")).not_to_have_text("")
        fonts = page.evaluate(
            """() => ['#replay-row .replay-counter', '#sub'].map(sel => {
                const s = getComputedStyle(document.querySelector(sel));
                return [s.fontFamily, s.fontSize, s.fontWeight, s.fontStyle];
            })"""
        )
        hd.cleanup()
        assert fonts[0] == fonts[1]
        assert fonts[0][2] == "400"
        title_size = page.evaluate("parseFloat(getComputedStyle(document.getElementById('title')).fontSize)")
        assert float(fonts[0][1].rstrip("px")) < title_size

    def test_the_timer_advances_between_states_and_stops_at_the_length(self, page, hd):
        hd.show(hs.SCENARIOS["replaying"])
        page.clock.install()
        open_page(page, hd)
        expect(replay_timer(page)).to_have_text(re.compile(r"^(1:59|2:0[0-9]) / 18:20$"))
        before = timer_seconds(page)
        page.clock.run_for(4000)
        assert 4 <= timer_seconds(page) - before <= 6

        hd.show(hs.replay_scenario("end", "replaying", position=1098.0, duration=1100.0, latency=0.0))
        expect(replay_timer(page)).to_have_text(re.compile(r"^18:19 / 18:20$"))
        page.clock.run_for(6000)
        expect(replay_timer(page)).to_have_text("18:20 / 18:20")
        page.clock.run_for(3000)
        expect(replay_timer(page)).to_have_text("18:20 / 18:20")

    def test_the_timer_steps_a_second_at_a_time_whenever_it_is_looked_at(self, page, hd):
        hd.show(replaying_at(120.0))
        page.clock.install()
        open_page(page, hd)
        expect(replay_timer(page)).to_have_text(re.compile(r"^2:0[0-9] / 18:20$"))
        freeze_clock(page)
        shown = [timer_seconds(page)]
        for _ in range(40):
            page.clock.run_for(250)
            shown.append(timer_seconds(page))
        steps = [b - a for a, b in zip(shown, shown[1:])]
        assert set(steps) == {0, 1}
        assert shown[-1] - shown[0] == 10
        # A whole second passes between one step and the next.
        at = [i for i, step in enumerate(steps) if step == 1]
        assert all(b - a == 4 for a, b in zip(at, at[1:]))

    def test_the_timer_never_steps_back_as_states_arrive_early_and_late(self, page, hd):
        """Each state's position is a little off the page's own clock, one
        way or the other. The timer keeps going forwards a second at a
        time and stays with the dial's position."""
        hd.show(replaying_at(120.0, "T0"))
        page.clock.install()
        open_page(page, hd)
        expect(page.locator("#title")).to_have_text("T0")
        freeze_clock(page)
        start = timer_seconds(page)
        shown = [start]
        elapsed = 0.0
        late = [0.4, -0.4, 0.3, -0.35, 0.45, -0.45, 0.2, -0.3, 0.4, -0.4] * 6
        # States arrive every 0.39 s, so at every part of a second in turn.
        for n, off in enumerate(late, start=1):
            for _ in range(3):
                page.clock.run_for(130)
                elapsed += 0.13
                shown.append(timer_seconds(page))
            hd.show(replaying_at(121.0 + elapsed + off, f"T{n}"))
            expect(page.locator("#title")).to_have_text(f"T{n}")
            shown.append(timer_seconds(page))
        steps = [b - a for a, b in zip(shown, shown[1:])]
        assert min(steps) >= 0, shown
        assert max(steps) <= 1, shown
        assert abs((shown[-1] - start) - elapsed) <= 1, shown

    def test_a_steady_difference_is_worked_off_without_a_jump(self, page, hd):
        hd.show(replaying_at(120.0, "T0"))
        page.clock.install()
        open_page(page, hd)
        expect(page.locator("#title")).to_have_text("T0")
        freeze_clock(page)
        start = timer_seconds(page)
        shown = [start]
        elapsed = 0.0
        # The dial is 1.2 s ahead of the page from now on.
        for n in range(1, 21):
            for _ in range(4):
                page.clock.run_for(500)
                elapsed += 0.5
                shown.append(timer_seconds(page))
            hd.show(replaying_at(121.0 + elapsed + 1.2, f"T{n}"))
            expect(page.locator("#title")).to_have_text(f"T{n}")
            shown.append(timer_seconds(page))
        steps = [b - a for a, b in zip(shown, shown[1:])]
        assert min(steps) >= 0 and max(steps) <= 1, shown
        # It has caught the dial up: the whole 1.2 s, give or take the cut to whole seconds.
        assert (shown[-1] - start) - elapsed >= 1, shown

    def test_a_large_difference_moves_the_timer_at_once(self, page, hd):
        hd.show(replaying_at(120.0, "T0"))
        page.clock.install()
        open_page(page, hd)
        expect(page.locator("#title")).to_have_text("T0")
        freeze_clock(page)
        page.clock.run_for(3000)
        # Restarted: back to the beginning.
        hd.show(replaying_at(0.5, "T1"))
        expect(page.locator("#title")).to_have_text("T1")
        assert timer_seconds(page) <= 1
        page.clock.run_for(2000)
        assert 2 <= timer_seconds(page) <= 3
        # Another replay, far along.
        hd.show(replaying_at(900.0, "T2"))
        expect(page.locator("#title")).to_have_text("T2")
        assert 900 <= timer_seconds(page) <= 901

    def test_fading_out_freezes_the_timer_and_disables_the_controls(self, page, hd):
        hd.show(hs.SCENARIOS["fading_out"])
        page.clock.install()
        sent = watch_actions(page)
        open_page(page, hd)
        timer = replay_timer(page)
        expect(timer).to_have_text("18:17 / 18:20")
        expect(timer).to_have_class(re.compile("frozen"))
        assert [(item["name"], item["disabled"]) for item in row_layout(page)] == [
            (REWIND, True), (STOP, True), ("timer", False)]
        for label in (REWIND, STOP):
            tap(page, f'#replay-row button[aria-label="{label}"]')
        page.clock.run_for(5000)
        expect(timer).to_have_text("18:17 / 18:20")
        assert sent == []

    def test_a_replay_that_starts_fading_stops_where_the_timer_was(self, page, hd):
        hd.show(replaying_at(120.0, "T0"))
        page.clock.install()
        open_page(page, hd)
        expect(page.locator("#title")).to_have_text("T0")
        freeze_clock(page)
        page.clock.run_for(5000)
        before = timer_seconds(page)
        # The fade's own position is the last one read, some seconds old.
        fading = hs.replay_scenario("f", "fading_out", position=121.0, duration=1100.0, latency=0.0)
        hd.show(fading.with_snapshot(now_playing=NowPlaying("Lounge", "Dire Straits", "T1", 42)))
        expect(page.locator("#title")).to_have_text("T1")
        expect(replay_timer(page)).to_have_class(re.compile("frozen"))
        assert timer_seconds(page) == before
        page.clock.run_for(4000)
        assert timer_seconds(page) == before

    def test_the_timer_follows_the_states_position_with_no_offset_of_its_own(self, page, hd):
        """The state's position is already the heard one; the page shows it."""
        hd.show(hs.replay_scenario("r", "replaying", position=300.0, duration=1100.0, latency=0.3))
        page.clock.install()
        open_page(page, hd)
        freeze_clock(page)
        # Reported 300.0 a second ago: about 301 now, less the 0.3 s start buffer.
        expect(replay_timer(page)).to_have_text(re.compile(r"^5:0[01] / 18:20$"))
        hd.show(hs.replay_scenario("r", "replaying", position=300.0, duration=1100.0, latency=3.5))
        expect(replay_timer(page)).to_have_text(re.compile(r"^4:5[78] / 18:20$"))

    def test_a_replay_just_started_reads_zero_until_the_start_buffer_has_passed(self, page, hd):
        hd.show(hs.replay_scenario("r", "replaying", position=0.0, duration=1100.0, latency=3.5))
        open_page(page, hd)
        expect(replay_timer(page)).to_have_text("0:00 / 18:20")

    def test_an_appliance_without_repeat_has_no_row(self, page, hd):
        base = hs.SCENARIOS["replaying"]
        appliances = tuple(dataclasses.replace(a, repeat_capable=False) for a in base.snapshot.appliances)
        hd.show(base.with_snapshot(appliances=appliances))
        open_page(page, hd)
        assert replay_row(page).locator("*").count() == 0
        expect(replay_row(page)).to_be_hidden()
        hd.show(hs.SCENARIOS["replaying"])
        expect(replay_row(page)).to_be_visible()

    @pytest.mark.parametrize("state", ["idle", "hold", "replaying"])
    def test_repeat_turned_off_on_the_appliance_has_no_row(self, page, hd, state):
        base = hs.replay_scenario("off", state)
        appliances = tuple(
            dataclasses.replace(a, repeat=dataclasses.replace(a.repeat, available=False))
            for a in base.snapshot.appliances)
        hd.show(base.with_snapshot(appliances=appliances))
        open_page(page, hd)
        expect(replay_row(page)).to_be_hidden()
        assert replay_row(page).locator("*").count() == 0

    def test_no_record_yet_has_no_row(self, page, hd):
        assert hs.SCENARIOS["playing_artwork"].snapshot.appliances[0].repeat is None
        open_page(page, hd)
        expect(replay_row(page)).to_be_hidden()

    def test_a_held_recording_elsewhere_is_replayed_by_focusing_it(self, page, hd):
        base = hs.SCENARIOS["replay_elsewhere"]
        lounge = dataclasses.replace(
            base.snapshot.appliances[1], playing=False, repeat=hs.repeat_record("hold", recording=600.0))
        hd.show(base.with_snapshot(appliances=(base.snapshot.appliances[0], lounge)))
        sent = watch_actions(page)
        open_page(page, hd)
        lounge_row = rows(page).filter(has_text="Lounge")
        expect(lounge_row.locator(".badge")).to_have_text("Replay 10:00")
        expect(replay_row(page)).to_be_hidden()
        lounge_row.click()
        assert sent == [("focus", {"appliance_id": LOUNGE})]
        hd.show(hs.SCENARIOS["replay_hold"])
        expect(replay_button(page, PLAY)).to_be_enabled()

    def test_stop_leaves_the_focus_alone(self, page, hd):
        hd.show(hs.SCENARIOS["replaying"])
        sent = watch_actions(page)
        open_page(page, hd)
        replay_button(page, STOP).click()
        page.wait_for_timeout(150)
        hd.show(hs.SCENARIOS["playing_artwork"])
        expect(rows(page).first).to_have_attribute("aria-current", "true")
        expect(page.locator("#title")).to_have_text("Tunnel of Love")
        assert only(sent, "focus") == []

    def test_the_controls_are_disabled_while_the_appliance_does_not_answer(self, page, hd):
        base = hs.SCENARIOS["replay_hold"]
        appliances = tuple(dataclasses.replace(a, status_error="timeout") for a in base.snapshot.appliances)
        hd.show(base.with_snapshot(appliances=appliances))
        open_page(page, hd)
        expect(replay_button(page, PLAY)).to_be_disabled()
        expect(replay_button(page, STOP)).to_be_disabled()
        running = hs.SCENARIOS["replaying"]
        appliances = tuple(dataclasses.replace(a, status_error="timeout") for a in running.snapshot.appliances)
        hd.show(running.with_snapshot(appliances=appliances))
        expect(replay_button(page, REWIND)).to_be_disabled()
        expect(replay_button(page, STOP)).to_be_disabled()
        playing = hs.replay_scenario("r", "recording")
        appliances = tuple(dataclasses.replace(a, status_error="timeout") for a in playing.snapshot.appliances)
        hd.show(playing.with_snapshot(appliances=appliances))
        expect(page.locator("#replay-row .repeat-arm input")).to_be_disabled()


STOP_URL = "**/api/v1/actions/replay_stop"


def answer_stop(page, body=None, status=200) -> list:
    """Answer the page's Stop itself (so that neither backend moves on to
    another state), and return the requests it saw."""
    seen: list = []

    def handler(route):
        seen.append(route.request.post_data_json)
        route.fulfill(status=status, content_type="application/json",
                      body=json.dumps(body if body is not None else {"ok": True}))

    page.route(STOP_URL, handler)
    return seen


def running_at_five_minutes(page, hd):
    hd.show(replaying_at(300.0, "T0"))
    page.clock.install()
    open_page(page, hd)
    expect(page.locator("#title")).to_have_text("T0")
    freeze_clock(page)
    page.clock.run_for(3000)
    return timer_seconds(page)


class TestStop:
    def test_pressing_stop_freezes_the_timer_and_greys_the_controls_at_once(self, page, hd):
        seen = answer_stop(page)
        shown = running_at_five_minutes(page, hd)
        assert shown >= 302
        replay_button(page, STOP).click()
        assert [(item["name"], item["disabled"]) for item in row_layout(page)] == [
            (REWIND, True), (STOP, True), ("timer", False)]
        expect(replay_timer(page)).to_have_class(re.compile("frozen"))
        assert timer_seconds(page) == shown
        page.clock.run_for(1500)
        assert timer_seconds(page) == shown
        assert seen == [{"appliance_id": LOUNGE}]

    def test_it_stays_frozen_as_later_states_still_say_replaying(self, page, hd):
        answer_stop(page)
        shown = running_at_five_minutes(page, hd)
        replay_button(page, STOP).click()
        page.clock.run_for(500)
        # The appliance has not caught up: its states still say replaying, further on.
        for n, position in enumerate((304.0, 305.5), start=1):
            hd.show(replaying_at(position, f"T{n}"))
            expect(page.locator("#title")).to_have_text(f"T{n}")
            assert timer_seconds(page) == shown
            expect(replay_button(page, STOP)).to_be_disabled()
            expect(replay_button(page, REWIND)).to_be_disabled()
            page.clock.run_for(300)
            assert timer_seconds(page) == shown

    def test_it_resets_to_the_hold_row_once_the_appliance_has_stopped(self, page, hd):
        answer_stop(page)
        running_at_five_minutes(page, hd)
        replay_button(page, STOP).click()
        hd.show(hs.replay_scenario("h", "hold", recording=1122.0))
        expect(replay_timer(page)).to_have_text("0:00 / 18:42")
        expect(replay_timer(page)).not_to_have_class(re.compile("frozen"))
        assert [(item["name"], item["disabled"]) for item in row_layout(page)] == [
            (PLAY, False), (STOP, True), ("timer", False)]
        page.clock.run_for(5000)
        expect(replay_timer(page)).to_have_text("0:00 / 18:42")

    def test_a_fade_that_follows_stays_where_stop_held_the_timer(self, page, hd):
        answer_stop(page)
        shown = running_at_five_minutes(page, hd)
        replay_button(page, STOP).click()
        page.clock.run_for(600)
        fading = hs.replay_scenario("f", "fading_out", position=304.0, duration=1100.0, latency=0.0)
        hd.show(fading.with_snapshot(now_playing=NowPlaying("Lounge", "Dire Straits", "T1", 42)))
        expect(page.locator("#title")).to_have_text("T1")
        assert timer_seconds(page) == shown
        page.clock.run_for(4000)
        assert timer_seconds(page) == shown
        expect(replay_timer(page)).to_have_class(re.compile("frozen"))

    def test_a_refused_stop_toasts_and_the_timer_carries_on(self, page, hd):
        answer_stop(page, {"ok": False, "error": "wrong_state"}, status=409)
        shown = running_at_five_minutes(page, hd)
        replay_button(page, STOP).click()
        expect(page.locator("#toast")).to_have_text("Not possible right now.")
        expect(replay_button(page, STOP)).to_be_enabled()
        expect(replay_button(page, REWIND)).to_be_enabled()
        expect(replay_timer(page)).not_to_have_class(re.compile("frozen"))
        assert timer_seconds(page) >= shown
        before = timer_seconds(page)
        page.clock.run_for(3000)
        assert 2 <= timer_seconds(page) - before <= 4

    def test_a_stop_the_appliance_never_confirms_gives_the_timer_back(self, page, hd):
        answer_stop(page)
        shown = running_at_five_minutes(page, hd)
        replay_button(page, STOP).click()
        page.clock.run_for(1000)
        assert timer_seconds(page) == shown
        page.clock.run_for(1500)
        # The pending window is over: the timer is where the replay now is.
        expect(replay_button(page, STOP)).to_be_enabled()
        expect(replay_timer(page)).not_to_have_class(re.compile("frozen"))
        assert 2 <= timer_seconds(page) - shown <= 3
        page.clock.run_for(3000)
        assert 5 <= timer_seconds(page) - shown <= 6

    def test_the_timer_does_not_step_back_when_it_resumes(self, page, hd):
        answer_stop(page)
        running_at_five_minutes(page, hd)
        replay_button(page, STOP).click()
        seen = [timer_seconds(page)]
        for _ in range(14):
            page.clock.run_for(250)
            seen.append(timer_seconds(page))
        steps = [b - a for a, b in zip(seen, seen[1:])]
        assert min(steps) >= 0, seen

    def test_stop_sends_one_request_however_often_it_is_pressed(self, page, hd):
        seen = answer_stop(page)
        running_at_five_minutes(page, hd)
        replay_button(page, STOP).click()
        replay_button(page, STOP).click(force=True)
        page.clock.run_for(500)
        assert len(seen) == 1


# ---------------------------------------------------------------------------
# The equaliser page
# ---------------------------------------------------------------------------

def eq_scenario(version=2, gains=None):
    """An equaliser state for the Lounge with the given band gains (by id)."""
    gains = gains or {}
    if version == 2:
        bands = tuple(
            EqBand(b.id, b.frequency_hz, gains.get(b.id, 0), b.min_db, b.max_db) for b in hs.SIX_BANDS
        ) + hs.DERIVED_BANDS
    else:
        bands = tuple(
            EqBand(b.id, None, gains.get(b.id, 0), b.min_db, b.max_db) for b in hs.DERIVED_BANDS
        )
    base = hs.SCENARIOS["eq_six"] if version == 2 else hs.SCENARIOS["eq_two"]
    return base.with_snapshot(eq=EqState(LOUNGE, version, bands, True, (), 0.0))


def open_eq(page):
    page.locator("#eq-open").click()
    expect(page.locator("#eq")).to_be_visible()
    page.wait_for_function("() => document.getElementById('eq').getBoundingClientRect().left === 0")


def band(page, n):
    return page.locator("#eq-bands .eq-band").nth(n)


def graph_image(page) -> str:
    page.wait_for_timeout(120)         # a frame, for the redraw
    return page.evaluate("document.getElementById('eq-graph').toDataURL()")


def curve_y(page, hz):
    """The row of the response curve's line at *hz*: the first pixel in that
    column that is the line's colour, or None. Waits a frame for the redraw."""
    page.wait_for_timeout(120)
    return page.evaluate(
        """(hz) => {
            const c = document.getElementById('eq-graph');
            const w = c.clientWidth, dpr = c.width / w;
            const pw = w - 34 - 10;
            const x = Math.round((34 + pw * Math.log(hz / 20) / Math.log(1000)) * dpr);
            const data = c.getContext('2d').getImageData(x, 0, 1, c.height).data;
            for (let y = 0; y < c.height; y++) {
                const r = data[y * 4], g = data[y * 4 + 1], b = data[y * 4 + 2];
                if (r > 60 && r < 105 && g > 130 && g < 175 && b > 190 && b < 235) { return y / dpr; }
            }
            return null;
        }""",
        hz,
    )


def zero_y(page) -> float:
    h = page.evaluate("document.getElementById('eq-graph').clientHeight")
    return 10 + (h - 32) / 2


class TestEqPage:
    def test_six_bands_labelled_by_frequency_beside_the_graph(self, page, hd):
        open_page(page, hd)
        expect(page.locator("#eq")).to_be_hidden()
        open_eq(page)
        expect(page.locator(".eq-title")).to_contain_text("Equaliser")
        expect(page.locator("#eq-for")).to_have_text("Lounge")
        labels = page.locator("#eq-bands .eq-band-freq").all_text_contents()
        assert labels == ["40Hz", "100Hz", "300Hz", "1kHz", "4kHz", "10kHz"]
        values = page.locator("#eq-bands .eq-band-val").all_text_contents()
        assert values == ["+2 dB", "0 dB", "-1 dB", "0 dB", "+3 dB", "+1 dB"]
        sliders = page.locator("#eq-bands input")
        assert sliders.count() == 6
        assert [sliders.nth(i).input_value() for i in range(6)] == ["2", "0", "-1", "0", "3", "1"]
        box = page.locator("#eq-graph").bounding_box()
        assert box["width"] > 200 and box["height"] > 150
        sliders_box = sliders.first.bounding_box()
        assert sliders_box["x"] + sliders_box["width"] < box["x"]
        assert sliders_box["height"] > 150

    def test_two_bands_for_a_bass_and_treble_appliance(self, page, hd):
        hd.show(hs.SCENARIOS["eq_two"])
        open_page(page, hd)
        open_eq(page)
        assert page.locator("#eq-bands .eq-band-freq").all_text_contents() == ["Bass", "Treble"]
        assert page.locator("#eq-bands .eq-band-val").all_text_contents() == ["+4 dB", "+1 dB"]
        slider = page.locator("#eq-bands input").first
        assert (slider.get_attribute("min"), slider.get_attribute("max")) == ("-6", "6")
        expect(page.locator("#eq-graph")).to_be_visible()

    def test_no_capability_no_icon_and_no_page(self, page, hd):
        hd.show(hs.SCENARIOS["eq_none"])
        open_page(page, hd)
        expect(page.locator("#eq-open")).to_be_hidden()
        expect(page.locator("#eq")).to_be_hidden()

    def test_back_returns_to_the_main_screen(self, page, hd):
        open_page(page, hd)
        open_eq(page)
        page.locator("#eq-close").click()
        expect(page.locator("#eq")).to_be_hidden()
        expect(page.locator("#volume-row")).to_be_visible()
        open_eq(page)

    def test_the_page_closes_when_the_focus_has_no_equaliser(self, page, hd):
        open_page(page, hd)
        open_eq(page)
        hd.show(hs.SCENARIOS["eq_none"])
        expect(page.locator("#eq")).to_be_hidden()
        hd.show(hs.SCENARIOS["playing_artwork"])
        expect(page.locator("#eq")).to_be_hidden()          # it does not reopen by itself

    def test_dragging_a_band_sends_its_gain_and_follows_the_thumb(self, page, hd):
        sent = watch_actions(page)
        open_page(page, hd)
        open_eq(page)
        drag_input(page, "#eq-bands .eq-band:nth-child(4) input", [3, 4, 5], final=6)
        expect(band(page, 3).locator(".eq-band-val")).to_have_text("+6 dB")
        page.wait_for_timeout(300)
        eq_sent = only(sent, "eq")
        assert eq_sent[0] == ("eq", {"appliance_id": LOUNGE, "gains": {"peq4": 3}})
        assert eq_sent[-1] == ("eq", {"appliance_id": LOUNGE, "gains": {"peq4": 6}})
        assert len(eq_sent) <= 4

    def test_a_finger_drag_on_a_slider(self, page, hd):
        sent = watch_actions(page)
        open_page(page, hd)
        open_eq(page)
        slider = band(page, 3).locator("input")
        box = slider.bounding_box()
        x = box["x"] + box["width"] / 2
        page.mouse.move(x, box["y"] + box["height"] / 2)
        page.mouse.down()
        page.mouse.move(x, box["y"] + 4, steps=6)
        page.mouse.up()
        page.wait_for_timeout(300)
        final = only(sent, "eq")[-1][1]["gains"]["peq4"]
        assert final >= 10
        expect(band(page, 3).locator(".eq-band-val")).to_have_text(f"+{final} dB")

    def test_the_curve_follows_the_sliders(self, page, hd):
        hd.show(eq_scenario(2))
        open_page(page, hd)
        open_eq(page)
        flat = graph_image(page)
        # A little off the band's centre, where its own marker does not hide the line.
        flat_y = curve_y(page, 1300)
        assert flat_y is not None and abs(flat_y - zero_y(page)) <= 3
        drag_input(page, "#eq-bands .eq-band:nth-child(4) input", [], final=12)
        assert graph_image(page) != flat
        assert curve_y(page, 1300) <= zero_y(page) - 40       # a boost rises well above the zero line
        assert abs(curve_y(page, 20) - zero_y(page)) <= 4     # far from the band: flat
        drag_input(page, "#eq-bands .eq-band:nth-child(4) input", [], final=-12)
        assert curve_y(page, 1300) >= zero_y(page) + 40       # a cut dips well below it

    def test_shelves_lift_their_own_end(self, page, hd):
        hd.show(eq_scenario(2))
        open_page(page, hd)
        open_eq(page)
        drag_input(page, "#eq-bands .eq-band:nth-child(1) input", [], final=12)
        assert curve_y(page, 20) <= zero_y(page) - 80 and abs(curve_y(page, 7000) - zero_y(page)) <= 4
        drag_input(page, "#eq-bands .eq-band:nth-child(1) input", [], final=0)
        drag_input(page, "#eq-bands .eq-band:nth-child(6) input", [], final=12)
        assert curve_y(page, 18000) <= zero_y(page) - 80 and abs(curve_y(page, 20) - zero_y(page)) <= 4

    def test_the_two_slider_curve_uses_the_bands_the_appliance_moves(self, page, hd):
        hd.show(eq_scenario(1, {"bass": 6}))
        open_page(page, hd)
        open_eq(page)
        assert curve_y(page, 20) < zero_y(page) - 10          # bass lifts the low end
        assert abs(curve_y(page, 7000) - zero_y(page)) <= 4
        hd.show(eq_scenario(1, {"treble": 6}))
        assert curve_y(page, 18000) < zero_y(page) - 6        # treble lifts the top
        assert abs(curve_y(page, 20) - zero_y(page)) <= 4

    def test_reset_sends_one_request_and_flattens_at_once(self, page, hd):
        hd.show(eq_scenario(2))
        sent = watch_actions(page)
        open_page(page, hd)
        open_eq(page)
        drag_input(page, "#eq-bands .eq-band:nth-child(2) input", [], final=9)
        page.locator("#eq-reset").click()
        values = page.locator("#eq-bands .eq-band-val").all_text_contents()
        assert values == ["0 dB"] * 6
        assert only(sent, "eq_reset") == [("eq_reset", {"appliance_id": LOUNGE})]
        assert abs(curve_y(page, 1300) - zero_y(page)) <= 3

    def test_reset_then_the_same_drag_is_sent_again(self, page, hd):
        hd.show(eq_scenario(2))
        sent = watch_actions(page)
        open_page(page, hd)
        open_eq(page)
        slider = "#eq-bands .eq-band:nth-child(2) input"
        drag_input(page, slider, [], final=5)
        page.locator("#eq-reset").click()
        drag_input(page, slider, [], final=5)
        page.wait_for_timeout(150)
        assert [b["gains"] for n, b in sent if n == "eq"] == [{"peq2": 5}, {"peq2": 5}]

    def test_an_unconfirmed_drag_rolls_back(self, page, hd):
        hd.show(eq_scenario(2))
        page.clock.install()
        open_page(page, hd)
        open_eq(page)
        drag_input(page, "#eq-bands .eq-band:nth-child(2) input", [], final=7)
        expect(band(page, 1).locator(".eq-band-val")).to_have_text("+7 dB")
        page.clock.run_for(2500)
        expect(band(page, 1).locator(".eq-band-val")).to_have_text("0 dB")

    def test_a_new_state_moves_the_sliders(self, page, hd):
        hd.show(eq_scenario(2))
        open_page(page, hd)
        open_eq(page)
        hd.show(eq_scenario(2, {"peq6": 4, "peq1": -3}))
        expect(band(page, 5).locator(".eq-band-val")).to_have_text("+4 dB")
        expect(band(page, 0).locator(".eq-band-val")).to_have_text("-3 dB")
        assert band(page, 5).locator("input").input_value() == "4"

    def test_markup_in_a_band_label_stays_text(self, page, hd):
        evil = "<img src=x onerror=alert(1)>"
        base = eq_scenario(2)
        bands = (dataclasses.replace(base.snapshot.eq.bands[0], id=evil),) + base.snapshot.eq.bands[1:]
        hd.show(base.with_snapshot(eq=dataclasses.replace(base.snapshot.eq, bands=bands)))
        open_page(page, hd)
        open_eq(page)
        assert page.locator("#eq img").count() == 0

    @pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s[0]}x{s[1]}")
    def test_layout_at_each_size(self, page, hd, size):
        open_page(page, hd, size)
        open_eq(page)
        width, height = size
        for selector in ("#eq-close", "#eq-reset", "#eq-graph", "#eq-bands"):
            box = page.locator(selector).bounding_box()
            assert box["x"] >= 0 and box["y"] >= 0
            assert box["x"] + box["width"] <= width and box["y"] + box["height"] <= height
        assert page.locator("#eq-close").bounding_box()["height"] >= 55
        assert page.locator("#eq-reset").bounding_box()["height"] >= 44
        assert page.evaluate("[document.documentElement.scrollWidth, document.documentElement.scrollHeight]") \
            == [width, height]


# ---------------------------------------------------------------------------
# The pull-down
# ---------------------------------------------------------------------------

def open_sheet(page):
    page.locator("#handle").click()
    expect(page.locator("#sheet")).to_be_visible()
    page.wait_for_function("() => document.getElementById('sheet').getBoundingClientRect().top === 0")


class TestPullDown:
    @pytest.fixture(autouse=True)
    def restore_settings(self, hd):
        yield
        post_settings(hd.url, {"brightness": 80, "sleep_after_s": 300, "always_show_controls": False})

    def test_the_handle_opens_it_and_shows_the_current_settings(self, page, hd):
        open_page(page, hd)
        expect(page.locator("#sheet")).to_be_hidden()
        open_sheet(page)
        expect(page.locator("#sheet")).to_be_visible()
        panel = current_state(page)["panel"]
        expect(page.locator("#brightness")).to_have_value(str(panel["brightness"]))
        expect(page.locator("#brightness-num")).to_have_text(str(panel["brightness"]))
        pressed = page.locator("#sleep-after button[aria-pressed=true]")
        expect(pressed).to_have_text("5 min")
        assert page.locator("#sleep-after button").all_text_contents() == ["1 min", "5 min", "15 min", "Never"]
        expect(page.locator("#always")).not_to_be_checked()
        expect(page.locator("#sleep-now")).to_be_visible()

    def test_this_dial_lists_the_details_from_the_info_route(self, page, hd):
        open_page(page, hd)
        open_sheet(page)
        expect(page.locator("#info .info-row")).to_have_count(7)
        first = page.locator("#info .info-row").first
        expect(first.locator("dt")).to_have_text("Dial name")
        expect(first.locator("dd")).to_have_text("Lounge dial")
        assert page.locator("#info .info-row dt").all_text_contents() == [
            "Dial name", "Firmware", "IPv4", "WiFi", "Signal", "Disk free", "SD health"]

    def test_details_that_cannot_be_fetched_say_so(self, page, hd):
        page.route("**/api/v1/info", lambda route: route.fulfill(status=500, body="{}"))
        open_page(page, hd)
        open_sheet(page)
        expect(page.locator("#info-note")).to_have_text("Details are not available.")

    def test_dragging_the_handle_down_opens_and_dragging_the_sheet_up_closes(self, page, hd):
        open_page(page, hd)
        x, y = centre(page, "#handle")
        page.mouse.move(x, y)
        page.mouse.down()
        page.mouse.move(x, y + 160, steps=6)
        page.mouse.up()
        expect(page.locator("#sheet")).to_be_visible()
        expect(page.locator("#handle")).to_have_attribute("aria-expanded", "true")
        page.mouse.move(417, 150)           # the sheet's own background, between its columns
        page.mouse.down()
        page.mouse.move(417, 20, steps=6)
        page.mouse.up()
        expect(page.locator("#sheet")).to_be_hidden()

    def test_a_short_drag_does_not_open_it(self, page, hd):
        open_page(page, hd)
        x, y = centre(page, "#handle")
        page.mouse.move(x, y)
        page.mouse.down()
        page.mouse.move(x, y + 25, steps=3)
        page.mouse.up()
        page.wait_for_timeout(400)
        expect(page.locator("#sheet")).to_be_hidden()

    def test_the_dimmed_area_closes_it(self, page, hd):
        open_page(page, hd)
        open_sheet(page)
        expect(page.locator("#sheet")).to_be_visible()
        page.mouse.click(700, 450)
        expect(page.locator("#sheet")).to_be_hidden()

    def test_nothing_underneath_is_reachable_while_it_is_open(self, page, hd):
        sent = watch_actions(page)
        open_page(page, hd)
        open_sheet(page)
        expect(page.locator("#sheet")).to_be_visible()
        tap(page, "#mute")
        page.wait_for_timeout(200)
        assert sent == []

    def test_brightness_posts_while_dragging_and_at_the_end(self, page, hd):
        sent = watch_posts(page)
        open_page(page, hd)
        open_sheet(page)
        drag_input(page, "#brightness", [60, 65, 70], final=75)
        expect(page.locator("#brightness-num")).to_have_text("75")
        page.wait_for_timeout(300)
        posts = only(sent, "settings")
        assert posts[0] == ("settings", {"brightness": 60})
        assert posts[-1] == ("settings", {"brightness": 75})
        page.wait_for_function("() => fetch('/api/v1/state').then(r => r.json()).then(s => s.panel.brightness === 75)")
        page.wait_for_timeout(300)
        expect(page.locator("#brightness-num")).to_have_text("75")

    def test_sleep_after_posts_the_chosen_seconds(self, page, hd):
        sent = watch_posts(page)
        open_page(page, hd)
        open_sheet(page)
        page.locator("#sleep-after button", has_text="15 min").click()
        expect(page.locator("#sleep-after button[aria-pressed=true]")).to_have_text("15 min")
        page.locator("#sleep-after button", has_text="Never").click()
        page.wait_for_timeout(200)
        assert only(sent, "settings") == [("settings", {"sleep_after_s": 900}), ("settings", {"sleep_after_s": 0})]
        page.wait_for_function("() => fetch('/api/v1/state').then(r => r.json()).then(s => s.panel.sleep_after_s === 0)")
        expect(page.locator("#sleep-after button[aria-pressed=true]")).to_have_text("Never")

    def test_always_show_controls_posts_and_sticks(self, page, hd):
        sent = watch_posts(page)
        open_page(page, hd)
        open_sheet(page)
        page.locator("#always").locator("xpath=..").click()
        expect(page.locator("#always")).to_be_checked()
        page.wait_for_function("() => fetch('/api/v1/state').then(r => r.json()).then(s => s.panel.always_show_controls === true)")
        assert only(sent, "settings") == [("settings", {"always_show_controls": True})]
        page.wait_for_timeout(300)
        expect(page.locator("#always")).to_be_checked()

    def test_a_refused_setting_snaps_back(self, page, hd):
        page.route("**/api/v1/settings", lambda route: route.fulfill(
            status=400, content_type="application/json", body=json.dumps({"ok": False, "error": "invalid_field"})))
        open_page(page, hd)
        open_sheet(page)
        page.locator("#sleep-after button", has_text="1 min").click()
        expect(page.locator("#sleep-after button[aria-pressed=true]")).to_have_text("5 min")

    def test_sleep_now_closes_it_and_puts_the_panel_to_sleep(self, page, hd):
        sent = watch_posts(page)
        open_page(page, hd)
        open_sheet(page)
        page.locator("#sleep-now").click()
        expect(page.locator("#sleep")).to_have_class(re.compile("on"))
        expect(page.locator("#sheet")).to_be_hidden()
        assert only(sent, "panel_sleep") == [("panel_sleep", {})]

    def test_without_a_backlight_the_screen_is_dimmed_by_the_setting(self, page, hd):
        hd.show(dataclasses.replace(
            hs.SCENARIOS["playing_artwork"], panel={**hs.PANEL_AWAKE, "backlight": "none", "brightness": 30}))
        if hd.kind == "real":
            post_settings(hd.url, {"brightness": 30})
        open_page(page, hd)
        expect(page.locator("#app")).to_have_class(re.compile("dimmed"))
        filter_value = page.evaluate("getComputedStyle(document.getElementById('app')).filter")
        assert abs(float(re.fullmatch(r"brightness\(([0-9.]+)\)", filter_value).group(1)) - 0.545) < 0.002

    def test_with_a_backlight_the_screen_is_not_dimmed(self, page, hd):
        open_page(page, hd)
        assert page.evaluate("getComputedStyle(document.getElementById('app')).filter") == "none"
        expect(page.locator("#app")).not_to_have_class(re.compile("dimmed"))

    @pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s[0]}x{s[1]}")
    def test_layout_at_each_size(self, page, hd, size):
        open_page(page, hd, size)
        open_sheet(page)
        expect(page.locator("#sheet")).to_be_visible()
        width, height = size
        sheet = page.locator("#sheet").bounding_box()
        assert sheet["y"] >= -1 and sheet["y"] + sheet["height"] <= height and sheet["width"] == width
        for selector in ("#sleep-now", "#sleep-after", "#brightness", "#always", "#info"):
            box = page.locator(selector).bounding_box()
            assert box["x"] >= 0 and box["x"] + box["width"] <= width, selector
            assert box["y"] + box["height"] <= sheet["y"] + sheet["height"], selector
        for button in page.locator("#sleep-after button").all():
            assert button.bounding_box()["height"] >= 44
        assert page.locator("#sleep-now").bounding_box()["height"] >= 44


# ---------------------------------------------------------------------------
# Warning and notice cards
# ---------------------------------------------------------------------------

def modal_card(page):
    return page.locator("#modal")


def with_recovery(base, active=True, confirmed=False):
    return dataclasses.replace(base, recovery=(active, confirmed))


def lounge_warning_while_on_kitchen(*, snoozed=False, dismissal="week"):
    """The Lounge has a stylus warning while the Kitchen is the focus."""
    base = hs.SCENARIOS["appliance_warning" if dismissal == "week" else "appliance_warning_notice"]
    kitchen = hs.appliance(KITCHEN, "Kitchen", playing=True, master_volume=35, muted=False)
    changes = dict(
        appliances=(kitchen, base.snapshot.appliances[0]),
        focus=FocusState(None, KITCHEN, None, KITCHEN, "Kitchen", None, False),
        now_playing=NowPlaying("Kitchen", "Joni Mitchell", "Blue", 35, album="Blue"),
        volume_readout=("Kitchen", 35), artwork=None,
    )
    if snoozed:
        changes["warnings"] = tuple(
            dataclasses.replace(w, snoozed_until=hs.WALL_NOW + 3600) if w.id == LOUNGE_STYLUS else w
            for w in base.snapshot.warnings)
    return base.with_snapshot(**changes)


class TestDialWarnings:
    def test_no_wifi_has_dismiss_and_restart(self, page, hd):
        hd.show(hs.SCENARIOS["warning_nowifi"])
        sent = watch_actions(page)
        open_page(page, hd)
        expect(modal_card(page)).to_be_visible()
        expect(page.locator("#card-title")).to_have_text("No WiFi")
        assert page.locator("#card-buttons button").all_text_contents() == ["Dismiss", "Restart"]
        expect(page.locator("#card-progress")).to_be_hidden()
        page.locator("#card-buttons button", has_text="Restart").click()
        page.wait_for_timeout(150)
        assert sent == [("dial_restart", {})]
        page.locator("#card-buttons button", has_text="Dismiss").click()
        page.wait_for_timeout(150)
        assert sent[-1] == ("warning_dismiss", {"warning_id": "nowifi"})

    def test_a_card_with_buttons_is_not_closed_by_the_dimmed_area(self, page, hd):
        hd.show(hs.SCENARIOS["warning_nowifi"])
        sent = watch_actions(page)
        open_page(page, hd)
        page.mouse.click(20, 460)
        page.wait_for_timeout(200)
        expect(modal_card(page)).to_be_visible()
        assert sent == []

    def test_sd_health(self, page, hd):
        hd.show(hs.SCENARIOS["warning_sdhealth"])
        sent = watch_actions(page)
        open_page(page, hd)
        expect(page.locator("#card-title")).to_have_text("microSD Health")
        expect(page.locator("#card-message")).to_have_text("6%: Replace Soon")
        assert page.locator("#card-buttons button").all_text_contents() == ["Dismiss"]
        page.locator("#card-buttons button").click()
        page.wait_for_timeout(150)
        assert sent == [("warning_dismiss", {"warning_id": "sdhealth"})]

    def test_the_update_progress_card_cannot_be_dismissed(self, page, hd):
        hd.show(hs.SCENARIOS["warning_update"])
        sent = watch_actions(page)
        open_page(page, hd)
        expect(page.locator("#card-title")).to_have_text("Updating...")
        expect(page.locator("#card-message")).to_have_text("Installing")
        expect(page.locator("#card-progress")).to_be_visible()
        assert page.evaluate("document.getElementById('card-bar').style.getPropertyValue('--fill')") == "40%"
        assert page.locator("#card-buttons button").count() == 0
        page.mouse.click(20, 460)
        page.keyboard.press("Escape")
        page.wait_for_timeout(200)
        expect(modal_card(page)).to_be_visible()
        assert sent == []

    def test_progress_moves_with_the_state(self, page, hd):
        hd.show(hs.SCENARIOS["warning_update"])
        open_page(page, hd)
        base = hs.SCENARIOS["warning_update"]
        update = dataclasses.replace(base.snapshot.update, percent=80)
        states = tuple(dataclasses.replace(w, severity=update) if w.id == "update" else w
                       for w in base.snapshot.warnings)
        hd.show(base.with_snapshot(update=update, warnings=states))
        page.wait_for_function(
            "() => document.getElementById('card-bar').style.getPropertyValue('--fill') === '80%'")

    def test_the_update_result_can_be_dismissed(self, page, hd):
        hd.show(hs.SCENARIOS["warning_update_result"])
        sent = watch_actions(page)
        open_page(page, hd)
        expect(page.locator("#card-title")).to_have_text("Updated")
        expect(page.locator("#card-message")).to_have_text("Version 0.8.0")
        page.locator("#card-buttons button", has_text="Dismiss").click()
        page.wait_for_timeout(150)
        assert sent == [("warning_dismiss", {"warning_id": "update_result"})]

    def test_the_card_goes_when_the_state_says_so(self, page, hd):
        hd.show(hs.SCENARIOS["warning_sdhealth"])
        open_page(page, hd)
        expect(modal_card(page)).to_be_visible()
        hd.show(hs.SCENARIOS["nothing_playing"])
        expect(modal_card(page)).to_be_hidden()

    def test_the_card_covers_the_controls(self, page, hd):
        hd.show(hs.SCENARIOS["warning_sdhealth"])
        sent = watch_actions(page)
        open_page(page, hd)
        tap(page, "#mute")
        tap(page, "#appliances .appliance")
        page.wait_for_timeout(200)
        assert sent == []

    def test_markup_in_a_warning_stays_text(self, page, hd):
        evil = "<img src=x onerror=alert(1)>"
        base = hs.SCENARIOS["appliance_warning"]
        warning = dataclasses.replace(base.snapshot.appliances[0].warnings[0], title=evil, message=evil)
        appliance = dataclasses.replace(base.snapshot.appliances[0], warnings=(warning,))
        hd.show(dataclasses.replace(
            base, snapshot=dataclasses.replace(base.snapshot, appliances=(appliance,)),
            descriptors=hs.WARNING_DESCRIPTORS + (hs.appliance_warning_descriptor(LOUNGE, warning),)))
        open_page(page, hd)
        expect(page.locator("#card-title")).to_have_text(evil)
        assert page.locator("#modal img").count() == 0

    @pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s[0]}x{s[1]}")
    @pytest.mark.parametrize("name", ["warning_nowifi", "warning_update", "appliance_warning", "recovery_pending"])
    def test_the_card_fits_the_screen(self, page, hd, name, size):
        hd.show(hs.SCENARIOS[name])
        open_page(page, hd, size)
        expect(modal_card(page)).to_be_visible()
        box = page.locator("#card").bounding_box()
        assert box["x"] >= 0 and box["y"] >= 0
        assert box["x"] + box["width"] <= size[0] and box["y"] + box["height"] <= size[1]
        for button in page.locator("#card-buttons button").all():
            assert button.bounding_box()["height"] >= 44


class TestApplianceWarnings:
    def test_the_focused_appliance_shows_its_card(self, page, hd):
        hd.show(hs.SCENARIOS["appliance_warning"])
        sent = watch_actions(page)
        open_page(page, hd)
        expect(modal_card(page)).to_be_visible()
        expect(page.locator("#card-title")).to_have_text("Technics stylus")
        expect(page.locator("#card-message")).to_have_text("Needs changing soon.")
        expect(page.locator("#card-source")).to_have_text("Lounge")
        assert page.locator("#card-buttons button").all_text_contents() == ["Dismiss"]
        page.locator("#card-buttons button").click()
        page.wait_for_timeout(150)
        assert sent == [("warning_dismiss", {"warning_id": LOUNGE_STYLUS})]

    def test_a_notice_has_an_ok_button(self, page, hd):
        hd.show(hs.SCENARIOS["appliance_warning_notice"])
        sent = watch_actions(page)
        open_page(page, hd)
        assert page.locator("#card-buttons button").all_text_contents() == ["OK"]
        page.locator("#card-buttons button").click()
        page.wait_for_timeout(150)
        assert sent == [("warning_dismiss", {"warning_id": LOUNGE_STYLUS})]

    def test_the_row_carries_a_badge_with_the_count(self, page, hd):
        hd.show(hs.SCENARIOS["appliance_warning"])
        open_page(page, hd)
        badge = rows(page).first.locator(".warn-badge")
        expect(badge).to_be_visible()
        expect(badge).to_have_text("1")
        expect(badge).to_have_class(re.compile("sev-warning"))

    def test_a_critical_warning_colours_the_badge(self, page, hd):
        base = hs.SCENARIOS["appliance_warning"]
        warning = dataclasses.replace(base.snapshot.appliances[0].warnings[0], severity="critical")
        appliance = dataclasses.replace(base.snapshot.appliances[0], warnings=(warning,))
        hd.show(dataclasses.replace(
            base, snapshot=dataclasses.replace(base.snapshot, appliances=(appliance,)),
            descriptors=hs.WARNING_DESCRIPTORS + (hs.appliance_warning_descriptor(LOUNGE, warning),)))
        open_page(page, hd)
        expect(rows(page).first.locator(".warn-badge")).to_have_class(re.compile("sev-critical"))
        colour = page.evaluate(
            "getComputedStyle(document.querySelector('.warn-badge')).backgroundColor")
        assert colour == page.evaluate(
            "(() => { const d = document.createElement('div');"
            " d.style.color = getComputedStyle(document.documentElement).getPropertyValue('--color-status-danger');"
            " document.body.appendChild(d); const c = getComputedStyle(d).color; d.remove(); return c; })()")

    def test_another_appliances_warning_is_a_badge_until_tapped(self, page, hd):
        hd.show(lounge_warning_while_on_kitchen())
        sent = watch_actions(page)
        open_page(page, hd)
        lounge = rows(page).filter(has_text="Lounge")
        expect(lounge.locator(".warn-badge")).to_have_text("1")
        expect(rows(page).filter(has_text="Kitchen").locator(".warn-badge")).to_be_hidden()
        expect(modal_card(page)).to_be_hidden()
        lounge.locator(".warn-badge").click()
        expect(modal_card(page)).to_be_visible()
        expect(page.locator("#card-title")).to_have_text("Technics stylus")
        assert sent == []                                   # the badge does not focus the row
        page.mouse.click(20, 460)                           # the dimmed area closes a card nobody is owed
        expect(modal_card(page)).to_be_hidden()
        lounge.click()
        assert sent == [("focus", {"appliance_id": LOUNGE})]

    def test_a_card_opened_from_its_badge_can_be_dismissed(self, page, hd):
        hd.show(lounge_warning_while_on_kitchen())
        sent = watch_actions(page)
        open_page(page, hd)
        rows(page).filter(has_text="Lounge").locator(".warn-badge").click()
        page.locator("#card-buttons button", has_text="Dismiss").click()
        page.wait_for_timeout(150)
        assert sent == [("warning_dismiss", {"warning_id": LOUNGE_STYLUS})]
        expect(modal_card(page)).to_be_hidden()

    def test_a_snoozed_warning_has_no_badge_and_no_card(self, page, hd):
        hd.show(lounge_warning_while_on_kitchen(snoozed=True))
        open_page(page, hd)
        expect(rows(page).filter(has_text="Lounge").locator(".warn-badge")).to_be_hidden()
        expect(modal_card(page)).to_be_hidden()

    def test_the_card_shows_when_the_warning_appliance_becomes_the_focus(self, page, hd):
        hd.show(lounge_warning_while_on_kitchen())
        open_page(page, hd)
        expect(modal_card(page)).to_be_hidden()
        hd.show(hs.SCENARIOS["appliance_warning"])
        expect(modal_card(page)).to_be_visible()


class TestNoticeAndPresence:
    def test_not_authorised_shows_the_allow_card(self, page, hd):
        hd.show(hs.SCENARIOS["unauthorized"])
        sent = watch_actions(page)
        open_page(page, hd)
        expect(modal_card(page)).to_be_hidden()
        rows(page).filter(has_text="Kitchen").click()
        expect(modal_card(page)).to_be_visible()
        expect(page.locator("#card-title")).to_have_text("Not authorised")
        expect(page.locator("#card-message")).to_have_text("Allow this dial in Kitchen's web UI (Setup, Dials)")
        expect(page.locator("#card-source")).to_have_text("http://192.0.2.20:80/")
        assert page.locator("#card-buttons button").all_text_contents() == ["OK"]
        page.locator("#card-buttons button").click()
        expect(modal_card(page)).to_be_hidden()
        assert sent == []

    def test_the_dimmed_area_closes_the_allow_card(self, page, hd):
        hd.show(hs.SCENARIOS["unauthorized"])
        open_page(page, hd)
        rows(page).filter(has_text="Kitchen").click()
        expect(modal_card(page)).to_be_visible()
        page.mouse.click(20, 460)
        expect(modal_card(page)).to_be_hidden()

    def test_the_allow_card_ends_when_the_appliance_is_authorised(self, page, hd):
        hd.show(hs.SCENARIOS["unauthorized"])
        open_page(page, hd)
        rows(page).filter(has_text="Kitchen").click()
        expect(modal_card(page)).to_be_visible()
        hd.show(hs.SCENARIOS["replay_elsewhere"])
        expect(modal_card(page)).to_be_hidden()

    def test_presence_card_with_a_confirm_button(self, page, hd):
        hd.show(hs.SCENARIOS["recovery_pending"])
        sent = watch_actions(page)
        open_page(page, hd)
        expect(modal_card(page)).to_be_visible()
        expect(page.locator("#card-title")).to_have_text("Confirm you are at the dial")
        assert page.locator("#card-buttons button").all_text_contents() == ["Confirm"]
        page.mouse.click(20, 460)
        page.keyboard.press("Escape")
        page.wait_for_timeout(200)
        expect(modal_card(page)).to_be_visible()
        page.locator("#card-buttons button").click()
        page.wait_for_timeout(150)
        assert sent == [("presence", {})]

    def test_presence_goes_once_confirmed(self, page, hd):
        hd.show(hs.SCENARIOS["recovery_pending"])
        open_page(page, hd)
        expect(modal_card(page)).to_be_visible()
        hd.show(with_recovery(hs.SCENARIOS["recovery_pending"], True, True))
        expect(modal_card(page)).to_be_hidden()

    def test_presence_outranks_a_warning_and_the_warning_follows(self, page, hd):
        hd.show(with_recovery(hs.SCENARIOS["warning_sdhealth"]))
        open_page(page, hd)
        expect(page.locator("#card-title")).to_have_text("Confirm you are at the dial")
        hd.show(hs.SCENARIOS["warning_sdhealth"])
        expect(page.locator("#card-title")).to_have_text("microSD Health")

    def test_presence_outranks_the_allow_card(self, page, hd):
        hd.show(hs.SCENARIOS["unauthorized"])
        open_page(page, hd)
        rows(page).filter(has_text="Kitchen").click()
        expect(page.locator("#card-title")).to_have_text("Not authorised")
        hd.show(with_recovery(hs.SCENARIOS["unauthorized"]))
        expect(page.locator("#card-title")).to_have_text("Confirm you are at the dial")


# ---------------------------------------------------------------------------
# Sleep, wake and activity
# ---------------------------------------------------------------------------

def asleep_scenario(name="playing_artwork"):
    base = hs.SCENARIOS[name]
    return dataclasses.replace(base, panel={**base.panel, "asleep": True})


class TestSleepShield:
    def test_asleep_draws_a_black_shield(self, page, hd):
        hd.show(asleep_scenario())
        open_page(page, hd)
        shield = page.locator("#sleep")
        expect(shield).to_have_class(re.compile("on"))
        page.wait_for_timeout(700)
        assert page.evaluate("getComputedStyle(document.getElementById('sleep')).opacity") == "1"
        assert page.evaluate("getComputedStyle(document.getElementById('sleep')).backgroundColor") == "rgb(0, 0, 0)"
        box = shield.bounding_box()
        assert (box["x"], box["y"], box["width"], box["height"]) == (0, 0, 800, 480)

    def test_awake_has_no_shield(self, page, hd):
        open_page(page, hd)
        expect(page.locator("#sleep")).not_to_have_class(re.compile("on"))
        assert page.evaluate("getComputedStyle(document.getElementById('sleep')).pointerEvents") == "none"

    def test_the_first_touch_only_wakes_and_reaches_nothing_underneath(self, page, hd):
        hd.show(asleep_scenario())
        sent = watch_posts(page)
        open_page(page, hd)
        expect(page.locator("#sleep")).to_have_class(re.compile("on"))
        tap(page, "#mute")                                    # a control right under the finger
        expect(page.locator("#sleep")).not_to_have_class(re.compile("on"))
        page.wait_for_timeout(200)
        assert sent == [("panel_wake", {})]
        assert page.locator("#mute").get_attribute("aria-pressed") == "false"
        tap(page, "#mute")                                    # the second touch is a press
        page.wait_for_timeout(200)
        assert only(sent, "mute_toggle") == [("mute_toggle", {"appliance_id": LOUNGE})]

    def test_the_shield_stays_until_the_state_says_awake(self, page, hd):
        hd.show(asleep_scenario())
        page.route("**/api/v1/panel/wake", lambda route: route.fulfill(
            status=200, content_type="application/json", body='{"ok":true}'))
        open_page(page, hd)
        tap(page, "#title")
        page.wait_for_timeout(300)
        expect(page.locator("#sleep")).to_have_class(re.compile("on"))
        hd.show(hs.SCENARIOS["playing_artwork"])
        expect(page.locator("#sleep")).not_to_have_class(re.compile("on"))

    def test_touches_on_the_shield_are_not_activity(self, page, hd):
        hd.show(asleep_scenario())
        sent = watch_posts(page)
        open_page(page, hd)
        tap(page, "#title")
        page.wait_for_timeout(300)
        assert only(sent, "panel_activity") == []

    def test_a_card_does_not_hide_the_shield(self, page, hd):
        base = hs.SCENARIOS["warning_sdhealth"]
        hd.show(dataclasses.replace(base, panel={**base.panel, "asleep": True}))
        sent = watch_actions(page)
        open_page(page, hd)
        expect(page.locator("#sleep")).to_have_class(re.compile("on"))
        tap(page, "#card-buttons button")
        page.wait_for_timeout(200)
        expect(page.locator("#modal")).to_be_visible()
        assert sent == []                                     # the card's button was not pressed


class TestPanelActivity:
    def test_the_first_touch_is_reported_and_a_burst_is_not_repeated(self, page, hd):
        sent = watch_posts(page)
        page.clock.install()
        open_page(page, hd)
        for _ in range(4):
            page.locator("#title").click()
        page.wait_for_timeout(200)
        assert only(sent, "panel_activity") == [("panel_activity", {})]

    def test_a_later_touch_is_reported_again(self, page, hd):
        sent = watch_posts(page)
        page.clock.install()
        open_page(page, hd)
        page.locator("#title").click()
        page.clock.run_for(2000)
        page.locator("#title").click()
        page.clock.run_for(4500)
        page.locator("#title").click()
        page.wait_for_timeout(200)
        assert len(only(sent, "panel_activity")) == 2

    def test_a_refused_report_is_quiet(self, page, hd):
        page.route("**/api/v1/panel/activity", lambda route: route.fulfill(
            status=404, content_type="application/json", body='{"ok":false,"error":"not_found"}'))
        open_page(page, hd)
        page.locator("#title").click()
        page.wait_for_timeout(300)
        assert "show" not in (page.locator("#toast").get_attribute("class") or "")

    def test_the_server_sees_the_report(self, page, hd_real):
        hd = Driver("real", hd_real)
        hd.show(hs.SCENARIOS["playing_artwork"])
        before = len(hd_real.panel.calls)
        open_page(page, hd)
        page.locator("#title").click()
        for _ in range(30):
            if "activity" in hd_real.panel.calls[before:]:
                break
            page.wait_for_timeout(50)
        assert "activity" in hd_real.panel.calls[before:]


# ---------------------------------------------------------------------------
# Idle controls
# ---------------------------------------------------------------------------

def art_height(page) -> float:
    return page.locator(".art-frame").bounding_box()["height"]


class TestControlsFade:
    def test_a_playing_screen_left_alone_shows_the_artwork_alone(self, page, hd):
        page.clock.install()
        open_page(page, hd)
        expect(page.locator("#volume-row")).to_be_visible()
        before = art_height(page)
        page.clock.run_for(4000)
        expect(page.locator("#volume-row")).to_be_visible()
        page.clock.run_for(3500)
        expect(page.locator("#right")).to_have_class(re.compile("controls-hidden"))
        for selector in ("#volume-row", ".track-row"):
            expect(page.locator(selector)).to_be_hidden()
        assert art_height(page) > before + 40
        assert art_height(page) <= 480 - 22 - 12

    def test_a_touch_on_the_right_column_brings_them_back(self, page, hd):
        page.clock.install()
        open_page(page, hd)
        page.clock.run_for(7000)
        expect(page.locator("#volume-row")).to_be_hidden()
        page.locator(".art-frame").click()
        expect(page.locator("#volume-row")).to_be_visible()
        page.clock.run_for(4000)
        expect(page.locator("#volume-row")).to_be_visible()
        page.clock.run_for(3000)
        expect(page.locator("#volume-row")).to_be_hidden()

    def test_a_tap_on_the_artwork_toggles_them(self, page, hd):
        open_page(page, hd)
        expect(page.locator("#volume-row")).to_be_visible()
        page.locator(".art-frame").click()
        expect(page.locator("#volume-row")).to_be_hidden()
        page.locator(".art-frame").click()
        expect(page.locator("#volume-row")).to_be_visible()

    def test_a_touch_elsewhere_does_not_bring_them_back(self, page, hd):
        page.clock.install()
        open_page(page, hd)
        page.clock.run_for(7000)
        expect(page.locator("#volume-row")).to_be_hidden()
        # The appliances label band: over the left column but over no card.
        assert page.evaluate("!document.elementFromPoint(60, 34).closest('.appliance, .output-card')")
        page.mouse.click(60, 34)
        page.wait_for_timeout(100)
        expect(page.locator("#volume-row")).to_be_hidden()

    def test_always_show_controls_keeps_them(self, page, hd):
        post_settings(hd.url, {"always_show_controls": True})
        try:
            page.clock.install()
            open_page(page, hd)
            page.clock.run_for(20000)
            expect(page.locator("#volume-row")).to_be_visible()
            expect(page.locator("#right")).not_to_have_class(re.compile("controls-hidden"))
            page.locator(".art-frame").click()
            expect(page.locator("#volume-row")).to_be_visible()
        finally:
            post_settings(hd.url, {"always_show_controls": False})

    def test_nothing_playing_never_hides_them(self, page, hd):
        hd.show(hs.SCENARIOS["nothing_playing"])
        page.clock.install()
        open_page(page, hd)
        page.clock.run_for(20000)
        expect(page.locator("#volume-row")).to_be_visible()

    def test_a_card_keeps_them_and_closing_it_starts_the_time_again(self, page, hd):
        page.clock.install()
        base = hs.SCENARIOS["playing_artwork"]
        hd.show(base.with_snapshot(appliances=(
            base.snapshot.appliances[0], hs.appliance(KITCHEN, "Kitchen", auth=hs.AUTH_UNAUTHORIZED))))
        open_page(page, hd)
        rows(page).filter(has_text="Kitchen").click()
        expect(modal_card(page)).to_be_visible()
        page.clock.run_for(9000)
        expect(page.locator("#right")).not_to_have_class(re.compile("controls-hidden"))
        page.locator("#card-buttons button").click()
        expect(modal_card(page)).to_be_hidden()
        expect(page.locator("#volume-row")).to_be_visible()
        page.clock.run_for(2000)
        expect(page.locator("#volume-row")).to_be_visible()
        page.clock.run_for(5000)
        expect(page.locator("#volume-row")).to_be_hidden()

    def test_the_equaliser_page_keeps_them(self, page, hd):
        page.clock.install()
        open_page(page, hd)
        open_eq(page)
        page.clock.run_for(9000)
        page.locator("#eq-close").click()
        expect(page.locator("#volume-row")).to_be_visible()


# ---------------------------------------------------------------------------
# The event stream is closed when the page goes
# ---------------------------------------------------------------------------

class TestStreamLifetime:
    def test_the_page_closes_its_stream_when_it_is_hidden(self, page, hd):
        page.add_init_script(
            "(() => { const Real = window.EventSource; window.__streams = [];"
            " window.EventSource = function (url) { const s = new Real(url);"
            " window.__streams.push(s); return s; };"
            " window.EventSource.CLOSED = Real.CLOSED; window.EventSource.OPEN = Real.OPEN; })()")
        open_page(page, hd)
        assert page.evaluate("window.__streams.length") == 1
        assert page.evaluate("window.__streams[0].readyState") == 1
        page.evaluate("window.dispatchEvent(new Event('pagehide'))")
        assert page.evaluate("window.__streams[0].readyState") == 2

    def test_leaving_the_page_frees_the_servers_client_slot(self, page, hd_real):
        hd = Driver("real", hd_real)
        hd.show(hs.SCENARIOS["playing_artwork"])

        def settled(count):
            for _ in range(60):
                if hd_real.server.client_count() == count:
                    return True
                page.wait_for_timeout(50)
            return hd_real.server.client_count() == count

        assert settled(0), "streams from earlier tests should have gone"
        open_page(page, hd)
        assert settled(1)
        page.goto("about:blank")
        assert settled(0)
