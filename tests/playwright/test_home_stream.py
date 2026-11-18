"""Playwright tests: the Home page follows the state change stream.

The page comes from the real Home renderer; the stub holds the event stream
open and writes the events a test pushes. With the stream up an idle page
fetches nothing, draws what an event carries, and polls the inputs part only
while a session or a replay is live. Without the stream it reads the whole
state every 2 seconds and tries the stream again after about 30 seconds. A
new boot id replaces the state it holds. The time-based cases drive the
page's clock.
"""
from __future__ import annotations

import re
import time

import pytest
import _home_stub as stub
from _home_stub import start_server
from _home_helpers import SHOWN, intents, open_home, outputs, speaker, wait_for, wait_stream, watch_errors

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

_LIVE = {"session": {"active": True, "source": "input1"}}
_IDLE = {"session": {"active": False, "source": None}}
_FADING = {"session": {"active": False, "source": None},
           "repeat": {"block": {"enabled": True, "replay": {"active": False, "fading_out": True}}}}


@pytest.fixture(scope="module")
def home_url():
    server, url = start_server(b"")
    try:
        yield url
    finally:
        server.shutdown()


@pytest.fixture
def errors(page: "Page"):
    """Console errors and page errors; a case fails if any is left at its end."""
    e = watch_errors(page)
    yield e
    stub.reset_stream()
    stub.REPLY_DELAY_S[0] = 0.0
    assert not e.left(), f"console errors: {e.left()}"


def _fetches(query: str | None = None) -> int:
    return len([q for q in stub.STATE_FETCHES if query is None or q == query])


def _set_hidden(page: "Page", hidden: bool) -> None:
    page.evaluate(
        "(h) => { Object.defineProperty(document, 'hidden', {configurable: true, get: () => h});"
        " Object.defineProperty(document, 'visibilityState', {configurable: true, get: () => h ? 'hidden' : 'visible'});"
        " document.dispatchEvent(new Event('visibilitychange')); }", hidden)


def _wait_connects(page: "Page", count: int, seconds: float = 5.0) -> None:
    wait_for(page, lambda: len(stub.STREAM_CONNECTS) >= count and stub.open_streams() >= 1,
             "the stream to open", seconds)


@_requires_browser
class TestHomeStream:
    def test_an_idle_page_is_quiet(self, page: "Page", home_url: str, errors):
        open_home(page, home_url)
        wait_stream(page)
        page.wait_for_timeout(5000)
        assert _fetches() == 0

    def test_a_speaker_change_made_elsewhere_shows_at_once(self, page: "Page", home_url: str, errors):
        open_home(page, home_url)
        wait_stream(page)
        stub.push({"outputs": outputs(speaker(selected=True))})
        expect(page.locator("#output_enabled_tv")).to_be_checked(timeout=1500)
        page.wait_for_timeout(500)
        assert _fetches() == 0

    def test_parts_the_page_does_not_show_cause_no_fetch_and_no_error(
            self, page: "Page", home_url: str, errors):
        open_home(page, home_url)
        wait_stream(page)
        stub.push({"devices": {"monitor_devices": []}})
        stub.push({"eq": {"output_bands": []}, "health": {}})
        page.wait_for_timeout(1000)
        assert _fetches() == 0

    def test_a_resync_reads_the_whole_state_once(self, page: "Page", home_url: str, errors):
        open_home(page, home_url)
        wait_stream(page)
        stub.PARTS["outputs"] = outputs(speaker(selected=True))
        stub.push(resync=True)
        expect(page.locator("#output_enabled_tv")).to_be_checked(timeout=2000)
        page.wait_for_timeout(500)
        assert stub.STATE_FETCHES == [""]

    def test_a_dropped_stream_is_resumed_without_polling(self, page: "Page", home_url: str, errors):
        open_home(page, home_url)
        wait_stream(page)
        stub.push({"devices": {"monitor_devices": []}})
        page.wait_for_timeout(300)
        last = f"{stub.STREAM['boot']}-{stub.STREAM['version']}"
        stub.drop()
        wait_for(page, lambda: len(stub.STREAM_CONNECTS) >= 2, "the resume", 1.5)
        assert stub.STREAM_CONNECTS[-1]["last_event_id"] == last
        page.wait_for_timeout(4000)
        assert _fetches() == 0

    def test_a_page_opens_its_stream_from_the_version_it_loaded_with(
            self, page: "Page", home_url: str, errors):
        open_home(page, home_url)
        wait_stream(page)
        assert stub.STREAM_CONNECTS[0]["since"] == f"{stub.STREAM['boot']}-{stub.STREAM['version']}"

    @pytest.mark.parametrize("live", [False, True])
    def test_a_hidden_page_holds_no_stream_and_resumes_when_shown(
            self, page: "Page", home_url: str, errors, live: bool):
        open_home(page, home_url, _LIVE if live else _IDLE)
        wait_stream(page)
        stub.push({"devices": {"monitor_devices": []}})
        page.wait_for_timeout(300)
        last = f"{stub.STREAM['boot']}-{stub.STREAM['version']}"
        _set_hidden(page, True)
        wait_for(page, lambda: stub.open_streams() == 0, "the stream to close", 1.5)
        assert stub.STREAM_CONNECTS[-1]["closed_at"] is not None
        before = _fetches()
        page.wait_for_timeout(3000)
        assert _fetches() == before
        _set_hidden(page, False)
        _wait_connects(page, 2)
        assert stub.STREAM_CONNECTS[-1]["since"] == last

    def test_nothing_is_read_on_a_timer_while_the_stream_is_up(
            self, page: "Page", home_url: str, errors):
        page.clock.install()
        open_home(page, home_url)
        wait_stream(page)
        page.clock.run_for(60000)
        page.wait_for_timeout(500)
        assert _fetches() == 0


@_requires_browser
class TestHomeWithoutTheStream:
    def test_a_refused_stream_still_shows_a_change_within_two_seconds_and_returns_later(
            self, page: "Page", home_url: str, errors):
        errors.ignore += ["EventSource", "text/event-stream"]
        page.clock.install()
        open_home(page, home_url)
        wait_stream(page)
        stub.refuse_from_now()
        stub.drop()
        stub.set_parts(outputs=outputs(speaker(selected=True)))
        expect(page.locator("#output_enabled_tv")).to_be_checked(timeout=6000)
        stub.stream_on()
        before = len(stub.STREAM_CONNECTS)
        page.clock.fast_forward(36000)
        wait_for(page, lambda: len(stub.STREAM_CONNECTS) > before and stub.open_streams() >= 1,
                 "the stream to return", 5)
        page.wait_for_timeout(800)
        settled = _fetches()
        page.wait_for_timeout(3500)
        assert _fetches() == settled

    def test_a_page_loaded_without_the_stream_reads_the_state_and_tries_again_later(
            self, page: "Page", home_url: str, errors):
        errors.ignore += ["EventSource", "text/event-stream"]
        page.clock.install()
        open_home(page, home_url, stream=False)
        wait_for(page, lambda: _fetches() >= 3, "three state reads", 8)
        stub.stream_on()
        page.clock.fast_forward(37000)
        wait_for(page, lambda: stub.open_streams() >= 1, "the stream to return", 5)

    def test_a_new_boot_with_a_lower_version_replaces_the_state(
            self, page: "Page", home_url: str, errors):
        errors.ignore += ["EventSource", "text/event-stream"]
        open_home(page, home_url, {"outputs": outputs(speaker(), stub.unit("old", "Old"))}, stream=False)
        page.wait_for_selector("#output_card_old", state="attached")
        stub.new_boot(version=3)
        stub.PARTS["outputs"] = outputs(speaker(selected=True, name="After the restart"))
        expect(page.locator("#output_card_tv .output-card-name")).to_contain_text("After the restart", timeout=6000)
        expect(page.locator("#output_enabled_tv")).to_be_checked()
        assert page.locator(".output-card").count() == 1


@_requires_browser
class TestHomeStartFailureOnTheStream:
    def test_a_start_failure_is_shown_once_after_an_outputs_event(
            self, page: "Page", home_url: str, errors):
        open_home(page, home_url)
        wait_stream(page)
        failure = {"seq": 1, "unit_id": "tv", "name": "Speaker A", "reason": "refused",
                   "at": time.time(), "requester": "webui"}
        stub.push({"outputs": outputs(speaker(), start_failure=failure)})
        modal = page.locator("#infoModal")
        expect(modal).to_have_class(SHOWN, timeout=2000)
        expect(page.locator("#infoModalTitle")).to_have_text("Could not start Speaker A")
        page.locator("#infoModalOk").click()
        stub.push({"outputs": outputs(speaker(), start_failure=failure)})
        page.wait_for_timeout(1000)
        expect(modal).not_to_have_class(SHOWN)


@_requires_browser
class TestHomeControls:
    def test_the_level_meter_polls_the_inputs_while_live_and_stops_when_idle(
            self, page: "Page", home_url: str, errors):
        open_home(page, home_url, show_input_detail=True)
        wait_stream(page)
        page.wait_for_timeout(1500)
        assert _fetches() == 0
        stub.push(_LIVE)
        wait_for(page, lambda: _fetches("parts=inputs") >= 3, "the inputs poll", 6)
        stub.push(_IDLE)
        page.wait_for_timeout(1200)
        settled = _fetches()
        page.wait_for_timeout(3000)
        assert _fetches() == settled

    def test_the_level_meter_keeps_polling_through_a_replay_fade_out(
            self, page: "Page", home_url: str, errors):
        open_home(page, home_url, show_input_detail=True)
        wait_stream(page)
        stub.push(_FADING)
        wait_for(page, lambda: _fetches("parts=inputs") >= 3, "the inputs poll", 6)

    def test_the_inputs_are_not_polled_without_input_detail(
            self, page: "Page", home_url: str, errors):
        open_home(page, home_url)
        wait_stream(page)
        stub.push(_LIVE)
        page.wait_for_timeout(2500)
        assert _fetches() == 0

    def test_there_is_no_mute_control(self, page: "Page", home_url: str, errors):
        open_home(page, home_url, {"session": _LIVE["session"]}, show_master_volume=True)
        expect(page.get_by_role("button", name=re.compile("mute", re.I))).to_have_count(0)
        expect(page.locator("[id*=mute]")).to_have_count(0)

    @staticmethod
    def _master_page(page: "Page", home_url: str) -> None:
        units = (stub.unit("tv", "Speaker A", selected=True, volume=20),
                 stub.unit("tv2", "Speaker B", selected=True, volume=40))
        open_home(page, home_url, {"session": _LIVE["session"], "outputs": stub.outputs_part(*units)},
                  show_master_volume=True)
        expect(page.locator("#master_vol_slider")).to_have_value("30")

    @staticmethod
    def _drag_master(page: "Page", value: int) -> None:
        page.evaluate(
            "(v) => { const s = document.getElementById('master_vol_slider');"
            " s.dispatchEvent(new Event('mousedown', {bubbles: true}));"
            " s.value = String(v); s.dispatchEvent(new Event('input', {bubbles: true}));"
            " s.dispatchEvent(new Event('change', {bubbles: true})); }", value)

    def test_the_master_slider_sends_one_volume_set_and_scales_the_cards(
            self, page: "Page", home_url: str, errors):
        self._master_page(page, home_url)
        self._drag_master(page, 60)
        expect(page.locator("#vol_slider_tv")).to_have_value("40")
        expect(page.locator("#vol_slider_tv2")).to_have_value("80")
        page.wait_for_timeout(500)
        assert intents() == [("volume.set", {"level": 60})]

    def test_an_event_that_lands_before_the_reply_does_not_snap_the_cards_back(
            self, page: "Page", home_url: str, errors):
        self._master_page(page, home_url)
        stub.REPLY_DELAY_S[0] = 0.8
        self._drag_master(page, 60)
        stale = stub.outputs_part(stub.unit("tv", "Speaker A", selected=True, volume=20),
                                  stub.unit("tv2", "Speaker B", selected=True, volume=40))
        stub.push({"outputs": stale})
        page.wait_for_timeout(300)
        expect(page.locator("#vol_slider_tv")).to_have_value("40")
        expect(page.locator("#vol_slider_tv2")).to_have_value("80")
        expect(page.locator("#master_vol_slider")).to_have_value("60")
        wait_for(page, lambda: len(stub.POSTS) == 1, "the request", 3)
        page.wait_for_timeout(1200)
        stub.push({"outputs": stub.outputs_part(stub.unit("tv", "Speaker A", selected=True, volume=40),
                                                stub.unit("tv2", "Speaker B", selected=True, volume=80))})
        page.wait_for_timeout(300)
        expect(page.locator("#vol_slider_tv")).to_have_value("40")
        expect(page.locator("#master_vol_slider")).to_have_value("60")
