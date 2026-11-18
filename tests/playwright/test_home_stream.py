"""Playwright tests: the Home page follows the state change stream.

The page comes from the real Home renderer; the stub holds the event stream
open and writes the events a test pushes. With the stream up an idle page
fetches nothing between changes, fetches what an event names, keeps polling
the status only while a session or a replay is live, and reconciles every 15
seconds. Without the stream it polls as before and tries the stream again
after about 30 seconds. The time-based cases drive the page's clock.
"""
from __future__ import annotations

import re
import time

import pytest
import _home_stub as stub
from _home_stub import render_home, start_server

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

_SHOWN = re.compile(r"\bshow\b")

ALL_PARTS = ["session", "repeat", "track", "inputs", "monitor", "playback",
             "health", "settings", "outputs", "eq", "devices"]


def _row(selected: bool = False) -> dict:
    return {"id": "tv", "name": "Speaker A", "selected": selected, "volume": 20,
            "pin_pending": False}


def _idle() -> dict:
    return {"ok": True, "session": {"active": False}, "repeat": {"replay": {}}}


def _live() -> dict:
    return {"ok": True, "session": {"active": True, "source": "input1"},
            "repeat": {"replay": {}}}


def _fading() -> dict:
    return {"ok": True, "session": {"active": False},
            "repeat": {"replay": {"active": False, "fading_out": True}}}


@pytest.fixture(scope="module")
def home_url():
    server, url = start_server(render_home())
    try:
        yield url
    finally:
        server.shutdown()


@pytest.fixture
def clean_stub():
    stub.reset_stream()
    stub.STATUS.clear()
    stub.STATUS_POLLS.clear()
    stub.POLLS.clear()
    stub.START_FAILURE.clear()
    stub.OUTPUTS[:] = [_row()]
    yield
    stub.reset_stream()
    stub.STATUS.clear()
    stub.STATUS_POLLS.clear()
    stub.POLLS.clear()
    stub.START_FAILURE.clear()


class _Errors:
    def __init__(self) -> None:
        self.seen: list[str] = []
        self.ignore: list[str] = []


@pytest.fixture
def errors(page: "Page", clean_stub):
    """Console errors and page errors; a case fails if any is left at its end."""
    e = _Errors()
    page.on("console", lambda m: e.seen.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda x: e.seen.append(str(x)))
    yield e
    left = [t for t in e.seen if not any(i in t for i in e.ignore)]
    assert not left, f"console errors: {left}"


def _open(page: "Page", base: str, status: dict | None = None, *, stream: bool = True) -> None:
    stub.STATUS.clear()
    stub.STATUS.update(status or _idle())
    if stream:
        stub.stream_on()
    page.goto(f"{base}/")
    page.wait_for_selector("#output_enabled_tv", state="attached")


def _settle(page: "Page", ms: int = 600) -> None:
    """Wait until a stream is open on the stub and the page has acted on it."""
    deadline = time.monotonic() + 10
    while stub.open_streams() < 1 and time.monotonic() < deadline:
        page.wait_for_timeout(50)
    assert stub.open_streams() >= 1, "the page did not open the stream"
    page.wait_for_timeout(ms)


def _counts() -> tuple[int, int]:
    return len(stub.STATUS_POLLS), len(stub.POLLS)


def _wait_count(page: "Page", which: int, target: int, seconds: float = 5.0) -> None:
    deadline = time.monotonic() + seconds
    while _counts()[which] < target and time.monotonic() < deadline:
        page.wait_for_timeout(25)
    assert _counts()[which] >= target, f"fetch count stayed at {_counts()[which]}, wanted {target}"


def _assert_not_polling(settled: tuple[int, int]) -> None:
    """No 1.5 s cadence since *settled*. After a jump of the page clock one
    reconcile fetch can land late, so one extra fetch of each is allowed."""
    s, o = _counts()
    assert s - settled[0] <= 1 and o - settled[1] <= 1, f"still polling: {settled} -> {(s, o)}"


def _arrivals(page: "Page", seconds: float) -> list[float]:
    """Seconds after now at which each status fetch arrived within *seconds*."""
    start = time.monotonic()
    seen = len(stub.STATUS_POLLS)
    out: list[float] = []
    while time.monotonic() - start < seconds:
        page.wait_for_timeout(15)
        while len(stub.STATUS_POLLS) > seen + len(out):
            out.append(time.monotonic() - start)
    return out


def _set_hidden(page: "Page", hidden: bool) -> None:
    page.evaluate(
        "(h) => { Object.defineProperty(document, 'hidden', {configurable: true, get: () => h});"
        " Object.defineProperty(document, 'visibilityState', {configurable: true, get: () => h ? 'hidden' : 'visible'});"
        " document.dispatchEvent(new Event('visibilitychange')); }", hidden)


@_requires_browser
class TestHomeStream:
    @pytest.mark.usefixtures("errors")
    def test_an_idle_page_is_quiet(self, page: "Page", home_url: str):
        _open(page, home_url)
        _settle(page)
        status, outputs = _counts()
        assert status <= 2 and outputs <= 2
        page.wait_for_timeout(5000)
        assert _counts() == (status, outputs)

    @pytest.mark.usefixtures("errors")
    def test_a_speaker_change_made_elsewhere_shows_at_once(self, page: "Page", home_url: str):
        _open(page, home_url)
        _settle(page)
        s0, o0 = _counts()
        stub.OUTPUTS[:] = [_row(selected=True)]
        stub.push(["outputs"])
        expect(page.locator("#output_enabled_tv")).to_be_checked(timeout=1500)
        page.wait_for_timeout(500)
        assert _counts() == (s0 + 1, o0 + 1)

    @pytest.mark.usefixtures("errors")
    def test_parts_the_page_does_not_show_cause_no_fetch(self, page: "Page", home_url: str):
        _open(page, home_url)
        _settle(page)
        before = _counts()
        stub.push(["devices"])
        stub.push(["eq"])
        stub.push(["monitor", "health"])
        page.wait_for_timeout(1000)
        assert _counts() == before

    @pytest.mark.usefixtures("errors")
    def test_a_settings_change_fetches_only_the_speaker_list(self, page: "Page", home_url: str):
        _open(page, home_url)
        _settle(page)
        s0, o0 = _counts()
        stub.push(["settings"])
        page.wait_for_timeout(1000)
        assert _counts() == (s0, o0 + 1)

    @pytest.mark.usefixtures("errors")
    @pytest.mark.parametrize("live_status,event", [(_live, "session"), (_fading, "repeat")])
    def test_a_live_page_keeps_polling_the_status_and_an_idle_one_stops(
            self, page: "Page", home_url: str, live_status, event):
        _open(page, home_url)
        _settle(page)
        s0, o0 = _counts()
        stub.STATUS.clear()
        stub.STATUS.update(live_status())
        stub.push([event])
        page.wait_for_timeout(4000)
        s1, o1 = _counts()
        assert s1 - s0 >= 3
        assert o1 == o0
        stub.STATUS.clear()
        stub.STATUS.update(_idle())
        stub.push([event])
        page.wait_for_timeout(1000)
        s2 = len(stub.STATUS_POLLS)
        page.wait_for_timeout(3500)
        assert len(stub.STATUS_POLLS) == s2

    @pytest.mark.usefixtures("errors")
    def test_going_live_does_not_fetch_twice_in_a_row(self, page: "Page", home_url: str):
        _open(page, home_url)
        _settle(page)
        stub.STATUS.clear()
        stub.STATUS.update(_live())
        stub.push(["session"])
        times = _arrivals(page, 3.2)
        assert len(times) >= 2
        assert times[0] < 0.6
        assert times[1] - times[0] >= 1.2

    @pytest.mark.usefixtures("errors")
    def test_a_page_loaded_while_live_makes_at_most_two_status_fetches_at_first(
            self, page: "Page", home_url: str):
        stub.STATUS_POLLS.clear()
        t0 = time.monotonic()
        _open(page, home_url, _live())
        _settle(page, 0)
        page.wait_for_timeout(max(0, int((1.4 - (time.monotonic() - t0)) * 1000)))
        assert len(stub.STATUS_POLLS) <= 2

    @pytest.mark.usefixtures("errors")
    def test_a_resync_fetches_both_once(self, page: "Page", home_url: str):
        _open(page, home_url)
        _settle(page)
        s0, o0 = _counts()
        stub.push(ALL_PARTS, resync=True)
        page.wait_for_timeout(1000)
        assert _counts() == (s0 + 1, o0 + 1)

    @pytest.mark.usefixtures("errors")
    def test_a_dropped_stream_is_resumed_without_polling(self, page: "Page", home_url: str):
        _open(page, home_url)
        _settle(page)
        stub.push(["devices"])
        page.wait_for_timeout(300)
        before = _counts()
        last = f"{stub.STREAM['boot']}-{stub.STREAM['version']}"
        stub.drop()
        deadline = time.monotonic() + 1.5
        while len(stub.STREAM_CONNECTS) < 2 and time.monotonic() < deadline:
            page.wait_for_timeout(25)
        assert len(stub.STREAM_CONNECTS) >= 2
        assert stub.STREAM_CONNECTS[-1]["last_event_id"] == last
        page.wait_for_timeout(4000)
        assert _counts() == before

    def test_a_refused_stream_falls_back_to_polling_and_returns_later(
            self, page: "Page", home_url: str, errors):
        errors.ignore += ["EventSource", "text/event-stream"]
        page.clock.install()
        _open(page, home_url)
        _settle(page)
        stub.refuse_from_now()
        stub.drop()
        s0, o0 = _counts()
        _wait_count(page, 0, s0 + 2, 8.0)
        _wait_count(page, 1, o0 + 2, 8.0)
        stub.stream_on()
        before = len(stub.STREAM_CONNECTS)
        page.clock.fast_forward(36000)
        deadline = time.monotonic() + 5
        while stub.open_streams() < 1 and time.monotonic() < deadline:
            page.wait_for_timeout(50)
        assert len(stub.STREAM_CONNECTS) > before and stub.open_streams() >= 1
        page.wait_for_timeout(800)
        settled = _counts()
        page.wait_for_timeout(3500)
        _assert_not_polling(settled)

    def test_a_page_loaded_without_the_stream_polls_and_tries_again_later(
            self, page: "Page", home_url: str, errors):
        errors.ignore += ["EventSource", "text/event-stream"]
        page.clock.install()
        _open(page, home_url, stream=False)
        opened = page.evaluate("Date.now()")
        _wait_count(page, 0, 3, 8.0)
        _wait_count(page, 1, 3, 8.0)
        stub.stream_on()
        page.clock.fast_forward(max(1, 23000 - (page.evaluate("Date.now()") - opened)))
        page.wait_for_timeout(500)
        assert len(stub.STREAM_CONNECTS) == 0
        page.clock.fast_forward(14000)
        deadline = time.monotonic() + 5
        while stub.open_streams() < 1 and time.monotonic() < deadline:
            page.wait_for_timeout(50)
        assert stub.open_streams() >= 1
        page.wait_for_timeout(800)
        settled = _counts()
        page.wait_for_timeout(3500)
        _assert_not_polling(settled)

    @pytest.mark.usefixtures("errors")
    @pytest.mark.parametrize("live", [False, True])
    def test_a_hidden_page_holds_no_stream_and_catches_up_when_shown(
            self, page: "Page", home_url: str, live: bool):
        _open(page, home_url, _live() if live else _idle())
        _settle(page)
        stub.push(["devices"])
        page.wait_for_timeout(300)
        last = f"{stub.STREAM['boot']}-{stub.STREAM['version']}"
        _set_hidden(page, True)
        deadline = time.monotonic() + 1.5
        while stub.open_streams() > 0 and time.monotonic() < deadline:
            page.wait_for_timeout(25)
        assert stub.open_streams() == 0
        assert stub.STREAM_CONNECTS[-1]["closed_at"] is not None
        page.wait_for_timeout(500)
        before = _counts()
        page.wait_for_timeout(3000)
        assert _counts() == before
        _set_hidden(page, False)
        _settle(page, 800)
        assert stub.STREAM_CONNECTS[-1]["since"] == last
        s1, o1 = _counts()
        assert (s1 - before[0], o1 - before[1]) == (1, 1)

    @pytest.mark.usefixtures("errors")
    def test_the_reconcile_fetches_both_every_fifteen_seconds(self, page: "Page", home_url: str):
        page.clock.install()
        _open(page, home_url)
        _settle(page)
        s0, o0 = _counts()
        page.clock.run_for(15000)
        page.wait_for_timeout(800)
        assert _counts() == (s0 + 1, o0 + 1)

    def test_a_failed_reconcile_restarts_the_stream(
            self, page: "Page", home_url: str, errors):
        errors.ignore += ["status of 500"]
        page.clock.install()
        _open(page, home_url)
        _settle(page)
        failures = {"n": 0}

        def answer(route):
            if failures["n"] == 0:
                failures["n"] += 1
                route.fulfill(status=500, content_type="application/json", body='{"ok": false}')
            else:
                route.continue_()

        page.route("**/api/status", answer)
        before = len(stub.STREAM_CONNECTS)
        page.clock.run_for(15000)
        deadline = time.monotonic() + 5
        while len(stub.STREAM_CONNECTS) <= before and time.monotonic() < deadline:
            page.wait_for_timeout(50)
        assert failures["n"] == 1
        assert len(stub.STREAM_CONNECTS) > before

    @pytest.mark.usefixtures("errors")
    def test_a_start_failure_is_shown_once_after_an_outputs_event(self, page: "Page", home_url: str):
        _open(page, home_url)
        _settle(page)
        stub.START_FAILURE.update({
            "seq": 1, "boot": "boot-1", "unit_id": "tv", "name": "Speaker A",
            "reason": "refused", "requester": "webui", "age_s": 4})
        stub.push(["outputs"])
        modal = page.locator("#infoModal")
        expect(modal).to_have_class(_SHOWN, timeout=2000)
        expect(page.locator("#infoModalTitle")).to_have_text("Could not start Speaker A")
        page.locator("#infoModalOk").click()
        stub.push(["outputs"])
        page.wait_for_timeout(1000)
        expect(modal).not_to_have_class(_SHOWN)
