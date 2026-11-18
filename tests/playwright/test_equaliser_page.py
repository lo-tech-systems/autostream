"""Playwright tests: the Equaliser page on the state protocol.

The page comes from the real renderer; the state parts and the intent replies
are stubbed. The sliders and the auto-trim switch follow the ``eq`` part, so a
change another client makes shows at once; a change made here is one intent.
"""
from __future__ import annotations

import pytest
import _home_stub as stub
from _home_stub import start_server
from _home_helpers import intents, wait_for, watch_errors

try:
    from playwright.sync_api import Page, expect  # type: ignore[attr-defined]
    _PLAYWRIGHT_INSTALLED = True
except ImportError:
    _PLAYWRIGHT_INSTALLED = False
    Page = object  # type: ignore[misc,assignment]
    expect = None  # type: ignore[assignment]

import _page_stub

_requires_browser = pytest.mark.skipif(not _PLAYWRIGHT_INSTALLED, reason="playwright not installed")

_FLAT = {"output_bands": [0, 0, 0, 0, 0, 0], "output_gain_db": 0.0, "auto_trim_enabled": False,
         "input_bands": {}, "input_gain": {}}


def _eq(**fields) -> dict:
    return {**_FLAT, **fields}


def _open(page: "Page", eq: dict, monitor: dict | None = None, *, stream: bool = True):
    parts = {"eq": eq}
    if monitor is not None:
        parts["monitor"] = monitor
    server, base = start_server(_page_stub.render("equaliser", parts=parts))
    for log in (stub.POSTS, stub.POST_PATHS, stub.POST_TOKENS, stub.REPLIES):
        log.clear()
    if stream:
        stub.stream_on()
    page.goto(f"{base}/")
    return server


def _slide(page: "Page", field: str, value: str) -> None:
    page.evaluate(
        "([id, v]) => { const s = document.getElementById(id); s.value = v;"
        " s.dispatchEvent(new Event('input', {bubbles: true})); }", [field, value])


@pytest.fixture(autouse=True)
def _errors(page: "Page"):
    e = watch_errors(page)
    e.ignore.append("EventSource")
    yield e
    stub.reset_stream()
    assert not e.left(), f"console errors: {e.left()}"


@_requires_browser
class TestEqualiserPage:
    def test_a_band_change_is_one_intent_with_the_csrf_token(self, page: "Page"):
        server = _open(page, _eq())
        try:
            _slide(page, "peq3_db", "6")
            wait_for(page, lambda: stub.POSTS, "the eq intent")
            page.wait_for_timeout(500)
            assert intents() == [("output.eq.set", {"fields": [["peq3_db", "6"]]})]
            assert stub.POST_TOKENS == ["t"]
            expect(page.locator("#peq3_db_val")).to_have_text("+6 dB")
        finally:
            server.shutdown()

    def test_the_gain_and_the_switch_send_their_own_fields(self, page: "Page"):
        server = _open(page, _eq())
        try:
            _slide(page, "output_gain_db", "-1.5")
            page.locator(".output-toggle .switch").click()
            wait_for(page, lambda: len(stub.POSTS) >= 2, "two eq intents")
            assert intents() == [("output.eq.set", {"fields": [["gain_db", "-1.5"]]}),
                                 ("output.eq.set", {"fields": [["auto_trim_enabled", "true"]]})]
            expect(page.locator("#output_gain_db_val")).to_have_text("-1.5 dB")
        finally:
            server.shutdown()

    def test_flat_sends_a_reset_and_zeroes_the_bands(self, page: "Page"):
        server = _open(page, _eq(output_bands=[3, -2, 0, 4, 0, 1]))
        try:
            expect(page.locator("#peq1_db_val")).to_have_text("+3 dB")
            page.locator("#eq-flat-btn").click()
            wait_for(page, lambda: stub.POSTS, "the reset intent")
            assert intents() == [("output.eq.reset", {})]
            expect(page.locator("#peq1_db_val")).to_have_text("0 dB")
            assert page.locator("#peq4_db").input_value() == "0"
        finally:
            server.shutdown()

    def test_another_clients_change_moves_the_slider_and_the_curve(self, page: "Page"):
        server = _open(page, _eq())
        try:
            wait_for(page, lambda: stub.open_streams() >= 1, "the stream")
            before = page.locator("#eq-curve-path").get_attribute("d")
            stub.push({"eq": _eq(output_bands=[0, 0, 5, 0, 0, 0], output_gain_db=2.5, auto_trim_enabled=True)})
            expect(page.locator("#peq3_db_val")).to_have_text("+5 dB")
            assert page.locator("#peq3_db").input_value() == "5"
            expect(page.locator("#output_gain_db_val")).to_have_text("+2.5 dB")
            assert page.locator("#output_auto_trim").is_checked()
            assert page.locator("#eq-curve-path").get_attribute("d") != before
            assert stub.POSTS == []
        finally:
            server.shutdown()

    def test_a_slider_in_hand_is_not_moved_by_a_push(self, page: "Page"):
        server = _open(page, _eq())
        try:
            wait_for(page, lambda: stub.open_streams() >= 1, "the stream")
            page.locator("#peq2_db").focus()
            stub.push({"eq": _eq(output_bands=[0, 7, 0, 0, 0, 0])})
            page.wait_for_timeout(400)
            assert page.locator("#peq2_db").input_value() == "0"
        finally:
            server.shutdown()

    def test_it_follows_the_state_by_polling_when_the_stream_is_refused(self, page: "Page"):
        server = _open(page, _eq(), stream=False)
        try:
            stub.set_parts(eq=_eq(output_bands=[0, 0, 0, 0, 0, -4]))
            expect(page.locator("#peq6_db_val")).to_have_text("-4 dB", timeout=6000)
        finally:
            server.shutdown()

    def test_the_trim_readout_polls_the_monitor_only_while_auto_trim_is_on(self, page: "Page"):
        server = _open(page, _eq(), {"connected": True, "output_trim_db": None})
        try:
            page.wait_for_timeout(500)
            assert not any("parts=monitor" in q for q in stub.STATE_FETCHES)
            stub.push({"eq": _eq(auto_trim_enabled=True)})
            expect(page.locator("#output_trim_status")).to_have_text("Calculating\u2026")
            stub.set_parts(monitor={"connected": True, "output_trim_db": -1.5})
            expect(page.locator("#output_trim_status")).to_have_text("Auto-trim: -1.5 dB applied", timeout=6000)
            assert any("parts=monitor" in q for q in stub.STATE_FETCHES)
            stub.push({"eq": _eq(auto_trim_enabled=False)})
            expect(page.locator("#output_trim_status")).to_be_hidden()
        finally:
            server.shutdown()
