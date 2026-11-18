"""Playwright tests: the Home page says when a speaker could not start.

The page comes from the real Home renderer; the state parts and the intent
replies are stubbed. The outputs part carries the failed start. Each failure is
shown once per (boot, seq) in a tab, a request for a PIN opens the PIN dialog
instead, and a wrong PIN shows no notice because the PIN dialog asks again.
"""
from __future__ import annotations

import time

import pytest
import _home_stub as stub
from _home_stub import start_server
from _home_helpers import SHOWN, open_home, outputs, speaker, wait_stream

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

_CPU_LIMIT = {"ok": False, "error": "encoder_capacity", "result": {"error": "encoder_capacity"}}
_NEEDS_PIN = {"ok": False, "result": {"pin_required": True}}
_WRONG_PIN = {"ok": False, "result": {"pin_invalid": True}}


def _failure(age_s: float = 4, **fields) -> dict:
    base = {"seq": 1, "unit_id": "tv", "name": "Speaker A", "reason": "refused",
            "requester": "webui", "at": time.time() - age_s}
    base.update(fields)
    return base


def _part(failure: dict | None, **row) -> dict:
    return outputs(speaker(**row), start_failure=failure)


@pytest.fixture(scope="module")
def home_url():
    server, url = start_server(b"")
    try:
        yield url
    finally:
        server.shutdown()


def _open(page: "Page", base: str, failure: dict | None = None, *, replies: list | None = None, **row) -> None:
    open_home(page, base, {"outputs": _part(failure, **row)})
    stub.REPLIES[:] = replies or []
    wait_stream(page, 200)


def _publish(**fields) -> None:
    """A failed start arrives on the stream."""
    stub.push({"outputs": _part(_failure(**fields))})


def _toggle_on(page: "Page") -> None:
    page.evaluate(
        "() => { const c = document.getElementById('output_enabled_tv');"
        " c.checked = true; c.dispatchEvent(new Event('change', {bubbles: true})); }"
    )


def _expect_notice(page: "Page", title: str = "Could not start Speaker A") -> None:
    expect(page.locator("#infoModal")).to_have_class(SHOWN)
    expect(page.locator("#infoModalTitle")).to_have_text(title)


def _expect_no_notice(page: "Page") -> None:
    expect(page.locator("#infoModal")).not_to_have_class(SHOWN)


def _dismiss(page: "Page") -> None:
    page.locator("#infoModalOk").click()
    _expect_no_notice(page)


@_requires_browser
class TestStartFailureNotice:
    def test_a_refused_start_shows_the_notice_once(self, page: "Page", home_url: str):
        _open(page, home_url, _failure())
        _expect_notice(page)
        expect(page.locator("#infoModalMessage")).to_contain_text("turned down the request")
        _dismiss(page)
        _publish()
        page.wait_for_timeout(800)
        _expect_no_notice(page)

    def test_a_second_failure_shows(self, page: "Page", home_url: str):
        _open(page, home_url, _failure())
        _expect_notice(page)
        _dismiss(page)
        _publish(seq=2, reason="timed_out")
        _expect_notice(page)
        expect(page.locator("#infoModalMessage")).to_contain_text("did not answer in time")

    def test_a_reload_with_the_same_boot_and_seq_shows_nothing(self, page: "Page", home_url: str):
        _open(page, home_url, _failure())
        _expect_notice(page)
        _dismiss(page)
        page.reload()
        page.wait_for_selector("#output_enabled_tv", state="attached")
        wait_stream(page, 800)
        _expect_no_notice(page)

    def test_a_new_boot_with_seq_one_shows(self, page: "Page", home_url: str):
        _open(page, home_url, _failure())
        _expect_notice(page)
        _dismiss(page)
        stub.new_boot()
        _publish(seq=1)
        _expect_notice(page)

    def test_a_failure_already_old_on_the_first_reading_shows_nothing(self, page: "Page", home_url: str):
        _open(page, home_url, _failure(age_s=120))
        page.wait_for_timeout(800)
        _expect_no_notice(page)

    def test_an_old_failure_that_arrives_later_shows(self, page: "Page", home_url: str):
        _open(page, home_url)
        _publish(age_s=120)
        _expect_notice(page)

    def test_a_request_for_a_pin_opens_the_pin_dialog_and_no_notice(self, page: "Page", home_url: str):
        _open(page, home_url)
        stub.push({"outputs": _part(_failure(reason="pin_required"), pin_pending=True, pin_claim="webui")})
        expect(page.locator("#pinModal")).to_have_class(SHOWN)
        _expect_no_notice(page)

    def test_a_request_for_a_pin_from_a_dial_shows_nothing(self, page: "Page", home_url: str):
        _open(page, home_url, _failure(reason="pin_required", requester="dial:x"),
              pin_pending=True, pin_claim="dial:x")
        page.wait_for_timeout(800)
        expect(page.locator("#pinModal")).not_to_have_class(SHOWN)
        _expect_no_notice(page)

    def test_the_cpu_limit_dialog_of_the_switch_is_not_followed_by_a_second_one(
        self, page: "Page", home_url: str
    ):
        _open(page, home_url, replies=[_CPU_LIMIT])
        _toggle_on(page)
        _expect_notice(page, "CPU limit reached")
        _publish(reason="encoder_capacity")
        page.wait_for_timeout(500)
        _expect_notice(page, "CPU limit reached")
        _dismiss(page)
        page.wait_for_timeout(500)
        _expect_no_notice(page)

    def test_a_speaker_name_is_text_not_markup(self, page: "Page", home_url: str):
        _open(page, home_url, _failure(name="<b>Loud</b>"))
        _expect_notice(page, "Could not start <b>Loud</b>")
        assert page.locator("#infoModalTitle b").count() == 0

    def test_a_wrong_pin_shows_no_notice_and_the_pin_dialog_asks_again(self, page: "Page", home_url: str):
        _open(page, home_url, replies=[_NEEDS_PIN, _WRONG_PIN])
        _toggle_on(page)
        expect(page.locator("#pinModal")).to_have_class(SHOWN)
        page.locator("#pinModalInput").fill("1111")
        page.locator("#pinModalOk").click()
        expect(page.locator("#pinModalNote")).to_have_text("That PIN was not accepted. Try again.")
        _publish(reason="pin_invalid")
        page.wait_for_timeout(500)
        expect(page.locator("#pinModal")).to_have_class(SHOWN)
        _expect_no_notice(page)

    def test_a_wrong_pin_from_a_dial_shows_nothing(self, page: "Page", home_url: str):
        _open(page, home_url, _failure(reason="pin_invalid", requester="dial:x"))
        page.wait_for_timeout(800)
        _expect_no_notice(page)
        expect(page.locator("#pinModal")).not_to_have_class(SHOWN)

    def test_a_failure_does_not_show_over_another_dialog_and_nothing_wedges(
        self, page: "Page", home_url: str
    ):
        _open(page, home_url, replies=[_CPU_LIMIT])
        _toggle_on(page)
        _expect_notice(page, "CPU limit reached")
        _publish(reason="failed")
        page.wait_for_timeout(500)
        _expect_notice(page, "CPU limit reached")
        page.locator("#infoModalOk").click()
        _expect_notice(page)
        expect(page.locator("#infoModalMessage")).to_contain_text("did not start")
        _dismiss(page)
        page.wait_for_timeout(500)
        _expect_no_notice(page)
        _publish(seq=2, reason="timed_out")
        _expect_notice(page)

    def test_a_failure_while_the_pin_dialog_is_open_shows_after_it_closes(
        self, page: "Page", home_url: str
    ):
        _open(page, home_url, replies=[_NEEDS_PIN])
        _toggle_on(page)
        expect(page.locator("#pinModal")).to_have_class(SHOWN)
        _publish()
        page.wait_for_timeout(500)
        _expect_no_notice(page)
        page.locator("#pinModalCancel").click()
        expect(page.locator("#pinModal")).not_to_have_class(SHOWN)
        _expect_notice(page)
