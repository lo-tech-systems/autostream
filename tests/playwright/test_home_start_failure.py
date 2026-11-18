"""Playwright tests: the Home page says when a speaker could not start.

The page comes from the real Home renderer; the speaker list poll and the
output POST are stubbed. ``START_FAILURE`` is the failed start the poll carries.
Each failure is shown once per (boot, seq) in a tab, a PIN request for a start
this page asked for opens the PIN dialog instead, and a wrong PIN shows no
notice because the PIN dialog asks again.
"""
from __future__ import annotations

import re
import time

import pytest
from _home_stub import (
    OUTPUTS as _OUTPUTS,
    POLLS as _POLLS,
    POSTS as _POSTS,
    REPLIES as _REPLIES,
    START_FAILURE as _FAILURE,
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

_SHOWN = re.compile(r"\bshow\b")


def _row() -> dict:
    return {"id": "tv", "name": "Speaker A", "selected": False, "volume": 20,
            "pin_pending": False}


def _failure(**fields) -> dict:
    base = {"seq": 1, "boot": "boot-1", "unit_id": "tv", "name": "Speaker A",
            "reason": "refused", "requester": "webui", "age_s": 4}
    base.update(fields)
    return base


@pytest.fixture(scope="module")
def home_url():
    server, url = start_server(render_home())
    try:
        yield url
    finally:
        server.shutdown()


@pytest.fixture(autouse=True)
def _clean_stub():
    _FAILURE.clear()
    yield
    _FAILURE.clear()


def _publish(**fields) -> None:
    _FAILURE.clear()
    _FAILURE.update(_failure(**fields))


def _open_home(page: "Page", base: str, *, replies: list | None = None) -> None:
    _OUTPUTS[:] = [_row()]
    _REPLIES[:] = replies or []
    _POSTS.clear()
    _POLLS.clear()
    page.goto(f"{base}/")
    page.wait_for_selector("#output_enabled_tv", state="attached")


def _wait_polls(page: "Page", count: int = 2) -> None:
    """Wait until the page has made *count* more speaker list polls."""
    target = len(_POLLS) + count
    deadline = time.monotonic() + 15
    while len(_POLLS) < target and time.monotonic() < deadline:
        page.wait_for_timeout(100)
    assert len(_POLLS) >= target, "the speaker list was not polled"


def _toggle_on(page: "Page") -> None:
    page.evaluate(
        "() => { const c = document.getElementById('output_enabled_tv');"
        " c.checked = true; c.dispatchEvent(new Event('change', {bubbles: true})); }"
    )


def _expect_notice(page: "Page", title: str = "Could not start Speaker A") -> None:
    expect(page.locator("#infoModal")).to_have_class(_SHOWN)
    expect(page.locator("#infoModalTitle")).to_have_text(title)


def _expect_no_notice(page: "Page") -> None:
    expect(page.locator("#infoModal")).not_to_have_class(_SHOWN)


def _dismiss(page: "Page") -> None:
    page.locator("#infoModalOk").click()
    _expect_no_notice(page)


@_requires_browser
class TestStartFailureNotice:
    def test_a_refused_start_shows_the_notice_once(self, page: "Page", home_url: str):
        _publish()
        _open_home(page, home_url)
        _expect_notice(page)
        expect(page.locator("#infoModalMessage")).to_contain_text("turned down the request")
        _dismiss(page)
        _wait_polls(page)
        _expect_no_notice(page)

    def test_a_second_failure_shows(self, page: "Page", home_url: str):
        _publish()
        _open_home(page, home_url)
        _expect_notice(page)
        _dismiss(page)
        _publish(seq=2, reason="timed_out")
        _expect_notice(page)
        expect(page.locator("#infoModalMessage")).to_contain_text("did not answer in time")

    def test_a_reload_with_the_same_boot_and_seq_shows_nothing(self, page: "Page", home_url: str):
        _publish()
        _open_home(page, home_url)
        _expect_notice(page)
        _dismiss(page)
        page.reload()
        page.wait_for_selector("#output_enabled_tv", state="attached")
        _wait_polls(page)
        _expect_no_notice(page)

    def test_a_new_boot_with_seq_one_shows(self, page: "Page", home_url: str):
        _publish()
        _open_home(page, home_url)
        _expect_notice(page)
        _dismiss(page)
        _publish(boot="boot-2", seq=1)
        _expect_notice(page)

    def test_a_failure_already_old_on_the_first_poll_shows_nothing(self, page: "Page", home_url: str):
        _publish(age_s=120)
        _open_home(page, home_url)
        _wait_polls(page)
        _expect_no_notice(page)

    def test_an_old_failure_that_arrives_on_a_later_poll_shows(self, page: "Page", home_url: str):
        _open_home(page, home_url)
        _wait_polls(page)
        _publish(age_s=120)
        _expect_notice(page)

    def test_a_pin_request_for_a_start_the_page_asked_for_opens_the_pin_dialog(
        self, page: "Page", home_url: str
    ):
        # The cards are drawn first: the page does not redraw its list while the
        # PIN dialog is open, so a request on the first poll would hide them.
        _open_home(page, home_url)
        _publish(reason="pin_required", requester="webui")
        expect(page.locator("#pinModal")).to_have_class(_SHOWN)
        _expect_no_notice(page)

    def test_a_pin_request_from_a_dial_shows_nothing(self, page: "Page", home_url: str):
        _publish(reason="pin_required", requester="dial:x")
        _open_home(page, home_url)
        _wait_polls(page)
        expect(page.locator("#pinModal")).not_to_have_class(_SHOWN)
        _expect_no_notice(page)

    def test_the_cpu_limit_dialog_of_the_switch_is_not_followed_by_a_second_one(
        self, page: "Page", home_url: str
    ):
        _open_home(page, home_url, replies=[{"ok": False, "error": "encoder_capacity"}])
        _toggle_on(page)
        _expect_notice(page, "CPU limit reached")
        _publish(reason="encoder_capacity")
        _wait_polls(page)
        _expect_notice(page, "CPU limit reached")
        _dismiss(page)
        _wait_polls(page)
        _expect_no_notice(page)

    def test_a_speaker_name_is_text_not_markup(self, page: "Page", home_url: str):
        _publish(name="<b>Loud</b>")
        _open_home(page, home_url)
        _expect_notice(page, "Could not start <b>Loud</b>")
        assert page.locator("#infoModalTitle b").count() == 0

    def test_a_wrong_pin_shows_no_notice_and_the_pin_dialog_asks_again(
        self, page: "Page", home_url: str
    ):
        _open_home(page, home_url, replies=[{"ok": False, "pin_required": True},
                                            {"ok": False, "pin_invalid": True}])
        _toggle_on(page)
        expect(page.locator("#pinModal")).to_have_class(_SHOWN)
        page.locator("#pinModalInput").fill("1111")
        page.locator("#pinModalOk").click()
        expect(page.locator("#pinModalNote")).to_have_text("That PIN was not accepted. Try again.")
        _publish(reason="pin_invalid", requester="webui")
        _wait_polls(page)
        expect(page.locator("#pinModal")).to_have_class(_SHOWN)
        _expect_no_notice(page)

    def test_a_wrong_pin_from_a_dial_shows_nothing(self, page: "Page", home_url: str):
        _publish(reason="pin_invalid", requester="dial:x")
        _open_home(page, home_url)
        _wait_polls(page)
        _expect_no_notice(page)
        expect(page.locator("#pinModal")).not_to_have_class(_SHOWN)

    def test_a_failure_does_not_show_over_another_dialog_and_nothing_wedges(
        self, page: "Page", home_url: str
    ):
        _open_home(page, home_url, replies=[{"ok": False, "error": "encoder_capacity"}])
        _toggle_on(page)
        _expect_notice(page, "CPU limit reached")
        _publish(reason="failed")
        _wait_polls(page)
        _expect_notice(page, "CPU limit reached")
        _dismiss(page)
        _expect_notice(page)
        expect(page.locator("#infoModalMessage")).to_contain_text("did not start")
        _dismiss(page)
        _wait_polls(page)
        _expect_no_notice(page)
        _publish(seq=2, reason="timed_out")
        _expect_notice(page)

    def test_a_failure_while_the_pin_dialog_is_open_shows_after_it_closes(
        self, page: "Page", home_url: str
    ):
        _open_home(page, home_url, replies=[{"ok": False, "pin_required": True}])
        _toggle_on(page)
        expect(page.locator("#pinModal")).to_have_class(_SHOWN)
        _publish()
        _wait_polls(page)
        _expect_no_notice(page)
        page.locator("#pinModalCancel").click()
        expect(page.locator("#pinModal")).not_to_have_class(_SHOWN)
        _expect_notice(page)
