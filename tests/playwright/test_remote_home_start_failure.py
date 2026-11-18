"""Playwright tests: the remote Home page says when a speaker on the other
appliance could not start.

The page comes from the real remote Home renderer; the gateway's home poll is
stubbed. ``failure`` is the failed start that poll carries. Each failure is
shown once per tab and appliance, both PIN reasons are silent on this page
(the other appliance's own pages prompt), and the local page keeps its own
record in the same tab.
"""
from __future__ import annotations

import re
import time

import pytest
import _home_stub as stub
from _home_stub import render_home, render_remote_home, start_server

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


def failure(**fields) -> dict:
    base = {"seq": 1, "boot": "boot-1", "unit_id": "tv", "name": "Speaker A",
            "reason": "refused", "requester": "webui", "age_s": 4}
    base.update(fields)
    return base


def publish(**fields) -> None:
    stub.REMOTE_HOME.clear()
    stub.REMOTE_HOME.update({"ok": True, "warnings": {}, "outputs": [],
                             "start_failure": failure(**fields)})


@pytest.fixture(scope="module")
def remote_url():
    server, url = start_server(render_remote_home())
    try:
        yield url
    finally:
        server.shutdown()


@pytest.fixture(autouse=True)
def _clean_stub():
    stub.REMOTE_HOME.clear()
    stub.REMOTE_HOME_POLLS.clear()
    stub.START_FAILURE.clear()
    stub.OUTPUTS[:] = []
    yield
    stub.REMOTE_HOME.clear()
    stub.REMOTE_HOME_POLLS.clear()
    stub.START_FAILURE.clear()
    stub.OUTPUTS[:] = []
    stub.set_page(render_remote_home())


def open_remote(page: "Page", base: str) -> None:
    stub.set_page(render_remote_home())
    stub.REMOTE_HOME_POLLS.clear()
    page.goto(f"{base}/")


def wait_polls(count: int, page: "Page") -> None:
    """Wait until the page has made *count* more home polls."""
    target = len(stub.REMOTE_HOME_POLLS) + count
    deadline = time.monotonic() + 20
    while len(stub.REMOTE_HOME_POLLS) < target and time.monotonic() < deadline:
        page.wait_for_timeout(100)
    assert len(stub.REMOTE_HOME_POLLS) >= target, "the home was not polled"


def expect_notice(page: "Page", title: str = "Could not start Speaker A") -> None:
    expect(page.locator("#infoModal")).to_have_class(_SHOWN, timeout=8000)
    expect(page.locator("#infoModalTitle")).to_have_text(title)


def expect_no_notice(page: "Page") -> None:
    expect(page.locator("#infoModal")).not_to_have_class(_SHOWN)


def dismiss(page: "Page") -> None:
    page.locator("#infoModalOk").click()
    expect_no_notice(page)


@_requires_browser
class TestRemoteStartFailureNotice:
    def test_a_refused_start_shows_once(self, page: "Page", remote_url: str):
        publish()
        open_remote(page, remote_url)
        expect_notice(page)
        expect(page.locator("#infoModalMessage")).to_contain_text("turned down the request")
        dismiss(page)
        wait_polls(2, page)
        expect_no_notice(page)

    def test_a_reload_shows_nothing(self, page: "Page", remote_url: str):
        publish()
        open_remote(page, remote_url)
        expect_notice(page)
        dismiss(page)
        page.reload()
        wait_polls(2, page)
        expect_no_notice(page)

    def test_a_later_failure_shows(self, page: "Page", remote_url: str):
        publish()
        open_remote(page, remote_url)
        expect_notice(page)
        dismiss(page)
        publish(seq=2, reason="timed_out")
        expect_notice(page)
        expect(page.locator("#infoModalMessage")).to_contain_text("did not answer in time")

    def test_the_local_page_in_the_same_tab_keeps_its_own_record(
        self, page: "Page", remote_url: str
    ):
        publish()
        open_remote(page, remote_url)
        expect_notice(page)
        dismiss(page)
        stub.REMOTE_HOME.clear()
        local = {"seq": 1, "unit_id": "tv", "name": "Speaker A", "reason": "refused",
                 "requester": "webui", "at": time.time() - 4}
        stub.set_page(render_home(parts={"outputs": stub.outputs_part(stub.unit(), start_failure=local)}))
        page.goto(f"{remote_url}/")
        expect_notice(page)

    @pytest.mark.parametrize("reason", ["pin_required", "pin_invalid"])
    @pytest.mark.parametrize("requester", ["webui", "dial:x", None])
    def test_a_pin_reason_shows_nothing_whoever_asked(
        self, page: "Page", remote_url: str, reason: str, requester
    ):
        publish(reason=reason, requester=requester)
        open_remote(page, remote_url)
        wait_polls(2, page)
        expect_no_notice(page)
        expect(page.locator("#pinModal")).not_to_have_class(_SHOWN)

    def test_a_cpu_limit_failure_shows_straight_after_a_switch_made_there(
        self, page: "Page", remote_url: str
    ):
        publish(reason="encoder_capacity")
        open_remote(page, remote_url)
        expect_notice(page)
        expect(page.locator("#infoModalMessage")).to_contain_text("cannot encode another stream")
