"""Playwright tests: the Home speaker card says when a speaker is connecting or offline.

The page comes from the real Home renderer; the speaker list poll and the
output POST are stubbed. A speaker that is wanted but not yet playing reads
"Name (Connecting)", with its switch dimmed and still usable to turn it off.
The default speaker's card while the player has no row for it reads
"Name (offline)": inside a session its switch is on and works, outside one it
is off and disabled. The server-rendered card and the card the page builds
from the list must come out the same.
"""
from __future__ import annotations

import re
import time

import pytest
from _home_stub import (
    OUTPUTS as _OUTPUTS,
    POLLS as _POLLS,
    POSTS as _POSTS,
    REMOTE_HOME as _REMOTE_HOME,
    REMOTE_HOME_POLLS as _REMOTE_POLLS,
    render_home,
    render_remote_home,
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

_CONNECTING = re.compile(r"\boutput-card-connecting\b")
_OFFLINE = re.compile(r"\boutput-card-offline\b")


def _row(**fields) -> dict:
    base = {"id": "tv", "name": "Speaker A", "selected": True, "volume": 20,
            "is_default": True, "needs_auth_key": False, "requires_auth": False,
            "pin_pending": False, "pin_claim": "", "connecting": False, "offline": False}
    base.update(fields)
    return base


CONNECTING = _row(connecting=True)
OFFLINE_IN_SESSION = _row(offline=True)
OFFLINE_OUTSIDE_SESSION = _row(offline=True, selected=False, disabled=True)
PLAYING = _row()


@pytest.fixture(autouse=True)
def _clean_stub():
    _OUTPUTS[:] = []
    _REMOTE_HOME.clear()
    yield
    _OUTPUTS[:] = []
    _REMOTE_HOME.clear()


@pytest.fixture
def serve():
    """Start the stub server with a page; each is shut down after the test."""
    servers = []

    def start(page_bytes: bytes) -> str:
        server, url = start_server(page_bytes)
        servers.append(server)
        return url

    yield start
    for server in servers:
        server.shutdown()


@pytest.fixture
def open_home(page: "Page", serve):
    """Open Home rendered with *rows*, and polled for them."""
    def open_(rows: list) -> None:
        _OUTPUTS[:] = rows
        _POSTS.clear()
        _POLLS.clear()
        page.goto(f"{serve(render_home(outputs=rows))}/")
        page.wait_for_selector("#output_enabled_tv", state="attached")

    return open_


def _wait_polls(page: "Page", count: int = 2) -> None:
    target = len(_POLLS) + count
    deadline = time.monotonic() + 15
    while len(_POLLS) < target and time.monotonic() < deadline:
        page.wait_for_timeout(100)
    assert len(_POLLS) >= target, "the speaker list was not polled"


def _tap(page: "Page") -> None:
    page.locator("#output_card_tv .output-toggle").click()


_DESCRIBE = """() => {
  const card = document.getElementById('output_card_tv');
  const cb = document.getElementById('output_enabled_tv');
  const label = document.getElementById('output_label_tv');
  const sl = document.getElementById('vol_slider_tv');
  return {
    classes: Array.from(card.classList).sort().join(' '),
    name: outputCardNameText(card.querySelector('.output-card-name')),
    label: label.textContent,
    labelHidden: label.hidden,
    checked: cb.checked,
    disabled: cb.disabled,
    sliderDisabled: sl.disabled,
    sliderHidden: document.getElementById('output_slider_wrap_tv').hidden,
    chip: document.getElementById('output_state_tv').textContent,
  };
}"""


@_requires_browser
class TestConnectingCard:
    def test_it_reads_connecting_with_a_dimmed_switch_that_still_works(self, page: "Page", open_home):
        open_home([CONNECTING])
        card = page.locator("#output_card_tv")
        expect(card).to_have_class(_CONNECTING)
        expect(page.locator("#output_label_tv")).to_have_text("(Connecting)")
        expect(page.locator("#output_label_tv")).to_be_visible()
        expect(page.locator("#output_card_tv .output-toggle .switch")).to_have_css("opacity", "0.45")
        expect(page.locator("#output_enabled_tv")).to_be_checked()
        expect(page.locator("#output_enabled_tv")).to_be_enabled()

    def test_a_tap_turns_the_speaker_off(self, page: "Page", open_home):
        open_home([CONNECTING])
        _tap(page)
        deadline = time.monotonic() + 5
        while not _POSTS and time.monotonic() < deadline:
            page.wait_for_timeout(50)
        assert _POSTS and _POSTS[-1]["id"] == "tv" and _POSTS[-1]["selected"] is False
        expect(page.locator("#output_label_tv")).to_be_hidden()
        expect(page.locator("#output_card_tv")).not_to_have_class(_CONNECTING)

    def test_a_poll_that_has_it_playing_clears_the_label(self, page: "Page", open_home):
        open_home([CONNECTING])
        expect(page.locator("#output_label_tv")).to_have_text("(Connecting)")
        _OUTPUTS[:] = [PLAYING]
        expect(page.locator("#output_label_tv")).to_be_hidden()
        expect(page.locator("#output_card_tv")).not_to_have_class(_CONNECTING)
        expect(page.locator("#output_card_tv .output-toggle .switch")).to_have_css("opacity", "1")
        expect(page.locator("#output_enabled_tv")).to_be_checked()

    def test_a_poll_that_has_it_connecting_sets_the_label(self, page: "Page", open_home):
        open_home([PLAYING])
        expect(page.locator("#output_label_tv")).to_be_hidden()
        _OUTPUTS[:] = [CONNECTING]
        expect(page.locator("#output_label_tv")).to_have_text("(Connecting)")
        expect(page.locator("#output_card_tv")).to_have_class(_CONNECTING)


@_requires_browser
class TestOfflineCard:
    def test_in_a_session_it_reads_offline_with_the_switch_on_and_working(self, page: "Page", open_home):
        open_home([OFFLINE_IN_SESSION])
        expect(page.locator("#output_card_tv")).to_have_class(_OFFLINE)
        expect(page.locator("#output_label_tv")).to_have_text("(offline)")
        expect(page.locator("#output_card_tv .output-toggle .switch")).to_have_css("opacity", "0.45")
        expect(page.locator("#output_enabled_tv")).to_be_checked()
        expect(page.locator("#output_enabled_tv")).to_be_enabled()
        expect(page.locator("#vol_slider_tv")).to_be_disabled()
        _tap(page)
        deadline = time.monotonic() + 5
        while not _POSTS and time.monotonic() < deadline:
            page.wait_for_timeout(50)
        assert _POSTS and _POSTS[-1]["id"] == "tv" and _POSTS[-1]["selected"] is False

    def test_outside_a_session_the_switch_is_off_and_disabled(self, page: "Page", open_home):
        open_home([OFFLINE_OUTSIDE_SESSION])
        expect(page.locator("#output_label_tv")).to_have_text("(offline)")
        expect(page.locator("#output_enabled_tv")).not_to_be_checked()
        expect(page.locator("#output_enabled_tv")).to_be_disabled()
        page.locator("#output_card_tv .output-toggle").click(force=True)
        page.wait_for_timeout(300)
        assert _POSTS == []

    def test_a_session_start_enables_the_switch(self, page: "Page", open_home):
        open_home([OFFLINE_OUTSIDE_SESSION])
        expect(page.locator("#output_enabled_tv")).to_be_disabled()
        _OUTPUTS[:] = [OFFLINE_IN_SESSION]
        expect(page.locator("#output_enabled_tv")).to_be_enabled()
        expect(page.locator("#output_enabled_tv")).to_be_checked()

    def test_the_card_becomes_a_normal_one_when_the_speaker_appears(self, page: "Page", open_home):
        open_home([OFFLINE_IN_SESSION])
        _OUTPUTS[:] = [_row(id="real", connecting=True)]
        page.wait_for_selector("#output_enabled_real", state="attached")
        expect(page.locator("#output_card_real")).to_have_class(_CONNECTING)
        expect(page.locator("#output_card_real")).not_to_have_class(_OFFLINE)
        expect(page.locator("#output_card_tv")).to_have_count(0)


@_requires_browser
class TestServerAndPageBuildAgree:
    @pytest.mark.parametrize("row", [CONNECTING, OFFLINE_IN_SESSION, OFFLINE_OUTSIDE_SESSION, PLAYING],
                             ids=["connecting", "offline_in_session", "offline_outside_session", "playing"])
    def test_the_two_cards_are_the_same(self, page: "Page", open_home, row: dict):
        open_home([row])
        rendered = page.evaluate(_DESCRIBE)
        page.evaluate("(rows) => renderOutputList(rows)", [row])
        built = page.evaluate(_DESCRIBE)
        assert built == rendered


@_requires_browser
class TestRemoteConnectingCard:
    def test_a_connecting_card_shows_and_clears_with_the_poll(self, page: "Page", serve):
        def publish(rows):
            _REMOTE_HOME.clear()
            _REMOTE_HOME.update({"ok": True, "warnings": {}, "outputs": rows})

        publish([CONNECTING])
        _REMOTE_POLLS.clear()
        page.goto(f"{serve(render_remote_home())}/")
        page.wait_for_selector("#output_enabled_tv", state="attached")
        expect(page.locator("#output_label_tv")).to_have_text("(Connecting)", timeout=8000)
        expect(page.locator("#output_card_tv")).to_have_class(_CONNECTING)
        expect(page.locator("#output_enabled_tv")).to_be_enabled()
        expect(page.locator("#output_card_tv .output-toggle .switch")).to_have_css("opacity", "0.45")
        publish([PLAYING])
        expect(page.locator("#output_label_tv")).to_be_hidden(timeout=10000)
        expect(page.locator("#output_card_tv")).not_to_have_class(_CONNECTING)
