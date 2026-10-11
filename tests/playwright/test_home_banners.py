"""Playwright tests: the Home page warning banners show and hide with the status poll.

The page comes from the real Home renderer and the status poll is stubbed.
Each banner in the warnings row is hidden when its text is empty, shown with
its exact text and link when it is not, and follows the poll in both
directions without a reload. The remote (federated) Home page has its own
renderer and poll, covered by a separate class.
"""
from __future__ import annotations

import sys

import pytest
import _home_stub as stub
from _home_stub import render_home, render_remote_home, start_server

sys.path.insert(0, str(stub.REPO_ROOT / "core"))
from autostream_core import SAMPLE_RATE_MISMATCH_BANNER_TEXT  # noqa: E402

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

# name, element id, link, status key, text
_BANNERS = {
    "stylus": ("stylus-warning-banner", "/service", "playback_banner_text",
               "Stylus wear is high: replace soon"),
    "belt": ("belt-warning-banner", "/service", "belt_banner_text",
             "Belt service is due"),
    "bearing": ("bearing-warning-banner", "/service", "bearing_banner_text",
                "Bearing service is due"),
    "dial_update": ("dial-update-warning-banner", "/setup#dials", "dial_update_banner_text",
                    "A dial needs an update"),
    "sample_rate": ("sample-rate-warning-banner", "/setup#input1", "sample_rate_banner_text",
                    "Sample Rate Mismatch: Please enable Dynamic Rate Matching"),
}
_NAMES = list(_BANNERS)


def _id(name: str) -> str:
    return "#" + _BANNERS[name][0]


def _key(name: str) -> str:
    return _BANNERS[name][2]


def _text(name: str) -> str:
    return _BANNERS[name][3]


def _href(name: str) -> str:
    return _BANNERS[name][1]


def _empty_status() -> dict:
    status: dict = {"ok": True}
    for name in _NAMES:
        status[_key(name)] = ""
    return status


def _full_status() -> dict:
    status: dict = {"ok": True}
    for name in _NAMES:
        status[_key(name)] = _text(name)
    return status


@pytest.fixture(scope="module")
def home_url():
    server, url = start_server(render_home())
    try:
        yield url
    finally:
        server.shutdown()


@pytest.fixture(autouse=True)
def _clean_stub():
    yield
    stub.STATUS.clear()
    stub.STATUS_POLLS.clear()
    stub.REMOTE_HOME.clear()
    stub.REMOTE_HOME_POLLS.clear()


def _open(page: "Page", base: str) -> None:
    stub.STATUS_POLLS.clear()
    page.goto(f"{base}/")


def _after_polls(page: "Page", count: int) -> None:
    """Wait until the page has made ``count`` status polls since it loaded."""
    for _ in range(100):
        if len(stub.STATUS_POLLS) >= count:
            return
        page.wait_for_timeout(100)
    raise AssertionError(f"only {len(stub.STATUS_POLLS)} status polls arrived")


@_requires_browser
class TestHomeBanners:
    @pytest.mark.parametrize("name", _NAMES)
    def test_hidden_when_empty(self, page: "Page", home_url: str, name: str):
        stub.set_page(render_home())
        stub.STATUS.update(_empty_status())
        _open(page, home_url)
        _after_polls(page, 1)
        banner = page.locator(_id(name))
        expect(banner).to_have_count(1)
        expect(banner).to_have_css("display", "none")
        expect(banner).to_have_text("")

    @pytest.mark.parametrize("name", _NAMES)
    def test_visible_on_first_render(self, page: "Page", home_url: str, name: str):
        stub.set_page(render_home(banners={name: _text(name)}))
        stub.STATUS.update(_empty_status())
        stub.STATUS[_key(name)] = _text(name)
        _open(page, home_url)
        _after_polls(page, 2)
        banner = page.locator(_id(name))
        expect(banner).to_be_visible()
        expect(banner).to_have_text(_text(name))
        expect(banner).to_have_attribute("href", _href(name))

    @pytest.mark.parametrize("name", _NAMES)
    def test_appears_on_a_poll_without_a_reload(self, page: "Page", home_url: str, name: str):
        stub.set_page(render_home())
        stub.STATUS.update(_empty_status())
        _open(page, home_url)
        _after_polls(page, 1)
        expect(page.locator(_id(name))).to_be_hidden()
        stub.STATUS[_key(name)] = _text(name)
        banner = page.locator(_id(name))
        expect(banner).to_be_visible(timeout=4000)
        expect(banner).to_have_text(_text(name))
        expect(banner).to_have_attribute("href", _href(name))

    @pytest.mark.parametrize("name", _NAMES)
    def test_disappears_on_a_poll_without_a_reload(self, page: "Page", home_url: str, name: str):
        stub.set_page(render_home())
        stub.STATUS.update(_empty_status())
        stub.STATUS[_key(name)] = _text(name)
        _open(page, home_url)
        expect(page.locator(_id(name))).to_be_visible(timeout=4000)
        stub.STATUS[_key(name)] = ""
        expect(page.locator(_id(name))).to_be_hidden(timeout=4000)
        expect(page.locator(_id(name))).to_have_text("")

    @pytest.mark.parametrize("cleared", _NAMES)
    def test_banners_do_not_clobber_one_another(self, page: "Page", home_url: str, cleared: str):
        stub.set_page(render_home())
        stub.STATUS.update(_full_status())
        _open(page, home_url)
        for name in _NAMES:
            expect(page.locator(_id(name))).to_be_visible(timeout=4000)
            expect(page.locator(_id(name))).to_have_text(_text(name))
        stub.STATUS[_key(cleared)] = ""
        expect(page.locator(_id(cleared))).to_be_hidden(timeout=4000)
        for name in _NAMES:
            if name == cleared:
                continue
            expect(page.locator(_id(name))).to_be_visible()
            expect(page.locator(_id(name))).to_have_text(_text(name))
            expect(page.locator(_id(name))).to_have_attribute("href", _href(name))

    def test_the_stylus_banner_follows_the_playback_key_not_its_own_name(
        self, page: "Page", home_url: str
    ):
        stub.set_page(render_home())
        stub.STATUS.update(_empty_status())
        stub.STATUS["stylus_banner_text"] = _text("stylus")
        stub.STATUS["playback_banner_text"] = ""
        _open(page, home_url)
        _after_polls(page, 2)
        expect(page.locator(_id("stylus"))).to_be_hidden()
        stub.STATUS["playback_banner_text"] = _text("stylus")
        expect(page.locator(_id("stylus"))).to_be_visible(timeout=4000)


def _levels(*mismatching: int, matching: bool = False) -> list:
    """Two input level entries; the numbered inputs report a mismatch."""
    return [
        {
            "index": n,
            "label": f"Input {n}",
            "rate_lock": "mismatch" if n in mismatching else "locked",
            "rate_mismatch_hz": 44100 if n in mismatching else 0,
            "dynamic_rate_matching": matching,
        }
        for n in (1, 2)
    ]


def _sample_rate_status(*mismatching: int) -> dict:
    status = _empty_status()
    status["sample_rate_banner_text"] = SAMPLE_RATE_MISMATCH_BANNER_TEXT
    status["input_levels"] = _levels(*mismatching)
    return status


@_requires_browser
class TestSampleRateBanner:
    def test_the_text_is_the_agreed_string(self, page: "Page", home_url: str):
        assert SAMPLE_RATE_MISMATCH_BANNER_TEXT == (
            "Sample Rate Mismatch: Please enable Dynamic Rate Matching"
        )
        stub.set_page(render_home())
        stub.STATUS.update(_sample_rate_status(1))
        _open(page, home_url)
        expect(page.locator(_id("sample_rate"))).to_have_text(
            SAMPLE_RATE_MISMATCH_BANNER_TEXT, timeout=4000
        )

    def test_it_is_shown_on_first_render_and_links_to_the_mismatching_input(
        self, page: "Page", home_url: str
    ):
        stub.set_page(render_home(
            banners={"sample_rate": SAMPLE_RATE_MISMATCH_BANNER_TEXT},
            levels=_levels(2),
        ))
        stub.STATUS.update(_sample_rate_status(2))
        _open(page, home_url)
        _after_polls(page, 2)
        banner = page.locator(_id("sample_rate"))
        expect(banner).to_be_visible()
        expect(banner).to_have_text(SAMPLE_RATE_MISMATCH_BANNER_TEXT)
        expect(banner).to_have_attribute("href", "/setup#input2")

    def test_the_link_follows_the_mismatching_input_without_a_reload(
        self, page: "Page", home_url: str
    ):
        stub.set_page(render_home())
        stub.STATUS.update(_sample_rate_status(2))
        _open(page, home_url)
        banner = page.locator(_id("sample_rate"))
        expect(banner).to_have_attribute("href", "/setup#input2", timeout=4000)
        stub.STATUS["input_levels"] = _levels(1, 2)
        expect(banner).to_have_attribute("href", "/setup#input1", timeout=4000)
        stub.STATUS["input_levels"] = _levels(2)
        expect(banner).to_have_attribute("href", "/setup#input2", timeout=4000)
        expect(banner).to_be_visible()

    def test_the_link_moves_from_input_1_to_input_2(self, page: "Page", home_url: str):
        stub.set_page(render_home())
        stub.STATUS.update(_sample_rate_status(1))
        _open(page, home_url)
        banner = page.locator(_id("sample_rate"))
        expect(banner).to_have_attribute("href", "/setup#input1", timeout=4000)
        stub.STATUS["input_levels"] = _levels(2)
        expect(banner).to_have_attribute("href", "/setup#input2", timeout=4000)

    def test_clicking_it_goes_to_the_mismatching_inputs_setup_card(
        self, page: "Page", home_url: str
    ):
        stub.set_page(render_home())
        stub.STATUS.update(_sample_rate_status(2))
        _open(page, home_url)
        banner = page.locator(_id("sample_rate"))
        expect(banner).to_have_attribute("href", "/setup#input2", timeout=4000)
        banner.click()
        page.wait_for_url("**/setup#input2")

    def test_it_is_hidden_once_the_setting_has_taken_effect(
        self, page: "Page", home_url: str
    ):
        stub.set_page(render_home(
            banners={"sample_rate": SAMPLE_RATE_MISMATCH_BANNER_TEXT},
            levels=_levels(1),
        ))
        stub.STATUS.update(_empty_status())
        stub.STATUS["input_levels"] = _levels(matching=True)
        _open(page, home_url)
        _after_polls(page, 1)
        expect(page.locator(_id("sample_rate"))).to_be_hidden()
        expect(page.locator(_id("sample_rate"))).to_have_text("")

    def test_an_older_monitor_shows_no_banner_and_breaks_nothing(
        self, page: "Page", home_url: str
    ):
        errors: list = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        stub.set_page(render_home())
        stub.STATUS.update({
            "ok": True,
            "playback_banner_text": _text("stylus"),
            "belt_banner_text": "",
            "bearing_banner_text": "",
            "dial_update_banner_text": "",
            "input_levels": [
                {"index": 1, "label": "Input 1", "dbfs": -40.0, "detected_hz": 48000.0,
                 "is_above_threshold": True},
            ],
        })
        _open(page, home_url)
        expect(page.locator(_id("stylus"))).to_be_visible(timeout=4000)
        _after_polls(page, 2)
        expect(page.locator(_id("sample_rate"))).to_be_hidden()
        assert not errors, f"JavaScript errors: {errors}"


def _level(**rate) -> dict:
    level = {"index": 1, "label": "Input 1", "dbfs": -30.0, "detected_hz": 0.0,
             "is_above_threshold": True}
    level.update(rate)
    return level


_LOCKED_48 = {"rate_lock": "locked", "detected_hz": 48000.0, "detected_khz": "48 kHz"}
_MISMATCH_44 = {"rate_lock": "mismatch", "detected_hz": 48000.0, "detected_khz": "48 kHz",
                "rate_mismatch_hz": 44100, "rate_mismatch_khz": "44.1 kHz"}


@_requires_browser
class TestInputCardRateText:
    """The rate line on the Now Playing card, shown only with input detail on."""

    @pytest.mark.parametrize("rate, text", [
        (_LOCKED_48, "Locked · 48 kHz"),
        ({"rate_lock": "locked", "detected_hz": 44100.0, "detected_khz": "44.1 kHz"},
         "Locked · 44.1 kHz"),
        ({"rate_lock": "acquiring", "detected_hz": 0.0, "detected_khz": ""}, "Acquiring"),
        # A stopped input has no rate lock to report.
        ({"rate_lock": "", "detected_hz": 44100.0, "detected_khz": "44.1 kHz"}, ""),
        ({"rate_lock": "", "detected_hz": 0.0, "detected_khz": ""}, ""),
        (_MISMATCH_44, "Mismatch · 44.1 kHz"),
        # An older monitor reports none of the rate keys.
        ({"detected_hz": 48000.0, "detected_khz": "48 kHz"}, "Locked · 48 kHz"),
        ({"detected_hz": 0.0, "detected_khz": ""}, ""),
    ])
    def test_the_text_is_the_same_on_first_render_and_after_a_poll(
        self, page: "Page", home_url: str, rate: dict, text: str
    ):
        stub.set_page(render_home(levels=[_level(**rate)], show_input_detail=True))
        _open(page, home_url)
        expect(page.locator("#np-signal")).to_have_text(text)
        stub.STATUS.update(_empty_status())
        stub.STATUS["input_levels"] = [_level(**rate)]
        _after_polls(page, 2)
        expect(page.locator("#np-signal")).to_have_text(text)

    def test_the_text_follows_the_poll(self, page: "Page", home_url: str):
        stub.set_page(render_home(levels=[_level(**_LOCKED_48)], show_input_detail=True))
        stub.STATUS.update(_empty_status())
        stub.STATUS["input_levels"] = [_level(**_LOCKED_48)]
        _open(page, home_url)
        expect(page.locator("#np-signal")).to_have_text("Locked · 48 kHz")
        stub.STATUS["input_levels"] = [_level(**_MISMATCH_44)]
        expect(page.locator("#np-signal")).to_have_text(
            "Mismatch · 44.1 kHz", timeout=4000
        )

    def test_no_text_without_input_detail(self, page: "Page", home_url: str):
        stub.set_page(render_home(levels=[_level(**_LOCKED_48)]))
        stub.STATUS.update(_empty_status())
        stub.STATUS["input_levels"] = [_level(**_LOCKED_48)]
        _open(page, home_url)
        _after_polls(page, 2)
        expect(page.locator("#np-signal")).to_have_text("")


_REMOTE_NAMES = ["stylus", "belt", "bearing"]


def _remote_home(warnings: dict) -> dict:
    return {"ok": True, "warnings": warnings}


@pytest.fixture(scope="module")
def remote_home_url():
    server, url = start_server(render_remote_home())
    try:
        yield url
    finally:
        server.shutdown()


@_requires_browser
class TestRemoteHomeBanners:
    def test_the_three_banners_show_the_polled_warnings(
        self, page: "Page", remote_home_url: str
    ):
        stub.set_page(render_remote_home())
        stub.REMOTE_HOME.update(_remote_home({n: _text(n) for n in _REMOTE_NAMES}))
        page.goto(f"{remote_home_url}/")
        for name in _REMOTE_NAMES:
            expect(page.locator(_id(name))).to_be_visible(timeout=4000)
            expect(page.locator(_id(name))).to_have_text(_text(name))

    def test_a_banner_hides_when_its_warning_clears_and_the_others_stay(
        self, page: "Page", remote_home_url: str
    ):
        stub.set_page(render_remote_home())
        stub.REMOTE_HOME.update(_remote_home({n: _text(n) for n in _REMOTE_NAMES}))
        page.goto(f"{remote_home_url}/")
        expect(page.locator(_id("belt"))).to_be_visible(timeout=4000)
        stub.REMOTE_HOME["warnings"]["belt"] = ""
        expect(page.locator(_id("belt"))).to_be_hidden(timeout=8000)
        for name in ("stylus", "bearing"):
            expect(page.locator(_id(name))).to_be_visible()
            expect(page.locator(_id(name))).to_have_text(_text(name))

    def test_a_banner_appears_when_a_warning_arrives_after_the_first_poll(
        self, page: "Page", remote_home_url: str
    ):
        stub.set_page(render_remote_home())
        stub.REMOTE_HOME.update(_remote_home({n: "" for n in _REMOTE_NAMES}))
        page.goto(f"{remote_home_url}/")
        for _ in range(100):
            if stub.REMOTE_HOME_POLLS:
                break
            page.wait_for_timeout(100)
        expect(page.locator(_id("bearing"))).to_be_hidden()
        stub.REMOTE_HOME["warnings"]["bearing"] = _text("bearing")
        expect(page.locator(_id("bearing"))).to_be_visible(timeout=8000)
        expect(page.locator(_id("bearing"))).to_have_text(_text("bearing"))

    def test_only_the_maintenance_banners_exist_on_the_remote_page(
        self, page: "Page", remote_home_url: str
    ):
        stub.set_page(render_remote_home())
        stub.REMOTE_HOME.update(_remote_home({n: _text(n) for n in _REMOTE_NAMES}))
        page.goto(f"{remote_home_url}/")
        expect(page.locator(_id("stylus"))).to_be_visible(timeout=4000)
        for name in _REMOTE_NAMES:
            expect(page.locator(_id(name))).to_have_count(1)
        expect(page.locator("#dial-update-warning-banner")).to_have_count(0)
        expect(page.locator("#sample-rate-warning-banner")).to_have_count(0)

    def test_a_sample_rate_warning_in_the_payload_is_ignored(
        self, page: "Page", remote_home_url: str
    ):
        errors: list = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        stub.set_page(render_remote_home())
        warnings = {n: _text(n) for n in _REMOTE_NAMES}
        warnings["sample_rate"] = SAMPLE_RATE_MISMATCH_BANNER_TEXT
        stub.REMOTE_HOME.update(_remote_home(warnings))
        page.goto(f"{remote_home_url}/")
        expect(page.locator(_id("stylus"))).to_be_visible(timeout=4000)
        for _ in range(100):
            if len(stub.REMOTE_HOME_POLLS) >= 2:
                break
            page.wait_for_timeout(100)
        expect(page.locator("#sample-rate-warning-banner")).to_have_count(0)
        expect(page.get_by_text(SAMPLE_RATE_MISMATCH_BANNER_TEXT)).to_have_count(0)
        assert not errors, f"JavaScript errors: {errors}"
