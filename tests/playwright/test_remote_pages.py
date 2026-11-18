"""Playwright tests: the remote Home and Equaliser over the gateway.

The pages come from the real renderers and the real ``/a/<id>/`` route; the
state, the change stream and the intents go through the real relay to a fake
appliance (``_remote_stub``). They draw from the state in the page, follow the
other appliance's changes, resync when it restarts, show it offline and go back
to this appliance's page when it cannot be had, and write to it through the
relay.
"""
from __future__ import annotations

import re

import pytest
import _home_stub as stub
from _home_helpers import wait_for, watch_errors
from _remote_stub import PEER_ID, roster, start

try:
    from playwright.sync_api import Page, expect  # type: ignore[attr-defined]
    _PLAYWRIGHT_INSTALLED = True
except ImportError:
    _PLAYWRIGHT_INSTALLED = False
    Page = object  # type: ignore[misc,assignment]
    expect = None  # type: ignore[assignment]

_requires_browser = pytest.mark.skipif(not _PLAYWRIGHT_INSTALLED, reason="playwright not installed")

OTHER_ID = "bbccddeeff0011223344"
THIRD_ID = "ccddeeff001122334455"
FLAT = {"output_bands": [0, 0, 0, 0, 0, 0], "output_gain_db": 0.0, "auto_trim_enabled": False,
        "input_bands": {}, "input_gain": {}}


def parts(*units: dict, **extra) -> dict:
    base = stub.base_parts(outputs=stub.outputs_part(*units), **extra)
    base["appliance"] = {"id": PEER_ID, "hostname": "Kitchen", "configured": True}
    return base


def speaker(**fields) -> dict:
    return stub.unit("tv", fields.pop("name", "Speaker A"), **fields)


@pytest.fixture
def remote(monkeypatch):
    made = []

    def make(**kw):
        rig = start(monkeypatch, **kw)
        made.append(rig)
        return rig
    yield make
    for rig in made:
        rig.close()


@pytest.fixture(autouse=True)
def _errors(page: "Page"):
    e = watch_errors(page)
    # A refused stream and a relay that answers an error are expected here.
    e.ignore += ["EventSource", "Failed to load resource", "net::ERR"]
    yield e
    assert not e.left(), f"console errors: {e.left()}"


def posts(rig, name: str) -> list:
    return [body for n, body in rig.peer.posts if n == name]


def open_home(page, rig, *, wait: bool = True) -> None:
    page.goto(f"{rig.url}/a/{PEER_ID}/")
    if wait:
        page.wait_for_selector("#output_enabled_tv", state="attached")


def toggle(page, on: bool = True) -> None:
    page.evaluate(
        "(on) => { const c = document.getElementById('output_enabled_tv');"
        " c.checked = on; c.dispatchEvent(new Event('change', {bubbles: true})); }", on)


@_requires_browser
class TestRemoteHome:
    def test_it_draws_from_the_state_in_the_page_and_calls_no_old_route(self, page: "Page", remote):
        rig = remote(parts=parts(speaker(name="Kitchen Radio", selected=True)))
        requests = []
        page.on("request", lambda r: requests.append(r.url))
        open_home(page, rig)
        expect(page.locator("#output_card_tv .output-card-name")).to_contain_text("Kitchen Radio")
        expect(page.locator("#output_enabled_tv")).to_be_checked()
        wait_for(page, lambda: any("/api/v1/peers/" + PEER_ID + "/events" in u for u in requests), "the relayed stream")
        assert not any("/api/appliances" in u for u in requests)
        assert page.evaluate("document.title") == "autostream — Kitchen"

    def test_a_change_on_the_other_appliance_shows_at_once(self, page: "Page", remote):
        rig = remote(parts=parts(speaker()))
        open_home(page, rig)
        wait_for(page, lambda: rig.peer.open_streams() >= 1, "the relayed stream", 10)
        expect(page.locator("#output_enabled_tv")).not_to_be_checked()
        rig.peer.push({"outputs": stub.outputs_part(speaker(selected=True))})
        expect(page.locator("#output_enabled_tv")).to_be_checked()

    def test_a_restart_of_the_other_appliance_resyncs_the_page(self, page: "Page", remote):
        rig = remote(parts=parts(speaker()))
        open_home(page, rig)
        wait_for(page, lambda: rig.peer.open_streams() >= 1, "the relayed stream", 10)
        rig.peer.parts["outputs"] = stub.outputs_part(speaker(selected=True), stub.unit("b", "B"))
        rig.peer.new_boot()
        expect(page.locator("#output_card_b")).to_be_attached(timeout=15000)
        expect(page.locator("#output_enabled_tv")).to_be_checked()

    def test_it_goes_back_to_this_appliance_after_three_failures(self, page: "Page", remote):
        rig = remote(parts=parts(speaker()))
        open_home(page, rig)
        wait_for(page, lambda: rig.peer.open_streams() >= 1, "the relayed stream", 10)
        rig.peer.stop()
        page.wait_for_url(f"{rig.url}/", timeout=45000)

    def test_an_appliance_the_relay_cannot_name_goes_back_at_once(self, page: "Page", remote):
        rig = remote(parts=parts(speaker()))
        open_home(page, rig)
        wait_for(page, lambda: rig.peer.open_streams() >= 1, "the relayed stream", 10)
        rig.kind = "unknown"
        rig.peer.new_boot()
        page.wait_for_url(f"{rig.url}/", timeout=20000)

    def test_a_speaker_switched_on_sends_no_volume(self, page: "Page", remote):
        rig = remote(parts=parts(speaker()))
        open_home(page, rig)
        toggle(page)
        wait_for(page, lambda: posts(rig, "outputs.set"), "outputs.set")
        (sent,) = posts(rig, "outputs.set")
        assert sent["args"]["selected"] is True and "volume" not in sent["args"]
        assert sent["client"].startswith("peer:")

    def test_a_pin_speaker_is_paired_through_the_relay(self, page: "Page", remote):
        rig = remote(parts=parts(speaker(name="Lounge TV")))
        replies = [{"ok": False, "result": {"pin_required": True}}, {"ok": True, "result": {}}]

        def reply(name, body):
            r = replies.pop(0) if replies else {"ok": True, "result": {}}
            return 200, {"ok": r["ok"], "error": None, "version": rig.peer.version,
                         "boot": rig.peer.boot, "result": r["result"]}
        rig.peer.intent_reply = reply
        open_home(page, rig)
        toggle(page)
        expect(page.locator("#pinModal")).to_have_class("modal-overlay show")
        page.locator("#pinModalInput").fill("1234")
        page.locator("#pinModalOk").click()
        wait_for(page, lambda: posts(rig, "output.pin.submit"), "output.pin.submit")
        (sent,) = posts(rig, "output.pin.submit")
        assert sent["args"]["pin"] == "1234" and sent["args"]["selected"] is True

    def test_tapping_a_speaker_in_use_elsewhere_opens_that_appliance(self, page: "Page", remote):
        rig = remote(parts=parts(speaker(name="Bedroom TV", in_use_by="Bedroom", in_use_id=OTHER_ID)))
        open_home(page, rig)
        with page.expect_request(lambda r: f"/a/{OTHER_ID}/" in r.url):
            page.locator("#output_card_tv .output-card-name").click()

    def test_the_pin_icon_saves_the_speakers_through_the_relay(self, page: "Page", remote):
        rig = remote(parts=parts(speaker(selected=True), session={"active": True, "source": "turntable"}))
        open_home(page, rig)
        expect(page.locator("#master-volume-card .slider-header #autostart-pin")).to_be_visible()
        page.locator("#autostart-pin").click()
        expect(page.locator("#autoStartModal")).to_have_class("modal-overlay show")
        page.locator("#autoStartYes").click()
        wait_for(page, lambda: posts(rig, "outputs.save_default"), "outputs.save_default")

    def test_the_selector_is_read_again_when_it_opens(self, page: "Page", remote):
        rig = remote(parts=parts(speaker()))
        rig.set_peers(roster(PEER_ID, "Kitchen"))
        open_home(page, rig)
        page.locator("#appliance-selector-btn").click()
        expect(page.locator("#appliance-selector-dropdown a.appliance-selector-option")).to_have_count(2)
        page.locator("body").click(position={"x": 2, "y": 2})
        rig.set_peers(roster(PEER_ID, "Kitchen"), roster(OTHER_ID, "Bedroom", protocol_ok=False),
                      roster(THIRD_ID, "Shed", configured=False))
        with page.expect_request(lambda r: "/api/v1/state?parts=peers" in r.url):
            page.locator("#appliance-selector-btn").click()
        options = page.locator("#appliance-selector-dropdown .appliance-selector-option")
        expect(options).to_have_count(4)
        expect(page.locator("#appliance-selector-dropdown span.appliance-selector-option")).to_have_text(
            ["Bedroom (needs an update)", "Shed (not set up)"])
        expect(page.locator("#appliance-selector-dropdown a.appliance-selector-option")).to_have_count(2)


@_requires_browser
class TestRemoteEqualiser:
    def open(self, page, rig) -> None:
        page.goto(f"{rig.url}/a/{PEER_ID}/equaliser")
        page.wait_for_selector("#peq1_db", state="attached")

    def test_the_sliders_are_the_other_appliances(self, page: "Page", remote):
        rig = remote(parts=parts(eq={**FLAT, "output_bands": [3, -3, 0, 0, 0, 6], "output_gain_db": 1.5}))
        self.open(page, rig)
        expect(page.locator("#peq1_db")).to_have_value("3")
        expect(page.locator("#peq6_db")).to_have_value("6")
        expect(page.locator("#output_gain_db")).to_have_value("1.5")

    def test_a_change_on_the_other_appliance_shows_at_once(self, page: "Page", remote):
        rig = remote(parts=parts(eq=FLAT))
        self.open(page, rig)
        wait_for(page, lambda: rig.peer.open_streams() >= 1, "the relayed stream", 10)
        rig.peer.push({"eq": {**FLAT, "output_bands": [0, 0, 0, 5, 0, 0]}})
        expect(page.locator("#peq4_db")).to_have_value("5")

    def test_a_slider_move_is_an_intent_on_the_other_appliance(self, page: "Page", remote):
        rig = remote(parts=parts(eq=FLAT))
        self.open(page, rig)
        page.evaluate(
            "() => { const s = document.getElementById('peq2_db'); s.value = '4';"
            " s.dispatchEvent(new Event('input', {bubbles: true})); }")
        wait_for(page, lambda: posts(rig, "output.eq.set"), "output.eq.set")
        assert posts(rig, "output.eq.set")[0]["args"] == {"fields": [["peq2_db", "4"]]}

    def test_a_restart_of_the_other_appliance_resyncs_the_page(self, page: "Page", remote):
        rig = remote(parts=parts(eq=FLAT))
        self.open(page, rig)
        wait_for(page, lambda: rig.peer.open_streams() >= 1, "the relayed stream", 10)
        rig.peer.parts["eq"] = {**FLAT, "output_bands": [0, 0, 7, 0, 0, 0]}
        rig.peer.new_boot()
        expect(page.locator("#peq3_db")).to_have_value("7", timeout=15000)

    def test_it_goes_back_at_once_when_the_relay_cannot_name_the_appliance(self, page: "Page", remote):
        rig = remote(parts=parts(eq=FLAT))
        self.open(page, rig)
        wait_for(page, lambda: rig.peer.open_streams() >= 1, "the relayed stream", 10)
        rig.kind = "unknown"
        rig.peer.new_boot()
        page.wait_for_url(f"{rig.url}/", timeout=20000)

    def test_it_goes_back_after_three_failures(self, page: "Page", remote):
        rig = remote(parts=parts(eq=FLAT))
        self.open(page, rig)
        wait_for(page, lambda: rig.peer.open_streams() >= 1, "the relayed stream", 10)
        rig.peer.stop()
        page.wait_for_url(f"{rig.url}/", timeout=45000)

    def test_the_selector_lists_the_appliances(self, page: "Page", remote):
        rig = remote(parts=parts(eq=FLAT))
        rig.set_peers(roster(PEER_ID, "Kitchen"), roster(OTHER_ID, "Bedroom"))
        self.open(page, rig)
        page.locator("#appliance-selector-btn").click()
        hrefs = page.locator("#appliance-selector-dropdown a.appliance-selector-option").evaluate_all(
            "els => els.map(e => e.getAttribute('href'))")
        assert hrefs == ["/equaliser", f"/a/{PEER_ID}/equaliser", f"/a/{OTHER_ID}/equaliser"]


def _entry(kind: str, severity: str, *, subject: str, link: str) -> dict:
    return {"id": f"{kind}_{subject}", "incident": "", "severity": severity, "kind": kind,
            "subject": subject, "title": f"{subject} {kind}", "message": f"{kind} message", "link": link}


@_requires_browser
class TestRemoteWarnings:
    def test_the_other_appliances_cards_are_plain_and_leave_the_service_tab_alone(self, page: "Page", remote):
        stylus = _entry("stylus", "warning", subject="Turntable", link="/service")
        rate = _entry("sample_rate", "warning", subject="CD", link="/setup#input1")
        rig = remote(parts=parts(speaker(), warnings={"entries": [stylus, rate]}))
        open_home(page, rig)
        strip = page.locator("#warnings-strip")
        expect(strip.locator("div.warning-card")).to_have_count(2)
        expect(strip.locator("a.warning-card-link")).to_have_count(0)
        expect(strip.locator(".warning-card-chevron")).to_have_count(0)
        expect(strip.get_by_role("link")).to_have_count(0)
        expect(page.locator("#service-nav-tab")).not_to_have_class(re.compile(r"nav-tab-warn"))
        wait_for(page, lambda: rig.peer.open_streams() >= 1, "the relayed stream", 10)
        belt = _entry("belt", "info", subject="Turntable", link="/service")
        rig.peer.push({"warnings": {"entries": [belt, stylus]}})
        expect(strip.get_by_text("belt message")).to_have_count(1)
        expect(strip.locator("a.warning-card-link")).to_have_count(0)
        expect(page.locator("#service-nav-tab")).not_to_have_class(re.compile(r"nav-tab-warn"))
