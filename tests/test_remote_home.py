"""tests/test_remote_home.py

The remote Home (/a/<id>/) through a real server whose relay follows a fake
appliance: what each thing the id can name does, and what the page it gets
holds. The page is the Home shell with the relay's routes as its base.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_logging as log_setup
import autostream_state as state
from _source_text import linked_static, page_data
from autostream_peer_client import RosterEntry
from autostream_protocol import PROTOCOL
from relay_rig import OWN_ID, PEER_ID, RelayRig
import webui.browser.home as home
from settings_fixtures import viewed_state

OTHER_ID = "bbccddeeff0011223344"
THIRD_ID = "ccddeeff001122334455"
SETTINGS = {"webui": {"show_hostname_on_home": True, "control_other_appliances": True,
                      "show_input_detail": True}}


@pytest.fixture
def rig(monkeypatch):
    log_setup.reset_for_tests()
    made = []
    monkeypatch.setattr(home, "get_setting", lambda *a, **k: SimpleNamespace(ok=False, value=None))
    monkeypatch.setattr(home, "get_system_hostname", lambda: "Lounge")

    def make(**kw):
        r = RelayRig(monkeypatch, **kw)
        page_state = viewed_state(SETTINGS)
        page_state.config_path, page_state.state_path = "dummy.ini", "dummy-state.json"
        monkeypatch.setattr("webui.session_state.STATE", page_state)
        made.append(r)
        return r
    yield make
    for r in made:
        r.close()


def ready(r):
    assert r.ready()
    return r


def peers(*rows):
    state.store().publish_for_tests("peers", state.PeersPart(tuple(RosterEntry(**r) for r in rows)))


def roster(peer_id, hostname, **fields):
    row = dict(id=peer_id, hostname=hostname, version="1.0", control=True, reachable=True,
               protocol_ok=True, access="playback", configured=True, playing=False)
    row.update(fields)
    return row


class TestRouting:
    def test_a_followed_appliance_gets_the_shell(self, rig):
        r = ready(rig())
        status, _, body = r.page(f"/a/{PEER_ID}/")
        assert status == 200 and "home_main.js" in body

    def test_no_trailing_slash_is_served_too(self, rig):
        r = ready(rig())
        assert r.page(f"/a/{PEER_ID}")[0] == 200

    def test_this_appliances_own_id_goes_to_home(self, rig):
        r = ready(rig())
        assert r.page(f"/a/{OWN_ID}/")[:2] == (302, "/")

    def test_this_appliances_own_id_equaliser_goes_to_its_equaliser(self, rig):
        r = ready(rig())
        assert r.page(f"/a/{OWN_ID}/equaliser")[:2] == (302, "/equaliser")

    def test_a_malformed_id_is_not_found(self, rig):
        r = ready(rig())
        assert r.page("/a/invalid/")[0] == 404

    def test_control_off_goes_home(self, rig):
        r = ready(rig())
        r.control = False
        assert r.page(f"/a/{PEER_ID}/")[:2] == (302, "/")

    @pytest.mark.parametrize("kind", ["unknown", "invalid", "conflict", "control_off", "unconfigured"])
    def test_what_cannot_be_shown_goes_home(self, rig, kind):
        r = ready(rig(kind=kind))
        assert r.page(f"/a/{PEER_ID}/")[:2] == (302, "/")

    def test_an_appliance_on_another_protocol_goes_home(self, rig):
        from autostream_state import store  # noqa: F401  (the page reads the store)
        r = rig(peer_protocol=PROTOCOL + 1)
        from stream_helpers import wait_for
        assert wait_for(lambda: not r.client.snapshot().protocol_ok)
        assert r.page(f"/a/{PEER_ID}/")[:2] == (302, "/")

    def test_no_sign_in_is_needed_with_a_pin_set(self, rig):
        r = ready(rig())
        r.server.auth._pin_value = "secret"
        r.server.auth._pin_status = "ok"
        assert r.page(f"/a/{PEER_ID}/")[0] == 200


class TestPage:
    def island(self, r, path=None):
        status, _, body = r.page(path or f"/a/{PEER_ID}/")
        assert status == 200
        return page_data(body), body

    def test_the_island_follows_the_relay(self, rig):
        r = ready(rig(parts={"outputs": {"units": []}}))
        island, _ = self.island(r)
        assert island["base"] == f"/api/v1/peers/{PEER_ID}"
        assert island["own"] is False
        assert island["state"]["boot"] == r.peer.boot
        assert island["state"]["parts"]["outputs"] == {"units": []}

    def test_the_island_state_is_the_relays_state_body(self, rig):
        from webui.peer import relay
        r = ready(rig())
        island, _ = self.island(r)
        body = relay.state_body(r.client.snapshot())
        assert set(island["state"]) == set(body)
        assert island["state"]["part_versions"] == body["part_versions"]

    def test_the_input_detail_preference_is_off_for_another_appliance(self, rig):
        r = ready(rig())
        assert self.island(r)[0]["prefs"]["show_input_detail"] is False
        assert page_data(r.page("/")[2])["prefs"]["show_input_detail"] is True

    def test_the_title_names_the_appliance(self, rig):
        r = ready(rig())
        _, body = self.island(r)
        assert "<title>autostream — Kitchen</title>" in body

    def test_the_page_is_the_shared_shell(self, rig):
        r = ready(rig())
        _, body = self.island(r)
        files = linked_static(body)
        assert "page/home/home_main.js" in files
        for old in ("page/remote_home.js", "page/home_cards.js", "render_fragments.js",
                    "page/start_failure.js", "page/appliance_selector.js"):
            assert old not in files
        assert "/api/appliances" not in body

    def test_the_csrf_token_is_on_the_page(self, rig):
        r = ready(rig())
        _, body = self.island(r)
        assert "window.__CSRF=" in body and "csrf-token" in body

    def test_the_top_banner_is_the_peers_critical_warnings(self, rig):
        def warn(severity, title):
            return {"id": title, "severity": severity, "title": title, "message": "m",
                    "kind": "k", "subject": "", "link": ""}
        r = ready(rig(parts={"warnings": {"entries": [
            warn("critical", "Peer broken"), warn("warning", "Minor"), warn("critical", "Peer worse")]}}))
        _, body = self.island(r)
        banner = body.split("red-banner", 1)[1].split("</div>", 1)[0]
        assert "Peer broken: m +1 more" in banner and "Minor" not in banner

    def test_this_appliances_warnings_are_not_the_banner(self, rig):
        r = ready(rig())
        state.store().publish_for_tests("warnings", state.WarningsPart((state.WarningEntry(
            "w", "", "critical", "k", "", "Local fault", "m", None, "week"),)))
        _, body = self.island(r)
        assert "Local fault" not in body


class TestSelector:
    def test_it_lists_this_appliance_then_the_ones_it_may_control(self, rig):
        r = ready(rig())
        peers(roster(PEER_ID, "Kitchen"), roster(OTHER_ID, "Bedroom"),
              roster(THIRD_ID, "Shed", control=False))
        island = page_data(r.page(f"/a/{PEER_ID}/")[2])
        assert [(a["hostname"], a["is_bound"]) for a in island["selector"]] == [
            ("Lounge", True), ("Kitchen", False), ("Bedroom", False)]

    def test_the_menu_links_each_appliance_and_marks_the_current_one(self, rig):
        r = ready(rig())
        peers(roster(PEER_ID, "Kitchen"), roster(OTHER_ID, "Bedroom"))
        body = r.page(f"/a/{PEER_ID}/")[2]
        assert 'href="/"' in body and f'href="/a/{OTHER_ID}/"' in body
        assert f'data-current-id="{PEER_ID}"' in body
        assert "appliance-selector-option-active" in body

    def test_an_appliance_needing_an_update_or_setup_is_listed_without_a_link(self, rig):
        r = ready(rig())
        peers(roster(PEER_ID, "Kitchen"), roster(OTHER_ID, "Bedroom", protocol_ok=False),
              roster(THIRD_ID, "Shed", configured=False))
        body = r.page(f"/a/{PEER_ID}/")[2]
        assert "Bedroom (needs an update)" in body and "Shed (not set up)" in body
        assert f'href="/a/{OTHER_ID}/"' not in body and f'href="/a/{THIRD_ID}/"' not in body

    def test_the_local_page_lists_the_same_appliances(self, rig):
        r = ready(rig())
        peers(roster(PEER_ID, "Kitchen"))
        island = page_data(r.page("/")[2])
        assert [a["hostname"] for a in island["selector"]] == ["Lounge", "Kitchen"]
        assert island["own"] is True and island["base"] == "/api/v1"
