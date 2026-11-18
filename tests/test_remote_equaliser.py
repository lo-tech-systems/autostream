"""tests/test_remote_equaliser.py

The remote Equaliser (/a/<id>/equaliser) through a real server whose relay
follows a fake appliance: what the route does and what the page holds, which
is the Equaliser shell with the relay's routes as its base and the sliders
set from the other appliance's eq part. Also the shell's own layout and the
sample rate its curve uses.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_logging as log_setup
from _source_text import linked_static, page_data, static_text
from relay_rig import OWN_ID, PEER_ID, RelayRig
import webui.browser.equaliser as equaliser
from settings_fixtures import CONTROLS_OTHER_APPLIANCES, viewed_state

_LOCAL_ID = "00000000000000000000"
EQ = {"output_bands": [1, -2, 3, -4, 5, -6], "output_gain_db": 2.5, "auto_trim_enabled": True,
      "input_bands": {}, "input_gain": {}}


@pytest.fixture
def rig(monkeypatch):
    log_setup.reset_for_tests()
    made = []
    monkeypatch.setattr(equaliser, "get_system_hostname", lambda: "Lounge")
    monkeypatch.setattr(equaliser, "get_live_monitor_output_rate", lambda fallback: 96000)

    def make(**kw):
        r = RelayRig(monkeypatch, **kw)
        page_state = viewed_state(CONTROLS_OTHER_APPLIANCES)
        page_state.config_path, page_state.state_path = "dummy.ini", "dummy-state.json"
        monkeypatch.setattr("webui.session_state.STATE", page_state)
        assert r.ready()
        made.append(r)
        return r
    yield make
    for r in made:
        r.close()


class TestRouting:
    def test_a_followed_appliance_gets_the_equaliser_shell(self, rig):
        r = rig(parts={"eq": EQ})
        status, _, body = r.page(f"/a/{PEER_ID}/equaliser")
        assert status == 200 and "page/equaliser.js" in linked_static(body)

    def test_this_appliances_own_id_goes_to_its_equaliser(self, rig):
        r = rig()
        assert r.page(f"/a/{OWN_ID}/equaliser")[:2] == (302, "/equaliser")

    def test_control_off_goes_home(self, rig):
        r = rig()
        r.control = False
        assert r.page(f"/a/{PEER_ID}/equaliser")[:2] == (302, "/")

    @pytest.mark.parametrize("kind", ["unknown", "conflict", "control_off", "unconfigured"])
    def test_what_cannot_be_shown_goes_home(self, rig, kind):
        r = rig(kind=kind)
        assert r.page(f"/a/{PEER_ID}/equaliser")[:2] == (302, "/")

    def test_no_sign_in_is_needed_with_a_pin_set(self, rig):
        r = rig()
        r.server.auth._pin_value = "secret"
        r.server.auth._pin_status = "ok"
        assert r.page(f"/a/{PEER_ID}/equaliser")[0] == 200


class TestPage:
    def render(self, r):
        status, _, body = r.page(f"/a/{PEER_ID}/equaliser")
        assert status == 200
        return page_data(body), body

    def test_the_island_follows_the_relay(self, rig):
        r = rig(parts={"eq": EQ})
        island, _ = self.render(r)
        assert island["base"] == f"/api/v1/peers/{PEER_ID}" and island["own"] is False
        assert island["state"]["boot"] == r.peer.boot
        assert island["state"]["parts"]["eq"] == EQ
        assert island["selector"][0]["is_bound"] is True

    def test_the_sliders_are_the_other_appliances_values(self, rig):
        r = rig(parts={"eq": EQ})
        _, body = self.render(r)
        for key, value in zip(["peq1_db", "peq2_db", "peq3_db", "peq4_db", "peq5_db", "peq6_db"], EQ["output_bands"]):
            assert f"id='{key}' value='{value:.0f}'" in body
        assert "id='output_gain_db' value='2.5'" in body
        assert "id='output_auto_trim' checked" in body

    def test_the_selector_is_in_the_header_and_the_flat_button_in_the_card(self, rig):
        r = rig(parts={"eq": EQ})
        _, body = self.render(r)
        header = body[body.index("<div class='eq-page-header'>"):body.index("<div class='eq-section'>")]
        assert "appliance-selector" in header and "eq-flat-btn" not in header
        assert body.index("id='eq-flat-btn'") > body.index("<div class='eq-section'>")

    def test_the_page_is_the_shared_shell(self, rig):
        r = rig(parts={"eq": EQ})
        _, body = self.render(r)
        files = linked_static(body)
        assert "page/equaliser_curve.js" in files and "page/remote_equaliser.js" not in files
        assert "page/appliance_selector.js" not in files
        assert "/api/appliances" not in body
        assert "<title>Equaliser — Kitchen</title>" in body

    def test_the_curve_uses_this_appliances_monitor_rate(self, rig):
        r = rig(parts={"eq": EQ})
        island, _ = self.render(r)
        assert island["eq_fs"] == 96000

    def test_the_csrf_token_is_on_the_page(self, rig):
        r = rig(parts={"eq": EQ})
        _, body = self.render(r)
        assert "id='_csrfField'" in body


class TestShell:
    def test_the_local_cards_keep_the_flat_button_layout(self):
        from autostream_eq_bands import OUTPUT_PEQ_BANDS
        values = {band["key"]: 0.0 for band in OUTPUT_PEQ_BANDS}
        eq = SimpleNamespace(gain_db=0.0, auto_trim_enabled=False, **values)
        html = equaliser._eq_cards_html(eq, selector_html="<div id='appliance-selector'></div>")
        header = html[html.index("<div class='eq-page-header'>"):html.index("<div class='eq-section'>")]
        assert "appliance-selector" in header and "eq-flat-btn" not in header
        assert "id='eq-flat-btn'" in html and ">Flat</button>" in html and ">Reset</button>" not in html

    def test_the_values_come_from_an_eq_part(self):
        eq = equaliser._eq_from_part(EQ)
        assert (eq.peq1_db, eq.peq6_db, eq.gain_db, eq.auto_trim_enabled) == (1.0, -6.0, 2.5, True)

    def test_a_part_with_nothing_in_it_is_flat(self):
        eq = equaliser._eq_from_part({})
        assert (eq.peq1_db, eq.gain_db, eq.auto_trim_enabled) == (0.0, 0.0, False)


class TestCurveSampleRate:
    """The curve's sample rate is the monitor's reported output rate, and 48000
    when the monitor cannot be reached."""

    def test_curve_fs_uses_monitor_output_rate(self):
        with patch("webui.browser.equaliser.get_live_monitor_output_rate", return_value=48000) as stub:
            assert equaliser._curve_fs() == 48000
        stub.assert_called_once_with(fallback=48000)

    def _local(self, **patches):
        state = viewed_state(CONTROLS_OTHER_APPLIANCES)
        state.config_path = "dummy.ini"
        handler = MagicMock()
        chunks = []
        handler.wfile.write = lambda data: chunks.append(data)
        handler._csrf_token = "testcsrf"
        handler._pending_set_cookies = []
        parsed = MagicMock()
        parsed.webui.dark_mode = False
        parsed.webui.show_hostname_on_home = False
        parsed.output_eq = SimpleNamespace(
            gain_db=0.0, auto_trim_enabled=False,
            peq1_db=0.0, peq2_db=0.0, peq3_db=0.0, peq4_db=0.0, peq5_db=0.0, peq6_db=0.0)
        with patch("webui.common._config_snapshot", return_value=parsed), \
             patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID), \
             patch("webui.browser.equaliser.get_system_hostname", return_value="bound-host"):
            if "rate" in patches:
                with patch("webui.browser.equaliser.get_live_monitor_output_rate",
                           return_value=patches["rate"]):
                    equaliser.send_equaliser_page(handler, state)
            else:
                equaliser.send_equaliser_page(handler, state)
        return b"".join(chunks).decode("utf-8", errors="replace")

    def test_local_page_embeds_the_live_output_rate(self):
        html = self._local(rate=96000)
        assert page_data(html)["eq_fs"] == 96000
        assert "page/equaliser_curve.js" in linked_static(html)
        assert "var _EQ_FS        = pageData.eq_fs;" in static_text("page/equaliser_curve.js")

    def test_page_falls_back_to_48000_when_the_monitor_is_unreachable(self):
        html = self._local()
        assert page_data(html)["eq_fs"] == equaliser._CURVE_FS_FALLBACK == 48000
        assert "page/appliance_selector.css" in linked_static(html)
        assert "nav-tab-disabled" in static_text("page/appliance_selector.css")
