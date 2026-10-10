"""Home page "Dial updates required" banner and the Setup page dial card flag.

A dial that is currently sighted but advertises an older dial_proto than the
appliance does works in an older dialect; the Home banner invites the owner to
update it and links to the Setup page's dial card, where each such dial is
flagged "Needs update" beside its Update firmware button.  Only dials sighted
now count.
"""
from __future__ import annotations

import json
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_appliance_models as models
import autostream_dials as dials
import autostream_webui_page_setup as setup
from autostream_webui_api import send_status_json
from autostream_webui_page_airplay import send_airplay_page

_BANNER = "Dial updates required"
_BANNER_OPEN = "<a id='dial-update-warning-banner' href='/setup#dials' style='display:"


def _sighting(uuid="u1", dial_proto="", version="1.0.0") -> dials.DialSighting:
    return dials.DialSighting(
        uuid=uuid, name="Dial", version=version, ip="192.0.2.9", port=7842,
        pin_recovery=False, dial_proto=dial_proto,
    )


def _sightings(*items):
    return patch("autostream_dials.get_all_sightings", return_value=list(items))


# ---------------------------------------------------------------------------
# Banner text
# ---------------------------------------------------------------------------

class TestBannerText:
    def test_empty_when_no_dials_sighted(self):
        with _sightings():
            assert dials.build_dial_update_banner_text() == ""

    def test_empty_when_all_sighted_dials_advertise_current_dialect(self):
        with _sightings(_sighting("a", "v3"), _sighting("b", "v3")):
            assert dials.build_dial_update_banner_text() == ""

    def test_one_legacy_dial_gives_banner(self):
        with _sightings(_sighting("a", "")):
            assert dials.build_dial_update_banner_text() == _BANNER

    def test_same_text_for_any_count(self):
        with _sightings(_sighting("a", ""), _sighting("b", ""), _sighting("c", "v3")):
            assert dials.build_dial_update_banner_text() == _BANNER

    def test_unknown_dialect_counts_as_needing_update(self):
        with _sightings(_sighting("a", "v1")):
            assert dials.build_dial_update_banner_text() == _BANNER

    def test_v2_dial_against_v3_appliance_gives_banner(self):
        with _sightings(_sighting("a", "v2")):
            assert dials.build_dial_update_banner_text() == _BANNER

    def test_dial_newer_than_the_appliance_gives_no_banner(self):
        with _sightings(_sighting("a", "v4")):
            assert dials.build_dial_update_banner_text() == ""


# ---------------------------------------------------------------------------
# Status payload and home state
# ---------------------------------------------------------------------------

def _status_body() -> dict:
    sent: dict = {}
    h = MagicMock()
    h.send_response.side_effect = lambda code: sent.__setitem__("code", code)
    h.wfile.write.side_effect = lambda data: sent.__setitem__("body", json.loads(data))
    with patch("autostream_webui_api.get_playback_snapshot") as gp:
        gp.return_value.to_public_dict.return_value = {}
        gp.return_value.stylus_banner_text = ""
        gp.return_value.belt_banner_text = ""
        gp.return_value.bearing_banner_text = ""
        send_status_json(h)
    return sent["body"]


class TestStatusPayload:
    def test_status_carries_banner_text_for_legacy_dial(self):
        with _sightings(_sighting("a", "")):
            assert _status_body()["dial_update_banner_text"] == _BANNER

    def test_status_banner_text_empty_when_all_current(self):
        with _sightings(_sighting("a", "v3")):
            assert _status_body()["dial_update_banner_text"] == ""

    def test_status_banner_text_empty_when_none_sighted(self):
        with _sightings():
            assert _status_body()["dial_update_banner_text"] == ""


def _home_state(tmp_path) -> dict:
    cfg = tmp_path / "autostream.json"
    cfg.write_text("{}", encoding="utf-8")
    playback = MagicMock()
    playback.to_public_dict.return_value = {}
    playback.stylus_banner_text = ""
    playback.belt_banner_text = ""
    playback.bearing_banner_text = ""
    with ExitStack() as stack:
        for p in (
            patch("autostream_appliance_models.locked_load_config", return_value={}),
            patch("autostream_appliance_models.parse_config", return_value=MagicMock()),
            patch("autostream_appliance_models.get_setting",
                  return_value=MagicMock(ok=True, value="2250")),
            patch("autostream_appliance_models.list_outputs",
                  return_value=MagicMock(ok=True, outputs=[])),
            patch("autostream_appliance_models.get_monitor_levels_dbfs", return_value=[]),
            patch("autostream_appliance_models.get_playback_snapshot", return_value=playback),
            patch("autostream_appliance_models.get_appliance_id", return_value="aabbccdd1122"),
            patch("autostream_appliance_models.get_system_hostname", return_value="host"),
            patch("autostream_appliance_models.get_app_version", return_value="2.0.0"),
        ):
            stack.enter_context(p)
        return models.build_home_state(str(cfg))


class TestHomeState:
    def test_warning_present_for_legacy_dial(self, tmp_path):
        with _sightings(_sighting("a", "")):
            assert _home_state(tmp_path)["warnings"]["dial_update"] == _BANNER

    def test_warning_empty_when_all_current(self, tmp_path):
        with _sightings(_sighting("a", "v3")):
            assert _home_state(tmp_path)["warnings"]["dial_update"] == ""

    def test_warning_empty_when_scanner_fails(self, tmp_path):
        with patch("autostream_dials.get_all_sightings", side_effect=RuntimeError("x")):
            assert _home_state(tmp_path)["warnings"]["dial_update"] == ""


# ---------------------------------------------------------------------------
# Home page HTML
# ---------------------------------------------------------------------------

def _render_home() -> str:
    handler = MagicMock()
    chunks: list = []
    handler.wfile.write = lambda d: chunks.append(d)
    handler._csrf_token = "t"
    handler._pending_set_cookies = []
    auth = MagicMock()
    auth.get_csrf_token.return_value = "t"
    state = MagicMock()
    state.config_path = "dummy.ini"

    parsed = MagicMock()
    parsed.owntone.base_url = "http://localhost:3689"
    parsed.owntone.output_name = "autostream"
    parsed.owntone.volume_percent = 20
    parsed.webui.show_master_volume = False
    parsed.webui.show_input_detail = False
    parsed.webui.show_hostname_on_home = False
    parsed.webui.control_other_appliances = False
    parsed.webui.hidden_outputs = []
    parsed.webui.dark_mode = False
    parsed.track_identification = MagicMock(enabled=False)
    snap = MagicMock()
    snap.inputs = {}
    snap.stylus_banner_text = ""
    snap.belt_banner_text = ""
    snap.bearing_banner_text = ""
    snap.has_warning = False
    snap.to_public_dict.return_value = {}

    from track_id.models import disabled_snapshot
    with ExitStack() as stack:
        for p in (
            patch("autostream_webui_page_airplay._config_snapshot", return_value=parsed),
            patch("autostream_webui_page_airplay.get_appliance_id", return_value="0" * 20),
            patch("autostream_webui_page_airplay.get_all_appliances", return_value=[]),
            patch("autostream_webui_page_airplay.get_system_hostname", return_value="autostream"),
            patch("autostream_webui_page_airplay.get_monitor_levels_dbfs", return_value=[]),
            patch("autostream_webui_page_airplay.get_playback_snapshot", return_value=snap),
            patch("autostream_webui_page_airplay.list_outputs",
                  return_value=MagicMock(ok=False, outputs=[])),
            patch("autostream_webui_page_airplay.get_setting",
                  return_value=MagicMock(ok=True, value="2250")),
            patch("autostream_core.get_active_track_identification_snapshot",
                  return_value=disabled_snapshot()),
            patch("autostream_webui_page_airplay.build_top_banner_html", return_value=("", "")),
        ):
            stack.enter_context(p)
        send_airplay_page(handler, state, auth)
    return b"".join(chunks).decode("utf-8", errors="replace")


class TestHomePage:
    def test_banner_visible_and_links_to_dial_card(self):
        with _sightings(_sighting("a", "")):
            page = _render_home()
        assert _BANNER_OPEN + "block;" in page
        assert f"{_BANNER}</a>" in page

    def test_banner_hidden_when_all_current(self):
        with _sightings(_sighting("a", "v3")):
            page = _render_home()
        assert _BANNER_OPEN + "none;" in page
        assert f"{_BANNER}</a>" not in page

    def test_banner_hidden_when_none_sighted(self):
        with _sightings():
            page = _render_home()
        assert _BANNER_OPEN + "none;" in page
        assert f"{_BANNER}</a>" not in page

    def test_poll_script_refreshes_the_banner(self):
        with _sightings():
            page = _render_home()
        assert "'dial_update'" in page
        assert "item.replace('_', '-') + '-warning-banner'" in page


# ---------------------------------------------------------------------------
# Setup page dial card
# ---------------------------------------------------------------------------

class TestDialCardFlag:
    def test_flag_and_update_button_for_protocol_update(self):
        html = setup._dial_card_html(
            uuid="u1", authorized=True, online=True, needs_update_protocol=True)
        assert "dial-badge-update" in html
        assert ">Needs update<" in html
        assert 'data-dial-action="update"' in html

    def test_no_flag_without_protocol_update(self):
        html = setup._dial_card_html(
            uuid="u1", authorized=True, online=True, needs_update_protocol=False)
        assert "dial-badge-update" not in html
        assert "Needs update" not in html
        assert 'data-dial-action="update"' not in html

    def test_no_flag_for_offline_dial(self):
        html = setup._dial_card_html(
            uuid="u1", authorized=True, online=False, needs_update_protocol=True)
        assert "dial-badge-update" not in html
        assert 'data-dial-action="update"' not in html

    def test_version_update_alone_has_button_but_no_flag(self):
        html = setup._dial_card_html(
            uuid="u1", authorized=True, online=True, needs_update=True)
        assert 'data-dial-action="update"' in html
        assert "dial-badge-update" not in html


class _Entry:
    def __init__(self, uuid):
        self.uuid = uuid
        self.name = uuid
        self.current_name = uuid
        self.last_seen = ""


def _cards(sightings, entries):
    with patch("autostream_webui_page_setup._get_dial_sightings", return_value=sightings), \
         patch("autostream_webui_page_setup.parse_dial_entries", return_value=entries), \
         patch("autostream_webui_page_setup.get_app_version", return_value="1.0.0"):
        return setup._setup_dial_cards_html()


class TestDialCardsHtml:
    def test_only_legacy_dial_is_flagged(self):
        legacy = _sighting("legacy", "", version="1.0.0")
        modern = _sighting("modern", "v3", version="1.0.0")
        cards_html, summary, _ = _cards([legacy, modern], [_Entry("legacy"), _Entry("modern")])
        cards = cards_html.split('<div class="dial-card"')
        legacy_card = next(c for c in cards if 'data-dial-uuid="legacy"' in c)
        modern_card = next(c for c in cards if 'data-dial-uuid="modern"' in c)
        assert "dial-badge-update" in legacy_card
        assert 'data-dial-action="update"' in legacy_card
        assert "dial-badge-update" not in modern_card
        assert cards_html.count("dial-badge-update") == 1
        assert summary.endswith("1 need update")

    def test_unauthorised_legacy_dial_is_flagged(self):
        cards_html, summary, _ = _cards([_sighting("new", "")], [])
        assert cards_html.count("dial-badge-update") == 1
        assert "1 need update" in summary

    def test_authorised_dial_not_sighted_is_not_flagged(self):
        cards_html, summary, _ = _cards([], [_Entry("gone")])
        assert "dial-badge-update" not in cards_html
        assert "need update" not in summary

    def test_summary_has_no_suffix_when_all_current(self):
        _, summary, _ = _cards([_sighting("a", "v3")], [_Entry("a")])
        assert "need update" not in summary


class TestDeepLink:
    def _src(self) -> str:
        return (REPO_ROOT / "core" / "autostream_webui_page_setup.py").read_text(encoding="utf-8")

    def test_setup_page_script_opens_dials_panel_for_hash(self):
        src = self._src()
        assert "location.hash === '#dials'" in src
        assert "openPanel('dials')" in src

    def test_dials_panel_target_exists(self):
        assert '_register_card("dials"' in self._src()
