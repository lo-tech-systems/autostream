"""Home page "Dial updates required" banner and the Setup page dial card flag.

A dial that is currently sighted but advertises an older protocol number than the
appliance does works in an older dialect; the Home banner invites the owner to
update it and links to the Setup page's dial card, where each such dial is
flagged "Needs update" beside its Update firmware button.  Only dials sighted
now count.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import _source_text

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_dials as dials
import webui.browser.setup.cards_dials as cards_dials

_BANNER_OPEN = "<a id='dial-update-warning-banner' href='/setup#dials' style='display:"


def _sighting(uuid="u1", proto=None, version="1.0.0") -> dials.DialSighting:
    return dials.DialSighting(
        uuid=uuid, name="Dial", version=version, ip="192.0.2.9", port=7842,
        pin_recovery=False, proto=proto,
    )


def _sightings(*items):
    return patch("autostream_dials.get_all_sightings", return_value=list(items))


# ---------------------------------------------------------------------------
# Home page HTML
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Setup page dial card
# ---------------------------------------------------------------------------

class TestDialCardFlag:
    def test_flag_and_update_button_for_protocol_update(self):
        html = cards_dials._dial_card_html(
            uuid="u1", authorized=True, online=True, needs_update_protocol=True)
        assert "dial-badge-update" in html
        assert ">Needs update<" in html
        assert 'data-dial-action="update"' in html

    def test_no_flag_without_protocol_update(self):
        html = cards_dials._dial_card_html(
            uuid="u1", authorized=True, online=True, needs_update_protocol=False)
        assert "dial-badge-update" not in html
        assert "Needs update" not in html
        assert 'data-dial-action="update"' not in html

    def test_no_flag_for_offline_dial(self):
        html = cards_dials._dial_card_html(
            uuid="u1", authorized=True, online=False, needs_update_protocol=True)
        assert "dial-badge-update" not in html
        assert 'data-dial-action="update"' not in html

    def test_version_update_alone_has_button_but_no_flag(self):
        html = cards_dials._dial_card_html(
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
    with patch("webui.browser.setup.cards_dials._get_dial_sightings", return_value=sightings), \
         patch("webui.browser.setup.cards_dials.parse_dial_entries", return_value=entries), \
         patch("webui.system.updates.get_app_version", return_value="1.0.0"):
        return cards_dials._setup_dial_cards_html()


class TestDialCardsHtml:
    def test_only_legacy_dial_is_flagged(self):
        legacy = _sighting("legacy", None, version="1.0.0")
        modern = _sighting("modern", 4, version="1.0.0")
        cards_html, summary = _cards([legacy, modern], [_Entry("legacy"), _Entry("modern")])
        cards = cards_html.split('<div class="dial-card"')
        legacy_card = next(c for c in cards if 'data-dial-uuid="legacy"' in c)
        modern_card = next(c for c in cards if 'data-dial-uuid="modern"' in c)
        assert "dial-badge-update" in legacy_card
        assert 'data-dial-action="update"' in legacy_card
        assert "dial-badge-update" not in modern_card
        assert cards_html.count("dial-badge-update") == 1
        assert summary.endswith("1 need update")

    def test_unauthorised_legacy_dial_is_flagged(self):
        cards_html, summary = _cards([_sighting("new", None)], [])
        assert cards_html.count("dial-badge-update") == 1
        assert "1 need update" in summary

    def test_authorised_dial_not_sighted_is_not_flagged(self):
        cards_html, summary = _cards([], [_Entry("gone")])
        assert "dial-badge-update" not in cards_html
        assert "need update" not in summary

    def test_summary_has_no_suffix_when_all_current(self):
        _, summary = _cards([_sighting("a", 4)], [_Entry("a")])
        assert "need update" not in summary


class TestDeepLink:
    def _src(self) -> str:
        return _source_text.page_source("setup")

    def test_setup_page_script_opens_dials_panel_for_hash(self):
        src = self._src()
        assert "location.hash === '#dials'" in src
        assert "openPanel('dials')" in src

    def test_dials_panel_target_exists(self):
        assert 'register_card("dials"' in self._src()
