"""tests/test_output_card_html.py

The server-rendered Home speaker card: the label after the name, the card's
class, and which of its controls are disabled, for a speaker that is
connecting, one that is offline and an ordinary one.
"""
from __future__ import annotations

import sys
from pathlib import Path

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from webui.components import output_card_html


def card(**kw) -> str:
    base = dict(out_id="7", name="Speaker A", selected=True, volume=20, is_default=False)
    base.update(kw)
    return output_card_html(**base)


def label(html_text: str) -> str:
    start = html_text.index('id="output_label_7"')
    return html_text[html_text.rindex("<span", 0, start):html_text.index("</span>", start) + 7]


def test_an_ordinary_card_has_an_empty_hidden_label():
    html_text = card()
    assert label(html_text) == '<span class="output-card-state-label" id="output_label_7" hidden></span>'
    assert "output-card-connecting" not in html_text and "output-card-offline" not in html_text
    assert "disabled" not in html_text


def test_a_connecting_card_says_so_and_keeps_its_switch_usable():
    html_text = card(connecting=True)
    assert label(html_text) == '<span class="output-card-state-label" id="output_label_7"> (Connecting)</span>'
    assert "output-card-on output-card-connecting" in html_text
    assert " checked" in html_text and "disabled" not in html_text


def test_an_offline_card_in_a_session_has_a_working_switch_and_a_fixed_slider():
    html_text = card(offline=True)
    assert label(html_text) == '<span class="output-card-state-label" id="output_label_7"> (offline)</span>'
    assert "output-card-offline" in html_text
    assert 'id="output_enabled_7" checked onchange' in html_text
    assert 'value="20" disabled' in html_text


def test_an_offline_card_outside_a_session_has_its_switch_off_and_disabled():
    html_text = card(offline=True, selected=False, disabled=True)
    assert 'id="output_enabled_7" disabled onchange' in html_text
    assert " checked" not in html_text.split("output_slider_wrap")[0].split('type="checkbox"')[1]


def test_a_speaker_in_use_by_another_appliance_ignores_the_new_states():
    html_text = card(remote_in_use=True, remote_owner="Hall", connecting=True)
    assert "output-card-connecting" not in html_text and "output-card-in-use" in html_text
