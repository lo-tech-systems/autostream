"""tests/_setup_card_test_helpers.py

Shared helper for tests that assert on Setup page detail-panel markup.

send_setup_page()'s response is summary-rows-plus-empty-panels shaped --
detail-panel bodies (input
fields, sliders, card-specific controls) are no longer inlined into the
initial /setup response; they're fetched lazily per card via
`GET /api/setup/card/<key>` (`handle_setup_card_get()`). Tests written
before that change assert markup presence against the full page render
directly; this helper reproduces "every card has been opened once" by
concatenating every card's lazy detail HTML onto the base page, so those
assertions keep working against the same combined content a real browser
session would eventually hold in the DOM.
"""
from __future__ import annotations

import io
import json
from unittest.mock import MagicMock


def render_full_setup_with_cards(handler, state, auth, **kwargs) -> str:
    """Render /setup, then fetch every registered card's lazy detail body
    and splice it into that card's empty
    `<div class="setup-detail-panel-body" id="panel-body-<key>"></div>`
    placeholder -- exactly what a browser ends up holding in the DOM once
    every panel has been opened once. ``handler`` must already have
    ``wfile`` set to an ``io.BytesIO()`` -- this function reads it after
    calling ``send_setup_page()``."""
    from autostream_webui_page_setup import CARDS, handle_setup_card_get, send_setup_page

    send_setup_page(handler, state, auth, **kwargs)
    html = handler.wfile.getvalue().decode("utf-8", errors="replace")

    for card in CARDS:
        detail_handler = MagicMock()
        detail_handler.wfile = io.BytesIO()
        handle_setup_card_get(detail_handler, state, auth, card.key)
        body_raw = detail_handler.wfile.getvalue().decode("utf-8", errors="replace")
        try:
            body = json.loads(body_raw)
        except ValueError:
            continue
        if not (body.get("ok") and isinstance(body.get("html"), str)):
            continue
        placeholder = f'<div class="setup-detail-panel-body" id="panel-body-{card.key}"></div>'
        if placeholder in html:
            html = html.replace(placeholder, body["html"], 1)
    return html
