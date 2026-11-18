"""tests/_setup_card_test_helpers.py

Shared helpers for tests that render the Setup page.

send_setup_page()'s response is summary-rows-plus-empty-panels shaped --
detail-panel bodies (input
fields, sliders, card-specific controls) are no longer inlined into the
initial /setup response; they're fetched lazily per card via
`GET /api/setup/card/<key>` (`handle_setup_card_get()`). Tests written
before that change assert markup presence against the full page render
directly; `render_full_setup_with_cards` reproduces "every card has been
opened once" by concatenating every card's lazy detail HTML onto the base
page, so those assertions keep working against the same combined content a
real browser session would eventually hold in the DOM.

`setup_page_mocks` applies the mocks every Setup render needs (the host's
name, the access-point name, the app version, the dial lists, the banner),
from one table of the module each name lives in.
"""
from __future__ import annotations

import io
import json
from contextlib import ExitStack, contextmanager
from unittest.mock import MagicMock, patch

import _source_text

# Each name the Setup page reads from outside, and the module it is looked up
# in at render time.
_SETUP_MOCK_HOMES = {
    "get_system_hostname": "autostream_webui_page_setup",
    "get_ap_ssid": "autostream_webui_page_setup",
    "get_app_version": "autostream_webui_page_setup",
    "_get_dial_sightings": "autostream_webui_page_setup",
    "parse_dial_entries": "autostream_webui_page_setup",
    "build_top_banner_html": "autostream_webui_page_setup",
    "is_high_performance_pi": "autostream_webui_page_setup",
    "_bluetooth_installed": "autostream_webui_page_setup",
    "_bluetooth_services_enabled": "autostream_webui_page_setup",
    "_bluetooth_onboard_enabled": "autostream_webui_page_setup",
    "_config_snapshot": "autostream_webui_page_setup",
}

# What a render sees unless a test says otherwise. The names left out are not
# mocked at all: the page reads the real function.
_SETUP_MOCK_DEFAULTS = {
    "get_system_hostname": "autostream",
    "get_ap_ssid": "autostream_AP",
    "get_app_version": "1.0.0",
    "_get_dial_sightings": [],
    "parse_dial_entries": [],
    "build_top_banner_html": ("", ""),
}


@contextmanager
def setup_page_mocks(**overrides):
    """Apply the Setup page's mocks for the length of the ``with`` block.

    Each keyword is the name of something the page reads, and its value is what
    the mock returns; a ``MagicMock`` is used as given. A keyword replaces the
    default of the same name or adds a mock the defaults leave out."""
    values = {**_SETUP_MOCK_DEFAULTS, **overrides}
    unknown = sorted(set(values) - set(_SETUP_MOCK_HOMES))
    if unknown:
        raise TypeError(f"setup_page_mocks does not know {unknown}")
    by_module: dict[str, dict] = {}
    for name, value in values.items():
        mock = value if isinstance(value, MagicMock) else MagicMock(return_value=value)
        by_module.setdefault(_SETUP_MOCK_HOMES[name], {})[name] = mock
    with ExitStack() as stack:
        for module, mocks in by_module.items():
            stack.enter_context(patch.multiple(module, **mocks))
        yield


def render_full_setup_with_cards(handler, state, auth, **kwargs) -> str:
    """Render /setup, then fetch every registered card's lazy detail body
    and splice it into that card's empty
    `<div class="setup-detail-panel-body" id="panel-body-<key>"></div>`
    placeholder -- exactly what a browser ends up holding in the DOM once
    every panel has been opened once. The result is followed by the text of
    every file the page links, so an assert on a script or a style finds it
    whether it is inline or in a file. ``handler`` must already have
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
    return _source_text.page_with_static(html)
