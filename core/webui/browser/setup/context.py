#!/usr/bin/env python3
"""webui/browser/setup/context.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The Setup page's card registry and shared pieces: the per-request context, the card
record and its list, the list rows and panel shells, and the page headers.
"""

from __future__ import annotations

import html
import logging
from dataclasses import dataclass
from typing import Callable, Optional

from autostream_sysutils import get_system_hostname, sdcard_health_state
from webui.session_state import WebUIState
from webui import common


# -----------------------------------------------------------------------------
# Setup card registry.
#
# ``SetupCtx`` bundles the per-request state every card's summary/detail
# renderer needs -- the same values ``send_setup_page()`` used to compute
# as inline locals before this split. It is built once by
# ``_setup_build_ctx()``: ``send_setup_page()`` uses it to render every
# card's *summary* row (cheap: no detail-panel HTML is built), and the
# lazy per-card fetch route (``handle_setup_card_get()``) uses a freshly
# built one to render a single card's *detail* panel HTML on demand.
#
# The initial /setup response does not inline all nine detail panels
# (only their collapsed summary rows + an empty per-panel body
# placeholder); opening a card fetches `GET /api/setup/card/<key>` the
# first time, caching the result client-side thereafter. Every card's
# field-level auto-save endpoints are unchanged -- only how the detail
# markup itself reaches the browser changes.
# -----------------------------------------------------------------------------


@dataclass
class SetupCtx:
    """Shared, per-request context for the Setup page's card registry."""

    handler: object
    state: WebUIState
    auth: object
    parsed: object
    monitor_devices: list
    bt_enabled: bool
    bt_status: Optional[dict]
    bt_paired: bool
    bt_services_on: bool
    bt_onboard_on: bool
    bt_buffer_ms: int
    bt_card_summary: str
    bt_paired_row_text: str
    sd_health: dict
    current_hostname: str
    factory_reset: dict
    dial_cards_html: str
    dials_summary: str


def _setup_build_ctx(handler, state: WebUIState, auth) -> SetupCtx:
    """Build the shared per-request context every card renderer reads from.

    May raise (a broken/partial config, per ``_config_snapshot()``'s own
    contract) -- callers are responsible for the "swallow and log, degrade
    gracefully" handling send_setup_page() has always done for this.
    """
    from webui.browser.setup import cards_bluetooth, cards_dials, cards_factory_reset

    parsed = common._config_snapshot(state)
    monitor_devices = state.get_monitor_devices()
    _bt_state = cards_bluetooth._setup_compute_bluetooth_state(state)
    try:
        sd_health = sdcard_health_state()
    except Exception:
        logging.exception("_setup_build_ctx: sdcard_health_state failed")
        sd_health = {
            "tool_present": False,
            "timer_enabled": False,
            "method": "auto",
            "check": "none",
            "serial": "",
            "at": "",
            "reason": "",
            "card": {"manfid": None, "oemid": None, "name": "", "serial": "", "likely_supported": False},
            "health_percent": None,
            "last_sampled_at": None,
        }
    current_hostname = get_system_hostname()
    factory_reset = cards_factory_reset._setup_factory_reset_html(auth)
    dial_cards_html, dials_summary = cards_dials._setup_dial_cards_html()
    return SetupCtx(
        handler=handler,
        state=state,
        auth=auth,
        parsed=parsed,
        monitor_devices=monitor_devices,
        bt_enabled=_bt_state["bt_enabled"],
        bt_status=_bt_state["bt_status"],
        bt_paired=_bt_state["bt_paired"],
        bt_services_on=_bt_state["bt_services_on"],
        bt_onboard_on=_bt_state["bt_onboard_on"],
        bt_buffer_ms=_bt_state["bt_buffer_ms"],
        bt_card_summary=_bt_state["bt_card_summary"],
        bt_paired_row_text=_bt_state["bt_paired_row_text"],
        sd_health=sd_health,
        current_hostname=current_hostname,
        factory_reset=factory_reset,
        dial_cards_html=dial_cards_html,
        dials_summary=dials_summary,
    )


@dataclass(frozen=True)
class Card:
    """One row of the Setup page's card registry.

    ``render_summary``/``render_detail`` both take a ``SetupCtx`` and
    return HTML fragments: the collapsed list-row's sub-text, and the
    detail panel's body (fetched lazily -- see module docstring above)
    respectively. ``detail_header`` is the title passed to
    ``_setup_detail_header()`` for the detail panel's heading; ``None``
    means the card's own detail HTML supplies its own heading (only
    Factory Reset does this today).
    """

    key: str
    title: str
    render_summary: Callable[[SetupCtx], str]
    render_detail: Callable[[SetupCtx], str]
    detail_header: Optional[str] = None


CARDS: list = []


def register_card(
    key: str,
    title: str,
    render_summary: Callable[[SetupCtx], str],
    render_detail: Callable[[SetupCtx], str],
    detail_header: Optional[str] = None,
) -> None:
    CARDS.append(
        Card(
            key=key,
            title=title,
            render_summary=render_summary,
            render_detail=render_detail,
            detail_header=detail_header,
        )
    )


def _setup_list_row_html(card: Card, summary_html: str) -> str:
    return f"""
      <div class="setup-list-card" onclick="openPanel('{card.key}')">
        <div class="setup-list-card-body">
          <span class="setup-list-card-title">{html.escape(card.title)}</span>
          <span class="setup-list-card-sub" id="{card.key}-card-sub">{summary_html}</span>
        </div>
        <span class="setup-list-chevron">&rsaquo;</span>
      </div>"""


def _setup_panel_shell_html(card: Card) -> str:
    header = _setup_detail_header(card.detail_header) if card.detail_header else ""
    return f"""
      <div class="setup-detail-panel" id="panel-{card.key}">
        <div class="setup-detail-back">
          <button type="button" class="pill-btn small" onclick="closePanel()">&larr; Back</button>
        </div>
        {header}
        <div class="setup-detail-panel-body" id="panel-body-{card.key}"></div>
      </div>"""


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _setup_page_header(title: str) -> str:
    return (
        "<div class='eq-page-header'>"
        "<div style='display:flex;align-items:center;gap:0.5rem;'>"
        f"<h1>{html.escape(title)}</h1>"
        "</div>"
        "</div>"
    )


def _setup_detail_header(title: str) -> str:
    return _setup_page_header(title)
