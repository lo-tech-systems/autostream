#!/usr/bin/env python3
"""autostream_webui_components.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Shared HTML widget builders, extracted one at a time from their current
best call site with byte-identical output. Kept dependency-light (stdlib
``html`` only) so any page module or ``autostream_webui_common.py`` can
import from here without risking a circular import.
"""

from __future__ import annotations

import html


def banner_html(banner_id: str, message_html: str) -> tuple[str, str]:
    """Render a top-of-page banner div plus its layout spacer.

    Returns ``(banner_html, spacer_html)`` -- the same pair shape
    ``build_top_banner_html()`` already returns to its callers.
    ``message_html`` is inserted verbatim (callers are responsible for
    escaping it first, matching current behaviour).
    """
    return (
        f"<div id='{banner_id}'>{message_html}</div>",
        f"<div id='{banner_id}-spacer'></div>",
    )


def slider_html(
    *,
    id: str,
    value,
    min_val=0,
    max_val=100,
    step=1,
    disabled: bool = False,
    extra_attrs: str = "",
) -> str:
    """Render a single ``<input type="range">`` element.

    ``extra_attrs`` is inserted verbatim right after the disabled attribute
    (if any) -- callers pass event handlers/etc. through it so this stays a
    thin, unopinionated wrapper around the tag shape rather than a new
    behaviour surface.
    """
    disabled_attr = " disabled" if disabled else ""
    return (
        f'<input type="range" id="{id}" min="{min_val}" max="{max_val}" step="{step}"'
        f' value="{value}"{disabled_attr}{extra_attrs}>'
    )


def toggle_html(
    *,
    name: str,
    id: str,
    checked: bool = False,
    disabled: bool = False,
    onchange: str = "",
    indent: str = "            ",
) -> str:
    """Render a checkbox-driven ``.output-toggle`` switch (label+input+span).

    Matches the markup already used across the Setup/Home/Align pages for a
    single on/off control. ``indent`` reproduces each call site's existing
    leading whitespace exactly, since this widget is inlined into larger
    byte-exact-checked templates (e.g. the Setup page golden test).
    """
    checked_attr = "  checked" if checked else ""
    disabled_attr = " disabled" if disabled else ""
    onchange_attr = f' onchange="{onchange}"' if onchange else ""
    return (
        f'{indent}<label class="output-toggle" style="margin:0;">\n'
        f'{indent}  <input type="checkbox" name="{name}" id="{id}"'
        f'{checked_attr}{disabled_attr}{onchange_attr}>\n'
        f'{indent}  <span class="switch"></span>\n'
        f'{indent}</label>'
    )


def output_card_html(
    *,
    out_id,
    name: str,
    selected: bool,
    volume,
    is_default: bool,
    remote_in_use: bool = False,
    remote_owner: str = "",
) -> str:
    """Render one output card, matching the local Home page's markup exactly.

    DELIBERATE DUAL-RENDER EXCEPTION (remote-shell JS mirroring): this is
    mirrored by the JS function
    ``renderOutputList()``/``buildOutputCardElement()`` in
    ``nginx/static/render_fragments.js`` (source of truth:
    ``RENDER_FRAGMENTS_JS``, core/autostream_webui_assets.py -- served
    statically like poll.js/theme.css, not inlined). Any change to the
    output-card markup/classes/data-* attributes here must be reflected
    there too, or the local and remote Home pages will visibly drift apart.
    """
    safe_name = html.escape(name)
    default_badge = '<span class="output-card-default">Default</span>' if is_default else ""
    if remote_in_use:
        state_text = html.escape(f"In Use by {remote_owner}" if remote_owner else "In Use")
        state_cls = "in-use"
        card_state_cls = "output-card-in-use"
        cb_disabled = " disabled"
    else:
        state_text = "On" if selected else "Off"
        state_cls = "on" if selected else "off"
        card_state_cls = "output-card-on" if selected else "output-card-off"
        cb_disabled = ""
    is_default_attr = "1" if is_default else "0"
    data_remote_in_use = "1" if remote_in_use else "0"
    safe_remote_owner = html.escape(remote_owner)
    return f"""
          <div class="output-card {card_state_cls}" id="output_card_{out_id}" data-output-id="{out_id}" data-is-default="{is_default_attr}" data-remote-in-use="{data_remote_in_use}" data-remote-owner="{safe_remote_owner}">
            <div class="output-card-head">
              <div class="output-card-meta">
                <div class="output-card-name">{safe_name}</div>
                {default_badge}
                <span class="output-state-chip {state_cls}" id="output_state_{out_id}">{state_text}</span>
              </div>
              <label class="output-toggle" onclick="event.stopPropagation();">
                <input type="checkbox" id="output_enabled_{out_id}"{' checked' if selected else ''}{cb_disabled} onchange="onToggleOutput('{out_id}')">
                <span class="switch" aria-hidden="true"></span>
              </label>
            </div>
            <div class="output-slider-wrap" id="output_slider_wrap_{out_id}" onclick="event.stopPropagation();"{' hidden' if not selected else ''}>
              <div class="slider-header"><span>Volume:</span><span id="vol_label_{out_id}" data-volume-label-for="{out_id}"></span></div>
              <input type="range" id="vol_slider_{out_id}" min="0" max="100" step="1" value="{volume}" oninput="updateVolumeLabel('{out_id}', this.value)" onchange="onVolumeChange('{out_id}', this.value)">
            </div>
          </div>
        """
