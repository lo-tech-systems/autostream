#!/usr/bin/env python3
"""webui/components.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Shared HTML widget builders, extracted one at a time from their current
best call site with byte-identical output. Kept dependency-light (stdlib
``html`` only) so any page module or ``webui/common.py`` can
import from here without risking a circular import.
"""

from __future__ import annotations



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
