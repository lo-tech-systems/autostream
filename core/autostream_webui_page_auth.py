#!/usr/bin/env python3
"""autostream_webui_page_auth.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

Page renderer for the /auth sign-in route.

The security logic (nonces, proofs, sessions, rate limiting) stays in
autostream_auth.AuthManager; this module only draws the page. The page asks for
the device PIN and proves it to /api/auth/verify with a hash of the nonce and
the PIN, so the PIN itself is not sent in plaintext (the script is
nginx/static/page/auth.js).
"""

from __future__ import annotations

import urllib.parse

import autostream_auth
import autostream_webui_static as static
from autostream_webui_assets import LICENSE_BANNER_CSS, logo_banner_html
from autostream_webui_common import _config_snapshot, build_nav_bar_html, send_html

_TITLE = "autostream"


def _dark_mode(state) -> bool:
    try:
        return bool(_config_snapshot(state).webui.dark_mode)
    except Exception:
        return False


def render_auth_page(next_path: str, nonce: str, error: bool, dark_mode: bool = False) -> str:
    """The sign-in page. *error* shows the red "Incorrect PIN" banner."""
    err_banner = ""
    if error:
        err_banner = (
            "<div id='red-banner'>Incorrect PIN</div>"
            "<div id='red-banner-spacer'></div>"
        )

    # The shared theme link, plus the page-specific banner rules inline when
    # there are any.
    style_link = static.style_tag("theme.css")
    if LICENSE_BANNER_CSS.strip():
        style_link += f"<style>{LICENSE_BANNER_CSS}</style>"
    nav_html = build_nav_bar_html("setup")

    theme_attr = ' data-theme="dark"' if dark_mode else ' data-theme="light"'
    body_cls = ' class="has-bottom-nav"' if nav_html else ""
    return f"""
            <!doctype html>
            <html lang=\"en\"{theme_attr}>
            <head>
            <meta charset=\"utf-8\" />
            <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
            <title>{_TITLE} &bull; Authentication</title>
            {style_link}
            </head>
            <body{body_cls}>
            <div class=\"container\">
                {err_banner}
                {logo_banner_html()}
                <p>Enter the device PIN to access Setup.</p>

                <div class=\"card\">
                <form id=\"auth-form\" autocomplete=\"off\">
                    <label for=\"pin\">PIN</label>
                    <input id=\"pin\" name=\"pin\" type=\"password\" inputmode=\"text\" autocapitalize=\"off\" autocomplete=\"off\" spellcheck=\"false\" required />
                    <div style=\"height: 10px\"></div>
                    <button class=\"btn\" type=\"submit\">Continue</button>
                    <input type=\"hidden\" id=\"next\" value=\"{urllib.parse.quote(next_path, safe='/')}\" />
                    <input type=\"hidden\" id=\"nonce\" value=\"{nonce}\" />
                </form>
                </div>
            </div>
            {nav_html}

            {static.script_tag("page/auth.js")}
            </body>
            </html>
        """


def send_auth_page(handler, state, auth, query: str) -> None:
    """GET /auth: issue a nonce for this client and render the sign-in page."""
    qs = urllib.parse.parse_qs(query or "", keep_blank_values=True)
    next_path = autostream_auth.safe_next_path((qs.get("next") or ["/"])[0])
    err = (qs.get("err") or [""])[0]

    nonce = auth.issue_nonce(handler)

    send_html(handler, 200, render_auth_page(next_path, nonce, bool(err), _dark_mode(state)))
