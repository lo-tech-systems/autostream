#!/usr/bin/env python3
"""webui/browser/rebooting.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Renderer for the /rebooting holding page.

Behaviour:
  - On load, POSTs /api/reboot (CSRF protected) to schedule a reboot.
  - Waits a minimum time before attempting to redirect back to '/'.
  - Polls '/' until reachable, then redirects.
"""

from __future__ import annotations

import html

from webui import static
from webui.assets import VIEWPORT_META
from webui.common import build_top_banner_html
from webui.session_state import WebUIState
from webui import common
from webui import session_state


def send_rebooting_page(handler, state: WebUIState, auth) -> None:
    """Render the reboot holding page."""
    # This page deliberately does not go through build_page_html():
    # it doesn't want the nav-bar/shell machinery -- there's nowhere
    # useful to navigate to while the appliance is rebooting -- so it builds its
    # own minimal document instead. It still links the shared theme.css just like
    # every other page. nginx serves /static/ directly, independent of the app, so
    # the stylesheet and the page script (nginx/static/page/rebooting.js) load
    # fine even this close to shutdown: both are fetched with the page itself,
    # before the reboot is requested.
    #
    # Minimum time (ms) before we even attempt to return to '/'. It reaches the
    # page script through the data island.
    # The reboot API schedules with a 3 s delay; shutdown and boot take time on
    # slower hardware.
    min_wait_ms = 90000

    lic_html, lic_spacer = build_top_banner_html(flash_msg=None)
    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""
    csrf_meta = (
        f"<meta name='csrf-token' content='{html.escape(csrf_token)}'>"
        f"<script>window.__CSRF='{html.escape(csrf_token)}';</script>"
    )

    style_link = static.style_tag("theme.css")

    body = f"""<!doctype html>
      <html lang="en">
      <head>
        <meta charset="utf-8">{VIEWPORT_META}
        <title>Rebooting&hellip;</title>
        {style_link}
        {static.style_tag("page/rebooting.css")}
        {csrf_meta}
        {static.page_data_island({"min_wait_ms": int(min_wait_ms)})}
      </head>
      <body>{lic_html}{lic_spacer}
        <div class="box">
          <h1>Rebooting&hellip;</h1>
          <p class="muted">Your device is restarting. This page will return you to the app automatically when it&rsquo;s ready.</p>
          <p id="status" class="muted">Requesting reboot&hellip;</p>
          <p class="muted">If you are not redirected, try <a href="/">opening the app</a> again in a moment.</p>
        </div>

        {static.script_tag("page/rebooting.js")}
      </body>
      </html>
    """
    common.send_html(handler, 200, body)


# -----------------------------------------------------------------------------
# Route-table adapters: the calling convention the dispatcher uses (handler,
# state[, body]) in front of the senders above.
# -----------------------------------------------------------------------------


def _route_get_rebooting(handler, state):
    send_rebooting_page(handler, state, session_state.AUTH)
