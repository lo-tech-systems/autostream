#!/usr/bin/env python3
"""autostream_webui_pages.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Facade module: re-exports all public page handlers and API endpoints so that
autostream_webui.py (and any other caller) can continue to use the same
'import autostream_webui_pages as pages' / 'pages.send_airplay_page(...)' pattern
without change.

Implementation is split across:
  autostream_webui_api           -- send_json, JSON endpoints, run_updater
  autostream_webui_page_airplay  -- send_airplay_page
  autostream_webui_page_setup    -- send_setup_page
  autostream_webui_page_owntone  -- send_owntone_setup_page, owntone restart support
  autostream_webui_post_handlers -- handle_* POST handlers

send_rebooting_page is defined here; it only depends on lower-level modules
(assets, common, state) so it requires no cross-module imports.
"""

from __future__ import annotations

import html

from autostream_webui_assets import STYLE_CSS, VIEWPORT_META
from autostream_webui_common import build_top_banner_html
from autostream_webui_state import WebUIState

from autostream_webui_api import (
    send_json,
    send_owntone_outputs_json,
    send_owntone_outputs_state_json,
    send_status_json,
    send_update_check_json,
    send_update_status_json,
)

from autostream_webui_page_airplay import send_airplay_page

from autostream_webui_page_setup import send_setup_page

from autostream_webui_page_owntone import (
    send_owntone_ready_json,
    send_owntone_restarting_page,
    send_owntone_setup_page,
    start_owntone_restart_async,
)

from autostream_webui_post_handlers import (
    handle_factory_reset_post,
    handle_live_input_eq_update,
    handle_live_input_gain_update,
    handle_output_update,
    handle_owntone_setup_post,
    handle_setup_post,
)


def send_rebooting_page(handler, state: WebUIState, auth) -> None:
    """
    "Holding" page shown while a reboot is initiated.

    Behaviour:
      - On load, POSTs /api/reboot (CSRF protected) to schedule a reboot with delay.
      - Waits a minimum time before trying to return to '/', to avoid bouncing
        back to the UI before the reboot has actually started.
      - Then polls '/' until reachable and redirects back.
    """
    # Minimum time (ms) before we even attempt to return to '/'. Must be > reboot delay.
    # The reboot API schedules with 3s delay; but shutdown takes time especially on older Pi.
    # Hence wait 30s before attempting to redirect user.
    min_wait_ms = 30000

    lic_html, lic_spacer = build_top_banner_html(flash_msg=None)
    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""
    csrf_meta = (
        f"<meta name='csrf-token' content='{html.escape(csrf_token)}'>"
        f"<script>window.__CSRF='{html.escape(csrf_token)}';</script>"
    )

    body = f"""<!doctype html>
      <html>
      <head>
        <meta charset="utf-8">{VIEWPORT_META}
        <title>Rebooting…</title>
        <style>
          {STYLE_CSS}
          body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }}
          .box {{ max-width: 42rem; margin: 2rem auto; padding: 1.25rem; border: 1px solid #ddd; border-radius: 12px; background:#fff; }}
          .muted {{ color: #666; }}
          .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }}
        </style>
        {csrf_meta}
      </head>
      <body>{lic_html}{lic_spacer}
        <div class="box">
          <h1>Rebooting…</h1>
          <p class="muted">Your device is restarting. This page will return you to the app automatically when it's ready.</p>
          <p id="status" class="muted">Requesting reboot…</p>
          <p class="muted">If you are not redirected, try <a href="/">opening the app</a> again in a moment.</p>
        </div>

        <script>
          const minWaitMs = {int(min_wait_ms)};
          const startedAt = Date.now();
          const statusEl = document.getElementById("status");

          function setStatus(t) {{
            if (statusEl) statusEl.textContent = t;
          }}

          async function requestReboot() {{
            try {{
              // keepalive improves odds the POST is delivered even if the browser navigates/reloads
              const r = await fetch("/api/reboot", {{
                method: "POST",
                headers: {{ "X-CSRF-Token": window.__CSRF || "" }},
                cache: "no-store",
                keepalive: true
              }});
              // Even if we can't parse JSON, the request may have been accepted.
              try {{
                const j = await r.json();
                if (j && j.ok) {{
                  setStatus("Reboot scheduled. Waiting for restart…");
                  return;
                }}
              }} catch (e) {{}}
              setStatus("Reboot requested. Waiting for restart…");
            }} catch (e) {{
              // If the reboot is already in progress, fetch may fail — that's fine.
              setStatus("Waiting for restart…");
            }}
          }}

          async function pollRoot() {{
            const elapsed = Date.now() - startedAt;
            if (elapsed < minWaitMs) {{
              const s = Math.ceil((minWaitMs - elapsed) / 1000);
              setStatus("Reboot scheduled. Restarting in ~" + s + "s…");
              setTimeout(pollRoot, 700);
              return;
            }}

            setStatus("Checking if the app is back…");
            try {{
              const r = await fetch("/", {{ cache: "no-store" }});
              if (r && r.ok) {{
                window.location.replace("/");
                return;
              }}
            }} catch (e) {{
              // Not up yet
            }}
            setTimeout(pollRoot, 1200);
          }}

          requestReboot();
          pollRoot();
        </script>
      </body>
      </html>
    """
    body_bytes = body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)


__all__ = [
    "handle_factory_reset_post",
    "handle_live_input_eq_update",
    "handle_live_input_gain_update",
    "handle_output_update",
    "handle_owntone_setup_post",
    "handle_setup_post",
    "send_airplay_page",
    "send_json",
    "send_owntone_outputs_json",
    "send_owntone_outputs_state_json",
    "send_owntone_ready_json",
    "send_owntone_restarting_page",
    "send_owntone_setup_page",
    "send_rebooting_page",
    "send_setup_page",
    "send_status_json",
    "send_update_check_json",
    "send_update_status_json",
    "start_owntone_restart_async",
]
