#!/usr/bin/env python3
"""autostream_webui_page_rebooting.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Renderer for the /rebooting holding page.

Behaviour:
  - On load, POSTs /api/reboot (CSRF protected) to schedule a reboot.
  - Waits a minimum time before attempting to redirect back to '/'.
  - Polls '/' until reachable, then redirects.
"""

from __future__ import annotations

import html

from autostream_webui_assets import STYLE_CSS, VIEWPORT_META
from autostream_webui_common import build_top_banner_html
from autostream_webui_state import WebUIState


def send_rebooting_page(handler, state: WebUIState, auth) -> None:
    """Render the reboot holding page."""
    # Minimum time (ms) before we even attempt to return to '/'.
    # The reboot API schedules with a 3 s delay; shutdown and boot take time on
    # slower hardware.
    min_wait_ms = 90000

    lic_html, lic_spacer = build_top_banner_html(flash_msg=None)
    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""
    csrf_meta = (
        f"<meta name='csrf-token' content='{html.escape(csrf_token)}'>"
        f"<script>window.__CSRF='{html.escape(csrf_token)}';</script>"
    )

    body = f"""<!doctype html>
      <html lang="en">
      <head>
        <meta charset="utf-8">{VIEWPORT_META}
        <title>Rebooting\u2026</title>
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
          <h1>Rebooting\u2026</h1>
          <p class="muted">Your device is restarting. This page will return you to the app automatically when it\u2019s ready.</p>
          <p id="status" class="muted">Requesting reboot\u2026</p>
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
              const r = await fetch("/api/reboot", {{
                method: "POST",
                headers: {{ "X-CSRF-Token": window.__CSRF || "" }},
                cache: "no-store",
                keepalive: true
              }});
              try {{
                const j = await r.json();
                if (j && j.ok) {{
                  setStatus("Reboot scheduled. Waiting for restart\u2026");
                  return;
                }}
              }} catch (e) {{}}
              setStatus("Reboot requested. Waiting for restart\u2026");
            }} catch (e) {{
              setStatus("Waiting for restart\u2026");
            }}
          }}

          async function pollRoot() {{
            const elapsed = Date.now() - startedAt;
            if (elapsed < minWaitMs) {{
              const s = Math.ceil((minWaitMs - elapsed) / 1000);
              setStatus("Reboot scheduled. Restarting in ~" + s + "s\u2026");
              setTimeout(pollRoot, 700);
              return;
            }}

            setStatus("Checking if the app is back\u2026");
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
