#!/usr/bin/env python3
"""autostream_webui_license.py

Dedicated renderer for the License page.
"""

from __future__ import annotations

import html
import textwrap

from autostream_webui_assets import (
    STYLE_CSS,
    BANNER_HTML,
    VIEWPORT_META,
)
from autostream_webui_pages import build_top_banner_html
from autostream_webui_state import WebUIState


def _load_license_text() -> str:
    for fname in ("LICENCE", "LICENSE"):
        try:
            with open(fname, "r", encoding="utf-8") as f:
                text = f.read().strip()
            if text:
                return text
        except FileNotFoundError:
            continue
        except Exception:
            continue
    return ""


def send_license_page(handler, state: WebUIState) -> None:
    _ = state
    lic_html, lic_spacer = build_top_banner_html()
    license_text = _load_license_text()

    if license_text:
        license_block = f"""
          <fieldset><legend>License</legend>
            <div class="licence-pane"><pre class="licence-text">{html.escape(license_text)}</pre></div>
          </fieldset>
        """
    else:
        license_block = """
          <fieldset><legend>License</legend>
            <p>License text is unavailable.</p>
          </fieldset>
        """

    html_body = textwrap.dedent(f"""\
      <!DOCTYPE html><html><head><meta charset="utf-8">{VIEWPORT_META}
      <title>License</title><style>{STYLE_CSS}
      .licence-pane {{ background: transparent !important; color: inherit !important; max-height: none !important; overflow: visible !important; }}
      .licence-pane .licence-text {{ margin: 0; padding: 0; background: transparent; color: inherit; border: 0; white-space: pre-wrap; overflow-wrap: anywhere; font: inherit; }}
      </style></head><body>{lic_html}{lic_spacer}<div class='container'>{BANNER_HTML}<h1>License</h1>
      <p class="actions" style="margin:1rem 0;"><a href="/about" class="pill-btn">← Back</a></p>
      {license_block}
      </div></body></html>
    """)
    body_bytes = html_body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)
