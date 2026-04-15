#!/usr/bin/env python3
"""autostream_webui_page_license.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

Page renderer for the /license route.

Dedicated renderer for the License page.
"""

from __future__ import annotations

import html
import re
import textwrap

from autostream_webui_assets import (
    STYLE_CSS,
    BANNER_HTML,
    VIEWPORT_META,
)
from autostream_webui_pages import build_top_banner_html
from autostream_webui_state import WebUIState


_URL_RE = re.compile(r'(https?://[^\s<>"]+)')


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


def _render_license_md(text: str) -> str:
    """Convert the limited Markdown used in the LICENSE file to HTML.

    Handles: # H1 (rendered as h2), ### H3, --- hr, * list items,
    bare URLs, and plain paragraphs.
    """
    def _autolink(s: str) -> str:
        return _URL_RE.sub(
            lambda m: f'<a href="{m.group(1)}" target="_blank" rel="noopener noreferrer">{m.group(1)}</a>', s
        )

    lines = text.splitlines()
    out: list[str] = []
    in_ul = False
    pending: list[str] = []

    def flush_para() -> None:
        nonlocal pending
        if pending:
            out.append(f"<p>{_autolink(' '.join(pending))}</p>")
            pending = []

    def close_ul() -> None:
        nonlocal in_ul
        if in_ul:
            out.append("</ul>")
            in_ul = False

    for line in lines:
        if line.startswith("# "):
            close_ul(); flush_para()
            out.append(f"<h2>{html.escape(line[2:].strip())}</h2>")
        elif line.startswith("### "):
            close_ul(); flush_para()
            out.append(f"<h3>{html.escape(line[4:].strip())}</h3>")
        elif line.strip() == "---":
            close_ul(); flush_para()
            out.append("<hr>")
        elif line.startswith("* "):
            flush_para()
            if not in_ul:
                out.append("<ul>")
                in_ul = True
            out.append(f"<li>{html.escape(line[2:].strip())}</li>")
        elif not line.strip():
            close_ul(); flush_para()
        else:
            close_ul()
            pending.append(html.escape(line.strip()))

    close_ul()
    flush_para()
    return "\n".join(out)


def send_license_page(handler, state: WebUIState) -> None:
    _ = state
    lic_html, lic_spacer = build_top_banner_html()
    license_text = _load_license_text()

    if license_text:
        license_block = f"""
          <fieldset><legend>License</legend>
            <div class="licence-pane">{_render_license_md(license_text)}</div>
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
      .licence-pane p {{ margin: 0.1rem 0 0.3rem; }}
      .licence-pane h2, .licence-pane h3 {{ margin: 0.5rem 0 0.15rem; }}
      .licence-pane ul {{ margin: 0.1rem 0 0.3rem; padding-left: 1.4rem; }}
      .licence-pane hr {{ margin: 0.5rem 0; border: 0; border-top: 1px solid currentColor; opacity: 0.2; }}
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
