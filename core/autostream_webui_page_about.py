#!/usr/bin/env python3
"""autostream_webui_page_about.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Page renderer for the /about route.

Responsibilities:
  - Render the About page: product overview, per-input stylus life bars,
    system information (build version, total playback hours, CPU temperature,
    disk usage, SD card health), and copyright notice.

Helpers kept in this module:
  - _stylus_box_html  -- render a single stylus-life fieldset card

Shared helpers (imported from autostream_webui_common):
  - get_app_version           -- read installed application version
  - _fallback_input_snapshot  -- build a zero-valued snapshot from config when
                                 the monitor has no live data for an input
  - _format_reset_date        -- format a stylus-reset ISO timestamp as a
                                 compact "Mon-YY" label
"""

from __future__ import annotations

import html
import textwrap

from autostream_config import parse_config
from autostream_core import get_playback_snapshot
from autostream_playback_stats import InputPlaybackSnapshot
from autostream_rpi import get_cpu_temperature_c
from autostream_sysutils import fmt_bytes, get_root_disk_usage, get_sdcard_health_percent

from autostream_webui_assets import (
    BANNER_HTML,
    STYLE_CSS,
    VIEWPORT_META,
)

from autostream_webui_common import (
    _fallback_input_snapshot,
    _format_reset_date,
    build_top_banner_html,
    get_app_version,
    locked_load_config,
)

from autostream_webui_state import WebUIState


# -----------------------------------------------------------------------------
# Stylus life bar card
# -----------------------------------------------------------------------------

def _stylus_box_html(
    *,
    title: str,
    snapshot: InputPlaybackSnapshot,
) -> str:
    """Render a fieldset card showing stylus life remaining as a coloured bar.

    Colour thresholds: red ≤10 %, amber ≤20 %, green otherwise.
    The bar width is clamped to [0, 100] so an overdue stylus (negative
    remaining) renders as a full red bar rather than a broken layout.
    """
    life_total_seconds = max(1, int(snapshot.stylus_life_hours) * 3600)
    remaining_seconds = max(0, int(snapshot.stylus_remaining_seconds or 0))
    remaining_hours = max(0.0, remaining_seconds / 3600.0)
    remaining_pct = max(0.0, min(100.0, (remaining_seconds / life_total_seconds) * 100.0))
    bar_color = (
        "#dc3545" if remaining_pct <= 10.0
        else ("#f0ad4e" if remaining_pct <= 20.0
              else "#28a745")
    )
    meta_text = f"{remaining_hours:.1f} hours remaining"
    return f"""
      <fieldset><legend>{html.escape(title)}</legend>
        <div class='bar-label'><strong>Life Remaining:</strong> {remaining_pct:.1f}%</div>
        <div class='storage-bar'><div class='used' style='width:{remaining_pct}%;background:{bar_color};'></div></div>
        <div class='storage-meta'>{html.escape(meta_text)}</div>
      </fieldset>
    """


# -----------------------------------------------------------------------------
# Page renderer
# -----------------------------------------------------------------------------

def send_about_page(handler, state: WebUIState) -> None:
    """Render and send the About page."""
    version = get_app_version()
    lic_html, lic_spacer = build_top_banner_html()

    # Playback totals across both inputs (indices 1 and 2).
    playback_snapshot = get_playback_snapshot()
    total_playback_seconds = sum(
        int(snap.total_playback_seconds)
        for idx, snap in playback_snapshot.inputs.items()
        if int(idx) in (1, 2)
    )
    total_playback_hours = total_playback_seconds / 3600.0

    cpu_temp_c = get_cpu_temperature_c()
    cpu_temp_text = (
        f"{cpu_temp_c:.1f}\N{DEGREE SIGN}C"
        if cpu_temp_c is not None
        else "Unavailable"
    )

    # Config is read defensively; the page degrades gracefully if it fails.
    parsed = None
    try:
        parsed = parse_config(locked_load_config(state.config_path))
    except Exception:
        parsed = None

    # Disk usage bar.
    du = get_root_disk_usage()
    storage_html = ""
    if du:
        tot, usd, fre = du
        pct = (usd / tot) * 100 if tot else 0
        clr = "#28a745" if pct < 60 else ("#f0ad4e" if pct < 80 else "#dc3545")
        storage_html = (
            f"<div class='bar-label'><strong>Disk Usage:</strong> {pct:.1f}%</div>"
            f"<div class='storage-bar'><div class='used' style='width:{pct}%;background:{clr};'></div></div>"
            f"<div class='storage-meta'>Free: {fmt_bytes(fre)} / {fmt_bytes(tot)}</div>"
        )

    # SD card health bar (only present when the platform reports it).
    sd_health = get_sdcard_health_percent()
    sd_html = ""
    if sd_health is not None:
        clr = "#dc3545" if sd_health <= 10 else ("#f0ad4e" if sd_health <= 30 else "#28a745")
        sd_html = (
            f"<div class='bar-label'><strong>SD Health:</strong> {sd_health}%</div>"
            f"<div class='storage-bar'><div class='used' style='width:{sd_health}%;background:{clr};'></div></div>"
        )

    # Stylus life cards — only shown for inputs configured as turntables.
    stylus_html = ""
    if parsed is not None:
        stylus_rows: list[str] = []

        input1_snapshot = playback_snapshot.inputs.get(1) or _fallback_input_snapshot(
            parsed.audio1,
            1,
            enabled=True,
        )
        if bool(parsed.audio1.is_turntable):
            input1_title = "Input 1 Stylus"
            if input1_snapshot.last_stylus_reset_at:
                input1_title += f" (last changed {_format_reset_date(input1_snapshot.last_stylus_reset_at)})"
            stylus_rows.append(
                _stylus_box_html(
                    title=input1_title,
                    snapshot=input1_snapshot,
                )
            )

        input2_snapshot = playback_snapshot.inputs.get(2) or _fallback_input_snapshot(
            parsed.audio2,
            2,
            enabled=parsed.audio2_enabled,
        )
        if bool(parsed.audio2_enabled and parsed.audio2.is_turntable):
            input2_title = "Input 2 Stylus"
            if input2_snapshot.last_stylus_reset_at:
                input2_title += f" (last changed {_format_reset_date(input2_snapshot.last_stylus_reset_at)})"
            stylus_rows.append(
                _stylus_box_html(
                    title=input2_title,
                    snapshot=input2_snapshot,
                )
            )

        stylus_html = "".join(stylus_rows)

    html_body = textwrap.dedent(f"""\
      <!DOCTYPE html><html><head><meta charset="utf-8">{VIEWPORT_META}
      <title>About</title><style>{STYLE_CSS}</style></head><body>{lic_html}{lic_spacer}<div class='container'>{BANNER_HTML}<h1>About</h1>
      <p class="actions" style="margin:1rem 0;display:flex;justify-content:space-between;align-items:center;gap:0.75rem;"><a href="/" class="pill-btn">← Back</a><a href="/license" class="pill-btn" style="background:#6c757d;color:#fff;border-color:#6c757d;">License</a></p>
      <fieldset><legend>Overview</legend>
          <p><strong>autostream</strong> streams audio from turntables, CD players, and other analogue Hi-Fi sources to AirPlay&#8209;compatible speakers.</p>
      </fieldset>
      {stylus_html}
      <fieldset><legend>System (build {html.escape(version)})</legend>
        <div class='bar-label'><strong>Total Playback Time:</strong> {total_playback_hours:.1f} hours</div>
        <div class='bar-label'><strong>CPU temperature:</strong> {html.escape(cpu_temp_text)}</div>
        {storage_html}{sd_html}
      </fieldset>
      <fieldset><legend>Copyright</legend>
          <p><strong>autostream</strong> is Copyright &copy; 2025&#8211;2026 Lo-tech Systems Limited. autostream and the autostream logo are trademarks of Lo-tech Systems Limited.</p>
          <p>autostream uses OwnTone and ALSA, redistributed under the terms of their respective open-source licences. AirPlay and AirPlay&nbsp;2 are trademarks of Apple Inc. All other trademarks are the property of their respective owners.</p>
      </fieldset>
      </div></body></html>
    """)
    body_bytes = html_body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)
