"""autostream_bluetooth_presentation.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Presentation-string builders for input 3's Bluetooth rows and summary.
Pure string formatting over a status dict -- no I/O, no dependency on the
socket client itself.

Split out of ``core/autostream_bluetooth_client.py``, which re-exports
these names for existing importers. These are the single source of truth
for input 3's presentation strings, shared between the Setup page's server
render, the status JSON API's ``ui`` payload, and the JS poll that
refreshes the card in place.
"""

from __future__ import annotations

from typing import Optional

def _format_sample_rate_khz(sample_rate) -> Optional[str]:
    """Render a Hz integer as '44.1 kHz' / '48 kHz' (one decimal only when
    the kHz value is non-integer), or None when *sample_rate* isn't a
    positive number."""
    if not isinstance(sample_rate, (int, float)) or isinstance(sample_rate, bool) or sample_rate <= 0:
        return None
    khz = sample_rate / 1000.0
    if khz == int(khz):
        return f"{int(khz)} kHz"
    return f"{khz:.1f} kHz"


def _codec_rate_suffix(status: Optional[dict]) -> str:
    """' <CODEC> <rate>' (leading space) when *status* carries codec/rate
    fields, else ''. Setup-card-only formatting helper -- never call this
    for home-page-facing text (see module docstring)."""
    if not isinstance(status, dict):
        return ""
    codec = str(status.get("codec") or "").strip()
    rate_text = _format_sample_rate_khz(status.get("sample_rate"))
    parts = [p for p in (codec, rate_text) if p]
    return f" {' '.join(parts)}" if parts else ""


def bluetooth_paired_row_text(status: Optional[dict]) -> str:
    """Card 'Paired' row text: '<name> · Connected/Not Connected', or 'No device paired'.

    When connected and *status* carries ``codec``/``sample_rate``, appends
    the negotiated format, e.g. 'Turntable · Connected - SBC 44.1 kHz'.
    Purely additive: absent fields leave the text unchanged from before this
    existed.
    """
    paired = status.get("paired") if isinstance(status, dict) else None
    if not isinstance(paired, dict) or not str(paired.get("name") or "").strip():
        return "No device paired"
    name = str(paired.get("name")).strip()
    link = str(status.get("link") or "disconnected") if isinstance(status, dict) else "disconnected"
    if link == "connected":
        suffix = _codec_rate_suffix(status)
        format_note = f" -{suffix}" if suffix else ""
        return f"{name} · Connected{format_note}"
    return f"{name} · Not Connected"


def bluetooth_input_fragment_text(status: Optional[dict]) -> str:
    """Input-card Bluetooth fragment: the paired device's name when linked, else 'Not Connected'.

    Used as the middle segment of an input card's 'Bluetooth · <X> · <gain>'
    summary, in place of the ALSA card name and turntable flag a non-Bluetooth
    input would show there.
    """
    link = str(status.get("link") or "disconnected") if isinstance(status, dict) else "disconnected"
    if link != "connected":
        return "Not Connected"
    paired = status.get("paired") if isinstance(status, dict) else None
    name = str(paired.get("name") or "").strip() if isinstance(paired, dict) else ""
    return name or "Connected"
