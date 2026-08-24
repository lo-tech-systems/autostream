"""autostream_bluetooth_presentation.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Presentation-string builders for the Bluetooth-input card and the
Setup-page loopback capture label. Pure string formatting over a status
dict -- no I/O, no dependency on the socket client itself.

Split out of ``core/autostream_bluetooth_client.py``, which re-exports
these names for existing importers. These are the single source of truth
for the Bluetooth card's and input card's presentation strings, shared
between the Setup page's server render, the status JSON API's ``ui``
payload, and the JS poll that refreshes the card in place. Pure code
motion -- no logic changed from the original module.
"""

from __future__ import annotations

from typing import Optional

_LABEL_UNPAIRED = "Bluetooth (not paired)"
_LABEL_UNAVAILABLE = "Bluetooth (service unavailable)"


def bluetooth_capture_label(status: Optional[dict]) -> str:
    """Return the Setup-page label for the loopback capture device.

    ``status`` is the cached/live daemon ``status`` reply (or None when the
    service is absent/unreachable).  Exactly the three label strings pinned
    as: "Bluetooth: <name>", "Bluetooth (not paired)",
    "Bluetooth (service unavailable)".
    """
    if not isinstance(status, dict) or status.get("ok") is not True:
        return _LABEL_UNAVAILABLE
    paired = status.get("paired")
    if isinstance(paired, dict):
        name = str(paired.get("name") or "").strip()
        if name:
            return f"Bluetooth: {name}"
    return _LABEL_UNPAIRED


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


def bluetooth_card_summary(services_enabled: bool, status: Optional[dict]) -> str:
    """Bluetooth card summary line, per the five pinned states.

    ``status`` is the cached/live daemon ``status`` reply (or None when the
    service is absent/unreachable). This is the single source of truth for
    the string -- shared between the Setup page's server render, the status
    JSON API's ``ui`` payload, and (via that payload) the JS poll that
    refreshes the card without a full page reload, so the "paired but link
    down" case can't be computed one way in one place and another way
    elsewhere.

    When streaming and the daemon reports ``codec``/``sample_rate``, the
    connected state appends the negotiated format, e.g.
    "Enabled · Turntable connected - SBC 44.1 kHz". Purely additive: absent
    fields leave the text unchanged from before this existed.
    """
    if not services_enabled:
        return "Disabled"
    if not isinstance(status, dict) or not status.get("adapter_present"):
        return "Enabled · No adapter found"
    paired = status.get("paired")
    if not isinstance(paired, dict) or not str(paired.get("name") or "").strip():
        return "Enabled · Not paired"
    name = str(paired.get("name")).strip()
    if str(status.get("link") or "disconnected") == "connected":
        suffix = _codec_rate_suffix(status)
        format_note = f" -{suffix}" if suffix else ""
        return f"Enabled · {name} connected{format_note}"
    return f"Enabled · {name} (not connected)"


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
