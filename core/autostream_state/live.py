"""autostream_state.live -- reads that go to the monitor daemon on the
caller's thread, with their own timeouts. Not part of the snapshot: two calls
may see different moments.
"""
from __future__ import annotations

import logging
from typing import Optional

import autostream_monitor_client as monitor_client


def get_live_output_eq_status(
    socket_path: Optional[str] = None,
) -> Optional[dict]:
    """Return current output EQ status from autostream_monitor, or None if unavailable.

    Returned dict contains:
      output_auto_trim_enabled  bool
      output_auto_trim_db       float  (current accumulated trim; 0.0 or negative)
      effective_output_gain_db  float
    """
    try:
        with monitor_client._connected_monitor(socket_path) as client:
            if client is None:
                return None
            status = client.get_status()
            if not status:
                return None
            return {
                "output_auto_trim_enabled": bool(status.get("output_auto_trim_enabled", False)),
                "output_auto_trim_db": float(status.get("output_auto_trim_db", 0.0)),
                "effective_output_gain_db": float(status.get("effective_output_gain_db", 0.0)),
            }
    except Exception as e:
        logging.warning("Could not get live output EQ status: %s", e)
        return None


def get_live_monitor_output_rate(
    fallback: int = 48000,
    socket_path: Optional[str] = None,
) -> int:
    """Return the monitor's live-reported output sample rate in Hz.

    Reads the "output_rate" field from get_status() (added alongside
    output_bits/output_channels for the 48k/32-bit IPC flip). Returns
    *fallback* whenever the monitor is unreachable, the field is missing,
    or the reported value is not a sane positive number -- callers must
    never hardcode a rate assumption instead.
    """
    try:
        with monitor_client._connected_monitor(socket_path) as client:
            if client is None:
                return fallback
            status = client.get_status()
            if not status:
                return fallback
            rate = status.get("output_rate")
            if isinstance(rate, bool) or not isinstance(rate, (int, float)):
                return fallback
            if rate <= 0:
                return fallback
            return int(rate)
    except Exception as e:
        logging.warning("Could not get live monitor output rate: %s", e)
        return fallback
