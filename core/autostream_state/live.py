"""autostream_state.live -- reads that go to the monitor daemon, the player and
other collaborators on the caller's thread, with their own timeouts. Not part of
the snapshot: two calls may see different moments.
"""
from __future__ import annotations

import logging
import threading
from typing import Callable, Optional

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


# ---------------------------------------------------------------------------
# Reads that go to the player, the track-identification client or the
# occupancy and log-policy modules on the caller's thread.
#
# Each function keeps the arguments, I/O and timeouts of the function it
# fronts. The Level 0 sources are imported inside the functions, so importing
# this package pulls none of them in. The Level 2 sources cannot be imported
# from here; their own module binds them (see bind()).
# ---------------------------------------------------------------------------

class LiveNotBound(RuntimeError):
    """A live read whose Level 2 owner has not been imported."""


# Names that a Level 2 module implements and binds when it is imported.
BINDABLE = ("annotate_outputs", "get_log_level_state", "get_align_status", "get_align_review",
            "current_warnings", "warnings_payload", "state_refresh")

_bound_lock = threading.Lock()
_bound: dict[str, tuple[Callable, str]] = {}


def bind(name: str, fn: Callable, *, owner: str) -> None:
    """Called once by the Level 2 module that implements *name*; a second
    owner raises. The owner binding again (a module imported twice under test)
    replaces its own entry."""
    if name not in BINDABLE:
        raise ValueError(f"{name!r} is not a bindable live read; known: {BINDABLE}")
    with _bound_lock:
        current = _bound.get(name)
        if current is not None and current[1] != owner:
            raise ValueError(f"live read {name!r} is already bound by {current[1]}")
        _bound[name] = (fn, owner)


def bound_owner(name: str) -> Optional[str]:
    """The module that bound *name*, or None."""
    with _bound_lock:
        entry = _bound.get(name)
    return entry[1] if entry else None


def _call_bound(name: str, *args, **kwargs):
    with _bound_lock:
        entry = _bound.get(name)
    if entry is None:
        raise LiveNotBound(f"live read {name!r} has no owner; import the module that binds it")
    return entry[0](*args, **kwargs)


def get_setting(base_url: str, key: str, *, timeout: float = 3.0):
    """One setting of the player (autostream_player_service.get_setting)."""
    import autostream_player_service as player_service  # noqa: PLC0415
    return player_service.get_setting(base_url, key, timeout=timeout)


def get_capabilities(base_url: str, *, timeout: float = 3.0):
    """What the player can do (autostream_player_service.get_capabilities)."""
    import autostream_player_service as player_service  # noqa: PLC0415
    return player_service.get_capabilities(base_url, timeout=timeout)


def list_outputs(base_url: str, *, timeout: float = 3.0):
    """The player's output list, asked directly (autostream_player_service.list_outputs).
    For the readiness probe of the OwnTone setup page, which waits for the
    player's API to answer after a restart; every other reader uses the
    outputs part of the snapshot."""
    import autostream_player_service as player_service  # noqa: PLC0415
    return player_service.list_outputs(base_url, timeout=timeout)


def get_owntone_runtime_info(base_url: str = "", *, timeout: float = 3.0, refresh_if_stale: bool = True):
    """The player's cached runtime metadata (autostream_player_service.get_owntone_runtime_info)."""
    import autostream_player_service as player_service  # noqa: PLC0415
    return player_service.get_owntone_runtime_info(
        base_url, timeout=timeout, refresh_if_stale=refresh_if_stale)


def get_vibra_runtime_info():
    """The track-identification client's in-memory runtime metadata
    (track_id.vibra_shazam.get_vibra_runtime_info)."""
    from track_id import vibra_shazam  # noqa: PLC0415
    return vibra_shazam.get_vibra_runtime_info()


def start_buffer_ms(base_url: Optional[str]) -> int:
    """The player's audio start buffer in ms, from the in-memory cache: never
    waits on the player, and may start one background refresh
    (autostream_start_buffer_cache.current_ms)."""
    import autostream_start_buffer_cache as start_buffer_cache  # noqa: PLC0415
    return start_buffer_cache.current_ms(base_url)


def pin_claim(output_id: str) -> str:
    """Who is entering a PIN for *output_id* now ("webui", "dial:<id>"), or ""
    (autostream_pin_pairing.holder). A claim lapses with time, so it is read,
    not published."""
    import autostream_pin_pairing as pairing  # noqa: PLC0415
    return pairing.holder(output_id)


def annotate_outputs(outputs: list[dict]) -> list[dict]:
    """The output dicts with remote-occupancy fields added (bound by autostream_output_usage)."""
    return _call_bound("annotate_outputs", outputs)


def get_log_level_state(*args, **kwargs):
    """The log-level policy state (bound by autostream_log_policy)."""
    return _call_bound("get_log_level_state", *args, **kwargs)


def get_align_status() -> dict:
    """The calibration run's status (bound by autostream_align)."""
    return _call_bound("get_align_status")


def get_align_review():
    """The calibration run's snapshots and pending result (bound by autostream_align)."""
    return _call_bound("get_align_review")


def state_refresh() -> None:
    """Ask the appliance state worker to re-read its sources now (bound by
    autostream_appliance_state). A missed call costs at most one 30 s pass."""
    _call_bound("state_refresh")


def current_warnings() -> list:
    """The warnings this appliance wants a dial to show (bound by autostream_dial_warnings)."""
    return _call_bound("current_warnings")


def warnings_payload(warnings) -> list:
    """*warnings* as the dial warnings route's list of objects (bound by autostream_dial_warnings)."""
    return _call_bound("warnings_payload", warnings)
