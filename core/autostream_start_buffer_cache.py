"""Cached copy of the OwnTone start buffer for the dial status path.

The dial's status request has a short timeout and must never wait on an
HTTP round trip to OwnTone, yet the dial wants the appliance's audio start
buffer (the delay between the replay position the appliance reports and what
the listener hears). This module keeps the last known value in memory:

  * current_ms() only ever reads the cache. When the cache is empty or older
    than REFRESH_INTERVAL_S it also kicks a single background refresh (daemon
    thread, short timeout, never raises) and returns the cached value, or the
    setting's default before the first successful read.
  * note_saved() records a value the WebUI has just saved, so a change shows
    on the next status poll without waiting for the refresh interval.
  * A failed refresh keeps the previous value and is retried after the
    interval.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Optional

from autostream_players import (
    SETTING_START_BUFFER_MS,
    SETTING_START_BUFFER_MS_DEFAULT,
    SETTING_START_BUFFER_MS_MAX,
    SETTING_START_BUFFER_MS_MIN,
)

REFRESH_INTERVAL_S = 60.0
_FETCH_TIMEOUT_S = 1.5

_lock = threading.Lock()
_value_ms: Optional[int] = None
_checked_at: Optional[float] = None
_refreshing = False


def _clamp(value: int) -> int:
    return max(SETTING_START_BUFFER_MS_MIN, min(SETTING_START_BUFFER_MS_MAX, value))


def _fetch(base_url: str) -> Optional[int]:
    """Read the setting from OwnTone; None on any failure."""
    from autostream_player_service import get_setting

    result = get_setting(base_url, SETTING_START_BUFFER_MS, timeout=_FETCH_TIMEOUT_S)
    if not result.ok:
        return None
    value = result.value
    if isinstance(value, bool):
        return None
    try:
        return _clamp(int(value))
    except (TypeError, ValueError):
        return None


def _refresh(base_url: str, fetch: Callable[[str], Optional[int]]) -> None:
    global _value_ms, _checked_at, _refreshing
    value = None
    try:
        value = fetch(base_url)
    except Exception as exc:  # noqa: BLE001 - a refresh must never raise
        logging.debug("start buffer refresh failed: %s", exc)
    with _lock:
        if value is not None:
            _value_ms = value
        _checked_at = time.monotonic()
        _refreshing = False


def current_ms(
    base_url: Optional[str],
    *,
    fetch: Optional[Callable[[str], Optional[int]]] = None,
) -> int:
    """The start buffer in ms, from cache only.

    Starts a background refresh when the cache is missing or stale and a
    base_url is available. Never blocks on OwnTone.
    """
    global _refreshing
    start = False
    with _lock:
        value = _value_ms
        stale = (
            _checked_at is None
            or time.monotonic() - _checked_at >= REFRESH_INTERVAL_S
        )
        if stale and base_url and not _refreshing:
            _refreshing = True
            start = True
    if start:
        try:
            threading.Thread(
                target=_refresh,
                args=(base_url, fetch or _fetch),
                name="start-buffer-refresh",
                daemon=True,
            ).start()
        except Exception:  # noqa: BLE001 - e.g. thread limit; try again later
            with _lock:
                _refreshing = False
    return SETTING_START_BUFFER_MS_DEFAULT if value is None else value


def note_saved(value_ms: int) -> None:
    """Record a start buffer the WebUI has just saved."""
    global _value_ms, _checked_at
    with _lock:
        _value_ms = _clamp(int(value_ms))
        _checked_at = time.monotonic()


def reset() -> None:
    """Forget everything (used by tests)."""
    global _value_ms, _checked_at, _refreshing
    with _lock:
        _value_ms = None
        _checked_at = None
        _refreshing = False
