"""dial_sdhealth.py: the dial's own view of its SD card's health.

Reads the same files the appliance's SD card health wrapper writes
(/var/lib/autostream/sdcardhealth-status.json and sdcardhealth.json), through
autostream_sysutils.sdcard_health_state() so the swapped-card and
monitoring-off rules are the appliance's own, and adds staleness from the
health file's age. The reading changes at most daily, so it is re-read on a
slow cadence from the network poller's own thread (tick(), wired by
dial_main.py), never from a thread of its own. The latest view is kept for
lock-free reads (latest()), and a fresh read can be forced after an enable
or disable (refresh_now()) so the screen and the info page do not wait for
the next scheduled read.

Never raises out of tick()/refresh_now(): a failed read yields an
"unavailable" view, which never raises the warning.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass

try:
    from autostream_sysutils import (
        SD_HEALTH_LOW_THRESHOLD,
        SD_HEALTH_RECOVER_THRESHOLD,
        SD_HEALTH_STALE_HOURS,
        SDCARD_HEALTH_JSON_FILE,
        sdcard_health_state,
    )
except ImportError:
    import sys
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "core")))
    from autostream_sysutils import (  # noqa: E402
        SD_HEALTH_LOW_THRESHOLD,
        SD_HEALTH_RECOVER_THRESHOLD,
        SD_HEALTH_STALE_HOURS,
        SDCARD_HEALTH_JSON_FILE,
        sdcard_health_state,
    )

# The probe runs daily; ten minutes is plenty to notice a new reading, and a
# forced refresh covers the enable/disable moment.
SD_HEALTH_POLL_INTERVAL_S = 600.0

STATUS_VALID = "valid"            # monitored, last check passed, a current percent
STATUS_STALE = "stale"            # as valid, but the health file is older than the stale window
STATUS_OFF = "off"                # monitoring not enabled (or the tool is absent)
STATUS_UNSUPPORTED = "unsupported"  # monitored once, the check failed or hung
STATUS_UNAVAILABLE = "unavailable"  # nothing usable (no files, a read error, a swapped card)


@dataclass(frozen=True)
class SdHealthView:
    status: str = STATUS_UNAVAILABLE
    percent: "int | None" = None
    check: str = "none"
    updated_at: float = 0.0


UNKNOWN_VIEW = SdHealthView()

_latest: SdHealthView = UNKNOWN_VIEW
_on_view = None
_last_read_monotonic: "float | None" = None
_lock = threading.Lock()


def latest() -> SdHealthView:
    return _latest


def start(*, on_view=None) -> None:
    """Register the display callback. The reads themselves are driven by
    tick() from the network poller's thread."""
    global _on_view
    _on_view = on_view


def read_health(now: "float | None" = None) -> SdHealthView:
    """One read. Never raises."""
    if now is None:
        now = time.monotonic()
    try:
        state = sdcard_health_state()
    except Exception:
        return SdHealthView(updated_at=now)
    check = str(state.get("check") or "none")
    if not state.get("tool_present") or not state.get("timer_enabled"):
        if check in ("failed", "hung"):
            return SdHealthView(status=STATUS_UNSUPPORTED, check=check, updated_at=now)
        return SdHealthView(status=STATUS_OFF, check=check, updated_at=now)
    percent = state.get("health_percent")
    if check != "passed" or not isinstance(percent, int):
        if check in ("failed", "hung"):
            return SdHealthView(status=STATUS_UNSUPPORTED, check=check, updated_at=now)
        return SdHealthView(status=STATUS_UNAVAILABLE, check=check, updated_at=now)
    status = STATUS_VALID
    try:
        age_h = (time.time() - os.stat(SDCARD_HEALTH_JSON_FILE).st_mtime) / 3600.0
        if age_h > SD_HEALTH_STALE_HOURS:
            status = STATUS_STALE
    except OSError:
        pass
    return SdHealthView(status=status, percent=percent, check=check, updated_at=now)


def is_low(view: SdHealthView, previously_low: bool) -> bool:
    """The warning rule with hysteresis, the storage guard's own: below the
    low threshold raises; once raised, the warning holds until the reading
    is strictly above the recover threshold. A stale reading keeps its
    percent (a worn card does not recover by itself); anything without a
    percent (monitoring off, unsupported, unavailable) ends the incident,
    which is what "no false alarm" means for a file that is absent."""
    if view.status not in (STATUS_VALID, STATUS_STALE) or view.percent is None:
        return False
    if view.percent < SD_HEALTH_LOW_THRESHOLD:
        return True
    return previously_low and view.percent <= SD_HEALTH_RECOVER_THRESHOLD


def _publish(view: SdHealthView) -> None:
    global _latest
    _latest = view
    if _on_view is not None:
        try:
            _on_view(view)
        except Exception:
            logging.debug("dial sdhealth: on_view callback raised", exc_info=True)


def tick(now: "float | None" = None) -> None:
    """Called after every network poll. Reads at most once per
    SD_HEALTH_POLL_INTERVAL_S; the first call reads at once."""
    global _last_read_monotonic
    if now is None:
        now = time.monotonic()
    with _lock:
        due = _last_read_monotonic is None or (now - _last_read_monotonic) >= SD_HEALTH_POLL_INTERVAL_S
        if due:
            _last_read_monotonic = now
    if due:
        _publish(read_health(now))


def refresh_now() -> None:
    """Force a read (after an enable or disable). Never raises."""
    global _last_read_monotonic
    now = time.monotonic()
    with _lock:
        _last_read_monotonic = now
    _publish(read_health(now))


def info_value(view: "SdHealthView | None" = None) -> str:
    """The info page's "SD health" value. Reads fresh when no view is given
    (the gather thread can afford one file read).

    The Low/Good band is percent <= SD_HEALTH_RECOVER_THRESHOLD, independent
    of incident state: a reading in the hysteresis zone (between the low and
    recover thresholds) always shows "Low" here, so the info page and the
    warning never disagree on the way down.
    """
    v = view if view is not None else read_health()
    if v.status == STATUS_OFF:
        return "Not monitored"
    if v.status == STATUS_UNSUPPORTED:
        return "Unsupported"
    if v.status in (STATUS_VALID, STATUS_STALE) and v.percent is not None:
        band = "Low" if v.percent <= SD_HEALTH_RECOVER_THRESHOLD else "Good"
        suffix = " (stale)" if v.status == STATUS_STALE else ""
        return f"{v.percent}% {band}{suffix}"
    return "-"


def reset_for_tests() -> None:
    global _latest, _on_view, _last_read_monotonic
    _latest, _on_view, _last_read_monotonic = UNKNOWN_VIEW, None, None
