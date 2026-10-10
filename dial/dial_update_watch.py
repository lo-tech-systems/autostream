"""dial_update_watch.py: the dial's view of a software update in progress.

The updater and the installer report through one small KEY=VALUE file
(/var/lib/autostream/update-result.env): a status (in_progress, success or
failure), a percent, a human message, the phase the run is in, the release
tags involved, the attempt number and whether a failed update was rolled
back. read_update_result() turns that file into an UpdateView, and
UpdateWatcher.tick() re-reads it only when the file has changed, so the
display's once-a-second tick costs one stat() while nothing is happening.

Also holds the "seen" marker: the timestamp of the last finished result the
screen has shown, so a result card appears once per result and not again
after a Dismiss, an expiry or a restart.

Never raises: an unreadable or missing file is "no view".

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

UPDATE_RESULT_PATH = "/var/lib/autostream/update-result.env"
UPDATE_SEEN_PATH = "/var/lib/autostream/dial-update-seen"

STATUS_IN_PROGRESS = "in_progress"
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"

# The phases the screen acts on (the others only choose a label).
PHASE_REBOOT = "reboot"
PHASE_VERIFY = "verify"


@dataclass(frozen=True)
class UpdateView:
    status: str = ""
    percent: int = 0
    message: str = ""
    phase: str = ""
    tag: str = ""
    previous_tag: str = ""
    attempt: int = 0
    rolled_back: bool = False
    last_run_at: str = ""


def _to_int(text: str, default: int = 0) -> int:
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return default


def parse_update_result(text: str) -> UpdateView:
    """Parse the file's text. Unknown keys and malformed lines are ignored;
    a missing key takes its default; the percent is clamped to 0..100."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"')
    return UpdateView(
        status=values.get("STATUS", ""),
        percent=max(0, min(100, _to_int(values.get("PERCENT_COMPLETE", "0")))),
        message=values.get("MESSAGE", ""),
        phase=values.get("PHASE", ""),
        tag=values.get("TAG", ""),
        previous_tag=values.get("PREVIOUS_TAG", ""),
        attempt=_to_int(values.get("ATTEMPT", "0")),
        rolled_back=values.get("ROLLED_BACK", "0") == "1",
        last_run_at=values.get("LAST_RUN_AT", ""),
    )


def read_update_result(path: str = UPDATE_RESULT_PATH) -> "UpdateView | None":
    """The parsed result file, or None when it is missing or unreadable."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return parse_update_result(handle.read())
    except OSError:
        return None


class UpdateWatcher:
    """Polls the result file by its stat signature. tick() returns the new
    view when the file's mtime or size changed since the last tick (the
    first tick after the file appears included), else None."""

    def __init__(self, path: str = UPDATE_RESULT_PATH) -> None:
        self._path = path
        self._signature: "tuple[int, int] | None" = None

    def tick(self, now: float = 0.0) -> "UpdateView | None":
        try:
            st = os.stat(self._path)
        except OSError:
            self._signature = None
            return None
        signature = (st.st_mtime_ns, st.st_size)
        if signature == self._signature:
            return None
        view = read_update_result(self._path)
        if view is None:
            return None
        self._signature = signature
        return view


def read_seen_marker(path: str = UPDATE_SEEN_PATH) -> str:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def write_seen_marker(value: str, path: str = UPDATE_SEEN_PATH) -> None:
    """Record *value* as the last result shown. Best effort: a failed write
    only means the card may show once more after a restart."""
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as handle:
            handle.write(value + "\n")
        os.replace(tmp, path)
    except OSError:
        logging.debug("dial update watch: could not write the seen marker", exc_info=True)
