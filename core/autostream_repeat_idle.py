#!/usr/bin/env python3
"""autostream_repeat_idle.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

Stops repeat once nothing has been heard for a while: when a replay, or a
live session with repeat armed, has gone to no speaker for
NO_SPEAKER_STOP_SECONDS, the monitor is asked to stop repeat. That disarms
it, fades out a replay and keeps the recording, so Repeat can be pressed
again. A speaker can be off for any reason: switched off, given up on, or
turned off by the receiver Pause timeout, which nudges this check to act at
once instead of waiting.

run_check() is called from the coordinator loop's interval table; nudge()
may be called from any thread.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Optional

from autostream_intents.table import Intent, submit
from autostream_state import Origin, store

LOG = logging.getLogger("autostream.repeat_idle")

NO_SPEAKER_STOP_SECONDS = 300.0
CHECK_PERIOD_SECONDS = 2.0


class NoSpeakerRepeatStop:
    """Decides when repeat should be stopped because nothing is heard.

    A stretch runs while something plays (a replay, or a live capture) and
    no speaker is on. It fires once when repeat is armed or replaying and
    either the stretch has lasted NO_SPEAKER_STOP_SECONDS or a nudge came.
    A speaker coming on, or nothing playing, ends the stretch; repeat being
    armed again starts a new one. check() is for one thread only."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._nudged = threading.Event()
        self._since: Optional[float] = None
        self._fired = False
        self._was_wanted = False
        self.last_was_nudge = False

    def nudge(self) -> None:
        """Ask the next check to act now rather than after the full time."""
        self._nudged.set()

    def check(self, *, speaker_on: bool, playing: bool, stop_wanted: bool) -> bool:
        """True on the one call that should stop repeat."""
        nudged = self._nudged.is_set()
        self._nudged.clear()
        rising = stop_wanted and not self._was_wanted
        self._was_wanted = stop_wanted

        if speaker_on or not playing:
            self._since = None
            self._fired = False
            return False
        now = self._clock()
        if self._since is None or rising:
            self._since = now
            self._fired = False
        if self._fired or not stop_wanted:
            return False
        if nudged or now - self._since >= NO_SPEAKER_STOP_SECONDS:
            self._fired = True
            self.last_was_nudge = nudged
            return True
        return False


def _repeat_flags(block) -> tuple[bool, bool]:
    """(replaying, armed) from the daemon's repeat status block."""
    if not isinstance(block, dict):
        return False, False
    replay = block.get("replay") if isinstance(block.get("replay"), dict) else {}
    replaying = bool(replay.get("active")) or bool(replay.get("fading_out"))
    return replaying, bool(block.get("armed"))


_watch = NoSpeakerRepeatStop()


def nudge() -> None:
    _watch.nudge()


def run_check() -> None:
    """One check, from the coordinator loop. Never raises."""
    try:
        snap = store().snapshot()
        replaying, armed = _repeat_flags(snap.repeat.block)
        capturing = any(e.capturing for e in snap.inputs.entries)
        if not _watch.check(
            speaker_on=bool(snap.outputs.selected_units()),
            playing=replaying or capturing,
            stop_wanted=replaying or armed,
        ):
            return
        if _watch.last_was_nudge:
            LOG.info("Pause timeout left no speaker on: repeat stopped")
        else:
            LOG.info("No speaker on for %d minutes: repeat stopped", int(NO_SPEAKER_STOP_SECONDS // 60))
        reply = submit(Intent("repeat.transport", {"action": "stop"}, Origin.POLICY, "policy"))
        if not reply.ok:
            LOG.warning("Could not stop repeat with no speaker on: %s", reply.error)
    except Exception:
        LOG.exception("repeat no-speaker check failed")


def reset_for_tests(clock: Callable[[], float] = time.monotonic) -> NoSpeakerRepeatStop:
    global _watch
    _watch = NoSpeakerRepeatStop(clock)
    return _watch
