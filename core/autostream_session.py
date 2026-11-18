"""autostream_session.py

The playback session as a part of the state snapshot. A session is active
while a live input is the audible source or a repeat recording is replaying;
"source" names which ("input1", "input2" or "replay").

The coordinator publishes the session once per poll cycle. A request thread
that starts a replay publishes it at once through note_replay_started(), so
the answer to "is it playing" is true from the moment the daemon acks the
start, not from the next cycle; the next cycle's publish overwrites it with
the tracker's own view.
"""
from __future__ import annotations

from typing import Optional

import autostream_state
from autostream_state import SessionPart

_writer = autostream_state.store().claim("session", "autostream_session")


def publish(active: bool, source: Optional[str], *, edge: bool = False) -> None:
    """The coordinator's per-cycle session state. edge=True when the cycle's
    tracker reported an event; the change then carries the "session" tag."""
    _writer.publish(
        SessionPart(bool(active), source), tags=("session",) if edge else (),
    ).notify()


def note_replay_started() -> None:
    """Called from the repeat ack when a replay starts from Hold: the session
    is active at once, as source "replay", unless it already is.

    A session that is already active is left alone: fading_out is already an
    active session from the coordinator's view, and hold/idle are left to its
    session-ended path so the OwnTone stop and now-playing end are not
    skipped."""
    _writer.update(lambda cur: cur if cur.active else SessionPart(True, "replay")).notify()
