"""autostream_session.py

The playback session as a part of the state snapshot. A session is active
while a live input is the audible source or a repeat recording is replaying;
"source" names which ("input1", "input2" or "replay").

The coordinator publishes the session once per poll cycle. A request thread
that starts a replay publishes it at once through note_replay_started(), so
the answer to "is it playing" is true from the moment the daemon acks the
start, not from the next cycle; the next cycle's publish overwrites it with
the tracker's own view.

This module also holds the now-playing republish request: set by a request
thread when an output has been enabled (or the backend has been brought back),
consumed once by the coordinator, which then re-sends the current bundle.
"""
from __future__ import annotations

import threading
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


# ── Now-playing republish request ────────────────────────────────────────────
# Set when an output is newly enabled (apply_output_mutation) or when the
# OwnTone recovery path has just re-applied outputs after a backend restart
# (_maybe_retry_owntone): in both cases the receiver-side backend only knows
# the bare queue defaults until the next natural metadata push, so the
# coordinator poll loop consumes this flag once per request and re-sends the
# active session's current now-playing bundle. Same lock discipline as the
# user-silence latch (web/request threads set, coordinator consumes).

_republish_lock = threading.Lock()
_republish_pending: bool = False


def request_nowplaying_republish() -> None:
    """Ask the coordinator to re-send the current now-playing metadata."""
    global _republish_pending
    with _republish_lock:
        _republish_pending = True


def consume_nowplaying_republish() -> bool:
    """Return-and-clear the pending republish request (coordinator loop)."""
    global _republish_pending
    with _republish_lock:
        pending = _republish_pending
        _republish_pending = False
        return pending


def reset_for_tests() -> None:
    """Clear the republish request."""
    global _republish_pending
    with _republish_lock:
        _republish_pending = False
