"""autostream_session.py

The playback session as a part of the state snapshot. A session is active
while a live input is the audible source or a repeat recording is replaying;
"source" names which ("input1", "input2" or "replay").

The coordinator publishes the session once per poll cycle. A request thread
that starts a replay publishes it at once through note_replay_started(), so
the answer to "is it playing" is true from the moment the daemon acks the
start, not from the next cycle; the next cycle's publish overwrites it with
the tracker's own view.

The tracker diffs the source vector once per poll cycle, and the dispatch
applies each edge it reports: the OwnTone output path and the now-playing
start and end.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

import autostream_intents as intents
import autostream_state
from autostream_intents import Intent
from autostream_nowplaying import NowPlayingMetadata
from autostream_state import Origin, SessionPart
from autostream_state.outputs import get_authority

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


# ── Unified playback-session tracker ─────────────────────────────────────────
#
# A single source-vector session model drives idle-stop gating and
# replay-end/OwnTone-stop handling uniformly: each poll cycle,
# the coordinator derives which of {input1, input2, replay} is the audible
# source from the SAME status snapshot already ingested, and diffs it
# against the previous cycle's source. Exactly one of three events results:
#
#   session_started  (no source -> a source)       -- new-session output path
#   session_ended     (a source -> no source)       -- stop-and-disable path
#   source_changed    (a source -> a *different*     -- no output/volume
#                      source)                          action whatsoever
#
# source_changed covers live-interrupt-of-replay, capture-end -> replay
# handoff, and input1 <-> input2 handoff: in each case OwnTone's selected
# outputs/volume are already correct for the still-active session and must
# be left alone.
#
# Coordinator-thread only: one SessionTracker instance per run_autostream()
# invocation (recreated on each reload), one update() call per poll cycle.
# No new threads or locks are introduced by the tracker itself.

def _current_source_monitor(monitors, source: Optional[str], origin_input: Optional[int]):
    """Resolve a vector key ("input1"/"input2"/"replay") to its AudioMonitor.

    *origin_input* is the already-computed replay_origin_input() for the
    SAME snapshot the vector was built from -- resolving "replay" any other
    way would risk reading a later, possibly-stale repeat_status.
    """
    if source is None:
        return None
    if source == "replay":
        idx = origin_input
    else:
        try:
            idx = int(source[len("input"):])
        except (ValueError, IndexError):
            return None
    return next((m for m in monitors if m.input_index == idx), None)


class SessionTracker:
    """Diffs the {input1, input2, replay} source vector between poll cycles.

    See module comment above for the event semantics. Resolves the AudioMonitor
    for both the previous and new source at update() time (while the snapshot
    driving them is fresh) rather than re-deriving it later from status that
    may have moved on by the time the caller acts on the event.
    """

    def __init__(self) -> None:
        self._source: Optional[str] = None
        self._source_monitor = None  # AudioMonitor or None

    def reset(self) -> None:
        """Clear tracked state so the next update() cannot manufacture a
        spurious event by diffing against stale pre-reset state.

        Called on coordinator reconnect/resync:
        if a session is genuinely still active across the resync, the next
        cycle reports it as a fresh session_started, which is intentional --
        reconnect already forces a full OwnTone output re-validation for
        every monitor (existing _owntone_enabled_ok reset), so re-running the
        new-session output path is consistent with that, not spurious. If
        nothing was active, both sides of the next diff are None and no
        event fires.
        """
        self._source = None
        self._source_monitor = None

    @property
    def active_source(self) -> Optional[str]:
        return self._source

    def update(self, monitors, repeat_status: Optional[dict]):
        """Advance one poll cycle.

        Returns (event, prev_monitor, new_monitor, new_source) where event is
        one of "session_started" / "session_ended" / "source_changed" / None.
        """
        origin_input = autostream_state.replay_origin_input(repeat_status)
        vector = {f"input{m.input_index}": bool(m.is_capturing) for m in monitors}
        vector["replay"] = origin_input is not None

        # Mutual exclusion between a capturing input and replay for the same
        # recording is a daemon invariant (see replay_origin_input); prefer
        # "replay" if it's ever violated since it is the rarer, more specific
        # state to surface.
        active = [k for k, v in vector.items() if v]
        new_source = "replay" if vector["replay"] else (active[0] if active else None)
        new_monitor = _current_source_monitor(monitors, new_source, origin_input)

        prev_source = self._source
        prev_monitor = self._source_monitor

        if prev_source is None and new_source is not None:
            event = "session_started"
        elif prev_source is not None and new_source is None:
            event = "session_ended"
        elif prev_source is not None and new_source is not None and prev_source != new_source:
            event = "source_changed"
        else:
            event = None

        self._source = new_source
        self._source_monitor = new_monitor
        return event, prev_monitor, new_monitor, new_source


def _start_session_owntone(monitor: "AudioMonitor") -> None:
    """New-session OwnTone output-enable path (session_started event).

    Equivalent to a capture-start-from-idle output-enable, but
    driven through whichever AudioMonitor is the session's source -- for a
    replay-sourced start that is the origin input's AudioMonitor, not the one
    (if any) that happens to be capturing, so replay start-from-idle reuses
    the existing _owntone_enabled_ok / _maybe_retry_owntone machinery instead
    of duplicating it (this is the fix for the "replay start never enables
    outputs" symptom).
    """
    monitor._owntone_enabled_ok = False
    monitor._owntone_last_attempt = 0.0
    monitor.clear_default_output_wait()
    if monitor.owntone_base_url:
        intents.submit(Intent("outputs.deselect_all", {}, Origin.SESSION, "coordinator"))
    get_authority().note_session(True)
    # replay_origin=True unconditionally: harmless for an input-sourced start
    # (is_capturing already satisfies the guard) and required for a
    # replay-sourced start (the origin input's is_capturing is False).
    monitor._maybe_retry_owntone(time.time(), replay_origin=True)


def _session_nowplaying_start(monitor: Optional["AudioMonitor"]) -> None:
    if monitor is None:
        return
    # Fresh session: drop any title/artist/artwork left over from whatever
    # last played (own previous session, or -- for source_changed -- the
    # other input) before publishing, so a stale cover doesn't flash before
    # this session's own identification (if any) lands.
    monitor._reset_nowplaying_for_new_session()
    monitor._nowplaying_publisher.publish_start(monitor._current_nowplaying)


def republish_current_nowplaying(monitor: Optional["AudioMonitor"], session_active: bool) -> None:
    """Re-send the active session's current now-playing bundle mid-session.

    Consumed-flag counterpart of runtime.request_nowplaying_republish():
    fired when a newly enabled output (or a freshly restarted backend) knows
    only the queue defaults. artwork is deliberately None -- publish_refresh()'s
    "no news" value -- so the publisher re-sends whatever artwork it
    currently holds (placeholder or identified cover) rather than treating
    the republish as an artwork change. Dropped silently when no session is
    active: a future session opens with its own publish_start()."""
    if not session_active or monitor is None:
        return
    cur = monitor._current_nowplaying
    if cur is None:
        return
    monitor._nowplaying_publisher.publish_refresh(
        NowPlayingMetadata(
            title=cur.title,
            artist=cur.artist,
            album=cur.album,
            artwork=None,
        )
    )


def _session_nowplaying_end(monitor: Optional["AudioMonitor"]) -> None:
    if monitor is None:
        return
    try:
        monitor._nowplaying_publisher.publish_end()
    except Exception as e:
        # Must be logged, not swallowed silently -- same as the publisher's own
        # start/refresh/end write-failure path (_run()'s except).
        logging.debug(
            "now-playing publish_end failed for input %d: %s",
            monitor.input_index, e,
        )


def dispatch_session_event(
    event: Optional[str],
    prev_monitor: Optional["AudioMonitor"],
    new_monitor: Optional["AudioMonitor"],
    owntone_base_url: str,
    new_source: Optional[str] = None,
) -> None:
    """Apply the session-level side effects for one SessionTracker event.

    - session_started: OwnTone new-session output-enable path (via
      new_monitor, see _start_session_owntone) + now-playing publish_start.
    - session_ended: all outputs switched off and the player stopped (the
      outputs.deselect_all intent) + now-playing publish_end.
    - source_changed: now-playing publish_end(prev) + publish_start(new)
      only -- NO output/volume action whatsoever. Applies to
      live-interrupt-of-replay, capture-end -> replay handoff, and
      input1 <-> input2 handoff: OwnTone's selected outputs/volume are
      already correct for the still-active session.
    - None: no event this cycle, nothing to do.

    *new_source* is the same SessionTracker.update() call's vector key
    ("input1"/"input2"/"replay"/None) for new_monitor. When a
    session_started or source_changed event lands on any source (replay or
    live), this also arms new_monitor's identification cycle: a
    replay-sourced input never gets a fresh is_capturing 0->1 edge to arm
    from, and a live input taking over from a replay can also reach this
    event with no fresh edge left (see _arm_track_identification_for_
    session()'s docstring for both cases), so this is the one place that
    is guaranteed to run for either.

    The replay-end identification teardown is deliberately not done here; see
    teardown_identification_after_replay_end(), which the poll loop calls
    once the session state and playing announcement have been updated.
    """
    if event == "session_started":
        _session_nowplaying_start(new_monitor)
        if new_monitor is not None:
            _start_session_owntone(new_monitor)
    elif event == "session_ended":
        _session_nowplaying_end(prev_monitor)
        if prev_monitor is not None:
            prev_monitor.clear_default_output_wait()
        if owntone_base_url:
            intents.submit(Intent("outputs.deselect_all", {}, Origin.SESSION, "coordinator"))
        # A new session always gets normal default-output behaviour: the
        # user's choice of silence and the retry back-offs end with it.
        get_authority().note_session(False)
    elif event == "source_changed":
        _session_nowplaying_end(prev_monitor)
        _session_nowplaying_start(new_monitor)

    if (
        event in ("session_started", "source_changed")
        and new_source is not None
        and new_monitor is not None
    ):
        new_monitor._arm_track_identification_for_session()


def teardown_identification_after_replay_end(
    event: Optional[str],
    prev_source: Optional[str],
    prev_monitor: Optional["AudioMonitor"],
    new_monitor: Optional["AudioMonitor"],
) -> None:
    """Tear down the replay origin monitor's identification when a replay ends.

    *prev_source* is the tracker's source before the update() call that
    produced *event*. When it was "replay" and the replay has ended
    (session_ended) or handed over to a different monitor (source_changed),
    the origin monitor's identification is torn down: the replay end raises
    no capture-stop edge, and _replay_origin is already false on that tick,
    so this is the only place that can tell. A live source ending is torn
    down by _on_capture_stopped() and is left alone here.

    The poll loop calls this after the session has been marked inactive and
    the playing announcement withdrawn, so a client never sees the appliance
    advertised as playing together with an already-reset identification.
    """
    if (
        event in ("session_ended", "source_changed")
        and prev_source == "replay"
        and prev_monitor is not None
        and prev_monitor is not new_monitor
    ):
        prev_monitor._teardown_identification_after_replay()
