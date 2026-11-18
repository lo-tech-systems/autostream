"""autostream_repeat.py

The repeat block of the state snapshot, and the ack overlay that keeps it
current between two poll cycles.

The coordinator publishes the daemon's top-level "repeat" status block once
per poll cycle through publish_from_daemon(). A transport or arm command sent
from a request thread (dial, Web UI) returns an ack; apply_repeat_ack()
folds that ack into the block at once, so the answer to "is it replaying" does
not wait for the next cycle. The next cycle's publish overwrites the overlay
with the daemon's own report.

Both paths hold _overlay_lock while they read and publish, so an ack overlaid
on the block it read cannot land after a newer block from the daemon. The
change is delivered to subscribers after the lock is released.
"""
from __future__ import annotations

import copy
import logging
import math
import threading
from typing import Optional

import autostream_announce as announce
import autostream_runtime as runtime
import autostream_session
import autostream_state
from autostream_state import RepeatPart

_writer = autostream_state.store().claim("repeat", "autostream_repeat")

# Held across read-overlay-publish by both publishers. Taken under no other
# lock; the store's own lock is taken inside it, and nothing is delivered
# while it is held.
_overlay_lock = threading.Lock()

_REPEAT_ACK_COMMANDS = ("repeat_seek", "repeat_stop", "set_repeat_armed")
_REPEAT_ACK_STATES = (
    "idle", "recording", "pending", "hold", "replaying", "fading_out",
)


def _overlay_repeat_status_from_ack(
    status: dict, ack: dict,
) -> tuple[dict, bool, bool]:
    """Return (overlaid copy of *status*, started, sought) for an accepted ack.

    Pure: *status* is never mutated (the published block may be in a reader's
    hands). started is True when the ack moves the daemon from not replaying
    to replaying; sought is True for a replaying repeat_seek ack.
    """
    new = copy.deepcopy(status)
    replay = new.get("replay")
    if not isinstance(replay, dict):
        replay = {}
        new["replay"] = replay
    was_active = bool(replay.get("active"))
    state = ack["state"]
    command = ack["command"]
    raw_position = ack.get("position_seconds")
    ack_position = (
        float(raw_position)
        if isinstance(raw_position, (int, float)) and not isinstance(raw_position, bool)
        and math.isfinite(raw_position)
        else None
    )

    new["armed"] = bool(ack.get("armed"))

    started = state == "replaying" and not was_active
    if state in ("replaying", "fading_out"):
        replay["active"] = True
        replay["fading_out"] = state == "fading_out"
        if command == "set_repeat_armed":
            # An arm ack carries the engine's current position, which is
            # stale when the arm starts a replay from Hold (that replay
            # always begins at zero) and irrelevant when already replaying.
            if started:
                replay["position_seconds"] = 0.0
        elif ack_position is not None:
            replay["position_seconds"] = ack_position
        if started:
            recording = new.get("recording")
            seconds = recording.get("seconds") if isinstance(recording, dict) else None
            if isinstance(seconds, (int, float)) and not isinstance(seconds, bool):
                # Both are total_bytes / byte_rate in the daemon, so the
                # recording length is the replay length.
                replay["duration_seconds"] = float(seconds)
    elif state in ("hold", "idle"):
        replay["active"] = False
        replay["fading_out"] = False
    # recording / pending: only "armed" can have changed.

    sought = state == "replaying" and command == "repeat_seek"
    return new, started, sought


def _rearm_replay_identification(origin_input: Optional[int], in_session: bool) -> None:
    """Re-arm track identification on the replay origin's monitor.

    Called from apply_repeat_ack on the API thread. in_session is False when
    the ack starts a replay from Hold (the coordinator's session_started
    will publish the session's now-playing) and True for a seek within a
    running replay. Does nothing when the origin monitor is not known.
    """
    if origin_input is None:
        return
    with runtime._monitors_lock:
        target = next(
            (m for m in runtime.all_monitors if m.input_index == origin_input), None)
    if target is not None:
        target.on_replay_seek_accepted(in_session)


def _announce_playing_if_active(version: str) -> None:
    """Pool worker: sync the announcement to the session state as it is now.

    The state is read when the task runs, not when it was submitted, so a
    stop that lands between the ack and the write leaves the service file
    removed (or never written) instead of announcing an idle appliance. A
    stop landing inside the window between this read and the write is
    corrected by the coordinator's next tick or the periodic reconciliation.
    """
    announce.sync_playing_announcement(
        autostream_state.store().snapshot().session.active, version)


def _announce_replay_playing() -> None:
    """Advertise the appliance as playing as soon as a replay start is acked.

    Called from apply_repeat_ack on the API thread, so the write (a sudo
    admin call) is handed to the task pool rather than run inline. The
    submission is single-flight, and sync_playing_announcement is
    idempotent under its lock, so the coordinator's own sync later in
    the session either finds it announced or waits briefly for the write:
    one write per session. Never raises.
    """
    version = announce._playing_version
    if version is None or announce._playing_announced:
        return
    try:
        runtime._task_pool.submit(
            "playing-announce", _announce_playing_if_active, version)
    except Exception:
        logging.debug("replay playing announcement not submitted", exc_info=True)


def apply_repeat_ack(ack: Optional[dict], *, requester: Optional[str] = None) -> Optional[dict]:
    """Fold an accepted transport/arm ack into the published repeat block.

    Called on the API thread by send_live_repeat_transport and
    set_live_repeat_armed_ack, so every entry point (dial, Web UI)
    gets it. *requester* names who asked; the change is published with it and
    with the "repeat" tag, so dials are hinted except the one that asked.
    Returns *ack* unchanged. No-op for None, ok:false, or a shape
    the daemon never produces. The next poll cycle overwrites everything
    written here with the daemon's own report; this only closes the gap
    between the ack and that cycle.

    Identification is re-armed here, at the ack, rather than by bumping the
    daemon's replay track_change_seq on a seek: this runs on the API thread
    so it is immediate, and every seek goes through
    send_live_repeat_transport so it covers every caller. A daemon-side bump
    would only be read on the coordinator's next poll and would re-arm a
    second time for the same seek.
    """
    if not (isinstance(ack, dict) and ack.get("ok")):
        return ack
    if ack.get("state") not in _REPEAT_ACK_STATES:
        return ack
    if ack.get("command") not in _REPEAT_ACK_COMMANDS:
        return ack

    with _overlay_lock:
        block = autostream_state.store().snapshot().repeat.block
        # Nothing to overlay (older daemon, or not yet polled), and no
        # recording origin to resolve. No change was published, so there is
        # nothing to deliver.
        if not isinstance(block, dict):
            return ack
        new_block, started, sought = _overlay_repeat_status_from_ack(block, ack)
        pending = _writer.publish(
            RepeatPart(new_block), requester=requester, tags=("repeat",))
    pending.notify()

    if ack["state"] == "replaying":
        # No-op when a session is already active (fading_out is one from the
        # coordinator's view; hold/idle are left to its session_ended path so
        # the OwnTone stop and now-playing end are not skipped).
        autostream_session.note_replay_started()

    if sought or started:
        _rearm_replay_identification(
            autostream_state.repeat_recording_origin(new_block), in_session=not started)
    if started:
        _announce_replay_playing()
    return ack


def publish_from_daemon(block: Optional[dict]) -> None:
    """The coordinator's per-cycle repeat block, verbatim from the daemon's
    status. None means the daemon has not reported one (older binary, or not
    yet polled): the feature is then treated as unsupported."""
    with _overlay_lock:
        pending = _writer.publish(RepeatPart(block if isinstance(block, dict) else None))
    pending.notify()
