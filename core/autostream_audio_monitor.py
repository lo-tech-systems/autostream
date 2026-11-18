"""autostream_audio_monitor -- one input's coordinator-side state: OwnTone
output and now-playing for its sessions, track identification, the playback
tracker's per-input state, and the track part entry for its input (published
under its identification lock).

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import contextlib
import logging
import random
import threading
import time
from dataclasses import replace
from typing import Optional

import autostream_logging as log_setup
import autostream_monitor_client as monitor_client
import autostream_runtime as runtime
import autostream_selfheal as selfheal
import autostream_state
from autostream_artwork import ArtworkMemoryCache
from autostream_config import (
    INPUT_TYPE_DEFAULT,
    input_type_label,
    normalize_input_type,
)
from autostream_nowplaying import (
    NowPlayingMetadata,
    PersistentNowPlayingCache,
    get_shared_metadata_publisher,
    release_shared_metadata_publisher,
    _load_placeholder_artwork,
)


_track_writer = autostream_state.store().claim("track", "autostream_audio_monitor")


def publish_track_service(enabled: bool) -> None:
    """Record whether a track identification service exists: with none, an
    input with nothing playing reads as disabled rather than waiting."""
    _track_writer.update(lambda cur: replace(cur, service_enabled=bool(enabled))).notify()


def _default_nowplaying_title(input_type: str) -> str:
    """The receiver-facing default title for an input with no manual hint
    and no identified track: the input type's label ("Turntable", "CD",
    "Line"), never the raw ALSA device string."""
    return input_type_label(input_type)


# --------------------------------------------------------------------------- #
# AudioMonitor                                                                 #
# --------------------------------------------------------------------------- #

class AudioMonitor:
    """Manages OwnTone control, now-playing metadata, and track recognition
    for one input channel.

    This class no longer performs audio capture or FIFO writing; those are
    handled by the C++ autostream_monitor daemon.  The coordinator loop
    ingests each get_status() poll via _ingest_status() and then fires
    OwnTone or recognition side-effects in a second pass once all monitor
    states have been updated.

    The allow_capture property is set by the coordinator to choose which
    input owns the FIFO at any moment; apply_allow_capture() sends the
    corresponding set_allow_capture command to the daemon when the value
    changes.
    """

    OWNTONE_RETRY_SECONDS = 10.0
    OWNTONE_LOG_THROTTLE_SECONDS = 60.0
    # The mismatch WARNING has its own timer so no other message can
    # silence it; the value matches the monitor's own mismatch log interval.
    RATE_MISMATCH_LOG_THROTTLE_SECONDS = 60.0

    def __init__(
        self,
        input_index: int,
        input_device: str,
        silence_threshold_dbfs: float,
        silence_seconds: int,
        fifo_path: str,
        owntone_base_url: str,
        owntone_output_name: str,
        owntone_volume_percent: int,
        track_change_silence_seconds: float = 1.25,
        minimum_playback_seconds: int = 30,
        owntone_output_offsets_ms: Optional[dict[str, int]] = None,
        owntone_output_airplay_modes: Optional[dict[str, str]] = None,
        gain_db: float = 0.0,
        eq_40hz_db: float = 0.0,
        eq_100hz_db: float = 0.0,
        eq_8khz_db: float = 0.0,
        is_turntable: bool = False,
        input_type: str = INPUT_TYPE_DEFAULT,
        dynamic_rate_matching: bool = True,
    ) -> None:
        self.input_index = input_index
        self.input_device = input_device
        self.is_turntable = is_turntable
        self.input_type = normalize_input_type(input_type)
        self.dynamic_rate_matching = bool(dynamic_rate_matching)
        self.silence_threshold_dbfs = silence_threshold_dbfs
        self.silence_seconds = silence_seconds
        self.track_change_silence_seconds = track_change_silence_seconds
        self.minimum_playback_seconds = minimum_playback_seconds
        self.fifo_path = fifo_path
        self.owntone_base_url = owntone_base_url
        self.owntone_output_name = owntone_output_name
        self.owntone_volume_percent = owntone_volume_percent
        self.owntone_output_offsets_ms = owntone_output_offsets_ms or {}
        self.owntone_output_airplay_modes = owntone_output_airplay_modes or {}
        self.gain_db = gain_db
        self.eq_40hz_db = eq_40hz_db
        self.eq_100hz_db = eq_100hz_db
        self.eq_8khz_db = eq_8khz_db

        # --- Now-playing metadata helpers ---
        self._nowplaying_cache = PersistentNowPlayingCache()
        # Shared per fifo_path: two AudioMonitors pointing at
        # the same physical FIFO (e.g. input1/input2 on one OwnTone pipe
        # input) must publish through one queue+thread, or their bundles can
        # interleave mid-stream during a cross-monitor source_changed
        # dispatch. Paired with release_shared_metadata_publisher() in stop().
        self._nowplaying_publisher = get_shared_metadata_publisher(fifo_path)
        # Track ID gives us an artwork URL; the cache fetches and normalises
        # it into an ArtworkImage entirely in memory (no file handoff -- see
        # autostream_artwork.ArtworkMemoryCache). The fetch cap is
        # deliberately generous (the module default): normalise_artwork()
        # re-encodes an oversized cover down to the publish-ready 48KB
        # regardless of how large the source was, so there is no reason to
        # reject a large source before that resampling gets a chance to run.
        self._artwork_cache = ArtworkMemoryCache()
        self._current_nowplaying = self._default_nowplaying_metadata()

        # --- Track identification scheduling ---
        from track_id.models import disabled_snapshot as _ds
        self._ti_state_lock = threading.Lock()  # guards dispatch setup and _apply_track_id_service
        # Held through _ti_locked(): the thread that holds the lock, and the
        # track-part changes made under it, delivered once it is released.
        self._ti_lock_owner: Optional[int] = None
        self._ti_pending: list = []
        self._ti_generation: int = 0           # incremented on service swap or capture start
        self._ti_inflight: bool = False
        self._ti_inflight_token: Optional[object] = None  # unique per worker
        self._ti_next_attempt: float = 0.0
        self._ti_next_attempt_reason: str = ""
        self._ti_last_attempt: float = 0.0
        self._ti_last_identified_at: float = 0.0
        with self._ti_locked():
            self._set_ti_snapshot(_ds())

        # --- Status (updated by coordinator via _ingest_status) ---
        self.level_dbfs: float = -90.0
        self.poll_peak_dbfs: float = -90.0
        self.detected_hz: float = 0.0
        self.negotiated_hz: int = 0
        self.rate_lock: str = "locked"
        self.relock_count: int = 0
        self.rate_mismatch_hz: int = 0
        # None until a status poll says: an older monitor never reports the
        # key, which is how the Setup card knows the setting cannot take effect.
        self.monitor_dynamic_rate_matching: Optional[bool] = None
        self._rate_mismatch_last_warning: float = 0.0
        self.is_silent: bool = True
        self.is_capturing: bool = False
        # Set each poll cycle from the coordinator's replay_origin_input():
        # True while this input is the origin of a currently
        # replaying recording, i.e. it is the session's audible source even
        # though it is not itself "capturing". See _ingest_status() and
        # maybe_trigger_track_identification()'s actively-sourcing gate.
        self._replay_origin: bool = False
        self._last_active_time: Optional[float] = None
        self._tracker_playback_active: bool = False
        self._tracker_wear_active: bool = False
        self.track_change_seq: int = 0           # last seq from daemon; monotonically increasing
        self._track_change_seq_baseline: int = 0  # seq at capture session start (baselined on "started" transition)
        # Latest VU history block from the daemon (passed through as-is).
        # Replaced atomically on each status poll; Flask thread reads under GIL.
        self.vu_history: dict = {}

        # --- allow_capture: set by coordinator; synced to daemon lazily ---
        self._allow_capture: bool = True
        self._allow_capture_sent: Optional[bool] = None  # last value sent to daemon

        # --- OwnTone retry state ---
        self._owntone_last_attempt: float = 0.0
        self._owntone_enabled_ok: bool = False
        # The output authority's player-restart marker when the selection was
        # last applied; a different one later means the player restarted.
        self._outputs_boot_seen: Optional[str] = None
        self._owntone_recovery_log = runtime.RecoveryLog("OwnTone output-enable")
        self._capture_start_no_output_retry_at: float = 0.0
        self._capture_start_no_output_log_at: float = 0.0

        with runtime._monitors_lock:
            runtime.all_monitors.append(self)

    # ── Public interface ─────────────────────────────────────────────────────

    @property
    def allow_capture(self) -> bool:
        return self._allow_capture

    @allow_capture.setter
    def allow_capture(self, value: bool) -> None:
        self._allow_capture = value
        # Actual socket send is deferred to apply_allow_capture().

    @property
    def seconds_since_last_activity(self) -> float:
        """Seconds since audio last exceeded the silence threshold.

        Returns float('inf') if activity has never been observed.
        """
        if self._last_active_time is None:
            return float("inf")
        return time.time() - self._last_active_time

    def _ingest_rate_status(self, status_entry: dict) -> None:
        """Take the sample-rate fields from a get_status() entry.

        An older monitor reports none of them, so each falls back to a
        value that leaves the Home page as it was: locked, no mismatch, and
        no sign that the monitor supports Dynamic Rate Matching. An input that
        is not started has no rate lock to report, so a monitor that reports
        one for it is read as reporting none (an empty string). A mismatch
        counts only while the input is started and the rate is non-zero;
        the rate, not the lock string, is what the banner and the log follow.
        """
        started = bool(status_entry.get("started", True))
        self.negotiated_hz = int(status_entry.get("negotiated_hz", 0) or 0)
        if "rate_lock" in status_entry and not started:
            self.rate_lock = ""
        else:
            self.rate_lock = str(status_entry.get("rate_lock", "locked") or "locked")
        raw_supported = status_entry.get("dynamic_rate_matching")
        self.monitor_dynamic_rate_matching = (
            raw_supported if isinstance(raw_supported, bool) else None
        )

        new_mismatch = int(status_entry.get("rate_mismatch_hz", 0) or 0) if started else 0
        if new_mismatch != self.rate_mismatch_hz:
            if new_mismatch:
                # The WARNING is limited to one a minute per input by its own
                # timer; a transition inside that period logs at INFO.
                now = time.time()
                level = (
                    logging.WARNING
                    if now - self._rate_mismatch_last_warning
                    >= self.RATE_MISMATCH_LOG_THROTTLE_SECONDS
                    else logging.INFO
                )
                if level == logging.WARNING:
                    self._rate_mismatch_last_warning = now
                logging.log(
                    level,
                    "Input %d is delivering %d Hz but was opened at %d Hz; "
                    "Dynamic Rate Matching is off for this input.",
                    self.input_index, new_mismatch, self.negotiated_hz,
                )
            else:
                logging.info("Input %d sample rate mismatch cleared.", self.input_index)
            self.rate_mismatch_hz = new_mismatch

        new_relocks = int(status_entry.get("relock_count", 0) or 0)
        if new_relocks != self.relock_count:
            if new_relocks:
                logging.info(
                    "Input %d capture rate step #%d: now %.1f Hz (negotiated %d Hz)",
                    self.input_index, new_relocks, self.detected_hz, self.negotiated_hz,
                )
            self.relock_count = new_relocks

    def _ingest_status(self, status_entry: dict, replay_origin: bool = False) -> str:
        """Update fields from a get_status() entry without firing callbacks.

        Returns 'started', 'stopped', or '' to indicate the capturing
        transition so the coordinator can fire callbacks in a second pass,
        after all monitors have been updated.

        *replay_origin* is this same poll cycle's replay_origin_input()
        result compared against self.input_index: True while
        this input is the origin of a currently-replaying recording, so it
        is "actively sourcing" the session even though is_capturing is False.
        track_change_seq advances are daemon-routed under origin_input during
        replay, so the steady-state seq check below must key off
        actively-sourcing, not is_capturing alone, or replay-driven track
        changes are silently dropped. The transition into/out of
        replay-sourcing itself is NOT handled here -- since is_capturing does
        not change when replay starts/stops, there is no "started"/"stopped"
        edge to return; the seq baseline + identification-cycle arming for
        that transition is handled by autostream_session.dispatch_session_event() ->
        _arm_track_identification_for_session(), which runs after this method
        for the whole monitor set (mirrors _on_capture_started, which arms
        the same cycle for a real capturing transition).
        """
        was_capturing = self.is_capturing
        was_actively_sourcing = was_capturing or self._replay_origin

        self.level_dbfs      = float(status_entry.get("level_dbfs", -90.0))
        self.poll_peak_dbfs  = float(status_entry.get("poll_peak_dbfs", -90.0))
        self.detected_hz     = float(status_entry.get("detected_hz", 0.0))
        self.is_silent       = bool(status_entry.get("silent", True))
        self.is_capturing    = bool(status_entry.get("capturing", False))
        self._ingest_rate_status(status_entry)
        self._replay_origin  = bool(replay_origin)
        raw_tcs = status_entry.get("track_change_seq")
        if isinstance(raw_tcs, int) and raw_tcs >= 0:
            self.track_change_seq = raw_tcs
        # Cache the whole vu_history block; Flask thread reads it as-is.
        raw_vu = status_entry.get("vu_history")
        self.vu_history = raw_vu if isinstance(raw_vu, dict) else {}

        if not self.is_silent:
            self._last_active_time = time.time()

        is_actively_sourcing = self.is_capturing or self._replay_origin

        if self.is_capturing and not was_capturing:
            self._track_change_seq_baseline = self.track_change_seq
            return "started"
        if not self.is_capturing and was_capturing:
            return "stopped"

        # No capturing transition this cycle: check for track-change events
        # whenever actively-sourcing on both sides of this ingest (a fresh
        # transition into replay-sourcing is armed by autostream_session.dispatch_session_event
        # instead, after this same poll cycle's baseline would otherwise be
        # stale/unset).
        if was_actively_sourcing and is_actively_sourcing:
            if self.track_change_seq != self._track_change_seq_baseline:
                self._on_possible_track_change(self.track_change_seq)

        return ""

    def _on_possible_track_change(self, new_seq: int) -> None:
        """Handle a track_change_seq advance while capturing."""
        self._track_change_seq_baseline = new_seq
        svc = runtime._track_id_service
        if svc is None:
            return
        from track_id.models import waiting_snapshot
        delay = svc.analysis_lead_in_seconds + svc.snapshot_seconds
        now = time.time()
        # Under the state lock so a worker keeping a held track after a failed
        # re-check (which re-checks the generation under the same lock) cannot
        # publish it over this reset.
        with self._ti_locked():
            self._ti_generation += 1  # invalidate stale in-flight worker results
            self._set_ti_snapshot(waiting_snapshot(input_index=self.input_index))
            self._schedule_track_id_after(now, delay, "track_change")
        logging.info(
            "track_id[%d]: possible track change seq=%d; analysis scheduled in %ds"
            " (lead-in=%ds window=%ds)",
            self.input_index, new_seq, delay,
            svc.analysis_lead_in_seconds, svc.snapshot_seconds,
        )
        self._publish_interstitial_nowplaying()

    def _publish_interstitial_nowplaying(self) -> None:
        """Reset the now-playing metadata to the input-label default and publish it.

        DETECTING-INTERSTITIAL policy: a detected track boundary (or a seek
        within a replay) is a visible moment for the receiver, not just a
        status change. Reset _current_nowplaying to the input-label default
        (with the bundled placeholder logo as its artwork, decided
        explicitly rather than left as None) and publish it immediately, so
        the receiver drops the just-finished track's title/cover and shows
        "<input label> / autostream" + the autostream logo while
        re-identification runs -- the same look a session start gets from
        _reset_nowplaying_for_new_session() / autostream_session._session_nowplaying_start().
        When the pending identification lands, _ti_worker() compares its
        result against this now-reset _current_nowplaying: for a *different*
        track the comparison obviously differs; for the *same* track it
        still differs (this interstitial's placeholder artwork vs. the
        identified cover), so either way _ti_worker() publishes real
        metadata and the receiver's display "restores" on its own -- no
        special-casing needed for the same-track case. Callers are a
        monitor-reported gap event (track_change_seq advancing) and an
        accepted seek within a running replay; the periodic
        re-identification timer (_ti_worker() scheduling itself via
        _schedule_track_id_after()) never calls this, so a routine refresh
        of an already-identified track does not re-trigger the interstitial.
        """
        self._current_nowplaying = self._default_nowplaying_metadata()
        self._current_nowplaying = replace(
            self._current_nowplaying, artwork=_load_placeholder_artwork()
        )
        self._nowplaying_publisher.publish_refresh(self._current_nowplaying)

    def _default_nowplaying_metadata(self) -> "NowPlayingMetadata":
        """The now-playing metadata for this input with no identified track:
        a manual hint from nowplaying_hints.json if one applies, otherwise a
        receiver-friendly input label (Turntable / CD / Line) as the
        title -- the prominent line on the receiver -- with the constant
        "autostream" as the artist beneath it, rather than leaking the raw
        ALSA device string. Re-read each call (not cached) so a manual-hints
        file edit is picked up at the next session start."""
        return self._nowplaying_cache.get_manual_hint(self.input_device) or NowPlayingMetadata(
            title=_default_nowplaying_title(self.input_type),
            artist="autostream",
            album="Unknown Album",
        )

    def _reset_nowplaying_for_new_session(self) -> None:
        """Called at the start of each new play session (session_started /
        source_changed dispatch, via autostream_session._session_nowplaying_start()) to drop
        any title/artist/artwork carried over from a previous session --
        otherwise a stale cover from whatever was last playing could flash
        up before this session's own track ID (if any) lands. Within a
        session, a detected track boundary resets metadata the same way
        (see _on_possible_track_change() above, and _ti_worker() below for
        where a completed identification then replaces it)."""
        self._current_nowplaying = self._default_nowplaying_metadata()

    def apply_allow_capture(self, client: "monitor_client.MonitorClient") -> None:
        """Send set_allow_capture to the daemon if the value has changed."""
        if self._allow_capture != self._allow_capture_sent:
            if client.set_allow_capture(self.input_index, self._allow_capture):
                self._allow_capture_sent = self._allow_capture

    def stop(self) -> None:
        """Release resources (call at shutdown)."""
        self._tracker_playback_active = False
        self._tracker_wear_active = False
        try:
            # Release this monitor's reference to the shared publisher
            # rather than closing it directly: another
            # AudioMonitor on the same fifo_path may still be using it. The
            # registry only actually closes the underlying thread once the
            # last referencing monitor has released it.
            release_shared_metadata_publisher(self.fifo_path)
        except Exception:
            pass

    def _sync_playback_tracker_state(self, repeat_status: Optional[dict] = None) -> None:
        """Keep playback-hour tracking aligned to activity, split by purpose.

        total_playback_seconds accrues for all audible playback, including
        repeat-buffer replay: *repeat_status* is the same-poll top-level
        "repeat" block, and while repeat.replay.active, the origin input's
        recording is audibly playing even though that input itself is not
        capturing, so total hours keep accruing against
        repeat.recording.origin_input. Stylus/belt/bearing wear counters
        accrue only for real input capture -- capturing and not silent --
        since replay is buffered audio with no corresponding physical wear
        on the source turntable. Track-ID/now-playing metadata are
        unaffected here -- they keep flowing from the daemon's replay-path
        track-change events independently.
        """
        tracker = runtime._playback_tracker
        if tracker is None:
            self._tracker_playback_active = False
            self._tracker_wear_active = False
            return

        replaying_this_input = False
        if isinstance(repeat_status, dict):
            replay = repeat_status.get("replay")
            if isinstance(replay, dict) and bool(replay.get("active")):
                recording = repeat_status.get("recording")
                origin_input = recording.get("origin_input") if isinstance(recording, dict) else None
                replaying_this_input = origin_input == self.input_index

        wear_active = self.is_capturing and not self.is_silent
        playback_active = wear_active or replaying_this_input

        if playback_active != self._tracker_playback_active:
            if playback_active:
                tracker.on_playback_started(self.input_index)
            else:
                tracker.on_playback_stopped(self.input_index)
            self._tracker_playback_active = playback_active

        if wear_active != self._tracker_wear_active:
            if wear_active:
                tracker.on_wear_started(self.input_index)
            else:
                tracker.on_wear_stopped(self.input_index)
            self._tracker_wear_active = wear_active

    # ── Capture transitions ──────────────────────────────────────────────────

    def _on_capture_started(self) -> None:
        """Called when the daemon transitions this channel to capturing.

        Per-input duties only: track-ID scheduling and logging.
        Session-level duties -- OwnTone output-enable/default-volume and
        now-playing publish_start -- are not fired unconditionally on
        every capture-start transition, since a replay-sourced session start
        never transitions any input to capturing at all. They run from the
        coordinator's autostream_session.SessionTracker session_started event via
        autostream_session._start_session_owntone() / autostream_session._session_nowplaying_start(), see the poll
        loop in run_autostream().

        A settling-noise transient on the replay-origin input can flip
        capturing true then false during its own replay (allowed since the
        monitor probation commit). self._replay_origin is refreshed for
        this same tick by _ingest_status() before this callback runs, so
        when it is true this is that transient, not a real capture start:
        the replay identification cycle (already armed by
        _arm_track_identification_for_session()) must be left alone rather
        than reset out from under it. Mirrors _on_capture_stopped()'s guard.
        """
        if self._replay_origin:
            logging.debug(
                "Input %d (%s): own recording is replaying; capture-start "
                "transient ignored, identification preserved.",
                self.input_index, self.input_device,
            )
            return

        with self._ti_locked():
            self._ti_generation += 1  # invalidate any worker queued before capture started
            self._ti_inflight = False
            self._ti_inflight_token = None
            self._ti_next_attempt = 0.0
            self._ti_next_attempt_reason = ""
            self._ti_last_identified_at = 0.0
            if runtime._track_id_service is not None:
                svc = runtime._track_id_service
                delay = svc.analysis_lead_in_seconds + svc.snapshot_seconds
                self._schedule_track_id_after(time.time(), delay, "initial")
                logging.debug(
                    "track_id[%d]: initial attempt scheduled in %.0fs (lead-in=%.0fs window=%.0fs).",
                    self.input_index, delay, svc.analysis_lead_in_seconds, svc.snapshot_seconds,
                )
                from track_id.models import waiting_snapshot
                self._set_ti_snapshot(waiting_snapshot(
                    next_attempt_at=self._ti_next_attempt,
                    next_attempt_reason=self._ti_next_attempt_reason,
                ))
            else:
                from track_id.models import disabled_snapshot
                self._set_ti_snapshot(disabled_snapshot())

        logging.info(
            "Input %d (%s): capture started.",
            self.input_index, self.input_device,
        )

    def _arm_track_identification_for_session(self) -> None:
        """Arm the identification cycle for this monitor's new session source.

        Mirrors _on_capture_started()'s track-ID setup (reset generation,
        invalidate in-flight state, schedule the initial attempt), but is
        invoked directly by autostream_session.dispatch_session_event() for a session_started
        or source_changed event landing on this monitor -- for a
        replay-sourced source ("replay") as well as a live one
        ("input1"/"input2"). Generalized from a replay-only arm (see history)
        because a live source can also reach a session_started/source_changed
        event without a fresh is_capturing 0->1 edge to arm from:

        - Replay case: is_capturing never transitions to True for the replay
          origin input (the origin input isn't capturing while its recording
          replays), so _on_capture_started would otherwise never fire and
          this input's identification cycle would stay parked at whatever
          state it was in before replay began: the daemon serves replay-tap
          snapshots under origin_input, so the Python side only needs to
          schedule attempts, not gate on is_capturing.

        - Live case (confirmed-live-interrupt of a replay): a probation
          transient can flip this input's is_capturing true while it is
          still the replay origin; _on_capture_started()'s replay-origin
          guard deliberately leaves the identification cycle alone for that
          edge (see its docstring) so the in-flight replay identification
          survives. If the transient turns into a genuine live takeover,
          the session source changes to this input with no further
          is_capturing edge to arm from (it was already True), so this
          session-arm call is the only place left to do it.

        Also baselines track_change_seq here, since _ingest_status()'s
        steady-state seq check requires actively-sourcing on BOTH sides of
        an ingest and so deliberately does not fire (and does not baseline)
        on the same cycle this transition is first observed.

        Takes _ti_state_lock, because the arm can also run on the API thread
        (on_replay_seek_accepted) and must not interleave with the
        coordinator's dispatch section.
        """
        with self._ti_locked():
            self._arm_identification_cycle_locked("initial")

        logging.info(
            "Input %d (%s): identification armed for session source.",
            self.input_index, self.input_device,
        )

    @contextlib.contextmanager
    def _ti_locked(self):
        """Hold _ti_state_lock. Changes made to the identification snapshot
        meanwhile are published to the track part under the lock, in order,
        and delivered to subscribers after it is released."""
        pending: list = []
        self._ti_state_lock.acquire()
        try:
            self._ti_lock_owner = threading.get_ident()
            try:
                yield
            finally:
                pending, self._ti_pending = self._ti_pending, []
                self._ti_lock_owner = None
        finally:
            self._ti_state_lock.release()
            for change in pending:
                change.notify()

    def _set_ti_snapshot(self, value) -> None:
        """Replace this input's identification snapshot and publish it as its
        entry in the track part. The caller holds _ti_state_lock through
        _ti_locked()."""
        assert self._ti_lock_owner == threading.get_ident(), (
            "_set_ti_snapshot outside _ti_locked()")
        self._ti_snapshot = value
        index = self.input_index
        self._ti_pending.append(_track_writer.update(lambda cur: replace(
            cur, entries=autostream_state.FrozenDict({**cur.entries, index: value}))))

    def _arm_identification_cycle_locked(self, reason: str) -> None:
        """Restart this monitor's identification cycle; caller holds _ti_state_lock.

        Baselines track_change_seq, bumps _ti_generation (a worker still in
        flight discards its result on the generation check), clears the
        in-flight state, schedules the first attempt one lead-in plus one
        snapshot window away and publishes a waiting (or disabled) snapshot.
        *reason* labels the scheduled attempt. Only a "seek" arm keeps a
        rate-limit or upstream-rejection deadline that lies further out than
        the new attempt: a provider backoff outranks a seek, whereas a new
        session source starts from a clean schedule.
        """
        self._track_change_seq_baseline = self.track_change_seq
        self._ti_generation += 1  # invalidate any worker queued before this cycle began
        self._ti_inflight = False
        self._ti_inflight_token = None
        if reason != "seek":
            self._ti_next_attempt = 0.0
            self._ti_next_attempt_reason = ""
        self._ti_last_identified_at = 0.0
        if runtime._track_id_service is not None:
            svc = runtime._track_id_service
            delay = svc.analysis_lead_in_seconds + svc.snapshot_seconds
            self._schedule_track_id_after(time.time(), delay, reason)
            logging.debug(
                "track_id[%d]: %s attempt scheduled in %.0fs (lead-in=%.0fs "
                "window=%.0fs).",
                self.input_index, reason, delay,
                svc.analysis_lead_in_seconds, svc.snapshot_seconds,
            )
            from track_id.models import waiting_snapshot
            self._set_ti_snapshot(waiting_snapshot(
                next_attempt_at=self._ti_next_attempt,
                next_attempt_reason=self._ti_next_attempt_reason,
            ))
        else:
            from track_id.models import disabled_snapshot
            self._ti_next_attempt = 0.0
            self._ti_next_attempt_reason = ""
            self._set_ti_snapshot(disabled_snapshot())

    def on_replay_seek_accepted(self, in_session: bool) -> None:
        """Re-arm identification after an accepted replay start or seek.

        Called on the API thread from apply_repeat_ack (autostream_repeat) for the replay origin
        monitor. A seek resets the daemon's reader and decoder but not its
        track_change_seq, so no gap event would ever tell the coordinator
        that the audio moved. *in_session* is True for a seek within a
        running replay: the receiver still shows the pre-seek track, so the
        interstitial is published now. It is False for a start from Hold:
        the coordinator's session_started publishes the session's now-playing
        on its next poll, and a refresh ahead of that session's start would be
        out of order. The later session_started arm repeats this one
        harmlessly (nothing can be in flight yet).
        """
        with self._ti_locked():
            self._arm_identification_cycle_locked("seek")
        if in_session:
            self._publish_interstitial_nowplaying()
        logging.info(
            "Input %d (%s): identification re-armed for a replay seek.",
            self.input_index, self.input_device,
        )

    def _on_capture_stopped(
        self,
        client: "monitor_client.MonitorClient",
    ) -> None:
        """Called when the daemon transitions this channel out of capturing.

        Per-input duties only: track-ID state invalidation and
        logging. Session-level duties -- the OwnTone idle-stop and
        now-playing publish_end -- are not fired here: the coordinator's
        autostream_session.SessionTracker source vector treats a capture-stop immediately
        followed by a replay-start as a source_changed event with no
        OwnTone-level capture-stop in between, so per-input teardown must
        stay silent on the session-level effects. The session-level stop
        runs from the tracker's session_ended event, see the poll loop in
        run_autostream().

        self._replay_origin is refreshed for this same tick by
        _ingest_status() before this callback runs, so when it is true this
        stop edge is one of two things, and either way the identification
        schedule must be left alone:

        - A settling-noise transient on the replay-origin input flipping
          capturing true then false during its own replay (allowed since
          the monitor probation commit): zeroing the identification
          schedule here would kill identification until the replay's own
          gap detector emits its next internal track boundary.

        - The ordinary armed-repeat handoff: repeat starts replay inside
          the same capture-stop tick, so an ordinary capture-end on the
          input that is about to become the replay origin also lands here
          with self._replay_origin already true. The session arm
          (_arm_track_identification_for_session(), via
          autostream_session.dispatch_session_event()) re-arms this input's identification
          cycle for the new replay source later in this same tick, so
          tearing it down here would just be redone -- and would race the
          re-arm if worker teardown timing ever shifted.

        Mirrors _on_capture_started()'s guard. The usual INFO capture-stopped
        line below is still emitted in both cases: OwnTone capture did stop,
        which is worth logging regardless of what happens to identification.
        """
        logging.info(
            "Input %d (%s): capture stopped.",
            self.input_index, self.input_device,
        )

        if self._replay_origin:
            logging.debug(
                "Input %d (%s): own recording is replaying; leaving "
                "identification to the session arm.",
                self.input_index, self.input_device,
            )
            return

        # Invalidate any running worker and clear scheduled deadlines so a
        # worker that completes after capture stops cannot overwrite the
        # waiting/disabled snapshot below or leave a stale _ti_next_attempt.
        # Under the state lock so a worker keeping a held track after a failed
        # re-check cannot publish it over this reset.
        with self._ti_locked():
            self._ti_generation += 1
            self._ti_next_attempt = 0.0
            self._ti_next_attempt_reason = ""
            self._track_change_seq_baseline = 0

            if runtime._track_id_service is not None:
                from track_id.models import waiting_snapshot
                self._set_ti_snapshot(waiting_snapshot())
            else:
                from track_id.models import disabled_snapshot
                self._set_ti_snapshot(disabled_snapshot())

    def _teardown_identification_after_replay(self) -> None:
        """Drop this monitor's identification state once its replay has ended.

        Called on the coordinator thread from
        autostream_session.teardown_identification_after_replay_end() when the session's
        previous source was "replay" and that source has gone
        (session_ended) or moved to a different monitor (source_changed).
        A replay end produces no capturing edge, so _on_capture_stopped()
        never runs for it; without this the origin monitor would carry its
        last identified snapshot through Hold and let a worker that finishes
        after the end land a match on an idle input.

        Same effect as _on_capture_stopped()'s live teardown (generation
        bump so a late worker result is discarded, deadlines and baseline
        zeroed, waiting/disabled snapshot), plus clearing the in-flight
        fields so the next arm starts clean. A rate-limit or
        upstream-rejection deadline is dropped with the rest, as on a live
        capture stop; the next session arm starts from a clean schedule
        either way. Takes _ti_state_lock. Idempotent: a second call only
        bumps the generation again.
        """
        with self._ti_locked():
            self._ti_generation += 1
            self._ti_inflight = False
            self._ti_inflight_token = None
            self._ti_next_attempt = 0.0
            self._ti_next_attempt_reason = ""
            self._ti_last_identified_at = 0.0
            self._track_change_seq_baseline = 0
            if runtime._track_id_service is not None:
                from track_id.models import waiting_snapshot
                self._set_ti_snapshot(waiting_snapshot())
            else:
                from track_id.models import disabled_snapshot
                self._set_ti_snapshot(disabled_snapshot())

        logging.debug(
            "Input %d (%s): identification torn down after replay.",
            self.input_index, self.input_device,
        )

    # ── Track identification ──────────────────────────────────────────────────

    def _apply_track_id_service(self, service) -> None:
        """Set the initial snapshot based on whether the service is available."""
        with self._ti_locked():
            self._ti_generation += 1  # invalidate any in-flight worker for the old service
            if service is not None:
                from track_id.models import waiting_snapshot
                # Schedule first attempt if actively sourcing (capturing, or
                # the replay-origin input of a currently replaying
                # recording); otherwise wait for capture-start / session-arm.
                # Without the replay-origin half of this check, changing the
                # track-ID setting mid-replay would park the schedule at 0.0
                # with nothing left to un-park it until replay ends.
                if self.is_capturing or self._replay_origin:
                    delay = service.analysis_lead_in_seconds + service.snapshot_seconds
                    self._schedule_track_id_after(time.time(), delay, "initial")
                else:
                    self._ti_next_attempt = 0.0
                    self._ti_next_attempt_reason = ""
                self._set_ti_snapshot(waiting_snapshot(
                    next_attempt_at=(self._ti_next_attempt or None),
                    next_attempt_reason=self._ti_next_attempt_reason,
                ))
            else:
                from track_id.models import disabled_snapshot
                self._set_ti_snapshot(disabled_snapshot())
                self._ti_next_attempt = 0.0
                self._ti_next_attempt_reason = ""
            self._ti_inflight = False
            self._ti_inflight_token = None
            self._ti_last_identified_at = 0.0

    def _schedule_track_id_attempt(self, when: float, reason: str) -> None:
        """Set the next attempt deadline to `when`, preserving any later protected deadline."""
        from autostream_config import (
            TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS,
            TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS,
        )
        protected_reasons = {"rate_limit", "upstream_rejection"}
        if (self._ti_next_attempt_reason in protected_reasons
                and self._ti_next_attempt > when):
            return
        self._ti_next_attempt = max(when, time.time() + 1.0)
        self._ti_next_attempt_reason = reason

    def _schedule_track_id_after(self, now: float, delay: float, reason: str) -> None:
        """Set the next attempt deadline to `now + delay`."""
        self._schedule_track_id_attempt(now + delay, reason)

    def maybe_trigger_track_identification(
        self, client: "monitor_client.MonitorClient", now: float, replay_origin: bool = False,
    ) -> None:
        """Dispatch an identification worker if the deadline has elapsed and conditions allow.

        *replay_origin* is this poll cycle's replay_origin_input() result
        compared against self.input_index: an input replaying
        its own recording is "actively sourcing" the session even though
        is_capturing is False, and the daemon already serves replay-tap
        snapshots for it under origin_input, so
        identification must run for it too. The is_silent check only applies
        to live capture -- a replay-sourced input is silent by definition
        (it isn't capturing anything), so gating on it here would make
        replay-sourced identification permanently dead.

        Self-heal: if this input is actively sourcing with the service
        enabled and nothing in flight, but _ti_next_attempt is still the
        0.0 sentinel (never armed, or a prior arming path was missed or
        raced), schedule an initial attempt here rather than staying
        parked forever. This bounds any such stall to one poll cycle plus
        the normal initial-attempt delay.
        """
        svc = runtime._track_id_service
        if svc is None:
            return
        actively_sourcing = self.is_capturing or replay_origin
        if not actively_sourcing:
            return
        if self.is_capturing and self.is_silent:
            return
        if self._ti_inflight:
            return
        if self._ti_next_attempt == 0.0:
            delay = svc.analysis_lead_in_seconds + svc.snapshot_seconds
            self._schedule_track_id_after(now, delay, "initial")
            logging.debug(
                "track_id[%d]: self-heal: schedule was parked at 0.0 while "
                "actively sourcing; initial attempt scheduled in %.0fs.",
                self.input_index, delay,
            )
            return
        if now < self._ti_next_attempt:
            return

        # Attempt non-blocking acquisition of the process-wide admission gate.
        if not runtime._track_id_request_gate.acquire(blocking=False):
            # Another input is active; retry after 1 s without disturbing the reason.
            self._ti_next_attempt = now + 1.0
            return

        # Gate acquired.  Recheck critical preconditions after acquiring.
        if not actively_sourcing or runtime._track_id_service is not svc:
            runtime._track_id_request_gate.release()
            return

        # Capture generation before the blocking snapshot call so any live
        # reconfiguration that bumps the generation during get_id_snapshot() is
        # detected by the recheck below.
        dispatch_gen = self._ti_generation

        snapshot = client.get_id_snapshot(self.input_index, max_seconds=svc.snapshot_seconds)

        # _ti_state_lock makes the post-snapshot recheck and all state mutations
        # atomic with respect to _apply_track_id_service(), which also holds this
        # lock.  Without it a concurrent live reconfiguration could publish a
        # disabled snapshot between our validation and our STATE_ANALYSING write,
        # leaving the UI stuck in analysing with no future attempt to clear it.
        with self._ti_locked():
            # Recheck generation and service immediately after the blocking
            # snapshot call, before interpreting its result.
            if self._ti_generation != dispatch_gen or runtime._track_id_service is not svc:
                logging.debug(
                    "track_id[%d]: generation or service changed during snapshot; aborting dispatch.",
                    self.input_index,
                )
                runtime._track_id_request_gate.release()
                return

            if snapshot is None or not snapshot[0]:
                logging.debug(
                    "track_id[%d]: get_id_snapshot returned no audio; retry in %.0fs.",
                    self.input_index, svc.retry_seconds,
                )
                runtime._track_id_request_gate.release()
                self._schedule_track_id_after(now, svc.retry_seconds, "no_match")
                return
            pcm_bytes, rate = snapshot

            duration_s = len(pcm_bytes) / (rate * 2)
            logging.debug(
                "track_id[%d]: snapshot returned %d bytes (%.1f s, requested=%d s).",
                self.input_index, len(pcm_bytes), duration_s, svc.snapshot_seconds,
            )
            from track_id.service import MIN_PCM_DURATION_SECONDS
            if duration_s < MIN_PCM_DURATION_SECONDS:
                logging.debug(
                    "track_id[%d]: snapshot too short (%.1f s); retry in %.0fs.",
                    self.input_index, duration_s, svc.retry_seconds,
                )
                runtime._track_id_request_gate.release()
                self._schedule_track_id_after(now, svc.retry_seconds, "no_match")
                return

            logging.info(
                "track_id[%d]: queuing identification (%.1f s of audio, reason=%s).",
                self.input_index, duration_s, self._ti_next_attempt_reason,
            )

            from track_id.models import (
                STATE_ANALYSING, STATE_IDENTIFIED, state_status_text,
                TrackIdentificationSnapshot,
            )
            # A snapshot still identified here means this is the periodic
            # re-check of a track that is playing: a track change, a new
            # session and a seek all replace the snapshot with a waiting one
            # first. Keep publishing the identified track while the attempt
            # runs (the in-flight flag stops a second attempt), so a dial, the
            # Home page or a receiver reading it never loses the title and
            # cover; the worker publishes the outcome. Any other attempt
            # shows the analysing state.
            held = self._ti_snapshot if self._ti_snapshot.state == STATE_IDENTIFIED else None
            if held is not None:
                # No attempt is scheduled while one is in flight.
                self._set_ti_snapshot(replace(
                    held, next_attempt_at=None, next_attempt_reason="",
                ))
            else:
                self._set_ti_snapshot(TrackIdentificationSnapshot(
                    enabled=True,
                    state=STATE_ANALYSING,
                    status_text=state_status_text(STATE_ANALYSING),
                    input_index=self.input_index,
                    provider=svc.provider_id,
                    updated_at=now,
                    last_attempt_at=now,
                ))
            worker_token = object()
            self._ti_inflight = True
            self._ti_inflight_token = worker_token
            self._ti_last_attempt = now

            # Scheduled on the process-wide task pool under a per-input
            # single-flight key -- same worker function, same args, just
            # scheduled via runtime._task_pool.submit() instead of a raw
            # threading.Thread(...).start(). The
            # process-wide runtime._track_id_request_gate above is still the true
            # admission control (at most one identification in flight across
            # all inputs); this per-input key is a second, redundant guard
            # that should never actually reject a submission in practice.
            # _ti_worker's own completion contract (release the gate, clear
            # _ti_inflight/_ti_inflight_token in its `finally`) is untouched.
            submitted = False
            try:
                submitted = runtime._task_pool.submit(
                    f"track-id-{self.input_index}",
                    self._ti_worker,
                    bytes(pcm_bytes), rate, worker_token, dispatch_gen, held,
                )
            except Exception:
                logging.warning(
                    "track_id[%d]: task pool submit() raised; releasing gate.",
                    self.input_index, exc_info=True,
                )
            else:
                if not submitted:
                    logging.warning(
                        "track_id[%d]: task pool submit() rejected (already in "
                        "flight for this input); releasing gate.",
                        self.input_index,
                    )
            if not submitted:
                runtime._track_id_request_gate.release()
                if self._ti_inflight_token is worker_token:
                    self._ti_inflight = False
                    self._ti_inflight_token = None

    def _keep_held_track(
        self, held, my_gen: int, worker_token: object, now: float,
    ) -> None:
        """Publish the held identified track again after a re-check that found
        nothing or failed, pointing its attempt fields at the retry just
        scheduled. The generation and token are checked again under the state
        lock, which a track change, a new session and a reconfiguration also
        take, so a superseded attempt never puts the old track back over the
        newer snapshot."""
        with self._ti_locked():
            if self._ti_generation != my_gen or self._ti_inflight_token is not worker_token:
                return
            self._set_ti_snapshot(replace(
                held,
                last_attempt_at=now,
                next_attempt_at=self._ti_next_attempt,
                next_attempt_reason=self._ti_next_attempt_reason,
            ))

    def _ti_worker(
        self, pcm16_mono: bytes, sample_rate: int, worker_token: object, dispatch_gen: int,
        held=None,
    ) -> None:
        """Run identification in the background and schedule the next attempt.

        *held* is the identified snapshot that was being published when this
        attempt was dispatched (a periodic re-check of a playing track), or
        None. A failed or empty attempt keeps publishing it rather than
        replacing it with a not-found or error state; a matching result
        replaces it as usual.
        """
        from track_id.models import (
            TrackIDProviderUnreachableError,
            TrackIDRateLimitedError,
            TrackIDUpstreamRejectionError,
            STATE_ERROR, STATE_IDENTIFIED, STATE_NOT_FOUND,
            state_status_text,
            TrackIdentificationSnapshot,
        )
        from autostream_config import (
            TRACK_ID_ERROR_RETRY_SECONDS,
            TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS,
            TRACK_ID_REFRESH_JITTER_SECONDS,
            TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS,
        )
        my_gen = dispatch_gen
        try:
            svc = runtime._track_id_service
            if svc is None:
                return

            result = svc.identify(pcm16_mono, sample_rate, input_index=self.input_index)
            now = time.time()

            if self._ti_generation != my_gen or self._ti_inflight_token is not worker_token:
                logging.info(
                    "track_id[%d]: match discarded: stale generation/service.",
                    self.input_index,
                )
                return  # stale: service replaced or capture restarted while we ran

            if result.matched:
                jitter = random.uniform(-TRACK_ID_REFRESH_JITTER_SECONDS, TRACK_ID_REFRESH_JITTER_SECONDS)
                delay = max(1.0, svc.refresh_seconds + jitter)
                self._schedule_track_id_after(now, delay, "match")
                logging.debug(
                    "track_id[%d]: identified; refresh scheduled in %.0fs (base=%.0fs jitter=%+.0fs).",
                    self.input_index, delay, svc.refresh_seconds, jitter,
                )
                self._ti_last_identified_at = now
                if result.title or result.artist:
                    # Fall back to the previous artwork rather than the hint's
                    # badge: an identified track with the wrong cover is worse
                    # than an identified track with the cover we already had.
                    # If there is no previous artwork either, the publisher's
                    # own HOLD-UNTIL-NEW fallback (see
                    # OwntoneMetadataPipePublisher._resolve_refresh_artwork())
                    # re-emits whatever it last sent for this session
                    # (placeholder or real), so the receiver never sees a
                    # bundle with no picture at all.
                    artwork_url = result.artwork.url if result.artwork else ""
                    artwork = (
                        self._artwork_cache.get(artwork_url)
                        or self._current_nowplaying.artwork
                    )
                    new_meta = NowPlayingMetadata(
                        title=result.title or self._current_nowplaying.title,
                        artist=result.artist or self._current_nowplaying.artist,
                        album=result.album or self._current_nowplaying.album,
                        artwork=artwork,
                    )
                    if new_meta != self._current_nowplaying:
                        self._current_nowplaying = new_meta
                        # publish_refresh(), not publish_start(): this fires
                        # mid-session (track-ID match landing after the
                        # session's pbeg already went out), so it must not
                        # emit a second pbeg.
                        self._nowplaying_publisher.publish_refresh(new_meta)
                with self._ti_locked():
                    self._set_ti_snapshot(TrackIdentificationSnapshot(
                        enabled=True,
                        state=STATE_IDENTIFIED,
                        status_text=state_status_text(STATE_IDENTIFIED),
                        input_index=self.input_index,
                        provider=result.provider or svc.provider_id,
                        title=result.title,
                        artist=result.artist,
                        album=result.album,
                        artwork_url=(result.artwork.url if result.artwork else ""),
                        confidence=result.confidence,
                        updated_at=now,
                        last_attempt_at=now,
                        next_attempt_at=self._ti_next_attempt,
                        next_attempt_reason=self._ti_next_attempt_reason,
                    ))
            elif result.is_configuration_error:
                self._schedule_track_id_after(now, TRACK_ID_ERROR_RETRY_SECONDS, "error")
                logging.debug(
                    "track_id[%d]: configuration error; retry scheduled in %.0fs.",
                    self.input_index, TRACK_ID_ERROR_RETRY_SECONDS,
                )
                if held is not None:
                    self._keep_held_track(held, my_gen, worker_token, now)
                else:
                    with self._ti_locked():
                        self._set_ti_snapshot(TrackIdentificationSnapshot(
                            enabled=True,
                            state=STATE_ERROR,
                            status_text=state_status_text(STATE_ERROR),
                            input_index=self.input_index,
                            provider=svc.provider_id,
                            updated_at=now,
                            last_attempt_at=now,
                            next_attempt_at=self._ti_next_attempt,
                            next_attempt_reason=self._ti_next_attempt_reason,
                        ))
            else:
                self._schedule_track_id_after(now, svc.retry_seconds, "no_match")
                logging.debug(
                    "track_id[%d]: no match; retry scheduled in %.0fs.",
                    self.input_index, svc.retry_seconds,
                )
                if held is not None:
                    self._keep_held_track(held, my_gen, worker_token, now)
                else:
                    with self._ti_locked():
                        self._set_ti_snapshot(TrackIdentificationSnapshot(
                            enabled=True,
                            state=STATE_NOT_FOUND,
                            status_text=state_status_text(STATE_NOT_FOUND),
                            input_index=self.input_index,
                            provider=svc.provider_id,
                            updated_at=now,
                            last_attempt_at=now,
                            next_attempt_at=self._ti_next_attempt,
                            next_attempt_reason=self._ti_next_attempt_reason,
                        ))

        except Exception as exc:
            now = time.time()
            if self._ti_generation != my_gen or self._ti_inflight_token is not worker_token:
                logging.info(
                    "track_id[%d]: match discarded: stale generation/service.",
                    self.input_index,
                )
                return  # stale
            if isinstance(exc, TrackIDUpstreamRejectionError):
                logging.warning(
                    "track_id[%d]: upstream rejected request (http_status=%d); backing off %ds",
                    self.input_index, exc.http_status, TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS,
                )
                self._schedule_track_id_after(now, TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS, "upstream_rejection")
            elif isinstance(exc, TrackIDRateLimitedError):
                # Honor a provider-supplied Retry-After-equivalent value
                # when present and positive; otherwise fall back to the
                # fixed constant.
                retry_after = getattr(exc, "retry_after_seconds", None)
                if isinstance(retry_after, (int, float)) and retry_after > 0:
                    backoff = float(retry_after)
                    logging.warning(
                        "track_id[%d]: rate limited; backing off %.0fs (provider Retry-After)",
                        self.input_index, backoff,
                    )
                else:
                    backoff = TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS
                    logging.warning(
                        "track_id[%d]: rate limited; backing off %ds",
                        self.input_index, backoff,
                    )
                self._schedule_track_id_after(now, backoff, "rate_limit")
            elif isinstance(exc, TrackIDProviderUnreachableError):
                # "Provider unreachable" (network/DNS/timeout) shares the
                # rate-limit backoff bucket rather than the generic
                # config-error one: a flaky network should not be retried
                # more aggressively than an explicit rate limit.
                logging.warning(
                    "track_id[%d]: provider unreachable; backing off %ds",
                    self.input_index, TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS,
                )
                self._schedule_track_id_after(now, TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS, "provider_unreachable")
            else:
                logging.warning(
                    "track_id[%d]: worker error: %s; retry in %.0fs.",
                    self.input_index, type(exc).__name__, TRACK_ID_ERROR_RETRY_SECONDS,
                )
                self._schedule_track_id_after(now, TRACK_ID_ERROR_RETRY_SECONDS, "error")
            if held is not None:
                self._keep_held_track(held, my_gen, worker_token, now)
            else:
                with self._ti_locked():
                    self._set_ti_snapshot(TrackIdentificationSnapshot(
                        enabled=True,
                        state=STATE_ERROR,
                        status_text=state_status_text(STATE_ERROR),
                        input_index=self.input_index,
                        provider=(runtime._track_id_service.provider_id if runtime._track_id_service else ""),
                        updated_at=now,
                        last_attempt_at=now,
                        error=type(exc).__name__,
                        next_attempt_at=self._ti_next_attempt,
                        next_attempt_reason=self._ti_next_attempt_reason,
                    ))

        finally:
            runtime._track_id_request_gate.release()
            if self._ti_inflight_token is worker_token:
                self._ti_inflight = False
                self._ti_inflight_token = None

    # ── OwnTone helpers ──────────────────────────────────────────────────────

    def _maybe_retry_owntone(
        self, now: float, replay_origin: bool = False, monitor_status: Optional[dict] = None,
    ) -> None:
        """Periodically retry refreshing currently selected OwnTone outputs.

        Thin delegate onto selfheal.SelfHeal.maybe_retry_owntone(): the substantive
        logic lives there, grouped with the other two self-heal mechanisms.
        Kept as a bound method under its original
        name so every existing call site (m._maybe_retry_owntone(...),
        patch.object(mon, "_maybe_retry_owntone")) keeps working unchanged.
        See selfheal.SelfHeal.maybe_retry_owntone()'s docstring for the full
        *replay_origin* / *monitor_status* contract.
        """
        selfheal.SelfHeal.maybe_retry_owntone(
            self, now, replay_origin=replay_origin, monitor_status=monitor_status,
        )

    def _throttled_owntone_log(self, now: float, level: int, msg: str, *args) -> None:
        """Log OwnTone-related failures with a long throttle to avoid SD churn.

        Each message has its own timer per input, so one failure repeating
        does not hide a different one."""
        if log_setup.log_every(
            ("owntone", self.input_index, msg),
            self.OWNTONE_LOG_THROTTLE_SECONDS,
            now=now,
        ):
            logging.log(level, msg, *args)

    def _log_default_output_refusal(self, now: float, default_name: str, reply) -> None:
        """The throttled line for a default-output select that was not made."""
        error = reply.error
        if error == "no_default":
            self._throttled_owntone_log(
                now, logging.WARNING,
                "No default output configured; cannot apply zero-target fallback.",
            )
        elif error == "not_found":
            self._throttled_owntone_log(
                now, logging.WARNING,
                "Default output '%s' not found in OwnTone; cannot apply fallback.", default_name,
            )
        elif error == "pin_pending":
            self._throttled_owntone_log(
                now, logging.INFO,
                "Default output '%s' is waiting for a PIN; not auto-enabling it.", default_name,
            )
        elif error == "in_use":
            self._throttled_owntone_log(
                now, logging.INFO,
                "Default output '%s' is in use by %s; skipping auto-select.",
                default_name, (reply.result or {}).get("owner", "another appliance"),
            )
        elif error == "pin_required":
            self._throttled_owntone_log(
                now, logging.INFO,
                "Default output '%s' requires a PIN; enable it via the web interface.", default_name,
            )
        else:
            self._throttled_owntone_log(
                now, logging.WARNING,
                "Failed to apply default output settings for '%s': %s",
                default_name, (reply.result or {}).get("message") or error,
            )
