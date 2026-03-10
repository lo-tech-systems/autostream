#!/usr/bin/env python3
"""autostream_core.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

This script is the engine behind autostream, capturing input and routing to targets
via OwnTone. It can be used standalone but is usually called by autostream_webui.py.

This script:

- Monitors one or two audio input devices for activity.

- When audio exceeds a configured raw sample threshold, it:

  * Starts an `ffmpeg` process, fed with RAW PCM from this script via stdin,
    writing to a FIFO pipe.

  * Reuses the currently selected OwnTone outputs so routing follows UI choices.

- When input has been below the threshold for a configured number of seconds, it:

  * Stops the `ffmpeg` process.

- Owntone must be configured to watch the pipe, and with auto playback enabled.
"""

import configparser
import errno
import logging
import math
import os
import select
import subprocess
import sys
import time
import signal
from typing import Optional
import threading
from dataclasses import dataclass
import requests
import numpy as np
import sounddevice as sd

from autostream_config import load_and_parse
from autostream_nowplaying import (
    NowPlayingMetadata,
    OwntoneMetadataPipePublisher,
    PersistentNowPlayingCache,
)
try:
    from autostream_nowplaying import VinylRecognizer
except ImportError:  # Optional recognizer; core should run without it.
    VinylRecognizer = None  # type: ignore[assignment]

from autostream_owntone import (
    owntone_disable_all_outputs,
    owntone_config_ok,
    owntone_restart_service,
    owntone_ensure_pipe_indexed,
    OWNTONE_OK,
    OWNTONE_RESTART_REQUIRED,
    OWNTONE_NOT_OK,
)

''' Process termination control '''
stop_flag = threading.Event()

# Track all AudioMonitor instances so we can see if any is capturing.
all_monitors = []

def any_monitor_capturing() -> bool:
    """Return True if any AudioMonitor currently has an active capture."""
    return any(getattr(m, 'is_capturing', False) for m in all_monitors)


def _sample_to_dbfs(sample: int, floor_dbfs: float = -90.0) -> float:
    """Convert a 16-bit average sample value (0..32767) to dBFS."""
    if sample <= 0:
        return floor_dbfs
    ratio = min(1.0, max(0.0, float(sample) / 32767.0))
    return max(floor_dbfs, 20.0 * math.log10(ratio))


def get_monitor_levels_dbfs() -> list[dict]:
    """Return current level data for each active monitor for the Web UI."""
    levels: list[dict] = []
    for idx, mon in enumerate(list(all_monitors), start=1):
        sample = int(getattr(mon, "current_level_sample", 0) or 0)
        threshold_sample = int(getattr(mon, "silence_threshold_sample", 1) or 1)
        dbfs = _sample_to_dbfs(sample)
        levels.append({
            "label": f"In{idx}",
            "dbfs": round(dbfs, 1),
            "is_above_threshold": sample >= threshold_sample,
        })
    return levels

def handle_signal(signum, frame):
    stop_flag.set()


signal.signal(signal.SIGINT, handle_signal)   # Ctrl+C
signal.signal(signal.SIGTERM, handle_signal)  # terminate()


def setup_logging(log_file: str) -> None:
    """
    Configure logging.

    If `log_file` has no directory component (e.g. "autostream.log"),
    log in the current working directory without trying to create "".
    """
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s: %(message)s",
        datefmt="%d-%b-%y %H:%M:%S",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout),
        ],
    )


def ensure_fifo(path: str) -> None:
    """Create a FIFO at `path` if it does not exist."""
    fifo_dir = os.path.dirname(path)
    if fifo_dir:
        os.makedirs(fifo_dir, exist_ok=True)

    if os.path.exists(path):
        if stat_is_fifo(path):
            return
        else:
            logging.warning("Path %s exists but is not a FIFO. Playback will fail.", path)
            return
    logging.warning("Path %s not found; creating FIFO...", path)
    os.mkfifo(path)


def stat_is_fifo(path: str) -> bool:
    import stat

    st = os.stat(path)
    return stat.S_ISFIFO(st.st_mode)


def start_ffmpeg(
    fifo_path: str,
    ffmpeg_in_rate: int,
    ffmpeg_out_rate: int,
) -> subprocess.Popen:
    """Start ffmpeg to consume raw PCM from stdin and write to the FIFO.
    This replaces the usual arecord+ffmpeg pipeline. The AudioMonitor
    will feed raw int16 PCM data into ffmpeg's stdin.
    """
    ensure_fifo(fifo_path)

    # We do:
    #   (this script) -> raw PCM (stdin) -> ffmpeg -> FIFO
    # Always use ffmpeg to asyncronously resample, to mask clock drift in the source
    ffmpeg_cmd = [
        "ffmpeg",
        "-hide_banner",
        "-loglevel",
        "error",
        "-y",
        "-f",
        "s16le",
        "-ac",
        "2",
        "-ar",
        str(ffmpeg_in_rate),
        "-i",
        "pipe:0",
        "-af",
        "aresample=async=1:first_pts=0",
        "-f",
        "s16le",
        "-ac",
        "2",
        "-ar",
        str(ffmpeg_out_rate),
        fifo_path,
    ]

    logging.info(
        "Starting ffmpeg (%s) fed from monitor stdin",
        " ".join(ffmpeg_cmd),
    )

    ffmpeg_proc = subprocess.Popen(
        ffmpeg_cmd,
        stdin=subprocess.PIPE,
        stderr=None,
    )

    # Non-blocking stdin lets us detect downstream backpressure and recover
    # instead of potentially stalling the monitor loop forever on write().
    try:
        if ffmpeg_proc.stdin:
            os.set_blocking(ffmpeg_proc.stdin.fileno(), False)
    except Exception as e:
        logging.warning("Could not set ffmpeg stdin non-blocking: %s", e)

    return ffmpeg_proc


def stop_ffmpeg(proc: subprocess.Popen) -> None:
    """Gracefully stop ffmpeg."""
    if proc is None:
        return

    # Close stdin so ffmpeg can flush and exit cleanly
    try:
        if proc.stdin:
            proc.stdin.close()
    except Exception as e:  # noqa: BLE001
        logging.error("Error closing ffmpeg stdin: %s", e)

    try:
        if proc.poll() is None:
            logging.info("Terminating ffmpeg process PID %s", proc.pid)
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logging.warning("ffmpeg process PID %s did not exit, killing", proc.pid)
                proc.kill()
    except Exception as e:  # noqa: BLE001
        logging.error("Error stopping ffmpeg process: %s", e)


def dbfs_to_sample_threshold(dbfs: float, full_scale: int = 32767) -> int:
    """Convert a dBFS value to a 16-bit sample amplitude threshold.

    ``dbfs`` is expected to be <= 0.0 (0 dBFS is full scale). The returned
    value is clamped to the range 1..full_scale.
    """
    dbfs = min(dbfs, 0.0)
    threshold = full_scale * (10.0 ** (dbfs / 20.0))
    return max(1, min(full_scale, int(threshold)))


class AudioMonitor:
    """Monitors an audio input device for activity and controls ffmpeg/Owntone.

    Audio activity detection is done on raw 16-bit PCM samples:
    - User config specifies a silence threshold in dBFS.
    - At startup we convert that to a 16-bit sample amplitude threshold.
    - In the monitor loop we read short blocks from the input device, compute the
      average absolute sample value, and compare it directly to that threshold.

    The most recent average absolute sample value (0..32767) is exposed as the
    attribute ``current_level_sample`` so that other code in the same process
    can inspect it. This enables display of average value in the associated web-UI.

    When the stream is considered "active", the same raw PCM blocks are written
    into an ffmpeg process stdin, which performs resampling and writes to the
    configured FIFO pipe watched by Owntone.

    When multiple AudioMonitor instances are used in the same process, an
    external coordinator can control which one is allowed to own the ffmpeg
    pipeline by toggling ``allow_capture``. In single-input setups this flag
    defaults to True so behaviour is unchanged.
    """

    def __init__(
        self,
        input_device: str,
        silence_threshold_dbfs: float,
        silence_seconds: int,
        capture_device: str,  # legacy/unused, kept for config compatibility
        fifo_path: str,
        arecord_format: str,  # legacy/unused, kept for config compatibility
        ffmpeg_in_rate: int,
        ffmpeg_out_rate: int,
        owntone_base_url: str,
        owntone_output_name: str,
        owntone_volume_percent: int,
        owntone_output_offsets_ms: Optional[dict[str, int]] = None,
    ) -> None:
        self.input_device = input_device
        self.silence_threshold_dbfs = silence_threshold_dbfs
        self.silence_threshold_sample = dbfs_to_sample_threshold(silence_threshold_dbfs)
        self.silence_seconds = silence_seconds
        self.capture_device = capture_device
        self.fifo_path = fifo_path
        self.arecord_format = arecord_format
        self.ffmpeg_in_rate = ffmpeg_in_rate
        self.ffmpeg_out_rate = ffmpeg_out_rate
        self.owntone_base_url = owntone_base_url
        self.owntone_output_name = owntone_output_name
        self.owntone_volume_percent = owntone_volume_percent
        self.owntone_output_offsets_ms = owntone_output_offsets_ms or {}

        # --- Now-playing metadata / artwork helpers ---
        self._nowplaying_cache = PersistentNowPlayingCache()
        self._nowplaying_publisher = OwntoneMetadataPipePublisher(self.fifo_path)
        self._vinyl_recognizer = (
            VinylRecognizer(self._nowplaying_cache, self.input_device) if VinylRecognizer else None
        )
        if self._vinyl_recognizer is None:
            logging.info("Vinyl recognizer unavailable; running with static now-playing metadata.")
        self._current_nowplaying = (
            self._nowplaying_cache.get_manual_hint(self.input_device)
            or NowPlayingMetadata(
                title=f"Autostream ({self.input_device})",
                artist="Vinyl",
                album="Unknown Album",
            )
        )

        # Track-level recognition tuning:
        # We collect full track audio and only fingerprint once a track boundary
        # (silence gap) is detected, so AcoustID gets full-track context.
        self._track_start_level_sample = max(
            self.silence_threshold_sample * 3,
            int((os.environ.get("AUTOSTREAM_TRACK_START_LEVEL_SAMPLE") or "120").strip() or "120"),
        )
        self._track_end_level_sample = max(
            1,
            int((os.environ.get("AUTOSTREAM_TRACK_END_LEVEL_SAMPLE") or str(self.silence_threshold_sample)).strip()
                or str(self.silence_threshold_sample)),
        )
        end_ratio_raw = (os.environ.get("AUTOSTREAM_TRACK_END_RATIO") or "0.65").strip()
        try:
            self._track_end_ratio = float(end_ratio_raw)
        except Exception:
            self._track_end_ratio = 0.65
        self._track_end_ratio = max(0.05, min(0.95, self._track_end_ratio))
        self._track_min_seconds = max(
            12.0,
            float((os.environ.get("AUTOSTREAM_TRACK_MIN_SECONDS") or "25").strip() or "25"),
        )
        self._track_gap_seconds = max(
            1.0,
            float((os.environ.get("AUTOSTREAM_TRACK_GAP_SECONDS") or "3.0").strip() or "3.0"),
        )
        self._track_max_seconds = max(
            self._track_min_seconds,
            float((os.environ.get("AUTOSTREAM_TRACK_MAX_SECONDS") or "900").strip() or "900"),
        )
        self._track_preroll_seconds = max(
            0.0,
            float((os.environ.get("AUTOSTREAM_TRACK_PREROLL_SECONDS") or "1.5").strip() or "1.5"),
        )
        self._track_buffer = bytearray()
        self._track_preroll_buffer = bytearray()
        self._track_active = False
        self._track_started_at: Optional[float] = None
        self._track_silence_started_at: Optional[float] = None
        self._track_status_log_seconds = max(
            10.0,
            float((os.environ.get("AUTOSTREAM_TRACK_STATUS_LOG_SECONDS") or "20").strip() or "20"),
        )
        self._track_last_status_log_at = 0.0
        self._last_input_samplerate: int = self.ffmpeg_in_rate

        self._recognition_inflight = False
        self._recognition_attempt_count = 0
        self._recognition_last_attempt_at = 0.0
        self._capture_started_at: Optional[float] = None

        # Exposed for other scripts in the same process: average absolute
        # sample value from the most recent audio block (0..32767).
        self.current_level_sample: int = 0

        # Coordinator flag: when False, this monitor will *not* start or keep
        # ffmpeg running even if audio is active, but it will continue to
        # measure levels into ``current_level_sample``.
        # Defaults to True so single-input behaviour is unchanged.
        self.allow_capture: bool = True

        self._running = False
        self._audio_thread: Optional[threading.Thread] = None
        self._ffmpeg_proc: Optional[subprocess.Popen] = None
        self._last_above_threshold: Optional[float] = None

        # --- Owntone retry state ---
        # While capture is active, retry refreshing currently selected outputs
        # to recover from transient OwnTone issues.
        self._owntone_last_attempt: float = 0.0
        self._owntone_last_log: float = 0.0
        self._owntone_enabled_ok: bool = False
        self._capture_start_no_output_retry_at: float = 0.0
        self._capture_start_no_output_log_at: float = 0.0

        # Track ffmpeg stdin backpressure so we can auto-recover from stalled
        # pipe playback without requiring a manual Owntone restart.
        self._ffmpeg_backpressure_since: Optional[float] = None
        self._ffmpeg_last_backpressure_log: float = 0.0
        self._ffmpeg_last_reassert_attempt: float = 0.0
        self._ffmpeg_last_recovery_restart: float = 0.0
        self._ffmpeg_pending_bytes = bytearray()

        # Register this monitor so hot-plug logic can see if any monitor is
        # currently capturing (i.e. playback is active).
        all_monitors.append(self)

    # How often we retry talking to Owntone while capture is active.
    # 10 seconds is a good compromise: responsive enough, and gentle on logs/IO.
    OWNTONE_RETRY_SECONDS = 10.0
    OWNTONE_LOG_THROTTLE_SECONDS = 60.0

    # Backpressure handling:
    # - first, re-assert selected outputs
    # - only restart ffmpeg if the stall persists significantly longer
    FFMPEG_BACKPRESSURE_REASSERT_SECONDS = 3.0
    FFMPEG_BACKPRESSURE_REASSERT_COOLDOWN_SECONDS = 10.0
    FFMPEG_BACKPRESSURE_RECOVERY_SECONDS = 15.0
    FFMPEG_BACKPRESSURE_RESTART_COOLDOWN_SECONDS = 30.0
    FFMPEG_BACKPRESSURE_LOG_THROTTLE_SECONDS = 5.0

    @property
    def is_capturing(self) -> bool:
        """Return True while ffmpeg is running for this monitor."""

        return self._ffmpeg_proc is not None

    @property
    def seconds_since_last_activity(self) -> float:
        """Seconds since audio last exceeded the silence threshold.

        Returns ``float('inf')`` if we've never seen a block above threshold.
        Useful for external coordination logic that wants to know how long
        this input has been effectively silent.
        """

        if self._last_above_threshold is None:
            return float("inf")
        return time.time() - self._last_above_threshold

    def start(self) -> None:
        """Start monitoring in a background thread."""
        if self._running:
            return
        self._running = True
        self._audio_thread = threading.Thread(target=self._run, daemon=True)
        self._audio_thread.start()

    def stop(self) -> None:
        """Stop monitoring and stop any running ffmpeg."""
        self._running = False
        if self._audio_thread and self._audio_thread.is_alive():
            self._audio_thread.join(timeout=5)
        if self._ffmpeg_proc:
            self._stop_capture(disable_outputs=False)

        try:
            self._nowplaying_publisher.close()
        except Exception:
            pass


    def _run(self) -> None:
        """Main monitoring loop.

        Uses sounddevice to capture short blocks of audio from ``input_device``.
        For each block we compute the average absolute value of the int16
        samples (0..32767) and:
        - store it in ``self.current_level_sample`` for external inspection;
        - treat the stream as "active" if that average is above the configured
          sample threshold within the configured silence window.

        When active *and* ``allow_capture`` is True, the same blocks are
        written into ffmpeg's stdin to be resampled and forwarded to the FIFO
        pipe.
        """
        logging.info(
            "Starting AudioMonitor on input=%s, silence_threshold=%.1f dBFS (~%d), silence_seconds=%d",
            self.input_device,
            self.silence_threshold_dbfs,
            self.silence_threshold_sample,
            self.silence_seconds,
        )

        # Configure block size and samplerate for monitoring
        samplerate = self.ffmpeg_in_rate or 48000
        block_duration_sec = 0.05  # 50 ms blocks
        block_size = int(samplerate * block_duration_sec)
        if block_size <= 0:
            block_size = 1024

        silence_window = self.silence_seconds

        RETRY_DELAY = 5.0
        EMPTY_SLEEP = 0.05
        MAX_EMPTY_READS = 50  # ~2.5s at 50 ms blocks

        while self._running:
            self._last_above_threshold = None
            empty_reads = 0

            try:
                with sd.InputStream(
                    device=self.input_device,
                    channels=2,  # match ffmpeg -ac 2
                    samplerate=samplerate,
                    dtype="int16",
                ) as stream:
                    logging.info(
                        "Opened input device %r – entering monitor loop (samplerate=%d, block_size=%d).",
                        self.input_device,
                        samplerate,
                        block_size,
                    )

                    while self._running:
                        try:
                            data, overflowed = stream.read(block_size)
                        except sd.PortAudioError as e:
                            logging.warning(
                                "PortAudio error reading from %s: %s; restarting stream",
                                self.input_device,
                                e,
                            )
                            break  # leave the 'with' block so we can recreate the stream

                        if overflowed:
                            logging.debug("Audio input overflow detected")

                        if data.size == 0:
                            empty_reads += 1
                            if empty_reads >= MAX_EMPTY_READS:
                                logging.warning(
                                    "No audio from %s for a while; treating as device lost",
                                    self.input_device,
                                )
                                break  # force stream recreation
                            time.sleep(EMPTY_SLEEP)
                            continue

                        empty_reads = 0

                        # data shape: (frames, channels)
                        samples = data[:, 0].astype(np.int32)
                        avg_abs = int(np.mean(np.abs(samples)))  # 0..32767

                        # Expose the current average level to other code
                        self.current_level_sample = avg_abs

                        now = time.time()
                        if avg_abs >= self.silence_threshold_sample:
                            self._last_above_threshold = now

                        if self._last_above_threshold is not None:
                            elapsed_since_loud = now - self._last_above_threshold
                            is_active = elapsed_since_loud < silence_window
                        else:
                            elapsed_since_loud = float("inf")
                            is_active = False

                        # Decide whether to start/stop ffmpeg based on activity and
                        # the coordinator's allow_capture flag.
                        if is_active and self.allow_capture and self._ffmpeg_proc is None:
                            self._start_capture()
                            if self._ffmpeg_proc is not None:
                                logging.info(
                                    "Starting capture (avg_abs=%d, threshold=%d, elapsed_since_loud=%.2f)",
                                    avg_abs,
                                    self.silence_threshold_sample,
                                    elapsed_since_loud,
                                )
                        elif (not is_active or not self.allow_capture) and self._ffmpeg_proc is not None:
                            if not self.allow_capture:
                                logging.info(
                                    "Stopping capture because this input was deselected "
                                    "(elapsed_since_loud=%.1f).",
                                    elapsed_since_loud,
                                )
                            else:
                                logging.info(
                                    "Audio has been below threshold for %.1f s. Stopping capture.",
                                    elapsed_since_loud,
                                )
                            self._stop_capture(disable_outputs=False)

                        # If ffmpeg is running, feed it the current block
                        if self._ffmpeg_proc is not None:
                            # While capture is active, periodically retry enabling
                            # the configured Owntone output. This helps with cases
                            # where Owntone is restarting or AirPlay speakers appear
                            # late. Throttled to be micro-SD/log friendly.
                            self._maybe_retry_owntone(time.time())

                            if self._ffmpeg_proc.poll() is not None:
                                logging.warning(
                                    "ffmpeg process exited unexpectedly, stopping capture."
                                )
                                self._stop_capture(disable_outputs=False)
                            else:
                                self._write_pcm_to_ffmpeg(data)
                                self._collect_recognition_audio(data, samplerate, avg_abs)

            except Exception as e:  # noqa: BLE001
                logging.error(
                    "Error in audio monitor loop for %s: %s",
                    self.input_device,
                    e,
                )

                # Attempt to handle hot-plug situations and PortAudio shutdowns.
                msg = str(e)

                # If PortAudio isn't initialised, try to initialise it immediately.
                if "PortAudio not initialized" in msg:
                    try:
                        logging.info(
                            "PortAudio not initialized when using %r; calling sd._initialize()",
                            self.input_device,
                        )
                        sd._initialize()
                    except Exception as ie:  # noqa: BLE001
                        logging.error("Error initialising PortAudio: %s", ie)

                # If the configured device isn't found, and no monitor is currently
                # capturing, force a full PortAudio re-initialisation so that newly
                # hot-plugged devices are discovered.
                device_missing = (
                    "No input device" in msg
                    or "No such device" in msg
                    or "Invalid device" in msg
                    or "Unanticipated host error" in msg
                )

                if device_missing:
                    if not any_monitor_capturing():
                        logging.info(
                            "Input device %r not found and no playback is active; "
                            "terminating and re-initialising sounddevice/PortAudio to force device rescan.",
                            self.input_device,
                        )
                        try:
                            sd._terminate()
                            sd._initialize()
                        except Exception as te:  # noqa: BLE001
                            logging.error("Error re-initialising sounddevice/PortAudio: %s", te)
                    else:
                        logging.info(
                            "Input device %r not found, but playback is active on another "
                            "monitor; skipping PortAudio reset this time.",
                            self.input_device,
                        )

            # Stream died or failed to open: ensure ffmpeg is stopped.
            if self._ffmpeg_proc is not None:
                self._stop_capture(disable_outputs=False)

            if not self._running:
                break

            logging.info(
                "Retrying device %r in %.1f seconds",
                self.input_device,
                RETRY_DELAY,
            )
            time.sleep(RETRY_DELAY)


    def _collect_recognition_audio(self, data: np.ndarray, samplerate: int, avg_abs: int) -> None:
        """Collect full track audio and trigger recognition at track boundaries."""
        if self._vinyl_recognizer is None:
            return
        if data.size == 0:
            return

        self._last_input_samplerate = samplerate

        try:
            mono = np.mean(data.astype(np.int32), axis=1).astype(np.int16)
            mono_bytes = mono.tobytes()
            mono_level = int(np.mean(np.abs(mono.astype(np.int32))))
            now = time.time()
            dynamic_end_threshold = int(self._track_start_level_sample * self._track_end_ratio)
            effective_end_threshold = max(self._track_end_level_sample, dynamic_end_threshold)

            # Keep a short pre-roll so the attack at track start is included.
            self._track_preroll_buffer.extend(mono_bytes)
            preroll_max = max(0, int(samplerate * self._track_preroll_seconds * 2))
            if preroll_max > 0 and len(self._track_preroll_buffer) > preroll_max:
                del self._track_preroll_buffer[:-preroll_max]

            if not self._track_active:
                if mono_level >= self._track_start_level_sample:
                    self._track_active = True
                    self._track_started_at = now
                    self._track_silence_started_at = None
                    self._track_buffer = bytearray(self._track_preroll_buffer)
                    self._track_last_status_log_at = now
                    logging.info(
                        "Track capture started for recognition (level=%d, start_threshold=%d, end_threshold=%d).",
                        mono_level,
                        self._track_start_level_sample,
                        effective_end_threshold,
                    )
                else:
                    return

            self._track_buffer.extend(mono_bytes)
            max_track_bytes = int(samplerate * self._track_max_seconds * 2)
            if max_track_bytes > 0 and len(self._track_buffer) > max_track_bytes:
                self._finalize_track_recognition(
                    samplerate=samplerate,
                    reason="max_track_seconds",
                    force=True,
                )
                return

            if mono_level < effective_end_threshold:
                if self._track_silence_started_at is None:
                    self._track_silence_started_at = now
            else:
                self._track_silence_started_at = None

            if (now - self._track_last_status_log_at) >= self._track_status_log_seconds:
                track_age = now - (self._track_started_at or now)
                silent_for = 0.0 if self._track_silence_started_at is None else (now - self._track_silence_started_at)
                logging.info(
                    "Track capture active (age=%.1fs, level=%d, end_threshold=%d, silent_for=%.1fs).",
                    track_age,
                    mono_level,
                    effective_end_threshold,
                    silent_for,
                )
                self._track_last_status_log_at = now

            if self._track_silence_started_at is None:
                return

            track_age = now - (self._track_started_at or now)
            silent_for = now - self._track_silence_started_at
            if track_age < self._track_min_seconds or silent_for < self._track_gap_seconds:
                return

            # Trim trailing inter-track silence from the fingerprint payload.
            trim_bytes = int(samplerate * self._track_gap_seconds * 2)
            if trim_bytes > 0 and len(self._track_buffer) > trim_bytes:
                del self._track_buffer[-trim_bytes:]

            self._finalize_track_recognition(
                samplerate=samplerate,
                reason="silence_gap",
                force=False,
                level=avg_abs,
            )
        except Exception as e:
            logging.info("Now-playing sample collection failed: %s", e)


    def _finalize_track_recognition(
        self,
        samplerate: int,
        reason: str,
        force: bool = False,
        level: int = 0,
    ) -> None:
        """Queue background recognition for a completed track segment."""
        if self._vinyl_recognizer is None:
            self._track_buffer = bytearray()
            self._track_active = False
            self._track_started_at = None
            self._track_silence_started_at = None
            return
        if not self._track_buffer:
            self._track_active = False
            self._track_started_at = None
            self._track_silence_started_at = None
            return

        track_seconds = len(self._track_buffer) / max(1, samplerate * 2)
        required_seconds = self._track_min_seconds
        if force:
            required_seconds = max(10.0, self._track_min_seconds * 0.5)
        if track_seconds < required_seconds:
            self._track_buffer = bytearray()
            self._track_active = False
            self._track_started_at = None
            self._track_silence_started_at = None
            return

        if self._recognition_inflight:
            logging.info(
                "Skipping track recognition queue (reason=%s) because prior attempt is still running.",
                reason,
            )
            self._track_buffer = bytearray()
            self._track_active = False
            self._track_started_at = None
            self._track_silence_started_at = None
            return

        self._recognition_attempt_count += 1
        attempt_no = self._recognition_attempt_count
        self._recognition_inflight = True
        self._recognition_last_attempt_at = time.time()
        pcm16_mono = bytes(self._track_buffer)

        logging.info(
            "Now-playing recognition attempt %d queued (reason=%s, track_seconds=%.1f, level=%d).",
            attempt_no,
            reason,
            track_seconds,
            level,
        )

        self._track_buffer = bytearray()
        self._track_active = False
        self._track_started_at = None
        self._track_silence_started_at = None

        threading.Thread(
            target=self._recognize_nowplaying_worker,
            args=(pcm16_mono, samplerate, attempt_no),
            daemon=True,
        ).start()


    def _recognize_nowplaying_worker(self, pcm16_mono: bytes, samplerate: int, attempt_no: int) -> None:
        """Resolve metadata in the background and publish updates if found."""
        try:
            if self._vinyl_recognizer is None:
                return
            meta, source = self._vinyl_recognizer.resolve_with_source(pcm16_mono, samplerate)
            if not meta:
                logging.info("Now-playing recognition attempt %d found no metadata.", attempt_no)
                return

            changed = meta != self._current_nowplaying
            self._current_nowplaying = meta
            if changed:
                self._nowplaying_publisher.publish_start(meta)
                logging.info(
                    "Now-playing updated (%s): artist=%s album=%s title=%s",
                    source,
                    meta.artist,
                    meta.album,
                    meta.title,
                )
            else:
                logging.info(
                    "Now-playing recognition attempt %d matched existing metadata (%s).",
                    attempt_no,
                    source,
                )
        except Exception as e:
            logging.info("Now-playing recognition failed: %s", e)
        finally:
            self._recognition_inflight = False


    def _maybe_retry_owntone(self, now: float) -> None:
        """Periodically retry refreshing currently selected OwnTone outputs."""
        if not self.owntone_base_url:
            return

        # Already refreshed successfully during this capture session.
        if self._owntone_enabled_ok:
            return

        # Retry gate
        if (now - self._owntone_last_attempt) < self.OWNTONE_RETRY_SECONDS:
            return
        self._owntone_last_attempt = now

        outputs = self._get_owntone_outputs()
        if outputs is None:
            self._throttled_owntone_log(
                now,
                logging.WARNING,
                "Skipping Owntone selected-output refresh because outputs API is unavailable.",
            )
            return

        if not self._has_any_selected_outputs(outputs):
            if not self._auto_select_default_output(now, outputs, reason="retry"):
                self._throttled_owntone_log(
                    now,
                    logging.INFO,
                    "No outputs selected during capture; default fallback not available yet.",
                )
                return
            outputs = self._get_owntone_outputs()
            if outputs is None or not self._has_any_selected_outputs(outputs):
                return

        if self._refresh_selected_outputs(outputs):
            self._owntone_enabled_ok = True
            return

        self._throttled_owntone_log(
            now,
            logging.WARNING,
            "Owntone selected-output refresh failed during capture; will retry.",
        )


    def _throttled_owntone_log(self, now: float, level: int, msg: str, *args) -> None:
        """Log Owntone-related failures with a long throttle to avoid SD churn."""
        if (now - self._owntone_last_log) < self.OWNTONE_LOG_THROTTLE_SECONDS:
            return
        self._owntone_last_log = now
        logging.log(level, msg, *args)

    def _clear_ffmpeg_backpressure(self) -> None:
        self._ffmpeg_backpressure_since = None

    def _handle_ffmpeg_backpressure(self, now: float) -> None:
        """Handle stalled ffmpeg stdin with staged recovery."""
        if self._ffmpeg_backpressure_since is None:
            self._ffmpeg_backpressure_since = now
        stalled_for = now - self._ffmpeg_backpressure_since

        if (now - self._ffmpeg_last_backpressure_log) >= self.FFMPEG_BACKPRESSURE_LOG_THROTTLE_SECONDS:
            self._ffmpeg_last_backpressure_log = now
            logging.warning("ffmpeg stdin backpressure (stalled %.2fs)", stalled_for)

        if (
            stalled_for >= self.FFMPEG_BACKPRESSURE_REASSERT_SECONDS
            and (now - self._ffmpeg_last_reassert_attempt) >= self.FFMPEG_BACKPRESSURE_REASSERT_COOLDOWN_SECONDS
        ):
            self._ffmpeg_last_reassert_attempt = now
            outputs = self._get_owntone_outputs()
            if outputs is not None and not self._has_any_selected_outputs(outputs):
                if not self._auto_select_default_output(now, outputs, reason="backpressure recovery"):
                    logging.info(
                        "ffmpeg backpressure with no selected outputs and default fallback unavailable; stopping capture."
                    )
                    self._stop_capture(disable_outputs=False)
                    self._clear_ffmpeg_backpressure()
                    return
                outputs = self._get_owntone_outputs()

            if self._refresh_selected_outputs(outputs):
                self._owntone_enabled_ok = True
                logging.warning(
                    "ffmpeg backpressure persisted for %.2fs; re-applied selected Owntone outputs.",
                    stalled_for,
                )
            else:
                # Force _maybe_retry_owntone() to perform an attempt now.
                self._owntone_enabled_ok = False
                self._owntone_last_attempt = 0.0
                self._maybe_retry_owntone(now)
                logging.warning(
                    "ffmpeg backpressure persisted for %.2fs; retried selected-output refresh.",
                    stalled_for,
                )

            # Ensure Owntone isn't stuck in paused state while input is active.
            self._request_owntone_play("backpressure recovery")

        if stalled_for >= self.FFMPEG_BACKPRESSURE_RECOVERY_SECONDS:
            if (now - self._ffmpeg_last_recovery_restart) < self.FFMPEG_BACKPRESSURE_RESTART_COOLDOWN_SECONDS:
                return
            self._ffmpeg_last_recovery_restart = now
            logging.error(
                "ffmpeg stdin stalled for %.2fs; restarting ffmpeg capture without disabling outputs.",
                stalled_for,
            )
            self._stop_capture(disable_outputs=False)
            self._start_capture()
            self._clear_ffmpeg_backpressure()

    def _write_pcm_to_ffmpeg(self, data: np.ndarray) -> None:
        """Write one PCM block to ffmpeg stdin with non-blocking stall detection."""
        proc = self._ffmpeg_proc
        if proc is None or proc.stdin is None:
            return

        fd = proc.stdin.fileno()
        now = time.time()

        try:
            # Queue the newest PCM block; drain as much as possible each cycle.
            # This avoids treating partial writes as hard stalls.
            if data.size:
                self._ffmpeg_pending_bytes.extend(data.tobytes())

            if not self._ffmpeg_pending_bytes:
                self._clear_ffmpeg_backpressure()
                return

            progress_made = False
            while self._ffmpeg_pending_bytes:
                # Fast non-blocking readiness check; avoids hanging on pipe writes.
                _, writable, _ = select.select([], [fd], [], 0.0)
                if not writable:
                    break

                written = os.write(fd, self._ffmpeg_pending_bytes)
                if written <= 0:
                    break

                del self._ffmpeg_pending_bytes[:written]
                progress_made = True

            if progress_made:
                self._clear_ffmpeg_backpressure()
            else:
                self._handle_ffmpeg_backpressure(now)

        except BlockingIOError:
            self._handle_ffmpeg_backpressure(now)
        except BrokenPipeError:
            logging.error("Broken pipe writing to ffmpeg stdin, stopping capture.")
            self._stop_capture(disable_outputs=False)
            self._clear_ffmpeg_backpressure()
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                self._handle_ffmpeg_backpressure(now)
            else:
                logging.error("OS error writing to ffmpeg stdin: %s", e)
                self._stop_capture(disable_outputs=False)
                self._clear_ffmpeg_backpressure()
        except Exception as e:  # noqa: BLE001
            logging.error("Error writing to ffmpeg stdin: %s", e)
            self._stop_capture(disable_outputs=False)
            self._clear_ffmpeg_backpressure()

    def _get_owntone_outputs(self) -> Optional[list[dict]]:
        """Return OwnTone outputs list, or None if API is unavailable."""
        if not self.owntone_base_url:
            return None
        try:
            resp = requests.get(self.owntone_base_url.rstrip("/") + "/api/outputs", timeout=3)
            if not resp.ok:
                return None
            outputs = (resp.json() or {}).get("outputs", [])
            return outputs if isinstance(outputs, list) else None
        except Exception:
            return None

    @staticmethod
    def _selected_output_ids(outputs: list[dict]) -> list[str]:
        return [str(o.get("id")) for o in outputs if o.get("selected") and o.get("id") is not None]

    def _has_any_selected_outputs(self, outputs: Optional[list[dict]] = None) -> bool:
        """Return True if Owntone currently has at least one selected output."""
        if outputs is None:
            outputs = self._get_owntone_outputs()
            if outputs is None:
                return False
        return any(bool(o.get("selected", False)) for o in outputs)

    def _auto_select_default_output(
        self,
        now: float,
        outputs: Optional[list[dict]] = None,
        reason: str = "auto-select",
    ) -> bool:
        """If nothing is selected, auto-enable the configured default output."""
        if not self.owntone_base_url:
            return False

        if outputs is None:
            outputs = self._get_owntone_outputs()
        if outputs is None:
            self._throttled_owntone_log(
                now,
                logging.WARNING,
                "Could not fetch Owntone outputs while attempting default fallback (%s).",
                reason,
            )
            return False
        if self._has_any_selected_outputs(outputs):
            return True

        default_name = (self.owntone_output_name or "").strip()
        if not default_name:
            self._throttled_owntone_log(
                now,
                logging.WARNING,
                "No default output configured; cannot apply zero-target fallback (%s).",
                reason,
            )
            return False

        default_out = next((o for o in outputs if str(o.get("name") or "") == default_name), None)
        if not default_out or default_out.get("id") is None:
            self._throttled_owntone_log(
                now,
                logging.WARNING,
                "Configured default output '%s' not found in Owntone; cannot apply fallback (%s).",
                default_name,
                reason,
            )
            return False

        out_id = str(default_out.get("id"))
        base = self.owntone_base_url.rstrip("/")
        try:
            out_volume = int(default_out.get("volume", self.owntone_volume_percent))
        except Exception:
            out_volume = int(self.owntone_volume_percent)
        out_volume = max(0, min(100, out_volume))
        payload: dict[str, object] = {"selected": True, "volume": out_volume}
        offset_val = self.owntone_output_offsets_ms.get(out_id)
        if offset_val is not None:
            try:
                payload["offset_ms"] = max(-2000, min(2000, int(offset_val)))
            except Exception:
                pass

        try:
            resp = requests.put(base + f"/api/outputs/{out_id}", json=payload, timeout=3)
            if not resp.ok:
                self._throttled_owntone_log(
                    now,
                    logging.WARNING,
                    "Failed to auto-enable default output '%s' (%s): status=%s body=%s",
                    default_name,
                    reason,
                    resp.status_code,
                    (resp.text or "")[:200],
                )
                return False
            logging.info(
                "No outputs selected; auto-enabled default output '%s' (%s).",
                default_name,
                reason,
            )
            return True
        except Exception as e:
            self._throttled_owntone_log(
                now,
                logging.WARNING,
                "Failed to auto-enable default output '%s' (%s): %s",
                default_name,
                reason,
                e,
            )
            return False

    def _refresh_selected_outputs(self, outputs: Optional[list[dict]] = None) -> bool:
        """Re-apply current selected output ids to nudge Owntone playback state."""
        if not self.owntone_base_url:
            return False
        base = self.owntone_base_url.rstrip("/")
        try:
            if outputs is None:
                outputs = self._get_owntone_outputs()
            if outputs is None:
                return False
            selected_ids = self._selected_output_ids(outputs)
            if not selected_ids:
                return False
            set_payload = {"outputs": selected_ids}
            set_resp = requests.put(base + "/api/outputs/set", json=set_payload, timeout=3)
            if not set_resp.ok:
                return False
            logging.info("Refreshed selected Owntone outputs: %s", selected_ids)
            return True
        except Exception:
            return False

    def _request_owntone_play(self, reason: str) -> bool:
        """Best-effort request to ensure Owntone player is in play state."""
        if not self.owntone_base_url:
            return False
        base = self.owntone_base_url.rstrip("/")

        now = time.time()
        outputs = self._get_owntone_outputs()
        if outputs is None:
            self._throttled_owntone_log(
                now,
                logging.WARNING,
                "Skipping Owntone play request (%s) because outputs API is unavailable.",
                reason,
            )
            return False
        if not self._has_any_selected_outputs(outputs):
            if not self._auto_select_default_output(now, outputs, reason=f"play request ({reason})"):
                self._throttled_owntone_log(
                    now,
                    logging.INFO,
                    "Skipping Owntone play request (%s) because no outputs are selected.",
                    reason,
                )
                return False

        try:
            resp = requests.put(base + "/api/player/play", timeout=3)
            if resp.ok:
                logging.info("Owntone play requested (%s).", reason)
                return True
            if resp.status_code == 500:
                self._throttled_owntone_log(
                    time.time(),
                    logging.INFO,
                    "Owntone play request returned 500 (%s); relying on pipe autostart.",
                    reason,
                )
                return False
            logging.warning(
                "Owntone play request failed (%s): status=%s body=%s",
                reason,
                resp.status_code,
                (resp.text or "")[:200],
            )
            return False
        except Exception as e:
            logging.warning("Owntone play request failed (%s): %s", reason, e)
            return False


    def _request_owntone_stop(self, reason: str) -> bool:
        """Best-effort stop request to release active output sessions."""
        if not self.owntone_base_url:
            return False
        base = self.owntone_base_url.rstrip("/")
        try:
            resp = requests.put(base + "/api/player/stop", timeout=3)
            if resp.ok:
                logging.info("Owntone stop requested (%s).", reason)
                return True
            logging.warning(
                "Owntone stop request failed (%s): status=%s body=%s",
                reason,
                resp.status_code,
                (resp.text or "")[:200],
            )
            return False
        except Exception as e:
            logging.warning("Owntone stop request failed (%s): %s", reason, e)
            return False


    def _start_capture(self) -> None:
        """Start ffmpeg and optionally enable Owntone output."""
        if self._ffmpeg_proc is not None:
            return

        now = time.time()
        if self.owntone_base_url:
            # Poll output state at a low frequency while waiting for OwnTone
            # so active-input loops don't hammer the JSON API.
            if now < self._capture_start_no_output_retry_at:
                return
            self._capture_start_no_output_retry_at = now + 2.0

            outputs = self._get_owntone_outputs()
            if outputs is None:
                return
            if not self._has_any_selected_outputs(outputs):
                if not self._auto_select_default_output(now, outputs, reason="capture start"):
                    if (now - self._capture_start_no_output_log_at) >= 15.0:
                        self._capture_start_no_output_log_at = now
                        logging.info(
                            "Input is active with no selected outputs; waiting to auto-select default output."
                        )
                    return
            self._capture_start_no_output_retry_at = 0.0

        # Reset Owntone enable state for this capture session.
        # We attempt immediately, and then keep retrying periodically while capture runs.
        self._owntone_enabled_ok = False
        self._owntone_last_attempt = 0.0  # force immediate attempt on start

        self._ffmpeg_proc = start_ffmpeg(
            self.fifo_path,
            self.ffmpeg_in_rate,
            self.ffmpeg_out_rate,
        )
        self._clear_ffmpeg_backpressure()
        self._ffmpeg_pending_bytes = bytearray()

        self._capture_started_at = time.time()
        self._track_buffer = bytearray()
        self._track_preroll_buffer = bytearray()
        self._track_active = False
        self._track_started_at = None
        self._track_silence_started_at = None
        self._track_last_status_log_at = 0.0
        self._recognition_inflight = False
        self._recognition_attempt_count = 0
        self._recognition_last_attempt_at = 0.0

        # Publish best-known now-playing metadata (manual hint, cached hash hit,
        # or default placeholder).
        self._nowplaying_publisher.publish_start(self._current_nowplaying)

        # Re-apply currently selected outputs to nudge OwnTone out of suspended state.
        refreshed_selected = self._refresh_selected_outputs()
        has_selected_outputs = refreshed_selected or self._has_any_selected_outputs()
        if refreshed_selected:
            self._owntone_enabled_ok = True
        elif has_selected_outputs:
            # We have selected outputs but refresh failed (Owntone transient issue), so
            # keep normal retry behavior.
            self._maybe_retry_owntone(time.time())
        else:
            # Keep retrying if OwnTone is still settling after startup/reconnect.
            self._owntone_enabled_ok = False

        # OwnTone can remain paused after long idle periods; nudge play once at
        # least one output is selected.
        if has_selected_outputs:
            self._request_owntone_play("capture start")


    def _stop_capture(self, disable_outputs: bool = False) -> None:
        """Stop ffmpeg.

        By default, this preserves the current OwnTone output selection and
        per-output volumes so playback routing survives long idle gaps.
        Set disable_outputs=True only for explicit teardown behavior.
        """
        if self._ffmpeg_proc is None:
            return

        # Flush any completed/partial track when capture is intentionally stopped.
        self._finalize_track_recognition(
            samplerate=max(1, int(self._last_input_samplerate or self.ffmpeg_in_rate)),
            reason="capture_stop",
            force=True,
            level=self.current_level_sample,
        )

        stop_ffmpeg(self._ffmpeg_proc)
        self._ffmpeg_proc = None
        self._clear_ffmpeg_backpressure()
        self._ffmpeg_pending_bytes = bytearray()
        self._capture_started_at = None

        # Reset Owntone state so a future capture session will attempt again.
        self._owntone_enabled_ok = False

        try:
            self._nowplaying_publisher.publish_end()
        except Exception:
            pass

        # If capture has ended and no monitor is active, request player stop so
        # network targets release their active input/session cleanly.
        if self.owntone_base_url and not any_monitor_capturing():
            self._request_owntone_stop("capture stop")

        # Clear outputs, but only if this was the last active capture.
        # This avoids breaking playback if another monitor is still capturing.
        if disable_outputs and self.owntone_base_url and not any_monitor_capturing():
            owntone_disable_all_outputs(self.owntone_base_url)


def run_autostream(config_path: str, start_webui=None) -> None:
    """Run the autostream monitor using the given config file path.

    If start_webui is provided, it will be called with the config_path
    to start any optional web UI (typically in a background thread).
    """
    cfg = load_and_parse(config_path)

    setup_logging(cfg.general.log_file)

    # --- Ensure OwnTone config is correct before doing anything else ---
    cfg_status = owntone_config_ok()
    if cfg_status == OWNTONE_OK:
        logging.info("OwnTone config OK (directories=/tmp/autostream-pipes, pipe_autostart enabled).")
    elif cfg_status == OWNTONE_RESTART_REQUIRED:
        logging.warning(
            "OwnTone config was updated (directories=/tmp/autostream-pipes, pipe_autostart enabled). "
            "OwnTone restart required for changes to take effect."
        )
        # Best-effort restart (won't break dev usage)
        try:
            if owntone_restart_service():
                logging.info("Requested OwnTone restart via autostream-admin.")
            else:
                logging.warning("OwnTone restart request failed (autostream-admin).")
        except Exception as e:  # noqa: BLE001
            logging.warning("Could not restart OwnTone automatically: %s", e)
    else:
        logging.error(
            "OwnTone config NOT OK and could not be fixed. "
            "Playback via pipe may fail."
        )

    # Optionally start the web UI
    if start_webui is not None:
        try:
            start_webui(config_path)
        except Exception as e:  # noqa: BLE001
            logging.error("Failed to start web UI: %s", e)

    # --- Load configuration data ---

    silence_seconds = cfg.general.silence_seconds
    fifo_path = cfg.general.fifo_path

    capture_device1 = cfg.audio1.capture_device
    arecord_format1 = cfg.audio1.arecord_format
    silence_threshold1 = cfg.audio1.silence_threshold_dbfs

    audio2_enabled = cfg.audio2_enabled
    capture_device2 = cfg.audio2.capture_device
    arecord_format2 = cfg.audio2.arecord_format
    silence_threshold2 = cfg.audio2.silence_threshold_dbfs

    ffmpeg_out_rate = cfg.ffmpeg.out_rate
    ffmpeg_in_rate1 = cfg.ffmpeg.in_rate1
    ffmpeg_in_rate2 = cfg.ffmpeg.in_rate2

    owntone_base = cfg.owntone.base_url
    owntone_output_name = cfg.owntone.output_name
    owntone_volume = cfg.owntone.volume_percent
    owntone_offsets = cfg.owntone.output_offsets_ms


    # Ensure pipe path exists before monitoring, then make sure OwnTone has
    # indexed the pipe source (important after reboot when /tmp is empty).
    ensure_fifo(fifo_path)
    if owntone_base:
        if owntone_ensure_pipe_indexed(owntone_base, timeout_s=15.0):
            logging.info("OwnTone pipe source is indexed and ready.")
        else:
            logging.warning(
                "OwnTone pipe source is not indexed yet; playback start may fail until files rescan succeeds."
            )

    # --- Create one or two AudioMonitor instances ---
    monitors: list[AudioMonitor] = []

    monitor1 = AudioMonitor(
        input_device=capture_device1,
        silence_threshold_dbfs=silence_threshold1,
        silence_seconds=silence_seconds,
        capture_device=capture_device1,
        fifo_path=fifo_path,
        arecord_format=arecord_format1,
        ffmpeg_in_rate=ffmpeg_in_rate1,
        ffmpeg_out_rate=ffmpeg_out_rate,
        owntone_base_url=owntone_base,
        owntone_output_name=owntone_output_name,
        owntone_volume_percent=owntone_volume,
        owntone_output_offsets_ms=owntone_offsets,
    )
    monitors.append(monitor1)

    if (
        audio2_enabled
        and capture_device2
        and capture_device2 != capture_device1
    ):
        monitor2 = AudioMonitor(
            input_device=capture_device2,
            silence_threshold_dbfs=silence_threshold2,
            silence_seconds=silence_seconds,
            capture_device=capture_device2,
            fifo_path=fifo_path,
            arecord_format=arecord_format2,
            ffmpeg_in_rate=ffmpeg_in_rate2,
            ffmpeg_out_rate=ffmpeg_out_rate,
            owntone_base_url=owntone_base,
            owntone_output_name=owntone_output_name,
            owntone_volume_percent=owntone_volume,
            owntone_output_offsets_ms=owntone_offsets,
        )
        monitors.append(monitor2)

    # If we have more than one monitor, let the coordinator choose who owns
    # ffmpeg. Start with nobody capturing.
    if len(monitors) > 1:
        for m in monitors:
            m.allow_capture = False

    # How long the current input must be silent before we consider switching.
    SWITCH_SILENCE_SECONDS = 5.0

    try:
        for m in monitors:
            m.start()

        logging.info(
            "autostream_core is now running with %d input(s). Press Ctrl+C to exit.",
            len(monitors),
        )

        current: Optional[AudioMonitor] = None

        while not stop_flag.is_set():
            if len(monitors) == 1:
                # Single-input mode: keep behaviour simple and identical to
                # earlier versions. Just ensure it's allowed to capture.
                monitors[0].allow_capture = True
                current = monitors[0]
                time.sleep(1)
                continue

            # Multi-input coordination.
            # 1) Find all monitors currently above their own threshold.
            loud_monitors = [
                m
                for m in monitors
                if m.current_level_sample >= m.silence_threshold_sample
            ]
            loud_monitors.sort(
                key=lambda m: m.current_level_sample,
                reverse=True,
            )
            candidate = loud_monitors[0] if loud_monitors else None

            new_current = current

            if current is None or not current.is_capturing:
                # Nothing is currently playing: choose any loud candidate.
                if candidate is not None:
                    new_current = candidate
            else:
                silent_for = current.seconds_since_last_activity
                if (
                    candidate is not None
                    and candidate is not current
                    and SWITCH_SILENCE_SECONDS <= silent_for < current.silence_seconds
                ):
                    # Current input has been silent for long enough, but not so
                    # long that it has fully timed out. Switch to the other
                    # input which is now active.
                    new_current = candidate

            # Apply selection if it changed.
            if new_current is not current:
                for m in monitors:
                    m.allow_capture = m is new_current
                current = new_current
                if current is not None:
                    logging.info("Switched active input to %s", current.input_device)
                else:
                    logging.info("No active input selected.")

            time.sleep(0.5)

    except Exception as e:  # noqa: BLE001
        logging.error("Unexpected error: %s", e)

    finally:
        for m in monitors:
            m.stop()
        logging.info("Stopped cleanly.")



def main() -> None:
    """CLI entrypoint for running autostream without the web UI."""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} PATH_TO_CONFIG.ini")
        sys.exit(1)

    config_path = sys.argv[1]
    run_autostream(config_path)


if __name__ == "__main__":
    main()
