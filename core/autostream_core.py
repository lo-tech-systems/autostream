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

  * Enables a configured output on a local `owntone` instance and sets its volume.

- When input has been below the threshold for a configured number of seconds, it:

  * Stops the `ffmpeg` process.

- Owntone must be configured to watch the pipe, and with auto playback enabled.
"""

import configparser
import logging
import os
import subprocess
import sys
import time
import signal
from typing import Optional
import threading
import requests
import numpy as np
import sounddevice as sd

from autostream_config import load_and_parse

from autostream_owntone import (
    get_owntone_output_id,
    owntone_set_output,
    owntone_disable_all_outputs,
    owntone_config_ok,
    owntone_restart_service,
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
        self._output_id: Optional[int] = None

        # Register this monitor so hot-plug logic can see if any monitor is
        # currently capturing (i.e. playback is active).
        all_monitors.append(self)

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
            stop_ffmpeg(self._ffmpeg_proc)
            self._ffmpeg_proc = None


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

        # Pre-resolve Owntone output ID
        if self.owntone_output_name:
            self._output_id = get_owntone_output_id(
                self.owntone_base_url,
                self.owntone_output_name,
            )
            if self._output_id is None:
                logging.warning(
                    "Could not resolve Owntone output '%s'. Audio will still be captured, "
                    "but the output won't be auto-enabled.",
                    self.owntone_output_name,
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
                            logging.info(
                                "Starting capture (avg_abs=%d, threshold=%d, elapsed_since_loud=%.2f)",
                                avg_abs,
                                self.silence_threshold_sample,
                                elapsed_since_loud,
                            )
                            self._start_capture()
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
                            self._stop_capture()

                        # If ffmpeg is running, feed it the current block
                        if self._ffmpeg_proc is not None:
                            if self._ffmpeg_proc.poll() is not None:
                                logging.warning(
                                    "ffmpeg process exited unexpectedly, stopping capture."
                                )
                                self._stop_capture()
                            else:
                                try:
                                    if self._ffmpeg_proc.stdin:
                                        self._ffmpeg_proc.stdin.write(data.tobytes())
                                except BrokenPipeError:
                                    logging.error(
                                        "Broken pipe writing to ffmpeg stdin, stopping capture."
                                    )
                                    self._stop_capture()
                                except Exception as e:  # noqa: BLE001
                                    logging.error("Error writing to ffmpeg stdin: %s", e)
                                    self._stop_capture()

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
                self._stop_capture()

            if not self._running:
                break

            logging.info(
                "Retrying device %r in %.1f seconds",
                self.input_device,
                RETRY_DELAY,
            )
            time.sleep(RETRY_DELAY)

    def _start_capture(self) -> None:
        """Start ffmpeg and optionally enable Owntone output."""
        if self._ffmpeg_proc is not None:
            return

        self._ffmpeg_proc = start_ffmpeg(
            self.fifo_path,
            self.ffmpeg_in_rate,
            self.ffmpeg_out_rate,
        )

        # If we're transitioning from idle -> playing, clear any previously
        # selected Owntone outputs so we start from a known state.
        if self.owntone_base_url and not any_monitor_capturing():
            owntone_disable_all_outputs(self.owntone_base_url)
            
        # Try to resolve Owntone output lazily if we don't have an id yet
        if self._output_id is None and self.owntone_output_name:
            oid = get_owntone_output_id(self.owntone_base_url, self.owntone_output_name)
            if oid is not None:
                logging.info(
                    "Resolved Owntone output %r -> id %s on capture start",
                    self.owntone_output_name,
                    oid,
                )
                self._output_id = oid
            else:
                logging.warning(
                    "Could not resolve Owntone output %r; auto-enable skipped.",
                    self.owntone_output_name,
                )

        if self._output_id is not None:
            ok = owntone_set_output(
                self.owntone_base_url,
                self._output_id,
                self.owntone_volume_percent,
            )
            if not ok and self.owntone_output_name:
                # ID might be stale – try to re-resolve once
                new_id = get_owntone_output_id(self.owntone_base_url, self.owntone_output_name)
                if new_id and new_id != self._output_id:
                    logging.info(
                        "Owntone output id changed for %r: %s -> %s; retrying",
                        self.owntone_output_name, self._output_id, new_id,
                    )
                    self._output_id = new_id
                    owntone_set_output(
                        self.owntone_base_url,
                        self._output_id,
                        self.owntone_volume_percent,
                    )


    def _stop_capture(self) -> None:
        """Stop ffmpeg."""
        if self._ffmpeg_proc is None:
            return
        stop_ffmpeg(self._ffmpeg_proc)
        self._ffmpeg_proc = None

        # Clear outputs, but only if this was the last active capture.
        # This avoids breaking playback if another monitor is still capturing.
        if self.owntone_base_url and not any_monitor_capturing():
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
        logging.info("OwnTone config OK (directories=/tmp, pipe_autostart enabled).")
    elif cfg_status == OWNTONE_RESTART_REQUIRED:
        logging.warning(
            "OwnTone config was updated (directories=/tmp, pipe_autostart enabled). "
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
