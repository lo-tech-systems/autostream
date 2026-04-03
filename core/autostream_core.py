#!/usr/bin/env python3
"""autostream_core.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Engine behind autostream.  Connects to autostream_monitor (the C++ daemon)
via a Unix domain socket to manage audio capture, resampling, silence
detection, and FIFO writing.  Python retains responsibility for OwnTone
HTTP control, now-playing metadata, and optional track recognition.

The daemon is expected to be running as a systemd service before this
script starts.  The socket path defaults to /tmp/autostream_monitor.sock
and can be overridden with the AUTOSTREAM_MONITOR_SOCKET environment
variable.
"""

import json
import logging
import os
import stat
import socket
import sys
import time
import signal
import threading
from typing import Optional

import requests

from autostream_config import load_and_parse, unconfigured
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
    owntone_check_api_settings,
    owntone_restart_service,
    owntone_ensure_pipe_indexed,
    OWNTONE_OK,
    OWNTONE_RESTART_REQUIRED,
    OWNTONE_NOT_OK,
)
from autostream_playback import (
    DEFAULT_STYLUS_LIFE_HOURS,
    InputPlaybackSnapshot,
    PlaybackInputConfig,
    PlaybackSnapshot,
    PlaybackTracker,
    StylusResetResult,
    input_label,
)


# --------------------------------------------------------------------------- #
# Process termination                                                          #
# --------------------------------------------------------------------------- #

stop_flag = threading.Event()
reload_flag = threading.Event()


def request_config_reload() -> None:
    """Signal the coordinator loop to tear down and re-initialise all monitors.

    Called by the Web UI after a successful settings save.  The coordinator
    picks this up within one poll interval and re-reads the INI without
    restarting the process.
    """
    reload_flag.set()


# Track all AudioMonitor instances so coordination logic can inspect them.
# _monitors_lock must be held when reading or mutating all_monitors or when
# taking a snapshot of its elements for use on a different thread (Web UI).
all_monitors: list["AudioMonitor"] = []
_monitors_lock = threading.Lock()
_playback_tracker: Optional[PlaybackTracker] = None


def _empty_playback_snapshot() -> PlaybackSnapshot:
    return PlaybackSnapshot(
        inputs={},
        warning_input_indices=(),
        overdue_input_indices=(),
        banner_text=None,
    )


def _playback_input_configs_from_config(cfg) -> dict[int, PlaybackInputConfig]:
    return {
        1: PlaybackInputConfig.normalized(
            enabled=True,
            is_turntable=cfg.audio1.is_turntable,
            stylus_life_hours=cfg.audio1.stylus_life_hours,
        ),
        2: PlaybackInputConfig.normalized(
            enabled=cfg.audio2_enabled,
            is_turntable=cfg.audio2.is_turntable,
            stylus_life_hours=cfg.audio2.stylus_life_hours,
        ),
    }


def _ensure_playback_tracker(cfg) -> Optional[PlaybackTracker]:
    global _playback_tracker

    try:
        if _playback_tracker is None:
            _playback_tracker = PlaybackTracker()
        _playback_tracker.replace_input_configs(_playback_input_configs_from_config(cfg))
    except Exception as e:
        logging.warning("Playback tracker unavailable: %s", e)
        _playback_tracker = None

    return _playback_tracker


def get_playback_snapshot() -> PlaybackSnapshot:
    tracker = _playback_tracker
    if tracker is None:
        return _empty_playback_snapshot()
    try:
        return tracker.snapshot()
    except Exception as e:
        logging.warning("Could not read playback snapshot: %s", e)
        return _empty_playback_snapshot()


def get_input_playback_snapshot(input_index: int) -> InputPlaybackSnapshot:
    idx = int(input_index)
    snap = get_playback_snapshot().inputs.get(idx)
    if snap is not None:
        return snap

    return InputPlaybackSnapshot(
        input_index=idx,
        label=input_label(idx),
        active=False,
        enabled=True,
        is_turntable=False,
        total_playback_seconds=0,
        total_playback_hours=0.0,
        stylus_playback_seconds=0,
        stylus_playback_hours=0.0,
        stylus_life_hours=DEFAULT_STYLUS_LIFE_HOURS,
        stylus_remaining_seconds=None,
        stylus_remaining_hours=None,
        stylus_warning=False,
        stylus_overdue=False,
        last_stylus_reset_at=None,
    )


def reset_input_stylus(input_index: int) -> StylusResetResult:
    tracker = _playback_tracker
    if tracker is None:
        return StylusResetResult(applied=False, persisted=False)
    try:
        return tracker.reset_stylus(int(input_index))
    except Exception as e:
        logging.warning("Could not reset stylus for input %s: %s", input_index, e)
        return StylusResetResult(applied=False, persisted=False)


def update_playback_input_config(
    input_index: int,
    *,
    enabled: bool,
    is_turntable: bool,
    stylus_life_hours: int,
) -> bool:
    tracker = _playback_tracker
    if tracker is None:
        return False
    try:
        tracker.update_input_config(
            int(input_index),
            enabled=enabled,
            is_turntable=is_turntable,
            stylus_life_hours=stylus_life_hours,
        )
        return True
    except Exception as e:
        logging.warning(
            "Could not update playback config for input %s: %s",
            input_index,
            e,
        )
        return False


def _normalize_owntone_output_offsets(
    output_offsets_ms: Optional[dict[str, object]] = None,
) -> dict[str, int]:
    normalized: dict[str, int] = {}
    for raw_key, raw_val in (output_offsets_ms or {}).items():
        key = str(raw_key).strip()
        if not key:
            continue
        try:
            off = int(raw_val)
        except Exception:
            off = 0
        normalized[key] = max(-2000, min(2000, off))
    return normalized


def update_live_owntone_runtime(
    *,
    output_name: str,
    volume_percent: object,
    output_offsets_ms: Optional[dict[str, object]] = None,
) -> bool:
    try:
        live_output_name = str(output_name or "").strip()
        try:
            live_volume_percent = int(str(volume_percent).strip())
        except Exception:
            live_volume_percent = 20
        live_volume_percent = max(0, min(100, live_volume_percent))
        live_output_offsets_ms = _normalize_owntone_output_offsets(output_offsets_ms)

        with _monitors_lock:
            for monitor in all_monitors:
                monitor.owntone_output_name = live_output_name
                monitor.owntone_volume_percent = live_volume_percent
                monitor.owntone_output_offsets_ms = dict(live_output_offsets_ms)
        return True
    except Exception as e:
        logging.warning("Could not update live OwnTone runtime settings: %s", e)
        return False


def any_monitor_capturing() -> bool:
    """Return True if any AudioMonitor currently has an active capture."""
    with _monitors_lock:
        return any(m.is_capturing for m in all_monitors)


def _stop_and_disable_owntone(base_url: str, reason: str) -> None:
    """Best-effort stop of OwnTone playback and deselection of all outputs."""
    if not base_url:
        return
    try:
        url = base_url.rstrip("/") + "/api/player/stop"
        resp = requests.put(url, timeout=3)
        if resp.ok:
            logging.info("OwnTone player stopped (%s).", reason)
        else:
            logging.warning(
                "OwnTone player stop failed (%s): status=%s",
                reason, resp.status_code,
            )
    except Exception as e:
        logging.warning(
            "OwnTone player stop request failed (%s): %s", reason, e,
        )

    owntone_disable_all_outputs(base_url)


def handle_signal(signum, frame):
    stop_flag.set()


signal.signal(signal.SIGINT,  handle_signal)
signal.signal(signal.SIGTERM, handle_signal)


def setup_logging(log_file: str) -> None:
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


def get_monitor_levels_dbfs() -> list[dict]:
    """Return current level data for each active monitor for the Web UI.

    Data is sourced from the most recent get_status() poll cached in each
    AudioMonitor instance, so it is at most one poll interval stale.
    """
    levels: list[dict] = []
    with _monitors_lock:
        snapshot = list(all_monitors)
    for idx, mon in enumerate(snapshot, start=1):
        levels.append({
            "label": f"Input {idx}",
            "dbfs": round(mon.level_dbfs, 1),
            "detected_hz": round(mon.detected_hz, 1),
            "is_above_threshold": not mon.is_silent,
        })
    return levels


def get_monitor_socket_path() -> str:
    """Return the configured autostream_monitor socket path."""
    return (
        os.environ.get("AUTOSTREAM_MONITOR_SOCKET", "").strip()
        or MonitorClient.DEFAULT_SOCKET_PATH
    )


def normalize_monitor_devices(devices: Optional[list[dict]]) -> list[dict]:
    """Normalize list_devices() results into a stable Web UI-friendly shape.

    Each returned dict contains:
      - hw: ALSA hardware identifier such as "hw:1,0"
      - card: ALSA card description (may be empty)
      - name: ALSA device description (may be empty)
      - label: user-facing text combining card/device/hw
    """
    normalized: list[dict] = []

    for dev in devices or []:
        hw = str(dev.get("hw") or "").strip()
        if not hw:
            continue

        card = str(dev.get("card") or "").strip()
        name = str(dev.get("name") or "").strip()

        label_parts = [part for part in (card, name) if part]
        label = " - ".join(label_parts) if label_parts else hw
        if hw not in label:
            label = f"{label} ({hw})"

        normalized.append({
            "hw": hw,
            "card": card,
            "name": name,
            "label": label,
        })

    normalized.sort(key=lambda d: (d["label"].casefold(), d["hw"].casefold()))
    return normalized


def get_available_monitor_devices(
    socket_path: Optional[str] = None,
) -> list[dict]:
    """Return currently visible monitor devices from autostream_monitor.

    Uses a short-lived MonitorClient connection so callers outside the main
    coordinator loop can safely query available ALSA capture devices.
    Returns an empty list if the daemon is unavailable or the command fails.
    """
    client = MonitorClient(socket_path or get_monitor_socket_path())
    try:
        if not client.connect():
            return []
        return normalize_monitor_devices(client.list_devices())
    except Exception as e:
        logging.warning("Could not query autostream_monitor devices: %s", e)
        return []
    finally:
        client.close()


def ensure_audio_fifo(path: str) -> bool:
    """Ensure the configured OwnTone audio FIFO exists and is a named pipe."""
    try:
        if not path or not os.path.isabs(path):
            logging.error("Configured fifo_path must be an absolute path: %r", path)
            return False

        fifo_dir = os.path.dirname(path)
        if fifo_dir:
            os.makedirs(fifo_dir, mode=0o777, exist_ok=True)

        if os.path.exists(path):
            st = os.stat(path)
            if not stat.S_ISFIFO(st.st_mode):
                logging.error("Configured fifo_path exists but is not a FIFO: %r", path)
                return False
            return True

        os.mkfifo(path, 0o666)
        logging.info("Created audio FIFO at %s", path)
        return True
    except Exception as e:
        logging.error("Could not create audio FIFO %r: %s", path, e)
        return False


def build_monitor_eq_bands(
    eq_40hz_db: float,
    eq_100hz_db: float,
    eq_10khz_db: float,
) -> list[dict]:
    """Return the fixed three-band EQ definition expected by autostream_monitor.

    For shelf filters, the monitor currently uses the RBJ cookbook shelf
    formula wired through the generic ``q`` field. A value of ``q=0.707`` is
    equivalent to a shelf slope of ``S=1.0``.
    """
    return [
        {"type": "peak", "freq_hz": 40.0, "gain_db": float(eq_40hz_db), "q": 0.707},
        {"type": "low_shelf", "freq_hz": 100.0, "gain_db": float(eq_100hz_db), "q": 0.707},
        {"type": "high_shelf", "freq_hz": 10000.0, "gain_db": float(eq_10khz_db), "q": 0.707},
    ]


def apply_input_eq(
    client: "MonitorClient",
    input_index: int,
    eq_40hz_db: float,
    eq_100hz_db: float,
    eq_10khz_db: float,
) -> bool:
    """Push one input's EQ settings to autostream_monitor."""
    return client.set_eq(
        input_index,
        build_monitor_eq_bands(eq_40hz_db, eq_100hz_db, eq_10khz_db),
    )


def apply_input_gain(
    client: "MonitorClient",
    input_index: int,
    gain_db: float,
) -> bool:
    """Push one input's gain setting to autostream_monitor."""
    return client.set_gain(input_index, float(gain_db))


def set_live_input_eq(
    input_index: int,
    eq_40hz_db: float,
    eq_100hz_db: float,
    eq_10khz_db: float,
    socket_path: Optional[str] = None,
) -> bool:
    """Apply one input's EQ immediately to the running autostream_monitor.

    Uses a short-lived monitor connection so the Web UI can update EQ live
    without depending on the coordinator loop's persistent client.
    Also updates any matching in-process AudioMonitor cache so reconnect replay
    continues to use the most recent live values until the INI is saved.
    """
    client = MonitorClient(socket_path or get_monitor_socket_path())
    try:
        if not client.connect():
            return False
        ok = apply_input_eq(
            client,
            input_index,
            eq_40hz_db,
            eq_100hz_db,
            eq_10khz_db,
        )
        if ok:
            with _monitors_lock:
                snapshot = list(all_monitors)
            for mon in snapshot:
                if mon.input_index == input_index:
                    mon.eq_40hz_db = float(eq_40hz_db)
                    mon.eq_100hz_db = float(eq_100hz_db)
                    mon.eq_10khz_db = float(eq_10khz_db)
        return ok
    finally:
        client.close()


def set_live_input_gain(
    input_index: int,
    gain_db: float,
    socket_path: Optional[str] = None,
) -> bool:
    """Apply one input's gain immediately to the running autostream_monitor."""
    client = MonitorClient(socket_path or get_monitor_socket_path())
    try:
        if not client.connect():
            return False
        ok = apply_input_gain(client, input_index, gain_db)
        if ok:
            with _monitors_lock:
                snapshot = list(all_monitors)
            for mon in snapshot:
                if mon.input_index == input_index:
                    mon.gain_db = float(gain_db)
        return ok
    finally:
        client.close()


# --------------------------------------------------------------------------- #
# MonitorClient                                                                #
# --------------------------------------------------------------------------- #

class MonitorClient:
    """Thin wrapper around the autostream_monitor Unix domain socket.

    All commands are synchronous and serialised by _lock so that callers
    on different threads (e.g. the coordinator loop and a background
    recognition thread) do not interleave their JSON lines.

    The client holds a persistent connection.  If the socket is lost,
    is_connected() returns False and the caller is responsible for calling
    connect() again (the coordinator loop does this automatically).
    """

    DEFAULT_SOCKET_PATH = "/tmp/autostream_monitor.sock"
    CONNECT_TIMEOUT = 5.0    # seconds
    COMMAND_TIMEOUT = 15.0   # seconds; covers get_id_snapshot binary transfer

    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH) -> None:
        self._socket_path = socket_path
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._recv_buf = b""

    # ── Connection ───────────────────────────────────────────────────────────

    def connect(self) -> bool:
        """Open the socket; return True on success."""
        self.close()
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.CONNECT_TIMEOUT)
            s.connect(self._socket_path)
            s.settimeout(self.COMMAND_TIMEOUT)
            self._sock = s
            self._recv_buf = b""
            logging.info("MonitorClient: connected to %s", self._socket_path)
            return True
        except OSError as e:
            logging.error("MonitorClient: connect failed: %s", e)
            return False

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._recv_buf = b""

    def is_connected(self) -> bool:
        return self._sock is not None

    # ── Low-level I/O ────────────────────────────────────────────────────────

    def _readline(self) -> Optional[bytes]:
        """Read bytes from the socket up to and including the next newline."""
        while b"\n" not in self._recv_buf:
            try:
                chunk = self._sock.recv(4096)
            except OSError:
                self.close()
                return None
            if not chunk:
                self.close()
                return None
            self._recv_buf += chunk
        idx = self._recv_buf.index(b"\n")
        line = self._recv_buf[:idx]
        self._recv_buf = self._recv_buf[idx + 1:]
        return line

    def _readbytes(self, n: int) -> Optional[bytes]:
        """Read exactly n bytes from the socket (used for binary payloads)."""
        while len(self._recv_buf) < n:
            try:
                chunk = self._sock.recv(65536)
            except OSError:
                self.close()
                return None
            if not chunk:
                self.close()
                return None
            self._recv_buf += chunk
        data = self._recv_buf[:n]
        self._recv_buf = self._recv_buf[n:]
        return data

    def _command(self, cmd: dict) -> Optional[dict]:
        """Send one JSON command and return the parsed response dict."""
        if not self._sock:
            return None
        try:
            self._sock.sendall((json.dumps(cmd) + "\n").encode())
            line = self._readline()
            if line is None:
                return None
            return json.loads(line)
        except (OSError, json.JSONDecodeError) as e:
            logging.warning("MonitorClient: command %r failed: %s", cmd.get("type"), e)
            self.close()
            return None

    # ── Commands ─────────────────────────────────────────────────────────────

    def list_devices(self) -> Optional[list[dict]]:
        with self._lock:
            resp = self._command({"type": "list_devices"})
            return resp.get("devices") if resp and resp.get("ok") else None

    def configure_input(
        self,
        index: int,
        device: str,
        silence_threshold_dbfs: float,
        silence_seconds: int,
    ) -> bool:
        with self._lock:
            resp = self._command({
                "type": "configure_input",
                "input": index,
                "device": device,
                "silence_threshold_dbfs": silence_threshold_dbfs,
                "silence_seconds": silence_seconds,
            })
            ok = bool(resp and resp.get("ok"))
            if not ok:
                logging.error(
                    "MonitorClient: configure_input(%d, %r) failed: %s",
                    index, device, (resp or {}).get("error", "no response"),
                )
            return ok

    def set_fifo(self, path: str) -> bool:
        with self._lock:
            resp = self._command({"type": "set_fifo", "path": path})
            ok = bool(resp and resp.get("ok"))
            if not ok:
                logging.error(
                    "MonitorClient: set_fifo(%r) failed: %s",
                    path, (resp or {}).get("error", "no response"),
                )
            return ok

    def start_input(self, index: int) -> bool:
        with self._lock:
            resp = self._command({"type": "start_input", "input": index})
            ok = bool(resp and resp.get("ok"))
            if not ok:
                logging.error(
                    "MonitorClient: start_input(%d) failed: %s",
                    index, (resp or {}).get("error", "no response"),
                )
            return ok

    def stop_input(self, index: int) -> bool:
        with self._lock:
            resp = self._command({"type": "stop_input", "input": index})
            return bool(resp and resp.get("ok"))

    def set_allow_capture(self, index: int, allow: bool) -> bool:
        with self._lock:
            resp = self._command({
                "type": "set_allow_capture",
                "input": index,
                "allow": allow,
            })
            return bool(resp and resp.get("ok"))

    def set_eq(self, index: int, bands: list[dict]) -> bool:
        with self._lock:
            resp = self._command({"type": "set_eq", "input": index, "bands": bands})
            return bool(resp and resp.get("ok"))

    def set_gain(self, index: int, gain_db: float) -> bool:
        with self._lock:
            resp = self._command({"type": "set_gain", "input": index, "gain_db": gain_db})
            return bool(resp and resp.get("ok"))

    def get_status(self) -> Optional[dict]:
        """Return the parsed status dict, or None on failure."""
        with self._lock:
            return self._command({"type": "get_status"})

    def get_id_snapshot(self, index: int, max_seconds: int = 20) -> Optional[bytes]:
        """Return raw s16le mono 22050 Hz PCM bytes, or None on failure.

        Reads the JSON ack line, then reads the binary payload of exactly
        frames * 2 bytes as declared in the ack.  Returns an empty bytes
        object if the monitor reports zero frames available.
        """
        with self._lock:
            resp = self._command({
                "type": "get_id_snapshot",
                "input": index,
                "max_seconds": max_seconds,
            })
            if not resp or not resp.get("ok"):
                return None
            frames = resp.get("frames", 0)
            if frames <= 0:
                return b""
            return self._readbytes(frames * 2)


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
        owntone_output_offsets_ms: Optional[dict[str, int]] = None,
        gain_db: float = 0.0,
        eq_40hz_db: float = 0.0,
        eq_100hz_db: float = 0.0,
        eq_10khz_db: float = 0.0,
    ) -> None:
        self.input_index = input_index
        self.input_device = input_device
        self.silence_threshold_dbfs = silence_threshold_dbfs
        self.silence_seconds = silence_seconds
        self.fifo_path = fifo_path
        self.owntone_base_url = owntone_base_url
        self.owntone_output_name = owntone_output_name
        self.owntone_volume_percent = owntone_volume_percent
        self.owntone_output_offsets_ms = owntone_output_offsets_ms or {}
        self.gain_db = gain_db
        self.eq_40hz_db = eq_40hz_db
        self.eq_100hz_db = eq_100hz_db
        self.eq_10khz_db = eq_10khz_db

        # --- Now-playing metadata helpers ---
        self._nowplaying_cache = PersistentNowPlayingCache()
        self._nowplaying_publisher = OwntoneMetadataPipePublisher(fifo_path)
        self._vinyl_recognizer = (
            VinylRecognizer(self._nowplaying_cache, input_device)
            if VinylRecognizer else None
        )
        if self._vinyl_recognizer is None:
            logging.info("Input %d: vinyl recognizer unavailable.", input_index)
        self._current_nowplaying = (
            self._nowplaying_cache.get_manual_hint(input_device)
            or NowPlayingMetadata(
                title=f"Autostream ({input_device})",
                artist="Vinyl",
                album="Unknown Album",
            )
        )

        # --- Recognition state ---
        self._recognition_inflight = False
        self._recognition_attempt_count = 0

        # --- Status (updated by coordinator via _ingest_status) ---
        self.level_dbfs: float = -90.0
        self.detected_hz: float = 0.0
        self.is_silent: bool = True
        self.is_capturing: bool = False
        self._last_active_time: Optional[float] = None

        # --- allow_capture: set by coordinator; synced to daemon lazily ---
        self._allow_capture: bool = True
        self._allow_capture_sent: Optional[bool] = None  # last value sent to daemon

        # --- OwnTone retry state ---
        self._owntone_last_attempt: float = 0.0
        self._owntone_last_log: float = 0.0
        self._owntone_enabled_ok: bool = False
        self._capture_start_no_output_retry_at: float = 0.0
        self._capture_start_no_output_log_at: float = 0.0

        with _monitors_lock:
            all_monitors.append(self)

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

    def _ingest_status(self, status_entry: dict) -> str:
        """Update fields from a get_status() entry without firing callbacks.

        Returns 'started', 'stopped', or '' to indicate the capturing
        transition so the coordinator can fire callbacks in a second pass,
        after all monitors have been updated.
        """
        was_capturing = self.is_capturing

        self.level_dbfs  = float(status_entry.get("level_dbfs", -90.0))
        self.detected_hz = float(status_entry.get("detected_hz", 0.0))
        self.is_silent   = bool(status_entry.get("silent", True))
        self.is_capturing = bool(status_entry.get("capturing", False))

        if not self.is_silent:
            self._last_active_time = time.time()

        if self.is_capturing and not was_capturing:
            return "started"
        if not self.is_capturing and was_capturing:
            return "stopped"
        return ""

    def apply_allow_capture(self, client: "MonitorClient") -> None:
        """Send set_allow_capture to the daemon if the value has changed."""
        if self._allow_capture != self._allow_capture_sent:
            if client.set_allow_capture(self.input_index, self._allow_capture):
                self._allow_capture_sent = self._allow_capture

    def stop(self) -> None:
        """Release resources (call at shutdown)."""
        try:
            self._nowplaying_publisher.close()
        except Exception:
            pass

    # ── Capture transitions ──────────────────────────────────────────────────

    def _on_capture_started(self, was_idle: bool) -> None:
        """Called when the daemon transitions this channel to capturing."""
        tracker = _playback_tracker
        if tracker is not None:
            tracker.on_capture_started(self.input_index)

        self._owntone_enabled_ok = False
        self._owntone_last_attempt = 0.0   # force immediate attempt

        # If transitioning from fully idle, clear previous output selection
        # so we start from a known state.
        if self.owntone_base_url and was_idle:
            owntone_disable_all_outputs(self.owntone_base_url)

        self._maybe_retry_owntone(time.time())

        self._recognition_inflight = False
        self._recognition_attempt_count = 0

        self._nowplaying_publisher.publish_start(self._current_nowplaying)

        logging.info(
            "Input %d (%s): capture started.",
            self.input_index, self.input_device,
        )

    def _on_capture_stopped(self, client: "MonitorClient") -> None:
        """Called when the daemon transitions this channel out of capturing."""
        tracker = _playback_tracker
        if tracker is not None:
            tracker.on_capture_stopped(self.input_index)

        self._owntone_enabled_ok = False

        # Request a PCM snapshot for track recognition before signalling stop.
        self._trigger_recognition(client)

        try:
            self._nowplaying_publisher.publish_end()
        except Exception:
            pass

        if self.owntone_base_url and not any_monitor_capturing():
            self._request_owntone_stop("capture stop")

        logging.info(
            "Input %d (%s): capture stopped.",
            self.input_index, self.input_device,
        )

    # ── Track recognition ────────────────────────────────────────────────────

    def _trigger_recognition(self, client: "MonitorClient") -> None:
        """Fetch an ID snapshot from the daemon and queue recognition."""
        if self._vinyl_recognizer is None:
            return
        if self._recognition_inflight:
            logging.info(
                "Input %d: skipping recognition (prior attempt still running).",
                self.input_index,
            )
            return

        pcm_bytes = client.get_id_snapshot(self.input_index, max_seconds=20)
        if not pcm_bytes:
            logging.info(
                "Input %d: get_id_snapshot returned no audio; skipping recognition.",
                self.input_index,
            )
            return

        self._recognition_attempt_count += 1
        attempt_no = self._recognition_attempt_count
        self._recognition_inflight = True

        duration_s = len(pcm_bytes) / (22050 * 2)
        logging.info(
            "Input %d: recognition attempt %d queued (%.1f s of audio).",
            self.input_index, attempt_no, duration_s,
        )

        threading.Thread(
            target=self._recognize_nowplaying_worker,
            args=(bytes(pcm_bytes), 22050, attempt_no),
            daemon=True,
        ).start()

    def _recognize_nowplaying_worker(
        self,
        pcm16_mono: bytes,
        samplerate: int,
        attempt_no: int,
    ) -> None:
        """Resolve metadata in the background and publish updates if found."""
        try:
            if self._vinyl_recognizer is None:
                return
            meta, source = self._vinyl_recognizer.resolve_with_source(pcm16_mono, samplerate)
            if not meta:
                logging.info(
                    "Input %d: recognition attempt %d found no metadata.",
                    self.input_index, attempt_no,
                )
                return

            changed = meta != self._current_nowplaying
            self._current_nowplaying = meta
            if changed:
                self._nowplaying_publisher.publish_start(meta)
                logging.info(
                    "Input %d: now-playing updated (%s): artist=%s album=%s title=%s",
                    self.input_index, source,
                    meta.artist, meta.album, meta.title,
                )
            else:
                logging.info(
                    "Input %d: recognition attempt %d matched existing metadata (%s).",
                    self.input_index, attempt_no, source,
                )
        except Exception as e:
            logging.info("Input %d: recognition failed: %s", self.input_index, e)
        finally:
            self._recognition_inflight = False

    # ── OwnTone helpers ──────────────────────────────────────────────────────

    def _request_owntone_stop(self, reason: str) -> None:
        """Send a player stop command to OwnTone."""
        _stop_and_disable_owntone(self.owntone_base_url, reason)

    def _maybe_retry_owntone(self, now: float) -> None:
        """Periodically retry refreshing currently selected OwnTone outputs."""
        if not self.is_capturing:
            return
        if not self.owntone_base_url:
            return
        if self._owntone_enabled_ok:
            return
        if (now - self._owntone_last_attempt) < self.OWNTONE_RETRY_SECONDS:
            return
        self._owntone_last_attempt = now

        outputs = self._get_owntone_outputs()
        if outputs is None:
            self._throttled_owntone_log(
                now,
                logging.WARNING,
                "Skipping OwnTone selected-output refresh: outputs API unavailable.",
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
            "OwnTone selected-output refresh failed during capture; will retry.",
        )

    def _throttled_owntone_log(self, now: float, level: int, msg: str, *args) -> None:
        """Log OwnTone-related failures with a long throttle to avoid SD churn."""
        if (now - self._owntone_last_log) < self.OWNTONE_LOG_THROTTLE_SECONDS:
            return
        self._owntone_last_log = now
        logging.log(level, msg, *args)

    def _get_owntone_outputs(self) -> Optional[list[dict]]:
        """Return OwnTone outputs list, or None if API is unavailable."""
        if not self.owntone_base_url:
            return None
        try:
            resp = requests.get(
                self.owntone_base_url.rstrip("/") + "/api/outputs", timeout=3,
            )
            if not resp.ok:
                return None
            outputs = (resp.json() or {}).get("outputs", [])
            return outputs if isinstance(outputs, list) else None
        except Exception:
            return None

    @staticmethod
    def _selected_output_ids(outputs: list[dict]) -> list[str]:
        return [
            str(o.get("id"))
            for o in outputs
            if o.get("selected") and o.get("id") is not None
        ]

    def _has_any_selected_outputs(self, outputs: Optional[list[dict]] = None) -> bool:
        """Return True if OwnTone currently has at least one selected output."""
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
                now, logging.WARNING,
                "Could not fetch OwnTone outputs for default fallback (%s).", reason,
            )
            return False
        if self._has_any_selected_outputs(outputs):
            return True

        default_name = (self.owntone_output_name or "").strip()
        if not default_name:
            self._throttled_owntone_log(
                now, logging.WARNING,
                "No default output configured; cannot apply zero-target fallback (%s).",
                reason,
            )
            return False

        default_out = next(
            (o for o in outputs if str(o.get("name") or "") == default_name),
            None,
        )
        if not default_out or default_out.get("id") is None:
            self._throttled_owntone_log(
                now, logging.WARNING,
                "Default output '%s' not found in OwnTone; cannot apply fallback (%s).",
                default_name, reason,
            )
            return False

        out_id = str(default_out.get("id"))
        base = self.owntone_base_url.rstrip("/")
        try:
            out_volume = int(self.owntone_volume_percent)
        except Exception:
            out_volume = 20
        out_volume = max(0, min(100, out_volume))
        payload: dict[str, object] = {"selected": True, "volume": out_volume}
        offset_val = self.owntone_output_offsets_ms.get(out_id)
        if offset_val is not None:
            try:
                payload["offset_ms"] = max(-2000, min(2000, int(offset_val)))
            except Exception:
                pass

        try:
            resp = requests.put(
                base + f"/api/outputs/{out_id}", json=payload, timeout=3,
            )
            if not resp.ok:
                self._throttled_owntone_log(
                    now, logging.WARNING,
                    "Failed to auto-enable default output '%s' (%s): status=%s body=%s",
                    default_name, reason, resp.status_code, (resp.text or "")[:200],
                )
                return False
            logging.info(
                "No outputs selected; auto-enabled default output '%s' (%s).",
                default_name, reason,
            )
            return True
        except Exception as e:
            self._throttled_owntone_log(
                now, logging.WARNING,
                "Failed to auto-enable default output '%s' (%s): %s",
                default_name, reason, e,
            )
            return False

    def _refresh_selected_outputs(self, outputs: Optional[list[dict]] = None) -> bool:
        """Re-apply current selected output IDs to nudge OwnTone playback state."""
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
            set_resp = requests.put(
                base + "/api/outputs/set", json=set_payload, timeout=3,
            )
            if not set_resp.ok:
                return False
            logging.info("Refreshed selected OwnTone outputs: %s", selected_ids)
            return True
        except Exception:
            return False


# --------------------------------------------------------------------------- #
# Top-level entry points                                                       #
# --------------------------------------------------------------------------- #

def _resync_monitor_daemon(
    client: MonitorClient,
    monitors: list["AudioMonitor"],
    fifo_path: str,
) -> bool:
    """Re-send the full daemon state after reconnect.

    This is transactional from Python's point of view: if any required step
    fails for any configured monitor, the whole resync is treated as failed so
    the coordinator does not continue with Python-side monitor objects that do
    not exist in the daemon.
    """
    if not ensure_audio_fifo(fifo_path):
        client.close()
        return False

    if not client.set_fifo(fifo_path):
        logging.warning("set_fifo failed after reconnect; will retry.")
        client.close()
        return False

    for m in monitors:
        m._allow_capture_sent = None

    # Stop all inputs before reconfiguring.  The daemon may not have restarted
    # (the connection could have dropped due to a transient timeout while the
    # coordinator was blocked in OwnTone callbacks), in which case the inputs
    # are still running and configure_input / start_input would fail.
    # api_stop_input is idempotent — it is a safe no-op if the input is not
    # currently started.
    for m in monitors:
        client.stop_input(m.input_index)

    for m in monitors:
        if not client.configure_input(
            m.input_index,
            m.input_device,
            m.silence_threshold_dbfs,
            m.silence_seconds,
        ):
            logging.warning(
                "configure_input(%d, %r) failed after reconnect; will retry full resync.",
                m.input_index,
                m.input_device,
            )
            client.close()
            return False

    for m in monitors:
        if not client.start_input(m.input_index):
            logging.warning(
                "start_input(%d) failed after reconnect; will retry full resync.",
                m.input_index,
            )
            client.close()
            return False

    for m in monitors:
        if not apply_input_gain(client, m.input_index, m.gain_db):
            logging.warning(
                "set_gain(%d, %.1f) failed after reconnect; will retry full resync.",
                m.input_index,
                m.gain_db,
            )
            client.close()
            return False

    for m in monitors:
        if not apply_input_eq(
            client,
            m.input_index,
            m.eq_40hz_db,
            m.eq_100hz_db,
            m.eq_10khz_db,
        ):
            logging.warning(
                "set_eq(%d) failed after reconnect; will retry full resync.",
                m.input_index,
            )
            client.close()
            return False

    for m in monitors:
        if not client.set_allow_capture(m.input_index, m._allow_capture):
            logging.warning(
                "set_allow_capture(%d, %r) failed after reconnect; will retry full resync.",
                m.input_index,
                m._allow_capture,
            )
            client.close()
            return False
        m._allow_capture_sent = m._allow_capture

    return True


def _configure_startup_monitors(
    client: MonitorClient,
    cfg,
    fifo_path: str,
) -> Optional[list["AudioMonitor"]]:
    """Configure daemon inputs for initial startup and return monitor objects."""
    # Defensively stop both inputs before configuring.  If a previous reload
    # left the daemon with inputs still running (e.g. stop_input in the finally
    # block failed silently due to a lost connection), configure_input and
    # start_input would otherwise fail.  api_stop_input is idempotent.
    client.stop_input(1)
    client.stop_input(2)

    if not client.configure_input(
        1,
        cfg.audio1.capture_device,
        cfg.audio1.silence_threshold_dbfs,
        cfg.general.silence_seconds,
    ):
        logging.warning(
            "configure_input(1, %r) failed during startup; will retry.",
            cfg.audio1.capture_device,
        )
        return None

    if not client.start_input(1):
        logging.warning("start_input(1) failed during startup; will retry.")
        return None

    if not apply_input_gain(client, 1, cfg.audio1.gain_db):
        logging.warning("set_gain(1) failed during startup; will retry.")
        return None

    if not apply_input_eq(
        client,
        1,
        cfg.audio1.eq_40hz_db,
        cfg.audio1.eq_100hz_db,
        cfg.audio1.eq_10khz_db,
    ):
        logging.warning("set_eq(1) failed during startup; will retry.")
        return None

    monitors: list[AudioMonitor] = [AudioMonitor(
        input_index=1,
        input_device=cfg.audio1.capture_device,
        silence_threshold_dbfs=cfg.audio1.silence_threshold_dbfs,
        silence_seconds=cfg.general.silence_seconds,
        fifo_path=fifo_path,
        owntone_base_url=cfg.owntone.base_url,
        owntone_output_name=cfg.owntone.output_name,
        owntone_volume_percent=cfg.owntone.volume_percent,
        owntone_output_offsets_ms=cfg.owntone.output_offsets_ms,
        gain_db=cfg.audio1.gain_db,
        eq_40hz_db=cfg.audio1.eq_40hz_db,
        eq_100hz_db=cfg.audio1.eq_100hz_db,
        eq_10khz_db=cfg.audio1.eq_10khz_db,
    )]

    if (
        cfg.audio2_enabled
        and cfg.audio2.capture_device
        and cfg.audio2.capture_device != cfg.audio1.capture_device
    ):
        audio2_ok = True

        if not client.configure_input(
            2,
            cfg.audio2.capture_device,
            cfg.audio2.silence_threshold_dbfs,
            cfg.general.silence_seconds,
        ):
            logging.error(
                "configure_input(2, %r) failed; skipping second input.",
                cfg.audio2.capture_device,
            )
            audio2_ok = False

        if audio2_ok and not client.start_input(2):
            logging.error("start_input(2) failed; skipping second input.")
            audio2_ok = False

        if audio2_ok and not apply_input_gain(client, 2, cfg.audio2.gain_db):
            logging.error("set_gain(2) failed; skipping second input.")
            audio2_ok = False

        if audio2_ok and not apply_input_eq(
            client,
            2,
            cfg.audio2.eq_40hz_db,
            cfg.audio2.eq_100hz_db,
            cfg.audio2.eq_10khz_db,
        ):
            logging.error("set_eq(2) failed; skipping second input.")
            audio2_ok = False

        if audio2_ok:
            monitors.append(AudioMonitor(
                input_index=2,
                input_device=cfg.audio2.capture_device,
                silence_threshold_dbfs=cfg.audio2.silence_threshold_dbfs,
                silence_seconds=cfg.general.silence_seconds,
                fifo_path=fifo_path,
                owntone_base_url=cfg.owntone.base_url,
                owntone_output_name=cfg.owntone.output_name,
                owntone_volume_percent=cfg.owntone.volume_percent,
                owntone_output_offsets_ms=cfg.owntone.output_offsets_ms,
                gain_db=cfg.audio2.gain_db,
                eq_40hz_db=cfg.audio2.eq_40hz_db,
                eq_100hz_db=cfg.audio2.eq_100hz_db,
                eq_10khz_db=cfg.audio2.eq_10khz_db,
            ))

    if len(monitors) > 1:
        for m in monitors:
            m.allow_capture = False

    for m in monitors:
        m.apply_allow_capture(client)

    return monitors

def run_autostream(config_path: str, start_webui=None) -> None:
    """Run autostream using the given config file path.

    Connects to the autostream_monitor daemon, configures inputs, and runs
    the coordinator loop until a stop signal is received.

    If start_webui is provided it is called with config_path to start the
    optional web UI in a background thread.
    """
    cfg = load_and_parse(config_path)
    setup_logging(cfg.general.log_file)
    _ensure_playback_tracker(cfg)

    # --- Ensure OwnTone config is correct before doing anything else ---
    cfg_status = owntone_config_ok()
    if cfg_status == OWNTONE_OK:
        logging.info(
            "OwnTone config OK (directories=/tmp/autostream-pipes).",
        )
    elif cfg_status == OWNTONE_RESTART_REQUIRED:
        logging.warning(
            "OwnTone config was updated; OwnTone restart required.",
        )
        try:
            if owntone_restart_service():
                logging.info("Requested OwnTone restart via autostream-admin.")
            else:
                logging.warning("OwnTone restart request failed (autostream-admin).")
        except Exception as e:
            logging.warning("Could not restart OwnTone automatically: %s", e)
    else:
        logging.error(
            "OwnTone config NOT OK and could not be fixed. Playback via pipe may fail.",
        )

    # Optionally start the web UI.
    if start_webui is not None:
        try:
            start_webui(config_path)
        except Exception as e:
            logging.error("Failed to start web UI: %s", e)

    socket_path = get_monitor_socket_path()
    POLL_INTERVAL = 0.5          # seconds between get_status() polls
    SWITCH_SILENCE_SECONDS = 5.0 # how long current input must be silent before switching

    # Outer loop: runs once normally; repeats after a config reload.
    while not stop_flag.is_set():
        client = MonitorClient(socket_path)
        monitors: Optional[list[AudioMonitor]] = None

        # ── Startup / configuration phase ────────────────────────────────────
        while not stop_flag.is_set():
            if unconfigured(config_path):
                if start_webui is None:
                    logging.error("Configuration is incomplete; cannot start without a valid INI.")
                    return
                logging.info(
                    "Configuration is incomplete or has an invalid device format; "
                    "starting in setup mode and waiting for Web UI changes.",
                )
                while not stop_flag.is_set() and unconfigured(config_path):
                    time.sleep(1.0)
                if stop_flag.is_set():
                    return
                cfg = load_and_parse(config_path)
                continue

            cfg = load_and_parse(config_path)
            fifo_path = cfg.general.fifo_path
            _ensure_playback_tracker(cfg)

            if not client.connect():
                logging.warning(
                    "Cannot connect to autostream_monitor at %s; retrying in 5 s.",
                    socket_path,
                )
                time.sleep(5.0)
                continue

            if not ensure_audio_fifo(fifo_path):
                client.close()
                time.sleep(5.0)
                continue

            if not client.set_fifo(fifo_path):
                logging.warning("set_fifo(%r) failed during startup; retrying in 5 s.", fifo_path)
                client.close()
                time.sleep(5.0)
                continue

            if cfg.owntone.base_url:
                if owntone_ensure_pipe_indexed(cfg.owntone.base_url, timeout_s=15.0):
                    logging.info("OwnTone pipe source is indexed and ready.")
                else:
                    logging.warning(
                        "OwnTone pipe source is not indexed yet; "
                        "playback start may fail until files rescan succeeds.",
                    )

                # Check pipe_autostart and loglevel via the settings API.
                # Falls back silently on older OwnTone builds that lack these endpoints.
                api_needs_restart = owntone_check_api_settings(cfg.owntone.base_url)
                if api_needs_restart:
                    logging.warning(
                        "OwnTone API settings were corrected; restarting OwnTone."
                    )
                    try:
                        if owntone_restart_service():
                            logging.info(
                                "Requested OwnTone restart (API settings fix)."
                            )
                            owntone_ensure_pipe_indexed(
                                cfg.owntone.base_url, timeout_s=15.0
                            )
                        else:
                            logging.warning(
                                "OwnTone restart request failed (API settings fix)."
                            )
                    except Exception as e:
                        logging.warning(
                            "Could not restart OwnTone after API settings fix: %s", e
                        )

            monitors = _configure_startup_monitors(client, cfg, fifo_path)
            if monitors is not None:
                break

            client.close()
            time.sleep(5.0)

        if stop_flag.is_set() or monitors is None:
            client.close()
            return

        logging.info(
            "autostream_core is now running with %d input(s). Press Ctrl+C to exit.",
            len(monitors),
        )

        current: Optional[AudioMonitor] = None
        reconnect_at: float = 0.0
        _reloading = False

        try:
            while not stop_flag.is_set():

                # ── Config reload requested by Web UI ────────────────────────
                if reload_flag.is_set():
                    reload_flag.clear()
                    _reloading = True
                    logging.info("Config reload requested; tearing down monitors.")
                    break

                # ── Reconnect if the socket was lost ─────────────────────────
                if not client.is_connected():
                    now = time.time()
                    if now < reconnect_at:
                        time.sleep(min(1.0, reconnect_at - now))
                        continue

                    if not client.connect():
                        logging.warning(
                            "autostream_monitor unavailable; retrying in 5 s.",
                        )
                        reconnect_at = time.time() + 5.0
                        continue

                    # Reconnected: re-send the full configuration because the
                    # daemon may have restarted and lost its state.
                    if not _resync_monitor_daemon(client, monitors, fifo_path):
                        reconnect_at = time.time() + 5.0
                        current = None
                        continue

                # ── Poll status ───────────────────────────────────────────────
                status = client.get_status()
                if status is None:
                    logging.warning("get_status() failed; will reconnect.")
                    reconnect_at = time.time() + 2.0
                    continue

                status_by_index = {
                    e["index"]: e for e in status.get("inputs", [])
                }

                # Two-pass update so that callbacks see the final state of ALL
                # monitors, not a partially-updated snapshot.  This prevents
                # spurious OwnTone stop/disable when one input hands off to
                # another in the same poll cycle.
                was_any_capturing = any_monitor_capturing()
                started: list[AudioMonitor] = []
                stopped: list[AudioMonitor] = []

                for m in monitors:
                    if m.input_index in status_by_index:
                        transition = m._ingest_status(status_by_index[m.input_index])
                        if transition == "started":
                            started.append(m)
                        elif transition == "stopped":
                            stopped.append(m)

                # Fire stopped callbacks first so any_monitor_capturing() is
                # already correct when started callbacks check it.
                for m in stopped:
                    m._on_capture_stopped(client)
                was_idle = not was_any_capturing
                for m in started:
                    m._on_capture_started(was_idle)

                # ── Multi-input coordination ──────────────────────────────────
                if len(monitors) == 1:
                    monitors[0].allow_capture = True
                    current = monitors[0]
                else:
                    # Rank inputs that are currently above their silence threshold
                    # by level, highest first.
                    loud = sorted(
                        [m for m in monitors if not m.is_silent],
                        key=lambda m: m.level_dbfs,
                        reverse=True,
                    )
                    candidate = loud[0] if loud else None
                    new_current = current

                    if current is None or not current.is_capturing:
                        # Nothing playing: pick any loud candidate.
                        if candidate is not None:
                            new_current = candidate
                    else:
                        silent_for = current.seconds_since_last_activity
                        if (
                            candidate is not None
                            and candidate is not current
                            and SWITCH_SILENCE_SECONDS <= silent_for < current.silence_seconds
                        ):
                            # Current has been silent long enough but not timed
                            # out yet; hand off to the louder candidate.
                            new_current = candidate

                    if new_current is not current:
                        for m in monitors:
                            m.allow_capture = m is new_current
                        current = new_current
                        if current is not None:
                            logging.info(
                                "Switched active input to %s.", current.input_device,
                            )
                        else:
                            logging.info("No active input selected.")

                # ── Flush pending allow_capture changes and OwnTone retries ───
                for m in monitors:
                    m.apply_allow_capture(client)
                    m._maybe_retry_owntone(time.time())

                tracker = _playback_tracker
                if tracker is not None:
                    tracker.maybe_flush()

                time.sleep(POLL_INTERVAL)

        except Exception as e:
            logging.error("Unexpected error: %s", e)

        finally:
            tracker = _playback_tracker
            teardown_was_capturing = any(m.is_capturing for m in monitors)
            teardown_owntone_base_url = next(
                (m.owntone_base_url for m in monitors if m.owntone_base_url),
                "",
            )
            if teardown_was_capturing and teardown_owntone_base_url:
                _stop_and_disable_owntone(
                    teardown_owntone_base_url,
                    "coordinator teardown",
                )
            for m in monitors:
                if tracker is not None:
                    tracker.on_capture_stopped(m.input_index)
                client.stop_input(m.input_index)
                m.stop()
            if tracker is not None:
                tracker.save()
            with _monitors_lock:
                all_monitors.clear()
            client.close()
            if not _reloading:
                logging.info("Stopped cleanly.")

        if not _reloading:
            break
        # _reloading: continue outer loop → startup phase runs again with fresh config


def main() -> None:
    """CLI entry point for running autostream without the web UI."""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} PATH_TO_CONFIG.ini")
        sys.exit(1)

    run_autostream(sys.argv[1])


if __name__ == "__main__":
    main()
