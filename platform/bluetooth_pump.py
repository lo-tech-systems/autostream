#!/usr/bin/python3
"""bluetooth_pump.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

The ALSA loopback feeder for the autostream_bluetooth daemon. Holds the
loopback playback PCM
(``hw:CARD=ASBT,DEV=0``) open for the daemon's lifetime and, depending on
whether an A2DP transport is currently active, feeds it either zero-fill
silence or a copy of the BlueALSA capture stream.

This is the load-bearing detail of the whole feature: the loopback capture
side's clock is driven entirely by writes on the playback side, so a gap in
writes (e.g. closing DEV=0 between transports) would stall the monitor's
``snd_pcm_readi`` instead of reading clean silence. The zero-fill path must
therefore never close the playback handle.

The playback ring is pre-filled with zero periods on every (re)open as a
jitter cushion for bursty A2DP delivery. The number of periods is derived
from a configurable buffer size in milliseconds (``buffer_ms``,
``set_buffer_ms()``), rounded *up* to whole ALSA periods at the rate the
playback PCM is being opened at: ``ceil(buffer_ms * rate / 1000 /
period_frames)``. The ALSA ring itself is requested a few periods larger
than the prefill so writes have somewhere to land; if the device negotiates
a smaller ring than requested, the prefill is clamped to what actually fits
and the effective value is logged (never surfaced to callers — the caller
only ever sees the ``buffer_ms`` it configured). A ``set_buffer_ms()`` call
takes effect on the next (re)open (rate change, recovery, or startup) —
never by force-reopening a stream already in progress.

``python3-alsaaudio`` is imported lazily (inside ``start()``, not at module
import time) because dev machines and the WSL test runner do not have it
installed; ``alsaaudio_module`` is injectable so tests can supply a fake.
"""
from __future__ import annotations

import logging
import math
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_PLAYBACK_DEVICE = "hw:CARD=ASBT,DEV=0"
DEFAULT_RATE = 44100
DEFAULT_CHANNELS = 2
DEFAULT_PERIOD_FRAMES = 512
BYTES_PER_SAMPLE = 2  # S16_LE

# Rate-follow fallback: if opening BlueALSA capture at
# the rate the transport claims (or the pump's currently-expected rate) fails,
# retry through these two rates before giving up for this step (44.1 kHz is
# by far the common A2DP case; 48 kHz is the other one BlueZ negotiates).
CAPTURE_RATE_FALLBACKS = (44100, 48000)

# Throttle for the "capture stalled/failed to open" warning so a persistently
# absent/misbehaving transport does not spam the log every ~12ms period.
STALL_LOG_THROTTLE_SECONDS = 30.0

# Configurable audio buffer: nominal milliseconds, rounded up to whole
# periods at apply time (see module docstring / compute_prefill_periods()).
DEFAULT_BUFFER_MS = 200
MIN_BUFFER_MS = 100
MAX_BUFFER_MS = 500

# The ALSA ring is requested this many periods larger than the computed
# prefill, so writes past the prefill have headroom before catching the
# read/write pointer.
PLAYBACK_RING_HEADROOM_PERIODS = 4

# Retry pacing for a loopback playback open refused over a parameter
# mismatch (see _open_playback): the shared snd-aloop cable takes its
# rate/format from whichever end opened first, so if the capture side is
# currently holding it at parameters other than the pump's, reopening is
# pointless until that side releases/reopens. Retrying on this pace keeps
# the pump responsive to the cable freeing up without busy-spinning.
PLAYBACK_PIN_RETRY_SECONDS = 2.0

# ALSA rate negotiation can report a timer-derived neighbour of the real
# rate (e.g. 47999 for a 48000 cable); treat rates within this distance as
# equal when verifying granted parameters.
RATE_MATCH_TOLERANCE_HZ = 2


def compute_prefill_periods(buffer_ms: int, rate: int, period_frames: int) -> int:
    """Whole ALSA periods needed to cover *buffer_ms* at *rate*, rounded up.

    Pure function shared by the pump and its tests so the rounding rule
    lives in exactly one place: ``ceil(buffer_ms * rate / 1000 /
    period_frames)`` (e.g. 200 ms @ 44100 Hz / 512-frame periods -> 18
    periods; 200 ms @ 48000 Hz -> 19 periods).
    """
    return math.ceil(buffer_ms * rate / 1000 / period_frames)


class AlsaUnavailable(RuntimeError):
    """Raised when python3-alsaaudio is not importable."""


def _import_alsaaudio():
    try:
        import alsaaudio
    except ImportError as e:
        raise AlsaUnavailable(f"python3-alsaaudio is required: {e}") from e
    return alsaaudio


def bluealsa_capture_device(mac: str) -> str:
    """The BlueALSA capture PCM name for a connected A2DP source."""
    return f"bluealsa:DEV={mac},PROFILE=a2dp"


class LoopbackPump:
    """Feeds the loopback playback side for the daemon's lifetime.

    ``set_active_source()`` is called by the bluez layer when a
    MediaTransport1 object appears/disappears — the pump never polls for
    transport state. ``alsaaudio_module`` is injectable for tests; production
    code imports the real python3-alsaaudio lazily in ``start()``.
    """

    def __init__(
        self,
        playback_device: str = DEFAULT_PLAYBACK_DEVICE,
        rate: int = DEFAULT_RATE,
        channels: int = DEFAULT_CHANNELS,
        period_frames: int = DEFAULT_PERIOD_FRAMES,
        buffer_ms: int = DEFAULT_BUFFER_MS,
        alsaaudio_module=None,
    ) -> None:
        self._playback_device = playback_device
        self._rate = rate
        self._channels = channels
        self._period_frames = period_frames
        self._buffer_ms = buffer_ms
        self._alsaaudio = alsaaudio_module  # resolved (real or fake) at start()

        self._lock = threading.Lock()
        self._active_capture_device: Optional[str] = None
        self._capture_rate = rate
        # The rate the playback PCM is *currently open at* — may drift from
        # ``self._rate`` (the constructor default) once a transport negotiates
        # a non-default rate; see ``_maybe_reopen_playback``.
        self._playback_rate = rate

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._playback_pcm = None
        self._capture_pcm = None
        self._last_stall_log = 0.0
        # Parameter-mismatch retry state: monotonic time before which
        # _write_playback() must not attempt another open after a refused
        # one (see PLAYBACK_PIN_RETRY_SECONDS), and a separate log throttle
        # so the mismatch warning stays visible without spamming.
        self._playback_retry_at = 0.0
        self._last_pin_log = 0.0

    # ---- control surface (called from bluetooth_service on bluez callbacks) ----

    def set_active_source(self, capture_device: Optional[str], rate: Optional[int] = None) -> None:
        """Set (or, with None, clear) the BlueALSA capture device to copy from.

        None reverts the pump to zero-fill on the next iteration; the current
        capture handle (if any) is closed by the pump thread itself, never
        here, so this call never blocks on ALSA I/O.
        """
        with self._lock:
            self._active_capture_device = capture_device
            if rate:
                self._capture_rate = rate

    def set_buffer_ms(self, buffer_ms: int) -> None:
        """Update the configured audio buffer (thread-safe). Takes effect on
        the playback PCM's *next* (re)open — a stream already in progress is
        never force-reopened to pick this up (LLD / plan SS1 "Audio buffer")."""
        with self._lock:
            self._buffer_ms = buffer_ms

    def is_streaming(self) -> bool:
        with self._lock:
            return self._active_capture_device is not None and self._capture_pcm is not None

    def get_negotiated_rate(self) -> Optional[int]:
        """The rate the playback PCM is currently open at (thread-safe) --
        the ground truth of what BlueALSA negotiated. Meaningful only while
        streaming; callers should gate on ``is_streaming()``."""
        with self._lock:
            return self._playback_rate

    def holds_loopback(self) -> bool:
        """True while the pump holds a verified open on the loopback
        playback end (thread-safe) -- i.e. the shared cable currently
        carries the pump's rate/format, so a capture-side open will
        negotiate to matching parameters. False during startup, and while
        a parameter mismatch has the pump paused/retrying."""
        with self._lock:
            return self._playback_pcm is not None

    def playback_locked_out(self) -> bool:
        """True while the shared loopback cable is held at incompatible
        parameters by its other end and the pump is pausing rather than
        writing garbled audio (thread-safe). False during startup before the
        first open attempt, and clears itself once a reopen succeeds.
        Recovery requires the other end to release/renegotiate the cable —
        the pump alone cannot force it."""
        with self._lock:
            return self._playback_pcm is None and self._playback_retry_at > 0

    def has_active_source(self) -> bool:
        """True once a capture device has been *set* (``set_active_source``),
        even before the pump thread has actually opened it — distinct from
        ``is_streaming()``, which additionally requires the capture PCM to be
        open. Used by the pair-success hook to tell "nothing armed yet" apart
        from "armed but not yet opened"."""
        with self._lock:
            return self._active_capture_device is not None

    # ---- lifecycle ----

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("LoopbackPump.start() called twice")
        alsaaudio = self._alsaaudio or _import_alsaaudio()
        self._alsaaudio = alsaaudio
        self._playback_pcm = self._open_playback(alsaaudio)
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="bt-pump", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        self._close_capture()
        if self._playback_pcm is not None:
            try:
                self._playback_pcm.close()
            except Exception:
                pass
            self._playback_pcm = None

    # ---- internals ----

    def _query_negotiated_periods(self, pcm) -> Optional[int]:
        """Best-effort read of the periods ALSA actually granted for *pcm*,
        via pyalsaaudio's ``PCM.info()`` where available. Returns ``None``
        when undeterminable (older pyalsaaudio without ``info()``, or an
        unexpected return shape) — callers then assume the requested count
        was honoured rather than guessing at a clamp."""
        try:
            info = pcm.info()
        except AttributeError:
            return None
        except Exception:
            return None
        if not isinstance(info, dict):
            return None
        periods = info.get("periods")
        if isinstance(periods, int) and not isinstance(periods, bool) and periods > 0:
            return periods
        return None

    def _verify_playback_params(self, pcm, granted_rate, granted_format, alsaaudio):
        """Compare what the device actually granted against what was
        requested. Ground truth is ``pcm.info()`` where available (same
        graceful-degradation contract as _query_negotiated_periods()); the
        ``setrate()``/``setformat()`` return values are the fallback for
        pyalsaaudio builds whose ``info()`` lacks rate/format fields. When
        neither source can prove a mismatch, the open is trusted.

        Returns a human-readable mismatch description, or None when the
        parameters match. This matters specifically on the shared snd-aloop
        cable: rate and format there are pinned by whichever end opened
        first, and ALSA grants the pinned values rather than failing the
        open -- S16-framed writes into a cable pinned at another rate or a
        wider format come out the capture side as noise, so a mismatched
        open must never be written to.
        """
        actual_rate: Optional[int] = None
        format_matches: Optional[bool] = None

        info = None
        try:
            info = pcm.info()
        except Exception:
            pass
        if isinstance(info, dict):
            r = info.get("rate")
            if isinstance(r, int) and not isinstance(r, bool) and r > 0:
                actual_rate = r
            fname = info.get("format_name")
            if isinstance(fname, str) and fname:
                format_matches = fname == "S16_LE"

        if actual_rate is None and isinstance(granted_rate, int) \
                and not isinstance(granted_rate, bool) and granted_rate > 0:
            actual_rate = granted_rate
        if format_matches is None and granted_format is not None:
            format_matches = granted_format == alsaaudio.PCM_FORMAT_S16_LE

        problems = []
        if actual_rate is not None and abs(actual_rate - self._rate) > RATE_MATCH_TOLERANCE_HZ:
            problems.append(f"rate {actual_rate} Hz (wanted {self._rate} Hz)")
        if format_matches is False:
            problems.append("format not S16_LE")
        return "; ".join(problems) if problems else None

    def _log_pin(self, msg: str, *args) -> None:
        now = time.monotonic()
        if now - self._last_pin_log >= STALL_LOG_THROTTLE_SECONDS:
            logger.warning(msg, *args)
            self._last_pin_log = now

    def _open_playback(self, alsaaudio):
        """Open, verify, and prefill the loopback playback PCM.

        Returns the open PCM, or None when the device would not grant the
        requested rate/format (the shared cable is currently pinned by its
        other end at incompatible parameters). None means "do not write":
        the caller-visible pump state is 'not holding the loopback', and
        _write_playback() retries on PLAYBACK_PIN_RETRY_SECONDS pacing until
        the cable frees up. This is the one deliberate exception to the
        never-close-DEV=0 rule -- writing through a mismatched open would
        deliver noise to the capture side, which is strictly worse than the
        capture clock pausing until parameters agree.
        """
        with self._lock:
            buffer_ms = self._buffer_ms
        prefill_periods = compute_prefill_periods(buffer_ms, self._rate, self._period_frames)
        requested_periods = prefill_periods + PLAYBACK_RING_HEADROOM_PERIODS

        pcm = alsaaudio.PCM(
            alsaaudio.PCM_PLAYBACK, alsaaudio.PCM_NORMAL,
            device=self._playback_device, periods=requested_periods,
        )
        try:
            # Channel count is not verified: both loopback substream ends
            # are stereo by construction (the monitor's capture open is
            # hardcoded to 2 channels), so a channel pin cannot differ.
            pcm.setchannels(self._channels)
            granted_rate = pcm.setrate(self._rate)
            granted_format = pcm.setformat(alsaaudio.PCM_FORMAT_S16_LE)
            pcm.setperiodsize(self._period_frames)
            mismatch = self._verify_playback_params(pcm, granted_rate, granted_format, alsaaudio)
        except Exception as e:
            mismatch = f"parameter negotiation failed ({e})"

        if mismatch:
            self._log_pin(
                "bluetooth pump: loopback playback open refused -- %s on '%s'; "
                "the loopback is held at incompatible parameters by its other "
                "end; retrying every %.0fs (audio is paused, not garbled)",
                mismatch, self._playback_device, PLAYBACK_PIN_RETRY_SECONDS,
            )
            try:
                pcm.close()
            except Exception:
                pass
            self._playback_retry_at = time.monotonic() + PLAYBACK_PIN_RETRY_SECONDS
            return None

        # If the device negotiated a smaller ring than requested, clamp the
        # prefill to what actually fits rather than write into the read
        # pointer. Never surfaced beyond this log line — callers only see the
        # nominal buffer_ms they configured.
        negotiated = self._query_negotiated_periods(pcm)
        effective_prefill = prefill_periods
        if negotiated is not None and negotiated < prefill_periods:
            effective_prefill = negotiated
        logger.info(
            "bluetooth pump: loopback playback opened at %d Hz (buffer_ms=%d -> "
            "prefill=%d periods, requested ring=%d periods%s)",
            self._rate, buffer_ms, effective_prefill, requested_periods,
            "" if negotiated is None else f", negotiated ring={negotiated} periods",
        )

        # Pre-fill the playback ring so Bluetooth delivery jitter has a
        # cushion to eat into.  Without this the write cadence exactly
        # matches the capture cadence, the ring drains to empty on the first
        # late A2DP packet, and the next write raises EPIPE ("Broken pipe
        # [hw:CARD=ASBT,DEV=0]").
        zero = self._zero_period()
        for _ in range(effective_prefill):
            try:
                pcm.write(zero)
            except Exception:
                break
        return pcm

    def _recover_playback(self) -> None:
        """Reopen the playback PCM after an unrecoverable write error
        (typically an EPIPE underrun).  The brief close/reopen stalls the
        loopback capture clock for a few ms — unavoidable, and far better
        than the pump thread dying.  The reopen may itself be refused on a
        parameter mismatch (None), in which case the pump drops into the
        paused/retrying state instead of holding a handle it must not
        write to."""
        try:
            if self._playback_pcm is not None:
                self._playback_pcm.close()
        except Exception:
            pass
        self._playback_pcm = self._open_playback(self._alsaaudio)

    def _write_playback(self, data: bytes) -> None:
        """Write to the loopback, recovering (reopen + prefill) on ALSA
        errors such as underrun EPIPE instead of letting the exception kill
        the pump thread.

        While no verified playback handle exists (open refused over a
        parameter mismatch), this drops the period instead: a retry open is
        attempted no more often than PLAYBACK_PIN_RETRY_SECONDS, and the
        drop sleeps for roughly one period so the surrounding loop keeps
        real-time pace without busy-spinning."""
        if self._playback_pcm is None:
            if time.monotonic() >= self._playback_retry_at:
                self._playback_pcm = self._open_playback(self._alsaaudio)
            if self._playback_pcm is None:
                time.sleep(self._period_frames / float(self._rate or DEFAULT_RATE))
                return
        try:
            self._playback_pcm.write(data)
        except Exception as e:
            self._log_stall("loopback playback write failed (%s); reopening", e)
            self._recover_playback()
            if self._playback_pcm is None:
                return
            try:
                self._playback_pcm.write(data)
            except Exception:
                pass

    def _open_capture(self, alsaaudio, device: str, rate: int):
        pcm = alsaaudio.PCM(
            alsaaudio.PCM_CAPTURE, alsaaudio.PCM_NORMAL, device=device
        )
        pcm.setchannels(self._channels)
        pcm.setrate(rate)
        pcm.setformat(alsaaudio.PCM_FORMAT_S16_LE)
        pcm.setperiodsize(self._period_frames)
        return pcm

    def _open_capture_with_fallback(self, alsaaudio, device: str, wanted_rate: int):
        """Open BlueALSA capture at *wanted_rate*, falling back through
        ``CAPTURE_RATE_FALLBACKS`` on failure.

        Returns ``(pcm, rate)`` for the rate that actually opened. Raises the
        last exception seen if every rate fails.
        """
        rates = [wanted_rate] if wanted_rate else []
        for r in CAPTURE_RATE_FALLBACKS:
            if r not in rates:
                rates.append(r)

        last_exc: Optional[Exception] = None
        for r in rates:
            try:
                return self._open_capture(alsaaudio, device, r), r
            except Exception as e:
                last_exc = e
                continue
        assert last_exc is not None
        raise last_exc

    def _maybe_reopen_playback(self, rate: int) -> None:
        """Reopen the loopback playback PCM at *rate* if it differs from the
        rate it is currently open at (rate follow).

        The "never close DEV=0" rule (module docstring) only matters while
        capture is absent — the loopback capture side's clock stalls without
        a writer. A brief close/reopen exactly at transport-start, while we
        are about to immediately resume writing (now at the new rate), is
        acceptable and unavoidable: ALSA PCMs cannot change sample rate
        without being reopened.
        """
        if rate == self._playback_rate:
            return
        logger.info(
            "bluetooth pump: reopening loopback playback at %d Hz (was %d Hz)",
            rate, self._playback_rate,
        )
        try:
            self._playback_pcm.close()
        except Exception:
            pass
        self._rate = rate
        self._playback_pcm = self._open_playback(self._alsaaudio)
        if self._playback_pcm is not None:
            self._playback_rate = rate

    def _close_capture(self) -> None:
        if self._capture_pcm is not None:
            try:
                self._capture_pcm.close()
            except Exception:
                pass
            self._capture_pcm = None

    def _zero_period(self) -> bytes:
        return b"\x00" * (self._period_frames * self._channels * BYTES_PER_SAMPLE)

    def _log_stall(self, msg: str, *args) -> None:
        now = time.monotonic()
        if now - self._last_stall_log >= STALL_LOG_THROTTLE_SECONDS:
            logger.warning(msg, *args)
            self._last_stall_log = now

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._step()
            except Exception as e:
                # The pump thread must never die: a dead pump stalls the
                # loopback capture clock for the monitor. Log (throttled),
                # back off briefly, carry on.
                self._log_stall("pump step failed: %s", e)
                time.sleep(0.05)

    def _step(self) -> None:
        """One pump iteration: exposed separately from ``_run`` so tests can
        drive it deterministically (one call == one period) without a real
        background thread or a real blocking ALSA device.
        """
        with self._lock:
            wanted_device = self._active_capture_device
            wanted_rate = self._capture_rate

        if wanted_device is None:
            # No transport: zero-fill. Never close the playback handle — the
            # loopback capture side's clock depends on it staying open.
            self._close_capture()
            self._write_playback(self._zero_period())
            return

        if self._capture_pcm is None:
            try:
                self._capture_pcm, opened_rate = self._open_capture_with_fallback(
                    self._alsaaudio, wanted_device, wanted_rate
                )
            except Exception as e:
                self._log_stall("Failed to open BlueALSA capture %s: %s", wanted_device, e)
                self._write_playback(self._zero_period())
                return
            logger.info(
                "bluetooth pump: capture opened device=%s rate=%d", wanted_device, opened_rate,
            )
            self._maybe_reopen_playback(opened_rate)

        try:
            length, data = self._capture_pcm.read()
        except Exception as e:
            self._log_stall("BlueALSA capture read failed on %s: %s", wanted_device, e)
            self._close_capture()
            self._write_playback(self._zero_period())
            return

        if length <= 0 or not data:
            # Stall/EOF (device dropped mid-stream): revert to zeros without
            # closing DEV=0 (see module docstring); drop the capture handle so the next
            # iteration retries opening it if the source is still "active".
            self._log_stall("BlueALSA capture stalled/EOF on %s (len=%s)", wanted_device, length)
            self._close_capture()
            self._write_playback(self._zero_period())
            return

        self._write_playback(data)
