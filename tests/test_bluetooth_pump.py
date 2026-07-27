"""Tests for the loopback feeder (platform/bluetooth_pump.py).

Drives ``LoopbackPump._step()`` directly (one call == one ALSA period)
against a fake alsaaudio module, so the control-flow (no transport -> zeros;
transport active -> copy BlueALSA capture; stall/EOF -> revert to zeros
without closing the loopback playback handle) is deterministic and requires
no real thread or real ALSA device.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
for _p in (REPO_ROOT / "platform",):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)

import bluetooth_pump as pump_mod  # noqa: E402

MAC_A = "AA:BB:CC:DD:EE:01"


class FakePcm:
    """Fake alsaaudio.PCM: records writes, and reads/raises as configured."""

    def __init__(self, kind: str, mode, device: str, periods=None) -> None:
        self.kind = kind
        self.device = device
        self.closed = False
        self.writes: list[bytes] = []
        self.channels = None
        self.rate = None
        self.fmt = None
        self.period = None
        # The ring size the caller requested at construction, and what the
        # (fake) device actually negotiated -- tests set negotiated_periods
        # to something smaller than periods_requested to exercise the
        # clamp path, or set info_supported=False to simulate an older
        # pyalsaaudio without PCM.info().
        self.periods_requested = periods
        self.negotiated_periods = periods
        self.info_supported = True
        # read() queue: each item is either a (len, bytes) tuple or an
        # exception instance to raise.
        self._read_queue: list = []

    def info(self) -> dict:
        if not self.info_supported:
            raise AttributeError("info() not supported on this pyalsaaudio version")
        return {"periods": self.negotiated_periods}

    def setchannels(self, n):
        self.channels = n

    def setrate(self, r):
        self.rate = r

    def setformat(self, f):
        self.fmt = f

    def setperiodsize(self, p):
        self.period = p

    def write(self, data: bytes) -> None:
        if self.closed:
            raise RuntimeError("write on closed PCM")
        self.writes.append(data)

    def queue_read(self, length: int, data: bytes) -> None:
        self._read_queue.append((length, data))

    def queue_read_error(self, exc: Exception) -> None:
        self._read_queue.append(exc)

    def read(self):
        if not self._read_queue:
            # Default: a normal successful read (simulates BlueALSA already
            # streaming silence). Real ALSA capture blocks rather than
            # returning a short/empty read when healthy; tests that want to
            # exercise the stall/EOF path queue (0, b"") or an exception
            # explicitly instead of relying on an empty queue.
            return (1, b"\x00\x00\x00\x00")
        item = self._read_queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def close(self) -> None:
        self.closed = True


class FakeAlsaAudio:
    """Fake alsaaudio module: PCM(...) returns a FakePcm and records every
    handle it created, keyed by (kind, device), for assertions."""

    PCM_PLAYBACK = "playback"
    PCM_CAPTURE = "capture"
    PCM_NORMAL = "normal"
    PCM_FORMAT_S16_LE = "s16le"

    def __init__(self) -> None:
        self.opened: list[FakePcm] = []
        self.open_capture_should_fail: Exception | None = None

    def PCM(self, kind, mode, device, periods=None):
        if kind == self.PCM_CAPTURE and self.open_capture_should_fail is not None:
            raise self.open_capture_should_fail
        pcm = FakePcm(kind, mode, device, periods=periods)
        self.opened.append(pcm)
        return pcm


# Small, deterministic default so unrelated tests (copy/stall/zero-fill logic)
# don't drown in prefill writes; the buffer-configuration tests below pick
# their own rate/period_frames/buffer_ms combinations explicitly.
def _make_pump(
    period_frames: int = 4, rate: int = 44100, buffer_ms: int = 1,
) -> tuple[pump_mod.LoopbackPump, FakeAlsaAudio]:
    fake = FakeAlsaAudio()
    pump = pump_mod.LoopbackPump(
        period_frames=period_frames, rate=rate, buffer_ms=buffer_ms, alsaaudio_module=fake,
    )
    # Manually perform what start() does, without spawning the real thread,
    # so _step() can be driven synchronously.
    pump._playback_pcm = pump._open_playback(fake)
    return pump, fake


def _expected_prefill(pump: pump_mod.LoopbackPump) -> int:
    """The prefill period count _make_pump's own _open_playback() call
    should have used, computed the same way production code does."""
    return pump_mod.compute_prefill_periods(pump._buffer_ms, pump._rate, pump._period_frames)


class TestZeroFillWhenNoTransport:
    def test_writes_zero_period_when_no_source_set(self):
        pump, fake = _make_pump(period_frames=4)
        pump._step()
        playback = fake.opened[0]
        assert playback.kind == "playback"
        expected = b"\x00" * (4 * 2 * 2)  # period * channels * bytes_per_sample
        # open() prefills the ring with the computed prefill periods; the
        # step then writes one more.
        assert playback.writes == [expected] * (_expected_prefill(pump) + 1)

    def test_never_closes_playback_handle_while_idle(self):
        pump, fake = _make_pump()
        for _ in range(5):
            pump._step()
        playback = fake.opened[0]
        assert playback.closed is False

    def test_no_capture_pcm_opened_without_a_source(self):
        pump, fake = _make_pump()
        pump._step()
        assert len(fake.opened) == 1  # playback only


class TestTransportActiveCopiesCapture:
    def test_opens_capture_device_lazily_on_first_active_step(self):
        pump, fake = _make_pump()
        device = pump_mod.bluealsa_capture_device(MAC_A)
        pump.set_active_source(device)
        pump._step()
        assert len(fake.opened) == 2
        capture = fake.opened[1]
        assert capture.kind == "capture"
        assert capture.device == device

    def test_capture_data_copied_to_playback(self):
        pump, fake = _make_pump(period_frames=4)
        device = pump_mod.bluealsa_capture_device(MAC_A)
        pump.set_active_source(device)
        pump._step()  # opens capture (default successful read)
        capture = fake.opened[1]
        capture.queue_read(4, b"\x01\x02" * 8)
        pump._step()  # consumes the explicitly queued read
        playback = fake.opened[0]
        assert b"\x01\x02" * 8 in playback.writes

    def test_capture_reused_across_steps_not_reopened(self):
        pump, fake = _make_pump()
        device = pump_mod.bluealsa_capture_device(MAC_A)
        pump.set_active_source(device)
        pump._step()
        pump._step()
        pump._step()
        assert len(fake.opened) == 2  # one playback + one capture, never re-opened

    def test_is_streaming_true_once_capture_open(self):
        pump, fake = _make_pump()
        assert pump.is_streaming() is False
        pump.set_active_source(pump_mod.bluealsa_capture_device(MAC_A))
        pump._step()
        assert pump.is_streaming() is True


class TestStallAndEofRevertToZeros:
    def test_read_stall_zero_length_reverts_to_zeros_without_closing_playback(self):
        pump, fake = _make_pump(period_frames=4)
        device = pump_mod.bluealsa_capture_device(MAC_A)
        pump.set_active_source(device)
        pump._step()  # opens capture (default successful read)
        capture = fake.opened[1]
        capture.queue_read(0, b"")
        pump._step()  # consumes the explicitly queued stall
        playback = fake.opened[0]
        assert playback.closed is False
        assert playback.writes[-1] == b"\x00" * (4 * 2 * 2)
        assert capture.closed is True

    def test_read_exception_reverts_to_zeros(self):
        pump, fake = _make_pump(period_frames=4)
        device = pump_mod.bluealsa_capture_device(MAC_A)
        pump.set_active_source(device)
        pump._step()  # opens capture (default successful read)
        capture = fake.opened[1]
        capture.queue_read_error(OSError("device disappeared"))
        pump._step()  # consumes the explicitly queued error
        playback = fake.opened[0]
        assert playback.writes[-1] == b"\x00" * (4 * 2 * 2)

    def test_capture_reopened_after_stall_when_still_wanted(self):
        pump, fake = _make_pump()
        device = pump_mod.bluealsa_capture_device(MAC_A)
        pump.set_active_source(device)
        pump._step()          # opens capture #1 (default successful read)
        fake.opened[1].queue_read(0, b"")
        pump._step()          # stall -> closes capture #1, writes zeros
        pump._step()          # source still active -> reopens capture
        assert len(fake.opened) == 3

    def test_open_capture_failure_falls_back_to_zeros(self):
        pump, fake = _make_pump(period_frames=4)
        fake.open_capture_should_fail = OSError("no such device")
        pump.set_active_source(pump_mod.bluealsa_capture_device(MAC_A))
        pump._step()
        playback = fake.opened[0]
        assert playback.writes[-1] == b"\x00" * (4 * 2 * 2)


class TestSourceCleared:
    def test_clearing_source_closes_capture_and_resumes_zeros(self):
        pump, fake = _make_pump(period_frames=4)
        device = pump_mod.bluealsa_capture_device(MAC_A)
        pump.set_active_source(device)
        pump._step()
        capture = fake.opened[1]
        capture.queue_read(4, b"\x03\x04" * 8)
        pump._step()

        pump.set_active_source(None)
        pump._step()
        assert capture.closed is True
        playback = fake.opened[0]
        assert playback.writes[-1] == b"\x00" * (4 * 2 * 2)
        assert pump.is_streaming() is False


class TestBlueAlsaCaptureDeviceName:
    def test_device_string_format(self):
        assert pump_mod.bluealsa_capture_device("AA:BB:CC:DD:EE:01") == \
            "bluealsa:DEV=AA:BB:CC:DD:EE:01,PROFILE=a2dp"


# ---------------------------------------------------------------------------
# Rate follow: non-44100 transports reopen both PCMs
# at the negotiated rate; capture-open failure falls back through 44100/48000.
# ---------------------------------------------------------------------------

class TestRateFollow:
    def test_non_default_rate_reopens_both_playback_and_capture(self):
        pump, fake = _make_pump(period_frames=4)
        device = pump_mod.bluealsa_capture_device(MAC_A)
        pump.set_active_source(device, rate=48000)
        pump._step()

        # Capture opened at the negotiated rate (opened before the playback
        # reopen, so it is not necessarily the last handle created).
        capture = [p for p in fake.opened if p.kind == "capture"][-1]
        assert capture.rate == 48000

        # Playback PCM was closed and reopened at the same rate: the
        # original playback handle (index 0) is closed, and a *new* handle
        # exists at 48000 Hz.
        original_playback = fake.opened[0]
        assert original_playback.closed is True
        new_playback = [p for p in fake.opened if p.kind == "playback"][-1]
        assert new_playback is not original_playback
        assert new_playback.rate == 48000
        assert pump._playback_pcm is new_playback

    def test_default_rate_never_reopens_playback(self):
        pump, fake = _make_pump(period_frames=4)
        device = pump_mod.bluealsa_capture_device(MAC_A)
        pump.set_active_source(device, rate=44100)
        pump._step()
        original_playback = fake.opened[0]
        assert original_playback.closed is False
        assert len([p for p in fake.opened if p.kind == "playback"]) == 1

    def test_reopen_only_happens_once_per_transport_start(self):
        pump, fake = _make_pump(period_frames=4)
        device = pump_mod.bluealsa_capture_device(MAC_A)
        pump.set_active_source(device, rate=48000)
        pump._step()
        pump._step()
        pump._step()
        # One playback handle from _make_pump's own setup, plus exactly one
        # reopen at transport-start -- never again across subsequent steps.
        assert len([p for p in fake.opened if p.kind == "playback"]) == 2
        # Capture opened exactly once too (not reopened every step).
        assert len([p for p in fake.opened if p.kind == "capture"]) == 1

    def test_capture_open_fails_at_wanted_rate_falls_back_to_44100(self):
        pump, fake = _make_pump(period_frames=4)
        device = pump_mod.bluealsa_capture_device(MAC_A)

        real_open_capture = pump._open_capture

        def flaky_open_capture(alsaaudio, dev, rate):
            if rate == 96000:
                raise OSError("unsupported rate")
            return real_open_capture(alsaaudio, dev, rate)

        pump._open_capture = flaky_open_capture
        pump.set_active_source(device, rate=96000)
        pump._step()

        capture = [p for p in fake.opened if p.kind == "capture"][-1]
        assert capture.rate == 44100
        assert pump._playback_rate == 44100

    def test_capture_open_fails_at_44100_falls_back_to_48000(self):
        pump, fake = _make_pump(period_frames=4)
        device = pump_mod.bluealsa_capture_device(MAC_A)

        real_open_capture = pump._open_capture

        def flaky_open_capture(alsaaudio, dev, rate):
            if rate in (96000, 44100):
                raise OSError("unsupported rate")
            return real_open_capture(alsaaudio, dev, rate)

        pump._open_capture = flaky_open_capture
        pump.set_active_source(device, rate=96000)
        pump._step()

        capture = [p for p in fake.opened if p.kind == "capture"][-1]
        assert capture.rate == 48000

    def test_all_fallback_rates_fail_reverts_to_zeros(self):
        pump, fake = _make_pump(period_frames=4)
        device = pump_mod.bluealsa_capture_device(MAC_A)
        fake.open_capture_should_fail = OSError("no such device")
        pump.set_active_source(device, rate=48000)
        pump._step()
        playback = fake.opened[0]
        assert playback.writes[-1] == b"\x00" * (4 * 2 * 2)
        assert playback.closed is False  # never reopened since capture never opened


class TestUnderrunHardening:
    """An A2DP delivery gap can drain the loopback playback ring, the next
    write raises ALSAAudioError EPIPE ("Broken pipe"), and that exception
    must not be allowed to kill the pump thread."""

    def test_playback_prefilled_on_open(self):
        pump, fake = _make_pump()
        playback = fake.opened[0]
        zero = pump._zero_period()
        assert len(playback.writes) == _expected_prefill(pump)
        assert all(w == zero for w in playback.writes)

    def test_write_failure_recovers_with_new_pcm(self):
        pump, fake = _make_pump()
        first_playback = fake.opened[0]
        first_playback.write = _raise_once(first_playback)  # type: ignore[method-assign]
        pump._write_playback(b"\x01\x02\x03\x04")
        # a replacement playback PCM was opened, prefilled, and the payload
        # write was retried on it
        assert first_playback.closed
        new_playback = fake.opened[-1]
        assert new_playback is not first_playback
        assert new_playback.writes[-1] == b"\x01\x02\x03\x04"
        assert len(new_playback.writes) == _expected_prefill(pump) + 1

    def test_run_loop_survives_step_exception(self):
        pump, fake = _make_pump()
        calls = {"n": 0}

        def boom():
            calls["n"] += 1
            if calls["n"] >= 3:
                pump._stop_event.set()
            raise RuntimeError("boom")

        pump._step = boom  # type: ignore[method-assign]
        pump._run()  # must return (stop set), never raise
        assert calls["n"] == 3


# ---------------------------------------------------------------------------
# Configurable audio buffer (plan SS1 "Audio buffer"): prefill/ring sizing
# from buffer_ms, round-up-to-periods, ring headroom, clamp-and-log, and
# set_buffer_ms()'s "takes effect on next reopen only" contract.
# ---------------------------------------------------------------------------

class TestComputePrefillPeriods:
    def test_200ms_at_44100hz_512_frame_periods_rounds_up_to_18(self):
        assert pump_mod.compute_prefill_periods(200, 44100, 512) == 18

    def test_200ms_at_48000hz_512_frame_periods_rounds_up_to_19(self):
        assert pump_mod.compute_prefill_periods(200, 48000, 512) == 19

    def test_100ms_at_44100hz_512_frame_periods(self):
        # 100 * 44100 / 1000 / 512 = 8.613... -> 9
        assert pump_mod.compute_prefill_periods(100, 44100, 512) == 9

    def test_500ms_at_48000hz_512_frame_periods(self):
        # 500 * 48000 / 1000 / 512 = 46.875 -> 47
        assert pump_mod.compute_prefill_periods(500, 48000, 512) == 47

    def test_exact_multiple_does_not_round_up_further(self):
        # 512000 frames worth -> exactly 1000 periods at 512 frames/period.
        assert pump_mod.compute_prefill_periods(1000, 512000, 512) == 1000


class TestPlaybackRingRequestsPeriodsParameter:
    def test_open_playback_requests_prefill_plus_headroom_periods(self):
        pump, fake = _make_pump(period_frames=512, rate=44100, buffer_ms=200)
        playback = fake.opened[0]
        assert playback.periods_requested == 18 + pump_mod.PLAYBACK_RING_HEADROOM_PERIODS

    def test_open_playback_at_48000_requests_19_plus_headroom(self):
        pump, fake = _make_pump(period_frames=512, rate=48000, buffer_ms=200)
        playback = fake.opened[0]
        assert playback.periods_requested == 19 + pump_mod.PLAYBACK_RING_HEADROOM_PERIODS

    def test_prefill_writes_match_computed_periods(self):
        pump, fake = _make_pump(period_frames=512, rate=44100, buffer_ms=200)
        playback = fake.opened[0]
        assert len(playback.writes) == 18


class TestPrefillClampsToNegotiatedRing:
    def test_smaller_negotiated_ring_clamps_prefill(self):
        fake = FakeAlsaAudio()
        pump = pump_mod.LoopbackPump(
            period_frames=512, rate=44100, buffer_ms=200, alsaaudio_module=fake,
        )
        # Patch PCM() so the produced FakePcm reports a negotiated ring
        # smaller than the 22-period request (18 prefill + 4 headroom).
        real_pcm = fake.PCM

        def small_ring_pcm(kind, mode, device, periods=None):
            pcm = real_pcm(kind, mode, device, periods=periods)
            if kind == fake.PCM_PLAYBACK:
                pcm.negotiated_periods = 10
            return pcm

        fake.PCM = small_ring_pcm
        pump._playback_pcm = pump._open_playback(fake)
        playback = fake.opened[0]
        assert playback.periods_requested == 22
        assert len(playback.writes) == 10  # clamped to the negotiated ring

    def test_negotiated_ring_at_least_as_big_uses_full_prefill(self):
        # Default FakePcm.negotiated_periods == periods_requested (22, the
        # full 18-prefill + 4-headroom request) -- no clamp applies.
        pump, fake = _make_pump(period_frames=512, rate=44100, buffer_ms=200)
        playback = fake.opened[0]
        assert playback.negotiated_periods == 22
        assert len(playback.writes) == 18

    def test_info_unavailable_assumes_request_honoured(self):
        """Older pyalsaaudio without PCM.info(): no clamp is attempted, the
        full computed prefill is written."""
        fake = FakeAlsaAudio()
        pump = pump_mod.LoopbackPump(
            period_frames=512, rate=44100, buffer_ms=200, alsaaudio_module=fake,
        )
        real_pcm = fake.PCM

        def no_info_pcm(kind, mode, device, periods=None):
            pcm = real_pcm(kind, mode, device, periods=periods)
            if kind == fake.PCM_PLAYBACK:
                pcm.info_supported = False
            return pcm

        fake.PCM = no_info_pcm
        pump._playback_pcm = pump._open_playback(fake)
        playback = fake.opened[0]
        assert len(playback.writes) == 18


class TestSetBufferMs:
    def test_set_buffer_ms_does_not_reopen_playback_immediately(self):
        pump, fake = _make_pump(period_frames=512, rate=44100, buffer_ms=200)
        original_playback = fake.opened[0]
        pump.set_buffer_ms(500)
        assert original_playback.closed is False
        assert len([p for p in fake.opened if p.kind == "playback"]) == 1

    def test_set_buffer_ms_takes_effect_on_next_rate_triggered_reopen(self):
        pump, fake = _make_pump(period_frames=512, rate=44100, buffer_ms=200)
        pump.set_buffer_ms(500)

        device = pump_mod.bluealsa_capture_device(MAC_A)
        pump.set_active_source(device, rate=48000)  # differs from 44100 -> reopens
        pump._step()

        new_playback = [p for p in fake.opened if p.kind == "playback"][-1]
        # 500 ms @ 48000 Hz / 512-frame periods = ceil(46.875) = 47, plus the
        # one real capture-data write the same _step() call performs after
        # reopening.
        assert len(new_playback.writes) == 47 + 1

    def test_set_buffer_ms_takes_effect_on_recovery_reopen(self):
        pump, fake = _make_pump(period_frames=512, rate=44100, buffer_ms=100)
        pump.set_buffer_ms(500)

        first_playback = fake.opened[0]
        first_playback.write = _raise_once(first_playback)  # type: ignore[method-assign]
        pump._write_playback(b"\x01\x02\x03\x04")

        new_playback = fake.opened[-1]
        # 500 ms @ 44100 Hz / 512-frame periods = ceil(43.06...) = 44.
        assert len(new_playback.writes) == 44 + 1  # prefill + the retried write

    def test_set_buffer_ms_thread_safe_read_back(self):
        pump, _ = _make_pump()
        pump.set_buffer_ms(350)
        assert pump._buffer_ms == 350


def _raise_once(pcm):
    original = FakePcm.write
    state = {"raised": False}

    def _write(data):
        if not state["raised"]:
            state["raised"] = True
            raise RuntimeError("Broken pipe [hw:CARD=ASBT,DEV=0]")
        return original(pcm, data)

    return _write
