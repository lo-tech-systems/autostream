"""Tests for core/autostream_align_tone.py.

These exercise the pure buffer-building and scheduling functions only --
no real FIFO and no real clock. The paced write loop in main() is built out
of these same functions (BurstCache, plan_chunks, sleep_until with an
injectable clock/sleep), so covering them here covers the loop's logic
without needing a live reader or wall-clock sleeps.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_align_tone import (
    BurstCache,
    build_period_frames,
    build_silence,
    build_tone_burst,
    ms_to_frames,
    parse_args,
    plan_chunks,
    read_freq,
)


def _zero_crossings(samples):
    count = 0
    prev = samples[0]
    for s in samples[1:]:
        if prev == 0:
            prev = s
            continue
        if (s > 0) != (prev > 0) and s != 0:
            count += 1
        if s != 0:
            prev = s
    return count


class TestBuildToneBurst:
    def test_length_matches_burst_ms(self):
        rate, channels, burst_ms = 44100, 2, 150
        buf = build_tone_burst(1000, rate, channels, burst_ms, amplitude=0.4)
        expected_frames = ms_to_frames(burst_ms, rate)
        assert len(buf) == expected_frames * channels

    def test_peak_amplitude_close_to_requested(self):
        buf = build_tone_burst(1000, 44100, 2, 150, amplitude=0.5)
        peak = max(abs(s) for s in buf)
        expected = 0.5 * 32767
        assert abs(peak - expected) / expected < 0.05

    def test_ramp_edges_near_zero(self):
        buf = build_tone_burst(1000, 44100, 2, 150, amplitude=0.4)
        assert buf[0] == 0
        assert buf[1] == 0  # both channels at frame 0
        assert abs(buf[-1]) < 50
        assert abs(buf[-2]) < 50

    def test_stereo_channels_identical(self):
        buf = build_tone_burst(1000, 44100, 2, 150, amplitude=0.4)
        left = buf[0::2]
        right = buf[1::2]
        assert list(left) == list(right)

    def test_frequency_via_zero_crossings(self):
        rate, burst_ms, freq = 44100, 150, 1000
        buf = build_tone_burst(freq, rate, 1, burst_ms, amplitude=0.4)
        crossings = _zero_crossings(list(buf))
        expected = 2 * freq * burst_ms / 1000.0
        assert abs(crossings - expected) / expected < 0.05

    def test_zero_duration_burst_is_empty(self):
        buf = build_tone_burst(1000, 44100, 2, 0, amplitude=0.4)
        assert len(buf) == 0


class TestSilence:
    def test_silence_is_all_zero(self):
        buf = build_silence(500, 2)
        assert len(buf) == 1000
        assert all(s == 0 for s in buf)

    def test_silence_zero_frames(self):
        assert len(build_silence(0, 2)) == 0


class TestBurstCache:
    def test_caches_distinct_frequencies_separately(self):
        cache = BurstCache(rate=44100, channels=2, burst_ms=150, amplitude=0.4)
        a = cache.burst(1000)
        b = cache.burst(2000)
        assert a is cache.burst(1000)  # same object returned on repeat use
        assert a != b

    def test_silence_cached_by_length(self):
        cache = BurstCache(rate=44100, channels=2, burst_ms=150, amplitude=0.4)
        s1 = cache.silence(100)
        s2 = cache.silence(100)
        assert s1 is s2


class TestBuildPeriodFrames:
    def test_silent_period_is_all_zero(self):
        cache = BurstCache(rate=44100, channels=2, burst_ms=150, amplitude=0.4)
        total = ms_to_frames(5000, 44100)
        buf = build_period_frames(None, cache, total)
        assert len(buf) == total * 2
        assert all(s == 0 for s in buf)

    def test_toned_period_has_burst_then_silence(self):
        rate, channels = 44100, 2
        cache = BurstCache(rate=rate, channels=channels, burst_ms=150, amplitude=0.4)
        total = ms_to_frames(5000, rate)
        buf = build_period_frames(1000, cache, total)
        assert len(buf) == total * channels
        burst_frames = ms_to_frames(150, rate)
        tail = buf[burst_frames * channels:]
        assert all(s == 0 for s in tail)
        assert any(s != 0 for s in buf[:burst_frames * channels])


class TestPlanChunks:
    def test_chunks_sum_to_total(self):
        rate = 44100
        total_frames = ms_to_frames(5000, rate)
        chunk_frames = ms_to_frames(50, rate)
        chunks = plan_chunks(total_frames, chunk_frames)
        assert sum(chunks) == total_frames

    def test_chunks_are_nominal_size_except_last(self):
        chunk_frames = 2205  # 50ms @ 44100
        chunks = plan_chunks(11025, chunk_frames)  # 250ms, not an exact multiple
        assert chunks[:-1] == [chunk_frames] * (len(chunks) - 1)
        assert 0 < chunks[-1] <= chunk_frames

    def test_exact_multiple_has_no_remainder_chunk(self):
        chunks = plan_chunks(4410, 2205)
        assert chunks == [2205, 2205]

    def test_zero_total_yields_no_chunks(self):
        assert plan_chunks(0, 2205) == []


class TestReadFreq:
    def test_missing_file(self, tmp_path):
        assert read_freq(str(tmp_path / "nope.txt")) is None

    def test_empty_file(self, tmp_path):
        p = tmp_path / "freq.txt"
        p.write_text("")
        assert read_freq(str(p)) is None

    def test_whitespace_only_file(self, tmp_path):
        p = tmp_path / "freq.txt"
        p.write_text("   \n")
        assert read_freq(str(p)) is None

    def test_garbage_file(self, tmp_path):
        p = tmp_path / "freq.txt"
        p.write_text("not-a-number")
        assert read_freq(str(p)) is None

    def test_zero_is_silence(self, tmp_path):
        p = tmp_path / "freq.txt"
        p.write_text("0")
        assert read_freq(str(p)) is None

    def test_negative_is_silence(self, tmp_path):
        p = tmp_path / "freq.txt"
        p.write_text("-100")
        assert read_freq(str(p)) is None

    def test_valid_frequency(self, tmp_path):
        p = tmp_path / "freq.txt"
        p.write_text("1000")
        assert read_freq(str(p)) == 1000

    def test_valid_frequency_with_surrounding_whitespace(self, tmp_path):
        p = tmp_path / "freq.txt"
        p.write_text("  1234\n")
        assert read_freq(str(p)) == 1234


class TestCliValidation:
    def test_bits_other_than_16_rejected(self, tmp_path):
        freq_file = tmp_path / "freq.txt"
        freq_file.write_text("1000")
        with pytest.raises(SystemExit):
            parse_args(["--fifo", "/tmp/fifo", "--freq-file", str(freq_file), "--bits", "24"])

    def test_amplitude_out_of_range_rejected(self, tmp_path):
        freq_file = tmp_path / "freq.txt"
        freq_file.write_text("1000")
        with pytest.raises(SystemExit):
            parse_args(["--fifo", "/tmp/fifo", "--freq-file", str(freq_file), "--amplitude", "1.5"])

    def test_valid_args_accepted(self, tmp_path):
        freq_file = tmp_path / "freq.txt"
        freq_file.write_text("1000")
        args = parse_args(["--fifo", "/tmp/fifo", "--freq-file", str(freq_file)])
        assert args.bits == 16
        assert args.rate == 44100
