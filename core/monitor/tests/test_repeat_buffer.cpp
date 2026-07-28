// =============================================================================
// test_repeat_buffer.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Unit tests for the header-only, pure repeat-feature core:
// autostream_repeat_buffer.h (RepeatBuffer/Reader, codec ladder,
// max_recording_seconds, /proc/meminfo parse, silence-trim accounting,
// onset-gated recording's OnsetGate/PreRollRing).
//
// Test IDs correspond to the repeat feature's unit-test numbering (U1-U9,
// U12-U16). U15/U16 plus the unnumbered onset-gated-recording composition
// test cover onset-gated recording (OnsetGate + PreRollRing + splice).
// No ALSA / libsamplerate / link deps — this is a pure C++17 standard-library
// test, buildable with a bare g++.
//
// Build (on Linux/WSL, from repo root):
//   g++ -std=c++17 -Wall -Wextra -O2 -I core/monitor \
//       core/monitor/tests/test_repeat_buffer.cpp \
//       -o /tmp/test_repeat_buffer && /tmp/test_repeat_buffer
// =============================================================================

#include "autostream_repeat_buffer.h"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>

// ---------------------------------------------------------------------------
// Minimal assertion harness (matches test_monitor_dsp.cpp / test_monitor_utils.cpp)
// ---------------------------------------------------------------------------

static int g_tests  = 0;
static int g_failed = 0;

#define CHECK(cond, msg) do { \
    ++g_tests; \
    if (!(cond)) { \
        ++g_failed; \
        std::fprintf(stderr, "FAIL [%s:%d] %s — %s\n", \
                     __FILE__, __LINE__, #cond, (msg)); \
    } \
} while (0)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Builds a byte buffer of `len` bytes with a repeating 0..255 ramp, so
// mismatches are easy to spot and every byte position has a distinct value
// modulo 256.
static std::vector<uint8_t> make_pattern(size_t len, uint8_t start = 0)
{
    std::vector<uint8_t> v(len);
    for (size_t i = 0; i < len; ++i)
        v[i] = static_cast<uint8_t>(start + i);
    return v;
}

// ---------------------------------------------------------------------------
// U1 — Buffer append/rollover
// ---------------------------------------------------------------------------

static void test_u1_append_rollover()
{
    const size_t kChunk = 16;  // tiny test chunk size, not the 16 MiB production one
    RepeatBuffer buf(kChunk);

    auto data = make_pattern(40);  // spans 3 chunks: 16 + 16 + 8
    CHECK(buf.append(data.data(), data.size()), "U1: append succeeds");

    CHECK(buf.total_bytes() == 40, "U1: total_bytes exact after append");
    CHECK(buf.chunk_count() == 3, "U1: chunk count == ceil(40/16) == 3");

    // Appending exactly a chunk boundary's worth more should not leave a
    // dangling empty chunk beyond what's needed.
    auto more = make_pattern(8, 40);
    CHECK(buf.append(more.data(), more.size()), "U1: second append succeeds");
    CHECK(buf.total_bytes() == 48, "U1: total_bytes exact after second append");
    CHECK(buf.chunk_count() == 3, "U1: still 3 chunks (48 == 3*16 exactly)");
}

// ---------------------------------------------------------------------------
// U2 — drop_oldest_chunk
// ---------------------------------------------------------------------------

static void test_u2_drop_oldest_chunk()
{
    const size_t kChunk = 16;
    RepeatBuffer buf(kChunk);

    auto data = make_pattern(40);  // 16 + 16 + 8
    buf.append(data.data(), data.size());

    CHECK(!buf.truncated_head(), "U2: truncated_head false before any drop");

    size_t before = buf.total_bytes();
    buf.drop_oldest_chunk();  // drops the first full 16-byte chunk
    CHECK(buf.total_bytes() == before - 16, "U2: bytes reduce by dropped chunk's used");
    CHECK(buf.truncated_head(), "U2: truncated_head latches true after a drop");

    buf.drop_oldest_chunk();  // drops the second full 16-byte chunk; one chunk (8 bytes) remains
    CHECK(buf.chunk_count() == 1, "U2: one chunk remains");
    CHECK(buf.total_bytes() == 8, "U2: 8 bytes remain in the last chunk");

    // Dropping further must never free the last chunk.
    buf.drop_oldest_chunk();
    CHECK(buf.chunk_count() == 1, "U2: dropping at one chunk is a no-op (chunk count)");
    CHECK(buf.total_bytes() == 8, "U2: dropping at one chunk is a no-op (bytes)");
    CHECK(buf.truncated_head(), "U2: truncated_head remains latched true");
}

// ---------------------------------------------------------------------------
// U3 — truncate_tail
// ---------------------------------------------------------------------------

static void test_u3_truncate_tail()
{
    const size_t kChunk = 16;

    // Zero-length truncate is a no-op.
    {
        RepeatBuffer buf(kChunk);
        auto data = make_pattern(40);
        buf.append(data.data(), data.size());
        buf.truncate_tail(0);
        CHECK(buf.total_bytes() == 40, "U3: zero-length truncate is a no-op");
    }

    // Truncate a byte count that spans a chunk boundary (24 bytes off the
    // tail of a 40-byte, 16+16+8 buffer removes all of the 8-byte chunk and
    // 16 bytes of the middle chunk).
    {
        RepeatBuffer buf(kChunk);
        auto data = make_pattern(40);
        buf.append(data.data(), data.size());
        buf.truncate_tail(24);
        CHECK(buf.total_bytes() == 16, "U3: cross-boundary truncate removes exactly N bytes");

        // The surviving bytes must be the first 16 bytes of the original data.
        RepeatBuffer::Reader reader(buf);
        std::vector<uint8_t> out(16);
        size_t n = reader.next(out.data(), out.size());
        CHECK(n == 16, "U3: reader sees exactly the surviving 16 bytes");
        CHECK(std::memcmp(out.data(), data.data(), 16) == 0,
              "U3: surviving bytes are the original head, untouched");
    }

    // Full-buffer truncate empties it cleanly.
    {
        RepeatBuffer buf(kChunk);
        auto data = make_pattern(40);
        buf.append(data.data(), data.size());
        buf.truncate_tail(40);
        CHECK(buf.total_bytes() == 0, "U3: full-buffer truncate empties the buffer");

        // Buffer must remain usable afterward (append still works).
        auto more = make_pattern(5, 99);
        CHECK(buf.append(more.data(), more.size()), "U3: append still works after full truncate");
        CHECK(buf.total_bytes() == 5, "U3: post-truncate append lands correctly");
    }
}

// ---------------------------------------------------------------------------
// U4 — Reader sequential
// ---------------------------------------------------------------------------

static void test_u4_reader_sequential()
{
    const size_t kChunk = 16;
    RepeatBuffer buf(kChunk);

    auto data = make_pattern(50);  // spans 4 chunks: 16+16+16+2
    buf.append(data.data(), data.size());

    RepeatBuffer::Reader reader(buf);
    std::vector<uint8_t> out(50, 0);

    // Read back in small, chunk-boundary-crossing slices to exercise the
    // cursor's chunk-to-chunk advance.
    size_t total_read = 0;
    while (total_read < out.size())
    {
        size_t n = reader.next(out.data() + total_read, 7);  // 7 doesn't divide 16 evenly
        if (n == 0)
            break;
        total_read += n;
    }

    CHECK(total_read == 50, "U4: reader returns every appended byte");
    CHECK(std::memcmp(out.data(), data.data(), 50) == 0,
          "U4: reader stream is byte-identical to what was appended");

    // A further read at end-of-buffer returns 0 (no data, no crash).
    uint8_t tail;
    CHECK(reader.next(&tail, 1) == 0, "U4: read at end of buffer returns 0");
}

// ---------------------------------------------------------------------------
// U5 — Reader vs concurrent-style drop
// ---------------------------------------------------------------------------

static void test_u5_reader_survives_drop()
{
    const size_t kChunk = 16;
    RepeatBuffer buf(kChunk);

    auto data = make_pattern(48);  // 3 full 16-byte chunks
    buf.append(data.data(), data.size());

    RepeatBuffer::Reader reader(buf);

    // Read partway into the first chunk, then simulate memory pressure
    // dropping the chunk the reader is sitting in (and the next one too).
    std::vector<uint8_t> partial(5);
    size_t n = reader.next(partial.data(), partial.size());
    CHECK(n == 5, "U5: initial partial read succeeds");

    buf.drop_oldest_chunk();  // drops the chunk the reader was reading
    buf.drop_oldest_chunk();  // drops the next one too

    // The reader must clamp to the new head rather than crash or duplicate
    // stale data. After the drops, only the third chunk (bytes 32..47 of the
    // original pattern) remains.
    std::vector<uint8_t> rest(16);
    size_t total = 0;
    while (total < rest.size())
    {
        size_t got = reader.next(rest.data() + total, rest.size() - total);
        if (got == 0)
            break;
        total += got;
    }

    CHECK(total == 16, "U5: reader recovers all bytes of the surviving chunk");
    CHECK(std::memcmp(rest.data(), data.data() + 32, 16) == 0,
          "U5: reader clamps to the new head, not stale/duplicated data");
}

// ---------------------------------------------------------------------------
// U6 — Target-duration codec selection (pick_codec_for_target())
// ---------------------------------------------------------------------------

// Local test-side mirror of autostream_repeat.cpp's (impure-TU-private)
// bitrate_kbps_for() -- that function isn't reachable from this pure,
// zero-link-dep test binary, so this small helper reconstructs it from the
// same byte_rate_for() this header already exposes (bitrate_kbps == byte_
// rate*8/1000 for every MP2 tier); PcmS16/Unavailable return 0, same
// contract as the original.
static int bitrate_kbps_of(CodecChoice c)
{
    long rate = byte_rate_for(c, 48000);   // MP2 byte rates are rate-independent
    if (c == CodecChoice::PcmS16 || c == CodecChoice::Unavailable)
        return 0;
    return static_cast<int>(rate * 8 / 1000);
}

// Exact bytes an MP2 tier needs to hold target_minutes at kbps.
static long long mp2_target_bytes(int kbps, int target_minutes)
{
    return (static_cast<long long>(kbps) * 1000 / 8) * (static_cast<long long>(target_minutes) * 60);
}

// Exact bytes PCM s16 stereo needs to hold target_minutes at sample_rate_hz.
static long long pcm_target_bytes(long sample_rate_hz, int target_minutes)
{
    return static_cast<long long>(byte_rate_for(CodecChoice::PcmS16, sample_rate_hz))
         * (static_cast<long long>(target_minutes) * 60);
}

// usable_mib the selection function derives internally from available_mib
// (available_mib - kFreeRamFloorMib, floored at 0) -- tests work forward from
// a target usable_mib to the available_mib that produces it, so each case's
// intent ("usable RAM this big") stays legible without hand-adding 64 twice.
static long available_for_usable(long usable_mib)
{
    return usable_mib + kFreeRamFloorMib;
}

static void test_u6_pick_codec_for_target()
{
    const int kTarget80 = 80;   // kDefaultRepeatTargetMinutes

    // ── PCM gate at 48 kHz: usable RAM comfortably above PCM's 80 min footprint ──
    {
        long long pcm_bytes_48k = pcm_target_bytes(48000, kTarget80);
        long usable_mib_generous = static_cast<long>(pcm_bytes_48k / (1024 * 1024)) + 100;
        CHECK(pick_codec_for_target(available_for_usable(usable_mib_generous), kTarget80, 48000)
                  == CodecChoice::PcmS16,
              "U6: 48k, usable well above PCM's 80min footprint -> PcmS16");
    }

    // ── PCM gate at 44.1 kHz (--compatible mode): a smaller footprint than
    //    48k, so a usable_mib that fits 44.1k PCM but not 48k PCM must still
    //    select PCM at 44.1k -- proves the PCM math is genuinely rate-dependent. ──
    {
        long long pcm_bytes_44k = pcm_target_bytes(44100, kTarget80);
        long long pcm_bytes_48k = pcm_target_bytes(48000, kTarget80);
        CHECK(pcm_bytes_44k < pcm_bytes_48k, "U6: sanity -- 44.1k PCM footprint smaller than 48k's");

        long usable_mib_between = static_cast<long>(pcm_bytes_44k / (1024 * 1024)) + 5;
        CHECK(pick_codec_for_target(available_for_usable(usable_mib_between), kTarget80, 44100)
                  == CodecChoice::PcmS16,
              "U6: 44.1k, usable fits 44.1k's (smaller) PCM footprint -> PcmS16");
    }

    // ── MP2 ladder: usable RAM fits 256k's target footprint but not 320k's ──
    {
        long long bytes_256 = mp2_target_bytes(256, kTarget80);
        long long bytes_320 = mp2_target_bytes(320, kTarget80);
        long usable_mib = static_cast<long>(bytes_256 / (1024 * 1024)) + 1;
        CHECK(static_cast<long long>(usable_mib) * 1024 * 1024 < bytes_320,
              "U6: sanity -- chosen usable_mib is below 320k's footprint");
        CHECK(pick_codec_for_target(available_for_usable(usable_mib), kTarget80, 48000)
                  == CodecChoice::Mp2_256,
              "U6: usable fits 256k but not 320k -> Mp2_256 (highest that fits)");
    }

    // ── Worked example: 246 MiB available, 80 min target, 48k. usable =
    //    246-64 = 182 MiB; 384k needs ~220.5 MiB (no), 320k needs ~183.75 MiB
    //    (no), 256k needs ~147 MiB (yes) -> Mp2_256. ──
    {
        CHECK(pick_codec_for_target(246, kTarget80, 48000) == CodecChoice::Mp2_256,
              "U6: worked example -- 246 MiB available, 80 min target, 48k -> Mp2_256");
    }

    // ── 160 kbps hard floor: usable RAM too small even for 160k's target
    //    footprint still selects Mp2_160 (goal, not an admission gate) ──
    {
        CHECK(pick_codec_for_target(available_for_usable(1), kTarget80, 48000) == CodecChoice::Mp2_160,
              "U6: usable RAM far too small for even 160k's target footprint -> Mp2_160 floor");
        CHECK(pick_codec_for_target(0, kTarget80, 48000) == CodecChoice::Mp2_160,
              "U6: available_mib at/under the floor (usable clamped to 0) -> Mp2_160 floor");
    }

    // ── Never below the floor: an artificially tiny target can't push
    //    selection below 160k either (the ladder simply stops walking down). ──
    {
        CHECK(pick_codec_for_target(available_for_usable(1), 10, 48000) == CodecChoice::Mp2_160,
              "U6: even the smallest legal target_minutes never selects below Mp2_160");
    }

    // ── Larger target_minutes needs more usable RAM to reach the same tier:
    //    a usable_mib that satisfies 256k at 80 min may not satisfy it at a
    //    larger target, falling back to a lower (but still >=160k) tier. ──
    {
        long long bytes_256_at_80 = mp2_target_bytes(256, 80);
        long usable_mib = static_cast<long>(bytes_256_at_80 / (1024 * 1024)) + 1;
        CodecChoice at_80  = pick_codec_for_target(available_for_usable(usable_mib), 80, 48000);
        CodecChoice at_600 = pick_codec_for_target(available_for_usable(usable_mib), 600, 48000);
        CHECK(at_80 == CodecChoice::Mp2_256, "U6: sanity -- fits 256k at the 80 min target");
        CHECK(at_600 != CodecChoice::PcmS16 && bitrate_kbps_of(at_600) <= bitrate_kbps_of(at_80),
              "U6: same usable RAM, larger target_minutes -> same or lower (never higher) tier");
    }
}

// ---------------------------------------------------------------------------
// U7 — max_recording_seconds
// ---------------------------------------------------------------------------

static void test_u7_max_recording_seconds()
{
    // The buffer is bounded ONLY by the free-RAM floor + codec ladder, so
    // max_recording_seconds() is a straight headroom/rate computation with
    // no min()-against-a-target step.

    // Fresh start, huge headroom: at 192k with 1000 MiB available, headroom
    // = (1000-64) MiB = 936 MiB, giving a large-but-exact number of seconds
    // (no cap kicks in to truncate it to some fixed target).
    // MP2 byte rates are bitrate-derived and rate-independent (see
    // byte_rate_for()'s comment); 48000 is passed explicitly throughout this
    // test since byte_rate_for() takes no default sample_rate_hz argument.
    long rate192 = byte_rate_for(CodecChoice::Mp2_192, 48000);
    long long expect_huge = (936LL * 1024 * 1024) / rate192;
    long s = max_recording_seconds(CodecChoice::Mp2_192, 1000, 0, 48000);
    CHECK(s == expect_huge, "U7: fresh start, huge headroom -> exact headroom/rate, uncapped");

    // Mid-recording (held > 0): held bytes count toward the available
    // duration without needing fresh headroom for them.
    size_t held = static_cast<size_t>(rate192) * 60;  // 60 s already held
    long s_mid = max_recording_seconds(CodecChoice::Mp2_192, 130 /*just above floor*/, held, 48000);
    CHECK(s_mid > 0, "U7: mid-recording with held bytes is > 0");
    long long expect_mid = (66LL * 1024 * 1024 + static_cast<long long>(held)) / rate192;
    CHECK(s_mid == expect_mid, "U7: mid-recording matches headroom+held/rate exactly");

    // Below-floor: available_mib at/under the 64 MiB floor with nothing held
    // yields zero (this is the condition that triggers drop_oldest_chunk in
    // the impure recorder).
    long s_floor = max_recording_seconds(CodecChoice::Mp2_192, 64, 0, 48000);
    CHECK(s_floor == 0, "U7: at the free-RAM floor with held=0 -> 0 seconds");
    long s_below_floor = max_recording_seconds(CodecChoice::Mp2_192, 10, 0, 48000);
    CHECK(s_below_floor == 0, "U7: below the free-RAM floor with held=0 -> 0 seconds");

    // PCM tier: uses the sample-rate-dependent byte rate, still uncapped.
    long rate_pcm = byte_rate_for(CodecChoice::PcmS16, 48000);
    long long expect_pcm = (936LL * 1024 * 1024) / rate_pcm;
    long s_pcm = max_recording_seconds(CodecChoice::PcmS16, 1000, 0, 48000);
    CHECK(s_pcm == expect_pcm, "U7: PCM tier headroom/rate, uncapped");

    // More available RAM simply yields more seconds -- no target ceiling to
    // saturate at.
    long s_2000 = max_recording_seconds(CodecChoice::Mp2_224, 2000, 0, 48000);
    long s_4000 = max_recording_seconds(CodecChoice::Mp2_224, 4000, 0, 48000);
    CHECK(s_4000 > s_2000, "U7: more available RAM -> strictly more seconds, uncapped");

    // Unavailable codec always yields zero regardless of headroom.
    long s_unavail = max_recording_seconds(CodecChoice::Unavailable, 2000, 0, 48000);
    CHECK(s_unavail == 0, "U7: Unavailable codec -> 0 seconds always");
}

// ---------------------------------------------------------------------------
// U14 — byte_rate_for() for the new tiers (256/320/384 kbps)
// ---------------------------------------------------------------------------

static void test_u14_byte_rate_for_new_tiers()
{
    CHECK(byte_rate_for(CodecChoice::Mp2_256, 48000) == 256000 / 8, "U14: Mp2_256 byte rate");
    CHECK(byte_rate_for(CodecChoice::Mp2_320, 48000) == 320000 / 8, "U14: Mp2_320 byte rate");
    CHECK(byte_rate_for(CodecChoice::Mp2_384, 48000) == 384000 / 8, "U14: Mp2_384 byte rate");

    // Rate-independent, exactly like the pre-existing MP2 tiers (bitrate/8
    // regardless of sample_rate_hz).
    CHECK(byte_rate_for(CodecChoice::Mp2_256, 44100) == byte_rate_for(CodecChoice::Mp2_256, 48000),
          "U14: Mp2_256 byte rate is sample-rate-independent");
    CHECK(byte_rate_for(CodecChoice::Mp2_384, 44100) == byte_rate_for(CodecChoice::Mp2_384, 48000),
          "U14: Mp2_384 byte rate is sample-rate-independent");

    // max_recording_seconds extends cleanly to the new tiers via the same
    // headroom/rate formula as every other tier.
    long rate320 = byte_rate_for(CodecChoice::Mp2_320, 48000);
    long long expect = (936LL * 1024 * 1024) / rate320;
    CHECK(max_recording_seconds(CodecChoice::Mp2_320, 1000, 0, 48000) == expect,
          "U14: max_recording_seconds works for a new tier (Mp2_320)");

    // codec_choice_for_bitrate_kbps round-trips through the legal table.
    CHECK(codec_choice_for_bitrate_kbps(160) == CodecChoice::Mp2_160, "U14: 160 -> Mp2_160");
    CHECK(codec_choice_for_bitrate_kbps(192) == CodecChoice::Mp2_192, "U14: 192 -> Mp2_192");
    CHECK(codec_choice_for_bitrate_kbps(224) == CodecChoice::Mp2_224, "U14: 224 -> Mp2_224");
    CHECK(codec_choice_for_bitrate_kbps(256) == CodecChoice::Mp2_256, "U14: 256 -> Mp2_256");
    CHECK(codec_choice_for_bitrate_kbps(320) == CodecChoice::Mp2_320, "U14: 320 -> Mp2_320");
    CHECK(codec_choice_for_bitrate_kbps(384) == CodecChoice::Mp2_384, "U14: 384 -> Mp2_384");
    CHECK(codec_choice_for_bitrate_kbps(128) == CodecChoice::Unavailable,
          "U14: a legal-but-below-floor MP2 bitrate is not in this ladder's table");
}

// ---------------------------------------------------------------------------
// U8 — meminfo parse
// ---------------------------------------------------------------------------

static void test_u8_meminfo_parse()
{
    // Canned realistic /proc/meminfo excerpt.
    const std::string text =
        "MemTotal:        3944232 kB\n"
        "MemFree:          182144 kB\n"
        "MemAvailable:     512000 kB\n"
        "Buffers:           45120 kB\n"
        "Cached:          1200000 kB\n";

    MemInfo info = parse_meminfo_text(text);
    CHECK(info.ok(), "U8: canned text parses ok");
    CHECK(info.available_mib == 512000 / 1024, "U8: MemAvailable converted to MiB correctly");

    // Missing field -> error sentinel, not a crash.
    const std::string missing =
        "MemTotal:        3944232 kB\n"
        "MemFree:          182144 kB\n";
    MemInfo info_missing = parse_meminfo_text(missing);
    CHECK(!info_missing.ok(), "U8: missing MemAvailable field -> not ok");
    CHECK(info_missing.available_mib == kMemInfoParseError, "U8: missing field -> error sentinel");

    // Malformed lines are ignored rather than crashing the parser: a
    // corrupted MemAvailable line (no digits) should not be mistaken for a
    // valid value, and unrelated garbage lines must not confuse the scan.
    const std::string malformed =
        "garbage line with no colon\n"
        "MemAvailable: not-a-number kB\n"
        "AnotherField: 123 kB\n";
    MemInfo info_malformed = parse_meminfo_text(malformed);
    CHECK(!info_malformed.ok(), "U8: malformed MemAvailable line ignored -> not ok");

    // Empty input.
    MemInfo info_empty = parse_meminfo_text("");
    CHECK(!info_empty.ok(), "U8: empty input -> not ok");
}

// ---------------------------------------------------------------------------
// U9 — Silence-trim accounting
// ---------------------------------------------------------------------------

static void test_u9_silence_trim_accounting()
{
    const size_t kFrameBytes = 4;  // arbitrary small "frame" for the test

    // Loud, then quiet: bytes_since_last_loud tracks only the trailing quiet run.
    {
        SilenceTrimAccountant acc;
        acc.on_block_appended(true, 100);   // loud block, resets counter
        acc.on_block_appended(false, 40);   // quiet
        acc.on_block_appended(false, 40);   // quiet
        CHECK(acc.bytes_since_last_loud() == 80, "U9: bytes_since_last_loud sums trailing quiet blocks");

        acc.on_block_appended(true, 20);    // loud again resets it
        CHECK(acc.bytes_since_last_loud() == 0, "U9: a loud block resets bytes_since_last_loud");

        acc.on_block_appended(false, 33);
        CHECK(acc.bytes_since_last_loud() == 33, "U9: accumulates again after reset");
    }

    // compute_trim_bytes: pad shorter than the quiet run -> some trim,
    // frame-aligned.
    {
        size_t bytes_since_last_loud = 100;
        size_t pad_bytes = 33;
        size_t total_bytes = 500;
        size_t trim = SilenceTrimAccountant::compute_trim_bytes(
            bytes_since_last_loud, pad_bytes, kFrameBytes, total_bytes);
        // Raw trim = 100 - 33 = 67, rounded down to a multiple of 4 -> 64.
        CHECK(trim == 64, "U9: trim is frame-aligned downward");
        CHECK(trim % kFrameBytes == 0, "U9: trim is an exact multiple of frame_bytes");
    }

    // pad longer than the quiet run -> no trim (recording ended near-loud).
    {
        size_t trim = SilenceTrimAccountant::compute_trim_bytes(10, 33, kFrameBytes, 500);
        CHECK(trim == 0, "U9: pad longer than quiet run -> no trim");
    }

    // All-silent recording: bytes_since_last_loud == total_bytes; trim
    // leaves ~pad bytes behind (edge case).
    {
        size_t total_bytes = 200;
        size_t pad_bytes = 40;
        size_t trim = SilenceTrimAccountant::compute_trim_bytes(
            total_bytes, pad_bytes, kFrameBytes, total_bytes);
        CHECK(trim == total_bytes - pad_bytes, "U9: all-silent trim leaves exactly the pad");
        size_t remaining = total_bytes - trim;
        CHECK(remaining == pad_bytes, "U9: all-silent recording trims to ~pad only");
    }

    // Trim can never exceed total_bytes even if bytes_since_last_loud does
    // (shouldn't happen in practice, but the helper must not underflow).
    {
        size_t trim = SilenceTrimAccountant::compute_trim_bytes(1000, 0, kFrameBytes, 200);
        CHECK(trim <= 200, "U9: trim is clamped to total_bytes");
    }
}

// ---------------------------------------------------------------------------
// Tail trim end-to-end — SilenceTrimAccountant + RepeatBuffer::truncate_tail()
// wired together the same way RepeatController::notify_capture_stopped()
// (autostream_repeat.cpp) uses them at session close: accumulate
// bytes_since_last_loud() as blocks are appended, compute_trim_bytes() at
// close, then truncate_tail() with the result. U9/U3 above test each piece
// in isolation with hand-picked numbers; this exercises them together so a
// mismatch in how the two APIs compose (units, ordering, off-by-one at a
// chunk boundary) would show up here even if each piece's own unit tests
// still pass.
// ---------------------------------------------------------------------------

static void test_tail_trim_end_to_end()
{
    const size_t kChunk = 16;
    const size_t kFrameBytes = 4;

    // A session that recorded 16 bytes of "loud" content, then a trailing
    // silence run of 24 bytes (the silence-timeout window's worth) before
    // the session closed. 1 s pad worth of bytes is kept back.
    {
        RepeatBuffer buf(kChunk);
        SilenceTrimAccountant trim;

        auto loud = make_pattern(16, /*start=*/0);
        buf.append(loud.data(), loud.size());
        trim.on_block_appended(/*above_threshold=*/true, loud.size());

        auto quiet = make_pattern(24, /*start=*/16);
        buf.append(quiet.data(), quiet.size());
        trim.on_block_appended(/*above_threshold=*/false, quiet.size());

        CHECK(buf.total_bytes() == 40, "tail trim e2e: 16 loud + 24 quiet appended");
        CHECK(trim.bytes_since_last_loud() == 24, "tail trim e2e: trailing quiet tracked exactly");

        const size_t pad_bytes = 8;  // e.g. ~1 s pad at this test's byte rate
        size_t trim_bytes = SilenceTrimAccountant::compute_trim_bytes(
            trim.bytes_since_last_loud(), pad_bytes, kFrameBytes, buf.total_bytes());
        // Raw trim = 24 - 8 = 16, already frame-aligned (multiple of 4).
        CHECK(trim_bytes == 16, "tail trim e2e: computed trim matches quiet run minus pad");

        buf.truncate_tail(trim_bytes);
        CHECK(buf.total_bytes() == 24, "tail trim e2e: buffer shrinks by exactly trim_bytes");

        // Surviving content is the original 16 loud bytes plus the first
        // 8 bytes of the quiet pad -- nothing from the trimmed tail, nothing
        // from the head.
        RepeatBuffer::Reader reader(buf);
        std::vector<uint8_t> out(24);
        size_t n = reader.next(out.data(), out.size());
        CHECK(n == 24, "tail trim e2e: reader sees exactly the surviving bytes");
        std::vector<uint8_t> expected;
        expected.insert(expected.end(), loud.begin(), loud.end());
        expected.insert(expected.end(), quiet.begin(), quiet.begin() + pad_bytes);
        CHECK(std::memcmp(out.data(), expected.data(), 24) == 0,
              "tail trim e2e: surviving bytes are loud content + untouched pad, byte-exact");
    }

    // Chunk-boundary edge case: the quiet run crosses a chunk boundary and
    // the trim removes an entire chunk plus part of another, mirroring U3's
    // cross-boundary case but driven by compute_trim_bytes() this time.
    {
        RepeatBuffer buf(kChunk);
        SilenceTrimAccountant trim;

        auto loud = make_pattern(16, 0);   // exactly one full chunk
        buf.append(loud.data(), loud.size());
        trim.on_block_appended(true, loud.size());

        auto quiet = make_pattern(24, 16);  // spans into a second and third chunk
        buf.append(quiet.data(), quiet.size());
        trim.on_block_appended(false, quiet.size());

        CHECK(buf.chunk_count() == 3, "tail trim e2e (boundary): 16+16+8 == 3 chunks before trim");

        size_t trim_bytes = SilenceTrimAccountant::compute_trim_bytes(
            trim.bytes_since_last_loud(), /*pad_bytes=*/0, kFrameBytes, buf.total_bytes());
        CHECK(trim_bytes == 24, "tail trim e2e (boundary): zero pad trims the whole quiet run");

        buf.truncate_tail(trim_bytes);
        CHECK(buf.total_bytes() == 16, "tail trim e2e (boundary): only the loud content survives");
        CHECK(buf.chunk_count() == 1, "tail trim e2e (boundary): trailing chunks fully dropped");
    }

    // Never trims below zero / never exceeds total_bytes even for a
    // recording that is entirely silence (degenerate but must not underflow
    // RepeatBuffer::truncate_tail(), which itself clamps -- this confirms
    // the pair composes safely at that extreme).
    {
        RepeatBuffer buf(kChunk);
        SilenceTrimAccountant trim;

        auto quiet = make_pattern(10, 0);
        buf.append(quiet.data(), quiet.size());
        trim.on_block_appended(false, quiet.size());

        size_t trim_bytes = SilenceTrimAccountant::compute_trim_bytes(
            trim.bytes_since_last_loud(), /*pad_bytes=*/0, kFrameBytes, buf.total_bytes());
        buf.truncate_tail(trim_bytes);
        CHECK(buf.total_bytes() <= 10, "tail trim e2e (all-silent): never underflows total_bytes");
    }
}

// ---------------------------------------------------------------------------
// U12 — steal_chunks (detach-under-lock / free-after-unlock support)
// ---------------------------------------------------------------------------

static void test_u12_steal_chunks()
{
    const size_t kChunk = 16;
    RepeatBuffer buf(kChunk);

    // Stealing from a fresh (never-appended) buffer yields an empty
    // container and leaves the buffer in the same empty state as a
    // just-constructed one.
    {
        auto stolen = buf.steal_chunks();
        CHECK(stolen.empty(), "U12: steal_chunks on an empty buffer returns nothing");
        CHECK(buf.total_bytes() == 0, "U12: buffer stays empty after stealing nothing");
        CHECK(buf.chunk_count() == 0, "U12: chunk_count is 0 after stealing nothing");
    }

    auto data = make_pattern(40);  // 16 + 16 + 8, spans 3 chunks
    buf.append(data.data(), data.size());
    buf.drop_oldest_chunk();   // exercise truncated_head/_head_seq before stealing
    CHECK(buf.truncated_head(), "U12: sanity -- truncated_head set before steal");

    size_t bytes_before = buf.total_bytes();
    CHECK(bytes_before > 0, "U12: sanity -- buffer non-empty before steal");

    auto stolen = buf.steal_chunks();

    // The detached container carries the actual bytes (sum of `used` across
    // the stolen chunks matches what total_bytes() reported pre-steal).
    size_t stolen_bytes = 0;
    for (const auto& c : stolen)
        stolen_bytes += c.used;
    CHECK(stolen_bytes == bytes_before, "U12: stolen chunks carry exactly the pre-steal byte count");

    // The buffer itself is left freshly cleared -- same observable state as
    // clear(), including truncated_head() resetting (it is a fresh buffer
    // now, not a truncated view of the old one).
    CHECK(buf.total_bytes() == 0, "U12: total_bytes is 0 immediately after steal_chunks");
    CHECK(buf.chunk_count() == 0, "U12: chunk_count is 0 immediately after steal_chunks");
    CHECK(!buf.truncated_head(), "U12: truncated_head resets after steal_chunks");

    // The buffer remains usable afterward, exactly like post-clear().
    auto more = make_pattern(5, 200);
    CHECK(buf.append(more.data(), more.size()), "U12: append still works after steal_chunks");
    CHECK(buf.total_bytes() == 5, "U12: post-steal append lands correctly");
}

// ---------------------------------------------------------------------------
// U13 — total_bytes incremental invariant across every mutator, including
// the preallocated-chunk append path
// ---------------------------------------------------------------------------

// Recomputes the "true" total from the outside: appends are tracked by the
// test itself (chunk internals are private), so this cross-checks
// total_bytes() against an independently-maintained running total after
// every single mutating call in a mixed sequence.
static void test_u13_total_bytes_invariant()
{
    const size_t kChunk = 16;
    RepeatBuffer buf(kChunk);
    size_t expected = 0;

    auto a = make_pattern(10);
    CHECK(buf.append(a.data(), a.size()), "U13: append #1 succeeds");
    expected += 10;
    CHECK(buf.total_bytes() == expected, "U13: total_bytes tracks append #1");

    // append_with_preallocated with a real preallocated chunk, forcing a
    // rollover (10 used of 16 in the current chunk; this append needs 10
    // more, which does not fit -- a new chunk is required).
    auto b = make_pattern(10, 50);
    auto storage = RepeatBuffer::allocate_chunk_storage(buf.chunk_bytes());
    CHECK(storage != nullptr, "U13: allocate_chunk_storage succeeds");
    CHECK(buf.append_with_preallocated(std::move(storage), b.data(), b.size()),
          "U13: append_with_preallocated succeeds");
    expected += 10;
    CHECK(buf.total_bytes() == expected, "U13: total_bytes tracks the preallocated append");

    // append_with_preallocated with a NULL preallocated pointer behaves
    // exactly like append() (falls back to internal allocation).
    auto c = make_pattern(30, 100);   // forces further rollovers
    CHECK(buf.append_with_preallocated(nullptr, c.data(), c.size()),
          "U13: append_with_preallocated(nullptr, ...) succeeds");
    expected += 30;
    CHECK(buf.total_bytes() == expected, "U13: total_bytes tracks a null-preallocated append");

    buf.drop_oldest_chunk();
    expected = buf.total_bytes();   // drop_oldest_chunk's exact byte delta is
                                     // already covered by U2; here we only
                                     // need total_bytes to still be internally
                                     // consistent for the rest of the sequence
    size_t after_drop = expected;

    buf.truncate_tail(7);
    expected = after_drop - std::min<size_t>(7, after_drop);
    CHECK(buf.total_bytes() == expected, "U13: total_bytes tracks truncate_tail");

    buf.clear();
    CHECK(buf.total_bytes() == 0, "U13: total_bytes is 0 after clear()");

    auto d = make_pattern(20, 150);
    buf.append(d.data(), d.size());
    auto stolen = buf.steal_chunks();
    CHECK(buf.total_bytes() == 0, "U13: total_bytes is 0 after steal_chunks()");
    size_t stolen_sum = 0;
    for (const auto& ch : stolen)
        stolen_sum += ch.used;
    CHECK(stolen_sum == 20, "U13: steal_chunks's returned container carries all the bytes");
}

// ---------------------------------------------------------------------------
// U15 — OnsetGate (onset-sustain decision core)
// ---------------------------------------------------------------------------

static void test_u15_onset_gate()
{
    // Confirms at exactly kOnsetSustainSeconds of continuous above-threshold
    // blocks, not before.
    {
        OnsetGate gate;
        CHECK(!gate.is_confirmed(), "U15: fresh gate is not confirmed");

        CHECK(!gate.on_block(true, 1.0), "U15: 1.0 s of 2.5 s -> not yet confirmed");
        CHECK(!gate.is_confirmed(), "U15: is_confirmed() agrees at 1.0 s");

        CHECK(!gate.on_block(true, 1.4), "U15: 2.4 s of 2.5 s -> still not confirmed");
        CHECK(!gate.is_confirmed(), "U15: is_confirmed() agrees at 2.4 s");

        // The block that pushes accumulated duration to exactly 2.5 s is the
        // confirming edge -- on_block() returns true exactly once, here.
        CHECK(gate.on_block(true, 0.1), "U15: block reaching exactly 2.5 s confirms");
        CHECK(gate.is_confirmed(), "U15: is_confirmed() true immediately after");

        // Latches: further above-threshold blocks never re-report the edge.
        CHECK(!gate.on_block(true, 1.0), "U15: no second confirming edge after latch");
        CHECK(gate.is_confirmed(), "U15: stays confirmed");
    }

    // Reset semantics: a single below-threshold block anywhere in an
    // otherwise-sustained run drops the accumulator back to zero, so the
    // sustain window must be genuinely unbroken.
    {
        OnsetGate gate;
        CHECK(!gate.on_block(true, 2.4), "U15: 2.4 s accumulated");
        CHECK(!gate.on_block(false, 0.1), "U15: a single below-threshold block resets, not confirms");
        CHECK(!gate.is_confirmed(), "U15: not confirmed after the reset");

        // Immediately following with 2.5 s more must confirm again from
        // zero -- the reset really did drop the whole prior 2.4 s, not just
        // decrement it.
        CHECK(!gate.on_block(true, 2.4), "U15: re-accumulating 2.4 s post-reset -> not yet");
        CHECK(gate.on_block(true, 0.1), "U15: full 2.5 s post-reset confirms");
        CHECK(gate.is_confirmed(), "U15: confirmed after the second run completes");
    }

    // Never confirms during continuous silence, however many blocks arrive.
    {
        OnsetGate gate;
        for (int i = 0; i < 100; ++i)
            CHECK(!gate.on_block(false, 1.0), "U15: silent blocks never confirm");
        CHECK(!gate.is_confirmed(), "U15: still not confirmed after 100 s of silence");
    }

    // A thump that cannot sustain the window: one loud block far short of
    // 2.5 s, then silence, then more loud blocks that individually never
    // reach 2.5 s unbroken -- must never confirm (the turntable-thump case).
    {
        OnsetGate gate;
        CHECK(!gate.on_block(true, 0.2), "U15: thump: short loud burst");
        CHECK(!gate.on_block(false, 20.0), "U15: thump: long spin-up quiet resets");
        CHECK(!gate.on_block(true, 0.3), "U15: thump: another short burst");
        CHECK(!gate.is_confirmed(), "U15: thump-only sequence never confirms onset");
    }

    // reset() returns a confirmed gate to the fresh state (new session reuse).
    {
        OnsetGate gate;
        gate.on_block(true, OnsetGate::kOnsetSustainSeconds);
        CHECK(gate.is_confirmed(), "U15: sanity -- confirmed before reset()");
        gate.reset();
        CHECK(!gate.is_confirmed(), "U15: reset() clears is_confirmed()");
        CHECK(!gate.on_block(true, 1.0), "U15: reset() clears the accumulator too (not still >= sustain)");
    }
}

// ---------------------------------------------------------------------------
// U16 — PreRollRing (pre-onset backlog)
// ---------------------------------------------------------------------------

// Builds an interleaved-stereo float block of `frames` frames, every sample
// set to `value` so a drained block's identity/order is trivial to check.
static std::vector<float> make_float_block(int frames, float value)
{
    return std::vector<float>(static_cast<size_t>(frames) * 2u, value);
}

static void test_u16_preroll_ring()
{
    // Disabled ring (capacity 0, the default-constructed state): push() is a
    // no-op, pop_front() always fails.
    {
        PreRollRing ring;
        auto blk = make_float_block(100, 1.0f);
        ring.push(blk.data(), 100, true);
        CHECK(ring.empty(), "U16: zero-capacity ring stays empty across push()");

        PreRollRing::Block out;
        CHECK(!ring.pop_front(out), "U16: pop_front on an empty/disabled ring returns false");
    }

    // Content preserved, splice order correct: push several distinguishable
    // blocks (well within capacity) and drain them in the same order.
    {
        PreRollRing ring;
        ring.set_capacity_frames(1000);

        auto a = make_float_block(10, 1.0f);
        auto b = make_float_block(20, 2.0f);
        auto c = make_float_block(30, 3.0f);
        ring.push(a.data(), 10, false);
        ring.push(b.data(), 20, false);
        ring.push(c.data(), 30, true);

        CHECK(ring.block_count() == 3, "U16: three blocks held");
        CHECK(ring.total_frames() == 60, "U16: total_frames sums held blocks exactly");

        PreRollRing::Block out;
        CHECK(ring.pop_front(out), "U16: first pop succeeds");
        CHECK(out.samples.size() == 20 && out.samples[0] == 1.0f && !out.above_threshold,
              "U16: drain order is chronological (a first), content and above_threshold preserved");

        CHECK(ring.pop_front(out), "U16: second pop succeeds");
        CHECK(out.samples.size() == 40 && out.samples[0] == 2.0f && !out.above_threshold,
              "U16: second drained block is b, in order");

        CHECK(ring.pop_front(out), "U16: third pop succeeds");
        CHECK(out.samples.size() == 60 && out.samples[0] == 3.0f && out.above_threshold,
              "U16: third drained block is c, above_threshold preserved true");

        CHECK(ring.empty(), "U16: ring empty after draining every pushed block");
        CHECK(!ring.pop_front(out), "U16: further pop_front on an empty ring returns false");
    }

    // Ring shorter than session start-to-onset: pushing more total duration
    // than capacity keeps only the most recent content (oldest blocks
    // dropped whole), proving the sliding-window behaviour the pre-roll
    // window relies on when a thump-then-quiet spin-up runs longer than
    // kPreRollSeconds before onset confirms.
    {
        PreRollRing ring;
        ring.set_capacity_frames(50);   // small capacity for the test

        auto a = make_float_block(20, 1.0f);   // oldest -- must be evicted
        auto b = make_float_block(20, 2.0f);
        auto c = make_float_block(20, 3.0f);   // newest
        ring.push(a.data(), 20, false);
        ring.push(b.data(), 20, false);
        ring.push(c.data(), 20, false);   // total 60 frames > capacity 50 -> a dropped

        CHECK(ring.total_frames() == 40, "U16: over-capacity push drops exactly the oldest block");
        CHECK(ring.block_count() == 2, "U16: only the two most recent blocks remain");

        PreRollRing::Block out;
        CHECK(ring.pop_front(out) && out.samples[0] == 2.0f,
              "U16: surviving oldest block is b, not the evicted a");
        CHECK(ring.pop_front(out) && out.samples[0] == 3.0f,
              "U16: surviving newest block is c");
    }

    // set_capacity_frames() also clears any existing content (used as the
    // per-session (re)initialisation call).
    {
        PreRollRing ring;
        ring.set_capacity_frames(1000);
        auto a = make_float_block(10, 1.0f);
        ring.push(a.data(), 10, true);
        CHECK(!ring.empty(), "U16: sanity -- ring non-empty before re-init");

        ring.set_capacity_frames(1000);   // simulates a fresh session start
        CHECK(ring.empty(), "U16: set_capacity_frames() clears prior content");
    }
}

// ---------------------------------------------------------------------------
// Onset-gated recording, composed end-to-end — OnsetGate + PreRollRing +
// RepeatBuffer + SilenceTrimAccountant wired together the same way
// RepeatController::process_recorder_samples() (autostream_repeat.cpp) uses
// them: while onset is unconfirmed, raw blocks go only into the ring; once
// confirmed, the ring is drained (chronological order) into the buffer via a
// trivial stand-in "encoder" (this pure test binary has no link dependency
// on libtwolame/libmpg123, so the stand-in just copies frames*frame_bytes of
// arbitrary content -- what matters here is COMMIT/NO-COMMIT and ordering,
// not real encoded bytes). U15/U16 above test each piece in isolation; this
// exercises the composition, matching the "tail trim end-to-end" test above.
// ---------------------------------------------------------------------------

namespace
{

// Stand-in "encoder": one output byte per sample (2 bytes/frame * frames),
// content = `tag`, a caller-chosen marker byte identifying which logical
// source segment (thump/quiet/music) a committed byte came from -- lets the
// tests assert exactly which segments reached the buffer, not merely
// "some bytes exist", without decoding anything real (this pure test binary
// has no link dependency on libtwolame/libmpg123).
std::vector<uint8_t> fake_encode(int frames, uint8_t tag)
{
    return std::vector<uint8_t>(static_cast<size_t>(frames) * 2u, tag);
}

// Drives one raw block through the onset-gated recording algorithm exactly
// as process_recorder_samples() does: push-to-ring while pending, drain the
// full ring plus this block once/after confirmed. No amortization cap here
// (draining is not itself the object under test in this composition -- U16
// already proves drain order/content in isolation) -- this always drains the
// whole ring in one call, which is a legal (if unlikely in production)
// degenerate case of "drain up to N blocks per call" with N == infinite.
// `tag` identifies this block's content for the test's own assertions (see
// fake_encode()); `above_threshold` drives the real onset/ring/trim logic
// exactly as it would for a genuine recorder block, independently of `tag`.
void feed_block(OnsetGate& onset, PreRollRing& ring, RepeatBuffer& buf,
                SilenceTrimAccountant& trim, int frames, bool above_threshold,
                uint8_t tag, double sample_rate_hz)
{
    bool block_in_ring = false;

    if (!onset.is_confirmed())
    {
        // The ring only needs to carry enough per-block identity for this
        // test's own bookkeeping; PreRollRing::Block itself only stores raw
        // samples + above_threshold (no tag field), so the tag is recovered
        // from the block's sample value below via encode_ring_block().
        std::vector<float> raw(static_cast<size_t>(frames) * 2u, static_cast<float>(tag));
        ring.push(raw.data(), frames, above_threshold);
        block_in_ring = true;
        onset.on_block(above_threshold, static_cast<double>(frames) / sample_rate_hz);
        if (!onset.is_confirmed())
            return;
    }

    PreRollRing::Block blk;
    while (ring.pop_front(blk))
    {
        int blk_frames = static_cast<int>(blk.samples.size() / 2u);
        uint8_t blk_tag = static_cast<uint8_t>(blk.samples[0]);   // recovers the tag stashed above
        auto encoded = fake_encode(blk_frames, blk_tag);
        buf.append(encoded.data(), encoded.size());
        trim.on_block_appended(blk.above_threshold, encoded.size());
    }

    if (block_in_ring)
        return;   // already committed via the ring drain above

    // Steady state (onset was already confirmed before this call): commit
    // this call's own live block directly, exactly matching process_
    // recorder_samples()'s post-onset behaviour.
    auto encoded = fake_encode(frames, tag);
    buf.append(encoded.data(), encoded.size());
    trim.on_block_appended(above_threshold, encoded.size());
}

}   // namespace

// Counts committed bytes tagged `tag` in a RepeatBuffer, via a fresh Reader.
static size_t count_tag_bytes(const RepeatBuffer& buf, uint8_t tag)
{
    RepeatBuffer::Reader reader(buf);
    std::vector<uint8_t> out(buf.total_bytes());
    size_t n = reader.next(out.data(), out.size());
    size_t count = 0;
    for (size_t i = 0; i < n; ++i)
        if (out[i] == tag)
            ++count;
    return count;
}

static const uint8_t kTagThump = 0x11;
static const uint8_t kTagQuiet = 0x22;
static const uint8_t kTagMusic = 0xAA;

static void test_onset_gated_recording_end_to_end()
{
    const double kRate = 48000.0;
    const int    kBlockFrames = static_cast<int>(kRate / 10.0);   // 100 ms blocks
    const size_t kBlockBytes  = static_cast<size_t>(kBlockFrames) * 2u;   // fake encoder: 2 bytes/frame

    // Thump-then-silence session: a short above-threshold burst that never
    // sustains 2.5 s, followed by silence for the rest of the (short) test
    // session -- the buffer must stay completely empty (property required
    // for "session ends before onset confirms -> nothing was committed",
    // which is what makes has_hold_bytes-gated replay correctly play
    // nothing).
    {
        OnsetGate onset;
        PreRollRing ring;
        ring.set_capacity_frames(static_cast<size_t>(kPreRollSeconds * kRate));
        RepeatBuffer buf(1024);
        SilenceTrimAccountant trim;

        feed_block(onset, ring, buf, trim, kBlockFrames, true, kTagThump, kRate);   // 100 ms thump
        for (int i = 0; i < 20; ++i)                                               // 2 s silence
            feed_block(onset, ring, buf, trim, kBlockFrames, false, kTagQuiet, kRate); // (never reaches 2.5 s)

        CHECK(!onset.is_confirmed(), "onset e2e (thump-only): onset never confirms");
        CHECK(buf.total_bytes() == 0, "onset e2e (thump-only): buffer stays empty");
    }

    // Thump -> quiet spin-up -> sustained music: the session-start transient
    // (the thump) must NOT appear in the committed buffer -- it is pushed
    // out of the pre-roll ring long before onset confirms, since the 10 s
    // spin-up quiet that follows it far exceeds the ring's 5 s capacity.
    // Some trailing quiet immediately before the music DOES survive (it is
    // still within the ring when onset confirms -- see the byte-count math
    // below), which is the intended pre-roll padding, not a defect: onset
    // takes 2.5 s of sustained music to confirm, and the ring holds 5 s, so
    // at most half the ring can have been overwritten by music by
    // confirmation time, leaving >=2.5 s of whatever preceded it (quiet,
    // here) still inside.
    {
        OnsetGate onset;
        PreRollRing ring;
        ring.set_capacity_frames(static_cast<size_t>(kPreRollSeconds * kRate));   // 50 blocks @ 100 ms
        RepeatBuffer buf(1u << 20);
        SilenceTrimAccountant trim;

        feed_block(onset, ring, buf, trim, kBlockFrames, true, kTagThump, kRate);   // 100 ms thump
        for (int i = 0; i < 100; ++i)                                              // 10 s spin-up quiet
            feed_block(onset, ring, buf, trim, kBlockFrames, false, kTagQuiet, kRate);
        CHECK(buf.total_bytes() == 0, "onset e2e (thump+quiet+music): still nothing committed pre-onset");

        // Sustained music: 30 blocks of 100 ms = 3 s. Onset confirms on the
        // 25th music block (25 * 100 ms == 2.5 s exactly).
        for (int i = 0; i < 30; ++i)
            feed_block(onset, ring, buf, trim, kBlockFrames, true, kTagMusic, kRate);

        CHECK(onset.is_confirmed(), "onset e2e (thump+quiet+music): onset confirms on sustained music");

        // Thump is long gone (1 block, 101 pushes before the ring's 50-block
        // capacity was last exceeded on the thump's account) -- zero thump
        // bytes ever reach the buffer.
        CHECK(count_tag_bytes(buf, kTagThump) == 0,
              "onset e2e (thump+quiet+music): the session-start thump never reaches the buffer");

        // Exactly 25 quiet blocks (2.5 s) remain in the ring at confirm time
        // (50-block ring, 25 of them overwritten by the 25 music blocks
        // pushed before confirmation) -- the pre-roll pad.
        CHECK(count_tag_bytes(buf, kTagQuiet) == 25 * kBlockBytes,
              "onset e2e (thump+quiet+music): exactly the ring's surviving pre-roll quiet is committed");

        // All 30 music blocks are committed: 25 via the ring splice (the
        // ones pushed while onset was still pending) plus 5 more via the
        // ordinary post-confirmation live path -- none lost, none doubled.
        CHECK(count_tag_bytes(buf, kTagMusic) == 30 * kBlockBytes,
              "onset e2e (thump+quiet+music): every music block is committed exactly once");

        CHECK(buf.total_bytes() == 25 * kBlockBytes + 30 * kBlockBytes,
              "onset e2e (thump+quiet+music): total committed is pre-roll quiet + all music, nothing else");
    }

    // CD-style immediate music: no thump, no quiet gap -- music from the
    // very first block. Onset confirms ~2.5 s in via the ring (which by
    // then holds everything back to session start, since kPreRollSeconds >
    // kOnsetSustainSeconds and the ring never even filled), so the FIRST
    // notes are present in the committed buffer, not just audio starting at
    // the 2.5 s mark.
    {
        OnsetGate onset;
        PreRollRing ring;
        ring.set_capacity_frames(static_cast<size_t>(kPreRollSeconds * kRate));
        RepeatBuffer buf(1u << 20);
        SilenceTrimAccountant trim;

        const int kTotalBlocks = 30;   // 3 s of continuous music
        for (int i = 0; i < kTotalBlocks; ++i)
            feed_block(onset, ring, buf, trim, kBlockFrames, true, kTagMusic, kRate);

        CHECK(onset.is_confirmed(), "onset e2e (CD-style): onset confirms on continuous music");

        // Every frame since session start is committed -- the ring never
        // exceeded its 5 s capacity in only 3 s of content, so nothing
        // (including the very first notes) was ever evicted before the
        // splice.
        CHECK(count_tag_bytes(buf, kTagMusic) == static_cast<size_t>(kTotalBlocks) * kBlockBytes,
              "onset e2e (CD-style): every frame since session start is committed, first notes included");
        CHECK(buf.total_bytes() == static_cast<size_t>(kTotalBlocks) * kBlockBytes,
              "onset e2e (CD-style): nothing beyond the music itself is in the buffer");
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int main()
{
    test_u1_append_rollover();
    test_u2_drop_oldest_chunk();
    test_u3_truncate_tail();
    test_u4_reader_sequential();
    test_u5_reader_survives_drop();
    test_u6_pick_codec_for_target();
    test_u7_max_recording_seconds();
    test_u14_byte_rate_for_new_tiers();
    test_u8_meminfo_parse();
    test_u9_silence_trim_accounting();
    test_tail_trim_end_to_end();
    test_u12_steal_chunks();
    test_u13_total_bytes_invariant();
    test_u15_onset_gate();
    test_u16_preroll_ring();
    test_onset_gated_recording_end_to_end();

    if (g_failed == 0) {
        std::printf("OK  %d/%d tests passed\n", g_tests, g_tests);
        return 0;
    }
    std::fprintf(stderr, "FAIL %d/%d tests failed\n", g_failed, g_tests);
    return 1;
}
