// =============================================================================
// test_repeat_buffer.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Unit tests for the header-only, pure repeat-feature core:
// autostream_repeat_buffer.h (RepeatBuffer/Reader, codec ladder,
// max_recording_seconds, /proc/meminfo parse, silence-trim accounting).
//
// Test IDs correspond to the repeat feature's unit-test numbering (U1-U9, U12-U13).
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
// U6 — Codec ladder boundaries
// ---------------------------------------------------------------------------

static void test_u6_codec_ladder_boundaries()
{
    CHECK(pick_codec(109) == CodecChoice::Unavailable, "U6: 109 MiB -> Unavailable");
    CHECK(pick_codec(110) == CodecChoice::Mp2_160,      "U6: 110 MiB -> Mp2_160");
    CHECK(pick_codec(129) == CodecChoice::Mp2_160,      "U6: 129 MiB -> Mp2_160");
    CHECK(pick_codec(130) == CodecChoice::Mp2_192,      "U6: 130 MiB -> Mp2_192");
    CHECK(pick_codec(159) == CodecChoice::Mp2_192,      "U6: 159 MiB -> Mp2_192");
    CHECK(pick_codec(160) == CodecChoice::Mp2_224,      "U6: 160 MiB -> Mp2_224");
    CHECK(pick_codec(999) == CodecChoice::Mp2_224,      "U6: 999 MiB -> Mp2_224");
    CHECK(pick_codec(1000) == CodecChoice::PcmS16,      "U6: 1000 MiB -> PcmS16");
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
    long rate192 = byte_rate_for(CodecChoice::Mp2_192);
    long long expect_huge = (936LL * 1024 * 1024) / rate192;
    long s = max_recording_seconds(CodecChoice::Mp2_192, 1000, 0);
    CHECK(s == expect_huge, "U7: fresh start, huge headroom -> exact headroom/rate, uncapped");

    // Mid-recording (held > 0): held bytes count toward the available
    // duration without needing fresh headroom for them.
    size_t held = static_cast<size_t>(rate192) * 60;  // 60 s already held
    long s_mid = max_recording_seconds(CodecChoice::Mp2_192, 130 /*just above floor*/, held);
    CHECK(s_mid > 0, "U7: mid-recording with held bytes is > 0");
    long long expect_mid = (66LL * 1024 * 1024 + static_cast<long long>(held)) / rate192;
    CHECK(s_mid == expect_mid, "U7: mid-recording matches headroom+held/rate exactly");

    // Below-floor: available_mib at/under the 64 MiB floor with nothing held
    // yields zero (this is the condition that triggers drop_oldest_chunk in
    // the impure recorder).
    long s_floor = max_recording_seconds(CodecChoice::Mp2_192, 64, 0);
    CHECK(s_floor == 0, "U7: at the free-RAM floor with held=0 -> 0 seconds");
    long s_below_floor = max_recording_seconds(CodecChoice::Mp2_192, 10, 0);
    CHECK(s_below_floor == 0, "U7: below the free-RAM floor with held=0 -> 0 seconds");

    // PCM tier: uses the sample-rate-dependent byte rate, still uncapped.
    long rate_pcm = byte_rate_for(CodecChoice::PcmS16, 44100);
    long long expect_pcm = (936LL * 1024 * 1024) / rate_pcm;
    long s_pcm = max_recording_seconds(CodecChoice::PcmS16, 1000, 0, 44100);
    CHECK(s_pcm == expect_pcm, "U7: PCM tier headroom/rate, uncapped");

    // More available RAM simply yields more seconds -- no target ceiling to
    // saturate at.
    long s_2000 = max_recording_seconds(CodecChoice::Mp2_224, 2000, 0);
    long s_4000 = max_recording_seconds(CodecChoice::Mp2_224, 4000, 0);
    CHECK(s_4000 > s_2000, "U7: more available RAM -> strictly more seconds, uncapped");

    // Unavailable codec always yields zero regardless of headroom.
    long s_unavail = max_recording_seconds(CodecChoice::Unavailable, 2000, 0);
    CHECK(s_unavail == 0, "U7: Unavailable codec -> 0 seconds always");
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
// Entry point
// ---------------------------------------------------------------------------

int main()
{
    test_u1_append_rollover();
    test_u2_drop_oldest_chunk();
    test_u3_truncate_tail();
    test_u4_reader_sequential();
    test_u5_reader_survives_drop();
    test_u6_codec_ladder_boundaries();
    test_u7_max_recording_seconds();
    test_u8_meminfo_parse();
    test_u9_silence_trim_accounting();
    test_u12_steal_chunks();
    test_u13_total_bytes_invariant();

    if (g_failed == 0) {
        std::printf("OK  %d/%d tests passed\n", g_tests, g_tests);
        return 0;
    }
    std::fprintf(stderr, "FAIL %d/%d tests failed\n", g_failed, g_tests);
    return 1;
}
