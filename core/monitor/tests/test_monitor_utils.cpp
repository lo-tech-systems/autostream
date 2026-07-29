// =============================================================================
// test_monitor_utils.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Unit tests for autostream_monitor_utils: log level parsing, get_monotonic_time
// resolution, and protocol_log_level_name round-trip.
//
// Build (on Linux, from repo root):
//   g++ -std=c++17 -O2 -I core/monitor \
//       core/monitor/tests/test_monitor_utils.cpp \
//       core/monitor/autostream_monitor_utils.cpp \
//       -lpthread -o /tmp/test_monitor_utils && /tmp/test_monitor_utils
// =============================================================================

#include "autostream_monitor_utils.h"

#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Minimal assertion harness
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
// parse_monitor_log_level
// ---------------------------------------------------------------------------

static void test_parse_log_level()
{
    MonitorLogLevel level;

    CHECK(parse_monitor_log_level("warning", &level), "parse 'warning'");
    CHECK(level == MonitorLogLevel::Warn, "warning maps to Warn");

    CHECK(parse_monitor_log_level("info", &level), "parse 'info'");
    CHECK(level == MonitorLogLevel::Info, "info maps to Info");

    CHECK(parse_monitor_log_level("debug", &level), "parse 'debug'");
    CHECK(level == MonitorLogLevel::Debug, "debug maps to Debug");

    CHECK(parse_monitor_log_level("spam", &level), "parse 'spam'");
    CHECK(level == MonitorLogLevel::Spam, "spam maps to Spam");

    CHECK(parse_monitor_log_level(" INFO ", &level), "parse uppercase info with whitespace");
    CHECK(level == MonitorLogLevel::Info, "uppercase INFO maps to Info");

    CHECK(parse_monitor_log_level("FATAL", &level), "parse uppercase fatal alias");
    CHECK(level == MonitorLogLevel::Warn, "fatal alias maps to Warn");

    CHECK(parse_monitor_log_level("log", &level), "parse log alias");
    CHECK(level == MonitorLogLevel::Warn, "log alias maps to Warn");

    CHECK(parse_monitor_log_level("warn", &level), "parse warn alias");
    CHECK(level == MonitorLogLevel::Warn, "warn alias maps to Warn");

    CHECK(!parse_monitor_log_level("unknown", &level), "unknown returns false");
    CHECK(!parse_monitor_log_level("", &level),         "empty returns false");
}

// ---------------------------------------------------------------------------
// protocol_log_level_name: round-trip via parse_monitor_log_level
// ---------------------------------------------------------------------------

static void test_protocol_log_level_name()
{
    // Each level must have a non-empty protocol name that can be parsed back.
    MonitorLogLevel levels[] = {
        MonitorLogLevel::Warn,
        MonitorLogLevel::Info,
        MonitorLogLevel::Debug,
        MonitorLogLevel::Spam,
    };

    for (auto lvl : levels) {
        const char* name = protocol_log_level_name(lvl);
        CHECK(name != nullptr && name[0] != '\0', "protocol name is non-empty");

        MonitorLogLevel parsed;
        bool ok = parse_monitor_log_level(name, &parsed);
        CHECK(ok, "protocol name round-trips through parse_monitor_log_level");
        CHECK(parsed == lvl, "round-tripped level matches original");
    }
}

// ---------------------------------------------------------------------------
// get_monotonic_time: basic sanity checks
// ---------------------------------------------------------------------------

static void test_get_monotonic_time()
{
    double t0 = get_monotonic_time();
    CHECK(t0 > 0.0, "monotonic time is positive");

    double t1 = get_monotonic_time();
    CHECK(t1 >= t0, "second sample is not earlier than first");

    // A nanosecond-resolution clock on any modern system should yield
    // values that differ by at least ~1 µs per call.  We only check for
    // gross anomalies here (values that differ by more than 10 seconds
    // suggest a clock source problem rather than a resolution issue).
    CHECK((t1 - t0) < 10.0, "two consecutive calls within 10 s");
}

// ---------------------------------------------------------------------------
// logger_set_level / logger_get_level
// ---------------------------------------------------------------------------

static void test_logger_set_get_level()
{
    logger_init(MonitorLogLevel::Warn);
    CHECK(logger_get_level() == MonitorLogLevel::Warn, "init sets level");

    logger_set_level(MonitorLogLevel::Debug);
    CHECK(logger_get_level() == MonitorLogLevel::Debug, "set to debug");

    logger_set_level(MonitorLogLevel::Info);
    CHECK(logger_get_level() == MonitorLogLevel::Info, "set to info");
}

// ---------------------------------------------------------------------------
// StderrRedirect: swap fd 2 to an arbitrary fd for the duration of a scope.
//
// The logger writes to the process's `stderr` FILE*, which glibc keeps
// unbuffered -- each fwrite() triggers an immediate write(2) against
// whatever fd 2 currently refers to.  Redirecting fd 2 to a pipe/file we
// control, without touching any production code, is what lets these tests
// exercise the logging thread's real sink-write path (including making it
// block) from a single process.  IMPORTANT: no CHECK()/fprintf(stderr, ...)
// diagnostics may run while a redirect that could block is active -- they
// would themselves block on it.  Restore first, then assert.
// ---------------------------------------------------------------------------

class StderrRedirect
{
public:
    explicit StderrRedirect(int new_fd)
    {
        std::fflush(stderr);
        _saved_fd = ::dup(STDERR_FILENO);
        ::dup2(new_fd, STDERR_FILENO);
    }

    ~StderrRedirect()
    {
        restore();
    }

    void restore()
    {
        if (_saved_fd < 0)
            return;
        std::fflush(stderr);
        ::dup2(_saved_fd, STDERR_FILENO);
        ::close(_saved_fd);
        _saved_fd = -1;
    }

private:
    int _saved_fd = -1;
};

// ---------------------------------------------------------------------------
// PipeDrain: continuously drain a pipe's read end in a background thread.
//
// IMPORTANT: a naive `while (read(fd, ...) > 0) {}` loop deadlocks here --
// read() only returns 0 (EOF) once every write end of the pipe is closed,
// but our write end stays open (dup2'd onto stderr) for the whole test, so
// such a loop blocks forever waiting for data that will never come once the
// logging thread finishes its current backlog. poll() with a short timeout,
// checked against a stop flag, lets the drain run concurrently with
// logger_test_wait_drained() (new messages can keep arriving while we wait)
// and still be stopped deterministically from the test thread.
// ---------------------------------------------------------------------------

static void pipe_drain_loop(int read_fd, std::atomic<bool>* stop_flag)
{
    char buf[4096];
    struct pollfd pfd;
    pfd.fd = read_fd;
    pfd.events = POLLIN;

    while (!stop_flag->load(std::memory_order_relaxed))
    {
        pfd.revents = 0;
        int rc = ::poll(&pfd, 1, 50 /* ms */);
        if (rc > 0 && (pfd.revents & POLLIN))
        {
            ssize_t n = ::read(read_fd, buf, sizeof(buf));
            if (n <= 0)
                break;  // pipe closed or genuine error
        }
    }
}

// ---------------------------------------------------------------------------
// build_wav_header replaces OutputDumpWriter's old
// hardcoded 44.1 kHz/16-bit WAV_PLACEHOLDER_HEADER byte array with a header
// derived from the monitor's actual output format descriptor.
// ---------------------------------------------------------------------------

static std::uint32_t read_u32(const std::array<std::uint8_t, 44>& h, std::size_t off)
{
    return static_cast<std::uint32_t>(h[off])
         | (static_cast<std::uint32_t>(h[off + 1]) << 8)
         | (static_cast<std::uint32_t>(h[off + 2]) << 16)
         | (static_cast<std::uint32_t>(h[off + 3]) << 24);
}

static std::uint16_t read_u16(const std::array<std::uint8_t, 44>& h, std::size_t off)
{
    return static_cast<std::uint16_t>(h[off] | (h[off + 1] << 8));
}

static void test_build_wav_header_fields_at_48k_32bit_stereo()
{
    // The monitor's current compile-time output format (AudioMonitor::
    // OUTPUT_RATE/OUTPUT_BITS/OUTPUT_CHANNELS).
    auto h = build_wav_header(48000, 32, 2, /*data_bytes=*/0);

    CHECK(h.size() == 44, "header is exactly 44 bytes (canonical PCM WAV)");
    CHECK(std::memcmp(&h[0], "RIFF", 4) == 0, "RIFF magic");
    CHECK(std::memcmp(&h[8], "WAVE", 4) == 0, "WAVE magic");
    CHECK(std::memcmp(&h[12], "fmt ", 4) == 0, "fmt chunk id");
    CHECK(read_u32(h, 16) == 16, "fmt sub-chunk size is 16 (canonical PCM)");
    CHECK(read_u16(h, 20) == 1, "audio_format is 1 (WAVE_FORMAT_PCM)");
    CHECK(read_u16(h, 22) == 2, "channels is 2");
    CHECK(read_u32(h, 24) == 48000, "sample_rate is 48000");
    CHECK(read_u32(h, 28) == 48000u * 2u * 4u, "byte_rate is rate*channels*(bits/8) = 384000");
    CHECK(read_u16(h, 32) == 2 * 4, "block_align is channels*(bits/8) = 8");
    CHECK(read_u16(h, 34) == 32, "bits_per_sample is 32");
    CHECK(std::memcmp(&h[36], "data", 4) == 0, "data chunk id");
    CHECK(read_u32(h, 4) == 36, "placeholder RIFF chunk size is 36 + 0 data bytes");
    CHECK(read_u32(h, 40) == 0, "placeholder data chunk size is 0");
}

static void test_build_wav_header_size_fields_reflect_data_bytes()
{
    auto h = build_wav_header(48000, 32, 2, /*data_bytes=*/1000);
    CHECK(read_u32(h, 4) == 1036, "RIFF chunk size is 36 + data_bytes");
    CHECK(read_u32(h, 40) == 1000, "data chunk size is data_bytes");
}

static void test_build_wav_header_legacy_44100_16bit_stereo_unchanged()
{
    // Sanity: the generalised builder reproduces the exact byte values the
    // old hardcoded WAV_PLACEHOLDER_HEADER array used for the legacy
    // 44100 Hz / 16-bit / stereo format, so the header math itself is
    // trustworthy independent of which format the monitor currently ships.
    auto h = build_wav_header(44100, 16, 2, /*data_bytes=*/0);
    CHECK(read_u32(h, 24) == 44100u, "legacy sample_rate 44100");
    CHECK(read_u32(h, 28) == 176400u, "legacy byte_rate 176400 (44100*2*2)");
    CHECK(read_u16(h, 32) == 4, "legacy block_align 4");
    CHECK(read_u16(h, 34) == 16, "legacy bits_per_sample 16");
}

// ---------------------------------------------------------------------------
// dbfs_to_linear_threshold / linear_to_dbfs: float-domain dBFS<->linear
// round-trip.
// ---------------------------------------------------------------------------

static void test_dbfs_linear_round_trip_across_range()
{
    // 0 dBFS and above clamp to full scale (1.0).
    CHECK(dbfs_to_linear_threshold(0.0f) == 1.0f, "0 dBFS clamps to 1.0 linear");
    CHECK(dbfs_to_linear_threshold(6.0f) == 1.0f, "positive dBFS clamps to 1.0 linear");

    // Round-trip at a handful of representative points across the range.
    float dbfs_points[] = { -1.0f, -6.0f, -20.0f, -40.0f, -60.0f, -80.0f };
    for (float dbfs : dbfs_points)
    {
        float linear = dbfs_to_linear_threshold(dbfs);
        CHECK(linear > 0.0f && linear <= 1.0f, "linear threshold stays in (0, 1]");

        float round_tripped = linear_to_dbfs(linear);
        CHECK(std::fabs(round_tripped - dbfs) < 0.05f,
              "linear_to_dbfs(dbfs_to_linear_threshold(x)) recovers x within 0.05 dB");
    }

    // Floor behaviour: very negative dBFS never collapses to exactly 0.0
    // linear (would make silence and the loudest possible sample compare
    // equal), and floors at 1/32768.
    float floor_linear = dbfs_to_linear_threshold(-200.0f);
    CHECK(floor_linear == 1.0f / 32768.0f, "extremely negative dBFS floors at 1/32768");

    // Silence and non-finite/negative peaks floor at -90 dBFS.
    CHECK(linear_to_dbfs(0.0f) == -90.0f, "zero peak maps to -90 dBFS floor");
    CHECK(linear_to_dbfs(-1.0f) == -90.0f, "negative peak maps to -90 dBFS floor");
}

// ---------------------------------------------------------------------------
// widen_s16_to_s32: the S16 -> S32 left-shift widening convention used by
// AlsaCapture::read()'s S16 fallback path.
// ---------------------------------------------------------------------------

static void test_widen_s16_to_s32_left_justifies()
{
    CHECK(widen_s16_to_s32(0) == 0, "zero widens to zero");
    CHECK(widen_s16_to_s32(1) == (1 << 16), "smallest positive step lands at bit 16");
    CHECK(widen_s16_to_s32(-1) == (-1 << 16), "smallest negative step lands at bit 16");
    CHECK(widen_s16_to_s32(32767) == (32767 << 16), "int16 max widens by <<16");
    CHECK(widen_s16_to_s32(-32768) == (static_cast<std::int32_t>(-32768) << 16),
          "int16 min widens by <<16");
}

// ---------------------------------------------------------------------------
// compute_should_capture_with_hold: minimum playback hold
// (suppression point (a) -- live-input silence-timeout session-end
// suppression). Pure decision function factored out of InputChannel::
// update_silence_state() so it is testable here without a running capture
// channel.
// ---------------------------------------------------------------------------

static void test_hold_disabled_matches_pre_hold_behaviour()
{
    // minimum_playback_seconds == 0 must reproduce exactly
    // (is_above_threshold && allow_capture) regardless of timestamps --
    // this is the "hold=0 => today's behaviour, byte for byte" contract.
    CHECK(compute_should_capture_with_hold(true, true, true, 0.0, 100.0, 0) == true,
          "hold disabled, above threshold, capturing -> true");
    CHECK(compute_should_capture_with_hold(false, true, true, 100.0, 100.5, 0) == false,
          "hold disabled, below threshold just after session start -> false (no hold)");
    CHECK(compute_should_capture_with_hold(false, true, true, 100.0, 129.999, 0) == false,
          "hold disabled, below threshold well within what would be a 30s hold -> still false");
    CHECK(compute_should_capture_with_hold(true, false, true, 100.0, 100.5, 0) == false,
          "hold disabled, allow_capture false always wins");
}

static void test_hold_suppresses_session_end_within_window()
{
    // Session started at t=100, 30 s hold, now t=115 (15 s in): elapsed
    // silence alone (is_above_threshold=false) must NOT end the session.
    CHECK(compute_should_capture_with_hold(
              /*is_above_threshold=*/false, /*allow_capture=*/true,
              /*capturing=*/true, /*capture_start_time=*/100.0,
              /*now=*/115.0, /*minimum_playback_seconds=*/30) == true,
          "silence within hold window is suppressed (should_capture stays true)");

    // Exactly at the boundary (elapsed == minimum_playback_seconds): hold
    // has just expired (strict less-than), so silence now ends the session.
    CHECK(compute_should_capture_with_hold(
              false, true, true, 100.0, 130.0, 30) == false,
          "hold boundary (elapsed == minimum_playback_seconds) is expired");

    // Comfortably after the hold: normal silence-timeout behaviour resumes.
    CHECK(compute_should_capture_with_hold(
              false, true, true, 100.0, 200.0, 30) == false,
          "silence well after hold expiry ends the session normally");

    // Signal present during the hold: unaffected either way (true or-ed
    // with true is still true).
    CHECK(compute_should_capture_with_hold(
              true, true, true, 100.0, 115.0, 30) == true,
          "signal present during hold -> still capturing");
}

static void test_hold_never_overrides_explicit_stop()
{
    // allow_capture=false must always win, hold active or not -- the hold
    // only suppresses the SILENCE-TIMEOUT reason for ending a session, never
    // an explicit stop (set_allow_capture(false), stop_input, a device/
    // config change).
    CHECK(compute_should_capture_with_hold(
              true, /*allow_capture=*/false, true, 100.0, 105.0, 30) == false,
          "explicit stop wins even with signal present and hold active");
    CHECK(compute_should_capture_with_hold(
              false, /*allow_capture=*/false, true, 100.0, 105.0, 30) == false,
          "explicit stop wins with silence and hold active");
}

static void test_hold_requires_an_active_session()
{
    // Not currently capturing (capturing=false): the hold cannot apply --
    // there is nothing to hold open. Guards against a stale non-zero
    // capture_start_time surviving into the next (unrelated) evaluation.
    CHECK(compute_should_capture_with_hold(
              false, true, /*capturing=*/false, /*capture_start_time=*/100.0,
              105.0, 30) == false,
          "not capturing -> hold never applies, even with a stale start time");

    // capture_start_time == 0.0 (no session ever recorded) also never holds,
    // even if capturing were somehow true.
    CHECK(compute_should_capture_with_hold(
              false, true, true, /*capture_start_time=*/0.0, 105.0, 30) == false,
          "capture_start_time == 0.0 -> hold never applies");
}

// ---------------------------------------------------------------------------
// compute_should_renotify_capture_started: minimum playback hold
// (suppression point (b) delivery mechanism) -- decides whether InputChannel
// should re-invoke notify_capture_started() this iteration to recover a
// session the repeat controller Ignored (or otherwise dropped) while this
// input kept capturing. Factored out the same way as
// compute_should_capture_with_hold() above.
// ---------------------------------------------------------------------------

static void test_renotify_never_fires_when_not_capturing()
{
    CHECK(compute_should_renotify_capture_started(
              /*capturing=*/false, /*repeat_enabled=*/true, /*recording_wanted=*/false,
              /*now=*/100.0, /*last_notify_time=*/0.0, /*interval_seconds=*/1.0) == false,
          "not capturing -> never re-notifies, regardless of cadence");
}

static void test_renotify_never_fires_when_repeat_disabled()
{
    CHECK(compute_should_renotify_capture_started(
              true, /*repeat_enabled=*/false, false,
              100.0, 0.0, 1.0) == false,
          "repeat feature disabled -> never re-notifies");
    // Distinguishes "disabled" from "enabled but not recording me" -- both
    // collapse to recording_wanted()==false on their own, but only the
    // disabled case must suppress the re-notify unconditionally.
    CHECK(compute_should_renotify_capture_started(
              true, /*repeat_enabled=*/false, /*recording_wanted=*/false,
              100.0, 90.0, 1.0) == false,
          "disabled wins even when the interval has long since elapsed");
}

static void test_renotify_never_fires_once_already_recording() {
    CHECK(compute_should_renotify_capture_started(
              true, true, /*recording_wanted=*/true,
              100.0, 0.0, 1.0) == false,
          "already recording this input -> re-notify is pure overhead, never fires");
    CHECK(compute_should_renotify_capture_started(
              true, true, /*recording_wanted=*/true,
              1000.0, 1.0, 1.0) == false,
          "recording_wanted=true wins even with a very stale last_notify_time");
}

static void test_renotify_respects_cadence_bound()
{
    // Never fired yet this session (last_notify_time <= 0.0): fires
    // immediately -- but in production this state is transient, since the
    // start-edge call always sets last_notify_time before the next
    // iteration's check runs.
    CHECK(compute_should_renotify_capture_started(
              true, true, false, 100.0, 0.0, 1.0) == true,
          "no prior notify this session -> fires immediately");

    // Just notified: must not fire again before the interval elapses.
    CHECK(compute_should_renotify_capture_started(
              true, true, false, /*now=*/100.4, /*last_notify_time=*/100.0,
              /*interval_seconds=*/1.0) == false,
          "within the interval -> does not re-fire");

    // Exactly at the boundary: fires (>=, not strictly >).
    CHECK(compute_should_renotify_capture_started(
              true, true, false, 101.0, 100.0, 1.0) == true,
          "exactly at the interval boundary -> fires");

    // Comfortably past the interval: fires.
    CHECK(compute_should_renotify_capture_started(
              true, true, false, 105.0, 100.0, 1.0) == true,
          "well past the interval -> fires");
}

// ---------------------------------------------------------------------------
// SRC quality tier: --src flag parsing
// ---------------------------------------------------------------------------

static void test_parse_src_quality_tier_valid_values()
{
    SrcQualityTier tier;

    CHECK(parse_src_quality_tier("fast", &tier), "parse 'fast'");
    CHECK(tier == SrcQualityTier::Fast, "'fast' maps to Fast");

    CHECK(parse_src_quality_tier("medium", &tier), "parse 'medium'");
    CHECK(tier == SrcQualityTier::Medium, "'medium' maps to Medium");

    CHECK(parse_src_quality_tier("best", &tier), "parse 'best'");
    CHECK(tier == SrcQualityTier::Best, "'best' maps to Best");
}

static void test_parse_src_quality_tier_invalid_and_absent()
{
    SrcQualityTier tier;

    CHECK(!parse_src_quality_tier("", &tier), "empty string is invalid");
    CHECK(!parse_src_quality_tier("Fast", &tier), "wrong case is invalid (case-sensitive)");
    CHECK(!parse_src_quality_tier("medium ", &tier), "trailing whitespace is invalid (no trimming)");
    CHECK(!parse_src_quality_tier("ultra", &tier), "unrecognised level is invalid");
    CHECK(!parse_src_quality_tier("fastest", &tier), "near-miss level is invalid");
}

static void test_src_quality_tier_name_round_trips()
{
    SrcQualityTier tiers[] = {
        SrcQualityTier::Fast, SrcQualityTier::Medium, SrcQualityTier::Best,
    };
    for (auto t : tiers)
    {
        const char* name = src_quality_tier_name(t);
        CHECK(name != nullptr && name[0] != '\0', "tier name is non-empty");
        SrcQualityTier parsed;
        CHECK(parse_src_quality_tier(name, &parsed), "tier name round-trips through parse_src_quality_tier");
        CHECK(parsed == t, "round-tripped tier matches original");
    }

    CHECK(std::string(src_quality_source_name(SrcQualitySource::Auto)) == "auto",
          "Auto source name is 'auto'");
    CHECK(std::string(src_quality_source_name(SrcQualitySource::Flag)) == "flag",
          "Flag source name is 'flag'");
}

// ---------------------------------------------------------------------------
// SRC quality tier: CPU-part auto-detect classifier
// (classify_src_tier_from_cpuinfo -- pure function over cpuinfo *content*,
// so this table is exercised without a real /proc filesystem)
// ---------------------------------------------------------------------------

static void test_classify_cortex_a76_is_best()
{
    // Real /proc/cpuinfo uses a tab before the colon; the format string's
    // literal spaces match any run of whitespace, so this is representative.
    std::string cpuinfo =
        "processor\t: 0\n"
        "model name\t: ARMv8 Processor rev 1 (v8l)\n"
        "CPU implementer\t: 0x41\n"
        "CPU part\t: 0xd0b\n";
    auto result = classify_src_tier_from_cpuinfo(cpuinfo);
    CHECK(result.tier == SrcQualityTier::Best, "Cortex-A76 (0xd0b) classifies as Best");
}

static void test_classify_cortex_a72_is_best()
{
    std::string cpuinfo =
        "processor\t: 0\n"
        "CPU part\t: 0xd08\n";
    auto result = classify_src_tier_from_cpuinfo(cpuinfo);
    CHECK(result.tier == SrcQualityTier::Best, "Cortex-A72 (0xd08) classifies as Best");
}

static void test_classify_cortex_a53_is_medium()
{
    std::string cpuinfo =
        "processor\t: 0\n"
        "CPU part\t: 0xd03\n";
    auto result = classify_src_tier_from_cpuinfo(cpuinfo);
    CHECK(result.tier == SrcQualityTier::Medium, "Cortex-A53 (0xd03) classifies as Medium");
}

static void test_classify_unknown_part_is_medium()
{
    // A recognised line format but a part id this classifier does not
    // special-case (e.g. Cortex-A55, 0xd05) -- Medium, per the "everything
    // else is Medium" contract; there is no path to Fast from auto-detect.
    std::string cpuinfo = "CPU part\t: 0xd05\n";
    auto result = classify_src_tier_from_cpuinfo(cpuinfo);
    CHECK(result.tier == SrcQualityTier::Medium, "unrecognised CPU part classifies as Medium");
}

static void test_classify_garbage_content_is_medium()
{
    // No "CPU part" line at all -- malformed/unexpected /proc/cpuinfo
    // content (e.g. a non-ARM host, or a stripped-down container).
    std::string cpuinfo = "this is not cpuinfo at all\nrandom text\n12345\n";
    auto result = classify_src_tier_from_cpuinfo(cpuinfo);
    CHECK(result.tier == SrcQualityTier::Medium, "garbage content classifies as Medium (fail-open)");
    CHECK(result.label == "unknown", "garbage content labels as 'unknown'");
}

static void test_classify_empty_content_is_medium()
{
    auto result = classify_src_tier_from_cpuinfo("");
    CHECK(result.tier == SrcQualityTier::Medium, "empty content classifies as Medium (fail-open)");
    CHECK(result.label == "unknown", "empty content labels as 'unknown'");
}

static void test_classify_big_little_one_big_core_is_enough()
{
    // Mirrors aac_coder_select()'s "on big.LITTLE one big core is enough"
    // note (src/transcode.c) -- a mix of small and big cores should still
    // classify as Best as soon as one high-performance part id is seen.
    std::string cpuinfo =
        "processor\t: 0\n"
        "CPU part\t: 0xd03\n"        // Cortex-A53 (LITTLE)
        "processor\t: 1\n"
        "CPU part\t: 0xd0b\n";       // Cortex-A76 (big)
    auto result = classify_src_tier_from_cpuinfo(cpuinfo);
    CHECK(result.tier == SrcQualityTier::Best, "one big core among small cores still classifies as Best");
}

static void test_detect_src_tier_from_proc_cpuinfo_does_not_crash()
{
    // Whatever the actual host CPU is (the CI/dev box, not a Pi), this must
    // return *some* valid classification without throwing or crashing --
    // the real integration point for the fail-open contract when the file
    // is readable but the classifier is asked to reason about it.
    auto result = detect_src_tier_from_proc_cpuinfo();
    CHECK(result.tier == SrcQualityTier::Medium || result.tier == SrcQualityTier::Best,
          "detect_src_tier_from_proc_cpuinfo() returns a valid tier");
    CHECK(!result.label.empty(), "detect_src_tier_from_proc_cpuinfo() returns a non-empty label");
}

// ---------------------------------------------------------------------------
// SRC quality tier: mapping to libsamplerate converter type constants
// ---------------------------------------------------------------------------

static void test_src_converter_type_for_tier_mapping()
{
    CHECK(src_converter_type_for_tier(SrcQualityTier::Fast) == SRC_SINC_FASTEST,
          "Fast maps to SRC_SINC_FASTEST");
    CHECK(src_converter_type_for_tier(SrcQualityTier::Medium) == SRC_SINC_MEDIUM_QUALITY,
          "Medium maps to SRC_SINC_MEDIUM_QUALITY");
    CHECK(src_converter_type_for_tier(SrcQualityTier::Best) == SRC_SINC_BEST_QUALITY,
          "Best maps to SRC_SINC_BEST_QUALITY");
}

// ---------------------------------------------------------------------------
// SRC quality tier: process-wide g_src_quality default
//
// A test binary never calls main(), so it never publishes a real --src /
// auto-detect result -- it must still see the documented fail-open default
// (Medium, Auto) rather than an arbitrary or zero-initialised value. Same
// contract as g_output_format defaulting to native (48000/32/2).
// ---------------------------------------------------------------------------

static void test_g_src_quality_default_is_medium_auto()
{
    CHECK(g_src_quality.tier == SrcQualityTier::Medium,
          "g_src_quality.tier defaults to Medium when main() never ran");
    CHECK(g_src_quality.source == SrcQualitySource::Auto,
          "g_src_quality.source defaults to Auto when main() never ran");
}

// ---------------------------------------------------------------------------
// CLI --help text: docs/CLI sync check
//
// No existing test asserted the in-binary --help text and docs/
// AUTOSTREAM-MONITOR.md's usage block stay in sync (checked: no such test
// exists anywhere under core/monitor/tests or tests/). This is a cheap
// substitute -- it cannot exercise main()'s actual --help branch without
// linking ALSA/libsamplerate/AudioMonitor, but monitor_help_text() is the
// exact string main() prints (factored out for this reason), so asserting
// its content here is equivalent to asserting the real --help output.
// ---------------------------------------------------------------------------

static void test_help_text_mentions_every_flag()
{
    std::string help = monitor_help_text("/tmp/autostream_monitor.sock");

    CHECK(help.find("--socket PATH") != std::string::npos, "--help mentions --socket");
    CHECK(help.find("--log-level") != std::string::npos, "--help mentions --log-level");
    CHECK(help.find("--test-hooks") != std::string::npos, "--help mentions --test-hooks");
    CHECK(help.find("--compatible") != std::string::npos, "--help mentions --compatible");
    CHECK(help.find("--src LEVEL") != std::string::npos, "--help mentions --src LEVEL");
    CHECK(help.find("fast|medium|best") != std::string::npos,
          "--help enumerates the --src vocabulary");
    CHECK(help.find("/tmp/autostream_monitor.sock") != std::string::npos,
          "--help interpolates the given default socket path");
}

// ---------------------------------------------------------------------------
// Logger queue: ordering + byte format preserved
// ---------------------------------------------------------------------------

static void test_logger_ordering_and_format()
{
    logger_init(MonitorLogLevel::Spam);

    char tmp_path[] = "/tmp/test_monitor_utils_ordering_XXXXXX";
    int tmp_fd = ::mkstemp(tmp_path);
    CHECK(tmp_fd >= 0, "mkstemp for ordering capture file succeeded");
    if (tmp_fd < 0)
        return;

    {
        StderrRedirect redirect(tmp_fd);
        LOG_WARN("[test] ordering message A");
        LOG_INFO("[test] ordering message B");
        LOG_DEBUG("[test] ordering message C");
        CHECK(logger_test_wait_drained(1000), "queue drained within 1s (ordering test)");
    }
    ::close(tmp_fd);

    std::ifstream in(tmp_path);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line))
        if (!line.empty())
            lines.push_back(line);
    in.close();
    ::unlink(tmp_path);

    CHECK(lines.size() == 3, "exactly 3 lines captured");
    if (lines.size() == 3)
    {
        // Byte format: "<DD-Mon-YY HH:MM:SS>: [LEVEL] message" -- unchanged
        // from the pre-queue logger.  Check the "[LEVEL] message" suffix and
        // the ": " timestamp separator rather than the timestamp digits
        // themselves (those are inherently non-deterministic).
        CHECK(lines[0].find(": [WARN] [test] ordering message A") != std::string::npos,
              "line 0 is message A with WARN tag");
        CHECK(lines[1].find(": [INFO] [test] ordering message B") != std::string::npos,
              "line 1 is message B with INFO tag");
        CHECK(lines[2].find(": [DEBUG] [test] ordering message C") != std::string::npos,
              "line 2 is message C with DEBUG tag");
    }

    logger_init(MonitorLogLevel::Warn);  // restore quiet default for later tests
}

// ---------------------------------------------------------------------------
// Logger queue: drop counting under sustained pressure
// ---------------------------------------------------------------------------

static void test_logger_drop_counting()
{
    logger_init(MonitorLogLevel::Spam);

    // A pipe whose write end we redirect stderr to, but whose read end we
    // never drain during the flood: once its kernel buffer fills, further
    // writes from the logging thread block, so the queue backs up and
    // logger_log() has to start dropping messages once LOGGER_QUEUE_CAPACITY
    // is exceeded.
    int fds[2];
    CHECK(::pipe(fds) == 0, "pipe() for drop-counting test succeeded");

    // Shrink the pipe buffer so the flood below reliably exceeds the
    // combined pipe + 256-entry queue capacity without needing an
    // unreasonably large loop.
#ifdef F_SETPIPE_SZ
    ::fcntl(fds[1], F_SETPIPE_SZ, 4096);
#endif

    uint64_t dropped_during_flood = 0;

    {
        StderrRedirect redirect(fds[1]);

        // Distinct messages (varying the counter in the text) so duplicate
        // suppression does not collapse them into a single emitted line --
        // we want raw enqueue volume, not post-suppression volume.
        for (int i = 0; i < 2000; ++i)
            LOG_WARN("[test] drop-flood message %d", i);

        dropped_during_flood = logger_test_dropped_count();

        // Start draining the read end (in the background, non-blocking poll
        // loop -- see PipeDrain comment above) so the logging thread can
        // unblock and finish writing whatever made it into the queue, then
        // wait for the drain to complete.
        std::atomic<bool> stop_drain{false};
        std::thread drain_thread(pipe_drain_loop, fds[0], &stop_drain);
        CHECK(logger_test_wait_drained(2000), "queue drained after unblocking sink");
        stop_drain.store(true, std::memory_order_relaxed);
        drain_thread.join();
    }
    ::close(fds[0]);
    ::close(fds[1]);

    CHECK(dropped_during_flood > 0,
          "flood exceeding queue capacity behind a stalled sink actually dropped messages");

    // The flood was 2000 distinct messages into a 256-entry queue behind a
    // stalled sink -- some must have been dropped and counted.  The drop
    // counter resets to 0 once the logging thread emits the "[logger]
    // dropped N messages" summary as part of draining, so by the time
    // logger_test_wait_drained() returned true, logger_test_dropped_count()
    // is back at 0; the observable effect is captured via the assertion
    // above (drain completing implies the summary path ran without
    // deadlocking) -- explicitly re-check it reads 0 post-drain here.
    CHECK(logger_test_dropped_count() == 0,
          "drop counter reset to 0 after summary emitted on drain");

    logger_init(MonitorLogLevel::Warn);
}

// ---------------------------------------------------------------------------
// Logger queue: producer stays responsive while the sink is stalled
// (stall-simulation -- proves no caller-held mutex is ever held across the
// actual sink write, so a stalled sink cannot wedge another thread)
// ---------------------------------------------------------------------------

static void test_logger_stall_does_not_block_producer()
{
    logger_init(MonitorLogLevel::Spam);

    int fds[2];
    CHECK(::pipe(fds) == 0, "pipe() for stall-simulation test succeeded");

    // Shrink the pipe's kernel buffer to the minimum (one page) so it fills
    // -- and the logging thread's fwrite() blocks -- after only a handful of
    // short log lines, rather than needing tens of thousands of messages.
#ifdef F_SETPIPE_SZ
    ::fcntl(fds[1], F_SETPIPE_SZ, 4096);
#endif

    double wall_ms = -1.0;
    uint64_t dropped_before = 0;
    uint64_t dropped_after  = 0;

    {
        StderrRedirect redirect(fds[1]);

        // Fill the pipe (and, once that's full, the 256-entry queue) without
        // ever reading from fds[0] -- this is a stalled sink: a write() that
        // blocks for a long time. If something held a mutex across that
        // write, any other thread wanting the same mutex would wedge behind
        // it. Here, nothing holds a mutex across it -- that's what we're
        // proving.
        for (int i = 0; i < 4000; ++i)
            LOG_WARN("[test] stall-flood message %d", i);

        dropped_before = logger_test_dropped_count();

        // This is the crux of the test: simulate a concurrent thread doing
        // something latency-sensitive (in production, e.g. get_status() /
        // a RepeatController call under _repeat_mutex) by timing further
        // logger_log() calls while the sink is still fully stalled behind
        // the flood above. If a mutex were held across fwrite/fflush, this
        // would block for as long as the stalled write() -- i.e.
        // indefinitely, since nothing is draining fds[0]. Instead it must
        // return almost immediately every time, because logger_log() never
        // touches the sink itself.
        auto t0 = std::chrono::steady_clock::now();
        for (int i = 0; i < 50; ++i)
            LOG_WARN("[test] responsiveness-probe %d", i);
        auto t1 = std::chrono::steady_clock::now();
        wall_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        dropped_after = logger_test_dropped_count();

        // Now unblock the stalled sink (background drain, see PipeDrain
        // comment above) and let the logging thread finish draining.
        std::atomic<bool> stop_drain{false};
        std::thread drain_thread(pipe_drain_loop, fds[0], &stop_drain);
        CHECK(logger_test_wait_drained(2000), "queue drained after unblocking stalled sink");
        stop_drain.store(true, std::memory_order_relaxed);
        drain_thread.join();
    }
    ::close(fds[0]);
    ::close(fds[1]);

    // The key evidence: 50 logger_log() calls made *while the sink was
    // still fully stalled* completed in well under a second combined --
    // proving the caller (the analogue of get_status()/_repeat_mutex
    // holders in production) was never blocked behind the wedged write().
    CHECK(wall_ms >= 0.0 && wall_ms < 500.0,
          "50 logger_log() calls during a stalled sink returned promptly (producer not blocked)");
    CHECK(dropped_after >= dropped_before,
          "drop counter is monotonic (queue-full path exercised, not a crash)");

    logger_init(MonitorLogLevel::Warn);
}

// ---------------------------------------------------------------------------
// logger_shutdown: bounded flush-on-shutdown
// ---------------------------------------------------------------------------

static void test_logger_shutdown_flushes_and_stops()
{
    logger_init(MonitorLogLevel::Spam);

    char tmp_path[] = "/tmp/test_monitor_utils_shutdown_XXXXXX";
    int tmp_fd = ::mkstemp(tmp_path);
    CHECK(tmp_fd >= 0, "mkstemp for shutdown capture file succeeded");
    if (tmp_fd < 0)
        return;

    {
        StderrRedirect redirect(tmp_fd);
        LOG_WARN("[test] shutdown message 1");
        LOG_WARN("[test] shutdown message 2");
        LOG_WARN("[test] shutdown message 2");  // duplicate: exercises repeat-summary flush too
        logger_shutdown();  // must drain the queue (and any repeat summary) before returning
    }
    ::close(tmp_fd);

    std::ifstream in(tmp_path);
    std::ostringstream contents;
    contents << in.rdbuf();
    in.close();
    ::unlink(tmp_path);

    CHECK(contents.str().find("shutdown message 1") != std::string::npos,
          "shutdown message 1 was flushed by logger_shutdown()");
    CHECK(contents.str().find("shutdown message 2") != std::string::npos,
          "shutdown message 2 was flushed by logger_shutdown()");
    CHECK(logger_test_queue_depth() == 0, "queue is empty after logger_shutdown()");

    // Restart logging for any subsequent tests / harness use in this process.
    logger_init(MonitorLogLevel::Warn);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int main()
{
    logger_init(MonitorLogLevel::Warn);   // silence log output during tests

    test_parse_log_level();
    test_protocol_log_level_name();
    test_get_monotonic_time();
    test_logger_set_get_level();

    // build_wav_header
    test_build_wav_header_fields_at_48k_32bit_stereo();
    test_build_wav_header_size_fields_reflect_data_bytes();
    test_build_wav_header_legacy_44100_16bit_stereo_unchanged();

    // dbfs_to_linear_threshold / linear_to_dbfs
    test_dbfs_linear_round_trip_across_range();

    // widen_s16_to_s32
    test_widen_s16_to_s32_left_justifies();

    // compute_should_capture_with_hold
    test_hold_disabled_matches_pre_hold_behaviour();
    test_hold_suppresses_session_end_within_window();
    test_hold_never_overrides_explicit_stop();
    test_hold_requires_an_active_session();

    // compute_should_renotify_capture_started
    test_renotify_never_fires_when_not_capturing();
    test_renotify_never_fires_when_repeat_disabled();
    test_renotify_never_fires_once_already_recording();
    test_renotify_respects_cadence_bound();

    // --src flag parsing
    test_parse_src_quality_tier_valid_values();
    test_parse_src_quality_tier_invalid_and_absent();
    test_src_quality_tier_name_round_trips();

    // CPU-part auto-detect classifier
    test_classify_cortex_a76_is_best();
    test_classify_cortex_a72_is_best();
    test_classify_cortex_a53_is_medium();
    test_classify_unknown_part_is_medium();
    test_classify_garbage_content_is_medium();
    test_classify_empty_content_is_medium();
    test_classify_big_little_one_big_core_is_enough();
    test_detect_src_tier_from_proc_cpuinfo_does_not_crash();

    // Tier -> libsamplerate converter type mapping
    test_src_converter_type_for_tier_mapping();

    // g_src_quality default (no main() ever ran)
    test_g_src_quality_default_is_medium_auto();

    // --help text / docs sync
    test_help_text_mentions_every_flag();

    test_logger_ordering_and_format();
    test_logger_drop_counting();
    test_logger_stall_does_not_block_producer();
    test_logger_shutdown_flushes_and_stops();

    // The logging thread is a background std::thread owned by process-wide
    // state (g_logger); it must be stopped (joined) before main() returns,
    // or the std::thread destructor at static-destruction time will find it
    // still joinable and call std::terminate(). Mirrors the real daemon's
    // main() teardown call in autostream_monitor.cpp.
    logger_shutdown();

    if (g_failed == 0) {
        std::printf("OK  %d/%d tests passed\n", g_tests, g_tests);
        return 0;
    }
    std::fprintf(stderr, "FAIL %d/%d tests failed\n", g_failed, g_tests);
    return 1;
}
