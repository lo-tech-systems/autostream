// =============================================================================
// test_fifo_writer.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Unit tests for FifoWriter's backlog behaviour: a reader that stalls no
// longer costs a resync (the fd is never closed on EAGAIN); bytes the pipe
// would not accept queue up and are delivered, in order, ahead of the next
// call's new data, once the reader catches up; and a backlog that grows
// past its one-second cap is dropped wholesale rather than allowed to grow
// without bound.
//
// Runs against a real FIFO (mkfifo) with a non-blocking reader fd that the
// test deliberately does not drain until it wants to exercise recovery, so
// every EAGAIN/backlog path below is the kernel's actual behaviour, not a
// simulation of it.
//
// Build (on Linux, from repo root):
//   g++ -std=c++17 -O2 -Wall -I core/monitor \
//       core/monitor/tests/test_fifo_writer.cpp \
//       core/monitor/autostream_fifo_writer.cpp \
//       core/monitor/autostream_monitor_utils.cpp \
//       -lpthread -o /tmp/test_fifo_writer && /tmp/test_fifo_writer
// =============================================================================

#include "autostream_monitor.h"
#include "test_log_capture.h"

#include <cerrno>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Minimal assertion harness (same shape as test_monitor_memory.cpp)
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
// Test fixture: a real FIFO with a non-blocking reader the test controls.
// ---------------------------------------------------------------------------

namespace {

// Fills a buffer with a counting byte pattern offset by `base`, so a block
// written out of order, truncated, or shifted by even one byte shows up
// immediately as a mismatch against the expected sequence rather than
// silently comparing equal.
std::vector<uint8_t> make_pattern(size_t len, uint8_t base)
{
    std::vector<uint8_t> buf(len);
    for (size_t i = 0; i < len; ++i)
        buf[i] = static_cast<uint8_t>(base + (i & 0xFF));
    return buf;
}

struct FifoFixture
{
    std::string dir;
    std::string path;
    int         reader_fd = -1;

    explicit FifoFixture(bool with_reader = true)
    {
        char dir_template[] = "/tmp/test_fifo_writer_XXXXXX";
        char* d = ::mkdtemp(dir_template);
        CHECK(d != nullptr, "mkdtemp for FIFO test dir succeeded");
        dir  = d ? d : "";
        path = dir + "/pipe";

        CHECK(::mkfifo(path.c_str(), 0600) == 0, "mkfifo succeeded");

        // Open the reader end first, non-blocking, so FifoWriter's own
        // open() below never blocks or sees ENXIO -- same ordering OwnTone
        // provides in production. A test of the no-reader path asks for
        // the fixture without one and opens it later.
        if (with_reader)
            open_reader();
    }

    ~FifoFixture()
    {
        close_reader();
        ::unlink(path.c_str());
        if (!dir.empty())
            ::rmdir(dir.c_str());
    }

    void open_reader()
    {
        reader_fd = ::open(path.c_str(), O_RDONLY | O_NONBLOCK);
        CHECK(reader_fd >= 0, "reader open succeeded");
    }

    void close_reader()
    {
        if (reader_fd >= 0)
        {
            ::close(reader_fd);
            reader_fd = -1;
        }
    }

    // Non-blocking read of exactly `len` bytes already sitting in the pipe.
    // Loops over short reads (a single read() is not guaranteed to return
    // everything available in one call) but never blocks: once nothing more
    // is immediately available it returns however much it collected.
    std::vector<uint8_t> read_available(size_t max_len)
    {
        std::vector<uint8_t> buf(max_len);
        size_t got = 0;
        while (got < max_len)
        {
            ssize_t n = ::read(reader_fd, buf.data() + got, max_len - got);
            if (n > 0)
            {
                got += static_cast<size_t>(n);
            }
            else
            {
                break;  // EAGAIN (nothing more queued yet) or EOF
            }
        }
        buf.resize(got);
        return buf;
    }

    // Confirms nothing further is queued in the pipe right now.
    bool nothing_more_available()
    {
        uint8_t probe;
        ssize_t n = ::read(reader_fd, &probe, 1);
        if (n > 0)
        {
            // Unread it conceptually is not possible on a pipe, so treat any
            // returned byte as a failure signal for the caller to report.
            return false;
        }
        return (n == 0) || (errno == EAGAIN || errno == EWOULDBLOCK);
    }
};

}  // namespace

// ---------------------------------------------------------------------------
// (1) A plain write with an empty backlog delivers byte-exact.
// ---------------------------------------------------------------------------

static void test_plain_write_byte_exact()
{
    FifoFixture fx;
    FifoWriter  writer;
    writer.set_path(fx.path);

    std::vector<uint8_t> block = make_pattern(4096, /*base=*/0);
    bool ok = writer.write(block.data(), block.size());
    CHECK(ok, "write() of a small block succeeds when the reader is draining");

    std::vector<uint8_t> got = fx.read_available(block.size());
    CHECK(got.size() == block.size(), "all bytes of the block reached the pipe");
    CHECK(got == block, "bytes read back match exactly what was written");

    CHECK(fx.nothing_more_available(), "no extra bytes were queued behind the block");

    FifoWriter::Counters c = writer.counters();
    CHECK(c.opens == 1, "one successful open");
    CHECK(c.pipe_bytes == ::fcntl(fx.reader_fd, F_GETPIPE_SZ), "pipe_bytes is the granted pipe size");
    CHECK(c.no_reader_bytes == 0 && c.overflow_bytes == 0 && c.error_bytes == 0 && c.stranded_bytes == 0,
          "a delivered block loses nothing");
    CHECK(c.overflow_events == 0 && c.write_errors == 0 && c.stall_events == 0, "no events on a clean write");
    CHECK(c.backlog_bytes == 0 && c.backlog_peak_bytes == 0, "nothing was queued");
}

// ---------------------------------------------------------------------------
// (2) Filling the pipe leaves the surplus in the backlog; the next write()
//     delivers the backlog first, then the new data, byte-exact and in order.
// ---------------------------------------------------------------------------

static void test_backlog_fills_and_drains_in_order()
{
    FifoFixture fx;
    FifoWriter  writer;
    writer.set_path(fx.path);

    // Prime the fd (and the pipe's resized capacity) with a small write,
    // fully drained immediately, so it does not interfere with the fill
    // below.
    {
        std::vector<uint8_t> priming = make_pattern(16, /*base=*/0);
        CHECK(writer.write(priming.data(), priming.size()), "priming write succeeds");
        fx.read_available(priming.size());
    }

    int pipe_cap = ::fcntl(fx.reader_fd, F_GETPIPE_SZ);
    CHECK(pipe_cap > 0, "F_GETPIPE_SZ reports the pipe's current capacity");

    const size_t tail_len = 777;  // bytes expected to overflow into the backlog
    const size_t fill_len = static_cast<size_t>(pipe_cap) + tail_len;

    std::vector<uint8_t> fill = make_pattern(fill_len, /*base=*/1);
    bool ok = writer.write(fill.data(), fill.size());
    CHECK(!ok, "write() reports false once the pipe cannot take the whole block");

    {
        FifoWriter::Counters c = writer.counters();
        CHECK(c.stall_events == 1, "the first failed write starts one stall streak");
        CHECK(c.backlog_bytes == tail_len, "the tail the pipe would not take is queued");
        CHECK(c.backlog_peak_bytes == tail_len, "the peak follows the queued tail");
        CHECK(c.pipe_bytes == pipe_cap, "pipe_bytes matches what the reader side reports");
        CHECK(c.overflow_bytes == 0 && c.error_bytes == 0 && c.no_reader_bytes == 0, "backpressure loses nothing");
    }

    // The pipe is now full of the first pipe_cap bytes of `fill`; the last
    // tail_len bytes are queued in the backlog, not on the pipe yet.

    // Drain exactly what the kernel accepted, and confirm it is the
    // beginning of `fill` (nothing reordered on the way in).
    std::vector<uint8_t> drained = fx.read_available(static_cast<size_t>(pipe_cap));
    CHECK(drained.size() == static_cast<size_t>(pipe_cap),
          "draining the pipe returns exactly its capacity in bytes");
    std::vector<uint8_t> expected_head(fill.begin(), fill.begin() + pipe_cap);
    CHECK(drained == expected_head, "the bytes the pipe accepted are the head of the written block, in order");

    // Now write a fresh, distinctly-patterned block. This call must deliver
    // the backlogged tail first, then this new block -- and, since both fit
    // in the now-empty pipe, it should succeed outright.
    std::vector<uint8_t> next_block = make_pattern(2048, /*base=*/97);
    bool ok2 = writer.write(next_block.data(), next_block.size());
    CHECK(ok2, "write() succeeds once the backlog plus the new block both fit");

    std::vector<uint8_t> expected_tail(fill.begin() + pipe_cap, fill.end());
    std::vector<uint8_t> expected_combined;
    expected_combined.reserve(expected_tail.size() + next_block.size());
    expected_combined.insert(expected_combined.end(), expected_tail.begin(), expected_tail.end());
    expected_combined.insert(expected_combined.end(), next_block.begin(), next_block.end());

    std::vector<uint8_t> got = fx.read_available(expected_combined.size());
    CHECK(got.size() == expected_combined.size(),
          "the backlog and the new block together reached the pipe");
    CHECK(got == expected_combined,
          "backlog bytes precede the new block's bytes, byte-exact and in order");

    CHECK(fx.nothing_more_available(), "nothing further is queued after the combined read");

    {
        FifoWriter::Counters c = writer.counters();
        CHECK(c.backlog_bytes == 0, "the backlog is empty once drained");
        CHECK(c.backlog_peak_bytes == tail_len, "the peak is not lowered by the drain");
        CHECK(c.stall_events == 1, "recovering does not add an event");
        CHECK(c.stall_max_seconds >= 0.0, "the closed streak's length is recorded");
        CHECK(writer.stalled_seconds() == 0.0, "a successful write clears the streak");
        CHECK(c.overflow_bytes == 0 && c.error_bytes == 0 && c.no_reader_bytes == 0, "a drained backlog loses nothing");
    }
}

// ---------------------------------------------------------------------------
// (3) A backlog that would grow past its one-second cap is dropped wholesale;
//     none of it (old or new) ever reaches the pipe.
// ---------------------------------------------------------------------------

static void test_backlog_overflow_drops_wholesale()
{
    FifoFixture fx;
    FifoWriter  writer;
    writer.set_path(fx.path);

    {
        std::vector<uint8_t> priming = make_pattern(16, /*base=*/0);
        CHECK(writer.write(priming.data(), priming.size()), "priming write succeeds");
        fx.read_available(priming.size());
    }

    int pipe_cap = ::fcntl(fx.reader_fd, F_GETPIPE_SZ);
    CHECK(pipe_cap > 0, "F_GETPIPE_SZ reports the pipe's current capacity");

    // Fill the pipe completely and leave a small tail sitting in the
    // backlog, exactly as in test (2).
    const size_t small_tail_len = 500;
    std::vector<uint8_t> fill = make_pattern(static_cast<size_t>(pipe_cap) + small_tail_len, /*base=*/2);
    bool ok = writer.write(fill.data(), fill.size());
    CHECK(!ok, "the fill write reports false (pipe cannot take it all)");

    // The backlog cap is one second of audio at the process-wide output
    // format; a test binary that never calls main() sees the documented
    // native default (48000 Hz / 32-bit / 2ch).
    size_t cap_bytes = static_cast<size_t>(AudioMonitor::output_rate_hz())
                     * static_cast<size_t>(AudioMonitor::output_bytes_per_frame());

    // A block big enough that (small_tail_len + oversized.size()) exceeds
    // the cap on its own -- comfortably past it, so the test does not
    // depend on the exact boundary arithmetic.
    std::vector<uint8_t> oversized = make_pattern(cap_bytes, /*base=*/3);

    // The pipe is still completely full (nothing has drained it since the
    // fill above), so this call cannot drain the existing backlog either:
    // draining sees EAGAIN with 0 bytes written, so the append path runs
    // and finds pending + oversized.size() > cap_bytes.
    bool ok2 = writer.write(oversized.data(), oversized.size());
    CHECK(!ok2, "write() still reports false once the backlog overflows its cap");

    // Draining the pipe should yield exactly the original fill's head
    // (pipe_cap bytes) -- nothing from the dropped backlog or the oversized
    // block, since both were discarded rather than queued.
    std::vector<uint8_t> drained = fx.read_available(static_cast<size_t>(pipe_cap) + oversized.size());
    CHECK(drained.size() == static_cast<size_t>(pipe_cap),
          "only the pipe's original contents are readable; nothing extra was queued");
    std::vector<uint8_t> expected_head(fill.begin(), fill.begin() + pipe_cap);
    CHECK(drained == expected_head, "the pipe's contents are unaffected by the dropped backlog");

    CHECK(fx.nothing_more_available(),
          "no stale backlog or oversized-block bytes remain queued after the drop");

    FifoWriter::Counters c = writer.counters();
    CHECK(c.overflow_events == 1, "one overflow");
    CHECK(c.overflow_bytes == small_tail_len + cap_bytes, "the queued tail and the refused block are both counted");
    CHECK(c.backlog_bytes == 0, "the backlog is empty after the drop");
    CHECK(c.backlog_peak_bytes == small_tail_len, "the refused block never raised the peak");
    CHECK(c.stall_events == 1, "a second failed write inside one streak is not a new event");
    CHECK(c.error_bytes == 0 && c.write_errors == 0, "an overflow is not a write error");
}

// ---------------------------------------------------------------------------
// (4) end_stream() drops the backlog, closes the stall streak at the last
//     write attempt and keeps the fd, so the next stream starts clean.
// ---------------------------------------------------------------------------

static void test_end_stream_drops_backlog_and_closes_streak()
{
    FifoFixture fx;
    FifoWriter  writer;
    writer.set_path(fx.path);

    {
        std::vector<uint8_t> priming = make_pattern(16, /*base=*/0);
        CHECK(writer.write(priming.data(), priming.size()), "priming write succeeds");
        fx.read_available(priming.size());
    }

    int pipe_cap = ::fcntl(fx.reader_fd, F_GETPIPE_SZ);
    CHECK(pipe_cap > 0, "F_GETPIPE_SZ reports the pipe's current capacity");

    const size_t tail_len = 777;
    std::vector<uint8_t> fill = make_pattern(static_cast<size_t>(pipe_cap) + tail_len, /*base=*/1);
    CHECK(!writer.write(fill.data(), fill.size()), "the fill write leaves a tail in the backlog");

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    double last_write_time = get_monotonic_time();
    // Time that passes after the last write attempt is not part of the streak.
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    FifoWriter::StreamEnd end = writer.end_stream(last_write_time);
    CHECK(end.dropped_bytes == tail_len, "the queued tail is reported as dropped");
    CHECK(end.stall_seconds > 0.0, "the open streak is reported");
    CHECK(std::fabs(end.stall_seconds - 0.1) < 0.05,
          "the streak ends at the last write attempt, not at the call");
    CHECK(writer.stalled_seconds() == 0.0, "the streak is closed");
    CHECK(writer.is_open(), "the fd stays open");

    FifoWriter::Counters c = writer.counters();
    CHECK(c.stranded_bytes == tail_len, "the dropped tail is counted as stranded");
    CHECK(c.stall_events == 1, "the streak was one event");
    CHECK(c.stall_max_seconds == end.stall_seconds, "the closed streak is the longest seen");
    CHECK(c.backlog_bytes == 0, "no backlog is reported after the drop");
    CHECK(c.overflow_bytes == 0 && c.error_bytes == 0, "ending a stream is not an overflow or an error");

    std::vector<uint8_t> drained = fx.read_available(static_cast<size_t>(pipe_cap) + tail_len);
    CHECK(drained.size() == static_cast<size_t>(pipe_cap),
          "the pipe holds only what it had accepted; the tail is gone");

    std::vector<uint8_t> next_block = make_pattern(2048, /*base=*/97);
    CHECK(writer.write(next_block.data(), next_block.size()), "the next stream's block is delivered");
    std::vector<uint8_t> got = fx.read_available(next_block.size() + tail_len);
    CHECK(got == next_block, "the next block arrives with no trace of the dropped tail");
    CHECK(fx.nothing_more_available(), "nothing further is queued");
}

// ---------------------------------------------------------------------------
// (5) end_stream() on a healthy writer changes nothing.
// ---------------------------------------------------------------------------

static void test_end_stream_on_a_healthy_writer_changes_nothing()
{
    FifoFixture fx;
    FifoWriter  writer;
    writer.set_path(fx.path);

    std::vector<uint8_t> block = make_pattern(4096, /*base=*/0);
    CHECK(writer.write(block.data(), block.size()), "write succeeds");
    CHECK(fx.read_available(block.size()) == block, "the block reached the pipe");

    FifoWriter::StreamEnd end = writer.end_stream(get_monotonic_time());
    CHECK(end.dropped_bytes == 0, "nothing was queued");
    CHECK(end.stall_seconds == 0.0, "no streak was open");
    CHECK(writer.is_open(), "the fd stays open");

    std::vector<uint8_t> next_block = make_pattern(1024, /*base=*/5);
    CHECK(writer.write(next_block.data(), next_block.size()), "the next write succeeds");
    CHECK(fx.read_available(next_block.size()) == next_block, "the next block is byte-exact");
    CHECK(fx.nothing_more_available(), "nothing further is queued");
}

// ---------------------------------------------------------------------------
// (6) With no reader on the FIFO, open() fails with ENXIO: the block is
//     discarded and counted, and the writer recovers once a reader appears.
// ---------------------------------------------------------------------------

static void test_no_reader_counts_discarded_bytes()
{
    FifoFixture fx(/*with_reader=*/false);
    FifoWriter  writer;
    writer.set_path(fx.path);

    std::vector<uint8_t> block = make_pattern(4096, /*base=*/5);
    bool ok = writer.write(block.data(), block.size());
    CHECK(!ok, "write() reports false while no reader has the FIFO open");
    CHECK(!writer.is_open(), "the writer stays closed when open() fails with ENXIO");

    FifoWriter::Counters c = writer.counters();
    CHECK(c.no_reader_bytes == block.size(), "the whole block is counted as discarded for want of a reader");
    CHECK(c.opens == 0, "no open has succeeded yet");
    CHECK(c.pipe_bytes == -1, "the pipe size is unknown while not open");
    CHECK(c.stall_events == 1, "a failed write with no streak in progress starts one");
    CHECK(c.write_errors == 0 && c.error_bytes == 0, "a missing reader is not a write error");

    fx.open_reader();
    bool ok2 = writer.write(block.data(), block.size());
    CHECK(ok2, "write() succeeds once a reader has opened the FIFO");
    c = writer.counters();
    CHECK(c.opens == 1, "the first successful open is counted");
    CHECK(c.no_reader_bytes == block.size(), "the earlier loss is not revised by the later success");
    CHECK(writer.stalled_seconds() == 0.0, "a successful write clears the stall streak");

    std::vector<uint8_t> got = fx.read_available(block.size());
    CHECK(got == block, "only the second block reached the pipe; the discarded one is gone");
    CHECK(fx.nothing_more_available(), "nothing further is queued");
}

// ---------------------------------------------------------------------------
// (7) The reader goes away with the pipe full and a tail queued: the next
//     write sees EPIPE, the fd is closed, the tail and the block are counted
//     as lost, and the writer reopens cleanly once a reader is back.
// ---------------------------------------------------------------------------

static void test_broken_pipe_counts_backlog_and_block()
{
    FifoFixture fx;
    FifoWriter  writer;
    writer.set_path(fx.path);

    {
        std::vector<uint8_t> priming = make_pattern(16, /*base=*/0);
        CHECK(writer.write(priming.data(), priming.size()), "priming write succeeds");
        fx.read_available(priming.size());
    }

    int pipe_cap = ::fcntl(fx.reader_fd, F_GETPIPE_SZ);
    CHECK(pipe_cap > 0, "F_GETPIPE_SZ reports the pipe's current capacity");

    const size_t tail_len = 777;
    std::vector<uint8_t> fill = make_pattern(static_cast<size_t>(pipe_cap) + tail_len, /*base=*/7);
    CHECK(!writer.write(fill.data(), fill.size()), "the fill write leaves a tail in the backlog");
    CHECK(writer.counters().backlog_bytes == tail_len, "the tail is queued");

    // The reader goes away with the pipe still full, so the next write's
    // backlog drain meets EPIPE rather than EAGAIN.
    fx.close_reader();

    std::vector<uint8_t> block = make_pattern(2048, /*base=*/9);
    bool ok = writer.write(block.data(), block.size());
    CHECK(!ok, "write() reports false on a broken pipe");
    CHECK(!writer.is_open(), "the fd is closed on a hard error");

    FifoWriter::Counters c = writer.counters();
    CHECK(c.write_errors == 1, "one hard write error");
    CHECK(c.error_bytes == tail_len + block.size(),
          "the queued tail and the whole unattempted block are counted as lost");
    CHECK(c.backlog_bytes == 0, "close() dropped the backlog");
    CHECK(c.pipe_bytes == -1, "the pipe size is unknown once closed");
    CHECK(c.opens == 1, "no reopen has happened yet");

    fx.open_reader();
    std::vector<uint8_t> next = make_pattern(1024, /*base=*/11);
    CHECK(writer.write(next.data(), next.size()), "write() reopens and succeeds once a reader is back");
    c = writer.counters();
    CHECK(c.opens == 2, "the reopen is counted");

    std::vector<uint8_t> got = fx.read_available(next.size() + 1);
    CHECK(got == next, "only the new block is readable: the old pipe's contents went with its last fd");
    CHECK(fx.nothing_more_available(), "nothing further is queued");
}

// ---------------------------------------------------------------------------
// (7) The backlog is sized to its cap at construction and a stall, a drain,
//     an overflow or a close never changes that capacity.
// ---------------------------------------------------------------------------

static void test_backlog_capacity_is_reserved_up_front()
{
    FifoFixture fx;
    FifoWriter  writer;

    size_t cap_bytes = static_cast<size_t>(AudioMonitor::output_rate_hz())
                     * static_cast<size_t>(AudioMonitor::output_bytes_per_frame());
    CHECK(writer.backlog_capacity_bytes() == cap_bytes, "the reported capacity is the cap");
    CHECK(writer.backlog_vector_capacity() >= cap_bytes, "the vector holds the cap from construction");
    const size_t capacity_before = writer.backlog_vector_capacity();

    writer.set_path(fx.path);
    {
        std::vector<uint8_t> priming = make_pattern(16, /*base=*/0);
        CHECK(writer.write(priming.data(), priming.size()), "priming write succeeds");
        fx.read_available(priming.size());
    }

    int pipe_cap = ::fcntl(fx.reader_fd, F_GETPIPE_SZ);
    CHECK(pipe_cap > 0, "F_GETPIPE_SZ reports the pipe's current capacity");

    const size_t tail_len = 777;
    std::vector<uint8_t> fill = make_pattern(static_cast<size_t>(pipe_cap) + tail_len, /*base=*/4);
    CHECK(!writer.write(fill.data(), fill.size()), "the fill write leaves a tail in the backlog");
    CHECK(writer.backlog_vector_capacity() == capacity_before, "queuing a tail does not change the capacity");

    fx.read_available(static_cast<size_t>(pipe_cap));
    std::vector<uint8_t> next = make_pattern(2048, /*base=*/6);
    CHECK(writer.write(next.data(), next.size()), "the drain write succeeds");
    CHECK(writer.backlog_vector_capacity() == capacity_before, "draining does not change the capacity");
    fx.read_available(tail_len + next.size());

    // An overflow drops the queue wholesale; the capacity stays.
    std::vector<uint8_t> fill2 = make_pattern(static_cast<size_t>(pipe_cap) + tail_len, /*base=*/8);
    CHECK(!writer.write(fill2.data(), fill2.size()), "a second fill queues a tail");
    std::vector<uint8_t> oversized = make_pattern(cap_bytes, /*base=*/9);
    CHECK(!writer.write(oversized.data(), oversized.size()), "an oversized block overflows the backlog");
    CHECK(writer.backlog_vector_capacity() == capacity_before, "an overflow does not change the capacity");

    writer.close();
    CHECK(writer.backlog_vector_capacity() == capacity_before, "close() does not change the capacity");
    CHECK(writer.backlog_capacity_bytes() == cap_bytes, "the reported capacity is unchanged");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// The reader-stalled warning goes through the keyed log limit: overflows
// repeated inside one window write one line, and the rest are counted.
// ---------------------------------------------------------------------------

static std::int64_t g_fixed_clock_ns = 1000000000;
static std::int64_t fixed_clock_ns() { return g_fixed_clock_ns; }

static int count_lines_containing(const std::vector<std::string>& lines, const char* needle)
{
    int n = 0;
    for (const std::string& line : lines)
        if (line.find(needle) != std::string::npos)
            ++n;
    return n;
}

static void test_repeated_overflows_write_one_line_per_window()
{
    logger_init(MonitorLogLevel::Warn);
    logger_test_set_clock(fixed_clock_ns);
    LogFileCapture capture;

    FifoFixture fx;
    FifoWriter  writer;
    writer.set_path(fx.path);

    std::vector<uint8_t> priming = make_pattern(16, /*base=*/0);
    writer.write(priming.data(), priming.size());
    fx.read_available(priming.size());
    int pipe_cap = ::fcntl(fx.reader_fd, F_GETPIPE_SZ);
    std::vector<uint8_t> fill = make_pattern(static_cast<size_t>(pipe_cap), /*base=*/2);
    writer.write(fill.data(), fill.size());

    size_t cap_bytes = static_cast<size_t>(AudioMonitor::output_rate_hz())
                     * static_cast<size_t>(AudioMonitor::output_bytes_per_frame());
    std::vector<uint8_t> oversized = make_pattern(cap_bytes + 1, /*base=*/3);
    for (int i = 0; i < 3; ++i)
        writer.write(oversized.data(), oversized.size());
    CHECK(writer.counters().overflow_events == 3, "T15 three overflows happened");

    logger_flush_repeats();
    std::vector<std::string> lines = capture.finish();
    logger_test_set_clock(nullptr);
    logger_init(MonitorLogLevel::Warn);
    CHECK(count_lines_containing(lines, "[fifo] Reader stalled") == 1,
          "T15 one warning for three overflows in a window");
    CHECK(count_lines_containing(lines, "fifo reader stalled: 2 more suppressed") == 1,
          "T15 the other two are counted");
}

int main()
{
    // The broken-pipe test writes to a FIFO whose reader has gone. The
    // daemon ignores SIGPIPE in its own main(); this binary must too, or
    // the kernel kills it before FifoWriter ever sees EPIPE.
    ::signal(SIGPIPE, SIG_IGN);
    logger_init(MonitorLogLevel::Warn);

    test_plain_write_byte_exact();
    test_backlog_fills_and_drains_in_order();
    test_backlog_overflow_drops_wholesale();
    test_end_stream_drops_backlog_and_closes_streak();
    test_end_stream_on_a_healthy_writer_changes_nothing();
    test_no_reader_counts_discarded_bytes();
    test_broken_pipe_counts_backlog_and_block();
    test_backlog_capacity_is_reserved_up_front();
    test_repeated_overflows_write_one_line_per_window();

    logger_shutdown();

    if (g_failed == 0) {
        std::printf("OK  %d/%d tests passed\n", g_tests, g_tests);
        return 0;
    }
    std::fprintf(stderr, "FAIL %d/%d tests failed\n", g_failed, g_tests);
    return 1;
}
