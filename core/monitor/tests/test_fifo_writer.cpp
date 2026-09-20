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

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
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

    FifoFixture()
    {
        char dir_template[] = "/tmp/test_fifo_writer_XXXXXX";
        char* d = ::mkdtemp(dir_template);
        CHECK(d != nullptr, "mkdtemp for FIFO test dir succeeded");
        dir  = d ? d : "";
        path = dir + "/pipe";

        CHECK(::mkfifo(path.c_str(), 0600) == 0, "mkfifo succeeded");

        // Open the reader end first, non-blocking, so FifoWriter's own
        // open() below never blocks or sees ENXIO -- same ordering OwnTone
        // provides in production.
        reader_fd = ::open(path.c_str(), O_RDONLY | O_NONBLOCK);
        CHECK(reader_fd >= 0, "reader open succeeded");
    }

    ~FifoFixture()
    {
        if (reader_fd >= 0)
            ::close(reader_fd);
        ::unlink(path.c_str());
        if (!dir.empty())
            ::rmdir(dir.c_str());
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
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int main()
{
    test_plain_write_byte_exact();
    test_backlog_fills_and_drains_in_order();
    test_backlog_overflow_drops_wholesale();

    if (g_failed == 0) {
        std::printf("OK  %d/%d tests passed\n", g_tests, g_tests);
        return 0;
    }
    std::fprintf(stderr, "FAIL %d/%d tests failed\n", g_failed, g_tests);
    return 1;
}
