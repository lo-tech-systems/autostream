// =============================================================================
// test_spsc_ring.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Unit tests for autostream_spsc_ring.h's SpscRing<T>.
//
// Test coverage:
//   - Fresh-ring accounting: write_available()/read_available() start at
//     capacity/0.
//   - Fill/drain exactness: writing N elements and reading them back yields
//     the same N elements in the same order, with accounting updated exactly.
//   - Wraparound at the mask boundary: repeated write/read cycles that walk
//     the position counters across the capacity boundary, including a single
//     write/read that straddles the boundary (exercises the two-segment
//     split on both write() and read()).
//   - write_available()/read_available() sum to capacity() at all times
//     (no element is ever double-counted or lost from the accounting).
//   - A hammer test: two real threads (producer/consumer), millions of
//     sequence-numbered elements, producer drops-and-retries on a full ring
//     exactly like every real call site does (check write_available() first),
//     consumer asserts strict sequence order with no loss/duplication.
//
// Build (on Linux/WSL, from repo root):
//   g++ -std=c++17 -Wall -Wextra -O2 -I core/monitor \
//       core/monitor/tests/test_spsc_ring.cpp \
//       -lpthread \
//       -o /tmp/test_spsc_ring && /tmp/test_spsc_ring
// =============================================================================

#include "autostream_spsc_ring.h"

#include <cstdio>
#include <cstdint>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
// Minimal assertion harness (matches test_id_tap.cpp / test_repeat_buffer.cpp)
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
// Basic accounting on a fresh ring
// ---------------------------------------------------------------------------

static void test_fresh_ring_accounting()
{
    SpscRing<int> ring(16);
    CHECK(ring.capacity() == 16, "capacity() reports constructor value");
    CHECK(ring.write_available() == 16, "fresh ring: full write availability");
    CHECK(ring.read_available() == 0, "fresh ring: no read availability");
}

// ---------------------------------------------------------------------------
// Fill/drain exactness
// ---------------------------------------------------------------------------

static void test_fill_drain_exactness()
{
    SpscRing<int> ring(16);

    std::vector<int> src(10);
    for (int i = 0; i < 10; ++i) src[static_cast<size_t>(i)] = 1000 + i;

    CHECK(ring.write_available() >= 10, "room for 10 elements");
    ring.write(src.data(), 10);

    CHECK(ring.read_available() == 10, "read_available reflects the write");
    CHECK(ring.write_available() == 6, "write_available shrinks by 10");

    std::vector<int> dst(10, -1);
    ring.read(dst.data(), 10);

    CHECK(dst == src, "read() returns exactly what was written, same order");
    CHECK(ring.read_available() == 0, "ring drained to empty");
    CHECK(ring.write_available() == 16, "full capacity reclaimed after drain");
}

// ---------------------------------------------------------------------------
// write_available()+read_available() == capacity() invariant, across many
// partial fill/drain cycles (not just the empty/full extremes).
// ---------------------------------------------------------------------------

static void test_availability_invariant()
{
    SpscRing<int> ring(32);
    std::vector<int> buf(32);
    for (int i = 0; i < 32; ++i) buf[static_cast<size_t>(i)] = i;

    for (int cycle = 0; cycle < 50; ++cycle)
    {
        size_t n = static_cast<size_t>((cycle * 7) % 20) + 1;  // 1..20
        if (n > ring.write_available())
            n = ring.write_available();
        if (n > 0)
            ring.write(buf.data(), n);

        CHECK(ring.write_available() + ring.read_available() == ring.capacity(),
              "availability invariant holds after write");

        size_t rn = ring.read_available() / 2;  // drain half
        std::vector<int> out(rn);
        if (rn > 0)
            ring.read(out.data(), rn);

        CHECK(ring.write_available() + ring.read_available() == ring.capacity(),
              "availability invariant holds after read");
    }
}

// ---------------------------------------------------------------------------
// Wraparound at the mask boundary: drive the position counters across the
// capacity boundary repeatedly, including a write/read that straddles it
// (exercises the two-segment memcpy split in both write() and read()).
// ---------------------------------------------------------------------------

static void test_wraparound_split()
{
    SpscRing<int> ring(8);

    // Walk the ring around several times with a chunk size that does not
    // evenly divide the capacity, so eventually a write (and a read) must
    // straddle the wrap boundary.
    int next_value = 0;
    long total_written = 0;
    long total_read     = 0;
    std::vector<int> verify;

    for (int round = 0; round < 40; ++round)
    {
        size_t n = 3;  // 8 % 3 != 0 -> guarantees eventual straddling writes
        if (n > ring.write_available())
        {
            // Drain first (consumer side) so the test can keep advancing --
            // mirrors a real consumer keeping up with a producer.
            size_t avail = ring.read_available();
            std::vector<int> dst(avail);
            ring.read(dst.data(), avail);
            for (int v : dst)
            {
                CHECK(v == verify[static_cast<size_t>(total_read)],
                      "wraparound: read value matches expected sequence");
                ++total_read;
            }
        }

        std::vector<int> src(n);
        for (size_t i = 0; i < n; ++i)
        {
            src[i] = next_value;
            verify.push_back(next_value);
            ++next_value;
        }
        ring.write(src.data(), n);
        total_written += static_cast<long>(n);
    }

    // Final drain.
    size_t avail = ring.read_available();
    std::vector<int> dst(avail);
    ring.read(dst.data(), avail);
    for (int v : dst)
    {
        CHECK(v == verify[static_cast<size_t>(total_read)],
              "wraparound: final drain matches expected sequence");
        ++total_read;
    }

    CHECK(total_read == total_written, "wraparound: every written element was read exactly once");
    CHECK(ring.read_available() == 0, "wraparound: ring empty at the end");
    CHECK(ring.write_available() == ring.capacity(), "wraparound: full capacity reclaimed at the end");
}

// A single write/read pair explicitly straddling the wrap boundary, checked
// element-by-element -- the most direct test of the two-segment split.
static void test_explicit_straddle()
{
    SpscRing<int> ring(8);

    std::vector<int> a = {1, 2, 3, 4, 5, 6};
    ring.write(a.data(), a.size());   // write_pos = 6

    std::vector<int> drain1(4);
    ring.read(drain1.data(), 4);      // read_pos = 4, ring now holds {5,6} logically

    // write_available() == 8 - (6-4) == 6; write 6 elements, which must wrap:
    // indices 6,7 (2 slots to end) then 0,1,2,3 (4 more) -- a genuine straddle.
    std::vector<int> b = {10, 11, 12, 13, 14, 15};
    CHECK(ring.write_available() == 6, "straddle setup: expected free space before wrap-write");
    ring.write(b.data(), b.size());

    std::vector<int> out(8, -1);
    ring.read(out.data(), 8);  // {5,6,10,11,12,13,14,15}
    std::vector<int> expected = {5, 6, 10, 11, 12, 13, 14, 15};
    CHECK(out == expected, "explicit straddle: two-segment split preserves order and values");
}

// ---------------------------------------------------------------------------
// Producer/consumer thread hammer test.
//
// Real call sites drop-and-count on a full ring rather than blocking, so this
// test mirrors that: the producer checks write_available() and, if the block
// doesn't fit, spins briefly and retries (never drops -- we want an exact
// count assertion at the end, not a drop-tolerant one) rather than looping
// forever burning the single core on some CI runners; a short yield keeps it
// well-behaved. The consumer never busy-waits on empty either.
// ---------------------------------------------------------------------------

static void test_producer_consumer_hammer()
{
    constexpr size_t kCapacity   = 1u << 12;   // 4096, power of two
    constexpr size_t kTotal      = 4'000'000;  // several million elements
    constexpr size_t kBlockElems = 37;         // odd size -> forces wraps

    SpscRing<uint64_t> ring(kCapacity);

    std::vector<uint64_t> observed;
    observed.reserve(kTotal);

    std::thread producer([&]()
    {
        uint64_t next = 0;
        std::vector<uint64_t> block(kBlockElems);
        while (next < kTotal)
        {
            size_t n = kBlockElems;
            if (next + n > kTotal)
                n = kTotal - next;

            while (ring.write_available() < n)
                std::this_thread::yield();

            for (size_t i = 0; i < n; ++i)
                block[i] = next + i;

            ring.write(block.data(), n);
            next += n;
        }
    });

    std::thread consumer([&]()
    {
        size_t received = 0;
        std::vector<uint64_t> block(kBlockElems);
        while (received < kTotal)
        {
            size_t avail = ring.read_available();
            if (avail == 0)
            {
                std::this_thread::yield();
                continue;
            }
            size_t n = avail < kBlockElems ? avail : kBlockElems;
            if (n > kTotal - received)
                n = kTotal - received;
            if (n == 0)
                continue;

            ring.read(block.data(), n);
            for (size_t i = 0; i < n; ++i)
                observed.push_back(block[i]);
            received += n;
        }
    });

    producer.join();
    consumer.join();

    CHECK(observed.size() == kTotal, "hammer test: element count matches (no loss, no duplication)");

    bool in_order = true;
    for (size_t i = 0; i < observed.size(); ++i)
    {
        if (observed[i] != static_cast<uint64_t>(i))
        {
            in_order = false;
            break;
        }
    }
    CHECK(in_order, "hammer test: sequence numbers arrive strictly in order, unbroken");
}

// ---------------------------------------------------------------------------
// A non-trivial payload type (POD struct), matching RepeatRecorder's
// BlockMeta usage of SpscRing<T> with T != a scalar.
// ---------------------------------------------------------------------------

struct Meta
{
    uint32_t frames          = 0;
    bool     above_threshold = false;
};

static void test_pod_struct_payload()
{
    SpscRing<Meta> ring(4);

    Meta m1{100, true};
    Meta m2{200, false};
    ring.write(&m1, 1);
    ring.write(&m2, 1);

    CHECK(ring.read_available() == 2, "struct payload: read_available counts elements, not bytes");

    Meta out{};
    ring.read(&out, 1);
    CHECK(out.frames == 100 && out.above_threshold == true, "struct payload: first read matches first write (FIFO)");

    ring.read(&out, 1);
    CHECK(out.frames == 200 && out.above_threshold == false, "struct payload: second read matches second write");
}

// ---------------------------------------------------------------------------

int main()
{
    test_fresh_ring_accounting();
    test_fill_drain_exactness();
    test_availability_invariant();
    test_wraparound_split();
    test_explicit_straddle();
    test_pod_struct_payload();
    test_producer_consumer_hammer();

    std::printf("test_spsc_ring: %d/%d checks passed\n", g_tests - g_failed, g_tests);
    return g_failed == 0 ? 0 : 1;
}
