// =============================================================================
// autostream_spsc_ring.h
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// SpscRing<T>: a fixed-capacity, power-of-two, single-producer/single-consumer
// ring buffer. Header-only, zero dependencies beyond the C++ standard library
// (pattern of autostream_repeat_buffer.h / autostream_id_tap.h), so it can be
// unit tested (core/monitor/tests/test_spsc_ring.cpp) without any link
// dependencies.
//
// This header exists because the monitor daemon otherwise needs three
// hand-copied SPSC rings -- InputChannel's capture-thread -> process-thread
// ring (int16_t stereo samples), OutputDumpWriter's process-thread ->
// writer-thread ring (int16_t stereo samples), and RepeatRecorder's
// process-thread -> worker-thread ring (float stereo samples, plus a
// parallel metadata ring of per-block info) -- each of which would re-prove
// the same single-writer/single-reader argument in its own comments and
// re-implement the same masked-index, two-segment-memcpy bulk transfer,
// so a fix in one copy would not reach the others. This header is that
// logic, written once.
//
// ---------------------------------------------------------------------------
// The canonical SPSC single-writer argument (ported from the strongest of
// the three original proof comments, formerly at autostream_monitor_io.cpp
// ~1215-1219; this paragraph now replaces that comment and its two siblings)
// ---------------------------------------------------------------------------
//
// _write_pos is written ONLY by the producer thread; _read_pos is written
// ONLY by the consumer thread. Each side only ever *reads* the other side's
// position atomically. This is what makes the ring safe without a mutex:
// there is never more than one writer for either atomic, so a plain
// std::atomic<size_t> with acquire/release ordering is sufficient --
// std::memory_order_seq_cst is not needed, and no lock is needed.
//
//   - The producer loads its own _write_pos with memory_order_relaxed (no
//     other thread ever writes it, so there is nothing to synchronise with),
//     loads the consumer's _read_pos with memory_order_acquire (to see the
//     most recently freed space), copies data into the ring, then publishes
//     the new _write_pos with memory_order_release (fetch_add) -- this
//     release makes the just-written ring contents visible to the consumer's
//     next acquire load of _write_pos.
//   - The consumer is the mirror image: relaxed load of its own _read_pos,
//     acquire load of the producer's _write_pos (to see the most recently
//     published data), copies data out, then a release store of the new
//     _read_pos.
//
// If the ring is full (producer) or empty (consumer), that is the caller's
// problem: this class never blocks and never overwrites unread data. Overflow
// policy (drop-and-count, block, etc.) is deliberately NOT decided here -- it
// stays at each call site, unchanged from before this class existed. The
// usual pattern is: caller checks write_available()/read_available() first,
// then calls write()/read() only with an amount it already knows fits.
// =============================================================================

#pragma once

#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <vector>

template <typename T>
class SpscRing
{
public:
    // capacity must be a power of two (asserted). The ring holds up to
    // `capacity` elements of T; one slot is NOT reserved (unlike some ring
    // designs) because capacity is tracked via a running (unwrapped) position
    // difference, not a full/empty sentinel -- exactly matching the three
    // original hand-rolled rings this replaces.
    explicit SpscRing(size_t capacity)
        : _capacity(capacity)
        , _mask(capacity - 1)
        , _buf(capacity)
    {
        assert(capacity > 0 && (capacity & (capacity - 1)) == 0 &&
               "SpscRing capacity must be a power of two");
    }

    size_t capacity() const { return _capacity; }

    // Producer-side: how many elements can be written right now without
    // overwriting unread data. Safe to call from the producer thread only
    // (reads the consumer's _read_pos with acquire ordering).
    size_t write_available() const
    {
        size_t w = _write_pos.load(std::memory_order_relaxed);
        size_t r = _read_pos.load(std::memory_order_acquire);
        return _capacity - (w - r);
    }

    // Consumer-side: how many elements are available to read right now.
    // Safe to call from the consumer thread only (reads the producer's
    // _write_pos with acquire ordering).
    size_t read_available() const
    {
        size_t w = _write_pos.load(std::memory_order_acquire);
        size_t r = _read_pos.load(std::memory_order_relaxed);
        return w - r;
    }

    // Copies n elements from src into the ring (two-segment split at the
    // wrap boundary, exactly as the original hand-rolled copies did) and
    // publishes the new write position with a release fetch_add.
    //
    // Precondition: n <= write_available() (i.e. the caller already checked
    // there is room, as every original call site did before touching the
    // ring). This function does not re-check or clamp -- that mirrors the
    // original code shape exactly (no extra branch on the hot path) and
    // keeps the drop-vs-accept decision entirely at the call site.
    void write(const T* src, size_t n)
    {
        size_t w        = _write_pos.load(std::memory_order_relaxed);
        size_t write_idx = w & _mask;
        size_t to_end    = _capacity - write_idx;
        size_t first     = n < to_end ? n : to_end;
        size_t second    = n - first;

        std::memcpy(_buf.data() + write_idx, src, first * sizeof(T));
        if (second > 0)
            std::memcpy(_buf.data(), src + first, second * sizeof(T));

        // Release: makes the copied data visible to the consumer's next
        // acquire load of _write_pos (read_available() / read()'s internal
        // load). fetch_add matches all three original producer sites.
        _write_pos.fetch_add(n, std::memory_order_release);
    }

    // Copies n elements out of the ring into dst (two-segment split) and
    // publishes the new read position with a release store.
    //
    // Precondition: n <= read_available() (caller already checked). No
    // internal re-check, for the same reason as write().
    //
    // The new read position is published via a plain release store of a
    // value already computed from the read position this call itself loaded
    // (not a fetch_add) -- equivalent for a single consumer, and matches the
    // cheapest of the three original consumer sites
    // (InputChannel::process_thread_func()'s ring drain).
    void read(T* dst, size_t n)
    {
        size_t r        = _read_pos.load(std::memory_order_relaxed);
        size_t read_idx = r & _mask;
        size_t to_end    = _capacity - read_idx;
        size_t first     = n < to_end ? n : to_end;
        size_t second    = n - first;

        std::memcpy(dst, _buf.data() + read_idx, first * sizeof(T));
        if (second > 0)
            std::memcpy(dst + first, _buf.data(), second * sizeof(T));

        _read_pos.store(r + n, std::memory_order_release);
    }

    // Resets both positions to zero. Only safe when neither the producer nor
    // the consumer thread is running (e.g. before starting a fresh session),
    // matching how the original rings were reset at start()/session-open.
    void reset()
    {
        _write_pos.store(0, std::memory_order_relaxed);
        _read_pos.store(0, std::memory_order_relaxed);
    }

private:
    const size_t          _capacity;
    const size_t          _mask;
    std::vector<T>         _buf;
    std::atomic<size_t>    _write_pos{0};  // written only by the producer thread
    std::atomic<size_t>    _read_pos{0};   // written only by the consumer thread
};
