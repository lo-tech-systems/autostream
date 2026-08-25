// =============================================================================
// autostream_repeat_buffer.h
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Header-only, pure (C++ standard library only) core of the "repeat" feature:
//
//   - RepeatBuffer / RepeatBuffer::Reader — chunked in-RAM store for the
//     recording, plus a sequential reader for replay.
//   - CodecChoice / pick_codec_for_target() / byte_rate_for() — the codec
//     ladder that picks recording quality to guarantee a target duration in
//     free RAM.
//   - ArenaPlan / plan_arena() — the fixed-arena sizing formula.
//   - parse_meminfo_text() — a pure parser for /proc/meminfo TEXT; the file
//     I/O wrapper that reads the real file lives in the impure .cpp.
//   - SilenceTrimAccountant — byte-accounting helper for the end-of-recording
//     silence trim.
//
// This file has NO ALSA / libsamplerate / twolame / mpg123 / system includes
// beyond the C++ standard library, exactly like autostream_track_gap_detector.h,
// so it can be unit tested (core/monitor/tests/test_repeat_buffer.cpp) without
// any link dependencies and included directly by the daemon proper
// (autostream_monitor.h / autostream_repeat.cpp).
// =============================================================================

#pragma once

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

// =============================================================================
// RepeatBuffer — chunked heap store for the in-RAM recording
//
// The recording is a sequence of fixed-size heap chunks (16 MiB in production;
// see the constructor).  Chunks are allocated lazily as data arrives and freed
// from the front (oldest first) under memory pressure, giving a sliding
// window: the buffer holds "as much of the recording as currently fits",
// biased toward keeping the most recent audio.
//
// NOT thread-safe.  In the daemon this is owned by RepeatController and all
// access happens under _repeat_mutex; the recorder worker thread appends,
// the replay thread only reads via Reader.
//
// The production chunk size is 16 MiB (RepeatBuffer::kDefaultChunkBytes).
// Tests inject a much smaller chunk size via the constructor so that chunk-
// boundary and multi-chunk behaviour (append rollover, drop_oldest_chunk,
// Reader clamping) can be exercised without slowly allocating real 16 MiB
// blocks (unit tests U1/U2).
// =============================================================================

class RepeatBuffer
{
public:
    // Production chunk size. Tests pass a smaller value.
    static constexpr size_t kDefaultChunkBytes = 16u * 1024 * 1024;

    struct Chunk
    {
        std::unique_ptr<uint8_t[]> data;
        size_t used     = 0;   // bytes written so far
        size_t capacity = 0;   // == chunk_bytes at construction time
    };

    explicit RepeatBuffer(size_t chunk_bytes = kDefaultChunkBytes)
        : _chunk_bytes(chunk_bytes)
    {
    }

    // Appends len bytes, allocating new chunks as needed (in fixed-capacity
    // arena mode -- see preallocate_one_more_chunk() -- "allocating" means
    // drawing from the spare pool or recycling the front chunk; see
    // allocate_chunk()). The recorder only ever appends whole encoded frames
    // (MP2 frame or PCM sample-aligned block), so chunk boundaries always
    // land on frame boundaries by construction — this function does not need
    // to know about frames.
    //
    // Returns false only if a new chunk allocation itself failed (out of
    // memory / address space -- effectively unreachable once an arena is
    // built, since allocate_chunk() then only draws from the spare pool or
    // recycles, never calling new). The legacy (non-arena) memory-guard
    // *policy* this function's OOM contract exists for -- checking
    // /proc/meminfo before allocating and calling drop_oldest_chunk()
    // pre-emptively to stay above the free-RAM floor -- was orchestrated by
    // the impure RepeatController; the fixed-arena model
    // replaces that per-append policy with the up-front build loop instead.
    bool append(const uint8_t* data, size_t len)
    {
        size_t written = 0;
        while (written < len)
        {
            if (_chunks.empty() || _chunks.back().used == _chunks.back().capacity)
            {
                if (!allocate_chunk())
                    return false;
            }
            Chunk& c = _chunks.back();
            size_t space = c.capacity - c.used;
            size_t n     = (len - written < space) ? (len - written) : space;
            std::memcpy(c.data.get() + c.used, data + written, n);
            c.used += n;
            _total_bytes += n;
            written += n;
        }
        return true;
    }

    // Allocates one chunk's worth of raw storage, WITHOUT touching this (or
    // any) RepeatBuffer instance. Static and side-effect-free on purpose:
    // the impure caller (RepeatController::process_recorder_samples())
    // calls this OUTSIDE whatever lock guards the buffer (_repeat_mutex),
    // then hands the result to append_with_preallocated() once it re-holds
    // the lock, so the potentially-slow allocation itself never happens
    // while the lock is held. Returns nullptr on allocation failure (same
    // OOM contract as append()'s internal allocate_chunk()).
    static std::unique_ptr<uint8_t[]> allocate_chunk_storage(size_t chunk_bytes)
    {
        try
        {
            return std::unique_ptr<uint8_t[]>(new uint8_t[chunk_bytes]);
        }
        catch (const std::bad_alloc&)
        {
            return nullptr;
        }
    }

    // Frees the oldest (front) chunk — the sliding-window mechanism.  Never
    // frees the last remaining chunk, even if empty: the buffer always keeps
    // at least one chunk once anything has been appended, so a Reader always
    // has a valid head to clamp to (unit test U2).  Latches truncated_head().
    //
    // Thin wrapper over evict_front(): this call site simply discards the
    // returned Chunk (and with it, the storage), which is exactly the
    // "free it" semantic this function's name promises. The fixed-capacity
    // arena's own recycle path (allocate_chunk()) calls evict_front()
    // directly instead, because it wants that same eviction bookkeeping
    // WITHOUT losing the storage -- see evict_front()'s own comment.
    void drop_oldest_chunk()
    {
        evict_front();
    }

    // Adds one committed chunk's worth of raw storage to the spare pool: a
    // loop-step primitive the CONTROLLER drives, chunk by chunk, to build a
    // fixed arena incrementally rather than in one giant up-front
    // allocation. Built on the existing allocate_chunk_storage() (no new
    // allocation code path), then every page is touched through a VOLATILE
    // write -- this is not about the stored value (allocate_chunk() below
    // always sets used = 0 before any byte of a spare chunk is ever read
    // back), it is about physically committing the pages. Under Linux's
    // default memory-overcommit policy, a fresh new[]/malloc reserves
    // address space but not physical RAM; the pages are not charged against
    // the system until something writes to them. Skipping the touch would
    // mean "successfully preallocated N chunks" is a lie the kernel is free
    // to call at the worst possible moment -- the first real write deep
    // into a long recording, at which point overcommit failure is a SIGKILL
    // from the OOM killer, not a catchable bad_alloc.
    //
    // Volatile, NOT memset: a plain memset-to-zero over freshly allocated
    // memory is exactly the dead store the optimizer is entitled to remove
    // (and demonstrably does at -O2 -- an arena "committed" that way showed
    // Rss 0 across every chunk in /proc/<pid>/smaps, i.e. not one page was
    // ever faulted in, silently reintroducing the OOM-kill exposure this
    // function exists to close). One volatile store per 4 KiB page cannot
    // be elided and faults each page in for a few thousand stores per
    // 16 MiB chunk -- negligible against the page-fault cost itself.
    //
    // Committing the pages here, one chunk at a time on the controller's
    // own incremental loop (see RepeatController::maybe_build_arena()), is
    // what turns "the arena exists" into a fact rather than a promise.
    // Also latches the fixed-capacity flag (see allocate_chunk()) --
    // calling this even once switches the buffer from legacy grow-and-free
    // mode into fixed-arena recycle mode for the rest of its life
    // (clear()/steal_chunks() are what turn it back off). Returns false on
    // allocation failure (out of address space -- distinct from the
    // overcommit case the page touch defends against), leaving the spare
    // pool and the fixed-capacity flag exactly as they were.
    bool preallocate_one_more_chunk()
    {
        auto storage = allocate_chunk_storage(_chunk_bytes);
        if (!storage)
            return false;
        volatile uint8_t* pages = storage.get();
        constexpr size_t kPageBytes = 4096;
        for (size_t off = 0; off < _chunk_bytes; off += kPageBytes)
            pages[off] = 0;
        if (_chunk_bytes > 0)
            pages[_chunk_bytes - 1] = 0;   // last page, if not stride-aligned
        _spare_storage.push_back(std::move(storage));
        _fixed_capacity = true;
        return true;
    }

    // Removes bytes_from_end bytes from the tail, across chunk boundaries.
    // The caller (silence trim) has already frame-aligned the byte count.
    // Clamped to total_bytes() — truncating "the whole buffer" empties
    // it cleanly rather than underflowing.
    //
    // In fixed-capacity mode (see allocate_chunk()/preallocate_one_more_
    // chunk()), an emptied tail chunk's storage is returned to the spare
    // pool instead of being destroyed -- the per-session end-of-recording
    // silence trim runs every session, and destroying chunks here would
    // silently erode the arena's total capacity, one trim at a time, until
    // nothing was left of a reservation the controller believes is still
    // intact. Legacy (non-fixed) mode keeps today's exact behaviour: the
    // chunk is popped and its storage freed with it.
    void truncate_tail(size_t bytes_from_end)
    {
        size_t remaining = bytes_from_end;
        if (remaining > total_bytes())
            remaining = total_bytes();

        size_t to_remove = remaining;   // exact amount being removed overall
        while (remaining > 0 && !_chunks.empty())
        {
            Chunk& c = _chunks.back();
            if (c.used <= remaining)
            {
                remaining -= c.used;
                c.used = 0;
                // Drop the now-empty tail chunk unless it is the sole chunk
                // (keep a live, empty chunk rather than an empty deque so
                // append() after a full truncate behaves like a fresh buffer
                // with the same chunk size).
                if (_chunks.size() > 1)
                {
                    if (_fixed_capacity)
                        _spare_storage.push_back(std::move(c.data));
                    _chunks.pop_back();
                }
            }
            else
            {
                c.used -= remaining;
                remaining = 0;
            }
        }
        _total_bytes -= (to_remove - remaining);   // always 0 by loop end, but
                                                    // written this way so a future
                                                    // change to the loop's exit
                                                    // conditions can't silently
                                                    // desync the two
    }

    // Session start without freeing: every existing chunk's storage is
    // returned to the spare pool -- as if it had never been drawn out of it
    // -- and the buffer's cursors reset to a fresh, empty state, but the
    // arena's total committed page count (chunk_count() + spare_chunk_
    // count()) is unchanged. The next session's appends reuse this exact
    // storage front-first via allocate_chunk()'s spare-pool draw, never
    // touching new/delete -- this is what "the arena persists across
    // sessions, only cursors reset" actually means at the
    // storage level. Distinct from clear()/steal_chunks(), which genuinely
    // free everything and are used only when the feature is being disabled,
    // not between sessions.
    //
    // Contract: the caller (RepeatController) must guarantee no live Reader
    // spans this call. A Reader tracks position as an absolute chunk
    // sequence number (see the Reader class comment) and clamps forward when
    // its chunk has merely been dropped from the head -- but reset_cursors()
    // renumbers the ENTIRE sequence back to zero, so a Reader constructed
    // before this call has no well-defined relationship to the buffer
    // afterward; nothing here detects or guards against that case. The
    // state machine already guarantees Recording and Replaying are mutually
    // exclusive on one controller, which is what makes this safe in
    // practice.
    void reset_cursors()
    {
        while (!_chunks.empty())
        {
            _spare_storage.push_back(std::move(_chunks.front().data));
            _chunks.pop_front();
        }
        _head_seq       = 0;
        _total_bytes    = 0;
        _truncated_head = false;
    }

    // Frees everything; resets to a brand-new buffer of the same chunk size.
    // Also frees the spare pool and clears the fixed-capacity flag (see
    // preallocate_one_more_chunk()) -- this is the feature-disable call, the
    // one place a fixed arena is actually torn down rather than merely
    // having its cursors reset (reset_cursors(), above, is the between-
    // sessions call while the feature stays enabled).
    void clear()
    {
        _chunks.clear();
        _spare_storage.clear();
        _head_seq        = 0;
        _truncated_head  = false;
        _total_bytes     = 0;
        _fixed_capacity  = false;
    }

    // Detaches (moves out) every chunk and returns them, leaving *this*
    // freshly cleared (equivalent to clear()). Lets the caller destroy the
    // actual chunk storage OUTSIDE whatever lock guards this buffer -- e.g.
    // RepeatController::_repeat_mutex -- since destructing a large
    // recording's worth of 16 MiB chunks is not instantaneous and holding a
    // mutex across it would stall every other caller (get_status(),
    // set_enabled(), notify_capture_stopped(), ...) for no good reason. The
    // returned container's destructor does the actual freeing; callers
    // arrange for it to run after they have released their lock (declare
    // the local variable that receives this return value BEFORE the
    // lock_guard, so it is destroyed AFTER the lock_guard per C++'s
    // reverse-order-of-construction local destruction rule).
    //
    // A fixed arena also has spare-pool storage (chunks preallocated but
    // never drawn into _chunks -- see preallocate_one_more_chunk()), which
    // is just as expensive to destroy and just as much in need of an
    // outside-the-lock free. out_spare_storage, if non-null, receives that
    // pool (moved out, same deferred-destruction contract as the returned
    // deque -- declare it before the same lock_guard the return value's
    // receiving variable is declared before). Left as an optional out-param
    // rather than folding spare storage into the return type so every
    // existing legacy caller (which never had a spare pool to worry about)
    // keeps compiling unchanged. Also clears the fixed-capacity flag, same
    // as clear() -- like clear(), this is a feature-disable call.
    std::deque<Chunk> steal_chunks(std::deque<std::unique_ptr<uint8_t[]>>* out_spare_storage = nullptr)
    {
        std::deque<Chunk> stolen = std::move(_chunks);
        _chunks.clear();
        if (out_spare_storage)
            *out_spare_storage = std::move(_spare_storage);
        _spare_storage.clear();
        _head_seq       = 0;
        _truncated_head = false;
        _total_bytes    = 0;
        _fixed_capacity = false;
        return stolen;
    }

    // O(1): backed by an incrementally-maintained counter rather than
    // summing every chunk's `used` on every call -- this sits on
    // RepeatController::get_status()'s poll path, i.e. it must not scale
    // with recording length (O(recording length / 16 MiB) would be too
    // slow there).
    size_t total_bytes() const { return _total_bytes; }

    // True once any chunk has ever been dropped by drop_oldest_chunk() —
    // i.e. the recording's head has been truncated by memory pressure and
    // replay will only ever see the tail (surfaced in status as
    // recording.truncated_head).
    bool truncated_head() const { return _truncated_head; }

    size_t chunk_bytes() const { return _chunk_bytes; }
    size_t chunk_count() const { return _chunks.size(); }

    // Number of chunks currently sitting in the spare pool -- preallocated
    // (and, for reset_cursors()/truncate_tail()'s returns, previously
    // committed) storage not currently part of _chunks. Together with
    // chunk_count() this is the arena's true page-committed footprint; see
    // arena_bytes() below.
    size_t spare_chunk_count() const { return _spare_storage.size(); }

    // True once preallocate_one_more_chunk() has ever been called (and
    // stays true until clear()/steal_chunks() tears the arena down). While
    // true, allocate_chunk() never calls new -- it draws from the spare pool
    // or recycles the front chunk instead (see allocate_chunk()'s own
    // comment). Exposed mainly for tests; production callers drive this
    // indirectly via preallocate_one_more_chunk()/clear()/steal_chunks()
    // rather than setting it themselves -- there is no public setter.
    bool fixed_capacity() const { return _fixed_capacity; }

    // Total bytes currently committed to this arena: (chunk_count() +
    // spare_chunk_count()) * chunk_bytes(). Zero outside fixed-capacity
    // mode, by construction (chunk_count() alone is the meaningful figure
    // for the legacy grow-and-free buffer, and spare_chunk_count() is
    // always zero there since nothing but preallocate_one_more_chunk() ever
    // populates the spare pool). This, not total_bytes() (which only counts
    // bytes actually WRITTEN so far), is the figure that should back a
    // status surface's "arena size" reporting -- total_bytes() dips after
    // every reset_cursors()/truncate_tail() even though the arena itself
    // hasn't shrunk.
    size_t arena_bytes() const
    {
        if (!_fixed_capacity)
            return 0;
        return (_chunks.size() + _spare_storage.size()) * _chunk_bytes;
    }

    // -------------------------------------------------------------------
    // Reader — sequential cursor for replay.
    //
    // Tracks position as an absolute chunk sequence number (not a deque
    // index), because drop_oldest_chunk() shifts every remaining chunk's
    // deque index down by one.  RepeatBuffer::_head_seq is the sequence
    // number of _chunks.front(); a Reader whose cursor has fallen behind
    // _head_seq (its chunk was dropped out from under it while replay was
    // paused/slow) clamps forward to the new head on the next read rather
    // than reading stale/reused memory or crashing (unit test U5).
    // -------------------------------------------------------------------
    class Reader
    {
    public:
        explicit Reader(const RepeatBuffer& buffer)
            : _buffer(&buffer), _chunk_seq(buffer._head_seq), _offset(0)
        {
        }

        // Copies up to max_len bytes into out, advancing the cursor.
        // Returns the number of bytes actually copied (0 at end of buffer).
        size_t next(uint8_t* out, size_t max_len)
        {
            clamp_to_head();

            size_t written = 0;
            while (written < max_len)
            {
                size_t chunk_index_bound = _buffer->_head_seq + _buffer->_chunks.size();
                if (_chunk_seq >= chunk_index_bound)
                    break;  // caught up with the writer; nothing more to read yet

                const Chunk& c = _buffer->_chunks[_chunk_seq - _buffer->_head_seq];
                if (_offset >= c.used)
                {
                    // Exhausted this chunk; move to the next one.
                    ++_chunk_seq;
                    _offset = 0;
                    continue;
                }

                size_t avail = c.used - _offset;
                size_t n     = (max_len - written < avail) ? (max_len - written) : avail;
                std::memcpy(out + written, c.data.get() + _offset, n);
                _offset += n;
                written += n;
            }
            return written;
        }

        // Returns to the current head of the buffer (used at loop restart
        // and by ReplayEngine when a new recording begins).
        void rewind()
        {
            _chunk_seq = _buffer->_head_seq;
            _offset    = 0;
        }

    private:
        void clamp_to_head()
        {
            if (_chunk_seq < _buffer->_head_seq)
            {
                _chunk_seq = _buffer->_head_seq;
                _offset    = 0;
            }
        }

        const RepeatBuffer* _buffer;
        size_t _chunk_seq;  // absolute sequence number of the chunk being read
        size_t _offset;     // byte offset within that chunk
    };

private:
    // Shared eviction bookkeeping for the front (oldest) chunk -- factored
    // out so drop_oldest_chunk() (discards the returned chunk) and
    // allocate_chunk()'s fixed-capacity recycle path (reuses the returned
    // chunk's storage as the new back chunk) share the EXACT SAME
    // consequences for every other piece of buffer state: _total_bytes
    // debited by the evicted chunk's `used`, _head_seq advanced, and
    // truncated_head() latched. That last part matters even on the recycle
    // path: a live Reader's clamp_to_head() only knows "the head moved
    // forward", not "the head moved forward because of memory pressure" vs
    // "because the arena wrapped" -- recycling under a fixed arena and
    // dropping under the legacy grow-and-free buffer are the same event
    // from a Reader's point of view, by construction, because they share
    // this one code path rather than parallel copies that could drift.
    //
    // Never evicts the only remaining chunk (returns a default-constructed
    // Chunk, whose `data` is null) -- the buffer always keeps at least one
    // chunk once anything has been appended, so a Reader always has a valid
    // head to clamp to (unit test U2). Callers MUST check the returned
    // Chunk's `data` for null before relying on it.
    Chunk evict_front()
    {
        if (_chunks.size() <= 1)
            return Chunk{};
        Chunk front = std::move(_chunks.front());
        _total_bytes -= front.used;   // keep the incremental counter exact
        _chunks.pop_front();
        ++_head_seq;
        _truncated_head = true;
        return front;
    }

    // Grows _chunks by exactly one chunk. Three sources, tried in order:
    //
    //   1. The spare pool (preallocate_one_more_chunk()'s committed
    //      storage, or storage handed back by reset_cursors()/
    //      truncate_tail() in fixed-capacity mode) -- adopted with
    //      used = 0. This is the common case once an arena has been built:
    //      append() never actually touches new/delete during normal
    //      recording, only at arena-build time.
    //   2. If the spare pool is empty AND fixed_capacity() is true (the
    //      arena is fully committed and every one of its chunks is already
    //      live in _chunks, all full): RECYCLE. evict_front() donates the
    //      current front chunk's storage, which becomes the new back chunk
    //      with used = 0 -- this is the wrap-around/keeps-last-N-minutes
    //      mechanism. Deliberately never calls new here:
    //      a fixed arena's whole point is that its footprint stops growing
    //      once built, however long recording continues. If evict_front()
    //      itself refuses (only one chunk exists -- see its own comment),
    //      this returns false: a one-chunk arena that is already full and
    //      has nothing to recycle simply cannot accept more data, which is
    //      the correct, if degenerate, outcome for an arena that small.
    //   3. Neither of the above (fixed_capacity() is false -- the legacy,
    //      pre-arena buffer): fall back to a normal heap allocation, exactly
    //      as this function always has.
    bool allocate_chunk()
    {
        if (!_spare_storage.empty())
        {
            Chunk c;
            c.data     = std::move(_spare_storage.front());
            _spare_storage.pop_front();
            c.capacity = _chunk_bytes;
            c.used     = 0;
            _chunks.push_back(std::move(c));
            return true;
        }

        if (_fixed_capacity)
        {
            Chunk recycled = evict_front();
            if (!recycled.data)
                return false;   // only one chunk exists; nothing to recycle
            recycled.used = 0;
            _chunks.push_back(std::move(recycled));
            return true;
        }

        Chunk c;
        c.capacity = _chunk_bytes;
        try
        {
            c.data.reset(new uint8_t[_chunk_bytes]);
        }
        catch (const std::bad_alloc&)
        {
            return false;
        }
        c.used = 0;
        _chunks.push_back(std::move(c));
        return true;
    }

    size_t _chunk_bytes;
    std::deque<Chunk> _chunks;
    size_t _head_seq       = 0;      // absolute sequence number of _chunks.front()
    bool   _truncated_head = false;

    // Fixed-capacity arena support. Both default to the
    // legacy grow-and-free buffer's behaviour: an empty spare pool and
    // _fixed_capacity == false mean allocate_chunk() always falls through to
    // its normal `new` path, so every existing caller/test that never calls
    // preallocate_one_more_chunk() sees no behaviour change whatsoever.
    //
    // _spare_storage holds committed (see preallocate_one_more_chunk()'s own
    // comment on why memset matters) chunk storage that is not currently
    // part of _chunks -- either preallocated ahead of first use, or handed
    // back by reset_cursors()/truncate_tail() once the arena exists.
    // allocate_chunk() always drains this before ever recycling or calling
    // new. A deque (not a vector) for the same O(1)-pop-front reason
    // _chunks itself is one; front-vs-back order within the pool has no
    // behavioural meaning (unlike _chunks, where order IS the recording's
    // chronology), push_back/pop_front here is just "a FIFO queue of
    // interchangeable free blocks".
    std::deque<std::unique_ptr<uint8_t[]>> _spare_storage;

    // Latched true by preallocate_one_more_chunk(), cleared by clear()/
    // steal_chunks(). Selects allocate_chunk()'s policy: false is the
    // legacy "grow via new, no ceiling" buffer; true is the fixed arena
    // ("never grow past what was committed, recycle the front chunk when
    // full instead"). Deliberately no public setter beyond
    // preallocate_one_more_chunk() -- entering fixed-capacity mode is a
    // side effect of actually building the arena, not a mode switch a
    // caller can flip on an empty/legacy buffer and expect anything
    // sensible to happen.
    bool _fixed_capacity = false;

    // Incremental mirror of "sum of every chunk's `used`", maintained by
    // every mutator (append_with_preallocated/drop_oldest_chunk/
    // truncate_tail/clear/steal_chunks/reset_cursors) so total_bytes() is
    // O(1) instead of O(chunk count) -- this sits on
    // RepeatController::get_status()'s poll path and must not scale with
    // recording length.
    size_t _total_bytes    = 0;
};


// =============================================================================
// convert_to_pipe_format — replay-side wire narrowing
//
// The FIFO wire runs in one of two layouts, selected once at process start
// (AudioMonitor::output_format_mode(), autostream_monitor.h) and shared by
// both producer edges (the live path's deliver_output(),
// autostream_monitor_io.cpp, and this replay-side helper):
//
//   - widen_to_s32 == true  ("native", 48000 Hz / 32-bit / 2ch): each s16
//     sample is left-shifted by 16 bits into a little-endian int32 container
//     -- 4 bytes/sample, 8 bytes/frame -- the same "left-justify the
//     significant bits" scaling AlsaCapture::read() uses for its own S16_LE
//     fallback path.
//   - widen_to_s32 == false ("compatible", 44100 Hz / 16-bit / 2ch): each
//     s16 sample passes through unchanged as its native little-endian
//     bytes -- 2 bytes/sample, 4 bytes/frame.
//
// Callers must pass the SAME mode the live writer is currently using for
// this process (AudioMonitor::output_format_mode() != OutputFormatMode::
// Compatible) -- a receiver reading the FIFO must see one consistent wire
// layout regardless of which writer (live or replay) is currently active.
// Pure and allocation-shaped only by n_samples (out is resized to exactly
// fit), so it is unit-testable without any audio/link dependencies.
// =============================================================================

inline void convert_to_pipe_format(const int16_t* in_s16, size_t n_samples,
                                    std::vector<uint8_t>& out, bool widen_to_s32)
{
    if (widen_to_s32)
    {
        out.resize(n_samples * sizeof(int32_t));
        int32_t* out32 = reinterpret_cast<int32_t*>(out.data());
        for (size_t i = 0; i < n_samples; ++i)
            // Shift through the unsigned type: left-shifting a negative
            // signed value is undefined before C++20, and this is built as
            // C++17. Same widening convention as widen_s16_to_s32().
            out32[i] = static_cast<int32_t>(
                static_cast<uint32_t>(static_cast<int32_t>(in_s16[i])) << 16);
    }
    else
    {
        out.resize(n_samples * sizeof(int16_t));
        // memcpy's source is declared non-null, so a zero-length call with a
        // null input is still undefined; callers legitimately pass both.
        if (n_samples != 0)
            std::memcpy(out.data(), in_s16, out.size());
    }
}


// =============================================================================
// Codec ladder and max_recording_seconds
// =============================================================================

// Recording quality tier. The tier is chosen to GUARANTEE a target recording
// duration (default 33 minutes -- RepeatController::_target_minutes_cfg /
// the socket API's "target_minutes" field) in whatever free RAM is currently
// usable, rather than from fixed free-RAM thresholds. See
// pick_codec_for_target() below. A pinned codec (config) still skips the
// ladder but goes through plan_arena()'s own sizing (below) for the
// free-RAM-floor arithmetic exactly the same way. Selection (auto or pinned)
// happens once, at arena-build time -- not re-picked per session.
enum class CodecChoice
{
    Unavailable,
    Mp2_160,
    Mp2_192,
    Mp2_224,
    Mp2_256,
    Mp2_320,
    Mp2_384,
    PcmS16,       // raw s16 PCM, no compression
};

// Legal MPEG-1 Layer II stereo bitrates this ladder is allowed to pick from,
// ascending, restricted to the subset useful here (below 160 kbps stereo MP2
// is poor enough quality that the feature's hard floor refuses to go there
// even if it would buy extra duration). twolame/libtwolame supports all of
// these at both 44100 Hz and 48000 Hz (MPEG-1 Layer II bitrates are
// sample-rate-independent within the MPEG-1 family; the full legal table
// also includes 32/48/56/64/80/96/112/128, all below the floor).
inline constexpr int kMp2LegalBitratesKbps[] = { 160, 192, 224, 256, 320, 384 };
inline constexpr int kMp2BitrateFloorKbps    = 160;   // hard floor: never select below this

// Target-duration knob (RepeatController::_target_minutes_cfg / the
// "target_minutes" field of {"type":"set_repeat_enabled",...}).
inline constexpr int kDefaultRepeatTargetMinutes = 33;
inline constexpr int kMinRepeatTargetMinutes     = 10;
inline constexpr int kMaxRepeatTargetMinutes     = 600;

inline CodecChoice codec_choice_for_bitrate_kbps(int kbps)
{
    switch (kbps)
    {
        case 160: return CodecChoice::Mp2_160;
        case 192: return CodecChoice::Mp2_192;
        case 224: return CodecChoice::Mp2_224;
        case 256: return CodecChoice::Mp2_256;
        case 320: return CodecChoice::Mp2_320;
        case 384: return CodecChoice::Mp2_384;
        default:  return CodecChoice::Unavailable;
    }
}

// Bytes/second the recorder appends to the buffer for a given codec choice.
// MP2 rates are exactly bitrate/8 (self-contained frames at a fixed bitrate,
// independent of sample rate). The PCM tier stores s16 stereo regardless of
// the pipe's bit depth, so its byte rate does depend on the sample rate:
// 2 channels * 2 bytes/sample * sample_rate_hz.
inline long byte_rate_for(CodecChoice codec, long sample_rate_hz)
{
    switch (codec)
    {
        case CodecChoice::Mp2_160: return 160000 / 8;                  // 20,000 B/s
        case CodecChoice::Mp2_192: return 192000 / 8;                  // 24,000 B/s
        case CodecChoice::Mp2_224: return 224000 / 8;                  // 28,000 B/s
        case CodecChoice::Mp2_256: return 256000 / 8;                  // 32,000 B/s
        case CodecChoice::Mp2_320: return 320000 / 8;                  // 40,000 B/s
        case CodecChoice::Mp2_384: return 384000 / 8;                  // 48,000 B/s
        case CodecChoice::PcmS16:  return sample_rate_hz * 2 /*ch*/ * 2 /*bytes*/;
        case CodecChoice::Unavailable:
        default:
            return 0;
    }
}

// The free-RAM floor: subtracted from available RAM before any sizing
// arithmetic -- both at codec SELECTION (pick_codec_for_target(), below) and
// at arena SIZING/incremental commit (plan_arena() and the controller's
// per-chunk build-loop check, autostream_repeat.cpp's maybe_build_arena()) --
// so the two can never disagree about how much RAM is actually claimable.
// Once the arena is built it is a fixed reservation, not a moving window: the
// floor governs how big a stationary arena is allowed to be, not an ongoing
// grow/shrink budget. 64 MiB is the smallest reserve that still leaves the
// appliance headroom for its other processes while the arena is built; on
// small-memory appliances it also buys roughly half an hour of extra
// recording time at the MP2 tier versus a larger floor.
constexpr long kFreeRamFloorMib = 64;

// Target-duration codec selection.
//
// Aims to GUARANTEE target_minutes of recording in whatever RAM is
// currently usable:
//
//   usable_mib = max(0, available_mib - kFreeRamFloorMib)   -- the same
//     floor plan_arena() (below) reapplies at the SIZING step, so the tier
//     chosen here and the arena actually built from it can never disagree
//     about how much RAM is claimable.
//
//   1. If PCM-s16's footprint for target_minutes fits usable_mib, choose PCM
//      (best quality, no compression) -- footprint is sample-rate-dependent
//      (byte_rate_for(PcmS16, sample_rate_hz) * target_seconds), so this
//      naturally differs between the 48000 Hz native and 44100 Hz
//      --compatible output rates.
//   2. Else choose the HIGHEST legal MP2 stereo bitrate from
//      kMp2LegalBitratesKbps whose target_minutes footprint
//      (bitrate_kbps*1000/8 * target_seconds) fits usable_mib.
//   3. HARD FLOOR: never select below kMp2BitrateFloorKbps (160 kbps). If
//      even 160 kbps's target-duration footprint does not fit, the target
//      is a GOAL, not an admission gate -- fall back to 160 kbps anyway and
//      let plan_arena() size the arena as large as usable RAM allows at that
//      tier, which comes out SMALLER than target_minutes asked for. That is
//      a valid, truthfully reported outcome ("X minutes requested, Y minutes
//      delivered"), not a refusal.
//
// This function never itself refuses to record -- it always returns a
// concrete tier (falling back to the 160 kbps floor in the worst case).
// plan_arena() is the one place that can still resolve to
// CodecChoice::Unavailable, and only when usable RAM cannot fit even one
// whole arena chunk.
inline CodecChoice pick_codec_for_target(long available_mib, int target_minutes,
                                          long sample_rate_hz)
{
    long usable_mib = available_mib - kFreeRamFloorMib;
    if (usable_mib < 0)
        usable_mib = 0;
    long long usable_bytes = static_cast<long long>(usable_mib) * 1024ll * 1024ll;

    int clamped_target_minutes = target_minutes;
    if (clamped_target_minutes < kMinRepeatTargetMinutes)
        clamped_target_minutes = kMinRepeatTargetMinutes;
    if (clamped_target_minutes > kMaxRepeatTargetMinutes)
        clamped_target_minutes = kMaxRepeatTargetMinutes;
    long long target_seconds = static_cast<long long>(clamped_target_minutes) * 60;

    long long pcm_footprint_bytes =
        static_cast<long long>(byte_rate_for(CodecChoice::PcmS16, sample_rate_hz)) * target_seconds;
    if (pcm_footprint_bytes <= usable_bytes)
        return CodecChoice::PcmS16;

    for (int i = static_cast<int>(sizeof(kMp2LegalBitratesKbps) / sizeof(kMp2LegalBitratesKbps[0])) - 1;
         i >= 0; --i)
    {
        int kbps = kMp2LegalBitratesKbps[i];
        long long footprint_bytes = (static_cast<long long>(kbps) * 1000 / 8) * target_seconds;
        if (footprint_bytes <= usable_bytes)
            return codec_choice_for_bitrate_kbps(kbps);
    }

    // Even the floor bitrate's target footprint doesn't fit usable RAM:
    // fall back to the floor anyway and let plan_arena() size the arena as
    // large as usable RAM allows at that tier -- a truthfully smaller
    // delivered duration than requested, not a refusal (see this function's
    // own doc comment and plan_arena()'s, below).
    return codec_choice_for_bitrate_kbps(kMp2BitrateFloorKbps);
}


// =============================================================================
// ArenaPlan / plan_arena() — fixed-arena sizing
//
// The controller calls this exactly once, at enable time (and again on any
// re-plan, which is always a disable+enable by design -- there is
// no in-place resize). Its output is what preallocate_one_more_chunk()'s
// incremental commit loop then aims for, chunk by chunk. This function does
// no allocation itself and touches no RepeatBuffer instance -- pure sizing
// arithmetic over the same inputs pick_codec_for_target() already uses, so
// it is unit-testable without any buffer/allocation machinery at all.
// =============================================================================

struct ArenaPlan
{
    CodecChoice codec;             // Unavailable => the feature cannot run at all
    size_t      arena_bytes;       // whole chunks; 0 when codec == Unavailable
    long        capacity_seconds;  // arena_bytes / byte_rate_for(codec, ...) -- the
                                    // REPORTED, truthfully-delivered duration
};

// Sizes a fixed arena for the "repeat" feature.
//
// pinned_codec == CodecChoice::Unavailable is the sentinel for "auto": the
// codec is chosen by handing effective_available_mib/target_minutes/
// sample_rate_hz to pick_codec_for_target() VERBATIM -- this function never
// re-implements or duplicates that tier walk (ladder + kMp2BitrateFloorKbps
// hard floor). Any other pinned_codec value skips the ladder outright: the
// caller has fixed quality (RepeatController's codec-pin config path), and
// this function only sizes the arena and reports how much duration that
// buys. This is where duration degradation actually happens, and it falls
// out of the sizing arithmetic below for free -- no separate branch needed,
// for either the auto-picked-160k-floor case or an explicitly pinned codec:
// when even the cheapest/pinned tier's target footprint doesn't fit
// usable RAM, arena_bytes is simply capped at usable_bytes (rounded to whole
// chunks) and capacity_seconds comes out smaller than target_minutes asked
// for -- a valid, honestly reported outcome ("X minutes requested, Y
// minutes delivered"), not a refusal.
//
// Sizing, once the codec is known:
//   usable_bytes = max(0, effective_available_mib - kFreeRamFloorMib), in
//     bytes -- the exact same floor discipline pick_codec_for_target()
//     applies at the selection step, reapplied here at the sizing step so
//     the two can never disagree about how much RAM is actually claimable.
//   target_footprint_bytes = byte_rate_for(codec, sample_rate_hz) *
//     clamp(target_minutes, kMinRepeatTargetMinutes, kMaxRepeatTargetMinutes)
//     * 60 -- same clamp pick_codec_for_target() applies internally.
//   raw_bytes = min(target_footprint_bytes, usable_bytes).
//   arena_bytes = raw_bytes rounded to a whole number of chunk_bytes -- a
//     fixed arena is only ever built from whole committed chunks
//     (preallocate_one_more_chunk()'s own loop-step granularity). The
//     rounding direction favours meeting the target: UP to the next whole
//     chunk whenever usable_bytes covers it (so a target that works out at
//     9.14 chunks is delivered as 10, at-or-just-past the ask, rather than
//     9, just short of it while RAM sits unused), DOWN only when the extra
//     chunk genuinely does not fit.
//   Zero whole chunks fit at all (usable_bytes < chunk_bytes, which is also
//     what a non-positive effective_available_mib collapses to once the
//     floor subtraction clamps usable_mib to 0) => the codec is forced to
//     Unavailable and arena_bytes/capacity_seconds are both 0, regardless of
//     what the ladder/pin chose -- the feature genuinely cannot run in this
//     little RAM.
//   capacity_seconds = arena_bytes / byte_rate_for(codec, sample_rate_hz) --
//     integer division, so this is the EXACT number of whole seconds the
//     committed arena_bytes guarantees, never rounded up past what actually
//     fits. This, alongside the caller's original target_minutes
//     (reported separately as requested_minutes), is the
//     requested-vs-delivered honesty surface the whole redesign exists for.
inline ArenaPlan plan_arena(long effective_available_mib, int target_minutes,
                             long sample_rate_hz, CodecChoice pinned_codec,
                             size_t chunk_bytes = RepeatBuffer::kDefaultChunkBytes)
{
    CodecChoice codec = (pinned_codec == CodecChoice::Unavailable)
        ? pick_codec_for_target(effective_available_mib, target_minutes, sample_rate_hz)
        : pinned_codec;

    long usable_mib = effective_available_mib - kFreeRamFloorMib;
    if (usable_mib < 0)
        usable_mib = 0;
    long long usable_bytes = static_cast<long long>(usable_mib) * 1024ll * 1024ll;

    int clamped_target_minutes = target_minutes;
    if (clamped_target_minutes < kMinRepeatTargetMinutes)
        clamped_target_minutes = kMinRepeatTargetMinutes;
    if (clamped_target_minutes > kMaxRepeatTargetMinutes)
        clamped_target_minutes = kMaxRepeatTargetMinutes;
    long long target_seconds = static_cast<long long>(clamped_target_minutes) * 60;

    long rate = byte_rate_for(codec, sample_rate_hz);
    long long target_footprint_bytes =
        (rate > 0) ? static_cast<long long>(rate) * target_seconds : 0;

    long long raw_bytes = (target_footprint_bytes < usable_bytes)
        ? target_footprint_bytes : usable_bytes;

    long long chunk_count = 0;
    if (chunk_bytes > 0)
    {
        chunk_count = raw_bytes / static_cast<long long>(chunk_bytes);
        // Round UP to the next whole chunk when usable RAM covers it, down
        // only when it does not: an 80-minute target that works out at 9.14
        // chunks must not be quietly delivered as 78 minutes ("80 requested,
        // 79 delivered") while plenty of RAM sits unused -- the partial
        // chunk is claimed whole and capacity comes out AT or a little past
        // the target instead of just short of it. This also subsumes the
        // minimum-one-chunk case (a sub-chunk target on a machine with room
        // for one chunk rounds up to exactly that one chunk).
        if (raw_bytes % static_cast<long long>(chunk_bytes) != 0
            && (chunk_count + 1) * static_cast<long long>(chunk_bytes) <= usable_bytes)
            ++chunk_count;
    }

    ArenaPlan plan;
    if (rate <= 0 || chunk_count <= 0)
    {
        plan.codec            = CodecChoice::Unavailable;
        plan.arena_bytes       = 0;
        plan.capacity_seconds  = 0;
        return plan;
    }

    plan.codec           = codec;
    plan.arena_bytes      = static_cast<size_t>(chunk_count * static_cast<long long>(chunk_bytes));
    plan.capacity_seconds = static_cast<long>(static_cast<long long>(plan.arena_bytes) / rate);
    return plan;
}


// =============================================================================
// /proc/meminfo TEXT parser
//
// Parses the MemAvailable field (the kernel's estimate of memory available
// for new allocations without swapping — the correct field for this purpose,
// since it accounts for reclaimable page cache). This function takes the
// file's TEXT content as a string so it is fully unit-testable on canned
// input with zero file I/O; the wrapper that actually reads /proc/meminfo
// from disk is impure and lives in the daemon .cpp.
// =============================================================================

// Sentinel returned in available_mib when the field could not be found/parsed
// (recording is refused in this case — never a crash; unit test U8).
constexpr long kMemInfoParseError = -1;

struct MemInfo
{
    long available_mib  = kMemInfoParseError;

    bool ok() const { return available_mib >= 0; }

    // The effective-available figure is exactly MemAvailable, with no swap
    // adjustment: these appliances are autostream-owned and swap is
    // zram-only, so charging swapped-out pages against MemAvailable
    // double-counts memory the kernel has already accounted for. The floor
    // discipline that guards actual admission/sizing (kFreeRamFloorMib) is
    // applied separately by callers, not folded into this figure.
    long effective_available_mib() const
    {
        return available_mib;
    }
};

namespace autostream_meminfo_detail
{
    // Attempts to parse one "<key><whitespace><digits> kB" line. Returns
    // true iff `line` begins with `key` -- regardless of whether the numeric
    // value itself went on to parse -- so the caller can tell "this was the
    // field, done with it" from "not this field, keep scanning". On a
    // malformed match (key present, digits missing/unparseable), out_mib is
    // left untouched, exactly as if the field were absent.
    inline bool try_parse_kib_field(const std::string& line, const char* key, long& out_mib)
    {
        size_t key_len = std::strlen(key);
        if (line.compare(0, key_len, key) != 0)
            return false;

        size_t pos = key_len;
        // Skip whitespace between the key and the numeric value.
        while (pos < line.size() && std::isspace(static_cast<unsigned char>(line[pos])))
            ++pos;

        size_t digits_start = pos;
        while (pos < line.size() && std::isdigit(static_cast<unsigned char>(line[pos])))
            ++pos;

        if (pos == digits_start)
            return true;  // key matched but no digits; malformed, leave out_mib as-is

        try
        {
            long kib = std::stol(line.substr(digits_start, pos - digits_start));
            out_mib = kib / 1024;
        }
        catch (const std::exception&)
        {
            // out-of-range or otherwise unparseable; leave out_mib as-is
        }
        return true;
    }
}

// Parses lines of the form "MemAvailable:    123456 kB" (any run of
// whitespace between the fields; the trailing unit is expected to be "kB"
// per the kernel's documented format). Other lines are ignored. A malformed
// candidate line (field present but the numeric value doesn't parse) is
// also ignored, as if the field were absent — this function never throws.
inline MemInfo parse_meminfo_text(const std::string& text)
{
    using autostream_meminfo_detail::try_parse_kib_field;

    MemInfo result;

    bool have_available  = false;

    size_t search_from = 0;
    while (search_from < text.size())
    {
        size_t line_end = text.find('\n', search_from);
        if (line_end == std::string::npos)
            line_end = text.size();

        std::string line = text.substr(search_from, line_end - search_from);
        search_from = line_end + 1;

        if (!have_available)
        {
            long mib = kMemInfoParseError;
            if (try_parse_kib_field(line, "MemAvailable:", mib))
            {
                if (mib != kMemInfoParseError)
                {
                    result.available_mib = mib;
                    have_available = true;
                }
                break;  // first (and only expected) MemAvailable line wins
            }
        }
    }

    return result;  // never found/parsed keeps available_mib at kMemInfoParseError
}


// =============================================================================
// SilenceTrimAccountant — end-of-recording silence trim byte accounting
//
// The recorder worker mirrors the input's silence test on the float blocks it
// drains, tracking how many encoded bytes have been appended since the last
// above-threshold block. On end_session(), the recording is truncated back
// to (bytes_since_last_loud - pad), removing the silence-timeout tail (and
// any run-out groove/lead-out) while leaving ~pad of quiet before the loop
// point.
// =============================================================================

class SilenceTrimAccountant
{
public:
    void reset() { _bytes_since_last_loud = 0; }

    // Called once per encoded block as it is appended to the RepeatBuffer.
    // above_threshold reflects the *input's* peak test on the source float
    // block that produced appended_bytes of encoded output (frame-aligned by
    // construction, same as RepeatBuffer::append()).
    void on_block_appended(bool above_threshold, size_t appended_bytes)
    {
        if (above_threshold)
            _bytes_since_last_loud = 0;
        else
            _bytes_since_last_loud += appended_bytes;
    }

    size_t bytes_since_last_loud() const { return _bytes_since_last_loud; }

    // Computes the number of bytes end_session() should truncate from the
    // tail: bytes_since_last_loud - pad_bytes, floored at zero (a recording
    // that ended on/near loud audio needs no trim), frame-aligned downward so
    // the trim never cuts a partial frame, and clamped to total_bytes (never
    // asked to trim more than exists — the all-silent-recording edge case,
    // where bytes_since_last_loud == total_bytes and the result leaves ~pad
    // bytes behind).
    static size_t compute_trim_bytes(size_t bytes_since_last_loud, size_t pad_bytes,
                                      size_t frame_bytes, size_t total_bytes)
    {
        size_t trim = (bytes_since_last_loud > pad_bytes)
                          ? (bytes_since_last_loud - pad_bytes)
                          : 0;

        if (frame_bytes > 0)
            trim -= trim % frame_bytes;  // round down to a whole number of frames

        if (trim > total_bytes)
            trim = total_bytes;

        return trim;
    }

private:
    size_t _bytes_since_last_loud = 0;
};


// =============================================================================
// SustainTracker — pure continuous above-threshold run accumulator
//
// The shared core of "has the signal been continuously above threshold for
// long enough to count as music, not a transient". Driven in the
// audio-block domain (block_seconds = frames / sample_rate_hz) rather than
// wall-clock time, matching SilenceTrimAccountant's own per-appended-block
// accounting style -- fed once per block, in order, pure so it is testable
// without a running capture channel or a real clock.
//
// Used by OnsetGate (below) to decide when the recorder may start
// committing audio at the HEAD of a recording, and by TailMarker (further
// below) to track where the last sustained run ended, at the TAIL. Both
// ends share this same accumulator definition -- one meaning of "sustained
// signal", the same kSustainSeconds constant and the same unbroken-run reset
// rule, for the whole recording.
// =============================================================================

class SustainTracker
{
public:
    // Sustained above-threshold duration that counts as a genuine run
    // (as opposed to a transient that cannot sustain this long). Remains the
    // default threshold for every existing caller (OnsetGate's recorder-
    // commit gate, TailMarker's tail-of-recording marker); NOT user-
    // configurable and NOT changed by the constructor overload below.
    static constexpr double kSustainSeconds = 2.5;

    SustainTracker() = default;

    // Same accumulator, a different sustain threshold. Added so
    // RepeatController's interrupt-probation gate (kInterruptSustainSeconds,
    // autostream_repeat_buffer.h) can reuse this exact "unbroken continuous
    // above-threshold run" core without perturbing kSustainSeconds or any of
    // its existing callers -- see the enumeration in RepeatController's
    // declaration comment for why the recorder-commit gate (2.5 s) and the
    // interrupt-probation gate (1.25 s) are deliberately separate constants
    // rather than one shared value.
    explicit SustainTracker(double sustain_seconds) : _sustain_seconds(sustain_seconds) {}

    void reset() { _above_seconds = 0.0; }

    // Called once per block, in the order the blocks occurred.
    // above_threshold is the block's own peak test against the origin
    // input's snapshotted silence threshold; block_seconds is the block's
    // duration.
    //
    // Reset semantics: any block whose above_threshold is false drops the
    // continuous-above-threshold accumulator back to zero -- the sustain
    // window must be UNBROKEN. A single below-threshold block anywhere
    // inside an otherwise-sustained run restarts the count from that
    // block's own (zero) contribution, not from whatever had already
    // accumulated before it.
    //
    // Returns true exactly on the call whose block_seconds pushes the
    // accumulated continuous-above-threshold duration from below
    // kSustainSeconds to >= kSustainSeconds (the crossing edge of THIS run).
    // Because the accumulator keeps running rather than latching, this can
    // report the edge again for a later run, once a below-threshold block
    // has reset it and a fresh run has itself reached kSustainSeconds --
    // callers that only care about the first-ever edge (OnsetGate) latch
    // that on top; callers that care about every run's edge (TailMarker) do
    // not need to.
    bool on_block(bool above_threshold, double block_seconds)
    {
        if (!above_threshold)
        {
            _above_seconds = 0.0;
            return false;
        }

        bool was_sustained = _above_seconds >= _sustain_seconds;
        _above_seconds += block_seconds;
        return !was_sustained && _above_seconds >= _sustain_seconds;
    }

    bool   is_sustained() const     { return _above_seconds >= _sustain_seconds; }
    double above_seconds() const    { return _above_seconds; }
    double sustain_seconds() const  { return _sustain_seconds; }

private:
    double _sustain_seconds = kSustainSeconds;
    double _above_seconds   = 0.0;
};


// =============================================================================
// OnsetGate — pure onset-sustain decision core
//
// The SESSION starts on the first above-threshold transient, exactly as
// before (see the minimum playback hold); this gate decides when the
// RECORDER may start committing audio.
// A mechanical start thump cannot sustain kOnsetSustainSeconds continuous
// above-threshold audio, so it never confirms on its own; a CD player's
// music sustains from its first note, so it confirms almost immediately
// once its own first note has run long enough.
//
// Thin latch-once wrapper around SustainTracker: SustainTracker does the
// run accumulation, OnsetGate adds "report the very first time this run
// reaches sustain, and never again until reset()".
// =============================================================================

class OnsetGate
{
public:
    // Sustained above-threshold duration required before the recorder starts
    // committing audio. Internal constant, not user-configurable.
    static constexpr double kOnsetSustainSeconds = SustainTracker::kSustainSeconds;

    void reset()
    {
        _confirmed = false;
        _core.reset();
    }

    // Called once per raw, pre-encode recorder block, in the order the
    // blocks arrive. See SustainTracker::on_block() for the argument and
    // reset-semantics contract.
    //
    // Returns true exactly once: on the call whose block_seconds pushes the
    // accumulated continuous-above-threshold duration to
    // >= kOnsetSustainSeconds (the confirming edge). Returns false on every
    // other call, including every call after confirmation (is_confirmed()
    // latches permanently until reset()).
    bool on_block(bool above_threshold, double block_seconds)
    {
        bool edge = _core.on_block(above_threshold, block_seconds);
        if (_confirmed)
            return false;
        if (edge)
        {
            _confirmed = true;
            return true;
        }
        return false;
    }

    bool is_confirmed() const { return _confirmed; }

private:
    bool           _confirmed = false;
    SustainTracker _core;
};


// =============================================================================
// TailMarker — last-sustained-run-end position, in committed-buffer bytes
//
// Tracks where the RECORDER's committed output last saw a sustained (>=
// SustainTracker::kSustainSeconds) above-threshold run end, so session close
// can cut the trailing run-out (isolated pops, a tonearm clunk, silence)
// while keeping everything up to the last real music.
//
// Fed once per block actually appended to the RepeatBuffer -- the same call
// site and same (above_threshold, block_seconds) values SilenceTrimAccountant
// already consumes -- so the byte position it records always lines up with a
// real, already-committed buffer offset. Internally owns its own
// SustainTracker: reusing the same accumulator definition as OnsetGate means
// the tail uses the identical notion of "sustained" as the head (same
// constant, same unbroken-run reset rule) without needing to reach back into
// OnsetGate's own instance, which is fed in raw arrival order (ahead of the
// pre-roll splice) rather than committed-buffer order -- replaying the
// identical per-block stream through a second instance, in commit order,
// gives the tail the buffer-position bookkeeping it needs while leaving
// onset confirmation's own timing completely untouched.
//
// The mark only starts existing once the FIRST sustained run appears in the
// committed stream -- for a normal recording that is exactly the run that
// confirmed onset (nothing shorter than a sustained run is ever committed
// before onset confirms), matching has_mark() to "onset has confirmed and
// stayed on long enough to matter". A transient (pop/clunk) can never itself
// sustain kSustainSeconds, so on its own it can only freeze the mark where it
// already was, never advance it.
// =============================================================================

class TailMarker
{
public:
    // pad_bytes configures the cut position recorded by on_block_committed():
    // the cut lands on the first committed block boundary at least pad_bytes
    // past the mark. Zero is valid (cut at the first post-run block) -- used
    // by the teardown/idle reset call sites, where no recording is active and
    // the value never matters.
    void reset(size_t pad_bytes = 0)
    {
        _run.reset();
        _mark_bytes = 0;
        _has_mark   = false;
        _pad_bytes  = pad_bytes;
        _cut_bytes  = 0;
        _has_cut    = false;
    }

    // Called once per block actually committed to the RepeatBuffer, in
    // buffer order. committed_bytes_after is the buffer's total_bytes()
    // AFTER this block was appended -- the position the mark advances to
    // when this block keeps (or newly reaches) a sustained run.
    //
    // Alongside the mark, this records the CUT position session close
    // truncates back to: the first committed block boundary at least
    // _pad_bytes past the mark. Because every committed block is a whole
    // number of encoder frames, the cut is always encoder-frame-aligned by
    // construction -- no byte-rate arithmetic is involved. A new sustained
    // run invalidates any recorded cut (the mark has moved past it); the cut
    // is then re-recorded once the new run has itself ended and pad_bytes of
    // post-run audio have been committed.
    void on_block_committed(bool above_threshold, double block_seconds,
                             size_t committed_bytes_after)
    {
        _run.on_block(above_threshold, block_seconds);
        if (_run.is_sustained())
        {
            _mark_bytes = committed_bytes_after;
            _has_mark   = true;
            _has_cut    = false;
        }
        else if (_has_mark && !_has_cut
                 && committed_bytes_after >= _mark_bytes + _pad_bytes)
        {
            _cut_bytes = committed_bytes_after;
            _has_cut   = true;
        }
    }

    // False until the committed stream has ever contained a sustained run
    // (i.e. onset never confirmed, or confirmed but the session ended before
    // any full run posted -- cannot happen in practice since the run that
    // confirms onset IS the first thing committed, but kept as an explicit,
    // checkable precondition rather than an assumption). Callers must treat
    // mark_bytes() as meaningless while this is false.
    bool   has_mark() const   { return _has_mark; }
    size_t mark_bytes() const { return _mark_bytes; }

    // True once a cut position has been recorded for the CURRENT last
    // sustained run: the session ran on for at least _pad_bytes of committed
    // audio past the run's end. False while a run is still live, and false
    // when the session ended within the pad of the last run (nothing needs
    // cutting -- the recording already ends close enough to the music).
    // Callers must treat cut_bytes() as meaningless while this is false.
    bool   has_cut() const    { return _has_cut; }

    // A committed append boundary (hence a whole number of encoder frames
    // from the start of the recording), at least _pad_bytes past mark_bytes().
    // Session close truncates the buffer back to exactly this position.
    size_t cut_bytes() const  { return _cut_bytes; }

private:
    SustainTracker _run;
    size_t         _mark_bytes = 0;
    bool           _has_mark   = false;
    size_t         _pad_bytes  = 0;
    size_t         _cut_bytes  = 0;
    bool           _has_cut    = false;
};


// =============================================================================
// PreRollRing — bounded pre-onset backlog of raw (pre-encode) recorder blocks
//
// While a recording session is active but OnsetGate has not yet confirmed,
// raw audio must not be lost (the onset's own lead-in -- the first notes, or
// the moment the sustained signal actually starts -- must still make it into
// the buffer once onset confirms) but must not be committed either (a thump
// that never sustains must leave nothing behind). This ring holds the most
// recent kPreRollSeconds of raw blocks, in order, dropping the oldest block
// once the held duration exceeds capacity -- a plain sliding window, no
// signal processing.
//
// Stores whole blocks (not a flat sample ring) so push()/pop_front() are O(1)
// amortized and so each block's own above_threshold flag survives the ring
// for correct SilenceTrimAccountant bookkeeping if the recording ends soon
// after the ring is spliced into the buffer. Typical recorder blocks are a
// few thousand frames, so a 5 s ring holds on the order of dozens of blocks
// -- a std::deque of small vectors is simple and entirely adequate; there is
// no need for a manually managed circular byte buffer here.
// =============================================================================

// Pre-roll window: sustain window (kOnsetSustainSeconds) plus margin, so a
// recording whose very first block is already above threshold (immediate
// onset -- the CD-player case, or a turntable thump that happens to sustain)
// still has the ring cover everything back to session start once onset
// confirms at kOnsetSustainSeconds in.
inline constexpr double kPreRollSeconds = 5.0;

// Live-interrupt probation window (RepeatController, autostream_repeat.cpp):
// how long a should_capture edge arriving during an ACTIVE replay must
// sustain continuous above-threshold audio before it is trusted enough to
// fade out the replay and free the held recording. Deliberately its own
// constant rather than reusing SustainTracker::kSustainSeconds (2.5 s) --
// that constant is the RECORDER's own onset-commit gate ("is this real
// enough to start committing a brand-new recording from silence"), a
// different, unrelated question from "is this real enough to interrupt an
// ALREADY-PLAYING replay". No caller of kSustainSeconds (OnsetGate's
// recorder-commit gate, TailMarker's tail-of-recording marker -- both purely
// on the RECORDER side) has any coupling to interrupt handling, so there is
// no reason to keep the two gates in lockstep; a shorter probation keeps a
// genuine live interrupt feeling responsive without reopening the original
// "a brief noise pop destroys the held recording" problem this exists to fix.
//
// kPreRollSeconds also doubles as this gate's TIMEOUT bound (see
// RepeatController::notify_probation_block()): a should_capture edge that
// never confirms within kPreRollSeconds resets silently and replay
// continues untouched. Chosen as the bound (rather than a fresh constant)
// because it is already the figure that bounds how long any onset-style
// decision in this codebase is allowed to sit unconfirmed before the
// original transient is too far in the past to still be a reasonable "this
// just happened" signal.
//
// Note what this arithmetic does NOT claim: probation and the fade that
// follows confirmation both run while the NEW session's own RepeatBuffer/
// OnsetGate/PreRollRing are still idle (still owned by the OLD held
// recording -- see the admit-before-free comment in RepeatController's
// perform_pending_start()), so the audio spanning the probation window
// itself is not captured into the eventual new recording, exactly as the
// pre-1.0 s fade window never was either. What the headroom below buys is
// operational slack: kInterruptSustainSeconds (to confirm) + kFadeSeconds
// (autostream_monitor.h; the fade that follows confirmation) = 1.25 + 1.0 =
// 2.25 s, well inside the 5 s bound above -- so a legitimate interrupt has
// comfortable room to confirm before timing out even under scheduling
// jitter, without the probation window itself needing to grow anywhere
// near kPreRollSeconds.
inline constexpr double kInterruptSustainSeconds = 1.25;

class PreRollRing
{
public:
    struct Block
    {
        std::vector<float> samples;          // interleaved stereo, pre-encode
        bool                above_threshold = false;
    };

    PreRollRing() = default;

    // capacity_frames == 0 disables the ring: push() becomes a no-op and the
    // ring stays permanently empty. Also clears any existing content, so
    // this doubles as the per-session (re)initialisation call.
    void set_capacity_frames(size_t capacity_frames)
    {
        _capacity_frames = capacity_frames;
        clear();
    }

    // Appends one block to the tail (frames stereo-interleaved samples
    // starting at `interleaved`), then drops whole blocks from the head
    // until the total held duration is back within capacity. A single block
    // larger than the entire capacity is still kept whole rather than split
    // -- recorder blocks are always far smaller than the multi-second
    // capacity in practice, so this never actually leaves the ring over
    // capacity for long.
    void push(const float* interleaved, int frames, bool above_threshold)
    {
        if (_capacity_frames == 0 || frames <= 0)
            return;

        Block b;
        b.samples.assign(interleaved, interleaved + static_cast<size_t>(frames) * 2u);
        b.above_threshold = above_threshold;
        _total_frames += static_cast<size_t>(frames);
        _blocks.push_back(std::move(b));

        while (_total_frames > _capacity_frames && _blocks.size() > 1)
        {
            _total_frames -= _blocks.front().samples.size() / 2u;
            _blocks.pop_front();
        }
    }

    bool   empty() const       { return _blocks.empty(); }
    size_t block_count() const { return _blocks.size(); }
    size_t total_frames() const { return _total_frames; }

    // Removes and returns the oldest held block (FIFO / chronological
    // order), for draining the ring into the normal write path once onset
    // confirms -- either all at once or amortized across several calls (the
    // caller decides the pacing; this is just the queue). Returns false
    // (out left untouched) if the ring is empty.
    bool pop_front(Block& out)
    {
        if (_blocks.empty())
            return false;
        out = std::move(_blocks.front());
        _total_frames -= out.samples.size() / 2u;
        _blocks.pop_front();
        return true;
    }

    // Frees all held blocks. Called at session start (before the first
    // push) and at session end/discard, so a stale backlog from a prior
    // session's thump never lingers in memory once that session is gone.
    void clear()
    {
        _blocks.clear();
        _total_frames = 0;
    }

private:
    size_t _capacity_frames = 0;
    std::deque<Block> _blocks;
    size_t _total_frames = 0;
};
