// =============================================================================
// autostream_output_stage.h
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// One continuous output stream, mixed from up to three sources (two live
// inputs and the recorded replay) and written to the FIFO by a single
// thread.
//
// OutputMixer is the pure core: three per-source rings and a gain-ramp state
// machine, with no thread of its own and no dependency beyond the standard
// library and the SPSC ring, so it builds and is unit-tested without linking
// ALSA or libsamplerate.
//
// OutputStage wraps the mixer with the thread that drives it: paced either
// by a live source's own rate or, when no live source is active, by the
// monotonic clock; applying the shared output processor once per block;
// converting to the wire format; feeding the engineering dump tap; and
// writing the FIFO, including the cold-start prefill. Its implementation
// lives in autostream_output_stage.cpp, which does link the audio libraries.
// =============================================================================

#pragma once

#include "autostream_spsc_ring.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>

// A "frame" throughout this file is one interleaved stereo sample pair; a
// block is block_frames() frames, i.e. block_frames()*2 floats.

enum class OutputSource
{
    Live1  = 0,
    Live2  = 1,
    Replay = 2,
    Count  = 3,
};

// =============================================================================
// OutputMixer
//
// Three SPSC rings, one per source, each fed by its own producer thread and
// drained only by mix_block() on the output thread. Gain state per source is
// a linear ramp: a current gain, a target, and a per-frame step, advanced
// only inside mix_block().
//
// A source that is not active is neither read nor summed and costs nothing.
// An active source whose gain and target are both exactly zero is still
// read every block, so its ring never drifts ahead of the stream, but needs
// no special case to keep it out of the sum: multiplying by a gain of
// exactly zero already contributes nothing.
//
// Thread model: push() is called by a source's own producer thread and only
// ever touches that source's ring and a per-source atomic -- no lock, and it
// never blocks. activate()/set_gain()/deactivate() and the read-only control
// queries take a single mutex, which mix_block() also takes -- once at the
// start of a block to copy the control state it needs, and once at the end
// to write the advanced state back -- but never while touching a ring or a
// sample, so the mixing loop itself is always lock-free.
//
// activate()/deactivate() reset the source's ring, which (like SpscRing's
// own reset()) is only safe when mix_block() is not concurrently reading
// that same ring. The intended caller sequences a source's session-boundary
// calls so this holds -- a source is never deactivated while its block is
// still being mixed.
// =============================================================================

class OutputMixer
{
public:
    OutputMixer(int rate_hz, size_t block_frames);

    int    rate_hz()      const { return _rate_hz; }
    size_t block_frames() const { return _block_frames; }

    // Producer side: one producer thread per source. Copies up to `frames`
    // interleaved stereo frames into that source's ring and returns how
    // many were actually accepted; the remainder are dropped and counted.
    // Returns 0 without touching the ring when the source is not active.
    // Never blocks, never takes a lock.
    size_t push(OutputSource s, const float* interleaved, size_t frames);

    // ---- Control: safe to call from any thread ----------------------------

    // Marks the source active, discards anything left in its ring, and sets
    // its gain to initial_gain, ramping linearly to a target of 1.0 over
    // ramp_to_one_seconds (0 = jump to 1.0 immediately).
    void activate(OutputSource s, float initial_gain, double ramp_to_one_seconds);

    // Re-targets an already-active source, ramping linearly from its
    // CURRENT gain to target over ramp_seconds (0 = jump immediately).
    // No-op if the source is not active.
    void set_gain(OutputSource s, float target, double ramp_seconds);

    // Marks the source inactive. The ring is reset by the next activate().
    void deactivate(OutputSource s);

    bool is_active(OutputSource s) const;

    // True once the source's gain and target have both reached exactly
    // zero -- either because it is deliberately sitting there (see the
    // class note above) or because a set_gain() ramp to zero has completed,
    // in which case mix_block() has already made it inactive. In the
    // latter case this keeps reporting true until the source is
    // deactivate()'d or activate()'d again, so a producer polling this
    // after starting a fade-out cannot miss the block where it completed.
    bool gain_is_zero(OutputSource s) const;

    // True while the source is active and its gain is being held at exactly
    // zero with no ramp toward anything else (target == 0 too) -- i.e. it is
    // deliberately silent right now, as opposed to gain_is_zero()'s broader
    // "reached zero, possibly via a completed fade-out" sense. Used to ask
    // "is this source currently muted" without caring how it got there.
    bool is_muted(OutputSource s) const;

    // ---- Consumer side: the output thread only -----------------------------

    bool any_active() const;

    // 0 or 1 for the lower-numbered active live source (Live1 before
    // Live2); -1 if neither live source is active. Replay never clocks the
    // stage.
    int live_clock_source() const;

    // Frames currently sitting in a source's ring.
    size_t available(OutputSource s) const;

    // Blocks until any_active() becomes true or the timeout elapses. Woken
    // by activate().
    void wait_for_activity(std::chrono::milliseconds timeout);

    // Fills exactly block_frames() frames (interleaved stereo) at
    // out_interleaved: reads one block from every active source's ring
    // (padding and counting an underrun when a source is short, except in
    // its first two blocks after activate()), advances each source's gain
    // linearly across the block, and sums gain * samples into the output.
    // A source whose ramp to a target of zero completes during this call is
    // left inactive, so gain_is_zero() keeps reporting it once this call
    // returns.
    void mix_block(float* out_interleaved);

    struct Counters
    {
        uint64_t underrun_frames[3]{};
        uint64_t dropped_frames[3]{};
    };
    Counters counters() const;

private:
    static constexpr size_t kNumSources = static_cast<size_t>(OutputSource::Count);

    struct SourceControl
    {
        bool  active                = false;
        float gain                  = 0.0f;
        float target                = 0.0f;
        float step_per_frame        = 0.0f;

        // Frames left until gain must land exactly on target, decremented
        // once per frame in mix_block(). 0 means no ramp is in flight (gain
        // already equals target). Kept alongside step_per_frame so the ramp
        // is guaranteed to reach target bit-exactly at the frame it was
        // asked to, regardless of float accumulation error in the running
        // gain over a long ramp -- gain_is_zero()'s equality test relies on
        // this.
        int   ramp_frames_remaining = 0;

        bool  faded_out             = false;
        int   blocks_since_activate = 0;
    };

    static size_t index_of(OutputSource s) { return static_cast<size_t>(s); }
    static size_t round_up_pow2(size_t v);

    int    _rate_hz;
    size_t _block_frames;
    size_t _ring_capacity_samples;

    mutable std::mutex      _mutex;
    std::condition_variable _cv;

    SourceControl _control[kNumSources];

    // Mirrors _control[i].active under _mutex, but is also read by push()
    // without taking it -- push() is the one call on this class that must
    // never lock, and all it needs from this is "may I touch the ring".
    std::atomic<bool> _push_active[kNumSources]{};

    std::atomic<uint64_t> _underrun_frames[kNumSources]{};
    std::atomic<uint64_t> _dropped_frames[kNumSources]{};

    SpscRing<float> _rings[kNumSources];

    // Per-source scratch for mix_block()'s ring read, sized once so the hot
    // path never allocates.
    std::vector<float> _scratch[kNumSources];
};

inline size_t OutputMixer::round_up_pow2(size_t v)
{
    size_t p = 1;
    while (p < v)
        p <<= 1;
    return p;
}

inline OutputMixer::OutputMixer(int rate_hz, size_t block_frames)
    : _rate_hz(rate_hz)
    , _block_frames(block_frames)
    , _ring_capacity_samples(round_up_pow2(static_cast<size_t>(static_cast<double>(rate_hz) * 2.0 * 0.5)))
    , _rings{ SpscRing<float>(_ring_capacity_samples),
              SpscRing<float>(_ring_capacity_samples),
              SpscRing<float>(_ring_capacity_samples) }
{
    static_assert(static_cast<size_t>(OutputSource::Count) == 3,
                  "OutputMixer's ring/scratch initialisers assume exactly three sources");

    // SpscRing's own std::vector<float>(capacity) construction already
    // zero-fills and therefore touches every page of each ring's backing
    // store; nothing further is needed here for that.
    for (size_t i = 0; i < kNumSources; ++i)
        _scratch[i].assign(_block_frames * 2, 0.0f);
}

inline size_t OutputMixer::push(OutputSource s, const float* interleaved, size_t frames)
{
    size_t i = index_of(s);
    if (!_push_active[i].load(std::memory_order_acquire))
        return 0;

    SpscRing<float>& ring = _rings[i];
    size_t avail_frames = ring.write_available() / 2;
    size_t accepted      = std::min(frames, avail_frames);

    if (accepted > 0)
        ring.write(interleaved, accepted * 2);

    size_t dropped = frames - accepted;
    if (dropped > 0)
        _dropped_frames[i].fetch_add(dropped, std::memory_order_relaxed);

    return accepted;
}

inline void OutputMixer::activate(OutputSource s, float initial_gain, double ramp_to_one_seconds)
{
    size_t i = index_of(s);
    std::lock_guard<std::mutex> lock(_mutex);

    _rings[i].reset();

    SourceControl& c = _control[i];
    c.active                = true;
    c.gain                  = initial_gain;
    c.target                = 1.0f;
    c.faded_out             = false;
    c.blocks_since_activate = 0;

    if (ramp_to_one_seconds <= 0.0)
    {
        c.gain                  = c.target;
        c.step_per_frame        = 0.0f;
        c.ramp_frames_remaining = 0;
    }
    else
    {
        long long total_frames = std::llround(ramp_to_one_seconds * static_cast<double>(_rate_hz));
        if (total_frames <= 0)
            total_frames = 1;
        c.step_per_frame = static_cast<float>(
            (static_cast<double>(c.target) - static_cast<double>(initial_gain)) / static_cast<double>(total_frames));
        c.ramp_frames_remaining = static_cast<int>(total_frames);
    }

    _push_active[i].store(true, std::memory_order_release);
    _cv.notify_all();
}

inline void OutputMixer::set_gain(OutputSource s, float target, double ramp_seconds)
{
    size_t i = index_of(s);
    std::lock_guard<std::mutex> lock(_mutex);

    SourceControl& c = _control[i];
    if (!c.active)
        return;

    c.target = target;

    if (ramp_seconds <= 0.0)
    {
        c.gain                  = target;
        c.step_per_frame        = 0.0f;
        c.ramp_frames_remaining = 0;
    }
    else
    {
        long long total_frames = std::llround(ramp_seconds * static_cast<double>(_rate_hz));
        if (total_frames <= 0)
            total_frames = 1;
        c.step_per_frame = static_cast<float>(
            (static_cast<double>(target) - static_cast<double>(c.gain)) / static_cast<double>(total_frames));
        c.ramp_frames_remaining = static_cast<int>(total_frames);
    }
}

inline void OutputMixer::deactivate(OutputSource s)
{
    size_t i = index_of(s);
    std::lock_guard<std::mutex> lock(_mutex);

    _control[i] = SourceControl{};
    _push_active[i].store(false, std::memory_order_release);
    // The ring is left alone: a producer may be inside push() on its own
    // thread, and SpscRing::reset() is not safe against a concurrent write.
    // The consumer stops reading an inactive source, and the next
    // activate() (always sequenced before the producer restarts) resets it.
}

inline bool OutputMixer::is_active(OutputSource s) const
{
    std::lock_guard<std::mutex> lock(_mutex);
    return _control[index_of(s)].active;
}

inline bool OutputMixer::gain_is_zero(OutputSource s) const
{
    std::lock_guard<std::mutex> lock(_mutex);
    const SourceControl& c = _control[index_of(s)];
    return c.faded_out || (c.active && c.gain == 0.0f && c.target == 0.0f);
}

inline bool OutputMixer::is_muted(OutputSource s) const
{
    std::lock_guard<std::mutex> lock(_mutex);
    const SourceControl& c = _control[index_of(s)];
    return c.active && c.gain == 0.0f && c.target == 0.0f;
}

inline bool OutputMixer::any_active() const
{
    std::lock_guard<std::mutex> lock(_mutex);
    for (size_t i = 0; i < kNumSources; ++i)
        if (_control[i].active)
            return true;
    return false;
}

inline int OutputMixer::live_clock_source() const
{
    std::lock_guard<std::mutex> lock(_mutex);
    if (_control[index_of(OutputSource::Live1)].active) return 0;
    if (_control[index_of(OutputSource::Live2)].active) return 1;
    return -1;
}

inline size_t OutputMixer::available(OutputSource s) const
{
    // The ring's own atomics make this safe without _mutex.
    return _rings[index_of(s)].read_available() / 2;
}

inline void OutputMixer::wait_for_activity(std::chrono::milliseconds timeout)
{
    std::unique_lock<std::mutex> lock(_mutex);
    _cv.wait_for(lock, timeout, [this]()
    {
        for (size_t i = 0; i < kNumSources; ++i)
            if (_control[i].active)
                return true;
        return false;
    });
}

inline OutputMixer::Counters OutputMixer::counters() const
{
    Counters c;
    for (size_t i = 0; i < kNumSources; ++i)
    {
        c.underrun_frames[i] = _underrun_frames[i].load(std::memory_order_relaxed);
        c.dropped_frames[i]  = _dropped_frames[i].load(std::memory_order_relaxed);
    }
    return c;
}

inline void OutputMixer::mix_block(float* out)
{
    struct Snapshot
    {
        bool  active;
        float gain;
        float target;
        float step;
        int   ramp_frames_remaining;
        int   blocks;
    };
    Snapshot snap[kNumSources];

    {
        std::lock_guard<std::mutex> lock(_mutex);
        for (size_t i = 0; i < kNumSources; ++i)
        {
            const SourceControl& c = _control[i];
            snap[i] = { c.active, c.gain, c.target, c.step_per_frame,
                        c.ramp_frames_remaining, c.blocks_since_activate };
        }
    }

    std::fill(out, out + _block_frames * 2, 0.0f);

    bool  now_inactive[kNumSources]  = { false, false, false };
    bool  now_faded_out[kNumSources] = { false, false, false };
    float final_gain[kNumSources];
    float final_step[kNumSources];
    int   final_ramp_remaining[kNumSources];
    int   final_blocks[kNumSources];

    for (size_t i = 0; i < kNumSources; ++i)
    {
        final_gain[i]           = snap[i].gain;
        final_step[i]           = snap[i].step;
        final_ramp_remaining[i] = snap[i].ramp_frames_remaining;
        final_blocks[i]         = snap[i].blocks;

        if (!snap[i].active)
            continue;

        float* scratch = _scratch[i].data();
        size_t avail_frames = _rings[i].read_available() / 2;
        size_t to_read       = std::min(_block_frames, avail_frames);

        if (to_read > 0)
            _rings[i].read(scratch, to_read * 2);

        if (to_read < _block_frames)
        {
            size_t shortfall = _block_frames - to_read;
            std::fill(scratch + to_read * 2, scratch + _block_frames * 2, 0.0f);
            // The first two blocks after activate() are exempt: a short
            // ring right after a session starts is normal, not a stall.
            if (snap[i].blocks >= 2)
                _underrun_frames[i].fetch_add(shortfall, std::memory_order_relaxed);
        }

        if (snap[i].blocks < 2)
            final_blocks[i] = snap[i].blocks + 1;

        float       g           = snap[i].gain;
        float       step        = snap[i].step;
        const float target      = snap[i].target;
        int         frames_left = snap[i].ramp_frames_remaining;
        const bool  was_ramping = (frames_left > 0);

        for (size_t f = 0; f < _block_frames; ++f)
        {
            out[f * 2]     += scratch[f * 2]     * g;
            out[f * 2 + 1] += scratch[f * 2 + 1] * g;

            if (frames_left > 0)
            {
                --frames_left;
                if (frames_left == 0)
                {
                    // Land exactly on target on the ramp's last frame,
                    // regardless of any float drift accumulated in g.
                    g    = target;
                    step = 0.0f;
                }
                else
                {
                    g += step;
                }
            }
        }

        final_gain[i]           = g;
        final_step[i]           = step;
        final_ramp_remaining[i] = frames_left;

        if (was_ramping && frames_left == 0 && target == 0.0f)
        {
            now_inactive[i]  = true;
            now_faded_out[i] = true;
        }
    }

    {
        std::lock_guard<std::mutex> lock(_mutex);
        for (size_t i = 0; i < kNumSources; ++i)
        {
            if (!snap[i].active)
                continue;

            SourceControl& c        = _control[i];
            c.gain                  = final_gain[i];
            c.step_per_frame        = final_step[i];
            c.ramp_frames_remaining = final_ramp_remaining[i];
            c.blocks_since_activate = final_blocks[i];

            if (now_inactive[i])
            {
                c.active = false;
                _push_active[i].store(false, std::memory_order_release);
            }
            if (now_faded_out[i])
                c.faded_out = true;
        }
    }
}


// =============================================================================
// OutputStage
//
// Runs OutputMixer on one thread: paces each block, applies the shared
// output processor, converts to the wire format, feeds the engineering
// dump tap, and writes the FIFO -- including the cold-start prefill that
// only ever applies after the stream has been genuinely idle.
//
// Implemented in autostream_output_stage.cpp, which links ALSA and
// libsamplerate; this declaration only needs to know the referenced types
// exist, so this header stays free of both.
// =============================================================================

class FifoWriter;
class OutputProcessor;
class OutputDumpWriter;

class OutputStage
{
public:
    OutputStage(OutputMixer& mixer, FifoWriter& writer, std::mutex& processor_mutex,
                OutputProcessor& processor, OutputDumpWriter& dump);
    ~OutputStage();

    OutputStage(const OutputStage&)            = delete;
    OutputStage& operator=(const OutputStage&) = delete;

    // Spawns the thread. A second call before stop() is a no-op.
    void start();

    // Sets the stop flag and joins the thread. Idempotent: safe to call
    // more than once, or when the thread was never started.
    void stop();

private:
    void thread_func();

    OutputMixer&      _mixer;
    FifoWriter&       _writer;
    std::mutex&       _processor_mutex;
    OutputProcessor&  _processor;
    OutputDumpWriter& _dump;

    std::thread       _thread;
    std::atomic<bool> _running{false};
    std::atomic<bool> _stop_requested{false};
};
