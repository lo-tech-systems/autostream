// =============================================================================
// autostream_repeat_buffer.h
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Header-only, pure (C++ standard library only) core of the "repeat" feature:
//
//   - RepeatBuffer / RepeatBuffer::Reader — chunked in-RAM store for the
//     recording, plus a sequential reader for replay.
//   - CodecChoice / pick_codec() / byte_rate_for() — the codec ladder that
//     picks recording quality from free RAM.
//   - max_recording_seconds() — the sliding-window sizing formula.
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

    // Appends len bytes, allocating new chunks as needed.  The recorder only
    // ever appends whole encoded frames (MP2 frame or PCM sample-aligned
    // block), so chunk boundaries always land on frame boundaries by
    // construction — this function does not need to know about frames.
    //
    // Returns false only if a new chunk allocation itself failed (out of
    // memory).  The memory-guard *policy* — checking /proc/meminfo before
    // allocating and calling drop_oldest_chunk() pre-emptively to stay above
    // the free-RAM floor — is orchestrated by the impure RepeatRecorder;
    // this pure buffer just tries to grow and reports hard allocation
    // failure.
    //
    // Thin wrapper over append_with_preallocated() so the incremental
    // _total_bytes bookkeeping only needs to live in one place.
    bool append(const uint8_t* data, size_t len)
    {
        return append_with_preallocated(nullptr, data, len);
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

    // Same contract as append(), except: if a NEW chunk turns out to be
    // needed for this call and `preallocated` is non-null, that storage is
    // ADOPTED as the new chunk instead of this function calling `new`
    // itself. `preallocated` must have been sized via
    // allocate_chunk_storage(chunk_bytes()) by the caller; if it is null,
    // or if more than one new chunk is needed in a single call (never
    // happens in practice — production block sizes are always far smaller
    // than chunk_bytes()), any additional chunks beyond the first fall back
    // to a normal internal allocation, exactly like append(). If a new
    // chunk was predicted but turns out not to be needed after all (the
    // caller's "will this need a new chunk?" check raced with something —
    // should not happen given single-writer discipline, but is harmless
    // either way), `preallocated` is simply destroyed when this function
    // returns.
    bool append_with_preallocated(std::unique_ptr<uint8_t[]> preallocated,
                                   const uint8_t* data, size_t len)
    {
        bool consumed_preallocated = false;
        size_t written = 0;
        while (written < len)
        {
            if (_chunks.empty() || _chunks.back().used == _chunks.back().capacity)
            {
                if (!consumed_preallocated && preallocated)
                {
                    Chunk c;
                    c.data     = std::move(preallocated);
                    c.capacity = _chunk_bytes;
                    c.used     = 0;
                    _chunks.push_back(std::move(c));
                    consumed_preallocated = true;
                }
                else if (!allocate_chunk())
                {
                    // _total_bytes must equal the sum of every chunk's
                    // `used` at all times, including on this early-return
                    // failure path (some bytes may already have been
                    // committed to earlier chunks this same call) -- so it
                    // is updated per-iteration below (c.used += n), never
                    // just once at the end.
                    return false;
                }
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

    // Frees the oldest (front) chunk — the sliding-window mechanism.  Never
    // frees the last remaining chunk, even if empty: the buffer always keeps
    // at least one chunk once anything has been appended, so a Reader always
    // has a valid head to clamp to (unit test U2).  Latches truncated_head().
    void drop_oldest_chunk()
    {
        if (_chunks.size() <= 1)
            return;
        _total_bytes -= _chunks.front().used;   // keep the incremental counter exact
        _chunks.pop_front();
        ++_head_seq;
        _truncated_head = true;
    }

    // Removes bytes_from_end bytes from the tail, across chunk boundaries.
    // The caller (silence trim) has already frame-aligned the byte count.
    // Clamped to total_bytes() — truncating "the whole buffer" empties
    // it cleanly rather than underflowing.
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
                    _chunks.pop_back();
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

    // Frees everything; resets to a brand-new buffer of the same chunk size.
    void clear()
    {
        _chunks.clear();
        _head_seq        = 0;
        _truncated_head  = false;
        _total_bytes     = 0;
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
    std::deque<Chunk> steal_chunks()
    {
        std::deque<Chunk> stolen = std::move(_chunks);
        _chunks.clear();
        _head_seq       = 0;
        _truncated_head = false;
        _total_bytes    = 0;
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
    bool allocate_chunk()
    {
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

    // Incremental mirror of "sum of every chunk's `used`", maintained by
    // every mutator (append_with_preallocated/drop_oldest_chunk/
    // truncate_tail/clear/steal_chunks) so total_bytes() is O(1) instead of
    // O(chunk count) -- this sits on RepeatController::get_status()'s poll
    // path and must not scale with recording length.
    size_t _total_bytes    = 0;
};


// =============================================================================
// Codec ladder and max_recording_seconds
// =============================================================================

// Recording quality tier, chosen from free RAM at each begin_session() when
// the configured codec is "auto"; a pinned codec (config) skips the ladder
// but still goes through max_recording_seconds() for the free-RAM-floor math.
enum class CodecChoice
{
    Unavailable,  // < 110 MiB available: recording refused
    Mp2_160,      // 110-129 MiB available
    Mp2_192,      // 130-159 MiB available
    Mp2_224,      // 160-999 MiB available
    PcmS16,       // >= 1000 MiB available: raw PCM, no compression
};

// Ladder thresholds, evaluated against MemAvailable in MiB.
inline CodecChoice pick_codec(long available_mib)
{
    if (available_mib < 110)
        return CodecChoice::Unavailable;
    if (available_mib < 130)
        return CodecChoice::Mp2_160;
    if (available_mib < 160)
        return CodecChoice::Mp2_192;
    if (available_mib < 1000)
        return CodecChoice::Mp2_224;
    return CodecChoice::PcmS16;
}

// Bytes/second the recorder appends to the buffer for a given codec choice.
// MP2 rates are exactly bitrate/8 (self-contained frames at a fixed bitrate,
// independent of sample rate). The PCM tier stores s16 stereo regardless of
// the pipe's bit depth, so its byte rate does depend on the sample rate:
// 2 channels * 2 bytes/sample * sample_rate_hz.
//
// Test plan U10 checks byte_rate_for(codec, rate) * target_seconds against
// the sizing table these constants are built from.
inline long byte_rate_for(CodecChoice codec, long sample_rate_hz)
{
    switch (codec)
    {
        case CodecChoice::Mp2_160: return 160000 / 8;                  // 20,000 B/s
        case CodecChoice::Mp2_192: return 192000 / 8;                  // 24,000 B/s
        case CodecChoice::Mp2_224: return 224000 / 8;                  // 28,000 B/s
        case CodecChoice::PcmS16:  return sample_rate_hz * 2 /*ch*/ * 2 /*bytes*/;
        case CodecChoice::Unavailable:
        default:
            return 0;
    }
}

// The free-RAM floor: the sliding window keeps (available_mib - 64 MiB)
// worth of headroom on top of what is already held, converted to a duration
// at the codec's byte rate. The buffer has no fixed target-duration cap: it
// is bounded ONLY by this floor and the codec ladder -- it buffers as much
// as it can, for as long as free RAM allows.
constexpr long kFreeRamFloorMib = 64;

// max_recording_seconds = ((available_mib - 64 MiB) + held_bytes) / byte_rate
//
// held_bytes is the recording's current size (0 at a fresh begin_session(),
// >0 mid-recording — the bytes already held don't need "new" headroom).  If
// available_mib is already at/under the floor, the headroom term is clamped
// to zero rather than going negative (the driving case: this is what
// happens right before drop_oldest_chunk() kicks in).
inline long max_recording_seconds(CodecChoice codec, long available_mib,
                                   size_t held_bytes,
                                   long sample_rate_hz)
{
    if (codec == CodecChoice::Unavailable)
        return 0;

    long rate = byte_rate_for(codec, sample_rate_hz);
    if (rate <= 0)
        return 0;

    long long headroom_mib = static_cast<long long>(available_mib) - kFreeRamFloorMib;
    long long headroom_bytes = headroom_mib * 1024ll * 1024ll +
                                static_cast<long long>(held_bytes);
    if (headroom_bytes < 0)
        headroom_bytes = 0;

    long long seconds = headroom_bytes / rate;
    if (seconds < 0)
        seconds = 0;

    return static_cast<long>(seconds);
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
    long available_mib = kMemInfoParseError;

    bool ok() const { return available_mib >= 0; }
};

// Parses lines of the form "MemAvailable:    123456 kB" (any run of
// whitespace between the fields; the trailing unit is expected to be "kB"
// per the kernel's documented format). Other lines are ignored. Malformed
// candidate lines (field present but the numeric value doesn't parse) are
// also ignored, as if the field were absent — this function never throws.
inline MemInfo parse_meminfo_text(const std::string& text)
{
    MemInfo result;

    const std::string key = "MemAvailable:";
    size_t search_from = 0;
    while (search_from < text.size())
    {
        size_t line_end = text.find('\n', search_from);
        if (line_end == std::string::npos)
            line_end = text.size();

        std::string line = text.substr(search_from, line_end - search_from);
        search_from = line_end + 1;

        size_t key_pos = line.find(key);
        if (key_pos != 0)
            continue;  // must be the field name at the start of the line

        size_t pos = key.size();
        // Skip whitespace between the key and the numeric value.
        while (pos < line.size() && std::isspace(static_cast<unsigned char>(line[pos])))
            ++pos;

        size_t digits_start = pos;
        while (pos < line.size() && std::isdigit(static_cast<unsigned char>(line[pos])))
            ++pos;

        if (pos == digits_start)
            continue;  // no digits found; malformed line, ignore it

        try
        {
            long kib = std::stol(line.substr(digits_start, pos - digits_start));
            result.available_mib = kib / 1024;
        }
        catch (const std::exception&)
        {
            continue;  // out-of-range or otherwise unparseable; ignore
        }
        return result;  // first (and only expected) MemAvailable line wins
    }

    return result;  // field never found: available_mib stays kMemInfoParseError
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
