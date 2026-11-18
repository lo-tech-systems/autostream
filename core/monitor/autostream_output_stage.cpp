// =============================================================================
// autostream_output_stage.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// OutputStage: the single thread that drives OutputMixer (see
// autostream_output_stage.h, where OutputMixer itself is fully inline) and
// owns the one FIFO write per block.
// =============================================================================

#include "autostream_output_stage.h"

#include "autostream_monitor.h"
#include "autostream_monitor_utils.h"

#include <samplerate.h>

namespace
{
    // Size of the cold-start prefill itself, once triggered.
    constexpr double kPrefillSeconds = 0.5;

    // Throttle for the "live-clocked wait timed out" warning.
    constexpr double kLiveWaitWarnPeriodSeconds = 5.0;

    // Threshold and throttle for the timer-paced "scheduling gap" warning:
    // how late the output thread's sleep_until() woke relative to its
    // intended deadline. Independent of kLiveWaitWarnPeriodSeconds above,
    // which throttles a different warning on the live-clocked branch.
    constexpr double kSchedGapWarnSeconds       = 0.5;
    constexpr double kSchedGapWarnPeriodSeconds = 5.0;

    // Every loss and timing counter the stream summary reports, copied with
    // relaxed loads (no allocation, no lock) when a stream opens and again
    // when it ends.
    struct StreamCounters
    {
        FifoWriter::Counters        fifo;
        OutputMixer::Counters       mixer;
        OutputThreadStats::Counters thread;
    };

    // One stream's figures: the counters at its start and end, how long it
    // ran, and the length of the stall streak still open when it ended.
    struct StreamSummary
    {
        StreamCounters before;
        StreamCounters after;
        double         seconds   = 0.0;
        double         end_stall = 0.0;
    };

    // Logs one line for a finished output stream from the counter deltas: a
    // warning when anything was lost, underran, was dropped from a ring or
    // stalled, debug otherwise. A partial prefill discarded at idle is
    // reported but does not raise the level. Called without the FIFO lock
    // held.
    void log_stream_summary(const StreamSummary& sm)
    {
        const StreamCounters& a = sm.after;
        const StreamCounters& b = sm.before;
        auto d = [](uint64_t after, uint64_t before) -> unsigned long long
        {
            return static_cast<unsigned long long>(after >= before ? after - before : 0);
        };

        unsigned long long no_reader = d(a.fifo.no_reader_bytes, b.fifo.no_reader_bytes);
        unsigned long long overflow  = d(a.fifo.overflow_bytes,  b.fifo.overflow_bytes);
        unsigned long long error     = d(a.fifo.error_bytes,     b.fifo.error_bytes);
        unsigned long long stranded  = d(a.fifo.stranded_bytes,  b.fifo.stranded_bytes);
        unsigned long long prefill   = d(a.thread.prefill_dropped_bytes, b.thread.prefill_dropped_bytes);
        unsigned long long stalls    = d(a.fifo.stall_events,    b.fifo.stall_events);

        unsigned long long under[3], drops[3];
        bool lost = no_reader || overflow || error || stranded || stalls;
        for (int i = 0; i < 3; ++i)
        {
            under[i] = d(a.mixer.underrun_frames[i], b.mixer.underrun_frames[i]);
            drops[i] = d(a.mixer.dropped_frames[i],  b.mixer.dropped_frames[i]);
            lost = lost || under[i] || drops[i];
        }

        char line[512];
        std::snprintf(line, sizeof(line),
            "[output] Stream ended after %.1f s: lost bytes no_reader=%llu overflow=%llu error=%llu "
            "stranded=%llu prefill=%llu; underrun frames live1=%llu live2=%llu replay=%llu; "
            "ring_drop frames live1=%llu live2=%llu replay=%llu; stalls=%llu end_stall=%.1f s "
            "live_wait_timeouts=%llu lock_waits_over_1ms=%llu",
            sm.seconds, no_reader, overflow, error, stranded, prefill,
            under[0], under[1], under[2], drops[0], drops[1], drops[2],
            stalls, sm.end_stall,
            d(a.thread.live_wait_timeouts, b.thread.live_wait_timeouts),
            d(a.thread.lock_waits_over_1ms, b.thread.lock_waits_over_1ms));

        if (lost)
            LOG_WARN("%s", line);
        else
            LOG_DEBUG("%s", line);
    }
}

OutputStage::OutputStage(OutputMixer& mixer, FifoWriter& writer, std::mutex& processor_mutex,
                          OutputProcessor& processor, OutputDumpWriter& dump)
    : _mixer(mixer)
    , _writer(writer)
    , _processor_mutex(processor_mutex)
    , _processor(processor)
    , _dump(dump)
{
}

OutputStage::~OutputStage()
{
    stop();
}

void OutputStage::start()
{
    if (_running.exchange(true, std::memory_order_acq_rel))
        return;   // already running

    _stop_requested.store(false, std::memory_order_relaxed);
    _thread = std::thread(&OutputStage::thread_func, this);
    LOG_INFO("[output] Output stage started");
}

void OutputStage::stop()
{
    if (!_running.exchange(false, std::memory_order_acq_rel))
        return;   // already stopped, or never started

    // No dedicated wake exists beyond this flag: the idle wait
    // (wait_for_activity(), 100 ms) and every other wait in thread_func()
    // are already bounded to at most a couple of block periods, so the
    // thread notices _stop_requested promptly without needing a signal of
    // its own.
    _stop_requested.store(true, std::memory_order_release);

    if (_thread.joinable())
        _thread.join();

    LOG_INFO("[output] Output stage stopped");
}

void OutputStage::thread_func()
{
    set_thread_realtime("output-stage", kRtPrioOutput);

    const int    rate_hz      = _mixer.rate_hz();
    const size_t block_frames = _mixer.block_frames();
    const auto   block_period = std::chrono::duration<double>(
        static_cast<double>(block_frames) / static_cast<double>(rate_hz));

    const size_t prefill_target_bytes =
        static_cast<size_t>(static_cast<double>(rate_hz) * kPrefillSeconds + 0.5)
        * static_cast<size_t>(AudioMonitor::output_bytes_per_frame());

    std::vector<float>   mix_buf(block_frames * 2);
    std::vector<int32_t> pcm32(block_frames * 2);
    std::vector<int16_t> pcm16(block_frames * 2);
    std::vector<uint8_t> prefill_buf;
    prefill_buf.reserve(prefill_target_bytes);

    bool   idle            = true;
    // Time of the last block handed to the writer, successful or not: a
    // stalled pipe must not re-trigger the cold-start hold mid-stream, only
    // an idle gap does. 0 = nothing handed over yet this stage lifetime.
    double last_write_time = 0.0;
    // True from the first write of a stream until it is ended (the output
    // has been idle past the cold-start interval, or a new stream starts
    // after such a gap).
    bool   stream_open     = false;
    // The counters, and the clock, as the open stream began.
    StreamCounters stream_start;
    double         stream_start_time = 0.0;
    // A stream ended at the cold-start decision, which holds the FIFO lock;
    // its summary is finished there and logged at the top of the next
    // iteration.
    bool          end_pending = false;
    StreamSummary pending_summary;

    auto read_counters = [this]()
    {
        StreamCounters c;
        c.fifo   = _writer.counters();
        c.mixer  = _mixer.counters();
        c.thread = _stats.counters();
        return c;
    };
    // Called just before the first write of a stream, so the figures it
    // reports include any loss in that write.
    auto note_stream_open = [&]()
    {
        if (stream_open)
            return;
        stream_start      = read_counters();
        stream_start_time = get_monotonic_time();
        stream_open       = true;
    };
    double warn_last_log   = 0.0;
    double sched_warn_last_log = 0.0;
    auto   deadline        = std::chrono::steady_clock::now();

    while (!_stop_requested.load(std::memory_order_relaxed))
    {
        if (end_pending)
        {
            log_stream_summary(pending_summary);
            end_pending = false;
        }

        if (!_mixer.any_active())
        {
            if (!idle)
            {
                LOG_DEBUG("[output] Entering idle");
                idle = true;
                // A partial prefill belongs to the session that just
                // ended; carrying it into whatever starts next would
                // splice stale audio ahead of it. It is audio that never
                // reached the writer, so it is counted as lost.
                if (!prefill_buf.empty())
                    _stats.record_prefill_dropped(prefill_buf.size());
                prefill_buf.clear();
            }

            // Idle past the cold-start interval: the stream is over. This
            // is the same test the next block applies to decide it is a
            // cold start, so the two cannot disagree.
            if (stream_open && output_gap_is_cold(last_write_time, get_monotonic_time()))
            {
                FifoWriter::StreamEnd end;
                {
                    std::lock_guard<std::mutex> lock(_processor_mutex);
                    end = _writer.end_stream(last_write_time);
                }
                stream_open = false;

                StreamSummary summary;
                summary.before    = stream_start;
                summary.after     = read_counters();
                summary.seconds   = last_write_time - stream_start_time;
                summary.end_stall = end.stall_seconds;
                log_stream_summary(summary);
            }
            _mixer.wait_for_activity(std::chrono::milliseconds(100));
            continue;
        }

        if (idle)
        {
            LOG_DEBUG("[output] Leaving idle");
            idle     = false;
            deadline = std::chrono::steady_clock::now();
        }

        int live_source = _mixer.live_clock_source();
        if (live_source >= 0)
        {
            // Live-clocked: the active live input's own (drift-compensated)
            // resampler sets the pace, so wait for its next block rather
            // than sleeping to a fixed deadline. Poll instead of blocking
            // on the ring directly, since the ring has no wake of its own.
            OutputSource src = (live_source == 0) ? OutputSource::Live1 : OutputSource::Live2;
            auto poll_deadline = std::chrono::steady_clock::now()
                + std::chrono::duration_cast<std::chrono::steady_clock::duration>(block_period * 2.0);
            bool ready = false;
            while (std::chrono::steady_clock::now() < poll_deadline)
            {
                if (_mixer.available(src) >= block_frames)
                {
                    ready = true;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            if (!ready)
            {
                _stats.record_live_wait_timeout();
                double now = get_monotonic_time();
                if (now - warn_last_log >= kLiveWaitWarnPeriodSeconds)
                {
                    LOG_WARN("[output] Live-clocked wait timed out; proceeding with a short block");
                    warn_last_log = now;
                }
                // mix_block() below pads whatever is missing and counts
                // the underrun.
            }

            // Re-base the timer-pacing deadline for whenever this stage
            // next falls back to it (the live source going quiet, or a
            // replay taking over).
            deadline = std::chrono::steady_clock::now();
        }
        else
        {
            std::this_thread::sleep_until(deadline);

            // Timer-paced only: the live-clocked branch above re-bases
            // deadline to "now" every block, so a gap measured there would
            // be meaningless. The gap includes any overrun of the previous
            // block's work, which is what a reader of the counter wants.
            double late = std::chrono::duration<double>(std::chrono::steady_clock::now() - deadline).count();
            _stats.record_late(late);
            if (late > kSchedGapWarnSeconds)
            {
                double now = get_monotonic_time();
                if (now - sched_warn_last_log >= kSchedGapWarnPeriodSeconds)
                {
                    LOG_WARN("[output] scheduling gap: woke %.0f ms late", late * 1000.0);
                    sched_warn_last_log = now;
                }
            }

            deadline += std::chrono::duration_cast<std::chrono::steady_clock::duration>(block_period);
        }

        _mixer.mix_block(mix_buf.data());

        // FifoWriter documents that every public method must be called
        // under this mutex; holding it across the whole block -- exactly
        // as InputChannel::deliver_output() holds _fifo_mutex today -- is
        // what keeps that true now that the write moved here.
        std::lock_guard<std::mutex> lock(_processor_mutex);

        _processor.apply(mix_buf.data(), static_cast<int>(block_frames));

        // Always produced, in both wire modes: the dump tap wants the
        // internal 32-bit representation regardless of the wire format
        // (mirrors deliver_output()'s int32 conversion in
        // autostream_monitor_io.cpp).
        src_float_to_int_array(mix_buf.data(), pcm32.data(), static_cast<int>(block_frames) * 2);

        bool compatible = AudioMonitor::output_format_mode() == OutputFormatMode::Compatible;
        if (compatible)
            src_float_to_short_array(mix_buf.data(), pcm16.data(), static_cast<int>(block_frames) * 2);

        _dump.submit_block(pcm32.data(), static_cast<int>(block_frames));

        const void* wire_ptr = compatible
            ? static_cast<const void*>(pcm16.data())
            : static_cast<const void*>(pcm32.data());
        const size_t wire_bytes = static_cast<size_t>(block_frames)
            * static_cast<size_t>(AudioMonitor::output_bytes_per_frame());

        double now = get_monotonic_time();
        bool cold_start = output_gap_is_cold(last_write_time, now);

        // A stream that starts after a gap this long finds the previous one
        // not yet ended when the wake from idle beat the idle check above.
        if (cold_start && stream_open)
        {
            FifoWriter::StreamEnd end = _writer.end_stream(last_write_time);
            pending_summary.before    = stream_start;
            pending_summary.after     = read_counters();
            pending_summary.seconds   = last_write_time - stream_start_time;
            pending_summary.end_stall = end.stall_seconds;
            end_pending = true;
            stream_open = false;
        }

        if (cold_start)
        {
            const uint8_t* bytes = static_cast<const uint8_t*>(wire_ptr);
            prefill_buf.insert(prefill_buf.end(), bytes, bytes + wire_bytes);

            if (prefill_buf.size() >= prefill_target_bytes)
            {
                note_stream_open();
                _writer.write(prefill_buf.data(), prefill_buf.size());
                last_write_time = get_monotonic_time();
                prefill_buf.clear();
            }
        }
        else
        {
            note_stream_open();
            _writer.write(wire_ptr, wire_bytes);
            last_write_time = get_monotonic_time();
        }
    }

    // Shut down with a stream open: report it, leaving the writer as it is
    // (stop() closes it).
    if (stream_open)
    {
        StreamSummary summary;
        summary.before  = stream_start;
        summary.after   = read_counters();
        summary.seconds = last_write_time - stream_start_time;
        log_stream_summary(summary);
    }
}
