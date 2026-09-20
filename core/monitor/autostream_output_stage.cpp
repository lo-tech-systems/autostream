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
    // The stream is treated as freshly started -- and re-primed with a
    // cold-start prefill -- once it has gone this long without a successful
    // write. Below this, a transition (a crossfade, an input switch) just
    // keeps writing block by block; the pipe and OwnTone's own buffer are
    // still warm, so no prefill is needed.
    constexpr double kColdStartSeconds = 1.0;

    // Size of the cold-start prefill itself, once triggered.
    constexpr double kPrefillSeconds = 0.5;

    // Throttle for the "live-clocked wait timed out" warning.
    constexpr double kLiveWaitWarnPeriodSeconds = 5.0;
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
    double warn_last_log   = 0.0;
    auto   deadline        = std::chrono::steady_clock::now();

    while (!_stop_requested.load(std::memory_order_relaxed))
    {
        if (!_mixer.any_active())
        {
            if (!idle)
            {
                LOG_DEBUG("[output] Entering idle");
                idle = true;
                // A partial prefill belongs to the session that just
                // ended; carrying it into whatever starts next would
                // splice stale audio ahead of it.
                prefill_buf.clear();
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
        bool cold_start = (last_write_time <= 0.0) || (now - last_write_time > kColdStartSeconds);

        if (cold_start)
        {
            const uint8_t* bytes = static_cast<const uint8_t*>(wire_ptr);
            prefill_buf.insert(prefill_buf.end(), bytes, bytes + wire_bytes);

            if (prefill_buf.size() >= prefill_target_bytes)
            {
                _writer.write(prefill_buf.data(), prefill_buf.size());
                last_write_time = get_monotonic_time();
                prefill_buf.clear();
            }
        }
        else
        {
            _writer.write(wire_ptr, wire_bytes);
            last_write_time = get_monotonic_time();
        }
    }
}
