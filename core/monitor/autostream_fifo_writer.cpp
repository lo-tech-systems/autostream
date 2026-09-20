// =============================================================================
// autostream_fifo_writer.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Implementation of FifoWriter (declared in autostream_monitor.h). Kept in
// its own translation unit, separate from autostream_monitor_io.cpp's other
// I/O classes, purely so a unit test can link this file plus
// autostream_monitor_utils.cpp without pulling in AlsaCapture/InputChannel
// and, through InputChannel, the full RepeatController/ReplayEngine
// dependency chain those classes call into.
// =============================================================================

#include "autostream_monitor.h"

#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>


// =============================================================================
// FifoWriter
// =============================================================================

FifoWriter::FifoWriter() = default;

FifoWriter::~FifoWriter()
{
    close();
}

void FifoWriter::set_path(const std::string& path)
{
    close();
    _path = path;
}

bool FifoWriter::try_open()
{
    if (_path.empty())
        return false;

    // O_NONBLOCK is kept permanently on the fd (never cleared).  This means:
    //   - If OwnTone has not opened its read end yet, open() returns ENXIO and
    //     we return false silently; the caller retries on the next block.
    //   - Once open, if the pipe buffer is full, write() returns EAGAIN rather
    //     than blocking the process thread indefinitely.
    int fd = ::open(_path.c_str(), O_WRONLY | O_NONBLOCK);
    if (fd < 0)
    {
        if (errno != ENXIO && errno != ENOENT)
        {
            LOG_WARN("[fifo] Cannot open '%s': %s",
                     _path.c_str(), strerror(errno));
        }
        return false;
    }

    // Verify the path is actually a named pipe.  O_NONBLOCK lets us open a
    // regular file without blocking, so we must reject it here before we
    // start writing raw PCM into it and silently fill the disk.
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISFIFO(st.st_mode))
    {
        LOG_WARN("[fifo] '%s' is not a named pipe; rejecting", _path.c_str());
        ::close(fd);
        return false;
    }

    _fd = fd;

    // Grow the pipe buffer on every open/reopen -- the kernel does not keep
    // a closed pipe's size, so a resize done once at startup would not
    // survive the broken-pipe reopen path above. See kFifoPipeBytes's doc
    // comment.
    int pipe_bytes = resize_fifo_pipe(_fd);
    if (pipe_bytes >= 0)
    {
        LOG_INFO("[fifo] Opened '%s' for writing (pipe size %d bytes)", _path.c_str(), pipe_bytes);
    }
    else
    {
        if (!_pipe_resize_warned)
        {
            LOG_WARN("[fifo] F_SETPIPE_SZ to %d failed on '%s': %s; using default pipe size",
                     kFifoPipeBytes, _path.c_str(), strerror(errno));
            _pipe_resize_warned = true;
        }
        LOG_INFO("[fifo] Opened '%s' for writing", _path.c_str());
    }
    return true;
}

bool FifoWriter::write(const void* data, size_t len)
{
    bool ok = write_impl(data, len);

    // Cheap stall tracking for get_status()'s top-level
    // "fifo.stalled_seconds" (single relaxed atomic; no new locks on this
    // hot path -- see the member's doc comment). Every call here is already
    // an attempt by an active writer (the caller only calls write() when it
    // actually has data to deliver), so a false return is unambiguously a
    // dropped/failed write, and a true return unambiguously clears any
    // in-progress stall streak.
    if (ok)
    {
        _stall_since.store(0.0, std::memory_order_relaxed);
    }
    else if (_stall_since.load(std::memory_order_relaxed) == 0.0)
    {
        _stall_since.store(get_monotonic_time(), std::memory_order_relaxed);
    }

    return ok;
}

size_t FifoWriter::write_some(const uint8_t* data, size_t len, bool* would_block, int* hard_errno)
{
    *would_block = false;
    *hard_errno  = 0;

    size_t written = 0;
    while (written < len)
    {
        ssize_t n = ::write(_fd, data + written, len - written);
        if (n > 0)
        {
            written += static_cast<size_t>(n);
        }
        else if (n == 0)
        {
            break;
        }
        else if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            *would_block = true;
            break;
        }
        else
        {
            *hard_errno = errno;
            break;
        }
    }
    return written;
}

size_t FifoWriter::backlog_cap_bytes() const
{
    static const size_t cap = static_cast<size_t>(AudioMonitor::output_rate_hz())
                             * static_cast<size_t>(AudioMonitor::output_bytes_per_frame());
    return cap;
}

void FifoWriter::append_to_backlog(const uint8_t* data, size_t len)
{
    size_t pending = _backlog.size() - _backlog_pos;
    size_t cap     = backlog_cap_bytes();

    if (pending + len > cap)
    {
        // The reader has fallen far enough behind that honouring this
        // append would exceed one second of queued audio. There is no way
        // to know a PCM frame boundary inside the backlog's raw bytes, so
        // the whole queue is dropped rather than trimmed to fit -- and the
        // new block is not kept either, since it cannot be delivered in
        // order without what was just discarded ahead of it. This is the
        // only path on which this class still loses audio.
        double now = get_monotonic_time();
        if (now - _stall_last_log_time >= 5.0)
        {
            LOG_WARN("[fifo] Reader stalled; dropped %zu bytes of backlog on '%s'",
                     pending, _path.c_str());
            _stall_last_log_time = now;
        }
        _backlog.clear();
        _backlog_pos = 0;
        return;
    }

    if (_backlog_pos > 0)
    {
        // Compact before growing so the vector never carries dead bytes
        // ahead of the read offset.
        _backlog.erase(_backlog.begin(), _backlog.begin() + static_cast<std::ptrdiff_t>(_backlog_pos));
        _backlog_pos = 0;
    }
    _backlog.insert(_backlog.end(), data, data + len);
}

bool FifoWriter::write_impl(const void* data, size_t len)
{
    if (_fd < 0)
    {
        // Not yet open — try to open now.  If this fails (OwnTone not ready),
        // silently discard the data and wait for the next call.
        if (!try_open())
            return false;
    }

    const uint8_t* ptr = static_cast<const uint8_t*>(data);

    // Drain any backlog first, in order, before this block's new data is
    // allowed to reach the pipe -- this is what keeps frame alignment
    // intact across a reader stall.
    if (!_backlog.empty())
    {
        bool   would_block = false;
        int    hard_errno  = 0;
        size_t pending     = _backlog.size() - _backlog_pos;
        size_t written     = write_some(_backlog.data() + _backlog_pos, pending,
                                         &would_block, &hard_errno);
        _backlog_pos += written;

        if (hard_errno != 0)
        {
            if (hard_errno == EPIPE || hard_errno == EBADF)
                LOG_WARN("[fifo] Broken pipe on '%s'; will reopen on next write", _path.c_str());
            else
                LOG_WARN("[fifo] Write error on '%s': %s", _path.c_str(), strerror(hard_errno));
            close();   // also drops the (now stale) backlog
            return false;
        }

        if (_backlog_pos < _backlog.size())
        {
            // Pipe still won't take any more (EAGAIN): the new block has to
            // queue up behind what is already waiting so delivery order is
            // preserved.
            append_to_backlog(ptr, len);
            return false;
        }

        // Backlog fully drained; free it rather than leaving an empty but
        // still-allocated vector around from a stall that has since cleared.
        _backlog.clear();
        _backlog_pos = 0;
    }

    // Backlog is empty: write the new block itself.
    bool   would_block = false;
    int    hard_errno  = 0;
    size_t written = write_some(ptr, len, &would_block, &hard_errno);

    if (hard_errno != 0)
    {
        if (hard_errno == EPIPE || hard_errno == EBADF)
            LOG_WARN("[fifo] Broken pipe on '%s'; will reopen on next write", _path.c_str());
        else
            LOG_WARN("[fifo] Write error on '%s': %s", _path.c_str(), strerror(hard_errno));
        close();
        return false;
    }

    if (written == len)
        return true;

    // EAGAIN: the pipe would not take the rest (or, if written == 0, any of
    // it). Queue the unwritten tail -- never close the fd here, this is
    // ordinary backpressure, not an error, and the backlog is exactly what
    // lets the stream resume without a resync once the reader catches up.
    append_to_backlog(ptr + written, len - written);
    return false;
}

void FifoWriter::close()
{
    if (_fd >= 0)
    {
        ::close(_fd);
        _fd = -1;
    }

    // The backlog's read offset only makes sense against this fd's pipe;
    // a reopen (whether from here or from a later try_open()) always
    // starts with an empty backlog.
    _backlog.clear();
    _backlog_pos = 0;
}
