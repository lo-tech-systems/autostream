// =============================================================================
// test_log_capture.h
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Helpers for tests that capture the monitor logger's output: redirect fd 2,
// drain a pipe, and read the captured lines back.
// =============================================================================

#pragma once

#include "autostream_monitor_utils.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#include <poll.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// StderrRedirect: swap fd 2 to an arbitrary fd for the duration of a scope.
//
// The logger writes to the process's `stderr` FILE*, which glibc keeps
// unbuffered -- each fwrite() triggers an immediate write(2) against
// whatever fd 2 currently refers to.  Redirecting fd 2 to a pipe/file we
// control, without touching any production code, is what lets these tests
// exercise the logging thread's real sink-write path (including making it
// block) from a single process.  IMPORTANT: no CHECK()/fprintf(stderr, ...)
// diagnostics may run while a redirect that could block is active -- they
// would themselves block on it.  Restore first, then assert.
// ---------------------------------------------------------------------------

class StderrRedirect
{
public:
    explicit StderrRedirect(int new_fd)
    {
        std::fflush(stderr);
        _saved_fd = ::dup(STDERR_FILENO);
        ::dup2(new_fd, STDERR_FILENO);
    }

    ~StderrRedirect()
    {
        restore();
    }

    void restore()
    {
        if (_saved_fd < 0)
            return;
        std::fflush(stderr);
        ::dup2(_saved_fd, STDERR_FILENO);
        ::close(_saved_fd);
        _saved_fd = -1;
    }

private:
    int _saved_fd = -1;
};

// ---------------------------------------------------------------------------
// PipeDrain: continuously drain a pipe's read end in a background thread.
//
// IMPORTANT: a naive `while (read(fd, ...) > 0) {}` loop deadlocks here --
// read() only returns 0 (EOF) once every write end of the pipe is closed,
// but our write end stays open (dup2'd onto stderr) for the whole test, so
// such a loop blocks forever waiting for data that will never come once the
// logging thread finishes its current backlog. poll() with a short timeout,
// checked against a stop flag, lets the drain run concurrently with
// logger_test_wait_drained() (new messages can keep arriving while we wait)
// and still be stopped deterministically from the test thread.
// ---------------------------------------------------------------------------

inline void pipe_drain_loop(int read_fd, std::atomic<bool>* stop_flag)
{
    char buf[4096];
    struct pollfd pfd;
    pfd.fd = read_fd;
    pfd.events = POLLIN;

    while (!stop_flag->load(std::memory_order_relaxed))
    {
        pfd.revents = 0;
        int rc = ::poll(&pfd, 1, 50 /* ms */);
        if (rc > 0 && (pfd.revents & POLLIN))
        {
            ssize_t n = ::read(read_fd, buf, sizeof(buf));
            if (n <= 0)
                break;  // pipe closed or genuine error
        }
    }
}

// ---------------------------------------------------------------------------
// read_captured_lines: the non-empty lines of a capture file, in order.
// ---------------------------------------------------------------------------

inline std::vector<std::string> read_captured_lines(const char* path)
{
    std::vector<std::string> lines;
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line))
        if (!line.empty())
            lines.push_back(line);
    return lines;
}

// ---------------------------------------------------------------------------
// LogFileCapture: capture the logger's sink into a file for one scope.
// finish() waits for the logging thread, stops capturing and returns the
// lines written; the destructor does the same and discards them.
// ---------------------------------------------------------------------------

class LogFileCapture
{
public:
    LogFileCapture()
    {
        logger_test_wait_drained(1000);   // lines logged earlier belong to no capture
        std::snprintf(_path, sizeof(_path), "/tmp/test_log_capture_XXXXXX");
        _fd = ::mkstemp(_path);
        if (_fd >= 0)
            _redirect = new StderrRedirect(_fd);
    }

    ~LogFileCapture()
    {
        finish();
    }

    LogFileCapture(const LogFileCapture&) = delete;
    LogFileCapture& operator=(const LogFileCapture&) = delete;

    std::vector<std::string> finish()
    {
        if (_fd < 0)
            return {};
        logger_test_wait_drained(1000);
        delete _redirect;
        _redirect = nullptr;
        ::close(_fd);
        _fd = -1;
        std::vector<std::string> lines = read_captured_lines(_path);
        ::unlink(_path);
        return lines;
    }

private:
    char _path[64];
    int _fd = -1;
    StderrRedirect* _redirect = nullptr;
};
