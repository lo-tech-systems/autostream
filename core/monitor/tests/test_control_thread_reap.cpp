// =============================================================================
// test_control_thread_reap.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Regression test for the ControlServer client-thread reaping algorithm
// (see accept_loop() / stop() in autostream_monitor.cpp and the ClientThread
// entry type in autostream_monitor.h).
//
// Why this test can't link the real ControlServer: ControlServer's
// constructor takes an AudioMonitor&, and AudioMonitor holds a
// RepeatController by value, whose implementation (autostream_repeat.cpp)
// includes <twolame.h> and <mpg123.h> at file scope. Those dev headers are
// not guaranteed present in every environment this suite runs in (the same
// class of gap as the libsamplerate0-dev CI issue), so a harness that
// actually instantiates AudioMonitor/ControlServer cannot be assumed to
// compile everywhere. accept_loop()/stop() also don't touch AudioMonitor at
// all -- only dispatch_command() (reached via handle_client()) does -- so
// the part of ControlServer this bug lives in has no real dependency on
// AudioMonitor; the coupling is purely a constructor-signature one.
//
// This test therefore exercises a structural mirror of the fix: the same
// entry type (thread + shared completion flag) and the same sweep-then-push
// sequence used in accept_loop(), with source-text checks in
// test_control_protocol.cpp asserting the real accept_loop()/stop() still
// contain that pattern (done->load()/done->store(true) ordering, etc). Full
// behavioural verification against the real ControlServer happens wherever
// the complete monitor can be linked (WSL with twolame-dev/mpg123-dev
// installed, or on-device).
//
// Build (on Linux, from repo root):
//   g++ -std=c++17 -O2 -pthread \
//       core/monitor/tests/test_control_thread_reap.cpp \
//       -o /tmp/test_control_thread_reap && /tmp/test_control_thread_reap
// =============================================================================

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <memory>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
// Minimal assertion harness
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
// Structural mirror of ControlServer's ClientThread entry + accept_loop()'s
// sweep-then-push sequence and stop()'s unconditional drain.
// ---------------------------------------------------------------------------

struct ClientThread
{
    std::thread                        thread;
    std::shared_ptr<std::atomic<bool>> done;
};

class ReapingServer
{
public:
    // Mirrors accept_loop(): sweep finished entries, then add one more.
    void on_connect_then_disconnect_quickly()
    {
        reap_finished();

        auto done = std::make_shared<std::atomic<bool>>(false);
        std::thread worker([done]()
        {
            // Simulate a client that connects and disconnects immediately.
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            done->store(true);
        });
        _threads.push_back({std::move(worker), done});
    }

    size_t container_size() const { return _threads.size(); }

    // Mirrors stop(): join every remaining entry, running or finished.
    void drain_all()
    {
        for (ClientThread& ct : _threads)
        {
            if (ct.thread.joinable())
                ct.thread.join();
        }
        _threads.clear();
    }

private:
    void reap_finished()
    {
        for (size_t i = 0; i < _threads.size(); )
        {
            if (_threads[i].done->load())
            {
                if (_threads[i].thread.joinable())
                    _threads[i].thread.join();
                _threads[i] = std::move(_threads.back());
                _threads.pop_back();
            }
            else
            {
                ++i;
            }
        }
    }

    std::vector<ClientThread> _threads;
};

// ---------------------------------------------------------------------------
// Test: the container stays bounded across many sequential connections
// instead of growing by one entry per connection for the life of the process.
// ---------------------------------------------------------------------------

static void test_container_bounded_across_many_connections()
{
    ReapingServer server;
    static constexpr int NUM_CONNECTIONS = 20;

    size_t max_size_seen = 0;
    for (int i = 0; i < NUM_CONNECTIONS; ++i)
    {
        server.on_connect_then_disconnect_quickly();

        // Give the worker thread a moment to finish and flag itself done,
        // so the *next* sweep (on the following iteration) has something to
        // reap. This mirrors real accept()-spaced connections, where client
        // threads finish well before the next connection arrives.
        std::this_thread::sleep_for(std::chrono::milliseconds(5));

        if (server.container_size() > max_size_seen)
            max_size_seen = server.container_size();
    }

    // Bounded means: nowhere near NUM_CONNECTIONS entries accumulated. Before
    // the fix, an unswept vector<thread> would sit at NUM_CONNECTIONS after
    // this loop. A small constant bound (well under NUM_CONNECTIONS) is what
    // reaping-before-each-accept guarantees.
    CHECK(max_size_seen < NUM_CONNECTIONS,
          "container never grows to one entry per connection");
    CHECK(max_size_seen <= 3,
          "container stays near the live-connection count, not the historical total");

    // stop()'s unconditional drain must still account for every thread ever
    // created, whether already reaped mid-loop or still pending.
    server.drain_all();
    CHECK(server.container_size() == 0, "drain_all() joins and clears everything remaining");
}

// ---------------------------------------------------------------------------
// Test: drain_all() (stop()'s equivalent) safely joins entries regardless of
// whether their done flag was ever observed as true by a sweep -- i.e.
// correctness of the final join does not depend on the reap sweep having run.
// ---------------------------------------------------------------------------

static void test_drain_all_joins_never_swept_entries()
{
    ReapingServer server;

    // Two connections with no sweep opportunity in between (no sleep, no
    // third connection to trigger a reap): both entries are still in the
    // container, at least one of them possibly still running or just
    // finished-but-unswept, when drain_all() is called directly.
    server.on_connect_then_disconnect_quickly();
    server.on_connect_then_disconnect_quickly();

    CHECK(server.container_size() == 2, "both entries are present before draining");

    server.drain_all();
    CHECK(server.container_size() == 0, "drain_all() joins both entries regardless of done state");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int main()
{
    test_container_bounded_across_many_connections();
    test_drain_all_joins_never_swept_entries();

    if (g_failed == 0) {
        std::printf("OK  %d/%d tests passed\n", g_tests, g_tests);
        return 0;
    }
    std::fprintf(stderr, "FAIL %d/%d tests failed\n", g_failed, g_tests);
    return 1;
}
