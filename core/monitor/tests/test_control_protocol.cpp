// =============================================================================
// test_control_protocol.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Source-inspection tests for the JSON control protocol.  These tests assert
// that every command name sent by MonitorClient in autostream_core.py has a
// matching dispatch branch in ControlServer::dispatch_command().  They do not
// link against ALSA or libsamplerate — they operate entirely on the source
// text so they can be compiled and run on any machine with g++.
//
// Build (on Linux or macOS/Windows, from repo root):
//   g++ -std=c++17 -O2 \
//       core/monitor/tests/test_control_protocol.cpp \
//       -o /tmp/test_control_protocol && /tmp/test_control_protocol
//
// The test reads two fixed relative paths:
//   core/monitor/autostream_monitor.cpp  (C++ dispatcher)
//   core/autostream_core.py              (Python client)
// =============================================================================

#include <cassert>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>

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
// Helpers
// ---------------------------------------------------------------------------

static std::string read_file(const std::string& path)
{
    std::ifstream f(path);
    if (!f.is_open())
        return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static bool contains(const std::string& haystack, const std::string& needle)
{
    return haystack.find(needle) != std::string::npos;
}

// ---------------------------------------------------------------------------
// Test: command names that MonitorClient emits are dispatched in the C++ code
// ---------------------------------------------------------------------------

// Every string in this table must be found in dispatch_command() in
// autostream_monitor.cpp.  They are the exact values of the "type" field
// sent by MonitorClient in autostream_core.py.
static const std::vector<std::string> EXPECTED_COMMANDS = {
    "configure_input",
    "set_fifo",
    "start_input",
    "stop_input",
    "set_allow_capture",
    "set_eq",
    "set_gain",
    "set_output_eq",
    "set_output_gain",
    "set_output_auto_trim",
    "set_log_level",
    "get_status",
    "get_id_snapshot",
    "start_output_dump",
    "stop_output_dump",
    "list_devices",
};

static void test_all_commands_dispatched(const std::string& dispatcher_src)
{
    for (const auto& cmd : EXPECTED_COMMANDS) {
        CHECK(contains(dispatcher_src, "\"" + cmd + "\""),
              ("dispatch_command handles command: " + cmd).c_str());
    }
}

static void test_all_commands_sent_by_python(const std::string& python_src)
{
    for (const auto& cmd : EXPECTED_COMMANDS) {
        // Python sends commands as: {"type": "command_name", ...}
        // Accept either single or double quoted strings.
        bool found = contains(python_src, "\"type\": \"" + cmd + "\"") ||
                     contains(python_src, "\"type\":\"" + cmd + "\"")  ||
                     contains(python_src, "'type': '"  + cmd + "'")    ||
                     contains(python_src, "'type':'"   + cmd + "'");
        CHECK(found, ("Python sends command: " + cmd).c_str());
    }
}

// ---------------------------------------------------------------------------
// Test: get_id_snapshot response includes length header protocol
// ---------------------------------------------------------------------------

static void test_length_header_in_dispatcher(const std::string& src)
{
    // The dispatcher must write a length-prefixed binary payload for
    // get_id_snapshot.  Check that the source references a "length" or "len"
    // field in the JSON response, which MonitorClient reads as a header.
    bool has_length_field =
        contains(src, "\"length\"") ||
        contains(src, "\"len\"")    ||
        contains(src, "snapshot_out");
    CHECK(has_length_field, "dispatch_command emits length field or snapshot payload for get_id_snapshot");
}

// ---------------------------------------------------------------------------
// Test: response JSON always contains "ok" field
// ---------------------------------------------------------------------------

static void test_ok_field_in_responses(const std::string& src)
{
    CHECK(contains(src, "\"ok\":true")  || contains(src, "\"ok\": true"),
          "dispatcher emits ok:true responses");
    CHECK(contains(src, "\"ok\":false") || contains(src, "\"ok\": false"),
          "dispatcher emits ok:false responses");
}

// ---------------------------------------------------------------------------
// Test: debug_fail_input test hook is dispatched AND runtime-gated
//
// debug_fail_input is deliberately NOT in EXPECTED_COMMANDS above: it is a
// test-only command (docs/AUTOSTREAM-MONITOR.md), never sent by the
// production Python client (core/autostream_core.py), so it must not be
// asserted present there. This is a narrower, source-text-only check (no
// ALSA link needed, matching this file's whole approach) that the command
// exists in the dispatcher and that its runtime gate (--test-hooks /
// test_hooks_enabled()) is present, rather than compile-time-only like
// AUTOSTREAM_REPEAT_TEST_HOOKS's debug_dump_repeat_buffer (also
// intentionally absent from EXPECTED_COMMANDS, for the same reason).
// ---------------------------------------------------------------------------

static void test_debug_fail_input_gated(const std::string& src)
{
    CHECK(contains(src, "\"debug_fail_input\""),
          "dispatch_command handles command: debug_fail_input");
    CHECK(contains(src, "test hooks not enabled"),
          "api_debug_fail_input rejects when test hooks are not enabled");
    CHECK(contains(src, "--test-hooks"),
          "main() parses --test-hooks");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int main(int argc, char** argv)
{
    // Locate source files relative to CWD (expected: repo root).
    std::string dispatcher_path = "core/monitor/autostream_monitor.cpp";
    std::string python_path     = "core/autostream_core.py";

    if (argc >= 2) dispatcher_path = argv[1];
    if (argc >= 3) python_path     = argv[2];

    std::string dispatcher_src = read_file(dispatcher_path);
    std::string python_src     = read_file(python_path);

    if (dispatcher_src.empty()) {
        std::fprintf(stderr, "ERROR: could not read %s\n", dispatcher_path.c_str());
        return 2;
    }
    if (python_src.empty()) {
        std::fprintf(stderr, "ERROR: could not read %s\n", python_path.c_str());
        return 2;
    }

    test_all_commands_dispatched(dispatcher_src);
    test_all_commands_sent_by_python(python_src);
    test_length_header_in_dispatcher(dispatcher_src);
    test_ok_field_in_responses(dispatcher_src);
    test_debug_fail_input_gated(dispatcher_src);

    if (g_failed == 0) {
        std::printf("OK  %d/%d tests passed\n", g_tests, g_tests);
        return 0;
    }
    std::fprintf(stderr, "FAIL %d/%d tests failed\n", g_failed, g_tests);
    return 1;
}
