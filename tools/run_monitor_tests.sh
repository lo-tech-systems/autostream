#!/usr/bin/env bash
# run_monitor_tests.sh — build and run the native monitor unit tests.
#
# Usage (from repo root):
#   bash tools/run_monitor_tests.sh              # normal -O2 build of every suite
#   bash tools/run_monitor_tests.sh --sanitize   # ASan/UBSan build of the repeat suites
#
# Requirements (Linux only):
#   apt-get install g++ libasound2-dev libsamplerate0-dev
#
# --sanitize rebuilds and reruns the two repeat-feature suites (the ones
# exercising the buffer's chunk recycling and the controller transition
# table) under -fsanitize=address,undefined: use-after-free at chunk seams,
# heap overflow across chunk boundaries, and UB in the sizing arithmetic.
# GCC's sanitizers cover the same classes as clang's and g++ is already the
# only compiler this script (and CI) assumes. Note the known blind spot:
# a stale Reader over a RECYCLED chunk is valid, owned memory — ASan cannot
# flag it — so that class is covered by content-assertion unit tests in
# test_repeat_buffer.cpp instead, which run in both modes.
#
# Exit code: 0 if all tests pass, 1 if any fail, 2 if build fails.

set -euo pipefail

if [ "${1:-}" = "--sanitize" ]; then
    REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
    MONITOR_DIR="$REPO_ROOT/core/monitor"
    TEST_DIR="$MONITOR_DIR/tests"
    BUILD_DIR="${TMPDIR:-/tmp}/autostream_monitor_tests_sanitize"
    SAN_FLAGS="-std=c++17 -Wall -Wextra -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer"

    mkdir -p "$BUILD_DIR"

    echo "=== [sanitize] Building test_repeat_buffer (ASan/UBSan) ==="
    # shellcheck disable=SC2086  # SAN_FLAGS is a deliberate word-split flag list
    g++ $SAN_FLAGS -I "$MONITOR_DIR" \
        "$TEST_DIR/test_repeat_buffer.cpp" \
        -o "$BUILD_DIR/test_repeat_buffer"

    echo "=== [sanitize] Building test_repeat_transitions (ASan/UBSan) ==="
    # shellcheck disable=SC2086
    g++ $SAN_FLAGS -I "$MONITOR_DIR" \
        "$TEST_DIR/test_repeat_transitions.cpp" \
        -lpthread \
        -o "$BUILD_DIR/test_repeat_transitions"

    echo ""
    echo "=== [sanitize] Running test_repeat_buffer ==="
    "$BUILD_DIR/test_repeat_buffer"

    echo ""
    echo "=== [sanitize] Running test_repeat_transitions ==="
    "$BUILD_DIR/test_repeat_transitions"

    echo ""
    echo "All sanitized repeat suites passed."
    exit 0
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MONITOR_DIR="$REPO_ROOT/core/monitor"
TEST_DIR="$MONITOR_DIR/tests"
BUILD_DIR="${TMPDIR:-/tmp}/autostream_monitor_tests"

mkdir -p "$BUILD_DIR"

echo "=== Building test_control_protocol (no system libs needed) ==="
g++ -std=c++17 -O2 \
    "$TEST_DIR/test_control_protocol.cpp" \
    -o "$BUILD_DIR/test_control_protocol"

echo "=== Building test_control_thread_reap (no system libs needed) ==="
g++ -std=c++17 -O2 -pthread \
    "$TEST_DIR/test_control_thread_reap.cpp" \
    -o "$BUILD_DIR/test_control_thread_reap"

echo "=== Building test_monitor_utils ==="
g++ -std=c++17 -O2 \
    -I "$MONITOR_DIR" \
    "$TEST_DIR/test_monitor_utils.cpp" \
    "$MONITOR_DIR/autostream_monitor_utils.cpp" \
    -lpthread \
    -o "$BUILD_DIR/test_monitor_utils"

echo "=== Building test_monitor_dsp (requires libasound2-dev, libsamplerate0-dev) ==="
g++ -std=c++17 -O2 \
    -I "$MONITOR_DIR" \
    "$TEST_DIR/test_monitor_dsp.cpp" \
    "$MONITOR_DIR/autostream_monitor_dsp.cpp" \
    "$MONITOR_DIR/autostream_monitor_utils.cpp" \
    -lpthread -lasound -lsamplerate -latomic \
    -o "$BUILD_DIR/test_monitor_dsp"

echo "=== Building test_repeat_buffer (header-only, no system libs needed) ==="
g++ -std=c++17 -Wall -Wextra -O2 \
    -I "$MONITOR_DIR" \
    "$TEST_DIR/test_repeat_buffer.cpp" \
    -o "$BUILD_DIR/test_repeat_buffer"

echo "=== Building test_id_tap (header-only, requires libsamplerate0-dev) ==="
g++ -std=c++17 -Wall -Wextra -O2 \
    -I "$MONITOR_DIR" \
    "$TEST_DIR/test_id_tap.cpp" \
    -lsamplerate \
    -o "$BUILD_DIR/test_id_tap"

echo "=== Building test_spsc_ring (header-only, no system libs needed) ==="
g++ -std=c++17 -Wall -Wextra -O2 \
    -I "$MONITOR_DIR" \
    "$TEST_DIR/test_spsc_ring.cpp" \
    -lpthread \
    -o "$BUILD_DIR/test_spsc_ring"

echo "=== Building test_repeat_transitions (header-only decide_repeat_transition(); requires libasound2-dev, libsamplerate0-dev for autostream_monitor.h, but NOT libtwolame-dev/libmpg123-dev) ==="
g++ -std=c++17 -Wall -Wextra -O2 \
    -I "$MONITOR_DIR" \
    "$TEST_DIR/test_repeat_transitions.cpp" \
    -lpthread \
    -o "$BUILD_DIR/test_repeat_transitions"

echo ""
echo "=== Running test_control_protocol (from repo root) ==="
(cd "$REPO_ROOT" && "$BUILD_DIR/test_control_protocol")

echo ""
echo "=== Running test_control_thread_reap ==="
"$BUILD_DIR/test_control_thread_reap"

echo ""
echo "=== Running test_monitor_utils ==="
"$BUILD_DIR/test_monitor_utils"

echo ""
echo "=== Running test_monitor_dsp ==="
"$BUILD_DIR/test_monitor_dsp"

echo ""
echo "=== Running test_repeat_buffer ==="
"$BUILD_DIR/test_repeat_buffer"

echo ""
echo "=== Running test_id_tap ==="
"$BUILD_DIR/test_id_tap"

echo ""
echo "=== Running test_spsc_ring ==="
"$BUILD_DIR/test_spsc_ring"

echo ""
echo "=== Running test_repeat_transitions ==="
"$BUILD_DIR/test_repeat_transitions"

echo ""
echo "All native monitor tests passed."
