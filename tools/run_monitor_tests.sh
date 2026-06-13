#!/usr/bin/env bash
# run_monitor_tests.sh — build and run the native monitor unit tests.
#
# Usage (from repo root):
#   bash tools/run_monitor_tests.sh
#
# Requirements (Linux only):
#   apt-get install g++ libasound2-dev libsamplerate0-dev
#
# Exit code: 0 if all tests pass, 1 if any fail, 2 if build fails.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MONITOR_DIR="$REPO_ROOT/core/monitor"
TEST_DIR="$MONITOR_DIR/tests"
BUILD_DIR="${TMPDIR:-/tmp}/autostream_monitor_tests"

mkdir -p "$BUILD_DIR"

echo "=== Building test_control_protocol (no system libs needed) ==="
g++ -std=c++17 -O2 \
    "$TEST_DIR/test_control_protocol.cpp" \
    -o "$BUILD_DIR/test_control_protocol"

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

echo ""
echo "=== Running test_control_protocol (from repo root) ==="
(cd "$REPO_ROOT" && "$BUILD_DIR/test_control_protocol")

echo ""
echo "=== Running test_monitor_utils ==="
"$BUILD_DIR/test_monitor_utils"

echo ""
echo "=== Running test_monitor_dsp ==="
"$BUILD_DIR/test_monitor_dsp"

echo ""
echo "All native monitor tests passed."
