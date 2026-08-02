"""Priority 9 — native monitor C++ test wrapper.

Builds and runs the native monitor unit tests from
core/monitor/tests/*.cpp via tools/run_monitor_tests.sh.

The native tests exercise:
  - test_control_protocol: command names present in both Python and C++,
    response framing contract (length header, ok field).  No system libs needed.
  - test_monitor_utils:    parse_monitor_log_level, get_monotonic_time,
    logger_get/set_level.  Needs libsamplerate (autostream_monitor_utils.h
    includes <samplerate.h>) plus libpthread for linking.
  - test_monitor_dsp:      BiquadFilter (0 dB passthrough, identity, zero
    input, nonzero gain, reset), EqChain (set/get bands), RateEstimator
    (initial ratio and rate, window update), OutputProcessor (initial state,
    manual gain, auto-trim, clip detection).  Needs libasound2 + libsamplerate.

Skip conditions (checked explicitly so the suite gives a clear reason):
  - Windows: g++ on Windows typically lacks libasound2 and libsamplerate;
    the tests are intended for Linux/Pi CI.
  - No g++ in PATH.
  - build dependency not found (libasound2-dev / libsamplerate0-dev).

To run locally on Linux:
  apt-get install g++ libasound2-dev libsamplerate0-dev
  python -m pytest tests/test_native_monitor.py -v
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SHELL_SCRIPT = REPO_ROOT / "tools" / "run_monitor_tests.sh"
TEST_DIR = REPO_ROOT / "core" / "monitor" / "tests"
MONITOR_DIR = REPO_ROOT / "core" / "monitor"

# ---------------------------------------------------------------------------
# Skip guards
# ---------------------------------------------------------------------------

def _have_executable(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None


def _have_header(header: str) -> bool:
    """Return True if g++ can find the given system header."""
    if not _have_executable("g++"):
        return False
    try:
        result = subprocess.run(
            ["g++", "-x", "c++", "-", "-o", "/dev/null", "-fsyntax-only"],
            input=f"#include <{header}>\n",
            text=True,
            capture_output=True,
            timeout=15,
        )
        return result.returncode == 0
    except Exception:
        return False


_have_alsa       = lambda: _have_header("alsa/asoundlib.h")
_have_samplerate = lambda: _have_header("samplerate.h")
_have_twolame    = lambda: _have_header("twolame.h")
_have_mpg123     = lambda: _have_header("mpg123.h")

SKIP_PLATFORM = pytest.mark.skipif(
    sys.platform == "win32",
    reason="native monitor tests require Linux headers (libasound2-dev, libsamplerate0-dev)",
)

SKIP_NO_GPP = pytest.mark.skipif(
    not _have_executable("g++"),
    reason="g++ not found in PATH; install build-essential",
)


# ---------------------------------------------------------------------------
# test_control_protocol — no ALSA/samplerate; runs on any platform with g++
# ---------------------------------------------------------------------------

@SKIP_NO_GPP
def test_control_protocol_source_consistency(tmp_path):
    """All MonitorClient command names have matching dispatch_command branches."""
    exe = tmp_path / "test_control_protocol"
    build = subprocess.run(
        [
            "g++", "-std=c++17", "-O2",
            str(TEST_DIR / "test_control_protocol.cpp"),
            "-o", str(exe),
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=60,
    )
    assert build.returncode == 0, (
        f"test_control_protocol build failed:\n{build.stderr}"
    )

    run = subprocess.run(
        [str(exe)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=30,
    )
    assert run.returncode == 0, (
        f"test_control_protocol failed:\n{run.stdout}\n{run.stderr}"
    )


# ---------------------------------------------------------------------------
# test_monitor_utils — requires libsamplerate0-dev (autostream_monitor_utils.h
# includes <samplerate.h>); links only against libpthread otherwise.
# ---------------------------------------------------------------------------

@SKIP_PLATFORM
@SKIP_NO_GPP
def test_monitor_utils(tmp_path):
    """Log level parsing, monotonic time, and logger set/get level."""
    if not _have_samplerate():
        pytest.skip("libsamplerate0-dev not installed (apt-get install libsamplerate0-dev)")

    exe = tmp_path / "test_monitor_utils"
    build = subprocess.run(
        [
            "g++", "-std=c++17", "-O2",
            "-I", str(MONITOR_DIR),
            str(TEST_DIR / "test_monitor_utils.cpp"),
            str(MONITOR_DIR / "autostream_monitor_utils.cpp"),
            "-lpthread",
            "-o", str(exe),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert build.returncode == 0, (
        f"test_monitor_utils build failed:\n{build.stderr}"
    )

    run = subprocess.run(
        [str(exe)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert run.returncode == 0, (
        f"test_monitor_utils failed:\n{run.stdout}\n{run.stderr}"
    )


# ---------------------------------------------------------------------------
# test_monitor_dsp — requires libasound2-dev, libsamplerate0-dev
# ---------------------------------------------------------------------------

@SKIP_PLATFORM
@SKIP_NO_GPP
@pytest.mark.skipif(
    sys.platform != "win32" and not _have_executable("g++"),
    reason="g++ not found",
)
def test_monitor_dsp(tmp_path):
    """BiquadFilter, EqChain, RateEstimator, and OutputProcessor DSP invariants."""
    if not _have_alsa():
        pytest.skip("libasound2-dev not installed (apt-get install libasound2-dev)")
    if not _have_samplerate():
        pytest.skip("libsamplerate0-dev not installed (apt-get install libsamplerate0-dev)")

    exe = tmp_path / "test_monitor_dsp"
    build = subprocess.run(
        [
            "g++", "-std=c++17", "-O2",
            "-I", str(MONITOR_DIR),
            str(TEST_DIR / "test_monitor_dsp.cpp"),
            str(MONITOR_DIR / "autostream_monitor_dsp.cpp"),
            str(MONITOR_DIR / "autostream_monitor_utils.cpp"),
            "-lpthread", "-lasound", "-lsamplerate", "-latomic",
            "-o", str(exe),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert build.returncode == 0, (
        f"test_monitor_dsp build failed:\n{build.stderr}"
    )

    run = subprocess.run(
        [str(exe)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert run.returncode == 0, (
        f"test_monitor_dsp failed:\n{run.stdout}\n{run.stderr}"
    )


# ---------------------------------------------------------------------------
# Compile-only check for all monitor translation units
# ---------------------------------------------------------------------------

@SKIP_PLATFORM
@SKIP_NO_GPP
def test_all_monitor_sources_compile(tmp_path):
    """All five monitor translation units compile cleanly with C++17."""
    if not _have_alsa():
        pytest.skip("libasound2-dev not installed")
    if not _have_samplerate():
        pytest.skip("libsamplerate0-dev not installed")
    if not _have_twolame():
        pytest.skip("libtwolame-dev not installed")
    if not _have_mpg123():
        pytest.skip("libmpg123-dev not installed")

    sources = [
        MONITOR_DIR / "autostream_monitor.cpp",
        MONITOR_DIR / "autostream_monitor_dsp.cpp",
        MONITOR_DIR / "autostream_monitor_io.cpp",
        MONITOR_DIR / "autostream_monitor_utils.cpp",
        MONITOR_DIR / "autostream_repeat.cpp",
    ]
    exe = tmp_path / "autostream_monitor_check"
    build = subprocess.run(
        [
            "g++", "-std=c++17", "-O2",
            "-I", str(MONITOR_DIR),
            *[str(s) for s in sources],
            "-lpthread", "-lasound", "-lsamplerate", "-latomic",
            "-ltwolame", "-lmpg123",
            "-o", str(exe),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert build.returncode == 0, (
        f"monitor build failed:\n{build.stderr}"
    )
