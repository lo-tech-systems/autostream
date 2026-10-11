"""P8 — Native monitor robustness tests.

Source-inspection suite (runs everywhere, no compiler needed):
  Mirrors test_control_protocol.cpp logic in Python.  Asserts that every
  command in EXPECTED_COMMANDS is dispatched by autostream_monitor.cpp and
  sent by MonitorClient in autostream_core.py.

MonitorClient edge cases (not covered by test_monitor_client.py):
  - sendall raises OSError → _command returns None and disconnects.
  - start_output_dump / stop_output_dump command contracts.

C++ build suite (Linux with g++ only, skipped otherwise):
  Compile and run:
    test_control_protocol.cpp  — no ALSA/libsamplerate
    test_monitor_utils.cpp     — requires libsamplerate (autostream_monitor_utils.h
                                 includes <samplerate.h>) and -lpthread
    test_monitor_dsp.cpp       — requires -lasound -lsamplerate -lpthread

  The tests for test_monitor_utils.cpp and test_monitor_dsp.cpp are
  additionally skipped when the libsamplerate development headers are
  absent, and test_monitor_dsp.cpp is also skipped when the ALSA
  development headers are absent.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_core as _core_mod
from autostream_core import MonitorClient


# ---------------------------------------------------------------------------
# Command table (mirrors EXPECTED_COMMANDS in test_control_protocol.cpp)
# ---------------------------------------------------------------------------

EXPECTED_COMMANDS = [
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
    "repeat_stop",
    "repeat_seek",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_source(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _cmd_in_dispatcher(src: str, cmd: str) -> bool:
    return f'"{cmd}"' in src


def _cmd_in_python(src: str, cmd: str) -> bool:
    return (
        f'"type": "{cmd}"' in src
        or f'"type":"{cmd}"' in src
        or f"'type': '{cmd}'" in src
        or f"'type':'{cmd}'" in src
    )


# ---------------------------------------------------------------------------
# Source-inspection: control protocol
# ---------------------------------------------------------------------------

class TestControlProtocolSourceInspection:
    """Python re-implementation of test_control_protocol.cpp — runs everywhere."""

    @pytest.fixture(scope="class")
    def dispatcher_src(self):
        p = REPO_ROOT / "core" / "monitor" / "autostream_monitor.cpp"
        if not p.exists():
            pytest.skip(f"autostream_monitor.cpp not found at {p}")
        return _read_source(p)

    @pytest.fixture(scope="class")
    def python_src(self):
        p = REPO_ROOT / "core" / "autostream_core.py"
        assert p.exists(), f"autostream_core.py not found at {p}"
        return _read_source(p)

    @pytest.mark.parametrize("cmd", EXPECTED_COMMANDS)
    def test_command_dispatched_by_cpp(self, dispatcher_src, cmd):
        assert _cmd_in_dispatcher(dispatcher_src, cmd), (
            f'dispatch_command() in autostream_monitor.cpp does not handle "{cmd}"; '
            "add an else-if branch for this command"
        )

    @pytest.mark.parametrize("cmd", EXPECTED_COMMANDS)
    def test_command_sent_by_python(self, python_src, cmd):
        assert _cmd_in_python(python_src, cmd), (
            f'MonitorClient in autostream_core.py does not send "{cmd}"; '
            "add the missing method"
        )

    def test_length_header_or_snapshot_out_in_dispatcher(self, dispatcher_src):
        has_header = (
            '"length"' in dispatcher_src
            or '"len"' in dispatcher_src
            or "snapshot_out" in dispatcher_src
        )
        assert has_header, (
            "dispatch_command() must write a length-prefixed payload or reference "
            "snapshot_out for get_id_snapshot; autostream_monitor.cpp needs updating"
        )

    def test_ok_true_response_in_dispatcher(self, dispatcher_src):
        # C++ source uses escaped quotes: \"ok\":true inside string literals,
        # which appear as the literal characters \"ok\":true when the file is
        # read as text. Accept both forms.
        assert (
            '"ok":true' in dispatcher_src
            or '"ok": true' in dispatcher_src
            or r'\"ok\":true' in dispatcher_src
            or r'\"ok\": true' in dispatcher_src
        ), "dispatch_command() must emit ok:true responses"

    def test_ok_false_response_in_dispatcher(self, dispatcher_src):
        assert (
            '"ok":false' in dispatcher_src
            or '"ok": false' in dispatcher_src
            or r'\"ok\":false' in dispatcher_src
            or r'\"ok\": false' in dispatcher_src
        ), "dispatch_command() must emit ok:false responses for error paths"

    def test_configure_input_reads_input_type(self, dispatcher_src):
        assert 'json_get_string(json_command, "input_type")' in dispatcher_src

    def test_configure_input_reads_dynamic_rate_matching_as_optional_bool(self, dispatcher_src):
        assert (
            'json_get_bool(json_command, "dynamic_rate_matching", false)'
            in dispatcher_src
        ), "an older coordinator that omits the field must get the option off"

    def test_track_change_seq_emitted_in_status_json(self, dispatcher_src):
        assert "track_change_seq" in dispatcher_src, (
            "autostream_monitor.cpp must include track_change_seq in the "
            "get_status JSON response for each input"
        )

    def test_track_change_silence_seconds_validated_in_cpp(self, dispatcher_src):
        assert "track_change_silence_seconds" in dispatcher_src, (
            "autostream_monitor.cpp must accept and validate "
            "track_change_silence_seconds in configure_input"
        )

    def test_track_change_silence_seconds_range_min_in_cpp(self, dispatcher_src):
        assert "0.5" in dispatcher_src, (
            "autostream_monitor.cpp must enforce the 0.5 s lower bound on "
            "track_change_silence_seconds"
        )

    def test_track_change_silence_seconds_range_max_in_cpp(self, dispatcher_src):
        assert "5.0" in dispatcher_src, (
            "autostream_monitor.cpp must enforce the 5.0 s upper bound on "
            "track_change_silence_seconds"
        )


# ---------------------------------------------------------------------------
# MonitorClient edge cases
# ---------------------------------------------------------------------------

class FakeSocket:
    """Minimal fake socket for MonitorClient injection."""

    def __init__(self, *chunks: bytes, sendall_error=None):
        self._chunks = list(chunks)
        self._sendall_error = sendall_error
        self.sent: list[bytes] = []
        self.closed = False

    def recv(self, _n: int) -> bytes:
        if not self._chunks:
            return b""
        return self._chunks.pop(0)

    def sendall(self, data: bytes) -> None:
        if self._sendall_error is not None:
            raise self._sendall_error
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True

    def settimeout(self, _t) -> None:
        pass

    def connect(self, _addr) -> None:
        pass


def _client(sock: FakeSocket | None = None) -> MonitorClient:
    c = MonitorClient("/tmp/fake.sock")
    if sock is not None:
        c._sock = sock
    return c


class TestMonitorClientSendallError:
    """sendall raising OSError must cause _command to return None and disconnect."""

    def test_sendall_os_error_returns_none(self):
        sock = FakeSocket(sendall_error=OSError("broken pipe"))
        c = _client(sock)
        resp = c._command({"type": "get_status"})
        assert resp is None

    def test_sendall_os_error_disconnects(self):
        sock = FakeSocket(sendall_error=OSError("broken pipe"))
        c = _client(sock)
        c._command({"type": "get_status"})
        assert not c.is_connected()

    def test_sendall_connection_reset_returns_none(self):
        sock = FakeSocket(sendall_error=ConnectionResetError("reset by peer"))
        c = _client(sock)
        resp = c._command({"type": "list_devices"})
        assert resp is None

    def test_sendall_error_does_not_hang(self):
        import threading
        import time
        sock = FakeSocket(sendall_error=BrokenPipeError("broken"))
        c = _client(sock)
        result: list = []

        def _run():
            result.append(c._command({"type": "get_status"}))

        t = threading.Thread(target=_run)
        t.start()
        t.join(timeout=2.0)
        assert not t.is_alive(), "_command hung instead of raising/returning on sendall error"
        assert result == [None]


# ---------------------------------------------------------------------------
# start_output_dump / stop_output_dump contracts
# ---------------------------------------------------------------------------

class TestStartStopOutputDump:
    """start_output_dump and stop_output_dump send correct commands."""

    def _ok(self, **extra) -> bytes:
        return (json.dumps({"ok": True, **extra}) + "\n").encode()

    def _fail(self, error: str = "nope") -> bytes:
        return (json.dumps({"ok": False, "error": error}) + "\n").encode()

    def test_start_output_dump_sends_correct_type(self):
        sock = FakeSocket(self._ok(path="/tmp/out.wav"))
        c = _client(sock)
        c.start_output_dump("/tmp/out.wav")
        cmd = json.loads(b"".join(sock.sent).strip())
        assert cmd["type"] == "start_output_dump"

    def test_start_output_dump_sends_path(self):
        sock = FakeSocket(self._ok(path="/tmp/out.wav"))
        c = _client(sock)
        c.start_output_dump("/tmp/out.wav")
        cmd = json.loads(b"".join(sock.sent).strip())
        assert cmd["path"] == "/tmp/out.wav"

    def test_start_output_dump_sends_overwrite_false_by_default(self):
        sock = FakeSocket(self._ok(path="/tmp/out.wav"))
        c = _client(sock)
        c.start_output_dump("/tmp/out.wav")
        cmd = json.loads(b"".join(sock.sent).strip())
        assert cmd.get("overwrite") is False

    def test_start_output_dump_sends_overwrite_true_when_requested(self):
        sock = FakeSocket(self._ok(path="/tmp/out.wav"))
        c = _client(sock)
        c.start_output_dump("/tmp/out.wav", overwrite=True)
        cmd = json.loads(b"".join(sock.sent).strip())
        assert cmd["overwrite"] is True

    def test_start_output_dump_returns_true_on_success(self):
        c = _client(FakeSocket(self._ok(path="/tmp/out.wav")))
        assert c.start_output_dump("/tmp/out.wav") is True

    def test_start_output_dump_returns_false_on_error(self):
        c = _client(FakeSocket(self._fail("dump already active")))
        assert c.start_output_dump("/tmp/out.wav") is False

    def test_start_output_dump_returns_false_on_no_response(self):
        c = _client(FakeSocket())   # EOF
        assert c.start_output_dump("/tmp/out.wav") is False

    def test_stop_output_dump_sends_correct_type(self):
        payload = {
            "ok": True, "was_active": True,
            "frames_written": 88200, "frames_dropped": 0,
        }
        sock = FakeSocket((json.dumps(payload) + "\n").encode())
        c = _client(sock)
        c.stop_output_dump()
        cmd = json.loads(b"".join(sock.sent).strip())
        assert cmd["type"] == "stop_output_dump"

    def test_stop_output_dump_returns_response_dict(self):
        payload = {
            "ok": True, "was_active": True,
            "frames_written": 48000, "frames_dropped": 0,
        }
        c = _client(FakeSocket((json.dumps(payload) + "\n").encode()))
        result = c.stop_output_dump()
        assert result is not None
        assert result["ok"] is True
        assert result["was_active"] is True
        assert result["frames_written"] == 48000

    def test_stop_output_dump_returns_none_on_no_response(self):
        c = _client(FakeSocket())   # EOF
        assert c.stop_output_dump() is None

    def test_stop_output_dump_not_active_still_returns_ok(self):
        payload = {
            "ok": True, "was_active": False,
            "frames_written": 0, "frames_dropped": 0,
        }
        c = _client(FakeSocket((json.dumps(payload) + "\n").encode()))
        result = c.stop_output_dump()
        assert result is not None
        assert result["ok"] is True
        assert result["was_active"] is False


# ---------------------------------------------------------------------------
# Source-inspection: activity gate wiring
# ---------------------------------------------------------------------------

class TestActivityGateSourceInspection:
    """The gate is configured, fed and reset in the places the audio loop needs."""

    @pytest.fixture(scope="class")
    def io_src(self):
        p = REPO_ROOT / "core" / "monitor" / "autostream_monitor_io.cpp"
        if not p.exists():
            pytest.skip(f"autostream_monitor_io.cpp not found at {p}")
        return _read_source(p)

    @staticmethod
    def _squash(src):
        return " ".join(src.split())

    def test_configure_resolves_gate_from_input_type(self, io_src):
        assert "input_type_activity_gated(cfg.input_type)" in io_src, (
            "configure() does not resolve the gate flag from cfg.input_type"
        )

    def test_gate_is_fed_in_one_place(self, io_src):
        n = io_src.count("_activity_gate.on_block(")
        assert n == 1, f"expected one _activity_gate.on_block( call, found {n}"

    def test_capture_rate_copied_once_in_start(self, io_src):
        needle = "_capture_rate_hz = _alsa.actual_rate();"
        assert io_src.count(needle) == 1, "capture rate must be copied exactly once"
        pos = io_src.index(needle)
        start = io_src.index("bool InputChannel::start(")
        stop = io_src.index("void InputChannel::stop()")
        assert start < pos < stop, "capture rate must be copied inside start()"

    def test_update_silence_state_has_no_alsa_or_logging(self, io_src):
        head = "bool InputChannel::update_silence_state("
        begin = io_src.index(head)
        end = io_src.index("\n// ──", begin)
        body = io_src[begin:end]
        assert "_alsa." not in body, "update_silence_state must not call into ALSA"
        assert "LOG_" not in body, "update_silence_state must not log"

    def test_gate_reset_count(self, io_src):
        n = io_src.count("_activity_gate.reset()")
        assert n == 3, f"expected 3 _activity_gate.reset() calls, found {n}"

    def test_probation_feed_uses_raw_comparison(self, io_src):
        flat = self._squash(io_src)
        assert ("_repeat_controller.notify_probation_block( _index, "
                "peak_sample >= silence_threshold_sample, now);") in flat, (
            "probation feed no longer receives the raw comparison"
        )

    def test_track_gap_detector_uses_raw_flag(self, io_src):
        flat = self._squash(io_src)
        assert "bool raw_above = (peak_sample >= silence_threshold_sample);" in flat, (
            "raw_above is no longer the raw comparison"
        )
        assert "_track_gap_detector.update(_capturing.load(), raw_above, now," in flat, (
            "track-gap detector no longer receives raw_above"
        )


# ---------------------------------------------------------------------------
# Source-inspection: capture loop ordering
# ---------------------------------------------------------------------------

class TestCaptureLoopSourceInspection:
    """The rate estimator counts every period the hardware delivered."""

    @pytest.fixture(scope="class")
    def capture_loop(self):
        p = REPO_ROOT / "core" / "monitor" / "autostream_monitor_io.cpp"
        if not p.exists():
            pytest.skip(f"autostream_monitor_io.cpp not found at {p}")
        src = _read_source(p)
        begin = src.index("void InputChannel::capture_thread_func()")
        end = src.index("void InputChannel::process_thread_func()")
        return src[begin:end]

    def test_rate_estimator_fed_once(self, capture_loop):
        n = capture_loop.count("_rate_estimator.feed(")
        assert n == 1, f"expected one _rate_estimator.feed( call, found {n}"

    def test_feed_precedes_ring_full_check(self, capture_loop):
        feed = capture_loop.index("_rate_estimator.feed(")
        overrun = capture_loop.index("_capture_overruns.fetch_add")
        full = capture_loop.index("_ring_buf.write_available()")
        assert overrun < feed < full, (
            "the rate estimator must be fed after the xrun skip and before "
            "the ring-full drop, so dropped periods are still counted"
        )

    def test_xrun_marks_the_rate_window(self, capture_loop):
        assert capture_loop.count("_rate_estimator.mark_capture_loss()") == 1
        overrun = capture_loop.index("_capture_overruns.fetch_add")
        mark = capture_loop.index("_rate_estimator.mark_capture_loss()")
        feed = capture_loop.index("_rate_estimator.feed(")
        assert overrun < mark < feed, (
            "an xrun must mark the rate estimator's window before the next "
            "period can be fed"
        )


class TestRateMatchingPlumbingSourceInspection:
    """The per-input rate matching option reaches the estimator, and the
    rate it reached is remembered across stop and start."""

    @pytest.fixture(scope="class")
    def io_src(self):
        p = REPO_ROOT / "core" / "monitor" / "autostream_monitor_io.cpp"
        if not p.exists():
            pytest.skip(f"autostream_monitor_io.cpp not found at {p}")
        return _read_source(p)

    @staticmethod
    def _span(src, begin_marker, end_marker):
        begin = src.index(begin_marker)
        return src[begin:src.index(end_marker, begin)]

    def test_configure_stores_the_option_in_the_estimator(self, io_src):
        body = self._span(io_src, "bool InputChannel::configure(",
                          "void InputChannel::set_eq(")
        assert body.count(
            "_rate_estimator.set_dynamic_rate_matching(cfg.dynamic_rate_matching);") == 1

    def test_start_seeds_the_estimator_once_from_the_remembered_rate(self, io_src):
        body = self._span(io_src, "bool InputChannel::start(",
                          "void InputChannel::stop()")
        assert body.count("_rate_estimator.reset(") == 1
        assert ("_rate_estimator.reset(_capture_rate_hz, "
                "AudioMonitor::output_rate_hz(), seed_rate, _index);") in body
        assert body.index("_capture_rate_hz = _alsa.actual_rate();") < \
            body.index("_rate_estimator.reset(")
        assert "_remembered_rate_hz" in body and "_remembered_device" in body
        assert "cfg.dynamic_rate_matching && remembered_rate > 0" in body
        assert "remembered_device == cfg.alsa_device" in body

    def test_stop_remembers_the_nominal_after_the_join(self, io_src):
        body = self._span(io_src, "void InputChannel::stop()",
                          "void InputChannel::set_allow_capture(")
        join = body.index("_process_thr.join();")
        read = body.index("_rate_estimator.nominal_rate()")
        assert join < read
        assert "_remembered_rate_hz = nominal;" in body
        assert "_remembered_device  = _opened_device;" in body

    def test_start_records_the_device_it_opened(self, io_src):
        body = self._span(io_src, "bool InputChannel::start(",
                          "void InputChannel::stop()")
        assert body.count("_opened_device = cfg.alsa_device;") == 1
        assert body.count("_capture_rate_hz = _alsa.actual_rate();") == 1

    def test_capture_thread_does_not_touch_the_memory(self, io_src):
        body = self._span(io_src, "void InputChannel::capture_thread_func()",
                          "void InputChannel::process_thread_func()")
        assert "_remembered" not in body
        assert "nominal_rate()" not in body


RATE_STATUS_KEYS = (
    "negotiated_hz",
    "rate_lock",
    "relock_count",
    "rate_mismatch_hz",
    "dynamic_rate_matching",
)


class TestRateStatusSourceInspection:
    """Each input's status reports the rate lock, from the right place."""

    @pytest.fixture(scope="class")
    def io_src(self):
        p = REPO_ROOT / "core" / "monitor" / "autostream_monitor_io.cpp"
        if not p.exists():
            pytest.skip(f"autostream_monitor_io.cpp not found at {p}")
        return _read_source(p)

    @pytest.fixture(scope="class")
    def mon_src(self):
        p = REPO_ROOT / "core" / "monitor" / "autostream_monitor.cpp"
        if not p.exists():
            pytest.skip(f"autostream_monitor.cpp not found at {p}")
        return _read_source(p)

    @staticmethod
    def _span(src, begin_marker, end_marker):
        begin = src.index(begin_marker)
        return src[begin:src.index(end_marker, begin)]

    def test_json_carries_the_keys_after_detected_hz(self, mon_src):
        body = self._span(mon_src, "std::string AudioMonitor::api_get_status()",
                          "// ── Validation helpers")
        positions = [body.index(f'\\"{key}\\":') for key in RATE_STATUS_KEYS]
        assert positions == sorted(positions)
        assert body.index('\\"detected_hz\\":') < positions[0]
        assert positions[-1] < body.index('\\"raw_peak_dbfs\\":')

    def test_lock_state_is_named_in_the_json(self, mon_src):
        for name in ("acquiring", "locked", "mismatch"):
            assert f'return "{name}";' in mon_src

    def test_start_records_the_negotiated_rate(self, io_src):
        body = self._span(io_src, "bool InputChannel::start(",
                          "void InputChannel::stop()")
        assert body.count("_status.negotiated_hz = _capture_rate_hz;") == 1
        assert body.index("_rate_estimator.reset(") < \
            body.index("_status.negotiated_hz = _capture_rate_hz;") < \
            body.index("_started.store(true);")

    def test_stop_clears_the_negotiated_rate(self, io_src):
        body = self._span(io_src, "void InputChannel::stop()",
                          "void InputChannel::set_allow_capture(")
        assert "_status.negotiated_hz   = 0;" in body

    def test_get_status_reads_only_the_atomic_accessors(self, io_src):
        body = self._span(io_src, "InputChannelStatus InputChannel::get_status() const",
                          "float InputChannel::compute_peak_sample(")
        for accessor in ("lock_state()", "mismatch_rate()", "relock_count()",
                         "dynamic_rate_matching()"):
            assert f"_rate_estimator.{accessor}" in body
        assert "nominal_rate()" not in body
        assert "negotiated_rate()" not in body
        assert "if (s.is_started)" in body

    def test_process_thread_snapshot_is_not_widened(self, io_src):
        body = self._span(io_src, "void InputChannel::process_thread_func()",
                          "// ── InputChannel::close_elapsed_vu_bins")
        for key in ("rate_lock", "rate_mismatch_hz", "relock_count",
                    "negotiated_hz"):
            assert key not in body

    def test_api_doc_describes_the_fields(self):
        text = _read_source(REPO_ROOT / "docs" / "AUTOSTREAM-MONITOR-API.md")
        for key in RATE_STATUS_KEYS:
            assert f"- `{key}`" in text, f"the API doc does not describe {key}"
            assert f'"{key}":' in text, f"the API doc has no example of {key}"


# ---------------------------------------------------------------------------
# C++ build suite (Linux with g++ only)
# ---------------------------------------------------------------------------

linux_only = pytest.mark.skipif(
    sys.platform != "linux",
    reason="C++ build tests require Linux",
)

gpp_available = pytest.mark.skipif(
    shutil.which("g++") is None,
    reason="g++ not in PATH — install build-essential",
)


def _gpp_ok() -> bool:
    return shutil.which("g++") is not None


def _lib_ok(lib: str) -> bool:
    """Return True if a pkg-config report is available for *lib*."""
    if shutil.which("pkg-config") is None:
        return False
    return subprocess.run(
        ["pkg-config", "--exists", lib], capture_output=True
    ).returncode == 0


def _compile_and_run(
    src_files: list[str],
    extra_flags: list[str],
    binary_name: str,
    extra_args: list[str] | None = None,
) -> tuple[bool, str]:
    """Compile *src_files* and run the resulting binary.

    Returns (success, output_or_error_text).
    """
    with tempfile.TemporaryDirectory(prefix="autostream_test_") as tmp:
        binary = Path(tmp) / binary_name
        compile_cmd = [
            "g++", "-std=c++17", "-O2",
            f"-I{REPO_ROOT / 'core' / 'monitor'}",
            *src_files,
            *extra_flags,
            "-o", str(binary),
        ]
        result = subprocess.run(
            compile_cmd,
            capture_output=True, text=True,
            cwd=str(REPO_ROOT),
            timeout=60,
        )
        if result.returncode != 0:
            return False, f"compile error:\n{result.stderr}"

        run_cmd = [str(binary)] + (extra_args or [])
        result = subprocess.run(
            run_cmd,
            capture_output=True, text=True,
            cwd=str(REPO_ROOT),
            timeout=30,
        )
        output = result.stdout + result.stderr
        return result.returncode == 0, output


@linux_only
@gpp_available
class TestCppTrackGapDetector:
    """Compile and run test_track_gap_detector.cpp (header-only, no extra libs)."""

    def test_compile_and_run(self):
        ok, output = _compile_and_run(
            src_files=["core/monitor/tests/test_track_gap_detector.cpp"],
            extra_flags=[],
            binary_name="test_track_gap_detector",
        )
        assert ok, f"test_track_gap_detector failed:\n{output}"


@linux_only
@gpp_available
class TestCppInputActivity:
    """Compile and run test_input_activity.cpp (header-only, no extra libs)."""

    def test_compile_and_run(self):
        ok, output = _compile_and_run(
            src_files=["core/monitor/tests/test_input_activity.cpp"],
            extra_flags=[],
            binary_name="test_input_activity",
        )
        assert ok, f"test_input_activity failed:\n{output}"


@linux_only
@gpp_available
class TestCppControlProtocol:
    """Compile and run test_control_protocol.cpp (no ALSA/libsamplerate needed)."""

    def test_compile_and_run(self):
        ok, output = _compile_and_run(
            src_files=["core/monitor/tests/test_control_protocol.cpp"],
            extra_flags=[],
            binary_name="test_control_protocol",
        )
        assert ok, f"test_control_protocol failed:\n{output}"
        assert "FAIL" not in output.upper().split("OK")[0] if "OK" in output else True


@linux_only
@gpp_available
@pytest.mark.skipif(
    not _lib_ok("samplerate"),
    reason="libsamplerate dev headers not installed (apt-get install libsamplerate0-dev)",
)
class TestCppMonitorUtils:
    """Compile and run test_monitor_utils.cpp (requires -lpthread and
    libsamplerate, since autostream_monitor_utils.h includes <samplerate.h>)."""

    def test_compile_and_run(self):
        ok, output = _compile_and_run(
            src_files=[
                "core/monitor/tests/test_monitor_utils.cpp",
                "core/monitor/autostream_monitor_utils.cpp",
            ],
            extra_flags=["-lpthread"],
            binary_name="test_monitor_utils",
        )
        assert ok, f"test_monitor_utils failed:\n{output}"


@linux_only
@gpp_available
@pytest.mark.skipif(
    not _lib_ok("alsa"),
    reason="ALSA dev headers not installed (apt-get install libasound2-dev)",
)
@pytest.mark.skipif(
    not _lib_ok("samplerate"),
    reason="libsamplerate dev headers not installed (apt-get install libsamplerate0-dev)",
)
class TestCppMonitorDsp:
    """Compile and run test_monitor_dsp.cpp (requires ALSA + libsamplerate)."""

    def test_compile_and_run(self):
        ok, output = _compile_and_run(
            src_files=[
                "core/monitor/tests/test_monitor_dsp.cpp",
                "core/monitor/autostream_monitor_dsp.cpp",
                "core/monitor/autostream_monitor_utils.cpp",
            ],
            extra_flags=["-lpthread", "-lasound", "-lsamplerate", "-latomic"],
            binary_name="test_monitor_dsp",
        )
        assert ok, f"test_monitor_dsp failed:\n{output}"
