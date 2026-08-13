"""tests/test_update_apply_async.py

Coverage for the async accept-then-poll contract of POST /api/update/apply:

  - the request thread returns {ok, accepted} immediately without waiting
    for run_updater("apply") to finish
  - a second POST while an apply is in flight returns already_in_progress
    without starting a second run_updater call
  - the in-flight guard clears once the background apply finishes, allowing
    a subsequent apply
  - a background failure (non-zero rc, ok:false JSON, exception, or timeout)
    is logged only. update-result.env is root-owned; autostream_updater
    (running as root) is the sole writer of it for the pre-installer
    phases, so this process must never touch the file itself.
"""
from __future__ import annotations

import logging
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

try:
    import autostream_webui as webui
    from autostream_webui import ConfigWebHandler
    _HAS_WEBUI = True
except ImportError:
    _HAS_WEBUI = False

_skip_no_webui = pytest.mark.skipif(
    not _HAS_WEBUI, reason="autostream_webui import chain unavailable"
)


@pytest.fixture(autouse=True)
def _clean_guard():
    """Reset the module-level in-flight guard before and after each test."""
    if _HAS_WEBUI:
        with webui._update_apply_lock:
            webui._update_apply_in_progress = False
    yield
    if _HAS_WEBUI:
        with webui._update_apply_lock:
            webui._update_apply_in_progress = False


def _handler() -> "ConfigWebHandler":
    return ConfigWebHandler.__new__(ConfigWebHandler)


def _wait_until_idle(timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with webui._update_apply_lock:
            if not webui._update_apply_in_progress:
                return
        time.sleep(0.02)
    raise AssertionError("background apply did not clear the in-flight guard in time")


@_skip_no_webui
class TestStartUpdateApplyAccepts:
    def test_response_sent_before_updater_returns(self):
        """The handler must respond before run_updater("apply") completes."""
        release_event = threading.Event()
        started_event = threading.Event()

        def blocking_run_updater(args, timeout=180):
            started_event.set()
            assert release_event.wait(5), "test did not release the updater in time"
            return (0, '{"ok": true, "staged_tag": "9.9.9"}', "")

        sent = {}

        def fake_send_json(handler, code, payload):
            sent["code"] = code
            sent["payload"] = payload

        h = _handler()
        with patch.object(webui, "run_updater", side_effect=blocking_run_updater), \
             patch.object(webui, "send_json", side_effect=fake_send_json):
            h._start_update_apply()

            # The response must already be sent even though run_updater is
            # still blocked inside the background thread.
            assert sent.get("payload") == {"ok": True, "accepted": True}
            assert started_event.wait(2), "background thread never called run_updater"

            release_event.set()
            _wait_until_idle()

    def test_in_flight_guard_blocks_second_apply(self):
        """A second POST while an apply is running returns already_in_progress
        and does not start a second run_updater call."""
        release_event = threading.Event()

        def blocking_run_updater(args, timeout=180):
            release_event.wait(5)
            return (0, "{}", "")

        sent = []

        def fake_send_json(handler, code, payload):
            sent.append(payload)

        h1, h2 = _handler(), _handler()
        with patch.object(webui, "run_updater", side_effect=blocking_run_updater) as mock_run, \
             patch.object(webui, "send_json", side_effect=fake_send_json):
            h1._start_update_apply()
            h2._start_update_apply()
            release_event.set()
            _wait_until_idle()

        assert sent[0] == {"ok": True, "accepted": True}
        assert sent[1] == {"ok": True, "accepted": True, "already_in_progress": True}
        assert mock_run.call_count == 1

    def test_guard_clears_after_completion_allows_next_apply(self):
        """Once a background apply finishes, a subsequent apply is accepted
        and actually starts run_updater again."""
        sent = []

        def fake_send_json(handler, code, payload):
            sent.append(payload)

        h1 = _handler()
        with patch.object(webui, "run_updater", return_value=(0, "{}", "")) as mock_run1, \
             patch.object(webui, "send_json", side_effect=fake_send_json):
            h1._start_update_apply()
            _wait_until_idle()
        assert mock_run1.call_count == 1

        h2 = _handler()
        with patch.object(webui, "run_updater", return_value=(0, "{}", "")) as mock_run2, \
             patch.object(webui, "send_json", side_effect=fake_send_json):
            h2._start_update_apply()
            _wait_until_idle()

        assert mock_run2.call_count == 1
        assert "already_in_progress" not in sent[0]
        assert "already_in_progress" not in sent[-1]


@_skip_no_webui
class TestBackgroundApplyFailureLogging:
    """_run_update_apply_background must never write update-result.env itself.

    The file is root-owned; autostream_updater (invoked as root via sudo) is
    now the sole writer of it for every phase before the installer takes
    over, including its own failure states. This process can only log what
    it observed.
    """

    def test_nonzero_rc_logs_and_leaves_result_file_untouched(self, tmp_path, caplog):
        result_file = tmp_path / "update-result.env"
        with patch.object(webui, "_UPDATE_RESULT_FILE", result_file), \
             patch.object(webui, "run_updater",
                           return_value=(1, '{"error": "staging failed"}', "boom")), \
             caplog.at_level(logging.ERROR):
            webui._run_update_apply_background()

        assert webui._update_apply_in_progress is False
        assert not result_file.exists()
        assert "staging failed" in caplog.text

    def test_ok_false_json_logs_and_leaves_result_file_untouched(self, tmp_path, caplog):
        result_file = tmp_path / "update-result.env"
        with patch.object(webui, "_UPDATE_RESULT_FILE", result_file), \
             patch.object(webui, "run_updater",
                           return_value=(0, '{"ok": false, "error": "no release"}', "")), \
             caplog.at_level(logging.ERROR):
            webui._run_update_apply_background()

        assert not result_file.exists()
        assert "no release" in caplog.text

    def test_exception_logs_and_leaves_result_file_untouched(self, tmp_path, caplog):
        result_file = tmp_path / "update-result.env"
        with patch.object(webui, "_UPDATE_RESULT_FILE", result_file), \
             patch.object(webui, "run_updater", side_effect=OSError("sudo not found")), \
             caplog.at_level(logging.ERROR):
            webui._run_update_apply_background()

        assert not result_file.exists()
        assert "sudo not found" in caplog.text

    def test_timeout_logs_and_leaves_result_file_untouched(self, tmp_path, caplog):
        import subprocess
        result_file = tmp_path / "update-result.env"
        with patch.object(webui, "_UPDATE_RESULT_FILE", result_file), \
             patch.object(webui, "run_updater",
                           side_effect=subprocess.TimeoutExpired(cmd="autostream_updater", timeout=180)), \
             caplog.at_level(logging.ERROR):
            webui._run_update_apply_background()

        # A subprocess timeout does not prove the apply failed (the sudo'd
        # child may survive and complete on its own): autostream_updater
        # owns the result file for this window, so this process must not
        # write anything of its own regardless of outcome.
        assert not result_file.exists()
        assert "timed out" in caplog.text

    def test_success_does_not_write_result_file(self, tmp_path):
        result_file = tmp_path / "update-result.env"
        with patch.object(webui, "_UPDATE_RESULT_FILE", result_file), \
             patch.object(webui, "run_updater",
                           return_value=(0, '{"ok": true, "staged_tag": "1.2.3"}', "")):
            webui._run_update_apply_background()

        assert not result_file.exists()

    def test_background_apply_always_clears_guard(self, tmp_path):
        """Even on failure the in-flight guard must clear so a retry is possible."""
        result_file = tmp_path / "update-result.env"
        with webui._update_apply_lock:
            webui._update_apply_in_progress = True
        with patch.object(webui, "_UPDATE_RESULT_FILE", result_file), \
             patch.object(webui, "run_updater", return_value=(1, "{}", "error")):
            webui._run_update_apply_background()

        assert webui._update_apply_in_progress is False
