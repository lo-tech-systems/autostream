"""tests/test_align_endpoints.py

Endpoint tests for the "Align outputs" feature (autostream_webui_page_align.py
+ the /api/align/* routes wired into autostream_webui.py).

Tests cover:
  - POST /api/align/start: success shape, refusal passthrough
  - POST /api/align/abort: calls AlignRun.abort()
  - GET  /api/align/status: returns AlignRun.status() verbatim
  - GET  /align/result: parses v/ref/data, calls AlignRun.finish() with the
    parsed result; malformed handoffs still stop the run (finish(None))
  - Review table math: proposed offset = current_stored_offset - delta_ms,
    clamped to [-2000, 2000]; noisy-spread warning
  - POST /api/align/apply: applies each offset via the same clamp/store/push
    path as send_owntone_output_offset_json, discards the pending result
  - CSRF is required on all POST /api/align/* routes (router-level)
"""
from __future__ import annotations

import io
import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_settings import SettingsStore
from autostream_align import AlignArrival, AlignOutputSnapshot, AlignResult


# ── Fixtures (mirrors tests/test_wp7_owntone_autosave.py conventions) ──────

def _make_config(tmp_path: str, extra: dict | None = None) -> str:
    cfg: dict = {
        "owntone": {"base_url": "http://localhost:3689", "output_name": "", "volume_percent": 20},
        "webui": {"hidden_outputs": []},
        "general": {},
    }
    if extra:
        for k, v in extra.items():
            cfg.setdefault(k, {}).update(v)
    path = os.path.join(tmp_path, "config.json")
    with open(path, "w") as f:
        json.dump(cfg, f)
    return path


def _make_state_file(tmp_path: str) -> str:
    path = os.path.join(tmp_path, "state.json")
    with open(path, "w") as f:
        json.dump({"owntone": {"known_outputs": {}}}, f)
    return path


def _make_store(config_path: str) -> SettingsStore:
    return SettingsStore(config_path, _save_interval_seconds=9999, _writer=MagicMock())


def _make_state(config_path: str, state_path: str, store: SettingsStore, align_run=None) -> MagicMock:
    state = MagicMock()
    state.config_path = config_path
    state.state_path = state_path
    state.settings = store
    state.align_run = align_run
    return state


def _json_or_raw(data: bytes):
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return data.decode("utf-8", "replace")


def _make_handler():
    handler = MagicMock()
    sent: dict = {}
    handler.send_response.side_effect = lambda code: sent.update({"code": code})
    handler.wfile = MagicMock()
    handler.wfile.write.side_effect = lambda data: sent.update({"body": _json_or_raw(data)})
    handler.end_headers = MagicMock()
    handler.send_header = MagicMock()
    handler.headers = {}
    handler._csrf_token = "tok"
    return handler, sent


# ── POST /api/align/start ───────────────────────────────────────────────────

class TestAlignStart:
    def test_success_returns_launch_url(self, tmp_path):
        from autostream_webui_page_align import send_align_start_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        align_run = MagicMock()
        align_run.start.return_value = (True, "https://lo-tech.co.uk/as-api/autoalign/#v=1&...")
        state = _make_state(config_path, state_path, store, align_run=align_run)
        handler, sent = _make_handler()
        handler.headers = {"Host": "autostream.local"}

        send_align_start_json(handler, state)

        assert sent["body"]["ok"] is True
        assert sent["body"]["launch_url"].startswith("https://lo-tech.co.uk/")
        kwargs = align_run.start.call_args.kwargs
        assert kwargs["base_url"] == "http://localhost:3689"
        assert kwargs["ret_url"] == "http://autostream.local/align/result"

    def test_refusal_passthrough(self, tmp_path):
        from autostream_webui_page_align import send_align_start_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        align_run = MagicMock()
        align_run.start.return_value = (False, "Select at least two outputs before calibrating")
        state = _make_state(config_path, state_path, store, align_run=align_run)
        handler, sent = _make_handler()
        handler.headers = {"Host": "autostream.local"}

        send_align_start_json(handler, state)

        assert sent["body"]["ok"] is False
        assert "two outputs" in sent["body"]["error"]

    def test_no_align_run_on_state_is_unavailable(self, tmp_path):
        from autostream_webui_page_align import send_align_start_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store, align_run=None)
        handler, sent = _make_handler()
        handler.headers = {"Host": "autostream.local"}

        send_align_start_json(handler, state)

        assert sent["body"]["ok"] is False


# ── POST /api/align/abort ────────────────────────────────────────────────────

def test_abort_calls_run_abort(tmp_path):
    from autostream_webui_page_align import send_align_abort_json
    config_path = _make_config(str(tmp_path))
    state_path = _make_state_file(str(tmp_path))
    store = _make_store(config_path)
    align_run = MagicMock()
    state = _make_state(config_path, state_path, store, align_run=align_run)
    handler, sent = _make_handler()

    send_align_abort_json(handler, state)

    align_run.abort.assert_called_once()
    assert sent["body"]["ok"] is True


# ── GET /api/align/status ────────────────────────────────────────────────────

def test_status_returns_run_status_verbatim(tmp_path):
    from autostream_webui_page_align import send_align_status_json
    config_path = _make_config(str(tmp_path))
    state_path = _make_state_file(str(tmp_path))
    store = _make_store(config_path)
    align_run = MagicMock()
    align_run.status.return_value = {
        "state": "running", "current_output_id": "a", "current_output_name": "A",
        "cycle_count": 2, "seconds_remaining": 300, "launch_url": "https://x",
        "last_error": "", "has_pending_result": False,
    }
    state = _make_state(config_path, state_path, store, align_run=align_run)
    handler, sent = _make_handler()

    send_align_status_json(handler, state)

    assert sent["body"] == align_run.status.return_value


def test_status_default_shape_when_no_align_run(tmp_path):
    from autostream_webui_page_align import send_align_status_json
    config_path = _make_config(str(tmp_path))
    state_path = _make_state_file(str(tmp_path))
    store = _make_store(config_path)
    state = _make_state(config_path, state_path, store, align_run=None)
    handler, sent = _make_handler()

    send_align_status_json(handler, state)

    assert sent["body"]["state"] == "idle"


# ── GET /align/result ────────────────────────────────────────────────────────

class TestAlignResultGet:
    def test_valid_handoff_calls_finish_with_parsed_result(self, tmp_path):
        from autostream_webui_page_align import send_align_result_get
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        align_run = MagicMock()
        align_run.snapshots.return_value = []
        align_run.pending_result.return_value = None
        state = _make_state(config_path, state_path, store, align_run=align_run)
        handler, sent = _make_handler()
        handler.headers = {}

        query = {"v": ["1"], "ref": ["out-a"], "data": ["out-b~12~3,out-c~-5~2"]}
        send_align_result_get(handler, state, query)

        align_run.finish.assert_called_once()
        result = align_run.finish.call_args.args[0]
        assert isinstance(result, AlignResult)
        assert result.ref_output_id == "out-a"
        assert result.arrivals == (AlignArrival("out-b", 12, 3), AlignArrival("out-c", -5, 2))
        assert sent["code"] == 200  # renders the /align page, not a redirect

    def test_malformed_entries_dropped_without_failing_whole_parse(self, tmp_path):
        from autostream_webui_page_align import send_align_result_get
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        align_run = MagicMock()
        align_run.snapshots.return_value = []
        align_run.pending_result.return_value = None
        state = _make_state(config_path, state_path, store, align_run=align_run)
        handler, sent = _make_handler()
        handler.headers = {}

        query = {"v": ["1"], "ref": ["out-a"], "data": ["out-b~12~3,garbage,out-c~notanint~5"]}
        send_align_result_get(handler, state, query)

        result = align_run.finish.call_args.args[0]
        assert result.arrivals == (AlignArrival("out-b", 12, 3),)

    def test_missing_ref_still_stops_run_without_result(self, tmp_path):
        from autostream_webui_page_align import send_align_result_get
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        align_run = MagicMock()
        align_run.snapshots.return_value = []
        align_run.pending_result.return_value = None
        state = _make_state(config_path, state_path, store, align_run=align_run)
        handler, sent = _make_handler()
        handler.headers = {}

        query = {"v": ["1"], "data": ["out-b~12~3"]}
        send_align_result_get(handler, state, query)

        align_run.finish.assert_called_once_with(None)

    def test_wrong_version_still_stops_run_without_result(self, tmp_path):
        from autostream_webui_page_align import send_align_result_get
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        align_run = MagicMock()
        align_run.snapshots.return_value = []
        align_run.pending_result.return_value = None
        state = _make_state(config_path, state_path, store, align_run=align_run)
        handler, sent = _make_handler()
        handler.headers = {}

        query = {"v": ["2"], "ref": ["out-a"], "data": ["out-b~12~3"]}
        send_align_result_get(handler, state, query)

        align_run.finish.assert_called_once_with(None)


# ── Review table math ────────────────────────────────────────────────────────

class TestReviewSection:
    def test_proposed_offset_is_stored_minus_delta_clamped(self, tmp_path):
        from autostream_webui_page_align import _render_review_section
        align_run = MagicMock()
        align_run.snapshots.return_value = [
            AlignOutputSnapshot(id="out-a", name="A", volume_percent=30, stored_offset_ms=100, freq_hz=1000),
            AlignOutputSnapshot(id="out-b", name="B", volume_percent=30, stored_offset_ms=-1900, freq_hz=1250),
        ]
        align_run.pending_result.return_value = AlignResult(
            ref_output_id="out-a",
            arrivals=(AlignArrival("out-b", -400, 5),),
        )
        state = MagicMock(align_run=align_run)

        html_out = _render_review_section(state)

        # out-a is the ref: proposed = 100 - 0 = 100
        assert ">100 ms<" in html_out
        # out-b: proposed = -1900 - (-400) = -1500, within [-2000, 2000]
        assert ">-1500 ms<" in html_out

    def test_proposed_offset_clamped_to_2000(self, tmp_path):
        from autostream_webui_page_align import _render_review_section
        align_run = MagicMock()
        align_run.snapshots.return_value = [
            AlignOutputSnapshot(id="out-a", name="A", volume_percent=30, stored_offset_ms=1900, freq_hz=1000),
            AlignOutputSnapshot(id="out-b", name="B", volume_percent=30, stored_offset_ms=1900, freq_hz=1250),
        ]
        align_run.pending_result.return_value = AlignResult(
            ref_output_id="out-a",
            arrivals=(AlignArrival("out-b", -500, 5),),
        )
        state = MagicMock(align_run=align_run)

        html_out = _render_review_section(state)

        # proposed = 1900 - (-500) = 2400 -> clamped to 2000
        assert ">2000 ms<" in html_out

    def test_noisy_spread_warns_but_still_shows(self, tmp_path):
        from autostream_webui_page_align import _render_review_section
        align_run = MagicMock()
        align_run.snapshots.return_value = [
            AlignOutputSnapshot(id="out-a", name="A", volume_percent=30, stored_offset_ms=0, freq_hz=1000),
            AlignOutputSnapshot(id="out-b", name="B", volume_percent=30, stored_offset_ms=0, freq_hz=1250),
        ]
        align_run.pending_result.return_value = AlignResult(
            ref_output_id="out-a",
            arrivals=(AlignArrival("out-b", 10, 55),),
        )
        state = MagicMock(align_run=align_run)

        html_out = _render_review_section(state)

        assert "noisy" in html_out
        assert "align-warn" in html_out

    def test_no_pending_result_renders_nothing(self):
        from autostream_webui_page_align import _render_review_section
        align_run = MagicMock()
        align_run.pending_result.return_value = None
        state = MagicMock(align_run=align_run)
        assert _render_review_section(state) == ""


# ── POST /api/align/apply ────────────────────────────────────────────────────

class TestAlignApply:
    def test_applies_offsets_via_shared_clamp_store_push_path(self, tmp_path):
        from autostream_webui_page_align import send_align_apply_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        align_run = MagicMock()
        state = _make_state(config_path, state_path, store, align_run=align_run)
        handler, sent = _make_handler()

        body = json.dumps({"offsets": {"out-a": 100, "out-b": 9999}})
        with patch("autostream_webui_api.update_live_owntone_runtime"):
            send_align_apply_json(handler, state, body)

        assert sent["body"]["ok"] is True
        assert sent["body"]["applied"] == {"out-a": 100, "out-b": 2000}  # clamped
        snap = store.snapshot()
        assert snap.owntone.output_offsets_ms.get("out-a") == 100
        assert snap.owntone.output_offsets_ms.get("out-b") == 2000
        align_run.discard_result.assert_called_once()

    def test_missing_offsets_returns_400(self, tmp_path):
        from autostream_webui_page_align import send_align_apply_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store, align_run=MagicMock())
        handler, sent = _make_handler()

        send_align_apply_json(handler, state, json.dumps({}))

        assert sent["code"] == 400

    def test_invalid_json_returns_400(self, tmp_path):
        from autostream_webui_page_align import send_align_apply_json
        config_path = _make_config(str(tmp_path))
        state_path = _make_state_file(str(tmp_path))
        store = _make_store(config_path)
        state = _make_state(config_path, state_path, store, align_run=MagicMock())
        handler, sent = _make_handler()

        send_align_apply_json(handler, state, "{not json")

        assert sent["code"] == 400


# ── POST /api/align/discard ──────────────────────────────────────────────────

def test_discard_calls_run_discard_result(tmp_path):
    from autostream_webui_page_align import send_align_discard_json
    config_path = _make_config(str(tmp_path))
    state_path = _make_state_file(str(tmp_path))
    store = _make_store(config_path)
    align_run = MagicMock()
    state = _make_state(config_path, state_path, store, align_run=align_run)
    handler, sent = _make_handler()

    send_align_discard_json(handler, state)

    align_run.discard_result.assert_called_once()
    assert sent["body"]["ok"] is True


# ── Router-level CSRF enforcement ────────────────────────────────────────────

try:
    from autostream_webui import ConfigWebHandler
    _HAS_WEBUI = True
except ImportError:
    _HAS_WEBUI = False

from autostream_auth import AuthManager, PIN_STATUS_MISSING

_skip_no_webui = pytest.mark.skipif(
    not _HAS_WEBUI, reason="autostream_webui import chain unavailable"
)


def _make_manager_no_pin() -> AuthManager:
    mgr = AuthManager(config_path="dummy.ini")
    mgr._pin_loaded = True
    mgr._pin_value = None
    mgr._pin_status = PIN_STATUS_MISSING
    return mgr


def _make_post_handler(path: str, csrf_token: Optional[str]) -> "ConfigWebHandler":
    body = b"{}"
    h = ConfigWebHandler.__new__(ConfigWebHandler)
    h.path = path
    h.command = "POST"
    h.request_version = "HTTP/1.1"
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        "X-Forwarded-For": "",
        "X-Real-IP": "",
        "Host": "autostream.local",
    }
    if csrf_token is not None:
        headers["X-CSRF-Token"] = csrf_token
    h.headers = headers
    h.client_address = ("127.0.0.1", 0)
    h.rfile = io.BytesIO(body)
    h.wfile = io.BytesIO()
    h.send_response = MagicMock()
    h.send_header = MagicMock()
    h.end_headers = MagicMock()
    h.send_error = MagicMock()
    h._pending_auth_cookie = None
    h._pending_set_cookies = []
    return h


@_skip_no_webui
@pytest.mark.parametrize("path,stub_target", [
    ("/api/align/start", "autostream_webui.send_align_start_json"),
    ("/api/align/abort", "autostream_webui.send_align_abort_json"),
    ("/api/align/apply", "autostream_webui.send_align_apply_json"),
    ("/api/align/discard", "autostream_webui.send_align_discard_json"),
])
def test_align_post_routes_require_csrf(path, stub_target):
    """No PIN configured (so PIN gate doesn't interfere), no CSRF token
    present -> the CSRF check must reject before the handler runs."""
    mgr = _make_manager_no_pin()
    handler = _make_post_handler(path, csrf_token=None)

    with patch("autostream_webui.AUTH", mgr), \
         patch("autostream_webui.STATE", MagicMock()), \
         patch("autostream_webui.is_commissioning_required", return_value=False), \
         patch(stub_target) as stub:
        handler.do_POST()

    stub.assert_not_called()
