"""Tests for the POST /api/dial/status endpoint.

Covers:
1.  Routing: dispatched in the UUID-auth block before session/CSRF.
2.  Authorization: absent, empty, non-string, unauthorized UUID → HTTP 403 {}.
3.  Malformed JSON → HTTP 400 (router's native behavior).
4.  Non-object JSON root → HTTP 403 (reaches handler as {}).
4b. Router-level: non-object JSON body does NOT trigger HTTP 400 for /api/dial/status.
5.  Valid authorized UUID → HTTP 200 with ok:true.
6.  application/json with charset parameter is accepted.
7.  selected output volumes [40, 60] → master_volume:50, selected_output_count:2.
8.  Tie cases [40, 61] and [41, 62] match Python round().
9.  No selected outputs → master_volume:null, selected_output_count:0.
10. Unselected outputs excluded from master calculation.
11. playing comes from the unified session state (live input or repeat
    replay), independent of output selection.
12. Config failure → config_error.
13. Backend exception → backend_unavailable.
14. Backend not-ok → backend_unavailable.
15. Handler never calls update_output().
16. calculate_master_volume() helper unit tests.
17. Both Avahi template and autostream_admin generate dial_status=v1.
18. NGINX policy: 403 is not in the intercepted error_page set.
"""
from __future__ import annotations

import io
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_players import ListOutputsResult, OutputInfo, ActionResult
from autostream_webui_api import (
    calculate_master_volume,
    send_dial_status_post_json,
)
from autostream_webui_state import WebUIState
from track_id.models import (
    TrackArtwork,
    TrackIdentificationSnapshot,
    disabled_snapshot,
    waiting_snapshot,
)

DIAL_ID = "test-dial-uuid-1234"
BASE_URL = "http://localhost:3689"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_handler() -> MagicMock:
    h = MagicMock()
    h.wfile = io.BytesIO()
    return h


def _response(handler: MagicMock) -> tuple[int, dict]:
    code = handler.send_response.call_args[0][0]
    body = json.loads(handler.wfile.getvalue())
    return code, body


def _output(id: str, volume: int, selected: bool = True) -> OutputInfo:
    return OutputInfo(id=id, name=id, selected=selected, volume_percent=volume)


def _ok_list(*outputs: OutputInfo) -> ListOutputsResult:
    return ListOutputsResult(ok=True, outputs=tuple(outputs))


def _fail_list(msg: str = "connection refused") -> ListOutputsResult:
    return ListOutputsResult(ok=False, error=msg)


def _invoke(
    json_obj: dict,
    *,
    authorized: bool = True,
    list_result: ListOutputsResult | None = None,
    config_error: bool = False,
    playing: bool = False,
    track_id_snapshot: TrackIdentificationSnapshot | None = None,
) -> tuple[int, dict, MagicMock]:
    """Call send_dial_status_post_json and return (status, body, update_mock)."""
    state = WebUIState(config_path="dummy.json", state_path="dummy-state.json")
    handler = _make_handler()
    if list_result is None:
        list_result = _ok_list()
    if track_id_snapshot is None:
        track_id_snapshot = disabled_snapshot()

    update_mock = MagicMock()

    parsed = MagicMock()
    parsed.owntone.base_url = BASE_URL

    def _cfg_snapshot(state):
        if config_error:
            raise OSError("disk full")
        return parsed

    with (
        patch("autostream_webui_api.is_dial_authorized", return_value=authorized),
        patch("autostream_webui_api._config_snapshot", side_effect=_cfg_snapshot),
        patch("autostream_webui_api.list_outputs", return_value=list_result),
        patch("autostream_webui_api.update_output", update_mock),
        patch("autostream_webui_api.get_session_state",
              return_value={"active": playing, "source": "input1" if playing else None}),
        patch("autostream_core.get_active_track_identification_snapshot",
              return_value=track_id_snapshot),
    ):
        send_dial_status_post_json(handler, state, json_obj)

    code, body = _response(handler)
    return code, body, update_mock


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------

class TestAuthorization:
    def test_missing_dial_id_returns_403_empty(self):
        code, body, _ = _invoke({})
        assert code == 403
        assert body == {}

    def test_empty_dial_id_returns_403_empty(self):
        code, body, _ = _invoke({"dial_id": ""})
        assert code == 403
        assert body == {}

    def test_non_string_dial_id_returns_403_empty(self):
        code, body, _ = _invoke({"dial_id": 12345})
        assert code == 403
        assert body == {}

    def test_unauthorized_dial_id_returns_403_empty(self):
        code, body, _ = _invoke({"dial_id": DIAL_ID}, authorized=False)
        assert code == 403
        assert body == {}

    def test_authorized_dial_id_returns_200_ok(self):
        code, body, _ = _invoke({"dial_id": DIAL_ID})
        assert code == 200
        assert body["ok"] is True


# ---------------------------------------------------------------------------
# Volume calculation
# ---------------------------------------------------------------------------

class TestMasterVolumeResponse:
    def test_two_outputs_returns_correct_master_and_count(self):
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID},
            list_result=_ok_list(_output("a", 40), _output("b", 60)),
        )
        assert code == 200
        assert body["ok"] is True
        assert body["master_volume"] == 50
        assert body["selected_output_count"] == 2

    def test_no_selected_outputs_returns_null(self):
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID},
            list_result=_ok_list(_output("a", 40, selected=False)),
        )
        assert code == 200
        assert body["ok"] is True
        assert body["master_volume"] is None
        assert body["selected_output_count"] == 0

    def test_unselected_outputs_excluded_from_calculation(self):
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID},
            list_result=_ok_list(
                _output("a", 60),
                _output("b", 80, selected=False),
            ),
        )
        assert code == 200
        assert body["master_volume"] == 60
        assert body["selected_output_count"] == 1

    def test_single_output_at_zero(self):
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID},
            list_result=_ok_list(_output("a", 0)),
        )
        assert code == 200
        assert body["master_volume"] == 0
        assert body["selected_output_count"] == 1


# ---------------------------------------------------------------------------
# Playing field
# ---------------------------------------------------------------------------

class TestPlayingField:
    def test_playing_true_when_session_active(self):
        code, body, _ = _invoke({"dial_id": DIAL_ID}, playing=True)
        assert body["playing"] is True

    def test_playing_false_when_session_inactive(self):
        code, body, _ = _invoke({"dial_id": DIAL_ID}, playing=False)
        assert body["playing"] is False

    def test_playing_true_during_replay_session(self):
        """A repeat-replay session counts as playing even though no monitor
        is capturing."""
        state = WebUIState(config_path="dummy.json", state_path="dummy-state.json")
        handler = _make_handler()
        parsed = MagicMock()
        parsed.owntone.base_url = BASE_URL
        with (
            patch("autostream_webui_api.is_dial_authorized", return_value=True),
            patch("autostream_webui_api._config_snapshot", return_value=parsed),
            patch("autostream_webui_api.list_outputs", return_value=_ok_list()),
            patch("autostream_webui_api.get_session_state",
                  return_value={"active": True, "source": "replay"}),
            patch("autostream_webui_api.any_monitor_capturing", return_value=False),
            patch("autostream_core.get_active_track_identification_snapshot",
                  return_value=disabled_snapshot()),
        ):
            send_dial_status_post_json(handler, state, {"dial_id": DIAL_ID})
        code, body = _response(handler)
        assert body["playing"] is True

    def test_playing_independent_of_outputs(self):
        """playing reflects session state, not output selection."""
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID},
            list_result=_ok_list(_output("a", 70)),
            playing=True,
        )
        assert body["playing"] is True


# ---------------------------------------------------------------------------
# track_id grouped object
# ---------------------------------------------------------------------------

class TestTrackIdField:
    def test_disabled_snapshot_yields_disabled_track_id(self):
        code, body, _ = _invoke({"dial_id": DIAL_ID}, track_id_snapshot=disabled_snapshot())
        assert code == 200
        assert body["track_id"] == {
            "enabled": False,
            "state": "disabled",
            "title": "",
            "artist": "",
            "album": "",
            "artwork_url": "",
            "updated_at": None,
            "last_attempt_at": None,
        }

    def test_waiting_snapshot_has_empty_artwork_url(self):
        code, body, _ = _invoke({"dial_id": DIAL_ID}, track_id_snapshot=waiting_snapshot())
        assert body["track_id"]["state"] == "waiting_for_audio"
        assert body["track_id"]["artwork_url"] == ""

    def test_identified_with_artwork_passes_through(self):
        snap = TrackIdentificationSnapshot(
            enabled=True,
            state="identified",
            status_text="Track identified",
            title="Song",
            artist="Artist",
            album="Album",
            artwork_url="https://provider.example/artwork/3f8a91c2.jpg",
            updated_at=1783170000.0,
            last_attempt_at=1783169990.0,
        )
        code, body, _ = _invoke({"dial_id": DIAL_ID}, track_id_snapshot=snap)
        assert body["track_id"] == {
            "enabled": True,
            "state": "identified",
            "title": "Song",
            "artist": "Artist",
            "album": "Album",
            "artwork_url": "https://provider.example/artwork/3f8a91c2.jpg",
            "updated_at": 1783170000.0,
            "last_attempt_at": 1783169990.0,
        }

    def test_identified_without_artwork_is_empty_string(self):
        snap = TrackIdentificationSnapshot(
            enabled=True, state="identified", status_text="Track identified",
            title="Song", artist="Artist", album="Album", artwork_url="",
        )
        code, body, _ = _invoke({"dial_id": DIAL_ID}, track_id_snapshot=snap)
        assert body["track_id"]["artwork_url"] == ""

    def test_not_found_state_has_empty_artwork_url(self):
        snap = TrackIdentificationSnapshot(
            enabled=True, state="not_found", status_text="Listening",
        )
        code, body, _ = _invoke({"dial_id": DIAL_ID}, track_id_snapshot=snap)
        assert body["track_id"]["state"] == "not_found"
        assert body["track_id"]["artwork_url"] == ""

    def test_error_state_has_empty_artwork_url(self):
        snap = TrackIdentificationSnapshot(
            enabled=True, state="error", status_text="Identification unavailable",
        )
        code, body, _ = _invoke({"dial_id": DIAL_ID}, track_id_snapshot=snap)
        assert body["track_id"]["state"] == "error"
        assert body["track_id"]["artwork_url"] == ""

    def test_non_identified_state_with_stray_artwork_url_is_scrubbed(self):
        """Defense in depth: a non-identified snapshot must never leak artwork_url."""
        snap = TrackIdentificationSnapshot(
            enabled=True, state="analysing", status_text="Analysing",
            artwork_url="https://provider.example/should-not-leak.jpg",
        )
        code, body, _ = _invoke({"dial_id": DIAL_ID}, track_id_snapshot=snap)
        assert body["track_id"]["artwork_url"] == ""

    def test_non_http_artwork_url_scrubbed_even_if_identified(self):
        snap = TrackIdentificationSnapshot(
            enabled=True, state="identified", status_text="Track identified",
            artwork_url="ftp://provider.example/x.jpg",
        )
        code, body, _ = _invoke({"dial_id": DIAL_ID}, track_id_snapshot=snap)
        assert body["track_id"]["artwork_url"] == ""

    def test_endpoint_remains_read_only_no_remote_fetch(self):
        """The handler must not touch urllib/network fetch machinery for artwork."""
        snap = TrackIdentificationSnapshot(
            enabled=True, state="identified", status_text="Track identified",
            artwork_url="https://provider.example/x.jpg",
        )
        with patch("urllib.request.urlopen") as mock_urlopen:
            code, body, _ = _invoke({"dial_id": DIAL_ID}, track_id_snapshot=snap)
        mock_urlopen.assert_not_called()
        assert body["track_id"]["artwork_url"] == "https://provider.example/x.jpg"


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------

class TestFailurePaths:
    def test_config_error_returns_config_error(self):
        state = WebUIState(config_path="dummy.json", state_path="dummy-state.json")
        handler = _make_handler()
        with (
            patch("autostream_webui_api.is_dial_authorized", return_value=True),
            patch("autostream_webui_api.get_session_state",
                  return_value={"active": False, "source": None}),
            patch("autostream_webui_api._config_snapshot",
                  side_effect=OSError("disk full")),
        ):
            send_dial_status_post_json(handler, state, {"dial_id": DIAL_ID})
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": False, "error": "config_error"}

    def test_backend_not_ok_returns_backend_unavailable(self):
        code, body, _ = _invoke(
            {"dial_id": DIAL_ID},
            list_result=_fail_list("OwnTone offline"),
        )
        assert code == 200
        assert body == {"ok": False, "error": "backend_unavailable"}

    def test_backend_exception_returns_backend_unavailable(self):
        state = WebUIState(config_path="dummy.json", state_path="dummy-state.json")
        handler = _make_handler()
        parsed = MagicMock()
        parsed.owntone.base_url = BASE_URL
        with (
            patch("autostream_webui_api.is_dial_authorized", return_value=True),
            patch("autostream_webui_api.get_session_state",
                  return_value={"active": False, "source": None}),
            patch("autostream_webui_api._config_snapshot", return_value=parsed),
            patch("autostream_webui_api.list_outputs",
                  side_effect=ConnectionRefusedError("refused")),
        ):
            send_dial_status_post_json(handler, state, {"dial_id": DIAL_ID})
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": False, "error": "backend_unavailable"}

    def test_no_side_effects_on_outputs(self):
        """Handler never calls update_output()."""
        code, body, update_mock = _invoke(
            {"dial_id": DIAL_ID},
            list_result=_ok_list(_output("a", 50)),
        )
        update_mock.assert_not_called()


# ---------------------------------------------------------------------------
# calculate_master_volume() helper
# ---------------------------------------------------------------------------

class TestCalculateMasterVolume:
    def test_empty_returns_none_zero(self):
        assert calculate_master_volume([]) == (None, 0)

    def test_no_selected_returns_none_zero(self):
        outputs = [_output("a", 50, selected=False)]
        assert calculate_master_volume(outputs) == (None, 0)

    def test_single_selected_output(self):
        outputs = [_output("a", 60)]
        assert calculate_master_volume(outputs) == (60, 1)

    def test_two_outputs_average(self):
        outputs = [_output("a", 40), _output("b", 60)]
        assert calculate_master_volume(outputs) == (50, 2)

    def test_rounding_40_61_matches_python_round(self):
        outputs = [_output("a", 40), _output("b", 61)]
        vol, count = calculate_master_volume(outputs)
        assert vol == round((40 + 61) / 2)
        assert count == 2

    def test_rounding_41_62_matches_python_round(self):
        outputs = [_output("a", 41), _output("b", 62)]
        vol, count = calculate_master_volume(outputs)
        assert vol == round((41 + 62) / 2)
        assert count == 2

    def test_volume_clamped_below_zero(self):
        # Negative volume_percent clamped to 0
        class FakeOutput:
            selected = True
            volume_percent = -10
        vol, count = calculate_master_volume([FakeOutput()])
        assert vol == 0
        assert count == 1

    def test_volume_clamped_above_100(self):
        class FakeOutput:
            selected = True
            volume_percent = 150
        vol, count = calculate_master_volume([FakeOutput()])
        assert vol == 100
        assert count == 1

    def test_mixed_selected_and_unselected(self):
        outputs = [_output("a", 60), _output("b", 80, selected=False)]
        vol, count = calculate_master_volume(outputs)
        assert vol == 60
        assert count == 1


# ---------------------------------------------------------------------------
# Avahi / admin source contract tests
# ---------------------------------------------------------------------------

class TestAvahiDialStatus:
    def test_static_avahi_template_has_dial_status_v1(self):
        avahi_file = REPO_ROOT / "system" / "avahi" / "autostream-playing.service"
        tree = ET.parse(avahi_file)
        root = tree.getroot()
        txt_records = [r.text for r in root.iter("txt-record")]
        assert "dial_status=v1" in txt_records, \
            f"dial_status=v1 not found in {avahi_file}: {txt_records}"

    def test_admin_write_playing_service_has_dial_status_v1(self):
        admin_path = REPO_ROOT / "supervisor" / "autostream_admin"
        text = admin_path.read_text(encoding="utf-8")
        # Verify the dial_status=v1 TXT record is in the _write_playing_service function.
        idx = text.find("_write_playing_service")
        assert idx != -1
        fn_text = text[idx:idx + 1000]
        assert "dial_status=v1" in fn_text, \
            "dial_status=v1 not found in _write_playing_service"


# ---------------------------------------------------------------------------
# NGINX policy: 403 must NOT be intercepted by error_page
# ---------------------------------------------------------------------------

class TestNginxPolicy403:
    def test_main_nginx_error_page_does_not_intercept_403(self):
        nginx_conf = REPO_ROOT / "system" / "nginx" / "autostream-nginx.conf"
        if not nginx_conf.exists():
            pytest.skip("main nginx config not found")
        text = nginx_conf.read_text(encoding="utf-8")
        # Extract error_page directives
        import re
        error_pages = re.findall(r"error_page\s+([^;]+);", text)
        for ep in error_pages:
            codes = ep.strip().split()
            # Last token starting with @ or / is the handler, not a code
            for code_str in codes:
                if code_str.startswith(("@", "/")):
                    break
                if code_str.isdigit() and int(code_str) == 403:
                    pytest.fail(
                        f"Main NGINX error_page intercepts 403; "
                        f"POST /api/dial/status must return native 403. "
                        f"Found: error_page {ep}"
                    )


# ---------------------------------------------------------------------------
# dial_status=v1 in DIAL_PROTOCOL.md
# ---------------------------------------------------------------------------

class TestDialProtocolDoc:
    def test_dial_protocol_documents_dial_status_v1(self):
        doc = REPO_ROOT / "docs" / "dial" / "DIAL_PROTOCOL.md"
        text = doc.read_text(encoding="utf-8")
        assert "dial_status" in text, "DIAL_PROTOCOL.md does not mention dial_status"
        assert "/api/dial/status" in text, \
            "DIAL_PROTOCOL.md does not document POST /api/dial/status"

    def test_dial_protocol_documents_track_id_object(self):
        doc = REPO_ROOT / "docs" / "dial" / "DIAL_PROTOCOL.md"
        text = doc.read_text(encoding="utf-8")
        assert "track_id" in text
        assert "artwork_url" in text
        assert "provider artwork" in text.lower()

    def test_dial_protocol_documents_screen_settings_endpoints(self):
        doc = REPO_ROOT / "docs" / "dial" / "DIAL_PROTOCOL.md"
        text = doc.read_text(encoding="utf-8")
        assert "GET /screen/settings" in text
        assert "POST /screen/settings" in text
        assert "invalid_screen_settings" in text
        assert "restart_required" in text

    def test_dial_protocol_documents_screen_type_and_bgr_capability_gate(self):
        doc = REPO_ROOT / "docs" / "dial" / "DIAL_PROTOCOL.md"
        text = doc.read_text(encoding="utf-8")
        assert "screen_type" in text
        assert "\"bgr\"" in text or "`bgr`" in text
        assert "supported" in text
        assert "screen_apply_failed" in text
        # The capability-gate contract must be spelled out, not just named.
        assert "capability" in text.lower()

    def test_dial_protocol_documents_touch_type_and_supported_touch(self):
        doc = REPO_ROOT / "docs" / "dial" / "DIAL_PROTOCOL.md"
        text = doc.read_text(encoding="utf-8")
        assert "touch_type" in text
        assert "supported_touch" in text
        # supported_touch must be documented as a capability separate from
        # `supported` — a dial can advertise screen profiles with no touch
        # capability at all, and clients must gate on supported_touch alone.
        assert "separate capability" in text.lower()
        # touch_type is the one screen setting that requires a restart to
        # take effect; the doc must say so explicitly.
        assert "restart_required" in text


# ---------------------------------------------------------------------------
# Router-level: non-object JSON must NOT trigger HTTP 400 for /api/dial/status
# ---------------------------------------------------------------------------

try:
    from autostream_webui import ConfigWebHandler
    import autostream_webui as _webui_module
    _HAS_WEBUI = True
except ImportError:
    _HAS_WEBUI = False

_skip_no_webui = pytest.mark.skipif(
    not _HAS_WEBUI, reason="autostream_webui import chain unavailable"
)


def _make_do_post_handler(path: str, body: bytes, content_type: str = "application/json"):
    """Build a ConfigWebHandler instance suitable for calling do_POST()."""
    h = ConfigWebHandler.__new__(ConfigWebHandler)
    h.path = path
    h.command = "POST"
    h.request_version = "HTTP/1.1"
    h.headers = {
        "Content-Type": content_type,
        "Content-Length": str(len(body)),
        "Cookie": "",
        "X-CSRF-Token": "",
        "X-Forwarded-For": "",
        "X-Real-IP": "",
    }
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
class TestRouterLevelDialStatus:
    """Router-level tests: do_POST() routing behavior for /api/dial/status.

    Verifies that a non-object JSON body (e.g. an array or null) does NOT
    cause the router to return HTTP 400.  Instead the body is treated as {}
    and the handler returns HTTP 403 for a missing dial_id.  This differs from
    /api/dial/volume and /api/dial/mute, which return HTTP 400 for non-object
    JSON to reject malformed requests early.
    """

    def test_array_body_reaches_handler_as_empty_object(self):
        """JSON array body must not produce HTTP 400; handler returns 403."""
        body = b"[]"
        handler = _make_do_post_handler("/api/dial/status", body)

        with patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.AUTH", MagicMock()), \
             patch("autostream_webui.send_dial_status_post_json") as mock_fn:
            handler.do_POST()

        # The router must NOT have short-circuited with send_error(400)
        handler.send_error.assert_not_called()
        # The handler must have been invoked with an empty dict (missing dial_id)
        mock_fn.assert_called_once()
        _, _, json_arg = mock_fn.call_args[0]
        assert json_arg == {}

    def test_null_body_reaches_handler_as_empty_object(self):
        """JSON null body must not produce HTTP 400; handler receives {}."""
        body = b"null"
        handler = _make_do_post_handler("/api/dial/status", body)

        with patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.AUTH", MagicMock()), \
             patch("autostream_webui.send_dial_status_post_json") as mock_fn:
            handler.do_POST()

        handler.send_error.assert_not_called()
        mock_fn.assert_called_once()
        _, _, json_arg = mock_fn.call_args[0]
        assert json_arg == {}

    def test_volume_route_still_rejects_array_with_400(self):
        """Regression: /api/dial/volume retains HTTP 400 for non-object JSON."""
        body = b"[]"
        handler = _make_do_post_handler("/api/dial/volume", body)

        with patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.AUTH", MagicMock()), \
             patch("autostream_webui.send_dial_volume_post_json") as mock_fn:
            handler.do_POST()

        handler.send_error.assert_called_once()
        call_args = handler.send_error.call_args[0]
        assert call_args[0] == 400
        mock_fn.assert_not_called()
