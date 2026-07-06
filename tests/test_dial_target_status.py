"""Tests for dial_target_status.enrich_targets() and dial_mdns.PlayingTarget.dial_status.

Covers:
1.  dial_status field in PlayingTarget parsed from TXT record.
2.  No targets → empty list.
3.  Unsupported target → status_error:'unsupported', no HTTP request.
4.  Successful enrichment — playing, master_volume, selected_output_count.
5.  No selected outputs → master_volume:null, selected_output_count:0.
6.  HTTP 403 → unauthorized.
7.  Connection failure → unreachable.
25. Missing Content-Type header → bad_response.
26. Non-JSON Content-Type → bad_response.
27. application/json with charset parameter is accepted.
28. ok missing, null, or integer with config_error → bad_response (ok must be exactly false).
8.  Timeout → timeout.
9.  Oversized response → bad_response.
10. Malformed JSON → bad_response.
11. Non-object JSON → bad_response.
12. ok:false config_error → config_error.
13. ok:false backend_unavailable → backend_unavailable.
14. ok:false unknown → bad_response.
15. Invalid playing field → bad_response.
16. Invalid selected_output_count → bad_response.
17. Inconsistent master_volume (count>0 but null) → bad_response.
18. master_volume out of range → bad_response.
19. master_volume present when count=0 → bad_response.
20. Multiple targets run concurrently; all returned.
21. One slow target does not hide successful ones.
22. Output sorted by (name.lower(), ip, port).
23. Result is a fresh list (not the original target list).
24. Failed enrichment leaves volume fields null.
"""
from __future__ import annotations

import http.client
import json
import socket
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import dial_mdns as dm
from dial_mdns import PlayingTarget
from dial_target_status import enrich_targets, fetch_target_status, _fetch_target_status
from dial_control_protocol import TARGET_STATUS_DEADLINE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _target(
    name="Kitchen",
    ip="192.168.1.10",
    port=80,
    dial_api=True,
    audio_status=True,
    dial_status=True,
) -> PlayingTarget:
    return PlayingTarget(
        ip=ip, port=port, name=name,
        dial_api=dial_api, audio_status=audio_status, dial_status=dial_status,
    )


def _ok_response(
    playing=True,
    master_volume=50,
    selected_output_count=2,
) -> dict:
    return {
        "ok": True,
        "playing": playing,
        "master_volume": master_volume,
        "selected_output_count": selected_output_count,
    }


class _FakeHTTPConn:
    """Minimal mock of http.client.HTTPConnection."""

    def __init__(
        self,
        response_data: bytes,
        status: int = 200,
        content_type: str = "application/json",
    ):
        self._data = response_data
        self._status = status
        self._content_type = content_type
        self.request_called = False

    def request(self, method, url, body=None, headers=None):
        self.request_called = True

    def getresponse(self):
        resp = MagicMock()
        resp.status = self._status
        resp.read = MagicMock(return_value=self._data)
        ct = self._content_type
        resp.getheader = MagicMock(side_effect=lambda h, default=None: ct if (h == "Content-Type" and ct is not None) else default)
        return resp

    def close(self):
        pass


def _mock_conn(data: dict | bytes, status: int = 200, content_type: str | None = "application/json"):
    """Return a context-manager patch for HTTPConnection returning data."""
    if isinstance(data, dict):
        raw = json.dumps(data).encode("utf-8")
    else:
        raw = data
    _ct = content_type

    class _Conn(_FakeHTTPConn):
        def __init__(self, host, port=None, timeout=None):
            super().__init__(raw, status, _ct)

    return patch("dial_target_status.http.client.HTTPConnection", _Conn)


# ---------------------------------------------------------------------------
# PlayingTarget.dial_status field in dial_mdns
# ---------------------------------------------------------------------------

class TestPlayingTargetDialStatus:
    def setup_method(self):
        with dm._browser._lock:
            dm._browser._by_key.clear()
            dm._browser._by_identity.clear()
        dm._had_targets = False

    def _add(self, txt):
        line = f"=;eth0;IPv4;Kitchen;_autostream-playing._tcp;local;host;192.168.1.10;80;{txt}"
        dm._browser._handle_line(line)

    def test_dial_status_v1_sets_true(self):
        self._add("dial_api=v1 dial_status=v1")
        targets = dm.get_playing_targets()
        assert targets[0].dial_status is True

    def test_dial_status_absent_is_false(self):
        self._add("dial_api=v1")
        targets = dm.get_playing_targets()
        assert targets[0].dial_status is False

    def test_dial_status_wrong_version_is_false(self):
        self._add("dial_api=v1 dial_status=v2")
        targets = dm.get_playing_targets()
        assert targets[0].dial_status is False

    def test_dial_api_v1_still_required(self):
        self._add("dial_status=v1")
        targets = dm.get_playing_targets()
        assert targets == []


# ---------------------------------------------------------------------------
# enrich_targets: no targets
# ---------------------------------------------------------------------------

class TestEnrichNoTargets:
    def test_empty_list_returns_empty(self):
        result = enrich_targets([], "some-dial-id")
        assert result == []


# ---------------------------------------------------------------------------
# enrich_targets: unsupported target
# ---------------------------------------------------------------------------

class TestEnrichUnsupported:
    def test_unsupported_returns_status_error_unsupported(self):
        t = _target(dial_status=False)
        with patch("dial_target_status.http.client.HTTPConnection") as mock_conn:
            result = enrich_targets([t], "dial-id")
        mock_conn.assert_not_called()
        assert len(result) == 1
        assert result[0]["status_error"] == "unsupported"
        assert result[0]["playing"] is None
        assert result[0]["master_volume"] is None
        assert result[0]["selected_output_count"] is None

    def test_unsupported_includes_all_public_fields(self):
        t = _target(dial_status=False)
        result = enrich_targets([t], "dial-id")
        rec = result[0]
        for field in ("name", "ip", "port", "dial_api", "audio_status", "dial_status"):
            assert field in rec


# ---------------------------------------------------------------------------
# enrich_targets: successful enrichment
# ---------------------------------------------------------------------------

class TestEnrichSuccess:
    def test_successful_enrichment(self):
        t = _target()
        with _mock_conn(_ok_response(playing=True, master_volume=59, selected_output_count=2)):
            result = enrich_targets([t], "dial-id")
        assert len(result) == 1
        r = result[0]
        assert r["status_error"] is None
        assert r["playing"] is True
        assert r["master_volume"] == 59
        assert r["selected_output_count"] == 2

    def test_no_selected_outputs_returns_null_master_zero_count(self):
        t = _target()
        with _mock_conn(_ok_response(playing=False, master_volume=None, selected_output_count=0)):
            result = enrich_targets([t], "dial-id")
        r = result[0]
        assert r["status_error"] is None
        assert r["master_volume"] is None
        assert r["selected_output_count"] == 0

    def test_all_public_fields_present(self):
        t = _target()
        with _mock_conn(_ok_response()):
            result = enrich_targets([t], "dial-id")
        r = result[0]
        for field in (
            "name", "ip", "port", "dial_api", "audio_status", "dial_status",
            "playing", "master_volume", "selected_output_count", "status_error",
        ):
            assert field in r, f"Missing field: {field}"


# ---------------------------------------------------------------------------
# enrich_targets: HTTP 403
# ---------------------------------------------------------------------------

class TestEnrichUnauthorized:
    def test_http_403_returns_unauthorized(self):
        t = _target()
        with _mock_conn(b"{}", status=403):
            result = enrich_targets([t], "wrong-dial-id")
        assert result[0]["status_error"] == "unauthorized"
        assert result[0]["playing"] is None


# ---------------------------------------------------------------------------
# enrich_targets: failure paths
# ---------------------------------------------------------------------------

class TestEnrichFailures:
    def test_connection_refused_returns_unreachable(self):
        t = _target()

        class _FailConn:
            def __init__(self, *a, **kw): pass
            def request(self, *a, **kw):
                raise ConnectionRefusedError("refused")
            def close(self): pass

        with patch("dial_target_status.http.client.HTTPConnection", _FailConn):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "unreachable"

    def test_timeout_error_returns_timeout(self):
        t = _target()

        class _TimeoutConn:
            def __init__(self, *a, **kw): pass
            def request(self, *a, **kw):
                raise TimeoutError("timed out")
            def close(self): pass

        with patch("dial_target_status.http.client.HTTPConnection", _TimeoutConn):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "timeout"

    def test_oversized_response_returns_bad_response(self):
        t = _target()
        oversized = b"x" * 65537
        with _mock_conn(oversized):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "bad_response"

    def test_malformed_json_returns_bad_response(self):
        t = _target()
        with _mock_conn(b"not json"):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "bad_response"

    def test_json_array_root_returns_bad_response(self):
        t = _target()
        with _mock_conn(b"[1,2,3]"):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "bad_response"

    def test_ok_false_config_error_maps_correctly(self):
        t = _target()
        with _mock_conn({"ok": False, "error": "config_error"}):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "config_error"

    def test_ok_false_backend_unavailable_maps_correctly(self):
        t = _target()
        with _mock_conn({"ok": False, "error": "backend_unavailable"}):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "backend_unavailable"

    def test_ok_false_unknown_error_returns_bad_response(self):
        t = _target()
        with _mock_conn({"ok": False, "error": "something_else"}):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "bad_response"

    def test_ok_missing_with_config_error_returns_bad_response(self):
        """ok absent but error:config_error must be bad_response, not config_error."""
        t = _target()
        with _mock_conn({"error": "config_error"}):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "bad_response"

    def test_ok_null_with_config_error_returns_bad_response(self):
        """ok:null is not ok:false — error field must not be honored."""
        t = _target()
        with _mock_conn({"ok": None, "error": "backend_unavailable"}):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "bad_response"

    def test_ok_integer_with_config_error_returns_bad_response(self):
        """ok:0 is not ok:false — error field must not be honored."""
        t = _target()
        with _mock_conn({"ok": 0, "error": "config_error"}):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "bad_response"

    def test_invalid_playing_field_returns_bad_response(self):
        t = _target()
        with _mock_conn({"ok": True, "playing": "yes", "master_volume": 50, "selected_output_count": 1}):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "bad_response"

    def test_boolean_selected_output_count_returns_bad_response(self):
        t = _target()
        with _mock_conn({"ok": True, "playing": True, "master_volume": None, "selected_output_count": True}):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "bad_response"

    def test_negative_selected_output_count_returns_bad_response(self):
        t = _target()
        with _mock_conn({"ok": True, "playing": True, "master_volume": None, "selected_output_count": -1}):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "bad_response"

    def test_master_volume_present_when_count_zero_returns_bad_response(self):
        t = _target()
        with _mock_conn({"ok": True, "playing": False, "master_volume": 50, "selected_output_count": 0}):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "bad_response"

    def test_master_volume_null_when_count_positive_returns_bad_response(self):
        t = _target()
        with _mock_conn({"ok": True, "playing": True, "master_volume": None, "selected_output_count": 2}):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "bad_response"

    def test_master_volume_out_of_range_returns_bad_response(self):
        t = _target()
        with _mock_conn({"ok": True, "playing": True, "master_volume": 101, "selected_output_count": 1}):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "bad_response"

    def test_failed_enrichment_leaves_volume_fields_null(self):
        t = _target()
        with _mock_conn(b"not json"):
            result = enrich_targets([t], "dial-id")
        r = result[0]
        assert r["playing"] is None
        assert r["master_volume"] is None
        assert r["selected_output_count"] is None


# ---------------------------------------------------------------------------
# enrich_targets: concurrency and sorting
# ---------------------------------------------------------------------------

class TestEnrichConcurrencyAndSorting:
    def test_multiple_targets_all_returned(self):
        t1 = _target(name="A", ip="192.168.1.1")
        t2 = _target(name="B", ip="192.168.1.2")

        call_count = [0]
        lock = threading.Lock()

        class _Conn:
            def __init__(self, host, *a, **kw): self._host = host
            def request(self, *a, **kw): pass
            def getresponse(self):
                with lock:
                    call_count[0] += 1
                resp = MagicMock()
                resp.status = 200
                resp.read = MagicMock(return_value=json.dumps(
                    _ok_response(playing=True, master_volume=50, selected_output_count=1)
                ).encode())
                return resp
            def close(self): pass

        with patch("dial_target_status.http.client.HTTPConnection", _Conn):
            result = enrich_targets([t1, t2], "dial-id")

        assert len(result) == 2
        assert call_count[0] == 2

    def test_one_failed_target_does_not_hide_successful(self):
        t_ok = _target(name="A", ip="192.168.1.1")
        t_fail = _target(name="B", ip="192.168.1.2")

        class _Conn:
            def __init__(self, host, port=None, timeout=None):
                self._host = host
            def request(self, *a, **kw):
                if self._host == "192.168.1.2":
                    raise ConnectionRefusedError("refused")
            def getresponse(self):
                resp = MagicMock()
                resp.status = 200
                resp.read = MagicMock(return_value=json.dumps(
                    _ok_response(playing=True, master_volume=60, selected_output_count=1)
                ).encode())
                resp.getheader = MagicMock(
                    side_effect=lambda h, d=None: "application/json" if h == "Content-Type" else d
                )
                return resp
            def close(self): pass

        with patch("dial_target_status.http.client.HTTPConnection", _Conn):
            result = enrich_targets([t_ok, t_fail], "dial-id")

        assert len(result) == 2
        # Sorted by name: A first, B second
        a_rec = next(r for r in result if r["name"] == "A")
        b_rec = next(r for r in result if r["name"] == "B")
        assert a_rec["status_error"] is None
        assert b_rec["status_error"] == "unreachable"

    def test_sorted_by_name_ip_port(self):
        targets = [
            _target(name="Z", ip="10.0.0.3"),
            _target(name="a", ip="10.0.0.1"),
            _target(name="M", ip="10.0.0.2"),
        ]
        with _mock_conn(_ok_response()):
            result = enrich_targets(targets, "dial-id")
        names = [r["name"] for r in result]
        assert names == sorted(names, key=str.lower)

    def test_result_is_fresh_list_not_original(self):
        t = _target()
        with _mock_conn(_ok_response()):
            result = enrich_targets([t], "dial-id")
        assert isinstance(result[0], dict)
        # Ensure it's a dict, not a PlayingTarget
        assert not isinstance(result[0], PlayingTarget)

    def test_deadline_makes_slow_target_timeout(self):
        t = _target()
        original_deadline = TARGET_STATUS_DEADLINE

        class _SlowConn:
            def __init__(self, *a, **kw): pass
            def request(self, *a, **kw):
                # Sleep longer than the deadline to simulate timeout
                time.sleep(original_deadline + 0.5)
            def close(self): pass

        with patch("dial_target_status.http.client.HTTPConnection", _SlowConn):
            with patch("dial_target_status.TARGET_STATUS_DEADLINE", 0.05):
                result = enrich_targets([t], "dial-id")

        assert result[0]["status_error"] == "timeout"


# ---------------------------------------------------------------------------
# track_id validation (shared by enrich_targets() and fetch_target_status())
# ---------------------------------------------------------------------------

def _identified_track_id(**overrides) -> dict:
    base = {
        "enabled": True,
        "state": "identified",
        "title": "Song",
        "artist": "Artist",
        "album": "Album",
        "artwork_url": "https://provider.example/x.jpg",
        "updated_at": 1783170000.0,
        "last_attempt_at": 1783169990.0,
    }
    base.update(overrides)
    return base


class TestTrackIdValidation:
    def test_absent_track_id_is_valid_no_artwork(self):
        t = _target()
        with _mock_conn(_ok_response()):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] is None
        assert result[0]["track_id"] is None

    def test_valid_identified_track_id_parsed(self):
        t = _target()
        body = {**_ok_response(), "track_id": _identified_track_id()}
        with _mock_conn(body):
            record = fetch_target_status(t, "dial-id")
        assert record["status_error"] is None
        assert record["track_id"] == _identified_track_id()

    def test_disabled_track_id_optional_fields_default_empty(self):
        t = _target()
        body = {**_ok_response(), "track_id": {
            "enabled": False, "state": "disabled", "artwork_url": "",
        }}
        with _mock_conn(body):
            record = fetch_target_status(t, "dial-id")
        assert record["status_error"] is None
        assert record["track_id"] == {
            "enabled": False, "state": "disabled",
            "title": "", "artist": "", "album": "",
            "artwork_url": "", "updated_at": None, "last_attempt_at": None,
        }

    def test_track_id_not_object_is_bad_response(self):
        t = _target()
        body = {**_ok_response(), "track_id": "nope"}
        with _mock_conn(body):
            record = fetch_target_status(t, "dial-id")
        assert record["status_error"] == "bad_response"

    def test_missing_enabled_is_bad_response(self):
        t = _target()
        body = {**_ok_response(), "track_id": {"state": "disabled", "artwork_url": ""}}
        with _mock_conn(body):
            record = fetch_target_status(t, "dial-id")
        assert record["status_error"] == "bad_response"

    def test_invalid_state_is_bad_response(self):
        t = _target()
        body = {**_ok_response(), "track_id": _identified_track_id(state="playing")}
        with _mock_conn(body):
            record = fetch_target_status(t, "dial-id")
        assert record["status_error"] == "bad_response"

    def test_non_string_artwork_url_is_bad_response(self):
        t = _target()
        body = {**_ok_response(), "track_id": _identified_track_id(artwork_url=123)}
        with _mock_conn(body):
            record = fetch_target_status(t, "dial-id")
        assert record["status_error"] == "bad_response"

    def test_non_string_title_is_bad_response(self):
        t = _target()
        body = {**_ok_response(), "track_id": _identified_track_id(title=42)}
        with _mock_conn(body):
            record = fetch_target_status(t, "dial-id")
        assert record["status_error"] == "bad_response"

    def test_non_numeric_updated_at_is_bad_response(self):
        t = _target()
        body = {**_ok_response(), "track_id": _identified_track_id(updated_at="yesterday")}
        with _mock_conn(body):
            record = fetch_target_status(t, "dial-id")
        assert record["status_error"] == "bad_response"

    def test_null_updated_at_is_valid(self):
        t = _target()
        body = {**_ok_response(), "track_id": _identified_track_id(updated_at=None, last_attempt_at=None)}
        with _mock_conn(body):
            record = fetch_target_status(t, "dial-id")
        assert record["status_error"] is None
        assert record["track_id"]["updated_at"] is None

    def test_unknown_track_id_fields_ignored(self):
        t = _target()
        body = {**_ok_response(), "track_id": _identified_track_id(provider="acoustid", confidence=0.9)}
        with _mock_conn(body):
            record = fetch_target_status(t, "dial-id")
        assert record["status_error"] is None
        assert "provider" not in record["track_id"]
        assert "confidence" not in record["track_id"]

    def test_non_identified_state_with_empty_artwork_is_valid(self):
        t = _target()
        body = {**_ok_response(), "track_id": {
            "enabled": True, "state": "not_found", "artwork_url": "",
        }}
        with _mock_conn(body):
            record = fetch_target_status(t, "dial-id")
        assert record["status_error"] is None
        assert record["track_id"]["state"] == "not_found"

    def test_fetch_target_status_and_enrich_targets_agree_on_parsing(self):
        """enrich_targets() must reuse the same track_id parsing as fetch_target_status()."""
        t = _target()
        body = {**_ok_response(), "track_id": _identified_track_id()}
        with _mock_conn(body):
            direct = fetch_target_status(t, "dial-id")
        with _mock_conn(body):
            via_enrich = enrich_targets([t], "dial-id")[0]
        assert direct["track_id"] == via_enrich["track_id"]


# ---------------------------------------------------------------------------
# Content-Type validation (finding #2)
# ---------------------------------------------------------------------------

class TestContentTypeValidation:
    """Response Content-Type must be application/json; otherwise bad_response."""

    def test_missing_content_type_returns_bad_response(self):
        """No Content-Type header → bad_response."""
        t = _target()
        with _mock_conn(_ok_response(), content_type=None):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "bad_response"

    def test_text_html_content_type_returns_bad_response(self):
        """text/html Content-Type → bad_response even when body is valid JSON."""
        t = _target()
        with _mock_conn(_ok_response(), content_type="text/html"):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "bad_response"

    def test_text_plain_content_type_returns_bad_response(self):
        """text/plain Content-Type → bad_response."""
        t = _target()
        with _mock_conn(_ok_response(), content_type="text/plain; charset=utf-8"):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] == "bad_response"

    def test_application_json_with_charset_is_accepted(self):
        """application/json; charset=utf-8 must be accepted (ignore params)."""
        t = _target()
        with _mock_conn(_ok_response(), content_type="application/json; charset=utf-8"):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] is None
        assert result[0]["playing"] is True

    def test_application_json_uppercase_is_accepted(self):
        """Content-Type matching is case-insensitive."""
        t = _target()
        with _mock_conn(_ok_response(), content_type="Application/JSON"):
            result = enrich_targets([t], "dial-id")
        assert result[0]["status_error"] is None
