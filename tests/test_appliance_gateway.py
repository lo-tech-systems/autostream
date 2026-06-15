"""test_appliance_gateway.py — unit tests for autostream_appliance_gateway.

Tests cover:
  - resolve_appliance (invalid/bound/conflict/remote/offline)
  - Backoff management (_check_backoff_locked, _record_failure_locked,
    _record_success_locked, _update_backoff)
  - Token cache (_get_token_from_cache_locked, _acquire_token, evict_gateway_token)
  - HTTP transport (_remote_federation_request: timeout, bad CT, oversized, valid)
  - _remote_request: token failure, 401 retry, normal success
  - _coalesced_remote_get: cache hit, backoff guard, owner path, coalescing
  - Public handlers: bound dispatch, remote dispatch, error responses
"""
from __future__ import annotations

import io
import json
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_appliance_gateway as gw


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_state():
    with gw._state_lock:
        gw._token_cache.clear()
        gw._backoff_state.clear()
        gw._read_cache.clear()
        gw._in_flight.clear()


@pytest.fixture(autouse=True)
def clean_state():
    _reset_state()
    yield
    _reset_state()


def _make_sighting(ip="1.2.3.4", port=8080, appliance_id="aabbccdd1122334455aa"):
    from autostream_appliances import ApplianceSighting
    return ApplianceSighting(
        id=appliance_id,
        service_name="_autostream._tcp.local.",
        hostname="study.local",
        ip=ip,
        port=port,
        version="1.0.0",
    )


def _make_handler():
    """Minimal handler stub that captures send_json / send_browser_api_error calls."""
    h = MagicMock()
    h.wfile = io.BytesIO()
    h._pending_auth_cookie = None
    h._pending_set_cookies = []
    return h


def _capture_send(handler):
    """Return (sent_code, sent_data) lists captured from send_json."""
    sent_code = []
    sent_data = []

    def fake_send_json(h, code, data):
        sent_code.append(code)
        sent_data.append(data)

    def fake_browser_err(h, code, error, *, retryable=None, extra=None):
        sent_code.append(code)
        sent_data.append({"ok": False, "error": error, "retryable": retryable, **(extra or {})})

    return sent_code, sent_data, fake_send_json, fake_browser_err


# ---------------------------------------------------------------------------
# resolve_appliance
# ---------------------------------------------------------------------------

class TestResolveAppliance:
    def test_invalid_short(self):
        res, _ = gw.resolve_appliance("abc")
        assert res == "invalid"

    def test_invalid_uppercase(self):
        # 20 chars but uppercase
        res, _ = gw.resolve_appliance("AABBCCDD1122334455AA")
        assert res == "invalid"

    def test_invalid_too_long(self):
        res, _ = gw.resolve_appliance("a" * 21)
        assert res == "invalid"

    def test_invalid_non_hex(self):
        res, _ = gw.resolve_appliance("zz" + "a" * 18)
        assert res == "invalid"

    def test_bound(self):
        local_id = "a" * 20
        with patch("autostream_appliance_gateway.get_appliance_id", return_value=local_id):
            res, sighting = gw.resolve_appliance(local_id)
        assert res == "bound"
        assert sighting is None

    def test_conflict(self):
        aid = "b" * 20
        with patch("autostream_appliance_gateway.get_appliance_id", return_value="c" * 20), \
             patch("autostream_appliance_gateway.get_conflict_ids", return_value=frozenset({aid})):
            res, _ = gw.resolve_appliance(aid)
        assert res == "conflict"

    def test_remote(self):
        aid = "d" * 20
        sighting = _make_sighting(appliance_id=aid)
        with patch("autostream_appliance_gateway.get_appliance_id", return_value="e" * 20), \
             patch("autostream_appliance_gateway.get_conflict_ids", return_value=frozenset()), \
             patch("autostream_appliance_gateway.get_appliance_sighting", return_value=sighting):
            res, got = gw.resolve_appliance(aid)
        assert res == "remote"
        assert got is sighting

    def test_offline(self):
        aid = "f" * 20
        with patch("autostream_appliance_gateway.get_appliance_id", return_value="e" * 20), \
             patch("autostream_appliance_gateway.get_conflict_ids", return_value=frozenset()), \
             patch("autostream_appliance_gateway.get_appliance_sighting", return_value=None):
            res, got = gw.resolve_appliance(aid)
        assert res == "offline"
        assert got is None


# ---------------------------------------------------------------------------
# Backoff management
# ---------------------------------------------------------------------------

class TestBackoff:
    def test_no_backoff_initially(self):
        with gw._state_lock:
            in_b, _ = gw._check_backoff_locked("x" * 20)
        assert in_b is False

    def test_first_failure_sets_1s_backoff(self):
        aid = "a" * 20
        with gw._state_lock:
            gw._record_failure_locked(aid)
            until, step = gw._backoff_state[aid]
        assert step == 0
        assert until > time.monotonic()

    def test_second_failure_advances_step(self):
        aid = "a" * 20
        with gw._state_lock:
            gw._record_failure_locked(aid)
            gw._record_failure_locked(aid)
            _, step = gw._backoff_state[aid]
        assert step == 1  # step 1 → 2 seconds

    def test_max_step_is_capped(self):
        aid = "a" * 20
        with gw._state_lock:
            for _ in range(20):  # way more failures than backoff steps
                gw._record_failure_locked(aid)
            _, step = gw._backoff_state[aid]
        assert step == len(gw._BACKOFF_STEPS) - 1

    def test_success_clears_backoff(self):
        aid = "a" * 20
        with gw._state_lock:
            gw._record_failure_locked(aid)
            gw._record_success_locked(aid)
        assert aid not in gw._backoff_state

    def test_update_backoff_success(self):
        aid = "a" * 20
        with gw._state_lock:
            gw._record_failure_locked(aid)
        gw._update_backoff(aid, 200, {"ok": True})
        assert aid not in gw._backoff_state

    def test_update_backoff_failure(self):
        aid = "a" * 20
        gw._update_backoff(aid, 0, {"ok": False, "error": "remote_timeout"})
        assert aid in gw._backoff_state

    def test_check_backoff_in_window(self):
        aid = "a" * 20
        with gw._state_lock:
            gw._backoff_state[aid] = (time.monotonic() + 10, 0)
            in_b, retry = gw._check_backoff_locked(aid)
        assert in_b is True
        assert retry >= 1

    def test_check_backoff_expired(self):
        aid = "a" * 20
        with gw._state_lock:
            gw._backoff_state[aid] = (time.monotonic() - 1, 0)
            in_b, _ = gw._check_backoff_locked(aid)
        assert in_b is False


# ---------------------------------------------------------------------------
# Token cache
# ---------------------------------------------------------------------------

class TestTokenCache:
    def test_no_token_initially(self):
        with gw._state_lock:
            t = gw._get_token_from_cache_locked("a" * 20)
        assert t is None

    def test_cached_token_returned_within_margin(self):
        aid = "a" * 20
        far_future = time.monotonic() + 600
        with gw._state_lock:
            gw._token_cache[aid] = ("mytoken", far_future)
            t = gw._get_token_from_cache_locked(aid)
        assert t == "mytoken"

    def test_token_near_expiry_not_returned(self):
        aid = "a" * 20
        # Expires in 60s which is less than _TOKEN_RENEW_MARGIN (120s)
        with gw._state_lock:
            gw._token_cache[aid] = ("mytoken", time.monotonic() + 60)
            t = gw._get_token_from_cache_locked(aid)
        assert t is None

    def test_evict_removes_token(self):
        aid = "a" * 20
        with gw._state_lock:
            gw._token_cache[aid] = ("mytoken", time.monotonic() + 600)
        gw.evict_gateway_token(aid)
        assert aid not in gw._token_cache

    def test_acquire_token_parses_schema(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        session_resp = {
            "ok": True,
            "token": "abc123",
            "token_type": "Bearer",
            "expires_in": 600,
            "federation_version": 1,
        }
        with patch.object(gw, "_remote_federation_request", return_value=(200, session_resp)):
            token, err = gw._acquire_token(aid, sighting)
        assert token == "abc123"
        assert err == ""
        assert aid in gw._token_cache

    def test_acquire_token_transport_error(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        with patch.object(gw, "_remote_federation_request",
                          return_value=(0, {"ok": False, "error": "remote_timeout"})):
            token, err = gw._acquire_token(aid, sighting)
        assert token is None
        assert err == "remote_timeout"

    def test_acquire_token_malformed_schema(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        bad_resp = {"ok": True, "token": 12345, "token_type": "Bearer",
                    "expires_in": 600, "federation_version": 1}
        with patch.object(gw, "_remote_federation_request", return_value=(200, bad_resp)):
            token, err = gw._acquire_token(aid, sighting)
        assert token is None
        assert err == "remote_bad_response"


# ---------------------------------------------------------------------------
# HTTP transport
# ---------------------------------------------------------------------------

class TestRemoteFederationRequest:
    def _make_sighting(self):
        return _make_sighting()

    def test_timeout_returns_0_and_remote_timeout(self):
        import socket as _socket
        sighting = self._make_sighting()
        with patch("autostream_appliance_gateway.http.client.HTTPConnection") as MockConn:
            MockConn.return_value.request.side_effect = _socket.timeout("timed out")
            status, data = gw._remote_federation_request("GET", sighting, "/foo", "tok")
        assert status == 0
        assert data["error"] == "remote_timeout"

    def test_connection_refused_returns_remote_timeout(self):
        sighting = self._make_sighting()
        with patch("autostream_appliance_gateway.http.client.HTTPConnection") as MockConn:
            MockConn.return_value.request.side_effect = ConnectionRefusedError()
            status, data = gw._remote_federation_request("GET", sighting, "/foo", "tok")
        assert status == 0
        assert data["error"] == "remote_timeout"

    def test_wrong_content_type_returns_remote_bad_response(self):
        sighting = self._make_sighting()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheader.return_value = "text/html"
        mock_resp.read.return_value = b"<html/>"
        with patch("autostream_appliance_gateway.http.client.HTTPConnection") as MockConn:
            MockConn.return_value.sock = MagicMock()
            MockConn.return_value.getresponse.return_value = mock_resp
            status, data = gw._remote_federation_request("GET", sighting, "/foo", "tok")
        assert status == 0
        assert data["error"] == "remote_bad_response"

    def test_oversized_body_returns_remote_bad_response(self):
        sighting = self._make_sighting()
        oversized = b'{"ok":true}' * 30000  # well over 256 KiB
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheader.return_value = "application/json"
        mock_resp.read.return_value = oversized
        with patch("autostream_appliance_gateway.http.client.HTTPConnection") as MockConn:
            MockConn.return_value.sock = MagicMock()
            MockConn.return_value.getresponse.return_value = mock_resp
            status, data = gw._remote_federation_request("GET", sighting, "/foo", "tok")
        assert status == 0
        assert data["error"] == "remote_bad_response"

    def test_invalid_json_returns_remote_bad_response(self):
        sighting = self._make_sighting()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheader.return_value = "application/json"
        mock_resp.read.return_value = b"not json"
        with patch("autostream_appliance_gateway.http.client.HTTPConnection") as MockConn:
            MockConn.return_value.sock = MagicMock()
            MockConn.return_value.getresponse.return_value = mock_resp
            status, data = gw._remote_federation_request("GET", sighting, "/foo", "tok")
        assert status == 0
        assert data["error"] == "remote_bad_response"

    def test_valid_response_returned(self):
        sighting = self._make_sighting()
        payload = {"ok": True, "value": 42}
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheader.return_value = "application/json"
        mock_resp.read.return_value = json.dumps(payload).encode()
        with patch("autostream_appliance_gateway.http.client.HTTPConnection") as MockConn:
            MockConn.return_value.sock = MagicMock()
            MockConn.return_value.getresponse.return_value = mock_resp
            status, data = gw._remote_federation_request("GET", sighting, "/foo", "tok")
        assert status == 200
        assert data == payload


# ---------------------------------------------------------------------------
# _remote_request: token failure and 401 retry
# ---------------------------------------------------------------------------

class TestRemoteRequest:
    def test_token_failure_returns_error(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        with patch.object(gw, "_get_or_renew_token", return_value=(None, "remote_timeout")):
            status, data = gw._remote_request(aid, sighting, "GET", "/foo")
        assert status == 0
        assert data["error"] == "remote_timeout"

    def test_401_triggers_retry(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        gw._token_cache[aid] = ("old_token", time.monotonic() + 600)
        call_count = [0]
        def fake_fed_req(method, s, path, token, body=None):
            call_count[0] += 1
            if call_count[0] == 1:
                return 401, {"ok": False, "error": "unauthorized"}
            return 200, {"ok": True}
        session_resp = {"ok": True, "token": "new_token", "token_type": "Bearer",
                        "expires_in": 600, "federation_version": 1}
        with patch.object(gw, "_remote_federation_request", side_effect=fake_fed_req), \
             patch.object(gw, "_acquire_token", return_value=("new_token", "")):
            status, data = gw._remote_request(aid, sighting, "GET", "/foo")
        assert status == 200
        assert data["ok"] is True

    def test_401_retry_token_acquisition_failure(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        gw._token_cache[aid] = ("old_token", time.monotonic() + 600)
        with patch.object(gw, "_remote_federation_request",
                          return_value=(401, {"ok": False, "error": "unauthorized"})), \
             patch.object(gw, "_acquire_token", return_value=(None, "remote_timeout")):
            status, data = gw._remote_request(aid, sighting, "GET", "/foo")
        assert status == 0
        assert data["error"] == "remote_timeout"

    def test_no_backoff_side_effects(self):
        """_remote_request must not touch backoff state — callers own that."""
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        with patch.object(gw, "_get_or_renew_token", return_value=("tok", "")), \
             patch.object(gw, "_remote_federation_request",
                          return_value=(0, {"ok": False, "error": "remote_timeout"})):
            gw._remote_request(aid, sighting, "GET", "/foo")
        # Backoff state must not have been modified
        assert aid not in gw._backoff_state


# ---------------------------------------------------------------------------
# _coalesced_remote_get
# ---------------------------------------------------------------------------

class TestCoalescedRemoteGet:
    def _ok_response(self):
        return (200, {"ok": True, "data": "value"})

    def test_cache_hit_returns_cached(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        cached = {"ok": True, "cached": True}
        with gw._state_lock:
            gw._read_cache[(aid, fed_path)] = (cached, time.monotonic() + 1.0)
        status, data = gw._coalesced_remote_get(aid, sighting, fed_path)
        assert status == 200
        assert data["cached"] is True

    def test_cache_miss_makes_request(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        ok_data = {"ok": True, "live": True}
        with patch.object(gw, "_remote_request", return_value=(200, ok_data)):
            status, data = gw._coalesced_remote_get(aid, sighting, fed_path)
        assert status == 200
        assert data["live"] is True

    def test_success_stores_in_cache(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        ok_data = {"ok": True}
        with patch.object(gw, "_remote_request", return_value=(200, ok_data)):
            gw._coalesced_remote_get(aid, sighting, fed_path)
        assert (aid, fed_path) in gw._read_cache

    def test_failure_records_backoff(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        with patch.object(gw, "_remote_request",
                          return_value=(0, {"ok": False, "error": "remote_timeout"})):
            gw._coalesced_remote_get(aid, sighting, fed_path)
        assert aid in gw._backoff_state

    def test_backoff_guard_short_circuits(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        with gw._state_lock:
            gw._backoff_state[aid] = (time.monotonic() + 10, 0)
        with patch.object(gw, "_remote_request") as mock_req:
            status, data = gw._coalesced_remote_get(aid, sighting, fed_path)
        mock_req.assert_not_called()
        assert data["error"] == "remote_backoff"

    def test_expired_cache_makes_new_request(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        expired = {"ok": True, "stale": True}
        with gw._state_lock:
            gw._read_cache[(aid, fed_path)] = (expired, time.monotonic() - 0.1)
        fresh = {"ok": True, "fresh": True}
        with patch.object(gw, "_remote_request", return_value=(200, fresh)):
            status, data = gw._coalesced_remote_get(aid, sighting, fed_path)
        assert data.get("fresh") is True

    def test_coalescing_second_caller_gets_same_result(self):
        """A second concurrent caller waits on the Event and gets the owner's result."""
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        ok_data = {"ok": True, "coalesced": True}
        results = [None, None]
        call_count = [0]

        def slow_request(*args, **kwargs):
            call_count[0] += 1
            time.sleep(0.2)  # hold long enough for t2 to join the in-flight
            return 200, ok_data

        with patch.object(gw, "_remote_request", side_effect=slow_request):
            def call_get(idx):
                results[idx] = gw._coalesced_remote_get(aid, sighting, fed_path)

            t1 = threading.Thread(target=call_get, args=(0,))
            t2 = threading.Thread(target=call_get, args=(1,))
            t1.start()
            time.sleep(0.05)  # ensure t1 registers as the in-flight owner first
            t2.start()
            t1.join(timeout=5)
            t2.join(timeout=5)

        # _remote_request must only have been called once (t2 coalesced)
        assert call_count[0] == 1, "Expected exactly one HTTP request (coalescing)"
        s1, d1 = results[0]
        s2, d2 = results[1]
        assert s1 == 200
        assert d1.get("coalesced") is True
        assert s2 == 200
        assert d2.get("coalesced") is True


# ---------------------------------------------------------------------------
# send_appliances_json
# ---------------------------------------------------------------------------

class TestSendAppliancesJson:
    def _call(self, local_id="aabbccdd1122334455aa", peers=None):
        from autostream_appliances import ApplianceSighting
        handler = _make_handler()
        sent_codes = []
        sent_data = []
        fake_peers = peers or []

        def fake_send_json(h, code, data):
            sent_codes.append(code)
            sent_data.append(data)

        with patch("autostream_appliance_gateway.get_appliance_id", return_value=local_id), \
             patch("autostream_appliance_gateway.scanner_ready", return_value=True), \
             patch("autostream_appliance_gateway.grace_remaining_ms", return_value=0), \
             patch("autostream_appliance_gateway.get_all_appliances", return_value=fake_peers), \
             patch("autostream_appliance_gateway._local_hostname", return_value="home"), \
             patch("autostream_appliance_gateway._local_version", return_value="1.0.0"), \
             patch("autostream_appliance_gateway.send_json", side_effect=fake_send_json):
            gw.send_appliances_json(handler, MagicMock())

        return sent_codes, sent_data

    def test_returns_ok_with_bound_appliance(self):
        codes, data = self._call()
        assert codes == [200]
        assert data[0]["ok"] is True
        assert data[0]["bound_appliance_id"] == "aabbccdd1122334455aa"

    def test_bound_appliance_first_in_list(self):
        codes, data = self._call()
        appliances = data[0]["appliances"]
        assert appliances[0]["is_bound"] is True
        assert appliances[0]["home_path"] == "/"
        assert appliances[0]["equaliser_path"] == "/equaliser"

    def test_missing_identity_returns_500(self):
        handler = _make_handler()
        sent_codes = []
        sent_data = []
        def fake_send_json(h, code, data):
            sent_codes.append(code)
            sent_data.append(data)
        with patch("autostream_appliance_gateway.get_appliance_id", return_value=None), \
             patch("autostream_appliance_gateway.send_json", side_effect=fake_send_json):
            gw.send_appliances_json(handler, MagicMock())
        assert sent_codes == [500]
        assert sent_data[0]["error"] == "appliance_identity_unavailable"

    def test_scanner_state_included(self):
        codes, data = self._call()
        scanner = data[0]["scanner"]
        assert "ready" in scanner
        assert "grace_remaining_ms" in scanner


# ---------------------------------------------------------------------------
# send_gateway_home_json
# ---------------------------------------------------------------------------

class TestSendGatewayHomeJson:
    def _run(self, aid, resolution, sighting=None, home_data=None):
        handler = _make_handler()
        sent_codes = []
        sent_data = []
        sent_browser_errors = []

        def fake_send_json(h, code, data):
            sent_codes.append(code)
            sent_data.append(data)

        def fake_browser_err(h, code, error, *, retryable=None, extra=None):
            sent_browser_errors.append((code, error))

        state = MagicMock()
        state.config_path = "dummy.ini"

        with patch("autostream_appliance_gateway.resolve_appliance",
                   return_value=(resolution, sighting)), \
             patch("autostream_appliance_gateway.build_home_state",
                   return_value=home_data or {"ok": True}), \
             patch("autostream_appliance_gateway.send_json", side_effect=fake_send_json), \
             patch("autostream_appliance_gateway.send_browser_api_error",
                   side_effect=fake_browser_err):
            gw.send_gateway_home_json(handler, state, aid)

        return sent_codes, sent_data, sent_browser_errors

    def test_invalid_id_returns_404(self):
        _, _, errs = self._run("bad-id", "invalid")
        assert errs and errs[0][0] == 404

    def test_conflict_returns_409(self):
        codes, data, _ = self._run("a" * 20, "conflict")
        assert codes == [409]
        assert data[0]["error"] == "appliance_conflicted"

    def test_offline_returns_503(self):
        _, _, errs = self._run("a" * 20, "offline")
        assert errs and errs[0][0] == 503

    def test_bound_calls_build_home_state(self):
        home = {"ok": True, "outputs": [], "appliance": {}, "playback": {},
                "input_levels": [], "warnings": {}, "preferences": {}, "vu_delay_ms": 100}
        codes, data, _ = self._run("a" * 20, "bound", home_data=home)
        assert codes == [200]
        assert data[0]["ok"] is True

    def test_remote_success_forwarded(self):
        sighting = _make_sighting()
        remote_data = {"ok": True, "outputs": []}
        handler = _make_handler()
        sent_codes = []
        sent_data = []
        state = MagicMock(config_path="dummy.ini")

        with patch("autostream_appliance_gateway.resolve_appliance",
                   return_value=("remote", sighting)), \
             patch.object(gw, "_check_and_emit_backoff", return_value=False), \
             patch.object(gw, "_coalesced_remote_get", return_value=(200, remote_data)), \
             patch("autostream_appliance_gateway.send_json",
                   side_effect=lambda h, c, d: (sent_codes.append(c), sent_data.append(d))):
            gw.send_gateway_home_json(handler, state, "a" * 20)

        assert sent_codes == [200]
        assert sent_data[0]["ok"] is True
