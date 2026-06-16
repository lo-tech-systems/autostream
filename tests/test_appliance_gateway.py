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
import logging
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
    _KEY = ("a" * 20, "/api/federation/v1/home")

    def test_no_backoff_initially(self):
        key = ("x" * 20, "/api/federation/v1/home")
        with gw._state_lock:
            in_b, _ = gw._check_backoff_locked(key)
        assert in_b is False

    def test_first_failure_sets_1s_backoff(self):
        key = self._KEY
        with gw._state_lock:
            gw._record_failure_locked(key)
            until, step = gw._backoff_state[key]
        assert step == 0
        assert until > time.monotonic()

    def test_second_failure_advances_step(self):
        key = self._KEY
        with gw._state_lock:
            gw._record_failure_locked(key)
            gw._record_failure_locked(key)
            _, step = gw._backoff_state[key]
        assert step == 1  # step 1 → 2 seconds

    def test_max_step_is_capped(self):
        key = self._KEY
        with gw._state_lock:
            for _ in range(20):  # way more failures than backoff steps
                gw._record_failure_locked(key)
            _, step = gw._backoff_state[key]
        assert step == len(gw._BACKOFF_STEPS) - 1

    def test_success_clears_backoff(self):
        key = self._KEY
        with gw._state_lock:
            gw._record_failure_locked(key)
            gw._record_success_locked(key)
        assert key not in gw._backoff_state

    def test_update_backoff_success(self):
        key = self._KEY
        with gw._state_lock:
            gw._record_failure_locked(key)
        gw._update_backoff(key, 200, {"ok": True})
        assert key not in gw._backoff_state

    def test_update_backoff_failure(self):
        key = self._KEY
        gw._update_backoff(key, 0, {"ok": False, "error": "remote_timeout"})
        assert key in gw._backoff_state

    def test_update_backoff_application_error_does_not_advance(self):
        """409 appliance_unconfigured is an application error, not a transport failure."""
        key = ("b" * 20, "/api/federation/v1/home")
        with gw._state_lock:
            gw._backoff_state.pop(key, None)
        gw._update_backoff(key, 409, {"ok": False, "error": "appliance_unconfigured"})
        assert key not in gw._backoff_state

    def test_update_backoff_remote_bad_response_is_transport(self):
        """remote_bad_response counts as a transport failure for backoff."""
        key = ("c" * 20, "/api/federation/v1/home")
        gw._update_backoff(key, 200, {"ok": False, "error": "remote_bad_response"})
        assert key in gw._backoff_state

    def test_check_backoff_in_window(self):
        key = self._KEY
        with gw._state_lock:
            gw._backoff_state[key] = (time.monotonic() + 10, 0)
            in_b, retry = gw._check_backoff_locked(key)
        assert in_b is True
        assert retry >= 1

    def test_check_backoff_expired(self):
        key = self._KEY
        with gw._state_lock:
            gw._backoff_state[key] = (time.monotonic() - 1, 0)
            in_b, _ = gw._check_backoff_locked(key)
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

    _VALID_TOKEN = "a" * 40  # minimum 40-char hex token for schema validation

    def test_acquire_token_parses_schema(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        session_resp = {
            "ok": True,
            "token": self._VALID_TOKEN,
            "token_type": "Bearer",
            "expires_in": 600,
            "federation_version": 1,
        }
        with patch.object(gw, "_remote_federation_request", return_value=(200, session_resp)):
            token, err, retry = gw._acquire_token(aid, sighting)
        assert token == self._VALID_TOKEN
        assert err == ""
        assert retry == 0
        assert aid in gw._token_cache

    def test_acquire_token_transport_error(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        with patch.object(gw, "_remote_federation_request",
                          return_value=(0, {"ok": False, "error": "remote_timeout"})):
            token, err, retry = gw._acquire_token(aid, sighting)
        assert token is None
        assert err == "remote_timeout"
        assert retry == 0

    def test_acquire_token_malformed_schema(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        bad_resp = {"ok": True, "token": 12345, "token_type": "Bearer",
                    "expires_in": 600, "federation_version": 1}
        with patch.object(gw, "_remote_federation_request", return_value=(200, bad_resp)):
            token, err, _ = gw._acquire_token(aid, sighting)
        assert token is None
        assert err == "remote_bad_response"

    def test_acquire_token_short_token_rejected(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        bad_resp = {"ok": True, "token": "short", "token_type": "Bearer",
                    "expires_in": 600, "federation_version": 1}
        with patch.object(gw, "_remote_federation_request", return_value=(200, bad_resp)):
            token, err, _ = gw._acquire_token(aid, sighting)
        assert token is None
        assert err == "remote_bad_response"

    def test_acquire_token_bool_federation_version_rejected(self):
        """True == 1 in Python; must not pass the fed_version != 1 check."""
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        bad_resp = {"ok": True, "token": self._VALID_TOKEN, "token_type": "Bearer",
                    "expires_in": 600, "federation_version": True}
        with patch.object(gw, "_remote_federation_request", return_value=(200, bad_resp)):
            token, err, _ = gw._acquire_token(aid, sighting)
        assert token is None
        assert err == "remote_bad_response"

    def test_acquire_token_extra_fields_rejected(self):
        """Session response with extra fields must be rejected as non-exact schema."""
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        extra_resp = {"ok": True, "token": self._VALID_TOKEN, "token_type": "Bearer",
                      "expires_in": 600, "federation_version": 1, "extra": "field"}
        with patch.object(gw, "_remote_federation_request", return_value=(200, extra_resp)):
            token, err, _ = gw._acquire_token(aid, sighting)
        assert token is None
        assert err == "remote_bad_response"

    def test_acquire_token_rate_limited_preserves_retry_after(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        with patch.object(gw, "_remote_federation_request",
                          return_value=(429, {"ok": False, "error": "rate_limited",
                                             "retry_after": 30})):
            token, err, retry = gw._acquire_token(aid, sighting)
        assert token is None
        assert err == "rate_limited"
        assert retry == 30


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
        with patch.object(gw, "_get_or_renew_token", return_value=(None, "remote_timeout", 0)):
            status, data = gw._remote_request(aid, sighting, "GET", "/foo")
        assert status == 0
        assert data["error"] == "remote_timeout"

    def test_rate_limited_token_returns_429_with_retry_after(self):
        """rate_limited from token acquisition must return 429 with retry_after, not status 0."""
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        with patch.object(gw, "_get_or_renew_token", return_value=(None, "rate_limited", 45)):
            status, data = gw._remote_request(aid, sighting, "GET", "/foo")
        assert status == 429
        assert data["error"] == "rate_limited"
        assert data.get("retry_after") == 45

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
             patch.object(gw, "_acquire_token", return_value=("new_token", "", 0)):
            status, data = gw._remote_request(aid, sighting, "GET", "/foo")
        assert status == 200
        assert data["ok"] is True

    def test_401_retry_token_acquisition_failure(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        gw._token_cache[aid] = ("old_token", time.monotonic() + 600)
        with patch.object(gw, "_remote_federation_request",
                          return_value=(401, {"ok": False, "error": "unauthorized"})), \
             patch.object(gw, "_acquire_token", return_value=(None, "remote_timeout", 0)):
            status, data = gw._remote_request(aid, sighting, "GET", "/foo")
        assert status == 0
        assert data["error"] == "remote_timeout"

    def test_no_backoff_side_effects(self):
        """_remote_request must not touch backoff state — callers own that."""
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        with patch.object(gw, "_get_or_renew_token", return_value=("tok", "", 0)), \
             patch.object(gw, "_remote_federation_request",
                          return_value=(0, {"ok": False, "error": "remote_timeout"})):
            gw._remote_request(aid, sighting, "GET", "/foo")
        # Backoff state must not have been modified (no tuple key for this aid)
        assert not any(k[0] == aid for k in gw._backoff_state)


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
        now = time.monotonic()
        with gw._state_lock:
            gw._read_cache[(aid, fed_path)] = {
                "data": cached, "cached_at": now,
                "fresh_until": now + 1.0, "stale_until": now + gw._STALE_READ_CACHE_TTL,
            }
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
        assert (aid, fed_path) in gw._backoff_state

    def test_backoff_guard_short_circuits(self):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        with gw._state_lock:
            gw._backoff_state[(aid, fed_path)] = (time.monotonic() + 10, 0)
        with patch.object(gw, "_remote_request") as mock_req:
            status, data = gw._coalesced_remote_get(aid, sighting, fed_path)
        mock_req.assert_not_called()
        assert data["error"] == "remote_backoff"

    def test_expired_fresh_cache_makes_new_request(self):
        """Past fresh_until but within stale_until: must attempt remote before returning stale."""
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        old_data = {"ok": True, "old": True}
        now = time.monotonic()
        with gw._state_lock:
            gw._read_cache[(aid, fed_path)] = {
                "data": old_data, "cached_at": now - 5.0,
                "fresh_until": now - 0.1,
                "stale_until": now + gw._STALE_READ_CACHE_TTL,
            }
        fresh = {"ok": True, "fresh": True}
        with patch.object(gw, "_remote_request", return_value=(200, fresh)):
            status, data = gw._coalesced_remote_get(aid, sighting, fed_path)
        assert data.get("fresh") is True

    def test_success_stores_new_cache_shape(self):
        """Successful remote request must store the dict-shape cache entry."""
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        ok_data = {"ok": True}
        with patch.object(gw, "_remote_request", return_value=(200, ok_data)):
            gw._coalesced_remote_get(aid, sighting, fed_path)
        entry = gw._read_cache.get((aid, fed_path))
        assert entry is not None
        assert "fresh_until" in entry
        assert "stale_until" in entry
        assert "cached_at" in entry
        assert entry["data"] is ok_data

    def test_rate_limited_does_not_advance_backoff(self):
        """rate_limited response (429 from token acquisition) must not advance backoff counter."""
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        with patch.object(gw, "_remote_request",
                          return_value=(429, {"ok": False, "error": "rate_limited",
                                             "retry_after": 30})):
            gw._coalesced_remote_get(aid, sighting, fed_path)
        assert (aid, fed_path) not in gw._backoff_state

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
# Stale cache fallback
# ---------------------------------------------------------------------------

class TestStaleCache:
    """_coalesced_remote_get stale-on-failure fallback behaviour."""

    def _prime_stale(self, aid, fed_path, data=None, fresh_offset=-2.0):
        """Insert a cache entry whose fresh_until has passed but stale_until has not."""
        now = time.monotonic()
        with gw._state_lock:
            gw._read_cache[(aid, fed_path)] = {
                "data": data or {"ok": True, "cached": True},
                "cached_at": now + fresh_offset - 1.0,
                "fresh_until": now + fresh_offset,
                "stale_until": now + gw._STALE_READ_CACHE_TTL,
            }

    def test_stale_returned_on_owner_transport_failure(self):
        """On remote_timeout, stale cached data is returned instead of an error."""
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        self._prime_stale(aid, fed_path, data={"ok": True, "last_known": True})

        with patch.object(gw, "_remote_request",
                          return_value=(0, {"ok": False, "error": "remote_timeout"})):
            status, data = gw._coalesced_remote_get(aid, sighting, fed_path)

        assert status == 200
        assert data.get("ok") is True
        assert data.get("stale") is True
        assert data.get("last_known") is True

    def test_stale_response_includes_metadata(self):
        """Stale response must include stale_reason and stale_age_ms."""
        aid = "b" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        self._prime_stale(aid, fed_path)

        with patch.object(gw, "_remote_request",
                          return_value=(0, {"ok": False, "error": "remote_timeout"})):
            _, data = gw._coalesced_remote_get(aid, sighting, fed_path)

        assert data["stale_reason"] == "remote_timeout"
        assert isinstance(data["stale_age_ms"], int)
        assert data["stale_age_ms"] >= 0

    def test_stale_returned_on_backoff(self):
        """When appliance is in backoff and stale data exists, return stale instead of backoff error."""
        aid = "c" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/equaliser"
        self._prime_stale(aid, fed_path, data={"ok": True, "eq_cached": True})
        with gw._state_lock:
            gw._backoff_state[(aid, fed_path)] = (time.monotonic() + 10, 0)

        with patch.object(gw, "_remote_request") as mock_req:
            status, data = gw._coalesced_remote_get(aid, sighting, fed_path)

        mock_req.assert_not_called()
        assert status == 200
        assert data.get("stale") is True
        assert data.get("stale_reason") == "remote_backoff"
        assert "retry_after" in data

    def test_stale_backoff_includes_retry_after(self):
        """Stale response for a backoff case must include retry_after."""
        aid = "d" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        self._prime_stale(aid, fed_path)
        with gw._state_lock:
            gw._backoff_state[(aid, fed_path)] = (time.monotonic() + 5, 0)

        _, data = gw._coalesced_remote_get(aid, sighting, fed_path)

        assert data.get("stale") is True
        assert data.get("retry_after", 0) >= 1

    def test_no_stale_after_stale_ttl(self):
        """Past stale_until, a transport failure returns the error, not stale data."""
        aid = "e" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        now = time.monotonic()
        with gw._state_lock:
            gw._read_cache[(aid, fed_path)] = {
                "data": {"ok": True},
                "cached_at": now - 20.0,
                "fresh_until": now - 16.0,
                "stale_until": now - 1.0,   # stale window also expired
            }

        with patch.object(gw, "_remote_request",
                          return_value=(0, {"ok": False, "error": "remote_timeout"})):
            status, data = gw._coalesced_remote_get(aid, sighting, fed_path)

        assert status == 0
        assert data["error"] == "remote_timeout"

    def test_stale_not_returned_when_remote_succeeds(self):
        """If the remote call succeeds, fresh data is returned, not the stale copy."""
        aid = "f" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        self._prime_stale(aid, fed_path, data={"ok": True, "old": True})

        fresh = {"ok": True, "fresh": True}
        with patch.object(gw, "_remote_request", return_value=(200, fresh)):
            status, data = gw._coalesced_remote_get(aid, sighting, fed_path)

        assert data.get("fresh") is True
        assert "stale" not in data

    def test_stale_does_not_mutate_cached_data(self):
        """_stale_response must not mutate the original cached dict."""
        aid = "g" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        original = {"ok": True, "key": "value"}
        self._prime_stale(aid, fed_path, data=original)

        with patch.object(gw, "_remote_request",
                          return_value=(0, {"ok": False, "error": "remote_timeout"})):
            gw._coalesced_remote_get(aid, sighting, fed_path)

        # Original cached data must not have been modified
        assert "stale" not in original

    def test_waiter_gets_stale_on_owner_failure(self):
        """A coalesced waiter must get stale data when the owner's request fails."""
        aid = "h" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        self._prime_stale(aid, fed_path, data={"ok": True, "waiter_stale": True})

        results = [None, None]
        call_count = [0]

        def slow_fail(*args, **kwargs):
            call_count[0] += 1
            time.sleep(0.2)
            return 0, {"ok": False, "error": "remote_timeout"}

        with patch.object(gw, "_remote_request", side_effect=slow_fail):
            def call_get(idx):
                results[idx] = gw._coalesced_remote_get(aid, sighting, fed_path)

            t1 = threading.Thread(target=call_get, args=(0,))
            t2 = threading.Thread(target=call_get, args=(1,))
            t1.start()
            time.sleep(0.05)
            t2.start()
            t1.join(timeout=5)
            t2.join(timeout=5)

        assert call_count[0] == 1, "Only one HTTP request (coalescing)"
        for s, d in results:
            assert s == 200
            assert d.get("stale") is True
            assert d.get("waiter_stale") is True

    def test_no_backoff_without_stale_data(self):
        """When in backoff and no stale data exists, return the backoff error as before."""
        aid = "i" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        with gw._state_lock:
            gw._backoff_state[(aid, fed_path)] = (time.monotonic() + 10, 0)

        with patch.object(gw, "_remote_request") as mock_req:
            status, data = gw._coalesced_remote_get(aid, sighting, fed_path)

        mock_req.assert_not_called()
        assert status == 0
        assert data["error"] == "remote_backoff"

    def test_definitive_error_not_served_stale(self):
        """Application errors like appliance_unconfigured must pass through, not serve stale."""
        aid = "j" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        self._prime_stale(aid, fed_path, data={"ok": True, "cached": True})

        with patch.object(gw, "_remote_request",
                          return_value=(200, {"ok": False, "error": "appliance_unconfigured"})):
            status, data = gw._coalesced_remote_get(aid, sighting, fed_path)

        assert data.get("error") == "appliance_unconfigured"
        assert "stale" not in data

    def test_waiter_gets_owner_error_for_definitive_failure(self):
        """Waiter must receive the actual application error, not stale data."""
        aid = "k" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        self._prime_stale(aid, fed_path, data={"ok": True, "cached": True})

        results = [None, None]

        def slow_definitive(*args, **kwargs):
            time.sleep(0.2)
            return 200, {"ok": False, "error": "appliance_identity_unavailable"}

        with patch.object(gw, "_remote_request", side_effect=slow_definitive):
            def call_get(idx):
                results[idx] = gw._coalesced_remote_get(aid, sighting, fed_path)

            t1 = threading.Thread(target=call_get, args=(0,))
            t2 = threading.Thread(target=call_get, args=(1,))
            t1.start()
            time.sleep(0.05)
            t2.start()
            t1.join(timeout=5)
            t2.join(timeout=5)

        for s, d in results:
            assert d.get("error") == "appliance_identity_unavailable"
            assert "stale" not in d

    def test_waiter_stale_reason_matches_owner_error(self):
        """Stale reason for a waiter must use the actual owner error, not remote_timeout."""
        aid = "l" * 20
        sighting = _make_sighting(appliance_id=aid)
        fed_path = "/api/federation/v1/home"
        self._prime_stale(aid, fed_path, data={"ok": True, "cached": True})

        results = [None, None]

        def slow_bad_response(*args, **kwargs):
            time.sleep(0.2)
            return 0, {"ok": False, "error": "remote_bad_response"}

        with patch.object(gw, "_remote_request", side_effect=slow_bad_response):
            def call_get(idx):
                results[idx] = gw._coalesced_remote_get(aid, sighting, fed_path)

            t1 = threading.Thread(target=call_get, args=(0,))
            t2 = threading.Thread(target=call_get, args=(1,))
            t1.start()
            time.sleep(0.05)
            t2.start()
            t1.join(timeout=5)
            t2.join(timeout=5)

        for s, d in results:
            assert s == 200
            assert d.get("stale") is True
            assert d.get("stale_reason") == "remote_bad_response"


# ---------------------------------------------------------------------------
# Endpoint-scoped backoff isolation
# ---------------------------------------------------------------------------

class TestEndpointScopedBackoff:
    """Backoff on one fed_path must not affect a different fed_path for the same appliance."""

    def test_home_backoff_does_not_block_equaliser(self):
        """/home backoff must not prevent /equaliser from making a remote call."""
        aid = "j" * 20
        sighting = _make_sighting(appliance_id=aid)
        home_path = "/api/federation/v1/home"
        eq_path = "/api/federation/v1/equaliser"
        with gw._state_lock:
            gw._backoff_state[(aid, home_path)] = (time.monotonic() + 30, 2)

        eq_data = {"ok": True, "equaliser": True}
        with patch.object(gw, "_remote_request", return_value=(200, eq_data)) as mock_req:
            status, data = gw._coalesced_remote_get(aid, sighting, eq_path)

        mock_req.assert_called_once()
        assert status == 200
        assert data.get("equaliser") is True

    def test_equaliser_backoff_does_not_block_home(self):
        """/equaliser backoff must not prevent /home from making a remote call."""
        aid = "k" * 20
        sighting = _make_sighting(appliance_id=aid)
        home_path = "/api/federation/v1/home"
        eq_path = "/api/federation/v1/equaliser"
        with gw._state_lock:
            gw._backoff_state[(aid, eq_path)] = (time.monotonic() + 30, 2)

        home_data = {"ok": True, "home": True}
        with patch.object(gw, "_remote_request", return_value=(200, home_data)) as mock_req:
            status, data = gw._coalesced_remote_get(aid, sighting, home_path)

        mock_req.assert_called_once()
        assert status == 200
        assert data.get("home") is True

    def test_write_backoff_uses_write_scope(self):
        """POST _update_backoff must use '*write*' scope, not the POST path."""
        aid = "l" * 20
        key = (aid, "*write*")
        with gw._state_lock:
            gw._backoff_state.pop(key, None)
        gw._update_backoff(key, 0, {"ok": False, "error": "remote_timeout"})
        assert key in gw._backoff_state
        # GET path must still be clear
        get_key = (aid, "/api/federation/v1/home")
        assert get_key not in gw._backoff_state


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
             patch.object(gw, "_coalesced_remote_get", return_value=(200, remote_data)), \
             patch("autostream_appliance_gateway.send_json",
                   side_effect=lambda h, c, d: (sent_codes.append(c), sent_data.append(d))):
            gw.send_gateway_home_json(handler, state, "a" * 20)

        assert sent_codes == [200]
        assert sent_data[0]["ok"] is True


# ---------------------------------------------------------------------------
# _handle_remote_response — error normalization
# ---------------------------------------------------------------------------

class TestHandleRemoteResponse:
    """Unknown error codes must be normalized to remote_bad_response, not exposed."""

    def _call(self, status, data):
        handler = _make_handler()
        sent_codes = []
        sent_errors = []

        def fake_json(h, code, d):
            sent_codes.append(code)
            sent_errors.append(d.get("error"))

        def fake_browser_err(h, code, error, *, retryable=None, extra=None):
            sent_codes.append(code)
            sent_errors.append(error)

        with patch("autostream_appliance_gateway.send_json", side_effect=fake_json), \
             patch("autostream_appliance_gateway.send_browser_api_error",
                   side_effect=fake_browser_err):
            gw._handle_remote_response(handler, "a" * 20, status, data)

        return sent_codes, sent_errors

    def test_success_forwarded_directly(self):
        codes, _ = self._call(200, {"ok": True, "data": "x"})
        assert codes == [200]

    def test_unknown_error_code_mapped_to_target_error(self):
        """An unrecognized error from a reachable target maps to 500 target_error."""
        codes, errors = self._call(500, {"ok": False, "error": "some_internal_state"})
        assert codes == [500]
        assert errors == ["target_error"]

    def test_appliance_unconfigured_mapped_to_409(self):
        codes, errors = self._call(409, {"ok": False, "error": "appliance_unconfigured"})
        assert codes == [409]
        assert errors == ["appliance_unconfigured"]

    def test_remote_timeout_mapped_to_504(self):
        codes, errors = self._call(0, {"ok": False, "error": "remote_timeout"})
        assert codes == [504]
        assert errors == ["remote_timeout"]

    def test_rate_limited_mapped_to_429(self):
        codes, errors = self._call(429, {"ok": False, "error": "rate_limited", "retry_after": 30})
        assert codes == [429]
        assert errors == ["rate_limited"]


# ---------------------------------------------------------------------------
# Debug logging
# ---------------------------------------------------------------------------

class TestGatewayLogging:
    """Verify that key gateway events emit debug log messages."""

    _VALID_TOKEN = "a" * 40
    _SESSION_RESP = {
        "ok": True,
        "token": "a" * 40,
        "token_type": "Bearer",
        "expires_in": 600,
        "federation_version": 1,
    }

    # -- Backoff transitions -------------------------------------------------

    def test_backoff_set_logged_on_failure(self, caplog):
        aid = "a" * 20
        key = (aid, "/api/federation/v1/home")
        with caplog.at_level(logging.DEBUG):
            with gw._state_lock:
                gw._record_failure_locked(key)
        assert any("backoff set" in r.message and aid in r.message for r in caplog.records)

    def test_backoff_set_includes_delay_and_step(self, caplog):
        aid = "b" * 20
        key = (aid, "/api/federation/v1/home")
        with caplog.at_level(logging.DEBUG):
            with gw._state_lock:
                gw._record_failure_locked(key)
        msg = next(r.message for r in caplog.records if "backoff set" in r.message)
        assert "1s" in msg  # first failure → step 0 → 1 second
        assert "step 0" in msg

    def test_backoff_cleared_logged_on_success(self, caplog):
        aid = "a" * 20
        key = (aid, "/api/federation/v1/home")
        with gw._state_lock:
            gw._record_failure_locked(key)  # pre-set (logged, but outside caplog scope)
        with caplog.at_level(logging.DEBUG):
            with gw._state_lock:
                gw._record_success_locked(key)
        assert any("backoff cleared" in r.message and aid in r.message for r in caplog.records)

    def test_backoff_not_logged_when_already_clear(self, caplog):
        key = ("a" * 20, "/api/federation/v1/home")  # no prior failure → nothing to clear
        with caplog.at_level(logging.DEBUG):
            with gw._state_lock:
                gw._record_success_locked(key)
        assert not any("backoff cleared" in r.message for r in caplog.records)

    def test_serving_backoff_logged(self, caplog):
        aid = "a" * 20
        scope = "/api/federation/v1/home"
        handler = _make_handler()
        with gw._state_lock:
            gw._backoff_state[(aid, scope)] = (time.monotonic() + 10, 0)
        with caplog.at_level(logging.DEBUG), \
             patch("autostream_appliance_gateway.send_browser_api_error"):
            gw._check_and_emit_backoff(handler, aid, scope)
        assert any("serving backoff" in r.message and aid in r.message for r in caplog.records)

    def test_no_serving_backoff_log_when_not_in_backoff(self, caplog):
        aid = "a" * 20
        scope = "/api/federation/v1/home"
        handler = _make_handler()
        with caplog.at_level(logging.DEBUG), \
             patch("autostream_appliance_gateway.send_browser_api_error"):
            gw._check_and_emit_backoff(handler, aid, scope)
        assert not any("serving backoff" in r.message for r in caplog.records)

    # -- Token acquisition ---------------------------------------------------

    def test_token_acquisition_attempt_logged(self, caplog):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        with patch.object(gw, "_remote_federation_request",
                          return_value=(0, {"ok": False, "error": "remote_timeout"})):
            with caplog.at_level(logging.DEBUG):
                gw._acquire_token(aid, sighting)
        assert any("acquiring token" in r.message and aid in r.message for r in caplog.records)

    def test_token_transport_failure_logged(self, caplog):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        with patch.object(gw, "_remote_federation_request",
                          return_value=(0, {"ok": False, "error": "remote_timeout"})):
            with caplog.at_level(logging.DEBUG):
                gw._acquire_token(aid, sighting)
        assert any("transport failure" in r.message and aid in r.message for r in caplog.records)

    def test_token_rate_limited_logged(self, caplog):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        with patch.object(gw, "_remote_federation_request",
                          return_value=(429, {"ok": False, "error": "rate_limited",
                                             "retry_after": 30})):
            with caplog.at_level(logging.DEBUG):
                gw._acquire_token(aid, sighting)
        assert any("rate-limited" in r.message and aid in r.message for r in caplog.records)

    def test_token_rejection_logged(self, caplog):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        with patch.object(gw, "_remote_federation_request",
                          return_value=(409, {"ok": False, "error": "appliance_unconfigured"})):
            with caplog.at_level(logging.DEBUG):
                gw._acquire_token(aid, sighting)
        assert any("token acquisition rejected" in r.message and "HTTP 409" in r.message
                   for r in caplog.records)

    def test_token_acquired_logged(self, caplog):
        aid = "a" * 20
        sighting = _make_sighting(appliance_id=aid)
        with patch.object(gw, "_remote_federation_request",
                          return_value=(200, self._SESSION_RESP)):
            with caplog.at_level(logging.DEBUG):
                gw._acquire_token(aid, sighting)
        assert any("token acquired" in r.message and aid in r.message for r in caplog.records)

    # -- Transport layer -----------------------------------------------------

    def test_socket_timeout_logged(self, caplog):
        import socket as _socket
        sighting = _make_sighting()
        with patch("autostream_appliance_gateway.http.client.HTTPConnection") as MockConn:
            MockConn.return_value.request.side_effect = _socket.timeout("timed out")
            with caplog.at_level(logging.DEBUG):
                gw._remote_federation_request("GET", sighting, "/api/federation/v1/home", "tok")
        assert any("socket timeout" in r.message for r in caplog.records)

    def test_connection_error_logged(self, caplog):
        sighting = _make_sighting()
        with patch("autostream_appliance_gateway.http.client.HTTPConnection") as MockConn:
            MockConn.return_value.request.side_effect = ConnectionRefusedError()
            with caplog.at_level(logging.DEBUG):
                gw._remote_federation_request("GET", sighting, "/api/federation/v1/home", "tok")
        assert any("connection error" in r.message for r in caplog.records)

    def test_successful_response_logged(self, caplog):
        sighting = _make_sighting()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheader.return_value = "application/json"
        mock_resp.read.return_value = json.dumps({"ok": True}).encode()
        with patch("autostream_appliance_gateway.http.client.HTTPConnection") as MockConn:
            MockConn.return_value.sock = MagicMock()
            MockConn.return_value.getresponse.return_value = mock_resp
            with caplog.at_level(logging.DEBUG):
                gw._remote_federation_request("GET", sighting, "/api/federation/v1/home", "tok")
        assert any("fed response" in r.message and "HTTP 200" in r.message for r in caplog.records)

    def test_token_not_logged_in_transport(self, caplog):
        """Bearer token must never appear in any log message."""
        secret = "s3cr3t" + "x" * 34  # 40-char token
        sighting = _make_sighting()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheader.return_value = "application/json"
        mock_resp.read.return_value = json.dumps({"ok": True}).encode()
        with patch("autostream_appliance_gateway.http.client.HTTPConnection") as MockConn:
            MockConn.return_value.sock = MagicMock()
            MockConn.return_value.getresponse.return_value = mock_resp
            with caplog.at_level(logging.DEBUG):
                gw._remote_federation_request("GET", sighting, "/foo", secret)
        assert not any(secret in r.message for r in caplog.records)

    # -- Browser error response ----------------------------------------------

    def test_error_response_to_browser_logged(self, caplog):
        aid = "a" * 20
        handler = _make_handler()
        with patch("autostream_appliance_gateway.send_browser_api_error"), \
             caplog.at_level(logging.DEBUG):
            gw._handle_remote_response(
                handler, aid, 0, {"ok": False, "error": "remote_timeout"},
            )
        assert any("error response" in r.message and aid in r.message for r in caplog.records)

    def test_success_response_not_logged_as_error(self, caplog):
        aid = "a" * 20
        handler = _make_handler()
        with patch("autostream_appliance_gateway.send_json"), \
             caplog.at_level(logging.DEBUG):
            gw._handle_remote_response(handler, aid, 200, {"ok": True})
        assert not any("error response" in r.message for r in caplog.records)
