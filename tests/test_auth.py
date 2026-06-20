"""Tests for AuthManager.

Covers:
1. _client_key uses raw IP, not SHA-256 hash.
2. Nonce lifecycle: issue, single-use consumption, expiry.
3. Session lifecycle: authenticated, unauthenticated, expiry.
4. Rate limiting: blocks after MAX_FAILED_ATTEMPTS, clears on success.
5. require_authenticated_if_pin_enabled: allows when no PIN, allows with
   valid session, returns 401 JSON without redirect_path, redirects with it.
6. POST auth: a single login session permits repeated saves without re-prompting.
"""
import sys
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_auth import (
    AuthManager,
    MAX_FAILED_ATTEMPTS,
    MAX_NONCES_PER_CLIENT,
    PIN_STATUS_MISSING,
    PIN_STATUS_UNREADABLE,
    SESSION_COOKIE_NAME,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_manager(pin: Optional[str] = None) -> AuthManager:
    """Return an AuthManager with a pre-loaded (or absent) PIN."""
    mgr = AuthManager(config_path="dummy.json", state_path="dummy_state.json")
    mgr._pin_loaded = True
    if pin is not None:
        mgr._pin_value = pin
        mgr._pin_status = "ok"
    else:
        mgr._pin_value = None
        mgr._pin_status = PIN_STATUS_MISSING
    return mgr


def _make_handler(
    session_token: Optional[str] = None,
    ip: str = "192.168.1.1",
    xff: str = "",
) -> MagicMock:
    """Return a minimal mock HTTP handler."""
    handler = MagicMock()
    cookie = f"{SESSION_COOKIE_NAME}={session_token}" if session_token else ""
    handler.headers = {
        "Cookie": cookie,
        "X-Forwarded-For": xff,
        "X-Real-IP": "",
    }
    handler.client_address = (ip, 0)
    handler.wfile = MagicMock()
    return handler


def _authenticated_session(mgr: AuthManager) -> str:
    """Create a live authenticated session; return its token."""
    sess = mgr._new_session()
    mgr._sessions[sess.token] = sess
    return sess.token


# ---------------------------------------------------------------------------
# 1. _client_key — raw IP, no SHA-256
# ---------------------------------------------------------------------------

class TestClientKey:
    def test_xff_used_when_present(self):
        mgr = _make_manager()
        handler = _make_handler(xff="10.0.0.5, 10.0.0.1")
        assert mgr._client_key(handler) == "10.0.0.5"

    def test_socket_ip_used_as_fallback(self):
        mgr = _make_manager()
        handler = _make_handler(ip="192.168.1.42")
        key = mgr._client_key(handler)
        assert key == "192.168.1.42"

    def test_key_is_not_sha256_hex(self):
        mgr = _make_manager()
        handler = _make_handler(ip="192.168.1.1")
        key = mgr._client_key(handler)
        # A SHA-256 hex digest is always 64 lowercase hex chars.
        assert len(key) != 64 or not all(c in "0123456789abcdef" for c in key)


# ---------------------------------------------------------------------------
# 2. Nonce lifecycle
# ---------------------------------------------------------------------------

class TestNonceLifecycle:
    def test_issued_nonce_can_be_consumed(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        val = mgr._issue_nonce(handler)
        assert mgr._consume_nonce(handler, val) is True

    def test_nonce_consumed_only_once(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        val = mgr._issue_nonce(handler)
        mgr._consume_nonce(handler, val)
        assert mgr._consume_nonce(handler, val) is False

    def test_wrong_nonce_value_rejected(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        mgr._issue_nonce(handler)
        assert mgr._consume_nonce(handler, "wrong-value") is False

    def test_expired_nonce_rejected(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        val = mgr._issue_nonce(handler)
        key = mgr._client_key(handler)
        # _nonces is now a nested dict: client_key → {nonce_value → Nonce}
        mgr._nonces[key][val].expires_at = 0
        assert mgr._consume_nonce(handler, val) is False


# ---------------------------------------------------------------------------
# 3. Session lifecycle
# ---------------------------------------------------------------------------

class TestSessionLifecycle:
    def test_authenticated_session_passes(self):
        mgr = _make_manager(pin="testpin1")
        token = _authenticated_session(mgr)
        handler = _make_handler(session_token=token)
        assert mgr.is_authenticated(handler.headers) is True

    def test_unauthenticated_session_fails(self):
        mgr = _make_manager(pin="testpin1")
        sess = mgr._new_session()
        sess.authenticated = False
        mgr._sessions[sess.token] = sess
        handler = _make_handler(session_token=sess.token)
        assert mgr.is_authenticated(handler.headers) is False

    def test_unknown_token_fails(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler(session_token="nonexistent-token")
        assert mgr.is_authenticated(handler.headers) is False

    def test_expired_session_fails(self):
        mgr = _make_manager(pin="testpin1")
        sess = mgr._new_session()
        sess.expires_at = 0
        mgr._sessions[sess.token] = sess
        handler = _make_handler(session_token=sess.token)
        assert mgr.is_authenticated(handler.headers) is False

    def test_no_cookie_fails(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        assert mgr.is_authenticated(handler.headers) is False


# ---------------------------------------------------------------------------
# 4. Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimiting:
    def test_not_blocked_initially(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        blocked, _ = mgr._rate_limit_check(handler)
        assert blocked is False

    def test_blocked_after_max_failures(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        for _ in range(MAX_FAILED_ATTEMPTS):
            mgr._rate_limit_fail(handler)
        blocked, retry_after = mgr._rate_limit_check(handler)
        assert blocked is True
        assert retry_after > 0

    def test_clears_on_success(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        for _ in range(MAX_FAILED_ATTEMPTS):
            mgr._rate_limit_fail(handler)
        mgr._rate_limit_success(handler)
        blocked, _ = mgr._rate_limit_check(handler)
        assert blocked is False

    def test_retry_after_increases_with_more_failures(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        for _ in range(MAX_FAILED_ATTEMPTS):
            mgr._rate_limit_fail(handler)
        _, retry1 = mgr._rate_limit_check(handler)
        mgr._rate_limit_fail(handler)
        _, retry2 = mgr._rate_limit_check(handler)
        assert retry2 >= retry1


# ---------------------------------------------------------------------------
# 5. require_authenticated_if_pin_enabled
# ---------------------------------------------------------------------------

class TestRequireAuthIfPinEnabled:
    def test_allows_when_no_pin_configured(self):
        mgr = _make_manager(pin=None)
        handler = _make_handler()
        assert mgr.require_authenticated_if_pin_enabled(handler) is True
        handler.send_response.assert_not_called()

    def test_allows_valid_authenticated_session(self):
        mgr = _make_manager(pin="testpin1")
        token = _authenticated_session(mgr)
        handler = _make_handler(session_token=token)
        assert mgr.require_authenticated_if_pin_enabled(handler) is True
        handler.send_response.assert_not_called()

    def test_returns_401_json_without_redirect_path(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        result = mgr.require_authenticated_if_pin_enabled(handler)
        assert result is False
        handler.send_response.assert_called_once_with(401)

    def test_returns_false_and_redirects_with_redirect_path(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        result = mgr.require_authenticated_if_pin_enabled(handler, redirect_path="/setup")
        assert result is False
        # A redirect is a 302
        handler.send_response.assert_called_once_with(302)
        # Location header must point to /auth
        location_calls = [
            call for call in handler.send_header.call_args_list
            if call.args[0] == "Location"
        ]
        assert len(location_calls) == 1
        assert location_calls[0].args[1].startswith("/auth")

    def test_redirect_path_encoded_in_next_param(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        mgr.require_authenticated_if_pin_enabled(handler, redirect_path="/setup")
        location_calls = [
            call.args[1]
            for call in handler.send_header.call_args_list
            if call.args[0] == "Location"
        ]
        assert location_calls and "/setup" in location_calls[0]


# ---------------------------------------------------------------------------
# 6. POST auth: one login permits repeated saves without re-prompting
# ---------------------------------------------------------------------------

class TestPostAuthPreservesSession:
    def test_single_login_permits_multiple_saves(self):
        """A session established at login allows multiple subsequent POSTs."""
        mgr = _make_manager(pin="testpin1")
        token = _authenticated_session(mgr)

        for i in range(3):
            handler = _make_handler(session_token=token)
            result = mgr.require_authenticated_if_pin_enabled(handler)
            assert result is True, f"save {i + 1} should pass without re-prompting"
            handler.send_response.assert_not_called()

    def test_unauthenticated_request_blocked_even_with_csrf_session(self):
        """A UI session that was never authenticated cannot POST to protected routes."""
        mgr = _make_manager(pin="testpin1")
        # Simulate an unauthenticated session (issued by ensure_session for page visits)
        sess = mgr._new_session()
        sess.authenticated = False
        mgr._sessions[sess.token] = sess

        handler = _make_handler(session_token=sess.token)
        result = mgr.require_authenticated_if_pin_enabled(handler)
        assert result is False
        handler.send_response.assert_called_once_with(401)

    def test_pin_change_revokes_old_session(self):
        """After set_pin(), the old session is revoked and a new one is needed."""
        mgr = _make_manager(pin="oldpin")
        old_token = _authenticated_session(mgr)

        # Simulate a PIN change
        with patch.object(mgr, '_read_pin_override', return_value=(None, None, None, PIN_STATUS_MISSING, False)), \
             patch('autostream_auth.write_pin_override'):
            mgr.set_pin("newpin")

        handler = _make_handler(session_token=old_token)
        assert mgr.is_authenticated(handler.headers) is False


# ---------------------------------------------------------------------------
# 7. Malformed state file — graceful degradation
# ---------------------------------------------------------------------------

class TestMalformedStateFile:

    def test_get_pin_if_enabled_treats_malformed_state_as_unreadable(self, tmp_path):
        """JSONDecodeError from load_state is caught; result is None and status UNREADABLE."""
        state = tmp_path / "state.json"
        state.write_text("{not valid json}")
        mgr = AuthManager(config_path="dummy.ini", state_path=str(state))
        result = mgr.get_pin_if_enabled()
        assert result is None
        assert mgr.get_pin_status() == PIN_STATUS_UNREADABLE

    def test_set_pin_returns_500_on_malformed_state(self, tmp_path):
        """JSONDecodeError inside write_pin_override is caught and returns HTTP 500."""
        state = tmp_path / "state.json"
        state.write_text("{not valid json}")
        mgr = AuthManager(config_path="dummy.json", state_path=str(state))
        # Pre-load a valid PIN so the format check passes before the write attempt.
        mgr._pin_loaded = True
        mgr._pin_value = "currentpin"
        mgr._pin_status = "ok"
        code, body = mgr.set_pin("newpin1234")
        assert code == 500
        assert body["ok"] is False


# ---------------------------------------------------------------------------
# 8. Multi-nonce per client and concurrency safety
# ---------------------------------------------------------------------------

class TestMultiNoncePerClient:
    """Two nonces issued to the same client can be consumed independently."""

    def test_two_nonces_both_usable(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        v1 = mgr._issue_nonce(handler)
        v2 = mgr._issue_nonce(handler)
        assert v1 != v2
        # Both should be consumable
        assert mgr._consume_nonce(handler, v1) is True
        assert mgr._consume_nonce(handler, v2) is True

    def test_consuming_one_nonce_leaves_other_intact(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        v1 = mgr._issue_nonce(handler)
        v2 = mgr._issue_nonce(handler)
        # Consume v1; v2 must still be valid
        mgr._consume_nonce(handler, v1)
        assert mgr._consume_nonce(handler, v2) is True

    def test_wrong_proof_consumes_only_the_attempted_nonce(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        v1 = mgr._issue_nonce(handler)
        v2 = mgr._issue_nonce(handler)
        # Wrong proof for v1 (simulate: try to consume v1 with wrong value — returns False)
        # Actually _consume_nonce looks up by nonce value not by proof.
        # The test should show that consuming v1 (even if the proof is wrong at
        # the application level) does NOT affect v2.
        mgr._consume_nonce(handler, v1)   # consumes v1 regardless
        # v2 is untouched
        assert mgr._consume_nonce(handler, v2) is True

    def test_nonce_cannot_be_consumed_by_different_client(self):
        mgr = _make_manager(pin="testpin1")
        h1 = _make_handler(ip="10.0.0.1")
        h2 = _make_handler(ip="10.0.0.2")
        val = mgr._issue_nonce(h1)
        # h2 should not be able to consume h1's nonce
        assert mgr._consume_nonce(h2, val) is False
        # The nonce must still be available to h1
        assert mgr._consume_nonce(h1, val) is True

    def test_expired_nonce_in_bucket_does_not_affect_valid_sibling(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        v1 = mgr._issue_nonce(handler)
        v2 = mgr._issue_nonce(handler)
        key = mgr._client_key(handler)
        # Expire v1
        mgr._nonces[key][v1].expires_at = 0
        # v1 is expired → consume fails
        assert mgr._consume_nonce(handler, v1) is False
        # v2 is still valid
        assert mgr._consume_nonce(handler, v2) is True

    def test_gc_removes_empty_bucket_after_all_nonces_consumed(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        key = mgr._client_key(handler)
        val = mgr._issue_nonce(handler)
        mgr._consume_nonce(handler, val)
        # After consumption the bucket should be removed by _consume_nonce
        assert key not in mgr._nonces

    def test_gc_removes_expired_nonces_and_empty_buckets(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        key = mgr._client_key(handler)
        val = mgr._issue_nonce(handler)
        # Expire the nonce
        mgr._nonces[key][val].expires_at = 0
        mgr._gc()
        assert key not in mgr._nonces

    def test_cap_prunes_oldest_when_limit_reached(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        issued = []
        for _ in range(MAX_NONCES_PER_CLIENT + 2):
            issued.append(mgr._issue_nonce(handler))
        key = mgr._client_key(handler)
        # Bucket must not exceed the cap
        assert len(mgr._nonces[key]) <= MAX_NONCES_PER_CLIENT
        # The most recently issued nonces should still be present
        assert issued[-1] in mgr._nonces[key]

    def test_nonce_single_use_prevents_replay(self):
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        val = mgr._issue_nonce(handler)
        assert mgr._consume_nonce(handler, val) is True
        # Second consumption must fail (replay protection)
        assert mgr._consume_nonce(handler, val) is False


class TestConcurrencySafety:
    """Concurrent operations on _sessions, _nonces, and _attempts must not corrupt state."""

    def test_concurrent_session_creation_does_not_raise(self):
        import threading as _t
        mgr = _make_manager(pin="testpin1")
        errors = []

        def _create():
            try:
                sess = mgr._new_session()
                with mgr._lock:
                    mgr._sessions[sess.token] = sess
            except Exception as e:
                errors.append(e)

        threads = [_t.Thread(target=_create) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors, f"Errors during concurrent session creation: {errors}"
        assert len(mgr._sessions) == 20

    def test_concurrent_nonce_issue_does_not_raise(self):
        import threading as _t
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        errors = []

        def _issue():
            try:
                mgr._issue_nonce(handler)
            except Exception as e:
                errors.append(e)

        threads = [_t.Thread(target=_issue) for _ in range(MAX_NONCES_PER_CLIENT * 3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors, f"Errors during concurrent nonce issue: {errors}"
        key = mgr._client_key(handler)
        # Bucket must not exceed the cap
        assert len(mgr._nonces.get(key, {})) <= MAX_NONCES_PER_CLIENT

    def test_concurrent_gc_and_issue_do_not_corrupt(self):
        import threading as _t
        mgr = _make_manager(pin="testpin1")
        handler = _make_handler()
        errors = []

        def _gc_loop():
            for _ in range(50):
                try:
                    mgr._gc()
                except Exception as e:
                    errors.append(e)

        def _issue_loop():
            for _ in range(50):
                try:
                    mgr._issue_nonce(handler)
                except Exception as e:
                    errors.append(e)

        t1 = _t.Thread(target=_gc_loop)
        t2 = _t.Thread(target=_issue_loop)
        t1.start(); t2.start()
        t1.join(timeout=5); t2.join(timeout=5)

        assert not errors, f"Errors during concurrent gc/issue: {errors}"
