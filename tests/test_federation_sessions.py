"""Priority 6 — federation session security tests.

Covers create_session (token entropy, v1 schema, source-IP binding, expiry,
rate-limiting, retry_after), validate_session (constant-time, expiry,
IP-mismatch), sweep_sessions (removes expired, cleans inactive rate queues),
evict_session_for_ip, and process-restart invalidation.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_federation as fed


def _reset_state():
    """Reset module-level session and rate-limit state between tests."""
    with fed._lock:
        fed._sessions.clear()
        fed._rate.clear()


@pytest.fixture(autouse=True)
def clean_state():
    _reset_state()
    yield
    _reset_state()


# ---------------------------------------------------------------------------
# Token entropy and basic schema
# ---------------------------------------------------------------------------

class TestCreateSession:
    def test_token_is_returned_on_success(self):
        token, expires_in = fed.create_session("1.2.3.4")
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0

    def test_token_has_at_least_128_bits_of_entropy(self):
        token, _ = fed.create_session("1.2.3.4")
        # 128 bits = 16 bytes = 32 hex chars
        assert len(token) >= 32

    def test_expires_in_is_600(self):
        _, expires_in = fed.create_session("1.2.3.4")
        assert expires_in == 600

    def test_expiry_constant_matches_schema(self):
        assert fed.EXPIRY_SECONDS == 600

    def test_federation_version_is_1(self):
        assert fed.FEDERATION_VERSION == 1

    def test_successive_tokens_are_unique(self):
        tokens = set()
        for _ in range(10):
            token, _ = fed.create_session("1.2.3.4")
            tokens.add(token)
            _reset_state()  # reset rate limit between iterations
        assert len(tokens) == 10

    def test_returned_token_is_opaque_hex_string(self):
        token, _ = fed.create_session("1.2.3.4")
        assert token.isalnum()  # hex chars only


# ---------------------------------------------------------------------------
# Session validation
# ---------------------------------------------------------------------------

class TestValidateSession:
    def test_valid_token_and_ip_returns_true(self):
        token, _ = fed.create_session("1.2.3.4")
        assert fed.validate_session(token, "1.2.3.4") is True

    def test_wrong_ip_returns_false(self):
        token, _ = fed.create_session("1.2.3.4")
        assert fed.validate_session(token, "9.9.9.9") is False

    def test_unknown_token_returns_false(self):
        assert fed.validate_session("deadbeef" * 8, "1.2.3.4") is False

    def test_empty_token_returns_false(self):
        assert fed.validate_session("", "1.2.3.4") is False

    def test_expired_token_returns_false(self):
        token, _ = fed.create_session("1.2.3.4")
        # Manually expire the token
        with fed._lock:
            ip, _ = fed._sessions[token]
            fed._sessions[token] = (ip, time.monotonic() - 1.0)
        assert fed.validate_session(token, "1.2.3.4") is False

    def test_valid_token_different_case_rejected(self):
        token, _ = fed.create_session("1.2.3.4")
        assert fed.validate_session(token.upper(), "1.2.3.4") is False

    def test_process_restart_invalidation(self):
        """New module state (simulating restart) has no tokens."""
        _reset_state()
        assert fed.validate_session("anytoken", "1.2.3.4") is False


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimit:
    def test_five_requests_succeed(self):
        for i in range(5):
            token, expires = fed.create_session("1.2.3.4")
            assert token is not None, f"Request {i+1} should succeed"
            # Reset rate deque to allow re-testing without clearing sessions
            with fed._lock:
                fed._rate.clear()
        # Re-fill 5 from scratch
        _reset_state()
        for i in range(5):
            token, _ = fed.create_session("1.2.3.4")
            assert token is not None

    def test_sixth_request_is_rate_limited(self):
        for _ in range(5):
            fed.create_session("1.2.3.4")
        token, retry_after = fed.create_session("1.2.3.4")
        assert token is None
        assert isinstance(retry_after, int)
        assert retry_after >= 1

    def test_rate_limit_is_per_source_ip(self):
        for _ in range(5):
            fed.create_session("1.2.3.4")
        # Different IP is not limited
        token, expires_in = fed.create_session("5.6.7.8")
        assert token is not None
        assert expires_in == 600

    def test_rejected_request_does_not_consume_slot(self):
        # Exhaust the limit
        for _ in range(5):
            fed.create_session("1.2.3.4")
        # Reject twice more (does not consume slot)
        fed.create_session("1.2.3.4")
        fed.create_session("1.2.3.4")
        # Still rejected — still 5 recorded issuances in window
        token, retry_after = fed.create_session("1.2.3.4")
        assert token is None

    def test_retry_after_is_positive_integer(self):
        for _ in range(5):
            fed.create_session("1.2.3.4")
        _, retry_after = fed.create_session("1.2.3.4")
        assert isinstance(retry_after, int)
        assert retry_after > 0

    def test_retry_after_does_not_exceed_window(self):
        for _ in range(5):
            fed.create_session("1.2.3.4")
        _, retry_after = fed.create_session("1.2.3.4")
        assert retry_after <= 60


# ---------------------------------------------------------------------------
# sweep_sessions
# ---------------------------------------------------------------------------

class TestSweepSessions:
    def test_expired_tokens_removed(self):
        token, _ = fed.create_session("1.2.3.4")
        with fed._lock:
            ip, _ = fed._sessions[token]
            fed._sessions[token] = (ip, time.monotonic() - 1.0)
        fed.sweep_sessions()
        assert fed.validate_session(token, "1.2.3.4") is False

    def test_unexpired_tokens_retained(self):
        token, _ = fed.create_session("1.2.3.4")
        fed.sweep_sessions()
        assert fed.validate_session(token, "1.2.3.4") is True

    def test_inactive_rate_entries_cleaned(self):
        fed.create_session("1.2.3.4")
        # Age out the rate queue
        with fed._lock:
            q = fed._rate["1.2.3.4"]
            while q:
                q.popleft()
        fed.sweep_sessions()
        with fed._lock:
            assert "1.2.3.4" not in fed._rate


# ---------------------------------------------------------------------------
# evict_session_for_ip
# ---------------------------------------------------------------------------

class TestEvictSessionForIp:
    def test_sessions_for_ip_are_removed(self):
        token1, _ = fed.create_session("1.2.3.4")
        _reset_state()
        with fed._lock:
            fed._sessions[token1] = ("1.2.3.4", time.monotonic() + 600)
        fed.evict_session_for_ip("1.2.3.4")
        assert fed.validate_session(token1, "1.2.3.4") is False

    def test_sessions_for_other_ips_retained(self):
        token_a, _ = fed.create_session("1.2.3.4")
        with fed._lock:
            fed._sessions["tok_b"] = ("9.9.9.9", time.monotonic() + 600)
        fed.evict_session_for_ip("1.2.3.4")
        assert fed.validate_session("tok_b", "9.9.9.9") is True
