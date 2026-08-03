"""Tests for VibraShazamProvider and VibraClient."""
from __future__ import annotations

import json
import socket
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

from track_id.vibra_client import VibraClient, VibraRuntimeInfo
from track_id.vibra_shazam import (
    PROVIDER_ID,
    VibraRateLimitedError,
    VibraRecognitionError,
    VibraUpstreamRejectionError,
    VibraShazamProvider,
    get_vibra_runtime_info,
    refresh_vibra_runtime_info,
)
from track_id.models import (
    TrackIDRateLimitedError,
    TrackIDUpstreamRejectionError,
    TrackIdentificationResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PCM = b"\x00" * (16000 * 2 * 15)  # 15 s of silence @ 16 kHz s16le mono


def _fake_client(response: dict) -> VibraClient:
    """Return a VibraClient whose recognize() returns the given response dict."""
    client = MagicMock(spec=VibraClient)
    client.recognize.return_value = response
    return client


def _matched_response(**overrides) -> dict:
    base = {
        "ok": True,
        "matched": True,
        "title": "Test Track",
        "artist": "Test Artist",
        "artwork_url": "https://example.com/art.jpg",
    }
    base.update(overrides)
    return base


def _valid_pong(version: str = "1.0.0") -> dict:
    return {"ok": True, "type": "pong", "version": version}


def _make_fake_socket_server(response_json: dict):
    """Return (server_thread, socket_path) for a single-request fake daemon (ping only)."""
    path = f"/tmp/test_vibra_{threading.get_ident()}_{id(response_json)}.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        import os
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        srv.bind(path)
        srv.listen(1)
        srv.settimeout(2.0)
    except Exception:
        srv.close()
        raise

    response_bytes = (json.dumps(response_json, separators=(",", ":")) + "\n").encode()

    def _serve():
        try:
            conn, _ = srv.accept()
            with conn:
                buf = b""
                while b"\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                # Read any binary payload (based on "frames" field in JSON header).
                try:
                    header = json.loads(buf.split(b"\n")[0])
                    if header.get("type") == "recognize":
                        frames = int(header.get("frames", 0))
                        remaining = frames * 2  # s16le
                        # Drain already-received bytes after newline.
                        after_nl = buf.split(b"\n", 1)[1] if b"\n" in buf else b""
                        remaining -= len(after_nl)
                        while remaining > 0:
                            chunk = conn.recv(min(remaining, 4096))
                            if not chunk:
                                break
                            remaining -= len(chunk)
                except Exception:
                    pass
                conn.sendall(response_bytes)
        except Exception:
            pass
        finally:
            srv.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return t, path


def _make_fake_daemon(pong: dict, recognize_response: dict):
    """Return (thread, path) for a daemon that handles ping→pong then recognize→response."""
    import os
    path = f"/tmp/test_vibra_daemon_{threading.get_ident()}_{id(pong)}.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        srv.bind(path)
        srv.listen(1)
        srv.settimeout(3.0)
    except Exception:
        srv.close()
        raise

    pong_bytes = (json.dumps(pong, separators=(",", ":")) + "\n").encode()
    resp_bytes = (json.dumps(recognize_response, separators=(",", ":")) + "\n").encode()

    received = []

    def _drain_line(conn):
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return None, buf
            buf += chunk
        nl = buf.index(b"\n")
        return buf[:nl], buf[nl + 1:]

    def _serve():
        try:
            conn, _ = srv.accept()
            with conn:
                conn.settimeout(3.0)
                # Handle ping
                line, leftover = _drain_line(conn)
                if line is None:
                    return
                received.append(line)
                conn.sendall(pong_bytes)
                # Handle recognize
                buf = leftover
                while b"\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                nl = buf.index(b"\n")
                hdr_bytes = buf[:nl]
                received.append(hdr_bytes)
                try:
                    header = json.loads(hdr_bytes)
                    if header.get("type") == "recognize":
                        after_nl = buf[nl + 1:]
                        remaining = int(header.get("frames", 0)) * 2 - len(after_nl)
                        while remaining > 0:
                            chunk = conn.recv(min(remaining, 4096))
                            if not chunk:
                                break
                            remaining -= len(chunk)
                except Exception:
                    pass
                conn.sendall(resp_bytes)
        except Exception:
            pass
        finally:
            srv.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    t._received = received
    return t, path


def _make_recording_daemon(responses: list):
    """Daemon that records every received line and responds from responses list."""
    import os
    path = f"/tmp/test_vibra_rec_{threading.get_ident()}_{id(responses)}.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        srv.bind(path)
        srv.listen(1)
        srv.settimeout(3.0)
    except Exception:
        srv.close()
        raise

    received_lines = []

    def _serve():
        try:
            conn, _ = srv.accept()
            with conn:
                conn.settimeout(3.0)
                for resp in responses:
                    buf = b""
                    while b"\n" not in buf:
                        chunk = conn.recv(4096)
                        if not chunk:
                            return
                        buf += chunk
                    nl = buf.index(b"\n")
                    received_lines.append(buf[:nl])
                    resp_bytes = (json.dumps(resp, separators=(",", ":")) + "\n").encode()
                    conn.sendall(resp_bytes)
        except Exception:
            pass
        finally:
            srv.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    t._received_lines = received_lines
    return t, path


# ---------------------------------------------------------------------------
# VibraShazamProvider.identify() — happy paths
# ---------------------------------------------------------------------------

class TestVibraShazamProviderIdentify:

    def test_matched_response_returns_result(self):
        provider = VibraShazamProvider({}, client=_fake_client(_matched_response()))
        result = provider.identify(_PCM, 16000)
        assert isinstance(result, TrackIdentificationResult)
        assert result.matched is True
        assert result.title == "Test Track"
        assert result.artist == "Test Artist"
        assert result.provider == PROVIDER_ID

    def test_matched_response_includes_artwork(self):
        provider = VibraShazamProvider({}, client=_fake_client(_matched_response()))
        result = provider.identify(_PCM, 16000)
        assert result.artwork is not None
        assert result.artwork.url == "https://example.com/art.jpg"

    def test_matched_no_artwork_url_gives_no_artwork(self):
        resp = _matched_response()
        del resp["artwork_url"]
        provider = VibraShazamProvider({}, client=_fake_client(resp))
        result = provider.identify(_PCM, 16000)
        assert result.artwork is None

    def test_empty_artwork_url_gives_no_artwork(self):
        provider = VibraShazamProvider({}, client=_fake_client(_matched_response(artwork_url="")))
        result = provider.identify(_PCM, 16000)
        assert result.artwork is None

    def test_no_match_response_returns_not_matched(self):
        provider = VibraShazamProvider({}, client=_fake_client({"ok": True, "matched": False}))
        result = provider.identify(_PCM, 16000)
        assert result.matched is False
        assert result.provider == PROVIDER_ID

    def test_passes_rate_16000_to_client(self):
        client = _fake_client(_matched_response())
        provider = VibraShazamProvider({}, client=client)
        provider.identify(_PCM, 16000)
        _, kwargs = client.recognize.call_args
        args, _ = client.recognize.call_args
        assert args[1] == 16000 or kwargs.get("rate") == 16000

    def test_passes_pcm_bytes_to_client(self):
        client = _fake_client(_matched_response())
        provider = VibraShazamProvider({}, client=client)
        provider.identify(_PCM, 16000)
        args, _ = client.recognize.call_args
        assert args[0] == _PCM


# ---------------------------------------------------------------------------
# VibraShazamProvider.identify() — error paths
# ---------------------------------------------------------------------------

class TestVibraShazamProviderErrors:

    def test_ok_false_rate_limited_raises_vibra_rate_limited_error(self):
        resp = {"ok": False, "error": "rate_limited"}
        provider = VibraShazamProvider({}, client=_fake_client(resp))
        with pytest.raises(VibraRateLimitedError):
            provider.identify(_PCM, 16000)

    def test_vibra_rate_limited_error_is_subclass_of_track_id_rate_limited_error(self):
        assert issubclass(VibraRateLimitedError, TrackIDRateLimitedError)

    def test_ok_false_other_raises_vibra_recognition_error(self):
        resp = {"ok": False, "error": "fingerprint_failed"}
        provider = VibraShazamProvider({}, client=_fake_client(resp))
        with pytest.raises(VibraRecognitionError):
            provider.identify(_PCM, 16000)

    def test_ok_false_no_error_field_raises_vibra_recognition_error(self):
        resp = {"ok": False}
        provider = VibraShazamProvider({}, client=_fake_client(resp))
        with pytest.raises(VibraRecognitionError):
            provider.identify(_PCM, 16000)

    def test_ok_false_http_403_raises_vibra_upstream_rejection_error(self):
        resp = {"ok": False, "error": "upstream_error", "http_status": 403}
        provider = VibraShazamProvider({}, client=_fake_client(resp))
        with pytest.raises(VibraUpstreamRejectionError) as exc_info:
            provider.identify(_PCM, 16000)
        assert exc_info.value.http_status == 403

    def test_ok_false_http_406_raises_vibra_upstream_rejection_error(self):
        resp = {"ok": False, "error": "upstream_error", "http_status": 406}
        provider = VibraShazamProvider({}, client=_fake_client(resp))
        with pytest.raises(VibraUpstreamRejectionError) as exc_info:
            provider.identify(_PCM, 16000)
        assert exc_info.value.http_status == 406

    def test_vibra_upstream_rejection_error_is_subclass_of_track_id_upstream_rejection_error(self):
        assert issubclass(VibraUpstreamRejectionError, TrackIDUpstreamRejectionError)

    def test_ok_false_http_200_does_not_raise_upstream_rejection(self):
        """Non-rejection http_status must not raise VibraUpstreamRejectionError."""
        resp = {"ok": False, "error": "fingerprint_failed", "http_status": 200}
        provider = VibraShazamProvider({}, client=_fake_client(resp))
        with pytest.raises(VibraRecognitionError):
            provider.identify(_PCM, 16000)

    def test_client_oserror_propagates(self):
        client = MagicMock(spec=VibraClient)
        client.recognize.side_effect = OSError("connection failed")
        provider = VibraShazamProvider({}, client=client)
        with pytest.raises(OSError):
            provider.identify(_PCM, 16000)


# ---------------------------------------------------------------------------
# VibraShazamProvider.fingerprint_pcm()
# ---------------------------------------------------------------------------

class TestVibraShazamProviderFingerprint:

    def test_fingerprint_pcm_always_returns_none(self):
        provider = VibraShazamProvider({}, client=_fake_client(_matched_response()))
        assert provider.fingerprint_pcm(_PCM, 16000) is None


# ---------------------------------------------------------------------------
# VibraClient — JSON framing and fake socket tests (single-request)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform == "win32", reason="Unix sockets not available on Windows")
class TestVibraClientFakeSocket:

    def test_recognize_matched_response(self):
        """recognize() goes through ping/pong handshake then recognize."""
        resp = _matched_response()
        _t, path = _make_fake_daemon(_valid_pong(), resp)
        client = VibraClient(socket_path=path)
        try:
            result = client.recognize(_PCM, 16000)
        finally:
            client.close()
        assert result.get("ok") is True
        assert result.get("matched") is True

    def test_ping_pong(self):
        """The public ping() method (used in tests/low-level callers) still works."""
        pong = {"type": "pong"}
        _t, path = _make_fake_socket_server(pong)
        client = VibraClient(socket_path=path)
        assert client.connect()
        try:
            resp = client.ping()
            assert resp.get("type") == "pong"
        finally:
            client.close()

    def test_connect_to_missing_socket_returns_false(self):
        client = VibraClient(socket_path="/tmp/nonexistent_vibra_test.sock")
        assert client.connect() is False
        assert not client.is_connected()

    def test_recognize_to_missing_socket_raises_oserror(self):
        client = VibraClient(socket_path="/tmp/nonexistent_vibra_test.sock")
        with pytest.raises(OSError):
            client.recognize(_PCM, 16000)


class TestVibraClientRecoveryLog:
    """connect()'s first success after a failure must emit exactly one
    recovery WARNING -- production runs at WARN level, so the connect
    failure warning alone would otherwise show no evidence the daemon
    connection ever came back."""

    def test_connect_failure_then_success_logs_one_recovery_warning(self, caplog):
        client = VibraClient(socket_path="/tmp/nonexistent_vibra_test_recovery.sock")
        with caplog.at_level("WARNING", logger="root"):
            assert client.connect() is False
        assert not any("recovered after" in r.getMessage() for r in caplog.records)

        pong = {"type": "pong"}
        _t, path = _make_fake_socket_server(pong)
        client._socket_path = path
        caplog.clear()
        try:
            with caplog.at_level("WARNING", logger="root"):
                assert client.connect() is True
        finally:
            client.close()

        recovered = [r for r in caplog.records if "recovered after" in r.getMessage()]
        assert len(recovered) == 1
        assert "vibra-mini connection recovered after 1 failure(s)" in recovered[0].getMessage()

    def test_connect_success_first_logs_no_recovery_warning(self, caplog):
        pong = {"type": "pong"}
        _t, path = _make_fake_socket_server(pong)
        client = VibraClient(socket_path=path)
        try:
            with caplog.at_level("WARNING", logger="root"):
                assert client.connect() is True
        finally:
            client.close()

        assert not any("recovered after" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# VibraClient — reconnect and retry
# ---------------------------------------------------------------------------

class TestVibraClientRetry:

    def test_recognize_retry_succeeds_after_first_io_failure(self):
        """recognize() retries once on OSError from _do_recognize."""
        client = VibraClient()
        responses = iter([OSError("eof"), {"ok": True, "matched": False}])

        def fake_do_recognize(pcm, rate):
            val = next(responses)
            if isinstance(val, Exception):
                raise val
            return val

        with patch.object(client, "_do_recognize", side_effect=fake_do_recognize), \
             patch.object(client, "connect", return_value=True), \
             patch.object(client, "_ping_and_record_runtime_info", return_value=True), \
             patch.object(client, "close"):
            result = client._recognize_with_retry(_PCM, 16000)
        assert result == {"ok": True, "matched": False}

    def test_recognize_retry_succeeds_after_initial_connect_failure(self):
        """recognize() retries once when the first connect() returns False."""
        client = VibraClient()
        connect_results = iter([False, True])

        def fake_connect():
            return next(connect_results)

        with patch.object(client, "connect", side_effect=fake_connect), \
             patch.object(client, "_ping_and_record_runtime_info", return_value=True), \
             patch.object(client, "_do_recognize", return_value={"ok": True, "matched": False}), \
             patch.object(client, "close"):
            result = client._recognize_with_retry(_PCM, 16000)
        assert result == {"ok": True, "matched": False}

    def test_recognize_raises_after_two_connect_failures(self):
        """recognize() raises OSError when both connect() attempts fail."""
        client = VibraClient()
        with patch.object(client, "connect", return_value=False), \
             patch.object(client, "close"):
            with pytest.raises(OSError):
                client._recognize_with_retry(_PCM, 16000)

    def test_recognize_raises_after_two_io_failures(self):
        """recognize() raises OSError when both _do_recognize attempts fail."""
        client = VibraClient()

        def always_fail(pcm, rate):
            raise OSError("permanent failure")

        with patch.object(client, "_do_recognize", side_effect=always_fail), \
             patch.object(client, "connect", return_value=True), \
             patch.object(client, "_ping_and_record_runtime_info", return_value=True), \
             patch.object(client, "close"):
            with pytest.raises(OSError):
                client._recognize_with_retry(_PCM, 16000)


# ---------------------------------------------------------------------------
# Shared singleton client
# ---------------------------------------------------------------------------

class TestSharedClientSingleton:

    def test_two_providers_share_same_client(self):
        import track_id.vibra_shazam as mod
        original = mod._shared_client
        mod._shared_client = None
        try:
            p1 = VibraShazamProvider({})
            p2 = VibraShazamProvider({})
            assert p1._client is p2._client
        finally:
            mod._shared_client = original

    def test_injectable_client_not_shared(self):
        c1 = _fake_client(_matched_response())
        c2 = _fake_client(_matched_response())
        p1 = VibraShazamProvider({}, client=c1)
        p2 = VibraShazamProvider({}, client=c2)
        assert p1._client is not p2._client


# ---------------------------------------------------------------------------
# WP1 — Vibra runtime metadata tests
# ---------------------------------------------------------------------------

class TestVibraClientRuntimeMetadata:
    """Tests for VibraClient runtime version/connected snapshot."""

    # Test 1 — wire request format
    @pytest.mark.skipif(sys.platform == "win32", reason="Unix sockets not available on Windows")
    def test_handshake_wire_request_is_compact_ping(self):
        """The handshake sends exactly {"type":"ping"}\\n."""
        pong = _valid_pong()
        _t, path = _make_recording_daemon([pong, _matched_response()])
        client = VibraClient(socket_path=path)
        try:
            client.recognize(_PCM, 16000)
        except Exception:
            pass
        finally:
            client.close()
        _t.join(timeout=2)
        assert _t._received_lines, "server received no data"
        ping_line = _t._received_lines[0]
        assert ping_line == b'{"type":"ping"}', (
            f"Expected compact ping, got {ping_line!r}"
        )

    # Test 2 — valid pong updates version and connected
    def test_valid_pong_records_version_and_connected(self):
        client = VibraClient()
        # Initially unknown / disconnected
        info = client.get_runtime_info()
        assert info.version == "unknown"
        assert info.connected is False

        with patch.object(client, "connect", return_value=True), \
             patch.object(client, "_sock", create=True):
            # Inject a mock socket so settimeout and close work without error
            mock_sock = MagicMock()
            client._sock = mock_sock
            pong_resp = {"ok": True, "type": "pong", "version": "1.0.0"}
            with patch.object(client, "_sendall", return_value=True), \
                 patch.object(client, "_read_response", return_value=pong_resp):
                result = client._ping_and_record_runtime_info()

        assert result is True
        info = client.get_runtime_info()
        assert info.version == "1.0.0"
        assert info.connected is True

    # Test 3 — invalid pong variations don't produce a successful version
    @pytest.mark.parametrize("bad_pong", [
        {"ok": False, "type": "pong", "version": "1.0.0"},      # ok is False
        {"ok": 1, "type": "pong", "version": "1.0.0"},          # ok is int, not True
        {"ok": "true", "type": "pong", "version": "1.0.0"},     # ok is string
        {"ok": True, "type": "ping", "version": "1.0.0"},       # wrong type
        {"ok": True, "type": "pong", "version": ""},            # blank version
        {"ok": True, "type": "pong", "version": "  "},          # whitespace-only version
        {"ok": True, "type": "pong"},                            # missing version
        "not a dict",                                            # non-object JSON
        None,                                                    # EOF / invalid JSON
    ])
    def test_invalid_pong_does_not_produce_successful_version(self, bad_pong):
        client = VibraClient()
        mock_sock = MagicMock()
        client._sock = mock_sock

        read_resp = bad_pong if isinstance(bad_pong, (dict, type(None))) else None

        with patch.object(client, "_sendall", return_value=True), \
             patch.object(client, "_read_response", return_value=read_resp):
            result = client._ping_and_record_runtime_info()

        assert result is False
        assert client.get_runtime_info().version == "unknown"
        assert client.get_runtime_info().connected is False

    # Test 4 — missing socket and EOF return unknown without raising
    def test_missing_socket_does_not_raise_returns_unknown(self):
        """Platform-independent: connect failure returns unknown without raising."""
        client = VibraClient(socket_path="/tmp/nonexistent_vibra_test2.sock")
        # Mock connect to return False — avoids AF_UNIX unavailability on Windows
        # and exercises the same code path as a real missing socket.
        with patch.object(client, "connect", return_value=False):
            info = client.refresh_runtime_info()
        assert info.version == "unknown"
        assert info.connected is False

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix sockets not available on Windows")
    def test_eof_from_daemon_returns_unknown_without_raising(self):
        """EOF during handshake leaves version unknown and doesn't raise."""
        import os
        path = f"/tmp/test_vibra_eof_{threading.get_ident()}.sock"
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        srv.bind(path)
        srv.listen(1)
        srv.settimeout(2.0)

        def _eof_server():
            try:
                conn, _ = srv.accept()
                conn.close()  # immediate EOF
            except Exception:
                pass
            finally:
                srv.close()

        threading.Thread(target=_eof_server, daemon=True).start()

        client = VibraClient(socket_path=path)
        info = client.refresh_runtime_info()
        assert info.version == "unknown"
        assert info.connected is False

    # Test 5 — successful version retained after later failure
    def test_last_seen_version_retained_after_failure(self):
        client = VibraClient()
        mock_sock = MagicMock()
        client._sock = mock_sock

        # First: successful handshake
        with patch.object(client, "_sendall", return_value=True), \
             patch.object(client, "_read_response",
                          return_value={"ok": True, "type": "pong", "version": "2.3.4"}):
            client._ping_and_record_runtime_info()

        assert client.get_runtime_info().version == "2.3.4"

        # Second: EOF failure — version must be retained, connected must become False
        client._sock = MagicMock()  # re-attach socket so we enter the method
        with patch.object(client, "_sendall", return_value=True), \
             patch.object(client, "_read_response", return_value=None), \
             patch.object(client, "close"):
            # Patch close() to prevent it being a no-op that skips _set_runtime_info;
            # the implementation now calls _set_runtime_info(connected=False) explicitly.
            client._ping_and_record_runtime_info()

        info = client.get_runtime_info()
        assert info.version == "2.3.4"
        assert info.connected is False

    # Test 6 — get_runtime_info performs no I/O and no lock contention
    def test_get_runtime_info_does_not_acquire_recognition_lock(self):
        client = VibraClient()
        acquired = client._lock.acquire(blocking=False)
        assert acquired, "lock should be free initially"
        try:
            # get_runtime_info must not try to acquire _lock (would deadlock)
            info = client.get_runtime_info()
        finally:
            client._lock.release()
        assert info.version == "unknown"
        assert info.connected is False

    def test_get_runtime_info_is_zero_io(self):
        client = VibraClient()
        with patch.object(client, "connect") as mock_connect, \
             patch.object(client, "_sendall") as mock_send, \
             patch.object(client, "_readline") as mock_recv:
            client.get_runtime_info()
            mock_connect.assert_not_called()
            mock_send.assert_not_called()
            mock_recv.assert_not_called()

    # Test 7 — handshake and recognition cannot interleave
    def test_handshake_and_recognition_cannot_interleave(self):
        """refresh_runtime_info() blocks while recognition holds the lock."""
        client = VibraClient()
        recognize_started = threading.Event()
        recognize_may_finish = threading.Event()

        def slow_do_recognize(pcm, rate):
            recognize_started.set()
            recognize_may_finish.wait(timeout=5)
            return {"ok": True, "matched": False}

        with patch.object(client, "connect", return_value=True), \
             patch.object(client, "_ping_and_record_runtime_info", return_value=True), \
             patch.object(client, "_do_recognize", side_effect=slow_do_recognize):
            recog_thread = threading.Thread(
                target=client.recognize, args=(_PCM, 16000)
            )
            recog_thread.start()
            recognize_started.wait(timeout=5)

            # Lock is now held by recognition thread
            refresh_done = threading.Event()

            def do_refresh():
                client.refresh_runtime_info()
                refresh_done.set()

            refresh_thread = threading.Thread(target=do_refresh)
            refresh_thread.start()

            # Refresh must still be blocked while recognition is running
            assert not refresh_done.wait(timeout=0.1), (
                "refresh_runtime_info() should block while recognition holds the lock"
            )

            recognize_may_finish.set()
            recog_thread.join(timeout=5)
            assert refresh_done.wait(timeout=5), (
                "refresh_runtime_info() did not complete after recognition finished"
            )

    # Test 8 — handshake timeout is restored before recognition
    def test_handshake_timeout_restored_to_command_timeout(self):
        """After a successful handshake, COMMAND_TIMEOUT is restored on the socket."""
        client = VibraClient()
        mock_sock = MagicMock()
        client._sock = mock_sock
        timeout_values = []

        def record_settimeout(t):
            timeout_values.append(t)

        mock_sock.settimeout.side_effect = record_settimeout

        pong_resp = {"ok": True, "type": "pong", "version": "1.0.0"}
        with patch.object(client, "_sendall", return_value=True), \
             patch.object(client, "_read_response", return_value=pong_resp):
            result = client._ping_and_record_runtime_info()

        assert result is True
        assert len(timeout_values) >= 2
        assert timeout_values[0] == VibraClient.HANDSHAKE_TIMEOUT
        assert timeout_values[-1] == VibraClient.COMMAND_TIMEOUT

    # Test 9 — failed handshake prevents recognition on that connection
    def test_failed_handshake_prevents_recognition_on_same_connection(self):
        """If handshake fails, _do_recognize must not be called on that connection."""
        client = VibraClient()
        do_recognize_calls = []

        def fake_do_recognize(pcm, rate):
            do_recognize_calls.append((pcm, rate))
            return {"ok": True, "matched": False}

        # Handshake fails both times → should raise, never call _do_recognize
        with patch.object(client, "connect", return_value=True), \
             patch.object(client, "_ping_and_record_runtime_info", return_value=False), \
             patch.object(client, "_do_recognize", side_effect=fake_do_recognize), \
             patch.object(client, "close"):
            with pytest.raises(OSError):
                client._recognize_with_retry(_PCM, 16000)

        assert do_recognize_calls == [], (
            "_do_recognize must not be called when handshake fails"
        )

    # Test 10 is covered by TestVibraClientRetry above (existing tests updated)

    # Test 11 — two providers, startup refresh, and runtime functions use same shared client
    def test_runtime_functions_use_shared_client(self):
        import track_id.vibra_shazam as mod
        original = mod._shared_client
        mod._shared_client = None
        try:
            p1 = VibraShazamProvider({})
            shared = p1._client

            # get_vibra_runtime_info reads from the same client
            info = get_vibra_runtime_info()
            assert isinstance(info, VibraRuntimeInfo)

            # The shared client is the one used by both providers and functions
            p2 = VibraShazamProvider({})
            assert p1._client is p2._client
            assert p1._client is mod._shared_client
        finally:
            mod._shared_client = original

    # Test 12 — startup refresh runs in background and does not delay startup
    def test_refresh_vibra_runtime_info_never_raises(self):
        """refresh_vibra_runtime_info() must not propagate exceptions."""
        import track_id.vibra_shazam as mod
        original = mod._shared_client
        # Replace with a client that fails at connect
        client = VibraClient(socket_path="/tmp/nonexistent_vibra_refresh_test.sock")
        mod._shared_client = client
        try:
            refresh_vibra_runtime_info()  # must not raise
        finally:
            mod._shared_client = original

    def test_startup_refresh_thread_does_not_block_caller(self):
        """Starting refresh_vibra_runtime_info in a daemon thread is non-blocking."""
        start = time.monotonic()
        t = threading.Thread(target=refresh_vibra_runtime_info, daemon=True)
        t.start()
        elapsed = time.monotonic() - start
        # Starting the thread must be nearly instantaneous
        assert elapsed < 0.5, f"Starting refresh thread took {elapsed:.3f}s"

    # Test 13 — refresh_runtime_info acquires recognition lock
    def test_refresh_runtime_info_acquires_recognition_lock(self):
        """refresh_runtime_info() must block while the recognition lock is held."""
        client = VibraClient()

        # Manually hold the recognition lock
        acquired = client._lock.acquire(blocking=False)
        assert acquired, "lock should be free"

        refresh_done = threading.Event()

        def do_refresh():
            # Mock connect so no real socket creation is needed
            with patch.object(client, "connect", return_value=False):
                client.refresh_runtime_info()
            refresh_done.set()

        t = threading.Thread(target=do_refresh)
        t.start()

        # Should still be blocked
        assert not refresh_done.wait(timeout=0.1), (
            "refresh_runtime_info() should block while _lock is held"
        )

        client._lock.release()
        assert refresh_done.wait(timeout=5), (
            "refresh_runtime_info() did not complete after lock release"
        )
        t.join(timeout=5)

    def test_refresh_runtime_info_uses_canonical_handshake_not_raw_ping(self):
        """refresh_runtime_info() must call _ping_and_record_runtime_info, not ping()."""
        client = VibraClient()
        with patch.object(client, "connect", return_value=True), \
             patch.object(client, "_ping_and_record_runtime_info", return_value=True) as mock_hs, \
             patch.object(client, "ping") as mock_ping:
            client.refresh_runtime_info()
        mock_hs.assert_called_once()
        mock_ping.assert_not_called()
