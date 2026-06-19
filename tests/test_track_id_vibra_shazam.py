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

from track_id.vibra_client import VibraClient
from track_id.vibra_shazam import (
    PROVIDER_ID,
    VibraRateLimitedError,
    VibraRecognitionError,
    VibraShazamProvider,
)
from track_id.models import TrackIDRateLimitedError, TrackIdentificationResult


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
# VibraClient — JSON framing and fake socket tests
# ---------------------------------------------------------------------------

def _make_fake_socket_server(response_json: dict):
    """Return (server_thread, socket_path) for a single-connection fake daemon."""
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


@pytest.mark.skipif(sys.platform == "win32", reason="Unix sockets not available on Windows")
class TestVibraClientFakeSocket:

    def test_recognize_matched_response(self):
        resp = _matched_response()
        _t, path = _make_fake_socket_server(resp)
        client = VibraClient(socket_path=path)
        try:
            result = client.recognize(_PCM, 16000)
        finally:
            client.close()
        assert result.get("ok") is True
        assert result.get("matched") is True

    def test_ping_pong(self):
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


# ---------------------------------------------------------------------------
# VibraClient — reconnect and retry
# ---------------------------------------------------------------------------

class TestVibraClientRetry:

    def test_recognize_retry_succeeds_after_first_failure(self):
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
             patch.object(client, "close"):
            result = client._recognize_with_retry(_PCM, 16000)
        assert result == {"ok": True, "matched": False}

    def test_recognize_raises_after_two_failures(self):
        """recognize() raises OSError when both attempts fail."""
        client = VibraClient()

        def always_fail(pcm, rate):
            raise OSError("permanent failure")

        with patch.object(client, "_do_recognize", side_effect=always_fail), \
             patch.object(client, "connect", return_value=True), \
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
