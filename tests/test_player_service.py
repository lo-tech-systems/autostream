"""Priority 2 — Player service tests.

Covers resolve_backend (caching, TTL, per-URL isolation), fallback behavior
for failed detection, ensure_audio_fifo, and stop_and_disable_all.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_players as ap
import autostream_player_service as svc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clear_cache():
    svc._DETECTION_CACHE.clear()


def _resp(status=200, json_data=None):
    r = MagicMock()
    r.status_code = status
    r.ok = 200 <= status < 300
    r.text = ""
    r.content = b"x"
    r.json.return_value = json_data or {}
    return r


def _mini_config_resp():
    return _resp(json_data={"version": "1.0", "product_name": "owntone-mini"})


# ---------------------------------------------------------------------------
# resolve_backend — caching
# ---------------------------------------------------------------------------

class TestResolveBackendCache:
    def setup_method(self):
        _clear_cache()

    def test_cache_hit_returns_same_backend_id(self):
        with patch("autostream_players.requests.get",
                   return_value=_mini_config_resp()):
            r1 = svc.resolve_backend("http://localhost:3689")

        # Second call should hit cache without making network requests
        with patch("autostream_players.requests.get",
                   side_effect=Exception("must not call")) as mock_get:
            r2 = svc.resolve_backend("http://localhost:3689")
            mock_get.assert_not_called()

        assert r1.backend_id == r2.backend_id

    def test_different_urls_have_isolated_cache_entries(self):
        with patch("autostream_players.requests.get",
                   return_value=_mini_config_resp()):
            r_a = svc.resolve_backend("http://host-a:3689")

        # Separate URL triggers fresh detection. Detection order: mini first,
        # then full owntone. Mini needs 1 /api/config call (no product_name);
        # full needs /api/config + /api/settings — 3 requests total.
        config_full = {"version": "28.9"}
        settings_full = {"categories": [{"name": "misc"}]}
        responses = [
            _resp(json_data=config_full),   # mini probe /api/config → no match
            _resp(json_data=config_full),   # full probe /api/config
            _resp(json_data=settings_full), # full probe /api/settings
        ]
        with patch("autostream_players.requests.get", side_effect=responses):
            r_b = svc.resolve_backend("http://host-b:3689")

        assert r_a.backend_id == ap.BACKEND_OWNTONE_MINI
        assert r_b.backend_id == ap.BACKEND_OWNTONE

    def test_failed_detection_falls_back_to_owntone(self):
        import requests as rq
        exc = rq.RequestException("refused")
        with patch("autostream_players.requests.get", side_effect=exc):
            result = svc.resolve_backend("http://down:3689")
        assert result.backend_id == ap.BACKEND_OWNTONE

    def test_cache_ttl_expired_triggers_re_probe(self):
        with patch("autostream_players.requests.get",
                   return_value=_mini_config_resp()):
            svc.resolve_backend("http://localhost:3689")

        # Manually expire the cache entry
        url = svc._normalize_base_url("http://localhost:3689")
        old = svc._DETECTION_CACHE[url]
        svc._DETECTION_CACHE[url] = (
            old[0] - svc._DETECTION_CACHE_SECONDS - 1,
            old[1], old[2], old[3],
        )

        probe_called = {"n": 0}

        def counting_get(u, **kw):
            probe_called["n"] += 1
            return _mini_config_resp()

        with patch("autostream_players.requests.get", side_effect=counting_get):
            svc.resolve_backend("http://localhost:3689")

        assert probe_called["n"] > 0


# ---------------------------------------------------------------------------
# ensure_audio_fifo
# ---------------------------------------------------------------------------

class TestEnsureAudioFifo:
    def test_relative_path_returns_invalid_path(self):
        result = svc.ensure_audio_fifo("relative/path")
        assert result.ok is False
        assert result.error_code == "invalid_path"

    def test_empty_path_returns_invalid_path(self):
        result = svc.ensure_audio_fifo("")
        assert result.ok is False
        assert result.error_code == "invalid_path"

    def test_existing_fifo_returns_ok(self, tmp_path):
        fifo = tmp_path / "test.fifo"
        try:
            os.mkfifo(str(fifo))
        except (AttributeError, OSError):
            pytest.skip("os.mkfifo not available on this platform")
        result = svc.ensure_audio_fifo(str(fifo))
        assert result.ok is True
        assert result.created_fifo is False

    def test_existing_regular_file_returns_not_fifo(self, tmp_path):
        f = tmp_path / "notfifo"
        f.write_text("x")
        result = svc.ensure_audio_fifo(str(f))
        assert result.ok is False
        assert result.error_code == "not_fifo"

    def test_creates_fifo_when_absent(self, tmp_path):
        fifo = tmp_path / "subdir" / "audio.fifo"
        result = svc.ensure_audio_fifo(str(fifo))
        if result.error_code == "create_failed":
            pytest.skip("os.mkfifo not available on this platform")
        assert result.ok is True
        assert result.created_fifo is True
        assert stat.S_ISFIFO(os.stat(str(fifo)).st_mode)


# ---------------------------------------------------------------------------
# stop_and_disable_all
# ---------------------------------------------------------------------------

class TestStopAndDisableAll:
    def setup_method(self):
        _clear_cache()

    def _mock_backend(self, stop_ok=True, disable_ok=True):
        b = MagicMock()
        b.backend_id = "owntone"
        b.stop.return_value = ap.ActionResult(ok=stop_ok)
        b.set_selected_outputs.return_value = ap.ActionResult(ok=disable_ok)
        return b

    def test_both_succeed_returns_ok(self):
        b = self._mock_backend()
        with patch.object(svc, "resolve_backend",
                          return_value=svc.ResolvedBackend(backend_id="owntone", backend=b)):
            result = svc.stop_and_disable_all("http://localhost:3689")
        assert result.ok is True

    def test_stop_fails_still_calls_disable(self):
        b = self._mock_backend(stop_ok=False)
        with patch.object(svc, "resolve_backend",
                          return_value=svc.ResolvedBackend(backend_id="owntone", backend=b)):
            result = svc.stop_and_disable_all("http://localhost:3689")
        b.set_selected_outputs.assert_called_once()
        assert result.ok is False

    def test_disable_fails_returns_failure(self):
        b = self._mock_backend(disable_ok=False)
        with patch.object(svc, "resolve_backend",
                          return_value=svc.ResolvedBackend(backend_id="owntone", backend=b)):
            result = svc.stop_and_disable_all("http://localhost:3689")
        assert result.ok is False


# ---------------------------------------------------------------------------
# reconcile_fifo_with_backend
# ---------------------------------------------------------------------------

class TestReconcileFifoWithBackend:
    def setup_method(self):
        _clear_cache()

    def _make_backend(self, *, pipe_path=None, get_ok=True, save_ok=True,
                      unsupported=False, refresh_ok=True):
        b = MagicMock()
        b.backend_id = "owntone"
        get_result = MagicMock()
        get_result.ok = get_ok and not unsupported
        get_result.unsupported = unsupported
        get_result.error_code = "unsupported" if unsupported else ("" if get_ok else "read_failed")
        get_result.value = pipe_path
        get_result.message = "" if (get_ok or unsupported) else "read failed"
        get_result.error = "" if (get_ok or unsupported) else "read failed"
        b.get_setting.return_value = get_result

        save_result = MagicMock()
        save_result.ok = save_ok
        save_result.restart_required = False
        save_result.error = "" if save_ok else "save failed"
        save_result.error_code = "" if save_ok else "save_failed"
        save_result.message = "" if save_ok else "save failed"
        b.save_setting.return_value = save_result

        refresh_result = MagicMock()
        refresh_result.ok = refresh_ok
        refresh_result.error_code = "" if refresh_ok else "update_failed"
        refresh_result.error = "" if refresh_ok else "update failed"
        refresh_result.message = "" if refresh_ok else "update failed"
        refresh_result.detail = ""
        b.update_library.return_value = refresh_result
        return b

    def _resolved(self, backend):
        return svc.ResolvedBackend(backend_id="owntone", backend=backend)

    def test_fifo_ensure_failure_returns_error(self, tmp_path):
        f = tmp_path / "notfifo"
        f.write_text("x")  # regular file, not a FIFO
        result = svc.reconcile_fifo_with_backend("http://localhost:3689", str(f))
        assert result.ok is False
        assert result.error_code == "not_fifo"

    def test_empty_base_url_skips_backend(self, tmp_path):
        fifo = tmp_path / "a.fifo"
        try:
            os.mkfifo(str(fifo))
        except (AttributeError, OSError):
            pytest.skip("os.mkfifo not available")
        result = svc.reconcile_fifo_with_backend("", str(fifo))
        assert result.ok is True

    def test_matching_path_no_save_called(self, tmp_path):
        fifo = tmp_path / "a.fifo"
        try:
            os.mkfifo(str(fifo))
        except (AttributeError, OSError):
            pytest.skip("os.mkfifo not available")
        b = self._make_backend(pipe_path=str(fifo))
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b)):
            result = svc.reconcile_fifo_with_backend("http://localhost:3689", str(fifo))
        assert result.ok is True
        b.save_setting.assert_not_called()

    def test_changed_path_saves_new_fifo_path(self, tmp_path):
        fifo = tmp_path / "a.fifo"
        try:
            os.mkfifo(str(fifo))
        except (AttributeError, OSError):
            pytest.skip("os.mkfifo not available")
        b = self._make_backend(pipe_path="/old/path.fifo")
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b)), \
             patch.object(svc, "_request_library_update_with_retry",
                          return_value=MagicMock(ok=True, error="", error_code="", detail="")):
            result = svc.reconcile_fifo_with_backend("http://localhost:3689", str(fifo))
        assert result.ok is True
        b.save_setting.assert_called_once()
        args = b.save_setting.call_args[0]
        assert str(fifo) in str(args)

    def test_save_failure_returns_ok_with_warning(self, tmp_path):
        fifo = tmp_path / "a.fifo"
        try:
            os.mkfifo(str(fifo))
        except (AttributeError, OSError):
            pytest.skip("os.mkfifo not available")
        b = self._make_backend(pipe_path="/different/path", save_ok=False)
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b)):
            result = svc.reconcile_fifo_with_backend("http://localhost:3689", str(fifo))
        # save failure is non-fatal: ok=True but error info present
        assert result.ok is True
        assert result.error or result.error_code

    def test_unsupported_setting_skips_save(self, tmp_path):
        fifo = tmp_path / "a.fifo"
        try:
            os.mkfifo(str(fifo))
        except (AttributeError, OSError):
            pytest.skip("os.mkfifo not available")
        b = self._make_backend(unsupported=True)
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b)):
            result = svc.reconcile_fifo_with_backend("http://localhost:3689", str(fifo))
        assert result.ok is True
        b.save_setting.assert_not_called()

    def test_get_failure_returns_ok_with_warning(self, tmp_path):
        fifo = tmp_path / "a.fifo"
        try:
            os.mkfifo(str(fifo))
        except (AttributeError, OSError):
            pytest.skip("os.mkfifo not available")
        b = self._make_backend(get_ok=False)
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b)):
            result = svc.reconcile_fifo_with_backend("http://localhost:3689", str(fifo))
        assert result.ok is True
        assert result.error or result.error_code
