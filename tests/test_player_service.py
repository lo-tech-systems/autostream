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

    def test_failed_detection_fallback_is_not_confident(self):
        """A fallback selection carries detection_confident=False so
        enforcement callers (reconcile_monitor_format/
        reconcile_pipe_format_with_backend) know not to trust it as a real
        backend identity."""
        import requests as rq
        exc = rq.RequestException("refused")
        with patch("autostream_players.requests.get", side_effect=exc):
            result = svc.resolve_backend("http://down:3689")
        assert result.detection_confident is False

    def test_positive_match_is_confident(self):
        with patch("autostream_players.requests.get",
                   return_value=_mini_config_resp()):
            result = svc.resolve_backend("http://localhost:3689")
        assert result.backend_id == ap.BACKEND_OWNTONE_MINI
        assert result.detection_confident is True

    def test_cache_hit_preserves_confidence_flag(self):
        import requests as rq
        exc = rq.RequestException("refused")
        with patch("autostream_players.requests.get", side_effect=exc):
            r1 = svc.resolve_backend("http://down:3689")
        assert r1.detection_confident is False

        with patch("autostream_players.requests.get",
                   side_effect=Exception("must not call")):
            r2 = svc.resolve_backend("http://down:3689")
        assert r2.detection_confident is False

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


# ---------------------------------------------------------------------------
# reconcile_pipe_format_with_backend / retry_pending_format_reconcile
# ---------------------------------------------------------------------------
#
# _FormatReconcileTestHelpers is a plain mixin (no "Test" prefix, so pytest
# does not collect it on its own) shared by both test classes below so the
# backend-mocking helpers aren't duplicated.

class _FormatReconcileTestHelpers:
    def setup_method(self):
        _clear_cache()
        svc._format_reconcile_state.clear()

    def _resolved(self, backend, *, confident=True):
        return svc.ResolvedBackend(
            backend_id="owntone-mini", backend=backend, detection_confident=confident,
        )

    def _setting_result(self, *, ok=True, unsupported=False, value=None, error_code=""):
        r = MagicMock()
        r.ok = ok and not unsupported
        r.unsupported = unsupported
        r.value = value
        r.error = "" if r.ok else (error_code or "failed")
        r.error_code = "unsupported" if unsupported else ("" if r.ok else (error_code or "failed"))
        r.message = r.error or r.error_code
        return r

    def _save_result(self, *, ok=True, error_code=""):
        r = MagicMock()
        r.ok = ok
        r.error = "" if ok else (error_code or "save failed")
        r.error_code = "" if ok else (error_code or "save_failed")
        r.message = r.error or r.error_code
        r.restart_required = True
        return r

    def _make_backend(self, *, backend_rate=44100, backend_bits=16,
                       get_ok=True, save_ok=True, unsupported=False,
                       save_rate_ok=None, save_bits_ok=None, save_error_code=""):
        """save_rate_ok/save_bits_ok override save_ok per key (for split-
        failure scenarios: one key's save_setting succeeds, the other
        fails)."""
        b = MagicMock()
        b.backend_id = "owntone-mini"

        def get_setting(key):
            if key == ap.SETTING_PIPE_SAMPLE_RATE:
                return self._setting_result(ok=get_ok, unsupported=unsupported, value=backend_rate)
            if key == ap.SETTING_PIPE_BITS_PER_SAMPLE:
                return self._setting_result(ok=get_ok, unsupported=unsupported, value=backend_bits)
            raise AssertionError(f"unexpected get_setting key {key!r}")

        rate_ok = save_ok if save_rate_ok is None else save_rate_ok
        bits_ok = save_ok if save_bits_ok is None else save_bits_ok

        def save_setting(key, value):
            if key == ap.SETTING_PIPE_SAMPLE_RATE:
                return self._save_result(ok=rate_ok, error_code=save_error_code)
            if key == ap.SETTING_PIPE_BITS_PER_SAMPLE:
                return self._save_result(ok=bits_ok, error_code=save_error_code)
            raise AssertionError(f"unexpected save_setting key {key!r}")

        b.get_setting.side_effect = get_setting
        b.save_setting.side_effect = save_setting
        return b


class TestReconcilePipeFormatWithBackend(_FormatReconcileTestHelpers):
    def test_empty_base_url_is_noop(self):
        result = svc.reconcile_pipe_format_with_backend("", {"output_rate": 48000, "output_bits": 32})
        assert result.ok is True
        assert result.changed is False

    def test_monitor_down_is_noop_and_logs_once(self, caplog):
        b = self._make_backend()
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b)):
            with caplog.at_level("INFO", logger=svc.LOG.name):
                r1 = svc.reconcile_pipe_format_with_backend("http://localhost:3689", None)
                r2 = svc.reconcile_pipe_format_with_backend("http://localhost:3689", {})
        assert r1.ok is True and r2.ok is True
        b.get_setting.assert_not_called()
        b.save_setting.assert_not_called()
        no_info_logs = [rec for rec in caplog.records if "did not report an output format" in rec.message]
        assert len(no_info_logs) == 1

    def test_old_monitor_build_missing_fields_is_noop(self):
        b = self._make_backend()
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b)):
            result = svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"monitor_build": "0.5.14"}
            )
        assert result.ok is True
        b.get_setting.assert_not_called()

    def test_matching_format_is_noop_idempotent(self):
        b = self._make_backend(backend_rate=48000, backend_bits=32)
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b)):
            r1 = svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
            )
            r2 = svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
            )
        assert r1.ok is True and r1.changed is False
        assert r2.ok is True and r2.changed is False
        b.save_setting.assert_not_called()

    def test_mismatch_pushes_both_values_and_restarts(self):
        b = self._make_backend(backend_rate=44100, backend_bits=16)
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b)), \
             patch.object(svc, "_restart_owntone_backend_async") as mock_restart:
            result = svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
            )
        assert result.ok is True
        assert result.changed is True
        assert result.restart_requested is True
        assert b.save_setting.call_count == 2
        saved_keys = {call.args[0] for call in b.save_setting.call_args_list}
        assert saved_keys == {ap.SETTING_PIPE_SAMPLE_RATE, ap.SETTING_PIPE_BITS_PER_SAMPLE}
        mock_restart.assert_called_once_with("http://localhost:3689")

    def test_unsupported_setting_skips_save(self):
        b = self._make_backend(unsupported=True)
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b)):
            result = svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
            )
        assert result.ok is True
        b.save_setting.assert_not_called()

    def test_read_failure_returns_ok_with_warning_no_save(self):
        b = self._make_backend(get_ok=False)
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b)):
            result = svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
            )
        assert result.ok is True
        assert result.error or result.error_code
        b.save_setting.assert_not_called()

    def test_rejected_value_is_retried_every_pass_without_restarting(self):
        """A persistently-rejected value must never trigger a restart, but
        also must never be permanently suppressed -- the anti-loop guarantee
        is "no restart", not "stop retrying": retry is what lets a torn pair
        self-heal."""
        b = self._make_backend(backend_rate=44100, backend_bits=16, save_ok=False)
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b)), \
             patch.object(svc, "_restart_owntone_backend_async") as mock_restart:
            r1 = svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
            )
            assert r1.ok is True
            assert r1.error or r1.error_code
            calls_after_first = b.save_setting.call_count
            assert calls_after_first >= 1

            # Same wanted format again: retried (not suppressed).
            r2 = svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
            )
            assert r2.ok is True
            assert b.save_setting.call_count > calls_after_first
            mock_restart.assert_not_called()

            # A different wanted format is also attempted, same as ever.
            calls_after_second = b.save_setting.call_count
            r3 = svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 88200, "output_bits": 16}
            )
            assert b.save_setting.call_count > calls_after_second
            mock_restart.assert_not_called()

    def test_rejected_value_logs_warning_only_once_per_state(self, caplog):
        """The retry itself is not throttled, but the WARNING log line must
        not spam once per poll for an unchanging rejected value."""
        b = self._make_backend(backend_rate=44100, backend_bits=16, save_ok=False,
                                save_error_code="http_error")
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b)):
            with caplog.at_level("WARNING", logger=svc.LOG.name):
                for _ in range(3):
                    svc.reconcile_pipe_format_with_backend(
                        "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
                    )
        reject_logs = [rec for rec in caplog.records if "rejected pipe format" in rec.message]
        assert len(reject_logs) == 1

    # ── Split-failure (partial save) scenarios ──────────────────────────────
    #
    # Regression coverage for the torn-persisted-pair bug: rate save succeeds
    # while bits save fails (transport blip / backend restarting mid-write).

    def test_split_failure_rate_ok_bits_transport_fail_no_restart_then_completes(self):
        """(a) rate-save ok + bits-save transport-fail -> no restart this
        pass; the next pass retries (only) the still-mismatched bits key and
        completes, restarting only then."""
        b = self._make_backend(
            backend_rate=44100, backend_bits=16,
            save_rate_ok=True, save_bits_ok=False, save_error_code="request_failed",
        )
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b)), \
             patch.object(svc, "_restart_owntone_backend_async") as mock_restart:
            r1 = svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
            )
        assert r1.ok is True
        assert r1.changed is True  # rate did persist this pass
        assert r1.restart_requested is False
        mock_restart.assert_not_called()
        assert b.save_setting.call_count == 2
        saved_keys_pass1 = {call.args[0] for call in b.save_setting.call_args_list}
        assert saved_keys_pass1 == {ap.SETTING_PIPE_SAMPLE_RATE, ap.SETTING_PIPE_BITS_PER_SAMPLE}

        # Next pass: backend now reports the rate that was actually saved
        # (44100 -> 48000), bits still stale at 16. Only bits should be
        # attempted (rate already matches and is skipped, not re-saved), and
        # this time it succeeds -> restart fires exactly once, on this pass.
        b2 = self._make_backend(backend_rate=48000, backend_bits=16, save_ok=True)
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b2)), \
             patch.object(svc, "_restart_owntone_backend_async") as mock_restart2:
            r2 = svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
            )
        assert r2.ok is True
        assert r2.changed is True
        assert r2.restart_requested is True
        assert b2.save_setting.call_count == 1
        b2.save_setting.assert_called_once_with(ap.SETTING_PIPE_BITS_PER_SAMPLE, 32)
        mock_restart2.assert_called_once_with("http://localhost:3689")

    def test_split_failure_never_restarts_on_any_partial_failure_pass(self):
        """(c) No restart fires on any pass where either save failed, whether
        rate failed / bits skipped, or rate ok / bits failed."""
        # rate fails outright -> bits is skipped this pass (ordering choice,
        # not a correctness dependency) -> partial-failure pass, no restart.
        b_rate_fails = self._make_backend(
            backend_rate=44100, backend_bits=16,
            save_rate_ok=False, save_bits_ok=True, save_error_code="http_error",
        )
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b_rate_fails)), \
             patch.object(svc, "_restart_owntone_backend_async") as mock_restart:
            result = svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
            )
        assert result.restart_requested is False
        mock_restart.assert_not_called()

        # rate ok, bits fails -> also no restart (covered in detail by the
        # split-failure test above; asserted again here for the "ANY partial
        # failure" framing).
        svc._format_reconcile_state.clear()
        b_bits_fails = self._make_backend(
            backend_rate=44100, backend_bits=16,
            save_rate_ok=True, save_bits_ok=False, save_error_code="request_failed",
        )
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b_bits_fails)), \
             patch.object(svc, "_restart_owntone_backend_async") as mock_restart2:
            result2 = svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
            )
        assert result2.restart_requested is False
        mock_restart2.assert_not_called()

    def test_genuine_validation_reject_both_keys_fail_no_restart(self):
        """(b) A genuine validation-reject (both keys deterministically
        rejected, e.g. owntone-mini's config_set_int returning HTTP 500 for
        an out-of-range value) never restarts, and is retried each pass
        rather than looping forever without ever restarting."""
        b = self._make_backend(backend_rate=44100, backend_bits=16, save_ok=False,
                                save_error_code="http_error")
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b)), \
             patch.object(svc, "_restart_owntone_backend_async") as mock_restart:
            for _ in range(3):
                result = svc.reconcile_pipe_format_with_backend(
                    "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
                )
                assert result.restart_requested is False
        mock_restart.assert_not_called()


class TestReconcilePipeFormatDetectionConfidence(_FormatReconcileTestHelpers):
    """Detection-confidence gate (see TestReconcileMonitorFormatDetectionConfidence
    for the monitor-side counterpart): pushing pipe settings to a fallback-guessed
    backend is less catastrophic (validation-rejected or a no-op) than the
    monitor-format case, but the same detection-confidence gate applies."""

    def _resolved_unconfident(self, backend):
        return svc.ResolvedBackend(
            backend_id="owntone", backend=backend, detection_confident=False,
        )

    def test_fallback_resolution_defers_no_get_no_save(self):
        b = self._make_backend(backend_rate=44100, backend_bits=16)
        with patch.object(svc, "resolve_backend", return_value=self._resolved_unconfident(b)):
            result = svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
            )
        assert result.ok is True
        assert result.changed is False
        b.get_setting.assert_not_called()
        b.save_setting.assert_not_called()

    def test_fallback_resolution_logs_once_per_state(self, caplog):
        b = self._make_backend(backend_rate=44100, backend_bits=16)
        with patch.object(svc, "resolve_backend", return_value=self._resolved_unconfident(b)):
            with caplog.at_level("WARNING", logger=svc.LOG.name):
                for _ in range(3):
                    svc.reconcile_pipe_format_with_backend(
                        "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
                    )
        matches = [
            r for r in caplog.records
            if "backend identity unconfirmed" in r.getMessage()
        ]
        assert len(matches) == 1

    def test_recovery_to_confident_backend_resumes_enforcement(self):
        b = self._make_backend(backend_rate=44100, backend_bits=16)
        with patch.object(svc, "resolve_backend", return_value=self._resolved_unconfident(b)):
            deferred = svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
            )
        assert deferred.ok is True
        b.get_setting.assert_not_called()

        with patch.object(svc, "resolve_backend", return_value=self._resolved(b)), \
             patch.object(svc, "_restart_owntone_backend_async") as mock_restart:
            result = svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
            )
        assert result.ok is True
        assert result.changed is True
        assert result.restart_requested is True
        mock_restart.assert_called_once_with("http://localhost:3689")


# ---------------------------------------------------------------------------
# retry_pending_format_reconcile
# ---------------------------------------------------------------------------
#
# The periodic (per-poll, while-capturing) counterpart to
# reconcile_pipe_format_with_backend()'s startup/reconnect-only passes: a
# torn-persisted-pair fix (see class above) only gets retried on the "next
# pass", which for a pure owntone-side transport blip could otherwise be
# days away (next monitor reconnect). This closes that gap cheaply: a no-op
# unless a previous full reconcile pass left something pending.

class TestRetryPendingFormatReconcile(_FormatReconcileTestHelpers):

    def test_steady_state_is_noop_zero_http_traffic(self):
        """Nothing pending (fresh state, or after a fully-synced pass) ->
        retry_pending_format_reconcile must not touch the network at all."""
        with patch.object(svc, "resolve_backend") as resolve_mock:
            result = svc.retry_pending_format_reconcile(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32},
            )
        assert result.ok is True
        resolve_mock.assert_not_called()

    def test_noop_after_a_fully_matching_pass(self):
        b = self._make_backend(backend_rate=48000, backend_bits=32)
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b)):
            svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
            )
        with patch.object(svc, "resolve_backend") as resolve_mock:
            result = svc.retry_pending_format_reconcile(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32},
            )
        assert result.ok is True
        resolve_mock.assert_not_called()

    def test_pending_and_owntone_recovered_completes_and_restarts(self):
        """A partial-failure pass leaves needs_retry set; once the backend
        actually saves cleanly on a later call, retry completes the sync and
        fires the restart."""
        b_fail = self._make_backend(
            backend_rate=44100, backend_bits=16,
            save_rate_ok=True, save_bits_ok=False, save_error_code="request_failed",
        )
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b_fail)), \
             patch.object(svc, "_restart_owntone_backend_async"):
            first = svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
            )
        assert first.restart_requested is False

        # Backend has now recovered: rate persisted from the first pass,
        # bits still stale -- and this time the save succeeds.
        b_recovered = self._make_backend(backend_rate=48000, backend_bits=16, save_ok=True)
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b_recovered)), \
             patch.object(svc, "_restart_owntone_backend_async") as mock_restart:
            result = svc.retry_pending_format_reconcile(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32},
            )
        assert result.ok is True
        assert result.changed is True
        assert result.restart_requested is True
        b_recovered.save_setting.assert_called_once_with(ap.SETTING_PIPE_BITS_PER_SAMPLE, 32)
        mock_restart.assert_called_once_with("http://localhost:3689")

        # And now steady-state again: a further retry call is a pure no-op.
        with patch.object(svc, "resolve_backend") as resolve_mock:
            svc.retry_pending_format_reconcile(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32},
            )
        resolve_mock.assert_not_called()

    def test_pending_and_owntone_still_down_stays_pending_quietly(self):
        """While owntone-mini is still unreachable, retry attempts (and may
        fail again) but must not restart, and must not blow up -- it just
        stays pending for the next call."""
        b_fail = self._make_backend(
            backend_rate=44100, backend_bits=16,
            save_rate_ok=True, save_bits_ok=False, save_error_code="request_failed",
        )
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b_fail)), \
             patch.object(svc, "_restart_owntone_backend_async"):
            svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
            )

        # Still down: a get_setting-level failure this time (transport).
        b_still_down = MagicMock()
        b_still_down.backend_id = "owntone-mini"
        down_result = MagicMock(ok=False, unsupported=False, value=None,
                                 error="down", error_code="request_failed", message="down")
        b_still_down.get_setting.return_value = down_result
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b_still_down)), \
             patch.object(svc, "_restart_owntone_backend_async") as mock_restart:
            result = svc.retry_pending_format_reconcile(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32},
            )
        assert result.ok is True
        assert result.restart_requested is False
        mock_restart.assert_not_called()
        b_still_down.save_setting.assert_not_called()

        # Still pending afterwards -- a subsequent retry call still attempts
        # (doesn't get permanently wedged closed by the failure).
        state = svc._format_reconcile_state_for("http://localhost:3689")
        assert state["needs_retry"] is True

    def test_pending_but_monitor_down_leaves_state_untouched_no_spam(self):
        """If the caller has no fresh monitor status (monitor unreachable),
        the pending flag must be left alone -- no backend traffic, and the
        monitor-down log is throttled by the existing once-per-outage gate
        (reconcile_pipe_format_with_backend's own no-format-info path)."""
        b_fail = self._make_backend(
            backend_rate=44100, backend_bits=16,
            save_rate_ok=True, save_bits_ok=False, save_error_code="request_failed",
        )
        with patch.object(svc, "resolve_backend", return_value=self._resolved(b_fail)), \
             patch.object(svc, "_restart_owntone_backend_async"):
            svc.reconcile_pipe_format_with_backend(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32}
            )

        with patch.object(svc, "resolve_backend") as resolve_mock:
            result = svc.retry_pending_format_reconcile("http://localhost:3689", None)
        assert result.ok is True
        resolve_mock.assert_not_called()
        state = svc._format_reconcile_state_for("http://localhost:3689")
        assert state["needs_retry"] is True

    def test_empty_base_url_is_noop(self):
        result = svc.retry_pending_format_reconcile("", {"output_rate": 48000, "output_bits": 32})
        assert result.ok is True


# ---------------------------------------------------------------------------
# reconcile_monitor_format() (FIFO format-switch)
#
# The monitor-*side* half of the format enforcement: compares the active
# backend's required_monitor_format() (desired) against what the monitor's
# status reports it is currently running as (reported), and on a definite
# mismatch rewrites MONITOR_ARGS_ENV_PATH and requests a monitor restart via
# the "restart-monitor" admin verb. Deliberately sequenced BEFORE
# reconcile_pipe_format_with_backend() at both autostream_core.py call sites
# (see tests/test_wp2_settings_ownership.py and tests/test_repeat_api.py
# for the ordering proof).

class _MonitorFormatReconcileTestHelpers:
    def setup_method(self):
        _clear_cache()
        svc._monitor_format_reconcile_state.clear()

    def _resolved(self, desired_format, *, backend_id="owntone-mini", confident=True):
        """desired_format may be "native"/"compatible"/None, or an
        Exception instance to make required_monitor_format() raise."""
        b = MagicMock()
        b.backend_id = backend_id
        if isinstance(desired_format, BaseException):
            b.required_monitor_format.side_effect = desired_format
        else:
            b.required_monitor_format.return_value = desired_format
        return svc.ResolvedBackend(
            backend_id=backend_id, backend=b, detection_confident=confident,
        )


class TestReconcileMonitorFormat(_MonitorFormatReconcileTestHelpers):
    def test_empty_base_url_is_noop(self):
        result = svc.reconcile_monitor_format("", {"output_format": "native"})
        assert result.ok is True

    def test_monitor_status_none_is_noop_no_backend_traffic(self):
        with patch.object(svc, "resolve_backend") as resolve_mock:
            result = svc.reconcile_monitor_format("http://localhost:3689", None)
        assert result.ok is True
        resolve_mock.assert_not_called()

    def test_monitor_status_empty_dict_is_noop_no_backend_traffic(self):
        with patch.object(svc, "resolve_backend") as resolve_mock:
            result = svc.reconcile_monitor_format("http://localhost:3689", {})
        assert result.ok is True
        resolve_mock.assert_not_called()

    def test_desired_none_is_noop(self):
        """required_monitor_format() returning None (backend unreachable /
        undecided) must never write the env file or request a restart."""
        resolved = self._resolved(None)
        with patch.object(svc, "resolve_backend", return_value=resolved), \
             patch.object(svc, "_write_monitor_args_env_file") as write_mock, \
             patch.object(svc, "_restart_monitor_async") as restart_mock:
            result = svc.reconcile_monitor_format(
                "http://localhost:3689", {"output_format": "native"},
            )
        assert result.ok is True
        write_mock.assert_not_called()
        restart_mock.assert_not_called()

    def test_matching_format_is_noop(self):
        resolved = self._resolved("native")
        with patch.object(svc, "resolve_backend", return_value=resolved), \
             patch.object(svc, "_write_monitor_args_env_file") as write_mock, \
             patch.object(svc, "_restart_monitor_async") as restart_mock:
            result = svc.reconcile_monitor_format(
                "http://localhost:3689", {"output_format": "native"},
            )
        assert result.ok is True
        assert result.changed is False
        write_mock.assert_not_called()
        restart_mock.assert_not_called()

    def test_matching_format_is_idempotent_across_repeated_polls(self):
        resolved = self._resolved("compatible")
        with patch.object(svc, "resolve_backend", return_value=resolved), \
             patch.object(svc, "_write_monitor_args_env_file") as write_mock, \
             patch.object(svc, "_restart_monitor_async") as restart_mock:
            for _ in range(5):
                result = svc.reconcile_monitor_format(
                    "http://localhost:3689", {"output_format": "compatible"},
                )
                assert result.ok is True
        write_mock.assert_not_called()
        restart_mock.assert_not_called()

    def test_mismatch_writes_env_file_and_restarts(self):
        resolved = self._resolved("compatible")
        with patch.object(svc, "resolve_backend", return_value=resolved), \
             patch.object(svc, "_write_monitor_args_env_file", return_value=True) as write_mock, \
             patch.object(svc, "_restart_monitor_async") as restart_mock:
            result = svc.reconcile_monitor_format(
                "http://localhost:3689", {"output_format": "native"},
            )
        assert result.ok is True
        assert result.changed is True
        assert result.restart_requested is True
        write_mock.assert_called_once_with("compatible")
        restart_mock.assert_called_once_with("compatible", "native")

    def test_env_write_failure_no_restart_and_retried_next_pass(self):
        resolved = self._resolved("compatible")
        with patch.object(svc, "resolve_backend", return_value=resolved), \
             patch.object(svc, "_write_monitor_args_env_file", return_value=False), \
             patch.object(svc, "_restart_monitor_async") as restart_mock:
            result = svc.reconcile_monitor_format(
                "http://localhost:3689", {"output_format": "native"},
            )
        assert result.ok is True
        assert result.changed is False
        assert result.error_code == "env_write_failed"
        restart_mock.assert_not_called()
        state = svc._monitor_format_reconcile_state_for("http://localhost:3689")
        assert state["needs_retry"] is True

        # Next reconcile pass: the transient write failure clears and a
        # restart is (only now) requested -- automatic retry, no special
        # caller action needed.
        with patch.object(svc, "resolve_backend", return_value=resolved), \
             patch.object(svc, "_write_monitor_args_env_file", return_value=True), \
             patch.object(svc, "_restart_monitor_async") as restart_mock2:
            result2 = svc.reconcile_monitor_format(
                "http://localhost:3689", {"output_format": "native"},
            )
        assert result2.changed is True
        assert result2.restart_requested is True
        restart_mock2.assert_called_once()
        state2 = svc._monitor_format_reconcile_state_for("http://localhost:3689")
        assert state2["needs_retry"] is False

    def test_mismatch_warning_logged_once_per_distinct_state(self, caplog):
        resolved = self._resolved("compatible")
        with patch.object(svc, "resolve_backend", return_value=resolved), \
             patch.object(svc, "_write_monitor_args_env_file", return_value=True), \
             patch.object(svc, "_restart_monitor_async"):
            with caplog.at_level("WARNING", logger=svc.LOG.name):
                svc.reconcile_monitor_format("http://localhost:3689", {"output_format": "native"})
                svc.reconcile_monitor_format("http://localhost:3689", {"output_format": "native"})
                svc.reconcile_monitor_format("http://localhost:3689", {"output_format": "native"})
        matches = [
            r for r in caplog.records
            if "requesting a monitor restart" in r.getMessage()
        ]
        assert len(matches) == 1

    def test_env_write_failure_warning_logged_once_per_distinct_state(self, caplog):
        resolved = self._resolved("compatible")
        with patch.object(svc, "resolve_backend", return_value=resolved), \
             patch.object(svc, "_write_monitor_args_env_file", return_value=False), \
             patch.object(svc, "_restart_monitor_async"):
            with caplog.at_level("WARNING", logger=svc.LOG.name):
                svc.reconcile_monitor_format("http://localhost:3689", {"output_format": "native"})
                svc.reconcile_monitor_format("http://localhost:3689", {"output_format": "native"})
        matches = [r for r in caplog.records if "will retry next pass" in r.getMessage()]
        assert len(matches) == 1

    def test_required_monitor_format_raising_is_noop_never_writes(self):
        resolved = self._resolved(RuntimeError("boom"))
        with patch.object(svc, "resolve_backend", return_value=resolved), \
             patch.object(svc, "_write_monitor_args_env_file") as write_mock, \
             patch.object(svc, "_restart_monitor_async") as restart_mock:
            result = svc.reconcile_monitor_format(
                "http://localhost:3689", {"output_format": "native"},
            )
        assert result.ok is True
        assert result.error_code == "probe_error"
        write_mock.assert_not_called()
        restart_mock.assert_not_called()

    def test_fallback_to_numeric_native_when_output_format_field_absent(self):
        """Older monitor binaries report output_rate/output_bits but not
        output_format yet; those builds predate --compatible entirely, so a
        numeric report is always native."""
        resolved = self._resolved("compatible")
        with patch.object(svc, "resolve_backend", return_value=resolved), \
             patch.object(svc, "_write_monitor_args_env_file", return_value=True), \
             patch.object(svc, "_restart_monitor_async") as restart_mock:
            result = svc.reconcile_monitor_format(
                "http://localhost:3689", {"output_rate": 48000, "output_bits": 32},
            )
        assert result.changed is True
        restart_mock.assert_called_once_with("compatible", "native")

    def test_ambiguous_numeric_pair_is_noop(self):
        """A numeric pair that cannot come from a pre-output_format monitor
        build (e.g. 44100/32) is treated as unrecognised, not guessed at."""
        resolved = self._resolved("compatible")
        with patch.object(svc, "resolve_backend", return_value=resolved), \
             patch.object(svc, "_write_monitor_args_env_file") as write_mock, \
             patch.object(svc, "_restart_monitor_async") as restart_mock:
            result = svc.reconcile_monitor_format(
                "http://localhost:3689", {"output_rate": 44100, "output_bits": 32},
            )
        assert result.ok is True
        write_mock.assert_not_called()
        restart_mock.assert_not_called()

    def test_old_monitor_build_missing_format_fields_is_noop(self):
        resolved = self._resolved("compatible")
        with patch.object(svc, "resolve_backend", return_value=resolved), \
             patch.object(svc, "_write_monitor_args_env_file") as write_mock:
            result = svc.reconcile_monitor_format(
                "http://localhost:3689", {"some_other_field": 1},
            )
        assert result.ok is True
        write_mock.assert_not_called()


class TestReconcileMonitorFormatDetectionConfidence(_MonitorFormatReconcileTestHelpers):
    """Gate contract: if owntone-mini is unreachable, detect_backend() finds
    no match and resolve_backend() falls back to the generic full-OwnTone
    adapter, whose required_monitor_format() is a static "compatible".
    Trusting that fallback guess would write --compatible to the monitor's
    env file and request a restart -- flipping a healthy native appliance
    into compatible mode and wiping the monitor's in-RAM repeat buffer.
    Enforcement must require a *confident* detection, not just any resolved
    backend_id.
    """

    def test_fallback_resolution_defers_no_write_no_restart(self):
        resolved = self._resolved("compatible", backend_id="owntone", confident=False)
        with patch.object(svc, "resolve_backend", return_value=resolved), \
             patch.object(svc, "_write_monitor_args_env_file") as write_mock, \
             patch.object(svc, "_restart_monitor_async") as restart_mock:
            result = svc.reconcile_monitor_format(
                "http://localhost:3689", {"output_format": "native"},
            )
        assert result.ok is True
        assert result.changed is False
        assert result.restart_requested is False
        write_mock.assert_not_called()
        restart_mock.assert_not_called()
        # required_monitor_format() must not even be consulted -- the
        # fallback's answer is not evidence of anything.
        resolved.backend.required_monitor_format.assert_not_called()

    def test_fallback_resolution_logs_once_per_state(self, caplog):
        resolved = self._resolved("compatible", backend_id="owntone", confident=False)
        with patch.object(svc, "resolve_backend", return_value=resolved), \
             patch.object(svc, "_write_monitor_args_env_file") as write_mock, \
             patch.object(svc, "_restart_monitor_async") as restart_mock:
            with caplog.at_level("WARNING", logger=svc.LOG.name):
                for _ in range(4):
                    svc.reconcile_monitor_format(
                        "http://localhost:3689", {"output_format": "native"},
                    )
        write_mock.assert_not_called()
        restart_mock.assert_not_called()
        matches = [
            r for r in caplog.records
            if "backend identity unconfirmed" in r.getMessage()
        ]
        assert len(matches) == 1

    def test_recovery_to_confident_mini_resumes_native_enforcement(self):
        """Backend comes back (owntone-mini detected again, native format
        required); enforcement must resume normally once detection is
        confident again."""
        unconfident = self._resolved("compatible", backend_id="owntone", confident=False)
        with patch.object(svc, "resolve_backend", return_value=unconfident), \
             patch.object(svc, "_write_monitor_args_env_file") as write_mock, \
             patch.object(svc, "_restart_monitor_async") as restart_mock:
            deferred = svc.reconcile_monitor_format(
                "http://localhost:3689", {"output_format": "compatible"},
            )
        assert deferred.ok is True
        write_mock.assert_not_called()
        restart_mock.assert_not_called()

        confident = self._resolved("native", backend_id="owntone-mini", confident=True)
        with patch.object(svc, "resolve_backend", return_value=confident), \
             patch.object(svc, "_write_monitor_args_env_file", return_value=True) as write_mock2, \
             patch.object(svc, "_restart_monitor_async") as restart_mock2:
            result = svc.reconcile_monitor_format(
                "http://localhost:3689", {"output_format": "compatible"},
            )
        assert result.changed is True
        assert result.restart_requested is True
        write_mock2.assert_called_once_with("native")
        restart_mock2.assert_called_once_with("native", "compatible")

    def test_confident_full_owntone_still_enforces_compatible(self):
        """The gate is detection confidence, not adapter identity: a
        POSITIVELY-detected full-OwnTone backend must still enforce its
        static "compatible" requirement."""
        resolved = self._resolved("compatible", backend_id="owntone", confident=True)
        with patch.object(svc, "resolve_backend", return_value=resolved), \
             patch.object(svc, "_write_monitor_args_env_file", return_value=True) as write_mock, \
             patch.object(svc, "_restart_monitor_async") as restart_mock:
            result = svc.reconcile_monitor_format(
                "http://localhost:3689", {"output_format": "native"},
            )
        assert result.changed is True
        assert result.restart_requested is True
        write_mock.assert_called_once_with("compatible")
        restart_mock.assert_called_once_with("compatible", "native")


class TestWriteMonitorArgsEnvFile:
    def test_writes_compatible_args(self, tmp_path):
        target = tmp_path / "monitor_args.env"
        with patch.object(svc, "MONITOR_ARGS_ENV_PATH", str(target)):
            ok = svc._write_monitor_args_env_file("compatible")
        assert ok is True
        assert target.read_text(encoding="utf-8") == "AUTOSTREAM_MONITOR_ARGS=--compatible\n"

    def test_writes_empty_args_for_native(self, tmp_path):
        target = tmp_path / "monitor_args.env"
        with patch.object(svc, "MONITOR_ARGS_ENV_PATH", str(target)):
            ok = svc._write_monitor_args_env_file("native")
        assert ok is True
        assert target.read_text(encoding="utf-8") == "AUTOSTREAM_MONITOR_ARGS=\n"

    def test_write_failure_returns_false(self, tmp_path):
        target = tmp_path / "monitor_args.env"
        with patch.object(svc, "MONITOR_ARGS_ENV_PATH", str(target)), \
             patch("autostream_sysutils.atomic_write_file", side_effect=OSError("disk full")):
            ok = svc._write_monitor_args_env_file("compatible")
        assert ok is False


class TestRestartMonitorAsync:
    def test_fires_restart_monitor_admin_verb_in_background(self):
        import threading as _threading

        done = _threading.Event()

        def _fake_run_admin_cmd(args, timeout=20.0):
            done.set()
            return MagicMock(returncode=0, stderr="")

        with patch.object(svc, "run_admin_cmd", side_effect=_fake_run_admin_cmd) as run_mock:
            svc._restart_monitor_async("compatible", "native")
            assert done.wait(timeout=5.0), "restart-monitor worker thread never ran"

        run_mock.assert_called_once_with(["restart-monitor"], timeout=20.0)
