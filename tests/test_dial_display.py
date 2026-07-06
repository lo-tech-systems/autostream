"""Tests for dial_display.py — display manager selection, fallback, and safety.

Covers: disabled config, no targets, unauthorized target suppression,
unsupported target, missing/omitted track_id treated as no artwork, provider
URL fetch eligibility (scheme, IP literal, .local, non-default port, unsafe
redirects), oversized response, decode failure fallback, oldest-playing
target stickiness, use of the single-target status helper (not
enrich_targets), later-target skip after first usable artwork, loop delay
measured from loop end, image dedupe, logo fallback, backend failure
degradation, and shutdown.
"""
from __future__ import annotations

import sys
import threading
import time
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PIL import Image

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dial_config import DialDisplayConfig
from dial_mdns import PlayingTarget
import dial_display as dd
from dial_display import (
    DialDisplay,
    NoOpBackend,
    _fetch_artwork,
    artwork_url_eligible,
    create_dial_display,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _target(
    name="Kitchen", ip="192.168.1.10", port=80,
    dial_status=True, display_authorized=True,
    service_name=None, playing_since=100.0,
) -> PlayingTarget:
    return PlayingTarget(
        ip=ip, port=port, name=name,
        dial_api=True, audio_status=True, dial_status=dial_status,
        service_name=service_name or name,
        playing_since=playing_since,
        display_authorized=display_authorized,
    )


def _track_id(**overrides) -> dict:
    base = {
        "enabled": True, "state": "identified",
        "title": "Song", "artist": "Artist", "album": "Album",
        "artwork_url": "https://provider.example/x.jpg",
        "updated_at": 1.0, "last_attempt_at": 1.0,
    }
    base.update(overrides)
    return base


def _status_result(track_id=None, status_error=None) -> dict:
    return {
        "playing": True, "master_volume": 50, "selected_output_count": 1,
        "track_id": track_id, "status_error": status_error,
    }


_TEST_LOGO_PATH = str(REPO_ROOT / "images" / "autostream-logo-centred-dark.png")


class FakeBackend:
    name = "fake"
    width = 128
    height = 160

    def __init__(self, fail_open=False, fail_display=False):
        self.fail_open = fail_open
        self.fail_display = fail_display
        self.opened = False
        self.closed = False
        self.cleared = False
        self.displayed: list = []

    def open(self):
        if self.fail_open:
            raise RuntimeError("open failed")
        self.opened = True

    def close(self):
        self.closed = True
        self.opened = False

    def clear(self):
        self.cleared = True

    def display(self, image):
        if self.fail_display:
            raise RuntimeError("display failed")
        self.displayed.append(image)


def _make_display(
    fitted=True, targets=None, backend=None,
    get_targets=None, mark_unauthorized=None,
) -> tuple[DialDisplay, FakeBackend, MagicMock, MagicMock]:
    cfg = DialDisplayConfig(fitted=fitted)
    fb = backend or FakeBackend()
    gt = get_targets or MagicMock(return_value=targets or [])
    mu = mark_unauthorized or MagicMock()
    display = DialDisplay(
        config=cfg,
        get_display_targets=gt,
        mark_display_target_unauthorized=mu,
        dial_id="dial-uuid",
        logo_path=_TEST_LOGO_PATH,
        backend_factory=lambda: fb,
    )
    return display, fb, gt, mu


# ---------------------------------------------------------------------------
# Disabled config / no-op behavior
# ---------------------------------------------------------------------------

class TestDisabledConfig:
    def test_disabled_backend_never_opens(self):
        display, fb, gt, mu = _make_display(fitted=False)
        display.start()
        display.stop()
        assert fb.opened is False

    def test_disabled_status_shape(self):
        display, fb, gt, mu = _make_display(fitted=False)
        status = display.get_status()
        assert status == {
            "fitted": False, "active": False, "backend": "noop",
            "backend_loaded": False, "showing": "noop",
            "last_error": "", "last_error_at": None,
        }

    def test_disabled_poll_does_not_query_targets(self):
        display, fb, gt, mu = _make_display(fitted=False)
        display._poll_once()
        gt.assert_not_called()


# ---------------------------------------------------------------------------
# Target selection / fallback
# ---------------------------------------------------------------------------

class TestTargetSelectionFallback:
    def test_no_targets_shows_logo(self):
        display, fb, gt, mu = _make_display(targets=[])
        display.enable()
        display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_unauthorized_target_suppressed_shows_logo(self):
        t = _target(display_authorized=False)
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status") as mock_fetch:
            display._poll_once()
        mock_fetch.assert_not_called()
        assert display.get_status()["showing"] == "logo"

    def test_unsupported_target_skipped(self):
        t = _target(dial_status=False)
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status") as mock_fetch:
            display._poll_once()
        mock_fetch.assert_not_called()
        assert display.get_status()["showing"] == "logo"

    def test_missing_track_id_treated_as_no_artwork(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_omitted_artwork_url_treated_as_no_artwork(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=_track_id(artwork_url=""))
        with patch("dial_display.fetch_target_status", return_value=result):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_non_identified_state_treated_as_no_artwork(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=_track_id(state="analysing"))
        with patch("dial_display.fetch_target_status", return_value=result):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_unauthorized_status_error_marks_target(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(status_error="unauthorized")):
            display._poll_once()
        mu.assert_called_once_with(t)

    def test_other_status_error_skips_without_marking(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status",
                   return_value=_status_result(status_error="timeout")):
            display._poll_once()
        mu.assert_not_called()
        assert display.get_status()["showing"] == "logo"

    def test_oldest_playing_target_stickiness_uses_target_order(self):
        """DialDisplay must iterate targets in the order get_display_targets() returns
        (oldest playing_since first) and stop at the first usable source."""
        t1 = _target(name="Older", playing_since=10.0)
        t2 = _target(name="Newer", playing_since=20.0)
        display, fb, gt, mu = _make_display(targets=[t1, t2])
        display.enable()

        calls = []

        def fake_fetch(target, dial_id, timeout_seconds):
            calls.append(target.name)
            return _status_result(track_id=_track_id())

        with patch("dial_display.fetch_target_status", side_effect=fake_fetch):
            display._poll_once()
        assert calls == ["Older"], "must stop polling after the first usable artwork source"

    def test_later_target_skipped_after_first_usable_artwork(self):
        t1 = _target(name="First", playing_since=10.0)
        t2 = _target(name="Second", playing_since=20.0)
        display, fb, gt, mu = _make_display(targets=[t1, t2])
        display.enable()

        calls = []

        def fake_fetch(target, dial_id, timeout_seconds):
            calls.append(target.name)
            if target.name == "First":
                return _status_result(track_id=_track_id())
            return _status_result(track_id=_track_id())

        with patch("dial_display.fetch_target_status", side_effect=fake_fetch):
            display._poll_once()
        assert calls == ["First"]

    def test_uses_single_target_helper_not_enrich_targets(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_target_status.enrich_targets") as mock_enrich, \
             patch("dial_display.fetch_target_status", return_value=_status_result()):
            display._poll_once()
        mock_enrich.assert_not_called()

    def test_fetch_target_status_called_with_dial_status_timeout(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result()) as mock_fetch:
            display._poll_once()
        _, kwargs = mock_fetch.call_args
        assert mock_fetch.call_args[0][0] is t
        assert mock_fetch.call_args[0][1] == "dial-uuid"
        assert kwargs["timeout_seconds"] == dd.DIAL_STATUS_TIMEOUT_SECONDS


# ---------------------------------------------------------------------------
# Provider artwork URL eligibility
# ---------------------------------------------------------------------------

class TestArtworkUrlEligibility:
    def test_https_dns_hostname_default_port_eligible(self):
        assert artwork_url_eligible("https://provider.example/a.jpg") is True

    def test_http_scheme_rejected(self):
        assert artwork_url_eligible("http://provider.example/a.jpg") is False

    def test_ipv4_literal_rejected(self):
        assert artwork_url_eligible("https://93.184.216.34/a.jpg") is False

    def test_ipv6_literal_rejected(self):
        assert artwork_url_eligible("https://[2001:db8::1]/a.jpg") is False

    def test_dot_local_hostname_rejected(self):
        assert artwork_url_eligible("https://box.local/a.jpg") is False

    def test_explicit_non_default_port_rejected(self):
        assert artwork_url_eligible("https://provider.example:8443/a.jpg") is False

    def test_explicit_default_port_443_accepted(self):
        assert artwork_url_eligible("https://provider.example:443/a.jpg") is True

    def test_malformed_url_rejected(self):
        assert artwork_url_eligible("not a url") is False


# ---------------------------------------------------------------------------
# Artwork fetch (redirect handling, size, content-type)
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status: int, headers: dict | None = None, body: bytes = b""):
        self.status = status
        self.headers = headers or {}
        self._body = body

    def read(self, n=-1):
        return self._body if n is None or n < 0 else self._body[:n]

    def close(self):
        pass

    def getcode(self):
        return self.status


class _FakeOpener:
    def __init__(self, responses):
        self._responses = list(responses)
        self.requested_urls: list[str] = []

    def open(self, req, timeout=None):
        self.requested_urls.append(req.full_url)
        resp = self._responses.pop(0)
        if isinstance(resp, Exception):
            raise resp
        return resp


class TestFetchArtwork:
    def test_success(self):
        resp = _FakeResponse(200, {"Content-Type": "image/jpeg"}, b"data")
        opener = _FakeOpener([resp])
        with patch("dial_display.urllib.request.build_opener", return_value=opener):
            data, err = _fetch_artwork("https://provider.example/a.jpg", 2.0)
        assert err == ""
        assert data == b"data"

    def test_ineligible_initial_url_rejected_without_request(self):
        opener = _FakeOpener([])
        with patch("dial_display.urllib.request.build_opener", return_value=opener):
            data, err = _fetch_artwork("http://provider.example/a.jpg", 2.0)
        assert data is None
        assert err == "ineligible_url"
        assert opener.requested_urls == []

    def test_follows_one_redirect(self):
        redirect = _FakeResponse(302, {"Location": "https://provider.example/final.jpg"})
        final = _FakeResponse(200, {"Content-Type": "image/png"}, b"final-data")
        opener = _FakeOpener([redirect, final])
        with patch("dial_display.urllib.request.build_opener", return_value=opener):
            data, err = _fetch_artwork("https://provider.example/start.jpg", 2.0)
        assert err == ""
        assert data == b"final-data"
        assert len(opener.requested_urls) == 2

    def test_rejects_redirect_to_ineligible_target(self):
        redirect = _FakeResponse(302, {"Location": "http://provider.example/final.jpg"})
        opener = _FakeOpener([redirect])
        with patch("dial_display.urllib.request.build_opener", return_value=opener):
            data, err = _fetch_artwork("https://provider.example/start.jpg", 2.0)
        assert data is None
        assert err == "ineligible_url"

    def test_rejects_more_than_two_redirects(self):
        redirects = [
            _FakeResponse(302, {"Location": f"https://provider.example/hop{i}.jpg"})
            for i in range(3)
        ]
        opener = _FakeOpener(redirects)
        with patch("dial_display.urllib.request.build_opener", return_value=opener):
            data, err = _fetch_artwork("https://provider.example/start.jpg", 2.0)
        assert data is None
        assert err == "too_many_redirects"

    def test_rejects_oversized_body(self):
        oversized = b"x" * (dd.MAX_ARTWORK_RESPONSE_BYTES + 1)
        resp = _FakeResponse(200, {"Content-Type": "image/jpeg"}, oversized)
        opener = _FakeOpener([resp])
        with patch("dial_display.urllib.request.build_opener", return_value=opener):
            data, err = _fetch_artwork("https://provider.example/a.jpg", 2.0)
        assert data is None
        assert err == "oversized"

    def test_rejects_unsupported_content_type(self):
        resp = _FakeResponse(200, {"Content-Type": "text/html"}, b"<html>")
        opener = _FakeOpener([resp])
        with patch("dial_display.urllib.request.build_opener", return_value=opener):
            data, err = _fetch_artwork("https://provider.example/a.jpg", 2.0)
        assert data is None
        assert err == "unsupported_content_type"

    def test_content_type_with_params_accepted(self):
        resp = _FakeResponse(200, {"Content-Type": "image/jpeg; charset=binary"}, b"data")
        opener = _FakeOpener([resp])
        with patch("dial_display.urllib.request.build_opener", return_value=opener):
            data, err = _fetch_artwork("https://provider.example/a.jpg", 2.0)
        assert err == ""

    def test_http_error_reported(self):
        opener = _FakeOpener([urllib.error.HTTPError("url", 404, "not found", {}, None)])
        with patch("dial_display.urllib.request.build_opener", return_value=opener):
            data, err = _fetch_artwork("https://provider.example/a.jpg", 2.0)
        assert data is None
        assert err == "http_404"


# ---------------------------------------------------------------------------
# End-to-end artwork rendering via DialDisplay
# ---------------------------------------------------------------------------

class TestArtworkRendering:
    def test_successful_artwork_fetch_renders_and_dedupes(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        fb.displayed.clear()

        fake_image = Image.new("RGB", (128, 160))
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"jpegdata", "")) as mock_fetch_art, \
             patch("dial_display.decode_artwork", return_value=fake_image) as mock_decode, \
             patch("dial_display.transform_artwork_for_panel", return_value=fake_image):
            display._poll_once()
            display._poll_once()

        assert display.get_status()["showing"] == "artwork"
        mock_fetch_art.assert_called_once()  # second poll reused the cached image
        mock_decode.assert_called_once()
        # Display is only updated when the image identity changes — the
        # second poll's unchanged URL must not trigger a redundant redraw.
        assert len(fb.displayed) == 1

    def test_decode_failure_falls_back_to_logo(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(b"bad", "")), \
             patch("dial_display.decode_artwork", return_value=None):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"
        assert display.get_status()["last_error"] == "artwork_decode_failed"

    def test_fetch_failure_falls_back_to_logo(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=_track_id())), \
             patch("dial_display._fetch_artwork", return_value=(None, "oversized")):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"
        assert display.get_status()["last_error"] == "artwork_fetch_failed"

    def test_ineligible_url_falls_back_to_logo_without_fetching(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        result = _status_result(track_id=_track_id(artwork_url="http://provider.example/a.jpg"))
        with patch("dial_display.fetch_target_status", return_value=result), \
             patch("dial_display._fetch_artwork") as mock_fetch_art:
            display._poll_once()
        mock_fetch_art.assert_not_called()
        assert display.get_status()["showing"] == "logo"


# ---------------------------------------------------------------------------
# Logo fallback
# ---------------------------------------------------------------------------

class TestLogoFallback:
    def test_logo_fallback_when_no_targets_visible(self):
        display, fb, gt, mu = _make_display(targets=[])
        display.enable()
        display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_logo_fallback_while_playing_with_no_artwork(self):
        t = _target()
        display, fb, gt, mu = _make_display(targets=[t])
        display.enable()
        with patch("dial_display.fetch_target_status", return_value=_status_result(track_id=None)):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_missing_logo_file_is_non_fatal(self):
        display, fb, gt, mu = _make_display(targets=[])
        display._logo_path = "/nonexistent/path/does-not-exist.png"
        display.enable()
        status = display.get_status()
        assert status["last_error"] == "logo_unavailable"
        assert status["showing"] in ("logo", "noop")


# ---------------------------------------------------------------------------
# Backend failure degradation
# ---------------------------------------------------------------------------

class TestBackendFailureDegradation:
    def test_backend_open_failure_degrades_to_noop(self):
        fb = FakeBackend(fail_open=True)
        display, _, gt, mu = _make_display(backend=fb)
        display.enable()
        status = display.get_status()
        assert status["backend_loaded"] is False
        assert status["showing"] == "noop"
        assert status["last_error"] == "backend_open_failed"

    def test_backend_display_failure_is_non_fatal(self):
        fb = FakeBackend(fail_display=True)
        display, _, gt, mu = _make_display(backend=fb)
        display.enable()  # logo render will fail silently at backend level
        status = display.get_status()
        assert status["last_error"] == "display_write_failed"

    def test_disabled_config_never_touches_backend(self):
        fb = FakeBackend()
        display, _, gt, mu = _make_display(fitted=False, backend=fb)
        display.update_config(DialDisplayConfig(fitted=False))
        assert fb.opened is False


# ---------------------------------------------------------------------------
# update_config live apply
# ---------------------------------------------------------------------------

class TestUpdateConfig:
    def test_enable_via_update_config_opens_backend(self):
        display, fb, gt, mu = _make_display(fitted=False)
        status = display.update_config(DialDisplayConfig(fitted=True))
        assert fb.opened is True
        assert status["backend_loaded"] is True

    def test_disable_via_update_config_closes_backend(self):
        display, fb, gt, mu = _make_display(fitted=True)
        display.enable()
        assert fb.opened is True
        status = display.update_config(DialDisplayConfig(fitted=False))
        assert fb.closed is True
        assert status["showing"] == "noop"


# ---------------------------------------------------------------------------
# Threading: start/stop and loop delay from loop end
# ---------------------------------------------------------------------------

class TestThreadingLifecycle:
    def test_start_stop_clean_shutdown(self):
        display, fb, gt, mu = _make_display(targets=[])
        display.start()
        time.sleep(0.05)
        display.stop()
        assert fb.closed is True
        assert display._thread is not None
        assert not display._thread.is_alive()

    def test_loop_waits_full_interval_after_poll_completes(self):
        display, fb, gt, mu = _make_display(targets=[])
        wait_calls = []

        def tracking_wait(timeout=None):
            wait_calls.append(timeout)
            display._stop_event.set()  # end the loop after the first wait
            return True

        with patch.object(display, "_poll_once") as mock_poll, \
             patch.object(display._stop_event, "wait", side_effect=tracking_wait):
            display._run()

        mock_poll.assert_called_once()
        assert wait_calls == [dd.DISPLAY_POLL_INTERVAL_SECONDS]

    def test_stop_is_idempotent(self):
        display, fb, gt, mu = _make_display(targets=[])
        display.start()
        display.stop()
        display.stop()  # must not raise


# ---------------------------------------------------------------------------
# create_dial_display() factory
# ---------------------------------------------------------------------------

class TestCreateDialDisplay:
    def test_factory_wires_config_and_dial_id(self):
        cfg = MagicMock()
        cfg.display = DialDisplayConfig(fitted=False)
        cfg.uuid = "abc123"
        gt = MagicMock()
        mu = MagicMock()
        display = create_dial_display(cfg, gt, mu)
        assert isinstance(display, DialDisplay)
        assert display._dial_id == "abc123"
        assert display._config is cfg.display

    def test_factory_uses_noop_backend(self):
        cfg = MagicMock()
        cfg.display = DialDisplayConfig(fitted=True)
        cfg.uuid = "abc123"
        display = create_dial_display(cfg, MagicMock(), MagicMock())
        display.enable()
        assert display.get_status()["backend"] == "noop"


# ---------------------------------------------------------------------------
# Rate-limited logging
# ---------------------------------------------------------------------------

class TestRateLimitedLogger:
    def test_first_occurrence_logs(self):
        limiter = dd._RateLimitedLogger()
        with patch("logging.log") as mock_log:
            limiter.log(30, "keyA", "msg %s", "x")
        mock_log.assert_called_once()

    def test_repeats_suppressed_until_tenth(self):
        limiter = dd._RateLimitedLogger()
        with patch("logging.log") as mock_log:
            for _ in range(9):
                limiter.log(30, "keyA", "msg")
        assert mock_log.call_count == 1  # only the first of these 9

    def test_tenth_repeat_logs(self):
        limiter = dd._RateLimitedLogger()
        with patch("logging.log") as mock_log:
            for _ in range(10):
                limiter.log(30, "keyA", "msg")
        assert mock_log.call_count == 2  # 1st and 10th

    def test_different_key_resets_and_logs_immediately(self):
        limiter = dd._RateLimitedLogger()
        with patch("logging.log") as mock_log:
            for _ in range(5):
                limiter.log(30, "keyA", "msg")
            limiter.log(30, "keyB", "other")
        assert mock_log.call_count == 2  # first of keyA, first of keyB
