"""Priority 2 — Player backend contract tests.

Tests the registry, detection flow, output normalization, and both
OwnToneBackend and OwnToneMiniBackend against the same normalized contract.
Uses request fakes (patched requests.get/put) rather than mocking backend methods.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_players as ap
from autostream_owntone import OwnToneBackend
from autostream_owntone_mini import OwnToneMiniBackend


# ---------------------------------------------------------------------------
# Response fakes
# ---------------------------------------------------------------------------

def _resp(status=200, json_data=None, content=b"x", raise_for_json=False):
    r = MagicMock()
    r.status_code = status
    r.ok = 200 <= status < 300
    r.text = ""
    if content is not None:
        r.content = content
    else:
        r.content = b""
    if raise_for_json:
        r.json.side_effect = ValueError("bad json")
    elif json_data is not None:
        r.json.return_value = json_data
    else:
        r.json.return_value = {}
    return r


def _net_err():
    import requests as rq
    return rq.RequestException("connection refused")


def _req_exc():
    """Return a live requests.RequestException instance usable as a side_effect."""
    import requests as rq
    return rq.RequestException("connection refused")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class TestRegistry:
    def test_register_and_retrieve(self):
        # Ensure built-ins are registered and retrievable.
        ap.ensure_builtin_backends_registered()
        assert ap.BACKEND_OWNTONE in ap.REGISTRY.backend_ids()
        assert ap.BACKEND_OWNTONE_MINI in ap.REGISTRY.backend_ids()
        b = ap.REGISTRY.create(ap.BACKEND_OWNTONE, base_url="http://localhost:3689")
        assert b.backend_id == ap.BACKEND_OWNTONE

    def test_unknown_backend_raises_key_error(self):
        reg = ap.PlayerBackendRegistry()
        with pytest.raises(KeyError):
            reg.create("nonexistent", base_url="http://localhost:3689")

    def test_duplicate_registration_replaces_previous(self):
        ap.ensure_builtin_backends_registered()
        saved = dict(ap.REGISTRY._backend_classes)
        # Register the same class a second time — count should not grow.
        from autostream_owntone import OwnToneBackend
        ap.REGISTRY.register(OwnToneBackend)
        assert len([k for k in ap.REGISTRY.backend_ids() if k == ap.BACKEND_OWNTONE]) == 1
        ap.REGISTRY._backend_classes.clear()
        ap.REGISTRY._backend_classes.update(saved)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

class TestDetectionOrder:
    def test_detection_continues_after_non_match(self):
        """If the first backend doesn't match, detection continues."""
        mini = OwnToneMiniBackend(base_url="http://localhost:3689")
        full = OwnToneBackend(base_url="http://localhost:3689")

        config_for_full = {"version": "28.9", "categories": []}
        settings_for_full = {"categories": [{"name": "misc", "options": []}]}

        call_count = {"n": 0}

        def fake_get(url, **kw):
            call_count["n"] += 1
            if "api/config" in url:
                if call_count["n"] <= 1:
                    # mini probe: config without product_name
                    return _resp(json_data={"version": "28.9"})
                return _resp(json_data=config_for_full)
            if "api/settings" in url:
                return _resp(json_data=settings_for_full)
            return _resp(status=404, content=b"")

        with patch("autostream_players.requests.get", side_effect=fake_get):
            ap.ensure_builtin_backends_registered()
            backend, detections = ap.detect_backend("http://localhost:3689")

        assert backend is not None
        assert backend.backend_id == ap.BACKEND_OWNTONE
        assert len(detections) >= 1

    def test_detection_returns_first_match(self):
        """Mini backend matches when product_name == 'owntone-mini'."""
        config_mini = {"version": "1.0", "product_name": "owntone-mini"}

        with patch("autostream_players.requests.get",
                   return_value=_resp(json_data=config_mini)):
            ap.ensure_builtin_backends_registered()
            backend, detections = ap.detect_backend("http://localhost:3689")

        assert backend is not None
        assert backend.backend_id == ap.BACKEND_OWNTONE_MINI

    def test_detection_returns_none_when_no_match(self):
        config_no_match = {"version": "28.9"}  # no product_name for mini
        settings_no_category = {"not_categories": []}  # fails full owntone check

        def fake_get(url, **kw):
            if "api/settings" in url:
                return _resp(json_data=settings_no_category)
            return _resp(json_data=config_no_match)

        with patch("autostream_players.requests.get", side_effect=fake_get):
            ap.ensure_builtin_backends_registered()
            backend, detections = ap.detect_backend("http://localhost:3689")

        assert backend is None
        assert len(detections) >= 2  # both backends attempted


# ---------------------------------------------------------------------------
# OwnToneHttpBackendBase: output normalization
# ---------------------------------------------------------------------------

class TestOutputNormalization:
    def _backend(self):
        return OwnToneBackend(base_url="http://localhost:3689")

    def test_missing_id_and_name(self):
        b = self._backend()
        out = b._normalize_output_info({})
        assert out.id == ""
        assert out.name == "Unknown Output"

    def test_volume_clamped_to_0_100(self):
        b = self._backend()
        out_low = b._normalize_output_info({"id": "x", "volume": -50})
        out_high = b._normalize_output_info({"id": "x", "volume": 150})
        assert out_low.volume_percent == 0
        assert out_high.volume_percent == 100

    def test_malformed_volume_defaults_to_zero(self):
        b = self._backend()
        out = b._normalize_output_info({"id": "x", "volume": "bad"})
        assert out.volume_percent == 0

    def test_offset_ms_present(self):
        b = self._backend()
        out = b._normalize_output_info({"id": "x", "offset_ms": 100})
        assert out.offset_ms == 100

    def test_offset_ms_absent_is_none(self):
        b = self._backend()
        out = b._normalize_output_info({"id": "x"})
        assert out.offset_ms is None

    def test_malformed_offset_ms_is_none(self):
        b = self._backend()
        out = b._normalize_output_info({"id": "x", "offset_ms": "bad"})
        assert out.offset_ms is None

    def test_auth_flags(self):
        b = self._backend()
        out = b._normalize_output_info({"id": "x", "has_password": True, "requires_auth": True})
        assert out.has_password is True
        assert out.requires_auth is True

    def test_base_url_trailing_slash_stripped(self):
        b = OwnToneBackend(base_url="http://localhost:3689/")
        assert b._base_url == "http://localhost:3689"


# ---------------------------------------------------------------------------
# OwnTone detection payloads
# ---------------------------------------------------------------------------

class TestOwnToneDetection:
    def test_mini_matches_on_product_name(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        config = {"version": "2.0", "product_name": "owntone-mini"}
        with patch("autostream_players.requests.get",
                   return_value=_resp(json_data=config)):
            result = b.detect()
        assert result.matched is True
        assert result.backend_id == ap.BACKEND_OWNTONE_MINI
        assert result.version == "2.0"

    def test_mini_no_match_without_product_name(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        config = {"version": "28.9"}
        with patch("autostream_players.requests.get",
                   return_value=_resp(json_data=config)):
            result = b.detect()
        assert result.matched is False

    def test_full_matches_on_settings_endpoint(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        config = {"version": "28.9"}
        settings = {"categories": [{"name": "misc", "options": []}]}
        responses = [_resp(json_data=config), _resp(json_data=settings)]
        with patch("autostream_players.requests.get", side_effect=responses):
            result = b.detect()
        assert result.matched is True
        assert result.version == "28.9"

    def test_full_no_match_when_settings_missing_categories(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        config = {"version": "28.9"}
        settings = {"other": "value"}
        responses = [_resp(json_data=config), _resp(json_data=settings)]
        with patch("autostream_players.requests.get", side_effect=responses):
            result = b.detect()
        assert result.matched is False

    def test_network_error_returns_unmatched(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        with patch("autostream_players.requests.get", side_effect=_req_exc()):
            result = b.detect()
        assert result.matched is False


# ---------------------------------------------------------------------------
# OwnTone Mini: mode normalization
# ---------------------------------------------------------------------------

class TestMiniModeNormalization:
    def test_supported_modes_includes_auto_when_omitted(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        out = b._normalize_output_info({"id": "x", "supported_modes": ["raop"]})
        assert ap.OUTPUT_MODE_AUTO in out.supported_modes

    def test_current_mode_parsed_from_server_value(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        out = b._normalize_output_info({"id": "x", "mode": "airplay2"})
        assert out.current_mode == ap.OUTPUT_MODE_AIRPLAY2

    def test_unknown_mode_defaults_to_auto(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        out = b._normalize_output_info({"id": "x", "mode": "legacy"})
        assert out.current_mode == ap.OUTPUT_MODE_AUTO

    def test_non_list_supported_modes_defaults_to_auto_tuple(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        out = b._normalize_output_info({"id": "x", "supported_modes": "bad"})
        assert out.supported_modes == (ap.OUTPUT_MODE_AUTO,)


# ---------------------------------------------------------------------------
# HTTP error / invalid JSON handling in _get_json
# ---------------------------------------------------------------------------

class TestGetJsonErrorHandling:
    def _b(self):
        return OwnToneBackend(base_url="http://localhost:3689")

    def test_network_error_returns_error_string(self):
        b = self._b()
        with patch("autostream_players.requests.get",
                   side_effect=_req_exc()):
            payload, resp, err = b._get_json("/api/test")
        assert payload is None
        assert resp is None
        assert err != ""

    def test_invalid_json_returns_error(self):
        b = self._b()
        with patch("autostream_players.requests.get",
                   return_value=_resp(raise_for_json=True)):
            payload, resp, err = b._get_json("/api/test")
        assert payload is None
        assert err != ""

    def test_non_dict_json_returns_error(self):
        b = self._b()
        r = _resp()
        r.json.return_value = [1, 2, 3]
        with patch("autostream_players.requests.get", return_value=r):
            payload, resp, err = b._get_json("/api/test")
        assert payload is None
        assert err != ""

    def test_empty_body_returns_empty_dict(self):
        b = self._b()
        r = _resp(content=b"")
        with patch("autostream_players.requests.get", return_value=r):
            payload, resp, err = b._get_json("/api/test")
        assert payload == {}
        assert err == ""


# ---------------------------------------------------------------------------
# _put_output_fields: pin_required / pin_invalid / not_found
# ---------------------------------------------------------------------------

class TestPutOutputFields:
    def _b(self):
        return OwnToneBackend(base_url="http://localhost:3689")

    def test_success_204(self):
        b = self._b()
        r = _resp(status=204, content=b"")
        with patch("autostream_players.requests.put", return_value=r):
            result = b._put_output_fields("abc", {"selected": True},
                                          allow_pin_required=True)
        assert result.ok is True

    def test_400_with_pin_required_flag(self):
        b = self._b()
        r = _resp(status=400, content=b"pin required")
        r.text = "pin required"
        with patch("autostream_players.requests.put", return_value=r):
            result = b._put_output_fields("abc", {"selected": True},
                                          allow_pin_required=True)
        assert result.ok is False
        assert result.error_code == "pin_required"

    def test_400_with_pin_invalid_flag(self):
        b = self._b()
        r = _resp(status=400, content=b"bad pin")
        r.text = "bad pin"
        with patch("autostream_players.requests.put", return_value=r):
            result = b._put_output_fields("abc", {"pin": "0000"},
                                          allow_pin_invalid=True)
        assert result.ok is False
        assert result.error_code == "pin_invalid"

    def test_missing_output_id_returns_error(self):
        b = self._b()
        result = b._put_output_fields("", {"selected": True})
        assert result.ok is False
        assert result.error_code == "missing_output_id"

    def test_network_error_returns_request_failed(self):
        b = self._b()
        with patch("autostream_players.requests.put",
                   side_effect=_req_exc()):
            result = b._put_output_fields("abc", {"selected": True})
        assert result.ok is False
        assert result.error_code == "request_failed"


# ---------------------------------------------------------------------------
# OwnTone Mini: list_outputs
# ---------------------------------------------------------------------------

class TestMiniListOutputs:
    def test_success(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        payload = {"outputs": [{"id": "1", "name": "Speaker", "volume": 50, "selected": True}]}
        with patch("autostream_players.requests.get",
                   return_value=_resp(json_data=payload)):
            result = b.list_outputs()
        assert result.ok is True
        assert len(result.outputs) == 1
        assert result.outputs[0].id == "1"
        assert result.outputs[0].volume_percent == 50

    def test_network_error_returns_failure(self):
        import requests as rq
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        with patch("autostream_players.requests.get",
                   side_effect=rq.RequestException("refused")):
            result = b.list_outputs()
        assert result.ok is False

    def test_non_200_returns_failure(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        with patch("autostream_players.requests.get",
                   return_value=_resp(status=503)):
            result = b.list_outputs()
        assert result.ok is False


# ---------------------------------------------------------------------------
# Capabilities match implementations
# ---------------------------------------------------------------------------

class TestCapabilities:
    def test_owntone_cannot_set_mode(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        caps = b.get_capabilities()
        assert caps.can_set_output_mode is False

    def test_owntone_mini_can_set_mode(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        caps = b.get_capabilities()
        assert caps.can_set_output_mode is True
        assert caps.supports_runtime_settings is True
