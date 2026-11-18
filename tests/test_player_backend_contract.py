"""Priority 2 — Player backend contract tests.

Tests the registry, detection flow, output normalization, and both
OwnToneBackend and OwnToneMiniBackend against the same normalized contract.
Uses request fakes (patched _session.get/put — the shared requests.Session) rather than mocking backend methods.
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

        with patch("autostream_players._session.get", side_effect=fake_get):
            ap.ensure_builtin_backends_registered()
            backend, detections = ap.detect_backend("http://localhost:3689")

        assert backend is not None
        assert backend.backend_id == ap.BACKEND_OWNTONE
        assert len(detections) >= 1

    def test_detection_returns_first_match(self):
        """Mini backend matches when product_name == 'owntone-mini'."""
        config_mini = {"version": "1.0", "product_name": "owntone-mini"}

        with patch("autostream_players._session.get",
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

        with patch("autostream_players._session.get", side_effect=fake_get):
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

    def test_pin_pending_flag(self):
        b = self._backend()
        out = b._normalize_output_info({"id": "x", "pin_pending": True})
        assert out.pin_pending is True

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
        with patch("autostream_players._session.get",
                   return_value=_resp(json_data=config)):
            result = b.detect()
        assert result.matched is True
        assert result.backend_id == ap.BACKEND_OWNTONE_MINI
        assert result.version == "2.0"

    def test_mini_no_match_without_product_name(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        config = {"version": "28.9"}
        with patch("autostream_players._session.get",
                   return_value=_resp(json_data=config)):
            result = b.detect()
        assert result.matched is False

    def test_full_matches_on_settings_endpoint(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        config = {"version": "28.9"}
        settings = {"categories": [{"name": "misc", "options": []}]}
        responses = [_resp(json_data=config), _resp(json_data=settings)]
        with patch("autostream_players._session.get", side_effect=responses):
            result = b.detect()
        assert result.matched is True
        assert result.version == "28.9"

    def test_full_no_match_when_settings_missing_categories(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        config = {"version": "28.9"}
        settings = {"other": "value"}
        responses = [_resp(json_data=config), _resp(json_data=settings)]
        with patch("autostream_players._session.get", side_effect=responses):
            result = b.detect()
        assert result.matched is False

    def test_network_error_returns_unmatched(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        with patch("autostream_players._session.get", side_effect=_req_exc()):
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

    def test_paused_by_device_true_surfaced_in_extra(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        out = b._normalize_output_info({"id": "x", "paused_by_device": True})
        assert out.extra_dict().get("paused_by_device") is True

    def test_paused_by_device_absent_surfaces_as_false(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        out = b._normalize_output_info({"id": "x"})
        assert out.extra_dict().get("paused_by_device") is False


# ---------------------------------------------------------------------------
# HTTP error / invalid JSON handling in _get_json
# ---------------------------------------------------------------------------

class TestGetJsonErrorHandling:
    def _b(self):
        return OwnToneBackend(base_url="http://localhost:3689")

    def test_network_error_returns_error_string(self):
        b = self._b()
        with patch("autostream_players._session.get",
                   side_effect=_req_exc()):
            payload, resp, err = b._get_json("/api/test")
        assert payload is None
        assert resp is None
        assert err != ""

    def test_invalid_json_returns_error(self):
        b = self._b()
        with patch("autostream_players._session.get",
                   return_value=_resp(raise_for_json=True)):
            payload, resp, err = b._get_json("/api/test")
        assert payload is None
        assert err != ""

    def test_non_dict_json_returns_error(self):
        b = self._b()
        r = _resp()
        r.json.return_value = [1, 2, 3]
        with patch("autostream_players._session.get", return_value=r):
            payload, resp, err = b._get_json("/api/test")
        assert payload is None
        assert err != ""

    def test_empty_body_returns_empty_dict(self):
        b = self._b()
        r = _resp(content=b"")
        with patch("autostream_players._session.get", return_value=r):
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
        with patch("autostream_players._session.put", return_value=r):
            result = b._put_output_fields("abc", {"selected": True},
                                          allow_pin_required=True)
        assert result.ok is True

    def test_400_with_pin_required_flag(self):
        b = self._b()
        r = _resp(status=400, content=b"pin required")
        r.text = "pin required"
        with patch("autostream_players._session.put", return_value=r):
            result = b._put_output_fields("abc", {"selected": True},
                                          allow_pin_required=True)
        assert result.ok is False
        assert result.error_code == "pin_required"

    def test_400_with_pin_invalid_flag(self):
        b = self._b()
        r = _resp(status=400, content=b"bad pin")
        r.text = "bad pin"
        with patch("autostream_players._session.put", return_value=r):
            result = b._put_output_fields("abc", {"pin": "0000"},
                                          allow_pin_invalid=True)
        assert result.ok is False
        assert result.error_code == "pin_invalid"

    def test_503_encoder_capacity_returns_encoder_capacity(self):
        b = self._b()
        r = _resp(status=503, content=b'{"error":"encoder_capacity"}')
        r.text = '{"error":"encoder_capacity"}'
        with patch("autostream_players._session.put", return_value=r):
            result = b._put_output_fields("abc", {"selected": True})
        assert result.ok is False
        assert result.error_code == "encoder_capacity"

    def test_503_unrelated_body_returns_http_error(self):
        b = self._b()
        r = _resp(status=503, content=b"upstream unavailable")
        r.text = "upstream unavailable"
        with patch("autostream_players._session.put", return_value=r):
            result = b._put_output_fields("abc", {"selected": True})
        assert result.ok is False
        assert result.error_code == "http_error"

    def test_missing_output_id_returns_error(self):
        b = self._b()
        result = b._put_output_fields("", {"selected": True})
        assert result.ok is False
        assert result.error_code == "missing_output_id"

    def test_network_error_returns_request_failed(self):
        b = self._b()
        with patch("autostream_players._session.put",
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
        with patch("autostream_players._session.get",
                   return_value=_resp(json_data=payload)):
            result = b.list_outputs()
        assert result.ok is True
        assert len(result.outputs) == 1
        assert result.outputs[0].id == "1"
        assert result.outputs[0].volume_percent == 50

    def test_network_error_returns_failure(self):
        import requests as rq
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        with patch("autostream_players._session.get",
                   side_effect=rq.RequestException("refused")):
            result = b.list_outputs()
        assert result.ok is False

    def test_non_200_returns_failure(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        with patch("autostream_players._session.get",
                   return_value=_resp(status=503)):
            result = b.list_outputs()
        assert result.ok is False

    def test_non_200_with_body_includes_status_and_snippet(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        r = _resp(status=500, content=b"<html>Internal Server Error</html>")
        r.text = "<html>Internal Server Error</html>"
        with patch("autostream_players._session.get", return_value=r):
            result = b.list_outputs()
        assert result.ok is False
        assert "Failed to list outputs" in result.error
        assert "500" in result.error
        assert "Internal Server Error" in result.error

    def test_oversized_body_is_truncated(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        long_body = "x" * 5000
        r = _resp(status=500, content=long_body.encode())
        r.text = long_body
        with patch("autostream_players._session.get", return_value=r):
            result = b.list_outputs()
        assert result.ok is False
        assert "500" in result.error
        # Body snippet stays well under the raw body length and the whole
        # error message never balloons to the full response size.
        assert len(result.error) < 400

    def test_body_with_newlines_stays_single_line(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        r = _resp(status=500, content=b"line one\nline two\nline three")
        r.text = "line one\nline two\nline three"
        with patch("autostream_players._session.get", return_value=r):
            result = b.list_outputs()
        assert result.ok is False
        assert "\n" not in result.error

    def test_network_error_returns_generic_failure_without_status(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        with patch("autostream_players._session.get",
                   side_effect=_req_exc()):
            result = b.list_outputs()
        assert result.ok is False
        assert result.error == "Failed to list outputs"
        assert result.error_code == "request_failed"


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


# ---------------------------------------------------------------------------
# Parameterized contract: both backends must satisfy these invariants
# ---------------------------------------------------------------------------

@pytest.fixture(params=["owntone", "owntone-mini"])
def backend(request):
    if request.param == "owntone":
        return OwnToneBackend(base_url="http://localhost:3689")
    return OwnToneMiniBackend(base_url="http://localhost:3689")


_OUTPUT_PAYLOAD = {
    "id": "1",
    "name": "Speaker",
    "volume": 50,
    "selected": True,
    "offset_ms": 100,
}


class TestListOutputsContract:
    def test_success_returns_ok_with_outputs(self, backend):
        payload = {"outputs": [_OUTPUT_PAYLOAD]}
        with patch("autostream_players._session.get",
                   return_value=_resp(json_data=payload)):
            result = backend.list_outputs()
        assert result.ok is True
        assert len(result.outputs) == 1
        out = result.outputs[0]
        assert out.id == "1"
        assert out.volume_percent == 50
        assert out.offset_ms == 100

    def test_network_error_returns_failure(self, backend):
        with patch("autostream_players._session.get", side_effect=_req_exc()):
            result = backend.list_outputs()
        assert result.ok is False
        assert result.error_code in ("request_failed", "http_error", "")

    def test_http_error_returns_failure(self, backend):
        with patch("autostream_players._session.get",
                   return_value=_resp(status=503)):
            result = backend.list_outputs()
        assert result.ok is False

    def test_empty_outputs_list_returns_ok(self, backend):
        payload = {"outputs": []}
        with patch("autostream_players._session.get",
                   return_value=_resp(json_data=payload)):
            result = backend.list_outputs()
        assert result.ok is True
        assert result.outputs == ()


class TestGetOutputContract:
    def test_success_returns_ok_with_output(self, backend):
        with patch("autostream_players._session.get",
                   return_value=_resp(json_data=_OUTPUT_PAYLOAD)):
            result = backend.get_output("1")
        assert result.ok is True
        assert result.output.id == "1"

    def test_missing_id_returns_missing_error(self, backend):
        result = backend.get_output("")
        assert result.ok is False
        assert result.error_code == "missing_output_id"

    def test_404_returns_not_found(self, backend):
        r = _resp(status=404)
        r.content = b""
        with patch("autostream_players._session.get", return_value=r):
            result = backend.get_output("99")
        assert result.ok is False
        assert result.error_code == "not_found"

    def test_network_error_returns_failure(self, backend):
        with patch("autostream_players._session.get", side_effect=_req_exc()):
            result = backend.get_output("1")
        assert result.ok is False


class TestStopContract:
    def test_stop_success_returns_ok(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players._session.put", return_value=r):
            result = backend.stop()
        assert result.ok is True

    def test_stop_network_error_returns_failure(self, backend):
        with patch("autostream_players._session.put", side_effect=_req_exc()):
            result = backend.stop()
        assert result.ok is False


class TestSetVolumeContract:
    def test_volume_clamped_to_100(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players._session.put", return_value=r) as mock_put:
            result = backend.set_output_volume("1", 9999)
        assert result.ok is True
        assert mock_put.call_args[0][0] == "http://localhost:3689/api/outputs/1"
        assert mock_put.call_args[1].get("json") == {"volume": 100}

    def test_volume_clamped_to_0(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players._session.put", return_value=r) as mock_put:
            result = backend.set_output_volume("1", -100)
        assert result.ok is True
        assert mock_put.call_args[0][0] == "http://localhost:3689/api/outputs/1"
        assert mock_put.call_args[1].get("json") == {"volume": 0}

    def test_non_numeric_volume_defaults_to_0(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players._session.put", return_value=r) as mock_put:
            result = backend.set_output_volume("1", "bad")
        assert result.ok is True
        assert mock_put.call_args[1].get("json") == {"volume": 0}


class TestSetOffsetContract:
    def test_offset_clamped_high(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players._session.put", return_value=r) as mock_put:
            result = backend.set_output_offset("1", 99999)
        assert result.ok is True
        assert mock_put.call_args[0][0] == "http://localhost:3689/api/outputs/1"
        assert mock_put.call_args[1].get("json") == {"offset_ms": 2000}

    def test_offset_clamped_low(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players._session.put", return_value=r) as mock_put:
            result = backend.set_output_offset("1", -99999)
        assert result.ok is True
        assert mock_put.call_args[0][0] == "http://localhost:3689/api/outputs/1"
        assert mock_put.call_args[1].get("json") == {"offset_ms": -2000}


class TestSubmitPinContract:
    def test_empty_pin_returns_missing_pin_error(self, backend):
        result = backend.submit_output_pin("1", "")
        assert result.ok is False
        assert result.error_code == "missing_pin"

    def test_valid_pin_sends_exact_payload(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players._session.put", return_value=r) as mock_put:
            result = backend.submit_output_pin("1", "1234")
        assert result.ok is True
        assert mock_put.call_args[0][0] == "http://localhost:3689/api/outputs/1"
        assert mock_put.call_args[1].get("json") == {"pin": "1234"}


class TestSetOutputEnabledContract:
    def test_enable_sends_selected_true(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players._session.put", return_value=r) as mock_put:
            result = backend.set_output_enabled("1", True)
        assert result.ok is True
        assert mock_put.call_args[0][0] == "http://localhost:3689/api/outputs/1"
        assert mock_put.call_args[1].get("json") == {"selected": True}

    def test_disable_sends_selected_false(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players._session.put", return_value=r) as mock_put:
            result = backend.set_output_enabled("1", False)
        assert result.ok is True
        assert mock_put.call_args[0][0] == "http://localhost:3689/api/outputs/1"
        assert mock_put.call_args[1].get("json") == {"selected": False}


class TestSetSelectedOutputsContract:
    def test_selected_outputs_sends_ids_list(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players._session.put", return_value=r) as mock_put:
            result = backend.set_selected_outputs(["id1", "id2"])
        assert result.ok is True
        assert mock_put.call_args[0][0] == "http://localhost:3689/api/outputs/set"
        assert mock_put.call_args[1].get("json") == {"outputs": ["id1", "id2"]}

    def test_empty_ids_sends_empty_list(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players._session.put", return_value=r) as mock_put:
            result = backend.set_selected_outputs([])
        assert result.ok is True
        assert mock_put.call_args[1].get("json") == {"outputs": []}


# ---------------------------------------------------------------------------
# Mini-only: output mode translation in update_output
# ---------------------------------------------------------------------------

class TestMiniOutputModeTranslation:
    def test_airplay1_translated_to_raop(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        r = _resp(status=204, content=b"")
        with patch("autostream_players._session.put", return_value=r) as mock_put:
            b.update_output("1", enabled=True, mode="airplay1")
        call_json = mock_put.call_args[1].get("json")
        assert call_json.get("mode") == "raop"

    def test_airplay2_passed_through(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        r = _resp(status=204, content=b"")
        with patch("autostream_players._session.put", return_value=r) as mock_put:
            b.update_output("1", enabled=True, mode="airplay2")
        call_json = mock_put.call_args[1].get("json")
        assert call_json.get("mode") == "airplay2"

    def test_auto_passed_through(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        r = _resp(status=204, content=b"")
        with patch("autostream_players._session.put", return_value=r) as mock_put:
            b.update_output("1", enabled=True, mode="auto")
        call_json = mock_put.call_args[1].get("json")
        assert call_json.get("mode") == "auto"

    def test_unknown_mode_omitted_from_payload(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        r = _resp(status=204, content=b"")
        with patch("autostream_players._session.put", return_value=r) as mock_put:
            b.update_output("1", enabled=True, mode="legacy")
        call_json = mock_put.call_args[1].get("json")
        assert "mode" not in call_json

    def test_full_owntone_ignores_mode(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        r = _resp(status=204, content=b"")
        with patch("autostream_players._session.put", return_value=r) as mock_put:
            b.update_output("1", enabled=True, mode="airplay1")
        call_json = mock_put.call_args[1].get("json")
        assert "mode" not in call_json


# ---------------------------------------------------------------------------
# Mini-only: settings contract (get_setting / save_setting)
# ---------------------------------------------------------------------------

class TestMiniGetSetting:
    def _backend(self):
        return OwnToneMiniBackend(base_url="http://localhost:3689")

    def test_unsupported_key_returns_unsupported(self):
        b = self._backend()
        result = b.get_setting("nonexistent_key")
        assert result.ok is False
        assert result.unsupported is True
        assert result.error_code == "unsupported"

    def test_success_returns_value(self):
        b = self._backend()
        payload = {"value": "/tmp/audio.fifo"}
        r = _resp(json_data=payload)
        with patch("autostream_players._session.get", return_value=r):
            result = b.get_setting(ap.SETTING_PIPE_PATH)
        assert result.ok is True
        assert result.value == "/tmp/audio.fifo"

    def test_404_returns_unsupported(self):
        b = self._backend()
        r = _resp(status=404)
        r.content = b""
        with patch("autostream_players._session.get", return_value=r):
            result = b.get_setting(ap.SETTING_PIPE_PATH)
        assert result.ok is False
        assert result.unsupported is True

    def test_bool_value_normalized_from_backend(self):
        b = self._backend()
        payload = {"value": 1}  # numeric true from server
        r = _resp(json_data=payload)
        with patch("autostream_players._session.get", return_value=r):
            result = b.get_setting(ap.SETTING_PIPE_AUTOSTART)
        assert result.ok is True
        assert result.value is True

    def test_int_value_normalized(self):
        b = self._backend()
        payload = {"value": 2250}
        r = _resp(json_data=payload)
        with patch("autostream_players._session.get", return_value=r):
            result = b.get_setting(ap.SETTING_START_BUFFER_MS)
        assert result.ok is True
        assert result.value == 2250

    def test_invalid_json_with_response_includes_status_and_snippet(self):
        b = self._backend()
        r = _resp(raise_for_json=True, content=b"not json")
        r.text = "not json"
        with patch("autostream_players._session.get", return_value=r):
            result = b.get_setting(ap.SETTING_PIPE_PATH)
        assert result.ok is False
        assert "Failed to read backend setting" in result.error
        assert "not json" in result.error
        assert "200" in result.error

    def test_http_error_includes_status_and_snippet(self):
        b = self._backend()
        r = _resp(status=500, content=b"upstream failure detail")
        r.text = "upstream failure detail"
        with patch("autostream_players._session.get", return_value=r):
            result = b.get_setting(ap.SETTING_PIPE_PATH)
        assert result.ok is False
        assert "500" in result.error
        assert "upstream failure detail" in result.error

    def test_oversized_body_is_truncated(self):
        b = self._backend()
        long_body = "y" * 5000
        r = _resp(status=500, content=long_body.encode())
        r.text = long_body
        with patch("autostream_players._session.get", return_value=r):
            result = b.get_setting(ap.SETTING_PIPE_PATH)
        assert result.ok is False
        assert len(result.error) < 400

    def test_network_error_returns_generic_failure_without_status(self):
        b = self._backend()
        with patch("autostream_players._session.get",
                   side_effect=_req_exc()):
            result = b.get_setting(ap.SETTING_PIPE_PATH)
        assert result.ok is False
        assert result.error == "Failed to read backend setting"
        assert result.error_code == "request_failed"


class TestMiniSaveSetting:
    def _backend(self):
        return OwnToneMiniBackend(base_url="http://localhost:3689")

    def _ok_resp(self, restart_required=False):
        r = _resp(status=200, json_data={"restart_required": restart_required})
        return r

    def test_unsupported_key_returns_unsupported(self):
        b = self._backend()
        result = b.save_setting("unknown_key", "value")
        assert result.ok is False
        assert result.unsupported is True

    def test_bool_sent_as_bool_to_backend(self):
        b = self._backend()
        with patch("autostream_players._session.put",
                   return_value=self._ok_resp()) as mock_put:
            b.save_setting(ap.SETTING_PIPE_AUTOSTART, True)
        call_json = mock_put.call_args[1].get("json")
        assert call_json["value"] is True

    def test_int_clamped_to_min(self):
        b = self._backend()
        with patch("autostream_players._session.put",
                   return_value=self._ok_resp()) as mock_put:
            b.save_setting(ap.SETTING_START_BUFFER_MS, 0)  # below min (300)
        call_json = mock_put.call_args[1].get("json")
        assert call_json["value"] == ap.SETTING_START_BUFFER_MS_MIN

    def test_int_clamped_to_max(self):
        b = self._backend()
        with patch("autostream_players._session.put",
                   return_value=self._ok_resp()) as mock_put:
            b.save_setting(ap.SETTING_START_BUFFER_MS, 99999)  # above max (3500)
        call_json = mock_put.call_args[1].get("json")
        assert call_json["value"] == ap.SETTING_START_BUFFER_MS_MAX

    def test_device_removal_grace_period_clamped_to_min(self):
        b = self._backend()
        with patch("autostream_players._session.put",
                   return_value=self._ok_resp()) as mock_put:
            b.save_setting(ap.SETTING_DEVICE_REMOVAL_GRACE_PERIOD, 0)  # below min (60 s)
        call_json = mock_put.call_args[1].get("json")
        assert call_json["value"] == 60  # 1 minute minimum in seconds

    def test_device_removal_grace_period_clamped_to_max(self):
        b = self._backend()
        with patch("autostream_players._session.put",
                   return_value=self._ok_resp()) as mock_put:
            b.save_setting(ap.SETTING_DEVICE_REMOVAL_GRACE_PERIOD, 99999)
        call_json = mock_put.call_args[1].get("json")
        assert call_json["value"] == 900  # 15 minute maximum in seconds

    def test_restart_required_propagated(self):
        b = self._backend()
        with patch("autostream_players._session.put",
                   return_value=self._ok_resp(restart_required=True)):
            result = b.save_setting(ap.SETTING_START_BUFFER_MS, 300)
        assert result.ok is True
        assert result.restart_required is True

    def test_network_error_returns_failure(self):
        b = self._backend()
        with patch("autostream_players._session.put", side_effect=_req_exc()):
            result = b.save_setting(ap.SETTING_PIPE_PATH, "/tmp/audio.fifo")
        assert result.ok is False
        assert result.error_code == "request_failed"


# ---------------------------------------------------------------------------
# OwnTone full: get_setting / save_setting are unsupported
# ---------------------------------------------------------------------------

class TestFullOwnToneSettingsUnsupported:
    def test_get_setting_unsupported(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        result = b.get_setting(ap.SETTING_PIPE_PATH)
        assert result.ok is False
        assert result.unsupported is True

    def test_save_setting_unsupported(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        result = b.save_setting(ap.SETTING_PIPE_PATH, "/tmp/audio.fifo")
        assert result.ok is False
        assert result.unsupported is True


# ---------------------------------------------------------------------------
# required_monitor_format() contract (FIFO format-switch): PlayerBackend's
# own default, and both concrete adapters.
# ---------------------------------------------------------------------------

def _make_stub_backend_cls():
    """A minimal concrete PlayerBackend subclass that stubs out every other
    abstract method with a no-op, so PlayerBackend's own (non-abstract)
    required_monitor_format() default can be exercised in isolation --
    neither shipped adapter (OwnToneBackend/OwnToneMiniBackend) uses the
    base default; both override it.
    """
    namespace: dict = {}
    for name in ap.PlayerBackend.__abstractmethods__:
        if name == "backend_id_cls":
            namespace[name] = classmethod(lambda cls: "stub-backend")
        else:
            namespace[name] = lambda self, *a, **k: None
    return type("StubBackend", (ap.PlayerBackend,), namespace)


class TestRequiredMonitorFormatDefault:
    def test_base_default_is_compatible(self):
        backend = _make_stub_backend_cls()()
        assert backend.required_monitor_format() == "compatible"


class TestRequiredMonitorFormatFullOwnTone:
    def test_always_compatible(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        assert b.required_monitor_format() == "compatible"

    def test_compatible_regardless_of_base_url(self):
        # No probe/HTTP traffic involved -- a constant, not a lookup.
        b = OwnToneBackend(base_url="http://elsewhere:3689")
        with patch("autostream_players.requests.get") as mock_get:
            result = b.required_monitor_format()
        assert result == "compatible"
        mock_get.assert_not_called()


class TestMiniRequiredMonitorFormatProbe:
    """owntone-mini's required_monitor_format(): a dynamic probe of
    SETTING_PIPE_SAMPLE_RATE via get_setting(), cached module-level by
    base_url (see autostream_owntone_mini._monitor_format_probe_cache)."""

    def setup_method(self):
        import autostream_owntone_mini as om
        om._monitor_format_probe_cache.clear()

    def _mini(self, base_url="http://mini1:3689"):
        return OwnToneMiniBackend(base_url=base_url)

    def test_settable_key_returns_native(self):
        b = self._mini()
        settable = MagicMock(unsupported=False, ok=True, value=48000)
        with patch.object(b, "get_setting", return_value=settable) as gs:
            result = b.required_monitor_format()
        assert result == "native"
        gs.assert_called_once_with(ap.SETTING_PIPE_SAMPLE_RATE)

    def test_unsupported_key_returns_compatible(self):
        b = self._mini()
        unsupported = MagicMock(unsupported=True, ok=False, value=None)
        with patch.object(b, "get_setting", return_value=unsupported):
            result = b.required_monitor_format()
        assert result == "compatible"

    def test_transport_failure_returns_none(self):
        b = self._mini()
        down = MagicMock(unsupported=False, ok=False, value=None)
        with patch.object(b, "get_setting", return_value=down):
            result = b.required_monitor_format()
        assert result is None

    def test_result_is_cached_across_calls(self):
        b = self._mini()
        settable = MagicMock(unsupported=False, ok=True, value=48000)
        with patch.object(b, "get_setting", return_value=settable) as gs:
            first = b.required_monitor_format()
            second = b.required_monitor_format()
        assert (first, second) == ("native", "native")
        gs.assert_called_once()  # second call served from cache

    def test_unknown_transport_failure_is_never_cached(self):
        b = self._mini()
        down = MagicMock(unsupported=False, ok=False, value=None)
        settable = MagicMock(unsupported=False, ok=True, value=48000)
        with patch.object(b, "get_setting", side_effect=[down, settable]) as gs:
            first = b.required_monitor_format()
            second = b.required_monitor_format()
        assert first is None
        assert second == "native"
        assert gs.call_count == 2

    def test_different_base_urls_have_isolated_cache_entries(self):
        b1 = self._mini("http://mini-a:3689")
        b2 = self._mini("http://mini-b:3689")
        settable = MagicMock(unsupported=False, ok=True, value=48000)
        unsupported = MagicMock(unsupported=True, ok=False, value=None)
        with patch.object(b1, "get_setting", return_value=settable):
            r1 = b1.required_monitor_format()
        with patch.object(b2, "get_setting", return_value=unsupported):
            r2 = b2.required_monitor_format()
        assert r1 == "native"
        assert r2 == "compatible"

    def test_cache_expires_after_ttl_and_reprobes(self):
        import autostream_owntone_mini as om
        b = self._mini()
        settable = MagicMock(unsupported=False, ok=True, value=48000)
        with patch.object(b, "get_setting", return_value=settable):
            first = b.required_monitor_format()
        assert first == "native"

        # Rewind the cached timestamp past the TTL to simulate staleness
        # (e.g. a firmware upgrade that made the key unsupported again)
        # without sleeping in the test.
        key = b._base_url
        ts, cached_value = om._monitor_format_probe_cache[key]
        om._monitor_format_probe_cache[key] = (
            ts - om._MONITOR_FORMAT_PROBE_CACHE_SECONDS - 1.0, cached_value,
        )

        unsupported = MagicMock(unsupported=True, ok=False, value=None)
        with patch.object(b, "get_setting", return_value=unsupported) as gs:
            second = b.required_monitor_format()
        assert second == "compatible"
        gs.assert_called_once()


class TestOwnToneOffsetCapabilityIsFalse:
    """Genuine upstream OwnTone has no offset_ms field: the adapter must not
    advertise offset support, and update_output must not send the field."""

    def test_capability_is_false(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        assert b.get_capabilities().can_set_output_offset is False

    def test_update_output_omits_offset_field(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        r = _resp(status=204, content=b"")
        with patch("autostream_players._session.put", return_value=r) as mock_put:
            result = b.update_output("1", volume_percent=50, offset_ms=300)
        assert result.ok is True
        assert mock_put.call_args[1].get("json") == {"volume": 50}

    def test_update_output_with_only_offset_is_a_no_op_error(self):
        """offset_ms is the sole field supplied and is dropped entirely, so
        there is nothing left to send -- mirrors the existing "no fields"
        contract rather than silently issuing an empty PUT."""
        b = OwnToneBackend(base_url="http://localhost:3689")
        with patch("autostream_players._session.put") as mock_put:
            result = b.update_output("1", offset_ms=300)
        assert result.ok is False
        assert result.error_code == "missing_fields"
        mock_put.assert_not_called()

    def test_supports_live_offset_default_false(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        assert b.supports_live_offset() is False


class TestMiniSupportsLiveOffsetProbe:
    """owntone-mini's supports_live_offset(): reads "live_offset" from
    /api/config, cached module-level by base_url (mirrors the
    required_monitor_format() probe cache above)."""

    def setup_method(self):
        import autostream_owntone_mini as om
        om._live_offset_probe_cache.clear()

    def _mini(self, base_url="http://mini1:3689"):
        return OwnToneMiniBackend(base_url=base_url)

    def test_offset_capability_stays_true_regardless_of_live_flag(self):
        # can_set_output_offset is unconditional -- offset_ms is a real field
        # on this backend even on builds that predate live mid-session apply.
        b = self._mini()
        assert b.get_capabilities().can_set_output_offset is True

    def test_flag_true_returns_true(self):
        b = self._mini()
        r = _resp(json_data={"live_offset": True})
        with patch("autostream_players._session.get", return_value=r) as mock_get:
            result = b.supports_live_offset()
        assert result is True
        mock_get.assert_called_once()

    def test_flag_absent_returns_false(self):
        b = self._mini()
        r = _resp(json_data={"product_name": "owntone-mini"})
        with patch("autostream_players._session.get", return_value=r):
            result = b.supports_live_offset()
        assert result is False

    def test_transport_failure_returns_false_and_is_not_cached(self):
        b = self._mini()
        with patch("autostream_players._session.get", side_effect=_req_exc()):
            first = b.supports_live_offset()
        r = _resp(json_data={"live_offset": True})
        with patch("autostream_players._session.get", return_value=r) as mock_get:
            second = b.supports_live_offset()
        assert first is False
        assert second is True
        mock_get.assert_called_once()  # not skipped by a bad cache entry

    def test_result_is_cached_across_calls(self):
        b = self._mini()
        r = _resp(json_data={"live_offset": True})
        with patch("autostream_players._session.get", return_value=r) as mock_get:
            first = b.supports_live_offset()
            second = b.supports_live_offset()
        assert (first, second) == (True, True)
        mock_get.assert_called_once()

    def test_different_base_urls_have_isolated_cache_entries(self):
        b1 = self._mini("http://mini-a:3689")
        b2 = self._mini("http://mini-b:3689")
        on = _resp(json_data={"live_offset": True})
        off = _resp(json_data={"live_offset": False})
        with patch("autostream_players._session.get", return_value=on):
            r1 = b1.supports_live_offset()
        with patch("autostream_players._session.get", return_value=off):
            r2 = b2.supports_live_offset()
        assert r1 is True
        assert r2 is False


# ---------------------------------------------------------------------------
# Session and group fields, capability flags, event channel, timeouts
# ---------------------------------------------------------------------------

# Example rows as the owntone-mini API documents them.
_ROW_PLAIN = {
    "id": "1",
    "name": "Speaker A",
    "type": "AirPlay 2",
    "selected": True,
    "has_password": False,
    "requires_auth": False,
    "needs_auth_key": False,
    "volume": 50,
    "offset_ms": 0,
    "format": "alac",
    "supported_formats": ["pcm", "alac"],
    "mode": "auto",
    "supported_modes": ["raop", "airplay2"],
    "session": {"state": "streaming", "failure": "none"},
    "group": {"gid": None, "role": "none", "leader_id": None, "pair_name": None, "hidden": False},
}

_ROW_TV_LEADER = {
    "id": "186916976721924",
    "name": "TV A",
    "selected": True,
    "session": {"state": "stopped", "failure": "none"},
    "group": {
        "gid": "5B2C0A44", "role": "tv_leader", "leader_id": "186916976721924",
        "pair_name": "Pair A", "hidden": False, "include_tv": False,
        "speakers": {"ids": ["186916976721925", "186916976721926"], "count": 2, "state": "streaming"},
    },
}

_ROW_OLD = {"id": "7", "name": "Speaker B", "selected": False, "volume": 30}


def _clear_mini_caches():
    import autostream_owntone_mini as om
    om._event_channel_probe_cache.clear()
    om._rows_carry_session.clear()
    om._live_offset_probe_cache.clear()


def _mini(base_url="http://mini-fields:3689"):
    return OwnToneMiniBackend(base_url=base_url)


class TestMiniSessionAndGroupFields:
    def test_plain_row_carries_session_and_default_group(self):
        out = _mini()._normalize_output_info(_ROW_PLAIN)
        assert out.session_state == "streaming"
        assert out.session_failure == "none"
        assert out.group_role == "none"
        assert out.group_gid is None
        assert out.group_hidden is False
        assert out.include_tv is None
        assert out.speakers is None

    def test_tv_leader_row_carries_group_fields(self):
        out = _mini()._normalize_output_info(_ROW_TV_LEADER)
        assert out.session_state == "stopped"
        assert out.group_role == "tv_leader"
        assert out.group_gid == "5B2C0A44"
        assert out.group_leader_id == "186916976721924"
        assert out.pair_name == "Pair A"
        assert out.include_tv is False
        assert out.speakers == ap.SpeakersSummary(
            ids=("186916976721925", "186916976721926"), count=2, state="streaming")

    def test_row_without_session_or_group_keeps_defaults(self):
        out = _mini()._normalize_output_info(_ROW_OLD)
        assert out.session_state == ""
        assert out.session_failure == "none"
        assert out.group_role == "none"
        assert out.speakers is None
        assert out.include_tv is None

    def test_unknown_role_and_states_read_as_neutral(self):
        out = _mini()._normalize_output_info({
            "id": "x",
            "session": {"state": "warming", "failure": "mystery"},
            "group": {"role": "stack", "speakers": {"ids": [], "count": 0, "state": "odd"}},
        })
        assert out.session_state == ""
        assert out.session_failure == "none"
        assert out.group_role == "none"
        assert out.speakers.state == "stopped"

    def test_capacity_failure_is_kept(self):
        out = _mini()._normalize_output_info({"id": "x", "session": {"state": "failed", "failure": "capacity"}})
        assert (out.session_state, out.session_failure) == ("failed", "capacity")

    def test_at_most_eight_speaker_ids_are_kept(self):
        ids = [str(n) for n in range(12)]
        out = _mini()._normalize_output_info({
            "id": "x", "group": {"role": "pair", "speakers": {"ids": ids, "count": 12, "state": "streaming"}}})
        assert len(out.speakers.ids) == 8
        assert out.speakers.count == 12

    def test_include_tv_only_when_boolean(self):
        out = _mini()._normalize_output_info({"id": "x", "group": {"role": "tv_leader", "include_tv": "no"}})
        assert out.include_tv is None

    def test_upstream_rows_have_no_session_fields(self):
        out = OwnToneBackend(base_url="http://localhost:3689")._normalize_output_info(_ROW_PLAIN)
        assert out.session_state == ""
        assert out.group_role == "none"


class TestMiniRowFlagsAndChannelCapabilities:
    def setup_method(self):
        _clear_mini_caches()

    def teardown_method(self):
        _clear_mini_caches()

    @staticmethod
    def _get(config, outputs):
        def fake_get(url, **kw):
            if url.endswith("/api/config"):
                return _resp(json_data=config)
            if url.endswith("/api/outputs"):
                return _resp(json_data={"outputs": outputs})
            return _resp(status=404, content=b"")
        return fake_get

    def test_channel_on_reports_unix_socket_and_device_events(self):
        b = _mini()
        config = {"event_channel": 1, "event_socket": "/run/owntone-mini/events.sock"}
        with patch("autostream_players._session.get", side_effect=self._get(config, [])):
            caps = b.get_capabilities()
        assert caps.event_source == "unix_socket"
        assert caps.delivers_device_events is True

    def test_channel_off_reports_poll(self):
        b = _mini()
        config = {"event_channel": 0, "event_socket": None}
        with patch("autostream_players._session.get", side_effect=self._get(config, [])):
            caps = b.get_capabilities()
        assert caps.event_source == "poll"
        assert caps.delivers_device_events is False

    def test_channel_absent_reports_poll(self):
        b = _mini()
        with patch("autostream_players._session.get", side_effect=self._get({"product_name": "owntone-mini"}, [])):
            caps = b.get_capabilities()
        assert caps.event_source == "poll"
        assert caps.delivers_device_events is False

    def test_row_flags_come_from_rows_even_when_the_channel_is_off(self):
        b = _mini()
        config = {"event_channel": 0, "event_socket": None}
        with patch("autostream_players._session.get", side_effect=self._get(config, [_ROW_PLAIN])):
            before = b.get_capabilities()
            assert b.list_outputs().ok
            after = b.get_capabilities()
        assert (before.supports_group_fields, before.supports_include_tv) == (False, False)
        assert (after.supports_group_fields, after.supports_include_tv) == (True, True)
        assert after.event_source == "poll"

    def test_rows_without_a_session_leave_the_row_flags_false(self):
        b = _mini()
        with patch("autostream_players._session.get", side_effect=self._get({}, [_ROW_OLD])):
            assert b.list_outputs().ok
            caps = b.get_capabilities()
        assert (caps.supports_group_fields, caps.supports_include_tv) == (False, False)

    def test_an_empty_list_does_not_change_the_row_flags(self):
        b = _mini()
        with patch("autostream_players._session.get", side_effect=self._get({}, [_ROW_PLAIN])):
            b.list_outputs()
        with patch("autostream_players._session.get", side_effect=self._get({}, [])):
            b.list_outputs()
            caps = b.get_capabilities()
        assert caps.supports_group_fields is True

    def test_channel_probe_is_cached(self):
        b = _mini()
        config = {"event_channel": 1, "event_socket": "/run/x.sock"}
        with patch("autostream_players._session.get", side_effect=self._get(config, [])) as mock_get:
            b.get_capabilities()
            b.get_capabilities()
        assert mock_get.call_count == 1

    def test_channel_probe_is_not_cached_on_a_transport_failure(self):
        b = _mini()
        with patch("autostream_players._session.get", side_effect=_req_exc()):
            first = b.get_capabilities()
        config = {"event_channel": 1, "event_socket": "/run/x.sock"}
        with patch("autostream_players._session.get", side_effect=self._get(config, [])):
            second = b.get_capabilities()
        assert first.event_source == "poll"
        assert second.event_source == "unix_socket"


class TestEventChannelInfo:
    def test_default_is_poll_and_unreachable(self):
        stub = _make_stub_backend_cls()()
        info = stub.event_channel_info()
        assert (info.kind, info.reachable) == ("poll", False)

    def test_mini_with_channel_names_the_socket(self):
        config = {"event_channel": 1, "event_socket": "/run/owntone-mini/events.sock"}
        with patch("autostream_players._session.get", return_value=_resp(json_data=config)):
            info = _mini().event_channel_info()
        assert info == ap.EventChannelInfo(
            kind="unix_socket", protocol=1, socket_path="/run/owntone-mini/events.sock", reachable=True)

    def test_mini_with_channel_off_is_poll_but_reachable(self):
        config = {"event_channel": 0, "event_socket": None}
        with patch("autostream_players._session.get", return_value=_resp(json_data=config)):
            info = _mini().event_channel_info()
        assert (info.kind, info.reachable, info.socket_path) == ("poll", True, None)

    def test_mini_without_a_socket_path_is_poll(self):
        config = {"event_channel": 1, "event_socket": ""}
        with patch("autostream_players._session.get", return_value=_resp(json_data=config)):
            info = _mini().event_channel_info()
        assert info.kind == "poll"

    def test_mini_without_the_keys_is_poll(self):
        with patch("autostream_players._session.get", return_value=_resp(json_data={"product_name": "owntone-mini"})):
            info = _mini().event_channel_info()
        assert (info.kind, info.protocol, info.reachable) == ("poll", 0, True)

    def test_mini_unreachable_is_poll_and_not_reachable(self):
        with patch("autostream_players._session.get", side_effect=_req_exc()):
            info = _mini().event_channel_info()
        assert (info.kind, info.reachable) == ("poll", False)

    def test_mini_probe_is_not_cached(self):
        b = _mini()
        with patch("autostream_players._session.get", return_value=_resp(json_data={})) as mock_get:
            b.event_channel_info()
            b.event_channel_info()
        assert mock_get.call_count == 2

    def test_upstream_is_a_websocket_with_its_port(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        with patch("autostream_players._session.get", return_value=_resp(json_data={"websocket_port": 3688})):
            info = b.event_channel_info()
        assert info == ap.EventChannelInfo(kind="websocket", websocket_port=3688, reachable=True)
        assert b.get_capabilities().event_source == "websocket"
        assert b.get_capabilities().delivers_device_events is False

    def test_upstream_without_a_port_reports_zero(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        with patch("autostream_players._session.get", return_value=_resp(json_data={})):
            info = b.event_channel_info()
        assert (info.kind, info.websocket_port, info.reachable) == ("websocket", 0, True)


class TestIncludeTv:
    def test_mini_puts_include_tv_next_to_selected(self):
        b = _mini()
        with patch("autostream_players._session.put", return_value=_resp(status=204, content=b"")) as mock_put:
            result = b.update_output("9", enabled=True, include_tv=False)
        assert result.ok
        assert mock_put.call_args.kwargs["json"] == {"selected": True, "include_tv": False}

    def test_mini_leaves_include_tv_out_when_not_given(self):
        b = _mini()
        with patch("autostream_players._session.put", return_value=_resp(status=204, content=b"")) as mock_put:
            b.update_output("9", enabled=True)
        assert "include_tv" not in mock_put.call_args.kwargs["json"]

    def test_upstream_accepts_and_ignores_include_tv(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        with patch("autostream_players._session.put", return_value=_resp(status=204, content=b"")) as mock_put:
            result = b.update_output("9", enabled=True, include_tv=False)
        assert result.ok
        assert mock_put.call_args.kwargs["json"] == {"selected": True}

    @pytest.mark.parametrize("code", ["reselect_required", "group_not_present"])
    def test_409_bodies_become_error_codes(self, code):
        b = _mini()
        r = _resp(status=409, json_data={"error": code})
        with patch("autostream_players._session.put", return_value=r):
            result = b.update_output("9", enabled=True, include_tv=False)
        assert not result.ok
        assert result.error_code == code

    def test_other_409_stays_an_http_error(self):
        b = _mini()
        r = _resp(status=409, json_data={"error": "something_else"})
        with patch("autostream_players._session.put", return_value=r):
            result = b.update_output("9", enabled=True)
        assert result.error_code == "http_error"

    def test_player_service_passes_include_tv_through(self):
        import autostream_player_service as ps
        backend = MagicMock()
        backend.update_output.return_value = ap.ActionResult(ok=True)
        with patch.object(ps, "resolve_backend", return_value=MagicMock(backend=backend)):
            ps.update_output("http://x:3689", "9", enabled=True, include_tv=False)
        assert backend.update_output.call_args.kwargs["include_tv"] is False


class TestTimeoutsHaveTheirOwnCode:
    def _timeout(self):
        import requests as rq
        return rq.Timeout("timed out")

    def _refused(self):
        import requests as rq
        return rq.ConnectionError("refused")

    @pytest.mark.parametrize("make", [OwnToneBackend, OwnToneMiniBackend])
    def test_list_outputs(self, make):
        b = make(base_url="http://localhost:3689")
        with patch("autostream_players._session.get", side_effect=self._timeout()):
            assert b.list_outputs().error_code == "timeout"
        with patch("autostream_players._session.get", side_effect=self._refused()):
            assert b.list_outputs().error_code == "request_failed"

    @pytest.mark.parametrize("make", [OwnToneBackend, OwnToneMiniBackend])
    def test_get_output(self, make):
        b = make(base_url="http://localhost:3689")
        with patch("autostream_players._session.get", side_effect=self._timeout()):
            assert b.get_output("1").error_code == "timeout"
        with patch("autostream_players._session.get", side_effect=self._refused()):
            assert b.get_output("1").error_code == "request_failed"

    @pytest.mark.parametrize("make", [OwnToneBackend, OwnToneMiniBackend])
    def test_put_output_fields(self, make):
        b = make(base_url="http://localhost:3689")
        with patch("autostream_players._session.put", side_effect=self._timeout()):
            assert b.set_output_enabled("1", True).error_code == "timeout"
        with patch("autostream_players._session.put", side_effect=self._refused()):
            assert b.set_output_enabled("1", True).error_code == "request_failed"

    @pytest.mark.parametrize("make", [OwnToneBackend, OwnToneMiniBackend])
    def test_put_json(self, make):
        b = make(base_url="http://localhost:3689")
        with patch("autostream_players._session.put", side_effect=self._timeout()):
            assert b.set_selected_outputs([]).error_code == "timeout"
        with patch("autostream_players._session.put", side_effect=self._refused()):
            assert b.set_selected_outputs([]).error_code == "request_failed"

    def test_get_json_marks_a_timeout_in_its_error_text(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        with patch("autostream_players._session.get", side_effect=self._timeout()):
            _payload, _response, err = b._get_json("/api/x")
        assert ap.is_timeout(err)
        assert "timed out" in err
