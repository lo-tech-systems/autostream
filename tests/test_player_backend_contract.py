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
        with patch("autostream_players.requests.get",
                   return_value=_resp(json_data=payload)):
            result = backend.list_outputs()
        assert result.ok is True
        assert len(result.outputs) == 1
        out = result.outputs[0]
        assert out.id == "1"
        assert out.volume_percent == 50
        assert out.offset_ms == 100

    def test_network_error_returns_failure(self, backend):
        with patch("autostream_players.requests.get", side_effect=_req_exc()):
            result = backend.list_outputs()
        assert result.ok is False
        assert result.error_code in ("request_failed", "http_error", "")

    def test_http_error_returns_failure(self, backend):
        with patch("autostream_players.requests.get",
                   return_value=_resp(status=503)):
            result = backend.list_outputs()
        assert result.ok is False

    def test_empty_outputs_list_returns_ok(self, backend):
        payload = {"outputs": []}
        with patch("autostream_players.requests.get",
                   return_value=_resp(json_data=payload)):
            result = backend.list_outputs()
        assert result.ok is True
        assert result.outputs == ()


class TestGetOutputContract:
    def test_success_returns_ok_with_output(self, backend):
        with patch("autostream_players.requests.get",
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
        with patch("autostream_players.requests.get", return_value=r):
            result = backend.get_output("99")
        assert result.ok is False
        assert result.error_code == "not_found"

    def test_network_error_returns_failure(self, backend):
        with patch("autostream_players.requests.get", side_effect=_req_exc()):
            result = backend.get_output("1")
        assert result.ok is False


class TestStopContract:
    def test_stop_success_returns_ok(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players.requests.put", return_value=r):
            result = backend.stop()
        assert result.ok is True

    def test_stop_network_error_returns_failure(self, backend):
        with patch("autostream_players.requests.put", side_effect=_req_exc()):
            result = backend.stop()
        assert result.ok is False


class TestSetVolumeContract:
    def test_volume_clamped_to_100(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players.requests.put", return_value=r) as mock_put:
            result = backend.set_output_volume("1", 9999)
        assert result.ok is True
        assert mock_put.call_args[0][0] == "http://localhost:3689/api/outputs/1"
        assert mock_put.call_args[1].get("json") == {"volume": 100}

    def test_volume_clamped_to_0(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players.requests.put", return_value=r) as mock_put:
            result = backend.set_output_volume("1", -100)
        assert result.ok is True
        assert mock_put.call_args[0][0] == "http://localhost:3689/api/outputs/1"
        assert mock_put.call_args[1].get("json") == {"volume": 0}

    def test_non_numeric_volume_defaults_to_0(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players.requests.put", return_value=r) as mock_put:
            result = backend.set_output_volume("1", "bad")
        assert result.ok is True
        assert mock_put.call_args[1].get("json") == {"volume": 0}


class TestSetOffsetContract:
    def test_offset_clamped_high(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players.requests.put", return_value=r) as mock_put:
            result = backend.set_output_offset("1", 99999)
        assert result.ok is True
        assert mock_put.call_args[0][0] == "http://localhost:3689/api/outputs/1"
        assert mock_put.call_args[1].get("json") == {"offset_ms": 2000}

    def test_offset_clamped_low(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players.requests.put", return_value=r) as mock_put:
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
        with patch("autostream_players.requests.put", return_value=r) as mock_put:
            result = backend.submit_output_pin("1", "1234")
        assert result.ok is True
        assert mock_put.call_args[0][0] == "http://localhost:3689/api/outputs/1"
        assert mock_put.call_args[1].get("json") == {"pin": "1234"}


class TestSetOutputEnabledContract:
    def test_enable_sends_selected_true(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players.requests.put", return_value=r) as mock_put:
            result = backend.set_output_enabled("1", True)
        assert result.ok is True
        assert mock_put.call_args[0][0] == "http://localhost:3689/api/outputs/1"
        assert mock_put.call_args[1].get("json") == {"selected": True}

    def test_disable_sends_selected_false(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players.requests.put", return_value=r) as mock_put:
            result = backend.set_output_enabled("1", False)
        assert result.ok is True
        assert mock_put.call_args[0][0] == "http://localhost:3689/api/outputs/1"
        assert mock_put.call_args[1].get("json") == {"selected": False}


class TestSetSelectedOutputsContract:
    def test_selected_outputs_sends_ids_list(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players.requests.put", return_value=r) as mock_put:
            result = backend.set_selected_outputs(["id1", "id2"])
        assert result.ok is True
        assert mock_put.call_args[0][0] == "http://localhost:3689/api/outputs/set"
        assert mock_put.call_args[1].get("json") == {"outputs": ["id1", "id2"]}

    def test_empty_ids_sends_empty_list(self, backend):
        r = _resp(status=204, content=b"")
        with patch("autostream_players.requests.put", return_value=r) as mock_put:
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
        with patch("autostream_players.requests.put", return_value=r) as mock_put:
            b.update_output("1", enabled=True, mode="airplay1")
        call_json = mock_put.call_args[1].get("json")
        assert call_json.get("mode") == "raop"

    def test_airplay2_passed_through(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        r = _resp(status=204, content=b"")
        with patch("autostream_players.requests.put", return_value=r) as mock_put:
            b.update_output("1", enabled=True, mode="airplay2")
        call_json = mock_put.call_args[1].get("json")
        assert call_json.get("mode") == "airplay2"

    def test_auto_passed_through(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        r = _resp(status=204, content=b"")
        with patch("autostream_players.requests.put", return_value=r) as mock_put:
            b.update_output("1", enabled=True, mode="auto")
        call_json = mock_put.call_args[1].get("json")
        assert call_json.get("mode") == "auto"

    def test_unknown_mode_omitted_from_payload(self):
        b = OwnToneMiniBackend(base_url="http://localhost:3689")
        r = _resp(status=204, content=b"")
        with patch("autostream_players.requests.put", return_value=r) as mock_put:
            b.update_output("1", enabled=True, mode="legacy")
        call_json = mock_put.call_args[1].get("json")
        assert "mode" not in call_json

    def test_full_owntone_ignores_mode(self):
        b = OwnToneBackend(base_url="http://localhost:3689")
        r = _resp(status=204, content=b"")
        with patch("autostream_players.requests.put", return_value=r) as mock_put:
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
        with patch("autostream_players.requests.get", return_value=r):
            result = b.get_setting(ap.SETTING_PIPE_PATH)
        assert result.ok is True
        assert result.value == "/tmp/audio.fifo"

    def test_404_returns_unsupported(self):
        b = self._backend()
        r = _resp(status=404)
        r.content = b""
        with patch("autostream_players.requests.get", return_value=r):
            result = b.get_setting(ap.SETTING_PIPE_PATH)
        assert result.ok is False
        assert result.unsupported is True

    def test_bool_value_normalized_from_backend(self):
        b = self._backend()
        payload = {"value": 1}  # numeric true from server
        r = _resp(json_data=payload)
        with patch("autostream_players.requests.get", return_value=r):
            result = b.get_setting(ap.SETTING_PIPE_AUTOSTART)
        assert result.ok is True
        assert result.value is True

    def test_int_value_normalized(self):
        b = self._backend()
        payload = {"value": 2250}
        r = _resp(json_data=payload)
        with patch("autostream_players.requests.get", return_value=r):
            result = b.get_setting(ap.SETTING_START_BUFFER_MS)
        assert result.ok is True
        assert result.value == 2250


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
        with patch("autostream_players.requests.put",
                   return_value=self._ok_resp()) as mock_put:
            b.save_setting(ap.SETTING_PIPE_AUTOSTART, True)
        call_json = mock_put.call_args[1].get("json")
        assert call_json["value"] is True

    def test_int_clamped_to_min(self):
        b = self._backend()
        with patch("autostream_players.requests.put",
                   return_value=self._ok_resp()) as mock_put:
            b.save_setting(ap.SETTING_START_BUFFER_MS, 0)  # below min (300)
        call_json = mock_put.call_args[1].get("json")
        assert call_json["value"] == ap.SETTING_START_BUFFER_MS_MIN

    def test_int_clamped_to_max(self):
        b = self._backend()
        with patch("autostream_players.requests.put",
                   return_value=self._ok_resp()) as mock_put:
            b.save_setting(ap.SETTING_START_BUFFER_MS, 99999)  # above max (3500)
        call_json = mock_put.call_args[1].get("json")
        assert call_json["value"] == ap.SETTING_START_BUFFER_MS_MAX

    def test_device_removal_grace_period_clamped_to_min(self):
        b = self._backend()
        with patch("autostream_players.requests.put",
                   return_value=self._ok_resp()) as mock_put:
            b.save_setting(ap.SETTING_DEVICE_REMOVAL_GRACE_PERIOD, 0)  # below min (60 s)
        call_json = mock_put.call_args[1].get("json")
        assert call_json["value"] == 60  # 1 minute minimum in seconds

    def test_device_removal_grace_period_clamped_to_max(self):
        b = self._backend()
        with patch("autostream_players.requests.put",
                   return_value=self._ok_resp()) as mock_put:
            b.save_setting(ap.SETTING_DEVICE_REMOVAL_GRACE_PERIOD, 99999)
        call_json = mock_put.call_args[1].get("json")
        assert call_json["value"] == 900  # 15 minute maximum in seconds

    def test_restart_required_propagated(self):
        b = self._backend()
        with patch("autostream_players.requests.put",
                   return_value=self._ok_resp(restart_required=True)):
            result = b.save_setting(ap.SETTING_START_BUFFER_MS, 300)
        assert result.ok is True
        assert result.restart_required is True

    def test_network_error_returns_failure(self):
        b = self._backend()
        with patch("autostream_players.requests.put", side_effect=_req_exc()):
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
