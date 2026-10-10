"""Tests for GET /api/dial/capabilities.

Covers: reply shape and the pinned key set (the endpoint is unauthenticated,
so it must never grow a field the mDNS records do not already broadcast), the
capability table, a null appliance_id for an identity-less appliance, the
no-store cache header, and the route registration (allowlisted, dial scheme).
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_auth as auth_mod
import autostream_webui_routes as routes_mod
from autostream_dials import DIAL_CAPABILITIES, DIAL_PROTO_VERSION
from autostream_webui_api import send_dial_capabilities_json

APPLIANCE_ID = "a1b2c3d4e5f6a7b8c9d0"


def _call(appliance_id=APPLIANCE_ID, version="0.8.0"):
    handler = MagicMock()
    handler.wfile = io.BytesIO()
    with patch("autostream_webui_api.get_appliance_id", return_value=appliance_id), \
         patch("autostream_webui_api.get_app_version", return_value=version):
        send_dial_capabilities_json(handler, MagicMock())
    code = handler.send_response.call_args[0][0]
    headers = {c[0][0]: c[0][1] for c in handler.send_header.call_args_list}
    return code, json.loads(handler.wfile.getvalue()), headers


class TestReply:
    def test_shape(self):
        code, body, _ = _call()
        assert code == 200
        assert body == {
            "ok": True,
            "appliance_id": APPLIANCE_ID,
            "version": "0.8.0",
            "dial_proto": 3,
            "capabilities": {
                "dial_status": 1,
                "dial_outputs": 2,
                "dial_eq": 2,
                "repeat": 1,
                "audio_status": 1,
                "dial_warnings": 1,
            },
        }

    def test_key_set_is_pinned(self):
        _, body, _ = _call()
        assert set(body) == {"ok", "appliance_id", "version", "dial_proto", "capabilities"}

    def test_dial_proto_is_the_integer_of_the_advertised_dialect(self):
        _, body, _ = _call()
        assert body["dial_proto"] == int(DIAL_PROTO_VERSION[1:])

    def test_capabilities_are_positive_integers(self):
        _, body, _ = _call()
        for name, version in body["capabilities"].items():
            assert isinstance(version, int) and not isinstance(version, bool), name
            assert version >= 1, name

    def test_appliance_id_null_without_identity(self):
        _, body, _ = _call(appliance_id=None)
        assert body["appliance_id"] is None

    def test_cache_control_is_no_store(self):
        _, _, headers = _call()
        assert "no-store" in headers["Cache-Control"]

    def test_reply_does_not_alias_the_table(self):
        _, body, _ = _call()
        body["capabilities"]["dial_eq"] = 99
        assert DIAL_CAPABILITIES["dial_eq"] == 2

    def test_warnings_capability_is_listed_at_version_one(self):
        assert DIAL_CAPABILITIES["dial_warnings"] == 1


class TestRegistration:
    def test_route_is_a_dial_scheme_get(self):
        matches = [r for r in routes_mod.ROUTES
                   if r.path == "/api/dial/capabilities" and "GET" in r.methods]
        assert len(matches) == 1
        assert matches[0].scheme == "dial"
        assert matches[0].methods == ("GET",)

    def test_path_is_allowlisted(self):
        assert "/api/dial/capabilities" in auth_mod.ALLOWLIST_PATHS

    def test_documented_in_dial_protocol(self):
        text = (REPO_ROOT / "docs" / "dial" / "DIAL_PROTOCOL.md").read_text(encoding="utf-8")
        assert "/api/dial/capabilities" in text
        for name in DIAL_CAPABILITIES:
            assert f"`{name}`" in text


class TestOutputsCapability:
    def test_outputs_capability_is_two(self):
        _, body, _ = _call()
        assert body["capabilities"]["dial_outputs"] == 2

    def test_every_capability_name_appears_in_the_protocol_doc(self):
        from pathlib import Path
        from autostream_dials import DIAL_CAPABILITIES
        doc = (Path(__file__).resolve().parent.parent / "docs" / "dial" / "DIAL_PROTOCOL.md"
               ).read_text(encoding="utf-8")
        for name in DIAL_CAPABILITIES:
            assert f"`{name}" in doc, name

    def test_txt_value_for_outputs_stays_v1_in_the_doc(self):
        from pathlib import Path
        doc = (Path(__file__).resolve().parent.parent / "docs" / "dial" / "DIAL_PROTOCOL.md"
               ).read_text(encoding="utf-8")
        assert "dial_outputs=v1" in doc
