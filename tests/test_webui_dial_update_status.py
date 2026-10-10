"""Appliance proxy of the dial's firmware update status.

The Setup page dial card polls /api/dial/update/status/<uuid>; the proxy must
hand the dial's body through untouched so the progress, retry and rollback
fields reach the page, and must report an unreachable dial in the tunneled
dial_offline shape the page treats as "restarting".
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_webui_dials import handle_dial_update_status

_STATUS = {
    "state": "failed",
    "version": "0.6.0",
    "percent": 100,
    "message": "Update failed; the previous release was restored",
    "phase": "rolled_back",
    "tag": "0.7.0",
    "previous_tag": "0.6.0",
    "attempt": 2,
    "max_attempts": 4,
    "rolled_back": True,
    "last_run_at": "2026-01-01T00:00:00+00:00",
}


def _capture(fn):
    sent = []

    def fake_send_json(handler, code, data):
        sent.append((code, dict(data)))

    with patch("autostream_webui_dials.send_json", side_effect=fake_send_json), \
         patch("autostream_webui_api.send_json", side_effect=fake_send_json):
        fn()
    return sent


def test_update_status_proxy_passes_result_fields_through():
    import json
    conn = MagicMock()
    resp = MagicMock()
    resp.status = 200
    resp.read.return_value = json.dumps(_STATUS).encode()
    conn.getresponse.return_value = resp
    sighting = MagicMock(ip="192.0.2.9", port=7842)
    with patch("autostream_webui_dials.get_dial_sighting", return_value=sighting), \
         patch("autostream_webui_dials.http.client.HTTPConnection", return_value=conn):
        sent = _capture(lambda: handle_dial_update_status(MagicMock(), "uuid"))
    code, data = sent[0]
    assert code == 200
    assert data == _STATUS
    assert conn.request.call_args[0][1] == "/update/status"


def test_update_status_offline_is_tunneled_dial_offline():
    with patch("autostream_webui_dials.get_dial_sighting", return_value=None):
        sent = _capture(lambda: handle_dial_update_status(MagicMock(), "uuid"))
    code, data = sent[0]
    assert code == 200
    assert data["error"] == "dial_offline"
    assert data["retryable"] is True
