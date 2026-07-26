"""Priority 7 — webui output EQ API tests.

Covers send_output_eq_config_json() (field validation, DB clamping,
bool parsing, all-band PEQ reconstruction, persistence failure, live-apply
failure, update_check/status endpoint pass-through) and
send_output_eq_reset_json() (all-fields zeroed, persistence failure).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_webui_api import (
    send_output_eq_config_json,
    send_output_eq_reset_json,
    send_update_check_json,
    send_update_status_json,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_cfg():
    return {
        "general": {"silence_seconds": 30},
        "owntone": {"base_url": "http://localhost:3689"},
        "audio1": {
            "capture_device": "hw:0,0",
            "silence_threshold": -66,
            "turntable": False,
            "stylus_life_hours": 500,
            "belt_life_hours": 0,
            "bearing_life_hours": 0,
            "belt_life_years": 0,
            "bearing_life_years": 0,
            "gain_db": 0,
            "eq_40hz_db": 0,
            "eq_100hz_db": 0,
            "eq_8khz_db": 0,
        },
        "audio2": {
            "capture_device": "hw:1,0",
            "silence_threshold": -66,
            "turntable": False,
            "stylus_life_hours": 250,
            "belt_life_hours": 0,
            "bearing_life_hours": 0,
            "belt_life_years": 0,
            "bearing_life_years": 0,
            "gain_db": 0,
            "eq_40hz_db": 0,
            "eq_100hz_db": 0,
            "eq_8khz_db": 0,
        },
        "output_eq": {
            "gain_db": 0.0,
            "peq1_db": 0.0, "peq2_db": 0.0, "peq3_db": 0.0,
            "peq4_db": 0.0, "peq5_db": 0.0, "peq6_db": 0.0,
            "auto_trim_enabled": False,
        },
    }


def _make_state(tmp_path: Path) -> MagicMock:
    cfg_path = tmp_path / "autostream.json"
    cfg_path.write_text(json.dumps(_minimal_cfg()), encoding="utf-8")
    state = MagicMock()
    state.config_path = cfg_path
    return state


def _call_eq_config(body: dict | str, tmp_path: Path,
                    save_exc=None, live_exc=None) -> tuple[int, dict]:
    if isinstance(body, dict):
        body_str = json.dumps(body)
    else:
        body_str = body
    sent = []

    def fake_send_json(h, code, data):
        sent.append((code, data))

    state = _make_state(tmp_path)

    with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
         patch("autostream_appliance_models.set_live_output_gain",
               side_effect=live_exc) if live_exc else patch("autostream_appliance_models.set_live_output_gain"), \
         patch("autostream_appliance_models.set_live_output_eq"), \
         patch("autostream_appliance_models.set_live_output_auto_trim"), \
         (patch("autostream_appliance_models.save_config", side_effect=save_exc)
          if save_exc else patch("autostream_appliance_models.save_config")):
        send_output_eq_config_json(MagicMock(), state, body_str)

    return sent[0] if sent else (None, {})


def _call_eq_reset(tmp_path: Path, save_exc=None) -> tuple[int, dict]:
    sent = []

    def fake_send_json(h, code, data):
        sent.append((code, data))

    state = _make_state(tmp_path)

    with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
         patch("autostream_appliance_models.set_live_output_gain"), \
         patch("autostream_appliance_models.set_live_output_eq"), \
         (patch("autostream_appliance_models.save_config", side_effect=save_exc)
          if save_exc else patch("autostream_appliance_models.save_config")):
        send_output_eq_reset_json(MagicMock(), state)

    return sent[0] if sent else (None, {})


# ---------------------------------------------------------------------------
# send_output_eq_config_json: field validation
# ---------------------------------------------------------------------------

class TestOutputEQConfigValidation:
    def test_unknown_field_returns_400(self, tmp_path):
        code, data = _call_eq_config({"field": "unknown_field", "value": "1.0"}, tmp_path)
        assert code == 400
        assert data["ok"] is False
        assert "Unknown field" in data["error"]

    def test_invalid_json_returns_400(self, tmp_path):
        code, data = _call_eq_config("not-json", tmp_path)
        assert code == 400

    def test_non_numeric_db_value_returns_400(self, tmp_path):
        code, data = _call_eq_config({"field": "gain_db", "value": "not-a-number"}, tmp_path)
        assert code == 400
        assert "numeric" in data["error"]


# ---------------------------------------------------------------------------
# send_output_eq_config_json: clamping
# ---------------------------------------------------------------------------

class TestOutputEQConfigClamping:
    def test_gain_clamped_to_max(self, tmp_path):
        code, data = _call_eq_config({"field": "gain_db", "value": "99"}, tmp_path)
        assert code == 200
        assert data["ok"] is True
        assert float(data["value"]) <= 12.0

    def test_gain_clamped_to_min(self, tmp_path):
        code, data = _call_eq_config({"field": "gain_db", "value": "-99"}, tmp_path)
        assert code == 200
        assert float(data["value"]) >= -12.0

    def test_peq_band_within_range_accepted(self, tmp_path):
        code, data = _call_eq_config({"field": "peq3_db", "value": "6.5"}, tmp_path)
        assert code == 200
        assert data["ok"] is True
        assert float(data["value"]) == pytest.approx(6.5)


# ---------------------------------------------------------------------------
# send_output_eq_config_json: bool field
# ---------------------------------------------------------------------------

class TestOutputEQConfigBoolField:
    def test_auto_trim_true_values(self, tmp_path):
        for val in ("true", "1", "yes", "True"):
            code, data = _call_eq_config({"field": "auto_trim_enabled", "value": val}, tmp_path)
            assert code == 200
            assert data["value"] == "true", f"Expected 'true' for input {val!r}"

    def test_auto_trim_false_values(self, tmp_path):
        for val in ("false", "0", "no", "False"):
            code, data = _call_eq_config({"field": "auto_trim_enabled", "value": val}, tmp_path)
            assert code == 200
            assert data["value"] == "false", f"Expected 'false' for input {val!r}"


# ---------------------------------------------------------------------------
# send_output_eq_config_json: all-band PEQ reconstruction
# ---------------------------------------------------------------------------

class TestOutputEQConfigAllBandReconstruction:
    def test_peq_change_calls_set_live_output_eq_with_all_bands(self, tmp_path):
        state = _make_state(tmp_path)
        sent = []

        def fake_send_json(h, code, data):
            sent.append((code, data))

        eq_calls = []

        with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_appliance_models.set_live_output_gain"), \
             patch("autostream_appliance_models.set_live_output_auto_trim"), \
             patch("autostream_appliance_models.set_live_output_eq",
                   side_effect=lambda *a: eq_calls.append(a)):
            send_output_eq_config_json(
                MagicMock(), state,
                json.dumps({"field": "peq2_db", "value": "3.0"}),
            )

        assert eq_calls, "set_live_output_eq must be called for a PEQ band change"
        assert len(eq_calls[0]) == 6, "All six bands must be passed to set_live_output_eq"

    def test_gain_change_calls_set_live_output_gain_not_eq(self, tmp_path):
        state = _make_state(tmp_path)
        gain_calls = []
        eq_calls = []

        with patch("autostream_webui_api.send_json"), \
             patch("autostream_appliance_models.set_live_output_auto_trim"), \
             patch("autostream_appliance_models.set_live_output_gain",
                   side_effect=lambda v: gain_calls.append(v)), \
             patch("autostream_appliance_models.set_live_output_eq",
                   side_effect=lambda *a: eq_calls.append(a)):
            send_output_eq_config_json(
                MagicMock(), state,
                json.dumps({"field": "gain_db", "value": "2.0"}),
            )

        assert gain_calls, "set_live_output_gain must be called for gain change"
        assert not eq_calls, "set_live_output_eq must NOT be called for gain change"


# ---------------------------------------------------------------------------
# send_output_eq_config_json: persistence failure
# ---------------------------------------------------------------------------

class TestOutputEQConfigPersistenceFailure:
    def test_save_failure_returns_ok_false(self, tmp_path):
        code, data = _call_eq_config(
            {"field": "gain_db", "value": "3.0"},
            tmp_path,
            save_exc=OSError("disk full"),
        )
        assert data["ok"] is False

    def test_save_failure_does_not_return_200_ok_true(self, tmp_path):
        code, data = _call_eq_config(
            {"field": "peq1_db", "value": "1.0"},
            tmp_path,
            save_exc=OSError("disk full"),
        )
        assert not (code == 200 and data.get("ok") is True)


# ---------------------------------------------------------------------------
# send_output_eq_reset_json
# ---------------------------------------------------------------------------

class TestOutputEQReset:
    def test_reset_returns_ok_true(self, tmp_path):
        code, data = _call_eq_reset(tmp_path)
        assert code == 200
        assert data["ok"] is True

    def test_reset_zeros_band_fields_in_config(self, tmp_path):
        state = _make_state(tmp_path)
        # Set some non-zero values first
        cfg = json.loads(state.config_path.read_text())
        cfg["output_eq"]["gain_db"] = 5.0
        cfg["output_eq"]["peq1_db"] = 3.0
        state.config_path.write_text(json.dumps(cfg))

        with patch("autostream_webui_api.send_json"), \
             patch("autostream_appliance_models.set_live_output_eq"):
            send_output_eq_reset_json(MagicMock(), state)

        saved = json.loads(state.config_path.read_text())
        for field in ("peq1_db", "peq2_db", "peq3_db", "peq4_db", "peq5_db", "peq6_db"):
            assert saved["output_eq"][field] == 0.0, f"{field} not zeroed"
        assert saved["output_eq"]["gain_db"] == 5.0, "gain_db must not be changed by Flat reset"

    def test_reset_calls_set_live_eq_but_not_gain(self, tmp_path):
        gain_calls = []
        eq_calls = []
        state = _make_state(tmp_path)

        with patch("autostream_webui_api.send_json"), \
             patch("autostream_appliance_models.set_live_output_gain",
                   side_effect=lambda v: gain_calls.append(v)), \
             patch("autostream_appliance_models.set_live_output_eq",
                   side_effect=lambda *a: eq_calls.append(a)):
            send_output_eq_reset_json(MagicMock(), state)

        assert gain_calls == [], "set_live_output_gain must not be called by Flat reset"
        assert eq_calls and all(v == 0.0 for v in eq_calls[0])

    def test_reset_save_failure_returns_ok_false(self, tmp_path):
        code, data = _call_eq_reset(tmp_path, save_exc=OSError("disk full"))
        assert data["ok"] is False


# ---------------------------------------------------------------------------
# send_update_check_json
# ---------------------------------------------------------------------------

class TestUpdateCheckJson:
    def _call(self) -> tuple[int, dict]:
        sent = []

        def fake_send_json(h, code, data):
            sent.append((code, data))

        with patch("autostream_webui_api.send_json", side_effect=fake_send_json):
            yield sent

    def test_nonzero_rc_returns_ok_false(self):
        sent = []
        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_webui_api.run_updater", return_value=(1, "", "error")):
            send_update_check_json(MagicMock())
        assert sent[0][1]["ok"] is False

    def test_zero_rc_passes_stdout_json(self):
        sent = []
        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_webui_api.run_updater",
                   return_value=(0, '{"ok": true, "tag": "v2.0.0"}', "")):
            send_update_check_json(MagicMock())
        assert sent[0][1]["ok"] is True
        assert sent[0][1]["tag"] == "v2.0.0"

    def test_malformed_stdout_returns_ok_false(self):
        sent = []
        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_webui_api.run_updater", return_value=(0, "not-json", "")):
            send_update_check_json(MagicMock())
        assert sent[0][1]["ok"] is False

    def test_release_notes_adds_rendered_html(self):
        sent = []
        payload = json.dumps({"ok": True, "tag": "v2.0.0", "release_notes": "- a\n- b"})
        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_webui_api.run_updater", return_value=(0, payload, "")):
            send_update_check_json(MagicMock())
        data = sent[0][1]
        assert data["ok"] is True
        assert data["release_notes"] == "- a\n- b"
        assert "release_notes_html" in data
        assert "<ul>" in data["release_notes_html"]

    def test_hostile_release_notes_are_escaped_in_html(self):
        sent = []
        payload = json.dumps({"ok": True, "release_notes": "<script>alert(1)</script>"})
        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_webui_api.run_updater", return_value=(0, payload, "")):
            send_update_check_json(MagicMock())
        html_out = sent[0][1]["release_notes_html"]
        assert "<script>" not in html_out
        assert "&lt;script&gt;" in html_out

    def test_no_release_notes_key_means_no_html_field(self):
        sent = []
        payload = json.dumps({"ok": True, "tag": "v2.0.0"})
        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_webui_api.run_updater", return_value=(0, payload, "")):
            send_update_check_json(MagicMock())
        assert "release_notes_html" not in sent[0][1]

    def test_empty_release_notes_means_no_html_field(self):
        sent = []
        payload = json.dumps({"ok": True, "release_notes": ""})
        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_webui_api.run_updater", return_value=(0, payload, "")):
            send_update_check_json(MagicMock())
        assert "release_notes_html" not in sent[0][1]

    def test_non_dict_stdout_passes_through_unchanged(self):
        sent = []
        payload = json.dumps(["not", "a", "dict"])
        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_webui_api.run_updater", return_value=(0, payload, "")):
            send_update_check_json(MagicMock())
        assert sent[0][1] == ["not", "a", "dict"]


# ---------------------------------------------------------------------------
# send_update_status_json
# ---------------------------------------------------------------------------

class TestUpdateStatusJson:
    def test_nonzero_rc_returns_error_status(self):
        sent = []
        proc = MagicMock(returncode=1, stdout="")
        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_webui_api.run_admin_cmd", return_value=proc):
            send_update_status_json(MagicMock())
        assert sent[0][1]["status"] == "error"
        assert sent[0][1]["ok"] is False

    def test_valid_status_passed_through(self):
        sent = []
        payload = json.dumps({"ok": True, "status": "success", "percent": 100,
                               "message": "Done", "last_run_at": "2026-01-01"})
        proc = MagicMock(returncode=0, stdout=payload)
        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_webui_api.run_admin_cmd", return_value=proc):
            send_update_status_json(MagicMock())
        assert sent[0][1]["status"] == "success"
        assert sent[0][1]["ok"] is True

    def test_malformed_stdout_returns_error_status(self):
        sent = []
        proc = MagicMock(returncode=0, stdout="not-json")
        with patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_webui_api.run_admin_cmd", return_value=proc):
            send_update_status_json(MagicMock())
        assert sent[0][1]["status"] == "error"
        assert sent[0][1]["ok"] is False
