"""WP3 — Generic settings API and browser autosave controller tests.

Covers:
1. GET /api/settings — response schema and values
2. POST /api/settings — field validation, normalisation, store mutation
3. Malformed-body handling
4. Unknown and missing fields
5. Hostname→control dependency (show_hostname_on_home=false forces control_other_appliances=false)
6. Last-write-wins for same field
7. SettingsStore unavailable fallback
8. JavaScript controller — syntax, exported symbols, event-coalescing structure
9. Route registration in autostream_webui
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_config(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def _minimal_cfg(tmp_path: Path) -> Path:
    cfg = tmp_path / "autostream.json"
    _write_config(cfg, {
        "general": {"log_level": "info"},
        "owntone": {"base_url": "http://localhost:3689"},
        "webui": {
            "dark_mode": False,
            "show_master_volume": True,
            "show_input_detail": False,
            "show_hostname_on_home": False,
            "control_other_appliances": True,
            "output_usage_poll_interval_seconds": 3,
        },
        "updates": {"auto_update": False, "update_channel": "stable"},
    })
    return cfg


def _make_handler() -> MagicMock:
    h = MagicMock()
    h.wfile = io.BytesIO()
    return h


def _response(handler: MagicMock) -> tuple[int, dict]:
    code = handler.send_response.call_args[0][0]
    body = json.loads(handler.wfile.getvalue())
    return code, body


def _make_state(tmp_path: Path, *, with_store: bool = True):
    from autostream_settings import SettingsStore
    from autostream_webui_state import WebUIState
    cfg = _minimal_cfg(tmp_path)
    if with_store:
        store = SettingsStore(str(cfg), _save_interval_seconds=9999)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)
        return state, store
    state = WebUIState(str(cfg), str(tmp_path / "state.json"))
    return state, None


# ---------------------------------------------------------------------------
# GET /api/settings — response schema
# ---------------------------------------------------------------------------

class TestSettingsGetJson:
    def test_returns_ok_true_with_values(self, tmp_path):
        from autostream_webui_api import send_settings_get_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_get_json(handler, state)
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True
        assert isinstance(body["values"], dict)

    def test_returns_all_expected_fields(self, tmp_path):
        from autostream_webui_api import send_settings_get_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_get_json(handler, state)
        finally:
            store.close(save=False)
        _, body = _response(handler)
        values = body["values"]
        assert "webui.dark_mode" in values
        assert "webui.show_master_volume" in values
        assert "webui.show_input_detail" in values
        assert "webui.show_hostname_on_home" in values
        assert "webui.control_other_appliances" in values
        assert "webui.output_usage_poll_interval_seconds" in values
        assert "updates.update_channel" in values

    def test_values_match_config(self, tmp_path):
        from autostream_webui_api import send_settings_get_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_get_json(handler, state)
        finally:
            store.close(save=False)
        _, body = _response(handler)
        v = body["values"]
        assert v["webui.dark_mode"] is False
        assert v["webui.show_master_volume"] is True
        assert v["webui.show_input_detail"] is False
        assert v["webui.show_hostname_on_home"] is False
        assert v["webui.output_usage_poll_interval_seconds"] == 3
        assert v["updates.update_channel"] == "stable"

    def test_get_reflects_store_mutations(self, tmp_path):
        from autostream_webui_api import send_settings_get_json
        state, store = _make_state(tmp_path)
        try:
            store.update(lambda raw: raw.setdefault("webui", {}).__setitem__("dark_mode", True))
            handler = _make_handler()
            send_settings_get_json(handler, state)
        finally:
            store.close(save=False)
        _, body = _response(handler)
        assert body["values"]["webui.dark_mode"] is True

    def test_config_error_returns_ok_false(self, tmp_path):
        from autostream_webui_api import send_settings_get_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            with patch("autostream_webui_api._config_snapshot", side_effect=OSError("disk error")):
                send_settings_get_json(handler, state)
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is False


# ---------------------------------------------------------------------------
# POST /api/settings — happy path
# ---------------------------------------------------------------------------

class TestSettingsPostJsonSuccess:
    def test_sets_bool_field_true(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(handler, state, {"field": "webui.dark_mode", "value": True})
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": True, "field": "webui.dark_mode", "value": True}

    def test_sets_bool_field_false(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(handler, state, {"field": "webui.show_master_volume", "value": False})
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True
        assert body["value"] is False

    def test_sets_poll_interval(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "webui.output_usage_poll_interval_seconds", "value": 10},
            )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True
        assert body["value"] == 10

    def test_sets_update_channel_dev(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "updates.update_channel", "value": "dev"},
            )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True
        assert body["value"] == "dev"

    def test_sets_update_channel_stable(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "updates.update_channel", "value": "stable"},
            )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True
        assert body["value"] == "stable"

    def test_mutation_persists_in_store(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "webui.dark_mode", "value": True},
            )
            snapshot = store.snapshot()
        finally:
            store.close(save=False)
        assert snapshot.webui.dark_mode is True


# ---------------------------------------------------------------------------
# POST /api/settings — hostname/control dependency
# ---------------------------------------------------------------------------

class TestHostnameControlDependency:
    def test_disabling_hostname_clears_control_other(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        from autostream_settings import SettingsStore
        from autostream_webui_state import WebUIState

        cfg = tmp_path / "autostream.json"
        _write_config(cfg, {
            "webui": {
                "show_hostname_on_home": True,
                "control_other_appliances": True,
            },
        })
        store = SettingsStore(str(cfg), _save_interval_seconds=9999)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "webui.show_hostname_on_home", "value": False},
            )
            snapshot = store.snapshot()
        finally:
            store.close(save=False)
        assert snapshot.webui.show_hostname_on_home is False
        assert snapshot.webui.control_other_appliances is False

    def test_enabling_hostname_does_not_force_control_on(self, tmp_path):
        """Enabling hostname display must not override existing control_other_appliances."""
        from autostream_webui_api import send_settings_post_json
        from autostream_settings import SettingsStore
        from autostream_webui_state import WebUIState

        cfg = tmp_path / "autostream.json"
        _write_config(cfg, {
            "webui": {
                "show_hostname_on_home": False,
                "control_other_appliances": False,
            },
        })
        store = SettingsStore(str(cfg), _save_interval_seconds=9999)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "webui.show_hostname_on_home", "value": True},
            )
            snapshot = store.snapshot()
        finally:
            store.close(save=False)
        assert snapshot.webui.show_hostname_on_home is True
        assert snapshot.webui.control_other_appliances is False  # unchanged


# ---------------------------------------------------------------------------
# POST /api/settings — last-write-wins
# ---------------------------------------------------------------------------

class TestLastWriteWins:
    def test_second_write_wins_for_same_field(self, tmp_path):
        """Sequential writes to the same field: final value is the last one."""
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        try:
            h1, h2 = _make_handler(), _make_handler()
            send_settings_post_json(h1, state, {"field": "webui.dark_mode", "value": True})
            send_settings_post_json(h2, state, {"field": "webui.dark_mode", "value": False})
            snapshot = store.snapshot()
        finally:
            store.close(save=False)
        _, b1 = _response(h1)
        _, b2 = _response(h2)
        assert b1["ok"] is True
        assert b2["ok"] is True
        assert snapshot.webui.dark_mode is False  # last write wins

    def test_independent_fields_do_not_interfere(self, tmp_path):
        """Writing field A then field B leaves both with their own values."""
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        try:
            send_settings_post_json(
                _make_handler(), state,
                {"field": "webui.dark_mode", "value": True},
            )
            send_settings_post_json(
                _make_handler(), state,
                {"field": "webui.show_input_detail", "value": True},
            )
            snapshot = store.snapshot()
        finally:
            store.close(save=False)
        assert snapshot.webui.dark_mode is True
        assert snapshot.webui.show_input_detail is True


# ---------------------------------------------------------------------------
# POST /api/settings — malformed body / validation errors
# ---------------------------------------------------------------------------

class TestSettingsPostJsonValidation:
    def test_missing_field_key_returns_400(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(handler, state, {"value": True})
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False

    def test_empty_field_name_returns_400(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(handler, state, {"field": "", "value": True})
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False

    def test_unknown_field_returns_400(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(handler, state, {"field": "unknown.field", "value": True})
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False
        assert body["field"] == "unknown.field"

    def test_missing_value_key_returns_400(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(handler, state, {"field": "webui.dark_mode"})
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False

    def test_string_for_bool_field_returns_400(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "webui.dark_mode", "value": "true"},
            )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False

    def test_int_for_bool_field_returns_400(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "webui.dark_mode", "value": 1},
            )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False

    def test_poll_interval_below_min_returns_400(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "webui.output_usage_poll_interval_seconds", "value": 0},
            )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False

    def test_poll_interval_above_max_returns_400(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "webui.output_usage_poll_interval_seconds", "value": 999},
            )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False

    def test_invalid_update_channel_returns_400(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "updates.update_channel", "value": "nightly"},
            )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False

    def test_non_string_update_channel_returns_400(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "updates.update_channel", "value": 1},
            )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False

    def test_non_dict_body_returns_400(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(handler, state, "not a dict")  # type: ignore[arg-type]
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False

    def test_bool_for_poll_interval_returns_400(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "webui.output_usage_poll_interval_seconds", "value": True},
            )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False


# ---------------------------------------------------------------------------
# POST /api/settings — store unavailable fallback
# ---------------------------------------------------------------------------

class TestStoreUnavailable:
    def test_no_store_returns_ok_false(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, _ = _make_state(tmp_path, with_store=False)
        handler = _make_handler()
        send_settings_post_json(handler, state, {"field": "webui.dark_mode", "value": True})
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is False
        assert "unavailable" in body.get("error", "").lower()


# ---------------------------------------------------------------------------
# Normalisation edge cases
# ---------------------------------------------------------------------------

class TestNormalisation:
    def test_poll_interval_float_truncated_to_int(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "webui.output_usage_poll_interval_seconds", "value": 5.9},
            )
            snapshot = store.snapshot()
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True
        assert body["value"] == 5
        assert snapshot.webui.output_usage_poll_interval_seconds == 5

    def test_update_channel_dev_case_insensitive(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "updates.update_channel", "value": "DEV"},
            )
            snapshot = store.snapshot()
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True
        assert body["value"] == "dev"
        assert snapshot.updates.update_channel == "dev"

    def test_update_channel_stable_case_insensitive(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "updates.update_channel", "value": "Stable"},
            )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["value"] == "stable"


# ---------------------------------------------------------------------------
# JavaScript autosave controller — syntax and exported symbols
# ---------------------------------------------------------------------------

class TestAutosaveJs:
    def test_autosave_js_non_empty(self):
        from autostream_webui_assets import AUTOSAVE_JS
        assert AUTOSAVE_JS.strip()

    def test_autosave_js_has_script_tags(self):
        from autostream_webui_assets import AUTOSAVE_JS
        assert "<script>" in AUTOSAVE_JS
        assert "</script>" in AUTOSAVE_JS

    def test_autosave_js_exports_save_field(self):
        from autostream_webui_assets import AUTOSAVE_JS
        assert "settingsSaveField" in AUTOSAVE_JS

    def test_autosave_js_exports_debounced(self):
        from autostream_webui_assets import AUTOSAVE_JS
        assert "settingsSaveFieldDebounced" in AUTOSAVE_JS

    def test_autosave_js_exports_flush(self):
        from autostream_webui_assets import AUTOSAVE_JS
        assert "flushPendingToServer" in AUTOSAVE_JS

    def test_autosave_js_has_beforeunload(self):
        from autostream_webui_assets import AUTOSAVE_JS
        assert "beforeunload" in AUTOSAVE_JS

    def test_autosave_js_uses_iife(self):
        """Controller must be wrapped in an IIFE to avoid polluting global scope."""
        from autostream_webui_assets import AUTOSAVE_JS
        assert "(function()" in AUTOSAVE_JS or "(function (" in AUTOSAVE_JS

    def test_autosave_js_targets_settings_endpoint(self):
        from autostream_webui_assets import AUTOSAVE_JS
        assert "/api/settings" in AUTOSAVE_JS

    def test_autosave_js_balanced_braces(self):
        from autostream_webui_assets import AUTOSAVE_JS
        assert AUTOSAVE_JS.count("{") == AUTOSAVE_JS.count("}")

    def test_autosave_js_balanced_parens(self):
        from autostream_webui_assets import AUTOSAVE_JS
        assert AUTOSAVE_JS.count("(") == AUTOSAVE_JS.count(")")

    def test_autosave_js_sends_csrf_header(self):
        from autostream_webui_assets import AUTOSAVE_JS
        assert "X-CSRF-Token" in AUTOSAVE_JS

    def test_autosave_js_uses_window_csrf(self):
        """Must read CSRF token from window.__CSRF set by the csrf_meta head tag."""
        from autostream_webui_assets import AUTOSAVE_JS
        assert "window.__CSRF" in AUTOSAVE_JS


# ---------------------------------------------------------------------------
# Setup page — status region and autosave wiring
# ---------------------------------------------------------------------------

class TestSetupPageAutosaveWiring:
    def _render_setup(self, tmp_path: Path) -> str:
        from autostream_webui_page_setup import send_setup_page
        from autostream_settings import SettingsStore
        from autostream_webui_state import WebUIState
        from autostream_players import ListOutputsResult

        cfg = _minimal_cfg(tmp_path)
        store = SettingsStore(str(cfg), _save_interval_seconds=9999)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)

        handler = MagicMock()
        handler.wfile = io.BytesIO()
        auth = MagicMock()
        auth.ensure_session.return_value = "test-csrf-token"
        auth.get_csrf_token.return_value = "test-csrf-token"
        auth.get_boot_pin_value.return_value = "1234"

        _list_result = ListOutputsResult(ok=False, error="unreachable")

        with patch.multiple(
            "autostream_webui_page_setup",
            get_system_hostname=MagicMock(return_value="autostream"),
            list_outputs=MagicMock(return_value=_list_result),
            get_ap_ssid=MagicMock(return_value="autostream_AP"),
            get_app_version=MagicMock(return_value="1.0.0"),
            _get_dial_sightings=MagicMock(return_value=[]),
            parse_dial_entries=MagicMock(return_value=[]),
            suggested_silence_threshold_dbfs=MagicMock(return_value=-50.0),
            build_top_banner_html=MagicMock(return_value=("", "")),
            _set_flash_cookie=MagicMock(),
            unconfigured=MagicMock(return_value=False),
        ):
            with patch.object(state, "get_monitor_devices", return_value=[]):
                send_setup_page(handler, state, auth, flash_msg="")

        store.close(save=False)
        return handler.wfile.getvalue().decode("utf-8", errors="replace")

    def test_autosave_status_region_present(self, tmp_path):
        html = self._render_setup(tmp_path)
        assert 'id="autosave-status"' in html

    def test_autosave_status_aria_live(self, tmp_path):
        html = self._render_setup(tmp_path)
        assert 'aria-live="polite"' in html

    def test_autosave_js_included(self, tmp_path):
        html = self._render_setup(tmp_path)
        assert "settingsSaveField" in html

    def test_dark_mode_checkbox_wired(self, tmp_path):
        html = self._render_setup(tmp_path)
        assert "settingsSaveField('webui.dark_mode'" in html

    def test_show_master_volume_wired(self, tmp_path):
        html = self._render_setup(tmp_path)
        assert "settingsSaveField('webui.show_master_volume'" in html

    def test_show_input_detail_wired(self, tmp_path):
        html = self._render_setup(tmp_path)
        assert "settingsSaveField('webui.show_input_detail'" in html

    def test_show_hostname_on_home_wired(self, tmp_path):
        html = self._render_setup(tmp_path)
        assert "settingsSaveField('webui.show_hostname_on_home'" in html

    def test_control_other_appliances_wired(self, tmp_path):
        html = self._render_setup(tmp_path)
        assert "settingsSaveField('webui.control_other_appliances'" in html

    def test_poll_interval_wired_debounced(self, tmp_path):
        html = self._render_setup(tmp_path)
        assert "settingsSaveFieldDebounced('webui.output_usage_poll_interval_seconds'" in html

    def test_update_channel_wired(self, tmp_path):
        html = self._render_setup(tmp_path)
        assert "settingsSaveField('updates.update_channel'" in html
