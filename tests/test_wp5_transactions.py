"""tests/test_wp5_transactions.py

WP5 acceptance tests: External and privileged Setup transactions.

Tests cover:
  - POST /api/settings/hostname: success redirects; same value is no-op;
    empty hostname rejected; set_system_hostname failure does not commit
  - POST /api/settings/advertisement: success persists to store; failed
    privileged call does not commit; bool validation
  - POST /api/settings/auto-update: success persists to store; failed
    admin command does not commit; bool validation
  - POST /api/settings/save: flushes store; missing store returns error
  - handle_factory_reset_post: discards dirty store before resetting
  - settingsTransact exported from AUTOSAVE_JS
  - Setup page wires hostname modal/advertise/auto-update controls to transaction endpoints
"""
from __future__ import annotations

import io
import json
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_cfg(tmp_path: Path) -> Path:
    cfg = tmp_path / "autostream.json"
    cfg.write_text(json.dumps({
        "general": {"log_level": "info"},
        "owntone": {"base_url": "http://localhost:3689"},
        "webui": {
            "dark_mode": False,
            "advertise_appliance": False,
        },
        "updates": {"auto_update": False, "update_channel": "stable"},
    }), encoding="utf-8")
    return cfg


def _make_handler(host: str = "autostream.local") -> MagicMock:
    h = MagicMock()
    h.wfile = io.BytesIO()
    h.headers = {"Host": host}
    return h


def _response(handler: MagicMock) -> tuple[int, dict]:
    code = handler.send_response.call_args[0][0]
    body = json.loads(handler.wfile.getvalue())
    return code, body


def _make_state(tmp_path: Path):
    from autostream_settings import SettingsStore
    from autostream_webui_state import WebUIState
    cfg = _minimal_cfg(tmp_path)
    store = SettingsStore(str(cfg), _save_interval_seconds=9999)
    state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)
    return state, store


# ---------------------------------------------------------------------------
# /api/settings/hostname
# ---------------------------------------------------------------------------

class TestHostnameEndpoint:
    def test_same_hostname_returns_ok_not_changed(self, tmp_path):
        from autostream_webui_api import send_hostname_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        with patch("autostream_webui_api.get_system_hostname", return_value="autostream"):
            send_hostname_post_json(handler, state, json.dumps({"value": "autostream"}))
        code, data = _response(handler)
        assert code == 200
        assert data["ok"] is True
        assert data["changed"] is False
        store.close(save=False)

    def test_new_hostname_calls_set_system_hostname(self, tmp_path):
        from autostream_webui_api import send_hostname_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler("autostream.local")
        with patch("autostream_webui_api.get_system_hostname", return_value="autostream"), \
             patch("autostream_webui_api.set_system_hostname") as mock_set:
            send_hostname_post_json(handler, state, json.dumps({"value": "newname"}))
        mock_set.assert_called_once_with("newname")
        store.close(save=False)

    def test_success_returns_redirect_url(self, tmp_path):
        from autostream_webui_api import send_hostname_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler("autostream.local")
        with patch("autostream_webui_api.get_system_hostname", return_value="autostream"), \
             patch("autostream_webui_api.set_system_hostname"):
            send_hostname_post_json(handler, state, json.dumps({"value": "newname"}))
        code, data = _response(handler)
        assert code == 200
        assert data["ok"] is True
        assert data["changed"] is True
        assert "redirect_url" in data
        assert "newname.local" in data["redirect_url"]
        assert "/setup" in data["redirect_url"]
        store.close(save=False)

    def test_redirect_url_includes_port_when_present(self, tmp_path):
        from autostream_webui_api import send_hostname_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler("autostream.local:8080")
        with patch("autostream_webui_api.get_system_hostname", return_value="autostream"), \
             patch("autostream_webui_api.set_system_hostname"):
            send_hostname_post_json(handler, state, json.dumps({"value": "newname"}))
        _, data = _response(handler)
        assert "8080" in data["redirect_url"]
        store.close(save=False)

    def test_empty_hostname_returns_400(self, tmp_path):
        from autostream_webui_api import send_hostname_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        send_hostname_post_json(handler, state, json.dumps({"value": ""}))
        code, data = _response(handler)
        assert code == 400
        assert data["ok"] is False
        store.close(save=False)

    def test_set_system_hostname_failure_does_not_report_success(self, tmp_path):
        from autostream_webui_api import send_hostname_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        with patch("autostream_webui_api.get_system_hostname", return_value="autostream"), \
             patch("autostream_webui_api.set_system_hostname", side_effect=RuntimeError("perm denied")):
            send_hostname_post_json(handler, state, json.dumps({"value": "newname"}))
        code, data = _response(handler)
        assert code == 200
        assert data["ok"] is False
        assert "error" in data
        store.close(save=False)

    def test_invalid_json_returns_400(self, tmp_path):
        from autostream_webui_api import send_hostname_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        send_hostname_post_json(handler, state, "not json")
        code, data = _response(handler)
        assert code == 400
        assert data["ok"] is False
        store.close(save=False)


# ---------------------------------------------------------------------------
# /api/settings/advertisement
# ---------------------------------------------------------------------------

class TestAdvertisementEndpoint:
    def _call(self, tmp_path, value: bool, *, reconcile_ok: bool = True):
        from autostream_webui_api import send_advertisement_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        with patch("autostream_webui_api.reconcile_appliance_announcement", return_value=reconcile_ok), \
             patch("autostream_webui_api.get_app_version", return_value="1.0.0"), \
             patch("autostream_webui_api.reconcile_appliance_announcement",
                   create=True, return_value=reconcile_ok):
            # Patch the import inside the function body
            with patch("autostream_appliances.reconcile_appliance_announcement",
                       return_value=reconcile_ok, create=True):
                send_advertisement_post_json(handler, state, json.dumps({"value": value}))
        code, data = _response(handler)
        return code, data, state, store

    def test_non_bool_value_returns_400(self, tmp_path):
        from autostream_webui_api import send_advertisement_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        send_advertisement_post_json(handler, state, json.dumps({"value": "yes"}))
        code, data = _response(handler)
        assert code == 400
        assert data["ok"] is False
        store.close(save=False)

    def test_int_value_returns_400(self, tmp_path):
        from autostream_webui_api import send_advertisement_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        send_advertisement_post_json(handler, state, json.dumps({"value": 1}))
        code, data = _response(handler)
        assert code == 400
        store.close(save=False)

    def test_invalid_json_returns_400(self, tmp_path):
        from autostream_webui_api import send_advertisement_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        send_advertisement_post_json(handler, state, "bad json")
        code, data = _response(handler)
        assert code == 400
        store.close(save=False)

    def test_success_persists_to_store(self, tmp_path):
        from autostream_webui_api import send_advertisement_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()

        import sys
        mock_mod = MagicMock()
        mock_mod.reconcile_appliance_announcement = MagicMock(return_value=True)
        with patch.dict(sys.modules, {"autostream_appliances": mock_mod}), \
             patch("autostream_webui_api.get_app_version", return_value="1.0.0", create=True):
            # The function imports reconcile inside; patch where it's imported
            import autostream_webui_common as _common
            with patch.object(_common, "get_app_version", return_value="1.0.0", create=True):
                send_advertisement_post_json(handler, state, json.dumps({"value": True}))

        code, data = _response(handler)
        assert code == 200
        assert data["ok"] is True
        snap = store.snapshot()
        assert snap.webui.advertise_appliance is True
        store.close(save=False)

    def test_failed_admin_call_does_not_commit(self, tmp_path):
        from autostream_webui_api import send_advertisement_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()

        import sys
        mock_mod = MagicMock()
        mock_mod.reconcile_appliance_announcement = MagicMock(return_value=False)
        with patch.dict(sys.modules, {"autostream_appliances": mock_mod}), \
             patch("autostream_webui_api.get_app_version", return_value="1.0.0", create=True):
            import autostream_webui_common as _common
            with patch.object(_common, "get_app_version", return_value="1.0.0", create=True):
                send_advertisement_post_json(handler, state, json.dumps({"value": True}))

        code, data = _response(handler)
        assert code == 200
        assert data["ok"] is False
        # Store must NOT have been updated since admin call failed
        snap = store.snapshot()
        assert snap.webui.advertise_appliance is False
        store.close(save=False)

    def test_store_commit_failure_returns_warning(self, tmp_path):
        """When admin call succeeds but store update fails, return ok with a warning."""
        from autostream_webui_api import send_advertisement_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        store.update = MagicMock(side_effect=RuntimeError("store full"))
        import sys
        mock_mod = MagicMock()
        mock_mod.reconcile_appliance_announcement = MagicMock(return_value=True)
        with patch.dict(sys.modules, {"autostream_appliances": mock_mod}):
            import autostream_webui_common as _common
            with patch.object(_common, "get_app_version", return_value="1.0.0", create=True):
                send_advertisement_post_json(handler, state, json.dumps({"value": True}))
        code, data = _response(handler)
        assert code == 200
        assert data["ok"] is True
        assert "warning" in data
        assert "revert" in data["warning"].lower()
        store.close(save=False)


# ---------------------------------------------------------------------------
# /api/settings/auto-update
# ---------------------------------------------------------------------------

class TestAutoUpdateEndpoint:
    def _admin_result(self, returncode: int = 0, stderr: str = "") -> MagicMock:
        r = MagicMock()
        r.returncode = returncode
        r.stderr = stderr
        return r

    def test_non_bool_value_returns_400(self, tmp_path):
        from autostream_webui_api import send_auto_update_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        send_auto_update_post_json(handler, state, json.dumps({"value": 1}))
        code, data = _response(handler)
        assert code == 400
        assert data["ok"] is False
        store.close(save=False)

    def test_invalid_json_returns_400(self, tmp_path):
        from autostream_webui_api import send_auto_update_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        send_auto_update_post_json(handler, state, "bad json")
        code, data = _response(handler)
        assert code == 400
        store.close(save=False)

    def test_enable_calls_toggle_update_timer_enable(self, tmp_path):
        from autostream_webui_api import send_auto_update_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        with patch("autostream_webui_api.run_admin_cmd", return_value=self._admin_result()) as mock_cmd:
            send_auto_update_post_json(handler, state, json.dumps({"value": True}))
        mock_cmd.assert_called_once_with(["toggle-update-timer", "enable"], timeout=5.0)
        store.close(save=False)

    def test_disable_calls_toggle_update_timer_disable(self, tmp_path):
        from autostream_webui_api import send_auto_update_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        with patch("autostream_webui_api.run_admin_cmd", return_value=self._admin_result()) as mock_cmd:
            send_auto_update_post_json(handler, state, json.dumps({"value": False}))
        mock_cmd.assert_called_once_with(["toggle-update-timer", "disable"], timeout=5.0)
        store.close(save=False)

    def test_success_persists_to_store(self, tmp_path):
        from autostream_webui_api import send_auto_update_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        with patch("autostream_webui_api.run_admin_cmd", return_value=self._admin_result()):
            send_auto_update_post_json(handler, state, json.dumps({"value": True}))
        code, data = _response(handler)
        assert code == 200
        assert data["ok"] is True
        snap = store.snapshot()
        assert snap.updates.auto_update is True
        store.close(save=False)

    def test_failed_admin_call_does_not_commit(self, tmp_path):
        from autostream_webui_api import send_auto_update_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        with patch("autostream_webui_api.run_admin_cmd", return_value=self._admin_result(returncode=1, stderr="fail")):
            send_auto_update_post_json(handler, state, json.dumps({"value": True}))
        code, data = _response(handler)
        assert code == 200
        assert data["ok"] is False
        snap = store.snapshot()
        assert snap.updates.auto_update is False  # original value preserved
        store.close(save=False)

    def test_failed_admin_returns_useful_error(self, tmp_path):
        from autostream_webui_api import send_auto_update_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        with patch("autostream_webui_api.run_admin_cmd", return_value=self._admin_result(returncode=1)):
            send_auto_update_post_json(handler, state, json.dumps({"value": True}))
        _, data = _response(handler)
        assert "error" in data
        assert data["error"]
        store.close(save=False)

    def test_store_commit_failure_returns_warning(self, tmp_path):
        """When the admin command succeeds but the store update fails, return ok with warning."""
        from autostream_webui_api import send_auto_update_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        store.update = MagicMock(side_effect=RuntimeError("store full"))
        with patch("autostream_webui_api.run_admin_cmd", return_value=self._admin_result()):
            send_auto_update_post_json(handler, state, json.dumps({"value": True}))
        code, data = _response(handler)
        assert code == 200
        assert data["ok"] is True
        assert "warning" in data
        assert "revert" in data["warning"].lower()


# ---------------------------------------------------------------------------
# /api/settings/mdns-grace-period
# ---------------------------------------------------------------------------

class TestMdnsGracePeriodEndpoint:
    def test_success_persists_and_applies_browser_grace(self, tmp_path):
        from autostream_webui_api import send_settings_mdns_grace_period_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        with patch("autostream_webui_api.save_setting") as m_save, \
             patch("autostream_appliances.set_grace_period") as m_browser, \
             patch("autostream_webui_api._config_snapshot") as m_snap:
            m_snap.return_value = MagicMock(owntone=MagicMock(base_url="http://localhost:3689"))
            m_save.return_value = MagicMock(ok=True, unsupported=False, restart_required=False, message="")
            send_settings_mdns_grace_period_json(handler, state, json.dumps({"value": 5}))

        code, data = _response(handler)
        assert code == 200
        assert data["ok"] is True
        assert data["seconds"] == 300
        m_browser.assert_called_once_with(300)
        assert store.raw_snapshot()["general"]["mdns_grace_period_seconds"] == 300
        m_save.assert_called_once()
        store.close(save=False)

    def test_owntone_forward_failure_returns_warning_without_reverting(self, tmp_path):
        from autostream_webui_api import send_settings_mdns_grace_period_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        with patch("autostream_webui_api.save_setting") as m_save, \
             patch("autostream_appliances.set_grace_period") as m_browser, \
             patch("autostream_webui_api._config_snapshot") as m_snap:
            m_snap.return_value = MagicMock(owntone=MagicMock(base_url="http://localhost:3689"))
            m_save.return_value = MagicMock(
                ok=False,
                unsupported=False,
                restart_required=False,
                message="backend offline",
            )
            send_settings_mdns_grace_period_json(handler, state, json.dumps({"value": 4}))

        code, data = _response(handler)
        assert code == 200
        assert data["ok"] is True
        assert "warning" in data
        assert "backend offline" in data["warning"]
        m_browser.assert_called_once_with(240)
        assert store.raw_snapshot()["general"]["mdns_grace_period_seconds"] == 240
        store.close(save=False)

    def test_invalid_json_returns_400(self, tmp_path):
        from autostream_webui_api import send_settings_mdns_grace_period_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        send_settings_mdns_grace_period_json(handler, state, "bad json")
        code, data = _response(handler)
        assert code == 400
        assert data["ok"] is False
        store.close(save=False)


# ---------------------------------------------------------------------------
# /api/settings/save
# ---------------------------------------------------------------------------

class TestSaveNowEndpoint:
    def test_save_now_called_on_store(self, tmp_path):
        from autostream_webui_api import send_save_now_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        with patch.object(store, "save_now") as mock_save:
            send_save_now_json(handler, state)
        mock_save.assert_called_once()
        _, data = _response(handler)
        assert data["ok"] is True
        store.close(save=False)

    def test_save_failure_returns_error(self, tmp_path):
        from autostream_webui_api import send_save_now_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        # save_now returns False on failure; it never raises
        with patch.object(store, "save_now", return_value=False):
            send_save_now_json(handler, state)
        code, data = _response(handler)
        assert code == 200
        assert data["ok"] is False
        assert "error" in data
        store.close(save=False)

    def test_no_store_returns_error(self, tmp_path):
        from autostream_webui_api import send_save_now_json
        from autostream_webui_state import WebUIState
        cfg = _minimal_cfg(tmp_path)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"))  # no settings store
        handler = _make_handler()
        send_save_now_json(handler, state)
        code, data = _response(handler)
        assert code == 200
        assert data["ok"] is False


# ---------------------------------------------------------------------------
# Factory reset discards dirty store
# ---------------------------------------------------------------------------

class TestFactoryResetDiscardsDirty:
    def test_factory_reset_closes_store_without_saving(self, tmp_path):
        from autostream_webui_post_handlers import handle_factory_reset_post
        state, store = _make_state(tmp_path)
        auth = MagicMock()
        handler = _make_handler()
        # Make a dirty change
        store.update(lambda raw: raw.setdefault("general", {}).update({"log_level": "debug"}))

        with patch("autostream_webui_post_handlers.factory_reset_system"), \
             patch.object(store, "close") as mock_close:
            handle_factory_reset_post(handler, state, auth)

        mock_close.assert_called_once_with(save=False)
        store.close(save=False)

    def test_factory_reset_proceeds_after_store_close(self, tmp_path):
        from autostream_webui_post_handlers import handle_factory_reset_post
        state, store = _make_state(tmp_path)
        auth = MagicMock()
        handler = _make_handler()

        with patch("autostream_webui_post_handlers.factory_reset_system") as mock_reset:
            handle_factory_reset_post(handler, state, auth)

        mock_reset.assert_called_once()
        code, data = _response(handler)
        assert data["ok"] is True
        store.close(save=False)


# ---------------------------------------------------------------------------
# AUTOSAVE_JS exports settingsTransact
# ---------------------------------------------------------------------------

class TestAutosaveJsTransact:
    def test_settings_transact_exported(self):
        from autostream_webui_assets import AUTOSAVE_JS
        assert "settingsTransact" in AUTOSAVE_JS

    def test_settings_transact_uses_window(self):
        from autostream_webui_assets import AUTOSAVE_JS
        assert "window.settingsTransact" in AUTOSAVE_JS

    def test_settings_transact_handles_redirect_url(self):
        from autostream_webui_assets import AUTOSAVE_JS
        assert "redirect_url" in AUTOSAVE_JS

    def test_settings_transact_sets_applying_status(self):
        from autostream_webui_assets import AUTOSAVE_JS
        assert "Applying" in AUTOSAVE_JS

    def test_settings_transact_has_on_success_callback(self):
        from autostream_webui_assets import AUTOSAVE_JS
        assert "onSuccess" in AUTOSAVE_JS

    def test_settings_transact_has_on_error_callback(self):
        from autostream_webui_assets import AUTOSAVE_JS
        assert "onError" in AUTOSAVE_JS


# ---------------------------------------------------------------------------
# Setup page wires hostname modal / advertise / auto-update controls
# ---------------------------------------------------------------------------

class TestSetupPageTransactionWiring:
    @pytest.fixture
    def html(self, tmp_path: Path) -> str:
        from autostream_settings import SettingsStore
        from autostream_webui_state import WebUIState
        from autostream_players import ListOutputsResult
        from _setup_card_test_helpers import render_full_setup_with_cards

        cfg = _minimal_cfg(tmp_path)
        store = SettingsStore(str(cfg), _save_interval_seconds=9999)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)

        handler = MagicMock()
        handler.wfile = io.BytesIO()
        auth = MagicMock()
        auth.ensure_session.return_value = "test-csrf"
        auth.get_csrf_token.return_value = "test-csrf"
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
        ):
            with patch.object(state, "get_monitor_devices", return_value=[]):
                html = render_full_setup_with_cards(handler, state, auth, flash_msg="")

        store.close(save=False)
        return html

    def test_hostname_modal_has_transaction_call(self, html):
        assert "settingsTransact('/api/settings/hostname'" in html

    def test_hostname_change_button_and_modal_present(self, html):
        assert 'id="btnChangeHostname"' in html
        assert 'id="hostnameModal"' in html
        assert 'id="hostnameModalInput"' in html
        assert 'value="autostream"' in html

    def test_hostname_not_wired_to_blur_autosave(self, html):
        assert 'name="system_hostname"' not in html
        assert "settingsTransact('/api/settings/hostname'" in html
        assert "onblur=\"refreshSystemCardSub(); if(liveEnabled" not in html

    def test_system_panel_card_order(self, html):
        system = html.index('>System</p>')
        network = html.index('id="networkCardTitle"')
        updates = html.index('>Updates</p>')
        assert system < network < updates

    def test_advertise_checkbox_has_transaction_call(self, html):
        assert "settingsTransact('/api/settings/advertisement'" in html

    def test_auto_update_checkbox_has_transaction_call(self, html):
        assert "settingsTransact('/api/settings/auto-update'" in html

    def test_request_reboot_saves_first(self, html):
        assert "/api/settings/save" in html
        assert "requestReboot" in html

    def test_install_button_saves_before_update(self, html):
        assert "Saving settings" in html

    def test_settings_transact_available(self, html):
        assert "settingsTransact" in html
