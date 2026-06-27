"""WP2 — Settings ownership and read migration tests.

Verifies:
- WebUIState stores a settings attribute
- start_webui_background accepts and stores a SettingsStore; doesn't create a second one
- _config_snapshot(state) reads from store when available
- _config_snapshot(state) falls back to disk when state.settings is None
- run_autostream calls settings.save_now() before exiting (final flush)
- All page-renderer and API read paths use the store (smoke test via _config_snapshot)
"""
from __future__ import annotations

import json
import sys
import threading
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
        "general": {"log_level": "info", "log_file": "/tmp/autostream.log"},
        "owntone": {"base_url": "http://localhost:3689"},
        "webui": {"dark_mode": False, "advertise_appliance": True},
    })
    return cfg


# ---------------------------------------------------------------------------
# WebUIState: settings attribute
# ---------------------------------------------------------------------------

class TestWebUIStateSettingsAttribute:
    def test_settings_defaults_to_none(self, tmp_path):
        from autostream_webui_state import WebUIState
        state = WebUIState(str(tmp_path / "cfg.json"), str(tmp_path / "state.json"))
        assert state.settings is None

    def test_settings_stored_from_constructor(self, tmp_path):
        from autostream_webui_state import WebUIState
        from autostream_settings import SettingsStore
        cfg = _minimal_cfg(tmp_path)
        store = SettingsStore(str(cfg), _save_interval_seconds=9999)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)
        assert state.settings is store
        store.close(save=False)

    def test_settings_attribute_mutable(self, tmp_path):
        from autostream_webui_state import WebUIState
        from autostream_settings import SettingsStore
        cfg = _minimal_cfg(tmp_path)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"))
        assert state.settings is None
        store = SettingsStore(str(cfg), _save_interval_seconds=9999)
        state.settings = store
        assert state.settings is store
        store.close(save=False)


# ---------------------------------------------------------------------------
# _config_snapshot: store path and fallback
# ---------------------------------------------------------------------------

class TestConfigSnapshot:
    def test_reads_from_store_when_available(self, tmp_path):
        from autostream_webui_common import _config_snapshot
        from autostream_settings import SettingsStore
        from autostream_webui_state import WebUIState

        cfg = _minimal_cfg(tmp_path)
        store = SettingsStore(str(cfg), _save_interval_seconds=9999)
        # Mutate in-memory so it differs from disk
        store.update(lambda d: d["general"].__setitem__("log_level", "debug"))
        state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)

        result = _config_snapshot(state)
        assert result.general.log_level == "debug"
        store.close(save=False)

    def test_falls_back_to_disk_when_no_store(self, tmp_path):
        from autostream_webui_common import _config_snapshot
        from autostream_webui_state import WebUIState

        cfg = _minimal_cfg(tmp_path)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"))
        assert state.settings is None

        result = _config_snapshot(state)
        assert result.general.log_level == "info"  # what's on disk

    def test_store_snapshot_is_independent(self, tmp_path):
        """Each _config_snapshot call returns a fresh object."""
        from autostream_webui_common import _config_snapshot
        from autostream_settings import SettingsStore
        from autostream_webui_state import WebUIState

        cfg = _minimal_cfg(tmp_path)
        store = SettingsStore(str(cfg), _save_interval_seconds=9999)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)

        a = _config_snapshot(state)
        b = _config_snapshot(state)
        assert a is not b
        store.close(save=False)


# ---------------------------------------------------------------------------
# start_webui_background: store injection and no duplicate creation
# ---------------------------------------------------------------------------

class TestStartWebuiBackground:
    def test_uses_provided_store(self, tmp_path):
        """When settings= is supplied, STATE.settings is that exact object."""
        cfg = _minimal_cfg(tmp_path)

        from autostream_settings import SettingsStore
        store = SettingsStore(str(cfg), _save_interval_seconds=9999)

        httpd_mock = MagicMock()
        httpd_mock.serve_forever = MagicMock(side_effect=KeyboardInterrupt)

        with (
            patch("autostream_webui.AuthManager"),
            patch("autostream_webui.stop_flag") as sf,
            patch("autostream_dials.start_dial_scanner"),
            patch("autostream_appliances.reconcile_appliance_announcement"),
            patch("autostream_appliances.start_appliance_scanner"),
            patch("autostream_webui.ThreadingHTTPServer", return_value=httpd_mock),
            patch("autostream_webui._scan_monitor_devices_loop"),
        ):
            sf.is_set.return_value = True  # stop reconcile loop immediately

            from autostream_webui import start_webui_background, STATE as _initial
            import autostream_webui as _wm

            _wm.STATE = None
            t = start_webui_background(str(cfg), settings=store)
            # Give the thread a brief moment to set globals
            t.join(timeout=2.0)

            assert _wm.STATE is not None
            assert _wm.STATE.settings is store

        store.close(save=False)

    def test_creates_store_when_none_provided(self, tmp_path):
        """When settings=None, start_webui_background creates its own store."""
        from autostream_settings import SettingsStore
        from autostream_webui import start_webui_background
        import autostream_webui as _wm

        cfg = _minimal_cfg(tmp_path)
        httpd_mock = MagicMock()
        httpd_mock.serve_forever = MagicMock(side_effect=KeyboardInterrupt)

        with (
            patch("autostream_webui.AuthManager"),
            patch("autostream_webui.stop_flag") as sf,
            patch("autostream_dials.start_dial_scanner"),
            patch("autostream_appliances.reconcile_appliance_announcement"),
            patch("autostream_appliances.start_appliance_scanner"),
            patch("autostream_webui.ThreadingHTTPServer", return_value=httpd_mock),
            patch("autostream_webui._scan_monitor_devices_loop"),
        ):
            sf.is_set.return_value = True
            _wm.STATE = None
            t = start_webui_background(str(cfg))
            t.join(timeout=2.0)

            assert _wm.STATE is not None
            assert _wm.STATE.settings is not None
            assert isinstance(_wm.STATE.settings, SettingsStore)
            _wm.STATE.settings.close(save=False)

    def test_startup_pushes_mdns_grace_period(self, tmp_path):
        from autostream_settings import SettingsStore
        from autostream_webui import start_webui_background
        import autostream_webui as _wm

        cfg = _minimal_cfg(tmp_path)
        raw = json.loads(cfg.read_text(encoding="utf-8"))
        raw.setdefault("general", {})["mdns_grace_period_seconds"] = 240
        cfg.write_text(json.dumps(raw), encoding="utf-8")
        store = SettingsStore(str(cfg), _save_interval_seconds=9999)

        httpd_mock = MagicMock()
        httpd_mock.serve_forever = MagicMock(side_effect=KeyboardInterrupt)

        with (
            patch("autostream_webui.AuthManager"),
            patch("autostream_webui.stop_flag") as sf,
            patch("autostream_dials.start_dial_scanner"),
            patch("autostream_appliances.reconcile_appliance_announcement"),
            patch("autostream_appliances.start_appliance_scanner"),
            patch("autostream_webui.ThreadingHTTPServer", return_value=httpd_mock),
            patch("autostream_webui._scan_monitor_devices_loop"),
            patch("autostream_webui_api.apply_mdns_grace_period") as m_apply,
        ):
            sf.is_set.return_value = True
            _wm.STATE = None
            t = start_webui_background(str(cfg), settings=store)
            t.join(timeout=2.0)

        m_apply.assert_called_once()
        assert m_apply.call_args[0][1] == 240
        store.close(save=False)


# ---------------------------------------------------------------------------
# run_autostream: final save_now() on exit
# ---------------------------------------------------------------------------

class TestRunAutostreamFinalSave:
    def test_calls_save_now_on_clean_exit(self, tmp_path):
        """run_autostream calls settings.save_now() before returning."""
        cfg = _minimal_cfg(tmp_path)

        from autostream_settings import SettingsStore
        save_calls = []
        original_save_now = SettingsStore.save_now

        class TrackingSave(SettingsStore):
            def save_now(self):
                save_calls.append(True)
                return True

        store = TrackingSave(str(cfg), _save_interval_seconds=9999)

        import autostream_webui
        _call_count = [0]

        def _is_set():
            _call_count[0] += 1
            # First call: outer while enters. Everything after: signal stop.
            return _call_count[0] > 1

        with (
            patch("autostream_core.stop_flag") as sf,
            patch("autostream_core.unconfigured", return_value=False),
            patch("autostream_core.MonitorClient") as mc,
            patch("autostream_core._install_signal_handlers"),
            patch("autostream_core.get_install_state", return_value={}),
            patch("autostream_core._ensure_playback_tracker"),
            patch("autostream_core.setup_logging"),
        ):
            sf.is_set.side_effect = _is_set
            sf.wait.return_value = True  # for any wait() calls
            mock_client = MagicMock()
            mc.return_value = mock_client

            from autostream_core import run_autostream
            run_autostream(str(cfg), settings=store)

        assert len(save_calls) >= 1, "save_now() should be called at coordinator exit"
        store.close(save=False)

    def test_own_store_closed_on_exit(self, tmp_path):
        """When run_autostream creates its own store it closes it on exit."""
        from autostream_settings import SettingsStore as _OrigStore

        cfg = _minimal_cfg(tmp_path)
        closed = []

        class CloseSpy(_OrigStore):
            def close(self, *, save=True):
                closed.append(save)
                super().close(save=save)

        _call_count = [0]

        def _is_set():
            _call_count[0] += 1
            return _call_count[0] > 1

        with (
            patch("autostream_core.stop_flag") as sf,
            patch("autostream_core.unconfigured", return_value=False),
            patch("autostream_core.MonitorClient") as mc,
            patch("autostream_core._install_signal_handlers"),
            patch("autostream_core.get_install_state", return_value={}),
            patch("autostream_core._ensure_playback_tracker"),
            patch("autostream_core.setup_logging"),
            patch("autostream_settings.SettingsStore", CloseSpy),
        ):
            sf.is_set.side_effect = _is_set
            sf.wait.return_value = True
            mock_client = MagicMock()
            mc.return_value = mock_client

            from autostream_core import run_autostream
            # settings=None so run_autostream creates its own via CloseSpy
            run_autostream(str(cfg))

        assert closed, "close() should be called when run_autostream owns the store"
