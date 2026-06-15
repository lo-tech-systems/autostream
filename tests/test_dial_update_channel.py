"""Tests for update channel feature — dial-specific components.

Covers the requirements from docs/working/dev-channel-implementation-plan.md sections 8 and 11.
"""
from __future__ import annotations

import copy
import importlib.util
import io
import json
import os
import sys
import urllib.error
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_SUPERVISOR = str(REPO_ROOT / "supervisor")
if _SUPERVISOR not in sys.path:
    sys.path.insert(0, _SUPERVISOR)
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import autostream_update_support as _asu
from autostream_update_support import API_LATEST, API_RELEASES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_script(name: str) -> ModuleType:
    from importlib.machinery import SourceFileLoader
    path   = str(REPO_ROOT / "supervisor" / name)
    loader = SourceFileLoader(name, path)
    spec   = importlib.util.spec_from_loader(name, loader)
    mod    = importlib.util.module_from_spec(spec)
    if sys.platform == "win32":
        with patch.dict("sys.modules", {"fcntl": MagicMock()}):
            loader.exec_module(mod)
    else:
        loader.exec_module(mod)
    return mod


def _make_dial_tarball(tmp_path: Path, tag: str = "v1.3.0") -> Path:
    """Build a minimal real dial release tarball for staging tests."""
    import tarfile as tf_mod
    src = tmp_path / "build" / f"repo-{tag}"
    src.mkdir(parents=True, exist_ok=True)
    installer = src / "autostream_dial_install.sh"
    installer.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(str(installer), 0o755)
    tar_path = tmp_path / "fake-dial.tgz"
    with tf_mod.open(tar_path, "w:gz") as tf:
        tf.add(str(src), arcname=f"repo-{tag}")
    return tar_path


def _mock_response(payload: bytes, status: int = 200) -> MagicMock:
    r = MagicMock()
    r.__enter__ = lambda s: s
    r.__exit__ = MagicMock(return_value=False)
    r.status = status
    r.read.return_value = payload
    return r


def _release_payload(tag: str = "v1.2.3") -> bytes:
    return json.dumps({
        "tag_name":    tag,
        "tarball_url": "https://example.com/release.tgz",
        "html_url":    "https://example.com/releases/" + tag,
        "body":        "Release notes",
    }).encode()


# ---------------------------------------------------------------------------
# Section 8.1 — DialConfig model
# ---------------------------------------------------------------------------

class TestDialConfigModel:
    def test_default_channel_is_stable(self):
        from dial_config import DialConfig
        cfg = DialConfig()
        assert cfg.update_channel == "stable"

    def test_load_config_stable_from_settings(self, tmp_path):
        from dial_config import DialConfig, SETTINGS_PATH, HW_CONFIG_PATH, load_config
        # Write minimal HW config
        hw = tmp_path / "autostream-dial.json"
        hw.write_text(json.dumps({"uuid": "test-uuid"}), encoding="utf-8")
        # Write settings with stable channel
        settings = tmp_path / "dial-settings.json"
        settings.write_text(
            json.dumps({"step_percent": 2, "name": "", "pin": "", "auto_update": False, "update_channel": "stable"}),
            encoding="utf-8",
        )
        import dial_config as dc
        orig_hw, orig_settings = dc.HW_CONFIG_PATH, dc.SETTINGS_PATH
        dc.HW_CONFIG_PATH = hw
        dc.SETTINGS_PATH = settings
        try:
            cfg = dc.load_config()
        finally:
            dc.HW_CONFIG_PATH = orig_hw
            dc.SETTINGS_PATH = orig_settings
        assert cfg.update_channel == "stable"

    def test_load_config_dev_from_settings(self, tmp_path):
        import dial_config as dc
        hw = tmp_path / "autostream-dial.json"
        hw.write_text(json.dumps({"uuid": "test-uuid"}), encoding="utf-8")
        settings = tmp_path / "dial-settings.json"
        settings.write_text(
            json.dumps({"step_percent": 2, "name": "", "pin": "", "auto_update": False, "update_channel": "dev"}),
            encoding="utf-8",
        )
        orig_hw, orig_settings = dc.HW_CONFIG_PATH, dc.SETTINGS_PATH
        dc.HW_CONFIG_PATH = hw
        dc.SETTINGS_PATH = settings
        try:
            cfg = dc.load_config()
        finally:
            dc.HW_CONFIG_PATH = orig_hw
            dc.SETTINGS_PATH = orig_settings
        assert cfg.update_channel == "dev"

    def test_load_config_invalid_channel_defaults_to_stable(self, tmp_path):
        import dial_config as dc
        hw = tmp_path / "autostream-dial.json"
        hw.write_text(json.dumps({"uuid": "test-uuid"}), encoding="utf-8")
        settings = tmp_path / "dial-settings.json"
        settings.write_text(
            json.dumps({"update_channel": "nightly"}),
            encoding="utf-8",
        )
        orig_hw, orig_settings = dc.HW_CONFIG_PATH, dc.SETTINGS_PATH
        dc.HW_CONFIG_PATH = hw
        dc.SETTINGS_PATH = settings
        try:
            cfg = dc.load_config()
        finally:
            dc.HW_CONFIG_PATH = orig_hw
            dc.SETTINGS_PATH = orig_settings
        assert cfg.update_channel == "stable"

    def test_load_config_missing_channel_defaults_to_stable(self, tmp_path):
        import dial_config as dc
        hw = tmp_path / "autostream-dial.json"
        hw.write_text(json.dumps({"uuid": "test-uuid"}), encoding="utf-8")
        settings = tmp_path / "dial-settings.json"
        settings.write_text(
            json.dumps({"step_percent": 2, "name": "", "pin": "", "auto_update": False}),
            encoding="utf-8",
        )
        orig_hw, orig_settings = dc.HW_CONFIG_PATH, dc.SETTINGS_PATH
        dc.HW_CONFIG_PATH = hw
        dc.SETTINGS_PATH = settings
        try:
            cfg = dc.load_config()
        finally:
            dc.HW_CONFIG_PATH = orig_hw
            dc.SETTINGS_PATH = orig_settings
        assert cfg.update_channel == "stable"

    def test_save_config_round_trips_stable(self, tmp_path):
        import dial_config as dc
        from dial_config import DialConfig
        settings = tmp_path / "dial-settings.json"
        orig_settings = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = settings
        try:
            cfg = DialConfig(uuid="x", update_channel="stable")
            dc.save_config(cfg)
            data = json.loads(settings.read_text())
        finally:
            dc.SETTINGS_PATH = orig_settings
        assert data["update_channel"] == "stable"

    def test_save_config_round_trips_dev(self, tmp_path):
        import dial_config as dc
        from dial_config import DialConfig
        settings = tmp_path / "dial-settings.json"
        orig_settings = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = settings
        try:
            cfg = DialConfig(uuid="x", update_channel="dev")
            dc.save_config(cfg)
            data = json.loads(settings.read_text())
        finally:
            dc.SETTINGS_PATH = orig_settings
        assert data["update_channel"] == "dev"


# ---------------------------------------------------------------------------
# Section 8.2 — Dial updater channel reading and cmd_check
# ---------------------------------------------------------------------------

class TestDialUpdaterChannelReading:
    def _load(self, tmp_path, channel: str = "stable") -> ModuleType:
        mod = _load_script("autostream_dial_updater")
        mod.STATE_DIR = tmp_path
        mod.APMODE_FLAG = tmp_path / "_apmode_absent"
        mod.LOG_PATH = tmp_path / "dial-update.log"
        settings = tmp_path / "dial-settings.json"
        settings.write_text(
            json.dumps({"auto_update": False, "update_channel": channel}),
            encoding="utf-8",
        )
        return mod

    def test_missing_settings_defaults_to_stable(self, tmp_path):
        mod = _load_script("autostream_dial_updater")
        mod.STATE_DIR = tmp_path  # no dial-settings.json
        assert mod._read_dial_channel() == "stable"

    def test_stable_channel_read(self, tmp_path):
        mod = self._load(tmp_path, channel="stable")
        assert mod._read_dial_channel() == "stable"

    def test_dev_channel_read(self, tmp_path):
        mod = self._load(tmp_path, channel="dev")
        assert mod._read_dial_channel() == "dev"

    def test_invalid_channel_defaults_to_stable(self, tmp_path):
        mod = _load_script("autostream_dial_updater")
        mod.STATE_DIR = tmp_path
        settings = tmp_path / "dial-settings.json"
        settings.write_text(json.dumps({"update_channel": "nightly"}), encoding="utf-8")
        assert mod._read_dial_channel() == "stable"


class TestDialUpdaterCmdCheck:
    def _load(self, tmp_path, channel: str = "stable") -> ModuleType:
        mod = _load_script("autostream_dial_updater")
        mod.STATE_DIR = tmp_path
        mod.APMODE_FLAG = tmp_path / "_apmode_absent"
        mod.LOG_PATH = tmp_path / "dial-update.log"
        settings = tmp_path / "dial-settings.json"
        settings.write_text(
            json.dumps({"auto_update": False, "update_channel": channel}),
            encoding="utf-8",
        )
        return mod

    def test_check_includes_channel_stable(self, tmp_path):
        mod = self._load(tmp_path, channel="stable")
        payload = _release_payload("v1.2.3")
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = mod.cmd_check()
        assert result.get("ok") is True
        assert result.get("channel") == "stable"

    def test_check_includes_channel_dev(self, tmp_path):
        mod = self._load(tmp_path, channel="dev")
        payload = json.dumps([json.loads(_release_payload("v1.3.0-beta.1"))]).encode()
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = mod.cmd_check()
        assert result.get("ok") is True
        assert result.get("channel") == "dev"

    def test_check_network_error_returns_false(self, tmp_path):
        mod = self._load(tmp_path, channel="stable")
        with patch("urllib.request.urlopen", side_effect=OSError("timeout")):
            result = mod.cmd_check()
        assert result.get("ok") is False

    def test_check_dev_uses_releases_list_endpoint(self, tmp_path):
        mod = self._load(tmp_path, channel="dev")
        payload = json.dumps([json.loads(_release_payload("v1.3.0-beta.1"))]).encode()
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as m:
            mod.cmd_check()
        url_called = m.call_args[0][0].full_url
        assert url_called == API_RELEASES


class TestDialUpdaterCmdApply:
    def _load(self, tmp_path, channel: str = "stable") -> ModuleType:
        mod = _load_script("autostream_dial_updater")
        mod.STATE_DIR = tmp_path
        mod.APMODE_FLAG = tmp_path / "_apmode_absent"
        mod.LOG_PATH = tmp_path / "dial-update.log"
        mod.LOCK_PATH = tmp_path / "dial-update.lock"
        mod.STAGING_DIR = tmp_path / "staging"
        mod.UPDATING_FLAG = tmp_path / "autostream-dial-updating"
        settings = tmp_path / "dial-settings.json"
        settings.write_text(
            json.dumps({"auto_update": False, "update_channel": channel}),
            encoding="utf-8",
        )
        return mod

    def test_apply_already_at_latest_noop(self, tmp_path):
        mod = self._load(tmp_path, channel="stable")
        state = tmp_path / "install-state.env"
        state.write_text("AUTOSTREAM_RELEASE_TAG=v1.2.3\n", encoding="utf-8")
        payload = _release_payload("v1.2.3")
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            with patch.object(mod, "_dial_update_unit_active", return_value=False):
                result = mod.cmd_apply()
        assert result.get("ok") is True

    def test_apply_auto_update_false_returns_noop(self, tmp_path):
        mod = self._load(tmp_path, channel="stable")
        result = mod.cmd_apply(auto=True)
        assert result == {"ok": True}

    def test_apply_auto_update_true_proceeds_past_gate(self, tmp_path):
        mod = self._load(tmp_path, channel="stable")
        settings = tmp_path / "dial-settings.json"
        settings.write_text(json.dumps({"auto_update": True, "update_channel": "stable"}), encoding="utf-8")
        payload = _release_payload("v1.2.3")
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            with patch.object(mod, "_dial_update_unit_active", return_value=False):
                with patch.object(mod, "_find_systemd_run", return_value=None):
                    result = mod.cmd_apply(auto=True)
        # Should reach systemd_run check and fail (not auto_update gate)
        assert result.get("ok") is False
        assert "systemd-run" in result.get("error", "")

    def test_apply_apmode_refused(self, tmp_path):
        mod = self._load(tmp_path, channel="stable")
        apmode = tmp_path / "dial-apmode"
        apmode.touch()
        mod.APMODE_FLAG = apmode
        result = mod.cmd_apply()
        assert result.get("ok") is False
        assert "AP mode" in result.get("error", "")

    def test_apply_network_error_returns_false(self, tmp_path):
        mod = self._load(tmp_path, channel="stable")
        with patch("urllib.request.urlopen", side_effect=OSError("timeout")):
            with patch.object(mod, "_dial_update_unit_active", return_value=False):
                result = mod.cmd_apply()
        assert result.get("ok") is False

    def test_apply_channel_dev_uses_releases_endpoint(self, tmp_path):
        mod = self._load(tmp_path, channel="dev")
        state = tmp_path / "install-state.env"
        state.write_text("AUTOSTREAM_RELEASE_TAG=v1.2.0\n", encoding="utf-8")
        payload = json.dumps([json.loads(_release_payload("v1.3.0-beta.1"))]).encode()
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as m:
            with patch.object(mod, "_dial_update_unit_active", return_value=False):
                with patch.object(mod, "_find_systemd_run", return_value=None):
                    mod.cmd_apply()
        url_called = m.call_args[0][0].full_url
        assert url_called == API_RELEASES

    def test_apply_auto_update_gate_independent_of_channel(self, tmp_path):
        """auto_update gate must work the same way regardless of channel."""
        mod = self._load(tmp_path, channel="dev")
        result = mod.cmd_apply(auto=True)
        assert result == {"ok": True}

    def test_apply_single_lookup_stages_correct_tarball(self, tmp_path):
        """apply() must call _resolve_dial_release exactly once, download the
        exact tarball it returned, write STAGING_DIR/release_tag, and pass
        AUTOSTREAM_RELEASE_TAG to systemd-run."""
        mod = self._load(tmp_path)
        (tmp_path / "install-state.env").write_text(
            "AUTOSTREAM_RELEASE_TAG=v1.2.0\n", encoding="utf-8"
        )
        settings = tmp_path / "dial-settings.json"
        settings.write_text(
            json.dumps({"auto_update": False, "update_channel": "stable"}),
            encoding="utf-8",
        )

        FAKE_TAG     = "v1.3.0"
        FAKE_TARBALL = "https://example.com/dial-v1.3.0.tgz"

        staging_dir = tmp_path / "staging"
        mod.STAGING_DIR = staging_dir

        # Build a real tarball so the staging extraction step succeeds without
        # patching tarfile.open (which is unreliable across import styles).
        real_tar = _make_dial_tarball(tmp_path / "tarball_build", tag=FAKE_TAG)

        resolved_calls = []
        downloaded_urls = []
        run_cmds = []

        def fake_resolve(channel):
            resolved_calls.append(channel)
            return (True, FAKE_TAG, FAKE_TARBALL, None, None)

        def fake_download(url, dst, ua, timeout=120):
            import shutil
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(real_tar), str(dst))
            downloaded_urls.append(url)

        def fake_run(cmd, timeout=60):
            run_cmds.append(list(cmd))
            return (0, "", "")

        mod.FLOCK_BIN = sys.executable

        with patch.object(mod, "_resolve_dial_release", side_effect=fake_resolve), \
             patch.object(mod, "_dial_update_unit_active", return_value=False), \
             patch.object(_asu, "_download_file", side_effect=fake_download), \
             patch.object(mod, "_find_systemd_run", return_value="/fake/systemd-run"), \
             patch.object(_asu, "_run", side_effect=fake_run):
            result = mod.cmd_apply()

        assert result.get("ok") is True, f"Expected ok:True, got {result}"
        assert len(resolved_calls) == 1, \
            f"Expected 1 resolver call, got {len(resolved_calls)}"
        assert downloaded_urls == [FAKE_TARBALL], \
            f"Expected tarball {FAKE_TARBALL}, got {downloaded_urls}"
        tag_file = staging_dir / "release_tag"
        assert tag_file.exists(), "release_tag was not created in STAGING_DIR"
        assert tag_file.read_text(encoding="utf-8") == FAKE_TAG + "\n"
        assert run_cmds, "systemd-run (_run) was never called"
        flat_cmd = " ".join(run_cmds[0])
        assert f"AUTOSTREAM_RELEASE_TAG={FAKE_TAG}" in flat_cmd, \
            f"AUTOSTREAM_RELEASE_TAG not in command: {flat_cmd}"


# ---------------------------------------------------------------------------
# Section 8.3 — Dial HTTP /configure API
# ---------------------------------------------------------------------------

class TestDialHttpConfigureApi:
    """Behavioral tests for the dial HTTP server's /configure endpoint."""

    def _call_configure(
        self,
        body: dict | None = None,
        cfg_overrides: dict | None = None,
        method: str = 'POST',
    ) -> dict:
        """Invoke do_GET() or _handle_configure() and return status/data/live_cfg/save_calls."""
        import dial_http_server as dhs
        from dial_config import DialConfig

        cfg = DialConfig(**(cfg_overrides or {}))

        class FakeDialServer:
            _cfg_lock = __import__('threading').Lock()
            _recovery_window = MagicMock(_active=False, _volume_confirmed=False)
            _make_handler = dhs.DialHTTPServer._make_handler

            def __init__(self, initial):
                self._cfg = initial

            def update_cfg(self, new_cfg):
                self._cfg = new_cfg

            def _on_announce(self, *a):
                pass

        fake_server = FakeDialServer(cfg)
        # Clear any per-IP rate-limit state left by previous test calls.
        dhs._pin_attempts.clear()
        Handler = fake_server._make_handler()

        body_bytes = json.dumps(body or {}).encode()
        handler = object.__new__(Handler)
        handler.path = '/configure'
        handler.rfile = io.BytesIO(body_bytes)
        handler.client_address = ('127.0.0.1', 1234)
        handler.headers = {'Content-Length': str(len(body_bytes))}

        result: dict = {}
        save_calls: list = []

        def _capture_json(status, data):
            result['status'] = status
            result['data'] = data

        def _capture_error(code, *a):
            result['status'] = code
            result['data'] = {'ok': False, 'error': f'http_{code}'}

        def _capture_429(wait_secs):
            result['status'] = 429
            result['data'] = {'ok': False, 'error': 'too_many_attempts'}

        handler._send_json = _capture_json
        handler.send_error = _capture_error
        handler._send_429 = _capture_429

        with patch('dial_config.save_config', side_effect=lambda c: save_calls.append(copy.copy(c))):
            if method == 'GET':
                handler.do_GET()
            else:
                handler._handle_configure()

        result['live_cfg'] = fake_server._cfg
        result['save_calls'] = save_calls
        return result

    # --- GET /configure ---

    def test_get_configure_returns_update_channel(self):
        """GET /configure response JSON includes the configured update_channel value."""
        for channel in ('stable', 'dev'):
            resp = self._call_configure(method='GET', cfg_overrides={'update_channel': channel})
            assert resp.get('status') == 200, f"Expected 200 for {channel!r}, got {resp}"
            assert resp['data'].get('update_channel') == channel, (
                f"Expected update_channel={channel!r} in GET response, got {resp['data']}"
            )

    # --- POST /configure — channel values ---

    def test_configure_post_accepts_dev_value(self):
        """POST update_channel='dev' succeeds, persists to save_config, and updates live cfg."""
        resp = self._call_configure({'update_channel': 'dev'})
        assert resp.get('status') == 200, f"Expected 200, got {resp}"
        assert resp['data'].get('ok') is True
        assert resp['save_calls'], "save_config was not called"
        assert resp['save_calls'][0].update_channel == 'dev'
        assert resp['live_cfg'].update_channel == 'dev'

    def test_configure_post_accepts_stable_value(self):
        """POST update_channel='stable' succeeds, persists to save_config, and updates live cfg."""
        resp = self._call_configure({'update_channel': 'stable'})
        assert resp.get('status') == 200, f"Expected 200, got {resp}"
        assert resp['data'].get('ok') is True
        assert resp['save_calls'], "save_config was not called"
        assert resp['save_calls'][0].update_channel == 'stable'
        assert resp['live_cfg'].update_channel == 'stable'

    def test_configure_post_rejects_non_string_channel(self):
        """Non-string update_channel must be rejected with 400 invalid_update_channel."""
        resp = self._call_configure({'update_channel': 42})
        assert resp.get('status') == 400, f"Expected 400, got {resp}"
        assert resp['data'].get('error') == 'invalid_update_channel'

    def test_configure_post_rejects_unknown_channel(self):
        """Unknown channel value must be rejected with 400 invalid_update_channel."""
        resp = self._call_configure({'update_channel': 'nightly'})
        assert resp.get('status') == 400, f"Expected 400, got {resp}"
        assert resp['data'].get('error') == 'invalid_update_channel'

    # --- PIN protection ---

    def test_configure_channel_change_no_pin_blocked(self):
        """channel change with no current_pin is rejected 403 when a PIN is set."""
        resp = self._call_configure(
            {'update_channel': 'dev'},
            cfg_overrides={'pin': '1234'},
        )
        assert resp.get('status') == 403, f"Expected 403, got {resp}"
        assert resp['data'].get('error') == 'wrong_pin'
        assert not resp['save_calls'], "save_config must not be called on auth failure"

    def test_configure_channel_change_wrong_pin_blocked(self):
        """channel change with wrong current_pin is rejected 403 when a PIN is set."""
        resp = self._call_configure(
            {'update_channel': 'dev', 'current_pin': '9999'},
            cfg_overrides={'pin': '1234'},
        )
        assert resp.get('status') == 403, f"Expected 403, got {resp}"
        assert resp['data'].get('error') == 'wrong_pin'
        assert not resp['save_calls'], "save_config must not be called on auth failure"

    def test_configure_channel_change_correct_pin_accepted(self):
        """channel change with correct current_pin succeeds and updates config when a PIN is set."""
        resp = self._call_configure(
            {'update_channel': 'dev', 'current_pin': '1234'},
            cfg_overrides={'pin': '1234'},
        )
        assert resp.get('status') == 200, f"Expected 200, got {resp}"
        assert resp['data'].get('ok') is True
        assert resp['save_calls'], "save_config was not called"
        assert resp['save_calls'][0].update_channel == 'dev'
        assert resp['live_cfg'].update_channel == 'dev'

    # --- Log entry ---

    def test_log_message_includes_update_channel(self, caplog):
        """A successful POST /configure must emit a log record containing update_channel."""
        import logging
        with caplog.at_level(logging.INFO):
            self._call_configure({'update_channel': 'dev'})
        assert any(
            'update_channel' in r.getMessage()
            for r in caplog.records
        ), "Expected a log record containing 'update_channel' after successful configure"


# ---------------------------------------------------------------------------
# Section 8.4 — Dial Setup UI (structural)
# ---------------------------------------------------------------------------

class TestDialSetupUiStructural:
    """Verify the dial Setup page HTML includes channel controls."""

    def test_prerelease_checkbox_present(self):
        from dial_webui_assets import SETUP_PAGE_HTML
        assert 'id="c-pre"' in SETUP_PAGE_HTML

    def test_loadcfg_populates_channel(self):
        from dial_webui_assets import SETUP_PAGE_HTML
        assert "update_channel === 'dev'" in SETUP_PAGE_HTML

    def test_saveconfig_includes_update_channel(self):
        from dial_webui_assets import SETUP_PAGE_HTML
        assert "update_channel:" in SETUP_PAGE_HTML
        assert "pre ? 'dev' : 'stable'" in SETUP_PAGE_HTML

    def test_channel_annotation_in_update_check_result(self):
        from dial_webui_assets import SETUP_PAGE_HTML
        assert "pre-release channel" in SETUP_PAGE_HTML


# ---------------------------------------------------------------------------
# Section 8.5 — Main appliance dial card (structural)
# ---------------------------------------------------------------------------

class TestMainDialCardStructural:
    """Verify the main appliance dial card HTML includes per-dial channel controls."""

    def _get_setup_page_source(self) -> str:
        source_path = REPO_ROOT / "core" / "autostream_webui_page_setup.py"
        return source_path.read_text(encoding="utf-8")

    def test_dial_channel_class_present(self):
        source = self._get_setup_page_source()
        assert 'class="dial-channel"' in source

    def test_dial_channel_save_config_action(self):
        source = self._get_setup_page_source()
        assert 'class="dial-channel" data-dial-action="save-config"' in source

    def test_dialloadconfig_populates_channel(self):
        source = self._get_setup_page_source()
        assert "chanEl.checked = (j.update_channel === 'dev')" in source

    def test_dialsaveconfig_includes_channel(self):
        source = self._get_setup_page_source()
        assert "body.update_channel = chanEl.checked ? 'dev' : 'stable'" in source

    def test_change_listener_includes_dial_channel(self):
        source = self._get_setup_page_source()
        assert "classList.contains('dial-channel')" in source

    def test_proxy_passthrough_no_modification(self):
        """The proxy strips uuid and forwards all other fields — no dials.py changes needed."""
        source_path = REPO_ROOT / "core" / "autostream_webui_dials.py"
        source = source_path.read_text(encoding="utf-8")
        # Proxy strips uuid and forwards everything else verbatim.
        assert 'k != "uuid"' in source


# ---------------------------------------------------------------------------
# Section 8.1 — Installer default (structural)
# ---------------------------------------------------------------------------

class TestInstallerDefault:
    def test_helpers_sh_includes_update_channel(self):
        helpers = REPO_ROOT / "installer" / "dial" / "helpers.sh"
        content = helpers.read_text(encoding="utf-8")
        assert "'update_channel': 'stable'" in content

    def test_helpers_sh_update_channel_in_settings_json(self):
        """update_channel must appear in the json.dump call that writes dial-settings.json."""
        helpers = REPO_ROOT / "installer" / "dial" / "helpers.sh"
        content = helpers.read_text(encoding="utf-8")
        # Find the write_dial_settings function
        start = content.find("write_dial_settings()")
        assert start != -1
        func_body = content[start:start + 400]
        assert "update_channel" in func_body


# ---------------------------------------------------------------------------
# Section 8.6 — Dial update-check passes channel through
# ---------------------------------------------------------------------------

class TestDialUpdateCheckPassthrough:
    def test_cmd_check_output_includes_channel(self, tmp_path):
        """The check result JSON includes 'channel', which the HTTP server passes through."""
        mod = _load_script("autostream_dial_updater")
        mod.STATE_DIR = tmp_path
        mod.APMODE_FLAG = tmp_path / "_apmode_absent"
        mod.LOG_PATH = tmp_path / "dial-update.log"
        settings = tmp_path / "dial-settings.json"
        settings.write_text(json.dumps({"auto_update": False, "update_channel": "dev"}), encoding="utf-8")
        payload = json.dumps([{
            "tag_name": "v1.3.0-beta.1",
            "tarball_url": "https://example.com/b.tgz",
            "html_url": "https://example.com",
            "body": "",
        }]).encode()
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = mod.cmd_check()
        assert "channel" in result
        assert result["channel"] == "dev"
