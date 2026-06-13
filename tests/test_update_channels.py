"""Tests for update channel feature — shared support, version ordering, and main appliance.

Covers the requirements from docs/working/dev-channel-implementation-plan.md sections 4–7 and 11.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tarfile as _tarfile
import urllib.error
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch, call

import pytest

REPO_ROOT = Path(__file__).parent.parent
_SUPERVISOR = str(REPO_ROOT / "supervisor")
if _SUPERVISOR not in sys.path:
    sys.path.insert(0, _SUPERVISOR)
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_update_support as _sup
from autostream_update_support import (
    API_LATEST,
    API_RELEASES,
    _github_latest_release,
    _normalise_update_channel,
    _sanitise_release_notes,
    _version_key,
)


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


def _mock_response(payload: bytes, status: int = 200) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.status = status
    mock_resp.read.return_value = payload
    return mock_resp


def _release_payload(
    tag: str = "v1.2.3",
    tarball: str = "https://example.com/release.tgz",
    html: str = "https://example.com/releases/v1.2.3",
    body: str = "Release notes",
) -> bytes:
    return json.dumps({
        "tag_name":    tag,
        "tarball_url": tarball,
        "html_url":    html,
        "body":        body,
    }).encode()


# ---------------------------------------------------------------------------
# Section 4 — Channel normalization
# ---------------------------------------------------------------------------

class TestNormaliseUpdateChannel:
    def test_dev_returns_dev(self):
        assert _normalise_update_channel("dev") == "dev"

    def test_dev_case_insensitive(self):
        assert _normalise_update_channel("DEV") == "dev"
        assert _normalise_update_channel("Dev") == "dev"

    def test_dev_with_whitespace(self):
        assert _normalise_update_channel("  dev  ") == "dev"

    def test_stable_returns_stable(self):
        assert _normalise_update_channel("stable") == "stable"

    def test_unknown_value_returns_stable(self):
        assert _normalise_update_channel("nightly") == "stable"
        assert _normalise_update_channel("beta") == "stable"

    def test_none_returns_stable(self):
        assert _normalise_update_channel(None) == "stable"

    def test_empty_string_returns_stable(self):
        assert _normalise_update_channel("") == "stable"

    def test_integer_returns_stable(self):
        assert _normalise_update_channel(42) == "stable"


# ---------------------------------------------------------------------------
# Section 5.1 — GitHub endpoint selection
# ---------------------------------------------------------------------------

class TestGithubEndpointSelection:
    """_github_latest_release must route to the correct endpoint per channel."""

    def test_stable_uses_releases_latest(self):
        payload = _release_payload()
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as m:
            _github_latest_release("ua", channel="stable")
        url_called = m.call_args[0][0].full_url
        assert url_called == API_LATEST

    def test_dev_uses_releases_list(self):
        payload = json.dumps([json.loads(_release_payload())]).encode()
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as m:
            _github_latest_release("ua", channel="dev")
        url_called = m.call_args[0][0].full_url
        assert url_called == API_RELEASES

    def test_invalid_channel_falls_back_to_stable(self):
        payload = _release_payload()
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as m:
            _github_latest_release("ua", channel="nightly")
        url_called = m.call_args[0][0].full_url
        assert url_called == API_LATEST

    def test_default_channel_is_stable(self):
        payload = _release_payload()
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as m:
            _github_latest_release("ua")
        url_called = m.call_args[0][0].full_url
        assert url_called == API_LATEST


# ---------------------------------------------------------------------------
# Section 5.1 — Response parsing
# ---------------------------------------------------------------------------

class TestStableResponseParsing:
    """Stable channel parses a JSON object response."""

    def test_valid_response_returns_correct_fields(self):
        payload = _release_payload(tag="v1.2.3", tarball="https://t.co/r.tgz")
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            reachable, tag, tarball, html, notes = _github_latest_release("ua", channel="stable")
        assert reachable is True
        assert tag == "v1.2.3"
        assert tarball == "https://t.co/r.tgz"
        assert notes is not None

    def test_404_returns_reachable_no_tag(self):
        err = urllib.error.HTTPError(url="", code=404, msg="Not Found", hdrs=None, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            reachable, tag, *_ = _github_latest_release("ua", channel="stable")
        assert reachable is True
        assert tag is None

    def test_network_error_returns_not_reachable(self):
        with patch("urllib.request.urlopen", side_effect=OSError("timeout")):
            reachable, tag, *_ = _github_latest_release("ua", channel="stable")
        assert reachable is False
        assert tag is None

    def test_non_404_http_error_returns_not_reachable(self):
        err = urllib.error.HTTPError(url="", code=500, msg="Server Error", hdrs=None, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            reachable, *_ = _github_latest_release("ua", channel="stable")
        assert reachable is False


class TestDevResponseParsing:
    """Dev channel parses a JSON list response."""

    def _list_payload(self, tag: str = "v1.3.0-beta.1") -> bytes:
        return json.dumps([{
            "tag_name":    tag,
            "tarball_url": "https://example.com/beta.tgz",
            "html_url":    "https://example.com/releases/" + tag,
            "body":        "Beta notes",
        }]).encode()

    def test_valid_list_returns_first_item(self):
        with patch("urllib.request.urlopen", return_value=_mock_response(self._list_payload("v1.3.0-beta.1"))):
            reachable, tag, tarball, html, notes = _github_latest_release("ua", channel="dev")
        assert reachable is True
        assert tag == "v1.3.0-beta.1"
        assert tarball is not None

    def test_empty_list_returns_reachable_no_tag(self):
        payload = json.dumps([]).encode()
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            reachable, tag, *_ = _github_latest_release("ua", channel="dev")
        assert reachable is True
        assert tag is None

    def test_non_list_response_returns_not_reachable(self):
        payload = json.dumps({"not": "a list"}).encode()
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            reachable, *_ = _github_latest_release("ua", channel="dev")
        assert reachable is False

    def test_network_error_returns_not_reachable(self):
        with patch("urllib.request.urlopen", side_effect=OSError("timeout")):
            reachable, *_ = _github_latest_release("ua", channel="dev")
        assert reachable is False


# ---------------------------------------------------------------------------
# Section 6 — Version ordering
# ---------------------------------------------------------------------------

class TestVersionOrdering:
    """Table-driven tests for the structured 7-tuple _version_key."""

    # Basic numeric ordering
    def test_higher_minor_is_newer(self):
        assert _version_key("1.2.9") < _version_key("1.3.0")

    def test_higher_patch_is_newer(self):
        assert _version_key("1.2.3") < _version_key("1.2.4")

    def test_v_prefix_same_as_no_prefix(self):
        assert _version_key("v1.3.0") == _version_key("1.3.0")

    # Final vs prerelease
    def test_prerelease_below_final(self):
        assert _version_key("1.3.0-rc.1") < _version_key("1.3.0")

    def test_beta_below_final(self):
        assert _version_key("1.3.0-beta.1") < _version_key("1.3.0")

    def test_alpha_below_final(self):
        assert _version_key("1.3.0-alpha.1") < _version_key("1.3.0")

    # Alpha < beta < rc < final
    def test_alpha_below_beta(self):
        assert _version_key("1.3.0-alpha.1") < _version_key("1.3.0-beta.1")

    def test_beta_below_rc(self):
        assert _version_key("1.3.0-beta.1") < _version_key("1.3.0-rc.1")

    def test_rc_below_final(self):
        assert _version_key("1.3.0-rc.1") < _version_key("1.3.0")

    # Numeric ordering within a label — key requirement: beta.2 < beta.10
    def test_alpha_sequential(self):
        assert _version_key("1.3.0-alpha.1") < _version_key("1.3.0-alpha.2")

    def test_beta_sequential(self):
        assert _version_key("1.3.0-beta.1") < _version_key("1.3.0-beta.2")

    def test_beta_numeric_not_lexicographic(self):
        assert _version_key("1.3.0-beta.2") < _version_key("1.3.0-beta.10")

    def test_rc_sequential(self):
        assert _version_key("1.3.0-rc.1") < _version_key("1.3.0-rc.2")

    # Cross-label ordering
    def test_alpha1_below_alpha2(self):
        assert _version_key("1.3.0-alpha.1") < _version_key("1.3.0-alpha.2")

    def test_beta2_below_beta10(self):
        assert _version_key("1.3.0-beta.2") < _version_key("1.3.0-beta.10")

    # Upgrade scenarios
    def test_installed_beta1_candidate_final_gives_update(self):
        assert _version_key("1.3.0") > _version_key("1.3.0-beta.1")

    def test_installed_beta1_candidate_older_stable_no_downgrade(self):
        assert _version_key("1.2.5") < _version_key("1.3.0-beta.1")

    # Malformed tags
    def test_malformed_tag_returns_zero_tuple(self):
        key = _version_key("not-a-version")
        assert key[0] == 0
        assert key[1] == 0
        assert key[2] == 0

    def test_empty_string_returns_zero_tuple(self):
        key = _version_key("")
        assert key[0] == 0

    def test_malformed_sorts_below_any_valid_tag(self):
        assert _version_key("garbage") < _version_key("0.0.1")

    # Missing components
    def test_missing_patch_treated_as_zero(self):
        assert _version_key("1.3") < _version_key("1.3.1")
        assert _version_key("1.3") == _version_key("1.3.0")


# ---------------------------------------------------------------------------
# Section 6.1 — Release note sanitization
# ---------------------------------------------------------------------------

class TestReleaseNotesSanitization:
    """_sanitise_release_notes must strip control chars and cap length."""

    def test_plain_text_is_returned(self):
        assert _sanitise_release_notes("Hello world") == "Hello world"

    def test_control_chars_stripped(self):
        raw = "line\x00with\x01nulls and \x07bell"
        result = _sanitise_release_notes(raw)
        assert "\x00" not in result
        assert "\x01" not in result
        assert "\x07" not in result
        assert "linewithnulls and bell" in result

    def test_long_text_truncated(self):
        long = "A" * 300
        result = _sanitise_release_notes(long, max_len=200)
        assert len(result) <= 200

    def test_empty_string_returns_empty(self):
        assert _sanitise_release_notes("") == ""

    def test_markdown_markers_pass_through(self):
        result = _sanitise_release_notes("- Fix bug #123\n- Add feature")
        assert "Fix bug" in result
        assert "Add feature" in result

    def test_whitespace_collapsed(self):
        result = _sanitise_release_notes("a   b   c")
        assert result == "a b c"


# ---------------------------------------------------------------------------
# Section 7.1 — UpdatesConfig model
# ---------------------------------------------------------------------------

class TestUpdatesConfigModel:
    def test_stable_channel_parsed(self):
        import autostream_config as c
        data = {"updates": {"auto_update": False, "update_channel": "stable"}}
        cfg = c.parse_config(data)
        assert cfg.updates.update_channel == "stable"
        assert cfg.updates.auto_update is False

    def test_dev_channel_parsed(self):
        import autostream_config as c
        data = {"updates": {"auto_update": True, "update_channel": "dev"}}
        cfg = c.parse_config(data)
        assert cfg.updates.update_channel == "dev"

    def test_missing_channel_defaults_to_stable(self):
        import autostream_config as c
        data = {"updates": {"auto_update": False}}
        cfg = c.parse_config(data)
        assert cfg.updates.update_channel == "stable"

    def test_invalid_channel_defaults_to_stable(self):
        import autostream_config as c
        data = {"updates": {"auto_update": False, "update_channel": "nightly"}}
        cfg = c.parse_config(data)
        assert cfg.updates.update_channel == "stable"

    def test_missing_updates_section_defaults_to_stable(self):
        import autostream_config as c
        cfg = c.parse_config({})
        assert cfg.updates.update_channel == "stable"

    def test_normalize_update_channel_function(self):
        import autostream_config as c
        assert c.normalize_update_channel("dev") == "dev"
        assert c.normalize_update_channel("DEV") == "dev"
        assert c.normalize_update_channel("stable") == "stable"
        assert c.normalize_update_channel(None) == "stable"
        assert c.normalize_update_channel("nightly") == "stable"


# ---------------------------------------------------------------------------
# Section 7.2 — Main updater channel reading
# ---------------------------------------------------------------------------

class TestMainUpdaterChannelReading:
    def _load_updater(self) -> ModuleType:
        return _load_script("autostream_updater")

    def test_missing_config_defaults_to_stable(self, tmp_path):
        mod = self._load_updater()
        mod.CONFIG_PATH = tmp_path / "absent.json"
        assert mod._read_update_channel() == "stable"

    def test_malformed_json_defaults_to_stable(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text("{bad json}", encoding="utf-8")
        mod = self._load_updater()
        mod.CONFIG_PATH = p
        assert mod._read_update_channel() == "stable"

    def test_stable_channel_read(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps({"updates": {"update_channel": "stable"}}), encoding="utf-8")
        mod = self._load_updater()
        mod.CONFIG_PATH = p
        assert mod._read_update_channel() == "stable"

    def test_dev_channel_read(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps({"updates": {"update_channel": "dev"}}), encoding="utf-8")
        mod = self._load_updater()
        mod.CONFIG_PATH = p
        assert mod._read_update_channel() == "dev"

    def test_missing_update_channel_key_defaults_to_stable(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps({"updates": {"auto_update": True}}), encoding="utf-8")
        mod = self._load_updater()
        mod.CONFIG_PATH = p
        assert mod._read_update_channel() == "stable"

    def test_non_dict_root_defaults_to_stable(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        mod = self._load_updater()
        mod.CONFIG_PATH = p
        assert mod._read_update_channel() == "stable"


# ---------------------------------------------------------------------------
# Section 7.2 — cmd_check() reports channel
# ---------------------------------------------------------------------------

class TestMainUpdaterCmdCheck:
    def _load(self, tmp_path, channel: str = "stable"):
        mod = _load_script("autostream_updater")
        mod.APMODE_FLAG = tmp_path / "_apmode_absent"
        mod.INSTALL_STATE_FILE = tmp_path / "install-state.env"
        mod.LOG_PATH = tmp_path / "update.log"
        cfg_path = tmp_path / "autostream.json"
        cfg_path.write_text(
            json.dumps({"updates": {"auto_update": False, "update_channel": channel}}),
            encoding="utf-8",
        )
        mod.CONFIG_PATH = cfg_path
        return mod

    def _mock_release(self, tag="v1.2.3", tarball="https://t.co/r.tgz"):
        payload = _release_payload(tag=tag, tarball=tarball)
        mock_resp = _mock_response(payload)
        return patch("urllib.request.urlopen", return_value=mock_resp)

    def test_check_includes_channel_stable(self, tmp_path):
        mod = self._load(tmp_path, channel="stable")
        with self._mock_release():
            result = mod.cmd_check()
        assert result.get("ok") is True
        assert result.get("channel") == "stable"

    def test_check_includes_channel_dev(self, tmp_path):
        mod = self._load(tmp_path, channel="dev")
        payload = json.dumps([json.loads(_release_payload(tag="v1.3.0-beta.1"))]).encode()
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            result = mod.cmd_check()
        assert result.get("ok") is True
        assert result.get("channel") == "dev"

    def test_check_no_release_includes_channel(self, tmp_path):
        mod = self._load(tmp_path, channel="stable")
        err = urllib.error.HTTPError(url="", code=404, msg="Not Found", hdrs=None, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            result = mod.cmd_check()
        assert result.get("ok") is True
        assert result.get("channel") == "stable"

    def test_check_network_error_returns_false(self, tmp_path):
        mod = self._load(tmp_path, channel="stable")
        with patch("urllib.request.urlopen", side_effect=OSError("timeout")):
            result = mod.cmd_check()
        assert result.get("ok") is False


# ---------------------------------------------------------------------------
# Section 7.2 — cmd_apply() uses single lookup, no double-call
# ---------------------------------------------------------------------------

class TestMainUpdaterApplySingleLookup:
    """apply() must use one lookup for both version guard and tarball staging."""

    def _load(self, tmp_path, channel: str = "stable"):
        mod = _load_script("autostream_updater")
        mod.APMODE_FLAG = tmp_path / "_apmode_absent"
        mod.INSTALL_STATE_FILE = tmp_path / "install-state.env"
        mod.LOG_PATH = tmp_path / "update.log"
        mod.UPDATE_LOCK_FILE = tmp_path / "update.lock"
        mod.UPDATE_RESULT_FILE = tmp_path / "update-result.env"
        mod.STAGING_DIR = tmp_path / "staging"
        cfg_path = tmp_path / "autostream.json"
        cfg_path.write_text(
            json.dumps({"updates": {"auto_update": False, "update_channel": channel}}),
            encoding="utf-8",
        )
        mod.CONFIG_PATH = cfg_path
        return mod

    def test_apply_already_at_latest_returns_noop(self, tmp_path):
        mod = self._load(tmp_path, channel="stable")
        state = tmp_path / "install-state.env"
        state.write_text("AUTOSTREAM_RELEASE_TAG=v1.2.3\n", encoding="utf-8")
        payload = _release_payload(tag="v1.2.3")
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
            with patch.object(mod, "_update_unit_active", return_value=False):
                result = mod.cmd_apply()
        assert result.get("ok") is True
        assert result.get("staged_tag") is None

    def test_apply_auto_disabled_skips(self, tmp_path):
        mod = self._load(tmp_path, channel="stable")
        result = mod.cmd_apply(auto=True)
        assert result.get("ok") is True
        assert result.get("reason") == "auto_update_disabled"

    def test_apply_apmode_refused(self, tmp_path):
        mod = self._load(tmp_path, channel="stable")
        apmode = tmp_path / "apmode"
        apmode.touch()
        mod.APMODE_FLAG = apmode
        result = mod.cmd_apply()
        assert result.get("ok") is False
        assert "AP mode" in result.get("error", "")

    def test_apply_network_error_returns_false(self, tmp_path):
        mod = self._load(tmp_path, channel="stable")
        with patch.object(mod, "_update_unit_active", return_value=False):
            with patch("urllib.request.urlopen", side_effect=OSError("timeout")):
                result = mod.cmd_apply()
        assert result.get("ok") is False

    def test_apply_channel_aware_dev_uses_list_endpoint(self, tmp_path):
        """apply() must call the dev endpoint when channel=dev."""
        mod = self._load(tmp_path, channel="dev")
        state = tmp_path / "install-state.env"
        state.write_text("AUTOSTREAM_RELEASE_TAG=v1.2.0\n", encoding="utf-8")
        payload = json.dumps([json.loads(_release_payload(tag="v1.3.0-beta.1"))]).encode()
        with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as m:
            with patch.object(mod, "_update_unit_active", return_value=False):
                with patch.object(mod, "_find_systemd_run", return_value=None):
                    mod.cmd_apply()
        url_called = m.call_args[0][0].full_url
        assert url_called == API_RELEASES

    def test_apply_single_lookup_stages_correct_tarball(self, tmp_path):
        """apply() must call _resolve_release exactly once, download the exact
        tarball it returned, write STAGING_DIR/release_tag, and pass
        AUTOSTREAM_RELEASE_TAG to systemd-run."""
        mod = self._load(tmp_path)
        (tmp_path / "install-state.env").write_text(
            "AUTOSTREAM_RELEASE_TAG=v1.2.0\n", encoding="utf-8"
        )

        FAKE_TAG     = "v1.3.0"
        FAKE_TARBALL = "https://example.com/v1.3.0.tgz"

        staging_dir = tmp_path / "staging"
        mod.STAGING_DIR = staging_dir

        resolved_calls = []
        downloaded_urls = []
        run_cmds = []

        def fake_resolve(channel):
            resolved_calls.append(channel)
            return (True, FAKE_TAG, FAKE_TARBALL, None, None)

        def fake_download(url, dst, ua, timeout=120):
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(b"placeholder")
            downloaded_urls.append(url)

        @contextmanager
        def fake_taropen(path, mode):
            # Create a minimal extracted tree so the installer-detection passes.
            extract_dir = staging_dir / "src"
            repo_dir = extract_dir / "repo-v1.3.0"
            repo_dir.mkdir(parents=True, exist_ok=True)
            installer = repo_dir / "autostream_install.sh"
            installer.write_text("#!/bin/bash\n", encoding="utf-8")
            os.chmod(str(installer), 0o755)
            (repo_dir / "system").mkdir(exist_ok=True)
            yield MagicMock()

        def fake_run(cmd, timeout=60):
            run_cmds.append(list(cmd))
            return (0, "", "")

        mod.FLOCK_BIN = sys.executable  # real, executable — bypasses isfile/isexec

        with patch.object(mod, "_resolve_release", side_effect=fake_resolve), \
             patch.object(mod, "_update_unit_active", return_value=False), \
             patch.object(mod, "_download_file", side_effect=fake_download), \
             patch.object(mod, "_find_systemd_run", return_value="/fake/systemd-run"), \
             patch.object(mod, "_run", side_effect=fake_run), \
             patch("tarfile.open", fake_taropen):
            result = mod.cmd_apply()

        assert result.get("ok") is True, f"Expected ok:True, got {result}"
        assert len(resolved_calls) == 1, f"Expected 1 resolver call, got {len(resolved_calls)}"
        assert downloaded_urls == [FAKE_TARBALL], \
            f"Expected tarball {FAKE_TARBALL}, got {downloaded_urls}"
        tag_file = staging_dir / "release_tag"
        assert tag_file.exists(), "release_tag was not created in STAGING_DIR"
        assert tag_file.read_text(encoding="utf-8") == FAKE_TAG + "\n"
        assert run_cmds, "systemd-run (_run) was never called"
        flat_cmd = " ".join(run_cmds[0])
        assert f"AUTOSTREAM_RELEASE_TAG={FAKE_TAG}" in flat_cmd, \
            f"AUTOSTREAM_RELEASE_TAG not in systemd-run command: {flat_cmd}"

    def test_apply_auto_skips_when_playing_service_exists(self, tmp_path):
        """auto mode must skip when the playing-service marker file is present."""
        mod = self._load(tmp_path)
        cfg_path = tmp_path / "autostream.json"
        cfg_path.write_text(
            json.dumps({"updates": {"auto_update": True, "update_channel": "stable"}}),
            encoding="utf-8",
        )
        playing = tmp_path / "playing.service"
        playing.touch()
        mod.PLAYING_SERVICE = playing
        result = mod.cmd_apply(auto=True)
        assert result == {"ok": True, "skipped": True, "reason": "playback_active"}


# ---------------------------------------------------------------------------
# Section 7.3 — Setup page renders channel toggle
# ---------------------------------------------------------------------------

class TestSetupPageChannelToggle:
    def _make_config(self, tmp_path, channel, auto_update=False):
        """Write a fully-configured JSON so unconfigured() returns False."""
        cfg = {
            "updates": {"update_channel": channel, "auto_update": auto_update},
            "general": {"fifo_path": "/tmp/fifo", "log_file": "/tmp/log"},
            "audio1": {"capture_device": "hw:0,0"},
            "owntone": {"output_name": "Test Speaker"},
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg), encoding="utf-8")
        return str(p)

    def _render(self, tmp_path, channel="stable", auto_update=False, initial=False):
        """Call the actual page renderer and return the rendered HTML."""
        import autostream_webui_page_setup as _page

        if initial:
            # Empty config makes unconfigured() return True (missing required keys).
            config_path = str(tmp_path / "config.json")
            (tmp_path / "config.json").write_text("{}", encoding="utf-8")
        else:
            config_path = self._make_config(tmp_path, channel, auto_update)

        handler = MagicMock()
        handler.wfile = io.BytesIO()
        handler._csrf_token = "test-csrf"
        handler.headers = {}

        state = MagicMock()
        state.config_path = config_path
        state.get_monitor_devices.return_value = []

        auth = MagicMock()
        auth.get_csrf_token.return_value = "test-csrf"
        auth.get_boot_pin_value.return_value = "1234"

        _list_result = MagicMock(ok=True, outputs=[])
        with patch.multiple(
            "autostream_webui_page_setup",
            get_system_hostname=MagicMock(return_value="testhost"),
            list_outputs=MagicMock(return_value=_list_result),
            get_ap_ssid=MagicMock(return_value="autostream_TEST"),
            get_app_version=MagicMock(return_value="1.0.0-test"),
            _get_dial_sightings=MagicMock(return_value=[]),
            parse_dial_entries=MagicMock(return_value=[]),
            suggested_silence_threshold_dbfs=MagicMock(return_value=-40.0),
            build_top_banner_html=MagicMock(return_value=("", "")),
            _set_flash_cookie=MagicMock(),
        ):
            _page.send_setup_page(handler, state, auth)

        return handler.wfile.getvalue().decode("utf-8", errors="replace")

    def test_stable_renders_unchecked(self, tmp_path):
        html = self._render(tmp_path, channel="stable")
        assert 'name="updates_channel_present"' in html
        assert 'name="updates_prerelease_channel"' in html
        assert 'updates_prerelease_channel" checked' not in html

    def test_dev_renders_checked(self, tmp_path):
        html = self._render(tmp_path, channel="dev")
        assert 'updates_prerelease_channel" checked' in html

    def test_initial_setup_omits_channel(self, tmp_path):
        html = self._render(tmp_path, channel="dev", initial=True)
        assert 'name="updates_channel_present"' not in html


# ---------------------------------------------------------------------------
# Section 7.4 — POST handler persists channel
# ---------------------------------------------------------------------------

class TestPostHandlerChannel:
    """Verify update_channel persistence via the actual handle_setup_post handler."""

    _BASE_CFG = {
        "general": {"log_file": "/tmp/log", "fifo_path": "/tmp/fifo"},
        "audio1":  {"capture_device": "hw:0,0"},
        "owntone": {"output_name": "Test"},
    }
    _POST_PATCHES = dict(
        get_system_hostname=MagicMock(return_value="testhost"),
        set_system_hostname=MagicMock(),
        run_admin_cmd=MagicMock(return_value=MagicMock(returncode=0)),
        update_live_owntone_runtime=MagicMock(),
        update_playback_input_config=MagicMock(),
        update_live_silence_seconds=MagicMock(return_value=True),
        request_config_reload=MagicMock(),
        suggested_silence_threshold_dbfs=MagicMock(return_value=-40.0),
        _set_flash_cookie=MagicMock(),
        send_setup_page=MagicMock(),
        build_top_banner_html=MagicMock(return_value=("", "")),
    )

    def _run_post(self, tmp_path, form_fields, extra_cfg=None):
        """Call the actual handle_setup_post and return the saved config dict."""
        from urllib.parse import urlencode
        import autostream_webui_post_handlers as ph

        cfg = {**self._BASE_CFG, "updates": {"auto_update": False, "update_channel": "stable"}}
        if extra_cfg:
            for k, v in extra_cfg.items():
                if isinstance(v, dict) and k in cfg:
                    cfg[k].update(v)
                else:
                    cfg[k] = v

        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")

        handler = MagicMock()
        handler.headers = {}
        handler.wfile = io.BytesIO()
        state = MagicMock()
        state.config_path = str(config_path)

        with patch.multiple("autostream_webui_post_handlers", **self._POST_PATCHES):
            ph.handle_setup_post(handler, state, MagicMock(), urlencode(form_fields))

        return json.loads(config_path.read_text(encoding="utf-8"))

    def test_post_dev_checkbox_saves_dev(self, tmp_path):
        form = {"updates_channel_present": "1", "updates_prerelease_channel": "1"}
        result = self._run_post(tmp_path, form)
        assert result["updates"]["update_channel"] == "dev"

    def test_post_unchecked_saves_stable(self, tmp_path):
        form = {"updates_channel_present": "1"}
        result = self._run_post(tmp_path, form, extra_cfg={"updates": {"update_channel": "dev"}})
        assert result["updates"]["update_channel"] == "stable"

    def test_missing_panel_preserves_existing_channel(self, tmp_path):
        form = {}  # updates panel absent (initial setup)
        result = self._run_post(tmp_path, form, extra_cfg={"updates": {"update_channel": "dev"}})
        assert result["updates"]["update_channel"] == "dev"

    def test_channel_change_does_not_trigger_timer(self, tmp_path):
        """Changing channel without changing auto_update must not call toggle-update-timer."""
        from urllib.parse import urlencode
        import autostream_webui_post_handlers as ph

        cfg = {**self._BASE_CFG, "updates": {"auto_update": False, "update_channel": "stable"}}
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")

        handler = MagicMock()
        handler.headers = {}
        handler.wfile = io.BytesIO()
        state = MagicMock()
        state.config_path = str(config_path)

        mock_admin = MagicMock(return_value=MagicMock(returncode=0))
        patches = {**self._POST_PATCHES, "run_admin_cmd": mock_admin}

        # Form: channel → dev, auto_update unchanged (False → False via sentinel absent)
        form = {"updates_channel_present": "1", "updates_prerelease_channel": "1"}
        with patch.multiple("autostream_webui_post_handlers", **patches):
            ph.handle_setup_post(handler, state, MagicMock(), urlencode(form))

        mock_admin.assert_not_called()
