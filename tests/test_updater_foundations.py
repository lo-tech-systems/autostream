"""Regression tests for update infrastructure (WP12–14 review findings).

Covers:
1. Deployment-manifest correctness — dial installer must deploy the two
   core Python modules that wifi_watcher depends on at runtime, and both
   installers must deploy the shared update-support module.
2. _github_latest_release must distinguish a real API/network failure
   (reachable=False) from a valid response with no published release
   (reachable=True, tag=None).
3. Both cmd_check() implementations must return ok: False when the
   GitHub API is unreachable rather than silently reporting no update.
"""
import importlib.util
import sys
import urllib.error
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_SUPERVISOR = str(REPO_ROOT / "supervisor")
if _SUPERVISOR not in sys.path:
    sys.path.insert(0, _SUPERVISOR)

# Import the support module (has .py extension — importable directly).
import autostream_update_support as _sup
from autostream_update_support import _github_latest_release

DIAL_INSTALLER = REPO_ROOT / "autostream_dial_install.sh"
HOST_INSTALLER = REPO_ROOT / "autostream_install.sh"
DIAL_HELPERS   = REPO_ROOT / "installer" / "dial" / "helpers.sh"


def _load_script(name: str) -> ModuleType:
    """Load a supervisor script (no .py extension) as a Python module.

    On Windows, stubs fcntl (Linux-only) so that the module can be imported
    for testing cmd_check(), which does not call any fcntl functions.
    """
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


# ---------------------------------------------------------------------------
# 1. Deployment-manifest correctness
# ---------------------------------------------------------------------------

class TestDialDeploymentManifest:
    """The dial installer must deploy core/autostream_sysutils.py and
    core/autostream_rpi.py explicitly so that wifi_watcher can import them
    on a fresh installation that does not co-install the host service.
    """

    def test_sysutils_deployed_from_core(self):
        content = DIAL_INSTALLER.read_text(encoding="utf-8")
        assert "core/autostream_sysutils.py" in content, (
            "Dial installer must deploy core/autostream_sysutils.py; "
            "wifi_watcher imports autostream_sysutils at runtime"
        )

    def test_rpi_deployed_from_core(self):
        content = DIAL_INSTALLER.read_text(encoding="utf-8")
        assert "core/autostream_rpi.py" in content, (
            "Dial installer must deploy core/autostream_rpi.py; "
            "autostream_sysutils imports autostream_rpi at runtime"
        )

    def test_platform_python_files_not_referenced(self):
        """After WP12 the platform/ Python copies are gone; the installer
        must not reference them (it would silently skip a missing file or
        fail loudly on a clean checkout)."""
        content = DIAL_INSTALLER.read_text(encoding="utf-8")
        assert "platform/autostream_sysutils.py" not in content
        assert "platform/autostream_rpi.py" not in content

    def test_update_support_deployed_by_dial_helpers(self):
        content = DIAL_HELPERS.read_text(encoding="utf-8")
        assert "autostream_update_support.py" in content, (
            "installer/dial/helpers.sh must deploy autostream_update_support.py "
            "alongside autostream_dial_updater"
        )


class TestHostDeploymentManifest:
    def test_update_support_deployed_by_host_installer(self):
        content = HOST_INSTALLER.read_text(encoding="utf-8")
        assert "autostream_update_support.py" in content, (
            "autostream_install.sh must deploy autostream_update_support.py "
            "alongside autostream_updater"
        )


# ---------------------------------------------------------------------------
# 2. _github_latest_release reachable / unreachable distinction
# ---------------------------------------------------------------------------

class TestGithubLatestRelease:
    def test_network_error_returns_not_reachable(self):
        with patch("urllib.request.urlopen", side_effect=OSError("Connection refused")):
            reachable, tag, tarball, html, notes = _github_latest_release("test-ua")
        assert reachable is False
        assert tag is None

    def test_non_404_http_error_returns_not_reachable(self):
        err = urllib.error.HTTPError(
            url="", code=500, msg="Internal Server Error", hdrs=None, fp=None
        )
        with patch("urllib.request.urlopen", side_effect=err):
            reachable, tag, tarball, html, notes = _github_latest_release("test-ua")
        assert reachable is False
        assert tag is None

    def test_404_returns_reachable_with_no_tag(self):
        err = urllib.error.HTTPError(
            url="", code=404, msg="Not Found", hdrs=None, fp=None
        )
        with patch("urllib.request.urlopen", side_effect=err):
            reachable, tag, tarball, html, notes = _github_latest_release("test-ua")
        assert reachable is True
        assert tag is None

    def test_valid_response_returns_reachable_with_tag(self):
        import io, json
        payload = json.dumps({
            "tag_name": "v1.2.3",
            "tarball_url": "https://example.com/release.tgz",
            "html_url": "https://example.com/releases/v1.2.3",
            "body": "Release notes here",
        }).encode()
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.status = 200
        mock_resp.read.return_value = payload
        with patch("urllib.request.urlopen", return_value=mock_resp):
            reachable, tag, tarball, html, notes = _github_latest_release("test-ua")
        assert reachable is True
        assert tag == "v1.2.3"
        assert tarball == "https://example.com/release.tgz"
        assert notes is not None


# ---------------------------------------------------------------------------
# 3. cmd_check returns ok: False when the API is unreachable
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 3. cmd_apply --auto respects the auto_update flag in dial-settings.json
# ---------------------------------------------------------------------------

class TestDialUpdaterAutoFlag:
    """cmd_apply(auto=True) reads auto_update from the correct path and gates accordingly."""

    def _load(self, tmp_path):
        mod = _load_script("autostream_dial_updater")
        mod.STATE_DIR = tmp_path
        # Keep APMODE_FLAG pointing at a path that will never exist in tmp_path.
        mod.APMODE_FLAG = tmp_path / "_apmode_absent"
        return mod

    def _write_settings(self, tmp_path, auto_update: bool):
        import json as _json
        (tmp_path / "dial-settings.json").write_text(
            _json.dumps({"auto_update": auto_update}), encoding="utf-8"
        )

    def test_auto_update_false_returns_noop(self, tmp_path):
        """auto_update: false → ok:True without proceeding to version check."""
        mod = self._load(tmp_path)
        self._write_settings(tmp_path, auto_update=False)
        result = mod.cmd_apply(auto=True)
        assert result == {"ok": True}

    def test_auto_update_true_proceeds_past_gate(self, tmp_path):
        """auto_update: true → passes the settings gate and reaches the release lookup."""
        mod = self._load(tmp_path)
        self._write_settings(tmp_path, auto_update=True)
        # Stub the single-lookup helper to return "already at latest" so we exit cleanly.
        installed_tag = "1.0.0"
        with patch.object(mod, "_resolve_dial_release",
                          return_value=(True, "v1.0.0", None, None, None)) as mock_resolve, \
             patch.object(mod, "_read_installed_tag", return_value=installed_tag):
            result = mod.cmd_apply(auto=True)
        assert result.get("ok") is True
        mock_resolve.assert_called_once()


# ---------------------------------------------------------------------------
# 4. cmd_check returns ok: False when the API is unreachable
# ---------------------------------------------------------------------------

class TestCmdCheckFailsOnNetworkError:
    """Both updater scripts must return {"ok": False} when the API is down,
    not {"ok": True, "update_available": False}."""

    def _network_error_patch(self):
        return patch(
            "urllib.request.urlopen",
            side_effect=OSError("Simulated network failure"),
        )

    def test_host_updater_cmd_check_returns_error(self):
        mod = _load_script("autostream_updater")
        with self._network_error_patch():
            result = mod.cmd_check()
        assert result.get("ok") is False, (
            f"cmd_check must return ok: False on network error; got {result}"
        )
        assert "error" in result

    def test_dial_updater_cmd_check_returns_error(self):
        mod = _load_script("autostream_dial_updater")
        with self._network_error_patch():
            result = mod.cmd_check()
        assert result.get("ok") is False, (
            f"dial cmd_check must return ok: False on network error; got {result}"
        )
        assert "error" in result
