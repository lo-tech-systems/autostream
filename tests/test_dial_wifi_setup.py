"""Structural and unit tests for dial WiFi setup changes.

Covers:
- wifi_watcher connect_to_configured_wifi does not bounce a healthy connection.
- wifi_watcher configure_wifi_with_nmcli does not delete user WiFi profiles by SSID name.
- Dial hotspot wait page shows 'Continue setup from an autostream appliance' instruction.
- Dial hotspot wait page JS does not redirect to the dial's own .local hostname on success.
- Non-dial wait page still redirects to .local on success.
- APP_DIAL_MODE=1 is set in the dial wifi watcher systemd service.
"""
from __future__ import annotations

import importlib
import importlib.machinery
import importlib.util
import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
WIFI_WATCHER_PATH = REPO_ROOT / "platform" / "wifi_watcher.py"
WIFI_CONFIG_PATH = REPO_ROOT / "platform" / "wifi_config.py"
WIFI_WEB_PATH = REPO_ROOT / "platform" / "wifi_web.py"
DIAL_SERVICE = REPO_ROOT / "system" / "systemd" / "autostream_dial_wifi_watcher.service"

# The watcher imports its sibling helper `autostream_wifi_network` (deployed
# alongside it). Make core/ importable so the load succeeds.
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)


# ---------------------------------------------------------------------------
# Helpers to load wifi_watcher as a module
# ---------------------------------------------------------------------------

def _load_wifi_watcher(env_overrides: dict | None = None) -> types.ModuleType:
    """Import platform/wifi_watcher.py as a module with optional env overrides.

    We reload on each call with a clean sys.modules entry so env vars set via
    os.environ take effect (module-level constants read env at import time).
    """
    env = dict(os.environ)
    env.update(env_overrides or {})

    source = WIFI_WATCHER_PATH.read_text(encoding="utf-8")
    spec = importlib.util.spec_from_loader("wifi_watcher_test", loader=None)
    mod = types.ModuleType("wifi_watcher_test")

    # Provide stub dependencies so the import doesn't fail in a non-Pi environment.
    stub_flask = types.ModuleType("flask")
    stub_flask.Flask = MagicMock(return_value=MagicMock())
    stub_flask.request = MagicMock()
    stub_flask.jsonify = MagicMock()
    stub_flask.redirect = MagicMock()
    stub_flask.url_for = MagicMock()
    stub_flask.make_response = MagicMock()

    stub_sysutils = types.ModuleType("autostream_sysutils")
    stub_sysutils.run_cmd = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
    stub_sysutils.prime_gateway = MagicMock()
    stub_sysutils.reboot_system = MagicMock()
    stub_sysutils.get_system_hostname = MagicMock(return_value="test-host")
    stub_sysutils.dataclasses = MagicMock()

    saved = {}
    for k, v in env.items():
        saved[k] = os.environ.get(k)
        os.environ[k] = v
    # Ensure APP_DIAL_MODE absent by default unless overridden
    if 'APP_DIAL_MODE' not in env:
        os.environ.pop('APP_DIAL_MODE', None)

    try:
        with patch.dict("sys.modules", {
            "flask": stub_flask,
            "autostream_sysutils": stub_sysutils,
            "autostream_rpi": MagicMock(),
        }):
            mod.__spec__ = spec
            exec(compile(source, str(WIFI_WATCHER_PATH), "exec"), mod.__dict__)  # noqa: S102
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    return mod


# ---------------------------------------------------------------------------
# Source-level structural tests (no import needed)
# ---------------------------------------------------------------------------

def _watcher_src() -> str:
    return WIFI_WATCHER_PATH.read_text(encoding="utf-8")


def _config_src() -> str:
    return WIFI_CONFIG_PATH.read_text(encoding="utf-8")


def _fn_body(src: str, fn_name: str, end_marker: str) -> str:
    """Extract source from 'def fn_name(' up to end_marker.

    end_marker may be a def statement ('def foo(') or any other string
    such as a decorator ('@app.route').
    """
    start = src.index(f"def {fn_name}(")
    # Try the literal end_marker first; if that fails try it as a def.
    try:
        end = src.index(end_marker, start)
    except ValueError:
        end = src.index(f"def {end_marker}(", start)
    return src[start:end]


# ---------------------------------------------------------------------------
# configure_wifi_with_nmcli — no SSID-named profile deletion
# ---------------------------------------------------------------------------

class TestConfigureWifiCandidateTransaction:
    """The credential-apply path uses the rollback-safe candidate sequence
    (Section 6.5) rather than ``nmcli device wifi connect``."""

    def test_does_not_use_device_wifi_connect(self):
        """``nmcli device wifi connect`` reuses/modifies an existing profile and
        undermines rollback; it must not be used to submit credentials."""
        src = _watcher_src()
        fn_body = _fn_body(src, "configure_wifi_with_nmcli", "wait_for_connection")
        assert '"connect"' not in fn_body, (
            "credential submission must not call nmcli device wifi connect"
        )

    def test_does_not_delete_connection_by_ssid_name(self):
        src = _watcher_src()
        fn_body = _fn_body(src, "_try_candidate_on_adapter", "configure_wifi_with_nmcli")
        assert '"connection", "delete", ssid' not in fn_body, (
            "the candidate transaction must not delete a profile by the ssid variable"
        )

    def test_creates_uniquely_named_candidate(self):
        src = _watcher_src()
        fn_body = _fn_body(src, "_try_candidate_on_adapter", "configure_wifi_with_nmcli")
        assert "generate_candidate_name" in fn_body, (
            "the apply path must create a uniquely named candidate profile"
        )

    def test_deletes_only_candidate_by_uuid_on_failure(self):
        src = _watcher_src()
        fn_body = _fn_body(src, "_try_candidate_on_adapter", "configure_wifi_with_nmcli")
        assert "nm.delete_by_uuid" in fn_body, (
            "candidate failure must delete only the candidate by UUID"
        )

    def test_clears_cross_adapter_restrictions(self):
        src = _watcher_src()
        fn_body = _fn_body(src, "_try_candidate_on_adapter", "configure_wifi_with_nmcli")
        assert "nm.clear_restrictions" in fn_body, (
            "candidate success must clear cross-adapter restrictions"
        )


# ---------------------------------------------------------------------------
# connect_to_configured_wifi — skip bounce when healthy
# ---------------------------------------------------------------------------

class TestConnectToConfiguredWifiHealthCheck:
    def test_health_check_present_in_function(self):
        """connect_to_configured_wifi must check is_wifi_client_healthy before bouncing."""
        src = _config_src()
        fn_body = _fn_body(src, "connect_to_configured_wifi", "migrate_client_profiles_autoconnect_no")
        assert "is_wifi_client_healthy" in fn_body, (
            "connect_to_configured_wifi must call is_wifi_client_healthy() "
            "to avoid bouncing a healthy connection"
        )

    def test_no_device_bounce_remains(self):
        """Regression: the broken nmcli device disconnect/connect bounce is gone.

        The bounce is ineffective for a wedged USB PHY (NO-CARRIER) and was
        replaced by the dead-PHY USB reset ladder.  connect_to_configured_wifi
        must no longer issue `nmcli device connect`/`disconnect` on the
        unhealthy reconnect path (dead-phy recovery plan, WP3).
        """
        src = _config_src()
        # Scope to connect_to_configured_wifi itself (ends at migrate_client_profiles_autoconnect_no).
        fn_body = _fn_body(src, "connect_to_configured_wifi", "migrate_client_profiles_autoconnect_no")
        assert '"disconnect"' not in fn_body, (
            "connect_to_configured_wifi must not issue an nmcli device disconnect bounce"
        )
        assert 'device", "connect"' not in fn_body and '"connect"]' not in fn_body, (
            "connect_to_configured_wifi must not issue an nmcli device connect bounce"
        )

    def test_connection_up_called_only_on_unhealthy_path(self):
        """nmcli connection up must only be called on the unhealthy (reconnect) path.

        When the configured WiFi is already healthy, do not disturb it — skip both
        the device bounce and the connection up call and return True immediately.
        """
        src = _config_src()
        fn_body = _fn_body(src, "connect_to_configured_wifi", "migrate_client_profiles_autoconnect_no")
        health_pos = fn_body.index("is_wifi_client_healthy")
        # After the health check there must be an early return True before the
        # activation call (now nm.activate_ident on the unhealthy reconnect path).
        after_health = fn_body[health_pos:]
        early_return_pos = after_health.find("return True")
        up_pos = after_health.find("activate_ident")
        assert early_return_pos != -1, (
            "connect_to_configured_wifi must return True early on the healthy path"
        )
        assert up_pos != -1, (
            "the activation call must still appear in the unhealthy reconnect path"
        )
        assert early_return_pos < up_pos, (
            "The early 'return True' must appear before the activation call, "
            "so healthy connections are not disturbed by an unnecessary activation call"
        )

    def test_early_return_when_healthy_skips_connection_up(self):
        """The healthy path must return before reaching 'nmcli connection up'.

        Sending 'connection up' to an already-active profile is unnecessary and
        can cause a brief re-authentication event on some APs.
        """
        src = _config_src()
        fn_body = _fn_body(src, "connect_to_configured_wifi", "migrate_client_profiles_autoconnect_no")
        # Isolate the healthy branch: from health check to the first 'return True'
        health_pos = fn_body.index("is_wifi_client_healthy")
        after_health = fn_body[health_pos:]
        first_return_pos = after_health.index("return True")
        healthy_branch = after_health[:first_return_pos]
        assert '"up"' not in healthy_branch, (
            "The healthy branch must not call 'nmcli connection up' — "
            "it must return True before reaching the reconnect code"
        )

# ---------------------------------------------------------------------------
# AP_CONNECTION_NAME deletion — only managed AP profile is deleted
# ---------------------------------------------------------------------------

class TestApProfileDeletion:
    def test_start_ap_mode_deletes_only_ap_connection_name(self):
        """start_ap_mode must delete AP_CONNECTION_NAME, not arbitrary profiles."""
        src = _watcher_src()
        fn_body = _fn_body(src, "start_ap_mode", "\ndef stop_ap_mode(")
        assert "AP_CONNECTION_NAME" in fn_body, (
            "start_ap_mode must delete the managed AP profile (AP_CONNECTION_NAME)"
        )

    def test_stop_ap_mode_deletes_only_ap_connection_name(self):
        """stop_ap_mode must delete AP_CONNECTION_NAME, not other profiles."""
        src = _watcher_src()
        fn_body = _fn_body(src, "stop_ap_mode", "\ndef scan_all_networks(")
        assert "AP_CONNECTION_NAME" in fn_body
        # Must not reference ssid variable (would delete user profile)
        assert '"delete", ssid' not in fn_body


# ---------------------------------------------------------------------------
# Dial mode wait page — instruction text and JS behaviour
# ---------------------------------------------------------------------------

def _load_wifi_web() -> types.ModuleType:
    """Load platform/wifi_web.py (owns render_wait_page) with real Flask."""
    try:
        import flask  # noqa: F401
    except ImportError:
        pytest.skip("flask not installed — wifi_web render tests skipped")
    loader = importlib.machinery.SourceFileLoader("wifi_web_dial_test", str(WIFI_WEB_PATH))
    spec = importlib.util.spec_from_loader("wifi_web_dial_test", loader)
    mod = importlib.util.module_from_spec(spec)
    # Register under its name before exec: the dataclass decorator on
    # WebContext resolves its field annotations via sys.modules, so the
    # module must be findable by name while it executes.
    sys.modules["wifi_web_dial_test"] = mod
    try:
        loader.exec_module(mod)
    finally:
        sys.modules.pop("wifi_web_dial_test", None)
    return mod


class _FakeWatcher:
    """Seam stub for render_wait_page (w._DIAL_MODE / w.get_system_hostname)."""

    def __init__(self, dial_mode: bool, hostname: str = "dial-host"):
        self._DIAL_MODE = dial_mode
        self._hostname = hostname

    def get_system_hostname(self) -> str:
        return self._hostname


def _render_wait(dial_mode: bool, ssid: str = "MyNet", hostname: str = "dial-host") -> str:
    import flask
    web = _load_wifi_web()
    app = flask.Flask(__name__)
    with app.test_request_context("/setup"):
        return web.render_wait_page(_FakeWatcher(dial_mode, hostname), ssid)


class TestDialWaitPageInstruction:
    """render_wait_page moved to wifi_web (HTTP-extraction WP1); assert behaviour."""

    def test_dial_mode_shows_appliance_instruction(self):
        """Dial mode wait page must include 'Continue setup from an autostream appliance'."""
        out = _render_wait(dial_mode=True)
        assert "Continue setup from an autostream appliance" in out, (
            "render_wait_page must include 'Continue setup from an autostream appliance' "
            "in the dial mode branch"
        )

    def test_dial_mode_no_redirect_to_host_local(self):
        """Dial mode success path must not redirect to the dial's own .local hostname."""
        out = _render_wait(dial_mode=True, hostname="dial-host")
        assert "window.location.replace('http://dial-host.local" not in out, (
            "Dial mode success path must not redirect to the dial's own .local hostname"
        )

    def test_non_dial_mode_redirects_to_local(self):
        """Non-dial mode wait page must redirect to the appliance's .local hostname."""
        out = _render_wait(dial_mode=False, hostname="appliance")
        assert "window.location.replace('http://appliance.local" in out, (
            "Non-dial mode must redirect to the appliance's .local hostname on success"
        )

    def test_dial_mode_variable_used(self):
        """render_wait_page must branch on _DIAL_MODE (dial vs non-dial differ)."""
        dial_out = _render_wait(dial_mode=True)
        non_dial_out = _render_wait(dial_mode=False)
        assert dial_out != non_dial_out, (
            "render_wait_page must branch on _DIAL_MODE to distinguish dial from appliance mode"
        )

    def test_failure_redirect_preserved_in_both_modes(self):
        """Both dial and non-dial wait pages must redirect to /setup on failure."""
        for dial in (True, False):
            assert "/setup?e=" in _render_wait(dial_mode=dial), (
                "Wait page must redirect to /setup on failure in both dial and non-dial mode"
            )


# ---------------------------------------------------------------------------
# Dial systemd service — APP_DIAL_MODE env var
# ---------------------------------------------------------------------------

class TestDialServiceDialMode:
    def test_app_dial_mode_set_in_service(self):
        """autostream_dial_wifi_watcher.service must set APP_DIAL_MODE=1."""
        content = DIAL_SERVICE.read_text(encoding="utf-8")
        assert "APP_DIAL_MODE=1" in content, (
            "autostream_dial_wifi_watcher.service must set APP_DIAL_MODE=1 "
            "so wifi_watcher uses dial-mode wait page behaviour"
        )

    def test_app_title_still_set(self):
        """APP_TITLE must still be set in the dial wifi watcher service."""
        content = DIAL_SERVICE.read_text(encoding="utf-8")
        assert "APP_TITLE" in content, (
            "APP_TITLE must still be present in autostream_dial_wifi_watcher.service"
        )

    def test_app_dial_mode_not_in_main_service(self):
        """autostream_wifi_watcher.service (appliance) must NOT set APP_DIAL_MODE=1."""
        main_service = REPO_ROOT / "system" / "systemd" / "autostream_wifi_watcher.service"
        if not main_service.exists():
            pytest.skip("autostream_wifi_watcher.service not found")
        content = main_service.read_text(encoding="utf-8")
        assert "APP_DIAL_MODE=1" not in content, (
            "The main appliance wifi watcher service must not set APP_DIAL_MODE=1"
        )
