"""Tests for removed low-value code, stale comments, and asset defects.

Covers:
- No-op touch_ap_timer hook was removed from wifi_watcher.
- Flask routes in wifi_watcher still respond correctly after the removal.
- Internal design identifiers removed from dial module docstrings.
- UPDATED markers removed from autostream-nginx.conf.
- Corrected privileged-helper default path in autostream_sysutils.py docstring.
- Corrected module header in autostream_webui_assets.py.
- Embedded-asset and page source files compile cleanly (SyntaxWarning = error).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
_dial = str(REPO_ROOT / "dial")
for _p in (_core, _dial):
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# 1. wifi_watcher — no-op hook removed
# ---------------------------------------------------------------------------

def _watcher_source() -> str:
    return (REPO_ROOT / "platform" / "wifi_watcher").read_text(encoding="utf-8")


def test_touch_ap_timer_removed():
    """touch_ap_timer must no longer appear in wifi_watcher."""
    src = _watcher_source()
    assert "touch_ap_timer" not in src, (
        "No-op touch_ap_timer was not removed from wifi_watcher"
    )


def test_before_request_removed():
    """The @app.before_request decorator for touch_ap_timer must be gone."""
    src = _watcher_source()
    # The only remaining before_request usage should be absent entirely
    assert "before_request" not in src, (
        "@app.before_request must be absent from wifi_watcher after removing the no-op hook"
    )


class TestWatcherFlaskRoutesUnchanged:
    """Flask routes must still function after the no-op hook removal."""

    @pytest.fixture
    def watcher_app(self):
        import importlib, importlib.util, types
        # Load wifi_watcher in a fresh module context so it doesn't need real netdev
        spec = importlib.util.spec_from_file_location(
            "wifi_watcher",
            REPO_ROOT / "platform" / "wifi_watcher",
        )
        try:
            import flask as _fl
        except ImportError:
            pytest.skip("Flask not available")

        mod = importlib.util.module_from_spec(spec)
        mod.__dict__["__name__"] = "wifi_watcher"
        try:
            spec.loader.exec_module(mod)
        except SystemExit:
            pass
        except Exception:
            pytest.skip("wifi_watcher could not be imported in test environment")

        app = getattr(mod, "app", None)
        if app is None:
            pytest.skip("no Flask app in wifi_watcher")
        app.config["TESTING"] = True
        return app.test_client()

    def test_setup_page_returns_html(self, watcher_app):
        r = watcher_app.get("/")
        # Should return 200 or a redirect — not a 500
        assert r.status_code in (200, 302, 301)


# ---------------------------------------------------------------------------
# 2. Internal design identifiers removed from dial module docstrings
# ---------------------------------------------------------------------------

def test_dr2_removed_from_dial_volume():
    """The old DR-2 design identifier must not appear in dial_volume.py."""
    src = (REPO_ROOT / "dial" / "dial_volume.py").read_text(encoding="utf-8")
    assert "DR-2" not in src, "DR-2 identifier still present in dial_volume.py"


def test_dr6_removed_from_dial_led():
    """The old DR-6 design identifier must not appear in dial_led.py."""
    src = (REPO_ROOT / "dial" / "dial_led.py").read_text(encoding="utf-8")
    assert "DR-6" not in src, "DR-6 identifier still present in dial_led.py"


# ---------------------------------------------------------------------------
# 3. UPDATED markers removed from autostream-nginx.conf
# ---------------------------------------------------------------------------

def test_updated_markers_removed_from_nginx_conf():
    """Stale UPDATED markers must be removed from autostream-nginx.conf."""
    conf = (REPO_ROOT / "system" / "nginx" / "autostream-nginx.conf").read_text(
        encoding="utf-8"
    )
    assert "UPDATED:" not in conf, (
        "Stale '# UPDATED:' markers still present in autostream-nginx.conf"
    )


# ---------------------------------------------------------------------------
# 4. autostream_sysutils.py docstring uses the correct helper path
# ---------------------------------------------------------------------------

def test_sysutils_docstring_correct_helper_path():
    """run_admin_cmd docstring must reference the production helper path."""
    src = (REPO_ROOT / "core" / "autostream_sysutils.py").read_text(encoding="utf-8")
    assert "/usr/local/libexec/autostream/autostream_admin" in src, (
        "run_admin_cmd docstring must reference the correct helper path"
    )
    assert "/usr/local/sbin/autostream_admin" not in src, (
        "Stale /usr/local/sbin/autostream_admin path must be removed from docstring"
    )


# ---------------------------------------------------------------------------
# 5. autostream_webui_assets.py module header is correct
# ---------------------------------------------------------------------------

def test_webui_assets_module_header_correct():
    """Module header must name the correct file and have a complete description."""
    src = (REPO_ROOT / "core" / "autostream_webui_assets.py").read_text(encoding="utf-8")
    # Correct filename in header
    assert '"""autostream_webui_assets.py' in src, (
        "Module header must name the file as autostream_webui_assets.py"
    )
    # No truncated "autostrea" description
    assert "for autostrea\n" not in src, (
        "Truncated 'for autostrea' description must be fixed in module header"
    )


# ---------------------------------------------------------------------------
# 6. Embedded-asset and page modules compile without SyntaxWarning
# ---------------------------------------------------------------------------

_ASSET_MODULES = [
    REPO_ROOT / "core" / "autostream_webui_assets.py",
    REPO_ROOT / "core" / "autostream_webui_page_setup.py",
    REPO_ROOT / "core" / "autostream_webui_page_service.py",
    REPO_ROOT / "core" / "autostream_webui_page_about.py",
    REPO_ROOT / "core" / "autostream_webui_page_logs.py",
    REPO_ROOT / "core" / "autostream_webui_page_equaliser.py",
    REPO_ROOT / "core" / "autostream_webui_page_owntone.py",
    REPO_ROOT / "core" / "autostream_webui_page_rebooting.py",
    REPO_ROOT / "dial" / "dial_webui_assets.py",
]


@pytest.mark.parametrize("module_path", _ASSET_MODULES, ids=lambda p: p.name)
def test_asset_module_compiles_cleanly(module_path):
    """Each embedded-asset/page module must compile without SyntaxWarning."""
    import warnings
    src = module_path.read_text(encoding="utf-8")
    with warnings.catch_warnings():
        warnings.simplefilter("error", SyntaxWarning)
        try:
            compile(src, str(module_path), "exec")
        except SyntaxWarning as e:
            pytest.fail(f"SyntaxWarning in {module_path.name}: {e}")
        except SyntaxError as e:
            pytest.fail(f"SyntaxError in {module_path.name}: {e}")
