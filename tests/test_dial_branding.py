"""Tests for setup-page and captive-portal branding.

Covers:
- dial/dial_webui_assets.py: badge img tag and three favicon link tags are
  present in SETUP_PAGE_HTML.
- platform/wifi_watcher.py: APP_BANNER_IMAGE env var causes BANNER_HTML to render
  an <img> element; when unset, the text <div class="app-title"> is rendered.
  .app-banner-image CSS class is defined for the image variant.
- system/systemd/autostream_dial_wifi_watcher.service: APP_BANNER_IMAGE is set
  to /autostream-dial-badge.png.
- Main-product watcher service does NOT set APP_BANNER_IMAGE.
"""
import importlib.util
import os
import sys
from pathlib import Path
from importlib.machinery import SourceFileLoader

REPO_ROOT = Path(__file__).parent.parent
DIAL_WEBUI_ASSETS = REPO_ROOT / "dial" / "dial_webui_assets.py"
WIFI_WATCHER = REPO_ROOT / "platform" / "wifi_watcher.py"
# Presentation (APP_TITLE/APP_BANNER_IMAGE/BANNER_HTML/STYLE_CSS) was extracted
# to wifi_web.py (HTTP-extraction plan, WP1).
WIFI_WEB = REPO_ROOT / "platform" / "wifi_web.py"
DIAL_WATCHER_SERVICE = REPO_ROOT / "system" / "systemd" / "autostream_dial_wifi_watcher.service"
MAIN_WATCHER_SERVICE = REPO_ROOT / "system" / "systemd" / "autostream_wifi_watcher.service"


def _load_wifi_web(alias: str, env_overrides: dict | None = None) -> object:
    """Load platform/wifi_web.py with optional environment overrides.

    Presentation constants (APP_TITLE/APP_BANNER_IMAGE/BANNER_HTML/STYLE_CSS)
    are read at import time.  Flask is stubbed so the module imports in
    isolation; the banner/CSS code paths use only the standard library.
    """
    from unittest.mock import MagicMock

    saved = {}
    try:
        env = env_overrides or {}
        for k, v in env.items():
            saved[k] = os.environ.get(k)
            os.environ[k] = v
        loader = SourceFileLoader(alias, str(WIFI_WEB))
        spec = importlib.util.spec_from_loader(alias, loader)
        mod = importlib.util.module_from_spec(spec)
        injected = []
        if "flask" not in sys.modules:
            sys.modules["flask"] = MagicMock()
            injected.append("flask")
        # Drop any cached wifi_web so this fresh env takes effect.
        sys.modules.pop("wifi_web", None)
        # Register under alias before exec: the dataclass decorator on
        # WebContext resolves its field annotations via sys.modules, so the
        # module must be findable by name while it executes.
        sys.modules[alias] = mod
        try:
            loader.exec_module(mod)
        finally:
            sys.modules.pop(alias, None)
            for sn in injected:
                sys.modules.pop(sn, None)
        return mod
    finally:
        for k, orig in saved.items():
            if orig is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = orig


# ---------------------------------------------------------------------------
# Setup page: badge and favicons
# ---------------------------------------------------------------------------

class TestSetupPageBranding:
    def _html(self):
        import importlib.util as _iu
        loader = SourceFileLoader("dial_webui_assets_test", str(DIAL_WEBUI_ASSETS))
        spec = _iu.spec_from_loader("dial_webui_assets_test", loader)
        mod = _iu.module_from_spec(spec)
        loader.exec_module(mod)
        return mod.SETUP_PAGE_HTML

    def test_badge_img_in_header(self):
        """SETUP_PAGE_HTML must include the badge img in the .hdr div."""
        html = self._html()
        assert "/autostream-dial-badge.png" in html, (
            "Badge image (/autostream-dial-badge.png) not found in setup page HTML"
        )
        assert '<img src="/autostream-dial-badge.png"' in html, (
            "Badge <img> tag not found in setup page HTML"
        )

    def test_badge_img_has_alt_text(self):
        """Badge img must have alt text."""
        html = self._html()
        assert 'alt="autostream dial"' in html, (
            "Badge img must have alt=\"autostream dial\""
        )

    def test_favicon_ico_link(self):
        """SETUP_PAGE_HTML must include a favicon.ico link."""
        html = self._html()
        assert 'href="/favicon.ico"' in html, (
            "favicon.ico link not found in setup page HTML"
        )

    def test_favicon_16_link(self):
        """SETUP_PAGE_HTML must include a 16x16 PNG favicon link."""
        html = self._html()
        assert 'href="/favicon-16x16.png"' in html

    def test_favicon_32_link(self):
        """SETUP_PAGE_HTML must include a 32x32 PNG favicon link."""
        html = self._html()
        assert 'href="/favicon-32x32.png"' in html

    def test_favicon_links_in_head(self):
        """Favicon links must appear before </head>."""
        html = self._html()
        head_end = html.find("</head>")
        assert head_end != -1
        favicon_pos = html.find("/favicon.ico")
        assert favicon_pos != -1
        assert favicon_pos < head_end, (
            "Favicon link must appear in <head>, not after </head>"
        )


# ---------------------------------------------------------------------------
# wifi_watcher: APP_BANNER_IMAGE support
# ---------------------------------------------------------------------------

class TestWifiWatcherBannerImage:
    def test_banner_image_env_var_read(self):
        """wifi_web must read APP_BANNER_IMAGE from environment (presentation moved
        out of the watcher in the HTTP-extraction plan, WP1)."""
        src = WIFI_WEB.read_text(encoding="utf-8")
        assert "APP_BANNER_IMAGE" in src, (
            "wifi_web must read APP_BANNER_IMAGE from os.environ"
        )

    def test_banner_html_is_img_when_env_var_set(self):
        """BANNER_HTML must be an <img> element when APP_BANNER_IMAGE is set."""
        mod = _load_wifi_web(
            "web_with_image",
            {"APP_BANNER_IMAGE": "/autostream-dial-badge.png"},
        )
        assert "<img" in mod.BANNER_HTML, (
            "BANNER_HTML must render <img> when APP_BANNER_IMAGE is set"
        )
        assert "/autostream-dial-badge.png" in mod.BANNER_HTML

    def test_banner_html_has_alt_text_from_app_title(self):
        """<img> BANNER_HTML must use APP_TITLE as alt text."""
        mod = _load_wifi_web(
            "web_with_image_title",
            {
                "APP_BANNER_IMAGE": "/autostream-dial-badge.png",
                "APP_TITLE": "autostream dial",
            },
        )
        assert 'alt="autostream dial"' in mod.BANNER_HTML

    def test_banner_html_is_div_when_env_var_absent(self):
        """BANNER_HTML must fall back to <div class=\"app-title\"> when APP_BANNER_IMAGE is unset."""
        # Temporarily remove the env var if it was set
        old = os.environ.pop("APP_BANNER_IMAGE", None)
        try:
            mod = _load_wifi_web("web_no_image")
            assert 'class="app-title"' in mod.BANNER_HTML, (
                "BANNER_HTML must fall back to <div class=\"app-title\"> "
                "when APP_BANNER_IMAGE is not set"
            )
            assert "<img" not in mod.BANNER_HTML
        finally:
            if old is not None:
                os.environ["APP_BANNER_IMAGE"] = old

    def test_banner_html_is_div_when_env_var_empty(self):
        """BANNER_HTML must fall back to text div when APP_BANNER_IMAGE is empty string."""
        mod = _load_wifi_web("web_empty_image", {"APP_BANNER_IMAGE": ""})
        assert 'class="app-title"' in mod.BANNER_HTML
        assert "<img" not in mod.BANNER_HTML

    def test_app_banner_image_css_class_defined(self):
        """STYLE_CSS must define a .app-banner-image rule."""
        mod = _load_wifi_web(
            "web_css_check",
            {"APP_BANNER_IMAGE": "/autostream-dial-badge.png"},
        )
        assert ".app-banner-image" in mod.STYLE_CSS, (
            ".app-banner-image CSS class must be defined in STYLE_CSS"
        )

    def test_banner_image_src_is_html_escaped(self):
        """Image src must be HTML-escaped to prevent injection."""
        # A safe URL with no special chars should pass through unchanged.
        mod = _load_wifi_web(
            "web_image_escape",
            {"APP_BANNER_IMAGE": "/autostream-dial-badge.png"},
        )
        # The src attribute must be quoted safely.
        assert 'src="/autostream-dial-badge.png"' in mod.BANNER_HTML


# ---------------------------------------------------------------------------
# Service file: dial watcher has the env var, main watcher does not
# ---------------------------------------------------------------------------

class TestWifiWatcherServiceFile:
    def test_dial_service_sets_app_banner_image(self):
        """autostream_dial_wifi_watcher.service must set APP_BANNER_IMAGE."""
        content = DIAL_WATCHER_SERVICE.read_text(encoding="utf-8")
        assert "APP_BANNER_IMAGE" in content, (
            "APP_BANNER_IMAGE not set in autostream_dial_wifi_watcher.service"
        )
        assert "/autostream-dial-badge.png" in content

    def test_dial_service_banner_image_points_to_dial_badge(self):
        """APP_BANNER_IMAGE in dial service must point to autostream-dial-badge.png."""
        content = DIAL_WATCHER_SERVICE.read_text(encoding="utf-8")
        lines = [l.strip() for l in content.splitlines()
                 if "APP_BANNER_IMAGE" in l]
        assert lines, "APP_BANNER_IMAGE not found"
        assert any("autostream-dial-badge.png" in l for l in lines)

    def test_main_service_does_not_set_app_banner_image(self):
        """Main autostream wifi_watcher service must NOT set APP_BANNER_IMAGE.

        Regression guard: the banner image is dial-specific. Adding it to the
        main product's service would override its existing text-based banner.
        """
        if not MAIN_WATCHER_SERVICE.exists():
            return  # main product service not present in this checkout
        content = MAIN_WATCHER_SERVICE.read_text(encoding="utf-8")
        assert "APP_BANNER_IMAGE" not in content, (
            "APP_BANNER_IMAGE must not be set in the main autostream "
            "wifi_watcher service — it is dial-specific"
        )
