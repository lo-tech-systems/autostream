"""Tests for the dial nginx configuration.

Covers:
- Static image routes for badge and favicons.
- Offline recovery page locations with required sub_filter substitutions.
- CGI endpoint routes (reboot, factory-reset, update-status, download-logs).
- Updating flag redirect ($is_updating → /offline/updating).
- @offline handler redirects to /offline/ (not bare text 503).
- Branding simulation: sub_filter rules applied to shared HTML leave no
  unsubstituted main-product strings in the rendered output.
- nginx config validity check (skipped if nginx is absent).
"""
import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
NGINX_CONF = REPO_ROOT / "system" / "nginx" / "autostream-dial-nginx.conf"
OFFLINE_DIR = REPO_ROOT / "nginx" / "offline"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _conf():
    return NGINX_CONF.read_text(encoding="utf-8")


def _location_block(conf: str, path: str) -> str:
    """Extract the body of a named location block."""
    pattern = rf"location\s+=?\s*{re.escape(path)}\s*\{{"
    m = re.search(pattern, conf)
    assert m, f"location block not found for: {path}"
    start = m.end()
    depth = 1
    i = start
    while i < len(conf) and depth > 0:
        if conf[i] == "{":
            depth += 1
        elif conf[i] == "}":
            depth -= 1
        i += 1
    return conf[start:i - 1]


def _sub_filters(block: str) -> list[tuple[str, str]]:
    """Extract (from, to) pairs from sub_filter directives in a block.

    Handles nginx-escaped inner quotes (\\") in sub_filter strings.
    """
    pairs = []
    # Match nginx double-quoted strings that may contain \" escapes.
    pattern = r'sub_filter\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"'
    for m in re.finditer(pattern, block):
        frm = m.group(1).replace('\\"', '"').replace("\\\\", "\\")
        to = m.group(2).replace('\\"', '"').replace("\\\\", "\\")
        pairs.append((frm, to))
    return pairs


def _apply_sub_filters(text: str, pairs: list[tuple[str, str]]) -> str:
    """Simulate nginx sub_filter_once off substitution."""
    for frm, to in pairs:
        text = text.replace(frm, to)
    return text


# ---------------------------------------------------------------------------
# Static image routes
# ---------------------------------------------------------------------------

class TestStaticImageRoutes:
    def test_badge_route_present(self):
        """nginx must serve /autostream-dial-badge.png as a static file."""
        conf = _conf()
        assert "/autostream-dial-badge.png" in conf
        assert "/opt/autostream/images/autostream-dial-badge.png" in conf

    def test_favicon_ico_route_present(self):
        conf = _conf()
        assert "favicon.ico" in conf
        assert "/opt/autostream/images/favicon.ico" in conf

    def test_favicon_16_route_present(self):
        conf = _conf()
        assert "favicon-16x16.png" in conf

    def test_favicon_32_route_present(self):
        conf = _conf()
        assert "favicon-32x32.png" in conf


# ---------------------------------------------------------------------------
# Offline page locations
# ---------------------------------------------------------------------------

class TestOfflinePageLocations:
    def test_offline_index_location_present(self):
        conf = _conf()
        block = _location_block(conf, "/offline/")
        assert "try_files" in block

    def test_offline_rebooting_location_present(self):
        conf = _conf()
        block = _location_block(conf, "/offline/rebooting")
        assert "rebooting.html" in block

    def test_offline_resetting_location_present(self):
        conf = _conf()
        block = _location_block(conf, "/offline/resetting")
        assert "resetting.html" in block

    def test_offline_updating_location_present(self):
        conf = _conf()
        block = _location_block(conf, "/offline/updating")
        assert "updating.html" in block

    def test_all_offline_pages_use_shared_root(self):
        """All offline locations must serve from /opt/autostream/nginx."""
        conf = _conf()
        for path in ["/offline/", "/offline/rebooting", "/offline/resetting", "/offline/updating"]:
            block = _location_block(conf, path)
            assert "/opt/autostream/nginx" in block, (
                f"location {path} must have root /opt/autostream/nginx"
            )

    def test_all_offline_pages_disable_cache(self):
        """All offline locations must set Cache-Control: no-store."""
        conf = _conf()
        for path in ["/offline/", "/offline/rebooting", "/offline/resetting", "/offline/updating"]:
            block = _location_block(conf, path)
            assert "no-store" in block, (
                f"location {path} must add Cache-Control: no-store"
            )

    def test_all_offline_pages_use_sub_filter_once_off(self):
        """sub_filter_once off is required so all occurrences are substituted."""
        conf = _conf()
        for path in ["/offline/", "/offline/rebooting", "/offline/resetting", "/offline/updating"]:
            block = _location_block(conf, path)
            assert "sub_filter_once off" in block, (
                f"location {path} must set sub_filter_once off"
            )


# ---------------------------------------------------------------------------
# Sub_filter substitutions — all required entries per location
# ---------------------------------------------------------------------------

class TestSubFilterEntries:
    def _block(self, path):
        return _location_block(_conf(), path)

    # /offline/ (index page)

    def test_index_substitutes_badge_image(self):
        block = self._block("/offline/")
        assert '"/autostream-badge.png"' in block
        assert '"/autostream-dial-badge.png"' in block

    def test_index_substitutes_hotspot_ssid(self):
        block = self._block("/offline/")
        assert '"autostream_XXXX"' in block
        assert '"autostream-dial_XXXX"' in block

    def test_index_substitutes_heading_text(self):
        block = self._block("/offline/")
        assert '">autostream<"' in block
        assert '">autostream dial<"' in block

    def test_index_substitutes_title(self):
        block = self._block("/offline/")
        assert '"<title>autostream</title>"' in block
        assert '"<title>autostream dial</title>"' in block

    def test_index_substitutes_alt_text(self):
        block = self._block("/offline/")
        assert '"alt=\\"AutoStream\\""' in block or 'alt="AutoStream"' in block

    def test_index_substitutes_log_zip_filename(self):
        block = self._block("/offline/")
        assert "'autostream-logs.zip'" in block
        assert "'autostream-dial-logs.zip'" in block

    def test_index_substitutes_baseurl(self):
        block = self._block("/offline/")
        assert '"__BASEURL__"' in block

    # /offline/updating (updating page has additional string substitutions)

    def test_updating_substitutes_badge(self):
        block = self._block("/offline/updating")
        assert "/autostream-badge.png" in block
        assert "/autostream-dial-badge.png" in block

    def test_updating_substitutes_updating_message(self):
        block = self._block("/offline/updating")
        assert "autostream is currently updating." in block
        assert "autostream dial is currently updating." in block

    def test_updating_substitutes_waiting_message(self):
        block = self._block("/offline/updating")
        assert "Waiting for autostream..." in block
        assert "Waiting for autostream dial..." in block

    def test_updating_substitutes_restarting_message(self):
        block = self._block("/offline/updating")
        assert "autostream appliance is restarting, please wait." in block
        assert "autostream dial is restarting, please wait." in block

    def test_updating_substitutes_checking_message(self):
        block = self._block("/offline/updating")
        assert "Checking if autostream is back online..." in block
        assert "Checking if autostream dial is back online..." in block


# ---------------------------------------------------------------------------
# Branding simulation: verify substitutions remove all main-product strings
# ---------------------------------------------------------------------------

class TestBrandingSimulation:
    """Apply the nginx sub_filter rules to the shared HTML files and verify
    that no unintended main-product strings survive in the rendered output.

    This catches missing sub_filter entries before the config is deployed to
    a real nginx instance.
    """

    STALE_STRINGS = [
        "/autostream-badge.png",   # badge URL
        "alt=\"AutoStream\"",      # image alt text
        "<title>autostream</title>",  # page title
        "autostream_XXXX",         # hotspot SSID
        "'autostream-logs.zip'",   # log filename in JS
        "__BASEURL__",             # placeholder URL
    ]

    def _simulate(self, location_path: str, html_filename: str) -> str:
        conf = _conf()
        block = _location_block(conf, location_path)
        pairs = _sub_filters(block)
        html = (OFFLINE_DIR / html_filename).read_text(encoding="utf-8")
        return _apply_sub_filters(html, pairs)

    def test_index_page_no_stale_badge_url(self):
        result = self._simulate("/offline/", "index.html")
        assert "/autostream-badge.png" not in result, (
            "Stale /autostream-badge.png URL remains in /offline/ after sub_filter"
        )

    def test_index_page_no_stale_alt_text(self):
        result = self._simulate("/offline/", "index.html")
        assert 'alt="AutoStream"' not in result, (
            "Stale alt=\"AutoStream\" remains in /offline/ after sub_filter"
        )

    def test_index_page_no_stale_title(self):
        result = self._simulate("/offline/", "index.html")
        assert "<title>autostream</title>" not in result, (
            "Stale <title>autostream</title> remains in /offline/ after sub_filter"
        )

    def test_index_page_no_stale_ssid(self):
        result = self._simulate("/offline/", "index.html")
        assert "autostream_XXXX" not in result, (
            "Stale autostream_XXXX SSID remains in /offline/ after sub_filter"
        )

    def test_index_page_no_stale_log_filename(self):
        result = self._simulate("/offline/", "index.html")
        assert "'autostream-logs.zip'" not in result, (
            "Stale 'autostream-logs.zip' remains in /offline/ after sub_filter"
        )

    def test_index_page_baseurl_substituted(self):
        result = self._simulate("/offline/", "index.html")
        assert "__BASEURL__" not in result, (
            "__BASEURL__ placeholder not substituted in /offline/"
        )

    def test_rebooting_page_no_stale_badge_url(self):
        result = self._simulate("/offline/rebooting", "rebooting.html")
        assert "/autostream-badge.png" not in result

    def test_rebooting_page_no_stale_alt_text(self):
        result = self._simulate("/offline/rebooting", "rebooting.html")
        assert 'alt="AutoStream"' not in result

    def test_rebooting_page_no_stale_title(self):
        result = self._simulate("/offline/rebooting", "rebooting.html")
        assert "<title>autostream</title>" not in result

    def test_resetting_page_no_stale_badge_url(self):
        result = self._simulate("/offline/resetting", "resetting.html")
        assert "/autostream-badge.png" not in result

    def test_resetting_page_no_stale_ssid(self):
        result = self._simulate("/offline/resetting", "resetting.html")
        assert "autostream_XXXX" not in result


# ---------------------------------------------------------------------------
# CGI endpoints
# ---------------------------------------------------------------------------

class TestCGIEndpoints:
    def test_reboot_cgi_route(self):
        conf = _conf()
        block = _location_block(conf, "/offline/reboot")
        assert "reboot.cgi" in block
        assert "fcgiwrap.socket" in block

    def test_factory_reset_cgi_route(self):
        conf = _conf()
        block = _location_block(conf, "/offline/factory-reset")
        assert "factory-reset.cgi" in block
        assert "fcgiwrap.socket" in block

    def test_update_status_cgi_route(self):
        conf = _conf()
        block = _location_block(conf, "/offline/update-status")
        assert "update-status.cgi" in block
        assert "fcgiwrap.socket" in block

    def test_download_logs_cgi_route(self):
        conf = _conf()
        block = _location_block(conf, "/offline/download-logs")
        assert "download-logs.cgi" in block
        assert "fcgiwrap.socket" in block


# ---------------------------------------------------------------------------
# Updating redirect
# ---------------------------------------------------------------------------

class TestUpdatingRedirect:
    def test_updating_flag_variable_set(self):
        """Config must set $is_updating based on /tmp/autostream-dial-updating."""
        conf = _conf()
        assert "is_updating" in conf
        assert "autostream-dial-updating" in conf

    def test_updating_redirect_in_location_block(self):
        """When $is_updating is set, location / must redirect to /offline/updating."""
        conf = _conf()
        block = _location_block(conf, "/")
        assert "is_updating" in block
        assert "/offline/updating" in block

    def test_updating_redirect_uses_302(self):
        """The updating redirect must be a 302 (temporary)."""
        conf = _conf()
        block = _location_block(conf, "/")
        assert "302" in block and "/offline/updating" in block


# ---------------------------------------------------------------------------
# @offline handler
# ---------------------------------------------------------------------------

class TestOfflineHandler:
    def test_offline_handler_redirects_not_text(self):
        """@offline must redirect to /offline/ instead of returning plain text 503."""
        conf = _conf()
        # Find @offline location block
        m = re.search(r"location\s+@offline\s*\{([^}]+)\}", conf)
        assert m, "@offline location block not found"
        body = m.group(1)
        assert "302" in body and "/offline/" in body, (
            "@offline must return 302 redirect to /offline/"
        )
        assert "503" not in body, (
            "@offline must not return a bare 503 plain-text response"
        )
        assert "text/plain" not in body, (
            "@offline must not serve text/plain"
        )


# ---------------------------------------------------------------------------
# nginx config validity (skipped when nginx binary is absent)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    subprocess.run(["which", "nginx"], capture_output=True).returncode != 0,
    reason="nginx binary not available",
)
class TestNginxValidity:
    def test_nginx_config_is_valid(self, tmp_path):
        """nginx -t must accept the configuration without errors."""
        # Write a minimal nginx wrapper that includes our server block
        wrapper = tmp_path / "nginx.conf"
        wrapper.write_text(
            f'events {{}}\nhttp {{ include {NGINX_CONF}; }}\n',
            encoding="utf-8",
        )
        result = subprocess.run(
            ["nginx", "-t", "-c", str(wrapper)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"nginx -t failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
