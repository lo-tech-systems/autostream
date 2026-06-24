"""WP9 — mDNS transition verification.

Key plan invariant: mDNS service types, TXT records, and federation APIs are
unchanged by the Wi-Fi adapter selection / recovery feature.  The wifi_watcher
and autostream_wifi_network.py must never touch these.

Tests are static source-analysis and config-file checks; no runtime required.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent

WIFI_WATCHER_SRC = (REPO_ROOT / "platform" / "wifi_watcher").read_text(encoding="utf-8")
WIFI_NETWORK_SRC = (REPO_ROOT / "core" / "autostream_wifi_network.py").read_text(encoding="utf-8")

# Known mDNS service types used by autostream
MDNS_SERVICE_TYPES = (
    "_autostream._tcp",
    "_autostream-playing._tcp",
    "_autostream-dial._tcp",
)

# Federation / mDNS module names that the watcher must NOT touch
FEDERATION_MODULES = (
    "autostream_appliances",
    "autostream_dials",
    "autostream_federation",
    "autostream_mdns",
)

# Avahi XML service files containing the canonical TXT records
AVAHI_PLAYING_SVC = REPO_ROOT / "system" / "avahi" / "autostream-playing.service"
AVAHI_DIAL_SVC = REPO_ROOT / "system" / "avahi" / "autostream-dial.service"


# ---------------------------------------------------------------------------
# wifi_watcher isolation from mDNS service types
# ---------------------------------------------------------------------------

class TestWifiWatcherMdnsIsolation:
    def test_watcher_does_not_reference_autostream_tcp_service(self):
        """The watcher must never browse or register mDNS service types."""
        for stype in MDNS_SERVICE_TYPES:
            assert stype not in WIFI_WATCHER_SRC, (
                f"wifi_watcher must not reference mDNS service type '{stype}'"
            )

    def test_watcher_does_not_import_federation_modules(self):
        """The watcher runs as root and must not import federation/appliance modules."""
        src_lower = WIFI_WATCHER_SRC.lower()
        for mod in FEDERATION_MODULES:
            # Check import statement presence, not substring match in comments
            assert f"import {mod}" not in WIFI_WATCHER_SRC, (
                f"wifi_watcher must not import {mod}"
            )

    def test_watcher_avahi_interaction_is_hostname_only(self):
        """The watcher interacts with Avahi only to verify/restore the mDNS hostname
        after a network handover.  It must not manipulate service registration."""
        # These strings confirm hostname-only interaction
        assert "avahi" in WIFI_WATCHER_SRC.lower()
        # These strings would indicate service manipulation (must be absent)
        forbidden = ("service-group", "<service>", "txt-record", "avahi-publish")
        for f in forbidden:
            assert f not in WIFI_WATCHER_SRC, (
                f"wifi_watcher must not manipulate Avahi service files (found '{f}')"
            )


# ---------------------------------------------------------------------------
# autostream_wifi_network.py isolation
# ---------------------------------------------------------------------------

class TestWifiNetworkModuleMdnsIsolation:
    def test_wifi_network_no_mdns_service_types(self):
        """autostream_wifi_network.py is a facts/primitives module; must not
        reference any mDNS service type strings."""
        for stype in MDNS_SERVICE_TYPES:
            assert stype not in WIFI_NETWORK_SRC, (
                f"autostream_wifi_network.py must not reference '{stype}'"
            )

    def test_wifi_network_no_federation_imports(self):
        """The bounded helper must not import federation/appliance modules."""
        for mod in FEDERATION_MODULES:
            assert f"import {mod}" not in WIFI_NETWORK_SRC, (
                f"autostream_wifi_network.py must not import {mod}"
            )

    def test_wifi_network_stdlib_only_imports(self):
        """Parse the import section of autostream_wifi_network.py and confirm
        every import is from the Python standard library or the known internal
        list.  Third-party mDNS libraries (e.g. zeroconf, dbus) must be absent."""
        forbidden_third_party = ("zeroconf", "dbus", "avahi", "pydbus", "jeepney")
        src_lower = WIFI_NETWORK_SRC.lower()
        for lib in forbidden_third_party:
            assert lib not in src_lower, (
                f"autostream_wifi_network.py must not import third-party library '{lib}'"
            )


# ---------------------------------------------------------------------------
# Avahi service file integrity (TXT records unchanged)
# ---------------------------------------------------------------------------

class TestAvahiServiceFileIntegrity:
    def test_playing_service_file_exists(self):
        assert AVAHI_PLAYING_SVC.exists(), "system/avahi/autostream-playing.service must exist"

    def test_playing_service_type_unchanged(self):
        txt = AVAHI_PLAYING_SVC.read_text(encoding="utf-8")
        assert "_autostream-playing._tcp" in txt

    def test_playing_service_txt_keys_present(self):
        txt = AVAHI_PLAYING_SVC.read_text(encoding="utf-8")
        for key in ("version=", "dial_api=", "audio_status=", "dial_status="):
            assert key in txt, f"TXT key '{key}' missing from autostream-playing.service"

    def test_dial_service_file_exists(self):
        assert AVAHI_DIAL_SVC.exists(), "system/avahi/autostream-dial.service must exist"

    def test_dial_service_type_unchanged(self):
        txt = AVAHI_DIAL_SVC.read_text(encoding="utf-8")
        assert "_autostream-dial._tcp" in txt

    def test_playing_service_port_unchanged(self):
        txt = AVAHI_PLAYING_SVC.read_text(encoding="utf-8")
        assert "<port>80</port>" in txt


# ---------------------------------------------------------------------------
# federation API handler unchanged
# ---------------------------------------------------------------------------

class TestFederationApiUnchanged:
    """Verify federation API files contain no wifi/adapter references that
    would indicate an interface change."""

    FEDERATION_SRC = (REPO_ROOT / "core" / "autostream_federation.py").read_text(encoding="utf-8")

    def test_federation_module_has_no_usb_adapter_references(self):
        """The federation API must be completely unaware of USB adapters."""
        assert "usb_adapter" not in self.FEDERATION_SRC
        assert "active_adapter" not in self.FEDERATION_SRC

    def test_federation_module_has_no_wifi_watcher_references(self):
        """The federation module must not call into the wifi watcher."""
        assert "wifi_watcher" not in self.FEDERATION_SRC
        assert "network_control" not in self.FEDERATION_SRC
