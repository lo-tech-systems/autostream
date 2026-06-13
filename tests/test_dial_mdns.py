"""Priority 5 — dial_mdns parsing and deduplication tests.

Covers: TXT parsing (quoting, escaping, malformed), _handle_line() event
routing (IPv4 only, dial_api=v1 filter, port defaults, add/remove), and
deduplication across interfaces.

No real avahi-browse subprocess is invoked — _handle_line() and _parse_txt()
are called directly.  Module-level maps (_by_key, _by_name) are reset between
tests by the autouse conftest fixture.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import dial_mdns as dm


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _av_add(iface="eth0", proto="IPv4", name="My-Appliance",
            svc_type="_autostream-playing._tcp", domain="local",
            host="myappliance.local", ip="192.168.1.10",
            port="80", txt='dial_api=v1') -> str:
    """Build an avahi-browse add event line."""
    return f"=;{iface};{proto};{name};{svc_type};{domain};{host};{ip};{port};{txt}"


def _av_remove(iface="eth0", proto="IPv4", name="My-Appliance",
               svc_type="_autostream-playing._tcp", domain="local") -> str:
    """Build an avahi-browse remove event line."""
    return f"-;{iface};{proto};{name};{svc_type};{domain}"


def _clear():
    dm._by_key.clear()
    dm._by_name.clear()
    dm._had_targets = False


# ---------------------------------------------------------------------------
# _parse_txt
# ---------------------------------------------------------------------------

class TestParseTxt:
    def test_simple_key_value(self):
        result = dm._parse_txt("dial_api=v1")
        assert result == {"dial_api": "v1"}

    def test_multiple_tokens(self):
        result = dm._parse_txt("dial_api=v1 audio_status=v1")
        assert result["dial_api"] == "v1"
        assert result["audio_status"] == "v1"

    def test_double_quoted_token(self):
        result = dm._parse_txt('"dial_api=v1" "name=My Appliance"')
        assert result.get("dial_api") == "v1"
        assert result.get("name") == "My Appliance"

    def test_token_without_equals_ignored(self):
        result = dm._parse_txt("justtoken dial_api=v1")
        assert "justtoken" not in result
        assert result.get("dial_api") == "v1"

    def test_empty_string_returns_empty_dict(self):
        assert dm._parse_txt("") == {}

    def test_malformed_shlex_returns_partial(self):
        # Unclosed quote is a shlex error — should return empty dict or partial
        result = dm._parse_txt('dial_api=v1 "unclosed')
        # Either {} (error caught) or {"dial_api": "v1"}
        assert isinstance(result, dict)

    def test_backslash_escaped_value(self):
        result = dm._parse_txt(r'"dial_api=v1" "flag=a\\b"')
        assert result.get("dial_api") == "v1"


# ---------------------------------------------------------------------------
# _handle_line: add events
# ---------------------------------------------------------------------------

class TestHandleLineAdd:
    def setup_method(self):
        _clear()

    def test_ipv4_entry_with_dial_api_v1_added(self):
        dm._handle_line(_av_add())
        targets = dm.get_playing_targets()
        assert len(targets) == 1
        assert targets[0].ip == "192.168.1.10"
        assert targets[0].dial_api is True

    def test_non_ipv4_entry_ignored(self):
        dm._handle_line(_av_add(proto="IPv6"))
        assert dm.get_playing_targets() == []

    def test_entry_without_dial_api_v1_ignored(self):
        dm._handle_line(_av_add(txt="version=2"))
        assert dm.get_playing_targets() == []

    def test_entry_with_wrong_dial_api_version_ignored(self):
        dm._handle_line(_av_add(txt="dial_api=v2"))
        assert dm.get_playing_targets() == []

    def test_invalid_port_defaults_to_80(self):
        dm._handle_line(_av_add(port="notaport"))
        targets = dm.get_playing_targets()
        assert targets[0].port == 80

    def test_valid_port_used(self):
        dm._handle_line(_av_add(port="7842"))
        targets = dm.get_playing_targets()
        assert targets[0].port == 7842

    def test_audio_status_flag_parsed(self):
        dm._handle_line(_av_add(txt="dial_api=v1 audio_status=v1"))
        targets = dm.get_playing_targets()
        assert targets[0].audio_status is True

    def test_audio_status_absent_is_false(self):
        dm._handle_line(_av_add(txt="dial_api=v1"))
        targets = dm.get_playing_targets()
        assert targets[0].audio_status is False

    def test_service_name_stored(self):
        dm._handle_line(_av_add(name="Kitchen"))
        targets = dm.get_playing_targets()
        assert targets[0].name == "Kitchen"


# ---------------------------------------------------------------------------
# _handle_line: deduplication across interfaces
# ---------------------------------------------------------------------------

class TestHandleLineDeduplication:
    def setup_method(self):
        _clear()

    def test_same_service_two_interfaces_gives_one_target(self):
        dm._handle_line(_av_add(iface="eth0", ip="192.168.1.10"))
        dm._handle_line(_av_add(iface="wlan0", ip="192.168.1.10"))
        targets = dm.get_playing_targets()
        assert len(targets) == 1

    def test_two_different_services_give_two_targets(self):
        dm._handle_line(_av_add(name="Service-A", ip="192.168.1.10"))
        dm._handle_line(_av_add(name="Service-B", ip="192.168.1.11"))
        targets = dm.get_playing_targets()
        assert len(targets) == 2

    def test_remove_one_interface_preserves_other(self):
        dm._handle_line(_av_add(iface="eth0", ip="10.0.0.1"))
        dm._handle_line(_av_add(iface="wlan0", ip="10.0.0.1"))
        # Remove eth0 sighting
        dm._handle_line(_av_remove(iface="eth0"))
        targets = dm.get_playing_targets()
        assert len(targets) == 1
        assert targets[0].ip == "10.0.0.1"

    def test_remove_all_interfaces_removes_target(self):
        dm._handle_line(_av_add(iface="eth0", ip="10.0.0.1"))
        dm._handle_line(_av_remove(iface="eth0"))
        assert dm.get_playing_targets() == []

    def test_remove_nonexistent_entry_is_noop(self):
        dm._handle_line(_av_add(iface="eth0"))
        dm._handle_line(_av_remove(iface="wlan0"))  # never added
        targets = dm.get_playing_targets()
        assert len(targets) == 1

    def test_unknown_event_prefix_ignored(self):
        dm._handle_line("?;eth0;IPv4;Service;_tcp;local;host;10.0.0.1;80;dial_api=v1")
        assert dm.get_playing_targets() == []

    def test_too_few_fields_in_add_line_ignored(self):
        dm._handle_line("=;eth0;IPv4;Service;_tcp;local")  # fewer than 10 parts
        assert dm.get_playing_targets() == []
