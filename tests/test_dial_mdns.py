"""Priority 5 — dial_mdns parsing and deduplication tests.

Covers: TXT parsing (quoting, escaping, malformed), event routing
(IPv4 only, dial_api=v1 filter, port defaults, add/remove), and
deduplication across interfaces.

No real avahi-browse subprocess is invoked — the shared MdnsBrowser's
_handle_line() is called directly.  The browser state is reset between
tests via the autouse conftest fixture and explicit _clear() calls.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import dial_mdns as dm
from autostream_mdns import parse_avahi_txt


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
    with dm._browser._lock:
        dm._browser._by_key.clear()
        dm._browser._by_identity.clear()
    with dm._state_lock:
        dm._target_state.clear()
    dm._had_targets = False


# ---------------------------------------------------------------------------
# TXT parsing (now via parse_avahi_txt from shared module)
# ---------------------------------------------------------------------------

class TestParseTxt:
    def test_simple_key_value(self):
        result = parse_avahi_txt("dial_api=v1")
        assert result == {"dial_api": "v1"}

    def test_multiple_tokens(self):
        result = parse_avahi_txt("dial_api=v1 audio_status=v1")
        assert result["dial_api"] == "v1"
        assert result["audio_status"] == "v1"

    def test_double_quoted_token(self):
        result = parse_avahi_txt('"dial_api=v1" "name=My Appliance"')
        assert result.get("dial_api") == "v1"
        assert result.get("name") == "My Appliance"

    def test_token_without_equals_ignored(self):
        result = parse_avahi_txt("justtoken dial_api=v1")
        assert "justtoken" not in result
        assert result.get("dial_api") == "v1"

    def test_empty_string_returns_empty_dict(self):
        assert parse_avahi_txt("") == {}

    def test_malformed_shlex_returns_partial(self):
        result = parse_avahi_txt('dial_api=v1 "unclosed')
        assert isinstance(result, dict)

    def test_backslash_escaped_value(self):
        result = parse_avahi_txt(r'"dial_api=v1" "flag=a\\b"')
        assert result.get("dial_api") == "v1"


# ---------------------------------------------------------------------------
# _handle_line: add events
# ---------------------------------------------------------------------------

class TestHandleLineAdd:
    def setup_method(self):
        _clear()

    def test_ipv4_entry_with_dial_api_v1_added(self):
        dm._browser._handle_line(_av_add())
        targets = dm.get_playing_targets()
        assert len(targets) == 1
        assert targets[0].ip == "192.168.1.10"
        assert targets[0].dial_api is True

    def test_non_ipv4_entry_ignored(self):
        dm._browser._handle_line(_av_add(proto="IPv6"))
        assert dm.get_playing_targets() == []

    def test_entry_without_dial_api_v1_ignored(self):
        dm._browser._handle_line(_av_add(txt="version=2"))
        assert dm.get_playing_targets() == []

    def test_entry_with_wrong_dial_api_version_ignored(self):
        dm._browser._handle_line(_av_add(txt="dial_api=v2"))
        assert dm.get_playing_targets() == []

    def test_invalid_port_defaults_to_80(self):
        dm._browser._handle_line(_av_add(port="notaport"))
        targets = dm.get_playing_targets()
        assert targets[0].port == 80

    def test_valid_port_used(self):
        dm._browser._handle_line(_av_add(port="7842"))
        targets = dm.get_playing_targets()
        assert targets[0].port == 7842

    def test_audio_status_flag_parsed(self):
        dm._browser._handle_line(_av_add(txt="dial_api=v1 audio_status=v1"))
        targets = dm.get_playing_targets()
        assert targets[0].audio_status is True

    def test_audio_status_absent_is_false(self):
        dm._browser._handle_line(_av_add(txt="dial_api=v1"))
        targets = dm.get_playing_targets()
        assert targets[0].audio_status is False

    def test_service_name_stored(self):
        dm._browser._handle_line(_av_add(name="Kitchen"))
        targets = dm.get_playing_targets()
        assert targets[0].name == "Kitchen"


# ---------------------------------------------------------------------------
# _handle_line: deduplication across interfaces
# ---------------------------------------------------------------------------

class TestHandleLineDeduplication:
    def setup_method(self):
        _clear()

    def test_same_service_two_interfaces_gives_one_target(self):
        dm._browser._handle_line(_av_add(iface="eth0", ip="192.168.1.10"))
        dm._browser._handle_line(_av_add(iface="wlan0", ip="192.168.1.10"))
        targets = dm.get_playing_targets()
        assert len(targets) == 1

    def test_two_different_services_give_two_targets(self):
        dm._browser._handle_line(_av_add(name="Service-A", ip="192.168.1.10"))
        dm._browser._handle_line(_av_add(name="Service-B", ip="192.168.1.11"))
        targets = dm.get_playing_targets()
        assert len(targets) == 2

    def test_remove_one_interface_preserves_other(self):
        dm._browser._handle_line(_av_add(iface="eth0", ip="10.0.0.1"))
        dm._browser._handle_line(_av_add(iface="wlan0", ip="10.0.0.1"))
        dm._browser._handle_line(_av_remove(iface="eth0"))
        targets = dm.get_playing_targets()
        assert len(targets) == 1
        assert targets[0].ip == "10.0.0.1"

    def test_remove_all_interfaces_removes_target(self):
        dm._browser._handle_line(_av_add(iface="eth0", ip="10.0.0.1"))
        dm._browser._handle_line(_av_remove(iface="eth0"))
        assert dm.get_playing_targets() == []

    def test_remove_nonexistent_entry_is_noop(self):
        dm._browser._handle_line(_av_add(iface="eth0"))
        dm._browser._handle_line(_av_remove(iface="wlan0"))
        targets = dm.get_playing_targets()
        assert len(targets) == 1

    def test_unknown_event_prefix_ignored(self):
        dm._browser._handle_line("?;eth0;IPv4;Service;_tcp;local;host;10.0.0.1;80;dial_api=v1")
        assert dm.get_playing_targets() == []

    def test_too_few_fields_in_add_line_ignored(self):
        dm._browser._handle_line("=;eth0;IPv4;Service;_tcp;local")
        assert dm.get_playing_targets() == []


# ---------------------------------------------------------------------------
# WP-5: playing_since / display_authorized registry and get_display_targets()
# ---------------------------------------------------------------------------

class TestPlayingSinceRegistry:
    def setup_method(self):
        _clear()

    def test_first_add_sets_playing_since(self):
        dm._browser._handle_line(_av_add())
        targets = dm.get_display_targets()
        assert len(targets) == 1
        assert targets[0].playing_since > 0

    def test_repeated_resolve_preserves_playing_since(self):
        dm._browser._handle_line(_av_add(iface="eth0"))
        first = dm.get_display_targets()[0].playing_since
        dm._browser._handle_line(_av_add(iface="eth0"))
        second = dm.get_display_targets()[0].playing_since
        assert first == second

    def test_ip_change_preserves_playing_since(self):
        """A re-resolve with a new address for the same service identity (no
        intervening remove event) preserves playing_since."""
        dm._browser._handle_line(_av_add(ip="10.0.0.1"))
        first_since = dm.get_display_targets()[0].playing_since
        dm._browser._handle_line(_av_add(ip="10.0.0.2"))
        targets = dm.get_display_targets()
        assert len(targets) == 1
        assert targets[0].playing_since == first_since
        assert targets[0].ip == "10.0.0.2"

    def test_address_change_resets_display_authorized(self):
        dm._browser._handle_line(_av_add(ip="10.0.0.1"))
        target = dm.get_display_targets()[0]
        dm.mark_display_target_unauthorized(target)
        assert dm.get_display_targets()[0].display_authorized is False

        dm._browser._handle_line(_av_add(ip="10.0.0.2"))
        targets = dm.get_display_targets()
        assert targets[0].display_authorized is True

    def test_mark_unauthorized_suppresses_row(self):
        dm._browser._handle_line(_av_add())
        target = dm.get_display_targets()[0]
        dm.mark_display_target_unauthorized(target)
        assert dm.get_display_targets()[0].display_authorized is False

    def test_mark_unauthorized_ignored_after_address_change(self):
        dm._browser._handle_line(_av_add(ip="10.0.0.1"))
        stale_target = dm.get_display_targets()[0]
        dm._browser._handle_line(_av_add(ip="10.0.0.2"))
        dm.mark_display_target_unauthorized(stale_target)
        assert dm.get_display_targets()[0].display_authorized is True

    def test_mark_unauthorized_ignored_after_removal(self):
        dm._browser._handle_line(_av_add())
        target = dm.get_display_targets()[0]
        dm._browser._handle_line(_av_remove())
        dm.mark_display_target_unauthorized(target)  # must not raise or resurrect state
        assert dm.get_display_targets() == []
        assert dm._target_state == {}

    def test_removal_clears_target_state(self):
        dm._browser._handle_line(_av_add())
        dm._browser._handle_line(_av_remove())
        assert dm._target_state == {}

    def test_reappear_after_removal_starts_fresh(self):
        dm._browser._handle_line(_av_add())
        target = dm.get_display_targets()[0]
        dm.mark_display_target_unauthorized(target)
        first_since = target.playing_since
        dm._browser._handle_line(_av_remove())
        time.sleep(0.005)
        dm._browser._handle_line(_av_add())
        targets = dm.get_display_targets()
        assert targets[0].playing_since > first_since
        assert targets[0].display_authorized is True

    def test_deterministic_sort_by_playing_since_then_name_ip_port(self):
        dm._browser._handle_line(_av_add(name="Earlier", ip="10.0.0.2"))
        dm._browser._handle_line(_av_add(name="Later", ip="10.0.0.1"))
        targets = dm.get_display_targets()
        assert [t.name for t in targets] == ["Earlier", "Later"]

    def test_tie_break_by_name_ip_port_when_playing_since_equal(self):
        dm._browser._handle_line(_av_add(name="Zeta", ip="10.0.0.9"))
        dm._browser._handle_line(_av_add(name="Alpha", ip="10.0.0.1"))
        # Force equal playing_since to isolate the name/ip/port tie-break.
        with dm._state_lock:
            for state in dm._target_state.values():
                state["playing_since"] = 100.0
        targets = dm.get_display_targets()
        assert [t.name for t in targets] == ["Alpha", "Zeta"]

    def test_service_name_field_matches_mdns_name(self):
        dm._browser._handle_line(_av_add(name="Kitchen"))
        target = dm.get_display_targets()[0]
        assert target.service_name == "Kitchen"

    def test_get_playing_targets_unaffected_by_display_authorized_marking(self):
        """Volume fan-out via get_playing_targets() must be unaffected by display marking."""
        dm._browser._handle_line(_av_add())
        target = dm.get_display_targets()[0]
        dm.mark_display_target_unauthorized(target)
        vol_targets = dm.get_playing_targets()
        assert len(vol_targets) == 1


# ---------------------------------------------------------------------------
# WP3: start/stop wrappers (plan section 6, tests 1-2)
# ---------------------------------------------------------------------------

class TestPlayingBrowserWrappers:
    def test_start_playing_browser_forwards_shutdown_event(self):
        """start_playing_browser() passes shutdown_event to the underlying browser."""
        import threading
        from unittest.mock import patch
        ev = threading.Event()
        with patch.object(dm._browser, "start") as mock_start:
            dm.start_playing_browser(shutdown_event=ev)
        mock_start.assert_called_once_with(shutdown_event=ev)

    def test_start_playing_browser_without_event_passes_none(self):
        """start_playing_browser() with no args passes shutdown_event=None."""
        from unittest.mock import patch
        with patch.object(dm._browser, "start") as mock_start:
            dm.start_playing_browser()
        mock_start.assert_called_once_with(shutdown_event=None)

    def test_stop_playing_browser_delegates_to_browser(self):
        """stop_playing_browser() calls stop() on the underlying browser exactly once."""
        from unittest.mock import patch
        with patch.object(dm._browser, "stop") as mock_stop:
            dm.stop_playing_browser()
        mock_stop.assert_called_once()
