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

import dial_auth
import dial_mdns as dm
from autostream_mdns import parse_avahi_txt

_VALID_ID = "a" * 20


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

    def test_id_txt_parsed_into_appliance_id(self):
        dm._browser._handle_line(_av_add(txt=f"dial_api=v1 id={_VALID_ID}"))
        targets = dm.get_playing_targets()
        assert targets[0].appliance_id == _VALID_ID

    def test_id_txt_absent_gives_empty_appliance_id(self):
        dm._browser._handle_line(_av_add())
        targets = dm.get_playing_targets()
        assert targets[0].appliance_id == ""

    def test_malformed_id_txt_gives_empty_appliance_id(self):
        dm._browser._handle_line(_av_add(txt="dial_api=v1 id=not-hex-at-all-nope"))
        targets = dm.get_playing_targets()
        assert targets[0].appliance_id == ""

    def test_short_id_txt_gives_empty_appliance_id(self):
        dm._browser._handle_line(_av_add(txt="dial_api=v1 id=abc123"))
        targets = dm.get_playing_targets()
        assert targets[0].appliance_id == ""


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
# playing_since / display_authorized registry and get_display_targets()
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

    def test_removal_clears_target_state(self):
        dm._browser._handle_line(_av_add())
        dm._browser._handle_line(_av_remove())
        assert dm._target_state == {}

    def test_reappear_after_removal_starts_fresh(self):
        dm._browser._handle_line(_av_add())
        target = dm.get_display_targets()[0]
        first_since = target.playing_since
        dm._browser._handle_line(_av_remove())
        time.sleep(0.005)
        dm._browser._handle_line(_av_add())
        targets = dm.get_display_targets()
        assert targets[0].playing_since > first_since

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


# ---------------------------------------------------------------------------
# appliance_id identity and the dial_auth-backed `auth` field.
# ---------------------------------------------------------------------------

class TestApplianceIdAndAuth:
    def setup_method(self):
        _clear()

    def test_sighting_creates_unknown_auth_entry(self):
        dm._browser._handle_line(_av_add(txt=f"dial_api=v1 id={_VALID_ID}"))
        assert dial_auth.auth_map.state(_VALID_ID) == dial_auth.AUTH_UNKNOWN

    def test_get_playing_targets_stamps_auth_from_map(self):
        dm._browser._handle_line(_av_add(txt=f"dial_api=v1 id={_VALID_ID}"))
        dial_auth.auth_map.apply(_VALID_ID, dial_auth.OUTCOME_AUTHORIZED, _VALID_ID, time.monotonic())
        targets = dm.get_playing_targets()
        assert targets[0].auth == dial_auth.AUTH_AUTHORIZED

    def test_get_display_targets_stamps_auth_from_map(self):
        dm._browser._handle_line(_av_add(txt=f"dial_api=v1 id={_VALID_ID}"))
        dial_auth.auth_map.apply(_VALID_ID, dial_auth.OUTCOME_UNAUTHORIZED, _VALID_ID, time.monotonic())
        targets = dm.get_display_targets()
        assert targets[0].auth == dial_auth.AUTH_UNAUTHORIZED

    def test_address_change_resets_auth_to_unknown(self):
        dm._browser._handle_line(_av_add(ip="10.0.0.1", txt=f"dial_api=v1 id={_VALID_ID}"))
        dial_auth.auth_map.apply(_VALID_ID, dial_auth.OUTCOME_AUTHORIZED, _VALID_ID, time.monotonic())
        assert dial_auth.auth_map.state(_VALID_ID) == dial_auth.AUTH_AUTHORIZED

        dm._browser._handle_line(_av_add(ip="10.0.0.2", txt=f"dial_api=v1 id={_VALID_ID}"))
        assert dial_auth.auth_map.state(_VALID_ID) == dial_auth.AUTH_UNKNOWN

    def test_raising_map_read_degrades_to_unknown(self):
        dm._browser._handle_line(_av_add(txt=f"dial_api=v1 id={_VALID_ID}"))
        with patch.object(dial_auth.auth_map, "state", side_effect=RuntimeError("boom")):
            targets = dm.get_playing_targets()
        assert targets[0].auth == dial_auth.AUTH_UNKNOWN

    def test_identityless_target_always_unknown(self):
        dm._browser._handle_line(_av_add())  # no id= — identity-less appliance
        dial_auth.auth_map.apply(_VALID_ID, dial_auth.OUTCOME_AUTHORIZED, _VALID_ID, time.monotonic())
        targets = dm.get_playing_targets()
        assert targets[0].auth == dial_auth.AUTH_UNKNOWN

    def test_get_playing_targets_unaffected_by_authorization_state(self):
        """Volume fan-out via get_playing_targets() must include a row regardless
        of its auth state — filtering is the caller's job, not this module's."""
        dm._browser._handle_line(_av_add(txt=f"dial_api=v1 id={_VALID_ID}"))
        dial_auth.auth_map.apply(_VALID_ID, dial_auth.OUTCOME_UNAUTHORIZED, _VALID_ID, time.monotonic())
        vol_targets = dm.get_playing_targets()
        assert len(vol_targets) == 1


# ---------------------------------------------------------------------------
# appliance_display_name()
# ---------------------------------------------------------------------------

class TestApplianceDisplayName:
    # avahi-browse -p delivers the instance name with spaces escaped as \032,
    # so these use the real on-the-wire form, not pre-spaced strings.
    def test_strips_escaped_service_prefix_and_replaces_underscores(self):
        assert dm.appliance_display_name("autostream\\032on\\032CD_Player") == "CD Player"

    def test_escaped_hostname_without_underscores_unchanged(self):
        assert dm.appliance_display_name("autostream\\032on\\032Turntable") == "Turntable"

    def test_already_unescaped_name_also_works(self):
        assert dm.appliance_display_name("autostream on Hallway") == "Hallway"

    def test_name_without_prefix_still_replaces_underscores(self):
        assert dm.appliance_display_name("Some_Other_Name") == "Some Other Name"


# ---------------------------------------------------------------------------
# Start/stop wrappers (plan section 6, tests 1-2)
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


# ---------------------------------------------------------------------------
# The _autostream._tcp general browser.
# ---------------------------------------------------------------------------

_VALID_ID2 = "b" * 20


def _gen_add(iface="eth0", proto="IPv4", name="My-Appliance",
             svc_type="_autostream._tcp", domain="local",
             host="myappliance.local", ip="192.168.1.10",
             port="80", txt=f"id={_VALID_ID} dial_api=v1") -> str:
    """Build an avahi-browse add event line for the general browser."""
    return f"=;{iface};{proto};{name};{svc_type};{domain};{host};{ip};{port};{txt}"


def _gen_remove(iface="eth0", proto="IPv4", name="My-Appliance",
                svc_type="_autostream._tcp", domain="local") -> str:
    """Build an avahi-browse remove event line for the general browser."""
    return f"-;{iface};{proto};{name};{svc_type};{domain}"


def _clear_general():
    with dm._general_browser._lock:
        dm._general_browser._by_key.clear()
        dm._general_browser._by_identity.clear()
    with dm._general_lock:
        dm._general_svc.clear()
        dm._general_conflicts.clear()


class TestGeneralBrowserParsing:
    def setup_method(self):
        _clear_general()

    def test_requires_dial_api_v1(self):
        dm._general_browser._handle_line(_gen_add(txt=f"id={_VALID_ID}"))
        assert dm._general_browser.get_snapshot() == {}

    def test_wrong_dial_api_version_ignored(self):
        dm._general_browser._handle_line(_gen_add(txt=f"id={_VALID_ID} dial_api=v2"))
        assert dm._general_browser.get_snapshot() == {}

    def test_requires_valid_id(self):
        dm._general_browser._handle_line(_gen_add(txt="dial_api=v1"))
        assert dm._general_browser.get_snapshot() == {}

    def test_malformed_id_ignored(self):
        dm._general_browser._handle_line(_gen_add(txt="dial_api=v1 id=not-hex-at-all"))
        assert dm._general_browser.get_snapshot() == {}

    def test_ui_and_federation_flags_not_required(self):
        """ui/federation are appliance-to-appliance capabilities the dial has
        no use for — their absence must not exclude an otherwise-valid row."""
        dm._general_browser._handle_line(_gen_add(txt=f"id={_VALID_ID} dial_api=v1"))
        assert _VALID_ID in dm._general_browser.get_snapshot()

    def test_control_flag_does_not_gate_the_general_browser(self):
        """Dials are gated by per-dial authorization only, never the peer-
        control setting — control=off must not exclude the row."""
        dm._general_browser._handle_line(
            _gen_add(txt=f"id={_VALID_ID} dial_api=v1 control=off"))
        assert _VALID_ID in dm._general_browser.get_snapshot()

    def test_repeat_v1_sets_repeat_true(self):
        dm._general_browser._handle_line(
            _gen_add(txt=f"id={_VALID_ID} dial_api=v1 repeat=v1"))
        assert dm._general_browser.get_snapshot()[_VALID_ID].repeat is True

    def test_repeat_absent_sets_repeat_false(self):
        dm._general_browser._handle_line(_gen_add(txt=f"id={_VALID_ID} dial_api=v1"))
        assert dm._general_browser.get_snapshot()[_VALID_ID].repeat is False

    def test_valid_entry_fields_parsed(self):
        dm._general_browser._handle_line(_gen_add(
            name="Kitchen", host="kitchen.local", ip="10.0.0.5", port="8080",
            txt=f"id={_VALID_ID} dial_api=v1 version=1.2.3",
        ))
        g = dm._general_browser.get_snapshot()[_VALID_ID]
        assert g.appliance_id == _VALID_ID
        assert g.service_name == "Kitchen"
        assert g.hostname == "kitchen.local"
        assert g.ip == "10.0.0.5"
        assert g.port == 8080
        assert g.version == "1.2.3"

    def test_invalid_port_defaults_to_80(self):
        dm._general_browser._handle_line(
            _gen_add(port="notaport", txt=f"id={_VALID_ID} dial_api=v1"))
        assert dm._general_browser.get_snapshot()[_VALID_ID].port == 80

    def test_never_calls_note_sighting_directly(self):
        """The general parser must never touch dial_auth — get_roster() is
        the single feeder for general sightings."""
        dial_auth.auth_map.reset()
        dm._general_browser._handle_line(_gen_add(txt=f"id={_VALID_ID} dial_api=v1"))
        assert dial_auth.auth_map.states() == {}


class TestGeneralBrowserConflict:
    """Exercises the conflict bookkeeping (_general_svc/_general_conflicts)
    directly at the parser and callback level — the same strategy
    tests/test_appliance_discovery.py uses for the mirrored appliance-side
    registry, and for the same reason: the real MdnsBrowser dedupes
    _by_identity by identity_key (appliance_id here), so two DIFFERENT
    service names sharing one id collapse to whichever was seen last, and
    firing that collapse's on_change through _handle_line() end-to-end
    would immediately self-resolve the very conflict it just raised. That
    interaction is inherited unchanged from autostream_appliances.py."""

    def setup_method(self):
        _clear_general()

    def _parts(self, service_name="SvcA", hostname="host-a.local",
               ip="10.0.0.1", port="80"):
        p = [""] * 9
        p[3] = service_name
        p[6] = hostname
        p[7] = ip
        p[8] = port
        return p

    def test_same_id_different_hostnames_causes_conflict(self):
        r1 = dm._parse_general_event(
            self._parts(service_name="SvcA", hostname="host-a.local"),
            {"id": _VALID_ID, "dial_api": "v1"})
        assert r1 is not None
        r2 = dm._parse_general_event(
            self._parts(service_name="SvcB", hostname="host-b.local"),
            {"id": _VALID_ID, "dial_api": "v1"})
        assert r2 is not None
        assert _VALID_ID in dm._general_conflicts

    def test_same_id_same_hostname_multiple_ips_no_conflict(self):
        dm._parse_general_event(
            self._parts(service_name="SvcA", hostname="host-a.local", ip="10.0.0.1"),
            {"id": _VALID_ID, "dial_api": "v1"})
        dm._parse_general_event(
            self._parts(service_name="SvcB", hostname="host-a.local", ip="10.0.0.2"),
            {"id": _VALID_ID, "dial_api": "v1"})
        assert _VALID_ID not in dm._general_conflicts

    def test_distinct_ids_no_conflict(self):
        dm._parse_general_event(
            self._parts(service_name="SvcA", hostname="host-a.local"),
            {"id": _VALID_ID, "dial_api": "v1"})
        dm._parse_general_event(
            self._parts(service_name="SvcB", hostname="host-b.local"),
            {"id": _VALID_ID2, "dial_api": "v1"})
        assert dm._general_conflicts == set()

    def test_on_general_change_resolves_conflict_when_one_side_removed(self):
        sighting_a = dm.GeneralSighting(_VALID_ID, "SvcA", "host-a.local",
                                         "10.0.0.1", 80, "", False)
        sighting_b = dm.GeneralSighting(_VALID_ID, "SvcB", "host-b.local",
                                         "10.0.0.2", 80, "", False)
        dm._general_svc["SvcA"] = (_VALID_ID, "host-a.local")
        dm._general_svc["SvcB"] = (_VALID_ID, "host-b.local")
        dm._general_conflicts.add(_VALID_ID)
        dm._on_general_change(_VALID_ID, sighting_a, sighting_b)
        assert _VALID_ID not in dm._general_conflicts
        assert "SvcA" not in dm._general_svc

    def test_on_general_remove_clears_all_state_for_id(self):
        dm._general_svc["SvcA"] = (_VALID_ID, "host-a.local")
        dm._general_svc["SvcB"] = (_VALID_ID, "host-b.local")
        dm._general_conflicts.add(_VALID_ID)
        dm._on_general_remove(_VALID_ID, None)
        assert dm._general_svc == {}
        assert _VALID_ID not in dm._general_conflicts


# ---------------------------------------------------------------------------
# get_roster(): the merged playing + general view and its single feeder.
# ---------------------------------------------------------------------------

class TestGetRoster:
    def setup_method(self):
        _clear()
        _clear_general()
        dial_auth.auth_map.reset()

    def _add_playing(self, name="Kitchen", ip="10.0.0.1", port=80, appliance_id=""):
        txt = "dial_api=v1 dial_status=v1"
        if appliance_id:
            txt += f" id={appliance_id}"
        dm._browser._handle_line(_av_add(name=name, ip=ip, port=str(port), txt=txt))

    def _add_general(self, name="Kitchen", host="kitchen.local", ip="10.0.0.1",
                      port=80, appliance_id=_VALID_ID, repeat=False):
        txt = f"id={appliance_id} dial_api=v1"
        if repeat:
            txt += " repeat=v1"
        dm._general_browser._handle_line(
            _gen_add(name=name, host=host, ip=ip, port=str(port), txt=txt))

    def test_playing_only_target_rostered(self):
        self._add_playing(appliance_id=_VALID_ID)
        roster = dm.get_roster()
        assert len(roster) == 1
        assert roster[0].appliance_id == _VALID_ID
        assert roster[0].playing is True
        assert roster[0].repeat_capable is False

    def test_general_only_target_rostered_and_feeds_note_sighting(self):
        self._add_general(appliance_id=_VALID_ID, ip="10.0.0.9", port=9999)
        roster = dm.get_roster()
        assert len(roster) == 1
        assert roster[0].appliance_id == _VALID_ID
        assert roster[0].playing is False
        assert _VALID_ID in dial_auth.auth_map.states()

    def test_identityless_playing_target_never_rostered(self):
        self._add_playing(appliance_id="")
        assert dm.get_roster() == []

    def test_conflicted_general_sighting_excluded(self):
        self._add_general(appliance_id=_VALID_ID, ip="10.0.0.1", port=80)
        with dm._general_lock:
            dm._general_conflicts.add(_VALID_ID)
        assert dm.get_roster() == []

    def test_repeat_capable_merged_onto_playing_entry(self):
        self._add_playing(appliance_id=_VALID_ID, ip="10.0.0.1", port=80)
        self._add_general(appliance_id=_VALID_ID, ip="10.0.0.1", port=80, repeat=True)
        roster = dm.get_roster()
        assert len(roster) == 1
        assert roster[0].repeat_capable is True

    def test_playing_address_is_canonical_and_general_never_refeeds_it(self):
        """The playing sighting is the canonical (ip, port) for an id present
        in both sets; get_roster() must not call note_sighting a second time
        for the same id from the general side — the auth map cannot flap."""
        self._add_playing(appliance_id=_VALID_ID, ip="10.0.0.1", port=100)
        self._add_general(appliance_id=_VALID_ID, ip="10.0.0.2", port=200)
        with patch.object(dial_auth.auth_map, "note_sighting") as mock_note:
            roster = dm.get_roster()
        mock_note.assert_not_called()
        assert roster[0].ip == "10.0.0.1"
        assert roster[0].port == 100

    def test_single_feeder_no_flap_when_id_starts_playing(self):
        """A general-only sighting feeds note_sighting; once the same id
        starts playing (fed directly by the playing parser), get_roster()
        must stop feeding the general address for it — the map never
        alternates between the two addresses for one id."""
        self._add_general(appliance_id=_VALID_ID, ip="10.0.0.9", port=9999)
        dm.get_roster()
        assert dial_auth.auth_map.state(_VALID_ID) == dial_auth.AUTH_UNKNOWN

        self._add_playing(appliance_id=_VALID_ID, ip="10.0.0.1", port=80)
        with patch.object(dial_auth.auth_map, "note_sighting") as mock_note:
            dm.get_roster()
        mock_note.assert_not_called()

    def test_get_playing_and_display_targets_unaffected_by_roster(self):
        self._add_playing(appliance_id=_VALID_ID)
        self._add_general(appliance_id=_VALID_ID2, ip="10.0.0.50", port=1234)
        before_playing = dm.get_playing_targets()
        before_display = dm.get_display_targets()
        dm.get_roster()
        assert dm.get_playing_targets() == before_playing
        assert dm.get_display_targets() == before_display

    def test_sort_order_playing_rows_before_idle_rows(self):
        self._add_general(name="Zeta", host="zeta.local",
                           appliance_id="d" * 20, ip="10.0.1.1")
        self._add_playing(name="Alpha", appliance_id="e" * 20, ip="10.0.2.1")
        roster = dm.get_roster()
        assert [r.playing for r in roster] == [True, False]


# ---------------------------------------------------------------------------
# Start/stop wrappers for the general browser.
# ---------------------------------------------------------------------------

class TestGeneralBrowserWrappers:
    def test_start_general_browser_forwards_shutdown_event(self):
        import threading
        ev = threading.Event()
        with patch.object(dm._general_browser, "start") as mock_start:
            dm.start_general_browser(shutdown_event=ev)
        mock_start.assert_called_once_with(shutdown_event=ev)

    def test_start_general_browser_without_event_passes_none(self):
        with patch.object(dm._general_browser, "start") as mock_start:
            dm.start_general_browser()
        mock_start.assert_called_once_with(shutdown_event=None)

    def test_stop_general_browser_delegates_to_browser(self):
        with patch.object(dm._general_browser, "stop") as mock_stop:
            dm.stop_general_browser()
        mock_stop.assert_called_once()
