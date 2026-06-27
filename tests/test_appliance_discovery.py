"""Tests for autostream_appliances.py — mDNS peer discovery and conflict detection."""
from __future__ import annotations

import sys
import threading
import types
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)


# ---------------------------------------------------------------------------
# Module bootstrap: stub external deps and expose MdnsBrowser parse_fn
# ---------------------------------------------------------------------------

_LOCAL_ID = "a1b2c3d4e5f6a1b2c3d4"
_PEER_ID   = "b2c3d4e5f6a1b2c3d4e5"

def _load_module():
    """Reload autostream_appliances with stubs; return (module, parse_fn)."""
    rpi_stub = types.ModuleType("autostream_rpi")
    rpi_stub.get_appliance_id = lambda: _LOCAL_ID
    rpi_stub.get_dial_id = lambda: None

    captured = {}

    mdns_stub = types.ModuleType("autostream_mdns")

    class _CaptureBrowser:
        """Captures parse_fn so tests can call it directly."""
        def __init__(self, *, service_type, parse_fn, on_add, on_remove, on_change=None):
            captured["parse_fn"] = parse_fn
            captured["on_add"] = on_add
            captured["on_remove"] = on_remove
            captured["on_change"] = on_change
            self._by_key: dict = {}
            self._lock = threading.Lock()
            self._started = False

        def start(self):
            self._started = True

        def get_snapshot(self) -> dict:
            with self._lock:
                return dict(self._by_key)

        def scanner_ready(self) -> bool:
            return True

        def grace_remaining_ms(self) -> int:
            return 0

    mdns_stub.MdnsBrowser = _CaptureBrowser

    fed_stub = types.ModuleType("autostream_federation")
    fed_stub.evict_session_for_ip = lambda ip: None

    with patch.dict("sys.modules", {
        "autostream_rpi": rpi_stub,
        "autostream_mdns": mdns_stub,
        "autostream_federation": fed_stub,
    }):
        if "autostream_appliances" in sys.modules:
            del sys.modules["autostream_appliances"]
        import autostream_appliances as m

    # Clear conflict-detection state between test runs
    m._svc_info.clear()
    m._id_hostnames.clear()
    m._conflict_ids.clear()
    m._conflict_logged.clear()

    return m, captured["parse_fn"], captured["on_add"], captured["on_remove"], captured.get("on_change")


def _parts(service_name="AS._autostream._tcp.local", hostname="peer.local",
           ip="192.168.1.2", port=80):
    """Build a minimal `parts` list matching what _parse_appliance_event expects."""
    # parts[3]=service_name, parts[6]=hostname, parts[7]=ip, parts[8]=str(port)
    p = [""] * 9
    p[3] = service_name
    p[6] = hostname
    p[7] = ip
    p[8] = str(port)
    return p


def _txt(appliance_id=_PEER_ID, ui="v1", federation="v1", version="v1.0"):
    return {"id": appliance_id, "ui": ui, "federation": federation, "version": version}


# ---------------------------------------------------------------------------
# _parse_appliance_event
# ---------------------------------------------------------------------------

class TestParseApplianceEvent:
    def test_valid_peer_returns_sighting(self):
        m, parse_fn, *_ = _load_module()
        result = parse_fn(_parts(), _txt())
        assert result is not None
        key, sighting = result
        assert key == _PEER_ID
        assert sighting.hostname == "peer.local"
        assert sighting.version == "v1.0"

    def test_local_id_filtered(self):
        m, parse_fn, *_ = _load_module()
        result = parse_fn(_parts(), _txt(appliance_id=_LOCAL_ID))
        assert result is None

    def test_invalid_id_too_short(self):
        m, parse_fn, *_ = _load_module()
        result = parse_fn(_parts(), _txt(appliance_id="abc123"))
        assert result is None

    def test_invalid_id_uppercase(self):
        m, parse_fn, *_ = _load_module()
        result = parse_fn(_parts(), _txt(appliance_id="A1B2C3D4E5F6A1B2C3D4"))
        assert result is None

    def test_missing_ui_capability(self):
        m, parse_fn, *_ = _load_module()
        result = parse_fn(_parts(), _txt(ui=""))
        assert result is None

    def test_wrong_ui_version(self):
        m, parse_fn, *_ = _load_module()
        result = parse_fn(_parts(), _txt(ui="v2"))
        assert result is None

    def test_ui_v1_in_csv_accepted(self):
        m, parse_fn, *_ = _load_module()
        result = parse_fn(_parts(), _txt(ui="v1,v2"))
        assert result is not None

    def test_missing_federation_capability(self):
        m, parse_fn, *_ = _load_module()
        result = parse_fn(_parts(), _txt(federation=""))
        assert result is None

    def test_port_parsed_from_parts(self):
        m, parse_fn, *_ = _load_module()
        result = parse_fn(_parts(port=8080), _txt())
        assert result is not None
        _, sighting = result
        assert sighting.port == 8080

    def test_invalid_port_defaults_to_80(self):
        m, parse_fn, *_ = _load_module()
        p = _parts()
        p[8] = "notanumber"
        result = parse_fn(p, _txt())
        assert result is not None
        _, sighting = result
        assert sighting.port == 80


# ---------------------------------------------------------------------------
# Conflict detection
# ---------------------------------------------------------------------------

class TestConflictDetection:
    def test_same_id_different_hosts_causes_conflict(self):
        m, parse_fn, *_ = _load_module()

        # First service: one hostname
        r1 = parse_fn(
            _parts(service_name="SvcA._autostream._tcp.local",
                   hostname="host-a.local", ip="192.168.1.10"),
            _txt(appliance_id=_PEER_ID),
        )
        assert r1 is not None  # not yet conflicted

        # Second service: same ID, different hostname — conflict detected
        r2 = parse_fn(
            _parts(service_name="SvcB._autostream._tcp.local",
                   hostname="host-b.local", ip="192.168.1.11"),
            _txt(appliance_id=_PEER_ID),
        )
        # r2 is now returned (not None) so MdnsBrowser can track the five-tuple for removal.
        # The public APIs filter by _conflict_ids, so conflicted sightings remain hidden.
        assert r2 is not None
        assert _PEER_ID in m.get_conflict_ids()
        assert m.get_appliance_sighting(_PEER_ID) is None

    def test_same_id_same_host_multiple_ips_no_conflict(self):
        m, parse_fn, *_ = _load_module()

        r1 = parse_fn(
            _parts(service_name="SvcA._autostream._tcp.local",
                   hostname="host-a.local", ip="192.168.1.10"),
            _txt(appliance_id=_PEER_ID),
        )
        r2 = parse_fn(
            _parts(service_name="SvcB._autostream._tcp.local",
                   hostname="host-a.local", ip="192.168.1.11"),
            _txt(appliance_id=_PEER_ID),
        )
        assert r1 is not None
        assert r2 is not None
        assert _PEER_ID not in m.get_conflict_ids()
        assert m._id_hostnames[_PEER_ID] == {"host-a.local"}

    def test_conflict_ids_reported(self):
        m, parse_fn, *_ = _load_module()

        parse_fn(
            _parts(service_name="SvcA._autostream._tcp.local",
                   hostname="ha.local", ip="192.168.1.10"),
            _txt(appliance_id=_PEER_ID),
        )
        parse_fn(
            _parts(service_name="SvcB._autostream._tcp.local",
                   hostname="hb.local", ip="192.168.1.11"),
            _txt(appliance_id=_PEER_ID),
        )
        assert _PEER_ID in m.get_conflict_ids()

    def test_distinct_ids_no_conflict(self):
        m, parse_fn, *_ = _load_module()
        id_b = "c3d4e5f6a1b2c3d4e5f6"

        r1 = parse_fn(_parts(service_name="SvcA._autostream._tcp.local",
                             hostname="ha.local", ip="192.168.1.10"),
                      _txt(appliance_id=_PEER_ID))
        r2 = parse_fn(_parts(service_name="SvcB._autostream._tcp.local",
                             hostname="hb.local", ip="192.168.1.11"),
                      _txt(appliance_id=id_b))
        assert r1 is not None
        assert r2 is not None

    def test_conflict_cleared_after_on_appliance_remove(self):
        """on_appliance_remove must fully clear _svc_info and conflict state."""
        m, parse_fn, _, on_remove, _ = _load_module()

        # Register first sighting (no conflict yet)
        r1 = parse_fn(
            _parts(service_name="SvcA._autostream._tcp.local",
                   hostname="ha.local", ip="192.168.1.10"),
            _txt(appliance_id=_PEER_ID),
        )
        assert r1 is not None
        # Trigger conflict: second service claims the same ID
        parse_fn(
            _parts(service_name="SvcB._autostream._tcp.local",
                   hostname="hb.local", ip="192.168.1.11"),
            _txt(appliance_id=_PEER_ID),
        )
        assert _PEER_ID in m.get_conflict_ids()
        assert "SvcB._autostream._tcp.local" in m._svc_info

        # Simulate browser calling on_remove when the last tracked sighting is gone
        _, sighting1 = r1
        on_remove(_PEER_ID, sighting1)

        assert _PEER_ID not in m.get_conflict_ids()
        assert _PEER_ID not in m._id_hostnames
        # Both service names must be evicted from _svc_info
        assert "SvcA._autostream._tcp.local" not in m._svc_info
        assert "SvcB._autostream._tcp.local" not in m._svc_info

    def test_on_change_resolves_conflict_when_one_sighting_disappears(self):
        """on_change must resolve conflict when one of the two conflicting sightings is removed."""
        m, parse_fn, _, on_remove, on_change = _load_module()

        r1 = parse_fn(
            _parts(service_name="SvcA._autostream._tcp.local",
                   hostname="ha.local", ip="192.168.1.10"),
            _txt(appliance_id=_PEER_ID),
        )
        r2 = parse_fn(
            _parts(service_name="SvcB._autostream._tcp.local",
                   hostname="hb.local", ip="192.168.1.11"),
            _txt(appliance_id=_PEER_ID),
        )
        assert _PEER_ID in m.get_conflict_ids()
        assert r1 is not None
        assert r2 is not None

        # Simulate MdnsBrowser firing on_change when SvcB is removed but SvcA remains
        _, sighting2 = r2
        _, sighting1 = r1
        on_change(_PEER_ID, sighting2, sighting1)

        # Conflict must be resolved
        assert _PEER_ID not in m.get_conflict_ids()
        # SvcB's svc_info entry must be removed
        assert "SvcB._autostream._tcp.local" not in m._svc_info
        # SvcA's svc_info entry must still be present
        assert "SvcA._autostream._tcp.local" in m._svc_info
        # Hostname conflict tracking must have only one entry now
        assert m._id_hostnames.get(_PEER_ID) == {"ha.local"}

    def test_on_change_keeps_same_hostname_multi_homed_non_conflicted(self):
        m, parse_fn, _, on_remove, on_change = _load_module()

        r1 = parse_fn(
            _parts(service_name="SvcA._autostream._tcp.local",
                   hostname="ha.local", ip="192.168.1.10"),
            _txt(appliance_id=_PEER_ID),
        )
        r2 = parse_fn(
            _parts(service_name="SvcB._autostream._tcp.local",
                   hostname="ha.local", ip="192.168.1.11"),
            _txt(appliance_id=_PEER_ID),
        )
        assert r1 is not None
        assert r2 is not None
        assert _PEER_ID not in m.get_conflict_ids()

        _, sighting1 = r1
        _, sighting2 = r2
        on_change(_PEER_ID, sighting2, sighting1)

        assert _PEER_ID not in m.get_conflict_ids()
        assert "SvcA._autostream._tcp.local" in m._svc_info
        assert "SvcB._autostream._tcp.local" not in m._svc_info
        assert m._id_hostnames.get(_PEER_ID) == {"ha.local"}

    def test_on_remove_clears_svc_info_entry(self):
        """on_appliance_remove removes _svc_info entries for the appliance."""
        m, parse_fn, _, on_remove, _ = _load_module()

        r1 = parse_fn(
            _parts(service_name="SvcA._autostream._tcp.local",
                   hostname="ha.local", ip="192.168.1.10"),
            _txt(appliance_id=_PEER_ID),
        )
        assert "SvcA._autostream._tcp.local" in m._svc_info
        _, sighting1 = r1
        on_remove(_PEER_ID, sighting1)
        assert "SvcA._autostream._tcp.local" not in m._svc_info


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class TestPublicAPI:
    def test_get_all_appliances_sorted_by_hostname(self):
        m, parse_fn, on_add, on_remove, _ = _load_module()
        id_a = "aa00000000000000000a"
        id_b = "bb00000000000000000b"

        r_z = parse_fn(_parts(service_name="Z", hostname="zebra.local", ip="10.0.0.1"),
                       _txt(appliance_id=id_a))
        r_a = parse_fn(_parts(service_name="A", hostname="apple.local", ip="10.0.0.2"),
                       _txt(appliance_id=id_b))

        # Inject into browser snapshot manually
        with m._browser._lock:
            if r_z:
                m._browser._by_key[r_z[0]] = r_z[1]
            if r_a:
                m._browser._by_key[r_a[0]] = r_a[1]

        all_sightings = m.get_all_appliances()
        hostnames = [s.hostname for s in all_sightings]
        assert hostnames == sorted(hostnames, key=str.lower)

    def test_get_appliance_sighting_unknown_returns_none(self):
        m, *_ = _load_module()
        assert m.get_appliance_sighting("0000000000000000dead") is None

    def test_get_appliance_sighting_conflicted_returns_none(self):
        """get_appliance_sighting must return None for a conflicted ID."""
        m, parse_fn, _, on_remove, _ = _load_module()

        r1 = parse_fn(
            _parts(service_name="SvcA._autostream._tcp.local",
                   hostname="ha.local", ip="192.168.1.10"),
            _txt(appliance_id=_PEER_ID),
        )
        assert r1 is not None
        # Manually put the first sighting into the browser snapshot to simulate it having
        # been registered before the second conflicting sighting arrived
        _, sighting1 = r1
        with m._browser._lock:
            m._browser._by_key[_PEER_ID] = sighting1

        # Trigger conflict via second service
        parse_fn(
            _parts(service_name="SvcB._autostream._tcp.local",
                   hostname="hb.local", ip="192.168.1.11"),
            _txt(appliance_id=_PEER_ID),
        )
        assert _PEER_ID in m.get_conflict_ids()
        # Even though browser has the first sighting, get_appliance_sighting must return None
        assert m.get_appliance_sighting(_PEER_ID) is None

    def test_get_all_appliances_excludes_conflicted(self):
        """get_all_appliances must not return sightings for conflicted IDs."""
        m, parse_fn, _, on_remove, _ = _load_module()

        r1 = parse_fn(
            _parts(service_name="SvcA._autostream._tcp.local",
                   hostname="ha.local", ip="192.168.1.10"),
            _txt(appliance_id=_PEER_ID),
        )
        assert r1 is not None
        _, sighting1 = r1
        with m._browser._lock:
            m._browser._by_key[_PEER_ID] = sighting1

        parse_fn(
            _parts(service_name="SvcB._autostream._tcp.local",
                   hostname="hb.local", ip="192.168.1.11"),
            _txt(appliance_id=_PEER_ID),
        )
        assert _PEER_ID in m.get_conflict_ids()
        assert m.get_all_appliances() == []

    def test_scanner_ready_returns_bool(self):
        m, *_ = _load_module()
        assert isinstance(m.scanner_ready(), bool)

    def test_grace_remaining_ms_returns_int(self):
        m, *_ = _load_module()
        assert isinstance(m.grace_remaining_ms(), int)
