"""Tests for autostream_appliances.py — reconcile_appliance_announcement."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_module():
    """Import autostream_appliances with external dependencies stubbed out.

    Uses explicit sys.modules manipulation so the returned module stays
    registered in sys.modules — required for patch("autostream_appliances.*")
    to resolve correctly in test bodies.
    """
    import types

    # Stub autostream_rpi
    rpi_stub = types.ModuleType("autostream_rpi")
    rpi_stub.get_appliance_id = lambda: "a1b2c3d4e5f6a1b2c3d4"
    rpi_stub.get_dial_id = lambda: None

    # Stub autostream_mdns
    mdns_stub = types.ModuleType("autostream_mdns")

    class _FakeBrowser:
        def __init__(self, **kwargs):
            self._kwargs = kwargs
            self._started = False
        def start(self, shutdown_event=None): self._started = True
        def stop(self): pass
        def get_snapshot(self): return {}
        def scanner_ready(self): return True
        def grace_remaining_ms(self): return 0

    mdns_stub.MdnsBrowser = _FakeBrowser

    # Save originals
    orig_rpi  = sys.modules.get("autostream_rpi")
    orig_mdns = sys.modules.get("autostream_mdns")

    # Install stubs and force-reimport
    sys.modules["autostream_rpi"]  = rpi_stub
    sys.modules["autostream_mdns"] = mdns_stub
    sys.modules.pop("autostream_appliances", None)
    try:
        import autostream_appliances as m
    finally:
        # Restore stub entries; leave autostream_appliances pointing to m
        if orig_rpi is None:
            sys.modules.pop("autostream_rpi", None)
        else:
            sys.modules["autostream_rpi"] = orig_rpi
        if orig_mdns is None:
            sys.modules.pop("autostream_mdns", None)
        else:
            sys.modules["autostream_mdns"] = orig_mdns
    return m


# ---------------------------------------------------------------------------
# reconcile_appliance_announcement
# ---------------------------------------------------------------------------

class TestReconcileApplianceAnnouncement:
    def test_advertise_true_calls_write_service(self):
        m = _make_module()
        calls = []
        def fake_run(cmd, **kw):
            r = MagicMock()
            r.returncode = 0
            calls.append(cmd)
            return r

        with patch("autostream_appliances._run_admin", side_effect=lambda args: (calls.append(args), 0)[1]):
            ok = m.reconcile_appliance_announcement("v1.0", True)

        assert ok is True
        assert any("write-appliance-service" in " ".join(a) for a in calls)

    def test_advertise_false_calls_remove_service(self):
        m = _make_module()
        calls = []

        with patch("autostream_appliances._run_admin", side_effect=lambda args: (calls.append(args), 0)[1]):
            ok = m.reconcile_appliance_announcement("v1.0", False)

        assert ok is True
        assert any("remove-appliance-service" in " ".join(a) for a in calls)

    def test_admin_failure_returns_false(self):
        m = _make_module()

        with patch("autostream_appliances._run_admin", return_value=1):
            ok = m.reconcile_appliance_announcement("v1.0", True)

        assert ok is False

    def test_no_local_id_advertise_true_calls_remove(self):
        """When local identity unavailable and advertise=True, remove-service is called."""
        m = _make_module()
        import autostream_rpi
        calls = []

        with patch("autostream_appliances.get_appliance_id", return_value=None), \
             patch("autostream_appliances._run_admin", side_effect=lambda args: (calls.append(args), 0)[1]):
            ok = m.reconcile_appliance_announcement("v1.0", True)

        assert ok is True
        assert any("remove-appliance-service" in " ".join(a) for a in calls)

    def test_no_local_id_advertise_false_calls_remove(self):
        m = _make_module()
        calls = []

        with patch("autostream_appliances.get_appliance_id", return_value=None), \
             patch("autostream_appliances._run_admin", side_effect=lambda args: (calls.append(args), 0)[1]):
            ok = m.reconcile_appliance_announcement("v1.0", False)

        assert ok is True
        assert any("remove-appliance-service" in " ".join(a) for a in calls)

    def test_version_passed_to_write_service(self):
        m = _make_module()
        calls = []

        with patch("autostream_appliances._run_admin", side_effect=lambda args: (calls.append(list(args)), 0)[1]):
            m.reconcile_appliance_announcement("v2.5.1", True)

        write_calls = [a for a in calls if a and a[0] == "write-appliance-service"]
        assert write_calls, "write-appliance-service not called"
        assert "v2.5.1" in write_calls[0]

    def test_none_version_becomes_unknown(self):
        m = _make_module()
        calls = []

        with patch("autostream_appliances._run_admin", side_effect=lambda args: (calls.append(list(args)), 0)[1]):
            m.reconcile_appliance_announcement(None, True)

        write_calls = [a for a in calls if a and a[0] == "write-appliance-service"]
        assert write_calls
        assert "unknown" in write_calls[0]


# ---------------------------------------------------------------------------
# start_appliance_scanner
# ---------------------------------------------------------------------------

class TestStartApplianceScanner:
    def test_start_with_local_id_starts_browser(self):
        m = _make_module()
        with patch("autostream_appliances.get_appliance_id", return_value="a1b2c3d4e5f6a1b2c3d4"):
            m.start_appliance_scanner()
        assert m._browser._started

    def test_start_without_local_id_noop(self):
        m = _make_module()
        with patch("autostream_appliances.get_appliance_id", return_value=None):
            m.start_appliance_scanner()
        assert not m._browser._started
