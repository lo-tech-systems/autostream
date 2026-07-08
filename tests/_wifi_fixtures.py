"""Shared loading helpers and fixtures for the wifi_watcher test suite.

wifi_watcher.py runs as root on real hardware and pulls in Flask and
autostream_sysutils at import time. These helpers make both dependencies
offline-safe for tests: a purpose-built stub module is swapped into
sys.modules for the duration of the import and the real module (if any) is
restored afterwards, so a real flask or autostream_sysutils import elsewhere
in the session is never mutated.
"""
from __future__ import annotations

import contextlib
import importlib
import importlib.util
import sys
import threading
from contextlib import ExitStack, contextmanager
from dataclasses import fields
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
WIFI_WATCHER_PATH = REPO_ROOT / "platform" / "wifi_watcher.py"

# wifi_watcher imports its siblings (wifi_policy, wifi_web, ...) as plain
# top-level names, matching the flat layout the installers deploy into
# /opt/autostream, and pulls autostream_wifi_network in from core/ the same
# way. Both directories must be importable for that to work.
for _dir in (REPO_ROOT / "platform", REPO_ROOT / "core"):
    _p = str(_dir)
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _stub_flask_module() -> ModuleType:
    """Build a lightweight stand-in for the flask package.

    wifi_web binds these names at import time; the stub keeps that import
    side-effect-free so tests that only exercise the state machine don't pay
    for a real Flask app.
    """
    stub = ModuleType("flask")
    stub.Flask = lambda *a, **kw: MagicMock()
    stub.request = MagicMock()
    stub.jsonify = lambda d: MagicMock()
    stub.redirect = lambda u: MagicMock()
    stub.url_for = lambda *a, **kw: "/"
    stub.make_response = lambda h, s: MagicMock()
    return stub


def _stub_sysutils_module() -> ModuleType:
    """Build a lightweight stand-in for autostream_sysutils.

    wifi_watcher pulls run_cmd/prime_gateway/reboot_system/get_system_hostname
    in by name at import time, so the stub must be in place before it loads.
    """
    stub = ModuleType("autostream_sysutils")
    stub.run_cmd = MagicMock()
    stub.prime_gateway = MagicMock()
    stub.reboot_system = MagicMock()
    stub.get_system_hostname = MagicMock(return_value="autostream")
    return stub


@contextlib.contextmanager
def _stubbed_watcher_deps(*, real_flask: bool = False):
    """Swap flask/autostream_sysutils in sys.modules for one watcher import.

    autostream_sysutils is always replaced with a fresh stub. flask is
    replaced too unless *real_flask* is set, in which case whatever flask is
    already in sys.modules (real or absent) is left alone. Either way the
    swap restores the previous sys.modules entries afterwards instead of
    mutating attributes on a real module. wifi_web is dropped from
    sys.modules for the duration so it re-binds against whichever flask is
    active for this load.
    """
    overrides: dict[str, ModuleType] = {"autostream_sysutils": _stub_sysutils_module()}
    if not real_flask:
        overrides["flask"] = _stub_flask_module()

    saved = {name: sys.modules.get(name) for name in overrides}
    saved_wifi_web = sys.modules.get("wifi_web")
    for name, mod in overrides.items():
        sys.modules[name] = mod
    sys.modules.pop("wifi_web", None)
    try:
        yield
    finally:
        for name, orig in saved.items():
            if orig is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = orig
        if saved_wifi_web is None:
            sys.modules.pop("wifi_web", None)
        else:
            sys.modules["wifi_web"] = saved_wifi_web


def _load_watcher_module(alias: str, *, real_flask: bool = False) -> ModuleType:
    """Import wifi_watcher fresh under *alias*, with its dependencies stubbed."""
    sys.modules.pop(alias, None)
    with _stubbed_watcher_deps(real_flask=real_flask):
        if alias == "wifi_watcher":
            mod = importlib.import_module("wifi_watcher")
        else:
            spec = importlib.util.spec_from_file_location(alias, WIFI_WATCHER_PATH)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[alias] = mod
            spec.loader.exec_module(mod)
    return mod


_watcher_mod: ModuleType | None = None
_watcher_lock = threading.Lock()


def _get_watcher() -> ModuleType:
    """Return the wifi_watcher module, loaded once and shared for the session."""
    global _watcher_mod
    with _watcher_lock:
        if _watcher_mod is None:
            _watcher_mod = _load_watcher_module("wifi_watcher")
        return _watcher_mod


@pytest.fixture(autouse=True)
def _restore_root_log_level():
    """Save/restore the root logger level so log-level tests don't leak."""
    import logging as _logging
    saved = _logging.getLogger().level
    yield
    _logging.getLogger().setLevel(saved)


@pytest.fixture(autouse=True)
def _reset_activation_worker():
    """Reset the module-level activation-worker slots between tests."""
    mod = _get_watcher()
    yield
    try:
        while True:
            mod.wifi_activation._activation_job_queue.get_nowait()
    except Exception:
        pass
    mod.wifi_activation._activation_result_slot = None
    mod.wifi_activation.activation_result_event.clear()
    mod.wifi_activation.clear_inflight_activation_epoch()


@pytest.fixture(autouse=True)
def _isolate_reboot_guard(tmp_path):
    """Point the persistent reboot-guard stamp at a per-test temp file.

    Every reboot domain (gateway-down, 12-hour catch-all, dead-PHY) routes
    through request_guarded_reboot, which consults/writes the persistent
    guard, so any reboot-exercising test touches the stamp. Isolating it per
    test keeps the guard off the real /var path and prevents cross-test
    accumulation. Tests that need their own stamp path still patch
    DEAD_ADAPTER_REBOOT_STAMP locally (the inner patch wins).
    """
    mod = _get_watcher()
    stamp = str(tmp_path / "reboot-guard.json")
    fault = str(tmp_path / "adapter-fault-state.json")
    # Production paths read these through RECOVERY_CTX, which freezes the
    # real /var paths at construction. Patch both the module attributes (for
    # tests that pass the watcher module as ctx) and the context fields (for
    # tests that reach recovery via a production RECOVERY_CTX path) so
    # neither escapes to the real /var location.
    with patch.object(mod, "DEAD_ADAPTER_REBOOT_STAMP", stamp), \
         patch.object(mod, "ADAPTER_FAULT_STATE_PATH", fault), \
         patch.object(mod.RECOVERY_CTX, "DEAD_ADAPTER_REBOOT_STAMP", stamp), \
         patch.object(mod.RECOVERY_CTX, "ADAPTER_FAULT_STATE_PATH", fault):
        yield


@pytest.fixture()
def watcher():
    """Return the loaded wifi_watcher module and reset its state before each test."""
    mod = _get_watcher()
    # The mode default is supplied by the hub, not by NetworkMonitorState
    # (wifi_state does not import wifi_policy), so mirror it here.
    reset_pairs = [
        (mod.STATE, mod.NetworkMonitorState(mode=mod.wifi_policy.Mode.BOOT)),
        (mod.APPLY_STATE, mod.ApplyState()),
        (mod.CONTROL_STATE, mod.ControlState()),
        (mod.LOG_STATE, mod.LogLevelState()),
        (mod.RECOVERY_STATE, mod.wifi_recovery.RecoveryState()),
    ]

    def _reset():
        # Every state object must be reset in place, field by field, rather
        # than rebound (mod.STATE = ...): the module contexts (RECOVERY_CTX,
        # ACTIVATION_CTX, ...) captured the object references when they were
        # built, so replacing an object here would silently desync them from
        # the state the module driver mutates.
        for live, defaults in reset_pairs:
            for f in fields(defaults):
                setattr(live, f.name, getattr(defaults, f.name))

    _reset()
    mod._last_logged_values.clear()
    mod._last_throttled_log.clear()
    yield mod
    # Reset again in case the test mutated STATE
    _reset()


@pytest.fixture()
def flask_client(watcher):
    """Return a Flask test client for the wifi_watcher app.

    wifi_watcher creates a module-level `app` via Flask(). The shared
    `watcher` module stubs Flask, so a working test client needs a second,
    freshly loaded copy of the module with the real Flask package active. If
    Flask is not installed the tests are skipped.
    """
    try:
        from flask import Flask  # noqa: F401
    except ImportError:
        pytest.skip("Flask not installed — captive portal route tests skipped")

    flask_mod = _load_watcher_module("wifi_watcher_flask_test", real_flask=True)
    flask_mod.app.config["TESTING"] = True
    return flask_mod.app.test_client(), flask_mod


# ---------------------------------------------------------------------------
# Shared test-data builders and patch helpers used across several wifi test
# modules (adapter/facts construction, dead-PHY sysfs patching, the reset
# ledger, and a single-pass monitor-loop runner).
# ---------------------------------------------------------------------------

def _adapter(mod, ifname, mac, is_usb=False, is_builtin=False):
    return mod.wifi_net.WifiAdapter(
        ifname=ifname, permanent_mac=mac, current_mac=mac,
        is_builtin=is_builtin, is_usb=is_usb, managed=True,
        state="connected", description=ifname,
    )


def _facts_for(mod, adapters, active_client, *, wifi_cfg=True, wired_ok=False,
               wired_connected=False, now=1000.0):
    """Build a per-pass Facts snapshot for handler/apply tests."""
    return mod.Facts(
        wifi_configured=wifi_cfg, adapters=adapters, wired_connected=wired_connected,
        wired_ok=wired_ok, active_client=active_client, addresses={}, taken_at=now,
    )


@contextmanager
def _patch_dead_phy_facts(watcher, *, sysfs_names=(), usb_paths_ifaces=(),
                          link_down=True, healthy=False, sysfs_mac=""):
    """Patch the sysfs/NM facts the dead-PHY helpers consult."""
    def _usb_paths(ifname, sys_root="/sys/class/net"):
        if ifname in usb_paths_ifaces:
            return {"interface_id": "1-1.5:1.0", "driver": "rtl8xxxu",
                    "usb_device_path": "/sys/devices/usb1/1-1.5"}
        return None

    def _find_by_mac(mac, sys_root="/sys/class/net"):
        # Resolve the recorded MAC to its sysfs ifname (first faked netdev).
        if mac and sysfs_mac and mac == sysfs_mac and sysfs_names:
            return list(sysfs_names)[0]
        return ""

    with patch.object(watcher.wifi_net, "list_sysfs_netdevs",
                      return_value=list(sysfs_names)), \
         patch.object(watcher.wifi_net, "usb_sysfs_paths", side_effect=_usb_paths), \
         patch.object(watcher.wifi_net, "read_link_down", return_value=link_down), \
         patch.object(watcher.wifi_net, "find_sysfs_netdev_by_mac", side_effect=_find_by_mac), \
         patch.object(watcher.wifi_net, "_sys_read_mac", return_value=sysfs_mac), \
         patch.object(watcher, "is_wifi_client_healthy", return_value=healthy), \
         patch.object(watcher.RECOVERY_CTX, "is_wifi_client_healthy", return_value=healthy):
        yield


def _ledger(watcher, stable_id):
    return watcher.RECOVERY_STATE.adapter_reset_ledgers[stable_id]


def _spend_window_budget(watcher, stable_id, now=0.0):
    watcher.RECOVERY_STATE.adapter_reset_ledgers[stable_id] = {
        "recent_resets": [now, now],
        "total_resets": 2,
        "quarantined_until": None,
    }


def tmp_guard():
    """Return a unique temp path for a dead-PHY reboot guard file."""
    import tempfile
    return Path(tempfile.mkdtemp()) / "dead-phy-reboot.stamp"


def _run_monitor_once(
    watcher,
    *,
    now: float,
    wifi_cfg: bool = False,
    wired_connected: bool = False,
    wired_ok: bool = False,
    wifi_connected: bool = False,
    client_ok: bool = False,
    adapters: list | None = None,
    active_client=None,
    dead_recovery=None,
):
    """Run one monitor pass with external facts patched to deterministic values."""
    adapters = adapters if adapters is not None else []
    with ExitStack() as stack:
        stack.enter_context(patch("time.monotonic", return_value=now))
        stack.enter_context(patch.object(watcher.LOOP_CTX, "check_and_repair_avahi_hostname"))
        stack.enter_context(patch.object(watcher.LOOP_CTX, "maybe_reannounce_mdns"))
        stack.enter_context(patch.object(watcher.LOOP_CTX, "revert_expired_log_level"))
        stack.enter_context(patch.object(watcher, "is_wifi_configured", return_value=wifi_cfg))
        stack.enter_context(patch.object(watcher, "is_wired_connected", return_value=wired_connected))
        stack.enter_context(patch.object(watcher, "any_wired_path_healthy", return_value=wired_ok))
        stack.enter_context(patch.object(watcher.wifi_net, "discover_adapters", return_value=adapters))
        stack.enter_context(patch.object(watcher.wifi_net, "list_interface_addresses", return_value={}))
        stack.enter_context(patch.object(watcher.LOOP_CTX, "update_known_adapters"))
        stack.enter_context(patch.object(watcher.wifi_adoption, "resolve_active_client", return_value=active_client))
        stack.enter_context(patch.object(watcher.LOOP_CTX, "handle_usb_failure_fallback", return_value=False))
        stack.enter_context(patch.object(watcher.wifi_net, "is_wifi_connected", return_value=wifi_connected))
        stack.enter_context(patch.object(watcher, "is_wifi_client_healthy", return_value=client_ok))
        stack.enter_context(patch.object(watcher.LOOP_CTX, "handle_runtime_usb_adoption", return_value=False))
        if dead_recovery is None:
            dead_recovery = MagicMock(return_value=False)
        stack.enter_context(patch.object(watcher.LOOP_CTX, "escalate_dead_adapter_recovery", dead_recovery))
        stack.enter_context(patch.object(watcher.LOOP_CTX, "publish_network_status"))
        stack.enter_context(patch.object(watcher.LOOP_CTX, "log_on_change"))
        stack.enter_context(patch.object(watcher.wifi_loop, "step_boot_client_bringup",
                                          return_value=watcher.Verdict.CONTINUE))
        connect = stack.enter_context(patch.object(watcher.LOOP_CTX, "connect_to_configured_wifi"))
        watcher.network_monitor_loop(run_once=True)
        return connect


class _Clock:
    """Monotonic clock stub driven explicitly by the test."""
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt
