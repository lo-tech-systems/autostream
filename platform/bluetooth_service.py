#!/usr/bin/python3
"""bluetooth_service.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

Entry point / main loop / thread orchestration for the autostream_bluetooth
daemon. Runs on the system Python as the unprivileged ``autostream`` user
(groups ``bluetooth``,
``audio``). Single process, three threads: GLib main loop (D-Bus, and the
pairing window's timers via a
``GLib.timeout_add_seconds`` tick), the control-socket server, and the
loopback pump. ``bluetooth_loop.LoopBridge`` is the one point where a call
crosses from another thread onto the loop thread.

Follows wifi_watcher.py's module-layout conventions: this module composes
the pieces, owns persistence and startup wiring, turns D-Bus signals into
machine events and runs the actions the machines return. Each sibling has
one job: ``bluetooth_window.py`` the pairing window machine,
``bluetooth_devices.py`` its device list, ``bluetooth_agent.py`` the pairing
accept/refuse policy, ``bluetooth_adapter_mode.py`` the adapter's
discoverable/pairable writes, ``bluetooth_commands.py`` the multi-step BlueZ
ops, ``bluetooth_bluez.py`` the one place that talks to BlueZ,
``bluetooth_pump.py`` the loopback feeder and its audio source machine, and
``bluetooth_socket.py`` the control-socket protocol. Every sibling module is
deployed flat beside this one (matching wifi_*.py); none of them import
this module, so the dependency direction is strictly hub-to-spoke.

``import dbus`` / ``from gi.repository import GLib`` / ``import alsaaudio``
are all lazy — performed only inside ``main()`` / the sibling modules' own
lazy import points — so this module (and the state machine it defines) is
importable, and independently testable, on systems without the Bluetooth
stack (dev machines, the WSL test runner).
"""
from __future__ import annotations

import json
import logging
import os
import signal
import socket
import sys
import tempfile
import time
from typing import Callable, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import bluetooth_bluez as bluez_mod
import bluetooth_adapter_mode as mode_mod
import bluetooth_agent as agent_mod
import bluetooth_commands as cmd_mod
import bluetooth_devices as devices_mod
import bluetooth_loop as loop_mod
import bluetooth_pump as pump_mod
import bluetooth_socket as socket_mod
import bluetooth_window as window_mod

logger = logging.getLogger(__name__)

# Kept in sync with the client-side copy (core/autostream_bluetooth_client.py's
# BLUETOOTH_SERVICE_VERSION) -- both must be bumped together whenever this
# daemon changes, since the client falls back to its own constant whenever
# the daemon is unreachable to query directly.
BLUETOOTH_SERVICE_VERSION = "0.6.0"

DEFAULT_STATE_PATH = "/var/lib/autostream/bluetooth.json"

# Timers (seconds). The pairing window's limits live in bluetooth_window.
TICK_INTERVAL_SECONDS = 1.0
# Adapter-absent degradation: how often the tick loop
# retries attaching to BlueZ when no adapter was found at startup.
ADAPTER_RETRY_INTERVAL_SECONDS = 30


LINK_DISCONNECTED = "disconnected"
LINK_CONNECTING = "connecting"
LINK_CONNECTED = "connected"


# Configurable audio buffer: nominal milliseconds,
# persisted alongside the pairing state; the pump rounds this up to whole
# ALSA periods at apply time (bluetooth_pump.compute_prefill_periods).
DEFAULT_BUFFER_MS = 200
MIN_BUFFER_MS = 100
MAX_BUFFER_MS = 500


def is_valid_buffer_ms(value: object) -> bool:
    """True when *value* is an int (not bool) in [MIN_BUFFER_MS, MAX_BUFFER_MS]."""
    return isinstance(value, int) and not isinstance(value, bool) \
        and MIN_BUFFER_MS <= value <= MAX_BUFFER_MS


def _setup_logging() -> None:
    level_name = os.environ.get("AUTOSTREAM_BLUETOOTH_LOG_LEVEL", "info").strip().lower()
    level = {"debug": logging.DEBUG, "info": logging.INFO,
             "warning": logging.WARNING, "error": logging.ERROR}.get(level_name, logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    if root.handlers:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%d-%b-%y %H:%M:%S"
    ))
    root.addHandler(handler)


# ---------------------------------------------------------------------------
# Persistence. Presentation/intent state only; BlueZ itself owns
# the actual bond under /var/lib/bluetooth/.
# ---------------------------------------------------------------------------

def load_persisted_state(path: str = DEFAULT_STATE_PATH) -> dict:
    """Load {"paired_mac", "name", "paired_at"}, tolerant of any failure."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_persisted_state_atomic(path: str, data: dict) -> None:
    """Atomic tmp+rename write (family convention, cf. wifi_web._atomic_write)."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def clear_persisted_state(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# BluetoothOps — the narrow surface the state machine drives. A real instance
# wraps a bluetooth_bluez.BluezClient; tests inject a fake with the same
# shape, so the state machine itself has no D-Bus dependency.
# ---------------------------------------------------------------------------

class BluetoothOps:
    """Adapts a BluezClient to the handful of calls the state machine issues.

    Adoption and window clean-up are multi-step chains
    driven entirely on the GLib loop thread via the small operation classes
    in ``bluetooth_commands.py`` rather than a worker thread, so the loop
    never stalls on a D-Bus round-trip to the far end of an A2DP handshake.
    Disconnect (the shutdown path), adapter property writes and the bond
    sweep stay plain synchronous, bounded BlueZ calls.

    ``bluez`` may be ``None`` at construction (adapter-absent degradation):
    the state machine, pump, and control socket are
    all constructed and started before BlueZ is known to be reachable, so
    ``adapter_present`` reports False and every bluez-driving call raises
    until ``set_bluez()`` binds a live client once ``BluetoothService``'s
    retry loop attaches one.
    """

    def __init__(self, bluez: Optional["bluez_mod.BluezClient"] = None) -> None:
        self._bluez = bluez

    def set_bluez(self, bluez: "bluez_mod.BluezClient") -> None:
        """Bind the real BluezClient once BlueZ becomes reachable."""
        self._bluez = bluez

    @property
    def adapter_present(self) -> bool:
        return self._bluez is not None and self._bluez.adapter_present

    def _require_bluez(self) -> "bluez_mod.BluezClient":
        if self._bluez is None:
            raise RuntimeError("bluetooth adapter not available")
        return self._bluez

    def start_discovery(self) -> None:
        self._require_bluez().start_discovery()

    def stop_discovery(self) -> None:
        self._require_bluez().stop_discovery()

    def set_adapter_property(self, name: str, value) -> None:
        self._require_bluez().set_adapter_property(name, value)

    def start_adopt(
        self,
        mac: str,
        entry: str,
        old_mac: Optional[str],
        on_result: Callable[[str, bool, Optional[str]], None],
        is_stale: Callable[[], bool],
    ) -> None:
        """Launch an ``AdoptDeviceOp`` (entry step ``pair`` or ``trust``)
        against the bound BluezClient."""
        cmd_mod.AdoptDeviceOp(self._require_bluez(), mac, entry, old_mac, on_result, is_stale).start()

    def start_remove_devices(self, macs, on_done: Callable[[], None]) -> None:
        """Launch a ``RemoveDevicesOp`` (disconnect then remove each)."""
        cmd_mod.RemoveDevicesOp(self._require_bluez(), macs, on_done).start()

    def device_alias_async(
        self, mac: str, on_result: Callable[[str], None], on_error: Callable[[Exception], None],
    ) -> None:
        self._require_bluez().device_alias_async(mac, on_result, on_error)

    def disconnect(self, mac: str) -> None:
        self._require_bluez().disconnect_device(mac)

    def remove_device(self, mac: str) -> None:
        self._require_bluez().remove_device(mac)

    def purge_cached_devices(self, keep_macs: set) -> int:
        """See ``bluetooth_bluez.BluezClient.remove_cached_devices``."""
        return self._require_bluez().remove_cached_devices(keep_macs)

    def sweep_bonds(self, keep_macs: set) -> int:
        """See ``bluetooth_bluez.BluezClient.remove_bonded_devices``."""
        return self._require_bluez().remove_bonded_devices(keep_macs)

    @property
    def adapter_kind(self) -> Optional[str]:
        """``"usb"`` / ``"onboard"`` / ``"unknown"``, or ``None`` when no
        BlueZ client is bound (mirrors ``adapter_present`` unbound-safety)."""
        if self._bluez is None:
            return None
        return self._bluez.adapter_kind

    def is_connected(self, mac: str) -> bool:
        """Bounded Device1.Connected query. Unlike the other ops methods,
        this tolerates an unbound/absent BlueZ client by returning False
        rather than raising — kept for the shutdown path and direct callers
        that want a synchronous answer; a "not connected" answer is always a
        safe default when nothing is bound yet."""
        if self._bluez is None:
            return False
        return self._bluez.is_connected(mac)

    def is_connected_async(
        self,
        mac: str,
        on_result: Callable[[bool], None],
        on_error: Callable[[Exception], None],
    ) -> None:
        """Async Device1.Connected query (loop-thread only). Mirrors
        ``is_connected()``'s unbound-safety: reports not-connected through
        *on_result* immediately, rather than raising, when no BlueZ client is
        bound yet -- used by the pair-success hook to pick up a link that
        came up before the device was adopted."""
        if self._bluez is None:
            on_result(False)
            return
        self._bluez.is_connected_async(mac, on_result, on_error)


# ---------------------------------------------------------------------------
# State machine. Pure aside from the injected BluetoothOps calls
# and persistence I/O; clock is injectable so window-expiry/backoff tests
# never sleep.
# ---------------------------------------------------------------------------

class BluetoothStateMachine:
    """Composes the pairing window, its device list, the adapter mode and
    the audio source machine; owns the single-paired-device record and
    presentation-state persistence.

    Single-threaded on the GLib loop thread: every entry point -- socket
    commands (marshalled onto the loop via ``LoopBridge.call_sync``), the
    tick timer, D-Bus signal handlers, agent calls, and op callbacks (see
    ``bluetooth_commands.py``) -- runs there. The machines are pure; this
    class turns each input into a machine event and runs the actions the
    window machine returns, through ``_actions``.
    """

    def __init__(
        self,
        *,
        ops: BluetoothOps,
        state_path: str = DEFAULT_STATE_PATH,
        clock: Callable[[], float] = time.monotonic,
        bridge: Optional["loop_mod.LoopBridge"] = None,
        hostname: Callable[[], str] = socket.gethostname,
    ) -> None:
        self._ops = ops
        self._state_path = state_path
        self._clock = clock
        self._bridge = bridge

        self._paired_mac: Optional[str] = None
        self._paired_name: str = ""
        self._paired_at: Optional[float] = None
        self._buffer_ms: int = DEFAULT_BUFFER_MS

        self._link_state = LINK_DISCONNECTED

        self._on_link_change: Optional[Callable[[str], None]] = None
        self._on_pair_success: Optional[Callable[[str], None]] = None
        self._on_buffer_change: Optional[Callable[[int], None]] = None

        paired = lambda: self._paired_mac  # noqa: E731 (read without the loop assertion)
        self.devices = devices_mod.DeviceList(paired_mac=paired)
        self.window = window_mod.WindowMachine(devices=self.devices, paired_mac=paired)
        self.adapter_mode = mode_mod.AdapterMode(write=ops.set_adapter_property, hostname=hostname)
        self.source = pump_mod.AudioSourceMachine(audio_mac=self.devices.audio_mac)
        self._actions = {
            window_mod.ACT_ADAPTER_OPEN: self.adapter_mode.open_window,
            window_mod.ACT_ADAPTER_CLOSE: self.adapter_mode.close_window,
            window_mod.ACT_ADAPTER_ATTACH: self.adapter_mode.at_attach,
            window_mod.ACT_START_DISCOVERY: self._act_start_discovery,
            window_mod.ACT_STOP_DISCOVERY: self._act_stop_discovery,
            window_mod.ACT_SWEEP_BONDS: self._act_sweep_bonds,
            window_mod.ACT_ADOPT: self._act_adopt,
            window_mod.ACT_REMOVE_DEVICES: self._act_remove_devices,
            window_mod.ACT_SOURCE_ADOPT: self._act_source_adopt,
        }

        self._load_persisted()

    def _assert_on_loop(self) -> None:
        if self._bridge is not None:
            self._bridge.assert_on_loop()

    def set_link_change_callback(self, cb: Callable[[str], None]) -> None:
        """*cb(link_state)* fires whenever the paired device's link state
        changes."""
        self._on_link_change = cb

    def set_pair_success_callback(self, cb: Callable[[str], None]) -> None:
        """*cb(mac)* fires once a tapped device has been adopted, so the
        service can re-query its actual connection state: a Connected=True
        that arrived before the device was adopted was not attributed to the
        paired device and the link would otherwise read "disconnected"."""
        self._on_pair_success = cb

    def set_buffer_change_callback(self, cb: Callable[[int], None]) -> None:
        """*cb(buffer_ms)* fires whenever the configured audio buffer
        changes, so the pump can be told to apply it on its next (re)open."""
        self._on_buffer_change = cb

    def attach_pump(self, pump) -> None:
        """Bind the running pump to the audio source machine."""
        self.source.bind(pump)

    # ---- persistence ----

    def _load_persisted(self) -> None:
        data = load_persisted_state(self._state_path)
        mac = data.get("paired_mac")
        if isinstance(mac, str) and bluez_mod.is_valid_mac(mac):
            self._paired_mac = mac.upper()
            self._paired_name = str(data.get("name") or "")
            self._paired_at = data.get("paired_at")
        # Tolerate files predating this key (default applies when absent or
        # out of range — a hand-edited/corrupt value must not wedge startup).
        buffer_ms = data.get("buffer_ms")
        self._buffer_ms = buffer_ms if is_valid_buffer_ms(buffer_ms) else DEFAULT_BUFFER_MS

    def _persist(self) -> None:
        if self._paired_mac is None and self._buffer_ms == DEFAULT_BUFFER_MS:
            clear_persisted_state(self._state_path)
            return
        data: dict = {"buffer_ms": self._buffer_ms}
        if self._paired_mac is not None:
            data.update({
                "paired_mac": self._paired_mac,
                "name": self._paired_name,
                "paired_at": self._paired_at,
            })
        save_persisted_state_atomic(self._state_path, data)

    # ---- pairing-agent policy hooks ----

    def window_open(self) -> bool:
        self._assert_on_loop()
        return self.window.is_open()

    def adopting(self) -> Optional[str]:
        self._assert_on_loop()
        return self.window.adopting

    def provisional_macs(self) -> frozenset:
        self._assert_on_loop()
        return self.devices.provisional_macs()

    def trusted_mac(self) -> Optional[str]:
        self._assert_on_loop()
        return self._paired_mac

    def mark_provisional(self, mac: str, passkey: Optional[int]) -> None:
        """The agent accepted a pairing from a device nobody tapped."""
        self._assert_on_loop()
        self._window_event(window_mod.AGENT_REQUEST, mac=mac.upper(), passkey=passkey)
        self._learn_name(mac)

    # ---- the window: socket commands ----

    def window_start(self) -> Optional[str]:
        self._assert_on_loop()
        if not self._ops.adapter_present:
            return "no_adapter"
        return self._window_event(window_mod.START)

    def window_stop(self) -> Optional[str]:
        self._assert_on_loop()
        return self._window_event(window_mod.STOP)

    def window_poll(self) -> dict:
        """The pairing screen's poll: records its heartbeat (one timestamp
        in memory) and returns the window and its list."""
        self._assert_on_loop()
        self._window_event(window_mod.HEARTBEAT)
        return self.window.snapshot(self._clock())

    def tap(self, mac: str) -> Optional[str]:
        self._assert_on_loop()
        if not bluez_mod.is_valid_mac(mac or ""):
            return window_mod.REPLY_UNKNOWN_DEVICE
        return self._window_event(window_mod.TAP, mac=mac.upper())

    # ---- the window: D-Bus signals ----

    def on_device_found(self, device: dict) -> None:
        """*device*: {mac, name, rssi, paired, audio_capable} (bluez layer
        already filtered to audio-capable devices)."""
        self._assert_on_loop()
        mac = (device.get("mac") or "").upper()
        if mac:
            self._window_event(window_mod.DISCOVERED, mac=mac, name=device.get("name") or "")

    def on_device_paired(self, mac: str) -> None:
        self._assert_on_loop()
        self._window_event(window_mod.PAIRED, mac=mac.upper())
        if self.devices.state(mac) == devices_mod.PROVISIONAL:
            self._learn_name(mac)

    def on_device_removed(self, mac: str) -> None:
        self._assert_on_loop()
        self._window_event(window_mod.DEVICE_REMOVED, mac=mac.upper())

    def on_device_name(self, mac: str, name: str) -> None:
        self._assert_on_loop()
        self.devices.set_name(mac, name)

    def on_attach(self) -> None:
        """An adapter was attached (daemon start, or a dongle back): the
        window is closed by construction and stray bonds are swept."""
        self._assert_on_loop()
        self._window_event(window_mod.ATTACH)

    def on_adapter_lost(self) -> None:
        self._assert_on_loop()
        self._window_event(window_mod.ADAPTER_LOST)
        self.on_link_state_changed(self._paired_mac or "", False)

    def _window_event(self, event: str, **args) -> Optional[str]:
        outcome = self.window.handle(event, self._clock(), **args)
        for action in outcome.actions:
            self._actions[action[0]](*action[1:])
        return outcome.reply

    def _learn_name(self, mac: str) -> None:
        """Best effort: ask BlueZ for the device's own name for the list."""
        try:
            self._ops.device_alias_async(
                mac,
                lambda name: self.devices.set_name(mac, name),
                lambda e: logger.debug("bluetooth: no name for %s: %s", mac, e),
            )
        except Exception as e:
            logger.debug("bluetooth: name lookup for %s not started: %s", mac, e)

    # ---- the window: actions ----

    def _act_start_discovery(self) -> None:
        # Purge BlueZ's own device cache before (re)starting discovery: a
        # device it already saw in an earlier session never fires
        # InterfacesAdded again, so without this it would never be listed.
        # Best-effort: a device that connects in still reaches the list
        # through the agent even if discovery cannot start.
        keep = {self._paired_mac} if self._paired_mac else set()
        try:
            removed = self._ops.purge_cached_devices(keep)
            logger.info("pairing window: purged %d cached device entries", removed)
        except Exception as e:
            logger.warning("pairing window: failed to purge cached device entries: %s", e)
        try:
            self._ops.start_discovery()
        except Exception as e:
            logger.warning("pairing window: discovery did not start: %s", e)

    def _act_stop_discovery(self) -> None:
        try:
            self._ops.stop_discovery()
        except Exception as e:
            logger.debug("pairing window: stop discovery: %s", e)

    def _act_sweep_bonds(self) -> None:
        keep = {self._paired_mac} if self._paired_mac else set()
        try:
            removed = self._ops.sweep_bonds(keep)
            if removed:
                logger.info("bluetooth: removed %d bond(s) that were not the paired device", removed)
        except Exception as e:
            logger.warning("bluetooth: bond sweep failed: %s", e)

    def _act_adopt(self, mac: str, entry: str) -> None:
        try:
            self._ops.start_adopt(
                mac, entry, self._paired_mac, self.on_adopt_result,
                lambda: self.window.adopting != mac,
            )
        except Exception as e:
            self.on_adopt_result(mac, False, str(e))

    def _act_remove_devices(self, macs: tuple) -> None:
        done = lambda: self._window_event(window_mod.CLEANUP_DONE)  # noqa: E731
        if not macs or not self._ops.adapter_present:
            done()
            return
        try:
            self._ops.start_remove_devices(macs, done)
        except Exception as e:
            logger.warning("pairing window: clean-up not started: %s", e)
            done()

    def _act_source_adopt(self, mac: str) -> None:
        self.source.handle(pump_mod.EV_ADOPT, mac)

    def on_adopt_result(self, mac: str, success: bool, error: Optional[str] = None) -> None:
        self._assert_on_loop()
        mac = mac.upper()
        if mac != self.window.adopting:
            logger.info("Ignoring stale adoption result for %s (now adopting %s)",
                        mac, self.window.adopting)
            return
        if success:
            name = self.devices.name(mac)
            if mac != self._paired_mac:
                self._link_state = LINK_DISCONNECTED
            self._paired_mac = mac
            self._paired_name = "" if name == mac else name
            self._paired_at = time.time()
            self._persist()
            logger.info("bluetooth: adopted %s (%s)", mac, self._paired_name or "no name")
        self._window_event(window_mod.ADOPT_DONE, mac=mac, ok=success, error=error)
        if success and self._on_pair_success:
            self._on_pair_success(mac)

    def close_window_for_shutdown(self) -> None:
        """Bounded, best effort: leave the adapter at rest before exiting.
        Bonds of devices nobody tapped are swept at the next attach."""
        self._assert_on_loop()
        self._window_event(window_mod.STOP)
        if self.window.state == window_mod.ADOPTING:
            self._act_stop_discovery()
            self.adapter_mode.close_window()

    # ---- audio buffer configuration ----

    def get_buffer_ms(self) -> int:
        self._assert_on_loop()
        return self._buffer_ms

    def set_buffer_ms(self, buffer_ms: object) -> bool:
        """Validate and apply a new buffer size (socket ``configure`` cmd).
        Returns False (no-op) for a non-integer or out-of-range value."""
        self._assert_on_loop()
        if not is_valid_buffer_ms(buffer_ms):
            return False
        self._buffer_ms = buffer_ms
        self._persist()
        if self._on_buffer_change:
            self._on_buffer_change(buffer_ms)
        return True

    # ---- forget / single-paired-device policy ----

    def forget(self) -> None:
        """Un-pair the trusted device. An open window closes first, which
        also makes any tap's op in flight stale, so its result cannot land
        late and re-persist state the user just asked to clear."""
        self._assert_on_loop()
        self._window_event(window_mod.FORGET)
        mac = self._paired_mac
        if mac is None:
            return
        self._paired_mac = None
        self._paired_name = ""
        self._paired_at = None
        self._link_state = LINK_DISCONNECTED
        self._persist()
        self.source.handle(pump_mod.EV_FORGET)
        try:
            self._ops.remove_device(mac)
        except Exception as e:
            logger.warning("forget: failed to remove device %s from BlueZ: %s", mac, e)
        if self._on_link_change:
            self._on_link_change(LINK_DISCONNECTED)

    # ---- link state / transport ----

    def on_link_state_changed(self, mac: str, connected: bool) -> None:
        self._assert_on_loop()
        if not mac or mac.upper() != self._paired_mac:
            return
        new_state = LINK_CONNECTED if connected else LINK_DISCONNECTED
        if new_state == self._link_state:
            return
        self._link_state = new_state
        if not connected:
            # The transport goes with the link; do not wait for its signal.
            self.source.handle(pump_mod.EV_TRANSPORT_IDLE, mac)
        if self._on_link_change:
            self._on_link_change(new_state)

    def on_transport(self, mac: Optional[str], state: str, rate: Optional[int] = None) -> None:
        """One transport's state for *mac*: active, idle or removed."""
        self._assert_on_loop()
        if not mac:
            return
        self.source.handle(_TRANSPORT_EVENTS[state], mac, rate)

    # ---- the 1 s tick (driven by the GLib timer) ----
    #
    # There is no outgoing reconnect: the paired source connects to the
    # appliance when it is switched on. Paging a source that is off holds a
    # shared Wi-Fi/Bluetooth radio for the whole page timeout, which stalls
    # the network stream of whatever input is playing.

    def tick(self) -> None:
        self._assert_on_loop()
        self._window_event(window_mod.TICK)

    # ---- status (socket contract) ----

    def get_status(self) -> dict:
        self._assert_on_loop()
        paired = None
        if self._paired_mac is not None:
            paired = {"mac": self._paired_mac, "name": self._paired_name}
        adapter_present = self._ops.adapter_present
        held = self.source.held_mac
        return {
            "adapter_present": adapter_present,
            "paired": paired,
            "link": self._link_state,
            "streaming": self.source.state == pump_mod.SOURCE_LIVE,
            "scanning": self.window.is_active(),
            "buffer_ms": self._buffer_ms,
            "adapter_kind": self._ops.adapter_kind if adapter_present else None,
            "window_state": self.window.state,
            "held": {"mac": held} if held else None,
        }


_TRANSPORT_EVENTS = {
    bluez_mod.TRANSPORT_ACTIVE: pump_mod.EV_TRANSPORT_ACTIVE,
    bluez_mod.TRANSPORT_IDLE: pump_mod.EV_TRANSPORT_IDLE,
    bluez_mod.TRANSPORT_REMOVED: pump_mod.EV_TRANSPORT_REMOVED,
}


# ---------------------------------------------------------------------------
# Wiring: bluez signals -> state machine -> pump; the daemon entry point.
# ---------------------------------------------------------------------------

class BluetoothService:
    """Wires BluezClient signals into the state machine and pump, runs the
    tick thread, and owns process lifetime. Constructed by ``main()``; kept
    separate from ``BluetoothStateMachine`` so the state machine stays
    testable without any bluez/GLib/alsaaudio object ever being constructed.
    """

    def __init__(
        self,
        *,
        state_path: str = DEFAULT_STATE_PATH,
        socket_path: str = socket_mod.DEFAULT_SOCKET_PATH,
        call_timeout: float = bluez_mod.DEFAULT_CALL_TIMEOUT,
    ) -> None:
        self._state_path = state_path
        self._socket_path = socket_path
        self._call_timeout = call_timeout

        self._bluez: Optional["bluez_mod.BluezClient"] = None
        self._ops: Optional[BluetoothOps] = None
        self._dbus = None  # bound once dbus is importable (start()); reused by retries
        self.state_machine: Optional[BluetoothStateMachine] = None
        self.pump: Optional[pump_mod.LoopbackPump] = None
        self.control_server: Optional[socket_mod.BluetoothControlServer] = None

        # Adapter-absent degradation.
        self._bluez_ready = False
        self._subscribed = False
        self._last_adapter_retry: Optional[float] = None
        self._agent = None
        # True when the most recent attach attempt found an adapter it could
        # not power on/prepare (distinct from no adapter being found at all).
        self._adapter_blocked = False
        self._adapter_recovery_log = loop_mod.RecoveryLog("BlueZ adapter attach")

        self._tick_source_id: Optional[int] = None
        self._glib_loop = None
        self.bridge = loop_mod.LoopBridge()
        # stop() must be idempotent: the SIGTERM source calls it on the loop
        # thread, and main()'s finally: calls it again once the loop exits.
        self._stop_started = False

        # Every MediaTransport1 object seen, by object path: {mac, rate,
        # codec, active}. A device can have more than one (a stream restarted
        # as a new object), so a removal only matters for the source when no
        # other transport of that device is still active.
        self._transports: dict[str, dict] = {}

    def _on_transport(
        self, path: str, mac: Optional[str], state: str,
        rate: Optional[int] = None, codec: Optional[str] = None,
    ) -> None:
        assert self.state_machine is not None
        entry = self._transports.get(path) or {"mac": mac, "rate": None, "codec": None}
        if rate:
            entry["rate"] = rate
        if codec:
            entry["codec"] = codec
        entry["mac"] = entry["mac"] or mac
        entry["active"] = state == bluez_mod.TRANSPORT_ACTIVE
        if state == bluez_mod.TRANSPORT_REMOVED:
            self._transports.pop(path, None)
        else:
            self._transports[path] = entry
        mac = entry["mac"]
        if state != bluez_mod.TRANSPORT_ACTIVE and self._active_transport(mac) is not None:
            logger.debug("bluetooth: transport %s %s; %s has another active", path, state, mac)
            return
        self.state_machine.on_transport(mac, state, entry["rate"])

    def _active_transport(self, mac: Optional[str] = None) -> Optional[dict]:
        """An active transport (of *mac*, or of any device), else None."""
        for entry in self._transports.values():
            if entry.get("active") and (mac is None or entry.get("mac") == mac):
                return entry
        return None

    def _on_pair_success(self, mac: str) -> None:
        """Pair-success hook: re-query actual BlueZ connection state -- the
        PropertiesChanged subscription can race and miss a Connected=True
        that arrived before the device was adopted. Runs entirely on the
        loop thread: the connection-state query is the async form,
        continuing via ``_finish_pair_success``/``_pair_success_probe_error``
        rather than blocking here for the answer. The audio itself follows
        the adoption through the audio source machine."""
        assert self.state_machine is not None and self._ops is not None
        self._ops.is_connected_async(
            mac,
            lambda connected: self._finish_pair_success(mac, connected),
            lambda error: self._pair_success_probe_error(mac, error),
        )

    def _finish_pair_success(self, mac: str, connected: bool) -> None:
        if connected:
            logger.info("bluetooth service: %s already connected at adoption", mac)
        self.state_machine.on_link_state_changed(mac, connected)

    def _pair_success_probe_error(self, mac: str, error: Exception) -> None:
        logger.warning(
            "bluetooth service: error querying connection state for %s after adoption: %s",
            mac, error,
        )
        self._finish_pair_success(mac, False)

    def _sync_startup_state(self, bluez: "bluez_mod.BluezClient") -> None:
        """Startup / adapter-(re)attach self-heal: BlueZ only
        signals InterfacesAdded/PropertiesChanged on *change*, so a daemon
        restart while a device is already connected and streaming never gets
        a fresh signal for either fact — without this the service is stuck
        reporting "disconnected"/zero-fill until something happens to change
        state again. Enumerates what is already there via GetManagedObjects
        and feeds it through the same paths a live signal would use."""
        try:
            snapshot = bluez.find_existing_state()
        except Exception:
            logger.exception("bluetooth service: error syncing startup BlueZ state")
            return
        mac = self.state_machine.trusted_mac()
        if mac and snapshot.get("devices", {}).get(mac):
            logger.info("bluetooth service: startup sync found %s already connected", mac)
            self.state_machine.on_link_state_changed(mac, True)
        for transport in snapshot.get("transports") or ():
            logger.info("bluetooth service: startup sync found an active transport for %s",
                        transport.get("mac"))
            self._on_transport(
                transport["path"], transport.get("mac"), bluez_mod.TRANSPORT_ACTIVE,
                transport.get("rate"), transport.get("codec"),
            )

    def _get_status(self) -> dict:
        """Wraps the state machine's status with the pump's actual state and
        the adapter-power-blocked flag: the state machine's inferred
        ``streaming`` flag alone can be true while the pump itself never got
        armed — ``pump_source_active`` lets callers tell the two apart
        without guessing — and ``adapter_present`` alone cannot distinguish
        "no adapter" from "adapter found but could not be powered on"; the
        additive ``adapter_blocked`` key carries that distinction.

        ``codec``/``sample_rate`` are additive and present only while a
        transport is active: the codec name and sample rate decoded from the
        transport's negotiated Configuration (falling back to a plain Rate
        property, then — only when a capture PCM is actually open — the
        pump's own negotiated rate, the ground truth of what was opened).
        The live device's transport is preferred over a held one.
        """
        status = self.state_machine.get_status()
        status["pump_source_active"] = self.pump.is_streaming() if self.pump is not None else False
        # Additive: whether the pump currently holds a verified open on the
        # loopback playback end. The monitor-side coordinator gates its own
        # capture open on this, so the shared cable always carries the
        # pump's rate/format by the time the capture side negotiates.
        status["loopback_held"] = self.pump.holds_loopback() if self.pump is not None else False
        # Additive: whether the loopback cable is currently held at
        # incompatible parameters by the other end, pausing the pump. The
        # coordinator watches this to bounce the monitor's inputs and force
        # renegotiation when the lockout persists.
        status["loopback_locked_out"] = self.pump.playback_locked_out() if self.pump is not None else False
        status["adapter_blocked"] = self._adapter_blocked
        status["version"] = BLUETOOTH_SERVICE_VERSION
        transport = (self._active_transport(self.state_machine.source.live_mac)
                     or self._active_transport())
        if transport is not None:
            sample_rate = transport.get("rate")
            if not sample_rate and self.pump is not None and self.pump.is_streaming():
                pump_rate = self.pump.get_negotiated_rate()
                if isinstance(pump_rate, int) and pump_rate > 0:
                    sample_rate = pump_rate
            if transport.get("codec"):
                status["codec"] = transport["codec"]
            if sample_rate:
                status["sample_rate"] = sample_rate
        return status

    def _on_props_changed(self, mac: str, changed: dict) -> None:
        if "Connected" in changed:
            self.state_machine.on_link_state_changed(mac, bool(changed["Connected"]))
        if changed.get("Paired") is True:
            self.state_machine.on_device_paired(mac)
        name = changed.get("Alias") or changed.get("Name")
        if name:
            self.state_machine.on_device_name(mac, str(name))

    def _on_adapter_lost(self) -> None:
        """The attached adapter went away: close any window, report the
        adapter missing, and let the tick retry the attach."""
        self.state_machine.on_adapter_lost()
        self._bluez_ready = False
        self._last_adapter_retry = None

    def _on_tick(self) -> bool:
        """``GLib.timeout_add_seconds`` callback: drives the pairing
        window's limits. Runs on the loop
        thread, same as every other D-Bus touch point. Must return True to
        stay armed -- GLib disarms a timeout source whose callback returns
        False/None."""
        try:
            self.state_machine.tick()
        except Exception:
            logger.exception("bluetooth service: error in tick loop")
        if not self._bluez_ready:
            self._maybe_retry_adapter()
        return True

    def _maybe_retry_adapter(self) -> None:
        """Adapter-absent degradation: retried from
        the tick callback every ADAPTER_RETRY_INTERVAL_SECONDS until an adapter
        appears — a missing/late-starting adapter must not crash-loop the
        unit; the control socket and zero-fill pump are already up."""
        now = time.monotonic()
        if (self._last_adapter_retry is not None
                and now - self._last_adapter_retry < ADAPTER_RETRY_INTERVAL_SECONDS):
            return
        self._last_adapter_retry = now
        try:
            self._try_connect_bluez()
        except Exception:
            logger.exception("bluetooth service: error retrying BlueZ adapter connect")

    def _register_agent(self) -> None:
        """Create the agent once and register it with BlueZ. On a later
        attach (a dongle back) only the registration is repeated; BlueZ
        answers AlreadyExists when it still holds it."""
        dbus = self._dbus
        if self._agent is None:
            sm = self.state_machine
            policy = agent_mod.PairingPolicy(
                window_open=sm.window_open,
                adopting=sm.adopting,
                paired_mac=sm.trusted_mac,
                provisional_macs=sm.provisional_macs,
                mark_provisional=sm.mark_provisional,
            )
            agent_class = agent_mod.build_agent_class(dbus)
            self._agent = agent_class(dbus.SystemBus(), agent_mod.AGENT_PATH, policy)
        agent_manager = dbus.Interface(
            dbus.SystemBus().get_object("org.bluez", "/org/bluez"),
            "org.bluez.AgentManager1",
        )
        try:
            agent_manager.RegisterAgent(agent_mod.AGENT_PATH, agent_mod.AGENT_CAPABILITY,
                                         timeout=self._call_timeout)
        except Exception as e:
            if "AlreadyExists" not in str(e):
                raise
        agent_manager.RequestDefaultAgent(agent_mod.AGENT_PATH, timeout=self._call_timeout)

    def _try_connect_bluez(self) -> bool:
        """Attempt to attach to BlueZ and, on success, complete the agent
        registration + signal wiring that requires a live adapter. Idempotent
        once already attached; safe to call repeatedly (startup, retries,
        and after the adapter was lost).
        """
        if self._bluez_ready:
            return True

        bluez = self._bluez or bluez_mod.BluezClient(call_timeout=self._call_timeout)
        try:
            bluez.connect()
            bluez.power_on()
        except bluez_mod.BluezUnavailable as e:
            self._adapter_recovery_log.fail(time.monotonic())
            logger.warning(
                "bluetooth service: BlueZ adapter not available yet (%s); will retry every %ds",
                e, ADAPTER_RETRY_INTERVAL_SECONDS,
            )
            self._adapter_blocked = False
            return False
        except Exception as e:
            # An adapter was found (connect() succeeded) but a later step in
            # this sequence raised — most commonly a plain D-Bus exception
            # from Powered=True (an rfkill soft-block or similar adapter
            # fault). This must degrade exactly like the adapter-absent case
            # above rather than propagate: the 30s retry this method is
            # already called from owns recovery, and the caller (including
            # the very first attach attempt made from start()) must never be
            # allowed to crash the process over an adapter that exists but
            # cannot currently be used.
            self._adapter_recovery_log.fail(time.monotonic())
            logger.warning(
                "bluetooth service: BlueZ adapter present but could not be powered/prepared "
                "(rfkill block?): %s; will retry every %ds",
                e, ADAPTER_RETRY_INTERVAL_SECONDS,
            )
            self._adapter_blocked = True
            return False

        self._adapter_blocked = False
        self._bluez = bluez
        self._ops.set_bluez(bluez)

        self._register_agent()

        if not self._subscribed:
            bluez.subscribe(
                on_device_found=self.state_machine.on_device_found,
                on_props_changed=self._on_props_changed,
                on_transport=self._on_transport,
                on_device_removed=self.state_machine.on_device_removed,
                on_adapter_lost=self._on_adapter_lost,
            )
            self._subscribed = True

        self.state_machine.on_attach()
        self._sync_startup_state(bluez)

        self._bluez_ready = True
        self._adapter_recovery_log.ok(time.monotonic())
        logger.info("bluetooth service: BlueZ adapter attached")
        return True

    def start(self) -> None:
        import dbus
        import dbus.mainloop.glib
        from gi.repository import GLib

        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        self._dbus = dbus
        # start() runs on the thread that goes on to call self._glib_loop.run()
        # below -- i.e. this thread *becomes* the loop thread from here on.
        self.bridge.mark_loop_thread()

        # ops/state-machine/pump/control-socket all come up regardless of
        # whether BlueZ (or an adapter) is reachable yet — the systemd unit
        # must never crash-loop just because bluetoothd hasn't started, or
        # no dongle is plugged in.
        self._ops = BluetoothOps()
        self.state_machine = BluetoothStateMachine(
            ops=self._ops, state_path=self._state_path, bridge=self.bridge,
        )
        self.state_machine.set_pair_success_callback(self._on_pair_success)

        self.pump = pump_mod.LoopbackPump(buffer_ms=self.state_machine.get_buffer_ms())
        self.pump.start()
        self.state_machine.attach_pump(self.pump)
        self.state_machine.set_buffer_change_callback(
            lambda buffer_ms: self.pump.set_buffer_ms(buffer_ms)
        )

        sm = self.state_machine
        self.control_server = socket_mod.BluetoothControlServer(
            get_status=self._get_status,
            window_start=sm.window_start,
            window_stop=sm.window_stop,
            window_poll=sm.window_poll,
            pair=sm.tap,
            forget=sm.forget,
            configure=sm.set_buffer_ms,
            bridge=self.bridge,
            socket_path=self._socket_path,
        )
        self.control_server.start()

        self._try_connect_bluez()

        self._tick_source_id = GLib.timeout_add_seconds(int(TICK_INTERVAL_SECONDS), self._on_tick)

        # SIGTERM is delivered as a GLib source rather than a Python-level
        # signal.signal handler: the latter only runs when the interpreter
        # executes bytecode between GLib dispatches, whereas a unix signal
        # source is dispatched by the loop itself, on the loop thread —
        # shutdown then runs under the same threading contract as everything
        # else.
        GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGTERM, self._on_sigterm)

        self._glib_loop = GLib.MainLoop()
        logger.info("autostream_bluetooth %s started (adapter_present=%s)",
                    BLUETOOTH_SERVICE_VERSION, self._bluez_ready)
        self._glib_loop.run()

    def _disconnect_on_shutdown(self) -> None:
        """Best-effort: drop the A2DP link before this service goes away, so
        a source is never left playing into a dead sink once services are
        disabled/stopped (SIGTERM path). Bounded by the underlying D-Bus
        call timeout; any failure is logged, never raised."""
        if self.state_machine is None or self._ops is None:
            return
        mac = self.state_machine.trusted_mac()
        if not mac:
            return
        if self.state_machine.get_status().get("link") != LINK_CONNECTED:
            return
        try:
            self._ops.disconnect(mac)
        except Exception:
            logger.exception(
                "bluetooth service: error disconnecting %s during shutdown", mac,
            )

    def _close_window_on_shutdown(self) -> None:
        if self.state_machine is None or self._ops is None:
            return
        try:
            self.state_machine.close_window_for_shutdown()
        except Exception:
            logger.exception("bluetooth service: error closing the pairing window during shutdown")

    def _on_sigterm(self) -> bool:
        """GLib unix-signal callback (loop thread). systemd sends SIGTERM on
        stop/restart; without this the process would die without unlinking
        the control socket, stopping the pump thread, or dropping the A2DP
        link. Returns False: one shot, the source removes itself."""
        logger.info("bluetooth service: received SIGTERM, shutting down")
        try:
            self.stop()
        except Exception:
            logger.exception("bluetooth service: error during signal shutdown")
        return False

    def stop(self) -> None:
        """Orderly shutdown; idempotent. Runs on the loop thread when
        triggered by SIGTERM. Bounded: the window close and the shutdown
        Disconnect are capped by their D-Bus timeouts, and a socket command
        caught mid-flight resolves within the bridge's call_sync timeout
        (the loop is quitting, so the marshalled call can only time out)."""
        if self._stop_started:
            return
        self._stop_started = True
        if self._tick_source_id is not None:
            from gi.repository import GLib
            GLib.source_remove(self._tick_source_id)
            self._tick_source_id = None
        self._close_window_on_shutdown()
        self._disconnect_on_shutdown()
        if self.control_server is not None:
            self.control_server.stop()
        if self.pump is not None:
            self.pump.stop()
        if self.state_machine is not None:
            self.state_machine.source.handle(pump_mod.EV_PUMP_STOP)
        if self._glib_loop is not None:
            self._glib_loop.quit()


def main() -> None:
    _setup_logging()
    service = BluetoothService()
    try:
        service.start()
    except KeyboardInterrupt:
        pass
    finally:
        service.stop()


if __name__ == "__main__":
    main()
