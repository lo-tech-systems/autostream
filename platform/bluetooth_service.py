#!/usr/bin/python3
"""bluetooth_service.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

Entry point / main loop / thread orchestration for the autostream_bluetooth
daemon. Runs on the system Python as the unprivileged ``autostream`` user
(groups ``bluetooth``,
``audio``). Single process, three threads: GLib main loop (D-Bus), the
control-socket server, and the loopback pump — plus a lightweight tick thread
driving the scan/pairing window timers and the reconnect supervisor.

Follows wifi_watcher.py's module-layout conventions: this module owns the
state machine, persistence, and startup wiring; ``bluetooth_bluez.py`` is the
one place that talks to BlueZ, ``bluetooth_agent.py`` owns the pairing
accept/reject policy, ``bluetooth_pump.py`` owns the loopback feeder, and
``bluetooth_socket.py`` owns the control-socket protocol. Every sibling
module is deployed flat beside this one (matching wifi_*.py); none of them
import this module, so the dependency direction is strictly hub-to-spoke.

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
import sys
import tempfile
import threading
import time
from typing import Callable, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import bluetooth_bluez as bluez_mod
import bluetooth_agent as agent_mod
import bluetooth_pump as pump_mod
import bluetooth_socket as socket_mod

logger = logging.getLogger(__name__)

BLUETOOTH_SERVICE_VERSION = "1.0.0"

DEFAULT_STATE_PATH = "/var/lib/autostream/bluetooth.json"

# Timers (seconds).
SCAN_WINDOW_SECONDS = 60
PAIRING_WINDOW_SECONDS = 30
RECONNECT_INTERVAL_SECONDS = 30
TICK_INTERVAL_SECONDS = 1.0
# Adapter-absent degradation: how often the tick loop
# retries attaching to BlueZ when no adapter was found at startup.
ADAPTER_RETRY_INTERVAL_SECONDS = 30

MODE_IDLE = "idle"
MODE_SCANNING = "scanning"
MODE_PAIRING = "pairing"

LINK_DISCONNECTED = "disconnected"
LINK_CONNECTING = "connecting"
LINK_CONNECTED = "connected"

PAIR_STATE_IDLE = "idle"
PAIR_STATE_PAIRING = "pairing"
PAIR_STATE_DONE = "done"
PAIR_STATE_FAILED = "failed"

# Configurable audio buffer (plan SS1 "Audio buffer"): nominal milliseconds,
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
    """Adapts a BluezClient to the handful of calls the state machine issues,
    dispatching the ones that can block (Pair/Connect/Disconnect) onto a
    worker thread so the GLib main loop / socket handlers never stall on a
    D-Bus round-trip to the far end of an A2DP handshake.

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

    def set_pairable(self, pairable: bool) -> None:
        self._require_bluez().set_pairable(pairable)

    def pair_and_trust(self, mac: str) -> None:
        """Pair, trust, and connect — runs on the calling (worker) thread."""
        bluez = self._require_bluez()
        bluez.pair(mac)
        bluez.set_trusted(mac, True)
        bluez.connect_device(mac)

    def connect(self, mac: str) -> None:
        self._require_bluez().connect_device(mac)

    def disconnect(self, mac: str) -> None:
        self._require_bluez().disconnect_device(mac)

    def remove_device(self, mac: str) -> None:
        self._require_bluez().remove_device(mac)

    def purge_cached_devices(self, keep_macs: set) -> int:
        """See ``bluetooth_bluez.BluezClient.remove_cached_devices``."""
        return self._require_bluez().remove_cached_devices(keep_macs)

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
        rather than raising — callers (reconnect supervisor, pair-success
        hook) use it purely to decide whether to *skip* other work, and a
        "not connected" answer is always a safe default for that."""
        if self._bluez is None:
            return False
        return self._bluez.is_connected(mac)


# ---------------------------------------------------------------------------
# State machine. Pure aside from the injected BluetoothOps calls
# and persistence I/O; clock is injectable so window-expiry/backoff tests
# never sleep.
# ---------------------------------------------------------------------------

class BluetoothStateMachine:
    """Owns the scan/pairing state machine, single-paired-device policy, the
    reconnect supervisor, and presentation-state persistence.

    Blocking BlueZ calls (Pair/Connect/Disconnect) are dispatched via
    ``run_async`` (defaults to a daemon thread per call; tests inject a
    synchronous stand-in) so state-machine methods called from the socket
    server or the tick thread never block on D-Bus.
    """

    def __init__(
        self,
        *,
        ops: BluetoothOps,
        state_path: str = DEFAULT_STATE_PATH,
        clock: Callable[[], float] = time.monotonic,
        run_async: Optional[Callable[[Callable[[], None]], None]] = None,
    ) -> None:
        self._ops = ops
        self._state_path = state_path
        self._clock = clock
        self._run_async = run_async or self._default_run_async
        self._lock = threading.RLock()

        self.mode = MODE_IDLE
        self._scan_started_at: Optional[float] = None
        self._scan_results: dict[str, dict] = {}

        self._pairing_target_mac: Optional[str] = None
        self._pairing_started_at: Optional[float] = None
        self._pair_state = PAIR_STATE_IDLE
        self._pair_error: Optional[str] = None

        self._paired_mac: Optional[str] = None
        self._paired_name: str = ""
        self._paired_at: Optional[float] = None
        self._buffer_ms: int = DEFAULT_BUFFER_MS

        self._link_state = LINK_DISCONNECTED
        self._streaming = False
        self._last_reconnect_attempt: Optional[float] = None

        self._on_link_change: Optional[Callable[[str], None]] = None
        self._on_pair_success: Optional[Callable[[str], None]] = None
        self._on_buffer_change: Optional[Callable[[int], None]] = None

        self._load_persisted()

    @staticmethod
    def _default_run_async(fn: Callable[[], None]) -> None:
        threading.Thread(target=fn, daemon=True, name="bt-worker").start()

    def set_link_change_callback(self, cb: Callable[[str], None]) -> None:
        """*cb(link_state)* fires whenever link state changes, so the pump
        can be told to stop expecting a transport once a device drops (the
        transport-appeared/disappeared signal already drives streaming)."""
        self._on_link_change = cb

    def set_pair_success_callback(self, cb: Callable[[str], None]) -> None:
        """*cb(mac)* fires outside the state-machine lock once pairing
        completes successfully. During the first pairing of
        a device, a MediaTransport1 object can appear (and a Connected=True
        PropertiesChanged can arrive) *before* the device is trusted — before
        this pairing has finished — so neither ``on_transport_changed`` nor
        ``on_link_state_changed`` had a trusted mac to attribute the event to
        and the daemon was stuck showing "disconnected"/zero-fill forever.
        The service's own transport handler now falls back to the in-flight
        pairing target mac as the primary fix; this callback is the
        belt-and-braces follow-up, letting the service re-query actual
        connection state and re-arm the pump once pairing lands."""
        self._on_pair_success = cb

    def set_buffer_change_callback(self, cb: Callable[[int], None]) -> None:
        """*cb(buffer_ms)* fires outside the state-machine lock whenever the
        configured audio buffer changes, so the pump can be told to apply it
        on its next (re)open."""
        self._on_buffer_change = cb

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

    def pairing_window_open(self) -> bool:
        with self._lock:
            return self.mode == MODE_PAIRING

    def pairing_target_mac(self) -> Optional[str]:
        with self._lock:
            return self._pairing_target_mac

    def trusted_mac(self) -> Optional[str]:
        with self._lock:
            return self._paired_mac

    # ---- scan ----

    def start_scan(self) -> bool:
        with self._lock:
            if self.mode == MODE_PAIRING:
                return False
            self.mode = MODE_SCANNING
            self._scan_started_at = self._clock()
            self._scan_results = {}
            keep_macs = {m for m in (self._paired_mac, self._pairing_target_mac) if m}
        # Purge BlueZ's own device cache before (re)starting discovery: a
        # device it already saw in an earlier session never fires
        # InterfacesAdded again, so without this later scans would show
        # nothing for anything already seen once. Best-effort — a purge
        # failure must not prevent the scan itself from starting.
        try:
            removed = self._ops.purge_cached_devices(keep_macs)
            logger.info("scan: purged %d cached device entries", removed)
        except Exception as e:
            logger.warning("scan: failed to purge cached device entries: %s", e)
        self._ops.start_discovery()
        return True

    def stop_scan(self) -> None:
        with self._lock:
            was_scanning = self.mode == MODE_SCANNING
            if was_scanning:
                self.mode = MODE_IDLE
                self._scan_started_at = None
        self._ops.stop_discovery()

    def on_device_found(self, device: dict) -> None:
        """*device*: {mac, name, rssi, paired, audio_capable} (bluez layer
        already filtered to audio-capable devices; only recorded while a
        scan is actually open)."""
        with self._lock:
            if self.mode != MODE_SCANNING:
                return
            mac = device.get("mac")
            if not mac:
                return
            self._scan_results[mac.upper()] = dict(device)

    def get_scan_results(self) -> list:
        with self._lock:
            paired = self._paired_mac
            results = []
            for mac, device in self._scan_results.items():
                results.append({
                    "mac": mac,
                    "name": device.get("name", ""),
                    "rssi": device.get("rssi"),
                    "paired": mac == paired,
                })
            return results

    # ---- pairing ----

    def start_pairing(self, mac: str) -> bool:
        mac = mac.upper()
        if not bluez_mod.is_valid_mac(mac):
            return False
        with self._lock:
            if self.mode == MODE_PAIRING:
                return False
            was_scanning = self.mode == MODE_SCANNING
            old_mac = self._paired_mac
            self.mode = MODE_PAIRING
            self._scan_started_at = None
            self._pairing_target_mac = mac
            self._pairing_started_at = self._clock()
            self._pair_state = PAIR_STATE_PAIRING
            self._pair_error = None
        # A scan in progress must yield the adapter before pairing starts
        # (mirrors stop_scan()'s own ops call, made outside the lock).
        if was_scanning:
            self._ops.stop_discovery()
        self._ops.set_pairable(True)

        def _work() -> None:
            try:
                # Pair the new device *before* removing the old one: if
                # pair_and_trust() fails, the previously
                # trusted device must remain paired/trusted rather than being
                # stranded with BlueZ no longer bonding it. A remove_device()
                # failure after a successful pair is logged but does not fail
                # the pairing itself — the new device is already trusted and
                # usable regardless of whether the old bond was cleaned up.
                self._ops.pair_and_trust(mac)
                if old_mac and old_mac != mac:
                    try:
                        self._ops.remove_device(old_mac)
                    except Exception:
                        logger.exception(
                            "Failed to remove replaced device %s after pairing %s",
                            old_mac, mac,
                        )
                self.on_pair_result(mac, True)
            except Exception as e:
                self.on_pair_result(mac, False, str(e))

        self._run_async(_work)
        return True

    def on_pair_result(self, mac: str, success: bool, error: Optional[str] = None) -> None:
        mac = mac.upper()
        with self._lock:
            if mac != self._pairing_target_mac:
                logger.info("Ignoring stale pair result for %s (current target %s)",
                            mac, self._pairing_target_mac)
                return
            self.mode = MODE_IDLE
            if success:
                self._pair_state = PAIR_STATE_DONE
                self._paired_mac = mac
                self._paired_name = self._scan_results.get(mac, {}).get("name", "")
                self._paired_at = time.time()
            else:
                self._pair_state = PAIR_STATE_FAILED
                self._pair_error = error or "pairing_failed"
        # ops/persistence I/O happens outside the lock (file convention: see
        # start_scan/stop_scan).
        self._ops.set_pairable(False)
        if success:
            self._persist()
            if self._on_pair_success:
                self._on_pair_success(mac)

    def get_pair_status(self) -> dict:
        with self._lock:
            result = {"state": self._pair_state}
            if self._pair_error:
                result["error"] = self._pair_error
            return result

    # ---- audio buffer configuration ----

    def get_buffer_ms(self) -> int:
        with self._lock:
            return self._buffer_ms

    def set_buffer_ms(self, buffer_ms: object) -> bool:
        """Validate and apply a new buffer size (socket ``configure`` cmd).
        Returns False (no-op) for a non-integer or out-of-range value."""
        if not is_valid_buffer_ms(buffer_ms):
            return False
        with self._lock:
            self._buffer_ms = buffer_ms
        self._persist()
        if self._on_buffer_change:
            self._on_buffer_change(buffer_ms)
        return True

    # ---- forget / single-paired-device policy ----

    def forget(self) -> None:
        """Un-pair the trusted device, and also
        invalidate any in-flight pairing attempt's target MAC — otherwise a
        pairing worker thread that is already running (e.g. a replacement
        pairing started before this forget()) would land its result late via
        ``on_pair_result`` and re-persist state the user just asked to clear.
        ``on_pair_result``'s own ``mac != self._pairing_target_mac`` guard
        rejects it once the target is cleared here.
        """
        with self._lock:
            mac = self._paired_mac
            was_pairing = self._pairing_target_mac is not None
            if was_pairing:
                self._pairing_target_mac = None
                self._pairing_started_at = None
                if self.mode == MODE_PAIRING:
                    self.mode = MODE_IDLE
            if mac is not None:
                self._paired_mac = None
                self._paired_name = ""
                self._paired_at = None
                self._link_state = LINK_DISCONNECTED
                self._streaming = False
                self._persist()
        if was_pairing:
            # Close the BlueZ pairing window the abandoned attempt opened;
            # on_pair_result() will no longer run this itself since its
            # stale-result guard now rejects the eventual worker outcome.
            self._ops.set_pairable(False)
        if mac is None:
            return
        try:
            self._ops.remove_device(mac)
        except Exception as e:
            logger.warning("forget: failed to remove device %s from BlueZ: %s", mac, e)
        if self._on_link_change:
            self._on_link_change(LINK_DISCONNECTED)

    # ---- link state / transport ----

    def on_link_state_changed(self, mac: str, connected: bool) -> None:
        with self._lock:
            if not mac or mac.upper() != self._paired_mac:
                return
            new_state = LINK_CONNECTED if connected else LINK_DISCONNECTED
            if new_state == self._link_state:
                return
            self._link_state = new_state
            if connected:
                self._last_reconnect_attempt = None
        if self._on_link_change:
            self._on_link_change(new_state)

    def on_transport_changed(self, active: bool) -> None:
        with self._lock:
            self._streaming = bool(active)

    # ---- reconnect supervisor ----

    def reconnect_tick(self) -> None:
        with self._lock:
            mac = self._paired_mac
            if mac is None or self._link_state != LINK_DISCONNECTED:
                return
            now = self._clock()
            if (self._last_reconnect_attempt is not None
                    and now - self._last_reconnect_attempt < RECONNECT_INTERVAL_SECONDS):
                return
            self._last_reconnect_attempt = now

        def _work() -> None:
            # Check actual connection state before hammering
            # Connect() — a stale "disconnected" link (the PropertiesChanged
            # subscription can miss a Connected=True that races pairing, or a
            # daemon restart loses all signal history) must self-heal from a
            # cheap property read instead of retrying Connect() against an
            # already-connected device every RECONNECT_INTERVAL_SECONDS.
            try:
                if self._ops.is_connected(mac):
                    self.on_link_state_changed(mac, True)
                    return
            except Exception as e:
                logger.info("Reconnect supervisor: is_connected check failed for %s: %s", mac, e)
            try:
                self._ops.connect(mac)
            except Exception as e:
                logger.info("Reconnect attempt to %s failed: %s", mac, e)

        self._run_async(_work)

    # ---- window expiry (called by the tick thread) ----

    def tick(self) -> None:
        now = self._clock()
        with self._lock:
            if self.mode == MODE_SCANNING and self._scan_started_at is not None:
                if now - self._scan_started_at >= SCAN_WINDOW_SECONDS:
                    expired = True
                else:
                    expired = False
            else:
                expired = False
        if expired:
            self.stop_scan()

        with self._lock:
            if self.mode == MODE_PAIRING and self._pairing_started_at is not None:
                if now - self._pairing_started_at >= PAIRING_WINDOW_SECONDS:
                    timed_out_mac = self._pairing_target_mac
                else:
                    timed_out_mac = None
            else:
                timed_out_mac = None
        if timed_out_mac is not None:
            self.on_pair_result(timed_out_mac, False, "timeout")

        self.reconnect_tick()

    # ---- status (socket contract) ----

    def get_status(self) -> dict:
        with self._lock:
            paired = None
            if self._paired_mac is not None:
                paired = {"mac": self._paired_mac, "name": self._paired_name}
            adapter_present = self._ops.adapter_present
            return {
                "adapter_present": adapter_present,
                "paired": paired,
                "link": self._link_state,
                "streaming": self._streaming,
                "scanning": self.mode == MODE_SCANNING,
                "buffer_ms": self._buffer_ms,
                "adapter_kind": self._ops.adapter_kind if adapter_present else None,
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
        self._last_adapter_retry: Optional[float] = None
        self._agent = None
        # True when the most recent attach attempt found an adapter it could
        # not power on/prepare (distinct from no adapter being found at all).
        self._adapter_blocked = False

        self._tick_stop = threading.Event()
        self._tick_thread: Optional[threading.Thread] = None
        self._glib_loop = None

        # Last transport signal seen: recorded
        # on *every* call to _on_transport_changed, independent of whether we
        # had a mac to arm the pump with at the time, so the pair-success
        # hook can re-check "was a transport already active when pairing
        # finished?" after the fact.
        self._last_transport_active = False
        self._last_transport_rate: Optional[int] = None

    def _on_transport_changed(self, active: bool, rate: Optional[int] = None) -> None:
        assert self.state_machine is not None and self.pump is not None
        self.state_machine.on_transport_changed(active)
        self._last_transport_active = active
        self._last_transport_rate = rate
        if active:
            # During the *first* pairing of a device, the
            # transport can appear while pair_and_trust() is still in flight
            # — trusted_mac() is still None — so fall back to the in-flight
            # pairing target. Without this the pump was never armed and
            # nothing ever retried (BlueZ only signals once, on appearance).
            mac = self.state_machine.trusted_mac() or self.state_machine.pairing_target_mac()
            if mac:
                logger.info(
                    "bluetooth pump: transport active (mac=%s, rate=%s) - arming source", mac, rate,
                )
                self.pump.set_active_source(pump_mod.bluealsa_capture_device(mac), rate=rate)
            else:
                logger.warning(
                    "bluetooth pump: transport active but no trusted/pairing mac known "
                    "(rate=%s) - pump stays zero-fill", rate,
                )
        else:
            logger.info("bluetooth pump: transport inactive - clearing source")
            self.pump.set_active_source(None)

    def _on_pair_success(self, mac: str) -> None:
        """Pair-success hook (belt-and-braces follow-up to the
        pairing-target-mac fallback in ``_on_transport_changed``): re-query
        actual BlueZ connection state — the PropertiesChanged subscription
        can race and miss a Connected=True that arrived mid-pairing — and, if
        a transport was already active by the time pairing landed but the
        pump was never armed, arm it now."""
        assert self.state_machine is not None and self.pump is not None and self._ops is not None
        try:
            connected = self._ops.is_connected(mac)
        except Exception:
            logger.exception(
                "bluetooth service: error querying connection state for %s after pairing", mac,
            )
            connected = False
        if connected:
            logger.info("bluetooth service: %s already connected at pairing completion", mac)
        self.state_machine.on_link_state_changed(mac, connected)
        if self._last_transport_active and not self.pump.has_active_source():
            logger.info(
                "bluetooth pump: arming source for %s after pairing completed "
                "(transport was already active)", mac,
            )
            self.pump.set_active_source(
                pump_mod.bluealsa_capture_device(mac), rate=self._last_transport_rate,
            )

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
        if snapshot.get("transport_active"):
            logger.info("bluetooth service: startup sync found an active MediaTransport1 object")
            self._on_transport_changed(True, snapshot.get("transport_rate"))

    def _get_status(self) -> dict:
        """Wraps the state machine's status with the pump's actual state and
        the adapter-power-blocked flag: the state machine's inferred
        ``streaming`` flag alone can be true while the pump itself never got
        armed — ``pump_source_active`` lets callers tell the two apart
        without guessing — and ``adapter_present`` alone cannot distinguish
        "no adapter" from "adapter found but could not be powered on"; the
        additive ``adapter_blocked`` key carries that distinction."""
        status = self.state_machine.get_status()
        status["pump_source_active"] = self.pump.is_streaming() if self.pump is not None else False
        status["adapter_blocked"] = self._adapter_blocked
        return status

    def _on_props_changed(self, mac: str, changed: dict) -> None:
        if "Connected" in changed:
            self.state_machine.on_link_state_changed(mac, bool(changed["Connected"]))

    def _tick_loop(self) -> None:
        while not self._tick_stop.wait(TICK_INTERVAL_SECONDS):
            try:
                self.state_machine.tick()
            except Exception:
                logger.exception("bluetooth service: error in tick loop")
            if not self._bluez_ready:
                self._maybe_retry_adapter()

    def _maybe_retry_adapter(self) -> None:
        """Adapter-absent degradation: retried from
        the tick thread every ADAPTER_RETRY_INTERVAL_SECONDS until an adapter
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

    def _try_connect_bluez(self) -> bool:
        """Attempt to attach to BlueZ and, on success, complete the agent
        registration + signal wiring that requires a live adapter. Idempotent
        once already attached; safe to call repeatedly (startup and retries).
        """
        if self._bluez_ready:
            return True

        dbus = self._dbus
        bluez = bluez_mod.BluezClient(call_timeout=self._call_timeout)
        try:
            bluez.connect()
            bluez.power_on()
            bluez.ensure_not_discoverable()
        except bluez_mod.BluezUnavailable as e:
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

        policy = agent_mod.PairingPolicy(
            pairing_window_open=self.state_machine.pairing_window_open,
            pairing_target_mac=self.state_machine.pairing_target_mac,
            trusted_mac=self.state_machine.trusted_mac,
        )
        agent_class = agent_mod.build_agent_class(dbus)
        self._agent = agent_class(dbus.SystemBus(), agent_mod.AGENT_PATH, policy)
        agent_manager = dbus.Interface(
            dbus.SystemBus().get_object("org.bluez", "/org/bluez"),
            "org.bluez.AgentManager1",
        )
        agent_manager.RegisterAgent(agent_mod.AGENT_PATH, agent_mod.AGENT_CAPABILITY,
                                     timeout=self._call_timeout)
        agent_manager.RequestDefaultAgent(agent_mod.AGENT_PATH, timeout=self._call_timeout)

        bluez.subscribe(
            self.state_machine.on_device_found,
            self._on_props_changed,
            self._on_transport_changed,
        )

        self._sync_startup_state(bluez)

        self._bluez_ready = True
        logger.info("bluetooth service: BlueZ adapter attached")
        return True

    def start(self) -> None:
        import dbus
        import dbus.mainloop.glib
        from gi.repository import GLib

        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        self._dbus = dbus

        # ops/state-machine/pump/control-socket all come up regardless of
        # whether BlueZ (or an adapter) is reachable yet — the systemd unit
        # must never crash-loop just because bluetoothd hasn't started, or
        # no dongle is plugged in.
        self._ops = BluetoothOps()
        self.state_machine = BluetoothStateMachine(ops=self._ops, state_path=self._state_path)
        self.state_machine.set_pair_success_callback(self._on_pair_success)

        self.pump = pump_mod.LoopbackPump(buffer_ms=self.state_machine.get_buffer_ms())
        self.pump.start()
        self.state_machine.set_link_change_callback(
            lambda link_state: self.pump.set_active_source(None) if link_state != LINK_CONNECTED else None
        )
        self.state_machine.set_buffer_change_callback(
            lambda buffer_ms: self.pump.set_buffer_ms(buffer_ms)
        )

        self.control_server = socket_mod.BluetoothControlServer(
            get_status=self._get_status,
            scan_start=lambda: self.state_machine.start_scan(),
            scan_stop=self.state_machine.stop_scan,
            get_scan_results=self.state_machine.get_scan_results,
            pair=self.state_machine.start_pairing,
            get_pair_status=self.state_machine.get_pair_status,
            forget=self.state_machine.forget,
            configure=self.state_machine.set_buffer_ms,
            socket_path=self._socket_path,
        )
        self.control_server.start()

        self._try_connect_bluez()

        self._tick_thread = threading.Thread(target=self._tick_loop, daemon=True, name="bt-tick")
        self._tick_thread.start()

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

    def stop(self) -> None:
        self._tick_stop.set()
        self._disconnect_on_shutdown()
        if self.control_server is not None:
            self.control_server.stop()
        if self.pump is not None:
            self.pump.stop()
        if self._glib_loop is not None:
            self._glib_loop.quit()


def make_sigterm_handler(stop: Callable[[], None]) -> Callable[[int, object], None]:
    """Build a ``signal.signal``-compatible handler that runs *stop*.
    systemd sends SIGTERM on stop/restart; without a
    handler the process dies without unlinking the control socket, stopping
    the pump thread, or unregistering the pairing agent — this makes SIGTERM
    trigger the same clean shutdown as Ctrl-C. Kept as a small, independently
    testable factory rather than inlined so a test can invoke the handler
    against a fake ``stop`` without touching real signal delivery.
    """

    def _handler(signum, frame) -> None:
        logger.info("bluetooth service: received signal %s, shutting down", signum)
        try:
            stop()
        except Exception:
            logger.exception("bluetooth service: error during signal shutdown")

    return _handler


def main() -> None:
    _setup_logging()
    service = BluetoothService()
    signal.signal(signal.SIGTERM, make_sigterm_handler(service.stop))
    try:
        service.start()
    except KeyboardInterrupt:
        pass
    finally:
        service.stop()


if __name__ == "__main__":
    main()
