"""autostream_services -- coordinator work that runs beside the poll loop until
the process stops: the capture-device and Bluetooth scan (with the Bluetooth
rate-follow and lockout-heal reloads), the dial and appliance scanners, the
dial warnings watcher, the appliance announcement, the cross-appliance output
usage poller, and the one-off identification-provider version read. The
device scan publishes the devices part.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Optional, Sequence

import autostream_appliances as appliances
import autostream_dial_warnings as dial_warnings
import autostream_dials as dials
import autostream_federation as federation
import autostream_monitor_client as monitor_client
import autostream_output_usage as output_usage
import autostream_runtime as runtime
import autostream_state
from autostream_bluetooth_client import (
    BluetoothClient,
    bluetooth_capture_label,
    bluetooth_installed,
    classify_loopback_hw,
)
from autostream_intents import Intent, Origin, submit

_OWNER = "autostream_services"
_devices_writer = autostream_state.store().claim("devices", _OWNER)

# Cooldown between lockout-triggered config reloads (_lockout_heal_check):
# a reload bounces the monitor's inputs, which is disruptive if repeated
# faster than the other end could plausibly release and re-pin the cable.
LOCKOUT_RELOAD_COOLDOWN_SECONDS = 120.0


def normalize_monitor_devices(
    devices: Optional[list[dict]],
    bluetooth_status: Optional[dict] = None,
    *,
    bluetooth_enabled: Optional[bool] = None,
) -> list[dict]:
    """Normalize list_devices() results into a stable Web UI-friendly shape.

    Each returned dict contains:
      - hw: ALSA hardware identifier such as "hw:1,0"
      - card: ALSA card description (may be empty)
      - name: ALSA device description (may be empty)
      - label: user-facing text combining card/device/hw

    Bluetooth relabel hook, active only when the Bluetooth-input subsystem
    is installed on this appliance: the loopback
    playback side (``CARD=ASBT,DEV=0``) is dropped entirely (it is not a
    selectable input), and the capture side (``CARD=ASBT,DEV=1``) is
    relabelled to "Bluetooth: <name>" / "Bluetooth (not paired)" /
    "Bluetooth (service unavailable)" using ``bluetooth_status`` (the
    cached-or-live daemon status; None is treated as "service
    unavailable").  ``bluetooth_enabled`` lets callers (tests) force the
    on/off branch explicitly; when omitted it is resolved from whether the
    Bluetooth-input subsystem is installed via ``bluetooth_installed()``
    (the relabel applies whenever the loopback card can exist, regardless
    of whether the service is currently enabled/running).  When the
    subsystem isn't installed, behaviour is byte-identical to before this
    hook existed -- the ASBT card cannot exist on such an appliance in any
    case.
    """
    bt_on = bluetooth_enabled if bluetooth_enabled is not None else bluetooth_installed()

    normalized: list[dict] = []

    for dev in devices or []:
        hw = str(dev.get("hw") or "").strip()
        if not hw:
            continue

        loopback_kind = classify_loopback_hw(hw) if bt_on else None
        if loopback_kind == "playback":
            continue

        card = str(dev.get("card") or "").strip()
        name = str(dev.get("name") or "").strip()

        label_parts = [part for part in (card, name) if part]
        label = " - ".join(label_parts) if label_parts else hw
        if hw not in label:
            label = f"{label} ({hw})"

        if loopback_kind == "capture":
            label = bluetooth_capture_label(bluetooth_status)

        normalized.append({
            "hw": hw,
            "card": card,
            "name": name,
            "label": label,
        })

    normalized.sort(key=lambda d: (d["label"].casefold(), d["hw"].casefold()))
    return normalized


def get_available_monitor_devices(
    socket_path: Optional[str] = None,
    bluetooth_status: Optional[dict] = None,
) -> list[dict]:
    """Return currently visible monitor devices from autostream_monitor.

    Uses a short-lived MonitorClient connection so callers outside the main
    coordinator loop can safely query available ALSA capture devices.
    Returns an empty list if the daemon is unavailable or the command fails.
    ``bluetooth_status`` is threaded through to ``normalize_monitor_devices()``
    for the Bluetooth relabel hook (see there); callers that don't pass it
    get the "service unavailable" label whenever Bluetooth mode is on.
    """
    try:
        with monitor_client._connected_monitor(socket_path) as client:
            if client is None:
                return []
            return normalize_monitor_devices(client.list_devices(), bluetooth_status)
    except Exception as e:
        logging.warning("Could not query autostream_monitor devices: %s", e)
        return []


def _bluetooth_input_configured(settings) -> bool:
    """True when either monitor input is configured on the Bluetooth
    loopback's capture side."""
    try:
        cfg = settings.snapshot()
    except Exception:
        return False
    return any(
        classify_loopback_hw(dev) == "capture"
        for dev in (cfg.audio1.capture_device, cfg.audio2.capture_device)
        if dev
    )


def _rate_follow_check(settings, bluetooth_status: Optional[dict],
                       last_cable_rate: Optional[int]) -> Optional[int]:
    """One rate-follow step: returns the updated last-seen cable rate.

    The loopback cable's rate follows the Bluetooth transport, and the
    monitor's capture side can only renegotiate by being reopened -- so a
    rate change while a Bluetooth input is configured triggers a
    coordinator config reload, which bounces the inputs through the same
    gated start-up path used at boot (the monitor reopens after the pump
    already holds the cable at the new rate).

    ``sample_rate`` is only present in the status while a transport is
    active; polls without it (transport gaps, unreachable service) leave
    the last-seen value untouched, so a plain reconnect at the same rate
    never triggers a reload -- only an observed rate CHANGE does.
    """
    rate = (bluetooth_status or {}).get("sample_rate")
    if not isinstance(rate, int) or isinstance(rate, bool) or rate <= 0:
        return last_cable_rate
    if (
        last_cable_rate is not None
        and rate != last_cable_rate
        and _bluetooth_input_configured(settings)
    ):
        logging.info(
            "Bluetooth transport rate changed %d Hz -> %d Hz; "
            "reloading monitor inputs to renegotiate the loopback.",
            last_cable_rate, rate,
        )
        submit(Intent("settings.reload", {"reason": "bluetooth rate follow"},
                      Origin.SYSTEM, "coordinator"))
    return rate


def _lockout_heal_check(settings, bluetooth_status: Optional[dict],
                        lockout_streak: int,
                        last_heal_reload: Optional[float]) -> tuple:
    """One lockout-healing step: returns the updated
    ``(lockout_streak, last_heal_reload)``.

    A sustained ``loopback_locked_out`` means the pump's capture-side peer
    pinned the shared cable at incompatible parameters while the pump was
    absent, and the pump alone cannot force a release -- only the monitor
    reopening its capture side renegotiates the cable. Reloading on the
    first observed lockout would over-react to a single transient poll, so
    the reload fires only once the lockout has been seen on two consecutive
    polls (and only while a Bluetooth input is actually configured), and no
    more often than ``LOCKOUT_RELOAD_COOLDOWN_SECONDS``.
    """
    locked_out = bool((bluetooth_status or {}).get("loopback_locked_out", False))
    if not locked_out:
        return 0, last_heal_reload

    lockout_streak += 1
    now = time.monotonic()
    cooldown_elapsed = (
        last_heal_reload is None or now - last_heal_reload >= LOCKOUT_RELOAD_COOLDOWN_SECONDS
    )
    if (
        lockout_streak >= 2
        and cooldown_elapsed
        and _bluetooth_input_configured(settings)
    ):
        logging.info(
            "Bluetooth loopback held at incompatible parameters with a "
            "Bluetooth input configured; reloading monitor inputs to "
            "renegotiate the cable.",
        )
        submit(Intent("settings.reload", {"reason": "bluetooth lockout heal"},
                      Origin.SYSTEM, "coordinator"))
        lockout_streak = 0
        last_heal_reload = now
    return lockout_streak, last_heal_reload

def _publish_devices(devices: list, bluetooth_status: Optional[dict]) -> None:
    """Publish the scan's result as the devices part: the list cleaned the way
    the Setup page reads it, and the Bluetooth status as fetched."""
    cleaned: list[dict[str, str]] = []
    for dev in devices:
        if not isinstance(dev, dict):
            continue
        hw = str(dev.get("hw") or "").strip()
        if not hw:
            continue
        cleaned.append({
            "hw": hw,
            "card": str(dev.get("card") or "").strip(),
            "name": str(dev.get("name") or "").strip(),
            "label": str(dev.get("label") or hw).strip(),
        })
    _devices_writer.publish(autostream_state.DevicesPart(
        tuple(cleaned),
        bluetooth_status if isinstance(bluetooth_status, dict) else None,
    )).notify()


def _device_scan_loop(life: runtime.Lifecycle, settings) -> None:
    """Background loop: refresh visible ALSA capture devices (and, when
    the Bluetooth-input subsystem is installed, the autostream_bluetooth
    daemon status) every 15 s. Each poll also runs the Bluetooth
    rate-follow step (_rate_follow_check) and the lockout-healing step
    (_lockout_heal_check).
    """
    last_cable_rate: Optional[int] = None
    lockout_streak = 0
    last_heal_reload: Optional[float] = None
    while not life.stopping():
        bluetooth_status: Optional[dict] = None
        if bluetooth_installed():
            try:
                bluetooth_status = BluetoothClient().status()
            except Exception as e:
                logging.error(
                    "Web UI: error querying autostream_bluetooth status: %s", e,
                )
                bluetooth_status = None

        try:
            devices = get_available_monitor_devices(bluetooth_status=bluetooth_status)
        except Exception as e:
            logging.error(
                "Web UI: error scanning autostream_monitor devices: %s", e,
            )
            devices = []

        try:
            last_cable_rate = _rate_follow_check(settings, bluetooth_status, last_cable_rate)
        except Exception:
            logging.debug("bluetooth rate-follow check failed", exc_info=True)

        try:
            lockout_streak, last_heal_reload = _lockout_heal_check(
                settings, bluetooth_status, lockout_streak, last_heal_reload,
            )
        except Exception:
            logging.debug("bluetooth lockout-heal check failed", exc_info=True)

        _publish_devices(devices, bluetooth_status)
        time.sleep(15)


def _announcement_loop(
    life: runtime.Lifecycle,
    settings,
    app_version: Callable[[], str],
    sweeps: Sequence[Callable[[], None]],
) -> None:
    """Reconcile the _autostream._tcp service file once at start, then every
    60 s, with the session sweep and each of *sweeps* before each reconcile."""

    def _reconcile() -> None:
        appliances.reconcile_appliance_announcement(
            app_version(), settings.snapshot().webui.advertise_appliance
        )

    # Initial announcement reconciliation (best-effort; errors are logged)
    try:
        _reconcile()
    except Exception:
        logging.debug("startup reconcile_announcement: error", exc_info=True)

    while not life.stopping():
        life.wait(60)
        if life.stopping():
            break
        try:
            federation.sweep_sessions()
        except Exception:
            logging.debug("sweep_sessions: error", exc_info=True)
        for fn in sweeps:
            try:
                fn()
            except Exception:
                logging.debug("%s: error", getattr(fn, "__name__", "sweep"), exc_info=True)
        try:
            _reconcile()
        except Exception:
            logging.debug("reconcile_announcement_loop: error", exc_info=True)


def start(
    life: runtime.Lifecycle,
    settings,
    *,
    app_version: Callable[[], str],
    sweeps: Sequence[Callable[[], None]] = (),
    on_peer_removed: Sequence[Callable[[str], None]] = (),
) -> None:
    """Start the dial and appliance scanners, the dial warnings watcher and
    the device-scan, announcement and identification-provider threads. Called
    once, before the web server starts. Each *on_peer_removed* callable is
    registered with the appliance registry before its scanner starts, and is
    called with the id of a peer that has gone."""
    try:
        dials.start_dial_scanner(shutdown_event=life.stop)
        dial_warnings.start_watcher(shutdown_event=life.stop)
        for fn in on_peer_removed:
            appliances.register_peer_removal_callback(fn)
        appliances.start_appliance_scanner(shutdown_event=life.stop)

        threading.Thread(
            target=_device_scan_loop, args=(life, settings),
            name="device-scan", daemon=True,
        ).start()
        threading.Thread(
            target=_announcement_loop, args=(life, settings, app_version, tuple(sweeps)),
            name="announce-reconcile", daemon=True,
        ).start()

        # Best-effort one-shot Vibra Mini version discovery before accepting
        # requests.  Runs in a daemon thread so it never delays startup.
        from track_id.vibra_shazam import refresh_vibra_runtime_info
        threading.Thread(
            target=refresh_vibra_runtime_info,
            name="vibra-runtime-refresh",
            daemon=True,
        ).start()
    except Exception:
        logging.exception("Background services error")
        raise


def start_output_usage_poller(cfg, life: runtime.Lifecycle) -> None:
    """Best-effort start/update of the cross-appliance output usage poller."""
    try:
        output_usage.configure(cfg.webui.output_usage_poll_interval_seconds)
        output_usage.start(shutdown_event=life.stop)
    except Exception:
        logging.warning("output-usage: failed to start poller", exc_info=True)


def stop_discovery() -> None:
    """Best-effort shutdown of all process-lifetime mDNS discovery services.

    Called once after the coordinator outer loop exits (including on SIGINT,
    SIGTERM, and unexpected exceptions).  Never called during a configuration
    reload.  All operations are idempotent.
    """
    try:
        output_usage.stop()
    except Exception:
        logging.debug("stop_discovery: output_usage.stop() raised", exc_info=True)
    try:
        dials.stop_dial_scanner()
    except Exception:
        logging.debug("stop_discovery: stop_dial_scanner() raised", exc_info=True)
    try:
        appliances.stop_appliance_scanner()
    except Exception:
        logging.debug("stop_discovery: stop_appliance_scanner() raised", exc_info=True)
