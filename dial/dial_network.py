"""dial_network.py — the dial's own view of its Wi-Fi link, own thread.

Polls the local Wi-Fi watcher's loopback status endpoint every
NETWORK_POLL_INTERVAL_S, classifies the device state into a link verdict
(connected / down / ignored / unknown), pairs it with the dial's own coarse
signal category (dial_info.wifi_status), and hands the resulting immutable
NetworkView to the display manager (on_view, wired to
DialCore.on_network_view by dial_main.py). The latest view is also kept
here for lock-free reads (latest()), which is how the info page learns
whether the dial is offline.

The worker thread never touches dial_display.DialDisplay._lock; the
callback is called with no lock held. Nothing here ever raises out of the
loop: a failed read yields an UNKNOWN view rather than a down one, so a
single missed poll can never flash the icon or raise the prompt.

request_reboot() asks the local offline-recovery CGI for a full OS reboot,
fire-and-forget on its own short-lived thread, rate-gated so a double tap
cannot queue two reboots. request_shutdown() asks the privileged helper for
a graceful power-off the same way, one request at a time.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import http.client
import json
import logging
import subprocess
import threading
import time
from dataclasses import dataclass

from dial_info import (
    SIGNAL_NORMAL,
    SIGNAL_STRONG,
    SIGNAL_WEAK,
    wifi_status,
)

# The watcher publishes a fresh snapshot every 15 s; polling faster than
# that can only ever re-read the same snapshot.
NETWORK_POLL_INTERVAL_S = 15.0
# One bounded loopback round trip per poll.
NETWORK_REQUEST_TIMEOUT_S = 4.0
# The snapshot is a few KB (a handful of adapters); the cap only stops a
# misbehaving responder from tying the worker up on an unbounded body.
_MAX_RESPONSE_BYTES = 256 * 1024

WATCHER_HOST = "127.0.0.1"
WATCHER_PORT = 9080
WATCHER_STATUS_PATH = "/network_status"
WATCHER_TOKEN_PATH = "/run/autostream/wifi-control.token"
WATCHER_TOKEN_HEADER = "X-Autostream-Wifi-Control"

# The offline recovery page's reboot action, served by the dial's own
# nginx on port 80 and performed by the privileged helper. Same-origin
# guard: the CGI accepts a POST with this header and no Origin header.
REBOOT_HOST = "127.0.0.1"
REBOOT_PORT = 80
REBOOT_PATH = "/offline/reboot"
REBOOT_REQUEST_TIMEOUT_S = 4.0
# A second Restart tap inside this window is ignored: the first reboot is
# already on its way, and the helper's own delay means the box is still up
# for a few seconds after it is asked.
REBOOT_COOLDOWN_S = 60.0

# The privileged helper's power-off verb, run through the dial's own sudo
# grant. The helper waits a few seconds before powering off, so the dial's
# reply has gone out by then.
ADMIN_CMD = "/usr/local/libexec/autostream/autostream_admin"
SHUTDOWN_REQUEST_TIMEOUT_S = 15.0

# Link verdicts, derived from the watcher's device.state.
LINK_CONNECTED = "connected"   # online, degraded
LINK_DOWN = "down"             # offline, recovering
LINK_IGNORED = "ignored"       # setup_mode, reboot_pending: neither flash nor prompt
LINK_UNKNOWN = "unknown"       # no snapshot yet, a failed read, or an unexpected value

_CONNECTED_STATES = frozenset(("online", "degraded"))
_DOWN_STATES = frozenset(("offline", "recovering"))
_IGNORED_STATES = frozenset(("setup_mode", "reboot_pending"))

# Signal category -> number of lit arcs on the idle screen's wifi glyph.
_BARS_FOR_CATEGORY = {SIGNAL_WEAK: 1, SIGNAL_NORMAL: 2, SIGNAL_STRONG: 3}


@dataclass(frozen=True)
class NetworkView:
    """One poll's worth of link state, immutable.

    link: one of the LINK_* verdicts.
    device_state: the watcher's raw device.state string ("" when unknown).
    bars: lit arcs for the idle icon, 0..3 — 0 unless link is connected.
    ssid: the joined SSID as the dial's own probe sees it ("" if none).
    signal: the dial's own coarse category label ("" if none).
    updated_at: time.monotonic() when this view was built.
    """

    link: str = LINK_UNKNOWN
    device_state: str = ""
    bars: int = 0
    ssid: str = ""
    signal: str = ""
    updated_at: float = 0.0


UNKNOWN_VIEW = NetworkView()

_latest: NetworkView = UNKNOWN_VIEW
_on_view = None
_on_tick = None
_stop_event = threading.Event()

_reboot_lock = threading.Lock()
_last_reboot_monotonic: "float | None" = None

_shutdown_lock = threading.Lock()
_shutdown_pending = False


def classify_device_state(state) -> str:
    """The watcher's device.state -> a LINK_* verdict. Pure. Anything that
    is not one of the known strings (including the pre-publish "unknown"
    placeholder) is LINK_UNKNOWN, never LINK_DOWN."""
    if not isinstance(state, str):
        return LINK_UNKNOWN
    if state in _CONNECTED_STATES:
        return LINK_CONNECTED
    if state in _DOWN_STATES:
        return LINK_DOWN
    if state in _IGNORED_STATES:
        return LINK_IGNORED
    return LINK_UNKNOWN


def bars_for_category(category: str) -> int:
    """Weak/Normal/Strong -> 1/2/3; anything else -> 0. Pure."""
    return _BARS_FOR_CATEGORY.get(category, 0)


def latest() -> NetworkView:
    """The most recent view — a plain reference read, safe from any
    thread. UNKNOWN_VIEW until the first poll lands."""
    return _latest


def start_network_worker(*, on_view=None, on_tick=None) -> None:
    """Start the background poll thread. on_view(view) is called after
    every poll with no lock held; on_tick(now) is called after that on the
    same thread, a housekeeping hook for slow readers that piggyback on
    this cadence rather than owning a thread (dial_sdhealth.tick). Either
    callback raising is swallowed by the loop, never allowed to kill the
    thread."""
    global _on_view, _on_tick
    _on_view = on_view
    _on_tick = on_tick
    _stop_event.clear()
    threading.Thread(target=_worker, daemon=True, name="network-worker").start()


def stop_network_worker() -> None:
    """Test hook: end the loop at its next wake."""
    _stop_event.set()


def _read_token() -> str:
    try:
        with open(WATCHER_TOKEN_PATH, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def _fetch_snapshot() -> "dict | None":
    """GET the watcher's status snapshot over loopback with the per-boot
    token. None on any failure: no token, a connection/timeout error, a
    non-200 status, a non-JSON or non-object body, or ok not true."""
    token = _read_token()
    if not token:
        return None
    try:
        conn = http.client.HTTPConnection(WATCHER_HOST, WATCHER_PORT, timeout=NETWORK_REQUEST_TIMEOUT_S)
        try:
            conn.request("GET", WATCHER_STATUS_PATH, headers={WATCHER_TOKEN_HEADER: token})
            resp = conn.getresponse()
            status = resp.status
            raw = resp.read(_MAX_RESPONSE_BYTES)
        finally:
            conn.close()
    except Exception:
        return None
    if status != 200:
        return None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(parsed, dict) or parsed.get("ok") is not True:
        return None
    return parsed


def _view_from_snapshot(snapshot: "dict | None", now: float) -> NetworkView:
    """Build the view for one poll. The signal probe runs only for a
    connected link: there is nothing to grade while offline, and skipping
    it keeps a down dial from spawning a network tool every poll."""
    device = snapshot.get("device") if isinstance(snapshot, dict) else None
    state = device.get("state") if isinstance(device, dict) else None
    link = classify_device_state(state)
    ssid, signal, bars = "", "", 0
    if link == LINK_CONNECTED:
        try:
            probed_ssid, category = wifi_status()
        except Exception:
            probed_ssid, category = "", ""
        if probed_ssid and probed_ssid != "-":
            ssid = probed_ssid
        bars = bars_for_category(category)
        signal = category if bars else ""
    return NetworkView(
        link=link, device_state=state if isinstance(state, str) else "",
        bars=bars, ssid=ssid, signal=signal, updated_at=now,
    )


def poll_once(now: "float | None" = None) -> NetworkView:
    """One poll: fetch, classify, publish as latest(). Never raises."""
    global _latest
    if now is None:
        now = time.monotonic()
    try:
        view = _view_from_snapshot(_fetch_snapshot(), now)
    except Exception:
        view = NetworkView(updated_at=now)
    _latest = view
    return view


def _worker() -> None:
    while not _stop_event.is_set():
        view = poll_once()
        if _on_view is not None:
            try:
                _on_view(view)
            except Exception:
                logging.debug("dial network: on_view callback raised", exc_info=True)
        if _on_tick is not None:
            try:
                _on_tick(time.monotonic())
            except Exception:
                logging.debug("dial network: on_tick callback raised", exc_info=True)
        _stop_event.wait(NETWORK_POLL_INTERVAL_S)


def _reboot_allowed(now: float) -> bool:
    """Reserve the reboot slot, refusing a second request inside
    REBOOT_COOLDOWN_S of the first — reserved before the request is sent
    so two taps racing each other cannot both pass."""
    global _last_reboot_monotonic
    with _reboot_lock:
        last = _last_reboot_monotonic
        if last is not None and (now - last) < REBOOT_COOLDOWN_S:
            return False
        _last_reboot_monotonic = now
        return True


def _post_reboot() -> "int | None":
    """POST the reboot action to the local recovery endpoint. Returns the
    HTTP status (302 on success) or None on a transport failure. Never
    raises. Never follows the redirect — the box is about to go down."""
    try:
        conn = http.client.HTTPConnection(REBOOT_HOST, REBOOT_PORT, timeout=REBOOT_REQUEST_TIMEOUT_S)
        try:
            conn.request(
                "POST", REBOOT_PATH, body=b"",
                headers={"X-Requested-With": "XMLHttpRequest", "Content-Length": "0"},
            )
            resp = conn.getresponse()
            resp.read(_MAX_RESPONSE_BYTES)
            return resp.status
        finally:
            conn.close()
    except Exception:
        return None


def _reboot_thread() -> None:
    status = _post_reboot()
    if status in (302, 200):
        logging.info("dial network: reboot requested (status %s)", status)
    else:
        logging.warning("dial network: reboot request failed (status %s)", status)


def request_reboot(now: "float | None" = None) -> bool:
    """Ask for a full OS reboot, fire-and-forget: reserves the cooldown
    slot and starts a short-lived daemon thread for the request. Returns
    False (and does nothing) while the cooldown holds. Does no I/O on the
    calling thread, so it is safe from the touch thread. Never raises."""
    if now is None:
        now = time.monotonic()
    try:
        if not _reboot_allowed(now):
            logging.warning("dial network: reboot refused — cooldown active")
            return False
        threading.Thread(target=_reboot_thread, daemon=True, name="dial-reboot").start()
        return True
    except Exception:
        logging.debug("dial network: request_reboot raised", exc_info=True)
        return False


def _shutdown_thread() -> None:
    """Run the helper's power-off verb. A request that did not go through
    frees the slot, so the person can ask again; one that did keeps it, as
    the box is going down."""
    global _shutdown_pending
    try:
        done = subprocess.run(
            ["sudo", "-n", ADMIN_CMD, "poweroff"],
            capture_output=True, timeout=SHUTDOWN_REQUEST_TIMEOUT_S,
        )
        ok = done.returncode == 0
    except Exception:
        ok = False
    if ok:
        logging.info("dial network: shutdown requested")
        return
    logging.warning("dial network: shutdown request failed")
    with _shutdown_lock:
        _shutdown_pending = False


def request_shutdown() -> bool:
    """Ask for a graceful power-off, fire-and-forget: starts a short-lived
    daemon thread for the request. Returns False (and does nothing) while an
    earlier request is still in hand. Does no I/O on the calling thread.
    Never raises."""
    global _shutdown_pending
    try:
        with _shutdown_lock:
            if _shutdown_pending:
                logging.warning("dial network: shutdown refused - already requested")
                return False
            _shutdown_pending = True
        threading.Thread(target=_shutdown_thread, daemon=True, name="dial-shutdown").start()
        return True
    except Exception:
        logging.debug("dial network: request_shutdown raised", exc_info=True)
        with _shutdown_lock:
            _shutdown_pending = False
        return False
