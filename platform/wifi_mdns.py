#!/usr/bin/python3
"""wifi_mdns.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Avahi / mDNS hostname monitoring and host-record re-announcement for the
Autostream Wi-Fi watcher (follow-on plan, WS2-WP1 split of platform/wifi_watcher).

This module owns the two mDNS concerns the watcher previously carried inline:
  * hostname-drift repair (avahi renames itself on an mDNS conflict; we detect the
    mismatch, wait out a grace period, then restart avahi-daemon so it reclaims the
    expected name — rate-limited and capped per boot), and
  * the address-set re-announce debounce (a network-path change, e.g. a removed USB
    adapter, must trigger a host-record re-announce so clients drop stale
    ``<hostname>.local`` answers; explicit handovers nudge the same debounce).

To keep the extraction mechanical and behaviour-preserving, every function takes
the watcher module ``w`` as its first argument and reads its STATE, constants,
``run_cmd``/``logger``/``log_on_change``/``get_system_hostname`` and the sibling
mDNS helpers through it (so a test that patches ``wifi_watcher.<name>`` still
intercepts an internal call).  ``autostream_wifi_network`` is imported directly
because it is a shared module object (patching it affects both modules).
"""
from __future__ import annotations

import logging
import time
from typing import Optional

import autostream_wifi_network as wifi_net


def get_avahi_registered_hostname(w) -> Optional[str]:
    """Query the mDNS hostname avahi-daemon is currently registered under.

    Uses the avahi D-Bus interface (org.freedesktop.Avahi.Server.GetHostName).
    Returns the bare hostname (without .local), or None on any failure.
    """
    if w._DBUS_SEND is None:
        return None

    result = w.run_cmd(
        [
            w._DBUS_SEND,
            "--system",
            "--print-reply",
            "--dest=org.freedesktop.Avahi",
            "/",
            "org.freedesktop.Avahi.Server.GetHostName",
        ],
        timeout=3.0,
    )
    if result.returncode != 0:
        w.logger.debug("avahi D-Bus query failed (rc=%d): %s",
                       result.returncode, result.stderr.strip())
        return None

    # dbus-send --print-reply output contains a line like:  string "sl-d303-2"
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith('string "') and stripped.endswith('"'):
            hostname = stripped[8:-1]
            if hostname:
                return hostname

    return None


def restart_avahi_daemon(w, reason: str) -> bool:
    """Restart avahi-daemon to force mDNS host/service re-announcement."""
    result = w.run_cmd(["systemctl", "restart", "avahi-daemon.service"],
                       timeout=w.NMCLI_QUICK_TIMEOUT)
    if result.returncode != 0:
        w.logger.error(
            "avahi-daemon restart failed (%s, rc=%d): %s",
            reason,
            result.returncode,
            result.stderr.strip(),
        )
        return False
    w.logger.info(
        "avahi-daemon restarted (%s); hostname will be verified on next check",
        reason,
    )
    return True


def mark_mdns_reannounce_pending(w, reason: str) -> None:
    """Request a debounced mDNS host-record re-announce from the monitor loop.

    Orchestrated handovers call this instead of restarting avahi directly so the
    re-announce is debounced behind the address set settling (avoiding a restart
    that re-announces the address being torn down) and de-duplicated with the
    passive address-change detector (maybe_reannounce_mdns).
    """
    now = time.monotonic()
    with w.state_lock:
        w.STATE.mdns_reannounce_pending = True
        # Anchor the debounce so the loop waits for the path to settle before
        # restarting, even when our observed address set looks unchanged.
        w.STATE.mdns_address_changed_at = now
    w.logger.info(
        "mDNS re-announce requested (%s); will fire once the address set settles",
        reason,
    )


def _current_mdns_address_set(w) -> frozenset:
    """Return the set of (ifname, ipv4) the host currently publishes via mDNS.

    Proxy for avahi-daemon's published host address records: every usable
    non-link-local unicast IPv4 on a non-loopback interface.  Used to detect
    network-path changes (e.g. a removed USB adapter) that require a host-record
    re-announce so clients drop stale ``<hostname>.local`` answers.
    """
    pairs: set = set()
    try:
        for ifname, addrs in wifi_net.list_interface_addresses().items():
            if ifname == "lo":
                continue
            for addr in addrs:
                if addr.get("family") != "ipv4":
                    continue
                ip = addr.get("address", "")
                if wifi_net.is_usable_unicast_ipv4(ip):
                    pairs.add((ifname, ip))
    except Exception as e:
        w.logger.debug("mDNS address-set probe failed: %s", e)
    return frozenset(pairs)


def maybe_reannounce_mdns(w, now: float) -> None:
    """Re-announce avahi host records when the published address set changes.

    Detects passive network-path changes (e.g. a USB Wi-Fi dongle removed while
    ethernet stays up) as well as explicit handover requests (via
    mark_mdns_reannounce_pending).  Once the address set has been stable for
    AVAHI_REANNOUNCE_DEBOUNCE seconds — and no re-announce has run within
    AVAHI_HANDOVER_RESTART_MIN_INTERVAL — it restarts avahi-daemon so it re-probes
    and re-announces its host address records (with the mDNS cache-flush bit) for
    the surviving interfaces only.  The first observation each boot only
    establishes a baseline; it never re-announces.
    """
    current = w._current_mdns_address_set()
    fire = False
    with w.state_lock:
        previous = w.STATE.mdns_address_set

        if previous != current:
            w.STATE.mdns_address_set = current

        if previous is None:
            # First observation: establish a baseline without re-announcing.  Any
            # handover that already marked a pending nudge is honoured on the next
            # pass once the set is seen as stable.
            return

        if current != previous:
            # Address set changed this pass; (re)start the debounce timer and wait
            # for it to settle before acting so flapping cannot re-poison clients.
            w.STATE.mdns_address_changed_at = now
            w.logger.info(
                "mDNS published address set changed -> %s; scheduling re-announce",
                sorted(current),
            )
            return

        # Set unchanged this pass.  A re-announce is due only when something armed
        # the debounce (a prior change or an explicit handover nudge).
        changed_at = w.STATE.mdns_address_changed_at
        if changed_at is None and not w.STATE.mdns_reannounce_pending:
            return
        if changed_at is not None and (now - changed_at) < w.AVAHI_REANNOUNCE_DEBOUNCE:
            return

        last_restart = w.STATE.last_avahi_handover_restart
        if (
            last_restart is not None
            and (now - last_restart) < w.AVAHI_HANDOVER_RESTART_MIN_INTERVAL
        ):
            # A recent re-announce is still within the rate-limit window; leave the
            # trigger armed and retry on a later pass rather than dropping it.
            w.logger.debug(
                "mDNS re-announce suppressed by rate limit (%.0fs remaining)",
                w.AVAHI_HANDOVER_RESTART_MIN_INTERVAL - (now - last_restart),
            )
            return

        # Commit: consume the trigger and record the restart time under the lock.
        w.STATE.mdns_address_changed_at = None
        w.STATE.mdns_reannounce_pending = False
        w.STATE.last_avahi_handover_restart = now
        fire = True

    if fire:
        w.logger.info("re-announcing mDNS host records after network-path change")
        w.restart_avahi_daemon("network-path re-announce")


def check_and_repair_avahi_hostname(w) -> None:
    """Check avahi's registered mDNS hostname and restart avahi if it has drifted.

    avahi renames itself (e.g. sl-d303 -> sl-d303-2) on detecting an mDNS host-name
    conflict.  This can be a false positive — for example, after WiFi AP roaming where
    a ghost mDNS record triggers a spurious probe conflict.  We apply a grace period
    (AVAHI_MISMATCH_GRACE) before acting, so transient conflicts resolve themselves.
    If the mismatch persists we restart avahi-daemon so it re-probes and reclaims the
    correct hostname.  Restarts are rate-limited and capped at AVAHI_MAX_RESTART_ATTEMPTS
    per boot to avoid persistent hammering when a genuine conflict cannot be resolved.
    """
    if w._DBUS_SEND is None:
        w.log_on_change(
            "avahi_dbus_unavailable", True,
            "dbus-send not found; avahi mDNS hostname monitoring disabled",
            logging.WARNING,
        )
        return

    avahi_host = w.get_avahi_registered_hostname()
    if avahi_host is None:
        # avahi temporarily unreachable (e.g. mid-restart); skip silently
        return

    # Expected: system hostname, lower-cased (avahi normalises to lowercase for mDNS)
    expected = w.get_system_hostname()
    if expected.lower().endswith(".local"):
        expected = expected[:-6]
    expected = expected.lower()

    now = time.monotonic()

    with w.state_lock:
        w.STATE.avahi_hostname = avahi_host

    if avahi_host.lower() == expected:
        with w.state_lock:
            was_mismatched = w.STATE.avahi_mismatch_start is not None
            w.STATE.avahi_mismatch_start = None
            w.STATE.avahi_restart_count = 0
        if was_mismatched:
            w.logger.info("avahi mDNS hostname restored to expected value '%s'", avahi_host)
        else:
            w.logger.debug("avahi mDNS hostname OK: '%s'", avahi_host)
        return

    # --- Mismatch ---
    with w.state_lock:
        if w.STATE.avahi_mismatch_start is None:
            w.STATE.avahi_mismatch_start = now
            w.logger.warning(
                "avahi mDNS hostname mismatch detected: avahi='%s', expected='%s'",
                avahi_host, expected,
            )
        mismatch_duration = now - w.STATE.avahi_mismatch_start
        restart_count = w.STATE.avahi_restart_count
        last_restart = w.STATE.last_avahi_restart

    # Give up after the maximum number of restart attempts (disabled when -1)
    if w.AVAHI_MAX_RESTART_ATTEMPTS >= 0 and restart_count >= w.AVAHI_MAX_RESTART_ATTEMPTS:
        w.log_on_change(
            "avahi_conflict_exhausted", avahi_host,
            f"avahi mDNS hostname conflict unresolved after {restart_count} restart(s); "
            f"avahi='{avahi_host}', expected='{expected}'. "
            f"No further attempts until reboot.",
            logging.WARNING,
        )
        return

    # Wait for the grace period to expire before acting
    if mismatch_duration < w.AVAHI_MISMATCH_GRACE:
        return

    # Rate-limit restart attempts
    if last_restart is not None and (now - last_restart) < w.AVAHI_RESTART_MIN_INTERVAL:
        return

    with w.state_lock:
        w.STATE.last_avahi_restart = now
        w.STATE.avahi_restart_count += 1
        new_count = w.STATE.avahi_restart_count

    attempt_str = (
        f"{new_count}/{w.AVAHI_MAX_RESTART_ATTEMPTS}"
        if w.AVAHI_MAX_RESTART_ATTEMPTS >= 0
        else str(new_count)
    )
    w.logger.warning(
        "avahi mDNS hostname mismatch persisted for %.0fs; "
        "restarting avahi-daemon (attempt %s); avahi='%s', expected='%s'",
        mismatch_duration, attempt_str, avahi_host, expected,
    )

    w.restart_avahi_daemon("hostname mismatch repair")
