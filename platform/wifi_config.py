#!/usr/bin/python3
"""wifi_config.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Configured-network reconnect and first-boot Wi-Fi profile import/migration for
the Autostream Wi-Fi watcher.

This module owns the two "which profile does NetworkManager know about, and
which one is ours" concerns the watcher previously carried inline:
  * the steady-state reconnect path used by the runtime reliability handler
    (``connect_to_configured_wifi``), which is fire-and-forget and defers to
    the monitor loop for validation, and
  * first-boot adoption of the machine's existing Wi-Fi state as the single
    managed profile, plus the every-boot autoconnect=no sweep that keeps NM
    from racing the watcher onto a stale profile.

Every function takes a :class:`ConfigContext` as its first argument — a narrow
view of the watcher exposing only the constants and callables this module
uses (the ``w`` seam narrowed, WP-11).  The watcher constructs the context
once and passes it where the whole module used to go.
``autostream_wifi_network`` is imported directly because it is a shared
module object (patching it affects both modules).
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Callable, Optional

import autostream_wifi_network as wifi_net


@dataclass
class ConfigContext:
    """Narrow view of the watcher that the config/first-boot helpers depend on.

    Constructed once by the watcher and passed to every function here.  It
    carries the NetworkManager client singleton, the state-file paths and the
    small set of watcher callables the helpers invoke — nothing else of the
    watcher is reachable from this module.
    """

    nm: object
    logger: logging.Logger
    NETWORK_STATE_PATH: str
    CONFIGURED_SSID: str
    FIRST_BOOT_IMPORT_MARKER: str
    get_configured_network_state: Callable
    is_wifi_client_healthy: Callable
    _activation_network_absent: Callable
    _commit_network_state: Callable


def connect_to_configured_wifi(ctx: ConfigContext) -> bool:
    """Attempt to bring up the configured WiFi client connection on the built-in.

    Returns True if nmcli was invoked (best-effort), False if there is no configured
    connection to try.  This is the built-in reconnect path used by the runtime
    reliability handler; the boot USB-first/onboard bring-up runs through the
    recovery ladder (step_boot_client_bringup), not this function.
    """
    state = ctx.get_configured_network_state()
    if not state.is_configured:
        return False
    connection_name = state.connection_name

    # If the configured WiFi is already healthy, do not disturb it.
    if ctx.is_wifi_client_healthy():
        ctx.logger.debug("Configured WiFi '%s' already healthy; no action needed", connection_name)
        return True

    # Resolve the UUID and clear cross-adapter restrictions before (re)activating,
    # so a legacy profile pinned to another adapter can reconnect on this
    # steady-state path exactly as it would at every other join site.  This is
    # fire-and-forget — no blocking IPv4 wait is added to the monitor loop (the
    # loop validates on a later pass) — and no ifname is pinned, so NM's adapter
    # selection is unchanged.
    uuid = _resolve_committed_uuid(ctx, state)
    if uuid:
        ctx.nm.clear_restrictions(uuid, wifi_net.CROSS_ADAPTER_RESTRICTIONS)
        # No ifname is pinned here, so NM chooses the adapter; it must not inherit
        # a BSSID pinned for a specific USB adapter.
        ctx.nm.set_bssid(uuid, "")
    ctx.logger.info("Attempting to connect to configured WiFi connection '%s'", connection_name)
    ident = ["uuid", uuid] if uuid else ["id", connection_name]
    r_up = ctx.nm.activate_ident(ident)
    if ctx._activation_network_absent(r_up):
        ctx.logger.info("Configured network '%s' not visible; reconnect deferred", connection_name)
    elif r_up.returncode != 0:
        ctx.logger.warning("nmcli connection up '%s' failed (rc=%d): %s",
                           connection_name, r_up.returncode, r_up.stderr.strip())
    return True


def migrate_client_profiles_autoconnect_no(ctx: ConfigContext) -> int:
    """Idempotently disable NM autoconnect on every managed non-AP Wi-Fi
    client profile at boot (self-healing).

    Newly-committed profiles are created with autoconnect=no, but a profile may
    pre-exist the install (OS/user-created, or imported by the installer with
    autoconnect=yes).  Running this every boot ensures no client profile can race
    the watcher's single-decider path onto a stale radio.  AP (hotspot) profiles
    are skipped so the recovery hotspot is unaffected.  Best-effort: a per-profile
    nmcli failure is logged and does not abort the sweep.  Returns the number of
    client profiles for which the modify succeeded.
    """
    modified = 0
    for uuid, name in wifi_net.list_wifi_connection_profiles():
        if wifi_net.wifi_profile_mode(uuid or name) == "ap":
            continue
        r = ctx.nm.set_autoconnect_no(uuid, name)
        if r.returncode == 0:
            modified += 1
        else:
            ctx.logger.warning("autoconnect=no migration failed for '%s' (rc=%d): %s",
                               name or uuid, r.returncode, r.stderr.strip())
    if modified:
        ctx.logger.info("D-WP2: ensured autoconnect=no on %d client profile(s)", modified)
    return modified


def _write_first_boot_import_marker(ctx: ConfigContext) -> None:
    """Atomically write the first-boot import marker (best-effort)."""
    try:
        directory = os.path.dirname(ctx.FIRST_BOOT_IMPORT_MARKER) or "."
        os.makedirs(directory, exist_ok=True)
        wifi_net._atomic_write(
            ctx.FIRST_BOOT_IMPORT_MARKER,
            "first-boot Wi-Fi import completed\n",
            mode=0o644,
        )
    except OSError as e:
        ctx.logger.warning("Could not persist first-boot import marker: %s", e)


def _active_wifi_connections(adapters: list) -> "list[tuple[str, str]]":
    """Return ``(ifname, connection_name)`` for each Wi-Fi adapter carrying an
    active (connected) client connection."""
    active = []
    for a in adapters:
        name = wifi_net.get_active_wifi_connection_name(a.ifname)
        if name:
            active.append((a.ifname, name))
    return active


def import_first_boot_wifi_profile(ctx: ConfigContext) -> None:
    """First-boot: adopt the machine's Wi-Fi state as the single managed profile.

    AutoStream owns the whole machine, so on the first boot after adoption the
    currently connected Wi-Fi profile is imported as the one managed profile and
    every other saved (non-AP) Wi-Fi profile is deleted, so NetworkManager cannot
    race the watcher onto a stale OS/user/installer profile.  Guarded by a
    persisted marker so it runs at most once; the destructive delete only ever
    bites when a genuinely first-adopted machine carries pre-existing profiles.

    Flow: skip if the marker exists; query active Wi-Fi connections (exactly one
    -> retain it, more than one -> retain the default-route carrier); commit the
    retained profile to network.json (+ legacy mirror), disable its autoconnect
    immediately, delete every other saved non-AP Wi-Fi profile (per-profile
    failure logged and tolerated), and write the marker.  With no active Wi-Fi
    profile nothing is deleted — the saved profiles stay autoconnect-disabled and
    the normal first-run hotspot owns setup — but the marker is still written so
    the check is idempotent.  Every retained/deleted profile is logged at INFO.
    """
    if os.path.exists(ctx.FIRST_BOOT_IMPORT_MARKER):
        ctx.logger.debug("First-boot Wi-Fi import already done; skipping")
        return
    try:
        adapters = wifi_net.discover_adapters()
        active = _active_wifi_connections(adapters)

        if not active:
            # No active Wi-Fi profile: delete nothing, leave saved profiles
            # autoconnect-disabled, and let the first-run hotspot own setup.
            ctx.logger.info(
                "First-boot Wi-Fi import: no active Wi-Fi profile; leaving saved "
                "profiles untouched (autoconnect already disabled)")
            _write_first_boot_import_marker(ctx)
            return

        if len(active) == 1:
            retain_ifname, retain_name = active[0]
        else:
            # Multiple active Wi-Fi profiles: retain the one carrying the current
            # default route; fall back to the first when none advertises one.
            retain_ifname, retain_name = active[0]
            for ifname, name in active:
                if wifi_net.default_gateway_ipv4(ifname):
                    retain_ifname, retain_name = ifname, name
                    break

        retain_uuid = ""
        try:
            retain_uuid = wifi_net.resolve_connection_uuid_for_name(retain_name) or ""
        except Exception:
            retain_uuid = ""
        ctx.logger.info(
            "First-boot Wi-Fi import: retaining active profile '%s' (uuid=%s, ifname=%s)",
            retain_name, retain_uuid or "unresolved", retain_ifname)

        # Commit the retained profile as the single managed network.
        ctx._commit_network_state(retain_name, retain_uuid)

        # Disable autoconnect on the retained profile immediately (do not wait for
        # the next boot's autoconnect=no sweep).
        r = ctx.nm.set_autoconnect_no(retain_uuid, retain_name)
        if r.returncode != 0:
            ctx.logger.warning(
                "First-boot Wi-Fi import: could not disable autoconnect on retained "
                "'%s' (rc=%d): %s", retain_name, r.returncode, r.stderr.strip())

        # Delete every other saved non-AP Wi-Fi profile.
        _delete_other_wifi_profiles(ctx, retain_uuid, retain_name)

        _write_first_boot_import_marker(ctx)
    except Exception as e:
        # Never let import failure block the monitor from starting; the marker is
        # not written, so a later boot retries.
        ctx.logger.warning("First-boot Wi-Fi import failed: %s", e)


def _delete_other_wifi_profiles(ctx: ConfigContext, retain_uuid: str, retain_name: str) -> int:
    """Delete every saved non-AP Wi-Fi profile except the retained one.

    Per-profile failures are logged and tolerated (the sweep continues).  AP
    (hotspot) profiles are never deleted.  Returns the count deleted.
    """
    deleted = 0
    for uuid, name in wifi_net.list_wifi_connection_profiles():
        if (retain_uuid and uuid == retain_uuid) or (retain_name and name == retain_name):
            continue
        if wifi_net.wifi_profile_mode(uuid or name) == "ap":
            continue
        r = ctx.nm.delete_by_uuid(uuid) if uuid else ctx.nm.delete_connection(name)
        if r.returncode == 0:
            deleted += 1
            ctx.logger.info("First-boot Wi-Fi import: deleted saved profile '%s'", name or uuid)
        else:
            ctx.logger.warning(
                "First-boot Wi-Fi import: could not delete '%s' (rc=%d): %s; continuing",
                name or uuid, r.returncode, r.stderr.strip())
    return deleted


def _resolve_committed_uuid(ctx: ConfigContext, state: "wifi_net.NetworkState") -> str:
    """Return the UUID for the committed profile, resolving and persisting if absent.

    When network.json was written without a UUID (e.g. migrated from the legacy
    ssid file), this resolves the UUID from NetworkManager at operation time and
    atomically persists it so future calls have it immediately.  Returns "" when
    the profile cannot be uniquely identified, in which case restriction clearing
    must be skipped.
    """
    if state.connection_uuid:
        return state.connection_uuid
    if not state.connection_name:
        return ""
    resolved = wifi_net.resolve_connection_uuid_for_name(state.connection_name)
    if not resolved:
        ctx.logger.warning(
            "Cannot resolve UUID for committed profile '%s'; "
            "cross-adapter restriction clearing will be skipped",
            state.connection_name,
        )
        return ""
    try:
        wifi_net.save_network_state(
            wifi_net.NetworkState(
                connection_name=state.connection_name,
                connection_uuid=resolved,
            ),
            state_path=ctx.NETWORK_STATE_PATH,
            legacy_path=ctx.CONFIGURED_SSID,
        )
        ctx.logger.info(
            "Lazily resolved and persisted UUID %s for committed profile '%s'",
            resolved, state.connection_name,
        )
    except Exception as e:
        ctx.logger.warning(
            "Could not persist resolved UUID for '%s': %s; will still clear restrictions",
            state.connection_name, e,
        )
    return resolved
