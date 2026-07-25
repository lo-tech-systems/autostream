"""autostream_log_policy.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

Shared log-level getter/setter used by both the Web API and the storage
guard maintenance service.  This module must not import the Web UI router.

Public interface:
    get_log_level_state(config_path) -> dict
    set_log_level(config_path, requested_level, *, changed_by, now=None) -> dict
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from autostream_config import (
    CONFIG_IO_LOCK,
    VALID_LOG_LEVELS,
    VALID_LOG_LEVEL_CHANGED_BY,
    load_config,
    normalize_log_level_changed_by,
    normalize_log_level_changed_at,
    parse_config,
    save_config,
)

logger = logging.getLogger(__name__)

# Log levels that trigger verbose NGINX access logging
_VERBOSE_NGINX_LEVELS = frozenset({"debug", "spam"})

# Log levels that trigger persistent journald storage.
# Journald rests at Storage=volatile (system/journald/99-autostream-storage.conf);
# a drop-in flips it to persistent only while the platform level is in this tier.
_PERSIST_JOURNAL_LEVELS = frozenset({"debug", "spam"})

# Levels considered "elevated" for the first-boot changed_at seed.
_ELEVATED_LEVELS = frozenset({"info", "debug", "spam"})


def _utc_now_str(now: Optional[datetime] = None) -> str:
    """Return current UTC time as a canonical ISO timestamp string."""
    if now is None:
        now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def get_log_level_state(config_path: str) -> dict:
    """Return the current log-level policy state from disk.

    Returns:
        {"ok": True, "level": str, "changed_by": str, "changed_at": str|None}
    """
    try:
        with CONFIG_IO_LOCK:
            cfg = load_config(config_path)
            parsed = parse_config(cfg)
        return {
            "ok": True,
            "level": parsed.general.log_level,
            "changed_by": parsed.general.log_level_changed_by,
            "changed_at": parsed.general.log_level_changed_at,
        }
    except Exception as e:
        logger.warning("get_log_level_state: failed reading config: %s", e)
        return {"ok": False, "error": "Could not read configuration"}


def set_log_level(
    config_path: str,
    requested_level: object,
    *,
    changed_by: str,
    now: Optional[datetime] = None,
    _startup: bool = False,
) -> dict:
    """Validate, persist, and apply a log-level change.

    Args:
        config_path:     Path to autostream.json.
        requested_level: The level name to set. Must be a member of VALID_LOG_LEVELS;
                         invalid values are rejected (not silently coerced).
        changed_by:      "user" or "system". Supplied by trusted internal code only.
        now:             Injectable clock for testing. Defaults to utc now.
        _startup:        When True, apply live without updating changed_at. This
                         argument is for internal startup use only.

    Returns a dict with:
        ok, level, changed_by, changed_at, changed (bool),
        applied: {autostream, monitor, owntone, nginx, wifi_watcher, journald}
    """
    # --- 1. Validate inputs (skip level check in startup mode; level comes from disk) ---
    if _startup:
        level_str = ""  # overridden from disk below
    else:
        level_str = str(requested_level or "").strip().lower()
        if level_str not in VALID_LOG_LEVELS:
            return {"ok": False, "error": f"Unsupported log level: {requested_level!r}"}

    # Validate before normalizing: normalize_log_level_changed_by silently maps
    # unknown values to "user", so the post-normalize check would never trigger.
    changed_by_str = str(changed_by or "").strip().lower()
    if changed_by_str not in VALID_LOG_LEVEL_CHANGED_BY:
        return {"ok": False, "error": f"Invalid changed_by value: {changed_by!r}"}

    # --- 2. Load, compute new policy state, save atomically (under lock) ---
    policy_changed = False
    new_level = level_str
    new_changed_by = changed_by_str
    new_changed_at: Optional[str] = None

    try:
        with CONFIG_IO_LOCK:
            cfg = load_config(config_path)
            parsed = parse_config(cfg)
            current_level = parsed.general.log_level
            current_changed_by = parsed.general.log_level_changed_by
            current_changed_at = parsed.general.log_level_changed_at

            if _startup:
                # Startup: apply live, but do not change the level or changed_by.
                new_level = current_level
                new_changed_by = current_changed_by
                new_changed_at = current_changed_at

                # A persisted elevated level with no changed_at has no clock for
                # the de-escalation staircase to age it from (compute_expiry_target
                # returns None when changed_at is missing). Seed it once, leaving the
                # level and changed_by exactly as the user/system left them. A
                # persisted warning/log/fatal level gets nothing.
                if current_level in _ELEVATED_LEVELS and current_changed_at is None:
                    new_changed_at = _utc_now_str(now)
                    cfg.setdefault("general", {}).update({
                        "log_level_changed_at": new_changed_at,
                    })
                    save_config(config_path, cfg)
                    logger.info(
                        "set_log_level: seeded missing log_level_changed_at=%s for "
                        "persisted level=%s so the de-escalation staircase can age it",
                        new_changed_at, current_level,
                    )
                # No further persistence needed.
            else:
                # Determine whether policy state changed (Section 3.2).
                level_changed = (level_str != current_level)
                owner_changed = (changed_by_str != current_changed_by)
                policy_changed = level_changed or owner_changed

                if policy_changed:
                    new_level = level_str
                    new_changed_by = changed_by_str
                    new_changed_at = _utc_now_str(now)
                    # Persist atomically.
                    cfg.setdefault("general", {}).update({
                        "log_level": new_level,
                        "log_level_changed_by": new_changed_by,
                        "log_level_changed_at": new_changed_at,
                    })
                    save_config(config_path, cfg)
                else:
                    # No-op; preserve existing metadata.
                    new_level = current_level
                    new_changed_by = current_changed_by
                    new_changed_at = current_changed_at

    except Exception as e:
        logger.error("set_log_level: persistence failed: %s", e)
        return {"ok": False, "error": "Configuration could not be saved"}

    # --- 3. Apply live to all targets (CONFIG_IO_LOCK released above) ---
    applied: dict = {
        "autostream": False,
        "monitor": False,
        "owntone": None,
        "nginx": False,
        "wifi_watcher": None,
        "journald": None,
    }

    # Apply to Python logger.
    try:
        from autostream_core import update_live_log_level
        update_live_log_level(new_level)
        applied["autostream"] = True
    except Exception as e:
        logger.warning("set_log_level: Python logger apply failed: %s", e)

    # Apply to monitor daemon.
    try:
        from autostream_core import set_live_monitor_log_level
        monitor_ok = set_live_monitor_log_level(new_level)
        applied["monitor"] = monitor_ok
    except Exception as e:
        logger.warning("set_log_level: monitor apply failed: %s", e)
        applied["monitor"] = False

    # Apply to OwnTone.
    try:
        cfg_for_owntone = load_config(config_path)
        parsed_for_owntone = parse_config(cfg_for_owntone)
        owntone_url = parsed_for_owntone.owntone.base_url
        if owntone_url:
            from autostream_player_service import save_log_level as _save_owntone_log_level
            result = _save_owntone_log_level(owntone_url, new_level)
            if result.unsupported:
                applied["owntone"] = None
            else:
                applied["owntone"] = bool(result.ok)
        else:
            applied["owntone"] = None
    except Exception as e:
        logger.warning("set_log_level: OwnTone apply failed: %s", e)
        applied["owntone"] = False

    # Apply to NGINX access logging.
    try:
        from autostream_sysutils import set_nginx_verbose_logging
        nginx_verbose = new_level in _VERBOSE_NGINX_LEVELS
        nginx_ok = set_nginx_verbose_logging(nginx_verbose)
        applied["nginx"] = nginx_ok
    except Exception as e:
        logger.warning("set_log_level: NGINX apply failed: %s", e)
        applied["nginx"] = False

    # Apply to the Wi-Fi watcher: folded into the shared fan-out so any caller
    # of set_log_level, not just the HTTP PUT handler, keeps the watcher in sync;
    # it force-TTLs a forwarded debug level to <=1h regardless).
    try:
        from autostream_webui_api import forward_log_level_to_watcher
        applied["wifi_watcher"] = forward_log_level_to_watcher(new_level)
    except Exception as e:
        logger.warning("set_log_level: watcher forward failed: %s", e)
        applied["wifi_watcher"] = False

    # Apply journald persistence coupling to the DIAG tier. Reconciles
    # to the desired state on every apply rather than only on tier transitions:
    # set_journald_persistent pre-checks the drop-in and returns True without a
    # sudo call or journald restart when already in the desired state, so
    # routine INFO<->WARNING re-applies stay free -- while a previously FAILED
    # toggle (e.g. journald mid-restart at the debug->info moment) self-heals on
    # the next apply (including the storage guard's pending-reapply retry)
    # instead of leaking persistent writes until the next reboot.
    try:
        from autostream_sysutils import set_journald_persistent
        applied["journald"] = set_journald_persistent(
            new_level in _PERSIST_JOURNAL_LEVELS
        )
    except Exception as e:
        logger.warning("set_log_level: journald apply failed: %s", e)
        applied["journald"] = False

    return {
        "ok": True,
        "level": new_level,
        "changed_by": new_changed_by,
        "changed_at": new_changed_at,
        "changed": policy_changed,
        "applied": applied,
    }


def apply_startup_log_level(config_path: str) -> None:
    """Apply the persisted log level at startup without updating policy metadata.

    Called once during coordinator startup to bring Python, monitor, OwnTone,
    and NGINX into alignment with the configured level.
    """
    try:
        result = set_log_level(
            config_path,
            requested_level=None,  # overridden by _startup=True
            changed_by="system",
            _startup=True,
        )
        if not result.get("ok"):
            logger.warning("apply_startup_log_level: could not apply: %s", result.get("error"))
    except Exception as e:
        logger.warning("apply_startup_log_level: exception: %s", e)
