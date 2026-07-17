#!/usr/bin/env python3
"""autostream_migrate.py

Migrate the main autostream appliance from the old file layout (INI config under
/opt/autostream/) to the new layout (JSON config under /etc/autostream/ and
/var/lib/autostream/).

Must be run as root. Called by the installer before starting services.
Applies only to main-appliance installations; autostream-dial uses the new
layout from its first deployment and requires no migration.

Usage:
    sudo python3 autostream_migrate.py [--dry-run] [--verbose]

Exits 0 on success (including "nothing to do") and non-zero on any unrecoverable error.
"""

from __future__ import annotations

import argparse
import configparser
import json
import logging
import os
import pwd
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# autostream device
_OLD_INI          = Path("/opt/autostream/autostream.ini")
_NEW_CFG          = Path("/etc/autostream/autostream.json")
_NEW_STATE        = Path("/var/lib/autostream/autostream-state.json")
_OLD_HINTS        = Path("/opt/autostream/nowplaying_hints.json")
_NEW_HINTS        = Path("/etc/autostream/nowplaying_hints.json")

_DATA_FILES = [
    ("dials.json",           Path("/opt/autostream/dials.json"),            Path("/var/lib/autostream/dials.json")),
    ("playback_stats.json",  Path("/opt/autostream/playback_stats.json"),   Path("/var/lib/autostream/playback_stats.json")),
    ("sdcardhealth.json",    Path("/opt/autostream/sdcardhealth.json"),      Path("/var/lib/autostream/sdcardhealth.json")),
    ("cpuinfo",              Path("/opt/autostream/cpuinfo"),                Path("/var/lib/autostream/cpuinfo")),
]

# Device sentinel
_AUTOSTREAM_SENTINEL = Path("/opt/autostream/autostream_webui.py")

_DEFAULT_MDNS_GRACE_PERIOD_SECONDS = 120
_MIN_MDNS_GRACE_PERIOD_SECONDS = 60
_MAX_MDNS_GRACE_PERIOD_SECONDS = 900

# Keep in step with FIFO_PATH in autostream_config.py. The FIFO moved off /tmp,
# where it was subject to age-based cleanup, so any path an existing config
# carries is replaced rather than preserved.
_FIFO_PATH = "/run/autostream-pipes/autostream.fifo"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG = logging.getLogger("autostream_migrate")


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stdout,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_autostream_uid_gid() -> tuple[int, int]:
    """Return (uid, gid) for the autostream OS user. Abort if missing."""
    try:
        pw = pwd.getpwnam("autostream")
        return pw.pw_uid, pw.pw_gid
    except KeyError:
        LOG.error(
            "OS user 'autostream' not found. "
            "The installer must create this user before calling the migration script."
        )
        sys.exit(1)


def _atomic_write_json(path: Path, data: dict, dry_run: bool) -> None:
    """Write *data* as JSON to *path* atomically. No-op if target already exists."""
    if path.exists():
        LOG.info("SKIP (already exists): %s", path)
        return
    LOG.info("Writing %s", path)
    if dry_run:
        return
    tmp = path.parent / f".{path.name}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _replace_json(path: Path, data: dict, dry_run: bool) -> None:
    """Atomically replace an existing JSON file."""
    LOG.info("Updating %s", path)
    if dry_run:
        return
    tmp = path.parent / f".{path.name}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _normalize_grace_seconds(value: object) -> int:
    try:
        seconds = int(value)  # type: ignore[arg-type]
    except Exception:
        return _DEFAULT_MDNS_GRACE_PERIOD_SECONDS
    return max(_MIN_MDNS_GRACE_PERIOD_SECONDS, min(_MAX_MDNS_GRACE_PERIOD_SECONDS, seconds))


def _read_backend_grace_period_seconds(config_data: dict) -> int:
    base_url = str((config_data.get("owntone") or {}).get("base_url") or "http://localhost:3689").rstrip("/")
    url = f"{base_url}/api/settings/player/device_removal_grace_period"
    try:
        with urllib.request.urlopen(url, timeout=2.0) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError, UnicodeDecodeError, TimeoutError):
        return _DEFAULT_MDNS_GRACE_PERIOD_SECONDS
    if not isinstance(payload, dict):
        return _DEFAULT_MDNS_GRACE_PERIOD_SECONDS
    return _normalize_grace_seconds(payload.get("value"))


def _ensure_mdns_grace_period(config_data: dict) -> bool:
    general = config_data.setdefault("general", {})
    if "mdns_grace_period_seconds" in general:
        before = general.get("mdns_grace_period_seconds")
        general["mdns_grace_period_seconds"] = _normalize_grace_seconds(
            before
        )
        return general["mdns_grace_period_seconds"] != before
    general["mdns_grace_period_seconds"] = _read_backend_grace_period_seconds(config_data)
    return True


def _ensure_fifo_path(config_data: dict) -> bool:
    """Force general.fifo_path to the canonical path. Returns True if changed."""
    general = config_data.setdefault("general", {})
    if general.get("fifo_path") == _FIFO_PATH:
        return False
    general["fifo_path"] = _FIFO_PATH
    return True


def _set_ownership_mode(path: Path, uid: int, gid: int, mode: int, dry_run: bool) -> None:
    if dry_run:
        LOG.debug("DRY-RUN chown/chmod %s uid=%d gid=%d mode=%04o", path, uid, gid, mode)
        return
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def _copy_file(src: Path, dst: Path, uid: int, gid: int, mode: int, dry_run: bool) -> None:
    """Copy *src* → *dst*, setting ownership and mode. No-op if dst already exists."""
    if dst.exists():
        LOG.info("SKIP (already exists): %s", dst)
        return
    if not src.exists():
        LOG.debug("SKIP (source absent): %s", src)
        return
    LOG.info("Copying %s → %s", src, dst)
    if dry_run:
        return
    shutil.copy2(src, dst)
    _set_ownership_mode(dst, uid, gid, mode, dry_run=False)


def _move_file(src: Path, dst: Path, uid: int, gid: int, mode: int, dry_run: bool) -> None:
    """Copy *src* → *dst* then remove *src*. No-op if dst already exists or src absent."""
    if dst.exists():
        LOG.info("SKIP (already exists): %s", dst)
        return
    if not src.exists():
        LOG.debug("SKIP (source absent): %s", src)
        return
    LOG.info("Moving %s → %s", src, dst)
    if dry_run:
        return
    shutil.copy2(src, dst)
    _set_ownership_mode(dst, uid, gid, mode, dry_run=False)
    src.unlink()


def _ensure_dir(path: Path, uid: int, gid: int, mode: int, dry_run: bool) -> None:
    if path.exists():
        # Always reapply ownership/mode in case a previous partial run left wrong values.
        LOG.debug("Reapplying ownership/mode to existing directory %s", path)
        if not dry_run:
            os.chown(path, uid, gid)
            os.chmod(path, mode)
        return
    LOG.info("Creating directory %s", path)
    if dry_run:
        return
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


# ---------------------------------------------------------------------------
# INI → JSON conversion helpers
# ---------------------------------------------------------------------------

def _ini_bool(cfg: configparser.ConfigParser, section: str, key: str, fallback: bool) -> bool:
    try:
        return cfg.getboolean(section, key, fallback=fallback)
    except Exception:
        return fallback


def _ini_float(cfg: configparser.ConfigParser, section: str, key: str, fallback: float) -> float:
    try:
        return cfg.getfloat(section, key, fallback=fallback)
    except Exception:
        return fallback


def _ini_int(cfg: configparser.ConfigParser, section: str, key: str, fallback: int) -> int:
    try:
        return cfg.getint(section, key, fallback=fallback)
    except Exception:
        return fallback


def _ini_str(cfg: configparser.ConfigParser, section: str, key: str, fallback: str) -> str:
    try:
        return cfg.get(section, key, fallback=fallback).strip()
    except Exception:
        return fallback


def _parse_hidden_outputs(raw: str) -> list[str]:
    items: list[str] = []
    for ln in str(raw or "").splitlines():
        for part in ln.split(","):
            s = part.strip()
            if s:
                items.append(s)
    seen: set[str] = set()
    out: list[str] = []
    for s in items:
        key = s.casefold()
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out


def _build_audio_section(cfg: configparser.ConfigParser, section: str) -> dict:
    out = {
        "capture_device":    _ini_str(cfg, section, "capture_device", ""),
        "turntable":         _ini_bool(cfg, section, "turntable", False),
        "gain_db":           _ini_float(cfg, section, "gain_db", 0.0),
        "eq_40hz_db":        _ini_float(cfg, section, "eq_40hz_db", 0.0),
        "eq_100hz_db":       _ini_float(cfg, section, "eq_100hz_db", 0.0),
        "eq_8khz_db":        (
            _ini_float(cfg, section, "eq_8khz_db", 0.0)
            if cfg.has_option(section, "eq_8khz_db")
            else _ini_float(cfg, section, "eq_10khz_db", 0.0)
        ),
        "stylus_life_hours": _ini_int(cfg, section, "stylus_life_hours", 0),
        "belt_life_hours":   _ini_int(cfg, section, "belt_life_hours", 0),
        "belt_life_years":   _ini_int(cfg, section, "belt_life_years", 0),
        "bearing_life_hours": _ini_int(cfg, section, "bearing_life_hours", 0),
        "bearing_life_years": _ini_int(cfg, section, "bearing_life_years", 0),
    }
    # Only carry an explicit INI value across. Omitting the key when the source
    # has none lets parse-time derivation pick the threshold from the
    # `turntable` flag instead of freezing in a migrator-invented default.
    if cfg.has_option(section, "silence_threshold"):
        out["silence_threshold"] = _ini_float(cfg, section, "silence_threshold", 0.0)
    return out


def _ini_to_config_json(cfg: configparser.ConfigParser) -> dict:
    """Convert a ConfigParser INI to the new config JSON structure."""
    offsets: dict[str, int] = {}
    if cfg.has_section("owntone_offsets"):
        for k, v in cfg.items("owntone_offsets"):
            try:
                offsets[str(k).strip()] = int(str(v).strip())
            except Exception:
                offsets[str(k).strip()] = 0

    airplay_modes: dict[str, str] = {}
    if cfg.has_section("owntone_airplay_modes"):
        for k, v in cfg.items("owntone_airplay_modes"):
            key = str(k).strip()
            if key:
                airplay_modes[key] = str(v).strip() or "default"

    audio2_section = _build_audio_section(cfg, "audio2")
    audio2_section["enabled"] = _ini_bool(cfg, "audio2", "enabled", False)

    return {
        "general": {
            "log_file":        _ini_str(cfg, "general", "log_file", "/var/log/autostream/autostream.log"),
            "log_level":       _ini_str(cfg, "general", "log_level", "info"),
            "fifo_path":       _FIFO_PATH,
            "silence_seconds": _ini_int(cfg, "general", "silence_seconds", 30),
        },
        "audio1": _build_audio_section(cfg, "audio1"),
        "audio2": audio2_section,
        "owntone": {
            "base_url":      _ini_str(cfg, "owntone", "base_url", "http://localhost:3689"),
            "output_name":   _ini_str(cfg, "owntone", "output_name", ""),
            "volume_percent": _ini_int(cfg, "owntone", "volume_percent", 20),
            "offsets":       offsets,
            "airplay_modes": airplay_modes,
        },
        "output_eq": {
            "gain_db":           _ini_float(cfg, "output_eq", "gain_db", 0.0),
            "auto_trim_enabled": _ini_bool(cfg, "output_eq", "auto_trim_enabled", False),
            "peq1_db":           _ini_float(cfg, "output_eq", "peq1_db", 0.0),
            "peq2_db":           _ini_float(cfg, "output_eq", "peq2_db", 0.0),
            "peq3_db":           _ini_float(cfg, "output_eq", "peq3_db", 0.0),
            "peq4_db":           _ini_float(cfg, "output_eq", "peq4_db", 0.0),
            "peq5_db":           _ini_float(cfg, "output_eq", "peq5_db", 0.0),
            "peq6_db":           _ini_float(cfg, "output_eq", "peq6_db", 0.0),
        },
        "webui": {
            "hidden_outputs":        _parse_hidden_outputs(
                _ini_str(cfg, "webui", "hidden_outputs", "")
            ),
            "show_master_volume":    _ini_bool(cfg, "webui", "show_master_volume", True),
            "show_input_detail":     _ini_bool(cfg, "webui", "show_input_detail", False),
            "dark_mode":             _ini_bool(cfg, "webui", "dark_mode", False),
            "show_hostname_on_home": _ini_bool(cfg, "webui", "show_hostname_on_home", False),
        },
        "updates": {
            "auto_update": _ini_bool(cfg, "updates", "auto_update", False),
        },
    }


def _ini_to_state_json(cfg: configparser.ConfigParser) -> dict:
    """Extract auth and known_outputs from the INI into the new state JSON structure."""
    pin_override = _ini_str(cfg, "auth", "pin_override", "") if cfg.has_section("auth") else ""

    known_outputs: dict[str, str] = {}
    if cfg.has_section("owntone_known_outputs"):
        for k, v in cfg.items("owntone_known_outputs"):
            key = str(k).strip()
            name = str(v).strip()
            if key and name:
                known_outputs[key] = name

    return {
        "auth": {
            "pin_override": pin_override,
        },
        "owntone": {
            "known_outputs": known_outputs,
        },
    }


# ---------------------------------------------------------------------------
# autostream device migration
# ---------------------------------------------------------------------------

def _migrate_autostream(dry_run: bool) -> None:
    uid, gid = _get_autostream_uid_gid()
    root_uid, root_gid = 0, 0

    # Detect migration state
    old_exists = _OLD_INI.exists()
    new_exists = _NEW_CFG.exists()

    if not old_exists and not new_exists:
        LOG.info("Fresh install (no INI, no JSON config) — creating empty skeleton files.")
        _ensure_dir(Path("/etc/autostream"), uid, gid, 0o755, dry_run)
        _ensure_dir(Path("/var/lib/autostream"), uid, gid, 0o750, dry_run)
        fresh_config = {
            "general": {
                "mdns_grace_period_seconds": _DEFAULT_MDNS_GRACE_PERIOD_SECONDS,
                "fifo_path": _FIFO_PATH,
            }
        }
        _atomic_write_json(_NEW_CFG, fresh_config, dry_run)
        if not dry_run and _NEW_CFG.exists():
            _set_ownership_mode(_NEW_CFG, uid, gid, 0o600, dry_run=False)
        _atomic_write_json(_NEW_STATE, {"auth": {"pin_override": ""}, "owntone": {"known_outputs": {}}}, dry_run)
        if not dry_run and _NEW_STATE.exists():
            _set_ownership_mode(_NEW_STATE, uid, gid, 0o600, dry_run=False)
        return

    if new_exists and not old_exists:
        try:
            with open(_NEW_CFG, encoding="utf-8") as f:
                config_data = json.load(f)
            if not isinstance(config_data, dict):
                config_data = {}
            changed = _ensure_mdns_grace_period(config_data)
            if _ensure_fifo_path(config_data):
                LOG.info("Set general.fifo_path to %s in %s", _FIFO_PATH, _NEW_CFG)
                changed = True
            if changed:
                _replace_json(_NEW_CFG, config_data, dry_run)
        except Exception as exc:
            LOG.warning("Could not seed general settings in %s: %s", _NEW_CFG, exc)
        LOG.info("Already migrated (new JSON config exists, old INI absent) — no layout change needed.")
        return

    if old_exists and new_exists:
        LOG.warning(
            "Both old INI (%s) and new JSON config (%s) exist — "
            "JSON config preserved; continuing data file migration in case a prior run was interrupted. "
            "Remove the old INI manually once the new install is confirmed working.",
            _OLD_INI, _NEW_CFG,
        )
        # If migration was interrupted between writing the config JSON and the state
        # JSON, the state file will be absent.  Reconstruct it from the INI now.
        if not _NEW_STATE.exists():
            LOG.info(
                "State file %s absent — interrupted migration detected; reconstructing from %s",
                _NEW_STATE, _OLD_INI,
            )
            ini = configparser.ConfigParser()
            try:
                if not ini.read(str(_OLD_INI)):
                    LOG.error("Could not read INI file: %s", _OLD_INI)
                    sys.exit(1)
            except configparser.Error as e:
                LOG.error("Malformed INI file %s: %s", _OLD_INI, e)
                sys.exit(1)
            state_data = _ini_to_state_json(ini)
            _atomic_write_json(_NEW_STATE, state_data, dry_run)
            if not dry_run and _NEW_STATE.exists():
                _set_ownership_mode(_NEW_STATE, uid, gid, 0o600, dry_run=False)

        try:
            with open(_NEW_CFG, encoding="utf-8") as f:
                config_data = json.load(f)
            if isinstance(config_data, dict) and _ensure_mdns_grace_period(config_data):
                _replace_json(_NEW_CFG, config_data, dry_run)
        except Exception as exc:
            LOG.warning("Could not seed mDNS grace period in %s: %s", _NEW_CFG, exc)

        # Data-file moves are individually idempotent (skip if dst already exists).
        for _label, src, dst in _DATA_FILES:
            _move_file(src, dst, uid, gid, 0o600, dry_run)
        if _OLD_HINTS.exists():
            _copy_file(_OLD_HINTS, _NEW_HINTS, root_uid, gid, 0o640, dry_run)
            if not dry_run and _NEW_HINTS.exists():
                LOG.info("Removing source hints file %s", _OLD_HINTS)
                _OLD_HINTS.unlink()
        return

    # old_exists and not new_exists → perform migration
    LOG.info("Migrating autostream device: %s → %s / %s", _OLD_INI, _NEW_CFG, _NEW_STATE)

    LOG.info("Parsing %s", _OLD_INI)
    cfg = configparser.ConfigParser()
    try:
        read = cfg.read(str(_OLD_INI))
        if not read:
            LOG.error("Could not read INI file: %s", _OLD_INI)
            sys.exit(1)
    except configparser.Error as e:
        LOG.error("Malformed INI file %s: %s", _OLD_INI, e)
        sys.exit(1)

    config_data = _ini_to_config_json(cfg)
    _ensure_mdns_grace_period(config_data)
    state_data  = _ini_to_state_json(cfg)

    # Create directories
    _ensure_dir(Path("/etc/autostream"), uid, gid, 0o755, dry_run)
    _ensure_dir(Path("/var/lib/autostream"), uid, gid, 0o750, dry_run)

    # Write config JSON
    LOG.info("Writing %s", _NEW_CFG)
    if not dry_run:
        _atomic_write_json(_NEW_CFG, config_data, dry_run=False)
        _set_ownership_mode(_NEW_CFG, uid, gid, 0o600, dry_run=False)

    # Write state JSON
    LOG.info("Writing %s", _NEW_STATE)
    if not dry_run:
        _atomic_write_json(_NEW_STATE, state_data, dry_run=False)
        _set_ownership_mode(_NEW_STATE, uid, gid, 0o600, dry_run=False)

    # Move data files
    for label, src, dst in _DATA_FILES:
        _move_file(src, dst, uid, gid, 0o600, dry_run)

    # Move nowplaying hints if present
    if _OLD_HINTS.exists():
        _copy_file(_OLD_HINTS, _NEW_HINTS, root_uid, gid, 0o640, dry_run)
        if not dry_run and _NEW_HINTS.exists():
            LOG.info("Removing source hints file %s", _OLD_HINTS)
            _OLD_HINTS.unlink()

    # Rename old INI as a safety backup (never delete it)
    backup = _OLD_INI.parent / (_OLD_INI.name + ".pre-migration")
    if not backup.exists() and not dry_run:
        LOG.info("Renaming %s → %s (safety backup — remove manually once confirmed working)", _OLD_INI, backup)
        _OLD_INI.rename(backup)
    elif dry_run:
        LOG.info("DRY-RUN: would rename %s → %s", _OLD_INI, backup)

    LOG.info("autostream device migration complete.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Migrate an autostream device to the new file layout.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Log actions without writing files.")
    parser.add_argument("--verbose", action="store_true", help="Enable DEBUG logging.")
    args = parser.parse_args()

    _setup_logging(args.verbose)

    if os.geteuid() != 0:
        LOG.error("This script must be run as root.")
        sys.exit(1)

    if args.dry_run:
        LOG.info("DRY-RUN mode — no files will be written or moved.")

    if not _AUTOSTREAM_SENTINEL.exists():
        LOG.warning(
            "%s not found. Not a main-appliance device — nothing to do.",
            _AUTOSTREAM_SENTINEL,
        )
        sys.exit(0)

    try:
        _migrate_autostream(dry_run=args.dry_run)
    except OSError as e:
        LOG.error("Migration failed with OS error: %s", e)
        LOG.error("Partial state may exist — check logs above before starting services.")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
