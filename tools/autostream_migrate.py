#!/usr/bin/env python3
"""autostream_migrate.py

Migrate the main autostream appliance from the old file layout (INI config under
/opt/autostream/) to the new layout (JSON config under /etc/autostream/ and
/var/lib/autostream/).

Must be run as root. Called by the installer before starting services.
Applies only to main-appliance installations; autostream-dial uses the new
layout from its first deployment and requires no migration.

Usage:
    sudo python3 autostream_migrate.py [--dry-run] [--verbose] [--bluetooth-services on|off]

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
import stat
import sys
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

_PLAYBACK_STATS = Path("/var/lib/autostream/playback_stats.json")

# Device sentinel
_AUTOSTREAM_SENTINEL = Path("/opt/autostream/autostream_webui.py")

_DEFAULT_MDNS_GRACE_PERIOD_SECONDS = 120

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
# Bluetooth moves to input 3
#
# Bluetooth used to borrow input 1 or 2 by setting that input's capture
# device to the loopback's capture side. It is now input 3, whose device is
# fixed. An appliance with Bluetooth on a wired input has that input's
# Bluetooth settings and counters moved to input 3, and the wired input
# freed: no device, disabled, its own settings back to their defaults. The
# move is recorded in input 3's section so the Setup cards can say so until
# either input is next changed. Input 3's enable always follows the
# Bluetooth services, which are the same switch.
#
# Kept in step with autostream_config: the section names, the move note's
# key, and the loopback card id.
# ---------------------------------------------------------------------------

_BLUETOOTH_INPUT = 3
_WIRED_INPUTS = (1, 2)
_MOVED_FROM_KEY = "moved_from"
_LOOPBACK_CARD = "CARD=ASBT"

# The per-input settings that belong to the Bluetooth source, not the input.
_BLUETOOTH_MOVED_KEYS = (
    "input_type", "turntable", "silence_threshold", "gain_db",
    "eq_40hz_db", "eq_100hz_db", "eq_8khz_db", "eq_10khz_db",
    "dynamic_rate_matching", "start_after_ms",
    "stylus_life_hours", "belt_life_hours", "belt_life_years",
    "bearing_life_hours", "bearing_life_years",
)


def _loopback_side(device: object) -> str | None:
    """"capture" or "playback" for either side of the Bluetooth loopback,
    else None."""
    upper = str(device or "").upper()
    if _LOOPBACK_CARD not in upper:
        return None
    if "DEV=1" in upper:
        return "capture"
    if "DEV=0" in upper:
        return "playback"
    return None


def _read_json_object(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except ValueError as e:
        LOG.warning("Could not parse %s (%s); leaving it as it is.", path, e)
        return {}
    return data if isinstance(data, dict) else {}


def _move_bluetooth_settings(config: dict) -> int | None:
    """Move a Bluetooth binding on a wired input to input 3, in *config*.
    Returns the wired input it came from, or None when there was none. Any
    other loopback value on a wired input is cleared."""
    moved_from = None
    for index in _WIRED_INPUTS:
        section = config.get(f"audio{index}")
        if not isinstance(section, dict):
            continue
        side = _loopback_side(section.get("capture_device"))
        if side is None:
            continue
        if side == "capture" and moved_from is None:
            target = config.setdefault(f"audio{_BLUETOOTH_INPUT}", {})
            for key in _BLUETOOTH_MOVED_KEYS:
                if key in section:
                    target[key] = section.pop(key)
            moved_from = index
        section["capture_device"] = ""
        section["enabled"] = False
        LOG.info("Input %d no longer uses the Bluetooth loopback (%s side)", index, side)
    return moved_from


def _move_playback_counters(stats: dict, moved_from: int) -> bool:
    """Move the wired input's playback and wear counters to input 3, in
    *stats*. Returns whether anything changed."""
    inputs = stats.get("inputs")
    if not isinstance(inputs, dict) or str(moved_from) not in inputs:
        return False
    inputs[str(_BLUETOOTH_INPUT)] = inputs.pop(str(moved_from))
    return True


def migrate_bluetooth_to_input3(
    cfg_path: Path, stats_path: Path, services_enabled: bool | None, dry_run: bool,
) -> None:
    """Move a Bluetooth binding on input 1 or 2 to input 3 and make input
    3's enable follow the Bluetooth services (*services_enabled*; None
    leaves it as it is). Idempotent: a second run finds no binding to move
    and an enable that already agrees, and writes nothing."""
    config = _read_json_object(cfg_path)
    if not config:
        LOG.info("No configuration at %s; no Bluetooth input to move.", cfg_path)
        return

    moved_from = _move_bluetooth_settings(config)
    section = config.setdefault(f"audio{_BLUETOOTH_INPUT}", {})
    if moved_from is not None:
        section[_MOVED_FROM_KEY] = moved_from
        LOG.info("Bluetooth moved from input %d to input %d", moved_from, _BLUETOOTH_INPUT)
    enable_changed = services_enabled is not None and section.get("enabled") != services_enabled
    if enable_changed:
        section["enabled"] = services_enabled
        LOG.info("Input %d enabled set to %s to match the Bluetooth services",
                 _BLUETOOTH_INPUT, services_enabled)

    # The counters first: if the run stops between the two writes, the next
    # run still finds the binding and the counters already where they go.
    if moved_from is not None:
        stats = _read_json_object(stats_path)
        if _move_playback_counters(stats, moved_from):
            LOG.info("Playback counters moved from input %d to input %d", moved_from, _BLUETOOTH_INPUT)
            _replace_json_keeping_owner(stats_path, stats, dry_run)

    if moved_from is not None or enable_changed:
        _replace_json_keeping_owner(cfg_path, config, dry_run)


def _replace_json_keeping_owner(path: Path, data: dict, dry_run: bool) -> None:
    """_replace_json, keeping the file's owner, group and mode."""
    st = path.stat()
    _replace_json(path, data, dry_run)
    _set_ownership_mode(path, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), dry_run)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Migrate an autostream device to the new file layout.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Log actions without writing files.")
    parser.add_argument("--verbose", action="store_true", help="Enable DEBUG logging.")
    parser.add_argument(
        "--bluetooth-services", choices=("on", "off"),
        help="Whether the Bluetooth services are enabled; input 3's enable is set to match.",
    )
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

    services = None if args.bluetooth_services is None else args.bluetooth_services == "on"
    try:
        _migrate_autostream(dry_run=args.dry_run)
        migrate_bluetooth_to_input3(_NEW_CFG, _PLAYBACK_STATS, services, dry_run=args.dry_run)
    except OSError as e:
        LOG.error("Migration failed with OS error: %s", e)
        LOG.error("Partial state may exist — check logs above before starting services.")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
