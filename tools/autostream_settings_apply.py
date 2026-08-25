#!/usr/bin/env python3
"""autostream_settings_apply.py

Apply one or more declarative settings manifests to the autostream and
owntone-mini JSON config files.

A manifest is a JSON document listing ordered "directives" -- ensure a key
has a value, overwrite it, delete it, or rename it -- against either
target's on-disk config. This lets a release ship config changes (schema
migrations, one-shot fixes, new defaults) as data instead of bespoke code,
applied idempotently on every install/update.

Must be run as root when writing the autostream target (the file has to be
handed back to the `autostream` OS user afterwards). Standalone and
stdlib-only: this script runs from the release tree without the autostream
package on sys.path, so it duplicates the handful of validation constants it
needs rather than importing them.

Usage:
    sudo python3 autostream_settings_apply.py [--manifest PATH]... \
        [--check-only] [--autostream-config PATH] [--owntone-config PATH] \
        [--state-file PATH]

Multiple --manifest flags apply in the order given, directives within a
manifest in list order. Exits 0 on success (including a no-op run) and
non-zero on any error; on error nothing is written to either target file.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_DEFAULT_MANIFEST_PATH = Path(__file__).resolve().parent.parent / "installer" / "settings-directives.json"
_DEFAULT_AUTOSTREAM_CONFIG = Path("/etc/autostream/autostream.json")
_DEFAULT_OWNTONE_CONFIG = Path("/etc/owntone-settings.json")
_DEFAULT_STATE_FILE = Path("/var/lib/autostream/install-state.env")

_TARGET_AUTOSTREAM = "autostream"
_TARGET_OWNTONE_MINI = "owntone-mini"
_TARGET_VIBRA_MINI = "vibra-mini"

# ---------------------------------------------------------------------------
# Logging -- plain stdout lines, one per directive/action; errors to stderr.
# ---------------------------------------------------------------------------

_LOG_PREFIX = "settings-apply:"


def _log(message: str) -> None:
    print(f"{_LOG_PREFIX} {message}")


def _log_err(message: str) -> None:
    print(f"{_LOG_PREFIX} ERROR: {message}", file=sys.stderr)


class EngineError(Exception):
    """Any condition that must abort the run before anything is written."""


# ---------------------------------------------------------------------------
# Manifest schema (v1) validation
# ---------------------------------------------------------------------------

_ALLOWED_TOP_KEYS = {"version", "directives"}
_ALLOWED_DIRECTIVE_FIELDS = {"target", "key", "mode", "value", "to", "reason", "from_before"}
_ALLOWED_TARGETS = {_TARGET_AUTOSTREAM, _TARGET_OWNTONE_MINI, _TARGET_VIBRA_MINI}
_ALLOWED_MODES = {"ensure", "overwrite", "delete", "rename"}


def _parse_dotted_tag(tag: Optional[str]) -> Optional[Tuple[int, ...]]:
    """Parse a dotted-numeric version tag into a comparable tuple.

    Returns None for anything that cannot ground a trustworthy comparison:
    absent, empty, the literal sentinels a fresh/source install records, or
    a component that is not purely numeric.
    """
    if not tag or tag in ("test", "unknown"):
        return None
    parts = tag.split(".")
    out: List[int] = []
    for part in parts:
        if not part.isdigit():
            return None
        out.append(int(part))
    return tuple(out) if out else None


def _validate_key_grammar(target: str, key: str, where: str) -> None:
    """Check a 'key' or 'to' value's dotted-path grammar for *target*.

    autostream keys are freely dotted (they address nested JSON objects).
    owntone-mini keys are flat, with one exception: per-device AirPlay
    settings, which live nested under airplay_devices.<name>.<key>.
    """
    if target == _TARGET_AUTOSTREAM:
        if any(part == "" for part in key.split(".")):
            raise EngineError(f"{where}: key {key!r} has an empty path segment")
        return
    if key.startswith("airplay_devices."):
        parts = key.split(".")
        if len(parts) != 3 or not all(parts):
            raise EngineError(
                f"{where}: airplay_devices key {key!r} must have the shape "
                "'airplay_devices.<name>.<key>'"
            )
        return
    if "." in key:
        raise EngineError(
            f"{where}: owntone-mini key {key!r} must be flat -- dotted keys are only "
            "valid under airplay_devices.<name>.<key>"
        )


def _validate_directive(raw: Any, manifest_path: Path, index: int) -> Dict[str, Any]:
    where = f"manifest {manifest_path} directive #{index}"
    if not isinstance(raw, dict):
        raise EngineError(f"{where}: must be a JSON object")

    unknown = set(raw.keys()) - _ALLOWED_DIRECTIVE_FIELDS
    if unknown:
        raise EngineError(f"{where}: unknown field(s): {sorted(unknown)}")

    target = raw.get("target")
    if target not in _ALLOWED_TARGETS:
        raise EngineError(f"{where}: unknown target {target!r}")
    if target == _TARGET_VIBRA_MINI:
        raise EngineError(
            f"{where}: target 'vibra-mini' is reserved -- no writer exists for it"
        )

    mode = raw.get("mode")
    if mode not in _ALLOWED_MODES:
        raise EngineError(f"{where}: unknown mode {mode!r}")

    key = raw.get("key")
    if not isinstance(key, str) or not key:
        raise EngineError(f"{where}: 'key' must be a non-empty string")
    _validate_key_grammar(target, key, where)

    has_value = "value" in raw
    has_to = "to" in raw

    if mode in ("ensure", "overwrite"):
        if not has_value:
            raise EngineError(f"{where}: mode {mode!r} requires 'value'")
    elif has_value:
        raise EngineError(f"{where}: mode {mode!r} must not include 'value'")

    if mode == "rename":
        to = raw.get("to")
        if not isinstance(to, str) or not to:
            raise EngineError(f"{where}: mode 'rename' requires a non-empty 'to'")
        _validate_key_grammar(target, to, where)
    elif has_to:
        raise EngineError(f"{where}: 'to' is only valid for mode 'rename'")

    if mode == "overwrite":
        reason = raw.get("reason")
        if not isinstance(reason, str) or not reason:
            raise EngineError(f"{where}: mode 'overwrite' requires a non-empty 'reason'")

    from_before = raw.get("from_before")
    if from_before is not None:
        if not isinstance(from_before, str) or _parse_dotted_tag(from_before) is None:
            raise EngineError(
                f"{where}: 'from_before' must be a dotted-numeric version string"
            )

    return dict(raw)


def _load_manifest(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise EngineError(f"manifest not found: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise EngineError(f"cannot read manifest {path}: {exc}")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EngineError(f"manifest {path} is not valid JSON: {exc}")
    if not isinstance(data, dict):
        raise EngineError(f"manifest {path}: top-level JSON value must be an object")

    unknown_top = set(data.keys()) - _ALLOWED_TOP_KEYS
    if unknown_top:
        raise EngineError(f"manifest {path}: unknown top-level key(s): {sorted(unknown_top)}")
    if data.get("version") != 1:
        raise EngineError(
            f"manifest {path}: unsupported schema version {data.get('version')!r} (expected 1)"
        )

    directives = data.get("directives")
    if not isinstance(directives, list):
        raise EngineError(f"manifest {path}: 'directives' must be a list")

    return [_validate_directive(raw, path, i) for i, raw in enumerate(directives)]


# ---------------------------------------------------------------------------
# from_before gating
# ---------------------------------------------------------------------------

def _read_old_release_tag(state_file: Path) -> Optional[str]:
    """Read AUTOSTREAM_RELEASE_TAG out of the install-state file.

    Parses KEY=VALUE lines directly rather than sourcing the file, mirroring
    the shell installer's own state-file reader: blank lines and lines
    starting with '#' are skipped, as are lines without '=', and a value
    wrapped in matching single or double quotes has them stripped. Returns
    None if the file is absent or the key is never set (a fresh install has
    no prior release to compare against).
    """
    if not state_file.exists():
        return None
    try:
        lines = state_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    tag: Optional[str] = None
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key != "AUTOSTREAM_RELEASE_TAG":
            continue
        if len(value) >= 2 and (
            (value[0] == '"' and value[-1] == '"') or (value[0] == "'" and value[-1] == "'")
        ):
            value = value[1:-1]
        tag = value
    return tag


def _gate_allows(
    directive: Dict[str, Any], old_tag_tuple: Optional[Tuple[int, ...]]
) -> Tuple[bool, Optional[str]]:
    """Decide whether a from_before-gated directive fires.

    Fires only when the previously installed release is strictly older than
    the gate tag. Any situation that leaves the prior release untrustworthy
    (no state file, an unparseable/sentinel tag) skips the directive rather
    than risk a one-shot firing without real history behind it.
    """
    from_before = directive.get("from_before")
    if from_before is None:
        return True, None
    if old_tag_tuple is None:
        return False, "no trustworthy prior release tag"
    gate_tuple = _parse_dotted_tag(from_before)
    if gate_tuple is not None and old_tag_tuple < gate_tuple:
        return True, None
    return False, "installed release is not older than the gate"


# ---------------------------------------------------------------------------
# In-memory document access -- dotted/flat path helpers
# ---------------------------------------------------------------------------

_MISSING = object()


def _key_segments(target: str, key: str) -> List[str]:
    return key.split(".")


def _get_at(doc: Dict[str, Any], segs: List[str]) -> Any:
    cur: Any = doc
    for seg in segs:
        if not isinstance(cur, dict) or seg not in cur:
            return _MISSING
        cur = cur[seg]
    return cur


def _get_nested(doc: Dict[str, Any], dotted_key: str) -> Any:
    return _get_at(doc, dotted_key.split("."))


def _set_at(doc: Dict[str, Any], segs: List[str], value: Any) -> None:
    cur = doc
    for seg in segs[:-1]:
        if seg in cur:
            nxt = cur[seg]
            if not isinstance(nxt, dict):
                raise EngineError(
                    f"cannot create nested path at {seg!r}: existing value is not an object"
                )
        else:
            nxt = {}
            cur[seg] = nxt
        cur = nxt
    cur[segs[-1]] = value


def _delete_at(doc: Dict[str, Any], segs: List[str]) -> bool:
    cur: Any = doc
    for seg in segs[:-1]:
        if not isinstance(cur, dict) or seg not in cur:
            return False
        cur = cur[seg]
    if isinstance(cur, dict) and segs[-1] in cur:
        del cur[segs[-1]]
        return True
    return False


def _apply_directive(
    doc: Dict[str, Any], target: str, directive: Dict[str, Any]
) -> Tuple[str, Optional[str]]:
    """Apply one directive to *doc* in place. Returns (status, detail)."""
    mode = directive["mode"]
    segs = _key_segments(target, directive["key"])

    if mode == "ensure":
        if _get_at(doc, segs) is not _MISSING:
            return "no-op", "key already present"
        _set_at(doc, segs, directive["value"])
        return "applied", None

    if mode == "overwrite":
        cur = _get_at(doc, segs)
        if cur is not _MISSING and cur == directive["value"]:
            return "no-op", "already set to the target value"
        _set_at(doc, segs, directive["value"])
        return "applied", None

    if mode == "delete":
        if _get_at(doc, segs) is _MISSING:
            return "no-op", "key already absent"
        _delete_at(doc, segs)
        return "applied", None

    if mode == "rename":
        cur = _get_at(doc, segs)
        if cur is _MISSING:
            return "no-op", "source key absent"
        to_segs = _key_segments(target, directive["to"])
        if _get_at(doc, to_segs) is not _MISSING:
            raise EngineError(
                f"{target}: rename target {directive['to']!r} already exists "
                f"(source {directive['key']!r})"
            )
        _delete_at(doc, segs)
        _set_at(doc, to_segs, cur)
        return "applied", None

    raise AssertionError(f"unreachable mode {mode!r}")  # pragma: no cover


# ---------------------------------------------------------------------------
# Result validation -- one entry per key this engine knows a constraint for.
# Keys not covered here are accepted as any JSON value; only the shapes
# below are enforced.
# ---------------------------------------------------------------------------

def _validate_owntone_result(doc: Dict[str, Any]) -> None:
    # Pipe-format brick-guards: owntone_config.c's config_set_int() rejects
    # these same sets at set-time, and pipe.c aborts the daemon at startup
    # (DPRINTF(E_FATAL, ...)) if a value outside them ever reaches the file.
    if "pipe_sample_rate" in doc:
        v = doc["pipe_sample_rate"]
        if v not in (44100, 48000, 88200, 96000):
            raise EngineError(f"owntone-mini: pipe_sample_rate {v!r} is not an accepted rate")
    if "pipe_bits_per_sample" in doc:
        v = doc["pipe_bits_per_sample"]
        if v not in (16, 32):
            raise EngineError(f"owntone-mini: pipe_bits_per_sample {v!r} must be 16 or 32")

    # Integer ranges mirrored from owntone_config.c's config_set_int().
    for key, lo, hi in (
        ("start_buffer_ms", 300, 3500),
        ("device_removal_grace_period", 0, 3600),
        ("buffered_encoder_budget", 0, 64),
    ):
        if key in doc:
            v = doc[key]
            if not isinstance(v, int) or isinstance(v, bool) or not (lo <= v <= hi):
                raise EngineError(f"owntone-mini: {key} {v!r} out of range {lo}-{hi}")

    if "user_agent" in doc:
        # Mirrored from httpd_jsonapi.c's user_agent_validate(): reject
        # control characters and anything over 255 bytes. Empty string is
        # accepted -- it is the daemon's sentinel for "derive the default".
        v = doc["user_agent"]
        if not isinstance(v, str):
            raise EngineError("owntone-mini: user_agent must be a string")
        if len(v.encode("utf-8")) > 255:
            raise EngineError("owntone-mini: user_agent exceeds 255 bytes")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in v):
            raise EngineError("owntone-mini: user_agent contains a control character")

    # Ports and trusted_networks have no C-side set-time validation to
    # mirror (neither is API-settable, and owntone_config.c enforces no
    # range on them) -- these are this engine's own conservative checks.
    for port_key in ("airplay_timing_port", "airplay_control_port"):
        if port_key in doc:
            v = doc[port_key]
            if not isinstance(v, int) or isinstance(v, bool) or not (0 <= v <= 65535):
                raise EngineError(f"owntone-mini: {port_key} {v!r} must be an integer 0-65535")
    if "trusted_networks" in doc:
        v = doc["trusted_networks"]
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise EngineError("owntone-mini: trusted_networks must be a list of strings")

    if "airplay_devices" in doc:
        v = doc["airplay_devices"]
        if not isinstance(v, dict) or not all(isinstance(x, dict) for x in v.values()):
            raise EngineError("owntone-mini: airplay_devices must be an object of name -> object")

    if "uid" in doc:
        # config_load() calls getpwnam() on this value before any other
        # thread starts; a name that does not resolve stops the daemon from
        # starting at all.
        v = doc["uid"]
        if not isinstance(v, str) or not v:
            raise EngineError("owntone-mini: uid must be a non-empty string")
        try:
            pwd.getpwnam(v)
        except KeyError:
            raise EngineError(f"owntone-mini: uid {v!r} does not resolve to an OS user")


def _validate_autostream_result(doc: Dict[str, Any]) -> None:
    v = _get_nested(doc, "general.mdns_grace_period_seconds")
    if v is not _MISSING:
        # Mirrors autostream_config.py's normalize_mdns_grace_period_seconds
        # clamp range.
        if not isinstance(v, int) or isinstance(v, bool) or not (60 <= v <= 900):
            raise EngineError(
                f"autostream: general.mdns_grace_period_seconds {v!r} out of range 60-900"
            )
    v = _get_nested(doc, "general.fifo_path")
    if v is not _MISSING:
        if not isinstance(v, str) or not v:
            raise EngineError("autostream: general.fifo_path must be a non-empty string")


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------

def _atomic_write_json(path: Path, doc: Dict[str, Any]) -> None:
    tmp = path.parent / f".{path.name}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Directive logging
# ---------------------------------------------------------------------------

def _describe_directive(directive: Dict[str, Any]) -> str:
    target = directive["target"]
    mode = directive["mode"]
    key = directive["key"]
    if mode == "rename":
        return f"{target} {key} -> {directive['to']}"
    return f"{target} {key} ({mode})"


def _log_directive(directive: Dict[str, Any], status: str, detail: Optional[str]) -> None:
    desc = _describe_directive(directive)
    if detail:
        _log(f"{status}: {desc} ({detail})")
    else:
        _log(f"{status}: {desc}")


# ---------------------------------------------------------------------------
# Engine entry point
# ---------------------------------------------------------------------------

def run(
    manifest_paths: List[Path],
    check_only: bool,
    autostream_config_path: Path,
    owntone_config_path: Path,
    state_file_path: Path,
) -> int:
    """Run the engine. Raises EngineError on any condition that must abort
    before anything is written; returns 0 on success."""
    directives: List[Dict[str, Any]] = []
    for manifest_path in manifest_paths:
        directives.extend(_load_manifest(manifest_path))

    old_tag_tuple = _parse_dotted_tag(_read_old_release_tag(state_file_path))

    config_paths = {
        _TARGET_AUTOSTREAM: autostream_config_path,
        _TARGET_OWNTONE_MINI: owntone_config_path,
    }
    docs: Dict[str, Dict[str, Any]] = {}
    changed = {_TARGET_AUTOSTREAM: False, _TARGET_OWNTONE_MINI: False}

    def load_target(target: str) -> Dict[str, Any]:
        if target in docs:
            return docs[target]
        path = config_paths[target]
        if not path.exists():
            data: Any = {}
        else:
            try:
                text = path.read_text(encoding="utf-8")
            except OSError as exc:
                raise EngineError(f"{target}: cannot read {path}: {exc}")
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                raise EngineError(f"{target}: existing config {path} is malformed JSON: {exc}")
            if not isinstance(data, dict):
                raise EngineError(f"{target}: existing config {path} is not a JSON object")
        docs[target] = data
        return data

    for directive in directives:
        target = directive["target"]
        doc = load_target(target)
        allowed, gate_reason = _gate_allows(directive, old_tag_tuple)
        if not allowed:
            _log_directive(directive, "skipped", gate_reason)
            continue
        status, detail = _apply_directive(doc, target, directive)
        if status == "applied":
            changed[target] = True
        _log_directive(directive, status, detail)

    for target, doc in list(docs.items()):
        if target == _TARGET_AUTOSTREAM:
            _validate_autostream_result(doc)
        else:
            _validate_owntone_result(doc)
        # Serialise + reparse so the in-memory form matches exactly what
        # will be written, before any file is touched.
        docs[target] = json.loads(json.dumps(doc))

    if check_only:
        _log("check-only: validation passed, no files written")
        return 0

    autostream_uid_gid: Optional[Tuple[int, int]] = None
    if changed[_TARGET_AUTOSTREAM]:
        try:
            pw = pwd.getpwnam("autostream")
        except KeyError:
            raise EngineError("OS user 'autostream' not found; cannot take ownership of autostream.json")
        autostream_uid_gid = (pw.pw_uid, pw.pw_gid)

    for target, doc in docs.items():
        path = config_paths[target]
        if not changed[target]:
            _log(f"{target}: no changes -- {path} not rewritten")
            continue
        _atomic_write_json(path, doc)
        if target == _TARGET_AUTOSTREAM:
            uid, gid = autostream_uid_gid  # type: ignore[misc]
            os.chown(path, uid, gid)
            os.chmod(path, 0o600)
        else:
            os.chmod(path, 0o644)
        _log(f"{target}: wrote {path}")

    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Apply declarative settings manifests to autostream and owntone-mini config files.",
    )
    parser.add_argument(
        "--manifest",
        action="append",
        dest="manifests",
        metavar="PATH",
        help="Manifest JSON file to apply. May be given multiple times; applied in order. "
        f"Default: {_DEFAULT_MANIFEST_PATH}",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Validate manifests and current config against them; write nothing.",
    )
    parser.add_argument(
        "--autostream-config",
        default=str(_DEFAULT_AUTOSTREAM_CONFIG),
        help=f"Path to the autostream config JSON. Default: {_DEFAULT_AUTOSTREAM_CONFIG}",
    )
    parser.add_argument(
        "--owntone-config",
        default=str(_DEFAULT_OWNTONE_CONFIG),
        help=f"Path to the owntone-mini config JSON. Default: {_DEFAULT_OWNTONE_CONFIG}",
    )
    parser.add_argument(
        "--state-file",
        default=str(_DEFAULT_STATE_FILE),
        help=f"Path to the install-state file used for from_before gating. Default: {_DEFAULT_STATE_FILE}",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    manifests = [Path(p) for p in args.manifests] if args.manifests else [_DEFAULT_MANIFEST_PATH]

    try:
        return run(
            manifest_paths=manifests,
            check_only=args.check_only,
            autostream_config_path=Path(args.autostream_config),
            owntone_config_path=Path(args.owntone_config),
            state_file_path=Path(args.state_file),
        )
    except EngineError as exc:
        _log_err(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
