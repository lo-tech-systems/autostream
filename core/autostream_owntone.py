"""autostream_owntone.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Provides access to OwnTone - both via it's API, and via it's configuration file
"""

from pathlib import Path
from typing import Optional

import logging
import os
import re
import tempfile
import time

import requests # third-party (pip install requests)
from autostream_sysutils import run_admin_cmd

logger = logging.getLogger(__name__)

# Location for owntone.conf. Default in most distros is /etc/owntone.conf. In
# autostream, we use our own copy at /opt/autostream/owntone/owntone.conf, which
# allevaites the need for autostream to have write access on /etc.
OWNTONE_CONF_PATH = Path(
    os.environ.get("OWNTONE_CONF", "/opt/autostream/owntone/owntone.conf")
).expanduser().resolve()
OWNTONE_CONF_DIR = OWNTONE_CONF_PATH.parent

# owntone_config_ok() return values
OWNTONE_OK = 0
OWNTONE_RESTART_REQUIRED = 1
OWNTONE_NOT_OK = -1

def get_owntone_output_id(base_url: str, output_name: str) -> Optional[int]:
    """Return the Owntone output ID matching `output_name`, or None if not found."""
    try:
        resp = requests.get(base_url.rstrip("/") + "/api/outputs", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        outputs = data.get("outputs", [])
        for out in outputs:
            if out.get("name") == output_name:
                return out.get("id")
    except Exception as e:  # noqa: BLE001
        logging.error("Error fetching Owntone outputs: %s", e)
    return None


def owntone_get_library_song_count(base_url: str) -> Optional[int]:
    """Return OwnTone library song count, or None on API error."""
    try:
        resp = requests.get(base_url.rstrip("/") + "/api/library", timeout=3)
        resp.raise_for_status()
        payload = resp.json() if resp.content else {}
        return int(payload.get("songs") or 0)
    except Exception as e:  # noqa: BLE001
        logging.warning("Error fetching OwnTone library stats: %s", e)
        return None


def owntone_trigger_files_rescan(base_url: str) -> bool:
    """Trigger OwnTone files rescan via JSON API."""
    try:
        resp = requests.put(
            base_url.rstrip("/") + "/api/update",
            params={"scan_kind": "files"},
            timeout=4,
        )
        if resp.status_code not in (200, 202, 204):
            logging.warning(
                "OwnTone files rescan request failed: %s %s",
                resp.status_code,
                resp.text,
            )
            return False
        logging.info("Requested OwnTone files rescan")
        return True
    except requests.RequestException as e:  # noqa: BLE001
        logging.warning("Error requesting OwnTone files rescan: %s", e)
        return False


def owntone_ensure_pipe_indexed(base_url: str, timeout_s: float = 15.0) -> bool:
    """Ensure OwnTone has indexed at least one library item (pipe source)."""
    deadline = time.time() + max(1.0, float(timeout_s))
    next_rescan_at = 0.0

    while time.time() < deadline:
        songs = owntone_get_library_song_count(base_url)
        if songs is not None and songs > 0:
            return True

        now = time.time()
        if now >= next_rescan_at:
            owntone_trigger_files_rescan(base_url)
            next_rescan_at = now + 2.0

        time.sleep(0.5)

    return False


def owntone_set_output(base_url: str, output_id: int, volume_percent: int, offset_ms: Optional[int] = None) -> bool:
    """Enable a specific output and set its volume via the Owntone JSON API.

    This endpoint updates a single output and does not reset the user's
    currently selected speaker group.
    """
    out_url = base_url.rstrip("/") + f"/api/outputs/{output_id}"
    vol = max(0, min(100, volume_percent))
    out_payload = {"selected": True, "volume": vol}

    # Optional per-output playback offset (ms). API range is -2000..2000.
    # Only include if provided, so we don't break outputs/versions that don't support it.
    if offset_ms is not None:
        try:
            off = int(offset_ms)
        except Exception:
            off = 0
        off = max(-2000, min(2000, off))
        out_payload["offset_ms"] = off

    try:
        resp = requests.put(out_url, json=out_payload, timeout=3)
        logging.info("Owntone PUT /api/outputs/%s status=%s", output_id, resp.status_code)
        logging.info("Owntone PUT /api/outputs/%s body=%s", output_id, resp.text)
        if not resp.ok:
            logging.error(
                "Owntone PUT /api/outputs/%s failed: %s %s",
                output_id,
                resp.status_code,
                resp.text,
            )
            return False
        else:
            logging.info("Enabled Owntone output id %s at %d%% volume", output_id, vol)
    except requests.RequestException as e:  # noqa: BLE001
        logging.error("Error configuring Owntone output %s: %s", output_id, e)
        return False

    return True


def owntone_restart_service() -> bool:
    """Restart the owntone service via the privileged autostream-admin helper.

    This avoids calling systemctl directly from the web process.
    """
    p = run_admin_cmd(["restart-owntone"], timeout=20.0)
    if p.returncode == 0:
        logger.info("Owntone restart requested via autostream-admin")
        return True
    logger.error(
        "Owntone restart via autostream-admin failed (rc=%s, stderr=%s)",
        p.returncode,
        (p.stderr or "").strip(),
    )
    return False


def owntone_disable_all_outputs(base_url: str) -> None:
    """Disable all outputs so that sinks (e.g., AirPlay devices) are released.

    This is done by sending an empty list of outputs to /api/outputs/set.
    """
    url = base_url.rstrip("/") + "/api/outputs/set"
    payload = {"outputs": []}
    logging.info("Owntone PUT /api/outputs/set (disable all) payload=%s", payload)
    try:
        resp = requests.put(url, json=payload, timeout=3)
        logging.info("Owntone PUT /api/outputs/set (disable all) status=%s", resp.status_code)
        logging.info("Owntone PUT /api/outputs/set (disable all) body=%s", resp.text)
        if not resp.ok:
            logging.error(
                "Owntone PUT /api/outputs/set (disable all) failed: %s %s",
                resp.status_code,
                resp.text,
            )
        else:
            logging.info("Owntone outputs disabled (empty outputs list sent)")
    except requests.RequestException as e:  # noqa: BLE001
        logging.error("Error disabling Owntone outputs: %s", e)


# ---------------------------------------------------------------------------
# OwnTone configuration helpers (owntone.conf)
# ---------------------------------------------------------------------------

# Globals populated by the "read_and_set_*" helpers below
OWNTONE_PIPE_DIR: str = ""
OWNTONE_UNCOMPRESSED_ALAC: bool = False


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""
    except Exception:
        logger.exception("Failed reading %s", path)
        return ""


def _atomic_write_text(path: Path, text: str) -> None:
    """Write file atomically, best-effort preserving mode/ownership."""
    try:
        st = path.stat()
        mode = st.st_mode
    except FileNotFoundError:
        st = None
        mode = None
    except Exception:
        st = None
        mode = None

    # Random, system-generated temp file in the same location as owntone.conf
    # This is because we then switch out the full file. This ensures we can't
    # be left with a half-written and broken file.
    fd, tmp_name = tempfile.mkstemp(prefix=f"{path.name}.", suffix=".tmp", dir=OWNTONE_CONF_DIR)
    tmp = Path(tmp_name)

    try:
        # Write via the returned fd to avoid reopening races
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())

        try:
            if mode is not None:
                os.chmod(tmp, mode)
            if st is not None:
                try:
                    os.chown(tmp, st.st_uid, st.st_gid)
                except PermissionError:
                    # Not fatal; e.g. when running unprivileged in dev/test.
                    pass
        except Exception:
            logger.exception("Failed setting ownership/mode for %s", tmp)

        os.replace(tmp, path)

    finally:
        # If os.replace() didn't run (or failed), clean up the temp file
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass



def _find_block_span(text: str, header_re: re.Pattern[str]) -> Optional[tuple[int, int]]:
    """Return (start_index, end_index_exclusive) for the first matching block."""
    m = header_re.search(text)
    if not m:
        return None

    # Find the opening brace for this block.
    # If the header regex already includes "{", prefer that brace; otherwise
    # fall back to searching after the match.
    brace_idx = text.find("{", m.start(), m.end())
    if brace_idx == -1:
        brace_idx = text.find("{", m.end())
    if brace_idx == -1:
        return None

    depth = 0
    i = brace_idx
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return (m.start(), i + 1)
        i += 1

    return None


def _parse_bool(raw: str) -> Optional[bool]:
    s = (raw or "").strip().strip('"').lower()
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"0", "false", "no", "off"}:
        return False
    return None


def _bool_to_conf(v: bool) -> str:
    return "true" if v else "false"


def read_and_set_global_pipe_directory(conf_path: Path | str = OWNTONE_CONF_PATH) -> str:
    """Read OwnTone's library.directories and set the global pipe directory.

    Conf source: `library { directories = { ... } }`.
    We infer the "pipe directory" as the first directory entry containing
    "pipe"/"pipes" in the path.
    """
    global OWNTONE_PIPE_DIR

    path = Path(conf_path)
    text = _read_text(path)
    if not text:
        OWNTONE_PIPE_DIR = ""
        return ""

    span = _find_block_span(text, re.compile(r"(?m)^\s*library\s*\{\s*$"))
    if not span:
        OWNTONE_PIPE_DIR = ""
        return ""

    block = text[span[0]:span[1]]
    m = re.search(r"(?m)^\s*directories\s*=\s*\{(?P<body>[^}]*)\}\s*$", block)
    if not m:
        OWNTONE_PIPE_DIR = ""
        return ""

    dirs = re.findall(r'"([^"]*)"', m.group("body"))
    pipe_dir = ""
    for d in dirs:
        if "pipe" in d.lower():
            pipe_dir = d
            break

    OWNTONE_PIPE_DIR = pipe_dir
    return pipe_dir


def write_and_set_global_pipe_directory(pipe_dir: str, conf_path: Path | str = OWNTONE_CONF_PATH) -> bool:
    """Ensure `pipe_dir` is present in `library.directories` and update global."""
    global OWNTONE_PIPE_DIR
    pipe_dir = (pipe_dir or "").strip()
    if not pipe_dir:
        return False

    path = Path(conf_path)
    text = _read_text(path)
    if not text:
        return False

    lib_re = re.compile(r"(?m)^\s*library\s*\{\s*$")
    span = _find_block_span(text, lib_re)
    if not span:
        return False

    block = text[span[0]:span[1]]

    dir_line_re = re.compile(r"(?m)^(?P<indent>\s*)directories\s*=\s*\{(?P<body>[^}]*)\}\s*$")
    m = dir_line_re.search(block)
    if m:
        indent = m.group("indent")
        dirs = re.findall(r'"([^"]*)"', m.group("body"))
        # Replace existing pipe-ish dir if present; else append.
        replaced = False
        for i, d in enumerate(list(dirs)):
            if "pipe" in d.lower():
                dirs[i] = pipe_dir
                replaced = True
                break
        if not replaced:
            dirs.append(pipe_dir)

        # Deduplicate while preserving order.
        seen: set[str] = set()
        cleaned: list[str] = []
        for d in dirs:
            if d not in seen:
                seen.add(d)
                cleaned.append(d)
        new_line = f"{indent}directories = {{ " + ", ".join(f'\"{d}\"' for d in cleaned) + " }"
        new_block = block[:m.start()] + new_line + block[m.end():]
    else:
        # Insert a new directories line near the top of the block.
        # Try to match indentation style (tabs in upstream example).
        indent = "\t"
        for ln in block.splitlines()[1:]:
            if ln.strip() and not ln.lstrip().startswith("#"):
                indent = re.match(r"^\s*", ln).group(0)  # type: ignore[union-attr]
                break
        insert_at = block.find("{")
        insert_at = block.find("\n", insert_at)
        if insert_at == -1:
            return False
        insert_at += 1
        new_line = f"{indent}directories = {{ \"{pipe_dir}\" }}\n"
        new_block = block[:insert_at] + new_line + block[insert_at:]

    new_text = text[:span[0]] + new_block + text[span[1]:]
    try:
        _atomic_write_text(path, new_text)
    except Exception:
        logger.exception("Failed writing %s", path)
        return False

    OWNTONE_PIPE_DIR = pipe_dir
    return True


def read_and_set_global_uncompressed_audio(conf_path: Path | str = OWNTONE_CONF_PATH) -> bool:
    """Read and set OwnTone's `airplay_shared.uncompressed_alac`."""
    global OWNTONE_UNCOMPRESSED_ALAC
    path = Path(conf_path)
    text = _read_text(path)
    if not text:
        OWNTONE_UNCOMPRESSED_ALAC = False
        return False

    span = _find_block_span(text, re.compile(r"(?m)^\s*airplay_shared\s*\{\s*$"))
    if not span:
        OWNTONE_UNCOMPRESSED_ALAC = False
        return False

    block = text[span[0]:span[1]]
    m = re.search(r"(?m)^\s*uncompressed_alac\s*=\s*(?P<v>[^\s#]+)", block)
    val = _parse_bool(m.group("v")) if m else None
    OWNTONE_UNCOMPRESSED_ALAC = bool(val) if val is not None else False
    return OWNTONE_UNCOMPRESSED_ALAC


def write_and_set_global_uncompressed_audio(enabled: bool, conf_path: Path | str = OWNTONE_CONF_PATH) -> bool:
    """Write OwnTone's `airplay_shared.uncompressed_alac` and update global."""
    global OWNTONE_UNCOMPRESSED_ALAC
    path = Path(conf_path)
    text = _read_text(path)
    if not text:
        return False

    shared_re = re.compile(r"(?m)^\s*airplay_shared\s*\{\s*$")
    span = _find_block_span(text, shared_re)

    if span:
        block = text[span[0]:span[1]]
        line_re = re.compile(r"(?m)^(?P<indent>\s*)uncompressed_alac\s*=\s*[^\s#]+(?P<rest>\s*(?:#.*)?)$")
        m = line_re.search(block)
        if m:
            indent = m.group("indent")
            rest = m.group("rest") or ""
            new_line = f"{indent}uncompressed_alac = {_bool_to_conf(bool(enabled))}{rest}"
            new_block = block[:m.start()] + new_line + block[m.end():]
        else:
            # Insert before closing brace.
            close_idx = block.rfind("}")
            if close_idx == -1:
                return False
            # Guess indentation.
            indent = "\t"
            for ln in block.splitlines()[1:]:
                if ln.strip() and not ln.lstrip().startswith("#"):
                    indent = re.match(r"^\s*", ln).group(0)  # type: ignore[union-attr]
                    break
            ins = f"{indent}uncompressed_alac = {_bool_to_conf(bool(enabled))}\n"
            new_block = block[:close_idx] + ins + block[close_idx:]

        new_text = text[:span[0]] + new_block + text[span[1]:]
    else:
        # Append a new block.
        if not text.endswith("\n"):
            text += "\n"
        new_text = text + (
            "\nairplay_shared {\n"
            f"\tuncompressed_alac = {_bool_to_conf(bool(enabled))}\n"
            "}\n"
        )

    try:
        _atomic_write_text(path, new_text)
    except Exception:
        logger.exception("Failed writing %s", path)
        return False

    OWNTONE_UNCOMPRESSED_ALAC = bool(enabled)
    return True


def read_airplay2_for_speaker(speaker_name: str, conf_path: Path | str = OWNTONE_CONF_PATH) -> Optional[bool]:
    """Return True if RAOP (AirPlay 1) is disabled for this speaker.

    OwnTone uses `raop_disable = true` inside an `airplay "NAME" { ... }` block
    to disable AirPlay 1 for that device (effectively forcing AirPlay 2 when supported).
    """
    speaker_name = (speaker_name or "").strip()
    if not speaker_name:
        return None

    path = Path(conf_path)
    text = _read_text(path)
    if not text:
        return None

    header = re.compile(rf'(?m)^\s*airplay\s+"{re.escape(speaker_name)}"\s*\{{\s*$')
    span = _find_block_span(text, header)
    if not span:
        return None

    block = text[span[0]:span[1]]
    m = re.search(r"(?m)^\s*raop_disable\s*=\s*(?P<v>[^\s#]+)", block)
    v = _parse_bool(m.group("v")) if m else None
    return v


def write_airplay2_for_speaker(speaker_name: str, enabled: bool, conf_path: Path | str = OWNTONE_CONF_PATH) -> bool:
    """Set AirPlay2 preference for a named speaker by writing `raop_disable`.

    - enabled=True  -> writes `raop_disable = true`
    - enabled=False -> writes `raop_disable = false`
    """
    speaker_name = (speaker_name or "").strip()
    if not speaker_name:
        return False

    path = Path(conf_path)
    text = _read_text(path)
    if not text:
        return False

    header = re.compile(rf'(?m)^\s*airplay\s+"{re.escape(speaker_name)}"\s*\{{\s*$')
    span = _find_block_span(text, header)

    if span:
        block = text[span[0]:span[1]]
        line_re = re.compile(r"(?m)^(?P<indent>\s*)raop_disable\s*=\s*[^\s#]+(?P<rest>\s*(?:#.*)?)$")
        m = line_re.search(block)
        if m:
            indent = m.group("indent")
            rest = m.group("rest") or ""
            new_line = f"{indent}raop_disable = {_bool_to_conf(bool(enabled))}{rest}"
            new_block = block[:m.start()] + new_line + block[m.end():]
        else:
            close_idx = block.rfind("}")
            if close_idx == -1:
                return False
            indent = "\t"
            for ln in block.splitlines()[1:]:
                if ln.strip() and not ln.lstrip().startswith("#"):
                    indent = re.match(r"^\s*", ln).group(0)  # type: ignore[union-attr]
                    break
            ins = f"{indent}raop_disable = {_bool_to_conf(bool(enabled))}\n"
            new_block = block[:close_idx] + ins + block[close_idx:]

        new_text = text[:span[0]] + new_block + text[span[1]:]
    else:
        # Append a new per-device block.
        if not text.endswith("\n"):
            text += "\n"
        new_text = text + (
            f"\nairplay \"{speaker_name}\" {{\n"
            f"\traop_disable = {_bool_to_conf(bool(enabled))}\n"
            "}\n"
        )

    try:
        _atomic_write_text(path, new_text)
    except Exception:
        logger.exception("Failed writing %s", path)
        return False
    return True


# ---------------------------------------------------------------------------
# OwnTone config health check + auto-fix
# ---------------------------------------------------------------------------

OWNTONE_OK = 0
OWNTONE_RESTART_REQUIRED = 1
OWNTONE_NOT_OK = -1
OWNTONE_TARGET_PIPE_DIR = "/tmp/autostream-pipes"
OWNTONE_TARGET_LOGLEVEL = "info"


def owntone_config_ok(conf_path: Path | str = OWNTONE_CONF_PATH) -> int:
    """
    Ensure owntone.conf has:
      1) library.directories = { "/tmp/autostream-pipes" }
      2) pipe_autostart enabled (pipe_autostart = true) inside library block
      3) general.loglevel = info

    Return codes:
      - OWNTONE_OK (=0) if already correct
      - OWNTONE_RESTART_REQUIRED (=1) if file was updated successfully
      - OWNTONE_NOT_OK (=-1) if update was needed but failed
    """
    path = Path(conf_path)
    text = _read_text(path)
    if not text:
        return OWNTONE_NOT_OK

    lib_re = re.compile(r"(?m)^\s*library\s*\{\s*$")
    lib_span = _find_block_span(text, lib_re)
    if not lib_span:
        return OWNTONE_NOT_OK
    lib_block = text[lib_span[0] : lib_span[1]]

    gen_re = re.compile(r"(?m)^\s*general\s*\{\s*$")
    gen_span = _find_block_span(text, gen_re)
    if not gen_span:
        return OWNTONE_NOT_OK
    gen_block = text[gen_span[0] : gen_span[1]]

    def _dirs_ok(b: str) -> bool:
        m = re.search(r"(?m)^\s*directories\s*=\s*\{(?P<body>[^}]*)\}\s*$", b)
        if not m:
            return False
        dirs = re.findall(r'"([^"]*)"', m.group("body"))
        return len(dirs) == 1 and dirs[0] == OWNTONE_TARGET_PIPE_DIR

    def _pipe_ok(b: str) -> bool:
        m = re.search(r"(?m)^\s*pipe_autostart\s*=\s*(?P<v>[^\s#]+)", b)
        if not m:
            return False
        val = _parse_bool(m.group("v"))
        return val is True

    def _loglevel_ok(b: str) -> bool:
        m = re.search(r"(?m)^\s*loglevel\s*=\s*(?P<v>[^\s#]+)", b)
        if not m:
            return False
        return m.group("v").strip().strip('"').lower() == OWNTONE_TARGET_LOGLEVEL

    dirs_ok = _dirs_ok(lib_block)
    pipe_ok = _pipe_ok(lib_block)
    log_ok = _loglevel_ok(gen_block)

    if dirs_ok and pipe_ok and log_ok:
        return OWNTONE_OK

    # Update library.directories target
    dir_line_re = re.compile(r"(?m)^(?P<indent>\s*)directories\s*=\s*\{[^}]*\}\s*$")
    m = dir_line_re.search(lib_block)
    if m:
        indent = m.group("indent")
        new_line = f'{indent}directories = {{ "{OWNTONE_TARGET_PIPE_DIR}" }}'
        lib_block = lib_block[: m.start()] + new_line + lib_block[m.end() :]
    else:
        insert_at = lib_block.find("{")
        insert_at = lib_block.find("\n", insert_at)
        if insert_at == -1:
            return OWNTONE_NOT_OK
        insert_at += 1
        lib_block = (
            lib_block[:insert_at]
            + f'\tdirectories = {{ "{OWNTONE_TARGET_PIPE_DIR}" }}\n'
            + lib_block[insert_at:]
        )

    # Enable pipe_autostart
    pipe_commented_re = re.compile(
        r"(?m)^(?P<indent>\s*)#\s*pipe_autostart\s*=\s*(true|false)\s*$"
    )
    m = pipe_commented_re.search(lib_block)
    if m:
        indent = m.group("indent")
        new_line = f"{indent}pipe_autostart = true"
        lib_block = lib_block[: m.start()] + new_line + lib_block[m.end() :]
    else:
        pipe_live_re = re.compile(
            r"(?m)^(?P<indent>\s*)pipe_autostart\s*=\s*(true|false)\s*$"
        )
        m2 = pipe_live_re.search(lib_block)
        if m2:
            indent = m2.group("indent")
            new_line = f"{indent}pipe_autostart = true"
            lib_block = lib_block[: m2.start()] + new_line + lib_block[m2.end() :]
        else:
            close_idx = lib_block.rfind("}")
            if close_idx == -1:
                return OWNTONE_NOT_OK
            lib_block = lib_block[:close_idx] + "\tpipe_autostart = true\n" + lib_block[close_idx:]

    # Set general.loglevel = info
    log_live_re = re.compile(r"(?m)^(?P<indent>\s*)loglevel\s*=\s*[^\s#]+\s*$")
    ml = log_live_re.search(gen_block)
    if ml:
        indent = ml.group("indent")
        new_line = f"{indent}loglevel = {OWNTONE_TARGET_LOGLEVEL}"
        gen_block = gen_block[: ml.start()] + new_line + gen_block[ml.end() :]
    else:
        log_commented_re = re.compile(r"(?m)^(?P<indent>\s*)#\s*loglevel\s*=\s*[^\s#]+\s*$")
        mlc = log_commented_re.search(gen_block)
        if mlc:
            indent = mlc.group("indent")
            new_line = f"{indent}loglevel = {OWNTONE_TARGET_LOGLEVEL}"
            gen_block = gen_block[: mlc.start()] + new_line + gen_block[mlc.end() :]
        else:
            insert_at = gen_block.find("{")
            insert_at = gen_block.find("\n", insert_at)
            if insert_at == -1:
                return OWNTONE_NOT_OK
            insert_at += 1
            gen_block = (
                gen_block[:insert_at]
                + f"\tloglevel = {OWNTONE_TARGET_LOGLEVEL}\n"
                + gen_block[insert_at:]
            )

    # Replace blocks from end to start to keep offsets valid
    new_text = text
    for span, new_block in sorted([(lib_span, lib_block), (gen_span, gen_block)], key=lambda x: x[0][0], reverse=True):
        new_text = new_text[: span[0]] + new_block + new_text[span[1] :]

    try:
        _atomic_write_text(path, new_text)
    except Exception:
        logger.exception("Failed writing %s", path)
        return OWNTONE_NOT_OK

    updated = _read_text(path)
    if not updated:
        return OWNTONE_NOT_OK

    lib_span2 = _find_block_span(updated, lib_re)
    gen_span2 = _find_block_span(updated, gen_re)
    if not lib_span2 or not gen_span2:
        return OWNTONE_NOT_OK

    lib_block2 = updated[lib_span2[0] : lib_span2[1]]
    gen_block2 = updated[gen_span2[0] : gen_span2[1]]

    if _dirs_ok(lib_block2) and _pipe_ok(lib_block2) and _loglevel_ok(gen_block2):
        return OWNTONE_RESTART_REQUIRED

    return OWNTONE_NOT_OK
