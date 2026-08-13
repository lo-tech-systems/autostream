"""autostream_update_support — shared update foundations.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Provides HTTP, versioning, tarball staging, and systemd-run helpers shared
by autostream_updater and autostream_dial_updater.  Each script owns its
product-specific paths, UA string, log file, and command implementations.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import tarfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional, Tuple

REPO_OWNER = "lo-tech-systems"
REPO_NAME  = "autostream"
API_LATEST    = (
    "https://api.github.com/repos/"
    f"{REPO_OWNER}/{REPO_NAME}/releases/latest"
)
# Window size for the dev-channel releases list fetch.  The list is ordered
# by creation time, not by version precedence, so a single-item fetch can
# miss the highest-version release; RELEASES_PAGE_SIZE bounds how far back
# we look while still being cheap.
RELEASES_PAGE_SIZE = 30
API_RELEASES  = (
    "https://api.github.com/repos/"
    f"{REPO_OWNER}/{REPO_NAME}/releases?per_page={RELEASES_PAGE_SIZE}"
)
RELEASES_HTML = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/releases"

FLOCK_BIN             = "/usr/bin/flock"
SYSTEMDRUN_CANDIDATES = ("/bin/systemd-run", "/usr/bin/systemd-run")

# Matches vMAJOR[.MINOR[.PATCH]][-LABEL[.N]][+build] — groups:
#   1=major, 2=minor, 3=patch, 4=prerelease-label, 5=prerelease-number
_semver_re = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?"
    r"(?:-([a-zA-Z][a-zA-Z0-9]*)(?:\.(\d+))?)?(?:\+.*)?$"
)

# Ordered label → rank; unknown labels get 0 (below all recognised labels
# and below final releases).
_LABEL_RANK: dict[str, int] = {"alpha": 1, "beta": 2, "rc": 3}


def _normalise_update_channel(value: object) -> str:
    """Return 'dev' only when *value* normalises to 'dev'; otherwise 'stable'."""
    return "dev" if str(value or "").strip().lower() == "dev" else "stable"


def _run(cmd: list[str], timeout: int = 60) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()


def _http_get(url: str, ua: str, timeout: int = 20) -> Tuple[int, bytes]:
    # No extra-headers parameter here (kept intentionally minimal) -- a
    # Cache-Control: no-cache header on the releases list fetch would help
    # avoid a stale intermediary cache, but adding a headers param would
    # touch every existing caller.  Left as a caveat rather than refactored.
    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return getattr(resp, "status", 200), resp.read()


def _read_env_file(path: Path) -> dict[str, str]:
    """Parse a KEY=VALUE env file; returns an empty dict if the file is absent."""
    data: dict[str, str] = {}
    try:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            data[key] = value
    except OSError:
        pass
    return data


def _version_key(v: str) -> Tuple[int, int, int, int, int, int, str]:
    """Return a 7-element comparison key with correct prerelease ordering.

    Shape: (major, minor, patch, final_rank, label_rank, prerelease_number, suffix)

    - final_rank=1 for a final release, 0 for a prerelease — ensures final
      releases sort above any prerelease of the same version.
    - label_rank orders alpha(1) < beta(2) < rc(3); unknown labels get 0,
      sorting below the recognised progression and below the final release.
    - prerelease_number is the integer after the label dot (e.g. beta.10 → 10),
      defaulting to 0 when absent.  This ensures beta.2 < beta.10.
    - suffix is the raw normalised tag used only as a deterministic tie-break.
    - Build metadata after '+' does not affect ordering.
    - Missing minor/patch components are treated as 0.
    - Malformed tags return (0, 0, 0, 0, 0, 0, raw_tag) — safe and ordered
      below every well-formed tag.
    """
    tag = (v or "").strip()
    m = _semver_re.match(tag)
    if not m:
        return (0, 0, 0, 0, 0, 0, tag)
    major = int(m.group(1) or 0)
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)
    label = (m.group(4) or "").lower()
    pre_n = int(m.group(5) or 0)
    # Build a canonical suffix from the parsed components so that v1.3.0, 1.3.0,
    # and 1.3 all produce the same tuple (equal for ordering purposes).
    if not label:
        norm_suffix = f"{major}.{minor}.{patch}"
        return (major, minor, patch, 1, 0, 0, norm_suffix)
    label_rank = _LABEL_RANK.get(label, 0)
    norm_suffix = f"{major}.{minor}.{patch}-{label}.{pre_n}"
    return (major, minor, patch, 0, label_rank, pre_n, norm_suffix)


def _sanitise_release_notes(text: str, max_len: int = 4000) -> str:
    """Return a sanitised, newline-preserving summary from a GitHub release body.

    - Normalises \\r\\n and \\r line endings to \\n.
    - Keeps only printable ASCII (0x20-0x7E) plus newline; all other
      characters (including non-ASCII and control characters) are dropped.
    - Collapses runs of spaces/tabs within a line to a single space and
      strips trailing whitespace from each line.
    - Collapses runs of 3+ consecutive blank lines down to 2, preserving
      paragraph breaks without allowing unbounded vertical whitespace.
    - Truncates to max_len; when truncation is needed, prefers cutting at
      the last newline within the final 20% of the kept text so lines are
      not split mid-way when a cheap, nearby boundary is available.
    - Strips leading/trailing blank lines from the final result.
    """
    normalised = text.replace("\r\n", "\n").replace("\r", "\n")
    # Tabs are kept through this pass (despite being outside the 0x20-0x7E
    # whitelist) purely so the per-line collapse below can fold them into a
    # single space along with runs of spaces; no literal tab survives.
    kept = "".join(ch for ch in normalised if ch in ("\n", "\t") or 0x20 <= ord(ch) <= 0x7E)

    lines = [re.sub(r"[ \t]+", " ", line).rstrip() for line in kept.split("\n")]
    collapsed_lines: list = []
    blank_run = 0
    for line in lines:
        if line == "":
            blank_run += 1
            if blank_run <= 2:
                collapsed_lines.append(line)
        else:
            blank_run = 0
            collapsed_lines.append(line)
    cleaned = "\n".join(collapsed_lines)

    if len(cleaned) > max_len:
        truncated = cleaned[:max_len]
        boundary = int(max_len * 0.8)
        cut = truncated.rfind("\n")
        if cut >= boundary:
            truncated = truncated[:cut]
        cleaned = truncated

    return cleaned.strip("\n")


def _parse_release_object(
    data: dict,
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Parse a GitHub release JSON object into (tag, tarball_url, html_url, notes)."""
    tag     = data.get("tag_name")
    tarball = data.get("tarball_url")
    html    = data.get("html_url")
    raw_body = data.get("body") or ""
    notes   = _sanitise_release_notes(str(raw_body)) if raw_body else None
    return (
        str(tag)     if tag     else None,
        str(tarball) if tarball else None,
        str(html)    if html    else None,
        notes,
    )


def _fetch_releases_list(ua: str) -> Tuple[bool, list]:
    """Fetch the releases-list window (API_RELEASES).

    Returns (reachable, entries).  reachable is False only when the request
    itself failed (network error, non-JSON body, or an unexpected shape);
    an empty list is a normal, reachable result (no releases published yet).
    """
    try:
        _status, raw = _http_get(API_RELEASES, ua, timeout=20)
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return False, []
    if not isinstance(data, list):
        return False, []
    return True, data


def _fetch_latest_release(ua: str) -> Tuple[bool, list]:
    """Fetch /releases/latest (API_LATEST) as a single-entry candidate list.

    Returns (reachable, entries).  A 404 (no releases published) is treated
    as reachable with an empty entry list, so it composes the same way as an
    empty releases-list result.  Any other failure (network error, non-404
    HTTP error, non-JSON body) is unreachable.
    """
    try:
        _status, raw = _http_get(API_LATEST, ua, timeout=20)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return True, []
        return False, []
    except Exception:
        return False, []
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return False, []
    if not isinstance(data, dict):
        return False, []
    return True, [data]


def _github_latest_release(
    ua: str,
    channel: str = "stable",
) -> Tuple[
    bool,
    Optional[str],
    Optional[str],
    Optional[str],
    Optional[str],
]:
    """Return (reachable, tag_name, tarball_url, html_url, release_notes).

    reachable is False when the API call itself fails (network error or a
    non-404 HTTP error).  reachable is True when the API responded, even if
    there is no published release (404 or empty tag_name/list).  Callers
    must check reachable before treating a missing tag as "no releases yet".

    channel is normalised before use:
      stable → uses /releases/latest (JSON object)
      dev    → uses /releases?per_page=RELEASES_PAGE_SIZE (JSON list) *and*
               /releases/latest, picking the highest-precedence tag across
               both (see selection comment below for why both are needed)
    """
    channel = _normalise_update_channel(channel)
    if channel != "dev":
        try:
            _status, raw = _http_get(API_LATEST, ua, timeout=20)
            data = json.loads(raw.decode("utf-8", errors="replace"))
            tag, tarball, html, notes = _parse_release_object(data)
            if not tag:
                return True, None, None, html, notes
            return True, tag, tarball, html, notes
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return True, None, None, None, None
            return False, None, None, None, None
        except Exception:
            return False, None, None, None, None

    # dev channel: the releases list is ordered by creation time, not by
    # version precedence or publish time, and it has been observed to omit
    # a just-published release entirely for some time after publication
    # while /releases/latest already served it correctly.  So we fetch both,
    # pool every candidate with a usable tag, and pick the max by
    # _version_key -- that's the only ordering that reflects actual release
    # precedence.  Either source failing independently must not fail the
    # whole resolution; only both failing is unreachable.
    list_reachable, list_entries = _fetch_releases_list(ua)
    latest_reachable, latest_entries = _fetch_latest_release(ua)

    if not list_reachable and not latest_reachable:
        return False, None, None, None, None

    best_entry = None
    best_key = None
    for entry in list_entries + latest_entries:
        if not isinstance(entry, dict):
            continue
        tag = entry.get("tag_name")
        if not tag:
            continue
        key = _version_key(str(tag))
        if best_entry is None or key > best_key:
            best_entry = entry
            best_key = key

    if best_entry is None:
        # Both sources reachable (or one reachable, one failed) but neither
        # yielded a usable tagged release.
        return True, None, None, None, None

    tag, tarball, html, notes = _parse_release_object(best_entry)
    if not tag:
        return True, None, None, html, notes
    return True, tag, tarball, html, notes


def _download_file(url: str, dst: Path, ua: str, timeout: int = 120) -> None:
    req = urllib.request.Request(
        url, headers={"User-Agent": ua, "Accept": "application/vnd.github+json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        dst.parent.mkdir(parents=True, exist_ok=True)
        with dst.open("wb") as f:
            shutil.copyfileobj(resp, f)


def _find_systemd_run() -> Optional[str]:
    """Return an absolute path to systemd-run if available, else None."""
    for path in SYSTEMDRUN_CANDIDATES:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    p = shutil.which("systemd-run")
    if p and os.path.isabs(p) and os.access(p, os.X_OK):
        return p
    return None


def is_active_transient_unit(pattern: str) -> bool:
    """Return True if any unit matching *pattern* is currently active.

    Raises RuntimeError on systemctl failure so callers used for admission
    control can reject the request conservatively rather than failing open.
    """
    rc, out, err = _run(
        ["systemctl", "list-units", "--state=active", "--no-legend", "--plain", pattern],
        timeout=10,
    )
    if rc != 0:
        raise RuntimeError(f"systemctl exited rc={rc}: {err!r}")
    return bool(out.strip())


def stage_release(
    tarball_url: str,
    tag: str,
    staging_dir: Path,
    installer_filename: str,
    required_paths: list,
    ua: str,
) -> Path:
    """Download, extract, and verify a release tarball into *staging_dir*.

    Cleans and recreates *staging_dir* with mode 0700, downloads the tarball,
    extracts with the safe 'data' filter, locates the installer, marks it
    executable, verifies *required_paths* exist, writes release_tag, and
    returns the installer path.  Removes partial staging on any failure and
    re-raises so callers can format a product-specific error response.
    """
    if staging_dir.exists():
        shutil.rmtree(str(staging_dir))

    staging_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(str(staging_dir), 0o700)

    try:
        tar_path = staging_dir / "release.tgz"
        _download_file(tarball_url, tar_path, ua, timeout=120)

        extract_dir = staging_dir / "src"
        extract_dir.mkdir(parents=True, exist_ok=True)

        with tarfile.open(tar_path, "r:gz") as tf:
            # filter='data' (Python 3.12+) strips absolute paths, '../' traversal
            # sequences, and unsafe member types (devices, setuid bits) before
            # extraction.  Without a filter a crafted tarball could write to
            # arbitrary filesystem paths because the updaters run as root.
            tf.extractall(extract_dir, filter="data")

        top_dirs = [p for p in extract_dir.iterdir() if p.is_dir()]
        repo_root = top_dirs[0] if len(top_dirs) == 1 else extract_dir

        installer = repo_root / installer_filename
        if not installer.exists():
            raise FileNotFoundError(
                f"{installer_filename} not found in extracted tree at {repo_root}"
            )
        os.chmod(str(installer), 0o755)

        for rel_path in required_paths:
            if not (repo_root / rel_path).exists():
                raise FileNotFoundError(
                    f"Expected {rel_path!r} not found in extracted tree at {repo_root}"
                )

        tag_file = staging_dir / "release_tag"
        tag_file.write_text(tag + "\n", encoding="utf-8")
        os.chmod(str(tag_file), 0o600)

        return installer
    except Exception:
        shutil.rmtree(str(staging_dir), ignore_errors=True)
        raise


def schedule_locked_installer(
    systemd_run: str,
    unit_name: str,
    lock_path: "str | Path",
    installer: "str | Path",
    installer_args: list,
    delay: int = 1,
    extra_env: Optional[dict] = None,
    extra_properties: Optional[list] = None,
) -> Tuple[int, str, str]:
    """Build and run a systemd-run + flock command to schedule an installer.

    Returns *(rc, stdout, stderr)*.
    """
    cmd: list = [
        systemd_run,
        "--quiet",
        "--collect",
        f"--unit={unit_name}",
        f"--on-active={delay}",
        "--property=Type=oneshot",
    ]
    if extra_properties:
        for prop in extra_properties:
            cmd.append(f"--property={prop}")
    if extra_env:
        for k, v in extra_env.items():
            cmd.append(f"--setenv={k}={v}")
    cmd += [
        "--",
        FLOCK_BIN, "--exclusive", str(lock_path),
        str(installer),
    ]
    cmd.extend(installer_args)
    return _run(cmd, timeout=15)


# ---- Pre-update teardown (host only: stop playback, free repeat buffer) -----
#
# Host-only helpers.  autostream_dial_updater does not call these -- the dial
# product has no OwnTone backend and no autostream_monitor daemon, so there is
# nothing to stop or free there.  See the host callers (autostream_updater
# cmd_apply, autostream_update_retry) for the single choke point each host
# update path passes through before scheduling the installer's heavy work
# (apt + OwnTone build).

OWNTONE_BASE_URL = "http://localhost:3689"
MONITOR_SOCKET_PATH = "/tmp/autostream_monitor.sock"


def _http_put(
    url: str, payload: Optional[dict], ua: str, timeout: float = 3.0
) -> Tuple[int, bytes]:
    data = None
    headers = {"User-Agent": ua}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method="PUT")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return getattr(resp, "status", 200), resp.read()


def stop_owntone_playback(
    base_url: str = OWNTONE_BASE_URL,
    ua: str = "autostream-updater/1.0",
    timeout: float = 3.0,
) -> Tuple[bool, str]:
    """Best-effort: stop playback and deselect all OwnTone outputs.

    Mirrors autostream_core.stop_and_disable_all's two calls (PUT
    /api/player/stop, then PUT /api/outputs/set with an empty outputs list)
    using plain urllib rather than importing core/, since these updater
    scripts are intentionally self-contained (installed outside /opt/autostream
    so they survive a broken or in-progress web-app update).  Never raises --
    callers should log-and-continue on failure (OwnTone may simply be down).
    """
    errors = []

    try:
        status, _body = _http_put(base_url.rstrip("/") + "/api/player/stop", None, ua, timeout)
        if status not in (200, 204):
            errors.append(f"stop returned HTTP {status}")
    except urllib.error.HTTPError as e:
        errors.append(f"stop failed: HTTP {e.code}")
    except Exception as e:
        errors.append(f"stop failed: {e}")

    try:
        status, _body = _http_put(
            base_url.rstrip("/") + "/api/outputs/set", {"outputs": []}, ua, timeout
        )
        if status not in (200, 204):
            errors.append(f"disable-outputs returned HTTP {status}")
    except urllib.error.HTTPError as e:
        errors.append(f"disable-outputs failed: HTTP {e.code}")
    except Exception as e:
        errors.append(f"disable-outputs failed: {e}")

    if errors:
        return False, "; ".join(errors)
    return True, "playback stopped and outputs deselected"


def _monitor_socket_request(
    sock_path: str, request: dict, timeout: float = 3.0
) -> Tuple[bool, Optional[dict], str]:
    """Send one newline-delimited JSON request to the monitor control socket.

    Returns (sent_ok, response_dict_or_None, error).  sent_ok is False only
    when the socket itself could not be reached (absent, refused, timed out);
    a malformed/rejecting response from a reachable daemon still returns
    sent_ok=True with the parsed ack (so callers can distinguish "monitor not
    running" from "old binary rejected the command").
    """
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(sock_path)
            sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
    except (OSError, socket.timeout) as e:
        return False, None, str(e)

    line = buf.split(b"\n", 1)[0]
    try:
        resp = json.loads(line.decode("utf-8", errors="replace"))
    except Exception as e:
        return True, None, f"invalid response: {e}"
    if not isinstance(resp, dict):
        return True, None, "unexpected response shape"
    return True, resp, ""


def free_repeat_buffer(
    sock_path: str = MONITOR_SOCKET_PATH, timeout: float = 3.0
) -> Tuple[bool, str]:
    """Best-effort: disarm and disable the "repeat" feature on the live daemon.

    Frees the in-RAM recording buffer (up to ~120 MiB+) before the update's
    heavy work (apt + OwnTone build, 40+ minutes on SD) runs, so that memory
    is available.  This intentionally does NOT touch the persisted
    repeat.enabled value in /etc/autostream/autostream.json -- the coordinator
    re-pushes that persisted value to the monitor on every startup and on every
    post-disconnect reconnect (see autostream_core._push_repeat_policy callers),
    so the live daemon's repeat policy is restored automatically once services
    resume after the update, without this script needing to read or write JSON
    config.

    Tolerates the socket being absent (monitor stopped) and an old monitor
    binary predating this feature rejecting either command -- both are
    logged by the caller and never fatal to the update.  Never raises.
    """
    results = []
    for request in (
        {"type": "set_repeat_armed", "armed": False},
        {"type": "set_repeat_enabled", "enabled": False, "codec": "auto"},
    ):
        cmd = request["type"]
        try:
            sent, resp, err = _monitor_socket_request(sock_path, request, timeout)
        except Exception as e:
            results.append(f"{cmd}: unexpected error: {e}")
            continue
        if not sent:
            results.append(f"{cmd}: socket unavailable: {err}")
        elif not (resp or {}).get("ok", False):
            results.append(f"{cmd}: rejected: {(resp or {}).get('error', err or 'unknown error')}")
        else:
            results.append(f"{cmd}: ok")

    ok_overall = all(r.endswith(": ok") for r in results)
    return ok_overall, "; ".join(results)
