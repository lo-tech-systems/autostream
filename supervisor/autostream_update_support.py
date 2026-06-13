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
import subprocess
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
API_RELEASES  = (
    "https://api.github.com/repos/"
    f"{REPO_OWNER}/{REPO_NAME}/releases?per_page=1"
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


def _sanitise_release_notes(text: str, max_len: int = 200) -> str:
    """Return a sanitised plain-text summary from a GitHub release body."""
    cleaned = "".join(ch for ch in text if 0x20 <= ord(ch) <= 0x7E)
    cleaned = " ".join(cleaned.split())
    return cleaned[:max_len].strip()


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
      dev    → uses /releases?per_page=1 (JSON list, first item)
    """
    channel = _normalise_update_channel(channel)
    try:
        if channel == "dev":
            _status, raw = _http_get(API_RELEASES, ua, timeout=20)
            data_list = json.loads(raw.decode("utf-8", errors="replace"))
            if not isinstance(data_list, list):
                return False, None, None, None, None
            if not data_list:
                # API reachable but no published release exists.
                return True, None, None, None, None
            tag, tarball, html, notes = _parse_release_object(data_list[0])
        else:
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
