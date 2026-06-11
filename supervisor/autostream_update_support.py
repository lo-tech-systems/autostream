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
API_LATEST    = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/latest"
RELEASES_HTML = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/releases"

FLOCK_BIN             = "/usr/bin/flock"
SYSTEMDRUN_CANDIDATES = ("/bin/systemd-run", "/usr/bin/systemd-run")

_semver_re = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].*)?$")


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


def _version_key(v: str) -> Tuple[int, int, int, str]:
    """Return a comparison key for vMAJOR.MINOR.PATCH style tags."""
    m = _semver_re.match((v or "").strip())
    if not m:
        return (0, 0, 0, v or "")
    return (int(m.group(1) or 0), int(m.group(2) or 0), int(m.group(3) or 0), v or "")


def _sanitise_release_notes(text: str, max_len: int = 200) -> str:
    """Return a sanitised plain-text summary from a GitHub release body."""
    cleaned = "".join(ch for ch in text if 0x20 <= ord(ch) <= 0x7E)
    cleaned = " ".join(cleaned.split())
    return cleaned[:max_len].strip()


def _github_latest_release(
    ua: str,
) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Return (reachable, tag_name, tarball_url, html_url, release_notes).

    reachable is False when the API call itself fails (network error or a
    non-404 HTTP error).  reachable is True when the API responded, even if
    there is no published release (404 or empty tag_name).  Callers must
    check reachable before treating a missing tag as "no releases yet".
    """
    try:
        status, raw = _http_get(API_LATEST, ua, timeout=20)
        if status == 404:
            return True, None, None, None, None
        data = json.loads(raw.decode("utf-8", errors="replace"))
        tag      = data.get("tag_name")
        tarball  = data.get("tarball_url")
        html     = data.get("html_url")
        raw_body = data.get("body") or ""
        notes    = _sanitise_release_notes(str(raw_body)) if raw_body else None
        if not tag:
            return True, None, None, (str(html) if html else None), notes
        return (
            True,
            str(tag),
            (str(tarball) if tarball else None),
            (str(html) if html else None),
            notes,
        )
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
