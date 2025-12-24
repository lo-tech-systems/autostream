#!/usr/bin/env python3
"""autostream-updater

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Root-only helper used by the Autostream web UI.

UPDATED IMPLEMENTATION

1) Check for updates by looking at GitHub releases for lo-tech-systems/autostream and
   comparing the latest release version to /opt/autostream/release.
2) If /opt/autostream/release does not exist, assume an update is available (provided
   the GitHub repo/releases is reachable, i.e. not a 404).
3) To update, download the latest release tarball and copy only *.py files into
   /opt/autostream, then update /opt/autostream/release.

Outputs JSON on stdout (kept compatible with the current web UI):
- check: {ok, installed, candidate, update_available, apmode}
- apply: {ok, installed} on success, or {ok:false, error, details?} on failure
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# ---- Paths / constants ----
LOG_PATH = Path("/var/log/autostream/update.log")
APMODE_FLAG = Path("/tmp/apmode")
INSTALL_DIR = Path("/opt/autostream")
RELEASE_FILE = INSTALL_DIR / "release"

# GitHub repo
REPO_OWNER = "lo-tech-systems"
REPO_NAME = "autostream"
RELEASES_HTML = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/releases"
API_LATEST = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/latest"

# A conservative user-agent helps avoid 403s.
UA = "autostream-updater/1.0 (+https://github.com/lo-tech-systems/autostream)"


# ---- Helpers ----

def _log(msg: str) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")


def _run(cmd: list[str], timeout: int = 60) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()


def _http_get(url: str, timeout: int = 20) -> Tuple[int, bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        status = getattr(resp, "status", 200)
        return status, resp.read()


def _repo_exists() -> bool:
    """Return True if the repo releases page is reachable (not 404)."""
    try:
        req = urllib.request.Request(RELEASES_HTML, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return getattr(resp, "status", 200) < 400
    except urllib.error.HTTPError as e:
        return False if e.code == 404 else False
    except Exception:
        return False


def _read_installed_version() -> str:
    try:
        v = RELEASE_FILE.read_text(encoding="utf-8").strip()
        return v or "unknown"
    except FileNotFoundError:
        return "missing"
    except Exception:
        return "unknown"


_semver_re = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].*)?$")


def _version_key(v: str) -> Tuple[int, int, int, str]:
    """Return a comparison key for typical vMAJOR.MINOR.PATCH style tags."""
    m = _semver_re.match((v or "").strip())
    if not m:
        return (0, 0, 0, v or "")
    maj = int(m.group(1) or 0)
    min_ = int(m.group(2) or 0)
    pat = int(m.group(3) or 0)
    return (maj, min_, pat, v)


def _github_latest_release() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (tag_name, tarball_url, html_url) from GitHub latest release."""
    try:
        status, raw = _http_get(API_LATEST, timeout=20)
        if status == 404:
            return None, None, None
        data = json.loads(raw.decode("utf-8", errors="replace"))
        tag = data.get("tag_name")
        tarball = data.get("tarball_url")
        html = data.get("html_url")
        if not tag:
            return None, None, html
        return str(tag), (str(tarball) if tarball else None), (str(html) if html else None)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, None, None
        _log(f"github_latest_release: HTTPError {e.code}")
        return None, None, None
    except Exception as e:
        _log(f"github_latest_release: exception {e}")
        return None, None, None


def _download_file(url: str, dst: Path, timeout: int = 60) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/octet-stream"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        dst.parent.mkdir(parents=True, exist_ok=True)
        with dst.open("wb") as f:
            shutil.copyfileobj(resp, f)


def _copy_py_files_from_tree(src_root: Path, dst_root: Path) -> int:
    """Copy all *.py files found under src_root into dst_root, preserving paths."""
    copied = 0
    for p in src_root.rglob("*.py"):
        if not p.is_file():
            continue
        rel = p.relative_to(src_root)
        out = dst_root / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, out)
        copied += 1
    return copied


# ---- Commands ----

def cmd_check() -> Dict[str, Any]:
    apmode = APMODE_FLAG.exists()

    if not _repo_exists():
        _log("check: GitHub releases page not reachable / 404")
        return {"ok": False, "error": "GitHub repo/releases not reachable (404 or network error)", "apmode": apmode}

    installed = _read_installed_version()

    tag, _tarball_url, html_url = _github_latest_release()
    if not tag:
        update_available = installed == "missing"
        _log(f"check: repo ok but no latest release tag; installed={installed}; update_available={update_available}")
        return {
            "ok": True,
            "installed": installed if installed != "missing" else "unknown",
            "candidate": "unknown",
            "update_available": update_available,
            "apmode": apmode,
            "source": "github",
        }

    candidate = tag.lstrip("v")

    if installed == "missing":
        update_available = True
        installed_out = "unknown"
    else:
        installed_out = installed
        update_available = _version_key(candidate) > _version_key(installed)

    _log(
        f"check: installed={installed_out} candidate={candidate} update_available={update_available} url={html_url or RELEASES_HTML}"
    )

    return {
        "ok": True,
        "installed": installed_out,
        "candidate": candidate,
        "update_available": update_available,
        "apmode": apmode,
        "source": "github",
    }


def cmd_apply() -> Dict[str, Any]:
    if APMODE_FLAG.exists():
        _log("apply: refused in AP mode")
        return {"ok": False, "error": "Refusing to update while in AP mode (/tmp/apmode present)."}

    if not _repo_exists():
        _log("apply: GitHub releases page not reachable / 404")
        return {"ok": False, "error": "GitHub repo/releases not reachable (404 or network error)"}

    tag, tarball_url, _html_url = _github_latest_release()
    if not tag or not tarball_url:
        _log("apply: no latest release or tarball_url")
        return {"ok": False, "error": "No latest GitHub release (or missing tarball URL)"}

    candidate = tag.lstrip("v")
    installed = _read_installed_version()

    _log(f"apply: candidate={candidate} installed={installed} tarball={tarball_url}")

    # Stop service before replacing python code.
    _log("apply: stopping autostream.service")
    _run(["/bin/systemctl", "stop", "autostream.service"], timeout=30)

    try:
        with tempfile.TemporaryDirectory(prefix="autostream_upd_") as td:
            td_path = Path(td)
            tar_path = td_path / "release.tgz"

            _log("apply: downloading release tarball")
            _download_file(tarball_url, tar_path, timeout=120)

            extract_dir = td_path / "extract"
            extract_dir.mkdir(parents=True, exist_ok=True)

            _log("apply: extracting tarball")
            with tarfile.open(tar_path, "r:gz") as tf:
                tf.extractall(extract_dir)

            # GitHub tarballs have a single top-level directory.
            top_dirs = [p for p in extract_dir.iterdir() if p.is_dir()]
            repo_root = top_dirs[0] if len(top_dirs) == 1 else extract_dir

            # Copy only *.py files from the extracted repo into /opt/autostream.
            _log("apply: copying .py files into /opt/autostream")
            copied = _copy_py_files_from_tree(repo_root, INSTALL_DIR)
            if copied <= 0:
                raise RuntimeError("No .py files found in release tarball")

            RELEASE_FILE.write_text(candidate + "\n", encoding="utf-8")
            _log(f"apply: wrote {RELEASE_FILE} = {candidate} (copied {copied} files)")

    except Exception as e:
        _log(f"apply: failed: {e}")
        _run(["/bin/systemctl", "start", "autostream.service"], timeout=30)
        return {"ok": False, "error": "Update failed", "details": str(e)}

    _log("apply: restarting autostream.service")
    _run(["/bin/systemctl", "restart", "autostream.service"], timeout=30)

    return {"ok": True, "installed": candidate}


# ---- Entrypoint ----

def main() -> int:
    if os.geteuid() != 0:
        print(json.dumps({"ok": False, "error": "Must be run as root"}))
        return 2

    if len(sys.argv) < 2:
        print(json.dumps({"ok": False, "error": "Usage: autostream-updater [check|apply]"}))
        return 1

    cmd = sys.argv[1].strip().lower()
    if cmd == "check":
        result = cmd_check()
        print(json.dumps(result))
        return 0 if result.get("ok") else 1

    if cmd in ("apply", "install", "update"):
        result = cmd_apply()
        print(json.dumps(result))
        return 0 if result.get("ok") else 1

    print(json.dumps({"ok": False, "error": f"Unknown command: {cmd}"}))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
