"""webui/static.py -- URLs and text of the files nginx serves under /static/.

A URL carries ?v= and the first ten hex digits of the file's SHA-256, read once
per file and kept for the life of the process, so a changed file gets a new URL
and nginx's one-hour cache never serves an old copy after an update.
"""
from __future__ import annotations

import hashlib
import html
import json
import logging
import threading
from pathlib import Path, PurePosixPath
from typing import Mapping

from webui.system import updates

STATIC_PREFIX = "/static/"
_VERSION_LEN = 10

_log = logging.getLogger(__name__)

# Leaf lock: held only around the two dicts, never across a read or a call out.
_lock = threading.Lock()
_versions: dict[str, str] = {}
_warned: set[str] = set()


def static_root() -> Path:
    """The served directory: <install directory>/nginx/static when it exists
    (the installed tree, /opt/autostream/nginx/static), else <repo>/nginx/static
    (the source tree, for tests and tools). The install directory is the one that
    holds the webui package, and in the source tree that is core/."""
    here = Path(__file__).resolve().parent.parent
    installed = here / "nginx" / "static"
    if installed.is_dir():
        return installed
    return here.parent / "nginx" / "static"


def _checked(rel: str) -> str:
    path = PurePosixPath(rel)
    if not rel or path.is_absolute() or "\\" in rel or ".." in path.parts:
        raise ValueError(f"static path must be relative and inside the static root: {rel!r}")
    return rel


def _warn_once(rel: str, why: str) -> None:
    with _lock:
        first = rel not in _warned
        _warned.add(rel)
    if first:
        _log.warning("static file %s unavailable (%s)", rel, why)


def asset_version(rel: str) -> str:
    """The content hash of static_root()/rel (cached under a leaf lock).
    A missing or unreadable file gives the application version and one WARNING
    per file: the page still renders, but the script does not load."""
    _checked(rel)
    with _lock:
        cached = _versions.get(rel)
    if cached is not None:
        return cached
    try:
        digest = hashlib.sha256((static_root() / rel).read_bytes()).hexdigest()[:_VERSION_LEN]
    except OSError as exc:
        _warn_once(rel, str(exc))
        digest = updates.get_app_version()
    with _lock:
        return _versions.setdefault(rel, digest)


def static_url(rel: str) -> str:
    """'/static/page/home.js?v=0123abcd45'"""
    return f"{STATIC_PREFIX}{_checked(rel)}?v={asset_version(rel)}"


def script_tag(rel: str) -> str:
    """'<script src="/static/page/home.js?v=..."></script>'"""
    return f'<script src="{html.escape(static_url(rel))}"></script>'


def module_tag(rel: str) -> str:
    """'<script type="module" src="/static/page/home/home_main.js?v=..."></script>'.
    The ?v= is on the entry module only; the modules it imports are reached
    by relative URLs, which carry no query."""
    return f'<script type="module" src="{html.escape(static_url(rel))}"></script>'


def style_tag(rel: str) -> str:
    """'<link rel="stylesheet" href="/static/theme.css?v=...">'"""
    return f'<link rel="stylesheet" href="{html.escape(static_url(rel))}">'


def page_data_island(data: Mapping) -> str:
    """'<script type="application/json" id="page-data">' + JSON + '</script>'.
    JSON with sort_keys=False, separators=(",", ":"), ensure_ascii=True, then
    "<" -> "\\u003c", ">" -> "\\u003e", "&" -> "\\u0026", so no value can end
    the element. Empty data gives no element."""
    if not data:
        return ""
    text = json.dumps(dict(data), sort_keys=False, separators=(",", ":"), ensure_ascii=True)
    text = text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return f'<script type="application/json" id="page-data">{text}</script>'


def reset_for_tests() -> None:
    """Clear the version cache and the warned set. Called by the tests that need
    it, never from an autouse fixture."""
    with _lock:
        _versions.clear()
        _warned.clear()
