"""dial_hd_static.py: the HD page's files and pictures.

Every name served comes from the fixed STATIC_FILES table, plus four fixed
names (index.html, login.html, theme.css, logo.png). A request path is never
mapped to the file system: the table is looked up, and only then is a file
path made from the root and the table's name.

The theme, the shared browser modules and the logo have repository fallbacks
for a checkout that is not installed. Files answer a conditional GET with an
ETag made from the modification time and size; the held artwork is keyed by
its own key. The artwork route serves the picture as it came, or a blurred
backdrop made from it.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import re
from pathlib import Path

# The artwork route: the key, then optionally the variant served for it.
ARTWORK_REST_RE = re.compile(r"^([0-9a-f]{16})(?:/(backdrop))?$")
ARTWORK_CACHE_CONTROL = "private, max-age=86400, immutable"

HD_STATIC_ROOT = Path(__file__).resolve().parent / "hd"
_REPO_ROOT = Path(__file__).resolve().parent.parent
THEME_FALLBACK_PATH = _REPO_ROOT / "nginx" / "static" / "theme.css"
SHARED_FALLBACK_DIR = _REPO_ROOT / "nginx" / "static" / "shared"
LOGO_PATH = Path("/opt/autostream/images/autostream-logo-centred-dark.png")
LOGO_FALLBACK_PATH = _REPO_ROOT / "images" / "autostream-logo-centred-dark.png"

_HTML = "text/html; charset=utf-8"
_CSS = "text/css; charset=utf-8"
_JS = "text/javascript; charset=utf-8"
_PNG = "image/png"

# The static files, by the name served at /static/<name>: the files are
# resolved from this fixed table, never from the request path.
STATIC_FILES = {
    "hd.css": _CSS,
    "hd.js": _JS,
    "hd-tables.js": _JS,
    "hd-dom.js": _JS,
    "hd-state.js": _JS,
    "hd-eq.js": _JS,
    "hd-derive.js": _JS,
    "hd-requests.js": _JS,
    "hd-actions.js": _JS,
    "hd-paint.js": _JS,
    "hd-bell.js": _JS,
    "login.js": _JS,
    "theme.css": _CSS,
    "logo.png": _PNG,
    "shared/state_stream.js": _JS,
    "shared/state_view.js": _JS,
    "shared/texts.js": _JS,
    "shared/pending.js": _JS,
}

# The first bytes of an image, and its type.
_IMAGE_SIGNATURES = (
    (b"\xff\xd8", "image/jpeg"),
    (b"\x89PNG", "image/png"),
    (b"GIF8", "image/gif"),
)


def sniff_image_type(data: bytes) -> str:
    """The image type *data* starts as, else application/octet-stream."""
    for prefix, content_type in _IMAGE_SIGNATURES:
        if data.startswith(prefix):
            return content_type
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return "application/octet-stream"


# The artwork route's variants: what is served for the held artwork, as
# (body, content type); a None body means that variant cannot be made.
ARTWORK_VARIANTS = {
    "": lambda files, art: (art.data, sniff_image_type(art.data)),
    "backdrop": lambda files, art: (files.backdrops.artwork(art.key, art.data), "image/jpeg"),
}


def static_path(root: Path, name: str) -> Path | None:
    """The file behind a static name under *root*, or None when the table has none."""
    if name in ("index.html", "login.html"):
        return root / name
    if name == "theme.css":
        for candidate in (root / "theme.css", THEME_FALLBACK_PATH):
            if candidate.is_file():
                return candidate
        return None
    if name == "logo.png":
        for candidate in (LOGO_PATH, LOGO_FALLBACK_PATH):
            if candidate.is_file():
                return candidate
        return None
    if name.startswith("shared/") and name in STATIC_FILES:
        # Installed beside the page; in the repository they are the
        # browser's own copies.
        for candidate in (root / name, SHARED_FALLBACK_DIR / name[len("shared/"):]):
            if candidate.is_file():
                return candidate
        return None
    if name in STATIC_FILES:
        return root / name
    return None


def _etag_matches(header: str | None, etag: str) -> bool:
    if not header:
        return False
    if header.strip() == "*":
        return True
    return any(part.strip().removeprefix("W/") == etag for part in header.split(","))


def _file_etag(info) -> str:
    """The validator for a file: its modification time and size."""
    return '"%x-%x"' % (info.st_mtime_ns, info.st_size)


def _not_modified(handler, headers, *, page: bool = False) -> bool:
    """Answer 304 with *headers* when the request already holds the ETag in
    them; True if it did."""
    if not _etag_matches(handler.headers.get("If-None-Match"), headers["ETag"]):
        return False
    handler.send_bytes(304, b"", None, headers, page=page)
    return True


class StaticFiles:
    """The page's file, artwork and logo routes. *root* is the directory the
    page files are served from, *core* supplies snapshot() for the held
    artwork, and *backdrops* is the BackdropStore that makes the blurred
    pictures. Every route handler takes (handler, rest) and reaches the
    request only through handler.headers, send_json and send_bytes."""

    def __init__(self, root: Path, core, backdrops) -> None:
        self._root = Path(root)
        self._core = core
        self._backdrops = backdrops

    @property
    def backdrops(self):
        return self._backdrops

    def index(self, handler, rest) -> None:
        self.send_file(handler, "index.html", _HTML)

    def login_page(self, handler, rest) -> None:
        self.send_file(handler, "login.html", _HTML)

    def static(self, handler, rest) -> None:
        content_type = STATIC_FILES.get(rest)
        if content_type is None:
            handler.send_json(404, {"ok": False, "error": "not_found"})
            return
        self.send_file(handler, rest, content_type)

    def send_file(self, handler, name: str, content_type: str) -> None:
        path = static_path(self._root, name)
        try:
            info = path.stat() if path is not None else None
            if info is None:
                raise FileNotFoundError(name)
            headers = {"ETag": _file_etag(info), "Cache-Control": "no-cache"}
            if _not_modified(handler, headers, page=True):
                return
            data = path.read_bytes()
        except OSError:
            handler.send_json(404, {"ok": False, "error": "not_found"})
            return
        handler.send_bytes(200, data, content_type, headers, page=True)

    def artwork(self, handler, rest) -> None:
        match = ARTWORK_REST_RE.match(rest)
        if match is None:
            handler.send_json(400, {"ok": False, "error": "bad_artwork_key"})
            return
        key, variant = match.group(1), match.group(2) or ""
        artwork = self._core.snapshot().artwork
        if artwork is None or artwork.key != key:
            handler.send_json(404, {"ok": False, "error": "no_artwork"})
            return
        headers = {
            "Cache-Control": ARTWORK_CACHE_CONTROL,
            "ETag": '"%s"' % artwork.key,
        }
        if _not_modified(handler, headers):
            return
        body, content_type = ARTWORK_VARIANTS[variant](self, artwork)
        if body is None:
            handler.send_json(404, {"ok": False, "error": "no_backdrop"})
            return
        handler.send_bytes(200, body, content_type, headers)

    def logo_backdrop(self, handler, rest) -> None:
        path = static_path(self._root, "logo.png")
        try:
            info = path.stat() if path is not None else None
        except OSError:
            info = None
        if info is None:
            handler.send_json(404, {"ok": False, "error": "not_found"})
            return
        headers = {"ETag": _file_etag(info), "Cache-Control": "no-cache"}
        if _not_modified(handler, headers):
            return
        body = self._backdrops.logo()
        if body is None:
            handler.send_json(404, {"ok": False, "error": "no_backdrop"})
            return
        handler.send_bytes(200, body, "image/jpeg", headers)
