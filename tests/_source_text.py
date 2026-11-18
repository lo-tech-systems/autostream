"""tests/_source_text.py

One reader for the source text of the application's Python modules.

Several tests inspect module source (protocol strings, embedded page scripts,
call-site shapes).  Reading through this module means a test names the module
it cares about, not the file it happens to live in today, so moving code
between modules does not leave a test reading the wrong file.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parent.parent / "core"


def core_sources() -> dict[str, str]:
    """Return every core Python file as {path relative to core/: text}, sorted."""
    out: dict[str, str] = {}
    for path in sorted(CORE_DIR.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        out[path.relative_to(CORE_DIR).as_posix()] = path.read_text(encoding="utf-8")
    return out


def core_text() -> str:
    """Return the concatenated text of every core Python file."""
    return "\n".join(core_sources().values())


def module_path(name: str) -> Path:
    """Return the file of the module with the given import name."""
    flat = CORE_DIR / f"{name}.py"
    if flat.is_file():
        return flat
    parts = name.split(".")
    nested = CORE_DIR.joinpath(*parts[:-1], f"{parts[-1]}.py")
    if nested.is_file():
        return nested
    package = CORE_DIR.joinpath(*parts, "__init__.py")
    if package.is_file():
        return package
    raise KeyError(f"no core module named {name!r}")


def module_text(name: str) -> str:
    """Return the source text of the module with the given import name. A
    package directory without a module of its own name (for example
    "webui.browser.setup") gives every file of it, sorted, joined."""
    parts = name.split(".")
    package_dir = CORE_DIR.joinpath(*parts)
    flat = CORE_DIR / f"{name}.py"
    nested = CORE_DIR.joinpath(*parts[:-1], f"{parts[-1]}.py")
    if package_dir.is_dir() and not flat.is_file() and not nested.is_file():
        files = sorted(p for p in package_dir.rglob("*.py") if "__pycache__" not in p.parts)
        if not files:
            raise KeyError(f"no core module named {name!r}")
        return "\n".join(p.read_text(encoding="utf-8") for p in files)
    return module_path(name).read_text(encoding="utf-8")


_WEB_FLAT_MODULES = ("autostream_webui*.py", "autostream_appliance_gateway.py")


def web_source() -> str:
    """Return the text of every file of the web modules, whether they are flat
    modules in core/ or files of the webui package, sorted by path."""
    files: set[Path] = set()
    for pattern in _WEB_FLAT_MODULES:
        files.update(CORE_DIR.glob(pattern))
    package = CORE_DIR / "webui"
    if package.is_dir():
        files.update(p for p in package.rglob("*.py") if "__pycache__" not in p.parts)
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(files))


STATIC_DIR = Path(__file__).resolve().parent.parent / "nginx" / "static"

_SCRIPT_ELEMENT = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.DOTALL | re.IGNORECASE)
_STATIC_LINK = re.compile(
    r"""<script\b[^>]*\bsrc=["'](?P<script>/static/[^"'?#]+)[^"']*["'][^>]*>"""
    r"""|<link\b[^>]*\bhref=["'](?P<style>/static/[^"'?#]+)[^"']*["'][^>]*>""",
    re.IGNORECASE,
)
_ISLAND = re.compile(
    r"""<script\b[^>]*\btype=["']application/json["'][^>]*\bid=["']page-data["'][^>]*>(.*?)</script>""",
    re.DOTALL | re.IGNORECASE,
)


def static_text(rel: str) -> str:
    """Return the text of a file under nginx/static (for example "page/home.js")."""
    return (STATIC_DIR / rel).read_text(encoding="utf-8")


def linked_static(html: str) -> list[str]:
    """Return the path under nginx/static of every /static/ script and stylesheet
    the page links, in document order, with the query stripped."""
    out = []
    for m in _STATIC_LINK.finditer(html):
        out.append((m.group("script") or m.group("style"))[len("/static/"):])
    return out


def page_scripts(html: str) -> str:
    """Return the page's script text in document order: each inline script body
    and, where a /static/ script is linked, that file's text. The data island is
    not script text (see page_data)."""
    parts = []
    for m in _SCRIPT_ELEMENT.finditer(html):
        attrs, body = m.group(1), m.group(2)
        src = re.search(r"""\bsrc=["'](/static/[^"'?#]+)""", attrs, re.IGNORECASE)
        if src:
            parts.append(static_text(src.group(1)[len("/static/"):]))
        elif not re.search(r"""\btype=["']application/json["']""", attrs, re.IGNORECASE):
            parts.append(body)
    return "\n".join(parts)


def page_data(html: str) -> dict:
    """Return the parsed data island of the page, or {} when it has none."""
    m = _ISLAND.search(html)
    return json.loads(m.group(1)) if m else {}


# For each page: the module names and the glob patterns under nginx/static that
# together hold its markup, scripts and styles.
PAGE_SOURCES = {
    "setup": (("webui.browser.setup",), ("page/setup_*.js", "page/setup.css")),
}


def page_source(page: str) -> str:
    """Return the source text behind one page: its modules' text, then the text
    of its static files (sorted by name). An assert that looks for a piece of
    page text then holds whether it lives in the Python or in a static file."""
    modules, patterns = PAGE_SOURCES[page]
    parts = [module_text(m) for m in modules]
    for pattern in patterns:
        parts.extend(p.read_text(encoding="utf-8") for p in sorted(STATIC_DIR.glob(pattern)))
    return "\n".join(parts)


def page_with_static(html: str) -> str:
    """Return the page markup followed by the text of every /static/ script and
    page stylesheet it links, in document order (the shared theme excepted). For
    asserts that look for a piece of page text without caring whether it is
    inline or in a linked file."""
    parts = [html]
    for rel in linked_static(html):
        if rel != "theme.css":
            parts.append(static_text(rel))
    return "\n".join(parts)
