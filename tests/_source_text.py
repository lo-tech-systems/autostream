"""tests/_source_text.py

One reader for the source text of the application's Python modules.

Several tests inspect module source (protocol strings, embedded page scripts,
call-site shapes).  Reading through this module means a test names the module
it cares about, not the file it happens to live in today, so moving code
between modules does not leave a test reading the wrong file.
"""
from __future__ import annotations

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
    """Return the source text of the module with the given import name."""
    return module_path(name).read_text(encoding="utf-8")
