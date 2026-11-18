"""tests/test_markup_latin1.py

Long text constants in the application's modules stay in one byte per
character.

CPython stores a str in one byte per character when every character is at or
below U+00FF, and in two bytes per character as soon as one is above it.  The
page modules hold constants of tens of kilobytes, so one typographic dash in a
large constant doubles its resident size for the life of the process.  This
test fails on any string constant (or the literal text of an f-string) of 120
characters or more that holds a character above U+00FF.  Write the character
as an HTML entity in markup, as a JavaScript escape in script text, or as
ASCII in a comment; text delivered as JSON or plain text is split so the
non-Latin-1 piece is its own short constant.
"""
from __future__ import annotations

import ast
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parent.parent / "core"
LIMIT = 120


def _first_wide(text: str) -> str | None:
    for ch in text:
        if ord(ch) > 0xFF:
            return ch
    return None


def find_wide_constants(source: str) -> list[tuple[int, str]]:
    """Return (line, character) for each long str constant or f-string whose
    literal text holds a character above U+00FF."""
    tree = ast.parse(source)
    found: list[tuple[int, str]] = []
    in_fstring: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            literal = "".join(
                part.value for part in node.values
                if isinstance(part, ast.Constant) and isinstance(part.value, str)
            )
            for part in node.values:
                in_fstring.add(id(part))
            if len(literal) >= LIMIT:
                ch = _first_wide(literal)
                if ch is not None:
                    found.append((node.lineno, ch))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in in_fstring
            and len(node.value) >= LIMIT
        ):
            ch = _first_wide(node.value)
            if ch is not None:
                found.append((node.lineno, ch))
    return sorted(found)


def test_no_long_constant_holds_a_wide_character():
    problems = []
    for path in sorted(CORE_DIR.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        for line, ch in find_wide_constants(source):
            rel = path.relative_to(CORE_DIR).as_posix()
            problems.append(f"{rel}:{line}: U+{ord(ch):04X} {ch!r}")
    assert not problems, (
        "long text constants must stay Latin-1 (use an entity, a JS escape or "
        "ASCII):\n" + "\n".join(problems)
    )


def test_guard_catches_a_long_constant():
    wide = "x" * LIMIT + "—"
    assert find_wide_constants(f"A = {wide!r}\n") == [(1, "—")]


def test_guard_catches_an_fstring_literal_part():
    wide = "x" * LIMIT + "…"
    src = f"A = f{wide!r} + f'{{v}}'\nv = 1\n"
    assert find_wide_constants(src) == [(1, "…")]


def test_guard_ignores_short_and_latin1_constants():
    assert find_wide_constants("A = '—'\nB = '" + "é" * 300 + "'\n") == []
