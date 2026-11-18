"""dial_values.py: small pure helpers used across the dial.

Integer checks, clamps, small-file and env-file reads, and JSON object
parsing. No dial imports and no logging: every helper returns a value or
raises, and the caller decides what to say.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import json
from pathlib import Path


def is_int(value) -> bool:
    """True for an int that is not a bool."""
    return isinstance(value, int) and not isinstance(value, bool)


def is_whole_number(value) -> bool:
    """True for an int (not a bool) or a float with no fractional part."""
    return is_int(value) or (isinstance(value, float) and value.is_integer())


def int_or_none(value) -> int | None:
    """The value when it is an int (not a bool), else None."""
    return value if is_int(value) else None


def parse_int(text, default: int = 0) -> int:
    """int(str(text).strip()), or default when it will not parse."""
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return default


def clamp(value, low, high):
    """value held to low..high."""
    return max(low, min(high, value))


def clamp_percent(value):
    """value held to 0..100."""
    return clamp(value, 0, 100)


def read_text_or(path, default: str = "") -> str:
    """The stripped UTF-8 text of a small file, or default when it cannot be opened."""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return default


def parse_env_text(text: str) -> dict[str, str]:
    """Parse KEY=VALUE lines without executing them.

    Blank lines, comments and lines with no '=' are skipped. One matching pair
    of surrounding quotes is removed from a value.
    """
    data: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, _, v = line.partition('=')
        k = k.strip()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
            v = v[1:-1]
        data[k] = v
    return data


def read_env_file(path) -> dict[str, str]:
    """parse_env_text of a UTF-8 file; an unreadable file gives {}."""
    try:
        return parse_env_text(Path(path).read_text(encoding='utf-8'))
    except OSError:
        return {}


class NotJson(ValueError):
    """The body is not valid JSON."""


class NotAnObject(ValueError):
    """The body is valid JSON but not an object."""


def parse_json_object(raw: bytes | str) -> dict:
    """The JSON object in raw; NotJson or NotAnObject otherwise."""
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError) as e:
        raise NotJson(str(e)) from e
    if not isinstance(obj, dict):
        raise NotAnObject("body must be a JSON object")
    return obj
