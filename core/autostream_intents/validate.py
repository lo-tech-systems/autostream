"""autostream_intents.validate -- argument validators for the intent table.

A validator takes the raw value and returns the normalised value, or raises
Invalid carrying the error name the route already answers with.
"""
from __future__ import annotations

import math
import re
from typing import Any, Callable, Optional

Validator = Callable[[object], Any]


class Invalid(ValueError):
    """An argument failed its validator; *error* is the name a route replies with."""

    def __init__(self, error: str) -> None:
        super().__init__(error)
        self.error = error


def boolean(*, error: str) -> Validator:
    """True or False only: not 0, 1 or any other truthy value."""

    def check(value: object) -> bool:
        if not isinstance(value, bool):
            raise Invalid(error)
        return value

    return check


def integer(low: int, high: int, *, error: str, clamp: bool = False) -> Validator:
    """An int (not a bool) in [low, high]; with clamp, out of range is moved to the end."""

    def check(value: object) -> int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise Invalid(error)
        if value < low or value > high:
            if not clamp:
                raise Invalid(error)
            return max(low, min(high, value))
        return value

    return check


def number(low: float, high: float, *, error: str, clamp: bool = False) -> Validator:
    """A finite int or float (not a bool) in [low, high]."""

    def check(value: object) -> float:
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise Invalid(error)
        if isinstance(value, float) and not math.isfinite(value):
            raise Invalid(error)
        if value < low or value > high:
            if not clamp:
                raise Invalid(error)
            return max(low, min(high, value))
        return value

    return check


def text(
    *,
    error: str,
    max_len: int = 256,
    allow_empty: bool = False,
    pattern: Optional["re.Pattern[str]"] = None,
) -> Validator:
    """A str, returned stripped. The pattern is matched against the value as
    given, before stripping, so padding that a pattern refuses stays refused."""

    def check(value: object) -> str:
        if not isinstance(value, str):
            raise Invalid(error)
        if pattern is not None and not pattern.match(value):
            raise Invalid(error)
        stripped = value.strip()
        if len(stripped) > max_len or (not stripped and not allow_empty):
            raise Invalid(error)
        return stripped

    return check


def texts(*, min_items: int, max_items: int, max_len: int, error: str) -> Validator:
    """A list or tuple of non-blank strings of at most *max_len* characters,
    between *min_items* and *max_items* long, returned as a tuple with each
    string as given."""

    def check(value: object) -> tuple:
        if not isinstance(value, (list, tuple)) or not (min_items <= len(value) <= max_items):
            raise Invalid(error)
        for item in value:
            if not isinstance(item, str) or not item.strip() or len(item) > max_len:
                raise Invalid(error)
        return tuple(value)

    return check


def choice(*values: object, error: str) -> Validator:
    """One of the listed values, compared by equality."""

    def check(value: object) -> object:
        for allowed in values:
            if type(value) is type(allowed) and value == allowed:
                return value
        raise Invalid(error)

    return check


def optional(validator: Validator) -> Validator:
    """None passes as None; anything else goes through *validator*."""

    def check(value: object) -> Any:
        return None if value is None else validator(value)

    return check


def pairs(*, error: str, max_items: int = 64) -> Validator:
    """A sequence of (str, value) pairs, returned as a tuple of tuples."""

    def check(value: object) -> tuple:
        if not isinstance(value, (list, tuple)) or len(value) > max_items:
            raise Invalid(error)
        out = []
        for item in value:
            if not isinstance(item, (list, tuple)) or len(item) != 2 or not isinstance(item[0], str):
                raise Invalid(error)
            out.append((item[0], item[1]))
        return tuple(out)

    return check


def anything() -> Validator:
    """Pass the value on; the handler validates it with its own rules."""

    def check(value: object) -> object:
        return value

    return check
