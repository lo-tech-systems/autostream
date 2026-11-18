"""Tests for dial_values.py: the dial's small shared value helpers.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import dial_values as v


@pytest.mark.parametrize("value, expected", [
    (0, True), (5, True), (-3, True), (True, False), (False, False),
    (1.0, False), ("1", False), (None, False), ([], False),
])
def test_is_int(value, expected):
    assert v.is_int(value) is expected


@pytest.mark.parametrize("value, expected", [
    (0, True), (7, True), (3.0, True), (3.5, False), (True, False),
    (float("nan"), False), (float("inf"), False), ("3", False), (None, False),
])
def test_is_whole_number(value, expected):
    assert v.is_whole_number(value) is expected


def test_int_or_none():
    assert v.int_or_none(4) == 4
    assert v.int_or_none(0) == 0
    assert v.int_or_none(True) is None
    assert v.int_or_none(4.0) is None
    assert v.int_or_none(None) is None


@pytest.mark.parametrize("text, default, expected", [
    ("12", 0, 12), (" 12 ", 0, 12), ("-4", 0, -4), (7, 0, 7),
    ("x", 0, 0), ("", 9, 9), (None, 5, 5), ("1.5", 3, 3), ([], 2, 2),
])
def test_parse_int(text, default, expected):
    assert v.parse_int(text, default) == expected


def test_clamp_holds_to_the_range():
    assert v.clamp(5, 0, 10) == 5
    assert v.clamp(-1, 0, 10) == 0
    assert v.clamp(11, 0, 10) == 10
    assert v.clamp(0.5, 0, 10) == 0.5


def test_clamp_percent():
    assert v.clamp_percent(-5) == 0
    assert v.clamp_percent(50) == 50
    assert v.clamp_percent(101) == 100


def test_read_text_or_strips_and_defaults(tmp_path):
    p = tmp_path / "f"
    p.write_text("  hello\n", encoding="utf-8")
    assert v.read_text_or(p) == "hello"
    assert v.read_text_or(tmp_path / "absent") == ""
    assert v.read_text_or(tmp_path / "absent", "x") == "x"


def test_read_text_or_lets_a_decode_error_through(tmp_path):
    p = tmp_path / "f"
    p.write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(UnicodeDecodeError):
        v.read_text_or(p)


def test_parse_env_text_rules():
    text = "\n".join([
        "# comment", "", "A=1", " B = two ", 'C="quoted"', "D='single'", 'E="unbalanced',
        "no equals", "F=a=b", "G=", 'H=""',
    ])
    assert v.parse_env_text(text) == {
        "A": "1", "B": "two", "C": "quoted", "D": "single", "E": '"unbalanced',
        "F": "a=b", "G": "", "H": "",
    }


def test_read_env_file(tmp_path):
    p = tmp_path / "x.env"
    p.write_text("A=1\n", encoding="utf-8")
    assert v.read_env_file(p) == {"A": "1"}
    assert v.read_env_file(str(p)) == {"A": "1"}
    assert v.read_env_file(tmp_path / "absent") == {}


def test_read_env_file_lets_a_decode_error_through(tmp_path):
    p = tmp_path / "x.env"
    p.write_bytes(b"\xff\xfe")
    with pytest.raises(UnicodeDecodeError):
        v.read_env_file(p)


def test_parse_json_object():
    assert v.parse_json_object(b'{"a": 1}') == {"a": 1}
    assert v.parse_json_object('{"a": 1}') == {"a": 1}
    assert v.parse_json_object("{}") == {}


@pytest.mark.parametrize("raw", [b"{", "nope", b"", None, b"\xff"])
def test_parse_json_object_rejects_bad_json(raw):
    with pytest.raises(v.NotJson):
        v.parse_json_object(raw)


@pytest.mark.parametrize("raw", ["[]", "1", "null", '"s"', "true"])
def test_parse_json_object_rejects_a_non_object(raw):
    with pytest.raises(v.NotAnObject):
        v.parse_json_object(raw)


def test_the_two_errors_are_value_errors():
    assert issubclass(v.NotJson, ValueError)
    assert issubclass(v.NotAnObject, ValueError)
