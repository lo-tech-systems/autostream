"""Tests for dial_http_common.py: the request mechanics both dial servers share.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import sys
from email.message import Message
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import dial_http_common as common


def test_content_length_is_none_when_absent():
    assert common.content_length({}) is None


def test_content_length_reads_a_plain_dict_and_a_message():
    assert common.content_length({"Content-Length": "12"}) == 12
    assert common.content_length({"Content-Length": 7}) == 7
    msg = Message()
    msg["Content-Length"] = "30"
    assert common.content_length(msg) == 30


def test_content_length_returns_a_negative_value_as_it_is():
    assert common.content_length({"Content-Length": "-1"}) == -1


@pytest.mark.parametrize("value", ["x", "1.5", ""])
def test_content_length_raises_on_a_malformed_value(value):
    with pytest.raises(ValueError):
        common.content_length({"Content-Length": value})


def test_json_bytes_default_and_compact():
    obj = {"a": 1, "b": [1, 2]}
    assert common.json_bytes(obj) == b'{"a": 1, "b": [1, 2]}'
    assert common.json_bytes(obj, compact=True) == b'{"a":1,"b":[1,2]}'


def test_json_bytes_escapes_non_ascii_text():
    out = common.json_bytes({"n": chr(233)}, compact=True)
    assert out == b'{"n":"' + bytes([92]) + b'u00e9"}'


def test_the_too_many_attempts_body_and_cap():
    assert common.TOO_MANY_ATTEMPTS == {"ok": False, "error": "too_many_attempts"}
    assert common.MAX_BODY == 4096
