"""tests/test_protocol.py

The protocol module: its number and the shape of a client's name.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))

import autostream_protocol as proto

ID = "0123456789abcdef0123"


def test_the_number_is_four():
    assert proto.PROTOCOL == 4


@pytest.mark.parametrize("kind", ["dial", "peer"])
def test_a_client_name_parses_to_its_kind_and_id(kind):
    assert proto.parse_client(f"{kind}:{ID}") == (kind, ID)


@pytest.mark.parametrize("text", [
    "", "dial", "dial:", f"dial:{ID[:-1]}", f"dial:{ID}0", f"dial:{ID.upper()}",
    f"browser:{ID}", f" dial:{ID}", f"dial:{ID}\n", f"dial:{ID[:-1]}g", f"dial: {ID}",
])
def test_a_malformed_client_name_is_none(text):
    assert proto.parse_client(text) is None


def test_a_non_string_is_none():
    assert proto.parse_client(None) is None
    assert proto.parse_client(b"dial:" + ID.encode()) is None


def test_an_appliance_id_is_twenty_lowercase_hex_characters():
    assert proto.APPLIANCE_ID_RE.fullmatch(ID)
    assert not proto.APPLIANCE_ID_RE.fullmatch(ID.upper())
    assert not proto.APPLIANCE_ID_RE.fullmatch(ID + "0")
