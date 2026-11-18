"""Tests for dial_pin_guard.py: the per-IP PIN failure count shared by both dial servers.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import dial_pin_guard as pg

IP = "10.0.0.7"


def test_an_unknown_address_is_not_blocked():
    assert pg.blocked(IP) == (False, 0)


def test_failures_below_the_limit_do_not_block():
    for _ in range(pg.MAX_ATTEMPTS - 1):
        pg.record_failure(IP)
    assert pg.blocked(IP) == (False, 0)


def test_the_limit_blocks_with_the_base_back_off():
    for _ in range(pg.MAX_ATTEMPTS):
        pg.record_failure(IP)
    is_blocked, wait = pg.blocked(IP)
    assert is_blocked is True
    assert 1 <= wait <= pg.BACKOFF_BASE_S + 1


def test_the_back_off_doubles_and_is_capped():
    with patch("dial_pin_guard.time.time", return_value=1000.0):
        for _ in range(pg.MAX_ATTEMPTS + 1):
            pg.record_failure(IP)
        assert pg.blocked(IP) == (True, pg.BACKOFF_BASE_S * 2 + 1)
        for _ in range(20):
            pg.record_failure(IP)
        assert pg.blocked(IP) == (True, pg.BACKOFF_MAX_S + 1)


def test_the_block_ends():
    with patch("dial_pin_guard.time.time", return_value=1000.0):
        for _ in range(pg.MAX_ATTEMPTS):
            pg.record_failure(IP)
    with patch("dial_pin_guard.time.time", return_value=1000.0 + pg.BACKOFF_BASE_S + 1):
        assert pg.blocked(IP) == (False, 0)


def test_clear_forgets_the_address():
    for _ in range(pg.MAX_ATTEMPTS):
        pg.record_failure(IP)
    pg.clear(IP)
    assert pg.blocked(IP) == (False, 0)
    assert IP not in pg._attempts


def test_addresses_are_counted_separately():
    for _ in range(pg.MAX_ATTEMPTS):
        pg.record_failure(IP)
    assert pg.blocked("10.0.0.8") == (False, 0)


def test_reset_for_tests_forgets_every_address():
    pg.record_failure(IP)
    pg.record_failure("10.0.0.8")
    pg.reset_for_tests()
    assert pg._attempts == {}
