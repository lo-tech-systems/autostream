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


# ---- the compare ---------------------------------------------------------------


def test_pin_matches_the_right_pin_only():
    assert pg.pin_matches("1234", "1234") is True
    assert pg.pin_matches("1235", "1234") is False
    assert pg.pin_matches("", "1234") is False
    assert pg.pin_matches("12345", "1234") is False


def test_pin_matches_compares_in_constant_time():
    with patch("dial_pin_guard.hmac.compare_digest", return_value=True) as compare:
        assert pg.pin_matches("1234", "1234") is True
    compare.assert_called_once_with(b"1234", b"1234")


def test_pin_matches_refuses_a_non_string_on_either_side():
    assert pg.pin_matches(1234, "1234") is False
    assert pg.pin_matches(None, "1234") is False
    assert pg.pin_matches(["1234"], "1234") is False
    assert pg.pin_matches("1234", 1234) is False
    assert pg.pin_matches("1234", None) is False


def test_pin_matches_refuses_an_over_long_guess_without_comparing():
    with patch("dial_pin_guard.hmac.compare_digest") as compare:
        assert pg.pin_matches("1" * (pg.PIN_MAX_LENGTH + 1), "1" * (pg.PIN_MAX_LENGTH + 1)) is False
    compare.assert_not_called()
    assert pg.pin_matches("1" * pg.PIN_MAX_LENGTH, "1" * pg.PIN_MAX_LENGTH) is True


def test_pin_matches_handles_non_ascii_text():
    assert pg.pin_matches(chr(233) * 4, chr(233) * 4) is True
    assert pg.pin_matches(chr(233) * 4, "1234") is False


# ---- authorise -----------------------------------------------------------------


def test_authorise_a_right_pin_clears_the_failures():
    pg.record_failure(IP)
    assert pg.authorise(IP, "1234", "1234") == pg.Verdict(True, 0)
    assert IP not in pg._attempts


def test_authorise_a_wrong_pin_is_counted_and_refused_without_a_wait():
    assert pg.authorise(IP, "0000", "1234") == pg.Verdict(False, 0)
    assert pg._attempts[IP][0] == 1


def test_authorise_the_failure_that_reaches_the_limit_asks_for_a_wait():
    for _ in range(pg.MAX_ATTEMPTS - 1):
        assert pg.authorise(IP, "0000", "1234") == pg.Verdict(False, 0)
    verdict = pg.authorise(IP, "0000", "1234")
    assert verdict.ok is False
    assert 1 <= verdict.wait_s <= pg.BACKOFF_BASE_S + 1


def test_authorise_refuses_a_backed_off_client_even_with_the_right_pin():
    for _ in range(pg.MAX_ATTEMPTS):
        pg.record_failure(IP)
    verdict = pg.authorise(IP, "1234", "1234")
    assert verdict.ok is False
    assert verdict.wait_s > 0
    assert pg._attempts[IP][0] == pg.MAX_ATTEMPTS


def test_authorise_a_non_string_stored_pin_refuses_instead_of_raising():
    assert pg.authorise(IP, "1234", 1234) == pg.Verdict(False, 0)
