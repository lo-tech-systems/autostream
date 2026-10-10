"""Tests for autostream_pin_pairing: claims, attempt limiter, PIN rule."""
from __future__ import annotations

import logging
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))

import autostream_pin_pairing as pp  # noqa: E402


class _Clock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def _state():
    clock = _Clock()
    return pp.PairingState(clock=clock), clock


def _lock_free(state) -> bool:
    got = state._lock.acquire(blocking=False)
    if got:
        state._lock.release()
    return got


class TestClaims:
    def test_first_claim_holds_against_a_later_requester_until_it_expires(self):
        st, clock = _state()
        assert st.claim("o1", "webui") == "webui"
        clock.t += 10
        assert st.claim("o1", "dial:a") == "webui"
        assert st.holder("o1") == "webui"
        clock.t += pp.PIN_CLAIM_S
        assert st.claim("o1", "dial:a") == "dial:a"
        assert st.holder("o1") == "dial:a"

    def test_the_holder_renews_its_own_claim(self):
        st, clock = _state()
        st.claim("o1", "webui")
        clock.t += 80
        assert st.claim("o1", "webui") == "webui"
        clock.t += 80
        assert st.holder("o1") == "webui"
        clock.t += 11
        assert st.holder("o1") == ""

    def test_release_clears_the_holder(self):
        st, _ = _state()
        st.claim("o1", "webui")
        st.release("o1")
        assert st.holder("o1") == ""
        st.release("never-claimed")

    def test_an_expired_claim_reads_as_none_and_is_dropped(self):
        st, clock = _state()
        st.claim("o1", "webui")
        clock.t += pp.PIN_CLAIM_S
        assert st.holder("o1") == ""
        assert "o1" not in st._claims

    def test_claims_are_bounded_and_the_oldest_is_evicted(self):
        st, clock = _state()
        for i in range(pp.PIN_CLAIMS_MAX + 1):
            st.claim(f"o{i}", "webui")
            clock.t += 0.001
        assert len(st._claims) == pp.PIN_CLAIMS_MAX
        assert st.holder("o0") == ""
        assert st.holder(f"o{pp.PIN_CLAIMS_MAX}") == "webui"

    def test_an_attempt_renews_the_requesters_own_claim_only(self):
        st, clock = _state()
        st.claim("o1", "webui")
        clock.t += 80
        st.note_attempt("dial:a", "o1")
        clock.t += 15
        assert st.holder("o1") == ""
        st.claim("o1", "webui")
        clock.t += 80
        st.note_attempt("webui", "o1")
        clock.t += 15
        assert st.holder("o1") == "webui"


class TestAttempts:
    def test_attempts_are_limited_per_requester_and_output_in_the_window(self):
        st, _ = _state()
        for i in range(pp.PIN_ATTEMPTS_MAX):
            assert st.note_attempt("webui", "o1", now=float(i)) == (True, 0)
        allowed, wait = st.note_attempt("webui", "o1", now=5.0)
        assert allowed is False and wait >= 1

    def test_a_refused_attempt_is_not_counted_and_says_how_long_to_wait(self):
        st, _ = _state()
        for i in range(5):
            assert st.note_attempt("webui", "o1", now=float(i))[0]
        assert st.note_attempt("webui", "o1", now=5.0) == (False, 55)
        assert st.note_attempt("webui", "o1", now=30.0) == (False, 30)
        # the refusals counted nothing: at t=60 the first leaves the window
        assert st.note_attempt("webui", "o1", now=59.9)[0] is False
        assert st.note_attempt("webui", "o1", now=60.0) == (True, 0)
        assert st.note_attempt("webui", "o1", now=60.0)[0] is False

    def test_the_sixth_attempt_after_five_at_zero_to_four_waits_56_seconds(self):
        st, _ = _state()
        for i in range(5):
            st.note_attempt("webui", "o1", now=float(i))
        # oldest is t=0, so the window frees it at t=60: 56 s from t=4
        assert st.note_attempt("webui", "o1", now=4.0) == (False, 56)

    def test_retry_after_is_rounded_up_and_never_zero(self):
        st, _ = _state()
        for _ in range(5):
            st.note_attempt("webui", "o1", now=0.0)
        assert st.note_attempt("webui", "o1", now=59.2) == (False, 1)
        assert st.note_attempt("webui", "o1", now=59.999) == (False, 1)
        assert st.note_attempt("webui", "o1", now=0.5) == (False, 60)

    def test_attempts_for_another_output_or_requester_do_not_count(self):
        st, _ = _state()
        for _ in range(5):
            st.note_attempt("webui", "o1", now=0.0)
        assert st.note_attempt("webui", "o2", now=0.0) == (True, 0)
        assert st.note_attempt("dial:a", "o1", now=0.0) == (True, 0)
        assert st.note_attempt("webui", "o1", now=0.0)[0] is False

    def test_a_key_keeps_at_most_the_last_five_times(self):
        st, _ = _state()
        for i in range(20):
            st.note_attempt("webui", "o1", now=float(i) * 100)
        assert len(st._attempts[("webui", "o1")]) <= pp.PIN_ATTEMPTS_MAX
        for i in range(5):
            st.note_attempt("webui", "o2", now=float(i))
        assert len(st._attempts[("webui", "o2")]) == pp.PIN_ATTEMPTS_MAX

    def test_idle_keys_are_dropped_and_the_table_is_capped(self):
        st, _ = _state()
        for i in range(pp.PIN_KEYS_MAX + 1):
            st.note_attempt(f"dial:{i}", "o1", now=float(i) / 1000)
        assert len(st._attempts) == pp.PIN_KEYS_MAX
        assert ("dial:0", "o1") not in st._attempts
        assert (f"dial:{pp.PIN_KEYS_MAX}", "o1") in st._attempts
        # an idle key restarts empty when it is next looked at
        st.note_attempt("dial:1", "o1", now=500.0)
        assert len(st._attempts[("dial:1", "o1")]) == 1


class TestRobustness:
    def test_the_lock_is_not_held_when_a_call_returns(self):
        st, _ = _state()
        st.claim("o1", "webui")
        assert _lock_free(st)
        st.holder("o1")
        assert _lock_free(st)
        st.note_attempt("webui", "o1")
        assert _lock_free(st)
        for _ in range(6):
            st.note_attempt("webui", "o1")
        assert _lock_free(st)
        st.release("o1")
        assert _lock_free(st)

    def test_a_raising_clock_fails_open(self, caplog):
        def raiser():
            raise RuntimeError("clock broke")

        st = pp.PairingState(clock=raiser)
        with caplog.at_level(logging.DEBUG):
            assert st.note_attempt("webui", "o1") == (True, 0)
            assert st.note_attempt("webui", "o1") == (True, 0)
            assert st.holder("o1") == ""
            assert st.claim("o1", "webui") == "webui"
        records = [r for r in caplog.records if "pin pairing" in r.getMessage()]
        assert len(records) == 1
        assert records[0].levelno == logging.DEBUG
        assert _lock_free(st)

    def test_corrupt_state_fails_open(self):
        st, _ = _state()
        st._attempts[("webui", "o1")] = "not a deque"
        assert st.note_attempt("webui", "o1", now=1.0) == (True, 0)
        assert _lock_free(st)

    def test_the_module_never_sleeps(self):
        src = Path(pp.__file__).read_text(encoding="utf-8")
        assert "time.sleep" not in src
        assert ".wait(" not in src

    def test_a_thousand_calls_complete_without_waiting(self):
        st = pp.PairingState()
        start = time.monotonic()
        for i in range(1000):
            st.note_attempt("webui", f"o{i % 10}")
            st.claim(f"o{i % 10}", "webui")
            st.holder(f"o{i % 10}")
        assert time.monotonic() - start < 2.0

    def test_concurrent_callers_all_complete(self):
        st = pp.PairingState()
        errors = []

        def work(n):
            try:
                for i in range(200):
                    st.note_attempt(f"dial:{n}", f"o{i % 3}")
                    st.claim(f"o{i % 3}", f"dial:{n}")
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert not errors
        assert not any(t.is_alive() for t in threads)


class TestRules:
    def test_dial_requester_prefix(self):
        assert pp.dial_requester("abc") == "dial:abc"
        assert pp.REQUESTER_WEBUI == "webui"

    def test_pin_re_accepts_four_to_eight_digits_only(self):
        for good in ("1234", "0000", "12345678", "00000"):
            assert pp.PIN_RE.match(good), good
        for bad in (
            "123", "123456789", "12a4", "１２３４", " 1234",
            "1234\n", "", "1234 ", "-1234", "12.34",
        ):
            assert not pp.PIN_RE.match(bad), repr(bad)

    def test_module_level_helpers_use_the_shared_state(self):
        pp.STATE.reset()
        assert pp.claim("o1", "webui") == "webui"
        assert pp.holder("o1") == "webui"
        pp.release("o1")
        assert pp.holder("o1") == ""
        assert pp.note_attempt("webui", "o1") == (True, 0)
        pp.STATE.reset()
