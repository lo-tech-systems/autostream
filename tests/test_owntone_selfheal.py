"""tests/test_owntone_selfheal.py

Self-healing tests for two OwnTone failure modes.

  1. Output re-arm after the player restarts: a still-active session that
     finds the output authority reporting a different player boot than the
     one the selection was applied under re-arms the output retry machinery
     (see tests/test_selfheal.py for the rule itself); here, the user's
     choice of silence and a speaker waiting for a PIN are checked against
     the default-output handler.

  2. OwnTone-hang watchdog (_OwntoneHangWatchdog /
     _maybe_run_owntone_hang_watchdog): a stalled FIFO write
     (status["fifo"]["stalled_seconds"]) during an active session, with
     OwnTone still reachable, requests a rate-limited supervised restart via
     run_admin_cmd(["restart-owntone"]); an absent "fifo" block (old daemon
     binary) disarms it silently.

  3. Composition: stall -> watchdog fires once (rate-limited thereafter) ->
     OwnTone comes back as a different boot -> the output retry is re-armed.

The C++ daemon side (the "fifo" status block) is mocked throughout -- these
tests exercise the Python contract against synthetic status/outputs
sequences, not a real daemon or OwnTone backend.
"""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from fake_store import FakeStore, fake_levels
import autostream_core as core
from autostream_audio_monitor import AudioMonitor
from autostream_selfheal import maybe_run_owntone_hang_watchdog as _maybe_run_owntone_hang_watchdog
from autostream_selfheal import carry_forward_hang_watchdog as _carry_forward_hang_watchdog
from autostream_selfheal import OwntoneHangWatchdog as _OwntoneHangWatchdog
from autostream_selfheal import SelfHeal as _SelfHeal
import autostream_output_intents as output_intents
import autostream_player_service as player_service
import autostream_runtime as runtime
import autostream_state
from autostream_intents import Intent
from autostream_players import ActionResult
from autostream_state import Origin
from autostream_state.outputs import get_authority
from output_fakes import row
import autostream_selfheal as selfheal


BASE_URL = "http://localhost:3689"


def _selfheal_state() -> dict:
    return autostream_state.store().snapshot().health.as_json()


def _make_monitor(**overrides) -> AudioMonitor:
    defaults = dict(
        input_index=1,
        input_device="hw:0,0",
        silence_threshold_dbfs=-50.0,
        silence_seconds=5,
        fifo_path="/tmp/test.fifo",
        owntone_base_url=BASE_URL,
        owntone_output_name="Test Speaker",
        owntone_volume_percent=50,
    )
    defaults.update(overrides)
    with patch("autostream_audio_monitor.PersistentNowPlayingCache") as mock_cache_cls, \
         patch("autostream_audio_monitor.get_shared_metadata_publisher") as mock_get_pub:
        mock_cache_cls.return_value.get_manual_hint.return_value = None
        mock_get_pub.side_effect = lambda path: MagicMock()
        mon = AudioMonitor(**defaults)
    return mon


@pytest.fixture(autouse=True)
def _reset_selfheal_state():
    selfheal._set_owntone_selfheal_state(
        reconcile_fired_count=0,
        reconcile_last_fired_at=0.0,
        watchdog_armed=False,
        watchdog_restart_count=0,
        watchdog_last_restart_at=0.0,
    )


@pytest.fixture
def writes(monkeypatch):
    """The player service: every output write is recorded and accepted."""
    rec = []

    def update_output(base_url, out_id, **kwargs):
        rec.append((out_id, kwargs))
        return ActionResult(ok=True)

    monkeypatch.setattr(player_service, "update_output", update_output)
    return rec


# ── The default-output handler: PIN veto ────────────────────────────────────

class TestSelectDefaultPinVeto:
    """The default-output select must not probe an output that OwnTone has
    already flagged as needing a PIN -- doing so would make the AirPlay device
    re-prompt (e.g. flash a fresh PIN on screen) on every retry interval
    instead of waiting for the user to pair it via the Web UI."""

    def _select(self):
        return output_intents._select_default(
            Intent("outputs.select_default", {"name": "Test Speaker", "volume": 50},
                   Origin.SESSION, "coordinator"),
            2.0,
        )

    def test_refused_without_a_write_when_the_default_needs_a_pin(self, writes):
        FakeStore().outputs([row("1", "Test Speaker", needs_auth_key=True)])
        outcome = self._select()
        assert outcome.ok is False
        assert outcome.error == "pin_pending"
        assert writes == []

    def test_default_output_without_pin_flag_still_enables(self, writes):
        """Sanity check: the veto is specific to a speaker waiting for a PIN,
        not a general regression in the default-select path."""
        FakeStore().outputs([row("1", "Test Speaker")])
        outcome = self._select()
        assert outcome.ok is True
        assert len(writes) == 1
        assert writes[0][0] == "1"


# ── The user's choice of silence ────────────────────────────────────────────

class TestUserSilenceChoice:
    def _silence_chosen(self):
        return autostream_state.store().snapshot().outputs.silence_chosen

    def test_initially_not_chosen(self):
        FakeStore().outputs([row("1", "Test Speaker", selected=True)])
        assert self._silence_chosen() is False

    def test_a_user_deselect_of_the_last_speaker_sets_it(self, writes):
        FakeStore().outputs([row("1", "Test Speaker", selected=True)])
        get_authority().deselect("1", Origin.USER)
        assert self._silence_chosen() is True

    def test_a_deselect_that_leaves_a_speaker_selected_does_not_set_it(self, writes):
        FakeStore().outputs([row("1", "Test Speaker", selected=True),
                             row("2", "Other", selected=True)])
        get_authority().deselect("1", Origin.USER)
        assert self._silence_chosen() is False

    def test_a_session_end_clears_it(self, writes):
        FakeStore().outputs([row("1", "Test Speaker", selected=True)])
        get_authority().deselect("1", Origin.USER)
        get_authority().note_session(False)
        assert self._silence_chosen() is False

    def test_a_user_select_accepted_by_the_player_clears_it(self, writes):
        FakeStore().outputs([row("1", "Test Speaker", selected=True)])
        get_authority().deselect("1", Origin.USER)
        get_authority().select("1", Origin.USER, volume=30)
        assert self._silence_chosen() is False


# ── _OwntoneHangWatchdog: pure decision logic ───────────────────────────────

class TestOwntoneHangWatchdogPure:
    def test_no_session_never_fires(self):
        wd = _OwntoneHangWatchdog()
        assert wd.maybe_fire(
            session_active=False, fifo_status={"stalled_seconds": 999.0},
            now=100.0, owntone_reachable_fn=lambda: True,
        ) is False

    def test_absent_fifo_block_disarmed_silently(self):
        wd = _OwntoneHangWatchdog()
        assert wd.maybe_fire(
            session_active=True, fifo_status=None,
            now=100.0, owntone_reachable_fn=lambda: True,
        ) is False
        assert wd.restart_count == 0

    def test_non_dict_fifo_block_disarmed(self):
        wd = _OwntoneHangWatchdog()
        assert wd.maybe_fire(
            session_active=True, fifo_status="not-a-dict",
            now=100.0, owntone_reachable_fn=lambda: True,
        ) is False

    def test_below_threshold_does_not_fire(self):
        wd = _OwntoneHangWatchdog()
        assert wd.maybe_fire(
            session_active=True,
            fifo_status={"stalled_seconds": wd.STALL_THRESHOLD_SECONDS - 1},
            now=100.0, owntone_reachable_fn=lambda: True,
        ) is False

    def test_above_threshold_and_reachable_fires(self):
        wd = _OwntoneHangWatchdog()
        assert wd.maybe_fire(
            session_active=True,
            fifo_status={"stalled_seconds": wd.STALL_THRESHOLD_SECONDS + 1},
            now=100.0, owntone_reachable_fn=lambda: True,
        ) is True
        assert wd.restart_count == 1

    def test_unreachable_owntone_does_not_fire(self):
        """OwnTone-down is handled by existing machinery, not this watchdog."""
        wd = _OwntoneHangWatchdog()
        assert wd.maybe_fire(
            session_active=True,
            fifo_status={"stalled_seconds": wd.STALL_THRESHOLD_SECONDS + 1},
            now=100.0, owntone_reachable_fn=lambda: False,
        ) is False
        assert wd.restart_count == 0

    def test_rate_limited_after_first_fire(self):
        wd = _OwntoneHangWatchdog()
        stalled = {"stalled_seconds": wd.STALL_THRESHOLD_SECONDS + 1}
        assert wd.maybe_fire(
            session_active=True, fifo_status=stalled, now=100.0,
            owntone_reachable_fn=lambda: True,
        ) is True
        # Still stalled a minute later: rate-limited.
        assert wd.maybe_fire(
            session_active=True, fifo_status=stalled, now=160.0,
            owntone_reachable_fn=lambda: True,
        ) is False
        # Past the 10-minute rate limit: can fire again.
        assert wd.maybe_fire(
            session_active=True, fifo_status=stalled,
            now=100.0 + wd.RESTART_RATE_LIMIT_SECONDS + 1,
            owntone_reachable_fn=lambda: True,
        ) is True
        assert wd.restart_count == 2

    def test_reachability_probe_only_called_when_stall_exceeds_threshold(self):
        """Cost discipline: the (non-zero-cost) reachability probe must not
        be evaluated on every poll, only once the stall threshold is
        already exceeded."""
        wd = _OwntoneHangWatchdog()
        probe = MagicMock(return_value=True)
        wd.maybe_fire(
            session_active=True,
            fifo_status={"stalled_seconds": 1.0},
            now=100.0, owntone_reachable_fn=probe,
        )
        probe.assert_not_called()


class TestCarryForwardHangWatchdog:
    """A config reload re-enters run_autostream's startup path, which must
    not hand the hang watchdog a clean slate -- the 10-minute restart rate
    limit is a hard ceiling that has to survive a reload exactly as it
    already survives a monitor-daemon reconnect."""

    def test_rate_limit_state_carried_into_new_instance(self):
        previous = _OwntoneHangWatchdog()
        previous.maybe_fire(
            session_active=True,
            fifo_status={"stalled_seconds": previous.STALL_THRESHOLD_SECONDS + 1},
            now=100.0, owntone_reachable_fn=lambda: True,
        )
        assert previous.restart_count == 1

        rebuilt = _carry_forward_hang_watchdog(previous)

        assert rebuilt.restart_count == 1
        assert rebuilt._last_restart_at == 100.0

    def test_rebuilt_watchdog_stays_rate_limited_shortly_after_reload(self):
        """Simulates: watchdog fires, a reload happens, and the stall is
        still present moments later -- must not fire a second restart."""
        previous = _OwntoneHangWatchdog()
        stalled = {"stalled_seconds": previous.STALL_THRESHOLD_SECONDS + 1}
        previous.maybe_fire(
            session_active=True, fifo_status=stalled, now=100.0,
            owntone_reachable_fn=lambda: True,
        )

        rebuilt = _carry_forward_hang_watchdog(previous)

        assert rebuilt.maybe_fire(
            session_active=True, fifo_status=stalled, now=105.0,
            owntone_reachable_fn=lambda: True,
        ) is False
        assert rebuilt.restart_count == 1

    def test_fresh_watchdog_carries_forward_vacuous_state(self):
        """A never-fired watchdog (first process start) carries forward
        cleanly -- carry-forward is safe to apply unconditionally."""
        previous = _OwntoneHangWatchdog()
        rebuilt = _carry_forward_hang_watchdog(previous)
        assert rebuilt.restart_count == 0
        assert rebuilt._last_restart_at == float("-inf")


class TestMaybeRunOwntoneHangWatchdogWiring:
    def test_fires_restart_command_via_run_admin_cmd(self):
        FakeStore().outputs([])
        wd = _OwntoneHangWatchdog()
        status = {"fifo": {"stalled_seconds": wd.STALL_THRESHOLD_SECONDS + 5}}
        fake_result = MagicMock(returncode=0, stderr="")
        with patch("autostream_selfheal.list_outputs") as mock_list, \
             patch("autostream_selfheal.run_admin_cmd", return_value=fake_result) as mock_admin, \
             patch.object(runtime._task_pool, "submit") as mock_submit:
            mock_list.return_value = SimpleNamespace(ok=True)
            # Run the submitted worker function synchronously instead of on
            # the task pool's real background thread, so the assertion below
            # can observe run_admin_cmd's call.
            def _run_now(key, fn, *args, **kwargs):
                fn(*args, **kwargs)
                return True
            mock_submit.side_effect = _run_now

            _maybe_run_owntone_hang_watchdog(wd, status, True, BASE_URL, 1000.0)

        mock_admin.assert_called_once_with(["restart-owntone"], timeout=20.0)
        state = _selfheal_state()
        assert state["watchdog_restart_count"] == 1
        assert state["watchdog_armed"] is True

    def test_absent_fifo_block_no_restart_and_reports_disarmed(self):
        wd = _OwntoneHangWatchdog()
        with patch("autostream_selfheal.run_admin_cmd") as mock_admin:
            _maybe_run_owntone_hang_watchdog(wd, {}, True, BASE_URL, 1000.0)
        mock_admin.assert_not_called()
        state = _selfheal_state()
        assert state["watchdog_armed"] is False

    def test_no_session_no_restart(self):
        wd = _OwntoneHangWatchdog()
        status = {"fifo": {"stalled_seconds": wd.STALL_THRESHOLD_SECONDS + 5}}
        with patch("autostream_selfheal.run_admin_cmd") as mock_admin:
            _maybe_run_owntone_hang_watchdog(wd, status, False, BASE_URL, 1000.0)
        mock_admin.assert_not_called()


# ── Composition: stall -> watchdog -> owntone back with zero outputs -> reconcile ──

class TestSelfHealComposition:
    def test_full_incident_sequence(self):
        """Synthetic status sequence modelling a full self-heal incident end-to-end:

        1. Session active, FIFO stalled beyond threshold, OwnTone reachable
           -> watchdog fires exactly once (and is rate-limited thereafter).
        2. OwnTone "comes back" (simulated: fifo stall clears) as a
           different boot -> the output retry is re-armed.
        3. Rate limiting: a second stall shortly after does NOT fire the
           watchdog again.
        """
        FakeStore().outputs([row("1", "Test Speaker", selected=True)], boot="b0")
        mon = _make_monitor()
        mon._owntone_enabled_ok = True
        mon._outputs_restarts_seen = 0
        watchdog = _OwntoneHangWatchdog()

        base = 1000.0
        restart_calls = []

        def _fake_run_admin_cmd(args, timeout=None):
            restart_calls.append(args)
            return MagicMock(returncode=0, stderr="")

        # Phase 1: stalled FIFO, OwnTone reachable.
        stalled_status = {"fifo": {"stalled_seconds": watchdog.STALL_THRESHOLD_SECONDS + 5}}
        with patch("autostream_selfheal.list_outputs", return_value=SimpleNamespace(ok=True)), \
             patch("autostream_selfheal.run_admin_cmd", side_effect=_fake_run_admin_cmd), \
             patch.object(runtime._task_pool, "submit") as mock_submit:
            def _run_now(key, fn, *args, **kwargs):
                fn(*args, **kwargs)
                return True
            mock_submit.side_effect = _run_now

            _maybe_run_owntone_hang_watchdog(watchdog, stalled_status, True, BASE_URL, base)
            # Immediately stalled again: rate-limited, must not fire twice.
            _maybe_run_owntone_hang_watchdog(watchdog, stalled_status, True, BASE_URL, base + 1)

        assert len(restart_calls) == 1
        assert restart_calls[0] == ["restart-owntone"]

        # Phase 2: OwnTone is back as a different boot.
        FakeStore().outputs([row("1", "Test Speaker", selected=True)], boot="b1")
        _SelfHeal.note_outputs(mon, True, base + 10)

        assert mon._owntone_enabled_ok is False
        assert mon._owntone_last_attempt == 0.0

        state = _selfheal_state()
        assert state["watchdog_restart_count"] == 1
        assert state["reconcile_fired_count"] == 1

    def test_user_deselect_does_not_trigger_a_rearm(self, writes):
        FakeStore().outputs([row("1", "Test Speaker", selected=True)], boot="b0")
        mon = _make_monitor()
        mon._owntone_enabled_ok = True
        mon._outputs_restarts_seen = 0

        get_authority().deselect("1", Origin.USER)  # user just switched everything off
        for i in range(5):
            _SelfHeal.note_outputs(mon, True, 1000.0 + i)

        assert mon._owntone_enabled_ok is True
        assert _selfheal_state()["reconcile_fired_count"] == 0


# ── _RecoveryLog: "first success after failure" recovery WARNING ───────────
#
# Production appliances run at WARN level, so a failure path that logs its
# retries at WARNING but its eventual recovery at INFO (or not at all) shows
# only the failure stream to an operator reading the logs -- there is never
# a WARN-level line saying the problem cleared. _RecoveryLog closes that
# gap: it tracks a boolean failing/ok state and emits exactly one WARNING,
# on the transition back to ok, summarizing how many failures occurred and
# how long the condition was down.

class TestRecoveryLogPure:
    def test_no_warning_when_never_failed(self, caplog):
        log = runtime.RecoveryLog("thing")
        with caplog.at_level("WARNING", logger="root"):
            log.ok(100.0)
        assert caplog.records == []

    def test_single_fail_then_ok_emits_one_warning(self, caplog):
        log = runtime.RecoveryLog("thing")
        log.fail(100.0)
        with caplog.at_level("WARNING", logger="root"):
            log.ok(105.0)
        assert len(caplog.records) == 1
        msg = caplog.records[0].getMessage()
        assert "thing recovered after 1 failure(s) (down for 5s)" in msg

    def test_repeated_fail_then_ok_counts_all_failures_since_first(self, caplog):
        log = runtime.RecoveryLog("thing")
        log.fail(100.0)
        log.fail(101.0)
        log.fail(102.0)
        with caplog.at_level("WARNING", logger="root"):
            log.ok(110.0)
        assert len(caplog.records) == 1
        msg = caplog.records[0].getMessage()
        assert "recovered after 3 failure(s) (down for 10s)" in msg

    def test_ok_without_prior_fail_is_silent_and_resets(self, caplog):
        log = runtime.RecoveryLog("thing")
        with caplog.at_level("WARNING", logger="root"):
            log.ok(100.0)
            log.ok(101.0)
        assert caplog.records == []

    def test_ok_resets_state_so_next_fail_ok_pair_is_independent(self, caplog):
        log = runtime.RecoveryLog("thing")
        log.fail(100.0)
        with caplog.at_level("WARNING", logger="root"):
            log.ok(101.0)
        assert len(caplog.records) == 1
        caplog.clear()

        # A second, independent failure/recovery pair must not remember the
        # first incident's count or start time.
        log.fail(200.0)
        with caplog.at_level("WARNING", logger="root"):
            log.ok(202.0)
        assert len(caplog.records) == 1
        assert "recovered after 1 failure(s) (down for 2s)" in caplog.records[0].getMessage()

    def test_consecutive_oks_after_recovery_stay_silent(self, caplog):
        log = runtime.RecoveryLog("thing")
        log.fail(100.0)
        with caplog.at_level("WARNING", logger="root"):
            log.ok(101.0)
            log.ok(102.0)
            log.ok(103.0)
        assert len(caplog.records) == 1


class TestMaybeRetryOwntoneRecoveryLog:
    """AudioMonitor._owntone_recovery_log, wired into the output retry's
    failure sites (not the INFO-level "no outputs selected" fallback site,
    which is not a failure worth surfacing as a recovery event on its own)."""

    @pytest.fixture(autouse=True)
    def _fifo_ok(self, monkeypatch):
        self.fifo = MagicMock(return_value=SimpleNamespace(ok=True, message=""))
        monkeypatch.setattr(selfheal, "reconcile_fifo_with_backend", self.fifo)
        monkeypatch.setattr(selfheal, "retry_pending_format_reconcile", lambda *a, **k: None)

    def _monitor(self):
        mon = _make_monitor(owntone_base_url=BASE_URL)
        mon.is_capturing = False  # replay_origin=True carries every call below
        return mon

    def test_fail_fail_success_emits_one_recovery_warning(self, caplog):
        mon = self._monitor()
        base = 1000.0
        step = mon.OWNTONE_RETRY_SECONDS + 1

        FakeStore().outputs([row("1", "Test Speaker", selected=True)])
        FakeStore().outputs_unreachable()
        with caplog.at_level("WARNING", logger="root"):
            mon._maybe_retry_owntone(base, replay_origin=True)
            mon._maybe_retry_owntone(base + step, replay_origin=True)
            FakeStore().outputs([row("1", "Test Speaker", selected=True)])
            mon._maybe_retry_owntone(base + 2 * step, replay_origin=True)

        recovered = [r for r in caplog.records if "recovered after" in r.getMessage()]
        assert len(recovered) == 1
        assert "OwnTone output-enable recovered after 2 failure(s)" in recovered[0].getMessage()
        assert mon._owntone_enabled_ok is True

    def test_success_first_emits_no_recovery_warning(self, caplog):
        mon = self._monitor()
        FakeStore().outputs([row("1", "Test Speaker", selected=True)])
        with caplog.at_level("WARNING", logger="root"):
            mon._maybe_retry_owntone(1000.0, replay_origin=True)

        recovered = [r for r in caplog.records if "recovered after" in r.getMessage()]
        assert recovered == []
        assert mon._owntone_enabled_ok is True

    def test_fifo_reconcile_failure_counts_as_a_failure(self, caplog):
        """The fifo_result.ok gate is also a retry WARNING site and must feed
        the same recovery log as the unreachable-outputs failure."""
        mon = self._monitor()
        FakeStore().outputs([row("1", "Test Speaker", selected=True)])
        self.fifo.side_effect = [
            SimpleNamespace(ok=False, message="backend down"),
            SimpleNamespace(ok=True, message=""),
        ]
        base = 2000.0
        with caplog.at_level("WARNING", logger="root"):
            mon._maybe_retry_owntone(base, replay_origin=True)
            mon._maybe_retry_owntone(base + mon.OWNTONE_RETRY_SECONDS + 1, replay_origin=True)

        recovered = [r for r in caplog.records if "recovered after" in r.getMessage()]
        assert len(recovered) == 1
        assert "recovered after 1 failure(s)" in recovered[0].getMessage()


# ── /api/status passthrough ─────────────────────────────────────────────────

class TestStatusPassthrough:
    def test_owntone_selfheal_block_present_in_status_json(self):
        from webui.browser.home_api import send_status_json

        selfheal._set_owntone_selfheal_state(
            reconcile_fired_count=2, reconcile_last_fired_at=42.0,
            watchdog_armed=True, watchdog_restart_count=1,
            watchdog_last_restart_at=99.0,
        )
        handler = MagicMock()
        handler.wfile = MagicMock()
        sent = {}

        def _wfile_write(data):
            import json
            sent["body"] = json.loads(data)

        handler.wfile.write.side_effect = _wfile_write

        with fake_levels([]):
            send_status_json(handler)

        assert sent["body"]["owntone_selfheal"] == {
            "reconcile_fired_count": 2,
            "reconcile_last_fired_at": 42.0,
            "watchdog_armed": True,
            "watchdog_restart_count": 1,
            "watchdog_last_restart_at": 99.0,
        }

    def test_never_fired_sentinel_yields_strict_json(self):
        """Regression: the watchdog's float('-inf') "never restarted"
        sentinel must not reach the JSON boundary. json.dumps emits
        -Infinity (invalid JSON) which every browser's JSON.parse rejects
        wholesale, silently breaking every /api/status consumer in the web
        UI while all Python-side parsing accepted it."""
        from webui.browser.home_api import send_status_json

        selfheal._set_owntone_selfheal_state(
            reconcile_fired_count=0, reconcile_last_fired_at=float("-inf"),
            watchdog_armed=True, watchdog_restart_count=0,
            watchdog_last_restart_at=float("-inf"),
        )
        handler = MagicMock()
        handler.wfile = MagicMock()
        sent = {}

        def _wfile_write(data):
            sent["raw"] = data

        handler.wfile.write.side_effect = _wfile_write

        with fake_levels([]):
            send_status_json(handler)

        raw = sent["raw"].decode("utf-8")
        assert "Infinity" not in raw and "NaN" not in raw

        import json as _json

        def _reject_constant(name):  # strict-parser stand-in for browsers
            raise AssertionError(f"non-strict JSON constant emitted: {name}")

        body = _json.loads(raw, parse_constant=_reject_constant)
        assert body["owntone_selfheal"]["watchdog_last_restart_at"] is None

    def test_send_json_sanitizes_unexpected_nonfinite(self):
        """send_json's allow_nan=False + sanitizing fallback: an unexpected
        nan/inf from any future producer must yield strict JSON with the
        offending values nulled, never an -Infinity payload."""
        from webui.common import send_json

        handler = MagicMock()
        handler.wfile = MagicMock()
        sent = {}
        handler.wfile.write.side_effect = lambda d: sent.__setitem__("raw", d)

        send_json(handler, 200, {
            "ok": True,
            "nested": {"bad": float("inf"), "worse": float("nan"),
                       "fine": 1.5, "list": [float("-inf"), 2]},
        })

        raw = sent["raw"].decode("utf-8")
        assert "Infinity" not in raw and "NaN" not in raw
        import json as _json
        body = _json.loads(raw)
        assert body["nested"]["bad"] is None
        assert body["nested"]["worse"] is None
        assert body["nested"]["fine"] == 1.5
        assert body["nested"]["list"] == [None, 2]


# ── _SelfHeal grouping ───────────────────────────────────────────────────

class TestSelfHealGrouping:
    """_SelfHeal gathers the three self-heal mechanisms under one namespace:
    the already-free reconcile/watchdog pieces are re-exposed unchanged, and
    AudioMonitor._maybe_retry_owntone delegates its logic to
    _SelfHeal.maybe_retry_owntone() while keeping its original bound-method
    call surface."""

    def test_hang_watchdog_class_is_the_original(self):
        assert _SelfHeal.HangWatchdog is _OwntoneHangWatchdog

    def test_maybe_run_hang_watchdog_is_the_original_function(self):
        assert _SelfHeal.maybe_run_hang_watchdog is _maybe_run_owntone_hang_watchdog

    def test_audio_monitor_delegate_calls_selfheal_with_same_args(self):
        mon = _make_monitor()
        with patch.object(_SelfHeal, "maybe_retry_owntone") as m_retry:
            mon._maybe_retry_owntone(123.0, replay_origin=True, monitor_status={"a": 1})

        m_retry.assert_called_once_with(
            mon, 123.0, replay_origin=True, monitor_status={"a": 1},
        )

    def test_maybe_retry_owntone_bails_out_when_idle_and_not_replay_origin(self):
        """Same short-circuit the original AudioMonitor method had: not
        capturing and not the replay origin means no OwnTone work at all --
        exercised here directly against the moved _SelfHeal implementation."""
        mon = _make_monitor()
        mon.is_capturing = False

        with patch("autostream_selfheal.reconcile_fifo_with_backend") as m_fifo:
            _SelfHeal.maybe_retry_owntone(mon, 100.0, replay_origin=False)

        m_fifo.assert_not_called()

    def test_maybe_retry_owntone_via_audiomonitor_reaches_selfheal_body(self):
        """End-to-end: calling the AudioMonitor-bound method (the real call
        site every production caller uses) still runs the moved logic --
        confirms the delegate is not a no-op stub."""
        mon = _make_monitor()
        mon.is_capturing = True
        mon._owntone_enabled_ok = False
        mon._owntone_last_attempt = 0.0

        with patch("autostream_selfheal.reconcile_fifo_with_backend") as m_fifo:
            m_fifo.return_value = SimpleNamespace(ok=False, message="down")
            mon._maybe_retry_owntone(1000.0)

        m_fifo.assert_called_once()

