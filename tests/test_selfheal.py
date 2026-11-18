"""tests/test_selfheal.py

The coordinator's output self-heal against the output authority: the default
speaker rule (and what vetoes it), the arguments of the default select and the
throttled line for each way it is refused, the pass after the player restarts,
and the mid-session re-arm. The speakers are arranged through the
state store; the intent the coordinator submits is recorded by a fake.
"""
from __future__ import annotations

import logging
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

import autostream_core as core
import autostream_player_service as player_service
import autostream_runtime as runtime
import autostream_state
from autostream_audio_monitor import AudioMonitor
from autostream_selfheal import maybe_run_owntone_hang_watchdog as _maybe_run_owntone_hang_watchdog
from autostream_selfheal import OwntoneHangWatchdog as _OwntoneHangWatchdog
from autostream_selfheal import SelfHeal as _SelfHeal
from autostream_intents.table import Reply
from autostream_players import ActionResult
from autostream_state import Origin
from autostream_state.outputs import get_authority
from fake_store import FakeStore
from output_fakes import row
import autostream_selfheal as selfheal

BASE_URL = "http://localhost:3689"
DEFAULT_NAME = "Test Speaker"
NOW = 1000.0


def _make_monitor(**overrides) -> AudioMonitor:
    defaults = dict(
        input_index=1,
        input_device="hw:0,0",
        silence_threshold_dbfs=-50.0,
        silence_seconds=5,
        fifo_path="/tmp/test.fifo",
        owntone_base_url=BASE_URL,
        owntone_output_name=DEFAULT_NAME,
        owntone_volume_percent=50,
    )
    defaults.update(overrides)
    with patch("autostream_audio_monitor.PersistentNowPlayingCache") as mock_cache_cls, \
         patch("autostream_audio_monitor.get_shared_metadata_publisher") as mock_get_pub:
        mock_cache_cls.return_value.get_manual_hint.return_value = None
        mock_get_pub.side_effect = lambda path: MagicMock()
        mon = AudioMonitor(**defaults)
    mon.is_capturing = True
    return mon


def _reply(ok=True, error=None, result=None) -> Reply:
    return Reply(ok=ok, error=error, version=0, boot="", result=result or {})


@pytest.fixture
def submitted(monkeypatch):
    """The coordinator's submitted intents; each is answered from `answers`
    (first to last), else with success."""
    rec = SimpleNamespace(intents=[], answers=[])

    def fake_submit(intent, **kwargs):
        rec.intents.append(intent)
        return rec.answers.pop(0) if rec.answers else _reply()

    monkeypatch.setattr(core.intents, "submit", fake_submit)
    return rec


@pytest.fixture
def fifo_ok(monkeypatch):
    monkeypatch.setattr(selfheal, "reconcile_fifo_with_backend",
                        lambda *a, **k: SimpleNamespace(ok=True, message=""))
    monkeypatch.setattr(selfheal, "retry_pending_format_reconcile", lambda *a, **k: None)


@pytest.fixture
def republish(monkeypatch):
    calls = []
    monkeypatch.setattr(runtime, "request_nowplaying_republish", lambda *a, **k: calls.append(a))
    return calls


@pytest.fixture
def player_ok(monkeypatch):
    """The player accepts every write."""
    monkeypatch.setattr(player_service, "update_output", lambda *a, **k: ActionResult(ok=True))


def _run(mon, now=NOW):
    _SelfHeal.maybe_retry_owntone(mon, now, replay_origin=False)


# -- the default rule ---------------------------------------------------------

class TestDefaultRule:
    def test_nothing_selected_submits_the_default_select(self, submitted, fifo_ok):
        FakeStore().outputs([row("1", DEFAULT_NAME)])
        mon = _make_monitor()
        _run(mon)
        assert [i.name for i in submitted.intents] == ["outputs.select_default"]
        assert submitted.intents[0].origin is Origin.SESSION
        assert mon._owntone_enabled_ok is True

    def test_a_selected_speaker_means_no_default_select(self, submitted, fifo_ok):
        FakeStore().outputs([row("1", DEFAULT_NAME, selected=True)])
        mon = _make_monitor()
        _run(mon)
        assert submitted.intents == []
        assert mon._owntone_enabled_ok is True

    def test_silence_chosen_vetoes_the_default(self, submitted, fifo_ok, player_ok):
        FakeStore().outputs([row("1", DEFAULT_NAME, selected=True)])
        get_authority().deselect("1", Origin.USER)
        assert autostream_state.store().snapshot().outputs.silence_chosen is True
        mon = _make_monitor()
        _run(mon)
        assert submitted.intents == []
        assert mon._owntone_enabled_ok is False

    def test_a_session_end_lifts_the_silence_veto(self, submitted, fifo_ok, player_ok):
        FakeStore().outputs([row("1", DEFAULT_NAME, selected=True)])
        get_authority().deselect("1", Origin.USER)
        get_authority().note_session(False)
        mon = _make_monitor()
        _run(mon)
        assert [i.name for i in submitted.intents] == ["outputs.select_default"]

    def test_a_unit_waiting_for_a_pin_vetoes_the_default(self, submitted, fifo_ok, caplog):
        FakeStore().outputs([row("1", DEFAULT_NAME, needs_auth_key=True), row("2", "Other")])
        mon = _make_monitor()
        with caplog.at_level(logging.INFO):
            _run(mon)
        assert submitted.intents == []
        assert mon._owntone_enabled_ok is False
        assert any("waiting for a PIN; not auto-enabling the default output" in r.getMessage()
                   for r in caplog.records)

    def test_the_veto_line_is_throttled(self, submitted, fifo_ok, caplog):
        FakeStore().outputs([row("1", DEFAULT_NAME, needs_auth_key=True)])
        mon = _make_monitor()
        with caplog.at_level(logging.INFO):
            _run(mon, NOW)
            _run(mon, NOW + mon.OWNTONE_RETRY_SECONDS + 1)
        lines = [r for r in caplog.records if "not auto-enabling the default output" in r.getMessage()]
        assert len(lines) == 1


class TestDefaultSelectArguments:
    def test_name_and_clamped_volume_only_when_the_unit_is_unknown(self, submitted, fifo_ok):
        FakeStore().outputs([row("1", "Other")])
        mon = _make_monitor(owntone_volume_percent=150)
        _run(mon)
        assert submitted.intents[0].args == {"name": DEFAULT_NAME, "volume": 100}

    def test_offset_and_mode_of_the_default_unit_are_added(self, submitted, fifo_ok):
        FakeStore().outputs([row("1", DEFAULT_NAME)])
        mon = _make_monitor(
            owntone_output_offsets_ms={"1": 120},
            owntone_output_airplay_modes={"1": "airplay2"},
        )
        _run(mon)
        args = submitted.intents[0].args
        assert args["name"] == DEFAULT_NAME
        assert args["volume"] == 50
        assert args["offset_ms"] == 120
        assert args["mode"] == player_service.config_airplay_mode_to_backend("airplay2")

    def test_the_requester_is_the_coordinator(self, submitted, fifo_ok):
        FakeStore().outputs([row("1", DEFAULT_NAME)])
        _run(_make_monitor())
        assert submitted.intents[0].requester == "coordinator"


class TestDefaultRefusal:
    @pytest.mark.parametrize("error,result,level,fragment", [
        ("no_default", {}, logging.WARNING, "No default output configured"),
        ("pin_pending", {}, logging.INFO, "is waiting for a PIN; not auto-enabling it"),
        ("in_use", {"owner": "Hall"}, logging.INFO, "is in use by Hall"),
        ("pin_required", {}, logging.INFO, "requires a PIN"),
        ("failed", {"message": "boom"}, logging.WARNING,
         "Failed to apply default output settings for 'Test Speaker': boom"),
    ])
    def test_the_line_for_each_reason(self, caplog, error, result, level, fragment):
        mon = _make_monitor()
        with caplog.at_level(logging.INFO):
            mon._log_default_output_refusal(NOW, DEFAULT_NAME, _reply(False, error, result))
        lines = [r for r in caplog.records if fragment in r.getMessage()]
        assert len(lines) == 1
        assert lines[0].levelno == level

    def test_the_line_is_throttled_per_reason(self, caplog):
        mon = _make_monitor()
        with caplog.at_level(logging.INFO):
            mon._log_default_output_refusal(NOW, DEFAULT_NAME, _reply(False, "no_default"))
            mon._log_default_output_refusal(NOW + 1, DEFAULT_NAME, _reply(False, "no_default"))
            mon._log_default_output_refusal(NOW + 1, DEFAULT_NAME, _reply(False, "pin_required"))
        assert len([r for r in caplog.records if "No default output configured" in r.getMessage()]) == 1
        assert len([r for r in caplog.records if "requires a PIN" in r.getMessage()]) == 1

    def test_a_default_that_is_not_there_logs_once_when_the_wait_starts(self, caplog):
        mon = _make_monitor()
        with caplog.at_level(logging.INFO):
            for i in range(5):
                mon._log_default_output_refusal(NOW + 10 * i, DEFAULT_NAME, _reply(False, "not_found"))
        lines = [r for r in caplog.records if "is not on the network yet" in r.getMessage()]
        assert len(lines) == 1 and lines[0].levelno == logging.INFO
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]

    def test_a_default_still_missing_after_five_minutes_warns_once(self, caplog):
        mon = _make_monitor()
        with caplog.at_level(logging.INFO):
            for t in (0, 100, 299, 300, 400, 900):
                mon._log_default_output_refusal(NOW + t, DEFAULT_NAME, _reply(False, "not_found"))
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1 and "still not on the network after 300 s" in warnings[0].getMessage()

    def test_the_default_appearing_ends_the_wait_with_one_line(self, submitted, fifo_ok, caplog):
        FakeStore().outputs([row("1", "Other")])
        mon = _make_monitor()
        with caplog.at_level(logging.INFO):
            mon._log_default_output_refusal(NOW, DEFAULT_NAME, _reply(False, "not_found"))
            FakeStore().outputs([row("1", "Other"), row("2", DEFAULT_NAME)])
            _run(mon, NOW + 42)
            _run(mon, NOW + 60)
        lines = [r.getMessage() for r in caplog.records if "appeared after" in r.getMessage()]
        assert lines == ["Default output 'Test Speaker' appeared after 42 s"]
        assert mon._default_missing_since is None

    def test_a_new_session_starts_the_wait_afresh(self, caplog):
        mon = _make_monitor()
        with caplog.at_level(logging.INFO):
            mon._log_default_output_refusal(NOW, DEFAULT_NAME, _reply(False, "not_found"))
            mon.clear_default_output_wait()
            mon._log_default_output_refusal(NOW + 5, DEFAULT_NAME, _reply(False, "not_found"))
        assert len([r for r in caplog.records if "is not on the network yet" in r.getMessage()]) == 2

    def test_a_refusal_logs_both_lines_and_leaves_the_retry_armed(self, submitted, fifo_ok, caplog):
        FakeStore().outputs([row("1", DEFAULT_NAME)])
        submitted.answers.append(_reply(False, "in_use", {"owner": "Hall"}))
        mon = _make_monitor()
        with caplog.at_level(logging.INFO):
            _run(mon)
        text = " | ".join(r.getMessage() for r in caplog.records)
        assert "is in use by Hall" in text
        assert "default fallback not available yet" in text
        assert mon._owntone_enabled_ok is False
        assert mon._outputs_restarts_seen is None


# -- the pass after the player restarts --------------------------------------

class TestPassAfterRestart:
    @pytest.fixture
    def no_authority_writes(self, monkeypatch):
        """The authority alone restores the selection: the pass asks it for nothing."""
        def fail(*a, **k):
            raise AssertionError("the pass reached the authority")
        monkeypatch.setattr(get_authority(), "select", fail)
        monkeypatch.setattr(get_authority(), "set_volume", fail)

    def test_a_restart_is_not_re_applied_by_the_pass(self, fifo_ok, no_authority_writes):
        FakeStore().outputs([row("1", DEFAULT_NAME, selected=True)], boot="b0")
        FakeStore().outputs([row("1", DEFAULT_NAME, selected=True)], boot="b1")
        mon = _make_monitor()
        mon._outputs_restarts_seen = 0
        _run(mon)
        assert not hasattr(get_authority(), "reapply_selected")
        assert mon._owntone_enabled_ok is True

    def test_no_pass_while_the_outputs_are_unreachable(self, fifo_ok):
        FakeStore().outputs([row("1", DEFAULT_NAME, selected=True)], boot="b0")
        FakeStore().outputs_unreachable()
        mon = _make_monitor()
        _run(mon)
        assert mon._owntone_enabled_ok is False


# -- the mid-session re-arm ---------------------------------------------------

class TestNoteOutputs:
    def _restart(self, boot):
        FakeStore().outputs([row("1", DEFAULT_NAME, selected=True)], boot=boot)

    def _armed(self, restarted=True, seen=0):
        """A monitor that has counted *seen* restarts; with *restarted* the
        player then restarts once."""
        self._restart("b0")
        mon = _make_monitor()
        mon._owntone_enabled_ok = True
        mon._owntone_last_attempt = 777.0
        mon._outputs_restarts_seen = seen
        if restarted:
            self._restart("b1")
        return mon

    def _health(self):
        return autostream_state.store().snapshot().health

    def test_a_boot_change_mid_session_rearms_and_counts(self, caplog):
        mon = self._armed()
        with caplog.at_level(logging.WARNING):
            _SelfHeal.note_outputs(mon, True, 1234.0)
        assert mon._owntone_enabled_ok is False
        assert mon._owntone_last_attempt == 0.0
        assert self._health().reconcile_fired_count == 1
        assert self._health().reconcile_last_fired_at == 1234.0
        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert warnings == ["OwnTone restarted mid-session; its outputs are restored by the output reconcile."]
        assert mon._outputs_restarts_seen == 1

    def test_idle_does_nothing(self):
        mon = self._armed()
        _SelfHeal.note_outputs(mon, False, 1234.0)
        assert mon._owntone_enabled_ok is True
        assert self._health().reconcile_fired_count == 0

    def test_no_monitor_does_nothing(self):
        _SelfHeal.note_outputs(None, True, 1234.0)
        assert self._health().reconcile_fired_count == 0

    def test_already_rearmed_does_not_count_again(self):
        mon = self._armed()
        mon._owntone_enabled_ok = False
        _SelfHeal.note_outputs(mon, True, 1234.0)
        assert self._health().reconcile_fired_count == 0

    def test_no_restart_does_nothing(self):
        mon = self._armed(restarted=False)
        _SelfHeal.note_outputs(mon, True, 1234.0)
        assert mon._owntone_enabled_ok is True
        assert self._health().reconcile_fired_count == 0

    def test_no_count_yet_adopts_the_current_one_without_counting(self):
        mon = self._armed(seen=None)
        _SelfHeal.note_outputs(mon, True, 1234.0)
        assert mon._owntone_enabled_ok is True
        assert mon._outputs_restarts_seen == 1
        assert self._health().reconcile_fired_count == 0

    def test_two_restarts_count_twice(self):
        mon = self._armed()
        _SelfHeal.note_outputs(mon, True, 1.0)
        mon._owntone_enabled_ok = True
        self._restart("b2")
        _SelfHeal.note_outputs(mon, True, 2.0)
        assert self._health().reconcile_fired_count == 2


# -- no republish request -----------------------------------------------------

class TestNoRepublish:
    def test_the_default_select_raises_no_republish_request(self, submitted, fifo_ok, republish):
        FakeStore().outputs([row("1", DEFAULT_NAME)])
        _run(_make_monitor())
        assert republish == []

    def test_the_restart_path_raises_no_republish_request(self, fifo_ok, republish):
        FakeStore().outputs([row("1", DEFAULT_NAME, selected=True)], boot="b0")
        FakeStore().outputs([row("1", DEFAULT_NAME, selected=True)], boot="b1")
        mon = _make_monitor()
        mon._outputs_restarts_seen = 0
        _run(mon)
        _SelfHeal.note_outputs(mon, True, NOW)
        assert republish == []


# -- the hang watchdog's reachability ----------------------------------------

class TestHangWatchdogReachability:
    def _stalled(self, wd):
        return {"fifo": {"stalled_seconds": wd.STALL_THRESHOLD_SECONDS + 5}}

    def test_not_connected_means_not_reachable_and_no_probe(self):
        FakeStore().outputs_unreachable()
        wd = _OwntoneHangWatchdog()
        with patch("autostream_selfheal.list_outputs") as probe, \
             patch("autostream_selfheal.run_admin_cmd") as admin:
            _maybe_run_owntone_hang_watchdog(wd, self._stalled(wd), True, BASE_URL, NOW)
        probe.assert_not_called()
        admin.assert_not_called()
        assert wd.restart_count == 0

    def test_connected_probes_the_player(self):
        FakeStore().outputs([])
        wd = _OwntoneHangWatchdog()
        probe_result = SimpleNamespace(ok=False)
        with patch("autostream_selfheal.list_outputs", return_value=probe_result) as probe, \
             patch("autostream_selfheal.run_admin_cmd") as admin:
            _maybe_run_owntone_hang_watchdog(wd, self._stalled(wd), True, BASE_URL, NOW)
        probe.assert_called_once()
        admin.assert_not_called()
