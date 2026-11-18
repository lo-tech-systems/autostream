"""tests/test_selfheal.py

The coordinator's output self-heal against the output authority: the default
speaker rule (and what vetoes it), the arguments of the default select and the
throttled line for each way it is refused, the re-apply after the player
restarts, and the mid-session re-arm. The speakers are arranged through the
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
from autostream_core import AudioMonitor, _SelfHeal, _maybe_run_owntone_hang_watchdog, _OwntoneHangWatchdog
from autostream_intents.table import Reply
from autostream_players import ActionResult
from autostream_state import Origin
from autostream_state.outputs import get_authority
from fake_store import FakeStore
from output_fakes import row

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
    with patch("autostream_core.PersistentNowPlayingCache") as mock_cache_cls, \
         patch("autostream_core.get_shared_metadata_publisher") as mock_get_pub:
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
    monkeypatch.setattr(core, "reconcile_fifo_with_backend",
                        lambda *a, **k: SimpleNamespace(ok=True, message=""))
    monkeypatch.setattr(core, "retry_pending_format_reconcile", lambda *a, **k: None)


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
        ("not_found", {}, logging.WARNING, "'Test Speaker' not found"),
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
            mon._log_default_output_refusal(NOW, DEFAULT_NAME, _reply(False, "not_found"))
            mon._log_default_output_refusal(NOW + 1, DEFAULT_NAME, _reply(False, "not_found"))
            mon._log_default_output_refusal(NOW + 1, DEFAULT_NAME, _reply(False, "no_default"))
        assert len([r for r in caplog.records if "not found" in r.getMessage()]) == 1
        assert len([r for r in caplog.records if "No default output configured" in r.getMessage()]) == 1

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
        assert mon._outputs_boot_seen is None


# -- re-apply after the player restarts ---------------------------------------

class TestReapplyAfterBootChange:
    @pytest.fixture
    def authority_spy(self, monkeypatch):
        spy = SimpleNamespace(reapply=[])
        spy.reapply_selected = lambda **kw: spy.reapply.append(kw)
        monkeypatch.setattr(core, "get_authority", lambda: spy)
        return spy

    def test_first_pass_records_the_boot_and_does_not_reapply(self, fifo_ok, authority_spy):
        FakeStore().outputs([row("1", DEFAULT_NAME, selected=True)], boot="b0")
        mon = _make_monitor()
        _run(mon)
        assert authority_spy.reapply == []
        assert mon._outputs_boot_seen == "b0"

    def test_same_boot_does_not_reapply(self, fifo_ok, authority_spy):
        FakeStore().outputs([row("1", DEFAULT_NAME, selected=True)], boot="b0")
        mon = _make_monitor()
        mon._outputs_boot_seen = "b0"
        _run(mon)
        assert authority_spy.reapply == []

    def test_a_boot_change_reapplies_with_the_clamped_volume_and_moves_the_marker(
            self, fifo_ok, authority_spy):
        FakeStore().outputs([row("1", DEFAULT_NAME, selected=True)], boot="b1")
        mon = _make_monitor(owntone_volume_percent=150)
        mon._outputs_boot_seen = "b0"
        _run(mon)
        assert authority_spy.reapply == [{"recovery_volume": 100}]
        assert mon._outputs_boot_seen == "b1"
        assert mon._owntone_enabled_ok is True

    def test_no_reapply_while_the_outputs_are_unreachable(self, fifo_ok, authority_spy):
        FakeStore().outputs([row("1", DEFAULT_NAME, selected=True)], boot="b0")
        FakeStore().outputs_unreachable()
        mon = _make_monitor()
        mon._outputs_boot_seen = "b0"
        _run(mon)
        assert authority_spy.reapply == []
        assert mon._owntone_enabled_ok is False


# -- the mid-session re-arm ---------------------------------------------------

class TestNoteOutputs:
    def _armed(self, seen="b0", current="b1"):
        FakeStore().outputs([row("1", DEFAULT_NAME, selected=True)], boot=current)
        mon = _make_monitor()
        mon._owntone_enabled_ok = True
        mon._owntone_last_attempt = 777.0
        mon._outputs_boot_seen = seen
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
        assert any(r.levelno == logging.WARNING for r in caplog.records)

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

    def test_same_boot_does_nothing(self):
        mon = self._armed(seen="b1", current="b1")
        _SelfHeal.note_outputs(mon, True, 1234.0)
        assert mon._owntone_enabled_ok is True
        assert self._health().reconcile_fired_count == 0

    def test_no_marker_yet_does_nothing(self):
        mon = self._armed(seen=None)
        _SelfHeal.note_outputs(mon, True, 1234.0)
        assert mon._owntone_enabled_ok is True
        assert self._health().reconcile_fired_count == 0

    def test_two_restarts_count_twice(self):
        mon = self._armed()
        _SelfHeal.note_outputs(mon, True, 1.0)
        mon._owntone_enabled_ok = True
        mon._outputs_boot_seen = "b0"
        _SelfHeal.note_outputs(mon, True, 2.0)
        assert self._health().reconcile_fired_count == 2


# -- no republish request -----------------------------------------------------

class TestNoRepublish:
    def test_the_default_select_raises_no_republish_request(self, submitted, fifo_ok, republish):
        FakeStore().outputs([row("1", DEFAULT_NAME)])
        _run(_make_monitor())
        assert republish == []

    def test_the_boot_change_path_raises_no_republish_request(self, fifo_ok, republish, monkeypatch):
        monkeypatch.setattr(core, "get_authority", lambda: SimpleNamespace(reapply_selected=lambda **k: None))
        FakeStore().outputs([row("1", DEFAULT_NAME, selected=True)], boot="b1")
        mon = _make_monitor()
        mon._outputs_boot_seen = "b0"
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
        with patch("autostream_core.list_outputs") as probe, \
             patch("autostream_core.run_admin_cmd") as admin:
            _maybe_run_owntone_hang_watchdog(wd, self._stalled(wd), True, BASE_URL, NOW)
        probe.assert_not_called()
        admin.assert_not_called()
        assert wd.restart_count == 0

    def test_connected_probes_the_player(self):
        FakeStore().outputs([])
        wd = _OwntoneHangWatchdog()
        probe_result = SimpleNamespace(ok=False)
        with patch("autostream_core.list_outputs", return_value=probe_result) as probe, \
             patch("autostream_core.run_admin_cmd") as admin:
            _maybe_run_owntone_hang_watchdog(wd, self._stalled(wd), True, BASE_URL, NOW)
        probe.assert_called_once()
        admin.assert_not_called()
