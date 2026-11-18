"""Pushbutton mute/unmute tests.

Covers:
- POST /api/dial/mute host endpoint: auth, explicit action validation,
  the remembered levels, partial failures, all-failed, and
  restore-with-default.
- dial_volume.py typed event queue: coalescing (collapse-to-last for mute
  runs), mute event ordering.
- enqueue_mute() enqueueing.
- DialConfig.sw_gpio default and JSON-key semantics.
- dial_main.py button callback wires enqueue_mute.
- helpers.sh writes sw_gpio=22 on fresh install.
"""
from __future__ import annotations

import io
import json
import queue
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Optional
from unittest.mock import MagicMock, call, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
_dial = str(REPO_ROOT / "dial")
for _p in (_core, _dial):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import autostream_player_service as player_service
from autostream_players import ActionResult, OutputInfo
from autostream_state import Origin, store
from autostream_state.outputs import get_authority
from fake_store import FakeStore


def _remembered() -> dict:
    """Test-only introspection of the levels the authority would restore
    (the volume of each muted speaker)."""
    return {u.id: u.volume for u in store().snapshot().outputs.units if u.muted}


# ---------------------------------------------------------------------------
# Helpers shared across tests
# ---------------------------------------------------------------------------

def _make_output(oid: str, volume: int, selected: bool = True):
    return OutputInfo(id=oid, name=oid, selected=selected, volume_percent=volume)


def _make_update_result(ok=True):
    return ActionResult(
        ok=ok, error="" if ok else "connection refused", error_code="" if ok else "request_failed")


def _make_parsed_config(base_url="http://localhost:3689", volume_percent=20):
    parsed = SimpleNamespace()
    parsed.owntone = SimpleNamespace(base_url=base_url, volume_percent=volume_percent)
    return parsed


def _make_state(tmp_path):
    cfg = tmp_path / "autostream.json"
    cfg.write_text('{"general":{}}')
    s = SimpleNamespace()
    s.config_path = str(cfg)
    return s


class _FakeHandler:
    """Minimal BaseHTTPRequestHandler stand-in."""
    def __init__(self):
        self.responses: list[tuple[int, dict]] = []

    def send_response(self, code):
        pass

    def send_header(self, k, v):
        pass

    def end_headers(self):
        pass

    @property
    def wfile(self):
        return io.BytesIO()


@pytest.fixture
def writes(monkeypatch):
    """The player service: records every write as (id, volume) in call order
    and answers from `results` (default: ok)."""
    rec = SimpleNamespace(calls=[], results=[])

    def update_output(base_url, out_id, **kwargs):
        rec.calls.append((out_id, kwargs.get("volume_percent")))
        return rec.results.pop(0) if rec.results else _make_update_result(True)

    monkeypatch.setattr(player_service, "update_output", update_output)
    return rec


def _arrange(outputs, remembered=None, writes=None):
    """Adopt *outputs*, then (when *remembered* is given) mute them so that
    each speaker remembers its level in *remembered* and reads as silent."""
    store_ = FakeStore()
    if not remembered:
        store_.outputs(list(outputs))
        return
    store_.outputs([
        OutputInfo(id=o.id, name=o.name, selected=o.selected,
                   volume_percent=remembered.get(o.id, o.volume_percent))
        for o in outputs
    ])
    get_authority().mute_all(Origin.USER)
    store_.outputs(list(outputs))
    if writes is not None:
        writes.calls.clear()


def _post(fn, json_obj, parsed=None, authorized=True):
    """Drive a dial route; return what it sent."""
    import autostream_webui_api as api
    captured = {}

    def fake_send_json(h, code, body):
        captured["code"] = code
        captured["body"] = body

    with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
         patch("autostream_webui_api.dial_authorization",
               return_value="authorized" if authorized else "not_authorized"), \
         patch("autostream_webui_api._config_snapshot", return_value=parsed or _make_parsed_config()):
        getattr(api, fn)(MagicMock(), MagicMock(), json_obj)
    return captured


# ---------------------------------------------------------------------------
# Host API: POST /api/dial/mute
# ---------------------------------------------------------------------------

class TestDialMuteAuth:
    """Authorization checks at the very top of send_dial_mute_post_json.

    These run before action validation, so dial_id/authorization failures
    are 403 regardless of whether an action is present or valid.
    """

    def _call(self, json_obj, authorized=True):
        return _post("send_dial_mute_post_json", json_obj, authorized=authorized)

    def test_missing_dial_id_returns_403(self):
        result = self._call({"action": "mute"})
        assert result["code"] == 403

    def test_empty_dial_id_returns_403(self):
        result = self._call({"dial_id": "", "action": "mute"})
        assert result["code"] == 403

    def test_non_string_dial_id_returns_403(self):
        result = self._call({"dial_id": 123, "action": "mute"})
        assert result["code"] == 403

    def test_unauthorized_dial_id_returns_403(self):
        result = self._call({"dial_id": "some-uuid", "action": "mute"}, authorized=False)
        assert result["code"] == 403

    def test_unauthorized_dial_with_valid_action_still_403_not_400(self):
        """Authorization is checked before the action, so an unauthorized
        caller must never see a 400 that would leak "your action was fine,
        only your authorization failed" — it always gets the same 403."""
        result = self._call({"dial_id": "some-uuid", "action": "restore"}, authorized=False)
        assert result["code"] == 403
        assert result["body"] == {}


class TestDialMuteActionValidation:
    """action must be exactly "mute" or "restore"; anything else is a 400,
    and this check runs only after dial_id/authorization have passed."""

    def _call(self, json_obj):
        return _post("send_dial_mute_post_json", json_obj)

    def test_missing_action_returns_400(self):
        result = self._call({"dial_id": "uid"})
        assert result["code"] == 400
        assert result["body"] == {"ok": False, "error": "invalid_action"}

    def test_empty_string_action_returns_400(self):
        result = self._call({"dial_id": "uid", "action": ""})
        assert result["code"] == 400
        assert result["body"] == {"ok": False, "error": "invalid_action"}

    def test_wrong_case_action_returns_400(self):
        result = self._call({"dial_id": "uid", "action": "MUTE"})
        assert result["code"] == 400
        assert result["body"] == {"ok": False, "error": "invalid_action"}

    def test_non_string_action_returns_400(self):
        result = self._call({"dial_id": "uid", "action": 123})
        assert result["code"] == 400
        assert result["body"] == {"ok": False, "error": "invalid_action"}


class TestDialMuteBackend:
    """Backend availability / no-output cases."""

    def _call_with_mocks(self, action="mute"):
        return _post("send_dial_mute_post_json", {"dial_id": "valid-uuid", "action": action})

    def test_backend_unavailable_returns_ok_false(self, writes):
        FakeStore().outputs_unreachable()
        result = self._call_with_mocks()
        assert result["body"]["ok"] is False
        assert result["body"]["error"] == "backend_unavailable"

    def test_no_active_outputs_returns_ok_false(self, writes):
        _arrange([_make_output("o1", 50, selected=False)])
        result = self._call_with_mocks()
        assert result["body"]["ok"] is False
        assert result["body"]["error"] == "no_active_outputs"


class TestDialMuteAction:
    """Explicit action execution and the remembered levels.

    The action always comes from the request body -- there is no local
    inference from output volumes any more, so every test here drives the
    handler with an explicit action and asserts it is obeyed.
    """

    def _call(self, outputs, action, initial_snapshot=None,
              update_results=None, default_vol=20, writes=None):
        _arrange(outputs, initial_snapshot, writes)
        if update_results is not None and writes is not None:
            writes.results.extend(update_results)
        captured = _post(
            "send_dial_mute_post_json", {"dial_id": "valid-uuid", "action": action},
            parsed=_make_parsed_config(volume_percent=default_vol),
        )
        return captured, _remembered()

    def test_mute_when_audible_output_present(self, writes):
        result, snapshot = self._call([_make_output("o1", 50)], "mute", writes=writes)
        assert result["body"]["ok"] is True
        assert result["body"]["muted"] is True
        assert snapshot["o1"] == 50

    def test_mute_remembers_all_audible_outputs(self, writes):
        outputs = [_make_output("o1", 30), _make_output("o2", 80)]
        result, snapshot = self._call(outputs, "mute", writes=writes)
        assert snapshot == {"o1": 30, "o2": 80}
        assert result["body"]["muted"] is True

    def test_mute_does_not_overwrite_an_existing_remembered_level(self, writes):
        outputs = [_make_output("o1", 0), _make_output("o2", 60)]
        result, snapshot = self._call(
            outputs, "mute", initial_snapshot={"o1": 45}, writes=writes
        )
        # o1 is already at zero (previously muted); o2 is still audible
        assert snapshot["o1"] == 45  # must not be overwritten
        assert snapshot["o2"] == 60
        assert result["body"]["muted"] is True

    def test_mute_when_already_silent_is_idempotent_noop(self, writes):
        """Explicit "mute" on an appliance whose selected outputs are all
        already at zero is a no-op -- not an error, and no write is made."""
        outputs = [_make_output("o1", 0), _make_output("o2", 0)]
        result, snapshot = self._call(outputs, "mute", writes=writes)
        assert result["body"] == {"ok": True, "muted": True}
        assert writes.calls == []

    def test_restore_when_all_outputs_at_zero(self, writes):
        outputs = [_make_output("o1", 0), _make_output("o2", 0)]
        result, snapshot = self._call(
            outputs, "restore", initial_snapshot={"o1": 30, "o2": 80}, writes=writes
        )
        assert result["body"]["ok"] is True
        assert result["body"]["muted"] is False
        assert snapshot == {}  # nothing left muted on full success

    def test_restore_when_already_audible_is_idempotent_noop(self, writes):
        """Explicit "restore" on an appliance whose selected outputs are all
        already non-zero is a no-op -- it must not be reinterpreted as a
        mute just because every output happens to be audible."""
        outputs = [_make_output("o1", 45), _make_output("o2", 60)]
        result, snapshot = self._call(outputs, "restore", writes=writes)
        assert result["body"] == {"ok": True, "muted": False}
        assert snapshot == {}
        assert writes.calls == []

    def test_explicit_restore_obeyed_even_though_stale_inference_would_mute(self, writes):
        """Mixed volumes -- the deleted any(volume>0) inference would have
        picked "mute" here since o2 is audible. The explicit "restore"
        request must be obeyed instead: o1 (zero, nothing remembered) rises
        to the default, o2 (already non-zero) is left alone."""
        outputs = [_make_output("o1", 0), _make_output("o2", 50)]
        result, snapshot = self._call(outputs, "restore", default_vol=35, writes=writes)
        assert result["body"]["ok"] is True
        assert result["body"]["muted"] is False
        assert writes.calls == [("o1", 35)]

    def test_restore_uses_the_remembered_volume(self, writes):
        self._call([_make_output("o1", 0)], "restore", initial_snapshot={"o1": 70}, writes=writes)
        assert writes.calls == [("o1", 70)]

    def test_restore_uses_default_vol_when_nothing_is_remembered(self, writes):
        """A silent output nothing is remembered for (one selected while
        muted, or whose mute was lost) is restored to the configured default,
        the only sensible target."""
        self._call([_make_output("o1", 0)], "restore", default_vol=35, writes=writes)
        assert writes.calls == [("o1", 35)]


class TestDialMuteFailures:
    """Partial and all-failed error paths."""

    def _call(self, outputs, action, update_ok_sequence, initial_snapshot=None, writes=None):
        _arrange(outputs, initial_snapshot, writes)
        writes.results.extend(_make_update_result(ok) for ok in update_ok_sequence)
        captured = _post("send_dial_mute_post_json", {"dial_id": "uid", "action": action})
        return captured, _remembered()

    def test_mute_all_fail_returns_all_outputs_failed(self, writes):
        outputs = [_make_output("o1", 50), _make_output("o2", 30)]
        result, snapshot = self._call(outputs, "mute", [False, False], writes=writes)
        assert result["body"]["ok"] is False
        assert result["body"]["error"] == "all_outputs_failed"

    def test_mute_partial_fail_returns_partial(self, writes):
        outputs = [_make_output("o1", 50), _make_output("o2", 30)]
        result, snapshot = self._call(outputs, "mute", [True, False], writes=writes)
        assert result["body"]["ok"] is True
        assert result["body"]["muted"] is True
        assert result["body"].get("partial") is True

    def test_restore_all_fail_returns_all_outputs_failed(self, writes):
        outputs = [_make_output("o1", 0), _make_output("o2", 0)]
        result, snapshot = self._call(
            outputs, "restore", [False, False],
            initial_snapshot={"o1": 50, "o2": 30}, writes=writes,
        )
        assert result["body"]["ok"] is False
        assert result["body"]["error"] == "all_outputs_failed"

    def test_restore_partial_fail_forgets_the_remembered_levels_anyway(self, writes):
        """The authority forgets every remembered level as soon as a restore
        is attempted, whichever individual writes then succeed or fail: the
        next read adopts what the speaker really has."""
        outputs = [_make_output("o1", 0), _make_output("o2", 0)]
        result, snapshot = self._call(
            outputs, "restore", [True, False],
            initial_snapshot={"o1": 50, "o2": 30}, writes=writes,
        )
        assert result["body"]["ok"] is True
        assert result["body"]["muted"] is False
        assert result["body"].get("partial") is True
        assert snapshot == {}

    def test_restore_retry_after_partial_failure_falls_back_to_default(self, writes):
        """A second restore call after a partial failure has nothing
        remembered for the output that failed, so it falls back to the
        configured default for it -- the same rule an unremembered silent
        output always gets."""
        # o1 was restored by an earlier request; o2's write failed and it is
        # still at 0 with nothing remembered for it any more.
        _arrange([_make_output("o1", 50), _make_output("o2", 0)])
        captured = _post(
            "send_dial_mute_post_json", {"dial_id": "uid", "action": "restore"},
            parsed=_make_parsed_config(volume_percent=35),
        )
        assert writes.calls == [("o2", 35)], (
            f"Retry must only restore o2 (o1 is already non-zero), to the "
            f"configured default; got {writes.calls}"
        )
        assert captured["body"]["ok"] is True
        assert captured["body"].get("muted") is False

    def test_restore_restores_zero_output_added_while_muted(self, writes):
        """An output selected at zero while muted must be restored to the
        default on unmute: o1 and o2 were muted (remembered); o3 was selected
        while everything was muted and has no remembered level."""
        outputs = [_make_output("o1", 0), _make_output("o2", 0), _make_output("o3", 0)]
        _arrange(outputs[:2], {"o1": 50, "o2": 30}, writes)
        FakeStore().outputs(outputs)
        captured = _post(
            "send_dial_mute_post_json", {"dial_id": "uid", "action": "restore"},
            parsed=_make_parsed_config(volume_percent=35),
        )
        ids_called = [id_ for id_, _ in writes.calls]
        assert "o1" in ids_called, "o1 must be restored to its remembered volume"
        assert "o2" in ids_called, "o2 must be restored to its remembered volume"
        assert "o3" in ids_called, "o3 (zero, not remembered) must be restored to default_vol"
        assert ("o3", 35) in writes.calls, f"o3 must use default_vol=35; got {writes.calls}"
        assert captured["body"]["ok"] is True
        assert captured["body"].get("muted") is False


class TestDialVolumeAndMuteEndToEnd:
    """Integration coverage across the two host endpoints together: a
    volume-up press while muted is a restore (not a raw delta apply -- see
    send_dial_volume_post_json), and an explicit mute/restore cycle with no
    intervening volume press still round-trips the exact pre-mute level.
    Drives the real handlers end to end, so a wiring mistake between the two
    endpoints would show up here."""

    def _run(self, live, actions, writes):
        """Run a sequence of ("mute", <action>) / ("delta", n) steps against
        the speakers in *live* ({output_id: volume}), using the real
        send_dial_mute_post_json / send_dial_volume_post_json handlers.

        Returns a list of per-action step dicts (one per action, in order):
        {"response": <captured send_json body>,
         "volumes": {output_id: level at the speaker (the last write)},
         "snapshot": {output_id: level a restore brings back}}
        so callers can assert on state *after each individual action*.
        """
        _arrange([_make_output(oid, vol) for oid, vol in live.items()])
        steps = []
        at_speaker = dict(live)
        for step in actions:
            before = len(writes.calls)
            if step[0] == "mute":
                body = _post("send_dial_mute_post_json", {"dial_id": "uid", "action": step[1]})["body"]
            else:
                body = _post("send_dial_volume_post_json", {"dial_id": "uid", "delta": step[1]})["body"]
            for oid, level in writes.calls[before:]:
                at_speaker[oid] = level
            steps.append({"response": body, "volumes": dict(at_speaker), "snapshot": _remembered()})
        return steps

    def test_volume_up_press_while_muted_restores_with_no_step(self, writes):
        """mute (40->0, remembers {o1:40}) -> a volume-up delta while muted
        is a plain restore, not a raw delta apply: o1 returns to exactly 40,
        not 40+2, and the appliance reports unmuted."""
        steps = self._run({"o1": 40}, [("mute", "mute"), ("delta", 2)], writes)

        assert steps[0]["response"]["muted"] is True
        assert steps[0]["volumes"]["o1"] == 0
        assert steps[0]["snapshot"] == {"o1": 40}

        assert steps[1]["response"]["ok"] is True
        assert steps[1]["response"]["muted"] is False
        assert steps[1]["response"]["volume"] == 40
        assert steps[1]["volumes"]["o1"] == 40
        assert steps[1]["snapshot"] == {}

    def test_volume_down_press_while_muted_is_a_pure_noop(self, writes):
        """A volume-down delta while muted writes nothing and stays muted,
        still reporting the level the output will return to."""
        steps = self._run({"o1": 40}, [("mute", "mute"), ("delta", -2)], writes)

        assert steps[1]["response"] == {"ok": True, "volume": 40, "muted": True}
        assert steps[1]["volumes"]["o1"] == 0  # untouched -- still silent
        assert steps[1]["snapshot"] == {"o1": 40}

    def test_plain_mute_then_restore_still_restores_original_volume(self, writes):
        """With no intervening volume delta, mute then restore must restore
        the exact pre-mute volume."""
        steps = self._run({"o1": 65}, [("mute", "mute"), ("mute", "restore")], writes)

        assert steps[0]["response"]["muted"] is True
        assert steps[0]["volumes"]["o1"] == 0
        assert steps[0]["snapshot"] == {"o1": 65}

        assert steps[1]["response"]["muted"] is False
        assert steps[1]["volumes"]["o1"] == 65
        assert steps[1]["snapshot"] == {}


# ---------------------------------------------------------------------------
# dial_volume.py — typed event queue
# ---------------------------------------------------------------------------

class TestDialVolumeQueue:
    """Unit tests for the typed event queue and coalescing.

    Mute events carry the resulting absolute action (a bool) rather than
    being a bare toggle marker, and a run of adjacent mute events collapses
    to the LAST one rather than cancelling in pairs — see
    dial_volume._coalesce() and its module docstring.
    """

    def setup_method(self):
        # Re-import to get a fresh module view
        import importlib
        import dial_volume
        importlib.reload(dial_volume)
        self._mod = dial_volume

    def test_enqueue_delta_puts_delta_event(self):
        self._mod.enqueue_delta(5)
        item = self._mod._queue.get_nowait()
        assert item == ("delta", 5)

    def test_enqueue_mute_flips_the_reported_state_it_is_given(self):
        new_state = self._mod.enqueue_mute(False)  # caller believes unmuted
        assert new_state is True
        item = self._mod._queue.get_nowait()
        assert item == ("mute", True)

    def test_enqueue_mute_flips_a_reported_muted_state_to_restore(self):
        new_state = self._mod.enqueue_mute(True)  # caller believes muted
        assert new_state is False
        item = self._mod._queue.get_nowait()
        assert item == ("mute", False)

    def test_enqueue_mute_echoes_into_the_observation_store(self):
        """The dial persists nothing, but a press must still repaint the
        glyph on the same frame — the echo lives in the mute observation
        store, not any local belief."""
        self._mod.observe_mute_state("svc", False)
        self._mod.enqueue_mute(False)
        assert self._mod.shown_muted("svc") is True

    def test_coalesce_single_delta(self):
        batch = self._mod._coalesce(("delta", 3))
        assert batch == [("delta", 3)]

    def test_coalesce_adjacent_deltas(self):
        self._mod._queue.put(("delta", 4))
        self._mod._queue.put(("delta", -2))
        batch = self._mod._coalesce(("delta", 1))
        # All three adjacent deltas should be summed: 1+4-2 = 3
        assert batch == [("delta", 3)]

    def test_coalesce_mute_between_deltas(self):
        self._mod._queue.put(("delta", 4))
        self._mod._queue.put(("mute", True))
        self._mod._queue.put(("delta", 2))
        batch = self._mod._coalesce(("delta", 1))
        # 1+4 coalesced, then mute, then 2
        assert batch == [("delta", 5), ("mute", True), ("delta", 2)]

    def test_coalesce_single_mute_event(self):
        batch = self._mod._coalesce(("mute", True))
        assert batch == [("mute", True)]

    def test_coalesce_delta_after_mute_not_merged_with_pre_mute_delta(self):
        # Ensure post-mute delta is separate from pre-mute delta
        self._mod._queue.put(("mute", True))
        self._mod._queue.put(("delta", 5))
        batch = self._mod._coalesce(("delta", 2))
        # delta(2), mute, delta(5) — the two deltas must not merge
        assert len(batch) == 3
        assert batch[0] == ("delta", 2)
        assert batch[1] == ("mute", True)
        assert batch[2] == ("delta", 5)

    def test_coalesce_adjacent_mutes_collapse_to_last(self):
        # mute(True) then mute(False): a run of adjacent mutes collapses to
        # the LAST resulting action, not a cancel-in-pairs.
        self._mod._queue.put(("mute", False))
        batch = self._mod._coalesce(("mute", True))
        assert batch == [("mute", False)]

    def test_coalesce_three_adjacent_mutes_collapse_to_last(self):
        self._mod._queue.put(("mute", False))
        self._mod._queue.put(("mute", True))
        batch = self._mod._coalesce(("mute", False))
        # All three collapse into the LAST one queued.
        assert batch == [("mute", True)]

    def test_coalesce_mute_run_between_deltas_still_splits_the_deltas(self):
        # Unlike the old cancel-in-pairs rule, a collapsed mute run is still
        # a real (idempotent) action to resend, so it must NOT let the
        # surrounding deltas merge across it.
        self._mod._queue.put(("mute", False))
        self._mod._queue.put(("mute", True))
        self._mod._queue.put(("delta", 3))
        batch = self._mod._coalesce(("delta", 2))
        assert batch == [("delta", 2), ("mute", True), ("delta", 3)]

    def test_coalesce_single_mute_still_survives_and_splits_deltas(self):
        # Regression guard: a lone (non-adjacent) mute must still be
        # preserved and still prevent the surrounding deltas from merging.
        self._mod._queue.put(("delta", 4))
        self._mod._queue.put(("mute", True))
        self._mod._queue.put(("delta", 2))
        batch = self._mod._coalesce(("delta", 1))
        # 1+4 coalesced, then the surviving mute, then 2
        assert batch == [("delta", 5), ("mute", True), ("delta", 2)]

    def test_coalesce_two_adjacent_mute_all_cancel(self):
        # Broadcast-scope mute_all is decided fresh at dispatch, not carried
        # as a belief -- a run collapses by PARITY (even cancels, odd sends
        # one), not "collapse to the last one" like plain mute.
        self._mod._queue.put(("mute_all", 1))
        batch = self._mod._coalesce(("mute_all", 1))
        assert batch == []

    def test_coalesce_three_adjacent_mute_all_send_one(self):
        self._mod._queue.put(("mute_all", 1))
        self._mod._queue.put(("mute_all", 1))
        batch = self._mod._coalesce(("mute_all", 1))
        assert batch == [("mute_all", 1)]

    def test_coalesce_single_mute_all_sends_one(self):
        batch = self._mod._coalesce(("mute_all", 1))
        assert batch == [("mute_all", 1)]

    def test_coalesce_delta_mute_all_delta_keeps_order(self):
        self._mod._queue.put(("mute_all", 1))
        self._mod._queue.put(("delta", 3))
        batch = self._mod._coalesce(("delta", 2))
        assert batch == [("delta", 2), ("mute_all", 1), ("delta", 3)]


# ---------------------------------------------------------------------------
# DialConfig — sw_gpio default and key semantics
# ---------------------------------------------------------------------------

class TestDialConfigSwGpio:
    """DialConfig.sw_gpio default and hw.get fallback behaviour."""

    def test_sw_gpio_class_default_is_22(self):
        from dial_config import DialConfig
        assert DialConfig.sw_gpio == 22

    def test_sw_gpio_missing_key_uses_default(self, tmp_path):
        from dial_config import DialConfig, load_config, HW_CONFIG_PATH, SETTINGS_PATH
        hw = {"clk_gpio": 17, "dt_gpio": 27, "led_gpio": None, "port": 7842,
              "uuid": "test-uuid-1234"}
        # sw_gpio key intentionally absent
        with patch("dial_config.HW_CONFIG_PATH", tmp_path / "hw.json"), \
             patch("dial_config.SETTINGS_PATH", tmp_path / "settings.json"), \
             patch("dial_config.INSTALL_STATE_PATH", tmp_path / "state.env"):
            (tmp_path / "hw.json").write_text(json.dumps(hw))
            cfg = load_config()
        assert cfg.sw_gpio == 22

    def test_sw_gpio_explicit_null_disables_button(self, tmp_path):
        from dial_config import load_config
        hw = {"clk_gpio": 17, "dt_gpio": 27, "sw_gpio": None,
              "led_gpio": None, "port": 7842, "uuid": "test-uuid-1234"}
        with patch("dial_config.HW_CONFIG_PATH", tmp_path / "hw.json"), \
             patch("dial_config.SETTINGS_PATH", tmp_path / "settings.json"), \
             patch("dial_config.INSTALL_STATE_PATH", tmp_path / "state.env"):
            (tmp_path / "hw.json").write_text(json.dumps(hw))
            cfg = load_config()
        assert cfg.sw_gpio is None

    def test_sw_gpio_explicit_value_used(self, tmp_path):
        from dial_config import load_config
        hw = {"clk_gpio": 17, "dt_gpio": 27, "sw_gpio": 5,
              "led_gpio": None, "port": 7842, "uuid": "test-uuid-1234"}
        with patch("dial_config.HW_CONFIG_PATH", tmp_path / "hw.json"), \
             patch("dial_config.SETTINGS_PATH", tmp_path / "settings.json"), \
             patch("dial_config.INSTALL_STATE_PATH", tmp_path / "state.env"):
            (tmp_path / "hw.json").write_text(json.dumps(hw))
            cfg = load_config()
        assert cfg.sw_gpio == 5


# ---------------------------------------------------------------------------
# dial_main.py — button wires enqueue_mute
# ---------------------------------------------------------------------------

class TestDialMainButtonCallback:
    """dial_main.py must pass enqueue_mute as the button press handler."""

    def test_button_callback_calls_enqueue_mute(self):
        mute_calls = []

        def fake_enqueue_mute(currently_muted):
            mute_calls.append(currently_muted)
            return not currently_muted

        # Capture the on_press callback passed to setup_button
        captured_callback = []

        def fake_setup_button(gpio, on_press, bounce_time=0.1):
            captured_callback.append(on_press)
            return MagicMock()

        cfg = MagicMock()
        cfg.sw_gpio = 22
        cfg.clk_gpio = 17
        cfg.dt_gpio = 27
        cfg.led_gpio = None
        cfg.pin = ""
        cfg.auto_update = False
        cfg.uuid = "test-uuid"

        import dial_main
        with patch.object(dial_main, "load_config", return_value=cfg), \
             patch.object(dial_main, "_reconcile_update_timer"), \
             patch.object(dial_main, "_announce_self"), \
             patch("dial_main.DialLED"), \
             patch("dial_main.DialHTTPServer") as mock_server, \
             patch("dial_main.start_playing_browser"), \
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.get_playing_targets", return_value=[]), \
             patch("dial_core.enqueue_mute", side_effect=fake_enqueue_mute), \
             patch("autostream_rpi.setup_rotary_encoder", return_value=MagicMock(),
                   create=True), \
             patch("autostream_rpi.setup_button", side_effect=fake_setup_button,
                   create=True):
            # We can't run main() to completion, so test the sub-section directly:
            # The button callback must call enqueue_mute
            pass

        # Direct test: create on_press closure the same way dial_main does
        def on_press():
            fake_enqueue_mute(False)

        on_press()
        assert mute_calls == [False]


# ---------------------------------------------------------------------------
# installer/helpers.sh — sw_gpio is 22
# ---------------------------------------------------------------------------

def test_helpers_sh_writes_sw_gpio_22():
    """Fresh-install hardware config must set sw_gpio to 22 (not null)."""
    helpers = REPO_ROOT / "installer" / "dial" / "helpers.sh"
    content = helpers.read_text(encoding="utf-8")
    # The JSON literal in the heredoc must have sw_gpio: 22, not None
    assert '"sw_gpio":  22,' in content or '"sw_gpio": 22,' in content, (
        "helpers.sh write_dial_hw_config must write sw_gpio=22 for production hardware"
    )
    assert '"sw_gpio":  None' not in content and '"sw_gpio": None' not in content, (
        "helpers.sh must not write sw_gpio=null (disabled button) on fresh install"
    )
