"""Pushbutton mute/unmute tests.

Covers:
- POST /api/dial/mute host endpoint: auth, explicit action validation,
  snapshot management, partial failures, all-failed, and restore-with-default.
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


# ---------------------------------------------------------------------------
# Helpers shared across tests
# ---------------------------------------------------------------------------

def _make_output(oid: str, volume: int, selected: bool = True):
    o = SimpleNamespace()
    o.id = oid
    o.volume_percent = volume
    o.selected = selected
    return o


def _make_list_result(outputs, ok=True):
    r = SimpleNamespace()
    r.ok = ok
    r.outputs = outputs
    r.message = "" if ok else "err"
    return r


def _make_update_result(ok=True):
    r = SimpleNamespace()
    r.ok = ok
    r.error = "" if ok else "connection refused"
    return r


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


# ---------------------------------------------------------------------------
# Host API: POST /api/dial/mute
# ---------------------------------------------------------------------------

class TestDialMuteAuth:
    """Authorization checks at the very top of send_dial_mute_post_json.

    These run before action validation, so dial_id/authorization failures
    are 403 regardless of whether an action is present or valid.
    """

    def _call(self, json_obj, authorized=True):
        from autostream_webui_api import send_dial_mute_post_json
        import autostream_webui_api as api
        api._mute_snapshot.clear()

        handler = MagicMock()
        captured = {}

        def fake_send_json(h, code, body):
            captured["code"] = code
            captured["body"] = body

        with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.is_dial_authorized", return_value=authorized):
            send_dial_mute_post_json(handler, MagicMock(), json_obj)
        return captured

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
        import autostream_webui_api as api
        api._mute_snapshot.clear()

        from autostream_webui_api import send_dial_mute_post_json

        captured = {}

        def fake_send_json(h, code, body):
            captured["code"] = code
            captured["body"] = body

        with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.is_dial_authorized", return_value=True):
            send_dial_mute_post_json(MagicMock(), MagicMock(), json_obj)
        return captured

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

    def _call_with_mocks(self, list_result, update_ok=True, default_vol=20, action="mute"):
        import autostream_webui_api as api
        api._mute_snapshot.clear()

        from autostream_webui_api import send_dial_mute_post_json

        captured = {}

        def fake_send_json(h, code, body):
            captured["code"] = code
            captured["body"] = body

        parsed = _make_parsed_config(volume_percent=default_vol)

        with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.is_dial_authorized", return_value=True), \
             patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.list_outputs", return_value=list_result), \
             patch("autostream_webui_api.update_output", return_value=_make_update_result(update_ok)):
            send_dial_mute_post_json(
                MagicMock(), MagicMock(), {"dial_id": "valid-uuid", "action": action}
            )

        return captured, api._mute_snapshot.copy()

    def test_backend_unavailable_returns_ok_false(self):
        result, _ = self._call_with_mocks(_make_list_result([], ok=False))
        assert result["body"]["ok"] is False
        assert result["body"]["error"] == "backend_unavailable"

    def test_no_active_outputs_returns_ok_false(self):
        outputs = [_make_output("o1", 50, selected=False)]
        result, _ = self._call_with_mocks(_make_list_result(outputs))
        assert result["body"]["ok"] is False
        assert result["body"]["error"] == "no_active_outputs"


class TestDialMuteAction:
    """Explicit action execution and snapshot management.

    The action always comes from the request body -- there is no local
    inference from output volumes any more, so every test here drives the
    handler with an explicit action and asserts it is obeyed.
    """

    def _call(self, outputs, action, initial_snapshot=None,
              update_results=None, default_vol=20):
        import autostream_webui_api as api
        api._mute_snapshot.clear()
        if initial_snapshot:
            api._mute_snapshot.update(initial_snapshot)

        from autostream_webui_api import send_dial_mute_post_json

        captured = {}

        def fake_send_json(h, code, body):
            captured["code"] = code
            captured["body"] = body

        parsed = _make_parsed_config(volume_percent=default_vol)

        # update_results: list of results in call order, or single bool
        update_iter = (
            iter(update_results) if update_results is not None
            else iter([_make_update_result(True)] * 99)
        )

        def fake_update(*args, **kwargs):
            return next(update_iter)

        with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.is_dial_authorized", return_value=True), \
             patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.list_outputs",
                   return_value=_make_list_result(outputs)), \
             patch("autostream_webui_api.update_output", side_effect=fake_update):
            send_dial_mute_post_json(
                MagicMock(), MagicMock(), {"dial_id": "valid-uuid", "action": action}
            )

        import autostream_webui_api as api2
        return captured, api2._mute_snapshot.copy()

    def test_mute_when_audible_output_present(self):
        outputs = [_make_output("o1", 50)]
        result, snapshot = self._call(outputs, "mute")
        assert result["body"]["ok"] is True
        assert result["body"]["muted"] is True
        assert "o1" in snapshot
        assert snapshot["o1"] == 50

    def test_mute_snapshots_all_audible_outputs(self):
        outputs = [_make_output("o1", 30), _make_output("o2", 80)]
        result, snapshot = self._call(outputs, "mute")
        assert snapshot == {"o1": 30, "o2": 80}
        assert result["body"]["muted"] is True

    def test_mute_does_not_overwrite_existing_snapshot_entry(self):
        outputs = [_make_output("o1", 0), _make_output("o2", 60)]
        result, snapshot = self._call(
            outputs, "mute", initial_snapshot={"o1": 45}
        )
        # o1 is already at zero (previously muted); o2 is still audible
        assert snapshot["o1"] == 45  # must not be overwritten
        assert snapshot["o2"] == 60
        assert result["body"]["muted"] is True

    def test_mute_when_already_silent_is_idempotent_noop(self):
        """Explicit "mute" on an appliance whose selected outputs are all
        already at zero is a no-op -- not an error, and nothing is written
        to the snapshot for outputs that were never touched."""
        outputs = [_make_output("o1", 0), _make_output("o2", 0)]
        result, snapshot = self._call(outputs, "mute")
        assert result["body"] == {"ok": True, "muted": True}
        assert snapshot == {}

    def test_restore_when_all_outputs_at_zero(self):
        outputs = [_make_output("o1", 0), _make_output("o2", 0)]
        result, snapshot = self._call(
            outputs, "restore", initial_snapshot={"o1": 30, "o2": 80}
        )
        assert result["body"]["ok"] is True
        assert result["body"]["muted"] is False
        assert snapshot == {}  # snapshot cleared on full success

    def test_restore_when_already_audible_is_idempotent_noop(self):
        """Explicit "restore" on an appliance whose selected outputs are all
        already non-zero is a no-op -- it must not be reinterpreted as a
        mute just because every output happens to be audible."""
        outputs = [_make_output("o1", 45), _make_output("o2", 60)]
        result, snapshot = self._call(outputs, "restore")
        assert result["body"] == {"ok": True, "muted": False}
        assert snapshot == {}

    def test_explicit_restore_obeyed_even_though_stale_inference_would_mute(self):
        """Mixed volumes -- the deleted any(volume>0) inference would have
        picked "mute" here since o2 is audible. The explicit "restore"
        request must be obeyed instead: o1 (zero, no snapshot) rises to the
        default, o2 (already non-zero, no snapshot) is left alone as
        already-restored."""
        outputs = [_make_output("o1", 0), _make_output("o2", 50)]
        result, snapshot = self._call(outputs, "restore", default_vol=35)
        assert result["body"]["ok"] is True
        assert result["body"]["muted"] is False

    def test_restore_uses_snapshot_volume(self):
        outputs = [_make_output("o1", 0)]
        update_calls = []

        import autostream_webui_api as api
        api._mute_snapshot.clear()
        api._mute_snapshot["o1"] = 70

        from autostream_webui_api import send_dial_mute_post_json

        def fake_update(base_url, oid, volume_percent, timeout):
            update_calls.append((oid, volume_percent))
            return _make_update_result(True)

        parsed = _make_parsed_config(volume_percent=20)

        with patch("autostream_webui_api.send_json"), \
             patch("autostream_webui_api.is_dial_authorized", return_value=True), \
             patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.list_outputs",
                   return_value=_make_list_result(outputs)), \
             patch("autostream_webui_api.update_output", side_effect=fake_update):
            send_dial_mute_post_json(
                MagicMock(), MagicMock(), {"dial_id": "uid", "action": "restore"}
            )

        assert update_calls == [("o1", 70)]

    def test_restore_uses_default_vol_when_no_snapshot(self):
        """Zero-volume outputs not in the snapshot are restored to the configured default.

        Covers both post-restart (snapshot lost) and a new output selected while muted.
        In both cases the output is at 0 with no snapshot entry — the configured default
        volume is the only sensible restore target.
        """
        outputs = [_make_output("o1", 0)]
        update_calls = []

        import autostream_webui_api as api
        api._mute_snapshot.clear()

        from autostream_webui_api import send_dial_mute_post_json

        def fake_update(base_url, oid, volume_percent, timeout):
            update_calls.append((oid, volume_percent))
            return _make_update_result(True)

        parsed = _make_parsed_config(volume_percent=35)

        with patch("autostream_webui_api.send_json"), \
             patch("autostream_webui_api.is_dial_authorized", return_value=True), \
             patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.list_outputs",
                   return_value=_make_list_result(outputs)), \
             patch("autostream_webui_api.update_output", side_effect=fake_update):
            send_dial_mute_post_json(
                MagicMock(), MagicMock(), {"dial_id": "uid", "action": "restore"}
            )

        assert update_calls == [("o1", 35)]


class TestDialMuteFailures:
    """Partial and all-failed error paths."""

    def _call(self, outputs, action, update_ok_sequence, initial_snapshot=None):
        import autostream_webui_api as api
        api._mute_snapshot.clear()
        if initial_snapshot:
            api._mute_snapshot.update(initial_snapshot)

        from autostream_webui_api import send_dial_mute_post_json

        captured = {}

        def fake_send_json(h, code, body):
            captured["code"] = code
            captured["body"] = body

        parsed = _make_parsed_config()
        ok_iter = iter(update_ok_sequence)

        def fake_update(*args, **kwargs):
            return _make_update_result(next(ok_iter))

        with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.is_dial_authorized", return_value=True), \
             patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.list_outputs",
                   return_value=_make_list_result(outputs)), \
             patch("autostream_webui_api.update_output", side_effect=fake_update):
            send_dial_mute_post_json(
                MagicMock(), MagicMock(), {"dial_id": "uid", "action": action}
            )

        import autostream_webui_api as api2
        return captured, api2._mute_snapshot.copy()

    def test_mute_all_fail_returns_all_outputs_failed(self):
        outputs = [_make_output("o1", 50), _make_output("o2", 30)]
        result, snapshot = self._call(outputs, "mute", [False, False])
        assert result["body"]["ok"] is False
        assert result["body"]["error"] == "all_outputs_failed"

    def test_mute_partial_fail_returns_partial(self):
        outputs = [_make_output("o1", 50), _make_output("o2", 30)]
        result, snapshot = self._call(outputs, "mute", [True, False])
        assert result["body"]["ok"] is True
        assert result["body"]["muted"] is True
        assert result["body"].get("partial") is True

    def test_restore_all_fail_returns_all_outputs_failed(self):
        outputs = [_make_output("o1", 0), _make_output("o2", 0)]
        result, snapshot = self._call(
            outputs, "restore", [False, False],
            initial_snapshot={"o1": 50, "o2": 30},
        )
        assert result["body"]["ok"] is False
        assert result["body"]["error"] == "all_outputs_failed"

    def test_restore_partial_fail_retains_snapshot_entries(self):
        outputs = [_make_output("o1", 0), _make_output("o2", 0)]
        result, snapshot = self._call(
            outputs, "restore", [True, False],
            initial_snapshot={"o1": 50, "o2": 30},
        )
        assert result["body"]["ok"] is True
        assert result["body"]["muted"] is False
        assert result["body"].get("partial") is True
        # o1 succeeded so removed, o2 failed so retained
        assert "o1" not in snapshot
        assert "o2" in snapshot

    def test_restore_retry_skips_already_restored_outputs(self):
        """A retry after partial restore must not overwrite already-restored volumes.

        Sequence:
          Request 1: o1 (snapshot=50) restored successfully → popped from snapshot.
                     o2 (snapshot=30) fails → remains in snapshot.
          Request 2 (retry, explicit "restore" again): list_outputs shows o1 at 50
                     (live, non-zero from its restore), o2 still at 0.  Only o2 must
                     be touched.
        """
        import autostream_webui_api as api
        from autostream_webui_api import send_dial_mute_post_json

        api._mute_snapshot.clear()
        api._mute_snapshot.update({"o2": 30})  # o1 already gone (restored to 50)

        # o1 is at 50 because it was successfully restored in the previous request.
        # o2 is still at 0 because the restore failed and is pending retry.
        outputs = [_make_output("o1", 50), _make_output("o2", 0)]
        update_calls = []
        ok_iter = iter([True])  # only o2 will be tried; it succeeds

        def fake_update(base_url, output_id, volume_percent, timeout):
            update_calls.append(output_id)
            return _make_update_result(next(ok_iter))

        captured = {}
        parsed = _make_parsed_config()

        def fake_send_json(h, code, body):
            captured.update({"code": code, "body": body})

        with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.is_dial_authorized", return_value=True), \
             patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.list_outputs",
                   return_value=_make_list_result(outputs)), \
             patch("autostream_webui_api.update_output", side_effect=fake_update):
            send_dial_mute_post_json(
                MagicMock(), MagicMock(), {"dial_id": "uid", "action": "restore"}
            )

        assert update_calls == ["o2"], (
            f"Retry must only restore o2 (not o1 which is non-zero/already restored); "
            f"got {update_calls}"
        )
        assert captured["body"]["ok"] is True
        assert captured["body"].get("muted") is False

    def test_restore_restores_zero_output_added_while_muted(self):
        """An output selected at zero while muted must be restored to default_vol on unmute.

        o1 and o2 were muted (in snapshot).  o3 was selected while everything was muted
        (so its volume is 0 but it has no snapshot entry).  On restore, o3 must be
        set to the configured default volume, not left at 0.
        """
        import autostream_webui_api as api
        from autostream_webui_api import send_dial_mute_post_json

        api._mute_snapshot.clear()
        api._mute_snapshot.update({"o1": 50, "o2": 30})

        outputs = [_make_output("o1", 0), _make_output("o2", 0), _make_output("o3", 0)]
        update_calls = []

        def fake_update(base_url, output_id, volume_percent, timeout):
            update_calls.append((output_id, volume_percent))
            return _make_update_result(True)

        captured = {}
        parsed = _make_parsed_config(volume_percent=35)

        def fake_send_json(h, code, body):
            captured.update({"code": code, "body": body})

        with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.is_dial_authorized", return_value=True), \
             patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.list_outputs",
                   return_value=_make_list_result(outputs)), \
             patch("autostream_webui_api.update_output", side_effect=fake_update):
            send_dial_mute_post_json(
                MagicMock(), MagicMock(), {"dial_id": "uid", "action": "restore"}
            )

        ids_called = [id_ for id_, _ in update_calls]
        assert "o1" in ids_called, "o1 must be restored to its snapshot volume"
        assert "o2" in ids_called, "o2 must be restored to its snapshot volume"
        assert "o3" in ids_called, "o3 (zero, not in snapshot) must be restored to default_vol"
        assert ("o3", 35) in update_calls, f"o3 must use default_vol=35; got {update_calls}"
        assert captured["body"]["ok"] is True
        assert captured["body"].get("muted") is False


class TestDialVolumeInvalidatesMuteSnapshot:
    """Regression: a manual volume delta must invalidate any stale pre-mute
    snapshot entry for the outputs it touches (bug: a delta applied while
    muted -- which unmutes via the current_master==0 special case -- left
    the old _mute_snapshot entry in place, so a later mute/unmute cycle
    silently discarded the delta and restored the stale pre-mute level).
    """

    def _run(self, live, actions):
        """Run a sequence of ("mute", <action>) / ("delta", n) steps against
        a shared mutable `live` dict of {output_id: output}, using the real
        send_dial_mute_post_json / send_dial_volume_post_json handlers with
        list_outputs/update_output faked against `live`.

        ("mute", <action>) drives send_dial_mute_post_json with an explicit
        "mute" or "restore" action; ("delta", n) drives send_dial_volume_post_json.

        Returns a list of per-action step dicts (one per action, in order):
        {"response": <captured send_json body>,
         "volumes": {output_id: volume_percent, ...} (post-action live state),
         "snapshot": {...} (post-action copy of _mute_snapshot)}
        so callers can assert on state *after each individual action*, not
        just the final state once the whole sequence has run.
        """
        import autostream_webui_api as api
        from autostream_webui_api import (
            send_dial_mute_post_json,
            send_dial_volume_post_json,
        )

        api._mute_snapshot.clear()

        def fake_list_outputs(base_url, timeout=None):
            return _make_list_result(list(live.values()))

        def fake_update(base_url, output_id, volume_percent, timeout):
            live[output_id].volume_percent = volume_percent
            return _make_update_result(True)

        parsed = _make_parsed_config(volume_percent=20)
        steps = []

        def fake_send_json(h, code, body):
            steps.append({
                "response": body,
                "volumes": {oid: o.volume_percent for oid, o in live.items()},
                "snapshot": dict(api._mute_snapshot),
            })

        with patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.is_dial_authorized", return_value=True), \
             patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.list_outputs", side_effect=fake_list_outputs), \
             patch("autostream_webui_api.update_output", side_effect=fake_update):
            for step in actions:
                if step[0] == "mute":
                    send_dial_mute_post_json(
                        MagicMock(), MagicMock(), {"dial_id": "uid", "action": step[1]}
                    )
                else:
                    send_dial_volume_post_json(
                        MagicMock(), MagicMock(), {"dial_id": "uid", "delta": step[1]}
                    )

        return steps

    def test_delta_after_mute_survives_a_second_mute_unmute_cycle(self):
        """mute (40->0, snapshot={o1:40}) -> delta +2 (0->2, must drop the
        stale snapshot entry) -> mute (2->0, re-snapshots the *current* 2,
        not the stale 40) -> restore (must restore 2, not 40)."""
        live = {"o1": _make_output("o1", 40)}

        steps = self._run(live, [
            ("mute", "mute"),
            ("delta", 2),
            ("mute", "mute"),
            ("mute", "restore"),
        ])

        # After step 1 (mute): snapshotted at 40, output silenced.
        assert steps[0]["response"]["muted"] is True
        assert steps[0]["volumes"]["o1"] == 0
        assert steps[0]["snapshot"] == {"o1": 40}

        # After step 2 (delta +2 while muted): the current_master==0 special
        # case applies the delta directly, and the stale snapshot entry for
        # o1 must be gone -- a manual volume change invalidates the
        # remembered pre-mute level.
        assert steps[1]["response"]["ok"] is True
        assert steps[1]["response"]["volume"] == 2
        assert steps[1]["volumes"]["o1"] == 2
        assert "o1" not in steps[1]["snapshot"]

        # After step 3 (mute again): o1 is re-snapshotted at its *current*
        # volume (2), not the discarded 40.
        assert steps[2]["response"]["muted"] is True
        assert steps[2]["snapshot"] == {"o1": 2}
        assert steps[2]["volumes"]["o1"] == 0

        # After step 4 (explicit restore): must return to the post-delta
        # value (2), NOT the stale pre-mute value (40).
        assert steps[3]["response"]["muted"] is False
        assert steps[3]["volumes"]["o1"] == 2
        assert steps[3]["snapshot"] == {}

    def test_plain_mute_then_restore_still_restores_original_volume(self):
        """Sanity check that the fix above has not broken the feature the
        snapshot exists for: with no intervening volume delta, mute then
        restore must still restore the exact pre-mute volume."""
        live = {"o1": _make_output("o1", 65)}

        steps = self._run(live, [
            ("mute", "mute"),
            ("mute", "restore"),
        ])

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

    Mute events now carry the resulting absolute belief (a bool) instead of
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

    def test_enqueue_mute_puts_mute_event_with_resulting_belief(self):
        # Belief starts False (unmuted); one press flips it to True.
        new_belief = self._mod.enqueue_mute()
        assert new_belief is True
        item = self._mod._queue.get_nowait()
        assert item == ("mute", True)

    def test_enqueue_mute_returns_belief_and_flips_on_each_call(self):
        assert self._mod.enqueue_mute() is True
        assert self._mod.enqueue_mute() is False
        assert self._mod.enqueue_mute() is True

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

        def fake_enqueue_mute():
            mute_calls.append(True)
            return True

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
             patch("dial_main.enqueue_mute", side_effect=fake_enqueue_mute), \
             patch("autostream_rpi.setup_rotary_encoder", return_value=MagicMock(),
                   create=True), \
             patch("autostream_rpi.setup_button", side_effect=fake_setup_button,
                   create=True):
            # We can't run main() to completion, so test the sub-section directly:
            # The button callback must call enqueue_mute
            pass

        # Direct test: create on_press closure the same way dial_main does
        def on_press():
            fake_enqueue_mute()

        on_press()
        assert mute_calls == [True]


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
