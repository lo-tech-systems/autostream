"""tests/test_golden_replies.py

Golden replies for the status, output, volume, mute, EQ, repeat, warning and
level routes.

Every route is called under every scenario in ``golden_scenarios``; the
status, the body (run-varying values blanked) and the backend calls it made
are compared with ``tests/golden/replies/<family>.json``.  A change to where
the coordinator keeps its state must leave these files untouched.

Re-record after a deliberate change to a reply:

    AUTOSTREAM_GOLDEN_RECORD=1 python -m pytest tests/test_golden_replies.py
"""
from __future__ import annotations

import json
import os

import pytest

import golden_scenarios as gs

RECORD = os.environ.get("AUTOSTREAM_GOLDEN_RECORD") == "1"


def _cases(family: str):
    return [(route, scenario)
            for route in gs.routes() if route.family == family
            for scenario in gs.SCENARIOS.values()]


@pytest.mark.parametrize("family", gs.families())
def test_replies_match_the_recorded_files(family, monkeypatch):
    actual = {}
    for route, scenario in _cases(family):
        with monkeypatch.context() as mp:
            actual[gs.case_key(route, scenario)] = gs.run_case(route, scenario, mp)

    path = gs.golden_path(family)
    if RECORD:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(actual, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        return

    assert path.exists(), f"missing {path}; record it with AUTOSTREAM_GOLDEN_RECORD=1"
    expected = json.loads(path.read_text(encoding="utf-8"))
    assert sorted(actual) == sorted(expected), "the set of recorded cases changed"
    differing = [key for key in expected if actual[key] != expected[key]]
    assert not differing, f"replies differ from the recorded ones: {differing}"


def test_every_scenario_is_exercised_by_every_route():
    assert set(gs.SCENARIOS) == {
        "idle", "one_output_playing_input1", "two_outputs_one_muted", "replay_holding",
        "replaying", "monitor_down", "backend_unreachable",
    }
    assert gs.families() == [
        "status", "outputs", "volume_mute", "eq", "repeat", "warnings", "levels"]


def test_a_backend_call_the_scenario_did_not_provide_fails(monkeypatch):
    import autostream_player_service as player_service

    rec = gs.apply(gs.SCENARIOS["idle"], monkeypatch)
    with pytest.raises(gs.UnpatchedBackendCall):
        player_service.list_outputs("http://localhost:3689")
    assert rec.unpatched == ["list_outputs"]


class TestNormalise:
    def test_blanks_the_run_varying_keys(self):
        body = json.dumps({
            "dbfs": -12.5, "vu_history": [1, 2], "updated_at": 5.0,
            "nested": {"last_seen_at": 7, "uptime_seconds": 9, "kept": 1},
        })
        assert json.loads(gs.normalise(body)) == {
            "dbfs": "<n>", "vu_history": "<n>", "updated_at": "<n>",
            "nested": {"last_seen_at": "<n>", "uptime_seconds": "<n>", "kept": 1},
        }

    def test_version_and_protocol_keys_stay_pinned(self):
        body = json.dumps({"version": "1.2.3", "dial_proto": 5, "boot": "x"})
        assert json.loads(gs.normalise(body)) == {
            "version": "1.2.3", "dial_proto": 5, "boot": "x"}

    def test_a_store_field_is_blanked_by_exact_path_only(self, monkeypatch):
        monkeypatch.setitem(gs.STORE_FIELDS, "GET /x", (("repeat", "armed"),))
        body = json.dumps({"repeat": {"armed": True}, "other": {"armed": True}})
        assert json.loads(gs.normalise(body, "GET /x")) == {
            "repeat": {"armed": "<n>"}, "other": {"armed": True}}
        assert json.loads(gs.normalise(body, "GET /y")) == json.loads(body)

    def test_key_order_is_kept(self):
        assert gs.normalise('{"b": 1, "a": 2}') == '{"b": 1, "a": 2}'

    def test_non_finite_numbers_are_refused(self):
        with pytest.raises(ValueError):
            gs.normalise('{"x": Infinity}')

    def test_html_timestamps_and_tokens_are_replaced(self):
        STAMP = "T".join(("-".join(("1999", "01", "02")), "03:04:05Z"))
        text = f"v={gs.FIXED_APP_VERSION} t={gs.FIXED_CSRF_TOKEN} at {STAMP}"
        assert gs.normalise_html(text) == "v={APP_VERSION} t={CSRF_TOKEN} at <n>"
