"""Tests for tools/hd_page_preview.py: the script loader, the action-lead
table reaching a scenario change through the real HD action layer, and the
log never carrying a PIN."""
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
for _p in ("tests", "tools", "dial", "core"):
    if str(REPO_ROOT / _p) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT / _p))

import hd_page_preview as preview_tool
import hd_scenarios
from dial_hd_actions import ACTIONS, Context
from hd_fake_core import FakeCore

LOUNGE = hd_scenarios.LOUNGE


class Spy:
    """Stands in for HdPreview: records the scenarios it is asked to show."""

    def __init__(self) -> None:
        self.shown: list = []

    def show(self, scenario) -> None:
        self.shown.append(scenario.name)


def write_script(tmp_path, steps) -> Path:
    path = tmp_path / "script.json"
    path.write_text(json.dumps(steps), encoding="utf-8")
    return path


class TestLoadScript:
    def test_the_shipped_journey_loads(self):
        steps = preview_tool.load_script(REPO_ROOT / "tests" / "hd_scripts" / "journey.json")
        assert steps and all(name in hd_scenarios.SCENARIOS and delay >= 0 for delay, name in steps)

    def test_steps_come_back_as_delay_and_name(self, tmp_path):
        path = write_script(tmp_path, [[0, "nothing_playing"], ["1.5", "replaying"]])
        assert preview_tool.load_script(path) == [(0.0, "nothing_playing"), (1.5, "replaying")]

    @pytest.mark.parametrize("step", [
        [1, "no_such_scenario"], [-1, "replaying"], ["soon", "replaying"], [1], "replaying", None,
    ])
    def test_a_bad_step_is_refused(self, tmp_path, step):
        with pytest.raises(ValueError, match="bad script step"):
            preview_tool.load_script(write_script(tmp_path, [step]))

    @pytest.mark.parametrize("text", ["not json", "{}", "5"])
    def test_a_script_that_is_not_a_list_is_refused(self, tmp_path, text):
        path = tmp_path / "script.json"
        path.write_text(text, encoding="utf-8")
        with pytest.raises(ValueError, match="script is not"):
            preview_tool.load_script(path)


class TestActionHook:
    @pytest.mark.parametrize("action,scenario", [
        ("replay_start", "replaying"), ("replay_restart", "replaying"),
        ("replay_stop", "playing_artwork"),
    ])
    def test_an_action_that_leads_somewhere_shows_that_scenario(self, action, scenario):
        spy, core = Spy(), FakeCore(hd_scenarios.SCENARIOS["playing_artwork"].snapshot)
        core.on_call = preview_tool.action_hook(spy, lambda text: None)
        result = ACTIONS[action][1](Context(core), {"appliance_id": LOUNGE})
        assert result.accepted and spy.shown == [scenario]

    def test_an_action_that_leads_nowhere_changes_nothing(self):
        spy, core = Spy(), FakeCore(hd_scenarios.SCENARIOS["playing_artwork"].snapshot)
        core.on_call = preview_tool.action_hook(spy, lambda text: None)
        core.set_focus(LOUNGE)
        assert spy.shown == []

    def test_the_log_never_carries_a_pin(self):
        lines: list = []
        hook = preview_tool.action_hook(Spy(), lines.append)
        hook("set_output", (LOUNGE, "o1"), {"selected": True, "pin": "4821", "pin_entry": True})
        assert len(lines) == 1 and "set_output" in lines[0] and "o1" in lines[0]
        assert "4821" not in lines[0] and "'pin'" not in lines[0]
