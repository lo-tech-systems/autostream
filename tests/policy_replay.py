"""tests/policy_replay.py

Replays a recorded device-event scenario through the production event parser,
the output authority and the policy, and returns what the player was asked to
do. A scenario is a JSON file in tests/fixtures/policy:

    {
      "outputs": [ rows as the player lists them ],
      "settings": { the outputs part of the settings file },
      "owntone": { the owntone part of the settings file, e.g. include_tv },
      "session": true,
      "steps": [ {"at": seconds, one of the keys below}, ... ],
      "expect": { "writes": [...], "units": {...}, "silence_chosen": bool, "log": [...] }
    }

Step keys: "line" (an event channel message, parsed as production does and
delivered to the authority), "outputs" (replace the player's rows),
"user" ([intent name, arguments], submitted as the user), "session" (false
ends the session), "tick" (a worker step with nothing new). A row whose
session has "holdable": true is held when asked; any other is refused. Every step runs a
worker step at its time and then a read of the player. Times are seconds from
the start.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from types import SimpleNamespace

import autostream_live_config as live_config
import autostream_output_intents  # noqa: F401  (binds the output rows)
import autostream_output_policy
import autostream_runtime as runtime
from autostream_backend_events import parse_event
from autostream_intents.table import Intent, submit
from autostream_owntone_mini import OwnToneMiniBackend
from autostream_players import ActionResult
from autostream_settings import SettingsStore
from autostream_state import Origin, store
from autostream_state.outputs import get_authority
from output_fakes import FakeBackend

FIXTURES = Path(__file__).parent / "fixtures" / "policy"
T0 = 1000.0


def names() -> list:
    return sorted(p.stem for p in FIXTURES.glob("*.json"))


class _Collect(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.INFO)
        self.lines: list = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


def _rows(raw: list) -> list:
    parser = OwnToneMiniBackend(base_url="http://player.test:3689")
    return [parser._normalize_output_info(dict(r)) for r in raw]


class PlayerModel(FakeBackend):
    """A player that keeps the rows its writes lead to, so a later read agrees
    with what autostream asked for."""

    def __init__(self, authority, raw_rows: list) -> None:
        super().__init__(authority)
        self.raw = [dict(r) for r in raw_rows]
        self.on_update = self._apply_update
        self.rows = _rows(self.raw)

    def replace(self, raw_rows: list) -> None:
        self.raw = [dict(r) for r in raw_rows]
        self.rows = _rows(self.raw)

    def _apply_update(self, output_id, fields) -> None:
        for r in self.raw:
            if r["id"] != output_id:
                continue
            if "enabled" in fields:
                r["selected"] = bool(fields["enabled"])
                if not fields["enabled"] and isinstance(r.get("session"), dict):
                    # Switching a speaker off ends its session, and its hold
                    r["session"] = dict(r["session"], held=False)
            if fields.get("volume_percent") is not None:
                r["volume"] = fields["volume_percent"]
        self.rows = _rows(self.raw)

    def set_selected_outputs(self, ids, timeout):
        result = super().set_selected_outputs(ids, timeout)
        for r in self.raw:
            r["selected"] = r["id"] in ids
        self.rows = _rows(self.raw)
        return result

    def set_output_hold(self, output_id, held, timeout):
        """A row whose session says it can be held is held; any other is
        refused, as the player refuses it."""
        self._record("set_output_hold", output_id, held, timeout=timeout)
        for r in self.raw:
            if r["id"] != output_id:
                continue
            session = r.get("session")
            if not (isinstance(session, dict) and session.get("holdable")):
                return ActionResult(ok=False, error="not holdable", error_code="not_holdable")
            r["session"] = dict(session, held=bool(held))
        self.rows = _rows(self.raw)
        return ActionResult(ok=True)


def _writes(fb: FakeBackend) -> list:
    out = []
    for name, args, kwargs in fb.calls:
        if name == "update_output":
            fields = {k: v for k, v in kwargs.items() if k != "timeout"}
            out.append([name, args[0], fields])
        elif name == "set_selected_outputs":
            out.append([name, list(args[0])])
        elif name == "set_output_hold":
            out.append([name, args[0], args[1]])
        else:
            out.append([name])
    return out


def replay(name: str, tmp_path, monkeypatch) -> SimpleNamespace:
    scenario = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"outputs": scenario.get("settings", {}), "owntone": scenario.get("owntone", {})}),
        encoding="utf-8")
    settings = SettingsStore(str(config), _save_interval_seconds=9999, _writer=lambda p, d: None)
    live_config.bind_settings_store(settings)
    policy = autostream_output_policy.get_policy()
    policy.bind_settings(live_config.output_policy_settings)

    authority = get_authority()
    clock = [T0]
    monkeypatch.setattr(authority, "_clock", lambda: clock[0])
    fb = PlayerModel(authority, scenario["outputs"])
    authority.start(fb)
    authority.set_policy(policy)
    authority.set_include_tv_reader(live_config.include_tv_for)
    runtime.reset_for_tests()

    collect = _Collect()
    logger = logging.getLogger("autostream.output_policy")
    previous = logger.level
    logger.setLevel(logging.INFO)
    logger.addHandler(collect)
    try:
        authority.merge_for_tests(fb.rows, boot="b0", now=T0)
        if scenario.get("session"):
            authority.note_session(True)
        for step in scenario["steps"]:
            now = T0 + step["at"]
            clock[0] = now
            if "line" in step:
                ev = parse_event(step["line"], received=now)
                assert ev is not None, step
                authority.on_device_event(ev)
            if "outputs" in step:
                fb.replace(step["outputs"])
                authority.merge_for_tests(fb.rows, now=now)
            if "user" in step:
                intent, args = step["user"]
                reply = submit(Intent(intent, args, Origin.USER, "webui", context=SimpleNamespace(settings=settings)))
                assert reply.ok, (intent, reply.error)
            if step.get("session") is False:
                authority.note_session(False)
            authority.step(now=now)
            # The player is read after every step, as it would be soon after a write.
            authority.merge_for_tests(fb.rows, now=now)
    finally:
        logger.removeHandler(collect)
        logger.setLevel(previous)
        live_config.bind_settings_store(None)
        settings.close(save=False)

    snap = store().snapshot().outputs
    return SimpleNamespace(
        scenario=scenario,
        writes=_writes(fb),
        units={
            u.id: {"selected": u.selected, "muted": u.muted, "volume": u.volume, "held": u.held}
            for u in snap.units
        },
        silence_chosen=snap.silence_chosen,
        paused=list(policy.paused_units()),
        log=collect.lines,
        calls=fb.calls,
    )


def matches(expected: list, actual: list) -> bool:
    """The writes in order; a field list names only the fields to compare."""
    if len(expected) != len(actual):
        return False
    for want, got in zip(expected, actual):
        if want[:2] != got[:2]:
            return False
        if len(want) > 2:
            if isinstance(want[2], dict):
                if any(got[2].get(k) != v for k, v in want[2].items()):
                    return False
            elif want[2:] != got[2:]:
                return False
    return True
