"""tests/golden_scenarios.py

Scenario data and a driver for the golden reply tests.

A scenario describes what the coordinator knows (session, repeat block,
inputs, outputs, track, mute) and what the backends answer.  ``apply`` puts
that into the seams the request handlers read, ``run_case`` calls one handler
through a fake HTTP handler and returns what went out on the wire, and
``normalise`` blanks the values that legitimately change from run to run.

Any backend call a scenario does not provide fails the test: the default
``list_outputs``, ``get_setting`` and ``update_output`` raise an exception
that the handlers' own ``except Exception`` clauses cannot swallow, and the
call is also recorded in ``Recorder.unpatched``.
"""
from __future__ import annotations

import contextlib
import dataclasses
import functools
import io
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Optional
from unittest.mock import MagicMock

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

FIXED_APP_VERSION = "1.0.0-golden"
FIXED_CSRF_TOKEN = "golden-csrf-token"
DIAL_ID = "dial-a"
APPLIANCE_ID = "a" * 20
PEER_IP = "192.0.2.10"
START_BUFFER_MS = 2250


class UnpatchedBackendCall(BaseException):
    """A handler reached a backend call the scenario did not provide.

    Derives from BaseException so that no ``except Exception`` in a handler
    can turn it into an ordinary error reply.
    """


# ---------------------------------------------------------------------------
# Scenario data
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Scenario:
    id: str
    session: dict
    repeat: Optional[dict]
    levels: tuple
    monitor_connected: bool
    selfheal: dict
    # None means list_outputs reports not ok.
    outputs: Optional[tuple]
    # True means get_setting raises.
    setting_raises: bool
    track: Any
    source_input: Optional[int]
    playback: Any
    # Output id -> remembered level, begun through the real mute state.
    muted_levels: Optional[dict] = None
    throttled: Optional[int] = None
    eq_status: Optional[dict] = None
    monitor_reachable: bool = True


def _output(out_id: str, name: str, volume: int, selected: bool):
    from autostream_players import OutputInfo
    return OutputInfo(id=out_id, name=name, selected=selected, volume_percent=volume)


def _level(index: int, dbfs: float, above: bool) -> dict:
    return {
        "index": index,
        "label": f"Input {index}",
        "dbfs": dbfs,
        "detected_hz": 44100.0,
        "detected_khz": "44.1 kHz",
        "negotiated_hz": 44100,
        "rate_lock": "locked",
        "relock_count": 0,
        "rate_mismatch_hz": 0,
        "rate_mismatch_khz": "",
        "dynamic_rate_matching": True,
        "monitor_supports_rate_matching": True,
        "is_above_threshold": above,
        "vu_history": [-60.0, -59.5, -61.0],
    }


def _playback(*, stylus_warning: bool = False):
    from autostream_playback_stats import PlaybackSnapshot, make_fallback_input_snapshot

    one = make_fallback_input_snapshot(
        1, "Input 1", is_turntable=True, stylus_life_hours=1000, input_type="turntable")
    two = make_fallback_input_snapshot(2, "Input 2", input_type="cd")
    if stylus_warning:
        one = dataclasses.replace(
            one, stylus_warning=True, stylus_playback_seconds=950 * 3600,
            stylus_playback_hours=950.0, stylus_remaining_seconds=50 * 3600,
            stylus_remaining_hours=50.0)
    text = "Stylus due for replacement soon" if stylus_warning else None
    return PlaybackSnapshot(
        inputs={1: one, 2: two},
        stylus_warning_indices=(1,) if stylus_warning else (),
        stylus_overdue_indices=(),
        stylus_banner_text=text,
        belt_warning_indices=(), belt_overdue_indices=(), belt_banner_text=None,
        bearing_warning_indices=(), bearing_overdue_indices=(), bearing_banner_text=None,
    )


def _track(state: str = "disabled", **fields):
    from track_id.models import TrackIdentificationSnapshot, state_status_text
    return TrackIdentificationSnapshot(
        enabled=state != "disabled", state=state,
        status_text=state_status_text(state), **fields)


def _selfheal(**fields) -> dict:
    base = {
        "reconcile_fired_count": 0,
        "reconcile_last_fired_at": 0.0,
        "watchdog_armed": False,
        "watchdog_restart_count": 0,
        "watchdog_last_restart_at": 0.0,
    }
    base.update(fields)
    return base


def _repeat(*, armed: bool, recording_seconds: float = 0.0, replay_active: bool = False,
            position: float = 0.0, duration: float = 0.0) -> dict:
    return {
        "enabled": True,
        "armed": armed,
        "recording": {"active": False, "seconds": recording_seconds, "origin_input": 1},
        "replay": {
            "active": replay_active, "fading_out": False,
            "position_seconds": position, "duration_seconds": duration,
        },
    }


_IDLE_SESSION = {"active": False, "source": None}

_TWO_OUTPUTS = (
    _output("1001", "Speaker A", 40, True),
    _output("1002", "Speaker B", 60, True),
)
_TWO_DESELECTED = (
    _output("1001", "Speaker A", 40, False),
    _output("1002", "Speaker B", 60, False),
)

SCENARIOS: dict[str, Scenario] = {s.id: s for s in (
    Scenario(
        id="idle",
        session=dict(_IDLE_SESSION),
        repeat=_repeat(armed=False),
        levels=(_level(1, -80.0, False), _level(2, -80.0, False)),
        monitor_connected=True,
        selfheal=_selfheal(),
        outputs=_TWO_DESELECTED,
        setting_raises=False,
        track=_track("disabled"),
        source_input=None,
        playback=_playback(),
        eq_status={"output_auto_trim_enabled": False, "output_auto_trim_db": 0.0,
                   "effective_output_gain_db": 0.0},
    ),
    Scenario(
        id="one_output_playing_input1",
        session={"active": True, "source": "input1"},
        repeat=_repeat(armed=True),
        levels=(_level(1, -18.5, True), _level(2, -80.0, False)),
        monitor_connected=True,
        selfheal=_selfheal(reconcile_fired_count=1, reconcile_last_fired_at=1000.0),
        outputs=(
            _output("1001", "Speaker A", 40, True),
            _output("1002", "Speaker B", 60, False),
        ),
        setting_raises=False,
        track=_track(
            "identified", input_index=1, provider="provider-x", title="Example Title",
            artist="Example Artist", album="Example Album",
            artwork_url="https://example.invalid/art/cover.jpg",
            confidence=0.93, updated_at=1000.0, last_attempt_at=990.0),
        source_input=1,
        playback=_playback(),
        eq_status={"output_auto_trim_enabled": True, "output_auto_trim_db": -1.5,
                   "effective_output_gain_db": -1.5},
    ),
    Scenario(
        id="two_outputs_one_muted",
        session={"active": True, "source": "input1"},
        repeat=_repeat(armed=True),
        levels=(_level(1, -22.0, True), _level(2, -80.0, False)),
        monitor_connected=True,
        selfheal=_selfheal(),
        # Muted: the appliance has silenced both selected outputs and
        # remembers the levels they return to.
        outputs=(
            _output("1001", "Speaker A", 0, True),
            _output("1002", "Speaker B", 0, True),
        ),
        setting_raises=False,
        track=_track("analysing", input_index=1),
        source_input=1,
        playback=_playback(stylus_warning=True),
        muted_levels={"1001": 40, "1002": 60},
        eq_status={"output_auto_trim_enabled": False, "output_auto_trim_db": 0.0,
                   "effective_output_gain_db": 0.0},
    ),
    Scenario(
        id="replay_holding",
        session=dict(_IDLE_SESSION),
        repeat=_repeat(armed=True, recording_seconds=1260.0),
        levels=(_level(1, -80.0, False), _level(2, -80.0, False)),
        monitor_connected=True,
        selfheal=_selfheal(),
        outputs=_TWO_DESELECTED,
        setting_raises=False,
        track=_track("disabled"),
        source_input=None,
        playback=_playback(),
        eq_status={"output_auto_trim_enabled": False, "output_auto_trim_db": 0.0,
                   "effective_output_gain_db": 0.0},
    ),
    Scenario(
        id="replaying",
        session={"active": True, "source": "replay"},
        repeat=_repeat(armed=True, recording_seconds=1260.0, replay_active=True,
                       position=312.5, duration=1260.0),
        levels=(_level(1, -80.0, False), _level(2, -80.0, False)),
        monitor_connected=True,
        selfheal=_selfheal(),
        outputs=(
            _output("1001", "Speaker A", 40, True),
            _output("1002", "Speaker B", 60, False),
        ),
        setting_raises=False,
        track=_track(
            "identified", input_index=1, provider="provider-x", title="Example Title",
            artist="Example Artist", album="Example Album",
            artwork_url="https://example.invalid/art/cover.jpg",
            confidence=0.93, updated_at=1000.0, last_attempt_at=990.0),
        source_input=1,
        playback=_playback(),
        throttled=0x1,
        eq_status={"output_auto_trim_enabled": False, "output_auto_trim_db": 0.0,
                   "effective_output_gain_db": 0.0},
    ),
    Scenario(
        id="monitor_down",
        session=dict(_IDLE_SESSION),
        repeat=None,
        levels=(),
        monitor_connected=False,
        selfheal=_selfheal(watchdog_armed=True, watchdog_restart_count=1,
                           watchdog_last_restart_at=float("-inf")),
        outputs=_TWO_DESELECTED,
        setting_raises=False,
        track=_track("disabled"),
        source_input=None,
        playback=_playback(),
        eq_status=None,
        monitor_reachable=False,
    ),
    Scenario(
        id="backend_unreachable",
        session=dict(_IDLE_SESSION),
        repeat=_repeat(armed=False),
        levels=(_level(1, -80.0, False), _level(2, -80.0, False)),
        monitor_connected=True,
        selfheal=_selfheal(),
        outputs=None,
        setting_raises=True,
        track=_track("disabled"),
        source_input=None,
        playback=_playback(),
        eq_status={"output_auto_trim_enabled": False, "output_auto_trim_db": 0.0,
                   "effective_output_gain_db": 0.0},
    ),
)}


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeHandler:
    """Just enough of an HTTP request handler for the response helpers."""

    def __init__(self) -> None:
        self.status: Optional[int] = None
        self.headers_sent: list[tuple[str, str]] = []
        self.wfile = io.BytesIO()
        self._csrf_token = FIXED_CSRF_TOKEN
        self._pending_set_cookies: list = []
        self.headers: dict = {}

    def send_response(self, code, message=None) -> None:
        self.status = code

    def send_header(self, name, value) -> None:
        self.headers_sent.append((name, value))

    def end_headers(self) -> None:
        pass

    def body(self) -> str:
        return self.wfile.getvalue().decode("utf-8")


@dataclass
class Recorder:
    calls: list = field(default_factory=list)
    unpatched: list = field(default_factory=list)


class FakeMonitorClient:
    """Answers the repeat commands the way the daemon would for the scenario."""

    def __init__(self, scenario: Scenario, recorder: Recorder) -> None:
        self._s = scenario
        self._rec = recorder

    def _state(self) -> str:
        block = self._s.repeat or {}
        rep = block.get("replay") or {}
        rec = block.get("recording") or {}
        if rep.get("active"):
            return "replaying"
        if (rec.get("seconds") or 0) > 0:
            return "hold"
        return "idle"

    def _armed(self) -> bool:
        return bool((self._s.repeat or {}).get("armed"))

    def _unavailable(self) -> Optional[dict]:
        if not (self._s.repeat or {}).get("enabled"):
            return {"ok": False, "error": "repeat_unavailable"}
        return None

    def repeat_stop(self) -> dict:
        self._rec.calls.append(["monitor", "repeat_stop"])
        return self._unavailable() or {
            "ok": True, "command": "repeat_stop", "state": "idle", "armed": self._armed()}

    def repeat_seek(self, position_seconds: float) -> dict:
        self._rec.calls.append(["monitor", "repeat_seek", float(position_seconds)])
        refused = self._unavailable()
        if refused:
            return refused
        if self._s.session.get("source", "") not in (None, "replay"):
            return {"ok": False, "error": "source_active", "state": self._state(),
                    "armed": self._armed()}
        if self._state() == "idle":
            return {"ok": False, "error": "no_recording", "state": "idle",
                    "armed": self._armed()}
        return {"ok": True, "command": "repeat_seek", "state": "replaying",
                "armed": self._armed(), "position_seconds": float(position_seconds)}

    def set_repeat_armed_ack(self, armed: bool) -> dict:
        self._rec.calls.append(["monitor", "set_repeat_armed", bool(armed)])
        return self._unavailable() or {
            "ok": True, "command": "set_repeat_armed", "state": self._state(),
            "armed": bool(armed)}


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def parsed_config():
    """The typed configuration every handler sees: two inputs, one default output."""
    from autostream_config import parse_config
    return parse_config({
        "audio1": {"enabled": True, "input_type": "turntable"},
        "audio2": {"enabled": True, "input_type": "cd"},
        "owntone": {"output_name": "Speaker A", "volume_percent": 20},
        "output_eq": {"gain_db": 1.0, "peq1_db": 2.0, "peq6_db": -3.0},
    }, high_perf=False)


def _unpatched(recorder: Recorder, name: str) -> Callable:
    def fn(*args, **kwargs):
        recorder.unpatched.append(name)
        raise UnpatchedBackendCall(name)
    return fn


def apply(scenario: Scenario, monkeypatch) -> Recorder:
    """Install *scenario* into every seam the golden routes read; return the recorder."""
    import autostream_appliance_models as models
    import autostream_monitor_client as monitor_client
    import autostream_federation as federation
    import autostream_player_service as player_service
    import autostream_repeat
    import autostream_state as state
    import autostream_start_buffer_cache as start_buffer_cache
    import autostream_system_stats as system_stats
    import autostream_webui_api as api
    import autostream_webui_page_airplay as airplay
    from autostream_dials import AUTH_AUTHORIZED
    from autostream_players import ActionResult
    from autostream_state.outputs import get_authority
    from fake_store import FakeStore, fake_track

    rec = Recorder()
    cfg = parsed_config()
    # Each case starts from an authority that has adopted nothing.
    get_authority().reset_for_tests()

    def get_setting(base_url, key, timeout=None):
        if scenario.setting_raises:
            raise OSError("connection refused")
        return SimpleNamespace(ok=True, value=str(START_BUFFER_MS))

    def update_output(base_url, out_id, **kwargs):
        rec.calls.append(["update_output", out_id, kwargs.get("volume_percent")])
        return ActionResult(ok=True)

    levels = [dict(lv) for lv in scenario.levels]
    fake = FakeStore()
    # The readers take the output list from the authority's snapshot.
    if scenario.outputs is None:
        fake.outputs_unreachable()
    elif scenario.muted_levels:
        _begin_mute(scenario, fake, monkeypatch)
    else:
        fake.outputs(list(scenario.outputs))
    fake.monitor(monitor_build="golden", log_level="info",
                 connected=scenario.monitor_connected, last_seen_at=1000.0)
    fake.health(**scenario.selfheal)
    fake.session(scenario.session.get("active"), scenario.session.get("source"))
    fake.repeat(scenario.repeat)
    fake.playback(scenario.playback)
    sample_rate_text = "Sample rate: 44.1 kHz"
    rate_note = state.RATE_MATCHING_NOTE_DEFAULT

    running = scenario.monitor_connected and bool(levels)
    fake.inputs([
        fake.input_entry(
            lv["index"], rate_note=rate_note,
            sample_rate_text=(
                sample_rate_text if running else state.SAMPLE_RATE_TEXT_NOT_RUNNING),
            **{k: v for k, v in lv.items() if k != "index"})
        for lv in levels
    ])
    fake_track(scenario.track)

    @contextlib.contextmanager
    def connected_monitor(socket_path=None):
        yield FakeMonitorClient(scenario, rec) if scenario.monitor_reachable else None

    def setattrs(module, **values) -> None:
        for name, value in values.items():
            monkeypatch.setattr(module, name, value)

    shared = dict(
        get_appliance_id=lambda: APPLIANCE_ID,
        get_app_version=lambda: FIXED_APP_VERSION,
        _dial_update_banner_text=lambda: "",
    )
    setattrs(api, **shared,
             dial_authorization=lambda dial_id: AUTH_AUTHORIZED,
             dial_speaks_v2=lambda dial_id: True,
             _config_snapshot=lambda state: cfg,
             get_live_output_eq_status=lambda: scenario.eq_status)
    setattrs(models, **{k: v for k, v in shared.items() if k not in ("get_app_version", "list_outputs")},
             get_app_version=lambda: FIXED_APP_VERSION,
             get_setting=get_setting,
             get_system_hostname=lambda: "golden.local",
             get_live_output_eq_status=lambda: scenario.eq_status,
             locked_load_config=lambda path: {
                 "audio1": {"enabled": True, "input_type": "turntable"},
                 "audio2": {"enabled": True, "input_type": "cd"},
                 "owntone": {"output_name": "Speaker A", "volume_percent": 20},
                 "output_eq": {"gain_db": 1.0, "peq1_db": 2.0, "peq6_db": -3.0},
             },
             parse_config=functools.partial(_parse_without_hardware_probe))
    setattrs(airplay, **{k: v for k, v in shared.items()
                         if k in ("get_appliance_id", "_dial_update_banner_text")},
             get_app_version=lambda: FIXED_APP_VERSION,
             _config_snapshot=lambda state: cfg,
             get_setting=get_setting,
             get_all_appliances=lambda: [],
             get_system_hostname=lambda: "golden.local",
             build_top_banner_html=lambda **kwargs: ("", ""))
    setattrs(autostream_repeat, apply_repeat_ack=lambda ack: ack)
    setattrs(monitor_client, _connected_monitor=connected_monitor)
    setattrs(start_buffer_cache, current_ms=lambda base_url=None: START_BUFFER_MS)
    setattrs(system_stats, _read_get_throttled_value=lambda: scenario.throttled)
    setattrs(federation, create_session=lambda ip: ("golden-token", 0))
    # The seek rate limit is per process; every case starts outside it.
    setattrs(api, _dial_seek_last=float("-inf"))
    # A backend call through any namespace the scenario did not provide fails.
    for name in ("list_outputs", "get_setting", "update_output", "set_output_enabled",
                 "submit_output_pin"):
        monkeypatch.setattr(player_service, name, _unpatched(rec, name))
    # The output authority makes its writes here; the case records them.
    monkeypatch.setattr(player_service, "update_output", update_output)
    return rec


def _begin_mute(scenario: Scenario, fake, monkeypatch) -> None:
    """Mute the scenario's selected outputs through the authority, so that each
    remembers the level in muted_levels. The rows are first read at those
    levels, and read again at the scenario's own once the mute is held."""
    import dataclasses
    import autostream_player_service as player_service
    from autostream_players import ActionResult
    from autostream_state import Origin
    from autostream_state.outputs import get_authority
    monkeypatch.setattr(player_service, "update_output", lambda *a, **k: ActionResult(ok=True))
    fake.outputs([
        dataclasses.replace(r, volume_percent=scenario.muted_levels.get(r.id, r.volume_percent))
        for r in scenario.outputs
    ])
    get_authority().mute_all(Origin.USER)
    fake.outputs(list(scenario.outputs))


def _parse_without_hardware_probe(data: dict, state: Optional[dict] = None):
    from autostream_config import parse_config
    return parse_config(data, state, high_perf=False)


def make_state():
    from autostream_webui_state import WebUIState
    return WebUIState(config_path="golden.json", state_path="golden-state.json")


def make_auth():
    auth = MagicMock()
    auth.get_csrf_token.return_value = FIXED_CSRF_TOKEN
    auth.ensure_session.return_value = FIXED_CSRF_TOKEN
    return auth


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Route:
    family: str
    name: str
    call: Callable[[FakeHandler], None]
    html: bool = False
    # Extra setup for the case, given the pytest monkeypatch.
    prepare: Optional[Callable[[Any], None]] = None


def _dial(extra: Optional[dict] = None) -> dict:
    return {"dial_id": DIAL_ID, **(extra or {})}


def routes() -> list[Route]:
    import autostream_webui_api as api
    import autostream_webui_page_airplay as airplay

    state = make_state()

    def federation_session(handler):
        api.send_federation_session_json(handler, PEER_IP)

    def refuse_sessions(monkeypatch):
        import autostream_federation as federation
        monkeypatch.setattr(federation, "create_session", lambda ip: (None, 12))

    table = [
        Route("status", "GET /api/status", lambda h: api.send_status_json(h, state)),
        Route("status", "GET /api/status (no state)", lambda h: api.send_status_json(h)),
        Route("status", "POST /api/dial/status",
              lambda h: api.send_dial_status_post_json(h, state, _dial())),
        Route("status", "GET /api/audio/status",
              lambda h: api.send_audio_status_json(h, state)),
        Route("status", "GET /api/playing-status",
              lambda h: api.send_playing_status_json(h)),
        Route("status", "POST /api/federation/v1/session", federation_session),
        Route("status", "POST /api/federation/v1/session (rate limited)", federation_session,
              prepare=refuse_sessions),
        Route("status", "GET /api/federation/v1/home",
              lambda h: api.send_federation_home_json(h, state)),
        Route("status", "GET /",
              lambda h: airplay.send_airplay_page(h, state, make_auth()), html=True),
        Route("outputs", "GET /api/owntone/outputs",
              lambda h: api.send_owntone_outputs_json(h, state)),
        Route("outputs", "GET /api/owntone/outputs_state",
              lambda h: api.send_owntone_outputs_state_json(h, state)),
        Route("outputs", "POST /api/dial/outputs",
              lambda h: api.send_dial_outputs_post_json(h, state, _dial())),
        Route("volume_mute", "POST /api/dial/volume +5",
              lambda h: api.send_dial_volume_post_json(h, state, _dial({"delta": 5}))),
        Route("volume_mute", "POST /api/dial/volume -5",
              lambda h: api.send_dial_volume_post_json(h, state, _dial({"delta": -5}))),
        Route("volume_mute", "POST /api/dial/mute mute",
              lambda h: api.send_dial_mute_post_json(h, state, _dial({"action": "mute"}))),
        Route("volume_mute", "POST /api/dial/mute restore",
              lambda h: api.send_dial_mute_post_json(h, state, _dial({"action": "restore"}))),
        Route("eq", "GET /api/output_eq/status",
              lambda h: api.send_output_eq_status_json(h)),
        Route("eq", "POST /api/dial/eq",
              lambda h: api.send_dial_eq_post_json(h, state, _dial())),
        Route("eq", "GET /api/federation/v1/equaliser/status",
              lambda h: api.send_federation_eq_status_json(h, state)),
        Route("repeat", "POST /api/dial/repeat seek",
              lambda h: api.send_dial_repeat_post_json(
                  h, state, _dial({"action": "seek", "position_seconds": 0}))),
        Route("repeat", "POST /api/dial/repeat/arm",
              lambda h: api.send_dial_repeat_arm_post_json(h, state, _dial({"armed": True}))),
        Route("repeat", "POST /api/repeat",
              lambda h: api.send_repeat_post_json(h, state, json.dumps({"armed": True}))),
        Route("warnings", "POST /api/dial/warnings",
              lambda h: api.send_dial_warnings_post_json(h, state, _dial())),
        Route("warnings", "POST /api/dial/capabilities",
              lambda h: api.send_dial_capabilities_json(h, state)),
        Route("levels", "GET /api/inputs/levels",
              lambda h: api.send_input_levels_json(h, state)),
    ]
    return table


def families() -> list[str]:
    seen: list[str] = []
    for route in routes():
        if route.family not in seen:
            seen.append(route.family)
    return seen


def case_key(route: Route, scenario: Scenario) -> str:
    return f"{route.name} {scenario.id}"


def run_case(route: Route, scenario: Scenario, monkeypatch) -> dict:
    """Run one route under one scenario; return {"status", "body", "calls"} normalised."""
    rec = apply(scenario, monkeypatch)
    if route.prepare is not None:
        route.prepare(monkeypatch)
    handler = FakeHandler()
    route.call(handler)
    if rec.unpatched:
        raise AssertionError(
            f"{case_key(route, scenario)}: unpatched backend calls {rec.unpatched}")
    body = handler.body()
    return {
        "status": handler.status,
        "body": normalise_html(body) if route.html else normalise(body, route.name),
        "calls": rec.calls,
    }


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

# Store fields a reply carries once the reply reads them from the state store:
# route name -> tuple of key paths (each a tuple of dict keys).  Each such
# field is replaced by its placeholder, by exact path, and nothing else is.
STORE_FIELDS: dict[str, tuple[tuple[str, ...], ...]] = {}

PLACEHOLDER = "<n>"


def _blank_key(key: str) -> bool:
    return (
        key in ("dbfs", "vu_history")
        or key.endswith("_at")
        or key.startswith("uptime")
    )


def _walk(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: (PLACEHOLDER if _blank_key(k) else _walk(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_walk(v) for v in value]
    return value


def _blank_path(obj: Any, path: tuple[str, ...]) -> None:
    cur = obj
    for key in path[:-1]:
        if not isinstance(cur, dict) or key not in cur:
            return
        cur = cur[key]
    if isinstance(cur, dict) and path[-1] in cur:
        cur[path[-1]] = PLACEHOLDER


def _reject_constant(token: str):
    raise ValueError(f"reply contains the non-JSON constant {token}")


def normalise(body: str, route_name: str = "") -> str:
    """Blank the run-varying values of a JSON reply and re-serialise it.

    Replaced by key: ``dbfs``, ``vu_history``, every key ending ``_at`` and
    every key starting ``uptime``.  Replaced by exact path per route: the
    fields in STORE_FIELDS.  A reply holding NaN or an infinity is refused.
    """
    obj = json.loads(body, parse_constant=_reject_constant)
    obj = _walk(obj)
    for path in STORE_FIELDS.get(route_name, ()):
        _blank_path(obj, path)
    return json.dumps(obj, allow_nan=False)


_TIMESTAMP = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
_EPOCH = re.compile(r"\b1\d{9}(?:\.\d+)?\b")


def normalise_html(body: str) -> str:
    """The setup page golden's substitutions, plus timestamps and epoch values."""
    body = body.replace(FIXED_APP_VERSION, "{APP_VERSION}")
    body = body.replace(FIXED_CSRF_TOKEN, "{CSRF_TOKEN}")
    body = re.sub(r"<MagicMock id='\d+'>", "{MOCK}", body)
    body = _TIMESTAMP.sub(PLACEHOLDER, body)
    return _EPOCH.sub(PLACEHOLDER, body)


GOLDEN_DIR = Path(__file__).resolve().parent / "golden" / "replies"


def golden_path(family: str) -> Path:
    return GOLDEN_DIR / f"{family}.json"
