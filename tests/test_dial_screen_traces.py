"""tests/test_dial_screen_traces.py

Behaviour-preservation trace corpus for the dial display's screen state
machine (main / appliance selector / repeat / replay picker).

Drives a DialDisplay instance through scripted scenarios and a handful of
seeded random walks, using a FakeBackend and a fully controlled clock so
every step is deterministic, and records a snapshot of every screen-related
field after each step. The recorded corpus is compared against a golden
fixture (tests/golden/dial_screen_traces.json) so that a later change to how
the manager decides screen behaviour can be proven not to have changed what
any existing screen actually does, byte for byte.

To regenerate the golden fixture after a deliberate, reviewed change, flip
_REGENERATE to True, run this file once, then flip it back to False.
"""
from __future__ import annotations

import dataclasses
import json
import random
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import dial_display as dd
from dial_config import DialDisplayConfig
from dial_display import DialDisplay, SELECTOR_TIMEOUT_SECONDS
from dial_mdns import PlayingTarget, RosterEntry
from dial_repeat_store import parse_repeat_object, repeat_store
from dial_touch_layout import TouchZone

GOLDEN_DIR = Path(__file__).parent / "golden"
GOLDEN_PATH = GOLDEN_DIR / "dial_screen_traces.json"

# Set to True locally to regenerate the golden fixture after a *deliberate*,
# reviewed change. Must be False in committed code.
_REGENERATE = False

_TEST_LOGO_PATH = str(REPO_ROOT / "images" / "autostream-logo-centred-dark.png")


# ---------------------------------------------------------------------------
# Small self-contained fixtures (deliberately not shared with
# test_dial_display.py, so this corpus stands on its own).
# ---------------------------------------------------------------------------

class _FakeClock:
    """Controllable stand-in for time.monotonic, advanced only by explicit
    "advance" steps so every scenario is fully deterministic."""

    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t


class FakeBackend:
    name = "fake"
    width = 128
    height = 160

    def __init__(self) -> None:
        self.opened = False
        self.closed = False
        self.cleared = False
        self.displayed: list = []
        self.sleep_calls = 0
        self.wake_calls = 0

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.closed = True
        self.opened = False

    def clear(self) -> None:
        self.cleared = True

    def display(self, image) -> None:
        self.displayed.append(image)

    def sleep(self) -> None:
        self.sleep_calls += 1

    def wake(self) -> None:
        self.wake_calls += 1


def _target(
    name: str, appliance_id: str, auth: str = "authorized", playing_since: float = 1.0,
) -> PlayingTarget:
    return PlayingTarget(
        ip="192.168.1.10", port=80, name=name,
        dial_api=True, audio_status=True, dial_status=True,
        service_name=name, playing_since=playing_since,
        appliance_id=appliance_id, auth=auth,
    )


def _idle_row(name: str, appliance_id: str, auth: str = "authorized", repeat_capable: bool = False) -> RosterEntry:
    return RosterEntry(
        appliance_id=appliance_id, service_name=name, name=name,
        ip="192.168.1.20", port=80, playing=False, repeat_capable=repeat_capable,
        dial_api=True, audio_status=True, dial_status=True, auth=auth,
    )


def _roster_row_for_target(t: PlayingTarget) -> RosterEntry:
    return RosterEntry(
        appliance_id=t.appliance_id, service_name=t.service_name, name=t.name,
        ip=t.ip, port=t.port, playing=True, repeat_capable=False,
        dial_api=t.dial_api, audio_status=t.audio_status, dial_status=t.dial_status,
        auth=t.auth,
    )


def _status_result(track_id=None, status_error=None, appliance_id=None, repeat=None) -> dict:
    result = {
        "playing": True, "master_volume": 50, "selected_output_count": 1,
        "track_id": track_id, "status_error": status_error,
        "appliance_id": appliance_id,
    }
    if repeat is not None:
        result["repeat"] = repeat
    return result


def _repeat_obj(**overrides) -> dict:
    base = {
        "available": True, "state": "hold", "armed": False, "held": True,
        "recording_seconds": 30.0,
        "replay": {"active": False, "position_seconds": 0.0, "duration_seconds": 30.0},
    }
    base.update(overrides)
    return base


def _aid(tag: str) -> str:
    """A stable, unique-enough 20-character appliance id for *tag*, so each
    scenario/walk can use its own id namespace without colliding with any
    other's — both dial_auth's map and dial_repeat_store are process-wide
    singletons, and this suite runs many scenarios back to back in one
    process without resetting them between scenarios."""
    return (tag + "0" * 20)[:20]


def _make_display(targets, get_roster) -> tuple[DialDisplay, FakeBackend, MagicMock]:
    cfg = DialDisplayConfig(fitted=True)
    fb = FakeBackend()
    gt = MagicMock(return_value=list(targets))
    display = DialDisplay(
        config=cfg,
        get_display_targets=gt,
        dial_id="dial-uuid",
        logo_path=_TEST_LOGO_PATH,
        backend_factory=lambda: fb,
        get_roster=get_roster,
    )
    return display, fb, gt


# ---------------------------------------------------------------------------
# Scenario context: owns the display instance, the fake clock, and the
# per-appliance status/repeat fixtures a scenario's steps can update as they
# go, plus the bookkeeping the snapshot function needs (frame-count deltas).
# ---------------------------------------------------------------------------

class _Ctx:
    def __init__(self, targets=()) -> None:
        self.clock = _FakeClock(start=1000.0)
        self.status_by_id: dict[str, dict] = {}
        self.roster_override: list | None = None
        self.display, self.fb, self.gt = _make_display(targets, self._get_roster)
        self.frame_offset = 0

    def _get_roster(self) -> list:
        if self.roster_override is not None:
            return self.roster_override
        return [_roster_row_for_target(t) for t in self.gt()]

    def fake_fetch(self, target, dial_id, timeout_seconds):
        aid = getattr(target, "appliance_id", None)
        return self.status_by_id.get(aid, _status_result(appliance_id=aid))

    def fake_enrich(self, targets, dial_id):
        return [
            {**self.status_by_id.get(t.appliance_id, _status_result(appliance_id=t.appliance_id)),
             "name": t.service_name}
            for t in targets
        ]


def _apply_step(ctx: _Ctx, step: tuple) -> None:
    d = ctx.display
    kind = step[0]
    if kind == "targets":
        ctx.gt.return_value = list(step[1])
    elif kind == "roster":
        ctx.roster_override = step[1]
    elif kind == "status":
        ctx.status_by_id.update(step[1])
    elif kind == "repeat_store_seed":
        _, aid, obj = step
        repeat_store.update(aid, parse_repeat_object(obj, ctx.clock.t))
    elif kind == "open_selector":
        d.open_selector()
    elif kind == "open_picker":
        d.open_picker()
    elif kind == "toggle_repeat":
        d.toggle_repeat_screen()
    elif kind == "close_list":
        d.close_list()
    elif kind == "pop_secondary":
        d.pop_secondary(step[1])
    elif kind == "list_page":
        d.list_page(step[1])
    elif kind == "list_row_tap":
        d.list_row_tap(step[1])
    elif kind == "selector_pick":
        d.selector_pick(step[1])
    elif kind == "picker_pick":
        d.picker_pick(step[1])
    elif kind == "set_manual_focus":
        d.set_manual_focus(step[1])
    elif kind == "set_manual_focus_pending":
        d.set_manual_focus_pending(step[1], step[2])
    elif kind == "notify_touch_activity":
        d.notify_touch_activity()
    elif kind == "set_pressed":
        d.set_pressed(step[1], step[2] if len(step) > 2 else None)
    elif kind == "poll":
        d._poll_once()
    elif kind == "repaint":
        with d._lock:
            d._repaint_current_locked()
    elif kind == "check_timeout":
        d._check_secondary_timeout()
    elif kind == "tick_repeat_line":
        d._tick_repeat_line()
    elif kind == "advance":
        ctx.clock.t += step[1]
    elif kind == "enable":
        d.enable()
    elif kind == "disable":
        d.disable()
    elif kind == "sleep_locked":
        with d._lock:
            d._sleep_locked()
    elif kind == "swap_backend_locked":
        with d._lock:
            d._swap_backend_locked()
    elif kind == "clear_last_roster":
        d._last_roster = []
    elif kind == "update_config":
        d.update_config(dataclasses.replace(d._config, **step[1]))
    else:
        raise ValueError(f"unknown scenario step kind: {kind!r}")


def _snapshot(ctx: _Ctx) -> dict:
    d = ctx.display

    def _list_state(state):
        if state is None:
            return None
        return {"page": state.page, "opened_at": state.opened_at, "rows": len(state.rows)}

    now_playing = d._now_playing
    now_playing_repr = None
    if now_playing is not None:
        now_playing_repr = {
            "service_name": now_playing.service_name, "artist": now_playing.artist,
            "title": now_playing.title, "master_volume": now_playing.master_volume,
            "album": now_playing.album,
        }
    pressed = d._pressed
    pressed_repr = None if pressed is None else [pressed[0].value, pressed[1]]
    frames = ctx.fb.displayed[ctx.frame_offset:]
    ctx.frame_offset = len(ctx.fb.displayed)
    surface = d.touch_surface()

    return {
        "screen": d._screen,
        "screen_request": d._screen_request,
        "page_request": d._page_request,
        "selector": _list_state(d._selector),
        "picker": _list_state(d._picker),
        "repeat_appliance_id": d._repeat_screen.appliance_id if d._repeat_screen is not None else None,
        "pressed": pressed_repr,
        "now_playing": now_playing_repr,
        "reporting_appliance_id": d._reporting_appliance_id,
        "manual_focus_id": d._manual_focus_id,
        "focus_pending": d._focus_pending is not None,
        "display_sleeping": d._display_sleeping,
        "idle_started": d._idle_started_at is not None,
        "touch_surface": [surface[0], surface[1], surface[2]],
        "persistent_overlay_shown": d.persistent_overlay_shown(),
        "repeat_close_reveal": d.consume_repeat_close_reveal(),
        "frame_count": len(frames),
        "frame_sizes": [list(im.size) for im in frames],
    }


def _run_scenario(steps: list[tuple]) -> list[dict]:
    ctx = _Ctx()
    with patch("dial_display.time.monotonic", ctx.clock), \
         patch("dial_display.fetch_target_status", side_effect=ctx.fake_fetch), \
         patch("dial_display.enrich_targets", side_effect=ctx.fake_enrich):
        ctx.display.enable()
        ctx.frame_offset = len(ctx.fb.displayed)
        trace = []
        for step in steps:
            _apply_step(ctx, step)
            trace.append(_snapshot(ctx))
    return trace


# ---------------------------------------------------------------------------
# Scripted scenarios — one per edge case captured for the screen model.
# ---------------------------------------------------------------------------

def _scripted_scenarios() -> list[tuple[str, list[tuple]]]:
    scenarios: list[tuple[str, list[tuple]]] = []

    def add(name, steps):
        scenarios.append((name, steps))

    # A selector request landing on top of the repeat screen switches
    # straight there without clearing the repeat screen's own state.
    aid = _aid("c1")
    t = _target("C1", aid)
    add("selector_over_repeat_leaves_repeat_state", [
        ("targets", [t]),
        ("status", {aid: _status_result(repeat=_repeat_obj(state="idle", available=True))}),
        ("poll",),
        ("toggle_repeat",),
        ("repaint",),
        ("open_selector",),
        ("repaint",),
    ])

    # A repeat request whose appliance disappears from the roster before the
    # repeat thread applies it is silently dropped — the current screen
    # (main) stays.
    aid = _aid("c2")
    t = _target("C2", aid)
    add("repeat_request_dropped_when_roster_entry_vanishes", [
        ("targets", [t]),
        ("status", {aid: _status_result(repeat=_repeat_obj(state="idle", available=True))}),
        ("poll",),
        ("toggle_repeat",),
        ("clear_last_roster",),
        ("repaint",),
    ])

    # The repeat screen is never requested while nothing plays.
    add("repeat_refused_with_nothing_playing", [
        ("targets", []),
        ("poll",),
        ("toggle_repeat",),
        ("repaint",),
    ])

    # A second DOTS tap closes the repeat screen and arms the one-shot
    # overlay-reveal flag; opening it does not.
    aid = _aid("c4")
    t = _target("C4", aid)
    add("repeat_dots_open_then_close_arms_reveal", [
        ("targets", [t]),
        ("status", {aid: _status_result(repeat=_repeat_obj(state="idle", available=True))}),
        ("poll",),
        ("toggle_repeat",),
        ("repaint",),
        ("toggle_repeat",),
        ("repaint",),
    ])

    # An encoder/button nudge pops the repeat screen back to main.
    aid = _aid("c5")
    t = _target("C5", aid)
    add("encoder_nudge_pops_repeat_to_main", [
        ("targets", [t]),
        ("status", {aid: _status_result(repeat=_repeat_obj(state="idle", available=True))}),
        ("poll",),
        ("toggle_repeat",),
        ("repaint",),
        ("pop_secondary", "repeat"),
        ("repaint",),
    ])

    # A mismatched nudge (asking to pop a screen that is not the one
    # showing) is a no-op.
    aid = _aid("c6")
    t = _target("C6", aid)
    add("encoder_nudge_mismatch_is_a_noop", [
        ("targets", [t]),
        ("status", {aid: _status_result(repeat=_repeat_obj(state="idle", available=True))}),
        ("poll",),
        ("toggle_repeat",),
        ("repaint",),
        ("pop_secondary", "selector"),
        ("repaint",),
    ])

    # Re-requesting the selector while it is already open resets its page
    # to 0 and restarts its inactivity clock.
    targets7 = [_target(f"C7-{i}", _aid(f"c7_{i}"), playing_since=float(i)) for i in range(5)]
    add("selector_reopen_resets_page_and_clock", [
        ("targets", targets7),
        ("poll",),
        ("open_selector",),
        ("repaint",),
        ("list_page", 1),
        ("repaint",),
        ("advance", 5.0),
        ("open_selector",),
        ("repaint",),
    ])

    # A page delta is ignored on the repeat screen (it is not paged).
    aid = _aid("c8")
    t = _target("C8", aid)
    add("page_delta_on_repeat_is_ignored", [
        ("targets", [t]),
        ("status", {aid: _status_result(repeat=_repeat_obj(state="idle", available=True))}),
        ("poll",),
        ("toggle_repeat",),
        ("repaint",),
        ("list_page", 1),
        ("repaint",),
    ])

    # A page delta before any list has ever opened is ignored.
    add("page_delta_before_any_list_is_ignored", [
        ("targets", []),
        ("list_page", 1),
        ("repaint",),
    ])

    # Any screen change clears the unified pressed channel.
    add("screen_change_clears_pressed", [
        ("targets", []),
        ("set_pressed", TouchZone.UP, None),
        ("repaint",),
        ("open_picker",),
        ("repaint",),
    ])

    # The selector closes after its inactivity timeout with no touch.
    aid = _aid("c11")
    t = _target("C11", aid)
    add("selector_closes_after_timeout", [
        ("targets", [t]),
        ("poll",),
        ("open_selector",),
        ("repaint",),
        ("advance", SELECTOR_TIMEOUT_SECONDS + 1),
        ("check_timeout",),
    ])

    # Touch activity while the selector is open restarts its timeout clock.
    aid = _aid("c12")
    t = _target("C12", aid)
    add("selector_touch_restarts_timeout", [
        ("targets", [t]),
        ("poll",),
        ("open_selector",),
        ("repaint",),
        ("advance", 17.0),
        ("notify_touch_activity",),
        ("repaint",),
        ("advance", SELECTOR_TIMEOUT_SECONDS - 1),
        ("check_timeout",),
        ("advance", 2.0),
        ("check_timeout",),
    ])

    # Touch activity does NOT restart the picker's timeout clock (today's
    # value — see the picker row's touch_extends_timeout field).
    add("picker_touch_does_not_restart_timeout", [
        ("targets", []),
        ("open_picker",),
        ("repaint",),
        ("advance", 17.0),
        ("notify_touch_activity",),
        ("repaint",),
        ("advance", 2.0),
        ("check_timeout",),
    ])

    # The repeat screen has no inactivity timeout of its own.
    aid = _aid("c14")
    t = _target("C14", aid)
    add("repeat_screen_never_times_out", [
        ("targets", [t]),
        ("status", {aid: _status_result(repeat=_repeat_obj(state="idle", available=True))}),
        ("poll",),
        ("toggle_repeat",),
        ("repaint",),
        ("advance", 900.0),
        ("check_timeout",),
    ])

    # With the selector open, a poll that finds nothing playing must not
    # update the stale now-playing readout until the list closes.
    aid = _aid("c16")
    t = _target("C16", aid)
    add("nothing_plays_selector_open_now_playing_stays_stale", [
        ("targets", [t]),
        ("status", {aid: _status_result()}),
        ("poll",),
        ("open_selector",),
        ("repaint",),
        ("targets", []),
        ("poll",),
        ("repaint",),
    ])

    # A picker open REQUEST that has not yet been applied still counts as
    # "a list is open" for the nothing-playing poll branch.
    add("nothing_plays_picker_request_pending_not_clobbered", [
        ("targets", []),
        ("open_picker",),
        ("poll",),
        ("repaint",),
    ])

    # With nothing playing and no idle focus, an open repeat screen closes.
    aid = _aid("c18")
    t = _target("C18", aid)
    add("nothing_plays_repeat_closes_without_idle_focus", [
        ("targets", [t]),
        ("status", {aid: _status_result(repeat=_repeat_obj(state="idle", available=True))}),
        ("poll",),
        ("toggle_repeat",),
        ("repaint",),
        ("targets", []),
        ("poll",),
    ])

    # With nothing playing but an idle focus resolving to the same
    # appliance, the repeat screen stays open.
    aid = _aid("c19")
    t = _target("C19", aid)
    add("nothing_plays_repeat_stays_with_idle_focus", [
        ("targets", [t]),
        ("status", {aid: _status_result(repeat=_repeat_obj(state="idle", available=True))}),
        ("poll",),
        ("set_manual_focus", aid),
        ("toggle_repeat",),
        ("repaint",),
        ("targets", []),
        ("roster", [_idle_row("C19", aid, repeat_capable=True)]),
        ("poll",),
    ])

    # Asleep: a poll that finds nothing playing stays dark and repaints
    # nothing further.
    add("asleep_stays_dark", [
        ("targets", []),
        ("poll",),
        ("advance", dd.DISPLAY_IDLE_SLEEP_SECONDS),
        ("poll",),
        ("poll",),
    ])

    # A selector closed by its own timeout, then idle for long enough,
    # sleeps — popping everything.
    aid = _aid("c21")
    t = _target("C21", aid)
    add("selector_timeout_then_idle_sleep_pops_everything", [
        ("targets", [t]),
        ("poll",),
        ("open_selector",),
        ("repaint",),
        ("advance", SELECTOR_TIMEOUT_SECONDS + 1),
        ("check_timeout",),
        ("targets", []),
        ("poll",),
        ("advance", dd.DISPLAY_IDLE_SLEEP_SECONDS),
        ("poll",),
    ])

    # A focus that clears (appliance gone) closes an open repeat screen.
    aid = _aid("c22")
    t = _target("C22", aid, playing_since=1.0)
    add("focus_cleared_closes_repeat", [
        ("targets", [t]),
        ("status", {aid: _status_result(repeat=_repeat_obj(state="idle", available=True))}),
        ("set_manual_focus", aid),
        ("poll",),
        ("toggle_repeat",),
        ("repaint",),
        ("targets", []),
        ("roster", []),
        ("poll",),
    ])

    # A focus that clears leaves an open selector alone.
    aid = _aid("c23")
    t = _target("C23", aid, playing_since=1.0)
    add("focus_cleared_selector_stays_open", [
        ("targets", [t]),
        ("set_manual_focus", aid),
        ("poll",),
        ("open_selector",),
        ("repaint",),
        ("targets", []),
        ("roster", []),
        ("poll",),
        ("repaint",),
    ])

    # Lifecycle closes pop every secondary screen back to main.
    aid = _aid("c24a")
    t = _target("C24A", aid)
    add("lifecycle_sleep_pops_selector", [
        ("targets", [t]),
        ("poll",),
        ("open_selector",),
        ("repaint",),
        ("sleep_locked",),
    ])
    add("lifecycle_disable_pops_picker", [
        ("targets", []),
        ("open_picker",),
        ("repaint",),
        ("disable",),
    ])
    aid = _aid("c24c")
    t = _target("C24C", aid)
    add("lifecycle_swap_pops_repeat", [
        ("targets", [t]),
        ("status", {aid: _status_result(repeat=_repeat_obj(state="idle", available=True))}),
        ("poll",),
        ("toggle_repeat",),
        ("repaint",),
        ("swap_backend_locked",),
    ])
    aid = _aid("c24d")
    t = _target("C24D", aid)
    add("lifecycle_layout_change_pops_selector", [
        ("targets", [t]),
        ("poll",),
        ("open_selector",),
        ("repaint",),
        ("update_config", {"layout_size": "large"}),
    ])

    # Waking leaves the screen exactly as it was (main, after the earlier
    # sleep already popped everything).
    add("wake_leaves_screen_unchanged", [
        ("targets", []),
        ("poll",),
        ("advance", dd.DISPLAY_IDLE_SLEEP_SECONDS),
        ("poll",),
        ("notify_touch_activity",),
        ("repaint",),
    ])

    # The idle "tap to replay" affordance appears on main once a held,
    # authorized, repeat-capable appliance is on the roster.
    aid = _aid("c28")
    add("idle_affordance_shown_on_main", [
        ("targets", []),
        ("roster", [_idle_row("C28", aid, repeat_capable=True)]),
        ("repeat_store_seed", aid, _repeat_obj(state="hold", available=True)),
        ("poll",),
    ])

    # Picking a picker row starts a pending-focus replay and closes back to
    # main; a stale index does the same without setting focus.
    aid = _aid("c29")
    add("picker_pick_sets_pending_focus_then_main", [
        ("targets", []),
        ("roster", [_idle_row("C29", aid, repeat_capable=True)]),
        ("repeat_store_seed", aid, _repeat_obj(state="hold", available=True, recording_seconds=12.0)),
        ("poll",),
        ("open_picker",),
        ("repaint",),
        ("picker_pick", 0),
        ("repaint",),
    ])
    aid = _aid("c30")
    add("picker_pick_stale_index_back_to_main", [
        ("targets", []),
        ("roster", [_idle_row("C30", aid, repeat_capable=True)]),
        ("repeat_store_seed", aid, _repeat_obj(state="hold", available=True, recording_seconds=12.0)),
        ("poll",),
        ("open_picker",),
        ("repaint",),
        ("picker_pick", 99),
        ("repaint",),
    ])

    # The picker survives repeated nothing-playing polls; only its own
    # timeout closes it.
    aid = _aid("c31")
    t = _target("C31", aid)
    add("picker_survives_repeated_idle_polls", [
        ("targets", [t]),
        ("poll",),
        ("open_picker",),
        ("repaint",),
        ("targets", []),
        ("poll",),
        ("poll",),
        ("advance", 5.0),
        ("poll",),
    ])

    return scenarios


# ---------------------------------------------------------------------------
# Seeded random walks — a few hundred steps each, exercising interactions
# nobody scripted above.
# ---------------------------------------------------------------------------

_ZONES = [
    TouchZone.UP, TouchZone.DOWN, TouchZone.NAME, TouchZone.DOTS, TouchZone.MUTE,
    TouchZone.LIST_ROW, TouchZone.LIST_BACK, TouchZone.LIST_UP, TouchZone.LIST_DOWN,
    TouchZone.REPEAT_PLAY, TouchZone.REPEAT_START, TouchZone.REPEAT_STOP, TouchZone.IDLE_REPLAY,
]
_ADVANCES = [1.0, 17.0, 19.0, 900.0]
_REPEAT_STATES = ["idle", "recording", "pending", "hold", "replaying", "fading_out"]

_ACTION_KINDS = (
    ["targets"] * 3 + ["roster"] * 2 + ["status"] * 5
    + ["open_selector"] * 2 + ["open_picker"] * 2 + ["toggle_repeat"] * 2
    + ["close_list"] * 2 + ["pop_secondary"] * 2 + ["list_page"] * 2
    + ["list_row_tap"] * 2 + ["set_manual_focus"] * 2 + ["notify_touch_activity"] * 2
    + ["set_pressed"] * 3 + ["poll"] * 6 + ["repaint"] * 6 + ["check_timeout"] * 2
    + ["tick_repeat_line"] * 2 + ["update_config"] * 2 + ["advance"] * 6
)


def _random_walk_steps(seed: int, n_steps: int, tag: str) -> list[tuple]:
    rng = random.Random(seed)
    aids = [_aid(f"{tag}_{i}") for i in range(3)]
    targets_full = [_target(f"{tag.upper()}{i}", aids[i], playing_since=float(i)) for i in range(3)]
    idle_row = _idle_row(f"{tag}Idle", _aid(f"{tag}_idle"), repeat_capable=True)

    steps: list[tuple] = [("targets", list(targets_full))]
    for _ in range(n_steps):
        kind = rng.choice(_ACTION_KINDS)
        if kind == "targets":
            k = rng.randint(0, len(targets_full))
            steps.append(("targets", rng.sample(targets_full, k)))
        elif kind == "roster":
            base = [_roster_row_for_target(t) for t in targets_full]
            if rng.random() < 0.5:
                base.append(idle_row)
            steps.append(("roster", base if rng.random() < 0.8 else None))
        elif kind == "status":
            aid = rng.choice(aids)
            if rng.random() < 0.15:
                steps.append(("status", {aid: _status_result(status_error="unauthorized")}))
            else:
                obj = _repeat_obj(
                    state=rng.choice(_REPEAT_STATES),
                    available=rng.random() < 0.85,
                    armed=rng.random() < 0.5,
                )
                steps.append(("status", {aid: _status_result(repeat=obj)}))
        elif kind == "pop_secondary":
            steps.append(("pop_secondary", rng.choice(["selector", "picker", "repeat"])))
        elif kind == "list_page":
            steps.append(("list_page", rng.choice([-2, -1, 1, 2])))
        elif kind == "list_row_tap":
            steps.append(("list_row_tap", rng.randint(0, 4)))
        elif kind == "set_manual_focus":
            steps.append(("set_manual_focus", rng.choice(aids + [None])))
        elif kind == "set_pressed":
            zone = rng.choice(_ZONES + [None])
            idx = rng.randint(0, 3) if zone == TouchZone.LIST_ROW else None
            steps.append(("set_pressed", zone, idx))
        elif kind == "update_config":
            field = rng.choice(["layout_large", "layout_none", "fitted_off", "fitted_on"])
            if field == "layout_large":
                steps.append(("update_config", {"layout_size": "large"}))
            elif field == "layout_none":
                steps.append(("update_config", {"layout_size": None}))
            elif field == "fitted_off":
                steps.append(("update_config", {"fitted": False}))
            else:
                steps.append(("update_config", {"fitted": True}))
        elif kind == "advance":
            steps.append(("advance", rng.choice(_ADVANCES)))
        else:
            # open_selector / open_picker / toggle_repeat / close_list /
            # notify_touch_activity / poll / repaint / check_timeout /
            # tick_repeat_line — no arguments.
            steps.append((kind,))
    return steps


def _random_walk_scenarios() -> list[tuple[str, list[tuple]]]:
    return [
        (f"random_walk_{seed}", _random_walk_steps(seed=seed, n_steps=300, tag=f"w{seed}"))
        for seed in (101, 202, 303)
    ]


# ---------------------------------------------------------------------------
# The test itself
# ---------------------------------------------------------------------------

class TestScreenTraceCorpus:
    def test_matches_golden(self):
        result = {}
        for name, steps in _scripted_scenarios() + _random_walk_scenarios():
            result[name] = _run_scenario(steps)

        payload = json.dumps(result, indent=2, sort_keys=True) + "\n"

        if _REGENERATE:
            GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
            GOLDEN_PATH.write_text(payload, encoding="utf-8")
            pytest.skip("golden file regenerated -- set _REGENERATE back to False")

        assert GOLDEN_PATH.exists(), (
            f"Golden file missing: {GOLDEN_PATH}. Run once with "
            f"_REGENERATE=True to create it, then set it back to False."
        )
        expected = GOLDEN_PATH.read_text(encoding="utf-8")
        assert payload == expected, (
            "The screen-policy trace corpus diverged from the golden file -- "
            "this must stay byte-identical across a dial-only refactor of "
            "how the manager decides screen behaviour."
        )
