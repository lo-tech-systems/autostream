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

import contextlib
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
from dial_core import FOCUS_PENDING_GRACE_S
from dial_core_state import ApplianceWarning, eq_gain
from dial_display import WARNING_DESCRIPTORS, DialDisplay, SELECTOR_TIMEOUT_SECONDS
from dial_mdns import PlayingTarget, RosterEntry
from dial_network import LINK_CONNECTED, LINK_DOWN, LINK_IGNORED, LINK_UNKNOWN, NetworkView
from dial_repeat_store import parse_repeat_object, repeat_store
from dial_sdhealth import SdHealthView, STATUS_VALID
from dial_touch_layout import TouchZone
from dial_warnings import WarningManager, WarningStore

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
    dial_outputs: bool = False, dial_eq: bool = False,
) -> PlayingTarget:
    return PlayingTarget(
        ip="192.168.1.10", port=80, name=name,
        dial_api=True, audio_status=True, dial_status=True, dial_outputs=dial_outputs,
        dial_eq=dial_eq,
        service_name=name, playing_since=playing_since,
        appliance_id=appliance_id, auth=auth,
    )


def _idle_row(
    name: str, appliance_id: str, auth: str = "authorized", repeat_capable: bool = False,
    dial_outputs: bool = False, dial_eq: bool = False,
) -> RosterEntry:
    return RosterEntry(
        appliance_id=appliance_id, service_name=name, name=name,
        ip="192.168.1.20", port=80, playing=False, repeat_capable=repeat_capable,
        dial_api=True, audio_status=True, dial_status=True, dial_outputs=dial_outputs,
        dial_eq=dial_eq, auth=auth,
    )


def _roster_row_for_target(t: PlayingTarget) -> RosterEntry:
    return RosterEntry(
        appliance_id=t.appliance_id, service_name=t.service_name, name=t.name,
        ip=t.ip, port=t.port, playing=True, repeat_capable=False,
        dial_api=t.dial_api, audio_status=t.audio_status, dial_status=t.dial_status,
        dial_outputs=t.dial_outputs, dial_eq=t.dial_eq, auth=t.auth,
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


def _outputs_body(rows) -> dict:
    """rows: an iterable of (id, name, selected, volume, remote_in_use
    [, is_default [, needs_auth_key]]) tuples -- the shape POST
    /api/dial/outputs returns, fed straight to on_outputs_result() via the
    "outputs_result" step. The "is_default" key is sent only for a row that
    gives a sixth element, "needs_auth_key" only for one that gives a
    seventh."""
    def _row(row):
        i, n, s, v, r, *rest = row
        body = {"id": i, "name": n, "selected": s, "volume": v, "remote_in_use": r}
        if rest:
            body["is_default"] = rest[0]
        if len(rest) > 1:
            body["needs_auth_key"] = rest[1]
        return body

    return {"ok": True, "outputs": [_row(row) for row in rows]}


def _art(url_tag: str, title: str = "Song", artist: str = "Artist") -> dict:
    """A minimal "identified, with artwork" track_id object, keyed by
    *url_tag* alone so two calls with different tags never collide on the
    dedupe url comparison _show_artwork() does."""
    return {
        "state": "identified", "artwork_url": f"https://provider.example/{url_tag}.jpg",
        "artist": artist, "title": title,
    }


def _aid(tag: str) -> str:
    """A stable, unique-enough 20-character appliance id for *tag*, so each
    scenario/walk can use its own id namespace without colliding with any
    other's — both dial_auth's map and dial_repeat_store are process-wide
    singletons, and this suite runs many scenarios back to back in one
    process without resetting them between scenarios."""
    return (tag + "0" * 20)[:20]


def _make_display(targets, get_roster, cfg=None, backend=None, warnings=None) -> tuple[DialDisplay, FakeBackend, MagicMock]:
    """*cfg*/*backend* let a scenario opt into a non-default profile/panel
    size (e.g. the compact tier's own 240x240 glass) — every existing call
    site leaves both None and gets exactly today's base-tier fixture."""
    cfg = cfg if cfg is not None else DialDisplayConfig(fitted=True)
    fb = backend if backend is not None else FakeBackend()
    gt = MagicMock(return_value=list(targets))
    display = DialDisplay(
        config=cfg,
        get_display_targets=gt,
        dial_id="dial-uuid",
        logo_path=_TEST_LOGO_PATH,
        backend_factory=lambda: fb,
        get_roster=get_roster,
        warnings=warnings,
    )
    return display, fb, gt


# ---------------------------------------------------------------------------
# Scenario context: owns the display instance, the fake clock, and the
# per-appliance status/repeat fixtures a scenario's steps can update as they
# go, plus the bookkeeping the snapshot function needs (frame-count deltas).
# ---------------------------------------------------------------------------

class _Ctx:
    def __init__(self, targets=(), cfg=None, backend=None) -> None:
        self.clock = _FakeClock(start=1000.0)
        self.status_by_id: dict[str, dict] = {}
        self.roster_override: list | None = None
        # The warning manager's own clock is the same fake clock the
        # "advance" step moves, kept in memory only (no state file):
        # every scenario is fully deterministic and self-contained.
        warnings = WarningManager(WARNING_DESCRIPTORS, WarningStore(None), clock=self.clock)
        self.display, self.fb, self.gt = _make_display(
            targets, self._get_roster, cfg=cfg, backend=backend, warnings=warnings,
        )
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
    elif kind == "open_info":
        d.open_info()
    elif kind == "toggle_repeat":
        d.cycle_pages()
    elif kind == "cycle_pages":
        d.cycle_pages()
    elif kind == "eq_step":
        d.eq_step(step[1], step[2])
    elif kind == "eq_result":
        # ("eq_result", appliance_id, status, body) -- feeds the EQ
        # worker's on_eq_result callback directly, the same shape the
        # worker itself calls it with after a fetch.
        _, aid, status, body = step
        d.core.on_eq_result("fetch", aid, status, body, {})
        d._apply_pending_snapshot()
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
        d.core.set_focus(step[1])
    elif kind == "set_manual_focus_pending":
        d.core.set_focus_pending(step[1], step[2], ctx.clock.t + FOCUS_PENDING_GRACE_S)
        d.core.request_poll()
    elif kind == "notify_touch_activity":
        d.notify_touch_activity()
    elif kind == "set_pressed":
        d.set_pressed(step[1], step[2] if len(step) > 2 else None)
    elif kind == "poll":
        d._poll_once()
    elif kind == "repaint":
        with d._lock:
            d._repaint_current_locked()
        # What a repaint wake does after painting: keep the core's record
        # of the pages being watched in step with the screens that are up.
        d._sync_core_interest()
    elif kind == "check_timeout":
        d._check_secondary_timeout()
    elif kind == "tick_repeat_line":
        d._tick_repeat_line()
    elif kind == "tick_warnings":
        # The core's warning housekeeping, then the view's own tick that
        # raises a warning whose snooze has just run out.
        d._apply_source_effects(d.core.expire_warnings())
        d._tick_due_warning()
        d.core.flush_warnings()
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
        d.core.set_roster([])
    elif kind == "update_config":
        d.update_config(dataclasses.replace(d._config, **step[1]))
    elif kind == "open_outputs":
        d.open_outputs()
    elif kind == "outputs_row_tap":
        d.outputs_row_tap(step[1])
    elif kind == "output_toggle_tap":
        d.output_toggle_tap()
    elif kind == "output_volume_tap":
        d.output_volume_tap(step[1])
    elif kind == "outputs_result":
        # ("outputs_result", appliance_id, status, body) -- feeds the
        # outputs worker's on_outputs_result callback directly, the same
        # shape the worker itself calls it with after a fetch, stamped with the
        # scenario clock as the worker stamps the fetch it requests.
        _, aid, status, body = step
        d.core.on_outputs_result("fetch", aid, status, body, {"started_at": ctx.clock.t})
        d._apply_pending_snapshot()
    elif kind == "outputs_set_result":
        # ("outputs_set_result", appliance_id, status, body) -- the reply to
        # a set the outputs worker sent, fed to the same callback with the
        # token of the request it answers, as the worker hands it back.
        _, aid, status, body = step
        held = d.core.snapshot().outputs_request
        d.core.on_outputs_result(
            "set", aid, status, body, {"token": None if held is None else held.requested_at},
        )
        d._apply_pending_snapshot()
    elif kind == "tick_outputs_refresh":
        d._tick_outputs_refresh()
    elif kind == "hide_controls":
        d.hide_controls()
    elif kind == "tick_controls_hidden":
        d._tick_controls_hidden()
    elif kind == "tick_controls_reveal":
        d._tick_controls_reveal()
    elif kind == "network":
        # ("network", link, bars) -- feeds the poller's callback directly,
        # the same shape the worker calls it with after a poll.
        d.core.on_network_view(NetworkView(link=step[1], bars=step[2] if len(step) > 2 else 0, updated_at=ctx.clock.t))
        d._drain_effects()
    elif kind == "open_nowifi":
        d.open_nowifi()
    elif kind == "nowifi_dismiss":
        d._run_warning_action(dd._WARNING_BY_ID["nowifi"], dd.ACTION_DISMISS)
    elif kind == "nowifi_restart":
        d._run_warning_action(dd._WARNING_BY_ID["nowifi"], dd.ACTION_RESTART)
    elif kind == "tick_wifi_flash":
        d._tick_wifi_flash()
    elif kind == "sd_health_view":
        # ("sd_health_view", status, percent) -- feeds the SD health
        # reader's callback directly, the same shape dial_sdhealth.tick()
        # calls it with after a read.
        _, status, percent = step
        d.core.on_sd_health_view(SdHealthView(status=status, percent=percent, updated_at=ctx.clock.t))
        d._drain_effects()
    elif kind == "sdhealth_dismiss":
        d._run_warning_action(dd._WARNING_BY_ID["sdhealth"], dd.ACTION_DISMISS)
    elif kind == "appliance_warnings":
        # ("appliance_warnings", appliance_id, [(id, severity, title,
        # message, dismissal), ...]) -- the validated set the appliance's
        # warnings worker hands the core, replacing the appliance's last.
        _, aid, rows = step
        d.core.set_appliance_warnings(aid, tuple(ApplianceWarning(*row) for row in rows))
    elif kind == "appliance_tap":
        # A tap on the one cell of the page showing (Dismiss, or OK).
        d.warning_button_tap(TouchZone.SDHEALTH_DISMISS)
    else:
        raise ValueError(f"unknown scenario step kind: {kind!r}")


def _snapshot(ctx: _Ctx) -> dict:
    d = ctx.display

    def _list_state(state):
        if state is None:
            return None
        return {"page": state.page, "opened_at": state.opened_at, "rows": len(state.rows)}

    core_snap = d.core.snapshot()
    now_playing = core_snap.now_playing
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

    outputs = d._outputs
    held_outputs = core_snap.outputs
    if outputs is None or held_outputs is None or held_outputs.appliance_id != outputs.appliance_id:
        held_outputs = None
    outputs_repr = None if outputs is None else {
        "appliance_id": outputs.appliance_id, "page": outputs.page,
        "opened_at": outputs.opened_at,
        "loaded": held_outputs is not None and held_outputs.loaded,
        "rows": [
            [r.id, r.name, r.selected, r.volume]
            for r in (dd._offerable(held_outputs.rows) if held_outputs is not None else ())
        ],
    }
    detail = d._output_detail
    detail_repr = None if detail is None else {
        "appliance_id": detail.appliance_id, "output_id": detail.output_id,
        "opened_at": detail.opened_at,
    }
    eq = d._eq
    held_eq = core_snap.eq
    if eq is None or held_eq is None or held_eq.appliance_id != eq.appliance_id:
        held_eq = None
    eq_repr = None if eq is None else {
        "appliance_id": eq.appliance_id, "opened_at": eq.opened_at,
        "bass_db": eq_gain(held_eq.bands, "bass") if held_eq is not None else None,
        "treble_db": eq_gain(held_eq.bands, "treble") if held_eq is not None else None,
        "loaded": held_eq is not None and dd._eq_loaded(held_eq),
    }
    outputs_override = d.core.outputs_override()
    eq_pairs, eq_expires_at = d.core.eq_override()
    eq_gains = dict(eq_pairs)
    network = core_snap.network

    # Present only once an appliance has registered a warning, so a scenario
    # that never involves one records exactly the fields it always did.
    appliance_rows = {
        wid: [active, snoozed_until is not None]
        for wid, active, _severity, _since, snoozed_until in d.core.warnings.runtime()
        if wid.startswith("appliance:")
    }
    appliance_extra = {} if not appliance_rows else {
        "appliance_warnings": appliance_rows,
        "warning_page": d._warning_screen.warning_id if d._warning_screen is not None else None,
    }

    # Present only once a held outputs row carries the default flag, for the
    # same reason: no scenario that never feeds one records anything new.
    default_row = next(
        (r.id for r in (core_snap.outputs.rows if core_snap.outputs is not None else ()) if r.is_default),
        None,
    )
    default_extra = {} if default_row is None else {"outputs_default": default_row}

    # Present only once an output request has been answered, for the same
    # reason: a request still pending (a tap whose reply the scenario never
    # feeds) records nothing.
    request = core_snap.outputs_request
    request_extra = {} if request is None or request.state == "pending" else {
        "outputs_request": [request.kind, request.state, request.error, request.output_id],
    }

    return {
        **appliance_extra,
        **default_extra,
        **request_extra,
        "screen": d._screen,
        "showing": d._showing,
        "screen_request": d._screen_request,
        "page_request": d._page_request,
        "selector": _list_state(d._selector),
        "picker": _list_state(d._picker),
        "info": _list_state(d._info),
        "repeat_appliance_id": d._repeat_screen.appliance_id if d._repeat_screen is not None else None,
        "outputs": outputs_repr,
        "output_detail": detail_repr,
        "outputs_optimistic": list(outputs_override) if outputs_override is not None else None,
        "eq": eq_repr,
        "eq_optimistic": (
            [eq_gains.get("bass"), eq_gains.get("treble"), eq_expires_at]
            if (eq_pairs or eq_expires_at) else None
        ),
        "eq_available": core_snap.eq_available,
        "network": None if network is None else {
            "link": network.link, "bars": network.bars,
            "down_streak": d.core.wifi_down_streak(),
            "dismissed": d.core.warnings.is_snoozed("nowifi"),
            "ever_connected": core_snap.wifi_ever_connected,
        },
        "nowifi_open": d._warning_screen is not None and d._warning_screen.warning_id == "nowifi",
        "restarting_open": d._restarting is not None,
        "sdhealth_open": d._warning_screen is not None and d._warning_screen.warning_id == "sdhealth",
        "pressed": pressed_repr,
        "now_playing": now_playing_repr,
        "reporting_appliance_id": core_snap.focus.reporting_id,
        "bound_appliance_id": core_snap.focus.bound_id,
        "source_artwork_url": d._source_artwork_key[:12],
        "manual_focus_id": core_snap.focus.manual_id,
        "focus_pending": core_snap.focus.pending is not None,
        "display_sleeping": d._display_sleeping,
        "idle_started": d._idle_started_at is not None,
        "touch_surface": [surface[0], surface[1], surface[2], surface[3]],
        "persistent_overlay_shown": d.persistent_overlay_shown(),
        "repeat_close_reveal": d.consume_repeat_close_reveal(),
        "frame_count": len(frames),
        "frame_sizes": [list(im.size) for im in frames],
    }


# Sized to match FakeBackend's own (default) panel dimensions: compose()
# drops a transformed frame whose size does not match the active logical
# size (see _show_artwork()'s post-transform guard), so a fake "transform"
# that ignores its requested size must still land on the one size these
# scenarios actually use.
_FAKE_ARTWORK_IMAGE = Image.new("RGB", (FakeBackend.width, FakeBackend.height))


# Every module-level name the scenarios replace, as (target, kwargs factory):
# the factory gets the scenario context and the artwork image the scenario's
# panel size needs. When a function that calls one of these moves to another
# module, this tuple (and _MONOTONIC_TARGETS) is the one place to repoint.
_PATCHES = (
    ("dial_display.fetch_target_status", lambda ctx, img: {"side_effect": ctx.fake_fetch}),
    ("dial_core_poll.fetch_target_status", lambda ctx, img: {"side_effect": ctx.fake_fetch}),
    ("dial_display.enrich_targets", lambda ctx, img: {"side_effect": ctx.fake_enrich}),
    ("dial_core_poll.enrich_targets", lambda ctx, img: {"side_effect": ctx.fake_enrich}),
    ("dial_display._fetch_artwork", lambda ctx, img: {"return_value": (b"jpegdata", "")}),
    ("dial_display.decode_artwork", lambda ctx, img: {"return_value": img}),
    ("dial_display_compositor.transform_artwork_for_panel", lambda ctx, img: {"return_value": img}),
    ("dial_display._request_reboot", lambda ctx, img: {}),
)
# Every place time.monotonic is read, all patched with the scenario's one
# fake clock.
_MONOTONIC_TARGETS = ("dial_display.time.monotonic", "dial_core_poll.time.monotonic")


def _run_scenario(steps: list[tuple], *, cfg=None, backend=None) -> list[dict]:
    ctx = _Ctx(cfg=cfg, backend=backend)
    # The fake "transform" must still land on the active logical size (see
    # _FAKE_ARTWORK_IMAGE's own comment) — the shared module-level image for
    # every existing (backend=None) scenario, a freshly sized one for a
    # scenario that opted into a non-default panel (e.g. the compact tier).
    artwork_image = _FAKE_ARTWORK_IMAGE if backend is None else Image.new("RGB", (backend.width, backend.height))
    with contextlib.ExitStack() as stack:
        for target in _MONOTONIC_TARGETS:
            stack.enter_context(patch(target, ctx.clock))
        for target, make_kwargs in _PATCHES:
            stack.enter_context(patch(target, **make_kwargs(ctx, artwork_image)))
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
    aid = _aid("c10b")
    add("screen_change_clears_pressed", [
        ("targets", []),
        # A held, authorized, repeat-capable roster row so the idle
        # affordance is due (open_picker() refuses without one —
        # see dial_display.DialDisplay.open_picker()); the matching status
        # entry keeps the reconcile pass's own re-fetch from clearing the
        # seeded hold record straight back out.
        ("roster", [_idle_row("C10B", aid, repeat_capable=True)]),
        ("status", {aid: _status_result(repeat=_repeat_obj(state="hold", available=True))}),
        ("repeat_store_seed", aid, _repeat_obj(state="hold", available=True)),
        ("poll",),
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

    # Touch activity restarts the picker's timeout clock, the same as the
    # selector's own — see the picker row's touch_extends_timeout field
    # (flipped to True: touch now extends every list screen's clock).
    aid = _aid("c13b")
    add("picker_touch_restarts_timeout", [
        ("targets", []),
        # A held, authorized, repeat-capable roster row so the idle
        # affordance is due (open_picker() refuses without one —
        # see dial_display.DialDisplay.open_picker()); the matching status
        # entry keeps the reconcile pass's own re-fetch from clearing the
        # seeded hold record straight back out.
        ("roster", [_idle_row("C13B", aid, repeat_capable=True)]),
        ("status", {aid: _status_result(repeat=_repeat_obj(state="hold", available=True))}),
        ("repeat_store_seed", aid, _repeat_obj(state="hold", available=True)),
        ("poll",),
        ("open_picker",),
        ("repaint",),
        ("advance", 17.0),
        ("notify_touch_activity",),
        ("repaint",),
        ("advance", SELECTOR_TIMEOUT_SECONDS - 1),
        ("check_timeout",),
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
    aid = _aid("c17b")
    add("nothing_plays_picker_request_pending_not_clobbered", [
        ("targets", []),
        # A held, authorized, repeat-capable roster row so the idle
        # affordance is due (open_picker() refuses without one —
        # see dial_display.DialDisplay.open_picker()); the matching status
        # entry keeps the reconcile pass's own re-fetch from clearing the
        # seeded hold record straight back out.
        ("roster", [_idle_row("C17B", aid, repeat_capable=True)]),
        ("status", {aid: _status_result(repeat=_repeat_obj(state="hold", available=True))}),
        ("repeat_store_seed", aid, _repeat_obj(state="hold", available=True)),
        ("poll",),
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
    aid = _aid("c24b")
    add("lifecycle_disable_pops_picker", [
        ("targets", []),
        # A held, authorized, repeat-capable roster row so the idle
        # affordance is due (open_picker() refuses without one —
        # see dial_display.DialDisplay.open_picker()); the matching status
        # entry keeps the reconcile pass's own re-fetch from clearing the
        # seeded hold record straight back out.
        ("roster", [_idle_row("C24B", aid, repeat_capable=True)]),
        ("status", {aid: _status_result(repeat=_repeat_obj(state="hold", available=True))}),
        ("repeat_store_seed", aid, _repeat_obj(state="hold", available=True)),
        ("poll",),
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

    # The idle screen's own "i" affordance is reachable regardless of
    # whether a replay is held: open the read-only info page, page to its
    # second (base tier: 3 rows/page, clamped) page, then X back to idle.
    add("idle_info_page_view_and_close", [
        ("targets", []),
        ("poll",),
        ("repaint",),  # touch_surface == "idle" (reachable with no replay held)
        ("open_info",),
        ("repaint",),  # info page opens with seven placeholder rows
        ("list_page", 1),
        ("repaint",),  # second page (base: 3 rows/page, 3 pages total)
        ("close_list",),
        ("repaint",),  # back to idle
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
        # The matching status entry keeps the reconcile pass's own
        # re-fetch from clearing the seeded hold record straight back out
        # (open_picker() now refuses without a genuinely-held
        # affordance, so this scenario's own point needs it to survive).
        ("roster", [_idle_row("C29", aid, repeat_capable=True)]),
        ("status", {aid: _status_result(repeat=_repeat_obj(state="hold", available=True, recording_seconds=12.0))}),
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
        ("status", {aid: _status_result(repeat=_repeat_obj(state="hold", available=True, recording_seconds=12.0))}),
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
    add("picker_survives_repeated_idle_polls", [
        ("targets", []),
        # A held, authorized, repeat-capable roster row so the idle
        # affordance is due (open_picker() refuses without one —
        # see dial_display.DialDisplay.open_picker()); the matching status
        # entry keeps the reconcile pass's own re-fetch from clearing the
        # seeded hold record straight back out.
        ("roster", [_idle_row("C31", aid, repeat_capable=True)]),
        ("status", {aid: _status_result(repeat=_repeat_obj(state="hold", available=True))}),
        ("repeat_store_seed", aid, _repeat_obj(state="hold", available=True)),
        ("poll",),
        ("open_picker",),
        ("repaint",),
        ("poll",),
        ("poll",),
        ("advance", 5.0),
        ("poll",),
    ])

    # --- Outputs list / per-output detail (dial_outputs=v1) -----------------

    # The OUTPUTS zone is inert for an appliance that does not advertise the
    # capability: open_outputs() makes no request at all.
    aid = _aid("o1")
    t = _target("O1", aid, dial_outputs=False)
    add("outputs_open_refused_without_capability", [
        ("targets", [t]),
        ("poll",),
        ("open_outputs",),
        ("repaint",),
    ])

    # Opening shows "Loading" until the first fetch result lands, then the
    # fetched rows.
    aid = _aid("o2")
    t = _target("O2", aid, dial_outputs=True)
    add("outputs_open_loading_then_loaded", [
        ("targets", [t]),
        ("poll",),
        ("open_outputs",),
        ("repaint",),
        ("outputs_result", aid, 200, _outputs_body([
            ("1", "Bedroom", True, 40, False), ("2", "Kitchen", False, 0, False),
        ])),
        ("repaint",),
    ])

    # A LIST_ROW tap on the outputs list opens the per-output detail page;
    # its own back control returns to the outputs list (back_to="outputs"),
    # not main.
    aid = _aid("o3")
    t = _target("O3", aid, dial_outputs=True)
    add("outputs_row_tap_opens_detail_then_back_to_outputs", [
        ("targets", [t]),
        ("poll",),
        ("open_outputs",),
        ("repaint",),
        ("outputs_result", aid, 200, _outputs_body([("1", "Bedroom", True, 40, False)])),
        ("repaint",),
        ("outputs_row_tap", 0),
        ("repaint",),
        ("close_list",),
        ("repaint",),
    ])

    # A stale row index (the row vanished between paint and tap) is treated
    # as back to main, same as a stale selector/picker index.
    aid = _aid("o4")
    t = _target("O4", aid, dial_outputs=True)
    add("outputs_row_tap_stale_index_back_to_main", [
        ("targets", [t]),
        ("poll",),
        ("open_outputs",),
        ("repaint",),
        ("outputs_result", aid, 200, _outputs_body([("1", "Bedroom", True, 40, False)])),
        ("repaint",),
        ("outputs_row_tap", 9),
        ("repaint",),
    ])

    # A toggle tap sets an optimistic override at once, shown before the
    # worker's own reconciling fetch would ever land (none is driven here —
    # this scenario only exercises the manager-side state the tap sets).
    aid = _aid("o5")
    t = _target("O5", aid, dial_outputs=True)
    add("output_toggle_tap_sets_optimistic_override", [
        ("targets", [t]),
        ("poll",),
        ("open_outputs",),
        ("repaint",),
        ("outputs_result", aid, 200, _outputs_body([("1", "Bedroom", False, 0, False)])),
        ("repaint",),
        ("outputs_row_tap", 0),
        ("repaint",),
        ("output_toggle_tap",),
        ("repaint",),
    ])

    # A volume step also sets an optimistic override, clamped to [0, 100].
    aid = _aid("o6")
    t = _target("O6", aid, dial_outputs=True)
    add("output_volume_tap_steps_and_clamps", [
        ("targets", [t]),
        ("poll",),
        ("open_outputs",),
        ("repaint",),
        ("outputs_result", aid, 200, _outputs_body([("1", "Bedroom", True, 95, False)])),
        ("repaint",),
        ("outputs_row_tap", 0),
        ("repaint",),
        ("output_volume_tap", 10),
        ("repaint",),
        ("output_volume_tap", 10),
        ("repaint",),
    ])

    # The appliance's default output is flagged in the held rows; the trace
    # records which row it is from the result onwards.
    aid = _aid("o7d")
    t = _target("O7D", aid, dial_outputs=True)
    add("outputs_default_row_marked", [
        ("targets", [t]),
        ("poll",),
        ("open_outputs",),
        ("repaint",),
        ("outputs_result", aid, 200, _outputs_body([
            ("1", "Bedroom", True, 40, False, False), ("2", "Study", False, 0, False, True),
        ])),
        ("repaint",),
        ("outputs_row_tap", 1),
        ("repaint",),
        ("close_list",),
        ("repaint",),
    ])

    # A volume step on a disabled output is ignored (no level to step from).
    aid = _aid("o7")
    t = _target("O7", aid, dial_outputs=True)
    add("output_volume_tap_ignored_when_disabled", [
        ("targets", [t]),
        ("poll",),
        ("open_outputs",),
        ("repaint",),
        ("outputs_result", aid, 200, _outputs_body([("1", "Bedroom", False, 0, False)])),
        ("repaint",),
        ("outputs_row_tap", 0),
        ("repaint",),
        ("output_volume_tap", 10),
        ("repaint",),
    ])

    # An output that goes remote-in-use (or is removed) while its detail
    # page is open is dropped from the next fetch; the fold requests the
    # outputs list back.
    aid = _aid("o8")
    t = _target("O8", aid, dial_outputs=True)
    add("output_detail_row_vanishes_falls_back_to_list", [
        ("targets", [t]),
        ("poll",),
        ("open_outputs",),
        ("repaint",),
        ("outputs_result", aid, 200, _outputs_body([("1", "Bedroom", True, 40, False)])),
        ("repaint",),
        ("outputs_row_tap", 0),
        ("repaint",),
        ("outputs_result", aid, 200, _outputs_body([("1", "Bedroom", False, 0, True)])),
        ("repaint",),
    ])

    # The outputs list closes to main when the focused/reporting appliance
    # changes to a different one — the screen is bound to the appliance it
    # was opened for (ScreenPolicy.bound_to_appliance).
    aid_a, aid_b = _aid("o9a"), _aid("o9b")
    ta = _target("O9A", aid_a, dial_outputs=True, playing_since=1.0)
    tb = _target("O9B", aid_b, dial_outputs=True, playing_since=2.0)
    add("outputs_closes_when_reporting_appliance_changes", [
        ("targets", [ta]),
        ("poll",),
        ("open_outputs",),
        ("repaint",),
        ("outputs_result", aid_a, 200, _outputs_body([("1", "Bedroom", True, 40, False)])),
        ("repaint",),
        ("targets", [tb]),
        ("poll",),
    ])

    # An idle focus resolving to the SAME appliance the outputs list is
    # bound to keeps it open (IDLE_KEEP, and the bound-appliance check
    # agrees since the focus id is unchanged).
    aid = _aid("o10")
    t = _target("O10", aid, dial_outputs=True)
    add("outputs_stays_open_with_matching_idle_focus", [
        ("targets", [t]),
        ("poll",),
        ("set_manual_focus", aid),
        ("open_outputs",),
        ("repaint",),
        ("outputs_result", aid, 200, _outputs_body([("1", "Bedroom", True, 40, False)])),
        ("repaint",),
        ("targets", []),
        ("roster", [_idle_row("O10", aid, dial_outputs=True)]),
        ("poll",),
    ])

    # The per-output detail page closes to main (not back to the outputs
    # list) after its own inactivity timeout — the timeout rule always
    # returns to main; back_to governs only an explicit back tap.
    aid = _aid("o11")
    t = _target("O11", aid, dial_outputs=True)
    add("output_detail_timeout_closes_to_main", [
        ("targets", [t]),
        ("poll",),
        ("open_outputs",),
        ("repaint",),
        ("outputs_result", aid, 200, _outputs_body([("1", "Bedroom", True, 40, False)])),
        ("repaint",),
        ("outputs_row_tap", 0),
        ("repaint",),
        ("advance", SELECTOR_TIMEOUT_SECONDS + 1),
        ("check_timeout",),
    ])

    # Sleep pops the outputs list, same as every other secondary screen.
    aid = _aid("o12")
    t = _target("O12", aid, dial_outputs=True)
    add("sleep_pops_outputs_list", [
        ("targets", [t]),
        ("poll",),
        ("open_outputs",),
        ("repaint",),
        ("outputs_result", aid, 200, _outputs_body([("1", "Bedroom", True, 40, False)])),
        ("repaint",),
        ("sleep_locked",),
    ])

    # A malformed/unreachable fetch result is transient: the last good
    # snapshot stays on screen rather than reverting to "Loading".
    aid = _aid("o13")
    t = _target("O13", aid, dial_outputs=True)
    add("outputs_fetch_failure_keeps_last_snapshot", [
        ("targets", [t]),
        ("poll",),
        ("open_outputs",),
        ("repaint",),
        ("outputs_result", aid, 200, _outputs_body([("1", "Bedroom", True, 40, False)])),
        ("repaint",),
        ("outputs_result", aid, 500, None),
        ("repaint",),
    ])

    # A late fetch result for an appliance the screen has since moved on
    # from (a different one now bound) is dropped.
    aid_a, aid_b = _aid("o14a"), _aid("o14b")
    ta = _target("O14A", aid_a, dial_outputs=True, playing_since=1.0)
    add("outputs_late_result_for_previous_appliance_dropped", [
        ("targets", [ta]),
        ("poll",),
        ("open_outputs",),
        ("repaint",),
        ("outputs_result", aid_a, 200, _outputs_body([("1", "Bedroom", True, 40, False)])),
        ("repaint",),
        ("targets", []),
        ("poll",),
        ("outputs_result", aid_a, 200, _outputs_body([("1", "Bedroom", False, 0, False)])),
        ("repaint",),
    ])

    # An enable the appliance refuses because the speaker wants a PIN puts
    # the pairing hint over the output page; closing it returns there.
    aid = _aid("o15")
    t = _target("O15", aid, dial_outputs=True)
    add("output_pin_required_shows_pair_page_and_returns", [
        ("targets", [t]),
        ("poll",),
        ("open_outputs",),
        ("repaint",),
        ("outputs_result", aid, 200, _outputs_body([("1", "Apple TV", False, 0, False)])),
        ("repaint",),
        ("outputs_row_tap", 0),
        ("repaint",),
        ("output_toggle_tap",),
        ("repaint",),
        ("outputs_set_result", aid, 200, {"ok": False, "pin_required": True, "error": "Output requires PIN"}),
        ("repaint",),
        ("close_list",),
        ("repaint",),
    ])

    # A row already known to need pairing shows the hint at the tap, with
    # no request sent (no request outcome is recorded).
    aid = _aid("o16")
    t = _target("O16", aid, dial_outputs=True)
    add("output_needs_pin_row_shows_pair_page_without_sending", [
        ("targets", [t]),
        ("poll",),
        ("open_outputs",),
        ("repaint",),
        ("outputs_result", aid, 200, _outputs_body([("1", "Apple TV", False, 0, False, False, True)])),
        ("repaint",),
        ("outputs_row_tap", 0),
        ("repaint",),
        ("output_toggle_tap",),
        ("repaint",),
    ])

    # An artwork tap hides the always-shown controls for a window; a
    # housekeeping tick before the window ends leaves them hidden, one
    # after it ends brings them back.
    aid = _aid("a1")
    t = _target("A1", aid)
    add("artwork_tap_hides_controls_then_expires", [
        ("targets", [t]),
        ("status", {aid: _status_result()}),
        ("update_config", {"always_show_controls": True}),
        ("poll",),
        ("repaint",),
        ("hide_controls",),
        ("repaint",),
        ("advance", 3.0),
        ("tick_controls_hidden",),
        ("repaint",),
        ("advance", 4.0),
        ("tick_controls_hidden",),
        ("repaint",),
    ])

    # A direct switch from one playing appliance to another (no gap in
    # between) pushes a brief dark transition frame before the new
    # appliance's own logo/artwork lands, so the previous one's artwork
    # never lingers under the new name.
    aid_a, aid_b = _aid("t1a"), _aid("t1b")
    ta = _target("T1A", aid_a, playing_since=1.0)
    tb = _target("T1B", aid_b, playing_since=2.0)
    add("device_switch_pushes_transition_frame", [
        ("targets", [ta]),
        ("poll",),
        ("targets", [tb]),
        ("poll",),
    ])

    # --- Sticky binding to the shown playing appliance (items 2 and 3) -----
    # A = oldest playing, B = later starter, art(X) = an identified track
    # with artwork on X. Each scenario name states the case it pins.

    aid_a = _aid("bd1")
    ta = _target("BD1A", aid_a, playing_since=1.0)
    add("binding_binds_on_the_first_tick", [
        ("targets", [ta]),
        ("status", {aid_a: _status_result(track_id=None)}),
        ("poll",),
    ])

    aid_a, aid_b = _aid("bd2a"), _aid("bd2b")
    ta = _target("BD2A", aid_a, playing_since=1.0)
    tb = _target("BD2B", aid_b, playing_since=2.0)
    add("binding_second_starter_with_no_artwork_on_bound_does_not_steal", [
        ("targets", [ta]),
        ("status", {aid_a: _status_result(track_id=None)}),
        ("poll",),
        ("targets", [ta, tb]),
        ("status", {aid_a: _status_result(track_id=None), aid_b: _status_result(track_id=_art("bd2b"))}),
        ("poll",),
    ])

    aid_a, aid_b = _aid("bd3a"), _aid("bd3b")
    ta = _target("BD3A", aid_a, playing_since=1.0)
    tb = _target("BD3B", aid_b, playing_since=2.0)
    add("binding_second_starter_with_both_identified_still_does_not_steal", [
        ("targets", [ta]),
        ("status", {aid_a: _status_result(track_id=_art("bd3a"))}),
        ("poll",),
        ("targets", [ta, tb]),
        ("status", {aid_a: _status_result(track_id=_art("bd3a")), aid_b: _status_result(track_id=_art("bd3b"))}),
        ("poll",),
    ])

    aid_a, aid_b = _aid("bd4a"), _aid("bd4b")
    ta = _target("BD4A", aid_a, playing_since=1.0)
    tb = _target("BD4B", aid_b, playing_since=2.0)
    add("binding_track_change_on_a_non_shown_appliance_is_invisible", [
        ("targets", [ta, tb]),
        ("status", {aid_a: _status_result(track_id=_art("bd4a")), aid_b: _status_result(track_id=_art("bd4b1"))}),
        ("poll",),
        ("status", {aid_b: _status_result(track_id=_art("bd4b2"))}),
        ("poll",),
    ])

    aid_a = _aid("bd5")
    ta = _target("BD5A", aid_a, playing_since=1.0)
    add("binding_track_change_on_the_bound_appliance_updates_artwork", [
        ("targets", [ta]),
        ("status", {aid_a: _status_result(track_id=_art("bd5v1"))}),
        ("poll",),
        ("status", {aid_a: _status_result(track_id=_art("bd5v2"))}),
        ("poll",),
    ])

    aid_a, aid_b = _aid("bd6a"), _aid("bd6b")
    ta = _target("BD6A", aid_a, playing_since=1.0)
    tb = _target("BD6B", aid_b, playing_since=2.0)
    add("binding_bound_appliance_stops_rebinds_to_the_survivor", [
        ("targets", [ta]),
        ("status", {aid_a: _status_result(track_id=_art("bd6a"))}),
        ("poll",),
        ("targets", [tb]),
        ("status", {aid_b: _status_result(track_id=_art("bd6b"))}),
        ("poll",),
    ])

    aid_a = _aid("bd7")
    ta = _target("BD7A", aid_a, playing_since=1.0)
    add("binding_bound_appliance_stops_nothing_playing_releases_to_idle", [
        ("targets", [ta]),
        ("status", {aid_a: _status_result(track_id=None)}),
        ("poll",),
        ("targets", []),
        ("poll",),
    ])

    aid_a, aid_b = _aid("bd8a"), _aid("bd8b")
    ta = _target("BD8A", aid_a, playing_since=1.0)
    tb = _target("BD8B", aid_b, playing_since=2.0)
    add("binding_survives_the_original_appliance_returning", [
        ("targets", [ta, tb]),
        ("status", {aid_a: _status_result(track_id=None), aid_b: _status_result(track_id=None)}),
        ("poll",),
        ("targets", [tb]),
        ("poll",),
        ("targets", [ta, tb]),
        ("poll",),
    ])

    aid_a, aid_b = _aid("bd9a"), _aid("bd9b")
    ta = _target("BD9A", aid_a, playing_since=1.0)
    tb = _target("BD9B", aid_b, playing_since=2.0)
    add("binding_selector_pick_sets_manual_focus_and_binding_mirrors_it", [
        ("targets", [ta, tb]),
        ("status", {aid_a: _status_result(track_id=None), aid_b: _status_result(track_id=None)}),
        ("poll",),
        ("open_selector",),
        ("repaint",),
        ("list_row_tap", 1),
        ("poll",),
    ])

    aid_a, aid_b = _aid("bd10a"), _aid("bd10b")
    ta = _target("BD10A", aid_a, playing_since=1.0)
    tb = _target("BD10B", aid_b, playing_since=2.0)
    add("binding_picked_appliance_stops_other_still_playing_rebinds", [
        ("targets", [ta, tb]),
        ("status", {aid_a: _status_result(track_id=None), aid_b: _status_result(track_id=None)}),
        ("poll",),
        ("set_manual_focus", aid_b),
        ("poll",),
        ("targets", [ta]),
        ("poll",),
    ])

    aid_a, aid_b = _aid("bd11a"), _aid("bd11b")
    ta = _target("BD11A", aid_a, playing_since=1.0)
    tb = _target("BD11B", aid_b, playing_since=2.0)
    add("binding_picked_appliance_stops_nothing_else_playing_goes_idle", [
        ("targets", [ta, tb]),
        ("status", {aid_a: _status_result(track_id=None), aid_b: _status_result(track_id=None)}),
        ("poll",),
        ("set_manual_focus", aid_b),
        ("poll",),
        ("targets", []),
        ("poll",),
    ])

    aid_a, aid_x = _aid("bd12a"), _aid("bd12x")
    ta = _target("BD12A", aid_a, playing_since=1.0)
    idle_x = _idle_row("BD12X", aid_x, repeat_capable=False)
    add("binding_idle_focus_pick_is_unaffected_by_another_appliance", [
        ("targets", [ta]),
        ("status", {aid_a: _status_result(track_id=None)}),
        ("roster", [_roster_row_for_target(ta), idle_x]),
        ("poll",),
        ("set_manual_focus", aid_x),
        ("poll",),
        ("targets", []),
        ("roster", [idle_x]),
        ("poll",),
        ("targets", [ta]),
        ("roster", [_roster_row_for_target(ta), idle_x]),
        ("poll",),
    ])

    aid_a, aid_b = _aid("bd13a"), _aid("bd13b")
    ta = _target("BD13A", aid_a, playing_since=1.0)
    tb = _target("BD13B", aid_b, playing_since=2.0)
    add("binding_bound_appliance_unauthorized_mid_tick_releases_and_continues", [
        ("targets", [ta, tb]),
        ("status", {aid_a: _status_result(track_id=None), aid_b: _status_result(track_id=None)}),
        ("poll",),
        ("status", {
            aid_a: _status_result(status_error="unauthorized"),
            aid_b: _status_result(track_id=_art("bd13b")),
        }),
        ("poll",),
    ])

    aid_a, aid_b = _aid("bd14a"), _aid("bd14b")
    ta = _target("BD14A", aid_a, playing_since=1.0)
    tb = _target("BD14B", aid_b, playing_since=2.0)
    add("binding_boot_with_two_playing_only_one_identified_binds_to_it", [
        ("targets", [ta, tb]),
        ("status", {aid_a: _status_result(track_id=None), aid_b: _status_result(track_id=_art("bd14b"))}),
        ("poll",),
    ])

    # ---- Wi-Fi link state machine: the idle icon and the No-WiFi page ----

    add("nowifi_streak_of_three_opens_then_connected_closes", [
        ("targets", []),
        ("poll",),
        ("network", LINK_CONNECTED, 3),
        ("repaint",),
        ("network", LINK_DOWN),
        ("repaint",),
        ("network", LINK_DOWN),
        ("repaint",),
        ("network", LINK_DOWN),
        ("repaint",),
        ("network", LINK_CONNECTED, 3),
        ("repaint",),
    ])

    add("nowifi_dismiss_suppresses_until_connected", [
        ("targets", []),
        ("poll",),
        ("network", LINK_CONNECTED, 3),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("repaint",),
        ("nowifi_dismiss",),
        ("repaint",),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("repaint",),
        ("network", LINK_CONNECTED, 2),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("repaint",),
    ])

    add("nowifi_unknown_does_not_break_the_streak", [
        ("targets", []),
        ("poll",),
        ("network", LINK_CONNECTED, 3),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("network", LINK_UNKNOWN),
        ("network", LINK_DOWN),
        ("repaint",),
    ])

    add("nowifi_ignored_resets_the_streak", [
        ("targets", []),
        ("poll",),
        ("network", LINK_CONNECTED, 3),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("network", LINK_IGNORED),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("repaint",),
    ])

    add("nowifi_icon_tap_reopens_after_dismiss", [
        ("targets", []),
        ("poll",),
        ("network", LINK_CONNECTED, 3),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("repaint",),
        ("nowifi_dismiss",),
        ("repaint",),
        ("open_nowifi",),
        ("repaint",),
    ])

    add("nowifi_never_opens_over_the_info_page", [
        ("targets", []),
        ("poll",),
        ("network", LINK_CONNECTED, 3),
        ("open_info",),
        ("repaint",),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("repaint",),
        ("close_list",),
        ("repaint",),
        ("network", LINK_DOWN),
        ("repaint",),
    ])

    add("nowifi_restart_shows_restarting_then_times_out", [
        ("targets", []),
        ("poll",),
        ("network", LINK_CONNECTED, 3),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("repaint",),
        ("nowifi_restart",),
        ("repaint",),
        ("advance", dd.RESTARTING_TIMEOUT_SECONDS + 1),
        ("check_timeout",),
        ("repaint",),
    ])

    add("nowifi_flash_tick_repaints_idle", [
        ("targets", []),
        ("poll",),
        ("network", LINK_CONNECTED, 3),
        ("network", LINK_DOWN),
        ("tick_wifi_flash",),
        ("repaint",),
        ("advance", 0.5),
        ("tick_wifi_flash",),
        ("repaint",),
    ])

    add("nowifi_sleep_pops_the_page", [
        ("targets", []),
        ("poll",),
        ("network", LINK_CONNECTED, 3),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("repaint",),
        ("sleep_locked",),
        ("repaint",),
    ])

    add("nowifi_never_connected_flashes_but_never_prompts", [
        ("targets", []),
        ("poll",),
        ("repaint",),
        ("network", LINK_DOWN),
        ("repaint",),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("repaint",),                      # still main: no auto-prompt before a first connection
        ("tick_wifi_flash",),
        ("advance", 0.5),
        ("repaint",),
        ("network", LINK_CONNECTED, 2),   # first connection: latch set
        ("repaint",),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("repaint",),                      # now a loss: the page opens
    ])

    add("nowifi_never_connected_icon_tap_opens_the_page", [
        ("targets", []),
        ("poll",),
        ("network", LINK_DOWN),
        ("repaint",),
        ("open_nowifi",),
        ("repaint",),
        ("nowifi_dismiss",),
        ("repaint",),
    ])

    # ---- SD card health warning: opened by the health reader, closed by
    # Dismiss/timeout/a recovered reading; never opens over the No-WiFi page.

    add("sdhealth_low_opens_then_recovered_closes", [
        ("targets", []),
        ("poll",),
        ("sd_health_view", STATUS_VALID, 15),
        ("repaint",),
        ("sd_health_view", STATUS_VALID, 26),
        ("repaint",),
    ])

    add("sdhealth_dismiss_suppresses_until_recovered", [
        ("targets", []),
        ("poll",),
        ("sd_health_view", STATUS_VALID, 15),
        ("repaint",),
        ("sdhealth_dismiss",),
        ("repaint",),
        ("sd_health_view", STATUS_VALID, 14),
        ("repaint",),
        ("sd_health_view", STATUS_VALID, 26),
        ("repaint",),
        ("sd_health_view", STATUS_VALID, 10),
        ("repaint",),
    ])

    add("sdhealth_hysteresis_holds_between_thresholds", [
        ("targets", []),
        ("poll",),
        ("sd_health_view", STATUS_VALID, 15),
        ("repaint",),
        ("sd_health_view", STATUS_VALID, 26),
        ("repaint",),
        ("sd_health_view", STATUS_VALID, 23),
        ("repaint",),
    ])

    add("sdhealth_never_opens_over_the_nowifi_page", [
        ("targets", []),
        ("poll",),
        ("network", LINK_CONNECTED, 3),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("repaint",),
        ("sd_health_view", STATUS_VALID, 10),
        ("repaint",),
        ("nowifi_dismiss",),
        ("repaint",),
        ("sd_health_view", STATUS_VALID, 9),
        ("repaint",),
    ])

    add("sdhealth_has_no_timeout", [
        ("targets", []),
        ("poll",),
        ("sd_health_view", STATUS_VALID, 15),
        ("repaint",),
        ("advance", 3600.0),
        ("check_timeout",),
        ("repaint",),
    ])

    # ---- Warning re-show: wake and the once-a-second tick ----

    add("sdhealth_sleep_then_wake_reshows", [
        ("targets", []),
        ("poll",),
        ("sd_health_view", STATUS_VALID, 15),
        ("repaint",),
        ("sleep_locked",),
        ("repaint",),
        ("notify_touch_activity",),
        ("repaint",),
    ])

    add("nowifi_sleep_then_wake_reshows", [
        ("targets", []),
        ("poll",),
        ("network", LINK_CONNECTED, 3),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("repaint",),
        ("sleep_locked",),
        ("repaint",),
        ("notify_touch_activity",),
        ("repaint",),
    ])

    add("sdhealth_dismiss_then_wake_stays_snoozed", [
        ("targets", []),
        ("poll",),
        ("sd_health_view", STATUS_VALID, 15),
        ("repaint",),
        ("sdhealth_dismiss",),
        ("repaint",),
        ("sleep_locked",),
        ("repaint",),
        ("notify_touch_activity",),
        ("repaint",),
    ])

    add("sdhealth_snooze_expires_and_reshows", [
        ("targets", []),
        ("poll",),
        ("sd_health_view", STATUS_VALID, 15),
        ("repaint",),
        ("sdhealth_dismiss",),
        ("repaint",),
        ("advance", 604801.0),
        ("tick_warnings",),
        ("repaint",),
    ])

    add("sdhealth_critical_snooze_is_one_day", [
        ("targets", []),
        ("poll",),
        ("sd_health_view", STATUS_VALID, 2),
        ("repaint",),
        ("sdhealth_dismiss",),
        ("repaint",),
        ("advance", 86401.0),
        ("tick_warnings",),
        ("repaint",),
    ])

    add("sdhealth_pending_behind_info_shows_on_tick_after_close", [
        ("targets", []),
        ("poll",),
        ("open_info",),
        ("repaint",),
        ("sd_health_view", STATUS_VALID, 15),
        ("repaint",),
        ("close_list",),
        ("repaint",),
        ("tick_warnings",),
        ("repaint",),
    ])

    add("warnings_nowifi_outranks_sdhealth_when_both_pending", [
        ("targets", []),
        ("poll",),
        ("network", LINK_CONNECTED, 3),
        ("open_info",),
        ("repaint",),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("network", LINK_DOWN),
        ("sd_health_view", STATUS_VALID, 10),
        ("repaint",),
        ("close_list",),
        ("repaint",),
        ("tick_warnings",),
        ("repaint",),               # nowifi wins on priority
        ("nowifi_dismiss",),
        ("repaint",),
        ("tick_warnings",),
        ("repaint",),               # sdhealth follows once nowifi is dismissed
    ])

    # An appliance's warnings page below every warning of the dial's own:
    # the SD card warning shows first, then the critical stylus warning (a
    # week's snooze), then the belt warning (a day's). The day's snooze
    # runs out and only the belt page returns.
    aid = _aid("aw1")
    lounge = _idle_row("Lounge", aid)
    add("appliance_warning_pages_below_sdhealth", [
        ("roster", [lounge]),
        ("poll",),
        ("repaint",),
        ("appliance_warnings", aid, [
            ("stylus_in1", "critical", "Technics stylus", "Needs changing now.", "week"),
            ("belt_in1", "warning", "Drive belt", "Service due soon.", "day"),
        ]),
        ("sd_health_view", STATUS_VALID, 12),
        ("repaint",),               # sdhealth first
        ("sdhealth_dismiss",),
        ("repaint",),
        ("tick_warnings",),
        ("repaint",),               # then the most severe appliance warning
        ("appliance_tap",),
        ("repaint",),
        ("tick_warnings",),
        ("repaint",),               # the next one follows the Dismiss
        ("appliance_tap",),
        ("repaint",),
        ("tick_warnings",),
        ("repaint",),               # nothing left
        ("advance", 86401.0),
        ("tick_warnings",),
        ("repaint",),               # the day's snooze is over, the week's is not
        ("appliance_tap",),
        ("repaint",),
    ])

    # A notice (dismissal "none") has one OK cell that holds until the
    # appliance stops reporting it: a long wait and the same report again
    # bring nothing back, a fresh report after it was cleared does, and the
    # appliance withdrawing it closes the open page.
    aid = _aid("aw2")
    kitchen = _idle_row("Kitchen", aid)
    notice = [("fw", "info", "Firmware", "Updated to 2.0.", "none")]
    add("appliance_warning_ok_holds_until_cleared", [
        ("roster", [kitchen]),
        ("poll",),
        ("repaint",),
        ("appliance_warnings", aid, notice),
        ("tick_warnings",),
        ("repaint",),               # the notice, one OK cell
        ("appliance_tap",),
        ("repaint",),               # OK: back to idle
        ("advance", 30 * 86400.0),
        ("tick_warnings",),
        ("repaint",),
        ("appliance_warnings", aid, notice),
        ("tick_warnings",),
        ("repaint",),               # unchanged report: still away
        ("appliance_warnings", aid, []),
        ("appliance_warnings", aid, notice),
        ("tick_warnings",),
        ("repaint",),               # a new incident shows again
        ("appliance_warnings", aid, []),
        ("tick_warnings",),
        ("repaint",),               # withdrawn while up: the page closes
    ])

    return scenarios


# ---------------------------------------------------------------------------
# Compact-tier scenarios: the 1.3in 240x240 profile's default diagonal
# already resolves the compact content tier (see dial_touch_layout.
# metrics_for) — each scenario below carries its own (cfg, backend) pair for
# _run_scenario, since every scenario above shares the module's default
# 128x160 base-tier fixture.
# ---------------------------------------------------------------------------

def _compact_display_args() -> tuple[DialDisplayConfig, "FakeBackend"]:
    fb = FakeBackend()
    fb.width, fb.height = 240, 240
    cfg = DialDisplayConfig(fitted=True, screen_type="st7789_240x240")
    return cfg, fb


def _compact_scenarios() -> list[tuple[str, list[tuple], dict]]:
    scenarios: list[tuple[str, list[tuple], dict]] = []

    # Playing 2x2 (held without always_show_controls) -> a mute press ->
    # repeat (enable layout) -> repeat_replay (replaying layout, once the
    # daemon starts one) -> a time-tap back to the playing 2x2.
    aid = _aid("cp1")
    t = _target("CP1", aid)
    cfg, fb = _compact_display_args()
    scenarios.append((
        "compact_playing_mute_repeat_and_repeat_replay_time_tap_back",
        [
            ("targets", [t]),
            ("status", {aid: _status_result(repeat=_repeat_obj(state="idle", available=True))}),
            ("poll",),
            ("repaint",),  # touch_surface == "held" -- compact holds with no always_show_controls
            ("set_pressed", TouchZone.MUTE, None),
            ("repaint",),
            ("toggle_repeat",),
            ("repaint",),  # touch_surface == "repeat" (compact enable layout)
            ("status", {aid: _status_result(repeat=_repeat_obj(
                state="replaying", available=True, armed=True,
                replay={"active": True, "position_seconds": 2.0, "duration_seconds": 30.0},
            ))}),
            ("poll",),
            ("repaint",),  # touch_surface == "repeat_replay" (compact replaying layout)
            ("toggle_repeat",),  # the time strip's own DOTS zone: tap = back
            ("repaint",),  # touch_surface == "held" again; reveal armed
        ],
        {"cfg": cfg, "backend": fb},
    ))

    # A picker with three held rows (rows_per_page == 2 on compact): each
    # appliance is seen playing first (so the auth map has already confirmed
    # it and a later reconcile pass never re-probes it away), then goes
    # idle with a retained recording -- the idle screen's replay affordance
    # and the picker's own rows both come from the same roster. Paging past
    # the last page wraps back to page 0 instead of clamping there.
    cfg2, fb2 = _compact_display_args()
    aids = [_aid(f"cp2_{i}") for i in range(3)]
    targets = [_target(f"CP2-{i}", aids[i], playing_since=float(i)) for i in range(3)]
    statuses = {
        a: _status_result(repeat=_repeat_obj(state="hold", available=True, recording_seconds=10.0 * (i + 1)))
        for i, a in enumerate(aids)
    }
    rows = [_idle_row(f"CP2-{i}", aids[i], repeat_capable=True) for i in range(3)]
    scenarios.append((
        "compact_picker_more_wraps_past_the_last_page",
        [
            ("targets", targets),
            ("status", statuses),
            ("poll",),  # each appliance seen playing at least once
            ("targets", []),
            ("roster", rows),
            ("poll",),  # all three now idle, held, on the roster
            ("open_picker",),
            ("repaint",),  # page 0: CP2-0, CP2-1
            ("list_page", 1),
            ("repaint",),  # page 1: CP2-2 alone
            ("list_page", 1),
            ("repaint",),  # wraps back to page 0, not clamped at page 1
        ],
        {"cfg": cfg2, "backend": fb2},
    ))

    # The idle screen's own "i" affordance on compact: open the info page,
    # page through all four (2-rows-per-page, seven fields) pages, wrapping
    # back to the first, tap a row to open its own drill-in value view, tap
    # anywhere to return to the list (at the same page), then X back to idle.
    cfg3, fb3 = _compact_display_args()
    scenarios.append((
        "compact_idle_info_page_view_and_close",
        [
            ("targets", []),
            ("poll",),
            ("repaint",),  # touch_surface == "idle"
            ("open_info",),
            ("repaint",),  # info page opens; compact shows 2 rows/page across 4 pages (7 fields)
            ("list_page", 1),
            ("repaint",),
            ("list_page", 1),
            ("repaint",),
            ("list_page", 1),
            ("repaint",),
            ("list_page", 1),  # wraps back to page 0, not clamped
            ("repaint",),
            ("list_row_tap", 0),  # opens the tapped field's own value view
            ("repaint",),
            ("close_list",),  # tap anywhere on the value view -> back to the list
            ("repaint",),
            ("close_list",),  # X on the list -> back to idle
            ("repaint",),  # back to idle
        ],
        {"cfg": cfg3, "backend": fb3},
    ))

    # The No-WiFi page on compact (the full-screen 2x2, no card): a streak
    # of three down polls opens it, Dismiss returns to idle.
    cfg4, fb4 = _compact_display_args()
    scenarios.append((
        "compact_nowifi_page_and_dismiss",
        [
            ("targets", []),
            ("poll",),
            ("network", LINK_CONNECTED, 3),
            ("repaint",),  # touch_surface == "idle"
            ("network", LINK_DOWN),
            ("network", LINK_DOWN),
            ("network", LINK_DOWN),
            ("repaint",),  # opens the No-WiFi page, full-screen 2x2
            ("nowifi_dismiss",),
            ("repaint",),  # back to idle; icon keeps flashing
        ],
        {"cfg": cfg4, "backend": fb4},
    ))

    # The SD card warning on compact (the full-screen card, no vertical
    # divider): a low reading opens it, Dismiss returns to idle.
    cfg5, fb5 = _compact_display_args()
    scenarios.append((
        "compact_sdhealth_warning_and_dismiss",
        [
            ("targets", []),
            ("poll",),
            ("repaint",),  # touch_surface == "idle"
            ("sd_health_view", STATUS_VALID, 12),
            ("repaint",),  # opens the SD warning, full-screen card
            ("sdhealth_dismiss",),
            ("repaint",),  # back to idle
        ],
        {"cfg": cfg5, "backend": fb5},
    ))

    return scenarios


def _rich_display_args() -> tuple[DialDisplayConfig, "FakeBackend"]:
    """A 320x240 panel at its shipped density, resolving the rich content
    tier (the right-hand rail list chassis, 5 rows/page) — mirrors
    _compact_display_args()'s own shape for the richer tier."""
    fb = FakeBackend()
    fb.width, fb.height = 320, 240
    cfg = DialDisplayConfig(fitted=True, screen_type="ili9341_320x240")
    return cfg, fb


def _rich_scenarios() -> list[tuple[str, list[tuple], dict]]:
    scenarios: list[tuple[str, list[tuple], dict]] = []

    # The idle screen's own "i" affordance on the rich tier: open the info
    # page (5 rows on page 0, 2 on page 1 -- the rail chevrons, not a bottom
    # bar), page to the second, then X back to idle.
    cfg, fb = _rich_display_args()
    scenarios.append((
        "rich_idle_info_page_view_and_close",
        [
            ("targets", []),
            ("poll",),
            ("repaint",),  # touch_surface == "idle"
            ("open_info",),
            ("repaint",),  # info page opens with seven placeholder rows
            ("list_page", 1),
            ("repaint",),  # second page: the sixth and seventh rows
            ("close_list",),
            ("repaint",),  # back to idle
        ],
        {"cfg": cfg, "backend": fb},
    ))

    # The EQ page on the rich tier: an EQ-capable appliance with no held
    # repeat record cycles straight from main to eq (skipping repeat), a
    # bass step shows an optimistic value at once, a fetch result folds in
    # and clears it, then cycling again closes back to main.
    cfg2, fb2 = _rich_display_args()
    eq_aid = _aid("eqrich")
    eq_target = _target("EqLiving", eq_aid, dial_eq=True)
    scenarios.append((
        "rich_eq_page_cycle_step_and_close",
        [
            ("targets", [eq_target]),
            ("status", {eq_aid: _status_result(appliance_id=eq_aid)}),
            ("poll",),
            ("repaint",),  # main, three dots (eq available, no repeat record)
            ("cycle_pages",),  # main -> eq
            ("repaint",),
            ("eq_result", eq_aid, 200, {"ok": True, "bass_db": 0, "treble_db": 0}),
            ("repaint",),  # bars now loaded at 0/0
            ("eq_step", "bass", 1),
            ("repaint",),  # optimistic bass=1 shown at once
            ("eq_result", eq_aid, 200, {"ok": True, "bass_db": 1, "treble_db": 0}),
            ("repaint",),  # reconciled, optimistic cleared
            ("cycle_pages",),  # eq -> main
            ("repaint",),
        ],
        {"cfg": cfg2, "backend": fb2},
    ))

    # The No-WiFi page on the rich tier (a centred card): a streak of three
    # down polls opens it, Restart shows "Restarting..." and asks for the
    # reboot, then that screen times out back to main when the (mocked)
    # reboot request never actually brings the box down.
    cfg3, fb3 = _rich_display_args()
    scenarios.append((
        "rich_nowifi_page_and_restart",
        [
            ("targets", []),
            ("poll",),
            ("network", LINK_CONNECTED, 3),
            ("repaint",),  # touch_surface == "idle"
            ("network", LINK_DOWN),
            ("network", LINK_DOWN),
            ("network", LINK_DOWN),
            ("repaint",),  # opens the No-WiFi page, centred card
            ("nowifi_restart",),
            ("repaint",),  # "Restarting..."
            ("advance", dd.RESTARTING_TIMEOUT_SECONDS + 1),
            ("check_timeout",),
            ("repaint",),  # falls back to main
        ],
        {"cfg": cfg3, "backend": fb3},
    ))

    # The SD card warning on the rich tier (a centred card): a low reading
    # opens it, Dismiss returns to main.
    cfg4, fb4 = _rich_display_args()
    scenarios.append((
        "rich_sdhealth_warning_and_dismiss",
        [
            ("targets", []),
            ("poll",),
            ("repaint",),  # touch_surface == "idle"
            ("sd_health_view", STATUS_VALID, 12),
            ("repaint",),  # opens the SD warning, centred card
            ("sdhealth_dismiss",),
            ("repaint",),  # back to idle
        ],
        {"cfg": cfg4, "backend": fb4},
    ))

    # An artwork tap on the rich tier with the controls held: the tap only
    # opens the hide window, the first repaint after it is still the ordinary
    # frame (the slide starts there), the surface reads "hidden" throughout,
    # a mid-slide repaint and the settled one each push one frame, and the
    # window's end brings the held controls back.
    cfg5, fb5 = _rich_display_args()
    aid5 = _aid("rs1")
    t5 = _target("RS1", aid5)
    scenarios.append((
        "rich_artwork_tap_slides_then_settles",
        [
            ("targets", [t5]),
            ("status", {aid5: _status_result()}),
            ("update_config", {"always_show_controls": True}),
            ("poll",),
            ("repaint",),  # touch_surface == "held"
            ("hide_controls",),
            ("repaint",),  # slide begins at progress 0
            ("advance", 0.2),
            ("tick_controls_reveal",),
            ("repaint",),  # mid-slide
            ("advance", 0.4),
            ("tick_controls_reveal",),
            ("repaint",),  # settled, bare
            ("advance", 6.0),
            ("tick_controls_hidden",),
            ("repaint",),  # window over, "held" again
        ],
        {"cfg": cfg5, "backend": fb5},
    ))

    # The same reveal on the replay screen while a replay runs: the tap
    # opens the window and the surface reads "hidden" (no Restart/Stop to
    # hit), the counter keeps ticking and repainting underneath, and the
    # window's end brings the replaying controls back.
    cfg6, fb6 = _rich_display_args()
    aid6 = _aid("rs2")
    t6 = _target("RS2", aid6)
    replaying = _repeat_obj(
        state="replaying", available=True, armed=True,
        replay={"active": True, "position_seconds": 2.0, "duration_seconds": 30.0},
    )
    scenarios.append((
        "rich_replay_artwork_tap_hides_and_counter_ticks",
        [
            ("targets", [t6]),
            ("status", {aid6: _status_result(repeat=replaying)}),
            ("poll",),
            ("toggle_repeat",),
            ("repaint",),  # touch_surface == "repeat", replaying layout
            ("hide_controls",),
            ("repaint",),  # slide begins at progress 0, surface "hidden"
            ("advance", 1.0),
            ("tick_repeat_line",),
            ("repaint",),  # the counter's next second, controls still hidden
            ("advance", 1.0),
            ("tick_repeat_line",),
            ("repaint",),
            ("advance", 6.0),
            ("tick_controls_hidden",),
            ("repaint",),  # window over, "repeat" again
        ],
        {"cfg": cfg6, "backend": fb6},
    ))

    return scenarios


# ---------------------------------------------------------------------------
# Seeded random walks — a few hundred steps each, exercising interactions
# nobody scripted above.
# ---------------------------------------------------------------------------

_ZONES = [
    TouchZone.UP, TouchZone.DOWN, TouchZone.NAME, TouchZone.DOTS, TouchZone.MUTE,
    TouchZone.LIST_ROW, TouchZone.LIST_BACK, TouchZone.LIST_UP, TouchZone.LIST_DOWN,
    TouchZone.REPEAT_PLAY, TouchZone.REPEAT_START, TouchZone.REPEAT_STOP, TouchZone.IDLE_REPLAY,
    TouchZone.OUTPUTS, TouchZone.OUTPUT_BACK, TouchZone.OUTPUT_TOGGLE,
    TouchZone.OUTPUT_UP, TouchZone.OUTPUT_DOWN,
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
    + ["open_outputs"] * 2 + ["outputs_row_tap"] * 2 + ["output_toggle_tap"] * 2
    + ["output_volume_tap"] * 2 + ["outputs_result"] * 3 + ["tick_outputs_refresh"] * 2
)


def _random_walk_steps(seed: int, n_steps: int, tag: str) -> list[tuple]:
    rng = random.Random(seed)
    aids = [_aid(f"{tag}_{i}") for i in range(3)]
    targets_full = [
        _target(f"{tag.upper()}{i}", aids[i], playing_since=float(i), dial_outputs=True)
        for i in range(3)
    ]
    idle_row = _idle_row(f"{tag}Idle", _aid(f"{tag}_idle"), repeat_capable=True, dial_outputs=True)

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
        elif kind == "outputs_row_tap":
            steps.append(("outputs_row_tap", rng.randint(0, 4)))
        elif kind == "output_volume_tap":
            steps.append(("output_volume_tap", rng.choice([-10, -1, 1, 10])))
        elif kind == "outputs_result":
            aid = rng.choice(aids)
            if rng.random() < 0.15:
                steps.append(("outputs_result", aid, 500, None))
            else:
                n_rows = rng.randint(0, 3)
                rows = [
                    (str(i), f"Output{i}", rng.random() < 0.5, rng.randint(0, 100), rng.random() < 0.2)
                    for i in range(n_rows)
                ]
                steps.append(("outputs_result", aid, 200, _outputs_body(rows)))
        else:
            # open_selector / open_picker / toggle_repeat / close_list /
            # notify_touch_activity / poll / repaint / check_timeout /
            # tick_repeat_line / open_outputs / output_toggle_tap /
            # tick_outputs_refresh — no arguments.
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
        for name, steps, kwargs in _compact_scenarios() + _rich_scenarios():
            result[name] = _run_scenario(steps, **kwargs)

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

    def test_the_renamed_picker_scenario_is_present_under_its_new_name(self):
        golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
        assert "picker_touch_restarts_timeout" in golden
        assert "picker_touch_does_not_restart_timeout" not in golden

    def test_the_fourteen_binding_scenarios_are_present(self):
        golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
        binding_scenarios = [name for name in golden if name.startswith("binding_")]
        assert len(binding_scenarios) == 14
