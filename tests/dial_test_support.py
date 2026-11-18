"""Shared helpers for dial display tests: a recording backend, builders for
targets, roster entries and status results, a controllable clock, and a
display factory whose core reads its appliances from a StatusBridge, shared
by the display, trace and core tests."""
from __future__ import annotations

import contextlib
import dataclasses
import sys
import time
import weakref
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).parent.parent
for _p in (str(REPO_ROOT / "dial"), str(REPO_ROOT / "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from autostream_peer_client import PeerReply, PeerSnapshot
from autostream_peer_registry import Sighting
import dial_core
import dial_peer_view
from dial_config import DialDisplayConfig
from dial_display import WARNING_DESCRIPTORS, DialDisplay
from dial_display_profiles import DEFAULT_PROFILE_KEY
from dial_mdns import PlayingTarget, RosterEntry
from dial_warnings import WarningManager


@dataclasses.dataclass(frozen=True)
class RowSnapshot(PeerSnapshot):
    """A PeerSnapshot built from a test row, carrying what that row says the
    appliance offers as (dial_outputs, dial_eq, repeat_capable)."""
    offers: tuple = ()


class _RowPeerView:
    """dial_peer_view as the core sees it in these tests: the same module,
    except that an appliance built from a test row offers what the row says.
    A peer on the protocol offers every capability; a test row may still
    leave one out, so the screens can be driven without it."""

    def __getattr__(self, name):
        return getattr(dial_peer_view, name)

    @staticmethod
    def appliance_state(sighting, snap, **kwargs):
        state = dial_peer_view.appliance_state(sighting, snap, **kwargs)
        offers = getattr(snap, "offers", ())
        if offers and state.dial_status:
            outputs, eq, repeat = offers
            state = dataclasses.replace(
                state, dial_outputs=outputs, dial_eq=eq, repeat_capable=repeat,
                dial_outputs_version=2 if outputs else 0, dial_eq_version=2 if eq else 0,
            )
        return state


dial_core.dial_peer_view = _RowPeerView()

TEST_LOGO_PATH = str(REPO_ROOT / "images" / "autostream-logo-centred-dark.png")


def _target(
    name="Kitchen", ip="192.168.1.10", port=80,
    dial_status=True, appliance_id=None, auth="unknown",
    service_name=None, playing_since=100.0, dial_proto_version=0,
) -> PlayingTarget:
    # Identified by default (a name-derived id): an identity-less target
    # (appliance_id="") is never acted on, so it has to be asked for.
    if appliance_id is None:
        appliance_id = (name.encode().hex() + "0" * 20)[:20]
    return PlayingTarget(
        ip=ip, port=port, name=name,
        dial_api=True, audio_status=True, dial_status=dial_status,
        service_name=service_name or name,
        playing_since=playing_since,
        appliance_id=appliance_id,
        auth=auth, dial_proto_version=dial_proto_version,
    )


def _roster_entry(
    name="Kitchen", ip="192.168.1.10", port=80,
    dial_status=True, appliance_id="a" * 20, auth="unknown",
    service_name=None, playing=False, repeat_capable=False, dial_outputs=False,
    dial_eq=False, dial_proto_version=0, version="",
) -> RosterEntry:
    """A merged-roster entry, for tests that need an idle (playing=False) or
    explicitly playing row without going through a PlayingTarget."""
    return RosterEntry(
        appliance_id=appliance_id, service_name=service_name or name, name=name,
        ip=ip, port=port, playing=playing, repeat_capable=repeat_capable,
        dial_api=True, audio_status=True, dial_status=dial_status, dial_outputs=dial_outputs,
        dial_eq=dial_eq, auth=auth, dial_proto_version=dial_proto_version, version=version,
    )


def _track_id(**overrides) -> dict:
    base = {
        "enabled": True, "state": "identified",
        "title": "Song", "artist": "Artist", "album": "Album",
        "artwork_url": "https://provider.example/x.jpg",
        "updated_at": 1.0, "last_attempt_at": 1.0,
    }
    base.update(overrides)
    return base


def _status_result(track_id=None, status_error=None, appliance_id=None, muted=False) -> dict:
    return {
        "playing": True, "master_volume": 50, "selected_output_count": 1,
        "track_id": track_id, "status_error": status_error,
        "appliance_id": appliance_id, "muted": muted,
    }


def _repeat_obj(**overrides) -> dict:
    base = {
        "available": True, "state": "hold", "armed": False, "held": True,
        "recording_seconds": 30.0,
        "replay": {"active": False, "position_seconds": 0.0, "duration_seconds": 30.0},
    }
    base.update(overrides)
    return base


class FakeBackend:
    name = "fake"
    width = 128
    height = 160

    def __init__(self, fail_open=False, fail_display=False, fail_sleep=False):
        self.fail_open = fail_open
        self.fail_display = fail_display
        self.fail_sleep = fail_sleep
        self.opened = False
        self.closed = False
        self.cleared = False
        self.displayed: list = []
        self.sleep_calls = 0
        self.wake_calls = 0

    def open(self):
        if self.fail_open:
            raise RuntimeError("open failed")
        self.opened = True

    def close(self):
        self.closed = True
        self.opened = False

    def clear(self):
        self.cleared = True

    def display(self, image):
        if self.fail_display:
            raise RuntimeError("display failed")
        self.displayed.append(image)

    def sleep(self):
        self.sleep_calls += 1
        if self.fail_sleep:
            raise RuntimeError("sleep failed")

    def wake(self):
        self.wake_calls += 1


class _FakeClock:
    """Controllable stand-in for time.monotonic, advanced explicitly between
    polls so elapsed-time math is deterministic instead of racing wall time.
    """

    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t


# Every place time.monotonic is read, all replaced together by patch_monotonic().
MONOTONIC_TARGETS = ("dial_display.time.monotonic",)


@contextlib.contextmanager
def patch_monotonic(clock):
    """Patch every time.monotonic reader with *clock*."""
    with contextlib.ExitStack() as stack:
        for target in MONOTONIC_TARGETS:
            stack.enter_context(patch(target, clock))
        yield


def _roster_from_targets(targets, repeat_capable=False) -> list:
    """Default roster stand-in: a RosterEntry per identity-carrying target,
    rebuilt from whatever *targets* holds each time it is called."""
    return [
        RosterEntry(
            appliance_id=t.appliance_id, service_name=t.service_name, name=t.name,
            ip=t.ip, port=t.port, playing=True, repeat_capable=repeat_capable,
            dial_api=t.dial_api, audio_status=t.audio_status, dial_status=t.dial_status,
            auth=t.auth,
        )
        for t in targets if t.appliance_id
    ]


def fetch_target_status(target, dial_id, timeout_seconds=None) -> dict:
    """What an appliance says about itself when a test has not said: it
    answers, with nothing identified, and leaves its repeat record as it
    was. Tests patch this name."""
    return dict(_status_result(), repeat_untold=True)


def _block_from_repeat_obj(obj) -> dict | None:
    """A repeat daemon block that maps back to the repeat object *obj*."""
    if not isinstance(obj, dict):
        return None
    state = obj.get("state")
    replay = obj.get("replay") if isinstance(obj.get("replay"), dict) else {}
    replaying = state in ("replaying", "fading_out")
    return {
        "enabled": bool(obj.get("available")),
        "armed": bool(obj.get("armed")),
        "recording": {
            "active": state == "recording",
            "seconds": float(obj.get("recording_seconds") or 0.0) if state != "idle" else 0.0,
            "bytes": 1000 if state not in ("idle",) else 0,
        },
        "replay": {
            "active": replaying, "fading_out": state == "fading_out",
            "position_seconds": float(replay.get("position_seconds") or 0.0),
            "duration_seconds": float(replay.get("duration_seconds") or 0.0),
        },
    }


def _unit_from_row(row) -> dict:
    """An outputs part unit for an OutputRow or an old outputs reply row."""
    get = (lambda k, d=None: row.get(k, d)) if isinstance(row, dict) else (lambda k, d=None: getattr(row, k, d))
    unit = {"id": get("id"), "name": get("name"), "selected": bool(get("selected")),
            "volume": get("volume") or 0, "availability": "ok",
            "auto_start": bool(get("is_default"))}
    if get("remote_in_use"):
        unit["in_use_by"] = get("remote_owner") or "another appliance"
    if get("needs_auth_key"):
        unit["reported"] = {"needs_auth_key": True}
    return unit


class _BridgeClient:
    """A PeerClient stand-in for one appliance of a StatusBridge."""

    def __init__(self, bridge: "StatusBridge", appliance_id: str) -> None:
        self.bridge = bridge
        self.appliance_id = appliance_id

    def snapshot(self):
        return self.bridge.snapshot_for(self.appliance_id)

    def submit(self, name, args, *, extra_body=None, read_s=None, backoff=True):
        self.bridge.submitted.append((self.appliance_id, name, dict(args), extra_body))
        return self.bridge.reply

    def fetch(self, parts, *, merge=False):
        return 200, {"parts": {}}


# How often a fold takes every appliance's own word on its repeat record.
EVERYONE_READ_S = 60.0


class StatusBridge:
    """The peer pool and registry behind a test display's core. On each fold
    it builds one PeerSnapshot per appliance from the test's targets (those
    playing), its roster (every appliance) and what `fetch_target_status`
    says of each, plus the speakers, EQ and repeat record a test seeds. Each
    snapshot carries what the appliance's row says it offers."""

    def __init__(self, get_targets, get_roster, dial_id: str) -> None:
        self._get_targets = get_targets
        self._get_roster = get_roster
        self._dial_id = dial_id
        self.repeats: dict = {}
        self.units: dict = {}
        self.bands: dict = {}
        self.boots: dict = {}
        self.versions: dict = {}
        self.submitted: list = []
        self.reply = None
        self.roster_override = None
        self._subs: list = []
        self._rows: dict = {}
        self._roster_rows: dict = {}
        self._sighted: set = set()
        self.ever_sighted: set = set()
        self._read: set = set()
        self._playing: set = set()
        self._everyone_at = None

    def _scan(self) -> tuple:
        """(rows, roster rows, playing ids) as the test's targets and roster
        say now. The targets are the playing set; a roster row only adds an
        appliance to the list."""
        rows = {}
        for t in self._get_targets() or ():
            if t.appliance_id:
                rows[t.appliance_id] = t
        playing = set(rows)
        roster = self.roster_override if self.roster_override is not None else self._get_roster()
        roster_rows = {}
        for r in roster or ():
            if r.appliance_id:
                roster_rows.setdefault(r.appliance_id, r)
            if r.appliance_id and r.appliance_id not in rows:
                rows[r.appliance_id] = r
        return rows, roster_rows, playing

    def snapshot_now(self, appliance_id: str):
        """The snapshot *appliance_id* would give now, or None when the test
        lists no such appliance; nothing is recorded as read."""
        rows, roster_rows, playing = self._scan()
        if appliance_id not in rows:
            return None
        return self._snapshot(appliance_id, rows[appliance_id], roster_rows, playing, read=False)

    # The registry.
    def sightings(self):
        rows, roster_rows, playing = self._scan()
        # The appliances whose own word on their repeat record this fold
        # takes: every playing one, one sighted for the first time, and every
        # one on the first fold, on a fold that finds the playing set has
        # shrunk and once a minute; the record of any other stays as it was
        # last told (or seeded).
        now = time.monotonic()
        if (self._everyone_at is None or self._playing - playing
                or now - self._everyone_at >= EVERYONE_READ_S):
            self._everyone_at = now
            self._read = playing | set(rows)
        else:
            self._read = playing | (set(rows) - self._sighted)
        self._sighted = set(rows)
        self.ever_sighted |= self._sighted
        self._rows = rows
        self._roster_rows = roster_rows
        self._playing = playing
        return {aid: Sighting(id=aid, hostname=r.name, ip=r.ip, port=r.port, version="0.8.0",
                              control=True, proto=4, service_name=r.service_name)
                for aid, r in rows.items()}

    # The pool.
    def clients(self):
        return {aid: _BridgeClient(self, aid) for aid in self._rows}

    def get(self, appliance_id):
        return _BridgeClient(self, appliance_id) if appliance_id in self._rows else None

    def subscribe(self, fn) -> int:
        self._subs.append(fn)
        return len(self._subs)

    def unsubscribe(self, handle) -> None:
        pass

    def snapshot_for(self, appliance_id: str):
        read = appliance_id in self._read
        self._read.discard(appliance_id)
        return self._snapshot(appliance_id, self._rows[appliance_id], self._roster_rows,
                              self._playing, read=read)

    def _snapshot(self, appliance_id, row, roster_rows, playing_ids, *, read):
        playing = appliance_id in playing_ids
        protocol_ok = getattr(row, "dial_status", True)
        status = fetch_target_status(row, self._dial_id, timeout_seconds=2.0) if protocol_ok else {}
        error = status.get("status_error")
        reachable = protocol_ok and error in (None, "unauthorized")
        access = "playback" if error is None and protocol_ok else "none" if error == "unauthorized" else None
        if isinstance(row, RosterEntry) and self.roster_override is not None:
            access = {"authorized": "playback", "unauthorized": "none"}.get(row.auth)
        elif getattr(row, "auth", "") == "unauthorized":
            access = "none"
        # A reply may say outright what access the appliance gives this dial.
        access = status.get("access", access)
        parts: dict = {"session": {"active": playing, "source": "input1" if playing else ""}}
        track = status.get("track_id")
        if isinstance(track, dict):
            parts["track"] = {"entries": {"1": dict(track)}}
        units = self.units.get(appliance_id, [])
        parts["outputs"] = {
            "connected": True, "master_volume": status.get("master_volume"),
            "muted_all": bool(status.get("muted")), "units": [dict(u) for u in units],
        }
        failure = status.get("start_failure")
        if isinstance(failure, dict):
            parts["outputs"]["start_failure"] = dict(failure)
        if appliance_id in self.bands:
            parts["eq"] = {"output_bands": list(self.bands[appliance_id])}
        if read:
            if status.get("repeat_untold"):
                pass
            elif error is None and protocol_ok:
                self.repeats[appliance_id] = status.get("repeat")
            elif error == "unauthorized":
                self.repeats[appliance_id] = None
        block = _block_from_repeat_obj(self.repeats.get(appliance_id))
        if block is not None:
            parts["repeat"] = {"block": block}
        offer = roster_rows.get(appliance_id, row)
        return RowSnapshot(
            peer_id=appliance_id, boot=self.boots.get(appliance_id, "b1"),
            version=self.versions.get(appliance_id, 1), part_versions=MappingProxyType({}),
            parts=MappingProxyType(parts), reachable=reachable, access=access,
            access_reason="dial_not_authorized" if access == "none" else None,
            protocol=4 if protocol_ok else 3, protocol_ok=protocol_ok, configured=True,
            heard_at=0.0, seq=1,
            offers=(bool(getattr(offer, "dial_outputs", False)), bool(getattr(offer, "dial_eq", False)),
                    bool(getattr(offer, "repeat_capable", False))))

    def sent(self, core) -> list:
        """The requests the core has queued on its request lane since the
        last call, as (appliance_id, intent name, args, extra_body)."""
        items = []
        lane_queue = core._lane._queue
        while True:
            try:
                item = lane_queue.get_nowait()
            except Exception:
                break
            if item is not None:
                items.append((item.appliance_id, item.name, dict(item.args or {}), item.extra_body))
        return items


def make_display(
    fitted=True, rotate=False, bgr=False, screen_type=DEFAULT_PROFILE_KEY,
    always_show_controls=False, screen_size_inches=None, layout_size=None,
    targets=None, backend=None,
    get_targets=None,
    get_roster=None,
    roster=None,
    backend_factory_builder=None,
    warnings=None,
    wall_clock=None,
    repeat_capable=False,
) -> tuple[DialDisplay, FakeBackend, MagicMock]:
    cfg = DialDisplayConfig(
        fitted=fitted, rotate=rotate, bgr=bgr, screen_type=screen_type,
        always_show_controls=always_show_controls, screen_size_inches=screen_size_inches,
        layout_size=layout_size,
    )
    fb = backend or FakeBackend()
    gt = get_targets or MagicMock(return_value=targets or [])
    if get_roster is not None:
        gr = get_roster
    elif roster is not None:
        gr = lambda: roster
    else:
        gr = lambda: _roster_from_targets(gt(), repeat_capable)
    display = DialDisplay(
        config=cfg,
        dial_id="dial-uuid",
        logo_path=TEST_LOGO_PATH,
        backend_factory=lambda: fb,
        backend_factory_builder=backend_factory_builder,
        warnings=warnings or WarningManager(WARNING_DESCRIPTORS, clock=wall_clock or time.time),
    )
    attach_bridge(display, gt, gr)
    return display, fb, gt


def attach_bridge(display, get_targets, get_roster) -> "StatusBridge":
    """Attach a StatusBridge over *get_targets* and *get_roster* to the core
    *display* paints, with the artwork download run inline."""
    bridge = StatusBridge(get_targets, get_roster, "dial-uuid")
    display.core.attach_pool(bridge, bridge)
    display.bridge = bridge
    _DISPLAYS.add(display)
    # The artwork download runs inline, so a fold ends with it held.
    io = display.core._io
    display.core.set_io(dataclasses.replace(io, spawn=lambda fn, *args: fn(*args)))
    return bridge


# ---------------------------------------------------------------------------
# Driving the core and the view by hand
#
# In production the core's own thread publishes snapshots and the view's
# repaint thread folds each into the screen. A test that has neither running
# does the two steps itself: it calls the core, then lets the view fold what
# the core published.
# ---------------------------------------------------------------------------

def fold(display) -> None:
    """Let the view take up what the core has published, as its repaint
    thread would: the effects the core queued, then the newest snapshot."""
    display._apply_pending_snapshot()


def on_network_view(display, view) -> None:
    """A network reading, handed to the core as the poller does, which
    guards its callback: a reading the core cannot fold is dropped."""
    try:
        display.core.on_network_view(view)
    except Exception:
        pass
    display._drain_effects()


def on_sd_health_view(display, view) -> None:
    """An SD health reading, handed to the core as the reader does, which
    guards its callback the way the network poller does."""
    try:
        display.core.on_sd_health_view(view)
    except Exception:
        pass
    display._drain_effects()


def pending_token(display, lane) -> "float | None":
    """The token of the latest request on *lane* ("transport" or
    "outputs_request"), which its reply is folded against."""
    held = getattr(display.core.snapshot(), lane)
    return None if held is None else held.requested_at


def _reply(status, body):
    """The PeerReply an appliance's answer of *status* and *body* stands for:
    ok for a 200 with ok true, else refused with its error name."""
    if status == 200 and isinstance(body, dict) and body.get("ok") is True:
        return PeerReply(True, None, None, None, dict(body), None)
    if status is None:
        return PeerReply(False, "unreachable", None, None, {}, None)
    error = None
    retry = None
    if isinstance(body, dict):
        error = ("pin_invalid" if body.get("pin_invalid") is True
                 else "pin_required" if body.get("pin_required") is True else body.get("error"))
        retry = body.get("retry_after_s") if isinstance(body.get("retry_after_s"), int) else None
    return PeerReply(False, error if isinstance(error, str) and error else "backend_error",
                     None, None, {}, retry)


def _fold_reply(display, lane, appliance_id, status, body, request) -> None:
    held = getattr(display.core.snapshot(), lane)
    token = (request or {}).get("token") if isinstance(request, dict) else None
    if token is None:
        token = held.requested_at if held is not None else 0.0
    kind = held.kind if held is not None else ""
    display.core._fold_reply(appliance_id, kind, token, _reply(status, body))


def on_repeat_result(display, kind, appliance_id, status, body, request=None) -> None:
    """An appliance's answer to the latest transport request, folded by the
    core. An accepted answer that says the daemon's state also becomes the
    appliance's repeat record, as its next change would."""
    if status == 200 and isinstance(body, dict) and body.get("ok") and isinstance(body.get("state"), str):
        held = display.bridge.repeats.get(appliance_id) or {}
        display.bridge.repeats[appliance_id] = dict(
            held, available=True, state=body["state"],
            armed=bool(body.get("armed", held.get("armed", False))))
    elif isinstance(body, dict) and body.get("error") in ("source_active", "no_recording"):
        display.bridge.repeats.pop(appliance_id, None)
    _fold_reply(display, "transport", appliance_id, status, body, request)
    display._drain_effects()


def on_outputs_result(display, kind, appliance_id, status, body, request=None) -> None:
    """An appliance's speakers (*kind* "fetch", the old list reply's shape)
    or its answer to the latest output request ("set"); the view then
    follows the snapshot it changed."""
    if kind == "set":
        _fold_reply(display, "outputs_request", appliance_id, status, body, request)
    elif status == 200 and isinstance(body, dict) and body.get("ok") is True:
        display.bridge.units[appliance_id] = [_unit_from_row(o) for o in body.get("outputs") or ()]
        display.bridge.versions[appliance_id] = display.bridge.versions.get(appliance_id, 1) + 1
        _reread(display, appliance_id)
    fold(display)


def _reread(display, appliance_id) -> None:
    """What one appliance's change event does: the snapshot the core holds
    for it takes up the speakers and EQ the bridge now says it has, and the
    focused appliance's outputs and EQ are mapped again. Nothing else is
    folded, so the focus and the list stay as the last fold left them."""
    bridge = display.bridge
    core = display.core

    held = core._state.peers.get(appliance_id)
    if held is None:
        # Not folded yet (a test that set the roster by hand): its first
        # snapshot, as its client would hold it.
        held = bridge.snapshot_now(appliance_id)

    def mutate(state):
        if held is None:
            # Never sighted (a screen set up by hand): its speakers are held
            # for it when nothing else is.
            if appliance_id in bridge.ever_sighted or (
                    state.outputs is not None and state.outputs.appliance_id != appliance_id):
                return False
            state.outputs = dial_peer_view.outputs_state(appliance_id, {"outputs": {
                "units": [dict(u) for u in bridge.units.get(appliance_id, [])]}}, fetched_at=core._clock())
            return None
        parts = dict(held.parts)
        parts["outputs"] = dict(parts.get("outputs") or {},
                                units=[dict(u) for u in bridge.units.get(appliance_id, [])])
        if appliance_id in bridge.bands:
            parts["eq"] = {"output_bands": list(bridge.bands[appliance_id])}
        snap = dataclasses.replace(
            held, parts=MappingProxyType(parts), version=bridge.versions.get(appliance_id, held.version))
        state.peers = {**state.peers, appliance_id: snap}
        core._fold_focused_locked(state, core._clock(), availability=False)
    core._publish(mutate)


def on_eq_result(display, kind, appliance_id, status, body, request=None) -> None:
    """An appliance's EQ (the old reply's shape: bass and treble, or six
    bands); the view then follows the snapshot it changed."""
    if kind == "fetch" and status == 200 and isinstance(body, dict) and body.get("ok"):
        bands = body.get("bands")
        if isinstance(bands, list) and len(bands) == 6:
            gains = [b.get("gain_db", 0) for b in bands]
        else:
            gains = [body.get("bass_db", 0), 0, 0, 0, 0, body.get("treble_db", 0)]
        display.bridge.bands[appliance_id] = gains
        _reread(display, appliance_id)
    fold(display)


def warning_active(display, warning_id, severity=None) -> None:
    """A source reports its condition present: the core records it and the
    view requests the page when it is a status that is due."""
    change = display.core.warning_active(warning_id, severity)
    display._request_due_status(wake=change.began)


def warning_cleared(display, warning_id) -> None:
    """A source reports its condition gone: the core ends the incident and
    the view closes the page."""
    display.core.warning_cleared(warning_id)
    display._close_status_request(warning_id)


def tick_warnings(display) -> None:
    """The core's warning housekeeping run by hand, then the view's own tick
    that raises a status that was due while another page was up."""
    display._apply_source_effects(display.core.expire_warnings())
    display._request_due_status()


def tick_update_watch(display) -> None:
    """The core's update watch run by hand."""
    effects = display.core.tick_update_watch(time.monotonic())
    if effects is not None:
        display._apply_source_effects(effects)


def apply_update_view(display, view) -> None:
    """An update reading, folded by the core and turned into screens."""
    display._apply_source_effects(display.core.apply_update_view(view))


def set_focus_pending(display, appliance_id, service_name) -> None:
    """Pin the focus to *appliance_id* as pending for the grace window, as
    a picker-started replay does."""
    from dial_core_focus import FOCUS_PENDING_GRACE_S
    display.core.set_focus_pending(appliance_id, service_name, time.monotonic() + FOCUS_PENDING_GRACE_S)
    display.core.request_fold()


def tap_output(display, output_id, selected, volume) -> None:
    """Make the core show *selected* and *volume* for a held output, as a set
    just made would; nothing is sent."""
    display.core.set_output(
        display._outputs.appliance_id, output_id, selected=selected, volume=volume,
    )
    display.bridge.sent(display.core)


def eq_optimistic(display):
    """The core's pending EQ tap as (bass, treble, expires_at), an element
    None when only the other control was stepped; None when there is no
    pending tap."""
    pairs, expires_at = display.core.eq_override()
    if not pairs and not expires_at:
        return None
    gains = dict(pairs)
    return gains.get("bass"), gains.get("treble"), expires_at


def set_eq_optimistic(display, value) -> None:
    """Give the core a pending EQ tap from a (bass, treble, expires_at)
    tuple, or clear it with None."""
    if value is None:
        display.core.set_eq_override((), 0.0)
        return
    bass, treble, expires_at = value
    pairs = tuple(
        (band, gain) for band, gain in (("bass", bass), ("treble", treble)) if gain is not None
    )
    display.core.set_eq_override(pairs, expires_at)


def tap_card(display, cell) -> None:
    """A tap on button *cell* of the card on screen, as the touch thread
    delivers it."""
    from dial_touch_layout import CARD_BUTTON_ZONES
    display.card_button_tap(CARD_BUTTON_ZONES[cell])


def open_warnings_page(display) -> None:
    """A tap on the bell, folded into the screen."""
    display.open_warnings()
    with display._lock:
        display._repaint_current_locked()


# ---------------------------------------------------------------------------
# Seeding what the appliances report
#
# The displays a test has built, so a seed made without one in hand reaches
# the core its screens read.
# ---------------------------------------------------------------------------

_DISPLAYS: "weakref.WeakSet" = weakref.WeakSet()


def _repeat_obj_from(record) -> "dict | None":
    """The repeat object a RepeatRecord (or a repeat object) stands for."""
    if record is None or isinstance(record, dict):
        return record
    return {
        "available": record.available, "state": record.state, "armed": record.armed,
        "recording_seconds": record.recording_seconds,
        "replay": {"active": record.state in ("replaying", "fading_out"),
                   "position_seconds": record.position_seconds,
                   "duration_seconds": record.duration_seconds},
        "latency_ms": int(round(record.latency_seconds * 1000)),
    }


def seed_repeat(appliance_id, record) -> None:
    """Make *appliance_id* report *record* (a repeat object, a RepeatRecord,
    or None for none) from now on, and show it at once in the appliance's
    state as the core holds it, observed at the record's own time."""
    from dial_repeat_store import RepeatRecord, parse_repeat_object
    obj = _repeat_obj_from(record)
    if isinstance(record, RepeatRecord):
        rec = record
    else:
        rec = parse_repeat_object(obj, time.monotonic()) if obj is not None else None
    for display in list(_DISPLAYS):
        bridge = display.bridge
        if obj is None:
            bridge.repeats.pop(appliance_id, None)
        else:
            bridge.repeats[appliance_id] = obj
        core = display.core

        def mutate(state, rec=rec):
            view = state.views.get(appliance_id)
            if view is None:
                # Not sighted yet: held for it all the same, as an idle,
                # repeat-capable appliance the screens can read.
                view = _state_of_row(SimpleNamespace(
                    appliance_id=appliance_id, service_name=appliance_id, ip="", port=0,
                    auth="unknown", repeat_capable=True))
                state.roster = [*state.roster, view]
            state.views = dict(state.views, **{appliance_id: dataclasses.replace(view, repeat=rec)})
            state.roster = [state.views.get(r.appliance_id, r) for r in state.roster]
            state.appliances = core._derive_appliances_locked(state)
        core._publish(mutate)


def repeat_of(appliance_id):
    """The repeat record of *appliance_id* as the newest test display's core
    holds it."""
    for display in list(_DISPLAYS):
        entry = display.core.snapshot().appliance(appliance_id)
        if entry is not None:
            return entry.repeat
    return None


def outputs_rows(body) -> tuple:
    """The rows an old outputs reply body lists, as the screens hold them."""
    from dial_core_state import OutputRow
    rows = []
    for o in body.get("outputs") or ():
        in_use = bool(o.get("remote_in_use"))
        rows.append(OutputRow(
            id=o["id"], name=o["name"], selected=bool(o.get("selected")),
            volume=max(0, min(100, int(o.get("volume") or 0))), remote_in_use=in_use,
            remote_owner=(o.get("remote_owner") or None) if in_use else None,
            is_default=bool(o.get("is_default")), needs_auth_key=o.get("needs_auth_key") is True,
        ))
    return tuple(rows)


# ---------------------------------------------------------------------------
# Holding state in the core by hand
#
# A screen test that sets the focus fields itself must not have them folded
# away, so these write what the core holds directly, as a fold of the same
# appliances would, and leave the focus alone. The bridge is told too, so a
# later fold agrees.
# ---------------------------------------------------------------------------

def _state_of_row(row, repeat=None):
    """The ApplianceState a fold would hold for roster row *row*."""
    from dial_core_state import ApplianceState
    from dial_mdns import appliance_display_name
    eq_version = getattr(row, "dial_eq_version", 0) or (2 if getattr(row, "dial_eq", False) else 0)
    return ApplianceState(
        appliance_id=row.appliance_id, service_name=row.service_name,
        name=appliance_display_name(row.service_name), ip=row.ip, port=row.port,
        playing=bool(getattr(row, "playing", False)),
        playing_since=float(getattr(row, "playing_since", 0.0) or 0.0),
        auth=row.auth, dial_status=getattr(row, "dial_status", True),
        dial_outputs=getattr(row, "dial_outputs", False), dial_eq=getattr(row, "dial_eq", False),
        repeat_capable=getattr(row, "repeat_capable", False),
        dial_proto_version=getattr(row, "dial_proto_version", 0) or 0,
        dial_eq_version=eq_version, dial_outputs_version=2 if getattr(row, "dial_outputs", False) else 0,
        status_error=None, master_volume=None, muted=None, repeat=repeat,
        webui_scheme="http", webui_host=row.ip, webui_port=row.port,
    )


def set_roster(display, roster) -> None:
    """Make the core hold *roster* (RosterEntry rows) as its appliances, each
    with the authorisation and capabilities its row says and the repeat
    record seeded for it, without touching the focus."""
    from dial_repeat_store import parse_repeat_object
    roster = list(roster)
    display.bridge.roster_override = roster
    core = display.core
    now = time.monotonic()
    views = {}
    for r in roster:
        obj = display.bridge.repeats.get(r.appliance_id)
        views[r.appliance_id] = _state_of_row(r, parse_repeat_object(obj, now) if obj else None)

    def mutate(state):
        state.views = views
        state.roster = [views[r.appliance_id] for r in roster]
        state.appliances = core._derive_appliances_locked(state)
    core._publish(mutate)


def update_availability(display) -> None:
    """What the focused (or reporting) appliance offers, worked out from the
    appliance states the core holds, as a fold works it out."""
    from dial_core_state import AUTH_UNAUTHORIZED, dots_active
    core = display.core

    def mutate(state):
        focused = state.focus.manual_id or state.focus.reporting_id
        entry = state.views.get(focused) if focused else None
        usable = entry is not None and entry.auth != AUTH_UNAUTHORIZED
        state.eq_available = bool(usable and entry.dial_eq and not core._eq_veto())
        state.outputs_available = bool(usable and entry.dial_outputs)
        state.dots_active = dots_active(entry.repeat if entry is not None else None, state.eq_available)
    core._publish(mutate)


def seed_outputs(display, rows, loaded=True) -> None:
    """Make the appliance the outputs screen shows report *rows* as its
    speakers, held by the core at once."""
    from dial_core_state import OutputsState
    appliance_id = display._outputs.appliance_id
    display.bridge.units[appliance_id] = [_unit_from_row(r) for r in rows]
    held = OutputsState(appliance_id, tuple(rows), loaded, time.monotonic())

    def mutate(state):
        state.outputs = held
    display.core._publish(mutate)
    fold(display)


def seed_eq(display, bass_db=None, treble_db=None, loaded=True) -> None:
    """Make the appliance the EQ page shows report a bass and treble (its
    lowest and highest bands), held by the core at once."""
    import dial_peer_view
    appliance_id = display._eq.appliance_id
    gains = [bass_db or 0, 0, 0, 0, 0, treble_db or 0]
    display.bridge.bands[appliance_id] = gains
    held = dial_peer_view.eq_state(appliance_id, {"eq": {"output_bands": gains}})
    if not loaded:
        held = dataclasses.replace(held, loaded=False)

    def mutate(state):
        state.eq = held
    display.core._publish(mutate)
    fold(display)


def seed_bands(display, appliance_id, gains) -> None:
    """Make *appliance_id* report *gains* as its EQ bands, as its next change
    event would carry them."""
    display.bridge.bands[appliance_id] = list(gains)
    _reread(display, appliance_id)
    fold(display)


def set_appliance_warnings(display, appliance_id, warnings):
    """Make the core hold *warnings* as what *appliance_id* reports, as a
    fold of its warnings part would; refused for an appliance the core does
    not hold."""
    from dial_core_state import ActionResult, attribute_appliance_warnings
    core = display.core
    outcome = []

    def mutate(state):
        view = state.views.get(appliance_id)
        if view is None:
            outcome.append(ActionResult(False, "unknown_appliance"))
            return False
        outcome.append(ActionResult(True))
        new = attribute_appliance_warnings(tuple(warnings), view.name)
        if not core._store_appliance_warnings_locked(state, appliance_id, new):
            return False
        state.appliances = core._derive_appliances_locked(state)
        core._sync_warnings_locked(state)
    core._publish(mutate)
    return outcome[0]


def sent(send_mock):
    """(target, intent, token) of the last request a patched DialCore._send
    was given; the target carries the appliance id the request went to."""
    appliance_id, intent, token = send_mock.call_args[0]
    return SimpleNamespace(appliance_id=appliance_id), intent, token


def sent_kwargs(send_mock) -> dict:
    """The speaker fields of the last outputs request a patched
    DialCore._send was given, None for a field it did not set."""
    _target, intent, _token = sent(send_mock)
    return {"selected": intent.args.get("selected"), "volume": intent.args.get("volume"),
            "pin": intent.args.get("pin")}
