"""Shared helpers for dial display tests: a recording backend, builders for
targets, roster entries and status results, a controllable clock and a
display factory. test_dial_display.py keeps its own older copies."""
from __future__ import annotations

import contextlib
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).parent.parent
for _p in (str(REPO_ROOT / "dial"), str(REPO_ROOT / "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dial_config import DialDisplayConfig
from dial_display import WARNING_DESCRIPTORS, DialDisplay
from dial_display_profiles import DEFAULT_PROFILE_KEY
from dial_mdns import PlayingTarget, RosterEntry
from dial_warnings import WarningManager, WarningStore

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
MONOTONIC_TARGETS = ("dial_display.time.monotonic", "dial_core_poll.time.monotonic")


@contextlib.contextmanager
def patch_monotonic(clock):
    """Patch every time.monotonic reader with *clock*."""
    with contextlib.ExitStack() as stack:
        for target in MONOTONIC_TARGETS:
            stack.enter_context(patch(target, clock))
        yield


def _roster_from_targets(targets, repeat_capable=False) -> list:
    """Default get_roster() stand-in: a RosterEntry per identity-carrying
    target, rebuilt from whatever *targets* holds each time it is called."""
    return [
        RosterEntry(
            appliance_id=t.appliance_id, service_name=t.service_name, name=t.name,
            ip=t.ip, port=t.port, playing=True, repeat_capable=repeat_capable,
            dial_api=t.dial_api, audio_status=t.audio_status, dial_status=t.dial_status,
            auth=t.auth,
        )
        for t in targets if t.appliance_id
    ]


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
        get_display_targets=gt,
        dial_id="dial-uuid",
        logo_path=TEST_LOGO_PATH,
        backend_factory=lambda: fb,
        backend_factory_builder=backend_factory_builder,
        get_roster=gr,
        warnings=warnings or WarningManager(WARNING_DESCRIPTORS, WarningStore(None), clock=wall_clock or time.time),
    )
    return display, fb, gt


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
    "outputs_request"), which a worker would hand back with its reply."""
    held = getattr(display.core.snapshot(), lane)
    return None if held is None else held.requested_at


def on_repeat_result(display, kind, appliance_id, status, body, request=None) -> None:
    """A repeat-transport worker result, handed to the core. Without a
    *request* it answers the latest transport request."""
    if request is None:
        request = {"token": pending_token(display, "transport")}
    display.core.on_repeat_result(kind, appliance_id, status, body, request)
    display._drain_effects()


def on_outputs_result(display, kind, appliance_id, status, body, request=None) -> None:
    """An outputs worker result, handed to the core; the view then follows
    the snapshot it changed. A set result without a *request* answers the
    latest output request."""
    if request is None and kind == "set":
        request = {"token": pending_token(display, "outputs_request")}
    display.core.on_outputs_result(kind, appliance_id, status, body, request)
    fold(display)


def on_eq_result(display, kind, appliance_id, status, body, request=None) -> None:
    """An EQ worker result, handed to the core; the view then follows the
    snapshot it changed."""
    display.core.on_eq_result(kind, appliance_id, status, body, request)
    fold(display)


def warning_active(display, warning_id, severity=None) -> None:
    """A source reports its condition present: the core records it and the
    view requests the page when it is due."""
    change = display.core.warning_active(warning_id, severity)
    display._request_due_warning(wake=change.began)


def warning_cleared(display, warning_id) -> None:
    """A source reports its condition gone: the core ends the incident and
    the view closes the page."""
    display.core.warning_cleared(warning_id)
    display._close_warning_request(warning_id)


def tick_warnings(display) -> None:
    """The core's warning housekeeping run by hand, then the view's own tick
    that raises a warning whose snooze has just run out."""
    display._apply_source_effects(display.core.expire_warnings())
    display._tick_due_warning()
    display.core.flush_warnings()


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
    from dial_core import FOCUS_PENDING_GRACE_S
    display.core.set_focus_pending(appliance_id, service_name, time.monotonic() + FOCUS_PENDING_GRACE_S)
    display.core.request_poll()


def seed_outputs(display, rows, loaded=True) -> None:
    """Make the core hold *rows* as the outputs of the appliance the
    outputs screen shows."""
    display.core.adopt_outputs(display._outputs.appliance_id, tuple(rows), loaded, overwrite=True)


def tap_output(display, output_id, selected, volume) -> None:
    """Make the core show *selected* and *volume* for a held output, as a set
    just made would; nothing is sent."""
    with patch("dial_core.enqueue_set"):
        display.core.set_output(
            display._outputs.appliance_id, output_id, selected=selected, volume=volume,
        )


def seed_eq(display, bass_db=None, treble_db=None, loaded=True) -> None:
    """Make the core hold a bass/treble reading for the appliance the EQ
    page shows."""
    from dial_core_state import EQ_LIMIT_DB, EqBand
    bands = tuple(
        EqBand(band_id, None, gain, -EQ_LIMIT_DB, EQ_LIMIT_DB)
        for band_id, gain in (("bass", bass_db), ("treble", treble_db)) if gain is not None
    )
    display.core.adopt_eq(display._eq.appliance_id, bands, loaded, overwrite=True)


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


def run_warning_action(display, warning_id, action) -> None:
    """Run a warning page's button action (Dismiss or Restart) as a tap on
    its cell does."""
    import dial_display as dd
    display._run_warning_action(dd._WARNING_BY_ID[warning_id], action)
