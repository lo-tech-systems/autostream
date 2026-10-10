"""Shared helpers for dial display tests: a recording backend, builders for
targets, roster entries and status results, a controllable clock and a
display factory. test_dial_display.py keeps its own older copies."""
from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

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
    dial_eq=False,
) -> RosterEntry:
    """A merged-roster entry, for tests that need an idle (playing=False) or
    explicitly playing row without going through a PlayingTarget."""
    return RosterEntry(
        appliance_id=appliance_id, service_name=service_name or name, name=name,
        ip=ip, port=port, playing=playing, repeat_capable=repeat_capable,
        dial_api=True, audio_status=True, dial_status=dial_status, dial_outputs=dial_outputs,
        dial_eq=dial_eq, auth=auth,
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


def _roster_from_targets(targets) -> list:
    """Default get_roster() stand-in: a RosterEntry per identity-carrying
    target, rebuilt from whatever *targets* holds each time it is called."""
    return [
        RosterEntry(
            appliance_id=t.appliance_id, service_name=t.service_name, name=t.name,
            ip=t.ip, port=t.port, playing=True, repeat_capable=False,
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
        gr = lambda: _roster_from_targets(gt())
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
