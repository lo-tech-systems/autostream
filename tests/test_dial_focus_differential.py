"""tests/test_dial_focus_differential.py -- the focus rule the dial follows,
checked against the poll that decided it before.

A generated grid of cases (appliances playing or not, identified or not,
authorised, unknown or refused, sighted or gone; a manual focus, a binding, a
pending focus that is live or has run out; the appliances that were playing at
the last decision) is decided three ways: by the poll's own tick
(DialCore.poll_once over scripted status replies), by
dial_core_focus.choose_focus, and by the core folding a peer pool. All three
must agree on every focus field and on what is shown.

The one deliberate change, the pending-focus grace (ten seconds for the poll,
three for the pool), lies in what a replay start passes as the pending
focus's expiry, not in the decision, so the grid gives each pending focus its
expiry outright and the grace is checked on its own.

This test exists only while the poll does: it goes with the poll's code.
"""
from __future__ import annotations

import random
import time
from unittest.mock import MagicMock

import pytest

from dial_pool_support import Rig, aid, peer

import dial_auth
import dial_core
import dial_core_focus
from dial_core import DialCore, PollIO
from dial_core_state import AUTH_AUTHORIZED, AUTH_UNAUTHORIZED, AUTH_UNKNOWN, ApplianceState, FocusState
from dial_mdns import PlayingTarget, RosterEntry
from dial_warning_text import WARNING_DESCRIPTORS
from dial_warnings import WarningManager, WarningStore

NOW = 1000.0
NAMES = ("Amp", "Bay", "Cove")
GONE = "f" * 20
CASES = 500

_TRACKS = {
    "none": None,
    "analysing": {"state": "analysing", "title": "x"},
    "art": {"state": "identified", "title": "T", "artist": "A", "album": "B",
            "artwork_url": "https://provider.example/a.jpg"},
    "noart": {"state": "identified", "title": "U", "artist": "C", "album": "D", "artwork_url": ""},
}
_ACCESS = {
    AUTH_AUTHORIZED: ("playback", None),
    AUTH_UNKNOWN: ("unknown", None),
    AUTH_UNAUTHORIZED: ("none", "dial_not_authorized"),
}


def service(name: str) -> str:
    return f"autostream on {name}"


def generate(rng: random.Random) -> dict:
    appliances = {}
    for name in NAMES:
        if rng.random() < 0.15:
            continue
        appliances[name] = {
            "playing": rng.random() < 0.6,
            "since": rng.choice((10.0, 20.0, 20.0, 30.0)),
            "auth": rng.choices((AUTH_AUTHORIZED, AUTH_UNKNOWN, AUTH_UNAUTHORIZED), (6, 2, 2))[0],
            "track": rng.choice(tuple(_TRACKS)),
        }
    manual = rng.choice((None, None, "Amp", "Bay", "Cove", "gone"))
    manual_id = None if manual is None else GONE if manual == "gone" else aid(manual)
    bound = rng.choice((None, None, "Amp", "Bay", "Cove"))
    pending = None
    if manual_id is not None and rng.random() < 0.4:
        pending = (manual_id, service(manual if manual != "gone" else "Gone"), NOW + rng.choice((-1.0, 5.0)))
    prev = {aid(n) for n in NAMES if rng.random() < 0.4}
    return {
        "appliances": appliances,
        "focus": FocusState(manual_id, None if bound is None else aid(bound), pending, None, None, None, False),
        "prev": prev,
    }


def by_poll(case: dict, monkeypatch) -> object:
    """The snapshot the poll's tick publishes for *case*."""
    apps = case["appliances"]
    auths = {aid(n): a["auth"] for n, a in apps.items()}
    monkeypatch.setattr(dial_auth.auth_map, "state", lambda appliance_id: auths.get(appliance_id, AUTH_UNKNOWN))
    targets = sorted(
        (PlayingTarget(ip="192.0.2.10", port=80, name=n, dial_api=True, audio_status=True, dial_status=True,
                       service_name=service(n), playing_since=a["since"], appliance_id=aid(n), auth=a["auth"],
                       dial_proto_version=2)
         for n, a in apps.items() if a["playing"]),
        key=lambda t: (t.playing_since, t.name, t.ip, t.port),
    )
    roster = [
        RosterEntry(appliance_id=aid(n), service_name=service(n), name=n, ip="192.0.2.10", port=80,
                    playing=a["playing"], repeat_capable=False, dial_api=True, audio_status=True, dial_status=True, auth=a["auth"],
                    dial_proto_version=2)
        for n, a in apps.items()
    ]
    tracks = {aid(n): _TRACKS[a["track"]] for n, a in apps.items()}

    def fetch_status(target, dial_id, timeout_seconds):
        return {"playing": True, "master_volume": 50, "selected_output_count": 1,
                "track_id": tracks.get(target.appliance_id), "status_error": None,
                "appliance_id": target.appliance_id, "muted": False}

    io = PollIO(fetch_status=fetch_status, enrich=lambda targets, dial_id: [], fetch_artwork=MagicMock(return_value=(None, "no")),
                artwork_eligible=lambda url: False, observe_mute=MagicMock(),
                observe_volume=MagicMock(), forget_mute=MagicMock())
    core = DialCore("dial-uuid", lambda: list(targets), lambda: list(roster), clock=lambda: NOW, io=io,
                    warnings=WarningManager(WARNING_DESCRIPTORS, WarningStore(None), clock=time.time))
    core.set_polling(True)
    core._prev_playing_ids = set(case["prev"])
    core._state.focus = case["focus"]
    core.poll_once()
    return core.snapshot()


def by_choose_focus(case: dict) -> FocusState:
    apps = case["appliances"]
    states = [
        ApplianceState(
            appliance_id=aid(n), service_name=service(n), name=n, ip="192.0.2.10", port=80,
            playing=a["playing"], playing_since=a["since"] if a["playing"] else 0.0, auth=a["auth"],
            dial_status=True, dial_outputs=True, dial_eq=True, repeat_capable=True, dial_proto_version=4,
            dial_eq_version=2, dial_outputs_version=2, status_error=None, master_volume=50, muted=False,
            repeat=None,
        )
        for n, a in apps.items()
    ]
    tracks = {aid(n): _TRACKS[a["track"]] if a["playing"] else None for n, a in apps.items()}
    choice = dial_core_focus.choose_focus(states, case["focus"], NOW, tracks=tracks, prev_playing_ids=case["prev"])
    return choice.apply(case["focus"])


def by_pool(case: dict) -> object:
    rig = Rig(start_lane=False)
    try:
        rig.t = NOW
        for n, a in case["appliances"].items():
            access, reason = _ACCESS[a["auth"]]
            rig.add(n, peer(n, playing=a["playing"], track_entry=_TRACKS[a["track"]], access=access,
                            access_reason=reason, master_volume=50))
        rig.core._state.playing_since = {
            aid(n): a["since"] for n, a in case["appliances"].items() if a["playing"]}
        rig.core._prev_playing_ids = set(case["prev"])
        rig.core._state.focus = case["focus"]
        return rig.fold()
    finally:
        rig.close()


def _focus_fields(focus) -> tuple:
    return (focus.manual_id, focus.bound_id, focus.pending, focus.reporting_id, focus.source_service_name)


def _shown(snapshot) -> tuple | None:
    np = snapshot.now_playing
    if np is None:
        return None
    return (np.service_name, np.artist, np.title, np.album, np.master_volume, np.playing)


_GRID = [generate(random.Random(seed)) for seed in range(CASES)]


@pytest.mark.parametrize("case", _GRID, ids=[f"case{n}" for n in range(CASES)])
def test_the_three_decide_alike(case, monkeypatch):
    old = by_poll(case, monkeypatch)
    assert _focus_fields(by_choose_focus(case)) == _focus_fields(old.focus)
    new = by_pool(case)
    assert _focus_fields(new.focus) == _focus_fields(old.focus)
    assert new.focus.idle_focus == old.focus.idle_focus
    assert _shown(new) == _shown(old)
    assert new.visible_playing == old.visible_playing


def test_the_grid_covers_the_rule():
    """Each branch of the rule is reached by some case."""
    seen = set()
    for case in _GRID:
        choice = dial_core_focus.choose_focus(
            [ApplianceState(aid(n), service(n), n, "192.0.2.10", 80, a["playing"],
                            a["since"] if a["playing"] else 0.0, a["auth"], True, True, True, True, 4, 2, 2,
                            None, 50, False, None)
             for n, a in case["appliances"].items()],
            case["focus"], NOW,
            tracks={aid(n): _TRACKS[a["track"]] if a["playing"] else None for n, a in case["appliances"].items()},
            prev_playing_ids=case["prev"])
        if choice.idle_focus is not None:
            seen.add("idle focus")
        if choice.clear_reason:
            seen.add(choice.clear_reason)
        if choice.pending is not None and not choice.visible:
            seen.add("pending shown")
        if choice.visible and choice.selection.url:
            seen.add("artwork")
        if choice.visible and not choice.selection.service:
            seen.add("oldest playing")
        if choice.visible and case["focus"].bound_id == choice.reporting_id and case["focus"].manual_id is None:
            seen.add("binding kept")
    assert seen >= {"idle focus", "appliance gone or unauthorized", "appliance stopped playing",
                    "pending shown", "artwork", "oldest playing", "binding kept"}


def test_the_pending_grace_is_the_one_change():
    assert dial_core.FOCUS_PENDING_GRACE_S == 10.0
    assert dial_core_focus.FOCUS_PENDING_GRACE_S == 3.0
