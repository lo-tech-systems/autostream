"""Showcase scenarios for the HD dial page: the same kind of scenario the
page's own corpus holds (tests/hd_scenarios.py), built here with the invented
tracks, generated cover art and the naming the product uses (appliances are
named for their input, speakers for their rooms).

The corpus's helpers are reused by import; its own scenarios are not touched.
Each scenario carries the page action that brings its state up, if any (the
equaliser is a panel the page opens on a tap).
"""
from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
for _p in (str(HERE), str(REPO_ROOT / "tests"), str(REPO_ROOT / "dial"), str(REPO_ROOT / "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import hd_scenarios as hs  # noqa: E402
from covers import cover_png  # noqa: E402
from dial_core_state import (  # noqa: E402
    ApplianceWarning, Artwork, EqBand, EqState, NowPlaying, OutputRow, OutputsState, artwork_key,
)
from dial_warning_text import WARNING_DESCRIPTORS, appliance_warning_descriptor, appliance_warning_key  # noqa: E402
from music import BY_KEY, Track  # noqa: E402

TURNTABLE = hs.LOUNGE
CD_PLAYER = hs.KITCHEN
TAPE_DECK = "c" * 20
IDS = {"Turntable": TURNTABLE, "CD Player": CD_PLAYER, "Tape Deck": TAPE_DECK}
NOW = hs.NOW

_ART_CACHE: dict = {}


def _art(track: Track):
    """(url, Artwork) for a track's generated cover."""
    url = f"https://provider.example/art/{track.key}.jpg"
    if track.key not in _ART_CACHE:
        _ART_CACHE[track.key] = cover_png(track)
    return url, Artwork("", artwork_key(url), _ART_CACHE[track.key], "", NOW - 5)


def speakers(*, busy=False) -> tuple:
    """Six rooms, some on and some off."""
    return (
        OutputRow("o1", "Lounge", True, 45, is_default=True),
        OutputRow("o2", "Kitchen", True, 30),
        OutputRow("o3", "Dining Room", False, 25),
        OutputRow("o4", "Bedroom", False, 20),
        OutputRow("o5", "Study", True, 38),
        OutputRow("o6", "Patio", False, 30,
                  remote_in_use=busy, remote_owner="CD Player" if busy else None),
    )


def _bands(gains) -> tuple:
    return tuple(
        EqBand(f"peq{n}", hz, gain, -12, 12)
        for n, (hz, gain) in enumerate(zip((40, 100, 300, 1000, 4000, 10000), gains), start=1)
    )


SIX_GAINS = (4, 2, -1, 0, 3, 5)


def _appliances(playing_name, volume, *, muted=False, repeat=None, eq_version=2, warnings=()):
    """Two appliances, both authorised: *playing_name* is playing and the
    other is idle. (Two rows fit the list at the smallest panel size.)"""
    other = "CD Player" if playing_name != "CD Player" else "Turntable"
    if playing_name == "Tape Deck":
        other = "Turntable"
    out = []
    for name in sorted((playing_name, other), key=list(IDS).index):
        ident = IDS[name]
        live = name == playing_name
        out.append(hs.appliance(
            ident, name, playing=live, eq_version=eq_version,
            master_volume=volume if live else 40, muted=muted if live else False,
            repeat=repeat if live else None, warnings=warnings if live else (),
            ip={"Turntable": "192.0.2.21", "CD Player": "192.0.2.22", "Tape Deck": "192.0.2.23"}[name],
        ))
    return tuple(out)


def playing(track: Track, *, volume=42, muted=False, rows=None, eq="six", repeat=None,
            artwork=True, **overrides):
    """A snapshot of *track* playing on its appliance, with the other
    appliances idle."""
    ident = IDS[track.appliance]
    url, held = _art(track)
    eq_version = {"six": 2, "two": 1}[eq]
    bands = _bands(SIX_GAINS) + hs.DERIVED_BANDS if eq == "six" else hs.DERIVED_BANDS
    values = dict(
        appliances=_appliances(track.appliance, volume, muted=muted, repeat=repeat, eq_version=eq_version),
        focus=hs._focus(reporting=ident, service=track.appliance),
        now_playing=NowPlaying(track.appliance, track.artist, track.title, volume, album=track.album,
                               artwork_url=url if artwork else ""),
        artwork=held if artwork else None,
        volume_readout=(track.appliance, volume), visible_playing=(ident,),
        outputs=OutputsState(ident, rows or speakers(), True, NOW - 1), outputs_available=True,
        eq=EqState(ident, eq_version, bands, True, (), 0.0), eq_available=True,
    )
    values.update(overrides)
    return hs.base(**values)


def _scenario(name, snapshot, *, muted=False, action="", **kwargs):
    scenario = hs.Scenario(name, snapshot, muted=muted, **kwargs)
    return scenario, action


def _stylus_scenario(track: Track):
    ident = IDS[track.appliance]
    warning = ApplianceWarning(
        "stylus_in1", "warning", "Stylus wear", "The stylus has played for about 450 hours.",
        "week", appliance_name=track.appliance,
    )
    key = appliance_warning_key(ident, warning.id)
    descriptor = appliance_warning_descriptor(ident, warning)
    snapshot = playing(track)
    snapshot = dataclasses.replace(
        snapshot,
        appliances=tuple(
            dataclasses.replace(a, warnings=(warning,)) if a.appliance_id == ident else a
            for a in snapshot.appliances),
        warnings=hs.warning_states({key: warning.severity}, extra=(key,)),
        due_warning_id=key,
    )
    return hs.Scenario("warning-stylus", snapshot, descriptors=WARNING_DESCRIPTORS + (descriptor,))


def build() -> list:
    """The showcase scenarios, in order, as (Scenario, action) pairs; the
    action is "" or what to do in the page once it has loaded ("eq" opens the
    equaliser, "scroll-speakers" scrolls the speaker list to its end).
    Scenario names are the file-name stems of the captured pictures."""
    jazz, folk, rock = BY_KEY["jazz"], BY_KEY["folk"], BY_KEY["rock"]
    classical, soul, electronic, ambient = (
        BY_KEY["classical"], BY_KEY["soul"], BY_KEY["electronic"], BY_KEY["ambient"])
    out = []

    def add(*args, **kwargs):
        out.append(_scenario(*args, **kwargs))

    # One now-playing picture per invented track.
    for track, volume in ((jazz, 42), (folk, 36), (rock, 58), (classical, 30), (soul, 50),
                          (electronic, 64), (ambient, 28)):
        add(f"now-playing-{track.key}", playing(track, volume=volume))
    add("now-playing-muted", playing(jazz, muted=True), muted=True)

    # The speakers: six rooms, some on and some off, one taken by another
    # appliance; the second is scrolled to the rooms below the first few.
    add("speakers", playing(soul, volume=50))
    add("speakers-more", playing(soul, volume=50), action="scroll-speakers")
    add("speakers-in-use", playing(soul, volume=50, rows=speakers(busy=True)),
        action="scroll-speakers")

    # The appliance list: the turntable playing, the CD player idle.
    add("appliances", playing(folk, volume=36))

    # The equaliser panel, in both of its layouts.
    add("equaliser-six-band", playing(rock, volume=58), action="eq")
    two = playing(classical, volume=30, eq="two")
    two = dataclasses.replace(two, eq=EqState(CD_PLAYER, 1, (
        EqBand("bass", None, 2, -6, 6), EqBand("treble", None, 3, -6, 6)), True, (), 0.0))
    add("equaliser-bass-treble", two, action="eq")

    # Repeat Play: enabled while playing live, then replaying.
    add("repeat-enabled", playing(jazz, repeat=hs.repeat_record("recording", armed=True)))
    replay = playing(
        folk, volume=36, repeat=hs.repeat_record("replaying", armed=True, position=120.0, duration=1100.0),
        transport=hs.TransportRequest(TURNTABLE, "seek", NOW - 2, "accepted", NOW - 1, None),
        focus=hs._focus(manual=TURNTABLE, reporting=TURNTABLE, service="Turntable"),
    )
    add("replaying", replay)

    # Nothing playing: the logo.
    add("idle", hs.base(appliances=tuple(
        hs.appliance(IDS[name], name, master_volume=40, muted=False, ip=f"192.0.2.{21 + n}")
        for n, name in enumerate(("Turntable", "CD Player")))), muted=None)

    # A warning card: the stylus reminder.
    out.append((_stylus_scenario(jazz), ""))
    return out


SCENARIOS = None


def scenarios() -> list:
    global SCENARIOS
    if SCENARIOS is None:
        SCENARIOS = build()
    return SCENARIOS
