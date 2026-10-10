"""The HD dial's scenario corpus: one real CoreSnapshot (with the warning
descriptors, panel view, recovery tuple and clock readings that go with it)
for each state the page has to draw.

Every other HD test layer reads from here, so a change to the snapshot types
breaks this module first. The snapshots are built straight from the frozen
dataclasses, so the corpus imports no display and no imaging library, and
what it holds is the same on every run.
"""
from __future__ import annotations

import dataclasses
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
for _p in (str(REPO_ROOT / "dial"), str(REPO_ROOT / "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dial_auth import AUTH_AUTHORIZED, AUTH_UNAUTHORIZED
from dial_core_state import (
    ApplianceState, ApplianceWarning, Artwork, CoreSnapshot, DialInfo, EqBand, EqState,
    FocusState, NowPlaying, OutputRow, OutputsState, TransportRequest, WarningState,
    artwork_key,
)
from dial_network import LINK_CONNECTED, LINK_DOWN, NetworkView
from dial_repeat_store import RepeatRecord
from dial_sdhealth import STATUS_VALID, SdHealthView
from dial_update_watch import STATUS_IN_PROGRESS, STATUS_SUCCESS, UpdateView
from dial_warning_text import WARNING_DESCRIPTORS, appliance_warning_descriptor, appliance_warning_key

# The two appliances most scenarios use.
LOUNGE = "a" * 20
KITCHEN = "b" * 20

# Fixed readings, so a build is the same on every run.
NOW = 1000.0            # monotonic
WALL_NOW = 1_700_000_000.0

# What the appliance would have sent that must never reach the page.
ARTWORK_URL = "https://provider.example/art/cover-7731.jpg"
SERVICE_NAME = "autostream on Lounge._autostream._tcp.local."
ARTWORK_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
    b"\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfe\xa7\x9a\xa0\xa0"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)
# A 2x2 dark blue PNG: what the mock serves for a backdrop, so it needs no imaging library.
BACKDROP_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x02\x00\x00\x00\x02\x08\x02\x00\x00\x00"
    b"\xfd\xd4\x9as\x00\x00\x00\x10IDATx\xdac\xe0\x94\xd2\x02\"\x06\x08\x05\x00\x07\xf6\x015\t\x13"
    b"\xbc\xfb\x00\x00\x00\x00IEND\xaeB`\x82"
)

DIAL = DialInfo(
    name="Lounge dial", version="0.8.0", uuid="11111111-2222-3333-4444-555555555555",
    ip="192.0.2.10", port=7842, inputs=("touch:hd",), volume_scope="current", mute_scope="current",
)

PANEL_AWAKE = {"asleep": False, "brightness": 80, "sleep_after_s": 300, "backlight": "sysfs"}
SETTINGS = {"brightness": 80, "sleep_after_s": 300, "always_show_controls": False}


def appliance(
    appliance_id=LOUNGE, name="Lounge", *, auth=AUTH_AUTHORIZED, playing=False, eq_version=2,
    outputs_version=1, repeat=None, status_error=None, master_volume=None, muted=None,
    warnings=(), supplies_warnings=True, ip="192.0.2.20",
) -> ApplianceState:
    return ApplianceState(
        appliance_id=appliance_id, service_name=name, name=name, ip=ip, port=80,
        playing=playing, playing_since=NOW - 60 if playing else 0.0, auth=auth,
        dial_status=True, dial_outputs=outputs_version > 0, dial_eq=eq_version > 0,
        repeat_capable=True, dial_proto_version=3, dial_eq_version=eq_version,
        dial_outputs_version=outputs_version, status_error=status_error,
        master_volume=master_volume, muted=muted, repeat=repeat, webui_scheme="http",
        webui_host=ip, webui_port=80, supplies_warnings=supplies_warnings, warnings=warnings,
    )


def repeat_record(state, *, armed=False, recording=1122.0, position=0.0, duration=0.0):
    return RepeatRecord(
        available=True, state=state, armed=armed, recording_seconds=recording,
        position_seconds=position, duration_seconds=duration, observed_at=NOW - 1.0,
    )


def warning_states(active: dict | None = None, snoozed: dict | None = None, extra: tuple = ()) -> tuple:
    """The registry's states, in registry order: the dial's own four, then
    *extra* ids. *active* maps an id to its severity (or reading)."""
    active = active or {}
    snoozed = snoozed or {}
    ids = tuple(d.id for d in WARNING_DESCRIPTORS) + tuple(extra)
    return tuple(
        WarningState(
            wid, wid in active, active.get(wid), WALL_NOW - 30 if wid in active else None,
            snoozed.get(wid),
        )
        for wid in ids
    )


def rows(*, in_use=False):
    return (
        OutputRow("o1", "Lounge L + R", True, 45, is_default=True),
        OutputRow("o2", "Patio", False, 30),
        OutputRow(
            "o3", "Bedroom", False, 20,
            remote_in_use=in_use, remote_owner="Kitchen" if in_use else None,
        ),
    )


SIX_BANDS = tuple(
    EqBand(f"peq{n}", hz, gain, -12, 12)
    for n, (hz, gain) in enumerate(
        ((40, 2), (100, 0), (300, -1), (1000, 0), (4000, 3), (10000, 1)), start=1,
    )
)
DERIVED_BANDS = (EqBand("bass", None, 2, -6, 6), EqBand("treble", None, 1, -6, 6))


def base(**overrides) -> CoreSnapshot:
    """An idle dial after its first poll: one authorised, silent appliance."""
    values = dict(
        seq=4790, at=NOW, polling=True, appliances=(appliance(),),
        focus=FocusState(None, None, None, None, None, None, False),
        now_playing=None, artwork=None, idle_affordance=False, outputs=None, eq=None,
        outputs_available=False, eq_available=False, warnings=warning_states(),
        due_warning_id=None,
        network=NetworkView(link=LINK_CONNECTED, bars=3, ssid="HomeNet", signal="Strong"),
        wifi_ever_connected=True,
        sd_health=SdHealthView(status=STATUS_VALID, percent=84),
        update=None, transport=None, volume_readout=(None, None), dial=DIAL,
        dots_active=False, visible_playing=(), ticks=12, tick=None, auth_promotions=0,
    )
    values.update(overrides)
    return CoreSnapshot(**values)


def _focus(reporting=LOUNGE, manual=None, idle=False, service="Lounge"):
    return FocusState(manual, reporting, None, reporting, service, None, idle)


def _playing(artwork=True, **overrides) -> CoreSnapshot:
    held = Artwork("", artwork_key(ARTWORK_URL), ARTWORK_BYTES, "", NOW - 5) if artwork else None
    values = dict(
        appliances=(appliance(playing=True, master_volume=42, muted=False),),
        focus=_focus(),
        now_playing=NowPlaying(
            "Lounge", "Dire Straits", "Tunnel of Love", 42, album="Making Movies",
            artwork_url=ARTWORK_URL if artwork else "",
        ),
        artwork=held, volume_readout=("Lounge", 42), visible_playing=(LOUNGE,),
        outputs=OutputsState(LOUNGE, rows(), True, NOW - 1, None), outputs_available=True,
        eq=EqState(LOUNGE, 2, SIX_BANDS + DERIVED_BANDS, True, (), 0.0), eq_available=True,
    )
    values.update(overrides)
    return base(**values)


def _replay_snapshot(state, **repeat_kwargs) -> CoreSnapshot:
    record = repeat_record(state, **repeat_kwargs)
    return _playing(
        artwork=False,
        appliances=(appliance(playing=state != "hold", repeat=record, master_volume=42, muted=False),),
        now_playing=NowPlaying("Lounge", "Dire Straits", "Tunnel of Love", 42, playing=state != "hold"),
        transport=TransportRequest(LOUNGE, "seek", NOW - 2, "accepted", NOW - 1, None),
        idle_affordance=state == "hold",
        focus=_focus(manual=LOUNGE, idle=state == "hold"),
    )


@dataclass(frozen=True)
class Scenario:
    name: str
    snapshot: CoreSnapshot
    descriptors: tuple = WARNING_DESCRIPTORS
    panel: dict = field(default_factory=lambda: dict(PANEL_AWAKE))
    settings: dict = field(default_factory=lambda: dict(SETTINGS))
    recovery: tuple = (False, False)
    muted: bool | None = False
    now: float = NOW
    wall_now: float = WALL_NOW

    def state(self, hub_seq: int = 4821) -> dict:
        """This scenario's state body, as the dial would build it."""
        from dial_hd_state import build_state
        return build_state(
            self.snapshot, descriptors=self.descriptors, panel=self.panel, settings=self.settings,
            recovery=self.recovery, hub_seq=hub_seq, now=self.now, wall_now=self.wall_now,
            muted=self.muted,
        )

    def with_snapshot(self, **overrides) -> "Scenario":
        return dataclasses.replace(self, snapshot=dataclasses.replace(self.snapshot, **overrides))


def replay_scenario(name: str, state: str, **repeat_kwargs) -> Scenario:
    """A scenario outside the corpus: the Lounge's repeat record in *state*
    (any of the six), with the record's readings given by *repeat_kwargs*."""
    return Scenario(name, _replay_snapshot(state, **repeat_kwargs), muted=None if state == "hold" else False)


def _stylus_warning(dismissal="week", severity="warning"):
    return ApplianceWarning(
        "stylus_in1", severity, "Technics stylus", "Needs changing soon.", dismissal,
        appliance_name="Lounge",
    )


def _appliance_warning_scenario(name, warning, snoozed=False) -> Scenario:
    key = appliance_warning_key(LOUNGE, warning.id)
    descriptor = appliance_warning_descriptor(LOUNGE, warning)
    snapshot = _playing(
        appliances=(appliance(playing=True, master_volume=42, muted=False, warnings=(warning,)),),
        warnings=warning_states(
            {key: warning.severity}, {key: WALL_NOW + 3600} if snoozed else None, extra=(key,),
        ),
        due_warning_id=key,
    )
    return Scenario(name, snapshot, descriptors=WARNING_DESCRIPTORS + (descriptor,))


def _build() -> dict:
    out: dict[str, Scenario] = {}

    def add(scenario: Scenario) -> None:
        out[scenario.name] = scenario

    add(Scenario("starting", base(ticks=0, appliances=(), network=None, sd_health=None), muted=None))
    add(Scenario("nothing_playing", base(), muted=None))
    add(Scenario("playing_artwork", _playing()))
    add(Scenario("playing_no_artwork", _playing(artwork=False)))
    add(Scenario("replay_hold", _replay_snapshot("hold", recording=1122.0), muted=None))
    add(Scenario("replaying", _replay_snapshot("replaying", armed=True, position=120.0, duration=1100.0)))
    add(Scenario("fading_out", _replay_snapshot("fading_out", position=1099.0, duration=1100.0)))

    kitchen_live = appliance(KITCHEN, "Kitchen", playing=True, master_volume=35, muted=False)
    add(Scenario("replay_elsewhere", _playing(
        appliances=(
            kitchen_live,
            appliance(LOUNGE, "Lounge", playing=True, repeat=repeat_record(
                "replaying", position=300.0, duration=1100.0), master_volume=42, muted=False),
        ),
        focus=_focus(reporting=KITCHEN, service="Kitchen"),
        now_playing=NowPlaying("Kitchen", "Joni Mitchell", "Blue", 35, album="Blue"),
        artwork=None, volume_readout=("Kitchen", 35), visible_playing=(KITCHEN, LOUNGE),
        outputs=OutputsState(KITCHEN, rows(), True, NOW - 1, None),
        eq=EqState(KITCHEN, 1, DERIVED_BANDS, True, (), 0.0),
    )))
    add(Scenario("in_use_speaker", _playing(
        outputs=OutputsState(LOUNGE, rows(in_use=True), True, NOW - 1, None),
    )))
    add(Scenario("unreachable", _playing(
        appliances=(appliance(playing=True, status_error="timeout"),), artwork=None,
    ), muted=None))
    add(Scenario("unauthorized", base(
        appliances=(appliance(), appliance(KITCHEN, "Kitchen", auth=AUTH_UNAUTHORIZED)),
    ), muted=None))
    add(Scenario("recovery_pending", base(), recovery=(True, False), muted=None))
    add(Scenario("eq_none", _playing(eq=None, eq_available=False, appliances=(
        appliance(playing=True, eq_version=0, master_volume=42, muted=False),))))
    add(Scenario("eq_two", _playing(
        appliances=(appliance(playing=True, eq_version=1, master_volume=42, muted=False),),
        eq=EqState(LOUNGE, 1, DERIVED_BANDS, True, (("bass", 4),), NOW + 1.5),
    )))
    add(Scenario("eq_six", _playing()))

    add(Scenario("warning_sdhealth", base(
        warnings=warning_states({"sdhealth": 6}), due_warning_id="sdhealth",
        sd_health=SdHealthView(status="stale", percent=6),
    ), muted=None))
    add(Scenario("warning_update", base(
        warnings=warning_states({"update": UpdateView(
            status=STATUS_IN_PROGRESS, percent=40, phase="python")}),
        due_warning_id="update",
        update=UpdateView(status=STATUS_IN_PROGRESS, percent=40, phase="python"),
    ), muted=None))
    done = UpdateView(status=STATUS_SUCCESS, percent=100, phase="done", tag="0.8.0", previous_tag="0.7.0")
    add(Scenario("warning_update_result", base(
        warnings=warning_states({"update_result": done}), due_warning_id="update_result", update=done,
    ), muted=None))
    add(Scenario("warning_nowifi", base(
        warnings=warning_states({"nowifi": None}), due_warning_id="nowifi",
        network=NetworkView(link=LINK_DOWN),
    ), muted=None))
    add(_appliance_warning_scenario("appliance_warning", _stylus_warning()))
    add(_appliance_warning_scenario(
        "appliance_warning_notice", _stylus_warning(dismissal="none", severity="info")))
    add(Scenario("disconnected", base(
        polling=False, appliances=(), network=NetworkView(link=LINK_DOWN), sd_health=None,
    ), muted=None))
    return out


SCENARIOS: dict = _build()

# The scenario names, in the order the corpus defines them.
SCENARIO_NAMES = tuple(SCENARIOS)
