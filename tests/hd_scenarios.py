"""The HD dial's scenario corpus: one real CoreSnapshot (with the warning
descriptors, panel view, recovery tuple and clock readings that go with it)
for each state the page has to draw.

Each snapshot carries the focused appliance's PeerSnapshot, as the core folds
it into a publish. Unless a scenario gives its own, it is made from the
snapshot's speaker rows, equaliser, now playing, volume readout and repeat
record (and the scenario's mute flag), so a test that changes one of those
changes what the appliance reports with it.

Every other HD test layer reads from here, so a change to the snapshot types
breaks this module first. The snapshots are built straight from the frozen
dataclasses, so the corpus imports no display and no imaging library, and
what it holds is the same on every run.
"""
from __future__ import annotations

import dataclasses
import sys
from types import MappingProxyType, SimpleNamespace
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
for _p in (str(REPO_ROOT / "dial"), str(REPO_ROOT / "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from autostream_peer_client import PeerSnapshot
from dial_core_state import AUTH_AUTHORIZED, AUTH_UNAUTHORIZED
from dial_appliance_warnings import ApplianceWarning, protocol_warning
from dial_core_state import (
    ApplianceState, Artwork, CoreSnapshot, DialInfo, EqBand, EqState,
    FocusState, NowPlaying, OutputRow, OutputsState, PowerState, StartFailureNotice,
    TransportRequest, WarningState, artwork_key,
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
    b"\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9ccP0\x08\xf8\x0f\x00\x02\xb4\x01\xa0GwI\x1d\x00\x00\x00\x00IEND\xaeB`\x82"
)
# A 2x2 dark blue PNG for a backdrop, so a test needs no imaging library.
BACKDROP_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x02\x00\x00\x00\x02\x08\x02\x00\x00\x00"
    b"\xfd\xd4\x9as\x00\x00\x00\x10IDATx\xdac\xe0\x94\xd2\x02\"\x06\x08\x05\x00\x07\xf6\x015\t\x13"
    b"\xbc\xfb\x00\x00\x00\x00IEND\xaeB`\x82"
)

DIAL = DialInfo(
    name="Lounge dial", version="0.8.0", uuid="11111111-2222-3333-4444-555555555555",
    ip="192.0.2.10", port=7842, inputs=("touch:hd",), volume_scope="current", mute_scope="current",
)

# The focused appliance's boot id and store version, as its snapshot reports them.
PEER_BOOT = "peer-boot-1"
PEER_VERSION = 4810

PANEL_AWAKE = {"asleep": False, "brightness": 80, "sleep_after_s": 300, "backlight": "sysfs"}
SETTINGS = {"brightness": 80, "sleep_after_s": 300}


def appliance(
    appliance_id=LOUNGE, name="Lounge", *, auth=AUTH_AUTHORIZED, playing=False, eq_version=2,
    outputs_version=1, repeat=None, status_error=None, master_volume=None, muted=None,
    warnings=(), ip="192.0.2.20", proto=3,
) -> ApplianceState:
    return ApplianceState(
        appliance_id=appliance_id, service_name=name, name=name, ip=ip, port=80,
        playing=playing, playing_since=NOW - 60 if playing else 0.0, auth=auth,
        dial_status=True, dial_outputs=outputs_version > 0, dial_eq=eq_version > 0,
        repeat_capable=True, dial_proto_version=proto,
        dial_outputs_version=outputs_version, status_error=status_error,
        master_volume=master_volume, muted=muted, repeat=repeat, webui_scheme="http",
        webui_host=ip, webui_port=80, warnings=warnings,
    )


def repeat_record(state, *, armed=False, recording=1122.0, position=0.0, duration=0.0,
                  latency=None):
    """A repeat record; *latency* (seconds the heard audio trails the
    reported position) is the record's default when left out."""
    extra = {} if latency is None else {"latency_seconds": latency}
    return RepeatRecord(
        available=True, state=state, armed=armed, recording_seconds=recording,
        position_seconds=position, duration_seconds=duration, observed_at=NOW - 1.0, **extra,
    )


def warning_states(active: dict | None = None, extra: tuple = ()) -> tuple:
    """The registry's states, in registry order: the dial's own four, then
    *extra* ids. *active* maps an id to its reading."""
    active = active or {}
    ids = tuple(d.id for d in WARNING_DESCRIPTORS) + tuple(extra)
    return tuple(
        WarningState(
            wid, wid in active, active.get(wid), WALL_NOW - 30 if wid in active else None,
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
        due_status_id=None,
        network=NetworkView(link=LINK_CONNECTED, bars=3, ssid="HomeNet", signal="Strong"),
        wifi_ever_connected=True,
        sd_health=SdHealthView(status=STATUS_VALID, percent=84),
        update=None, transport=None, dial=DIAL,
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
        artwork=held, visible_playing=(LOUNGE,),
        outputs=OutputsState(LOUNGE, rows(), True, NOW - 1), outputs_available=True,
        eq=EqState(LOUNGE, 2, SIX_BANDS + DERIVED_BANDS, True, (), 0.0), eq_available=True,
    )
    values.update(overrides)
    return base(**values)


def pin_request(state, error=None, kind="output_set", at=NOW - 1, retry_after_s=0) -> TransportRequest:
    """An output request on the Lounge's Patio speaker (id o2), made at *at*
    and now in *state*."""
    return TransportRequest(LOUNGE, kind, at, state, at, error, "o2", retry_after_s)


def _start_failure_notice(appliance_id, reason) -> StartFailureNotice:
    """A notice for the Patio speaker (id o2) of *appliance_id*."""
    return StartFailureNotice(
        appliance_id, f"{appliance_id}:boot-a:3", "o2", "Patio", reason, NOW - 1)


def _pin_snapshot(request, outputs_version=2) -> CoreSnapshot:
    return _playing(
        appliances=(appliance(
            playing=True, master_volume=42, muted=False, outputs_version=outputs_version),),
        outputs_request=request,
    )


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


def _repeat_part(record) -> dict:
    replaying = record.state in ("replaying", "fading_out")
    return {"block": {
        "enabled": True, "armed": record.armed,
        "recording": {"active": record.state == "recording", "seconds": record.recording_seconds,
                      "bytes": 1000 if record.recording_seconds else 0, "origin_input": 1},
        "replay": {"active": replaying, "fading_out": record.state == "fading_out",
                   "position_seconds": record.position_seconds, "duration_seconds": record.duration_seconds},
    }}


def _units(held) -> list:
    return [{
        "id": row.id, "name": row.name, "selected": row.selected, "volume": row.volume,
        "availability": "ok", "auto_start": row.is_default, "held": row.paused, "muted": row.muted,
        **({"in_use_by": row.remote_owner or "another appliance", "in_use_id": KITCHEN}
           if row.remote_in_use else {}),
    } for row in held.rows]


def focused_peer(snapshot: CoreSnapshot, muted=None, *, level=None, boot=PEER_BOOT, version=PEER_VERSION, **parts):
    """The focused appliance's PeerSnapshot for *snapshot*, made from the same
    readings the snapshot holds; None with no focus. *parts* replace or add
    whole parts. *level* is the master volume shown, else the appliance's own."""
    appliance_id = snapshot.focused_id()
    a = snapshot.appliance(appliance_id)
    if a is None:
        return None
    reachable = a.status_error in (None, "unauthorized", "protocol")
    protocol_ok = a.status_error != "protocol"
    access = "playback" if a.auth == AUTH_AUTHORIZED and reachable and protocol_ok else "none"
    held: dict = {}
    if protocol_ok:
        replaying = a.repeat is not None and a.repeat.state in ("replaying", "fading_out")
        playing = snapshot.now_playing if snapshot.focus.reporting_id == appliance_id else None
        active = bool(a.playing) and (playing is None or playing.playing)
        held["session"] = {"active": active, "source": "replay" if replaying else "input1" if active else ""}
        if playing is not None and playing.title:
            held["track"] = {"entries": {"1": {"enabled": True, "state": "identified", "title": playing.title,
                                               "artist": playing.artist, "album": playing.album}}}
        kind = {"CD": "cd", "Turntable": "turntable"}.get(playing.input_label, "line") if playing is not None else "line"
        held["inputs"] = {"entries": [{"index": 1, "input_type": kind, "level": {"label": "Input 1"}}]}
        outputs = snapshot.outputs
        if outputs is not None and outputs.appliance_id == appliance_id:
            units = _units(outputs)
            on = {u["id"] for u in units if u["selected"]}
            saved = {u["id"] for u in units if u["auto_start"]}
            held["outputs"] = {
                "connected": True, "master_volume": a.master_volume if level is None else level,
                "muted_all": bool(muted if muted is not None else a.muted),
                "units": units, "default_matches": bool(on) and on == saved,
            }
        eq = snapshot.eq
        if eq is not None and eq.appliance_id == appliance_id and eq.capability_version >= 2:
            gains = {band.id: band.gain_db for band in eq.bands}
            held["eq"] = {"output_bands": [gains.get(f"peq{n}", 0) for n in range(1, 7)]}
        if a.repeat is not None:
            held["repeat"] = _repeat_part(a.repeat)
    held.update(parts)
    return PeerSnapshot(
        peer_id=appliance_id, boot=boot, version=version, part_versions=MappingProxyType({}),
        parts=MappingProxyType(held), reachable=reachable, access=access, access_reason=None,
        protocol=4 if protocol_ok else 3, protocol_ok=protocol_ok, configured=True, heard_at=NOW - 1, seq=1)


# A Scenario's peer when it gives none: made from its snapshot.
DERIVED = "derived"


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
    # The focused appliance's PeerSnapshot (or None), else DERIVED.
    peer: object = DERIVED
    # The master volume the derived peer shows, else the focused appliance's own.
    level: int | None = None

    def __post_init__(self) -> None:
        peer = focused_peer(self.snapshot, self.muted, level=self.level) if self.peer == DERIVED else self.peer
        object.__setattr__(self, "snapshot", dataclasses.replace(self.snapshot, focused_peer=peer))

    def state(self) -> dict:
        """This scenario's `dial` part, as the dial would build it."""
        return self.parts()["dial"]

    def parts(self) -> dict:
        """This scenario's two parts, as the dial would build them."""
        from dial_hd_state import build_parts
        return build_parts(
            self.snapshot, descriptors=self.descriptors, panel=self.panel, settings=self.settings,
            recovery=self.recovery, now=self.now,
        )

    def with_snapshot(self, **overrides) -> "Scenario":
        """This scenario with snapshot fields replaced; the peer is made again
        from them unless *focused_peer* is one of them."""
        peer = overrides.pop("focused_peer", self.peer)
        return dataclasses.replace(self, snapshot=dataclasses.replace(self.snapshot, **overrides), peer=peer)

    def with_level(self, level: int) -> "Scenario":
        """This scenario with the master volume its derived peer shows set to *level*."""
        return dataclasses.replace(self, level=level)

    def with_peer(self, **changes) -> "Scenario":
        """This scenario with its derived peer changed: *changes* are
        focused_peer's keywords (boot, version, whole parts) or PeerSnapshot
        fields."""
        fields = {k: changes.pop(k) for k in list(changes) if k in PeerSnapshot.__dataclass_fields__ and k not in ("boot", "version")}
        peer = focused_peer(self.snapshot, self.muted, level=self.level, **changes)
        return dataclasses.replace(self, peer=dataclasses.replace(peer, **fields))


def replay_scenario(name: str, state: str, **repeat_kwargs) -> Scenario:
    """A scenario outside the corpus: the Lounge's repeat record in *state*
    (any of the six), with the record's readings given by *repeat_kwargs*."""
    return Scenario(name, _replay_snapshot(state, **repeat_kwargs), muted=None if state == "hold" else False)


def _stylus_warning(severity="warning", detail=""):
    return ApplianceWarning(
        "stylus_in1", severity, "Technics stylus", "Needs changing soon.",
        appliance_name="Lounge", detail=detail,
    )


def _update_warning():
    """The warning the dial raises for the Lounge appliance on an older dial
    protocol than its own."""
    entry = SimpleNamespace(
        appliance_id=LOUNGE, auth=AUTH_AUTHORIZED, dial_proto_version=2, service_name="Lounge")
    return protocol_warning(entry, 3)


def _appliance_warning_scenario(name, warning, proto=3) -> Scenario:
    key = appliance_warning_key(LOUNGE, warning.id)
    descriptor = appliance_warning_descriptor(LOUNGE, warning)
    snapshot = _playing(
        appliances=(appliance(
            playing=True, master_volume=42, muted=False, warnings=(warning,), proto=proto),),
        warnings=warning_states({key: warning.severity}, extra=(key,)),
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
    add(Scenario("playing_untitled", _playing(
        artwork=False, now_playing=NowPlaying("Lounge", "", "", 42),
    )))
    add(Scenario("playing_untitled_input", _playing(
        artwork=False, now_playing=NowPlaying("Lounge", "", "", 42, input_label="CD"),
    )))
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
        artwork=None, visible_playing=(KITCHEN, LOUNGE),
        outputs=OutputsState(KITCHEN, rows(), True, NOW - 1),
        eq=EqState(KITCHEN, 1, DERIVED_BANDS, True, (), 0.0),
    )))
    add(Scenario("in_use_speaker", _playing(
        outputs=OutputsState(LOUNGE, rows(in_use=True), True, NOW - 1),
    )))
    add(Scenario("unreachable", _playing(
        appliances=(appliance(playing=True, status_error="timeout", master_volume=42),), artwork=None,
    ), muted=None))
    add(Scenario("unauthorized", base(
        appliances=(appliance(), appliance(KITCHEN, "Kitchen", auth=AUTH_UNAUTHORIZED)),
    ), muted=None))
    add(Scenario("recovery_pending", base(), recovery=(True, False), muted=None))
    add(Scenario("power_requested", base(power=PowerState("requested", NOW - 1)), muted=None))
    add(Scenario("power_failed", base(power=PowerState("failed", NOW - 1)), muted=None))
    add(Scenario("eq_none", _playing(eq=None, eq_available=False, appliances=(
        appliance(playing=True, eq_version=0, master_volume=42, muted=False),))))
    add(Scenario("eq_six", _playing()))

    add(Scenario("warning_sdhealth", base(
        warnings=warning_states({"sdhealth": ("low", 18, "2026-03-03T10:00:00+00:00")}),
        sd_health=SdHealthView(status="stale", percent=18, date="2026-03-03T10:00:00+00:00"),
    ), muted=None))
    add(Scenario("warning_update", base(
        warnings=warning_states({"update": UpdateView(
            status=STATUS_IN_PROGRESS, percent=40, phase="python")}),
        due_status_id="update",
        update=UpdateView(status=STATUS_IN_PROGRESS, percent=40, phase="python"),
    ), muted=None))
    done = UpdateView(status=STATUS_SUCCESS, percent=100, phase="done", tag="0.8.0", previous_tag="0.7.0")
    add(Scenario("warning_update_result", base(
        warnings=warning_states({"update_result": done}), due_status_id="update_result", update=done,
    ), muted=None))
    add(Scenario("warning_nowifi", base(
        warnings=warning_states({"nowifi": None}),
        network=NetworkView(link=LINK_DOWN),
    ), muted=None))
    add(_appliance_warning_scenario("appliance_warning", _stylus_warning()))
    add(_appliance_warning_scenario("appliance_warning_info", _stylus_warning(severity="info")))
    add(_appliance_warning_scenario(
        "appliance_warning_detail", _stylus_warning(detail="Played 450 h of its 500 h life.")))
    needs_update = _appliance_warning_scenario(
        "appliance_needs_update", _update_warning(), proto=2)
    add(needs_update.with_snapshot(appliances=tuple(
        dataclasses.replace(a, status_error="protocol") for a in needs_update.snapshot.appliances)))
    add(Scenario("pin_required", _pin_snapshot(pin_request("rejected", "pin_required"))))
    add(Scenario("pin_invalid", _pin_snapshot(pin_request("rejected", "pin_invalid", "output_pin"))))
    add(Scenario("pin_busy", _pin_snapshot(pin_request("pending", None, "output_pin"))))
    add(Scenario("pin_rate_limited", _pin_snapshot(
        pin_request("rejected", "rate_limited", "output_pin", retry_after_s=7))))
    add(Scenario("pin_expired", _pin_snapshot(pin_request("rejected", "pin_required", at=NOW - 100))))
    add(Scenario("start_failure_refused", _playing(
        start_failure=_start_failure_notice(LOUNGE, "refused"))))
    add(Scenario("start_failure_elsewhere", _playing(
        start_failure=_start_failure_notice(KITCHEN, "refused"))))
    add(Scenario("start_failure_late_pin", _pin_snapshot(TransportRequest(
        LOUNGE, "output_set", NOW - 5, "rejected", NOW - 1, "pin_required", "o2", 0))))
    add(Scenario("disconnected", base(
        polling=False, appliances=(), network=NetworkView(link=LINK_DOWN), sd_health=None,
    ), muted=None))
    return out


SCENARIOS: dict = _build()

# The scenario names, in the order the corpus defines them.
SCENARIO_NAMES = tuple(SCENARIOS)
