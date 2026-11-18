"""autostream_state.parts -- the part types of the state snapshot.

Every part is a frozen dataclass whose values are immutable all the way down
(dicts are FrozenDict, lists are tuples), so a snapshot can be handed to any
thread and kept for as long as it is wanted. Each part also has a digest: the
tuple of the fields a reader would tell apart. The store bumps a part's
version only when its digest moves, so a field that changes every cycle and
matters to nobody (a position, a level) rides along in the part without
waking anyone.

The pure helpers at the end read one snapshot and nothing else.
"""
from __future__ import annotations

import dataclasses
import math
from dataclasses import dataclass, field
from typing import Callable, Optional

from autostream_peer_client import RosterEntry
from autostream_playback_stats import PlaybackSnapshot
from autostream_players import OutputInfo
from track_id.models import (
    STATE_ANALYSING,
    STATE_IDENTIFIED,
    TrackIdentificationSnapshot,
    disabled_snapshot,
    waiting_snapshot,
)

from .freeze import FrozenDict, thaw
from .origin import Origin


# ---------------------------------------------------------------------------
# Constants shared with the Setup readout
# ---------------------------------------------------------------------------

RATE_MATCHING_NOTE_DEFAULT = (
    "Follows the sample rate of the source. Turn on for an optical (S/PDIF) "
    "adapter fed by a CD or DVD player."
)
SAMPLE_RATE_TEXT_NOT_RUNNING = "Sample rate: not running"
MISSING_RATE_TEXTS = (RATE_MATCHING_NOTE_DEFAULT, SAMPLE_RATE_TEXT_NOT_RUNNING)


def format_khz(hz: float) -> str:
    """'44.1 kHz' / '48 kHz': one decimal, trimmed when the rounded value is
    whole; '' for a non-positive or non-finite value."""
    try:
        khz = round(float(hz) / 1000.0, 1)
    except (TypeError, ValueError):
        return ""
    if not math.isfinite(khz) or khz <= 0:
        return ""
    return f"{int(khz)} kHz" if khz == int(khz) else f"{khz:.1f} kHz"


# ---------------------------------------------------------------------------
# Parts
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SessionPart:
    active: bool = False
    source: Optional[str] = None            # "input1" | "input2" | "replay" | None

    def as_dict(self) -> dict:
        return {"active": self.active, "source": self.source}


@dataclass(frozen=True)
class RepeatPart:
    # The daemon's "repeat" status block, verbatim and frozen; None when the
    # feature has not reported (old binary, or not yet polled).
    block: Optional[FrozenDict] = None


@dataclass(frozen=True)
class TrackPart:
    entries: FrozenDict = field(default_factory=FrozenDict)   # input index -> TrackIdentificationSnapshot
    service_enabled: bool = False           # an identification service exists


@dataclass(frozen=True)
class InputEntry:
    index: int
    device: str
    input_type: str
    capturing: bool
    replay_origin: bool
    rate_note: str                          # Dynamic Rate Matching note on the Setup page
    sample_rate_text: str                   # Setup readout
    rate_mismatch_hz: int
    level: FrozenDict                       # the Web UI level item; moves every cycle, so not in the digest


@dataclass(frozen=True)
class InputsPart:
    entries: tuple[InputEntry, ...] = ()    # monitor order
    sample_rate_mismatch_input: int = 0
    sample_rate_warning_text: str = ""

    def levels(self) -> list[dict]:
        """The level item of each input as fresh, mutable dicts."""
        return [thaw(e.level) for e in self.entries]

    def entry(self, index: int) -> Optional[InputEntry]:
        for e in self.entries:
            if e.index == index:
                return e
        return None

    def rate_texts(self, index: int) -> tuple[str, str]:
        """(Dynamic Rate Matching note, sample rate readout) for an input;
        the not-running pair for an input that is absent."""
        e = self.entry(index)
        if e is None:
            return MISSING_RATE_TEXTS
        return e.rate_note, e.sample_rate_text


@dataclass(frozen=True)
class MonitorRuntimeInfo:
    """Latest top-level runtime metadata reported by autostream_monitor."""

    monitor_build: str = "unknown"
    log_level: str = "unknown"
    connected: bool = False
    last_seen_at: float = 0.0               # moves every cycle, so not in the digest
    output_trim_db: Optional[float] = None  # the auto-trim the monitor has accumulated; moves with the audio, so not in the digest


@dataclass(frozen=True)
class HealthPart:
    reconcile_fired_count: int = 0
    reconcile_last_fired_at: float = 0.0
    watchdog_armed: bool = False
    watchdog_restart_count: int = 0
    watchdog_last_restart_at: float = 0.0   # float("-inf") means never restarted

    def as_json(self) -> dict:
        """The five fields as a dict for the status reply.

        JSON boundary rule: the watchdog's "never restarted" sentinel is
        float("-inf") (the rate limit is vacuously satisfied), but -Infinity is
        not valid JSON. Python's json.dumps emits it anyway and Python's
        json.loads accepts it back, while every browser's strict JSON.parse
        rejects the whole payload. Non-finite timestamps are therefore mapped
        to None here, at the boundary; the part keeps the sentinel.
        """
        out = {
            "reconcile_fired_count": self.reconcile_fired_count,
            "reconcile_last_fired_at": self.reconcile_last_fired_at,
            "watchdog_armed": self.watchdog_armed,
            "watchdog_restart_count": self.watchdog_restart_count,
            "watchdog_last_restart_at": self.watchdog_last_restart_at,
        }
        for name, ts in out.items():
            if name.endswith("_at") and isinstance(ts, float) and not math.isfinite(ts):
                out[name] = None
        return out


@dataclass(frozen=True)
class EqPart:
    """The equaliser values the monitor daemon last acknowledged."""

    input_bands: FrozenDict = field(default_factory=FrozenDict)   # input index -> (40 Hz, 100 Hz, 8 kHz) dB
    input_gain: FrozenDict = field(default_factory=FrozenDict)    # input index -> dB
    output_bands: tuple = ()                # (peq1 .. peq6) dB; () before the first push
    output_gain_db: Optional[float] = None
    auto_trim_enabled: Optional[bool] = None


@dataclass(frozen=True)
class DevicesPart:
    """The capture devices the monitor lists and the Bluetooth daemon's status,
    refreshed by the device scan."""

    # Each device a FrozenDict with hw, card, name and label, in the order the
    # scan returns them.
    monitor_devices: tuple = ()
    # The Bluetooth daemon's last status reply; None when it was not fetched or
    # the service did not answer.
    bluetooth_status: Optional[FrozenDict] = None


@dataclass(frozen=True)
class SettingsPart:
    generation: int = 0


@dataclass(frozen=True)
class StartFailure:
    """The latest speaker start that failed, for the "could not start" notice."""

    seq: int                                # starts at 1 per process, +1 per failure; a client shows each seq once
    unit_id: str
    name: str                               # display name at the time of the failure
    reason: str                             # "pin_required" | "pin_invalid" | "encoder_capacity" | "refused" | "failed" | "timed_out"
    at: float                               # wall clock; not in the digest
    requester: Optional[str] = None         # who asked for the start ("webui", "dial:<id>", "peer"); None: the coordinator
    # With the store's boot id, (boot, seq) names one failure for ever: a
    # client that keeps the last seq it showed shows nothing twice, including
    # across its own reloads, and resets on a new boot.


@dataclass(frozen=True)
class OutputUnitView:
    id: str                                 # the visible row id (the Apple TV's id for a TV group)
    name: str
    selected: bool                          # desired
    volume: int                             # intended level: remembered level while muted, else desired volume
    muted: bool
    availability: str                       # "ok" | "starting" | "failed" | "password" | "gone"
    cause: Origin                           # who last changed desired
    reported: Optional[OutputInfo]          # the last row; None while the row is away after a boot change
    connecting: bool = False                # wanted in a session and the player has it, but it is not playing yet
    auto_start: bool = False                # the unit matches a member of the Auto-Start set, or is a placeholder for one
    hidden: bool = False                    # the name is in the hidden-speakers setting (compared casefolded)
    pin_claim: str = ""                     # who is entering a PIN for it ("webui", "dial:<id>"), or ""
    in_use_by: str = ""                     # the hostname of the other appliance playing it, or "" (never while it is selected here)
    in_use_id: str = ""                     # that appliance's id, or ""

    @property
    def offline(self) -> bool:
        """The player has no row for it: the default speaker's card while the
        speaker is not on the network."""
        return self.reported is None

    @property
    def shown_selected(self) -> bool:
        """What lists show as on: desired, except that a unit waiting for a
        PIN shows as off with its PIN offer, as the player reports it."""
        return self.selected and self.availability != "password"


@dataclass(frozen=True)
class DefaultMemberView:
    """One member of the Auto-Start set."""

    key: str                                # stable within the set
    id: str                                 # the saved unit id ("" for a member saved without one)
    name: str                               # the matched unit's live name, else the saved name
    volume: int                             # the saved level
    unit_id: str                            # the matched unit's id, or the placeholder card's id
    placeholder: bool                       # no unit matches; unit_id is the placeholder card
    pending: bool                           # still to be added this session


@dataclass(frozen=True)
class OutputsPart:
    units: tuple[OutputUnitView, ...] = ()  # backend row order
    connected: bool = False                 # reads succeed (or a start is pending)
    backend_boot: str = ""                  # the player's boot id, or "epoch:<n>" when it has none
    backend_restarts: int = 0               # restarts of the player seen since autostream started
    event_source: str = "poll"
    muted_all: bool = False                 # the appliance-level mute shown by dials and Home
    silence_chosen: bool = False            # per session: the user turned every speaker off
    start_failure: Optional[StartFailure] = None
    device_events: bool = False             # the player reports receiver commands and device volumes
    include_tv_supported: bool = False      # rows carry has_homepods: an Apple TV's HomePods can play without it
    default_members: tuple[DefaultMemberView, ...] = ()   # the Auto-Start set, in order
    default_matches: bool = False           # the selection is exactly the set, each member at its saved level
    master_volume: Optional[int] = None     # mean intended level of the selected speakers the player has; None when there are none
    selected_count: int = 0                 # how many speakers that is

    def unit(self, unit_id: str) -> Optional[OutputUnitView]:
        for u in self.units:
            if u.id == unit_id:
                return u
        return None

    def unit_by_name(self, name: str) -> Optional[OutputUnitView]:
        for u in self.units:
            if u.name == name and not u.offline:
                return u
        return None

    def placeholder_member(self, unit_id: str) -> Optional[DefaultMemberView]:
        """The member whose placeholder card has this id, or None."""
        for m in self.default_members:
            if m.placeholder and m.unit_id == unit_id:
                return m
        return None

    def selected_units(self) -> tuple[OutputUnitView, ...]:
        """The units that are desired selected and that the player has."""
        return tuple(u for u in self.units if u.selected and not u.offline)

    def reported_rows(self) -> tuple[OutputInfo, ...]:
        """The player's last row of every unit that has one, in row order."""
        return tuple(u.reported for u in self.units if u.reported is not None)


@dataclass(frozen=True)
class AppliancePart:
    """Who this appliance is and whether it is set up."""

    id: str = ""                            # the appliance id, or "" when it has none
    hostname: str = ""                      # as people see it, without ".local"
    version: str = ""                       # the installed release
    configured: bool = False                # first-boot commissioning is not required
    pin_set: bool = False                   # a PIN is in force


@dataclass(frozen=True)
class DialsPart:
    generation: int = 0                     # +1 on every authorise or revoke


@dataclass(frozen=True)
class WarningEntry:
    """One thing the appliance wants a person to know."""

    id: str                                 # kind id, e.g. "stylus_in1", "psu"
    incident: str                           # reserved; always ""
    severity: str                           # "info" | "warning" | "critical"
    kind: str                               # "psu", "cpu_temp", "sd_health", "stylus", ...
    subject: str                            # the input label for per-input kinds, else ""
    title: str
    message: str
    link: Optional[str]                     # a page of the web UI, or None
    snooze: str                             # "day" | "week" | "none"


@dataclass(frozen=True)
class WarningsPart:
    entries: tuple[WarningEntry, ...] = ()  # most severe first


@dataclass(frozen=True)
class PeersPart:
    entries: tuple[RosterEntry, ...] = ()   # the other appliances sighted, by hostname


def empty_playback_snapshot() -> PlaybackSnapshot:
    return PlaybackSnapshot(
        inputs=FrozenDict(),
        stylus_warning_indices=(),
        stylus_overdue_indices=(),
        stylus_banner_text=None,
        belt_warning_indices=(),
        belt_overdue_indices=(),
        belt_banner_text=None,
        bearing_warning_indices=(),
        bearing_overdue_indices=(),
        bearing_banner_text=None,
    )


@dataclass(frozen=True)
class Snapshot:
    """Everything the appliance knows about itself at one version."""

    version: int = 0
    boot: str = ""                          # 16 hex digits, new per process
    part_versions: FrozenDict = field(default_factory=FrozenDict)
    session: SessionPart = field(default_factory=SessionPart)
    repeat: RepeatPart = field(default_factory=RepeatPart)
    track: TrackPart = field(default_factory=TrackPart)
    inputs: InputsPart = field(default_factory=InputsPart)
    monitor: MonitorRuntimeInfo = field(default_factory=MonitorRuntimeInfo)
    playback: PlaybackSnapshot = field(default_factory=empty_playback_snapshot)
    health: HealthPart = field(default_factory=HealthPart)
    settings: SettingsPart = field(default_factory=SettingsPart)
    outputs: OutputsPart = field(default_factory=OutputsPart)
    eq: EqPart = field(default_factory=EqPart)
    devices: DevicesPart = field(default_factory=DevicesPart)
    appliance: AppliancePart = field(default_factory=AppliancePart)
    dials: DialsPart = field(default_factory=DialsPart)
    warnings: WarningsPart = field(default_factory=WarningsPart)
    peers: PeersPart = field(default_factory=PeersPart)


PART_NAMES = (
    "session", "repeat", "track", "inputs", "monitor", "playback", "health", "settings",
    "outputs", "eq", "devices", "appliance", "dials", "warnings", "peers",
)


# ---------------------------------------------------------------------------
# Digests
# ---------------------------------------------------------------------------

def repeat_digest(rs) -> tuple:
    """The parts of the daemon's repeat block a dial shows: whether the
    feature is on and armed, whether it is recording, holds a recording, is
    replaying or fading out. Positions and durations move every cycle and
    are left out."""
    if not isinstance(rs, dict):
        return ()
    rec = rs.get("recording") if isinstance(rs.get("recording"), dict) else {}
    rep = rs.get("replay") if isinstance(rs.get("replay"), dict) else {}
    return (
        bool(rs.get("enabled")), bool(rs.get("armed")), bool(rec.get("active")),
        (rec.get("seconds") or 0) > 0, bool(rep.get("active")), bool(rep.get("fading_out")),
    )


def track_digest(snap) -> tuple | None:
    """The parts of a track identification snapshot a dial shows: whether a
    track is identified and, if so, its title, artist, album and artwork.
    While an attempt is in flight there is nothing to say (None); the
    timestamps and the attempt states a dial does not tell apart are left
    out."""
    state = getattr(snap, "state", None)
    if state == STATE_ANALYSING:
        return None
    identified = state == STATE_IDENTIFIED
    artwork = (getattr(snap, "artwork_url", "") or "") if identified else ""
    if not artwork.startswith(("http://", "https://")):
        artwork = ""
    text = (
        tuple(getattr(snap, name, "") or "" for name in ("title", "artist", "album"))
        if identified else ("", "", "")
    )
    return (bool(getattr(snap, "enabled", False)), identified) + text + (artwork,)


def _session_digest(p: SessionPart) -> tuple:
    return (p.active, p.source)


def _repeat_part_digest(p: RepeatPart) -> tuple:
    return repeat_digest(p.block)


def _track_part_digest(p: TrackPart) -> tuple:
    return (
        p.service_enabled,
        tuple((i, track_digest(s)) for i, s in sorted(p.entries.items())),
    )


def _inputs_digest(p: InputsPart) -> tuple:
    return (
        tuple(
            (e.index, e.device, e.input_type, e.capturing, e.replay_origin,
             e.rate_note, e.sample_rate_text, e.rate_mismatch_hz)
            for e in p.entries
        ),
        p.sample_rate_mismatch_input,
        p.sample_rate_warning_text,
    )


def _monitor_digest(p: MonitorRuntimeInfo) -> tuple:
    return (p.monitor_build, p.log_level, p.connected)


def _playback_digest(p: PlaybackSnapshot) -> tuple:
    per_input = tuple(
        (i, s.enabled, s.active, s.stylus_warning, s.stylus_overdue,
         s.belt_warning, s.belt_overdue, s.bearing_warning, s.bearing_overdue,
         int(s.total_playback_seconds) // 60, int(s.stylus_playback_seconds) // 60)
        for i, s in sorted(p.inputs.items())
    )
    return (
        p.stylus_banner_text, p.belt_banner_text, p.bearing_banner_text,
        tuple(p.stylus_warning_indices), tuple(p.stylus_overdue_indices),
        tuple(p.belt_warning_indices), tuple(p.belt_overdue_indices),
        tuple(p.bearing_warning_indices), tuple(p.bearing_overdue_indices),
        per_input,
    )


def _health_digest(p: HealthPart) -> tuple:
    return (
        p.reconcile_fired_count, p.reconcile_last_fired_at, p.watchdog_armed,
        p.watchdog_restart_count, p.watchdog_last_restart_at,
    )


def _settings_digest(p: SettingsPart) -> int:
    return p.generation


def _unit_pin_fields(u: OutputUnitView) -> tuple:
    r = u.reported
    if r is None:
        return (False, False, False)
    return (r.needs_auth_key, r.requires_auth, r.pin_pending)


def _outputs_digest(p: OutputsPart) -> tuple:
    return (
        tuple(
            (u.id, u.name, u.shown_selected, u.volume, u.muted, u.availability,
             _unit_pin_fields(u), u.reported.type if u.reported is not None else "", u.connecting,
             u.auto_start, u.hidden, u.pin_claim, u.in_use_by, u.in_use_id)
            for u in p.units
        ),
        p.connected, p.muted_all, p.silence_chosen,
        p.start_failure.seq if p.start_failure is not None else 0,
        p.device_events, p.include_tv_supported, p.master_volume, p.selected_count,
        p.default_matches,
        tuple((m.key, m.name, m.volume, m.unit_id, m.placeholder, m.pending)
              for m in p.default_members),
    )


def _eq_digest(p: EqPart) -> tuple:
    return (
        tuple(sorted(p.input_bands.items())),
        tuple(sorted(p.input_gain.items())),
        p.output_bands, p.output_gain_db, p.auto_trim_enabled,
    )


def _devices_digest(p: DevicesPart) -> tuple:
    return (p.monitor_devices, p.bluetooth_status)


def _appliance_digest(p: AppliancePart) -> tuple:
    return (p.id, p.hostname, p.version, p.configured, p.pin_set)


def _dials_digest(p: DialsPart) -> int:
    return p.generation


def _warnings_digest(p: WarningsPart) -> tuple:
    return tuple(
        (e.id, e.incident, e.severity, e.kind, e.subject, e.title, e.message, e.link, e.snooze)
        for e in p.entries
    )


def _peers_digest(p: PeersPart) -> tuple:
    return tuple(dataclasses.astuple(e) for e in p.entries)


def eq_band_digest(p: EqPart) -> tuple:
    """What a dial shows of the equaliser: the output bands."""
    return p.output_bands


def outputs_list_digest(p: OutputsPart) -> tuple:
    """What a speaker list shows: each unit's name, whether it is on, whether
    it is starting or failed, its PIN fields, and whether the player answers."""
    return (
        tuple((u.id, u.name, u.shown_selected, u.availability, _unit_pin_fields(u))
              for u in p.units if not u.offline),
        p.connected,
    )


def outputs_volume_digest(p: OutputsPart) -> tuple:
    return tuple((u.id, u.volume) for u in p.units if not u.offline)


def outputs_mute_digest(p: OutputsPart) -> tuple:
    return (p.muted_all, tuple((u.id, u.muted) for u in p.units if not u.offline))


DIGESTS: dict[str, Callable] = {
    "session": _session_digest,
    "repeat": _repeat_part_digest,
    "track": _track_part_digest,
    "inputs": _inputs_digest,
    "monitor": _monitor_digest,
    "playback": _playback_digest,
    "health": _health_digest,
    "settings": _settings_digest,
    "outputs": _outputs_digest,
    "eq": _eq_digest,
    "devices": _devices_digest,
    "appliance": _appliance_digest,
    "dials": _dials_digest,
    "warnings": _warnings_digest,
    "peers": _peers_digest,
}


# ---------------------------------------------------------------------------
# Pure helpers over one snapshot
# ---------------------------------------------------------------------------

def replay_origin_input(repeat_status: Optional[dict]) -> Optional[int]:
    """Return the input index replay is attributed to, or None if not replaying.

    Replay is only a "source" while repeat.replay.active is
    true, and it is attributed to repeat.recording.origin_input (the daemon
    guarantees capture-stop -> replay-start is atomic within one snapshot, so
    there is never a poll where an input is still "capturing" for the same
    recording that is also replaying).
    """
    if not isinstance(repeat_status, dict):
        return None
    replay = repeat_status.get("replay")
    if not (isinstance(replay, dict) and bool(replay.get("active"))):
        return None
    recording = repeat_status.get("recording")
    if not isinstance(recording, dict):
        return None
    origin = recording.get("origin_input")
    return origin if isinstance(origin, int) else None


def repeat_recording_origin(repeat_status: Optional[dict]) -> Optional[int]:
    """Return repeat.recording.origin_input from a repeat block, or None.

    Unlike replay_origin_input() this does not require replay to be active:
    the daemon retains the origin through Hold, so it is still meaningful for
    an ack that is about to start a replay.
    """
    if not isinstance(repeat_status, dict):
        return None
    recording = repeat_status.get("recording")
    if not isinstance(recording, dict):
        return None
    origin = recording.get("origin_input")
    return origin if isinstance(origin, int) and not isinstance(origin, bool) else None


def session_source_input_index(snap: Snapshot) -> Optional[int]:
    """The input number behind the current session, or None when idle.

    "input1"/"input2" name a live source; "replay" resolves to the input
    the replaying recording came from, as the track identification snapshot
    and the now-playing source are resolved.
    """
    source = snap.session.source
    if source is None:
        return None
    if source == "replay":
        return replay_origin_input(snap.repeat.block)
    try:
        return int(source[len("input"):])
    except (ValueError, IndexError, TypeError):
        return None


def track_for_input(snap: Snapshot, index: int) -> TrackIdentificationSnapshot:
    """The latest identification snapshot of an input channel; the disabled
    snapshot for an input with none."""
    found = snap.track.entries.get(index)
    return found if found is not None else disabled_snapshot()


def active_track(snap: Snapshot) -> TrackIdentificationSnapshot:
    """Track identification state for the input actively sourcing audio.

    Prefers the session's own source over "any capturing input": the session
    source names the input that is genuinely the audible source ("input1" or
    "input2" for a live source, "replay" for the replay-origin input), so a
    probation transient's brief capturing flicker on a second input cannot
    hijack the displayed snapshot away from an input-1 replay by winning the
    first-capturing scan below.

    "Actively sourcing" (for the fallback scan) means capturing, or being the
    replay-origin input of a currently replaying recording. That scan checks
    capturing first, so a live capture on another input takes priority over a
    concurrently replaying recording when the session source is not yet known
    (the first cycle, before the session is published).

    Returns a waiting snapshot when the service is configured but nothing is
    actively sourcing, or a disabled snapshot when the service is off.
    """
    entries = snap.inputs.entries
    source = snap.session.source
    if source == "replay":
        for e in entries:
            if e.replay_origin:
                return track_for_input(snap, e.index)
    elif source is not None:
        try:
            idx = int(source[len("input"):])
        except (ValueError, IndexError):
            idx = None
        if idx is not None:
            for e in entries:
                if e.index == idx:
                    return track_for_input(snap, e.index)
    for e in entries:
        if e.capturing:
            return track_for_input(snap, e.index)
    for e in entries:
        if e.replay_origin:
            return track_for_input(snap, e.index)
    if snap.track.service_enabled:
        return waiting_snapshot()
    return disabled_snapshot()
