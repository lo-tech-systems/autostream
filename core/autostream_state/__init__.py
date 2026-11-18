"""autostream_state -- the process's immutable state snapshot.

store() is the process singleton: snapshot() for readers, claim() for the one
module that writes each part. The part types, their digests and the pure
helpers that read one snapshot are public here; the machinery behind them is
in the submodules.
"""
from .freeze import FrozenDict, thaw
from .parts import (
    MISSING_RATE_TEXTS,
    RATE_MATCHING_NOTE_DEFAULT,
    SAMPLE_RATE_TEXT_NOT_RUNNING,
    HealthPart,
    InputEntry,
    InputsPart,
    MonitorRuntimeInfo,
    RepeatPart,
    SessionPart,
    SettingsPart,
    Snapshot,
    TrackPart,
    active_track,
    empty_playback_snapshot,
    repeat_digest,
    repeat_recording_origin,
    replay_origin_input,
    session_source_input_index,
    track_digest,
    track_for_input,
)
from .store import Change, Origin, WriterTaken, store

__all__ = [
    "store", "Snapshot", "Change", "Origin", "FrozenDict", "thaw", "WriterTaken",
    "SessionPart", "RepeatPart", "TrackPart", "InputEntry", "InputsPart",
    "MonitorRuntimeInfo", "HealthPart", "SettingsPart",
    "RATE_MATCHING_NOTE_DEFAULT", "SAMPLE_RATE_TEXT_NOT_RUNNING", "MISSING_RATE_TEXTS",
    "empty_playback_snapshot", "repeat_digest", "track_digest",
    "replay_origin_input", "repeat_recording_origin",
    "session_source_input_index", "active_track", "track_for_input",
]
