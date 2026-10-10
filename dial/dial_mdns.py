"""dial_mdns.py — mDNS browsers for _autostream-playing._tcp and
_autostream._tcp, and the merged roster built from both.

Scans for autostream appliances announcing _autostream-playing._tcp.  Only
entries that carry dial_api=v1 in their TXT record are tracked — earlier
appliances without this field are ignored.

IPv4 only.  Deduplication across interfaces is handled by the shared
MdnsBrowser, keyed by mDNS service name.  get_playing_targets() returns one
entry per service name for fan-out.

Transition logging (0→1 and N→0) is preserved here using callbacks, outside
the shared registry lock.

Identity is appliance_id, parsed from the TXT `id` record. Authorization
knowledge for that id lives entirely in dial_auth, and is stamped onto every
target this module returns as `auth` — this module never decides who is
authorized, it only carries the id and reports the current answer.

A second browser (started only when a screen is fitted) scans
_autostream._tcp — every dial-capable appliance, playing or idle — and
get_roster() merges it with the playing browser's own view into one list
keyed by appliance_id. The merge is also the single feeder of general
(idle) sightings into dial_auth's map: the playing browser's parser keeps
feeding it for ids it sees, so a given id is never fed from both sides at
once. Volume and mute never read this roster — they stay on
get_playing_targets()/get_display_targets(), unaffected by anything below.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import re
import sys
import os
import threading
import time

import dial_auth

# The dial deployment copies core modules into /opt/autostream/ at the same
# level as the dial package, so autostream_mdns is importable directly there.
# In the repo the module lives in core/, which may or may not be on sys.path.
try:
    from autostream_mdns import MdnsBrowser
except ImportError:
    _core = os.path.join(os.path.dirname(__file__), '..', 'core')
    sys.path.insert(0, os.path.abspath(_core))
    from autostream_mdns import MdnsBrowser

import dataclasses
from dataclasses import dataclass

_APPLIANCE_ID_RE = re.compile(r"^[0-9a-f]{20}$")

# The mDNS service name prefix stripped by appliance_display_name().
_SERVICE_PREFIX = "autostream on "


@dataclass
class PlayingTarget:
    ip:                 str
    port:               int
    name:               str
    dial_api:           bool  = False
    audio_status:       bool  = False
    dial_status:        bool  = False
    dial_outputs:       bool  = False
    dial_eq:            bool  = False
    service_name:       str   = ""
    playing_since:      float = 0.0
    appliance_id:       str   = ""
    auth:               str   = dial_auth.AUTH_UNKNOWN


# Tracks whether we have ever seen a playing target — persists across
# avahi-browse restarts so that restart-cycle re-resolutions do not
# re-emit the 0→1 transition log.
_had_targets: bool = False

# Display-selection bookkeeping, keyed by mDNS service name. playing_since is
# tied to the service identity and survives IP/port refreshes across resolve
# cycles. Authorization knowledge itself is NOT kept here — it lives in
# dial_auth, keyed by appliance_id, so it survives a service-name rename.
_state_lock: threading.Lock = threading.Lock()
_target_state: dict[str, dict] = {}


def _parse_playing_event(parts: list, txt: dict) -> tuple | None:
    """Parse a resolved _autostream-playing._tcp event.

    Returns (service_name, PlayingTarget) or None if the appliance lacks
    dial_api=v1 capability.
    """
    if txt.get('dial_api') != 'v1':
        return None
    try:
        port = int(parts[8])
    except (ValueError, IndexError):
        port = 80
    svc_name = parts[3]
    ip = parts[7]

    raw_id = txt.get('id', '')
    appliance_id = raw_id if _APPLIANCE_ID_RE.match(raw_id) else ""

    with _state_lock:
        prior = _target_state.get(svc_name)
        if prior is None:
            playing_since = time.monotonic()
        else:
            playing_since = prior["playing_since"]
        _target_state[svc_name] = {
            "playing_since":  playing_since,
            "ip":             ip,
            "port":           port,
            "appliance_id":   appliance_id,
        }

    # Outside _state_lock: dial_auth._lock is a leaf lock and must never be
    # nested with another lock.
    if appliance_id:
        dial_auth.auth_map.note_sighting(appliance_id, ip, port, time.monotonic())

    target = PlayingTarget(
        ip=ip,
        port=port,
        name=svc_name,
        dial_api=True,
        audio_status=(txt.get('audio_status') == 'v1'),
        dial_status=(txt.get('dial_status') == 'v1'),
        dial_outputs=(txt.get('dial_outputs') == 'v1'),
        dial_eq=(txt.get('dial_eq') == 'v1'),
        service_name=svc_name,
        playing_since=playing_since,
        appliance_id=appliance_id,
    )
    return (svc_name, target)


def _on_target_add(svc_name: str, target: PlayingTarget) -> None:
    global _had_targets
    if not _had_targets:
        _had_targets = True
        logging.info("playing target found: %s (%s)", svc_name, target.ip)


def _on_target_change(svc_name: str, old: PlayingTarget, new: PlayingTarget) -> None:
    """Log an address change. The auth reset for it already happened inside
    _parse_playing_event via note_sighting, which is the single place the
    (ip, port) pair is compared — this callback only logs."""
    if (old.ip, old.port) != (new.ip, new.port):
        logging.debug(
            "playing target address changed: %s %s:%s -> %s:%s",
            svc_name, old.ip, old.port, new.ip, new.port,
        )


def _on_target_remove(svc_name: str, target: PlayingTarget | None) -> None:
    with _state_lock:
        _target_state.pop(svc_name, None)
    snap = _browser.get_snapshot()
    if not snap:
        global _had_targets
        _had_targets = False
        logging.info("no playing targets — encoder gated")


_browser: MdnsBrowser = MdnsBrowser(
    service_type="_autostream-playing._tcp",
    parse_fn=_parse_playing_event,
    on_add=_on_target_add,
    on_remove=_on_target_remove,
    on_change=_on_target_change,
)


def _with_auth(target: PlayingTarget) -> PlayingTarget:
    """Stamp the current auth state for target.appliance_id.

    A raising map read must never gate control, so any failure degrades to
    unknown — the same as an appliance never seen before.
    """
    try:
        state = dial_auth.auth_map.state(target.appliance_id)
    except Exception:
        state = dial_auth.AUTH_UNKNOWN
    return dataclasses.replace(target, auth=state)


def get_playing_targets() -> list[PlayingTarget]:
    """Return one entry per mDNS service name — deduplicated across interfaces."""
    return [_with_auth(t) for t in _browser.get_snapshot().values()]


def get_display_targets() -> list[PlayingTarget]:
    """Return currently visible playing targets, ordered for display-source selection.

    Sorted by oldest playing_since first, with stable name/ip/port tie-breaks.
    """
    snapshot = _browser.get_snapshot()
    targets: list[PlayingTarget] = []
    with _state_lock:
        for svc_name, target in snapshot.items():
            state = _target_state.get(svc_name)
            if state is None:
                targets.append(target)
                continue
            targets.append(dataclasses.replace(
                target,
                playing_since=state["playing_since"],
            ))
    targets.sort(key=lambda t: (t.playing_since, t.name, t.ip, t.port))
    return [_with_auth(t) for t in targets]


def _avahi_unescape(s: str) -> str:
    """Decode avahi-browse parsable-mode escapes. In -p output a byte is
    escaped as a backslash followed by its three-digit DECIMAL value (a
    space becomes \\032), and dot and backslash as \\. and \\\\. The service
    instance name therefore arrives as e.g. autostream\\032on\\032CD_Player."""
    out = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), s)
    return out.replace("\\.", ".").replace("\\\\", "\\")


def appliance_display_name(service_name: str) -> str:
    """Hostname part of the mDNS service name, underscores shown as spaces.

    The name is unescaped first (see _avahi_unescape): avahi hands us the
    instance name with spaces escaped as \\032, so the "autostream on "
    prefix only matches after decoding.
    """
    name = _avahi_unescape(service_name)
    host = (
        name[len(_SERVICE_PREFIX):]
        if name.startswith(_SERVICE_PREFIX)
        else name
    )
    return host.replace("_", " ")


def start_playing_browser(
    shutdown_event: "threading.Event | None" = None,
) -> None:
    """Start the background mDNS browser for _autostream-playing._tcp.  Idempotent."""
    _browser.start(shutdown_event=shutdown_event)


def stop_playing_browser() -> None:
    """Stop the background mDNS browser for _autostream-playing._tcp.  Idempotent."""
    _browser.stop()


# ---------------------------------------------------------------------------
# The _autostream._tcp general browser and the merged roster.
#
# This is the dial's OWN general-appliance browser — distinct from
# core/autostream_appliances.py's browser of the same service type, which the
# appliance side runs for peer/federation discovery. The dial never imports
# that module; it runs its own instance of the shared MdnsBrowser so it can
# see idle (not-currently-playing) appliances too, which the playing-only
# browser above never reports.
# ---------------------------------------------------------------------------

_GENERAL_SERVICE_TYPE = "_autostream._tcp"


@dataclass
class GeneralSighting:
    appliance_id: str
    service_name: str
    hostname: str
    ip: str
    port: int
    version: str
    repeat: bool          # repeat=v1
    dial_outputs: bool    # dial_outputs=v1
    dial_eq: bool         # dial_eq=v1


# Conflict-detection state for the general browser, keyed the same way as
# core/autostream_appliances.py's registry: a service_name -> (appliance_id,
# hostname) map, from which the set of distinct hostnames claiming a given
# id is rebuilt on every add/remove. A leaf lock, never nested with any
# other lock in this module.
_general_lock: threading.Lock = threading.Lock()
_general_svc: dict[str, tuple[str, str]] = {}
_general_conflicts: set[str] = set()


def _rebuild_general_conflict_locked(appliance_id: str) -> None:
    """Recompute whether appliance_id is in conflict from the current
    _general_svc contents. Caller holds _general_lock."""
    hostnames = {h for aid, h in _general_svc.values() if aid == appliance_id}
    if len(hostnames) > 1:
        _general_conflicts.add(appliance_id)
    else:
        _general_conflicts.discard(appliance_id)


def _parse_general_event(parts: list, txt: dict) -> tuple | None:
    """Parse a resolved _autostream._tcp event for the dial's general
    browser.

    Requires dial_api=v1 (not ui/federation, which are appliance-to-
    appliance capabilities the dial has no use for) and a valid id. The
    control TXT flag is deliberately not read here: dials are gated by
    per-dial authorization only, never by the peer-control setting.

    Never calls note_sighting — the roster merge in get_roster() below is
    the single feeder for general sightings, so exactly one (ip, port) per
    id ever reaches dial_auth's map.
    """
    appliance_id = txt.get("id", "")
    if not _APPLIANCE_ID_RE.match(appliance_id):
        return None
    if txt.get("dial_api") != "v1":
        return None
    try:
        port = int(parts[8])
    except (ValueError, IndexError):
        port = 80
    service_name = parts[3]
    hostname = parts[6]
    ip = parts[7]
    version = txt.get("version", "")
    repeat = txt.get("repeat") == "v1"
    dial_outputs = txt.get("dial_outputs") == "v1"
    dial_eq = txt.get("dial_eq") == "v1"

    with _general_lock:
        _general_svc[service_name] = (appliance_id, hostname)
        _rebuild_general_conflict_locked(appliance_id)
        # Still return the sighting so MdnsBrowser tracks the five-tuple —
        # the same reason a conflicted appliance sighting is still returned
        # in core/autostream_appliances.py: on_remove/on_change must fire
        # when a conflicting appliance goes offline so conflict state is
        # cleaned up automatically.

    sighting = GeneralSighting(
        appliance_id=appliance_id,
        service_name=service_name,
        hostname=hostname,
        ip=ip,
        port=port,
        version=version,
        repeat=repeat,
        dial_outputs=dial_outputs,
        dial_eq=dial_eq,
    )
    return (appliance_id, sighting)


def _on_general_change(
    appliance_id: str,
    removed: "GeneralSighting | None",
    remaining: "GeneralSighting",
) -> None:
    """Called when one of multiple tracked sightings for an id is removed
    but at least one remains — mirrors
    autostream_appliances._on_appliance_change."""
    if removed is not None:
        with _general_lock:
            _general_svc.pop(removed.service_name, None)
            _rebuild_general_conflict_locked(appliance_id)


def _on_general_remove(appliance_id: str, sighting: "GeneralSighting | None") -> None:
    """Called only when the browser's last five-tuple for appliance_id is
    gone — mirrors autostream_appliances._on_appliance_remove. Cleans up
    every _general_svc entry for this id, including any conflict-orphan
    entries the parser wrote but never registered with the browser."""
    with _general_lock:
        stale = [k for k, v in _general_svc.items() if v[0] == appliance_id]
        for k in stale:
            _general_svc.pop(k, None)
        _general_conflicts.discard(appliance_id)


_general_browser: MdnsBrowser = MdnsBrowser(
    service_type=_GENERAL_SERVICE_TYPE,
    parse_fn=_parse_general_event,
    on_remove=_on_general_remove,
    on_change=_on_general_change,
)


@dataclass(frozen=True)
class RosterEntry:
    # Attribute names match PlayingTarget where dial_target_status reads
    # them (name, ip, port, dial_api, audio_status, dial_status,
    # service_name, appliance_id, auth) so fetch_target_status() and
    # enrich_targets() accept a RosterEntry exactly as they accept a
    # PlayingTarget.
    appliance_id:   str
    service_name:   str
    name:           str
    ip:             str
    port:           int
    playing:        bool
    repeat_capable: bool
    dial_api:       bool = True
    audio_status:   bool = False
    dial_status:    bool = True
    dial_outputs:   bool = False
    dial_eq:        bool = False
    auth:           str = dial_auth.AUTH_UNKNOWN


def _safe_state(appliance_id: str) -> str:
    """dial_auth.auth_map.state(), degrading to unknown on any raise — the
    same discipline as _with_auth() above, factored out so get_roster() can
    share it without gating volume/mute on the same read path."""
    try:
        return dial_auth.auth_map.state(appliance_id)
    except Exception:
        return dial_auth.AUTH_UNKNOWN


def get_roster() -> list[RosterEntry]:
    """Merged view of every rostered appliance, keyed by appliance_id.

    Every playing target with an id is rostered with the playing sighting
    as its canonical (ip, port); every non-conflicted general sighting NOT
    already in the playing set is rostered with the general sighting as
    its canonical address. Identity-less playing targets are never
    rostered.

    Called from the display poll thread only. This function is the ONLY
    caller of note_sighting for general sightings — the playing parser
    keeps its own call (_parse_playing_event) — so exactly one (ip, port)
    per id ever reaches dial_auth's map: a general sighting feeds
    note_sighting only while its id is absent from the playing set, and the
    playing parser feeds it only while present, so the two feeders never
    alternate for one id. get_playing_targets() and get_display_targets()
    are untouched by this function's existence.
    """
    now = time.monotonic()
    playing = {t.appliance_id: t for t in get_display_targets() if t.appliance_id}
    with _general_lock:
        conflicts = frozenset(_general_conflicts)
    general = _general_browser.get_snapshot()

    roster: list[RosterEntry] = []
    for aid, t in playing.items():
        g = general.get(aid)
        roster.append(RosterEntry(
            appliance_id=aid,
            service_name=t.service_name,
            name=t.name,
            ip=t.ip,
            port=t.port,
            playing=True,
            repeat_capable=bool(g and g.repeat),
            dial_api=t.dial_api,
            audio_status=t.audio_status,
            dial_status=t.dial_status,
            dial_outputs=t.dial_outputs,
            dial_eq=t.dial_eq,
        ))
    for aid, g in general.items():
        if aid in playing or aid in conflicts:
            continue
        # Outside _general_lock: dial_auth._lock is a leaf lock and must
        # never be nested with another lock.
        dial_auth.auth_map.note_sighting(aid, g.ip, g.port, now)
        roster.append(RosterEntry(
            appliance_id=aid,
            service_name=g.service_name,
            name=g.service_name,
            ip=g.ip,
            port=g.port,
            playing=False,
            repeat_capable=g.repeat,
            dial_outputs=g.dial_outputs,
            dial_eq=g.dial_eq,
        ))

    roster.sort(key=lambda r: (
        not r.playing, appliance_display_name(r.service_name).lower(), r.appliance_id,
    ))
    return [dataclasses.replace(r, auth=_safe_state(r.appliance_id)) for r in roster]


def start_general_browser(
    shutdown_event: "threading.Event | None" = None,
) -> None:
    """Start the background mDNS browser for _autostream._tcp.  Idempotent.

    Started only when a screen is fitted (see dial_main.py) — an unfitted
    dial has no roster/repeat UI to feed, so there is nothing for this
    browser's avahi-browse child process to be worth running for.
    """
    _general_browser.start(shutdown_event=shutdown_event)


def stop_general_browser() -> None:
    """Stop the background mDNS browser for _autostream._tcp.  Idempotent."""
    _general_browser.stop()
