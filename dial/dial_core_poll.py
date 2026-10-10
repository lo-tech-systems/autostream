"""dial_core_poll.py — the poll tick's I/O steps as plain functions.

Each step that talks to an appliance (a status fetch, the concurrent
reconcile fan-out, the artwork download) or feeds a leaf store with what it
learned (the auth map, the repeat store, the mute/volume observations) lives
here as a module-level function. The network calls are injected as keyword
arguments (`fetch`, `enrich`, `now_fn`), defaulting to the real ones looked
up when the step runs, so a test can drive a step with a stub, or patch one
module attribute, without building a display.

No Pillow, no compositor, no layout and no import of the display: whoever
owns the poll tick calls these in order and keeps the lock, paint and sleep
parts for itself.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import hashlib
import logging
import math
import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from dial_auth import (
    AUTH_AUTHORIZED,
    AUTH_UNAUTHORIZED,
    AUTH_UNKNOWN,
    OUTCOME_AUTHORIZED,
    OUTCOME_TRANSIENT,
    OUTCOME_UNAUTHORIZED,
    auth_map,
)
import dial_capabilities
from dial_capabilities import Capabilities, appliance_capabilities  # noqa: F401
from dial_core_state import (
    DERIVED_EQ_IDS, EQ_LIMIT_DB, Artwork, EqBand, OutputRow, Selection, artwork_key, six_band,
    walk_fallback, walk_step,
)
from dial_mdns import appliance_display_name
from dial_repeat_store import parse_repeat_object, repeat_store
from dial_target_status import enrich_targets, fetch_target_status
from dial_volume import forget_mute_states_except, observe_master_volume, observe_mute_state

DIAL_STATUS_TIMEOUT_SECONDS = 2.0
ARTWORK_FETCH_TIMEOUT_SECONDS = 2.0
# The largest artwork response the dial will take.
MAX_ARTWORK_RESPONSE_BYTES = 2 * 1024 * 1024


# ---- capabilities -----------------------------------------------------------
#
# The switch point lives in dial_capabilities; it is re-exported here so the
# poll's own steps and their callers read it from one place.

# ---- applying a status reply to the leaf stores -----------------------------


def apply_status_to_auth(target, result: dict) -> bool:
    """Map a fetch_target_status/enrich_targets record onto the auth
    map. Only the two explicit outcomes move state; everything else
    (including a missing appliance_id) is transient."""
    err = result.get("status_error")
    if err is None:
        outcome = OUTCOME_AUTHORIZED
    elif err == "unauthorized":
        outcome = OUTCOME_UNAUTHORIZED
    else:
        outcome = OUTCOME_TRANSIENT
    body_id = result.get("appliance_id")
    if result.get("untyped_refusal") and not body_id:
        # An earlier-dialect refusal carries no id: correlate with the
        # id this target was resolved to.
        body_id = target.appliance_id
    elif (
        outcome == OUTCOME_AUTHORIZED and not body_id
        and not appliance_capabilities(target).typed_refusals
    ):
        # Nor does an earlier-dialect success reply. Without this, an
        # appliance of that dialect that once refused the dial could
        # never be seen to accept it again.
        body_id = target.appliance_id
    changed = auth_map.apply(
        target.appliance_id, outcome, body_id, time.monotonic(),
    )
    if (
        outcome == OUTCOME_UNAUTHORIZED
        and auth_map.state(target.appliance_id) == AUTH_UNAUTHORIZED
        and auth_map.record_refusal(target.appliance_id)
    ):
        logging.warning(
            "dial display: appliance %s refused this dial; allow it in "
            "that appliance's web UI",
            appliance_display_name(target.service_name or target.name),
        )
    return changed


def apply_status_to_repeat(appliance_id: str, result: dict, now: float) -> None:
    """Feed dial_repeat_store from a fetch_target_status/enrich_targets
    record — mirrors apply_status_to_auth's three-way split: a good
    200 updates the store from the record's repeat object (parsed
    strictly by dial_repeat_store.parse_repeat_object, so a malformed
    object degrades to "unavailable" rather than raising); a confirmed
    412 clears it (this dial's authorization for the appliance was
    revoked, so any cached repeat state is no longer this dial's to
    show); everything else (timeout, unreachable, bad_response, ...) is
    transient and leaves the record untouched — the repeat screen and
    the idle affordance must not blank mid-poll on a single bad
    response. A no-op for an identity-less
    target (dial_repeat_store.update/clear both already guard on this,
    checked again here so the intent reads at the call site)."""
    if not appliance_id:
        return
    err = result.get("status_error")
    if err is None:
        repeat_store.update(appliance_id, parse_repeat_object(result.get("repeat"), now))
    elif err == "unauthorized":
        repeat_store.clear(appliance_id)


def probe_auth(target, dial_id: str, *, fetch: Callable | None = None) -> dict:
    """Fetch one target's status and apply it to the auth map. Shared
    by the push-probe path and the reconcile pass."""
    fetch = fetch or fetch_target_status
    result = fetch(target, dial_id, timeout_seconds=DIAL_STATUS_TIMEOUT_SECONDS)
    apply_status_to_auth(target, result)
    return result


# ---- the tick's fetch steps -------------------------------------------------


def first_checks(
    visible: list, prev_playing_ids, dial_id: str,
    *, fetch: Callable | None = None, now_fn: Callable[[], float] | None = None,
) -> dict[str, tuple[float, dict]]:
    """Check an appliance that has just started playing and has never
    answered this dial (after a restart, say) before anything wakes the
    panel for it or shows it: otherwise one that refuses the dial would be
    shown as playing until a later poll hid it again.

    Walks *visible* in the walk's own order and stops at the first appliance
    that does not refuse (that is the one the walk would have asked first
    anyway), or at the first that needs no check. Returns
    {service_name: (sent_at, reply)} for every appliance asked, so the walk
    can use the reply instead of asking again."""
    fetch = fetch or fetch_target_status
    now_fn = now_fn or time.monotonic
    checks: dict[str, tuple[float, dict]] = {}
    for t in visible:
        if (
            t.auth != AUTH_UNKNOWN or not appliance_capabilities(t).status
            or t.appliance_id in prev_playing_ids
        ):
            break
        sent_at = now_fn()
        result = fetch(t, dial_id, timeout_seconds=DIAL_STATUS_TIMEOUT_SECONDS)
        apply_status_to_auth(t, result)
        apply_status_to_repeat(t.appliance_id, result, now_fn())
        checks[t.service_name] = (sent_at, result)
        if auth_map.state(t.appliance_id) != AUTH_UNAUTHORIZED:
            break
    return checks


@dataclass
class WalkResult:
    records: dict = field(default_factory=dict)         # service_name -> good status record
    errors: dict = field(default_factory=dict)          # service_name -> status_error of a failed fetch
    status_sent_at: dict = field(default_factory=dict)  # service_name -> monotonic send time
    visited: set = field(default_factory=set)           # service names asked (or answered by a first check)
    selection: Selection = field(default_factory=Selection)
    released: bool = False                               # the pin was revoked mid-walk


def walk(
    ordered: list, first_checks: dict, dial_id: str, pin_target,
    *, fetch: Callable | None = None, now_fn: Callable[[], float] | None = None,
    on_revoke: Callable[[], None] | None = None,
) -> WalkResult:
    """The sequential artwork-selection walk: ask each target in *ordered*
    for its status (using a first check's reply where there is one) and
    stop at the first that identifies a track, or at the pinned target
    regardless.

    A pinned target whose status says unauthorized has been revoked
    mid-tick: *on_revoke* is called (the caller clears the focus or releases
    the binding), the pin is dropped, and the walk carries on over the
    remaining targets in this same pass."""
    fetch = fetch or fetch_target_status
    now_fn = now_fn or time.monotonic
    out = WalkResult()
    fallback = None
    selection = Selection()
    for target in ordered:
        is_focus = pin_target is not None and target is pin_target
        if target.auth == AUTH_UNAUTHORIZED:
            logging.debug("dial display: skip unauthorized row %s", target.service_name)
            continue
        if not appliance_capabilities(target).status:
            logging.debug("dial display: skip unsupported target %s", target.service_name)
            if is_focus:
                # No status to poll, but the screen still follows the
                # pinned target for its name/label; there is simply
                # no artwork.
                selection, fallback = walk_step(target, None, True, fallback)
                break
            continue

        checked = first_checks.get(target.service_name)
        if checked is not None:
            out.status_sent_at[target.service_name], result = checked
        else:
            out.status_sent_at[target.service_name] = now_fn()
            result = fetch(target, dial_id, timeout_seconds=DIAL_STATUS_TIMEOUT_SECONDS)
            apply_status_to_auth(target, result)
            apply_status_to_repeat(target.appliance_id, result, now_fn())
        out.visited.add(target.service_name)
        status_error = result.get("status_error")

        if is_focus and status_error == "unauthorized":
            # Revoked mid-tick: release whichever pin this was and fall
            # through to the normal walk over the remaining targets.
            if on_revoke is not None:
                on_revoke()
            out.released = True
            pin_target = None
            is_focus = False
            continue

        if status_error and not is_focus:
            logging.debug(
                "dial display: target %s status_error=%s", target.service_name, status_error,
            )
        record = None if status_error else result
        if record is not None:
            out.records[target.service_name] = record
        else:
            out.errors[target.service_name] = str(status_error)
        # A pinned target is shown regardless of whether it has
        # identified artwork — never fall through to another
        # appliance's artwork while a focus or a binding pins one.
        selection, fallback = walk_step(target, record, is_focus, fallback)
        if selection is not None:
            break
    else:
        selection = walk_fallback(fallback)
    out.selection = selection
    return out


def observe_tick(
    records: dict, reporting_name: str | None, status_sent_at: dict, visible: list,
    master_volume,
    *, observe_mute: Callable | None = None, observe_volume: Callable | None = None,
    forget: Callable | None = None,
) -> None:
    """Record this tick's mute and master-volume observations.

    Mute is recorded for EVERY target the tick actually walked, not only the
    reporting one — a screened dial set to broadcast scope "all" wants an
    up-to-date entry for every appliance it might fan a push out to. Each
    target has its own entry in the observation store (see
    dial_volume.observe_mute_state()), so this can never clobber another
    target's flag. Whether a service's status carries the flag at all
    decides how a missing value is treated (see the store's comment block).
    """
    observe_mute = observe_mute or observe_mute_state
    observe_volume = observe_volume or observe_master_volume
    forget = forget or forget_mute_states_except
    record = records.get(reporting_name) if reporting_name else None
    reports_mute = {t.service_name: appliance_capabilities(t).reports_mute for t in visible}
    for walked_name, walked_record in records.items():
        if walked_name == reporting_name:
            continue  # the explicit call just below covers this one
        observe_mute(
            walked_name, walked_record.get("muted"), requested_at=status_sent_at.get(walked_name, 0.0),
            status_reports_mute=reports_mute.get(walked_name, True),
        )
    observe_mute(
        reporting_name, record.get("muted") if record else None,
        requested_at=status_sent_at.get(reporting_name, 0.0),
        status_reports_mute=reports_mute.get(reporting_name, True),
    )
    forget({t.service_name for t in visible})
    if isinstance(master_volume, int) and not isinstance(master_volume, bool):
        observe_volume(reporting_name, master_volume)
    elif reporting_name is not None:
        observe_volume(reporting_name, None)


def reconcile(
    roster: list, visited: set, dial_id: str,
    *, enrich: Callable | None = None, now_fn: Callable[[], float] | None = None,
) -> None:
    """Concurrent fan-out over rows the sequential poll walk did not
    already fetch this tick, so an unauthorized row's re-probe backoff
    and every row's occasional re-confirmation happen without adding
    sequential latency to the artwork-selection walk.

    Runs over the MERGED roster (dial_mdns.get_roster()), not just the
    playing set: an idle appliance is reconciled here — feeding the
    auth map and the repeat store — but never gets an artwork fetch and
    never sets the now-playing state (that stays exclusively the playing
    walk's job). After every pending row is processed, dial_repeat_store is
    pruned to the roster's current id set so a departed appliance's record
    does not linger forever.
    """
    enrich = enrich or enrich_targets
    now_fn = now_fn or time.monotonic
    now = now_fn()
    auth_map.prune(now)
    pending = [
        r for r in roster
        if appliance_capabilities(r).status and r.appliance_id and r.service_name not in visited
        and auth_map.due_for_probe(r.appliance_id, now)
    ]
    if pending:
        for record in enrich(pending, dial_id):
            target = next(t for t in pending if t.service_name == record["name"])
            apply_status_to_auth(target, record)
            # Stamped at apply time, not with the `now` taken before the
            # fan-out: the fetch blocks for up to its own deadline, and a
            # replay position stamped earlier than it was sampled would
            # interpolate ahead of the truth by that much.
            apply_status_to_repeat(target.appliance_id, record, now_fn())
    repeat_store.prune({r.appliance_id for r in roster})
    dial_capabilities.prune({r.appliance_id for r in roster})


def drain_push_probes(
    ids, targets: dict, roster: dict, dial_id: str, probe: Callable,
) -> set[str]:
    """Probe every appliance id in *ids* that is addressable right now:
    *targets* (the playing set) first, then *roster* (the last-published
    roster), so an authorization granted to an idle appliance is confirmed
    here rather than waiting for the next reconcile pass. An id in neither,
    or one without a status endpoint, is skipped: it is learned on the next
    poll. *probe* is called with the target and fetches and applies its
    status (probe_auth with the caller's fetcher).

    Returns the ids a probe moved to authorised from some other state."""
    promoted: set[str] = set()
    for appliance_id in ids:
        target = targets.get(appliance_id) or roster.get(appliance_id)
        if target is None or not appliance_capabilities(target).status:
            continue     # not rostered right now: learn on the next poll
        before = auth_map.state(appliance_id)
        probe(target)
        after = auth_map.state(appliance_id)
        if after == AUTH_AUTHORIZED and before != AUTH_AUTHORIZED:
            promoted.add(appliance_id)
    return promoted


# ---- artwork ------------------------------------------------------------------


class RateLimitedLogger:
    """Emits the first occurrence and every 10th consecutive repeat of a key.

    A different key resets the count so its own first occurrence is visible
    immediately, per the dial logging policy.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_key: str | None = None
        self._count = 0

    def log(self, level: int, key: str, msg: str, *args) -> None:
        with self._lock:
            if key != self._last_key:
                self._last_key = key
                self._count = 1
            else:
                self._count += 1
            should_log = self._count == 1 or self._count % 10 == 0
        if should_log:
            logging.log(level, msg, *args)


def _artwork_module():
    """The shared artwork fetcher. The dial deployment copies core modules
    alongside the dial package; in the repo they live in core/, which may
    or may not be on sys.path."""
    try:
        import autostream_artwork
    except ImportError:
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "core")))
        import autostream_artwork
    return autostream_artwork


def default_fetch_artwork(url: str, timeout: float) -> tuple[bytes | None, str]:
    """Fetch artwork at the dial's own size ceiling: (bytes_or_None, error_text)."""
    return _artwork_module().fetch_artwork(url, timeout, MAX_ARTWORK_RESPONSE_BYTES)


def default_artwork_eligible(url: str) -> bool:
    """Whether *url* may be fetched at all (the shared fetcher's own rule)."""
    return _artwork_module().artwork_url_eligible(url)


def url_log_key(url: str) -> str:
    """Short, non-reversible identifier for a provider URL, safe at INFO/WARNING."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]


def fetch_artwork_bytes(
    url: str, log_limiter, *, fetch: Callable,
    timeout: float = ARTWORK_FETCH_TIMEOUT_SECONDS,
    on_error: Callable[[str], None] | None = None,
    now_fn: Callable[[], float] | None = None,
) -> Artwork | None:
    """Download the artwork at *url* without decoding it. *fetch* is called
    as fetch(url, timeout) and returns (bytes_or_None, error_text). A failed
    fetch is reported through *on_error* ("artwork_fetch_failed") and
    logged at WARNING through the rate limiter, and returns None; the
    caller shows the logo and tries again on a later tick."""
    data, err = fetch(url, timeout)
    if err:
        if on_error is not None:
            on_error("artwork_fetch_failed")
        url_key = url_log_key(url)
        log_limiter.log(
            logging.WARNING, f"artwork_fetch:{url_key}",
            "dial display: artwork fetch failed (%s): %s", url_key, err,
        )
        return None
    now_fn = now_fn or time.monotonic
    return Artwork(
        url=url,
        key=artwork_key(url),
        data=data,
        content_type="",
        fetched_at=now_fn(),
    )


# ---- outputs and EQ replies ---------------------------------------------------


def parse_outputs_body(status, body) -> "tuple[OutputRow, ...] | None":
    """Validate and convert a POST /api/dial/outputs response body into
    rows. None on anything malformed, non-200 or unreachable: transient, so
    the caller keeps the last good rows. An output another appliance has
    taken is kept and marked (`remote_in_use`, with `remote_owner` when the
    reply names it) so a surface can show it dimmed; one that is not
    well-formed is skipped, as it never made the result unusable. The optional
    `is_default` flag reads as false when absent. `needs_auth_key` reads
    the same way (false unless it is the bool true); the list's other pairing
    fields are not read here."""
    if status != 200 or not isinstance(body, dict) or body.get("ok") is not True:
        return None
    raw = body.get("outputs")
    if not isinstance(raw, list):
        return None
    rows = []
    for o in raw:
        if not isinstance(o, dict):
            return None
        in_use = bool(o.get("remote_in_use"))
        out_id, name, selected, volume = o.get("id"), o.get("name"), o.get("selected"), o.get("volume")
        valid = (
            isinstance(out_id, str) and bool(out_id) and isinstance(name, str)
            and isinstance(selected, bool)
            and isinstance(volume, int) and not isinstance(volume, bool)
        )
        if not valid:
            if in_use:
                continue
            return None
        owner = o.get("remote_owner")
        rows.append(OutputRow(
            id=out_id, name=name, selected=selected, volume=max(0, min(100, volume)),
            remote_in_use=in_use,
            remote_owner=owner if in_use and isinstance(owner, str) and owner else None,
            is_default=bool(o.get("is_default")),
            needs_auth_key=o.get("needs_auth_key") is True,
        ))
    return tuple(rows)


_REPLY_ID_RE = re.compile(r"^[a-z_]{1,32}\Z")
RETRY_AFTER_MAX_S = 3600


def reply_error_id(status, body) -> "str | None":
    """None for an accepted set reply (200 with ok true); otherwise the id a
    view keys its reaction on: pin_invalid, pin_required, a short typed
    error, unreachable (no reply), else backend_error. A reply whose error
    is not a short lower-case id (a backend's free text, anything of another
    type) is backend_error, so nothing a responder sends reaches a screen."""
    if status is None:
        return "unreachable"
    if isinstance(body, dict):
        if status == 200 and body.get("ok") is True:
            return None
        if body.get("pin_invalid") is True:
            return "pin_invalid"
        if body.get("pin_required") is True:
            return "pin_required"
        error = body.get("error")
        if isinstance(error, str) and _REPLY_ID_RE.match(error):
            return error
    return "backend_error"


def reply_retry_after(body) -> int:
    """The whole seconds a reply asks the sender to wait: a non-negative int
    capped at RETRY_AFTER_MAX_S; 0 for anything else (bools and floats
    included)."""
    if not isinstance(body, dict):
        return 0
    value = body.get("retry_after_s")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return min(value, RETRY_AFTER_MAX_S)


_EQ_BAND_ID_RE = re.compile(r"[a-z0-9_]{1,16}")
_EQ_BANDS_MAX = 16


def _whole_db(value) -> "int | None":
    """*value* as whole dB (halves round up), or None when it is not a finite
    number."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return math.floor(value + 0.5)


def _parse_eq_bands(entries) -> "tuple[EqBand, ...] | None":
    """The appliance's own bands from the `bands` list of an EQ reply, in
    order, or None when the list is malformed: at most _EQ_BANDS_MAX
    objects, each with an id (lowercase letters, digits and underscores,
    never one of the derived controls' ids), a positive integer centre
    frequency, a finite gain and a finite range with its low end not above
    its high end. A gain is rounded to whole dB and held within the range;
    a repeated id is dropped."""
    if not isinstance(entries, list) or len(entries) > _EQ_BANDS_MAX:
        return None
    out: list[EqBand] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            return None
        band_id = entry.get("id")
        frequency = entry.get("frequency_hz")
        if (
            not isinstance(band_id, str) or _EQ_BAND_ID_RE.fullmatch(band_id) is None
            or band_id in DERIVED_EQ_IDS
        ):
            return None
        if isinstance(frequency, bool) or not isinstance(frequency, int) or frequency <= 0:
            return None
        gain, low, high = (_whole_db(entry.get(k)) for k in ("gain_db", "min_db", "max_db"))
        if gain is None or low is None or high is None or low > high:
            return None
        if band_id in seen:
            continue
        seen.add(band_id)
        out.append(EqBand(band_id, frequency, max(low, min(high, gain)), low, high))
    return tuple(out)


def parse_eq_body(status, body, capability_version: int = 1) -> "tuple[EqBand, ...] | None":
    """Validate a POST /api/dial/eq response body and map it to bands. The
    bass/treble capability (version 1) gives the two derived controls,
    `"bass"` and `"treble"`, each in the +-EQ_LIMIT_DB range with no centre
    frequency. The six-band capability (version 2 or later) gives the
    appliance's own bands, in the order it lists them, followed by the same
    two derived controls, so a surface that knows only bass and treble is
    unaffected. None on anything malformed or failed."""
    if status != 200 or not isinstance(body, dict) or not body.get("ok"):
        return None
    bass, treble = body.get("bass_db"), body.get("treble_db")
    if isinstance(bass, bool) or not isinstance(bass, int):
        return None
    if isinstance(treble, bool) or not isinstance(treble, int):
        return None
    derived = (
        EqBand("bass", None, bass, -EQ_LIMIT_DB, EQ_LIMIT_DB),
        EqBand("treble", None, treble, -EQ_LIMIT_DB, EQ_LIMIT_DB),
    )
    if not six_band(capability_version):
        return derived
    bands = _parse_eq_bands(body.get("bands"))
    return None if bands is None else bands + derived
