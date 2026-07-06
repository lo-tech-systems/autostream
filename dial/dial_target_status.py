"""dial_target_status.py — Concurrent target status enrichment.

Queries POST /api/dial/status on each discovered playing target that advertises
dial_status=v1, enriching target records with live playing state, master volume,
and (when present) grouped track_id now-playing state.

fetch_target_status() is the single-target status protocol helper shared by
enrich_targets() (concurrent, name-sorted list presentation) and the display
manager (sequential, playing_since-ordered artwork source selection). Display
source policy must not live here — this module only validates and normalizes
one target's response.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import http.client
import json
import logging
import queue
import threading
import time
from typing import TYPE_CHECKING

from dial_control_protocol import (
    TARGET_STATUS_DEADLINE,
    TARGET_STATUS_MAX_BYTES,
    TARGET_STATUS_TIMEOUT,
)

if TYPE_CHECKING:
    from dial_mdns import PlayingTarget

_VALID_TRACK_ID_STATES = frozenset({
    "disabled", "waiting_for_audio", "analysing",
    "identified", "not_found", "error",
})


def _parse_track_id(data: dict) -> tuple[dict | None, bool]:
    """Validate and normalize the optional grouped track_id object.

    Returns (track_id_dict_or_None, ok). track_id absent is valid no-artwork:
    returns (None, True). An invalid track_id object returns (None, False) —
    the caller must treat the whole response as bad_response.
    """
    if "track_id" not in data:
        return None, True
    raw = data["track_id"]
    if not isinstance(raw, dict):
        return None, False

    enabled = raw.get("enabled")
    state = raw.get("state")
    artwork_url = raw.get("artwork_url")
    if not isinstance(enabled, bool):
        return None, False
    if not isinstance(state, str) or state not in _VALID_TRACK_ID_STATES:
        return None, False
    if not isinstance(artwork_url, str):
        return None, False

    result = {
        "enabled": enabled,
        "state": state,
        "artwork_url": artwork_url,
    }

    for field in ("title", "artist", "album"):
        if field not in raw:
            result[field] = ""
            continue
        value = raw[field]
        if not isinstance(value, str):
            return None, False
        result[field] = value

    for field in ("updated_at", "last_attempt_at"):
        if field not in raw:
            result[field] = None
            continue
        value = raw[field]
        if value is None:
            result[field] = None
        elif isinstance(value, bool) or not isinstance(value, (int, float)):
            return None, False
        else:
            result[field] = value

    return result, True


def _base_record(target: "PlayingTarget") -> dict:
    return {
        "name": target.name,
        "ip": target.ip,
        "port": target.port,
        "dial_api": target.dial_api,
        "audio_status": target.audio_status,
        "dial_status": target.dial_status,
        "playing": None,
        "master_volume": None,
        "selected_output_count": None,
        "track_id": None,
        "status_error": None,
    }


def fetch_target_status(
    target: "PlayingTarget",
    dial_id: str,
    timeout_seconds: float = TARGET_STATUS_TIMEOUT,
) -> dict:
    """Fetch and validate POST /api/dial/status for a single target.

    Shared by enrich_targets() (list presentation) and the display manager
    (artwork source selection). Never raises — failures are reported via the
    record's status_error field.
    """
    record = _base_record(target)

    if not target.dial_status:
        record["status_error"] = "unsupported"
        return record

    try:
        conn = http.client.HTTPConnection(target.ip, target.port, timeout=timeout_seconds)
        try:
            body = json.dumps({"dial_id": dial_id}).encode("utf-8")
            conn.request(
                "POST",
                "/api/dial/status",
                body=body,
                headers={"Content-Type": "application/json"},
            )
            resp = conn.getresponse()
            http_status = resp.status

            # Enforce response size limit: read at most MAX+1 bytes
            raw = resp.read(TARGET_STATUS_MAX_BYTES + 1)
        finally:
            conn.close()
    except (TimeoutError, http.client.HTTPException, OSError) as exc:
        error_str = str(exc).lower()
        if "timed out" in error_str or isinstance(exc, TimeoutError):
            record["status_error"] = "timeout"
        else:
            record["status_error"] = "unreachable"
        return record
    except Exception:
        record["status_error"] = "unreachable"
        return record

    # Map HTTP 403 → unauthorized
    if http_status == 403:
        record["status_error"] = "unauthorized"
        return record

    # Validate Content-Type: must be application/json (case-insensitive, ignoring params)
    ct_header = resp.getheader("Content-Type") or ""
    ct_base = ct_header.split(";")[0].strip().lower()
    if ct_base != "application/json":
        record["status_error"] = "bad_response"
        return record

    # Oversized response
    if len(raw) > TARGET_STATUS_MAX_BYTES:
        record["status_error"] = "bad_response"
        return record

    # Parse JSON
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        record["status_error"] = "bad_response"
        return record

    # Must be an object
    if not isinstance(data, dict):
        record["status_error"] = "bad_response"
        return record

    # HTTP non-200 after the 403 check
    if http_status != 200:
        record["status_error"] = "bad_response"
        return record

    # Success or application-level failure: ok must be an exact boolean.
    # Any other value (missing, null, integer, string) is a schema violation.
    ok = data.get("ok")
    if ok is not True:
        if ok is False:
            app_error = data.get("error", "")
            record["status_error"] = (
                app_error if app_error in ("config_error", "backend_unavailable")
                else "bad_response"
            )
        else:
            record["status_error"] = "bad_response"
        return record

    # Validate success response fields
    playing = data.get("playing")
    master_volume = data.get("master_volume")
    selected_output_count = data.get("selected_output_count")

    if not isinstance(playing, bool):
        record["status_error"] = "bad_response"
        return record

    if (
        isinstance(selected_output_count, bool)
        or not isinstance(selected_output_count, int)
        or selected_output_count < 0
    ):
        record["status_error"] = "bad_response"
        return record

    if selected_output_count == 0:
        if master_volume is not None:
            record["status_error"] = "bad_response"
            return record
    else:
        if (
            isinstance(master_volume, bool)
            or not isinstance(master_volume, int)
            or not (0 <= master_volume <= 100)
        ):
            record["status_error"] = "bad_response"
            return record

    track_id, track_id_ok = _parse_track_id(data)
    if not track_id_ok:
        record["status_error"] = "bad_response"
        return record

    record["playing"] = playing
    record["master_volume"] = master_volume
    record["selected_output_count"] = selected_output_count
    record["track_id"] = track_id
    return record


def _fetch_target_status(
    target: "PlayingTarget",
    dial_id: str,
    index: int,
    result_queue: queue.Queue,
) -> None:
    """Fetch /api/dial/status for one target and put the enriched record on the queue."""
    record = fetch_target_status(target, dial_id, timeout_seconds=TARGET_STATUS_TIMEOUT)
    result_queue.put((index, record))


def enrich_targets(
    targets: list["PlayingTarget"],
    dial_id: str,
) -> list[dict]:
    """Enrich a snapshot of playing targets with live status from each appliance.

    Launches one daemon thread per target.  Collects results until all supported
    targets reply or the TARGET_STATUS_DEADLINE is reached.  Timed-out targets
    receive status_error='timeout'.  Unsupported targets receive 'unsupported'.

    Returns a fresh list of dicts sorted by (name.lower(), ip, port).
    """
    if not targets:
        return []

    result_queue: queue.Queue = queue.Queue()
    # Pre-populate records for all targets; threads will overwrite their slot.
    records: list[dict | None] = [None] * len(targets)

    supported_indices: list[int] = []
    threads: list[threading.Thread] = []

    for i, target in enumerate(targets):
        if not target.dial_status:
            # Unsupported — place result immediately without a thread.
            records[i] = _base_record(target)
            records[i]["status_error"] = "unsupported"
        else:
            supported_indices.append(i)
            t = threading.Thread(
                target=_fetch_target_status,
                args=(target, dial_id, i, result_queue),
                daemon=True,
            )
            threads.append(t)
            t.start()

    # Collect results until deadline
    deadline = time.monotonic() + TARGET_STATUS_DEADLINE
    remaining_supported = len(supported_indices)
    collected = 0

    while collected < remaining_supported:
        timeout = deadline - time.monotonic()
        if timeout <= 0:
            break
        try:
            idx, enriched = result_queue.get(timeout=timeout)
            records[idx] = enriched
            collected += 1
        except queue.Empty:
            break

    # Any supported target that didn't report becomes timeout
    for i in supported_indices:
        if records[i] is None:
            records[i] = _base_record(targets[i])
            records[i]["status_error"] = "timeout"

    # Sort by (name lower, ip, port) and return fresh copies
    sorted_records = sorted(
        records,
        key=lambda r: (r["name"].lower(), r["ip"], r["port"]),  # type: ignore[index]
    )
    return sorted_records
