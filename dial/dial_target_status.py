"""dial_target_status.py — Concurrent target status enrichment.

Queries POST /api/dial/status on each discovered playing target that advertises
dial_status=v1, enriching target records with live playing state and master volume.

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


def _fetch_target_status(
    target: "PlayingTarget",
    dial_id: str,
    index: int,
    result_queue: queue.Queue,
) -> None:
    """Fetch /api/dial/status for one target and put the enriched record on the queue."""
    record: dict = {
        "name": target.name,
        "ip": target.ip,
        "port": target.port,
        "dial_api": target.dial_api,
        "audio_status": target.audio_status,
        "dial_status": target.dial_status,
        "playing": None,
        "master_volume": None,
        "selected_output_count": None,
        "status_error": None,
    }

    if not target.dial_status:
        record["status_error"] = "unsupported"
        result_queue.put((index, record))
        return

    try:
        conn = http.client.HTTPConnection(
            target.ip, target.port, timeout=TARGET_STATUS_TIMEOUT
        )
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
        result_queue.put((index, record))
        return
    except Exception:
        record["status_error"] = "unreachable"
        result_queue.put((index, record))
        return

    # Map HTTP 403 → unauthorized
    if http_status == 403:
        record["status_error"] = "unauthorized"
        result_queue.put((index, record))
        return

    # Validate Content-Type: must be application/json (case-insensitive, ignoring params)
    ct_header = resp.getheader("Content-Type") or ""
    ct_base = ct_header.split(";")[0].strip().lower()
    if ct_base != "application/json":
        record["status_error"] = "bad_response"
        result_queue.put((index, record))
        return

    # Oversized response
    if len(raw) > TARGET_STATUS_MAX_BYTES:
        record["status_error"] = "bad_response"
        result_queue.put((index, record))
        return

    # Parse JSON
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        record["status_error"] = "bad_response"
        result_queue.put((index, record))
        return

    # Must be an object
    if not isinstance(data, dict):
        record["status_error"] = "bad_response"
        result_queue.put((index, record))
        return

    # HTTP non-200 after the 403 check
    if http_status != 200:
        record["status_error"] = "bad_response"
        result_queue.put((index, record))
        return

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
        result_queue.put((index, record))
        return

    # Validate success response fields
    playing = data.get("playing")
    master_volume = data.get("master_volume")
    selected_output_count = data.get("selected_output_count")

    if not isinstance(playing, bool):
        record["status_error"] = "bad_response"
        result_queue.put((index, record))
        return

    if (
        isinstance(selected_output_count, bool)
        or not isinstance(selected_output_count, int)
        or selected_output_count < 0
    ):
        record["status_error"] = "bad_response"
        result_queue.put((index, record))
        return

    if selected_output_count == 0:
        if master_volume is not None:
            record["status_error"] = "bad_response"
            result_queue.put((index, record))
            return
    else:
        if (
            isinstance(master_volume, bool)
            or not isinstance(master_volume, int)
            or not (0 <= master_volume <= 100)
        ):
            record["status_error"] = "bad_response"
            result_queue.put((index, record))
            return

    record["playing"] = playing
    record["master_volume"] = master_volume
    record["selected_output_count"] = selected_output_count
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
            records[i] = {
                "name": target.name,
                "ip": target.ip,
                "port": target.port,
                "dial_api": target.dial_api,
                "audio_status": target.audio_status,
                "dial_status": target.dial_status,
                "playing": None,
                "master_volume": None,
                "selected_output_count": None,
                "status_error": "unsupported",
            }
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
            target = targets[i]
            records[i] = {
                "name": target.name,
                "ip": target.ip,
                "port": target.port,
                "dial_api": target.dial_api,
                "audio_status": target.audio_status,
                "dial_status": target.dial_status,
                "playing": None,
                "master_volume": None,
                "selected_output_count": None,
                "status_error": "timeout",
            }

    # Sort by (name lower, ip, port) and return fresh copies
    sorted_records = sorted(
        records,
        key=lambda r: (r["name"].lower(), r["ip"], r["port"]),  # type: ignore[index]
    )
    return sorted_records
