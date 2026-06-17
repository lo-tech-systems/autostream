"""autostream_output_usage.py — Cross-appliance output occupancy service.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Tracks which output names are in use by other currently-playing autostream
appliances.  Polls GET /api/audio/status on appliances discovered via
_autostream-playing._tcp (audio_status=v1 required).

Public surface
--------------
  OutputUsage            -- frozen dataclass for one occupancy entry
  configure(interval)    -- set poll interval before start()
  start()                -- begin background polling (idempotent)
  refresh_now(reason, timeout) -- bounded synchronous refresh
  get_usage_snapshot()   -- dict[lower_name, OutputUsage]
  usage_for_output(name) -- cache lookup for one output (case-insensitive)
  annotate_outputs(outputs)    -- add remote_in_use fields to output dicts
  is_output_in_use_elsewhere(name)  -- convenience boolean check
"""
from __future__ import annotations

import logging
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable

from autostream_config import (
    OUTPUT_USAGE_POLL_INTERVAL_DEFAULT,
    OUTPUT_USAGE_POLL_INTERVAL_MAX,
    OUTPUT_USAGE_POLL_INTERVAL_MIN,
    normalize_output_usage_poll_interval,
)

logger = logging.getLogger(__name__)

_LOG_PREFIX = "output-usage"

# ---------------------------------------------------------------------------
# Internal playing-target model (mirrors dial/dial_mdns.PlayingTarget minimally)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _PlayingTarget:
    service_name: str
    ip: str
    port: int
    name: str
    audio_status: bool = False


def _parse_playing_target(parts: list, txt: dict) -> tuple | None:
    """Parse an Avahi _autostream-playing._tcp event.

    Intentionally mirrors the parser in dial/dial_mdns.py but is kept
    here so core code does not depend on the dial/ package at runtime.
    Only tracks targets with dial_api=v1 and audio_status=v1.
    """
    if txt.get("dial_api") != "v1":
        return None
    if txt.get("audio_status") != "v1":
        return None
    try:
        port = int(parts[8])
    except (IndexError, ValueError):
        return None
    svc_name = parts[3]
    target = _PlayingTarget(
        service_name=svc_name,
        ip=parts[7],
        port=port,
        name=svc_name,
        audio_status=True,
    )
    return (svc_name, target)


# ---------------------------------------------------------------------------
# Playing-target browser (lazy-imported so tests can substitute it)
# ---------------------------------------------------------------------------

_browser_lock = threading.Lock()
_browser = None


def _get_browser():
    global _browser
    with _browser_lock:
        if _browser is None:
            from autostream_mdns import MdnsBrowser
            _browser = MdnsBrowser(
                service_type="_autostream-playing._tcp",
                parse_fn=_parse_playing_target,
            )
            _browser.start()
        return _browser


# Injectable target provider for testing.  Replace with a callable that returns
# a list of _PlayingTarget (or duck-typed equivalent).
_target_provider: Callable[[], list] | None = None


def _get_playing_targets() -> list:
    if _target_provider is not None:
        return _target_provider()
    return list(_get_browser().get_snapshot().values())


# ---------------------------------------------------------------------------
# OutputUsage dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OutputUsage:
    output_name: str
    owner_name: str
    owner_ip: str
    owner_port: int
    service_name: str
    observed_at: float
    expires_at: float


# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_cache: dict[str, OutputUsage] = {}  # lower(output_name) -> OutputUsage
_poll_interval: int = OUTPUT_USAGE_POLL_INTERVAL_DEFAULT
_started = False
_poll_thread: threading.Thread | None = None

# Injected HTTP fetcher for unit tests.
# Signature: (url: str, timeout: float) -> dict   (raises on error)
_http_fetcher: Callable | None = None

# Injected monotonic clock for unit tests.
_clock: Callable[[], float] | None = None


def _now() -> float:
    if _clock is not None:
        return _clock()
    return time.monotonic()


def _fetch_audio_status(ip: str, port: int, timeout: float) -> dict:
    url = f"http://{ip}:{port}/api/audio/status"
    if _http_fetcher is not None:
        return _http_fetcher(url, timeout)
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise ValueError(f"HTTP {resp.status}")
        import json
        data = json.loads(resp.read().decode())
        if not isinstance(data, dict):
            raise ValueError("not a JSON object")
        return data


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def configure(interval_seconds: int) -> None:
    """Set the poll interval.  Safe to call after start()."""
    global _poll_interval
    normalized = normalize_output_usage_poll_interval(interval_seconds)
    if normalized != interval_seconds:
        logger.warning(
            "%s: poll interval %r out of range [%d, %d]; using %d s",
            _LOG_PREFIX, interval_seconds,
            OUTPUT_USAGE_POLL_INTERVAL_MIN, OUTPUT_USAGE_POLL_INTERVAL_MAX,
            normalized,
        )
    with _lock:
        _poll_interval = normalized


def _get_poll_interval() -> int:
    with _lock:
        return _poll_interval


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _expire_stale(now: float) -> None:
    """Remove entries whose expires_at has passed.  Must be called under _lock."""
    expired = [k for k, v in _cache.items() if v.expires_at <= now]
    for k in expired:
        usage = _cache.pop(k)
        logger.debug("%s: expired %s owned by %s", _LOG_PREFIX, usage.output_name, usage.owner_name)


def _update_cache_for_target(
    target, outputs: list[str], now: float, ttl: float
) -> tuple[list[tuple], list[tuple]]:
    """Update the cache for one target's outputs.  Must be called under _lock."""
    target_lower_outputs = {o.lower() for o in outputs if o.strip()}
    appeared: list[tuple] = []
    cleared: list[tuple] = []

    # Add or refresh entries for reported outputs.
    for out_name in outputs:
        if not out_name.strip():
            continue
        key = out_name.lower()
        existing = _cache.get(key)
        if existing and existing.service_name != target.service_name:
            logger.debug(
                "%s: multiple owners for output %s; %s overrides %s",
                _LOG_PREFIX, out_name, target.service_name, existing.service_name,
            )
        new_entry = OutputUsage(
            output_name=out_name,
            owner_name=target.name,
            owner_ip=target.ip,
            owner_port=target.port,
            service_name=target.service_name,
            observed_at=now,
            expires_at=now + ttl,
        )
        if existing is None or existing.service_name != target.service_name:
            appeared.append((out_name, target.name))
        _cache[key] = new_entry

    # Clear entries for this target that are no longer reported.
    to_remove = [
        k for k, v in _cache.items()
        if v.service_name == target.service_name and k not in target_lower_outputs
    ]
    for k in to_remove:
        usage = _cache.pop(k)
        cleared.append((usage.output_name, usage.owner_name))

    return appeared, cleared


# ---------------------------------------------------------------------------
# Per-target fetch
# ---------------------------------------------------------------------------

def _fetch_target(target, timeout: float, ttl: float) -> tuple[list, list]:
    """Fetch audio/status from one target.  Returns (appeared, cleared) transition lists."""
    try:
        data = _fetch_audio_status(target.ip, target.port, timeout=timeout)
    except Exception as e:
        logger.debug("%s: %s audio/status failed: %s", _LOG_PREFIX, target.name, e)
        return [], []

    playing = data.get("playing")
    outputs_raw = data.get("outputs")

    if playing is not True:
        logger.debug(
            "%s: %s returned playing=%r; not updating usage",
            _LOG_PREFIX, target.name, playing,
        )
        return [], []

    if not isinstance(outputs_raw, list) or len(outputs_raw) == 0:
        logger.debug(
            "%s: %s returned playing=true outputs=%r; treating usage as unknown",
            _LOG_PREFIX, target.name, outputs_raw,
        )
        return [], []

    outputs = [str(o) for o in outputs_raw if isinstance(o, str) and o.strip()]
    if not outputs:
        logger.debug(
            "%s: %s playing=true but no non-empty output strings; treating as unknown",
            _LOG_PREFIX, target.name,
        )
        return [], []

    now = _now()
    with _lock:
        appeared, cleared = _update_cache_for_target(target, outputs, now, ttl)

    return appeared, cleared


# ---------------------------------------------------------------------------
# Poll loop
# ---------------------------------------------------------------------------

def _poll_once(interval: int) -> None:
    ttl = float(max(2 * interval + 1, 5))
    per_timeout = min(1.5, max(0.5, interval / 2))
    targets = _get_playing_targets()
    logger.debug(
        "%s: polling %d playing targets interval=%ds", _LOG_PREFIX, len(targets), interval
    )

    # Expire stale entries first.
    now = _now()
    with _lock:
        _expire_stale(now)

    if not targets:
        return

    cap = min(len(targets), 4)
    all_appeared: list[tuple] = []
    all_cleared: list[tuple] = []

    with ThreadPoolExecutor(max_workers=cap) as pool:
        futures = {
            pool.submit(_fetch_target, t, per_timeout, ttl): t
            for t in targets
        }
        for fut in as_completed(futures):
            try:
                appeared, cleared = fut.result()
                all_appeared.extend(appeared)
                all_cleared.extend(cleared)
            except Exception as e:
                logger.debug("%s: unexpected error from target fetch: %s", _LOG_PREFIX, e)

    for out_name, owner in all_appeared:
        logger.info("%s: %s now in use by %s", _LOG_PREFIX, out_name, owner)
    for out_name, owner in all_cleared:
        logger.info("%s: %s no longer in use by %s", _LOG_PREFIX, out_name, owner)


def _poll_loop() -> None:
    while True:
        interval = _get_poll_interval()
        try:
            _poll_once(interval)
        except Exception:
            logger.warning("%s: unexpected exception in poll loop", _LOG_PREFIX, exc_info=True)
        time.sleep(interval)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start() -> None:
    """Start background polling.  Idempotent."""
    global _started, _poll_thread
    with _lock:
        if _started:
            return
        _started = True
    t = threading.Thread(target=_poll_loop, name="output-usage-poller", daemon=True)
    t.start()
    with _lock:
        _poll_thread = t


def refresh_now(reason: str = "", timeout: float = 1.5) -> None:
    """Perform a bounded immediate poll.  Blocks up to *timeout* seconds."""
    start_t = _now()
    interval = _get_poll_interval()
    ttl = float(max(2 * interval + 1, 5))
    per_timeout = min(timeout, min(1.5, max(0.5, interval / 2)))

    targets = _get_playing_targets()
    if not targets:
        return

    cap = min(len(targets), 4)
    all_appeared: list[tuple] = []
    all_cleared: list[tuple] = []

    pool = ThreadPoolExecutor(max_workers=cap)
    try:
        futures = {
            pool.submit(_fetch_target, t, per_timeout, ttl): t
            for t in targets
        }
        remaining = timeout - (_now() - start_t)
        try:
            for fut in as_completed(futures, timeout=max(0.0, remaining)):
                try:
                    appeared, cleared = fut.result()
                    all_appeared.extend(appeared)
                    all_cleared.extend(cleared)
                except Exception as e:
                    logger.debug("%s: refresh_now fetch error: %s", _LOG_PREFIX, e)
        except TimeoutError:
            logger.debug("%s: refresh_now timed out after %.2fs", _LOG_PREFIX, timeout)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    for out_name, owner in all_appeared:
        logger.info("%s: %s now in use by %s", _LOG_PREFIX, out_name, owner)
    for out_name, owner in all_cleared:
        logger.info("%s: %s no longer in use by %s", _LOG_PREFIX, out_name, owner)


def get_usage_snapshot() -> dict[str, OutputUsage]:
    """Return a copy of the current occupancy cache keyed by lower-cased output name."""
    now = _now()
    with _lock:
        return {k: v for k, v in _cache.items() if v.expires_at > now}


def usage_for_output(output_name: str) -> OutputUsage | None:
    """Cache-only lookup.  Returns None if the output is not occupied elsewhere."""
    key = output_name.strip().lower()
    now = _now()
    with _lock:
        entry = _cache.get(key)
    if entry is None or entry.expires_at <= now:
        return None
    return entry


def is_output_in_use_elsewhere(output_name: str) -> bool:
    return usage_for_output(output_name) is not None


def annotate_outputs(outputs: list[dict]) -> list[dict]:
    """Return a new list of output dicts annotated with remote occupancy fields.

    Never calls refresh_now() or any remote HTTP.  Safe to call from request
    handlers.  Dicts are shallow-copied before mutation.
    """
    snapshot = get_usage_snapshot()
    result = []
    for out in outputs:
        out = dict(out)
        name = str(out.get("name") or "")
        key = name.lower()
        locally_selected = bool(out.get("selected"))
        usage = snapshot.get(key)
        if usage and not locally_selected:
            out["remote_in_use"] = True
            out["remote_owner"] = usage.owner_name
            out["remote_owner_service"] = usage.service_name
        else:
            out["remote_in_use"] = False
            out["remote_owner"] = ""
            out["remote_owner_service"] = ""
        result.append(out)
    return result
