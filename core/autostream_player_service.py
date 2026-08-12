#!/usr/bin/env python3
"""High-level player service built on top of autostream_players."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import os
import stat
import threading
import time
from typing import Optional, Any

from autostream_players import (
    ActionResult,
    BACKEND_OWNTONE,
    BackendCapabilities,
    BackendStatus,
    GetOutputResult,
    ListOutputsResult,
    OUTPUT_MODE_AIRPLAY1,
    OUTPUT_MODE_AIRPLAY2,
    OUTPUT_MODE_AIRPLAY2_BUFFERED,
    OUTPUT_MODE_AIRPLAY2_SURROUND_STEREO,
    OUTPUT_MODE_AIRPLAY2_SURROUND_UPMIX,
    OUTPUT_MODE_AUTO,
    OutputInfo,
    PlaybackMetadata,
    SaveSettingResult,
    SETTING_LOG_LEVEL,
    SETTING_PIPE_BITS_PER_SAMPLE,
    SETTING_PIPE_PATH,
    SETTING_PIPE_SAMPLE_RATE,
    SETTING_RESAMPLE_QUALITY,
    SettingDescriptor,
    SettingValueResult,
    create_backend,
    detect_backend,
)
from autostream_sysutils import run_admin_cmd


_CACHE_LOCK = threading.Lock()
_DETECTION_CACHE_SECONDS = 120.0
# (cached_at_monotonic, backend_id, version, last_seen_at, detection_confident)
_DETECTION_CACHE: dict[str, tuple[float, str, str, float, bool]] = {}
LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class ResolvedBackend:
    backend_id: str
    backend: Any
    # True when this backend_id came from a POSITIVE detection match (a
    # probe in detect_backend() actually confirmed it); False when
    # detect_backend() matched nothing and resolve_backend() fell back to
    # the generic BACKEND_OWNTONE adapter as a guess (see resolve_backend()
    # "No playback backend probe matched" branch). Callers that enforce
    # backend-declared policy (e.g. reconcile_monitor_format(),
    # reconcile_pipe_format_with_backend()) MUST gate enforcement on this
    # flag being True -- a fallback guess is not evidence about what the
    # real backend (if any, e.g. a crashed owntone-mini) actually needs.
    # Defaults True so the many existing call sites/tests that construct a
    # ResolvedBackend directly for a known-good backend need no changes.
    detection_confident: bool = True


@dataclass(frozen=True)
class OwnToneRuntimeInfo:
    """Latest cached runtime metadata for the active OwnTone-compatible backend."""

    base_url: str
    backend_id: str
    version: str
    connected: bool
    last_seen_at: float


@dataclass(frozen=True)
class FifoEnsureResult:
    ok: bool
    created_dir: bool = False
    created_fifo: bool = False
    error: str = ""
    error_code: str = ""

    @property
    def message(self) -> str:
        return self.error or self.error_code


@dataclass(frozen=True)
class FifoReconcileResult:
    ok: bool
    error: str = ""
    error_code: str = ""
    detail: str = ""

    @property
    def message(self) -> str:
        return self.error or self.detail or self.error_code


@dataclass(frozen=True)
class FormatReconcileResult:
    """Result of reconcile_pipe_format_with_backend().

    ``ok`` follows reconcile_fifo_with_backend()'s convention: it reports
    whether the reconcile *attempt itself* completed (no exception, no fatal
    local error), not whether the backend actually ended up matching the
    monitor's format. A rejected/unsaveable value or an unreachable monitor
    are both non-fatal outcomes surfaced via error/error_code, same as the
    FIFO-path reconcile above.
    """

    ok: bool
    changed: bool = False
    restart_requested: bool = False
    error: str = ""
    error_code: str = ""
    detail: str = ""

    @property
    def message(self) -> str:
        return self.error or self.detail or self.error_code


_owntone_runtime_info_lock = threading.Lock()
_owntone_runtime_info = OwnToneRuntimeInfo(
    base_url="",
    backend_id="unknown",
    version="unknown",
    connected=False,
    last_seen_at=0.0,
)


def _set_owntone_runtime_info(
    *,
    base_url: Optional[str] = None,
    backend_id: Optional[str] = None,
    version: Optional[str] = None,
    connected: Optional[bool] = None,
    last_seen_at: Optional[float] = None,
) -> None:
    """Update the cached OwnTone runtime metadata snapshot."""
    global _owntone_runtime_info
    with _owntone_runtime_info_lock:
        cur = _owntone_runtime_info
        _owntone_runtime_info = OwnToneRuntimeInfo(
            base_url=(
                _normalize_base_url(base_url)
                if base_url is not None and str(base_url).strip()
                else ("" if base_url is not None else cur.base_url)
            ),
            backend_id=(
                str(backend_id).strip()
                if backend_id is not None
                else cur.backend_id
            ) or "unknown",
            version=(
                str(version).strip()
                if version is not None
                else cur.version
            ) or "unknown",
            connected=bool(cur.connected if connected is None else connected),
            last_seen_at=(
                cur.last_seen_at
                if last_seen_at is None
                else float(last_seen_at)
            ),
        )


def _get_owntone_runtime_info_cached() -> OwnToneRuntimeInfo:
    with _owntone_runtime_info_lock:
        return _owntone_runtime_info


def _detection_cache_age(base_url: str) -> Optional[float]:
    normalized_base_url = _normalize_base_url(base_url)
    with _CACHE_LOCK:
        cached = _DETECTION_CACHE.get(normalized_base_url)
        if not cached:
            return None
        return time.monotonic() - cached[0]


def get_owntone_runtime_info(
    base_url: str = "",
    *,
    timeout: float = 3.0,
    refresh_if_stale: bool = True,
) -> OwnToneRuntimeInfo:
    """Return cached OwnTone runtime metadata, refreshing if the cache is stale.

    When ``refresh_if_stale=False`` the process-wide snapshot is returned
    immediately without any I/O or base_url requirement.  This is the path
    used by the System Info API which must not initiate OwnTone HTTP traffic.

    When ``base_url`` is provided and the backend-detection cache is stale (or
    absent), this triggers a lightweight re-probe via resolve_backend() so the
    version can follow a restarted/upgraded OwnTone service without requiring
    a Python process restart.
    """
    if not refresh_if_stale:
        return _get_owntone_runtime_info_cached()
    normalized_base_url = _normalize_base_url(base_url) if str(base_url or "").strip() else ""
    if not normalized_base_url:
        return _get_owntone_runtime_info_cached()
    cached_info = _get_owntone_runtime_info_cached()
    age = _detection_cache_age(base_url)
    if (
        age is None
        or age > _DETECTION_CACHE_SECONDS
        or cached_info.base_url != normalized_base_url
    ):
        try:
            resolve_backend(base_url, timeout=timeout)
        except Exception:
            # resolve_backend() is defensive already; this is a final guard
            # so version display never breaks page rendering.
            LOG.debug("OwnTone runtime refresh failed for %s", base_url, exc_info=True)
    return _get_owntone_runtime_info_cached()


def _normalize_base_url(base_url: str) -> str:
    return (str(base_url or "").strip() or "http://localhost:3689").rstrip("/")


def ensure_audio_fifo(path: str) -> FifoEnsureResult:
    """Ensure the configured backend audio FIFO exists and is a named pipe."""
    try:
        if not path or not os.path.isabs(path):
            return FifoEnsureResult(
                ok=False,
                error=f"Configured fifo_path must be an absolute path: {path!r}",
                error_code="invalid_path",
            )

        created_dir = False
        fifo_dir = os.path.dirname(path)
        if fifo_dir:
            created_dir = not os.path.isdir(fifo_dir)
            os.makedirs(fifo_dir, mode=0o777, exist_ok=True)

        if os.path.exists(path):
            st = os.stat(path)
            if not stat.S_ISFIFO(st.st_mode):
                return FifoEnsureResult(
                    ok=False,
                    created_dir=created_dir,
                    error=f"Configured fifo_path exists but is not a FIFO: {path!r}",
                    error_code="not_fifo",
                )
            return FifoEnsureResult(ok=True, created_dir=created_dir)

        os.mkfifo(path, 0o666)
        return FifoEnsureResult(ok=True, created_dir=created_dir, created_fifo=True)
    except Exception as exc:
        return FifoEnsureResult(
            ok=False,
            error=f"Could not create audio FIFO {path!r}: {exc}",
            error_code="create_failed",
        )


def _request_library_update_with_retry(
    backend: Any,
    base_url: str,
    *,
    timeout_s: float = 30.0,
    interval_s: float = 5.0,
) -> ActionResult:
    """Request a backend update, retrying briefly during cold start."""
    deadline = time.monotonic() + max(0.0, float(timeout_s))
    attempt = 0

    while True:
        attempt += 1
        result = backend.request_library_update()
        if result.ok:
            LOG.info(
                "Playback backend update accepted for %s after %d attempt(s).",
                base_url,
                attempt,
            )
            return result

        if result.error_code == "unsupported":
            LOG.info(
                "Playback backend %s does not support update requests for %s.",
                getattr(backend, "backend_id", "unknown"),
                base_url,
            )
            return result

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return result

        LOG.info(
            "Playback backend update for %s not ready yet; retrying in %.1f s (%s).",
            base_url,
            interval_s,
            result.error or result.detail or result.error_code or "request failed",
        )
        time.sleep(min(float(interval_s), max(0.0, remaining)))


def reconcile_fifo_with_backend(
    base_url: str,
    fifo_path: str,
    *,
    timeout: float = 3.0,
    update_timeout_s: float = 30.0,
    update_interval_s: float = 5.0,
) -> FifoReconcileResult:
    """Ensure the local FIFO exists and align backend pipe-path state if possible."""
    fifo_result = ensure_audio_fifo(fifo_path)
    if not fifo_result.ok:
        return FifoReconcileResult(
            ok=False,
            error=fifo_result.error,
            error_code=fifo_result.error_code,
        )

    if fifo_result.created_dir:
        LOG.info("Created audio FIFO directory at %s", os.path.dirname(fifo_path))
    if fifo_result.created_fifo:
        LOG.info("Created audio FIFO at %s", fifo_path)

    base_url_text = str(base_url or "").strip()
    if not base_url_text:
        return FifoReconcileResult(ok=True)

    resolved = resolve_backend(base_url_text, timeout=timeout)
    backend = resolved.backend
    setting_changed = False
    warning_error = ""
    warning_error_code = ""
    warning_detail = ""

    setting_result = backend.get_setting(SETTING_PIPE_PATH)
    if setting_result.unsupported or setting_result.error_code == "unsupported":
        LOG.debug(
            "Playback backend %s does not expose pipe-path inspection at %s; continuing.",
            resolved.backend_id,
            base_url_text,
        )
    elif setting_result.ok:
        backend_fifo_path = str(setting_result.value or "").strip()
        wanted_fifo_path = str(fifo_path or "").strip()
        if backend_fifo_path == wanted_fifo_path:
            LOG.debug(
                "Playback backend %s pipe path already matches configured FIFO at %s.",
                resolved.backend_id,
                base_url_text,
            )
        else:
            save_result = backend.save_setting(SETTING_PIPE_PATH, wanted_fifo_path)
            if not save_result.ok:
                LOG.warning(
                    "Could not update playback backend %s pipe path at %s: %s",
                    resolved.backend_id,
                    base_url_text,
                    save_result.message or "save failed",
                )
                warning_error = save_result.error or "Failed to save backend FIFO path"
                warning_error_code = save_result.error_code or "save_failed"
            else:
                setting_changed = True
                LOG.info(
                    "Updated playback backend %s pipe path from %r to %r at %s.",
                    resolved.backend_id,
                    backend_fifo_path,
                    wanted_fifo_path,
                    base_url_text,
                )
                if save_result.restart_required:
                    LOG.warning(
                        "Playback backend %s still reported restart_required after pipe-path update at %s.",
                        resolved.backend_id,
                        base_url_text,
                    )
    else:
        LOG.warning(
            "Could not read playback backend %s pipe path at %s: %s",
            resolved.backend_id,
            base_url_text,
            setting_result.message or "read failed",
        )
        warning_error = setting_result.error or "Failed to read backend FIFO path"
        warning_error_code = setting_result.error_code or "read_failed"

    should_refresh = bool(fifo_result.created_fifo or setting_changed)
    if not should_refresh:
        return FifoReconcileResult(
            ok=True,
            error=warning_error,
            error_code=warning_error_code,
            detail=warning_detail,
        )

    update_result = _request_library_update_with_retry(
        backend,
        base_url_text,
        timeout_s=update_timeout_s,
        interval_s=update_interval_s,
    )
    if not update_result.ok and update_result.error_code != "unsupported":
        LOG.warning(
            "Could not request playback backend update for %s: %s",
            base_url_text,
            update_result.message or "update failed",
        )
        return FifoReconcileResult(
            ok=True,
            error=update_result.error or warning_error or "Failed to request backend update",
            error_code=update_result.error_code or warning_error_code or "update_failed",
            detail=update_result.detail or warning_detail,
        )

    return FifoReconcileResult(
        ok=True,
        error=warning_error,
        error_code=warning_error_code,
        detail=update_result.detail or warning_detail,
    )


# ---------------------------------------------------------------------------
# Pipe-format reconcile
# ---------------------------------------------------------------------------
#
# reconcile_fifo_with_backend() above reconciles the FIFO *path*; this
# reconciles the FIFO *format* (sample rate / bit depth) the same way: read
# the source of truth (there, the local filesystem; here, the monitor's
# reported output format), compare with what owntone-mini currently has
# persisted, and push+restart on mismatch.
#
# One structural difference from the path reconcile: this module has no
# monitor socket access of its own (autostream_core.py, which owns
# MonitorClient, already imports this module, so importing back would be
# circular). The caller is therefore responsible for passing in the
# monitor's status snapshot (whatever MonitorClient.get_status() returned on
# the current poll) rather than this function fetching it itself -- mirrors
# how reconcile_fifo_with_backend() is handed fifo_path instead of computing
# it.
_format_reconcile_state_lock = threading.Lock()
_format_reconcile_state: dict[str, dict[str, Any]] = {}


def _format_reconcile_state_for(base_url: str) -> dict[str, Any]:
    with _format_reconcile_state_lock:
        state = _format_reconcile_state.get(base_url)
        if state is None:
            state = {
                "logged_no_monitor_info": False,
                "last_logged_reject": None,
                # Set whenever a pass ends without the backend fully matching
                # wanted (partial or full save failure); cleared on a fully
                # matching/synced pass. Read by retry_pending_format_reconcile()
                # below so the periodic (per-poll, while-capturing) path can
                # cheaply no-op in the steady state and only spend an HTTP
                # round trip when there is actually something left to retry.
                "needs_retry": False,
            }
            _format_reconcile_state[base_url] = state
        return state


def _extract_monitor_output_format(
    monitor_status: Optional[dict],
) -> tuple[Optional[int], Optional[int]]:
    """Pull (output_rate, output_bits) out of a MonitorClient.get_status() dict.

    Returns (None, None) for anything that isn't a well-formed pair of
    positive integers -- including monitor_status being None/empty (monitor
    unreachable) or an older monitor build that doesn't report these fields
    yet. Both are meant to
    be indistinguishable "no format info available" cases to the caller.
    """
    if not isinstance(monitor_status, dict):
        return None, None
    rate = monitor_status.get("output_rate")
    bits = monitor_status.get("output_bits")
    try:
        rate_int = int(rate)
        bits_int = int(bits)
    except (TypeError, ValueError):
        return None, None
    if isinstance(rate, bool) or isinstance(bits, bool):
        return None, None
    if rate_int <= 0 or bits_int <= 0:
        return None, None
    return rate_int, bits_int


def _restart_owntone_backend_async(base_url: str) -> None:
    """Fire-and-forget owntone-mini process restart request.

    Pipe-format settings are restart-required: owntone-mini reads
    pipe_sample_rate/pipe_bits_per_sample once at pipe_setup() init, so a
    settings-API write alone (which is all reconcile_fifo_with_backend's own
    restart-coupled follow-up, _request_library_update_with_retry, does) is
    not enough to make a format change take effect. Mirrors the coordinator's
    OwnTone-hang-watchdog restart trigger (autostream_core.py
    _fire_owntone_hang_restart) and the Web UI's owntone-setup restart button
    (autostream_webui_page_owntone.py _restart_owntone_worker): both
    ultimately run "sudo -n autostream_admin restart-owntone" via
    run_admin_cmd(); this does the same directly, without depending on
    WebUIState (out of scope for this module).
    """
    def _worker() -> None:
        try:
            p = run_admin_cmd(["restart-owntone"], timeout=20.0)
            if p.returncode != 0:
                LOG.error(
                    "Pipe-format reconcile: restart-owntone failed (rc=%s) for %s: %s",
                    p.returncode, base_url, (p.stderr or "").strip(),
                )
            else:
                LOG.warning(
                    "Pipe-format reconcile: restart-owntone requested for %s.",
                    base_url,
                )
        except Exception:
            LOG.exception(
                "Pipe-format reconcile: restart-owntone raised for %s", base_url
            )

    threading.Thread(
        target=_worker, name="owntone-format-reconcile-restart", daemon=True
    ).start()


def reconcile_pipe_format_with_backend(
    base_url: str,
    monitor_status: Optional[dict],
    *,
    timeout: float = 3.0,
) -> FormatReconcileResult:
    """Align owntone-mini's pipe format settings with the monitor's actual output.

    *monitor_status* is whatever MonitorClient.get_status() most recently
    returned (or None if the monitor is unreachable); the caller supplies it
    since this module cannot query the monitor socket directly (see the
    module comment above).

    Guarantees:
      - Idempotent: once the backend already matches, no get/save is
        attempted beyond the read used to check (safe to call every poll).
        A key that already matches is never re-saved even mid-recovery from
        a previous partial failure (see below) -- each of the two keys is
        only pushed when it individually still differs from wanted.
      - Safe when the monitor is down or too old to report a format: a
        single no-op with one throttled log line, not a warning per call.
      - Safe when owntone-mini rejects a value:
        never turns into a restart-request loop, because a restart is only
        ever requested after BOTH keys have been confirmed saved (see
        "changed"/reject_error handling below) -- a save failure of either
        key unconditionally skips the restart for that pass.
      - No indefinite torn-pair state: on a *partial* failure (one of the
        two save_setting calls succeeds, the other fails -- e.g. a
        transport blip or backend restart mid-reconcile), the previous
        implementation cached the whole (rate, bits) pair as "rejected" and
        then short-circuited every later attempt to retry it, including the
        one key that had actually already failed to save -- so a torn
        persisted pair (new rate + stale bits, a combination the monitor
        never itself writes) could sit armed indefinitely until the
        monitor's wanted format happened to change. Fixed: this function no
        longer memoizes anything that would suppress a retry attempt.
        SaveSettingResult's error_code cannot reliably distinguish a
        deterministic value-level rejection (owntone-mini's config_set_int
        validation failure surfaces as the same HTTP 500 / "http_error" as
        an unrelated transient backend error) from a transport blip
        ("request_failed"/"no_response" are unambiguous transport failures,
        but "http_error" is not distinguishable from a real reject) -- see
        the module-level investigation note above reconcile_pipe_format_
        with_backend's call sites in autostream_core.py for the trace. Per
        When the signal is ambiguous the safe default is to keep
        retrying, not to keep suppressing: each
        reconcile pass re-diffs backend vs. wanted per key (already-matching
        keys are skipped, not re-saved -- see "Idempotent" above) and
        attempts to save only the key(s) still out of sync, so a torn pair
        self-heals on the very next pass once the transient condition
        clears. What IS still memoized is purely for log-noise control (a
        WARNING is logged once per distinct (wanted_format, error_code)
        state, not once per poll) -- never for suppressing the underlying
        retry.
    """
    base_url_text = str(base_url or "").strip()
    if not base_url_text:
        return FormatReconcileResult(ok=True)

    state = _format_reconcile_state_for(base_url_text)

    wanted_rate, wanted_bits = _extract_monitor_output_format(monitor_status)
    if wanted_rate is None or wanted_bits is None:
        with _format_reconcile_state_lock:
            already_logged = state["logged_no_monitor_info"]
            state["logged_no_monitor_info"] = True
        if not already_logged:
            LOG.info(
                "Monitor did not report an output format (output_rate/output_bits) "
                "in its status; skipping pipe-format reconcile for %s until it does.",
                base_url_text,
            )
        return FormatReconcileResult(ok=True)

    with _format_reconcile_state_lock:
        state["logged_no_monitor_info"] = False

    resolved = resolve_backend(base_url_text, timeout=timeout)
    backend = resolved.backend

    if not resolved.detection_confident:
        # Same detection-confidence gate as reconcile_monitor_format() above
        # (see ResolvedBackend.detection_confident) -- pushing pipe settings
        # to a fallback-guessed backend is less catastrophic than the
        # monitor-format case (a wrong guess is validation-rejected or a
        # no-op rather than actively destructive), but the underlying
        # backend identity is just as unconfirmed, so apply the same no-op
        # deferral rather than acting on a guess.
        with _format_reconcile_state_lock:
            already_logged = state.get("last_logged_reject") == "unconfirmed"
            state["last_logged_reject"] = "unconfirmed"
        if not already_logged:
            LOG.warning(
                "Pipe-format reconcile: backend identity unconfirmed for %s "
                "(detection fell back to a default); format enforcement "
                "deferred.",
                base_url_text,
            )
        return FormatReconcileResult(ok=True)

    rate_result = backend.get_setting(SETTING_PIPE_SAMPLE_RATE)
    bits_result = backend.get_setting(SETTING_PIPE_BITS_PER_SAMPLE)

    if rate_result.unsupported or bits_result.unsupported:
        LOG.debug(
            "Playback backend %s does not expose pipe-format settings at %s; "
            "skipping format reconcile.",
            resolved.backend_id,
            base_url_text,
        )
        # Retrying is futile while the backend doesn't expose these keys at
        # all -- nothing for a periodic retry
        # to accomplish, so don't leave it spinning on this base_url.
        with _format_reconcile_state_lock:
            state["needs_retry"] = False
        return FormatReconcileResult(ok=True)

    if not rate_result.ok or not bits_result.ok:
        failed = rate_result if not rate_result.ok else bits_result
        LOG.warning(
            "Could not read playback backend %s pipe format at %s: %s",
            resolved.backend_id,
            base_url_text,
            failed.message or "read failed",
        )
        # Couldn't even confirm the current state -- worth another look once
        # the backend is reachable again (retry_pending_format_reconcile()).
        with _format_reconcile_state_lock:
            state["needs_retry"] = True
        return FormatReconcileResult(
            ok=True,
            error=failed.error or "Failed to read backend pipe format",
            error_code=failed.error_code or "read_failed",
        )

    try:
        backend_rate = int(rate_result.value)
    except (TypeError, ValueError):
        backend_rate = None
    try:
        backend_bits = int(bits_result.value)
    except (TypeError, ValueError):
        backend_bits = None

    if backend_rate == wanted_rate and backend_bits == wanted_bits:
        LOG.debug(
            "Playback backend %s pipe format already matches monitor output "
            "(%d Hz / %d-bit) at %s.",
            resolved.backend_id, wanted_rate, wanted_bits, base_url_text,
        )
        with _format_reconcile_state_lock:
            state["last_logged_reject"] = None
            state["needs_retry"] = False
        return FormatReconcileResult(ok=True)

    wanted_format = (wanted_rate, wanted_bits)

    changed = False
    reject_error = ""
    reject_error_code = ""

    if backend_rate != wanted_rate:
        save_result = backend.save_setting(SETTING_PIPE_SAMPLE_RATE, wanted_rate)
        if save_result.ok:
            changed = True
            LOG.info(
                "Updated playback backend %s pipe_sample_rate from %r to %r at %s.",
                resolved.backend_id, backend_rate, wanted_rate, base_url_text,
            )
        else:
            reject_error = save_result.error or "Failed to save pipe_sample_rate"
            reject_error_code = save_result.error_code or "save_failed"

    # Skip the bits save this pass if rate already failed (keeps the two
    # writes ordered rather than firing both in parallel), but this is only
    # an ordering choice, not a correctness dependency -- a rate-only
    # failure here still leaves bits to be retried (or matching, and thus
    # skipped) on the very next reconcile pass regardless.
    if backend_bits != wanted_bits and not reject_error:
        save_result = backend.save_setting(SETTING_PIPE_BITS_PER_SAMPLE, wanted_bits)
        if save_result.ok:
            changed = True
            LOG.info(
                "Updated playback backend %s pipe_bits_per_sample from %r to %r at %s.",
                resolved.backend_id, backend_bits, wanted_bits, base_url_text,
            )
        else:
            reject_error = save_result.error or "Failed to save pipe_bits_per_sample"
            reject_error_code = save_result.error_code or "save_failed"

    if reject_error:
        # Log-noise control ONLY: throttles the WARNING to once per distinct
        # (wanted_format, error_code) state, never suppresses the retry
        # itself -- see the "No indefinite torn-pair state" guarantee above.
        # A partial failure here (one save ok, one failed) deliberately does
        # NOT restart owntone-mini (falls through to the return below,
        # before the restart trigger further down) so a torn persisted pair
        # is never armed by a restart from this pass.
        log_key = (wanted_format, reject_error_code)
        with _format_reconcile_state_lock:
            already_logged = state.get("last_logged_reject") == log_key
            state["last_logged_reject"] = log_key
            # A pending retry: picked up by retry_pending_format_reconcile()
            # from the periodic (per-poll, while-capturing) path the moment
            # owntone-mini is confirmed reachable again -- closes the gap
            # where a transient partial-save failure at startup/resync time
            # would otherwise only be revisited at the next monitor
            # reconnect (which could be days away).
            state["needs_retry"] = True
        if not already_logged:
            LOG.warning(
                "Playback backend %s rejected pipe format %d Hz / %d-bit at %s: %s "
                "(will retry on the next reconcile pass).",
                resolved.backend_id, wanted_rate, wanted_bits, base_url_text,
                reject_error,
            )
        return FormatReconcileResult(
            ok=True,
            changed=changed,
            error=reject_error,
            error_code=reject_error_code,
        )

    with _format_reconcile_state_lock:
        state["last_logged_reject"] = None
        state["needs_retry"] = False

    if not changed:
        return FormatReconcileResult(ok=True)

    LOG.warning(
        "Pipe format changed to %d Hz / %d-bit for %s; requesting OwnTone restart.",
        wanted_rate, wanted_bits, base_url_text,
    )
    _restart_owntone_backend_async(base_url_text)
    return FormatReconcileResult(ok=True, changed=True, restart_requested=True)


def retry_pending_format_reconcile(
    base_url: str,
    monitor_status: Optional[dict],
    *,
    timeout: float = 3.0,
) -> FormatReconcileResult:
    """Retry a still-pending pipe-format reconcile, cheaply, from the
    periodic path.

    reconcile_pipe_format_with_backend() only runs at startup and monitor
    reconnect. Its own retry-on-next-pass behaviour (the
    torn-persisted-pair fix) therefore only actually gets a next pass at one
    of those two moments -- fine for a monitor-side hiccup (a reconnect
    follows shortly), but a *transport* failure talking to owntone-mini
    (the backend itself down/restarting mid-save) recovers on its own
    schedule, unrelated to the monitor's connection state. Without this,
    a partial save from a startup-time transient could sit unresolved until
    the next monitor reconnect, which may be days away.

    This is a thin, cheap gate around the real reconcile: a NO-OP with zero
    HTTP traffic whenever nothing is pending (the steady-state case, so
    calling this every poll while capturing costs nothing) and a full
    reconcile pass when something is. Callers should invoke this from
    wherever owntone-mini's reachability has just been freshly confirmed
    (e.g. right after a successful outputs probe), so the retry fires
    exactly when the backend is actually back -- not on some fixed timer
    that pings a backend known to still be down.

    *monitor_status* is passed straight through to
    reconcile_pipe_format_with_backend(); if the monitor itself is down (or
    the caller has no fresher status handy), pass None or a stale dict --
    the underlying no-format-info no-op path (logged once, not per call)
    already covers that case, and the pending flag is left untouched so a
    later call with real status still gets a chance to retry.
    """
    base_url_text = str(base_url or "").strip()
    if not base_url_text:
        return FormatReconcileResult(ok=True)

    state = _format_reconcile_state_for(base_url_text)
    with _format_reconcile_state_lock:
        pending = bool(state.get("needs_retry"))
    if not pending:
        return FormatReconcileResult(ok=True)

    return reconcile_pipe_format_with_backend(
        base_url_text, monitor_status, timeout=timeout,
    )


# ---------------------------------------------------------------------------
# reconcile_monitor_format() -- the monitor-*side* enforcement half of the
# FIFO format-switch design. reconcile_pipe_format_with_backend()
# above reconciles owntone-mini's persisted pipe-format settings to follow
# whatever the monitor is REPORTING; this reconciles the monitor's own
# startup args -- whether it runs with --compatible or not -- against what
# the active backend adapter DECLARES it needs
# (PlayerBackend.required_monitor_format()). The two are deliberately
# sequenced monitor-format-first at both call sites in autostream_core.py:
# a monitor restart here changes what it reports, which the FIFO-path
# reconcile above then follows on the very next resync it triggers.
#
# Provisioning: the monitor's systemd unit
# (system/systemd/autostream_monitor.service) sources
# MONITOR_ARGS_ENV_PATH via `EnvironmentFile=-...` (the leading `-` makes a
# missing file non-fatal, so a fresh install with no file yet still starts
# the monitor in native mode) and appends $AUTOSTREAM_MONITOR_ARGS to
# ExecStart. Python (this module) owns writing that file; actually
# restarting the systemd unit requires root, so this reuses the
# restart-owntone admin pattern above: a new "restart-monitor" verb on
# supervisor/autostream_admin, invoked via run_admin_cmd(), authorized by a
# new Cmnd_Alias in system/sudoers/autostream_admin modeled on
# AUTOSTREAM_ADMIN_OWNTONE.
#
# AUTOSTREAM_MONITOR_ARGS carries two independent knobs composed together by
# _monitor_args_for_format(): the pipe-format token ("--compatible" or
# nothing, driven by the backend-declared required_monitor_format() as
# described above) and the SRC quality tier ("--src {fast,medium,best}",
# driven by the audio_path setting -- see autostream_config.normalize_
# audio_path and the audio_path -> tier table below). Both are always
# written together as one line; there is no partial-rewrite path, matching
# the "wholesale single-writer rewrite" contract for this file.
_monitor_format_reconcile_state_lock = threading.Lock()
_monitor_format_reconcile_state: dict[str, dict[str, Any]] = {}

# Written by Python (as the "autostream" user -- /etc/autostream is owned by
# autostream:autostream, see bootstrap_phase() in autostream_install.sh),
# read by the monitor's systemd unit via EnvironmentFile=-. Module-level so
# tests can monkeypatch it to a temp path.
MONITOR_ARGS_ENV_PATH = "/etc/autostream/monitor_args.env"


def _monitor_format_reconcile_state_for(base_url: str) -> dict[str, Any]:
    with _monitor_format_reconcile_state_lock:
        state = _monitor_format_reconcile_state.get(base_url)
        if state is None:
            state = {
                # Throttles the mismatch/failure WARNING to once per distinct
                # (desired, reported) pair, mirroring
                # _format_reconcile_state's "last_logged_reject" above --
                # never suppresses the retry itself.
                "last_logged_state": None,
                "needs_retry": False,
            }
            _monitor_format_reconcile_state[base_url] = state
        return state


def _extract_reported_monitor_format(monitor_status: Optional[dict]) -> Optional[str]:
    """Return "native"/"compatible" as reported by the monitor, or None.

    Prefers the explicit "output_format" status field. Falls back to
    interpreting the numeric output_rate/output_bits pair for older
    monitor binaries, which report those two fields but not output_format
    yet -- those builds predate
    --compatible entirely, so a numeric report is always native
    (48000/32); anything else (including a --compatible-shaped 44100/16
    pair, which cannot come from those builds) is treated as unrecognised
    rather than guessed at.
    """
    if not isinstance(monitor_status, dict):
        return None

    reported = monitor_status.get("output_format")
    if isinstance(reported, str) and reported in ("native", "compatible"):
        return reported

    rate, bits = _extract_monitor_output_format(monitor_status)
    if rate is None or bits is None:
        return None
    if rate == 48000 and bits == 32:
        return "native"
    if rate == 44100 and bits == 16:
        return "compatible"
    return None


# audio_path -> monitor --src tier. Kept adjacent to
# _monitor_args_for_format() since both AUTOSTREAM_MONITOR_ARGS knobs are
# composed there. Unrecognised/missing audio_path falls back to "medium",
# matching autostream_config.AUDIO_PATH_DEFAULT ("balanced").
_AUDIO_PATH_SRC_TIER = {
    "max": "best",
    "balanced": "medium",
    "fast": "fast",
}
_AUDIO_PATH_SRC_TIER_DEFAULT = "medium"

# audio_path -> owntone-mini resample_quality. "max" and "balanced" share
# the soxr-VHQ tier deliberately (its cost is trivial, so no middle tier is
# needed); "fast" reproduces pre-change swr-default behaviour.
_AUDIO_PATH_RESAMPLE_QUALITY = {
    "max": "high",
    "balanced": "high",
    "fast": "standard",
}
_AUDIO_PATH_RESAMPLE_QUALITY_DEFAULT = "high"


def _src_tier_for_audio_path(audio_path: str) -> str:
    return _AUDIO_PATH_SRC_TIER.get(str(audio_path or "").strip().lower(), _AUDIO_PATH_SRC_TIER_DEFAULT)


def _resample_quality_for_audio_path(audio_path: str) -> str:
    return _AUDIO_PATH_RESAMPLE_QUALITY.get(
        str(audio_path or "").strip().lower(), _AUDIO_PATH_RESAMPLE_QUALITY_DEFAULT
    )


def _monitor_args_for_format(desired_format: str, audio_path: str = "balanced") -> str:
    parts = []
    if desired_format == "compatible":
        parts.append("--compatible")
    parts.append("--src")
    parts.append(_src_tier_for_audio_path(audio_path))
    return " ".join(parts)


def _read_current_monitor_args() -> Optional[str]:
    """Return the AUTOSTREAM_MONITOR_ARGS value currently persisted at
    MONITOR_ARGS_ENV_PATH, or None if the file is absent/unreadable or does
    not contain the line -- callers must treat None as "unknown", never as
    an empty composed string (an actually-empty native/no-tier value is
    represented by the line being present with nothing after '=').
    """
    try:
        with open(MONITOR_ARGS_ENV_PATH, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return None
    prefix = "AUTOSTREAM_MONITOR_ARGS="
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):]
    return None


def _write_monitor_args_env_file(desired_format: str, audio_path: str = "balanced") -> bool:
    from autostream_sysutils import atomic_write_file

    args = _monitor_args_for_format(desired_format, audio_path)
    try:
        atomic_write_file(
            MONITOR_ARGS_ENV_PATH,
            lambda f: f.write(f"AUTOSTREAM_MONITOR_ARGS={args}\n"),
            preserve_mode=False,
        )
    except Exception:
        LOG.exception(
            "Monitor-format reconcile: failed writing %s", MONITOR_ARGS_ENV_PATH,
        )
        return False
    try:
        os.chmod(MONITOR_ARGS_ENV_PATH, 0o644)
    except OSError:
        LOG.debug(
            "Monitor-format reconcile: could not chmod %s", MONITOR_ARGS_ENV_PATH,
        )
    return True


def _restart_monitor_async(desired_format: str, reported_format: str) -> None:
    """Fire-and-forget monitor restart request, mirroring
    _restart_owntone_backend_async() above (same run_admin_cmd() /
    "sudo -n autostream_admin <verb>" pattern, new "restart-monitor" verb).
    """
    def _worker() -> None:
        try:
            p = run_admin_cmd(["restart-monitor"], timeout=20.0)
            if p.returncode != 0:
                LOG.error(
                    "Monitor-format reconcile: restart-monitor failed (rc=%s): %s",
                    p.returncode, (p.stderr or "").strip(),
                )
            else:
                LOG.warning(
                    "Monitor-format reconcile: restart-monitor requested "
                    "(%s -> %s).",
                    reported_format, desired_format,
                )
        except Exception:
            LOG.exception("Monitor-format reconcile: restart-monitor raised")

    threading.Thread(
        target=_worker, name="monitor-format-reconcile-restart", daemon=True,
    ).start()


def reconcile_monitor_format(
    base_url: str,
    monitor_status: Optional[dict],
    *,
    timeout: float = 3.0,
    audio_path: str = "balanced",
) -> FormatReconcileResult:
    """Align the monitor's --compatible startup arg with what the active
    playback backend declares it needs.

    desired = resolve_backend(base_url).backend.required_monitor_format()
    reported = _extract_reported_monitor_format(monitor_status)

    *audio_path* only affects the composed --src tier written on a mismatch
    pass (see _monitor_args_for_format()); it plays no part in the
    native/compatible comparison below. A same-format --src-only change (the
    Audio Path dropdown, with the pipe format unchanged) does not flow
    through here -- see sync_monitor_args_for_audio_path() for that path.

    Guarantees (mirrors reconcile_pipe_format_with_backend()'s above):
      - Idempotent: a matching pass never writes the env file or restarts.
      - desired is None (backend unreachable/undecided) => no-op.
      - monitor_status is falsy/malformed, or reported comes back None
        (monitor down, or too old to report a format at all) => no-op --
        there is nothing to compare against yet.
      - Throttled logging: one WARNING per distinct (desired, reported)
        state, not once per poll/call.
      - An env-file write failure is logged (also throttled) and never
        triggers a restart (nothing would have changed on disk yet); the
        pending state is left set so the next reconcile pass -- run from
        the same call sites as reconcile_pipe_format_with_backend(), i.e.
        every startup/resync -- retries automatically.
      - A restart is only ever requested after the env file write itself
        has been confirmed to succeed.
    """
    base_url_text = str(base_url or "").strip()
    if not base_url_text:
        return FormatReconcileResult(ok=True)

    state = _monitor_format_reconcile_state_for(base_url_text)

    if not isinstance(monitor_status, dict) or not monitor_status:
        # Monitor down / no status yet -- nothing to reconcile against this
        # pass. Deliberately not treated as an error (same convention as
        # reconcile_pipe_format_with_backend()'s no-monitor-info path).
        return FormatReconcileResult(ok=True)

    resolved = resolve_backend(base_url_text, timeout=timeout)
    backend = resolved.backend

    if not resolved.detection_confident:
        # detect_backend() matched nothing this pass and resolve_backend()
        # guessed BACKEND_OWNTONE as a fallback default (e.g. owntone-mini
        # crashed/unreachable) -- see ResolvedBackend.detection_confident.
        # The fallback adapter's required_monitor_format() answer is not
        # evidence of what the real backend needs, so treat desired as
        # UNKNOWN: no env write, no restart. Trusting a fallback guess here
        # can flip a healthy native appliance into --compatible mode and
        # wipe the monitor's in-RAM repeat buffer while owntone-mini is
        # merely unreachable rather than genuinely reconfigured.
        with _monitor_format_reconcile_state_lock:
            already_logged = state.get("last_logged_state") == "unconfirmed"
            state["last_logged_state"] = "unconfirmed"
        if not already_logged:
            LOG.warning(
                "Monitor-format reconcile: backend identity unconfirmed for "
                "%s (detection fell back to a default); format enforcement "
                "deferred.",
                base_url_text,
            )
        return FormatReconcileResult(ok=True)

    try:
        desired_format = backend.required_monitor_format()
    except Exception:
        LOG.exception(
            "Monitor-format reconcile: required_monitor_format() raised for "
            "backend %s at %s",
            resolved.backend_id, base_url_text,
        )
        return FormatReconcileResult(
            ok=True, error="required_monitor_format() raised", error_code="probe_error",
        )

    if desired_format not in ("native", "compatible"):
        # None: backend unreachable or otherwise unable to answer right now.
        # Take no enforcement action -- do not guess, do not clear pending
        # retry state (a real answer may already be pending resolution).
        return FormatReconcileResult(ok=True)

    reported_format = _extract_reported_monitor_format(monitor_status)
    if reported_format is None:
        # Monitor status doesn't (yet) carry a usable format signal -- an
        # older monitor build, or an unrecognised numeric pair.
        return FormatReconcileResult(ok=True)

    log_key = (desired_format, reported_format)

    if desired_format == reported_format:
        with _monitor_format_reconcile_state_lock:
            state["last_logged_state"] = None
            state["needs_retry"] = False
        return FormatReconcileResult(ok=True)

    if not _write_monitor_args_env_file(desired_format, audio_path):
        with _monitor_format_reconcile_state_lock:
            already_logged = state.get("last_logged_state") == log_key
            state["last_logged_state"] = log_key
            state["needs_retry"] = True
        if not already_logged:
            LOG.warning(
                "Monitor-format reconcile: backend %s requires %r but monitor "
                "reports %r at %s; failed to write %s (will retry next pass).",
                resolved.backend_id, desired_format, reported_format,
                base_url_text, MONITOR_ARGS_ENV_PATH,
            )
        return FormatReconcileResult(
            ok=True,
            error="failed to write monitor args env file",
            error_code="env_write_failed",
        )

    with _monitor_format_reconcile_state_lock:
        already_logged = state.get("last_logged_state") == log_key
        state["last_logged_state"] = log_key
        state["needs_retry"] = False

    if not already_logged:
        LOG.warning(
            "Monitor-format reconcile: backend %s requires %r but monitor "
            "reports %r at %s; wrote %s and requesting a monitor restart.",
            resolved.backend_id, desired_format, reported_format,
            base_url_text, MONITOR_ARGS_ENV_PATH,
        )
    _restart_monitor_async(desired_format, reported_format)
    return FormatReconcileResult(ok=True, changed=True, restart_requested=True)


def sync_monitor_args_for_audio_path(
    base_url: str,
    audio_path: str,
    *,
    timeout: float = 3.0,
) -> bool:
    """Recompose AUTOSTREAM_MONITOR_ARGS for the current backend-declared
    pipe format and *audio_path*; write it and request a monitor restart
    only if the composed line actually differs from what is currently
    persisted. Returns True iff a restart was requested.

    This is the Web UI change-flow half of monitor-arg maintenance:
    reconcile_monitor_format() above only reacts to a native/compatible
    mismatch reported by the running monitor, so a same-format --src-tier-
    only change (e.g. the Audio Path dropdown) never reaches its write path.
    This function instead compares the composed args string itself, so it
    reacts correctly regardless of whether the pipe format also changed.
    Safe to call from any reconcile/resync pass -- a no-op once the
    persisted line already matches, per _read_current_monitor_args().
    """
    base_url_text = str(base_url or "").strip()
    if not base_url_text:
        return False

    resolved = resolve_backend(base_url_text, timeout=timeout)
    if not resolved.detection_confident:
        # Same fallback-guess deferral as reconcile_monitor_format() above --
        # an unconfirmed backend identity is not evidence of what format it
        # actually needs.
        return False

    try:
        desired_format = resolved.backend.required_monitor_format()
    except Exception:
        LOG.exception(
            "sync_monitor_args_for_audio_path: required_monitor_format() "
            "raised for %s", base_url_text,
        )
        return False
    if desired_format not in ("native", "compatible"):
        return False

    new_args = _monitor_args_for_format(desired_format, audio_path)
    current_args = _read_current_monitor_args()
    if current_args is not None and current_args == new_args:
        return False

    if not _write_monitor_args_env_file(desired_format, audio_path):
        LOG.warning(
            "audio_path change: failed to write %s for %s (will retry on "
            "the next reconcile pass).",
            MONITOR_ARGS_ENV_PATH, base_url_text,
        )
        return False

    LOG.warning(
        "audio_path change: wrote %s (%r) for %s and requesting a monitor "
        "restart.",
        MONITOR_ARGS_ENV_PATH, new_args, base_url_text,
    )
    _restart_monitor_async(desired_format, f"audio_path={audio_path}")
    return True


def push_resample_quality(
    base_url: str,
    audio_path: str,
    *,
    timeout: float = 3.0,
) -> SaveSettingResult:
    """Push the owntone-mini resample_quality knob derived from *audio_path*.

    Capability-aware, same idiom as the pipe-format keys in
    reconcile_pipe_format_with_backend(): a backend that reports the setting
    as unsupported -- stock/full OwnTone (no normalized-settings surface at
    all) or an owntone-mini build that predates this key (404) -- is a
    debug-logged no-op here, never a failure. A genuine save rejection
    (backend reachable, key recognised, value refused, or a transient
    transport error) is logged at INFO and left for the caller to retry on
    the next reconcile pass -- the same tolerated-to-fail rule
    set_repeat_enabled uses against an old monitor binary.
    """
    quality = _resample_quality_for_audio_path(audio_path)
    result = save_setting(base_url, SETTING_RESAMPLE_QUALITY, quality, timeout=timeout)
    if result.unsupported:
        LOG.debug(
            "resample_quality push skipped for %s: backend does not expose "
            "this setting (stock OwnTone, or an owntone-mini build "
            "predating the key).",
            base_url,
        )
    elif not result.ok:
        LOG.info(
            "resample_quality push (%r) not accepted for %s: %s (will "
            "retry on the next reconcile pass).",
            quality, base_url, result.message or "save failed",
        )
    return result


def resolve_backend(base_url: str, *, timeout: float = 3.0) -> ResolvedBackend:
    normalized_base_url = _normalize_base_url(base_url)

    with _CACHE_LOCK:
        cached = _DETECTION_CACHE.get(normalized_base_url)
        if cached and (time.monotonic() - cached[0]) <= _DETECTION_CACHE_SECONDS:
            backend_id = cached[1]
            version = cached[2]
            last_seen_at = cached[3]
            detection_confident = cached[4] if len(cached) > 4 else True
            LOG.debug(
                "Playback backend cache hit for %s: backend=%s age=%.2fs",
                normalized_base_url,
                backend_id,
                time.monotonic() - cached[0],
            )
            _set_owntone_runtime_info(
                base_url=normalized_base_url,
                backend_id=backend_id,
                version=version or "unknown",
                connected=True,
                last_seen_at=last_seen_at,
            )
            return ResolvedBackend(
                backend_id=backend_id,
                backend=create_backend(backend_id, base_url=normalized_base_url, timeout=timeout),
                detection_confident=detection_confident,
            )

    LOG.debug(
        "Resolving playback backend for %s (timeout=%.1fs)",
        normalized_base_url,
        timeout,
    )
    backend, detections = detect_backend(normalized_base_url, timeout=timeout)
    for detection in detections:
        LOG.debug(
            "Playback backend probe for %s: candidate=%s matched=%s detail=%s",
            normalized_base_url,
            detection.backend_id,
            detection.matched,
            detection.detail or "-",
        )
    # Whether *this* resolution came from a probe that actually matched
    # (True) vs. detect_backend() finding nothing and resolve_backend()
    # guessing BACKEND_OWNTONE as a default (False). See ResolvedBackend.
    # detection_confident's docstring -- enforcement callers must not treat
    # a fallback guess as evidence of what the real backend needs.
    detection_confident = backend is not None
    if backend is None:
        LOG.info(
            "No playback backend probe matched for %s; falling back to backend=%s",
            normalized_base_url,
            BACKEND_OWNTONE,
        )
        _set_owntone_runtime_info(base_url=normalized_base_url, connected=False)
        backend = create_backend(BACKEND_OWNTONE, base_url=normalized_base_url, timeout=timeout)
    backend_id = backend.backend_id
    selected_detection = next(
        (d for d in detections if d.matched and d.backend_id == backend_id),
        None,
    )
    detected_version = (
        str(selected_detection.version).strip()
        if selected_detection is not None
        else ""
    )
    detected_at = time.time()
    LOG.debug(
        "Playback backend selected for %s: backend=%s",
        normalized_base_url,
        backend_id,
    )

    with _CACHE_LOCK:
        _DETECTION_CACHE[normalized_base_url] = (
            time.monotonic(),
            backend_id,
            detected_version,
            detected_at,
            detection_confident,
        )
        LOG.debug(
            "Cached playback backend selection for %s: backend=%s ttl=%.1fs confident=%s",
            normalized_base_url,
            backend_id,
            _DETECTION_CACHE_SECONDS,
            detection_confident,
        )

    if selected_detection is not None:
        _set_owntone_runtime_info(
            base_url=normalized_base_url,
            backend_id=backend_id,
            version=detected_version or "unknown",
            connected=True,
            last_seen_at=detected_at,
        )
    else:
        _set_owntone_runtime_info(
            base_url=normalized_base_url,
            backend_id=backend_id,
            connected=False,
        )

    return ResolvedBackend(backend_id=backend_id, backend=backend, detection_confident=detection_confident)


def list_outputs(base_url: str, *, timeout: float = 3.0) -> ListOutputsResult:
    return resolve_backend(base_url, timeout=timeout).backend.list_outputs()


def get_output(base_url: str, output_id: str, *, timeout: float = 3.0) -> GetOutputResult:
    return resolve_backend(base_url, timeout=timeout).backend.get_output(output_id)


def get_output_by_name(base_url: str, output_name: str, *, timeout: float = 3.0) -> Optional[OutputInfo]:
    wanted = str(output_name or "").strip()
    if not wanted:
        return None
    result = list_outputs(base_url, timeout=timeout)
    if not result.ok:
        return None
    for output in result.outputs:
        if str(output.name or "").strip() == wanted:
            return output
    return None


def set_output_enabled(base_url: str, output_id: str, enabled: bool, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.set_output_enabled(output_id, enabled)


def set_selected_outputs(base_url: str, output_ids: list[str], *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.set_selected_outputs(output_ids)


def set_output_volume(base_url: str, output_id: str, volume_percent: int, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.set_output_volume(output_id, volume_percent)


def set_output_offset(base_url: str, output_id: str, offset_ms: int, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.set_output_offset(output_id, offset_ms)


def update_output(
    base_url: str,
    output_id: str,
    *,
    enabled: bool | None = None,
    volume_percent: int | None = None,
    offset_ms: int | None = None,
    mode: str | None = None,
    timeout: float = 3.0,
) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.update_output(
        output_id,
        enabled=enabled,
        volume_percent=volume_percent,
        offset_ms=offset_ms,
        mode=mode,
    )


def submit_output_pin(base_url: str, output_id: str, pin: str, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.submit_output_pin(output_id, pin)


def play(base_url: str, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.play()


def stop(base_url: str, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.stop()


def stop_and_disable_all(base_url: str, *, timeout: float = 3.0) -> ActionResult:
    stop_result = stop(base_url, timeout=timeout)
    disable_result = set_selected_outputs(base_url, [], timeout=timeout)
    if stop_result.ok and disable_result.ok:
        return ActionResult(ok=True)
    errors = [r.error for r in (stop_result, disable_result) if not r.ok and r.error]
    codes = [r.error_code for r in (stop_result, disable_result) if not r.ok and r.error_code]
    return ActionResult(
        ok=False,
        error="; ".join(errors) or "Failed to stop playback and disable outputs",
        error_code=codes[0] if codes else "compound_error",
        detail="; ".join(
            f"{label}: {r.detail}"
            for label, r in (("stop", stop_result), ("disable", disable_result))
            if not r.ok and r.detail
        ),
    )


def ensure_pipe_source_ready(base_url: str, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.ensure_pipe_source_ready()


def refresh_runtime_state(base_url: str, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.refresh_runtime_state()


def request_library_update(base_url: str, *, timeout: float = 3.0) -> ActionResult:
    return resolve_backend(base_url, timeout=timeout).backend.request_library_update()


def get_status(base_url: str, *, timeout: float = 3.0) -> BackendStatus:
    return resolve_backend(base_url, timeout=timeout).backend.get_status()


def get_capabilities(base_url: str, *, timeout: float = 3.0) -> BackendCapabilities:
    return resolve_backend(base_url, timeout=timeout).backend.get_capabilities()


def get_setting(base_url: str, key: str, *, timeout: float = 3.0) -> SettingValueResult:
    return resolve_backend(base_url, timeout=timeout).backend.get_setting(key)


def save_setting(base_url: str, key: str, value: Any, *, timeout: float = 3.0) -> SaveSettingResult:
    return resolve_backend(base_url, timeout=timeout).backend.save_setting(key, value)


def list_supported_settings(base_url: str, *, timeout: float = 3.0) -> list[SettingDescriptor]:
    return resolve_backend(base_url, timeout=timeout).backend.list_supported_settings()


def push_metadata(base_url: str, *, title: str = "", artist: str = "", album: str = "", artwork_url: str = "", timeout: float = 3.0) -> ActionResult:
    """No live caller today. The supported now-playing artwork transport is
    the pipe metadata bundle (see core/autostream_nowplaying.py), not this
    API path -- artwork_url here goes straight to the backend as a raw
    reference and skips the <=48KB normalisation contract every other
    artwork consumer relies on. Any future caller must normalise first."""
    metadata = PlaybackMetadata(
        title=str(title or ""),
        artist=str(artist or ""),
        album=str(album or ""),
        artwork_url=str(artwork_url or ""),
    )
    return resolve_backend(base_url, timeout=timeout).backend.push_metadata(metadata)


def save_log_level(base_url: str, level_name: str, *, timeout: float = 3.0):
    return save_setting(base_url, SETTING_LOG_LEVEL, level_name, timeout=timeout)


def config_airplay_mode_to_backend(mode: object) -> str:
    text = str(mode or "").strip().lower()
    if text == "raop":
        return OUTPUT_MODE_AIRPLAY1
    if text == "airplay2":
        return OUTPUT_MODE_AIRPLAY2
    if text == OUTPUT_MODE_AIRPLAY2_BUFFERED:
        return OUTPUT_MODE_AIRPLAY2_BUFFERED
    if text == OUTPUT_MODE_AIRPLAY2_SURROUND_STEREO:
        return OUTPUT_MODE_AIRPLAY2_SURROUND_STEREO
    if text == OUTPUT_MODE_AIRPLAY2_SURROUND_UPMIX:
        return OUTPUT_MODE_AIRPLAY2_SURROUND_UPMIX
    return OUTPUT_MODE_AUTO


def backend_output_mode_to_config(mode: object) -> str:
    text = str(mode or "").strip().lower()
    if text == OUTPUT_MODE_AIRPLAY1:
        return "raop"
    if text == OUTPUT_MODE_AIRPLAY2:
        return "airplay2"
    if text == OUTPUT_MODE_AIRPLAY2_BUFFERED:
        return OUTPUT_MODE_AIRPLAY2_BUFFERED
    if text == OUTPUT_MODE_AIRPLAY2_SURROUND_STEREO:
        return OUTPUT_MODE_AIRPLAY2_SURROUND_STEREO
    if text == OUTPUT_MODE_AIRPLAY2_SURROUND_UPMIX:
        return OUTPUT_MODE_AIRPLAY2_SURROUND_UPMIX
    return "default"


def output_supported_config_modes(output: OutputInfo) -> tuple[str, ...]:
    config_modes: list[str] = []
    for mode in output.supported_modes or (OUTPUT_MODE_AUTO,):
        mapped = backend_output_mode_to_config(mode)
        if mapped not in config_modes:
            config_modes.append(mapped)
    return tuple(config_modes)
