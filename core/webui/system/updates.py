#!/usr/bin/env python3
"""webui/system/updates.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The installed application version, read once through the privileged helper.
"""

from __future__ import annotations

import json
import logging
import subprocess
import threading
from typing import Optional

from autostream_intents import Intent, submit
from autostream_state import Origin
from autostream_sysutils import run_admin_cmd

# The page helpers import this module (for the version in asset URLs), so
# the functions below import them when called, not at module level.

# Cached on first call; immutable for the process lifetime since an update
# always triggers a full process restart.
_app_version_cache: Optional[str] = None

# A leaf lock: the start-up announcement and the web server's prime may both
# ask at once; they share one helper call.
_app_version_lock = threading.Lock()


def get_app_version() -> str:
    """Return the installed application version via the privileged helper.

    The result is cached in memory after the first call. Because applying an
    update always restarts the process, the version cannot change while the
    process is running.  Every failed helper outcome (exception, nonzero exit,
    invalid JSON, blank tag) is cached as "unknown" so repeated calls cannot
    each incur the five-second subprocess timeout.
    """
    with _app_version_lock:
        return _get_app_version_locked()


def _get_app_version_locked() -> str:
    global _app_version_cache
    if _app_version_cache is not None:
        return _app_version_cache

    cmd = [
        "/usr/bin/sudo",
        "-n",
        "/usr/local/libexec/autostream/autostream_admin",
        "version-info",
    ]
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:
        _app_version_cache = "unknown"
        return _app_version_cache

    if p.returncode != 0:
        _app_version_cache = "unknown"
        return _app_version_cache

    try:
        payload = json.loads(p.stdout or "{}")
    except Exception:
        _app_version_cache = "unknown"
        return _app_version_cache

    version = str(payload.get("release_tag") or "").strip()
    _app_version_cache = version or "unknown"
    return _app_version_cache

# -----------------------------------------------------------------------------
# Updater subprocess helper
# -----------------------------------------------------------------------------

def run_updater(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
    cmd = ["/usr/bin/sudo", "-n", "/usr/local/libexec/autostream/autostream_updater", *args]
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    return p.returncode, p.stdout, p.stderr


def send_update_check_json(handler, state=None) -> None:
    # The updater subprocess reads the update channel from the config file on
    # disk, while settings changes (e.g. the pre-release channel toggle) are
    # flushed to disk on a debounced interval -- force the flush first so a
    # check issued right after a toggle cannot run against the old channel.
    from webui import common
    if getattr(state, "settings", None) is not None:
        try:
            submit(Intent("settings.save", {"timeout": 5.0}, Origin.USER, "webui", context=state))
        except Exception:
            pass  # best effort; the check still runs against current disk state
    rc, out, err = run_updater(["check"], timeout=60)
    if rc != 0:
        common.send_json(handler, 200, {"ok": False, "error": "check failed"})
        return
    try:
        payload = json.loads(out)
    except Exception:
        common.send_json(handler, 200, {"ok": False})
        return
    if isinstance(payload, dict):
        notes = payload.get("release_notes")
        if isinstance(notes, str) and notes:
            payload = {**payload, "release_notes_html": common.render_license_md(notes)}
    common.send_json(handler, 200, payload)


def send_update_status_json(handler) -> None:
    """Return the persisted update status from update-result.env via autostream_admin.

    The response shape matches what autostream_admin update-status emits:
      {ok, status, message, percent, last_run_at}
    where status is one of: in_progress | success | failure | error | unknown
    """
    from webui import common
    p = run_admin_cmd(["update-status"], timeout=10.0)
    if p.returncode != 0:
        common.send_json(handler, 200, {
            "ok": False,
            "status": "error",
            "message": "Could not read update status",
            "percent": 0,
            "last_run_at": "",
        })
        return
    try:
        common.send_json(handler, 200, json.loads(p.stdout or "{}"))
    except Exception:
        common.send_json(handler, 200, {
            "ok": False,
            "status": "error",
            "message": "Malformed update status response",
            "percent": 0,
            "last_run_at": "",
        })

# -----------------------------------------------------------------------------
# Background update-apply state
# -----------------------------------------------------------------------------

# Guards against a second POST /api/update/apply starting a concurrent
# staging run while one is already in flight. The installer itself is
# flock-protected once scheduled, so this only needs to cover the staging
# window that now runs off the request thread.
_update_apply_lock = threading.Lock()
_update_apply_in_progress = False


def _update_apply_mark_finished() -> None:
    global _update_apply_in_progress
    with _update_apply_lock:
        _update_apply_in_progress = False


def _run_update_apply_background() -> None:
    """Run the updater's apply step off the request thread.

    Started as a daemon thread by _start_update_apply once the response has
    already been sent to the client. Always clears the in-flight guard on
    the way out, regardless of outcome.
    """
    try:
        try:
            rc, out, err = run_updater(["apply"], timeout=180)
        except subprocess.TimeoutExpired:
            # The updater subprocess (invoked via sudo) is not guaranteed to
            # die with its parent, so a timeout here does not mean the apply
            # itself failed — staging or the installer hand-off may still be
            # under way. autostream_updater (running as root) is the sole
            # writer of update-result.env for this window; if it is still
            # progressing, its own writes continue to land regardless of this
            # process losing track of the subprocess, so nothing needs to be
            # written here — only logged.
            logging.error("update apply: timed out waiting for updater subprocess")
            return
        except Exception as e:
            # As above: autostream_updater owns update-result.env, including
            # any failure state, so only logging is needed here.
            logging.error("update apply: background apply raised: %s", e)
            return

        if rc == 0:
            try:
                result = json.loads(out or "{}")
            except Exception:
                result = {"ok": True}
            if not result.get("ok", True):
                # The updater has already written its own failure (or, for a
                # detected concurrent update, deliberately left the running
                # instance's own progress untouched) — log only.
                logging.error("update apply: updater reported failure: %s", result)
            return

        try:
            result = json.loads(out or "{}")
            message = str(result.get("error") or "Update failed")
        except Exception:
            message = "Update failed"
        if err.strip():
            message = f"{message}: {err.strip()}"
        # The updater owns update-result.env; a non-zero exit before it could
        # write anything is rare (e.g. sudo/exec failure) but even then there
        # is nothing this unprivileged process can do about the result file.
        logging.error("update apply: updater exited rc=%s: %s", rc, message)
    finally:
        _update_apply_mark_finished()


def start_update_apply(handler) -> None:
    """Accept an update-apply request and run it in the background.

    Staging the release tarball can take long enough on slow hardware to
    exceed the reverse proxy's read timeout, so this no longer blocks the
    request: it starts run_updater("apply") on a daemon thread and
    responds immediately with {ok: True, accepted: True}. The JS client
    treats "accepted" the same way it used to treat a synchronous
    success and navigates to /offline/updating, which polls the update
    status autostream_updater (running as root) and, once scheduled,
    the installer write to update-result.env. This process cannot write
    that root-owned file itself, so _run_update_apply_background only
    logs outcomes rather than persisting them there.

    A second POST while an apply is already in flight does not start a
    concurrent run -- it returns already_in_progress=True instead. The
    installer itself is flock-protected once scheduled; this guard only
    needs to cover the staging window that now runs here.
    """
    from webui import common
    global _update_apply_in_progress
    with _update_apply_lock:
        if _update_apply_in_progress:
            common.send_json(handler, 200, {"ok": True, "accepted": True, "already_in_progress": True})
            return
        _update_apply_in_progress = True

    try:
        threading.Thread(
            target=_run_update_apply_background,
            name="update-apply",
            daemon=True,
        ).start()
    except Exception as e:
        # The guard must never outlive a run that was never started, or
        # every later apply would be refused as already_in_progress.
        _update_apply_mark_finished()
        logging.error("update apply: could not start background thread: %s", e)
        common.send_json(handler, 200, {"ok": False, "error": "Could not start update"})
        return
    common.send_json(handler, 200, {"ok": True, "accepted": True})

# -----------------------------------------------------------------------------
# Route-table adapters
# -----------------------------------------------------------------------------


def _route_get_update_status(handler, state):
    send_update_status_json(handler)


def _route_post_update_apply(handler, state, body_str):
    # Legacy inline pre-logic (do_POST's former /api/update/apply arm):
    # flush dirty settings to disk before staging an update.
    from webui import common
    from webui.system import power
    if not power._settings_save_barrier(state):
        common.send_json(handler, 200, {"ok": False, "error": "Settings could not be saved before update"})
        return
    handler._start_update_apply()

