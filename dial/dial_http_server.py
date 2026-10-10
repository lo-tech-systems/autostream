"""dial_http_server.py — Dial management API (port 7842).

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

This module is a management API used by the autostream appliance to configure
the dial (name, PIN, step size, auto-update).  It does not serve a browser-
facing setup UI; dial configuration is done through the appliance web interface.

Routes: GET /configure, POST /configure, GET /recovery_status,
GET /update/status, GET /update/check, POST /update,
POST /recovery/arm, POST /recovery/disarm, POST /auth-changed,
POST /warnings-changed,
GET /screen/settings, POST /screen/settings, GET /screen/image,
GET /sdcard-health, POST /sdcard-health.
"""
from __future__ import annotations

import copy
import http.server
import json
import logging
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

from dial_config import (
    InvalidScreenSettings,
    PIN_RESET_PATH,
    _read_env_file,
    effective_scope,
    validate_screen_settings,
)
from dial_display_profiles import (
    DEFAULT_PROFILE_KEY,
    UnknownDisplayProfileError,
    get_profile,
    layout_context_for,
    layout_size_options,
    list_profiles,
)
from dial_touch_controllers import list_controllers
from dial_touch_layout import metrics_for

# autostream_sysutils is deployed flat into /opt/autostream beside the dial
# package; in the repo it lives in core/.
try:
    from autostream_sysutils import (
        SDCARD_HEALTH_METHODS,
        sdcard_health_check,
        sdcard_health_disable,
        sdcard_health_enable,
        sdcard_health_state,
    )
except ImportError:
    import os as _os
    import sys as _sys
    _sys.path.insert(0, _os.path.abspath(_os.path.join(_os.path.dirname(__file__), '..', 'core')))
    from autostream_sysutils import (
        SDCARD_HEALTH_METHODS,
        sdcard_health_check,
        sdcard_health_disable,
        sdcard_health_enable,
        sdcard_health_state,
    )

ADMIN_CMD           = '/usr/local/libexec/autostream/autostream_admin'
_UPDATER_CMD        = '/usr/local/libexec/autostream/autostream_dial_updater'
_INSTALL_STATE_PATH = Path('/var/lib/autostream/install-state.env')
_UPDATE_RESULT_PATH = Path('/var/lib/autostream/update-result.env')

MAX_BODY = 4096  # bytes — rejects oversized bodies before JSON parsing

# POST /screen/settings is unauthenticated when no PIN is configured (the
# out-of-box state — see the PIN check further down), and the dial's unit
# has RestartSec=10. Without a floor on trigger frequency, an open restart
# endpoint is a sustained denial-of-service. This is a security control,
# not a nicety.
_TOUCH_RESTART_COOLDOWN_SECONDS = 60

# ---- Version ----------------------------------------------------------------

def _load_version() -> str:
    env = _read_env_file(_INSTALL_STATE_PATH)
    return env.get('AUTOSTREAM_RELEASE_TAG', 'unknown') or 'unknown'


VERSION = _load_version()

# ---- Screen profile resolution -----------------------------------------------

def _profile_for(display_cfg):
    """Resolve *display_cfg*'s screen_type to a DisplayProfile, falling back
    to the default profile for an unresolvable key — the same fallback
    layout_context_for() and the display manager use, so the layout sizes
    this reports always match what the display would actually offer."""
    try:
        return get_profile(display_cfg.screen_type)
    except UnknownDisplayProfileError:
        return get_profile(DEFAULT_PROFILE_KEY)


def _layout_report_for(display_cfg) -> dict:
    """What *display_cfg*'s screen_type, screen_size_inches and layout_size
    resolve to: the logical size the display composes and hit-tests at, the
    physical panel size it resamples to, and the content tier and touch-
    target assessment for that combination. Computed from the persisted
    configuration (not the open backend), so the answer is available before
    a panel is fitted or open — the display manager's own
    layout_context_for()/metrics_for() pair, applied here to the request's
    own config snapshot. Pure and lock-free: a few multiplications on that
    snapshot. Never raises: an unknown screen_type resolves to the default
    profile inside layout_context_for()."""
    ctx = layout_context_for(display_cfg)
    m = metrics_for(
        ctx.logical_width, ctx.logical_height,
        mm_per_px=ctx.mm_per_px, size_chosen=ctx.size_chosen,
    )
    return {
        "logical_width": ctx.logical_width,
        "logical_height": ctx.logical_height,
        "physical_width": ctx.physical_width,
        "physical_height": ctx.physical_height,
        "resampled": ctx.resamples,
        "size_chosen": ctx.size_chosen,
        "content_tier": m.content_tier,
        "touch_short": m.touch_short,
    }


def _scope_report_for(display_cfg) -> dict:
    """The EFFECTIVE volume/mute scope for *display_cfg*: the stored choice
    while a screen is fitted, else always "all" (see
    dial_config.effective_scope()). Informational — a client never sends
    this back; it exists so the setup card and a person reading the JSON can
    see what the dial is actually doing, not just what is stored. Pure and
    lock-free: computed from the request's own config snapshot."""
    return {
        "volume": effective_scope(display_cfg, display_cfg.volume_scope),
        "mute": effective_scope(display_cfg, display_cfg.mute_scope),
    }


# ---- Name validation --------------------------------------------------------

_SAFE_NAME = re.compile(r'^[\x20-\x7e]*$')
_BAD_CHARS = re.compile(r'[;|]')


def _validate_dial_name(name: str) -> None:
    if not _SAFE_NAME.match(name) or _BAD_CHARS.search(name):
        raise ValueError(f"Dial name contains disallowed characters: {name!r}")


# ---- PIN rate limiting (per-IP) ---------------------------------------------
# PIN is stored in plaintext in the 0600 settings file — adequate for a home
# LAN appliance. Rate limiting prevents casual brute-force from the browser.

_PIN_MAX_ATTEMPTS = 5
_PIN_BACKOFF_BASE = 5       # seconds
_PIN_BACKOFF_MAX  = 300     # seconds
_pin_attempts: dict[str, tuple[int, float]] = {}
_pin_lock = threading.Lock()


def _pin_check_rate_limit(ip: str) -> tuple[bool, int]:
    with _pin_lock:
        fails, blocked_until = _pin_attempts.get(ip, (0, 0.0))
        if blocked_until and blocked_until > time.time():
            return True, int(blocked_until - time.time()) + 1
        return False, 0


def _pin_record_failure(ip: str) -> None:
    with _pin_lock:
        fails, _ = _pin_attempts.get(ip, (0, 0.0))
        fails += 1
        blocked_until = 0.0
        if fails >= _PIN_MAX_ATTEMPTS:
            exp = min(fails - _PIN_MAX_ATTEMPTS, 6)
            delay = min(_PIN_BACKOFF_BASE * (2 ** exp), _PIN_BACKOFF_MAX)
            blocked_until = time.time() + delay
        _pin_attempts[ip] = (fails, blocked_until)


def _pin_clear_attempts(ip: str) -> None:
    with _pin_lock:
        _pin_attempts.pop(ip, None)


# ---- appliance pushes: routes, appliance id and rate limiting ---------------

# The routes an appliance pushes a change to, and the display-provider method
# each one hands the appliance id to. Both share one body check, one source
# check and one rate limiter.
_PUSH_ROUTES = {
    '/auth-changed':     'notify_auth_changed',
    '/warnings-changed': 'notify_warnings_changed',
}

_APPLIANCE_ID_RE = re.compile(r'^[0-9a-f]{20}$')

# Per source IP, at most one accepted push every _PUSH_IP_INTERVAL_S; per
# appliance_id, at most one every _PUSH_ID_INTERVAL_S. A refused push is
# still answered 202 and simply never enqueued — the response must not leak
# whether the id is known, rostered, or rate-limited.
_PUSH_IP_INTERVAL_S = 2.0
_PUSH_ID_INTERVAL_S = 5.0
_PUSH_ENTRY_MAX_AGE_S = 60.0


class _PushLimiter:
    """Pure rate limiter for the appliance push routes, with its own leaf lock."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_ip: dict[str, float] = {}
        self._by_id: dict[str, float] = {}

    def allow(self, ip: str, appliance_id: str, now: float) -> bool:
        with self._lock:
            self._prune_locked(now)
            last_ip = self._by_ip.get(ip)
            last_id = self._by_id.get(appliance_id)
            if last_ip is not None and now - last_ip < _PUSH_IP_INTERVAL_S:
                return False
            if last_id is not None and now - last_id < _PUSH_ID_INTERVAL_S:
                return False
            self._by_ip[ip] = now
            self._by_id[appliance_id] = now
            return True

    def _prune_locked(self, now: float) -> None:
        # Entries older than the longer of the two intervals are stale by
        # construction; a fixed ceiling keeps both dicts bounded regardless
        # of how many distinct IPs/ids are ever seen.
        for d in (self._by_ip, self._by_id):
            stale = [k for k, t in d.items() if now - t > _PUSH_ENTRY_MAX_AGE_S]
            for k in stale:
                del d[k]


# ---- Update state -----------------------------------------------------------

def _read_update_state() -> str:
    env = _read_env_file(_UPDATE_RESULT_PATH)
    status = env.get('STATUS', '').lower()
    return {'success': 'complete', 'failure': 'failed', 'in_progress': 'running'}.get(
        status, 'idle'
    )


def _read_update_fields() -> dict:
    """Progress fields of the update result file, for GET /update/status.

    Every field is optional in the file (older result files lack the phase
    and attempt keys), so each falls back to a neutral value.
    """
    env = _read_env_file(_UPDATE_RESULT_PATH)

    def _int(key: str, high: int) -> int:
        try:
            return max(0, min(high, int(env.get(key) or '0')))
        except ValueError:
            return 0

    return {
        'percent':      _int('PERCENT_COMPLETE', 100),
        'message':      env.get('MESSAGE', ''),
        'phase':        env.get('PHASE', ''),
        'tag':          env.get('TAG', ''),
        'previous_tag': env.get('PREVIOUS_TAG', ''),
        'attempt':      _int('ATTEMPT', 99),
        'max_attempts': _int('MAX_ATTEMPTS', 99),
        'rolled_back':  env.get('ROLLED_BACK', '0') == '1',
        'last_run_at':  env.get('LAST_RUN_AT', ''),
    }


# ---- Self-announcement ------------------------------------------------------

def _announce_self(cfg) -> None:
    """Write/update the avahi service file for this dial via admin verb."""
    args = ["sudo", ADMIN_CMD, "update-dial-service",
            VERSION, cfg.uuid, cfg.name or cfg.uuid]
    try:
        subprocess.run(args, timeout=5, check=False)
    except Exception as e:
        logging.warning("_announce_self failed: %s — will retry at next configure", e)


# ---- Recovery window --------------------------------------------------------

class RecoveryWindow:
    """10-minute PIN recovery window opened at startup when a PIN is set.

    State machine:
      open()          → _active=True,  _volume_confirmed=False, starts timer
      confirm_volume()→ _volume_confirmed=True (only while active)
      _expire()       → timer fires: _active=False, announce without pin_recovery
      complete()      → PIN replaced: cancel timer, _active=False, announce
    """

    _WINDOW_S = 600

    def __init__(self, on_announce: Callable[[bool], None]) -> None:
        self._on_announce      = on_announce
        self._lock             = threading.Lock()
        self._active           = False
        self._volume_confirmed = False
        self._opened_monotonic: float | None = None
        self._timer: threading.Timer | None = None

    def open(self) -> None:
        with self._lock:
            self._volume_confirmed = False
            self._active = True
            self._opened_monotonic = time.monotonic()
            timer = threading.Timer(self._WINDOW_S, self._expire)
            timer.daemon = True
            self._timer = timer
        timer.start()
        self._on_announce(True)   # outside lock — slow subprocess
        logging.info("PIN recovery window opened (10 min)")

    def _expire(self) -> None:
        with self._lock:
            self._active = False
        self._on_announce(False)  # outside lock
        logging.info("PIN recovery window expired")

    def complete(self) -> None:
        with self._lock:
            timer = self._timer
            self._timer = None
            self._active = False
        if timer:
            timer.cancel()
        self._on_announce(False)  # outside lock
        logging.info("PIN recovery: PIN updated")

    def confirm_volume(self) -> None:
        with self._lock:
            if not (self._active and not self._volume_confirmed):
                return
            self._volume_confirmed = True
        logging.info("PIN recovery: volume confirmed")

    def snapshot(self) -> dict:
        """Return a thread-safe copy of current recovery window state,
        including recovery_remaining_ms — milliseconds left in the 10-minute
        window, clamped at 0 (0 whenever the window is not active)."""
        with self._lock:
            remaining_ms = 0
            if self._active and self._opened_monotonic is not None:
                elapsed_ms = int((time.monotonic() - self._opened_monotonic) * 1000)
                remaining_ms = max(0, self._WINDOW_S * 1000 - elapsed_ms)
            return {
                "active": self._active,
                "volume_confirmed": self._volume_confirmed,
                "recovery_remaining_ms": remaining_ms,
            }


# ---- Display status provider (fallback when no display manager is wired) ----

class NoOpDisplayStatusProvider:
    """Screen-settings runtime status provider used when no real display
    manager was supplied — the server still answers /screen/settings so a
    display-disabled dial behaves consistently. Tracks only the fitted flag it
    is told about; every other runtime field stays at its no-op default.
    """

    def __init__(self) -> None:
        self._fitted = False

    def get_status(self) -> dict:
        return {
            "fitted":         self._fitted,
            "rotate":         False,
            "screen_type":    DEFAULT_PROFILE_KEY,
            "bgr":            False,
            "touch_type":     "",
            "always_show_controls": False,
            "active":         False,
            "backend":        "noop",
            "backend_loaded": False,
            "showing":        "noop",
            "last_error":     "",
            "last_error_at":  None,
            "display_sleeping":     False,
            "display_idle_seconds": 0,
        }

    def update_config(self, config) -> dict:
        self._fitted = bool(config.fitted)
        return self.get_status()

    def latest_frame_png(self):
        return None

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass


# ---- HTTP server ------------------------------------------------------------

class DialHTTPServer:
    # Callables run with the new config after every update_cfg swap; replaced,
    # never mutated, so a server built without __init__ still has the default.
    _cfg_listeners: tuple = ()
    _apply_lock = threading.Lock()   # serialises apply_screen_settings

    def __init__(self, cfg, display_status_provider=None, get_rostered_ips=None) -> None:
        self._cfg             = cfg
        self._cfg_lock        = threading.Lock()
        self._recovery_window = RecoveryWindow(self._on_announce)
        # Set by dial_main.py after inputs are actually constructed — reports
        # what is RUNNING (encoder/button/touch actually built and started),
        # not merely what cfg says is configured. Defaults False so an early
        # /configure or /recovery_status poll (before construction finishes)
        # never overclaims presence-confirmation capability.
        self._can_confirm_presence = False
        self._touch_source = None
        self._touch_runtime = ''
        self._touch_restart_lock = threading.Lock()
        self._last_touch_restart_monotonic: float | None = None
        self._display_status  = display_status_provider or NoOpDisplayStatusProvider()
        self._display_status.update_config(cfg.display)
        self._push_limiter = _PushLimiter()
        # Zero-arg callable returning {appliance_id: ip} for every appliance
        # currently sighted, playing or idle — dial_main wires the real
        # mDNS-backed one; tests pass a dict-returning lambda. None (a
        # display-less/bare test server) behaves as "nothing rostered".
        self._get_rostered_ips = get_rostered_ips
        # The SD card health probe runs on its own short-lived thread (the
        # guarded wrapper can take 90 s and the appliance proxy waits 4 s),
        # so a POST only starts it and GET reports on it. One at a time.
        self._sdmon_lock = threading.Lock()
        self._sdmon_probe: dict = {"running": False, "outcome": None, "reason": "", "finished_at": None}
        self._server          = http.server.HTTPServer(
            ('', cfg.port), self._make_handler()
        )

    def start(self) -> None:
        threading.Thread(
            target=self._server.serve_forever,
            daemon=True, name='dial-http',
        ).start()
        logging.info("HTTP server listening on port %d", self._cfg.port)

    @property
    def step_percent(self) -> int:
        with self._cfg_lock:
            return self._cfg.step_percent

    @property
    def effective_volume_scope(self) -> str:
        with self._cfg_lock:
            return effective_scope(self._cfg.display, self._cfg.display.volume_scope)

    @property
    def effective_mute_scope(self) -> str:
        with self._cfg_lock:
            return effective_scope(self._cfg.display, self._cfg.display.mute_scope)

    @property
    def display_config(self):
        with self._cfg_lock:
            return self._cfg.display

    @property
    def current_pin(self) -> str:
        """The management PIN now in force ('' when none is set). Read by the
        HD development listener's login, never sent anywhere."""
        with self._cfg_lock:
            return self._cfg.pin

    def add_cfg_listener(self, callback) -> None:
        """Register *callback*(new_cfg), run after every update_cfg swap."""
        self._cfg_listeners = (*self._cfg_listeners, callback)

    def update_cfg(self, cfg) -> None:
        """Replace live config after save_config() succeeds in POST /configure.

        Listeners run after the swap, outside the config lock, and a raising
        listener never reaches the caller or stops the others."""
        with self._cfg_lock:
            self._cfg = cfg
        for callback in list(self._cfg_listeners):
            try:
                callback(cfg)
            except Exception as e:
                logging.warning("config listener raised: %s", e)

    def screen_report(self, display=None) -> dict:
        """The `screen` object the screen-settings replies carry: *display*
        (a DialDisplayConfig), or the current one when omitted."""
        if display is None:
            display = self.display_config
        return {
            'fitted':      display.fitted,
            'rotate':      display.rotate,
            'screen_type': display.screen_type,
            'bgr':         display.bgr,
            'touch_type':  display.touch_type,
            'always_show_controls': display.always_show_controls,
            'screen_size_inches': display.screen_size_inches,
            'layout_size': display.layout_size,
            'volume_scope': display.volume_scope,
            'mute_scope': display.mute_scope,
            'poll_interval_s': display.poll_interval_s,
            'sleep_after_s': display.sleep_after_s,
            'brightness': display.brightness,
            'panel_power_off': display.panel_power_off,
            'surface': _profile_for(display).surface,
        }

    def apply_screen_settings(self, screen) -> tuple[int, dict]:
        """Validate, apply, persist and report a `screen` settings object, as
        the management route and the HD page's settings route both do. The
        caller has already authorised the request. Returns (status, body);
        a body with 'restarting' set means the caller must call
        fire_touch_restart() once the reply has been sent. One apply at a
        time, so two servers cannot interleave a read-modify-write."""
        with self._apply_lock:
            return self._apply_screen_settings_locked(screen)

    def _apply_screen_settings_locked(self, screen) -> tuple[int, dict]:
        with self._cfg_lock:
            cfg = self._cfg
        if isinstance(screen, dict):
            # The appliance's screen form never sends these keys, so a
            # save from it keeps the configured values rather than
            # resetting them to the defaults.
            for key in ('poll_interval_s', 'sleep_after_s', 'brightness', 'panel_power_off'):
                if key not in screen:
                    screen = {**screen, key: getattr(cfg.display, key)}
            # surface is reported from the profile, never set: drop it
            # so a GET object posted back with one field changed is
            # accepted.
            screen = {k: v for k, v in screen.items() if k != 'surface'}
        try:
            new_display = validate_screen_settings(screen)
        except InvalidScreenSettings:
            return 400, {'ok': False, 'error': 'invalid_screen_settings'}

        new_cfg = copy.copy(cfg)
        new_cfg.display = new_display

        # Apply-then-persist — reverses the usual save-first ordering
        # used by /configure. Several screen_type profiles are
        # untested on hardware; saving before confirming the backend
        # actually opens would persist a broken choice and the dial
        # would boot into a no-op display every restart. fitted/
        # rotate/bgr can never fail to apply, so this reordering has
        # no observable effect on them — only a bad screen_type can
        # trip the failure path below.
        touch_type_changed = (
            new_display.touch_type != cfg.display.touch_type
        )
        runtime = self._display_status.update_config(new_cfg.display)
        # Rotate is applied to the frame in software; the touch sheet
        # has to turn with it or every press lands diagonally
        # opposite the button being looked at. Best-effort: a touch
        # remap must never fail a settings save.
        if self._touch_source is not None:
            try:
                self._touch_source.display_config_changed(
                    new_display.rotate, layout=layout_context_for(new_display),
                )
            except Exception as e:
                logging.warning("dial touch: remap failed (%s)", e)
        # A failed live apply while fitted is requested surfaces as
        # last_error == "backend_open_failed" (set by DialDisplay's
        # degrade-to-noop path — see dial_display.py _enable_locked);
        # a successful enable always clears last_error, and disabling
        # the display can never fail, so gating on fitted here avoids
        # ever misreading a stale unrelated error as an apply failure.
        #
        # Only a screen_type change withholds persistence: that is the
        # setting that can leave the dial opening a broken profile on
        # every boot. fitted/rotate/bgr keep their previous
        # save-regardless behaviour, so they stay changeable even on a
        # dial whose panel is absent or faulty (where every open fails).
        #
        # The comparison is against the PERSISTED profile, not the
        # active one. Comparing against active would mean that on a
        # dial whose panel cannot open at all (none fitted, faulty
        # wiring) nothing ever matches, so every setting would be
        # rejected and the display would become unconfigurable.
        #
        # Known limitation: a screen_type accepted while fitted is
        # false cannot be opened, so it is persisted unvalidated; if
        # the later enable fails on it, that enable counts as "no
        # change" here and is persisted. The web UI cannot reach this
        # (its selector is disabled unless fitted is checked), and the
        # drift is visible — runtime.screen_type reports no active
        # profile while the configured one names it.
        apply_failed = (
            new_display.fitted
            and new_display.screen_type != cfg.display.screen_type
            and runtime.get('last_error') == 'backend_open_failed'
        )
        if apply_failed:
            logging.warning(
                "screen settings apply failed (screen_type=%s) — on-disk config left unchanged",
                new_display.screen_type,
            )
            runtime['touch_type'] = self._touch_runtime
            return 200, {
                'ok':      False,
                'error':   'screen_apply_failed',
                'screen':  self.screen_report(cfg.display),
                'layout_sizes': layout_size_options(_profile_for(cfg.display)),
                'layout': _layout_report_for(cfg.display),
                'scope': _scope_report_for(cfg.display),
                'runtime': runtime,
            }

        from dial_config import save_config
        try:
            save_config(new_cfg)
        except Exception as e:
            logging.warning("save_config failed: %s", e)
            return 500, {'ok': False, 'error': 'save_failed'}

        self.update_cfg(new_cfg)

        logging.info(
            "screen settings updated: fitted=%s rotate=%s screen_type=%s bgr=%s "
            "touch_type=%s always_show_controls=%s screen_size_inches=%s layout_size=%s "
            "poll_interval_s=%s sleep_after_s=%s brightness=%s panel_power_off=%s",
            new_display.fitted, new_display.rotate, new_display.screen_type,
            new_display.bgr, new_display.touch_type, new_display.always_show_controls,
            new_display.screen_size_inches, new_display.layout_size,
            new_display.poll_interval_s, new_display.sleep_after_s,
            new_display.brightness, new_display.panel_power_off,
        )
        runtime['touch_type'] = self._touch_runtime
        # fitted/rotate/bgr/screen_type all apply live. touch_type
        # does not: the touch stack is constructed once at startup
        # from the persisted controller, so a change to it only
        # takes effect on the next service start. Say so rather
        # than reporting a live apply that did not happen — and,
        # if the change is real and the cooldown allows it, restart
        # the service ourselves so it does not sit stale.
        #
        # The cooldown gate is decided here so the outcome can be
        # reflected in the response, but the restart is only
        # actually FIRED once the caller has sent the reply (the
        # response carries 'restarting') — see
        # DialHTTPServer.fire_touch_restart.
        restarting = touch_type_changed and self._touch_restart_allowed()
        response = {
            'ok':               True,
            'screen':           self.screen_report(new_cfg.display),
            'layout_sizes':     layout_size_options(_profile_for(new_cfg.display)),
            'layout':           _layout_report_for(new_cfg.display),
            'scope':            _scope_report_for(new_cfg.display),
            'runtime':          runtime,
            'restart_required': touch_type_changed,
        }
        if restarting:
            response['restarting'] = True
        return 200, response

    def begin_recovery_window(self) -> None:
        self._recovery_window.open()

    def confirm_volume(self) -> None:
        self._recovery_window.confirm_volume()

    def set_touch_source(self, touch_source) -> None:
        """Register the running touch session, if any, so a live screen
        settings change can remap the touch axes to match the frame. None on
        a dial with no touch panel. Called once at startup."""
        self._touch_source = touch_source

    def set_can_confirm_presence(self, value: bool) -> None:
        """Record whether this dial actually has at least one working
        confirmable input running right now (encoder, button, or touch —
        see dial_main.py's construction of each). Called once at startup
        after construction finishes; reflects runtime reality, not config."""
        self._can_confirm_presence = bool(value)

    def set_touch_runtime(self, value: str) -> None:
        """Record what the touch stack actually did at startup, distinct
        from cfg.display.touch_type: the running controller key (e.g.
        "xpt2046") when touch was constructed and started, "none" when
        touch was deliberately not built (disabled by config or no
        screen fitted), or "failed" when construction was attempted and
        raised. Called once at startup after touch construction finishes.
        This is what makes GET /screen/settings' runtime.touch_type a real
        signal instead of the persisted config echoed back early."""
        self._touch_runtime = value

    def _rostered_ips(self) -> dict:
        """appliance_id -> ip for every currently sighted appliance.

        Wraps the injected get_rostered_ips callable so a broken or absent
        browser can never turn a push into a 500 — a raising or unset
        callable degrades to "nothing rostered", which just means the push
        is not enqueued.
        """
        if self._get_rostered_ips is None:
            return {}
        try:
            return self._get_rostered_ips()
        except Exception as e:
            logging.debug("appliance push: get_rostered_ips raised: %s", e)
            return {}

    def _touch_restart_allowed(self) -> bool:
        """Rate-gate a touch-type restart trigger: refuses more than one
        per _TOUCH_RESTART_COOLDOWN_SECONDS. Reserves the slot immediately
        (before the caller actually fires the restart) so two requests
        racing each other cannot both pass. Call this BEFORE the HTTP
        response is sent, so the decision can be reflected in the response
        body — only the actual subprocess launch (fire_touch_restart) has
        to wait until after the response is flushed."""
        now = time.monotonic()
        with self._touch_restart_lock:
            last = self._last_touch_restart_monotonic
            if last is not None and (now - last) < _TOUCH_RESTART_COOLDOWN_SECONDS:
                logging.warning(
                    "dial touch: restart refused — cooldown active (%.1fs remaining)",
                    _TOUCH_RESTART_COOLDOWN_SECONDS - (now - last),
                )
                return False
            self._last_touch_restart_monotonic = now
            return True

    def fire_touch_restart(self) -> None:
        """Launch the self-restart, fire-and-forget. Must only be called
        AFTER the HTTP response has been sent: _send_json writes
        synchronously to wfile on the handler thread, and the server is
        the stdlib blocking HTTPServer, so triggering first risks the
        process being torn down mid-write. Uses Popen (never waited on) so
        the handler thread never blocks; sudo -n fails fast rather than
        hanging if sudo is ever misconfigured, instead of the bare `sudo`
        this module's other call sites use. A failed trigger must not fail
        the settings save — the config is already persisted by the time
        this runs — so any error here is logged and swallowed."""
        try:
            subprocess.Popen(["sudo", "-n", ADMIN_CMD, "restart-dial-service"])
            logging.info("dial touch: restart triggered (touch_type changed)")
        except Exception as e:
            logging.warning("dial touch: restart trigger failed: %s", e)

    def sdmon_probe_snapshot(self) -> dict:
        with self._sdmon_lock:
            return dict(self._sdmon_probe)

    def start_sdmon_change(self, enabled: bool, method: str) -> bool:
        """Start the enable (probe, then enable) or disable run on a daemon
        thread. Returns False without starting when one is already running."""
        with self._sdmon_lock:
            if self._sdmon_probe["running"]:
                return False
            self._sdmon_probe = {"running": True, "outcome": None, "reason": "", "finished_at": None}
        threading.Thread(
            target=self._sdmon_change_thread, args=(enabled, method),
            daemon=True, name="dial-sdmon-probe",
        ).start()
        return True

    def _sdmon_change_thread(self, enabled: bool, method: str) -> None:
        """Enable: the wrapper's check verb first (it never enables), then
        its enable verb only on a pass. Disable: the disable verb. Either
        way the persisted intent follows the outcome, and the on-screen
        reader is refreshed so a fresh reading shows without waiting for
        its next scheduled read."""
        outcome, reason = "passed", ""
        try:
            if enabled:
                ok, code, payload = sdcard_health_check(method)
                if not ok:
                    outcome = {3: "unsupported", 4: "hung", 2: "tool_missing"}.get(code, "check_failed")
                    reason = str(payload.get("reason") or payload.get("output") or "")[:200]
                else:
                    ok, code, payload = sdcard_health_enable(method)
                    if not ok:
                        outcome, reason = "enable_failed", str(payload.get("output") or "")[:200]
            else:
                ok, code, payload = sdcard_health_disable()
                if not ok:
                    outcome, reason = "disable_failed", str(payload.get("output") or "")[:200]
            if outcome == "passed":
                self._persist_sd_health_intent(enabled)
        except Exception as e:
            outcome, reason = "check_failed", str(e)[:200]
        finally:
            with self._sdmon_lock:
                self._sdmon_probe = {
                    "running": False, "outcome": outcome, "reason": reason,
                    "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
            try:
                import dial_sdhealth
                dial_sdhealth.refresh_now()
            except Exception:
                pass

    def _persist_sd_health_intent(self, enabled: bool) -> None:
        from dial_config import save_config
        with self._cfg_lock:
            cfg = self._cfg
        if cfg.sd_health_monitoring == enabled:
            return
        new_cfg = copy.copy(cfg)
        new_cfg.sd_health_monitoring = enabled
        try:
            save_config(new_cfg)
        except Exception as e:
            logging.warning("sd health: save_config failed: %s", e)
            return
        self.update_cfg(new_cfg)

    def get_runtime_status(self) -> dict:
        """Return a fresh snapshot of runtime state without exposing secrets.

        Returns a dict with keys: uuid, name, step_percent, recovery_active,
        volume_confirmed.  Safe to call from any thread.
        """
        with self._cfg_lock:
            cfg = self._cfg
        snap = self._recovery_window.snapshot()
        return {
            "uuid": cfg.uuid,
            "name": cfg.name,
            "step_percent": cfg.step_percent,
            "recovery_active": snap["active"],
            "volume_confirmed": snap["volume_confirmed"],
        }

    def _on_announce(self, add: bool) -> None:
        with self._cfg_lock:
            cfg = self._cfg
        args = ["sudo", ADMIN_CMD, "update-dial-service",
                VERSION, cfg.uuid, cfg.name or cfg.uuid]
        if add:
            args.append("--pin-recovery")
        try:
            subprocess.run(args, timeout=5, check=False)
        except Exception as e:
            logging.warning("update-dial-service failed: %s", e)

    def _make_handler(self) -> type:
        dial_server = self

        class _Handler(http.server.BaseHTTPRequestHandler):

            def _send_json(self, status: int, data: dict) -> None:
                body = json.dumps(data).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _send_bytes(self, status: int, content_type: str, body: bytes) -> None:
                self.send_response(status)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(body)

            def _send_429(self, wait_secs: int) -> None:
                body = json.dumps({'ok': False, 'error': 'too_many_attempts'}).encode()
                self.send_response(429)
                self.send_header('Retry-After', str(wait_secs))
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _read_body(self) -> bytes | None:
                try:
                    content_length = int(self.headers.get('Content-Length', 0))
                except (ValueError, TypeError):
                    self.send_error(400)
                    return None
                if not (0 <= content_length <= MAX_BODY):
                    self.send_error(413)
                    return None
                return self.rfile.read(content_length)

            def do_GET(self) -> None:
                if self.path == '/configure':
                    with dial_server._cfg_lock:
                        cfg = dial_server._cfg
                    self._send_json(200, {
                        'step_percent':         cfg.step_percent,
                        'pin_set':              bool(cfg.pin),
                        'name':                 cfg.name,
                        'version':              VERSION,
                        'auto_update':          cfg.auto_update,
                        'update_channel':       cfg.update_channel,
                        'can_confirm_presence': dial_server._can_confirm_presence,
                        'hd_dev_access':        cfg.hd_dev_access,
                    })

                elif self.path == '/recovery_status':
                    snap = dial_server._recovery_window.snapshot()
                    if not snap['active']:
                        self._send_json(404, {
                            'active':               False,
                            'can_confirm_presence': dial_server._can_confirm_presence,
                        })
                    else:
                        self._send_json(200, {
                            'active':                 True,
                            'volume_confirmed':       snap['volume_confirmed'],
                            'recovery_remaining_ms':  snap['recovery_remaining_ms'],
                            'can_confirm_presence':   dial_server._can_confirm_presence,
                        })

                elif self.path == '/update/status':
                    body = {
                        'state':   _read_update_state(),
                        'version': VERSION,
                    }
                    body.update(_read_update_fields())
                    self._send_json(200, body)

                elif self.path == '/update/check':
                    self._handle_update_check()

                elif self.path == '/screen/settings':
                    with dial_server._cfg_lock:
                        cfg = dial_server._cfg
                    runtime = dial_server._display_status.get_status()
                    runtime['touch_type'] = dial_server._touch_runtime
                    self._send_json(200, {
                        'ok':             True,
                        'screen':         dial_server.screen_report(cfg.display),
                        'supported':      list_profiles(),
                        'supported_touch': list_controllers(),
                        'layout_sizes':   layout_size_options(_profile_for(cfg.display)),
                        'layout':         _layout_report_for(cfg.display),
                        'scope':          _scope_report_for(cfg.display),
                        'runtime':        runtime,
                    })

                elif self.path == '/screen/image':
                    frame_png = None
                    getter = getattr(dial_server._display_status, 'latest_frame_png', None)
                    if getter is not None:
                        try:
                            frame_png = getter()
                        except Exception as e:
                            logging.debug("screen image: frame accessor raised: %s", e)
                    if frame_png is None:
                        self._send_json(404, {'ok': False, 'error': 'no_frame'})
                    else:
                        self._send_bytes(200, 'image/png', frame_png)

                elif self.path == '/sdcard-health':
                    with dial_server._cfg_lock:
                        cfg = dial_server._cfg
                    try:
                        state = sdcard_health_state()
                    except Exception as e:
                        logging.debug("sd health: state read raised: %s", e)
                        state = {}
                    self._send_json(200, {
                        'ok': True,
                        'state': state,
                        'requested': cfg.sd_health_monitoring,
                        'probe': dial_server.sdmon_probe_snapshot(),
                    })

                else:
                    self.send_error(404)

            def do_POST(self) -> None:
                if self.path == '/configure':
                    self._handle_configure()
                elif self.path == '/update':
                    self._handle_update()
                elif self.path == '/screen/settings':
                    self._handle_screen_settings()
                elif self.path == '/sdcard-health':
                    self._handle_sdcard_health()
                elif self.path == '/recovery/arm':
                    self._handle_recovery_arm()
                elif self.path == '/recovery/disarm':
                    self._handle_recovery_disarm()
                elif self.path in _PUSH_ROUTES:
                    self._handle_appliance_push(_PUSH_ROUTES[self.path])
                else:
                    self.send_error(404)

            # These two endpoints deliberately do NOT run the PIN check that
            # /configure and /screen/settings apply (compare _handle_configure
            # and _handle_screen_settings above). Recovery exists to let an
            # admin who has forgotten the PIN get it back — requiring the PIN
            # to reach the endpoint that recovers it would be circular. What
            # stands in for authentication here is that only the appliance's
            # authenticated web UI is expected to call these (it proxies the
            # request after checking its own login), and completing recovery
            # still requires physical presence at the dial afterwards. See
            # dial_main.py for the startup rule that turns a written request
            # into an actually-armed recovery window.
            def _handle_recovery_arm(self) -> None:
                try:
                    PIN_RESET_PATH.touch(exist_ok=True)
                except OSError as e:
                    logging.warning(
                        "recovery arm: could not write %s: %s", PIN_RESET_PATH, e
                    )
                self._send_json(200, {'ok': True})

            def _handle_recovery_disarm(self) -> None:
                try:
                    PIN_RESET_PATH.unlink(missing_ok=True)
                except OSError as e:
                    logging.warning(
                        "recovery disarm: could not remove %s: %s", PIN_RESET_PATH, e
                    )
                self._send_json(200, {'ok': True})

            def _handle_appliance_push(self, notify_name: str) -> None:
                """Advisory notification from an appliance that something
                about appliance_id changed (its authorization, or its
                warnings). Never authenticated (anyone on the LAN can reach
                port 7842), so this grants nothing by itself — it only causes
                a fetch or probe if the source IP matches a currently sighted
                address of that id, and even then only hands the id to the
                display provider's *notify_name*, which queues it; it never
                fetches inline here on the single-threaded server.
                """
                body = self._read_body()
                if body is None:
                    return
                try:
                    obj = json.loads(body)
                except (ValueError, TypeError):
                    self._send_json(400, {'ok': False, 'error': 'invalid_json'})
                    return
                if not isinstance(obj, dict):
                    self._send_json(400, {'ok': False, 'error': 'body_must_be_object'})
                    return
                appliance_id = obj.get('appliance_id')
                if not isinstance(appliance_id, str) or not _APPLIANCE_ID_RE.fullmatch(appliance_id):
                    self._send_json(400, {'ok': False, 'error': 'invalid_appliance_id'})
                    return

                # Always 202 from here: the push is advisory and grants
                # nothing, and the response must never leak whether the id is
                # known, rostered, or rate-limited.
                self._send_json(202, {'ok': True})

                ip = self.client_address[0]
                if not dial_server._push_limiter.allow(ip, appliance_id, time.monotonic()):
                    return
                rostered = dial_server._rostered_ips()
                if rostered.get(appliance_id) != ip:
                    logging.debug(
                        "%s: %s from %s does not match a sighting",
                        self.path, appliance_id, ip,
                    )
                    return
                notify = getattr(dial_server._display_status, notify_name, None)
                if notify is not None:
                    try:
                        notify(appliance_id)
                    except Exception as e:
                        logging.debug("%s: enqueue failed: %s", self.path, e)

            def _handle_configure(self) -> None:
                body = self._read_body()
                if body is None:
                    return
                try:
                    obj = json.loads(body)
                except (ValueError, TypeError):
                    self._send_json(400, {'ok': False, 'error': 'invalid_json'})
                    return
                if not isinstance(obj, dict):
                    self._send_json(400, {'ok': False, 'error': 'body_must_be_object'})
                    return

                ip = self.client_address[0]

                # ---- Field validation ----
                with dial_server._cfg_lock:
                    cfg = dial_server._cfg
                new_cfg = copy.copy(cfg)

                changing_protected = any(k in obj for k in ('name', 'step_percent', 'new_pin', 'auto_update', 'update_channel', 'hd_dev_access'))

                # PIN auth
                if cfg.pin and changing_protected:
                    if obj.get('pin_recovery') is True:
                        # Recovery requires a new_pin to replace the forgotten one
                        p = obj.get('new_pin', '')
                        if not isinstance(p, str) or not re.fullmatch(r'\d{4,8}', p):
                            self._send_json(400, {'ok': False, 'error': 'new_pin_required_for_recovery'})
                            return
                        snap = dial_server._recovery_window.snapshot()
                        if not snap['active'] or not snap['volume_confirmed']:
                            self._send_json(403, {'ok': False, 'error': 'recovery_not_confirmed'})
                            return
                    else:
                        blocked, wait_secs = _pin_check_rate_limit(ip)
                        if blocked:
                            self._send_429(wait_secs)
                            return
                        current_pin = obj.get('current_pin', '')
                        if not isinstance(current_pin, str) or current_pin != cfg.pin:
                            _pin_record_failure(ip)
                            # Return 429 immediately if this failure hit the threshold
                            blocked, wait_secs = _pin_check_rate_limit(ip)
                            if blocked:
                                self._send_429(wait_secs)
                            else:
                                self._send_json(403, {'ok': False, 'error': 'wrong_pin'})
                            return
                        _pin_clear_attempts(ip)

                if 'name' in obj:
                    v = obj['name']
                    if not isinstance(v, str) or len(v) > 64:
                        self._send_json(400, {'ok': False, 'error': 'invalid_name'})
                        return
                    try:
                        _validate_dial_name(v)
                    except ValueError:
                        self._send_json(400, {'ok': False, 'error': 'invalid_name_chars'})
                        return
                    new_cfg.name = v

                if 'step_percent' in obj:
                    v = obj['step_percent']
                    if not isinstance(v, int) or isinstance(v, bool) or not (1 <= v <= 10):
                        self._send_json(400, {'ok': False, 'error': 'invalid_step_percent'})
                        return
                    new_cfg.step_percent = v

                if 'auto_update' in obj:
                    v = obj['auto_update']
                    if not isinstance(v, bool):
                        self._send_json(400, {'ok': False, 'error': 'invalid_auto_update'})
                        return
                    new_cfg.auto_update = v

                if 'update_channel' in obj:
                    v = obj['update_channel']
                    if not isinstance(v, str):
                        self._send_json(400, {'ok': False, 'error': 'invalid_update_channel'})
                        return
                    v_norm = v.strip().lower()
                    if v_norm not in ('stable', 'dev'):
                        self._send_json(400, {'ok': False, 'error': 'invalid_update_channel'})
                        return
                    new_cfg.update_channel = v_norm

                if 'new_pin' in obj:
                    p = obj['new_pin']
                    if isinstance(p, str) and p:
                        if not re.fullmatch(r'\d{4,8}', p):
                            self._send_json(400, {'ok': False, 'error': 'invalid_new_pin'})
                            return
                        new_cfg.pin = p
                    elif isinstance(p, str) and p == '':
                        new_cfg.pin = ''
                    else:
                        self._send_json(400, {'ok': False, 'error': 'invalid_new_pin'})
                        return

                if 'hd_dev_access' in obj:
                    v = obj['hd_dev_access']
                    if not isinstance(v, bool):
                        self._send_json(400, {'ok': False, 'error': 'invalid_hd_dev_access'})
                        return
                    new_cfg.hd_dev_access = v
                # The development listener authenticates with the PIN, so it
                # cannot be switched on without one and does not outlive it.
                if new_cfg.hd_dev_access and not new_cfg.pin:
                    if 'hd_dev_access' in obj:
                        self._send_json(400, {'ok': False, 'error': 'pin_required'})
                        return
                    new_cfg.hd_dev_access = False

                # ---- Persist ----
                from dial_config import save_config
                try:
                    save_config(new_cfg)
                except Exception as e:
                    logging.warning("save_config failed: %s", e)
                    self._send_json(500, {'ok': False, 'error': 'save_failed'})
                    return

                dial_server.update_cfg(new_cfg)

                # ---- Side effects ----
                name_changed = 'name' in obj and obj['name'] != cfg.name
                pin_recovery = obj.get('pin_recovery') is True

                if name_changed:
                    dial_server._on_announce(False)

                if pin_recovery and cfg.pin:
                    dial_server._recovery_window.complete()

                if 'auto_update' in obj and new_cfg.auto_update != cfg.auto_update:
                    verb = "enable" if new_cfg.auto_update else "disable"
                    r = subprocess.run(
                        ["sudo", ADMIN_CMD, "toggle-dial-update-timer", verb],
                        timeout=5, capture_output=True,
                    )
                    if r.returncode != 0:
                        # Rollback saved value
                        rollback = copy.copy(new_cfg)
                        rollback.auto_update = cfg.auto_update
                        try:
                            save_config(rollback)
                            dial_server.update_cfg(rollback)
                        except Exception as rb_err:
                            logging.warning("auto_update rollback failed: %s", rb_err)
                        logging.warning("toggle-dial-update-timer %s failed (rc=%d)", verb, r.returncode)
                        self._send_json(200, {'ok': False, 'error': 'timer_command_failed'})
                        return

                logging.info(
                    "config updated: name=%r step=%d auto_update=%s update_channel=%s",
                    new_cfg.name, new_cfg.step_percent, new_cfg.auto_update, new_cfg.update_channel,
                )
                self._send_json(200, {'ok': True})

            def _handle_screen_settings(self) -> None:
                body = self._read_body()
                if body is None:
                    return
                try:
                    obj = json.loads(body)
                except (ValueError, TypeError):
                    self._send_json(400, {'ok': False, 'error': 'invalid_json'})
                    return
                if not isinstance(obj, dict):
                    self._send_json(400, {'ok': False, 'error': 'body_must_be_object'})
                    return

                ip = self.client_address[0]
                with dial_server._cfg_lock:
                    cfg = dial_server._cfg

                # PIN auth — screen settings follow POST /configure semantics.
                if cfg.pin:
                    blocked, wait_secs = _pin_check_rate_limit(ip)
                    if blocked:
                        self._send_429(wait_secs)
                        return
                    current_pin = obj.get('current_pin', '')
                    if not isinstance(current_pin, str) or current_pin != cfg.pin:
                        _pin_record_failure(ip)
                        blocked, wait_secs = _pin_check_rate_limit(ip)
                        if blocked:
                            self._send_429(wait_secs)
                        else:
                            self._send_json(403, {'ok': False, 'error': 'wrong_pin'})
                        return
                    _pin_clear_attempts(ip)

                status, response = dial_server.apply_screen_settings(obj.get('screen'))
                self._send_json(status, response)
                if response.get('restarting'):
                    dial_server.fire_touch_restart()

            def _handle_sdcard_health(self) -> None:
                body = self._read_body()
                if body is None:
                    return
                try:
                    obj = json.loads(body)
                except (ValueError, TypeError):
                    self._send_json(400, {'ok': False, 'error': 'invalid_json'})
                    return
                if not isinstance(obj, dict):
                    self._send_json(400, {'ok': False, 'error': 'body_must_be_object'})
                    return

                ip = self.client_address[0]
                with dial_server._cfg_lock:
                    cfg = dial_server._cfg

                # PIN auth: same rule as POST /screen/settings.
                if cfg.pin:
                    blocked, wait_secs = _pin_check_rate_limit(ip)
                    if blocked:
                        self._send_429(wait_secs)
                        return
                    current_pin = obj.get('current_pin', '')
                    if not isinstance(current_pin, str) or current_pin != cfg.pin:
                        _pin_record_failure(ip)
                        blocked, wait_secs = _pin_check_rate_limit(ip)
                        if blocked:
                            self._send_429(wait_secs)
                        else:
                            self._send_json(403, {'ok': False, 'error': 'wrong_pin'})
                        return
                    _pin_clear_attempts(ip)

                enabled = obj.get('enabled')
                if not isinstance(enabled, bool):
                    self._send_json(400, {'ok': False, 'error': 'invalid_enabled'})
                    return
                method = obj.get('method', 'auto')
                if not isinstance(method, str) or method not in SDCARD_HEALTH_METHODS:
                    self._send_json(400, {'ok': False, 'error': 'invalid_method'})
                    return

                if enabled:
                    try:
                        tool_present = bool(sdcard_health_state().get('tool_present'))
                    except Exception:
                        tool_present = False
                    if not tool_present:
                        self._send_json(200, {'ok': False, 'error': 'tool_missing'})
                        return

                if not dial_server.start_sdmon_change(enabled, method):
                    self._send_json(200, {'ok': False, 'error': 'probe_running'})
                    return
                logging.info("sd health: %s requested (method %s)", "enable" if enabled else "disable", method)
                self._send_json(200, {'ok': True, 'probe': dial_server.sdmon_probe_snapshot()})

            def _handle_update_check(self) -> None:
                try:
                    r = subprocess.run(
                        [_UPDATER_CMD, "check"],
                        capture_output=True, text=True, timeout=30,
                    )
                    result = json.loads(r.stdout) if r.returncode == 0 else {'ok': False, 'error': 'check_failed'}
                    self._send_json(200, result)
                except Exception as e:
                    logging.warning("update check failed: %s", e)
                    self._send_json(200, {'ok': False, 'error': 'check_failed'})

            def _handle_update(self) -> None:
                r = subprocess.run(
                    ["sudo", ADMIN_CMD, "run-updater"],
                    timeout=5, capture_output=True,
                )
                if r.returncode != 0:
                    self._send_json(200, {'ok': False, 'error': 'scheduler_failed'})
                else:
                    self._send_json(200, {'ok': True})

            def log_message(self, fmt, *args) -> None:
                logging.debug("HTTP %s", fmt % args)

        return _Handler
