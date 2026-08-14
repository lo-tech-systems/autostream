"""dial_http_server.py — Dial management API (port 7842).

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

This module is a management API used by the autostream appliance to configure
the dial (name, PIN, step size, auto-update).  It does not serve a browser-
facing setup UI; dial configuration is done through the appliance web interface.

Routes: GET /configure, POST /configure, GET /recovery_status,
GET /update/status, GET /update/check, POST /update.
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

from dial_config import InvalidScreenSettings, _read_env_file, validate_screen_settings
from dial_display_profiles import DEFAULT_PROFILE_KEY, list_profiles

ADMIN_CMD           = '/usr/local/libexec/autostream/autostream_admin'
_UPDATER_CMD        = '/usr/local/libexec/autostream/autostream_dial_updater'
_INSTALL_STATE_PATH = Path('/var/lib/autostream/install-state.env')
_UPDATE_RESULT_PATH = Path('/var/lib/autostream/update-result.env')

MAX_BODY = 4096  # bytes — rejects oversized bodies before JSON parsing

# ---- Version ----------------------------------------------------------------

def _load_version() -> str:
    env = _read_env_file(_INSTALL_STATE_PATH)
    return env.get('AUTOSTREAM_RELEASE_TAG', 'unknown') or 'unknown'


VERSION = _load_version()

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


# ---- Update state -----------------------------------------------------------

def _read_update_state() -> str:
    env = _read_env_file(_UPDATE_RESULT_PATH)
    status = env.get('STATUS', '').lower()
    return {'success': 'complete', 'failure': 'failed', 'in_progress': 'running'}.get(
        status, 'idle'
    )


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

    def __init__(self, on_announce: Callable[[bool], None]) -> None:
        self._on_announce      = on_announce
        self._lock             = threading.Lock()
        self._active           = False
        self._volume_confirmed = False
        self._timer: threading.Timer | None = None

    def open(self) -> None:
        with self._lock:
            self._volume_confirmed = False
            self._active = True
            timer = threading.Timer(600, self._expire)
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
        """Return a thread-safe copy of current recovery window state."""
        with self._lock:
            return {
                "active": self._active,
                "volume_confirmed": self._volume_confirmed,
            }


# ---- Display status provider (placeholder until the real display manager) --

class NoOpDisplayStatusProvider:
    """Default screen-settings runtime status provider used before WP-6/WP-8
    wire in the real DialDisplay manager. Tracks only the fitted flag it is
    told about; every other runtime field stays at its no-op default.
    """

    def __init__(self) -> None:
        self._fitted = False

    def get_status(self) -> dict:
        return {
            "fitted":         self._fitted,
            "rotate":         False,
            "screen_type":    DEFAULT_PROFILE_KEY,
            "bgr":            False,
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

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass


# ---- HTTP server ------------------------------------------------------------

class DialHTTPServer:
    def __init__(self, cfg, display_status_provider=None) -> None:
        self._cfg             = cfg
        self._cfg_lock        = threading.Lock()
        self._recovery_window = RecoveryWindow(self._on_announce)
        self._display_status  = display_status_provider or NoOpDisplayStatusProvider()
        self._display_status.update_config(cfg.display)
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

    def update_cfg(self, cfg) -> None:
        """Replace live config after save_config() succeeds in POST /configure."""
        with self._cfg_lock:
            self._cfg = cfg

    def begin_recovery_window(self) -> None:
        self._recovery_window.open()

    def confirm_volume(self) -> None:
        self._recovery_window.confirm_volume()

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
                        'step_percent':   cfg.step_percent,
                        'pin_set':        bool(cfg.pin),
                        'name':           cfg.name,
                        'version':        VERSION,
                        'auto_update':    cfg.auto_update,
                        'update_channel': cfg.update_channel,
                    })

                elif self.path == '/recovery_status':
                    snap = dial_server._recovery_window.snapshot()
                    if not snap['active']:
                        self._send_json(404, {'active': False})
                    else:
                        self._send_json(200, {
                            'active':           True,
                            'volume_confirmed': snap['volume_confirmed'],
                        })

                elif self.path == '/update/status':
                    self._send_json(200, {
                        'state':   _read_update_state(),
                        'version': VERSION,
                    })

                elif self.path == '/update/check':
                    self._handle_update_check()

                elif self.path == '/screen/settings':
                    with dial_server._cfg_lock:
                        cfg = dial_server._cfg
                    self._send_json(200, {
                        'ok':        True,
                        'screen':    {
                            'fitted':      cfg.display.fitted,
                            'rotate':      cfg.display.rotate,
                            'screen_type': cfg.display.screen_type,
                            'bgr':         cfg.display.bgr,
                        },
                        'supported': list_profiles(),
                        'runtime':   dial_server._display_status.get_status(),
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
                else:
                    self.send_error(404)

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

                changing_protected = any(k in obj for k in ('name', 'step_percent', 'new_pin', 'auto_update', 'update_channel'))

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

                try:
                    new_display = validate_screen_settings(obj.get('screen'))
                except InvalidScreenSettings:
                    self._send_json(400, {'ok': False, 'error': 'invalid_screen_settings'})
                    return

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
                runtime = dial_server._display_status.update_config(new_cfg.display)
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
                    self._send_json(200, {
                        'ok':      False,
                        'error':   'screen_apply_failed',
                        'screen':  {
                            'fitted':      cfg.display.fitted,
                            'rotate':      cfg.display.rotate,
                            'screen_type': cfg.display.screen_type,
                            'bgr':         cfg.display.bgr,
                        },
                        'runtime': runtime,
                    })
                    return

                from dial_config import save_config
                try:
                    save_config(new_cfg)
                except Exception as e:
                    logging.warning("save_config failed: %s", e)
                    self._send_json(500, {'ok': False, 'error': 'save_failed'})
                    return

                dial_server.update_cfg(new_cfg)

                logging.info(
                    "screen settings updated: fitted=%s rotate=%s screen_type=%s bgr=%s",
                    new_display.fitted, new_display.rotate, new_display.screen_type, new_display.bgr,
                )
                self._send_json(200, {
                    'ok':               True,
                    'screen':           {
                        'fitted':      new_cfg.display.fitted,
                        'rotate':      new_cfg.display.rotate,
                        'screen_type': new_cfg.display.screen_type,
                        'bgr':         new_cfg.display.bgr,
                    },
                    'runtime':          runtime,
                    'restart_required': False,
                })

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
