"""dial_http_server.py — Dial management API (port 7842).

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

This module is a management API used by the autostream appliance to configure
the dial (name, PIN, step size, auto-update).  It does not serve a browser-
facing setup UI; dial configuration is done through the appliance web interface.

Routes: GET /configure, POST /configure, GET /recovery_status,
GET /update/status, GET /update/check, POST /update,
POST /recovery/arm, POST /recovery/disarm,
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

from dial_config import PIN_RESET_PATH, effective_scope
from dial_update_watch import UPDATE_RESULT_PATH, UpdateView, read_update_result
from dial_recovery import RecoveryWindow
from dial_screen_settings import NoOpDisplayStatusProvider, ScreenSettingsService, screen_report
from dial_values import NotAnObject, NotJson, is_int, parse_json_object, read_env_file

import dial_admin
import dial_pin_guard
from dial_http_common import (
    MAX_BODY,
    TOO_MANY_ATTEMPTS,
    content_length,
    json_bytes,
)
from autostream_sysutils import (
    SDCARD_HEALTH_METHODS,
    sdcard_health_check,
    sdcard_health_disable,
    sdcard_health_enable,
    sdcard_health_state,
)

_UPDATER_CMD        = '/usr/local/libexec/autostream/autostream_dial_updater'
_INSTALL_STATE_PATH = Path('/var/lib/autostream/install-state.env')
_UPDATE_RESULT_PATH = Path(UPDATE_RESULT_PATH)

# ---- Version ----------------------------------------------------------------

def _load_version() -> str:
    env = read_env_file(_INSTALL_STATE_PATH)
    return env.get('AUTOSTREAM_RELEASE_TAG', 'unknown') or 'unknown'


VERSION = _load_version()

# ---- Name validation --------------------------------------------------------

_SAFE_NAME = re.compile(r'^[\x20-\x7e]*$')
_BAD_CHARS = re.compile(r'[;|]')


def _validate_dial_name(name: str) -> None:
    if not _SAFE_NAME.match(name) or _BAD_CHARS.search(name):
        raise ValueError(f"Dial name contains disallowed characters: {name!r}")


# ---- Update state -----------------------------------------------------------

def _read_update_state() -> str:
    view = read_update_result(_UPDATE_RESULT_PATH) or UpdateView()
    return {'success': 'complete', 'failure': 'failed', 'in_progress': 'running'}.get(
        view.status.lower(), 'idle'
    )


def _read_update_fields() -> dict:
    """Progress fields of the update result file, for GET /update/status.

    Every field is optional in the file (older result files lack the phase
    and attempt keys), so each falls back to a neutral value.
    """
    view = read_update_result(_UPDATE_RESULT_PATH) or UpdateView()
    return {
        'percent':      view.percent,
        'message':      view.message,
        'phase':        view.phase,
        'tag':          view.tag,
        'previous_tag': view.previous_tag,
        'attempt':      view.attempt,
        'max_attempts': view.max_attempts,
        'rolled_back':  view.rolled_back,
        'last_run_at':  view.last_run_at,
    }


# ---- Self-announcement ------------------------------------------------------

def _announce_self(cfg) -> None:
    """Write/update the avahi service file for this dial via admin verb."""
    dial_admin.announce(cfg, VERSION)


# ---- HTTP server ------------------------------------------------------------

class DialHTTPServer:
    # Callables run with the new config after every update_cfg swap; replaced,
    # never mutated, so a server built without __init__ still has the default.
    _cfg_listeners: tuple = ()

    def __init__(self, cfg, display_status_provider=None) -> None:
        self._cfg             = cfg
        self._cfg_lock        = threading.Lock()
        self._recovery_window = RecoveryWindow(self._on_announce)
        # Set by dial_main.py after inputs are actually constructed — reports
        # what is RUNNING (encoder/button/touch actually built and started),
        # not merely what cfg says is configured. Defaults False so an early
        # /configure or /recovery_status poll (before construction finishes)
        # never overclaims presence-confirmation capability.
        self._can_confirm_presence = False
        provider = display_status_provider or NoOpDisplayStatusProvider()
        provider.update_config(cfg.display)
        self._screen = ScreenSettingsService(
            config=self.config_snapshot, update_cfg=self.update_cfg,
            display_status=provider,
        )
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

    def config_snapshot(self):
        """The live config object. It is replaced on every update, never
        mutated, so the snapshot is stable for as long as the caller holds it."""
        with self._cfg_lock:
            return self._cfg

    @property
    def can_confirm_presence(self) -> bool:
        """Whether a confirmable input is running (see set_can_confirm_presence)."""
        return self._can_confirm_presence

    def recovery_snapshot(self) -> dict:
        """A thread-safe copy of the PIN recovery window's state."""
        return self._recovery_window.snapshot()

    def complete_recovery(self) -> None:
        """Close the PIN recovery window after the PIN was replaced."""
        self._recovery_window.complete()

    def announce(self, pin_recovery: bool = False) -> None:
        """Rewrite the dial's service announcement."""
        self._on_announce(pin_recovery)

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
        return screen_report(display if display is not None else self.display_config)

    def apply_screen_settings(self, screen) -> tuple[int, dict]:
        """Validate, apply, persist and report a `screen` settings object, as
        the management route and the HD page's settings route both do. The
        caller has already authorised the request. Returns (status, body);
        a body with 'restarting' set means the caller must call
        fire_touch_restart() once the reply has been sent."""
        return self._screen.apply(screen)

    def screen_settings_reply(self) -> dict:
        """The body of GET /screen/settings."""
        return self._screen.settings_reply()

    def latest_frame_png(self) -> bytes | None:
        """The display's latest frame as a PNG, or None when there is none."""
        return self._screen.latest_frame_png()

    def fire_touch_restart(self) -> None:
        """Launch the self-restart for a touch-type change, once the reply
        has been sent."""
        self._screen.fire_touch_restart()

    def set_touch_source(self, touch_source) -> None:
        """Register the running touch session, if any, so a live screen
        settings change can remap the touch axes to match the frame. None on
        a dial with no touch panel. Called once at startup."""
        self._screen.set_touch_source(touch_source)

    def set_touch_runtime(self, value: str) -> None:
        """Record what the touch stack actually did at startup (see
        ScreenSettingsService.set_touch_runtime). Called once at startup
        after touch construction finishes."""
        self._screen.set_touch_runtime(value)

    def begin_recovery_window(self) -> None:
        self._recovery_window.open()

    def confirm_volume(self) -> None:
        self._recovery_window.confirm_volume()

    def set_can_confirm_presence(self, value: bool) -> None:
        """Record whether this dial actually has at least one working
        confirmable input running right now (encoder, button, or touch —
        see dial_main.py's construction of each). Called once at startup
        after construction finishes; reflects runtime reality, not config."""
        self._can_confirm_presence = bool(value)

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
        cfg = self.config_snapshot()
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
        cfg = self.config_snapshot()
        snap = self._recovery_window.snapshot()
        return {
            "uuid": cfg.uuid,
            "name": cfg.name,
            "step_percent": cfg.step_percent,
            "recovery_active": snap["active"],
            "volume_confirmed": snap["volume_confirmed"],
        }

    def _on_announce(self, add: bool) -> None:
        cfg = self.config_snapshot()
        dial_admin.announce(cfg, VERSION, pin_recovery=add)

    def _make_handler(self) -> type:
        dial_server = self

        class _Handler(http.server.BaseHTTPRequestHandler):

            def _send_json(self, status: int, data: dict) -> None:
                body = json_bytes(data)
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
                body = json_bytes(TOO_MANY_ATTEMPTS)
                self.send_response(429)
                self.send_header('Retry-After', str(wait_secs))
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _read_body(self) -> bytes | None:
                try:
                    length = content_length(self.headers) or 0
                except (ValueError, TypeError):
                    self.send_error(400)
                    return None
                if not (0 <= length <= MAX_BODY):
                    self.send_error(413)
                    return None
                return self.rfile.read(length)

            def _read_json_object(self) -> dict | None:
                """The request body as a JSON object, or None after answering
                the refusal itself."""
                body = self._read_body()
                if body is None:
                    return None
                try:
                    return parse_json_object(body)
                except NotJson:
                    self._send_json(400, {'ok': False, 'error': 'invalid_json'})
                except NotAnObject:
                    self._send_json(400, {'ok': False, 'error': 'body_must_be_object'})
                return None

            def _pin_ok(self, obj: dict, cfg) -> bool:
                """True when the body carries the current PIN. Otherwise the
                refusal (429 while backed off, else 403) has been sent."""
                verdict = dial_pin_guard.authorise(
                    self.client_address[0], obj.get('current_pin', ''), cfg.pin,
                )
                if verdict.ok:
                    return True
                if verdict.wait_s:
                    self._send_429(verdict.wait_s)
                else:
                    self._send_json(403, {'ok': False, 'error': 'wrong_pin'})
                return False

            def do_GET(self) -> None:
                if self.path == '/configure':
                    cfg = dial_server.config_snapshot()
                    self._send_json(200, {
                        'step_percent':         cfg.step_percent,
                        'pin_set':              bool(cfg.pin),
                        'name':                 cfg.name,
                        'version':              VERSION,
                        'auto_update':          cfg.auto_update,
                        'update_channel':       cfg.update_channel,
                        'can_confirm_presence': dial_server.can_confirm_presence,
                        'hd_dev_access':        cfg.hd_dev_access,
                    })

                elif self.path == '/recovery_status':
                    snap = dial_server.recovery_snapshot()
                    if not snap['active']:
                        self._send_json(404, {
                            'active':               False,
                            'can_confirm_presence': dial_server.can_confirm_presence,
                        })
                    else:
                        self._send_json(200, {
                            'active':                 True,
                            'volume_confirmed':       snap['volume_confirmed'],
                            'recovery_remaining_ms':  snap['recovery_remaining_ms'],
                            'can_confirm_presence':   dial_server.can_confirm_presence,
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
                    self._send_json(200, dial_server.screen_settings_reply())

                elif self.path == '/screen/image':
                    frame_png = dial_server.latest_frame_png()
                    if frame_png is None:
                        self._send_json(404, {'ok': False, 'error': 'no_frame'})
                    else:
                        self._send_bytes(200, 'image/png', frame_png)

                elif self.path == '/sdcard-health':
                    cfg = dial_server.config_snapshot()
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

            def _handle_configure(self) -> None:
                obj = self._read_json_object()
                if obj is None:
                    return

                # ---- Field validation ----
                cfg = dial_server.config_snapshot()
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
                        snap = dial_server.recovery_snapshot()
                        if not snap['active'] or not snap['volume_confirmed']:
                            self._send_json(403, {'ok': False, 'error': 'recovery_not_confirmed'})
                            return
                    elif not self._pin_ok(obj, cfg):
                        return

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
                    if not is_int(v) or not (1 <= v <= 10):
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
                    dial_server.announce()

                if pin_recovery and cfg.pin:
                    dial_server.complete_recovery()

                if 'auto_update' in obj and new_cfg.auto_update != cfg.auto_update:
                    verb = "enable" if new_cfg.auto_update else "disable"
                    r = dial_admin.run_admin("toggle-dial-update-timer", verb, timeout=5, capture=True)
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
                obj = self._read_json_object()
                if obj is None:
                    return
                cfg = dial_server.config_snapshot()

                # PIN auth — screen settings follow POST /configure semantics.
                if cfg.pin and not self._pin_ok(obj, cfg):
                    return

                status, response = dial_server.apply_screen_settings(obj.get('screen'))
                self._send_json(status, response)
                if response.get('restarting'):
                    dial_server.fire_touch_restart()

            def _handle_sdcard_health(self) -> None:
                obj = self._read_json_object()
                if obj is None:
                    return
                cfg = dial_server.config_snapshot()

                # PIN auth: same rule as POST /screen/settings.
                if cfg.pin and not self._pin_ok(obj, cfg):
                    return

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
                r = dial_admin.run_admin("run-updater", timeout=5, capture=True)
                if r.returncode != 0:
                    self._send_json(200, {'ok': False, 'error': 'scheduler_failed'})
                else:
                    self._send_json(200, {'ok': True})

            def log_message(self, fmt, *args) -> None:
                logging.debug("HTTP %s", fmt % args)

        return _Handler
