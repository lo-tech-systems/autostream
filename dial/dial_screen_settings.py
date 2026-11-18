"""dial_screen_settings.py -- the dial's screen settings, as both servers apply them.

The management API (POST /screen/settings) and the HD page's settings route
share one path: validate the request, apply it to the running display,
persist it, and report the result. ScreenSettingsService holds that path
and the state it needs (the display status provider, the running touch
session and what the touch stack did at startup).

Apply-then-persist: a screen_type is opened on the live display before it is
saved, because saving first would persist a profile that may not open and the
dial would boot into a no-op display every restart. Only a screen_type change
withholds the save when the open fails.

A touch_type change only takes effect on the next service start, so the
service reports it as restart_required and, if the cooldown allows, the
caller restarts the service once the reply has been sent. The cooldown is a
security control: the route is unauthenticated while no PIN is set.

One apply runs at a time across every server, through a class-level lock.

NoOpDisplayStatusProvider is the display status used when the dial has no
display manager; it fixes the shape of GET /screen/settings' runtime object.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import copy
import logging
import threading
import time
from typing import Callable

from dial_config import (
    CARRIED_SCREEN_FIELDS,
    DialConfig,
    InvalidScreenSettings,
    display_settings,
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
from dial_layout_metrics import metrics_for
from dial_touch_controllers import list_controllers

import dial_admin


# POST /screen/settings is unauthenticated when no PIN is configured (the
# out-of-box state — see the PIN check in the management handler), and the dial's unit
# has RestartSec=10. Without a floor on trigger frequency, an open restart
# endpoint is a sustained denial-of-service. This is a security control,
# not a nicety.
_TOUCH_RESTART_COOLDOWN_SECONDS = 60


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


def screen_report(display) -> dict:
    """The `screen` object the screen-settings replies carry for *display*
    (a DialDisplayConfig)."""
    return {**display_settings(display), 'surface': _profile_for(display).surface}


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


class ScreenSettingsService:
    """Validate, apply, persist and report the dial's screen settings.

    *config* returns the live config, *update_cfg* swaps in a new one after a
    save, and *display_status* is the object that applies a display config to
    the running display and reports its state."""

    # One apply at a time whichever server asks, so two servers cannot
    # interleave a read-modify-write of the config.
    _apply_lock = threading.Lock()

    def __init__(self, *, config: Callable[[], DialConfig],
                 update_cfg: Callable[[DialConfig], None],
                 display_status) -> None:
        self._config = config
        self._update_cfg = update_cfg
        self._display_status = display_status
        self._touch_source = None
        self._touch_runtime = ''
        self._touch_restart_lock = threading.Lock()
        self._last_touch_restart_monotonic: float | None = None

    @property
    def display_status(self):
        return self._display_status

    def apply(self, screen) -> tuple[int, dict]:
        """Validate, apply, persist and report *screen*. Returns (status,
        body); a body with 'restarting' set means the caller must call
        fire_touch_restart() once the reply has been sent."""
        with self._apply_lock:
            return self._apply_locked(screen)

    def _apply_locked(self, screen) -> tuple[int, dict]:
        cfg = self._config()
        if isinstance(screen, dict):
            # The appliance's screen form never sends these keys, so a
            # save from it keeps the configured values rather than
            # resetting them to the defaults.
            for key in CARRIED_SCREEN_FIELDS:
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
                'screen':  screen_report(cfg.display),
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

        self._update_cfg(new_cfg)

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
        # ScreenSettingsService.fire_touch_restart.
        restarting = touch_type_changed and self._touch_restart_allowed()
        response = {
            'ok':               True,
            'screen':           screen_report(new_cfg.display),
            'layout_sizes':     layout_size_options(_profile_for(new_cfg.display)),
            'layout':           _layout_report_for(new_cfg.display),
            'scope':            _scope_report_for(new_cfg.display),
            'runtime':          runtime,
            'restart_required': touch_type_changed,
        }
        if restarting:
            response['restarting'] = True
        return 200, response

    def settings_reply(self) -> dict:
        """The body of GET /screen/settings."""
        cfg = self._config()
        runtime = self._display_status.get_status()
        runtime['touch_type'] = self._touch_runtime
        return {
            'ok':             True,
            'screen':         screen_report(cfg.display),
            'supported':      list_profiles(),
            'supported_touch': list_controllers(),
            'layout_sizes':   layout_size_options(_profile_for(cfg.display)),
            'layout':         _layout_report_for(cfg.display),
            'scope':          _scope_report_for(cfg.display),
            'runtime':        runtime,
        }


    def latest_frame_png(self) -> bytes | None:
        """The display's latest frame as a PNG, or None when there is none."""
        getter = getattr(self._display_status, 'latest_frame_png', None)
        if getter is None:
            return None
        try:
            return getter()
        except Exception as e:
            logging.debug("screen image: frame accessor raised: %s", e)
            return None


    def set_touch_source(self, touch_source) -> None:
        """Register the running touch session, if any, so a live screen
        settings change can remap the touch axes to match the frame. None on
        a dial with no touch panel. Called once at startup."""
        self._touch_source = touch_source


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
            dial_admin.spawn_admin("restart-dial-service")
            logging.info("dial touch: restart triggered (touch_type changed)")
        except Exception as e:
            logging.warning("dial touch: restart trigger failed: %s", e)
