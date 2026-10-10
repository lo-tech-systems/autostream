#!/usr/bin/env python3
"""dial_main.py — autostream dial service entry point.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable

from dial_config import PIN_RESET_PATH, RUNNING_MARKER_PATH, SCOPE_ALL, load_config
from dial_control import DialControlServer
from dial_http_server import (
    ADMIN_CMD,
    VERSION,
    DialHTTPServer,
    NoOpDisplayStatusProvider,
    _announce_self,
)
from dial_eq import start_eq_worker
from dial_info import gather_dial_info
from dial_led import DialLED
from dial_mdns import (
    get_display_targets,
    get_playing_targets,
    start_general_browser,
    start_playing_browser,
    stop_general_browser,
    stop_playing_browser,
)
from dial_network import latest as network_latest
from dial_network import start_network_worker
import dial_sdhealth
# autostream_sysutils is deployed flat into /opt/autostream beside the dial
# package; in the repo it lives in core/.
try:
    from autostream_sysutils import log_lifecycle
except ImportError:
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "core")))
    from autostream_sysutils import log_lifecycle  # noqa: E402
from dial_outputs import start_outputs_worker
from dial_repeat import start_repeat_worker
from dial_target_status import enrich_targets
from dial_volume import (
    enqueue_delta,
    enqueue_mute,
    enqueue_mute_all,
    select_volume_target,
    shown_muted,
    start_volume_worker,
)


# The dial's log file lives on the SD card. Warnings and errors are what a
# field diagnosis needs first; the lifecycle chatter at INFO is available on
# demand by setting APP_LOG_LEVEL=INFO (or DEBUG) in the service environment.
DEFAULT_LOG_LEVEL = 'WARNING'


def _configure_logging() -> str:
    """Set up the dial's log file and console output, and return the name
    of the level applied."""
    level_name = os.environ.get('APP_LOG_LEVEL', DEFAULT_LOG_LEVEL).strip().upper()
    level = getattr(logging, level_name, logging.WARNING)
    if not isinstance(level, int):
        level = logging.WARNING
    log_file = "/var/log/autostream/autostream-dial.log"
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logging.basicConfig(
        level=level,
        format="%(asctime)s: %(message)s",
        datefmt="%d-%b-%y %H:%M:%S",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout),
        ],
    )
    # Suppress library noise at INFO; still visible at DEBUG.
    logging.getLogger('gpiozero').setLevel(logging.WARNING)
    logging.getLogger('lgpio').setLevel(logging.WARNING)
    return logging.getLevelName(level)


def _reconcile_update_timer(auto_update: bool) -> None:
    """Ensure the systemd timer matches the persisted auto_update value.

    Called at every startup to recover from crashes between config save and
    timer activation (POST /configure step 3→5) where rollback never ran.
    Non-fatal — a failure must never prevent the service from starting.
    """
    verb = "enable" if auto_update else "disable"
    try:
        r = subprocess.run(
            ["sudo", ADMIN_CMD, "toggle-dial-update-timer", verb],
            timeout=10,
        )
        if r.returncode != 0:
            logging.warning(
                "startup: timer reconciliation failed (rc=%d, verb=%s) — timer state may be stale",
                r.returncode, verb,
            )
    except Exception as e:
        logging.warning(
            "startup: timer reconciliation raised %s: %s — continuing",
            type(e).__name__, e,
        )


def _check_unclean_shutdown() -> bool:
    """Log a WARNING if the running marker survived from a previous run,
    and return whether it did.

    Its survival means the previous stop did NOT go through the clean-
    shutdown path in main()'s finally block — most likely a power loss, or
    the process being killed outright. The return value is also the
    "genuinely power-cycled" half of the PIN-recovery arming decision below:
    a service restart that went through clean shutdown must not be treated
    as evidence of physical presence at the device.

    Must be called BEFORE _create_running_marker() recreates the file, or
    the check would always see the marker this very process just wrote and
    "detect" an unclean shutdown on every start.
    """
    survived = RUNNING_MARKER_PATH.exists()
    if survived:
        logging.warning(
            "autostream-dial: running marker survived from the previous "
            "run — last shutdown was not clean (power loss or the process "
            "was killed)"
        )
    return survived


def _create_running_marker() -> None:
    """Create the running marker for this run.

    Wrapped in try/except: a dial with a read-only or otherwise broken state
    directory must still be able to start. Losing this signal only degrades
    unclean-shutdown detection, it must never take the service down.
    """
    try:
        RUNNING_MARKER_PATH.touch(exist_ok=True)
    except OSError as e:
        logging.warning(
            "autostream-dial: could not create running marker %s: %s",
            RUNNING_MARKER_PATH, e,
        )


def _remove_running_marker() -> None:
    """Delete the running marker as part of a clean shutdown.

    Wrapped in try/except: a failure here must never prevent the rest of
    the shutdown sequence (in main()'s finally block) from completing.
    """
    try:
        RUNNING_MARKER_PATH.unlink(missing_ok=True)
    except OSError as e:
        logging.warning(
            "autostream-dial: could not remove running marker %s: %s",
            RUNNING_MARKER_PATH, e,
        )


# ---- PIN-recovery arming decision ------------------------------------------
#
# A PIN-recovery request is only ever armed on startup, and only when BOTH
# the running marker survived (the previous stop was not clean — see
# _check_unclean_shutdown above) AND a request file is present. Neither
# alone is enough: a survived marker with no request means an ordinary power
# cycle nobody asked for, and a request with a clean-shutdown marker means a
# restart happened before the device was ever power-cycled (a
# reconfiguration restart, or a plain `reboot`) — the request must stay
# armed for a real power cycle later, not fire on the restart itself.

_TIMESYNC_MARKER_PATH = Path('/run/systemd/timesync/synchronized')
_RECOVERY_REQUEST_MAX_AGE_S = 30 * 60
_TIMESYNC_POLL_TIMEOUT_S = 30
_TIMESYNC_POLL_INTERVAL_S = 1


def _recovery_request_within_window(
    request_path: Path,
    *,
    sync_marker_path: Path,
    now: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Return whether a pending PIN-recovery request is still within its
    30-minute window, measured from *request_path*'s mtime.

    This hardware has no RTC. systemd-timesyncd restores the last known
    time from disk at boot, so the clock starts plausible but can easily sit
    slightly BEHIND a file written after that save — an age comparison
    against it would be meaningless, or even negative, until NTP finishes.
    Comparing dates cannot detect this; timesyncd instead publishes the fact
    directly by creating *sync_marker_path* only once the clock has actually
    synchronised. Being tmpfs, that marker is absent at every boot, so its
    absence here is a real "not yet synced" signal, not a stale leftover.

    If the marker is not there yet, this polls for it briefly rather than
    trusting an unsynced clock immediately — but only because a request is
    actually pending; a normal boot with no request never reaches this
    function at all, so it is never delayed by this wait.

    If the clock still has not synchronised after the poll times out, the
    request is honoured anyway and the skipped check is logged. This is
    deliberate, not an oversight: a dial with broken time sync and a lost
    PIN would otherwise be permanently unrecoverable. The rest of the
    arming chain — an explicit request plus physical presence at the device
    afterwards — is still intact; the clock is simply the least trustworthy
    input in that chain, so it is the one that yields. Resist the urge to
    "fix" this into a fail-closed check; that trade was made on purpose.
    """
    if not sync_marker_path.exists():
        waited = 0.0
        while waited < _TIMESYNC_POLL_TIMEOUT_S:
            sleep(_TIMESYNC_POLL_INTERVAL_S)
            waited += _TIMESYNC_POLL_INTERVAL_S
            if sync_marker_path.exists():
                break
        if not sync_marker_path.exists():
            logging.warning(
                "autostream-dial: clock not yet synchronised after waiting "
                "%ds — honouring the pending PIN recovery request without "
                "checking its age",
                _TIMESYNC_POLL_TIMEOUT_S,
            )
            return True

    try:
        age_s = now() - request_path.stat().st_mtime
    except OSError:
        # The file existed moments ago (the caller only reaches this
        # function when it does) but disappeared under us — treat that the
        # same as an expired request rather than raising out of startup.
        return False
    return age_s <= _RECOVERY_REQUEST_MAX_AGE_S


def _clear_recovery_request() -> None:
    """Delete a consumed PIN-recovery request file.

    Best-effort like the running-marker helpers above: a failure here must
    never prevent the service from starting, and by the time this runs the
    request has already been acted on (armed, or correctly left unarmed).
    """
    try:
        PIN_RESET_PATH.unlink(missing_ok=True)
    except OSError as e:
        logging.warning(
            "autostream-dial: could not remove PIN recovery request %s: %s",
            PIN_RESET_PATH, e,
        )


def _build_volume_targets_fn(
    display, get_targets=get_display_targets, *, scope_fn=None, get_all_targets=get_playing_targets,
):
    """Zero-arg resolver for the volume worker.

    Under broadcast scope "all" (scope_fn returns SCOPE_ALL — a screenless
    dial, or one whose screen was later unfitted, cannot choose an
    appliance), every playing target with auth != "unauthorized" is
    returned, focus ignored: a fleet-wide twist has no single appliance to
    pin to. Otherwise (scope_fn absent or returning anything else) today's
    single-target behaviour: a manual focus (playing or idle) the display is
    showing, when it has one, else the display's artwork source, else the
    oldest playing target — as a list of zero or one target.

    display may be any object — in particular NoOpDisplayStatusProvider,
    which has neither accessor at all — a missing or raising accessor
    degrades to the next step so a NoOp or broken display never blocks
    volume (display failure must never affect volume control). get_targets
    defaults to the real dial_mdns.get_display_targets, imported at module
    load time; tests override it directly for a fake target list. scope_fn,
    when supplied, is called fresh on every resolve (the live-read discipline
    every resolver here already follows), so a /screen/settings save or a
    screen being unfitted applies to the very next twist with no restart.

    Rows with a confirmed 412 (auth == "unauthorized") are excluded. Rows
    whose auth is still "unknown" stay eligible — the encoder must be live
    from the first second, and only a definitive miss removes a row.
    """
    getter = getattr(display, "current_source_service_name", None)
    focus_getter = getattr(display, "focus_volume_target", None)

    def resolve():
        if scope_fn is not None and scope_fn() == SCOPE_ALL:
            return [t for t in get_all_targets() if t.auth != "unauthorized"]
        if focus_getter is not None:
            try:
                focused = focus_getter()
            except Exception:
                focused = None
            if focused is not None:
                return [focused]
        targets = [t for t in get_targets() if t.auth != "unauthorized"]
        preferred = None
        if getter is not None:
            try:
                preferred = getter()
            except Exception:
                preferred = None
        chosen = select_volume_target(targets, preferred)
        return [chosen] if chosen is not None else []
    return resolve


def _build_mute_targets_fn(http_server, volume_targets_fn, get_all_targets=get_playing_targets):
    """Zero-arg resolver for mute: every playing target when the dial's live
    effective mute scope is "all", else the same single target volume uses.
    Reads the scope through http_server (not a captured cfg value) so a
    /screen/settings change, or the screen being unfitted, applies without a
    restart, exactly like step_percent does for the encoder today. As with
    volume, unauthorized rows are excluded from the "all" fan-out; unknown
    rows stay eligible."""
    def resolve():
        if http_server.effective_mute_scope == SCOPE_ALL:
            return [t for t in get_all_targets() if t.auth != "unauthorized"]
        return volume_targets_fn()
    return resolve


def _build_mute_press_fn(display, http_server):
    """The one thing a mute push does, shared by the touch MUTE zone and the
    physical button: under broadcast scope "all", enqueue a fleet toggle
    decided at dispatch (see dial_volume.enqueue_mute_all()); otherwise flip
    what the bound appliance last reported, exactly as a screened dial always
    has. Both branches are plain writes plus a queue put — no network, no
    DialDisplay lock — so sharing this one function between the two press
    entries does not change either one's lock-free-touch guarantee."""
    getter = getattr(display, "current_source_service_name", lambda: None)

    def press() -> None:
        if http_server.effective_mute_scope == SCOPE_ALL:
            enqueue_mute_all()
        else:
            enqueue_mute(shown_muted(getter()))
    return press


def _build_touch_source(cfg, display, confirm_presence=None, step_percent=None, mute_press=None):
    """Construct and wire a TouchEventSource for cfg.display against the
    already-built *display* manager.

    Every import here is deferred to inside this function, exactly like
    dial_display.create_dial_display() is deferred inside main() — in
    particular, dial_display_compositor (needed here for OverlayState) pulls
    in Pillow at module import time, so hoisting any of these imports to
    module level would defeat the same ImportError isolation the display
    stack already gets. The caller wraps this whole call in its own
    try/except so a missing gpiozero/SPI/I2C library, or any other
    construction failure, degrades to no-touch without taking the display
    or volume control down with it.

    step_percent, when supplied, is a zero-arg callable returning the
    CURRENT step size — main() passes `lambda: http_server.step_percent` so
    a live /configure change is honoured by touch immediately, matching the
    encoder's nudge_up/nudge_down (which already read http_server.step_percent
    rather than the startup cfg). When omitted, the callbacks fall back to
    the startup cfg.step_percent, unchanged from before this parameter
    existed.

    mute_press, when supplied, is the zero-arg callable built by
    _build_mute_press_fn(display, http_server) — main() passes the SAME
    instance it also gives the physical button, so a touch tap and a button
    press make identical scope decisions. When omitted (tests that construct
    a touch source with no http_server), the MUTE zone falls back to the
    plain scope-"current" behaviour this parameter replaces: read
    shown_muted() for the display's current source and enqueue that.
    """
    from dial_display_compositor import OverlayState
    from dial_display_profiles import get_profile, layout_context_for
    from dial_touch import TouchEventSource, TouchStateMachine
    from dial_touch_layout import metrics_for
    from dial_touch_controllers import get_controller
    from dial_touch_drivers import open_driver
    from dial_touch_filter import DEFAULT_Z_THRESHOLD, TouchFilter
    from dial_touch_layout import TouchZone, WARNING_ZONES

    # Any deliberate contact with the screen proves physical presence — the
    # reveal-then-arm scheme (see dial_touch.py) means a first touch may only
    # ever reveal the overlay and never arm/actuate anything, so confirmation
    # must not wait for an armed zone. on_reveal_overlay fires on that very
    # first touch-down; on_set_pressed_zone fires whenever a press arms
    # (either immediately, if the overlay was already visible, or later via
    # overlay_live()). Together they cover every contact. confirm_presence is
    # optional so callers/tests that don't care about recovery can omit it.
    _confirm_presence = confirm_presence or (lambda: None)
    _mute_press = mute_press or (
        lambda: enqueue_mute(shown_muted(display.current_source_service_name()))
    )

    controller = get_controller(cfg.display.touch_type)
    profile = get_profile(cfg.display.screen_type)
    layout = layout_context_for(cfg.display)
    driver = open_driver(controller.driver_tag)
    # ft6206 (capacitive) leaves z_threshold unset — it reports already-
    # "touching" samples with no meaningful analog pressure, so the
    # threshold check is effectively a no-op for it (see
    # dial_touch_drivers.FT6206Driver). TouchFilter still needs *some* int
    # threshold to compare against, so fall back to its own default.
    z_threshold = (
        controller.z_threshold if controller.z_threshold is not None else DEFAULT_Z_THRESHOLD
    )
    # A 180-degree screen rotation is applied to the frame in software, so
    # the touch sheet has to be turned the same way or presses land
    # diagonally opposite what the user sees. Inverting BOTH axes is what
    # 180 degrees means; it composes with the profile's own axis mapping.
    rotated = bool(cfg.display.rotate)
    touch_filter = TouchFilter(
        layout.logical_width,
        layout.logical_height,
        z_threshold=z_threshold,
        raw_x_min=controller.raw_x_min,
        raw_x_max=controller.raw_x_max,
        raw_y_min=controller.raw_y_min,
        raw_y_max=controller.raw_y_max,
        swap_xy=profile.touch_swap_xy,
        invert_x=profile.touch_invert_x != rotated,
        invert_y=profile.touch_invert_y != rotated,
        physical_size=layout.physical_size,
    )
    touch_metrics = metrics_for(
        layout.logical_width, layout.logical_height,
        mm_per_px=layout.mm_per_px, size_chosen=layout.size_chosen,
    )
    state_machine = TouchStateMachine(layout.logical_width, layout.logical_height, metrics=touch_metrics)

    def on_reveal_overlay() -> None:
        _confirm_presence()
        display.notify_touch_activity()
        # muted is left at the OverlayState default -- the display's own
        # compose-time merge (_effective_overlay_locked) fills it in from
        # the observation store (dial_volume.shown_muted()) for whichever
        # appliance is actually reporting, which is the dial's only source
        # of truth for mute; there is nothing to publish here.
        display.set_overlay(OverlayState(visible=True))
        # The repaint thread services the overlay signal well ahead of any
        # human-perceptible delay; treating "signaled" as "rendered" here
        # (rather than blocking on the repaint thread's actual SPI push)
        # keeps touch dispatch decoupled from frame latency, matching the
        # rest of this feature's lock-order discipline.
        touch_source.overlay_live()

    def on_dismiss_overlay() -> None:
        display.set_overlay(OverlayState(visible=False))

    def on_set_pressed_zone(zone, index=None) -> None:
        # Every zone on every screen reports through one channel; the
        # display resolves it against the screen actually showing, so a
        # zone that does not exist there draws nothing. zone=None is the
        # flash-clear.
        _confirm_presence()
        display.notify_touch_activity()
        display.set_pressed(zone, index)

    def on_volume_up() -> None:
        # enqueue_delta() first, THEN notify_touch_activity() — the reverse
        # of the order below until this feature: notify_touch_activity()
        # sets the repaint signal, and the repaint must see the nudged
        # pending readout value (see dial_volume.enqueue_delta()), not the
        # pre-press one.
        step = step_percent() if step_percent is not None else cfg.step_percent
        enqueue_delta(step)
        display.notify_touch_activity()

    def on_volume_down() -> None:
        step = step_percent() if step_percent is not None else cfg.step_percent
        enqueue_delta(-step)
        display.notify_touch_activity()

    def on_mute_toggle() -> None:
        display.notify_touch_activity()
        # mute_press() (see _build_mute_press_fn) is the same decision the
        # physical button makes: under scope "current" it flips whatever the
        # reporting appliance last reported (read from the observation
        # store, never inferred or persisted here) and echoes the request
        # into that same store so the glyph updates on this frame; under
        # scope "all" it enqueues a fleet toggle the volume worker decides at
        # dispatch instead. Either way this does no network I/O and takes no
        # DialDisplay lock, so this stays as cheap as the volume callbacks
        # above. on_set_pressed_zone() always runs immediately before this
        # for the MUTE zone (see TouchStateMachine._arm) and already
        # recorded the press on the pressed channel.
        _mute_press()
        display.set_overlay(OverlayState(visible=True))

    def on_zone_tap(zone, index) -> None:
        # NAME opens the appliance selector (from either the main, repeat
        # or EQ screen); the LIST_* zones act on whichever list-chassis
        # screen (selector, picker or outputs) is open; DOTS cycles the
        # pages (main -> repeat -> eq -> main, skipping one with nothing to
        # show — closing back to main also reveals the main screen's volume
        # overlay on return — see display.cycle_pages()); REPEAT_* act on
        # the repeat screen; EQ_BASS_*/EQ_TREBLE_* act on the EQ page's own
        # bars; IDLE_REPLAY opens the replay picker; IDLE_INFO opens the
        # idle screen's read-only info page; IDLE_WIFI opens the No-WiFi
        # page while the link is down; any warning cell (WARNING_ZONES)
        # goes to the display's warning dispatch; OUTPUTS
        # opens the outputs list; OUTPUT_* act on the per-output detail
        # page; ARTWORK hides the main screen's own bands for a few
        # seconds — see dial_touch.py's SURFACES paragraph for how a press
        # ever reaches one of these zones in the first place.
        _confirm_presence()
        display.notify_touch_activity()
        if zone == TouchZone.NAME:
            display.open_selector()
        elif zone == TouchZone.LIST_BACK:
            display.close_list()
        elif zone == TouchZone.LIST_DOWN:
            display.list_page(+1)
        elif zone == TouchZone.LIST_UP:
            display.list_page(-1)
        elif zone == TouchZone.LIST_ROW:
            display.list_row_tap(index)
        elif zone == TouchZone.DOTS:
            display.cycle_pages()
        elif zone == TouchZone.EQ_BASS_DOWN:
            display.eq_step("bass", -1)
        elif zone == TouchZone.EQ_BASS_UP:
            display.eq_step("bass", +1)
        elif zone == TouchZone.EQ_TREBLE_DOWN:
            display.eq_step("treble", -1)
        elif zone == TouchZone.EQ_TREBLE_UP:
            display.eq_step("treble", +1)
        elif zone == TouchZone.REPEAT_PLAY:
            display.repeat_toggle_tap()
        elif zone == TouchZone.REPEAT_START:
            display.repeat_start_tap()
        elif zone == TouchZone.REPEAT_STOP:
            display.repeat_stop_tap()
        elif zone == TouchZone.IDLE_REPLAY:
            display.open_picker()
        elif zone == TouchZone.IDLE_INFO:
            display.open_info()
        elif zone == TouchZone.IDLE_WIFI:
            display.open_nowifi()
        elif zone in WARNING_ZONES:
            display.warning_button_tap(zone)
        elif zone == TouchZone.OUTPUTS:
            display.open_outputs()
        elif zone == TouchZone.OUTPUT_BACK:
            display.close_list()
        elif zone == TouchZone.OUTPUT_TOGGLE:
            display.output_toggle_tap()
        elif zone == TouchZone.OUTPUT_UP:
            step = step_percent() if step_percent is not None else cfg.step_percent
            display.output_volume_tap(+step)
        elif zone == TouchZone.OUTPUT_DOWN:
            step = step_percent() if step_percent is not None else cfg.step_percent
            display.output_volume_tap(-step)
        elif zone == TouchZone.ARTWORK:
            display.hide_controls()
            # The session must know the controls are gone: with the
            # controls revealed by touch nothing else would tell it, and a
            # finger must never arm against bands that are no longer drawn.
            touch_source.overlay_hidden()

    touch_source = TouchEventSource(
        driver, touch_filter, state_machine,
        on_reveal_overlay=on_reveal_overlay,
        on_volume_up=on_volume_up,
        on_volume_down=on_volume_down,
        on_mute_toggle=on_mute_toggle,
        on_dismiss_overlay=on_dismiss_overlay,
        on_set_pressed_zone=on_set_pressed_zone,
        on_zone_tap=on_zone_tap,
        get_noncomposited_generation=display.noncomposited_generation,
        # get_touch_surface (surface + name_active) is the preferred sync;
        # get_persistent_overlay is kept as the legacy fallback so a
        # display stand-in that only implements the older attribute (or
        # the NoOp provider, which implements neither) still behaves
        # exactly as before — see dial_touch.TouchEventSource._poll_surface.
        get_touch_surface=getattr(display, "touch_surface", None),
        get_persistent_overlay=getattr(display, "persistent_overlay_shown", None),
        consume_repeat_close_reveal=getattr(display, "consume_repeat_close_reveal", None),
        axis_signs=(
            profile.touch_swap_xy, profile.touch_invert_x, profile.touch_invert_y
        ),
    )
    # Logged on success, not just on failure: without this there is no way
    # to tell from the journal whether the touch stack came up at all, and
    # the axis mapping is the first thing to check when presses land in the
    # wrong place.
    logging.info(
        "dial touch: %s ready on %dx%d logical on %dx%d (raw x %s-%s y %s-%s, swap_xy=%s, "
        "invert x=%s y=%s, rotate=%s)",
        controller.key, layout.logical_width, layout.logical_height,
        profile.width, profile.height,
        controller.raw_x_min, controller.raw_x_max,
        controller.raw_y_min, controller.raw_y_max,
        profile.touch_swap_xy,
        profile.touch_invert_x != rotated, profile.touch_invert_y != rotated,
        rotated,
    )
    return touch_source


def main() -> None:
    log_level = _configure_logging()

    shutdown_event = threading.Event()

    # Start and stop are always logged, whatever the level (see
    # log_lifecycle()): a log bundle must say which version was running.
    def _on_sigterm(sig, frame):
        log_lifecycle("autostream-dial stopping")
        shutdown_event.set()

    def _on_sigint(sig, frame):
        log_lifecycle("autostream-dial stopping")
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _on_sigterm)
    signal.signal(signal.SIGINT, _on_sigint)

    cfg = load_config()
    log_lifecycle(
        "autostream-dial starting (version %s, uuid %s, python %s, log level %s)",
        VERSION, cfg.uuid, sys.version.split()[0], log_level,
    )

    # Check BEFORE recreating: recreating first would make the marker
    # "survive" every single start, including this one. Likewise the
    # request file is read here, before anything below can touch it.
    running_marker_survived = _check_unclean_shutdown()
    recovery_request_present = PIN_RESET_PATH.exists()

    # Arm only when both signals line up: a survived marker (genuine power
    # cycle) AND a pending request (someone asked). The request file is
    # deleted only in this branch — an admin who arms recovery and then hits
    # an unrelated clean restart before power-cycling must find the arm
    # still intact, not silently cleared.
    recovery_armed = False
    if running_marker_survived and recovery_request_present:
        if cfg.pin:
            recovery_armed = _recovery_request_within_window(
                PIN_RESET_PATH, sync_marker_path=_TIMESYNC_MARKER_PATH,
            )
        # else: a request with no PIN configured has nothing to recover —
        # fall through to the deletion below without evaluating its age.
        _clear_recovery_request()

    _create_running_marker()

    # The display is built and lit before anything else that costs time
    # (the update-timer reconcile and the announce verb both fork
    # subprocesses), so the panel shows "Starting..." as early as the
    # process can manage. Imported lazily so a Pillow/display-stack import
    # failure (e.g. an incomplete apt install) degrades to a no-op display
    # rather than taking down the whole service — volume control must not
    # depend on Pillow.
    try:
        from dial_display import create_dial_display
        display = create_dial_display(cfg, get_display_targets)
    except ImportError as e:
        logging.warning("dial display: display stack unavailable (%s) — display disabled", e)
        display = NoOpDisplayStatusProvider()
    # The boot splash: opens the manager's one backend and paints
    # "Starting..." now, before any display thread exists; display.start()
    # below reuses that open and the first poll replaces the splash.
    # getattr guards the NoOpDisplayStatusProvider fallback, which has no
    # screen. show_starting() never raises.
    show_starting = getattr(display, "show_starting", None)
    if show_starting is not None:
        show_starting()

    _reconcile_update_timer(cfg.auto_update)
    _announce_self(cfg)

    led = DialLED(cfg.led_gpio)

    http_server = DialHTTPServer(
        cfg, display_status_provider=display,
        get_rostered_ips=lambda: {
            t.appliance_id: t.ip for t in get_playing_targets() if t.appliance_id
        },
    )
    http_server.start()

    if recovery_armed:
        http_server.begin_recovery_window()

    start_playing_browser(shutdown_event=shutdown_event)
    # The general-appliance browser feeds the roster/repeat-store machinery
    # display.start() (and, later, touch) reads — an unfitted dial has no
    # roster/repeat UI to feed, so it is not worth an extra avahi-browse
    # child for that case.
    if cfg.display.fitted:
        start_general_browser(shutdown_event=shutdown_event)

    # Wired here, after the HTTP server exists (its get_runtime_status()
    # supplies the dial's live name) and before display.start() (so the
    # provider is in place before the repeat thread can ever open the info
    # page). hasattr guards the NoOpDisplayStatusProvider fallback above,
    # which has no screen and so no provider to set.
    if hasattr(display, "set_info_provider"):
        display.set_info_provider(
            lambda: gather_dial_info(
                http_server.get_runtime_status()["name"], VERSION,
                network=network_latest(), sd_health=dial_sdhealth.info_value(),
            )
        )
    display.start()

    # Volume/mute broadcast scope (see dial_volume.py's module docstring):
    # each addresses the display's single reporting-from target, unless the
    # dial's live effective scope is "all" (a screenless dial, or a screened
    # one whose choice says "all"), in which case it addresses every playing
    # target instead. Both resolvers degrade gracefully for a
    # NoOpDisplayStatusProvider (no current_source_service_name) and for a
    # bare mock http_server in tests — see _build_volume_targets_fn/
    # _build_mute_targets_fn.
    volume_targets_fn = _build_volume_targets_fn(
        display, scope_fn=lambda: http_server.effective_volume_scope,
    )
    start_volume_worker(
        cfg, volume_targets_fn, led,
        mute_targets_fn=_build_mute_targets_fn(http_server, volume_targets_fn),
        on_readout_changed=getattr(display, "request_repaint", None),
    )

    # Shared by the touch MUTE zone and the physical button below, so both
    # make the identical scope decision from the same live http_server state
    # — see _build_mute_press_fn.
    mute_press = _build_mute_press_fn(display, http_server)

    # The repeat-transport sender: its own thread, queue and HTTP client,
    # entirely separate from the volume worker above (see dial_repeat.py's
    # module docstring for why). on_result degrades to a no-op for a
    # NoOpDisplayStatusProvider (no on_repeat_result method).
    start_repeat_worker(cfg, on_result=getattr(display, "on_repeat_result", None))

    # The outputs list/mutation sender: its own thread, queue and HTTP
    # client, entirely separate from the volume and repeat workers above
    # (see dial_outputs.py's module docstring). on_result degrades to a
    # no-op for a NoOpDisplayStatusProvider (no on_outputs_result method).
    start_outputs_worker(cfg, on_result=getattr(display, "on_outputs_result", None))

    # The EQ page's bass/treble sender: its own thread, queue and HTTP
    # client, entirely separate from every other worker above (see
    # dial_eq.py's module docstring). on_result degrades to a no-op for a
    # NoOpDisplayStatusProvider (no on_eq_result method).
    start_eq_worker(cfg, on_result=getattr(display, "on_eq_result", None))

    # The Wi-Fi link poller: its own thread, one loopback read of the local
    # watcher every 15 s (see dial_network.py's module docstring). Feeds the
    # idle screen's status glyph and the No-WiFi page; on_view degrades to a
    # no-op for a NoOpDisplayStatusProvider (no on_network_view method).
    # The SD card health reader rides the same thread through on_tick,
    # reading its files at most every ten minutes (see dial_sdhealth.py).
    dial_sdhealth.start(on_view=getattr(display, "on_sd_health_view", None))
    start_network_worker(
        on_view=getattr(display, "on_network_view", None),
        on_tick=dial_sdhealth.tick,
    )

    # Touch requires a screen (a product decision) — built AFTER the display
    # and only when the config says both a screen is fitted and a touch
    # controller is selected. `hasattr(display, "set_overlay")` excludes the
    # NoOpDisplayStatusProvider fallback above: if the display stack itself
    # failed to import, there is nothing for touch to draw an overlay onto,
    # so touch must not start either, regardless of what cfg.display says.
    # Construction failures here (missing gpiozero, no SPI/I2C, an unknown
    # driver tag, ...) degrade to no-touch and log it — touch must never
    # prevent the dial from starting or affect volume control, exactly like
    # the display stack's own isolation above.
    touch_source = None
    # Runtime readiness signal for GET /screen/settings — distinct from the
    # persisted cfg.display.touch_type, which changes the instant a POST
    # saves it even though the running process hasn't restarted yet. See
    # DialHTTPServer.set_touch_runtime.
    touch_runtime = "none"
    if (
        cfg.display.fitted
        and cfg.display.touch_type != "none"
        and hasattr(display, "set_overlay")
    ):
        try:
            touch_source = _build_touch_source(
                cfg, display, confirm_presence=http_server.confirm_volume,
                step_percent=lambda: http_server.step_percent,
                mute_press=mute_press,
            )
            touch_source.start()
            touch_runtime = cfg.display.touch_type
        except Exception as e:
            logging.warning("dial touch: touch stack unavailable (%s) — touch disabled", e)
            touch_source = None
            touch_runtime = "failed"
    http_server.set_touch_runtime(touch_runtime)

    # ---- Shared nudge callbacks (passed to both encoder and control socket) ----

    def _pop_repeat_screen() -> None:
        # A physical volume/mute nudge while the repeat screen is open
        # returns to the volume readout on main — display.pop_secondary()
        # is a lock-free flag write; a raising/missing display (e.g. the
        # NoOp fallback) must never block the nudge itself.
        try:
            display.pop_secondary("repeat")
        except Exception:
            pass

    def nudge_up() -> int:
        http_server.confirm_volume()
        _pop_repeat_screen()
        delta = http_server.step_percent
        enqueue_delta(delta)
        return delta

    def nudge_down() -> int:
        http_server.confirm_volume()
        _pop_repeat_screen()
        delta = -http_server.step_percent
        enqueue_delta(delta)
        return delta

    def nudge_delta(delta: int) -> int:
        if delta != 0:
            http_server.confirm_volume()
        enqueue_delta(delta)
        return delta

    # ---- Local control socket ----

    control_server = DialControlServer(
        get_runtime_status=http_server.get_runtime_status,
        get_targets=get_playing_targets,
        enrich_targets=enrich_targets,
        nudge_up=nudge_up,
        nudge_down=nudge_down,
        nudge_delta=nudge_delta,
        software_version=VERSION,
    )

    # Import GPIO helpers lazily — non-Pi hosts can still run the HTTP service.
    try:
        from autostream_rpi import setup_rotary_encoder, setup_button  # type: ignore[import]
    except ImportError:
        setup_rotary_encoder = None  # type: ignore[assignment]
        setup_button = None  # type: ignore[assignment]

    # Socket startup failures are fatal — let them escape so systemd can retry.
    # The finally block stops the control server and HTTP server on any exit.
    try:
        control_server.start()

        # Store encoder and button in long-lived locals — prevents GC from
        # finalising the underlying lgpio device handle and silently stopping
        # interrupts.
        encoder = None
        if cfg.clk_gpio is None or cfg.dt_gpio is None:
            # A screen-only build has no rotary encoder wired up — this is a
            # deliberate config choice, not a hardware fault, so it gets an
            # INFO line rather than the GPIO-init warning below.
            logging.info("rotary encoder not configured; skipping")
        elif setup_rotary_encoder is not None:
            encoder = setup_rotary_encoder(cfg.clk_gpio, cfg.dt_gpio, nudge_up, nudge_down)

        def on_press() -> None:
            http_server.confirm_volume()
            _pop_repeat_screen()
            mute_press()

        button = None
        if cfg.sw_gpio is None:
            logging.info("button not configured; skipping")
        elif setup_button is not None:
            button = setup_button(cfg.sw_gpio, on_press)

        # Runtime-derived, not config-derived: a dial with clk/dt/sw_gpio set
        # but whose GPIO init failed (setup_rotary_encoder/setup_button
        # returning None) must not claim it can confirm presence, and
        # neither must a dial whose touch stack raised above (touch_source
        # stays None on that path). See DialHTTPServer.set_can_confirm_presence.
        http_server.set_touch_source(touch_source)
        http_server.set_can_confirm_presence(
            encoder is not None or button is not None or touch_source is not None
        )

        while not shutdown_event.wait(5):
            led.set_playing() if get_playing_targets() else led.set_idle()
    finally:
        _remove_running_marker()
        stop_playing_browser()
        stop_general_browser()
        if touch_source is not None:
            touch_source.stop()
        display.stop()
        control_server.stop()
        http_server._server.shutdown()


if __name__ == '__main__':
    main()
