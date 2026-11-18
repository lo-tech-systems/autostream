#!/usr/bin/env python3
"""dial_main.py — autostream dial service entry point.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time

# In the repository core/ sits beside dial/; in /opt/autostream the core
# modules are flat beside this file.
_REPO_CORE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "core"))
if os.path.isdir(_REPO_CORE) and _REPO_CORE not in sys.path:
    sys.path.insert(0, _REPO_CORE)

import dial_admin
from dial_config import SCOPE_ALL, load_config
from dial_display_profiles import get_profile_or_default
from dial_control import DialControlServer, core_target_records
from dial_core import create_dial_core
from dial_core_state import awaiting_pin
from dial_hd_events import ChangeHub
from dial_hd_ddc import detect_backlight
from dial_hd_panel import HdPanel
from dial_hd_server import HdServer
from dial_http_server import (
    VERSION,
    DialHTTPServer,
    _announce_self,
)
from dial_info import current_ipv4, gather_dial_info
from dial_led import DialLED
import dial_mdns
from dial_mdns import (
    get_display_targets,
    get_playing_targets,
)
from dial_network import latest as network_latest
from dial_network import start_network_worker
from dial_recovery import begin_run, end_run
from dial_touch_wiring import build_touch_source
from dial_screen_settings import NoOpDisplayStatusProvider
import dial_sdhealth
import autostream_logging as log_setup
from autostream_peer_client import PeerClient, PeerPool
from autostream_peer_registry import PeerRegistry
from autostream_sysutils import log_lifecycle
from dial_core_focus import select_volume_target
from dial_volume import start_volume_worker


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
    handlers = [
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout),
    ]
    # Identical warnings are limited per handler so a failing neighbour cannot
    # flood the SD card.
    for handler in handlers:
        log_setup.install_rate_limit(handler)
    logging.basicConfig(
        level=level,
        format="%(asctime)s: %(message)s",
        datefmt="%d-%b-%y %H:%M:%S",
        handlers=handlers,
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
        r = dial_admin.run_admin("toggle-dial-update-timer", verb, timeout=10)
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


class _HeadlessDisplay(NoOpDisplayStatusProvider):
    """Stands in for the display when its stack will not load: there is no
    screen, but the core still holds every appliance, so volume and mute
    follow the appliance the dial reports from, and warnings and the update
    watch keep running. The core is built, started and stopped by the
    caller."""

    def __init__(self, display_config) -> None:
        super().__init__()
        self.update_config(display_config)


def _core_view(core):
    """What the volume control reads of an appliance: the core's last
    published state for it (playing, since when, and whether it takes this
    dial's writes)."""
    return lambda appliance_id: core.snapshot().appliance(appliance_id)


def _start_peer_pool(cfg, core, shutdown_event):
    """The appliances as the core reads them: one registry of sightings, a
    pool holding a PeerClient for each, and the core attached to both.
    Returns (registry, pool) for the caller to stop."""
    registry = PeerRegistry(local_id=None)
    dial_mdns.attach(registry, _core_view(core))
    registry.start(shutdown_event)
    pool = PeerPool(registry, lambda peer_id: PeerClient(peer_id, client_id=f"dial:{cfg.uuid}"))
    pool.start()
    core.attach_pool(pool, registry)
    return registry, pool


def _build_volume_targets_fn(
    core, get_targets=get_display_targets, *, scope_fn=None, get_all_targets=get_playing_targets,
):
    """Zero-arg resolver for the volume worker.

    Under broadcast scope "all" (scope_fn returns SCOPE_ALL — a screenless
    dial, or one whose screen was later unfitted, cannot choose an
    appliance), every playing target with auth != "unauthorized" and an
    identity is returned, focus ignored: a fleet-wide twist has no single appliance to
    pin to. Otherwise (scope_fn absent or returning anything else) today's
    single-target behaviour: a manual focus (playing or idle) the dial is
    following, when it has one, else the core's artwork source, else the
    oldest playing target — as a list of zero or one target.

    core may be any object with the two accessors; a missing or raising
    accessor degrades to the next step so a broken core never blocks volume
    (a failure elsewhere must never affect volume control). get_targets
    defaults to the real dial_mdns.get_display_targets, imported at module
    load time; tests override it directly for a fake target list. scope_fn,
    when supplied, is called fresh on every resolve (the live-read discipline
    every resolver here already follows), so a /screen/settings save or a
    screen being unfitted applies to the very next twist with no restart.

    Rows with a confirmed refusal (auth == "unauthorized") are excluded, as
    are rows with no identity (an unresolved legacy or identity-less
    appliance cannot be tracked or addressed). Rows
    whose auth is still "unknown" stay eligible — the encoder must be live
    from the first second, and only a definitive miss removes a row.
    """
    getter = getattr(core, "current_source_service_name", None)
    focus_getter = getattr(core, "focus_volume_target", None)

    def resolve():
        if scope_fn is not None and scope_fn() == SCOPE_ALL:
            return [t for t in get_all_targets() if t.auth != "unauthorized" and t.appliance_id]
        if focus_getter is not None:
            try:
                focused = focus_getter()
            except Exception:
                focused = None
            if focused is not None:
                return [focused]
        targets = [t for t in get_targets() if t.auth != "unauthorized" and t.appliance_id]
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
    volume, unauthorized and identity-less rows are excluded from the "all"
    fan-out; unknown rows stay eligible."""
    def resolve():
        if http_server.effective_mute_scope == SCOPE_ALL:
            return [t for t in get_all_targets() if t.auth != "unauthorized" and t.appliance_id]
        return volume_targets_fn()
    return resolve


def _build_display(cfg, core):
    """The display manager for the configured profile. A kiosk-surface profile
    (a browser on an HD panel) has no SPI view, so the headless stand-in runs
    the core for it. Otherwise the SPI display stack is imported lazily so a
    Pillow/display-stack import failure (e.g. an incomplete apt install)
    degrades to the same stand-in rather than taking the service down."""
    if get_profile_or_default(cfg.display.screen_type).surface == "kiosk":
        return _HeadlessDisplay(cfg.display)
    try:
        from dial_display import create_dial_display
        return create_dial_display(cfg, core)
    except ImportError as e:
        logging.warning("dial display: display stack unavailable (%s) — display disabled", e)
        return _HeadlessDisplay(cfg.display)


def _build_inputs(core, http_server, view_hooks):
    """The encoder, button and control-socket callbacks, as
    (nudge_up, nudge_down, nudge_delta, on_press).

    Each physical use first confirms presence for PIN recovery, then tells
    every view hook which input it was ("volume" for a nudge, "mute" for the
    button; a hook that raises never blocks the input), then asks the core
    for the volume step or mute toggle. The nudges return the step they
    asked for, which the control socket reports. A nudge of zero (control
    socket only) does not confirm presence and tells no hook."""
    def tell_views(kind: str) -> None:
        for hook in view_hooks:
            try:
                hook(kind)
            except Exception:
                pass

    def nudge_up() -> int:
        http_server.confirm_volume()
        tell_views("volume")
        delta = http_server.step_percent
        core.volume_step(delta)
        return delta

    def nudge_down() -> int:
        http_server.confirm_volume()
        tell_views("volume")
        delta = -http_server.step_percent
        core.volume_step(delta)
        return delta

    def nudge_delta(delta: int) -> int:
        if delta != 0:
            http_server.confirm_volume()
        core.volume_step(delta)
        return delta

    def on_press() -> None:
        http_server.confirm_volume()
        tell_views("mute")
        core.mute_toggle()

    return nudge_up, nudge_down, nudge_delta, on_press


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

    recovery_armed = begin_run(cfg.pin)

    # The core is built first: it does no I/O and starts no thread here, and
    # everything below that acts on appliances (the display, the workers,
    # the inputs) is handed it. It is started further down, after the
    # splash, and stopped in the finally block.
    core = create_dial_core(cfg)

    # The display is built and lit before anything else that costs time
    # (the update-timer reconcile and the announce verb both fork
    # subprocesses), so the panel shows "Starting..." as early as the
    # process can manage. Imported lazily so a Pillow/display-stack import
    # failure (e.g. an incomplete apt install) degrades to a screenless
    # display, with the core still running, rather than taking down the
    # whole service — volume control must not depend on Pillow.
    display = _build_display(cfg, core)
    # The boot splash: opens the manager's one backend and paints
    # "Starting..." now, before any display thread exists; display.start()
    # below reuses that open and the first fold replaces the splash.
    # getattr guards the NoOpDisplayStatusProvider fallback, which has no
    # screen. show_starting() never raises.
    show_starting = getattr(display, "show_starting", None)
    if show_starting is not None:
        show_starting()

    _reconcile_update_timer(cfg.auto_update)
    _announce_self(cfg)

    led = DialLED(cfg.led_gpio)

    http_server = DialHTTPServer(cfg, display_status_provider=display)
    http_server.start()

    # The HD page's loopback server runs on every dial. A port that cannot be
    # bound costs the page, never the dial.
    hd_server = None
    hd_hub = None
    hd_panel = None
    try:
        hd_hub = ChangeHub(core)
        kiosk_surface = get_profile_or_default(cfg.display.screen_type).surface == "kiosk"

        def panel_inputs() -> tuple[bool, bool, bool]:
            due = core.warnings.due_status()
            snap = core.snapshot()
            return (
                bool(snap.visible_playing),
                bool(due is not None and due.interrupting),
                # a PIN being asked for holds the panel awake
                awaiting_pin(snap.outputs_request, time.monotonic()),
            )

        hd_panel = HdPanel(
            hd_hub, settings=lambda: http_server.display_config,
            backlight=(
                detect_backlight(power_off_asleep=lambda: http_server.display_config.panel_power_off)
                if kiosk_surface else None
            ), inputs=panel_inputs,
            kiosk=kiosk_surface,
        )
        hd_server = HdServer(
            cfg, core, http_server=http_server, panel=hd_panel, hub=hd_hub, port=cfg.hd_port,
            info_fn=lambda: gather_dial_info(
                http_server.get_runtime_status()["name"], VERSION,
                network=network_latest(), sd_health=dial_sdhealth.info_value(), uuid=cfg.uuid,
            ),
        )
        hd_hub.start()
        hd_server.start()
        hd_panel.start()
        # Screen settings are part of the state the page shows, and the
        # panel follows a changed brightness.
        http_server.add_cfg_listener(lambda new_cfg: hd_panel.apply_settings())
        http_server.add_cfg_listener(lambda new_cfg: hd_hub.publish())
        # The development listener follows the config: switched on or off, and
        # its sessions dropped when the PIN changes.
        http_server.add_cfg_listener(hd_server.on_config)
        hd_server.on_config(cfg)
    except OSError as e:
        logging.warning("HD server not started: %s", e)
        if hd_panel is not None:
            hd_panel.stop()
        if hd_hub is not None:
            hd_hub.stop()
        hd_server = None
        hd_hub = None
        hd_panel = None

    # What the core publishes about this dial, and how far a mute reaches,
    # read live from the HTTP server so a /configure or /screen/settings
    # change applies without a restart. Set once the server exists, before
    # the core thread starts.
    core.set_mute_scope(lambda: http_server.effective_mute_scope)
    core.set_volume_scope(lambda: http_server.effective_volume_scope)
    core.set_identity(lambda: http_server.get_runtime_status()["name"], VERSION, cfg.port)
    core.set_address_source(current_ipv4)

    if recovery_armed:
        http_server.begin_recovery_window()

    # Wired here, after the HTTP server exists (its get_runtime_status()
    # supplies the dial's live name) and before display.start() (so the
    # provider is in place before the repeat thread can ever open the info
    # page). hasattr guards the screenless fallback above, which has no
    # screen and so no provider to set.
    if hasattr(display, "set_info_provider"):
        display.set_info_provider(
            lambda: gather_dial_info(
                http_server.get_runtime_status()["name"], VERSION,
                network=network_latest(), sd_health=dial_sdhealth.info_value(), uuid=cfg.uuid,
            )
        )
    # Every sighted appliance is held by its own client in the pool, and the
    # core reads them all from there; its request lane, the one sender of the
    # screens' speaker, EQ and repeat requests, starts with the core.
    peer_registry, peer_pool = _start_peer_pool(cfg, core, shutdown_event)
    # The core's thread starts before the view's, so the first fold is not
    # held up by the panel; what the core publishes in between is folded in
    # by the view when it starts.
    core.start()
    display.start()

    # Volume/mute broadcast scope (see dial_volume.py's module docstring):
    # each addresses the core's single reporting-from target, unless the
    # dial's live effective scope is "all" (a screenless dial, or a screened
    # one whose choice says "all"), in which case it addresses every playing
    # target instead. See _build_volume_targets_fn/_build_mute_targets_fn.
    volume_targets_fn = _build_volume_targets_fn(
        core, scope_fn=lambda: http_server.effective_volume_scope,
    )
    start_volume_worker(
        volume_targets_fn, led,
        mute_targets_fn=_build_mute_targets_fn(http_server, volume_targets_fn),
        on_readout_changed=core.readout_changed,
        on_mute_changed=core.mute_changed,
        client_for=peer_pool.get,
    )

    # The Wi-Fi link poller: its own thread, one loopback read of the local
    # watcher every 15 s (see dial_network.py's module docstring). Feeds the
    # core, which carries the link for the idle screen's status glyph and
    # the No-WiFi warning. The SD card health reader rides the same thread
    # through on_tick, reading its files at most every ten minutes (see
    # dial_sdhealth.py).
    dial_sdhealth.start(on_view=core.on_sd_health_view)
    start_network_worker(on_view=core.on_network_view, on_tick=dial_sdhealth.tick)

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
            touch_source = build_touch_source(
                cfg, display, confirm_presence=http_server.confirm_volume,
                step_percent=lambda: http_server.step_percent, core=core,
            )
            touch_source.start()
            touch_runtime = cfg.display.touch_type
        except Exception as e:
            logging.warning("dial touch: touch stack unavailable (%s) — touch disabled", e)
            touch_source = None
            touch_runtime = "failed"
    http_server.set_touch_runtime(touch_runtime)

    # ---- Shared nudge callbacks (passed to both encoder and control socket) ----

    # A screen is told of each physical input so it can react (the repeat
    # screen returns to the volume readout); a screenless dial has no hook.
    view_hooks = [display.on_input] if hasattr(display, "on_input") else []
    nudge_up, nudge_down, nudge_delta, on_press = _build_inputs(core, http_server, view_hooks)

    # ---- Local control socket ----

    control_server = DialControlServer(
        get_runtime_status=http_server.get_runtime_status,
        get_targets=get_playing_targets,
        enrich_targets=core_target_records(core),
        nudge_up=nudge_up,
        nudge_down=nudge_down,
        nudge_delta=nudge_delta,
        software_version=VERSION,
    )

    # Import GPIO helpers lazily — non-Pi hosts can still run the HTTP service.
    try:
        from autostream_dial_gpio import setup_rotary_encoder, setup_button  # type: ignore[import]
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
        inputs = []
        if encoder is not None:
            inputs.append("encoder")
        if button is not None:
            inputs.append("button")
        if touch_source is not None:
            inputs.append("touch:" + touch_runtime)
        # An HD page can confirm presence itself.
        if get_profile_or_default(cfg.display.screen_type).surface == "kiosk":
            inputs.append("touch:hd")
        core.set_inputs(inputs)
        http_server.set_can_confirm_presence(bool(inputs))

        while not shutdown_event.wait(5):
            led.set_playing() if get_playing_targets() else led.set_idle()
    finally:
        end_run()
        if hd_server is not None:
            hd_server.stop()
        if hd_panel is not None:
            hd_panel.stop()
        if hd_hub is not None:
            hd_hub.stop()
        if touch_source is not None:
            touch_source.stop()
        core.stop()
        peer_pool.stop()
        peer_registry.stop()
        display.stop()
        control_server.stop()
        http_server._server.shutdown()


if __name__ == '__main__':
    main()
