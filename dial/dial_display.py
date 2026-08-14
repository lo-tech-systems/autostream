"""dial_display.py — Dial display manager facade.

Owns threading, fallback policy (logo vs artwork), image identity dedupe,
error handling, and the no-op path for display-disabled installs. Consumes
the mDNS display-selection helpers (get_display_targets() /
mark_display_target_unauthorized()) — never the volume fan-out
get_playing_targets(), which is unrelated and unaffected by display state.

Display failure must always degrade to a no-op display; it must never affect
volume control. Backend hardware code lives in dial_display_adafruit.py;
Pillow-only image policy lives in dial_display_image.py.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import dataclasses
import hashlib
import logging
import os
import sys
import threading
import time
from dataclasses import dataclass

from PIL import Image

from dial_display_image import (
    MAX_ARTWORK_RESPONSE_BYTES,
    decode_artwork,
    load_logo,
    transform_artwork_for_panel,
)
from dial_display_profiles import (
    DEFAULT_PROFILE_KEY,
    UnknownDisplayProfileError,
    get_profile,
)
from dial_target_status import fetch_target_status

# The artwork fetch is shared with the OwnTone metadata publisher, which also
# turns provider URLs into images. It faces the open internet, so it lives in
# one place rather than being copied here (see core/autostream_artwork.py).
# The dial deployment copies core modules alongside the dial package; in the
# repo they live in core/, which may or may not be on sys.path.
try:
    from autostream_artwork import artwork_url_eligible, fetch_artwork
except ImportError:
    _core = os.path.join(os.path.dirname(__file__), '..', 'core')
    sys.path.insert(0, os.path.abspath(_core))
    from autostream_artwork import artwork_url_eligible, fetch_artwork

DEFAULT_DISPLAY_LOGO_PATH = "/opt/autostream/images/autostream-logo-centred-dark.png"

# Fallback compose dimensions for when no backend is open yet (or it just
# closed) — the default profile's landscape 160x128, matching today's only
# shipped panel.
_DEFAULT_PANEL_WIDTH = get_profile(DEFAULT_PROFILE_KEY).width
_DEFAULT_PANEL_HEIGHT = get_profile(DEFAULT_PROFILE_KEY).height

DISPLAY_POLL_INTERVAL_SECONDS = 6
DIAL_STATUS_TIMEOUT_SECONDS = 2.0
ARTWORK_FETCH_TIMEOUT_SECONDS = 2.0
DISPLAY_IDLE_SLEEP_SECONDS = 15 * 60


def _fetch_artwork(url: str, timeout: float) -> tuple[bytes | None, str]:
    """Fetch artwork for the panel, at the dial's own size ceiling."""
    return fetch_artwork(url, timeout, MAX_ARTWORK_RESPONSE_BYTES)


# ---------------------------------------------------------------------------
# Rate-limited logging
# ---------------------------------------------------------------------------

class _RateLimitedLogger:
    """Emits the first occurrence and every 10th consecutive repeat of a key.

    A different key resets the count so its own first occurrence is visible
    immediately, per the dial logging policy.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_key: str | None = None
        self._count = 0

    def log(self, level: int, key: str, msg: str, *args) -> None:
        with self._lock:
            if key != self._last_key:
                self._last_key = key
                self._count = 1
            else:
                self._count += 1
            should_log = self._count == 1 or self._count % 10 == 0
        if should_log:
            logging.log(level, msg, *args)


def _url_log_key(url: str) -> str:
    """Short, non-reversible identifier for a provider URL, safe at INFO/WARNING."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Runtime status
# ---------------------------------------------------------------------------

@dataclass
class DisplayRuntimeStatus:
    fitted: bool
    rotate: bool
    screen_type: str
    bgr: bool
    active: bool
    backend: str
    backend_loaded: bool
    showing: str
    last_error: str
    last_error_at: float | None
    display_sleeping: bool
    display_idle_seconds: int

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Backend protocol
# ---------------------------------------------------------------------------

class DisplayBackend:
    name = "backend"
    # Sourced from the default profile rather than hardcoded — these were
    # previously 128/160, the transpose of the real landscape panel (see
    # dial_display_profiles.py for why the panel is 160 wide x 128 tall).
    width = _DEFAULT_PANEL_WIDTH
    height = _DEFAULT_PANEL_HEIGHT

    def open(self) -> None: ...

    def close(self) -> None: ...

    def clear(self) -> None: ...

    def display(self, image) -> None: ...

    def sleep(self) -> None: ...

    def wake(self) -> None: ...


class NoOpBackend(DisplayBackend):
    name = "noop"
    width = _DEFAULT_PANEL_WIDTH
    height = _DEFAULT_PANEL_HEIGHT

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    def clear(self) -> None:
        pass

    def display(self, image) -> None:
        pass

    def sleep(self) -> None:
        pass

    def wake(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Display manager
# ---------------------------------------------------------------------------

class DialDisplay:
    def __init__(
        self,
        config,
        get_display_targets,
        mark_display_target_unauthorized,
        dial_id: str,
        logo_path: str = DEFAULT_DISPLAY_LOGO_PATH,
        backend_factory=NoOpBackend,
        backend_factory_builder=None,
    ) -> None:
        self._lock = threading.Lock()
        self._config = config
        self._get_display_targets = get_display_targets
        self._mark_unauthorized = mark_display_target_unauthorized
        self._dial_id = dial_id
        self._logo_path = logo_path
        self._backend_factory = backend_factory
        # Optional screen_type -> zero-arg-backend-factory resolver, used to
        # rebuild self._backend_factory on a live screen_type swap. Left as
        # an injected callable (rather than importing a concrete backend
        # module here) so this facade stays free of hardware-specific
        # coupling; create_dial_display() supplies the real profile-driven
        # resolver, and tests that never swap can leave this unset.
        self._backend_factory_builder = backend_factory_builder

        self._backend: DisplayBackend | None = None
        self._backend_name = "noop"
        # Profile key of the backend actually open right now ("" when none).
        # Distinct from self._config.screen_type, which is what was REQUESTED.
        self._active_screen_type = ""
        self._backend_open = False
        self._backend_loaded = False
        self._showing = "noop"
        self._last_error = ""
        self._last_error_at: float | None = None

        # Artwork identity dedupe state — only the current rendered image is
        # kept in memory; nothing persists across restart.
        self._source_artwork_url = ""
        self._current_rendered_image = None

        # Idle/sleep state — set while the display has shown the logo with no
        # playing targets on the network; cleared on any activity or disable.
        self._idle_started_at: float | None = None
        self._display_sleeping = False

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._log_limiter = _RateLimitedLogger()

    # ---- lifecycle -------------------------------------------------------

    def start(self) -> None:
        with self._lock:
            if self._config.fitted:
                self._enable_locked()
        self._stop_event.clear()
        try:
            self._thread = threading.Thread(target=self._run, daemon=True, name="dial-display")
            self._thread.start()
        except Exception as e:
            # Must never prevent the rest of dial_main.py's startup/shutdown
            # sequence (volume control, mDNS, control socket) from running.
            logging.warning("dial display: failed to start polling thread: %s", e)
            self._thread = None

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            try:
                self._thread.join(timeout=2)
            except RuntimeError:
                # Thread.start() had not finished registering when stop() ran
                # right behind it — the daemon thread still exits on its own
                # once _stop_event is set.
                pass
        with self._lock:
            self._disable_locked()

    # ---- public facade -----------------------------------------------------

    def get_status(self) -> dict:
        with self._lock:
            if self._idle_started_at is None:
                idle_seconds = 0
            else:
                idle_seconds = min(
                    DISPLAY_IDLE_SLEEP_SECONDS,
                    int(time.monotonic() - self._idle_started_at),
                )
            return DisplayRuntimeStatus(
                fitted=self._config.fitted,
                rotate=self._config.rotate,
                # The ACTIVE profile, not the configured one: after a failed
                # swap the configured key is the one that would not open, so
                # reporting it here would hide exactly the drift this field
                # exists to expose. Empty while no backend is open.
                screen_type=self._active_screen_type,
                bgr=self._config.bgr,
                active=self._backend_open and self._backend_name != "noop",
                backend=self._backend_name,
                backend_loaded=self._backend_loaded,
                showing=self._showing,
                last_error=self._last_error,
                last_error_at=self._last_error_at,
                display_sleeping=self._display_sleeping,
                display_idle_seconds=idle_seconds,
            ).to_dict()

    def update_config(self, config) -> dict:
        with self._lock:
            old_config = self._config
            self._config = config
            screen_type_changed = old_config.screen_type != config.screen_type
            if screen_type_changed:
                # Rebuild unconditionally, NOT only when fitted: a screen_type
                # change accepted while the display is off must still be in
                # force when it is later switched on. Rebuilding only under
                # `fitted` leaves the stale factory in place, and the later
                # enable sees no screen_type change to react to — so it would
                # silently open the previous profile while status and disk
                # both report the new one.
                self._rebuild_backend_factory_locked(config.screen_type)
            if config.fitted:
                if screen_type_changed and self._backend_open:
                    # Swap branch takes precedence over the rotate/bgr
                    # redisplay branch below — for this same update_config()
                    # call the two are mutually exclusive. Redisplaying a
                    # cached frame composed at the OLD backend's dimensions
                    # against the new backend would push a wrong-size frame
                    # (the backend would silently letterbox it), so the swap
                    # clears the cache instead and lets the next poll (or the
                    # logo render below) recompose at the new dims.
                    self._swap_backend_locked()
                else:
                    self._enable_locked()
                    # _enable_locked() is a no-op when the backend is already
                    # open, so a rotate/bgr-only toggle needs its own path
                    # here — re-display the current frame under the new
                    # settings immediately rather than waiting for the next
                    # poll. Never runs alongside a screen_type change (see
                    # the swap branch above).
                    redisplay_changed = (
                        old_config.fitted and not screen_type_changed
                        and (old_config.rotate != config.rotate or old_config.bgr != config.bgr)
                    )
                    if redisplay_changed and self._backend_open:
                        self._redisplay_current_locked()
            else:
                self._disable_locked()
        return self.get_status()

    def enable(self) -> None:
        with self._lock:
            self._enable_locked()

    def disable(self) -> None:
        with self._lock:
            self._disable_locked()

    def clear(self) -> None:
        with self._lock:
            self._clear_locked()

    def show_logo(self) -> None:
        with self._lock:
            if not (self._backend_open and self._backend is not None):
                return
            if self._showing == "logo":
                return
            self._render_logo_locked()

    def display(self, image) -> None:
        with self._lock:
            self._display_locked(image)

    # ---- backend lifecycle (caller must hold self._lock) -------------------

    def _enable_locked(self) -> None:
        if self._backend_open:
            return
        backend = self._backend_factory()
        try:
            backend.open()
        except Exception as e:
            self._record_error_locked("backend_open_failed")
            logging.warning("dial display: backend open failed — degrading to no-op: %s", e)
            return
        self._backend = backend
        self._backend_name = getattr(backend, "name", "noop")
        self._active_screen_type = self._config.screen_type
        self._backend_open = True
        self._backend_loaded = True
        # A successful open clears any stale unrelated failure — today only
        # a successful artwork render did this, so a successful screen_type
        # swap would otherwise keep reporting a stale error and defeat drift
        # detection.
        self._last_error = ""
        self._last_error_at = None
        logging.info(
            "dial display: backend %s open (%dx%d)",
            self._backend_name, backend.width, backend.height,
        )
        # Rendering the logo here is the awake state — reset any stale idle
        # timer/sleep flag from before this open.
        self._idle_started_at = None
        self._display_sleeping = False
        self._render_logo_locked()

    def _rebuild_backend_factory_locked(self, screen_type: str) -> None:
        """Rebuild self._backend_factory for *screen_type* via the injected
        resolver, so the next _enable_locked() opens the right backend.

        A no-op when no resolver was supplied (see backend_factory_builder
        in __init__) — the manager simply keeps using its original factory.
        """
        if self._backend_factory_builder is None:
            return
        self._backend_factory = self._backend_factory_builder(screen_type)

    def _swap_backend_locked(self) -> None:
        """Close the currently open backend and reopen via the (already
        rebuilt) factory — used when screen_type changes while fitted and
        open. If the new backend fails to open, _enable_locked()'s existing
        degrade-to-noop path holds and runtime reflects it.
        """
        if self._backend_open and self._backend is not None:
            try:
                self._backend.close()
            except Exception as e:
                logging.debug("dial display: backend close raised during swap: %s", e)
        self._backend = None
        self._backend_open = False
        self._backend_loaded = False
        self._backend_name = "noop"
        self._active_screen_type = ""
        # Drop the cached frame and its source identity before reopening: it
        # was composed at the OLD panel's dimensions. A successful
        # _enable_locked() renders the logo (which clears these anyway), but
        # on a failed open the stale frame and URL would otherwise survive
        # into the degraded state and be reused by the next poll.
        self._showing = "noop"
        self._source_artwork_url = ""
        self._current_rendered_image = None
        self._enable_locked()

    def _disable_locked(self) -> None:
        if self._backend_open and self._backend is not None:
            try:
                self._backend.close()
            except Exception as e:
                logging.debug("dial display: backend close raised: %s", e)
        self._backend = None
        self._backend_open = False
        self._backend_loaded = False
        self._backend_name = "noop"
        self._active_screen_type = ""
        self._showing = "noop"
        self._source_artwork_url = ""
        self._current_rendered_image = None
        self._idle_started_at = None
        self._display_sleeping = False

    def _clear_locked(self) -> None:
        if self._backend_open and self._backend is not None:
            try:
                self._backend.clear()
            except Exception as e:
                logging.debug("dial display: backend clear raised: %s", e)
        self._showing = "noop"

    def _sleep_locked(self) -> None:
        if self._backend_open and self._backend is not None:
            try:
                self._backend.sleep()
            except Exception as e:
                self._record_error_locked("display_sleep_failed")
                logging.debug("dial display: backend sleep raised: %s", e)
        self._display_sleeping = True
        self._showing = "sleeping"
        self._source_artwork_url = ""
        self._current_rendered_image = None
        logging.info("dial display: idle %ds — sleeping", DISPLAY_IDLE_SLEEP_SECONDS)

    def _wake_locked(self) -> None:
        if self._backend_open and self._backend is not None:
            try:
                self._backend.wake()
            except Exception as e:
                self._record_error_locked("display_wake_failed")
                logging.debug("dial display: backend wake raised: %s", e)
        self._display_sleeping = False
        # The cached-artwork fast path in _show_artwork and the show_logo
        # dedupe both skip rendering when _showing looks unchanged — force
        # the next render to actually paint by clearing the known artwork
        # url and setting a showing value neither path treats as "already
        # shown".
        self._showing = "waking"
        self._source_artwork_url = ""
        logging.info("dial display: activity resumed — waking")

    def _record_error_locked(self, error_id: str) -> None:
        self._last_error = error_id
        self._last_error_at = time.time()

    def _record_error(self, error_id: str) -> None:
        with self._lock:
            self._record_error_locked(error_id)

    def _active_panel_dims(self) -> tuple[int, int]:
        """Return the open backend's panel dimensions, falling back to the
        default profile's dimensions when no backend is open (e.g. between
        close() and the next open()).

        May be called with or without self._lock held. The HTTP thread can
        swap or close the backend concurrently (update_config runs there), so
        the reference is snapshotted into a local before use rather than being
        dereferenced through self — otherwise a swap landing between the
        _backend_open check and the width read would raise on None.

        These dimensions are therefore advisory: a frame composed against them
        can still be superseded by a swap while it is being built. That is why
        the size is re-checked under the lock before the frame is pushed (see
        _show_artwork) — the guard, not this read, is what keeps a wrong-sized
        frame off the panel.
        """
        backend = self._backend
        if self._backend_open and backend is not None:
            return backend.width, backend.height
        return _DEFAULT_PANEL_WIDTH, _DEFAULT_PANEL_HEIGHT

    def _apply_frame_transform(self, image):
        """Apply configured rotate/BGR transforms for display hand-off.

        Applied here, at the single point every frame reaches the backend,
        so self._current_rendered_image stays untransformed in the cache and
        a rotate/bgr toggle can re-display it under the new settings without
        re-fetching or re-transforming artwork. Rotate (180°) is applied
        before the BGR channel swap; the order is arbitrary since the two
        operations commute, but is kept consistent here.

        This seam is bypassed by the backend-internal clear()/sleep() fills,
        which paint directly against the backend rather than going through
        _display_locked(). sleep()'s black fill is swap-symmetric so that is
        harmless; clear()'s background colour is not — an accepted cosmetic
        exception, limited to the fallback background and never artwork.
        """
        if image is None:
            return image
        if self._config.rotate:
            image = image.transpose(Image.ROTATE_180)
        if self._config.bgr:
            image = Image.merge("RGB", image.split()[::-1])
        return image

    def _display_locked(self, image) -> None:
        if not (self._backend_open and self._backend is not None):
            return
        try:
            self._backend.display(self._apply_frame_transform(image))
        except Exception as e:
            self._record_error_locked("display_write_failed")
            self._log_limiter.log(
                logging.WARNING, "display_write_failed",
                "dial display: backend write failed: %s", e,
            )

    def _redisplay_current_locked(self) -> None:
        """Re-display the current frame synchronously — used when rotate
        changes while already fitted and open, so the new orientation is
        visible immediately rather than at the next poll.
        """
        if not (self._backend_open and self._backend is not None):
            return
        if self._current_rendered_image is not None:
            self._display_locked(self._current_rendered_image)
        else:
            self._render_logo_locked()

    # ---- logo fallback -------------------------------------------------

    def _render_logo_locked(self) -> None:
        width, height = self._active_panel_dims()
        image = load_logo(self._logo_path, width, height)
        if image is None:
            self._record_error_locked("logo_unavailable")
            self._log_limiter.log(
                logging.WARNING, "logo_unavailable",
                "dial display: logo unavailable at %s", self._logo_path,
            )
            self._clear_locked()
            return
        was_showing = self._showing
        self._display_locked(image)
        self._source_artwork_url = ""
        self._current_rendered_image = None
        self._showing = "logo"
        if was_showing == "artwork":
            logging.info("dial display: showing logo (no usable artwork)")

    # ---- polling loop ----------------------------------------------------

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception:
                logging.debug("dial display: poll iteration raised", exc_info=True)
            # Wait from the end of this loop so slow polls never accumulate
            # into a backlog.
            self._stop_event.wait(DISPLAY_POLL_INTERVAL_SECONDS)

    def _poll_once(self) -> None:
        with self._lock:
            fitted = self._config.fitted
        if not fitted:
            return

        targets = self._get_display_targets()

        # Any visible playing target counts as activity — including
        # unauthorized or status-erroring ones — because the mDNS
        # _autostream-playing._tcp presence alone means audio is playing
        # somewhere on the network, regardless of whether this dial's
        # display is allowed to source artwork from it.
        if targets:
            with self._lock:
                self._idle_started_at = None
                if self._display_sleeping:
                    self._wake_locked()
        else:
            with self._lock:
                if self._idle_started_at is None:
                    self._idle_started_at = time.monotonic()
                if self._display_sleeping:
                    # Stay dark — no repaint while asleep.
                    return
                should_sleep = (
                    time.monotonic() - self._idle_started_at >= DISPLAY_IDLE_SLEEP_SECONDS
                )
                if should_sleep:
                    self._sleep_locked()
                    return
            self.show_logo()
            return

        selected_url = None
        for target in targets:
            if not target.display_authorized:
                logging.debug("dial display: skip unauthorized row %s", target.service_name)
                continue
            if not target.dial_status:
                logging.debug("dial display: skip unsupported target %s", target.service_name)
                continue

            result = fetch_target_status(target, self._dial_id, timeout_seconds=DIAL_STATUS_TIMEOUT_SECONDS)
            status_error = result.get("status_error")
            if status_error == "unauthorized":
                self._mark_unauthorized(target)
                continue
            if status_error:
                logging.debug(
                    "dial display: target %s status_error=%s", target.service_name, status_error,
                )
                continue

            track_id = result.get("track_id")
            if track_id and track_id.get("state") == "identified" and track_id.get("artwork_url"):
                selected_url = track_id["artwork_url"]
                break

        if selected_url:
            self._show_artwork(selected_url)
        else:
            self.show_logo()

    # ---- artwork selection -------------------------------------------------

    def _show_artwork(self, url: str) -> None:
        with self._lock:
            if not (self._backend_open and self._backend is not None):
                return
            if url == self._source_artwork_url and self._showing == "artwork":
                logging.debug("dial display: unchanged artwork url reuse")
                return
            cached_reusable = (
                url == self._source_artwork_url and self._current_rendered_image is not None
            )
            if cached_reusable:
                was_showing = self._showing
                self._display_locked(self._current_rendered_image)
                self._showing = "artwork"
                if was_showing == "logo":
                    logging.info("dial display: showing artwork")
                return

        if not artwork_url_eligible(url):
            logging.debug("dial display: unsupported artwork url candidate")
            self.show_logo()
            return

        # Fetch, decode, and transform happen outside the lock so a slow
        # network round-trip never blocks a settings change. This is the only
        # thread that changes which artwork is SELECTED, so no mid-fetch
        # cancellation is needed — but it is not the only thread touching
        # display state: the HTTP thread can swap or close the backend
        # underneath this work via update_config. The re-check below, taken
        # under the lock, is what makes that safe.
        url_key = _url_log_key(url)
        data, err = _fetch_artwork(url, ARTWORK_FETCH_TIMEOUT_SECONDS)
        if err:
            self._record_error("artwork_fetch_failed")
            self._log_limiter.log(
                logging.WARNING, f"artwork_fetch:{url_key}",
                "dial display: artwork fetch failed (%s): %s", url_key, err,
            )
            self.show_logo()
            return

        image = decode_artwork(data)
        if image is None:
            self._record_error("artwork_decode_failed")
            self._log_limiter.log(
                logging.WARNING, f"artwork_decode:{url_key}",
                "dial display: artwork decode failed (%s)", url_key,
            )
            self.show_logo()
            return

        width, height = self._active_panel_dims()
        transformed = transform_artwork_for_panel(image, width, height)

        with self._lock:
            if not (self._backend_open and self._backend is not None):
                return
            if transformed.size != (self._backend.width, self._backend.height):
                # A screen_type swap raced with this fetch/transform, which
                # ran outside the lock against the backend that was active
                # at the time — composed for its (now superseded) dims. Drop
                # the stale-sized frame rather than letting the new backend
                # silently letterbox it; the next poll recomposes at the now
                # -active dims.
                logging.debug(
                    "dial display: dropping frame sized for a superseded backend"
                )
                return
            was_showing = self._showing
            self._display_locked(transformed)
            self._source_artwork_url = url
            self._current_rendered_image = transformed
            self._showing = "artwork"
            self._last_error = ""
            self._last_error_at = None

        logging.info("dial display: artwork replaced (%s)", url_key)
        if was_showing == "logo":
            logging.info("dial display: showing artwork")


def _adafruit_backend_factory_for_screen_type(screen_type: str):
    """Resolve *screen_type* to a zero-arg AdafruitDisplayBackend factory,
    falling back to the default profile if the key is unresolvable.

    dial_display_adafruit imports hardware modules only inside its open()
    method, so importing it here is safe even when no screen is fitted or
    the Adafruit package is absent — screen_type resolution itself never
    touches hardware.
    """
    from dial_display_adafruit import AdafruitDisplayBackend

    try:
        profile = get_profile(screen_type)
    except UnknownDisplayProfileError:
        profile = get_profile(DEFAULT_PROFILE_KEY)
    return lambda: AdafruitDisplayBackend(profile)


def create_dial_display(cfg, get_display_targets, mark_display_target_unauthorized) -> DialDisplay:
    """Build the display manager for dial_main.py wiring.

    Builds the backend factory from the configured profile (cfg.display.
    screen_type) at startup, falling back to the default profile if the key
    is unresolvable; whether it is ever opened is controlled by the fitted
    flag in DialDisplay.enable()/update_config(), not by this factory
    choice. Also wires the screen_type -> factory resolver so a live
    screen_type change can rebuild and swap the backend without a restart.
    """
    return DialDisplay(
        config=cfg.display,
        get_display_targets=get_display_targets,
        mark_display_target_unauthorized=mark_display_target_unauthorized,
        dial_id=cfg.uuid,
        backend_factory=_adafruit_backend_factory_for_screen_type(cfg.display.screen_type),
        backend_factory_builder=_adafruit_backend_factory_for_screen_type,
    )
