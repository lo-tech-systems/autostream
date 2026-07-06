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
import ipaddress
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

from dial_display_image import (
    MAX_ARTWORK_RESPONSE_BYTES,
    decode_artwork,
    load_logo,
    transform_artwork_for_panel,
)
from dial_target_status import fetch_target_status

DEFAULT_DISPLAY_LOGO_PATH = "/opt/autostream/images/autostream-logo-centred-dark.png"

DISPLAY_POLL_INTERVAL_SECONDS = 6
DIAL_STATUS_TIMEOUT_SECONDS = 2.0
ARTWORK_FETCH_TIMEOUT_SECONDS = 2.0
_MAX_ARTWORK_REDIRECTS = 2
_ARTWORK_CONTENT_TYPES = ("image/jpeg", "image/png", "image/webp")


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
# Artwork URL eligibility (stricter than general Track ID provider URL rules)
# ---------------------------------------------------------------------------

def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def artwork_url_eligible(url: str) -> bool:
    """https-only, DNS hostname, no IP literal, no .local, no explicit non-default port."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme != "https":
        return False
    hostname = parsed.hostname
    if not hostname:
        return False
    if hostname.endswith(".local"):
        return False
    if _is_ip_literal(hostname):
        return False
    if parsed.port is not None and parsed.port != 443:
        return False
    return True


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _fetch_artwork(url: str, timeout: float) -> tuple[bytes | None, str]:
    """Fetch one provider artwork URL with explicit, revalidated redirects.

    Returns (data, error). error is "" on success. Redirect targets are
    revalidated against the same eligibility rules; a chain longer than two
    hops is treated as a fetch failure.
    """
    opener = urllib.request.build_opener(_NoRedirectHandler)
    current_url = url

    for _ in range(_MAX_ARTWORK_REDIRECTS + 1):
        if not artwork_url_eligible(current_url):
            return None, "ineligible_url"

        logging.debug("dial display: fetching artwork %s", current_url)
        req = urllib.request.Request(current_url, headers={"User-Agent": "autostream-dial"})
        try:
            resp = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            # _NoRedirectHandler.redirect_request() returning None does not
            # stop urllib from raising HTTPError for 3xx responses — it still
            # surfaces as an exception here rather than a plain response, so
            # redirects must be handled in this branch too.
            if 300 <= e.code < 400:
                location = e.headers.get("Location") if e.headers else None
                if not location:
                    return None, "redirect_no_location"
                current_url = urllib.parse.urljoin(current_url, location)
                continue
            return None, f"http_{e.code}"
        except Exception as e:
            return None, type(e).__name__

        try:
            status = getattr(resp, "status", None) or resp.getcode()
            if 300 <= status < 400:
                location = resp.headers.get("Location")
                if not location:
                    return None, "redirect_no_location"
                current_url = urllib.parse.urljoin(current_url, location)
                continue

            if status != 200:
                return None, f"http_{status}"

            content_type = resp.headers.get("Content-Type", "")
            ct_base = content_type.split(";")[0].strip().lower()
            if ct_base not in _ARTWORK_CONTENT_TYPES:
                return None, "unsupported_content_type"

            data = resp.read(MAX_ARTWORK_RESPONSE_BYTES + 1)
            if len(data) > MAX_ARTWORK_RESPONSE_BYTES:
                return None, "oversized"
            return data, ""
        finally:
            resp.close()

    return None, "too_many_redirects"


# ---------------------------------------------------------------------------
# Runtime status
# ---------------------------------------------------------------------------

@dataclass
class DisplayRuntimeStatus:
    fitted: bool
    active: bool
    backend: str
    backend_loaded: bool
    showing: str
    last_error: str
    last_error_at: float | None

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Backend protocol
# ---------------------------------------------------------------------------

class DisplayBackend:
    name = "backend"
    width = 128
    height = 160

    def open(self) -> None: ...

    def close(self) -> None: ...

    def clear(self) -> None: ...

    def display(self, image) -> None: ...


class NoOpBackend(DisplayBackend):
    name = "noop"
    width = 128
    height = 160

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    def clear(self) -> None:
        pass

    def display(self, image) -> None:
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
    ) -> None:
        self._lock = threading.Lock()
        self._config = config
        self._get_display_targets = get_display_targets
        self._mark_unauthorized = mark_display_target_unauthorized
        self._dial_id = dial_id
        self._logo_path = logo_path
        self._backend_factory = backend_factory

        self._backend: DisplayBackend | None = None
        self._backend_name = "noop"
        self._backend_open = False
        self._backend_loaded = False
        self._showing = "noop"
        self._last_error = ""
        self._last_error_at: float | None = None

        # Artwork identity dedupe state — only the current rendered image is
        # kept in memory; nothing persists across restart.
        self._source_artwork_url = ""
        self._current_rendered_image = None

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
            return DisplayRuntimeStatus(
                fitted=self._config.fitted,
                active=self._backend_open and self._backend_name != "noop",
                backend=self._backend_name,
                backend_loaded=self._backend_loaded,
                showing=self._showing,
                last_error=self._last_error,
                last_error_at=self._last_error_at,
            ).to_dict()

    def update_config(self, config) -> dict:
        with self._lock:
            self._config = config
            if config.fitted:
                self._enable_locked()
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
        self._backend_open = True
        self._backend_loaded = True
        logging.info(
            "dial display: backend %s open (%dx%d)",
            self._backend_name, backend.width, backend.height,
        )
        self._render_logo_locked()

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
        self._showing = "noop"
        self._source_artwork_url = ""
        self._current_rendered_image = None

    def _clear_locked(self) -> None:
        if self._backend_open and self._backend is not None:
            try:
                self._backend.clear()
            except Exception as e:
                logging.debug("dial display: backend clear raised: %s", e)
        self._showing = "noop"

    def _record_error_locked(self, error_id: str) -> None:
        self._last_error = error_id
        self._last_error_at = time.time()

    def _record_error(self, error_id: str) -> None:
        with self._lock:
            self._record_error_locked(error_id)

    def _display_locked(self, image) -> None:
        if not (self._backend_open and self._backend is not None):
            return
        try:
            self._backend.display(image)
        except Exception as e:
            self._record_error_locked("display_write_failed")
            self._log_limiter.log(
                logging.WARNING, "display_write_failed",
                "dial display: backend write failed: %s", e,
            )

    # ---- logo fallback -------------------------------------------------

    def _render_logo_locked(self) -> None:
        image = load_logo(self._logo_path)
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

        selected_url = None
        for target in self._get_display_targets():
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

        # Fetch, decode, and transform happen outside the lock — this is the
        # only thread that mutates display state, so there is no concurrent
        # selection change to race against; no mid-fetch cancellation is
        # needed.
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

        transformed = transform_artwork_for_panel(image)

        with self._lock:
            if not (self._backend_open and self._backend is not None):
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


def create_dial_display(cfg, get_display_targets, mark_display_target_unauthorized) -> DialDisplay:
    """Build the display manager for dial_main.py wiring.

    Always uses the real ST7735S backend factory; whether it is ever opened
    is controlled by the fitted flag in DialDisplay.enable()/update_config(),
    not by this factory choice. dial_display_adafruit imports hardware
    modules only inside its open() method, so importing it here is safe even
    when no screen is fitted or the Adafruit package is absent.
    """
    from dial_display_adafruit import AdafruitST7735SBackend

    return DialDisplay(
        config=cfg.display,
        get_display_targets=get_display_targets,
        mark_display_target_unauthorized=mark_display_target_unauthorized,
        dial_id=cfg.uuid,
        backend_factory=AdafruitST7735SBackend,
    )
