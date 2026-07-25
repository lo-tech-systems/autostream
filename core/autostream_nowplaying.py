"""autostream_nowplaying.py

Helpers for OwnTone pipe metadata publishing and static now-playing hints.
"""

from __future__ import annotations

import base64
import errno
import json
import logging
import os
import queue
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


LOGGER = logging.getLogger(__name__)

DEFAULT_HINTS_PATH = "/etc/autostream/nowplaying_hints.json"
PIPE_METADATA_ENV = "AUTOSTREAM_ENABLE_PIPE_METADATA"

# Must not exceed PIPE_PICTURE_SIZE_MAX in OwnTone's src/inputs/pipe.c: it
# discards a metadata bundle whose picture is larger than this. The two are
# raised together; owntone-mini carries the matching 2MB limit.
MAX_PICTURE_BYTES = 2 * 1024 * 1024

# ── Shared-publisher registry ─────────────────────────────────
#
# Each AudioMonitor sharing a physical FIFO path must NOT construct its own
# OwntoneMetadataPipePublisher: two monitors can point at the SAME physical FIFO
# (e.g. input1/input2 sharing one OwnTone pipe input). Two independent
# publishers each running their own queue+thread can then interleave partial
# multi-item bundles on the wire during a same-poll-cycle handoff (a
# source_changed dispatch firing publish_end() on one monitor's publisher
# concurrently with publish_start() on the other's). Routing every monitor
# for the same path through one shared instance makes each bundle atomic
# relative to the others, since the single writer thread only ever processes
# one queued item (one full open->write->close cycle) at a time.
#
# Refcounted so config-reload teardown (AudioMonitor.stop() -> release) tears
# down the underlying thread only once the last referencing monitor for that
# path has released it, and a fresh acquire() after that creates a new
# instance -- matching the per-monitor create/close lifecycle.
_publisher_registry_lock = threading.Lock()
_publisher_registry: dict[str, list] = {}  # path -> [OwntoneMetadataPipePublisher, refcount]


def get_shared_metadata_publisher(audio_fifo_path: str) -> "OwntoneMetadataPipePublisher":
    """Return the single publisher instance for *audio_fifo_path*, creating it
    on first use. Pair every call with release_shared_metadata_publisher()."""
    with _publisher_registry_lock:
        entry = _publisher_registry.get(audio_fifo_path)
        if entry is None:
            pub = OwntoneMetadataPipePublisher(audio_fifo_path)
            _publisher_registry[audio_fifo_path] = [pub, 1]
            return pub
        entry[1] += 1
        return entry[0]


def release_shared_metadata_publisher(audio_fifo_path: str) -> None:
    """Release one reference to the publisher for *audio_fifo_path*, closing
    and dropping it once the last referencing caller has released it."""
    with _publisher_registry_lock:
        entry = _publisher_registry.get(audio_fifo_path)
        if entry is None:
            return
        entry[1] -= 1
        if entry[1] <= 0:
            del _publisher_registry[audio_fifo_path]
            entry[0].close()


@dataclass
class NowPlayingMetadata:
    title: str = "Autostream Input"
    artist: str = "Vinyl"
    album: str = "Unknown Album"
    artwork_path: Optional[str] = None


class PersistentNowPlayingCache:
    """Loads manual now-playing hints from a local JSON file."""

    def __init__(self, hints_path: Optional[str] = None) -> None:
        env_path = (os.environ.get("AUTOSTREAM_NOWPLAYING_HINTS_PATH") or "").strip()
        chosen = (hints_path or env_path or DEFAULT_HINTS_PATH).strip()
        self.hints_path = Path(chosen)
        self._lock = threading.Lock()
        self._hints_mtime = 0.0
        self._hints_cache: dict = {}

    def get_manual_hint(self, input_name: str) -> Optional[NowPlayingMetadata]:
        """Optional manual overrides from /etc/autostream/nowplaying_hints.json.

        File format examples:
        {
          "default": {"title": "Turntable", "artist": "Vinyl", "album": "Unknown"},
          "USB AUDIO  CODEC: Audio": {
            "title": "...",
            "artist": "...",
            "album": "...",
            "artwork_path": "/opt/autostream/images/autostream-badge.png"
          }
        }
        """
        try:
            if not self.hints_path.exists():
                return None
            st = self.hints_path.stat()
            with self._lock:
                if st.st_mtime > self._hints_mtime:
                    with self.hints_path.open("r", encoding="utf-8") as f:
                        data = json.load(f)
                    self._hints_cache = data if isinstance(data, dict) else {}
                    self._hints_mtime = st.st_mtime

                raw = self._hints_cache.get(input_name) or self._hints_cache.get("default")

            if not isinstance(raw, dict):
                return None

            return NowPlayingMetadata(
                title=str(raw.get("title") or "Autostream Input"),
                artist=str(raw.get("artist") or "Vinyl"),
                album=str(raw.get("album") or "Unknown Album"),
                artwork_path=(str(raw.get("artwork_path")) if raw.get("artwork_path") else None),
            )
        except Exception as e:
            LOGGER.warning("Failed loading manual now-playing hints: %s", e)
            return None


class OwntoneMetadataPipePublisher:
    """Writes Shairport-style metadata events to <audio_fifo>.metadata."""

    # OwnTone may attach metadata reader after audio autostarts.
    # Keep trying long enough to bridge restart/discovery delays.
    OPEN_RETRY_COUNT = 160
    OPEN_RETRY_SLEEP_SECONDS = 0.25

    def __init__(self, audio_fifo_path: str) -> None:
        self.audio_fifo_path = audio_fifo_path
        self.metadata_fifo_path = f"{audio_fifo_path}.metadata"
        raw = (os.environ.get(PIPE_METADATA_ENV) or "").strip().lower()
        self._enabled = raw in {"1", "true", "yes", "on"}

        if not self._enabled:
            self._cleanup_stale_fifo()
            LOGGER.info("OwnTone pipe metadata publishing disabled (set %s=1 to enable).", PIPE_METADATA_ENV)
            return

        self._queue: queue.Queue[tuple[str, Optional[NowPlayingMetadata]]] = queue.Queue()
        self._stop = threading.Event()
        # Bundle framing state: touched only from within _run(),
        # the single consumer thread, so it needs no separate lock. True from
        # the moment a session-begin ("pbeg") bundle has been emitted until a
        # matching session-end ("pend") bundle is emitted.
        self._session_open = False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def close(self) -> None:
        if not self._enabled:
            return
        self._stop.set()
        self._queue.put(("stop", None))

    def publish_start(self, meta: NowPlayingMetadata) -> None:
        """Begin a new play session: emits pbeg once, then a mdst..mden
        metadata bundle. Must be paired with a later publish_end(); for a
        metadata-only update to an already-open session use publish_refresh()
        instead (Shairport-sync convention: pbeg/pend delimit the session,
        mdst/mden delimit each metadata update within it)."""
        if not self._enabled:
            return
        self._queue.put(("start", meta))

    def publish_refresh(self, meta: NowPlayingMetadata) -> None:
        """Publish updated metadata mid-session (e.g. a track-ID match
        landing after the session already began): emits a mdst..mden bundle
        only, WITHOUT a second pbeg. If no session is
        currently open (defensive fallback -- should not happen in normal
        operation), falls back to a full session-begin bundle so the wire
        framing stays valid."""
        if not self._enabled:
            return
        self._queue.put(("refresh", meta))

    def publish_end(self) -> None:
        if not self._enabled:
            return
        self._queue.put(("end", None))

    def _cleanup_stale_fifo(self) -> None:
        p = Path(self.metadata_fifo_path)
        try:
            if p.exists() and stat.S_ISFIFO(p.stat().st_mode):
                p.unlink()
        except Exception:
            pass

    @staticmethod
    def _tag_hex(tag: str) -> str:
        b = (tag or "").encode("ascii", errors="ignore")[:4].ljust(4, b" ")
        return f"{int.from_bytes(b, 'big'):08x}"

    def _ensure_fifo(self) -> bool:
        p = Path(self.metadata_fifo_path)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        if p.exists():
            try:
                st = p.stat()
                if not stat.S_ISFIFO(st.st_mode):
                    p.unlink()
                else:
                    return True
            except Exception:
                try:
                    p.unlink()
                except Exception:
                    return False

        try:
            os.mkfifo(p, 0o644)
            return True
        except FileExistsError:
            return True
        except Exception as e:
            LOGGER.info("Could not create metadata fifo %s: %s", p, e)
            return False

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                kind, meta = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if kind == "stop":
                return

            if not self._ensure_fifo():
                continue

            fd = None
            for _ in range(self.OPEN_RETRY_COUNT):
                try:
                    fd = os.open(self.metadata_fifo_path, os.O_WRONLY | os.O_NONBLOCK)
                    break
                except OSError as e:
                    if e.errno in (errno.ENXIO, errno.ENOENT):
                        time.sleep(self.OPEN_RETRY_SLEEP_SECONDS)
                        continue
                    LOGGER.info("Metadata fifo open failed: %s", e)
                    break

            if fd is None:
                LOGGER.info(
                    "Metadata fifo writer gave up waiting for reader after %.1fs",
                    self.OPEN_RETRY_COUNT * self.OPEN_RETRY_SLEEP_SECONDS,
                )
                continue

            try:
                with os.fdopen(fd, "wb", buffering=0) as out:
                    if kind == "start" and meta is not None:
                        self._emit_start_bundle(out, meta)
                        self._session_open = True
                    elif kind == "refresh" and meta is not None:
                        if self._session_open:
                            self._emit_metadata_refresh_bundle(out, meta)
                        else:
                            # No open session to refresh -- fall back to a
                            # full session-begin so we still emit valid
                            # pbeg/mdst.../mden framing rather than a
                            # dangling mdst with no bracketing pbeg.
                            LOGGER.debug(
                                "Metadata refresh requested with no open session; "
                                "emitting a session-begin bundle instead.",
                            )
                            self._emit_start_bundle(out, meta)
                            self._session_open = True
                    elif kind == "end":
                        if self._session_open:
                            self._emit_end_bundle(out)
                        self._session_open = False
            except Exception as e:
                LOGGER.info("Metadata publish failed: %s", e)

    def _write_item(self, out, type_tag: str, code_tag: str, payload: bytes = b"") -> None:
        type_hex = self._tag_hex(type_tag)
        code_hex = self._tag_hex(code_tag)
        if payload:
            b64 = base64.b64encode(payload).decode("ascii")
            xml = (
                f"<item><type>{type_hex}</type><code>{code_hex}</code><length>{len(payload)}</length>"
                f"<data encoding=\"base64\">{b64}</data></item>\n"
            )
        else:
            xml = f"<item><type>{type_hex}</type><code>{code_hex}</code><length>0</length></item>\n"

        out.write(xml.encode("ascii"))

    def _write_metadata_items(self, out, meta: NowPlayingMetadata) -> None:
        """Write the asar/asal/minm/artwork items shared by both the
        session-begin and metadata-refresh bundles (the mdst/mden bracket
        and any pbeg/pend framing are the caller's responsibility)."""
        if meta.artist:
            self._write_item(out, "core", "asar", meta.artist.encode("utf-8", errors="replace"))
        if meta.album:
            self._write_item(out, "core", "asal", meta.album.encode("utf-8", errors="replace"))
        if meta.title:
            self._write_item(out, "core", "minm", meta.title.encode("utf-8", errors="replace"))

        art_payload = None
        if meta.artwork_path:
            try:
                art_path = Path(meta.artwork_path)
                if not (art_path.exists() and art_path.is_file()):
                    LOGGER.info("Pipe metadata: artwork %s is missing, publishing without it", art_path)
                else:
                    art_payload = art_path.read_bytes()
                    if len(art_payload) > MAX_PICTURE_BYTES:
                        # OwnTone rejects a picture larger than this outright
                        # (PIPE_PICTURE_SIZE_MAX in its inputs/pipe.c), so
                        # sending it would cost us the whole metadata bundle.
                        LOGGER.warning(
                            "Pipe metadata: artwork %s is %d bytes, over the %d byte limit; publishing without it",
                            art_path, len(art_payload), MAX_PICTURE_BYTES,
                        )
                        art_payload = None
            except Exception as e:
                LOGGER.warning("Pipe metadata: could not read artwork %s: %s", meta.artwork_path, e)
                art_payload = None

        if art_payload:
            self._write_item(out, "ssnc", "pcst")
            self._write_item(out, "ssnc", "PICT", art_payload)
            self._write_item(out, "ssnc", "pcen")

    def _emit_start_bundle(self, out, meta: NowPlayingMetadata) -> None:
        """Session-begin bundle: pbeg once, then one mdst..mden metadata
        update. Only ever emitted for a "start" queue item (a fresh
        session_started/source_changed dispatch) -- see publish_start()."""
        self._write_item(out, "ssnc", "pbeg")
        self._write_item(out, "ssnc", "mdst")
        self._write_metadata_items(out, meta)
        self._write_item(out, "ssnc", "mden")

    def _emit_metadata_refresh_bundle(self, out, meta: NowPlayingMetadata) -> None:
        """Metadata-only update within an already-open session: mdst..mden,
        no pbeg (Shairport-sync convention -- see publish_refresh())."""
        self._write_item(out, "ssnc", "mdst")
        self._write_metadata_items(out, meta)
        self._write_item(out, "ssnc", "mden")

    def _emit_end_bundle(self, out) -> None:
        self._write_item(out, "ssnc", "pend")
