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
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def close(self) -> None:
        if not self._enabled:
            return
        self._stop.set()
        self._queue.put(("stop", None))

    def publish_start(self, meta: NowPlayingMetadata) -> None:
        if not self._enabled:
            return
        self._queue.put(("start", meta))

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
                    elif kind == "end":
                        self._emit_end_bundle(out)
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

    def _emit_start_bundle(self, out, meta: NowPlayingMetadata) -> None:
        self._write_item(out, "ssnc", "pbeg")
        self._write_item(out, "ssnc", "mdst")

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
                if art_path.exists() and art_path.is_file():
                    art_payload = art_path.read_bytes()
                    if len(art_payload) > 1024 * 1024:
                        art_payload = None
            except Exception:
                art_payload = None

        if art_payload:
            self._write_item(out, "ssnc", "pcst")
            self._write_item(out, "ssnc", "PICT", art_payload)
            self._write_item(out, "ssnc", "pcen")

        self._write_item(out, "ssnc", "mden")

    def _emit_end_bundle(self, out) -> None:
        self._write_item(out, "ssnc", "pend")
