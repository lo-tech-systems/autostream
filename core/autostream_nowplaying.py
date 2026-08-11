"""autostream_nowplaying.py

Helpers for OwnTone pipe metadata publishing and static now-playing hints.
"""

from __future__ import annotations

import base64
import errno
import functools
import json
import logging
import os
import queue
import select
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

# Bundled fallback artwork so a receiver (e.g. an Apple TV) always has a
# picture to show for a session: track ID disabled, the startup window
# before the first identification, and an identified track with no artwork
# of its own all fall back to this file.
PLACEHOLDER_ARTWORK_FILENAME = "autostream-playback-logo-dark-512x512.png"
# Overrides the resolved placeholder path outright (tests; or an operator
# who wants a different placeholder without touching the install tree).
PLACEHOLDER_ARTWORK_ENV = "AUTOSTREAM_PLACEHOLDER_ARTWORK_PATH"


@functools.lru_cache(maxsize=1)
def _resolve_placeholder_artwork_path() -> Optional[str]:
    """Resolve the bundled Now Playing placeholder artwork's on-disk path.

    AUTOSTREAM_PLACEHOLDER_ARTWORK_PATH, if set, is used as-is and is NOT
    existence-checked here -- a deliberately-pointed-at-a-missing-file
    override degrades the same way a missing bundled file does (the reader
    finds nothing and the caller publishes without artwork, never raising).

    Otherwise: Path(__file__).resolve().parent.parent / "images" / <file>
    resolves correctly both in the dev checkout (repo_root/images) and the
    installed tree (/opt/autostream/images), since the installer copies
    images/ alongside core/. That default path IS existence-checked so a
    mangled install tree logs once instead of returning a path that will
    fail on every read.

    Cached (functools.lru_cache) so this is resolved once per process and a
    missing file is logged only once, not on every bundle -- call
    .cache_clear() to force re-resolution (tests only). Returns None (and
    logs at info, never raises) if no usable path was found -- the writer
    must keep publishing metadata without artwork rather than crash.
    """
    override = (os.environ.get(PLACEHOLDER_ARTWORK_ENV) or "").strip()
    if override:
        return override

    # Two layouts have to work: the dev checkout keeps this module under
    # core/ with images/ a level up (repo/core/<mod>.py + repo/images), while
    # the installer flattens core/* into the install dir so the module and
    # images/ become siblings (/opt/autostream/<mod>.py + /opt/autostream/
    # images). Try the sibling images/ first, then the parent's.
    here = Path(__file__).resolve().parent
    candidates = [
        here / "images" / PLACEHOLDER_ARTWORK_FILENAME,
        here.parent / "images" / PLACEHOLDER_ARTWORK_FILENAME,
    ]
    for path in candidates:
        try:
            if path.exists() and path.is_file():
                return str(path)
        except Exception as e:
            LOGGER.info("Could not check placeholder artwork %s: %s", path, e)
    LOGGER.info(
        "Now-playing placeholder artwork not found (looked in %s); publishing "
        "without a fallback picture until a session provides real artwork.",
        " and ".join(str(c.parent) for c in candidates),
    )
    return None


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
    title: str = "Line-In"
    artist: str = "autostream"
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

        # Placeholder-artwork bytes cache: the placeholder file is re-used
        # for every artless bundle (session start with no art, every
        # artless refresh while nothing better is held), so its bytes are
        # read from disk once and reused rather than re-read on every
        # publish -- see _read_artwork_bytes(). Keyed by the path they were
        # read for, so a changed placeholder path (env override change,
        # or a fresh cache_clear() in tests) invalidates it correctly.
        # Initialized unconditionally so the attributes exist even when
        # publishing is disabled.
        self._placeholder_bytes: Optional[bytes] = None
        self._placeholder_bytes_path: Optional[str] = None

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
        # HOLD-UNTIL-NEW: the artwork_path actually emitted for the
        # currently-open session (placeholder or real), so an artless
        # refresh can re-emit it instead of omitting PICT -- see
        # _resolve_refresh_artwork(). Reset on session end/start.
        self._held_artwork_path: Optional[str] = None
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
        framing stays valid.

        *meta.artwork_path* has three meaningful states here -- see
        _resolve_refresh_artwork() for the full rationale: a real path (new
        artwork, becomes the new held artwork), None (no news either way --
        re-send whatever is currently held, if anything), and "" (the empty
        string -- a decided "this track has no artwork", which clears the
        hold instead of re-sending a previous, different track's cover)."""
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
                        self._held_artwork_path = None
            except Exception as e:
                LOGGER.info("Metadata publish failed: %s", e)

    # A bundle carrying a base64 cover routinely exceeds the kernel FIFO
    # capacity (64KB on Linux), and the fd is opened O_NONBLOCK (so the open
    # can poll for a reader). An unbuffered non-blocking write() then does a
    # PARTIAL write once the pipe is full -- silently, via its return value --
    # truncating the item mid-base64. The reader resyncs on the next item
    # boundary and sees a picture item with no data, so any cover larger than
    # ~47KB was simply lost. Hence: every write drains the pipe via poll and
    # writes the remainder, bounded by a deadline so a reader that died
    # mid-bundle can't hang the publisher thread forever.
    WRITE_DEADLINE_SECONDS = 10.0

    def _write_all(self, out, data: bytes) -> None:
        deadline = time.monotonic() + self.WRITE_DEADLINE_SECONDS
        offset = 0
        while offset < len(data):
            try:
                n = out.write(data[offset:] if offset else data)
            except BlockingIOError:
                n = 0
            if n is None:
                # Raw non-blocking file objects -- io.FileIO, which is
                # exactly what _run()'s os.fdopen(fd, "wb", buffering=0)
                # produces -- return None when the pipe is full and not a
                # single byte could be written (RawIOBase contract). That is
                # a zero-progress write, NOT completion: fall through to the
                # poll below. (Treating it as completion silently dropped
                # the unwritten remainder of large covers.)
                n = 0
            if n:
                offset += n
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"metadata fifo write stalled with {len(data) - offset} bytes unwritten"
                )
            select.select([], [out.fileno()], [], min(remaining, 0.5))

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

        self._write_all(out, xml.encode("ascii"))

    def _resolve_start_artwork(self, incoming: Optional[str]) -> Optional[str]:
        """Session-begin artwork resolution: use the incoming path if the
        caller has one (a manual hint or an already-identified track);
        otherwise fall back to the bundled placeholder so the very first
        bundle of a session always carries a PICT (covers: track ID
        disabled, and the startup window before the first identification).
        Whatever this resolves to becomes the held artwork for the session.
        """
        path = incoming or _resolve_placeholder_artwork_path()
        self._held_artwork_path = path
        return path

    def _resolve_refresh_artwork(self, incoming: Optional[str]) -> Optional[str]:
        """Mid-session artwork resolution.

        - incoming is a real path: a track-ID match landed new/updated
          artwork. Remember and use it.
        - incoming is None: no news either way (e.g. identification still
          pending) -- HOLD-UNTIL-NEW: explicitly re-emit the previously held
          artwork rather than omitting PICT from this bundle. A bundle with
          no picture item at all can cause the receiver to drop the artwork
          it is already showing, so "no new artwork this refresh" must mean
          "re-send the old one", not "send nothing".
        - incoming is "" (the empty string, distinct from None): a *decided*
          outcome -- identification completed and this track genuinely has
          no artwork of its own (see AudioMonitor._ti_worker() in
          autostream_core.py). Unlike the None case, this must NOT keep
          holding the previous (different) track's cover -- fall back to the
          placeholder instead (same as a fresh session start with no art),
          and hold *that* from here on, so a later artless refresh
          (incoming=None) keeps re-sending the placeholder rather than
          reverting to no-PICT-at-all.
        """
        if incoming:
            self._held_artwork_path = incoming
            return incoming
        if incoming == "":
            path = _resolve_placeholder_artwork_path()
            self._held_artwork_path = path
            return path
        return getattr(self, "_held_artwork_path", None)

    def _read_artwork_bytes(self, path: str) -> Optional[bytes]:
        """Read artwork bytes for *path*, honoring MAX_PICTURE_BYTES.

        When *path* is the resolved placeholder path, bytes are cached in
        this instance after the first successful read (see __init__ /
        _placeholder_bytes) so repeated placeholder use -- a session with
        track ID disabled re-sends it on every refresh -- doesn't re-read
        the same file from disk each time. Any other path (real or held
        real artwork) is read fresh each call, unchanged from the
        pre-existing per-publish read.
        """
        if path == self._placeholder_bytes_path and self._placeholder_bytes is not None:
            return self._placeholder_bytes

        try:
            art_path = Path(path)
            if not (art_path.exists() and art_path.is_file()):
                LOGGER.info("Pipe metadata: artwork %s is missing, publishing without it", art_path)
                return None
            data = art_path.read_bytes()
        except Exception as e:
            LOGGER.warning("Pipe metadata: could not read artwork %s: %s", path, e)
            return None

        if len(data) > MAX_PICTURE_BYTES:
            # OwnTone rejects a picture larger than this outright
            # (PIPE_PICTURE_SIZE_MAX in its inputs/pipe.c), so sending it
            # would cost us the whole metadata bundle.
            LOGGER.warning(
                "Pipe metadata: artwork %s is %d bytes, over the %d byte limit; publishing without it",
                art_path, len(data), MAX_PICTURE_BYTES,
            )
            return None

        if path == _resolve_placeholder_artwork_path():
            self._placeholder_bytes = data
            self._placeholder_bytes_path = path

        return data

    def _write_metadata_items(self, out, meta: NowPlayingMetadata, artwork_path: Optional[str]) -> None:
        """Write the asar/asal/minm/artwork items shared by both the
        session-begin and metadata-refresh bundles (the mdst/mden bracket
        and any pbeg/pend framing are the caller's responsibility).

        *artwork_path* is the already-resolved picture to publish (placeholder,
        held, or the caller's own) -- see _resolve_start_artwork() /
        _resolve_refresh_artwork(); this method never looks at
        meta.artwork_path directly, since the effective picture for a bundle
        can differ from what the caller passed in (fallback/hold)."""
        if meta.artist:
            self._write_item(out, "core", "asar", meta.artist.encode("utf-8", errors="replace"))
        if meta.album:
            self._write_item(out, "core", "asal", meta.album.encode("utf-8", errors="replace"))
        if meta.title:
            self._write_item(out, "core", "minm", meta.title.encode("utf-8", errors="replace"))

        art_payload = self._read_artwork_bytes(artwork_path) if artwork_path else None

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
        artwork_path = self._resolve_start_artwork(meta.artwork_path)
        self._write_metadata_items(out, meta, artwork_path)
        self._write_item(out, "ssnc", "mden")

    def _emit_metadata_refresh_bundle(self, out, meta: NowPlayingMetadata) -> None:
        """Metadata-only update within an already-open session: mdst..mden,
        no pbeg (Shairport-sync convention -- see publish_refresh())."""
        self._write_item(out, "ssnc", "mdst")
        artwork_path = self._resolve_refresh_artwork(meta.artwork_path)
        self._write_metadata_items(out, meta, artwork_path)
        self._write_item(out, "ssnc", "mden")

    def _emit_end_bundle(self, out) -> None:
        self._write_item(out, "ssnc", "pend")
