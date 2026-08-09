"""P6 — Now-playing and metadata pipeline tests.

What runs here (offline, no audio hardware, no OwnTone):
  - PersistentNowPlayingCache: hint file parsing for valid, missing, malformed,
    non-dict, empty, and non-object-root content.  Input-name lookup, default
    fallback, explicit artwork_path, and cache invalidation when mtime changes.
  - NowPlayingMetadata: default values and field normalisation.
  - OwntoneMetadataPipePublisher disabled path: env var unset → _enabled=False
    → publish_start/publish_end/close are all no-ops.
  - _tag_hex(): hex encoding of 4-char and short ASCII tags.
  - _write_item(): XML item generation with and without payload.
  - _emit_start_bundle() / _emit_end_bundle(): bundle structure checks.

Environment-dependent (Linux only):
  - Named FIFO creation (os.mkfifo), open/write, retry on ENXIO.
  - Full pipeline end-to-end: audio start → FIFO write → OwnTone metadata.
    Requires OwnTone running and reading the FIFO.
  CI mechanism: linux-owntone integration job.

Covered by existing tests (not duplicated here):
  - AudioMonitor integration (test_audio_monitor_coordination.py) stubs out
    PersistentNowPlayingCache and OwntoneMetadataPipePublisher entirely.
"""
from __future__ import annotations

import io
import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "core"))

from autostream_nowplaying import (
    NowPlayingMetadata,
    OwntoneMetadataPipePublisher,
    PersistentNowPlayingCache,
    get_shared_metadata_publisher,
    release_shared_metadata_publisher,
    _publisher_registry,
    _resolve_placeholder_artwork_path,
)
from autostream_core import _default_nowplaying_title


# ---------------------------------------------------------------------------
# NowPlayingMetadata — defaults and field normalisation
# ---------------------------------------------------------------------------

class TestNowPlayingMetadataDefaults:
    def test_default_title(self):
        m = NowPlayingMetadata()
        assert m.title == "Line-In"

    def test_default_artist(self):
        assert NowPlayingMetadata().artist == "autostream"

    def test_default_album(self):
        assert NowPlayingMetadata().album == "Unknown Album"

    def test_default_artwork_path_is_none(self):
        assert NowPlayingMetadata().artwork_path is None

    def test_custom_values_stored(self):
        m = NowPlayingMetadata(title="T", artist="A", album="L", artwork_path="/img.png")
        assert m.title == "T"
        assert m.artist == "A"
        assert m.album == "L"
        assert m.artwork_path == "/img.png"


# ---------------------------------------------------------------------------
# PersistentNowPlayingCache — hint file parsing
# ---------------------------------------------------------------------------

def _write_hints(path: Path, data) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


class TestHintFileParsing:
    """PersistentNowPlayingCache reads and caches hint files."""

    def test_returns_none_when_file_missing(self, tmp_path):
        cache = PersistentNowPlayingCache(str(tmp_path / "nonexistent.json"))
        assert cache.get_manual_hint("USB AUDIO") is None

    def test_returns_none_for_malformed_json(self, tmp_path):
        p = tmp_path / "hints.json"
        p.write_text("{ not valid json }", encoding="utf-8")
        cache = PersistentNowPlayingCache(str(p))
        assert cache.get_manual_hint("any") is None

    def test_returns_none_when_root_is_not_dict(self, tmp_path):
        p = tmp_path / "hints.json"
        _write_hints(p, [{"title": "oops"}])
        cache = PersistentNowPlayingCache(str(p))
        assert cache.get_manual_hint("any") is None

    def test_returns_none_when_root_is_string(self, tmp_path):
        p = tmp_path / "hints.json"
        p.write_text('"just a string"', encoding="utf-8")
        cache = PersistentNowPlayingCache(str(p))
        assert cache.get_manual_hint("any") is None

    def test_returns_none_when_entry_is_not_dict(self, tmp_path):
        p = tmp_path / "hints.json"
        _write_hints(p, {"my-input": "should be a dict not a string"})
        cache = PersistentNowPlayingCache(str(p))
        assert cache.get_manual_hint("my-input") is None

    def test_returns_none_when_entry_is_null(self, tmp_path):
        p = tmp_path / "hints.json"
        _write_hints(p, {"my-input": None})
        cache = PersistentNowPlayingCache(str(p))
        assert cache.get_manual_hint("my-input") is None

    def test_returns_none_when_no_match_and_no_default(self, tmp_path):
        p = tmp_path / "hints.json"
        _write_hints(p, {"other-input": {"title": "x", "artist": "y", "album": "z"}})
        cache = PersistentNowPlayingCache(str(p))
        assert cache.get_manual_hint("USB AUDIO") is None

    def test_returns_metadata_for_matching_input(self, tmp_path):
        p = tmp_path / "hints.json"
        _write_hints(p, {
            "USB AUDIO  CODEC: Audio": {"title": "Turntable", "artist": "Vinyl", "album": "LP"}
        })
        cache = PersistentNowPlayingCache(str(p))
        meta = cache.get_manual_hint("USB AUDIO  CODEC: Audio")
        assert meta is not None
        assert meta.title == "Turntable"
        assert meta.artist == "Vinyl"
        assert meta.album == "LP"

    def test_falls_back_to_default_entry(self, tmp_path):
        p = tmp_path / "hints.json"
        _write_hints(p, {
            "default": {"title": "DefaultTitle", "artist": "DefaultArtist", "album": "DefaultAlbum"}
        })
        cache = PersistentNowPlayingCache(str(p))
        meta = cache.get_manual_hint("USB AUDIO  CODEC: Audio")
        assert meta is not None
        assert meta.title == "DefaultTitle"

    def test_specific_entry_takes_priority_over_default(self, tmp_path):
        p = tmp_path / "hints.json"
        _write_hints(p, {
            "default": {"title": "DefaultTitle", "artist": "A", "album": "B"},
            "USB AUDIO  CODEC: Audio": {"title": "SpecificTitle", "artist": "A", "album": "B"},
        })
        cache = PersistentNowPlayingCache(str(p))
        meta = cache.get_manual_hint("USB AUDIO  CODEC: Audio")
        assert meta.title == "SpecificTitle"

    def test_artwork_path_included_when_present(self, tmp_path):
        p = tmp_path / "hints.json"
        _write_hints(p, {"default": {
            "title": "T", "artist": "A", "album": "B",
            "artwork_path": "/opt/autostream/images/badge.png"
        }})
        cache = PersistentNowPlayingCache(str(p))
        meta = cache.get_manual_hint("default")
        assert meta.artwork_path == "/opt/autostream/images/badge.png"

    def test_artwork_path_is_none_when_absent(self, tmp_path):
        p = tmp_path / "hints.json"
        _write_hints(p, {"default": {"title": "T", "artist": "A", "album": "B"}})
        cache = PersistentNowPlayingCache(str(p))
        meta = cache.get_manual_hint("default")
        assert meta.artwork_path is None

    def test_missing_title_field_uses_default(self, tmp_path):
        p = tmp_path / "hints.json"
        _write_hints(p, {"default": {"artist": "A", "album": "B"}})
        cache = PersistentNowPlayingCache(str(p))
        meta = cache.get_manual_hint("default")
        assert meta.title == "Autostream Input"

    def test_missing_artist_field_uses_default(self, tmp_path):
        p = tmp_path / "hints.json"
        _write_hints(p, {"default": {"title": "T", "album": "B"}})
        cache = PersistentNowPlayingCache(str(p))
        meta = cache.get_manual_hint("default")
        assert meta.artist == "Vinyl"

    def test_missing_album_field_uses_default(self, tmp_path):
        p = tmp_path / "hints.json"
        _write_hints(p, {"default": {"title": "T", "artist": "A"}})
        cache = PersistentNowPlayingCache(str(p))
        meta = cache.get_manual_hint("default")
        assert meta.album == "Unknown Album"

    def test_empty_file_does_not_crash(self, tmp_path):
        p = tmp_path / "hints.json"
        p.write_text("", encoding="utf-8")
        cache = PersistentNowPlayingCache(str(p))
        assert cache.get_manual_hint("any") is None

    def test_cache_reloads_on_mtime_change(self, tmp_path):
        p = tmp_path / "hints.json"
        _write_hints(p, {"default": {"title": "Old", "artist": "A", "album": "B"}})
        cache = PersistentNowPlayingCache(str(p))
        cache.get_manual_hint("default")  # prime the cache

        # Update file content and bump mtime explicitly
        time.sleep(0.05)   # ensure mtime changes
        _write_hints(p, {"default": {"title": "New", "artist": "A", "album": "B"}})
        # Touch to ensure mtime is strictly greater
        new_time = os.path.getmtime(str(p)) + 1
        os.utime(str(p), (new_time, new_time))

        meta = cache.get_manual_hint("default")
        assert meta.title == "New"

    def test_cache_uses_cached_value_when_mtime_unchanged(self, tmp_path):
        p = tmp_path / "hints.json"
        _write_hints(p, {"default": {"title": "Original", "artist": "A", "album": "B"}})
        cache = PersistentNowPlayingCache(str(p))

        meta1 = cache.get_manual_hint("default")
        # Overwrite without changing mtime — cache should still return old data
        p.write_bytes(json.dumps({"default": {"title": "Changed"}}).encode())
        os.utime(str(p), (meta1.__class__ and cache._hints_mtime, cache._hints_mtime))

        meta2 = cache.get_manual_hint("default")
        assert meta2.title == "Original"   # still using cached value

    def test_does_not_raise_on_permission_error(self, tmp_path):
        p = tmp_path / "hints.json"
        _write_hints(p, {"default": {"title": "T", "artist": "A", "album": "B"}})
        cache = PersistentNowPlayingCache(str(p))
        with patch.object(Path, "stat", side_effect=PermissionError("denied")):
            # Must not raise; returns None on exception
            result = cache.get_manual_hint("default")
        assert result is None


# ---------------------------------------------------------------------------
# PersistentNowPlayingCache — env var path resolution
# ---------------------------------------------------------------------------

class TestHintFileCachePathResolution:
    def test_uses_explicit_path_arg(self, tmp_path):
        p = tmp_path / "my_hints.json"
        _write_hints(p, {"default": {"title": "X", "artist": "A", "album": "B"}})
        cache = PersistentNowPlayingCache(str(p))
        assert cache.hints_path == p

    def test_env_var_overrides_default(self, tmp_path):
        p = tmp_path / "env_hints.json"
        with patch.dict(os.environ, {"AUTOSTREAM_NOWPLAYING_HINTS_PATH": str(p)}):
            cache = PersistentNowPlayingCache()
        assert cache.hints_path == p

    def test_explicit_arg_overrides_env_var(self, tmp_path):
        arg_path = tmp_path / "arg.json"
        env_path = tmp_path / "env.json"
        with patch.dict(os.environ, {"AUTOSTREAM_NOWPLAYING_HINTS_PATH": str(env_path)}):
            cache = PersistentNowPlayingCache(str(arg_path))
        assert cache.hints_path == arg_path


# ---------------------------------------------------------------------------
# OwntoneMetadataPipePublisher — disabled path
# ---------------------------------------------------------------------------

class TestOwntonePublisherDisabled:
    """When AUTOSTREAM_ENABLE_PIPE_METADATA is not set, publisher is disabled."""

    def _make_disabled(self, tmp_path):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTOSTREAM_ENABLE_PIPE_METADATA", None)
            pub = OwntoneMetadataPipePublisher(str(tmp_path / "audio.fifo"))
        return pub

    def test_disabled_when_env_not_set(self, tmp_path):
        pub = self._make_disabled(tmp_path)
        assert not pub._enabled

    def test_disabled_when_env_is_empty(self, tmp_path):
        with patch.dict(os.environ, {"AUTOSTREAM_ENABLE_PIPE_METADATA": ""}):
            pub = OwntoneMetadataPipePublisher(str(tmp_path / "audio.fifo"))
        assert not pub._enabled

    def test_enabled_when_env_is_1(self, tmp_path):
        with patch.dict(os.environ, {"AUTOSTREAM_ENABLE_PIPE_METADATA": "1"}), \
             patch("threading.Thread"):
            pub = OwntoneMetadataPipePublisher(str(tmp_path / "audio.fifo"))
        assert pub._enabled

    def test_enabled_when_env_is_true(self, tmp_path):
        with patch.dict(os.environ, {"AUTOSTREAM_ENABLE_PIPE_METADATA": "true"}), \
             patch("threading.Thread"):
            pub = OwntoneMetadataPipePublisher(str(tmp_path / "audio.fifo"))
        assert pub._enabled

    def test_publish_start_noop_when_disabled(self, tmp_path):
        pub = self._make_disabled(tmp_path)
        pub.publish_start(NowPlayingMetadata())  # must not raise

    def test_publish_end_noop_when_disabled(self, tmp_path):
        pub = self._make_disabled(tmp_path)
        pub.publish_end()   # must not raise

    def test_close_noop_when_disabled(self, tmp_path):
        pub = self._make_disabled(tmp_path)
        pub.close()   # must not raise


# ---------------------------------------------------------------------------
# _tag_hex() — ASCII tag → 8-digit hex
# ---------------------------------------------------------------------------

class TestTagHex:
    def _hex(self, tag: str) -> str:
        return OwntoneMetadataPipePublisher._tag_hex(tag)

    def test_four_char_tag(self):
        result = self._hex("core")
        assert len(result) == 8
        assert result == f"{int.from_bytes(b'core', 'big'):08x}"

    def test_ssnc_tag(self):
        result = self._hex("ssnc")
        assert result == f"{int.from_bytes(b'ssnc', 'big'):08x}"

    def test_short_tag_padded_with_spaces(self):
        # "pb" → b'pb  ' (padded to 4 bytes)
        result = self._hex("pb")
        expected = f"{int.from_bytes(b'pb  ', 'big'):08x}"
        assert result == expected

    def test_empty_tag_is_all_spaces(self):
        result = self._hex("")
        expected = f"{int.from_bytes(b'    ', 'big'):08x}"
        assert result == expected

    def test_known_pbeg_tag(self):
        result = self._hex("pbeg")
        assert result == f"{int.from_bytes(b'pbeg', 'big'):08x}"

    def test_known_pend_tag(self):
        result = self._hex("pend")
        assert result == f"{int.from_bytes(b'pend', 'big'):08x}"


# ---------------------------------------------------------------------------
# _write_item() — XML structure
# ---------------------------------------------------------------------------

class TestWriteItem:
    """_write_item() produces valid Shairport-style XML items."""

    def _make_publisher(self, tmp_path):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTOSTREAM_ENABLE_PIPE_METADATA", None)
        pub = OwntoneMetadataPipePublisher.__new__(OwntoneMetadataPipePublisher)
        pub._enabled = False
        pub.audio_fifo_path = str(tmp_path / "audio.fifo")
        pub.metadata_fifo_path = str(tmp_path / "audio.fifo.metadata")
        return pub

    def _write_to_bytes(self, pub, type_tag, code_tag, payload=b""):
        buf = io.BytesIO()

        class _FakeOut:
            def write(self, data):
                buf.write(data if isinstance(data, bytes) else data.encode("ascii"))

        pub._write_item(_FakeOut(), type_tag, code_tag, payload)
        return buf.getvalue().decode("ascii")

    def test_empty_item_has_length_zero(self, tmp_path):
        pub = self._make_publisher(tmp_path)
        xml = self._write_to_bytes(pub, "ssnc", "pbeg")
        assert "<length>0</length>" in xml
        assert "<data" not in xml

    def test_payload_item_has_base64_data(self, tmp_path):
        import base64
        pub = self._make_publisher(tmp_path)
        payload = b"Hello world"
        xml = self._write_to_bytes(pub, "core", "minm", payload)
        b64 = base64.b64encode(payload).decode("ascii")
        assert b64 in xml
        assert "<data encoding=\"base64\">" in xml

    def test_payload_item_has_correct_length(self, tmp_path):
        pub = self._make_publisher(tmp_path)
        payload = b"abc"
        xml = self._write_to_bytes(pub, "core", "asar", payload)
        assert f"<length>{len(payload)}</length>" in xml

    def test_item_contains_type_and_code(self, tmp_path):
        pub = self._make_publisher(tmp_path)
        xml = self._write_to_bytes(pub, "ssnc", "pend")
        assert "<type>" in xml
        assert "<code>" in xml

    def test_item_ends_with_newline(self, tmp_path):
        pub = self._make_publisher(tmp_path)
        xml = self._write_to_bytes(pub, "ssnc", "pbeg")
        assert xml.endswith("\n")


# ---------------------------------------------------------------------------
# _emit_start_bundle() / _emit_end_bundle()
# ---------------------------------------------------------------------------

class TestEmitBundles:
    def _make_publisher(self, tmp_path):
        pub = OwntoneMetadataPipePublisher.__new__(OwntoneMetadataPipePublisher)
        pub._enabled = False
        pub.audio_fifo_path = str(tmp_path / "fifo")
        pub.metadata_fifo_path = str(tmp_path / "fifo.metadata")
        pub._held_artwork_path = None
        pub._placeholder_bytes = None
        pub._placeholder_bytes_path = None
        return pub

    def _capture(self, pub, meta=None):
        buf = io.BytesIO()

        class _Out:
            def write(self, data):
                buf.write(data if isinstance(data, bytes) else data.encode())

        out = _Out()
        if meta is not None:
            pub._emit_start_bundle(out, meta)
        else:
            pub._emit_end_bundle(out)
        return buf.getvalue().decode("ascii")

    def test_start_bundle_begins_with_pbeg(self, tmp_path):
        pub = self._make_publisher(tmp_path)
        meta = NowPlayingMetadata(title="T", artist="A", album="B")
        xml = self._capture(pub, meta)
        pbeg_hex = OwntoneMetadataPipePublisher._tag_hex("pbeg")
        assert pbeg_hex in xml

    def test_start_bundle_ends_with_mden(self, tmp_path):
        pub = self._make_publisher(tmp_path)
        meta = NowPlayingMetadata(title="T", artist="A", album="B")
        xml = self._capture(pub, meta)
        mden_hex = OwntoneMetadataPipePublisher._tag_hex("mden")
        assert mden_hex in xml

    def test_start_bundle_includes_title(self, tmp_path):
        import base64
        pub = self._make_publisher(tmp_path)
        meta = NowPlayingMetadata(title="TurntableTitle", artist="A", album="B")
        xml = self._capture(pub, meta)
        assert base64.b64encode(b"TurntableTitle").decode("ascii") in xml

    def test_start_bundle_includes_artist(self, tmp_path):
        import base64
        pub = self._make_publisher(tmp_path)
        meta = NowPlayingMetadata(title="T", artist="VinylArtist", album="B")
        xml = self._capture(pub, meta)
        assert base64.b64encode(b"VinylArtist").decode("ascii") in xml

    def test_start_bundle_includes_album(self, tmp_path):
        import base64
        pub = self._make_publisher(tmp_path)
        meta = NowPlayingMetadata(title="T", artist="A", album="MyAlbum")
        xml = self._capture(pub, meta)
        assert base64.b64encode(b"MyAlbum").decode("ascii") in xml

    def test_start_bundle_falls_back_to_placeholder_when_path_is_none(self, tmp_path):
        """Session start with no artwork of its own must still carry a PICT:
        the publisher falls back to the bundled placeholder (item 2) rather
        than omitting the picture, so a receiver can raise Now Playing
        immediately (track ID disabled / startup window)."""
        import base64
        pub = self._make_publisher(tmp_path)
        placeholder = tmp_path / "placeholder.png"
        placeholder.write_bytes(b"PLACEHOLDERBYTES")
        meta = NowPlayingMetadata(title="T", artist="A", album="B", artwork_path=None)
        with patch(
            "autostream_nowplaying._resolve_placeholder_artwork_path",
            return_value=str(placeholder),
        ):
            xml = self._capture(pub, meta)
        pict_hex = OwntoneMetadataPipePublisher._tag_hex("PICT")
        assert pict_hex in xml
        assert base64.b64encode(b"PLACEHOLDERBYTES").decode("ascii") in xml
        assert pub._held_artwork_path == str(placeholder)

    def test_start_bundle_no_artwork_when_file_missing(self, tmp_path):
        pub = self._make_publisher(tmp_path)
        meta = NowPlayingMetadata(
            title="T", artist="A", album="B",
            artwork_path=str(tmp_path / "missing.png")
        )
        xml = self._capture(pub, meta)
        pict_hex = OwntoneMetadataPipePublisher._tag_hex("PICT")
        assert pict_hex not in xml

    def test_start_bundle_includes_artwork_when_file_exists(self, tmp_path):
        import base64
        pub = self._make_publisher(tmp_path)
        img_path = tmp_path / "art.png"
        img_path.write_bytes(b"FAKEIMAGEDATA")
        meta = NowPlayingMetadata(
            title="T", artist="A", album="B",
            artwork_path=str(img_path)
        )
        xml = self._capture(pub, meta)
        pict_hex = OwntoneMetadataPipePublisher._tag_hex("PICT")
        assert pict_hex in xml
        assert base64.b64encode(b"FAKEIMAGEDATA").decode("ascii") in xml
        assert pub._held_artwork_path == str(img_path)

    def test_end_bundle_contains_pend(self, tmp_path):
        pub = self._make_publisher(tmp_path)
        xml = self._capture(pub, meta=None)
        pend_hex = OwntoneMetadataPipePublisher._tag_hex("pend")
        assert pend_hex in xml

    def test_end_bundle_does_not_contain_pbeg(self, tmp_path):
        pub = self._make_publisher(tmp_path)
        xml = self._capture(pub, meta=None)
        pbeg_hex = OwntoneMetadataPipePublisher._tag_hex("pbeg")
        assert pbeg_hex not in xml


# ---------------------------------------------------------------------------
# Shared publisher per fifo_path
# ---------------------------------------------------------------------------

class TestSharedMetadataPublisher:
    """get_shared_metadata_publisher()/release_shared_metadata_publisher():
    one queue+thread per physical FIFO path, refcounted so a config reload's
    stop()/re-create cycle only tears down the thread once the last
    referencing monitor has released it."""

    def teardown_method(self, method):
        # Defensive: a failed assertion mid-test could leave an entry
        # dangling and bleed into the next test's path (paths are
        # tmp_path-scoped so collisions are unlikely, but keep it clean).
        _publisher_registry.clear()

    def test_same_path_returns_same_instance(self, tmp_path):
        path = str(tmp_path / "shared.fifo")
        pub1 = get_shared_metadata_publisher(path)
        pub2 = get_shared_metadata_publisher(path)
        try:
            assert pub1 is pub2
        finally:
            release_shared_metadata_publisher(path)
            release_shared_metadata_publisher(path)

    def test_different_paths_return_different_instances(self, tmp_path):
        path_a = str(tmp_path / "a.fifo")
        path_b = str(tmp_path / "b.fifo")
        pub_a = get_shared_metadata_publisher(path_a)
        pub_b = get_shared_metadata_publisher(path_b)
        try:
            assert pub_a is not pub_b
        finally:
            release_shared_metadata_publisher(path_a)
            release_shared_metadata_publisher(path_b)

    def test_release_does_not_close_while_other_monitor_still_referencing(self, tmp_path):
        """Two AudioMonitors on the same path (the exact bug scenario): the
        first monitor's stop() must not tear down the publisher the second
        monitor is still using."""
        path = str(tmp_path / "shared.fifo")
        pub = get_shared_metadata_publisher(path)   # monitor 1 acquires
        get_shared_metadata_publisher(path)          # monitor 2 acquires (refcount=2)
        with patch.object(pub, "close") as close_mock:
            release_shared_metadata_publisher(path)  # monitor 1 releases
            close_mock.assert_not_called()
            release_shared_metadata_publisher(path)  # monitor 2 releases (refcount=0)
            close_mock.assert_called_once()

    def test_release_unknown_path_is_a_noop(self, tmp_path):
        # Must not raise even if never acquired (e.g. double-release).
        release_shared_metadata_publisher(str(tmp_path / "never-acquired.fifo"))

    def test_acquire_after_full_release_creates_fresh_instance(self, tmp_path):
        path = str(tmp_path / "shared.fifo")
        pub1 = get_shared_metadata_publisher(path)
        release_shared_metadata_publisher(path)
        pub2 = get_shared_metadata_publisher(path)
        try:
            assert pub1 is not pub2
        finally:
            release_shared_metadata_publisher(path)

    def test_two_monitors_serialize_bundles_through_one_queue(self, tmp_path):
        """The core correctness property fix 1a exists for: two 'monitors'
        sharing a path publish through the same queue, so a start from one
        and an end from the other cannot interleave -- they're just two
        items processed one at a time by the single writer thread."""
        path = str(tmp_path / "shared.fifo")
        with patch.dict(os.environ, {"AUTOSTREAM_ENABLE_PIPE_METADATA": "1"}), \
             patch("threading.Thread"):
            pub_for_input1 = get_shared_metadata_publisher(path)
            pub_for_input2 = get_shared_metadata_publisher(path)
        try:
            assert pub_for_input1 is pub_for_input2
            assert pub_for_input1._queue is pub_for_input2._queue
        finally:
            release_shared_metadata_publisher(path)
            release_shared_metadata_publisher(path)


# ---------------------------------------------------------------------------
# Session-begin vs metadata-refresh bundle framing
# ---------------------------------------------------------------------------

class TestBundleFraming:
    """publish_start() must emit pbeg exactly once per session; a mid-session
    metadata refresh (publish_refresh()) must emit mdst..mden WITHOUT a
    second pbeg, and publish_end() must emit pend exactly once."""

    def _make_publisher(self, tmp_path):
        pub = OwntoneMetadataPipePublisher.__new__(OwntoneMetadataPipePublisher)
        pub._enabled = False
        pub.audio_fifo_path = str(tmp_path / "fifo")
        pub.metadata_fifo_path = str(tmp_path / "fifo.metadata")
        pub._session_open = False
        pub._held_artwork_path = None
        pub._placeholder_bytes = None
        pub._placeholder_bytes_path = None
        return pub

    def _capture_bundle(self, write_fn) -> str:
        buf = io.BytesIO()

        class _Out:
            def write(self, data):
                buf.write(data if isinstance(data, bytes) else data.encode())

        write_fn(_Out())
        return buf.getvalue().decode("ascii")

    def _run_dispatch(self, pub, kind, meta):
        """Reproduce _run()'s per-item dispatch (the "start"/"refresh"/"end"
        branch) directly against a captured buffer, without a real fifo/
        thread -- mirrors how TestEmitBundles exercises the bundle emitters
        in isolation."""
        return self._capture_bundle(
            lambda out: self._dispatch_one(pub, out, kind, meta)
        )

    @staticmethod
    def _dispatch_one(pub, out, kind, meta):
        if kind == "start" and meta is not None:
            pub._emit_start_bundle(out, meta)
            pub._session_open = True
        elif kind == "refresh" and meta is not None:
            if pub._session_open:
                pub._emit_metadata_refresh_bundle(out, meta)
            else:
                pub._emit_start_bundle(out, meta)
                pub._session_open = True
        elif kind == "end":
            if pub._session_open:
                pub._emit_end_bundle(out)
            pub._session_open = False
            pub._held_artwork_path = None

    def test_session_begin_emits_pbeg_once(self, tmp_path):
        pub = self._make_publisher(tmp_path)
        meta = NowPlayingMetadata(title="T", artist="A", album="B")
        xml = self._run_dispatch(pub, "start", meta)
        pbeg_hex = OwntoneMetadataPipePublisher._tag_hex("pbeg")
        assert xml.count(pbeg_hex) == 1
        assert pub._session_open is True

    def test_refresh_after_start_does_not_emit_second_pbeg(self, tmp_path):
        pub = self._make_publisher(tmp_path)
        meta1 = NowPlayingMetadata(title="T1", artist="A", album="B")
        meta2 = NowPlayingMetadata(title="T2", artist="A", album="B")
        xml_start = self._run_dispatch(pub, "start", meta1)
        xml_refresh = self._run_dispatch(pub, "refresh", meta2)

        pbeg_hex = OwntoneMetadataPipePublisher._tag_hex("pbeg")
        mdst_hex = OwntoneMetadataPipePublisher._tag_hex("mdst")
        mden_hex = OwntoneMetadataPipePublisher._tag_hex("mden")

        assert pbeg_hex in xml_start
        assert pbeg_hex not in xml_refresh  # the bug this fix closes
        assert mdst_hex in xml_refresh
        assert mden_hex in xml_refresh

    def test_refresh_still_carries_new_metadata(self, tmp_path):
        import base64
        pub = self._make_publisher(tmp_path)
        pub._session_open = True  # already mid-session
        meta = NowPlayingMetadata(title="RefreshedTitle", artist="A", album="B")
        xml_refresh = self._run_dispatch(pub, "refresh", meta)
        assert base64.b64encode(b"RefreshedTitle").decode("ascii") in xml_refresh

    def test_refresh_with_no_open_session_falls_back_to_session_begin(self, tmp_path):
        """Defensive fallback: a refresh with no open session (should not
        happen in normal operation) still emits valid pbeg/mdst/mden framing
        rather than a dangling mdst."""
        pub = self._make_publisher(tmp_path)
        assert pub._session_open is False
        meta = NowPlayingMetadata(title="T", artist="A", album="B")
        xml = self._run_dispatch(pub, "refresh", meta)
        pbeg_hex = OwntoneMetadataPipePublisher._tag_hex("pbeg")
        assert pbeg_hex in xml
        assert pub._session_open is True

    def test_end_after_start_emits_pend_once(self, tmp_path):
        pub = self._make_publisher(tmp_path)
        meta = NowPlayingMetadata(title="T", artist="A", album="B")
        self._run_dispatch(pub, "start", meta)
        xml_end = self._run_dispatch(pub, "end", None)
        pend_hex = OwntoneMetadataPipePublisher._tag_hex("pend")
        assert xml_end.count(pend_hex) == 1
        assert pub._session_open is False

    def test_end_with_no_open_session_emits_nothing(self, tmp_path):
        """publish_end() with no open session (e.g. a duplicate/late end)
        must not emit a dangling pend."""
        pub = self._make_publisher(tmp_path)
        xml_end = self._run_dispatch(pub, "end", None)
        assert xml_end == ""

    def test_full_session_lifecycle_pbeg_once_mdst_mden_pairs_pend_once(self, tmp_path):
        """One begin, two refreshes, one end: exactly one pbeg, exactly one
        pend, and one mdst/mden pair per bundle."""
        pub = self._make_publisher(tmp_path)
        meta = NowPlayingMetadata(title="T", artist="A", album="B")
        whole = (
            self._run_dispatch(pub, "start", meta)
            + self._run_dispatch(pub, "refresh", meta)
            + self._run_dispatch(pub, "refresh", meta)
            + self._run_dispatch(pub, "end", None)
        )
        pbeg_hex = OwntoneMetadataPipePublisher._tag_hex("pbeg")
        pend_hex = OwntoneMetadataPipePublisher._tag_hex("pend")
        mdst_hex = OwntoneMetadataPipePublisher._tag_hex("mdst")
        mden_hex = OwntoneMetadataPipePublisher._tag_hex("mden")
        assert whole.count(pbeg_hex) == 1
        assert whole.count(pend_hex) == 1
        assert whole.count(mdst_hex) == 3  # begin + 2 refreshes
        assert whole.count(mden_hex) == 3


# ---------------------------------------------------------------------------
# Artwork fallback + HOLD-UNTIL-NEW across a session lifecycle
# ---------------------------------------------------------------------------

class TestArtworkFallbackAndHold:
    """Every start/refresh bundle must carry a PICT: placeholder at first,
    real artwork once identified, the previous artwork retained across
    artless refreshes, and placeholder again only on a fresh session."""

    def _make_publisher(self, tmp_path):
        pub = OwntoneMetadataPipePublisher.__new__(OwntoneMetadataPipePublisher)
        pub._enabled = False
        pub.audio_fifo_path = str(tmp_path / "fifo")
        pub.metadata_fifo_path = str(tmp_path / "fifo.metadata")
        pub._session_open = False
        pub._held_artwork_path = None
        pub._placeholder_bytes = None
        pub._placeholder_bytes_path = None
        return pub

    def _capture(self, write_fn) -> str:
        buf = io.BytesIO()

        class _Out:
            def write(self, data):
                buf.write(data if isinstance(data, bytes) else data.encode())

        write_fn(_Out())
        return buf.getvalue().decode("ascii")

    @staticmethod
    def _dispatch_one(pub, out, kind, meta):
        # Mirrors _run()'s per-item dispatch, including the held-artwork
        # reset on session end -- see OwntoneMetadataPipePublisher._run().
        if kind == "start" and meta is not None:
            pub._emit_start_bundle(out, meta)
            pub._session_open = True
        elif kind == "refresh" and meta is not None:
            if pub._session_open:
                pub._emit_metadata_refresh_bundle(out, meta)
            else:
                pub._emit_start_bundle(out, meta)
                pub._session_open = True
        elif kind == "end":
            if pub._session_open:
                pub._emit_end_bundle(out)
            pub._session_open = False
            pub._held_artwork_path = None

    def _run_dispatch(self, pub, kind, meta) -> str:
        return self._capture(lambda out: self._dispatch_one(pub, out, kind, meta))

    def test_placeholder_used_at_session_start_with_no_artwork(self, tmp_path):
        pub = self._make_publisher(tmp_path)
        placeholder = tmp_path / "placeholder.png"
        placeholder.write_bytes(b"PLACEHOLDERBYTES")
        meta = NowPlayingMetadata(title="T", artist="A", album="B", artwork_path=None)
        with patch(
            "autostream_nowplaying._resolve_placeholder_artwork_path",
            return_value=str(placeholder),
        ):
            xml = self._run_dispatch(pub, "start", meta)
        pict_hex = OwntoneMetadataPipePublisher._tag_hex("PICT")
        assert pict_hex in xml
        import base64
        assert base64.b64encode(b"PLACEHOLDERBYTES").decode("ascii") in xml
        assert pub._held_artwork_path == str(placeholder)

    def test_real_artwork_passes_through_and_updates_held_path(self, tmp_path):
        import base64
        pub = self._make_publisher(tmp_path)
        art = tmp_path / "art.png"
        art.write_bytes(b"REALARTBYTES")
        meta = NowPlayingMetadata(title="T", artist="A", album="B", artwork_path=str(art))
        xml = self._run_dispatch(pub, "start", meta)
        assert base64.b64encode(b"REALARTBYTES").decode("ascii") in xml
        assert pub._held_artwork_path == str(art)

    def test_artless_refresh_reemits_held_artwork(self, tmp_path):
        """A track-ID refresh that brings no artwork of its own must
        re-emit the artwork already held for this session, not omit PICT."""
        import base64
        pub = self._make_publisher(tmp_path)
        art = tmp_path / "art.png"
        art.write_bytes(b"HELDARTBYTES")
        start_meta = NowPlayingMetadata(title="T1", artist="A", album="B", artwork_path=str(art))
        self._run_dispatch(pub, "start", start_meta)

        refresh_meta = NowPlayingMetadata(title="T2", artist="A", album="B", artwork_path=None)
        xml_refresh = self._run_dispatch(pub, "refresh", refresh_meta)

        pict_hex = OwntoneMetadataPipePublisher._tag_hex("PICT")
        assert pict_hex in xml_refresh
        assert base64.b64encode(b"HELDARTBYTES").decode("ascii") in xml_refresh
        assert pub._held_artwork_path == str(art)

    def test_refresh_with_new_artwork_updates_held_path(self, tmp_path):
        import base64
        pub = self._make_publisher(tmp_path)
        art1 = tmp_path / "art1.png"
        art1.write_bytes(b"FIRSTART")
        art2 = tmp_path / "art2.png"
        art2.write_bytes(b"SECONDART")

        self._run_dispatch(pub, "start", NowPlayingMetadata(
            title="T1", artist="A", album="B", artwork_path=str(art1)))
        xml_refresh = self._run_dispatch(pub, "refresh", NowPlayingMetadata(
            title="T2", artist="A", album="B", artwork_path=str(art2)))

        assert base64.b64encode(b"SECONDART").decode("ascii") in xml_refresh
        assert base64.b64encode(b"FIRSTART").decode("ascii") not in xml_refresh
        assert pub._held_artwork_path == str(art2)

    def test_held_state_resets_on_session_end_next_start_uses_placeholder(self, tmp_path):
        """Held artwork must not leak across sessions: after publish_end(),
        a fresh session with no artwork of its own falls back to the
        placeholder again, not the previous session's held artwork."""
        import base64
        pub = self._make_publisher(tmp_path)
        art = tmp_path / "art.png"
        art.write_bytes(b"OLDSESSIONART")
        placeholder = tmp_path / "placeholder.png"
        placeholder.write_bytes(b"FRESHPLACEHOLDER")

        self._run_dispatch(pub, "start", NowPlayingMetadata(
            title="T1", artist="A", album="B", artwork_path=str(art)))
        self._run_dispatch(pub, "end", None)
        assert pub._held_artwork_path is None

        with patch(
            "autostream_nowplaying._resolve_placeholder_artwork_path",
            return_value=str(placeholder),
        ):
            xml_new_start = self._run_dispatch(pub, "start", NowPlayingMetadata(
                title="T2", artist="A", album="B", artwork_path=None))

        assert base64.b64encode(b"FRESHPLACEHOLDER").decode("ascii") in xml_new_start
        assert base64.b64encode(b"OLDSESSIONART").decode("ascii") not in xml_new_start
        assert pub._held_artwork_path == str(placeholder)

    def test_missing_placeholder_file_continues_without_artwork_no_exception(self, tmp_path):
        """If the bundled placeholder file isn't present at runtime, the
        writer must log and continue publishing metadata without a picture
        -- never raise."""
        pub = self._make_publisher(tmp_path)
        meta = NowPlayingMetadata(title="T", artist="A", album="B", artwork_path=None)
        with patch(
            "autostream_nowplaying._resolve_placeholder_artwork_path",
            return_value=None,
        ):
            xml = self._run_dispatch(pub, "start", meta)  # must not raise
        pict_hex = OwntoneMetadataPipePublisher._tag_hex("PICT")
        assert pict_hex not in xml
        assert pub._held_artwork_path is None

    def test_resolve_placeholder_artwork_path_missing_file_returns_none(self):
        """_resolve_placeholder_artwork_path() itself must degrade to None
        (never raise) when the bundled file is absent, e.g. a mangled
        install tree missing images/."""
        _resolve_placeholder_artwork_path.cache_clear()
        try:
            with patch("autostream_nowplaying.PLACEHOLDER_ARTWORK_FILENAME", "does-not-exist.png"):
                result = _resolve_placeholder_artwork_path()
            assert result is None
        finally:
            _resolve_placeholder_artwork_path.cache_clear()

    def test_resolve_placeholder_artwork_path_resolves_bundled_file(self):
        """The real (unpatched) resolver finds the actual bundled placeholder
        shipped in the repo's images/ directory."""
        _resolve_placeholder_artwork_path.cache_clear()
        try:
            result = _resolve_placeholder_artwork_path()
        finally:
            _resolve_placeholder_artwork_path.cache_clear()
        assert result is not None
        assert Path(result).is_file()
        assert Path(result).name == "autostream-playback-logo-dark-512x512.png"

    def test_env_override_is_honoured(self, tmp_path):
        """AUTOSTREAM_PLACEHOLDER_ARTWORK_PATH overrides the bundled default
        (tests, or an operator with a different placeholder)."""
        custom = tmp_path / "custom_placeholder.png"
        custom.write_bytes(b"CUSTOM")
        _resolve_placeholder_artwork_path.cache_clear()
        try:
            with patch.dict(os.environ, {"AUTOSTREAM_PLACEHOLDER_ARTWORK_PATH": str(custom)}):
                result = _resolve_placeholder_artwork_path()
            assert result == str(custom)
        finally:
            _resolve_placeholder_artwork_path.cache_clear()

    def test_no_artwork_resolution_does_not_hold_previous_track_cover(self, tmp_path):
        """A track-change refresh that resolves to "" (identification
        completed, this track confirmed to have no artwork of its own) must
        NOT keep re-emitting the previous (different) track's cover -- that
        would misattribute someone else's artwork to this track. It falls
        back to the placeholder instead, same as a fresh session."""
        import base64
        pub = self._make_publisher(tmp_path)
        old_art = tmp_path / "old_track_art.png"
        old_art.write_bytes(b"OLDTRACKART")
        placeholder = tmp_path / "placeholder.png"
        placeholder.write_bytes(b"PLACEHOLDERBYTES")

        self._run_dispatch(pub, "start", NowPlayingMetadata(
            title="T1", artist="A", album="B", artwork_path=str(old_art)))

        with patch(
            "autostream_nowplaying._resolve_placeholder_artwork_path",
            return_value=str(placeholder),
        ):
            xml_refresh = self._run_dispatch(pub, "refresh", NowPlayingMetadata(
                title="T2", artist="A", album="B", artwork_path=""))

        pict_hex = OwntoneMetadataPipePublisher._tag_hex("PICT")
        assert pict_hex in xml_refresh
        assert base64.b64encode(b"PLACEHOLDERBYTES").decode("ascii") in xml_refresh
        assert base64.b64encode(b"OLDTRACKART").decode("ascii") not in xml_refresh
        assert pub._held_artwork_path == str(placeholder)

    def test_pending_reidentification_still_holds_previous_track_cover(self, tmp_path):
        """Contrast with the above: a refresh with artwork_path=None (no
        decision yet, e.g. title/artist-only update while ID is still
        pending) DOES keep re-emitting the previously held artwork -- see
        _resolve_refresh_artwork()'s None vs "" distinction."""
        import base64
        pub = self._make_publisher(tmp_path)
        art = tmp_path / "current_track_art.png"
        art.write_bytes(b"CURRENTTRACKART")

        self._run_dispatch(pub, "start", NowPlayingMetadata(
            title="T1", artist="A", album="B", artwork_path=str(art)))
        xml_refresh = self._run_dispatch(pub, "refresh", NowPlayingMetadata(
            title="T1", artist="A", album="B", artwork_path=None))

        pict_hex = OwntoneMetadataPipePublisher._tag_hex("PICT")
        assert pict_hex in xml_refresh
        assert base64.b64encode(b"CURRENTTRACKART").decode("ascii") in xml_refresh
        assert pub._held_artwork_path == str(art)

    def test_placeholder_bytes_are_cached_not_reread_per_publish(self, tmp_path):
        """The placeholder is read from disk at most once per publisher
        instance -- repeated artless bundles reuse the cached bytes."""
        pub = self._make_publisher(tmp_path)
        placeholder = tmp_path / "placeholder.png"
        placeholder.write_bytes(b"PLACEHOLDERBYTES")

        with patch(
            "autostream_nowplaying._resolve_placeholder_artwork_path",
            return_value=str(placeholder),
        ):
            self._run_dispatch(pub, "start", NowPlayingMetadata(
                title="T1", artist="A", album="B", artwork_path=None))
            assert pub._placeholder_bytes == b"PLACEHOLDERBYTES"
            assert pub._placeholder_bytes_path == str(placeholder)

            # Mutate the file on disk; the cached bytes must NOT change,
            # proving the second publish reused the cache instead of
            # re-reading.
            placeholder.write_bytes(b"CHANGEDBYTES")
            xml_refresh = self._run_dispatch(pub, "refresh", NowPlayingMetadata(
                title="T1", artist="A", album="B", artwork_path=None))

        import base64
        assert base64.b64encode(b"PLACEHOLDERBYTES").decode("ascii") in xml_refresh
        assert base64.b64encode(b"CHANGEDBYTES").decode("ascii") not in xml_refresh


# ---------------------------------------------------------------------------
# Default now-playing title/artist strings (no raw ALSA device strings)
# ---------------------------------------------------------------------------

class TestDefaultNowPlayingStrings:
    """_default_nowplaying_title() picks a receiver-facing label instead of
    leaking the raw ALSA device string, with turntable taking precedence
    over bluetooth-ness (an established design decision: a bluetooth
    turntable is still "Vinyl")."""

    def test_turntable_input_is_vinyl(self):
        assert _default_nowplaying_title(True, "hw:1,0") == "Vinyl"

    def test_turntable_wins_over_bluetooth(self):
        # A bluetooth-loopback-shaped device string, but is_turntable=True.
        assert _default_nowplaying_title(True, "hw:CARD=ASBT,DEV=1") == "Vinyl"

    def test_bluetooth_loopback_input_is_bluetooth(self):
        assert _default_nowplaying_title(False, "hw:CARD=ASBT,DEV=1") == "Bluetooth"

    def test_other_input_is_line_in(self):
        assert _default_nowplaying_title(False, "hw:1,0") == "Line-In"

    def test_default_title_never_contains_raw_device_string(self):
        raw_device = "hw:CARD=USB_AUDIO_CODEC,DEV=0"
        for is_turntable in (True, False):
            label = _default_nowplaying_title(is_turntable, raw_device)
            assert raw_device not in label

    def test_default_metadata_artist_is_autostream(self):
        # "autostream" is the constant artist; _default_nowplaying_title()
        # supplies the *title* (Vinyl/Bluetooth/Line-In), the prominent line on
        # the receiver -- see TestNowPlayingMetadataDefaults.
        assert NowPlayingMetadata().artist == "autostream"
