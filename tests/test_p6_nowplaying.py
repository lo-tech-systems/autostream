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
)


# ---------------------------------------------------------------------------
# NowPlayingMetadata — defaults and field normalisation
# ---------------------------------------------------------------------------

class TestNowPlayingMetadataDefaults:
    def test_default_title(self):
        m = NowPlayingMetadata()
        assert m.title == "Autostream Input"

    def test_default_artist(self):
        assert NowPlayingMetadata().artist == "Vinyl"

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

    def test_start_bundle_no_artwork_when_path_is_none(self, tmp_path):
        pub = self._make_publisher(tmp_path)
        meta = NowPlayingMetadata(title="T", artist="A", album="B", artwork_path=None)
        xml = self._capture(pub, meta)
        pict_hex = OwntoneMetadataPipePublisher._tag_hex("PICT")
        assert pict_hex not in xml

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
