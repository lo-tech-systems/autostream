"""WP1 — Appliance identity tests.

Covers:
  - CPU serial normalization and validation
  - Deterministic hash vector for get_appliance_id()
  - Exact 20-character lowercase hexadecimal format
  - Invalid / non-hex serial handling
  - Process-lifetime cache behavior
  - Fallback-file read (valid, invalid, missing)
  - Both sources unavailable returns None without raising
  - Missing identity logs one error per process and does not raise
  - Raw CPU serial is absent from the returned public ID
  - Installer fallback creation: only when CPU serial unavailable and file absent
  - Installer idempotence: existing fallback file is preserved
"""
from __future__ import annotations

import hashlib
import sys
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_rpi as rpi


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_appliance_id_cache():
    """Reset process-level identity cache between tests."""
    orig_cache = rpi._appliance_id_cache
    orig_set = rpi._appliance_id_cache_set
    orig_err = rpi._appliance_id_error_logged
    yield
    with rpi._ID_CACHE_LOCK:
        rpi._appliance_id_cache = orig_cache
        rpi._appliance_id_cache_set = orig_set
        rpi._appliance_id_error_logged = orig_err


def _clear_cache():
    with rpi._ID_CACHE_LOCK:
        rpi._appliance_id_cache = None
        rpi._appliance_id_cache_set = False
        rpi._appliance_id_error_logged = False


# ---------------------------------------------------------------------------
# _namespaced_id_hash
# ---------------------------------------------------------------------------

class TestNamespacedIdHash:
    def test_returns_20_char_lowercase_hex(self):
        result = rpi._namespaced_id_hash("ns:", "deadbeef1234")
        assert result is not None
        assert len(result) == 20
        assert result == result.lower()
        assert all(c in "0123456789abcdef" for c in result)

    def test_deterministic_for_same_inputs(self):
        r1 = rpi._namespaced_id_hash("autostream-appliance-v1:", "00000000abcdef12")
        r2 = rpi._namespaced_id_hash("autostream-appliance-v1:", "00000000abcdef12")
        assert r1 == r2

    def test_known_hash_vector(self):
        namespace = "autostream-appliance-v1:"
        serial = "00000000abcdef12"
        expected_full = hashlib.sha256(
            (namespace + serial).encode("utf-8")
        ).hexdigest()
        assert rpi._namespaced_id_hash(namespace, serial) == expected_full[:20]

    def test_normalizes_uppercase_serial(self):
        r_lower = rpi._namespaced_id_hash("ns:", "deadbeef")
        r_upper = rpi._namespaced_id_hash("ns:", "DEADBEEF")
        assert r_lower == r_upper

    def test_strips_whitespace_from_serial(self):
        r_plain = rpi._namespaced_id_hash("ns:", "abcd1234")
        r_padded = rpi._namespaced_id_hash("ns:", "  abcd1234  ")
        assert r_plain == r_padded

    def test_empty_serial_returns_none(self):
        assert rpi._namespaced_id_hash("ns:", "") is None

    def test_whitespace_only_serial_returns_none(self):
        assert rpi._namespaced_id_hash("ns:", "   ") is None

    def test_non_hex_serial_returns_none(self):
        assert rpi._namespaced_id_hash("ns:", "xyz!") is None

    def test_serial_with_embedded_space_returns_none(self):
        # After strip, "ab cd ef" is not valid hex
        assert rpi._namespaced_id_hash("ns:", "ab cd ef") is None

    def test_different_namespaces_produce_different_ids(self):
        r1 = rpi._namespaced_id_hash("autostream-appliance-v1:", "deadbeef")
        r2 = rpi._namespaced_id_hash("autostream-dial-v1:", "deadbeef")
        assert r1 != r2

    def test_raw_serial_not_in_output(self):
        serial = "12345678abcdef90"
        result = rpi._namespaced_id_hash("autostream-appliance-v1:", serial)
        assert result is not None
        assert serial not in result


# ---------------------------------------------------------------------------
# _read_id_file
# ---------------------------------------------------------------------------

class TestReadIdFile:
    def test_reads_valid_20char_hex_file(self, tmp_path):
        f = tmp_path / "appliance-id"
        f.write_text("deadbeef1234567890ab", encoding="utf-8")
        assert rpi._read_id_file(f) == "deadbeef1234567890ab"

    def test_strips_trailing_newline(self, tmp_path):
        f = tmp_path / "appliance-id"
        f.write_text("deadbeef1234567890ab\n", encoding="utf-8")
        assert rpi._read_id_file(f) == "deadbeef1234567890ab"

    def test_missing_file_returns_none(self, tmp_path):
        assert rpi._read_id_file(tmp_path / "nonexistent") is None

    def test_wrong_length_returns_none(self, tmp_path):
        f = tmp_path / "appliance-id"
        f.write_text("deadbeef", encoding="utf-8")
        assert rpi._read_id_file(f) is None

    def test_non_hex_content_returns_none(self, tmp_path):
        f = tmp_path / "appliance-id"
        f.write_text("zzzzzzzzzzzzzzzzzzzz", encoding="utf-8")
        assert rpi._read_id_file(f) is None

    def test_uppercase_content_returns_none(self, tmp_path):
        f = tmp_path / "appliance-id"
        f.write_text("DEADBEEF1234567890AB", encoding="utf-8")
        assert rpi._read_id_file(f) is None


# ---------------------------------------------------------------------------
# get_appliance_id: primary path (CPU serial hash)
# ---------------------------------------------------------------------------

class TestGetApplianceIdPrimary:
    def test_returns_20char_lowercase_hex(self):
        _clear_cache()
        with patch.object(rpi, "get_cpu_serial", return_value="00000000abcdef12"):
            result = rpi.get_appliance_id()
        assert result is not None
        assert len(result) == 20
        assert result == result.lower()
        assert all(c in "0123456789abcdef" for c in result)

    def test_deterministic_for_same_serial(self):
        _clear_cache()
        with patch.object(rpi, "get_cpu_serial", return_value="00000000abcdef12"):
            r1 = rpi.get_appliance_id()
        _clear_cache()
        with patch.object(rpi, "get_cpu_serial", return_value="00000000abcdef12"):
            r2 = rpi.get_appliance_id()
        assert r1 == r2

    def test_matches_known_hash_vector(self):
        _clear_cache()
        serial = "00000000abcdef12"
        with patch.object(rpi, "get_cpu_serial", return_value=serial):
            result = rpi.get_appliance_id()
        expected = hashlib.sha256(
            ("autostream-appliance-v1:" + serial).encode("utf-8")
        ).hexdigest()[:20]
        assert result == expected

    def test_cpu_serial_not_in_returned_id(self):
        _clear_cache()
        serial = "aabbccddeeff0011"
        with patch.object(rpi, "get_cpu_serial", return_value=serial):
            result = rpi.get_appliance_id()
        assert result is not None
        assert serial not in result

    def test_normalizes_uppercase_serial(self):
        _clear_cache()
        with patch.object(rpi, "get_cpu_serial", return_value="AABBCCDD12345678"):
            result_upper = rpi.get_appliance_id()
        _clear_cache()
        with patch.object(rpi, "get_cpu_serial", return_value="aabbccdd12345678"):
            result_lower = rpi.get_appliance_id()
        assert result_upper == result_lower

    def test_appliance_namespace_differs_from_dial_namespace(self):
        serial = "aabbccdd11223344"
        _clear_cache()
        with patch.object(rpi, "get_cpu_serial", return_value=serial):
            appliance_id = rpi.get_appliance_id()
        dial_id_direct = rpi._namespaced_id_hash(rpi._DIAL_NAMESPACE, serial)
        assert appliance_id != dial_id_direct


# ---------------------------------------------------------------------------
# get_appliance_id: fallback path
# ---------------------------------------------------------------------------

class TestGetApplianceIdFallback:
    def test_uses_fallback_file_when_serial_unavailable(self, tmp_path):
        _clear_cache()
        fallback = tmp_path / "appliance-id"
        fallback.write_text("cafebabe12345678ab01", encoding="utf-8")
        with patch.object(rpi, "get_cpu_serial", return_value=""), \
             patch.object(rpi, "APPLIANCE_ID_FILE", fallback):
            result = rpi.get_appliance_id()
        assert result == "cafebabe12345678ab01"

    def test_cpu_serial_takes_precedence_over_fallback(self, tmp_path):
        _clear_cache()
        fallback = tmp_path / "appliance-id"
        fallback.write_text("cafebabe12345678ab01", encoding="utf-8")
        serial = "00000000abcdef12"
        with patch.object(rpi, "get_cpu_serial", return_value=serial), \
             patch.object(rpi, "APPLIANCE_ID_FILE", fallback):
            result = rpi.get_appliance_id()
        expected = hashlib.sha256(
            ("autostream-appliance-v1:" + serial).encode("utf-8")
        ).hexdigest()[:20]
        assert result == expected

    def test_invalid_serial_and_missing_fallback_returns_none(self, tmp_path):
        _clear_cache()
        missing = tmp_path / "no-such-file"
        with patch.object(rpi, "get_cpu_serial", return_value=""), \
             patch.object(rpi, "APPLIANCE_ID_FILE", missing):
            result = rpi.get_appliance_id()
        assert result is None

    def test_invalid_serial_and_invalid_fallback_returns_none(self, tmp_path):
        _clear_cache()
        fallback = tmp_path / "appliance-id"
        fallback.write_text("tooshort", encoding="utf-8")
        with patch.object(rpi, "get_cpu_serial", return_value=""), \
             patch.object(rpi, "APPLIANCE_ID_FILE", fallback):
            result = rpi.get_appliance_id()
        assert result is None

    def test_does_not_create_fallback_file_at_runtime(self, tmp_path):
        _clear_cache()
        missing = tmp_path / "appliance-id"
        with patch.object(rpi, "get_cpu_serial", return_value=""), \
             patch.object(rpi, "APPLIANCE_ID_FILE", missing):
            rpi.get_appliance_id()
        assert not missing.exists()


# ---------------------------------------------------------------------------
# get_appliance_id: process-lifetime cache
# ---------------------------------------------------------------------------

class TestGetApplianceIdCache:
    def test_result_is_cached_for_process_lifetime(self):
        _clear_cache()
        call_count = [0]

        def counting_serial():
            call_count[0] += 1
            return "00000000abcdef12"

        with patch.object(rpi, "get_cpu_serial", side_effect=counting_serial):
            r1 = rpi.get_appliance_id()
            r2 = rpi.get_appliance_id()
            r3 = rpi.get_appliance_id()

        assert r1 == r2 == r3
        assert call_count[0] == 1  # only called once

    def test_none_is_also_cached(self, tmp_path):
        _clear_cache()
        missing = tmp_path / "no-file"
        call_count = [0]

        def counting_serial():
            call_count[0] += 1
            return ""

        with patch.object(rpi, "get_cpu_serial", side_effect=counting_serial), \
             patch.object(rpi, "APPLIANCE_ID_FILE", missing):
            r1 = rpi.get_appliance_id()
            r2 = rpi.get_appliance_id()

        assert r1 is None
        assert r2 is None
        assert call_count[0] == 1

    def test_cache_is_thread_safe(self):
        _clear_cache()
        results = []

        with patch.object(rpi, "get_cpu_serial", return_value="deadbeef12345678"):
            def worker():
                results.append(rpi.get_appliance_id())

            threads = [threading.Thread(target=worker) for _ in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        assert all(r == results[0] for r in results)
        assert results[0] is not None


# ---------------------------------------------------------------------------
# get_appliance_id: error logging
# ---------------------------------------------------------------------------

class TestGetApplianceIdErrorLogging:
    def test_logs_one_error_when_identity_unavailable(self, tmp_path, caplog):
        _clear_cache()
        missing = tmp_path / "no-file"
        with patch.object(rpi, "get_cpu_serial", return_value=""), \
             patch.object(rpi, "APPLIANCE_ID_FILE", missing):
            import logging
            with caplog.at_level(logging.ERROR, logger="autostream_rpi"):
                rpi.get_appliance_id()
                rpi.get_appliance_id()  # second call must not log again

        error_records = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(error_records) == 1

    def test_does_not_raise_when_identity_unavailable(self, tmp_path):
        _clear_cache()
        missing = tmp_path / "no-file"
        with patch.object(rpi, "get_cpu_serial", return_value=""), \
             patch.object(rpi, "APPLIANCE_ID_FILE", missing):
            result = rpi.get_appliance_id()
        assert result is None


# ---------------------------------------------------------------------------
# Installer fallback creation semantics (unit-tested as Python logic)
# ---------------------------------------------------------------------------

class TestInstallerFallbackSemantics:
    """Simulate the installer Python snippet behavior in isolation."""

    def _run_installer_logic(self, tmp_path, cpu_serial: str) -> Path:
        """Replicate the installer's fallback-creation logic for testing."""
        import re
        import secrets

        fallback_path = tmp_path / "appliance-id"
        serial = cpu_serial.strip().lower()

        if re.match(r'^[0-9a-f]+$', serial) and serial:
            pass  # CPU serial available; fallback not needed
        elif fallback_path.exists():
            pass  # already exists; preserve
        else:
            new_id = secrets.token_hex(10)
            tmp_file = fallback_path.with_suffix(".tmp")
            tmp_file.write_text(new_id, encoding="utf-8")
            tmp_file.replace(fallback_path)

        return fallback_path

    def test_creates_fallback_when_serial_unavailable(self, tmp_path):
        path = self._run_installer_logic(tmp_path, cpu_serial="")
        assert path.exists()
        content = path.read_text(encoding="utf-8").strip()
        assert len(content) == 20
        assert all(c in "0123456789abcdef" for c in content)

    def test_does_not_create_fallback_when_serial_valid(self, tmp_path):
        path = self._run_installer_logic(tmp_path, cpu_serial="00000000abcdef12")
        assert not path.exists()

    def test_preserves_existing_fallback(self, tmp_path):
        original_id = "aabbccddeeff001122ab"
        existing = tmp_path / "appliance-id"
        existing.write_text(original_id, encoding="utf-8")
        path = self._run_installer_logic(tmp_path, cpu_serial="")
        assert path.read_text(encoding="utf-8").strip() == original_id

    def test_fallback_is_20_lowercase_hex(self, tmp_path):
        path = self._run_installer_logic(tmp_path, cpu_serial="")
        content = path.read_text(encoding="utf-8").strip()
        assert len(content) == 20
        assert content == content.lower()
        assert all(c in "0123456789abcdef" for c in content)

    def test_idempotent_on_second_run_with_serial(self, tmp_path):
        # Run once without serial → creates fallback
        path = self._run_installer_logic(tmp_path, cpu_serial="")
        first_id = path.read_text(encoding="utf-8").strip()
        # Run again with serial available → existing fallback untouched
        self._run_installer_logic(tmp_path, cpu_serial="00000000abcdef12")
        assert path.read_text(encoding="utf-8").strip() == first_id

    def test_fallback_different_across_calls(self, tmp_path):
        """Two separate installs without serial produce different IDs."""
        path1 = tmp_path / "install1"
        path1.mkdir()
        path2 = tmp_path / "install2"
        path2.mkdir()
        id1 = self._run_installer_logic(path1, "")
        id2 = self._run_installer_logic(path2, "")
        assert id1.read_text().strip() != id2.read_text().strip()
