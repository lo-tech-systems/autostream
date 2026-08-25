"""Tests for autostream_settings_apply.py — the declarative settings engine.

Coverage:
- Manifest schema validation (unknown fields/modes/targets, mode-specific
  field requirements, dotted-key grammar, the vibra-mini reservation,
  from_before format)
- ensure/overwrite/delete/rename semantics, including rename collision
- from_before gating (fires, skips-not-older, skips-untrustworthy-tag)
- Result validation against the brick-guard/range/shape table
- Malformed / missing existing target files
- Atomic write with autostream chown+chmod and owntone-mini chmod
- Multi-manifest ordering, --check-only, and idempotent re-runs
"""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_tools = str(REPO_ROOT / "tools")
if _tools not in sys.path:
    sys.path.insert(0, _tools)
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

# pwd is Unix-only; stub it before importing the module under test so tests
# run on any platform. The module binds the name at import time, so the
# stub instance stays reachable as m.pwd even after being popped here.
_pwd_injected = "pwd" not in sys.modules
if _pwd_injected:
    sys.modules["pwd"] = MagicMock()

import autostream_settings_apply as m

if _pwd_injected:
    sys.modules.pop("pwd", None)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def stub_pwd():
    """Default pwd.getpwnam stub: any name resolves. Individual tests
    override with a specific side_effect/return_value to exercise failure
    paths (missing OS user, unresolvable uid)."""
    with patch.object(
        m.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=65534, pw_gid=65534)
    ) as stub:
        yield stub


@pytest.fixture(autouse=True)
def stub_chown():
    """os.chown does not exist meaningfully on Windows; patched everywhere,
    per tests/test_update_recovery.py's pattern (create=True)."""
    with patch("os.chown", return_value=None, create=True) as stub:
        yield stub


def _manifest_path(tmp_path: Path, name: str, directives, version=1) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"version": version, "directives": directives}), encoding="utf-8")
    return path


def _run(tmp_path, manifests, check_only=False, autostream=None, owntone=None, state=None):
    return m.run(
        manifest_paths=manifests,
        check_only=check_only,
        autostream_config_path=autostream or (tmp_path / "autostream.json"),
        owntone_config_path=owntone or (tmp_path / "owntone-settings.json"),
        state_file_path=state or (tmp_path / "install-state.env"),
    )


_NOVALUE = object()


def _directive(target="owntone-mini", key="user_agent", mode="ensure", value=_NOVALUE, **extra):
    """Build a directive dict. 'value' defaults to a placeholder for
    ensure/overwrite (which require one) and is omitted otherwise (delete/
    rename forbid it) -- pass value=... explicitly to override either way."""
    d = {"target": target, "key": key, "mode": mode}
    if value is _NOVALUE:
        if mode in ("ensure", "overwrite"):
            value = "x"
    if value is not _NOVALUE:
        d["value"] = value
    d.update(extra)
    return d


# ---------------------------------------------------------------------------
# Manifest schema validation
# ---------------------------------------------------------------------------

class TestSchemaValidation:

    def test_unknown_top_level_key_rejected(self, tmp_path):
        path = tmp_path / "m.json"
        path.write_text(json.dumps({"version": 1, "directives": [], "extra": 1}), encoding="utf-8")
        with pytest.raises(m.EngineError, match="unknown top-level"):
            _run(tmp_path, [path])

    def test_unsupported_version_rejected(self, tmp_path):
        path = _manifest_path(tmp_path, "m.json", [], version=2)
        with pytest.raises(m.EngineError, match="unsupported schema version"):
            _run(tmp_path, [path])

    def test_directives_not_a_list_rejected(self, tmp_path):
        path = tmp_path / "m.json"
        path.write_text(json.dumps({"version": 1, "directives": {}}), encoding="utf-8")
        with pytest.raises(m.EngineError, match="must be a list"):
            _run(tmp_path, [path])

    def test_unknown_directive_field_rejected(self, tmp_path):
        d = _directive(bogus="x")
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="unknown field"):
            _run(tmp_path, [path])

    def test_unknown_target_rejected(self, tmp_path):
        d = _directive(target="not-a-target")
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="unknown target"):
            _run(tmp_path, [path])

    def test_vibra_mini_target_rejected_distinctly(self, tmp_path):
        d = _directive(target="vibra-mini")
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="reserved"):
            _run(tmp_path, [path])

    def test_unknown_mode_rejected(self, tmp_path):
        d = _directive(mode="bogus")
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="unknown mode"):
            _run(tmp_path, [path])

    def test_ensure_requires_value(self, tmp_path):
        d = _directive(mode="ensure")
        del d["value"]
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="requires 'value'"):
            _run(tmp_path, [path])

    def test_overwrite_requires_reason(self, tmp_path):
        d = _directive(mode="overwrite", value="x")
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="requires a non-empty 'reason'"):
            _run(tmp_path, [path])

    def test_overwrite_with_reason_is_valid(self, tmp_path):
        d = _directive(mode="overwrite", value="x", reason="because")
        path = _manifest_path(tmp_path, "m.json", [d])
        assert _run(tmp_path, [path]) == 0

    def test_delete_forbids_value(self, tmp_path):
        d = _directive(mode="delete", value="x")
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="must not include 'value'"):
            _run(tmp_path, [path])

    def test_rename_forbids_value(self, tmp_path):
        d = _directive(mode="rename", value="x", to="user_agent2")
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="must not include 'value'"):
            _run(tmp_path, [path])

    def test_rename_requires_to(self, tmp_path):
        d = _directive(mode="rename")
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="requires a non-empty 'to'"):
            _run(tmp_path, [path])

    def test_to_forbidden_outside_rename(self, tmp_path):
        d = _directive(mode="ensure", to="somewhere")
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="only valid for mode 'rename'"):
            _run(tmp_path, [path])

    def test_dotted_owntone_key_rejected(self, tmp_path):
        d = _directive(key="general.user_agent")
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="must be flat"):
            _run(tmp_path, [path])

    def test_airplay_devices_key_accepted(self, tmp_path):
        d = _directive(key="airplay_devices.Living Room.max_volume", value=11)
        path = _manifest_path(tmp_path, "m.json", [d])
        assert _run(tmp_path, [path]) == 0

    def test_airplay_devices_key_wrong_depth_rejected(self, tmp_path):
        d = _directive(key="airplay_devices.max_volume", value=11)
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="airplay_devices key"):
            _run(tmp_path, [path])

    def test_autostream_dotted_key_accepted(self, tmp_path):
        d = _directive(target="autostream", key="general.silence_seconds", value=30)
        path = _manifest_path(tmp_path, "m.json", [d])
        assert _run(tmp_path, [path]) == 0

    def test_from_before_malformed_rejected(self, tmp_path):
        d = _directive(from_before="not-a-version")
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="from_before"):
            _run(tmp_path, [path])

    def test_from_before_prerelease_accepted(self, tmp_path):
        d = _directive(from_before="0.6.0-beta.1")
        path = _manifest_path(tmp_path, "m.json", [d])
        assert _run(tmp_path, [path]) == 0

    def test_malformed_manifest_json_rejected(self, tmp_path):
        path = tmp_path / "m.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(m.EngineError, match="not valid JSON"):
            _run(tmp_path, [path])

    def test_missing_manifest_rejected(self, tmp_path):
        with pytest.raises(m.EngineError, match="manifest not found"):
            _run(tmp_path, [tmp_path / "nope.json"])


# ---------------------------------------------------------------------------
# Mode semantics
# ---------------------------------------------------------------------------

class TestModeSemantics:

    def test_ensure_absent_sets_value(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(mode="ensure", key="server_name", value="hifi")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone)
        assert json.loads(owntone.read_text())["server_name"] == "hifi"

    def test_ensure_present_is_noop(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        owntone.write_text(json.dumps({"server_name": "existing"}), encoding="utf-8")
        d = _directive(mode="ensure", key="server_name", value="hifi")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone)
        assert json.loads(owntone.read_text())["server_name"] == "existing"

    def test_overwrite_converges_existing_value(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        owntone.write_text(json.dumps({"server_name": "old"}), encoding="utf-8")
        d = _directive(mode="overwrite", key="server_name", value="new", reason="converge")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone)
        assert json.loads(owntone.read_text())["server_name"] == "new"

    def test_overwrite_absent_sets_value(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(mode="overwrite", key="server_name", value="new", reason="seed")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone)
        assert json.loads(owntone.read_text())["server_name"] == "new"

    def test_delete_present_removes_key(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        owntone.write_text(json.dumps({"server_name": "old"}), encoding="utf-8")
        d = _directive(mode="delete", key="server_name")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone)
        assert "server_name" not in json.loads(owntone.read_text())

    def test_delete_absent_is_noop_and_no_write(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(mode="delete", key="server_name")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone)
        assert not owntone.exists()

    def test_rename_moves_value(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        owntone.write_text(json.dumps({"old_name": "hi-fi"}), encoding="utf-8")
        d = _directive(mode="rename", key="old_name", to="server_name")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone)
        data = json.loads(owntone.read_text())
        assert "old_name" not in data
        assert data["server_name"] == "hi-fi"

    def test_rename_absent_source_is_noop(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(mode="rename", key="old_name", to="server_name")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone)
        assert not owntone.exists()

    def test_rename_collision_raises_and_writes_nothing(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        original = json.dumps({"old_name": "hi-fi", "server_name": "already-here"})
        owntone.write_text(original, encoding="utf-8")
        d = _directive(mode="rename", key="old_name", to="server_name")
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="already exists"):
            _run(tmp_path, [path], owntone=owntone)
        assert owntone.read_text() == original

    def test_autostream_dotted_ensure_creates_intermediate(self, tmp_path):
        autostream = tmp_path / "autostream.json"
        d = _directive(target="autostream", key="general.fifo_path",
                        mode="ensure", value="/run/autostream-pipes/autostream.fifo")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], autostream=autostream)
        data = json.loads(autostream.read_text())
        assert data["general"]["fifo_path"] == "/run/autostream-pipes/autostream.fifo"


# ---------------------------------------------------------------------------
# from_before gating
# ---------------------------------------------------------------------------

class TestFromBeforeGating:

    def _state(self, tmp_path, tag):
        state = tmp_path / "install-state.env"
        state.write_text(f'AUTOSTREAM_RELEASE_TAG="{tag}"\n', encoding="utf-8")
        return state

    def test_gate_fires_when_old_tag_older(self, tmp_path):
        state = self._state(tmp_path, "0.4.0")
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(mode="ensure", key="server_name", value="hifi", from_before="0.5.0")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone, state=state)
        assert json.loads(owntone.read_text())["server_name"] == "hifi"

    def test_gate_skips_when_old_tag_not_older(self, tmp_path):
        state = self._state(tmp_path, "0.5.0")
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(mode="ensure", key="server_name", value="hifi", from_before="0.5.0")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone, state=state)
        assert not owntone.exists()

    def test_gate_skips_when_state_file_missing(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(mode="ensure", key="server_name", value="hifi", from_before="0.5.0")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone, state=tmp_path / "absent.env")
        assert not owntone.exists()

    def test_gate_skips_for_test_sentinel_tag(self, tmp_path):
        state = self._state(tmp_path, "test")
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(mode="ensure", key="server_name", value="hifi", from_before="0.5.0")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone, state=state)
        assert not owntone.exists()

    def test_gate_skips_for_unknown_sentinel_tag(self, tmp_path):
        state = self._state(tmp_path, "unknown")
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(mode="ensure", key="server_name", value="hifi", from_before="0.5.0")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone, state=state)
        assert not owntone.exists()

    def test_gate_skips_for_unparseable_tag(self, tmp_path):
        state = self._state(tmp_path, "not-numeric")
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(mode="ensure", key="server_name", value="hifi", from_before="0.5.0")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone, state=state)
        assert not owntone.exists()

    def test_ungated_directive_ignores_state(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(mode="ensure", key="server_name", value="hifi")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone, state=tmp_path / "absent.env")
        assert json.loads(owntone.read_text())["server_name"] == "hifi"

    def test_gate_fires_when_old_tag_is_beta_of_gate_version(self, tmp_path):
        # A device installed from a pre-release build records that build's
        # own tag; it must not be treated as untrustworthy just because it
        # carries a -beta.N suffix.
        state = self._state(tmp_path, "0.6.0-beta.1")
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(mode="ensure", key="server_name", value="hifi", from_before="0.6.0")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone, state=state)
        assert json.loads(owntone.read_text())["server_name"] == "hifi"

    def test_gate_skips_when_old_tag_is_final_release_of_gate_version(self, tmp_path):
        # The final 0.6.0 release is not older than its own beta -- confirms
        # a pre-release orders strictly below its final release.
        state = self._state(tmp_path, "0.6.0")
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(mode="ensure", key="server_name", value="hifi", from_before="0.6.0-beta.1")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone, state=state)
        assert not owntone.exists()

    def test_gate_fires_across_beta_to_beta(self, tmp_path):
        state = self._state(tmp_path, "0.6.0-beta.1")
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(mode="ensure", key="server_name", value="hifi", from_before="0.6.0-beta.2")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone, state=state)
        assert json.loads(owntone.read_text())["server_name"] == "hifi"

    def test_gate_orders_alpha_before_beta_before_rc_before_final(self, tmp_path):
        for older, newer in (
            ("0.6.0-alpha.1", "0.6.0-beta.1"),
            ("0.6.0-beta.1", "0.6.0-rc.1"),
            ("0.6.0-rc.1", "0.6.0"),
        ):
            state = self._state(tmp_path, older)
            owntone = tmp_path / "owntone-settings.json"
            d = _directive(mode="ensure", key="server_name", value="hifi", from_before=newer)
            path = _manifest_path(tmp_path, "m.json", [d])
            _run(tmp_path, [path], owntone=owntone, state=state)
            assert json.loads(owntone.read_text())["server_name"] == "hifi", (older, newer)
            owntone.unlink()

    def test_gate_skips_for_garbage_prerelease_tag(self, tmp_path):
        state = self._state(tmp_path, "0.6.0-nightly.1")
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(mode="ensure", key="server_name", value="hifi", from_before="0.6.0")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone, state=state)
        assert not owntone.exists()


# ---------------------------------------------------------------------------
# Result validation (brick-guards / ranges / shapes)
# ---------------------------------------------------------------------------

class TestResultValidation:

    @pytest.mark.parametrize("value", [44101, 0, -1])
    def test_pipe_sample_rate_rejected(self, tmp_path, value):
        owntone = tmp_path / "owntone-settings.json"
        original = owntone.exists() and owntone.read_text()
        d = _directive(key="pipe_sample_rate", value=value)
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="pipe_sample_rate"):
            _run(tmp_path, [path], owntone=owntone)
        assert not owntone.exists()

    def test_pipe_sample_rate_accepted_value_written(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(key="pipe_sample_rate", value=48000)
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone)
        assert json.loads(owntone.read_text())["pipe_sample_rate"] == 48000

    def test_pipe_bits_per_sample_rejected(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(key="pipe_bits_per_sample", value=24)
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="pipe_bits_per_sample"):
            _run(tmp_path, [path], owntone=owntone)
        assert not owntone.exists()

    def test_start_buffer_ms_out_of_range_rejected(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(key="start_buffer_ms", value=10)
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="start_buffer_ms"):
            _run(tmp_path, [path], owntone=owntone)

    def test_device_removal_grace_period_out_of_range_rejected(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(key="device_removal_grace_period", value=99999)
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="device_removal_grace_period"):
            _run(tmp_path, [path], owntone=owntone)

    def test_buffered_encoder_budget_out_of_range_rejected(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(key="buffered_encoder_budget", value=65)
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="buffered_encoder_budget"):
            _run(tmp_path, [path], owntone=owntone)

    def test_user_agent_empty_string_accepted(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(mode="overwrite", key="user_agent", value="", reason="reset")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone)
        assert json.loads(owntone.read_text())["user_agent"] == ""

    def test_user_agent_control_char_rejected(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(key="user_agent", value="bad\x07agent")
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="user_agent"):
            _run(tmp_path, [path], owntone=owntone)

    def test_user_agent_too_long_rejected(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(key="user_agent", value="x" * 256)
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="user_agent"):
            _run(tmp_path, [path], owntone=owntone)

    def test_port_out_of_range_rejected(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(key="airplay_timing_port", value=70000)
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="airplay_timing_port"):
            _run(tmp_path, [path], owntone=owntone)

    def test_trusted_networks_non_string_item_rejected(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(key="trusted_networks", value=["lan", 5])
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="trusted_networks"):
            _run(tmp_path, [path], owntone=owntone)

    def test_trusted_networks_list_of_strings_accepted(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(key="trusted_networks", value=["lan", "192.168.1.0/24"])
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone)
        assert json.loads(owntone.read_text())["trusted_networks"] == ["lan", "192.168.1.0/24"]

    def test_airplay_devices_non_object_value_rejected(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(key="airplay_devices", value={"Living Room": "not-an-object"})
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="airplay_devices"):
            _run(tmp_path, [path], owntone=owntone)

    def test_uid_unresolvable_rejected(self, tmp_path, stub_pwd):
        stub_pwd.side_effect = KeyError
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(key="uid", value="nosuchuser")
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="uid"):
            _run(tmp_path, [path], owntone=owntone)

    def test_uid_resolvable_accepted(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(key="uid", value="owntone")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone)
        assert json.loads(owntone.read_text())["uid"] == "owntone"

    def test_autostream_mdns_grace_period_out_of_range_rejected(self, tmp_path):
        autostream = tmp_path / "autostream.json"
        d = _directive(target="autostream", key="general.mdns_grace_period_seconds", value=1)
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="mdns_grace_period_seconds"):
            _run(tmp_path, [path], autostream=autostream)
        assert not autostream.exists()

    def test_autostream_mdns_grace_period_in_range_accepted(self, tmp_path):
        autostream = tmp_path / "autostream.json"
        d = _directive(target="autostream", key="general.mdns_grace_period_seconds", value=120)
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], autostream=autostream)
        assert json.loads(autostream.read_text())["general"]["mdns_grace_period_seconds"] == 120


# ---------------------------------------------------------------------------
# Existing file handling
# ---------------------------------------------------------------------------

class TestExistingFileHandling:

    def test_malformed_existing_file_raises_and_leaves_untouched(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        owntone.write_text("{not json", encoding="utf-8")
        d = _directive(key="server_name", value="hifi")
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="malformed JSON"):
            _run(tmp_path, [path], owntone=owntone)
        assert owntone.read_text() == "{not json"

    def test_missing_file_created_with_directive_content(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        assert not owntone.exists()
        d = _directive(key="server_name", value="hifi")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone)
        assert json.loads(owntone.read_text()) == {"server_name": "hifi"}

    def test_non_object_existing_file_raises(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        owntone.write_text("[1, 2, 3]", encoding="utf-8")
        d = _directive(key="server_name", value="hifi")
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="not a JSON object"):
            _run(tmp_path, [path], owntone=owntone)


# ---------------------------------------------------------------------------
# Ownership / mode on write
# ---------------------------------------------------------------------------

class TestOwnershipAndMode:

    def test_autostream_chown_and_chmod_applied(self, tmp_path, stub_pwd, stub_chown):
        # os.chmod's argument is asserted directly rather than the resulting
        # stat() mode bits: Windows filesystems do not honour POSIX mode
        # bits, so a real chmod(0o600) there does not read back as 0o600.
        stub_pwd.return_value = SimpleNamespace(pw_uid=1001, pw_gid=1002)
        autostream = tmp_path / "autostream.json"
        d = _directive(target="autostream", key="general.log_level", mode="ensure", value="info")
        path = _manifest_path(tmp_path, "m.json", [d])
        with patch("os.chmod") as stub_chmod:
            _run(tmp_path, [path], autostream=autostream)
        stub_chown.assert_called_once_with(autostream, 1001, 1002)
        stub_chmod.assert_called_once_with(autostream, 0o600)

    def test_autostream_missing_os_user_raises_before_write(self, tmp_path, stub_pwd):
        stub_pwd.side_effect = KeyError
        autostream = tmp_path / "autostream.json"
        d = _directive(target="autostream", key="general.log_level", mode="ensure", value="info")
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="autostream"):
            _run(tmp_path, [path], autostream=autostream)
        assert not autostream.exists()

    def test_owntone_chmod_0644(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(key="server_name", value="hifi")
        path = _manifest_path(tmp_path, "m.json", [d])
        with patch("os.chmod") as stub_chmod:
            _run(tmp_path, [path], owntone=owntone)
        stub_chmod.assert_called_once_with(owntone, 0o644)

    def test_owntone_write_does_not_touch_autostream_pwd(self, tmp_path, stub_pwd):
        """Only the autostream target needs OS-user resolution; a run that
        touches only owntone-mini must not require it to succeed."""
        stub_pwd.side_effect = KeyError
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(key="server_name", value="hifi")
        path = _manifest_path(tmp_path, "m.json", [d])
        _run(tmp_path, [path], owntone=owntone)
        assert json.loads(owntone.read_text())["server_name"] == "hifi"


# ---------------------------------------------------------------------------
# Multi-manifest ordering / --check-only / idempotency
# ---------------------------------------------------------------------------

class TestOrderingCheckOnlyIdempotency:

    def test_multi_manifest_applies_in_order(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        m1 = _manifest_path(tmp_path, "m1.json", [
            _directive(mode="ensure", key="server_name", value="first"),
        ])
        m2 = _manifest_path(tmp_path, "m2.json", [
            _directive(mode="overwrite", key="server_name", value="second", reason="later manifest wins"),
        ])
        _run(tmp_path, [m1, m2], owntone=owntone)
        assert json.loads(owntone.read_text())["server_name"] == "second"

    def test_manifest_order_reversed_changes_outcome(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        m1 = _manifest_path(tmp_path, "m1.json", [
            _directive(mode="overwrite", key="server_name", value="second", reason="applied first here"),
        ])
        m2 = _manifest_path(tmp_path, "m2.json", [
            _directive(mode="ensure", key="server_name", value="first"),
        ])
        _run(tmp_path, [m1, m2], owntone=owntone)
        assert json.loads(owntone.read_text())["server_name"] == "second"

    def test_check_only_writes_nothing(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(key="server_name", value="hifi")
        path = _manifest_path(tmp_path, "m.json", [d])
        rc = _run(tmp_path, [path], check_only=True, owntone=owntone)
        assert rc == 0
        assert not owntone.exists()

    def test_check_only_still_validates(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(key="pipe_sample_rate", value=1234)
        path = _manifest_path(tmp_path, "m.json", [d])
        with pytest.raises(m.EngineError, match="pipe_sample_rate"):
            _run(tmp_path, [path], check_only=True, owntone=owntone)
        assert not owntone.exists()

    def test_idempotent_rerun_is_byte_identical_and_writes_once(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(mode="overwrite", key="server_name", value="hifi", reason="converge")
        path = _manifest_path(tmp_path, "m.json", [d])

        _run(tmp_path, [path], owntone=owntone)
        first_bytes = owntone.read_bytes()
        first_mtime_ns = owntone.stat().st_mtime_ns

        _run(tmp_path, [path], owntone=owntone)
        second_bytes = owntone.read_bytes()

        assert second_bytes == first_bytes
        # No rewrite should have occurred at all on the converged second run.
        assert owntone.stat().st_mtime_ns == first_mtime_ns

    def test_mixed_target_directives_only_write_changed_targets(self, tmp_path):
        autostream = tmp_path / "autostream.json"
        owntone = tmp_path / "owntone-settings.json"
        owntone.write_text(json.dumps({"server_name": "already-set"}), encoding="utf-8")
        directives = [
            _directive(target="autostream", key="general.log_level", mode="ensure", value="info"),
            _directive(mode="ensure", key="server_name", value="already-set"),
        ]
        path = _manifest_path(tmp_path, "m.json", directives)
        before_mtime = owntone.stat().st_mtime_ns
        _run(tmp_path, [path], autostream=autostream, owntone=owntone)
        assert autostream.exists()
        assert owntone.stat().st_mtime_ns == before_mtime


# ---------------------------------------------------------------------------
# CLI-level default manifest path
# ---------------------------------------------------------------------------

class TestCLIDefaults:

    def test_default_manifest_path_is_relative_to_script(self):
        expected = REPO_ROOT / "installer" / "settings-directives.json"
        assert m._DEFAULT_MANIFEST_PATH == expected

    def test_main_check_only_returns_zero_and_writes_nothing(self, tmp_path):
        owntone = tmp_path / "owntone-settings.json"
        d = _directive(key="server_name", value="hifi")
        path = _manifest_path(tmp_path, "m.json", [d])
        rc = m.main([
            "--manifest", str(path),
            "--check-only",
            "--owntone-config", str(owntone),
            "--autostream-config", str(tmp_path / "autostream.json"),
            "--state-file", str(tmp_path / "install-state.env"),
        ])
        assert rc == 0
        assert not owntone.exists()

    def test_main_returns_nonzero_on_engine_error(self, tmp_path):
        rc = m.main(["--manifest", str(tmp_path / "nope.json")])
        assert rc == 1


# ---------------------------------------------------------------------------
# The manifest actually shipped with releases
# ---------------------------------------------------------------------------

class TestShippedManifest:

    _MANIFEST_PATH = REPO_ROOT / "installer" / "settings-directives.json"

    def test_shipped_manifest_validates(self, tmp_path):
        assert _run(tmp_path, [self._MANIFEST_PATH], check_only=True) == 0

    def test_fifo_directive_matches_config_constant(self):
        import autostream_config

        directives = json.loads(self._MANIFEST_PATH.read_text())["directives"]
        directive = next(d for d in directives if d["key"] == "general.fifo_path")
        assert directive["value"] == autostream_config.FIFO_PATH

    def test_mdns_directive_matches_config_constant(self):
        import autostream_config

        directives = json.loads(self._MANIFEST_PATH.read_text())["directives"]
        directive = next(d for d in directives if d["key"] == "general.mdns_grace_period_seconds")
        assert directive["value"] == autostream_config.DEFAULT_MDNS_GRACE_PERIOD_SECONDS


# ---------------------------------------------------------------------------
# The documentation example manifest
# ---------------------------------------------------------------------------

class TestExampleManifest:

    _MANIFEST_PATH = REPO_ROOT / "installer" / "settings-directives.example.json"

    def test_example_manifest_validates(self, tmp_path):
        assert (
            _run(
                tmp_path,
                [self._MANIFEST_PATH],
                check_only=True,
                autostream=tmp_path / "autostream.json",
                owntone=tmp_path / "owntone-settings.json",
            )
            == 0
        )
