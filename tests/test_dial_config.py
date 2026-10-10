"""Priority 5 — dial_config loading and saving tests.

Covers: hardware overlay, UUID fallback order, missing-UUID error,
malformed required JSON, save writing only mutable fields, chmod ordering,
fsync, atomic replace, and temp-file cleanup on error.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import dial_config as dc
from dial_config import (
    DialConfig,
    DialDisplayConfig,
    InvalidScreenSettings,
    load_config,
    save_config,
    validate_screen_settings,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_hw(path: Path, **extra) -> None:
    base = {"uuid": "hw-uuid-1234"}
    base.update(extra)
    path.write_text(json.dumps(base), encoding="utf-8")


def _write_settings(path: Path, **fields) -> None:
    path.write_text(json.dumps(fields), encoding="utf-8")


def _redirect(tmp_path: Path, *, hw_path: Path | None = None,
               settings_path: Path | None = None,
               install_state_path: Path | None = None):
    """Context manager that temporarily overrides dc path constants."""
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        orig_hw     = dc.HW_CONFIG_PATH
        orig_set    = dc.SETTINGS_PATH
        orig_state  = dc.INSTALL_STATE_PATH
        dc.HW_CONFIG_PATH     = hw_path     or orig_hw
        dc.SETTINGS_PATH      = settings_path or orig_set
        dc.INSTALL_STATE_PATH = install_state_path or orig_state
        try:
            yield
        finally:
            dc.HW_CONFIG_PATH     = orig_hw
            dc.SETTINGS_PATH      = orig_set
            dc.INSTALL_STATE_PATH = orig_state

    return _ctx()


# ---------------------------------------------------------------------------
# load_config: hardware overlay
# ---------------------------------------------------------------------------

class TestLoadConfigHardwareOverlay:
    def test_hardware_gpio_fields_applied(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, clk_gpio=4, dt_gpio=5, sw_gpio=6, led_gpio=7, port=9000)
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.clk_gpio == 4
        assert cfg.dt_gpio == 5
        assert cfg.sw_gpio == 6
        assert cfg.led_gpio == 7
        assert cfg.port == 9000

    def test_mutable_settings_overlay_applied(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        s = tmp_path / "settings.json"
        _write_settings(s, step_percent=5, name="Living Room",
                        pin="1234", auto_update=True, update_channel="dev")
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.step_percent == 5
        assert cfg.name == "Living Room"
        assert cfg.pin == "1234"
        assert cfg.auto_update is True
        assert cfg.update_channel == "dev"

    def test_missing_settings_file_uses_defaults(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        absent = tmp_path / "absent-settings.json"
        with _redirect(tmp_path, hw_path=hw, settings_path=absent):
            cfg = load_config()
        assert cfg.step_percent == 2
        assert cfg.name == ""
        assert cfg.pin == ""
        assert cfg.auto_update is False

    def test_hardware_uuid_used_when_present(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, uuid="dead-beef-uuid")
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.uuid == "dead-beef-uuid"

    def test_null_clk_dt_sw_gpio_become_none(self, tmp_path):
        """A screen-only dial has no rotary encoder or button wired up —
        explicit null in the hw config must load as None, mirroring led_gpio."""
        hw = tmp_path / "hw.json"
        _write_hw(hw, clk_gpio=None, dt_gpio=None, sw_gpio=None)
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.clk_gpio is None
        assert cfg.dt_gpio is None
        assert cfg.sw_gpio is None

    def test_absent_clk_dt_sw_gpio_keep_defaults(self, tmp_path):
        """Omitting the keys entirely (as opposed to explicit null) must
        preserve today's defaults, unchanged."""
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.clk_gpio == 17
        assert cfg.dt_gpio == 27
        assert cfg.sw_gpio == 22

    def test_explicit_int_clk_dt_sw_gpio_still_applied(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, clk_gpio=4, dt_gpio=5, sw_gpio=6)
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.clk_gpio == 4
        assert cfg.dt_gpio == 5
        assert cfg.sw_gpio == 6

    def test_invalid_update_channel_in_settings_defaults_to_stable(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        s = tmp_path / "settings.json"
        _write_settings(s, update_channel="nightly")
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.update_channel == "stable"


# ---------------------------------------------------------------------------
# load_config: UUID fallback order
# ---------------------------------------------------------------------------

class TestLoadConfigUUIDFallback:
    def test_uuid_fallback_to_install_state(self, tmp_path):
        hw = tmp_path / "hw.json"
        hw.write_text(json.dumps({"clk_gpio": 17, "dt_gpio": 27}), encoding="utf-8")
        state = tmp_path / "install-state.env"
        state.write_text('DIAL_UUID="fallback-uuid-9999"\n', encoding="utf-8")
        with _redirect(tmp_path, hw_path=hw, install_state_path=state):
            cfg = load_config()
        assert cfg.uuid == "fallback-uuid-9999"

    def test_hw_uuid_takes_precedence_over_install_state(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, uuid="hw-first")
        state = tmp_path / "install-state.env"
        state.write_text('DIAL_UUID="state-fallback"\n', encoding="utf-8")
        with _redirect(tmp_path, hw_path=hw, install_state_path=state):
            cfg = load_config()
        assert cfg.uuid == "hw-first"

    def test_missing_uuid_raises_runtime_error(self, tmp_path):
        hw = tmp_path / "hw.json"
        hw.write_text(json.dumps({"clk_gpio": 17}), encoding="utf-8")
        absent_state = tmp_path / "absent.env"
        with _redirect(tmp_path, hw_path=hw, install_state_path=absent_state):
            with pytest.raises(RuntimeError, match="UUID"):
                load_config()

    def test_empty_uuid_in_hw_falls_back_to_install_state(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, uuid="")
        state = tmp_path / "install-state.env"
        state.write_text('DIAL_UUID="env-uuid"\n', encoding="utf-8")
        with _redirect(tmp_path, hw_path=hw, install_state_path=state):
            cfg = load_config()
        assert cfg.uuid == "env-uuid"


# ---------------------------------------------------------------------------
# load_config: malformed JSON
# ---------------------------------------------------------------------------

class TestLoadConfigMalformedJSON:
    def test_missing_hw_config_raises(self, tmp_path):
        absent = tmp_path / "missing-hw.json"
        with _redirect(tmp_path, hw_path=absent):
            with pytest.raises((FileNotFoundError, OSError)):
                load_config()

    def test_malformed_hw_config_raises(self, tmp_path):
        hw = tmp_path / "hw.json"
        hw.write_text("not-json", encoding="utf-8")
        with _redirect(tmp_path, hw_path=hw):
            with pytest.raises(ValueError):
                load_config()


# ---------------------------------------------------------------------------
# save_config: mutable fields only
# ---------------------------------------------------------------------------

class TestSaveConfigMutableFieldsOnly:
    def test_saves_only_mutable_fields(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        orig = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = s
        try:
            cfg = DialConfig(
                clk_gpio=4, dt_gpio=5, port=9000,
                uuid="secret-uuid",
                step_percent=3, name="Test",
                pin="5678", auto_update=True, update_channel="dev",
            )
            save_config(cfg)
            data = json.loads(s.read_text())
        finally:
            dc.SETTINGS_PATH = orig

        assert set(data.keys()) == {
            "step_percent", "name", "pin", "auto_update", "update_channel",
            "sd_health_monitoring", "display",
        }
        assert "uuid" not in data
        assert "clk_gpio" not in data
        assert "port" not in data
        assert data["step_percent"] == 3
        assert data["name"] == "Test"
        assert data["pin"] == "5678"
        assert data["auto_update"] is True
        assert data["update_channel"] == "dev"

    def test_save_and_reload_round_trip(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        orig_s, orig_hw = dc.SETTINGS_PATH, dc.HW_CONFIG_PATH
        dc.SETTINGS_PATH = s
        dc.HW_CONFIG_PATH = hw
        try:
            cfg = DialConfig(uuid="hw-uuid-1234", name="Round Trip",
                             step_percent=7, auto_update=False, update_channel="stable")
            save_config(cfg)
            reloaded = load_config()
        finally:
            dc.SETTINGS_PATH = orig_s
            dc.HW_CONFIG_PATH = orig_hw

        assert reloaded.name == "Round Trip"
        assert reloaded.step_percent == 7


class TestSdHealthMonitoringSetting:
    def test_round_trip(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        orig_s, orig_hw = dc.SETTINGS_PATH, dc.HW_CONFIG_PATH
        dc.SETTINGS_PATH = s
        dc.HW_CONFIG_PATH = hw
        try:
            cfg = DialConfig(uuid="hw-uuid-1234", sd_health_monitoring=True)
            save_config(cfg)
            data = json.loads(s.read_text())
            reloaded = load_config()
        finally:
            dc.SETTINGS_PATH = orig_s
            dc.HW_CONFIG_PATH = orig_hw

        assert data["sd_health_monitoring"] is True
        assert reloaded.sd_health_monitoring is True

    def test_missing_key_loads_false(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        s.write_text(json.dumps({"step_percent": 2, "name": "", "pin": ""}), encoding="utf-8")
        orig_s, orig_hw = dc.SETTINGS_PATH, dc.HW_CONFIG_PATH
        dc.SETTINGS_PATH = s
        dc.HW_CONFIG_PATH = hw
        try:
            reloaded = load_config()
        finally:
            dc.SETTINGS_PATH = orig_s
            dc.HW_CONFIG_PATH = orig_hw

        assert reloaded.sd_health_monitoring is False


# ---------------------------------------------------------------------------
# volume_scope/mute_scope: broadcast scope for a screenless (or too-small-to-
# select) dial. Colocated with the other screen fields (DialDisplayConfig),
# same save/validate path. mute_all_playing (the field these two settings
# retire) no longer exists on DialConfig; a persisted mute_all_playing=true
# migrates to mute_scope="all" once, in load_config, when the settings file
# has no display.mute_scope key yet.
# ---------------------------------------------------------------------------

class TestScopeSettings:
    def test_defaults_are_current(self):
        d = DialDisplayConfig()
        assert d.volume_scope == "current"
        assert d.mute_scope == "current"

    def test_missing_settings_file_defaults_current(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.volume_scope == "current"
        assert cfg.display.mute_scope == "current"

    def test_hw_display_values_applied(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True, "volume_scope": "all", "mute_scope": "all"})
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.volume_scope == "all"
        assert cfg.display.mute_scope == "all"

    def test_mutable_settings_override_hw(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True, "volume_scope": "all", "mute_scope": "all"})
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True, "volume_scope": "current", "mute_scope": "current"})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.volume_scope == "current"
        assert cfg.display.mute_scope == "current"

    def test_persisted_garbage_falls_back_to_current_with_warning(self, tmp_path, caplog):
        import logging
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True, "volume_scope": "everything", "mute_scope": 1})
        with caplog.at_level(logging.WARNING):
            with _redirect(tmp_path, hw_path=hw, settings_path=s):
                cfg = load_config()
        assert cfg.display.volume_scope == "current"
        assert cfg.display.mute_scope == "current"
        assert any("scope" in r.getMessage() for r in caplog.records)

    def test_save_persists_both(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        orig = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = s
        try:
            cfg = DialConfig(
                uuid="x",
                display=DialDisplayConfig(fitted=True, volume_scope="all", mute_scope="all"),
            )
            save_config(cfg)
            data = json.loads(s.read_text())
        finally:
            dc.SETTINGS_PATH = orig
        assert data["display"]["volume_scope"] == "all"
        assert data["display"]["mute_scope"] == "all"

    def test_save_and_reload_round_trip(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        orig_s, orig_hw = dc.SETTINGS_PATH, dc.HW_CONFIG_PATH
        dc.SETTINGS_PATH = s
        dc.HW_CONFIG_PATH = hw
        try:
            cfg = DialConfig(
                uuid="hw-uuid-1234",
                display=DialDisplayConfig(fitted=True, volume_scope="all", mute_scope="current"),
            )
            save_config(cfg)
            reloaded = load_config()
        finally:
            dc.SETTINGS_PATH = orig_s
            dc.HW_CONFIG_PATH = orig_hw
        assert reloaded.display.volume_scope == "all"
        assert reloaded.display.mute_scope == "current"

    def test_mute_all_playing_not_persisted_by_save_config(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        orig = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = s
        try:
            save_config(DialConfig(uuid="x"))
            data = json.loads(s.read_text())
        finally:
            dc.SETTINGS_PATH = orig
        assert "mute_all_playing" not in data

    def test_legacy_mute_all_playing_true_migrates_to_mute_scope_all(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        s = tmp_path / "settings.json"
        _write_settings(s, mute_all_playing=True, display={"fitted": True})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.mute_scope == "all"

    def test_legacy_mute_all_playing_true_with_no_display_block_still_migrates(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        s = tmp_path / "settings.json"
        _write_settings(s, mute_all_playing=True)
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.mute_scope == "all"

    def test_legacy_mute_all_playing_false_does_not_force_all(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        s = tmp_path / "settings.json"
        _write_settings(s, mute_all_playing=False, display={"fitted": True})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.mute_scope == "current"

    def test_explicit_mute_scope_ignores_the_legacy_key(self, tmp_path):
        """Once a settings file has its own display.mute_scope, the legacy
        mute_all_playing key (even if still present from before an upgrade)
        is never consulted again."""
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        s = tmp_path / "settings.json"
        _write_settings(
            s, mute_all_playing=True,
            display={"fitted": True, "mute_scope": "current"},
        )
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.mute_scope == "current"

    def test_migration_does_not_touch_volume_scope(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        s = tmp_path / "settings.json"
        _write_settings(s, mute_all_playing=True, display={"fitted": True})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.volume_scope == "current"

    def test_migrated_config_saved_output_has_no_legacy_key_and_carries_mute_scope(self, tmp_path):
        """The migration only ever happens on load; the next save_config()
        writes mute_scope and never re-introduces the legacy key."""
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        s = tmp_path / "settings.json"
        _write_settings(s, mute_all_playing=True, display={"fitted": True})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
            save_config(cfg)
            data = json.loads(s.read_text())
        assert "mute_all_playing" not in data
        assert data["display"]["mute_scope"] == "all"


class TestEffectiveScope:
    def test_fitted_true_returns_stored(self):
        d = DialDisplayConfig(fitted=True, volume_scope="all", mute_scope="current")
        assert dc.effective_scope(d, d.volume_scope) == "all"
        assert dc.effective_scope(d, d.mute_scope) == "current"

    def test_fitted_false_always_returns_all(self):
        d = DialDisplayConfig(fitted=False, volume_scope="current", mute_scope="current")
        assert dc.effective_scope(d, d.volume_scope) == "all"
        assert dc.effective_scope(d, d.mute_scope) == "all"

    def test_dataclass_properties_agree_with_the_function(self):
        fitted = DialDisplayConfig(fitted=True, volume_scope="all", mute_scope="current")
        assert fitted.effective_volume_scope == dc.effective_scope(fitted, fitted.volume_scope)
        assert fitted.effective_mute_scope == dc.effective_scope(fitted, fitted.mute_scope)

        unfitted = DialDisplayConfig(fitted=False, volume_scope="current", mute_scope="all")
        assert unfitted.effective_volume_scope == "all"
        assert unfitted.effective_mute_scope == "all"


# ---------------------------------------------------------------------------
# save_config: chmod 0600 before data
# ---------------------------------------------------------------------------

class TestSaveConfigChmod:
    def test_chmod_called_with_0600(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        orig = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = s
        try:
            chmod_modes = []
            real_chmod = os.chmod

            def tracking_chmod(path, mode):
                chmod_modes.append(mode)
                real_chmod(path, mode)

            with patch("os.chmod", side_effect=tracking_chmod):
                save_config(DialConfig(uuid="x"))
        finally:
            dc.SETTINGS_PATH = orig

        assert 0o600 in chmod_modes, f"Expected chmod 0600, got modes: {[oct(m) for m in chmod_modes]}"

    def test_chmod_called_before_write(self, tmp_path):
        """chmod must be called on the temp file before data is written."""
        s = tmp_path / "dial-settings.json"
        orig = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = s
        try:
            call_order = []
            real_chmod = os.chmod
            real_fdopen = os.fdopen

            def tracking_chmod(path, mode):
                call_order.append("chmod")
                real_chmod(path, mode)

            def tracking_fdopen(fd, *args, **kwargs):
                call_order.append("fdopen")
                return real_fdopen(fd, *args, **kwargs)

            with patch("os.chmod", side_effect=tracking_chmod), \
                 patch("os.fdopen", side_effect=tracking_fdopen):
                save_config(DialConfig(uuid="x"))
        finally:
            dc.SETTINGS_PATH = orig

        assert call_order.index("chmod") < call_order.index("fdopen"), \
            f"chmod must precede fdopen; order was {call_order}"


# ---------------------------------------------------------------------------
# save_config: fsync
# ---------------------------------------------------------------------------

class TestSaveConfigFsync:
    def test_fsync_called(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        orig = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = s
        try:
            with patch("os.fsync") as mock_fsync:
                save_config(DialConfig(uuid="x"))
        finally:
            dc.SETTINGS_PATH = orig

        mock_fsync.assert_called_once()


# ---------------------------------------------------------------------------
# save_config: atomic replace and temp cleanup
# ---------------------------------------------------------------------------

class TestDisplaySettings:
    def test_missing_display_defaults_fitted_false(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.fitted is False

    def test_hw_display_fitted_true_applied(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True})
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.fitted is True

    def test_explicit_disabled_display_in_hw(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": False})
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.fitted is False

    def test_mutable_settings_override_hw_display(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": False})
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.fitted is True

    def test_save_persists_display_fitted(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        orig = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = s
        try:
            cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True))
            save_config(cfg)
            data = json.loads(s.read_text())
        finally:
            dc.SETTINGS_PATH = orig
        assert data["display"] == {
            "fitted": True, "rotate": False,
            "screen_type": dc.DEFAULT_PROFILE_KEY, "bgr": False,
            "touch_type": dc.DEFAULT_TOUCH_KEY,
            "always_show_controls": False,
            "screen_size_inches": None,
            "layout_size": None,
            "volume_scope": "current",
            "mute_scope": "current",
            "poll_interval_s": 6,
        }

    def test_missing_display_defaults_rotate_false(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.rotate is False

    def test_hw_display_rotate_true_applied(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True, "rotate": True})
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.rotate is True

    def test_mutable_settings_override_hw_rotate(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True, "rotate": False})
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True, "rotate": True})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.rotate is True

    def test_save_persists_display_rotate(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        orig = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = s
        try:
            cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True, rotate=True))
            save_config(cfg)
            data = json.loads(s.read_text())
        finally:
            dc.SETTINGS_PATH = orig
        assert data["display"] == {
            "fitted": True, "rotate": True,
            "screen_type": dc.DEFAULT_PROFILE_KEY, "bgr": False,
            "touch_type": dc.DEFAULT_TOUCH_KEY,
            "always_show_controls": False,
            "screen_size_inches": None,
            "layout_size": None,
            "volume_scope": "current",
            "mute_scope": "current",
            "poll_interval_s": 6,
        }


class TestScreenTypeAndBgrSettings:
    def test_missing_display_defaults_screen_type(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.screen_type == dc.DEFAULT_PROFILE_KEY

    def test_missing_display_defaults_bgr_false(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.bgr is False

    def test_hw_display_screen_type_applied(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True, "screen_type": "ili9341_320x240"})
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.screen_type == "ili9341_320x240"

    def test_hw_display_bgr_true_applied(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True, "bgr": True})
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.bgr is True

    def test_mutable_settings_override_hw_screen_type(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True, "screen_type": "st7735s_160x128"})
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True, "screen_type": "st7789_320x240"})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.screen_type == "st7789_320x240"

    def test_mutable_settings_override_hw_bgr(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True, "bgr": False})
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True, "bgr": True})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.bgr is True

    def test_save_persists_screen_type_and_bgr(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        orig = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = s
        try:
            cfg = DialConfig(
                uuid="x",
                display=DialDisplayConfig(fitted=True, screen_type="st7789_240x240", bgr=True),
            )
            save_config(cfg)
            data = json.loads(s.read_text())
        finally:
            dc.SETTINGS_PATH = orig
        assert data["display"]["screen_type"] == "st7789_240x240"
        assert data["display"]["bgr"] is True

    def test_corrupt_persisted_screen_type_in_settings_falls_back_to_default(self, tmp_path):
        """A corrupt/stale settings file must not brick the dial at startup —
        an unknown screen_type falls back to the default profile with a
        warning log rather than raising."""
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True, "screen_type": "no_such_panel_anymore"})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.screen_type == dc.DEFAULT_PROFILE_KEY
        assert cfg.display.fitted is True

    def test_corrupt_hw_screen_type_falls_back_to_default(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True, "screen_type": "totally_bogus"})
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.screen_type == dc.DEFAULT_PROFILE_KEY


class TestTouchTypeSettings:
    def test_missing_display_defaults_touch_type(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.touch_type == dc.DEFAULT_TOUCH_KEY

    def test_hw_display_touch_type_applied(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True, "touch_type": "xpt2046"})
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.touch_type == "xpt2046"

    def test_mutable_settings_override_hw_touch_type(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True, "touch_type": "xpt2046"})
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True, "touch_type": "ft6206"})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.touch_type == "ft6206"

    def test_save_persists_touch_type(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        orig = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = s
        try:
            cfg = DialConfig(
                uuid="x",
                display=DialDisplayConfig(fitted=True, touch_type="ft6206"),
            )
            save_config(cfg)
            data = json.loads(s.read_text())
        finally:
            dc.SETTINGS_PATH = orig
        assert data["display"]["touch_type"] == "ft6206"

    def test_save_and_reload_round_trip_touch_type(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        orig_s, orig_hw = dc.SETTINGS_PATH, dc.HW_CONFIG_PATH
        dc.SETTINGS_PATH = s
        dc.HW_CONFIG_PATH = hw
        try:
            cfg = DialConfig(uuid="hw-uuid-1234", display=DialDisplayConfig(fitted=True, touch_type="xpt2046"))
            save_config(cfg)
            reloaded = load_config()
        finally:
            dc.SETTINGS_PATH = orig_s
            dc.HW_CONFIG_PATH = orig_hw
        assert reloaded.display.touch_type == "xpt2046"

    def test_corrupt_persisted_touch_type_in_settings_falls_back_to_default(self, tmp_path):
        """A corrupt/stale settings file must not brick the dial at startup —
        an unknown touch_type falls back to the default controller with a
        warning log rather than raising."""
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True, "touch_type": "no_such_controller_anymore"})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.touch_type == dc.DEFAULT_TOUCH_KEY
        assert cfg.display.fitted is True

    def test_corrupt_hw_touch_type_falls_back_to_default(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True, "touch_type": "totally_bogus"})
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.touch_type == dc.DEFAULT_TOUCH_KEY


# ---------------------------------------------------------------------------
# "Always show controls" screen setting (B.2) — colocated with the other
# screen fields, same save path and validation path as rotate/bgr/touch_type.
# ---------------------------------------------------------------------------

class TestAlwaysShowControlsSetting:
    def test_missing_display_defaults_false(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.always_show_controls is False

    def test_hw_display_true_applied(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True, "always_show_controls": True})
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.always_show_controls is True

    def test_mutable_settings_override_hw(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True, "always_show_controls": True})
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True, "always_show_controls": False})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.always_show_controls is False

    def test_save_persists(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        orig = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = s
        try:
            cfg = DialConfig(
                uuid="x",
                display=DialDisplayConfig(fitted=True, always_show_controls=True),
            )
            save_config(cfg)
            data = json.loads(s.read_text())
        finally:
            dc.SETTINGS_PATH = orig
        assert data["display"]["always_show_controls"] is True

    def test_save_and_reload_round_trip(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        orig_s, orig_hw = dc.SETTINGS_PATH, dc.HW_CONFIG_PATH
        dc.SETTINGS_PATH = s
        dc.HW_CONFIG_PATH = hw
        try:
            cfg = DialConfig(
                uuid="hw-uuid-1234",
                display=DialDisplayConfig(fitted=True, always_show_controls=True),
            )
            save_config(cfg)
            reloaded = load_config()
        finally:
            dc.SETTINGS_PATH = orig_s
            dc.HW_CONFIG_PATH = orig_hw
        assert reloaded.display.always_show_controls is True

    def test_non_bool_persisted_value_coerced_by_bool(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True, "always_show_controls": 1})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.always_show_controls is True


class TestPollInterval:
    def test_default_matches_the_display_constant(self):
        import dial_display
        assert dc.POLL_INTERVAL_DEFAULT_S == dial_display.DISPLAY_POLL_INTERVAL_SECONDS
        assert DialDisplayConfig().poll_interval_s == dc.POLL_INTERVAL_DEFAULT_S

    @pytest.mark.parametrize("value", [2, 3, 4, 5, 6])
    def test_valid_values_accepted(self, value):
        result = validate_screen_settings({"fitted": True, "poll_interval_s": value})
        assert result == DialDisplayConfig(fitted=True, poll_interval_s=value)

    def test_omitted_defaults_to_six(self):
        result = validate_screen_settings({"fitted": True})
        assert result.poll_interval_s == 6

    @pytest.mark.parametrize("value", [1, 7, 0, -3, "6", 6.0, 2.5, True, False, None, [6]])
    def test_invalid_values_rejected(self, value):
        with pytest.raises(InvalidScreenSettings, match="poll_interval_s"):
            validate_screen_settings({"fitted": True, "poll_interval_s": value})

    def test_missing_display_defaults_to_six(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.poll_interval_s == 6

    def test_mutable_settings_override_hw(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True, "poll_interval_s": 4})
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True, "poll_interval_s": 2})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.poll_interval_s == 2

    def test_settings_without_the_key_keep_the_hw_value(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True, "poll_interval_s": 4})
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.poll_interval_s == 4

    @pytest.mark.parametrize("value", [0, 9, "3", 3.0, True])
    def test_unusable_persisted_value_falls_back_to_default(self, tmp_path, value):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True, "poll_interval_s": value})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.poll_interval_s == 6

    def test_save_and_reload_round_trip(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        orig_s, orig_hw = dc.SETTINGS_PATH, dc.HW_CONFIG_PATH
        dc.SETTINGS_PATH = s
        dc.HW_CONFIG_PATH = hw
        try:
            cfg = DialConfig(
                uuid="hw-uuid-1234",
                display=DialDisplayConfig(fitted=True, poll_interval_s=3),
            )
            save_config(cfg)
            data = json.loads(s.read_text())
            reloaded = load_config()
        finally:
            dc.SETTINGS_PATH = orig_s
            dc.HW_CONFIG_PATH = orig_hw
        assert data["display"]["poll_interval_s"] == 3
        assert reloaded.display.poll_interval_s == 3


# ---------------------------------------------------------------------------
# Screen-size setting (physical diagonal, inches) — colocated with the other
# screen fields, same save path and validation path as the settings above.
# None means "use the selected profile's own built-in default".
# ---------------------------------------------------------------------------

class TestScreenSizeInchesSetting:
    def test_default_is_none(self):
        assert DialDisplayConfig().screen_size_inches is None

    def test_missing_display_defaults_none(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.screen_size_inches is None

    def test_hw_display_value_applied(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True, "screen_size_inches": 2.8})
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.screen_size_inches == 2.8

    def test_mutable_settings_override_hw(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={"fitted": True, "screen_size_inches": 1.8})
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True, "screen_size_inches": 3.5})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.screen_size_inches == 3.5

    def test_save_persists_float(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        orig = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = s
        try:
            cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True, screen_size_inches=2.8))
            save_config(cfg)
            data = json.loads(s.read_text())
        finally:
            dc.SETTINGS_PATH = orig
        assert data["display"]["screen_size_inches"] == 2.8

    def test_save_persists_none_as_null(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        orig = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = s
        try:
            cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True, screen_size_inches=None))
            save_config(cfg)
            data = json.loads(s.read_text())
        finally:
            dc.SETTINGS_PATH = orig
        assert data["display"]["screen_size_inches"] is None

    def test_save_and_reload_round_trip(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        orig_s, orig_hw = dc.SETTINGS_PATH, dc.HW_CONFIG_PATH
        dc.SETTINGS_PATH = s
        dc.HW_CONFIG_PATH = hw
        try:
            cfg = DialConfig(
                uuid="hw-uuid-1234",
                display=DialDisplayConfig(fitted=True, screen_size_inches=3.5),
            )
            save_config(cfg)
            reloaded = load_config()
        finally:
            dc.SETTINGS_PATH = orig_s
            dc.HW_CONFIG_PATH = orig_hw
        assert reloaded.display.screen_size_inches == 3.5

    def test_missing_key_migration_resolves_to_profile_default(self, tmp_path):
        """A settings file written before this field existed has no key at
        all -- must resolve to None (falling through to the selected
        profile's own default), never raise, and never coerce to a stray
        value."""
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True, "screen_type": "ili9341_320x240"})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.screen_size_inches is None

        from dial_display_profiles import effective_diagonal_inches, get_profile

        profile = get_profile(cfg.display.screen_type)
        assert effective_diagonal_inches(profile, cfg.display.screen_size_inches) == 2.8

    def test_corrupt_string_value_falls_back_to_none(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True, "screen_size_inches": "2.8"})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.screen_size_inches is None

    def test_corrupt_bool_value_falls_back_to_none(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True, "screen_size_inches": True})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.screen_size_inches is None

    def test_corrupt_out_of_range_value_falls_back_to_none(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        s = tmp_path / "settings.json"
        _write_settings(s, display={"fitted": True, "screen_size_inches": 25})
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.screen_size_inches is None


class TestLayoutSizeSetting:
    def test_default_is_none(self):
        assert DialDisplayConfig().layout_size is None

    def test_missing_display_defaults_none(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw)
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.layout_size is None

    def test_hw_display_value_applied(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={
            "fitted": True, "screen_type": "ili9341_320x240", "layout_size": "large",
        })
        with _redirect(tmp_path, hw_path=hw):
            cfg = load_config()
        assert cfg.display.layout_size == "large"

    def test_mutable_settings_override_hw(self, tmp_path):
        hw = tmp_path / "hw.json"
        _write_hw(hw, display={
            "fitted": True, "screen_type": "ili9341_320x240", "layout_size": "small",
        })
        s = tmp_path / "settings.json"
        _write_settings(s, display={
            "fitted": True, "screen_type": "ili9341_320x240", "layout_size": "medium",
        })
        with _redirect(tmp_path, hw_path=hw, settings_path=s):
            cfg = load_config()
        assert cfg.display.layout_size == "medium"

    def test_save_persists_string(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        orig = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = s
        try:
            cfg = DialConfig(uuid="x", display=DialDisplayConfig(
                fitted=True, screen_type="ili9341_320x240", layout_size="large",
            ))
            save_config(cfg)
            data = json.loads(s.read_text())
        finally:
            dc.SETTINGS_PATH = orig
        assert data["display"]["layout_size"] == "large"

    def test_save_persists_none_as_null(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        orig = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = s
        try:
            cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True, layout_size=None))
            save_config(cfg)
            data = json.loads(s.read_text())
        finally:
            dc.SETTINGS_PATH = orig
        assert data["display"]["layout_size"] is None

    def test_validate_accepts_null(self):
        result = validate_screen_settings({"fitted": True})
        assert result.layout_size is None

    def test_validate_accepts_offered_key_for_default_profile(self):
        result = validate_screen_settings({"fitted": True, "layout_size": "small"})
        assert result.layout_size == "small"

    @pytest.mark.parametrize("key", ["small", "medium", "large"])
    def test_validate_accepts_every_offered_key_on_a_4x3_panel(self, key):
        result = validate_screen_settings({
            "fitted": True, "screen_type": "ili9341_320x240", "layout_size": key,
        })
        assert result.layout_size == key

    def test_validate_rejects_non_string(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "layout_size": 1})

    def test_validate_rejects_bool(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "layout_size": True})

    def test_validate_rejects_unknown_string(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "layout_size": "huge"})

    def test_validate_rejects_key_not_offered_for_screen_type(self):
        """"medium" is native on a 4:3 panel but not offered on the default
        5:4 st7789_240x240... use a square panel instead, which offers
        nothing at all."""
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({
                "fitted": True, "screen_type": "st7789_240x240", "layout_size": "medium",
            })

    def test_persisted_resolver_warns_and_yields_none_for_unknown_value(self, caplog):
        from dial_config import _resolve_persisted_layout_size
        with caplog.at_level("WARNING"):
            result = _resolve_persisted_layout_size("huge", "ili9341_320x240")
        assert result is None
        assert "layout_size" in caplog.text

    def test_persisted_resolver_warns_and_yields_none_for_value_not_offered(self, caplog):
        from dial_config import _resolve_persisted_layout_size
        with caplog.at_level("WARNING"):
            result = _resolve_persisted_layout_size("medium", "st7789_240x240")
        assert result is None
        assert "layout_size" in caplog.text

    def test_persisted_resolver_silent_for_none(self, caplog):
        from dial_config import _resolve_persisted_layout_size
        with caplog.at_level("WARNING"):
            result = _resolve_persisted_layout_size(None, "ili9341_320x240")
        assert result is None
        assert caplog.text == ""

    def test_persisted_resolver_accepts_offered_value(self):
        from dial_config import _resolve_persisted_layout_size
        assert _resolve_persisted_layout_size("large", "ili9341_320x240") == "large"


class TestValidateScreenSettings:
    def test_valid_true_accepted(self):
        result = validate_screen_settings({"fitted": True})
        assert result == DialDisplayConfig(fitted=True)

    def test_valid_false_accepted(self):
        result = validate_screen_settings({"fitted": False})
        assert result == DialDisplayConfig(fitted=False)

    def test_missing_fitted_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({})

    def test_non_object_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings("true")

    def test_unknown_field_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "rotation": 90})

    def test_integer_fitted_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": 1})

    def test_string_fitted_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": "true"})

    def test_valid_rotate_true_accepted(self):
        result = validate_screen_settings({"fitted": True, "rotate": True})
        assert result == DialDisplayConfig(fitted=True, rotate=True)

    def test_valid_rotate_false_accepted(self):
        result = validate_screen_settings({"fitted": True, "rotate": False})
        assert result == DialDisplayConfig(fitted=True, rotate=False)

    def test_rotate_omitted_defaults_false(self):
        result = validate_screen_settings({"fitted": True})
        assert result == DialDisplayConfig(fitted=True, rotate=False)

    def test_integer_rotate_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "rotate": 1})

    def test_string_rotate_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "rotate": "true"})

    def test_valid_bgr_true_accepted(self):
        result = validate_screen_settings({"fitted": True, "bgr": True})
        assert result == DialDisplayConfig(fitted=True, bgr=True)

    def test_valid_bgr_false_accepted(self):
        result = validate_screen_settings({"fitted": True, "bgr": False})
        assert result == DialDisplayConfig(fitted=True, bgr=False)

    def test_bgr_omitted_defaults_false(self):
        result = validate_screen_settings({"fitted": True})
        assert result == DialDisplayConfig(fitted=True, bgr=False)

    def test_integer_bgr_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "bgr": 1})

    def test_string_bgr_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "bgr": "true"})

    def test_valid_screen_type_accepted(self):
        result = validate_screen_settings({"fitted": True, "screen_type": "st7789_240x240"})
        assert result == DialDisplayConfig(fitted=True, screen_type="st7789_240x240")

    def test_screen_type_omitted_defaults_to_default_profile_key(self):
        result = validate_screen_settings({"fitted": True})
        assert result == DialDisplayConfig(fitted=True, screen_type=dc.DEFAULT_PROFILE_KEY)

    def test_unknown_screen_type_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "screen_type": "no_such_panel"})

    def test_non_string_screen_type_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "screen_type": 42})

    def test_valid_touch_type_accepted(self):
        result = validate_screen_settings({"fitted": True, "touch_type": "xpt2046"})
        assert result == DialDisplayConfig(fitted=True, touch_type="xpt2046")

    def test_touch_type_omitted_defaults_to_default_touch_key(self):
        result = validate_screen_settings({"fitted": True})
        assert result == DialDisplayConfig(fitted=True, touch_type=dc.DEFAULT_TOUCH_KEY)

    def test_unknown_touch_type_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "touch_type": "no_such_controller"})

    def test_non_string_touch_type_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "touch_type": 42})

    def test_valid_always_show_controls_true_accepted(self):
        result = validate_screen_settings({"fitted": True, "always_show_controls": True})
        assert result == DialDisplayConfig(fitted=True, always_show_controls=True)

    def test_valid_always_show_controls_false_accepted(self):
        result = validate_screen_settings({"fitted": True, "always_show_controls": False})
        assert result == DialDisplayConfig(fitted=True, always_show_controls=False)

    def test_always_show_controls_omitted_defaults_false(self):
        result = validate_screen_settings({"fitted": True})
        assert result == DialDisplayConfig(fitted=True, always_show_controls=False)

    def test_integer_always_show_controls_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "always_show_controls": 1})

    def test_string_always_show_controls_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "always_show_controls": "true"})

    def test_compat_old_appliance_omitting_field_defaults_false(self):
        """An old appliance's whole-object POST never sends the field at
        all — this must default rather than 400, so an old appliance saving
        any OTHER screen setting on a new dial does not get rejected."""
        result = validate_screen_settings({
            "fitted": True, "rotate": True, "screen_type": dc.DEFAULT_PROFILE_KEY,
            "bgr": False, "touch_type": dc.DEFAULT_TOUCH_KEY,
        })
        assert result.always_show_controls is False

    def test_screen_size_inches_absent_defaults_none(self):
        result = validate_screen_settings({"fitted": True})
        assert result.screen_size_inches is None

    def test_screen_size_inches_null_accepted(self):
        result = validate_screen_settings({"fitted": True, "screen_size_inches": None})
        assert result.screen_size_inches is None

    def test_screen_size_inches_float_accepted(self):
        result = validate_screen_settings({"fitted": True, "screen_size_inches": 2.8})
        assert result.screen_size_inches == 2.8

    def test_screen_size_inches_int_accepted_and_becomes_float(self):
        result = validate_screen_settings({"fitted": True, "screen_size_inches": 3})
        assert result.screen_size_inches == 3.0
        assert isinstance(result.screen_size_inches, float)

    def test_screen_size_inches_bool_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "screen_size_inches": True})

    def test_screen_size_inches_string_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "screen_size_inches": "2.8"})

    def test_screen_size_inches_below_range_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "screen_size_inches": 0.1})

    def test_screen_size_inches_above_range_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "screen_size_inches": 25})

    def test_screen_size_inches_boundary_values_accepted(self):
        assert validate_screen_settings(
            {"fitted": True, "screen_size_inches": 0.5}
        ).screen_size_inches == 0.5
        assert validate_screen_settings(
            {"fitted": True, "screen_size_inches": 20}
        ).screen_size_inches == 20.0

    def test_volume_scope_omitted_defaults_current(self):
        result = validate_screen_settings({"fitted": True})
        assert result.volume_scope == "current"

    def test_volume_scope_all_accepted(self):
        result = validate_screen_settings({"fitted": True, "volume_scope": "all"})
        assert result.volume_scope == "all"

    def test_volume_scope_current_accepted(self):
        result = validate_screen_settings({"fitted": True, "volume_scope": "current"})
        assert result.volume_scope == "current"

    def test_volume_scope_non_string_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "volume_scope": True})

    def test_volume_scope_unknown_string_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "volume_scope": "everything"})

    def test_mute_scope_omitted_defaults_current(self):
        result = validate_screen_settings({"fitted": True})
        assert result.mute_scope == "current"

    def test_mute_scope_all_accepted(self):
        result = validate_screen_settings({"fitted": True, "mute_scope": "all"})
        assert result.mute_scope == "all"

    def test_mute_scope_non_string_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "mute_scope": 1})

    def test_mute_scope_unknown_string_rejected(self):
        with pytest.raises(InvalidScreenSettings):
            validate_screen_settings({"fitted": True, "mute_scope": "everything"})

    def test_compat_old_appliance_omitting_scope_fields_defaults_current(self):
        """An old appliance's whole-object POST never sends these fields at
        all — must default rather than 400, exactly like always_show_controls
        above."""
        result = validate_screen_settings({
            "fitted": True, "rotate": True, "screen_type": dc.DEFAULT_PROFILE_KEY,
            "bgr": False, "touch_type": dc.DEFAULT_TOUCH_KEY,
            "always_show_controls": False,
        })
        assert result.volume_scope == "current"
        assert result.mute_scope == "current"


class TestRunningMarkerPath:
    """RUNNING_MARKER_PATH is the unclean-shutdown signal dial_main.py
    lifecycles — it MUST sit on real disk beside SETTINGS_PATH, never in
    /run or any other tmpfs (tmpfs is cleared at every boot, which would
    make the signal permanently absent and silently defeat the whole
    feature built on top of it)."""

    def test_marker_is_under_the_state_directory(self):
        assert dc.RUNNING_MARKER_PATH.parent == dc.SETTINGS_PATH.parent

    def test_marker_is_not_under_run(self):
        assert "/run/" not in dc.RUNNING_MARKER_PATH.as_posix()
        assert not dc.RUNNING_MARKER_PATH.as_posix().startswith("/run/")

    def test_marker_filename(self):
        assert dc.RUNNING_MARKER_PATH.name == "running.txt"


class TestPinResetPath:
    """PIN_RESET_PATH is the PIN-recovery arm-request file dial_main.py
    consumes at startup — same real-disk placement rule as
    RUNNING_MARKER_PATH above and for the same reason."""

    def test_path_is_under_the_state_directory(self):
        assert dc.PIN_RESET_PATH.parent == dc.SETTINGS_PATH.parent

    def test_path_is_not_under_run(self):
        assert "/run/" not in dc.PIN_RESET_PATH.as_posix()
        assert not dc.PIN_RESET_PATH.as_posix().startswith("/run/")

    def test_path_filename(self):
        assert dc.PIN_RESET_PATH.name == "pin_reset.txt"


class TestSaveConfigAtomic:
    def test_settings_path_exists_after_save(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        orig = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = s
        try:
            save_config(DialConfig(uuid="x"))
        finally:
            dc.SETTINGS_PATH = orig

        assert s.exists()
        assert not any(tmp_path.glob("*.tmp")), "Temp file should have been replaced/removed"

    def test_temp_file_removed_on_error(self, tmp_path):
        s = tmp_path / "dial-settings.json"
        orig = dc.SETTINGS_PATH
        dc.SETTINGS_PATH = s
        try:
            with patch.object(Path, "replace", side_effect=OSError("disk full")):
                with pytest.raises(OSError, match="disk full"):
                    save_config(DialConfig(uuid="x"))
        finally:
            dc.SETTINGS_PATH = orig

        assert not any(tmp_path.glob("*.tmp")), "Temp file must be cleaned up after error"
