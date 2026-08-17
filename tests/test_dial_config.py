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

        assert set(data.keys()) == {"step_percent", "name", "pin", "auto_update", "update_channel", "display"}
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
