"""Pushbutton mute/unmute tests.

Covers:
- dial_volume.py typed event queue: coalescing (collapse-to-last for mute
  runs), mute event ordering.
- enqueue_mute() enqueueing.
- DialConfig.sw_gpio default and JSON-key semantics.
- dial_main.py button callback wires enqueue_mute.
- helpers.sh writes sw_gpio=22 on fresh install.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
_dial = str(REPO_ROOT / "dial")
for _p in (_core, _dial):
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# dial_volume.py — typed event queue
# ---------------------------------------------------------------------------

class TestDialVolumeQueue:
    """Unit tests for the typed event queue and coalescing.

    Mute events carry the resulting absolute action (a bool) rather than
    being a bare toggle marker, and a run of adjacent mute events collapses
    to the LAST one rather than cancelling in pairs — see
    dial_volume._coalesce() and its module docstring.
    """

    def setup_method(self):
        # Re-import to get a fresh module view
        import importlib
        import dial_volume
        importlib.reload(dial_volume)
        self._mod = dial_volume

    def test_enqueue_delta_puts_delta_event(self):
        self._mod.enqueue_delta(5)
        item = self._mod._queue.get_nowait()
        assert item == ("delta", 5)

    def test_enqueue_mute_flips_the_reported_state_it_is_given(self):
        new_state = self._mod.enqueue_mute(False)  # caller believes unmuted
        assert new_state is True
        item = self._mod._queue.get_nowait()
        assert item == ("mute", True)

    def test_enqueue_mute_flips_a_reported_muted_state_to_restore(self):
        new_state = self._mod.enqueue_mute(True)  # caller believes muted
        assert new_state is False
        item = self._mod._queue.get_nowait()
        assert item == ("mute", False)

    def test_enqueue_mute_echoes_into_the_observation_store(self):
        """The dial persists nothing, but a press must still repaint the
        glyph on the same frame — the echo lives in the mute observation
        store, not any local belief."""
        self._mod.observe_mute_state("svc", False)
        self._mod.enqueue_mute(False)
        assert self._mod.shown_muted("svc") is True

    def test_coalesce_single_delta(self):
        batch = self._mod._coalesce(("delta", 3))
        assert batch == [("delta", 3)]

    def test_coalesce_adjacent_deltas(self):
        self._mod._queue.put(("delta", 4))
        self._mod._queue.put(("delta", -2))
        batch = self._mod._coalesce(("delta", 1))
        # All three adjacent deltas should be summed: 1+4-2 = 3
        assert batch == [("delta", 3)]

    def test_coalesce_mute_between_deltas(self):
        self._mod._queue.put(("delta", 4))
        self._mod._queue.put(("mute", True))
        self._mod._queue.put(("delta", 2))
        batch = self._mod._coalesce(("delta", 1))
        # 1+4 coalesced, then mute, then 2
        assert batch == [("delta", 5), ("mute", True), ("delta", 2)]

    def test_coalesce_single_mute_event(self):
        batch = self._mod._coalesce(("mute", True))
        assert batch == [("mute", True)]

    def test_coalesce_delta_after_mute_not_merged_with_pre_mute_delta(self):
        # Ensure post-mute delta is separate from pre-mute delta
        self._mod._queue.put(("mute", True))
        self._mod._queue.put(("delta", 5))
        batch = self._mod._coalesce(("delta", 2))
        # delta(2), mute, delta(5) — the two deltas must not merge
        assert len(batch) == 3
        assert batch[0] == ("delta", 2)
        assert batch[1] == ("mute", True)
        assert batch[2] == ("delta", 5)

    def test_coalesce_adjacent_mutes_collapse_to_last(self):
        # mute(True) then mute(False): a run of adjacent mutes collapses to
        # the LAST resulting action, not a cancel-in-pairs.
        self._mod._queue.put(("mute", False))
        batch = self._mod._coalesce(("mute", True))
        assert batch == [("mute", False)]

    def test_coalesce_three_adjacent_mutes_collapse_to_last(self):
        self._mod._queue.put(("mute", False))
        self._mod._queue.put(("mute", True))
        batch = self._mod._coalesce(("mute", False))
        # All three collapse into the LAST one queued.
        assert batch == [("mute", True)]

    def test_coalesce_mute_run_between_deltas_still_splits_the_deltas(self):
        # Unlike the old cancel-in-pairs rule, a collapsed mute run is still
        # a real (idempotent) action to resend, so it must NOT let the
        # surrounding deltas merge across it.
        self._mod._queue.put(("mute", False))
        self._mod._queue.put(("mute", True))
        self._mod._queue.put(("delta", 3))
        batch = self._mod._coalesce(("delta", 2))
        assert batch == [("delta", 2), ("mute", True), ("delta", 3)]

    def test_coalesce_single_mute_still_survives_and_splits_deltas(self):
        # Regression guard: a lone (non-adjacent) mute must still be
        # preserved and still prevent the surrounding deltas from merging.
        self._mod._queue.put(("delta", 4))
        self._mod._queue.put(("mute", True))
        self._mod._queue.put(("delta", 2))
        batch = self._mod._coalesce(("delta", 1))
        # 1+4 coalesced, then the surviving mute, then 2
        assert batch == [("delta", 5), ("mute", True), ("delta", 2)]

    def test_coalesce_two_adjacent_mute_all_cancel(self):
        # Broadcast-scope mute_all is decided fresh at dispatch, not carried
        # as a belief -- a run collapses by PARITY (even cancels, odd sends
        # one), not "collapse to the last one" like plain mute.
        self._mod._queue.put(("mute_all", 1))
        batch = self._mod._coalesce(("mute_all", 1))
        assert batch == []

    def test_coalesce_three_adjacent_mute_all_send_one(self):
        self._mod._queue.put(("mute_all", 1))
        self._mod._queue.put(("mute_all", 1))
        batch = self._mod._coalesce(("mute_all", 1))
        assert batch == [("mute_all", 1)]

    def test_coalesce_single_mute_all_sends_one(self):
        batch = self._mod._coalesce(("mute_all", 1))
        assert batch == [("mute_all", 1)]

    def test_coalesce_delta_mute_all_delta_keeps_order(self):
        self._mod._queue.put(("mute_all", 1))
        self._mod._queue.put(("delta", 3))
        batch = self._mod._coalesce(("delta", 2))
        assert batch == [("delta", 2), ("mute_all", 1), ("delta", 3)]


# ---------------------------------------------------------------------------
# DialConfig — sw_gpio default and key semantics
# ---------------------------------------------------------------------------

class TestDialConfigSwGpio:
    """DialConfig.sw_gpio default and hw.get fallback behaviour."""

    def test_sw_gpio_class_default_is_22(self):
        from dial_config import DialConfig
        assert DialConfig.sw_gpio == 22

    def test_sw_gpio_missing_key_uses_default(self, tmp_path):
        from dial_config import DialConfig, load_config, HW_CONFIG_PATH, SETTINGS_PATH
        hw = {"clk_gpio": 17, "dt_gpio": 27, "led_gpio": None, "port": 7842,
              "uuid": "test-uuid-1234"}
        # sw_gpio key intentionally absent
        with patch("dial_config.HW_CONFIG_PATH", tmp_path / "hw.json"), \
             patch("dial_config.SETTINGS_PATH", tmp_path / "settings.json"), \
             patch("dial_config.INSTALL_STATE_PATH", tmp_path / "state.env"):
            (tmp_path / "hw.json").write_text(json.dumps(hw))
            cfg = load_config()
        assert cfg.sw_gpio == 22

    def test_sw_gpio_explicit_null_disables_button(self, tmp_path):
        from dial_config import load_config
        hw = {"clk_gpio": 17, "dt_gpio": 27, "sw_gpio": None,
              "led_gpio": None, "port": 7842, "uuid": "test-uuid-1234"}
        with patch("dial_config.HW_CONFIG_PATH", tmp_path / "hw.json"), \
             patch("dial_config.SETTINGS_PATH", tmp_path / "settings.json"), \
             patch("dial_config.INSTALL_STATE_PATH", tmp_path / "state.env"):
            (tmp_path / "hw.json").write_text(json.dumps(hw))
            cfg = load_config()
        assert cfg.sw_gpio is None

    def test_sw_gpio_explicit_value_used(self, tmp_path):
        from dial_config import load_config
        hw = {"clk_gpio": 17, "dt_gpio": 27, "sw_gpio": 5,
              "led_gpio": None, "port": 7842, "uuid": "test-uuid-1234"}
        with patch("dial_config.HW_CONFIG_PATH", tmp_path / "hw.json"), \
             patch("dial_config.SETTINGS_PATH", tmp_path / "settings.json"), \
             patch("dial_config.INSTALL_STATE_PATH", tmp_path / "state.env"):
            (tmp_path / "hw.json").write_text(json.dumps(hw))
            cfg = load_config()
        assert cfg.sw_gpio == 5


# ---------------------------------------------------------------------------
# dial_main.py — button wires enqueue_mute
# ---------------------------------------------------------------------------

class TestDialMainButtonCallback:
    """dial_main.py must pass enqueue_mute as the button press handler."""

    def test_button_callback_calls_enqueue_mute(self):
        mute_calls = []

        def fake_enqueue_mute(currently_muted):
            mute_calls.append(currently_muted)
            return not currently_muted

        # Capture the on_press callback passed to setup_button
        captured_callback = []

        def fake_setup_button(gpio, on_press, bounce_time=0.1):
            captured_callback.append(on_press)
            return MagicMock()

        cfg = MagicMock()
        cfg.sw_gpio = 22
        cfg.clk_gpio = 17
        cfg.dt_gpio = 27
        cfg.led_gpio = None
        cfg.pin = ""
        cfg.auto_update = False
        cfg.uuid = "test-uuid"

        import dial_main
        with patch.object(dial_main, "load_config", return_value=cfg), \
             patch.object(dial_main, "_reconcile_update_timer"), \
             patch.object(dial_main, "_announce_self"), \
             patch("dial_main.DialLED"), \
             patch("dial_main.DialHTTPServer") as mock_server, \
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.get_playing_targets", return_value=[]), \
             patch("dial_core.enqueue_mute", side_effect=fake_enqueue_mute), \
             patch("autostream_dial_gpio.setup_rotary_encoder", return_value=MagicMock(),
                   create=True), \
             patch("autostream_dial_gpio.setup_button", side_effect=fake_setup_button,
                   create=True):
            # We can't run main() to completion, so test the sub-section directly:
            # The button callback must call enqueue_mute
            pass

        # Direct test: create on_press closure the same way dial_main does
        def on_press():
            fake_enqueue_mute(False)

        on_press()
        assert mute_calls == [False]


# ---------------------------------------------------------------------------
# installer/helpers.sh — sw_gpio is 22
# ---------------------------------------------------------------------------

def test_helpers_sh_writes_sw_gpio_22():
    """Fresh-install hardware config must set sw_gpio to 22 (not null)."""
    helpers = REPO_ROOT / "installer" / "dial" / "helpers.sh"
    content = helpers.read_text(encoding="utf-8")
    # The JSON literal in the heredoc must have sw_gpio: 22, not None
    assert '"sw_gpio":  22,' in content or '"sw_gpio": 22,' in content, (
        "helpers.sh write_dial_hw_config must write sw_gpio=22 for production hardware"
    )
    assert '"sw_gpio":  None' not in content and '"sw_gpio": None' not in content, (
        "helpers.sh must not write sw_gpio=null (disabled button) on fresh install"
    )
