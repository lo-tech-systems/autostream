"""Tests for what the core carries for the service wiring: the dial's own
info (name, version, address, inputs, scopes), the volume readout, and the
effects the worker callbacks queue for a view."""
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))


from dial_core import ADDRESS_REFRESH_S, EFFECTS_BACKLOG_MAX, DialCore, SourceEffects
from dial_core_state import NowPlaying
from dial_network import LINK_CONNECTED, NetworkView

AID = "a" * 20


def _core():
    return DialCore("dial-1")


class TestDialInfo:
    def test_identity_is_published_with_the_live_name(self):
        core = _core()
        name = ["Kitchen"]
        core.set_identity(lambda: name[0], "0.7.0", 7845)
        info = core.snapshot().dial
        assert (info.name, info.version, info.port, info.uuid) == ("Kitchen", "0.7.0", 7845, "dial-1")
        name[0] = "Lounge"
        core._housekeeping(1.0)
        assert core.snapshot().dial.name == "Lounge"

    def test_inputs_are_published_in_the_order_given(self):
        core = _core()
        core.set_inputs(["encoder", "button", "touch:xpt2046"])
        assert core.snapshot().dial.inputs == ("encoder", "button", "touch:xpt2046")

    def test_inputs_set_again_unchanged_publish_nothing(self):
        core = _core()
        core.set_inputs(["encoder"])
        seq = core.snapshot().seq
        core.set_inputs(("encoder",))
        assert core.snapshot().seq == seq

    def test_the_effective_scopes_follow_their_sources(self):
        core = _core()
        volume, mute = ["current"], ["current"]
        core.set_volume_scope(lambda: volume[0])
        core.set_mute_scope(lambda: mute[0])
        core._housekeeping(1.0)
        assert (core.snapshot().dial.volume_scope, core.snapshot().dial.mute_scope) == ("current", "current")
        volume[0], mute[0] = "all", "all"
        core._housekeeping(2.0)
        assert (core.snapshot().dial.volume_scope, core.snapshot().dial.mute_scope) == ("all", "all")

    def test_the_address_is_read_once_a_minute(self):
        core = _core()
        source = MagicMock(return_value="192.0.2.7")
        core.set_address_source(source)
        core._housekeeping(10.0)
        assert core.snapshot().dial.ip == "192.0.2.7"
        source.return_value = "192.0.2.8"
        core._housekeeping(10.0 + ADDRESS_REFRESH_S - 1)
        assert core.snapshot().dial.ip == "192.0.2.7"
        core._housekeeping(10.0 + ADDRESS_REFRESH_S)
        assert core.snapshot().dial.ip == "192.0.2.8"
        assert source.call_count == 2

    def test_a_source_that_raises_keeps_the_value_held(self):
        core = _core()
        core.set_identity(lambda: "Kitchen", "0.7.0", 7845)

        def boom():
            raise RuntimeError("no")
        core._name_source = boom
        core.set_address_source(boom)
        core._housekeeping(1.0)
        assert core.snapshot().dial.name == "Kitchen"
        assert core.snapshot().dial.ip == ""

    def test_a_quiet_second_publishes_nothing(self):
        core = _core()
        core.set_identity(lambda: "Kitchen", "0.7.0", 7845)
        core.set_volume_scope(lambda: "current")
        core._housekeeping(1.0)
        seq = core.snapshot().seq
        core._housekeeping(2.0)
        assert core.snapshot().seq == seq


class TestReadoutChanged:
    def test_the_readout_is_published_for_the_reporting_service(self):
        core = _core()
        core.set_field_for_tests("now_playing", NowPlaying("Kitchen", "", "", 40))
        with patch("dial_core.shown_volume", return_value=42) as shown:
            core.readout_changed()
        shown.assert_called_once_with("Kitchen")
        assert core.snapshot().volume_readout == ("Kitchen", 42)

    def test_with_nothing_reported_the_readout_is_empty(self):
        core = _core()
        core.set_field_for_tests("source_service_name", "Kitchen")
        core.readout_changed()
        assert core.snapshot().volume_readout == (None, None)

    def test_a_mute_change_publishes_the_readout_and_queues_no_repaint(self):
        core = _core()
        core.set_field_for_tests("now_playing", NowPlaying("Kitchen", "", "", 40))
        seen = []
        core.subscribe(lambda: seen.append(len(core._effects)))
        seq = core.snapshot().seq
        with patch("dial_core.shown_volume", return_value=42):
            core.mute_changed()
        assert core.snapshot().seq == seq + 1
        assert core.snapshot().volume_readout == ("Kitchen", 42)
        assert seen == [0]

    def test_a_mute_change_never_raises_into_the_worker(self):
        core = _core()
        with patch("dial_core.shown_volume", side_effect=RuntimeError("store")):
            core.mute_changed()
            core.readout_changed()

    def test_a_view_is_told_to_repaint_before_it_is_woken(self):
        core = _core()
        seen = []
        core.subscribe(lambda: seen.append(len(core._effects)))
        core.readout_changed()
        assert seen and seen[-1] == 1
        effects = core.take_effects()
        assert effects == [SourceEffects()] and effects[0].signal is True

    def test_a_failure_never_reaches_the_worker(self):
        core = _core()
        with patch("dial_core.shown_volume", side_effect=RuntimeError("boom")):
            core.readout_changed()


class TestQueuedWorkerEffects:
    def test_a_network_reading_queues_what_it_did_to_the_warnings(self):
        core = _core()
        effects = core.on_network_view(NetworkView(LINK_CONNECTED, "connected"))
        assert core.take_effects() == [effects]
        assert [c.warning_id for c in effects.changes] == ["nowifi"]

    def test_a_queue_nobody_drains_keeps_the_newest(self):
        core = _core()
        for _ in range(EFFECTS_BACKLOG_MAX + 40):
            core.readout_changed()
        assert len(core.take_effects()) == EFFECTS_BACKLOG_MAX
