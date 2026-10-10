"""Tests for how dial_main.main() wires the core: built first and owned by
main(), started before the view and stopped before it, handed to the display,
the workers and the inputs, with or without a screen."""
from __future__ import annotations

import builtins
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, call, patch

REPO_ROOT = Path(__file__).parent.parent
for _p in (str(REPO_ROOT / "dial"), str(REPO_ROOT / "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _make_cfg():
    cfg = MagicMock()
    cfg.uuid = "test-uuid"
    cfg.auto_update = False
    cfg.pin = None
    cfg.led_gpio = 17
    cfg.clk_gpio = None
    cfg.dt_gpio = None
    cfg.sw_gpio = None
    cfg.port = 7845
    return cfg


def _run_core_wiring(fitted=True, display_import_fails=False):
    """Run main() against a real core (and, unless the display stack is made
    to fail, a real DialDisplay), recording the order things start and stop
    in and what each worker callback was wired to."""
    import dial_main as dm
    import dial_display as dd

    cfg = _make_cfg()
    cfg.display.fitted = fitted
    cfg.display.poll_interval_s = 4
    mock_http = MagicMock()
    mock_http._server = MagicMock()
    mock_http.get_runtime_status.return_value = {"name": "Kitchen Dial"}
    mock_http.effective_mute_scope = "current"
    mock_http.effective_volume_scope = "current"
    order = []
    captured = {"order": order, "http": mock_http}

    class _QuickEvent(threading.Event):
        def wait(self, timeout=None):
            return True

    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if display_import_fails and (name == "dial_display" or name.startswith("dial_display.")):
            raise ImportError("simulated missing Pillow/display stack")
        return real_import(name, *args, **kwargs)

    real_create_core = dm.create_dial_core

    def spy_create_core(*args, **kwargs):
        core = real_create_core(*args, **kwargs)
        captured["core"] = core
        order.append("core built")
        real_start, real_stop = core.start, core.stop
        core.start = lambda: (order.append("core.start"), real_start())[1]
        core.stop = lambda: (order.append("core.stop"), real_stop())[1]
        return core

    real_create_display = dd.create_dial_display

    def spy_create_display(*args, **kwargs):
        display = real_create_display(*args, **kwargs)
        captured["display"] = display
        order.append("display built")
        real_show, real_start, real_stop = display.show_starting, display.start, display.stop
        display.show_starting = lambda: (order.append("show_starting"), real_show())[1]
        display.start = lambda: (order.append("display.start"), real_start())[1]
        display.stop = lambda: (order.append("display.stop"), real_stop())[1]
        return display

    with patch("dial_main._configure_logging"), \
         patch("dial_main.load_config", return_value=cfg), \
         patch("dial_main._reconcile_update_timer"), \
         patch("dial_main._announce_self"), \
         patch("dial_main.DialLED"), \
         patch("dial_main.DialHTTPServer", return_value=mock_http), \
         patch("dial_main.start_playing_browser"), \
         patch("dial_main.start_general_browser"), \
         patch("dial_main.stop_playing_browser"), \
         patch("dial_main.stop_general_browser"), \
         patch("dial_main.start_volume_worker") as volume_worker, \
         patch("dial_main.start_repeat_worker") as repeat_worker, \
         patch("dial_main.start_outputs_worker") as outputs_worker, \
         patch("dial_main.start_eq_worker") as eq_worker, \
         patch("dial_main.start_network_worker") as network_worker, \
         patch("dial_main.dial_sdhealth.start") as sdhealth_start, \
         patch("dial_main.DialControlServer"), \
         patch.object(dm, "create_dial_core", side_effect=spy_create_core), \
         patch.object(dd, "create_dial_display", side_effect=spy_create_display), \
         patch("threading.Event", _QuickEvent), \
         patch("builtins.__import__", side_effect=_fake_import):
        dm.main()

    captured.update(
        volume_worker=volume_worker, repeat_worker=repeat_worker, outputs_worker=outputs_worker,
        eq_worker=eq_worker, network_worker=network_worker, sdhealth_start=sdhealth_start,
    )
    return captured


class TestCoreWiring:
    def test_the_core_is_built_before_the_display_and_started_before_it(self):
        order = _run_core_wiring()["order"]
        assert order.index("core built") < order.index("display built")
        assert order.index("show_starting") < order.index("core.start")
        assert order.index("core.start") < order.index("display.start")

    def test_the_core_is_stopped_before_the_display_and_only_by_main(self):
        captured = _run_core_wiring()
        order = captured["order"]
        assert order.count("core.stop") == 1
        assert order.index("core.stop") < order.index("display.stop")
        assert captured["display"]._owns_core is False

    def test_the_display_paints_the_core_main_built(self):
        captured = _run_core_wiring()
        assert captured["display"].core is captured["core"]

    def test_the_workers_and_pollers_report_to_the_core(self):
        captured = _run_core_wiring()
        core = captured["core"]
        assert captured["repeat_worker"].call_args.kwargs["on_result"] == core.on_repeat_result
        assert captured["volume_worker"].call_args.kwargs["on_readout_changed"] == core.readout_changed
        assert captured["network_worker"].call_args.kwargs["on_view"] == core.on_network_view
        assert captured["sdhealth_start"].call_args.kwargs["on_view"] == core.on_sd_health_view

    def test_the_outputs_and_eq_results_go_straight_to_the_core(self):
        captured = _run_core_wiring()
        core = captured["core"]
        assert captured["outputs_worker"].call_args.kwargs["on_result"] == core.on_outputs_result
        assert captured["eq_worker"].call_args.kwargs["on_result"] == core.on_eq_result

    def test_the_core_publishes_who_the_dial_is_and_what_inputs_run(self):
        info = _run_core_wiring()["core"].snapshot().dial
        assert (info.name, info.port, info.uuid) == ("Kitchen Dial", 7845, "test-uuid")
        assert info.version
        assert info.inputs == ()
        assert (info.volume_scope, info.mute_scope) == ("current", "current")

    def test_the_core_reads_how_far_a_mute_reaches_from_the_http_server(self):
        captured = _run_core_wiring()
        captured["http"].effective_mute_scope = "all"
        with patch("dial_core.enqueue_mute") as mute, patch("dial_core.enqueue_mute_all") as mute_all:
            captured["core"].mute_toggle()
        mute.assert_not_called()
        mute_all.assert_called_once_with()

    def test_a_screenless_dial_builds_a_core_that_does_not_poll(self):
        captured = _run_core_wiring(fitted=False)
        assert captured["core"].snapshot().polling is False

    def test_a_fitted_dial_polls_at_its_configured_interval(self):
        captured = _run_core_wiring(fitted=True)
        assert captured["core"].snapshot().polling is True
        assert captured["core"]._poll_interval == 4


class TestHeadlessWiring:
    def test_the_core_runs_without_a_view_and_takes_every_worker_result(self):
        captured = _run_core_wiring(fitted=True, display_import_fails=True)
        core = captured["core"]
        assert "display built" not in captured["order"]
        assert captured["order"].index("core.start") < captured["order"].index("core.stop")
        assert core.snapshot().polling is True
        assert captured["outputs_worker"].call_args.kwargs["on_result"] == core.on_outputs_result
        assert captured["eq_worker"].call_args.kwargs["on_result"] == core.on_eq_result
        assert captured["repeat_worker"].call_args.kwargs["on_result"] == core.on_repeat_result
        assert captured["network_worker"].call_args.kwargs["on_view"] == core.on_network_view

    def test_a_screenless_headless_dial_does_not_poll(self):
        captured = _run_core_wiring(fitted=False, display_import_fails=True)
        assert captured["core"].snapshot().polling is False


class TestBuildInputs:
    def _inputs(self, hooks):
        import dial_main as dm

        http_server = MagicMock()
        http_server.step_percent = 3
        core = MagicMock()
        calls = MagicMock()
        calls.attach_mock(http_server.confirm_volume, "confirm")
        calls.attach_mock(core.volume_step, "volume_step")
        calls.attach_mock(core.mute_toggle, "mute_toggle")
        return dm._build_inputs(core, http_server, hooks), calls, core

    def test_a_nudge_confirms_tells_the_views_then_steps_the_volume(self):
        hook = MagicMock()
        (up, down, _delta, _press), calls, core = self._inputs([hook])
        calls.attach_mock(hook, "hook")

        assert up() == 3
        assert calls.mock_calls == [call.confirm(), call.hook("volume"), call.volume_step(3)]
        calls.reset_mock()
        assert down() == -3
        assert calls.mock_calls == [call.confirm(), call.hook("volume"), call.volume_step(-3)]

    def test_the_button_confirms_tells_the_views_then_toggles_mute(self):
        hook = MagicMock()
        (_up, _down, _delta, press), calls, core = self._inputs([hook])
        calls.attach_mock(hook, "hook")

        press()
        assert calls.mock_calls == [call.confirm(), call.hook("mute"), call.mute_toggle()]

    def test_a_screenless_dial_has_no_hooks(self):
        (up, _down, _delta, press), calls, core = self._inputs([])
        up()
        press()
        core.volume_step.assert_called_once_with(3)
        core.mute_toggle.assert_called_once_with()

    def test_a_raising_hook_never_blocks_the_input(self):
        hook = MagicMock(side_effect=RuntimeError("boom"))
        (up, _down, _delta, press), calls, core = self._inputs([hook])
        up()
        press()
        core.volume_step.assert_called_once_with(3)
        core.mute_toggle.assert_called_once_with()

    def test_the_control_socket_delta_confirms_only_when_it_moves_and_tells_no_view(self):
        hook = MagicMock()
        (_up, _down, delta, _press), calls, core = self._inputs([hook])

        assert delta(5) == 5
        hook.assert_not_called()
        core.volume_step.assert_called_once_with(5)
        calls.confirm.assert_called_once_with()

        calls.reset_mock()
        assert delta(0) == 0
        calls.confirm.assert_not_called()
        core.volume_step.assert_called_with(0)
