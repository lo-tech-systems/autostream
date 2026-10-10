"""Tests for how dial_main.main() wires the core: built first and owned by
main(), started before the view and stopped before it, handed to the display,
the workers and the inputs, with or without a screen."""
from __future__ import annotations

import builtins
import sys
import threading
from pathlib import Path
from unittest.mock import DEFAULT, MagicMock, call, patch

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
    cfg.hd_port = 7843
    return cfg


def _run_core_wiring(fitted=True, display_import_fails=False, screen_type=None, hd_error=None):
    """Run main() against a real core (and, unless the display stack is made
    to fail, a real DialDisplay), recording the order things start and stop
    in and what each worker callback was wired to."""
    import dial_main as dm
    import dial_display as dd

    cfg = _make_cfg()
    cfg.display.fitted = fitted
    cfg.display.poll_interval_s = 4
    if screen_type is not None:
        cfg.display.screen_type = screen_type
    mock_hd = MagicMock()
    mock_hd.start.side_effect = lambda: order.append("hd.start")
    mock_hd.stop.side_effect = lambda: order.append("hd.stop")
    mock_hd_class = MagicMock(return_value=mock_hd, side_effect=hd_error)
    mock_hub = MagicMock()
    mock_hub.start.side_effect = lambda: order.append("hub.start")
    mock_hub.stop.side_effect = lambda: order.append("hub.stop")
    mock_hub_class = MagicMock(return_value=mock_hub)
    mock_panel = MagicMock()
    mock_panel.start.side_effect = lambda: order.append("panel.start")
    mock_panel.stop.side_effect = lambda: order.append("panel.stop")
    mock_panel_class = MagicMock(return_value=mock_panel)
    mock_backlight = MagicMock()
    mock_http = MagicMock()
    mock_http._server = MagicMock()
    mock_http.get_runtime_status.return_value = {"name": "Kitchen Dial"}
    mock_http.effective_mute_scope = "current"
    mock_http.effective_volume_scope = "current"
    order = []
    captured = {"order": order, "http": mock_http, "hd": mock_hd, "hd_class": mock_hd_class,
                "hub": mock_hub, "hub_class": mock_hub_class, "panel": mock_panel,
                "panel_class": mock_panel_class, "backlight": mock_backlight}

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
         patch.multiple("dial_main", DialLED=DEFAULT, HdServer=mock_hd_class, ChangeHub=mock_hub_class,
                       HdPanel=mock_panel_class, detect_backlight=mock_backlight), \
         patch("dial_main.DialHTTPServer", return_value=mock_http), \
         patch("dial_main.start_playing_browser") as playing_browser, \
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
        playing_browser=playing_browser,
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

    def test_the_playing_browser_wakes_the_core_on_an_add(self):
        captured = _run_core_wiring()
        kwargs = captured["playing_browser"].call_args.kwargs
        assert kwargs["on_add"] == captured["core"].request_poll

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


class TestKioskSurfaceWiring:
    def test_a_kiosk_profile_never_builds_the_spi_display(self):
        captured = _run_core_wiring(fitted=True, screen_type="hd_kiosk")
        assert "display built" not in captured["order"]

    def test_a_fitted_kiosk_dial_polls_at_its_configured_interval(self):
        captured = _run_core_wiring(fitted=True, screen_type="hd_kiosk")
        assert captured["core"].snapshot().polling is True
        assert captured["core"]._poll_interval == 4

    def test_an_unfitted_kiosk_dial_does_not_poll(self):
        captured = _run_core_wiring(fitted=False, screen_type="hd_kiosk")
        assert captured["core"].snapshot().polling is False

    def test_a_kiosk_dial_lists_the_page_as_an_input_and_can_confirm_presence(self):
        captured = _run_core_wiring(fitted=True, screen_type="hd_kiosk")
        assert captured["core"].snapshot().dial.inputs == ("touch:hd",)
        captured["http"].set_can_confirm_presence.assert_called_once_with(True)

    def test_a_kiosk_dial_starts_no_touch_source(self):
        import dial_main as dm
        with patch.object(dm, "_build_touch_source") as build:
            _run_core_wiring(fitted=True, screen_type="hd_kiosk")
        build.assert_not_called()

    def test_an_spi_profile_is_unchanged(self):
        captured = _run_core_wiring(fitted=True, screen_type="st7735s_160x128")
        assert "display built" in captured["order"]
        assert captured["core"].snapshot().dial.inputs == ()


class TestHdServerWiring:
    def test_the_hd_server_is_built_on_every_dial_with_the_core_and_the_configured_port(self):
        for screen_type in (None, "hd_kiosk"):
            captured = _run_core_wiring(fitted=True, screen_type=screen_type)
            args, kwargs = captured["hd_class"].call_args
            assert args[1] is captured["core"]
            assert kwargs["http_server"] is captured["http"]
            assert kwargs["port"] == 7843

    def test_it_is_started_before_the_core_and_stopped_before_it(self):
        order = _run_core_wiring()["order"]
        assert order.index("hd.start") < order.index("core.start")
        assert order.count("hd.stop") == 1
        assert order.index("hd.stop") < order.index("core.stop")

    def test_a_port_that_cannot_be_bound_costs_the_page_not_the_dial(self):
        captured = _run_core_wiring(hd_error=OSError(98, "Address already in use"))
        assert "core.start" in captured["order"]
        assert "core.stop" in captured["order"]
        assert "hd.stop" not in captured["order"]

    def test_the_hub_is_built_on_the_core_and_given_to_the_server(self):
        captured = _run_core_wiring()
        captured["hub_class"].assert_called_once_with(captured["core"])
        assert captured["hd_class"].call_args.kwargs["hub"] is captured["hub"]

    def test_the_hub_starts_before_the_server_and_stops_after_it(self):
        order = _run_core_wiring()["order"]
        assert order.index("hub.start") < order.index("hd.start") < order.index("core.start")
        assert order.index("hd.stop") < order.index("hub.stop") < order.index("core.stop")

    def test_a_config_change_publishes_to_the_hub(self):
        captured = _run_core_wiring()
        captured["hub"].publish.assert_not_called()
        for (callback,), _ in captured["http"].add_cfg_listener.call_args_list:
            callback(object())
        captured["hub"].publish.assert_called_once_with()

    def test_a_config_change_reaches_the_panel_and_the_dev_access_setting(self):
        captured = _run_core_wiring()
        listeners = [args[0] for args, _ in captured["http"].add_cfg_listener.call_args_list]
        assert any(callback is captured["hd"].on_config for callback in listeners)
        captured["hd"].on_config.reset_mock()
        captured["panel"].apply_settings.reset_mock()
        new_cfg = object()
        for callback in listeners:
            callback(new_cfg)
        captured["hd"].on_config.assert_called_once_with(new_cfg)
        captured["panel"].apply_settings.assert_called_once_with()

    def test_dev_access_is_applied_from_the_loaded_config_at_startup(self):
        captured = _run_core_wiring()
        captured["hd"].on_config.assert_any_call(captured["hd_class"].call_args.args[0])

    def test_the_panel_is_built_on_the_hub_and_given_to_the_server(self):
        captured = _run_core_wiring()
        args, kwargs = captured["panel_class"].call_args
        assert args[0] is captured["hub"]
        assert captured["hd_class"].call_args.kwargs["panel"] is captured["panel"]
        assert callable(captured["hd_class"].call_args.kwargs["info_fn"])

    def test_a_pin_being_awaited_engages_the_panel(self):
        import time
        from dial_core_state import TransportRequest
        captured = _run_core_wiring()
        inputs = captured["panel_class"].call_args.kwargs["inputs"]
        core = captured["core"]
        assert inputs() == (False, False, False)

        def set_request(request):
            core._publish(lambda state: setattr(state, "outputs_request", request))

        now = time.monotonic()
        set_request(TransportRequest("a" * 20, "output_pin", now, "pending", now, None, "o2"))
        assert inputs() == (False, False, True)
        set_request(TransportRequest("a" * 20, "output_set", now, "rejected", now, "pin_required", "o2"))
        assert inputs() == (False, False, True)
        set_request(TransportRequest("a" * 20, "output_set", now, "rejected", now, "output_in_use", "o2"))
        assert inputs() == (False, False, False)
        set_request(TransportRequest("a" * 20, "output_set", now - 500, "rejected", now - 500, "pin_required", "o2"))
        assert inputs() == (False, False, False)
        core._publish(lambda state: setattr(state, "visible_playing", ("o1",)))
        assert inputs() == (True, False, False)       # playback alone

    def test_the_panel_drives_a_backlight_only_on_a_kiosk_surface(self):
        spi = _run_core_wiring(screen_type="st7735s_160x128")
        assert spi["panel_class"].call_args.kwargs["backlight"] is None
        kiosk = _run_core_wiring(screen_type="hd_kiosk")
        assert kiosk["panel_class"].call_args.kwargs["backlight"] is kiosk["backlight"].return_value

    def test_the_panel_starts_after_the_server_and_stops_after_it(self):
        order = _run_core_wiring()["order"]
        assert order.index("hd.start") < order.index("panel.start") < order.index("core.start")
        assert order.index("hd.stop") < order.index("panel.stop") < order.index("hub.stop")

    def test_the_hub_is_stopped_when_the_server_cannot_bind(self):
        captured = _run_core_wiring(hd_error=OSError(98, "Address already in use"))
        assert "hub.stop" in captured["order"]
        captured["http"].add_cfg_listener.assert_not_called()


class TestBuildDisplay:
    def _cfg(self, screen_type):
        cfg = MagicMock()
        cfg.display.screen_type = screen_type
        cfg.display.fitted = True
        cfg.display.poll_interval_s = 3
        return cfg

    def test_kiosk_surface_returns_the_stand_in(self):
        import dial_main as dm
        core = MagicMock()
        with patch("dial_display.create_dial_display") as create:
            display = dm._build_display(self._cfg("hd_kiosk"), core)
        create.assert_not_called()
        assert isinstance(display, dm._HeadlessDisplay)
        core.set_polling.assert_called_with(True)
        core.set_poll_interval.assert_called_with(3)

    def test_spi_surface_uses_the_display_factory(self):
        import dial_main as dm
        with patch("dial_display.create_dial_display") as create:
            display = dm._build_display(self._cfg("st7735s_160x128"), MagicMock())
        assert display is create.return_value

    def test_spi_surface_falls_back_to_the_stand_in_on_import_failure(self):
        import dial_main as dm
        with patch("dial_display.create_dial_display", side_effect=ImportError("no Pillow")):
            display = dm._build_display(self._cfg("st7735s_160x128"), MagicMock())
        assert isinstance(display, dm._HeadlessDisplay)


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
