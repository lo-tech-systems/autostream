"""The production HD server on a fake core, put into a scenario.

HdPreview is the one place that builds this: the real HdServer, a ChangeHub, a
FakeCore, a FakePanel and a real (never started) management server, with fixed
clocks so a scenario's readings are what the page sees. show() puts the dial
into a scenario of tests/hd_scenarios.py. The browser tests hold one for the
whole run, and tools/hd_page_preview.py serves one to a developer's browser.
The settings route persists the config, so start() keeps that off the disk.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = Path(__file__).parent.parent
for _p in (str(REPO_ROOT / "tests"), str(REPO_ROOT / "dial"), str(REPO_ROOT / "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import dial_hd_server as hds
import hd_scenarios
from dial_hd_events import ChangeHub
from hd_fake_core import FakeCore
from hd_http_support import close_management_server, management_server

DEFAULT_SCENARIO = "playing_artwork"
# Pages closed without a clean goodbye are noticed within a second, but tests
# open pages faster than that now and then, so the client cap is lifted.
CLIENT_CAP = 1000


class FakePanel:
    """The panel service as the server sees it: a sleep flag the page can
    flip, and every call it makes recorded."""

    INFO_ROWS = (
        ("Dial name", "Lounge dial"), ("Firmware", "0.8.0"), ("IPv4", "192.0.2.10"), ("WiFi", "HomeNet"),
        ("Signal", "Strong"), ("Disk free", "5.2 GB"), ("SD health", "84%"),
    )

    def __init__(self, publish) -> None:
        self._publish = publish
        self.asleep = False
        self.backlight = "sysfs"
        self.kiosk = False
        self.calls: list = []

    def view(self) -> dict:
        return {"asleep": self.asleep, "backlight": self.backlight, "kiosk": self.kiosk}

    def set_view(self, asleep: bool, backlight: str, kiosk: "bool | None" = None) -> None:
        self.asleep, self.backlight = asleep, backlight
        if kiosk is not None:
            self.kiosk = kiosk
        self._publish()

    def wake(self) -> None:
        self.calls.append("wake")
        self.set_view(False, self.backlight)

    touch = lambda self: self.calls.append("activity")  # noqa: E731

    def sleep_now(self) -> None:
        self.calls.append("sleep")
        self.set_view(True, self.backlight)


class HdPreview:
    """The server, bound to a free port unless *port* is given. Attributes:
    core, server, hub, panel, management, muted and dial_clock (one-item
    lists the server reads) and url."""

    def __init__(self, port: int = 0) -> None:
        self.muted = [False]
        # The dial's clock reading for the next state; show() sets it from the scenario.
        self.dial_clock = [hd_scenarios.NOW]
        self.core = FakeCore(hd_scenarios.SCENARIOS[DEFAULT_SCENARIO].snapshot)
        self.management = management_server()
        self.hub = ChangeHub(self.core)
        self.panel = FakePanel(self.hub.publish)
        self.management.add_cfg_listener(lambda cfg: self.hub.publish())
        self.server = hds.HdServer(
            SimpleNamespace(), self.core, http_server=self.management, hub=self.hub, port=port,
            panel=self.panel, info_fn=lambda: FakePanel.INFO_ROWS,
            muted_fn=lambda service: self.muted[0],
            # The scenarios carry fixed readings, so the server reads fixed clocks.
            clock=lambda: self.dial_clock[0], wall_clock=lambda: hd_scenarios.WALL_NOW,
        )
        self.url = f"http://127.0.0.1:{self.server.port}"
        self._first_screen = {k: v for k, v in self.management.screen_report().items() if k != "surface"}
        self._saver = patch("dial_config.save_config", lambda cfg: None)
        self._saved_cap = hds.SSE_MAX_CLIENTS

    def start(self) -> "HdPreview":
        hds.SSE_MAX_CLIENTS = CLIENT_CAP
        self.hub.start()
        self.server.start()
        self._saver.start()
        return self

    def stop(self) -> None:
        self._saver.stop()
        self.server.stop()
        self.hub.stop()
        close_management_server(self.management)
        hds.SSE_MAX_CLIENTS = self._saved_cap

    def __enter__(self) -> "HdPreview":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    def reset(self) -> None:
        """Put back what a test can change that show() does not set: the
        screen settings, what the core and the panel recorded and the
        warnings registered. Call it before show()."""
        status, reply = self.management.apply_screen_settings(dict(self._first_screen))
        assert status == 200 and reply.get("ok"), reply
        self.core.reset()
        self.panel.calls.clear()

    def show(self, scenario) -> None:
        """Make *scenario* the state the dial reports now."""
        self.muted[0] = scenario.muted
        self.dial_clock[0] = scenario.now
        for descriptor in scenario.descriptors:
            self.core.warnings.register(descriptor)
        window = self.management._recovery_window
        window.complete()
        active, confirmed = scenario.recovery
        if active:
            window.open()
            if confirmed:
                window.confirm_volume()
        self.panel.set_view(
            bool(scenario.panel.get("asleep")), scenario.panel.get("backlight", "sysfs"),
            bool(scenario.panel.get("kiosk")))
        self.core.publish(snapshot=scenario.snapshot)
