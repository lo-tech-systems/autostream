"""A real web server for the remote pages, and a fake appliance behind it.

The Home and Equaliser shells for another appliance come from the real
renderers and the real route; the state, the change stream and the intents
come from the real relay, which follows a ``FakePeer`` through a started
``PeerClient``. ``/static/*`` is served from ``nginx/static`` (through
``_page_stub``), as nginx serves it.

    rig = start(monkeypatch, parts=base_parts(...))
    page.goto(f"{rig.url}/a/{PEER_ID}/")
    rig.peer.push({...})          # the other appliance changes
    rig.close()
"""
from __future__ import annotations

import sys
from types import SimpleNamespace

import _page_stub
from _page_stub import REPO_ROOT

for _p in (REPO_ROOT / "core", REPO_ROOT / "tests"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import autostream_state as state  # noqa: E402
from autostream_peer_client import RosterEntry  # noqa: E402
from relay_rig import OWN_ID, PEER_ID, RelayRig  # noqa: E402,F401
from settings_fixtures import viewed_state  # noqa: E402
from webui.server import ConfigWebHandler  # noqa: E402

SETTINGS = {"webui": {"show_hostname_on_home": True, "control_other_appliances": True,
                      "show_master_volume": True}}


class _Handler(ConfigWebHandler):
    def do_GET(self) -> None:
        if self.path.startswith("/static/"):
            _page_stub.serve_static(self, self.path)
        else:
            super().do_GET()


class Remote(RelayRig):
    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.port}"

    def set_peers(self, *rows: dict) -> None:
        """The peers part, as this appliance's page is rendered from it and
        its own state route serves it."""
        part = state.PeersPart(tuple(RosterEntry(**r) for r in rows))
        state.store().publish_for_tests("peers", part)
        self.server.store.publish_for_tests("peers", part)


def roster(peer_id: str, hostname: str, **fields) -> dict:
    row = dict(id=peer_id, hostname=hostname, version="1.0", control=True, reachable=True,
               protocol_ok=True, access="playback", configured=True, playing=False)
    row.update(fields)
    return row


def start(monkeypatch, **kwargs) -> Remote:
    import webui.browser.equaliser as equaliser
    import webui.browser.home as home

    monkeypatch.setattr(home, "get_setting", lambda *a, **k: SimpleNamespace(ok=False, value=None))
    monkeypatch.setattr(home, "get_system_hostname", lambda: "Lounge")
    monkeypatch.setattr(equaliser, "get_system_hostname", lambda: "Lounge")
    monkeypatch.setattr(equaliser, "get_live_monitor_output_rate", lambda fallback: 48000)
    rig = Remote(monkeypatch, handler=_Handler, **kwargs)
    rig.server.store.reset_for_tests()
    page_state = viewed_state(SETTINGS)
    page_state.config_path, page_state.state_path = "dummy.ini", "dummy-state.json"
    monkeypatch.setattr("webui.session_state.STATE", page_state)
    assert rig.ready()
    return rig
