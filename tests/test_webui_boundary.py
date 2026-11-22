"""The web package's boundary: who imports it, what it leaves behind, and what
its server takes from the process that starts it.

The static layering scan (test_layering.py) says what the package may import.
These tests hold the other half: the package is imported only by the
coordinator and the entry script, no flat web module is left beside it, it
works on its own without the coordinator, its server takes only a narrow
set of dependencies, and its directories re-export nothing.
"""
from __future__ import annotations

import ast
import dataclasses
import json
import subprocess
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import test_layering as layering
import webui.protocol.hub as proto_hub

CORE_DIR = Path(__file__).resolve().parent.parent / "core"
WEBUI_DIR = CORE_DIR / "webui"


def test_only_the_entry_script_and_the_coordinator_import_the_web_package():
    _modules, edges, _claims = layering.scan(CORE_DIR)
    importers = {e.importer for e in edges if e.module.split(".")[0] == "webui"}
    assert importers == {"autostream_core", "autostream_webui"}


def test_no_flat_web_module_is_left():
    flat = sorted(
        p.name for pattern in (
            "autostream_webui_*.py", "autostream_appliance_models.py", "autostream_appliance_gateway.py",
        ) for p in CORE_DIR.glob(pattern)
    )
    assert flat == []
    # The service's ExecStart file stays where the unit expects it.
    assert (CORE_DIR / "autostream_webui.py").is_file()


# Modules the web package must not pull in when it is imported on its own.
# The monitor client and the player service are not listed: the state store
# and the alignment helpers, which the package may import, load them.
_NOT_LOADED_ALONE = (
    "autostream_core", "autostream_audio_monitor", "autostream_monitor_control",
    "autostream_owntone", "autostream_owntone_mini", "autostream_runtime",
    "autostream_live_config", "autostream_output_intents",
)

_ALONE_DRIVER = r"""
import json, sys
import webui.server
import autostream_intents
from autostream_intents import Intent, IntentNotBound
from autostream_state import Origin
try:
    autostream_intents.submit(Intent("outputs.set", {"id": "x", "selected": True}, Origin.USER, "webui"))
    unbound = False
except IntentNotBound:
    unbound = True
except Exception as exc:
    unbound = "other:" + type(exc).__name__
print(json.dumps({"modules": sorted(sys.modules), "unbound": unbound}))
"""


def _l2_modules_outside_the_allowlist() -> list[str]:
    allowed = set(layering.ALLOWED_FOR_WEBUI)
    return sorted(
        name for name, layer in layering.LAYERS.items()
        if layer == "L2" and name not in allowed
    )


def test_the_web_package_imports_alone():
    result = subprocess.run(
        [sys.executable, "-c", _ALONE_DRIVER],
        cwd=str(CORE_DIR), capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    out = json.loads(result.stdout.strip().splitlines()[-1])
    loaded = set(out["modules"])
    assert "webui.server" in loaded
    forbidden = set(_NOT_LOADED_ALONE) | set(_l2_modules_outside_the_allowlist())
    assert sorted(loaded & forbidden) == []
    # No intent handler is bound by the web package: the coordinator binds them.
    assert out["unbound"] is True


def test_web_deps_fields():
    import webui.server as server

    fields = [f.name for f in dataclasses.fields(server.WebUIDeps)]
    assert fields == ["config_path", "state_path", "settings", "startup", "host", "port"]
    deps = server.WebUIDeps("c.json", "s.json", settings=MagicMock())
    with pytest.raises(dataclasses.FrozenInstanceError):
        deps.port = 1  # type: ignore[misc]


def test_start_server_refuses_anything_but_a_settings_view(tmp_path):
    import webui.server as server
    from autostream_settings import SettingsStore

    store = SettingsStore(str(tmp_path / "autostream.json"), _save_interval_seconds=9999)
    try:
        for bad in (store, MagicMock(), None):
            with pytest.raises(TypeError):
                server.start_server(server.WebUIDeps("c.json", "s.json", settings=bad))
    finally:
        store.close(save=False)


def test_the_startup_hook_runs_once_on_the_web_thread_before_serving():
    import webui.server as server
    import webui.session_state as session_state
    from settings_fixtures import fixed_view

    events: list[tuple[str, str]] = []
    done = threading.Event()

    class _FakeHttpd:
        def __init__(self, *_a, **_kw):
            events.append(("construct", threading.current_thread().name))

        def serve_forever(self):
            events.append(("serve", threading.current_thread().name))
            done.set()

    def hook(state):
        assert state is session_state.STATE
        events.append(("startup", threading.current_thread().name))

    with patch.object(server, "ThreadingHTTPServer", _FakeHttpd), \
         patch.object(server, "AuthManager"), \
         patch.object(server.updates, "get_app_version"):
        thread = server.start_server(server.WebUIDeps(
            "c.json", "s.json", settings=fixed_view(), startup=hook, port=0,
        ))
        assert done.wait(timeout=5)
        thread.join(timeout=5)

    assert [kind for kind, _name in events] == ["startup", "construct", "serve"]
    assert {name for _kind, name in events} == {thread.name}
    assert thread.name != threading.current_thread().name


def test_start_server_installs_a_subscribed_hub_over_the_store_before_serving():
    import autostream_state
    import webui.server as server
    from settings_fixtures import fixed_view

    seen: dict = {}
    done = threading.Event()

    class _FakeHttpd:
        def __init__(self, *_a, **_kw):
            pass

        def serve_forever(self):
            hub = proto_hub._HUB
            seen["hub"] = hub
            seen["subscribed"] = hub is not None and hub._handle is not None
            seen["store"] = hub.store if hub is not None else None
            done.set()

    proto_hub.install(None)
    try:
        with patch.object(server, "ThreadingHTTPServer", _FakeHttpd),              patch.object(server, "AuthManager"),              patch.object(server.updates, "get_app_version"):
            thread = server.start_server(server.WebUIDeps(
                "c.json", "s.json", settings=fixed_view(), port=0,
            ))
            assert done.wait(timeout=5)
            thread.join(timeout=5)
        assert isinstance(seen["hub"], proto_hub.StreamHub)
        assert seen["store"] is autostream_state.store()
        assert seen["subscribed"] is True
    finally:
        if seen.get("hub") is not None:
            seen["hub"].stop()
        proto_hub.install(None)


def _package_inits() -> list[Path]:
    return sorted(p for p in WEBUI_DIR.rglob("__init__.py") if "__pycache__" not in p.parts)


def test_every_web_package_directory_has_an_empty_init():
    inits = _package_inits()
    assert len(inits) == 7
    directories = {p.parent for p in WEBUI_DIR.rglob("*.py") if "__pycache__" not in p.parts}
    assert directories == {p.parent for p in inits}
    for init in inits:
        body = ast.parse(init.read_text(encoding="utf-8")).body
        only_a_docstring = all(
            isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)
            for n in body
        ) and len(body) <= 1
        assert only_a_docstring, f"{init.relative_to(CORE_DIR)} holds more than a docstring"


def test_no_web_module_imports_the_server():
    offenders = []
    for path in sorted(WEBUI_DIR.rglob("*.py")):
        if "__pycache__" in path.parts or path == WEBUI_DIR / "server.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import) and any(a.name == "webui.server" for a in node.names):
                offenders.append(path.name)
            elif isinstance(node, ast.ImportFrom) and not node.level:
                if node.module == "webui.server" or (
                    node.module == "webui" and any(a.name == "server" for a in node.names)
                ):
                    offenders.append(path.name)
    assert offenders == []


_REGISTRATIONS_DRIVER = r"""
import json, sys
import autostream_settings_schema as schema
before = set(schema.SETTINGS_SCHEMA)
import webui.server
import webui.routes as routes
from webui.browser.setup import context
added = sorted(set(schema.SETTINGS_SCHEMA) - before)
named = sorted({r.handler.rpartition(".")[0] for r in routes.ROUTES if isinstance(r.handler, str)})
print(json.dumps({
    "added": added,
    "cards": [c.key for c in context.CARDS],
    "routes": len(routes.ROUTES),
    "unloaded": [m for m in named if m not in sys.modules],
}))
"""


def test_importing_the_server_runs_every_registration_before_the_first_request():
    result = subprocess.run(
        [sys.executable, "-c", _REGISTRATIONS_DRIVER],
        cwd=str(CORE_DIR), capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    out = json.loads(result.stdout.strip().splitlines()[-1])
    added = set(out["added"])
    # Schema rows registered by importing the web modules.
    assert {
        "webui.dark_mode", "webui.show_master_volume", "webui.show_input_detail",
        "webui.show_hostname_on_home", "webui.control_other_appliances",
        "updates.update_channel",
    } <= added
    assert any(name.startswith("service_") and "_life_hours_input1" in name for name in added)
    assert any(name.startswith("service_") and "_life_years_input2" in name for name in added)
    # The Setup page's cards, in page order.
    assert out["cards"] == [
        "input1", "input2", "input3", "playback", "track-id", "dials",
        "customise", "system", "factory-reset",
    ]
    # The table is filled and every module it names is already loaded.
    assert out["routes"] > 80
    assert out["unloaded"] == []
