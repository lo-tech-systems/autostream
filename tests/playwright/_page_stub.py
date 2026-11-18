"""Shared page renderers and static-file server for the Playwright tests.

Two things live here for every browser page:

* ``serve_static`` answers a ``/static/*`` request from ``nginx/static``, so a
  stub server hands the browser the same script and style files nginx would.
* ``render(page, **fakes)`` renders one page the way the server does, with the
  collaborators it reads (the settings, the player, the monitor, the host)
  replaced by plain fakes, and returns the response bytes.

``PAGES`` lists every page ``render`` knows. Rendering needs only the Python
side (no browser), so the plain test suite uses it too.
"""
from __future__ import annotations

import json
import sys
import tempfile
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).parent.parent.parent
STATIC_ROOT = REPO_ROOT / "nginx" / "static"

for _p in (REPO_ROOT / "core", REPO_ROOT / "tests"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

REMOTE_APPLIANCE_ID = "aabbccdd1122334455aa"
LOCAL_APPLIANCE_ID = "0" * 20

_CONTENT_TYPES = {
    ".js": "application/javascript",
    ".css": "text/css",
    ".json": "application/json",
}


def serve_static(handler, path: str) -> None:
    """Answer a ``/static/...`` request on a ``BaseHTTPRequestHandler``.

    The query is ignored, as nginx ignores it. A path outside ``nginx/static``
    or a missing file answers 404.
    """
    rel = path.split("?", 1)[0][len("/static/"):]
    root = STATIC_ROOT.resolve()
    target = (root / rel).resolve()
    if root in target.parents and target.is_file():
        body = target.read_bytes()
        ctype = _CONTENT_TYPES.get(target.suffix, "application/octet-stream")
        code = 200
    else:
        body = b""
        ctype = "text/plain"
        code = 404
    handler.send_response(code)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def _handler(path: str = "/") -> tuple[MagicMock, list]:
    handler = MagicMock()
    chunks: list = []
    handler.wfile.write = lambda d: chunks.append(d)
    handler._csrf_token = "t"
    handler._pending_set_cookies = []
    handler.headers = {}
    handler.path = path
    return handler, chunks


def _scratch_state(tmp: str, config_extra: dict | None = None) -> MagicMock:
    """A state with a real settings store over a scratch configuration file."""
    from autostream_settings import SettingsStore, as_view  # noqa: PLC0415

    cfg: dict = {
        "owntone": {"base_url": "http://localhost:3689", "output_name": "", "volume_percent": 20},
        "audio1": {"capture_device": "hw:0,0"},
        "webui": {"hidden_outputs": []},
        "general": {"fifo_path": "/tmp/fifo"},
    }
    for section, values in (config_extra or {}).items():
        cfg.setdefault(section, {}).update(values)
    config_path = Path(tmp) / "config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    state_path = Path(tmp) / "state.json"
    state_path.write_text(json.dumps({"owntone": {"known_outputs": {}}}), encoding="utf-8")

    state = MagicMock()
    state.config_path = str(config_path)
    state.state_path = str(state_path)
    state.settings = as_view(SettingsStore(str(config_path), _save_interval_seconds=9999, _writer=MagicMock()))
    state.get_monitor_devices.return_value = [{"hw": "hw:0,0", "label": "USB Audio"}]
    return state


def _auth() -> MagicMock:
    auth = MagicMock()
    auth.get_csrf_token.return_value = "t"
    return auth


def _banner_patches(module: str) -> list:
    return [patch(f"{module}.build_top_banner_html", return_value=("", ""))]


def _render_home(**fakes) -> bytes:
    import _home_stub  # noqa: PLC0415
    return _home_stub.render_home(**fakes)


def _render_remote_home(**fakes) -> bytes:
    import _home_stub  # noqa: PLC0415
    return _home_stub.render_remote_home(**fakes)


def _render_equaliser(*, eq_fs: int = 96000, **_fakes) -> bytes:
    from autostream_webui_page_equaliser import send_equaliser_page  # noqa: PLC0415

    handler, chunks = _handler("/equaliser")
    with tempfile.TemporaryDirectory() as tmp:
        state = _scratch_state(tmp)
        with ExitStack() as stack:
            for p in (
                *_banner_patches("autostream_webui_page_equaliser"),
                patch("autostream_rpi.get_appliance_id", return_value=LOCAL_APPLIANCE_ID),
                patch("autostream_webui_page_equaliser.get_all_appliances", return_value=[]),
                patch("autostream_webui_page_equaliser.get_system_hostname", return_value="autostream"),
            ):
                stack.enter_context(p)
            send_equaliser_page(handler, state)
    return b"".join(chunks)


def _render_remote_equaliser(*, appliance_id: str = REMOTE_APPLIANCE_ID, **_fakes) -> bytes:
    from autostream_webui_page_equaliser import send_remote_equaliser_page  # noqa: PLC0415

    handler, chunks = _handler()
    state = MagicMock()
    state.config_path = "dummy.ini"
    parsed = MagicMock()
    parsed.webui.dark_mode = False
    with patch("webui.common._config_snapshot", return_value=parsed), \
         patch("autostream_rpi.get_appliance_id", return_value=LOCAL_APPLIANCE_ID), \
         patch("autostream_webui_page_equaliser.get_all_appliances", return_value=[]), \
         patch("autostream_webui_page_equaliser.get_system_hostname", return_value="autostream"):
        send_remote_equaliser_page(handler, state, appliance_id)
    return b"".join(chunks)


def _render_about(*, license_text: str = "", **_fakes) -> bytes:
    import autostream_webui_page_about as about  # noqa: PLC0415

    handler, chunks = _handler("/about")
    state = MagicMock()
    with patch("webui.system.updates.get_app_version", return_value="1.2.3"), \
         patch("autostream_webui_page_about.build_top_banner_html", return_value=("", "")), \
         patch("webui.common._config_snapshot", return_value=None), \
         patch("autostream_webui_page_about.load_license_text", return_value=license_text), \
         patch("autostream_webui_page_about.render_license_md", return_value=""):
        about.send_about_page(handler, state)
    return b"".join(chunks)


def _render_align(**_fakes) -> bytes:
    from autostream_webui_page_align import send_align_page  # noqa: PLC0415

    handler, chunks = _handler("/align")
    with tempfile.TemporaryDirectory() as tmp:
        state = _scratch_state(tmp)
        run = MagicMock()
        run.pending_result.return_value = None
        run.snapshots.return_value = []
        with ExitStack() as stack:
            for p in (
                *_banner_patches("autostream_webui_page_align"),
                patch("autostream_webui_page_align._offsets_supported", return_value=True),
                patch("autostream_align._RUN", run),
            ):
                stack.enter_context(p)
            send_align_page(handler, state)
    return b"".join(chunks)


def _render_service(**_fakes) -> bytes:
    from autostream_webui_page_service import send_service_page  # noqa: PLC0415

    handler, chunks = _handler("/service")
    with tempfile.TemporaryDirectory() as tmp:
        state = _scratch_state(tmp)
        with ExitStack() as stack:
            for p in _banner_patches("autostream_webui_page_service"):
                stack.enter_context(p)
            send_service_page(handler, state)
    return b"".join(chunks)


def _render_logs(**_fakes) -> bytes:
    from autostream_webui_page_logs import send_logs_page  # noqa: PLC0415

    handler, chunks = _handler("/logs")
    with tempfile.TemporaryDirectory() as tmp:
        state = _scratch_state(tmp)
        with ExitStack() as stack:
            for p in _banner_patches("autostream_webui_page_logs"):
                stack.enter_context(p)
            send_logs_page(handler, state)
    return b"".join(chunks)


def _render_owntone(*, outputs: list | None = None, **_fakes) -> bytes:
    from autostream_webui_page_owntone import send_owntone_setup_page  # noqa: PLC0415
    from fake_store import fake_outputs  # noqa: PLC0415

    handler, chunks = _handler("/owntone-setup")
    cap = MagicMock()
    cap.can_set_output_mode = False
    cap.can_set_output_offset = False
    unsupported = MagicMock(ok=False, unsupported=True)
    with tempfile.TemporaryDirectory() as tmp:
        state = _scratch_state(tmp)
        with ExitStack() as stack:
            for p in (
                fake_outputs(list(outputs or []), connected=True),
                patch("autostream_webui_page_owntone.get_capabilities", return_value=cap),
                patch("autostream_webui_page_owntone.get_setting", return_value=unsupported),
                *_banner_patches("autostream_webui_page_owntone"),
            ):
                stack.enter_context(p)
            send_owntone_setup_page(handler, state, _auth())
    return b"".join(chunks)


def _render_owntone_restarting(*, next_path: str | None = None, **_fakes) -> bytes:
    from urllib.parse import quote  # noqa: PLC0415
    from autostream_webui_page_owntone import send_owntone_restarting_page  # noqa: PLC0415

    handler, chunks = _handler(
        "/owntone-restarting" + (f"?next={quote(next_path)}" if next_path else ""))
    send_owntone_restarting_page(handler, MagicMock())
    return b"".join(chunks)


def _render_rebooting(**_fakes) -> bytes:
    from autostream_webui_page_rebooting import send_rebooting_page  # noqa: PLC0415

    handler, chunks = _handler("/rebooting")
    with patch("autostream_webui_page_rebooting.build_top_banner_html", return_value=("", "")):
        send_rebooting_page(handler, MagicMock(), _auth())
    return b"".join(chunks)


def _render_first_boot_owntone(**_fakes) -> bytes:
    from autostream_webui_page_first_boot import send_first_boot_owntone_page  # noqa: PLC0415
    from fake_store import fake_outputs  # noqa: PLC0415

    handler, chunks = _handler("/first-boot/owntone")
    with tempfile.TemporaryDirectory() as tmp:
        state = _scratch_state(tmp)
        with fake_outputs([], connected=True):
            send_first_boot_owntone_page(handler, state, _auth())
    return b"".join(chunks)


def _render_first_boot_appliance(**_fakes) -> bytes:
    from autostream_webui_page_first_boot import send_first_boot_appliance_page  # noqa: PLC0415

    handler, chunks = _handler("/first-boot/appliance")
    with tempfile.TemporaryDirectory() as tmp:
        state = _scratch_state(tmp)
        with patch("autostream_webui_page_first_boot.get_system_hostname", return_value="autostream"):
            send_first_boot_appliance_page(handler, state, _auth())
    return b"".join(chunks)


def _render_hostname_changed(*, hostname: str = "autostream", **_fakes) -> bytes:
    from webui.common import send_hostname_changed_page  # noqa: PLC0415

    handler, chunks = _handler("/")
    handler.headers = {"Host": "old.local"}
    send_hostname_changed_page(handler, hostname, path="/", show_nav=False)
    return b"".join(chunks)


def _render_auth(*, next_path: str = "/", **_fakes) -> bytes:
    from urllib.parse import quote  # noqa: PLC0415
    from autostream_auth import AuthManager  # noqa: PLC0415
    from autostream_webui_page_auth import send_auth_page  # noqa: PLC0415

    handler, chunks = _handler("/auth")
    manager = AuthManager(config_path="dummy.ini")
    with tempfile.TemporaryDirectory() as tmp:
        send_auth_page(handler, _scratch_state(tmp), manager, f"next={quote(next_path)}")
    return b"".join(chunks)


_SETUP_CONFIG = {
    "general": {"fifo_path": "/tmp/autostream.fifo"},
    "audio1": {"capture_device": "hw:0,0"},
    "owntone": {"output_name": "Living Room"},
}

_SETUP_BT_STATUS = {"adapter_present": True, "paired": None, "link": "disconnected",
                    "streaming": False, "scanning": False}


@contextmanager
def _setup_session(*, bt_enabled=False, bt_status=None, dial_sightings=(), dial_entries=(), outputs=()):
    """Yield ``(state, auth)`` for the Setup page with the collaborators it reads
    (the settings, the speaker list, the host's names, the dial lists and
    Bluetooth) replaced by plain fakes."""
    from _setup_card_test_helpers import setup_page_mocks  # noqa: PLC0415
    from autostream_settings import SettingsStore, as_view  # noqa: PLC0415
    from webui.session_state import WebUIState  # noqa: PLC0415
    from fake_store import fake_outputs  # noqa: PLC0415

    auth = _auth()
    auth.get_boot_pin_value.return_value = None
    with tempfile.TemporaryDirectory() as tmp:
        config_path = Path(tmp) / "config.json"
        config_path.write_text(json.dumps(_SETUP_CONFIG), encoding="utf-8")
        store = SettingsStore(str(config_path), _save_interval_seconds=9999, _writer=MagicMock())
        state = WebUIState(str(config_path), str(Path(tmp) / "state.json"), settings=as_view(store))
        if bt_enabled:
            state.get_bluetooth_status = lambda: dict(bt_status or _SETUP_BT_STATUS)
        mocks = {
            "get_ap_ssid": "autostream-setup",
            "get_system_hostname": "autostream",
            "get_app_version": "2.0.0",
            "_get_dial_sightings": list(dial_sightings),
            "parse_dial_entries": list(dial_entries),
        }
        if bt_enabled:
            mocks.update(_bluetooth_installed=True, _bluetooth_services_enabled=True,
                         _bluetooth_onboard_enabled=True)
        else:
            mocks["_bluetooth_installed"] = False
        with fake_outputs(list(outputs), connected=True), setup_page_mocks(**mocks):
            yield state, auth
        store.close(save=False)


def _render_setup(*, bt_enabled: bool = False, bt_status: dict | None = None,
                  dial_sightings=(), dial_entries=(), outputs=(), **_fakes) -> bytes:
    from webui.browser.setup.page import send_setup_page  # noqa: PLC0415

    handler, chunks = _handler("/setup")
    with _setup_session(bt_enabled=bt_enabled, bt_status=bt_status, dial_sightings=dial_sightings,
                        dial_entries=dial_entries, outputs=outputs) as (state, auth):
        send_setup_page(handler, state, auth)
    return b"".join(chunks)


def setup_card_json(*, bt_enabled: bool = False, bt_status: dict | None = None,
                    dial_sightings=(), dial_entries=(), outputs=()) -> dict[str, bytes]:
    """Render every Setup card's lazy ``GET /api/setup/card/<key>`` reply, keyed
    by card key, as the stub server hands them to the page."""
    from webui.browser.setup.page import handle_setup_card_get
    from webui.browser.setup.context import CARDS  # noqa: PLC0415

    replies: dict[str, bytes] = {}
    with _setup_session(bt_enabled=bt_enabled, bt_status=bt_status, dial_sightings=dial_sightings,
                        dial_entries=dial_entries, outputs=outputs) as (state, auth):
        for card in CARDS:
            handler, chunks = _handler(f"/api/setup/card/{card.key}")
            handle_setup_card_get(handler, state, auth, card.key)
            replies[card.key] = b"".join(chunks)
    return replies


_RENDERERS = {
    "home": _render_home,
    "remote_home": _render_remote_home,
    "equaliser": _render_equaliser,
    "remote_equaliser": _render_remote_equaliser,
    "about": _render_about,
    "align": _render_align,
    "service": _render_service,
    "logs": _render_logs,
    "owntone": _render_owntone,
    "owntone_restarting": _render_owntone_restarting,
    "rebooting": _render_rebooting,
    "first_boot_owntone": _render_first_boot_owntone,
    "first_boot_appliance": _render_first_boot_appliance,
    "hostname_changed": _render_hostname_changed,
    "auth": _render_auth,
    "setup": _render_setup,
}

PAGES = tuple(_RENDERERS)


def render(page: str, **fakes) -> bytes:
    """Render ``page`` (one of ``PAGES``) as the server would and return the
    response bytes. ``fakes`` are per-page overrides (for example
    ``license_text`` for the About page); an unknown one is ignored."""
    try:
        renderer = _RENDERERS[page]
    except KeyError:
        raise ValueError(f"unknown page {page!r}; known: {sorted(_RENDERERS)}") from None
    return renderer(**fakes)
