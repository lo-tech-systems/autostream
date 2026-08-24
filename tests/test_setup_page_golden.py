"""tests/test_setup_page_golden.py

Golden-file characterisation test for send_setup_page().

Captures the full rendered HTML output of /setup as a golden file, and
re-asserts it unchanged after each per-card extraction from that function.

The Setup page composes from a card registry (`CARDS`); the nine detail
panels are not inlined into the initial /setup response -- each panel
renders as an empty `id="panel-body-<key>"` placeholder that the browser
fills in lazily via `GET /api/setup/card/<key>` the first time it's opened
(see `_setup_build_ctx()`/`handle_setup_card_get()` in
`autostream_webui_page_setup.py`). The collapsed summary rows (the only
per-card state visible on initial load) are unchanged byte-for-byte; only
the nine detail-panel bodies moved out of this response. The golden file
tracks that summary-rows-plus-empty-panels shape -- a deliberate wire
change, not accidental drift.

Three paths are characterised:
  - the full rendered page against a representative, fixed config (both
    inputs enabled, repeat + track identification on, one authorized+online
    dial, a real OwnTone output list) -- summary-rows-plus-empty-panels
    shaped;
  - the "broken config" failure path (`_config_snapshot` raising), which
    send_setup_page() handles by 302-redirecting to "/" -- easy to lose
    silently when the function is split;
  - one lazy card-detail response (`GET /api/setup/card/bluetooth`, via
    `handle_setup_card_get()`), characterising the JSON `{ok, html}` shape
    and the Bluetooth card's detail HTML the browser injects into
    `#panel-body-bluetooth` on first open.

Genuinely run-varying values (app version, CSRF token) are pinned to fixed
mock values by the test harness itself; `_normalise()` is still applied
before comparison as a defensive substitution layer so the golden file
stays valid even if a future change makes one of these genuinely dynamic
again.
"""
from __future__ import annotations

import io
import json
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

GOLDEN_DIR = Path(__file__).parent / "golden"
GOLDEN_FULL_PAGE = GOLDEN_DIR / "setup_page_full.html"
GOLDEN_CARD_DETAIL = GOLDEN_DIR / "setup_card_detail_bluetooth.json"

# Set to True locally to regenerate the golden file after a *deliberate*,
# reviewed change to the rendered output. Must be False in committed code.
_REGENERATE = False

FIXED_APP_VERSION = "1.0.0-golden"
FIXED_CSRF_TOKEN = "golden-csrf-token"


def _minimal_cfg(tmp_path: Path) -> Path:
    cfg = tmp_path / "autostream.json"
    cfg.write_text(json.dumps({
        "general": {
            "log_level": "info",
            "silence_seconds": 30,
            "audio_path": "balanced",
            "minimum_playback_seconds": 5,
            "mdns_grace_period_seconds": 600,
        },
        "owntone": {
            "base_url": "http://localhost:3689",
            "output_name": "Living Room Speaker",
            "volume_percent": 65,
        },
        "audio1": {
            "capture_device": "hw:1,0",
            "gain_db": 2,
            "eq_40hz_db": -1,
            "eq_100hz_db": 0,
            "eq_8khz_db": 1,
            "turntable": True,
            "enabled": True,
        },
        "audio2": {
            "capture_device": "hw:2,0",
            "gain_db": -3,
            "eq_40hz_db": 0,
            "eq_100hz_db": 2,
            "eq_8khz_db": 0,
            "turntable": False,
            "enabled": True,
        },
        "repeat": {
            "enabled": True,
            "target_minutes": 33,
        },
        "track_identification": {
            "enabled": True,
            "analysis_lead_in_seconds": 5,
            "refresh_seconds": 300,
            "track_change_silence_seconds": 2.0,
        },
        "webui": {
            "dark_mode": False,
            "show_master_volume": True,
            "show_input_detail": True,
            "show_hostname_on_home": True,
            "control_other_appliances": True,
            "advertise_appliance": True,
            "hidden_outputs": [],
            "output_usage_poll_interval_seconds": 3,
        },
        "updates": {"auto_update": True, "update_channel": "stable"},
    }), encoding="utf-8")
    return cfg


class _DialSighting:
    def __init__(self, uuid, name, version, pin_recovery=False):
        self.uuid = uuid
        self.name = name
        self.version = version
        self.pin_recovery = pin_recovery


class _DialEntry:
    def __init__(self, uuid, name, current_name="", last_seen=""):
        self.uuid = uuid
        self.name = name
        self.current_name = current_name
        self.last_seen = last_seen


class _OutputInfo:
    def __init__(self, name):
        self.name = name


class _ListOutputsResult:
    def __init__(self, ok, outputs=(), error=""):
        self.ok = ok
        self.outputs = outputs
        self.error = error


class _BackendCapabilities:
    def __init__(self, can_set_output_offset=True):
        self.can_set_output_offset = can_set_output_offset


def _normalise(html: str) -> str:
    """Substitute genuinely run-varying values before golden comparison.

    Both values below are pinned to fixed mocks by the test harness itself
    (FIXED_APP_VERSION / FIXED_CSRF_TOKEN), so this is a defensive no-op in
    practice today -- kept so the golden file doesn't silently start
    "passing" by accident if one of these becomes genuinely dynamic again.
    """
    html = html.replace(FIXED_APP_VERSION, "{APP_VERSION}")
    html = html.replace(FIXED_CSRF_TOKEN, "{CSRF_TOKEN}")
    # Belt-and-braces: strip any stray object-identity repr that would make
    # a MagicMock-derived value non-deterministic across runs/machines.
    html = re.sub(r"<MagicMock id='\d+'>", "{MOCK}", html)
    return html


def _render_full_page(tmp_path: Path) -> str:
    from autostream_webui_page_setup import send_setup_page
    from autostream_settings import SettingsStore
    from autostream_webui_state import WebUIState

    cfg = _minimal_cfg(tmp_path)
    store = SettingsStore(str(cfg), _save_interval_seconds=9999)
    state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)

    handler = MagicMock()
    handler.wfile = io.BytesIO()
    handler._csrf_token = None  # force auth.get_csrf_token() path, not a stray MagicMock attr
    auth = MagicMock()
    auth.ensure_session.return_value = FIXED_CSRF_TOKEN
    auth.get_csrf_token.return_value = FIXED_CSRF_TOKEN
    auth.get_boot_pin_value.return_value = "1234"

    outputs = (
        _OutputInfo("Living Room Speaker"),
        _OutputInfo("Kitchen Speaker"),
    )
    list_result = _ListOutputsResult(ok=True, outputs=outputs)

    sightings = [_DialSighting("dial-aaaa-1111", "Hallway Dial", "1.0.0-golden", pin_recovery=False)]
    entries = [_DialEntry("dial-aaaa-1111", "Hallway Dial", current_name="Hallway Dial")]

    with patch.multiple(
        "autostream_webui_page_setup",
        get_system_hostname=MagicMock(return_value="autostream-golden"),
        list_outputs=MagicMock(return_value=list_result),
        get_ap_ssid=MagicMock(return_value="autostream_AP"),
        get_app_version=MagicMock(return_value=FIXED_APP_VERSION),
        _get_dial_sightings=MagicMock(return_value=sightings),
        parse_dial_entries=MagicMock(return_value=entries),
        suggested_silence_threshold_dbfs=MagicMock(return_value=-50.0),
        build_top_banner_html=MagicMock(return_value=("", "")),
        _set_flash_cookie=MagicMock(),
        is_high_performance_pi=MagicMock(return_value=True),
    ):
        with patch.object(
            state, "get_monitor_devices",
            return_value=[
                {"hw": "hw:1,0", "label": "USB Turntable", "card": "USB Turntable, USB Audio"},
                {"hw": "hw:2,0", "label": "USB Line In", "card": "USB Line In, USB Audio"},
            ],
        ):
            with patch(
                "autostream_player_service.get_capabilities",
                return_value=_BackendCapabilities(can_set_output_offset=True),
            ):
                send_setup_page(handler, state, auth, flash_msg="")

    store.close(save=False)
    return handler.wfile.getvalue().decode("utf-8", errors="replace")


def _render_card_detail(tmp_path: Path, key: str) -> str:
    """Render one lazy card-detail response -- the JSON body
    `GET /api/setup/card/<key>` returns, matching `_render_full_page()`'s
    fixed config/mocks so the two goldens describe the same appliance
    state."""
    from autostream_webui_page_setup import handle_setup_card_get
    from autostream_settings import SettingsStore
    from autostream_webui_state import WebUIState

    cfg = _minimal_cfg(tmp_path)
    store = SettingsStore(str(cfg), _save_interval_seconds=9999)
    state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)

    handler = MagicMock()
    handler.wfile = io.BytesIO()
    auth = MagicMock()
    auth.ensure_session.return_value = FIXED_CSRF_TOKEN
    auth.get_csrf_token.return_value = FIXED_CSRF_TOKEN
    auth.get_boot_pin_value.return_value = "1234"

    outputs = (
        _OutputInfo("Living Room Speaker"),
        _OutputInfo("Kitchen Speaker"),
    )
    list_result = _ListOutputsResult(ok=True, outputs=outputs)

    sightings = [_DialSighting("dial-aaaa-1111", "Hallway Dial", "1.0.0-golden", pin_recovery=False)]
    entries = [_DialEntry("dial-aaaa-1111", "Hallway Dial", current_name="Hallway Dial")]

    with patch.multiple(
        "autostream_webui_page_setup",
        get_system_hostname=MagicMock(return_value="autostream-golden"),
        list_outputs=MagicMock(return_value=list_result),
        get_ap_ssid=MagicMock(return_value="autostream_AP"),
        get_app_version=MagicMock(return_value=FIXED_APP_VERSION),
        _get_dial_sightings=MagicMock(return_value=sightings),
        parse_dial_entries=MagicMock(return_value=entries),
        suggested_silence_threshold_dbfs=MagicMock(return_value=-50.0),
        build_top_banner_html=MagicMock(return_value=("", "")),
        _set_flash_cookie=MagicMock(),
        is_high_performance_pi=MagicMock(return_value=True),
    ):
        with patch.object(
            state, "get_monitor_devices",
            return_value=[
                {"hw": "hw:1,0", "label": "USB Turntable", "card": "USB Turntable, USB Audio"},
                {"hw": "hw:2,0", "label": "USB Line In", "card": "USB Line In, USB Audio"},
            ],
        ):
            with patch(
                "autostream_player_service.get_capabilities",
                return_value=_BackendCapabilities(can_set_output_offset=True),
            ):
                handle_setup_card_get(handler, state, auth, key)

    store.close(save=False)
    return handler.wfile.getvalue().decode("utf-8", errors="replace")


class TestSetupPageGolden:
    def test_full_page_matches_golden(self, tmp_path: Path):
        html = _normalise(_render_full_page(tmp_path))

        if _REGENERATE:
            GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
            GOLDEN_FULL_PAGE.write_text(html, encoding="utf-8")
            pytest.skip("golden file regenerated -- set _REGENERATE back to False")

        assert GOLDEN_FULL_PAGE.exists(), (
            f"Golden file missing: {GOLDEN_FULL_PAGE}. Run once with "
            f"_REGENERATE=True to create it, then set it back to False."
        )
        expected = GOLDEN_FULL_PAGE.read_text(encoding="utf-8")
        assert html == expected, (
            "Rendered /setup page diverged from the golden file -- this "
            "must stay byte-identical across the send_setup_page() card "
            "extraction."
        )


class TestSetupPageBrokenConfigFailurePath:
    """send_setup_page()'s outer try/except: a config-load failure must
    302-redirect to '/' and write no body, per its documented "swallow and
    log, degrade gracefully" convention. Easy to lose silently when the
    function is split into per-card pieces."""

    def test_broken_config_redirects_to_home(self, tmp_path: Path):
        from autostream_webui_page_setup import send_setup_page
        from autostream_settings import SettingsStore
        from autostream_webui_state import WebUIState

        cfg = _minimal_cfg(tmp_path)
        store = SettingsStore(str(cfg), _save_interval_seconds=9999)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)

        handler = MagicMock()
        handler.wfile = io.BytesIO()
        auth = MagicMock()

        with patch(
            "autostream_webui_page_setup._config_snapshot",
            side_effect=RuntimeError("broken config for characterisation test"),
        ):
            send_setup_page(handler, state, auth, flash_msg="")

        store.close(save=False)

        handler.send_response.assert_called_once_with(302)
        handler.send_header.assert_called_once_with("Location", "/")
        handler.end_headers.assert_called_once()
        assert handler.wfile.getvalue() == b""


class TestSetupCardDetailGolden:
    """The lazy per-card detail fetch: `GET /api/setup/card/<key>`
    (`handle_setup_card_get()`) must return the same detail HTML this card
    used to carry inline in the full-page golden above, just wrapped in a
    `{ok, html}` JSON envelope and fetched on demand instead."""

    def test_bluetooth_card_detail_matches_golden(self, tmp_path: Path):
        body = _normalise(_render_card_detail(tmp_path, "bluetooth"))

        if _REGENERATE:
            GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
            GOLDEN_CARD_DETAIL.write_text(body, encoding="utf-8")
            pytest.skip("golden file regenerated -- set _REGENERATE back to False")

        assert GOLDEN_CARD_DETAIL.exists(), (
            f"Golden file missing: {GOLDEN_CARD_DETAIL}. Run once with "
            f"_REGENERATE=True to create it, then set it back to False."
        )
        expected = GOLDEN_CARD_DETAIL.read_text(encoding="utf-8")
        assert body == expected, (
            "GET /api/setup/card/bluetooth's response diverged from the "
            "golden file."
        )
        payload = json.loads(body)
        assert payload["ok"] is True
        assert "bt-card-summary" not in payload["html"]  # sanity: detail, not the list row

    def test_unknown_card_key_returns_404_shape(self, tmp_path: Path):
        body = _normalise(_render_card_detail(tmp_path, "not-a-real-card"))
        payload = json.loads(body)
        assert payload == {"ok": False, "error": "unknown_card"}
