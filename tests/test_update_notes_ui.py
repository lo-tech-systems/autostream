"""tests/test_update_notes_ui.py

Frontend coverage for the release-notes modal wired into the Setup page's
Updates card: the shared info modal (INFO_MODAL_HTML / INFO_MODAL_SCRIPT)
must be embedded exactly once, and the Check/Info button must switch modes
based on the /api/update/check response rather than writing notes inline.

Style matches tests/test_p2_browser_behavior.py: source-contract substring
assertions against the raw module source, plus one full-render check via
send_setup_page with external dependencies mocked out.
"""
from __future__ import annotations

import importlib.util
import io
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).parent.parent


def _setup_page_src() -> str:
    return (REPO_ROOT / "core" / "autostream_webui_page_setup.py").read_text(encoding="utf-8")


def _load_page_setup() -> ModuleType:
    sys.path.insert(0, str(REPO_ROOT / "core"))
    import autostream_webui_page_setup as m
    return m


def _render_setup_page() -> str:
    """Render the full setup page HTML with all external dependencies mocked."""
    m = _load_page_setup()
    mod = m.__name__

    buf = io.BytesIO()
    handler = MagicMock()
    handler.wfile = buf
    handler._csrf_token = "tok"
    handler.headers = {"Cookie": ""}

    auth = MagicMock()
    auth.get_csrf_token.return_value = "tok"
    auth.get_boot_pin_value.return_value = ""

    state = MagicMock()
    state.get_monitor_devices.return_value = []

    import autostream_config as _cfg
    parsed = _cfg.parse_config({
        "audio1": {"capture_device": "hw:0,0"},
    })

    list_out = MagicMock()
    list_out.ok = False

    with patch(f"{mod}._config_snapshot", new=lambda state: parsed), \
         patch(f"{mod}.list_outputs", new=lambda base_url, timeout: list_out), \
         patch(f"{mod}.build_top_banner_html", new=lambda **kw: ("", "")), \
         patch(f"{mod}.get_system_hostname", new=lambda: "test-host"), \
         patch(f"{mod}.get_app_version", new=lambda: "1.0.0"), \
         patch(f"{mod}.suggested_silence_threshold_dbfs", new=lambda tt: -45.0), \
         patch(f"{mod}.get_ap_ssid", new=lambda: "test-ssid"), \
         patch(f"{mod}.parse_dial_entries", new=lambda: []), \
         patch(f"{mod}._get_dial_sightings", new=lambda: []):
        m.send_setup_page(handler, state, auth)

    return buf.getvalue().decode("utf-8", errors="replace")


def _updates_iife(src: str) -> str:
    """Return the body of the updates-card IIFE (bCheck/bInst wiring)."""
    start = src.find('const bCheck = document.getElementById("btnCheck")')
    assert start >= 0, "updates IIFE not found (bCheck lookup missing)"
    end = src.find("})();", start)
    assert end > start, "updates IIFE close not found"
    return src[start:end]


class TestInfoModalEmbedded:
    """The shared info modal must be embedded exactly once in the setup page.

    INFO_MODAL_HTML / INFO_MODAL_SCRIPT are imported constants from
    autostream_webui_assets, not literal text in the page-setup module, so
    these are asserted against the fully rendered page rather than raw
    source. The import itself is covered separately below.
    """

    def test_page_setup_imports_info_modal_constants(self):
        src = _setup_page_src()
        assert "INFO_MODAL_HTML" in src
        assert "INFO_MODAL_SCRIPT" in src

    def test_rendered_page_has_info_modal_exactly_once(self):
        html_out = _render_setup_page()
        assert html_out.count('id="infoModal"') == 1

    def test_rendered_page_defines_show_info_modal(self):
        html_out = _render_setup_page()
        assert "function showInfoModal" in html_out

    def test_info_modal_not_added_to_global_escape_listener(self):
        """The setup page's shared keydown Escape listener handles its other
        modals explicitly; infoModal must not be added there because
        showInfoModal installs its own per-call Escape handler."""
        src = _setup_page_src()
        start = src.find("document.addEventListener('keydown', function(ev) {{")
        assert start >= 0, "global Escape listener not found"
        end = src.find("});", start)
        block = src[start:end]
        assert "infoModal" not in block


class TestCheckButtonInfoModeSwitch:
    """The Check button flips to Info mode when an update is available."""

    def test_info_label_assigned_on_update_available(self):
        block = _updates_iife(_setup_page_src())
        assert 'bCheck.textContent = "Info";' in block

    def test_check_label_restored_on_no_update(self):
        block = _updates_iife(_setup_page_src())
        # No-update branch resets via the shared helper (which relabels
        # the button back to "Check") before setting its own message.
        idx = block.find('msg(j.ok?"No updates available.":"Check failed.");')
        assert idx >= 0
        preceding = block[:idx]
        reset_call_idx = preceding.rfind('resetUpdateCheckState();')
        info_idx = preceding.rfind('bCheck.textContent = "Info";')
        assert reset_call_idx >= 0
        assert reset_call_idx > info_idx

    def test_check_label_restored_on_check_failure(self):
        block = _updates_iife(_setup_page_src())
        idx = block.find('catch(e) {{')
        assert idx >= 0
        tail = block[idx:]
        assert 'resetUpdateCheckState();' in tail
        assert 'msg("Check failed.");' in tail

    def test_info_mode_click_opens_modal_instead_of_rechecking(self):
        block = _updates_iife(_setup_page_src())
        idx = block.find("if (infoMode) {{")
        assert idx >= 0
        end = block.find("}}", idx)
        info_branch = block[idx:end]
        assert 'showInfoModal("Release Notes"' in info_branch
        assert "return;" in info_branch

    def test_release_notes_html_consumed_from_check_response(self):
        block = _updates_iife(_setup_page_src())
        assert "j.release_notes_html" in block

    def test_release_notes_text_consumed_from_check_response(self):
        block = _updates_iife(_setup_page_src())
        assert "j.release_notes" in block

    def test_no_release_notes_fallback_text_present(self):
        block = _updates_iife(_setup_page_src())
        assert "No release notes provided." in block

    def test_notes_state_cleared_on_reset(self):
        block = _updates_iife(_setup_page_src())
        # Notes are cleared once, inside the shared reset helper.
        assert block.count('notesHtml = ""; notesText = "";') == 1
        # Both the no-update and error paths route through that helper.
        assert block.count('resetUpdateCheckState();') >= 2


class TestResetUpdateCheckState:
    """window.resetUpdateCheckState is exposed so the pre-release channel
    toggle can invalidate a stale candidate/notes from the other channel."""

    def test_reset_function_exposed_on_window(self):
        block = _updates_iife(_setup_page_src())
        assert "window.resetUpdateCheckState = resetUpdateCheckState;" in block

    def test_reset_function_relabels_check_button_and_clears_candidate(self):
        block = _updates_iife(_setup_page_src())
        start = block.find("function resetUpdateCheckState()")
        assert start >= 0
        end = block.find("window.resetUpdateCheckState", start)
        body = block[start:end]
        assert 'bCheck.textContent = "Check";' in body
        assert "cand = null;" in body
        assert "infoMode = false;" in body
        assert 'notesHtml = ""; notesText = "";' in body

    def test_reset_function_disables_install_button(self):
        block = _updates_iife(_setup_page_src())
        start = block.find("function resetUpdateCheckState()")
        end = block.find("window.resetUpdateCheckState", start)
        body = block[start:end]
        assert "bInst.disabled = true;" in body

    def test_reset_function_clears_upd_msg(self):
        block = _updates_iife(_setup_page_src())
        start = block.find("function resetUpdateCheckState()")
        end = block.find("window.resetUpdateCheckState", start)
        body = block[start:end]
        assert 'msg("");' in body

    def test_prerelease_checkbox_calls_reset_on_toggle(self):
        src = _setup_page_src()
        idx = src.find('id="updates_prerelease_channel"')
        assert idx >= 0
        onchange_start = src.find('onchange="', idx)
        onchange_end = src.find('"', onchange_start + len('onchange="'))
        onchange = src[onchange_start:onchange_end]
        assert "resetUpdateCheckState()" in onchange
        assert "refreshSystemCardSub()" in onchange
        assert "settingsSaveField('updates.update_channel'" in onchange


class TestUpdNotesRemoved:
    """#updNotes and its old notes() writer are unused after this change and
    have been removed rather than left dead."""

    def test_upd_notes_element_id_absent(self):
        src = _setup_page_src()
        assert 'id="updNotes"' not in src

    def test_notes_helper_absent(self):
        src = _setup_page_src()
        assert 'document.getElementById("updNotes")' not in src

    def test_upd_msg_still_present(self):
        """updMsg (the version-line status) is untouched by this change."""
        src = _setup_page_src()
        assert 'id="updMsg"' in src
