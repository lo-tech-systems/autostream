"""test_remote_polling.py — JS-source tests for remote Home and Equaliser polling.

Covers:
  Remote Home:
    - visibility resume re-enables polling before calling pollHomeState
    - output fingerprint (shape) includes name, is_default — not just IDs
    - re-render decision uses shape comparison, not raw DOM ID scan

  Remote Equaliser:
    - full EQ state polling is scheduled, not just trim-status polling
    - _pollFullEqState fetches __POLL_URL (full state endpoint)
    - renderEqFromState has an update path for existing sliders/labels
    - active (focused) sliders are not overwritten by remote updates
    - pending fields (in-flight saves) are not overwritten
    - _saveEqField marks fields pending and clears on completion
    - visibility resume immediately calls _pollFullEqState
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

try:
    from autostream_webui_page_airplay import _REMOTE_HOME_SCRIPT
    from autostream_webui_page_equaliser import _EQUALISER_JS, _REMOTE_EQUALISER_SCRIPT
    _HAS_SCRIPTS = True
except ImportError:
    _HAS_SCRIPTS = False
    _EQUALISER_JS = ""

_skip = pytest.mark.skipif(not _HAS_SCRIPTS, reason="page scripts unavailable")


# ---------------------------------------------------------------------------
# Remote Home — visibility resume fix
# ---------------------------------------------------------------------------

@_skip
class TestRemoteHomeVisibilityResume:
    def test_sets_polling_true_before_poll_on_resume(self):
        """visibilitychange must set __remotePolling=true before pollHomeState()."""
        src = _REMOTE_HOME_SCRIPT
        # Find the visibilitychange handler body
        vis_idx = src.index('visibilitychange')
        resume_block = src[vis_idx:vis_idx + 300]
        enable_pos = resume_block.index('__remotePolling=true')
        poll_pos = resume_block.index('pollHomeState()')
        assert enable_pos < poll_pos, (
            "__remotePolling=true must appear before pollHomeState() in "
            "the visibility-resume branch"
        )

    def test_polling_flag_not_reset_on_hide(self):
        """visibilitychange hide branch must set __remotePolling=false."""
        src = _REMOTE_HOME_SCRIPT
        assert '__remotePolling=false' in src


# ---------------------------------------------------------------------------
# Remote Home — output shape fingerprint
# ---------------------------------------------------------------------------

@_skip
class TestRemoteHomeOutputShape:
    def test_shape_helper_function_declared(self):
        assert '_outputsShape' in _REMOTE_HOME_SCRIPT

    def test_last_shape_initialized_before_polling_starts(self):
        """The first non-empty response must not read an undeclared shape variable."""
        src = _REMOTE_HOME_SCRIPT
        declaration_pos = src.index("var __lastOutputsShape='';")
        startup_pos = src.index("window.addEventListener('DOMContentLoaded'")
        assert declaration_pos < startup_pos

    def test_shape_key_includes_name(self):
        """Shape key must capture output name so name changes trigger re-render."""
        src = _REMOTE_HOME_SCRIPT
        # _outputShapeKey uses o.name
        key_fn_idx = src.index('_outputShapeKey')
        key_fn_body = src[key_fn_idx:key_fn_idx + 150]
        assert 'o.name' in key_fn_body or '.name' in key_fn_body

    def test_shape_key_includes_default_flag(self):
        """Shape key must capture is_default so default changes trigger re-render."""
        src = _REMOTE_HOME_SCRIPT
        key_fn_idx = src.index('_outputShapeKey')
        key_fn_body = src[key_fn_idx:key_fn_idx + 200]
        assert 'is_default' in key_fn_body

    def test_shape_key_includes_id(self):
        """Shape key must capture id so add/remove triggers re-render."""
        src = _REMOTE_HOME_SCRIPT
        key_fn_idx = src.index('_outputShapeKey')
        key_fn_body = src[key_fn_idx:key_fn_idx + 150]
        assert 'o.id' in key_fn_body or '.id' in key_fn_body

    def test_render_home_state_uses_last_shape(self):
        """renderHomeState must compare against __lastOutputsShape, not DOM IDs."""
        src = _REMOTE_HOME_SCRIPT
        render_fn_idx = src.index('function renderHomeState(')
        render_fn_end = src.index('\nvar __remoteFailCount', render_fn_idx)
        render_body = src[render_fn_idx:render_fn_end]
        assert '__lastOutputsShape' in render_body

    def test_render_home_state_drops_json_sort_id_comparison(self):
        """Old DOM-ID sort comparison must be replaced."""
        # The legacy approach serialised two sorted ID arrays via JSON.stringify
        assert 'JSON.stringify(inIds' not in _REMOTE_HOME_SCRIPT
        assert 'domIds' not in _REMOTE_HOME_SCRIPT

    def test_last_shape_updated_on_rerender(self):
        """__lastOutputsShape must be updated before calling renderOutputList."""
        src = _REMOTE_HOME_SCRIPT
        render_fn_idx = src.index('function renderHomeState(')
        render_fn_end = src.index('\nvar __remoteFailCount', render_fn_idx)
        render_body = src[render_fn_idx:render_fn_end]
        update_pos = render_body.index('__lastOutputsShape=')
        render_pos = render_body.index('renderOutputList(')
        assert update_pos < render_pos

    def test_empty_outputs_clears_existing_cards_once_tolerance_elapses(self):
        """Once the empty-outputs tolerance has elapsed, existing output cards
        must be removed from the DOM (the clear is gated on elapsed time, not
        immediate on the first empty observation)."""
        src = _REMOTE_HOME_SCRIPT
        render_fn_idx = src.index('function renderHomeState(')
        render_fn_end = src.index('\nvar __remoteFailCount', render_fn_idx)
        render_body = src[render_fn_idx:render_fn_end]
        # Find the empty-outputs branch and confirm it removes children
        empty_idx = render_body.index('outputs.length===0')
        empty_branch = render_body[empty_idx:empty_idx + 400]
        assert 'removeChild' in empty_branch or 'innerHTML' in empty_branch
        # The clear must be conditioned on the elapsed-tolerance check, not
        # performed unconditionally on the first empty observation.
        tolerance_idx = empty_branch.index('__OUTPUTS_EMPTY_TOLERANCE_MS')
        clear_idx = empty_branch.index('removeChild')
        assert tolerance_idx < clear_idx

    def test_empty_outputs_resets_last_shape(self):
        """Once cleared, __lastOutputsShape must be reset so the next non-empty poll re-renders."""
        src = _REMOTE_HOME_SCRIPT
        render_fn_idx = src.index('function renderHomeState(')
        render_fn_end = src.index('\nvar __remoteFailCount', render_fn_idx)
        render_body = src[render_fn_idx:render_fn_end]
        empty_idx = render_body.index('outputs.length===0')
        empty_branch = render_body[empty_idx:empty_idx + 400]
        assert "__lastOutputsShape=''" in empty_branch

    def test_empty_outputs_debounce_is_time_based(self):
        """The empty-outputs debounce must track wall-clock elapsed time
        (Date.now()-based), not a poll count."""
        src = _REMOTE_HOME_SCRIPT
        assert '__outputsEmptySince' in src
        assert '__OUTPUTS_EMPTY_COUNT' not in src
        render_fn_idx = src.index('function renderHomeState(')
        render_fn_end = src.index('\nvar __remoteFailCount', render_fn_idx)
        render_body = src[render_fn_idx:render_fn_end]
        assert 'window.__OUTPUTS_EMPTY_TOLERANCE_MS' in render_body

    def test_non_empty_outputs_resets_empty_since(self):
        """A non-empty outputs observation must reset the empty-since timer."""
        src = _REMOTE_HOME_SCRIPT
        render_fn_idx = src.index('function renderHomeState(')
        render_fn_end = src.index('\nvar __remoteFailCount', render_fn_idx)
        render_body = src[render_fn_idx:render_fn_end]
        assert '__outputsEmptySince=null' in render_body

    def test_outputs_unknown_does_not_clear_or_advance_timer(self):
        """When data.outputs is not an array (unknown/missing), the DOM must
        be left untouched and the empty-since timer must not be touched."""
        src = _REMOTE_HOME_SCRIPT
        render_fn_idx = src.index('function renderHomeState(')
        render_fn_end = src.index('\nvar __remoteFailCount', render_fn_idx)
        render_body = src[render_fn_idx:render_fn_end]
        assert 'Array.isArray(data.outputs)' in render_body


# ---------------------------------------------------------------------------
# Local Home page — outputs-empty tolerance (time-based, replacing the old
# poll-count debounce) and the tolerance constant injection
# ---------------------------------------------------------------------------

def _render_local_home_html() -> str:
    from unittest.mock import MagicMock
    from contextlib import ExitStack
    from unittest.mock import patch as _patch
    from autostream_webui_page_airplay import send_airplay_page
    from track_id.models import disabled_snapshot

    handler = MagicMock()
    chunks: list = []
    handler.wfile.write = lambda d: chunks.append(d)
    handler._csrf_token = "testcsrf"
    handler._pending_set_cookies = []

    auth = MagicMock()
    auth.get_csrf_token.return_value = "testcsrf"

    state = MagicMock()
    state.config_path = "dummy.ini"

    parsed = MagicMock()
    parsed.owntone.base_url = "http://localhost:3689"
    parsed.owntone.output_name = "autostream"
    parsed.owntone.volume_percent = 20
    parsed.webui.show_master_volume = True
    parsed.webui.show_input_detail = False
    parsed.webui.show_hostname_on_home = False
    parsed.webui.control_other_appliances = False
    parsed.webui.hidden_outputs = []
    parsed.webui.dark_mode = False
    parsed.track_identification = MagicMock(enabled=False)
    parsed.repeat.enabled = True
    parsed.repeat.codec = "auto"

    playback = MagicMock()
    playback.inputs = {}
    playback.stylus_banner_text = ""
    playback.belt_banner_text = ""
    playback.bearing_banner_text = ""
    playback.has_warning = False
    playback.to_public_dict.return_value = {}

    list_result = MagicMock(ok=False, outputs=[])
    buf_result = MagicMock(ok=True, value="2250")

    patches = [
        _patch("autostream_webui_page_airplay._config_snapshot", return_value=parsed),
        _patch("autostream_webui_page_airplay.get_appliance_id", return_value="00000000000000000000"),
        _patch("autostream_webui_page_airplay.get_all_appliances", return_value=[]),
        _patch("autostream_webui_page_airplay.get_system_hostname", return_value="autostream"),
        _patch("autostream_webui_page_airplay.get_monitor_levels_dbfs", return_value=[]),
        _patch("autostream_webui_page_airplay.get_playback_snapshot", return_value=playback),
        _patch("autostream_webui_page_airplay.list_outputs", return_value=list_result),
        _patch("autostream_webui_page_airplay.get_setting", return_value=buf_result),
        _patch("autostream_core.get_active_track_identification_snapshot",
               return_value=disabled_snapshot()),
        _patch("autostream_webui_page_airplay.build_top_banner_html", return_value=("", "")),
    ]

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        send_airplay_page(handler, state, auth)

    return b"".join(chunks).decode("utf-8", errors="replace")


@pytest.fixture(scope="module")
def local_home_html() -> str:
    return _render_local_home_html()


@_skip
class TestOutputsEmptyToleranceConstant:
    def test_tolerance_constant_defined_in_python(self):
        from autostream_webui_page_airplay import OUTPUTS_EMPTY_TOLERANCE_SECONDS
        assert OUTPUTS_EMPTY_TOLERANCE_SECONDS == 6.0

    def test_tolerance_injected_into_local_script(self, local_home_html):
        assert "window.__OUTPUTS_EMPTY_TOLERANCE_MS=6000;" in local_home_html

    def test_tolerance_injected_into_remote_script(self):
        from unittest.mock import MagicMock
        from contextlib import ExitStack
        from unittest.mock import patch as _patch
        from autostream_webui_page_airplay import send_remote_home_page

        handler = MagicMock()
        chunks: list = []
        handler.wfile.write = lambda d: chunks.append(d)
        handler._csrf_token = "testcsrf"
        handler._pending_set_cookies = []

        state = MagicMock()
        state.config_path = "dummy.ini"
        parsed = MagicMock()
        parsed.owntone.base_url = "http://localhost:3689"
        parsed.owntone.volume_percent = 20
        parsed.webui.dark_mode = False
        parsed.webui.show_hostname_on_home = False
        parsed.webui.control_other_appliances = False
        parsed.repeat.enabled = True
        parsed.repeat.codec = "auto"

        patches = [
            _patch("autostream_webui_page_airplay._config_snapshot", return_value=parsed),
            _patch("autostream_webui_page_airplay.get_appliance_id", return_value="00000000000000000000"),
            _patch("autostream_webui_page_airplay._build_appliances_for_selector", return_value=[]),
            _patch("autostream_webui_page_airplay.build_appliance_selector_html", return_value=""),
        ]
        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            send_remote_home_page(handler, state, "some-remote-appliance-id")

        remote_home_html = b"".join(chunks).decode("utf-8", errors="replace")
        assert "window.__OUTPUTS_EMPTY_TOLERANCE_MS=6000;" in remote_home_html


@_skip
class TestLocalHomeOutputsEmptyDebounce:
    def test_old_count_mechanism_removed(self, local_home_html):
        assert "__OUTPUTS_EMPTY_COUNT" not in local_home_html

    def test_time_based_debounce_present(self, local_home_html):
        # Local Home's output-poll body migrated onto the shared Poller helper:
        # the fetch/in-flight-guard wrapper moved into poll.js, leaving
        # this page's own onOutputsPollData(j) as the onData callback holding
        # the empty-list debounce logic that's specific to this one poller.
        assert "__OUTPUTS_EMPTY_SINCE" in local_home_html
        fn_idx = local_home_html.index("function onOutputsPollData")
        fn_end = local_home_html.index("window.addEventListener('DOMContentLoaded'", fn_idx)
        fn_body = local_home_html[fn_idx:fn_end]
        assert "Date.now() - window.__OUTPUTS_EMPTY_SINCE" in fn_body
        assert "window.__OUTPUTS_EMPTY_TOLERANCE_MS" in fn_body

    def test_non_empty_outputs_resets_empty_since(self, local_home_html):
        fn_idx = local_home_html.index("function onOutputsPollData")
        fn_end = local_home_html.index("window.addEventListener('DOMContentLoaded'", fn_idx)
        fn_body = local_home_html[fn_idx:fn_end]
        assert "window.__OUTPUTS_EMPTY_SINCE = null;" in fn_body

    def test_outputs_unknown_leaves_dom_alone(self, local_home_html):
        """A non-array outputs field (missing despite ok:true) must be treated
        as unknown, not as a confirmed empty list -- and must not consume or
        reset the empty-tolerance timer."""
        fn_idx = local_home_html.index("function onOutputsPollData")
        fn_end = local_home_html.index("window.addEventListener('DOMContentLoaded'", fn_idx)
        fn_body = local_home_html[fn_idx:fn_end]
        unknown_idx = fn_body.index("!Array.isArray(j.outputs)")
        unknown_branch = fn_body[unknown_idx:unknown_idx + 350]
        assert "return;" in unknown_branch


# ---------------------------------------------------------------------------
# Remote Equaliser — full-state polling
# ---------------------------------------------------------------------------

@_skip
class TestRemoteEqualiserFullPolling:
    def test_poll_full_eq_state_function_exists(self):
        assert '_pollFullEqState' in _REMOTE_EQUALISER_SCRIPT

    def test_poll_full_eq_state_fetches_poll_url(self):
        """_pollFullEqState must fetch __POLL_URL, not just the status endpoint."""
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('async function _pollFullEqState')
        fn_body = src[fn_idx:fn_idx + 400]
        assert '__POLL_URL' in fn_body

    def test_schedule_eq_poll_calls_poll_full_eq(self):
        """_scheduleEqPoll must schedule _pollFullEqState, not _pollTrimStatus."""
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('function _scheduleEqPoll')
        fn_body = src[fn_idx:fn_idx + 200]
        assert '_pollFullEqState' in fn_body
        assert '_pollTrimStatus' not in fn_body

    def test_schedule_eq_poll_no_longer_calls_trim_directly(self):
        """The old pattern of calling _pollTrimStatus inside the setTimeout must be gone."""
        src = _REMOTE_EQUALISER_SCRIPT
        # In the old code, _pollTrimStatus was called inside _scheduleEqPoll's timer
        fn_idx = src.index('function _scheduleEqPoll')
        fn_body = src[fn_idx:fn_idx + 250]
        assert '_pollTrimStatus' not in fn_body

    def test_poll_full_eq_applies_state(self):
        """_pollFullEqState must call renderEqFromState on success."""
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('async function _pollFullEqState')
        fn_body = src[fn_idx:fn_idx + 700]
        assert 'renderEqFromState' in fn_body

    def test_poll_full_eq_reschedules(self):
        """_pollFullEqState must call _scheduleEqPoll to reschedule."""
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('async function _pollFullEqState')
        fn_body = src[fn_idx:fn_idx + 600]
        assert '_scheduleEqPoll()' in fn_body


# ---------------------------------------------------------------------------
# Remote Equaliser — renderEqFromState update path
# ---------------------------------------------------------------------------

@_skip
class TestRemoteEqualiserRenderUpdate:
    def test_update_path_for_existing_band_sliders(self):
        """renderEqFromState must have an else branch that updates existing sliders."""
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('function renderEqFromState(')
        fn_body = src[fn_idx:fn_idx + 1500]
        # The create-path has the !bandContainer.querySelector guard;
        # the update path must follow as an else block
        assert '}else if(bandContainer){' in fn_body or '} else if(bandContainer){' in fn_body

    def test_update_path_skips_focused_slider(self):
        """Update path must not clobber sliders that are focused/being dragged."""
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('function renderEqFromState(')
        fn_body = src[fn_idx:fn_idx + 1500]
        assert 'document.activeElement' in fn_body

    def test_update_path_skips_pending_fields(self):
        """Update path must skip fields with in-flight saves."""
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('function renderEqFromState(')
        fn_body = src[fn_idx:fn_idx + 1500]
        assert '_eqPendingFields' in fn_body

    def test_update_path_updates_gain(self):
        """Update path for gain section must handle output_gain_db."""
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('function renderEqFromState(')
        fn_end = src.index('async function _loadInitialEqState')
        fn_body = src[fn_idx:fn_end]
        assert '}else if(gainSection){' in fn_body or '} else if(gainSection){' in fn_body

    def test_update_path_updates_auto_trim_checkbox(self):
        """Update path must update the auto_trim checkbox when not pending."""
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('function renderEqFromState(')
        fn_end = src.index('async function _loadInitialEqState')
        fn_body = src[fn_idx:fn_end]
        # auto_trim_enabled must appear in the update (else) block
        else_gain_marker = '}else if(gainSection){' if '}else if(gainSection){' in fn_body else '} else if(gainSection){'
        gain_else_idx = fn_body.index(else_gain_marker)
        after_else = fn_body[gain_else_idx:]
        assert 'auto_trim_enabled' in after_else

    def test_trim_status_updated_from_full_response(self):
        """output_auto_trim_db in full response must update trim status display."""
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('function renderEqFromState(')
        fn_end = src.index('async function _loadInitialEqState')
        fn_body = src[fn_idx:fn_end]
        assert 'output_auto_trim_db' in fn_body

    def test_eq_curve_redrawn_after_update(self):
        """_drawEqCurve must be called after updating sliders."""
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('function renderEqFromState(')
        fn_end = src.index('async function _loadInitialEqState')
        fn_body = src[fn_idx:fn_end]
        assert '_drawEqCurve' in fn_body

    def test_auto_trim_off_hides_and_clears_status(self):
        """When remote auto_trim_enabled is false, update path must hide+clear the status element."""
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('function renderEqFromState(')
        fn_end = src.index('async function _loadInitialEqState')
        fn_body = src[fn_idx:fn_end]
        else_gain_marker = '}else if(gainSection){' if '}else if(gainSection){' in fn_body else '} else if(gainSection){'
        gain_else_idx = fn_body.index(else_gain_marker)
        after_else = fn_body[gain_else_idx:]
        # Must hide the trim status element when auto_trim is false
        assert 'output_trim_status' in after_else
        assert "style.display='none'" in after_else or "style.display = 'none'" in after_else


# ---------------------------------------------------------------------------
# Remote Equaliser — pending-field guard (_eqPendingFields)
# ---------------------------------------------------------------------------

@_skip
class TestRemoteEqualiserPendingFields:
    def test_pending_fields_declared(self):
        assert '_eqPendingFields=new Set()' in _REMOTE_EQUALISER_SCRIPT

    def test_save_adds_field_to_pending(self):
        """_saveEqField must add the field to _eqPendingFields before fetching."""
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('function _saveEqField(')
        fn_body = src[fn_idx:fn_idx + 600]
        add_pos = fn_body.index('_eqPendingFields.add(field)')
        fetch_pos = fn_body.index('fetch(window.__SAVE_URL')
        assert add_pos < fetch_pos, "_eqPendingFields.add must precede the fetch call"

    def test_save_clears_field_on_success(self):
        """_saveEqField must delete the field from _eqPendingFields on success."""
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('function _saveEqField(')
        fn_body = src[fn_idx:fn_idx + 700]
        assert '_eqPendingFields.delete(field)' in fn_body

    def test_save_clears_field_on_error(self):
        """_saveEqField must delete field from _eqPendingFields in catch block too."""
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('function _saveEqField(')
        fn_end = src.index('\nfunction syncOutputGain')
        fn_body = src[fn_idx:fn_end]
        # Must appear in both then callback and catch block
        assert fn_body.count('_eqPendingFields.delete(field)') >= 2

    def test_save_only_clears_matching_seq(self):
        """_eqPendingFields.delete must only run when seq matches (stale responses ignored)."""
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('function _saveEqField(')
        fn_end = src.index('\nfunction syncOutputGain')
        fn_body = src[fn_idx:fn_end]
        # The seq guard must come before delete
        seq_check_pos = fn_body.index('if(_eqWriteSeq[field]!==seq)return')
        delete_pos = fn_body.index('_eqPendingFields.delete(field)')
        assert seq_check_pos < delete_pos


# ---------------------------------------------------------------------------
# Remote Equaliser — visibility resume
# ---------------------------------------------------------------------------

@_skip
class TestRemoteEqualiserVisibilityResume:
    def test_visibility_resume_calls_poll_full_eq_state(self):
        """visibilitychange resume must call _pollFullEqState for immediate refresh."""
        src = _REMOTE_EQUALISER_SCRIPT
        vis_idx = src.index('visibilitychange')
        vis_body = src[vis_idx:vis_idx + 300]
        assert '_pollFullEqState()' in vis_body

    def test_visibility_resume_enables_polling_flag(self):
        src = _REMOTE_EQUALISER_SCRIPT
        vis_idx = src.index('visibilitychange')
        vis_body = src[vis_idx:vis_idx + 300]
        assert '_eqPolling=true' in vis_body

    def test_visibility_hide_disables_polling_flag(self):
        src = _REMOTE_EQUALISER_SCRIPT
        vis_idx = src.index('visibilitychange')
        vis_body = src[vis_idx:vis_idx + 300]
        assert '_eqPolling=false' in vis_body

    def test_visibility_resume_resets_fail_count(self):
        src = _REMOTE_EQUALISER_SCRIPT
        vis_idx = src.index('visibilitychange')
        vis_body = src[vis_idx:vis_idx + 300]
        assert '_eqDegraded=false' in vis_body


# ---------------------------------------------------------------------------
# Remote Equaliser — degraded polling mode
# ---------------------------------------------------------------------------

@_skip
class TestRemoteEqualiserDegradedMode:
    def test_degraded_vars_declared(self):
        assert '_EQ_DEGRADED_POLL_MS=10000' in _REMOTE_EQUALISER_SCRIPT
        assert '_eqDegraded=false' in _REMOTE_EQUALISER_SCRIPT

    def test_schedule_eq_poll_uses_degraded_var(self):
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('function _scheduleEqPoll')
        fn_body = src[fn_idx:fn_idx + 200]
        assert '_EQ_DEGRADED_POLL_MS' in fn_body
        assert '_eqDegraded' in fn_body

    def test_poll_full_eq_sets_degraded_on_transport_failure(self):
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('async function _pollFullEqState')
        fn_body = src[fn_idx:fn_idx + 700]
        assert '_eqDegraded=true' in fn_body

    def test_poll_full_eq_clears_degraded_on_success(self):
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('async function _pollFullEqState')
        fn_body = src[fn_idx:fn_idx + 700]
        assert '_eqDegraded=false' in fn_body

    def test_poll_full_eq_no_redirect_on_transport(self):
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('async function _pollFullEqState')
        fn_body = src[fn_idx:fn_idx + 700]
        assert '_eqRedirectWithFlash' not in fn_body

    def test_poll_trim_status_no_redirect_in_catch(self):
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('function _pollTrimStatus')
        fn_body = src[fn_idx:fn_idx + 500]
        assert '_eqRedirectWithFlash' not in fn_body

    def test_save_eq_field_no_redirect_in_catch(self):
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('function _saveEqField')
        fn_end = src.index('function syncOutputGain')
        fn_body = src[fn_idx:fn_end]
        # The catch block must not redirect; only _eqDegraded=true
        catch_idx = fn_body.rfind('.catch(')
        catch_body = fn_body[catch_idx:]
        assert '_eqRedirectWithFlash' not in catch_body
        assert '_eqDegraded=true' in catch_body

    def test_visibility_resume_resets_degraded(self):
        src = _REMOTE_EQUALISER_SCRIPT
        vis_idx = src.index('visibilitychange')
        vis_body = src[vis_idx:vis_idx + 300]
        assert '_eqDegraded=false' in vis_body


# ---------------------------------------------------------------------------
# Remote Equaliser — initial-load retry
# ---------------------------------------------------------------------------

@_skip
class TestRemoteEqualiserInitialLoadRetry:
    def _load_fn(self):
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('async function _loadInitialEqState')
        fn_end = src.index('function initApplianceSelector')
        return src[fn_idx:fn_end]

    def test_initial_load_fn_exists(self):
        assert 'async function _loadInitialEqState' in _REMOTE_EQUALISER_SCRIPT

    def test_constants_declared(self):
        assert '_EQ_INITIAL_RETRY_DELAYS_MS' in _REMOTE_EQUALISER_SCRIPT
        assert '_EQ_NORMAL_POLL_MS' in _REMOTE_EQUALISER_SCRIPT

    def test_sleep_helper_declared(self):
        assert 'function _sleep(' in _REMOTE_EQUALISER_SCRIPT

    def test_retry_loop_uses_delays_constant(self):
        fn = self._load_fn()
        assert '_EQ_INITIAL_RETRY_DELAYS_MS' in fn

    def test_definitive_errors_still_redirect(self):
        fn = self._load_fn()
        assert '__EQ_DEFINITIVE_ERRORS' in fn
        assert '_eqHandleError' in fn

    def test_stale_data_accepted_via_ok_path(self):
        """Gateway stale responses have ok:true; _loadInitialEqState must render them."""
        fn = self._load_fn()
        # Stale responses have ok:true so they're caught by the data.ok branch
        assert 'data&&data.ok' in fn or 'data.ok' in fn
        assert 'renderEqFromState' in fn

    def test_on_exhaustion_schedules_poll_not_redirect(self):
        fn = self._load_fn()
        assert '_scheduleEqPoll()' in fn

    def test_success_path_calls_render_and_schedules_poll(self):
        fn = self._load_fn()
        assert 'renderEqFromState' in fn
        assert '_scheduleEqPoll()' in fn

    def test_retry_after_honored_without_double_sleep(self):
        """retry_after must replace the scheduled delay, not add to it (no continue)."""
        fn = self._load_fn()
        assert 'retry_after' in fn
        # The old double-sleep pattern used `continue` to re-run the top-of-loop sleep
        assert 'continue' not in fn

    def test_schedule_eq_poll_uses_normal_poll_ms(self):
        src = _REMOTE_EQUALISER_SCRIPT
        fn_idx = src.index('function _scheduleEqPoll')
        fn_body = src[fn_idx:fn_idx + 200]
        assert '_EQ_NORMAL_POLL_MS' in fn_body


# ---------------------------------------------------------------------------
# Local Equaliser — full-state polling
# ---------------------------------------------------------------------------

@_skip
class TestLocalEqualiserFullPolling:
    def test_poll_full_eq_state_function_exists(self):
        """_EQUALISER_JS must define _pollFullEqState."""
        assert '_pollFullEqState' in _EQUALISER_JS

    def test_poll_full_eq_state_fetches_poll_url(self):
        """_pollFullEqState must fetch window.__POLL_URL, not just the status endpoint."""
        src = _EQUALISER_JS
        fn_idx = src.index('async function _pollFullEqState')
        fn_body = src[fn_idx:fn_idx + 400]
        assert '__POLL_URL' in fn_body
        assert '/api/output_eq/status' not in fn_body

    def test_schedule_eq_poll_calls_poll_full_eq(self):
        """_scheduleEqPoll must schedule _pollFullEqState."""
        src = _EQUALISER_JS
        fn_idx = src.index('function _scheduleEqPoll')
        fn_body = src[fn_idx:fn_idx + 200]
        assert '_pollFullEqState' in fn_body

    def test_poll_full_eq_applies_state(self):
        """_pollFullEqState must call _updateEqFromPoll on success."""
        src = _EQUALISER_JS
        fn_idx = src.index('async function _pollFullEqState')
        fn_body = src[fn_idx:fn_idx + 400]
        assert '_updateEqFromPoll' in fn_body

    def test_poll_full_eq_reschedules(self):
        """_pollFullEqState must call _scheduleEqPoll to reschedule."""
        src = _EQUALISER_JS
        fn_idx = src.index('async function _pollFullEqState')
        fn_body = src[fn_idx:fn_idx + 400]
        assert '_scheduleEqPoll()' in fn_body

    def test_domcontentloaded_starts_full_poll(self):
        """DOMContentLoaded must call _pollFullEqState, not setInterval(_pollTrimStatus)."""
        src = _EQUALISER_JS
        dl_idx = src.index('DOMContentLoaded')
        dl_body = src[dl_idx:dl_idx + 400]
        assert '_pollFullEqState' in dl_body
        assert 'setInterval(_pollTrimStatus' not in dl_body

    def test_no_trim_status_interval(self):
        """_EQUALISER_JS must not contain a periodic trim-status-only poll."""
        assert 'setInterval(_pollTrimStatus' not in _EQUALISER_JS

    def test_visibility_resume_calls_poll_full_eq_state(self):
        """visibilitychange resume must call _pollFullEqState for immediate refresh."""
        src = _EQUALISER_JS
        vis_idx = src.index('visibilitychange')
        vis_body = src[vis_idx:vis_idx + 300]
        assert '_pollFullEqState()' in vis_body


# ---------------------------------------------------------------------------
# Local Equaliser — _updateEqFromPoll update path
# ---------------------------------------------------------------------------

@_skip
class TestLocalEqualiserUpdateFromPoll:
    def _fn_body(self) -> str:
        src = _EQUALISER_JS
        fn_idx = src.index('function _updateEqFromPoll(')
        fn_end = src.index('document.addEventListener(', fn_idx)
        return src[fn_idx:fn_end]

    def test_update_skips_focused_slider(self):
        """_updateEqFromPoll must not clobber band sliders that are focused."""
        fn_body = self._fn_body()
        assert 'document.activeElement' in fn_body

    def test_update_skips_pending_fields(self):
        """_updateEqFromPoll must skip fields with in-flight saves."""
        fn_body = self._fn_body()
        assert '_eqPendingFields' in fn_body

    def test_update_refreshes_band_sliders(self):
        """_updateEqFromPoll must iterate _EQ_BAND_KEYS and update sliders."""
        fn_body = self._fn_body()
        assert '_EQ_BAND_KEYS' in fn_body

    def test_update_refreshes_gain(self):
        """_updateEqFromPoll must update output_gain_db when not pending and not focused."""
        fn_body = self._fn_body()
        assert 'output_gain_db' in fn_body
        assert 'gain_db' in fn_body

    def test_update_refreshes_auto_trim_checkbox(self):
        """_updateEqFromPoll must update the auto_trim checkbox when not pending."""
        fn_body = self._fn_body()
        assert 'auto_trim_enabled' in fn_body
        assert 'output_auto_trim' in fn_body

    def test_trim_status_updated_from_full_response(self):
        """output_auto_trim_db in full response must update trim status display."""
        fn_body = self._fn_body()
        assert 'output_auto_trim_db' in fn_body

    def test_eq_curve_redrawn_after_update(self):
        """_drawEqCurve must be called after applying the poll response."""
        fn_body = self._fn_body()
        assert '_drawEqCurve' in fn_body


# ---------------------------------------------------------------------------
# Local Equaliser — pending-field guard (_eqPendingFields)
# ---------------------------------------------------------------------------

@_skip
class TestLocalEqualiserPendingFields:
    def _save_fn(self) -> str:
        src = _EQUALISER_JS
        fn_idx = src.index('function _saveEqField(')
        fn_end = src.index('\nfunction syncOutputGain')
        return src[fn_idx:fn_end]

    def test_pending_fields_declared(self):
        assert '_eqPendingFields = new Set()' in _EQUALISER_JS

    def test_write_seq_declared(self):
        assert '_eqWriteSeq = {}' in _EQUALISER_JS

    def test_save_adds_field_to_pending(self):
        """_saveEqField must add the field to _eqPendingFields before fetching."""
        fn_body = self._save_fn()
        add_pos = fn_body.index('_eqPendingFields.add(field)')
        fetch_pos = fn_body.index("fetch('/api/output_eq/config'")
        assert add_pos < fetch_pos

    def test_save_increments_seq_before_fetch(self):
        """_saveEqField must increment the per-field sequence counter before fetching."""
        fn_body = self._save_fn()
        seq_pos = fn_body.index('var seq = ++_eqWriteSeq[field]')
        fetch_pos = fn_body.index("fetch('/api/output_eq/config'")
        assert seq_pos < fetch_pos

    def test_save_clears_field_on_success(self):
        """_saveEqField must delete field from _eqPendingFields on success."""
        fn_body = self._save_fn()
        assert '_eqPendingFields.delete(field)' in fn_body

    def test_save_checks_seq_before_clearing_on_success(self):
        """_saveEqField must guard delete with seq check so stale saves don't clear pending."""
        fn_body = self._save_fn()
        seq_check_pos = fn_body.index('if (_eqWriteSeq[field] !== seq) return;')
        delete_pos = fn_body.index('_eqPendingFields.delete(field)')
        assert seq_check_pos < delete_pos

    def test_save_clears_field_on_error(self):
        """_saveEqField must delete field from _eqPendingFields in catch block too."""
        fn_body = self._save_fn()
        assert fn_body.count('_eqPendingFields.delete(field)') >= 2

    def test_save_checks_seq_in_catch(self):
        """catch block must also guard delete with seq check."""
        fn_body = self._save_fn()
        catch_idx = fn_body.index('.catch(function(')
        catch_body = fn_body[catch_idx:]
        assert 'if (_eqWriteSeq[field] !== seq) return;' in catch_body
