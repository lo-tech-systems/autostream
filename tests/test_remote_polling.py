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
    from autostream_webui_page_equaliser import _REMOTE_EQUALISER_SCRIPT
    _HAS_SCRIPTS = True
except ImportError:
    _HAS_SCRIPTS = False

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

    def test_empty_outputs_clears_existing_cards(self):
        """When outputs is empty, existing output cards must be removed from the DOM."""
        src = _REMOTE_HOME_SCRIPT
        render_fn_idx = src.index('function renderHomeState(')
        render_fn_end = src.index('\nvar __remoteFailCount', render_fn_idx)
        render_body = src[render_fn_idx:render_fn_end]
        # Find the empty-outputs branch and confirm it removes children
        empty_idx = render_body.index('outputs.length===0')
        empty_branch = render_body[empty_idx:empty_idx + 200]
        assert 'removeChild' in empty_branch or 'innerHTML' in empty_branch

    def test_empty_outputs_resets_last_shape(self):
        """When outputs is empty, __lastOutputsShape must be reset so the next non-empty poll re-renders."""
        src = _REMOTE_HOME_SCRIPT
        render_fn_idx = src.index('function renderHomeState(')
        render_fn_end = src.index('\nvar __remoteFailCount', render_fn_idx)
        render_body = src[render_fn_idx:render_fn_end]
        empty_idx = render_body.index('outputs.length===0')
        empty_branch = render_body[empty_idx:empty_idx + 200]
        assert "__lastOutputsShape=''" in empty_branch


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
        fn_body = src[fn_idx:fn_idx + 400]
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
        assert '_eqFailCount=0' in vis_body
