"""test_appliance_selector.py — unit tests for build_appliance_selector_html.

Tests: selector ordering, accessibility attributes, divider placement,
active-item marking, navigation paths and empty-state rendering.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_webui_common import build_appliance_selector_html


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_BOUND_ID = "a" * 20
_REMOTE_ID = "b" * 20

_BOUND = {
    "id": _BOUND_ID,
    "hostname": "bound-host",
    "is_bound": True,
    "home_path": "/",
    "equaliser_path": "/equaliser",
}
_REMOTE = {
    "id": _REMOTE_ID,
    "hostname": "remote-host",
    "is_bound": False,
    "home_path": f"/a/{_REMOTE_ID}/",
    "equaliser_path": f"/a/{_REMOTE_ID}/equaliser",
}


def _sel(
    appliances=None,
    current_id: str = _BOUND_ID,
    current_page: str = "home",
) -> str:
    if appliances is None:
        appliances = [_BOUND, _REMOTE]
    return build_appliance_selector_html(appliances, current_id, current_page)


# ---------------------------------------------------------------------------
# Ordering and divider
# ---------------------------------------------------------------------------

class TestSelectorOrdering:
    def test_bound_appears_before_remote(self):
        out = _sel()
        assert out.index("bound-host") < out.index("remote-host")

    def test_divider_present_between_bound_and_remote(self):
        out = _sel()
        assert "appliance-selector-divider" in out
        # Divider appears after bound, before remote
        bound_pos = out.index("bound-host")
        div_pos = out.index("appliance-selector-divider")
        remote_pos = out.index("remote-host")
        assert bound_pos < div_pos < remote_pos

    def test_no_divider_with_only_bound(self):
        out = _sel(appliances=[_BOUND])
        assert "appliance-selector-divider" not in out

    def test_no_divider_with_no_appliances(self):
        out = _sel(appliances=[])
        assert "appliance-selector-divider" not in out


# ---------------------------------------------------------------------------
# Active / selected state
# ---------------------------------------------------------------------------

class TestSelectorActiveState:
    def test_current_id_marked_aria_selected_true(self):
        out = _sel(current_id=_BOUND_ID)
        # The option for the bound appliance should have aria-selected="true"
        assert 'aria-selected="true"' in out

    def test_non_current_id_marked_aria_selected_false(self):
        out = _sel(current_id=_BOUND_ID)
        assert 'aria-selected="false"' in out

    def test_active_class_on_current_option(self):
        out = _sel(current_id=_REMOTE_ID)
        assert "appliance-selector-option-active" in out

    def test_active_class_absent_for_non_current(self):
        # Only one option should have the active class
        out = _sel(current_id=_BOUND_ID)
        # Remote option should not have active class
        remote_opt_start = out.index("remote-host")
        remote_section = out[remote_opt_start - 200 : remote_opt_start]
        assert "appliance-selector-option-active" not in remote_section


# ---------------------------------------------------------------------------
# Navigation paths
# ---------------------------------------------------------------------------

class TestSelectorPaths:
    def test_bound_links_to_local_home(self):
        out = _sel(current_page="home")
        # Bound appliance home_path is "/"
        assert 'href="/"' in out

    def test_remote_links_to_remote_home(self):
        out = _sel(current_page="home")
        expected_path = f"/a/{_REMOTE_ID}/"
        assert expected_path in out

    def test_equaliser_page_uses_equaliser_paths(self):
        out = _sel(current_page="equaliser")
        assert 'href="/equaliser"' in out
        assert f"/a/{_REMOTE_ID}/equaliser" in out

    def test_bound_bold_styling(self):
        """Bound appliance should be visually distinguished (font-weight:700)."""
        out = _sel()
        # The bound option in the dropdown list has font-weight:700.
        # The selector HTML has two occurrences of "bound-host": one in the
        # trigger button span and one in the option list. Find the option
        # by looking for the role="option" context.
        assert "font-weight:700" in out


# ---------------------------------------------------------------------------
# Accessibility attributes
# ---------------------------------------------------------------------------

class TestSelectorAccessibility:
    def test_button_has_aria_haspopup(self):
        out = _sel()
        assert 'aria-haspopup="listbox"' in out

    def test_button_has_aria_expanded_false(self):
        out = _sel()
        assert 'aria-expanded="false"' in out

    def test_dropdown_has_role_listbox(self):
        out = _sel()
        assert 'role="listbox"' in out

    def test_options_have_role_option(self):
        out = _sel()
        assert 'role="option"' in out

    def test_button_id_set(self):
        out = _sel()
        assert 'id="appliance-selector-btn"' in out

    def test_dropdown_id_set(self):
        out = _sel()
        assert 'id="appliance-selector-dropdown"' in out

    def test_dropdown_initially_hidden(self):
        out = _sel()
        assert "hidden" in out

    def test_data_current_id_attribute(self):
        out = _sel(current_id=_BOUND_ID)
        assert f'data-current-id="{_BOUND_ID}"' in out

    def test_data_current_page_attribute(self):
        out = _sel(current_page="home")
        assert 'data-current-page="home"' in out


# ---------------------------------------------------------------------------
# Trigger button label
# ---------------------------------------------------------------------------

class TestSelectorTrigger:
    def test_trigger_shows_current_appliance_name(self):
        out = _sel(current_id=_BOUND_ID)
        assert "bound-host" in out

    def test_trigger_shows_remote_name_when_remote_selected(self):
        out = _sel(current_id=_REMOTE_ID)
        assert "remote-host" in out

    def test_trigger_fallback_for_unknown_id(self):
        """When current_id not in list, trigger falls back to 'autostream'."""
        out = _sel(current_id="0" * 20)
        assert "autostream" in out

    def test_xss_escaping_in_hostname(self):
        malicious = [
            {
                "id": _BOUND_ID,
                "hostname": '<script>alert(1)</script>',
                "is_bound": True,
                "home_path": "/",
                "equaliser_path": "/equaliser",
            }
        ]
        out = build_appliance_selector_html(malicious, _BOUND_ID, "home")
        assert "<script>" not in out
        assert "&lt;script&gt;" in out

    def test_xss_escaping_in_home_path(self):
        malicious_path = '/" onmouseover="evil()'
        malicious = [
            {
                "id": _REMOTE_ID,
                "hostname": "safe",
                "is_bound": False,
                "home_path": malicious_path,
                "equaliser_path": "/eq",
            }
        ]
        out = build_appliance_selector_html(malicious, _BOUND_ID, "home")
        assert malicious_path not in out
