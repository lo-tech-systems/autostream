"""What the pages still carry inline, and what their data islands hold.

A page links its script and style files and carries one data island for the
values it computes; the only inline script left on an extracted page is the
bootstrap that hands the browser its CSRF token. This test keeps it that way
and checks the island of each extracted page against the route that serves it.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tests" / "playwright"))

import _page_stub  # noqa: E402
import _source_text  # noqa: E402

_INLINE = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.DOTALL | re.IGNORECASE)

# The most inline scripts each page may carry. A page may only come down.
MAX_INLINE = {
    "home": 1,
    "remote_home": 1,
    "equaliser": 2,
    "remote_equaliser": 4,
    "about": 2,
    "align": 2,
    "service": 1,
    "logs": 1,
    "owntone": 2,
    "owntone_restarting": 1,
    "rebooting": 2,
    "first_boot_owntone": 0,
    "first_boot_appliance": 0,
    "hostname_changed": 1,
    "auth": 1,
}
SETUP_INLINE = 12

# Pages whose scripts are all files: nothing inline but the token bootstrap.
EXTRACTED = ("home", "remote_home")

_BOOTSTRAP = "window.__CSRF='t';"

# Island keys each extracted page may carry, and the route that serves it.
_HOME_KEYS = {
    "preset_volume", "show_input_detail", "vu_delay_ms", "icons", "local_id",
    "selector_current_id", "output_url", "repeat_url", "outputs_empty_tolerance_ms",
    "pin_prompt_fallback", "control_other_appliances",
}
ISLAND_KEYS = {
    "home": _HOME_KEYS,
    "remote_home": _HOME_KEYS | {"remote_aid", "remote_hostname", "poll_url"},
}
PAGE_PATH = {
    "home": "/",
    "remote_home": "/a/" + _page_stub.REMOTE_APPLIANCE_ID + "/",
}


def _render(page: str) -> str:
    import autostream_state  # noqa: PLC0415
    autostream_state.store().reset_for_tests()
    return _page_stub.render(page).decode("utf-8")


def _inline_scripts(html: str) -> list[str]:
    out = []
    for attrs, body in _INLINE.findall(html):
        if re.search(r"\bsrc=", attrs, re.IGNORECASE):
            continue
        if re.search(r"""type=["']application/json["']""", attrs, re.IGNORECASE):
            continue
        out.append(body)
    return out


@pytest.mark.parametrize("page", sorted(MAX_INLINE))
def test_a_page_carries_no_more_inline_scripts_than_its_limit(page):
    count = len(_inline_scripts(_render(page)))
    assert count <= MAX_INLINE[page], (
        f"{page} carries {count} inline scripts; the limit is {MAX_INLINE[page]}")


def test_setup_carries_no_more_inline_scripts_than_its_limit():
    html = (REPO_ROOT / "tests" / "golden" / "setup_page_full.html").read_text(encoding="utf-8")
    assert len(_inline_scripts(html)) <= SETUP_INLINE


@pytest.mark.parametrize("page", EXTRACTED)
def test_an_extracted_page_carries_only_the_token_bootstrap(page):
    assert _inline_scripts(_render(page)) == [_BOOTSTRAP]


@pytest.mark.parametrize("page", EXTRACTED)
def test_the_island_comes_before_the_first_page_script(page):
    html = _render(page)
    island = html.index('id="page-data"')
    first = html.index("/static/page/home_cards.js")
    assert island < first
    assert html.count('id="page-data"') == 1


@pytest.mark.parametrize("page", EXTRACTED)
def test_the_island_carries_only_the_keys_of_its_page(page):
    island = _source_text.page_data(_render(page))
    assert set(island) == ISLAND_KEYS[page]


@pytest.mark.parametrize("page", EXTRACTED)
def test_an_island_on_a_public_route_carries_only_listed_keys(page):
    import autostream_webui_routes as routes  # noqa: PLC0415
    route = routes._resolve(PAGE_PATH[page], "GET")
    assert route is not None
    if route.auth is routes.AuthRequirement.NONE:
        assert set(_source_text.page_data(_render(page))) <= ISLAND_KEYS[page]


def test_the_island_of_the_home_page_holds_the_values_the_old_globals_did():
    from autostream_webui_assets import (  # noqa: PLC0415
        ICON_BLUETOOTH, ICON_CD, ICON_LINE_LEVEL, ICON_TURNTABLE)
    island = _source_text.page_data(_render("home"))
    assert island["icons"] == {
        "turntable": ICON_TURNTABLE, "bluetooth": ICON_BLUETOOTH,
        "cd": ICON_CD, "line_level": ICON_LINE_LEVEL}
    assert island["output_url"] == "/api/output"
    assert island["repeat_url"] == "/api/repeat"
    assert island["outputs_empty_tolerance_ms"] == 6000
    assert island["pin_prompt_fallback"] == "Enter PIN shown on your device"
    assert island["selector_current_id"] == island["local_id"]
    assert isinstance(island["preset_volume"], int) and 0 <= island["preset_volume"] <= 100
    assert isinstance(island["vu_delay_ms"], int)
    assert isinstance(island["show_input_detail"], bool)
    assert isinstance(island["control_other_appliances"], bool)


def test_the_island_of_the_remote_home_page_points_at_the_remote_appliance():
    rid = _page_stub.REMOTE_APPLIANCE_ID
    island = _source_text.page_data(_render("remote_home"))
    assert island["remote_aid"] == rid
    assert island["selector_current_id"] == rid
    assert island["poll_url"] == f"/api/appliances/{rid}/home"
    assert island["output_url"] == f"/api/appliances/{rid}/output"
    assert island["repeat_url"] == f"/api/appliances/{rid}/repeat"
    assert island["show_input_detail"] is False
    assert island["vu_delay_ms"] == 2250
    assert island["outputs_empty_tolerance_ms"] == 6000


def test_an_island_value_cannot_end_its_script_element():
    from autostream_webui_static import page_data_island  # noqa: PLC0415
    text = page_data_island({"name": "</script><b>&"})
    assert text.count("</script>") == 1
    body = re.search(r">(\{.*\})</script>", text).group(1)
    assert json.loads(body) == {"name": "</script><b>&"}
