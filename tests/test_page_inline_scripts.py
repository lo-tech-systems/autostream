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
    "equaliser": 0,
    "remote_equaliser": 1,
    "about": 0,
    "align": 1,
    "service": 0,
    "logs": 0,
    "owntone": 1,
    "owntone_restarting": 0,
    "rebooting": 1,
    "first_boot_owntone": 0,
    "first_boot_appliance": 0,
    "hostname_changed": 0,
    "auth": 0,
}
SETUP_INLINE = 12

# Pages whose scripts are all files: nothing inline but the token bootstrap.
EXTRACTED = (
    "home", "remote_home", "equaliser", "remote_equaliser", "about", "align", "service", "logs",
    "owntone", "owntone_restarting", "rebooting", "first_boot_owntone", "first_boot_appliance",
    "hostname_changed", "auth",
)

_BOOTSTRAP = "window.__CSRF='t';"
# The local equaliser reads its token from a hidden field, so it carries no inline script.
EXPECTED_INLINE = {
    "home": [_BOOTSTRAP],
    "remote_home": [_BOOTSTRAP],
    "equaliser": [],
    "remote_equaliser": [_BOOTSTRAP],
    "about": [],
    "align": [_BOOTSTRAP],
    "service": [],
    "logs": [],
    "owntone": [_BOOTSTRAP],
    "owntone_restarting": [],
    "rebooting": [_BOOTSTRAP],
    "first_boot_owntone": [],
    "first_boot_appliance": [],
    "hostname_changed": [],
    "auth": [],
}
# The page's own scripts; the island must come before the first of them.
FIRST_FILES = {
    "home": ("home_cards.js",),
    "remote_home": ("home_cards.js",),
    "equaliser": ("equaliser_curve.js", "equaliser.js"),
    "remote_equaliser": ("remote_equaliser.js", "equaliser_curve.js"),
    "about": ("about.js",),
    "logs": ("logs.js",),
    "owntone": ("owntone.js",),
    "owntone_restarting": ("owntone_restarting.js",),
    "rebooting": ("rebooting.js",),
    "hostname_changed": ("hostname_changed.js",),
    "auth": ("auth.js",),
}

# Island keys each extracted page may carry, and the route that serves it.
_HOME_KEYS = {
    "preset_volume", "show_input_detail", "vu_delay_ms", "icons", "local_id",
    "selector_current_id", "output_url", "repeat_url", "outputs_empty_tolerance_ms",
    "pin_prompt_fallback", "control_other_appliances",
}
_EQ_KEYS = {"local_id", "selector_current_page", "poll_url", "eq_bands", "eq_fs", "curve"}
ISLAND_KEYS = {
    "home": _HOME_KEYS,
    "remote_home": _HOME_KEYS | {"remote_aid", "remote_hostname", "poll_url"},
    "equaliser": _EQ_KEYS,
    "remote_equaliser": _EQ_KEYS | {"save_url", "reset_url", "status_url", "remote_aid", "remote_hostname"},
    "about": {"license_text"},
    "align": set(),
    "service": set(),
    "logs": {"csrf_token"},
    "owntone": {"live_enabled"},
    "owntone_restarting": {"next_path"},
    "rebooting": {"min_wait_ms"},
    "first_boot_owntone": set(),
    "first_boot_appliance": set(),
    "hostname_changed": {"redirect_url"},
    "auth": set(),
}
PAGE_PATH = {
    "home": "/",
    "remote_home": "/a/" + _page_stub.REMOTE_APPLIANCE_ID + "/",
    "equaliser": "/equaliser",
    "remote_equaliser": "/a/" + _page_stub.REMOTE_APPLIANCE_ID + "/equaliser",
    "about": "/about",
    "align": "/align",
    "service": "/service",
    "logs": "/logs",
    "owntone": "/owntone-setup",
    "owntone_restarting": "/owntone-restarting",
    "rebooting": "/rebooting",
    "first_boot_owntone": "/first-boot/owntone",
    "first_boot_appliance": "/first-boot/appliance",
    # Served as the reply to a hostname change, not at a path of its own.
    "hostname_changed": None,
    "auth": "/auth",
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
    assert len(_inline_scripts(_render("setup"))) <= SETUP_INLINE


@pytest.mark.parametrize("page", EXTRACTED)
def test_an_extracted_page_carries_nothing_inline_but_its_token(page):
    assert _inline_scripts(_render(page)) == EXPECTED_INLINE[page]


@pytest.mark.parametrize("page", EXTRACTED)
def test_the_island_comes_before_the_first_page_script(page):
    html = _render(page)
    if not ISLAND_KEYS[page]:
        assert 'id="page-data"' not in html
        return
    island = html.index('id="page-data"')
    first = min(html.index(f"/static/page/{name}") for name in FIRST_FILES[page])
    assert island < first
    assert html.count('id="page-data"') == 1


@pytest.mark.parametrize("page", EXTRACTED)
def test_the_island_carries_only_the_keys_of_its_page(page):
    island = _source_text.page_data(_render(page))
    assert set(island) == ISLAND_KEYS[page]


@pytest.mark.parametrize("page", EXTRACTED)
def test_an_island_on_a_public_route_carries_only_listed_keys(page):
    import autostream_webui_routes as routes  # noqa: PLC0415
    if PAGE_PATH[page] is None:
        pytest.skip("not served at a path of its own")
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


@pytest.mark.parametrize("page", ("equaliser", "remote_equaliser"))
def test_the_equaliser_island_holds_the_curve_geometry_and_the_bands(page):
    import autostream_webui_page_equaliser as eq  # noqa: PLC0415
    from autostream_eq_bands import OUTPUT_PEQ_BANDS  # noqa: PLC0415
    island = _source_text.page_data(_render(page))
    assert island["curve"] == {
        "w": eq._CURVE_W, "h": eq._CURVE_H, "f_min": eq._CURVE_F_MIN, "f_max": eq._CURVE_F_MAX,
        "db_range": eq._CURVE_DB_RANGE, "pad_y": eq._CURVE_PAD_Y, "n_pts": eq._CURVE_N_PTS}
    assert [b["key"] for b in island["eq_bands"]] == [b["key"] for b in OUTPUT_PEQ_BANDS]
    assert all(set(b) == {"key", "type", "freq_hz", "q", "label"} for b in island["eq_bands"])
    assert isinstance(island["eq_fs"], int) and island["eq_fs"] > 0
    assert island["selector_current_page"] == "equaliser"


def test_the_about_island_carries_the_licence_text_and_cannot_end_its_element():
    text = "Terms </script><script>alert(1)</script> & <!-- more"
    html = _page_stub.render("about", license_text=text).decode("utf-8")
    assert _source_text.page_data(html) == {"license_text": text}
    assert html.count("</script>") == html.count("<script")
    assert "alert(1)" not in _source_text.page_scripts(html)


def test_the_logs_island_carries_the_page_token():
    assert _source_text.page_data(_render("logs")) == {"csrf_token": "t"}


@pytest.mark.parametrize("page", ("owntone", "owntone_restarting", "rebooting"))
def test_the_pages_with_a_live_flag_or_a_redirect_target_need_a_full_sign_in(page):
    import autostream_webui_routes as routes  # noqa: PLC0415
    route = routes._resolve(PAGE_PATH[page], "GET")
    assert route.auth is routes.AuthRequirement.FULL


def test_the_restarting_island_carries_the_next_path_and_cannot_end_its_element():
    html = _page_stub.render("owntone_restarting", next_path="/x</script><b>&").decode("utf-8")
    assert _source_text.page_data(html) == {"next_path": "/x</script><b>&"}
    assert html.count("</script>") == html.count("<script")


def test_the_rebooting_island_carries_the_minimum_wait():
    assert _source_text.page_data(_render("rebooting")) == {"min_wait_ms": 90000}


def test_the_hostname_changed_island_carries_the_redirect_url():
    island = _source_text.page_data(_render("hostname_changed"))
    assert island["redirect_url"].startswith("http://autostream.local")
