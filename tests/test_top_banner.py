"""The red banner a page carries when it loads: the critical entries of the
warnings part, none, one or several, on every page that builds one."""
from __future__ import annotations

import html
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))

from autostream_state import WarningEntry, WarningsPart  # noqa: E402
from webui import common  # noqa: E402


def _entry(severity: str, title: str, message: str, kind: str = "psu", link=None) -> WarningEntry:
    return WarningEntry(id=kind, incident="", severity=severity, kind=kind, subject="", title=title,
                        message=message, link=link, snooze="none")


def _snap(*entries: WarningEntry):
    return type("Snap", (), {"warnings": WarningsPart(entries=tuple(entries))})()


def _banner(*entries: WarningEntry) -> tuple[str, str]:
    snap = _snap(*entries)
    store = type("Store", (), {"snapshot": lambda self: snap})()
    with patch("webui.common.store", return_value=store):
        return common.build_top_banner_html()


class TestTopBanner:
    def test_no_critical_entry_gives_no_banner(self):
        assert _banner() == ("", "")
        assert _banner(_entry("warning", "Temperature", "Hot"), _entry("info", "No input", "None")) == ("", "")

    def test_one_critical_entry_is_its_title_and_message(self):
        banner, spacer = _banner(_entry("critical", "Power supply", "Undervoltage detected"))
        assert banner == "<div id='red-banner'>Power supply: Undervoltage detected</div>"
        assert spacer == "<div id='red-banner-spacer'></div>"

    def test_several_criticals_read_the_first_and_a_count_of_the_rest(self):
        banner, _ = _banner(_entry("critical", "Power supply", "Undervoltage detected"),
                            _entry("critical", "Storage", "Failing", "sd_health"),
                            _entry("critical", "Memory", "Low", "memory"))
        assert banner == "<div id='red-banner'>Power supply: Undervoltage detected +2 more</div>"

    def test_a_warning_between_criticals_is_not_counted(self):
        banner, _ = _banner(_entry("critical", "A", "a"), _entry("warning", "B", "b"), _entry("critical", "C", "c"))
        assert banner == "<div id='red-banner'>A: a +1 more</div>"

    def test_text_is_escaped(self):
        banner, _ = _banner(_entry("critical", "<b>x</b>", "a & b"))
        assert html.escape("<b>x</b>: a & b") in banner

    def test_the_builder_takes_only_another_appliances_entries(self):
        import inspect
        assert list(inspect.signature(common.build_top_banner_html).parameters) == ["entries"]

    def test_entries_given_as_the_state_shows_them_are_read_instead_of_this_appliances(self):
        entries = [{"severity": "critical", "title": "Other", "message": "broken"},
                   {"severity": "warning", "title": "Minor", "message": "m"},
                   {"severity": "critical", "title": "Worse", "message": "w"}]
        banner, spacer = common.build_top_banner_html(entries=entries)
        assert banner == "<div id='red-banner'>Other: broken +1 more</div>"
        assert spacer == "<div id='red-banner-spacer'></div>"
        assert common.build_top_banner_html(entries=[]) == ("", "")


class TestEveryPageCarriesTheBanner:
    """Each page that builds the banner reads the same builder."""

    def test_the_builders_in_the_pages_are_the_shared_one(self):
        import importlib
        for name in ("about", "align", "equaliser", "first_boot", "home", "logs", "owntone", "rebooting",
                     "service"):
            module = importlib.import_module(f"webui.browser.{name}")
            assert module.build_top_banner_html is common.build_top_banner_html, name
        from webui.browser.setup import page
        assert page.build_top_banner_html is common.build_top_banner_html


class TestServiceMarker:
    """The Service tab is coloured by the worst warning that links to the Service page."""

    def test_no_warning_for_the_service_page_gives_none(self):
        assert common.service_severity(_snap()) is None
        assert common.service_severity(_snap(_entry("critical", "A", "a"), _entry("warning", "B", "b", link="/setup"))) is None

    def test_the_worst_severity_linking_to_service_wins(self):
        entries = (_entry("critical", "A", "a", link="/service"), _entry("warning", "B", "b", link="/service"))
        assert common.service_severity(_snap(*entries)) == "critical"
        assert common.service_severity(_snap(entries[1], _entry("info", "C", "c", link="/service"))) == "warning"

    def test_it_reads_the_store_when_given_no_snapshot(self):
        snap = _snap(_entry("info", "A", "a", link="/service"))
        store = type("Store", (), {"snapshot": lambda self: snap})()
        with patch("webui.common.store", return_value=store):
            assert common.service_severity() == "info"

    def test_the_tab_class_follows_the_severity(self):
        for severity in ("critical", "warning", "info"):
            nav = common.build_nav_bar_html("home", service_severity=severity)
            assert f'class="nav-tab nav-tab-warn-{severity}" id="service-nav-tab"' in nav
        assert "nav-tab-warn" not in common.build_nav_bar_html("home")

    def test_a_remote_appliances_nav_never_carries_the_marker(self):
        assert "nav-tab-warn" not in common.build_nav_bar_html("home", service_severity="critical", remote_id="a" * 20)

    def test_a_page_renders_the_class_at_load(self):
        page = common.build_page_html("t", "<p>x</p>", active_tab="home", service_severity="warning")
        assert "nav-tab-warn-warning" in page
