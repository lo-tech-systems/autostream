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


def _entry(severity: str, title: str, message: str, kind: str = "psu") -> WarningEntry:
    return WarningEntry(id=kind, incident="", severity=severity, kind=kind, subject="", title=title,
                        message=message, link=None, snooze="none")


def _banner(*entries: WarningEntry, **kw) -> tuple[str, str]:
    snap = type("Snap", (), {"warnings": WarningsPart(entries=tuple(entries))})()
    store = type("Store", (), {"snapshot": lambda self: snap})()
    with patch("webui.common.store", return_value=store):
        return common.build_top_banner_html(**kw)


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

    def test_a_flash_message_still_takes_the_slot(self):
        banner, _ = _banner(_entry("critical", "A", "a"), flash_msg="Saved")
        assert "green-banner" in banner and "red-banner" not in banner


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
