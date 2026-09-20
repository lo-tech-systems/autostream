"""tests/test_setup_sdcard_row.py

Unit tests for the two small formatting helpers behind the Setup page's
"SD card health monitoring" row: `_sdcard_health_status_line()` and
`_sdcard_health_card_line()`. Both take the merged state dict produced by
`autostream_sysutils.sdcard_health_state()` and never touch the network,
disk, or systemd -- so they're exercised directly here rather than through
a full page render.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_webui_page_setup as setup


class TestSdcardHealthStatusLine:
    def test_tool_absent(self):
        sd_health = {"tool_present": False, "timer_enabled": True, "check": "passed", "health_percent": 80}
        assert setup._sdcard_health_status_line(sd_health) == "Tool not installed"

    def test_timer_disabled_with_check_passed_and_percent(self):
        # Monitoring is off: a leftover "passed" check and percent from
        # before disabling must not surface as a current reading.
        sd_health = {
            "tool_present": True, "timer_enabled": False,
            "check": "passed", "health_percent": 80, "last_sampled_at": "2026-01-01T00:00:00Z",
        }
        assert setup._sdcard_health_status_line(sd_health) == "Not monitored"

    def test_timer_enabled_with_percent(self):
        sd_health = {
            "tool_present": True, "timer_enabled": True,
            "check": "passed", "health_percent": 80, "last_sampled_at": "2026-01-01T00:00:00Z",
        }
        line = setup._sdcard_health_status_line(sd_health)
        assert line.startswith("Monitored, 80 % ")

    def test_timer_enabled_without_a_passed_reading(self):
        sd_health = {"tool_present": True, "timer_enabled": True, "check": "none", "health_percent": None}
        assert setup._sdcard_health_status_line(sd_health) == "Not monitored"


class TestSdcardHealthCardLine:
    def test_with_likely_supported(self):
        sd_health = {"card": {"name": "SD64G", "manfid": 0x03, "likely_supported": True}}
        line = setup._sdcard_health_card_line(sd_health)
        assert line == "SD64G, manufacturer 0x03, likely supported"

    def test_without_likely_supported(self):
        sd_health = {"card": {"name": "SD64G", "manfid": 0x99, "likely_supported": False}}
        line = setup._sdcard_health_card_line(sd_health)
        assert line == "SD64G, manufacturer 0x99"

    def test_missing_card_identity(self):
        sd_health = {"card": {"name": "", "manfid": None, "likely_supported": False}}
        assert setup._sdcard_health_card_line(sd_health) == "support unknown"
