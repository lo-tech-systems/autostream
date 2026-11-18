"""The dial's "Update <appliance>" warning for an appliance on an older dial
protocol than its own: the pure rule, how the core holds and clears it, and
that the dial goes on working with the appliance."""
import logging
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

import pytest

import dial_capabilities
import dial_core_state as cs
from dial_auth import AUTH_AUTHORIZED, AUTH_UNAUTHORIZED, AUTH_UNKNOWN
from dial_core import DialCore
from dial_mdns import RosterEntry
from dial_warning_text import WARNING_DESCRIPTORS, appliance_warning_key
from dial_warnings import WarningManager, WarningStore

OWN = 3


def entry(name="Lounge", *, appliance_id="a" * 20, auth=AUTH_AUTHORIZED, proto=2):
    return RosterEntry(
        appliance_id=appliance_id, service_name=name, name=name, ip="192.0.2.10", port=80,
        playing=False, repeat_capable=False, dial_api=True, audio_status=True,
        dial_status=True, dial_outputs=False, dial_eq=False, auth=auth, dial_proto_version=proto,
    )


class TestProtocolWarning:
    def test_an_older_authorised_appliance_gets_the_warning(self):
        warning = cs.protocol_warning(entry(proto=2), OWN)
        assert warning.id == cs.PROTOCOL_WARNING_ID == "update_appliance"
        assert warning.severity == "warning" and warning.dismissal == "week"
        assert warning.title == "Update Lounge"
        assert warning.message == "Its software is older than this dial's. Update it from its web UI."
        assert warning.appliance_name == "Lounge"

    @pytest.mark.parametrize("proto", [3, 4, 9])
    def test_the_same_or_a_newer_generation_gets_none(self, proto):
        assert cs.protocol_warning(entry(proto=proto), OWN) is None

    def test_an_appliance_advertising_no_generation_is_older_than_any(self):
        assert cs.protocol_warning(entry(proto=0), OWN) is not None

    @pytest.mark.parametrize("auth", [AUTH_UNAUTHORIZED, AUTH_UNKNOWN])
    def test_an_appliance_that_has_not_authorised_the_dial_gets_none(self, auth):
        assert cs.protocol_warning(entry(auth=auth), OWN) is None

    def test_an_appliance_with_no_identity_gets_none(self):
        assert cs.protocol_warning(entry(appliance_id=""), OWN) is None

    def test_a_long_name_is_fitted_to_the_title(self):
        warning = cs.protocol_warning(entry("x" * 60), OWN)
        assert len(warning.title) <= cs.APPLIANCE_WARNING_TITLE_MAX
        assert warning.title.startswith("Update xxx")

    def test_a_name_from_the_network_is_cleaned(self):
        warning = cs.protocol_warning(entry("Lo‮unge\x07"), OWN)
        assert "‮" not in warning.title and "\x07" not in warning.title


class Rig:
    def __init__(self):
        self.roster = [entry()]
        self.manager = WarningManager(WARNING_DESCRIPTORS, WarningStore(None))
        self.core = DialCore(
            "dial-1", lambda: [], lambda: self.roster, warnings=self.manager,
            update_seen_path="/nonexistent/seen",
        )
        self.core.set_roster(self.roster)
        self.key = appliance_warning_key("a" * 20, cs.PROTOCOL_WARNING_ID)

    def housekeep(self, roster=None):
        if roster is not None:
            self.roster = roster
            self.core.set_roster(roster)
        self.core._housekeeping(1.0)

    def held(self):
        return self.core.snapshot().appliance("a" * 20).warnings


class TestCore:
    def test_the_warning_is_raised_once_over_several_ticks(self):
        rig = Rig()
        rig.housekeep()
        seq = rig.core.snapshot().seq
        assert [w.id for w in rig.held()] == [cs.PROTOCOL_WARNING_ID]
        assert any(s.id == rig.key and s.active for s in rig.core.snapshot().warnings)
        rig.housekeep()
        rig.housekeep()
        assert rig.core.snapshot().seq == seq
        assert len(rig.held()) == 1

    def test_it_survives_an_empty_warnings_reply_and_the_clear_for_no_warnings(self):
        rig = Rig()
        rig.housekeep()
        rig.core.set_appliance_warnings("a" * 20, ())
        assert [w.id for w in rig.held()] == [cs.PROTOCOL_WARNING_ID]
        rig.housekeep()
        assert [w.id for w in rig.held()] == [cs.PROTOCOL_WARNING_ID]

    def test_it_comes_after_the_warnings_the_appliance_supplies(self):
        rig = Rig()
        rig.housekeep()
        own = cs.ApplianceWarning("stylus", "info", "Stylus", "Soon.", "day")
        rig.core.set_appliance_warnings("a" * 20, (own,))
        assert [w.id for w in rig.held()] == ["stylus", cs.PROTOCOL_WARNING_ID]
        rig.core.set_appliance_warnings("a" * 20, ())
        assert [w.id for w in rig.held()] == [cs.PROTOCOL_WARNING_ID]

    @pytest.mark.parametrize("change", ["updated", "refused", "gone"])
    def test_it_clears_when_the_appliance_is_updated_refuses_or_leaves(self, change):
        rig = Rig()
        rig.housekeep()
        assert rig.held()
        new = {
            "updated": [entry(proto=3)],
            "refused": [entry(auth=AUTH_UNAUTHORIZED)],
            "gone": [],
        }[change]
        rig.housekeep(new)
        assert not any(s.id == rig.key for s in rig.core.snapshot().warnings)
        assert rig.core.snapshot().appliance("a" * 20) is None or rig.held() == ()

    def test_it_returns_if_the_appliance_goes_back(self):
        rig = Rig()
        rig.housekeep()
        rig.housekeep([entry(proto=3)])
        rig.housekeep([entry(proto=2)])
        assert [w.id for w in rig.held()] == [cs.PROTOCOL_WARNING_ID]

    def test_the_dial_keeps_controlling_the_appliance(self):
        rig = Rig()
        rig.housekeep()
        assert rig.core.set_focus("a" * 20).accepted

    def test_one_info_line_per_raise_and_per_clear(self, caplog):
        rig = Rig()
        with caplog.at_level(logging.INFO):
            rig.housekeep()
            rig.housekeep()
            rig.housekeep([entry(proto=3)])
            rig.housekeep([entry(proto=3)])
        lines = [r.getMessage() for r in caplog.records if "dial protocol" in r.getMessage()
                 or "needs an update" in r.getMessage()]
        assert lines == [
            "dial core: Lounge runs an older dial protocol",
            "dial core: Lounge no longer needs an update",
        ]


def test_the_constant_matches_the_record_the_dial_advertises():
    text = (Path(__file__).parent.parent / "system" / "avahi" / "autostream-dial.service").read_text(
        encoding="utf-8")
    match = re.search(r"<txt-record>dial_proto=v(\d+)</txt-record>", text)
    assert match is not None
    assert dial_capabilities.DIAL_PROTO_GENERATION == int(match.group(1))
