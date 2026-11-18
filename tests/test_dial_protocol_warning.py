"""The dial's warning for an appliance that speaks a different protocol number:
the pure rule (lower, higher, equal, absent), where the number is read from
(the hello when it has been read, else the record's `proto`), how the core
holds and clears it, and that the dial goes on working with the appliance."""
import logging
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
for _p in (str(REPO_ROOT / "dial"), str(REPO_ROOT / "core"), str(REPO_ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import dial_appliance_warnings as aw
import dial_mdns
from autostream_protocol import PROTOCOL
from dial_test_support import RosterEntry
from dial_pool_support import Rig, aid, peer
from dial_warning_text import appliance_warning_key

OWN = 4


def entry(name="Lounge", *, appliance_id="a" * 20, auth="authorized", proto=3):
    return RosterEntry(
        appliance_id=appliance_id, service_name=name, name=name, ip="192.0.2.10", port=80,
        playing=False, repeat_capable=False, dial_api=True, audio_status=True,
        dial_status=True, dial_outputs=False, dial_eq=False, auth=auth, dial_proto_version=proto,
    )


class TestProtocolWarning:
    def test_a_lower_number_gives_update_appliance(self):
        warning = aw.protocol_warning(entry(proto=3), OWN)
        assert warning.id == aw.PROTOCOL_WARNING_ID == "update_appliance"
        assert warning.severity == "warning"
        assert warning.title == "Update Lounge"
        assert warning.message == "Its software is older than this dial's. Update it from its web UI."
        assert warning.appliance_name == "Lounge"

    @pytest.mark.parametrize("proto", [5, 9])
    def test_a_higher_number_gives_no_appliance_warning(self, proto):
        assert aw.protocol_warning(entry(proto=proto), OWN) is None

    def test_the_newer_appliances_are_named_in_roster_order(self):
        roster = (
            entry("Lounge", appliance_id="a" * 20, proto=5),
            entry("Kitchen", appliance_id="b" * 20, proto=OWN),
            entry("Study", appliance_id="c" * 20, proto=2),
            entry("Patio", appliance_id="d" * 20, proto=9),
        )
        assert aw.newer_appliance_names(roster, OWN) == ("Lounge", "Patio")

    @pytest.mark.parametrize("proto", [0, None, True, OWN])
    def test_an_appliance_with_no_newer_number_is_not_named(self, proto):
        assert aw.newer_appliance_names((entry(proto=proto),), OWN) == ()

    def test_an_appliance_with_no_identity_is_not_named(self):
        assert aw.newer_appliance_names((entry(appliance_id="", proto=9),), OWN) == ()

    def test_the_same_number_gives_none(self):
        assert aw.protocol_warning(entry(proto=OWN), OWN) is None

    @pytest.mark.parametrize("proto", [0, None, True])
    def test_an_appliance_that_has_not_said_a_number_gets_none_yet(self, proto):
        assert aw.protocol_warning(entry(proto=proto), OWN) is None

    @pytest.mark.parametrize("auth", ["unauthorized", "unknown", "authorized"])
    def test_access_is_not_asked(self, auth):
        assert aw.protocol_warning(entry(auth=auth), OWN) is not None

    def test_an_appliance_with_no_identity_gets_none(self):
        assert aw.protocol_warning(entry(appliance_id=""), OWN) is None

    def test_a_long_name_is_fitted_to_the_title(self):
        warning = aw.protocol_warning(entry("x" * 60), OWN)
        assert len(warning.title) <= aw.APPLIANCE_WARNING_TITLE_MAX
        assert warning.title.startswith("Update xxx")

    def test_a_long_name_is_fitted_to_the_message_of_the_dial_warning(self):
        from dial_warning_text import WARNING_BY_ID
        names = aw.newer_appliance_names((entry("x" * 300, proto=5),), OWN)
        assert len(WARNING_BY_ID["update_dial"].message_for(names)) <= aw.APPLIANCE_WARNING_MESSAGE_MAX

    def test_a_name_from_the_network_is_cleaned(self):
        warning = aw.protocol_warning(entry("Lo‮unge\x07"), OWN)
        assert "‮" not in warning.title and "\x07" not in warning.title


class Pool:
    """A core over a fake pool holding one appliance, "Lounge"."""

    def __init__(self):
        self.rig = Rig()
        self.key = appliance_warning_key(aid("Lounge"), aw.PROTOCOL_WARNING_ID)

    def set(self, *, hello=None, record=PROTOCOL, access="unknown", seq=1):
        """The appliance as sighted (the record's number) and as its client
        reports it (the hello's number, None before one is read)."""
        snap = peer("Lounge", protocol=hello, protocol_ok=hello == PROTOCOL, access=access, seq=seq)
        if aid("Lounge") in self.rig.pool._clients:
            self.rig.remove("Lounge")
        self.rig.add("Lounge", snap, proto=record)
        self.rig.fold()
        self.rig.core._housekeeping(1.0)

    def remove(self):
        self.rig.remove("Lounge")
        self.rig.fold()
        self.rig.core._housekeeping(1.0)

    def held(self):
        a = self.rig.core.snapshot().appliance(aid("Lounge"))
        return () if a is None else a.warnings

    def dial_warning(self):
        """The reading of the dial's own warning, None when it is not active."""
        warnings = self.rig.core.warnings
        return warnings.reading(aw.DIAL_WARNING_ID) if warnings.is_active(aw.DIAL_WARNING_ID) else None

    def ids(self):
        return [w.id for w in self.held()]

    def close(self):
        self.rig.close()


@pytest.fixture
def pool():
    p = Pool()
    yield p
    p.close()


class TestCore:
    def test_a_lower_hello_raises_update_appliance(self, pool):
        pool.set(hello=3)
        assert pool.ids() == [aw.PROTOCOL_WARNING_ID]

    def test_a_higher_hello_raises_the_dials_own_warning_naming_the_appliance(self, pool):
        pool.set(hello=5)
        assert pool.ids() == []
        assert pool.dial_warning() == ("Lounge",)

    def test_an_equal_hello_raises_nothing(self, pool):
        pool.set(hello=PROTOCOL, access="playback")
        assert pool.ids() == []

    def test_the_record_is_read_until_the_hello_has_been(self, pool):
        pool.set(hello=None, record=3)
        assert pool.ids() == [aw.PROTOCOL_WARNING_ID]
        pool.set(hello=None, record=5)
        assert pool.ids() == [] and pool.dial_warning() == ("Lounge",)

    def test_the_hello_wins_over_the_record(self, pool):
        pool.set(hello=PROTOCOL, record=3, access="playback")
        assert pool.ids() == []

    def test_a_number_on_neither_gives_no_warning_yet(self, pool):
        pool.set(hello=None, record=None)
        assert pool.ids() == []

    def test_a_mismatched_appliance_with_unknown_access_is_still_warned(self, pool):
        pool.set(hello=3, access="unknown")
        assert pool.ids() == [aw.PROTOCOL_WARNING_ID]
        pool.set(hello=3, access="none", seq=2)
        assert pool.ids() == [aw.PROTOCOL_WARNING_ID]

    def test_it_is_registered_once_over_several_ticks(self, pool):
        pool.set(hello=3)
        seq = pool.rig.core.snapshot().seq
        assert any(s.id == pool.key and s.active for s in pool.rig.core.snapshot().warnings)
        pool.rig.core._housekeeping(2.0)
        pool.rig.core._housekeeping(3.0)
        assert pool.rig.core.snapshot().seq == seq
        assert len(pool.held()) == 1

    def test_it_clears_when_the_appliance_is_updated(self, pool):
        pool.set(hello=3)
        pool.set(hello=PROTOCOL, access="playback", seq=2)
        assert pool.ids() == []
        assert not any(s.id == pool.key for s in pool.rig.core.snapshot().warnings)

    def test_it_clears_when_the_appliance_leaves(self, pool):
        pool.set(hello=3)
        pool.remove()
        assert not any(s.id == pool.key for s in pool.rig.core.snapshot().warnings)

    def test_it_changes_with_the_direction(self, pool):
        pool.set(hello=3)
        pool.set(hello=5, seq=2)
        assert pool.ids() == [] and pool.dial_warning() == ("Lounge",)
        assert not any(s.id == pool.key for s in pool.rig.core.snapshot().warnings)
        pool.set(hello=PROTOCOL, access="playback", seq=3)
        assert pool.dial_warning() is None

    def test_the_dial_warning_clears_when_the_appliance_leaves(self, pool):
        pool.set(hello=5)
        pool.remove()
        assert pool.dial_warning() is None

    def test_one_info_line_per_raise_and_per_clear(self, pool, caplog):
        with caplog.at_level(logging.INFO):
            pool.set(hello=3)
            pool.rig.core._housekeeping(2.0)
            pool.set(hello=PROTOCOL, access="playback", seq=2)
            pool.rig.core._housekeeping(3.0)
        lines = [r.getMessage() for r in caplog.records if "dial protocol" in r.getMessage()
                 or "needs an update" in r.getMessage()]
        assert lines == [
            "dial core: Lounge speaks a different dial protocol",
            "dial core: Lounge no longer needs an update",
        ]

    def test_one_info_line_per_raise_and_per_clear_of_the_dials_own_warning(self, pool, caplog):
        with caplog.at_level(logging.INFO):
            pool.set(hello=5)
            pool.rig.core._housekeeping(2.0)
            pool.set(hello=PROTOCOL, access="playback", seq=2)
        lines = [r.getMessage() for r in caplog.records if "dial protocol" in r.getMessage()
                 or "needs an update" in r.getMessage() or "this dial" in r.getMessage()]
        assert lines == [
            "dial core: Lounge speaks a newer dial protocol",
            "dial core: this dial no longer needs an update",
        ]


class TestTheNumberIsTheSharedOne:
    def test_the_dial_reads_the_programs_constant(self):
        import autostream_protocol
        assert dial_mdns.PROTOCOL is autostream_protocol.PROTOCOL

    def test_it_matches_the_record_the_dial_advertises(self):
        text = (REPO_ROOT / "system" / "avahi" / "autostream-dial.service").read_text(encoding="utf-8")
        match = re.search(r"<txt-record>proto=(\d+)</txt-record>", text)
        assert match is not None
        assert PROTOCOL == int(match.group(1))
