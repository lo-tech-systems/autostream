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

import dial_core_state as cs
import dial_mdns
from autostream_protocol import PROTOCOL
from dial_mdns import RosterEntry
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
        warning = cs.protocol_warning(entry(proto=3), OWN)
        assert warning.id == cs.PROTOCOL_WARNING_ID == "update_appliance"
        assert warning.severity == "warning" and warning.dismissal == "week"
        assert warning.title == "Update Lounge"
        assert warning.message == "Its software is older than this dial's. Update it from its web UI."
        assert warning.appliance_name == "Lounge"

    @pytest.mark.parametrize("proto", [5, 9])
    def test_a_higher_number_gives_update_dial(self, proto):
        warning = cs.protocol_warning(entry(proto=proto), OWN)
        assert warning.id == cs.DIAL_WARNING_ID == "update_dial"
        assert warning.severity == "warning" and warning.dismissal == "week"
        assert warning.title == "Update this dial"
        assert warning.message == "Lounge needs a newer dial"
        assert warning.appliance_name == "Lounge"

    def test_the_same_number_gives_none(self):
        assert cs.protocol_warning(entry(proto=OWN), OWN) is None

    @pytest.mark.parametrize("proto", [0, None, True])
    def test_an_appliance_that_has_not_said_a_number_gets_none_yet(self, proto):
        assert cs.protocol_warning(entry(proto=proto), OWN) is None

    @pytest.mark.parametrize("auth", ["unauthorized", "unknown", "authorized"])
    def test_access_is_not_asked(self, auth):
        assert cs.protocol_warning(entry(auth=auth), OWN) is not None

    def test_an_appliance_with_no_identity_gets_none(self):
        assert cs.protocol_warning(entry(appliance_id=""), OWN) is None

    def test_a_long_name_is_fitted_to_the_title(self):
        warning = cs.protocol_warning(entry("x" * 60), OWN)
        assert len(warning.title) <= cs.APPLIANCE_WARNING_TITLE_MAX
        assert warning.title.startswith("Update xxx")

    def test_a_long_name_is_fitted_to_the_message_of_the_dial_warning(self):
        warning = cs.protocol_warning(entry("x" * 300, proto=5), OWN)
        assert len(warning.message) <= cs.APPLIANCE_WARNING_MESSAGE_MAX

    def test_a_name_from_the_network_is_cleaned(self):
        warning = cs.protocol_warning(entry("Lo‮unge\x07"), OWN)
        assert "‮" not in warning.title and "\x07" not in warning.title


class Pool:
    """A core over a fake pool holding one appliance, "Lounge"."""

    def __init__(self):
        self.rig = Rig()
        self.key = appliance_warning_key(aid("Lounge"), cs.PROTOCOL_WARNING_ID)

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
        assert pool.ids() == [cs.PROTOCOL_WARNING_ID]

    def test_a_higher_hello_raises_update_dial(self, pool):
        pool.set(hello=5)
        assert pool.ids() == [cs.DIAL_WARNING_ID]

    def test_an_equal_hello_raises_nothing(self, pool):
        pool.set(hello=PROTOCOL, access="playback")
        assert pool.ids() == []

    def test_the_record_is_read_until_the_hello_has_been(self, pool):
        pool.set(hello=None, record=3)
        assert pool.ids() == [cs.PROTOCOL_WARNING_ID]
        pool.set(hello=None, record=5)
        assert pool.ids() == [cs.DIAL_WARNING_ID]

    def test_the_hello_wins_over_the_record(self, pool):
        pool.set(hello=PROTOCOL, record=3, access="playback")
        assert pool.ids() == []

    def test_a_number_on_neither_gives_no_warning_yet(self, pool):
        pool.set(hello=None, record=None)
        assert pool.ids() == []

    def test_a_mismatched_appliance_with_unknown_access_is_still_warned(self, pool):
        pool.set(hello=3, access="unknown")
        assert pool.ids() == [cs.PROTOCOL_WARNING_ID]
        pool.set(hello=3, access="none", seq=2)
        assert pool.ids() == [cs.PROTOCOL_WARNING_ID]

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
        assert pool.ids() == [cs.DIAL_WARNING_ID]
        assert not any(s.id == pool.key for s in pool.rig.core.snapshot().warnings)

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


class TestTheNumberIsTheSharedOne:
    def test_the_dial_reads_the_programs_constant(self):
        import autostream_protocol
        assert dial_mdns.PROTOCOL is autostream_protocol.PROTOCOL

    def test_it_matches_the_record_the_dial_advertises(self):
        text = (REPO_ROOT / "system" / "avahi" / "autostream-dial.service").read_text(encoding="utf-8")
        match = re.search(r"<txt-record>proto=(\d+)</txt-record>", text)
        assert match is not None
        assert PROTOCOL == int(match.group(1))
