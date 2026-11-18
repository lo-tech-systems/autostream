"""Tests for autostream_peer_registry, driven through the real MdnsBrowser with
resolved lines fed to it (no avahi)."""
from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))

from autostream_peer_registry import PeerRegistry  # noqa: E402

LOCAL = "a1b2c3d4e5f6a1b2c3d4"
PEER = "b2c3d4e5f6a1b2c3d4e5"
OTHER = "c3d4e5f6a1b2c3d4e5f6"


def line(peer_id=PEER, *, service="Svc", host="peer.local", ip="192.168.1.2", port=80,
         proto="4", control=None, version="0.8.0", iface="eth0"):
    txt = f'"id={peer_id}" "version={version}"'
    if proto is not None:
        txt += f' "proto={proto}"'
    if control is not None:
        txt += f' "control={control}"'
    return f"=;{iface};IPv4;{service};_autostream._tcp;local;{host};{ip};{port};{txt}"


def gone(service="Svc", iface="eth0"):
    return f"-;{iface};IPv4;{service};_autostream._tcp;local"


def make(local_id=LOCAL):
    reg = PeerRegistry(local_id=local_id)
    events = []
    reg.subscribe(lambda kind, i, s: events.append((kind, i, s)))
    return reg, reg._browser, events


class TestParse:
    def test_sighting_fields(self):
        reg, br, events = make()
        br._handle_line(line(port=8080, control="off", proto="4"))
        s = reg.sightings()[PEER]
        assert (s.hostname, s.ip, s.port, s.version, s.control, s.proto) == (
            "peer", "192.168.1.2", 8080, "0.8.0", False, 4)
        assert s.service_name == "Svc"
        assert [e[0] for e in events] == ["add"]

    def test_proto_absent_or_not_an_integer_is_none(self):
        reg, br, _ = make()
        br._handle_line(line(proto=None))
        assert reg.sightings()[PEER].proto is None
        br._handle_line(line(OTHER, service="B", proto="x"))
        assert reg.sightings()[OTHER].proto is None

    def test_ui_and_federation_keys_are_not_required(self):
        reg, br, _ = make()
        br._handle_line(line())
        assert PEER in reg.sightings()

    def test_invalid_id_and_own_id_are_dropped(self):
        reg, br, events = make()
        br._handle_line(line("abc123"))
        br._handle_line(line(LOCAL, service="Me"))
        assert reg.sightings() == {} and events == []

    def test_no_local_id_filters_nothing(self):
        reg, br, _ = make(local_id=None)
        br._handle_line(line(LOCAL))
        assert LOCAL in reg.sightings()

    def test_empty_hostname_is_autostream(self):
        reg, br, _ = make()
        br._handle_line(line(host=".local"))
        assert reg.sightings()[PEER].hostname == "autostream"


class TestChangeAndRemove:
    def test_address_move_is_a_change(self):
        reg, br, events = make()
        br._handle_line(line(ip="192.168.1.2"))
        br._handle_line(line(ip="192.168.1.9"))
        assert [e[0] for e in events] == ["add", "change"]
        assert reg.sightings()[PEER].ip == "192.168.1.9"

    def test_a_txt_change_is_a_change(self):
        reg, br, events = make()
        br._handle_line(line(control="on"))
        br._handle_line(line(control="off"))
        assert events[-1][0] == "change" and events[-1][2].control is False

    def test_same_sighting_again_is_nothing(self):
        reg, br, events = make()
        br._handle_line(line())
        br._handle_line(line())
        assert len(events) == 1

    def test_removal(self):
        reg, br, events = make()
        br._handle_line(line())
        br._handle_line(gone())
        assert reg.sightings() == {}
        assert events[-1] == ("remove", PEER, None)

    def test_grace_period_passes_through(self):
        reg, br, _ = make()
        reg.set_grace_period(30)
        assert br._grace_period_secs == 30

    def test_unsubscribe(self):
        reg, br, events = make()
        handle = reg.subscribe(lambda *a: events.append("late"))
        reg.unsubscribe(handle)
        br._handle_line(line())
        assert "late" not in events

    def test_a_raising_subscriber_does_not_stop_the_others(self):
        reg, br, events = make()
        reg.subscribe(lambda *a: 1 / 0)
        br._handle_line(line())
        assert len(events) == 1


class TestConflict:
    def conflict(self, br):
        br._handle_line(line(service="A", host="ha.local", ip="192.168.1.10"))
        br._handle_line(line(service="B", host="hb.local", ip="192.168.1.11"))

    def test_two_hostnames_for_one_id_are_a_conflict_and_hidden(self):
        reg, br, events = make()
        self.conflict(br)
        assert PEER in reg.conflicts()
        assert reg.sightings() == {}
        assert [e[0] for e in events] == ["add", "remove"]

    def test_same_hostname_on_two_addresses_is_no_conflict(self):
        reg, br, _ = make()
        br._handle_line(line(service="A", host="ha.local", ip="192.168.1.10"))
        br._handle_line(line(service="B", host="ha.local", ip="192.168.1.11"))
        assert reg.conflicts() == frozenset()
        assert PEER in reg.sightings()

    def test_conflict_logs_once_per_id(self, caplog):
        reg, br, _ = make()
        with caplog.at_level(logging.WARNING):
            self.conflict(br)
            br._handle_line(line(service="B", host="hb.local", ip="192.168.1.12"))
        assert sum("id conflict" in r.message for r in caplog.records) == 1

    def test_conflict_ends_when_one_goes_and_is_an_add(self):
        reg, br, events = make()
        self.conflict(br)
        br._handle_line(gone("B"))
        assert reg.conflicts() == frozenset()
        assert PEER in reg.sightings()
        assert events[-1][0] == "add"

    def test_removal_of_the_last_clears_state_and_logging(self, caplog):
        reg, br, events = make()
        self.conflict(br)
        br._handle_line(gone("A"))
        br._handle_line(gone("B"))
        assert reg.conflicts() == frozenset() and reg.sightings() == {}
        assert reg._conflict_logged == set()
        with caplog.at_level(logging.WARNING):
            self.conflict(br)
        assert any("id conflict" in r.message for r in caplog.records)

    def test_stop_clears_everything(self):
        reg, br, _ = make()
        self.conflict(br)
        reg.stop()
        assert reg.conflicts() == frozenset() and reg.sightings() == {}
