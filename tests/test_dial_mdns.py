"""dial_mdns: the appliances sighted by the peer registry, as the volume
control and the operator socket read them.

The module browses nothing itself: it reads the registry's sightings and, for
whether an appliance is playing and whether it takes this dial's writes, the
callable it is attached with.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).parent.parent
for _p in (str(REPO_ROOT / "dial"), str(REPO_ROOT / "core"), str(REPO_ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import dial_mdns as dm
from autostream_protocol import PROTOCOL
from dial_pool_support import FakeRegistry, aid, sighting


@pytest.fixture(autouse=True)
def detached():
    dm.attach(None, None)
    yield
    dm.attach(None, None)


def registry(*names, **kwargs):
    r = FakeRegistry()
    for name in names:
        s = sighting(name, **kwargs)
        r.seen[s.id] = s
    return r


def view(playing=False, since=0.0, auth="authorized"):
    return SimpleNamespace(playing=playing, playing_since=since, auth=auth)


class TestWithNothingAttached:
    def test_there_are_no_targets(self):
        assert dm.get_display_targets() == dm.get_playing_targets() == []


class TestTargets:
    def test_only_playing_appliances_are_targets(self):
        r = registry("Kitchen", "Lounge")
        states = {aid("Kitchen"): view(playing=True, since=5.0)}
        dm.attach(r, states.get)
        assert [t.appliance_id for t in dm.get_playing_targets()] == [aid("Kitchen")]

    def test_a_target_carries_the_sighting_and_the_core_view(self):
        r = registry("Kitchen", ip="192.0.2.30", port=8080)
        dm.attach(r, {aid("Kitchen"): view(playing=True, since=7.0, auth="unknown")}.get)
        (t,) = dm.get_display_targets()
        assert (t.ip, t.port, t.appliance_id) == ("192.0.2.30", 8080, aid("Kitchen"))
        assert t.service_name == t.name == "autostream on Kitchen"
        assert (t.playing_since, t.auth) == (7.0, "unknown")
        assert t.dial_api and t.dial_status and t.dial_outputs and t.dial_eq

    def test_an_appliance_on_another_protocol_is_not_marked_capable(self):
        dm.attach(registry("Kitchen", proto=PROTOCOL + 1), {aid("Kitchen"): view(playing=True)}.get)
        (t,) = dm.get_display_targets()
        assert not (t.dial_status or t.dial_outputs or t.dial_eq)

    def test_the_display_order_is_oldest_playing_first_with_stable_tie_breaks(self):
        r = registry("Lounge", "Kitchen", "Study")
        states = {
            aid("Lounge"): view(playing=True, since=1.0),
            aid("Kitchen"): view(playing=True, since=2.0),
            aid("Study"): view(playing=True, since=1.0),
        }
        dm.attach(r, states.get)
        assert [t.service_name[len("autostream on "):] for t in dm.get_display_targets()] == [
            "Lounge", "Study", "Kitchen"]

    def test_nothing_is_playing_without_a_view(self):
        dm.attach(registry("Kitchen"), None)
        assert dm.get_playing_targets() == []

    def test_a_view_that_raises_reads_as_unknown(self):
        def boom(appliance_id):
            raise RuntimeError("view")
        dm.attach(registry("Kitchen"), boom)
        assert dm.get_playing_targets() == []

    def test_an_appliance_with_no_view_yet_is_not_playing(self):
        dm.attach(registry("Kitchen"), {}.get)
        assert dm.get_playing_targets() == []


class TestApplianceDisplayName:
    # avahi-browse -p delivers the instance name with spaces escaped as \032,
    # so these use the real on-the-wire form, not pre-spaced strings.
    def test_strips_escaped_service_prefix_and_replaces_underscores(self):
        assert dm.appliance_display_name("autostream\\032on\\032CD_Player") == "CD Player"

    def test_escaped_hostname_without_underscores_unchanged(self):
        assert dm.appliance_display_name("autostream\\032on\\032Turntable") == "Turntable"

    def test_already_unescaped_name_also_works(self):
        assert dm.appliance_display_name("autostream on Hallway") == "Hallway"

    def test_name_without_prefix_still_replaces_underscores(self):
        assert dm.appliance_display_name("Some_Other_Name") == "Some Other Name"


class TestNoBrowserOfItsOwn:
    def test_the_module_starts_no_browser(self):
        assert not hasattr(dm, "start_playing_browser") and not hasattr(dm, "start_general_browser")
        assert not hasattr(dm, "_browser") and not hasattr(dm, "_general_browser")
