"""tests/test_dial_peer_view.py -- dial_peer_view: a peer snapshot as the dial types."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
for _p in (_ROOT / "dial", _ROOT / "core"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import dial_peer_view as pv  # noqa: E402
from autostream_peer_client import PeerSnapshot  # noqa: E402
from autostream_peer_registry import Sighting  # noqa: E402
from dial_appliance_warnings import APPLIANCE_WARNINGS_MAX, ApplianceWarning  # noqa: E402
from dial_core_state import AUTH_AUTHORIZED, AUTH_UNAUTHORIZED, AUTH_UNKNOWN  # noqa: E402

AID = "a" * 20
ME = "dial:abc"


def sighting(**kw):
    base = dict(id=AID, hostname="turntable", ip="192.0.2.5", port=80, version="0.8.0",
                control=True, proto=4, service_name="autostream on Turntable")
    base.update(kw)
    return Sighting(**base)


def unit(uid, name, **kw):
    base = dict(id=uid, name=name, selected=False, volume=30, muted=False, availability="ok",
                cause="user", reported={"id": uid, "name": name}, connecting=False,
                auto_start=False, hidden=False, pin_claim="", in_use_by="", in_use_id="",
                offline=False)
    base.update(kw)
    return base


def outputs(*units, **kw):
    base = dict(units=list(units), connected=True, muted_all=False, master_volume=40,
                start_failure=None)
    base.update(kw)
    return base


def snap(parts=None, **kw):
    base = dict(peer_id=AID, boot="b1", version=3, part_versions={}, parts=parts or {},
                reachable=True, access="playback", access_reason=None, protocol=4,
                protocol_ok=True, configured=True, heard_at=1.0, seq=1)
    base.update(kw)
    return PeerSnapshot(**base)


def state(s, **kw):
    return pv.appliance_state(sighting(), s, now=100.0, **kw)


# ---- appliance_state ------------------------------------------------------------


class TestApplianceState:
    def test_identity_comes_from_the_sighting(self):
        a = state(snap({"outputs": outputs()}))
        assert (a.appliance_id, a.ip, a.port) == (AID, "192.0.2.5", 80)
        assert a.service_name == "autostream on Turntable"
        assert a.name == "Turntable"
        assert (a.webui_scheme, a.webui_host, a.webui_port) == ("http", "192.0.2.5", 80)

    def test_playing_and_playing_since(self):
        s = snap({"session": {"active": True, "source": "input1"}, "outputs": outputs()})
        a = state(s, playing_since=55.0)
        assert a.playing and a.playing_since == 55.0
        idle = state(snap({"session": {"active": False, "source": None}, "outputs": outputs()}),
                     playing_since=55.0)
        assert not idle.playing and idle.playing_since == 0.0

    @pytest.mark.parametrize("access, reason, expect", [
        ("playback", None, AUTH_AUTHORIZED),
        ("none", "dial_not_authorized", AUTH_UNAUTHORIZED),
        ("none", "unconfigured", AUTH_UNAUTHORIZED),
        ("none", "auth_unavailable", AUTH_UNKNOWN),
        ("none", None, AUTH_UNKNOWN),
        ("unknown", None, AUTH_UNKNOWN),
    ])
    def test_auth_from_access(self, access, reason, expect):
        assert state(snap(access=access, access_reason=reason)).auth == expect

    def test_capabilities_follow_the_protocol(self):
        a = state(snap({"outputs": outputs()}))
        assert (a.dial_status, a.dial_outputs, a.dial_eq, a.repeat_capable) == (True,) * 4
        assert (a.dial_outputs_version, a.dial_proto_version) == (2, 4)
        b = state(snap(protocol=5, protocol_ok=False, reachable=False))
        assert (b.dial_status, b.dial_outputs, b.dial_eq, b.repeat_capable) == (False,) * 4
        assert (b.dial_outputs_version, b.dial_proto_version) == (0, 5)

    def test_status_error(self):
        assert state(snap({"outputs": outputs()})).status_error is None
        assert state(snap(reachable=False)).status_error == "unreachable"
        assert state(snap(protocol_ok=False, reachable=False)).status_error == "protocol"
        assert state(snap(access="none", access_reason="dial_not_authorized")).status_error == "unauthorized"
        assert state(snap({"outputs": outputs(connected=False)})).status_error == "unavailable"
        assert state(None).status_error == "unreachable"

    def test_volume_and_mute(self):
        a = state(snap({"outputs": outputs(master_volume=61, muted_all=True)}))
        assert (a.master_volume, a.muted) == (61, True)
        b = state(snap({}))
        assert (b.master_volume, b.muted) == (None, None)

    def test_repeat_only_when_reachable(self):
        block = {"enabled": True, "armed": False, "recording": {"seconds": 30.0},
                 "replay": {"active": False}}
        parts = {"repeat": {"block": block}, "outputs": outputs()}
        assert state(snap(parts)).repeat.state == "hold"
        assert state(snap(parts, reachable=False)).repeat is None

    def test_warnings_carry_the_name(self):
        entries = [{"id": "psu", "incident": "", "severity": "critical", "kind": "psu",
                    "subject": "", "title": "Power supply", "message": "Weak", "link": None}]
        a = state(snap({"warnings": {"entries": entries}}))
        assert a.warnings == (ApplianceWarning("psu", "critical", "Power supply", "Weak", appliance_name="Turntable"),)

    def test_no_snapshot_yet(self):
        a = state(None)
        assert (a.auth, a.playing, a.repeat, a.warnings) == (AUTH_UNKNOWN, False, None, ())


# ---- warnings ---------------------------------------------------------------------


class TestWarnings:
    def _entry(self, i, **kw):
        base = {"id": f"w{i}", "severity": "info", "title": f"T{i}", "message": "m"}
        base.update(kw)
        return base

    def test_sixteen_entries_are_accepted_with_the_limit_raised(self):
        out = pv.appliance_warnings([self._entry(i) for i in range(16)], "X", limit=16)
        assert [w.id for w in out] == [f"w{i}" for i in range(16)]

    def test_default_limit_is_the_dial_cap(self):
        out = pv.appliance_warnings([self._entry(i) for i in range(50)], "X")
        assert len(out) == APPLIANCE_WARNINGS_MAX

    def test_guard_drops_bad_entries_and_clamps_values(self):
        out = pv.appliance_warnings([
            "junk", self._entry(1, id="BAD ID"), self._entry(2, title=""),
            self._entry(3, severity="loud"), self._entry(4, id="w3"),
        ], "X")
        assert [(w.id, w.severity) for w in out] == [("w3", "info")]

    def test_none_entries(self):
        assert pv.appliance_warnings(None, "X") == ()


# ---- outputs -----------------------------------------------------------------------


class TestOutputs:
    def test_rows_by_the_speaker_card_rules(self):
        parts = {"outputs": outputs(
            unit("b", "Bravo", selected=True, volume=55),
            unit("a", "alpha", auto_start=True),
            unit("h", "Hidden", hidden=True),
            unit("hs", "Hidden on", hidden=True, selected=True),
            unit("u", "Used", in_use_by="Kitchen", in_use_id="k" * 20),
            unit("o", "Offline", offline=True, reported=None),
        )}
        st = pv.outputs_state(AID, parts)
        assert st.loaded and st.appliance_id == AID
        assert [(r.id, r.selected, r.volume, r.is_default) for r in st.rows] == [
            ("a", False, 30, True), ("b", True, 55, False), ("hs", True, 30, False),
            ("u", False, 30, False)]
        used = st.rows[3]
        assert used.remote_in_use and used.remote_owner == "Kitchen"
        assert not st.rows[0].remote_in_use and st.rows[0].remote_owner is None

    def test_needs_auth_key_from_the_unit(self):
        parts = {"outputs": outputs(
            unit("p", "Pin", reported={"id": "p", "name": "Pin", "needs_auth_key": True}),
            unit("q", "Plain"))}
        rows = {r.id: r for r in pv.outputs_state(AID, parts).rows}
        assert rows["p"].needs_auth_key and not rows["q"].needs_auth_key

    def test_a_unit_waiting_for_a_pin_reads_as_off(self):
        parts = {"outputs": outputs(unit("p", "Pin", selected=True, availability="password"))}
        assert pv.outputs_state(AID, parts).rows[0].selected is False

    def test_a_speaker_switched_off_while_it_ends_its_session_is_stopping(self):
        parts = {"outputs": outputs(unit("s", "Stopping", stopping=True), unit("p", "Plain"),
                                    unit("u", "Used", stopping=True, in_use_by="Kitchen"))}
        rows = {r.id: r for r in pv.outputs_state(AID, parts).rows}
        assert rows["s"].stopping and not rows["p"].stopping and not rows["u"].stopping

    def test_no_outputs_part(self):
        st = pv.outputs_state(AID, {})
        assert st.rows == () and not st.loaded


# ---- eq ----------------------------------------------------------------------------


class TestEq:
    def test_six_bands_then_bass_and_treble(self):
        st = pv.eq_state(AID, {"eq": {"output_bands": [3.0, 0, -2.4, 1.5, 0, -8]}})
        assert st.loaded and st.capability_version == 2
        assert [b.id for b in st.bands] == ["peq1", "peq2", "peq3", "peq4", "peq5", "peq6", "bass", "treble"]
        peq = st.bands[:6]
        assert [b.frequency_hz for b in peq] == [40, 100, 300, 1000, 4000, 10000]
        assert [b.gain_db for b in peq] == [3, 0, -2, 2, 0, -8]
        assert all((b.min_db, b.max_db) == (-12, 12) for b in peq)
        bass, treble = st.bands[6], st.bands[7]
        assert (bass.gain_db, bass.frequency_hz, bass.min_db, bass.max_db) == (3, None, -6, 6)
        assert treble.gain_db == -6      # -8 held to the dial's range

    def test_gain_is_held_to_the_band_range(self):
        st = pv.eq_state(AID, {"eq": {"output_bands": [40, 0, 0, 0, 0, -40]}})
        assert (st.bands[0].gain_db, st.bands[5].gain_db) == (12, -12)

    @pytest.mark.parametrize("parts", [{}, {"eq": {}}, {"eq": {"output_bands": []}},
                                       {"eq": {"output_bands": [1, 2, 3]}}])
    def test_empty_part_is_not_loaded(self, parts):
        st = pv.eq_state(AID, parts)
        assert st.bands == () and not st.loaded


# ---- now playing ---------------------------------------------------------------------


def _track(**kw):
    base = {"enabled": True, "state": "identified", "title": "Song", "artist": "Band",
            "album": "Disc", "artwork_url": "https://example.test/a.jpg"}
    base.update(kw)
    return base


def _playing_parts(track, source="input1", input_type="cd"):
    return {
        "session": {"active": True, "source": source},
        "inputs": {"entries": [{"index": 1, "input_type": input_type, "level": {}}]},
        "track": {"entries": {"1": track}},
        "outputs": outputs(master_volume=44),
    }


class TestNowPlaying:
    def test_identified_track(self):
        n = pv.now_playing(_playing_parts(_track()), "Turntable")
        assert (n.service_name, n.title, n.artist, n.album) == ("Turntable", "Song", "Band", "Disc")
        assert n.artwork_url == "https://example.test/a.jpg"
        assert (n.playing, n.master_volume, n.input_label) == (True, 44, "CD")

    def test_not_identified_gives_no_text(self):
        n = pv.now_playing(_playing_parts(_track(state="analysing")))
        assert (n.title, n.artist, n.album, n.artwork_url) == ("", "", "", "")
        assert n.playing

    def test_artwork_needs_an_http_url(self):
        assert pv.now_playing(_playing_parts(_track(artwork_url="file:///x"))).artwork_url == ""
        assert pv.now_playing(_playing_parts(_track(artwork_url="http://e.test/a"))).artwork_url == "http://e.test/a"

    def test_idle_has_no_input_label(self):
        n = pv.now_playing({"session": {"active": False, "source": None}, "outputs": outputs()})
        assert (n.playing, n.input_label, n.title) == (False, "", "")

    def test_replay_takes_the_origin_inputs_track(self):
        parts = _playing_parts(_track(title="Origin"), source="replay")
        parts["repeat"] = {"block": {"replay": {"active": True}, "recording": {"origin_input": 1}}}
        assert pv.now_playing(parts).title == "Origin"

    def test_unknown_input_type_reads_as_line(self):
        assert pv.now_playing(_playing_parts(_track(), input_type="odd")).input_label == "Line"


# ---- start failure ---------------------------------------------------------------------


class TestStartFailure:
    RAW = {"seq": 3, "unit_id": "u1", "name": "Kitchen", "reason": "refused", "at": 10.0,
           "requester": ME}

    def test_mine(self):
        r = pv.start_failure(self.RAW, "b1", ME, age_s=4)
        assert (r.boot, r.seq, r.unit_id, r.name, r.reason, r.mine, r.age_s) == (
            "b1", 3, "u1", "Kitchen", "refused", True, 4)

    def test_not_mine(self):
        assert pv.start_failure(dict(self.RAW, requester="webui"), "b1", ME).mine is False
        assert pv.start_failure(dict(self.RAW, requester=None), "b1", ME).mine is False

    @pytest.mark.parametrize("raw", [None, {}, {"seq": 0}, "x"])
    def test_none_when_absent_or_malformed(self, raw):
        assert pv.start_failure(raw, "b1", ME) is None


# ---- repeat ------------------------------------------------------------------------------


class TestRepeat:
    def rec(self, **block):
        return pv.repeat_record(block, 7.0)

    def test_states(self):
        assert self.rec(enabled=True, replay={"active": True}).state == "replaying"
        assert self.rec(enabled=True, replay={"active": True, "fading_out": True}).state == "fading_out"
        assert self.rec(enabled=True, recording={"active": True}).state == "recording"
        assert self.rec(enabled=True, recording={"seconds": 5}).state == "hold"
        assert self.rec(enabled=True).state == "idle"
        assert self.rec(enabled=False, recording={"seconds": 5}).state == "idle"

    def test_fields(self):
        r = self.rec(enabled=True, armed=True, recording={"seconds": 12.5},
                     replay={"active": True, "position_seconds": 3.0, "duration_seconds": 12.5})
        assert (r.available, r.armed, r.recording_seconds) == (True, True, 12.5)
        assert (r.position_seconds, r.duration_seconds, r.observed_at) == (3.0, 12.5, 7.0)

    def test_no_block(self):
        assert pv.repeat_record(None, 1.0) is None
