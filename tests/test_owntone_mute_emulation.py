"""tests/test_owntone_mute_emulation.py

Upstream OwnTone has no mute of its own, so the adapter mutes an output by
setting it to volume 0 and keeping the level it returns to, and lays that
level over the rows it reads back. The player's HTTP API is faked by a small
in-memory player behind the shared requests session.
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_owntone as owntone
import autostream_players as ap
from autostream_owntone import OwnToneBackend

BASE = "http://upstream.test:3689"
OTHER = "http://other.test:3689"


class _Resp:
    def __init__(self, status, body=None):
        self.status_code = status
        self.ok = 200 <= status < 300
        self.content = b"" if body is None else json.dumps(body).encode()
        self.text = self.content.decode()
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


class FakePlayer:
    """Outputs of one or more players by address. Every request is recorded
    as (method, base, path, body), and *on_request* is called first."""

    def __init__(self):
        self.outputs = {}
        self.calls = []
        self.fail_puts = 0
        self.on_request = None

    def add(self, base, oid, volume, selected=True):
        self.outputs.setdefault(base, {})[oid] = {"id": oid, "name": f"Speaker {oid}",
                                                  "selected": selected, "volume": volume}

    def volume(self, base, oid):
        return self.outputs[base][oid]["volume"]

    def _split(self, url):
        for base in self.outputs:
            if url.startswith(base):
                return base, url[len(base):]
        raise AssertionError(f"unknown player {url}")

    def get(self, url, timeout=None):
        if self.on_request:
            self.on_request()
        base, path = self._split(url)
        self.calls.append(("GET", base, path, None))
        if path == "/api/outputs":
            return _Resp(200, {"outputs": [dict(o) for o in self.outputs[base].values()]})
        oid = path.rsplit("/", 1)[-1]
        row = self.outputs[base].get(oid)
        return _Resp(200, dict(row)) if row else _Resp(404)

    def put(self, url, json=None, timeout=None):
        if self.on_request:
            self.on_request()
        base, path = self._split(url)
        self.calls.append(("PUT", base, path, json))
        if self.fail_puts:
            self.fail_puts -= 1
            return _Resp(400)
        if path == "/api/outputs/set":
            for oid, row in self.outputs[base].items():
                row["selected"] = oid in json["outputs"]
            return _Resp(204)
        row = self.outputs[base][path.rsplit("/", 1)[-1]]
        if "selected" in json:
            row["selected"] = json["selected"]
        if "volume" in json:
            row["volume"] = json["volume"]
        return _Resp(204)

    def puts(self):
        return [(path, body) for method, _base, path, body in self.calls if method == "PUT"]

    def gets(self):
        return [path for method, _base, path, _body in self.calls if method == "GET"]


@pytest.fixture
def player(monkeypatch):
    p = FakePlayer()
    p.add(BASE, "1", 40)
    p.add(BASE, "2", 60)
    monkeypatch.setattr(ap, "_session", p)
    return p


def _b(base=BASE):
    return OwnToneBackend(base_url=base)


def _rows(base=BASE):
    result = _b(base).list_outputs()
    assert result.ok
    return {r.id: r for r in result.outputs}


def test_a_mute_takes_the_last_listed_level_without_a_get(player):
    _rows()
    player.calls.clear()
    assert _b().set_output_muted("1", True).ok
    assert player.calls == [("PUT", BASE, "/api/outputs/1", {"volume": 0})]
    row = _rows()["1"]
    assert row.muted is True and row.volume_percent == 40
    assert player.volume(BASE, "1") == 0


def test_a_mute_with_nothing_listed_gets_the_level_first(player):
    assert _b().set_output_muted("2", True).ok
    assert player.gets() == ["/api/outputs/2"]
    assert player.puts() == [("/api/outputs/2", {"volume": 0})]
    assert owntone._MUTED.kept(BASE, "2") == 60


def test_a_second_mute_sends_nothing(player):
    _rows()
    _b().set_output_muted("1", True)
    player.calls.clear()
    assert _b().set_output_muted("1", True).ok
    assert player.calls == []


def test_an_unmute_puts_the_kept_level_and_forgets_it(player):
    _rows()
    _b().set_output_muted("1", True)
    player.calls.clear()
    assert _b().set_output_muted("1", False).ok
    assert player.puts() == [("/api/outputs/1", {"volume": 40})]
    assert owntone._MUTED.kept(BASE, "1") is None
    row = _rows()["1"]
    assert row.muted is False and row.volume_percent == 40
    # An output that is not muted is left alone.
    player.calls.clear()
    assert _b().set_output_muted("2", False).ok
    assert player.calls == []


def test_a_level_while_muted_is_kept_not_sent(player):
    _rows()
    _b().set_output_muted("1", True)
    player.calls.clear()
    assert _b().update_output("1", volume_percent=55).ok
    assert _b().set_output_volume("1", 57).ok
    assert player.calls == []
    assert _rows()["1"].volume_percent == 57 and player.volume(BASE, "1") == 0
    player.calls.clear()
    _b().set_output_muted("1", False)
    assert player.puts() == [("/api/outputs/1", {"volume": 57})]


def test_enable_with_mute_sends_zero_and_keeps_the_level(player):
    player.add(BASE, "3", 25, selected=False)
    _rows()
    player.calls.clear()
    assert _b().update_output("3", enabled=True, volume_percent=35, muted=True).ok
    assert player.puts() == [("/api/outputs/3", {"selected": True, "volume": 0})]
    row = _rows()["3"]
    assert row.selected and row.muted and row.volume_percent == 35
    player.calls.clear()
    assert _b().update_output("3", enabled=True, volume_percent=45, muted=False).ok
    assert player.puts() == [("/api/outputs/3", {"selected": True, "volume": 45})]
    assert owntone._MUTED.kept(BASE, "3") is None
    # Unmuting with no level given sends the kept one.
    _b().update_output("3", muted=True)
    player.calls.clear()
    assert _b().update_output("3", enabled=True, muted=False).ok
    assert player.puts() == [("/api/outputs/3", {"selected": True, "volume": 45})]


def test_switching_off_forgets_the_entry(player):
    player.add(BASE, "3", 30)
    _rows()
    for oid in ("1", "2", "3"):
        _b().set_output_muted(oid, True)
    assert _b().update_output("1", enabled=False).ok
    assert owntone._MUTED.kept(BASE, "1") is None
    assert player.puts()[-1] == ("/api/outputs/1", {"selected": False})
    assert _b().set_output_enabled("2", False).ok
    assert owntone._MUTED.kept(BASE, "2") is None
    _b().set_output_muted("1", True)
    assert _b().set_selected_outputs(["3"]).ok
    assert owntone._MUTED.kept(BASE, "1") is None and owntone._MUTED.kept(BASE, "3") == 30


def test_the_list_overlays_kept_rows_and_drops_stale_entries(player):
    player.add(BASE, "3", 30)
    _rows()
    for oid in ("1", "2", "3"):
        _b().set_output_muted(oid, True)
    # Switched off outside autostream: the mute ends with it.
    player.outputs[BASE]["2"]["selected"] = False
    # Gone from the list for a moment: forgotten too.
    gone = player.outputs[BASE].pop("3")
    rows = _rows()
    assert rows["1"].muted and rows["1"].volume_percent == 40
    assert not rows["2"].muted and rows["2"].volume_percent == 0
    assert owntone._MUTED.kept(BASE, "2") is None and owntone._MUTED.kept(BASE, "3") is None
    player.outputs[BASE]["3"] = gone
    assert _rows()["3"].muted is False
    # One output's own row is overlaid too, without forgetting the others.
    one = _b().get_output("1")
    assert one.ok and one.output.muted and one.output.volume_percent == 40


def test_a_failed_mute_forgets_and_a_failed_unmute_keeps(player):
    _rows()
    player.fail_puts = 1
    assert not _b().set_output_muted("1", True).ok
    assert owntone._MUTED.kept(BASE, "1") is None
    assert _rows()["1"].muted is False
    _b().set_output_muted("1", True)
    player.fail_puts = 1
    assert not _b().set_output_muted("1", False).ok
    assert owntone._MUTED.kept(BASE, "1") == 40
    assert _rows()["1"].muted is True
    # A failed switch-on muted leaves the table as it was.
    player.add(BASE, "3", 25, selected=False)
    _rows()
    player.fail_puts = 1
    assert not _b().update_output("3", enabled=True, volume_percent=35, muted=True).ok
    assert owntone._MUTED.kept(BASE, "3") is None


def test_two_players_do_not_share_entries(player):
    player.add(OTHER, "1", 70)
    _rows()
    _rows(OTHER)
    _b().set_output_muted("1", True)
    assert owntone._MUTED.kept(BASE, "1") == 40
    assert owntone._MUTED.kept(OTHER, "1") is None
    assert _rows(OTHER)["1"].muted is False
    # A backend object built afresh sees the same table.
    assert OwnToneBackend(base_url=BASE).list_outputs().outputs[0].muted is True


class _HolderLock:
    """A lock that knows which thread holds it."""

    def __init__(self):
        self._lock = threading.Lock()
        self.owner = None

    def __enter__(self):
        self._lock.acquire()
        self.owner = threading.get_ident()
        return self

    def __exit__(self, *exc):
        self.owner = None
        self._lock.release()


def test_no_request_is_made_under_the_table_lock(player, monkeypatch):
    lock = _HolderLock()
    monkeypatch.setattr(owntone._MUTED, "_lock", lock)
    requests = []

    def check():
        requests.append(1)
        assert lock.owner != threading.get_ident(), "a request was made under the mute table's lock"

    player.on_request = check
    player.add(BASE, "3", 25, selected=False)
    b = _b()
    b.set_output_muted("2", True)                  # with a GET first
    b.list_outputs()
    b.set_output_muted("1", True)
    b.set_output_muted("1", True)
    b.update_output("1", volume_percent=50)
    b.set_output_volume("1", 52)
    b.set_output_muted("1", False)
    b.update_output("3", enabled=True, volume_percent=30, muted=True)
    b.update_output("3", enabled=True, muted=False)
    b.get_output("2")
    player.fail_puts = 1
    b.set_output_muted("1", True)
    b.update_output("1", enabled=False)
    b.set_output_enabled("2", False)
    b.set_selected_outputs(["3"])
    assert len(requests) >= 12


def test_after_a_reset_the_output_reads_unmuted_at_zero(player):
    assert "after autostream restarts" in owntone._MuteEmulation.__doc__
    _rows()
    _b().set_output_muted("1", True)
    owntone.reset_mute_emulation_for_tests()
    row = _rows()["1"]
    assert row.muted is False and row.volume_percent == 0


def test_a_mute_straight_after_a_level_write_keeps_that_level(player):
    _rows()
    assert _b().set_output_volume("1", 65).ok
    assert _b().update_output("2", volume_percent=15).ok
    player.calls.clear()
    _b().set_output_muted("1", True)
    _b().set_output_muted("2", True)
    assert player.gets() == []
    assert owntone._MUTED.kept(BASE, "1") == 65 and owntone._MUTED.kept(BASE, "2") == 15
    player.calls.clear()
    _b().set_output_muted("1", False)
    assert player.puts() == [("/api/outputs/1", {"volume": 65})]
