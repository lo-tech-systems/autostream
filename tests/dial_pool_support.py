"""A stand-in peer pool for the dial core: scripted PeerSnapshots behind fake
clients, a registry of sightings, and a core attached to them, driven by hand
(fold_once) without the core thread."""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from types import MappingProxyType
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).parent.parent
for _p in (str(REPO_ROOT / "dial"), str(REPO_ROOT / "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from autostream_peer_client import PeerReply, PeerSnapshot  # noqa: E402
from autostream_peer_registry import Sighting  # noqa: E402
from dial_core import DialCore, PollIO  # noqa: E402
from dial_warning_text import WARNING_DESCRIPTORS  # noqa: E402
from dial_warnings import WarningManager, WarningStore  # noqa: E402

DIAL_ID = "dial-uuid"


def aid(name: str) -> str:
    """A 20-hex appliance id derived from *name*."""
    return (name.lower().encode().hex() + "0" * 20)[:20]


def sighting(name: str, *, ip: str = "192.0.2.10", port: int = 80, proto: int | None = 4) -> Sighting:
    return Sighting(id=aid(name), hostname=name, ip=ip, port=port, version="0.8.0",
                    control=True, proto=proto, service_name=f"autostream on {name}")


def track(title="Song", artist="Artist", album="Album", url="https://provider.example/a.jpg", state="identified"):
    return {"state": state, "title": title, "artist": artist, "album": album, "artwork_url": url}


def unit(uid="u1", name="Lounge", *, selected=False, volume=40, availability="ok", **extra):
    return {"id": uid, "name": name, "selected": selected, "volume": volume,
            "availability": availability, **extra}


def replay_block(state="replaying", position=5.0, duration=60.0, seconds=60.0):
    replaying = state in ("replaying", "fading_out")
    return {
        "enabled": True, "armed": False,
        "recording": {"active": state == "recording", "seconds": seconds, "bytes": 1000, "origin_input": 1},
        "replay": {"active": replaying, "fading_out": state == "fading_out",
                   "position_seconds": position, "duration_seconds": duration},
    }


def peer(name: str, *, playing=False, source="input1", track_entry=None, access="playback",
         access_reason=None, units=(), master_volume=40, muted_all=False, bands=None,
         repeat=None, warnings=None, start_failure=None, reachable=True, protocol_ok=True,
         protocol=4, boot="b1", version=1, seq=1, heard_at=1.0, outputs=True) -> PeerSnapshot:
    parts: dict = {"session": {"active": playing, "source": source if playing else ""}}
    if track_entry is not None:
        parts["track"] = {"entries": {"1": track_entry}}
    if outputs:
        parts["outputs"] = {"connected": True, "master_volume": master_volume, "muted_all": muted_all,
                            "units": [dict(u) for u in units]}
        if start_failure is not None:
            parts["outputs"]["start_failure"] = start_failure
    if bands is not None:
        parts["eq"] = {"output_bands": list(bands)}
    if repeat is not None:
        parts["repeat"] = {"block": repeat}
    if warnings is not None:
        parts["warnings"] = {"entries": list(warnings)}
    return PeerSnapshot(
        peer_id=aid(name), boot=boot, version=version, part_versions=MappingProxyType({}),
        parts=MappingProxyType(parts), reachable=reachable, access=access,
        access_reason=access_reason, protocol=protocol, protocol_ok=protocol_ok,
        configured=True, heard_at=heard_at, seq=seq)


def ok(version=2, boot="b1", result=None) -> PeerReply:
    return PeerReply(True, None, version, boot, result or {}, None)


def refused(error, retry=None) -> PeerReply:
    return PeerReply(False, error, None, None, {}, retry)


class FakeClient:
    """A PeerClient stand-in: a scripted snapshot, and a record of what was
    sent. *reply* answers every submit; *gate*, when set, holds a submit
    until it is set."""

    def __init__(self, snap: PeerSnapshot, pool: "FakePool") -> None:
        self.snap = snap
        self.pool = pool
        self.calls: list = []
        self.reply = ok()
        self.gate: threading.Event | None = None
        self.threads: list = []
        self.fetched = threading.Event()

    def snapshot(self) -> PeerSnapshot:
        return self.snap

    def submit(self, name, args, *, extra_body=None, read_s=None, backoff=True):
        self.calls.append(("submit", name, dict(args), extra_body))
        self.threads.append(threading.current_thread())
        if self.gate is not None:
            self.gate.wait(10)
        return self.reply

    def fetch(self, parts, *, merge=False):
        self.calls.append(("fetch", list(parts), merge))
        self.fetched.set()
        return 200, {"parts": {}}

    def sent(self) -> list:
        return [c for c in self.calls if c[0] == "submit"]

    def fetches(self) -> list:
        return [c for c in self.calls if c[0] == "fetch"]


class FakePool:
    def __init__(self) -> None:
        self._clients: dict = {}
        self._subs: list = []

    def clients(self):
        return dict(self._clients)

    def get(self, peer_id):
        return self._clients.get(peer_id)

    def subscribe(self, fn) -> int:
        self._subs.append(fn)
        return len(self._subs)

    def unsubscribe(self, handle) -> None:
        pass

    def signal(self) -> None:
        for fn in list(self._subs):
            fn()


class FakeRegistry:
    def __init__(self) -> None:
        self.seen: dict = {}

    def sightings(self):
        return dict(self.seen)


class Rig:
    """A core attached to a fake pool, folded by hand."""

    def __init__(self, *, clock=None, start_lane=True) -> None:
        self.t = 1000.0
        self.pool = FakePool()
        self.registry = FakeRegistry()
        self.io = PollIO(
            fetch_artwork=MagicMock(return_value=(b"jpeg", "")),
            artwork_eligible=lambda url: True,
            observe_mute=MagicMock(), observe_volume=MagicMock(), forget_mute=MagicMock(),
        )
        self.core = DialCore(
            DIAL_ID, lambda: [], lambda: [], clock=clock or (lambda: self.t), io=self.io,
            warnings=WarningManager(WARNING_DESCRIPTORS, WarningStore(None), clock=time.time),
        )
        self.core.attach_pool(self.pool, self.registry)
        if start_lane:
            self.core._lane.start()

    def close(self) -> None:
        if self.core._lane is not None:
            self.core._lane.stop()

    def add(self, name: str, snap: PeerSnapshot | None = None, **sighting_kw) -> FakeClient:
        s = sighting(name, **sighting_kw)
        self.registry.seen[s.id] = s
        client = FakeClient(snap if snap is not None else peer(name), self.pool)
        self.pool._clients[s.id] = client
        return client

    def set(self, name: str, snap: PeerSnapshot) -> None:
        self.pool._clients[aid(name)].snap = snap

    def remove(self, name: str) -> None:
        self.registry.seen.pop(aid(name), None)
        self.pool._clients.pop(aid(name), None)

    def fold(self):
        return self.core.fold_once()

    def wait(self, predicate, timeout=5.0) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate():
                return True
            time.sleep(0.005)
        return predicate()
