"""autostream_peer_registry.py -- the appliances seen on the network.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

One browser of ``_autostream._tcp`` turned into a registry of sightings, one
per appliance id. An id claimed by two different hostnames is a conflict and is
left out until one of them goes. Subscribers hear of an appliance appearing,
changing address or details, and going. The module imports only the standard
library and the program's mDNS and logging modules, so a dial can carry it.
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass
from typing import Any, Callable, Optional

from autostream_mdns import MdnsBrowser

SERVICE_TYPE = "_autostream._tcp"

_ID_RE = re.compile(r"[0-9a-f]{20}")


@dataclass(frozen=True)
class Sighting:
    id: str             # 20 lowercase hex
    hostname: str       # no ".local"; "autostream" when empty
    ip: str
    port: int
    version: str
    control: bool       # the TXT control key is not "off"
    proto: Optional[int]  # the TXT proto key; None when absent or not an integer
    service_name: str


def _trim_hostname(raw: str) -> str:
    hostname = str(raw or "").strip()
    if hostname.lower().endswith(".local"):
        hostname = hostname[:-6]
    return hostname.strip() or "autostream"


def _proto(raw: Optional[str]) -> Optional[int]:
    try:
        return int(raw) if raw is not None else None
    except ValueError:
        return None


class PeerRegistry:
    """The live, non-conflicting appliances other than this one."""

    def __init__(self, *, local_id: Optional[str],
                 browser_factory: Callable[..., Any] = MdnsBrowser) -> None:
        """*local_id* is this appliance's id, which is never listed; a dial,
        which has none, passes None."""
        self._local_id = local_id
        self._lock = threading.Lock()
        self._conflict_ids: set[str] = set()
        self._conflict_logged: set[str] = set()
        self._subs: dict[int, Callable] = {}
        self._next_handle = 1
        self._browser = browser_factory(
            service_type=SERVICE_TYPE, parse_fn=self._parse,
            on_add=self._on_add, on_remove=self._on_remove, on_change=self._on_change)

    # -- public -----------------------------------------------------------

    def start(self, shutdown_event: Optional[threading.Event] = None) -> None:
        """Start browsing. Idempotent."""
        self._browser.start(shutdown_event=shutdown_event)

    def stop(self) -> None:
        self._browser.stop()
        with self._lock:
            self._conflict_ids.clear()
            self._conflict_logged.clear()

    def sightings(self) -> dict[str, Sighting]:
        """The live sightings by id, without conflicts."""
        conflicts = self.conflicts()
        return {i: s for i, s in self._browser.get_snapshot().items() if i not in conflicts}

    def conflicts(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._conflict_ids)

    def subscribe(self, fn: Callable[[str, str, Optional[Sighting]], None]) -> int:
        """Call ``fn(kind, id, sighting)`` on each change: kind is "add",
        "change" or "remove" (the sighting is None for a remove). It runs on
        the browser's thread outside the registry's lock and must not do
        network I/O."""
        with self._lock:
            handle = self._next_handle
            self._next_handle += 1
            self._subs[handle] = fn
        return handle

    def unsubscribe(self, handle: int) -> None:
        with self._lock:
            self._subs.pop(handle, None)

    def set_grace_period(self, seconds: int) -> None:
        """How long a sighting outlives its last announcement."""
        self._browser.set_grace_period(seconds)

    # -- browser callbacks ------------------------------------------------

    def _live_hostnames(self, peer_id: str, besides: Optional[Sighting] = None) -> set[str]:
        """The hostnames the live records of *peer_id* carry, with *besides*
        standing in for any record of its own service."""
        names = {m.hostname for m in self._browser.get_models(peer_id)
                 if besides is None or m.service_name != besides.service_name}
        if besides is not None:
            names.add(besides.hostname)
        return names

    def _parse(self, parts: list, txt: dict) -> Optional[tuple[str, Sighting]]:
        peer_id = txt.get("id", "")
        if not _ID_RE.fullmatch(peer_id):
            return None
        if self._local_id and peer_id == self._local_id:
            return None
        try:
            port = int(parts[8])
        except (ValueError, IndexError):
            port = 80
        service_name = parts[3]
        hostname = _trim_hostname(parts[6])
        sighting = Sighting(
            id=peer_id, hostname=hostname, ip=parts[7], port=port,
            version=txt.get("version", ""), control=txt.get("control", "on") != "off",
            proto=_proto(txt.get("proto")), service_name=service_name)
        hostnames = self._live_hostnames(peer_id, sighting)
        appeared = cleared = False
        with self._lock:
            in_conflict = peer_id in self._conflict_ids
            if len(hostnames) > 1 and not in_conflict:
                self._conflict_ids.add(peer_id)
                appeared = True
                if peer_id not in self._conflict_logged:
                    self._conflict_logged.add(peer_id)
                    logging.warning("appliance id conflict: id=%s hostnames=[%s]",
                                    peer_id, ", ".join(sorted(hostnames)))
            elif len(hostnames) <= 1 and in_conflict:
                self._conflict_ids.discard(peer_id)
                cleared = True
        # The sighting is returned even in conflict, so the browser keeps
        # tracking it and reports its removal.
        if appeared:
            self._notify("remove", peer_id, None)
        elif cleared:
            self._notify("add", peer_id, sighting)
        return peer_id, sighting

    def _on_add(self, peer_id: str, sighting: Sighting) -> None:
        if peer_id not in self.conflicts():
            self._notify("add", peer_id, sighting)

    def _on_change(self, peer_id: str, old: Optional[Sighting], new: Sighting) -> None:
        conflicting = len(self._live_hostnames(peer_id)) > 1
        with self._lock:
            was_conflict = peer_id in self._conflict_ids
            if not conflicting:
                self._conflict_ids.discard(peer_id)
        if conflicting:
            return
        self._notify("add" if was_conflict else "change", peer_id, new)

    def _on_remove(self, peer_id: str, sighting: Optional[Sighting]) -> None:
        # The browser's last record for the id is gone.
        with self._lock:
            was_conflict = peer_id in self._conflict_ids
            self._conflict_ids.discard(peer_id)
            self._conflict_logged.discard(peer_id)
        if not was_conflict:
            self._notify("remove", peer_id, None)

    def _notify(self, kind: str, peer_id: str, sighting: Optional[Sighting]) -> None:
        with self._lock:
            subs = list(self._subs.values())
        for fn in subs:
            try:
                fn(kind, peer_id, sighting)
            except Exception:
                logging.debug("peer registry: a subscriber raised", exc_info=True)
