"""dial_mdns.py — mDNS browser for _autostream-playing._tcp.

Scans for autostream appliances announcing _autostream-playing._tcp.  Only
entries that carry dial_api=v1 in their TXT record are tracked — earlier
appliances without this field are ignored.

IPv4 only.  5-tuple key deduplication per §6.2; get_playing_targets() returns
one entry per mDNS service name (deduplicated across interfaces) for fan-out.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass


@dataclass
class PlayingTarget:
    ip:           str
    port:         int
    name:         str
    dial_api:     bool = False
    audio_status: bool = False


_lock    = threading.Lock()
_by_key:  dict[tuple, PlayingTarget] = {}   # key: (iface, proto, name, type, domain)
_by_name: dict[str, PlayingTarget]   = {}   # key: mDNS service name; dedup across ifaces
_had_targets = False  # persists across avahi-browse restarts to suppress restart-cycle re-logs


def get_playing_targets() -> list[PlayingTarget]:
    """Return one entry per mDNS service name — deduplicated across interfaces."""
    with _lock:
        return list(_by_name.values())


def start_playing_browser() -> None:
    """Start the background mDNS browser for _autostream-playing._tcp."""
    threading.Thread(target=_browse_loop, daemon=True, name='mdns-browser').start()


def _parse_txt(raw: str) -> dict[str, str]:
    """Parse avahi TXT record string into key=value dict.  Uses shlex for
    double-quoted tokens and backslash escaping."""
    result: dict[str, str] = {}
    try:
        for token in shlex.split(raw):
            if '=' in token:
                k, _, v = token.partition('=')
                result[k] = v
    except ValueError as e:
        logging.debug("TXT parse error: %s", e)
    return result


def _browse_loop() -> None:
    while True:
        with _lock:
            _by_key.clear()
            _by_name.clear()
        try:
            proc = subprocess.Popen(
                ["avahi-browse", "--no-fail", "-p", "-r", "_autostream-playing._tcp"],
                stdout=subprocess.PIPE, text=True,
            )
            for line in proc.stdout:
                _handle_line(line.strip())
            logging.warning("mDNS browser: avahi-browse exited, restarting in 5 s")
        except Exception as e:
            logging.warning("mDNS browser: %s", e)
        time.sleep(5)


def _handle_line(line: str) -> None:
    parts = line.split(';')
    event = parts[0] if parts else ''

    if event == '=' and len(parts) >= 10 and parts[2] == 'IPv4':
        key      = tuple(parts[1:6])
        txt      = _parse_txt(parts[9])
        if txt.get('dial_api') != 'v1':
            return   # not a dial-capable appliance; ignore
        try:
            port = int(parts[8])
        except ValueError:
            port = 80
        svc_name = parts[3]
        target   = PlayingTarget(
            ip=parts[7],
            port=port,
            name=svc_name,
            dial_api=True,
            audio_status=(txt.get('audio_status') == 'v1'),
        )
        log_found = False
        with _lock:
            global _had_targets
            _by_key[key] = target
            if not _by_name and not _had_targets:
                log_found = True   # genuine 0→1 transition (not restart re-resolution)
                _had_targets = True
            _by_name[svc_name] = target
        if log_found:
            logging.info("playing target found: %s (%s)", svc_name, parts[7])

    elif event == '-' and len(parts) >= 6 and parts[2] == 'IPv4':
        key      = tuple(parts[1:6])
        log_gone = False
        with _lock:
            removed = _by_key.pop(key, None)
            if removed:
                svc_name = parts[3]
                # Only remove from _by_name when no other key for this service name remains
                remaining = next(
                    (t for k, t in _by_key.items() if k[2] == svc_name), None
                )
                if remaining:
                    _by_name[svc_name] = remaining   # update to live sighting
                else:
                    _by_name.pop(svc_name, None)
                    if not _by_name:
                        _had_targets = False
                        log_gone = True   # N→0 transition
        if log_gone:
            logging.info("no playing targets — encoder gated")
