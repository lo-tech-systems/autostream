"""tests/nginx_helpers.py

Helpers for tests that run nginx unprivileged: a free port, and a copy of a
shipped config with its listen ports and log paths moved somewhere a normal
user can bind and write.
"""
from __future__ import annotations

import re
from pathlib import Path

_LISTEN_PORT_RE = re.compile(r"(\blisten\s+(?:\[[^\]]*\]:|[\w.]+:)?)(\d+)\b")
_LOG_PATH_RE = re.compile(r"(\b(?:access_log|error_log)\s+)(/[^\s;]+)")


def free_port() -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def copy_for_unprivileged_check(src: Path, dst_dir: Path, ports: dict[int, int]) -> Path:
    """Copy *src* into *dst_dir* ready for an unprivileged nginx -t, which
    binds every listen socket and opens every log file named: each listen
    port moves to a free unprivileged one (the same port always to the same
    replacement, so a server listening on IPv4 and IPv6 stays one server),
    since ports below 1024 need privilege and a local nginx may already
    serve the real one; and each absolute access_log/error_log file moves
    into *dst_dir*, since the system log directory is not writable. Only
    port numbers and log file paths change; every other directive, log
    formats and conditions included, is checked as deployed."""
    def port(m: re.Match) -> str:
        p = int(m.group(2))
        if p not in ports:
            ports[p] = free_port()
        return f"{m.group(1)}{ports[p]}"

    def log_path(m: re.Match) -> str:
        return f"{m.group(1)}{(dst_dir / Path(m.group(2)).name).as_posix()}"

    text = src.read_text(encoding="utf-8")
    text = _LOG_PATH_RE.sub(log_path, _LISTEN_PORT_RE.sub(port, text))
    dst = dst_dir / src.name
    dst.write_text(text, encoding="utf-8")
    return dst

