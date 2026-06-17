#!/usr/bin/env python3
"""autostream-dial-control — Operator CLI for the running autostream-dial service.

Connects to the local Unix-domain control socket and issues commands.

Usage:
    autostream-dial-control [--json] <command> [args]

Commands:
    ping
    version
    status
    targets [--json]
    nudge up
    nudge down
    nudge --delta <N>

Options:
    --json   Print the raw server response as compact JSON instead of
             human-readable output.  May appear before or after the subcommand.

Exit codes:
    0   Server returned ok:true
    1   Server returned ok:false
    2   CLI argument/usage error
    3   Socket missing, permission denied, timeout, or invalid server response

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
from typing import NoReturn

from dial_control_protocol import (
    CONTROL_CLIENT_CONNECT_TIMEOUT,
    CONTROL_CLIENT_RESPONSE_TIMEOUT,
    CONTROL_RESPONSE_MAX_BYTES,
    CONTROL_SOCKET_PATH,
)


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

def _send_command(sock_path: str, req: dict) -> dict:
    """Connect to sock_path, send req, and return the parsed response dict.

    Raises SystemExit(3) on any transport failure.
    """
    if not hasattr(socket, "AF_UNIX"):
        _transport_error("AF_UNIX is not available on this platform")

    line = json.dumps(req, separators=(",", ":")) + "\n"
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)  # type: ignore[attr-defined]
        s.settimeout(CONTROL_CLIENT_CONNECT_TIMEOUT)
        try:
            s.connect(sock_path)
        except FileNotFoundError:
            _transport_error(f"socket not found: {sock_path!r}")
        except PermissionError:
            _transport_error(f"permission denied: {sock_path!r}")
        except (ConnectionRefusedError, OSError) as e:
            _transport_error(str(e))

        s.settimeout(CONTROL_CLIENT_RESPONSE_TIMEOUT)
        try:
            s.sendall(line.encode("utf-8"))
        except OSError as e:
            _transport_error(f"send failed: {e}")

        # Read response
        buf = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if b"\n" in buf:
                    break
                if len(buf) > CONTROL_RESPONSE_MAX_BYTES:
                    _transport_error("response exceeded size limit")
        except socket.timeout:
            _transport_error("timed out waiting for response")
        except OSError as e:
            _transport_error(f"read failed: {e}")
    finally:
        try:
            s.close()
        except Exception:
            pass

    # Parse
    newline = buf.find(b"\n")
    if newline < 0:
        _transport_error("server response missing newline (truncated?)")
    response_bytes = buf[:newline]
    if len(response_bytes) >= CONTROL_RESPONSE_MAX_BYTES:
        _transport_error("server response line too long")

    try:
        resp = json.loads(response_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        _transport_error(f"malformed server response: {e}")

    if not isinstance(resp, dict):
        _transport_error("server response is not a JSON object")

    return resp  # type: ignore[return-value]


def _transport_error(msg: str) -> NoReturn:
    print(f"autostream-dial-control: {msg}", file=sys.stderr)
    sys.exit(3)


# ---------------------------------------------------------------------------
# Human-readable output formatters
# ---------------------------------------------------------------------------

def _format_ping(resp: dict) -> str:
    return "autostream-dial is responding."


def _format_version(resp: dict) -> str:
    proto = resp.get("protocol_version", "?")
    sw = resp.get("software_version", "?")
    return f"Control protocol v{proto}; autostream-dial {sw}."


def _format_status(resp: dict) -> str:
    lines = [
        f"Dial: {resp.get('name', '')}",
        f"UUID: {resp.get('uuid', '')}",
        f"Step: {resp.get('step_percent', '?')}%",
        f"Discovered targets: {resp.get('target_count', 0)}",
    ]
    active = resp.get("recovery_active", False)
    confirmed = resp.get("volume_confirmed", False)
    if active and confirmed:
        lines.append("PIN recovery: active (volume confirmed)")
    elif active:
        lines.append("PIN recovery: active")
    else:
        lines.append("PIN recovery: inactive")
    return "\n".join(lines)


def _format_targets(resp: dict) -> str:
    count = resp.get("count", 0)
    targets = resp.get("targets", [])
    if not targets:
        return "No compatible playing targets discovered."
    lines = [f"{count} compatible playing target{'s' if count != 1 else ''}"]
    for t in targets:
        name = t.get("name", "?")
        ip = t.get("ip", "?")
        port = t.get("port", 80)
        addr = f"{ip}:{port}"
        err = t.get("status_error")
        if err:
            lines.append(f"{name}  {addr}  volume=unknown  status={err}")
        else:
            vol = t.get("master_volume")
            outs = t.get("selected_output_count", "?")
            lines.append(f"{name}  {addr}  volume={vol}%  outputs={outs}")
    return "\n".join(lines)


def _format_nudge(resp: dict) -> str:
    delta = resp.get("delta", 0)
    count = resp.get("target_count", 0)
    sign = "+" if delta >= 0 else ""
    return f"Queued volume delta {sign}{delta} for {count} discovered targets."


_FORMATTERS = {
    "ping":    _format_ping,
    "version": _format_version,
    "status":  _format_status,
    "targets": _format_targets,
    "nudge":   _format_nudge,
}


# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="autostream-dial-control",
        description="Control the running autostream-dial service.",
        add_help=True,
    )
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("ping", help="Check that the service is responding.")
    sub.add_parser("version", help="Print protocol and software versions.")
    sub.add_parser("status", help="Print live dial status.")
    targets_p = sub.add_parser("targets", help="List discovered playing targets.")

    nudge_p = sub.add_parser("nudge", help="Queue a volume delta.")
    nudge_dir = nudge_p.add_mutually_exclusive_group(required=True)
    nudge_dir.add_argument(
        "direction", nargs="?", choices=["up", "down"],
        help="Direction: up or down."
    )
    nudge_dir.add_argument(
        "--delta", type=int, metavar="N",
        help="Explicit delta (-100..100, excluding 0).",
    )
    return p


def _build_request(args: argparse.Namespace) -> dict:
    req: dict = {"command": args.command}
    if args.command == "nudge":
        if args.delta is not None:
            req["delta"] = args.delta
        elif args.direction:
            req["direction"] = args.direction
        else:
            print("autostream-dial-control: nudge requires direction or --delta",
                  file=sys.stderr)
            sys.exit(2)
    return req


def main(argv: list[str] | None = None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    # Extract --json before argparse so it can appear anywhere
    json_count = argv.count("--json")
    if json_count > 1:
        print("autostream-dial-control: --json may only be specified once",
              file=sys.stderr)
        sys.exit(2)
    json_mode = json_count == 1
    if json_mode:
        argv = [a for a in argv if a != "--json"]

    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        sys.exit(2 if e.code != 0 else 0)

    req = _build_request(args)
    resp = _send_command(CONTROL_SOCKET_PATH, req)

    ok = resp.get("ok")
    if not isinstance(ok, bool):
        _transport_error("invalid server response: ok field missing or not a boolean")

    if json_mode:
        print(json.dumps(resp, separators=(",", ":"), sort_keys=True))
        sys.exit(0 if ok else 1)

    # Human-readable output
    if not ok:
        msg = resp.get("message") or resp.get("error") or "unknown error"
        if msg:
            print(msg, file=sys.stderr)
        sys.exit(1)

    # Validate command-specific fields before rendering to prevent crashes on
    # malformed local-server output.
    if args.command == "targets":
        targets = resp.get("targets")
        if not isinstance(targets, list) or not all(isinstance(t, dict) for t in targets):
            _transport_error("invalid server response: targets must be a list of objects")

    formatter = _FORMATTERS.get(args.command)
    if formatter:
        print(formatter(resp))
    sys.exit(0)


if __name__ == "__main__":
    main()
