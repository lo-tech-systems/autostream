#!/usr/bin/env bash
# This file is part of autostream.
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

set -euo pipefail

# Match autostream_sysutils default path/env behaviour
AUTOSTREAM_ADMIN_BIN="${AUTOSTREAM_ADMIN_BIN:-/usr/local/libexec/autostream/autostream_admin}"

if [[ "${REQUEST_METHOD:-}" != "POST" ]]; then
  printf "Status: 405 Method Not Allowed\r\n"
  printf "Allow: POST\r\n"
  printf "Content-Type: text/plain; charset=utf-8\r\n"
  printf "Cache-Control: no-store\r\n"
  printf "\r\n"
  printf "Method not allowed\n"
  exit 1
fi

if [[ -n "${HTTP_ORIGIN:-}" ]]; then
  origin_host="${HTTP_ORIGIN#*://}"
  origin_host="${origin_host%%/*}"
  if [[ "${origin_host}" != "${HTTP_HOST:-}" ]]; then
    printf "Status: 403 Forbidden\r\n"
    printf "Content-Type: text/plain; charset=utf-8\r\n"
    printf "Cache-Control: no-store\r\n"
    printf "\r\n"
    printf "Forbidden\n"
    exit 1
  fi
fi

if [[ "${HTTP_X_REQUESTED_WITH:-}" != "XMLHttpRequest" ]]; then
  printf "Status: 400 Bad Request\r\n"
  printf "Content-Type: text/plain; charset=utf-8\r\n"
  printf "Cache-Control: no-store\r\n"
  printf "\r\n"
  printf "Bad Request\n"
  exit 1
fi

# No credential check: the offline recovery page is only reachable in AP mode
# or on a trusted LAN. POST enforcement and same-origin checks above prevent
# CSRF from remote pages. Trusted LAN users may invoke recovery actions.

# Schedule factory reset via the privileged helper.
# The helper uses systemd-run to escape the service cgroup and returns
# immediately; the actual reset runs ~1s later as a transient systemd unit.
if /usr/bin/sudo -n "$AUTOSTREAM_ADMIN_BIN" factory-reset >/dev/null 2>&1; then
  # Redirect to nginx-served factory reset holding page
  printf "Status: 302 Found\r\n"
  printf "Location: /offline/resetting\r\n"
  printf "Cache-Control: no-store\r\n"
  printf "\r\n"
  exit 0
fi

# If scheduling failed, return an error (still offline-safe)
printf "Status: 500 Internal Server Error\r\n"
printf "Content-Type: text/plain; charset=utf-8\r\n"
printf "Cache-Control: no-store\r\n"
printf "\r\n"
printf "Unable to initiate factory reset. Please power-cycle the autostream platform. A re-image may be necessary.\n"
