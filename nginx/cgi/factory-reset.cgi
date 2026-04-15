#!/usr/bin/env bash
# This file is part of autostream.
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

set -euo pipefail

# Match autostream_sysutils default path/env behaviour
AUTOSTREAM_ADMIN_BIN="${AUTOSTREAM_ADMIN_BIN:-/usr/local/libexec/autostream/autostream_admin}"

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
