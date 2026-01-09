#!/usr/bin/env bash
# This file is part of autostream.
# Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

set -euo pipefail

# Match autostream_sysutils default path/env behaviour
AUTOSTREAM_ADMIN_BIN="${AUTOSTREAM_ADMIN_BIN:-/usr/local/libexec/autostream/autostream_admin}"

REASON="UserRequestSystemError"

# Request reboot via the privileged helper
# Use full sudo path for fcgiwrap environments with minimal PATH.
if /usr/bin/sudo -n "$AUTOSTREAM_ADMIN_BIN" reboot --delay 3 "$REASON" >/dev/null 2>&1; then
  # Redirect to branded rebooting page
  printf "Status: 302 Found\r\n"
  printf "Location: /offline/rebooting\r\n"
  printf "Cache-Control: no-store\r\n"
  printf "\r\n"
  exit 0
fi

# If reboot request failed, return an error page (still offline-safe)
printf "Status: 500 Internal Server Error\r\n"
printf "Content-Type: text/plain; charset=utf-8\r\n"
printf "Cache-Control: no-store\r\n"
printf "\r\n"
printf "Unable to reboot device. Please power-cycle the autostream platform. A re-image may be necessary.\n"
