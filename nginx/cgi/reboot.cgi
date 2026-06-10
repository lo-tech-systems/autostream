#!/usr/bin/env bash
# This file is part of autostream.
# Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

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
