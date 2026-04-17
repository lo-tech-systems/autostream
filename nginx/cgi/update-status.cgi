#!/usr/bin/env bash
# This file is part of autostream.
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

set -euo pipefail

AUTOSTREAM_ADMIN_BIN="${AUTOSTREAM_ADMIN_BIN:-/usr/local/libexec/autostream/autostream_admin}"

printf "Status: 200 OK\r\n"
printf "Content-Type: application/json; charset=utf-8\r\n"
printf "Cache-Control: no-store\r\n"
printf "Pragma: no-cache\r\n"
printf "Expires: 0\r\n"
printf "\r\n"

if json="$(/usr/bin/sudo -n "$AUTOSTREAM_ADMIN_BIN" update-status 2>/dev/null)"; then
  printf "%s\n" "${json}"
  exit 0
fi

printf '{"ok":false,"last_run_at":"","status":"error","message":"Unable to read update status","percent":0}\n'
