#!/bin/bash

# autostream_rebooter.sh
#
# This file is part of autostream.
# Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.
#
# This script is called by systemd if the WATCH_FILE is present.
# It's purpose is to log the reason then reboot the host.
#
# The WATCH_FILE is expected to contain the reason, which is written
# to the log. Reasons are:
#
# AutostreamUpdate          Set by autostream_webui after updates.
# UserRequestNormal         Set by autostream_webui if user hits button.
# UserRequestSystemError    Set by NGINX 50x handler when user requests.
# NetworkDown               Set by autostream_wifi_watcher.service
#

set -euo pipefail

WATCH_FILE="/tmp/rebootrequired"
LOG_FILE="${LOG_FILE:-/var/log/rebootrequired.log}"

# Rate-limit state (only used for NetworkDown)
STATE_DIR="/run/rebootrequired"
STAMP_FILE="$STATE_DIR/networkdown.last"

mkdir -p "$STATE_DIR"

if [[ ! -e "$WATCH_FILE" ]]; then
  exit 0
fi

# Grab first line as the reason (trim CR if present)
reason="$(head -n 1 "$WATCH_FILE" | tr -d '\r')"
if [[ -z "${reason}" ]]; then
  reason="(no reason provided)"
fi

ts="$(date -Is)"

# Rate-limit NetworkDown to once per hour
if [[ "$reason" == "NetworkDown" ]]; then
  now_epoch="$(date +%s)"
  if [[ -f "$STAMP_FILE" ]]; then
    last_epoch="$(cat "$STAMP_FILE" 2>/dev/null || echo 0)"
  else
    last_epoch=0
  fi

  # 3600 seconds = 1 hour
  if (( now_epoch - last_epoch < 3600 )); then
    remaining=$(( 3600 - (now_epoch - last_epoch) ))
    printf '%s rebootrequired: %s (rate-limited; %ss remaining)\n' "$ts" "$reason" "$remaining" >> "$LOG_FILE"

    # Clear the request file so we don't re-trigger immediately in a tight loop
    rm -f "$WATCH_FILE"
    exit 0
  fi

  echo "$now_epoch" > "$STAMP_FILE"
fi

printf '%s rebootrequired: %s\n' "$ts" "$reason" >> "$LOG_FILE"

# Clear the trigger file to avoid re-trigger loops
rm -f "$WATCH_FILE"

# Reboot
/sbin/reboot
