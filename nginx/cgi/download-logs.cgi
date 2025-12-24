#!/usr/bin/env bash
# This file is part of autostream.
# Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

set -euo pipefail

LOG_GLOB="/var/log/autostream/"'*.log'
TS="$(date +%Y%m%d%H%M%S)"
FNAME="autostream-logs-${TS}.zip"
ZIP_PATH="/tmp/${FNAME}"

# Create zip (quiet). If no logs, create an empty zip with a note.
shopt -s nullglob
logs=(/var/log/autostream/*.log)
shopt -u nullglob

if [ "${#logs[@]}" -gt 0 ]; then
  /usr/bin/zip -q -j "${ZIP_PATH}" "${logs[@]}"
else
  tmpnote="/tmp/autostream-logs-${TS}.txt"
  echo "No log files found matching ${LOG_GLOB}" > "${tmpnote}"
  /usr/bin/zip -q -j "${ZIP_PATH}" "${tmpnote}"
  rm -f "${tmpnote}"
fi

SIZE="$(stat -c%s "${ZIP_PATH}")"

printf "Status: 200 OK\r\n"

# Use octet-stream to discourage any attempt to “open” the zip inline.
printf "Content-Type: application/octet-stream\r\n"
printf "X-Content-Type-Options: nosniff\r\n"

# Provide both filename= and filename*= (RFC 5987) for broader client compatibility.
printf "Content-Disposition: attachment; filename=\"%s\"; filename*=UTF-8''%s\r\n" "${FNAME}" "${FNAME}"

printf "Content-Length: %s\r\n" "${SIZE}"

# Avoid caching weirdness in iOS webviews/standalone
printf "Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n"
printf "Pragma: no-cache\r\n"
printf "Expires: 0\r\n"

# Some clients still look at this
printf "Content-Transfer-Encoding: binary\r\n"

printf "\r\n"

cat "${ZIP_PATH}"
rm -f "${ZIP_PATH}"
