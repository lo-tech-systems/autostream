#!/usr/bin/env bash
# This file is part of autostream.
# Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

set -euo pipefail

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

if [[ "${REQUEST_METHOD:-}" != "POST" ]]; then
  printf "Status: 405 Method Not Allowed\r\n"
  printf "Allow: POST\r\n"
  printf "Content-Type: text/plain; charset=utf-8\r\n"
  printf "Cache-Control: no-store\r\n"
  printf "\r\n"
  printf "Method not allowed\n"
  exit 1
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

TS="$(date +%Y%m%d%H%M%S)"
FNAME="autostream-logs-${TS}.zip"
ZIP_PATH="/tmp/${FNAME}"
STAGE_DIR="$(mktemp -d /tmp/autostream-logs.XXXXXX)"

cleanup() {
  rm -f "${ZIP_PATH}" 2>/dev/null || true
  rm -rf "${STAGE_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "${STAGE_DIR}/autostream" "${STAGE_DIR}/owntone"

# Where the logs live; overridable so tests can point at scratch files (CGI
# clients cannot set these: request headers only ever arrive as HTTP_*
# variables).
LOG_DIR="${AUTOSTREAM_LOG_DIR:-/var/log/autostream}"
OWNTONE_LOG="${AUTOSTREAM_OWNTONE_LOG:-/var/log/owntone.log}"

added_any=0

# Everything in the autostream log directory, every rotation included: the
# appliance's journal is volatile, so these files are its history.
shopt -s nullglob
for src in "${LOG_DIR}"/*; do
  if [ -f "${src}" ] && [ -r "${src}" ]; then
    cp -f "${src}" "${STAGE_DIR}/autostream/$(basename "${src}")"
    added_any=1
  fi
done
shopt -u nullglob

# OwnTone's log with its three most recent rotations (.1 uncompressed under
# delaycompress, older ones .N.gz; either form accepted for each).
for f in "${OWNTONE_LOG}" "${OWNTONE_LOG}.1" "${OWNTONE_LOG}.1.gz" "${OWNTONE_LOG}.2" \
         "${OWNTONE_LOG}.2.gz" "${OWNTONE_LOG}.3" "${OWNTONE_LOG}.3.gz"; do
  if [ -f "${f}" ] && [ -r "${f}" ]; then
    cp -f "${f}" "${STAGE_DIR}/owntone/$(basename "${f}")"
    added_any=1
  fi
done

if [ "${added_any}" -eq 0 ]; then
  cat > "${STAGE_DIR}/README.txt" <<EOF
No readable log files were found for bundling.

Checked:
- ${LOG_DIR}/*
- ${OWNTONE_LOG}, with its three most recent rotations

Some files may exist but be unreadable to the nginx/fcgiwrap user.
EOF
fi

(
  cd "${STAGE_DIR}"
  /usr/bin/zip -q -r "${ZIP_PATH}" .
)

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
