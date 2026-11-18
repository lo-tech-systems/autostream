#!/usr/bin/env bash
# measure_setup_hwm.sh — how far two simultaneous Setup page requests raise
# the coordinator's peak memory.
#
# Usage:
#   sudo bash tools/measure_setup_hwm.sh --cookie JAR [--label LABEL]
#
# Reads VmHWM (the process's high-water mark) of the autostream service's main
# process, fetches /setup twice at the same time with the session in the
# cookie jar JAR, waits for both, reads VmHWM again, and prints:
#   label,VmHWM_before_kB,VmHWM_after_kB,step_kB
#
# The high-water mark only ever rises, so run this soon after a restart, or
# the step can read zero because an earlier peak was already higher.
#
# The cookie jar holds a signed-in session. On an appliance with a PIN, make it
# by posting the proof the PIN form computes (the SHA-256 of the nonce on the
# form followed by the PIN) to the sign-in endpoint:
#
#   base=http://localhost:8080
#   nonce=$(curl -s -c JAR "$base/auth" | sed -n 's/.*id="nonce" value="\([^"]*\)".*/\1/p')
#   proof=$(printf '%s%s' "$nonce" "$PIN" | sha256sum | cut -d' ' -f1)
#   curl -s -b JAR -c JAR -H 'Content-Type: application/json' \
#        -d "{\"nonce\":\"$nonce\",\"proof\":\"$proof\",\"next\":\"/setup\"}" \
#        "$base/api/auth/verify"
#
# Environment:
#   BASE_URL   the web interface (default http://localhost:8080)
#   PROC_ROOT  where /proc is read from (default /proc)
#   SERVICE    the systemd unit whose main process is measured (default
#              autostream)

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
PROC_ROOT="${PROC_ROOT:-/proc}"
SERVICE="${SERVICE:-autostream}"

usage() {
    echo "Usage: $0 --cookie JAR [--label LABEL]" >&2
    exit 2
}

jar=""
label="setup"
while [ $# -gt 0 ]; do
    case "$1" in
        --cookie) [ $# -ge 2 ] || usage; jar="$2"; shift 2 ;;
        --label)  [ $# -ge 2 ] || usage; label="$2"; shift 2 ;;
        *)        usage ;;
    esac
done
[ -n "${jar}" ] || usage
[ -f "${jar}" ] || { echo "cookie jar ${jar} not found" >&2; exit 2; }
case "${label}" in
    *,*|*[[:space:]]*) echo "label must not contain commas or white space" >&2; exit 2 ;;
esac

pid="$(systemctl show -p MainPID --value "${SERVICE}")"
if ! [[ "${pid}" =~ ^[0-9]+$ ]] || [ "${pid}" -eq 0 ]; then
    echo "${SERVICE} has no running main process" >&2
    exit 1
fi

hwm() {
    awk '$1 == "VmHWM:" { print $2; exit }' "${PROC_ROOT}/${pid}/status"
}

fetch() {
    curl -s -o /dev/null -b "${jar}" "${BASE_URL}/setup"
}

before="$(hwm)"
fetch &
first=$!
fetch &
second=$!
failed=0
wait "${first}" || failed=1
wait "${second}" || failed=1
if [ "${failed}" -ne 0 ]; then
    echo "a request for ${BASE_URL}/setup failed" >&2
    exit 1
fi
after="$(hwm)"

echo "${label},${before},${after},$(( after - before ))"
