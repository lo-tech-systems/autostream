#!/usr/bin/env bash
# measure_memory.sh — one CSV line of the coordinator process's memory.
#
# Usage:
#   sudo bash tools/measure_memory.sh --label before-change
#   bash tools/measure_memory.sh --header      # print the column names only
#
# Prints: label,unix_time,VmRSS_kB,VmHWM_kB,Pss_kB,threads,MemAvailable_kB
#
# The process is the main PID of the autostream service. VmRSS, VmHWM and the
# thread count come from /proc/PID/status, Pss from /proc/PID/smaps_rollup
# (readable by root only, so run this as root) and MemAvailable from
# /proc/meminfo. Compare runs only on the same board, kernel, virtual
# environment and OwnTone build.
#
# Environment:
#   PROC_ROOT  where /proc is read from (default /proc; a test points it at a
#              scratch tree)
#   SERVICE    the systemd unit whose main process is measured (default
#              autostream)

set -euo pipefail

PROC_ROOT="${PROC_ROOT:-/proc}"
SERVICE="${SERVICE:-autostream}"
HEADER="label,unix_time,VmRSS_kB,VmHWM_kB,Pss_kB,threads,MemAvailable_kB"

usage() {
    echo "Usage: $0 --label LABEL | --header" >&2
    exit 2
}

label=""
while [ $# -gt 0 ]; do
    case "$1" in
        --label)  [ $# -ge 2 ] || usage; label="$2"; shift 2 ;;
        --header) echo "${HEADER}"; exit 0 ;;
        *)        usage ;;
    esac
done
[ -n "${label}" ] || usage
case "${label}" in
    *,*|*[[:space:]]*) echo "label must not contain commas or white space" >&2; exit 2 ;;
esac

pid="$(systemctl show -p MainPID --value "${SERVICE}")"
if ! [[ "${pid}" =~ ^[0-9]+$ ]] || [ "${pid}" -eq 0 ]; then
    echo "${SERVICE} has no running main process" >&2
    exit 1
fi

# field FILE KEY: the first number on the line that starts "KEY:".
field() {
    awk -v key="$2:" '$1 == key { print $2; exit }' "$1" 2>/dev/null || true
}

status="${PROC_ROOT}/${pid}/status"
rollup="${PROC_ROOT}/${pid}/smaps_rollup"
meminfo="${PROC_ROOT}/meminfo"

vmrss="$(field "${status}" VmRSS)"
vmhwm="$(field "${status}" VmHWM)"
threads="$(field "${status}" Threads)"
pss="$(field "${rollup}" Pss)"
avail="$(field "${meminfo}" MemAvailable)"

for value in "${vmrss}" "${vmhwm}" "${threads}" "${pss}" "${avail}"; do
    if [ -z "${value}" ]; then
        echo "could not read every figure for process ${pid} (smaps_rollup needs root)" >&2
        exit 1
    fi
done

echo "${label},$(date +%s),${vmrss},${vmhwm},${pss},${threads},${avail}"
