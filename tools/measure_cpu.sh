#!/usr/bin/env bash
# measure_cpu.sh — the coordinator process's CPU use over an interval.
#
# Usage:
#   bash tools/measure_cpu.sh [--label LABEL] [--seconds N]
#
# Reads utime and stime (fields 14 and 15 of /proc/PID/stat) and the clock
# tick rate before and after waiting N seconds (default 600), and prints:
#   label,seconds,cpu_seconds,percent_of_one_core
#
# The process is the main PID of the autostream service. Compare runs only on
# the same board, kernel, virtual environment and OwnTone build, in the same
# state (for example, idle with one page open).
#
# Environment:
#   PROC_ROOT  where /proc is read from (default /proc; a test points it at a
#              scratch tree)
#   SERVICE    the systemd unit whose main process is measured (default
#              autostream)

set -euo pipefail

PROC_ROOT="${PROC_ROOT:-/proc}"
SERVICE="${SERVICE:-autostream}"

usage() {
    echo "Usage: $0 [--label LABEL] [--seconds N]" >&2
    exit 2
}

label="cpu"
seconds=600
while [ $# -gt 0 ]; do
    case "$1" in
        --label)   [ $# -ge 2 ] || usage; label="$2"; shift 2 ;;
        --seconds) [ $# -ge 2 ] || usage; seconds="$2"; shift 2 ;;
        *)         usage ;;
    esac
done
if ! [[ "${seconds}" =~ ^[0-9]+$ ]] || [ "${seconds}" -le 0 ]; then
    usage
fi
case "${label}" in
    *,*|*[[:space:]]*) echo "label must not contain commas or white space" >&2; exit 2 ;;
esac

pid="$(systemctl show -p MainPID --value "${SERVICE}")"
if ! [[ "${pid}" =~ ^[0-9]+$ ]] || [ "${pid}" -eq 0 ]; then
    echo "${SERVICE} has no running main process" >&2
    exit 1
fi

tick="$(getconf CLK_TCK)"
stat_file="${PROC_ROOT}/${pid}/stat"

# cpu_ticks: utime + stime. The command name (field 2) may hold spaces and
# brackets, so the fields are counted from after its closing bracket, where
# utime and stime are the 12th and 13th.
cpu_ticks() {
    local line rest
    line="$(cat "${stat_file}")"
    rest="${line##*) }"
    # shellcheck disable=SC2086  # word splitting of the stat fields is the point
    set -- ${rest}
    echo $(( ${12} + ${13} ))
}

before="$(cpu_ticks)"
sleep "${seconds}"
after="$(cpu_ticks)"

awk -v label="${label}" -v secs="${seconds}" -v b="${before}" -v a="${after}" -v tick="${tick}" '
    BEGIN {
        cpu = (a - b) / tick
        printf "%s,%d,%.2f,%.2f\n", label, secs, cpu, cpu / secs * 100
    }'
