#!/usr/bin/env bash
#
# installer/lib/handover.sh
#
# Keeping a fresh install alive when the login session it was started from
# ends. A fresh install takes twenty to forty minutes, often over Wi-Fi, and a
# process left running in an SSH session is stopped with that session when the
# connection drops (or when logind drops the session for any reason). Started
# from a login session, the installer asks its questions, then runs itself
# again as a transient system service that no session owns, and follows that
# service's log on the terminal until it ends. The service has no terminal, so
# every question must be answered before the hand-over; the end-of-install
# reboot question is asked by the process that holds the terminal.
#
# An --update is not handed over: the updaters start it as a transient service
# already.
#
# Sourced by autostream_install.sh and installer/dial/helpers.sh; not executed
# directly.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

# Where the process's control group is read from, and the directory that exists
# only when systemd is the init system; variables so a test can point them at a
# sandbox.
HANDOVER_CGROUP_FILE="${HANDOVER_CGROUP_FILE:-/proc/self/cgroup}"
HANDOVER_SYSTEMD_DIR="${HANDOVER_SYSTEMD_DIR:-/run/systemd/system}"

# Environment passed on to the service, which otherwise starts with a clean one:
# the release the installer records and the user who started it.
HANDOVER_ENV_VARS=(AUTOSTREAM_RELEASE_TAG SUDO_USER SUDO_UID SUDO_GID)

# in_login_session: succeeds when this process belongs to a login session (an
# SSH login, a console login, su or sudo from either), the only place a process
# is stopped along with the session. A system service is not.
in_login_session() {
  grep -qE '(^|/)session-[0-9]+\.scope(/|$)' "${HANDOVER_CGROUP_FILE}" 2>/dev/null
}

# handover_available: succeeds when the hand-over can be made and is wanted:
# root, on a systemd machine, with systemd-run, in a login session, and not
# already the service the hand-over started.
handover_available() {
  [[ "${AUTOSTREAM_HANDED_OVER:-0}" != "1" ]] || return 1
  [[ "$(id -u)" == "0" ]] || return 1
  [[ -d "${HANDOVER_SYSTEMD_DIR}" ]] || return 1
  command -v systemd-run >/dev/null 2>&1 || return 1
  in_login_session
}

# handover_refuse_if_running: when a hand-over would be made, stop at once if an
# install it started earlier is still running as UNIT, saying how to follow it
# and how to stop it. Call it before asking anything or writing anything, so a
# second run changes nothing.
# Usage: handover_refuse_if_running UNIT LOGFILE
handover_refuse_if_running() {
  local unit="$1" logfile="$2"
  handover_available || return 0
  if systemctl is-active --quiet "${unit}.service" 2>/dev/null; then
    printf '%s\n' "[ERROR] An install is already running as ${unit}.service; nothing has been changed." \
      "[ERROR] Follow it with: tail -f ${logfile}  (or: journalctl -fu ${unit})" \
      "[ERROR] To stop it: sudo systemctl stop ${unit}" >&2
    exit 1
  fi
}

# follow_log_until: show what is appended to FILE from byte START until the
# process PID ends, and what it wrote at the end. A file that is not a regular
# file, or is a link, is not read (the log sits in a directory the service
# account may own). A file that shrank (rotated) is read again from the top.
# Usage: follow_log_until PID FILE START
follow_log_until() {
  local pid="$1" file="$2" off="$3" size alive
  while :; do
    alive=1
    kill -0 "${pid}" 2>/dev/null || alive=0
    if [[ -f "${file}" && ! -L "${file}" ]]; then
      size="$(stat -c %s -- "${file}" 2>/dev/null || echo 0)"
      if [[ "${size}" -lt "${off}" ]]; then
        off=0
      fi
      if [[ "${size}" -gt "${off}" ]]; then
        tail -c "+$((off + 1))" -- "${file}" 2>/dev/null | head -c "$((size - off))" || true
        off="${size}"
      fi
    fi
    [[ "${alive}" -eq 1 ]] || break
    sleep "${HANDOVER_POLL_SECONDS:-1}"
  done
}

# hand_over_to_unit: run SCRIPT with ARGS again as the transient system service
# UNIT, in the same directory and with the environment it needs, and follow
# LOGFILE until the service ends. When the service ran, return 0 with its exit
# status in HANDOVER_RC, for the caller to act on (it holds the terminal, so it
# asks the reboot question). Return 1, with the reason on standard error, when
# the hand-over is not available or the service could not be started, so the
# caller can carry on in this process.
# Usage: hand_over_to_unit UNIT SCRIPT LOGFILE [ARGS...]
hand_over_to_unit() {
  local unit="$1" script="$2" logfile="$3"
  shift 3
  handover_available || return 1
  handover_refuse_if_running "${unit}" "${logfile}"

  local -a cmd=(systemd-run --collect --wait "--unit=${unit}"
                "--description=autostream installer"
                "--working-directory=${PWD}" --setenv=AUTOSTREAM_HANDED_OVER=1)
  local var
  for var in "${HANDOVER_ENV_VARS[@]}"; do
    if [[ -n "${!var:-}" ]]; then
      cmd+=("--setenv=${var}=${!var}")
    fi
  done
  cmd+=(-- bash "${script}" "$@")

  local out start=0 pid rc=0
  out="$(mktemp)"
  if [[ -f "${logfile}" && ! -L "${logfile}" ]]; then
    start="$(stat -c %s -- "${logfile}" 2>/dev/null || echo 0)"
  fi

  printf '%s\n' "[INFO] Handing the install over to the system service ${unit}.service," \
    "[INFO] so that it carries on if this session ends. Progress is shown from" \
    "[INFO] ${logfile}; the same output is in the journal (journalctl -u ${unit})."
  "${cmd[@]}" < /dev/null > "${out}" 2>&1 &
  pid=$!
  # Leaving early (Ctrl-C, a closed terminal) leaves the service running.
  trap 'printf "%s\n" "[INFO] Leaving the install running as ${unit}.service; follow it with: journalctl -fu ${unit}" >&2; exit 1' INT TERM HUP
  follow_log_until "${pid}" "${logfile}" "${start}"
  wait "${pid}" || rc=$?
  trap - INT TERM HUP

  if [[ "${rc}" -ne 0 ]] && ! grep -q 'Running as unit' "${out}"; then
    # The service never started: nothing ran, so the install can go on here.
    printf '%s\n' "[WARN] Could not start ${unit}.service: $(tr '\n' ' ' < "${out}")" >&2
    rm -f "${out}"
    return 1
  fi
  cat "${out}"
  rm -f "${out}"
  # shellcheck disable=SC2034  # read by the installer that sourced this file
  HANDOVER_RC="${rc}"
  return 0
}

# stay_running_after_hangup: for an install that could not be handed over,
# ignore the hang-up a closing terminal sends, so it is not stopped by that
# alone. It does not protect against the session itself being removed.
stay_running_after_hangup() {
  trap '' HUP
}
