#!/usr/bin/env bash
#
# installer/lib/output_log.sh
#
# Finishing the install log. An installer copies its output into a log through
# a writer process it starts with process substitution. Left alone, the writer
# is still holding output when the installer exits: the last lines are missing
# from the log, and when the installer runs as a system service the service's
# control group is killed as soon as the installer's own process ends, so the
# writer is killed before it has written them. finish_output_log gives the
# terminal (or the journal) back, so the writer sees the end of its input, and
# waits for it to finish.
#
# Sourced by autostream_install.sh and autostream_dial_install.sh; not executed
# directly.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

# What the installer sets up, and finish_output_log undoes:
#   OUTPUT_LOG_SAVED_OUT/ERR  descriptors holding the original stdout/stderr
#                             (made by save_terminal_output)
#   OUTPUT_LOG_TEE_PID        process that standard output now goes to
#   OUTPUT_LOG_WRITER_FD/PID  a second descriptor and process behind the first,
#                             if it writes into another process
OUTPUT_LOG_SAVED_OUT=""
OUTPUT_LOG_SAVED_ERR=""
OUTPUT_LOG_TEE_PID=""
OUTPUT_LOG_WRITER_FD=""
OUTPUT_LOG_WRITER_PID=""
# How long to wait for a writer, in tenths of a second. A child that was left
# running with the output open would otherwise hold the shutdown up for good.
OUTPUT_LOG_WAIT_TENTHS="${OUTPUT_LOG_WAIT_TENTHS:-100}"

# save_terminal_output: keep the current standard output and error, to be
# given back by finish_output_log. Call before redirecting them.
save_terminal_output() {
  exec {OUTPUT_LOG_SAVED_OUT}>&1 {OUTPUT_LOG_SAVED_ERR}>&2
}

_output_log_wait() {
  local pid="$1" tenths=0
  # The pause is a read that times out on a pipe nothing writes to, not sleep:
  # sleep is an external command, which a minimal system or a wrapper may replace.
  local pause _
  exec {pause}<> <(:)
  while kill -0 "${pid}" 2>/dev/null && [[ "${tenths}" -lt "${OUTPUT_LOG_WAIT_TENTHS}" ]]; do
    read -r -t 0.1 -u "${pause}" _ || true
    tenths=$((tenths + 1))
  done
  exec {pause}>&-
  if kill -0 "${pid}" 2>/dev/null; then
    echo "[WARN] the log writer (pid ${pid}) did not finish; the end of the log may be missing" >&2
  else
    wait "${pid}" 2>/dev/null || true
  fi
}

# finish_output_log: give standard output and error back, wait until the log
# writer has taken in and written everything, and forget it. Safe to call more
# than once, or when no writer was started. Call it last: nothing written after
# it reaches the log.
finish_output_log() {
  [[ -n "${OUTPUT_LOG_TEE_PID}" ]] || return 0
  local tee_pid="${OUTPUT_LOG_TEE_PID}" writer_pid="${OUTPUT_LOG_WRITER_PID}"
  OUTPUT_LOG_TEE_PID=""
  OUTPUT_LOG_WRITER_PID=""
  # Closing our copies of the pipe into the writer ends its input.
  exec 1>&"${OUTPUT_LOG_SAVED_OUT}" 2>&"${OUTPUT_LOG_SAVED_ERR}"
  exec {OUTPUT_LOG_SAVED_OUT}>&- {OUTPUT_LOG_SAVED_ERR}>&-
  _output_log_wait "${tee_pid}"
  if [[ -n "${OUTPUT_LOG_WRITER_FD}" ]]; then
    exec {OUTPUT_LOG_WRITER_FD}>&-
    OUTPUT_LOG_WRITER_FD=""
    _output_log_wait "${writer_pid}"
  fi
}
