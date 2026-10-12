#!/usr/bin/env bash
#
# installer/lib/sudoers.sh
#
# Install a sudoers drop-in only if it parses. Shared by the appliance and dial
# installers; sourced, not executed directly.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

install_sudoers_file() {
  # A drop-in with a syntax error makes sudo refuse to start for the whole
  # system, the owner's login included, so the file is checked as a temporary
  # copy first and only a valid one replaces the installed file. A rejected
  # file leaves the existing one exactly as it was.
  # Usage: install_sudoers_file SOURCE DEST
  local src="$1" dest="$2" tmp
  local -a own=()
  [[ "${EUID:-$(id -u)}" -eq 0 ]] && own=(-o root -g root)

  if [[ ! -f "${src}" ]]; then
    echo "ERROR: sudoers file ${src} is missing; ${dest} was not changed." >&2
    return 1
  fi
  if ! command -v visudo >/dev/null 2>&1; then
    echo "WARNING: visudo not found; installing ${dest} without checking its syntax." >&2
    install -m 0440 ${own[@]+"${own[@]}"} "${src}" "${dest}"
    return
  fi
  tmp="$(mktemp)" || return 1
  install -m 0440 ${own[@]+"${own[@]}"} "${src}" "${tmp}"
  if ! visudo -cf "${tmp}"; then
    rm -f "${tmp}"
    echo "ERROR: ${src} is not valid sudoers syntax; ${dest} was not changed." >&2
    return 1
  fi
  install -m 0440 ${own[@]+"${own[@]}"} "${tmp}" "${dest}"
  rm -f "${tmp}"
}
