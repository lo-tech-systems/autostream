#!/usr/bin/env bash
#
# installer/lib/state_files.sh
#
# Writing a state file as root into a directory that the service account also
# owns. That account can put a link, or any other file, at any name in its own
# directory, so a write that opens the final name (a redirect), or changes its
# mode or owner by name, can land somewhere else. The new content goes to a
# new file with an unpredictable name next to the old one instead, created so
# that nothing can already be there, with mode and owner set on the open file
# itself, and is then renamed over the old one. A rename replaces whatever
# is at the final name, a link included, and never follows it.
#
# Reading is the mirror of it: a state file root acts on is opened without
# following a link, and one that is not a regular file reads as absent.
#
# Sourced by installer/dial/helpers.sh and autostream_install.sh; not executed
# directly.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

# write_state_file: replace FILE with the content read from standard input.
# MODE is applied to the new file; OWNER (user or user:group) is applied when
# given, and otherwise the file belongs to whoever runs this. On any failure
# the new file is removed and FILE is as it was.
# Usage: write_state_file FILE MODE [OWNER] < content
write_state_file() {
  local file="$1" mode="$2" owner="${3:-}" tmp
  tmp="$(mktemp -u -- "$(dirname -- "${file}")/.$(basename -- "${file}").XXXXXXXXXX")" \
    || return 1
  # Under noclobber the shell creates the file exclusively, so it fails rather
  # than open something already there. Mode and owner are set through the
  # descriptor the shell holds open (standard output of the group), which is
  # that file whatever happens to its name.
  if ! (
    set -C
    {
      chmod "${mode}" "/proc/${BASHPID}/fd/1" &&
        { [[ -z "${owner}" ]] || chown "${owner}" "/proc/${BASHPID}/fd/1"; } &&
        cat
    } > "${tmp}"
  ) || ! mv -f -T -- "${tmp}" "${file}"; then
    rm -f -- "${tmp}"
    return 1
  fi
  return 0
}

# read_state_file: print FILE, at most 64 KiB of it, when it is a regular file
# reached without following a link; print nothing and return 1 otherwise. The
# file is opened with O_NOFOLLOW (and without blocking, so a pipe put there
# does not hold the installer up), so a link placed at the name after the
# check is refused as well. Use it for any read of a file in that directory
# whose content root acts on. The status is that of the open, not of the
# content: an empty file prints nothing and succeeds.
# Usage: content="$(read_state_file FILE)" || ...
read_state_file() {
  local file="$1"
  [[ -f "${file}" && ! -L "${file}" ]] || return 1
  dd if="${file}" iflag=nofollow,nonblock bs=65536 count=1 status=none 2>/dev/null
}

# read_state_value: print the value of the first KEY=VALUE line of FILE, read
# as read_state_file reads it; print nothing when the file cannot be read
# safely or has no such line. The value is exactly what follows the first
# equals sign: no quote stripping, no validation. Always returns success.
# Usage: read_state_value FILE KEY
read_state_value() {
  local file="$1" key="$2" content line
  content="$(read_state_file "${file}")" || return 0
  while IFS= read -r line || [[ -n "${line}" ]]; do
    if [[ "${line}" == "${key}="* ]]; then
      printf '%s\n' "${line#*=}"
      return 0
    fi
  done <<< "${content}"
  return 0
}
