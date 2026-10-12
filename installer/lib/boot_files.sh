#!/usr/bin/env bash
#
# installer/lib/boot_files.sh
#
# Replacing a file on the boot partition (config.txt, cmdline.txt) without
# ever leaving it empty or half written. The boot partition is FAT: a file that
# is truncated and then written is empty if the power goes in between, and an
# empty cmdline.txt is a board that will not boot. The new content is written
# to a temporary file in the same directory instead, then renamed over the
# old one, so the old file or the new one is there at every instant.
#
# Sourced by installer/lib/hardware.sh and installer/dial/helpers.sh; not
# executed directly.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

# boot_file_stage: make a temporary file next to FILE and print its name. The
# caller writes the new content to it and then calls boot_file_commit.
# Usage: boot_file_stage FILE
boot_file_stage() {
  local file="$1"
  mktemp "$(dirname -- "${file}")/.$(basename -- "${file}").XXXXXX"
}

# boot_file_commit: put the finished temporary file in place of FILE with the
# file's own mode and owner, by rename, and flush the partition. On any
# failure the temporary file is removed and FILE is as it was.
# Usage: boot_file_commit TMP FILE
boot_file_commit() {
  local tmp="$1" file="$2"
  # A FAT mount fixes mode and owner for every file; failing to copy them
  # across there changes nothing.
  chmod --reference="${file}" -- "${tmp}" 2>/dev/null || true
  chown --reference="${file}" -- "${tmp}" 2>/dev/null || true
  if ! { sync -- "${tmp}" 2>/dev/null || sync; } || ! mv -f -T -- "${tmp}" "${file}"; then
    rm -f -- "${tmp}"
    return 1
  fi
  sync
  return 0
}

# boot_file_discard: remove a temporary file made by boot_file_stage that is
# not going to be committed.
# Usage: boot_file_discard TMP
boot_file_discard() {
  rm -f -- "$1"
}
