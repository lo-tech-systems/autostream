#!/usr/bin/env bash
#
# installer/lib/update_state.sh
#
# The directory that holds what root executes and trusts while an update is
# staged, handed to the next boot, or retried: the downloaded release, the
# release tag and retry count, and (on the dial) the swap hand-off and the
# backup. It belongs to root alone and has mode 0700, so the service account,
# which owns /var/lib/autostream and can replace anything in it, can neither
# write here nor swap a file or a directory that root is about to run or
# read. Nothing the web UI or the dial needs to read lives here.
#
# Sourced by autostream_install.sh and installer/dial/helpers.sh; not
# executed directly.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

UPDATE_STATE_DIR_DEFAULT="/var/lib/autostream-update"

# ensure_update_state_dir: make DIR exist as a real directory owned by whoever
# runs this (root, in the installers) with mode 0700. Anything already at that
# name that is not exactly that, a link, a file, a directory with another
# owner or a looser mode, is removed first and the directory made again, so
# nothing a hand-made or weakened copy held is trusted. A directory that is
# already right is left, contents included.
# Usage: ensure_update_state_dir [DIR]
ensure_update_state_dir() {
  local dir="${1:-${UPDATE_STATE_DIR_DEFAULT}}" me
  [[ -n "${dir}" && "${dir}" != "/" ]] || return 1
  me="$(id -u)"
  if [[ -L "${dir}" ]]; then
    rm -f -- "${dir}" || return 1
  elif [[ -e "${dir}" && ! -d "${dir}" ]]; then
    rm -f -- "${dir}" || return 1
  elif [[ -d "${dir}" && "$(stat -c '%u %a' -- "${dir}")" != "${me} 700" ]]; then
    rm -rf --one-file-system -- "${dir}" || return 1
  fi
  if [[ ! -d "${dir}" ]]; then
    mkdir -p -- "$(dirname -- "${dir}")" || return 1
    mkdir -m 0700 -- "${dir}" || return 1
  fi
  if [[ "${me}" -eq 0 ]]; then
    chown root:root -- "${dir}" || return 1
  fi
  [[ -d "${dir}" && ! -L "${dir}" && "$(stat -c '%u %a' -- "${dir}")" == "${me} 700" ]]
}

# An update started by an older release's updater runs this installer from the
# place that updater chose, a directory inside the one the service account
# owns. That one run cannot be protected, and the staged release is not copied
# anywhere to be retried: if the run is cut short, the update is reported as
# failed and the next scheduled or manual update stages again in the
# system-only directory. What the older updater left behind is removed with
# remove_legacy_update_state once the update has an outcome.
#
# remove_legacy_update_state: take away what an older release left in the
# service account's directory, which nothing reads any more: a name that is a
# link is unlinked, a directory is removed without following anything in it.
# Pass each name as it is, with no trailing slash and no glob.
# Usage: remove_legacy_update_state PATH...
remove_legacy_update_state() {
  local path
  for path in "$@"; do
    if [[ -L "${path}" ]]; then
      rm -f -- "${path}" || true
    elif [[ -e "${path}" ]]; then
      rm -rf --one-file-system -- "${path}" || true
    fi
  done
}
