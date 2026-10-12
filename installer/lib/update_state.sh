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

# migrate_staged_release: an update started by an older release's updater runs
# this installer from the old place, a directory inside the one the service
# account owns, because that updater chose where to stage it. That one run
# cannot be protected, but what it leaves for a later retry can be: the staged
# release is copied into the system-only directory, where the boot-time retry
# looks, so an interruption part way through is retried from a tree only the
# system could have written. Nothing is copied when the installer was not run
# from the old place. The copy is made beside the final name and renamed into
# place, and dropped if the installer in it is not the one now running.
# The release tag and the retry count are carried across only if they are
# plain values.
# Usage: migrate_staged_release RELEASE_DIR OLD_STAGING STAGING INSTALLER [COUNT_FILE_NAME]
migrate_staged_release() {
  local release="$1" old="$2" staging="$3" installer="$4" count_name="${5:-}"
  local real old_real name tmp tag count
  old_real="$(cd -- "${old}" 2>/dev/null && pwd -P)" || return 0
  real="$(cd -- "${release}" 2>/dev/null && pwd -P)" || return 1
  case "${real}/" in
    "${old_real}/"*) ;;
    *) return 0 ;;
  esac
  name="$(basename -- "${real}")"
  tmp="${staging}.new"
  rm -rf --one-file-system -- "${tmp}" "${staging}" || return 1
  mkdir -m 0700 -- "${tmp}" "${tmp}/src" || return 1
  if ! cp -a --no-preserve=ownership -- "${real}" "${tmp}/src/${name}" \
     || ! cmp -s -- "${real}/${installer}" "${tmp}/src/${name}/${installer}"; then
    rm -rf --one-file-system -- "${tmp}"
    return 1
  fi
  tag="${AUTOSTREAM_RELEASE_TAG:-}"
  if [[ ! "${tag}" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$ ]]; then
    tag="$(read_state_file "${old_real}/release_tag" || true)"
    tag="${tag//[[:space:]]/}"
  fi
  if [[ "${tag}" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$ ]]; then
    printf '%s\n' "${tag}" > "${tmp}/release_tag"
  fi
  if [[ -n "${count_name}" ]]; then
    count="$(read_state_file "${old_real}/${count_name}" || true)"
    count="${count//[[:space:]]/}"
    if [[ "${count}" =~ ^[0-9]{1,3}$ ]]; then
      printf '%s\n' "${count}" > "${tmp}/${count_name}"
    fi
  fi
  mv -T -- "${tmp}" "${staging}"
}

# remove_legacy_update_state: take away what an older release left in the
# service account's directory, which nothing reads any more: a name that is a
# link is unlinked, a directory is removed without following anything in it.
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
