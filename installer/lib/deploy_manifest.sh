#!/usr/bin/env bash
#
# installer/lib/deploy_manifest.sh
#
# Removing the application files an earlier release installed and this one no
# longer ships. The installer copies the new files over the install directory,
# which adds and replaces but never removes, so a module that was renamed or
# deleted stays behind and reads as live code to anyone inspecting the
# appliance.
#
# What the installer shipped is recorded in DEST/.core-manifest: the regular
# files under core/ (named relative to the install directory) and under
# nginx/static/, and the files placed beside them from elsewhere in the tree,
# one path per line. After the new files are copied, a file in
# the old manifest that is not in the new list is removed, and the manifest is
# replaced. Nothing outside the old manifest is touched, so configuration,
# state, logs, the virtual environment and the compiled monitor are never at
# risk.
#
# The first upgrade from a release that wrote no manifest has nothing to go
# by. It removes only the top-level autostream_*.py modules (and their compiled
# copies) that the new release does not ship.
#
# Sourced by autostream_install.sh; not executed directly. The caller provides
# info().
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

# deploy_manifest_list SRC: print the files this release ships, one relative
# path per line, sorted bytewise. Built from the source tree SRC, so it is the
# same whatever the install directory holds. Besides core/ and nginx/static/ it
# names what the installer places in the install directory from elsewhere (the
# Wi-Fi watcher and its modules from platform/, and the licence), so a file that
# moves between those trees is never removed right after it was installed.
deploy_manifest_list() {
  local src="$1" f
  {
    if [[ -d "${src}/core" ]]; then
      (cd "${src}/core" && find . -type f ! -path '*/__pycache__/*' ! -name '*.pyc' -print) \
        | sed 's|^\./||'
    fi
    if [[ -f "${src}/platform/wifi_watcher.py" ]]; then
      printf '%s\n' autostream_wifi_watcher
    fi
    for f in "${src}"/platform/wifi_*.py; do
      [[ -f "${f}" ]] || continue
      [[ "$(basename -- "${f}")" == wifi_watcher.py ]] && continue
      basename -- "${f}"
    done
    if [[ -f "${src}/LICENSE" ]]; then
      printf '%s\n' LICENSE
    fi
    if [[ -d "${src}/nginx/static" ]]; then
      (cd "${src}/nginx/static" && find . -type f ! -path '*/__pycache__/*' ! -name '*.pyc' -print) \
        | sed 's|^\./|nginx/static/|'
    fi
  } | LC_ALL=C sort -u
}

# _deploy_manifest_readable FILE: succeeds when FILE is a readable manifest
# worth acting on: not empty, and every line a relative path that cannot leave
# the install directory (not blank, not only white space, no "..", no leading
# "/"). Anything else is treated as no manifest at all.
_deploy_manifest_readable() {
  local file="$1" line seen=0
  [[ -f "${file}" && -r "${file}" ]] || return 1
  while IFS= read -r line || [[ -n "${line}" ]]; do
    seen=1
    [[ -n "${line//[[:space:]]/}" ]] || return 1
    [[ "${line}" != *..* ]] || return 1
    [[ "${line}" != /* ]] || return 1
  done < "${file}"
  [[ "${seen}" -eq 1 ]]
}

# _deploy_manifest_remove_compiled DIR STEM: remove the compiled copies of the
# module STEM that sit in DIR/__pycache__.
_deploy_manifest_remove_compiled() {
  local dir="$1" stem="$2" pyc
  for pyc in "${dir}/__pycache__/${stem}".*.pyc; do
    [[ -e "${pyc}" ]] || continue
    info "Removing ${pyc} (module no longer shipped)"
    rm -f -- "${pyc}"
  done
  return 0
}

# _deploy_manifest_remove DEST REL: remove DEST/REL and, for a module, its
# compiled copies, then every directory that is left empty above it, up to but
# not including DEST. rmdir only ever removes an empty directory.
_deploy_manifest_remove() {
  local dest="$1" rel="$2" dir base parent
  if [[ -e "${dest}/${rel}" || -L "${dest}/${rel}" ]]; then
    info "Removing ${dest}/${rel} (no longer shipped)"
    rm -f -- "${dest}/${rel}"
  fi
  dir="$(dirname -- "${rel}")"
  base="$(basename -- "${rel}")"
  if [[ "${base}" == *.py ]]; then
    _deploy_manifest_remove_compiled "${dest}/${dir}" "${base%.py}"
    rmdir -- "${dest}/${dir}/__pycache__" 2>/dev/null || true
  fi
  parent="${dir}"
  while [[ "${parent}" != "." && "${parent}" != "/" && -n "${parent}" ]]; do
    rmdir -- "${dest}/${parent}" 2>/dev/null || break
    parent="$(dirname -- "${parent}")"
  done
  return 0
}

# deploy_manifest_prune DEST SRC: remove from DEST what the previous release
# shipped and this one (the source tree SRC) does not. Call after the new
# files have been copied into DEST.
deploy_manifest_prune() {
  local dest="$1" src="$2" old="$1/.core-manifest"
  local -A shipped=()
  local rel base

  while IFS= read -r rel; do
    if [[ -n "${rel}" ]]; then shipped["${rel}"]=1; fi
  done < <(deploy_manifest_list "${src}")

  if _deploy_manifest_readable "${old}"; then
    while IFS= read -r rel || [[ -n "${rel}" ]]; do
      if [[ -z "${shipped[${rel}]:-}" ]]; then
        _deploy_manifest_remove "${dest}" "${rel}"
      fi
    done < "${old}"
    return 0
  fi

  # No usable manifest: the first upgrade from a release that wrote none.
  for rel in "${dest}"/autostream_*.py; do
    [[ -f "${rel}" ]] || continue
    base="$(basename -- "${rel}")"
    if [[ ! -e "${src}/core/${base}" ]]; then
      info "Removing ${rel} (no longer shipped)"
      rm -f -- "${rel}"
      _deploy_manifest_remove_compiled "${dest}" "${base%.py}"
    fi
  done
  return 0
}

# deploy_manifest_write DEST SRC: record what this release ships in
# DEST/.core-manifest. The new list goes to a temporary file in DEST first and
# is renamed over the old manifest, so an interrupted write leaves the old one.
deploy_manifest_write() {
  local dest="$1" src="$2" tmp="$1/.core-manifest.tmp.$$"
  if ! deploy_manifest_list "${src}" > "${tmp}"; then
    rm -f -- "${tmp}"
    return 1
  fi
  chmod 0644 "${tmp}" && mv -f -- "${tmp}" "${dest}/.core-manifest"
}
