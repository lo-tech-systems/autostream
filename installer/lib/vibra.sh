#!/usr/bin/env bash
#
# installer/lib/vibra.sh
#
# Builds and installs the vibra-mini Shazam recognition daemon.
# Sourced by autostream_install.sh; not
# executed directly.
#
# Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

VIBRA_REPO="https://github.com/lo-tech-systems/vibra-mini.git"
VIBRA_VERSION="v1.0.0"
VIBRA_INSTALL_PREFIX="/opt/autostream/vibra"
# Control socket the running daemon answers on; matches
# core/track_id/vibra_client.py's DEFAULT_SOCKET_PATH and the systemd unit's
# --socket argument.
VIBRA_SOCKET_PATH="/tmp/vibra-mini.sock"
# Version stamp written at the end of a successful build; the fallback
# fast-path check when the daemon isn't reachable (e.g. stopped ahead of an
# update). /var/lib/autostream is the installer's existing root-only
# stamp/state area (see autostream_install.sh's STAMP_DIR).
VIBRA_VERSION_STAMP="/var/lib/autostream/vibra-mini-version"

install_vibra_build_dependencies() {
  apt_install libfftw3-dev libcurl4-openssl-dev libjson-c-dev cmake
}

clone_vibra_source() {
  local destination="$1"

  info "Fetching vibra-mini ${VIBRA_VERSION}"
  git clone \
    --branch "${VIBRA_VERSION}" \
    --depth 1 \
    --single-branch \
    "${VIBRA_REPO}" \
    "${destination}"

  local checked_out_tag
  checked_out_tag="$(git -C "${destination}" describe --tags --exact-match HEAD)"
  if [[ "${checked_out_tag}" != "${VIBRA_VERSION}" ]]; then
    error "Expected vibra-mini ${VIBRA_VERSION}, checked out ${checked_out_tag:-unknown}"
    return 1
  fi
}

vibra_mini_reported_version() {
  # Print the version the running vibra-mini daemon reports over its
  # ping/pong control socket, or nothing if no daemon answers there / the
  # handshake fails. Never fails the caller: python3 errors are swallowed.
  python3 - "${VIBRA_SOCKET_PATH}" <<'PY' 2>/dev/null || true
import json
import socket
import sys

path = sys.argv[1]
try:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(path)
    sock.sendall((json.dumps({"type": "ping"}) + "\n").encode())
    data = sock.recv(4096)
    sock.close()
    resp = json.loads(data.decode().strip())
    if resp.get("ok") is True and resp.get("type") == "pong":
        version = str(resp.get("version") or "").strip()
        if version:
            print(version)
except Exception:
    pass
PY
}

vibra_mini_daemon_reports_pinned_version() {
  # True if a running vibra-mini already reports the pinned release over its
  # control socket (tags carry a "v" prefix; the daemon's own version string
  # does not). Any probe failure -- daemon not running, stale socket, garbled
  # reply -- is treated as "not matching".
  local reported
  reported="$(vibra_mini_reported_version)"
  [[ -n "${reported}" && "${reported}" == "${VIBRA_VERSION#v}" ]]
}

vibra_mini_stamp_reports_pinned_version() {
  # Fallback evidence for when the control socket is unreachable, e.g. the
  # daemon was stopped ahead of this step: a stamp file this same script
  # writes on a successful build, cross-checked against the installed binary
  # still actually being present (so a stamp left behind by a since-removed
  # install can't produce a false skip). Any read failure -- no stamp, no
  # binary -- is treated as "not matching".
  local stamped
  stamped="$(cat "${VIBRA_VERSION_STAMP}" 2>/dev/null)" || return 1
  [[ "${stamped}" == "${VIBRA_VERSION}" && -x "${VIBRA_INSTALL_PREFIX}/bin/vibra-mini" ]]
}

write_vibra_version_stamp() {
  mkdir -p "$(dirname "${VIBRA_VERSION_STAMP}")" 2>/dev/null || true
  printf '%s' "${VIBRA_VERSION}" > "${VIBRA_VERSION_STAMP}" 2>/dev/null || true
}

build_and_install_vibra_from_source() {
  install_vibra_build_dependencies

  local tmpdir
  tmpdir="$(mktemp -d)"
  clone_vibra_source "${tmpdir}/vibra-mini"
  (
    cd "${tmpdir}/vibra-mini"
    cmake -S . -B build \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_TESTING=OFF \
      "-DCMAKE_INSTALL_PREFIX=${VIBRA_INSTALL_PREFIX}"
    cmake --build build --parallel 2
    cmake --install build
  )
  [[ -x "${VIBRA_INSTALL_PREFIX}/bin/vibra-mini" ]] || {
    error "vibra-mini installation did not produce ${VIBRA_INSTALL_PREFIX}/bin/vibra-mini"
    return 1
  }
  rm -rf "${tmpdir}"
  write_vibra_version_stamp
}

install_vibra_from_source() {
  info "Installing vibra-mini ${VIBRA_VERSION} from lo-tech-systems source repository"
  build_and_install_vibra_from_source
}

update_vibra_from_source() {
  # Fast path, primary: the running daemon already reports the pinned
  # release, so there is nothing to rebuild.
  if vibra_mini_daemon_reports_pinned_version; then
    info "vibra-mini ${VIBRA_VERSION} already installed; skipping rebuild (running daemon)"
    return 0
  fi

  # Fast path, fallback: the control socket is unreachable (daemon stopped
  # ahead of this step), but the last successful build's stamp plus the
  # binary it produced still confirm the pinned release is in place.
  if vibra_mini_stamp_reports_pinned_version; then
    info "vibra-mini ${VIBRA_VERSION} already installed; skipping rebuild (version stamp)"
    return 0
  fi

  info "Updating vibra-mini to ${VIBRA_VERSION} from lo-tech-systems source repository"
  build_and_install_vibra_from_source
}
