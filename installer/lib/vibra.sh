#!/usr/bin/env bash
#
# installer/lib/vibra.sh
#
# Builds and installs the autostream-vibra Shazam recognition daemon from the
# lo-tech-systems/vibra-mini fork.  Sourced by autostream_install.sh; not
# executed directly.
#
# Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

VIBRA_REPO="https://github.com/lo-tech-systems/vibra-mini.git"
VIBRA_BRANCH="autostream"
VIBRA_INSTALL_PREFIX="/opt/autostream/vibra"

install_vibra_build_dependencies() {
  apt_install libfftw3-dev libcurl4-openssl-dev cmake
}

install_vibra_from_source() {
  info "Installing autostream-vibra from lo-tech-systems source repository"

  install_vibra_build_dependencies

  local tmpdir
  tmpdir="$(mktemp -d)"
  git clone --branch "${VIBRA_BRANCH}" --single-branch "${VIBRA_REPO}" "${tmpdir}/vibra-mini"
  (
    cd "${tmpdir}/vibra-mini"
    cmake -S . -B build \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_TESTING=OFF \
      "-DCMAKE_INSTALL_PREFIX=${VIBRA_INSTALL_PREFIX}"
    cmake --build build --parallel 2
    cmake --install build
  )
  rm -rf "${tmpdir}"
}

update_vibra_from_source() {
  info "Updating autostream-vibra from lo-tech-systems source repository"

  install_vibra_build_dependencies

  local tmpdir
  tmpdir="$(mktemp -d)"
  git clone --branch "${VIBRA_BRANCH}" --single-branch "${VIBRA_REPO}" "${tmpdir}/vibra-mini"
  (
    cd "${tmpdir}/vibra-mini"
    cmake -S . -B build \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_TESTING=OFF \
      "-DCMAKE_INSTALL_PREFIX=${VIBRA_INSTALL_PREFIX}"
    cmake --build build --parallel 2
    cmake --install build
  )
  rm -rf "${tmpdir}"
}
