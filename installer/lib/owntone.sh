#!/usr/bin/env bash
#
# installer/lib/owntone.sh
#
# OwnTone provisioning: mini (lo-tech source build, pinned release), full
# (packaged), skip. Also manages /etc/owntone.conf for pipe playback.
# Sourced by autostream_install.sh; not executed directly.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

OWNTONE_MINI_REPO="https://github.com/lo-tech-systems/owntone-mini.git"
# The owntone-mini release this autostream release is built against. Both
# fresh installs and updates build exactly this tag; keep in sync with the
# default ref in tools/owntone_mini_update.sh.
OWNTONE_MINI_VERSION="1.1.1"
# Version stamp written at the end of a successful build; the fallback
# fast-path check when the running-daemon probe misses (e.g. the service was
# stopped ahead of an update). /var/lib/autostream is the installer's
# existing root-only stamp/state area (see autostream_install.sh's
# STAMP_DIR).
OWNTONE_MINI_VERSION_STAMP="/var/lib/autostream/owntone-mini-version"
# Binary the source build installs; also removed by the uninstaller.
OWNTONE_MINI_BINARY="/usr/sbin/owntone"

configure_owntone_apt_repo() {
  info "Configuring OwnTone APT repository"
  curl -fsSL "https://raw.githubusercontent.com/owntone/owntone-apt/refs/heads/master/repo/rpi/owntone.gpg" \
    | gpg --dearmor \
    | tee /usr/share/keyrings/owntone-archive-keyring.gpg >/dev/null

  curl -fsSL \
    -o /etc/apt/sources.list.d/owntone.list \
    "https://raw.githubusercontent.com/owntone/owntone-apt/refs/heads/master/repo/rpi/owntone-trixie.list"

  DEBIAN_FRONTEND=noninteractive apt-get update
}

remove_owntone_apt_repo() {
  local removed=0
  if [[ -f /etc/apt/sources.list.d/owntone.list ]]; then
    rm -f /etc/apt/sources.list.d/owntone.list
    removed=1
  fi
  if [[ -f /usr/share/keyrings/owntone-archive-keyring.gpg ]]; then
    rm -f /usr/share/keyrings/owntone-archive-keyring.gpg
    removed=1
  fi
  if [[ ${removed} -eq 1 ]]; then
    info "Removed OwnTone APT repository configuration"
    DEBIAN_FRONTEND=noninteractive apt-get update
  fi
}

install_packaged_owntone() {
  configure_owntone_apt_repo
  apt_install owntone
  systemctl enable owntone
}

owntone_mini_reported_identity() {
  # Print "<product_name> <version>" of the owntone instance answering on
  # localhost, or nothing if none answers / the reply is malformed.
  curl -fsS --max-time 5 http://localhost:3689/api/config 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("product_name",""), d.get("version",""))' 2>/dev/null \
    || true
}

owntone_mini_stamp_reports_pinned_version() {
  # Fallback evidence for when the API probe is unreachable, e.g. the daemon
  # was stopped ahead of this step: a stamp file this same script writes on
  # a successful build, cross-checked against the installed binary still
  # actually being present (so a stamp left behind by a since-removed
  # install can't produce a false skip). Any read failure -- no stamp, no
  # binary -- is treated as "not matching".
  local stamped
  stamped="$(cat "${OWNTONE_MINI_VERSION_STAMP}" 2>/dev/null)" || return 1
  [[ "${stamped}" == "${OWNTONE_MINI_VERSION}" && -x "${OWNTONE_MINI_BINARY}" ]]
}

write_owntone_mini_version_stamp() {
  mkdir -p "$(dirname "${OWNTONE_MINI_VERSION_STAMP}")" 2>/dev/null || true
  printf '%s' "${OWNTONE_MINI_VERSION}" > "${OWNTONE_MINI_VERSION_STAMP}" 2>/dev/null || true
}

install_owntone_mini_from_source() {
  # Fast path, primary: the running owntone-mini already reports the pinned
  # release, so there is nothing to rebuild (a source build costs ~10 minutes
  # on Pi-class hardware). Any probe failure -- service down, stock OwnTone,
  # an older mini -- falls through to the fallback probe, then the full
  # pinned-source build.
  local reported
  reported="$(owntone_mini_reported_identity)"
  if [[ "${reported}" == "owntone-mini ${OWNTONE_MINI_VERSION}" ]]; then
    info "OwnTone Mini ${OWNTONE_MINI_VERSION} already installed; skipping source rebuild (running daemon)"
    write_owntone_mini_version_stamp
    systemctl enable avahi-daemon
    systemctl enable owntone
    return 0
  fi

  # Fast path, fallback: the API is unreachable (daemon stopped ahead of
  # this step), but the last successful build's stamp plus the binary it
  # produced still confirm the pinned release is in place.
  if owntone_mini_stamp_reports_pinned_version; then
    info "OwnTone Mini ${OWNTONE_MINI_VERSION} already installed; skipping source rebuild (version stamp)"
    systemctl enable avahi-daemon
    systemctl enable owntone
    return 0
  fi

  info "Installing OwnTone Mini ${OWNTONE_MINI_VERSION} from lo-tech-systems source repository"
  update_progress "Installing OwnTone dependencies..." 65
  apt_install nginx autotools-dev autoconf automake libtool gettext gawk \
    gperf bison flex libconfuse-dev libunistring-dev libsqlite3-dev \
    libavcodec-dev libavformat-dev libavfilter-dev libswscale-dev libavutil-dev \
    libxml2-dev libgcrypt20-dev libavahi-client-dev zlib1g-dev \
    libevent-dev libplist-dev libsodium-dev libjson-c-dev libwebsockets-dev \
    libcurl4-openssl-dev libprotobuf-c-dev libgnutls28-dev

  if dpkg -s owntone >/dev/null 2>&1; then
    info "Removing packaged OwnTone before source install"
    systemctl stop owntone || true
    DEBIAN_FRONTEND=noninteractive apt-get remove -y owntone
    remove_owntone_apt_repo
  else
    remove_owntone_apt_repo
  fi

  local tmpdir
  tmpdir="$(mktemp -d)"
  info "Fetching owntone-mini ${OWNTONE_MINI_VERSION}"
  git clone \
    --branch "${OWNTONE_MINI_VERSION}" \
    --depth 1 \
    --single-branch \
    "${OWNTONE_MINI_REPO}" \
    "${tmpdir}/owntone-mini"

  local checked_out_tag
  checked_out_tag="$(git -C "${tmpdir}/owntone-mini" describe --tags --exact-match HEAD)"
  if [[ "${checked_out_tag}" != "${OWNTONE_MINI_VERSION}" ]]; then
    error "Expected owntone-mini ${OWNTONE_MINI_VERSION}, checked out ${checked_out_tag:-unknown}"
    return 1
  fi
  (
    cd "${tmpdir}/owntone-mini"
    autoreconf -i
    # -Ofast (implies -ffast-math): measurably lighter AAC encode on Pi-class
    # CPUs (validated on Pi 5 and Pi Zero 2W).
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-install-user --enable-chromecast \
      CFLAGS="-Ofast" CXXFLAGS="-Ofast"
    update_progress "Building OwnTone..." 71
    make -j2
    make install
  )
  rm -rf "${tmpdir}"
  write_owntone_mini_version_stamp

  systemctl daemon-reload
  systemctl enable avahi-daemon
  systemctl enable owntone
  systemctl start owntone
}

configure_owntone_conf() {
  # Ensure /etc/owntone.conf has the autostream pipe directory in its library block.
  # Safe to call on both install and update; idempotent.
  local conf="/etc/owntone.conf"

  if [[ "${OWNTONE_MODE}" == "mini" ]]; then
    info "Skipping /etc/owntone.conf update for --owntone=mini"
    return 0
  fi

  if [[ "${OWNTONE_MODE}" == "skip" && ! -f "${conf}" ]]; then
    warn "--owntone=skip is set and ${conf} is missing; skipping OwnTone config update."
    return 0
  fi

  info "Configuring ${conf} for autostream pipe playback"
  python3 - "${conf}" <<'PYOWNTONE'
from pathlib import Path
import re
import sys

conf = Path(sys.argv[1])
if conf.exists():
    text = conf.read_text(encoding="utf-8")
else:
    text = ""

line = 'directories = { "/run/autostream-pipes" }'
lib = re.search(r'(?ms)^\s*library\s*\{.*?^\s*\}', text)
if lib:
    block = lib.group(0)
    if re.search(r'(?m)^\s*directories\s*=\s*\{[^}]*\}', block):
        block = re.sub(
            r'(?m)^(\s*)directories\s*=\s*\{[^}]*\}\s*$',
            r'\1' + line,
            block,
            count=1,
        )
    else:
        open_brace = block.find('{')
        first_newline = block.find('\n', open_brace)
        if first_newline != -1:
            block = block[:first_newline + 1] + '\t' + line + '\n' + block[first_newline + 1:]
        else:
            block = block.rstrip() + '\n\t' + line + '\n}'
    text = text[:lib.start()] + block + text[lib.end():]
else:
    if text and not text.endswith('\n'):
        text += '\n'
    if text:
        text += '\n'
    text += 'library {\n\t' + line + '\n}\n'

conf.write_text(text, encoding="utf-8")
PYOWNTONE
}

provision_owntone() {
  # Dispatch to the correct OwnTone provisioning path based on OWNTONE_MODE.
  local mode="${1:-install}"   # install | update

  case "${OWNTONE_MODE}" in
    skip)
      info "OwnTone: skip mode - reusing existing system OwnTone"
      ;;
    mini)
      install_owntone_mini_from_source
      ;;
    full)
      if [[ "${mode}" == "install" ]]; then
        install_packaged_owntone
      else
        info "OwnTone: full mode - package upgrade handled by system upgrade phase"
      fi
      ;;
  esac

  configure_owntone_conf
}
