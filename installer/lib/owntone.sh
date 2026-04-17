#!/usr/bin/env bash
#
# installer/lib/owntone.sh
#
# OwnTone provisioning: mini (lo-tech source build), full (packaged), skip.
# Also manages /etc/owntone.conf for pipe playback.
# Sourced by autostream_install.sh; not executed directly.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

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

install_owntone_mini_from_source() {
  info "Installing OwnTone Mini from lo-tech-systems source repository"
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
  git clone --branch minimal --single-branch https://github.com/lo-tech-systems/owntone-server.git "${tmpdir}/owntone-server"
  (
    cd "${tmpdir}/owntone-server"
    autoreconf -i
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-install-user --enable-chromecast
    make -j2
    make install
  )
  rm -rf "${tmpdir}"

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

line = 'directories = { "/tmp/autostream-pipes" }'
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
