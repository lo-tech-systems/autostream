#!/usr/bin/env bash
#
# installer/lib/swap.sh
#
# Swap-file size limit, shared by the appliance and dial installers; sourced,
# not executed directly.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

install_swap_limit() {
  # Raspberry Pi OS sizes its swap file with the rpi-swap package (settings in
  # /etc/rpi/swap.conf, drop-ins in /etc/rpi/swap.conf.d) and by default makes
  # it as large as the board's RAM, up to 2048 MiB, on the SD card. Install the
  # drop-in that limits the file to 512 MiB.
  #
  # A device without rpi-swap has nothing that reads the drop-in, so it is left
  # alone and /etc/rpi is not created. (The journald and core dump drop-ins make
  # their directories regardless, because systemd always reads them.) The limit
  # applies when swap is next set up, at boot: a swap file that is already
  # larger is not resized while the system runs, and is expected to be replaced
  # by the smaller one at the next reboot.
  # Usage: install_swap_limit SOURCE [RPI_CONFIG_DIR]
  local src="$1" dir="${2:-/etc/rpi}"
  if [[ ! -f "${src}" ]]; then
    echo "WARNING: ${src} is missing; the swap file limit was not installed." >&2
    return 0
  fi
  if [[ ! -f "${dir}/swap.conf" ]] && ! dpkg -s rpi-swap >/dev/null 2>&1; then
    echo "rpi-swap not found; leaving the swap settings alone."
    return 0
  fi
  mkdir -p "${dir}/swap.conf.d" || {
    echo "WARNING: could not create ${dir}/swap.conf.d; the swap file limit was not installed." >&2
    return 0
  }
  install -m 0644 "${src}" "${dir}/swap.conf.d/99-autostream-swap.conf" || {
    echo "WARNING: could not install the swap file limit." >&2
    return 0
  }
  echo "Limited the swap file to 512 MiB (takes effect at the next reboot)."
}
