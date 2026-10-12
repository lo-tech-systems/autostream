#!/usr/bin/env bash
#
# installer/lib/system_tuning.sh
#
# Base operating-system tuning shared by the appliance and dial installers:
# Wi-Fi power saving off, swap behaviour, unneeded packages, and the power key.
# Sourced, not executed directly. The caller provides info() and warn().
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

_root_owner_args() {
  # install(1) options that make a file root-owned; empty when not running as
  # root, so a run as an ordinary user (a test, say) can still copy files.
  [[ "${EUID:-$(id -u)}" -eq 0 ]] && printf '%s\n' -o root -g root
  return 0
}

install_wifi_power_save_off() {
  # Turn Wi-Fi power saving off. An adapter that sleeps between beacons is slow
  # to receive what the device is sent, and drops out under load. Two files do
  # it: wifi-powersave.conf makes NetworkManager set power saving off on every
  # Wi-Fi connection it brings up, and the 99-wlan-fix dispatcher script turns
  # it off on the interface itself (and applies the built-in radio's transmit
  # power) whenever an interface comes up. NetworkManager reads both when it
  # next starts or a connection next comes up, so they take effect after a
  # reboot; nothing is restarted here.
  # Usage: install_wifi_power_save_off SYSTEM_DIR [ROOT]
  #   SYSTEM_DIR  the release's system/ directory
  #   ROOT        prefix for the destination paths (a test sandbox); default none
  local sys="$1" root="${2:-}"
  local -a own=()
  mapfile -t own < <(_root_owner_args)
  mkdir -p "${root}/etc/NetworkManager/dispatcher.d" "${root}/etc/NetworkManager/conf.d"
  install -m 0755 ${own[@]+"${own[@]}"} "${sys}/NetworkManager/99-wlan-fix" \
    "${root}/etc/NetworkManager/dispatcher.d/99-wlan-fix"
  install -m 0644 ${own[@]+"${own[@]}"} "${sys}/NetworkManager/wifi-powersave.conf" \
    "${root}/etc/NetworkManager/conf.d/wifi-powersave.conf"
}

# tune_memory_behaviour: converge swap/zram tuning on every install and
# update. Best-effort only -- tuning must never fail an install.
#
# - Masks rpi-zram-writeback.timer: on a small-RAM, swap-heavy device the
#   timer pushes compressed zram pages out to microSD, trading sustained
#   card wear for no benefit. `systemctl mask --now` both stops it if active
#   and masks it; masking a unit that is not installed still succeeds and
#   the mask persists, so a package that later installs the timer comes up
#   masked rather than active.
# - Drops a sysctl file setting vm.swappiness=20, so zram is used as a spike
#   absorber rather than a working-set host, and applies it immediately with
#   `sysctl -p`.
# Usage: tune_memory_behaviour [SYSCTL_DROP_IN]
tune_memory_behaviour() {
  info "Tuning memory/swap behaviour"

  systemctl mask --now rpi-zram-writeback.timer || \
    warn "Could not mask rpi-zram-writeback.timer; continuing."

  local conf="${1:-/etc/sysctl.d/90-autostream-swappiness.conf}"
  local tmp
  tmp="$(mktemp)"
  cat > "${tmp}" <<'EOT'
# zram is a spike absorber, not a working-set host, on this small-RAM
# realtime-audio appliance.
vm.swappiness=20
EOT
  install -m 0644 -o root -g root "${tmp}" "${conf}"
  rm -f "${tmp}"

  sysctl -p "${conf}" || warn "sysctl -p ${conf} failed to apply; will take effect on next boot."
}

remove_unneeded_packages() {
  # modemmanager and udisks2 are pulled in by desktop-oriented base images but
  # have no role on these devices: there is no modem hardware, and no
  # removable-storage workflow that would need udisks2 (removing it also closes
  # an otherwise-idle D-Bus surface). Each is removed only after a `dpkg -s`
  # presence check -- an unguarded `apt-get remove` on a package apt has never
  # seen exits non-zero and would abort the install under `set -e`, so the check
  # makes re-running this on an already-clean box a no-op. Best effort: a failed
  # removal is a warning. The removal is refused, with a warning, when apt says
  # it would take another package with it (see apt_remove_guarded in
  # lib/apt.sh). Not reversed on uninstall.
  local pkg
  for pkg in modemmanager udisks2; do
    if dpkg -s "${pkg}" >/dev/null 2>&1; then
      info "Removing package: ${pkg}"
      apt_remove_guarded remove "${pkg}" || \
        warn "apt-get remove -y ${pkg} failed or was refused; continuing."
    else
      info "Package '${pkg}' already absent; skipping."
    fi
  done
}

ignore_power_key() {
  # Install the logind drop-in that ignores the power key, so spurious power-key
  # events from USB enumeration cannot shut down an unattended device, and
  # restart logind to apply it. logind is restarted only when the drop-in is new
  # or changed: it reads the file at start, so a restart on every update would
  # do nothing but disturb the login sessions.
  # Usage: ignore_power_key SYSTEM_DIR [ROOT]
  #   SYSTEM_DIR  the release's system/ directory
  #   ROOT        prefix for the destination path (a test sandbox); default none
  local sys="$1" root="${2:-}"
  local src="${sys}/logind/90-autostream-ignore-power-key.conf"
  local dest="${root}/etc/systemd/logind.conf.d/90-autostream-ignore-power-key.conf"
  local -a own=()
  mapfile -t own < <(_root_owner_args)
  mkdir -p "${root}/etc/systemd/logind.conf.d"
  if cmp -s "${src}" "${dest}"; then
    return 0
  fi
  install -m 0644 ${own[@]+"${own[@]}"} "${src}" "${dest}"
  systemctl restart systemd-logind || warn "systemctl restart systemd-logind failed"
}
