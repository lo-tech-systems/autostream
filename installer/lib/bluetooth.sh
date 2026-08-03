#!/usr/bin/env bash
#
# installer/lib/bluetooth.sh
#
# Bluetooth input subsystem: turns the Pi into an A2DP sink whose decoded
# audio is fed into the existing capture pipeline via the ALSA loopback
# (snd-aloop, card id ASBT).
#
# Sourced by autostream_install.sh; not executed directly.
#
# install_bluetooth_stack() is called unconditionally from configure_phase
# on every install and update: the apt packages, snd-aloop/BlueZ config, and
# the systemd unit are always present on every appliance. The unit itself is
# installed disabled and not started -- enabling/starting it (and the stock
# bluetooth/bluealsa(d) services it depends on) is a separate, privileged,
# runtime action triggered later and is not part of installation.
#
# remove_bluetooth_stack() is only called from autostream_uninstall.sh; it
# removes the unit and module/BlueZ config. Apt packages are deliberately
# retained, consistent with the uninstaller's existing light-touch stance.
#
# Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

# Pinned constants shared with the daemon/monitor/webui layers -- do not
# change independently of the rest of the Bluetooth input implementation.
BLUETOOTH_LOOPBACK_CARD_ID="ASBT"
BLUETOOTH_UNIT_NAME="autostream_bluetooth.service"

BLUETOOTH_MODULES_LOAD_FILE="/etc/modules-load.d/autostream-bluetooth.conf"
BLUETOOTH_MODPROBE_FILE="/etc/modprobe.d/autostream-bluetooth.conf"
BLUETOOTH_MAIN_CONF_DIR="/etc/bluetooth/main.conf.d"
BLUETOOTH_MAIN_CONF_FILE="${BLUETOOTH_MAIN_CONF_DIR}/autostream.conf"

# The daemon's modules (platform/bluetooth_*.py) are deployed by
# install_bluetooth_stack() via _copy_bluetooth_daemon_files(); deploy_phase's
# targeted cp list does not include them. The module set is discovered by
# globbing the source checkout (see _copy_bluetooth_daemon_files) rather than
# hand-listed here, so adding a new bluetooth_*.py module cannot silently
# leave it undeployed. bluetooth_service.py is the daemon's entry point,
# referenced by the systemd unit's ExecStart.

#############################################
# ALSA loopback + BlueZ config
#############################################
_install_bluetooth_module_config() {
  info "Configuring snd-aloop for Bluetooth input (card id ${BLUETOOTH_LOOPBACK_CARD_ID})"
  install -m 0644 -o root -g root \
      "${AUTOSTREAM_DIR}/system/modules-load.d/autostream-bluetooth.conf" \
      "${BLUETOOTH_MODULES_LOAD_FILE}"
  install -m 0644 -o root -g root \
      "${AUTOSTREAM_DIR}/system/modprobe.d/autostream-bluetooth.conf" \
      "${BLUETOOTH_MODPROBE_FILE}"
}

_remove_bluetooth_module_config() {
  rm -f "${BLUETOOTH_MODULES_LOAD_FILE}" "${BLUETOOTH_MODPROBE_FILE}"
}

_install_bluetooth_main_conf() {
  info "Configuring BlueZ main.conf.d for Bluetooth input"
  mkdir -p "${BLUETOOTH_MAIN_CONF_DIR}"
  install -m 0644 -o root -g root \
      "${AUTOSTREAM_DIR}/system/bluetooth/autostream.conf" \
      "${BLUETOOTH_MAIN_CONF_FILE}"
}

_remove_bluetooth_main_conf() {
  rm -f "${BLUETOOTH_MAIN_CONF_FILE}"
}

#############################################
# Daemon deployment + systemd unit
#############################################

# _copy_bluetooth_daemon_files: deploy platform/bluetooth_*.py beside the rest
# of the application tree at ${INSTALL_DIR}/platform. The set of modules to
# deploy is discovered by globbing the source checkout rather than
# hand-listed, so a newly added bluetooth_*.py module is never silently left
# undeployed. An empty match (no bluetooth_*.py files present) is warned
# about, not fatal -- allows this library to be exercised/tested ahead of the
# daemon implementation landing.
_copy_bluetooth_daemon_files() {
  local dest="${INSTALL_DIR}/platform"
  mkdir -p "${dest}"

  # nullglob so a non-matching pattern expands to zero words instead of the
  # literal pattern string -- required under set -e so an empty match doesn't
  # get treated as a real (nonexistent) filename below.
  local restore_nullglob=0
  shopt -q nullglob || restore_nullglob=1
  shopt -s nullglob
  local src_files=("${AUTOSTREAM_DIR}"/platform/bluetooth_*.py)
  (( restore_nullglob )) && shopt -u nullglob

  if [[ ${#src_files[@]} -eq 0 ]]; then
    warn "No bluetooth_*.py modules found in ${AUTOSTREAM_DIR}/platform; skipping"
    return 0
  fi

  local f base
  for f in "${src_files[@]}"; do
    base="$(basename "${f}")"
    install -m 0644 -o root -g root "${f}" "${dest}/${base}"
  done
}

# _install_bluetooth_unit: install the unit file and reload systemd only.
# Deliberately does NOT enable or start it -- enabling/starting the
# Bluetooth input subsystem is a separate, privileged, runtime action, not
# part of installation. An update re-installs the unit file in place without
# touching whatever enabled/running state a later runtime action may have
# put it into.
_install_bluetooth_unit() {
  info "Installing ${BLUETOOTH_UNIT_NAME} (disabled)"
  install -m 0644 -o root -g root \
      "${AUTOSTREAM_DIR}/system/systemd/${BLUETOOTH_UNIT_NAME}" \
      "/etc/systemd/system/${BLUETOOTH_UNIT_NAME}"
  systemctl daemon-reload
}

_remove_bluetooth_unit() {
  systemctl disable --now "${BLUETOOTH_UNIT_NAME}" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/${BLUETOOTH_UNIT_NAME}"
  systemctl daemon-reload
}

#############################################
# Public entry points
#############################################

# install_bluetooth_stack: install the Bluetooth input subsystem. Idempotent;
# safe to call repeatedly. Called unconditionally from configure_phase on
# every install and update -- there is no on/off mode any more.
install_bluetooth_stack() {
  info "=== Bluetooth input: installing subsystem ==="

  apt_install bluez bluez-alsa-utils python3-dbus python3-gi python3-alsaaudio

  _install_bluetooth_module_config
  # Load the loopback immediately so no reboot is needed for it.
  modprobe snd-aloop || warn "modprobe snd-aloop failed; check dmesg"

  _install_bluetooth_main_conf

  # Debian's BlueZ D-Bus policy grants org.bluez access to the bluetooth
  # group -- this is the entire privilege story for the daemon; no sudoers
  # additions. The group is created by the bluez package installed above.
  ensure_user_in_group autostream bluetooth

  _copy_bluetooth_daemon_files
  _install_bluetooth_unit

  # bluez-alsa-utils ships bluealsa-aplay.service, which auto-plays every
  # incoming A2DP stream to a local ALSA output. The Bluetooth pump owns the
  # BlueALSA capture -> ASBT loopback path; bluealsa-aplay would compete for
  # the same capture stream, so keep it off. Guarded: harmless no-op if the
  # unit does not exist.
  systemctl disable --now bluealsa-aplay.service >/dev/null 2>&1 || true

  info "Bluetooth input subsystem installed (service disabled)"
}

# remove_bluetooth_stack: remove the Bluetooth input subsystem. Used only by
# autostream_uninstall.sh. Apt packages (bluez, bluez-alsa-utils, ...) are
# deliberately KEPT, consistent with the uninstaller's existing light-touch
# stance. No firmware work is needed: the dtoverlay=disable-bt line is
# owned by update_pi_firmware_config() (installer/lib/hardware.sh) -- written
# on fresh installs, preserved as-is on updates -- independently of whether
# this subsystem is present.
remove_bluetooth_stack() {
  info "=== Bluetooth input: removing subsystem ==="

  _remove_bluetooth_unit
  _remove_bluetooth_module_config
  _remove_bluetooth_main_conf

  info "Bluetooth input subsystem removed (apt packages retained)"
}
