#!/usr/bin/env bash
#
# installer/lib/hardware.sh
#
# Raspberry Pi hardware/platform helpers: firmware config.
# Sourced by autostream_install.sh; not executed directly.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

#############################################
# Firmware / watchdog helpers
#############################################

# update_pi_firmware_config: idempotent strip-then-insert of the watchdog,
# GPU memory, and disable-bt lines in /boot/firmware/config.txt.
#
# dtoverlay=disable-bt doubles as the onboard-Bluetooth setting store: the
# Setup page's onboard-radio toggle removes/reinserts the line in place
# (autostream_admin bt-onboard-on/off) and no other record of the choice
# exists. A FRESH install therefore writes the line (radio disabled by
# default; enabling it is a separate, later, opt-in runtime action), while
# an UPDATE preserves the line's current presence/absence -- re-asserting
# the fresh-install default would silently revert the opt-in, with the
# radio loss deferred to whenever the appliance next reboots. The watchdog
# and gpu_mem lines are unconditional in both modes: the appliance is
# headless (no HDMI console in normal operation), so the GPU memory split
# is minimised to leave more RAM to the audio pipeline, and that is a
# permanent property of the appliance, not a runtime opt-in like the radio.
#
# Accepts an optional path argument overriding the config.txt location, and
# an optional mode argument overriding INSTALL_MODE (install|update) -- both
# used only by tests/test_bluetooth_installer.py to exercise this exact
# function against a temp file; all production callsites pass no arguments
# and keep today's hardcoded /boot/firmware/config.txt and the installer's
# own INSTALL_MODE.
update_pi_firmware_config() {
  local cfg="${1:-/boot/firmware/config.txt}"
  local mode="${2:-${INSTALL_MODE:-install}}"
  if [[ ! -f "${cfg}" ]]; then
    warn "${cfg} not found; skipping firmware settings update."
    return 0
  fi
  info "Updating firmware settings in ${cfg}"

  local tmp
  tmp="$(mktemp)"

  local bt_line="dtoverlay=disable-bt"
  local write_bt=1
  if [[ "${mode}" == "update" ]] && \
     ! grep -qE '^[[:space:]]*dtoverlay=disable-bt([[:space:]]*|,.*)$' "${cfg}"; then
    write_bt=0
  fi

  if grep -qE '^\s*\[all\]\s*$' "${cfg}"; then
    awk -v bt_line="${bt_line}" -v write_bt="${write_bt}" '
      BEGIN { inserted=0 }
      /^[[:space:]]*dtparam=watchdog[[:space:]]*=.*$/ { next }
      /^[[:space:]]*gpu_mem[[:space:]]*=.*$/ { next }
      /^[[:space:]]*dtoverlay=disable-bt([[:space:]]*|,.*)$/ { next }
      {
        print
        if (!inserted && $0 ~ /^[[:space:]]*\[all\][[:space:]]*$/) {
          print "dtparam=watchdog=on"
          print "gpu_mem=16"
          if (write_bt) print bt_line
          inserted=1
        }
      }
    ' "${cfg}" > "${tmp}"
  else
    {
      echo "[all]"
      echo "dtparam=watchdog=on"
      echo "gpu_mem=16"
      if [[ "${write_bt}" == "1" ]]; then
        echo "${bt_line}"
      fi
      echo
      awk '
        /^[[:space:]]*dtparam=watchdog[[:space:]]*=.*$/ { next }
        /^[[:space:]]*gpu_mem[[:space:]]*=.*$/ { next }
        /^[[:space:]]*dtoverlay=disable-bt([[:space:]]*|,.*)$/ { next }
        { print }
      ' "${cfg}"
    } > "${tmp}"
  fi

  install -m "$(stat -c %a "${cfg}")" \
          -o "$(stat -c %u "${cfg}")" \
          -g "$(stat -c %g "${cfg}")" \
          "${tmp}" "${cfg}"
  rm -f "${tmp}"
}
