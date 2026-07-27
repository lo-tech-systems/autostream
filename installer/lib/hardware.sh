#!/usr/bin/env bash
#
# installer/lib/hardware.sh
#
# Raspberry Pi hardware/platform helpers: firmware config and sdmon patching.
# Sourced by autostream_install.sh; not executed directly.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

#############################################
# Firmware / watchdog helpers
#############################################

# update_pi_firmware_config: idempotent strip-then-insert of the watchdog and
# disable-bt lines in /boot/firmware/config.txt. dtoverlay=disable-bt is
# always written -- the onboard Bluetooth radio stays disabled by default on
# every appliance; enabling it is a separate, later, opt-in runtime action
# and is not part of installation.
#
# Accepts an optional path argument overriding the config.txt location, used
# only by tests/test_bluetooth_installer.py to exercise this exact function
# against a temp file; all production callsites pass no argument and keep
# today's hardcoded /boot/firmware/config.txt.
update_pi_firmware_config() {
  local cfg="${1:-/boot/firmware/config.txt}"
  if [[ ! -f "${cfg}" ]]; then
    warn "${cfg} not found; skipping firmware settings update."
    return 0
  fi
  info "Updating firmware settings in ${cfg}"

  local tmp
  tmp="$(mktemp)"

  local bt_line="dtoverlay=disable-bt"

  if grep -qE '^\s*\[all\]\s*$' "${cfg}"; then
    awk -v bt_line="${bt_line}" '
      BEGIN { inserted=0 }
      /^[[:space:]]*dtparam=watchdog[[:space:]]*=.*$/ { next }
      /^[[:space:]]*dtoverlay=disable-bt([[:space:]]*|,.*)$/ { next }
      {
        print
        if (!inserted && $0 ~ /^[[:space:]]*\[all\][[:space:]]*$/) {
          print "dtparam=watchdog=on"
          print bt_line
          inserted=1
        }
      }
    ' "${cfg}" > "${tmp}"
  else
    {
      echo "[all]"
      echo "dtparam=watchdog=on"
      echo "${bt_line}"
      echo
      awk '
        /^[[:space:]]*dtparam=watchdog[[:space:]]*=.*$/ { next }
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

#############################################
# sdmon helper
#############################################
patch_sdmon_service_method() {
  local method="$1"
  local svc="/etc/systemd/system/autostream_sdcardhealth.service"

  [[ -f "${svc}" ]] || { warn "sdmon service not found at ${svc}; cannot patch method"; return 0; }

  local method_args="-m ${method}"
  if [[ "${method}" == "2step" ]]; then
    method_args="${method_args} -a"
  fi

  if grep -qE "^ExecStart=.*\\bsdmon\\b" "${svc}"; then
    info "Patching ${svc} to set sdmon method: ${method}"
    sed -i -E \
      "/^ExecStart=.*\\bsdmon\\b/ {
        s/[[:space:]]-m[[:space:]]+[A-Za-z0-9_-]+//g
        s/[[:space:]]-a//g
        s#(\\bsdmon\\b[^\n]*)([[:space:]]+/dev/)#\\1 ${method_args}\\2#
      }" \
      "${svc}"
  else
    warn "No ExecStart line referencing sdmon found in ${svc}; cannot patch method"
  fi
}
