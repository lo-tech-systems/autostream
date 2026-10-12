#!/usr/bin/env bash
#
# installer/lib/hardware.sh
#
# Raspberry Pi hardware/platform helpers: firmware config.
# Sourced by autostream_install.sh; not executed directly.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

# shellcheck source=boot_files.sh
source "${BASH_SOURCE[0]%/*}/boot_files.sh"

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
# Low power mode (LOW_POWER=1, the installer's --low-power switch) also writes
# arm_freq=700, arm_boost=0 and force_turbo=0 under [all], replacing any
# arm_freq, arm_boost or force_turbo line already in the unconditional part of
# the file or under [all]; lines in other sections are left alone. Without it
# those three lines, and every other line (over_voltage included), are left
# exactly as they are, so a device that already has them keeps them.
#
# Accepts an optional path argument overriding the config.txt location, an
# optional mode argument overriding INSTALL_MODE (install|update), and an
# optional low-power argument (0|1) overriding LOW_POWER -- all used only by
# tests/test_bluetooth_installer.py and tests/test_low_power_mode.py to exercise
# this exact function against a temp file; all production callsites pass no
# arguments and keep today's hardcoded /boot/firmware/config.txt, the
# installer's own INSTALL_MODE and its own LOW_POWER.
update_pi_firmware_config() {
  local cfg="${1:-/boot/firmware/config.txt}"
  local mode="${2:-${INSTALL_MODE:-install}}"
  local low_power="${3:-${LOW_POWER:-0}}"
  if [[ ! -f "${cfg}" ]]; then
    warn "${cfg} not found; skipping firmware settings update."
    return 0
  fi
  info "Updating firmware settings in ${cfg}"

  local tmp
  tmp="$(boot_file_stage "${cfg}")" || { warn "Could not update ${cfg}."; return 1; }

  local bt_line="dtoverlay=disable-bt"
  local write_bt=1
  if [[ "${mode}" == "update" ]] && \
     ! grep -qE '^[[:space:]]*dtoverlay=disable-bt([[:space:]]*|,.*)$' "${cfg}"; then
    write_bt=0
  fi

  if grep -qE '^\s*\[all\]\s*$' "${cfg}"; then
    awk -v bt_line="${bt_line}" -v write_bt="${write_bt}" -v low_power="${low_power}" '
      BEGIN { inserted=0; cond=0 }
      /^[[:space:]]*\[/ { s=$0; gsub(/[[:space:]]/, "", s); cond=(s != "[all]") }
      /^[[:space:]]*dtparam=watchdog[[:space:]]*=.*$/ { next }
      /^[[:space:]]*gpu_mem[[:space:]]*=.*$/ { next }
      /^[[:space:]]*dtoverlay=disable-bt([[:space:]]*|,.*)$/ { next }
      low_power == "1" && !cond && /^[[:space:]]*(arm_freq|arm_boost|force_turbo)[[:space:]]*=/ { next }
      {
        print
        if (!inserted && $0 ~ /^[[:space:]]*\[all\][[:space:]]*$/) {
          print "dtparam=watchdog=on"
          print "gpu_mem=16"
          if (write_bt) print bt_line
          if (low_power == "1") {
            print "arm_freq=700"
            print "arm_boost=0"
            print "force_turbo=0"
          }
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
      if [[ "${low_power}" == "1" ]]; then
        echo "arm_freq=700"
        echo "arm_boost=0"
        echo "force_turbo=0"
      fi
      echo
      awk -v low_power="${low_power}" '
        BEGIN { cond=0 }
        /^[[:space:]]*\[/ { s=$0; gsub(/[[:space:]]/, "", s); cond=(s != "[all]") }
        /^[[:space:]]*dtparam=watchdog[[:space:]]*=.*$/ { next }
        /^[[:space:]]*gpu_mem[[:space:]]*=.*$/ { next }
        /^[[:space:]]*dtoverlay=disable-bt([[:space:]]*|,.*)$/ { next }
        low_power == "1" && !cond && /^[[:space:]]*(arm_freq|arm_boost|force_turbo)[[:space:]]*=/ { next }
        { print }
      ' "${cfg}"
    } > "${tmp}"
  fi

  boot_file_commit "${tmp}" "${cfg}" || { warn "Could not update ${cfg}."; return 1; }
}

#############################################
# Kernel command line and low power mode
#############################################

# boot_file_path: the path of a boot partition file (config.txt, cmdline.txt):
# under /boot/firmware where that directory exists, otherwise under /boot, the
# same choice the PIN file makes.
boot_file_path() {
  if [[ -d /boot/firmware ]]; then
    printf '%s\n' "/boot/firmware/$1"
  else
    printf '%s\n' "/boot/$1"
  fi
}

# _cmdline_rewrite: write the kernel command line back as one line.
# Usage: _cmdline_rewrite FILE HAS_TRAILING_NEWLINE LINE
# The first change to a file keeps a copy of the original beside it
# (FILE.autostream-bak), and a later change does not replace that copy. The
# file is replaced by renaming a finished copy over it (see boot_files.sh), so
# a power cut leaves the old line or the new one and never an empty file; its
# mode and ownership are carried across.
_cmdline_rewrite() {
  local file="$1" has_nl="$2" line="$3" tmp
  if [[ ! -e "${file}.autostream-bak" ]]; then
    cp -p "${file}" "${file}.autostream-bak" || \
      warn "Could not back up ${file}; continuing."
  fi
  tmp="$(boot_file_stage "${file}")" || return 1
  {
    printf '%s' "${line}"
    [[ "${has_nl}" == "1" ]] && printf '\n'
    true
  } > "${tmp}" || { boot_file_discard "${tmp}"; return 1; }
  boot_file_commit "${tmp}" "${file}"
}

# _cmdline_read: split a kernel command line file into its facts.
# Sets CMDLINE_LINE (the one line), CMDLINE_HAS_NL (1 when the file ends in a
# newline or is empty) and CMDLINE_TOKENS (the space-separated tokens).
# Returns 1, and warns, when the file has more than one non-blank line: the
# kernel reads a single line, and what the other lines mean is not guessed.
_cmdline_read() {
  local file="$1"
  CMDLINE_LINE=""
  CMDLINE_HAS_NL=1
  CMDLINE_TOKENS=()
  if [[ "$(grep -c '[^[:space:]]' "${file}")" -gt 1 ]]; then
    warn "${file} has more than one line; leaving it alone."
    return 1
  fi
  CMDLINE_LINE="$(grep -m1 '[^[:space:]]' "${file}" || true)"
  # A file saved with Windows line endings ends in a carriage return that is
  # not part of the command line; it is dropped, and the line is written back
  # with a plain newline.
  while [[ "${CMDLINE_LINE}" == *$'\r' ]]; do
    CMDLINE_LINE="${CMDLINE_LINE%$'\r'}"
  done
  if [[ -s "${file}" && -n "$(tail -c1 "${file}")" ]]; then
    CMDLINE_HAS_NL=0
  fi
  IFS=$' \t' read -r -a CMDLINE_TOKENS <<< "${CMDLINE_LINE}" || true
  return 0
}

# ensure_cmdline_option: make the kernel command line carry KEY=VALUE exactly
# once. Absent: appended. Present with another value: set to VALUE in place.
# Already KEY=VALUE once: the file is not touched. The line stays a single
# line, and keeps or lacks its trailing newline as it had.
# Usage: ensure_cmdline_option KEY VALUE [CMDLINE_FILE]
ensure_cmdline_option() {
  local key="$1" value="$2" file="${3:-$(boot_file_path cmdline.txt)}"
  if [[ ! -f "${file}" ]]; then
    warn "${file} not found; add ${key}=${value} to the kernel command line manually."
    return 0
  fi
  _cmdline_read "${file}" || return 0

  local tok found=0 changed=0
  local -a out=()
  for tok in ${CMDLINE_TOKENS[@]+"${CMDLINE_TOKENS[@]}"}; do
    if [[ "${tok}" == "${key}" || "${tok}" == "${key}="* ]]; then
      if (( found )); then
        changed=1
        continue
      fi
      found=1
      [[ "${tok}" == "${key}=${value}" ]] || changed=1
      out+=("${key}=${value}")
    else
      out+=("${tok}")
    fi
  done
  if (( ! found )); then
    out+=("${key}=${value}")
    changed=1
  fi
  (( changed )) || return 0

  local IFS=' '
  _cmdline_rewrite "${file}" "${CMDLINE_HAS_NL}" "${out[*]}" || \
    warn "Could not write ${key}=${value} to ${file}."
}

# remove_cmdline_option: take KEY=VALUE off the kernel command line. Only that
# exact token goes; the same key with another value, and every other token,
# stay. A file without the token is not touched.
# Usage: remove_cmdline_option KEY VALUE [CMDLINE_FILE]
remove_cmdline_option() {
  local key="$1" value="$2" file="${3:-$(boot_file_path cmdline.txt)}"
  [[ -f "${file}" ]] || return 0
  _cmdline_read "${file}" || return 0

  local tok removed=0
  local -a out=()
  for tok in ${CMDLINE_TOKENS[@]+"${CMDLINE_TOKENS[@]}"}; do
    if [[ "${tok}" == "${key}=${value}" ]]; then
      removed=1
    else
      out+=("${tok}")
    fi
  done
  (( removed )) || return 0

  local IFS=' '
  _cmdline_rewrite "${file}" "${CMDLINE_HAS_NL}" "${out[*]-}" || \
    warn "Could not remove ${key}=${value} from ${file}."
}

# apply_low_power_cmdline: the kernel command line half of low power mode
# (maxcpus=2). The config.txt half is written by update_pi_firmware_config.
# Both take effect at the next boot.
apply_low_power_cmdline() {
  ensure_cmdline_option maxcpus 2 "$@"
}

# Where low power mode records what it replaced, in the directory only root can
# write (the service account owns /var/lib/autostream and could plant lines
# there that root would then write into the boot files).
LOW_POWER_RECORD_FILE="/var/lib/autostream-update/low-power-restore.env"

# record_low_power_originals: before low power mode first changes anything,
# note which lines of its own it is about to replace, so removing the mode can
# put them back: an arm_freq, arm_boost or force_turbo line in the unconditional
# part of config.txt or under [all] with a numeric value (a line in any other
# section is left alone by the mode, and so is not recorded), and a maxcpus
# token on the kernel command line with a value other than 2. A line that is
# exactly what the mode writes, under [all], is not recorded: it cannot be told
# from the mode's own. The record is made once; if it exists it is left as it
# is, so a later run, which finds the mode's own lines, cannot overwrite what
# the board had before. An empty record (nothing replaced) is still a record.
# Usage: record_low_power_originals [CONFIG_FILE [CMDLINE_FILE [RECORD_FILE]]]
record_low_power_originals() {
  local cfg="${1:-$(boot_file_path config.txt)}"
  local cmdline="${2:-$(boot_file_path cmdline.txt)}"
  local rec="${3:-${LOW_POWER_RECORD_FILE}}"
  if [[ -e "${rec}" || -L "${rec}" ]]; then
    return 0
  fi
  local dir
  dir="$(dirname -- "${rec}")"
  if [[ "${rec}" == "${LOW_POWER_RECORD_FILE}" ]] && declare -F ensure_update_state_dir >/dev/null; then
    ensure_update_state_dir "${dir}" || { warn "Could not prepare ${dir}; not recording the previous CPU settings."; return 0; }
  else
    mkdir -p -- "${dir}" || { warn "Could not create ${dir}; not recording the previous CPU settings."; return 0; }
  fi

  local body="# What low power mode replaced. Put back when it is removed."
  if [[ -f "${cfg}" ]]; then
    local found
    found="$(awk '
      BEGIN { sec="top" }
      /^[[:space:]]*\[/ { s=$0; gsub(/[[:space:]]/, "", s); sec=(s == "[all]") ? "all" : "other" }
      sec != "other" && /^[[:space:]]*(arm_freq|arm_boost|force_turbo)[[:space:]]*=[[:space:]]*[0-9]+[[:space:]]*$/ {
        line=$0; gsub(/[[:space:]]/, "", line); split(line, kv, "=")
        ours = (sec == "all" && ((kv[1] == "arm_freq" && kv[2] == "700") || \
                                 (kv[1] == "arm_boost" && kv[2] == "0") || \
                                 (kv[1] == "force_turbo" && kv[2] == "0")))
        if (!ours) print "CONFIG=" sec ":" kv[1] ":" kv[2]
      }
    ' "${cfg}")" || found=""
    [[ -z "${found}" ]] || body+=$'\n'"${found}"
  fi
  if [[ -f "${cmdline}" ]] && _cmdline_read "${cmdline}"; then
    local tok
    for tok in ${CMDLINE_TOKENS[@]+"${CMDLINE_TOKENS[@]}"}; do
      if [[ "${tok}" =~ ^maxcpus=([0-9]+)$ && "${BASH_REMATCH[1]}" != "2" ]]; then
        body+=$'\n'"MAXCPUS=${BASH_REMATCH[1]}"
        break
      fi
    done
  fi
  printf '%s\n' "${body}" | write_state_file "${rec}" 0600 || \
    warn "Could not record the previous CPU settings in ${rec}."
}

# _read_low_power_record: print the lines of the record that are what the
# installer writes, and nothing else: a CONFIG line for one of the three keys
# with a numeric value and a place, or a numeric MAXCPUS line. The file is read
# without following a link and only if it is a regular file the reader owns.
# Returns 1 when there is no usable record.
_read_low_power_record() {
  local rec="$1" content line
  [[ -f "${rec}" && ! -L "${rec}" && "$(stat -c '%u' -- "${rec}" 2>/dev/null)" == "$(id -u)" ]] || return 1
  content="$(dd if="${rec}" iflag=nofollow,nonblock bs=65536 count=1 status=none 2>/dev/null)" || return 1
  while IFS= read -r line || [[ -n "${line}" ]]; do
    if [[ "${line}" =~ ^CONFIG=(top|all):(arm_freq|arm_boost|force_turbo):[0-9]+$ \
          || "${line}" =~ ^MAXCPUS=[0-9]+$ ]]; then
      printf '%s\n' "${line}"
    fi
  done <<< "${content}"
  return 0
}

# remove_low_power_settings: take back what low power mode added: maxcpus=2 on
# the kernel command line, and arm_freq=700, arm_boost=0 and force_turbo=0 from
# the unconditional part of config.txt and [all]. Only those exact settings go;
# the same keys with other values, other sections and over_voltage are left
# alone. What the mode replaced when it was first applied (see
# record_low_power_originals) is put back: config.txt lines in the part of the
# file they came from, and the maxcpus value the command line had. Without a
# record only the added settings are removed.
# Usage: remove_low_power_settings [CONFIG_FILE [CMDLINE_FILE [RECORD_FILE]]]
remove_low_power_settings() {
  local cfg="${1:-$(boot_file_path config.txt)}"
  local cmdline="${2:-$(boot_file_path cmdline.txt)}"
  local rec="${3:-${LOW_POWER_RECORD_FILE}}"

  local top="" all="" maxcpus="" line value
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    if [[ "${line}" == MAXCPUS=* ]]; then
      maxcpus="${line#MAXCPUS=}"
    else
      value="${line#CONFIG=}"           # place:key:number
      if [[ "${value}" == top:* ]]; then
        top+="${value#top:}"'\n'
      else
        all+="${value#all:}"'\n'
      fi
    fi
  done < <(_read_low_power_record "${rec}" || true)
  # The record's "key:number" becomes the "key=number" line it came from.
  top="${top//:/=}"
  all="${all//:/=}"

  if [[ -f "${cfg}" ]]; then
    local tmp
    tmp="$(boot_file_stage "${cfg}")" || { warn "Could not update ${cfg}."; tmp=""; }
    if [[ -n "${tmp}" ]]; then
      awk -v top="${top}" -v all="${all}" '
        BEGIN { cond=0; done_top=(top == ""); done_all=(all == "") }
        /^[[:space:]]*\[/ {
          s=$0; gsub(/[[:space:]]/, "", s); cond=(s != "[all]")
          if (!done_top) { printf "%s", top; done_top=1 }
          print
          if (s == "[all]" && !done_all) { printf "%s", all; done_all=1 }
          next
        }
        !cond && /^[[:space:]]*(arm_freq=700|arm_boost=0|force_turbo=0)[[:space:]]*$/ { next }
        { print }
        END {
          if (!done_top) printf "%s", top
          if (!done_all) { print "[all]"; printf "%s", all }
        }
      ' "${cfg}" > "${tmp}"
      if cmp -s "${tmp}" "${cfg}"; then
        boot_file_discard "${tmp}"
      else
        boot_file_commit "${tmp}" "${cfg}" || warn "Could not update ${cfg}."
      fi
    fi
  fi
  if [[ -n "${maxcpus}" ]]; then
    ensure_cmdline_option maxcpus "${maxcpus}" "${cmdline}"
  else
    remove_cmdline_option maxcpus 2 "${cmdline}"
  fi
  rm -f -- "${rec}"
}
