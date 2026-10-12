#!/usr/bin/env bash
#
# installer/lib/wifi_restore.sh
#
# Hands saved Wi-Fi profiles back to NetworkManager. Shared by the appliance
# and dial uninstallers; sourced, not executed directly. The caller provides
# info() and warn().
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

restore_wifi_profiles() {
  # The wifi watcher (see migrate_client_profiles_autoconnect_no in
  # platform/wifi_config.py) sets connection.autoconnect no on every Wi-Fi
  # client profile and is the sole reconnection agent while autostream is
  # installed; a surviving profile may also carry an 802-11-wireless.bssid
  # pin and a connection.interface-name restriction. Once autostream is
  # uninstalled nothing re-enables those profiles, so hand Wi-Fi back to
  # stock NetworkManager behaviour here. This is best-effort: a missing
  # nmcli, a stopped NetworkManager, or a single profile failure must not
  # abort the uninstall.
  if ! command -v nmcli >/dev/null 2>&1; then
    info "nmcli not found; skipping Wi-Fi profile restoration"
    return 0
  fi

  info "Restoring Wi-Fi connection profiles to NetworkManager defaults"

  local uuid type mode
  while IFS=: read -r uuid type; do
    [[ "${type}" == "802-11-wireless" ]] || continue

    mode="$(nmcli -g 802-11-wireless.mode connection show "${uuid}" 2>/dev/null || true)"

    if [[ "${mode}" == "ap" ]]; then
      if nmcli connection delete "${uuid}" >/dev/null 2>&1; then
        info "Deleted leftover AP profile ${uuid}"
      else
        warn "Failed to delete AP profile ${uuid}"
      fi
    else
      if nmcli connection modify "${uuid}" \
          connection.autoconnect yes \
          802-11-wireless.bssid "" \
          connection.interface-name "" >/dev/null 2>&1; then
        info "Restored autoconnect and cleared pins on Wi-Fi profile ${uuid}"
      else
        warn "Failed to restore Wi-Fi profile ${uuid}"
      fi
    fi
  done < <(nmcli -t -f UUID,TYPE connection show 2>/dev/null || true)
}
