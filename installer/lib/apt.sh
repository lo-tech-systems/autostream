#!/usr/bin/env bash
#
# installer/lib/apt.sh
#
# Package-manager housekeeping shared by the appliance and dial installers;
# sourced, not executed directly.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

recover_interrupted_packages() {
  # A power cut or crash in the middle of an apt run leaves dpkg with
  # half-configured packages, and apt then refuses every further install or
  # upgrade ("dpkg was interrupted, you must manually run dpkg --configure -a"),
  # so each automatic retry of an update fails the same way. Finish that
  # configuration before the first apt command of an install or update. On a
  # healthy system this does nothing. Best effort: if it cannot run (another
  # package manager holds the lock) the installer carries on, and the apt step
  # that follows reports whatever is still wrong.
  if ! DEBIAN_FRONTEND=noninteractive dpkg --configure -a; then
    echo "WARNING: dpkg --configure -a did not complete; continuing" >&2
  fi
}

clean_package_cache() {
  # Delete the downloaded package files kept in /var/cache/apt/archives: they
  # are only needed to reinstall a package offline, and on a small SD card they
  # grow to hundreds of megabytes over an install or update. Call it only once
  # an install or update is known good. It does not remove any installed
  # package, and the package lists are kept. Best effort: a failure (the
  # package manager is busy, say) is a warning and never fails the install.
  if ! apt-get clean; then
    echo "WARNING: apt-get clean failed; the package cache was left as it was" >&2
  fi
  return 0
}

apt_remove_guarded() {
  # Remove or purge the named packages only if apt says nothing else would go
  # with them. A package can have a dependant nobody expected (an operating
  # system update can add one), and removing it would take that with it; this
  # asks apt first with a simulation and, when the simulation lists any
  # package that was not named, or cannot be run, warns and removes nothing.
  # Returns 1 for a removal refused or failed, 0 otherwise (also when there is
  # nothing to remove).
  # Usage: apt_remove_guarded remove|purge PACKAGE...
  local action="$1" simulation line name pkg listed
  local -a extra=()
  shift
  (( $# )) || return 0
  if ! simulation="$(LC_ALL=C DEBIAN_FRONTEND=noninteractive apt-get -s "${action}" -y "$@" 2>&1)"; then
    echo "WARNING: could not check what apt-get ${action} $* would remove; leaving it installed" >&2
    return 1
  fi
  while IFS= read -r line; do
    case "${line}" in
      Remv\ *|Purg\ *)
        name="${line#* }"
        name="${name%% *}"
        name="${name%%:*}"
        listed=0
        for pkg in "$@"; do
          [[ "${pkg}" == "${name}" ]] && listed=1
        done
        (( listed )) || extra+=("${name}")
        ;;
    esac
  done <<< "${simulation}"
  if (( ${#extra[@]} )); then
    echo "WARNING: apt-get ${action} $* would also remove ${extra[*]}; leaving it installed" >&2
    return 1
  fi
  DEBIAN_FRONTEND=noninteractive apt-get "${action}" -y "$@"
}

# ---- Waiting for the network ---------------------------------------------------
# An update can restart networking itself: upgrading the Wi-Fi authentication
# service, NetworkManager, radio firmware or a driver drops the link for a
# while. The steps that download must not fail just because that happened a
# moment ago. Budget: a link that has lost its radio is normally back within
# seconds once the Wi-Fi watcher reconnects it, but a link that stays down is
# reconnected by the watcher only after five minutes and then every two, so a
# step waits long enough to cover one full cycle of that: nine minutes,
# checking every five seconds. A device that is truly offline waits once, for
# this long, and every step after that fails at once. Overridable in the
# environment.
: "${NETWORK_WAIT_BUDGET:=540}"
: "${NETWORK_WAIT_INTERVAL:=5}"
# Longest a test connection to a host may take.
: "${NETWORK_CONNECT_TIMEOUT:=5}"
# Where the package sources are read from (a test points it elsewhere).
: "${NETWORK_APT_ETC:=/etc/apt}"
# Used when the configured sources name no host that can be resolved.
: "${NETWORK_FALLBACK_HOSTS:=deb.debian.org archive.raspberrypi.com}"
# Output that marks a failed step as the network's fault.
NETWORK_FAILURE_PATTERN='Failed to fetch|Temporary failure resolving|Temporary failure in name resolution|Could not resolve|Name or service not known|Network is unreachable|No route to host|Connection timed out|Connection failed|Failed to connect|Unable to connect|Read timed out|Max retries exceeded'
# Set once a wait has used its whole budget, so that the steps after it on a
# device that is truly offline fail at once instead of each waiting again.
NETWORK_WAIT_GAVE_UP=0

network_apt_hosts() {
  # The host names apt is configured to download from, one per line (at most
  # four), read from the classic and the deb822 source files.
  local files=() f
  for f in "${NETWORK_APT_ETC}/sources.list" \
           "${NETWORK_APT_ETC}"/sources.list.d/*.list \
           "${NETWORK_APT_ETC}"/sources.list.d/*.sources; do
    [[ -r "${f}" ]] && files+=("${f}")
  done
  (( ${#files[@]} )) || return 0
  grep -hE '^(deb|deb-src|URIs:)' "${files[@]}" 2>/dev/null \
    | grep -oE '(https?|ftp)://[^/ ]+' \
    | sed -E 's#^[a-z]+://##; s#^[^@]*@##; s#:[0-9]+$##' \
    | sort -u | head -n 4
}

network_interface_ready() {
  # True when the interface has a carrier and a global address.
  local dev="$1" link
  link="$(ip -o link show dev "${dev}" 2>/dev/null)" || true
  [[ "${link}" != *NO-CARRIER* ]] || return 1
  [[ -n "$(ip -o addr show dev "${dev}" scope global 2>/dev/null)" ]]
}

network_connect() {
  # True when a TCP connection to HOST can be opened now, on the https port or
  # else the http one. The name is resolved as part of the connection, so an
  # answer left in a resolver's cache while the link is down does not count.
  timeout "${NETWORK_CONNECT_TIMEOUT}" bash -c \
    'true 3<>"/dev/tcp/$0/443" || true 3<>"/dev/tcp/$0/80"' "$1" >/dev/null 2>&1
}

network_usable() {
  # True when a download can be expected to work now: a default route exists,
  # the interface it leaves by has a carrier and an address, and a connection
  # can be opened to a host the next step needs. The hosts are the arguments;
  # with none, the ones apt is configured to use, or else the Debian and
  # Raspberry Pi archives. One reachable host is enough, so a single dead
  # mirror does not hold the install up. Nothing here depends on the kind of
  # link, so a device on a cable passes the same way.
  local hosts=("$@") host dev ready=0
  if command -v ip >/dev/null 2>&1; then
    local routes
    routes="$(ip -o route show default 2>/dev/null; ip -o -6 route show default 2>/dev/null)"
    [[ -n "${routes}" ]] || return 1
    while read -r dev; do
      [[ -n "${dev}" ]] || continue
      if network_interface_ready "${dev}"; then
        ready=1
        break
      fi
    done < <(grep -oE ' dev [^ ]+' <<< "${routes}" | awk '{print $2}' | sort -u)
    (( ready )) || return 1
  fi
  if (( ${#hosts[@]} == 0 )); then
    mapfile -t hosts < <(network_apt_hosts)
    if (( ${#hosts[@]} == 0 )); then
      read -r -a hosts <<< "${NETWORK_FALLBACK_HOSTS}"
    fi
  fi
  for host in "${hosts[@]}"; do
    if network_connect "${host}"; then
      return 0
    fi
  done
  return 1
}

network_wait() {
  # Return at once when the network is usable. Otherwise wait for it, up to
  # NETWORK_WAIT_BUDGET seconds, saying so once at the start and once at the
  # end. Returns 1 when the budget ran out; a later call on a network that is
  # still down then returns 1 straight away. The hosts to check are arguments,
  # as for network_usable.
  local start="${SECONDS}" waited=0 elapsed
  if network_usable "$@"; then
    NETWORK_WAIT_GAVE_UP=0
    return 0
  fi
  if [[ "${NETWORK_WAIT_GAVE_UP}" == 1 ]]; then
    return 1
  fi
  echo "The network is not available; waiting up to ${NETWORK_WAIT_BUDGET}s for it to return."
  # The count of sleeps bounds the wait when the clock is not trusted; the
  # clock bounds it when the checks themselves are slow.
  while (( waited < NETWORK_WAIT_BUDGET && SECONDS - start < NETWORK_WAIT_BUDGET )); do
    sleep "${NETWORK_WAIT_INTERVAL}"
    waited=$(( waited + NETWORK_WAIT_INTERVAL ))
    if network_usable "$@"; then
      elapsed=$(( SECONDS - start ))
      (( elapsed > waited )) && waited="${elapsed}"
      echo "The network is back after about ${waited}s."
      NETWORK_WAIT_GAVE_UP=0
      return 0
    fi
  done
  echo "WARNING: the network did not return within ${NETWORK_WAIT_BUDGET}s" >&2
  NETWORK_WAIT_GAVE_UP=1
  return 1
}

network_attempt() {
  # Run a command, passing its output through and keeping a copy in a file.
  # Usage: network_attempt OUTFILE COMMAND [ARG...]; returns the command's status.
  local out="$1" rc
  shift
  if "$@" 2>&1 | tee "${out}"; then
    rc="${PIPESTATUS[0]}"
  else
    rc="${PIPESTATUS[0]}"
  fi
  return "${rc}"
}

network_failed() {
  # True when a failed step looks to have failed because of the network: its
  # output (the file named first) says so, or the network is not usable now.
  # The hosts to check are the remaining arguments.
  local out="$1"
  shift
  grep -qE "${NETWORK_FAILURE_PATTERN}" "${out}" || ! network_usable "$@"
}

network_step() {
  # Run a step that downloads: wait for the network first; if the step then
  # fails because of the network, wait again and run it once more. A second
  # failure is returned to the caller after a message saying the network was
  # not available. A failure that is not the network's fault is returned at
  # once. The command may be a function (it runs in a subshell, so it must not
  # be relied on to set variables).
  # Usage: network_step [--host HOST]... COMMAND [ARG...]
  # --host names what the step downloads from, when that is not apt's mirror.
  local hosts=() out rc=0 gave_up=0
  while [[ "${1:-}" == --host ]]; do
    hosts+=("$2")
    shift 2
  done
  network_wait "${hosts[@]}" || gave_up=1
  out="$(mktemp)"
  network_attempt "${out}" "$@" || rc=$?
  if (( rc == 0 )); then
    rm -f "${out}"
    return 0
  fi
  if ! network_failed "${out}" "${hosts[@]}"; then
    rm -f "${out}"
    return "${rc}"
  fi
  if (( ! gave_up )); then
    echo "Step failed because the network was not available; trying once more: $*" >&2
    if network_wait "${hosts[@]}"; then
      rc=0
      network_attempt "${out}" "$@" || rc=$?
      if (( rc == 0 )); then
        rm -f "${out}"
        return 0
      fi
      if ! network_failed "${out}" "${hosts[@]}"; then
        rm -f "${out}"
        return "${rc}"
      fi
    fi
  fi
  rm -f "${out}"
  echo "ERROR: the network was not available, so this step failed: $*" >&2
  return "${rc}"
}
