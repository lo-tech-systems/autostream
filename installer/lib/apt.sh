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
