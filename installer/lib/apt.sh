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
