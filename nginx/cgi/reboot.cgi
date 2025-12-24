#!/usr/bin/env bash
# This file is part of autostream.
# Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

set -euo pipefail

# Create the reboot request flag with reason
printf "UserRequestSystemError" > /tmp/rebootrequired

# Redirect to branded rebooting page
printf "Status: 302 Found\r\n"
printf "Location: /offline/rebooting\r\n"
printf "Cache-Control: no-store\r\n"
printf "\r\n"
