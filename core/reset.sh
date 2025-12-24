#!/bin/bash
#
# This file is part of autostream.
# Copyright (c) 2025, Lo-tech Systems Limited. All rights reserved.
#
# Resets autotune and reboots the system. It will drop to hotspot mode on reboot.
# PIN is preserved. Edit /boot/firmware/pin.txt to change.
#
# Run as root (sudo ./reset.sh)

# Stop services
service stop autotune
service stop owntone

# Remove config files
rm /opt/autostream/autostream.ini
rm /opt/autostream/ssid

# Reset owntone
cp /etc/owntone.conf /opt/autostream/owntone/

# Get all saved Wi-Fi connection names and delete them
nmcli -t -f NAME,TYPE connection show \
  | awk -F: 'BEGIN{IGNORECASE=1} $2 ~ /(wifi|wireless)/ {print $1}' \
  | while IFS= read -r conn; do
      echo "Deleting Wi-Fi connection: $conn"
      nmcli connection delete id "$conn"
    done

# Reboot
reboot
