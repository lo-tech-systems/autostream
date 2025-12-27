#!/bin/bash

# Resets autotune and reboots the system. It will drop to hotspot mode.

# Stop services
service stop autotune
service stop owntone

# Remove config files
rm /opt/autostream/autostream.ini
rm /opt/autostream/cpuid
rm /opt/autostream/ssid

# Get all saved Wi-Fi connection names and delete them
nmcli -t -f NAME,TYPE connection show \
  | awk -F: 'BEGIN{IGNORECASE=1} $2 ~ /(wifi|wireless)/ {print $1}' \
  | while IFS= read -r conn; do
      echo "Deleting Wi-Fi connection: $conn"
      nmcli connection delete id "$conn"
    done

# Reboot
reboot
