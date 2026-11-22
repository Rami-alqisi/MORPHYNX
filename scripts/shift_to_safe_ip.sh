#!/bin/bash
OLD_IP="$1"
NEW_IP="$2"

IFACE="enp0s3"

echo "[*] Shifting real server IP from $OLD_IP to $NEW_IP on $IFACE"

ip addr del "$OLD_IP/24" dev "$IFACE" 2>/dev/null
ip addr add "$NEW_IP/24" dev "$IFACE"
