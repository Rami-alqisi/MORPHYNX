#!/bin/bash
ORIGINAL_IP="$1"
SAFE_IP="$2"
IFACE="enp0s3"

echo "[*] Rolling back server IP from $SAFE_IP to $ORIGINAL_IP on $IFACE"

ip addr del "$SAFE_IP/24" dev "$IFACE" 2>/dev/null
ip addr add "$ORIGINAL_IP/24" dev "$IFACE"
