#!/bin/bash
HONEYPOT_IP="$1"
IFACE="enp0s3"

echo "[*] Removing honeypot IP $HONEYPOT_IP from $IFACE"

ip addr del "$HONEYPOT_IP/24" dev "$IFACE" 2>/dev/null