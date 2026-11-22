#!/bin/bash
HONEYPOT_IP="$1"
IFACE="enp0s3"

echo "[*] Assigning old vulnerable IP to honeypot on $IFACE (ip: $HONEYPOT_IP)"

ip addr add "$HONEYPOT_IP/24" dev "$IFACE"

