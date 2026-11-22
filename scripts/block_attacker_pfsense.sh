#!/bin/bash

ATTACKER_IP="$1"

PFSENSE_IP="10.0.0.1"
PFSENSE_USER="admin"

echo "[*] Blocking attacker $ATTACKER_IP on pfSense..."

ssh -o StrictHostKeyChecking=no \
$PFSENSE_USER@$PFSENSE_IP \
"pfctl -t morphynx_block -T add $ATTACKER_IP"

echo "[+] Attacker blocked successfully."