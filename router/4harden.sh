#!/usr/bin/env bash
set -euo pipefail

echo "[*] Hardening VyOS services"

configure

# Disable SSH by removing its config entirely
# delete service ssh

# Disable SNMP by removing its config entirely
delete service snmp

# Optional: disable LLDP if you do not want device discovery chatter
delete service lldp

# Optional: disable config-sync if it exists
delete service config-sync

# Optional: disable console-server if it exists
delete service console-server

commit-confirm 5
save

echo "[*] Verifying local listeners"
run ss -lntup || true

echo "[*] Checking TCP 22 / TCP 23"
if run ss -lnt | grep -Eq '(^|[[:space:]])LISTEN.*:22[[:space:]]'; then
  echo "[!] SSH still appears to be listening on :22"
else
  echo "[+] SSH not listening on :22"
fi

if run ss -lnt | grep -Eq '(^|[[:space:]])LISTEN.*:23[[:space:]]'; then
  echo "[!] Something is listening on :23"
else
  echo "[+] Nothing listening on :23"
fi

echo "[*] Done"