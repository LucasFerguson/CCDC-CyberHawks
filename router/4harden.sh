#!/bin/vbash

if [ "$(id -g -n)" != "vyattacfg" ]; then
    exec sg vyattacfg -c "/bin/vbash $(readlink -f "$0") $@"
fi

source /opt/vyatta/etc/functions/script-template
set -e

echo "[*] Hardening VyOS services"

configure

delete service ssh
delete service snmp
delete service lldp
delete service config-sync
delete service console-server

commit-confirm 5
save

echo "[*] Verifying listeners"
run ss -lntup || true

if run ss -lnt | grep -Eq '(^|[[:space:]])LISTEN.*:22([[:space:]]|$)'; then
    echo "[!] SSH still appears to be listening on :22"
else
    echo "[+] SSH not listening on :22"
fi

if run ss -lnt | grep -Eq '(^|[[:space:]])LISTEN.*:23([[:space:]]|$)'; then
    echo "[!] Something is listening on :23"
else
    echo "[+] Nothing listening on :23"
fi

exit