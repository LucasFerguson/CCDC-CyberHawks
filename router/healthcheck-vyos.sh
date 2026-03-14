#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="/config/healthcheck"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$OUT_DIR/$TS"
mkdir -p "$OUT"

echo "[*] Writing health snapshot to $OUT"

vbash -s <<'EOF' > "$OUT/vyos.txt"
source /opt/vyatta/etc/functions/script-template

echo "===== VERSION ====="
run show version
echo

echo "===== SYSTEM IMAGE ====="
run show system image
echo

echo "===== INTERFACES ====="
run show interfaces
echo

echo "===== ROUTES ====="
run show ip route
echo

echo "===== CONFIG COMMANDS ====="
run show configuration commands
echo

echo "===== LOG ====="
run show log
echo

exit
EOF

ip -br link > "$OUT/ip-link.txt"
ip -br addr > "$OUT/ip-addr.txt"
ip route show table all > "$OUT/ip-route.txt"
ss -lntup > "$OUT/listening.txt" || true
ps -ef > "$OUT/ps.txt"
systemctl list-unit-files --type=service --state=enabled > "$OUT/enabled-services.txt" || true
systemctl list-units --type=service --state=running > "$OUT/running-services.txt" || true
getent passwd > "$OUT/passwd.txt"

if [ -f /config/config.boot ]; then
  sha256sum /config/config.boot > "$OUT/config.boot.sha256"
fi

if [ -d /config/scripts ]; then
  ls -laR /config/scripts > "$OUT/config-scripts.txt"
fi

echo "[*] Done"