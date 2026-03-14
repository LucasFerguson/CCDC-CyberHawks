#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="./healthcheck"
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

# Create a simple manifest of generated files
{
  echo "Health Check Snapshot"
  echo "Timestamp: $TS"
  echo "Path: $OUT"
  echo
  echo "Generated files:"
  find "$OUT" -maxdepth 1 -type f | sort | sed "s|$OUT/|- |"
} > "$OUT/summary.txt"

# Hash all generated files for quick integrity comparison
(
  cd "$OUT"
  sha256sum *.txt *.sha256 2>/dev/null | sort > file-hashes.txt || true
)

# Update 'latest' symlink
ln -sfn "$TS" "$OUT_DIR/latest"

echo "[*] Created Health Check at $OUT"
echo "[*] Summary file: $OUT/summary.txt"
echo "[*] Hash manifest: $OUT/file-hashes.txt"