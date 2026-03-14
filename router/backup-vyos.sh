#!/usr/bin/env bash
set -euo pipefail

TS="$(date +%Y%m%d-%H%M%S)"
DEST_BASE="./backups/$TS"
mkdir -p "$DEST_BASE"

cp /config/config.boot "$DEST_BASE/config.boot"

vbash -s <<'EOF' > "$DEST_BASE/show-configuration-commands.txt"
source /opt/vyatta/etc/functions/script-template
run show configuration commands
exit
EOF

tar -czf "$DEST_BASE/config-dir.tgz" /config

cp "$DEST_BASE/config.boot" /tmp/config.boot.$TS
cp "$DEST_BASE/show-configuration-commands.txt" /tmp/show-config.$TS.txt

echo "[*] Backup written to $DEST_BASE and /tmp"