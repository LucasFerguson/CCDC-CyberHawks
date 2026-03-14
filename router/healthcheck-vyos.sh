#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="./healthcheck"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$OUT_DIR/$TS"
mkdir -p "$OUT"

echo "[*] Writing health snapshot to $OUT"

# VyOS command helper
run_vyos_cmd() {
    local outfile="$1"
    local cmd="$2"

    vbash -s <<EOF > "$outfile"
source /opt/vyatta/etc/functions/script-template
run $cmd
exit
EOF
}

# Collect VyOS outputs into separate files
run_vyos_cmd "$OUT/version.txt" "show version"
run_vyos_cmd "$OUT/system-image.txt" "show system image"
run_vyos_cmd "$OUT/interfaces.txt" "show interfaces"
run_vyos_cmd "$OUT/routes-raw.txt" "show ip route"
run_vyos_cmd "$OUT/config-commands.txt" "show configuration commands"

# Normalize routes by stripping route age timers like 01:36:56
sed -E 's/, [0-9]{2}:[0-9]{2}:[0-9]{2}$//' "$OUT/routes-raw.txt" > "$OUT/routes.txt"
rm -f "$OUT/routes-raw.txt"

# Linux-level checks
ip -br link > "$OUT/ip-link.txt"
ip -br addr > "$OUT/ip-addr.txt"
ip route show table all > "$OUT/ip-route.txt"
ss -lntup | sort > "$OUT/listening.txt" || true

# Normalize ps output:
# - keep header
# - sort remaining lines
{
    ps -ef | head -n 1
    ps -ef | tail -n +2 | sort
} > "$OUT/ps.txt"

systemctl list-unit-files --type=service --state=enabled | sort > "$OUT/enabled-services.txt" || true
systemctl list-units --type=service --state=running | sort > "$OUT/running-services.txt" || true
getent passwd | sort > "$OUT/passwd.txt"

if [ -f /config/config.boot ]; then
    sha256sum /config/config.boot > "$OUT/config.boot.sha256"
fi

if [ -d /config/scripts ]; then
    ls -laR /config/scripts > "$OUT/config-scripts.txt"
fi

# Less noisy summary
{
    echo "Health Check Snapshot"
    echo "Timestamp: $TS"
    echo
    echo "Generated files:"
    find "$OUT" -maxdepth 1 -type f -printf "%f\n" | sort | sed 's/^/- /'
} > "$OUT/summary.txt"

# Hash only relatively stable files
(
    cd "$OUT"
    HASH_TARGETS=(
        "version.txt"
        "system-image.txt"
        "interfaces.txt"
        "routes.txt"
        "config-commands.txt"
        "ip-link.txt"
        "ip-addr.txt"
        "ip-route.txt"
        "listening.txt"
        "enabled-services.txt"
        "running-services.txt"
        "passwd.txt"
        "config.boot.sha256"
        "config-scripts.txt"
    )

    : > file-hashes.txt
    for f in "${HASH_TARGETS[@]}"; do
        if [ -f "$f" ]; then
            sha256sum "$f" >> file-hashes.txt
        fi
    done

    sort -o file-hashes.txt file-hashes.txt
)

ln -sfn "$TS" "$OUT_DIR/latest"

echo "[*] Created Health Check at $OUT"
echo "[*] Summary file: $OUT/summary.txt"
echo "[*] Hash manifest: $OUT/file-hashes.txt"