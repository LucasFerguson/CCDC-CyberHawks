#!/usr/bin/env bash
set -euo pipefail

echo "[*] Applying transit outbound block"

configure

set firewall ipv4 forward filter default-action 'drop'

# Allow established / related sessions
set firewall ipv4 forward filter rule 10 action 'accept'
set firewall ipv4 forward filter rule 10 state 'established'
set firewall ipv4 forward filter rule 10 state 'related'
set firewall ipv4 forward filter rule 10 description 'Allow established/related transit traffic'

# Log everything else
set firewall ipv4 forward filter rule 999 action 'drop'
set firewall ipv4 forward filter rule 999 log
set firewall ipv4 forward filter rule 999 description 'Log and drop all other transit IPv4 traffic'

commit-confirm 5
save

echo "[*] Done"