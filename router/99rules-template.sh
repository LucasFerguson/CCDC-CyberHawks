#!/bin/vbash

# NOTE: VyOS 1.4.x template for CCDC scored-services allowlist
# Fill in the destination addresses after auditing whether FORWARD rules
# should match the public VIP or the post-DNAT internal server IP.

if [ "$(id -g -n)" != "vyattacfg" ]; then
    exec sg vyattacfg -c "/bin/vbash $(readlink -f "$0") $@"
fi

source /opt/vyatta/etc/functions/script-template
set -e

echo "[*] Applying CCDC scored-services transit allowlist"

configure

# Default deny for transit traffic
set firewall ipv4 forward filter default-action 'drop'

# ------------------------------------------------------------
# IMPORTANT:
# Replace the destination addresses below after auditing NAT.
# Depending on your live VyOS/NAT behavior, these may need to be:
#   - the PUBLIC scored IP
#   - or the INTERNAL server IP after DNAT
# ------------------------------------------------------------

# 50 - Ubuntu Ecom web
set firewall ipv4 forward filter rule 50 action 'accept'
set firewall ipv4 forward filter rule 50 protocol 'tcp'
set firewall ipv4 forward filter rule 50 destination address '<ECOM_MATCH_IP>'
set firewall ipv4 forward filter rule 50 destination port '80,443'
set firewall ipv4 forward filter rule 50 description 'Allow scored e-commerce web traffic'

# 60 - Fedora Webmail UI
set firewall ipv4 forward filter rule 60 action 'accept'
set firewall ipv4 forward filter rule 60 protocol 'tcp'
set firewall ipv4 forward filter rule 60 destination address '<WEBMAIL_MATCH_IP>'
set firewall ipv4 forward filter rule 60 destination port '80,443'
set firewall ipv4 forward filter rule 60 description 'Allow scored webmail UI traffic'

# 61 - Fedora Webmail mail protocols
set firewall ipv4 forward filter rule 61 action 'accept'
set firewall ipv4 forward filter rule 61 protocol 'tcp'
set firewall ipv4 forward filter rule 61 destination address '<WEBMAIL_MATCH_IP>'
set firewall ipv4 forward filter rule 61 destination port '25,465,587,110,995,143,993'
set firewall ipv4 forward filter rule 61 description 'Allow scored mail protocols'

# 70 - Windows AD/DNS
set firewall ipv4 forward filter rule 70 action 'accept'
set firewall ipv4 forward filter rule 70 protocol 'tcp_udp'
set firewall ipv4 forward filter rule 70 destination address '<AD_DNS_MATCH_IP>'
set firewall ipv4 forward filter rule 70 destination port '53,88,389,445,135,464,123'
set firewall ipv4 forward filter rule 70 description 'Allow scored AD DNS traffic'

# 80 - Windows Web
set firewall ipv4 forward filter rule 80 action 'accept'
set firewall ipv4 forward filter rule 80 protocol 'tcp'
set firewall ipv4 forward filter rule 80 destination address '<WINWEB_MATCH_IP>'
set firewall ipv4 forward filter rule 80 destination port '80,443'
set firewall ipv4 forward filter rule 80 description 'Allow scored Windows web traffic'

# 90 - Windows FTP control
set firewall ipv4 forward filter rule 90 action 'accept'
set firewall ipv4 forward filter rule 90 protocol 'tcp'
set firewall ipv4 forward filter rule 90 destination address '<FTP_MATCH_IP>'
set firewall ipv4 forward filter rule 90 destination port '21'
set firewall ipv4 forward filter rule 90 description 'Allow scored FTP control traffic'

# 900 - Allow return traffic
set firewall ipv4 forward filter rule 900 action 'accept'
set firewall ipv4 forward filter rule 900 state established
set firewall ipv4 forward filter rule 900 state related
set firewall ipv4 forward filter rule 900 description 'Allow established and related transit traffic'

# 999 - Final deny/log
set firewall ipv4 forward filter rule 999 action 'drop'
set firewall ipv4 forward filter rule 999 log
set firewall ipv4 forward filter rule 999 description 'Drop and log all other transit traffic'

echo
echo "[*] Pending firewall configuration:"
show | compare
echo

echo "[*] Firewall rules that will be applied:"
run show configuration commands | match firewall
echo

echo "[*] Applying firewall rules with 5-minute rollback safety"
commit-confirm 5
save

echo
echo "[*] Firewall rules applied TEMPORARILY"
echo "[*] Verify them with:"
echo "    show configuration commands | match firewall"
echo "    sudo nft list ruleset"
echo
echo "[*] If everything looks good, run:"
echo "    confirm"
echo
echo "[*] If something broke, do nothing and the config will rollback in 5 minutes"
echo

exit