#!/bin/bash
cd ~
dnf install fzf ripgrep auditd tcpdump rkhunter chkrootkit strings binutils policycoreutils nmap logrotate wget curl
dnf upgrade
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
# Run av.sh?