#!/bin/bash

# A script to replace main.cf with the concise version
cd ~
mkdir -p .frog
LANG=C comm -23 <(postconf -n) <(postconf -d) > main_c.cf
sudo chown root:root main_c.cf
sudo mv /etc/postfix/main.cf .frog/
sudo mv main_c.cf /etc/postfix/main.cf
sudo restorecon -v /etc/postfix/main.cf
sudo systemctl reload postfix
