#!/bin/bash

# A script to concise dovecot configurations
cd ~
doveconf -n > dovecot_c.conf
sudo chown root:root dovecot_c.conf
mkdir -p .frog
sudo mv /etc/dovecot/dovecot.conf /etc/dovecot/conf.d/ .frog/
sudo mv dovecot_c.conf /etc/dovecot/dovecot.conf
sudo restorecon -v /etc/dovecot/dovecot.conf
sudo systemctl restart dovecot
