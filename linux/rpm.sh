#!/bin/bash
sudo find / -type f -perm /a+x 2>/dev/null | while read -r file; do if $(file "$file" | cut -d' ' -f2- | grep -Eq 'ELF '); then echo "$file"; fi done > elfs
sudo rpm -qa | while read pkg; do rpm -ql "$pkg"; done > trk
sudo python3 trk.py
cat non_trk