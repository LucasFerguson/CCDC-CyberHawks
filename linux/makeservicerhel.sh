#!/bin/bash
mkdir -p psychocity-rhel; systemctl list-units --all | awk '{print $1}' | grep "\." | while read -r line; do p=$(systemctl show -P FragmentPath "$line" 2>/dev/null); if [ -n "$p" ]; then cp "$p" psychocity-rhel; fi; done
