#!/bin/bash

cd /var/lib/dpkg/info
ls | grep "\.md5sums" | cut -d'.' -f1 | while read -r line; do cat "$line.md5sums" | cut -d' ' -f3 | awk '{print "/" $0}' > "/tmp/$line.md5sums.cut"; done
