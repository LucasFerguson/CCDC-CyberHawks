#!/bin/bash
# Shared Object Userland Rootkits (LD_PRELOAD/LD_LIBRARY_PATH/LD_AUDIT)

# Search for bad env var sudoers entries for all users
for user in $(getent passwd | cut -d: -f1); do sudo -U "$user" -l 2>/dev/null | grep -Eq "LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT" && echo "$user"; done

# Search for bad env vars in current shell
echo "LD_PRELOAD: $LD_PRELOAD, LD_LIBRARY_PATH: $LD_LIBRARY_PATH, LD_AUDIT: $LD_AUDIT"

# Search for bad env vars in all processes
sudo rg --text "LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT" /proc/*/environ 2>/dev/null

# Search for processes using known malicious .so
sudo rg <path_to_malicious.so> /proc/*/maps

# Search for .so's being used that aren't in the standard directories (/lib,/usr/lib,/lib64,/usr/lib64)
sudo rg "\.so" /proc/*/maps 2>/dev/null | rg -v "/usr/lib64/|/lib/|/usr/lib/|/lib64/|/usr/libexec/sudo/sudoers.so|/usr/libexec/sudo/libsudo_util.so.0.0.0"

# Search places used to find shared objects

# Check ld cache:
strings /etc/ld.so.cache | rg "\.so" | rg -v "/usr/lib64/|/lib/|/usr/lib/|/lib64|glibc-ld.so.cache1.1"

# Check /etc/ld.so.conf
cat /etc/ld.so.conf
rg "." /etc/ld.so.conf.d/*