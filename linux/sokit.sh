#!/bin/bash
# Shared Object Userland Rootkits (LD_PRELOAD/LD_LIBRARY_PATH/LD_AUDIT)

function echol(){
    echo "";
    echo "$@";
}

# Search for bad env var sudoers entries for all users
echo "Users with sudoers settings with LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT:" 
for user in $(getent passwd | cut -d: -f1); do sudo -U "$user" -l 2>/dev/null | grep -Eq "LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT" && echo "$user"; done

# Search for bad env vars in current shell
echo ""
echo "Current shell env var values -- LD_PRELOAD: $LD_PRELOAD, LD_LIBRARY_PATH: $LD_LIBRARY_PATH, LD_AUDIT: $LD_AUDIT"

# Search for bad env vars in all processes
echo ""
echo "Search for LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT in all processes:"
sudo rg --pre strings --text "LD_PRELOAD=|LD_LIBRARY_PATH=|LD_AUDIT=" /proc/*/environ 2>/dev/null

# Search for processes using known malicious .so
# sudo rg <path_to_malicious.so> /proc/*/maps

# Search for .so's being used that aren't in the standard directories (/lib,/usr/lib,/lib64,/usr/lib64)
echo ""
echo "Shared objects being used in memory that aren't in the standard directories (/lib,/usr/lib,/lib64,/usr/lib64):"
sudo rg "\.so" /proc/*/maps 2>/dev/null | rg -v "/usr/lib64/|/lib/|/usr/lib/|/lib64/|/usr/libexec/sudo/sudoers.so|/usr/libexec/sudo/libsudo_util.so.0.0.0"

# Check ld cache:
echo ""
echo "Check ld cache for shared objects in weird places:"
strings /etc/ld.so.cache | rg "\.so" | rg -v "/usr/lib64/|/lib/|/usr/lib/|/lib64|glibc-ld.so.cache1.1"

# Check /etc/ld.so.conf
echo ""
echo "Print all folders checked for shared objects system-wide (found in ld.so.conf and ld.so.conf.d):"
rg -v "^#" /etc/ld.so.conf*

echol "Shared objects that are checked before anything else (/etc/ld.so.preload): "
rg -v "^#" /etc/ld.so.preload