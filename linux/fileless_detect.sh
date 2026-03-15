#!/bin/bash

echol () {
    echo "";
    echo "$@";
}

echo "FILELESS MALWARE DETECTOR"
echo "---------------------------"
# Check for memfd_create method
# Check for /proc/*/exe pointing to (deleted) or file descriptor
echol "Search for deleted files running as a process:"
sudo rg --pre $PWD/lah.sh "deleted" /proc/*/exe 2>/dev/null
echol "Search for processes that are running off a file created in the RAM using memfd_create syscall:"
sudo rg --pre $PWD/lah.sh "memfd" /proc/*/exe 2>/dev/null
echol "Search for files that are in RAM directories (/dev/shm or /run/shm):"
sudo rg --pre $PWD/lah.sh "/dev/shm|/run/shm" /proc/*/exe 2>/dev/null
sudo rg --pre strings "/dev/shm|/run/shm" /proc/*/cmdline 2>/dev/null

# Check for open files with deleted entries
echol "Search for open files marked as deleted:"
sudo lsof | rg "(deleted)"
echol "Search for open files in RAM created with memfd:"
sudo lsof | rg "/memfd"

# Check for /proc/*/maps with rwx
echol "Search for processes with rwx regions in memory:"
sudo rg "rwxp" /proc/*/maps 2>/dev/null