#!/bin/bash

# Check for memfd_create method


# Check for /proc/*/exe pointing to (deleted) or file descriptor
sudo ls -l /proc/*/exe | grep deleted
sudo ls -l /proc/*/exe | grep memfd
sudo cat /proc/*/exe | grep shm 2>/dev/null
sudo cat /proc/*/cmdline | grep shm 2>/dev/null

# Check for /proc/*/maps with rwx
sudo rg "rwxp" /proc/*/maps 2>/dev/null

# Check for open files with deleted entries
sudo lsof | rg "(deleted)"