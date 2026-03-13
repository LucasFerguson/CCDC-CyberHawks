#!/bin/bash
# Detecting Malicious Kernel Modules

# Diff /proc/modules to standard_kernel_modules file
# lsmod | awk '{print $1}' | sort > baseline.txt
# diff baseline.txt <(lsmod | awk '{print $1}' | sort)

# Check for out-of-tree modules
cat /proc/modules | grep "(OE)"

# Compare lsmod and /proc/modules
lsmod | cut -d' ' -f1 | grep -Ev "^Module$" > lsmod_output
cat /proc/modules | cut -d' ' -f1 > proc_modules_output
diff lsmod_output proc_modules_output

# Check dmesg logs
sudo dmesg | grep -i "module"

# Check for autostart malicious .ko's
# More generally, check systemd-modules-load.service for ConditionDirectoryNotEmpty dirs
cat $(systemctl show -P FragmentPath systemd-modules-load.service) | grep "ConditionDirectoryNotEmpty=|" | cut -d'|' -f2

# and check all of those. use dropin finder functionality
# systemd-modules-load.service will also look at the modules-load and rd.modules-load kernel command-line parameters. Find out what these are!!

# Verify module signatures
# cat /sys/module/module/parameters/sig_enforce
# modinfo -F signer <module.ko>
# What do above commands do?

# Use rkhunter or chkrootkit
# sudo rkhunter --check

# Check for Kernel Taint!
cat /proc/sys/kernel/tainted
chmod +x kernel_chktaint
./kernel_chktaint
dmesg | grep taint

# Detect malicious kexec. This is why important to prevent reloading!

# 1. Enforce Module Signing
# Enable module signing in the kernel configuration (CONFIG_MODULE_SIG=y) to allow only trusted modules.

# 2. Lock Down Module Loading
# echo 1 > /proc/sys/kernel/modules_disabled

# Restrict Access to insmod, modprobe, and /lib/modules
# chmod 700 /sbin/insmod /sbin/modprobe
# chown root:root /lib/modules -R

# Use Mandatory Access Control
# setsebool -P allow_kernel_modload off

# Monitoring Module Events with Auditd
# sudo auditctl -w /sbin/insmod -p x -k modload
# sudo auditctl -w /sbin/modprobe -p x -k modload
# ausearch -k modload

# Check audit.log, kern.log, for module loading and unloading event.

# What is /sys/module?

# Use Volatility Framework to find hidden modules in kernel memory