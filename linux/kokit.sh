#!/bin/bash
# Detecting Malicious Kernel Modules

sudo rkhunter -c
sudo chkrootkit

# Diff /proc/modules to standard_kernel_modules file
# lsmod | awk '{print $1}' | sort > baseline.txt
# diff baseline.txt <(lsmod | awk '{print $1}' | sort)

# Check for out-of-tree modules
echo ""
echo "Out-of-tree (non standard kernel) loaded modules:"
cat /proc/modules | grep "(OE)"

# Compare lsmod and /proc/modules
echo ""
echo "Discrepancies between lsmod and /proc/modules:"
lsmod | cut -d' ' -f1 | grep -Ev "^Module$" > lsmod_output
cat /proc/modules | cut -d' ' -f1 > proc_modules_output
diff lsmod_output proc_modules_output

# Check dmesg logs
echo ""
echo "Kernel module log messages:"
sudo dmesg | grep -i "module"

# Check for autostart malicious .ko's
# More generally, check systemd-modules-load.service for ConditionDirectoryNotEmpty dirs
echo ""
echo "Check for autostart .ko's:"
cat $(systemctl show -P FragmentPath systemd-modules-load.service) | grep "ConditionDirectoryNotEmpty=|" | cut -d'|' -f2 | while read -r line; do echo "Contents of $line:"; ls "$line" | while read -r folderfile; do echo "$line/$folderfile:"; cat "$line/$folderfile"; done; done 2>/dev/null

# run modinfo on modules found.

# and check all of those. use dropin finder functionality
# systemd-modules-load.service will also look at the modules-load and rd.modules-load kernel command-line parameters. Find out what these are!!

# Verify module signatures
echo ""
echo "Loaded modules without a signature:"
cat /proc/modules | cut -d' ' -f1 | while read -r line; do
	if [ -z "$(modinfo -F signer "$line")" ]; then
		echo "$line"; 
	fi;
done

# Check for Kernel Taint!
echo ""
echo "Check for kernel taint:"
cat /proc/sys/kernel/tainted
chmod +x kernel-chktaint
./kernel-chktaint
dmesg | grep taint

# Detect malicious kexec. This is why important to prevent reloading!

# Restrict Access to insmod, modprobe
echo ""
echo "chmod'ing 700 to insmod, modprobe"
sudo chmod 700 "$(which insmod)" "$(which modprobe)" 

# Monitoring Module Events with Auditd
echo ""
echo "Attempt to still audit insmod and modprobe:"
sudo auditctl -w "$(which insmod)" -p x -k modload 2>&1
sudo auditctl -w "$(which modprobe)" -p x -k modload 2>&1
# ausearch -k modload
