#!/bin/bash

# Diff /proc/modules to standard_kernel_modules file
echo "Diff between current system loaded kernel modules and Fedora 42 Server baseline:"
cat fedora_lsmod_out | awk '{print $1}' | sort > /tmp/fedora_baseline
diff /tmp/fedora_baseline <(lsmod | awk '{print $1}' | sort)