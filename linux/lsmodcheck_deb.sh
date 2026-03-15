#!/bin/bash

echo "Diff between current system loaded kernel modules and Ubuntu 24.04 baseline:"
cat ubuntu_lsmod_out | awk '{print $1}' | sort > /tmp/ubuntu_baseline
diff /tmp/ubuntu_baseline <(lsmod | awk '{print $1}' | sort)