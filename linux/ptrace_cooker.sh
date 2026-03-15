#!/bin/bash
echo "Cooking ptrace..."
sudo echo "3" > /proc/sys/kernel/yama/ptrace_scope
sudo setsebool -P deny_ptrace on
sudo sysctl -w kernel.yama.ptrace_scope=3
echo "Cooked!"
