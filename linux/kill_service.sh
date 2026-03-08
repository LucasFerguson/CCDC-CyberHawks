#!/bin/bash

for var in "$@"
do
	systemctl stop "$var"
	systemctl disable "$var"
	systemctl mask "$var"
	echo "$var" >> killed_services
done
systemctl daemon-reload
