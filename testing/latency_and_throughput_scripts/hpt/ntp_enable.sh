#!/bin/bash

set -eu

if [[ $(systemctl show -p SubState ntp) != *running ]]; then
	# Start it.
	sudo service start ntp
else
	echo "NTP Already running!"
fi
