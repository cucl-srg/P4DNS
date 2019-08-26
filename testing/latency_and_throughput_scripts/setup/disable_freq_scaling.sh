#!/bin/bash

# Note that this does not persist accross reboots.
set -eu

if [[ ! -f /etc/default/cpufrequtils || $(grep -ce 'GOVERNOR="performance"' /etc/default/cpufrequtils || true) == 0 ]]; then
	echo 'GOVERNOR="performance"' >> /etc/default/cpufrequtils
fi

/etc/init.d/cpufrequtils restart
