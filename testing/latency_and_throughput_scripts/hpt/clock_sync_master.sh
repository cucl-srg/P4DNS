#!/bin/bash

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <hpt device>"
	exit 1
fi

# Make sure that NTP has started.
/root/jcw78/scripts/hpt/ntp_enable.sh

# And then sync to the host.
/root/jcw78/scripts/hpt/clock_sync_to_host.sh $1

pkill exanic-clock-sy || echo "Clock sync not running already"

pushd /root/jcw78/scripts/hpt_setup/exanic-software/util/
./exanic-config $1 pps-out on
popd
