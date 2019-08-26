#!/bin/bash

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <hpt card name>"
	exit 1
fi

pkill exanic-clock-sy
pushd /root/jcw78/scripts/hpt_setup/exanic-software/util/
# Make sure that the PPS master pulse is off
./exanic-config $1 pps-out off
popd
