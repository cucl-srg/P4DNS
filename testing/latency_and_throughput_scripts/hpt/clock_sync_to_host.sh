#!/bin/bash

set -eu

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <device name>"
	exit 1
fi

pkill exanic-clock-sy || echo "Clock sync not running already"

pushd /root/jcw78/scripts/hpt_setup/exanic-software/util/
./exanic-clock-sync $1:host &
popd

# Give this time to sync.
sleep 10
