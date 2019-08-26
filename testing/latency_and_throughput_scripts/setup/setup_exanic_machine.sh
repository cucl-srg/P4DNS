#!/bin/bash

set -ue
mkdir -p /root/jcw78/scripts/hpt_setup/

pushd /root/jcw78/scripts/hpt_setup/
if [[ ! -d exanic-software ]]; then
	echo "Run the main setup first."
	exit 1
fi

pushd exanic-software
make
make install
popd

# Once we have this, we can load the right kernel module:
if [[ $(lsmod | grep -ce 'exasock') -ge 1 ]]; then
	rmmod exasock
fi
if [[ $(lsmod | grep -ce 'exanic') -ge 1 ]]; then
	rmmod exanic
fi

modprobe exasock 
modprobe exanic
exanic-config exanic0

# Check that the firmware is the right date:
pushd /root/jcw78/scripts/hpt_setup/exanic-software/util/
echo "Finding firmware date"
fm_date=$(./exanic-config | grep -ce 'Firmware date: 20180221 ' || true)
popd
echo "Firmware date found ($fm_date)"
if [[ $fm_date == 0 ]]; then
	echo "Installing new firmware"
	./update_exanic_firmware.sh
fi

# Install any python software needed.
python -m pip install -U matplotlib

# Make sure that the DFS is turned off:
./disable_freq_scaling.sh
